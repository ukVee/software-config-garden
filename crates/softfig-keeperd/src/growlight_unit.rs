//! keeperd → growlightd lifecycle (config-in-garden milestone, slice 2).
//!
//! growlightd runs as its own systemd **user** unit
//! (`softfig-growlightd.service`, `Restart=on-failure`, no `WantedBy`). keeperd
//! starts/stops it **event-drivenly** on the unlock/lock transitions it already
//! owns — growlightd never polls keeperd to learn the garden is up; keeperd
//! tells it by starting the unit. The trigger is gated on the in-garden
//! `config/growlight.toml` `fleet_enabled` flag (read through the mount).
//!
//! ## Persist through a relock-cycle (locked-decision 5)
//!
//! A `softfig daemon cycle` / relock is a *resume* — keeperd bounces but the
//! garden stays armed. keeperd must NOT stop growlightd then: it rides the
//! keeperd bounce via its reconnecting IPC, and its child `claude -p` agents keep
//! running. keeperd distinguishes resume from a terminal lock by the same signal
//! the relock teardown already uses — a live (unexpired) relock blob means a
//! cycle is pending. So [`stop_on_terminal_lock`] stops the unit only when no
//! live relock blob is armed; on resume it leaves growlightd running and the next
//! unlock re-fires the idempotent [`start_if_enabled`] (a no-op).
//!
//! ## Test-safety
//!
//! Every `systemctl` call is gated behind
//! [`KeeperConfig::enable_growlight_supervision`](crate::config::KeeperConfig::enable_growlight_supervision),
//! which is **off** by default and turned on only by the real `softfig-keeperd`
//! binary — so no library or test path ever shells out.

use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use crate::daemon::Daemon;

/// The growlightd systemd **user** unit keeperd manages.
pub const GROWLIGHTD_UNIT: &str = "softfig-growlightd.service";

/// Read just the `fleet_enabled` gate from `<garden_root>/config/growlight.toml`,
/// through the mount (FUSE serves it — the same plain, lock-free, no-mount-walk
/// read [`apply_garden_config`](crate::handlers) uses for `config/keeper.toml`).
/// Fail-closed: absent / unreadable / malformed ⇒ `false`, so a config problem
/// never auto-arms the fleet. Deliberately a one-bool reader — keeperd does not
/// pull in growlightd's full fleet schema; the roster stays growlightd's concern.
pub fn fleet_enabled(garden_root: &Path) -> bool {
    #[derive(Deserialize)]
    struct Gate {
        #[serde(default)]
        fleet_enabled: bool,
    }
    let path = garden_root
        .join(softfig_ipc::GARDEN_CONFIG_DIR)
        .join(softfig_ipc::GROWLIGHT_CONFIG_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return false; // absent / unreadable ⇒ fleet stays off
    };
    // Unknown keys (`claude_bin`, `prompt`, `[[fleet]]`) are ignored — we only
    // need the gate. A parse error fails closed.
    toml::from_str::<Gate>(&raw)
        .map(|g| g.fleet_enabled)
        .unwrap_or(false)
}

/// On an unlock/resume: `systemctl --user start softfig-growlightd` iff the
/// in-garden gate is on. Idempotent (systemd no-ops an already-active unit, so a
/// relock resume re-firing this is harmless). A disabled gate ensures the unit is
/// *not* started (we never `stop` here — a live-disable takes effect at the next
/// cycle via the lock-side stop; see the decision doc's locked-decision 6).
///
/// No-op unless supervision is enabled in the config — so only the real keeperd
/// binary ever shells `systemctl`. Best-effort: a `systemctl` failure is logged,
/// never fatal to the unlock.
pub fn start_if_enabled(daemon: &Daemon) {
    let (supervise, garden_root) = {
        let inner = daemon.inner.lock().unwrap();
        (
            inner.config.enable_growlight_supervision,
            inner.config.garden_root.clone(),
        )
    };
    if !supervise {
        return;
    }
    if !fleet_enabled(&garden_root) {
        return; // gate off ⇒ leave the fleet down
    }
    // `start` is fast (Type=simple); wait for it so we can log a real failure.
    match Command::new("systemctl")
        .args(["--user", "start", GROWLIGHTD_UNIT])
        .status()
    {
        Ok(s) if s.success() => {
            eprintln!("keeperd: fleet enabled — started {GROWLIGHTD_UNIT}");
        }
        Ok(s) => eprintln!("keeperd: `systemctl --user start {GROWLIGHTD_UNIT}` exited {s}"),
        Err(e) => eprintln!("keeperd: could not start {GROWLIGHTD_UNIT} ({e})"),
    }
}

/// On a daemon teardown: stop the growlightd unit **only if this is a terminal
/// lock** — i.e. no live relock blob is armed. A pending relock (a `daemon cycle`
/// / `relock`) is a *resume*: leave growlightd running so it rides the keeperd
/// bounce (locked-decision 5).
///
/// `resume_pending` is computed by the caller while it still holds `inner`
/// (it already inspects the relock blob there), so this function stays
/// lock-free. Fire-and-forget: `systemctl --user stop` blocks until the unit's
/// graceful boundary exit (up to its `TimeoutStopSec`), which must NOT stall
/// keeperd's own teardown (the 2026-06-21/22 wedge class), so we **spawn without
/// waiting** — systemd drives growlightd's graceful stop independently while
/// keeperd's teardown returns at once.
///
/// No-op unless supervision is enabled — only the real keeperd binary shells out.
pub fn stop_on_terminal_lock(supervise: bool, resume_pending: bool) {
    if !supervise || resume_pending {
        return; // disabled, or a cycle is pending (resume) ⇒ leave it running
    }
    match Command::new("systemctl")
        .args(["--user", "stop", GROWLIGHTD_UNIT])
        .spawn()
    {
        Ok(_) => eprintln!("keeperd: terminal lock — stopping {GROWLIGHTD_UNIT}"),
        Err(e) => eprintln!("keeperd: could not stop {GROWLIGHTD_UNIT} ({e})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(garden: &Path, body: &str) {
        let cd = garden.join(softfig_ipc::GARDEN_CONFIG_DIR);
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(cd.join(softfig_ipc::GROWLIGHT_CONFIG_FILE), body).unwrap();
    }

    #[test]
    fn gate_absent_config_is_disabled() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!fleet_enabled(dir.path()), "no config/growlight.toml ⇒ off");
    }

    #[test]
    fn gate_reads_true_only_when_armed() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "fleet_enabled = true\n[[fleet]]\nagent = \"a\"\n");
        assert!(fleet_enabled(dir.path()), "armed gate reads true");
    }

    #[test]
    fn gate_false_or_omitted_is_disabled() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "fleet_enabled = false\n");
        assert!(!fleet_enabled(dir.path()));
        // Omitted entirely (e.g. a scaffolded-but-untouched config) ⇒ off.
        write_config(dir.path(), "# commented default, nothing set\n");
        assert!(!fleet_enabled(dir.path()));
    }

    #[test]
    fn gate_malformed_config_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "fleet_enabled = \"yes\"\n"); // wrong type
        assert!(!fleet_enabled(dir.path()), "a parse error never auto-arms");
    }

    #[test]
    fn gate_ignores_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        // The full growlightd schema (claude_bin/prompt/[[fleet]]) must not break
        // keeperd's one-bool read.
        write_config(
            dir.path(),
            "fleet_enabled = true\nclaude_bin = \"/usr/bin/claude\"\nprompt = \"go\"\n\
             [[fleet]]\nagent = \"a\"\npin = \"q\"\n",
        );
        assert!(fleet_enabled(dir.path()));
    }

    #[test]
    fn stop_is_a_noop_when_supervision_off_or_resume_pending() {
        // Neither call shells `systemctl` (supervision off, or a resume is
        // pending). If either did, an unprivileged test runner without a user
        // systemd bus would still not panic — but the guard means we never even
        // construct the Command.
        stop_on_terminal_lock(false, false); // supervision off
        stop_on_terminal_lock(true, true); // resume pending
    }
}
