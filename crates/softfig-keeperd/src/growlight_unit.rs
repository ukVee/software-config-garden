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

/// Env var the softfig-keeperd **unit file** sets to mark an instance as the
/// systemd-deployed keeperd. Supervision must mean "the deployed instance", not
/// "the keeperd binary": integration tests spawn this very binary
/// (`CARGO_BIN_EXE_softfig-keeperd`), and when `main` opted in unconditionally,
/// every test-keeperd teardown ran a real `systemctl --user stop
/// {GROWLIGHTD_UNIT}` on the host — invisibly killing a live fleet ~10 min into
/// any agent run that reached `cargo test --workspace`
/// (incident-20260706-growlightd-fleet-liveness-2bugs, Bug A). Only the unit
/// file exports it, so a test-spawned keeperd is inert by construction.
pub const SUPERVISE_ENV: &str = "SOFTFIG_SUPERVISE_GROWLIGHTD";

/// True iff [`SUPERVISE_ENV`] is set to a non-empty, non-`"0"` value in this
/// process's environment.
pub fn supervision_from_env() -> bool {
    supervision_from(std::env::var_os(SUPERVISE_ENV))
}

/// [`supervision_from_env`], factored pure for testing.
fn supervision_from(v: Option<std::ffi::OsString>) -> bool {
    matches!(v, Some(s) if !s.is_empty() && s != *"0")
}

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

/// On an unlock/resume: bring the growlightd unit into line with the in-garden
/// `fleet_enabled` gate — **start** it if the gate is on, **ensure it is stopped**
/// if the gate is off. The stop half is what makes a *live disable* take effect:
/// flip `fleet_enabled` true→false, and the next unlock/`daemon cycle` re-reads
/// the gate here and stops the unit (locked-decision 6). Idempotent in both
/// directions (systemd no-ops an already-active start / already-stopped stop), so
/// a relock resume re-firing this is harmless.
///
/// No-op unless supervision is enabled in the config — so only the real keeperd
/// binary ever shells `systemctl`. Best-effort: a `systemctl` failure is logged,
/// never fatal to the unlock.
pub fn apply_fleet_gate(daemon: &Daemon) {
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
    // `unit_is_active` is only consulted on the gate-off path (lazy), so a normal
    // gate-on unlock doesn't pay for it.
    match gate_action(fleet_enabled(&garden_root), unit_is_active) {
        GateAction::Start => start_unit(),
        GateAction::Stop => {
            eprintln!("keeperd: fleet disabled — stopping {GROWLIGHTD_UNIT}");
            spawn_stop();
        }
        GateAction::Noop => {}
    }
}

/// What [`apply_fleet_gate`] does, factored pure for testing.
#[derive(Debug, PartialEq, Eq)]
enum GateAction {
    /// Gate on ⇒ start (idempotent if already active).
    Start,
    /// Gate off but the unit is still up ⇒ a live disable: stop it.
    Stop,
    /// Gate off and already down (the common disabled-fleet unlock) ⇒ nothing.
    Noop,
}

/// Decide the gate action. `is_active` is a thunk so the (subprocess) liveness
/// check is taken **only** on the gate-off branch — a gate-on unlock never runs it.
fn gate_action(gate_on: bool, is_active: impl FnOnce() -> bool) -> GateAction {
    if gate_on {
        GateAction::Start
    } else if is_active() {
        GateAction::Stop
    } else {
        GateAction::Noop
    }
}

/// `systemctl --user start softfig-growlightd` — fast (Type=simple), so we wait
/// for it and log a real failure. Idempotent (systemd no-ops an active unit).
fn start_unit() {
    match Command::new("systemctl")
        .args(["--user", "start", GROWLIGHTD_UNIT])
        .status()
    {
        Ok(s) if s.success() => eprintln!("keeperd: fleet enabled — started {GROWLIGHTD_UNIT}"),
        Ok(s) => eprintln!("keeperd: `systemctl --user start {GROWLIGHTD_UNIT}` exited {s}"),
        Err(e) => eprintln!("keeperd: could not start {GROWLIGHTD_UNIT} ({e})"),
    }
}

/// `systemctl --user is-active --quiet <unit>` → true iff the unit is active.
/// Lets the gate-off path skip a pointless stop on the common disabled-fleet
/// unlock.
fn unit_is_active() -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", GROWLIGHTD_UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Spawn `systemctl --user stop <unit>` **without waiting**. `stop` blocks until
/// the unit's graceful boundary exit (up to its `TimeoutStopSec`); that must
/// never stall the caller — neither keeperd's own teardown (the 2026-06-21/22
/// wedge class) nor a live unlock. systemd drives growlightd's graceful stop
/// independently while the caller returns at once.
fn spawn_stop() {
    if let Err(e) = Command::new("systemctl")
        .args(["--user", "stop", GROWLIGHTD_UNIT])
        .spawn()
    {
        eprintln!("keeperd: could not stop {GROWLIGHTD_UNIT} ({e})");
    }
}

/// On a daemon teardown: stop the growlightd unit **only if this is a terminal
/// lock** — i.e. no live relock blob is armed. A pending relock (a `daemon cycle`
/// / `relock`) is a *resume*: leave growlightd running so it rides the keeperd
/// bounce (locked-decision 5).
///
/// `resume_pending` is computed by the caller while it still holds `inner` (it
/// already inspects the relock blob there), so this function stays lock-free.
///
/// No-op unless supervision is enabled — only the real keeperd binary shells out.
pub fn stop_on_terminal_lock(supervise: bool, resume_pending: bool) {
    if !supervise || resume_pending {
        return; // disabled, or a cycle is pending (resume) ⇒ leave it running
    }
    eprintln!("keeperd: terminal lock — stopping {GROWLIGHTD_UNIT}");
    spawn_stop();
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
    fn gate_action_matrix() {
        use std::cell::Cell;
        // Gate on ⇒ Start, and the liveness thunk is NEVER consulted (no wasted
        // subprocess on the common gate-on unlock).
        let consulted = Cell::new(false);
        let a = gate_action(true, || {
            consulted.set(true);
            true
        });
        assert_eq!(a, GateAction::Start);
        assert!(!consulted.get(), "gate-on must not check liveness");

        // Gate off + unit up ⇒ Stop (the live-disable path this fixes).
        assert_eq!(gate_action(false, || true), GateAction::Stop);
        // Gate off + unit already down ⇒ Noop (common disabled-fleet unlock).
        assert_eq!(gate_action(false, || false), GateAction::Noop);
    }

    #[test]
    fn supervision_env_gate_requires_a_truthy_value() {
        use std::ffi::OsString;
        // Unset (every library/test spawn, incl. CARGO_BIN_EXE integration
        // fixtures) ⇒ off — the Bug-A regression shape.
        assert!(!supervision_from(None));
        // Explicitly disabled / empty ⇒ off.
        assert!(!supervision_from(Some(OsString::from("0"))));
        assert!(!supervision_from(Some(OsString::from(""))));
        // The unit file's `Environment={SUPERVISE_ENV}=1` ⇒ on.
        assert!(supervision_from(Some(OsString::from("1"))));
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
