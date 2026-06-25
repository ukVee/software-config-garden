//! Live fleet assembly (`growlight-live-fleet` slice 001).
//!
//! Phases 1–7 + drive-loop + wire-loose-ends shipped every pure core and seam,
//! but nothing was ever *assembled* in the daemon — `DriveLoop::new` /
//! `spawn_drive_loop` / `ClaudeBackend::new` were never called outside tests. This
//! module is the one place that constructs a *live* [`DriveLoop`] over a real
//! [`ClaudeBackend`] and spawns it — **only** when the off-by-default
//! `[growlight] fleet_enabled` gate is on.
//!
//! ## The gate lives off the agent-writable surface
//!
//! The fleet config is read from the **plaintext** keeper.toml bootstrap pointer
//! (`<garden_root>/.softfig/keeper.toml`), the same file that already holds
//! `state_root` + `[growlight] allow_relock` — deliberately *not* the in-garden
//! `config/keeper.toml` (config-in-garden Slice 1). `fleet_enabled` is a
//! live-capability switch, so the loop must not be able to self-enable the fleet
//! by committing to its own garden: arming it is a human edit to a file the agents
//! can't author. We read only the `[growlight]` table; every other keeperd-owned
//! key is ignored.
//!
//! ## Fail-closed
//!
//! An absent pointer, an unreadable one, or an out-of-shape `[growlight]` table
//! all collapse to [`FleetConfig::disabled`] — a config problem can never *enable*
//! the fleet. Gate off ⇒ [`assemble_fleet`] constructs nothing (no backend, no
//! thread) and growlightd is byte-identical to today.
//!
//! ## Scope of this slice
//!
//! Only the assembly + spawn + gate. The live [`QueueSource`] (slice 002), the
//! real 5h/7d reserve (slice 005) and the live [`RateSource`] (slice 006) are
//! still their deferred/permissive defaults here ([`DeferredQueues`] /
//! [`PermissiveRate`]) — safe because the gate stays off until
//! `growlight-verify-merge` enables it on-device.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde::Deserialize;

use crate::admission::AdmissionGovernor;
use crate::claude_backend::ClaudeBackend;
use crate::daemon::Daemon;
use crate::drive_loop::{
    spawn_drive_loop, DeferredQueues, DriveLoop, FleetMember, PermissiveRate, DRIVE_POLL_MS,
};
use crate::notify_dispatch::{GuiNotifier, LogNotifier, NotifyDispatcher};
use crate::supervisor::{AgentSpec, Supervisor};

/// The `claude` binary the backend shells when the config omits `claude_bin`.
pub const DEFAULT_CLAUDE_BIN: &str = "claude";

/// The generic per-agent turn kick when the config omits `prompt`. The
/// SessionStart hook in each agent's `--settings` injects the protocol + baton;
/// this is the bare "go" the backend passes as `claude -p <prompt>`.
pub const DEFAULT_PROMPT: &str = "Begin this growlight iteration. The operating protocol and your current baton have been injected above — boot per protocol step 1, execute NEXT ACTION as one coherent chunk, then hand off by rewriting the baton.";

/// One configured fleet member as read from a `[[growlight.fleet]]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FleetMemberConfig {
    /// The agent's bus address / work-stream id (the `@`-stripped name).
    pub agent: String,
    /// The queue this member is pinned to, or `None` for a fallback-only member.
    #[serde(default)]
    pub pin: Option<String>,
    /// Per-agent pre-approved `loop.json` (settings + hooks).
    pub loop_settings: PathBuf,
    /// Per-agent `mcp.json` (the softfig-mcp attach config).
    pub mcp_config: PathBuf,
}

impl FleetMemberConfig {
    fn to_member(&self) -> FleetMember {
        let spec = AgentSpec::new(&self.agent, &self.loop_settings, &self.mcp_config);
        match &self.pin {
            Some(pin) => FleetMember::pinned(spec, pin.clone()),
            None => FleetMember::unpinned(spec),
        }
    }
}

/// The parsed `[growlight]` fleet config: the off-by-default `enabled` gate, the
/// shared-backend `bin`/`prompt`, and the configured `members`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetConfig {
    /// `[growlight] fleet_enabled` — off by default; the live-capability gate.
    pub enabled: bool,
    /// `[growlight] claude_bin` — the backend's `claude` binary.
    pub bin: String,
    /// `[growlight] prompt` — the generic per-agent turn kick.
    pub prompt: String,
    /// `[[growlight.fleet]]` members, in config order.
    pub members: Vec<FleetMember>,
}

impl FleetConfig {
    /// The fail-closed default: gate off, no members, default bin/prompt.
    /// Returned whenever the config is absent or unreadable.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            bin: DEFAULT_CLAUDE_BIN.to_string(),
            prompt: DEFAULT_PROMPT.to_string(),
            members: Vec::new(),
        }
    }

    /// Parse the `[growlight]` table out of a keeper.toml document, reading ONLY
    /// that table (every other keeperd-owned key is ignored). A document with no
    /// `[growlight]` table yields [`disabled`](Self::disabled); an out-of-shape
    /// `[growlight]` table is an `Err` the loader treats as fail-closed.
    pub fn from_keeper_toml(s: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Doc {
            growlight: Option<RawGrowlight>,
        }
        #[derive(Deserialize)]
        struct RawGrowlight {
            #[serde(default)]
            fleet_enabled: bool,
            claude_bin: Option<String>,
            prompt: Option<String>,
            #[serde(default)]
            fleet: Vec<FleetMemberConfig>,
        }
        let doc: Doc = toml::from_str(s).map_err(|e| format!("parse keeper.toml: {e}"))?;
        let Some(g) = doc.growlight else {
            return Ok(Self::disabled());
        };
        Ok(Self {
            enabled: g.fleet_enabled,
            bin: g.claude_bin.unwrap_or_else(|| DEFAULT_CLAUDE_BIN.to_string()),
            prompt: g.prompt.unwrap_or_else(|| DEFAULT_PROMPT.to_string()),
            members: g.fleet.iter().map(FleetMemberConfig::to_member).collect(),
        })
    }
}

/// Load the fleet config from the plaintext keeper.toml bootstrap pointer at
/// `<garden_root>/.softfig/keeper.toml`, fail-closed. An absent file, an
/// unreadable one, or an out-of-shape `[growlight]` table all yield
/// [`FleetConfig::disabled`] (with a stderr warning for the malformed case) — so
/// a config problem can never *enable* the fleet.
pub fn load_fleet_config(garden_root: &Path) -> FleetConfig {
    let path = garden_root.join(".softfig").join("keeper.toml");
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => return FleetConfig::disabled(), // absent/unreadable pointer ⇒ no fleet
    };
    match FleetConfig::from_keeper_toml(&raw) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!(
                "softfig-growlightd: ignoring malformed [growlight] fleet config at {} ({e}); fleet stays OFF",
                path.display()
            );
            FleetConfig::disabled()
        }
    }
}

/// Assemble the live [`DriveLoop`] — **iff `fleet.enabled`**. Gate off ⇒ `None`
/// having constructed nothing (no backend, no supervisor, no dispatcher). Gate on
/// ⇒ one shared `Arc<ClaudeBackend>` placed behind BOTH the
/// [`AgentHealthSource`](crate::drive_loop::AgentHealthSource) and
/// [`BudgetSampleSource`](crate::drive_loop::BudgetSampleSource) *and* given to
/// the [`Supervisor`] as its backend — all three clones of the one Arc, as the
/// [`DriveLoop::new`] contract requires. Production notifiers (the GUI hub +
/// stderr audit log) are registered on the owned dispatcher.
///
/// Split out from [`spawn_fleet`] so the gate + assembly are unit-testable
/// without spawning the 1s-cadence thread: an assembled loop can be `tick`ed
/// in-process, and (because [`DeferredQueues`] yields an empty snapshot) that tick
/// schedules nothing and never shells a real `claude`.
pub fn assemble_fleet(daemon: &Daemon, fleet: &FleetConfig) -> Option<DriveLoop> {
    if !fleet.enabled {
        return None;
    }
    let hub = daemon.hub.clone();
    // One backend, shared three ways (the `DriveLoop::new` contract): the
    // supervisor spawns through it, and health + budget are read off the SAME
    // cells it populates.
    let backend = Arc::new(ClaudeBackend::new(
        fleet.bin.clone(),
        fleet.prompt.clone(),
        hub.clone(),
    ));
    let governor = AdmissionGovernor::new(daemon.policy());
    let supervisor = Supervisor::new(Box::new(Arc::clone(&backend)), governor);

    let mut dispatcher = NotifyDispatcher::new();
    dispatcher.register(Box::new(GuiNotifier::new(hub)));
    dispatcher.register(Box::new(LogNotifier::stderr()));

    Some(DriveLoop::new(
        daemon.clone(),
        supervisor,
        Box::new(Arc::clone(&backend)), // health  — live ClaudeBackend (slice 001)
        Box::new(DeferredQueues),       // queues  — slice 002 wires the live source
        Box::new(Arc::clone(&backend)), // samples — live budget cell (drive-loop 003)
        Box::new(PermissiveRate),       // rate    — slice 006 wires the live source
        dispatcher,
        fleet.members.clone(),
    ))
}

/// Assemble (via [`assemble_fleet`]) and spawn the live drive-loop thread — iff
/// the gate is on. Gate off ⇒ `Ok(None)`, nothing spawned. A thin wrapper over
/// the already-proven [`spawn_drive_loop`], whose thread ticks until the daemon
/// enters [`State::Stopping`](crate::state::State::Stopping), mirroring
/// `spawn_bus_tailer`.
pub fn spawn_fleet(
    daemon: &Daemon,
    fleet: &FleetConfig,
) -> std::io::Result<Option<JoinHandle<()>>> {
    match assemble_fleet(daemon, fleet) {
        None => Ok(None),
        Some(drive) => Ok(Some(spawn_drive_loop(
            daemon.clone(),
            drive,
            Duration::from_millis(DRIVE_POLL_MS),
        )?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GrowlightdConfig;

    fn daemon() -> Daemon {
        Daemon::new(GrowlightdConfig::new("/run/g.sock".into(), "/garden".into()))
    }

    fn member_toml() -> &'static str {
        "[[growlight.fleet]]\nagent = \"a\"\nloop_settings = \"/l\"\nmcp_config = \"/m\"\n"
    }

    #[test]
    fn gate_off_assembles_nothing() {
        let d = daemon();
        assert!(
            assemble_fleet(&d, &FleetConfig::disabled()).is_none(),
            "the disabled default constructs no DriveLoop",
        );
        // An explicit `fleet_enabled = false` with a member present is still off —
        // a configured-but-disarmed fleet spawns nothing.
        let cfg = FleetConfig::from_keeper_toml(&format!(
            "[growlight]\nfleet_enabled = false\n{}",
            member_toml()
        ))
        .unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.members.len(), 1, "members still parse while disarmed");
        assert!(
            assemble_fleet(&d, &cfg).is_none(),
            "gate off ⇒ no DriveLoop even with configured members",
        );
    }

    #[test]
    fn gate_on_assembles_a_loop_that_ticks_idle_without_a_live_queue() {
        let d = daemon();
        let cfg = FleetConfig::from_keeper_toml(&format!(
            "[growlight]\nfleet_enabled = true\n{}",
            member_toml()
        ))
        .unwrap();
        let mut drive = assemble_fleet(&d, &cfg).expect("gate on ⇒ Some(DriveLoop)");
        // `DeferredQueues` yields an empty snapshot, so a tick schedules nothing
        // and never shells a real `claude` — safe to run in-process.
        let report = drive.tick(0);
        assert!(report.started.is_empty(), "no live queue ⇒ no starts");
        assert!(report.held_starts.is_empty());
        assert!(!report.paused);
    }

    #[test]
    fn parses_a_growlight_fleet_table_into_members() {
        let toml = r#"
state_root = "/state"

[growlight]
allow_relock = false
fleet_enabled = true
claude_bin = "/usr/bin/claude"
prompt = "kick"

[[growlight.fleet]]
agent = "builder"
pin = "queue:build"
loop_settings = "/cfg/builder/loop.json"
mcp_config = "/cfg/builder/mcp.json"

[[growlight.fleet]]
agent = "reviewer"
loop_settings = "/cfg/reviewer/loop.json"
mcp_config = "/cfg/reviewer/mcp.json"
"#;
        let cfg = FleetConfig::from_keeper_toml(toml).expect("valid config");
        assert!(cfg.enabled);
        assert_eq!(cfg.bin, "/usr/bin/claude");
        assert_eq!(cfg.prompt, "kick");
        assert_eq!(
            cfg.members,
            vec![
                FleetMember::pinned(
                    AgentSpec::new("builder", "/cfg/builder/loop.json", "/cfg/builder/mcp.json"),
                    "queue:build",
                ),
                FleetMember::unpinned(AgentSpec::new(
                    "reviewer",
                    "/cfg/reviewer/loop.json",
                    "/cfg/reviewer/mcp.json",
                )),
            ],
            "the table maps to a pinned + an unpinned member, in order",
        );
    }

    #[test]
    fn no_growlight_table_is_the_disabled_default() {
        let cfg = FleetConfig::from_keeper_toml("state_root = \"/state\"\n").unwrap();
        assert_eq!(cfg, FleetConfig::disabled());
    }

    #[test]
    fn bin_and_prompt_default_when_omitted() {
        let cfg = FleetConfig::from_keeper_toml("[growlight]\nfleet_enabled = true\n").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.bin, DEFAULT_CLAUDE_BIN);
        assert_eq!(cfg.prompt, DEFAULT_PROMPT);
        assert!(cfg.members.is_empty());
    }

    #[test]
    fn a_malformed_growlight_table_is_an_error() {
        // `fleet_enabled` as a string, not a bool — the loader treats Err as
        // fail-closed, so this never enables the fleet.
        let r = FleetConfig::from_keeper_toml("[growlight]\nfleet_enabled = \"yes\"\n");
        assert!(r.is_err(), "an out-of-shape table is rejected, not silently on");
    }

    #[test]
    fn load_is_disabled_when_the_pointer_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        // No `.softfig/keeper.toml` under the garden root.
        assert_eq!(load_fleet_config(dir.path()), FleetConfig::disabled());
    }

    #[test]
    fn load_is_disabled_when_the_pointer_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().join(".softfig");
        std::fs::create_dir_all(&sd).unwrap();
        std::fs::write(sd.join("keeper.toml"), "[growlight]\nfleet_enabled = 3\n").unwrap();
        // A broken table fails closed, not on.
        assert_eq!(load_fleet_config(dir.path()), FleetConfig::disabled());
    }

    #[test]
    fn load_reads_an_armed_pointer() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().join(".softfig");
        std::fs::create_dir_all(&sd).unwrap();
        std::fs::write(
            sd.join("keeper.toml"),
            format!("state_root = \"/s\"\n[growlight]\nfleet_enabled = true\n{}", member_toml()),
        )
        .unwrap();
        let cfg = load_fleet_config(dir.path());
        assert!(cfg.enabled);
        assert_eq!(cfg.members.len(), 1);
    }
}
