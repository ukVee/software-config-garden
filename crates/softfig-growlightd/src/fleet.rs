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
//! Assembly + spawn + gate, plus the live [`QueueSource`] (slice 002): the queue
//! snapshot is pulled from keeperd's per-queue managed regions
//! ([`KeeperdQueueSource`]). Admission now gates on BOTH windows from real data —
//! the live 5h/7d reserve (slice 005, off the backend's `rate_limit_event` fold)
//! and the live TPM/RPM [`RateSource`] ([`LiveRate`] over the backend's
//! rolling-minute meters, slice 006). `PermissiveRate` is gone from the
//! production path; the fleet gate ([`crate::config`]'s `fleet_enabled`) still
//! stays off until `growlight-verify-merge` enables it on-device.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde::Deserialize;

use crate::admission::AdmissionGovernor;
use crate::claim::KeeperdPartClaimer;
use crate::claude_backend::ClaudeBackend;
use crate::daemon::Daemon;
use crate::drive_loop::{
    spawn_drive_loop, DriveLoop, FleetMember, LiveRate, DRIVE_POLL_MS,
};
use crate::notify_dispatch::{GuiNotifier, LogNotifier, NotifyDispatcher};
use crate::preapproval::{agent_paths, PreApproval};
use crate::queue_source::KeeperdQueueSource;
use crate::supervisor::{AgentSpec, Supervisor};

/// The `claude` binary the backend shells when the config omits `claude_bin`.
pub const DEFAULT_CLAUDE_BIN: &str = "claude";

/// The generic per-agent turn kick when the config omits `prompt`. The
/// SessionStart hook in each agent's `--settings` injects the protocol + baton;
/// this is the bare "go" the backend passes as `claude -p <prompt>`.
pub const DEFAULT_PROMPT: &str = "Begin this growlight iteration. The operating protocol and your current baton have been injected above — boot per protocol step 1, execute NEXT ACTION as one coherent chunk, then hand off by rewriting the baton.";

/// One configured fleet member as read from a `[[growlight.fleet]]` table. The
/// human declares only the agent's id + (optional) pinned queue; growlightd OWNS
/// the per-agent pre-approval paths — it GENERATES `loop.json`/`mcp.json` into the
/// runtime namespace `$XDG_CONFIG_HOME/softfig/growlight/agents/<id>/` (slice 004,
/// fail-closed) rather than letting the config name arbitrary paths (which could
/// point at the harness-sensitive `~/.claude`). The `AgentSpec` paths are derived
/// from `agent` at assembly via [`agent_paths`], not configured.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FleetMemberConfig {
    /// The agent's bus address / work-stream id (the `@`-stripped name).
    pub agent: String,
    /// The queue this member is pinned to, or `None` for a fallback-only member.
    #[serde(default)]
    pub pin: Option<String>,
}

impl FleetMemberConfig {
    /// Build the runtime [`FleetMember`], deriving the `AgentSpec`'s pre-approval
    /// paths under `agents_dir/<id>/` (the same scheme [`PreApproval::generate`]
    /// writes, so the spec the backend shells and the generated files never drift).
    fn to_member(&self, agents_dir: &Path) -> FleetMember {
        let paths = agent_paths(agents_dir, &self.agent);
        let spec = AgentSpec::new(&self.agent, paths.loop_settings, paths.mcp_config);
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
    /// `[[growlight.fleet]]` members, in config order. Raw `{agent, pin}` — the
    /// runtime `AgentSpec` paths are derived at [`assemble_fleet`] (they need the
    /// runtime `agents_dir`, not known at parse).
    pub members: Vec<FleetMemberConfig>,
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
            members: g.fleet,
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
/// without spawning the 1s-cadence thread. `keeperd_socket` backs the live
/// [`KeeperdQueueSource`] (slice 002): each tick pulls the per-queue managed
/// regions from keeperd, fail-closed (a read error idles, never a scheduling
/// failure), so a gated-on loop with keeperd unreachable simply schedules
/// nothing rather than shelling a real `claude`.
pub fn assemble_fleet(
    daemon: &Daemon,
    fleet: &FleetConfig,
    keeperd_socket: &Path,
) -> Option<DriveLoop> {
    if !fleet.enabled {
        return None;
    }
    let hub = daemon.hub.clone();

    // The §15 fail-closed pre-approval context (slice 004): growlightd generates
    // each agent's loop.json/mcp.json into the runtime namespace
    // `$XDG_CONFIG_HOME/softfig/growlight/agents/<id>/` at spawn (never under
    // ~/.claude), anchored to THIS garden's protocol + deny rules. The same
    // `agents_dir` derives the AgentSpec paths the backend shells, so the spec and
    // the generated files can't drift.
    let garden_root = daemon.garden_root();
    let agents_dir = runtime_agents_dir();
    let preapproval = PreApproval::new(
        agents_dir.clone(),
        garden_root.join(PILLAR).join("protocol.md"),
        garden_root,
        softfig_mcp_path(),
        claude_dir(),
    );

    // One backend, shared three ways (the `DriveLoop::new` contract): the
    // supervisor spawns through it, and health + budget are read off the SAME
    // cells it populates.
    let backend = Arc::new(ClaudeBackend::new(
        fleet.bin.clone(),
        fleet.prompt.clone(),
        hub.clone(),
        preapproval,
    ));
    let members: Vec<FleetMember> = fleet
        .members
        .iter()
        .map(|m| m.to_member(&agents_dir))
        .collect();
    let governor = AdmissionGovernor::new(daemon.policy());
    let supervisor = Supervisor::new(Box::new(Arc::clone(&backend)), governor);

    let mut dispatcher = NotifyDispatcher::new();
    dispatcher.register(Box::new(GuiNotifier::new(hub)));
    dispatcher.register(Box::new(LogNotifier::stderr()));

    Some(DriveLoop::new(
        daemon.clone(),
        supervisor,
        Box::new(Arc::clone(&backend)), // health  — live ClaudeBackend (slice 001)
        Box::new(KeeperdQueueSource::new(keeperd_socket.to_path_buf())), // queues — live (slice 002)
        Box::new(KeeperdPartClaimer::new(keeperd_socket.to_path_buf())), // claimer — live (slice 003)
        Box::new(Arc::clone(&backend)), // samples — live budget cell (drive-loop 003)
        Box::new(LiveRate::new(Arc::clone(&backend), daemon.rate_limits())), // rate — live TPM/RPM meter (slice 006)
        dispatcher,
        members,
    ))
}

/// The runtime per-agent namespace `$XDG_CONFIG_HOME/softfig/growlight/agents`
/// (fallback `~/.config/...`) — the same churny-runtime space `softfig growlight
/// start` owns, NOT the garden. Derived from the environment, never a literal
/// (spec §3/§12). growlightd writes each agent's generated pre-approval under
/// `agents/<id>/` here.
fn runtime_agents_dir() -> PathBuf {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home_dir().join(".config"),
    };
    base.join("softfig").join(PILLAR).join("agents")
}

/// `~/.claude` — the harness-sensitive root the pre-approval generator refuses to
/// write under (and whose `projects/` subtree it grants for claude-memory).
fn claude_dir() -> PathBuf {
    home_dir().join(".claude")
}

/// `$HOME`, or `/` as a last resort (the generator's fail-closed guard catches a
/// nonsense derivation; a missing `$HOME` should never silently target the wrong
/// tree).
fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Resolve the `softfig-mcp` bridge binary `mcp.json` attaches: prefer the sibling
/// of the running exe (a dev build points at its own freshly-built bridge, not a
/// stale PATH copy), falling back to a bare `softfig-mcp` (PATH lookup by Claude
/// Code's stdio launcher). Mirrors the single-agent `growlight start` resolver.
fn softfig_mcp_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("softfig-mcp");
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from("softfig-mcp")
}

/// Garden-relative pillar name (matches the daemon-side `paths::PILLAR` + the
/// single-agent launcher's constant).
const PILLAR: &str = "growlight";

/// Assemble (via [`assemble_fleet`]) and spawn the live drive-loop thread — iff
/// the gate is on. Gate off ⇒ `Ok(None)`, nothing spawned. A thin wrapper over
/// the already-proven [`spawn_drive_loop`], whose thread ticks until the daemon
/// enters [`State::Stopping`](crate::state::State::Stopping), mirroring
/// `spawn_bus_tailer`.
pub fn spawn_fleet(
    daemon: &Daemon,
    fleet: &FleetConfig,
    keeperd_socket: &Path,
) -> std::io::Result<Option<JoinHandle<()>>> {
    match assemble_fleet(daemon, fleet, keeperd_socket) {
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
        "[[growlight.fleet]]\nagent = \"a\"\n"
    }

    /// A stand-in keeperd socket for the assembly tests. Gate-off assembly never
    /// touches it (it returns before building the queue source); gate-on assembly
    /// only stores the path (the live pull happens on `tick`, which these tests do
    /// not call — the live source's read/parse paths are proven in `queue_source`).
    fn keeperd_socket() -> &'static Path {
        Path::new("/run/nonexistent-keeperd.sock")
    }

    #[test]
    fn gate_off_assembles_nothing() {
        let d = daemon();
        assert!(
            assemble_fleet(&d, &FleetConfig::disabled(), keeperd_socket()).is_none(),
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
            assemble_fleet(&d, &cfg, keeperd_socket()).is_none(),
            "gate off ⇒ no DriveLoop even with configured members",
        );
    }

    #[test]
    fn gate_on_assembles_a_loop_over_the_live_keeperd_queue_source() {
        let d = daemon();
        let cfg = FleetConfig::from_keeper_toml(&format!(
            "[growlight]\nfleet_enabled = true\n{}",
            member_toml()
        ))
        .unwrap();
        // Gate on ⇒ a live DriveLoop is assembled over the keeperd-backed
        // QueueSource (slice 002). We deliberately do NOT `tick` here: a tick pulls
        // the backlog doc over the socket (`call_reconnecting`, ~3s budget against a
        // dead socket). The live source's fail-closed-idle-on-error path and the
        // empty-snapshot-schedules-nothing path are unit-proven in `queue_source`
        // and `drive_loop`, so assembly success is all this test needs to assert.
        assert!(
            assemble_fleet(&d, &cfg, keeperd_socket()).is_some(),
            "gate on ⇒ Some(DriveLoop) over the live queue source",
        );
    }

    #[test]
    fn parses_a_growlight_fleet_table_into_members() {
        // The human declares only `agent` (+ optional `pin`) — growlightd OWNS the
        // pre-approval paths (slice 004), so the config no longer names them.
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

[[growlight.fleet]]
agent = "reviewer"
"#;
        let cfg = FleetConfig::from_keeper_toml(toml).expect("valid config");
        assert!(cfg.enabled);
        assert_eq!(cfg.bin, "/usr/bin/claude");
        assert_eq!(cfg.prompt, "kick");
        assert_eq!(
            cfg.members,
            vec![
                FleetMemberConfig { agent: "builder".into(), pin: Some("queue:build".into()) },
                FleetMemberConfig { agent: "reviewer".into(), pin: None },
            ],
            "the table parses a pinned + an unpinned member, in order",
        );

        // The runtime AgentSpec paths are DERIVED under the agents namespace (the
        // same scheme PreApproval::generate writes), never read from the config.
        let agents = Path::new("/cfg/agents");
        assert_eq!(
            cfg.members.iter().map(|m| m.to_member(agents)).collect::<Vec<_>>(),
            vec![
                FleetMember::pinned(
                    AgentSpec::new(
                        "builder",
                        "/cfg/agents/builder/loop.json",
                        "/cfg/agents/builder/mcp.json",
                    ),
                    "queue:build",
                ),
                FleetMember::unpinned(AgentSpec::new(
                    "reviewer",
                    "/cfg/agents/reviewer/loop.json",
                    "/cfg/agents/reviewer/mcp.json",
                )),
            ],
            "derived pre-approval paths land under agents/<id>/",
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
