//! Live fleet assembly (`growlight-live-fleet` slice 001).
//!
//! Phases 1–7 + drive-loop + wire-loose-ends shipped every pure core and seam,
//! but nothing was ever *assembled* in the daemon — `DriveLoop::new` /
//! `spawn_drive_loop` / `ClaudeBackend::new` were never called outside tests. This
//! module is the one place that constructs a *live* [`DriveLoop`] over a real
//! [`ClaudeBackend`] and spawns it — **only** when the off-by-default
//! `fleet_enabled` gate is on.
//!
//! ## The gate lives in the mount-visible in-garden config
//!
//! The fleet config is read from the in-garden `config/growlight.toml`
//! (`<garden_root>/config/growlight.toml`), served *through* the FUSE mount —
//! the same way growlightd already reads `protocol.md` and the backlog. This is
//! the bug-fix at the heart of the `growlight-config-in-garden` milestone: the
//! config previously lived in the `.softfig/keeper.toml` bootstrap pointer, but
//! the FUSE mount keeperd projects over the garden root *shadows* `.softfig/`
//! while unlocked, so growlightd's post-mount read always hit ENOENT and the
//! fleet could never arm on a running garden. The in-garden config is
//! mount-visible, encrypted-at-rest, versioned, M5b-synced, and editable live
//! (softfig-mcp or through the mount) — no lock/unmount dance to arm it.
//!
//! The gate is intentionally **agent-writable** now (it rides garden content):
//! the old "a human must be present to arm" property is deliberately dropped in
//! favour of the budget halts + `pause` as the runaway protection. See
//! `journal/decisions/decision-growlight-config-in-garden.md`.
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
use softfig_ipc as ipc;

use crate::admission::AdmissionGovernor;
use crate::baton_store::FsBatonStore;
use crate::config::BuildCaps;
use crate::claim::{KeeperdItemParker, KeeperdPartClaimer};
use crate::claude_backend::ClaudeBackend;
use crate::daemon::Daemon;
use crate::drive_loop::{
    spawn_drive_loop, DriveLoop, FleetMember, LiveRate, RouteConnectivity, SystemExeProbe,
    DRIVE_POLL_MS,
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

/// One configured fleet member as read from a `[[fleet]]` table. The
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

/// The parsed `config/growlight.toml` fleet config: the off-by-default `enabled`
/// gate, the shared-backend `bin`/`prompt`, and the configured `members`. The
/// keys are top-level (this is a dedicated file, not a table inside a shared one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetConfig {
    /// `fleet_enabled` — off by default; the live-capability gate.
    pub enabled: bool,
    /// `claude_bin` — the backend's `claude` binary.
    pub bin: String,
    /// `prompt` — the generic per-agent turn kick.
    pub prompt: String,
    /// `[[fleet]]` members, in config order. Raw `{agent, pin}` — the runtime
    /// `AgentSpec` paths are derived at [`assemble_fleet`] (they need the runtime
    /// `agents_dir`, not known at parse).
    pub members: Vec<FleetMemberConfig>,
    /// `[build_caps]` — the GENTLE per-agent build-resource throttle applied to
    /// each agent's transient scope (slice 002). A missing table ⇒
    /// [`BuildCaps::default`] (conservative for the 7.7 GB tablet). Threaded into
    /// the backend so [`crate::claude_backend::ClaudeBackend`] caps every spawn.
    pub build_caps: BuildCaps,
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
            build_caps: BuildCaps::default(),
        }
    }

    /// Parse a `config/growlight.toml` document (top-level keys + `[[fleet]]`
    /// members). An empty document yields [`disabled`](Self::disabled) (every
    /// field defaults); an out-of-shape document is an `Err` the loader treats as
    /// fail-closed (a config problem can never *enable* the fleet).
    pub fn from_growlight_toml(s: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Doc {
            #[serde(default)]
            fleet_enabled: bool,
            claude_bin: Option<String>,
            prompt: Option<String>,
            #[serde(default)]
            fleet: Vec<FleetMemberConfig>,
            #[serde(default)]
            build_caps: BuildCaps,
        }
        let doc: Doc =
            toml::from_str(s).map_err(|e| format!("parse {}: {e}", ipc::GROWLIGHT_CONFIG_FILE))?;
        // Reject-not-clamp at the config boundary (hardening slice 005): the agent id
        // becomes the systemd scope unit (`growlight-agent-<id>`) and the key into
        // every per-agent map, but it comes straight from the user-edited
        // `[[fleet]]` table. `scope_base_name` sanitizes non-slug chars MANY-TO-ONE
        // (`build.a`/`build-a`/`build/a` all collapse), and a duplicate `agent` shares
        // a name — silently colliding scopes (cross-talk on set-property/kill, the
        // second member fail-closed-never-spawns). Validate here so a valid config
        // never exercises that lossy path; fail-closed (load treats Err as disabled).
        validate_fleet_member_ids(&doc.fleet)?;
        Ok(Self {
            enabled: doc.fleet_enabled,
            bin: doc.claude_bin.unwrap_or_else(|| DEFAULT_CLAUDE_BIN.to_string()),
            prompt: doc.prompt.unwrap_or_else(|| DEFAULT_PROMPT.to_string()),
            members: doc.fleet,
            build_caps: doc.build_caps,
        })
    }
}

/// Reject a `[[fleet]]` roster whose agent ids aren't canonical slugs or aren't
/// unique (hardening slice 005, `scope-name-collision-from-sanitize`). A valid id
/// is non-empty and `[a-z0-9-]` only — the same charset the scope unit name is
/// built from, so it survives `scope_base_name` UNCHANGED (no lossy many-to-one
/// `-` mapping). Duplicates are rejected because two members would share a scope
/// unit AND a per-agent map key. Fail-closed: any violation is an `Err` the loader
/// turns into a disabled fleet.
fn validate_fleet_member_ids(members: &[FleetMemberConfig]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for m in members {
        let id = &m.agent;
        let is_slug = !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !is_slug {
            return Err(format!(
                "fleet agent id {id:?} is not a valid slug — use lowercase letters, \
                 digits, and '-' only (non-empty)"
            ));
        }
        if !seen.insert(id) {
            return Err(format!(
                "duplicate fleet agent id {id:?} — each [[fleet]] member needs a unique id"
            ));
        }
    }
    Ok(())
}

/// Load the fleet config from the in-garden `config/growlight.toml`, read
/// *through the FUSE mount* (the same client-side plain read growlightd uses for
/// `protocol.md`/the backlog — never the FUSE-shadowed `.softfig/` pointer that
/// caused the mount-shadow bug). Fail-closed: an absent file, an unreadable one,
/// or a malformed document all yield [`FleetConfig::disabled`] (with a stderr
/// warning for the malformed case), so a config problem can never *enable* the
/// fleet.
pub fn load_fleet_config(garden_root: &Path) -> FleetConfig {
    let path = garden_root
        .join(ipc::GARDEN_CONFIG_DIR)
        .join(ipc::GROWLIGHT_CONFIG_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => return FleetConfig::disabled(), // absent/unreadable ⇒ no fleet
    };
    match FleetConfig::from_growlight_toml(&raw) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!(
                "softfig-growlightd: ignoring malformed fleet config at {} ({e}); fleet stays OFF",
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
    // The garden's directory name — a cosmetic `loop:` tag in the seed baton,
    // matching the single-agent baton's frontmatter. Derived before `garden_root`
    // is moved into the pre-approval context below.
    let garden_name = garden_root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| PILLAR.to_string());
    let preapproval = PreApproval::new(
        agents_dir.clone(),
        // The FLEET variant (no self-pull) — every member growlightd spawns is a
        // fleet member; the orchestrator owns continuation (slice 002).
        fleet_protocol(&garden_root),
        garden_root,
        softfig_mcp_path(),
        claude_dir(),
    );

    // One per-member baton store over the SAME runtime `agents/` namespace the
    // pre-approval generator writes each agent's `loop.json` into (and `inject.sh`
    // cats `baton.md` from). It is BOTH the seeder (the fresh-start baton write, so
    // a member boots with its baton, not `(no baton yet)`) AND the
    // `BatonStatusSource` slice 001 reads on exit — one store cloned into both
    // boxes, so the file the seeder writes and the file the reader parses can never
    // drift. `FsBatonStore` is a cheap `Clone` (two paths + a name), so no `Arc`.
    let baton_store = FsBatonStore::new(agents_dir.clone(), garden_name);

    // One backend, shared many ways (the `DriveLoop::new` contract): the
    // supervisor spawns through it, and health + stderr + budget + rate are read
    // off the SAME per-agent cells it populates.
    let backend = Arc::new(ClaudeBackend::new(
        fleet.bin.clone(),
        fleet.prompt.clone(),
        hub.clone(),
        preapproval,
        // The GENTLE per-agent build throttle (slice 002): every spawn's scope is
        // capped to slow — never kill — a building agent. Shared by Arc with the
        // daemon (peer-isolation slice 003) so `set_resources` adjusts the
        // next-spawn throttle live; the daemon's cell was seeded from
        // `fleet.build_caps` at `set_fleet_config`, so the backend reads the
        // configured value (and any subsequent live change) off this same cell.
        Arc::clone(&daemon.build_caps),
        // The live agent→running-scope registry (peer-isolation hardening slice
        // 002): each spawn records its generation-suffixed `.scope` unit here so
        // `set_resources` pushes onto the actually-running scopes. Shared by Arc
        // with the daemon, like `build_caps`.
        Arc::clone(&daemon.live_scopes),
        // The live agent→kill-handle registry (audit slice 005): each spawn
        // records its kill handle here so `force_stop --hard-kill` /
        // `request_restart` reach the running agent. Shared by Arc with the
        // daemon (it owns the registry `hard_kill_agent` drains), like `live_scopes`.
        Arc::clone(&daemon.kill_handles),
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
        Box::new(Arc::clone(&backend)), // stderr — live in-memory ring (crash-diagnostics slice 001)
        Box::new(baton_store.clone()), // baton  — live per-member read-back (fleet-loop-spin slice 002)
        Box::new(baton_store), // seeder — fresh-start baton seed (fleet-loop-spin slice 002)
        Box::new(KeeperdQueueSource::new(keeperd_socket.to_path_buf())), // queues — live (slice 002)
        Box::new(KeeperdPartClaimer::new(keeperd_socket.to_path_buf())), // claimer — live (slice 003)
        Box::new(KeeperdItemParker::new(keeperd_socket.to_path_buf())), // parker — live item-park (fleet-member-model slice 003)
        Box::new(Arc::clone(&backend)), // samples — live budget cell (drive-loop 003)
        Box::new(LiveRate::new(Arc::clone(&backend), daemon.rate_limits())), // rate — live TPM/RPM meter (slice 006)
        Box::new(RouteConnectivity), // connectivity — live kernel routing-table probe (network-failsafe slice 001)
        Box::new(SystemExeProbe::capture()), // exe_probe — re-stat growlightd's own launch binary (stale-binary guard, task 039)
        dispatcher,
        members,
    ))
}

/// The runtime growlight namespace root `$XDG_CONFIG_HOME/softfig/growlight`
/// (fallback `~/.config/...`) — the churny-runtime space `softfig growlight start`
/// owns (the runtime baton, `usage.json`, per-agent `agents/`), NOT the garden.
/// Derived from the environment, never a literal (spec §3/§12). Public so the
/// `baton` read verb ([`crate::server`]) can resolve the runtime baton path the
/// same way, independent of an assembled fleet (the verb answers even when the
/// fleet is disarmed).
pub fn runtime_growlight_dir() -> PathBuf {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home_dir().join(".config"),
    };
    base.join("softfig").join(PILLAR)
}

/// The runtime per-agent namespace `$XDG_CONFIG_HOME/softfig/growlight/agents`
/// (fallback `~/.config/...`) — the same churny-runtime space `softfig growlight
/// start` owns, NOT the garden. growlightd writes each agent's generated
/// pre-approval under `agents/<id>/` here.
fn runtime_agents_dir() -> PathBuf {
    runtime_growlight_dir().join("agents")
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

/// The fleet-member protocol filename within the pillar. growlightd injects the
/// fleet variant (no self-pull — the orchestrator owns the queue, slice 002),
/// distinct from the single-agent `protocol.md` that `softfig growlight start`
/// injects. growlightd only ever spawns fleet members, so this is the protocol
/// every pre-approval it generates carries.
const FLEET_PROTOCOL_FILE: &str = "protocol-fleet.md";

/// The garden path to the fleet-member protocol the SessionStart hook injects.
/// Pure + named so the fleet/single-agent split is a tested choice, not an inline
/// literal: a fleet member injects `protocol-fleet.md`, NEVER the single-agent
/// `protocol.md`.
fn fleet_protocol(garden_root: &Path) -> PathBuf {
    garden_root.join(PILLAR).join(FLEET_PROTOCOL_FILE)
}

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
        "[[fleet]]\nagent = \"a\"\n"
    }

    /// Write `<dir>/config/growlight.toml` with `body`, returning the garden root.
    fn write_config(dir: &Path, body: &str) {
        let cd = dir.join(ipc::GARDEN_CONFIG_DIR);
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(cd.join(ipc::GROWLIGHT_CONFIG_FILE), body).unwrap();
    }

    /// A stand-in keeperd socket for the assembly tests. Gate-off assembly never
    /// touches it (it returns before building the queue source); gate-on assembly
    /// only stores the path (the live pull happens on `tick`, which these tests do
    /// not call — the live source's read/parse paths are proven in `queue_source`).
    fn keeperd_socket() -> &'static Path {
        Path::new("/run/nonexistent-keeperd.sock")
    }

    #[test]
    fn fleet_members_inject_the_no_self_pull_fleet_protocol() {
        // growlightd only spawns fleet members, so the pre-approval protocol is the
        // fleet variant (protocol-fleet.md) — never the single-agent protocol.md
        // that `softfig growlight start` injects. This is the slice-002 split that
        // closes the self-pull double-assignment race.
        let p = fleet_protocol(Path::new("/garden"));
        assert_eq!(p, Path::new("/garden/growlight/protocol-fleet.md"));
        assert_ne!(
            p.file_name().unwrap(),
            "protocol.md",
            "a fleet member must NOT inject the single-agent self-pull protocol",
        );
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
        let cfg = FleetConfig::from_growlight_toml(&format!(
            "fleet_enabled = false\n{}",
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
        let cfg = FleetConfig::from_growlight_toml(&format!(
            "fleet_enabled = true\n{}",
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
        // pre-approval paths (slice 004), so the config no longer names them. The
        // keys are top-level: this is a dedicated `config/growlight.toml`, not a
        // table inside a shared file.
        let toml = r#"
fleet_enabled = true
claude_bin = "/usr/bin/claude"
prompt = "kick"

[[fleet]]
agent = "builder"
pin = "queue:build"

[[fleet]]
agent = "reviewer"
"#;
        let cfg = FleetConfig::from_growlight_toml(toml).expect("valid config");
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
    fn an_empty_config_is_the_disabled_default() {
        // An empty (or comment-only) config file — every field defaults — is the
        // off-by-default fleet, identical to `disabled()`.
        assert_eq!(FleetConfig::from_growlight_toml("").unwrap(), FleetConfig::disabled());
        assert_eq!(
            FleetConfig::from_growlight_toml("# just a comment\n").unwrap(),
            FleetConfig::disabled()
        );
    }

    #[test]
    fn bin_and_prompt_default_when_omitted() {
        let cfg = FleetConfig::from_growlight_toml("fleet_enabled = true\n").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.bin, DEFAULT_CLAUDE_BIN);
        assert_eq!(cfg.prompt, DEFAULT_PROMPT);
        assert!(cfg.members.is_empty());
    }

    #[test]
    fn build_caps_default_when_absent_and_parse_when_present() {
        // No `[build_caps]` table ⇒ the conservative 7.7 GB-tablet defaults.
        let cfg = FleetConfig::from_growlight_toml("fleet_enabled = true\n").unwrap();
        assert_eq!(cfg.build_caps, BuildCaps::default());

        // A full `[build_caps]` table parses every field through.
        let cfg = FleetConfig::from_growlight_toml(concat!(
            "fleet_enabled = true\n",
            "[build_caps]\n",
            "cargo_build_jobs = 4\n",
            "memory_high = \"5G\"\n",
            "cpu_weight = 80\n",
        ))
        .unwrap();
        assert_eq!(
            cfg.build_caps,
            BuildCaps {
                cargo_build_jobs: Some(4),
                memory_high: Some("5G".to_string()),
                cpu_weight: Some(80),
            }
        );

        // A PARTIAL `[build_caps]` table fills the unset fields from the defaults
        // (container `#[serde(default)]`), so a human can override just one knob.
        let cfg = FleetConfig::from_growlight_toml(concat!(
            "fleet_enabled = true\n",
            "[build_caps]\n",
            "memory_high = \"6G\"\n",
        ))
        .unwrap();
        assert_eq!(
            cfg.build_caps,
            BuildCaps {
                cargo_build_jobs: Some(2),
                memory_high: Some("6G".to_string()),
                cpu_weight: Some(50),
            },
            "an unset field falls back to the conservative default",
        );
    }

    #[test]
    fn a_malformed_config_is_an_error() {
        // `fleet_enabled` as a string, not a bool — the loader treats Err as
        // fail-closed, so this never enables the fleet.
        let r = FleetConfig::from_growlight_toml("fleet_enabled = \"yes\"\n");
        assert!(r.is_err(), "an out-of-shape config is rejected, not silently on");
    }

    #[test]
    fn load_is_disabled_when_the_config_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        // No `config/growlight.toml` under the garden root.
        assert_eq!(load_fleet_config(dir.path()), FleetConfig::disabled());
    }

    #[test]
    fn load_is_disabled_when_the_config_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "fleet_enabled = 3\n");
        // A broken config fails closed, not on.
        assert_eq!(load_fleet_config(dir.path()), FleetConfig::disabled());
    }

    #[test]
    fn load_reads_an_armed_config() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), &format!("fleet_enabled = true\n{}", member_toml()));
        let cfg = load_fleet_config(dir.path());
        assert!(cfg.enabled);
        assert_eq!(cfg.members.len(), 1);
    }

    #[test]
    fn non_slug_fleet_agent_ids_are_rejected_at_config_load() {
        // slice 005 (reject-not-clamp): an id that scope_base_name would sanitize
        // many-to-one is refused at load, not silently collapsed into a colliding
        // scope unit. A `.`, `/`, an empty id, or UPPERCASE each fail closed.
        for bad in ["build.a", "build/a", "", "UPPER", "has space", "under_score"] {
            let toml = format!("fleet_enabled = true\n[[fleet]]\nagent = \"{bad}\"\n");
            assert!(
                FleetConfig::from_growlight_toml(&toml).is_err(),
                "agent id {bad:?} is not a valid slug and must be rejected",
            );
        }
    }

    #[test]
    fn duplicate_fleet_agent_ids_are_rejected_at_config_load() {
        // Two members with the same id would share one scope unit AND one per-agent
        // map key — refused, not silently merged.
        let toml = concat!(
            "fleet_enabled = true\n",
            "[[fleet]]\nagent = \"a\"\n",
            "[[fleet]]\nagent = \"a\"\n",
        );
        assert!(
            FleetConfig::from_growlight_toml(toml).is_err(),
            "a duplicate agent id is rejected",
        );
    }

    #[test]
    fn a_clean_slug_roster_is_accepted() {
        let toml = concat!(
            "fleet_enabled = true\n",
            "[[fleet]]\nagent = \"a\"\n",
            "[[fleet]]\nagent = \"builder-2\"\n",
            "[[fleet]]\nagent = \"reviewer3\"\n",
        );
        let cfg = FleetConfig::from_growlight_toml(toml).expect("a clean slug roster is valid");
        assert_eq!(cfg.members.len(), 3);
    }
}
