//! growlightd's wire contract — the op names and reply payloads its clients
//! (the CLI, the iced GUI, the phone) speak over its own Unix socket.
//!
//! growlightd is the multi-agent orchestrator daemon
//! (`meta/spec-growlight-orchestrator.md` §2/§13): a *separate* process from
//! keeperd that owns the agent fleet. It reuses the shared JSON-Lines envelope
//! ([`crate::Request`] / [`crate::Response`] / [`crate::ErrorKind`]) — the same
//! "keeperd-style" framing — but on a distinct socket with its own verbs. These
//! live here (not in `softfig-keeperd`) for the same reason the keeperd verbs do:
//! the wire types are shared by the daemon and every client, so neither side has
//! to depend on the other's crate.
//!
//! Phase 1 (slice 001) defines only `status` + `shutdown`; later slices add the
//! observe/control/coordinate families (spec §13).

use serde::{Deserialize, Serialize};

/// growlightd op names. Distinct namespace from the keeperd [`crate::op`]
/// module even where the string coincides (`status`) — they ride different
/// sockets.
pub mod op {
    /// `status() -> FleetStatusReply`. Fleet + per-agent snapshot. Always
    /// answerable. Phase-1 fleet is empty (no agents yet).
    pub const STATUS: &str = "status";
    /// `shutdown() -> {}`. Orderly daemon teardown. The ack is flushed before
    /// the accept loop winds down (ack-before-teardown, mirroring keeperd).
    pub const SHUTDOWN: &str = "shutdown";
}

/// Reply to `status`: the orchestrator's own state, the garden root it derived
/// from keeperd, the active per-device policy, and the (phase-1: empty) fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStatusReply {
    /// "running" or "stopping".
    pub state: String,
    /// Garden root growlightd derived from the keeperd `status` handshake
    /// (never a literal path — spec §12).
    pub garden_root: String,
    /// growlightd's own IPC protocol version (the shared [`crate::PROTOCOL_VERSION`]).
    pub protocol_version: u8,
    /// The active per-device policy (budget thresholds + concurrency cap).
    pub policy: PolicySummary,
    /// Per-agent summaries. Empty in phase 1 — the fleet arrives with the
    /// scheduler/concurrency milestones.
    #[serde(default)]
    pub agents: Vec<AgentSummary>,
}

/// Per-agent line in [`FleetStatusReply::agents`]. Intentionally minimal for
/// phase 1 (the fleet is empty); fleshed out by the observe + scheduler slices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    /// Stable agent id (queue/work-stream tag).
    pub id: String,
    /// Coarse lifecycle label (e.g. "idle", "running", "paused").
    pub status: String,
}

/// The per-device policy growlightd runs under, echoed in `status`. Mirrors
/// [`crate::PROTOCOL_VERSION`]-stable budget knobs from spec §7 plus the §17
/// concurrency cap; the GUI's tweak panel (spec §11) edits these.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySummary {
    /// Max agents the device runs at once (spec §7/§17; default ~2).
    pub max_concurrent_agents: u32,
    /// Context-window % at which an agent finishes its atomic step then rolls.
    pub ctx_roll_pct: u8,
    /// Context-window % at which an agent hands off immediately.
    pub ctx_handoff_pct: u8,
    /// 5h rolling-reserve % at which admission halts new/rolling agents.
    pub session_5h_halt_pct: u8,
    /// 7d rolling-reserve % halt threshold.
    pub session_7d_halt_pct: u8,
}
