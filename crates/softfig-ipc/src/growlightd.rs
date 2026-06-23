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
    /// `subscribe() -> stream<`[`Event`]`>`. The one *streaming* verb (spec §13
    /// Observe): instead of a single [`crate::Response`], the daemon holds the
    /// connection open and writes newline-framed [`Event`] JSON objects as they
    /// occur, until the client disconnects or the daemon stops. Clients decode
    /// each line as an [`Event`], not a [`crate::Response`].
    pub const SUBSCRIBE: &str = "subscribe";

    // --- Control family (spec §13 Control / §8 pings & control). Every control
    // verb is ONE-SHOT (a single [`crate::Response`]); only `subscribe` streams.
    // The state they set is *intent* the future drive loop reads at safe
    // handoff boundaries — there is no native mid-session injection (spec §8).

    /// `pause() -> `[`PausedReply`]. Flip the fleet admission gate on: the
    /// scheduler admits no new/rolling agents until `resume`. Idempotent.
    pub const PAUSE: &str = "pause";
    /// `resume() -> `[`PausedReply`]. Clear the admission gate. Idempotent.
    pub const RESUME: &str = "resume";
    /// `stop_after_slice(`[`StopAfterSliceArgs`]`) -> `[`StopReply`]. Record a
    /// graceful "shut down after the current slice" boundary intent for one
    /// agent (spec §8 level 1) — the drive loop honours it at the next handoff.
    pub const STOP_AFTER_SLICE: &str = "stop_after_slice";
    /// `force_stop(`[`ForceStopArgs`]`) -> `[`StopReply`]. The leveled stop
    /// (spec §8): `after_slice`/`after_iteration` record boundary intent;
    /// `hard_kill` interrupts immediately via the kill-safety path.
    pub const FORCE_STOP: &str = "force_stop";
    /// `inject_message(`[`InjectMessageArgs`]`) -> `[`InjectReply`]. Queue a
    /// message onto an agent's boundary-async inject lane — delivered at the
    /// agent's NEXT baton, never mid-iteration (spec §8).
    pub const INJECT_MESSAGE: &str = "inject_message";
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
    /// Whether the fleet admission gate is engaged (`pause`/`resume`, spec §8).
    /// Additive (`#[serde(default)]`) so a pre-control client/decoder that never
    /// sent this field still parses — it reads back as `false` (not paused).
    #[serde(default)]
    pub paused: bool,
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

/// One frame of the `subscribe` event stream (spec §13 Observe / §12 runtime
/// leverage). Internally tagged on `type` so a client matches on a single field
/// and new variants stay backward-compatible.
///
/// Producers arrive across phases: agent deltas + budgets with the
/// fleet (concurrency/admission milestones), leases with the scheduler, and
/// [`Event::BusMessage`] with the coordination-bus milestone. The bus variant is
/// defined here *now* so every client can already decode the stream — but
/// growlightd does **not** emit it in phase 1 (no bus exists yet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// A stream-json delta from one agent's `claude -p` run — the GUI's
    /// "what's it thinking now" source (spec §12). Carries one assistant-text,
    /// tool-call, or thinking-block fragment.
    AgentDelta {
        /// The agent (work-stream) the delta came from.
        agent: String,
        /// Which kind of stream-json block this fragment is.
        kind: AgentDeltaKind,
        /// The fragment text (assistant prose, a tool-call rendering, or a
        /// thinking-block excerpt).
        text: String,
    },
    /// An agent's (or the fleet's) budget reading changed — drives the GUI
    /// gauges and admission (spec §7). Context % is per-agent; the 5h/7d rolling
    /// reserves are the shared account-wide pool, so `agent` is `None` for those
    /// fleet-wide updates.
    BudgetChanged {
        /// The agent this reading is for, or `None` for a fleet-wide (account
        /// pool) update.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<String>,
        /// Context-window occupancy %, when this update carries one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ctx_pct: Option<u8>,
        /// 5h rolling-reserve %, when this update carries one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_5h_pct: Option<u8>,
        /// 7d rolling-reserve %, when this update carries one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_7d_pct: Option<u8>,
    },
    /// A shared-action lease changed hands (spec §4c — arrives with the
    /// scheduler milestone).
    LeaseChanged {
        /// The lease key (the shared resource / action being arbitrated).
        lease: String,
        /// The agent now holding the lease, or `None` if it was released.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        holder: Option<String>,
        /// Coarse lease state, e.g. "granted", "released", "waiting".
        state: String,
    },
    /// A message on the coordination bus (spec §13 Coordinate). **Not produced
    /// in phase 1** — the bus is the `growlight-coordination-bus` milestone; the
    /// variant exists here so clients can already decode the stream once it does.
    BusMessage {
        /// Sender — an agent id, or "human".
        from: String,
        /// Recipient — an agent id, "all", or "human".
        to: String,
        /// Message class (e.g. "note", "question", "alert").
        kind: String,
        /// The message body.
        body: String,
    },
}

impl Event {
    /// Construct an [`Event::AgentDelta`] — the common producer path (the
    /// stream-json tailer) and the one tests script.
    pub fn agent_delta(
        agent: impl Into<String>,
        kind: AgentDeltaKind,
        text: impl Into<String>,
    ) -> Self {
        Event::AgentDelta {
            agent: agent.into(),
            kind,
            text: text.into(),
        }
    }
}

/// Which stream-json block an [`Event::AgentDelta`] carries — the three kinds
/// `claude -p --output-format stream-json` makes observable (spec §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDeltaKind {
    /// Assistant-visible prose.
    Assistant,
    /// A tool invocation.
    ToolCall,
    /// A thinking-block fragment.
    Thinking,
}

// ---------------------------------------------------------------------------
// Control family (spec §8 / §13 Control). Args + replies for the one-shot
// pause/resume/stop/inject verbs. All boundary-async: a stop or inject sets
// *intent* the drive loop honours at the next handoff, never mid-iteration.
// ---------------------------------------------------------------------------

/// The three levels of `force_stop` (spec §8).
///
/// The first two are **boundary intents** the drive loop honours at a safe
/// handoff; [`StopLevel::HardKill`] is the escape hatch that interrupts
/// **immediately** and therefore must ride the kill-safety discipline (take the
/// child handle out under the daemon lock, then SIGKILL OUTSIDE it — the keeperd
/// `force_release_mount` / commit-from-memory lesson, incident 20260622).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopLevel {
    /// Graceful: stop after the agent finishes its current slice (spec §8 #1).
    AfterSlice,
    /// Graceful: stop after the agent finishes its current iteration (§8 #2).
    AfterIteration,
    /// Immediate: kill the `claude -p` child now and (later) re-roll it (§8 #3).
    HardKill,
}

impl StopLevel {
    /// Whether this level acts immediately (only [`StopLevel::HardKill`]) rather
    /// than recording a boundary intent the drive loop reads at the next handoff.
    pub fn is_immediate(self) -> bool {
        matches!(self, StopLevel::HardKill)
    }
}

/// Args for `stop_after_slice`: the agent to wind down after its current slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopAfterSliceArgs {
    /// The target agent (work-stream) id.
    pub agent: String,
}

/// Args for `force_stop`: the agent and the [`StopLevel`] to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceStopArgs {
    /// The target agent (work-stream) id.
    pub agent: String,
    /// Which stop level to apply.
    pub level: StopLevel,
}

/// Args for `inject_message`: the agent and the message to queue onto its
/// boundary-async inject lane (delivered at its NEXT baton, spec §8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectMessageArgs {
    /// The target agent (work-stream) id.
    pub agent: String,
    /// The message body to deliver at the agent's next handoff.
    pub message: String,
}

/// Reply to `pause` / `resume`: the resulting admission-gate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PausedReply {
    /// `true` after `pause`, `false` after `resume`.
    pub paused: bool,
}

/// Reply to `stop_after_slice` / `force_stop`: which agent + level was applied,
/// and whether it acted immediately (`hard_kill`) or recorded a boundary intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopReply {
    /// The agent the stop was applied to.
    pub agent: String,
    /// The level applied.
    pub level: StopLevel,
    /// `true` if it acted now (`hard_kill`); `false` if it recorded a boundary
    /// intent the drive loop honours at the next handoff.
    pub immediate: bool,
}

/// Reply to `inject_message`: the agent and its inject-lane depth after the
/// append (how many messages are now queued for the agent's next baton).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectReply {
    /// The agent the message was queued for.
    pub agent: String,
    /// Number of messages now waiting in the agent's inject lane.
    pub queued: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_delta_round_trips_tagged() {
        let e = Event::agent_delta("loop-1", AgentDeltaKind::Thinking, "hmm");
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"type\":\"agent_delta\""), "tagged on type: {s}");
        assert!(s.contains("\"kind\":\"thinking\""), "kind is snake_case: {s}");
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn bus_message_decodes_even_though_phase1_never_emits_it() {
        let e = Event::BusMessage {
            from: "human".into(),
            to: "all".into(),
            kind: "note".into(),
            body: "hi".into(),
        };
        let back: Event = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn budget_changed_omits_absent_fields() {
        let e = Event::BudgetChanged {
            agent: Some("a1".into()),
            ctx_pct: Some(42),
            session_5h_pct: None,
            session_7d_pct: None,
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"ctx_pct\":42"));
        assert!(!s.contains("session_5h_pct"), "absent optionals are skipped: {s}");
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn lease_changed_round_trips() {
        let e = Event::LeaseChanged {
            lease: "snapshot:packages".into(),
            holder: None,
            state: "released".into(),
        };
        let back: Event = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn stop_level_is_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&StopLevel::AfterSlice).unwrap(),
            "\"after_slice\""
        );
        assert_eq!(
            serde_json::to_string(&StopLevel::HardKill).unwrap(),
            "\"hard_kill\""
        );
        let back: StopLevel = serde_json::from_str("\"after_iteration\"").unwrap();
        assert_eq!(back, StopLevel::AfterIteration);
    }

    #[test]
    fn only_hard_kill_is_immediate() {
        assert!(StopLevel::HardKill.is_immediate());
        assert!(!StopLevel::AfterSlice.is_immediate());
        assert!(!StopLevel::AfterIteration.is_immediate());
    }

    #[test]
    fn force_stop_args_round_trip() {
        let a = ForceStopArgs {
            agent: "loop-1".into(),
            level: StopLevel::HardKill,
        };
        let s = serde_json::to_string(&a).unwrap();
        let back: ForceStopArgs = serde_json::from_str(&s).unwrap();
        assert_eq!(back.agent, "loop-1");
        assert_eq!(back.level, StopLevel::HardKill);
    }

    #[test]
    fn control_replies_round_trip() {
        let p = PausedReply { paused: true };
        assert_eq!(
            serde_json::from_str::<PausedReply>(&serde_json::to_string(&p).unwrap()).unwrap(),
            p
        );
        let s = StopReply {
            agent: "a1".into(),
            level: StopLevel::AfterSlice,
            immediate: false,
        };
        assert_eq!(
            serde_json::from_str::<StopReply>(&serde_json::to_string(&s).unwrap()).unwrap(),
            s
        );
        let i = InjectReply {
            agent: "a1".into(),
            queued: 2,
        };
        assert_eq!(
            serde_json::from_str::<InjectReply>(&serde_json::to_string(&i).unwrap()).unwrap(),
            i
        );
    }

    #[test]
    fn fleet_status_paused_defaults_when_a_pre_control_client_omits_it() {
        // A decoder that predates the control family never sends `paused`; the
        // additive `#[serde(default)]` must read it back as `false`.
        let json = r#"{
            "state": "running",
            "garden_root": "/g",
            "protocol_version": 1,
            "policy": {
                "max_concurrent_agents": 2,
                "ctx_roll_pct": 50,
                "ctx_handoff_pct": 60,
                "session_5h_halt_pct": 85,
                "session_7d_halt_pct": 90
            }
        }"#;
        let reply: FleetStatusReply = serde_json::from_str(json).unwrap();
        assert!(!reply.paused, "missing paused decodes as not-paused");
        assert!(reply.agents.is_empty());
    }
}
