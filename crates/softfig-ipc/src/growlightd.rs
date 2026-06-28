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
    /// `set_policy(`[`SetPolicyArgs`]`) -> `[`PolicySummary`]. Replace the active
    /// per-device policy — the GUI tweak-knobs panel (budgets,
    /// `max_concurrent_agents`, active queues; spec §11/§13 Control). The reply
    /// echoes the applied [`PolicySummary`].
    ///
    /// **Wire contract only, for now.** The string + args live here so every
    /// client (the iced GUI's knobs panel) is ready, but **the daemon handler
    /// arrives with the admission governor (phase 6)**: today the policy is a
    /// startup config field (`config.policy`), and the live surface a runtime
    /// `set_policy` mutates is the governor's — which is the deferred phase-6
    /// wiring. Until then growlightd answers `unknown op`. This mirrors the
    /// bus/coordinate types defined here ahead of their producers.
    pub const SET_POLICY: &str = "set_policy";
    /// `resume_item(`[`ResumeItemArgs`]`) -> `[`ResumeItemReply`]. Un-block a
    /// human-blocked backlog item (`blocked → queued`) so the scheduler re-picks
    /// it — the inverse of the drive loop's item-park (fleet-member-model slice
    /// 003). **Distinct from [`RESUME`]**, which clears the fleet-wide admission
    /// gate; this acts on ONE queue item. growlightd reads the item's current
    /// status from keeperd and only un-blocks a currently-`blocked` item (the
    /// guard — a missing / non-blocked / ambiguous item comes back as an error),
    /// then flips it via keeperd's `set_item_status` (reusing the `item_status_set`
    /// commit intent; no new intent). One-shot.
    pub const RESUME_ITEM: &str = "resume_item";

    // --- Coordinate family (spec §13 Coordinate / §4c leases). Agent-facing:
    // these are the arbitrated shared-action verbs (spec §14, also reachable via
    // MCP). growlightd grants/queues/denies; a granted restart is performed by
    // the DAEMON, never by an agent.

    /// `request_lease(`[`RequestLeaseArgs`]`) -> `[`LeaseReply`]. Request a lease
    /// over a shared resource/action (spec §4c). Free → granted; held by another
    /// → queued (FIFO); held by the requester → idempotently granted. A granted
    /// lease over a thrash-flagged target clears that flag (§4d ladder rung 2).
    pub const REQUEST_LEASE: &str = "request_lease";
    /// `release_lease(`[`ReleaseLeaseArgs`]`) -> `[`LeaseReply`]. Release a lease
    /// the caller holds; the head waiter (if any) is promoted to holder. A
    /// release by a non-holder is refused.
    pub const RELEASE_LEASE: &str = "release_lease";
    /// `request_restart(`[`RequestRestartArgs`]`) -> `[`RestartReply`]. Ask
    /// growlightd to restart another agent (spec §4c/§8). Arbitrated through a
    /// restart lease over the target: granted → the DAEMON performs the kill
    /// under the kill-safety discipline; already in flight → queued; targeting
    /// the requester itself → denied (use `force_stop`).
    pub const REQUEST_RESTART: &str = "request_restart";
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
    /// Whether the in-garden `config/growlight.toml` `fleet_enabled` gate is on
    /// (config-in-garden milestone). Distinct from `paused`: `fleet_enabled` is
    /// the config-level arm/disarm (off ⇒ growlightd assembled no drive loop at
    /// all), `paused` is the runtime admission gate over an armed fleet. Additive
    /// (`#[serde(default)]`) so a pre-field decoder reads it back as `false`.
    #[serde(default)]
    pub fleet_enabled: bool,
    /// The configured roster from `config/growlight.toml` (`[[fleet]]` members),
    /// in config order — surfaced so `growlight status` lists the fleet even when
    /// the gate is off (the agents haven't spawned). Additive/defaulted for wire
    /// back-compat. Distinct from `agents` (the *live* per-agent runtime state).
    #[serde(default)]
    pub roster: Vec<FleetMemberSummary>,
    /// Per-agent summaries. Empty in phase 1 — the fleet arrives with the
    /// scheduler/concurrency milestones.
    #[serde(default)]
    pub agents: Vec<AgentSummary>,
}

/// One configured roster member echoed in [`FleetStatusReply::roster`] — the
/// agent id + its optional pinned queue, as declared in `config/growlight.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetMemberSummary {
    /// The agent's work-stream id (the `@`-stripped name).
    pub agent: String,
    /// The queue this member is pinned to, or `None` for a fallback-only member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
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

    /// Construct an [`Event::BusMessage`] — the coordination-bus producer path
    /// the growlightd bus bridge fans onto `subscribe` (and the §9 alert hook
    /// rides the same stream, an alert being just `kind == "alert"`). `kind` is
    /// the chat wire token passed straight through as the class; `from`/`to` are
    /// the bus addresses with the `@` sigil stripped (`@all` → `all`,
    /// `@human` → `human`) to match this variant's documented address form.
    pub fn bus_message(
        from: impl Into<String>,
        to: impl Into<String>,
        kind: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Event::BusMessage {
            from: from.into(),
            to: to.into(),
            kind: kind.into(),
            body: body.into(),
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

/// Args for `set_policy`: the full replacement [`PolicySummary`] the GUI
/// tweak-knobs panel applies (spec §11/§13). The whole policy is sent (not a
/// diff) so the wire op is idempotent and order-free; the reply echoes the
/// applied [`PolicySummary`]. (The daemon handler is deferred to the
/// admission-governor phase — see [`op::SET_POLICY`].)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetPolicyArgs {
    /// The policy to apply, replacing the running one.
    pub policy: PolicySummary,
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

/// Args for `resume_item`: the backlog item to un-block, and an optional `queue`
/// to disambiguate when the same id exists in more than one queue. Omit `queue`
/// to let growlightd resolve the id across every queue (unique today) — an
/// ambiguous id with no `queue` comes back as a `BadArgs` error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeItemArgs {
    /// The blocked item's queue id (milestone slug or task `NNN`).
    pub item: String,
    /// Which queue the item lives in, or `None` to resolve it across all queues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
}

/// Reply to `resume_item`: which item in which queue was un-blocked, its
/// resulting status (always `"queued"`), and whether THIS call performed the
/// flip (`resumed: true`) or the item was already `queued` — an idempotent no-op
/// (`resumed: false`). A missing / non-blocked / ambiguous item is reported as a
/// `Response::Err` (the guard), not this reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeItemReply {
    /// The item the resume acted on.
    pub item: String,
    /// The queue the item was resolved in.
    pub queue: String,
    /// The item's status after the call — `"queued"`.
    pub status: String,
    /// `true` if this call flipped `blocked → queued`; `false` if it was already
    /// `queued` (idempotent no-op).
    pub resumed: bool,
}

// ---------------------------------------------------------------------------
// Coordinate family (spec §4c leases / §13 Coordinate / §14 MCP). Args + the
// shared `LeaseReply` for `request_lease`/`release_lease`, plus the restart
// verb's args + reply. `state` is a documented string (matching
// [`Event::LeaseChanged`]'s `state`) so a new outcome never needs a wire-enum
// version bump.
// ---------------------------------------------------------------------------

/// Args for `request_lease`: the requesting agent and the lease key (the shared
/// resource/action — for a contended garden section, the thrash target label
/// `"path §heading"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLeaseArgs {
    /// The requesting agent (work-stream) id.
    pub agent: String,
    /// The lease key naming the shared resource/action being arbitrated.
    pub key: String,
}

/// Args for `release_lease`: the holder releasing the lease and the key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseLeaseArgs {
    /// The agent releasing the lease (must be the current holder).
    pub agent: String,
    /// The lease key being released.
    pub key: String,
}

/// Reply to `request_lease` / `release_lease`: the key, the resulting `state`,
/// the holder after the call, and (when queued) the caller's 1-based wait slot.
///
/// `state` is one of `"granted"` (the caller now holds it), `"waiting"` (queued
/// behind the holder), `"released"` (the caller released; `holder` is the
/// promoted waiter or `None` if now free), or `"denied"` (refused — e.g. a
/// release by a non-holder; `reason` explains).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseReply {
    /// The lease key this reply concerns.
    pub key: String,
    /// Coarse outcome: `granted` | `waiting` | `released` | `denied`.
    pub state: String,
    /// The lease holder after the call (the caller on `granted`; the promoted
    /// waiter or `None` on `released`; the existing holder on `waiting`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// The caller's 1-based slot in the wait queue, present only when `waiting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<usize>,
    /// Why the request was denied, present only when `state == "denied"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Args for `request_restart`: who is asking and which agent to restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRestartArgs {
    /// The agent requesting the restart.
    pub requester: String,
    /// The agent to restart (must differ from `requester` — self-restart is
    /// denied; use `force_stop`).
    pub target: String,
}

/// Reply to `request_restart`: the target, the outcome `state`, and whether the
/// daemon actually killed a live child.
///
/// `state` is `"restarted"` (the restart lease was granted and the DAEMON
/// performed the kill), `"queued"` (another restart of the same target is in
/// flight — the caller waits), or `"denied"` (refused — e.g. a self-restart;
/// `reason` explains).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartReply {
    /// The agent the restart was requested for.
    pub target: String,
    /// Coarse outcome: `restarted` | `queued` | `denied`.
    pub state: String,
    /// Whether a live child was present and killed by the daemon. `false` when
    /// queued/denied, and (in production today) when no agent is live behind the
    /// target — the arbitration still ran.
    pub performed: bool,
    /// Why the request was denied, present only when `state == "denied"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    fn set_policy_args_round_trip_with_the_full_policy() {
        let a = SetPolicyArgs {
            policy: PolicySummary {
                max_concurrent_agents: 3,
                ctx_roll_pct: 50,
                ctx_handoff_pct: 60,
                session_5h_halt_pct: 85,
                session_7d_halt_pct: 90,
            },
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("\"max_concurrent_agents\":3"), "carries the knobs: {s}");
        let back: SetPolicyArgs = serde_json::from_str(&s).unwrap();
        assert_eq!(back.policy, a.policy);
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
    fn resume_item_args_round_trip_with_and_without_a_queue() {
        // No queue: omitted on the wire (skip_serializing_if), decodes as None.
        let a = ResumeItemArgs {
            item: "019".into(),
            queue: None,
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(!s.contains("queue"), "absent queue is skipped: {s}");
        let back: ResumeItemArgs = serde_json::from_str(&s).unwrap();
        assert_eq!(back.item, "019");
        assert_eq!(back.queue, None);

        // With a queue: it disambiguates a cross-queue id.
        let a = ResumeItemArgs {
            item: "019".into(),
            queue: Some("queue:build".into()),
        };
        let back: ResumeItemArgs =
            serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(back.queue.as_deref(), Some("queue:build"));
    }

    #[test]
    fn resume_item_reply_round_trips_performed_and_noop() {
        let performed = ResumeItemReply {
            item: "019".into(),
            queue: "default".into(),
            status: "queued".into(),
            resumed: true,
        };
        assert_eq!(
            serde_json::from_str::<ResumeItemReply>(&serde_json::to_string(&performed).unwrap())
                .unwrap(),
            performed,
        );
        // The idempotent no-op (already queued) carries resumed: false.
        let noop = ResumeItemReply {
            item: "019".into(),
            queue: "default".into(),
            status: "queued".into(),
            resumed: false,
        };
        let back: ResumeItemReply =
            serde_json::from_str(&serde_json::to_string(&noop).unwrap()).unwrap();
        assert!(!back.resumed);
    }

    #[test]
    fn lease_args_round_trip() {
        let req = RequestLeaseArgs {
            agent: "a".into(),
            key: "dock.rs §Layout".into(),
        };
        let back: RequestLeaseArgs =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.agent, "a");
        assert_eq!(back.key, "dock.rs §Layout");

        let rr = RequestRestartArgs {
            requester: "a".into(),
            target: "b".into(),
        };
        let back: RequestRestartArgs =
            serde_json::from_str(&serde_json::to_string(&rr).unwrap()).unwrap();
        assert_eq!(back.requester, "a");
        assert_eq!(back.target, "b");
    }

    #[test]
    fn lease_reply_skips_absent_optionals_and_round_trips() {
        // A granted reply carries a holder but no position/reason.
        let granted = LeaseReply {
            key: "k".into(),
            state: "granted".into(),
            holder: Some("a".into()),
            position: None,
            reason: None,
        };
        let s = serde_json::to_string(&granted).unwrap();
        assert!(s.contains("\"state\":\"granted\""));
        assert!(!s.contains("position"), "absent optionals are skipped: {s}");
        assert!(!s.contains("reason"));
        assert_eq!(serde_json::from_str::<LeaseReply>(&s).unwrap(), granted);

        // A waiting reply carries holder + position.
        let waiting = LeaseReply {
            key: "k".into(),
            state: "waiting".into(),
            holder: Some("a".into()),
            position: Some(2),
            reason: None,
        };
        let back: LeaseReply =
            serde_json::from_str(&serde_json::to_string(&waiting).unwrap()).unwrap();
        assert_eq!(back, waiting);
    }

    #[test]
    fn restart_reply_round_trips_with_and_without_a_reason() {
        let restarted = RestartReply {
            target: "b".into(),
            state: "restarted".into(),
            performed: true,
            reason: None,
        };
        let s = serde_json::to_string(&restarted).unwrap();
        assert!(!s.contains("reason"), "no reason on success: {s}");
        assert_eq!(serde_json::from_str::<RestartReply>(&s).unwrap(), restarted);

        let denied = RestartReply {
            target: "b".into(),
            state: "denied".into(),
            performed: false,
            reason: Some("an agent cannot restart itself".into()),
        };
        let back: RestartReply =
            serde_json::from_str(&serde_json::to_string(&denied).unwrap()).unwrap();
        assert_eq!(back, denied);
    }

    #[test]
    fn fleet_status_paused_defaults_when_a_pre_control_client_omits_it() {
        // A decoder that predates the control family never sends `paused`; the
        // additive `#[serde(default)]` must read it back as `false`. The
        // config-in-garden `fleet_enabled`/`roster` fields are likewise additive,
        // so the SAME pre-field payload must still parse with both defaulted.
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
        assert!(!reply.fleet_enabled, "missing fleet_enabled decodes as off");
        assert!(reply.roster.is_empty(), "missing roster decodes as empty");
        assert!(reply.agents.is_empty());
    }

    #[test]
    fn fleet_status_round_trips_gate_and_roster() {
        let reply = FleetStatusReply {
            state: "running".into(),
            garden_root: "/g".into(),
            protocol_version: 1,
            policy: PolicySummary {
                max_concurrent_agents: 2,
                ctx_roll_pct: 50,
                ctx_handoff_pct: 60,
                session_5h_halt_pct: 85,
                session_7d_halt_pct: 90,
            },
            paused: false,
            fleet_enabled: true,
            roster: vec![
                FleetMemberSummary { agent: "builder".into(), pin: Some("queue:build".into()) },
                FleetMemberSummary { agent: "reviewer".into(), pin: None },
            ],
            agents: Vec::new(),
        };
        let back: FleetStatusReply =
            serde_json::from_str(&serde_json::to_string(&reply).unwrap()).unwrap();
        assert!(back.fleet_enabled);
        assert_eq!(back.roster.len(), 2);
        assert_eq!(back.roster[0].agent, "builder");
        assert_eq!(back.roster[0].pin.as_deref(), Some("queue:build"));
        assert_eq!(back.roster[1].pin, None);
    }
}
