//! Fleet **supervision** (phase 6, slice 002) — spawn, observe, and re-roll N
//! concurrent agents behind the [`AgentBackend`] seam, with capped-backoff crash
//! recovery, all gated by the global [`AdmissionGovernor`]
//! (spec-growlight-orchestrator §15 operational must-haves, §12 runtime/backend
//! seam, §7 admission).
//!
//! ## What this is (and isn't)
//!
//! Two pieces, in this crate's established shape:
//!
//! 1. A **spawn seam** — [`AgentBackend::spawn`] turns a per-agent [`AgentSpec`]
//!    (its bus id + the pre-approval `loop.json`/`mcp.json` paths) into a live
//!    [`AgentChild`] handle. **The live binding is deferred**, exactly like
//!    [`crate::leases::ThrashClear`] / [`crate::notify_dispatch::BusEmit`]: the
//!    real backend shells `claude -p --output-format stream-json` per agent (the
//!    §12 backend decision — single-language Rust, a clean per-agent SIGKILL for
//!    the §8 hard-kill, `loop.json` covering permissions because headless
//!    **errors out** on a prompt, it does not pause). That subprocess plumbing
//!    rides the phase-6 drive loop; here only a fake backend exists, so the
//!    supervision policy is provable with no real process, no clock, no socket.
//! 2. A **supervisor manager** — [`Supervisor`] owns the backend seam, the
//!    [`AdmissionGovernor`], and the per-agent fleet state. It is *not* a daemon:
//!    the drive loop drives it ([`start`](Supervisor::start) on demand,
//!    [`poll`](Supervisor::poll) on each health observation,
//!    [`tick`](Supervisor::tick) each cycle), so it carries no thread/lock of its
//!    own — the kill-outside-the-lock contract ([`AgentChild`]) holds because the
//!    drive loop runs it off the connection mutex.
//!
//! The pure backoff math lives in [`Backoff`]; the health classification is a
//! pure function of the observation + the hang threshold + `now`. Time is
//! injected (`now`, Unix seconds), never read — mirroring [`crate::admission`]
//! and [`crate::notifications`].
//!
//! ## The policy (spec §15)
//!
//! - **Admission gates every spawn.** A brand-new agent
//!   ([`start`](Supervisor::start)) is an [`Intent::Start`] — the per-device cap
//!   *and* the shared budget/rate rails gate it. A re-roll
//!   ([`tick`](Supervisor::tick)) is an [`Intent::Roll`] — it keeps the agent's
//!   slot, so the cap never gates it, but budget/rate still do (a roll bursts
//!   tokens against the shared pool just like a start, [`crate::admission`]).
//! - **Hang/error detection → re-roll with capped backoff.** A non-zero exit (the
//!   headless permission-prompt error, or any abnormal end) and a stale heartbeat
//!   (no `stream-json` delta within the hang window) both classify as **crashed**.
//!   On a crash the supervisor kills any still-live (hung) child, bumps the
//!   consecutive-failure count, schedules the re-roll no earlier than
//!   `now + Backoff::delay(failures)`, and surfaces an [`NotifyEvent::AgentCrashed`]
//!   for the caller to route. Repeated crashes grow the delay until it caps —
//!   a wedged agent (e.g. a missing allow-rule that re-errors every spawn) backs
//!   off instead of hot-looping.
//! - **A clean exit reads the agent's baton, then decides.** Exit code 0 is a
//!   session that ended on its own baton boundary; the supervisor reads that
//!   baton's terminal status (the shared [`softfig_ipc::baton`] vocabulary) and
//!   maps it — a within-item continue (`IN_PROGRESS`, or no baton yet) re-rolls
//!   the SAME part immediately (no backoff, no alert, streak cleared); an item
//!   boundary (`ITEM_COMPLETE` / `ITEM_DEFERRED`) **releases the member's slot**
//!   (it leaves the fleet, exactly like a retire) so the drive loop re-claims +
//!   re-seeds its next part through the same handshake a fresh start uses — the
//!   member never self-pulls (the fleet-member-model fix); `QUEUE_EMPTY`
//!   **retires** the member to idle (it leaves the fleet, so it is never
//!   re-rolled — the empty-queue spin fix, [[decision-growlight-fleet-loop-spin]]);
//!   `HALTED_RATE_LIMIT` **parks** it until its window resets; an agent-written
//!   `STUCK` / `BLOCKED_ON_HUMAN` / unrecognized status **parks** it and surfaces
//!   an [`NotifyEvent::AgentCrashed`] human alert. Deciding re-roll-vs-retire
//!   purely on the exit code — without this read — is what spun `claude -p` on a
//!   drained queue.
//! - **A healthy agent is left alone.** An alive child with a recent heartbeat
//!   produces no action and no spawn.
//!
//! ## Why the crash alert is **returned**, not emitted here
//!
//! [`NotifyEvent::AgentCrashed`] is handed back from [`poll`](Supervisor::poll)
//! rather than pushed through a [`crate::notify_dispatch::NotifyDispatcher`] the
//! supervisor owns: the drive loop owns the *single* dispatcher, and slice 003
//! (cross-agent budget aggregation) feeds the same one. Keeping the supervisor a
//! value-model that *names* the alert — instead of capturing the dispatcher —
//! keeps process lifecycle (the supervisor's job) and notification routing (the
//! drive loop's job) decoupled, and keeps the policy unit-provable.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use softfig_ipc::baton::{classify_status, BatonDisposition};

use crate::admission::{
    AdmissionDecision, AdmissionGovernor, BudgetUsage, Intent, RateState, RefuseReason,
};
use crate::config::Policy;
use crate::control::AgentChild;
use crate::notifications::NotifyEvent;

/// Default capped-backoff base: the first re-roll after a crash waits this long.
const DEFAULT_BACKOFF_BASE_SECS: i64 = 5;
/// Default capped-backoff ceiling: a persistently-crashing agent never waits
/// longer than this between re-roll attempts.
const DEFAULT_BACKOFF_CAP_SECS: i64 = 300;
/// Default hang window: an alive child with no `stream-json` delta for at least
/// this long is treated as hung (and re-rolled). Generous because a working
/// session can think/tool-call silently for a while.
const DEFAULT_HANG_SECS: i64 = 600;
/// Spin guard (task 038): a member that clean-exits on a **continue** status
/// (`IN_PROGRESS` / no baton) with a `# NEXT ACTION` byte-identical to its
/// previous continue-exit this many times in a row is wedged — making no progress
/// yet re-rollable — so instead of re-rolling it (and burning the shared budget in
/// a tight loop) the supervisor releases it as `STUCK`. Mirrors the deleted
/// `--auto` orchestrator's `STALL_LIMIT` (protocol step 6: "NEXT ACTION materially
/// unchanged across 2+ iterations → STUCK"): the first repeat arms the streak, the
/// second trips it, so a stuck member burns at most one extra session before it is
/// parked with a reason rather than spinning until a budget rail trips.
const STALL_LIMIT: u32 = 2;

/// The per-agent spec a backend spawns from: the agent's bus id (work-stream
/// name) plus the paths to its pre-approval `loop.json` and `mcp.json` (§15 —
/// each agent pre-approves its full toolset or headless errors out mid-run).
/// Pure data; the backend reads it to build the `claude -p` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpec {
    /// The agent's bus address / work-stream id (the `@`-stripped name).
    pub agent: String,
    /// Per-agent `loop.json` — the pre-approved toolset + hook settings.
    pub loop_settings: PathBuf,
    /// Per-agent `mcp.json` — the softfig-mcp attach config.
    pub mcp_config: PathBuf,
}

impl AgentSpec {
    /// Construct a spec for `agent` from its pre-approval file paths.
    pub fn new(
        agent: impl Into<String>,
        loop_settings: impl Into<PathBuf>,
        mcp_config: impl Into<PathBuf>,
    ) -> Self {
        Self {
            agent: agent.into(),
            loop_settings: loop_settings.into(),
            mcp_config: mcp_config.into(),
        }
    }
}

/// A backend spawn failure — the `claude -p` child could not be launched (e.g.
/// the binary is missing or the spec paths are unreadable). Distinct from a
/// *running* agent that later crashes: this is the launch itself failing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnError(pub String);

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent spawn failed: {}", self.0)
    }
}

impl std::error::Error for SpawnError {}

/// The spawn seam: produce a live [`AgentChild`] from a per-agent [`AgentSpec`].
///
/// **Default-absent live binding** (like [`crate::leases::ThrashClear`] /
/// [`crate::notify_dispatch::BusEmit`]): the production impl shells `claude -p
/// --output-format stream-json` (§12) and arrives with the phase-6 drive loop.
/// `Send + Sync + Debug` because the daemon shares the supervisor across the
/// drive-loop task (the [`crate::notify_dispatch::Notifier`] seam shape).
pub trait AgentBackend: Send + Sync + fmt::Debug {
    /// Spawn a fresh agent process from `spec`, returning its killable handle.
    /// `Err` means the launch itself failed (not a later crash).
    fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError>;
}

/// One agent's health as the drive loop observed it. The drive loop derives this
/// from the `claude -p` child: an exit yields [`Self::Exited`]; a still-running
/// child yields [`Self::Alive`] stamped with its last `stream-json` activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentHealth {
    /// The child is still running; `last_active` (Unix seconds) is its most
    /// recent `stream-json` delta. A stale stamp (older than the hang window) is
    /// classified as hung.
    Alive {
        /// Unix-seconds timestamp of the last observed `stream-json` activity.
        last_active: i64,
    },
    /// The child exited with this code. `0` is a clean baton-boundary roll;
    /// non-zero is a crash (the headless permission-prompt error, or any abnormal
    /// end).
    Exited {
        /// The process exit code.
        code: i32,
    },
}

/// Capped exponential backoff between re-roll attempts. Pure: `delay(failures)`
/// is `min(base << (failures - 1), cap)`, saturating so a long failure streak
/// never overflows. `failures == 0` (no crash yet) is a zero delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Delay after the first crash (seconds).
    pub base_secs: i64,
    /// Upper bound on the delay, however many crashes in a row (seconds).
    pub cap_secs: i64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base_secs: DEFAULT_BACKOFF_BASE_SECS,
            cap_secs: DEFAULT_BACKOFF_CAP_SECS,
        }
    }
}

impl Backoff {
    /// The delay before the re-roll that follows the `failures`-th consecutive
    /// crash (1-based). `base << (failures-1)`, clamped to `cap`. Saturating: an
    /// arbitrarily long streak pins at `cap`, never overflows.
    pub fn delay(&self, failures: u32) -> i64 {
        if failures == 0 {
            return 0;
        }
        // Clamp the shift well under i64's width so the doubling can't wrap; the
        // `.min(cap)` makes any large exponent indistinguishable anyway.
        let exp = (failures - 1).min(62);
        let doubled = self.base_secs.saturating_mul(1i64 << exp);
        doubled.min(self.cap_secs)
    }
}

/// The health classification a single observation yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Alive with a recent heartbeat — nothing to do.
    Healthy,
    /// Exited cleanly (code 0) — roll a fresh session, no alert/backoff.
    CleanExit,
    /// Errored exit or a stale heartbeat — re-roll with backoff + alert.
    Crashed,
}

/// Classify one `health` observation at `now` against the hang window.
fn classify(health: &AgentHealth, hang_secs: i64, now: i64) -> Verdict {
    match health {
        AgentHealth::Exited { code } => {
            if *code == 0 {
                Verdict::CleanExit
            } else {
                Verdict::Crashed
            }
        }
        AgentHealth::Alive { last_active } => {
            if now.saturating_sub(*last_active) >= hang_secs {
                Verdict::Crashed
            } else {
                Verdict::Healthy
            }
        }
    }
}

/// The outcome of registering + starting a brand-new agent ([`Supervisor::start`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOutcome {
    /// Admitted and spawned — the agent is now in the fleet.
    Started,
    /// The fleet is at the per-device cap; the start is held for a free slot
    /// (the agent was **not** registered — the drive loop retries).
    Queued {
        /// Agents currently running.
        active: u32,
        /// The per-device `max_concurrent_agents` cap.
        cap: u32,
    },
    /// A budget/rate rail refused the start; back off until it recovers (not
    /// registered).
    Refused {
        /// Which exhausted resource blocked the start.
        reason: RefuseReason,
    },
    /// Admission cleared but the part-claim that gates the spawn could not be
    /// made — keeperd refused the claim, was unreachable, or the write outcome
    /// was ambiguous. **Fail-closed:** nothing spawned (no agent orphaned on an
    /// unclaimed part) and nothing registered, so the drive loop retries the
    /// claim next tick. The fallback double-assignment window stays closed: a
    /// start that could not claim its part never runs on it.
    ClaimFailed {
        /// Why the claim could not be confirmed.
        reason: String,
    },
    /// Admission cleared but the backend launch itself failed.
    SpawnFailed {
        /// The backend's error text.
        error: String,
    },
}

/// The outcome of one health observation ([`Supervisor::poll`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// Alive with a recent heartbeat — left running, nothing scheduled.
    Healthy,
    /// Exited cleanly on a continue status (or with no baton signal yet) —
    /// scheduled an immediate re-roll, cleared the failure streak, no alert.
    Rolling,
    /// Exited cleanly on a `QUEUE_EMPTY` baton — the member retired itself to
    /// idle: dropped from the fleet so it is never re-rolled. The daemon stays
    /// resident; when new queued work appears the drive loop re-starts a fresh
    /// member (the empty-queue spin fix, [[decision-growlight-fleet-loop-spin]]).
    Retired,
    /// Exited cleanly on an `ITEM_COMPLETE` / `ITEM_DEFERRED` baton — the member
    /// finished/deferred its current part and **released its slot**: dropped from
    /// the fleet, exactly like [`Retired`](PollOutcome::Retired), EXCEPT the queue
    /// still has work, so the drive loop's step-3 scheduler re-claims + re-seeds it
    /// onto its NEXT workable part this same tick (the orchestrator owns
    /// continuation; the member never self-pulls — the fleet-member-model fix). A
    /// distinct outcome from `Retired` only so the caller can log an item boundary
    /// apart from a drained queue; the lifecycle effect (release, re-pickable) is
    /// identical.
    Completed,
    /// Exited cleanly on a `HALTED_RATE_LIMIT` baton — the member is brought down
    /// (its child cleared) but kept in the fleet, so [`tick`](Supervisor::tick)
    /// re-rolls it the moment admission's rate gate recovers (the timed re-arm —
    /// "work till the limit, then resume when it restores"). No alert: a transient
    /// halt the budget governor resumes; the rate gate itself, not a flag, holds it
    /// until its window resets.
    ParkedRateLimited,
    /// Exited cleanly on a `STUCK` / `BLOCKED_ON_HUMAN` / unrecognized baton — the
    /// member can't progress on its current part without a human, so it is
    /// **released to idle** (dropped from the fleet, slot freed — exactly like an
    /// item-boundary release / `QUEUE_EMPTY` retire), NOT sticky-parked on its slot.
    /// The drive loop **item-parks** the member's current part (marks it `blocked`
    /// in keeperd), so the freed member pivots past it to other workable work
    /// (pivot-on-block, spec §6) and the human is alerted via the parked-head set —
    /// the item, not the agent, is what the alert names. The raw status is carried
    /// for the log (the item-park / pivot is the drive loop's job; the supervisor
    /// only releases + names the block).
    Blocked {
        /// The raw terminal baton status that blocked the member (for the log). For a
        /// member-written block this is its `STUCK` / `BLOCKED_ON_HUMAN` / unrecognized
        /// status; for a spin-guard block it is a synthesized reason naming the
        /// unchanged-NEXT-ACTION streak.
        status: String,
        /// The supervisor **synthesized** this block from its spin guard (the
        /// member's `# NEXT ACTION` was unchanged across [`STALL_LIMIT`] consecutive
        /// continue re-rolls — task 038), rather than the member itself writing a
        /// `STUCK` / `BLOCKED_ON_HUMAN` baton. The lifecycle is identical (release to
        /// idle + item-park + human alert); the flag only distinguishes the
        /// journal/alert reason so a spin never reads as a member-declared human block.
        spin_guard: bool,
    },
    /// Crashed (errored exit or hung) — killed any live child, bumped the failure
    /// streak, scheduled a backoff re-roll, and surfaced this alert for the caller
    /// to route through the [`crate::notify_dispatch::NotifyDispatcher`].
    Crashed {
        /// The [`NotifyEvent::AgentCrashed`] to dispatch.
        event: NotifyEvent,
        /// Consecutive crashes for this agent (drives the backoff).
        failures: u32,
        /// Earliest Unix-seconds a re-roll may spawn.
        not_before: i64,
    },
    /// A non-zero exit the network classifier attributed to a TRANSIENT network
    /// death (network-failsafe slice 002): the peer lost its API connection mid-
    /// session (link dropped / DNS / TLS / connection reset) rather than genuinely
    /// crashing. Treated as a soft **reconnect**, NOT a crash — any hung child is
    /// killed, but the failure streak is NOT bumped, NO punitive backoff is
    /// scheduled (the member is immediately re-rollable), and NO `AgentCrashed`
    /// alert fires. The member stays down-but-registered so
    /// [`tick`](Supervisor::tick) re-rolls it off its baton; the pre-spawn
    /// connectivity gate (slice 001) paces that re-spawn while the link is still
    /// down, so there is no spin — the false-crash-loop fix.
    Reconnecting,
    /// A registered member re-observed DOWN (no live child) with the same exit it
    /// already crashed on — inert. The backend's health cell LATCHES the last exit
    /// until a re-spawn overwrites it, so a down member is re-observed with that
    /// same stale exit every ~1s tick; before this outcome each re-observation
    /// re-ran the crash path — streak bump + `not_before` pushed past `now` again —
    /// so a crashed member was `HeldForBackoff` on EVERY tick and never re-rolled
    /// (the 2026-07-11 crash-exit stall: crash → idle → 10h silence on a
    /// still-`active` item). An exit is consumed exactly once: the first
    /// observation (live child, or the errored exit's first sighting) runs
    /// [`on_crash`](Supervisor::poll); re-observations are `Down` — no streak bump,
    /// no backoff push, no alert — and [`tick`](Supervisor::tick) owns the re-roll
    /// once the already-armed backoff elapses. The drive loop honors a pending
    /// boundary stop on this outcome (a down member is BETWEEN sessions — at a
    /// boundary — so stopping it beats re-spawning a session just to stop it).
    Down,
    /// The agent was never started (unknown id) — ignored.
    Unknown,
}

/// The outcome of attempting one re-roll during a [`Supervisor::tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RerollOutcome {
    /// Re-spawned — the agent is running again.
    Rerolled {
        /// The re-rolled agent's id.
        agent: String,
    },
    /// Still inside the crash backoff window — try again later.
    HeldForBackoff {
        /// The held agent's id.
        agent: String,
        /// Earliest Unix-seconds the re-roll may spawn.
        not_before: i64,
    },
    /// The member's queue has no workable part right now (the queue-gate) — held,
    /// not re-rolled into an empty queue. It keeps its slot and is retried when
    /// queued work reappears (the respawn half of the empty-queue spin fix).
    HeldNoWork {
        /// The held agent's id.
        agent: String,
    },
    /// A budget/rate rail refused the re-roll (the cap never gates a roll).
    HeldForAdmission {
        /// The held agent's id.
        agent: String,
        /// The refusing admission decision.
        decision: AdmissionDecision,
    },
    /// The backend launch failed; the agent backs off and is retried.
    SpawnFailed {
        /// The agent whose re-spawn failed.
        agent: String,
        /// The backend's error text.
        error: String,
    },
}

/// One supervised agent's live state.
#[derive(Debug)]
struct Supervised {
    spec: AgentSpec,
    /// The live child handle while running; `None` while awaiting a re-roll.
    child: Option<Box<dyn AgentChild>>,
    /// Consecutive crashes since the last clean run (drives the backoff).
    consecutive_failures: u32,
    /// Earliest Unix-seconds the next re-roll may spawn.
    not_before: i64,
    /// The `# NEXT ACTION` body this member handed off on its PREVIOUS **continue**
    /// (`IN_PROGRESS` / no-baton) clean exit — the spin-guard progress baseline
    /// (task 038). `None` until the first continue-exit. Reset when the member is
    /// re-picked onto a fresh part (an item-boundary release drops the whole
    /// `Supervised`, so a re-seeded member starts its streak clean) and when it
    /// parks on a rate limit (a budget pause is not a stall).
    last_next_action: Option<String>,
    /// Consecutive continue clean-exits whose `# NEXT ACTION` was byte-identical to
    /// the previous one — the no-progress streak. At [`STALL_LIMIT`] the spin guard
    /// releases the member as `STUCK` instead of re-rolling it (task 038).
    unchanged_streak: u32,
}

/// The fleet supervisor: owns the spawn seam, the admission governor, and the
/// per-agent state. Driven by the phase-6 drive loop, not a thread of its own.
#[derive(Debug)]
pub struct Supervisor {
    backend: Box<dyn AgentBackend>,
    governor: AdmissionGovernor,
    backoff: Backoff,
    hang_secs: i64,
    agents: BTreeMap<String, Supervised>,
}

impl Supervisor {
    /// A supervisor over `backend` and `governor`, with default backoff + hang
    /// window.
    pub fn new(backend: Box<dyn AgentBackend>, governor: AdmissionGovernor) -> Self {
        Self::with_backoff(backend, governor, Backoff::default(), DEFAULT_HANG_SECS)
    }

    /// A supervisor with an explicit backoff + hang window (the test seam;
    /// production uses [`new`](Self::new)).
    pub fn with_backoff(
        backend: Box<dyn AgentBackend>,
        governor: AdmissionGovernor,
        backoff: Backoff,
        hang_secs: i64,
    ) -> Self {
        Self {
            backend,
            governor,
            backoff,
            hang_secs,
            agents: BTreeMap::new(),
        }
    }

    /// Agents with a live child right now (a real running `claude -p`).
    pub fn live_count(&self) -> u32 {
        self.agents.values().filter(|s| s.child.is_some()).count() as u32
    }

    /// **Committed** roster slots — every registered member, whether it is live,
    /// awaiting a re-roll (down, inside a crash backoff), or parked. This, not
    /// [`live_count`](Self::live_count), is what the per-device concurrency cap
    /// gates a fresh [`Intent::Start`] on: a member that is momentarily down still
    /// *owns* its slot (it will reclaim it on its next re-roll), so counting only
    /// live children would let a fresh start fill that transiently-empty slot and
    /// then overshoot the cap the instant the down member re-rolls. Counting
    /// committed slots reserves them, so concurrency can never exceed the cap
    /// regardless of the order claims/spawns/re-rolls interleave within a tick (the
    /// atomic-`max_agents` invariant — fleet-loop-spin slice 003). A retired
    /// (`QUEUE_EMPTY`) member has left `agents`, so it frees its slot.
    pub fn committed_count(&self) -> u32 {
        self.agents.len() as u32
    }

    /// The admission governor's current per-device [`Policy`] — so the drive loop
    /// only rebuilds the governor on a real `set_policy` change.
    pub fn policy(&self) -> Policy {
        self.governor.policy()
    }

    /// Replace the admission governor's per-device [`Policy`] at a safe boundary.
    /// The drive loop pushes a live `set_policy` change in here before its next
    /// admission decision, so the new cap/rails take effect at that boundary
    /// without a restart. Re-decisions are pure, so swapping the configured policy
    /// is all that is needed — in-flight agents are untouched; the change gates the
    /// *next* start/roll.
    pub fn set_policy(&mut self, policy: Policy) {
        self.governor = AdmissionGovernor::new(policy);
    }

    /// Whether `agent` is registered and currently running.
    pub fn is_running(&self, agent: &str) -> bool {
        self.agents
            .get(agent)
            .is_some_and(|s| s.child.is_some())
    }

    /// `agent`'s consecutive-crash count (0 if unknown or last run was clean).
    pub fn failures(&self, agent: &str) -> u32 {
        self.agents
            .get(agent)
            .map_or(0, |s| s.consecutive_failures)
    }

    /// Whether `agent` is registered with the supervisor at all — running OR
    /// awaiting a re-roll. The drive loop gates a fresh [`Intent::Start`] on this:
    /// an agent the supervisor already manages re-rolls via [`tick`](Self::tick),
    /// it is never re-`start`ed (which would reset its crash streak / slot).
    pub fn is_registered(&self, agent: &str) -> bool {
        self.agents.contains_key(agent)
    }

    /// Retire `agent` from the fleet — drop its supervised state and hand back any
    /// still-live child so the caller can kill it OUTSIDE the daemon lock (the
    /// [`AgentChild`] contract, incident 20260622). The drive loop calls this to
    /// honor a boundary stop (`stop_after_slice` / `stop_after_iteration`): once a
    /// retiring agent reaches its boundary it must NOT be re-rolled, so it leaves
    /// the supervised set entirely. Returns the live child if one was running (an
    /// immediate stop), or `None` if the agent was unknown or already down (a
    /// graceful boundary stop — the agent has already exited).
    pub fn retire(&mut self, agent: &str) -> Option<Box<dyn AgentChild>> {
        self.agents.remove(agent).and_then(|s| s.child)
    }

    /// Register and start a brand-new agent ([`Intent::Start`]). The cap *and*
    /// budget/rate gate it; on admit the backend spawns it and it joins the
    /// fleet. A queue/refuse leaves it unregistered for the drive loop to retry.
    ///
    /// This is [`start_claiming`](Self::start_claiming) with a no-op claim — the
    /// supervisor-internal / test entry point. The drive loop uses the claiming
    /// form so the part is claimed before the spawn.
    pub fn start(
        &mut self,
        spec: AgentSpec,
        budget: BudgetUsage,
        rate: RateState,
        now: i64,
    ) -> StartOutcome {
        self.start_claiming(spec, budget, rate, now, || Ok(()))
    }

    /// Like [`start`](Self::start), but interposes a `claim` step between
    /// admission *admitting* and the backend *spawning*. The drive loop passes
    /// its keeperd part-claim here (mark the picked part `active`); the ordering
    /// is the whole point:
    ///
    /// - **admit → claim → spawn**, so a claim that returns `Err` aborts the
    ///   start ([`StartOutcome::ClaimFailed`]) **before** any child is spawned —
    ///   no agent is ever left running on an unclaimed part (fail-closed).
    /// - the claim sits *after* admission, so a queued/refused start never even
    ///   attempts the claim (no wasted keeperd write, no claim leaked onto a part
    ///   no agent will run); and a failed claim consumes no per-device slot,
    ///   because nothing is registered until the spawn succeeds.
    ///
    /// `claim` returns `Ok(())` when the part is now this agent's (keeperd's
    /// idempotent already-`active` no-op counts), `Err(reason)` when it could not
    /// be confirmed.
    pub fn start_claiming<F>(
        &mut self,
        spec: AgentSpec,
        budget: BudgetUsage,
        rate: RateState,
        now: i64,
        claim: F,
    ) -> StartOutcome
    where
        F: FnOnce() -> Result<(), String>,
    {
        // Gate the cap on COMMITTED slots, not just live children: a member that is
        // momentarily down (awaiting a re-roll / inside a backoff) still owns its
        // slot, so counting it here reserves that slot and keeps a fresh start from
        // transiently overshooting the cap (the atomic-`max_agents` invariant).
        let fleet = self.committed_count();
        match self.governor.decide(Intent::Start, fleet, budget, rate) {
            AdmissionDecision::Admit => match claim() {
                Ok(()) => match self.backend.spawn(&spec) {
                    Ok(child) => {
                        self.agents.insert(
                            spec.agent.clone(),
                            Supervised {
                                spec,
                                child: Some(child),
                                consecutive_failures: 0,
                                not_before: now,
                                last_next_action: None,
                                unchanged_streak: 0,
                            },
                        );
                        StartOutcome::Started
                    }
                    Err(e) => StartOutcome::SpawnFailed {
                        error: e.to_string(),
                    },
                },
                Err(reason) => StartOutcome::ClaimFailed { reason },
            },
            AdmissionDecision::Queue { active, cap } => StartOutcome::Queued { active, cap },
            AdmissionDecision::Refuse { reason } => StartOutcome::Refused { reason },
        }
    }

    /// Observe one supervised agent's `health` at `now`, given the terminal
    /// `baton_status` it wrote on exit (`None` if no baton was readable — the
    /// historical clean-exit fallback). Healthy → nothing; crash → kill any live
    /// (hung) child, bump the streak, backoff re-roll + alert; clean exit →
    /// [`Self::on_clean_exit`] reads the baton and decides re-roll / retire / park.
    ///
    /// Reading the baton on a clean exit is the empty-queue spin fix: deciding on
    /// the exit code alone re-rolled a `QUEUE_EMPTY` exit straight back into a
    /// fresh `claude -p` ([[decision-growlight-fleet-loop-spin]]).
    pub fn poll(
        &mut self,
        agent: &str,
        health: AgentHealth,
        baton_status: Option<&str>,
        now: i64,
    ) -> PollOutcome {
        // Default the network classifier to "never a network exit" — the pre-slice-
        // 002 behaviour, where every non-zero exit is a genuine crash — AND default
        // the spin-guard's NEXT ACTION signal to `None` (a `None` never proves a
        // repeat, so the guard stays inert). The drive loop uses `poll_with_network`
        // to feed the real classifier off the stderr ring + a connectivity probe and
        // the real NEXT ACTION off the baton; the supervisor's own tests exercise
        // this default (a spin-guard test passes the NEXT ACTION via that richer form).
        self.poll_with_network(agent, health, baton_status, None, now, || false)
    }

    /// Like [`poll`](Self::poll), but with a `network_exit` predicate — evaluated
    /// ONLY when a crash verdict is reached (so a healthy tick pays nothing) — that
    /// decides whether a non-zero exit is a TRANSIENT network death
    /// ([`PollOutcome::Reconnecting`]: re-roll, no streak/backoff/alert) rather than a
    /// genuine crash ([`PollOutcome::Crashed`], unchanged). The drive loop builds it
    /// from the peer's in-memory stderr tail + a connectivity probe (network-failsafe
    /// slice 002); a genuine hang or a non-network exit yields `false` and the
    /// historical crash path is bit-for-bit unchanged.
    pub fn poll_with_network<F: FnOnce() -> bool>(
        &mut self,
        agent: &str,
        health: AgentHealth,
        baton_status: Option<&str>,
        next_action: Option<&str>,
        now: i64,
        network_exit: F,
    ) -> PollOutcome {
        let hang_secs = self.hang_secs;
        if !self.agents.contains_key(agent) {
            return PollOutcome::Unknown;
        }
        match classify(&health, hang_secs, now) {
            Verdict::Healthy => PollOutcome::Healthy,
            Verdict::CleanExit => {
                if self.agents[agent].child.is_none() {
                    // Already-consumed CLEAN exit (task 047, the twin of task 044's
                    // crash-side guard below): the health cell latches the exit until
                    // a re-spawn, so a member whose re-roll is HELD (admission
                    // budget/rate, the queue-gate) re-observes the same clean exit on
                    // every ~1s tick. Re-running `on_clean_exit` fed the spin guard
                    // the SAME baton NEXT ACTION each observation — two held ticks
                    // read as a no-progress "stall" and the guard mislabel-parked the
                    // item `blocked` on a human (the 2026-07-20 m5f parks). Inert
                    // instead: the first observation consumed the exit (`roll` / the
                    // rate-park cleared `child`; every other disposition removes the
                    // agent), and `tick` owns the re-roll once the hold clears — the
                    // spin streak counts real consecutive sessions only.
                    PollOutcome::Down
                } else {
                    self.on_clean_exit(agent, baton_status, next_action, now)
                }
            }
            Verdict::Crashed => {
                if network_exit() {
                    // Evaluated BEFORE the consumed-exit guard below so a
                    // reconnecting member keeps re-classifying `Reconnecting`
                    // every tick while the connectivity hold gates its re-roll
                    // (the slice-002 latch + narration contract) — idempotent:
                    // `on_network_exit` never bumps the streak and re-arms
                    // `not_before = now`, so re-observation is harmless there.
                    self.on_network_exit(agent, health, now)
                } else if self.agents[agent].child.is_none() {
                    // Already-consumed exit (task 044 / the 2026-07-11 stall):
                    // the health cell latches the exit until a re-spawn, so a
                    // down member re-observes it every tick. Re-running
                    // `on_crash` here re-bumped the streak and pushed
                    // `not_before` past `now` on every tick — the re-roll was
                    // `HeldForBackoff` forever and the crashed member never
                    // came back. Inert instead: the first observation armed
                    // the backoff; `tick` re-rolls when it elapses. Covers the
                    // errored-exit re-observation AND the killed-hung child
                    // whose stale `Alive` lingers until the reaper flips it.
                    PollOutcome::Down
                } else {
                    self.on_crash(agent, health, now)
                }
            }
        }
    }

    /// Handle a **crash** (errored exit or stale heartbeat): kill any live (hung)
    /// child via the [`AgentChild`] contract (the drive loop runs `poll` off the
    /// connection lock, so the kill-outside-the-lock invariant holds; an errored
    /// exit is already gone, so its handle is just dropped), bump the failure
    /// streak, schedule the backoff re-roll, and surface the [`NotifyEvent`] alert.
    fn on_crash(&mut self, agent: &str, health: AgentHealth, now: i64) -> PollOutcome {
        let backoff = self.backoff;
        let sup = self.agents.get_mut(agent).expect("agent exists (checked in poll)");
        let was_hung = matches!(health, AgentHealth::Alive { .. });
        if let Some(child) = sup.child.take() {
            if was_hung {
                child.kill();
            }
        }
        sup.consecutive_failures = sup.consecutive_failures.saturating_add(1);
        sup.not_before = now.saturating_add(backoff.delay(sup.consecutive_failures));
        PollOutcome::Crashed {
            // Built without a stderr tail — the supervisor has no backend to read it
            // from; the drive loop enriches this alert with the crashed agent's
            // in-memory stderr ring before dispatch (crash-diagnostics slice 001).
            event: NotifyEvent::agent_crashed(agent),
            failures: sup.consecutive_failures,
            not_before: sup.not_before,
        }
    }

    /// Handle a **transient network exit** (network-failsafe slice 002): a non-zero
    /// exit the classifier attributed to a lost API connection, not a genuine crash.
    /// Kill any live (hung) child, then — unlike [`on_crash`](Self::on_crash) — do
    /// NOT bump the failure streak, do NOT schedule a punitive backoff, and do NOT
    /// surface an alert. The member is left down-but-registered and immediately
    /// re-rollable (`not_before = now`); [`tick`](Self::tick) re-rolls it off its
    /// baton, and the pre-spawn connectivity gate (slice 001) holds that re-spawn
    /// while the link is still down — so a flaky link reconnects off the baton
    /// instead of crash-looping with punitive backoff + a false page.
    fn on_network_exit(&mut self, agent: &str, health: AgentHealth, now: i64) -> PollOutcome {
        let sup = self
            .agents
            .get_mut(agent)
            .expect("agent exists (checked in poll)");
        let was_hung = matches!(health, AgentHealth::Alive { .. });
        if let Some(child) = sup.child.take() {
            if was_hung {
                child.kill();
            }
        }
        // Transient: the failure streak is left untouched (a network blip is not a
        // failure, so it neither counts nor resets a real streak), and the member is
        // immediately re-rollable — no punitive backoff. The connectivity gate paces
        // the actual re-spawn while offline.
        sup.not_before = now;
        PollOutcome::Reconnecting
    }

    /// Decide what a clean (code-0) exit means by reading the agent's terminal
    /// baton status — the spin fix. The shared [`softfig_ipc::baton`] vocabulary
    /// classifies it; each disposition maps to a fleet lifecycle:
    ///
    /// - **Continue** (`IN_PROGRESS`, or `None` — no baton write-back yet) →
    ///   re-roll immediately, SAME part, streak cleared (the within-item handoff).
    /// - **ItemBoundary** (`ITEM_COMPLETE` / `ITEM_DEFERRED`) → **release to idle**:
    ///   the member leaves the fleet (its slot freed), exactly like a retire, so the
    ///   drive loop re-claims + re-seeds its NEXT part through the fresh-start
    ///   handshake — the member never self-pulls (the fleet-member-model fix).
    /// - **`QUEUE_EMPTY`** → **retire**: the member leaves the fleet entirely, so
    ///   [`tick`](Self::tick) never re-rolls it. No spin on a drained queue.
    /// - **`HALTED_RATE_LIMIT`** → bring the member down but keep it in the fleet, so
    ///   `tick` re-rolls it once admission's rate gate recovers (no alert).
    /// - **`BLOCKED_ON_HUMAN` / `STUCK` / unrecognized** → **release to idle**: the
    ///   member leaves the fleet (its slot freed), exactly like an item boundary, so
    ///   it does NOT sit on its slot waiting for a person. The drive loop item-parks
    ///   its current part (`blocked`) so the freed member pivots to other work and
    ///   the human is alerted via the parked-head set ([`PollOutcome::Blocked`]).
    ///
    /// A released/retired member is gone (its slot freed); a rate-limited one is
    /// down-but-registered (re-rolled when its window recovers). All stop the
    /// blind re-roll, which is what kept `claude -p` spinning.
    fn on_clean_exit(
        &mut self,
        agent: &str,
        baton_status: Option<&str>,
        next_action: Option<&str>,
        now: i64,
    ) -> PollOutcome {
        // No baton signal → the historical clean-exit re-roll, but still through the
        // spin guard: a member that never rewrites its baton keeps the seed's constant
        // NEXT ACTION, so `roll_or_spin` catches it as a stall (its NEXT ACTION repeats
        // unchanged) rather than re-rolling it forever. A truly missing/unreadable
        // baton leaves `next_action` `None`, which never proves a repeat, so the guard
        // stays inert there — the exact historical re-roll.
        let Some(status) = baton_status else {
            return self.roll_or_spin(agent, next_action, now);
        };
        match classify_status(Some(status)) {
            BatonDisposition::Continue => self.roll_or_spin(agent, next_action, now),
            BatonDisposition::ItemBoundary => {
                // Item boundary: the member already wrote `set_item_status <part>
                // done|deferred`, so its part is finished. Release its slot — drop
                // it from the fleet, exactly like the QUEUE_EMPTY retire — and the
                // drive loop's step-3 scheduler re-claims + re-seeds it onto its
                // next workable part this same tick (the orchestrator owns
                // continuation; no member self-pull). The child already exited
                // clean, so there is nothing to kill.
                self.agents.remove(agent);
                PollOutcome::Completed
            }
            BatonDisposition::QueueEmpty => {
                // Retire to idle: drop the member so it is never re-rolled. The
                // child already exited (clean), so there is nothing to kill.
                self.agents.remove(agent);
                PollOutcome::Retired
            }
            BatonDisposition::RateLimited => {
                // Transient halt: bring the member down (clear its child) but keep
                // it registered, so it stays a re-roll candidate. Admission's rate
                // gate — not a sticky flag — holds it every `tick` until its window
                // recovers, at which point `tick` re-rolls it (the timed re-arm).
                // Reset the spin streak: a rate-limit park is a budget pause, not a
                // no-progress stall, so a member that resumes on the SAME NEXT ACTION
                // after its window reopens must not be mistaken for spinning (task 038).
                if let Some(sup) = self.agents.get_mut(agent) {
                    sup.child = None;
                    sup.last_next_action = None;
                    sup.unchanged_streak = 0;
                }
                PollOutcome::ParkedRateLimited
            }
            BatonDisposition::BlockedOnHuman | BatonDisposition::Stuck(_) => {
                // The member can't progress on this part without a human. Item-park,
                // not member-park (the fleet-member-model fix): RELEASE it to idle —
                // drop it from the fleet, exactly like an item-boundary release — so
                // it does not sit on its slot. The drive loop marks its current part
                // `blocked` (the item-park write seam) so the freed member pivots to
                // other work and the human is alerted on the *item*. The child
                // already exited clean, so there is nothing to kill.
                self.agents.remove(agent);
                PollOutcome::Blocked {
                    status: status.to_string(),
                    // The MEMBER wrote this block — not the supervisor's spin guard.
                    spin_guard: false,
                }
            }
        }
    }

    /// A **continue** clean exit (`IN_PROGRESS` / no baton): re-roll the SAME part —
    /// UNLESS the member's `# NEXT ACTION` has repeated byte-identical across
    /// [`STALL_LIMIT`] consecutive continue-exits, the **spin guard** (task 038).
    ///
    /// growlightd's re-roll path had no fleet equivalent of the deleted `--auto`
    /// STUCK threshold (protocol step 6): a member wedged on the same next-action
    /// (a compile it can't fix, a question it keeps re-asking) was re-spawned
    /// immediately with no backoff, burning the shared 5h/7d pool until a budget rail
    /// tripped. This mirrors that threshold structurally: the NEXT ACTION is the
    /// progress signal, and an unchanged one across the streak means no progress.
    ///
    /// The streak update matches the `--auto` guard exactly — a repeat requires BOTH
    /// the previous and current NEXT ACTION to be present and equal; anything else (a
    /// changed action, or a missing one) resets the streak to 1, and a `None` can
    /// never prove a repeat. On a trip the member is **released to idle** (dropped
    /// from the fleet, exactly like an agent-written `STUCK`), so the drive loop
    /// item-parks its part `blocked` and alerts the human on the item — the block is
    /// tagged `spin_guard` so the journal names WHY it parked instead of reading as a
    /// member-declared human block. Not a re-roll, so no more budget is burned.
    fn roll_or_spin(&mut self, agent: &str, next_action: Option<&str>, now: i64) -> PollOutcome {
        let streak = {
            let sup = self
                .agents
                .get_mut(agent)
                .expect("agent exists (checked in poll)");
            let same = matches!(
                (sup.last_next_action.as_deref(), next_action),
                (Some(prev), Some(cur)) if prev == cur
            );
            sup.unchanged_streak = if same {
                sup.unchanged_streak.saturating_add(1)
            } else {
                1
            };
            sup.last_next_action = next_action.map(str::to_string);
            sup.unchanged_streak
        };
        if streak >= STALL_LIMIT {
            // Spin guard tripped: the member handed off the same NEXT ACTION `streak`
            // continue-exits running — wedged, not progressing. Do NOT re-roll it into
            // another budget-burning session. Release it to idle (drop from the fleet,
            // the agent-written-`STUCK` lifecycle) and name the block for the log/alert;
            // the drive loop item-parks its part + pages the human on the item.
            self.agents.remove(agent);
            return PollOutcome::Blocked {
                status: format!(
                    "STUCK (spin guard): NEXT ACTION unchanged across {streak} consecutive re-rolls"
                ),
                spin_guard: true,
            };
        }
        self.roll(agent, now)
    }

    /// Schedule an immediate re-roll for a cleanly-exited member: drop the dead
    /// handle, clear the failure streak, and arm the roll for `now`.
    fn roll(&mut self, agent: &str, now: i64) -> PollOutcome {
        if let Some(sup) = self.agents.get_mut(agent) {
            sup.child = None;
            sup.consecutive_failures = 0;
            sup.not_before = now;
        }
        PollOutcome::Rolling
    }

    /// Perform any due re-rolls ([`Intent::Roll`]). For each registered agent with
    /// no live child: held if still inside its backoff window; held if its queue has
    /// no workable part (`workable(agent)` is `false` — the queue-gate, so a
    /// clean-exit member is never re-rolled into an empty queue); else
    /// admission-gated (cap never gates a roll, budget/rate do); on admit the
    /// backend re-spawns it. A failed re-spawn bumps the streak and backs off.
    /// Returns one outcome per candidate; running agents produce nothing.
    ///
    /// `workable` answers "does this agent have a workable part right now?" — the
    /// drive loop builds it over this tick's queue snapshot from the member's own
    /// recorded assignment (its part still standing head-`active` is the mid-item
    /// carry-forward it re-rolls onto — fallback `pick` alone would skip its own
    /// claim and strand it, the 2026-07-06 stall) plus the same
    /// pinned-with-fallback [`crate::scheduler::pick`] a fresh start uses. It is
    /// the belt-and-suspenders to slice 001's terminal-status retire: even a
    /// member that exited on a *continue* status is not respawned if its queue
    /// has since drained.
    ///
    /// A rate-limited member (down on a `HALTED_RATE_LIMIT` exit but still
    /// registered) IS a candidate: admission's rate/budget gate holds it (a
    /// [`RerollOutcome::HeldForAdmission`]) every tick until its window recovers, at
    /// which point this re-roll re-arms it — the timed re-arm. A member that needed
    /// a human (`BLOCKED_ON_HUMAN` / `STUCK`) was already *released* on its exit
    /// (it left the fleet), so it never reaches here — its part is item-parked and a
    /// fresh start re-picks the fleet's next workable work (pivot-on-block).
    pub fn tick(
        &mut self,
        budget: BudgetUsage,
        rate: RateState,
        now: i64,
        workable: &dyn Fn(&str) -> bool,
    ) -> Vec<RerollOutcome> {
        let candidates: Vec<String> = self
            .agents
            .iter()
            // Down members only (a live child is left running). Every down member is
            // a re-roll candidate now that a human-block releases instead of
            // sticky-parking: a `HALTED_RATE_LIMIT` member is held here by admission
            // until its rate window recovers (then re-rolled); a crashed member is
            // held by its backoff. Nothing parks on its slot.
            .filter(|(_, s)| s.child.is_none())
            .map(|(id, _)| id.clone())
            .collect();

        let mut out = Vec::with_capacity(candidates.len());
        for agent in candidates {
            let not_before = self.agents[&agent].not_before;
            if now < not_before {
                out.push(RerollOutcome::HeldForBackoff { agent, not_before });
                continue;
            }
            // Queue-gate: never re-roll a member whose queue has no workable part —
            // that is the respawn-into-an-empty-queue half of the spin. It stays
            // registered (slot reserved) and is retried when work reappears.
            if !workable(&agent) {
                out.push(RerollOutcome::HeldNoWork { agent });
                continue;
            }
            // A roll keeps the agent's slot — the cap never gates it — but the
            // shared budget/rate rails still do (and hold a rate-limited member here
            // until its window recovers).
            let fleet = self.live_count();
            let decision = self.governor.decide(Intent::Roll, fleet, budget, rate);
            if !decision.is_admit() {
                out.push(RerollOutcome::HeldForAdmission { agent, decision });
                continue;
            }
            let spec = self.agents[&agent].spec.clone();
            match self.backend.spawn(&spec) {
                Ok(child) => {
                    let sup = self.agents.get_mut(&agent).expect("candidate exists");
                    sup.child = Some(child);
                    out.push(RerollOutcome::Rerolled { agent });
                }
                Err(e) => {
                    let backoff = self.backoff;
                    let sup = self.agents.get_mut(&agent).expect("candidate exists");
                    sup.consecutive_failures = sup.consecutive_failures.saturating_add(1);
                    sup.not_before = now.saturating_add(backoff.delay(sup.consecutive_failures));
                    out.push(RerollOutcome::SpawnFailed {
                        agent,
                        error: e.to_string(),
                    });
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A fake live child that records how many times it was killed.
    #[derive(Debug)]
    struct FakeChild {
        kills: Arc<AtomicUsize>,
    }

    impl AgentChild for FakeChild {
        fn kill(&self) {
            self.kills.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A fake backend: records the agent id of every spawn, can be toggled to
    /// fail, and shares a kill counter with the children it makes.
    #[derive(Debug, Default)]
    struct FakeBackend {
        spawns: Mutex<Vec<String>>,
        fail: AtomicBool,
        kills: Arc<AtomicUsize>,
    }

    impl FakeBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn spawns(&self) -> Vec<String> {
            self.spawns.lock().unwrap().clone()
        }
        fn spawn_count(&self) -> usize {
            self.spawns.lock().unwrap().len()
        }
        fn kill_count(&self) -> usize {
            self.kills.load(Ordering::SeqCst)
        }
        fn set_fail(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }
    }

    impl AgentBackend for Arc<FakeBackend> {
        fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
            self.spawns.lock().unwrap().push(spec.agent.clone());
            if self.fail.load(Ordering::SeqCst) {
                return Err(SpawnError("backend down".into()));
            }
            Ok(Box::new(FakeChild {
                kills: Arc::clone(&self.kills),
            }))
        }
    }

    fn fresh_budget() -> BudgetUsage {
        BudgetUsage::new(10, 5)
    }

    fn hot_budget() -> BudgetUsage {
        BudgetUsage::new(90, 5) // over the 85 halt
    }

    fn fresh_rate() -> RateState {
        RateState {
            tpm_used: 10_000,
            rpm_used: 20,
            tpm_limit: 100_000,
            rpm_limit: 100,
            tpm_per_agent: 20_000,
            rpm_per_agent: 10,
        }
    }

    /// A rate window with no headroom — admission refuses a roll (the agent's
    /// share would cross the per-minute limit). Models "still rate-limited".
    fn hot_rate() -> RateState {
        RateState {
            tpm_used: 90_000, // 90k + 20k/agent > 100k limit → would exceed
            ..fresh_rate()
        }
    }

    /// The default queue-gate for the re-roll tests: every agent always has
    /// workable work, so `tick` behaves as it did before the queue-gate. Tests
    /// that exercise the gate pass their own predicate.
    fn any_work(_: &str) -> bool {
        true
    }

    fn spec(id: &str) -> AgentSpec {
        AgentSpec::new(id, format!("/cfg/{id}/loop.json"), format!("/cfg/{id}/mcp.json"))
    }

    fn gov() -> AdmissionGovernor {
        AdmissionGovernor::new(Policy::default()) // cap 2
    }

    /// A supervisor with a small, easy-to-assert backoff (base 2, cap 8) and a
    /// 100s hang window.
    fn sup(backend: Arc<FakeBackend>) -> Supervisor {
        Supervisor::with_backoff(
            Box::new(backend),
            gov(),
            Backoff {
                base_secs: 2,
                cap_secs: 8,
            },
            100,
        )
    }

    /// `start` spawns under the cap, queues at the cap, and refuses on budget.
    #[test]
    fn start_admits_under_cap_queues_at_cap_refuses_on_budget() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));

        // cap 2: first two start, the third queues.
        assert_eq!(
            s.start(spec("a1"), fresh_budget(), fresh_rate(), 0),
            StartOutcome::Started
        );
        assert_eq!(
            s.start(spec("a2"), fresh_budget(), fresh_rate(), 0),
            StartOutcome::Started
        );
        assert_eq!(
            s.start(spec("a3"), fresh_budget(), fresh_rate(), 0),
            StartOutcome::Queued { active: 2, cap: 2 }
        );
        // Only the two admitted starts spawned; the queued one did not.
        assert_eq!(backend.spawns(), vec!["a1", "a2"]);
        assert_eq!(s.live_count(), 2);

        // An exhausted budget refuses even an under-cap start.
        let backend2 = FakeBackend::new();
        let mut s2 = sup(Arc::clone(&backend2));
        assert_eq!(
            s2.start(spec("a1"), hot_budget(), fresh_rate(), 0),
            StartOutcome::Refused {
                reason: RefuseReason::Budget5h
            }
        );
        assert_eq!(backend2.spawn_count(), 0, "a refused start never spawns");
    }

    /// `start` surfaces a backend launch failure as `SpawnFailed` and registers
    /// nothing.
    #[test]
    fn start_surfaces_a_backend_launch_failure() {
        let backend = FakeBackend::new();
        backend.set_fail(true);
        let mut s = sup(Arc::clone(&backend));
        assert_eq!(
            s.start(spec("a1"), fresh_budget(), fresh_rate(), 0),
            StartOutcome::SpawnFailed {
                error: SpawnError("backend down".into()).to_string()
            }
        );
        assert!(!s.is_running("a1"), "a failed start registers nothing");
    }

    /// The claim gate sits between admission and the spawn: a failed claim aborts
    /// the start fail-closed (no spawn, nothing registered), a successful claim
    /// spawns, and a non-admitted start never attempts the claim at all.
    #[test]
    fn the_claim_gate_orders_admit_then_claim_then_spawn() {
        use std::sync::atomic::AtomicUsize;

        // 1. Admitted but the claim fails → ClaimFailed, no spawn, not registered.
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let out = s.start_claiming(spec("a1"), fresh_budget(), fresh_rate(), 0, move || {
            c.fetch_add(1, Ordering::SeqCst);
            Err("claim refused".to_string())
        });
        assert_eq!(
            out,
            StartOutcome::ClaimFailed {
                reason: "claim refused".into()
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the claim was attempted");
        assert_eq!(backend.spawn_count(), 0, "a failed claim never spawns");
        assert!(!s.is_registered("a1"), "a failed claim registers nothing");

        // 2. Admitted and the claim succeeds → spawned + registered.
        let out = s.start_claiming(spec("a1"), fresh_budget(), fresh_rate(), 0, || Ok(()));
        assert_eq!(out, StartOutcome::Started);
        assert_eq!(backend.spawns(), vec!["a1"], "a confirmed claim spawns the agent");

        // 3. A budget-refused start never reaches the claim (admit gates first).
        let backend2 = FakeBackend::new();
        let mut s2 = sup(Arc::clone(&backend2));
        let calls2 = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&calls2);
        let out = s2.start_claiming(spec("a1"), hot_budget(), fresh_rate(), 0, move || {
            c2.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(
            out,
            StartOutcome::Refused {
                reason: RefuseReason::Budget5h
            }
        );
        assert_eq!(calls2.load(Ordering::SeqCst), 0, "a refused start never claims");
        assert_eq!(backend2.spawn_count(), 0);
    }

    /// A healthy heartbeat leaves the agent running untouched — no kill, no spawn.
    #[test]
    fn a_healthy_agent_runs_uninterrupted() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // Recent heartbeat (well inside the 100s hang window).
        assert_eq!(
            s.poll("a1", AgentHealth::Alive { last_active: 950 }, None, 1000),
            PollOutcome::Healthy
        );
        assert!(s.is_running("a1"));
        assert_eq!(backend.spawn_count(), 1, "no re-spawn for a healthy agent");
        assert_eq!(backend.kill_count(), 0, "no kill for a healthy agent");
        // tick has no candidate (the child is live).
        assert!(s.tick(fresh_budget(), fresh_rate(), 1000, &any_work).is_empty());
    }

    /// An errored exit is detected as a crash, alerts, and re-rolls only after the
    /// backoff window — then admission admits the roll.
    #[test]
    fn an_errored_exit_is_detected_then_re_rolled_after_backoff() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // A non-zero exit (the headless permission-prompt error) → crash.
        let out = s.poll("a1", AgentHealth::Exited { code: 1 }, None, 0);
        assert_eq!(
            out,
            PollOutcome::Crashed {
                event: NotifyEvent::agent_crashed("a1"),
                failures: 1,
                not_before: 2, // base backoff
            }
        );
        assert!(!s.is_running("a1"), "the crashed child was dropped");
        assert_eq!(backend.kill_count(), 0, "an exited child is not killed again");

        // Inside the backoff window → held, no re-spawn.
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 1, &any_work),
            vec![RerollOutcome::HeldForBackoff {
                agent: "a1".into(),
                not_before: 2
            }]
        );
        assert_eq!(backend.spawn_count(), 1);

        // At the backoff boundary → admission admits the roll → re-spawn.
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 2, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"]);
        assert!(s.is_running("a1"));
    }

    /// A hung agent (stale heartbeat) is killed before it is re-rolled.
    #[test]
    fn a_hung_agent_is_killed_before_re_roll() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // Alive but the last delta was 100s ago == the hang window → hung crash.
        let out = s.poll("a1", AgentHealth::Alive { last_active: 0 }, None, 100);
        assert!(matches!(out, PollOutcome::Crashed { failures: 1, .. }));
        assert_eq!(backend.kill_count(), 1, "the hung child was terminated");
        assert!(!s.is_running("a1"));

        // One under the window is still healthy.
        let backend2 = FakeBackend::new();
        let mut s2 = sup(Arc::clone(&backend2));
        s2.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert_eq!(
            s2.poll("a1", AgentHealth::Alive { last_active: 0 }, None, 99),
            PollOutcome::Healthy
        );
        assert_eq!(backend2.kill_count(), 0);
    }

    /// Repeated crashes grow the re-roll delay until it pins at the cap.
    #[test]
    fn backoff_cap_is_honored_across_repeated_crashes() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend)); // base 2, cap 8
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // delay(1..=5) for base 2 / cap 8 is 2, 4, 8, 8, 8.
        let expected = [2i64, 4, 8, 8, 8];
        let mut now = 0i64;
        for (i, &want) in expected.iter().enumerate() {
            // Observe a crash at `now`.
            let out = s.poll("a1", AgentHealth::Exited { code: 1 }, None, now);
            let PollOutcome::Crashed {
                failures,
                not_before,
                ..
            } = out
            else {
                panic!("expected a crash, got {out:?}");
            };
            assert_eq!(failures, (i + 1) as u32);
            assert_eq!(not_before - now, want, "backoff after crash {}", i + 1);
            assert!(not_before - now <= 8, "delay never exceeds the cap");
            // Advance to the boundary and let it re-roll for the next crash.
            now = not_before;
            assert_eq!(
                s.tick(fresh_budget(), fresh_rate(), now, &any_work),
                vec![RerollOutcome::Rerolled { agent: "a1".into() }]
            );
        }
    }

    /// A clean exit (code 0) re-rolls immediately with no alert and clears the
    /// failure streak.
    #[test]
    fn a_clean_exit_re_rolls_without_alert_or_backoff() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // Build up a failure streak first.
        s.poll("a1", AgentHealth::Exited { code: 1 }, None, 0);
        assert_eq!(s.failures("a1"), 1);
        s.tick(fresh_budget(), fresh_rate(), 2, &any_work); // re-roll

        // Now a clean exit at t=10 with no baton signal (the slice-002 precondition):
        // immediate re-roll, streak cleared, no alert.
        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, None, 10),
            PollOutcome::Rolling
        );
        assert_eq!(s.failures("a1"), 0, "a clean run clears the streak");
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 10, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "no backoff wait after a clean exit"
        );
    }

    /// A budget rail refuses the re-roll (the cap never gates a roll); when the
    /// budget recovers the same agent re-rolls.
    #[test]
    fn a_re_roll_is_held_when_the_budget_is_exhausted() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        s.poll("a1", AgentHealth::Exited { code: 1 }, None, 0); // crash, not_before = 2

        // Past the backoff window but the budget is hot → held on admission.
        assert_eq!(
            s.tick(hot_budget(), fresh_rate(), 5, &any_work),
            vec![RerollOutcome::HeldForAdmission {
                agent: "a1".into(),
                decision: AdmissionDecision::Refuse {
                    reason: RefuseReason::Budget5h
                }
            }]
        );
        assert!(!s.is_running("a1"));

        // Budget recovers → the roll is admitted (the cap is irrelevant to a roll).
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 6, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );
        assert!(s.is_running("a1"));
    }

    /// A failed re-spawn backs the agent off and is retried (no hot loop).
    #[test]
    fn a_failed_re_spawn_backs_off_and_retries() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0); // failures 0
        s.poll("a1", AgentHealth::Exited { code: 1 }, None, 0); // failures 1, not_before 2

        // Backend now refuses to launch.
        backend.set_fail(true);
        let out = s.tick(fresh_budget(), fresh_rate(), 2, &any_work);
        assert_eq!(
            out,
            vec![RerollOutcome::SpawnFailed {
                agent: "a1".into(),
                error: SpawnError("backend down".into()).to_string()
            }]
        );
        assert_eq!(s.failures("a1"), 2, "a failed re-spawn bumps the streak");
        assert!(!s.is_running("a1"));

        // Still held inside the grown backoff (delay(2) == 4 → not_before 6).
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 5, &any_work),
            vec![RerollOutcome::HeldForBackoff {
                agent: "a1".into(),
                not_before: 6
            }]
        );

        // Backend recovers → the retry re-rolls.
        backend.set_fail(false);
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 6, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );
    }

    /// Polling an agent that was never started is ignored.
    #[test]
    fn polling_an_unknown_agent_is_ignored() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        assert_eq!(
            s.poll("ghost", AgentHealth::Exited { code: 1 }, None, 0),
            PollOutcome::Unknown
        );
        assert_eq!(backend.spawn_count(), 0);
    }

    /// SLICE 002 — `poll_with_network` routes a non-zero exit to a soft RECONNECT
    /// (no streak bump, no backoff, no alert) when the predicate says "network", and
    /// to the historical CRASH path (streak + backoff + alert) when it says "genuine".
    #[test]
    fn poll_with_network_reconnects_a_network_exit_without_backoff() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend)); // base 2, cap 8
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // A network-classified non-zero exit → Reconnecting, no streak bump, no alert.
        let out = s.poll_with_network("a1", AgentHealth::Exited { code: 1 }, None, None, 0, || true);
        assert_eq!(out, PollOutcome::Reconnecting);
        assert_eq!(s.failures("a1"), 0, "a network exit bumps no failure streak");
        assert!(s.is_registered("a1"), "the member stays registered for its re-roll");

        // Re-roll it live again (a network exit is immediately re-rollable) — the
        // consumed-exit guard (task 044) makes a DOWN member's re-observation
        // inert, so the genuine-crash half below needs a live child to crash.
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 0, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );

        // A genuine (non-network) exit still crashes with backoff — the unchanged path.
        let out2 = s.poll_with_network("a1", AgentHealth::Exited { code: 1 }, None, None, 0, || false);
        let PollOutcome::Crashed { failures, not_before, .. } = out2 else {
            panic!("expected a crash, got {out2:?}");
        };
        assert_eq!(failures, 1, "a genuine crash bumps the streak");
        assert_eq!(not_before, 2, "and schedules the backoff (base 2)");
    }

    /// TASK 044 (the 2026-07-11 crash-exit stall) — an exit is CONSUMED exactly
    /// once. The backend health cell latches the last exit until a re-spawn
    /// overwrites it, so the drive loop re-observes a down member with the SAME
    /// exit every ~1s tick. Re-running the crash path on each re-observation
    /// bumped the streak and pushed `not_before` past `now` again — the re-roll
    /// was `HeldForBackoff` on every tick and a crashed member NEVER came back
    /// while its item sat `active`. A re-observation is the inert [`PollOutcome::Down`];
    /// the backoff the FIRST observation armed elapses and `tick` re-rolls.
    #[test]
    fn a_latched_exit_is_consumed_once_and_the_backoff_re_roll_still_fires() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend)); // base 2, cap 8
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // First observation: the genuine crash — streak 1, backoff armed for t=2.
        let out = s.poll("a1", AgentHealth::Exited { code: 1 }, None, 0);
        assert!(
            matches!(out, PollOutcome::Crashed { failures: 1, not_before: 2, .. }),
            "the first observation runs the crash path: {out:?}",
        );

        // Every subsequent tick re-observes the SAME latched exit: inert — no new
        // crash event, no streak bump, no backoff push (the pre-fix behaviour
        // bumped to failures 2/3 here and pushed not_before to 5 then 10).
        assert_eq!(s.poll("a1", AgentHealth::Exited { code: 1 }, None, 1), PollOutcome::Down);
        assert_eq!(s.poll("a1", AgentHealth::Exited { code: 1 }, None, 2), PollOutcome::Down);
        assert_eq!(s.failures("a1"), 1, "a re-observed exit bumps no streak");

        // The armed backoff elapses → the re-roll fires. Before the guard this was
        // `HeldForBackoff` on every tick forever — the incident's silent stall.
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 2, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"]);

        // The killed-hung twin: a hang crashes (kill + streak) once; the stale
        // `Alive` lingering until the reaper flips it re-observes as `Down` too.
        let out = s.poll("a1", AgentHealth::Alive { last_active: 2 }, None, 102);
        assert!(matches!(out, PollOutcome::Crashed { failures: 2, .. }), "got {out:?}");
        assert_eq!(backend.kill_count(), 1, "the hung child was killed");
        assert_eq!(
            s.poll("a1", AgentHealth::Alive { last_active: 2 }, None, 103),
            PollOutcome::Down,
            "the not-yet-reaped stale heartbeat is the same consumed crash",
        );
        assert_eq!(s.failures("a1"), 2, "still no re-observation bump");
    }

    /// The crash alert a `poll` returns routes through the phase-5 dispatcher to
    /// phone+GUI+log (an `AgentCrashed` is human-attention) — proving the alert
    /// fires end to end with the existing notification machinery.
    #[test]
    fn the_crash_alert_routes_through_the_notify_dispatcher() {
        use crate::notifications::NotifyPolicy;
        use crate::notify_dispatch::{LogNotifier, LogSink, NotifyDispatcher};
        use crate::Channel;

        #[derive(Debug, Default)]
        struct SpyLog(Mutex<Vec<String>>);
        impl LogSink for Arc<SpyLog> {
            fn write_line(&self, line: &str) {
                self.0.lock().unwrap().push(line.to_string());
            }
        }

        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("tab"), fresh_budget(), fresh_rate(), 0);

        let PollOutcome::Crashed { event, .. } =
            s.poll("tab", AgentHealth::Exited { code: 1 }, None, 0)
        else {
            panic!("expected a crash");
        };

        let spy = Arc::new(SpyLog::default());
        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(100));
        d.register(Box::new(LogNotifier::new(Arc::clone(&spy))));
        let channels = d.notify(&event, 0);

        // AgentCrashed is human-attention → routes to the phone too.
        assert!(channels.contains(&Channel::Gui));
        assert!(channels.contains(&Channel::Log));
        assert!(channels.contains(&Channel::Phone));
        assert_eq!(
            spy.0.lock().unwrap().clone(),
            vec!["growlightd alert: agent `tab` crashed".to_string()]
        );
    }

    /// `Backoff::delay` is `min(base << (n-1), cap)`, saturating and zero at 0.
    #[test]
    fn backoff_delay_doubles_then_caps() {
        let b = Backoff {
            base_secs: 5,
            cap_secs: 300,
        };
        assert_eq!(b.delay(0), 0);
        assert_eq!(b.delay(1), 5);
        assert_eq!(b.delay(2), 10);
        assert_eq!(b.delay(3), 20);
        assert_eq!(b.delay(7), 300, "5<<6 == 320 → capped at 300");
        assert_eq!(b.delay(1000), 300, "a long streak never overflows, pins at cap");
    }

    /// `is_registered` tracks membership across a crash (awaiting re-roll is still
    /// registered) and a retire (gone).
    #[test]
    fn is_registered_tracks_membership_across_a_crash_and_retire() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        assert!(!s.is_registered("a1"), "unknown agent is not registered");

        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert!(s.is_registered("a1") && s.is_running("a1"));

        // A crashed agent awaiting its re-roll is still registered (the loop must
        // not re-`start` it — `tick` rolls it).
        s.poll("a1", AgentHealth::Exited { code: 1 }, None, 0);
        assert!(!s.is_running("a1"));
        assert!(s.is_registered("a1"), "awaiting a re-roll is still registered");

        // Retire drops it entirely (no live child while awaiting a re-roll).
        assert!(s.retire("a1").is_none());
        assert!(!s.is_registered("a1"), "retired agent is gone");
    }

    /// `retire` hands back a running agent's live child for an outside-the-lock
    /// kill, and retires an unknown/down agent to nothing.
    #[test]
    fn retire_returns_a_live_child_then_drops_the_agent() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert!(s.is_running("a1"));

        // A running agent's retire yields its child (the loop kills it OUTSIDE the
        // lock for an immediate stop).
        let child = s.retire("a1").expect("a running agent yields its child");
        child.kill();
        assert_eq!(backend.kill_count(), 1, "the retired child was killed");
        assert!(!s.is_registered("a1"), "retired agent left the fleet");

        // A second retire (or an unknown agent) finds nothing.
        assert!(s.retire("a1").is_none());
        assert!(s.retire("ghost").is_none());
    }

    /// THE SPIN FIX (slice 001, [[decision-growlight-fleet-loop-spin]]): a member
    /// that exits cleanly on a `QUEUE_EMPTY` baton is RETIRED to idle — dropped
    /// from the fleet — and is NOT re-rolled. The inverse of the old behaviour,
    /// where a code-0 exit re-rolled unconditionally into a fresh `claude -p`.
    #[test]
    fn a_queue_empty_baton_retires_to_idle_and_is_not_re_rolled() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert_eq!(backend.spawn_count(), 1);

        // Clean exit carrying a QUEUE_EMPTY baton → retire, not re-roll.
        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("QUEUE_EMPTY"), 10),
            PollOutcome::Retired
        );
        assert!(!s.is_registered("a1"), "a retired member left the fleet");
        assert!(!s.is_running("a1"));

        // The whole point: no re-roll. A tick well past any backoff spawns nothing.
        assert!(
            s.tick(fresh_budget(), fresh_rate(), 1_000, &any_work).is_empty(),
            "a retired member is never a re-roll candidate"
        );
        assert_eq!(backend.spawn_count(), 1, "NO fresh claude -p on a drained queue");
        assert_eq!(backend.kill_count(), 0, "the clean exit needs no kill");
    }

    /// A `STUCK` baton **releases** the member to idle (slot freed, not sticky-
    /// parked) and names the block via [`PollOutcome::Blocked`] — the drive loop
    /// item-parks the part + alerts the human. A released member is never re-rolled.
    #[test]
    fn a_stuck_baton_releases_the_member_to_idle() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("STUCK"), 10),
            PollOutcome::Blocked {
                status: "STUCK".into(),
                spin_guard: false,
            }
        );
        // Released = gone from the fleet (slot freed), exactly like an item boundary
        // — NOT sticky-parked on its slot. The freed slot lets a fresh start re-pick.
        assert!(!s.is_registered("a1"), "a blocked member releases its slot");
        assert_eq!(s.committed_count(), 0, "the slot is freed for a pivot");
        assert!(
            s.tick(fresh_budget(), fresh_rate(), 1_000, &any_work).is_empty(),
            "a released member has nothing to re-roll"
        );
        assert_eq!(backend.spawn_count(), 1, "no re-roll of a released member");
        assert_eq!(backend.kill_count(), 0, "the clean exit needs no kill");
    }

    /// A `BLOCKED_ON_HUMAN` baton releases the member, exactly like `STUCK` (carries
    /// the raw status for the log).
    #[test]
    fn a_blocked_on_human_baton_releases_the_member_to_idle() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("BLOCKED_ON_HUMAN"), 10),
            PollOutcome::Blocked {
                status: "BLOCKED_ON_HUMAN".into(),
                spin_guard: false,
            }
        );
        assert!(!s.is_registered("a1"), "a blocked member releases its slot");
        assert!(s.tick(fresh_budget(), fresh_rate(), 1_000, &any_work).is_empty());
    }

    /// An unrecognized terminal status is a `Stuck(_)` disposition — it releases the
    /// member to idle too (conservative: an unknown status needs a human), never a
    /// blind re-roll.
    #[test]
    fn an_unrecognized_baton_status_releases_the_member() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("WAT_IS_THIS"), 10),
            PollOutcome::Blocked {
                status: "WAT_IS_THIS".into(),
                spin_guard: false,
            }
        );
        assert!(!s.is_registered("a1"));
    }

    /// A `HALTED_RATE_LIMIT` baton parks WITHOUT an alert (a transient halt), is
    /// held by admission while the window is still hot, and is **auto-re-armed** by
    /// `tick` the moment the rate window recovers — no human, no restart. This is
    /// the "work till the limit, then resume when it restores" behaviour (slice
    /// 003's timed re-arm).
    #[test]
    fn a_rate_limited_baton_parks_then_re_arms_when_the_window_recovers() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // The rate-limit baton parks it without an alert, slot kept.
        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("HALTED_RATE_LIMIT"), 10),
            PollOutcome::ParkedRateLimited
        );
        assert!(s.is_registered("a1"), "a rate-parked member keeps its slot");
        assert!(!s.is_running("a1"));

        // While the window is still hot, the re-arm is HELD by admission — no
        // respawn (it does not spin against the limit).
        let held = s.tick(hot_budget(), hot_rate(), 1_000, &any_work);
        assert!(
            matches!(held.as_slice(), [RerollOutcome::HeldForAdmission { agent, .. }] if agent == "a1"),
            "a rate-parked member is held, not re-rolled, while the window is hot: {held:?}",
        );
        assert_eq!(backend.spawn_count(), 1, "no respawn while still throttled");

        // The window recovers → tick re-arms it (re-rolls) and clears the park.
        let armed = s.tick(fresh_budget(), fresh_rate(), 2_000, &any_work);
        assert_eq!(
            armed,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "the rate-parked member is auto-re-armed once the window recovers",
        );
        assert!(s.is_running("a1"), "re-armed → running again");
        assert_eq!(backend.spawn_count(), 2);
    }

    /// The queue-gate: a clean-exit member awaiting a re-roll is NOT re-rolled when
    /// its queue has no workable part (`workable` is false) — it is held and keeps
    /// its slot, so it never respawns `claude -p` into a drained queue (the respawn
    /// half of the empty-queue spin fix). When work reappears it re-rolls.
    #[test]
    fn the_re_roll_is_queue_gated_no_workable_part_holds() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        // A continue-status clean exit arms a re-roll (child down, registered).
        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("IN_PROGRESS"), 10),
            PollOutcome::Rolling
        );

        // Queue empty for this agent → held, not re-rolled.
        let no_work = |_: &str| false;
        let held = s.tick(fresh_budget(), fresh_rate(), 20, &no_work);
        assert_eq!(
            held,
            vec![RerollOutcome::HeldNoWork { agent: "a1".into() }],
            "no workable part ⇒ the re-roll is held, not spawned",
        );
        assert_eq!(backend.spawn_count(), 1, "no respawn into an empty queue");
        assert!(s.is_registered("a1"), "the member keeps its slot");

        // Work reappears → it re-rolls.
        let armed = s.tick(fresh_budget(), fresh_rate(), 21, &any_work);
        assert_eq!(armed, vec![RerollOutcome::Rerolled { agent: "a1".into() }]);
        assert_eq!(backend.spawn_count(), 2);
    }

    /// Atomic `max_agents`: a fresh start is gated on the COMMITTED roster, not just
    /// live children, so a slot reserved by a member that is momentarily down
    /// (here: inside a crash backoff) cannot be transiently filled by a fresh start
    /// and then overshot when the down member re-rolls. With cap 1, while a1 backs
    /// off, a2 is Queued — never two concurrent.
    #[test]
    fn a_fresh_start_never_overshoots_the_cap_while_a_member_is_down() {
        let backend = FakeBackend::new();
        // Cap 1: at most one concurrent agent.
        let policy = Policy {
            max_concurrent_agents: 1,
            ..Policy::default()
        };
        let mut s = Supervisor::with_backoff(
            Box::new(Arc::clone(&backend)),
            AdmissionGovernor::new(policy),
            Backoff { base_secs: 10, cap_secs: 100 },
            100,
        );
        // a1 starts and then crashes → down, registered, inside its backoff window.
        assert_eq!(s.start(spec("a1"), fresh_budget(), fresh_rate(), 0), StartOutcome::Started);
        s.poll("a1", AgentHealth::Exited { code: 1 }, None, 0); // crash → not_before = 10
        assert!(!s.is_running("a1"), "a1 is down, awaiting its backoff re-roll");
        assert_eq!(s.committed_count(), 1, "a1 still OWNS its slot while down");

        // A fresh a2 must be QUEUED — the committed cap is full even though no
        // child is live right now. (With the old live_count gate this admitted a2,
        // and a1's later re-roll then made TWO concurrent against cap 1.)
        assert_eq!(
            s.start(spec("a2"), fresh_budget(), fresh_rate(), 1),
            StartOutcome::Queued { active: 1, cap: 1 },
            "a slot reserved by a down member is not stolen by a fresh start",
        );
        assert_eq!(s.committed_count(), 1, "a2 was not registered");
    }

    /// A continue-status baton (`IN_PROGRESS`) still re-rolls — the loop keeps the
    /// member going, exactly as before the spin fix.
    #[test]
    fn a_continue_baton_still_re_rolls() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("IN_PROGRESS"), 10),
            PollOutcome::Rolling
        );
        assert!(s.is_registered("a1"));
        // No backoff after a clean exit → an immediate re-roll.
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 10, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );
        assert_eq!(backend.spawn_count(), 2, "a continue baton re-rolls");
    }

    /// SPIN GUARD (task 038): a member that clean-exits on a continue status
    /// (`IN_PROGRESS`) with the SAME `# NEXT ACTION` across `STALL_LIMIT` consecutive
    /// re-rolls is wedged — the fleet analog of the deleted `--auto` STUCK threshold
    /// (protocol step 6). The first repeat arms the streak (still re-rolls), the
    /// second TRIPS it: the member is released to idle as a spin-guard block instead
    /// of re-rolled, so it stops burning the shared budget, and the block is tagged
    /// `spin_guard: true` so the drive loop can name WHY it parked. (This is also the
    /// never-rewrites-its-baton case — an untouched seed keeps a constant NEXT ACTION.)
    #[test]
    fn spin_guard_trips_when_next_action_is_unchanged_across_re_rolls() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert_eq!(backend.spawn_count(), 1);

        // First continue-exit on "compile it" → arms the streak (1), re-rolls as normal.
        assert_eq!(
            s.poll_with_network(
                "a1",
                AgentHealth::Exited { code: 0 },
                Some("IN_PROGRESS"),
                Some("compile it"),
                10,
                || false,
            ),
            PollOutcome::Rolling
        );
        assert!(s.is_registered("a1"), "still in the fleet after the first repeat");
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 10, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );
        assert_eq!(backend.spawn_count(), 2, "the first re-roll fired");

        // Second continue-exit on the SAME NEXT ACTION: no progress → the guard trips.
        assert_eq!(
            s.poll_with_network(
                "a1",
                AgentHealth::Exited { code: 0 },
                Some("IN_PROGRESS"),
                Some("compile it"),
                20,
                || false,
            ),
            PollOutcome::Blocked {
                status: "STUCK (spin guard): NEXT ACTION unchanged across 2 consecutive re-rolls"
                    .into(),
                spin_guard: true,
            }
        );
        // Released like an agent-written STUCK — slot freed, never re-rolled, so no
        // further sessions (no shared-budget burn) are spent on the wedged member.
        assert!(!s.is_registered("a1"), "the spun-out member left the fleet");
        assert!(s.tick(fresh_budget(), fresh_rate(), 1_000, &any_work).is_empty());
        assert_eq!(backend.spawn_count(), 2, "no re-roll of the released member");
        assert_eq!(backend.kill_count(), 0, "the clean exit needs no kill");
    }

    /// Task 047: a continue-exit whose re-roll is HELD (admission budget/rate)
    /// re-observes the same latched clean exit every tick — those re-observations
    /// are inert (`Down`), never fed to the spin guard. Pre-fix, two held ticks
    /// bumped the unchanged-NEXT-ACTION streak to `STALL_LIMIT` and the guard
    /// mislabel-parked the item `blocked` on a human (the 2026-07-20 m5f parks:
    /// `holding a (admission budget/rate)` → one second later `blocked on a
    /// human decision`). The member must stay registered on its part, resume via
    /// the next admission window, and the guard must still trip on REAL
    /// consecutive sessions.
    #[test]
    fn a_held_continue_exit_is_consumed_once_and_never_trips_the_spin_guard() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert_eq!(backend.spawn_count(), 1);

        // The continue-exit: streak 1, immediate re-roll armed.
        assert_eq!(
            s.poll_with_network(
                "a1",
                AgentHealth::Exited { code: 0 },
                Some("IN_PROGRESS"),
                Some("compile it"),
                10,
                || false,
            ),
            PollOutcome::Rolling
        );

        // The re-roll is admission-held (hot budget) — the member stays down.
        assert_eq!(
            s.tick(hot_budget(), fresh_rate(), 11, &any_work),
            vec![RerollOutcome::HeldForAdmission {
                agent: "a1".into(),
                decision: AdmissionDecision::Refuse { reason: RefuseReason::Budget5h }
            }]
        );

        // Every held tick re-observes the SAME latched clean exit: inert. Pre-fix
        // the second observation returned `Blocked { spin_guard: true }` here.
        for t in 12..16 {
            assert_eq!(
                s.poll_with_network(
                    "a1",
                    AgentHealth::Exited { code: 0 },
                    Some("IN_PROGRESS"),
                    Some("compile it"),
                    t,
                    || false,
                ),
                PollOutcome::Down,
                "a held member's re-observed clean exit must stay inert (t={t})",
            );
        }
        assert!(s.is_registered("a1"), "the held member never left the fleet");

        // Admission recovers → the timed resume re-rolls the SAME member.
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 20, &any_work),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );
        assert_eq!(backend.spawn_count(), 2, "resumed via the admission window");

        // The guard still does its real job: a SECOND full session ending on the
        // byte-identical NEXT ACTION is a genuine no-progress streak → trip.
        assert_eq!(
            s.poll_with_network(
                "a1",
                AgentHealth::Exited { code: 0 },
                Some("IN_PROGRESS"),
                Some("compile it"),
                30,
                || false,
            ),
            PollOutcome::Blocked {
                status: "STUCK (spin guard): NEXT ACTION unchanged across 2 consecutive re-rolls"
                    .into(),
                spin_guard: true,
            }
        );
    }

    /// The guard does NOT trip while the member makes progress: a DIFFERENT
    /// `# NEXT ACTION` each continue-exit resets the streak, so it keeps re-rolling
    /// indefinitely (the normal within-item handoff — the opposite failure mode from
    /// task 033's stall, which the guard must not reintroduce).
    #[test]
    fn spin_guard_does_not_trip_when_next_action_changes() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        for (i, na) in ["step one", "step two", "step three", "step four"]
            .iter()
            .enumerate()
        {
            let now = (i as i64) * 10;
            assert_eq!(
                s.poll_with_network(
                    "a1",
                    AgentHealth::Exited { code: 0 },
                    Some("IN_PROGRESS"),
                    Some(na),
                    now,
                    || false,
                ),
                PollOutcome::Rolling,
                "a changing NEXT ACTION keeps re-rolling (iteration {i})"
            );
            assert!(s.is_registered("a1"));
            // Re-roll it live so the next iteration observes a fresh exit.
            s.tick(fresh_budget(), fresh_rate(), now, &any_work);
        }
        assert!(s.is_registered("a1"), "progress never trips the guard");
        assert_eq!(backend.spawn_count(), 5, "start + one re-roll per progressing exit");
    }

    /// A `HALTED_RATE_LIMIT` park between two identical continue-exits RESETS the spin
    /// streak — a budget pause is not a no-progress stall, so a member that resumes on
    /// the same NEXT ACTION after its window reopens is not mistaken for spinning.
    #[test]
    fn spin_guard_streak_resets_on_a_rate_limit_park() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // Continue-exit on "resume the build" → arms the streak (1).
        assert_eq!(
            s.poll_with_network(
                "a1",
                AgentHealth::Exited { code: 0 },
                Some("IN_PROGRESS"),
                Some("resume the build"),
                10,
                || false,
            ),
            PollOutcome::Rolling
        );
        s.tick(fresh_budget(), fresh_rate(), 10, &any_work);
        // A rate-limit park before the next session clears the streak.
        assert_eq!(
            s.poll_with_network(
                "a1",
                AgentHealth::Exited { code: 0 },
                Some("HALTED_RATE_LIMIT"),
                None,
                20,
                || false,
            ),
            PollOutcome::ParkedRateLimited
        );
        s.tick(fresh_budget(), fresh_rate(), 20, &any_work);
        // Window reopened; the member exits on the SAME NEXT ACTION. With the streak
        // reset this is only the FIRST repeat again → re-roll, not a trip.
        assert_eq!(
            s.poll_with_network(
                "a1",
                AgentHealth::Exited { code: 0 },
                Some("IN_PROGRESS"),
                Some("resume the build"),
                30,
                || false,
            ),
            PollOutcome::Rolling
        );
        assert!(
            s.is_registered("a1"),
            "the rate-limit park cleared the streak, so no spin trip"
        );
    }

    /// With NO `# NEXT ACTION` signal (a missing/unreadable baton) the guard stays
    /// inert — a `None` can't prove a repeat — preserving the historical no-baton
    /// clean-exit re-roll exactly (mirrors the `--auto` guard, which also required
    /// both sides present to count a repeat).
    #[test]
    fn spin_guard_stays_inert_without_a_next_action_signal() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        for i in 0..4 {
            let now = i * 10;
            assert_eq!(
                s.poll_with_network(
                    "a1",
                    AgentHealth::Exited { code: 0 },
                    Some("IN_PROGRESS"),
                    None,
                    now,
                    || false,
                ),
                PollOutcome::Rolling,
                "no NEXT ACTION signal → historical re-roll (iteration {i})"
            );
            s.tick(fresh_budget(), fresh_rate(), now, &any_work);
        }
        assert!(
            s.is_registered("a1"),
            "a no-signal member keeps re-rolling, never spin-tripped"
        );
    }

    /// THE FLEET-MEMBER-MODEL FIX (slice 001): a member that exits cleanly on an
    /// `ITEM_COMPLETE` baton RELEASES its slot — dropped from the fleet, exactly
    /// like a retire — and is NOT re-rolled by the supervisor. Continuation is the
    /// drive loop's job (re-claim its next part through the fresh-start handshake,
    /// proven in the drive_loop tests); here we prove the supervisor releases the
    /// member and never self-rolls the same finished part.
    #[test]
    fn an_item_complete_baton_releases_to_idle_and_is_not_re_rolled() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert_eq!(backend.spawn_count(), 1);

        // Clean exit carrying an ITEM_COMPLETE baton → release to idle, not re-roll.
        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("ITEM_COMPLETE"), 10),
            PollOutcome::Completed
        );
        assert!(!s.is_registered("a1"), "a released member left the fleet (slot freed)");
        assert!(!s.is_running("a1"));

        // The supervisor never re-rolls it — the finished part is not re-run.
        assert!(
            s.tick(fresh_budget(), fresh_rate(), 1_000, &any_work).is_empty(),
            "a released member is not a re-roll candidate",
        );
        assert_eq!(backend.spawn_count(), 1, "no supervisor self-roll on an item boundary");
        assert_eq!(backend.kill_count(), 0, "the clean exit needs no kill");
    }

    /// `ITEM_DEFERRED` releases to idle identically to `ITEM_COMPLETE` — both are
    /// item boundaries (the member's part is done with, slot freed).
    #[test]
    fn an_item_deferred_baton_also_releases_to_idle() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("ITEM_DEFERRED"), 10),
            PollOutcome::Completed
        );
        assert!(!s.is_registered("a1"), "ITEM_DEFERRED also frees the slot");
        assert!(s.tick(fresh_budget(), fresh_rate(), 1_000, &any_work).is_empty());
        assert_eq!(backend.spawn_count(), 1, "no self-roll on a deferred boundary");
    }
}
