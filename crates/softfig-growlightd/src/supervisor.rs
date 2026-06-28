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
//!   maps it — a continue status (or no baton yet) re-rolls immediately (no
//!   backoff, no alert, streak cleared); `QUEUE_EMPTY` **retires** the member to
//!   idle (it leaves the fleet, so it is never re-rolled — the empty-queue spin
//!   fix, [[decision-growlight-fleet-loop-spin]]); `HALTED_RATE_LIMIT` **parks**
//!   it until its window resets; an agent-written `STUCK` / `BLOCKED_ON_HUMAN` /
//!   unrecognized status **parks** it and surfaces an [`NotifyEvent::AgentCrashed`]
//!   human alert. Deciding re-roll-vs-retire purely on the exit code — without
//!   this read — is what spun `claude -p` on a drained queue.
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
    /// Exited cleanly on a `HALTED_RATE_LIMIT` baton — parked (kept in the fleet,
    /// not re-rolled) until its rate window resets. No alert: a transient halt the
    /// budget governor resumes (slice 003 wires the timed re-arm).
    ParkedRateLimited,
    /// Exited cleanly on a `STUCK` / `BLOCKED_ON_HUMAN` / unrecognized baton — the
    /// loop can't safely continue, so the member is parked (kept, not re-rolled)
    /// pending a human, and this §9 alert is surfaced for the caller to route.
    Parked {
        /// The [`NotifyEvent::AgentCrashed`] to dispatch (the agent needs a human).
        event: NotifyEvent,
        /// The raw terminal baton status that parked it (for the log/alert).
        status: String,
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

/// Why a cleanly-exited member is **parked** — kept in the fleet (it holds its
/// concurrency slot) but not immediately re-rolled. The reason decides whether
/// [`tick`](Supervisor::tick) may auto-resume it:
///
/// - [`RateLimited`](ParkReason::RateLimited) is a *transient* park: the member
///   hit `HALTED_RATE_LIMIT`, so it stays a re-roll candidate but admission's rate
///   /budget gate holds it every tick until the window recovers, at which point
///   `tick` re-rolls it automatically (the timed re-arm — "work till the limit,
///   then resume when it restores"). No human needed.
/// - [`Human`](ParkReason::Human) is a *sticky* park: `STUCK` / `BLOCKED_ON_HUMAN`
///   (or an unrecognized status) needs a person, so `tick` never re-rolls it on
///   its own — it is excluded from the candidate set until a human clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParkReason {
    /// `HALTED_RATE_LIMIT` — auto-re-armed by `tick` once admission recovers.
    RateLimited,
    /// `STUCK` / `BLOCKED_ON_HUMAN` / unrecognized — never auto-re-armed.
    Human,
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
    /// Parked on a terminal baton — kept in the fleet (still holds its slot) but
    /// handled per [`ParkReason`]: a `RateLimited` park stays a re-roll candidate
    /// (admission holds it until its window recovers, then `tick` re-arms it); a
    /// `Human` park is excluded from re-rolls until a person clears it. `None` is
    /// the normal running / awaiting-re-roll state. The `QUEUE_EMPTY` case never
    /// parks; it retires (leaves the fleet entirely).
    park: Option<ParkReason>,
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
                                park: None,
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
        let hang_secs = self.hang_secs;
        if !self.agents.contains_key(agent) {
            return PollOutcome::Unknown;
        }
        match classify(&health, hang_secs, now) {
            Verdict::Healthy => PollOutcome::Healthy,
            Verdict::CleanExit => self.on_clean_exit(agent, baton_status, now),
            Verdict::Crashed => self.on_crash(agent, health, now),
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
            event: NotifyEvent::AgentCrashed {
                agent: agent.to_string(),
            },
            failures: sup.consecutive_failures,
            not_before: sup.not_before,
        }
    }

    /// Decide what a clean (code-0) exit means by reading the agent's terminal
    /// baton status — the spin fix. The shared [`softfig_ipc::baton`] vocabulary
    /// classifies it; each disposition maps to a fleet lifecycle:
    ///
    /// - **Continue** (or `None` — no baton write-back yet, the slice-002
    ///   precondition) → re-roll immediately, streak cleared (today's behaviour).
    /// - **`QUEUE_EMPTY`** → **retire**: the member leaves the fleet entirely, so
    ///   [`tick`](Self::tick) never re-rolls it. No spin on a drained queue.
    /// - **`HALTED_RATE_LIMIT`** → **park** until its window resets (no alert).
    /// - **`BLOCKED_ON_HUMAN` / `STUCK` / unrecognized** → **park** + an
    ///   [`NotifyEvent::AgentCrashed`] human alert.
    ///
    /// A parked member keeps its slot but is skipped by `tick`; a retired one is
    /// gone. Both stop the re-roll, which is what kept `claude -p` spinning.
    fn on_clean_exit(&mut self, agent: &str, baton_status: Option<&str>, now: i64) -> PollOutcome {
        // No baton signal → the historical clean-exit re-roll. Slice 002 wires the
        // per-member write-back so a working member always supplies a status; until
        // then (and for a brand-new member's first boundary) this is the fallback.
        let Some(status) = baton_status else {
            return self.roll(agent, now);
        };
        match classify_status(Some(status)) {
            BatonDisposition::Continue => self.roll(agent, now),
            BatonDisposition::QueueEmpty => {
                // Retire to idle: drop the member so it is never re-rolled. The
                // child already exited (clean), so there is nothing to kill.
                self.agents.remove(agent);
                PollOutcome::Retired
            }
            BatonDisposition::RateLimited => {
                // Transient: keep it a re-roll candidate, but admission's rate gate
                // holds it until the window recovers, when `tick` re-arms it.
                self.park(agent, ParkReason::RateLimited);
                PollOutcome::ParkedRateLimited
            }
            BatonDisposition::BlockedOnHuman | BatonDisposition::Stuck(_) => {
                self.park(agent, ParkReason::Human);
                PollOutcome::Parked {
                    event: NotifyEvent::AgentCrashed {
                        agent: agent.to_string(),
                    },
                    status: status.to_string(),
                }
            }
        }
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

    /// Park a cleanly-exited member with its [`ParkReason`]: drop the dead handle
    /// and record why it parked. It keeps its slot (still registered). A `Human`
    /// park is skipped by [`tick`](Self::tick) until a person clears it; a
    /// `RateLimited` park stays a candidate that admission holds until its window
    /// recovers (then `tick` re-arms it).
    fn park(&mut self, agent: &str, reason: ParkReason) {
        if let Some(sup) = self.agents.get_mut(agent) {
            sup.child = None;
            sup.park = Some(reason);
        }
    }

    /// Perform any due re-rolls ([`Intent::Roll`]). For each registered agent with
    /// no live child: held if still inside its backoff window; held if its queue has
    /// no workable part (`workable(agent)` is `false` — the queue-gate, so a
    /// clean-exit member is never re-rolled into an empty queue); else
    /// admission-gated (cap never gates a roll, budget/rate do); on admit the
    /// backend re-spawns it. A failed re-spawn bumps the streak and backs off.
    /// Returns one outcome per candidate; running agents produce nothing.
    ///
    /// `workable` answers "does this agent have a pickable part right now?" — the
    /// drive loop builds it from the same pinned-with-fallback [`crate::scheduler::pick`]
    /// a fresh start uses, over this tick's queue snapshot. It is the belt-and-
    /// suspenders to slice 001's terminal-status retire: even a member that exited
    /// on a *continue* status is not respawned if its queue has since drained.
    ///
    /// A [`ParkReason::RateLimited`] member IS a candidate: admission's rate/budget
    /// gate holds it (a [`RerollOutcome::HeldForAdmission`]) every tick until its
    /// window recovers, at which point this re-roll re-arms it and clears the park
    /// — the timed re-arm. A [`ParkReason::Human`] member is excluded entirely
    /// (only a person resumes it).
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
            // Down members only (a live child is left running). A `Human` park is
            // skipped until a person clears it; a `RateLimited` park stays a
            // candidate so admission can re-arm it when its window recovers. Not
            // re-rolling a `Human`-parked member is what stops the spin.
            .filter(|(_, s)| s.child.is_none() && !matches!(s.park, Some(ParkReason::Human)))
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
            // shared budget/rate rails still do (and hold a rate-limited park here
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
                    // Re-armed: a successful re-roll clears any rate-limit park.
                    sup.park = None;
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
                event: NotifyEvent::AgentCrashed {
                    agent: "a1".into()
                },
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

    /// A `STUCK` baton parks the member (kept but not re-rolled) and surfaces the
    /// §9 `AgentCrashed` human alert.
    #[test]
    fn a_stuck_baton_parks_with_an_alert_and_is_not_re_rolled() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("STUCK"), 10),
            PollOutcome::Parked {
                event: NotifyEvent::AgentCrashed { agent: "a1".into() },
                status: "STUCK".into(),
            }
        );
        // Parked = kept in the fleet (still registered) but never re-rolled.
        assert!(s.is_registered("a1"), "a parked member keeps its slot");
        assert!(!s.is_running("a1"));
        assert!(
            s.tick(fresh_budget(), fresh_rate(), 1_000, &any_work).is_empty(),
            "a parked member is skipped by tick"
        );
        assert_eq!(backend.spawn_count(), 1, "no re-roll of a stuck member");
    }

    /// A `BLOCKED_ON_HUMAN` baton parks + alerts, exactly like `STUCK` (carries the
    /// raw status for the alert/log).
    #[test]
    fn a_blocked_on_human_baton_parks_with_an_alert() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, Some("BLOCKED_ON_HUMAN"), 10),
            PollOutcome::Parked {
                event: NotifyEvent::AgentCrashed { agent: "a1".into() },
                status: "BLOCKED_ON_HUMAN".into(),
            }
        );
        assert!(s.is_registered("a1"));
        assert!(s.tick(fresh_budget(), fresh_rate(), 1_000, &any_work).is_empty());
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
}
