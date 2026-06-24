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
//! - **A clean exit rolls free.** Exit code 0 is a session that ended on its own
//!   baton boundary; it re-rolls immediately (no backoff, no alert) and clears the
//!   failure streak — the loop simply keeps the agent going.
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
    /// Exited cleanly — scheduled an immediate re-roll, cleared the failure
    /// streak, no alert.
    Rolling,
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

    /// Agents with a live child right now (the fleet size admission gates on).
    pub fn live_count(&self) -> u32 {
        self.agents.values().filter(|s| s.child.is_some()).count() as u32
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
    pub fn start(
        &mut self,
        spec: AgentSpec,
        budget: BudgetUsage,
        rate: RateState,
        now: i64,
    ) -> StartOutcome {
        let fleet = self.live_count();
        match self.governor.decide(Intent::Start, fleet, budget, rate) {
            AdmissionDecision::Admit => match self.backend.spawn(&spec) {
                Ok(child) => {
                    self.agents.insert(
                        spec.agent.clone(),
                        Supervised {
                            spec,
                            child: Some(child),
                            consecutive_failures: 0,
                            not_before: now,
                        },
                    );
                    StartOutcome::Started
                }
                Err(e) => StartOutcome::SpawnFailed {
                    error: e.to_string(),
                },
            },
            AdmissionDecision::Queue { active, cap } => StartOutcome::Queued { active, cap },
            AdmissionDecision::Refuse { reason } => StartOutcome::Refused { reason },
        }
    }

    /// Observe one supervised agent's `health` at `now`. Healthy → nothing; clean
    /// exit → schedule an immediate re-roll (streak cleared); crash → kill any
    /// live (hung) child, bump the streak, schedule a backoff re-roll, and return
    /// the [`NotifyEvent::AgentCrashed`] alert.
    pub fn poll(&mut self, agent: &str, health: AgentHealth, now: i64) -> PollOutcome {
        // Copy the pure config out so the per-agent mutable borrow stands alone.
        let backoff = self.backoff;
        let hang_secs = self.hang_secs;
        let Some(sup) = self.agents.get_mut(agent) else {
            return PollOutcome::Unknown;
        };
        match classify(&health, hang_secs, now) {
            Verdict::Healthy => PollOutcome::Healthy,
            Verdict::CleanExit => {
                // Ended on its own boundary — drop the dead handle and roll fresh
                // immediately, clearing the failure streak.
                sup.child = None;
                sup.consecutive_failures = 0;
                sup.not_before = now;
                PollOutcome::Rolling
            }
            Verdict::Crashed => {
                // A hung child is still alive — terminate it via the AgentChild
                // contract (the drive loop runs poll off the connection lock, so
                // the kill-outside-the-lock invariant holds). An *errored exit* is
                // already gone, so its handle is just dropped (no needless SIGKILL).
                let was_hung = matches!(health, AgentHealth::Alive { .. });
                if let Some(child) = sup.child.take() {
                    if was_hung {
                        child.kill();
                    }
                }
                sup.consecutive_failures = sup.consecutive_failures.saturating_add(1);
                let delay = backoff.delay(sup.consecutive_failures);
                sup.not_before = now.saturating_add(delay);
                PollOutcome::Crashed {
                    event: NotifyEvent::AgentCrashed {
                        agent: agent.to_string(),
                    },
                    failures: sup.consecutive_failures,
                    not_before: sup.not_before,
                }
            }
        }
    }

    /// Perform any due re-rolls ([`Intent::Roll`]). For each registered agent with
    /// no live child: held if still inside its backoff window; else admission-gated
    /// (cap never gates a roll, budget/rate do); on admit the backend re-spawns it.
    /// A failed re-spawn bumps the streak and backs off. Returns one outcome per
    /// candidate; running agents produce nothing.
    pub fn tick(&mut self, budget: BudgetUsage, rate: RateState, now: i64) -> Vec<RerollOutcome> {
        let candidates: Vec<String> = self
            .agents
            .iter()
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
            // A roll keeps the agent's slot — the cap never gates it — but the
            // shared budget/rate rails still do.
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

    /// A healthy heartbeat leaves the agent running untouched — no kill, no spawn.
    #[test]
    fn a_healthy_agent_runs_uninterrupted() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // Recent heartbeat (well inside the 100s hang window).
        assert_eq!(
            s.poll("a1", AgentHealth::Alive { last_active: 950 }, 1000),
            PollOutcome::Healthy
        );
        assert!(s.is_running("a1"));
        assert_eq!(backend.spawn_count(), 1, "no re-spawn for a healthy agent");
        assert_eq!(backend.kill_count(), 0, "no kill for a healthy agent");
        // tick has no candidate (the child is live).
        assert!(s.tick(fresh_budget(), fresh_rate(), 1000).is_empty());
    }

    /// An errored exit is detected as a crash, alerts, and re-rolls only after the
    /// backoff window — then admission admits the roll.
    #[test]
    fn an_errored_exit_is_detected_then_re_rolled_after_backoff() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        s.start(spec("a1"), fresh_budget(), fresh_rate(), 0);

        // A non-zero exit (the headless permission-prompt error) → crash.
        let out = s.poll("a1", AgentHealth::Exited { code: 1 }, 0);
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
            s.tick(fresh_budget(), fresh_rate(), 1),
            vec![RerollOutcome::HeldForBackoff {
                agent: "a1".into(),
                not_before: 2
            }]
        );
        assert_eq!(backend.spawn_count(), 1);

        // At the backoff boundary → admission admits the roll → re-spawn.
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 2),
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
        let out = s.poll("a1", AgentHealth::Alive { last_active: 0 }, 100);
        assert!(matches!(out, PollOutcome::Crashed { failures: 1, .. }));
        assert_eq!(backend.kill_count(), 1, "the hung child was terminated");
        assert!(!s.is_running("a1"));

        // One under the window is still healthy.
        let backend2 = FakeBackend::new();
        let mut s2 = sup(Arc::clone(&backend2));
        s2.start(spec("a1"), fresh_budget(), fresh_rate(), 0);
        assert_eq!(
            s2.poll("a1", AgentHealth::Alive { last_active: 0 }, 99),
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
            let out = s.poll("a1", AgentHealth::Exited { code: 1 }, now);
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
                s.tick(fresh_budget(), fresh_rate(), now),
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
        s.poll("a1", AgentHealth::Exited { code: 1 }, 0);
        assert_eq!(s.failures("a1"), 1);
        s.tick(fresh_budget(), fresh_rate(), 2); // re-roll

        // Now a clean exit at t=10: immediate re-roll, streak cleared, no alert.
        assert_eq!(
            s.poll("a1", AgentHealth::Exited { code: 0 }, 10),
            PollOutcome::Rolling
        );
        assert_eq!(s.failures("a1"), 0, "a clean run clears the streak");
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 10),
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
        s.poll("a1", AgentHealth::Exited { code: 1 }, 0); // crash, not_before = 2

        // Past the backoff window but the budget is hot → held on admission.
        assert_eq!(
            s.tick(hot_budget(), fresh_rate(), 5),
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
            s.tick(fresh_budget(), fresh_rate(), 6),
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
        s.poll("a1", AgentHealth::Exited { code: 1 }, 0); // failures 1, not_before 2

        // Backend now refuses to launch.
        backend.set_fail(true);
        let out = s.tick(fresh_budget(), fresh_rate(), 2);
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
            s.tick(fresh_budget(), fresh_rate(), 5),
            vec![RerollOutcome::HeldForBackoff {
                agent: "a1".into(),
                not_before: 6
            }]
        );

        // Backend recovers → the retry re-rolls.
        backend.set_fail(false);
        assert_eq!(
            s.tick(fresh_budget(), fresh_rate(), 6),
            vec![RerollOutcome::Rerolled { agent: "a1".into() }]
        );
    }

    /// Polling an agent that was never started is ignored.
    #[test]
    fn polling_an_unknown_agent_is_ignored() {
        let backend = FakeBackend::new();
        let mut s = sup(Arc::clone(&backend));
        assert_eq!(
            s.poll("ghost", AgentHealth::Exited { code: 1 }, 0),
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
            s.poll("tab", AgentHealth::Exited { code: 1 }, 0)
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
        s.poll("a1", AgentHealth::Exited { code: 1 }, 0);
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
}
