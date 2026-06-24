//! The orchestration **drive loop** (drive-loop slice 002) — the thin coordinator
//! that turns the proven phase 3–6 pure cores into a running fleet
//! (spec-growlight-orchestrator §6 scheduler, §7 admission, §8 control, §15
//! operational must-haves).
//!
//! ## What this is (and isn't)
//!
//! [`DriveLoop::tick`] is the daemon's per-cycle coordinator. It instantiates
//! nothing new — it *binds* the existing cores: the pure scheduler
//! ([`crate::scheduler::pick`] / [`parked`]), the [`Supervisor`] (which itself
//! owns the [`crate::admission::AdmissionGovernor`] and the live
//! [`crate::supervisor::AgentBackend`]), and the daemon's control state
//! ([`Daemon::take_pending_stop`] / [`Daemon::drain_inject_lane`] /
//! [`Daemon::is_paused`]). Each tick, for the configured fleet:
//!
//! 1. **Honor control** at the per-agent boundary (spec §8): a pending boundary
//!    stop (`stop_after_slice` / `stop_after_iteration`) is read once and the
//!    agent retired when it next reaches its boundary; the boundary-async inject
//!    lane is drained (delivered at the agent's next baton, never mid-iteration);
//!    `pause` gates admission so a paused fleet starts and rolls nothing.
//! 2. **Observe + re-roll** (spec §15): each agent's [`AgentHealth`] feeds
//!    [`Supervisor::poll`]; a crash surfaces a [`NotifyEvent::AgentCrashed`] and
//!    schedules a capped-backoff re-roll, performed by [`Supervisor::tick`].
//! 3. **Schedule + admit + spawn** (spec §6/§7): the [`Snapshot`] picks each idle
//!    member's next workable part (pinned-with-fallback, pivot-on-block); an
//!    admitted [`Intent::Start`](crate::admission::Intent) spawns it via the live
//!    backend under the per-device cap, a queued/refused one is held.
//!
//! The hard logic already exists and is unit-proven in isolation; this loop is the
//! thin binding around it. The live data sources are **default-deferred seams**,
//! exactly like [`crate::leases::ThrashClear`] / [`crate::notify_dispatch::BusEmit`]:
//!
//! - [`QueueSource`] — the live impl pulls keeperd's per-queue managed regions;
//!   wiring that pull is `growlight-wire-loose-ends`.
//! - [`BudgetSource`] — the live impl is the cross-agent [`crate::usage`]
//!   aggregator feed; wiring that is drive-loop slice 003.
//! - [`AgentHealthSource`] — implemented over [`crate::claude_backend::ClaudeBackend`]
//!   (slice 001), so the live loop reads real `stream-json` heartbeats.
//!
//! Keeping the sources behind seams keeps `tick` provable over fakes (scripted
//! queues / budget / health, the slice-001 fake backend) with **no real `claude`
//! spawn**, and lets the live assembly land in the slices that own each source.
//! The crash dispatcher itself is the drive loop's single
//! [`crate::notify_dispatch::NotifyDispatcher`], wired in slice 003 — for now each
//! tick *collects* the crash + park events into its [`TickReport`] for the caller
//! to route.
//!
//! ## Time
//!
//! [`DriveLoop::tick`] takes `now` (injected Unix seconds), like every pure core;
//! only [`spawn_drive_loop`]'s live thread reads the wall clock.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::admission::{BudgetUsage, RateState};
use crate::claude_backend::ClaudeBackend;
use crate::daemon::Daemon;
use crate::notifications::NotifyEvent;
use crate::scheduler::{parked, pick, Snapshot};
use crate::state::State;
use crate::supervisor::{
    AgentHealth, AgentSpec, PollOutcome, RerollOutcome, StartOutcome, Supervisor,
};

/// How often the live drive loop ticks: schedule, observe health, honor control,
/// re-roll. Agents run for minutes per session, so a ~1s cadence is ample — this
/// is not a hot path (mirrors [`crate::bus::BUS_POLL_MS`]).
pub const DRIVE_POLL_MS: u64 = 1_000;

/// The seam the loop reads the current multi-queue [`Snapshot`] through. The
/// production impl pulls keeperd's per-queue managed regions (the `queue` /
/// `queue:<name>` item tables) — deferred to `growlight-wire-loose-ends`; a test
/// injects a fixed snapshot.
pub trait QueueSource: Send + Sync + fmt::Debug {
    /// The current view of every queue the fleet can draw from, in fallback order.
    fn snapshot(&self) -> Snapshot;
}

/// The seam the loop reads the shared budget + per-minute rate through, to gate
/// admission. The production impl is the cross-agent [`crate::usage`] aggregator
/// feed (drive-loop slice 003); a test injects fixed readings.
pub trait BudgetSource: Send + Sync + fmt::Debug {
    /// The current shared-pool budget reserves and rolling-minute rate readings.
    fn readings(&self) -> (BudgetUsage, RateState);
}

/// The seam the loop reads per-agent [`AgentHealth`] through, to feed
/// [`Supervisor::poll`]. Implemented over the live [`ClaudeBackend`] (slice 001),
/// which tracks a heartbeat-or-exit cell per agent; a test scripts the health.
pub trait AgentHealthSource: Send + Sync + fmt::Debug {
    /// `agent`'s current health, or `None` if it was never spawned (so the loop
    /// skips a `poll` it has no observation for).
    fn health(&self, agent: &str) -> Option<AgentHealth>;
}

impl AgentHealthSource for Arc<ClaudeBackend> {
    fn health(&self, agent: &str) -> Option<AgentHealth> {
        // Disambiguate from this trait method: call the inherent one on the
        // backed `ClaudeBackend`.
        self.as_ref().health(agent)
    }
}

/// One configured fleet member: the agent's spawn [`AgentSpec`] plus the
/// work-stream it is **pinned** to (pinned-with-fallback, spec §6). An unpinned
/// member (`pin: None`) goes straight to fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetMember {
    /// The per-agent spawn spec (id + pre-approval file paths).
    pub spec: AgentSpec,
    /// The agent's pinned queue name, or `None` for an unpinned agent.
    pub pin: Option<String>,
}

impl FleetMember {
    /// A member pinned to `pin`'s work-stream.
    pub fn pinned(spec: AgentSpec, pin: impl Into<String>) -> Self {
        Self {
            spec,
            pin: Some(pin.into()),
        }
    }

    /// An unpinned member (fallback-only).
    pub fn unpinned(spec: AgentSpec) -> Self {
        Self { spec, pin: None }
    }
}

/// A scheduler assignment the loop acted on this tick: which agent it started on
/// which `(queue, part)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The agent that was started.
    pub agent: String,
    /// The queue the scheduler picked for it.
    pub queue: String,
    /// The part (item id) at that queue's head.
    pub part: String,
}

/// A start the admission governor did not admit this tick — queued (cap) or
/// refused (budget/rate). Carries the [`StartOutcome`] so the caller can log /
/// alert the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldStart {
    /// The agent whose start was held.
    pub agent: String,
    /// The non-admit outcome (`Queued` / `Refused` / `SpawnFailed`).
    pub outcome: StartOutcome,
}

/// Everything one [`DriveLoop::tick`] did, for the caller (the live thread, or a
/// test) to inspect and — in slice 003 — route through the single notification
/// dispatcher.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Agents started this tick, with their scheduler assignment.
    pub started: Vec<Assignment>,
    /// Starts held by admission (cap queue / budget-rate refuse / spawn failure).
    pub held_starts: Vec<HeldStart>,
    /// Re-roll outcomes from [`Supervisor::tick`] (rerolled / held / failed).
    pub rerolls: Vec<RerollOutcome>,
    /// Crash alerts surfaced by [`Supervisor::poll`] (slice 003 dispatches these).
    pub crashes: Vec<NotifyEvent>,
    /// Agents retired this tick (a boundary stop was honored).
    pub retired: Vec<String>,
    /// Boundary-async messages drained from inject lanes, per agent.
    pub injected: Vec<(String, Vec<String>)>,
    /// Parked (blocked-head) queues, surfaced for the §9 alert hook every tick —
    /// even while paused, so the human still learns an item needs them.
    pub parked: Vec<(String, String)>,
    /// Whether admission was gated by `pause` this tick (no starts/rolls attempted).
    pub paused: bool,
}

/// The fleet drive loop: binds the scheduler, the [`Supervisor`], and the daemon
/// control state into one per-tick coordinator. Owned by the daemon's drive-loop
/// thread (see [`spawn_drive_loop`]) — it carries `&mut self` mutable state (the
/// supervised fleet, the retire/stop bookkeeping), so it is NOT shared behind the
/// daemon mutex; it reads control through the daemon's lock-brief boundary
/// accessors.
#[derive(Debug)]
pub struct DriveLoop {
    /// The daemon handle — read-only here for control intent + lifecycle (the loop
    /// never mutates `DaemonInner` directly; it goes through the public boundary
    /// accessors, each of which takes the daemon lock only briefly).
    daemon: Daemon,
    /// The fleet supervisor (owns the live backend + admission governor).
    supervisor: Supervisor,
    /// Per-agent health probe (the live [`ClaudeBackend`] in production).
    health: Box<dyn AgentHealthSource>,
    /// Where the multi-queue snapshot comes from.
    queues: Box<dyn QueueSource>,
    /// Where the budget/rate readings come from.
    budget: Box<dyn BudgetSource>,
    /// The configured fleet (specs + pins). Stable across ticks; lifecycle is
    /// tracked in `retiring`/`stopped`, not by mutating this.
    fleet: Vec<FleetMember>,
    /// Agents that were asked to stop and are awaiting their next boundary to
    /// retire (the boundary intent was consumed; this persists it until honored).
    retiring: BTreeSet<String>,
    /// Agents that have retired on a boundary stop — never re-started this run.
    stopped: BTreeSet<String>,
}

impl DriveLoop {
    /// Assemble a drive loop over its seams + fleet. The `health` probe should
    /// observe the SAME backend the `supervisor` spawns through (in production both
    /// are clones of one `Arc<ClaudeBackend>`).
    pub fn new(
        daemon: Daemon,
        supervisor: Supervisor,
        health: Box<dyn AgentHealthSource>,
        queues: Box<dyn QueueSource>,
        budget: Box<dyn BudgetSource>,
        fleet: Vec<FleetMember>,
    ) -> Self {
        Self {
            daemon,
            supervisor,
            health,
            queues,
            budget,
            fleet,
            retiring: BTreeSet::new(),
            stopped: BTreeSet::new(),
        }
    }

    /// One orchestration cycle at `now` (injected Unix seconds): honor control,
    /// observe + re-roll, then schedule + admit + spawn. Returns a [`TickReport`]
    /// of everything it did.
    pub fn tick(&mut self, now: i64) -> TickReport {
        let mut report = TickReport::default();
        let (budget, rate) = self.budget.readings();
        let paused = self.daemon.is_paused();
        report.paused = paused;

        // Clone the configured fleet up front so the per-agent pass can borrow the
        // supervisor / lifecycle sets mutably without aliasing `self.fleet`.
        let fleet = self.fleet.clone();

        // 1. Per-agent control + health pass (boundary semantics, spec §8).
        for member in &fleet {
            let agent = &member.spec.agent;

            // a. Honor a pending boundary stop, exactly once. The agent does not
            //    stop until it reaches its boundary; we just record the intent.
            if self.daemon.take_pending_stop(agent).is_some() {
                self.retiring.insert(agent.clone());
            }

            // b. Drain the boundary-async inject lane (delivered at the agent's
            //    next baton — folding it into the next session is wire-loose-ends).
            let drained = self.daemon.drain_inject_lane(agent);
            if !drained.is_empty() {
                report.injected.push((agent.clone(), drained));
            }

            // c. Health-driven lifecycle. No observation (never spawned, or already
            //    retired) → nothing to poll.
            if let Some(health) = self.health.health(agent) {
                match self.supervisor.poll(agent, health, now) {
                    PollOutcome::Crashed { event, .. } => {
                        report.crashes.push(event);
                        // A retiring agent that crashes at its boundary stops here
                        // rather than re-rolling.
                        if self.retiring.remove(agent) {
                            self.retire(agent, &mut report);
                        }
                    }
                    PollOutcome::Rolling => {
                        // Clean boundary exit: a retiring agent stops here instead
                        // of re-rolling; otherwise `Supervisor::tick` rolls it below.
                        if self.retiring.remove(agent) {
                            self.retire(agent, &mut report);
                        }
                    }
                    PollOutcome::Healthy | PollOutcome::Unknown => {}
                }
            }
        }

        // 2. Re-roll due agents ([`Intent::Roll`]). `pause` is the admission gate
        //    (spec §8): a paused fleet attempts no rolls (and no starts, below).
        if !paused {
            report.rerolls = self.supervisor.tick(budget, rate, now);
        }

        // 3. Schedule + admit + spawn. Read the snapshot once; surface parked
        //    queues regardless of pause, then start fresh agents only when running.
        let snapshot = self.queues.snapshot();
        report.parked = parked(&snapshot);
        if !paused {
            for member in &fleet {
                let agent = &member.spec.agent;
                // A stopping/stopped agent is never (re-)started; a registered one
                // re-rolls via step 2, it is not re-`start`ed.
                if self.retiring.contains(agent)
                    || self.stopped.contains(agent)
                    || self.supervisor.is_registered(agent)
                {
                    continue;
                }
                let Some((queue, part)) = pick(&snapshot, member.pin.as_deref()) else {
                    continue; // nothing workable for this agent's pin right now
                };
                match self.supervisor.start(member.spec.clone(), budget, rate, now) {
                    StartOutcome::Started => report.started.push(Assignment {
                        agent: agent.clone(),
                        queue,
                        part,
                    }),
                    outcome => report.held_starts.push(HeldStart {
                        agent: agent.clone(),
                        outcome,
                    }),
                }
            }
        }

        report
    }

    /// Retire `agent` from the supervisor on a boundary stop, killing any live
    /// child OUTSIDE any daemon lock (the [`crate::control::AgentChild`] contract).
    /// Records the retire and marks the agent permanently stopped for this run.
    fn retire(&mut self, agent: &str, report: &mut TickReport) {
        if let Some(child) = self.supervisor.retire(agent) {
            child.kill();
        }
        self.stopped.insert(agent.to_string());
        report.retired.push(agent.to_string());
    }
}

/// Spawn the daemon-owned drive-loop thread: tick the loop every `interval` until
/// the daemon enters [`State::Stopping`], mirroring [`crate::bus::spawn_bus_tailer`].
/// The live thread reads the wall clock for `now`; the pure [`DriveLoop::tick`]
/// stays time-injected so it is unit-proven against fakes.
///
/// Construction of a *live* `DriveLoop` (a real [`ClaudeBackend`], the keeperd
/// [`QueueSource`], the usage-aggregator [`BudgetSource`]) is assembled by the
/// slices that own each source; this is the thread shape that drives it.
pub fn spawn_drive_loop(
    daemon: Daemon,
    mut drive: DriveLoop,
    interval: Duration,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("growlightd-drive-loop".into())
        .spawn(move || {
            while daemon.state() != State::Stopping {
                drive.tick(unix_now());
                thread::sleep(interval);
            }
        })
}

/// Wall-clock Unix seconds for the live thread's `now`. The pure policy stays
/// time-injected; only this live driver reads the clock (mirrors
/// [`crate::claude_backend`]'s local clock).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{AdmissionDecision, AdmissionGovernor, RefuseReason};
    use crate::config::{GrowlightdConfig, Policy};
    use crate::control::AgentChild;
    use crate::scheduler::{PartView, QueueView};
    use crate::supervisor::{AgentBackend, Backoff, SpawnError};
    use softfig_ipc::growlightd::StopLevel;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

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

    /// A fake fleet backend that is BOTH the spawn seam ([`AgentBackend`]) and the
    /// health probe ([`AgentHealthSource`]) — the production split is `ClaudeBackend`
    /// behind both. Records every spawn, scripts each agent's health, and shares a
    /// kill counter with the children it makes.
    #[derive(Debug, Default)]
    struct FakeFleet {
        spawns: Mutex<Vec<String>>,
        kills: Arc<AtomicUsize>,
        health: Mutex<BTreeMap<String, AgentHealth>>,
    }
    impl FakeFleet {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn set_health(&self, agent: &str, h: AgentHealth) {
            self.health.lock().unwrap().insert(agent.to_string(), h);
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
    }
    impl AgentBackend for Arc<FakeFleet> {
        fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
            self.spawns.lock().unwrap().push(spec.agent.clone());
            Ok(Box::new(FakeChild {
                kills: Arc::clone(&self.kills),
            }))
        }
    }
    impl AgentHealthSource for Arc<FakeFleet> {
        fn health(&self, agent: &str) -> Option<AgentHealth> {
            self.health.lock().unwrap().get(agent).copied()
        }
    }

    /// A fixed (mutable) queue snapshot source.
    #[derive(Debug)]
    struct FixedQueues(Mutex<Snapshot>);
    impl FixedQueues {
        fn new(qs: Vec<QueueView>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(Snapshot::new(qs))))
        }
    }
    impl QueueSource for Arc<FixedQueues> {
        fn snapshot(&self) -> Snapshot {
            self.0.lock().unwrap().clone()
        }
    }

    /// A fixed (mutable) budget/rate source.
    #[derive(Debug)]
    struct FixedBudget(Mutex<(BudgetUsage, RateState)>);
    impl FixedBudget {
        fn fresh() -> Arc<Self> {
            Arc::new(Self(Mutex::new((fresh_budget(), fresh_rate()))))
        }
        fn set(&self, budget: BudgetUsage) {
            self.0.lock().unwrap().0 = budget;
        }
    }
    impl BudgetSource for Arc<FixedBudget> {
        fn readings(&self) -> (BudgetUsage, RateState) {
            *self.0.lock().unwrap()
        }
    }

    fn fresh_budget() -> BudgetUsage {
        BudgetUsage::new(10, 5)
    }
    fn hot_budget() -> BudgetUsage {
        BudgetUsage::new(90, 5) // over the 85 5h halt
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
    fn member(id: &str, pin: &str) -> FleetMember {
        FleetMember::pinned(spec(id), pin)
    }
    fn q(name: &str, rows: &[(&str, &str)]) -> QueueView {
        QueueView::new(
            name,
            rows.iter().map(|(i, s)| PartView::new(*i, s)).collect(),
        )
    }
    fn daemon() -> Daemon {
        Daemon::new(GrowlightdConfig::new("/run/g.sock".into(), "/garden".into()))
    }

    /// Assemble a loop with the given fleet + policy over fresh seam fakes,
    /// returning the loop plus the handles a test pokes (daemon control, backend
    /// health, budget). The supervisor uses a small, easy-to-assert backoff.
    fn make(
        fleet: Vec<FleetMember>,
        snapshot: Vec<QueueView>,
        policy: Policy,
    ) -> (DriveLoop, Daemon, Arc<FakeFleet>, Arc<FixedBudget>) {
        let d = daemon();
        let backend = FakeFleet::new();
        let budget = FixedBudget::fresh();
        let queues = FixedQueues::new(snapshot);
        let sup = Supervisor::with_backoff(
            Box::new(Arc::clone(&backend)),
            AdmissionGovernor::new(policy),
            Backoff {
                base_secs: 2,
                cap_secs: 8,
            },
            100,
        );
        let drive = DriveLoop::new(
            d.clone(),
            sup,
            Box::new(Arc::clone(&backend)),
            Box::new(Arc::clone(&queues)),
            Box::new(Arc::clone(&budget)),
            fleet,
        );
        (drive, d, backend, budget)
    }

    /// The loop picks each member's pinned part, admits under the per-device cap,
    /// and queues the over-cap start.
    #[test]
    fn schedules_and_starts_under_the_cap_queuing_the_rest() {
        let (mut loop_, _d, backend, _budget) = make(
            vec![member("a1", "qa"), member("a2", "qb"), member("a3", "qc")],
            vec![
                q("qa", &[("p1", "queued")]),
                q("qb", &[("p2", "queued")]),
                q("qc", &[("p3", "queued")]),
            ],
            Policy::default(), // cap 2
        );

        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![
                Assignment {
                    agent: "a1".into(),
                    queue: "qa".into(),
                    part: "p1".into()
                },
                Assignment {
                    agent: "a2".into(),
                    queue: "qb".into(),
                    part: "p2".into()
                },
            ],
            "two members start, each on its pinned part",
        );
        assert_eq!(
            r.held_starts,
            vec![HeldStart {
                agent: "a3".into(),
                outcome: StartOutcome::Queued { active: 2, cap: 2 },
            }],
            "the third is queued behind the cap",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a2"], "only admitted starts spawn");

        // A second tick starts nothing new (the two are running; the third is still
        // capped) and re-rolls nothing (all healthy / no observation).
        let r2 = loop_.tick(1);
        assert!(r2.started.is_empty());
        assert_eq!(backend.spawn_count(), 2, "no duplicate spawn of running agents");
    }

    /// An exhausted shared budget refuses a start (not a slot wait).
    #[test]
    fn an_exhausted_budget_refuses_the_start() {
        let (mut loop_, _d, backend, budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        budget.set(hot_budget());

        let r = loop_.tick(0);
        assert!(r.started.is_empty());
        assert_eq!(
            r.held_starts,
            vec![HeldStart {
                agent: "a1".into(),
                outcome: StartOutcome::Refused {
                    reason: RefuseReason::Budget5h
                },
            }],
        );
        assert_eq!(backend.spawn_count(), 0, "a refused start never spawns");
    }

    /// A blocked pinned head does not halt the agent — it pivots to another queue,
    /// and the blocked head is surfaced as parked for the §9 alert.
    #[test]
    fn pivots_off_a_blocked_pinned_queue_and_surfaces_the_park() {
        let (mut loop_, _d, backend, _budget) = make(
            vec![member("a1", "mine")],
            vec![
                q("mine", &[("p1", "blocked"), ("p2", "queued")]),
                q("other", &[("o1", "queued")]),
            ],
            Policy::default(),
        );

        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![Assignment {
                agent: "a1".into(),
                queue: "other".into(),
                part: "o1".into()
            }],
            "a blocked pinned head pivots to the fallback queue",
        );
        assert_eq!(
            r.parked,
            vec![("mine".into(), "p1".into())],
            "the blocked head is surfaced for the human alert",
        );
        assert_eq!(backend.spawns(), vec!["a1"]);
    }

    /// A pending boundary stop is honored once: the agent retires at its next clean
    /// boundary instead of re-rolling, and is never re-started.
    #[test]
    fn honors_a_boundary_stop_then_never_re_starts_the_agent() {
        let (mut loop_, d, backend, _budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());

        // Tick 1 starts a1.
        assert_eq!(loop_.tick(0).started.len(), 1);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // The human asks a1 to stop after its slice; a1 then reaches a clean
        // boundary (exit 0).
        d.inner
            .lock()
            .unwrap()
            .control
            .request_stop("a1", StopLevel::AfterSlice);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });

        let r = loop_.tick(1);
        assert_eq!(r.retired, vec!["a1".to_string()], "the boundary stop retired a1");
        assert!(r.rerolls.is_empty(), "a retiring agent does not re-roll");
        assert_eq!(backend.spawn_count(), 1, "a1 was not re-spawned");

        // The stop is permanent for this run: even with workable queued work, a
        // later tick never re-starts a1.
        let r2 = loop_.tick(2);
        assert!(r2.started.is_empty() && r2.rerolls.is_empty());
        assert_eq!(backend.spawn_count(), 1, "a stopped agent is never re-started");
    }

    /// The inject lane is boundary-async: a queued message is invisible until the
    /// next tick drains it, and it is delivered exactly once.
    #[test]
    fn drains_the_inject_lane_at_the_boundary_once() {
        let (mut loop_, d, _backend, _budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        loop_.tick(0); // start a1

        // Queue two messages mid-run; nothing observes them yet.
        d.inner.lock().unwrap().control.queue_inject("a1", "ping".into());
        d.inner.lock().unwrap().control.queue_inject("a1", "pong".into());

        let r = loop_.tick(1);
        assert_eq!(
            r.injected,
            vec![("a1".to_string(), vec!["ping".to_string(), "pong".to_string()])],
            "the lane drains in FIFO order at the boundary",
        );

        // Delivered once — the next boundary drains nothing.
        let r2 = loop_.tick(2);
        assert!(r2.injected.is_empty(), "a second boundary drains nothing");
    }

    /// A crashed agent surfaces an `AgentCrashed` alert, is held through its
    /// backoff window, then re-rolls when the window opens.
    #[test]
    fn re_rolls_a_crashed_agent_after_its_backoff() {
        let (mut loop_, _d, backend, _budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());

        // Tick 1 starts a1.
        loop_.tick(0);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // a1 errors out → crash classification.
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        let r = loop_.tick(0);
        assert_eq!(
            r.crashes,
            vec![NotifyEvent::AgentCrashed { agent: "a1".into() }],
            "the crash surfaces an alert for the dispatcher (slice 003)",
        );
        assert_eq!(
            r.rerolls,
            vec![RerollOutcome::HeldForBackoff {
                agent: "a1".into(),
                not_before: 2,
            }],
            "inside the backoff window it is held",
        );
        assert_eq!(backend.spawn_count(), 1, "no re-spawn yet");

        // The re-rolled session is healthy; at the backoff boundary it re-rolls.
        backend.set_health("a1", AgentHealth::Alive { last_active: 2 });
        let r2 = loop_.tick(2);
        assert!(r2.crashes.is_empty(), "the healthy poll raises no new crash");
        assert_eq!(
            r2.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"], "a1 was re-spawned");
    }

    /// `pause` is the admission gate: a paused fleet starts nothing and re-rolls
    /// nothing; resuming releases both. Parked queues are still surfaced.
    #[test]
    fn pause_gates_starts_and_re_rolls_resume_releases_them() {
        let (mut loop_, d, backend, _budget) = make(
            vec![member("a1", "qa")],
            vec![
                q("qa", &[("p1", "queued")]),
                q("parked", &[("b1", "blocked")]),
            ],
            Policy::default(),
        );

        // Start a1, then crash it so a re-roll is pending.
        loop_.tick(0);
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        loop_.tick(0); // crash → held for backoff (not_before 2)
        assert_eq!(backend.spawn_count(), 1);

        // Pause; past the backoff window a re-roll would be due, but pause gates it.
        d.inner.lock().unwrap().control.pause();
        backend.set_health("a1", AgentHealth::Alive { last_active: 2 });
        let r = loop_.tick(2);
        assert!(r.paused, "the tick reports the paused gate");
        assert!(r.rerolls.is_empty(), "no re-roll while paused");
        assert!(r.started.is_empty(), "no new start while paused");
        assert_eq!(
            r.parked,
            vec![("parked".into(), "b1".into())],
            "parked queues are surfaced even while paused",
        );
        assert_eq!(backend.spawn_count(), 1, "paused: nothing spawned");

        // Resume → the held re-roll fires.
        d.inner.lock().unwrap().control.resume();
        let r2 = loop_.tick(3);
        assert!(!r2.paused);
        assert_eq!(
            r2.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "resume releases the re-roll",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"]);
    }

    /// An immediate-stop (force_stop hard kill) retiring agent that is still alive
    /// at its boundary crash is killed via the returned child, outside any lock.
    #[test]
    fn a_hung_retiring_agent_is_killed_on_retire() {
        let (mut loop_, d, backend, _budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        loop_.tick(0); // start a1
        assert_eq!(backend.kill_count(), 0);

        // Ask a1 to stop, and have it hang (stale heartbeat) — poll classifies a
        // crash and kills the still-live child; the retire path also drops it.
        d.inner
            .lock()
            .unwrap()
            .control
            .request_stop("a1", StopLevel::AfterIteration);
        backend.set_health("a1", AgentHealth::Alive { last_active: 0 });
        let r = loop_.tick(1000); // 1000s gap >> 100s hang window → hung crash

        assert_eq!(r.retired, vec!["a1".to_string()]);
        assert!(
            r.crashes.contains(&NotifyEvent::AgentCrashed { agent: "a1".into() }),
            "the hung agent also surfaces a crash alert",
        );
        // The supervisor's poll kills the hung child once; retire finds it already
        // taken, so no double kill.
        assert_eq!(backend.kill_count(), 1, "the hung child was killed exactly once");
        // Permanently stopped: never re-started.
        let r2 = loop_.tick(1001);
        assert!(r2.started.is_empty());
        assert_eq!(backend.spawn_count(), 1);
    }

    /// An unpinned member falls back to the first ready queue.
    #[test]
    fn an_unpinned_member_takes_the_first_ready_queue() {
        let (mut loop_, _d, backend, _budget) = make(
            vec![FleetMember::unpinned(spec("a1"))],
            vec![
                q("claimed", &[("c1", "active")]), // skipped (claimed)
                q("free", &[("f1", "queued")]),
            ],
            Policy::default(),
        );
        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![Assignment {
                agent: "a1".into(),
                queue: "free".into(),
                part: "f1".into()
            }],
        );
        assert_eq!(backend.spawns(), vec!["a1"]);
    }

    /// Belt-and-suspenders: a budget that goes hot AFTER the fleet is running holds
    /// a re-roll on admission (the cap never gates a roll, the budget rail does).
    #[test]
    fn a_re_roll_is_held_when_the_budget_goes_hot() {
        let (mut loop_, _d, backend, budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        loop_.tick(0); // start a1
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        loop_.tick(0); // crash → backoff not_before 2

        budget.set(hot_budget());
        backend.set_health("a1", AgentHealth::Alive { last_active: 2 });
        let r = loop_.tick(2);
        assert_eq!(
            r.rerolls,
            vec![RerollOutcome::HeldForAdmission {
                agent: "a1".into(),
                decision: AdmissionDecision::Refuse {
                    reason: RefuseReason::Budget5h
                },
            }],
        );
        assert_eq!(backend.spawn_count(), 1, "the held re-roll did not spawn");
    }
}
