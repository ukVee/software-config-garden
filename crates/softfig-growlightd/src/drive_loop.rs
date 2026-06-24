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
//! - [`BudgetSampleSource`] — the live impl is the per-agent
//!   [`ClaudeBackend`] budget cell (slice 003); each tick the loop folds every
//!   agent's reading into its **owned** [`UsageAggregator`] and gates admission on
//!   the aggregate. [`RateSource`] feeds admission's second (rate) gate — live
//!   feed is `growlight-wire-loose-ends`, [`PermissiveRate`] until then.
//! - [`AgentHealthSource`] — implemented over [`crate::claude_backend::ClaudeBackend`]
//!   (slice 001), so the live loop reads real `stream-json` heartbeats.
//!
//! Keeping the sources behind seams keeps `tick` provable over fakes (scripted
//! queues / budget / health, the slice-001 fake backend) with **no real `claude`
//! spawn**, and lets the live assembly land in the slices that own each source.
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
use crate::notify_dispatch::NotifyDispatcher;
use crate::scheduler::{parked, pick, Snapshot};
use crate::state::State;
use crate::supervisor::{
    AgentHealth, AgentSpec, PollOutcome, RerollOutcome, StartOutcome, Supervisor,
};
use crate::usage::{UsageAggregator, UsageSample};

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

/// The seam the loop reads each agent's latest reading of the **shared** account
/// budget pool through, to fold into the loop's owned cross-agent
/// [`UsageAggregator`]. The aggregate then gates admission and fires the §9 usage
/// alert. Implemented over the live [`ClaudeBackend`]'s per-agent budget cell
/// (drive-loop slice 003); a test injects per-agent readings.
pub trait BudgetSampleSource: Send + Sync + fmt::Debug {
    /// `agent`'s latest reading of the shared pool, or `None` if it has not
    /// reported a parseable reserve yet (so the aggregator skips it this tick).
    fn budget(&self, agent: &str) -> Option<BudgetUsage>;
}

impl BudgetSampleSource for Arc<ClaudeBackend> {
    fn budget(&self, agent: &str) -> Option<BudgetUsage> {
        // Disambiguate from this trait method: call the inherent one on the
        // backed `ClaudeBackend`.
        self.as_ref().budget(agent)
    }
}

/// The seam the loop reads the per-minute **rate** (TPM/RPM) through, admission's
/// second gate alongside the budget aggregate. The live feed (the keeperd rate
/// handshake) is out of this slice — `growlight-wire-loose-ends` binds it; until
/// then [`PermissiveRate`] grants headroom and a test injects a fixed rate.
pub trait RateSource: Send + Sync + fmt::Debug {
    /// The current rolling-minute rate reading.
    fn rate(&self) -> RateState;
}

/// The default [`RateSource`] until the live rate feed lands: generous per-minute
/// headroom so the rate gate never refuses. The budget aggregate and the
/// per-device cap are the live gates this slice wires; the real rate feed is
/// `growlight-wire-loose-ends`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PermissiveRate;

impl RateSource for PermissiveRate {
    fn rate(&self) -> RateState {
        RateState {
            tpm_used: 0,
            rpm_used: 0,
            tpm_limit: u32::MAX,
            rpm_limit: u32::MAX,
            tpm_per_agent: 0,
            rpm_per_agent: 0,
        }
    }
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
    /// Per-agent shared-pool budget readings, folded into `aggregator` each tick.
    samples: Box<dyn BudgetSampleSource>,
    /// Per-minute rate readings — admission's second gate.
    rate: Box<dyn RateSource>,
    /// The cross-agent usage aggregate (owned): refreshed from `samples` each tick,
    /// it feeds admission (gate on real fleet burn) and the single §9 usage alert
    /// ([`UsageAggregator::fleet_alert`]).
    aggregator: UsageAggregator,
    /// The single notification dispatcher (owned): every tick's events — crashes,
    /// parked (blocked-head) items, the usage alert — route through it, so its
    /// per-event dedup/cooldown makes a sustained condition announce at most once
    /// per window (spec §9). Owned (not per-tick) precisely so that state persists
    /// across ticks.
    dispatcher: NotifyDispatcher,
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
    /// Assemble a drive loop over its seams + fleet. The `health` and `samples`
    /// probes should observe the SAME backend the `supervisor` spawns through (in
    /// production all three are clones of one `Arc<ClaudeBackend>`). The owned
    /// [`UsageAggregator`] starts empty (a fresh fleet has burned nothing); the
    /// `dispatcher` arrives with its channels already registered (in production a
    /// [`crate::notify_dispatch::GuiNotifier`] over the daemon hub + a
    /// [`crate::notify_dispatch::LogNotifier`]).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        daemon: Daemon,
        supervisor: Supervisor,
        health: Box<dyn AgentHealthSource>,
        queues: Box<dyn QueueSource>,
        samples: Box<dyn BudgetSampleSource>,
        rate: Box<dyn RateSource>,
        dispatcher: NotifyDispatcher,
        fleet: Vec<FleetMember>,
    ) -> Self {
        Self {
            daemon,
            supervisor,
            health,
            queues,
            samples,
            rate,
            aggregator: UsageAggregator::new(),
            dispatcher,
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
        let paused = self.daemon.is_paused();
        report.paused = paused;

        // Clone the configured fleet up front so the per-agent passes can borrow the
        // supervisor / aggregator / lifecycle sets mutably without aliasing
        // `self.fleet`.
        let fleet = self.fleet.clone();

        // 0. Refresh the cross-agent usage aggregate BEFORE the admission gate
        //    (spec §7): fold in each live agent's latest reading of the shared
        //    pool, and forget a stopped agent's stale reading so it can never pin
        //    the aggregate after it leaves the fleet (see [`crate::usage`]).
        for member in &fleet {
            let agent = &member.spec.agent;
            if self.stopped.contains(agent) {
                self.aggregator.forget(agent);
            } else if let Some(budget) = self.samples.budget(agent) {
                self.aggregator
                    .observe(UsageSample::new(agent.clone(), budget));
            }
        }
        let budget = self.aggregator.aggregate_or_fresh();
        let rate = self.rate.rate();

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

        // 4. Route this tick's events through the single owned dispatcher (spec
        //    §9). The report is still RETURNED for the caller (and tests) to
        //    inspect — dispatch is the live side-effect on top of it.
        self.dispatch(&report, now);

        report
    }

    /// Route a completed tick's events through the single owned
    /// [`NotifyDispatcher`] (spec §9): every surfaced crash and every parked
    /// (blocked-head) item alerts, and the cross-agent usage aggregate reaching
    /// the single near-exhaustion rung ([`UsageAggregator::fleet_alert`]) fires
    /// the one usage alert. The dispatcher's per-event dedup/cooldown makes a
    /// sustained condition — a still-blocked head, a still-hot pool — announce at
    /// most once per window, even though `tick` surfaces it every cycle.
    fn dispatch(&mut self, report: &TickReport, now: i64) {
        for crash in &report.crashes {
            self.dispatcher.notify(crash, now);
        }
        for (_queue, part) in &report.parked {
            self.dispatcher
                .notify(&NotifyEvent::BlockedOnHuman { item: part.clone() }, now);
        }
        if self.aggregator.fleet_alert() {
            self.dispatcher.notify(&NotifyEvent::Usage, now);
        }
    }

    /// Retire `agent` from the supervisor on a boundary stop, killing any live
    /// child OUTSIDE any daemon lock (the [`crate::control::AgentChild`] contract).
    /// Records the retire and marks the agent permanently stopped for this run.
    fn retire(&mut self, agent: &str, report: &mut TickReport) {
        if let Some(child) = self.supervisor.retire(agent) {
            child.kill();
        }
        // Drop its budget reading so a departed agent can't pin the fleet aggregate.
        self.aggregator.forget(agent);
        self.stopped.insert(agent.to_string());
        report.retired.push(agent.to_string());
    }
}

/// Spawn the daemon-owned drive-loop thread: tick the loop every `interval` until
/// the daemon enters [`State::Stopping`], mirroring [`crate::bus::spawn_bus_tailer`].
/// The live thread reads the wall clock for `now`; the pure [`DriveLoop::tick`]
/// stays time-injected so it is unit-proven against fakes.
///
/// Construction of a *live* `DriveLoop` (a real [`ClaudeBackend`] behind both
/// [`AgentHealthSource`] and [`BudgetSampleSource`], the keeperd [`QueueSource`],
/// a [`RateSource`]) is assembled by the slices that own each source; this is the
/// thread shape that drives it.
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
    use crate::hub::EventHub;
    use crate::notifications::NotifyPolicy;
    use crate::notify_dispatch::{GuiNotifier, LogNotifier, LogSink};
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
        budgets: Mutex<BTreeMap<String, BudgetUsage>>,
    }
    impl FakeFleet {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn set_health(&self, agent: &str, h: AgentHealth) {
            self.health.lock().unwrap().insert(agent.to_string(), h);
        }
        /// Script `agent`'s latest reading of the shared pool (its budget cell).
        fn set_budget(&self, agent: &str, b: BudgetUsage) {
            self.budgets.lock().unwrap().insert(agent.to_string(), b);
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
    impl BudgetSampleSource for Arc<FakeFleet> {
        fn budget(&self, agent: &str) -> Option<BudgetUsage> {
            self.budgets.lock().unwrap().get(agent).copied()
        }
    }

    /// A recording [`LogSink`] — captures the audit lines the loop's owned
    /// dispatcher fanned out, so a test can assert "exactly one alert" without
    /// scraping stderr.
    #[derive(Debug, Default)]
    struct SpyLog {
        lines: Mutex<Vec<String>>,
    }
    impl SpyLog {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn lines(&self) -> Vec<String> {
            self.lines.lock().unwrap().clone()
        }
    }
    impl LogSink for Arc<SpyLog> {
        fn write_line(&self, line: &str) {
            self.lines.lock().unwrap().push(line.to_string());
        }
    }

    /// The dispatch side a test inspects after a tick: the GUI subscribe stream the
    /// loop's [`GuiNotifier`] fans alerts onto, and the audit-log spy. The fake
    /// backend publishes nothing to this hub, so every event on it is a dispatched
    /// alert.
    struct Probe {
        alerts: crate::hub::Subscription,
        log: Arc<SpyLog>,
    }
    impl Probe {
        /// Drain and count the alert bus-messages dispatched to the GUI hub.
        fn gui_alerts(&self) -> usize {
            let mut n = 0;
            while self.alerts.try_recv().is_ok() {
                n += 1;
            }
            n
        }
        fn log_lines(&self) -> Vec<String> {
            self.log.lines()
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

    fn hot_budget() -> BudgetUsage {
        BudgetUsage::new(90, 5) // over the 85 5h halt
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
    /// returning the loop plus the handles a test pokes (daemon control, the fake
    /// backend = health + budget source, and a [`Probe`] over the owned
    /// dispatcher's GUI hub + audit log). The supervisor uses a small,
    /// easy-to-assert backoff; the dispatcher's cooldown is huge so a sustained
    /// condition (a still-blocked head re-surfaced every tick) announces once.
    fn make(
        fleet: Vec<FleetMember>,
        snapshot: Vec<QueueView>,
        policy: Policy,
    ) -> (DriveLoop, Daemon, Arc<FakeFleet>, Probe) {
        let d = daemon();
        let backend = FakeFleet::new();
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
        let hub = EventHub::new();
        let alerts = hub.subscribe();
        let log = SpyLog::new();
        let mut dispatcher = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(1_000_000));
        dispatcher.register(Box::new(GuiNotifier::new(hub)));
        dispatcher.register(Box::new(LogNotifier::new(Arc::clone(&log))));
        let drive = DriveLoop::new(
            d.clone(),
            sup,
            Box::new(Arc::clone(&backend)),
            Box::new(Arc::clone(&queues)),
            Box::new(Arc::clone(&backend)),
            Box::new(PermissiveRate),
            dispatcher,
            fleet,
        );
        (drive, d, backend, Probe { alerts, log })
    }

    /// The loop picks each member's pinned part, admits under the per-device cap,
    /// and queues the over-cap start.
    #[test]
    fn schedules_and_starts_under_the_cap_queuing_the_rest() {
        let (mut loop_, _d, backend, _probe) = make(
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

    /// An exhausted shared budget refuses a start (not a slot wait): the fleet
    /// aggregate, fed from a1's hot reading of the shared pool, is over the rail.
    #[test]
    fn an_exhausted_budget_refuses_the_start() {
        let (mut loop_, _d, backend, _probe) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        backend.set_budget("a1", hot_budget());

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
        let (mut loop_, _d, backend, _probe) = make(
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
        let (mut loop_, d, backend, _probe) = make(
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
        let (mut loop_, _d, backend, _probe) = make(
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
        let (mut loop_, _d, backend, _probe) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        loop_.tick(0); // start a1
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        loop_.tick(0); // crash → backoff not_before 2

        backend.set_budget("a1", hot_budget());
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

    /// Admission gates on the cross-agent aggregate (spec §7): one agent that saw
    /// the shared pool deeper than the others pushes the per-field MAX over the 5h
    /// rail, so EVERY start is refused on budget — not just that agent's.
    #[test]
    fn admission_gates_on_the_cross_agent_aggregate() {
        let (mut loop_, _d, backend, _probe) = make(
            vec![member("a1", "qa"), member("a2", "qb"), member("a3", "qc")],
            vec![
                q("qa", &[("p1", "queued")]),
                q("qb", &[("p2", "queued")]),
                q("qc", &[("p3", "queued")]),
            ],
            Policy::default(),
        );
        // a1/a2 each read the pool under the 85 rail; a3 saw it at 88 (over).
        backend.set_budget("a1", BudgetUsage::new(50, 10));
        backend.set_budget("a2", BudgetUsage::new(70, 10));
        backend.set_budget("a3", BudgetUsage::new(88, 10));

        let r = loop_.tick(0);
        assert!(r.started.is_empty(), "the fleet aggregate (88) is over the rail");
        assert_eq!(r.held_starts.len(), 3, "every member's start is held");
        assert!(
            r.held_starts.iter().all(|h| matches!(
                h.outcome,
                StartOutcome::Refused {
                    reason: RefuseReason::Budget5h
                }
            )),
            "all refused on the shared 5h budget, not the cap",
        );
        assert_eq!(backend.spawn_count(), 0, "nothing spawns over the budget rail");
    }

    /// A retired agent's stale-hot reading is forgotten, so it stops pinning the
    /// admission aggregate for the remaining fleet (the loop's `forget` on retire,
    /// belt-and-suspenders with the per-tick refresh forgetting stopped agents).
    #[test]
    fn a_retired_hot_agent_no_longer_pins_the_admission_aggregate() {
        // cap 1: a1 runs first, a2 waits behind the cap.
        let policy = Policy {
            max_concurrent_agents: 1,
            ..Policy::default()
        };
        let (mut loop_, d, backend, _probe) = make(
            vec![member("a1", "qa"), member("a2", "qb")],
            vec![q("qa", &[("p1", "queued")]), q("qb", &[("p2", "queued")])],
            policy,
        );
        backend.set_budget("a1", BudgetUsage::new(20, 5)); // cool → a1 admitted
        backend.set_budget("a2", BudgetUsage::new(20, 5));

        // Tick 0: a1 starts (cap 1); a2 is queued behind the cap.
        assert_eq!(loop_.tick(0).started.len(), 1);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // a1 now reads the shared pool HOT (over the rail) — while it is in the
        // fleet its reading pins the aggregate. Then a1 is asked to stop and
        // reaches a clean boundary → it retires, freeing the slot AND leaving the
        // aggregate.
        backend.set_budget("a1", hot_budget());
        d.inner
            .lock()
            .unwrap()
            .control
            .request_stop("a1", StopLevel::AfterSlice);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        assert_eq!(loop_.tick(1).retired, vec!["a1".to_string()]);

        // Next tick: a1's hot reading is gone, the aggregate is a2's cool 20, the
        // slot is free → a2 starts. (Had a1's 90 lingered, a2 would be refused.)
        let r = loop_.tick(2);
        assert_eq!(
            r.started,
            vec![Assignment {
                agent: "a2".into(),
                queue: "qb".into(),
                part: "p2".into()
            }],
            "the retired hot agent no longer gates the remaining fleet",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a2"]);
    }

    /// The cross-agent aggregate crossing the single 97% rung fires exactly ONE
    /// usage alert through the loop's owned dispatcher (one GUI hub message + one
    /// audit line); sub-97 readings fire nothing and a later still-hot reading
    /// does not re-announce it (the §9 dedup holds across ticks).
    #[test]
    fn the_aggregate_crossing_97_alerts_exactly_once_via_the_owned_dispatcher() {
        let (mut loop_, _d, backend, probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        // Below the rung: the usage alert never fires.
        backend.set_budget("a1", BudgetUsage::new(80, 5));
        loop_.tick(0);
        backend.set_budget("a1", BudgetUsage::new(96, 5));
        loop_.tick(1);
        assert_eq!(probe.gui_alerts(), 0, "sub-97 never alerts");
        assert!(probe.log_lines().is_empty(), "no audit line under the rung");

        // Crossing 97 fires once; a later still-over-97 reading re-reaches the rung
        // but the dedup suppresses a repeat.
        backend.set_budget("a1", BudgetUsage::new(98, 5));
        loop_.tick(2);
        backend.set_budget("a1", BudgetUsage::new(99, 5));
        loop_.tick(3);
        assert_eq!(probe.gui_alerts(), 1, "exactly one GUI alert across the crossing");
        assert_eq!(
            probe.log_lines(),
            vec!["growlightd alert: 5h budget at 97%".to_string()],
            "exactly one audit line",
        );
    }

    /// Each surfaced crash and each parked (blocked-head) item routes through the
    /// loop's owned dispatcher as its own alert, and a re-surfaced blocked head is
    /// deduped — proving `tick` both RETURNS the report AND dispatches it.
    #[test]
    fn crashes_and_parked_heads_route_through_the_owned_dispatcher() {
        let (mut loop_, _d, backend, probe) = make(
            vec![member("a1", "mine")],
            vec![
                q("mine", &[("p1", "blocked"), ("p2", "queued")]),
                q("other", &[("o1", "queued")]),
            ],
            Policy::default(),
        );

        // Tick 0: a1 pivots off the blocked head onto `other`; the blocked head
        // `p1` is surfaced as parked → dispatched as one BlockedOnHuman alert.
        let r0 = loop_.tick(0);
        assert_eq!(r0.parked, vec![("mine".into(), "p1".into())]);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // a1 then crashes → an AgentCrashed alert is dispatched; the still-blocked
        // `p1` re-surfaces this tick but its alert is suppressed by the dedup.
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        let r1 = loop_.tick(1);
        assert_eq!(
            r1.crashes,
            vec![NotifyEvent::AgentCrashed { agent: "a1".into() }]
        );

        // Two distinct alerts fired across the two ticks (blocked p1 + crashed a1),
        // each exactly once.
        assert_eq!(probe.gui_alerts(), 2, "one blocked + one crash alert");
        let lines = probe.log_lines();
        assert_eq!(lines.len(), 2, "exactly two distinct audit lines");
        assert!(lines.iter().any(|l| l.contains("blocked on a human")));
        assert!(lines.iter().any(|l| l.contains("crashed")));
    }
}
