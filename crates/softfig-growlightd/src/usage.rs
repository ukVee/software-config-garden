//! Cross-agent **usage aggregation** (phase 6, slice 003) — fold every agent's
//! reading of the **one shared** account budget pool into a single fleet-wide
//! [`BudgetUsage`], and report whether that aggregate has reached the single
//! near-exhaustion alert rung (spec-growlight-orchestrator §7 shared-pool
//! budgets, §9 the one 97% event — refined 2026-06-23 from the old 85/90/95
//! ladder: one late warning is enough, three rungs were noise).
//!
//! ## What this is (and isn't)
//!
//! A **pure value model**, exactly the shape of this crate's
//! [`AdmissionGovernor`](crate::admission) / [`NotifyPolicy`](crate::notifications)
//! / [`Supervisor`](crate::supervisor) and keeperd's `ThrashDetector`: all inputs
//! injected, no clock, no I/O, no socket. It answers two questions —
//!
//! 1. *Given each agent's latest reading of the shared pool, what is the one
//!    fleet-wide reserve right now?* ([`UsageAggregator::aggregate_at`])
//! 2. *Has that aggregate reached the [`USAGE_ALERT_PCT`] rung?*
//!    ([`UsageAggregator::fleet_alert_at`])
//!
//! — and nothing else. The **live source** — populating per-agent samples from
//! the keeperd budget handshake (`BudgetChanged { agent: Some(id), .. }`) and the
//! single [`NotifyDispatcher`](crate::notify_dispatch) the alerts fan out to — is
//! the **phase-6 drive loop's** job, deferred behind this pure core just like the
//! [`AgentBackend`](crate::supervisor::AgentBackend) /
//! [`BusEmit`](crate::notify_dispatch::BusEmit) seams. The drive loop passes the
//! tick's `now` (unix seconds) into every read; the module keeps no clock of its
//! own.
//!
//! ## Why this aggregate exists (spec §7)
//!
//! The 5h/7d budget is **one shared account-wide pool**, so N agents burn it N×.
//! The per-agent *halt* of the single-agent loop ([[spec-growlight]] §6) becomes
//! global *admission*: the governor must gate on the **fleet's** burn, not one
//! agent's. But each agent only ever sees its own last reading of that shared
//! meter (taken at its own cadence), so growlightd has to fold those readings
//! back into the single number the meter actually represents. That fold is this
//! module; its output feeds **both** the governor (admission on real fleet burn)
//! and the dispatcher (the one 97% near-exhaustion alert).
//!
//! ## Why **max**, not sum or mean
//!
//! The reserve is a *percentage of one shared pool*, so it is never summed —
//! three agents each seeing 30% is a 30% pool, not 90%. Within a window the
//! shared meter only **rises**, so each agent's last reading is a *lower bound*
//! on the true current burn (it can only have gone up since they read it). The
//! per-field **maximum** across the fleet is therefore the tightest reading the
//! fleet can vouch for and the safe input to an admission gate: never admit on
//! one agent's stale-low reading while another already saw the pool deeper.
//! Over-counting (refusing a touch early) is benign and self-corrects on the next
//! sample; under-counting (admitting a dead pool) is the dangerous error, and max
//! never makes it.
//!
//! ## Why a **window-staleness** bound (task 046)
//!
//! Max makes over-counting safe only *within a live window*. A reading outlives
//! its window: the 5h reserve a departed-or-**wedged** agent read is meaningless
//! once 5 hours have passed, because that window has demonstrably reset (a live
//! agent in a fresh window would report a *decayed* value). The drive loop already
//! [`forget`](UsageAggregator::forget)s a **non-running** agent's sample, so a
//! crashed peer can't pin the fold — but a peer that is still `is_running` yet has
//! gone silent (wedged) keeps re-reporting its last near-full reading every tick,
//! and nothing drops it. Left unbounded, that stale ≥97% sample pins the aggregate
//! over the 5h rail and admission refuses every spawn *after the pool has actually
//! reset* — the phantom halt of `incident-20260716-growlightd-crash-budget-pin-stall`.
//!
//! The cure is structural, not another forget arm: a reading is only valid for the
//! length of its window. [`aggregate_at`](UsageAggregator::aggregate_at) drops a
//! sample's 5h field once it is `>= FIVE_H_WINDOW_SECS` old and its 7d field once
//! it is `>= SEVEN_D_WINDOW_SECS` old (each window independently), and
//! [`observe`](UsageAggregator::observe) preserves a reading's age across an
//! **unchanged** re-report so a wedged peer's frozen sample actually ages out
//! instead of being perpetually refreshed. The max-fold under-count safety is
//! untouched *inside* a live window; only a demonstrably-reset reading is dropped.
//!
//! ## Why the bound must also honor **`resets_at`** (task 048)
//!
//! Age alone can only catch a reading that has outlived its *own window length*,
//! and that is structurally too weak: the windows are **anchored**, not rolling
//! from the moment of the read. A 7d reading taken 5d17h ago is younger than its
//! 7-day window and so survives the age bound — yet its own `resets_at` may have
//! passed five days earlier, meaning the window it describes reset long before the
//! reading was even that old. That is exactly the fossil that held admission in
//! [[incident-20260720-m5f-double-park]]: a 7d field of 86% gating the fleet on a
//! window that had been fresh for five days.
//!
//! So a reading carries the boundary it was read against ([`WindowResets`], the
//! wire's `rate_limit_event` `resetsAt`, present on every status — not just a
//! `rejected` one), and [`aggregate_at`](UsageAggregator::aggregate_at) drops a
//! window's field once `resets_at <= now`, **independently per window and
//! alongside** the age bound — either one voids the field. A window whose boundary
//! is unknown (a `result`-line reserve, a seam with no rate-limit signal) keeps the
//! age bound alone, exactly as before. Under-count safety inside a live window is
//! again untouched: a boundary that has not yet passed is a window that has not
//! reset, and the max-fold still gates on it.

use std::collections::BTreeMap;

use crate::admission::BudgetUsage;

/// The single 5h near-exhaustion alert rung (spec §9, refined 2026-06-23). One
/// late warning at 97% replaces the old 85/90/95 ladder — the sole threshold
/// [`usage_alert_reached`] tests the fleet aggregate against, and the percentage
/// the [`NotifyEvent::Usage`](crate::notifications::NotifyEvent::Usage) summary
/// renders.
pub const USAGE_ALERT_PCT: u8 = 97;

/// The 5h budget window (spec §7), in seconds — the staleness bound for a sample's
/// `session_5h_pct`. A reading at least this old has outlived its 5h window (which
/// has therefore reset at least once), so its 5h field stops contributing to the
/// fold. See the module docs, "Why a window-staleness bound".
pub const FIVE_H_WINDOW_SECS: i64 = 5 * 60 * 60;

/// The 7d budget window (spec §7), in seconds — the staleness bound for a sample's
/// `session_7d_pct`, applied independently of the 5h bound (a reading can be stale
/// on 5h while its 7d field is still live).
pub const SEVEN_D_WINDOW_SECS: i64 = 7 * 24 * 60 * 60;

/// The **boundary** each budget window carried in one reading: the unix-seconds
/// instant that window next resets (the wire's `rate_limit_event`
/// `rate_limit_info.resetsAt`, which every status carries — `allowed` and
/// `warning` as well as `rejected`).
///
/// This is what makes a reading falsifiable independently of its age. The windows
/// are anchored to account time, not to when an agent happened to read them, so a
/// reading younger than its window length can still describe a window that has
/// demonstrably reset — see the module docs, "Why the bound must also honor
/// `resets_at`". `None` means the reading never carried that window's boundary
/// (a `result`-line reserve, or a backend with no rate-limit signal at all); such
/// a window falls back to the age bound alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowResets {
    /// When the 5h window this reading describes next resets, if known.
    pub five_h: Option<i64>,
    /// When the 7d window this reading describes next resets, if known.
    pub seven_d: Option<i64>,
}

impl WindowResets {
    /// A reading that carried no boundary for either window — the age bound alone
    /// applies (the pre-048 behaviour).
    pub const UNKNOWN: Self = Self {
        five_h: None,
        seven_d: None,
    };

    /// Both boundaries at once.
    pub fn new(five_h: Option<i64>, seven_d: Option<i64>) -> Self {
        Self { five_h, seven_d }
    }

    /// Whether a known boundary has already passed at `now` — i.e. the window this
    /// reading describes has demonstrably reset since it was read, so the reading's
    /// field for that window is void regardless of how young the reading is. An
    /// unknown boundary is never "passed" (it defers to the age bound).
    fn passed(boundary: Option<i64>, now: i64) -> bool {
        boundary.is_some_and(|at| at <= now)
    }
}

/// One agent's most-recent reading of the **shared account-wide** budget pool, and
/// **when** it was read.
///
/// The percentages are NOT this agent's private context window — they are the
/// account-wide 5h/7d reserve this agent read from the keeperd budget handshake
/// (`BudgetChanged { agent: Some(id), .. }`). Every agent reads the *same* meter;
/// a sample only records what one agent last saw of it, so the aggregator can
/// fold the readings back into the single number the meter represents.
///
/// `read_at` (unix seconds, the drive loop's tick clock) is the reading's age
/// anchor for the window-staleness bound: a reading does not get younger, so an
/// unchanged re-report keeps its original `read_at` (see
/// [`UsageAggregator::observe`]) and a wedged agent's frozen sample ages out of its
/// window rather than pinning the fold forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageSample {
    /// The reporting agent's bus id (the `@`-stripped work-stream name).
    pub agent: String,
    /// The account-wide reserve this agent last read.
    pub budget: BudgetUsage,
    /// Unix-seconds instant this reading was taken (the drive loop stamps the
    /// tick's `now`). Anchors the window-staleness bound.
    pub read_at: i64,
    /// The window boundaries this reading was taken against (task 048). A window
    /// whose `resets_at` has passed is void no matter how young the reading is —
    /// the age bound cannot see that, because the windows are anchored rather than
    /// rolling from the read. Unknown boundaries fall back to the age bound.
    pub resets_at: WindowResets,
}

impl UsageSample {
    /// Construct a sample of the shared pool as `agent` read it at `read_at`
    /// (unix seconds), carrying no window boundaries — the age bound alone applies.
    /// Add them with [`with_resets`](Self::with_resets) when the reading knows them.
    pub fn new(agent: impl Into<String>, budget: BudgetUsage, read_at: i64) -> Self {
        Self {
            agent: agent.into(),
            budget,
            read_at,
            resets_at: WindowResets::UNKNOWN,
        }
    }

    /// The same reading, carrying the window boundaries it was read against.
    pub fn with_resets(mut self, resets_at: WindowResets) -> Self {
        self.resets_at = resets_at;
        self
    }
}

/// Whether the shared pool's **5h** reserve has reached the single
/// [`USAGE_ALERT_PCT`] near-exhaustion rung — a pure threshold test
/// (`>= 97`, inclusive). The 7d reserve never trips this 5h rung.
///
/// When true, fire one [`NotifyEvent::Usage`](crate::notifications::NotifyEvent::Usage)
/// at the [`NotifyDispatcher`](crate::notify_dispatch); its dedup
/// ([`NotifyPolicy`](crate::notifications), keyed `usage`) makes that alert fire
/// **exactly once** across the rising budget, so this stays a *stateless fact* —
/// the "fired once" state belongs to the engine, not duplicated here (the
/// pure-module discipline: consume the existing seam). The rung is 5h-scoped,
/// matching the event's "5h budget at 97%" summary.
pub fn usage_alert_reached(budget: BudgetUsage) -> bool {
    budget.session_5h_pct >= USAGE_ALERT_PCT
}

/// The cross-agent usage aggregator: holds each agent's latest reading of the
/// shared pool and folds them into one fleet-wide [`BudgetUsage`]. Pure — no
/// clock, no I/O; the drive loop feeds it from the live `BudgetChanged{agent}`
/// stream and reads [`aggregate_or_fresh_at`](Self::aggregate_or_fresh_at) /
/// [`fleet_alert_at`](Self::fleet_alert_at) — passing the tick's `now` — at each
/// admission/notify boundary.
#[derive(Debug, Default)]
pub struct UsageAggregator {
    /// The latest reading per agent (last-write-wins, age-preserving on an
    /// unchanged re-report). Keyed for a deterministic fold and stable iteration.
    latest: BTreeMap<String, UsageSample>,
}

impl UsageAggregator {
    /// An aggregator with no samples yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `sample` as the reporting agent's latest reading of the shared pool.
    ///
    /// **Last-write-wins** on the *value*: a falling reading (a window reset the
    /// agent observed) lowers that agent's contribution immediately. But a reading
    /// does not get **younger** — if the incoming reading equals the stored one
    /// (a wedged agent re-emitting its last sample every tick), the stored
    /// `read_at` is retained so the sample keeps aging toward its window bound.
    /// Only a *changed* reading — a genuine fresh read, since a window reset shows
    /// as a decayed value or a new boundary — resets the age. "Unchanged" means the
    /// **whole** reading: the percentages *and* the window boundaries it was read
    /// against, so a re-report that carries a fresh [`WindowResets`] counts as the
    /// new read it is. This is the age-preserving half of the window-staleness
    /// bound; [`aggregate_at`](Self::aggregate_at) is the expiry half.
    pub fn observe(&mut self, mut sample: UsageSample) {
        if let Some(prev) = self.latest.get(&sample.agent) {
            if prev.budget == sample.budget && prev.resets_at == sample.resets_at {
                sample.read_at = prev.read_at;
            }
        }
        self.latest.insert(sample.agent.clone(), sample);
    }

    /// Drop a departed agent's sample, so a dead agent's stale reading can never
    /// pin the fleet aggregate (the drive loop calls this when an agent leaves
    /// the fleet). Returns whether a sample was actually removed. Complementary to
    /// the window-staleness bound: `forget` drops a **non-running** agent's sample
    /// at once, the staleness bound covers a still-`is_running`-but-wedged one.
    pub fn forget(&mut self, agent: &str) -> bool {
        self.latest.remove(agent).is_some()
    }

    /// How many agents are currently contributing a sample (stale or not — the
    /// staleness bound applies at fold time, not on membership).
    pub fn agent_count(&self) -> usize {
        self.latest.len()
    }

    /// The fleet-wide reserve as of `now` (unix seconds): the per-field **maximum**
    /// across every agent's latest reading of the shared pool, **excluding a field
    /// whose window has demonstrably reset** since the reading was taken. A window
    /// is void either because the reading has outlived it (5h reading
    /// `>= FIVE_H_WINDOW_SECS` old, 7d reading `>= SEVEN_D_WINDOW_SECS` old) **or**
    /// because the boundary the reading carried has passed (`resets_at <= now`,
    /// task 048) — the two bounds are independent, and each window is judged on its
    /// own. `None` when no agent has reported at all; `Some((0, 0))` when every
    /// contributing reading is void (an effectively fresh pool). See the module docs
    /// for why max within a live window and why these bounds are what void one.
    pub fn aggregate_at(&self, now: i64) -> Option<BudgetUsage> {
        if self.latest.is_empty() {
            return None;
        }
        let mut five_h = 0u8;
        let mut seven_d = 0u8;
        for s in self.latest.values() {
            let age = now.saturating_sub(s.read_at);
            if age < FIVE_H_WINDOW_SECS && !WindowResets::passed(s.resets_at.five_h, now) {
                five_h = five_h.max(s.budget.session_5h_pct);
            }
            if age < SEVEN_D_WINDOW_SECS && !WindowResets::passed(s.resets_at.seven_d, now) {
                seven_d = seven_d.max(s.budget.session_7d_pct);
            }
        }
        Some(BudgetUsage::new(five_h, seven_d))
    }

    /// The fleet-wide reserve as of `now`, defaulting to a fresh `(0, 0)` pool when
    /// no agent has reported — the form the [`AdmissionGovernor`](crate::admission)
    /// reads directly (an empty fleet, or one whose readings have all aged out, has
    /// no vouchable burn).
    pub fn aggregate_or_fresh_at(&self, now: i64) -> BudgetUsage {
        self.aggregate_at(now).unwrap_or(BudgetUsage::new(0, 0))
    }

    /// Whether the **current fleet aggregate** (as of `now`) has reached the single
    /// near-exhaustion rung — [`usage_alert_reached`] over
    /// [`aggregate_or_fresh_at`](Self::aggregate_or_fresh_at). A stale reading that
    /// has aged out cannot trip it. When true, the drive loop fires one
    /// [`NotifyEvent::Usage`](crate::notifications::NotifyEvent::Usage) at its single
    /// [`NotifyDispatcher`](crate::notify_dispatch), whose dedup makes it announce
    /// exactly once.
    pub fn fleet_alert_at(&self, now: i64) -> bool {
        usage_alert_reached(self.aggregate_or_fresh_at(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{
        AdmissionDecision, AdmissionGovernor, Intent, RateState, RefuseReason,
    };
    use crate::config::Policy;
    use crate::notifications::{NotifyEvent, NotifyPolicy};
    use crate::notify_dispatch::NotifyDispatcher;

    /// A sample read at `t = 0`; the fold `now` in these tests stays well inside a
    /// window unless a test is exercising the staleness bound, so `read_at = 0`
    /// keeps every reading live by default.
    fn sample(agent: &str, five_h: u8, seven_d: u8) -> UsageSample {
        UsageSample::new(agent, BudgetUsage::new(five_h, seven_d), 0)
    }

    /// A rate reading with generous per-minute headroom (so the governor tests
    /// isolate the budget gate).
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

    /// An empty fleet has no aggregate; `_or_fresh` reads a clean (0,0) pool.
    #[test]
    fn an_empty_fleet_aggregates_to_nothing() {
        let agg = UsageAggregator::new();
        assert_eq!(agg.aggregate_at(0), None);
        assert_eq!(agg.aggregate_or_fresh_at(0), BudgetUsage::new(0, 0));
        assert_eq!(agg.agent_count(), 0);
        assert!(!agg.fleet_alert_at(0), "an empty fleet has not reached the rung");
    }

    /// The fold is the per-field MAX across agents — the freshest-vouchable view
    /// of the one shared pool — and a percentage pool is never summed.
    #[test]
    fn aggregate_is_the_per_field_max_across_agents() {
        let mut agg = UsageAggregator::new();
        // Three agents burning the SAME shared pool, each with its own last
        // reading (5h, 7d).
        agg.observe(sample("a1", 60, 10));
        agg.observe(sample("a2", 72, 20));
        agg.observe(sample("a3", 75, 15));
        assert_eq!(agg.agent_count(), 3);
        // Aggregate = max per field (5h=75, 7d=20) — the shared total, NOT the
        // sum (60+72+75 would be a nonsensical 207% pool).
        assert_eq!(agg.aggregate_at(0), Some(BudgetUsage::new(75, 20)));
    }

    /// A reading is per-agent last-write-wins: a fresh lower sample (a window
    /// reset that agent observed) lowers that agent's contribution at once.
    #[test]
    fn observe_is_last_write_wins_per_agent() {
        let mut agg = UsageAggregator::new();
        agg.observe(sample("a1", 80, 30));
        agg.observe(sample("a2", 50, 10));
        assert_eq!(agg.aggregate_at(0), Some(BudgetUsage::new(80, 30)));
        // a1's window reset — its next reading is low. Last-write-wins, so a1 no
        // longer dominates; the aggregate falls to a2's reading.
        agg.observe(sample("a1", 20, 5));
        assert_eq!(agg.agent_count(), 2, "still two agents, a1 was replaced");
        assert_eq!(agg.aggregate_at(0), Some(BudgetUsage::new(50, 10)));
    }

    /// Forgetting a departed agent drops its (possibly stale-high) reading so it
    /// can never pin the aggregate after it leaves the fleet.
    #[test]
    fn forget_drops_a_departed_agents_stale_reading() {
        let mut agg = UsageAggregator::new();
        agg.observe(sample("hot", 92, 40));
        agg.observe(sample("cool", 30, 10));
        assert_eq!(agg.aggregate_at(0), Some(BudgetUsage::new(92, 40)));

        assert!(agg.forget("hot"), "a present sample is removed");
        assert!(!agg.forget("hot"), "forget is idempotent / reports a no-op");
        // The stale-high reading is gone — the aggregate reflects the survivor.
        assert_eq!(agg.aggregate_at(0), Some(BudgetUsage::new(30, 10)));
        assert_eq!(agg.agent_count(), 1);
    }

    /// TASK 046 (the phantom-halt cure): a ≥97% reading from a wedged/departed
    /// agent must stop pinning admission once its **5h window** has elapsed — the
    /// window-staleness bound. Within a live window the max-fold still gates (the
    /// under-count safety is preserved); only a reading older than its window
    /// (which has demonstrably reset) is dropped. Pure: the elapsed time is the
    /// injected `now`, no clock I/O.
    #[test]
    fn a_stale_reading_stops_pinning_admission_after_its_5h_window_elapses() {
        let g = AdmissionGovernor::new(Policy::default()); // 5h halt 85
        let mut agg = UsageAggregator::new();
        let t0 = 1_000;
        // One agent read the shared pool at 97% (over the 5h rail) + 7d 20% at t0.
        agg.observe(UsageSample::new("wedged", BudgetUsage::new(97, 20), t0));

        // WITHIN the 5h window the reading still gates — the under-count safety holds.
        let within = t0 + FIVE_H_WINDOW_SECS - 1;
        assert_eq!(
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh_at(within), fresh_rate()),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget5h
            },
            "a still-fresh 97% reading refuses admission (max-fold safety intact)",
        );

        // A wedged agent re-emits its LAST sample every tick — that must not reset
        // the reading's age (the age-preserving `observe`).
        agg.observe(UsageSample::new("wedged", BudgetUsage::new(97, 20), within));

        // Once the 5h window has elapsed the reading is void — the 5h field drops
        // from the fold and admission reopens (no spawn can ever lower it otherwise).
        let after = t0 + FIVE_H_WINDOW_SECS;
        assert!(
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh_at(after), fresh_rate())
                .is_admit(),
            "the stale 97% reading no longer pins the 5h admission gate",
        );
        assert!(!agg.fleet_alert_at(after), "a stale reading cannot trip the §9 alert");
        // The 7d field (a 7-day window) is NOT yet stale, so it still contributes.
        assert_eq!(agg.aggregate_at(after), Some(BudgetUsage::new(0, 20)));
    }

    /// The 5h and 7d staleness bounds are independent: a reading can age out of its
    /// 5h window while its 7d field is still live, and only the 7d field survives to
    /// the 7d bound.
    #[test]
    fn the_5h_and_7d_staleness_bounds_are_independent() {
        let mut agg = UsageAggregator::new();
        agg.observe(UsageSample::new("a", BudgetUsage::new(90, 88), 0));
        // Just inside both windows: both fields contribute.
        assert_eq!(
            agg.aggregate_at(FIVE_H_WINDOW_SECS - 1),
            Some(BudgetUsage::new(90, 88))
        );
        // Past the 5h bound, inside the 7d bound: only 7d survives.
        assert_eq!(
            agg.aggregate_at(FIVE_H_WINDOW_SECS),
            Some(BudgetUsage::new(0, 88))
        );
        // Past the 7d bound too: nothing contributes → a fresh (0,0) pool.
        assert_eq!(
            agg.aggregate_at(SEVEN_D_WINDOW_SECS),
            Some(BudgetUsage::new(0, 0))
        );
    }

    /// TASK 048 (the m5f double-park fossil): a reading whose window boundary has
    /// PASSED is void even though the reading is far younger than that window — the
    /// exact case the 046 age bound structurally cannot catch. Reproduces the
    /// incident's numbers: a 7d field of 86% read 5d17h ago, whose own `resets_at`
    /// fell five days before the fold.
    #[test]
    fn a_reading_past_its_resets_at_is_void_even_though_it_is_younger_than_its_window() {
        let g = AdmissionGovernor::new(Policy::default());
        let mut agg = UsageAggregator::new();
        let read_at = 1_000_000;
        // The 7d window this reading describes reset a day after it was taken...
        let boundary = read_at + 24 * 60 * 60;
        // ...and the fold happens 5d17h after the read — well inside the 7-day age
        // bound, so age alone keeps the field alive.
        let now = read_at + 5 * 24 * 60 * 60 + 17 * 60 * 60;
        assert!(
            now - read_at < SEVEN_D_WINDOW_SECS,
            "the reading is younger than its own window — age can never void it",
        );

        // Without the boundary the age bound is all there is, and the fossil folds.
        agg.observe(UsageSample::new("fossil", BudgetUsage::new(0, 86), read_at));
        assert_eq!(
            agg.aggregate_at(now),
            Some(BudgetUsage::new(0, 86)),
            "age alone cannot see that the window already reset",
        );

        // Carrying the boundary it was read against, the same reading is void.
        agg.observe(
            UsageSample::new("fossil", BudgetUsage::new(0, 86), read_at)
                .with_resets(WindowResets::new(None, Some(boundary))),
        );
        assert_eq!(
            agg.aggregate_at(now),
            Some(BudgetUsage::new(0, 0)),
            "a passed resets_at voids the 7d field regardless of the reading's age",
        );
        assert!(
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh_at(now), fresh_rate())
                .is_admit(),
            "admission reopens — the m5f phantom hold does not recur",
        );
    }

    /// The `resets_at` bound is per-window and complements (never replaces) the age
    /// bound: a FUTURE boundary still folds, an unknown boundary defers to age, and
    /// a passed boundary voids only its own window.
    #[test]
    fn the_resets_at_bound_is_per_window_and_complements_the_age_bound() {
        let mut agg = UsageAggregator::new();
        let t0 = 1_000;
        let now = t0 + 60;
        // 5h boundary already passed, 7d boundary still ahead.
        agg.observe(
            UsageSample::new("a", BudgetUsage::new(97, 44), t0)
                .with_resets(WindowResets::new(Some(now), Some(now + 1))),
        );
        assert_eq!(
            agg.aggregate_at(now),
            Some(BudgetUsage::new(0, 44)),
            "a boundary AT `now` has passed (inclusive); the future 7d one still folds",
        );
        // Both boundaries ahead: a young reading folds in full, exactly as before 048.
        agg.observe(
            UsageSample::new("a", BudgetUsage::new(97, 44), t0)
                .with_resets(WindowResets::new(Some(now + 1), Some(now + 1))),
        );
        assert_eq!(
            agg.aggregate_at(now),
            Some(BudgetUsage::new(97, 44)),
            "a live window is untouched — the max-fold under-count safety holds",
        );
        // Unknown boundaries: the age bound alone, so the same reading still folds
        // now and still ages out at its 5h window.
        agg.observe(UsageSample::new("a", BudgetUsage::new(97, 44), t0));
        assert_eq!(agg.aggregate_at(now), Some(BudgetUsage::new(97, 44)));
        assert_eq!(
            agg.aggregate_at(t0 + FIVE_H_WINDOW_SECS),
            Some(BudgetUsage::new(0, 44)),
            "with no boundary the pre-048 age bound is unchanged",
        );
    }

    /// A re-report carrying a NEW boundary is a genuine fresh read, so it resets the
    /// reading's age even when the percentages happen to be identical — the case a
    /// budget-only comparison would freeze forever (a window can reset to the same
    /// low number every time).
    #[test]
    fn a_changed_boundary_counts_as_a_fresh_read_even_when_the_percentages_match() {
        let mut agg = UsageAggregator::new();
        let hour = 3_600;
        let first = WindowResets::new(Some(hour), None);
        agg.observe(UsageSample::new("a", BudgetUsage::new(40, 10), 0).with_resets(first));
        // Same percentages AND the same boundary re-reported an hour later: a frozen
        // wedged sample, so the age is preserved (read at 0, not at `hour`)...
        agg.observe(UsageSample::new("a", BudgetUsage::new(40, 10), hour).with_resets(first));
        // ...and at the boundary the 5h field is void on the resets_at bound alone —
        // the reading is only an hour old, nowhere near its age bound.
        assert_eq!(
            agg.aggregate_at(hour),
            Some(BudgetUsage::new(0, 10)),
            "the frozen sample's 5h field is void at its own passed boundary",
        );
        // The next window opens: same percentages, NEW boundary — a fresh read, so
        // the field is live again AND its age restarts from the new stamp (proved by
        // folding at an instant the ORIGINAL stamp would have aged out of).
        let second = WindowResets::new(Some(hour + FIVE_H_WINDOW_SECS), None);
        agg.observe(UsageSample::new("a", BudgetUsage::new(40, 10), hour).with_resets(second));
        assert_eq!(
            agg.aggregate_at(hour + FIVE_H_WINDOW_SECS - 1),
            Some(BudgetUsage::new(40, 10)),
            "a new boundary is a new read: the field folds again from its own stamp",
        );
    }

    /// `observe` preserves a reading's age across an UNCHANGED re-report (so a
    /// wedged sample ages out), but a CHANGED reading is a genuine fresh read whose
    /// age restarts from the new stamp.
    #[test]
    fn observe_freezes_age_on_an_unchanged_reading_but_resets_it_on_a_change() {
        let mut agg = UsageAggregator::new();
        agg.observe(UsageSample::new("a", BudgetUsage::new(97, 10), 100));
        // Same reading re-reported much later — age is still measured from 100.
        agg.observe(UsageSample::new("a", BudgetUsage::new(97, 10), 100_000));
        assert_eq!(
            agg.aggregate_at(100 + FIVE_H_WINDOW_SECS),
            Some(BudgetUsage::new(0, 10)),
            "the 5h field aged out from the ORIGINAL read time, not the re-report",
        );
        // A CHANGED reading is a fresh read — its age restarts from the new stamp.
        agg.observe(UsageSample::new("a", BudgetUsage::new(96, 10), 100_000));
        assert_eq!(
            agg.aggregate_at(100_000 + FIVE_H_WINDOW_SECS - 1),
            Some(BudgetUsage::new(96, 10)),
            "a changed reading contributes fresh from its own stamp",
        );
    }

    /// `usage_alert_reached` is a pure threshold test on the 5h reserve at the
    /// single 97% rung (>= is inclusive; 7d never trips it).
    #[test]
    fn usage_alert_reached_at_97_inclusive() {
        let hit = |five_h| usage_alert_reached(BudgetUsage::new(five_h, 0));
        assert!(!hit(85), "the old first rung no longer alerts");
        assert!(!hit(95), "the old top rung no longer alerts on its own");
        assert!(!hit(96), "just under the rung");
        assert!(hit(97), "at the rung (inclusive)");
        assert!(hit(100), "saturated");
        // The 7d reserve never trips the 5h rung.
        assert!(!usage_alert_reached(BudgetUsage::new(10, 99)));
    }

    /// The fleet aggregate crossing the single 97% rung fires **exactly one**
    /// alert via the dispatcher's dedup — sub-97 readings fire nothing, and a
    /// later still-over-97 sample never re-announces it.
    #[test]
    fn the_fleet_alert_fires_once_when_the_pool_crosses_97() {
        let mut agg = UsageAggregator::new();
        // A long cooldown so a repeat is always suppressed within the run.
        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(1_000_000));
        let now = 1_000;

        let mut fires = 0;
        // The shared pool burns up over successive samples; only the one that
        // crosses 97 fires, and only once (one agent suffices — the aggregate is
        // the shared meter).
        for five_h in [80u8, 90, 96, 98, 99] {
            agg.observe(UsageSample::new("a1", BudgetUsage::new(five_h, 5), now));
            if agg.fleet_alert_at(now)
                && !d.notify(&NotifyEvent::Usage { pct: five_h }, now).is_empty()
            {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "exactly one alert across the whole rising burn");
    }

    /// A jump straight past the rung announces it once, then stays quiet.
    #[test]
    fn a_jump_past_the_rung_fires_once_then_stays_quiet() {
        let mut agg = UsageAggregator::new();
        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(1_000_000));
        agg.observe(UsageSample::new("a1", BudgetUsage::new(98, 5), 0)); // 0 → 98 in one reading

        assert!(agg.fleet_alert_at(0));
        assert!(
            !d.notify(&NotifyEvent::Usage { pct: 98 }, 0).is_empty(),
            "the reached rung fires once"
        );
        // A later sample still over 97 re-reaches the rung but does not re-fire.
        agg.observe(UsageSample::new("a1", BudgetUsage::new(99, 5), 1));
        assert!(agg.fleet_alert_at(1));
        assert!(
            d.notify(&NotifyEvent::Usage { pct: 99 }, 1).is_empty(),
            "the already-announced rung stays quiet"
        );
    }

    /// The governor reads the fleet aggregate and refuses admission once the
    /// shared 5h pool breaches the reserve — an agent under the rail alone
    /// doesn't, but the fleet's combined burn does.
    #[test]
    fn the_governor_refuses_once_the_aggregate_breaches_5h() {
        let g = AdmissionGovernor::new(Policy::default()); // 5h halt 85
        let mut agg = UsageAggregator::new();
        agg.observe(sample("a1", 50, 10));
        agg.observe(sample("a2", 70, 10));
        // Aggregate 5h = 70 < 85 → admit.
        assert!(g
            .decide(Intent::Start, 0, agg.aggregate_or_fresh_at(0), fresh_rate())
            .is_admit());
        // A third agent sees the shared pool deeper (88%) → the fleet aggregate
        // breaches the rail → refuse.
        agg.observe(sample("a3", 88, 10));
        assert_eq!(
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh_at(0), fresh_rate()),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget5h
            }
        );
    }

    /// The 7d field aggregates and gates independently of 5h.
    #[test]
    fn the_governor_refuses_once_the_aggregate_breaches_7d() {
        let g = AdmissionGovernor::new(Policy::default()); // 7d halt 90
        let mut agg = UsageAggregator::new();
        agg.observe(sample("a1", 10, 80));
        agg.observe(sample("a2", 10, 91)); // 7d over the rail, 5h fine
        assert_eq!(
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh_at(0), fresh_rate()),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget7d
            }
        );
    }

    /// TASK 037 (finish-criterion 4, co-member half): once a parked rate-limited
    /// member's reading is FORGOTTEN it must stop pinning the aggregate — else its
    /// stale near-full sample would keep refusing a co-member the shared window has
    /// room for. While the parked member still contributes, the per-field MAX gates
    /// admission; the forget (the drive loop's `ParkedRateLimited` arm, symmetric
    /// with task 031's boundary forgets) drops it so admission reads the co-member's
    /// fresh reading and re-admits. The ONE structural rule, not two patches.
    #[test]
    fn a_forgotten_parked_reading_stops_pinning_a_co_member() {
        let g = AdmissionGovernor::new(Policy::default()); // 5h halt 85
        let mut agg = UsageAggregator::new();
        // a1 tripped the 5h window (98%, over the rail); a2 is fresh. While a1's
        // parked sample lingers, the per-field MAX refuses a2's start.
        agg.observe(sample("a1", 98, 5));
        agg.observe(sample("a2", 20, 5));
        assert_eq!(
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh_at(0), fresh_rate()),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget5h
            },
            "a1's hot parked reading pins the aggregate over the 5h rail",
        );
        // a1 parks rate-limited → its reading is forgotten. The aggregate falls to
        // a2's fresh reading → the co-member is admitted (no pin, no restart).
        agg.forget("a1");
        assert!(
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh_at(0), fresh_rate())
                .is_admit(),
            "the forgotten parked reading no longer blocks the co-member",
        );
    }
}
