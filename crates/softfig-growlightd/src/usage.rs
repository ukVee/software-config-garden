//! Cross-agent **usage aggregation** (phase 6, slice 003) — fold every agent's
//! reading of the **one shared** account budget pool into a single fleet-wide
//! [`BudgetUsage`], and report which [`UsageLevel`] rungs that aggregate meets
//! (spec-growlight-orchestrator §7 shared-pool budgets, §9 the 85/90/95 events).
//!
//! ## What this is (and isn't)
//!
//! A **pure value model**, exactly the shape of this crate's
//! [`AdmissionGovernor`](crate::admission) / [`NotifyPolicy`](crate::notifications)
//! / [`Supervisor`](crate::supervisor) and keeperd's `ThrashDetector`: all inputs
//! injected, no clock, no I/O, no socket. It answers two questions —
//!
//! 1. *Given each agent's latest reading of the shared pool, what is the one
//!    fleet-wide reserve right now?* ([`UsageAggregator::aggregate`])
//! 2. *Which 85/90/95 rungs does that aggregate meet?* ([`levels_reached`])
//!
//! — and nothing else. The **live source** — populating per-agent samples from
//! the keeperd budget handshake (`BudgetChanged { agent: Some(id), .. }`) and the
//! single [`NotifyDispatcher`](crate::notify_dispatch) the alerts fan out to — is
//! the **phase-6 drive loop's** job, deferred behind this pure core just like the
//! [`AgentBackend`](crate::supervisor::AgentBackend) /
//! [`BusEmit`](crate::notify_dispatch::BusEmit) seams.
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
//! and the dispatcher (the 85/90/95 alerts).
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
//! never makes it. A departed agent's stale reading is dropped with
//! [`forget`](UsageAggregator::forget) so it can never pin the aggregate after a
//! window reset.

use std::collections::BTreeMap;

use crate::admission::BudgetUsage;
use crate::notifications::UsageLevel;

/// The defined 5h usage rungs, ascending — the thresholds [`levels_reached`]
/// tests the aggregate against. Mirrors [`UsageLevel`]'s three variants; each
/// `pct()` is its threshold.
const USAGE_RUNGS: [UsageLevel; 3] = [UsageLevel::Pct85, UsageLevel::Pct90, UsageLevel::Pct95];

/// One agent's most-recent reading of the **shared account-wide** budget pool.
///
/// The percentages are NOT this agent's private context window — they are the
/// account-wide 5h/7d reserve this agent read from the keeperd budget handshake
/// (`BudgetChanged { agent: Some(id), .. }`). Every agent reads the *same* meter;
/// a sample only records what one agent last saw of it, so the aggregator can
/// fold the readings back into the single number the meter represents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageSample {
    /// The reporting agent's bus id (the `@`-stripped work-stream name).
    pub agent: String,
    /// The account-wide reserve this agent last read.
    pub budget: BudgetUsage,
}

impl UsageSample {
    /// Construct a sample of the shared pool as `agent` last read it.
    pub fn new(agent: impl Into<String>, budget: BudgetUsage) -> Self {
        Self {
            agent: agent.into(),
            budget,
        }
    }
}

/// Which [`UsageLevel`] rungs the shared pool's **5h** reserve currently meets,
/// ascending. A pure threshold map: `>= 85 → [Pct85]`, `>= 90 → [Pct85, Pct90]`,
/// `>= 95 → [Pct85, Pct90, Pct95]`.
///
/// Feed each returned rung to the [`NotifyDispatcher`](crate::notify_dispatch);
/// its existing per-rung dedup ([`NotifyPolicy`](crate::notifications), keyed
/// `usage:85|90|95`) makes each fire **exactly once** across the rising budget,
/// so this stays a *stateless fact* — the "fired once" state belongs to the
/// engine, not duplicated here (the pure-module discipline: consume the existing
/// seam). A jump straight past several rungs reports all of them, and the engine
/// still fires each once. The rungs are 5h-scoped, matching
/// [`NotifyEvent::Usage`](crate::notifications::NotifyEvent::Usage)'s
/// "5h budget at N%" summary.
pub fn levels_reached(budget: BudgetUsage) -> Vec<UsageLevel> {
    USAGE_RUNGS
        .into_iter()
        .filter(|rung| budget.session_5h_pct >= rung.pct())
        .collect()
}

/// The cross-agent usage aggregator: holds each agent's latest reading of the
/// shared pool and folds them into one fleet-wide [`BudgetUsage`]. Pure — no
/// clock, no I/O; the drive loop feeds it from the live `BudgetChanged{agent}`
/// stream and reads [`aggregate_or_fresh`](Self::aggregate_or_fresh) /
/// [`fleet_levels`](Self::fleet_levels) at each admission/notify boundary.
#[derive(Debug, Default)]
pub struct UsageAggregator {
    /// The latest reading per agent (last-write-wins). Keyed for a deterministic
    /// fold and stable iteration.
    latest: BTreeMap<String, BudgetUsage>,
}

impl UsageAggregator {
    /// An aggregator with no samples yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `sample` as the reporting agent's latest reading of the shared
    /// pool. **Last-write-wins**: the drive loop overwrites an agent's prior
    /// sample on each fresh `BudgetChanged`, so a falling reading (a window
    /// reset) lowers that agent's contribution immediately.
    pub fn observe(&mut self, sample: UsageSample) {
        self.latest.insert(sample.agent, sample.budget);
    }

    /// Drop a departed agent's sample, so a dead agent's stale reading can never
    /// pin the fleet aggregate (the drive loop calls this when an agent leaves
    /// the fleet). Returns whether a sample was actually removed.
    pub fn forget(&mut self, agent: &str) -> bool {
        self.latest.remove(agent).is_some()
    }

    /// How many agents are currently contributing a sample.
    pub fn agent_count(&self) -> usize {
        self.latest.len()
    }

    /// The fleet-wide reserve: the per-field **maximum** across every agent's
    /// latest reading of the shared pool, or `None` when no agent has reported.
    /// See the module docs for why max (and never a sum) is the right fold for a
    /// shared, monotone-within-window percentage pool.
    pub fn aggregate(&self) -> Option<BudgetUsage> {
        self.latest.values().copied().reduce(|a, b| BudgetUsage {
            session_5h_pct: a.session_5h_pct.max(b.session_5h_pct),
            session_7d_pct: a.session_7d_pct.max(b.session_7d_pct),
        })
    }

    /// The fleet-wide reserve, defaulting to a fresh `(0, 0)` pool when no agent
    /// has reported — the form the [`AdmissionGovernor`](crate::admission) reads
    /// directly (an empty fleet has burned nothing).
    pub fn aggregate_or_fresh(&self) -> BudgetUsage {
        self.aggregate().unwrap_or(BudgetUsage::new(0, 0))
    }

    /// The usage rungs the **current fleet aggregate** meets — [`levels_reached`]
    /// over [`aggregate_or_fresh`](Self::aggregate_or_fresh). The drive loop
    /// feeds these to its single [`NotifyDispatcher`](crate::notify_dispatch).
    pub fn fleet_levels(&self) -> Vec<UsageLevel> {
        levels_reached(self.aggregate_or_fresh())
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

    fn sample(agent: &str, five_h: u8, seven_d: u8) -> UsageSample {
        UsageSample::new(agent, BudgetUsage::new(five_h, seven_d))
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
        assert_eq!(agg.aggregate(), None);
        assert_eq!(agg.aggregate_or_fresh(), BudgetUsage::new(0, 0));
        assert_eq!(agg.agent_count(), 0);
        assert!(agg.fleet_levels().is_empty());
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
        assert_eq!(agg.aggregate(), Some(BudgetUsage::new(75, 20)));
    }

    /// A reading is per-agent last-write-wins: a fresh lower sample (a window
    /// reset that agent observed) lowers that agent's contribution at once.
    #[test]
    fn observe_is_last_write_wins_per_agent() {
        let mut agg = UsageAggregator::new();
        agg.observe(sample("a1", 80, 30));
        agg.observe(sample("a2", 50, 10));
        assert_eq!(agg.aggregate(), Some(BudgetUsage::new(80, 30)));
        // a1's window reset — its next reading is low. Last-write-wins, so a1 no
        // longer dominates; the aggregate falls to a2's reading.
        agg.observe(sample("a1", 20, 5));
        assert_eq!(agg.agent_count(), 2, "still two agents, a1 was replaced");
        assert_eq!(agg.aggregate(), Some(BudgetUsage::new(50, 10)));
    }

    /// Forgetting a departed agent drops its (possibly stale-high) reading so it
    /// can never pin the aggregate after it leaves the fleet.
    #[test]
    fn forget_drops_a_departed_agents_stale_reading() {
        let mut agg = UsageAggregator::new();
        agg.observe(sample("hot", 92, 40));
        agg.observe(sample("cool", 30, 10));
        assert_eq!(agg.aggregate(), Some(BudgetUsage::new(92, 40)));

        assert!(agg.forget("hot"), "a present sample is removed");
        assert!(!agg.forget("hot"), "forget is idempotent / reports a no-op");
        // The stale-high reading is gone — the aggregate reflects the survivor.
        assert_eq!(agg.aggregate(), Some(BudgetUsage::new(30, 10)));
        assert_eq!(agg.agent_count(), 1);
    }

    /// `levels_reached` is a pure threshold map on the 5h reserve, at the
    /// boundaries (>= is inclusive; 7d is irrelevant to the rungs).
    #[test]
    fn levels_reached_maps_thresholds_inclusively() {
        let lvls = |five_h| levels_reached(BudgetUsage::new(five_h, 0));
        assert!(lvls(84).is_empty(), "under the first rung");
        assert_eq!(lvls(85), vec![UsageLevel::Pct85], "at 85");
        assert_eq!(lvls(89), vec![UsageLevel::Pct85]);
        assert_eq!(lvls(90), vec![UsageLevel::Pct85, UsageLevel::Pct90], "at 90");
        assert_eq!(lvls(94), vec![UsageLevel::Pct85, UsageLevel::Pct90]);
        assert_eq!(
            lvls(95),
            vec![UsageLevel::Pct85, UsageLevel::Pct90, UsageLevel::Pct95],
            "at 95 all three"
        );
        assert_eq!(lvls(100).len(), 3, "saturated still just the three rungs");
        // The 7d reserve never adds a 5h rung.
        assert!(levels_reached(BudgetUsage::new(10, 99)).is_empty());
    }

    /// The fleet aggregate gradually crossing 85 → 90 → 95 fires each alert
    /// **exactly once** via the dispatcher's existing per-rung dedup.
    #[test]
    fn crossing_85_90_95_fires_each_alert_exactly_once() {
        let mut agg = UsageAggregator::new();
        // A long cooldown so a repeat of a rung is always suppressed within the run.
        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(1_000_000));
        let now = 1_000;

        let mut fired: Vec<u8> = Vec::new();
        // The shared pool burns up over successive samples (one agent suffices —
        // the aggregate is the shared meter).
        for five_h in [80u8, 86, 91, 96] {
            agg.observe(sample("a1", five_h, 5));
            for level in agg.fleet_levels() {
                if !d.notify(&NotifyEvent::Usage(level), now).is_empty() {
                    fired.push(level.pct());
                }
            }
        }
        // Each rung announced once, in order — never re-fired despite being
        // "reached" on every later sample.
        assert_eq!(fired, vec![85, 90, 95]);
    }

    /// A jump straight past every rung announces all reached rungs once, then
    /// never re-fires them.
    #[test]
    fn a_jump_past_every_rung_fires_each_once_then_stays_quiet() {
        let mut agg = UsageAggregator::new();
        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(1_000_000));
        agg.observe(sample("a1", 96, 5)); // 0 → 96 in one reading

        let mut fired_now: Vec<u8> = Vec::new();
        for level in agg.fleet_levels() {
            if !d.notify(&NotifyEvent::Usage(level), 0).is_empty() {
                fired_now.push(level.pct());
            }
        }
        assert_eq!(fired_now, vec![85, 90, 95], "all reached rungs fire once");

        // A later sample still at/over 95 re-reaches the same rungs but none fire.
        agg.observe(sample("a1", 97, 5));
        let any = agg
            .fleet_levels()
            .into_iter()
            .any(|l| !d.notify(&NotifyEvent::Usage(l), 1).is_empty());
        assert!(!any, "already-announced rungs stay quiet");
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
            .decide(Intent::Start, 0, agg.aggregate_or_fresh(), fresh_rate())
            .is_admit());
        // A third agent sees the shared pool deeper (88%) → the fleet aggregate
        // breaches the rail → refuse.
        agg.observe(sample("a3", 88, 10));
        assert_eq!(
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh(), fresh_rate()),
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
            g.decide(Intent::Start, 0, agg.aggregate_or_fresh(), fresh_rate()),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget7d
            }
        );
    }
}
