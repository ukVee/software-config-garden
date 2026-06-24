//! The global **admission governor** (phase 6, slice 001) — the pure
//! gate that decides whether one agent may *start* or *roll* right now
//! (spec-growlight-orchestrator §7).
//!
//! ## What this is (and isn't)
//!
//! A **pure value model**: [`AdmissionGovernor::decide`] maps the current fleet
//! load + shared budget + per-minute rate readings to an
//! **admit / queue / refuse** decision, with **all inputs injected** — no real
//! API calls, no live meter, no clock, no socket, no daemon lock. Exactly the
//! shape of this crate's [`crate::leases::LeaseTable`] and
//! [`crate::scheduler::pick`] (and keeperd's `ThrashDetector`): the hard policy
//! is provable in isolation against fakes (the theory-code proof obligation),
//! and the live wiring stays thin around it.
//!
//! The live gate — populating the readings from the keeperd budget handshake
//! and a rolling per-minute meter, and consulting the governor at each
//! start/roll boundary — is the **drive loop's** job (slice 002 fleet
//! supervision + the phase-6 drive loop). This slice answers only the policy
//! question: *given these readings right now, may one more agent run?*
//!
//! ## The policy (spec §7)
//!
//! The 5-hour budget is **one shared account-wide pool**, so the governor moves
//! from a per-agent *halt* ([[spec-growlight]] §6) to global **admission**:
//! before starting or rolling any agent, growlightd checks **headroom** and the
//! **per-device cap**. Two windows, not one — gate on **both** the 5h/7d rolling
//! reserve *and* short-window **TPM/RPM** (tokens/requests per minute), because N
//! agents starting at once burst against per-minute limits even with 5h headroom
//! ("request N× TPM for N agents").
//!
//! Three constraints, in precedence order (the strongest blocker wins, so the
//! decision names the *real* reason the caller should wait on):
//!
//! 1. **Shared budget reserve** (5h, then 7d). At/over the per-device halt pct
//!    the account pool is exhausted — **refuse** a start *and* a roll, regardless
//!    of slots. (A roll past the halt should HALT, not roll — [[spec-growlight]]
//!    §6.) This is the hardest rail (the account-wide, longest-window one) so it
//!    is checked first.
//! 2. **Short-window rate** (TPM, then RPM). If admitting one more agent's burst
//!    would exceed the rolling-minute limit — **refuse**. Transient (it recovers
//!    within a minute) but it is a back-off, not a slot wait.
//! 3. **Per-device concurrency cap.** Only a **start** consumes a slot, so the
//!    cap gates a [`Intent::Start`] only: at/over `max_concurrent_agents` →
//!    **queue** (wait for a slot to free). A [`Intent::Roll`] keeps the slot it
//!    already holds, so the cap never gates it — otherwise a full fleet could
//!    never roll any agent (a deadlock).
//!
//! All three clear → **admit**.
//!
//! ## Why budget/rate **refuse** outranks the cap **queue**
//!
//! When the fleet is full *and* the budget is exhausted, both a slot and the
//! pool are missing. `Refuse` is surfaced rather than `Queue` because the budget
//! is the actionable blocker: telling the caller "wait for a slot" would be
//! misleading when even a freed slot could not run. The two only differ in what
//! the caller waits on — a freed-slot event (`Queue`) vs a window/minute recovery
//! (`Refuse`) — and either way the caller re-consults and converges.

use crate::config::Policy;

/// Whether the agent being admitted is brand-new to the fleet or an existing
/// agent rolling into a fresh session. The distinction matters for the
/// concurrency cap: a [`Self::Start`] consumes a slot (the cap gates it); a
/// [`Self::Roll`] keeps the slot it already holds (the cap never gates it).
/// Budget and rate gate **both** — a roll bursts tokens and draws the shared
/// pool just like a start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Adding a new agent to the fleet — consumes a concurrency slot.
    Start,
    /// An existing agent ending its session and beginning a fresh one — keeps
    /// its slot, so the cap does not gate it.
    Roll,
}

/// A snapshot of the shared account-wide budget reserves, as percentages
/// **used** (0–100). These are the `session_5h_pct` / `session_7d_pct` numbers
/// [`softfig_ipc::growlightd::Event::BudgetChanged`] carries with `agent: None`
/// (the fleet-wide pool, not a per-agent context window). The governor refuses
/// when a reading reaches the matching halt pct in [`Policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetUsage {
    /// 5h rolling-reserve used %, account-wide.
    pub session_5h_pct: u8,
    /// 7d rolling-reserve used %, account-wide.
    pub session_7d_pct: u8,
}

impl BudgetUsage {
    /// Construct a budget reading.
    pub fn new(session_5h_pct: u8, session_7d_pct: u8) -> Self {
        Self {
            session_5h_pct,
            session_7d_pct,
        }
    }
}

/// A snapshot of the short-window (rolling-minute) rate state: how many
/// tokens/requests the fleet has spent in the current minute, the account
/// limits, and the headroom one fresh agent is expected to need. Modeled as a
/// plain injected input (no clock here): the rolling-minute aggregation is the
/// live meter's job in the drive loop; the governor only checks whether
/// admitting **one more** agent's burst would cross the limit
/// (`used + per_agent > limit`), realizing "request N× TPM for N agents".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateState {
    /// Tokens spent in the current rolling minute, account-wide.
    pub tpm_used: u32,
    /// Requests issued in the current rolling minute, account-wide.
    pub rpm_used: u32,
    /// Account tokens-per-minute limit.
    pub tpm_limit: u32,
    /// Account requests-per-minute limit.
    pub rpm_limit: u32,
    /// Tokens-per-minute one fresh agent is expected to burst — the headroom
    /// that must be free before it is admitted.
    pub tpm_per_agent: u32,
    /// Requests-per-minute one fresh agent is expected to burst.
    pub rpm_per_agent: u32,
}

impl RateState {
    /// Whether admitting one more agent would exceed the tokens-per-minute
    /// limit. Saturating so an over-provisioned reading can never overflow-panic.
    fn tpm_would_exceed(&self) -> bool {
        self.tpm_used.saturating_add(self.tpm_per_agent) > self.tpm_limit
    }

    /// Whether admitting one more agent would exceed the requests-per-minute
    /// limit.
    fn rpm_would_exceed(&self) -> bool {
        self.rpm_used.saturating_add(self.rpm_per_agent) > self.rpm_limit
    }
}

/// Why admission **refused** — which exhausted resource the caller must wait on.
/// Distinct from a [`AdmissionDecision::Queue`] (a slot wait): a refusal recovers
/// when the named window/minute does, not when an agent finishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// The 5h shared reserve is at/over the halt pct.
    Budget5h,
    /// The 7d shared reserve is at/over the halt pct.
    Budget7d,
    /// One more agent's burst would exceed the per-minute token limit.
    Tpm,
    /// One more agent's burst would exceed the per-minute request limit.
    Rpm,
}

impl RefuseReason {
    /// A one-line human-facing label — the body the drive loop renders into the
    /// log line / `kind: alert` bus message when a start is refused.
    pub fn label(self) -> &'static str {
        match self {
            Self::Budget5h => "5h budget reserve at the halt rail",
            Self::Budget7d => "7d budget reserve at the halt rail",
            Self::Tpm => "per-minute token limit reached",
            Self::Rpm => "per-minute request limit reached",
        }
    }
}

/// The admission governor's verdict for one start/roll request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Admit the agent — every gate cleared. Start it (or let it roll).
    Admit,
    /// The fleet is at the per-device cap; **wait for a slot to free** (transient,
    /// resolves when an agent finishes). Only a [`Intent::Start`] is ever queued.
    Queue {
        /// Agents currently running.
        active: u32,
        /// The per-device `max_concurrent_agents` cap.
        cap: u32,
    },
    /// Do **not** admit — a budget reserve or per-minute rate limit is exhausted.
    /// Back off until the named window/minute recovers; not a slot problem.
    Refuse {
        /// Which exhausted resource blocked admission.
        reason: RefuseReason,
    },
}

impl AdmissionDecision {
    /// Whether the agent was admitted.
    pub fn is_admit(self) -> bool {
        matches!(self, Self::Admit)
    }

    /// Whether the agent was queued behind the concurrency cap.
    pub fn is_queued(self) -> bool {
        matches!(self, Self::Queue { .. })
    }

    /// Whether the agent was refused on budget/rate.
    pub fn is_refused(self) -> bool {
        matches!(self, Self::Refuse { .. })
    }

    /// A one-line human-facing summary — the body the drive loop logs / surfaces
    /// as a `kind: alert` when a start is held off.
    pub fn summary(self) -> String {
        match self {
            Self::Admit => "admitted".to_string(),
            Self::Queue { active, cap } => {
                format!("queued — fleet at the {active}/{cap} concurrency cap")
            }
            Self::Refuse { reason } => format!("refused — {}", reason.label()),
        }
    }
}

/// The global admission governor: a pure gate configured by the per-device
/// [`Policy`] (the concurrency cap + the 5h/7d halt pcts). Holds no mutable
/// state — every reading is injected per [`decide`](Self::decide) call, so the
/// daemon constructs it once with the device policy and consults it at each
/// start/roll boundary.
#[derive(Debug, Clone)]
pub struct AdmissionGovernor {
    policy: Policy,
}

impl AdmissionGovernor {
    /// Construct a governor for the given per-device policy.
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// The per-device concurrency cap this governor enforces.
    pub fn max_concurrent_agents(&self) -> u32 {
        self.policy.max_concurrent_agents
    }

    /// The per-device [`Policy`] this governor enforces — so a live `set_policy`
    /// change can be detected (a `Copy` compare) before the drive loop rebuilds
    /// the governor. The decision logic itself stays a pure function of the
    /// injected readings; only the *configured* policy is exposed here.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Decide whether one agent may `intent` (start or roll) right now, given
    /// the current `fleet_size` (agents running), the shared `budget` reserves,
    /// and the per-minute `rate` state. See the module docs for the precedence:
    /// budget reserve → rate → cap, strongest blocker first.
    pub fn decide(
        &self,
        intent: Intent,
        fleet_size: u32,
        budget: BudgetUsage,
        rate: RateState,
    ) -> AdmissionDecision {
        // 1. Shared budget rails (5h then 7d) — the account pool is exhausted;
        //    neither a start nor a roll may proceed regardless of slots.
        if budget.session_5h_pct >= self.policy.session_5h_halt_pct {
            return AdmissionDecision::Refuse {
                reason: RefuseReason::Budget5h,
            };
        }
        if budget.session_7d_pct >= self.policy.session_7d_halt_pct {
            return AdmissionDecision::Refuse {
                reason: RefuseReason::Budget7d,
            };
        }

        // 2. Short-window per-minute burst (TPM then RPM) — admitting one more
        //    agent's share would cross the rolling-minute limit. Back off.
        if rate.tpm_would_exceed() {
            return AdmissionDecision::Refuse {
                reason: RefuseReason::Tpm,
            };
        }
        if rate.rpm_would_exceed() {
            return AdmissionDecision::Refuse {
                reason: RefuseReason::Rpm,
            };
        }

        // 3. Per-device concurrency cap — only a start consumes a slot; a roll
        //    keeps the one it already holds, so the cap never gates a roll.
        if intent == Intent::Start && fleet_size >= self.policy.max_concurrent_agents {
            return AdmissionDecision::Queue {
                active: fleet_size,
                cap: self.policy.max_concurrent_agents,
            };
        }

        // 4. Every gate clear.
        AdmissionDecision::Admit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A budget reading well under any halt rail.
    fn fresh_budget() -> BudgetUsage {
        BudgetUsage::new(10, 5)
    }

    /// A rate reading with generous headroom: admitting one more agent stays
    /// well under both per-minute limits.
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

    /// The default-policy governor (cap 2, 5h halt 85, 7d halt 90).
    fn gov() -> AdmissionGovernor {
        AdmissionGovernor::new(Policy::default())
    }

    /// Under the cap with budget+rate headroom → admit.
    #[test]
    fn under_cap_with_headroom_admits() {
        let g = gov();
        // cap is 2; one agent running, starting a second is fine.
        assert_eq!(
            g.decide(Intent::Start, 1, fresh_budget(), fresh_rate()),
            AdmissionDecision::Admit
        );
        // an empty fleet too.
        assert_eq!(
            g.decide(Intent::Start, 0, fresh_budget(), fresh_rate()),
            AdmissionDecision::Admit
        );
    }

    /// At (or over) the per-device cap, a *start* queues for a slot.
    #[test]
    fn at_or_over_cap_a_start_queues() {
        let g = gov(); // cap 2
        assert_eq!(
            g.decide(Intent::Start, 2, fresh_budget(), fresh_rate()),
            AdmissionDecision::Queue { active: 2, cap: 2 }
        );
        // defensively, an over-full fleet also queues (never silently admits).
        assert_eq!(
            g.decide(Intent::Start, 3, fresh_budget(), fresh_rate()),
            AdmissionDecision::Queue { active: 3, cap: 2 }
        );
    }

    /// The cap never gates a *roll* — an agent already in a full fleet may roll
    /// its own session (otherwise a full fleet deadlocks, never rolling).
    #[test]
    fn the_cap_never_gates_a_roll() {
        let g = gov(); // cap 2
        // fleet at and over the cap: a roll is still admitted.
        assert_eq!(
            g.decide(Intent::Roll, 2, fresh_budget(), fresh_rate()),
            AdmissionDecision::Admit
        );
        assert_eq!(
            g.decide(Intent::Roll, 5, fresh_budget(), fresh_rate()),
            AdmissionDecision::Admit
        );
    }

    /// The 5h reserve at/over the halt pct refuses both a start and a roll.
    #[test]
    fn budget_5h_at_the_halt_rail_refuses_start_and_roll() {
        let g = gov(); // 5h halt 85
        let hot = BudgetUsage::new(85, 5);
        for intent in [Intent::Start, Intent::Roll] {
            assert_eq!(
                g.decide(intent, 0, hot, fresh_rate()),
                AdmissionDecision::Refuse {
                    reason: RefuseReason::Budget5h
                },
                "{intent:?} refused at the 5h rail"
            );
        }
        // one under the rail is fine.
        assert_eq!(
            g.decide(Intent::Start, 0, BudgetUsage::new(84, 5), fresh_rate()),
            AdmissionDecision::Admit
        );
    }

    /// The 7d reserve at/over its halt pct refuses (when 5h is still fine).
    #[test]
    fn budget_7d_at_the_halt_rail_refuses() {
        let g = gov(); // 7d halt 90
        assert_eq!(
            g.decide(Intent::Start, 0, BudgetUsage::new(10, 90), fresh_rate()),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget7d
            }
        );
        assert_eq!(
            g.decide(Intent::Start, 0, BudgetUsage::new(10, 89), fresh_rate()),
            AdmissionDecision::Admit
        );
    }

    /// A per-minute token burst over the limit refuses (Tpm).
    #[test]
    fn tpm_burst_over_the_window_refuses() {
        let g = gov();
        let mut rate = fresh_rate();
        // used + per_agent would cross the limit: 90k + 20k > 100k.
        rate.tpm_used = 90_000;
        assert_eq!(
            g.decide(Intent::Start, 0, fresh_budget(), rate),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Tpm
            }
        );
    }

    /// A per-minute request burst over the limit refuses (Rpm), even with token
    /// headroom.
    #[test]
    fn rpm_burst_over_the_window_refuses() {
        let g = gov();
        let mut rate = fresh_rate();
        // 95 + 10 > 100 requests, but tokens are fine.
        rate.rpm_used = 95;
        assert_eq!(
            g.decide(Intent::Start, 0, fresh_budget(), rate),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Rpm
            }
        );
    }

    /// The rate gate is `used + per_agent > limit`: exactly at the limit still
    /// admits; one token/request over refuses.
    #[test]
    fn rate_boundary_at_the_limit_admits_one_over_refuses() {
        let g = gov();
        // tokens: 80k used + 20k per-agent == 100k limit → exactly fits.
        let mut at_limit = fresh_rate();
        at_limit.tpm_used = 80_000;
        assert_eq!(
            g.decide(Intent::Start, 0, fresh_budget(), at_limit),
            AdmissionDecision::Admit
        );
        // one token over → refuse.
        let mut over = at_limit;
        over.tpm_used = 80_001;
        assert_eq!(
            g.decide(Intent::Start, 0, fresh_budget(), over),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Tpm
            }
        );
    }

    /// Precedence: a budget refusal outranks the cap queue — a full fleet with an
    /// exhausted pool surfaces the *budget*, not a slot wait.
    #[test]
    fn budget_refuse_outranks_the_cap_queue() {
        let g = gov(); // cap 2, 5h halt 85
        assert_eq!(
            g.decide(Intent::Start, 2, BudgetUsage::new(85, 5), fresh_rate()),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget5h
            },
            "full fleet + exhausted budget → refuse (not queue)"
        );
    }

    /// Precedence among refusals: 5h outranks 7d, and budget outranks rate.
    #[test]
    fn refusal_precedence_is_5h_then_7d_then_rate() {
        let g = gov();
        let mut burst = fresh_rate();
        burst.tpm_used = 90_000; // also over TPM
                                 // 5h + 7d + rate all hot → 5h wins.
        assert_eq!(
            g.decide(Intent::Start, 0, BudgetUsage::new(85, 90), burst),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget5h
            }
        );
        // 7d + rate hot, 5h fine → 7d wins over rate.
        assert_eq!(
            g.decide(Intent::Start, 0, BudgetUsage::new(10, 90), burst),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget7d
            }
        );
    }

    /// When headroom returns, the same request that was held now admits — the
    /// gate carries no state, so recovery is immediate.
    #[test]
    fn admits_again_once_headroom_returns() {
        let g = gov();
        // First: budget exhausted → refuse.
        assert!(g
            .decide(Intent::Start, 1, BudgetUsage::new(90, 5), fresh_rate())
            .is_refused());
        // Budget recovers (window reset) → the same start now admits.
        assert_eq!(
            g.decide(Intent::Start, 1, BudgetUsage::new(40, 5), fresh_rate()),
            AdmissionDecision::Admit
        );
        // Likewise a queued start admits once a slot frees.
        assert!(g
            .decide(Intent::Start, 2, fresh_budget(), fresh_rate())
            .is_queued());
        assert!(g
            .decide(Intent::Start, 1, fresh_budget(), fresh_rate())
            .is_admit());
    }

    /// A non-default device policy (a beefier cap) is honored.
    #[test]
    fn honors_a_device_scaled_cap() {
        let policy = Policy {
            max_concurrent_agents: 8,
            ..Policy::default()
        };
        let g = AdmissionGovernor::new(policy);
        assert_eq!(g.max_concurrent_agents(), 8);
        // 7 running, an 8th starts fine; the 9th queues.
        assert!(g
            .decide(Intent::Start, 7, fresh_budget(), fresh_rate())
            .is_admit());
        assert_eq!(
            g.decide(Intent::Start, 8, fresh_budget(), fresh_rate()),
            AdmissionDecision::Queue { active: 8, cap: 8 }
        );
    }

    /// Decision predicates and summaries are coherent and non-empty (the drive
    /// loop logs / alerts these).
    #[test]
    fn decision_helpers_and_summaries() {
        assert!(AdmissionDecision::Admit.is_admit());
        let q = AdmissionDecision::Queue { active: 2, cap: 2 };
        assert!(q.is_queued() && !q.is_admit() && !q.is_refused());
        let r = AdmissionDecision::Refuse {
            reason: RefuseReason::Tpm,
        };
        assert!(r.is_refused() && !r.is_admit());
        for d in [q, r, AdmissionDecision::Admit] {
            assert!(!d.summary().is_empty(), "{d:?} has a summary");
        }
        for reason in [
            RefuseReason::Budget5h,
            RefuseReason::Budget7d,
            RefuseReason::Tpm,
            RefuseReason::Rpm,
        ] {
            assert!(!reason.label().is_empty(), "{reason:?} has a label");
        }
    }
}
