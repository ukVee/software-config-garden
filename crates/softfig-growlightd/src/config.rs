//! growlightd configuration: the bound socket, the garden root (derived from
//! keeperd — never a literal), and the per-device [`Policy`].
//!
//! Slice 001 loads policy from defaults only; a `[growlight]`-style on-disk
//! override arrives with the scheduler/admission milestones (spec §7). Keeping
//! the defaults in one typed place now means later slices add fields without
//! reshaping callers.

use std::path::PathBuf;

use softfig_ipc::growlightd::PolicySummary;

/// Defensive ceiling on the per-device concurrency cap a `set_policy` may set:
/// generous (a beefy workstation runs many agents), but a value past it is a
/// fat-fingered nonsense cap that would try to spawn a runaway fleet. The
/// budget/rate rails still gate admission, but the cap itself should never be
/// absurd — so `set_policy` *rejects* (not clamps) one over this.
pub const MAX_CONCURRENT_AGENTS_CEILING: u32 = 64;

/// Per-device orchestration policy (spec §7 budgets + §17 concurrency cap).
///
/// Defaults mirror the single-agent loop's two budgets
/// (`meta/spec-growlight.md` §6: context 50→roll / 60→handoff, 5h 85% halt)
/// plus the orchestrator's device-scaled agent cap (spec §17: "start at ~2").
/// The GUI's tweak panel (spec §11) edits these live in a later phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Max agents the device runs concurrently. Device-scaled: a low-power
    /// tablet runs ~1–2, a workstation many (spec §7).
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

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_concurrent_agents: 2,
            ctx_roll_pct: 50,
            ctx_handoff_pct: 60,
            session_5h_halt_pct: 85,
            session_7d_halt_pct: 90,
        }
    }
}

/// Per-device **short-window rate limits** (spec §7 admission's second window):
/// the account TPM/RPM ceilings plus the per-agent burst headroom the governor
/// reserves before admitting one more agent ("request N× TPM for N agents").
///
/// These are deliberately **separate from [`Policy`]** (and off the wire
/// [`PolicySummary`]): they are static per-device config, not a `set_policy`
/// /GUI-tunable knob in this slice. Like slice-001's policy they are
/// **defaults-only** today — a future `[growlight]`-style on-disk override
/// threads them the same way `Policy` flows from keeperd. The live
/// [`crate::drive_loop::LiveRate`] source pairs these limits with the fleet-wide
/// rolling-minute *used* readings the backend meter observes.
///
/// The default ceilings are **conservative placeholders**: the real per-account
/// TPM/RPM is not carried on the headless `rate_limit_event` wire (it reports
/// only a coarse `status`), so confirming the device's true limits is this
/// milestone's on-device `## Deferred verification`. The defaults satisfy the
/// invariant `tpm_per_agent * max_concurrent_agents < tpm_limit` so a full
/// default fleet (cap 2) is never spuriously refused at idle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// Account tokens-per-minute ceiling.
    pub tpm_limit: u32,
    /// Account requests-per-minute ceiling.
    pub rpm_limit: u32,
    /// Tokens-per-minute one fresh agent is expected to burst — the headroom that
    /// must be free before it is admitted.
    pub tpm_per_agent: u32,
    /// Requests-per-minute one fresh agent is expected to burst.
    pub rpm_per_agent: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            tpm_limit: 2_000_000,
            rpm_limit: 1_000,
            tpm_per_agent: 200_000,
            rpm_per_agent: 50,
        }
    }
}

impl Policy {
    /// Project onto the wire summary echoed by `status`.
    pub fn summary(&self) -> PolicySummary {
        PolicySummary {
            max_concurrent_agents: self.max_concurrent_agents,
            ctx_roll_pct: self.ctx_roll_pct,
            ctx_handoff_pct: self.ctx_handoff_pct,
            session_5h_halt_pct: self.session_5h_halt_pct,
            session_7d_halt_pct: self.session_7d_halt_pct,
        }
    }

    /// Build a runtime policy from a wire [`PolicySummary`] (the `set_policy`
    /// verb), validating every field is in a sane operating range. A nonsense
    /// value is **rejected** with a clear message, never silently clamped, so a
    /// GUI typo can't quietly disable the fleet (a cap of `0` admits nothing; a
    /// `0`/over-`100` pct rail is meaningless). The mapping is otherwise the
    /// inverse of [`summary`](Self::summary). This is pure validation — it adds
    /// no new policy *semantics*, only the range guard `set_policy` needs.
    pub fn from_summary(s: PolicySummary) -> Result<Self, String> {
        if !(1..=MAX_CONCURRENT_AGENTS_CEILING).contains(&s.max_concurrent_agents) {
            return Err(format!(
                "max_concurrent_agents must be 1..={MAX_CONCURRENT_AGENTS_CEILING}, got {}",
                s.max_concurrent_agents
            ));
        }
        for (name, pct) in [
            ("ctx_roll_pct", s.ctx_roll_pct),
            ("ctx_handoff_pct", s.ctx_handoff_pct),
            ("session_5h_halt_pct", s.session_5h_halt_pct),
            ("session_7d_halt_pct", s.session_7d_halt_pct),
        ] {
            if !(1..=100).contains(&pct) {
                return Err(format!("{name} must be 1..=100, got {pct}"));
            }
        }
        Ok(Self {
            max_concurrent_agents: s.max_concurrent_agents,
            ctx_roll_pct: s.ctx_roll_pct,
            ctx_handoff_pct: s.ctx_handoff_pct,
            session_5h_halt_pct: s.session_5h_halt_pct,
            session_7d_halt_pct: s.session_7d_halt_pct,
        })
    }
}

/// Everything growlightd needs to boot: where it listens, the garden it serves,
/// and the policy it runs under.
#[derive(Debug, Clone)]
pub struct GrowlightdConfig {
    /// growlightd's own listen socket.
    pub socket_path: PathBuf,
    /// Garden root, derived from the keeperd `status` handshake (or an explicit
    /// override for tests). Never a hardcoded literal in production.
    pub garden_root: PathBuf,
    /// Per-device orchestration policy.
    pub policy: Policy,
    /// Per-device short-window TPM/RPM limits feeding admission's second window
    /// (spec §7). Static per-device config, defaults-only today (see
    /// [`RateLimits`]); not part of the wire `set_policy`/`status` surface.
    pub rate_limits: RateLimits,
}

impl GrowlightdConfig {
    /// Build a config with default policy.
    pub fn new(socket_path: PathBuf, garden_root: PathBuf) -> Self {
        Self {
            socket_path,
            garden_root,
            policy: Policy::default(),
            rate_limits: RateLimits::default(),
        }
    }

    /// Override the policy (builder-style).
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_defaults_match_spec() {
        let p = Policy::default();
        assert_eq!(p.max_concurrent_agents, 2, "spec §17: start at ~2");
        assert_eq!(p.ctx_roll_pct, 50);
        assert_eq!(p.ctx_handoff_pct, 60);
        assert_eq!(p.session_5h_halt_pct, 85);
        assert_eq!(p.session_7d_halt_pct, 90);
    }

    #[test]
    fn policy_summary_round_trips_fields() {
        let p = Policy::default();
        let s = p.summary();
        assert_eq!(s.max_concurrent_agents, p.max_concurrent_agents);
        assert_eq!(s.ctx_roll_pct, p.ctx_roll_pct);
        assert_eq!(s.session_5h_halt_pct, p.session_5h_halt_pct);
    }

    #[test]
    fn config_new_uses_default_policy() {
        let c = GrowlightdConfig::new("/run/g.sock".into(), "/garden".into());
        assert_eq!(c.policy, Policy::default());
        assert_eq!(c.garden_root, PathBuf::from("/garden"));
    }

    #[test]
    fn from_summary_round_trips_a_valid_policy() {
        // `from_summary` is the inverse of `summary` for any in-range policy.
        let p = Policy {
            max_concurrent_agents: 4,
            ctx_roll_pct: 45,
            ctx_handoff_pct: 55,
            session_5h_halt_pct: 80,
            session_7d_halt_pct: 88,
        };
        assert_eq!(Policy::from_summary(p.summary()), Ok(p));
        // The default policy round-trips too.
        let d = Policy::default();
        assert_eq!(Policy::from_summary(d.summary()), Ok(d));
    }

    #[test]
    fn from_summary_rejects_out_of_range_values() {
        let base = Policy::default().summary();

        // A zero cap admits nothing → rejected (not clamped).
        let mut zero_cap = base;
        zero_cap.max_concurrent_agents = 0;
        assert!(Policy::from_summary(zero_cap).is_err(), "cap 0 rejected");

        // A cap past the defensive ceiling is a runaway nonsense value.
        let mut huge_cap = base;
        huge_cap.max_concurrent_agents = MAX_CONCURRENT_AGENTS_CEILING + 1;
        assert!(Policy::from_summary(huge_cap).is_err(), "over-ceiling cap rejected");
        // Exactly at the ceiling is fine.
        let mut at_ceiling = base;
        at_ceiling.max_concurrent_agents = MAX_CONCURRENT_AGENTS_CEILING;
        assert!(Policy::from_summary(at_ceiling).is_ok(), "the ceiling itself is valid");

        // A 0 pct and an over-100 pct are both out of range, on every rail.
        for set in [
            |s: &mut PolicySummary| s.ctx_roll_pct = 0,
            |s: &mut PolicySummary| s.ctx_handoff_pct = 101,
            |s: &mut PolicySummary| s.session_5h_halt_pct = 200,
            |s: &mut PolicySummary| s.session_7d_halt_pct = 0,
        ] {
            let mut bad = base;
            set(&mut bad);
            assert!(Policy::from_summary(bad).is_err(), "an out-of-range pct is rejected");
        }
    }
}
