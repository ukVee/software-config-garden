//! growlightd configuration: the bound socket, the garden root (derived from
//! keeperd — never a literal), and the per-device [`Policy`].
//!
//! Slice 001 loads policy from defaults only; a `[growlight]`-style on-disk
//! override arrives with the scheduler/admission milestones (spec §7). Keeping
//! the defaults in one typed place now means later slices add fields without
//! reshaping callers.

use std::path::PathBuf;

use softfig_ipc::growlightd::PolicySummary;

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
}

impl GrowlightdConfig {
    /// Build a config with default policy.
    pub fn new(socket_path: PathBuf, garden_root: PathBuf) -> Self {
        Self {
            socket_path,
            garden_root,
            policy: Policy::default(),
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
}
