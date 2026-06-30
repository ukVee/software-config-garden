//! growlightd configuration: the bound socket, the garden root (derived from
//! keeperd — never a literal), and the per-device [`Policy`].
//!
//! Slice 001 loads policy from defaults only; a `[growlight]`-style on-disk
//! override arrives with the scheduler/admission milestones (spec §7). Keeping
//! the defaults in one typed place now means later slices add fields without
//! reshaping callers.

use std::path::PathBuf;

use serde::Deserialize;
use softfig_ipc::growlightd::{BuildCapsSummary, PolicySummary, SetResourcesArgs};

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

/// Per-agent **build-resource caps** applied to each agent's transient systemd
/// scope (peer-isolation slice 002). These THROTTLE a building agent — they
/// never abort the build (incident growlightd-resource-down-build; human
/// direction 2026-06-28): a headless `claude -p` runs `cargo build`/`test` as a
/// *blocking* tool call and simply waits for it, so a SLOWER build is just a
/// longer wait, not a failure. The caps may only slow a build, never kill it.
///
/// Defaults are conservative for the Surface Go 3 (7.7 GB): a low parallel-`rustc`
/// cap, a SOFT `MemoryHigh` (the kernel throttles + reclaims past it, never
/// OOM-kills), and a deprioritizing `CPUWeight`. Deliberately NEVER `MemoryMax`
/// (the hard OOM-kill cap) and NEVER a tight `TasksMax` (a `fork` EAGAIN) — both
/// would abort the build the agent is blocked on. Parsed from the in-garden
/// `config/growlight.toml` `[build_caps]` table (a missing table ⇒ these
/// defaults; a partial table fills the rest from them). Live runtime adjustment
/// via the CLI + GUI is slice 003.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct BuildCaps {
    /// `CARGO_BUILD_JOBS` set on the scope — the parallel-`rustc` ceiling. Low
    /// (default 2) ⇒ fewer concurrent `rustc` ⇒ lower peak RAM; cargo serializes
    /// the rest gracefully, so this only slows the build. `None` leaves it unset.
    pub cargo_build_jobs: Option<u32>,
    /// `MemoryHigh` SOFT throttle, as a systemd memory value (bytes, or a suffix
    /// like `"3G"` / `"70%"`). Past it the kernel throttles + reclaims the scope,
    /// so the build slows under pressure but is NOT OOM-killed — deliberately NOT
    /// `MemoryMax` (which would abort it). `None` leaves it unset.
    pub memory_high: Option<String>,
    /// `CPUWeight` (1..=10000, systemd default 100) — a lower weight deprioritizes
    /// the agent against growlightd + the rest of the box, keeping the tablet
    /// responsive. Only slows the build. `None` leaves it unset.
    pub cpu_weight: Option<u32>,
}

impl Default for BuildCaps {
    fn default() -> Self {
        Self {
            cargo_build_jobs: Some(2),
            memory_high: Some("3G".to_string()),
            cpu_weight: Some(50),
        }
    }
}

/// systemd's valid `CPUWeight` range (inclusive). A value outside it is a
/// fat-fingered nonsense weight `set_resources` **rejects** (not clamps), like
/// [`Policy::from_summary`] guards the policy rails.
pub const CPU_WEIGHT_MIN: u32 = 1;
pub const CPU_WEIGHT_MAX: u32 = 10_000;

/// Defensive ceiling on `CARGO_BUILD_JOBS` a `set_resources` may set: comfortably
/// above any real core count (the Surface Go 3 has 2), but a value past it is a
/// fat-fingered nonsense cap that invites a `rustc` fork-storm — the opposite
/// failure mode from a `0` cap (which stalls). Like [`CPU_WEIGHT_MAX`] it is
/// **rejected**, not clamped, so the reject-not-clamp invariant bounds `build_jobs`
/// on BOTH ends (audit slice 006).
pub const BUILD_JOBS_MAX: u32 = 64;

/// Does `value` parse as a systemd `MemoryHigh=` value, closely enough that any
/// value accepted here `systemd-run` will also accept? (slice 001, the HIGH:
/// `memory-high-validated-nonempty-only-poisons-config-and-fail-closes-spawn`.)
///
/// Before this guard, `with_update` accepted any non-empty `memory_high` and
/// deferred to systemd's *live* check — which is best-effort-swallowed, so a
/// typo like `3GB` (systemd wants `3G`) was persisted + committed first, then
/// fail-closed every later spawn and **survived restart**. One typo durably
/// bricked fleet spawning with no user-facing error. Validating here refuses the
/// bad value at the verb boundary so it can never be stored, persisted, or reach
/// a spawn — reject-not-clamp at the source.
///
/// Mirrors systemd's `parse_size(., 1024)` grammar (`src/basic/parse-util.c`):
/// - `infinity` (no limit), or
/// - a percentage `N%` / `N.N%` (`config_parse_memory_limit`'s permyriad path), or
/// - one or more `<digits><unit?>` groups (systemd sums `4G512M`), where a unit
///   is a single 1024-base suffix `K`/`M`/`G`/`T`/`P`/`E` or the byte suffix `B`;
///   a bare number is bytes.
///
/// Rejects empty/whitespace, embedded or surrounding spaces, unknown units, and
/// doubled suffixes like `3GB` (the trailing `B` has no preceding number — the
/// exact systemd rejection this slice guards against). Stricter on whitespace
/// than systemd by design: we never store a value with surrounding spaces.
pub fn is_valid_memory_high(value: &str) -> bool {
    if value == "infinity" {
        return true;
    }
    if let Some(pct) = value.strip_suffix('%') {
        // `N%` or `N.N%` — at least one digit before the dot, digits after if present.
        let mut parts = pct.splitn(2, '.');
        let int = parts.next().unwrap_or("");
        let frac = parts.next();
        return !int.is_empty()
            && int.bytes().all(|b| b.is_ascii_digit())
            && frac.is_none_or(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()));
    }
    // One or more `<digits><single-suffix?>` groups (systemd `parse_size`).
    let bytes = value.as_bytes();
    let mut i = 0;
    let mut groups = 0;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            // A suffix with no preceding number — e.g. the `B` left after `3G` in `3GB`,
            // a leading space, or junk like `banana`.
            return false;
        }
        if i < bytes.len() && matches!(bytes[i], b'K' | b'M' | b'G' | b'T' | b'P' | b'E' | b'B') {
            i += 1;
        }
        groups += 1;
    }
    groups >= 1
}

impl BuildCaps {
    /// Project onto the wire [`BuildCapsSummary`] echoed by `status` /
    /// `set_resources`.
    pub fn summary(&self) -> BuildCapsSummary {
        BuildCapsSummary {
            cargo_build_jobs: self.cargo_build_jobs,
            memory_high: self.memory_high.clone(),
            cpu_weight: self.cpu_weight,
        }
    }

    /// Apply a **partial** [`SetResourcesArgs`] update (the `set_resources` verb,
    /// slice 003): each `Some` knob overwrites this cap, each `None` leaves the
    /// current value untouched (the merge is onto `self`, never a full replace).
    ///
    /// Every value being set is **validated against its sane operating range** and
    /// a nonsense value is **rejected** with a clear message — never silently
    /// clamped — so a GUI/CLI typo can't quietly disable the throttle. The guard
    /// is the inverse spirit of [`Policy::from_summary`]:
    /// - `build_jobs` must be `1..=`[`BUILD_JOBS_MAX`] (a `0` cap would stall the
    ///   build; an over-large cap invites a `rustc` fork-storm on a low-RAM device);
    /// - `cpu_weight` must be [`CPU_WEIGHT_MIN`]..=[`CPU_WEIGHT_MAX`] (systemd's range);
    /// - `memory_high` must parse as a systemd `MemoryHigh=` value
    ///   ([`is_valid_memory_high`]) — a typo like `3GB` is rejected HERE, never
    ///   deferred to a swallowed live check that would poison the config and
    ///   fail-close every later spawn (slice 001).
    ///
    /// **Throttle, not kill.** There is no hard-cap knob to validate — the args
    /// carry only the three SOFT throttles, so a merged [`BuildCaps`] can only ever
    /// slow a build, never abort it (no `MemoryMax`, no tight `TasksMax`). That
    /// invariant is structural; this method just range-guards the soft values.
    pub fn with_update(&self, args: &SetResourcesArgs) -> Result<BuildCaps, String> {
        if let Some(jobs) = args.build_jobs {
            if jobs < 1 {
                return Err("build_jobs must be >= 1 (a 0 parallel-rustc cap stalls the build)".into());
            }
            if jobs > BUILD_JOBS_MAX {
                return Err(format!(
                    "build_jobs must be 1..={BUILD_JOBS_MAX}, got {jobs} \
                     (an over-large cap invites a rustc fork-storm that harms a low-RAM device)"
                ));
            }
        }
        if let Some(weight) = args.cpu_weight {
            if !(CPU_WEIGHT_MIN..=CPU_WEIGHT_MAX).contains(&weight) {
                return Err(format!(
                    "cpu_weight must be {CPU_WEIGHT_MIN}..={CPU_WEIGHT_MAX}, got {weight}"
                ));
            }
        }
        if let Some(high) = &args.memory_high {
            if !is_valid_memory_high(high) {
                return Err(format!(
                    "memory_high {high:?} is not a valid systemd MemoryHigh value \
                     (want bytes, a 1024-base suffix like 3G/512M, a percentage like 70%, \
                     or infinity)"
                ));
            }
        }
        let mut merged = self.clone();
        if let Some(jobs) = args.build_jobs {
            merged.cargo_build_jobs = Some(jobs);
        }
        if let Some(high) = &args.memory_high {
            merged.memory_high = Some(high.clone());
        }
        if let Some(weight) = args.cpu_weight {
            merged.cpu_weight = Some(weight);
        }
        Ok(merged)
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
    fn build_caps_defaults_are_conservative_and_gentle() {
        // Conservative for the 7.7 GB tablet: a low parallel-rustc cap + a SOFT
        // MemoryHigh + a deprioritizing CPUWeight — every one a THROTTLE.
        let c = BuildCaps::default();
        assert_eq!(c.cargo_build_jobs, Some(2), "few parallel rustc → lower peak RAM");
        assert_eq!(c.memory_high.as_deref(), Some("3G"), "SOFT throttle, not a hard cap");
        assert_eq!(c.cpu_weight, Some(50), "deprioritized vs growlightd (default 100)");
    }

    #[test]
    fn build_caps_summary_projects_every_knob() {
        let s = BuildCaps::default().summary();
        assert_eq!(s.cargo_build_jobs, Some(2));
        assert_eq!(s.memory_high.as_deref(), Some("3G"));
        assert_eq!(s.cpu_weight, Some(50));
    }

    #[test]
    fn with_update_merges_only_the_set_knobs() {
        // A partial update touches only the named knob; the rest keep their value.
        let base = BuildCaps::default();
        let merged = base
            .with_update(&SetResourcesArgs {
                build_jobs: None,
                memory_high: Some("6G".into()),
                cpu_weight: None,
            })
            .expect("a valid partial update");
        assert_eq!(
            merged,
            BuildCaps {
                cargo_build_jobs: Some(2), // untouched
                memory_high: Some("6G".to_string()), // set
                cpu_weight: Some(50), // untouched
            },
        );

        // An all-None update is an idempotent no-op (returns the caps unchanged).
        assert_eq!(
            base.with_update(&SetResourcesArgs::default()).unwrap(),
            base,
        );

        // Every knob at once.
        let all = base
            .with_update(&SetResourcesArgs {
                build_jobs: Some(4),
                memory_high: Some("5G".into()),
                cpu_weight: Some(80),
            })
            .unwrap();
        assert_eq!(
            all,
            BuildCaps {
                cargo_build_jobs: Some(4),
                memory_high: Some("5G".to_string()),
                cpu_weight: Some(80),
            },
        );
    }

    #[test]
    fn with_update_rejects_out_of_range_soft_values_and_has_no_hard_cap_knob() {
        let base = BuildCaps::default();

        // build_jobs = 0 would stall the build → rejected (not clamped to 1).
        assert!(
            base.with_update(&SetResourcesArgs { build_jobs: Some(0), ..Default::default() })
                .is_err(),
            "a 0 parallel-rustc cap is rejected",
        );

        // build_jobs past the fork-storm ceiling → rejected on the upper end (not
        // clamped down), with a clear message naming the bound (audit slice 006).
        let over = base
            .with_update(&SetResourcesArgs {
                build_jobs: Some(BUILD_JOBS_MAX + 1),
                ..Default::default()
            })
            .expect_err("an over-large build_jobs is rejected");
        assert!(
            over.contains(&BUILD_JOBS_MAX.to_string()),
            "the rejection names the ceiling: {over:?}",
        );
        // Both build_jobs bounds are themselves valid (the floor 1 and the ceiling).
        assert!(base
            .with_update(&SetResourcesArgs { build_jobs: Some(1), ..Default::default() })
            .is_ok());
        assert!(
            base.with_update(&SetResourcesArgs {
                build_jobs: Some(BUILD_JOBS_MAX),
                ..Default::default()
            })
            .is_ok(),
            "the ceiling itself is a valid build_jobs",
        );

        // cpu_weight outside systemd's 1..=10000 → rejected on both ends.
        assert!(base
            .with_update(&SetResourcesArgs { cpu_weight: Some(0), ..Default::default() })
            .is_err());
        assert!(base
            .with_update(&SetResourcesArgs {
                cpu_weight: Some(CPU_WEIGHT_MAX + 1),
                ..Default::default()
            })
            .is_err());
        // The bounds themselves are valid.
        assert!(base
            .with_update(&SetResourcesArgs { cpu_weight: Some(CPU_WEIGHT_MIN), ..Default::default() })
            .is_ok());
        assert!(base
            .with_update(&SetResourcesArgs { cpu_weight: Some(CPU_WEIGHT_MAX), ..Default::default() })
            .is_ok());

        // An empty / whitespace memory_high is rejected (never a silent unset).
        assert!(base
            .with_update(&SetResourcesArgs { memory_high: Some("".into()), ..Default::default() })
            .is_err());
        assert!(base
            .with_update(&SetResourcesArgs { memory_high: Some("  ".into()), ..Default::default() })
            .is_err());

        // Throttle-not-kill is STRUCTURAL: the only memory knob is the SOFT
        // `memory_high` — there is no field through which a `MemoryMax` OOM-kill cap
        // could be requested. A merged caps therefore can only ever slow a build.
        let merged = base
            .with_update(&SetResourcesArgs { memory_high: Some("2G".into()), ..Default::default() })
            .unwrap();
        assert_eq!(merged.memory_high.as_deref(), Some("2G"), "sets MemoryHigh, never MemoryMax");
    }

    #[test]
    fn with_update_validates_the_memory_high_systemd_grammar() {
        // slice 001 (HIGH): a value `with_update` accepts, `systemd-run` must also
        // accept — so a typo can never be stored/persisted/committed nor fail-close a
        // later spawn. The accept/reject set mirrors systemd `parse_size(., 1024)`.
        let base = BuildCaps::default();
        let ok = |v: &str| {
            base.with_update(&SetResourcesArgs { memory_high: Some(v.into()), ..Default::default() })
        };

        for good in ["3G", "512M", "70%", "1500000000", "infinity"] {
            assert!(ok(good).is_ok(), "{good:?} is a valid systemd MemoryHigh value");
        }
        for bad in ["3GB", "banana", "3 G", "", "  "] {
            assert!(ok(bad).is_err(), "{bad:?} is NOT a valid systemd MemoryHigh value");
        }

        // Direct grammar coverage of the edges (chained groups, byte suffix, decimal %).
        assert!(is_valid_memory_high("4G512M"), "systemd sums chained groups");
        assert!(is_valid_memory_high("4096B"), "bare byte suffix is valid");
        assert!(is_valid_memory_high("70%"));
        assert!(is_valid_memory_high("70.5%"), "permyriad decimal percentage");
        assert!(!is_valid_memory_high("3Gi"), "no IEC i-variant in systemd parse_size");
        assert!(!is_valid_memory_high(" 3G"), "no surrounding whitespace");
        assert!(!is_valid_memory_high("3G "), "no trailing whitespace");
        assert!(!is_valid_memory_high("%"), "a bare percent sign is not a percentage");
        assert!(!is_valid_memory_high("G"), "a bare unit is not a value");
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
