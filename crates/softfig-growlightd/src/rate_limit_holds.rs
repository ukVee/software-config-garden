//! Per-profile rate-limit admission holds (claude-login-switcher slice 008) —
//! the drive-loop state that gates fresh starts and re-rolls against each
//! claude-login slot's `resetsAt`, so a `rejected` on one account never halts a
//! co-member running on a different account (review 047 B3).
//!
//! ## What this is (and isn't)
//!
//! A **pure value model**: a tiny `BTreeMap<ProfileKey, i64>` with an `extend`
//! policy (never shortens an existing hold — the LATER of the two boundaries
//! wins, so a window extended by a stdout stream error does not get wiped by a
//! smaller step-0 `rate_limit_event`) and an elapse pass. No clock, no I/O; the
//! drive loop passes the tick's `now`.
//!
//! Before slice 008 this was a single `Option<i64>` keyed on the fleet
//! (`DriveLoop::rate_limit_hold_until`). Any member's `rejected` halted every
//! member — the exact failure the switcher exists to remove once two accounts
//! are configured.
//!
//! Opencode members have no profile; they carry no hold here (opencode's own
//! provider gating is a separate path).

use std::collections::BTreeMap;

/// A profile the hold is keyed on — the claude-login slot name (or `home`) a
/// member's reading was taken against. Opencode members never contribute a hold;
/// they are not reached through this map.
pub type ProfileKey = String;

/// Per-profile admission holds — one `resets_at` instant per claude-login slot.
///
/// Set from a reporting member's `reading_profile` on a `rejected`
/// `rate_limit_event` (step 0) or on a rate-limit death whose stdout stream
/// carried a `resets_at` (health pass, task 070). Cleared independently per
/// profile once `now >= hold` — the fleet auto-resumes on the slot's own window
/// reset, with no human bounce (the deleted `--auto` governor's timed-resume,
/// task 037, now per-profile).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RateLimitHolds {
    /// `slot name` → the unix-seconds instant admission may re-probe that slot.
    /// Absence = no hold on that slot.
    holds: BTreeMap<ProfileKey, i64>,
}

impl RateLimitHolds {
    /// A fresh map with no holds — the pre-rate-limit posture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Extend `profile`'s hold to `until` **monotonically**: a new boundary is
    /// taken only when it is strictly LATER than any existing hold on the same
    /// slot. The reason is identical to the pre-slice-008 scalar's rule — a
    /// later window boundary must win so admission reopens only once every
    /// tripped window has, and a smaller late-arriving `resets_at` must never
    /// wipe a longer hold. Returns `true` if the stored value changed.
    pub fn extend(&mut self, profile: impl Into<ProfileKey>, until: i64) -> bool {
        let profile = profile.into();
        match self.holds.get(&profile).copied() {
            Some(existing) if existing >= until => false,
            _ => {
                self.holds.insert(profile, until);
                true
            }
        }
    }

    /// Drop every hold whose `resets_at` is `<= now`. Called each tick after
    /// setting the hold, so an elapsed window reopens on the same tick its
    /// `resets_at` passes — no spin, no waiting a cycle.
    pub fn clear_elapsed(&mut self, now: i64) {
        self.holds.retain(|_, until| *until > now);
    }

    /// Whether this profile is currently held. Opencode members never pass a
    /// profile here — they go through a different gating path.
    pub fn is_held(&self, profile: &str) -> bool {
        self.holds.contains_key(profile)
    }

    /// The `resets_at` admission may re-probe `profile` at, or `None` when it
    /// is not held. The number is the same monotonically-maximised value
    /// `extend` recorded; a probe before this `now` is held.
    pub fn held_until(&self, profile: &str) -> Option<i64> {
        self.holds.get(profile).copied()
    }

    /// Whether a claude member whose `admission_profiles` is `profiles` is
    /// currently held — true iff **every** profile the member could spawn on is
    /// held. An empty `profiles` is never held (no slots means nothing to hold:
    /// opencode's path, or a claude member whose seam gave no profiles, both
    /// defer to the broader admission gates).
    pub fn member_fully_held(&self, profiles: &[String]) -> bool {
        !profiles.is_empty() && profiles.iter().all(|p| self.is_held(p))
    }

    /// The earliest held boundary across every slot, or `None` when nothing is
    /// held — the single value `report.waiting_for_rate_limit_reset` renders
    /// for status. The choice is deliberate (slice 008): a per-profile list on
    /// the status wire would churn the surface for an edge-case that none of
    /// its readers consume, while a single "earliest held" matches the status
    /// bar's "when does admission reopen next?" question and reduces to the
    /// pre-switcher scalar when only one profile is held at a time (the common
    /// case for a single-account fleet).
    pub fn earliest(&self) -> Option<i64> {
        self.holds.values().copied().min()
    }

    /// Whether any slot is currently held — the backward-compat test the
    /// drive-loop `rate_limited` short-circuit used before slice 008. A caller
    /// that wants per-member gating uses [`member_fully_held`] instead.
    pub fn any_held(&self) -> bool {
        !self.holds.is_empty()
    }

    /// Every held slot (sorted) — status surfaces that render the per-profile
    /// detail (slice 010 runbook) read this.
    pub fn iter(&self) -> impl Iterator<Item = (&str, i64)> {
        self.holds.iter().map(|(k, v)| (k.as_str(), *v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_map_holds_nothing() {
        let h = RateLimitHolds::new();
        assert!(!h.any_held());
        assert_eq!(h.earliest(), None);
        assert_eq!(h.held_until("slot1"), None);
        assert!(!h.is_held("slot1"));
        assert!(!h.member_fully_held(&[]));
        assert!(!h.member_fully_held(&["slot1".into()]));
    }

    #[test]
    fn extend_is_monotonic_and_never_shortens() {
        let mut h = RateLimitHolds::new();
        assert!(h.extend("slot1", 1_000));
        assert_eq!(h.held_until("slot1"), Some(1_000));
        // A later boundary wins — the slot's window must reopen only at the
        // LATER instant.
        assert!(h.extend("slot1", 1_200));
        assert_eq!(h.held_until("slot1"), Some(1_200));
        // A smaller late-arriving boundary is a no-op; the hold is preserved.
        assert!(!h.extend("slot1", 500));
        assert_eq!(h.held_until("slot1"), Some(1_200));
        // An equal re-report is also a no-op (deterministic).
        assert!(!h.extend("slot1", 1_200));
    }

    #[test]
    fn holds_are_independent_per_profile() {
        let mut h = RateLimitHolds::new();
        h.extend("slot1", 1_000);
        h.extend("slot2", 2_000);
        assert_eq!(h.held_until("slot1"), Some(1_000));
        assert_eq!(h.held_until("slot2"), Some(2_000));
        assert_eq!(h.earliest(), Some(1_000));
        assert!(h.is_held("slot1"));
        assert!(h.is_held("slot2"));
        assert!(!h.is_held("home"));
    }

    #[test]
    fn clear_elapsed_drops_only_passed_holds() {
        let mut h = RateLimitHolds::new();
        h.extend("slot1", 1_000);
        h.extend("slot2", 2_000);
        h.clear_elapsed(999);
        assert!(h.is_held("slot1") && h.is_held("slot2"), "nothing elapses before 1000");
        // 1_000 has passed (inclusive — same as the scalar's `now >= until`).
        h.clear_elapsed(1_000);
        assert!(!h.is_held("slot1"));
        assert!(h.is_held("slot2"));
        assert_eq!(h.earliest(), Some(2_000));
        h.clear_elapsed(2_000);
        assert!(!h.any_held());
    }

    #[test]
    fn member_fully_held_requires_every_pool_slot() {
        let mut h = RateLimitHolds::new();
        h.extend("slot1", 1_000);
        // A pooled member on [slot1, slot2] is NOT fully held: slot2 is free.
        let pool = vec!["slot1".to_string(), "slot2".to_string()];
        assert!(!h.member_fully_held(&pool));
        // Hold slot2 too — now every slot is held.
        h.extend("slot2", 1_500);
        assert!(h.member_fully_held(&pool));
        // An unpooled member on [slot1] alone is fully held.
        assert!(h.member_fully_held(&["slot1".to_string()]));
        // An opencode-style empty admission set is never held here.
        assert!(!h.member_fully_held(&[]));
    }

    #[test]
    fn no_pools_anywhere_matches_the_old_global_hold() {
        // Back-compat guard: with a single implicit profile (`home`), the
        // per-profile map behaves exactly like the pre-slice-008 scalar.
        let mut h = RateLimitHolds::new();
        h.extend("home", 1_000);
        assert!(h.any_held());
        assert_eq!(h.earliest(), Some(1_000));
        let pool = vec!["home".to_string()];
        assert!(h.member_fully_held(&pool));
        h.clear_elapsed(1_000);
        assert!(!h.any_held());
    }
}
