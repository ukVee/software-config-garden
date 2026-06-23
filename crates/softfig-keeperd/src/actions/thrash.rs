//! Phase 3 slice 002 — the ping-pong contention detector (spec §4d).
//!
//! A pure, clock-injected state machine fed from the section-edit commit path.
//! When the SAME target (path + optional heading) is edited in a strict
//! A→B→A→B alternation between exactly two editors inside a short window, it
//! has tripped: two agents are fighting over one section, burning budget in a
//! silent loop. The detector turns that into one observable event — the wiring
//! ([`super::sections::note_edit_for_thrash`]) posts a single `coord-request`
//! nudge to the coordination bus ("settle `<target>`") and flags the target
//! for a lease.
//!
//! The lease GRANT and the @human escalation are the *next* rungs of the §4d
//! ladder; they land with the scheduler milestone (phase 4). This module only
//! detects + flags, leaving a clean hook (`lease_flagged` / `clear_flag`).
//!
//! Purity: [`ThrashDetector::record`] takes an injected `now` (Unix seconds) so
//! the whole trip / no-trip / once-per-window / flag-set behaviour is
//! unit-testable with no real clock and no sleeps. A single editor (the default
//! `"anon"` when no per-agent identity is supplied) can never alternate with
//! itself, so the live single-agent loop never trips — only a real multi-agent
//! fleet does.

use std::collections::{HashMap, HashSet};

/// A contention target: a garden-relative path plus an optional heading
/// address. Whole-file edits (no heading) and section edits are tracked
/// separately, mirroring the CAS granularity (spec §5).
pub type Target = (String, Option<String>);

/// Default contention window: edits more than this many seconds apart don't
/// count as the same ping-pong.
const DEFAULT_WINDOW_SECS: i64 = 120;
/// Default nudge cooldown: after a trip, the same target is suppressed for at
/// least this long, so one ping-pong yields one nudge, not a storm.
const DEFAULT_COOLDOWN_SECS: i64 = 120;
/// Minimum alternating edits (A→B→A→B) before a target is considered thrashing.
const MIN_ALTERNATIONS: usize = 4;
/// Upper bound on retained per-target history (a memory cap; window pruning
/// keeps it far smaller in practice).
const MAX_HISTORY: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Edit {
    editor: String,
    at: i64,
}

/// A tripped ping-pong: the wiring renders a single bus nudge from this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trip {
    pub path: String,
    pub heading: Option<String>,
    /// The two contending editors, in first-seen order — for the nudge body
    /// and the future lease arbitration (phase 4).
    pub editors: Vec<String>,
}

impl Trip {
    /// The human-facing target label for a nudge: `path` or `path §heading`.
    pub fn target_label(&self) -> String {
        match &self.heading {
            Some(h) => format!("{} §{}", self.path, h),
            None => self.path.clone(),
        }
    }
}

/// Per-target ping-pong detector. Holds bounded recent edit history, a
/// last-trip stamp for cooldown dedup, and the live lease-flag set.
#[derive(Debug)]
pub struct ThrashDetector {
    window_secs: i64,
    cooldown_secs: i64,
    history: HashMap<Target, Vec<Edit>>,
    last_trip: HashMap<Target, i64>,
    lease_flagged: HashSet<Target>,
}

impl Default for ThrashDetector {
    fn default() -> Self {
        Self::with_params(DEFAULT_WINDOW_SECS, DEFAULT_COOLDOWN_SECS)
    }
}

impl ThrashDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with explicit window/cooldown (the test seam — production uses
    /// [`new`](Self::new)).
    pub fn with_params(window_secs: i64, cooldown_secs: i64) -> Self {
        Self {
            window_secs,
            cooldown_secs,
            history: HashMap::new(),
            last_trip: HashMap::new(),
            lease_flagged: HashSet::new(),
        }
    }

    /// Record one committed edit of `(path, heading)` by `editor` at `now`
    /// (Unix seconds). Returns `Some(Trip)` exactly when this edit completes a
    /// fresh A→B→A→B ping-pong (≥ [`MIN_ALTERNATIONS`] strictly-alternating
    /// edits between exactly two editors, all within the window) AND the target
    /// is past its post-trip cooldown. A trip sets the lease flag.
    pub fn record(
        &mut self,
        path: &str,
        heading: Option<&str>,
        editor: &str,
        now: i64,
    ) -> Option<Trip> {
        let target: Target = (path.to_string(), heading.map(str::to_string));

        let hist = self.history.entry(target.clone()).or_default();
        hist.push(Edit { editor: editor.to_string(), at: now });
        // Window prune (drop edits older than the window), then memory cap.
        let cutoff = now - self.window_secs;
        hist.retain(|e| e.at >= cutoff);
        if hist.len() > MAX_HISTORY {
            let drop = hist.len() - MAX_HISTORY;
            hist.drain(0..drop);
        }
        let editors = alternating_pair(hist)?;

        // Dedup: one nudge per cooldown per target. The flag persists; only the
        // nudge is rate-limited.
        if let Some(&last) = self.last_trip.get(&target) {
            if now - last < self.cooldown_secs {
                return None;
            }
        }
        self.last_trip.insert(target.clone(), now);
        self.lease_flagged.insert(target);

        Some(Trip {
            path: path.to_string(),
            heading: heading.map(str::to_string),
            editors,
        })
    }

    /// Whether `(path, heading)` is currently flagged for a lease (set on trip,
    /// cleared by the scheduler when it grants/arbitrates — phase 4).
    pub fn is_lease_flagged(&self, path: &str, heading: Option<&str>) -> bool {
        self.lease_flagged
            .contains(&(path.to_string(), heading.map(str::to_string)))
    }

    /// The set of targets currently flagged for a lease.
    pub fn lease_flagged(&self) -> impl Iterator<Item = &Target> {
        self.lease_flagged.iter()
    }

    /// Clear a target's lease flag (the phase-4 hook: a granted/arbitrated
    /// lease resolves the contention). Returns whether a flag was present.
    pub fn clear_flag(&mut self, path: &str, heading: Option<&str>) -> bool {
        self.lease_flagged
            .remove(&(path.to_string(), heading.map(str::to_string)))
    }
}

/// If the suffix of `hist` ending at the last edit is a strict alternation
/// (consecutive editors always differ) of length ≥ [`MIN_ALTERNATIONS`] using
/// exactly two distinct editors, return those two editors in first-seen order.
/// Otherwise `None`. A run of one editor (no alternation) and a 3+-way round
/// robin (alternation but >2 editors) both fail — only a genuine two-party
/// ping-pong trips.
fn alternating_pair(hist: &[Edit]) -> Option<Vec<String>> {
    if hist.len() < MIN_ALTERNATIONS {
        return None;
    }
    // Walk back from the end while consecutive editors differ.
    let mut start = hist.len() - 1;
    while start > 0 && hist[start - 1].editor != hist[start].editor {
        start -= 1;
    }
    let suffix = &hist[start..];
    if suffix.len() < MIN_ALTERNATIONS {
        return None;
    }
    let mut order: Vec<String> = Vec::new();
    for e in suffix {
        if !order.contains(&e.editor) {
            order.push(e.editor.clone());
        }
    }
    (order.len() == 2).then_some(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "doc.md";
    const SEC: Option<&str> = Some("Layout");

    /// A→B→A→B on one section within the window trips exactly on the 4th edit,
    /// reporting both editors and the target.
    #[test]
    fn trips_on_a_b_a_b_within_window() {
        let mut d = ThrashDetector::with_params(100, 100);
        assert!(d.record(DOC, SEC, "a", 0).is_none());
        assert!(d.record(DOC, SEC, "b", 1).is_none());
        assert!(d.record(DOC, SEC, "a", 2).is_none());
        let trip = d.record(DOC, SEC, "b", 3).expect("4th edit trips");
        assert_eq!(trip.path, DOC);
        assert_eq!(trip.heading.as_deref(), SEC);
        assert_eq!(trip.editors, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(trip.target_label(), "doc.md §Layout");
    }

    /// A single editor (the `"anon"` default) can never alternate with itself.
    #[test]
    fn never_trips_for_a_single_editor() {
        let mut d = ThrashDetector::with_params(100, 100);
        for t in 0..6 {
            assert!(d.record(DOC, SEC, "anon", t).is_none(), "edit {t}");
        }
        assert!(!d.is_lease_flagged(DOC, SEC));
    }

    /// A 3-way round robin alternates but uses >2 editors — not a ping-pong.
    #[test]
    fn never_trips_for_a_three_way_round_robin() {
        let mut d = ThrashDetector::with_params(100, 100);
        let seq = ["a", "b", "c", "a", "b", "c"];
        for (t, e) in seq.iter().enumerate() {
            assert!(d.record(DOC, SEC, e, t as i64).is_none(), "edit {t}");
        }
    }

    /// Edits spread wider than the window never accumulate ≥4 in-window, so
    /// they never trip even though they alternate.
    #[test]
    fn never_trips_when_spread_beyond_window() {
        let mut d = ThrashDetector::with_params(50, 50);
        // 100s apart with a 50s window → at most one prior edit survives.
        assert!(d.record(DOC, SEC, "a", 0).is_none());
        assert!(d.record(DOC, SEC, "b", 100).is_none());
        assert!(d.record(DOC, SEC, "a", 200).is_none());
        assert!(d.record(DOC, SEC, "b", 300).is_none());
    }

    /// One nudge per cooldown: alternation continuing inside the cooldown is
    /// suppressed; past it, the same target trips again.
    #[test]
    fn nudges_once_per_cooldown_window() {
        let mut d = ThrashDetector::with_params(1000, 100);
        assert!(d.record(DOC, SEC, "a", 0).is_none());
        assert!(d.record(DOC, SEC, "b", 1).is_none());
        assert!(d.record(DOC, SEC, "a", 2).is_none());
        assert!(d.record(DOC, SEC, "b", 3).is_some(), "first trip");
        // Still alternating, but inside the 100s cooldown → suppressed.
        assert!(d.record(DOC, SEC, "a", 4).is_none());
        assert!(d.record(DOC, SEC, "b", 5).is_none());
        // Past the cooldown, still thrashing → trips again.
        assert!(d.record(DOC, SEC, "a", 200).is_some(), "second trip");
    }

    /// A trip flags the target for a lease; a clean target isn't flagged; the
    /// phase-4 hook clears it.
    #[test]
    fn trip_sets_then_clears_the_lease_flag() {
        let mut d = ThrashDetector::with_params(100, 100);
        d.record(DOC, SEC, "a", 0);
        d.record(DOC, SEC, "b", 1);
        d.record(DOC, SEC, "a", 2);
        assert!(!d.is_lease_flagged(DOC, SEC), "not yet tripped");
        d.record(DOC, SEC, "b", 3);
        assert!(d.is_lease_flagged(DOC, SEC));
        assert!(!d.is_lease_flagged("other.md", SEC));
        assert_eq!(d.lease_flagged().count(), 1);
        assert!(d.clear_flag(DOC, SEC));
        assert!(!d.is_lease_flagged(DOC, SEC));
        assert!(!d.clear_flag(DOC, SEC), "already cleared");
    }

    /// Two different targets keep independent history — interleaving A/B across
    /// two sections trips neither (each sees only 2 same-target edits).
    #[test]
    fn distinct_targets_do_not_share_history() {
        let mut d = ThrashDetector::with_params(100, 100);
        let one = Some("One");
        let two = Some("Two");
        assert!(d.record(DOC, one, "a", 0).is_none());
        assert!(d.record(DOC, two, "b", 1).is_none());
        assert!(d.record(DOC, one, "b", 2).is_none());
        assert!(d.record(DOC, two, "a", 3).is_none());
        assert!(d.record(DOC, one, "a", 4).is_none());
        assert!(d.record(DOC, two, "b", 5).is_none());
        // Each target has only 3 edits and they don't form a 4-long alternation.
        assert!(!d.is_lease_flagged(DOC, one));
        assert!(!d.is_lease_flagged(DOC, two));
    }

    /// A whole-file target (no heading) and a section target on the same path
    /// are distinct keys.
    #[test]
    fn whole_file_and_section_targets_are_distinct() {
        let mut d = ThrashDetector::with_params(100, 100);
        for (t, e) in ["a", "b", "a", "b"].iter().enumerate() {
            d.record(DOC, None, e, t as i64);
        }
        assert!(d.is_lease_flagged(DOC, None));
        assert!(!d.is_lease_flagged(DOC, SEC));
    }
}
