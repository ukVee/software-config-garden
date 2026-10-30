//! Per-profile budget headroom for the claude-login budget-aware picker
//! (`claude-login-switcher` slice 004).
//!
//! Each claude-login profile slot keeps its own rolling budget sample at
//!
//! ```text
//! $XDG_CONFIG_HOME/softfig/growlight/usage.by-profile/<slot>.json
//! ```
//!
//! written by the per-member tee in [`crate::claude_backend`] when a
//! `rate_limit_event` arrives on a spawn pinned to `<slot>`. The shape is the
//! same [`UsageSnapshot`] the shared account-wide `usage.json` uses — the file
//! IS a per-slot reading of a per-slot pool, carrying the slot name in its
//! `profile` field — so no new wire type is introduced and a reader built for
//! `usage.json` reads one of these without ceremony.
//!
//! Scope and non-scope:
//!
//! - The **reader** is pure: it takes an optional snapshot and a clock and
//!   returns a [`Headroom`]. Every pick-time decision reduces to a sort over
//!   these pairs. [`headroom_from`] is unit-proven here so the picker's
//!   branches ([`crate::profile_pin::pick_with_budget`]) are plain
//!   assertions.
//! - The **staleness floor** is [`STALE_FLOOR_SECS`] = one 5h window plus a
//!   little slack. A reading older than that is treated as "fresh (unused)",
//!   not "stall": a profile that has been quiet long enough for its own window
//!   to turn over twice has demonstrably not been pinning the budget, and the
//!   alternative — stalling on a stale sample — is exactly the fossil hazard
//!   task 048 removed from the shared file.
//! - The **writer** is not here; it lives next to the shared tee in
//!   [`crate::usage_file::UsageCapture`], which writes both files from the
//!   same per-line observer so a stream-json fold cannot land in one file and
//!   miss the other.

use std::path::{Path, PathBuf};

use softfig_ipc::usage::{RateWindow, UsageSnapshot};

/// How old a per-profile reading may be before the picker treats it as a
/// fresh/unused pool rather than a stall. Six hours = one 5h window plus
/// slack, so a profile idle long enough for its own window to roll over
/// twice is not penalised by a fossil sample.
///
/// The alternative is risking a stall on a profile that genuinely has budget
/// (slice 004 "window freshness" rule); we trade a mis-call toward usage, not
/// toward refusal.
pub const STALE_FLOOR_SECS: i64 = 6 * 3_600;

/// One profile's budget-pool headroom at a moment in time.
///
/// `pct` is `0..=100`, where `100` means "full headroom" (fresh / unused /
/// stale / window demonstrably reset by `now`), `0` means a `rejected` status
/// whose window has not yet reset. `resets_at` is the 5h window boundary the
/// reading reported, when known — the earliest moment a stall may re-probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headroom {
    /// Remaining 5h headroom as a percentage, `0..=100`.
    pub pct: u8,
    /// The 5h `resetsAt` behind the reading, unix seconds — `None` when the
    /// reading omitted it (headless readings normally carry it; a stale or
    /// never-written sample does not).
    pub resets_at: Option<i64>,
}

impl Headroom {
    /// A profile with no reading on record, or one whose reading has demonstrably
    /// turned over — the pick-friendly "unknown is full" case.
    pub const fn full() -> Self {
        Self {
            pct: 100,
            resets_at: None,
        }
    }
}

/// The on-disk path for `<slot>`'s per-profile budget file under
/// `by_profile_dir`. Pure, no I/O. The filename is just the slot stem +
/// `.json`, matching the human-facing form `usage.by-profile/slot1.json`.
pub fn profile_budget_path(by_profile_dir: &Path, slot: &str) -> PathBuf {
    by_profile_dir.join(format!("{slot}.json"))
}

/// Headroom from one reading at `now` (unix seconds). Pure.
///
/// Combines **both** the 5h and 7d windows (slice 009 S2): a slot's headroom is
/// `min(5h, 7d)` and the hold's `resets_at` is the binding window's. A
/// weekly-exhausted slot therefore reads as 0 and is never picked, and its hold
/// waits for the 7d reopen, not the 5h one.
///
/// Priority:
/// 1. No reading ⇒ [`Headroom::full`] (never used, so no case to deny).
/// 2. Reading older than [`STALE_FLOOR_SECS`] ⇒ full. The sample is a fossil;
///    treating it as "unknown-but-unused" avoids stalling on days-old data
///    (the task-048 fossil hazard, now per-profile).
/// 3. For each window: a demonstrably-reset window
///    ([`softfig_ipc::usage::RateWindow::window_reset_by`]) folds to full for
///    that window. Then take the min of the two.
///
/// Within one window ([`window_headroom`]):
/// - A vouchable percentage ([`softfig_ipc::usage::RateWindow::vouchable_pct_at`])
///   yields `100 - used`. Interactive statuslines write a percentage; this is
///   the high-fidelity path when it is available.
/// - The coarse per-window `status` string (slice 009 S1 — real wire form):
///   `"allowed"` ⇒ full, `"rejected"` ⇒ `0`, anything else (including the real
///   wire form `"allowed_warning"`, confirmed in `auto-run.log`) ⇒ `5` (below
///   the warn threshold but above stall). The headless `rate_limit_event` wire
///   carries only this coarse label (no percentage), so it is the realistic
///   headroom source for the fleet path.
/// - **Take the smaller** when both a vouchable pct and a non-`allowed` status
///   are present (slice 009 S1). The invariants under this rule: a vouchable
///   pct never overrules a `rejected` wire status, and `allowed` plus a pct
///   degrades gracefully to the pct.
pub fn headroom_from(snapshot: Option<&UsageSnapshot>, now: i64) -> Headroom {
    let Some(snap) = snapshot else {
        return Headroom::full();
    };
    let sample_ts = snap.ts as i64;
    let age = now.saturating_sub(sample_ts);
    if age > STALE_FLOOR_SECS {
        return Headroom::full();
    }
    let five = window_headroom(&snap.rate_limits.five_hour, now);
    let seven = window_headroom(&snap.rate_limits.seven_day, now);
    binding_headroom(five, seven)
}

/// Per-window headroom with the S1 take-smaller rule applied. A window whose
/// own boundary has passed folds to full (its reading describes a window that
/// no longer exists).
fn window_headroom(w: &RateWindow, now: i64) -> Headroom {
    if w.window_reset_by(now) {
        return Headroom::full();
    }
    let pct_from_pct = w
        .vouchable_pct_at(now)
        .map(|used| 100_u8.saturating_sub(used.min(100)));
    // Slice 009 S1: real wire strings. Any status other than `allowed` is low
    // (the real wire form is `allowed_warning`, not the invented `warning`); the
    // headless `rate_limit_event` wire carries this label with no percentage.
    let pct_from_status = w.status.as_deref().map(|s| match s {
        "allowed" => 100_u8,
        "rejected" => 0,
        // `allowed_warning` and any future low-but-not-rejected label.
        _ => 5,
    });
    // Take the smaller when both are present — `rejected` must always bind,
    // and `allowed` + a pct must degrade to the pct, not to full.
    let pct = match (pct_from_pct, pct_from_status) {
        (Some(a), Some(b)) => a.min(b),
        (Some(p), None) | (None, Some(p)) => p,
        (None, None) => 100,
    };
    Headroom {
        pct,
        resets_at: w.resets_at,
    }
}

/// Combine the 5h and 7d headrooms into one binding reading (slice 009 S2).
///
/// The binding window is the one with lower `pct` — that is the window that
/// denies. On a tie, use the later `resets_at`: when both are exhausted the
/// slot stays denied until BOTH reopen, and when both are healthy the exact
/// value does not matter for admission. A `None`/`Some` tie falls through to
/// the known boundary.
fn binding_headroom(five: Headroom, seven: Headroom) -> Headroom {
    use std::cmp::Ordering;
    match five.pct.cmp(&seven.pct) {
        Ordering::Less => five,
        Ordering::Greater => seven,
        Ordering::Equal => Headroom {
            pct: five.pct,
            resets_at: match (five.resets_at, seven.resets_at) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
        },
    }
}

/// Read `<slot>`'s per-profile budget file under `by_profile_dir`, or `None`
/// when it does not exist / is malformed. A corrupt file reads as `None`:
/// callers that use this directly (the human-facing CLI listing) treat it as
/// "never-written". The admission path reads through [`slot_headroom`]
/// instead, which fails closed on a torn file.
pub fn read_profile_budget(by_profile_dir: &Path, slot: &str) -> Option<UsageSnapshot> {
    UsageSnapshot::load(&profile_budget_path(by_profile_dir, slot))
        .ok()
        .flatten()
}

/// Headroom for one slot's on-disk file, failing closed on a torn or
/// unreadable file (claude-login-switcher slice 009 S7). The three cases:
/// - **Absent** (file does not exist) ⇒ [`Headroom::full`]. Nothing to deny.
/// - **Loaded** ⇒ [`headroom_from`] of the parsed reading.
/// - **Unreadable** (parse error, or I/O other than `NotFound`) ⇒ one short
///   retry (a reader may have observed a half-written moment between a
///   writer's `write` and `rename`), then warn tier
///   `Headroom { pct: 5, resets_at: None }`. Never full — a slot whose file
///   is unreadable at pick time must not be preferred over one that is.
///
/// The retry is a single immediate re-read. The underlying `write_atomic` is
/// a rename, so a reader never observes a torn file in the middle of ONE
/// write — but [`UsageSnapshot::load`] does its own re-open and the file can
/// change between the two syscalls, which is what the retry covers.
pub fn slot_headroom(by_profile_dir: &Path, slot: &str, now: i64) -> Headroom {
    let path = profile_budget_path(by_profile_dir, slot);
    for _ in 0..2 {
        match UsageSnapshot::load(&path) {
            Ok(Some(snap)) => return headroom_from(Some(&snap), now),
            Ok(None) => return Headroom::full(),
            Err(_) => continue,
        }
    }
    Headroom {
        pct: 5,
        resets_at: None,
    }
}

/// Snapshot every slot in `pool` to `(slot, headroom)` pairs, in pool order.
/// One disk read per slot (file sizes are small, a few hundred bytes); called
/// once per spawn pick and once per status render. A torn file lands in the
/// warn tier via [`slot_headroom`], never as full headroom.
pub fn pool_headroom(by_profile_dir: &Path, pool: &[String], now: i64) -> Vec<(String, Headroom)> {
    pool.iter()
        .map(|slot| (slot.clone(), slot_headroom(by_profile_dir, slot, now)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::usage::{RateLimits, RateWindow, UsageSnapshot};

    fn snap(five: RateWindow, seven: RateWindow, ts: i64) -> UsageSnapshot {
        UsageSnapshot {
            context_window: None,
            rate_limits: RateLimits {
                five_hour: five,
                seven_day: seven,
            },
            ts: ts as f64,
            profile: None,
        }
    }

    fn rw_status(status: &str, resets_at: i64) -> RateWindow {
        RateWindow {
            used_percentage: None,
            resets_at: Some(resets_at),
            status: Some(status.to_string()),
        }
    }

    fn rw_pct(used: u8, status: &str, resets_at: i64) -> RateWindow {
        RateWindow {
            used_percentage: Some(used),
            resets_at: Some(resets_at),
            status: Some(status.to_string()),
        }
    }

    #[test]
    fn no_reading_is_full_headroom() {
        assert_eq!(headroom_from(None, 1_000), Headroom::full());
    }

    #[test]
    fn stale_reading_past_six_hours_folds_to_full() {
        // Sample at ts=0, picker running at ts=STALE_FLOOR+1 ⇒ fossil
        // (slice 004 "window freshness" rule — six hours is enough slack for
        // the window to have turned over, so the sample tells us nothing).
        let s = snap(rw_status("rejected", 60), RateWindow::default(), 0);
        assert_eq!(headroom_from(Some(&s), STALE_FLOOR_SECS + 1), Headroom::full());
    }

    #[test]
    fn five_hour_window_already_reset_folds_to_full() {
        // A reading younger than six hours but whose own boundary has passed:
        // the window it describes no longer exists.
        let s = snap(rw_status("rejected", 500), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 600);
        assert_eq!(hr, Headroom::full());
    }

    #[test]
    fn vouchable_percentage_wins_over_coarse_status() {
        // 73% used + still-live window ⇒ 27% headroom; status label ignored
        // when a vouchable number is in hand (the interactive-statusline path).
        let s = snap(rw_pct(73, "allowed", 2_000), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 27);
        assert_eq!(hr.resets_at, Some(2_000));
    }

    #[test]
    fn coarse_rejected_maps_to_zero_headroom() {
        // No vouchable percentage (the headless wire), status=rejected, window
        // still ahead ⇒ 0 headroom + the reset time pinned.
        let s = snap(rw_status("rejected", 2_000), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 0);
        assert_eq!(hr.resets_at, Some(2_000));
    }

    #[test]
    fn coarse_allowed_warning_maps_to_warn_tier() {
        // Slice 009 S1: `allowed_warning` is the real wire string
        // (3× in `auto-run.log`); the pre-slice-009 code matched an invented
        // `"warning"` and read every real reading as `allowed` ⇒ 100.
        let s = snap(rw_status("allowed_warning", 2_000), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 500);
        // Below the 10% warn threshold, above the 2% stall floor — pickable
        // but logged.
        assert_eq!(hr.pct, 5);
    }

    #[test]
    fn coarse_allowed_is_full_headroom() {
        let s = snap(rw_status("allowed", 2_000), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 100);
    }

    #[test]
    fn status_and_pct_take_the_smaller() {
        // Slice 009 S1: a vouchable pct does NOT overrule a `rejected` status.
        // 90% used would give 10 headroom, but the wire said rejected ⇒ 0 binds.
        let s = snap(rw_pct(90, "rejected", 2_000), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 0);
        assert_eq!(hr.resets_at, Some(2_000));
    }

    #[test]
    fn status_allowed_degrades_to_the_pct() {
        // `allowed` + 73% used ⇒ 27 headroom (pct wins because status is full).
        // This is the test the pre-slice-009 code happened to pass under the
        // old "vouchable-pct wins" rule; the new min-rule reduces to the same.
        let s = snap(rw_pct(73, "allowed", 2_000), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 27);
    }

    // ---- Slice 009 S2: the 7d window ---------------------------------------

    #[test]
    fn seven_day_rejected_binds_hold_even_when_five_hour_is_healthy() {
        // The headline S2 case: 5h is allowed, 7d is rejected. The slot is not
        // pickable, and the hold's `resets_at` is the 7d one (90_000), not the
        // 5h one (2_000) — hold until the binding window reopens.
        let s = snap(
            rw_status("allowed", 2_000),
            rw_status("rejected", 90_000),
            100,
        );
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 0, "weekly-exhausted ⇒ not pickable");
        assert_eq!(
            hr.resets_at,
            Some(90_000),
            "hold waits for the 7d reopen (binding window)",
        );
    }

    #[test]
    fn headroom_is_the_min_of_the_two_windows() {
        // 5h at 20 headroom (80 used), 7d at 60 headroom (40 used) ⇒ 20 wins
        // and the 5h boundary binds.
        let s = snap(rw_pct(80, "allowed", 2_000), rw_pct(40, "allowed", 90_000), 100);
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 20);
        assert_eq!(hr.resets_at, Some(2_000));
    }

    #[test]
    fn both_windows_rejected_pins_to_the_later_reopen() {
        // On a tie the hold must wait for BOTH windows to reopen — picking the
        // earlier `resets_at` would re-roll onto a still-rejected 7d and park
        // again. Max wins.
        let s = snap(
            rw_status("rejected", 2_000),
            rw_status("rejected", 90_000),
            100,
        );
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 0);
        assert_eq!(hr.resets_at, Some(90_000));
    }

    #[test]
    fn seven_day_window_already_reset_folds_to_full_within_the_fold() {
        // 5h at 10 headroom (90 used, status rejected), 7d demonstrably reset.
        // The 7d window describes a reset-by-now window, so it folds to full
        // and the 5h binds — 10 headroom, 5h resets_at.
        let s = snap(
            rw_pct(90, "rejected", 2_000),
            rw_status("rejected", 50), // boundary at 50 ≤ now 500 ⇒ reset
            100,
        );
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 0, "5h rejected still binds (status takes smaller)");
        assert_eq!(hr.resets_at, Some(2_000));
    }

    #[test]
    fn no_seven_day_info_does_not_falsely_deny() {
        // A reading with only 5h info (default 7d) ⇒ 7d reads as full and the
        // 5h binds. Protects against a false-deny when a reader has not yet
        // observed a 7d event.
        let s = snap(rw_status("allowed", 2_000), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 500);
        assert_eq!(hr.pct, 100);
    }

    #[test]
    fn pool_headroom_reads_each_slot_in_pool_order() {
        let dir = tempfile::tempdir().unwrap();
        // slot1 => rejected, slot2 => allowed, slot3 => nothing on disk
        snap(rw_status("rejected", 9_999), RateWindow::default(), 500)
            .write_atomic(&profile_budget_path(dir.path(), "slot1"))
            .unwrap();
        snap(rw_status("allowed", 9_999), RateWindow::default(), 500)
            .write_atomic(&profile_budget_path(dir.path(), "slot2"))
            .unwrap();

        let pool = vec!["slot1".to_string(), "slot2".into(), "slot3".into()];
        let got = pool_headroom(dir.path(), &pool, 600);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, "slot1");
        assert_eq!(got[0].1.pct, 0);
        assert_eq!(got[1].0, "slot2");
        assert_eq!(got[1].1.pct, 100);
        assert_eq!(got[2].0, "slot3");
        assert_eq!(got[2].1, Headroom::full(), "a missing file reads as full");
    }

    #[test]
    fn profile_budget_path_names_the_file_as_slot_json() {
        let p = profile_budget_path(Path::new("/x"), "slot1");
        assert_eq!(p, PathBuf::from("/x/slot1.json"));
    }

    /// Slice 009 S7: a torn or otherwise unreadable file lands in the warn
    /// tier — never full headroom — so the picker cannot prefer a slot whose
    /// file it can't read over one it can.
    #[test]
    fn a_torn_read_lands_in_the_warn_tier_not_full_headroom() {
        let dir = tempfile::tempdir().unwrap();
        let path = profile_budget_path(dir.path(), "slot1");
        std::fs::write(&path, "{this is not json").unwrap();

        let hr = slot_headroom(dir.path(), "slot1", 500);
        assert_eq!(hr.pct, 5, "torn file reads as warn tier");
        assert_eq!(hr.resets_at, None);
    }

    #[test]
    fn an_absent_file_still_reads_as_full_headroom() {
        // Explicit regression guard: the S7 flip must not deny a never-written
        // slot. Only an *unreadable* file is a signal; an absent one is nothing.
        let dir = tempfile::tempdir().unwrap();
        let hr = slot_headroom(dir.path(), "slot-never-written", 500);
        assert_eq!(hr, Headroom::full());
    }
}
