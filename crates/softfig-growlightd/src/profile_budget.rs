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

use softfig_ipc::usage::UsageSnapshot;

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
/// Priority:
/// 1. No reading ⇒ [`Headroom::full`] (never used, so no case to deny).
/// 2. Reading older than [`STALE_FLOOR_SECS`] ⇒ full. The sample is a fossil;
///    treating it as "unknown-but-unused" avoids stalling on days-old data
///    (the task-048 fossil hazard, now per-profile).
/// 3. The 5h window has demonstrably reset by `now`
///    ([`softfig_ipc::usage::RateWindow::window_reset_by`]) ⇒ full. A reading
///    older than its own boundary describes a window that no longer exists.
/// 4. A vouchable percentage ([`softfig_ipc::usage::RateWindow::vouchable_pct_at`])
///    ⇒ `100 - used`. Interactive statuslines write a percentage; this is the
///    high-fidelity path when it is available.
/// 5. The coarse per-window `status` string: `"allowed"` ⇒ full,
///    `"warning"` ⇒ `5%` (below the warn threshold but above stall), `"rejected"`
///    ⇒ `0%`. The headless `rate_limit_event` wire carries only this coarse
///    label (no percentage), so it is the realistic headroom source for the
///    fleet path.
pub fn headroom_from(snapshot: Option<&UsageSnapshot>, now: i64) -> Headroom {
    let Some(snap) = snapshot else {
        return Headroom::full();
    };
    let sample_ts = snap.ts as i64;
    let age = now.saturating_sub(sample_ts);
    if age > STALE_FLOOR_SECS {
        return Headroom::full();
    }
    let w = &snap.rate_limits.five_hour;
    if w.window_reset_by(now) {
        return Headroom::full();
    }
    if let Some(used) = w.vouchable_pct_at(now) {
        let pct = 100_u8.saturating_sub(used.min(100));
        return Headroom {
            pct,
            resets_at: w.resets_at,
        };
    }
    let pct = match w.status.as_deref() {
        Some("rejected") => 0,
        Some("warning") => 5,
        _ => 100,
    };
    Headroom {
        pct,
        resets_at: w.resets_at,
    }
}

/// Read `<slot>`'s per-profile budget file under `by_profile_dir`, or `None`
/// when it does not exist / is malformed. A corrupt file reads as `None`:
/// the picker then treats the slot as [`Headroom::full`], which matches the
/// writer's own policy of preferring usage over refusal on a bad sample.
pub fn read_profile_budget(by_profile_dir: &Path, slot: &str) -> Option<UsageSnapshot> {
    UsageSnapshot::load(&profile_budget_path(by_profile_dir, slot))
        .ok()
        .flatten()
}

/// Snapshot every slot in `pool` to `(slot, headroom)` pairs, in pool order.
/// One disk read per slot (file sizes are small, a few hundred bytes); called
/// once per spawn pick and once per status render.
pub fn pool_headroom(by_profile_dir: &Path, pool: &[String], now: i64) -> Vec<(String, Headroom)> {
    pool.iter()
        .map(|slot| {
            let snap = read_profile_budget(by_profile_dir, slot);
            (slot.clone(), headroom_from(snap.as_ref(), now))
        })
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
    fn coarse_warning_maps_to_low_but_pickable() {
        let s = snap(rw_status("warning", 2_000), RateWindow::default(), 100);
        let hr = headroom_from(Some(&s), 500);
        // Below the 10% warn threshold (slice spec), above the 2% stall floor,
        // so a lone-warning slot is still pickable with a warn log.
        assert_eq!(hr.pct, 5);
    }

    #[test]
    fn coarse_allowed_is_full_headroom() {
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
}
