//! **Headless capture** of the shared-pool reading into the runtime `usage.json`
//! (task 048).
//!
//! `usage.json` ([`softfig_ipc::usage`]) is the one budget file everything outside
//! this daemon reads: the loop protocol's §2b boot check (a member reads it before
//! starting a step), the `--auto` between-iteration governor, the human. Its only
//! writer used to be the **interactive statusline** hook — and a headless
//! `claude -p` fleet member has no statusline, so across six days of fleet
//! iterations nobody wrote it. Both the members and the governor then acted on a
//! reading from whenever the human last sat at an interactive session: the fossil
//! behind `incident-20260720-m5f-double-park`.
//!
//! growlightd is the process that *does* see every headless reading — each
//! member's `rate_limit_event` lines stream through
//! [`pump`](crate::claude_backend) into that agent's budget cell. This module tees
//! the same readings to the file, so the fleet keeps `usage.json` fresh on its own.
//!
//! ## What it writes
//!
//! Only what the wire vouches for: the window's coarse `status` and its `resets_at`
//! boundary, plus a `used_percentage` **only if** the reading carried a real one
//! (the headless wire does not — see [`softfig_ipc::usage`] on why an unknown
//! percentage is omitted rather than written as `0`). It never writes a
//! `context_window`: a fleet has N members with N context windows and no single one
//! is "the" context, and each member reports its own in its baton head.
//!
//! Readings come from `rate_limit_event` lines alone — the reliable headless source
//! — not from the opportunistic `rate_limits` block a terminal `result` line may
//! carry, which is wire-format-unconfirmed and carries no boundary.
//!
//! ## When it writes
//!
//! On a **changed** reading, and otherwise no more often than
//! [`REFRESH_FLOOR_SECS`]. The fleet sees these events continuously and this device
//! is an eMMC tablet, so a write per event (or per tick) would be pointless disk
//! churn; a reading that has not changed is still the same reading, and its `ts`
//! only needs refreshing often enough that a reader can tell a live capture from an
//! abandoned one. Both halves matter: change-only would leave `ts` stale through a
//! long steady run, and time-only would delay a genuine status change.

use std::path::PathBuf;
use std::sync::Mutex;

use softfig_ipc::usage::{RateWindow, UsageSnapshot};

use crate::claude_backend::BudgetWindow;

/// How stale a captured reading may get before an unchanged re-read is written
/// again purely to refresh its `ts` — five minutes. Bounds the file's apparent age
/// during a steady run without turning a per-event tee into per-event disk writes.
pub const REFRESH_FLOOR_SECS: i64 = 300;

/// The live tee from the fleet's stream-json readings to the runtime `usage.json`.
/// One per daemon, shared by every member's reader thread: the file describes the
/// **account-wide** pool every member reads, so the freshest reading any member
/// took is the file's content (last write wins), not a per-member artifact.
///
/// [`disabled`](Self::disabled) yields a capture with no target — the shape a unit
/// test and a backend constructed outside a growlight runtime both want; it records
/// readings in memory and never touches disk.
#[derive(Debug)]
pub struct UsageCapture {
    /// The `usage.json` to keep fresh; `None` disables writing entirely.
    path: Option<PathBuf>,
    state: Mutex<CaptureState>,
}

/// The last reading captured, and when it was last persisted.
#[derive(Debug, Default)]
struct CaptureState {
    snapshot: UsageSnapshot,
    /// Unix seconds of the last successful write, `None` before the first.
    written_at: Option<i64>,
}

impl UsageCapture {
    /// A capture that keeps `path` fresh.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            state: Mutex::new(CaptureState::default()),
        }
    }

    /// A capture with no target: it folds readings in memory and never writes. The
    /// default for a backend that is not running under a growlight runtime, and the
    /// test double.
    pub fn disabled() -> Self {
        Self {
            path: None,
            state: Mutex::new(CaptureState::default()),
        }
    }

    /// Tee one window's reading — exactly as the wire reported it — into the file,
    /// stamping the snapshot `at` (unix seconds, the reader thread's clock).
    ///
    /// Merges per window: a reading of the 5h window never disturbs what is known
    /// about the 7d one. Writes when the reading **changed**, or when the last write
    /// is [`REFRESH_FLOOR_SECS`] old (see the module docs); a write failure is
    /// reported to the daemon's stderr — the journal — and dropped, because a
    /// budget tee must never take down an agent's reader thread.
    pub fn record(&self, window: BudgetWindow, reading: RateWindow, at: i64) {
        let mut state = self.state.lock().unwrap();
        let slot = match window {
            BudgetWindow::FiveHour => &mut state.snapshot.rate_limits.five_hour,
            BudgetWindow::SevenDay => &mut state.snapshot.rate_limits.seven_day,
        };
        let changed = *slot != reading;
        *slot = reading;
        let due = state
            .written_at
            .is_none_or(|last| at.saturating_sub(last) >= REFRESH_FLOOR_SECS);
        if !changed && !due {
            return;
        }
        state.snapshot.ts = at as f64;
        let Some(path) = self.path.as_deref() else {
            state.written_at = Some(at);
            return;
        };
        match state.snapshot.write_atomic(path) {
            Ok(()) => state.written_at = Some(at),
            Err(e) => eprintln!(
                "growlightd: could not write the budget capture to {}: {e}",
                path.display()
            ),
        }
    }

    /// The reading captured so far — the content a write would persist. For tests
    /// and for a caller that wants the fleet's freshest reading without re-reading
    /// the file.
    pub fn snapshot(&self) -> UsageSnapshot {
        self.state.lock().unwrap().snapshot.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(status: &str, resets_at: i64) -> RateWindow {
        RateWindow {
            used_percentage: None,
            resets_at: Some(resets_at),
            status: Some(status.to_string()),
        }
    }

    /// The headless capture writes what the wire vouches for — per-window status +
    /// boundary, no percentage, no context block — and the file it leaves behind
    /// parses back as the same reading.
    #[test]
    fn a_headless_reading_lands_in_the_file_without_inventing_a_percentage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("growlight").join("usage.json");
        let cap = UsageCapture::new(path.clone());

        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000);
        cap.record(BudgetWindow::SevenDay, window("warning", 9_000), 1_001);

        let raw = std::fs::read_to_string(&path).expect("the capture created the file");
        assert!(
            !raw.contains("used_percentage"),
            "the headless wire reports no percentage, so none is written: {raw}",
        );
        assert!(
            !raw.contains("context_window"),
            "a fleet has no single context window to report: {raw}",
        );
        let back = UsageSnapshot::load(&path).unwrap().expect("the file exists");
        assert_eq!(back.rate_limits.five_hour.status.as_deref(), Some("allowed"));
        assert_eq!(back.rate_limits.five_hour.resets_at, Some(2_000));
        assert_eq!(back.rate_limits.seven_day.status.as_deref(), Some("warning"));
        assert_eq!(back.rate_limits.seven_day.resets_at, Some(9_000));
        assert_eq!(back.ts, 1_001.0, "the file is stamped with the reading's clock");
    }

    /// An unchanged reading is not re-written per event (this is an eMMC tablet),
    /// but it is refreshed once the last write is `REFRESH_FLOOR_SECS` old, so a
    /// steady run's file never *looks* abandoned. A changed reading writes at once.
    #[test]
    fn an_unchanged_reading_refreshes_on_the_floor_and_a_changed_one_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.json");
        let cap = UsageCapture::new(path.clone());

        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000);
        let mtime = |p: &std::path::Path| std::fs::metadata(p).unwrap().modified().unwrap();
        let first = mtime(&path);

        // Re-reported unchanged a minute later: no write, so `ts` still reads 1_000.
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_060);
        assert_eq!(
            UsageSnapshot::load(&path).unwrap().unwrap().ts,
            1_000.0,
            "an unchanged reading inside the floor is not re-written",
        );
        assert_eq!(mtime(&path), first, "…and the file was not touched at all");

        // Past the floor: the same reading is re-stamped so its age stays honest.
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000 + REFRESH_FLOOR_SECS);
        assert_eq!(
            UsageSnapshot::load(&path).unwrap().unwrap().ts,
            (1_000 + REFRESH_FLOOR_SECS) as f64,
        );

        // A changed status is written immediately, floor or no floor.
        cap.record(BudgetWindow::FiveHour, window("rejected", 2_000), 1_000 + REFRESH_FLOOR_SECS + 1);
        let back = UsageSnapshot::load(&path).unwrap().unwrap();
        assert_eq!(back.rate_limits.five_hour.status.as_deref(), Some("rejected"));
        assert_eq!(back.ts, (1_000 + REFRESH_FLOOR_SECS + 1) as f64);
    }

    /// A disabled capture folds readings in memory and never creates a file — the
    /// shape a backend outside a growlight runtime (and every unit test that is not
    /// about the file) gets.
    #[test]
    fn a_disabled_capture_never_touches_disk() {
        let cap = UsageCapture::disabled();
        cap.record(BudgetWindow::FiveHour, window("rejected", 5), 1);
        assert_eq!(
            cap.snapshot().rate_limits.five_hour.status.as_deref(),
            Some("rejected"),
            "the reading is still folded, so a caller can read it back",
        );
    }
}
