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

use softfig_ipc::claude_profiles;
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
    /// Shared-capture active-slot gate (claude-login-switcher slice 009 S8).
    /// When set, a reading tagged with a `profile` is written only when that
    /// profile matches `claude_profiles::read_active(&store)` at write time;
    /// a non-active slot's reading is dropped entirely — not folded into
    /// state, not written. An untagged reading (unpooled member) always
    /// writes. Per-slot captures leave this unset so each writes its own
    /// file regardless.
    active_store: Option<PathBuf>,
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
    /// A capture that keeps `path` fresh. No active-slot gate — every reading
    /// is written. Used for the shared `usage.json` on a daemon without a
    /// claude-login store (nothing to be active against) and in tests.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            active_store: None,
            state: Mutex::new(CaptureState::default()),
        }
    }

    /// A per-slot capture seeded from whatever already lives on disk at `path`
    /// (claude-login-switcher slice 009 S7). On fresh construction, the first
    /// write of a steady unchanged reading used to overwrite the file with
    /// just one window's data, losing the other window's prior reading;
    /// seeding fixes that. A malformed or missing file reads as empty — a
    /// torn file is overwritten by the next real reading, and the picker's
    /// own read already treats such a file as warn-tier via
    /// [`crate::profile_budget::slot_headroom`].
    pub fn seeded(path: PathBuf) -> Self {
        let mut state = CaptureState::default();
        if let Ok(Some(snap)) = UsageSnapshot::load(&path) {
            let last = snap.ts as i64;
            state.snapshot = snap;
            state.written_at = Some(last);
        }
        Self {
            path: Some(path),
            active_store: None,
            state: Mutex::new(state),
        }
    }

    /// The shared `usage.json` capture, gated on the human's `active` slot
    /// (claude-login-switcher slice 009 S8). A reading tagged with a `profile`
    /// is written only when that profile matches `read_active(&store)` at
    /// write time; a non-active slot's reading is dropped entirely so the
    /// shared file never mixes accounts. An untagged reading (an unpooled
    /// member) always writes.
    pub fn new_shared_with_active_gate(path: PathBuf, store: PathBuf) -> Self {
        Self {
            path: Some(path),
            active_store: Some(store),
            state: Mutex::new(CaptureState::default()),
        }
    }

    /// A capture with no target: it folds readings in memory and never writes. The
    /// default for a backend that is not running under a growlight runtime, and the
    /// test double.
    pub fn disabled() -> Self {
        Self {
            path: None,
            active_store: None,
            state: Mutex::new(CaptureState::default()),
        }
    }

    /// Tee one window's reading — exactly as the wire reported it — into the file,
    /// stamping the snapshot `at` (unix seconds, the reader thread's clock) and
    /// tagging it with the writing member's `profile` slot (claude-login-switcher
    /// slice 004) when the member has one pinned. The tag is a hint to readers
    /// bucketing by profile; the shared top-level `usage.json` reflects the LAST
    /// writer's slot (one capture, many members), while a per-profile file
    /// (`usage.by-profile/<slot>.json`) is written by a sibling capture pointed
    /// at that path with the same slot every time.
    ///
    /// Merges per window: a reading of the 5h window never disturbs what is known
    /// about the 7d one. Writes when the reading **changed** or when the last
    /// write is [`REFRESH_FLOOR_SECS`] old (see the module docs); a tag flip
    /// alone no longer forces a write — the shared file's slot is governed by
    /// the active-slot gate, and a per-profile capture only ever sees its own
    /// slot. A write failure is reported to the daemon's stderr — the
    /// journal — and dropped, because a budget tee must never take down an
    /// agent's reader thread.
    ///
    /// With a shared-capture [`active_store`](Self::new_shared_with_active_gate)
    /// a reading tagged with a `profile` that is not the human's current
    /// `active` slot is dropped entirely: not folded into state, not written.
    /// That is what keeps the shared `usage.json` holding one account's
    /// readings only, so protocol §2b readers never mix accounts.
    pub fn record(
        &self,
        window: BudgetWindow,
        reading: RateWindow,
        at: i64,
        profile: Option<&str>,
    ) {
        // Slice 009 S8: a shared capture with an active gate drops every
        // reading tagged with a non-active slot — before any state is touched,
        // so the file keeps the active slot's history alone.
        if let (Some(store), Some(p)) = (self.active_store.as_deref(), profile)
            && claude_profiles::read_active(store).ok().as_deref() != Some(p)
        {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let slot = match window {
            BudgetWindow::FiveHour => &mut state.snapshot.rate_limits.five_hour,
            BudgetWindow::SevenDay => &mut state.snapshot.rate_limits.seven_day,
        };
        let changed = *slot != reading;
        *slot = reading;
        state.snapshot.profile = profile.map(str::to_string);
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

        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000, None);
        cap.record(BudgetWindow::SevenDay, window("warning", 9_000), 1_001, None);

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

        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000, None);
        let mtime = |p: &std::path::Path| std::fs::metadata(p).unwrap().modified().unwrap();
        let first = mtime(&path);

        // Re-reported unchanged a minute later: no write, so `ts` still reads 1_000.
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_060, None);
        assert_eq!(
            UsageSnapshot::load(&path).unwrap().unwrap().ts,
            1_000.0,
            "an unchanged reading inside the floor is not re-written",
        );
        assert_eq!(mtime(&path), first, "…and the file was not touched at all");

        // Past the floor: the same reading is re-stamped so its age stays honest.
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000 + REFRESH_FLOOR_SECS, None);
        assert_eq!(
            UsageSnapshot::load(&path).unwrap().unwrap().ts,
            (1_000 + REFRESH_FLOOR_SECS) as f64,
        );

        // A changed status is written immediately, floor or no floor.
        cap.record(BudgetWindow::FiveHour, window("rejected", 2_000), 1_000 + REFRESH_FLOOR_SECS + 1, None);
        let back = UsageSnapshot::load(&path).unwrap().unwrap();
        assert_eq!(back.rate_limits.five_hour.status.as_deref(), Some("rejected"));
        assert_eq!(back.ts, (1_000 + REFRESH_FLOOR_SECS + 1) as f64);
    }

    /// The `profile` tag is persisted to the file; after slice 009 S8 a tag
    /// flip alone (same reading, different slot, same window) no longer forces
    /// a write — the shared file's slot is governed by the active-slot gate
    /// below, not by whoever wrote last. The eMMC floor is restored.
    #[test]
    fn a_profile_tag_is_persisted_but_a_tag_flip_alone_does_not_force_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.json");
        let cap = UsageCapture::new(path.clone());

        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000, Some("slot1"));
        let back = UsageSnapshot::load(&path).unwrap().unwrap();
        assert_eq!(back.profile.as_deref(), Some("slot1"));
        assert_eq!(back.ts, 1_000.0);

        // Same reading, different slot, inside the floor — no write (slice 009
        // S8 removed the `profile_changed` forced write; the file still reads
        // the first writer's content).
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_030, Some("slot2"));
        let back = UsageSnapshot::load(&path).unwrap().unwrap();
        assert_eq!(
            back.profile.as_deref(),
            Some("slot1"),
            "tag flip alone no longer forces a shared-file write",
        );
        assert_eq!(back.ts, 1_000.0);

        // Past the floor, the same reading is re-stamped; state has slot2 by
        // now, so a floor refresh promotes the tag honestly.
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000 + REFRESH_FLOOR_SECS, Some("slot2"));
        let back = UsageSnapshot::load(&path).unwrap().unwrap();
        assert_eq!(back.profile.as_deref(), Some("slot2"));
    }

    /// A seeded per-slot capture loads whatever already lives on disk at `path`
    /// (claude-login-switcher slice 009 S7). The first unchanged event inside
    /// the floor no longer overwrites the file with just one window's data,
    /// losing the other window's prior reading.
    #[test]
    fn a_seeded_capture_preserves_the_other_windows_prior_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slot1.json");
        // Pre-exist: both windows have readings.
        let seed = UsageSnapshot {
            context_window: None,
            rate_limits: softfig_ipc::usage::RateLimits {
                five_hour: window("allowed", 2_000),
                seven_day: window("allowed_warning", 90_000),
            },
            ts: 500.0,
            profile: Some("slot1".into()),
        };
        seed.write_atomic(&path).unwrap();

        // Fresh daemon, same slot: seed loads the file. A 5h unchanged event
        // inside the floor is a no-op (no disk churn), and the 7d data stays.
        let cap = UsageCapture::seeded(path.clone());
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 600, Some("slot1"));
        let back = UsageSnapshot::load(&path).unwrap().unwrap();
        assert_eq!(back.rate_limits.seven_day.status.as_deref(), Some("allowed_warning"));
        assert_eq!(back.rate_limits.seven_day.resets_at, Some(90_000));
        assert_eq!(back.ts, 500.0, "unchanged inside the floor ⇒ no write");

        // A changed 5h reading writes — and still carries the seeded 7d data,
        // because state was seeded, not empty.
        cap.record(BudgetWindow::FiveHour, window("rejected", 2_000), 601, Some("slot1"));
        let back = UsageSnapshot::load(&path).unwrap().unwrap();
        assert_eq!(back.rate_limits.five_hour.status.as_deref(), Some("rejected"));
        assert_eq!(
            back.rate_limits.seven_day.status.as_deref(),
            Some("allowed_warning"),
            "seeded 7d reading survived the first write",
        );
    }

    /// Two interleaved writers to one slot leave no torn file, and a stale
    /// temp from a crashed writer doesn't block the next write
    /// (claude-login-switcher slice 009 S7). The unique-per-write temp names
    /// in [`UsageSnapshot::write_atomic`] mean concurrent writers no longer
    /// collide on one `*.json.tmp`.
    #[test]
    fn two_interleaved_writers_to_one_slot_leave_no_torn_file_and_a_stale_temp_does_not_block_the_next_write() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slot1.json");

        // Pre-plant a stale temp as if a prior process crashed between write and
        // rename (the OLD fixed `slot1.json.tmp` name). The new write path never
        // touches it, so it must not block.
        let stale = dir.path().join("slot1.json.tmp");
        std::fs::write(&stale, "garbage-from-a-crashed-writer").unwrap();

        let path_a = Arc::new(path.clone());
        let path_b = Arc::clone(&path_a);
        let t1 = std::thread::spawn(move || {
            for i in 0..200 {
                UsageSnapshot {
                    context_window: None,
                    rate_limits: softfig_ipc::usage::RateLimits {
                        five_hour: window("allowed", 2_000 + i),
                        seven_day: RateWindow::default(),
                    },
                    ts: 1_000.0 + i as f64,
                    profile: Some("slot1".into()),
                }
                .write_atomic(&path_a)
                .expect("writer A: write_atomic should succeed");
            }
        });
        let t2 = std::thread::spawn(move || {
            for i in 0..200 {
                UsageSnapshot {
                    context_window: None,
                    rate_limits: softfig_ipc::usage::RateLimits {
                        five_hour: window("rejected", 3_000 + i),
                        seven_day: RateWindow::default(),
                    },
                    ts: 2_000.0 + i as f64,
                    profile: Some("slot1".into()),
                }
                .write_atomic(&path_b)
                .expect("writer B: write_atomic should succeed");
            }
        });
        t1.join().unwrap();
        t2.join().unwrap();

        // The file parses: no half-written content survived.
        let back = UsageSnapshot::load(&path).unwrap().expect("file exists");
        assert!(
            back.rate_limits.five_hour.status.is_some(),
            "file is intact JSON after 400 interleaved writes",
        );
        // The stale temp is harmless (left on disk; the next write doesn't need it).
        assert!(stale.exists(), "stale temp still there, no block, no corruption");
    }

    /// With the shared capture's active-slot gate installed, interleaved
    /// slot1/slot2 events (active = slot1) leave the shared `usage.json`
    /// holding slot1 only, and the eMMC floor is respected
    /// (claude-login-switcher slice 009 S8).
    #[test]
    fn interleaved_slot1_slot2_events_leave_the_shared_file_slot1_only_and_respect_the_300s_floor() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(store.join("slot1")).unwrap();
        std::fs::create_dir_all(store.join("slot2")).unwrap();
        // `active` -> `slot1`.
        std::os::unix::fs::symlink("slot1", store.join("active")).unwrap();

        let shared = dir.path().join("usage.json");
        let cap = UsageCapture::new_shared_with_active_gate(shared.clone(), store.clone());

        // slot1 event ⇒ written (first write).
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000, Some("slot1"));
        let back = UsageSnapshot::load(&shared).unwrap().unwrap();
        assert_eq!(back.profile.as_deref(), Some("slot1"));
        assert_eq!(back.rate_limits.five_hour.status.as_deref(), Some("allowed"));
        assert_eq!(back.ts, 1_000.0);

        // slot2 event ⇒ dropped entirely by the gate (state untouched, no write).
        cap.record(BudgetWindow::FiveHour, window("rejected", 2_000), 1_010, Some("slot2"));
        let back = UsageSnapshot::load(&shared).unwrap().unwrap();
        assert_eq!(
            back.profile.as_deref(),
            Some("slot1"),
            "shared file holds the active slot only",
        );
        assert_eq!(
            back.rate_limits.five_hour.status.as_deref(),
            Some("allowed"),
            "slot2's rejection never polluted slot1's reading",
        );
        assert_eq!(back.ts, 1_000.0);

        // slot1 same reading, inside the floor ⇒ no write (floor respected).
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_060, Some("slot1"));
        let back = UsageSnapshot::load(&shared).unwrap().unwrap();
        assert_eq!(back.ts, 1_000.0, "floor still respected (same slot, same reading)");

        // slot1 past the floor ⇒ written (refresh).
        cap.record(BudgetWindow::FiveHour, window("allowed", 2_000), 1_000 + REFRESH_FLOOR_SECS, Some("slot1"));
        let back = UsageSnapshot::load(&shared).unwrap().unwrap();
        assert_eq!(back.ts, (1_000 + REFRESH_FLOOR_SECS) as f64);

        // Change the active pointer to slot2: now a slot1 event is dropped and
        // a slot2 event writes.
        std::fs::remove_file(store.join("active")).unwrap();
        std::os::unix::fs::symlink("slot2", store.join("active")).unwrap();
        let later = 1_000 + REFRESH_FLOOR_SECS * 3;
        cap.record(BudgetWindow::FiveHour, window("rejected", 5_555), later, Some("slot1"));
        let back = UsageSnapshot::load(&shared).unwrap().unwrap();
        assert_eq!(
            back.rate_limits.five_hour.status.as_deref(),
            Some("allowed"),
            "slot1 is no longer active ⇒ its reading is dropped",
        );
        cap.record(BudgetWindow::FiveHour, window("rejected", 5_555), later, Some("slot2"));
        let back = UsageSnapshot::load(&shared).unwrap().unwrap();
        assert_eq!(back.profile.as_deref(), Some("slot2"));
        assert_eq!(back.rate_limits.five_hour.status.as_deref(), Some("rejected"));
    }

    /// A disabled capture folds readings in memory and never creates a file — the
    /// shape a backend outside a growlight runtime (and every unit test that is not
    /// about the file) gets.
    #[test]
    fn a_disabled_capture_never_touches_disk() {
        let cap = UsageCapture::disabled();
        cap.record(BudgetWindow::FiveHour, window("rejected", 5), 1, None);
        assert_eq!(
            cap.snapshot().rate_limits.five_hour.status.as_deref(),
            Some("rejected"),
            "the reading is still folded, so a caller can read it back",
        );
    }
}
