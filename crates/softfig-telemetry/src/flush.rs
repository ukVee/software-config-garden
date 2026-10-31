//! The flush thread: drains the ring into the store in batches and runs the
//! retention sweep (spec §5).
//!
//! It wakes when the ring reaches its threshold or the interval passes,
//! whichever comes first, and writes the whole drain in one transaction. An
//! empty drain writes nothing, so an idle daemon costs the eMMC nothing.

use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ring::RingRecorder;
use crate::schema::{FLUSH_INTERVAL_SECS, RETENTION_SWEEP_SECS};
use crate::store::Store;

/// The unix-seconds clock the sweep reads. Injected so a test can age rows
/// without waiting 90 days.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// When the flush thread writes and sweeps. The ring's own limits decide the
/// pending-row trigger.
#[derive(Clone)]
pub struct FlushPolicy {
    /// The longest a recorded row waits before it is written.
    pub interval: Duration,
    /// Seconds (by `clock`) between retention sweeps. One also runs at spawn,
    /// so a daemon that restarts more often than this still sweeps.
    pub sweep_every_secs: i64,
    pub clock: Clock,
}

impl Default for FlushPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(FLUSH_INTERVAL_SECS),
            sweep_every_secs: RETENTION_SWEEP_SECS as i64,
            clock: Arc::new(unix_now),
        }
    }
}

impl std::fmt::Debug for FlushPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlushPolicy")
            .field("interval", &self.interval)
            .field("sweep_every_secs", &self.sweep_every_secs)
            .finish_non_exhaustive()
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What the flush thread has done. Only transactions that were opened are
/// counted, so an idle thread reads all zeros.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlushStats {
    /// Insert transactions committed.
    pub batches: u64,
    /// Rows those transactions added (re-ingested duplicates excluded).
    pub rows_written: u64,
    /// Batches whose transaction failed; their rows are gone (spec §11 accepts
    /// telemetry loss over blocking a member).
    pub failed_batches: u64,
    /// Sweeps that rolled at least one row up.
    pub sweeps: u64,
    /// Raw rows rolled up and deleted.
    pub rolled: u64,
}

pub struct Flusher;

impl Flusher {
    /// Start the flush thread. It owns `store` until the handle shuts down.
    pub fn spawn(
        store: Store,
        ring: RingRecorder,
        policy: FlushPolicy,
    ) -> std::io::Result<FlushHandle> {
        let stats = Arc::new(Mutex::new(FlushStats::default()));
        let thread = {
            let ring = ring.clone();
            let stats = Arc::clone(&stats);
            std::thread::Builder::new()
                .name("telemetry-flush".into())
                .spawn(move || run(store, ring, policy, stats))?
        };
        Ok(FlushHandle {
            ring,
            stats,
            thread: Some(thread),
        })
    }
}

fn run(mut store: Store, ring: RingRecorder, policy: FlushPolicy, stats: Arc<Mutex<FlushStats>>) {
    let mut last_sweep: Option<i64> = None;
    loop {
        let now = (policy.clock)();
        if last_sweep.is_none_or(|t| now - t >= policy.sweep_every_secs) {
            last_sweep = Some(now);
            match store.sweep_retention(now) {
                Ok(o) if o.rolled > 0 => update(&stats, |s| {
                    s.sweeps += 1;
                    s.rolled += o.rolled as u64;
                }),
                Ok(_) => {}
                Err(e) => eprintln!("telemetry: retention sweep failed: {e}"),
            }
        }

        let closed = ring.wait_for_batch(policy.interval);
        let rows = ring.drain();
        if !rows.is_empty() {
            match store.insert_batch(&rows) {
                Ok(n) => update(&stats, |s| {
                    s.batches += 1;
                    s.rows_written += n as u64;
                }),
                Err(e) => {
                    eprintln!("telemetry: flush of {} rows failed: {e}", rows.len());
                    update(&stats, |s| s.failed_batches += 1);
                }
            }
        }
        if closed {
            return;
        }
    }
}

fn update(stats: &Mutex<FlushStats>, f: impl FnOnce(&mut FlushStats)) {
    f(&mut stats.lock().unwrap_or_else(PoisonError::into_inner));
}

/// Owns the flush thread. Dropping it shuts down the same way
/// [`shutdown`](Self::shutdown) does.
pub struct FlushHandle {
    ring: RingRecorder,
    stats: Arc<Mutex<FlushStats>>,
    thread: Option<JoinHandle<()>>,
}

impl FlushHandle {
    pub fn stats(&self) -> FlushStats {
        *self.stats.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wake the thread for a final flush of whatever is pending, join it, and
    /// return what it did. Rows recorded after this returns are not written.
    pub fn shutdown(mut self) -> FlushStats {
        self.stop();
        self.stats()
    }

    fn stop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.ring.close();
            if thread.join().is_err() {
                eprintln!("telemetry: flush thread panicked");
            }
        }
    }
}

impl Drop for FlushHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::Recorder;
    use crate::schema::RAW_RETENTION_DAYS;
    use crate::store::tests::row;
    use std::path::Path;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::Instant;

    const NOW: i64 = 1_793_462_624;
    const DAY: i64 = 86_400;
    const LONG: Duration = Duration::from_secs(600);

    fn policy(interval: Duration, clock: Clock) -> FlushPolicy {
        FlushPolicy {
            interval,
            sweep_every_secs: DAY,
            clock,
        }
    }

    fn fixed(t: i64) -> Clock {
        Arc::new(move || t)
    }

    fn rows_in(path: &Path) -> i64 {
        Store::open(path)
            .unwrap()
            .conn()
            .query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))
            .unwrap()
    }

    fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn the_pending_count_triggers_a_flush_before_the_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let ring = RingRecorder::with_limits(100, 3);
        let handle = Flusher::spawn(
            Store::open(&path).unwrap(),
            ring.clone(),
            policy(LONG, fixed(NOW)),
        )
        .unwrap();
        for i in 0..3 {
            ring.record(row("s", &format!("r{i}"), NOW));
        }
        eventually("a count-triggered batch", || handle.stats().batches == 1);
        assert_eq!(rows_in(&path), 3);
        assert_eq!(handle.shutdown().rows_written, 3);
    }

    #[test]
    fn the_interval_flushes_a_batch_below_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let ring = RingRecorder::with_limits(100, 50);
        let handle = Flusher::spawn(
            Store::open(&path).unwrap(),
            ring.clone(),
            policy(Duration::from_millis(20), fixed(NOW)),
        )
        .unwrap();
        ring.record(row("s", "r1", NOW));
        eventually("an interval-triggered batch", || {
            handle.stats().batches == 1
        });
        assert_eq!(rows_in(&path), 1);
        drop(handle);
    }

    #[test]
    fn an_idle_thread_opens_no_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let ring = RingRecorder::with_limits(100, 50);
        let handle = Flusher::spawn(
            Store::open(&dir.path().join("t.db")).unwrap(),
            ring,
            policy(Duration::from_millis(2), fixed(NOW)),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(handle.shutdown(), FlushStats::default());
    }

    #[test]
    fn shutdown_flushes_what_is_pending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let ring = RingRecorder::with_limits(100, 50);
        let handle = Flusher::spawn(
            Store::open(&path).unwrap(),
            ring.clone(),
            policy(LONG, fixed(NOW)),
        )
        .unwrap();
        ring.record(row("s", "r1", NOW));
        ring.record(row("s", "r2", NOW));
        let started = Instant::now();
        let stats = handle.shutdown();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "shutdown didn't wait out the interval"
        );
        assert_eq!((stats.batches, stats.rows_written), (1, 2));
        assert_eq!(rows_in(&path), 2);
    }

    #[test]
    fn a_sweep_runs_at_spawn_and_again_once_the_clock_moves_a_period() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let horizon = i64::from(RAW_RETENTION_DAYS) * DAY;
        {
            let mut store = Store::open(&path).unwrap();
            store
                .insert_batch(&[row("s", "aged", NOW - horizon - 1)])
                .unwrap();
        }
        let clock = Arc::new(AtomicI64::new(NOW));
        let read = {
            let clock = Arc::clone(&clock);
            Arc::new(move || clock.load(Ordering::SeqCst)) as Clock
        };
        let ring = RingRecorder::with_limits(100, 1);
        let handle = Flusher::spawn(
            Store::open(&path).unwrap(),
            ring.clone(),
            policy(Duration::from_millis(5), read),
        )
        .unwrap();
        eventually("the spawn sweep", || handle.stats().rolled == 1);

        // Fresh at NOW, aged once the clock has moved two days.
        ring.record(row("s", "later", NOW - horizon + DAY));
        eventually("the flush", || handle.stats().rows_written == 1);
        assert_eq!(
            handle.stats().sweeps,
            1,
            "no second sweep before a period passes"
        );
        clock.store(NOW + 2 * DAY, Ordering::SeqCst);
        eventually("the periodic sweep", || handle.stats().rolled == 2);

        let stats = handle.shutdown();
        assert_eq!(stats.sweeps, 2);
        assert_eq!(rows_in(&path), 0);
    }
}
