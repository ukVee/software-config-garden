//! The bounded in-memory ring capture points record into (spec §5).
//!
//! `record` runs on a member's stdout reader thread, so it only pushes under a
//! short lock: no I/O, no allocation beyond the row itself. When the ring is
//! full the oldest row goes and is counted, so a stalled flusher costs history,
//! never the member.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::recorder::Recorder;
use crate::row::RequestRow;
use crate::schema::{FLUSH_PENDING_ROWS, RING_CAPACITY};

/// A cloneable handle; every clone records into the same ring.
#[derive(Debug, Clone)]
pub struct RingRecorder {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    ready: Condvar,
    capacity: usize,
    flush_at: usize,
}

#[derive(Debug, Default)]
struct State {
    rows: VecDeque<RequestRow>,
    dropped: u64,
    closed: bool,
}

impl Default for RingRecorder {
    fn default() -> Self {
        Self::with_limits(RING_CAPACITY, FLUSH_PENDING_ROWS)
    }
}

impl RingRecorder {
    /// [`RING_CAPACITY`] rows, waking the flusher at [`FLUSH_PENDING_ROWS`].
    pub fn new() -> Self {
        Self::default()
    }

    /// A ring of `capacity` rows that wakes the flusher once `flush_at` are
    /// pending. Both are clamped to at least 1.
    pub fn with_limits(capacity: usize, flush_at: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::default()),
                ready: Condvar::new(),
                capacity,
                flush_at: flush_at.clamp(1, capacity),
            }),
        }
    }

    /// Take every pending row, oldest first.
    pub fn drain(&self) -> Vec<RequestRow> {
        self.lock().rows.drain(..).collect()
    }

    /// Rows lost to overflow since the ring was made.
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }

    /// Block until `flush_at` rows are pending, the ring is closed, or
    /// `timeout` passes. Returns whether the ring is closed.
    pub(crate) fn wait_for_batch(&self, timeout: Duration) -> bool {
        let guard = self.lock();
        let (guard, _) = self
            .shared
            .ready
            .wait_timeout_while(guard, timeout, |s| {
                s.rows.len() < self.shared.flush_at && !s.closed
            })
            .unwrap_or_else(PoisonError::into_inner);
        guard.closed
    }

    /// Wake the flusher for its final drain.
    pub(crate) fn close(&self) {
        self.lock().closed = true;
        self.shared.ready.notify_all();
    }

    // A panic elsewhere while holding the lock leaves the queue intact, and
    // accounting must never take a member down with it.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Recorder for RingRecorder {
    fn record(&self, row: RequestRow) {
        let mut state = self.lock();
        if state.rows.len() >= self.shared.capacity {
            state.rows.pop_front();
            state.dropped += 1;
        }
        state.rows.push_back(row);
        if state.rows.len() >= self.shared.flush_at {
            self.shared.ready.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::row;

    #[test]
    fn overflow_drops_the_oldest_and_counts_it() {
        let ring = RingRecorder::with_limits(3, 3);
        for i in 1..=5 {
            ring.record(row("s", &format!("r{i}"), 0));
        }
        assert_eq!(ring.dropped(), 2);
        let ids: Vec<_> = ring.drain().into_iter().map(|r| r.request_id).collect();
        assert_eq!(ids, ["r3", "r4", "r5"]);
        assert!(ring.drain().is_empty());
        assert_eq!(ring.dropped(), 2, "draining doesn't reset the drop count");
    }

    #[test]
    fn reaching_the_threshold_wakes_a_waiter() {
        let ring = RingRecorder::with_limits(10, 2);
        let waiter = {
            let ring = ring.clone();
            std::thread::spawn(move || {
                let t = std::time::Instant::now();
                let closed = ring.wait_for_batch(Duration::from_secs(30));
                (closed, t.elapsed())
            })
        };
        ring.record(row("s", "r1", 0));
        ring.record(row("s", "r2", 0));
        let (closed, waited) = waiter.join().unwrap();
        assert!(!closed);
        assert!(
            waited < Duration::from_secs(10),
            "woke on the count, not the timeout"
        );
    }

    #[test]
    fn below_the_threshold_waits_out_the_timeout() {
        let ring = RingRecorder::with_limits(10, 2);
        ring.record(row("s", "r1", 0));
        assert!(!ring.wait_for_batch(Duration::from_millis(20)));
        assert_eq!(ring.drain().len(), 1);
    }

    #[test]
    fn close_wakes_a_waiter() {
        let ring = RingRecorder::with_limits(10, 5);
        let waiter = {
            let ring = ring.clone();
            std::thread::spawn(move || ring.wait_for_batch(Duration::from_secs(30)))
        };
        ring.close();
        assert!(waiter.join().unwrap());
    }
}
