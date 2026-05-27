//! Adapter that routes FUSE handler notifications into the daemon's
//! shared [`DirtySetAccumulator`].
//!
//! M2a's "single classifier pipeline" pick: FUSE writes feed the same
//! accumulator inotify uses, so the classifier sees a single coherent
//! dirty set per debounce window regardless of which source originated
//! each event.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use softfig_fuse::DirtyEventSink;

use crate::watcher::{DirtyEvent, DirtySetAccumulator, DEBOUNCE_MS};

/// Pushes [`DirtyEvent`]s into the accumulator and arranges for a
/// `flush()` after the M1d 200 ms quiet window. The flush is driven by
/// a tiny dedicated thread that wakes every `DEBOUNCE_MS / 2` to check
/// whether the accumulator has been quiet long enough.
#[derive(Debug)]
pub struct AccumulatorSink {
    accumulator: Arc<DirtySetAccumulator>,
    last_nudge: Mutex<Option<Instant>>,
}

impl AccumulatorSink {
    pub fn spawn(accumulator: Arc<DirtySetAccumulator>) -> Arc<Self> {
        let sink = Arc::new(Self {
            accumulator,
            last_nudge: Mutex::new(None),
        });
        let driver = sink.clone();
        thread::Builder::new()
            .name("keeperd-fuse-flush".into())
            .spawn(move || driver.run_flush_loop())
            .expect("spawn fuse-flush");
        sink
    }

    fn run_flush_loop(self: Arc<Self>) {
        let tick = Duration::from_millis(DEBOUNCE_MS / 2);
        loop {
            thread::sleep(tick);
            // Daemon-shutdown isn't directly visible from the sink; we
            // rely on the accumulator's own state-aware flush (it bails
            // when the daemon isn't Unlocked) and Arc-strong-count
            // dropping to terminate this thread once the daemon and
            // mount handles are gone.
            if Arc::strong_count(&self) == 1 {
                return;
            }
            let due = {
                let mut g = self.last_nudge.lock().unwrap();
                match *g {
                    Some(t) if t.elapsed() >= Duration::from_millis(DEBOUNCE_MS) => {
                        *g = None;
                        true
                    }
                    _ => false,
                }
            };
            if due {
                self.accumulator.flush();
            }
        }
    }
}

impl DirtyEventSink for AccumulatorSink {
    fn created(&self, repo_relative: &str) {
        self.accumulator
            .push(DirtyEvent::Created(repo_relative.to_string()));
    }

    fn modified(&self, repo_relative: &str) {
        self.accumulator
            .push(DirtyEvent::Modified(repo_relative.to_string()));
    }

    fn removed(&self, repo_relative: &str) {
        self.accumulator
            .push(DirtyEvent::Removed(repo_relative.to_string()));
    }

    fn renamed(&self, from: &str, to: &str) {
        self.accumulator.push(DirtyEvent::Renamed {
            from: from.to_string(),
            to: to.to_string(),
        });
    }

    fn nudge(&self) {
        *self.last_nudge.lock().unwrap() = Some(Instant::now());
    }
}
