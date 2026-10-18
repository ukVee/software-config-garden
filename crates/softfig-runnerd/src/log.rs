//! The per-job log collector (spec remote-runner §6 Logs).
//!
//! The run step's stdout/stderr are streamed live as `JobLog` frames and also
//! accumulated here: a bounded in-memory ring (default 4 MiB — the
//! attach/resume machinery lands in chunk 4, but the bound is spec §6 Logs)
//! plus a running BLAKE3 of the **full** log, which the attestation records as
//! `log_blake3`.
//!
//! On the tablet, prefer in-memory to disk (spec §6 Logs): this ring is RAM,
//! and nothing is written to a file unless a caller asks.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// The live-forward channel's capacity in chunks: a bounded buffer so a job
/// spewing output can never grow runnerd's memory without bound. A chunk is
/// dropped only when this buffer is full — the ring and hash still hold every
/// byte, so `log_blake3` and the attach tail stay correct.
const LIVE_CHANNEL_CAP: usize = 256;

/// The default per-job log-ring bound (spec §6 Logs).
pub const DEFAULT_LOG_RING_BYTES: usize = 4 * 1024 * 1024;

/// One live log chunk: a write of `bytes` to `stream` (0=stdout, 1=stderr,
/// 2=system).
#[derive(Debug, Clone)]
pub struct LogChunk {
    pub seq: u64,
    pub stream: u8,
    pub bytes: Vec<u8>,
}

/// The collector's shared inner state.
struct Inner {
    /// The bounded tail of the log (oldest bytes evicted past the cap).
    ring: VecDeque<u8>,
    /// The ring bound in bytes.
    ring_cap: usize,
    /// Total chunks pushed (the live-stream sequence number).
    seq: u64,
    /// Running BLAKE3 of the full log.
    hasher: blake3::Hasher,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            ring: VecDeque::new(),
            ring_cap: DEFAULT_LOG_RING_BYTES,
            seq: 0,
            hasher: blake3::Hasher::new(),
        }
    }
}

/// A cloneable handle that appends log bytes. One per reader thread.
#[derive(Clone)]
pub struct LogSink {
    tx: Option<mpsc::SyncSender<LogChunk>>,
    inner: Arc<Mutex<Inner>>,
}

impl LogSink {
    /// Append `bytes` to `stream`: hash them, ring them, and forward a live
    /// chunk over the channel (when present). A full forward buffer drops the
    /// chunk without blocking — the ring + hash still hold it, so `log_blake3`
    /// and the attach tail remain correct.
    pub fn push(&self, stream: u8, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.hasher.update(bytes);
        for &b in bytes {
            inner.ring.push_back(b);
        }
        while inner.ring.len() > inner.ring_cap {
            inner.ring.pop_front();
        }
        let seq = inner.seq;
        inner.seq += 1;
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(LogChunk { seq, stream, bytes: bytes.to_vec() });
        }
    }
}

/// The job's log collector. Owns the live channel; a [`LogSink`] clone is
/// handed to each producer (reader thread), and the wire drains the receiver
/// into `JobLog` frames.
pub struct JobLogs {
    inner: Arc<Mutex<Inner>>,
    tx: Option<mpsc::SyncSender<LogChunk>>,
}

impl JobLogs {
    /// Create a collector with the default ring bound, returning it plus the
    /// live-channel receiver.
    pub fn new() -> (Self, mpsc::Receiver<LogChunk>) {
        Self::with_capacity(DEFAULT_LOG_RING_BYTES)
    }

    /// Create a collector with an explicit ring bound.
    pub fn with_capacity(ring_bytes: usize) -> (Self, mpsc::Receiver<LogChunk>) {
        let (tx, rx) = mpsc::sync_channel(LIVE_CHANNEL_CAP);
        let logs = Self {
            inner: Arc::new(Mutex::new(Inner { ring_cap: ring_bytes, ..Inner::default() })),
            tx: Some(tx),
        };
        (logs, rx)
    }

    /// A cloneable producer handle.
    pub fn sink(&self) -> LogSink {
        LogSink { tx: self.tx.clone(), inner: Arc::clone(&self.inner) }
    }

    /// Close the live channel (drop the last sender), so a receiver's `recv`
    /// loop sees the channel close once every producer has also dropped.
    pub fn close(&mut self) {
        self.tx = None;
    }

    /// `BLAKE3` of the full log (the attestation's `log_blake3`).
    pub fn log_blake3(&self) -> [u8; 32] {
        let inner = self.inner.lock().unwrap();
        let hasher = inner.hasher.clone();
        *hasher.finalize().as_bytes()
    }

    /// The bounded ring's current contents (the log tail, oldest-first).
    pub fn tail(&self) -> Vec<u8> {
        self.inner.lock().unwrap().ring.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_blake3_is_over_the_full_log() {
        let (logs, _rx) = JobLogs::new();
        let sink = logs.sink();
        sink.push(0, b"hello ");
        sink.push(1, b"world");
        assert_eq!(
            logs.log_blake3(),
            *blake3::hash(b"hello world").as_bytes(),
            "log_blake3 must be the BLAKE3 of the concatenated log"
        );
    }

    #[test]
    fn ring_is_bounded_to_the_tail() {
        let (logs, _rx) = JobLogs::with_capacity(4);
        let sink = logs.sink();
        sink.push(0, b"abcdef");
        // Only the last 4 bytes survive; the hash still covers all 6.
        assert_eq!(logs.tail(), b"cdef");
        assert_eq!(logs.log_blake3(), *blake3::hash(b"abcdef").as_bytes());
    }

    #[test]
    fn chunks_stream_in_order_with_seq() {
        let (mut logs, rx) = JobLogs::new();
        let sink = logs.sink();
        sink.push(0, b"a");
        sink.push(1, b"b");
        logs.close(); // drop the master sender
        drop(sink); // drop the last producer clone

        let mut got = Vec::new();
        while let Ok(c) = rx.recv() {
            got.push((c.seq, c.stream, c.bytes));
        }
        assert_eq!(
            got,
            vec![(0, 0, b"a".to_vec()), (1, 1, b"b".to_vec())],
            "chunks must arrive in push order with monotonically increasing seq"
        );
    }
}
