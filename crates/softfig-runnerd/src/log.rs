//! The per-job log collector (spec remote-runner §6 Logs).
//!
//! The run step's stdout/stderr are streamed live as `JobLog` frames and also
//! accumulated here: a bounded in-memory ring (default 4 MiB — the
//! attach/resume machinery, chunk 4) plus a running BLAKE3 of the **full** log,
//! which the attestation records as `log_blake3`.
//!
//! The ring is **chunk-structured** (each `push` is one `LogChunk` tagged with
//! its monotonic `seq`), so `JobAttach{from_seq}` can resume from a chunk
//! sequence number. Live forwarding is a broadcast: the wire drain thread and
//! any attach connection each subscribe for their own copy.
//!
//! A `LogSink` can also be file-backed (`with_file`): the transient unit's
//! `--run-job` payload writes the run step's output, framed, to a file the
//! runner reads back after the unit completes (unit-mode log capture).
//!
//! On the tablet, prefer in-memory to disk (spec §6 Logs): this ring is RAM,
//! and nothing is written to a file unless a caller asks.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

/// The live-forward channel's capacity in chunks: a bounded buffer so a job
/// spewing output can never grow runnerd's memory without bound. A chunk is
/// dropped only when a subscriber's buffer is full — the ring + hash still hold
/// every byte, so `log_blake3` and the attach tail stay correct.
const LIVE_CHANNEL_CAP: usize = 256;

/// The default per-job log-ring bound (spec §6 Logs).
pub const DEFAULT_LOG_RING_BYTES: usize = 4 * 1024 * 1024;

/// One live log chunk: a write of `bytes` to `stream` (0=stdout, 1=stderr,
/// 2=system), tagged with its monotonic sequence number.
#[derive(Debug, Clone)]
pub struct LogChunk {
    pub seq: u64,
    pub stream: u8,
    pub bytes: Vec<u8>,
}

/// The collector's shared inner state.
struct Inner {
    /// The bounded tail of the log, chunk-structured (oldest chunks evicted
    /// past the byte cap; at least one chunk is always retained).
    ring: VecDeque<LogChunk>,
    /// Total bytes currently in the ring.
    ring_bytes: usize,
    /// The ring bound in bytes.
    ring_cap: usize,
    /// Total chunks pushed (the live-stream sequence number).
    seq: u64,
    /// Running BLAKE3 of the full log.
    hasher: blake3::Hasher,
    /// Live-forward subscribers (the wire drain and any attach connections).
    subscribers: Vec<SyncSender<LogChunk>>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            ring: VecDeque::new(),
            ring_bytes: 0,
            ring_cap: DEFAULT_LOG_RING_BYTES,
            seq: 0,
            hasher: blake3::Hasher::new(),
            subscribers: Vec::new(),
        }
    }
}

/// A cloneable handle that appends log bytes (one per reader thread).
#[derive(Clone)]
pub struct LogSink {
    inner: Arc<Mutex<Inner>>,
    /// Optional framed file the payload writes (unit mode), so the runner can
    /// stream the transient unit's output back after it completes.
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl LogSink {
    /// A sink that additionally writes every chunk, framed, to `file` (unit
    /// mode's `--run-job` payload).
    pub fn with_file(&self, file: std::fs::File) -> Self {
        Self { inner: Arc::clone(&self.inner), file: Some(Arc::new(Mutex::new(file))) }
    }

    /// Append `bytes` to `stream`: hash them, ring them, write them to the file
    /// (when present), and forward a live chunk to every subscriber. A full
    /// subscriber drops the chunk without blocking — the ring + hash still hold
    /// every byte.
    pub fn push(&self, stream: u8, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.hasher.update(bytes);
        let seq = inner.seq;
        inner.seq += 1;
        let chunk = LogChunk { seq, stream, bytes: bytes.to_vec() };
        inner.ring.push_back(chunk.clone());
        inner.ring_bytes += bytes.len();
        while inner.ring_bytes > inner.ring_cap && inner.ring.len() > 1 {
            if let Some(front) = inner.ring.pop_front() {
                inner.ring_bytes -= front.bytes.len();
            } else {
                break;
            }
        }
        if let Some(file) = &self.file
            && let Ok(mut f) = file.lock()
        {
            let _ = write_framed_chunk(&mut *f, stream, bytes);
        }
        inner.subscribers.retain(|tx| match tx.try_send(chunk.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        });
    }
}

/// The job's log collector. Cloneable and cheap (`Arc`-shared); the wire owns
/// one, hands `LogSink` clones to each producer, and hands subscriber receivers
/// to the drain thread and any attach connections.
#[derive(Clone)]
pub struct JobLogs {
    inner: Arc<Mutex<Inner>>,
}

impl JobLogs {
    /// Create a collector with the default ring bound.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_LOG_RING_BYTES)
    }

    /// Create a collector with an explicit ring bound.
    pub fn with_capacity(ring_bytes: usize) -> Self {
        Self { inner: Arc::new(Mutex::new(Inner { ring_cap: ring_bytes, ..Inner::default() })) }
    }

    /// A cloneable producer handle.
    pub fn sink(&self) -> LogSink {
        LogSink { inner: Arc::clone(&self.inner), file: None }
    }

    /// Register a live subscriber and return its receiver.
    pub fn subscribe(&self) -> Receiver<LogChunk> {
        let (tx, rx) = mpsc::sync_channel(LIVE_CHANNEL_CAP);
        self.inner.lock().unwrap().subscribers.push(tx);
        rx
    }

    /// Subscribe AND replay the retained chunks with `seq >= from_seq`, in one
    /// atomic step, so nothing pushed between the replay snapshot and the
    /// subscription is missed or duplicated.
    pub fn subscribe_and_replay(&self, from_seq: u64) -> (Receiver<LogChunk>, Vec<LogChunk>) {
        let mut inner = self.inner.lock().unwrap();
        let replay: Vec<LogChunk> =
            inner.ring.iter().filter(|c| c.seq >= from_seq).cloned().collect();
        let (tx, rx) = mpsc::sync_channel(LIVE_CHANNEL_CAP);
        inner.subscribers.push(tx);
        (rx, replay)
    }

    /// `BLAKE3` of the full log (the attestation's `log_blake3`).
    pub fn log_blake3(&self) -> [u8; 32] {
        let inner = self.inner.lock().unwrap();
        let hasher = inner.hasher.clone();
        *hasher.finalize().as_bytes()
    }

    /// The retained chunks with `seq >= from_seq` (the attach resume tail).
    pub fn tail_from(&self, from_seq: u64) -> Vec<LogChunk> {
        self.inner.lock().unwrap().ring.iter().filter(|c| c.seq >= from_seq).cloned().collect()
    }

    /// The bounded ring's current contents as flat bytes (the log tail,
    /// oldest-first) — for callers that want the raw tail, not the chunks.
    pub fn tail(&self) -> Vec<u8> {
        self.inner.lock().unwrap().ring.iter().flat_map(|c| c.bytes.iter().copied()).collect()
    }
}

impl Default for JobLogs {
    fn default() -> Self {
        Self::new()
    }
}

/// Append one framed chunk (`stream` byte + u32-LE length + bytes) to `w`.
pub fn write_framed_chunk(w: &mut impl Write, stream: u8, bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(&[stream])?;
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)?;
    Ok(())
}

/// Read framed chunks from `r` until EOF, tolerating a truncated final chunk (a
/// payload killed mid-write). Returns `(stream, bytes)` pairs.
pub fn read_framed_chunks(r: &mut impl Read) -> std::io::Result<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    loop {
        let mut head = [0u8; 5];
        let n = read_full(r, &mut head)?;
        if n == 0 {
            return Ok(out);
        }
        if n < 5 {
            return Ok(out);
        }
        let stream = head[0];
        let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
        // A corrupt/truncated length must not allocate unbounded memory.
        if len > 16 * 1024 * 1024 {
            return Ok(out);
        }
        let mut bytes = vec![0u8; len];
        if read_full(r, &mut bytes)? < len {
            return Ok(out);
        }
        out.push((stream, bytes));
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_blake3_is_over_the_full_log() {
        let logs = JobLogs::new();
        let sink = logs.sink();
        sink.push(0, b"hello ");
        sink.push(1, b"world");
        assert_eq!(logs.log_blake3(), *blake3::hash(b"hello world").as_bytes());
    }

    #[test]
    fn ring_is_bounded_to_the_tail_and_resumes_from_seq() {
        let logs = JobLogs::with_capacity(4);
        let sink = logs.sink();
        // Three 2-byte chunks; the 4-byte cap keeps only the last two chunks.
        sink.push(0, b"ab");
        sink.push(0, b"cd");
        sink.push(0, b"ef");
        assert_eq!(logs.tail(), b"cdef");
        let from1: Vec<u8> = logs.tail_from(1).into_iter().flat_map(|c| c.bytes).collect();
        assert_eq!(from1, b"cdef");
        let from2: Vec<u8> = logs.tail_from(2).into_iter().flat_map(|c| c.bytes).collect();
        assert_eq!(from2, b"ef");
        // The full-log hash still covers all three chunks.
        assert_eq!(logs.log_blake3(), *blake3::hash(b"abcdef").as_bytes());
    }

    #[test]
    fn chunks_stream_in_order_with_seq() {
        let logs = JobLogs::new();
        let rx = logs.subscribe();
        let sink = logs.sink();
        sink.push(0, b"a");
        sink.push(1, b"b");
        drop(sink);

        let mut got = Vec::new();
        while let Ok(c) = rx.try_recv() {
            got.push((c.seq, c.stream, c.bytes));
        }
        assert_eq!(got, vec![(0, 0, b"a".to_vec()), (1, 1, b"b".to_vec())]);
    }

    #[test]
    fn subscribe_and_replay_resumes_from_seq_atomically() {
        let logs = JobLogs::new();
        let sink = logs.sink();
        sink.push(0, b"a");
        sink.push(0, b"b");
        sink.push(0, b"c");
        let (rx, replay) = logs.subscribe_and_replay(1);
        let replay_bytes: Vec<u8> = replay.into_iter().flat_map(|c| c.bytes).collect();
        assert_eq!(replay_bytes, b"bc");

        // A push after subscribing arrives on rx (not replayed).
        sink.push(0, b"d");
        let mut live = Vec::new();
        while let Ok(c) = rx.try_recv() {
            live.extend_from_slice(&c.bytes);
        }
        assert_eq!(live, b"d");
    }

    #[test]
    fn framed_file_round_trips_stream_and_bytes() {
        let mut buf = Vec::new();
        write_framed_chunk(&mut buf, 0, b"out\n").unwrap();
        write_framed_chunk(&mut buf, 1, b"err\n").unwrap();
        let chunks = read_framed_chunks(&mut &buf[..]).unwrap();
        assert_eq!(
            chunks,
            vec![(0, b"out\n".to_vec()), (1, b"err\n".to_vec())]
        );
    }

    #[test]
    fn framed_file_tolerates_a_truncated_final_chunk() {
        let mut buf = Vec::new();
        write_framed_chunk(&mut buf, 0, b"hello").unwrap();
        // Truncate the trailing 3 bytes of the 5-byte body.
        buf.truncate(buf.len() - 3);
        let chunks = read_framed_chunks(&mut &buf[..]).unwrap();
        assert!(chunks.is_empty(), "a truncated chunk is dropped, not returned");
    }
}
