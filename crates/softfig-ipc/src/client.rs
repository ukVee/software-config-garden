//! Sync JSON-Lines client helpers. The daemon-side serving code lives
//! in `softfig-keeperd`; this module is consumed by the CLI's daemon
//! bridge and the MCP bridge.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::proto::{ErrorKind, Request, Response};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("decode: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("daemon error ({kind:?}): {message}")]
    Daemon { kind: ErrorKind, message: String },
    #[error("daemon closed connection without replying")]
    UnexpectedEof,
}

impl ClientError {
    /// True if the error reason is "daemon socket isn't there" — the
    /// only condition the CLI is allowed to fall back to direct mode on.
    pub fn is_daemon_absent(&self) -> bool {
        match self {
            ClientError::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ),
            _ => false,
        }
    }
}

/// Connect to the daemon socket. Sets a generous read/write timeout so a
/// hung daemon surfaces as `Io` rather than wedging the caller.
pub fn connect(path: &Path) -> Result<UnixStream, ClientError> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    Ok(stream)
}

/// Send one request, read one response. JSON-Lines framing: one JSON
/// object terminated by `\n` in each direction.
pub fn call(stream: &mut UnixStream, req: &Request) -> Result<Response, ClientError> {
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    read_response(stream)
}

/// Read one `\n`-framed response off an already-written stream. Shared by
/// `call` and the reconnecting path so the EOF / decode handling lives once.
fn read_response(stream: &mut UnixStream) -> Result<Response, ClientError> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(ClientError::UnexpectedEof);
    }
    let resp: Response = serde_json::from_str(line.trim_end_matches('\n'))?;
    Ok(resp)
}

/// Convenience: call + unwrap to the data payload, mapping daemon errors
/// to `ClientError::Daemon`.
pub fn call_data(
    stream: &mut UnixStream,
    req: &Request,
) -> Result<serde_json::Value, ClientError> {
    let resp = call(stream, req)?;
    match resp.into_result() {
        Ok(v) => Ok(v),
        Err((kind, message)) => Err(ClientError::Daemon { kind, message }),
    }
}

/// Bounds for the reconnecting retry loop used by `call_reconnecting`.
///
/// The retry exists to ride out a *transient* keeperd restart (a
/// `softfig daemon cycle`/stop/start, or a crash-respawn) without surfacing the
/// momentary socket outage to the caller. It is deliberately short-bounded: the
/// first attempt always runs, and further attempts stop once `budget` would be
/// exceeded, so a genuinely-down daemon errors promptly instead of hanging.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total wall-clock budget for the reconnect attempts.
    pub budget: Duration,
    /// Backoff before the first retry; doubles each retry, capped at `max_backoff`.
    pub initial_backoff: Duration,
    /// Cap on the per-retry backoff.
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(3),
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_millis(400),
        }
    }
}

/// Why a reconnecting call ultimately failed. The variant carries the
/// idempotency disposition so the caller never has to guess whether a retry is
/// safe.
#[derive(Debug, Error)]
pub enum ReconnectError {
    /// Never reached keeperd within the budget — every attempt failed at
    /// connect (or before the request was written). Nothing was sent, so the
    /// operation definitely did not apply.
    #[error(
        "keeperd unreachable at {} after {attempts} attempt(s) ({elapsed_ms} ms); \
         it may be down or restarting — try again in a moment ({source})",
        .socket.display()
    )]
    Unreachable {
        socket: PathBuf,
        attempts: u32,
        elapsed_ms: u128,
        #[source]
        source: ClientError,
    },
    /// The connection dropped *after* the request was sent, while reading the
    /// response. The verb may already have applied (garden write verbs commit),
    /// so this is NOT retried — the caller must verify before re-issuing.
    #[error(
        "keeperd dropped the connection at {} after the request was sent; \
         the operation may or may not have applied — verify before retrying ({source})",
        .socket.display()
    )]
    Ambiguous {
        socket: PathBuf,
        #[source]
        source: ClientError,
    },
    /// The request could not be serialized — a programmer error, never retried.
    #[error("could not encode request: {0}")]
    Encode(#[source] serde_json::Error),
}

/// Outcome of a single connect→send→receive attempt, tagged with where it
/// failed so the retry loop can apply the idempotency boundary.
enum Attempt {
    Ok(Response),
    /// Failed at connect or while writing the request — the daemon never acted
    /// on it, so a reconnecting retry is safe.
    PreSend(ClientError),
    /// Failed while reading the response — the request was already sent and may
    /// have applied, so this must not be blindly retried.
    Ambiguous(ClientError),
}

/// One connect + send (pre-framed bytes) + receive against the socket.
fn attempt(socket: &Path, framed: &[u8]) -> Attempt {
    let mut stream = match connect(socket) {
        Ok(s) => s,
        Err(e) => return Attempt::PreSend(e),
    };
    if let Err(e) = stream.write_all(framed).and_then(|_| stream.flush()) {
        return Attempt::PreSend(ClientError::Io(e));
    }
    match read_response(&mut stream) {
        Ok(resp) => Attempt::Ok(resp),
        Err(e) => Attempt::Ambiguous(e),
    }
}

/// Like [`call`], but connects per attempt and rides out a transient keeperd
/// restart by reconnecting with bounded backoff (see [`RetryPolicy`]).
///
/// Idempotency boundary: only *pre-send* failures (connect failed, or the write
/// failed before delivery) are retried — those provably did not apply. A failure
/// while reading the response is ambiguous (the verb may have committed) and is
/// surfaced as [`ReconnectError::Ambiguous`] rather than blindly retried into a
/// possible double-apply. A normal daemon-side error (`Response::Err`) is a
/// successful round-trip and is returned as `Ok(Response::Err { .. })`.
pub fn call_reconnecting(
    socket: &Path,
    req: &Request,
    policy: RetryPolicy,
) -> Result<Response, ReconnectError> {
    let mut framed = serde_json::to_vec(req).map_err(ReconnectError::Encode)?;
    framed.push(b'\n');

    let start = Instant::now();
    let mut backoff = policy.initial_backoff;
    let mut attempts: u32 = 0;
    loop {
        attempts += 1;
        match attempt(socket, &framed) {
            Attempt::Ok(resp) => return Ok(resp),
            Attempt::Ambiguous(source) => {
                return Err(ReconnectError::Ambiguous {
                    socket: socket.to_path_buf(),
                    source,
                });
            }
            Attempt::PreSend(source) => {
                let elapsed = start.elapsed();
                // Stop before sleeping past the budget; always make ≥1 attempt.
                if elapsed.saturating_add(backoff) >= policy.budget {
                    return Err(ReconnectError::Unreachable {
                        socket: socket.to_path_buf(),
                        attempts,
                        elapsed_ms: elapsed.as_millis(),
                        source,
                    });
                }
                thread::sleep(backoff);
                backoff = (backoff * 2).min(policy.max_backoff);
            }
        }
    }
}
