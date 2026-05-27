//! Sync JSON-Lines client helpers. The daemon-side serving code lives
//! in `softfig-keeperd`; this module is consumed by the CLI's daemon
//! bridge and the MCP bridge.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

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
