//! Derive the garden root from keeperd, the same way `softfig growlight start`
//! does — a read-only `status` query, never a hardcoded path (spec §2/§12).
//!
//! growlightd is itself a keeperd *client* (spec §2): it reaches the garden
//! through keeperd/MCP. Before serving anything it asks keeperd where the garden
//! is and confirms it's unlocked, reusing the shared [`softfig_ipc`] `status`
//! verb + [`StatusReply`] type — the exact seam
//! `cmd_growlight::resolve_garden_root` uses, so the two daemons can never
//! disagree on the path.
//!
//! The same reply carries keeperd's build (release-pipeline slice 002), so
//! growlightd also refuses to start against a keeperd of another build: a
//! stale daemon, or a partial install.

use std::path::{Path, PathBuf};
use std::time::Duration;

use softfig_ipc::compat::VersionMismatch;
use softfig_ipc::{connect, op, ClientError, Request, StatusReply};
use thiserror::Error;

use crate::v2_source::TipProbe;

#[derive(Debug, Error)]
pub enum HandshakeError {
    /// keeperd isn't listening on the socket. The garden must be unlocked +
    /// mounted before growlightd can serve the fleet.
    #[error(
        "no keeperd at {socket} — unlock the garden first (`softfig daemon unlock`), \
         or pass --garden-root"
    )]
    KeeperdAbsent { socket: PathBuf },
    /// keeperd answered but the garden is locked; growlightd needs the mounted
    /// garden to read protocol/baton/backlog for its agents.
    #[error("garden is {state} — unlock it first (`softfig daemon unlock`)")]
    NotUnlocked { state: String },
    /// keeperd is another build than this growlightd. Checked before the lock
    /// state, because unlocking would not make the pair work.
    #[error("{0}")]
    VersionMismatch(#[from] VersionMismatch),
    /// Transport/decode failure talking to keeperd.
    #[error("keeperd status query failed: {0}")]
    Ipc(#[from] ClientError),
    /// Response wasn't a well-formed `StatusReply`.
    #[error("malformed keeperd status reply: {0}")]
    Decode(#[from] serde_json::Error),
}

/// Query keeperd's `status` over `socket` and return the unlocked garden root.
///
/// Mirrors `cmd_growlight::resolve_garden_root`: daemon-absent and
/// not-unlocked are distinct, actionable errors; anything else surfaces raw.
pub fn garden_root_via_keeperd(socket: &Path) -> Result<PathBuf, HandshakeError> {
    let mut stream = match connect(socket) {
        Ok(s) => s,
        Err(e) if e.is_daemon_absent() => {
            return Err(HandshakeError::KeeperdAbsent {
                socket: socket.to_path_buf(),
            });
        }
        Err(e) => return Err(HandshakeError::Ipc(e)),
    };
    let req = Request::new(op::STATUS, serde_json::Value::Null);
    let resp = softfig_ipc::call(&mut stream, &req)?;
    let value = match resp.into_result() {
        Ok(v) => v,
        Err((kind, message)) => {
            return Err(HandshakeError::Ipc(ClientError::Daemon { kind, message }));
        }
    };
    let reply: StatusReply = serde_json::from_value(value)?;
    softfig_ipc::compat::version_check(&reply)?;
    if reply.state != "unlocked" {
        return Err(HandshakeError::NotUnlocked { state: reply.state });
    }
    Ok(PathBuf::from(reply.garden_root))
}

/// How long a tick waits on keeperd for its tip before assembling anyway.
/// keeperd answers `status` under the lock its commits hold, so a tick must not
/// queue behind a slow commit (the drive-loop stall family, task 042).
const TIP_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// The keeperd-backed [`TipProbe`]: one `status` round-trip per tick, bounded
/// by [`TIP_PROBE_TIMEOUT`]. No daemon, a timeout, a garden with no tip, or a
/// malformed reply is `None`, and the v2 source assembles as if unprobed.
#[derive(Debug, Clone)]
pub struct KeeperdTipProbe {
    socket: PathBuf,
}

impl KeeperdTipProbe {
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }
}

impl TipProbe for KeeperdTipProbe {
    fn tip(&self) -> Option<String> {
        let mut stream = connect(&self.socket).ok()?;
        stream.set_read_timeout(Some(TIP_PROBE_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(TIP_PROBE_TIMEOUT)).ok()?;
        let req = Request::new(op::STATUS, serde_json::Value::Null);
        let value = softfig_ipc::call(&mut stream, &req).ok()?.into_result().ok()?;
        serde_json::from_value::<StatusReply>(value).ok()?.tip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use softfig_ipc::compat::{binary_version, this_build_axes};
    use softfig_ipc::{Response, PROTOCOL_VERSION};

    /// A one-shot mock keeperd: accept one connection, read the `status`
    /// request, reply with the scripted `StatusReply` payload, exit.
    fn spawn_mock_keeperd(
        socket: PathBuf,
        reply: serde_json::Value,
    ) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let req: Request = serde_json::from_str(line.trim_end()).unwrap();
                assert_eq!(req.op, op::STATUS);
                assert_eq!(req.v, PROTOCOL_VERSION);
                let resp = Response::ok(reply);
                let mut bytes = serde_json::to_vec(&resp).unwrap();
                bytes.push(b'\n');
                stream.write_all(&bytes).unwrap();
                stream.flush().unwrap();
            }
        })
    }

    fn status_reply(state: &str, garden_root: &str) -> serde_json::Value {
        serde_json::json!({
            "state": state,
            "tip": null,
            "garden_root": garden_root,
            "protocol_version": PROTOCOL_VERSION,
            "axes": this_build_axes(1, 1),
        })
    }

    #[test]
    fn derives_root_from_unlocked_keeperd() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let h = spawn_mock_keeperd(
            socket.clone(),
            status_reply("unlocked", "/home/u/garden"),
        );
        let root = garden_root_via_keeperd(&socket).unwrap();
        assert_eq!(root, PathBuf::from("/home/u/garden"));
        h.join().unwrap();
    }

    #[test]
    fn refuses_when_locked() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let h = spawn_mock_keeperd(socket.clone(), status_reply("locked", "/g"));
        let err = garden_root_via_keeperd(&socket).unwrap_err();
        assert!(matches!(err, HandshakeError::NotUnlocked { .. }));
        h.join().unwrap();
    }

    /// A keeperd of another build is refused with the handshake's message,
    /// even when the garden is unlocked.
    #[test]
    fn refuses_a_keeperd_of_another_build() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let mut reply = status_reply("unlocked", "/g");
        reply["axes"]["binary"] = "0.0.1".into();
        let h = spawn_mock_keeperd(socket.clone(), reply);
        let err = garden_root_via_keeperd(&socket).unwrap_err();
        h.join().unwrap();
        assert!(matches!(err, HandshakeError::VersionMismatch(_)), "{err:?}");
        let msg = err.to_string();
        assert!(
            msg.starts_with(&format!(
                "your `softfig` ({}) is newer than the running daemon (0.0.1)",
                binary_version()
            )),
            "{msg}"
        );
    }

    /// A keeperd that predates the stamp reports no axes: an older build.
    #[test]
    fn refuses_a_keeperd_that_predates_the_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let mut reply = status_reply("unlocked", "/g");
        reply.as_object_mut().unwrap().remove("axes");
        let h = spawn_mock_keeperd(socket.clone(), reply);
        let err = garden_root_via_keeperd(&socket).unwrap_err();
        h.join().unwrap();
        assert!(err.to_string().contains("predates version stamping"), "{err}");
    }

    #[test]
    fn reports_keeperd_absent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nonexistent.sock");
        let err = garden_root_via_keeperd(&socket).unwrap_err();
        assert!(matches!(err, HandshakeError::KeeperdAbsent { .. }));
    }

    #[test]
    fn tip_probe_reads_the_tip_from_status() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let mut reply = status_reply("unlocked", "/g");
        reply["tip"] = serde_json::json!("abc123");
        let h = spawn_mock_keeperd(socket.clone(), reply);
        assert_eq!(KeeperdTipProbe::new(socket).tip(), Some("abc123".to_string()));
        h.join().unwrap();
    }

    #[test]
    fn tip_probe_is_none_without_a_daemon_or_a_tip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(KeeperdTipProbe::new(dir.path().join("absent.sock")).tip(), None);

        let socket = dir.path().join("keeperd.sock");
        let h = spawn_mock_keeperd(socket.clone(), status_reply("unlocked", "/g"));
        assert_eq!(KeeperdTipProbe::new(socket).tip(), None, "a garden with no tip yet");
        h.join().unwrap();
    }

    /// A keeperd stuck behind a commit must cost the tick at most the timeout.
    #[test]
    fn tip_probe_gives_up_on_a_daemon_that_does_not_answer() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(KeeperdTipProbe::new(socket).tip(), None);
        let waited = started.elapsed();
        assert!(waited >= TIP_PROBE_TIMEOUT, "it waited for an answer: {waited:?}");
        assert!(waited < TIP_PROBE_TIMEOUT * 4, "and then gave up: {waited:?}");
        drop(listener);
    }
}
