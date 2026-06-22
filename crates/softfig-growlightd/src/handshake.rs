//! Derive the garden root from keeperd, the same way `softfig growlight start`
//! does — a read-only `status` query, never a hardcoded path (spec §2/§12).
//!
//! growlightd is itself a keeperd *client* (spec §2): it reaches the garden
//! through keeperd/MCP. Before serving anything it asks keeperd where the garden
//! is and confirms it's unlocked, reusing the shared [`softfig_ipc`] `status`
//! verb + [`StatusReply`] type — the exact seam
//! `cmd_growlight::resolve_garden_root` uses, so the two daemons can never
//! disagree on the path.

use std::path::{Path, PathBuf};

use softfig_ipc::{connect, op, ClientError, Request, StatusReply};
use thiserror::Error;

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
    if reply.state != "unlocked" {
        return Err(HandshakeError::NotUnlocked { state: reply.state });
    }
    Ok(PathBuf::from(reply.garden_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

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

    #[test]
    fn reports_keeperd_absent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nonexistent.sock");
        let err = garden_root_via_keeperd(&socket).unwrap_err();
        assert!(matches!(err, HandshakeError::KeeperdAbsent { .. }));
    }
}
