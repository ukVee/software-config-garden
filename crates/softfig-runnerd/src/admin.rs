//! The admin unix socket: the only local channel that can change runner state.
//!
//! `softfig runner grant|revoke|apply|enable|disable|…` talk to runnerd over
//! this socket. It accepts **only the configured owner uid** (the laptop
//! owner), checked with `SO_PEERCRED` on every connection — the socket file is
//! left world-connectable (0666) so the owner (a *different* uid from
//! `softfig-runner`) can reach it, and the credential check is the boundary.
//! No root is needed after install.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One admin request. `verb` names the operation; `args` is the verb's payload.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminRequest {
    pub verb: String,
    #[serde(default)]
    pub args: serde_json::Value,
}

/// One admin response. `ok: true` plus `data`, or `ok: false` plus `error`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl AdminResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

#[allow(unsafe_code)]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into `cred`, which is
    // sized exactly `len`. `fd` outlives the call (we hold the `UnixStream`),
    // and getsockopt is MT-safe.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// `Ok(())` if the peer's uid equals the configured owner uid; `Err` in every
/// other case (a foreign uid, or the `getsockopt` call itself failing).
pub fn require_owner_uid(stream: &UnixStream, owner_uid: u32) -> io::Result<()> {
    let them = peer_uid(stream)?;
    if them == owner_uid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("admin peer uid {them} is not the owner uid {owner_uid}"),
        ))
    }
}

/// The bound admin socket. Owns the listener and the owner uid it gates on.
pub struct AdminSocket {
    listener: UnixListener,
    owner_uid: u32,
}

impl AdminSocket {
    /// Bind at `path`, removing any stale socket first. The socket file is made
    /// world-connectable (0666); `SO_PEERCRED` is the actual gate.
    pub fn bind(path: &Path, owner_uid: u32) -> io::Result<Self> {
        if path.exists() {
            fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        Ok(Self { listener, owner_uid })
    }

    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// Accept connections and serve each with `dispatch`, one at a time. A
    /// connection whose peer is not the owner uid is dropped without a byte.
    pub fn run<F>(&self, mut dispatch: F) -> io::Result<()>
    where
        F: FnMut(&AdminRequest) -> AdminResponse,
    {
        for stream in self.listener.incoming() {
            let stream = stream?;
            // Drop on a foreign uid; the requester just sees a closed socket.
            if serve_connection(stream, self.owner_uid, &mut dispatch).is_err() {
                continue;
            }
        }
        Ok(())
    }
}

/// Serve a single connection: enforce the owner-uid gate, then answer one
/// newline-delimited JSON request per line. Exposed for unit testing the gate.
pub fn serve_connection<F>(
    stream: UnixStream,
    owner_uid: u32,
    dispatch: &mut F,
) -> io::Result<()>
where
    F: FnMut(&AdminRequest) -> AdminResponse,
{
    // The gate: a non-owner peer is refused before anything is read.
    require_owner_uid(&stream, owner_uid)?;

    let reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    for line in reader.lines() {
        let line = line?;
        let resp = match serde_json::from_str::<AdminRequest>(&line) {
            Ok(req) => dispatch(&req),
            Err(e) => AdminResponse::err(format!("bad request: {e}")),
        };
        serde_json::to_writer(&mut writer, &resp)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[allow(unsafe_code)]
    fn current_uid() -> u32 {
        // SAFETY: `geteuid` takes no arguments and returns a plain integer.
        unsafe { libc::geteuid() }
    }

    /// Start a server on a temp socket and return its path + owner uid, so the
    /// test can connect and assert the gate.
    fn bind_temp(dir: &Path, owner_uid: u32) -> std::path::PathBuf {
        let path = dir.join("admin.sock");
        let sock = AdminSocket::bind(&path, owner_uid).unwrap();
        std::thread::spawn(move || {
            let _ = sock.run(|req| match req.verb.as_str() {
                "ping" => AdminResponse::ok(serde_json::json!({"pong": true})),
                other => AdminResponse::err(format!("unknown verb {other}")),
            });
        });
        path
    }

    fn call(path: &Path, verb: &str) -> Option<AdminResponse> {
        let mut stream = UnixStream::connect(path).ok()?;
        writeln!(stream, "{}", serde_json::json!({"verb": verb})).ok()?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).ok()?;
        serde_json::from_str::<AdminResponse>(&line).ok()
    }

    #[test]
    fn owner_uid_is_served() {
        let dir = tempfile::tempdir().unwrap();
        let path = bind_temp(dir.path(), current_uid());
        let resp = call(&path, "ping").expect("owner should be served");
        assert!(resp.ok);
        assert_eq!(resp.data, Some(serde_json::json!({"pong": true})));
    }

    #[test]
    fn foreign_uid_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        // A uid that is not (and cannot be) the test process's own.
        let path = bind_temp(dir.path(), current_uid().wrapping_add(1_000_000));
        // The connection either fails outright or is closed without a reply.
        match UnixStream::connect(&path) {
            Ok(mut stream) => {
                stream.write_all(b"{\"verb\":\"ping\"}\n").unwrap();
                let mut buf = String::new();
                let n = BufReader::new(stream).read_line(&mut buf).unwrap_or(0);
                assert_eq!(n, 0, "foreign uid must receive no response, got {buf:?}");
            }
            Err(_) => { /* refused at connect time is also fine */ }
        }
    }

    #[test]
    fn unknown_verb_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = bind_temp(dir.path(), current_uid());
        let resp = call(&path, "nonsense").expect("owner should be served");
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("unknown verb"));
    }
}
