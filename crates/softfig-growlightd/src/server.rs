//! Accept loop. Binds the socket with restrictive perms, polls in a short loop
//! so `Stopping` takes effect promptly, and spawns one thread per accepted
//! connection. Mirrors keeperd's `server.rs` (same JSON-Lines framing,
//! same-uid peer check, ack-before-teardown for `shutdown`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use softfig_ipc::growlightd::{op, FleetStatusReply};
use softfig_ipc::{ErrorKind, Request, Response};

use crate::daemon::{Daemon, DaemonHandle, Result};
use crate::state::State;

const ACCEPT_POLL_MS: u64 = 100;
/// How often a `subscribe` stream wakes between events to re-check `Stopping`.
const SUBSCRIBE_POLL_MS: u64 = 200;

pub fn start(daemon: Daemon) -> Result<DaemonHandle> {
    let socket_path = daemon.socket_path();

    // Stale socket from a previous unclean exit.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let listener = UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;
    let mut perms = std::fs::metadata(&socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&socket_path, perms)?;

    let daemon_for_thread = daemon.clone();
    let socket_for_thread = socket_path.clone();
    let thread = thread::Builder::new()
        .name("growlightd-accept".into())
        .spawn(move || accept_loop(listener, daemon_for_thread, socket_for_thread))?;

    Ok(DaemonHandle {
        daemon,
        thread: Some(thread),
        socket_path,
    })
}

fn accept_loop(listener: UnixListener, daemon: Daemon, socket_path: PathBuf) -> Result<()> {
    loop {
        if daemon.state() == State::Stopping {
            break;
        }

        match listener.accept() {
            Ok((stream, _addr)) => {
                if let Err(e) = crate::peer::require_same_uid(&stream) {
                    eprintln!("growlightd: rejecting peer: {e}");
                    drop(stream);
                    continue;
                }
                let d = daemon.clone();
                thread::Builder::new()
                    .name("growlightd-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(d, stream) {
                            eprintln!("growlightd: connection error: {e}");
                        }
                    })
                    .ok();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
            Err(e) => {
                eprintln!("growlightd: accept error: {e}");
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

fn handle_connection(daemon: Daemon, mut stream: UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(());
    }

    let req = match serde_json::from_str::<Request>(line.trim_end_matches('\n')) {
        Ok(req) => req,
        Err(e) => {
            return write_one_shot(
                &mut stream,
                Response::err(ErrorKind::BadArgs, format!("decode: {e}")),
            )
        }
    };

    if req.v != softfig_ipc::PROTOCOL_VERSION {
        let msg = format!(
            "unsupported protocol version {} (want {})",
            req.v,
            softfig_ipc::PROTOCOL_VERSION
        );
        return write_one_shot(&mut stream, Response::err(ErrorKind::BadArgs, msg));
    }

    match req.op.as_str() {
        // The one streaming verb: it takes over the connection and writes
        // newline-framed `Event` objects until the client hangs up or the daemon
        // stops. Every other verb is one-shot.
        op::SUBSCRIBE => stream_subscription(&daemon, stream),
        op::STATUS => write_one_shot(&mut stream, status(&daemon)),
        // ack-before-teardown: flush the ack, THEN flip to Stopping, so the
        // client is guaranteed its reply before the accept loop winds down
        // (keeperd incident 20260622).
        op::SHUTDOWN => {
            write_one_shot(&mut stream, Response::ok(serde_json::json!({})))?;
            daemon.request_shutdown();
            Ok(())
        }
        other => write_one_shot(
            &mut stream,
            Response::err(ErrorKind::BadArgs, format!("unknown op {other:?}")),
        ),
    }
}

/// Write one `\n`-framed [`Response`] and flush — the reply path for every verb
/// except `subscribe`.
fn write_one_shot(stream: &mut UnixStream, resp: Response) -> Result<()> {
    let mut bytes = serde_json::to_vec(&resp)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// `subscribe`: hold the connection open and stream the hub's events as
/// newline-framed `Event` JSON (NOT `Response` envelopes — the client knows it
/// asked to subscribe). Ends when the client disconnects (a write fails) or the
/// daemon enters `Stopping`. All per-subscriber buffering lives in the hub, so a
/// slow client here can never stall the event producer (spec §13 Observe).
fn stream_subscription(daemon: &Daemon, mut stream: UnixStream) -> Result<()> {
    let subscription = daemon.hub.subscribe();
    loop {
        if daemon.state() == State::Stopping {
            break;
        }
        match subscription.recv_timeout(Duration::from_millis(SUBSCRIBE_POLL_MS)) {
            Ok(event) => {
                let mut bytes = serde_json::to_vec(&event)?;
                bytes.push(b'\n');
                // A write error means the client hung up — end the subscription.
                if stream.write_all(&bytes).and_then(|_| stream.flush()).is_err() {
                    break;
                }
            }
            // Periodic wake with nothing pending: loop to re-check `Stopping`.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            // Hub gone (daemon tearing down): end the stream.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

/// `status`: the fleet snapshot. Phase 1 — empty fleet, just identity + policy.
fn status(daemon: &Daemon) -> Response {
    let inner = daemon.inner.lock().unwrap();
    let reply = FleetStatusReply {
        state: inner.state.label().to_string(),
        garden_root: inner.config.garden_root.display().to_string(),
        protocol_version: softfig_ipc::PROTOCOL_VERSION,
        policy: inner.config.policy.summary(),
        agents: Vec::new(),
    };
    match serde_json::to_value(&reply) {
        Ok(v) => Response::ok(v),
        Err(e) => Response::err(ErrorKind::Internal, format!("encode status: {e}")),
    }
}
