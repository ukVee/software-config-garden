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

use softfig_ipc::growlightd::{
    op, FleetStatusReply, ForceStopArgs, InjectMessageArgs, InjectReply, PausedReply,
    ReleaseLeaseArgs, RequestLeaseArgs, RequestRestartArgs, SetPolicyArgs, StopAfterSliceArgs,
    StopLevel, StopReply,
};
use softfig_ipc::{ErrorKind, Request, Response};

use crate::config::Policy;
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
        // Control family — all one-shot (spec §13 Control). The state they set is
        // intent the future drive loop reads at safe handoff boundaries (§8).
        op::PAUSE => write_one_shot(&mut stream, set_paused(&daemon, true)),
        op::RESUME => write_one_shot(&mut stream, set_paused(&daemon, false)),
        op::STOP_AFTER_SLICE => write_one_shot(&mut stream, stop_after_slice(&daemon, &req)),
        op::FORCE_STOP => write_one_shot(&mut stream, force_stop(&daemon, &req)),
        op::INJECT_MESSAGE => write_one_shot(&mut stream, inject_message(&daemon, &req)),
        op::SET_POLICY => write_one_shot(&mut stream, set_policy(&daemon, &req)),
        // Coordinate family — arbitrated shared-action leases (spec §4c / §14).
        // One-shot; growlightd grants/queues/denies and (for a restart) acts.
        op::REQUEST_LEASE => write_one_shot(&mut stream, request_lease(&daemon, &req)),
        op::RELEASE_LEASE => write_one_shot(&mut stream, release_lease(&daemon, &req)),
        op::REQUEST_RESTART => write_one_shot(&mut stream, request_restart(&daemon, &req)),
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

/// `status`: the fleet snapshot. Phase 1 — empty fleet, just identity, policy,
/// and the admission-gate (`paused`) state.
fn status(daemon: &Daemon) -> Response {
    let inner = daemon.inner.lock().unwrap();
    let reply = FleetStatusReply {
        state: inner.state.label().to_string(),
        garden_root: inner.config.garden_root.display().to_string(),
        protocol_version: softfig_ipc::PROTOCOL_VERSION,
        policy: inner.config.policy.summary(),
        paused: inner.control.paused,
        agents: Vec::new(),
    };
    ok_reply(&reply, "status")
}

/// `pause` / `resume`: flip the fleet admission gate and echo the new state.
/// Idempotent — the verb sets an absolute state, not a toggle.
fn set_paused(daemon: &Daemon, paused: bool) -> Response {
    let mut inner = daemon.inner.lock().unwrap();
    let paused = if paused {
        inner.control.pause()
    } else {
        inner.control.resume()
    };
    ok_reply(&PausedReply { paused }, "pause")
}

/// `stop_after_slice`: record a graceful "stop after the current slice" boundary
/// intent for one agent (spec §8 level 1). The drive loop honours it at the next
/// handoff via [`Daemon::take_pending_stop`]. One-shot ack.
fn stop_after_slice(daemon: &Daemon, req: &Request) -> Response {
    let args: StopAfterSliceArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if args.agent.is_empty() {
        return Response::err(ErrorKind::BadArgs, "agent must be non-empty");
    }
    daemon
        .inner
        .lock()
        .unwrap()
        .control
        .request_stop(&args.agent, StopLevel::AfterSlice);
    ok_reply(
        &StopReply {
            agent: args.agent,
            level: StopLevel::AfterSlice,
            immediate: false,
        },
        "stop_after_slice",
    )
}

/// `force_stop`: the leveled stop (spec §8). `after_slice`/`after_iteration`
/// record a boundary intent the drive loop reads at the next handoff;
/// `hard_kill` acts immediately via the kill-safety path
/// ([`Daemon::hard_kill_agent`]). One-shot ack either way.
fn force_stop(daemon: &Daemon, req: &Request) -> Response {
    let args: ForceStopArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if args.agent.is_empty() {
        return Response::err(ErrorKind::BadArgs, "agent must be non-empty");
    }
    if args.level.is_immediate() {
        // hard_kill: interrupt now, OUTSIDE the lock (the function enforces it).
        daemon.hard_kill_agent(&args.agent);
    } else {
        daemon
            .inner
            .lock()
            .unwrap()
            .control
            .request_stop(&args.agent, args.level);
    }
    ok_reply(
        &StopReply {
            agent: args.agent,
            level: args.level,
            immediate: args.level.is_immediate(),
        },
        "force_stop",
    )
}

/// `inject_message`: queue a message onto an agent's boundary-async inject lane,
/// delivered at the agent's NEXT baton — never mid-iteration (spec §8). Replies
/// with the lane depth after the append. One-shot.
fn inject_message(daemon: &Daemon, req: &Request) -> Response {
    let args: InjectMessageArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if args.agent.is_empty() {
        return Response::err(ErrorKind::BadArgs, "agent must be non-empty");
    }
    if args.message.is_empty() {
        return Response::err(ErrorKind::BadArgs, "message must be non-empty");
    }
    let queued = daemon
        .inner
        .lock()
        .unwrap()
        .control
        .queue_inject(&args.agent, args.message.clone());
    ok_reply(
        &InjectReply {
            agent: args.agent,
            queued,
        },
        "inject_message",
    )
}

/// `set_policy`: replace the runtime per-device policy (spec §11/§13 Control).
/// The whole policy is sent (idempotent, order-free), each field is validated
/// against its sane operating range, and a nonsense value is **rejected** with a
/// clear `BadArgs` — never silently clamped — so a GUI typo can't quietly disable
/// the fleet. On success the new policy is stored under the daemon lock (so
/// `status` and the drive loop's next admission boundary both read it) and the
/// applied [`softfig_ipc::growlightd::PolicySummary`] is echoed. One-shot.
fn set_policy(daemon: &Daemon, req: &Request) -> Response {
    let args: SetPolicyArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let policy = match Policy::from_summary(args.policy) {
        Ok(p) => p,
        Err(e) => return Response::err(ErrorKind::BadArgs, e),
    };
    daemon.set_policy(policy);
    ok_reply(&policy.summary(), "set_policy")
}

/// `request_lease`: arbitrate a lease over a shared resource/action (spec §4c).
/// growlightd grants/queues; a granted lease over a thrash-flagged target clears
/// that flag (§4d). One-shot ack carrying the resulting state.
fn request_lease(daemon: &Daemon, req: &Request) -> Response {
    let args: RequestLeaseArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if args.agent.is_empty() {
        return Response::err(ErrorKind::BadArgs, "agent must be non-empty");
    }
    if args.key.is_empty() {
        return Response::err(ErrorKind::BadArgs, "key must be non-empty");
    }
    ok_reply(&daemon.request_lease(&args.agent, &args.key), "request_lease")
}

/// `release_lease`: release a held lease, promoting the head waiter (spec §4c).
/// A release by a non-holder comes back `denied`. One-shot ack.
fn release_lease(daemon: &Daemon, req: &Request) -> Response {
    let args: ReleaseLeaseArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if args.agent.is_empty() {
        return Response::err(ErrorKind::BadArgs, "agent must be non-empty");
    }
    if args.key.is_empty() {
        return Response::err(ErrorKind::BadArgs, "key must be non-empty");
    }
    ok_reply(&daemon.release_lease(&args.agent, &args.key), "release_lease")
}

/// `request_restart`: ask growlightd to restart another agent (spec §4c/§8).
/// Arbitrated through a restart lease; a granted restart is performed by the
/// DAEMON via the kill-safety path. Self-restart is denied. One-shot ack.
fn request_restart(daemon: &Daemon, req: &Request) -> Response {
    let args: RequestRestartArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if args.requester.is_empty() {
        return Response::err(ErrorKind::BadArgs, "requester must be non-empty");
    }
    if args.target.is_empty() {
        return Response::err(ErrorKind::BadArgs, "target must be non-empty");
    }
    ok_reply(
        &daemon.request_restart(&args.requester, &args.target),
        "request_restart",
    )
}

/// Encode a typed reply as a one-shot `Response::ok`, mapping a serialization
/// failure to an `Internal` error (`what` names the verb for the message).
fn ok_reply<T: serde::Serialize>(reply: &T, what: &str) -> Response {
    match serde_json::to_value(reply) {
        Ok(v) => Response::ok(v),
        Err(e) => Response::err(ErrorKind::Internal, format!("encode {what}: {e}")),
    }
}

/// Decode a request's `args` into a typed payload, mapping a decode failure to a
/// `BadArgs` `Response` the caller returns as-is. (Fully-qualified `Result` — the
/// crate's `daemon::Result` alias is in scope here.)
fn parse_args<T: serde::de::DeserializeOwned>(
    req: &Request,
) -> std::result::Result<T, Response> {
    serde_json::from_value(req.args.clone())
        .map_err(|e| Response::err(ErrorKind::BadArgs, format!("decode args: {e}")))
}
