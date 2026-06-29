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
    ReleaseLeaseArgs, RequestLeaseArgs, RequestRestartArgs, ResumeItemArgs, ResumeItemReply,
    SetPolicyArgs, SetResourcesArgs, SetResourcesReply, StopAfterSliceArgs, StopLevel, StopReply,
};
use softfig_ipc::{ErrorKind, Request, Response};

use crate::claude_backend::apply_set_property;
use crate::config::Policy;
use crate::daemon::{Daemon, DaemonHandle, Result};
use crate::resume::ResumeOutcome;
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
        op::SET_RESOURCES => write_one_shot(&mut stream, set_resources(&daemon, &req)),
        op::RESUME_ITEM => write_one_shot(&mut stream, resume_item(&daemon, &req)),
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
    let roster = inner
        .fleet
        .members
        .iter()
        .map(|m| softfig_ipc::growlightd::FleetMemberSummary {
            agent: m.agent.clone(),
            pin: m.pin.clone(),
        })
        .collect();
    let reply = FleetStatusReply {
        state: inner.state.label().to_string(),
        garden_root: inner.config.garden_root.display().to_string(),
        protocol_version: softfig_ipc::PROTOCOL_VERSION,
        policy: inner.config.policy.summary(),
        build_caps: daemon.build_caps().summary(),
        paused: inner.control.paused,
        fleet_enabled: inner.fleet.enabled,
        roster,
        agents: Vec::new(),
        // The genuinely-running scope units (slice 006) — independent leaf lock,
        // like build_caps above; never reconstructed CLI-side.
        live_scopes: daemon.live_scope_units(),
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

/// `set_resources`: adjust the GENTLE per-agent build-resource caps LIVE
/// (peer-isolation slice 003). A **partial** update — each omitted knob keeps its
/// current value. Every set value is validated against its sane range and a
/// nonsense value is **rejected** with a clear `BadArgs`, never clamped
/// ([`crate::config::BuildCaps::with_update`]); the args carry no hard-cap knob, so
/// the change is throttle-not-kill by construction.
///
/// Two effects, surfaced in the reply (the now-vs-next-spawn distinction):
/// 1. the merged caps become the live default the NEXT spawn throttles with
///    (stored on the shared cell the backend reads), and
/// 2. the live scope properties (`MemoryHigh`/`CPUWeight`) are pushed onto every
///    RUNNING agent scope immediately via `systemctl --user set-property
///    --runtime` — best-effort, OUTSIDE the daemon lock (the kill-safety
///    lock-ordering discipline). `CARGO_BUILD_JOBS` is an env var, so it is
///    reported under `next_spawn`, never pushed live.
fn set_resources(daemon: &Daemon, req: &Request) -> Response {
    let args: SetResourcesArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    // Validate + merge + store the next-spawn default. A nonsense value is rejected
    // here and the live caps are left unchanged.
    let new = match daemon.apply_resources(&args) {
        Ok(caps) => caps,
        Err(e) => return Response::err(ErrorKind::BadArgs, e),
    };

    // Push the live scope properties onto every running agent scope (best-effort).
    // We hold NO daemon lock here, so each `systemctl set-property` subprocess runs
    // outside the lock (incident 20260622 lock-ordering). A scope that isn't running
    // is a harmless miss; a disarmed fleet (empty roster) targets nothing.
    let scopes_targeted = daemon.live_scope_units();
    let live_succeeded = scopes_targeted
        .iter()
        .filter(|unit| apply_set_property(unit, &new))
        .count();

    // Shape the now-vs-next-spawn surface from the operator's DELTA (`args`, the
    // knobs they actually sent) + the REAL live outcome (`live_succeeded`), not the
    // full merged caps (slice 004): a build-jobs-only change must not report
    // MemoryHigh/CPUWeight it never touched, and a memory-only change must not report
    // CARGO_BUILD_JOBS. A changed live prop lands in `applied_live` only when a
    // running scope took it; otherwise it falls to `next_spawn`.
    let (applied_live, next_spawn) = shape_set_resources_effects(&args, live_succeeded);

    // Persist the new default into `config/growlight.toml` via keeperd so it
    // survives a daemon restart (peer-isolation slice 003a-persist). Best-effort +
    // OUTSIDE the daemon lock (we hold none here, the kill-safety lock-ordering
    // discipline): the running fleet has already taken the new caps, so a persist
    // failure must NOT fail the verb — we log it and carry on. A `None` hook (a
    // test, or no keeperd socket) skips the persist entirely.
    if let Some(persister) = daemon.persister.as_ref() {
        if let Err(e) = persister.persist(&new) {
            eprintln!(
                "growlightd set_resources: persist to config/growlight.toml failed \
                 (live adjust kept): {e}"
            );
        }
    }

    ok_reply(
        &SetResourcesReply {
            build_caps: new.summary(),
            applied_live,
            next_spawn,
            scopes_applied: live_succeeded,
            scopes_targeted,
        },
        "set_resources",
    )
}

/// Shape the now-vs-next-spawn surface of a `set_resources` reply PURELY from the
/// operator's delta (`args` — the knobs they actually sent) and the live push
/// outcome (`live_applied` = how many running scopes took it) — slice 004. So a
/// build-jobs-only change never reports MemoryHigh/CPUWeight, and a memory-only
/// change never reports CARGO_BUILD_JOBS. Returns `(applied_live, next_spawn)`.
///
/// - `CARGO_BUILD_JOBS` is an env var ⇒ always NEXT-spawn (when `build_jobs` changed).
/// - `MemoryHigh` / `CPUWeight` are scope properties ⇒ applied LIVE when changed AND
///   at least one running scope took the push; otherwise (no scope took it — a
///   disarmed fleet, or a push that failed everywhere) they fall to next-spawn.
///
/// Pure (no shell-out, no daemon), so the reporting branches are unit-tested
/// directly — and slice 003's "targeted but all failed" reporting rides on it.
pub(crate) fn shape_set_resources_effects(
    args: &SetResourcesArgs,
    live_applied: usize,
) -> (Vec<String>, Vec<String>) {
    let mut applied_live = Vec::new();
    let mut next_spawn = Vec::new();
    if args.build_jobs.is_some() {
        next_spawn.push("CARGO_BUILD_JOBS".to_string());
    }
    let landed = live_applied > 0;
    for (changed, name) in [
        (args.memory_high.is_some(), "MemoryHigh"),
        (args.cpu_weight.is_some(), "CPUWeight"),
    ] {
        if changed {
            if landed {
                applied_live.push(name.to_string());
            } else {
                next_spawn.push(name.to_string());
            }
        }
    }
    (applied_live, next_spawn)
}

/// `resume_item`: un-block a human-parked backlog item (`blocked → queued`) so
/// the scheduler re-picks it (fleet-member-model slice 004) — the inverse of the
/// drive loop's item-park, and **distinct from `resume`** (the fleet-wide
/// admission gate). growlightd reads the item's current status from keeperd and
/// only un-blocks a currently-`blocked` item (the guard); the typed
/// [`ResumeOutcome`] is mapped to an Ok [`ResumeItemReply`] (resumed, or an
/// idempotent already-`queued` no-op) or a clear `Response::Err` (missing /
/// non-blocked / ambiguous / keeperd unreachable). One-shot.
fn resume_item(daemon: &Daemon, req: &Request) -> Response {
    let args: ResumeItemArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if args.item.is_empty() {
        return Response::err(ErrorKind::BadArgs, "item must be non-empty");
    }
    // An empty `queue` string is treated as "no queue" (resolve across all).
    let queue = args.queue.as_deref().filter(|q| !q.is_empty());
    match daemon.resume_item(&args.item, queue) {
        // The two success shapes: the flip we performed, or an already-queued
        // item (idempotent no-op). Both echo `status: "queued"`.
        ResumeOutcome::Resumed { queue } => ok_reply(
            &ResumeItemReply {
                item: args.item,
                queue,
                status: "queued".to_string(),
                resumed: true,
            },
            "resume_item",
        ),
        ResumeOutcome::AlreadyQueued { queue } => ok_reply(
            &ResumeItemReply {
                item: args.item,
                queue,
                status: "queued".to_string(),
                resumed: false,
            },
            "resume_item",
        ),
        // The guard: only a blocked item un-blocks. A different status is a clear
        // refusal (un-blocking a `done` item would corrupt it), not a silent no-op.
        ResumeOutcome::NotBlocked { queue, status } => Response::err(
            ErrorKind::BadArgs,
            format!(
                "item {:?} in queue {queue:?} is {status}, not blocked; \
                 resume only un-blocks a blocked item",
                args.item
            ),
        ),
        ResumeOutcome::NotFound => Response::err(
            ErrorKind::NotFound,
            format!("no backlog item with id {:?} to resume", args.item),
        ),
        ResumeOutcome::Ambiguous { queues } => Response::err(
            ErrorKind::BadArgs,
            format!(
                "item id {:?} exists in multiple queues ({}); pass --queue to disambiguate",
                args.item,
                queues.join(", ")
            ),
        ),
        ResumeOutcome::Unreachable { reason } => Response::err(ErrorKind::Io, reason),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_resources_effects_are_shaped_from_the_delta_not_the_merged_caps() {
        // build-jobs-only change: ONLY CARGO_BUILD_JOBS is next-spawn — never
        // MemoryHigh/CPUWeight the operator didn't touch (slice 004, the bug was
        // reporting off the always-Some merged caps).
        let jobs_only = SetResourcesArgs { build_jobs: Some(4), ..Default::default() };
        assert_eq!(
            shape_set_resources_effects(&jobs_only, 2),
            (vec![], vec!["CARGO_BUILD_JOBS".to_string()]),
            "a build-jobs-only change reports only CARGO_BUILD_JOBS",
        );

        // memory-only change WITH a scope that took it → applied_live=[MemoryHigh],
        // and crucially next_spawn is empty (no spurious CARGO_BUILD_JOBS).
        let mem_only = SetResourcesArgs { memory_high: Some("6G".into()), ..Default::default() };
        assert_eq!(
            shape_set_resources_effects(&mem_only, 1),
            (vec!["MemoryHigh".to_string()], vec![]),
            "a memory-only change applied live reports only MemoryHigh",
        );

        // memory-only change with NO running scope taking it (disarmed / all-failed)
        // → it falls to next-spawn, not applied_live.
        assert_eq!(
            shape_set_resources_effects(&mem_only, 0),
            (vec![], vec!["MemoryHigh".to_string()]),
            "a live prop no scope took falls to next-spawn",
        );

        // All three set, live scopes took the props: MemoryHigh+CPUWeight live,
        // CARGO_BUILD_JOBS next-spawn.
        let all = SetResourcesArgs {
            build_jobs: Some(4),
            memory_high: Some("6G".into()),
            cpu_weight: Some(70),
        };
        assert_eq!(
            shape_set_resources_effects(&all, 3),
            (
                vec!["MemoryHigh".to_string(), "CPUWeight".to_string()],
                vec!["CARGO_BUILD_JOBS".to_string()],
            ),
        );
    }
}
