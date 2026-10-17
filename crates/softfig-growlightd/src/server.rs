//! Accept loop. Binds the socket with restrictive perms, polls in a short loop
//! so `Stopping` takes effect promptly, and spawns one thread per accepted
//! connection. Mirrors keeperd's `server.rs` (same JSON-Lines framing,
//! same-uid peer check, ack-before-teardown for `shutdown`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use std::path::Path;

use softfig_ipc::growlightd::{
    op, AgentSpendSummary, AgentSummary, BatonArgs, BatonReply, FleetStatusReply, ForceStopArgs,
    InjectMessageArgs, InjectReply, MemberCall, MemberVerbReply, PausedReply, QueuePickArgs,
    QueuePickAssignment, QueuePickReply, QueuePickSkip, RefusalCode, ReleaseLeaseArgs,
    RequestLeaseArgs, RequestRestartArgs, ResumeItemArgs, ResumeItemReply, SetPolicyArgs,
    SetResourcesArgs, SetResourcesReply, StopAfterSliceArgs, StopLevel, StopReply,
    BACKEND_CLAUDE, BACKEND_OPENCODE,
};
use softfig_ipc::model_choice::{Backend, ModelList};
use softfig_ipc::verbs::{SliceInsertArgs, SliceUpdateArgs};
use softfig_ipc::{ErrorKind, Request, Response};

use crate::agent_harness::apply_set_property;
use crate::backend_router::BackendRouter;
use crate::config::Policy;
use crate::daemon::{Daemon, DaemonHandle, Result};
use crate::drive_loop::AgentHealthSource;
use crate::fleet::{FleetMemberConfig, MemberBackend};
use crate::member_slices;
use crate::member_verbs::{self, MemberVerb, Refusal, VerbError};
use crate::scheduler_v2::{self, Member, Unit};
use crate::opencode_backend::ModelSelection;
use crate::resume::ResumeOutcome;
use crate::state::State;
use crate::supervisor::AgentHealth;

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
        // Read-only transitional bridge to the out-of-garden runtime baton.
        op::BATON => write_one_shot(&mut stream, baton(&req)),
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
        // Read-only queue-v2 surface (spec-growlight-queue §6.9): what `pick_v2`
        // assigns a member now, and why each skipped entry was skipped.
        op::QUEUE_PICK => write_one_shot(&mut stream, queue_pick(&daemon, &req)),
        // Coordinate family — arbitrated shared-action leases (spec §4c / §14).
        // One-shot; growlightd grants/queues/denies and (for a restart) acts.
        op::REQUEST_LEASE => write_one_shot(&mut stream, request_lease(&daemon, &req)),
        op::RELEASE_LEASE => write_one_shot(&mut stream, release_lease(&daemon, &req)),
        op::REQUEST_RESTART => write_one_shot(&mut stream, request_restart(&daemon, &req)),
        // Member verbs (spec-growlight-queue §6.1–§6.6) — one-shot. A refusal
        // is an ok reply with `state: refused`; it never touches the session.
        op::GROWLIGHT_ADD_FOLLOW_UP_SESSION
        | op::GROWLIGHT_COMPLETE_SLICE
        | op::GROWLIGHT_COMPLETE_ENTRY
        | op::GROWLIGHT_BLOCK
        | op::GROWLIGHT_ADD_SUB_MILESTONE => write_one_shot(&mut stream, member_verb(&daemon, &req)),
        // A member's §6.8 slice verbs (§6.7), relayed by keeperd — one-shot.
        op::MEMBER_SLICE_INSERT | op::MEMBER_SLICE_UPDATE => {
            write_one_shot(&mut stream, member_slice_verb(&daemon, &req))
        }
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

/// `status`: the fleet snapshot — identity, policy, the admission gate (`paused`),
/// the configured roster, and (on an ARMED fleet) one live row per member.
///
/// The live rows come from the registered [`BackendRouter`](crate::backend_router::BackendRouter)
/// — the same table the drive loop routes through — so a member's reported health
/// and spend are read off the backend actually serving it. A disarmed fleet has no
/// router and therefore no live rows; `roster` is the whole truth then.
///
/// Snapshots the daemon lock and **releases it** before building the per-member
/// rows: those read each backend's own cells, and taking a second lock under the
/// daemon mutex is the shape that reintroduced the keeperd deadlock class
/// (incident 20260622). The roster is a handful of members, so cloning it out is
/// cheaper than the hazard.
fn status(daemon: &Daemon) -> Response {
    let router = daemon.backend_router();
    // Everything the daemon lock owns, taken in one brief hold.
    let (state, garden_root, policy, paused, fleet_enabled, members) = {
        let inner = daemon.inner.lock().unwrap();
        (
            inner.state.label().to_string(),
            inner.config.garden_root.display().to_string(),
            inner.config.policy.summary(),
            inner.control.paused,
            inner.fleet.enabled,
            inner.fleet.members.clone(),
        )
    };
    let roster = members
        .iter()
        .map(|m| softfig_ipc::growlightd::FleetMemberSummary {
            agent: m.agent.clone(),
            pin: m.pin.clone(),
        })
        .collect();
    // One row per member of an armed fleet. `None` (disarmed) ⇒ no rows at all,
    // rather than a roster echo with invented liveness.
    let agents = match &router {
        Some(router) => members.iter().map(|m| agent_summary(m, router)).collect(),
        None => Vec::new(),
    };
    let reply = FleetStatusReply {
        state,
        garden_root,
        protocol_version: softfig_ipc::PROTOCOL_VERSION,
        policy,
        build_caps: daemon.build_caps().summary(),
        paused,
        fleet_enabled,
        roster,
        agents,
        // The genuinely-running scope units (slice 006) — independent leaf lock,
        // like build_caps above; never reconstructed CLI-side.
        live_scopes: daemon.live_scope_units(),
    };
    ok_reply(&reply, "status")
}

/// One armed member's live `status` row: its lifecycle read off the backend
/// serving it, plus — for a metered backend — that backend's spend accounting.
///
/// The backend and model come from the CONFIG (`m.backend`), not from the router:
/// they are what the operator declared, and they are known even before the member
/// first spawns. Only health and spend are live readings. Both views are built
/// from the same `fleet.members`, so they cannot name different backends.
fn agent_summary(m: &FleetMemberConfig, router: &Arc<BackendRouter>) -> AgentSummary {
    let health = AgentHealthSource::health(router, &m.agent);
    let row = AgentSummary::new(
        &m.agent,
        health_label(health),
        matches!(health, Some(AgentHealth::Alive { .. })),
    );
    match &m.backend {
        // A subscription member: no per-member dollar figure exists, and the row
        // deliberately carries no spend rather than a $0.00 that would read as
        // "metered, spent nothing" (see `AgentSummary`'s docs).
        MemberBackend::Claude => row,
        // A metered member: show what it has actually cost. `spend` is `Some` for
        // every opencode route, but the config has ALREADY established this member
        // is metered, so a missing reading is the zero accounting — never a silent
        // demotion to the unmetered posture, which would misdescribe the member.
        MemberBackend::Opencode(selection) => row.on_opencode(
            Some(model_label(selection)),
            router
                .spend(&m.agent)
                .map(|s| AgentSpendSummary {
                    micro_usd: s.micro_usd,
                    steps: s.steps,
                })
                .unwrap_or_default(),
        ),
    }
}

/// The display label for an observed [`AgentHealth`]. Pure, so it is unit-proven
/// directly.
///
/// `None` is `"idle"` — an armed member the backend has never spawned (or has
/// forgotten), which is genuinely idle rather than missing. Note what is NOT here:
/// `"hung"`. Classifying a stale `last_active` as hung needs the hang window and
/// the current instant, which are the drive loop's (it owns the clock and acts on
/// the verdict); `status` reports what it can see without re-deriving a judgement
/// it would make with different inputs.
fn health_label(health: Option<AgentHealth>) -> String {
    match health {
        None => "idle".to_string(),
        Some(AgentHealth::Alive { .. }) => "running".to_string(),
        // A clean exit is the normal baton-boundary roll, not a fault.
        Some(AgentHealth::Exited { code: 0 }) => "exited".to_string(),
        Some(AgentHealth::Exited { code }) => format!("crashed ({code})"),
    }
}

/// The operator-facing label for an opencode member's [`ModelSelection`]:
/// `<model>` or `<model> (<variant>)`. Always present, because a member cannot
/// exist without a model (the fleet refuses one at parse; opencode-v2-repin slice
/// 002).
fn model_label(selection: &ModelSelection) -> String {
    match &selection.variant {
        Some(variant) => format!("{} ({variant})", selection.model),
        None => selection.model.clone(),
    }
}

/// `baton`: read the LIVE runtime baton (read-only, transitional bridge). No
/// `agent` → the fleet/legacy single-agent runtime baton (`<growlight>/baton.md`);
/// `agent:"a"` → that member's `<growlight>/agents/<id>/baton.md`. A missing file
/// soft-fails to an empty `text` (the runtime may hold no baton yet), never an
/// error. Resolves the runtime dir from the environment (like the fleet
/// assembler) so it answers even when the fleet is disarmed and no store is
/// assembled. Stateless — takes no daemon lock.
fn baton(req: &Request) -> Response {
    let args: BatonArgs = match parse_args(req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    // Guard the member id: it becomes a single path component, so reject anything
    // that isn't a bare name (a `/`, `\`, or `.`/`..` traversal). A well-behaved
    // client only ever sends a roster id; this keeps a malformed request from
    // reading an arbitrary file rather than soft-failing to empty.
    if let Some(id) = args.agent.as_deref() {
        if !is_simple_agent_id(id) {
            return Response::err(
                ErrorKind::BadArgs,
                format!("agent id {id:?} must be a bare name (no path separators)"),
            );
        }
    }
    let dir = crate::fleet::runtime_growlight_dir();
    ok_reply(&read_runtime_baton(&dir, args.agent.as_deref()), "baton")
}

/// Whether `id` is a safe single path component for the per-member baton path: a
/// non-empty bare name, never a `.`/`..` traversal or a name carrying a path
/// separator. Pure (no IO), so the guard is unit-tested directly.
pub(crate) fn is_simple_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id != "."
        && id != ".."
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains('\0')
}

/// Resolve + read a runtime baton under `growlight_dir`: `None` → the fleet/legacy
/// single-agent baton `<growlight>/baton.md`; `Some(id)` → that member's
/// `<growlight>/agents/<id>/baton.md`. A missing file is the documented soft-fail
/// — empty `text`, never an error, never a panic. Pure but for the one read, so
/// the default / per-member / missing-file shapes are unit-tested with a temp dir.
pub(crate) fn read_runtime_baton(growlight_dir: &Path, agent: Option<&str>) -> BatonReply {
    let path = match agent {
        None => growlight_dir.join("baton.md"),
        Some(id) => growlight_dir.join("agents").join(id).join("baton.md"),
    };
    // A missing runtime baton is expected (disarmed / freshly-init'd fleet, or a
    // member that hasn't been seeded) — surface empty text, not an IO error.
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    BatonReply {
        agent: agent.map(str::to_string),
        path: path.display().to_string(),
        text,
    }
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
            // A boundary intent terminates nothing now.
            performed: false,
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
    // `hard_kill` interrupts now and reports whether it actually terminated a live
    // child (`performed`), so a no-op kill (no live agent behind the id) is never
    // reported as success — the audit-005 false-success fix. A boundary stop only
    // records an intent (terminates nothing now), so it never "performs".
    let performed = if args.level.is_immediate() {
        // OUTSIDE the lock (the function enforces it).
        daemon.hard_kill_agent(&args.agent)
    } else {
        daemon
            .inner
            .lock()
            .unwrap()
            .control
            .request_stop(&args.agent, args.level);
        false
    };
    ok_reply(
        &StopReply {
            agent: args.agent,
            level: args.level,
            immediate: args.level.is_immediate(),
            performed,
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
    //
    // Benign concurrent-set race (slice 008, acknowledged not locked): apply (cell
    // update) then the live push below are not one atomic unit, and the server runs
    // a thread per connection, so two clients (CLI + GUI) can interleave — the cell
    // may end as caps-B while a running scope's `set-property` landed caps-A, until
    // the next (re)spawn re-reads the cell. Soft-throttle-only and self-healing, so
    // we deliberately do NOT hold a lock across the subprocess push (that would
    // reintroduce the keeperd deadlock class, incident 20260622); lock-ordering wins.
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

/// A queue-v2 member verb (spec-growlight-queue §6.3): the identity from the
/// envelope, the caller's live v2 assignment (the drive loop's mirror), then
/// [`member_verbs::validate`] over a fresh read of the v2 list. Every refusal
/// is an ok [`MemberVerbReply`] with `state: refused` and leaves the calling
/// session untouched — nothing here signals, kills or rolls it. A pass runs
/// step 3 ([`crate::member_handoff::execute`]: keeperd commits, the baton is
/// stored as the entry's) and replies `ok` with what runs next; the drive loop
/// then ends the session after the grace and picks (steps 4–5).
///
/// The v2 list is read through the mount without the daemon lock (the drive
/// loop's own read path), so a slow read never blocks another verb.
pub(crate) fn member_verb(daemon: &Daemon, req: &Request) -> Response {
    let (member, verb) = match decode_member_verb(req) {
        Ok(decoded) => decoded,
        Err(resp) => return resp,
    };
    let name = verb.name();
    let refused = |r: Refusal| ok_reply(&MemberVerbReply::refused(name, r.code, r.message), name);
    let member = match member_verbs::identity(member.as_deref()) {
        Ok(member) => member.to_string(),
        Err(r) => return refused(r),
    };
    let Some(assignment) = daemon.v2_assignment(&member) else {
        return refused(member_verbs::no_assignment(&member));
    };
    let snapshot = match crate::v2_source::assemble(&daemon.garden_root()) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return refused(Refusal {
                code: RefusalCode::NotYourSession,
                message: "there is no queue-v2 list (growlight/backlog/queue.toml), so no \
                          session holds a v2 entry"
                    .into(),
            })
        }
        Err(e) => {
            return Response::err(
                ErrorKind::Io,
                format!("{name}: the queue-v2 list can't be read, so the call can't be validated: {e}"),
            )
        }
    };
    // §9's `urgent_waiting` is not in this build (it rides the bus overhaul),
    // so growlightd has told no member to yield: a `preempted` roll counts
    // toward the cap like any other (review R2). When the message lands, this
    // reads the drive loop's record of whom it told, consumed at the handshake.
    let told_to_yield = false;
    let v = match member_verbs::validate(&member, &assignment, &snapshot, verb, told_to_yield) {
        Ok(v) => v,
        Err(VerbError::Refused(r)) => return refused(r),
        Err(VerbError::BadArgs(m)) => {
            return Response::err(ErrorKind::BadArgs, format!("{name}: {m}"))
        }
    };
    let unit = member_verbs::unit_label(&v.assignment.unit);
    let Some(seams) = daemon.v2_handoff_seams() else {
        return Response::err(
            ErrorKind::Internal,
            format!(
                "{name}: growlightd has no handshake seams installed, so it can't commit a \
                 handoff — nothing was written and this session keeps running"
            ),
        );
    };
    // §6.3 step 3. Take the assignment out of the mirror first, so a second
    // verb from the same session can't validate against work this one moves.
    if !daemon.begin_v2_handoff(&member, &assignment) {
        return refused(Refusal {
            code: RefusalCode::NotYourSession,
            message: format!(
                "this session's handoff is already under way or done — member {member} \
                 no longer holds {} / {unit}",
                assignment.entry
            ),
        });
    }
    match crate::member_handoff::execute(&v, &snapshot, &seams) {
        Ok(done) => {
            for w in &done.warnings {
                eprintln!("growlightd: {name} for {member} on {}: {w}", v.assignment.entry);
            }
            let reply = MemberVerbReply::ok(
                name,
                v.assignment.entry.clone(),
                unit,
                done.next,
                done.warnings,
            );
            daemon.commit_v2_handoff(&member, done.handoff);
            ok_reply(&reply, name)
        }
        Err(e) => {
            daemon.abort_v2_handoff(&member, assignment);
            Response::err(ErrorKind::Io, format!("{name}: {e}"))
        }
    }
}

/// A member's `slice_insert` / `slice_update`, relayed by keeperd (§6.7):
/// the identity, the member's live assignment and — for an insert's subset
/// rule — a fresh read of the v2 list, then [`member_slices`]'s checks. A pass
/// issues the plain human verb to keeperd as growlightd's own client and
/// relays keeperd's response verbatim; a refusal is a wire error led by its
/// code, like any §6.8 refusal. Nothing here touches the calling session.
pub(crate) fn member_slice_verb(daemon: &Daemon, req: &Request) -> Response {
    let refused = |message: String| Response::err(ErrorKind::BadArgs, message);
    let (member, human) = match req.op.as_str() {
        op::MEMBER_SLICE_INSERT => match parse_args::<MemberCall<SliceInsertArgs>>(req) {
            Ok(call) => (call.member, HumanSliceVerb::Insert(call.args)),
            Err(resp) => return resp,
        },
        _ => match parse_args::<MemberCall<SliceUpdateArgs>>(req) {
            Ok(call) => (call.member, HumanSliceVerb::Update(call.args)),
            Err(resp) => return resp,
        },
    };
    let member = match member_verbs::identity(member.as_deref()) {
        Ok(member) => member.to_string(),
        Err(r) => return refused(format!("{}: {}", r.code.as_str(), r.message)),
    };
    let assignment = daemon.v2_assignment(&member);
    let checked = match &human {
        HumanSliceVerb::Insert(args) => {
            let snapshot = match crate::v2_source::assemble(&daemon.garden_root()) {
                Ok(snapshot) => snapshot.unwrap_or_default(),
                Err(e) => {
                    return Response::err(
                        ErrorKind::Io,
                        format!(
                            "slice_insert: the queue-v2 list can't be read, so the call can't be \
                             validated: {e}"
                        ),
                    )
                }
            };
            member_slices::check_insert(&member, assignment.as_ref(), &snapshot, args)
        }
        HumanSliceVerb::Update(args) => {
            member_slices::check_update(&member, assignment.as_ref(), args)
        }
    };
    if let Err(message) = checked {
        return refused(message);
    }
    let Some(seams) = daemon.v2_handoff_seams() else {
        return Response::err(
            ErrorKind::Internal,
            "growlightd has no keeperd seam installed, so it can't issue the slice verb — \
             nothing was written",
        );
    };
    let relayed = match &human {
        HumanSliceVerb::Insert(args) => {
            serde_json::to_value(args).map(|a| Request::new(softfig_ipc::op::SLICE_INSERT, a))
        }
        HumanSliceVerb::Update(args) => {
            serde_json::to_value(args).map(|a| Request::new(softfig_ipc::op::SLICE_UPDATE, a))
        }
    };
    match relayed {
        Ok(req) => seams.keeper.relay(&req),
        Err(e) => Response::err(ErrorKind::Internal, format!("encode the slice verb: {e}")),
    }
}

/// `queue pick` (spec-growlight-queue §6.9): **read-only**. Runs the same
/// [`scheduler_v2::pick_v2`] the drive loop runs — over a fresh read of the v2
/// list with the loop's published runtime overlay applied — and returns the
/// assignment plus every skipped entry with its reason.
///
/// growlightd answers it because `pick_v2` and the v2 source live here
/// (milestone finding 6), not in the CLI. Two reads matter:
/// - the **roster** is cloned under one brief lock: a named member's pin and
///   backend come from it, and an unnamed member is unpinned on the default
///   backend;
/// - the **list** is read through the mount *without* the daemon lock — the
///   same path the member verbs take, so a slow read never blocks another verb.
///
/// A named member that is not on the roster is a `BadArgs` refusal, not an
/// empty pick: guessing a pin would answer a different question than the one
/// asked.
pub(crate) fn queue_pick(daemon: &Daemon, req: &Request) -> Response {
    let args = match parse_args::<QueuePickArgs>(req) {
        Ok(args) => args,
        Err(resp) => return resp,
    };
    let members = {
        let inner = daemon.inner.lock().unwrap();
        inner.fleet.members.clone()
    };
    let member = match resolve_pick_member(&members, args.member.as_deref()) {
        Ok(member) => member,
        Err(message) => {
            return Response::err(ErrorKind::BadArgs, format!("queue_pick: {message}"))
        }
    };
    let base = QueuePickReply {
        // §3.4: a garden with no v2 file shows nothing, and does so as a reply —
        // not an error — exactly like `queue show`.
        list: false,
        member: args.member.clone(),
        pin: member.pin.clone(),
        backend: backend_label(&member.backend).to_string(),
        picked: None,
        skips: Vec::new(),
    };
    let mut snapshot = match crate::v2_source::assemble(&daemon.garden_root()) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return ok_reply(&base, "queue_pick"),
        Err(e) => {
            return Response::err(
                ErrorKind::Io,
                format!("queue_pick: the queue-v2 list can't be read: {e}"),
            )
        }
    };
    // The runtime holders and accepted model changes, as of the loop's last tick
    // — the same overlay the loop's own pick sees (slice 012).
    crate::drive_loop::apply_v2_overlay(&mut snapshot, &daemon.v2_overlay());
    let outcome = scheduler_v2::pick_v2(&snapshot, &member);
    let reply = QueuePickReply {
        list: true,
        picked: outcome.picked.map(|p| QueuePickAssignment {
            entry: p.entry,
            unit: pick_unit_label(&p.unit),
            declared: p.declared.as_ref().map(declared_label),
        }),
        skips: outcome
            .skips
            .into_iter()
            .map(|s| QueuePickSkip {
                entry: s.entry,
                reason: s.reason.as_str().to_string(),
                detail: s.reason.describe().to_string(),
            })
            .collect(),
        ..base
    };
    ok_reply(&reply, "queue_pick")
}

/// The member a pick runs for: a roster row (its id, backend and pin), or an
/// unnamed unpinned member on the default backend.
///
/// The unnamed member's id is the empty string, which no roster agent can be
/// (ids are non-empty), so it never matches a live holder: another member's
/// `active` entry reads as held, which is the truth for *this* member.
fn resolve_pick_member(
    members: &[FleetMemberConfig],
    requested: Option<&str>,
) -> std::result::Result<Member, String> {
    let Some(id) = requested else {
        return Ok(Member {
            id: String::new(),
            backend: Backend::Claude,
            pin: None,
        });
    };
    let Some(row) = members.iter().find(|m| m.agent == id) else {
        let roster = if members.is_empty() {
            "the roster is empty".to_string()
        } else {
            format!(
                "the roster is: {}",
                members
                    .iter()
                    .map(|m| m.agent.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        return Err(format!("no fleet member {id:?} on the roster — {roster}"));
    };
    Ok(Member {
        id: row.agent.clone(),
        backend: row.backend.ipc_backend(),
        pin: row.pin.clone(),
    })
}

/// The wire/CLI label for a member's backend.
fn backend_label(backend: &Backend) -> &'static str {
    match backend {
        Backend::Claude => BACKEND_CLAUDE,
        Backend::Opencode => BACKEND_OPENCODE,
    }
}

/// A picked unit, for a reader: `slice 002 of m1` (a sub-milestone's slice names
/// `m1/sub`), `the close-out of m1`, or `the entry itself` for a task/restack.
fn pick_unit_label(unit: &Unit) -> String {
    match unit {
        Unit::Slice { milestone, slice } => format!("slice {slice} of {milestone}"),
        Unit::CloseOut { milestone } => format!("the close-out of {milestone}"),
        Unit::Entry => "the entry itself".to_string(),
    }
}

/// A unit's declared `> Model:` list, comma-separated, as `queue pick` prints
/// it: `claude`, `provider/model`, or `provider/model variant=<v>`.
fn declared_label(list: &ModelList) -> String {
    list.entries()
        .iter()
        .map(|choice| match (&choice.model, &choice.variant) {
            (None, _) => BACKEND_CLAUDE.to_string(),
            (Some(model), Some(variant)) => format!("{model} variant={variant}"),
            (Some(model), None) => model.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The human slice verb a member's relayed call carries.
enum HumanSliceVerb {
    Insert(SliceInsertArgs),
    Update(SliceUpdateArgs),
}

/// Decode a member verb's [`MemberCall`] envelope by op: the identity it
/// carries and the typed verb.
fn decode_member_verb(
    req: &Request,
) -> std::result::Result<(Option<String>, MemberVerb), Response> {
    fn take<A: serde::de::DeserializeOwned>(
        req: &Request,
        wrap: fn(A) -> MemberVerb,
    ) -> std::result::Result<(Option<String>, MemberVerb), Response> {
        let call: MemberCall<A> = parse_args(req)?;
        Ok((call.member, wrap(call.args)))
    }
    match req.op.as_str() {
        op::GROWLIGHT_ADD_FOLLOW_UP_SESSION => take(req, MemberVerb::AddFollowUpSession),
        op::GROWLIGHT_COMPLETE_SLICE => take(req, MemberVerb::CompleteSlice),
        op::GROWLIGHT_COMPLETE_ENTRY => take(req, MemberVerb::CompleteEntry),
        op::GROWLIGHT_BLOCK => take(req, MemberVerb::Block),
        op::GROWLIGHT_ADD_SUB_MILESTONE => take(req, MemberVerb::AddSubMilestone),
        other => Err(Response::err(
            ErrorKind::BadArgs,
            format!("{other:?} is not a member verb"),
        )),
    }
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
    use crate::config::{BuildCaps, GrowlightdConfig};
    use crate::persist::ResourcePersister;
    use std::sync::{Arc, Mutex};

    /// A spy [`ResourcePersister`] (slice 009): records every `persist` call's caps
    /// and returns a configurable result, so the `set_resources` swallow path
    /// (invariant 5) is proven without a live keeperd.
    #[derive(Debug)]
    struct SpyPersister {
        fail: bool,
        calls: Mutex<Vec<BuildCaps>>,
    }
    impl SpyPersister {
        fn new(fail: bool) -> Arc<Self> {
            Arc::new(Self { fail, calls: Mutex::new(Vec::new()) })
        }
    }
    impl ResourcePersister for SpyPersister {
        fn persist(&self, caps: &BuildCaps) -> std::result::Result<(), String> {
            self.calls.lock().unwrap().push(caps.clone());
            if self.fail {
                Err("spy: keeperd unreachable".into())
            } else {
                Ok(())
            }
        }
    }

    fn test_daemon_with(persister: Arc<SpyPersister>) -> Daemon {
        Daemon::new(GrowlightdConfig::new("/run/g.sock".into(), "/garden".into()))
            .with_resource_persister(persister)
    }

    /// A member's relayed slice verb (§6.7): identity, then the member's own
    /// entry, then keeperd as growlightd's own client — the relayed request
    /// is the plain human verb with no member on it, and keeperd's reply comes
    /// back verbatim. A refusal is a wire error led by its code and relays
    /// nothing.
    #[test]
    fn a_members_slice_verb_is_checked_then_relayed_to_keeperd_as_a_human_verb() {
        use crate::member_handoff::{tests::SpyKeeper, HandoffSeams};
        use crate::scheduler_v2::Unit;
        let garden = tempfile::tempdir().unwrap();
        let spy = Arc::new(SpyKeeper::default());
        let daemon = Daemon::new(GrowlightdConfig::new("/run/g.sock".into(), garden.path().into()))
            .with_v2_handoff(HandoffSeams {
                keeper: Box::new(spy.clone()),
                entries: crate::baton_store::FsEntryBatonStore::new(garden.path().join("e"), "g"),
            });
        let assignment = crate::drive_loop::V2Assignment {
            agent: "c".into(),
            entry: "m1".into(),
            unit: Unit::Slice { milestone: "m1".into(), slice: "001".into() },
            resolved_model: softfig_ipc::model_choice::ModelChoice::claude(),
        };
        daemon.publish_v2_assignments(&std::iter::once(("c".to_string(), assignment)).collect());

        let call = |member: Option<&str>, op_: &str, args: serde_json::Value| {
            let mut envelope = serde_json::json!({ "args": args });
            if let Some(member) = member {
                envelope["member"] = member.into();
            }
            member_slice_verb(&daemon, &Request::new(op_, envelope))
        };
        let refusal = |resp: Response| match resp {
            Response::Err { kind, error, .. } => {
                assert_eq!(kind, ErrorKind::BadArgs, "{error}");
                error
            }
            Response::Ok { data, .. } => panic!("expected a refusal, got {data}"),
        };
        let insert = |milestone: &str| serde_json::json!({ "milestone": milestone, "slug": "found", "body": "work" });
        let mv = |id: &str| serde_json::json!({ "milestone": "m1", "id": id, "move": { "to": "front" } });

        let e = refusal(call(None, op::MEMBER_SLICE_INSERT, insert("m1")));
        assert!(e.starts_with("not_a_member:"), "{e}");
        let e = refusal(call(Some("z"), op::MEMBER_SLICE_INSERT, insert("m1")));
        assert!(e.starts_with("member_not_allowed:") && e.contains("holds no v2 entry"), "{e}");
        let e = refusal(call(Some("c"), op::MEMBER_SLICE_INSERT, insert("m2")));
        assert!(e.starts_with("member_not_allowed:") && e.contains("outside"), "{e}");
        let e = refusal(call(Some("c"), op::MEMBER_SLICE_UPDATE, mv("001")));
        assert!(e.contains("own active slice"), "{e}");
        assert!(spy.relayed.lock().unwrap().is_empty(), "a refusal relays nothing");

        for (op_, args, human) in [
            (op::MEMBER_SLICE_INSERT, insert("m1/sub"), softfig_ipc::op::SLICE_INSERT),
            (op::MEMBER_SLICE_UPDATE, mv("002"), softfig_ipc::op::SLICE_UPDATE),
        ] {
            let resp = call(Some("c"), op_, args.clone());
            assert!(matches!(&resp, Response::Ok { data, .. } if data["relayed"] == human), "{resp:?}");
            let relayed = spy.relayed.lock().unwrap().pop().expect("relayed");
            assert_eq!((relayed.op.as_str(), relayed.member.as_deref()), (human, None));
            assert_eq!(relayed.args["milestone"], args["milestone"], "the human verb's own args");
        }
    }

    /// A claude + opencode roster, the shape slice 006's status surface has to make
    /// legible: `a`/`d` on the subscription pool, `b`/`c` metered on their own
    /// models.
    fn mixed_fleet() -> crate::fleet::FleetConfig {
        crate::fleet::FleetConfig::from_growlight_toml(concat!(
            "fleet_enabled = true\n",
            "claude_bin = \"claude\"\n",
            "opencode_bin = \"opencode\"\n",
            "prompt = \"kick\"\n",
            "[[fleet]]\nagent = \"a\"\n",
            "[[fleet]]\nagent = \"b\"\nbackend = \"opencode\"\n",
            "model = \"deepseek/deepseek-flash\"\nvariant = \"high\"\n",
            "[[fleet]]\nagent = \"c\"\nbackend = \"opencode\"\n",
            "model = \"deepseek/deepseek-v4-pro\"\n",
            "[[fleet]]\nagent = \"d\"\nbackend = \"claude\"\n",
        ))
        .expect("a mixed roster is valid")
    }

    /// Decode a `status` response's reply payload.
    fn status_reply(daemon: &Daemon) -> FleetStatusReply {
        let data = status(daemon)
            .into_result()
            .expect("status succeeds");
        serde_json::from_value(data).expect("the reply decodes")
    }

    #[test]
    fn status_renders_a_metered_member_with_its_spend_and_no_reserve_gauge() {
        // Slice 006's user-visible deliverable, and the end of the long-standing
        // `agents (none)` display: `agents` was a hardcoded `Vec::new()`, so an armed
        // fleet reported "0 agent(s) running (roster: a)" however many members were
        // live, and a metered member had nowhere to show what it had cost — the
        // operator saw an Anthropic reserve surface with nothing in it and read the
        // member as broken.
        //
        // Goes through `assemble_fleet`, so what `status` reads is the router the
        // drive loop routes through — not a second reconstruction that could name a
        // different backend for the same member.
        let daemon = test_daemon_with(SpyPersister::new(false));
        daemon.set_fleet_config(mixed_fleet());
        let _loop = crate::fleet::assemble_fleet(&daemon, &mixed_fleet(), Path::new("/run/k.sock"))
            .expect("an armed mixed roster assembles");

        // `b` bills some real work; `c` stays untouched, so it is a metered member
        // that has not billed yet (a distinct case from `b` — see below).
        let router = daemon.backend_router().expect("assembly registered the router");
        match router.backend_for("b").expect("a roster member is routed") {
            crate::backend_router::BackendHandle::Opencode(b) => {
                b.accrue_spend_for_test("b", 0.14)
            }
            crate::backend_router::BackendHandle::Claude(_) => {
                unreachable!("b is configured as an opencode member")
            }
        }

        let reply = status_reply(&daemon);
        assert_eq!(reply.agents.len(), 4, "every armed member gets a row");
        assert_eq!(
            reply.agents.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["a", "b", "c", "d"],
            "rows follow config order, like the roster",
        );

        // The metered member reads as "opencode · <model> · $0.14".
        let b = &reply.agents[1];
        assert_eq!(b.backend, softfig_ipc::growlightd::BACKEND_OPENCODE);
        assert_eq!(b.model.as_deref(), Some("deepseek/deepseek-flash (high)"));
        let spend = b.spend.expect("a metered member carries its spend");
        assert_eq!(spend.micro_usd, 140_000);
        assert_eq!(spend.steps, 1);
        assert_eq!(spend.dollars(), "$0.14");

        // A metered member that has never billed still shows the METERED posture —
        // `$0.00`, zero steps. That is not the empty reserve gauge: it is a correct
        // reading of a member that has not spent anything, and it names the pool it
        // *will* spend from. (Zero steps, not one: a zero-cost `step_finish` would
        // still count a step, so `steps == 0` means genuinely nothing observed.)
        let c = &reply.agents[2];
        assert_eq!(c.backend, softfig_ipc::growlightd::BACKEND_OPENCODE);
        assert_eq!(c.model.as_deref(), Some("deepseek/deepseek-v4-pro"));
        assert_eq!(c.spend, Some(AgentSpendSummary::default()));

        // And the subscription members carry NO spend field at all — not a $0.00.
        // Their cost is the shared 5h/7d reserve on the policy line, which is a
        // fleet-level reading; a per-member dollar figure there would be invented.
        for claude_member in [&reply.agents[0], &reply.agents[3]] {
            assert_eq!(claude_member.backend, softfig_ipc::growlightd::BACKEND_CLAUDE);
            assert_eq!(claude_member.model, None);
            assert_eq!(
                claude_member.spend, None,
                "{} is on the subscription pool: no metered spend, which is not \
                 the same as $0.00",
                claude_member.id,
            );
        }

        // Nothing has spawned, so nothing is running — the row exists without
        // claiming liveness, which is what keeps the "N agent(s) running" count
        // honest now that idle members are rows too.
        assert!(
            reply.agents.iter().all(|a| !a.running),
            "an un-spawned member is a row, not a running agent",
        );
        assert_eq!(
            reply.agents.iter().map(|a| a.status.as_str()).collect::<Vec<_>>(),
            ["idle"; 4],
        );
    }

    #[test]
    fn a_disarmed_fleet_reports_its_roster_and_no_live_rows() {
        // The complement: with the gate off growlightd assembles nothing, so there is
        // no router and no live state to report. `agents` stays empty — the honest
        // answer — and `roster` carries the configured fleet, exactly as it did
        // before this slice. A roster echo under `agents` would claim liveness the
        // daemon cannot observe.
        let daemon = test_daemon_with(SpyPersister::new(false));
        let mut disarmed = mixed_fleet();
        disarmed.enabled = false;
        daemon.set_fleet_config(disarmed);

        let reply = status_reply(&daemon);
        assert!(!reply.fleet_enabled);
        assert!(reply.agents.is_empty(), "a disarmed fleet has no live rows");
        assert_eq!(reply.roster.len(), 4, "the configured roster still reports");
    }

    #[test]
    fn health_label_reports_what_it_observed_and_never_guesses_hung() {
        // `None` is "idle" (an armed member the backend has not spawned), a clean
        // exit is the normal baton-boundary roll rather than a fault, and a non-zero
        // exit names its code so the operator can match it to the stderr tail.
        assert_eq!(health_label(None), "idle");
        assert_eq!(health_label(Some(AgentHealth::Alive { last_active: 7 })), "running");
        assert_eq!(health_label(Some(AgentHealth::Exited { code: 0 })), "exited");
        assert_eq!(health_label(Some(AgentHealth::Exited { code: 1 })), "crashed (1)");
        // Deliberately absent: "hung". Classifying a stale `last_active` needs the
        // hang window and the current instant, which are the drive loop's — a
        // second, differently-fed judgement here could disagree with the one the
        // fleet actually acts on.
        assert_eq!(
            health_label(Some(AgentHealth::Alive { last_active: 0 })),
            "running",
            "status reports liveness, it does not re-derive the hang verdict",
        );
    }

    #[test]
    fn model_label_names_the_model_and_any_variant() {
        assert_eq!(
            model_label(&ModelSelection::model("deepseek/deepseek-flash")),
            "deepseek/deepseek-flash",
        );
        assert_eq!(
            model_label(&ModelSelection::model("deepseek/deepseek-flash").with_variant("high")),
            "deepseek/deepseek-flash (high)",
        );
    }

    fn call_set_resources(daemon: &Daemon, args: SetResourcesArgs) -> Response {
        let req = Request::new(op::SET_RESOURCES, serde_json::to_value(args).unwrap());
        set_resources(daemon, &req)
    }

    #[test]
    fn a_persist_failure_is_logged_and_swallowed_not_failing_the_verb() {
        // Invariant 5 (slice 009): a keeperd persist that errors must NOT fail the
        // live `set_resources` — the running fleet already took the new caps. The
        // spy returns Err; the verb still returns Ok and the attempt was recorded.
        let spy = SpyPersister::new(true);
        let daemon = test_daemon_with(Arc::clone(&spy));
        let resp = call_set_resources(
            &daemon,
            SetResourcesArgs { build_jobs: Some(4), ..Default::default() },
        );
        assert!(
            matches!(resp, Response::Ok { .. }),
            "a persist Err is swallowed — the verb still succeeds: {resp:?}",
        );
        assert_eq!(spy.calls.lock().unwrap().len(), 1, "the persist was attempted once");
        // The live default still took the change despite the failed persist.
        assert_eq!(daemon.build_caps().cargo_build_jobs, Some(4));
    }

    #[test]
    fn a_successful_persist_is_invoked_once_with_the_merged_caps() {
        // The mirror case: an Ok spy is called exactly once, with the FULL merged
        // caps (the partial update folded onto the live defaults).
        let spy = SpyPersister::new(false);
        let daemon = test_daemon_with(Arc::clone(&spy));
        let resp = call_set_resources(
            &daemon,
            SetResourcesArgs { build_jobs: Some(4), ..Default::default() },
        );
        assert!(matches!(resp, Response::Ok { .. }));
        let calls = spy.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "persist invoked exactly once");
        assert_eq!(calls[0].cargo_build_jobs, Some(4), "the changed knob");
        assert_eq!(calls[0].memory_high.as_deref(), Some("3G"), "the merged (untouched) default");
        assert_eq!(calls[0].cpu_weight, Some(50), "the merged (untouched) default");
    }

    #[test]
    fn baton_reads_the_default_runtime_baton() {
        // No agent → `<growlight>/baton.md`, contents surfaced verbatim.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("baton.md"), "# NEXT ACTION\ngo").unwrap();
        let reply = read_runtime_baton(tmp.path(), None);
        assert_eq!(reply.agent, None, "the default read echoes no agent");
        assert!(reply.path.ends_with("/baton.md"), "resolves the legacy root baton: {}", reply.path);
        assert!(!reply.path.contains("/agents/"), "the default baton is NOT under agents/");
        assert_eq!(reply.text, "# NEXT ACTION\ngo");
    }

    #[test]
    fn baton_reads_a_per_member_baton() {
        // `agent:"a"` → `<growlight>/agents/a/baton.md`.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("agents").join("a");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("baton.md"), "member a baton").unwrap();
        let reply = read_runtime_baton(tmp.path(), Some("a"));
        assert_eq!(reply.agent.as_deref(), Some("a"), "echoes the requested member");
        assert!(reply.path.ends_with("/agents/a/baton.md"), "per-member path: {}", reply.path);
        assert_eq!(reply.text, "member a baton");
    }

    #[test]
    fn baton_missing_file_soft_fails_to_empty_text_not_an_error() {
        // The documented soft-fail: an absent runtime baton is empty text, never
        // an error and never a panic — for both the default and per-member reads.
        let tmp = tempfile::tempdir().unwrap();
        let default = read_runtime_baton(tmp.path(), None);
        assert!(default.text.is_empty(), "a missing default baton → empty text");
        assert!(default.path.ends_with("/baton.md"), "the path is still reported: {}", default.path);

        let member = read_runtime_baton(tmp.path(), Some("ghost"));
        assert!(member.text.is_empty(), "a missing per-member baton → empty text");
        assert_eq!(member.agent.as_deref(), Some("ghost"));
    }

    #[test]
    fn baton_verb_rejects_a_traversal_agent_id() {
        // A malformed agent id (path traversal) is a BadArgs refusal, so the verb
        // can never read an arbitrary file behind an `agent` arg. A clean id
        // (missing baton) still soft-fails to Ok/empty.
        let bad = Request::new(op::BATON, serde_json::json!({ "agent": "../../etc/passwd" }));
        assert!(matches!(baton(&bad), Response::Err { .. }), "traversal id refused");
        assert!(!is_simple_agent_id("../x"));
        assert!(!is_simple_agent_id("a/b"));
        assert!(!is_simple_agent_id(".."));
        assert!(!is_simple_agent_id(""));
        assert!(is_simple_agent_id("a"));
        assert!(is_simple_agent_id("builder"));
    }

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
