//! Integration: boot growlightd on a real Unix socket and drive the control
//! family (`pause`/`resume`, `stop_after_slice`, `force_stop`, `inject_message`)
//! end to end. Each verb is one-shot (a single `Response`); the state it sets is
//! intent the future drive loop reads at a safe handoff boundary, which we assert
//! through the daemon's drive-loop accessors — NOT wall-clock timing (spec §8).
//!
//! No keeperd and no live agent are involved: the garden root is injected and
//! the per-agent control map is addressable by id with nothing behind the key —
//! exactly the phase-1 seam slice 004's e2e swaps a fake agent backend into.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use softfig_growlightd::{Daemon, GrowlightdConfig, ItemResumer, ResumeOutcome};
use softfig_ipc::connect;
use softfig_ipc::growlightd::{
    op, FleetStatusReply, InjectReply, PausedReply, ResumeItemReply, StopLevel, StopReply,
};
use softfig_ipc::{ErrorKind, Request};

fn boot(socket: PathBuf, garden: PathBuf) -> softfig_growlightd::DaemonHandle {
    Daemon::new(GrowlightdConfig::new(socket, garden))
        .start()
        .expect("daemon boots")
}

/// Boot growlightd with a scripted item-resume hook installed (in production
/// `main` installs the live `KeeperdItemResumer` over keeperd's socket; the e2e
/// swaps a fake so the `resume_item` verb is driven without a live keeperd).
fn boot_with_resumer(
    socket: PathBuf,
    garden: PathBuf,
    resumer: Arc<dyn ItemResumer>,
) -> softfig_growlightd::DaemonHandle {
    Daemon::new(GrowlightdConfig::new(socket, garden))
        .with_item_resumer(resumer)
        .start()
        .expect("daemon boots")
}

/// A fake `ItemResumer`: returns a scripted [`ResumeOutcome`] per item id
/// (default [`ResumeOutcome::NotFound`]) and records every `(item, queue)` call so
/// the test can assert the verb routed the args through.
#[derive(Debug, Default)]
struct ScriptedResumer {
    outcomes: HashMap<String, ResumeOutcome>,
    calls: Mutex<Vec<(String, Option<String>)>>,
}

impl ScriptedResumer {
    fn with(outcomes: Vec<(&str, ResumeOutcome)>) -> Arc<Self> {
        Arc::new(Self {
            outcomes: outcomes.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            calls: Mutex::new(Vec::new()),
        })
    }
    fn calls(&self) -> Vec<(String, Option<String>)> {
        self.calls.lock().unwrap().clone()
    }
}

impl ItemResumer for ScriptedResumer {
    fn resume_item(&self, item: &str, queue: Option<&str>) -> ResumeOutcome {
        self.calls
            .lock()
            .unwrap()
            .push((item.to_string(), queue.map(str::to_string)));
        self.outcomes
            .get(item)
            .cloned()
            .unwrap_or(ResumeOutcome::NotFound)
    }
}

/// One-shot call: connect, send the verb, decode the `data` payload as `T`.
fn call_ok<T: serde::de::DeserializeOwned>(
    socket: &std::path::Path,
    op: &str,
    args: serde_json::Value,
) -> T {
    let mut stream = connect(socket).expect("client connects");
    let resp =
        softfig_ipc::call(&mut stream, &Request::new(op, args)).expect("verb round-trip");
    let value = resp.into_result().expect("verb ok");
    serde_json::from_value(value).expect("reply decodes")
}

fn call_err(
    socket: &std::path::Path,
    op: &str,
    args: serde_json::Value,
) -> softfig_ipc::ErrorKind {
    let mut stream = connect(socket).expect("client connects");
    let resp =
        softfig_ipc::call(&mut stream, &Request::new(op, args)).expect("verb round-trip");
    match resp.into_result() {
        Err((kind, _)) => kind,
        Ok(_) => panic!("expected an error reply"),
    }
}

fn status(socket: &std::path::Path) -> FleetStatusReply {
    call_ok(socket, op::STATUS, serde_json::Value::Null)
}

#[test]
fn pause_and_resume_flip_the_admission_gate_and_surface_in_status() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    assert!(!status(&socket).paused, "starts un-paused");

    let r: PausedReply = call_ok(&socket, op::PAUSE, serde_json::Value::Null);
    assert!(r.paused);
    assert!(status(&socket).paused, "pause surfaces in status");
    assert!(handle.daemon.is_paused(), "drive loop sees the gate");

    // Idempotent: pausing again stays paused.
    let r: PausedReply = call_ok(&socket, op::PAUSE, serde_json::Value::Null);
    assert!(r.paused);

    let r: PausedReply = call_ok(&socket, op::RESUME, serde_json::Value::Null);
    assert!(!r.paused);
    assert!(!status(&socket).paused, "resume clears the gate");

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn stop_after_slice_records_a_boundary_intent_read_once_by_the_drive_loop() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    let reply: StopReply =
        call_ok(&socket, op::STOP_AFTER_SLICE, serde_json::json!({ "agent": "loop-1" }));
    assert_eq!(reply.agent, "loop-1");
    assert_eq!(reply.level, StopLevel::AfterSlice);
    assert!(!reply.immediate, "a graceful stop is a boundary intent, not immediate");

    // The drive loop reads the intent at the next handoff — exactly once.
    assert_eq!(handle.daemon.take_pending_stop("loop-1"), Some(StopLevel::AfterSlice));
    assert_eq!(handle.daemon.take_pending_stop("loop-1"), None, "honoured once");

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn force_stop_boundary_levels_record_intent_hard_kill_acts_immediately() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    // after_iteration → boundary intent the drive loop reads at the next handoff.
    let reply: StopReply = call_ok(
        &socket,
        op::FORCE_STOP,
        serde_json::json!({ "agent": "loop-1", "level": "after_iteration" }),
    );
    assert_eq!(reply.level, StopLevel::AfterIteration);
    assert!(!reply.immediate);
    assert_eq!(
        handle.daemon.take_pending_stop("loop-1"),
        Some(StopLevel::AfterIteration)
    );

    // hard_kill → acts immediately; phase 1 has no live child, so nothing is
    // killed, but the verb succeeds and reports it acted now (not a boundary).
    let reply: StopReply = call_ok(
        &socket,
        op::FORCE_STOP,
        serde_json::json!({ "agent": "loop-1", "level": "hard_kill" }),
    );
    assert_eq!(reply.level, StopLevel::HardKill);
    assert!(reply.immediate, "hard_kill is the immediate escape hatch");
    // A hard kill is NOT a boundary intent — it leaves no pending stop behind.
    assert_eq!(handle.daemon.take_pending_stop("loop-1"), None);

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn inject_message_is_boundary_async_delivered_only_on_the_next_baton() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    let r: InjectReply =
        call_ok(&socket, op::INJECT_MESSAGE, serde_json::json!({ "agent": "loop-1", "message": "rebase first" }));
    assert_eq!(r.queued, 1, "lane depth after the first append");
    let r: InjectReply =
        call_ok(&socket, op::INJECT_MESSAGE, serde_json::json!({ "agent": "loop-1", "message": "then run tests" }));
    assert_eq!(r.queued, 2, "lane depth grows");

    // Boundary-async: the messages are invisible mid-iteration — the only way to
    // see them is the drive loop's boundary drain, which delivers them FIFO once.
    assert_eq!(
        handle.daemon.drain_inject_lane("loop-1"),
        vec!["rebase first".to_string(), "then run tests".to_string()],
    );
    assert!(
        handle.daemon.drain_inject_lane("loop-1").is_empty(),
        "delivered once — the next baton boundary sees an empty lane",
    );

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn control_verbs_reject_an_empty_target_and_an_empty_message() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    use softfig_ipc::ErrorKind::BadArgs;
    assert_eq!(call_err(&socket, op::STOP_AFTER_SLICE, serde_json::json!({ "agent": "" })), BadArgs);
    assert_eq!(
        call_err(&socket, op::FORCE_STOP, serde_json::json!({ "agent": "", "level": "after_slice" })),
        BadArgs,
    );
    assert_eq!(
        call_err(&socket, op::INJECT_MESSAGE, serde_json::json!({ "agent": "a1", "message": "" })),
        BadArgs,
    );
    // A malformed level is a decode error → BadArgs, not a crash.
    assert_eq!(
        call_err(&socket, op::FORCE_STOP, serde_json::json!({ "agent": "a1", "level": "nope" })),
        BadArgs,
    );

    // Still serving after the rejections.
    assert_eq!(status(&socket).state, "running");

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn resume_item_unblocks_a_blocked_item_and_routes_the_queue_arg() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let resumer = ScriptedResumer::with(vec![(
        "019",
        ResumeOutcome::Resumed { queue: "default".into() },
    )]);
    let handle = boot_with_resumer(
        socket.clone(),
        dir.path().join("garden"),
        Arc::clone(&resumer) as Arc<dyn ItemResumer>,
    );

    // A blocked item flips to queued — the scheduler re-picks it (no retire).
    let reply: ResumeItemReply = call_ok(
        &socket,
        op::RESUME_ITEM,
        serde_json::json!({ "item": "019", "queue": "build" }),
    );
    assert!(reply.resumed, "a blocked item is un-blocked");
    assert_eq!(reply.item, "019");
    assert_eq!(reply.queue, "default");
    assert_eq!(reply.status, "queued");

    // The verb routed item + queue through to the hook (CLI/GUI → growlightd →
    // keeperd path), preserving the disambiguating queue.
    assert_eq!(
        resumer.calls(),
        vec![("019".to_string(), Some("build".to_string()))],
    );

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn resume_item_is_idempotent_on_an_already_queued_item() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let resumer = ScriptedResumer::with(vec![(
        "t1",
        ResumeOutcome::AlreadyQueued { queue: "default".into() },
    )]);
    let handle = boot_with_resumer(
        socket.clone(),
        dir.path().join("garden"),
        resumer as Arc<dyn ItemResumer>,
    );

    // Already queued → a no-op success (resumed: false), not an error.
    let reply: ResumeItemReply =
        call_ok(&socket, op::RESUME_ITEM, serde_json::json!({ "item": "t1" }));
    assert!(!reply.resumed, "an already-queued item is an idempotent no-op");
    assert_eq!(reply.status, "queued");

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn resume_item_guards_a_non_blocked_item_and_an_empty_item() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let resumer = ScriptedResumer::with(vec![(
        "t1",
        ResumeOutcome::NotBlocked { queue: "default".into(), status: "active".into() },
    )]);
    let handle = boot_with_resumer(
        socket.clone(),
        dir.path().join("garden"),
        resumer as Arc<dyn ItemResumer>,
    );

    // The guard: only a blocked item un-blocks — a non-blocked one is a clear
    // refusal (un-blocking a done/active item would corrupt it).
    assert_eq!(
        call_err(&socket, op::RESUME_ITEM, serde_json::json!({ "item": "t1" })),
        ErrorKind::BadArgs,
    );
    // An unknown item (the scripted default) is NotFound.
    assert_eq!(
        call_err(&socket, op::RESUME_ITEM, serde_json::json!({ "item": "ghost" })),
        ErrorKind::NotFound,
    );
    // An empty item is rejected server-side before the hook is consulted.
    assert_eq!(
        call_err(&socket, op::RESUME_ITEM, serde_json::json!({ "item": "" })),
        ErrorKind::BadArgs,
    );

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn resume_item_with_no_hook_installed_is_unreachable() {
    // The default boot installs no resumer (no keeperd binding): the verb reports
    // it as unavailable (an Io error), never a silent success.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    assert_eq!(
        call_err(&socket, op::RESUME_ITEM, serde_json::json!({ "item": "019" })),
        ErrorKind::Io,
    );

    handle.shutdown();
    handle.join().unwrap();
}
