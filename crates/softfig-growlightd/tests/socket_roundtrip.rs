//! Integration: boot growlightd on a real Unix socket, exercise the phase-1
//! IPC surface (`status` + `shutdown`) end to end, and prove clean shutdown.
//!
//! No keeperd and no agents are involved — the garden root is injected
//! directly (the `--garden-root` override path), which is exactly the seam the
//! later e2e test (slice 004) swaps a fake keeperd into.

use std::path::PathBuf;

use softfig_growlightd::{Daemon, GrowlightdConfig, Policy};
use softfig_ipc::growlightd::{op, FleetStatusReply, PolicySummary, SetPolicyArgs};
use softfig_ipc::{connect, Request};

fn boot(socket: PathBuf, garden_root: PathBuf) -> softfig_growlightd::DaemonHandle {
    let config = GrowlightdConfig::new(socket, garden_root);
    Daemon::new(config).start().expect("daemon boots")
}

fn call_status(socket: &std::path::Path) -> FleetStatusReply {
    let mut stream = connect(socket).expect("client connects");
    let req = Request::new(op::STATUS, serde_json::Value::Null);
    let resp = softfig_ipc::call(&mut stream, &req).expect("status round-trip");
    let value = resp.into_result().expect("status ok");
    serde_json::from_value(value).expect("FleetStatusReply decodes")
}

/// Call `set_policy`, returning the echoed [`PolicySummary`] on success or the
/// `(kind, message)` error the daemon refused with.
fn call_set_policy(
    socket: &std::path::Path,
    policy: PolicySummary,
) -> Result<PolicySummary, (softfig_ipc::ErrorKind, String)> {
    let mut stream = connect(socket).expect("client connects");
    let args = serde_json::to_value(SetPolicyArgs { policy }).unwrap();
    let resp = softfig_ipc::call(&mut stream, &Request::new(op::SET_POLICY, args))
        .expect("set_policy round-trip");
    resp.into_result()
        .map(|v| serde_json::from_value(v).expect("PolicySummary decodes"))
}

#[test]
fn boots_serves_status_and_shuts_down_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let garden = dir.path().join("garden");
    let handle = boot(socket.clone(), garden.clone());

    // The socket exists with 0600 perms.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket must be owner-only");

    // status: empty fleet, default policy, the injected garden root echoed.
    let reply = call_status(&socket);
    assert_eq!(reply.state, "running");
    assert_eq!(reply.garden_root, garden.display().to_string());
    assert!(reply.agents.is_empty(), "phase 1 has no agents");
    assert_eq!(reply.policy, Policy::default().summary());
    assert_eq!(reply.protocol_version, softfig_ipc::PROTOCOL_VERSION);

    // shutdown over IPC: ack arrives, then the daemon winds down on its own.
    let mut stream = connect(&socket).expect("client connects");
    let resp = softfig_ipc::call(&mut stream, &Request::new(op::SHUTDOWN, serde_json::Value::Null))
        .expect("shutdown ack");
    assert!(resp.into_result().is_ok(), "shutdown acked before teardown");

    handle.join().expect("accept loop exits cleanly");
    assert!(!socket.exists(), "socket cleaned up on shutdown");
}

#[test]
fn unknown_op_is_bad_args_not_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    let mut stream = connect(&socket).expect("client connects");
    let resp = softfig_ipc::call(&mut stream, &Request::new("nope", serde_json::Value::Null))
        .expect("round-trip");
    match resp.into_result() {
        Err((kind, _)) => assert_eq!(kind, softfig_ipc::ErrorKind::BadArgs),
        Ok(_) => panic!("unknown op should error"),
    }

    // Daemon is still alive and serving after a bad op.
    let reply = call_status(&socket);
    assert_eq!(reply.state, "running");

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn set_policy_updates_the_runtime_policy_and_status_reflects_it() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    // The daemon boots on the default policy.
    assert_eq!(call_status(&socket).policy, Policy::default().summary());

    // Apply a new runtime policy: a bigger cap + tighter rails. No more `unknown
    // op` — the handler answers and echoes the applied policy.
    let new = PolicySummary {
        max_concurrent_agents: 4,
        ctx_roll_pct: 45,
        ctx_handoff_pct: 55,
        session_5h_halt_pct: 80,
        session_7d_halt_pct: 88,
    };
    let echoed = call_set_policy(&socket, new).expect("a valid policy is accepted");
    assert_eq!(echoed, new, "the reply echoes the applied policy");

    // `status` now reflects the new runtime policy (the single source of truth was
    // updated under the daemon lock).
    assert_eq!(
        call_status(&socket).policy,
        new,
        "status reflects the new runtime policy",
    );

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn set_policy_rejects_an_out_of_range_value_and_leaves_the_policy_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    // A cap of 0 admits nothing → rejected (not clamped) with BadArgs.
    let mut bad = Policy::default().summary();
    bad.max_concurrent_agents = 0;
    let err = call_set_policy(&socket, bad).expect_err("a zero cap is rejected");
    assert_eq!(err.0, softfig_ipc::ErrorKind::BadArgs);

    // An over-100 pct rail is likewise rejected.
    let mut bad2 = Policy::default().summary();
    bad2.session_5h_halt_pct = 200;
    assert!(
        call_set_policy(&socket, bad2).is_err(),
        "an over-100 budget rail is rejected",
    );

    // After both refusals the runtime policy is unchanged — the daemon never
    // applied the nonsense values.
    assert_eq!(
        call_status(&socket).policy,
        Policy::default().summary(),
        "a rejected set_policy leaves the runtime policy unchanged",
    );

    // The daemon is still alive and serving after the bad ops.
    assert_eq!(call_status(&socket).state, "running");

    handle.shutdown();
    handle.join().unwrap();
}
