//! Integration: boot growlightd on a real Unix socket, exercise the phase-1
//! IPC surface (`status` + `shutdown`) end to end, and prove clean shutdown.
//!
//! No keeperd and no agents are involved — the garden root is injected
//! directly (the `--garden-root` override path), which is exactly the seam the
//! later e2e test (slice 004) swaps a fake keeperd into.

use std::path::PathBuf;

use softfig_growlightd::{BuildCaps, Daemon, GrowlightdConfig, Policy};
use softfig_ipc::growlightd::{
    op, FleetStatusReply, PolicySummary, SetPolicyArgs, SetResourcesArgs, SetResourcesReply,
};
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

/// Call `set_resources`, returning the reply on success or the `(kind, message)`
/// the daemon refused with.
fn call_set_resources(
    socket: &std::path::Path,
    args: SetResourcesArgs,
) -> Result<SetResourcesReply, (softfig_ipc::ErrorKind, String)> {
    let mut stream = connect(socket).expect("client connects");
    let args = serde_json::to_value(args).unwrap();
    let resp = softfig_ipc::call(&mut stream, &Request::new(op::SET_RESOURCES, args))
        .expect("set_resources round-trip");
    resp.into_result()
        .map(|v| serde_json::from_value(v).expect("SetResourcesReply decodes"))
}

/// slice 011: this proves the NEXT-SPAWN + `status` path on a DISARMED fleet — NOT
/// the live `set-property` push. With no running scopes there is nothing to
/// `set-property` on, so the genuine live push (a property landing on a running
/// agent's cgroup) is the on-device §7b check, never this test. The name says so.
#[test]
fn set_resources_updates_the_next_spawn_default_and_status_disarmed() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    // No fleet config set ⇒ disarmed, empty roster ⇒ no live `set-property` shells
    // out (so this test never touches a real `systemctl`).
    let handle = boot(socket.clone(), dir.path().join("garden"));

    // The daemon boots on the conservative default caps.
    assert_eq!(call_status(&socket).build_caps, BuildCaps::default().summary());

    // A partial update: bump MemoryHigh + CPUWeight, leave build_jobs untouched.
    let reply = call_set_resources(
        &socket,
        SetResourcesArgs {
            build_jobs: None,
            memory_high: Some("6G".into()),
            cpu_weight: Some(70),
        },
    )
    .expect("a valid update is accepted");
    assert_eq!(reply.build_caps.memory_high.as_deref(), Some("6G"));
    assert_eq!(reply.build_caps.cpu_weight, Some(70));
    assert_eq!(reply.build_caps.cargo_build_jobs, Some(2), "untouched knob kept");
    // Disarmed fleet ⇒ no running scopes ⇒ nothing applied live; the surface is
    // shaped from the DELTA (slice 004), so the two CHANGED live props fall to
    // next-spawn and the UNTOUCHED build_jobs reports NOTHING (the old code wrongly
    // reported CARGO_BUILD_JOBS off the always-Some merged caps).
    assert!(reply.scopes_targeted.is_empty(), "no running scopes to push to");
    assert_eq!(reply.scopes_applied, 0, "no scope took the update");
    assert!(reply.applied_live.is_empty(), "nothing live with no scopes");
    assert_eq!(
        reply.next_spawn,
        vec!["MemoryHigh".to_string(), "CPUWeight".to_string()],
        "the two changed live props fall to next-spawn; untouched build_jobs is silent",
    );

    // `status` now reflects the new live default (what the next spawn throttles with).
    let after = call_status(&socket).build_caps;
    assert_eq!(after.memory_high.as_deref(), Some("6G"));
    assert_eq!(after.cpu_weight, Some(70));

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn set_resources_rejects_a_hard_cap_style_value_and_leaves_the_caps_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    // A 0 parallel-rustc cap (would stall the build) is rejected, not clamped.
    let err = call_set_resources(
        &socket,
        SetResourcesArgs { build_jobs: Some(0), ..Default::default() },
    )
    .expect_err("a 0 build_jobs is rejected");
    assert_eq!(err.0, softfig_ipc::ErrorKind::BadArgs);

    // An out-of-range CPUWeight is likewise rejected.
    assert!(
        call_set_resources(
            &socket,
            SetResourcesArgs { cpu_weight: Some(50_000), ..Default::default() },
        )
        .is_err(),
        "an out-of-range cpu_weight is rejected",
    );

    // slice 001 (HIGH): a malformed memory_high (systemd wants `3G`, not `3GB`) is
    // refused at the verb boundary with BadArgs — never stored/persisted/committed,
    // so it can't poison the config and fail-close every later spawn.
    let err = call_set_resources(
        &socket,
        SetResourcesArgs { memory_high: Some("3GB".into()), ..Default::default() },
    )
    .expect_err("a malformed memory_high is rejected");
    assert_eq!(err.0, softfig_ipc::ErrorKind::BadArgs);

    // After all refusals the live caps are unchanged (the daemon never applied the
    // nonsense values) — the throttle-not-kill invariant holds.
    assert_eq!(
        call_status(&socket).build_caps,
        BuildCaps::default().summary(),
        "a rejected set_resources leaves the live caps unchanged",
    );
    assert_eq!(call_status(&socket).state, "running");

    handle.shutdown();
    handle.join().unwrap();
}
