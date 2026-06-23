//! Integration: boot growlightd on a real Unix socket and drive the coordinate
//! family's lease verbs (`request_lease`/`release_lease`/`request_restart`) end
//! to end (spec §4c/§14). growlightd grants/queues/denies; a restart is
//! arbitrated and (would be) performed by the DAEMON. No keeperd and no live
//! agent are involved — the arbitration is pure state the verbs round-trip.

use std::path::PathBuf;

use softfig_growlightd::{Daemon, GrowlightdConfig};
use softfig_ipc::connect;
use softfig_ipc::growlightd::{op, LeaseReply, RestartReply};
use softfig_ipc::Request;

fn boot(socket: PathBuf, garden: PathBuf) -> softfig_growlightd::DaemonHandle {
    Daemon::new(GrowlightdConfig::new(socket, garden))
        .start()
        .expect("daemon boots")
}

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

#[test]
fn a_lease_is_granted_free_queued_when_held_and_handed_on_at_release() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));
    let key = "dock.rs §Layout";

    // Free → granted to the first requester.
    let r: LeaseReply = call_ok(
        &socket,
        op::REQUEST_LEASE,
        serde_json::json!({ "agent": "a", "key": key }),
    );
    assert_eq!(r.state, "granted");
    assert_eq!(r.holder.as_deref(), Some("a"));

    // Held by another → queued behind the holder.
    let r: LeaseReply = call_ok(
        &socket,
        op::REQUEST_LEASE,
        serde_json::json!({ "agent": "b", "key": key }),
    );
    assert_eq!(r.state, "waiting");
    assert_eq!(r.position, Some(1));
    assert_eq!(r.holder.as_deref(), Some("a"));

    // a releases → b is promoted to holder.
    let r: LeaseReply = call_ok(
        &socket,
        op::RELEASE_LEASE,
        serde_json::json!({ "agent": "a", "key": key }),
    );
    assert_eq!(r.state, "released");
    assert_eq!(r.holder.as_deref(), Some("b"));

    // A non-holder release is denied.
    let r: LeaseReply = call_ok(
        &socket,
        op::RELEASE_LEASE,
        serde_json::json!({ "agent": "a", "key": key }),
    );
    assert_eq!(r.state, "denied");
    assert_eq!(r.holder.as_deref(), Some("b"));

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn request_restart_is_arbitrated_and_self_restart_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    // Self-restart is denied (use force_stop).
    let r: RestartReply = call_ok(
        &socket,
        op::REQUEST_RESTART,
        serde_json::json!({ "requester": "a", "target": "a" }),
    );
    assert_eq!(r.state, "denied");
    assert!(!r.performed);

    // Restart of another agent is granted + arbitrated; no live child here, so
    // nothing is killed, but the arbitration ran and the lease is now in flight.
    let r: RestartReply = call_ok(
        &socket,
        op::REQUEST_RESTART,
        serde_json::json!({ "requester": "a", "target": "b" }),
    );
    assert_eq!(r.state, "restarted");
    assert!(!r.performed, "no live child to kill in this phase");

    // A concurrent second restart of the same target queues (no double-kill).
    let r: RestartReply = call_ok(
        &socket,
        op::REQUEST_RESTART,
        serde_json::json!({ "requester": "c", "target": "b" }),
    );
    assert_eq!(r.state, "queued");

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn lease_verbs_reject_empty_targets() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    use softfig_ipc::ErrorKind::BadArgs;
    assert_eq!(
        call_err(&socket, op::REQUEST_LEASE, serde_json::json!({ "agent": "", "key": "k" })),
        BadArgs,
    );
    assert_eq!(
        call_err(&socket, op::REQUEST_LEASE, serde_json::json!({ "agent": "a", "key": "" })),
        BadArgs,
    );
    assert_eq!(
        call_err(&socket, op::RELEASE_LEASE, serde_json::json!({ "agent": "a", "key": "" })),
        BadArgs,
    );
    assert_eq!(
        call_err(
            &socket,
            op::REQUEST_RESTART,
            serde_json::json!({ "requester": "a", "target": "" }),
        ),
        BadArgs,
    );

    handle.shutdown();
    handle.join().unwrap();
}
