//! wire-loose-ends slice 002 integration: the agent-facing lease verbs routed
//! MCP-shape → keeperd → growlightd, end to end over live sockets.
//!
//! The MCP is a thin op-mapper (unit-tested in its own crate); the request it
//! emits is `Request::new(op::REQUEST_LEASE, {agent, key})` against keeperd's
//! socket. Here we drive keeperd with exactly that request and assert keeperd
//! forwards it to a **real growlightd** (booted on a tempdir socket) which owns
//! the `LeaseTable`, then relays the `LeaseReply` back. This proves the FIRST
//! keeperd→growlightd hop: free → granted, second requester → waiting, release
//! → promote/free, non-holder release → denied, empty key → growlightd's
//! `BadArgs` surfaced, and growlightd-down → a clean transport error.

use std::path::{Path, PathBuf};

use softfig_growlightd::{Daemon as GlDaemon, DaemonHandle as GlHandle, GrowlightdConfig};
use softfig_ipc::growlightd::LeaseReply;
use softfig_ipc::verbs::op;
use softfig_ipc::{ErrorKind, Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::Vault;
use softfig_vcs::Repo;

mod common;
use common::{fast_params, send, wait_for_socket};

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

fn init_garden(garden: &Path) {
    let (_vault, session, _recovery) =
        Vault::init_with_params(garden, PASS, fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
}

/// keeperd + a real growlightd, wired so keeperd forwards lease verbs to it.
struct Fixture {
    keeper_sock: PathBuf,
    _keeper: Option<DaemonHandle>,
    _growlightd: GlHandle,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    /// `with_growlightd = false` boots keeperd pointed at a growlightd socket
    /// path that has *no* daemon behind it (to exercise the transport-failure
    /// branch); but we still need a live growlightd handle to satisfy the
    /// struct, so we always boot one and (when asked) aim keeperd elsewhere.
    fn start() -> Self {
        Self::start_inner(true)
    }

    fn start_unreachable() -> Self {
        Self::start_inner(false)
    }

    fn start_inner(reachable: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let garden = tmp.path().join("garden");
        std::fs::create_dir_all(&garden).unwrap();
        init_garden(&garden);

        // Real growlightd on its own tempdir socket.
        let gl_sock = tmp.path().join("growlightd.sock");
        let growlightd =
            GlDaemon::new(GrowlightdConfig::new(gl_sock.clone(), tmp.path().join("gl-garden")))
                .start()
                .expect("growlightd boots");

        // keeperd forwards to the real growlightd (reachable) or to a dead path.
        let target = if reachable {
            gl_sock.clone()
        } else {
            tmp.path().join("no-such-growlightd.sock")
        };
        let keeper_sock = garden.join("keeper.sock");
        let config = KeeperConfig::new(&garden)
            .without_watcher()
            .without_net()
            .with_socket(&keeper_sock)
            .with_growlightd_socket(&target);
        let keeper = Daemon::new(config).start().unwrap();
        wait_for_socket(&keeper_sock);
        let resp = send(
            &keeper_sock,
            &Request::new(op::UNLOCK, serde_json::json!({ "passphrase": PASS_STR })),
        );
        assert!(matches!(resp, Response::Ok { .. }), "unlock: {resp:?}");

        Fixture {
            keeper_sock,
            _keeper: Some(keeper),
            _growlightd: growlightd,
            _tmp: tmp,
        }
    }

    /// Drive keeperd with the exact request the MCP emits and decode the reply.
    fn lease(&self, op_name: &str, agent: &str, key: &str) -> LeaseReply {
        let resp = send(
            &self.keeper_sock,
            &Request::new(op_name, serde_json::json!({ "agent": agent, "key": key })),
        );
        match resp {
            Response::Ok { data, .. } => serde_json::from_value(data).expect("LeaseReply decodes"),
            other => panic!("expected Ok LeaseReply, got {other:?}"),
        }
    }

    fn lease_err(&self, op_name: &str, args: serde_json::Value) -> (ErrorKind, String) {
        match send(&self.keeper_sock, &Request::new(op_name, args)) {
            Response::Err { kind, error, .. } => (kind, error),
            other => panic!("expected Err, got {other:?}"),
        }
    }
}

#[test]
fn request_and_release_round_trip_keeperd_to_growlightd() {
    let fx = Fixture::start();
    let key = "dock.rs §Layout";

    // Free → granted to the first requester, who becomes holder.
    let r = fx.lease(op::REQUEST_LEASE, "a", key);
    assert_eq!(r.state, "granted");
    assert_eq!(r.holder.as_deref(), Some("a"));

    // Re-requesting as the holder is idempotent — still granted, no self-queue.
    let again = fx.lease(op::REQUEST_LEASE, "a", key);
    assert_eq!(again.state, "granted");

    // A second agent is queued behind the holder at FIFO position 1.
    let b = fx.lease(op::REQUEST_LEASE, "b", key);
    assert_eq!(b.state, "waiting");
    assert_eq!(b.holder.as_deref(), Some("a"));
    assert_eq!(b.position, Some(1));

    // Holder releases → the head waiter (b) is promoted to holder.
    let rel = fx.lease(op::RELEASE_LEASE, "a", key);
    assert_eq!(rel.state, "released");
    assert_eq!(rel.holder.as_deref(), Some("b"));

    // A release by a non-holder is denied and changes nothing.
    let denied = fx.lease(op::RELEASE_LEASE, "a", key);
    assert_eq!(denied.state, "denied");
    assert!(denied.reason.is_some());

    // b releases the last claim → the key is free again (no promoted holder).
    let freed = fx.lease(op::RELEASE_LEASE, "b", key);
    assert_eq!(freed.state, "released");
    assert_eq!(freed.holder, None);
}

#[test]
fn growlightd_rejects_empty_args_and_keeperd_surfaces_it() {
    let fx = Fixture::start();
    // Empty key is rejected by growlightd (the arbiter); keeperd relays the
    // BadArgs verbatim rather than swallowing it.
    let (kind, msg) = fx.lease_err(
        op::REQUEST_LEASE,
        serde_json::json!({ "agent": "a", "key": "" }),
    );
    assert_eq!(kind, ErrorKind::BadArgs);
    assert!(msg.contains("key"), "unexpected message: {msg}");
}

#[test]
fn malformed_args_fail_locally_as_bad_args() {
    let fx = Fixture::start();
    // Missing the required `key` field → keeperd's typed parse rejects it before
    // any growlightd hop.
    let (kind, _) = fx.lease_err(op::REQUEST_LEASE, serde_json::json!({ "agent": "a" }));
    assert_eq!(kind, ErrorKind::BadArgs);
}

#[test]
fn growlightd_down_surfaces_a_clean_transport_error() {
    let fx = Fixture::start_unreachable();
    let (kind, msg) = fx.lease_err(
        op::REQUEST_LEASE,
        serde_json::json!({ "agent": "a", "key": "k" }),
    );
    assert_eq!(kind, ErrorKind::Io);
    assert!(msg.contains("growlightd unreachable"), "unexpected message: {msg}");
}
