//! M5a-4: the network pairing verbs end-to-end against a real daemon.
//!
//! The *initiator* path (`pair_begin`) drives its own outbound socket, so it is
//! fully exercisable headless: a second forged device runs `softfig-net`'s
//! `pair_responder` on a loopback `TcpListener`, the daemon's `pair_begin`
//! dials it, both derive the SAS, `pair_confirm` persists the peer into the
//! `peers.toml` ring, and `pair_list` / `pair_remove` read and unpair it. The
//! daemon's own inbound listener / mDNS / relay are disabled here
//! (`without_net`) — that live infra is the documented manual real-machine
//! smoke step. The error paths (no endpoint, unreachable endpoint, unknown
//! ids) are checked too.

use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use softfig_vcs::Repo;
use softfig_ipc::{
    self,
    verbs::{
        op, PairBeginArgs, PairBeginReply, PairConfirmArgs, PairConfirmReply, PairListReply,
        PairRemoveArgs, PairRemoveReply, UnlockArgs,
    },
    ErrorKind, Request, Response,
};
use softfig_keeperd::{Daemon, KeeperConfig};
use softfig_net::pairing::{pair_responder, LocalDevice};
use softfig_net::static_attestation_message;
use softfig_vault::{params::VaultParams, Vault};

const PASS: &str = "correct horse battery staple";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn rpc(socket: &Path, op: &str, args: serde_json::Value) -> Response {
    let mut s = softfig_ipc::connect(socket).expect("connect");
    softfig_ipc::call(&mut s, &Request::new(op, args)).expect("call")
}

fn unwrap_ok(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("expected ok, got {kind:?}: {error}"),
    }
}

fn expect_err(resp: Response) -> ErrorKind {
    match resp {
        Response::Err { kind, .. } => kind,
        Response::Ok { data, .. } => panic!("expected error, got ok: {data}"),
    }
}

/// Spin up an unlocked daemon (no watcher, no live net host) in a fresh
/// tempdir, returning the handle, socket path, and the temp guard.
fn unlocked_daemon() -> (softfig_keeperd::DaemonHandle, std::path::PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let socket = garden.join("keeperd.sock");
    let config = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher()
        .without_net();
    let handle = Daemon::new(config).start().expect("start");

    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "socket never appeared");

    let _ = unwrap_ok(rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));
    (handle, socket, tmp)
}

/// Build a self-consistent (verifiable) `LocalDevice` for the test peer from
/// raw seeds — exactly what the vault produces in production, forged here.
fn forge_device(name: &str, id_seed: u8, tk_seed: u8) -> LocalDevice {
    let id = SigningKey::from_bytes(&[id_seed; 32]);
    let transport_secret = [tk_seed; 32];
    let transport_pubkey =
        x25519_dalek::x25519(transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    let static_attestation = id
        .sign(&static_attestation_message(&transport_pubkey))
        .to_bytes();
    LocalDevice {
        transport_secret,
        device_id: id.verifying_key().to_bytes(),
        device_name: name.into(),
        static_attestation,
    }
}

/// Bind a loopback listener and serve one `pair_responder` for `device`,
/// returning the bound endpoint and a channel that yields the responder-side
/// SAS once the handshake completes.
fn spawn_responder(device: LocalDevice) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        match pair_responder(stream, &device) {
            Ok(pending) => {
                let _ = tx.send(pending.sas().grouped());
                // Hold the session briefly so the initiator finishes parking
                // before the socket closes.
                thread::sleep(Duration::from_millis(50));
                drop(pending);
            }
            Err(e) => panic!("responder pairing failed: {e}"),
        }
    });
    (endpoint, rx)
}

#[test]
fn pair_begin_confirm_list_remove_round_trip() {
    let (handle, socket, _tmp) = unlocked_daemon();

    let peer = forge_device("test-peer", 7, 8);
    let peer_fp = hex::encode(peer.device_id);
    let (endpoint, sas_rx) = spawn_responder(peer);

    // pair_begin: initiator dials the responder, derives the SAS, parks.
    let begin: PairBeginReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::PAIR_BEGIN,
        serde_json::to_value(PairBeginArgs {
            fingerprint: peer_fp.clone(),
            endpoint: Some(endpoint),
        })
        .unwrap(),
    )))
    .unwrap();
    assert_eq!(begin.fingerprint, peer_fp);
    assert_eq!(begin.name, "test-peer");

    // Both honest endpoints derive the same SAS.
    let responder_sas = sas_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(begin.sas, responder_sas, "SAS must match on both devices");

    // Before confirm: the pairing shows up as pending, the ring is empty.
    let pre: PairListReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::PAIR_LIST, json!({})))).unwrap();
    assert!(pre.peers.is_empty());
    assert_eq!(pre.pending.len(), 1);
    assert_eq!(pre.pending[0].pairing_id, begin.pairing_id);

    // pair_confirm: persist into the ring.
    let confirm: PairConfirmReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::PAIR_CONFIRM,
        serde_json::to_value(PairConfirmArgs {
            pairing_id: begin.pairing_id.clone(),
        })
        .unwrap(),
    )))
    .unwrap();
    assert_eq!(confirm.fingerprint, peer_fp);

    // pair_list now shows the peer and no pending.
    let post: PairListReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::PAIR_LIST, json!({})))).unwrap();
    assert_eq!(post.peers.len(), 1);
    assert_eq!(post.peers[0].fingerprint, peer_fp);
    assert_eq!(post.peers[0].name, "test-peer");
    assert!(post.pending.is_empty());

    // The ring persisted to disk and verifies on reload.
    let ring = softfig_net::ring::Ring::load(&softfig_net::ring::ring_path(_tmp.path())).unwrap();
    assert_eq!(ring.len(), 1);
    assert!(ring.peers()[0].verify());

    // pair_remove by a unique prefix unpairs.
    let removed: PairRemoveReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::PAIR_REMOVE,
        serde_json::to_value(PairRemoveArgs {
            fingerprint: peer_fp[..12].to_string(),
        })
        .unwrap(),
    )))
    .unwrap();
    assert!(removed.removed);
    assert_eq!(removed.fingerprint, peer_fp);

    let empty: PairListReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::PAIR_LIST, json!({})))).unwrap();
    assert!(empty.peers.is_empty());

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn pair_begin_without_endpoint_is_not_found() {
    let (handle, socket, _tmp) = unlocked_daemon();
    // Net host is disabled → no discovery cache → an undiscovered fingerprint
    // with no explicit endpoint can't be resolved.
    let kind = expect_err(rpc(
        &socket,
        op::PAIR_BEGIN,
        serde_json::to_value(PairBeginArgs {
            fingerprint: "aa".repeat(32),
            endpoint: None,
        })
        .unwrap(),
    ));
    assert_eq!(kind, ErrorKind::NotFound);
    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn pair_begin_unreachable_endpoint_is_pair_failed() {
    let (handle, socket, _tmp) = unlocked_daemon();
    // Port 1 on loopback is not listening → connect refused → PairFailed.
    let kind = expect_err(rpc(
        &socket,
        op::PAIR_BEGIN,
        serde_json::to_value(PairBeginArgs {
            fingerprint: "bb".repeat(32),
            endpoint: Some("127.0.0.1:1".into()),
        })
        .unwrap(),
    ));
    assert_eq!(kind, ErrorKind::PairFailed);
    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn pair_begin_bad_fingerprint_is_bad_args() {
    let (handle, socket, _tmp) = unlocked_daemon();
    let kind = expect_err(rpc(
        &socket,
        op::PAIR_BEGIN,
        serde_json::to_value(PairBeginArgs {
            fingerprint: "not-hex-!!".into(),
            endpoint: Some("127.0.0.1:1".into()),
        })
        .unwrap(),
    ));
    assert_eq!(kind, ErrorKind::BadArgs);
    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn pair_confirm_unknown_id_is_not_found() {
    let (handle, socket, _tmp) = unlocked_daemon();
    let kind = expect_err(rpc(
        &socket,
        op::PAIR_CONFIRM,
        serde_json::to_value(PairConfirmArgs {
            pairing_id: "pair-deadbeef".into(),
        })
        .unwrap(),
    ));
    assert_eq!(kind, ErrorKind::NotFound);
    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn pair_remove_unknown_is_not_found() {
    let (handle, socket, _tmp) = unlocked_daemon();
    let kind = expect_err(rpc(
        &socket,
        op::PAIR_REMOVE,
        serde_json::to_value(PairRemoveArgs {
            fingerprint: "cc".repeat(32),
        })
        .unwrap(),
    ));
    assert_eq!(kind, ErrorKind::NotFound);
    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn net_host_starts_on_unlock_and_serves_verbs() {
    // Net host ENABLED on an ephemeral loopback port (collision-free), so this
    // exercises the real NetRuntime lifecycle — bind the inbound listener,
    // create the mDNS daemon, spawn the browse loop — and proves it neither
    // fails the unlock nor wedges shutdown (Drop joins the threads). The live
    // two-device handshake / mDNS resolution remain the manual smoke step.
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let socket = garden.join("keeperd.sock");
    let mut config = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    // Ephemeral port: always bindable, never collides with a real keeper.
    config.net.listen = "127.0.0.1:0".to_string();
    let handle = Daemon::new(config).start().expect("start");
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let _ = unwrap_ok(rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));

    // The net host came up without breaking unlock; the verbs answer.
    let list: PairListReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::PAIR_LIST, json!({})))).unwrap();
    assert!(list.peers.is_empty());

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn pairing_verbs_require_unlock() {
    // A locked daemon must refuse the pairing verbs.
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);
    let socket = garden.join("keeperd.sock");
    let handle = Daemon::new(
        KeeperConfig::new(garden)
            .with_socket(&socket)
            .without_watcher()
            .without_net(),
    )
    .start()
    .unwrap();
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let kind = expect_err(rpc(&socket, op::PAIR_LIST, json!({})));
    assert_eq!(kind, ErrorKind::VaultLocked);

    handle.shutdown();
    handle.join().unwrap();
}
