//! Growlight relock token, end-to-end over IPC. The unattended-restart is
//! simulated by shutting down daemon #1 and starting daemon #2 on the *same*
//! garden + socket (what systemd does for real), then redeeming the token the
//! first daemon minted — no passphrase in between.

use std::fs;
use std::path::Path;
use std::time::Duration;

use serde_json::json;
use softfig_ipc::{
    self,
    verbs::{
        op, CommitArgs, RelockMintArgs, RelockMintReply, RelockRedeemArgs, StatusReply, UnlockArgs,
    },
    ErrorKind, Request, Response,
};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::Vault;
use softfig_vcs::Repo;

mod common;
use common::fast_params;

const PASS: &str = "correct horse battery staple";

fn rpc(socket: &Path, op: &str, args: serde_json::Value) -> Response {
    let mut s = softfig_ipc::connect(socket).expect("connect");
    let req = Request::new(op, args);
    softfig_ipc::call(&mut s, &req).expect("call")
}

fn unwrap_ok(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("expected ok, got {kind:?}: {error}"),
    }
}

fn err_kind(resp: Response) -> ErrorKind {
    match resp {
        Response::Err { kind, .. } => kind,
        Response::Ok { data, .. } => panic!("expected error, got ok: {data}"),
    }
}

/// Start a daemon on `garden`/`socket` and wait for the socket to bind.
fn boot(garden: &Path, socket: &Path, allow_relock: bool) -> DaemonHandle {
    let config = KeeperConfig::new(garden)
        .with_socket(socket)
        .without_watcher()
        .without_net()
        .allow_relock(allow_relock);
    let handle = Daemon::new(config).start().expect("start");
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "socket never appeared");
    handle
}

fn unlock(socket: &Path) {
    let _ = unwrap_ok(rpc(
        socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs { passphrase: PASS.into() }).unwrap(),
    ));
}

fn status(socket: &Path) -> StatusReply {
    serde_json::from_value(unwrap_ok(rpc(socket, op::STATUS, json!({})))).unwrap()
}

fn init_garden(garden: &Path) {
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);
}

/// `cycle` shape: mint returns the token in the reply (held in RAM), the blob
/// stays on tmpfs across the restart, and the new daemon redeems it.
#[test]
fn relock_cycle_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let socket = garden.join("keeperd.sock");
    init_garden(garden);

    // Daemon #1: unlock, then mint a (non-persisted) relock token.
    let h1 = boot(garden, &socket, true);
    unlock(&socket);
    let mint: RelockMintReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::RELOCK_MINT,
        serde_json::to_value(RelockMintArgs { persist: false }).unwrap(),
    )))
    .unwrap();
    assert!(!mint.persisted);
    let token = mint.token.clone().expect("cycle mint returns the token");
    assert_eq!(token.len(), 64, "token is 32 bytes of hex");
    assert!(mint.token_path.is_none());
    assert!(Path::new(&mint.blob_path).exists(), "blob written to tmpfs");

    // Restart: stop #1 (blob must survive), start #2 — it comes back Locked.
    h1.shutdown();
    h1.join().expect("clean exit");
    assert!(Path::new(&mint.blob_path).exists(), "live blob survives shutdown");

    let h2 = boot(garden, &socket, true);
    let s = status(&socket);
    assert_eq!(s.state, "locked");
    assert!(s.relock_pending, "armed token surfaces in status");
    assert_eq!(s.relock_expires_at, Some(mint.expires_at));

    // Redeem with the token held in RAM → Unlocked, no passphrase.
    let data = unwrap_ok(rpc(
        &socket,
        op::RELOCK_REDEEM,
        serde_json::to_value(RelockRedeemArgs { token: Some(token) }).unwrap(),
    ));
    assert_eq!(data["state"], "unlocked");

    // Session is fully live: status sees the tip, and a commit goes through.
    let s = status(&socket);
    assert_eq!(s.state, "unlocked");
    assert!(s.tip.is_some());
    assert!(!s.relock_pending, "blob consumed on redeem");
    assert!(!Path::new(&mint.blob_path).exists(), "blob deleted (single-use)");

    let commit = CommitArgs {
        intent: "memory_edit".into(),
        payload: json!({"summary": "post-relock", "files": ["a.md"]}),
    };
    fs::write(garden.join("a.md"), "hi\n").unwrap();
    let _ = unwrap_ok(rpc(&socket, op::COMMIT, serde_json::to_value(commit).unwrap()));

    h2.shutdown();
    h2.join().unwrap();
}

/// `relock-arm` shape: the token is persisted to tmpfs; the new daemon reads
/// its own token file on redeem (the CLI passes no token bytes).
#[test]
fn relock_arm_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let socket = garden.join("keeperd.sock");
    init_garden(garden);

    let h1 = boot(garden, &socket, true);
    unlock(&socket);
    let mint: RelockMintReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::RELOCK_MINT,
        serde_json::to_value(RelockMintArgs { persist: true }).unwrap(),
    )))
    .unwrap();
    assert!(mint.persisted);
    assert!(mint.token.is_none(), "persist mode keeps the token off the wire");
    let token_path = mint.token_path.clone().expect("persist returns the token path");
    assert!(Path::new(&token_path).exists());

    h1.shutdown();
    h1.join().unwrap();

    let h2 = boot(garden, &socket, true);
    // Redeem with NO token in args — the daemon reads its persisted token file.
    let data = unwrap_ok(rpc(
        &socket,
        op::RELOCK_REDEEM,
        serde_json::to_value(RelockRedeemArgs { token: None }).unwrap(),
    ));
    assert_eq!(data["state"], "unlocked");
    assert!(!Path::new(&token_path).exists(), "persisted token deleted on redeem");
    assert!(!Path::new(&mint.blob_path).exists(), "blob deleted on redeem");

    h2.shutdown();
    h2.join().unwrap();
}

/// Off by default: a daemon without `[growlight] allow_relock` refuses to mint,
/// so the agent can never self-grant the capability.
#[test]
fn relock_mint_refused_when_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let socket = garden.join("keeperd.sock");
    init_garden(garden);

    let h = boot(garden, &socket, false);
    unlock(&socket);
    let resp = rpc(
        &socket,
        op::RELOCK_MINT,
        serde_json::to_value(RelockMintArgs { persist: false }).unwrap(),
    );
    assert_eq!(err_kind(resp), ErrorKind::RelockDisabled);

    h.shutdown();
    h.join().unwrap();
}

/// Relock never cold-unlocks: mint requires the daemon already Unlocked.
#[test]
fn relock_mint_requires_unlocked() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let socket = garden.join("keeperd.sock");
    init_garden(garden);

    let h = boot(garden, &socket, true);
    // No unlock — still Locked.
    let resp = rpc(
        &socket,
        op::RELOCK_MINT,
        serde_json::to_value(RelockMintArgs { persist: false }).unwrap(),
    );
    assert_eq!(err_kind(resp), ErrorKind::VaultLocked);

    h.shutdown();
    h.join().unwrap();
}

/// A wrong token fails the redeem and does NOT consume the armed blob, so the
/// real `cycle`/`relock` can still succeed afterward.
#[test]
fn relock_redeem_wrong_token_keeps_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let socket = garden.join("keeperd.sock");
    init_garden(garden);

    let h1 = boot(garden, &socket, true);
    unlock(&socket);
    let mint: RelockMintReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::RELOCK_MINT,
        serde_json::to_value(RelockMintArgs { persist: false }).unwrap(),
    )))
    .unwrap();
    let good = mint.token.clone().unwrap();
    h1.shutdown();
    h1.join().unwrap();

    let h2 = boot(garden, &socket, true);
    let bogus = "00".repeat(32);
    let resp = rpc(
        &socket,
        op::RELOCK_REDEEM,
        serde_json::to_value(RelockRedeemArgs { token: Some(bogus) }).unwrap(),
    );
    assert_eq!(err_kind(resp), ErrorKind::AuthFailed);
    assert_eq!(status(&socket).state, "locked", "still locked after a bad token");
    assert!(Path::new(&mint.blob_path).exists(), "blob survives a failed redeem");

    // The correct token still works.
    let data = unwrap_ok(rpc(
        &socket,
        op::RELOCK_REDEEM,
        serde_json::to_value(RelockRedeemArgs { token: Some(good) }).unwrap(),
    ));
    assert_eq!(data["state"], "unlocked");

    h2.shutdown();
    h2.join().unwrap();
}
