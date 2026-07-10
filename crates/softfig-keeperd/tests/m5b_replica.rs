//! M5b: device-chain replication end-to-end, headless.
//!
//! Two halves, matching the project's "pure logic + a loopback-TCP path"
//! posture (live two-device mDNS/relay replication is the manual real-machine
//! smoke step):
//!
//! * **Loopback replication** — a real owner `Repo` (signed commits, real
//!   ciphertext objects) serves over a real Noise session while a real
//!   [`MirrorStore`] pulls, verifies, and fast-forwards. Covers a full
//!   backfill, an incremental fast-forward, an `fsck`-clean mirror, a rollback
//!   rejection, and a wrong-owner rejection — all with real crypto.
//! * **Owner-side IPC surface** — `replica_grant` / `replica_revoke` /
//!   `replica_status` against a live daemon with a forged ring peer, mirroring
//!   `m5a4_pairing.rs`'s daemon harness.

use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use softfig_ipc::{
    self,
    verbs::{op, ReplicaGrantArgs, ReplicaGrantReply, ReplicaRevokeArgs, ReplicaRevokeReply,
        ReplicaStatusReply, UnlockArgs},
    ErrorKind, Request, Response,
};
use softfig_keeperd::replica::{build_announce, mirror_dir, MirrorStore, RepoSource};
use softfig_keeperd::{Daemon, KeeperConfig};
use softfig_net::proto::{HelloPayload, TipAnnounce};
use softfig_net::ring::{ring_path, Ring, RingEntry};
use softfig_net::transport::{xx_initiator, xx_responder};
use softfig_net::{
    pull_replication, pull_replication_pipelined, serve_replication, tipannounce_signing_bytes,
    NetError, PullSummary, ReplicaSink,
};
use softfig_store::{Db, Hash, ObjectStore, StorePaths};
use softfig_vault::{Vault, VaultSession};
use softfig_vcs::{Intent, Repo};

mod common;
use common::fast_params;

const PASS: &str = "correct horse battery staple";

// --- Loopback replication helpers -------------------------------------------

/// An unlocked owner garden (M1c-compat: `.softfig/` lives in the garden) with
/// `Repo` + `VaultSession`, in a fresh tempdir.
struct Owner {
    _tmp: tempfile::TempDir,
    garden: std::path::PathBuf,
    repo: Repo,
    session: VaultSession,
    device_id: [u8; 32],
    transport_secret: [u8; 32],
}

fn new_owner() -> Owner {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path().to_path_buf();
    let (_v, session, _r) = Vault::init_with_params(&garden, PASS.as_bytes(), fast_params()).unwrap();
    let (repo, _genesis) = Repo::init(&garden, &session).unwrap();
    let device_id = session.identity_pubkey().to_bytes();
    let transport_secret = *session.transport_secret();
    Owner {
        _tmp: tmp,
        garden,
        repo,
        session,
        device_id,
        transport_secret,
    }
}

impl Owner {
    /// Write `body` to `rel` and commit it; returns the new tip hash.
    fn commit_file(&mut self, rel: &str, body: &str) -> Hash {
        let path = self.garden.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, body).unwrap();
        let intent = Intent::new("manual_edit", json!({ "path": rel })).unwrap();
        self.repo.commit_workdir(&self.session, intent).unwrap()
    }

    /// Write `n` distinct files under `dir/` and commit them in ONE commit,
    /// producing a subtree that fans out past the pipeline window. Returns the
    /// new tip hash.
    fn commit_many(&mut self, dir: &str, n: usize) -> Hash {
        let base = self.garden.join(dir);
        std::fs::create_dir_all(&base).unwrap();
        for i in 0..n {
            std::fs::write(base.join(format!("f{i:03}.md")), format!("content-{i}")).unwrap();
        }
        let intent = Intent::new("manual_edit", json!({ "dir": dir })).unwrap();
        self.repo.commit_workdir(&self.session, intent).unwrap()
    }
}

/// Which pull driver [`replicate_with`] exercises.
#[derive(Clone, Copy)]
enum Driver {
    /// Strict request→response per object ([`pull_replication`]).
    Sequential,
    /// Full-duplex windowed backfill ([`pull_replication_pipelined`]).
    Pipelined,
}

/// Run one serve/pull round over a real loopback Noise session with the
/// **sequential** driver. Thin wrapper over [`replicate_with`].
fn replicate_once(
    garden: &Path,
    owner_transport: [u8; 32],
    owner_device_id: [u8; 32],
    announce: TipAnnounce,
    mirror: &mut MirrorStore,
) -> Result<PullSummary, NetError> {
    replicate_with(
        Driver::Sequential,
        garden,
        owner_transport,
        owner_device_id,
        announce,
        mirror,
    )
}

/// Run one serve/pull round over a real loopback Noise session: the owner
/// (responder) serves a fresh read-only `Repo` handle while the host (initiator)
/// drives the pull into `mirror` with `driver`. Returns the pull result. The
/// client session is dropped/consumed before joining so a mid-exchange abort
/// can't deadlock the unbuffered socket.
fn replicate_with(
    driver: Driver,
    garden: &Path,
    owner_transport: [u8; 32],
    owner_device_id: [u8; 32],
    announce: TipAnnounce,
    mirror: &mut MirrorStore,
) -> Result<PullSummary, NetError> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let garden = garden.to_path_buf();

    let owner_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let hello = HelloPayload::new(owner_device_id.to_vec(), "owner");
        let mut session = xx_responder(stream, &owner_transport, &hello).unwrap();
        let repo = Repo::open(&garden).unwrap();
        let source = RepoSource::new(repo, announce);
        let _ = serve_replication(&mut session, &source);
    });

    let stream = TcpStream::connect(endpoint).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let hello = HelloPayload::new(b"host-device".to_vec(), "host");
    let mut session = xx_initiator(stream, &[9u8; 32], &hello).unwrap();
    let result = match driver {
        Driver::Sequential => {
            let r = pull_replication(&mut session, mirror);
            drop(session); // let the owner's serve loop see EOF on abort
            r
        }
        // The pipelined driver consumes the session (it splits it); its halves
        // drop at the end, closing the socket for the same EOF-on-abort effect.
        Driver::Pipelined => pull_replication_pipelined(session, mirror),
    };
    owner_thread.join().unwrap();
    result
}

/// fsck the mirror at `<replica_root>/<owner-id>/.softfig/` and return the
/// report (commits/trees/objects checked, problems).
fn fsck_mirror(replica_root: &Path, owner_device_id: &[u8; 32]) -> softfig_vcs::FsckReport {
    let dir = mirror_dir(replica_root, owner_device_id);
    let paths = StorePaths::with_state_root(&dir, &dir);
    let db = Db::open(&paths).unwrap();
    let objects = ObjectStore::new(paths);
    softfig_vcs::fsck(&db, &objects).unwrap()
}

fn mirror_tip(replica_root: &Path, owner_device_id: &[u8; 32]) -> Option<Hash> {
    let dir = mirror_dir(replica_root, owner_device_id);
    let paths = StorePaths::with_state_root(&dir, &dir);
    Db::open(&paths).ok()?.try_get_ref("tip").ok().flatten()
}

#[test]
fn full_backfill_then_fsck_clean() {
    let mut owner = new_owner();
    owner.commit_file("a.md", "alpha");
    owner.commit_file("dir/b.md", "beta");
    let tip = owner.commit_file("dir/c.md", "gamma");

    let chain_id = owner.repo.repo_id().unwrap().into_bytes();
    let announce = build_announce(&owner.repo, &owner.session).unwrap();

    let replica_root = tempfile::tempdir().unwrap();
    let mut mirror =
        MirrorStore::open_or_create(replica_root.path(), &owner.device_id, "owner", &chain_id)
            .unwrap();

    let summary = replicate_once(
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce,
        &mut mirror,
    )
    .unwrap();

    // Genesis + 3 content commits.
    assert_eq!(summary.commits, 4);
    assert_eq!(summary.new_tip, Some(*tip.as_bytes()));
    drop(mirror);

    assert_eq!(mirror_tip(replica_root.path(), &owner.device_id), Some(tip));
    let report = fsck_mirror(replica_root.path(), &owner.device_id);
    assert!(report.ok(), "mirror not fsck-clean: {:?}", report.problems);
    assert_eq!(report.commits_checked, 4);
    // The three distinct files produced three distinct ciphertext objects.
    assert!(report.objects_checked >= 3, "got {}", report.objects_checked);
}

#[test]
fn incremental_fast_forward_fetches_only_new_commits() {
    let mut owner = new_owner();
    owner.commit_file("a.md", "alpha");
    let chain_id = owner.repo.repo_id().unwrap().into_bytes();

    let replica_root = tempfile::tempdir().unwrap();
    let mut mirror =
        MirrorStore::open_or_create(replica_root.path(), &owner.device_id, "owner", &chain_id)
            .unwrap();

    // First sync: genesis + a.md.
    let announce1 = build_announce(&owner.repo, &owner.session).unwrap();
    let s1 = replicate_once(
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce1,
        &mut mirror,
    )
    .unwrap();
    assert_eq!(s1.commits, 2);

    // Owner advances by two commits; the mirror fast-forwards just those.
    owner.commit_file("b.md", "beta");
    let tip = owner.commit_file("c.md", "gamma");
    let announce2 = build_announce(&owner.repo, &owner.session).unwrap();
    let s2 = replicate_once(
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce2,
        &mut mirror,
    )
    .unwrap();
    assert_eq!(s2.commits, 2, "only the two new commits are fetched");
    assert_eq!(s2.new_tip, Some(*tip.as_bytes()));

    // A redundant pull at the same tip is a clean no-op.
    let announce3 = build_announce(&owner.repo, &owner.session).unwrap();
    let s3 = replicate_once(
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce3,
        &mut mirror,
    )
    .unwrap();
    assert!(s3.up_to_date);
    assert_eq!(s3.commits, 0);
    drop(mirror);

    assert_eq!(mirror_tip(replica_root.path(), &owner.device_id), Some(tip));
    assert!(fsck_mirror(replica_root.path(), &owner.device_id).ok());
}

#[test]
fn rollback_announce_is_rejected_and_mirror_unchanged() {
    let mut owner = new_owner();
    let tip_a = owner.commit_file("a.md", "alpha");
    let tip_b = owner.commit_file("b.md", "beta");
    let chain_id = owner.repo.repo_id().unwrap().into_bytes();

    let replica_root = tempfile::tempdir().unwrap();
    let mut mirror =
        MirrorStore::open_or_create(replica_root.path(), &owner.device_id, "owner", &chain_id)
            .unwrap();

    // Sync to tip B.
    let announce_b = build_announce(&owner.repo, &owner.session).unwrap();
    replicate_once(
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce_b,
        &mut mirror,
    )
    .unwrap();
    assert_eq!(mirror.stored_tip(), Some(*tip_b.as_bytes()));

    // Now announce an OLDER tip (A) — a rollback. It is signed by the real owner
    // and A is a real ancestor the mirror holds, but A != the mirror's tip B, so
    // the fast-forward-only rule must reject it.
    let height_a = 2; // genesis + A
    let rollback = TipAnnounce {
        chain_id: chain_id.clone(),
        tip_hash: tip_a.as_bytes().to_vec(),
        height: height_a,
        signature: owner
            .session
            .sign(&tipannounce_signing_bytes(&chain_id, tip_a.as_bytes(), height_a))
            .to_bytes()
            .to_vec(),
    };
    let result = replicate_once(
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        rollback,
        &mut mirror,
    );
    assert!(result.is_err(), "rollback must be rejected");
    assert_eq!(
        mirror.stored_tip(),
        Some(*tip_b.as_bytes()),
        "mirror tip must be left at B, never force-updated"
    );
}

#[test]
fn announce_from_wrong_owner_is_rejected() {
    let mut owner = new_owner();
    owner.commit_file("a.md", "alpha");
    let chain_id = owner.repo.repo_id().unwrap().into_bytes();
    let announce = build_announce(&owner.repo, &owner.session).unwrap();

    // Configure the mirror to expect a DIFFERENT owner identity. The announce is
    // validly signed by the real owner, but not by the key the host expects, so
    // the host refuses to mirror it (chain-owner binding).
    let wrong_owner = [0x33u8; 32];
    let replica_root = tempfile::tempdir().unwrap();
    let mut mirror =
        MirrorStore::open_or_create(replica_root.path(), &wrong_owner, "imposter", &chain_id)
            .unwrap();

    let result = replicate_once(
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce,
        &mut mirror,
    );
    assert!(result.is_err(), "a chain not signed by the expected owner must be rejected");
    assert!(mirror.stored_tip().is_none(), "nothing stored");
}

// --- Full-duplex pipelined driver, end-to-end over a real Repo/store --------

#[test]
fn pipelined_full_backfill_then_fsck_clean() {
    let mut owner = new_owner();
    owner.commit_file("a.md", "alpha");
    owner.commit_file("dir/b.md", "beta");
    let tip = owner.commit_file("dir/c.md", "gamma");

    let chain_id = owner.repo.repo_id().unwrap().into_bytes();
    let announce = build_announce(&owner.repo, &owner.session).unwrap();

    let replica_root = tempfile::tempdir().unwrap();
    let mut mirror =
        MirrorStore::open_or_create(replica_root.path(), &owner.device_id, "owner", &chain_id)
            .unwrap();

    let summary = replicate_with(
        Driver::Pipelined,
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce,
        &mut mirror,
    )
    .unwrap();

    assert_eq!(summary.commits, 4);
    assert_eq!(summary.new_tip, Some(*tip.as_bytes()));
    drop(mirror);

    assert_eq!(mirror_tip(replica_root.path(), &owner.device_id), Some(tip));
    let report = fsck_mirror(replica_root.path(), &owner.device_id);
    assert!(report.ok(), "mirror not fsck-clean: {:?}", report.problems);
    assert_eq!(report.commits_checked, 4);
    assert!(report.objects_checked >= 3, "got {}", report.objects_checked);
}

#[test]
fn pipelined_many_object_backfill_exercises_the_window_fsck_clean() {
    // One commit whose subtree fans out past PIPELINE_WINDOW (32), so the
    // pipelined driver keeps a full in-flight window and still stores the
    // subtree post-order before the root that references it.
    let n = 40;
    let mut owner = new_owner();
    let tip = owner.commit_many("wide", n);

    let chain_id = owner.repo.repo_id().unwrap().into_bytes();
    let announce = build_announce(&owner.repo, &owner.session).unwrap();

    let replica_root = tempfile::tempdir().unwrap();
    let mut mirror =
        MirrorStore::open_or_create(replica_root.path(), &owner.device_id, "owner", &chain_id)
            .unwrap();

    let summary = replicate_with(
        Driver::Pipelined,
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce,
        &mut mirror,
    )
    .unwrap();
    assert_eq!(summary.new_tip, Some(*tip.as_bytes()));
    drop(mirror);

    assert_eq!(mirror_tip(replica_root.path(), &owner.device_id), Some(tip));
    let report = fsck_mirror(replica_root.path(), &owner.device_id);
    assert!(report.ok(), "mirror not fsck-clean: {:?}", report.problems);
    assert!(
        report.objects_checked >= n,
        "expected >= {n} objects, got {}",
        report.objects_checked
    );
}

#[test]
fn pipelined_incremental_fast_forward_fetches_only_new_commits() {
    let mut owner = new_owner();
    owner.commit_file("a.md", "alpha");
    let chain_id = owner.repo.repo_id().unwrap().into_bytes();

    let replica_root = tempfile::tempdir().unwrap();
    let mut mirror =
        MirrorStore::open_or_create(replica_root.path(), &owner.device_id, "owner", &chain_id)
            .unwrap();

    let announce1 = build_announce(&owner.repo, &owner.session).unwrap();
    let s1 = replicate_with(
        Driver::Pipelined,
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce1,
        &mut mirror,
    )
    .unwrap();
    assert_eq!(s1.commits, 2);

    owner.commit_file("b.md", "beta");
    let tip = owner.commit_file("c.md", "gamma");
    let announce2 = build_announce(&owner.repo, &owner.session).unwrap();
    let s2 = replicate_with(
        Driver::Pipelined,
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce2,
        &mut mirror,
    )
    .unwrap();
    assert_eq!(s2.commits, 2, "only the two new commits are fetched");
    assert_eq!(s2.new_tip, Some(*tip.as_bytes()));
    drop(mirror);

    assert_eq!(mirror_tip(replica_root.path(), &owner.device_id), Some(tip));
    assert!(fsck_mirror(replica_root.path(), &owner.device_id).ok());
}

#[test]
fn pipelined_rollback_announce_is_rejected_and_mirror_unchanged() {
    let mut owner = new_owner();
    let tip_a = owner.commit_file("a.md", "alpha");
    let tip_b = owner.commit_file("b.md", "beta");
    let chain_id = owner.repo.repo_id().unwrap().into_bytes();

    let replica_root = tempfile::tempdir().unwrap();
    let mut mirror =
        MirrorStore::open_or_create(replica_root.path(), &owner.device_id, "owner", &chain_id)
            .unwrap();

    let announce_b = build_announce(&owner.repo, &owner.session).unwrap();
    replicate_with(
        Driver::Pipelined,
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        announce_b,
        &mut mirror,
    )
    .unwrap();
    assert_eq!(mirror.stored_tip(), Some(*tip_b.as_bytes()));

    // Announce an OLDER tip (A) — a rollback. The fast-forward-only check in
    // negotiation must reject it before the session is split; the mirror stays
    // at B.
    let height_a = 2;
    let rollback = TipAnnounce {
        chain_id: chain_id.clone(),
        tip_hash: tip_a.as_bytes().to_vec(),
        height: height_a,
        signature: owner
            .session
            .sign(&tipannounce_signing_bytes(&chain_id, tip_a.as_bytes(), height_a))
            .to_bytes()
            .to_vec(),
    };
    let result = replicate_with(
        Driver::Pipelined,
        &owner.garden,
        owner.transport_secret,
        owner.device_id,
        rollback,
        &mut mirror,
    );
    assert!(result.is_err(), "rollback must be rejected");
    assert_eq!(
        mirror.stored_tip(),
        Some(*tip_b.as_bytes()),
        "mirror tip must be left at B, never force-updated"
    );
}

// --- Owner-side IPC surface (grant / revoke / status) -----------------------

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

/// A forged, self-consistent ring entry for a peer device, persisted into the
/// daemon's `peers.toml` so `replica_grant` can find it as a paired peer.
fn forge_ring_peer(state_dir: &Path, id_seed: u8, tk_seed: u8, name: &str) -> String {
    let id = SigningKey::from_bytes(&[id_seed; 32]);
    let transport_pubkey = x25519_dalek::x25519([tk_seed; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
    let attestation = id
        .sign(&softfig_net::static_attestation_message(&transport_pubkey))
        .to_bytes();
    let entry = RingEntry {
        device_id: id.verifying_key().to_bytes(),
        name: name.into(),
        transport_pubkey,
        endpoints: vec![],
        attestation,
        paired_at: 1,
    };
    let fp = entry.fingerprint();
    let path = ring_path(state_dir);
    let mut ring = Ring::load(&path).unwrap();
    ring.upsert(entry);
    ring.save(&path).unwrap();
    fp
}

/// Spin up an unlocked daemon (M1c-compat, no watcher/net) with a tempdir
/// replica root, returning the handle, socket, garden tempdir, and replica-root
/// tempdir guard.
fn unlocked_daemon() -> (
    softfig_keeperd::DaemonHandle,
    std::path::PathBuf,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let (_v, session, _r) = Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let replica_root = tempfile::tempdir().unwrap();
    let socket = garden.join("keeperd.sock");
    let config = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher()
        .without_net()
        .with_replica_root(replica_root.path());
    let handle = Daemon::new(config).start().expect("start");

    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "socket never appeared");

    unwrap_ok(rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));
    (handle, socket, tmp, replica_root)
}

#[test]
fn replica_grant_revoke_status_round_trip() {
    let (handle, socket, garden, _replica_root) = unlocked_daemon();
    let peer_fp = forge_ring_peer(garden.path(), 7, 8, "backup-host");

    // Initially: not a host, nothing granted, nothing hosted.
    let status: ReplicaStatusReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::REPLICA_STATUS, json!({})))).unwrap();
    assert!(!status.host);
    assert!(status.push_to.is_empty());
    assert!(status.hosted.is_empty());

    // Grant by a unique prefix → resolves to the full ring fingerprint.
    let granted: ReplicaGrantReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::REPLICA_GRANT,
        serde_json::to_value(ReplicaGrantArgs {
            fingerprint: peer_fp[..12].to_string(),
        })
        .unwrap(),
    )))
    .unwrap();
    assert!(granted.granted);
    assert_eq!(granted.fingerprint, peer_fp);

    // Idempotent second grant is a no-op.
    let again: ReplicaGrantReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::REPLICA_GRANT,
        serde_json::to_value(ReplicaGrantArgs {
            fingerprint: peer_fp.clone(),
        })
        .unwrap(),
    )))
    .unwrap();
    assert!(!again.granted);

    // Status now lists the grant.
    let status: ReplicaStatusReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::REPLICA_STATUS, json!({})))).unwrap();
    assert_eq!(status.push_to, vec![peer_fp.clone()]);

    // Revoke removes it.
    let revoked: ReplicaRevokeReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::REPLICA_REVOKE,
        serde_json::to_value(ReplicaRevokeArgs {
            fingerprint: peer_fp.clone(),
        })
        .unwrap(),
    )))
    .unwrap();
    assert!(revoked.revoked);

    let status: ReplicaStatusReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::REPLICA_STATUS, json!({})))).unwrap();
    assert!(status.push_to.is_empty());

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn grant_requires_a_paired_peer() {
    let (handle, socket, _garden, _replica_root) = unlocked_daemon();
    // No ring entry for this fingerprint → cannot grant a stranger.
    let kind = expect_err(rpc(
        &socket,
        op::REPLICA_GRANT,
        serde_json::to_value(ReplicaGrantArgs {
            fingerprint: "ab".repeat(32),
        })
        .unwrap(),
    ));
    assert_eq!(kind, ErrorKind::NotFound);
    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn revoke_unknown_is_not_found() {
    let (handle, socket, _garden, _replica_root) = unlocked_daemon();
    let kind = expect_err(rpc(
        &socket,
        op::REPLICA_REVOKE,
        serde_json::to_value(ReplicaRevokeArgs {
            fingerprint: "cd".repeat(32),
        })
        .unwrap(),
    ));
    assert_eq!(kind, ErrorKind::NotFound);
    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn replica_verbs_require_unlock() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let (_v, session, _r) = Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
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

    assert_eq!(
        expect_err(rpc(&socket, op::REPLICA_STATUS, json!({}))),
        ErrorKind::VaultLocked
    );
    assert_eq!(
        expect_err(rpc(
            &socket,
            op::REPLICA_GRANT,
            serde_json::to_value(ReplicaGrantArgs {
                fingerprint: "aa".repeat(32),
            })
            .unwrap()
        )),
        ErrorKind::VaultLocked
    );

    handle.shutdown();
    handle.join().unwrap();
}
