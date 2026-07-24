//! M5f slice 005 — the **divergent-path proof**: two members mount ONE shared
//! chain at DIFFERENT garden paths and the full sync cycle is placement-free.
//!
//! The two members here are a *sharer* (Node A, mounts `journal` at
//! `projects/shared`) and a *recipient* (Node B, mounts the SAME `journal` chain
//! at `collab/from-ring`, a placement divergent from A's recommendation). Both
//! key the chain with the identical `S` under the same key id, so content flows
//! S-sealed and content-addressed between them; the tests drive the production
//! push → apply → conflict-resolve spine over a real loopback-TCP + Noise `IK`
//! session (the same choreography `push_shared_chain_to_host` runs after its
//! dial) and assert two things at once:
//!
//! * **chain-side convergence** — both members' `chain/journal` tip root trees
//!   are byte-identical (identical S-sealed blobs, content-addressed);
//! * **per-device placement** — that byte-identical content is served at each
//!   member's OWN garden path and nowhere else. Placement is per-device state;
//!   the shared chain never carries it ([[decision-shared-subtree-recipient-placement]]).
//!
//! This combines the single-daemon FUSE-attach seam (m5c: `add`/`accept`/
//! `migrate`/`key`/`toggle` + the composed-view `path_exists` probe) with the
//! two-daemon loopback push harness (m5e) into ONE harness so a node can drive
//! BOTH surfaces.
//!
//! Rotation-at-divergent-path (the final clause of slice 005) is a follow-on
//! chunk: driving the real `rotate_shared_key` needs a ceremony transcript not
//! reachable from an integration test via public API; tracked in the m5f baton.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use softfig_ipc::verbs::{
    op, MigrateIntoShareArgs, MigrateIntoShareReply, SharedSubtreeAcceptArgs,
    SharedSubtreeAcceptReply, SharedSubtreeAddArgs, SharedSubtreeListReply, SharedSubtreeToggleArgs,
    SharedSubtreeToggleReply,
};
use softfig_ipc::{Request, Response};
use softfig_keeperd::net::{
    build_local_device, build_shared_chain_push_frame, serve_established, serve_shared_subtree,
};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_net::ring::{Ring, RingEntry};
use softfig_net::transport::{ik_initiator, ik_responder};
use softfig_net::LocalDevice;
use std::sync::Arc as StdArc;

use softfig_store::{Hash, TreeEntryKind};
use softfig_vault::{params::VaultParams, Vault, VaultSession};
use softfig_vcs::tree::BlobEncryptor;
use softfig_vcs::Repo;

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

/// The single shared chain both members mount — same id, same ref, keyed with
/// the same `S` on both nodes.
const CHAIN_ID: &str = "journal";
const CHAIN_REF: &str = "chain/journal";
const KEY_ID: &str = "S-m5f-005";

/// The divergent mount paths — the whole point of the slice.
const MOUNT_A: &str = "projects/shared";
const MOUNT_B: &str = "collab/from-ring";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            if let Ok(stream) = UnixStream::connect(path) {
                drop(stream);
                return;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("socket {} did not appear", path.display());
}

/// One request over the node's Unix socket (copy of m5c's `send`/`call`).
fn send(socket: &Path, req: &Request) -> Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    let mut bytes = serde_json::to_vec(req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn ok_data(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("expected Ok, got {kind:?}: {error}"),
    }
}

/// The committed cipher blob at chain-relative `rel` under `ref_name`'s tip
/// (copy of m5c's `committed_blob`): navigate the tree component by component,
/// `None` if the ref is unborn or the path is absent / not a blob. Lets a test
/// assert both presence + the container kind (M vs S) of shared content.
fn committed_blob(garden: &Path, ref_name: &str, rel: &str) -> Option<Vec<u8>> {
    let repo = Repo::open(garden).unwrap();
    let tip = repo.tip_of(ref_name).unwrap()?;
    let mut tree = repo.db().get_commit(&tip).unwrap().root_tree;
    let comps: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    for (i, comp) in comps.iter().enumerate() {
        let entry = repo
            .db()
            .get_tree(&tree)
            .unwrap()
            .into_iter()
            .find(|e| e.name == *comp)?;
        if i + 1 == comps.len() {
            return match entry.kind {
                TreeEntryKind::Blob => Some(repo.objects().get(&entry.target).unwrap()),
                TreeEntryKind::Tree => None,
            };
        }
        match entry.kind {
            TreeEntryKind::Tree => tree = entry.target,
            TreeEntryKind::Blob => return None, // path descends through a file
        }
    }
    None
}

/// Whether `ref_name`'s tip tree contains an entry at chain-relative `rel`
/// (blob or tree). Walks the committed tip tree component by component. Lets a
/// test assert the sidecar landed without knowing its container kind.
fn tip_tree_has_path(garden: &Path, ref_name: &str, rel: &str) -> bool {
    let repo = Repo::open(garden).unwrap();
    let Some(tip) = repo.tip_of(ref_name).unwrap() else {
        return false;
    };
    let mut tree = repo.db().get_commit(&tip).unwrap().root_tree;
    let comps: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    for (i, comp) in comps.iter().enumerate() {
        let Some(entry) = repo
            .db()
            .get_tree(&tree)
            .unwrap()
            .into_iter()
            .find(|e| e.name == *comp)
        else {
            return false;
        };
        if i + 1 == comps.len() {
            return true;
        }
        match entry.kind {
            TreeEntryKind::Tree => tree = entry.target,
            TreeEntryKind::Blob => return false,
        }
    }
    false
}

/// A test-side blob encryptor that seals a keyed shared chain's blobs under its
/// `S` (the production `LayerBHook` behavior), so an in-test chain edit authored
/// via a fresh `Repo` handle produces the SAME S-sealed containers the daemon's
/// migrate/write path does — and, crucially, the SAME key both members hold, so
/// a transferred blob decrypts on the receiver (an M-sealed blob would be sealed
/// under the *author's* per-vault master `M`, undecryptable by the peer). Only
/// `CHAIN_REF` is committed through it, and it always S-seals under [`KEY_ID`].
struct SharedChainEncryptor;

impl BlobEncryptor for SharedChainEncryptor {
    fn encrypt(
        &self,
        _path: &str,
        content: &[u8],
        session: &VaultSession,
    ) -> softfig_vcs::Result<Vec<u8>> {
        Ok(session.encrypt_shared_blob(KEY_ID, content)?)
    }
}

/// A combined divergent-path member: it drives BOTH the socket lifecycle verbs
/// (m5c: add/accept/migrate/key/toggle/read + the composed-view `path_exists`
/// probe) AND the m5e push machinery (a real Noise session over loopback TCP).
/// It carries the socket + its own `mount_path` so the tests can prove that one
/// shared chain serves at each member's own placement.
struct Node {
    _tmp: tempfile::TempDir,
    garden: PathBuf,
    socket: PathBuf,
    handle: Option<DaemonHandle>,
    session: VaultSession,
    local: LocalDevice,
    device_id: [u8; 32],
    transport_pubkey: [u8; 32],
    name: String,
    mount_path: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
            let _ = handle.join();
        }
    }
}

/// A live unlocked daemon (FUSE-attach seam, no watcher, no net) with NO
/// auto-genesis'd chain — the tests drive add/accept explicitly (unlike m5e).
/// The test inits the vault, so it holds the same identity + transport keys the
/// daemon derives on unlock (used to sign push frames + forge the peer's ring
/// entry).
fn new_node(name: &str, mount_path: &str) -> Node {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path().to_path_buf();
    let (_v, session, _r) = Vault::init_with_params(&garden, PASS, fast_params()).unwrap();
    Repo::init(&garden, &session).unwrap();
    let local = build_local_device(&session, name.to_string());
    let device_id = session.identity_pubkey().to_bytes();
    let transport_pubkey = session.transport_pubkey();

    let socket = garden.join("sock");
    let config = KeeperConfig::new(&garden)
        .without_watcher()
        .without_net()
        .with_socket(&socket)
        .with_unmounted_fuse_attach();
    let handle = Daemon::new(config).start().expect("start daemon");

    wait_for_socket(&socket);
    ok_data(send(
        &socket,
        &Request::new(op::UNLOCK, serde_json::json!({ "passphrase": PASS_STR })),
    ));

    Node {
        _tmp: tmp,
        garden,
        socket,
        handle: Some(handle),
        session,
        local,
        device_id,
        transport_pubkey,
        name: name.to_string(),
        mount_path: mount_path.to_string(),
    }
}

impl Node {
    fn call(&self, op_name: &str, args: serde_json::Value) -> Response {
        send(&self.socket, &Request::new(op_name, args))
    }

    /// A ring entry naming this node (its real device id + transport static +
    /// self-signed attestation), for the peer to trust it as an S-member (copy
    /// of m5e's `ring_entry`).
    fn ring_entry(&self) -> RingEntry {
        RingEntry {
            device_id: self.device_id,
            name: self.name.clone(),
            transport_pubkey: self.transport_pubkey,
            endpoints: vec![],
            attestation: self.local.static_attestation,
            paired_at: 1,
        }
    }

    // --- m5c socket lifecycle verbs (over this node's own daemon) -----------

    fn add(&self, mount_path: &str, id: Option<&str>) -> Response {
        self.call(
            op::SHARED_SUBTREE_ADD,
            serde_json::to_value(SharedSubtreeAddArgs {
                mount_path: mount_path.into(),
                id: id.map(str::to_string),
            })
            .unwrap(),
        )
    }

    /// Seed a device-local pending share-offer as if a peer had fanned it over
    /// the wire (copy of m5c's `seed_offer`).
    fn seed_offer(&self, id: &str, recommended_path: Option<&str>) {
        use softfig_keeperd::pending_offers::{PendingOffer, PendingOffers};
        let state_dir = {
            let inner = self.handle.as_ref().unwrap().daemon.inner.lock().unwrap();
            inner.config.state_dir().to_path_buf()
        };
        let mut store = PendingOffers::load(&state_dir);
        store.upsert(PendingOffer {
            id: id.into(),
            ref_name: format!("chain/{id}"),
            recommended_path: recommended_path.map(str::to_string),
            offered_by: "aa".repeat(32),
        });
        store.save(&state_dir).unwrap();
    }

    fn accept(&self, id: &str, mount_path: Option<&str>) -> SharedSubtreeAcceptReply {
        serde_json::from_value(ok_data(self.call(
            op::SHARED_SUBTREE_ACCEPT,
            serde_json::to_value(SharedSubtreeAcceptArgs {
                id: id.into(),
                mount_path: mount_path.map(str::to_string),
            })
            .unwrap(),
        )))
        .unwrap()
    }

    fn migrate(&self, id: &str, from: &str) -> MigrateIntoShareReply {
        serde_json::from_value(ok_data(self.call(
            op::MIGRATE_INTO_SHARE,
            serde_json::to_value(MigrateIntoShareArgs {
                id: id.into(),
                from: from.into(),
            })
            .unwrap(),
        )))
        .unwrap()
    }

    fn list(&self) -> SharedSubtreeListReply {
        serde_json::from_value(ok_data(self.call(op::SHARED_SUBTREE_LIST, serde_json::Value::Null)))
            .unwrap()
    }

    /// The committed `mount_path` this member serves the chain at (its own
    /// placement row).
    fn membership_mount_path(&self, id: &str) -> String {
        self.list()
            .subtrees
            .into_iter()
            .find(|s| s.id == id)
            .unwrap_or_else(|| panic!("no membership row for {id}"))
            .mount_path
    }

    fn toggle(&self, op_name: &str, id: &str) -> SharedSubtreeToggleReply {
        serde_json::from_value(ok_data(self.call(
            op_name,
            serde_json::to_value(SharedSubtreeToggleArgs { id: id.into() }).unwrap(),
        )))
        .unwrap()
    }

    /// Committed text of `config/shared-subtrees.toml` (copy of m5c's
    /// `config_text`) — the attach-seam fixture has no on-disk working tree.
    fn config_text(&self) -> Option<String> {
        match self.call(
            op::READ_FILE,
            serde_json::json!({ "path": "config/shared-subtrees.toml" }),
        ) {
            Response::Ok { data, .. } => Some(data["content"].as_str().unwrap().to_string()),
            Response::Err { .. } => None,
        }
    }

    /// Break-glass write: commit `content` at garden-relative `path` (copy of
    /// m5c's `write_committed`).
    fn write_committed(&self, path: &str, content: &str) {
        let resp = self.call(
            op::REPLACE_FILE,
            serde_json::json!({ "path": path, "content": content }),
        );
        assert!(matches!(resp, Response::Ok { .. }), "replace_file {path}: {resp:?}");
    }

    /// Headless key ceremony stand-in (copy of m5c's `key_chain`): store the
    /// SAME `S` under the SAME key id in this node's vault, fill `key_id` in the
    /// committed membership row, then disable/enable so the daemon re-derives its
    /// mount registry + `S` router. Keying the same bytes under the same id on
    /// both nodes gives them a shared `S`. The chain must be empty here.
    fn key_chain(&self, id: &str, ref_name: &str, s_id: &str) {
        let session = Vault::at(&self.garden).unlock(PASS).unwrap();
        session.store_shared_key(s_id, &[0x51u8; 32]).unwrap();
        let text = self.config_text().expect("membership exists after add/accept");
        let needle = format!("ref_name = \"{ref_name}\"");
        assert!(text.contains(&needle), "no membership row for {ref_name} in: {text}");
        let keyed = text.replace(&needle, &format!("{needle}\nkey_id = \"{s_id}\""));
        self.write_committed("config/shared-subtrees.toml", &keyed);
        let r = self.toggle(op::SHARED_SUBTREE_DISABLE, id);
        assert!(!r.enabled);
        let r = self.toggle(op::SHARED_SUBTREE_ENABLE, id);
        assert!(r.enabled);
    }

    /// Force a recompose of the union view (disable → enable) so the mount
    /// registry picks up a newly-committed chain tip (the network apply advances
    /// the ref but the compose only refreshes on toggle here).
    fn recompose(&self, id: &str) {
        let r = self.toggle(op::SHARED_SUBTREE_DISABLE, id);
        assert!(!r.enabled);
        let r = self.toggle(op::SHARED_SUBTREE_ENABLE, id);
        assert!(r.enabled);
    }

    /// Whether the composed (tip ∪ overlay) mount view has a live entry at `rel`
    /// (copy of m5c's `mount_path_exists`).
    fn mount_path_exists(&self, rel: &str) -> bool {
        let daemon = &self.handle.as_ref().unwrap().daemon;
        let inner = daemon.inner.lock().unwrap();
        inner.fuse.as_ref().expect("fuse attached").path_exists(rel)
    }

    // --- chain-ref reads via a fresh repo handle (WAL-sharing) --------------

    /// This node's `chain/journal` tip commit hash + its root tree.
    fn chain_tip(&self) -> (Hash, Hash) {
        let repo = Repo::open(&self.garden).unwrap();
        let tip = repo.tip_of(CHAIN_REF).unwrap().expect("chain has a tip");
        let root = repo.db().get_commit(&tip).unwrap().root_tree;
        (tip, root)
    }

    fn chain_root_tree(&self) -> Hash {
        self.chain_tip().1
    }

    /// This node's own garden placement for the shared chain (per-device state).
    fn mount(&self) -> &str {
        &self.mount_path
    }

    /// The full tip commit row (`author_device`, `timestamp`, `intent`, …) for
    /// `chain/journal`.
    fn chain_tip_row(&self) -> softfig_store::CommitRow {
        let repo = Repo::open(&self.garden).unwrap();
        let tip = repo.tip_of(CHAIN_REF).unwrap().expect("chain has a tip");
        repo.db().get_commit(&tip).unwrap()
    }

    /// Author a chain edit on `chain/journal` at the CHAIN-RELATIVE path `rel`
    /// (NOT mount-prefixed) over the current tip via a fresh (WAL-sharing) repo
    /// handle. Returns the edit's new root tree — the tree the `SharedChainPush`
    /// frame carries. Blobs seal under this fresh repo's default Layer A (M);
    /// the receiver's conflict-resolution re-seal (which runs on the daemon's
    /// S-routed repo) is what converts the winner to the shared container.
    fn commit_chain_edit(&self, rel: &str, body: &str) -> Hash {
        use softfig_vcs::{Intent, WalkSnapshot};
        let mut repo = Repo::open(&self.garden).unwrap();
        // Seal the keyed chain's blobs under its shared `S` (the daemon write
        // path's behavior), not the per-vault master `M` — an M-sealed blob is
        // undecryptable by the peer, which would break the conflict resolver's
        // materialize/read of a transferred loser tree.
        repo.set_blob_encryptor(StdArc::new(SharedChainEncryptor));
        let mut snap = WalkSnapshot::empty();
        snap.insert_file(Path::new(rel), 0o100644, body.as_bytes().to_vec())
            .unwrap();
        let intent = Intent::new("manual_edit", serde_json::json!({ "path": rel })).unwrap();
        let edit_tip = repo
            .commit_snapshot_to(CHAIN_REF, &self.session, snap, intent)
            .unwrap();
        repo.db().get_commit(&edit_tip).unwrap().root_tree
    }
}

/// Push one already-committed chain edit from `sender` to `receiver` over a real
/// loopback TCP + Noise `IK` session (generalized copy of m5e's `push_edit`):
/// the sender sends the signed `SharedChainPush` frame tagged with an EXPLICIT
/// `writer_device` + `timestamp` (so the LWW key is symmetric — A's edit carries
/// A's own committed `(author_device, timestamp)` whether seen locally at A or
/// incoming at B) + the stable `subtree` id, then serves the edit's subtree
/// closure; the receiver runs the production inbound dispatch (`serve_established`
/// → `serve_shared_chain_push`), which pulls + re-authors (or, on divergence,
/// resolves LWW+sidecar). `receiver_ring` must already trust `sender`.
#[allow(clippy::too_many_arguments)]
fn push_edit_tagged(
    sender: &Node,
    receiver: &Node,
    receiver_ring: &Arc<Mutex<Ring>>,
    subtree: &str,
    new_tree: Hash,
    base_tree: Hash,
    writer_device: &str,
    timestamp: i64,
    files: &[String],
) {
    let frame = build_shared_chain_push_frame(
        &sender.session,
        &sender.local,
        CHAIN_REF,
        subtree,
        new_tree.as_bytes(),
        base_tree.as_bytes(),
        writer_device,
        files,
        timestamp,
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let sender_secret = sender.local.transport_secret;
    let sender_hello = sender.local.hello();
    let receiver_static = receiver.transport_pubkey;
    let sender_garden = sender.garden.clone();
    let new_tree_bytes = *new_tree.as_bytes();
    let sender_thread = thread::spawn(move || {
        let stream = TcpStream::connect(addr).unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let mut session = ik_initiator(stream, &sender_secret, &receiver_static, &sender_hello)
            .expect("sender IK handshake");
        session.send_frame(&frame).expect("send push frame");
        // A benign EOF once the receiver finishes pulling is not a failure — the
        // receiver-side chain state is the real assertion.
        let _ = serve_shared_subtree(&mut session, &new_tree_bytes, &sender_garden, None);
    });

    let owner = sender.ring_entry();
    let (conn, _) = listener.accept().unwrap();
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(10)));
    let session = ik_responder(conn, &receiver.local.transport_secret, &receiver.local.hello())
        .expect("receiver IK handshake");
    serve_established(
        &receiver.handle.as_ref().unwrap().daemon,
        &receiver.local,
        &owner,
        receiver_ring,
        session,
    );

    sender_thread.join().unwrap();
}

/// A ring holding exactly `peer` (as trusted S-member).
fn ring_trusting(peer: &Node) -> Arc<Mutex<Ring>> {
    Arc::new(Mutex::new({
        let mut r = Ring::default();
        r.upsert(peer.ring_entry());
        r
    }))
}

// ---------------------------------------------------------------------------
// TEST 1 — divergent placement converges, each member serves at its own path.
// ---------------------------------------------------------------------------

/// The headline proof: A (sharer, `projects/shared`) migrates a two-file device
/// subtree into the keyed `journal` chain and pushes it to B (recipient,
/// `collab/from-ring`). Both chains converge to a byte-identical root tree of
/// S-sealed blobs, and the SAME content is served at each member's OWN garden
/// path — never the other's. Placement is per-device; the chain carries none of
/// it.
#[test]
fn divergent_paths_converge_and_each_serves_at_its_own_path() {
    let a = new_node("node-a", MOUNT_A);
    let b = new_node("node-b", MOUNT_B);

    // (1) A shares `journal` at its path; B accepts the SAME id at a DIVERGENT
    // path (over the sharer's advisory recommendation).
    ok_data(a.add(MOUNT_A, Some(CHAIN_ID)));
    b.seed_offer(CHAIN_ID, Some(MOUNT_A));
    let reply = b.accept(CHAIN_ID, Some(MOUNT_B));
    assert_eq!(reply.mount_path, MOUNT_B, "recipient's chosen placement wins");
    assert_eq!(
        b.membership_mount_path(CHAIN_ID),
        b.mount(),
        "B's committed membership row records its own divergent placement"
    );
    assert_eq!(a.membership_mount_path(CHAIN_ID), a.mount(), "A keeps its own placement");

    // (2) Key BOTH nodes with the identical S under the same id (chain empty).
    a.key_chain(CHAIN_ID, CHAIN_REF, KEY_ID);
    b.key_chain(CHAIN_ID, CHAIN_REF, KEY_ID);

    // Capture B's genesis tree (the empty genesis both share) BEFORE A migrates —
    // it is the base A's edit fast-forwards over.
    let base_tree = b.chain_root_tree();

    // (3) A authors device content at a disjoint device path, then migrates it
    // into the keyed share (S-sealed from birth, carved out of the device chain).
    a.write_committed("notes/src/a.md", "alpha\n");
    a.write_committed("notes/src/sub/b.md", "beta\n");
    let mig = a.migrate(CHAIN_ID, "notes/src");
    assert_eq!(mig.files, 2, "the whole subtree migrated");

    // (4) Push A→B: A's `chain/journal` tip tree over B's genesis, files
    // CHAIN-RELATIVE (the production m5f-slice-002 convention).
    let new_tree = a.chain_root_tree();
    assert_ne!(new_tree, base_tree, "A's migrate actually advanced the chain");
    let ring_b = ring_trusting(&a);
    push_edit_tagged(
        &a,
        &b,
        &ring_b,
        CHAIN_ID,
        new_tree,
        base_tree,
        &a.name,
        1_700_000_000,
        &["a.md".to_string(), "sub/b.md".to_string()],
    );

    // (5) Chain-side convergence: byte-identical tip root trees.
    assert_eq!(
        a.chain_root_tree(),
        b.chain_root_tree(),
        "both members' chain tip root trees are byte-identical"
    );
    assert_eq!(
        b.chain_root_tree(),
        new_tree,
        "B fast-forwarded to A's migrated tree"
    );
    // Both tips carry the migrated blobs, S-sealed under the shared key.
    for (node, garden) in [(&a, &a.garden), (&b, &b.garden)] {
        let _ = node;
        for rel in ["a.md", "sub/b.md"] {
            let cipher = committed_blob(garden, CHAIN_REF, rel)
                .unwrap_or_else(|| panic!("{} missing chain blob {rel}", garden.display()));
            assert!(
                softfig_vault::is_shared_blob(&cipher),
                "{rel} must be in the shared (S) container on {}",
                garden.display()
            );
            assert_eq!(
                softfig_vault::shared::read_key_id(&cipher).unwrap(),
                KEY_ID,
                "{rel} sealed under the shared key id on {}",
                garden.display()
            );
        }
    }

    // (6) Composed view at each member's OWN path. Recompose both so the mount
    // registry picks up the new committed chain tip.
    a.recompose(CHAIN_ID);
    b.recompose(CHAIN_ID);

    // A serves the content at `projects/shared/...`, and NOT at B's placement.
    assert!(a.mount_path_exists("projects/shared/a.md"), "A serves a.md at its own path");
    assert!(
        a.mount_path_exists("projects/shared/sub/b.md"),
        "A serves sub/b.md at its own path"
    );
    assert!(
        !a.mount_path_exists("collab/from-ring/a.md"),
        "B's placement is meaningless on A"
    );

    // B serves the SAME content at `collab/from-ring/...`, and NOT at A's path.
    assert!(
        b.mount_path_exists("collab/from-ring/a.md"),
        "B serves a.md at its own divergent path"
    );
    assert!(
        b.mount_path_exists("collab/from-ring/sub/b.md"),
        "B serves sub/b.md at its own divergent path"
    );
    assert!(
        !b.mount_path_exists("projects/shared/a.md"),
        "A's placement is meaningless on B — identical content, per-device placement"
    );
}

// ---------------------------------------------------------------------------
// TEST 2 — a partitioned concurrent conflict converges (LWW + sidecar), and the
// sidecar lands at EACH member's own path.
// ---------------------------------------------------------------------------

/// Set both members up converged at a base tree `T` holding `a.md="base"`, then
/// drive a partitioned concurrent conflict on chain-relative `a.md`: A edits it
/// to `A-edit`, B (strictly later) to `B-edit`. Both members resolve the same
/// LWW winner (B) and reconstruct the byte-identical winner-tree + a loser
/// sidecar for A's edit — converging to a byte-identical tip — and each serves
/// that sidecar at its OWN garden path.
#[test]
fn divergent_paths_conflict_sidecar_converges_and_lands_at_each_own_path() {
    let a = new_node("node-a", MOUNT_A);
    let b = new_node("node-b", MOUNT_B);

    // Setup: divergent placement + shared key + a common base `T` = {a.md=base}.
    ok_data(a.add(MOUNT_A, Some(CHAIN_ID)));
    b.seed_offer(CHAIN_ID, Some(MOUNT_A));
    assert_eq!(b.accept(CHAIN_ID, Some(MOUNT_B)).mount_path, MOUNT_B);
    a.key_chain(CHAIN_ID, CHAIN_REF, KEY_ID);
    b.key_chain(CHAIN_ID, CHAIN_REF, KEY_ID);

    // A writes `a.md=base` through the keyed share (S-sealed), then pushes it to
    // B so both hold the identical base tree `T`.
    let genesis = b.chain_root_tree();
    a.write_committed("projects/shared/a.md", "base\n");
    let base_committed = a.chain_root_tree();
    assert_ne!(base_committed, genesis, "the base write advanced A's chain");
    let ring_b = ring_trusting(&a);
    push_edit_tagged(
        &a,
        &b,
        &ring_b,
        CHAIN_ID,
        base_committed,
        genesis,
        &a.name,
        1_700_000_000,
        &["a.md".to_string()],
    );
    let t = a.chain_root_tree();
    assert_eq!(t, b.chain_root_tree(), "both members converged at the base tree T");

    // (1) A authors a chain edit `a.md=A-edit` over `T` (CHAIN-RELATIVE path),
    // then captures A's OWN committed `(author_device, timestamp)` + new tree.
    let a_new_tree = a.commit_chain_edit("a.md", "A-edit\n");
    let a_row = a.chain_tip_row();
    let a_author_device = a_row.author_device.clone();
    let a_ts = a_row.timestamp;

    // (2) Sleep 1100ms — there is NO time-injection seam; the public commit API
    // stamps wall-clock seconds, so a >1s sleep guarantees B's edit lands in a
    // strictly later second, making LWW deterministic.
    thread::sleep(Duration::from_millis(1100));

    // (3) B authors a DIVERGENT chain edit `a.md=B-edit` over `T`.
    let b_new_tree = b.commit_chain_edit("a.md", "B-edit\n");
    let b_row = b.chain_tip_row();
    let b_author_device = b_row.author_device.clone();
    let b_ts = b_row.timestamp;
    assert!(
        b_ts > a_ts,
        "the sleep must order the edits (b_ts={b_ts} > a_ts={a_ts}); LWW would be \
         nondeterministic otherwise"
    );

    // (4) Push A→B tagged with A's OWN (author_device, timestamp) so A's edit's
    // LWW key is identical whether seen locally at A or incoming at B. B (local,
    // b_ts) beats A (incoming, a_ts) → A LOSES → sidecar for A.
    let ring_b2 = ring_trusting(&a);
    push_edit_tagged(
        &a,
        &b,
        &ring_b2,
        CHAIN_ID,
        a_new_tree,
        t,
        &a_author_device,
        a_ts,
        &["a.md".to_string()],
    );

    // (5) Symmetrically push B→A tagged with B's OWN (author_device, timestamp).
    // At A: incoming B (b_ts) beats local A (a_ts) → A LOSES → sidecar for A.
    // Same loser identity (a_author_device, a_ts) on BOTH sides.
    let ring_a = ring_trusting(&b);
    push_edit_tagged(
        &b,
        &a,
        &ring_a,
        CHAIN_ID,
        b_new_tree,
        t,
        &b_author_device,
        b_ts,
        &["a.md".to_string()],
    );

    // (6) Both nodes' chain tips are byte-identical (conflict resolution
    // converged) and carry the winner `a.md` (B-edit) S-sealed + the A-loser
    // sidecar.
    assert_eq!(
        a.chain_root_tree(),
        b.chain_root_tree(),
        "conflict resolution converged to a byte-identical tip on both members"
    );

    // The sidecar name replicates `sanitize_name_component`'s logic for the
    // actual `a_author_device` we read (it is a hostname → already a single safe
    // component, so it sanitizes to itself; we assert existence by walking the
    // tip tree, since the sanitizer is `pub(crate)` and unreachable here).
    let sidecar = format!("a.md.conflict-{}-{}.md", sanitize_component(&a_author_device), a_ts);
    for garden in [&a.garden, &b.garden] {
        assert!(
            tip_tree_has_path(garden, CHAIN_REF, &sidecar),
            "the A-loser sidecar {sidecar} is present in the tip tree on {}",
            garden.display()
        );
        // The winner `a.md` is present, shared-sealed under the chain key.
        let cipher = committed_blob(garden, CHAIN_REF, "a.md")
            .unwrap_or_else(|| panic!("winner a.md missing on {}", garden.display()));
        assert!(
            softfig_vault::is_shared_blob(&cipher),
            "winner a.md must be in the shared (S) container on {}",
            garden.display()
        );
        assert_eq!(
            softfig_vault::shared::read_key_id(&cipher).unwrap(),
            KEY_ID,
            "winner a.md sealed under the shared key id on {}",
            garden.display()
        );
    }

    // (7) The sidecar is served at EACH member's OWN path (and the cross-negative
    // holds — neither serves it at the other's placement).
    a.recompose(CHAIN_ID);
    b.recompose(CHAIN_ID);
    assert!(
        a.mount_path_exists(&format!("projects/shared/{sidecar}")),
        "A serves the sidecar at its own path"
    );
    assert!(
        b.mount_path_exists(&format!("collab/from-ring/{sidecar}")),
        "B serves the sidecar at its own divergent path"
    );
    assert!(
        !a.mount_path_exists(&format!("collab/from-ring/{sidecar}")),
        "B's placement is meaningless on A"
    );
    assert!(
        !b.mount_path_exists(&format!("projects/shared/{sidecar}")),
        "A's placement is meaningless on B"
    );

    // (8) Both tips' conflict-resolution commit intent is `sync_conflict`.
    assert_eq!(
        a.chain_tip_row().intent,
        "sync_conflict",
        "A's tip is a sync_conflict resolution"
    );
    assert_eq!(
        b.chain_tip_row().intent,
        "sync_conflict",
        "B's tip is a sync_conflict resolution"
    );
}

/// A local replica of `sanitize_name_component`'s logic (it is `pub(crate)`,
/// unreachable from an integration test): any char outside `[A-Za-z0-9._-]`
/// becomes `_`, any run of `.` collapses to one `.`, empty → `_`. A hostname is
/// already a single safe component, so this returns it unchanged — but the exact
/// derivation is replicated so the assertion is honest for any device name.
fn sanitize_component(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dot = false;
    for ch in name.chars() {
        let c = if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            ch
        } else {
            '_'
        };
        if c == '.' {
            if prev_dot {
                continue;
            }
            prev_dot = true;
        } else {
            prev_dot = false;
        }
        out.push(c);
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}
