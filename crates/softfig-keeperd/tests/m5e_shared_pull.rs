//! M5e slice 002 part 2b-4a — loopback-TCP integration for the shared-chain
//! push → apply path: 2-daemon fast-forward propagation + `AlreadyPresent`
//! dedup, with real crypto over a real Noise `IK` session.
//!
//! Mirrors `m5b_replica.rs`'s posture (two live daemons over loopback TCP,
//! real ciphertext, real signatures) but drives the **2b-3 wire primitives**
//! directly rather than through the live net runtime — that runtime's
//! push-on-commit sweep (`reconcile_shared_pushes`) and inbound listener are
//! timing-driven and mDNS-dependent, so the deterministic seam is to hand-build
//! the Noise session and call the primitives on each end:
//!
//! * **sender**: [`build_shared_chain_push_frame`] then [`serve_shared_subtree`]
//!   (the send-frame-then-serve choreography `push_shared_chain_to_host` runs
//!   after its dial).
//! * **receiver**: [`serve_established`] — the real inbound dispatch — decodes
//!   the `SharedChainPush` frame and routes it into `serve_shared_chain_push`,
//!   which pulls the edit's tree closure into the live store and re-authors it
//!   as a local `shared_pull` commit.
//!
//! With exactly two members the receiver's mesh re-push target set is empty
//! (members − self − sender = ∅), so these 2-daemon cases exercise the
//! outbound-serve + receive + apply spine but NOT the fan-out hop.
//!
//! Part 2b-4b (`mesh_converges_and_terminates_across_three_daemons`) adds the
//! fan-out: three daemons A,B,C, each with a real in-test accept-loop listener,
//! so a seed A→B fans out B→C→A entirely through the production re-push dial
//! ([`push_shared_chain_to_host`] inside `serve_shared_chain_push`'s `Applied`
//! arm). It converges (all three root trees == the edit tree) and terminates
//! (C→A is `AlreadyPresent` — A authored the tree — so A does not re-push).

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;

use softfig_ipc::{
    self,
    verbs::{op, SharedSubtreeAddArgs, UnlockArgs},
    Request, Response,
};
use softfig_keeperd::net::{
    build_local_device, build_shared_chain_push_frame, push_shared_chain_to_host, serve_established,
    serve_shared_subtree,
};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_net::ring::{Ring, RingEntry};
use softfig_net::transport::{ik_initiator, ik_responder};
use softfig_net::LocalDevice;
use softfig_store::Hash;
use softfig_vault::{params::VaultParams, Vault, VaultSession};
use softfig_vcs::{Intent, Repo, WalkSnapshot};

const PASS: &str = "correct horse battery staple";
const CHAIN_ID: &str = "journals";
const CHAIN_REF: &str = "chain/journals";
const MOUNT_PATH: &str = "proj/journals";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

/// A live unlocked daemon (FUSE-attach seam, no watcher, no net) with a
/// genesis'd shared chain, plus the test-side vault session/keys for its garden
/// (the test inits the vault, so it holds the same identity + transport keys the
/// daemon derives on unlock — used to sign push frames, author chain edits, and
/// forge the peer's ring entry).
struct Node {
    _tmp: tempfile::TempDir,
    garden: std::path::PathBuf,
    handle: Option<DaemonHandle>,
    session: VaultSession,
    local: LocalDevice,
    device_id: [u8; 32],
    transport_pubkey: [u8; 32],
    name: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
            let _ = handle.join();
        }
    }
}

fn rpc(socket: &Path, op: &str, args: serde_json::Value) -> Response {
    let mut s = softfig_ipc::connect(socket).expect("connect");
    softfig_ipc::call(&mut s, &Request::new(op, args)).expect("call")
}

fn ok(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("expected Ok, got {kind:?}: {error}"),
    }
}

fn new_node(name: &str) -> Node {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path().to_path_buf();
    let (_v, session, _r) = Vault::init_with_params(&garden, PASS.as_bytes(), fast_params()).unwrap();
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

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !socket.exists() {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "socket for {name} never appeared");
    ok(rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs { passphrase: PASS.into() }).unwrap(),
    ));

    // Genesis the shared chain through the production add path (empty
    // `WalkSnapshot`, so the genesis root tree is the deterministic empty tree —
    // identical across devices, which is what lets an independent add on each
    // node produce a shared base the peer's edit fast-forwards over).
    ok(rpc(
        &socket,
        op::SHARED_SUBTREE_ADD,
        serde_json::to_value(SharedSubtreeAddArgs {
            mount_path: MOUNT_PATH.into(),
            id: Some(CHAIN_ID.into()),
        })
        .unwrap(),
    ));

    Node {
        _tmp: tmp,
        garden,
        handle: Some(handle),
        session,
        local,
        device_id,
        transport_pubkey,
        name: name.to_string(),
    }
}

impl Node {
    /// A ring entry naming this node (its real device id + transport static +
    /// self-signed attestation), for the peer to trust it as an S-member.
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

    /// Author a chain edit on this node's `chain/<id>` over its current tip via a
    /// fresh (WAL-sharing) repo handle. Returns `(base_tree, new_tree)`: the tip
    /// tree the edit was authored over, and the edit's root tree — the two the
    /// `SharedChainPush` frame carries.
    fn commit_chain_edit(&self, filename: &str, body: &str) -> (Hash, Hash) {
        let mut repo = Repo::open(&self.garden).unwrap();
        let base_tip = repo.tip_of(CHAIN_REF).unwrap().expect("chain genesis exists");
        let base_tree = repo.db().get_commit(&base_tip).unwrap().root_tree;
        let mut snap = WalkSnapshot::empty();
        snap.insert_file(Path::new(filename), 0o100644, body.as_bytes().to_vec())
            .unwrap();
        let intent = Intent::new("manual_edit", json!({ "path": filename })).unwrap();
        let edit_tip = repo
            .commit_snapshot_to(CHAIN_REF, &self.session, snap, intent)
            .unwrap();
        let new_tree = repo.db().get_commit(&edit_tip).unwrap().root_tree;
        (base_tree, new_tree)
    }

    /// The receiver's `chain/<id>` tip commit + its root tree, via a fresh repo
    /// handle (reads the daemon's committed WAL state).
    fn chain_tip(&self) -> Option<(Hash, Hash)> {
        let repo = Repo::open(&self.garden).unwrap();
        repo.tip_of(CHAIN_REF).unwrap().map(|tip| {
            let row = repo.db().get_commit(&tip).unwrap();
            (tip, row.root_tree)
        })
    }

    fn chain_intent(&self, commit: Hash) -> String {
        Repo::open(&self.garden).unwrap().db().get_commit(&commit).unwrap().intent
    }
}

/// Push one already-committed chain edit from `sender` to `receiver` over a real
/// loopback TCP + Noise `IK` session, driving the 2b-3 primitives directly: the
/// sender sends the signed frame then serves the edit's subtree closure; the
/// receiver runs the production inbound dispatch (`serve_established` →
/// `serve_shared_chain_push`), which pulls + re-authors it. `receiver_ring` must
/// already trust `sender` as an S-member.
fn push_edit(
    sender: &Node,
    receiver: &Node,
    receiver_ring: &Arc<Mutex<Ring>>,
    new_tree: Hash,
    base_tree: Hash,
    files: &[String],
) {
    let frame = build_shared_chain_push_frame(
        &sender.session,
        &sender.local,
        CHAIN_REF,
        MOUNT_PATH,
        new_tree.as_bytes(),
        base_tree.as_bytes(),
        &sender.name,
        files,
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Sender (initiator) on a thread: dial, IK handshake against the receiver's
    // transport static, send the push frame, then serve the subtree closure.
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
        // Result deliberately ignored (mirrors m5b's owner serve): a benign
        // EOF once the receiver finishes pulling is not a failure — the receiver
        // side's resulting chain state is the real assertion.
        let _ = serve_shared_subtree(&mut session, &new_tree_bytes, &sender_garden, None);
    });

    // Receiver (responder) on the main thread: accept, IK reconnect, then the
    // real inbound dispatch on the first frame.
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

/// Scenario 1 — fast-forward propagation. `a` commits an edit to the shared
/// chain and pushes it to `b`; `b` applies it as a local `shared_pull` commit
/// that fast-forwards its chain ref to a commit whose root tree equals `a`'s
/// edit tree.
#[test]
fn fast_forward_propagates_a_shared_edit_to_a_peer() {
    let a = new_node("node-a");
    let b = new_node("node-b");

    // b trusts a as the chain's other S-member (unkeyed chain → member set falls
    // back to the ring; `assemble_member_set` = {b} ∪ ring peers = {b, a}).
    let ring_b = Arc::new(Mutex::new({
        let mut r = Ring::default();
        r.upsert(a.ring_entry());
        r
    }));

    // Before: b holds only the empty genesis, and a's genesis base tree matches
    // it (both are the deterministic empty tree) — the clean fast-forward setup.
    let (_, b_genesis_tree) = b.chain_tip().expect("b has a genesis");
    let (base_tree, new_tree) = a.commit_chain_edit("proj/journals/entry.md", "shared edit from A");
    assert_eq!(
        base_tree, b_genesis_tree,
        "a's edit base must equal b's genesis tree for a clean ff"
    );
    assert_ne!(new_tree, base_tree, "the edit must actually change the tree");

    push_edit(&a, &b, &ring_b, new_tree, base_tree, &["proj/journals/entry.md".into()]);

    let (b_tip, b_tip_tree) = b.chain_tip().expect("b's chain still exists");
    assert_eq!(
        b_tip_tree, new_tree,
        "b's chain fast-forwarded to a commit over a's edit tree"
    );
    assert_eq!(
        b.chain_intent(b_tip),
        "shared_pull",
        "the applied commit is re-authored under the shared_pull intent"
    );
    assert_ne!(
        b_tip, new_tree,
        "sanity: the local commit hash is not the tree hash"
    );
}

/// Scenario 2 — ping-pong terminates via `AlreadyPresent`. After b holds a's
/// edit, re-pushing the SAME edit is a content dedup: b's tree already equals the
/// peer tree, so `apply_shared_pull` returns `AlreadyPresent` and the chain ref
/// does NOT advance (no new re-authored commit). With two members b's own
/// re-push target set is empty, so the terminator here is at the receiver.
#[test]
fn re_pushing_a_held_edit_is_already_present_and_does_not_advance() {
    let a = new_node("node-a");
    let b = new_node("node-b");

    let ring_b = Arc::new(Mutex::new({
        let mut r = Ring::default();
        r.upsert(a.ring_entry());
        r
    }));

    let (base_tree, new_tree) = a.commit_chain_edit("proj/journals/entry.md", "shared edit from A");
    let files = vec!["proj/journals/entry.md".to_string()];

    // First push applies (fast-forward).
    push_edit(&a, &b, &ring_b, new_tree, base_tree, &files);
    let (tip_after_first, tree_after_first) = b.chain_tip().expect("b applied the edit");
    assert_eq!(tree_after_first, new_tree, "first push fast-forwarded");

    // Re-push the identical edit: dedup by tree content, no advance.
    push_edit(&a, &b, &ring_b, new_tree, base_tree, &files);
    let (tip_after_second, _) = b.chain_tip().expect("b's chain still exists");
    assert_eq!(
        tip_after_second, tip_after_first,
        "an already-held edit must not re-author a new commit (ping-pong terminator)"
    );
}

// --- 2b-4b: 3-daemon mesh converge + terminate ------------------------------

/// A live accept-loop listener for one node, on its own thread: it accepts a
/// real loopback connection, runs the IK responder, resolves the dialing peer's
/// `RingEntry` from the ring (by transport static), and hands the session to the
/// production inbound dispatch [`serve_established`] — the same path the live
/// daemon's listener runs. This is what lets a re-push actually DIAL a node (the
/// 2-daemon cases had no listener because their target set was empty). The loop
/// polls a non-blocking accept so a shutdown flag can stop it; [`Drop`] sets the
/// flag and joins, so a failed assertion never leaks the thread.
struct MeshListener {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Drop for MeshListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// A ring entry naming `node` with its accept-loop `addr` filled in, so a peer's
/// `push_shared_chain_to_host` (`plan_routes`/`dial_direct`) can reach it. The
/// 2-daemon cases left endpoints empty (nobody dialed the members); the mesh
/// re-push MUST resolve a real endpoint per hop.
fn ring_entry_at(node: &Node, addr: SocketAddr) -> RingEntry {
    let mut entry = node.ring_entry();
    entry.endpoints = vec![addr.to_string()];
    entry
}

/// Spawn `node`'s accept-loop listener on the already-bound (non-blocking)
/// `listener`, dispatching each inbound session through `serve_established`
/// against `ring` (the node's own view: its two peers, with endpoints).
fn spawn_mesh_listener(node: &Node, listener: TcpListener, ring: Arc<Mutex<Ring>>) -> MeshListener {
    let daemon = node.handle.as_ref().unwrap().daemon.clone();
    let local = node.local.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let join = thread::spawn(move || loop {
        if stop_thread.load(Ordering::SeqCst) {
            return;
        }
        match listener.accept() {
            Ok((conn, _)) => {
                // The accepted socket serves blocking with bounded timeouts, even
                // though the listener itself is non-blocking for the poll.
                let _ = conn.set_nonblocking(false);
                let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = conn.set_write_timeout(Some(Duration::from_secs(10)));
                let Ok(session) = ik_responder(conn, &local.transport_secret, &local.hello()) else {
                    continue; // a peer that errored before establishing; keep serving
                };
                // Trust the IK-authenticated static over any wire claim: the owner
                // is the ring member holding this transport key.
                let peer_static = *session.peer_static();
                let owner = ring
                    .lock()
                    .unwrap()
                    .peers()
                    .iter()
                    .find(|p| p.transport_pubkey == peer_static)
                    .cloned();
                if let Some(owner) = owner {
                    serve_established(&daemon, &local, &owner, &ring, session);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return,
        }
    });
    MeshListener { stop, join: Some(join) }
}

/// Scenario 3 (2b-4b) — 3-daemon mesh converge + terminate. A commits a shared
/// edit and seeds it to B; B applies then re-pushes to its remaining member
/// (`{A,B,C} − B − A = {C}`); C applies then re-pushes to ITS remaining member
/// (`{A,B,C} − C − B = {A}`); A already holds the edit tree (it authored it) so
/// its apply is `AlreadyPresent` → no re-push → the fan-out TERMINATES. The whole
/// mesh is driven by the single seed dial + the two production re-push hops; the
/// three accept-loop listeners are what make those hops land.
///
/// Asserts (1) convergence — all three chains' root trees equal A's edit tree —
/// and (2) termination at A — A's chain tip does not advance (it stays A's own
/// authored commit, never re-authored as a `shared_pull`), the direct check that
/// C→A dedup'd instead of looping. That the test returns at all (no hang) is the
/// second half of "terminates": an infinite ping-pong would only stop on socket
/// timeouts.
#[test]
fn mesh_converges_and_terminates_across_three_daemons() {
    let a = new_node("node-a");
    let b = new_node("node-b");
    let c = new_node("node-c");

    // Bind all three listeners first so every ring can carry every peer's real
    // endpoint (the rings reference each other's addrs).
    let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_c = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    let addr_b = listener_b.local_addr().unwrap();
    let addr_c = listener_c.local_addr().unwrap();
    listener_a.set_nonblocking(true).unwrap();
    listener_b.set_nonblocking(true).unwrap();
    listener_c.set_nonblocking(true).unwrap();

    // Each node's ring holds the OTHER two (with endpoints) → the unkeyed chain's
    // member set on every node is `assemble_member_set` = {self} ∪ ring peers =
    // {A,B,C}, which is what makes each re-push target set a single next hop.
    let ring_a = Arc::new(Mutex::new({
        let mut r = Ring::default();
        r.upsert(ring_entry_at(&b, addr_b));
        r.upsert(ring_entry_at(&c, addr_c));
        r
    }));
    let ring_b = Arc::new(Mutex::new({
        let mut r = Ring::default();
        r.upsert(ring_entry_at(&a, addr_a));
        r.upsert(ring_entry_at(&c, addr_c));
        r
    }));
    let ring_c = Arc::new(Mutex::new({
        let mut r = Ring::default();
        r.upsert(ring_entry_at(&a, addr_a));
        r.upsert(ring_entry_at(&b, addr_b));
        r
    }));

    // Kept alive (and dropped → stopped + joined) for the whole test.
    let _lis_a = spawn_mesh_listener(&a, listener_a, ring_a);
    let _lis_b = spawn_mesh_listener(&b, listener_b, ring_b);
    let _lis_c = spawn_mesh_listener(&c, listener_c, ring_c);

    // All three genesis to the same deterministic empty tree, so A's edit base
    // equals B's and C's tips — the clean-ff setup at every hop.
    let (base_tree, new_tree) = a.commit_chain_edit("proj/journals/entry.md", "shared edit from A");
    assert_ne!(new_tree, base_tree, "the edit must actually change the tree");
    let (a_tip_before, _) = a.chain_tip().expect("a authored the edit");

    // Seed A→B on its own thread via the production outbound push (dial B's
    // listener, send the frame, serve the closure). Its result is ignored (a
    // benign EOF once B finishes is not a failure, exactly as `push_edit` does);
    // the converged chain state is the assertion.
    let files = vec!["proj/journals/entry.md".to_string()];
    let frame = build_shared_chain_push_frame(
        &a.session,
        &a.local,
        CHAIN_REF,
        MOUNT_PATH,
        new_tree.as_bytes(),
        base_tree.as_bytes(),
        &a.name,
        &files,
    );
    let seed = {
        let a_local = a.local.clone();
        let a_garden = a.garden.clone();
        let b_target = ring_entry_at(&b, addr_b);
        let new_tree_bytes = *new_tree.as_bytes();
        thread::spawn(move || {
            let _ = push_shared_chain_to_host(
                &a_local,
                &b_target,
                &frame,
                &new_tree_bytes,
                &a_garden,
                None,
                None,
            );
        })
    };

    // Poll until all three root trees equal the edit tree, bounded — a timeout
    // means the mesh failed to converge (or to terminate, hanging the hops).
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let converged = [&a, &b, &c]
            .iter()
            .all(|n| n.chain_tip().map(|(_, tree)| tree == new_tree).unwrap_or(false));
        if converged {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "mesh did not converge within timeout: a={:?} b={:?} c={:?}",
            a.chain_tip().map(|(_, t)| t == new_tree),
            b.chain_tip().map(|(_, t)| t == new_tree),
            c.chain_tip().map(|(_, t)| t == new_tree),
        );
        thread::sleep(Duration::from_millis(50));
    }
    seed.join().unwrap();

    // Termination at A: its tip is unchanged — C→A was `AlreadyPresent`, so A
    // never re-authored (and thus never re-pushed to B, closing the loop). Its
    // tip stays its own authored `manual_edit`, not a `shared_pull`.
    let (a_tip_after, a_tree_after) = a.chain_tip().expect("a's chain still exists");
    assert_eq!(
        a_tip_after, a_tip_before,
        "A must not advance: C→A re-push is AlreadyPresent (the mesh terminator)"
    );
    assert_eq!(a_tree_after, new_tree, "A's tree is (still) the edit tree");
    assert_eq!(
        a.chain_intent(a_tip_after),
        "manual_edit",
        "A's tip stays its own authored edit, never re-authored"
    );

    // B and C adopted the edit as re-authored `shared_pull` commits.
    let (b_tip, b_tree) = b.chain_tip().expect("b's chain still exists");
    let (c_tip, c_tree) = c.chain_tip().expect("c's chain still exists");
    assert_eq!(b_tree, new_tree, "B fast-forwarded to the edit tree");
    assert_eq!(c_tree, new_tree, "C fast-forwarded to the edit tree (via the B→C hop)");
    assert_eq!(b.chain_intent(b_tip), "shared_pull", "B applied it as a shared_pull");
    assert_eq!(c.chain_intent(c_tip), "shared_pull", "C applied it as a shared_pull");
    assert_ne!(b_tip, new_tree, "sanity: commit hash is not the tree hash");
    assert_ne!(c_tip, new_tree, "sanity: commit hash is not the tree hash");
}
