//! Task 059 — loopback-TCP integration for the shared-chain membership split:
//! the three behaviours the live bug needed and had none of.
//!
//! The live failure was 12,854 identical journal lines over 27 days with neither
//! device learning anything: the receiver's non-member path was a bare `return`,
//! so the pusher's `serve_replication` hit its `UnexpectedEof` arm and
//! `push_shared_chain_to_host` returned `Ok(())` — a refusal was
//! indistinguishable from **success**. The unit tests in
//! `softfig_keeperd::chain_health` cover the latch in isolation; these cover the
//! paths that have to *reach* it:
//!
//! 1. [`a_push_for_a_chain_with_no_membership_row_is_refused_with_unknown_chain`]
//!    — the reason crosses the wire, signed by the refusing device, and arrives
//!    as `Ok(PushOutcome::Rejected)` rather than an `Err` or a silent `Ok`.
//! 2. [`a_refused_sender_stops_pushing_on_the_next_tick`] — driven through the
//!    production reconcile tick ([`reconcile_shared_pushes`]), so the assertion
//!    is that the real fan-out resolves no target, not that the latch would have
//!    said so if asked. The receiver counts inbound connections: a suppressed
//!    chain produces **no dial at all**.
//! 3. [`n_consecutive_refused_pushes_cost_o1_journal_lines`] — N real pushes all
//!    land on one latched row (`count == N`), and the row is then silent to an
//!    N+1'th identical observation. That is the O(1) claim measured against the
//!    live, integration-populated latch rather than a hand-fed one.
//!
//! Mirrors `m5e_shared_pull.rs`'s posture (two live daemons over loopback TCP,
//! real crypto, the production inbound dispatch via [`serve_established`]) with
//! one difference: the **sender** side here is the production outbound primitive
//! ([`push_shared_chain_to_host`], and in case 2 the whole tick), because the
//! sender's half is what the bug destroyed.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;

use softfig_ipc::{
    verbs::{op, SharedSubtreeAddArgs, UnlockArgs},
    Request,
};
use softfig_keeperd::chain_health::{Class, Role};
use softfig_keeperd::net::{
    build_local_device, build_shared_chain_push_frame, push_shared_chain_to_host,
    reconcile_shared_pushes, serve_established, PushOutcome,
};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_net::ring::{ring_path, Ring, RingEntry};
use softfig_net::transport::ik_responder;
use softfig_net::{ChainRejectReason, LocalDevice};
use softfig_store::Hash;
use softfig_vault::{Vault, VaultSession};
use softfig_vcs::{Intent, Repo, WalkSnapshot};

mod common;
use common::{fast_params, ok_data, send, wait_for_socket};

const PASS: &str = "correct horse battery staple";
const CHAIN_ID: &str = "journals";
const CHAIN_REF: &str = "chain/journals";
const MOUNT_PATH: &str = "proj/journals";

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// A live unlocked daemon (FUSE-attach seam, no watcher, no net), plus the
/// test-side vault session for its garden. `with_chain` is the whole point of the
/// fixture: the **receiver** in every case here is a daemon that holds no
/// membership row for `CHAIN_REF` at all — the live 2026-08 shape, where this
/// device's `subtree` list was empty while the peer still held its own row.
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

fn new_node(name: &str, with_chain: bool) -> Node {
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
    wait_for_socket(&socket);
    ok_data(send(
        &socket,
        &Request::new(
            op::UNLOCK,
            serde_json::to_value(UnlockArgs { passphrase: PASS.into() }).unwrap(),
        ),
    ));

    if with_chain {
        // Genesis the shared chain through the production add path, exactly as
        // `m5e_shared_pull`'s harness does: this is the device that believes it
        // is a member and keeps pushing.
        ok_data(send(
            &socket,
            &Request::new(
                op::SHARED_SUBTREE_ADD,
                serde_json::to_value(SharedSubtreeAddArgs {
                    mount_path: MOUNT_PATH.into(),
                    id: Some(CHAIN_ID.into()),
                })
                .unwrap(),
            ),
        ));
    }

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
    fn daemon(&self) -> &Daemon {
        &self.handle.as_ref().unwrap().daemon
    }

    /// A ring entry naming this node (real device id + transport static +
    /// self-signed attestation), optionally reachable at `addr`. An entry with no
    /// endpoint is unroutable (`plan_routes` yields nothing with no relay), so
    /// the dialing side always gets the `addr` form.
    fn ring_entry(&self, addr: Option<SocketAddr>) -> RingEntry {
        RingEntry {
            device_id: self.device_id,
            name: self.name.clone(),
            transport_pubkey: self.transport_pubkey,
            endpoints: addr.map(|a| vec![a.to_string()]).unwrap_or_default(),
            attestation: self.local.static_attestation,
            paired_at: 1,
        }
    }

    /// Persist `peer` into this node's **on-disk** ring, which is where the
    /// production tick reads its peers from (`load_ring` → `Ring::load` on the
    /// state dir, since a fresh garden has no `config/peers.toml`). Case 2 needs
    /// this: `reconcile_shared_pushes` takes no ring argument, by design.
    fn seed_ring(&self, peer: &RingEntry) {
        let path = ring_path(&self.garden);
        let mut ring = Ring::load(&path).unwrap();
        ring.upsert(peer.clone());
        ring.save(&path).unwrap();
    }

    /// Author a chain edit over the current tip via a fresh (WAL-sharing) repo
    /// handle. Returns `(base_tree, new_tree)` — the two trees the
    /// `SharedChainPush` frame carries. An edit beyond genesis is also what makes
    /// the tick have anything to push (a genesis-only chain is skipped).
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

    /// This node's latched divergences for `CHAIN_REF` in one role, read off the
    /// live daemon — the same read model `shared-subtree list` and the TUI render.
    fn divergences(&self, role: Role) -> Vec<softfig_keeperd::chain_health::Divergence> {
        let inner = self.daemon().inner.lock().unwrap();
        inner
            .chain_health
            .divergences(now_secs())
            .into_iter()
            .filter(|d| d.role == role && d.chain == CHAIN_REF)
            .collect()
    }
}

/// The receiving half: a real accept loop on its own thread running the
/// production inbound dispatch, counting every connection it accepts.
///
/// The count is the assertion case 2 needs — "stopped pushing" means no dial
/// reaches here, which is a different claim from "dialed and was refused again".
///
/// Deliberately not `softfig_net::testing::accept_within`: that panics when
/// nothing arrives within the shared deadline, and here a quiet stretch is the
/// *expected* outcome. Every accepted stream still gets `with_deadlines`, so the
/// wedge `accept_within` exists to prevent (a peer that connects then goes
/// silent) is still bounded — only the absence of a connection is tolerated.
struct Receiver {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Receiver {
    fn start(node: &Node, sender: &Node) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let daemon = node.daemon().clone();
        let local = node.local.clone();
        // The authenticated peer `serve_established` serves under. The receiver
        // trusts the sender as a ring peer (unkeyed chain → the member set falls
        // back to the ring), so the refusal below is about the missing chain row,
        // not about an unknown device.
        let owner = sender.ring_entry(None);
        let ring = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(sender.ring_entry(None));
            r
        }));

        let (counter, halt) = (Arc::clone(&accepted), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        // Counted BEFORE the handshake, and the dialer's push
                        // call cannot return until this connection's round-trip
                        // completes — so a tick that returns without bumping
                        // this count made no dial.
                        counter.fetch_add(1, Ordering::SeqCst);
                        conn.set_nonblocking(false).unwrap();
                        let conn = softfig_net::testing::with_deadlines(conn, "refused chain push");
                        match ik_responder(conn, &local.transport_secret, &local.hello()) {
                            Ok(session) => serve_established(&daemon, &local, &owner, &ring, session),
                            // Not a panic: an unwinding accept thread turns a
                            // clear assertion failure on the main thread into a
                            // join-time mystery. The latch assertions below fail
                            // loudly enough, with this line as the reason.
                            Err(e) => eprintln!("test receiver: IK handshake failed: {e}"),
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        eprintln!("test receiver: accept failed: {e}");
                        return;
                    }
                }
            }
        });

        Self {
            addr,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// One outbound push through the production primitive, to a receiver reachable at
/// `addr`. Returns what the round-trip MEANT — the distinction the bug erased.
fn push_once(sender: &Node, receiver: &Node, addr: SocketAddr) -> Result<PushOutcome, String> {
    let (base_tree, new_tree) = sender_tip_trees(sender);
    let host = receiver.ring_entry(Some(addr));
    let frame = build_shared_chain_push_frame(
        &sender.session,
        &sender.local,
        CHAIN_REF,
        CHAIN_ID,
        new_tree.as_bytes(),
        base_tree.as_bytes(),
        &sender.name,
        &["entry.md".to_string()],
        1_700_000_000,
    );
    push_shared_chain_to_host(
        &sender.local,
        &host,
        &frame,
        new_tree.as_bytes(),
        &sender.garden,
        None,
        None,
    )
}

/// `(base_tree, new_tree)` for the sender's current chain tip — the same pair
/// `reconcile_shared_pushes` derives (tip's parent tree, tip's tree).
fn sender_tip_trees(sender: &Node) -> (Hash, Hash) {
    let repo = Repo::open(&sender.garden).unwrap();
    let tip = repo.tip_of(CHAIN_REF).unwrap().expect("sender has a chain tip");
    let row = repo.db().get_commit(&tip).unwrap();
    let parent = row.parent.expect("the tip is an edit over genesis");
    let parent_row = repo.db().get_commit(&parent).unwrap();
    (parent_row.root_tree, row.root_tree)
}

/// Behaviour 1 — the reason crosses the wire. A push for a chain the receiver
/// holds **no membership row for** comes back as `Ok(PushOutcome::Rejected)`
/// carrying `UnknownChain`, signed by the device that refused it and naming the
/// chain that was pushed. Pre-fix this same round-trip returned `Ok(())`: the
/// session closed, `serve_replication` read it as `UnexpectedEof`, and the sender
/// recorded a success.
#[test]
fn a_push_for_a_chain_with_no_membership_row_is_refused_with_unknown_chain() {
    let sender = new_node("node-a", true);
    let receiver = new_node("node-b", false);
    sender.commit_chain_edit("proj/journals/entry.md", "shared edit from A");
    let rx = Receiver::start(&receiver, &sender);

    let outcome = push_once(&sender, &receiver, rx.addr).expect("the member ANSWERED — not an Err");

    let PushOutcome::Rejected(rejection) = outcome else {
        panic!("a non-member receiver must refuse, not accept: {outcome:?}");
    };
    assert_eq!(
        rejection.reason,
        ChainRejectReason::UnknownChain,
        "no membership row at all is UnknownChain, not NotAMember (the fixes differ)"
    );
    assert_eq!(
        rejection.chain, CHAIN_REF,
        "the refusal names the chain that was pushed"
    );
    assert!(
        rejection.verified(&receiver.device_id),
        "the refusal is signed by the device we dialed, so it is actionable"
    );
    assert_eq!(rx.accepted(), 1, "exactly one round-trip happened");

    // The receiver's own side of it: one latched inbound row, so the human-facing
    // surface can say which device holds the fix.
    let inbound = receiver.divergences(Role::Inbound);
    assert_eq!(inbound.len(), 1, "one latched inbound row: {inbound:?}");
    assert_eq!(inbound[0].class, Class::Rejected(ChainRejectReason::UnknownChain));
    assert_eq!(inbound[0].peer, sender.device_id, "the row names the pusher");
    assert_eq!(inbound[0].count, 1);
}

/// Behaviour 2 — the sender stops. Driven through the production reconcile tick,
/// so what is asserted is that the real fan-out
/// (`reconcile_shared_pushes` → `resolve_turn_targets` →
/// `ChainHealth::pushes_suppressed`) resolves **no target** for a chain a peer
/// refused, and therefore makes no dial. The pre-fix tick re-derived its targets
/// from its own membership every ~50s and pushed forever, which is what produced
/// 12,854 of these.
#[test]
fn a_refused_sender_stops_pushing_on_the_next_tick() {
    let sender = new_node("node-a", true);
    let receiver = new_node("node-b", false);
    sender.commit_chain_edit("proj/journals/entry.md", "shared edit from A");
    let rx = Receiver::start(&receiver, &sender);
    // The tick reads its peers off disk, so the receiver must be a persisted ring
    // entry with a reachable endpoint for a route to exist at all.
    sender.seed_ring(&receiver.ring_entry(Some(rx.addr)));

    // Tick 1: a member it believes in, a route to it → one real push, refused.
    reconcile_shared_pushes(sender.daemon(), &sender.local);
    assert_eq!(rx.accepted(), 1, "the first tick pushes for real");
    let outbound = sender.divergences(Role::Outbound);
    assert_eq!(outbound.len(), 1, "the refusal latched: {outbound:?}");
    assert_eq!(
        outbound[0].class,
        Class::Rejected(ChainRejectReason::UnknownChain)
    );
    assert!(
        outbound[0].class.is_terminal(),
        "UnknownChain is terminal for the sender, so it gates the fan-out"
    );

    // Ticks 2 and 3: nothing changed here, so the fan-out finds no target and
    // dials nothing. `push_shared_chain_to_host` is synchronous, so a dial this
    // tick would already have been accepted by the time the call returns.
    reconcile_shared_pushes(sender.daemon(), &sender.local);
    reconcile_shared_pushes(sender.daemon(), &sender.local);
    assert_eq!(
        rx.accepted(),
        1,
        "a latched membership verdict suppresses the push entirely — no dial, \
         not a dial that gets refused again"
    );

    // And the sender did NOT act on the say-so by dropping its own membership:
    // convergence runs through the authority that grants membership, never
    // through the wire.
    let repo = Repo::open(&sender.garden).unwrap();
    assert!(
        repo.tip_of(CHAIN_REF).unwrap().is_some(),
        "the local chain is untouched; only pushing is paused"
    );
    assert_eq!(
        sender.divergences(Role::Outbound).len(),
        1,
        "the suppressed ticks add no new rows either"
    );
}

/// Behaviour 3 — the log is bounded. N consecutive refused pushes all land on one
/// latched row (`count == N`, so none of them bypassed the latch on the way in),
/// and that row is then **silent** to an N+1'th identical observation. The live
/// bug logged one line per push, unconditionally, forever: 12,854 lines.
///
/// The per-line budget inside the latch is unit-tested in
/// `softfig_keeperd::chain_health` (an in-process test cannot capture the
/// daemon's `eprintln!`); what is integration-tested here is that the inbound
/// serve path routes every refusal *through* `observe` rather than printing
/// beside it.
#[test]
fn n_consecutive_refused_pushes_cost_o1_journal_lines() {
    const N: u64 = 6;

    let sender = new_node("node-a", true);
    let receiver = new_node("node-b", false);
    sender.commit_chain_edit("proj/journals/entry.md", "shared edit from A");
    let rx = Receiver::start(&receiver, &sender);

    // Pushed directly rather than via the tick: the tick latches after the first
    // refusal and stops (behaviour 2), so the N-in-a-row case is what the
    // receiver sees from a peer running pre-059 code — which is exactly the live
    // shape, since the flooding device has not been upgraded.
    for i in 1..=N {
        let outcome = push_once(&sender, &receiver, rx.addr)
            .unwrap_or_else(|e| panic!("push {i} did not complete a round-trip: {e}"));
        assert!(
            matches!(outcome, PushOutcome::Rejected(_)),
            "push {i} must be refused, not accepted"
        );
    }
    assert_eq!(rx.accepted(), N as usize, "all N round-trips happened");

    let inbound = receiver.divergences(Role::Inbound);
    assert_eq!(
        inbound.len(),
        1,
        "N refusals collapse onto ONE row, not N rows: {inbound:?}"
    );
    assert_eq!(
        inbound[0].count, N,
        "every refusal was observed by the latch — none bypassed it"
    );

    // The row has already spoken, so the next identical observation is silent:
    // O(1) lines for this outage, not O(N).
    let mut inner = receiver.daemon().inner.lock().unwrap();
    let line = inner.chain_health.observe(
        Role::Inbound,
        CHAIN_REF,
        sender.device_id,
        Class::Rejected(ChainRejectReason::UnknownChain),
        now_secs(),
    );
    assert!(
        line.is_none(),
        "an identical refusal inside the summary window must print nothing, got: {line:?}"
    );
}
