//! M5b device-chain replication: the wire drive loops + the host/owner traits.
//!
//! One **owner** (the single writer of a linear device chain) replicates its
//! signed, content-addressed *ciphertext* to authorized backup **hosts** that
//! verify and store it but cannot decrypt it. This module owns the **protocol**
//! — the request/response exchange over an established [`NoiseSession`] and the
//! **fast-forward-only** ingest policy — expressed over two traits the caller
//! implements:
//!
//! * [`ReplicaSource`] — the owner side. Serves a signed [`TipAnnounce`], commit
//!   rows, tree rows, and ciphertext objects on request.
//! * [`ReplicaSink`] — the host side. Verifies (per-commit signature, content
//!   addresses, owner binding) and stores into a ciphertext-only mirror it never
//!   decrypts; exposes the mirror's tip/ancestry so the drive loop can enforce
//!   fast-forward-only.
//!
//! Crypto + storage stay with the caller (keeperd): `softfig-net` holds no vault
//! keys and no VCS/store types. This module carries only the wire shapes, the
//! drive logic, and the domain-separated **signing-byte** helpers
//! ([`tipannounce_signing_bytes`], [`grant_signing_bytes`]) — mirroring the
//! [`attest`](crate::attest) split, the vault signs/verifies the bytes.
//!
//! # Roles, not dialers
//!
//! Replication direction follows the *grant relationship*, not who dialed: the
//! chain owner is always the source, the backup host always the sink (it pulls,
//! verifies, fast-forwards). Whether the owner dialed (push-on-commit) or the
//! host dialed (pull-on-connect), the host runs [`pull_replication`] and the
//! owner runs [`serve_replication`] over the same session. Either way the sink
//! reconciles from the announced tip back to what it already holds, so a single
//! push *is* the authoritative tip-driven catch-up.
//!
//! # Fast-forward only
//!
//! A single honest owner writes a linear chain, so a replicated tip is always a
//! descendant of the mirror's tip. The drive loop walks back from the announced
//! tip until it reaches a commit the mirror already holds; that commit **must**
//! be the mirror's current tip (or genesis, for an empty mirror). Anything else
//! — a fork or a rollback — is a tamper/key-compromise signal: the loop refuses
//! and the caller alarms. The mirror is never force-updated.

use std::io::{Read, Write};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::error::{NetError, Result};
use crate::proto::{
    frame, CommitData, Frame, ObjectData, ReplicaGrant, TipAnnounce, TreeData,
};
use crate::transport::{NoiseReader, NoiseSession, NoiseWriter, SplitIo};

/// Domain-separation prefix for the [`TipAnnounce`] signature. Versioned and
/// distinct from every other context the identity key signs (commits, the
/// transport attestation, the replication grant).
const TIPANNOUNCE_DOMAIN: &[u8] = b"softfig/replica/tip-announce/v1";

/// Domain-separation prefix for the [`ReplicaGrant`](crate::proto::ReplicaGrant)
/// signature.
const GRANT_DOMAIN: &[u8] = b"softfig/replica/grant/v1";

/// Upper bound on the number of commits the sink will walk back in one pull,
/// so a hostile/buggy source can't drive an unbounded walk + allocation. A
/// personal device chain is far smaller; raise deliberately if needed.
/// (v1 holds the missing-commit set in memory — streaming/resumable backfill of
/// very long chains is a noted follow-up.)
const MAX_CHAIN_WALK: usize = 1_000_000;

/// The exact bytes the owner's Ed25519 identity signs for a [`TipAnnounce`].
/// Variable-length fields are length-prefixed so no two distinct tuples share an
/// encoding. The vault produces the signature; the verifier reconstructs these
/// bytes and checks it against the owner's identity key.
pub fn tipannounce_signing_bytes(chain_id: &[u8], tip_hash: &[u8], height: u64) -> Vec<u8> {
    let mut m =
        Vec::with_capacity(TIPANNOUNCE_DOMAIN.len() + 8 + chain_id.len() + 8 + tip_hash.len() + 8);
    m.extend_from_slice(TIPANNOUNCE_DOMAIN);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(&(tip_hash.len() as u32).to_be_bytes());
    m.extend_from_slice(tip_hash);
    m.extend_from_slice(&height.to_be_bytes());
    m
}

/// The exact bytes the owner's Ed25519 identity signs for a replication grant:
/// "I authorize `grantee_device_id` to mirror `chain_id`, issued at `issued_at`."
/// Length-prefixed + domain-separated; the host reconstructs and verifies it
/// against the connecting ring member's identity key.
pub fn grant_signing_bytes(grantee_device_id: &[u8], chain_id: &[u8], issued_at: i64) -> Vec<u8> {
    let mut m =
        Vec::with_capacity(GRANT_DOMAIN.len() + 8 + grantee_device_id.len() + 8 + chain_id.len() + 8);
    m.extend_from_slice(GRANT_DOMAIN);
    m.extend_from_slice(&(grantee_device_id.len() as u32).to_be_bytes());
    m.extend_from_slice(grantee_device_id);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(&issued_at.to_be_bytes());
    m
}

/// Verify a [`TipAnnounce`]'s signature against `owner_pubkey` (the chain
/// owner's Ed25519 identity). Never panics on malformed input — a bad key, a
/// wrong-length signature, or a non-verifying signature all return `false`.
pub fn verify_tipannounce(owner_pubkey: &[u8; 32], ann: &TipAnnounce) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(owner_pubkey) else {
        return false;
    };
    let Ok(sig_bytes): std::result::Result<[u8; 64], _> = ann.signature.as_slice().try_into() else {
        return false;
    };
    let msg = tipannounce_signing_bytes(&ann.chain_id, &ann.tip_hash, ann.height);
    vk.verify(&msg, &Signature::from_bytes(&sig_bytes)).is_ok()
}

/// Verify a [`ReplicaGrant`]: it names `self_device_id` as grantee and is signed
/// by `owner_pubkey` (the connecting ring member's identity). Both halves of
/// consent: the owner authorized *this* host for *this* chain. Never panics.
pub fn verify_grant(
    grant: &ReplicaGrant,
    owner_pubkey: &[u8; 32],
    self_device_id: &[u8; 32],
) -> bool {
    if grant.grantee_device_id.as_slice() != self_device_id.as_slice() {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(owner_pubkey) else {
        return false;
    };
    let Ok(sig_bytes): std::result::Result<[u8; 64], _> = grant.signature.as_slice().try_into()
    else {
        return false;
    };
    let msg = grant_signing_bytes(&grant.grantee_device_id, &grant.chain_id, grant.issued_at);
    vk.verify(&msg, &Signature::from_bytes(&sig_bytes)).is_ok()
}

/// The owner side of replication: serve chain data the sink asks for. All four
/// methods are read-only against the owner's own VCS store; `tip_announce`
/// additionally returns a signature the owner's vault produced.
pub trait ReplicaSource {
    /// The current chain tip + height, signed by the owner. An empty `tip_hash`
    /// means the chain has no commits yet.
    fn tip_announce(&self) -> TipAnnounce;
    /// The commit row for `hash`, or a `found = false` [`CommitData`] if absent.
    fn get_commit(&self, hash: &[u8; 32]) -> CommitData;
    /// The tree rows for `hash`, or a `found = false` [`TreeData`] if absent.
    fn get_tree(&self, hash: &[u8; 32]) -> TreeData;
    /// The ciphertext blob for `hash`, or a `found = false` [`ObjectData`].
    fn get_object(&self, hash: &[u8; 32]) -> ObjectData;
}

/// The host side of replication: verify + store into a ciphertext-only mirror.
/// Implementors never decrypt; they only check signatures, content addresses,
/// and the owner binding, and expose the mirror's tip so the drive loop can
/// enforce fast-forward-only.
pub trait ReplicaSink {
    /// Verify a [`TipAnnounce`]'s signature against the chain owner's identity
    /// key. `false` aborts the pull before any state changes.
    fn verify_announce(&self, ann: &TipAnnounce) -> bool;
    /// The mirror's current stored tip, or `None` if the mirror is empty.
    fn stored_tip(&self) -> Option<[u8; 32]>;
    /// Whether the mirror already holds the commit `hash`.
    fn has_commit(&self, hash: &[u8; 32]) -> bool;
    /// Verify a commit's integrity **without storing it**: declared hash matches
    /// its canonical form, the Ed25519 signature verifies, and `author_pubkey`
    /// is the chain owner's identity key. Called during the back-walk so a
    /// forged parent pointer can't steer the chain.
    fn verify_commit(&self, c: &CommitData) -> Result<()>;
    /// Store a previously-[`verify_commit`](Self::verify_commit)ed commit row.
    /// Does **not** advance the tip.
    fn store_commit(&mut self, c: &CommitData) -> Result<()>;
    /// Whether the mirror already holds the tree `hash` (and, by construction,
    /// its whole subtree — trees are stored post-order).
    fn has_tree(&self, hash: &[u8; 32]) -> bool;
    /// Verify `t.hash == BLAKE3(canonical_tree_bytes(entries))` and store it.
    fn store_tree(&mut self, t: &TreeData) -> Result<()>;
    /// Whether the mirror already holds the ciphertext object `hash`.
    fn has_object(&self, hash: &[u8; 32]) -> bool;
    /// Verify `BLAKE3(bytes) == hash` and store the ciphertext object.
    fn store_object(&mut self, hash: &[u8; 32], bytes: &[u8]) -> Result<()>;
    /// Advance the mirror's stored tip to `hash` (height for status/anti-rollback
    /// bookkeeping). Called once, last, after the whole range applied.
    fn advance_tip(&mut self, hash: &[u8; 32], height: u64) -> Result<()>;
}

/// What a [`pull_replication`] run did, for the caller's status/log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PullSummary {
    /// The mirror was already at the announced tip; nothing fetched.
    pub up_to_date: bool,
    pub commits: u64,
    pub trees: u64,
    pub objects: u64,
    /// The tip the mirror advanced to, if it advanced.
    pub new_tip: Option<[u8; 32]>,
}

/// What a [`serve_replication`] run answered, for the owner's log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServeSummary {
    pub commits_served: u64,
    pub trees_served: u64,
    pub objects_served: u64,
}

/// What a [`pull_subtree`] run fetched, for the caller's status/log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubtreeSummary {
    /// The store already held the whole closure; nothing fetched.
    pub up_to_date: bool,
    pub trees: u64,
    pub objects: u64,
}

/// What a pull negotiation ([`negotiate_pull`]) resolved to: what, if anything,
/// the mirror must backfill. Computed identically for the sequential and
/// full-duplex drivers so they agree on the fast-forward / fork decision
/// bit-for-bit.
enum Plan {
    /// The mirror already holds the announced tip — nothing to fetch.
    UpToDate,
    /// The owner has no commits to mirror.
    Empty,
    /// The commits missing from the mirror (newest .. oldest) plus the tip to
    /// advance to once they (and their trees/objects) are stored.
    Backfill {
        missing: Vec<CommitData>,
        announced_tip: [u8; 32],
        height: u64,
    },
}

/// Phase 1 (ask for the tip + verify the signed announce) and phase 2 (walk
/// back from the announced tip to the fast-forward base, verifying each commit
/// and rejecting forks/rollbacks). Shared by [`pull_replication`] and
/// [`pull_replication_pipelined`]. It stores nothing and sends no `ReplicaDone`,
/// so the caller owns storage + session teardown.
fn negotiate_pull<S: Read + Write>(
    session: &mut NoiseSession<S>,
    sink: &mut dyn ReplicaSink,
) -> Result<Plan> {
    // 1. Ask for the tip + verify the signed announce.
    session.send_frame(&Frame::get_tip())?;
    let ann = expect_tip_announce(session.recv_frame()?)?;
    if !sink.verify_announce(&ann) {
        return Err(NetError::Protocol(
            "tip announce failed owner signature verification",
        ));
    }
    if ann.tip_hash.is_empty() {
        // Owner has no commits — nothing to mirror.
        return Ok(Plan::Empty);
    }
    let announced_tip = to_hash32(&ann.tip_hash)?;

    if sink.stored_tip() == Some(announced_tip) {
        return Ok(Plan::UpToDate);
    }

    // 2. Walk back from the announced tip, verifying each commit, until we reach
    //    the fast-forward base (a commit the mirror holds) or genesis.
    let mut missing: Vec<CommitData> = Vec::new(); // newest .. oldest
    let mut cur = announced_tip;
    loop {
        if missing.len() > MAX_CHAIN_WALK {
            return Err(NetError::Protocol(
                "replication chain walk exceeded limit",
            ));
        }
        if sink.has_commit(&cur) {
            // Fast-forward only: the base must be the mirror's current tip.
            if sink.stored_tip() != Some(cur) {
                return Err(NetError::Protocol(
                    "non-fast-forward replication (fork or rollback); refusing",
                ));
            }
            break;
        }
        let c = request_commit(session, &cur)?;
        sink.verify_commit(&c)?;
        let parent = parent_of(&c)?;
        missing.push(c);
        match parent {
            Some(p) => cur = p,
            None => {
                // Reached genesis. If the mirror already holds commits but this
                // chain never met them, the two share no history — a fork.
                if sink.stored_tip().is_some() {
                    return Err(NetError::Protocol(
                        "replicated chain shares no history with the mirror (fork); refusing",
                    ));
                }
                break; // empty mirror -> full backfill from genesis
            }
        }
    }

    Ok(Plan::Backfill {
        missing,
        announced_tip,
        height: ann.height,
    })
}

/// Drive a pull as the **sink** (host). Asks for the tip, verifies the announce,
/// walks back to the fast-forward base (rejecting forks/rollbacks), then applies
/// the missing commits oldest-first — fetching each commit's trees + ciphertext
/// objects it lacks — and advances the mirror tip. Sends `ReplicaDone` when
/// finished so the source can close.
///
/// This is the **sequential** driver: one strict request→response→request
/// round-trip per object. It works over any `Read + Write` stream, including the
/// relay tunnel. LAN-direct callers use [`pull_replication_pipelined`] for the
/// same result with a full-duplex, windowed transfer.
pub fn pull_replication<S: Read + Write>(
    session: &mut NoiseSession<S>,
    sink: &mut dyn ReplicaSink,
) -> Result<PullSummary> {
    let (missing, announced_tip, height) = match negotiate_pull(session, sink)? {
        Plan::Empty => {
            session.send_frame(&Frame::replica_done())?;
            return Ok(PullSummary::default());
        }
        Plan::UpToDate => {
            session.send_frame(&Frame::replica_done())?;
            return Ok(PullSummary {
                up_to_date: true,
                ..Default::default()
            });
        }
        Plan::Backfill {
            missing,
            announced_tip,
            height,
        } => (missing, announced_tip, height),
    };

    // 3. Apply oldest -> newest: each commit's trees + objects, then the row.
    let mut summary = PullSummary::default();
    for c in missing.iter().rev() {
        let root = to_hash32(&c.root_tree)?;
        ensure_tree(session, sink, &root, &mut summary)?;
        sink.store_commit(c)?;
        summary.commits += 1;
    }
    sink.advance_tip(&announced_tip, height)?;
    session.send_frame(&Frame::replica_done())?;
    summary.new_tip = Some(announced_tip);
    Ok(summary)
}

/// Ensure the full subtree rooted at `hash` is mirrored, fetching missing trees
/// and ciphertext objects from the source. **Post-order**: descendants (and a
/// tree's blob children) are stored before the tree itself, so a stored tree
/// implies its whole subtree is present (the `has_tree` dedup short-circuit is
/// then sound, even after an interrupted earlier run).
fn ensure_tree<S: Read + Write>(
    session: &mut NoiseSession<S>,
    sink: &mut dyn ReplicaSink,
    hash: &[u8; 32],
    summary: &mut PullSummary,
) -> Result<()> {
    if sink.has_tree(hash) {
        return Ok(());
    }
    let tree = request_tree(session, hash)?;
    for entry in &tree.entries {
        let target = to_hash32(&entry.target)?;
        match entry.kind.as_str() {
            "tree" => ensure_tree(session, sink, &target, summary)?,
            "blob" => {
                if !sink.has_object(&target) {
                    let bytes = request_object(session, &target)?;
                    sink.store_object(&target, &bytes)?;
                    summary.objects += 1;
                }
            }
            _ => return Err(NetError::Protocol("tree entry has unknown kind")),
        }
    }
    sink.store_tree(&tree)?;
    summary.trees += 1;
    Ok(())
}

/// Fetch the full subtree rooted at `root_tree` — every tree row + ciphertext
/// object in its closure the sink lacks — from a peer running
/// [`serve_replication`], **without** touching the commit graph. This is the M5e
/// shared-pull transfer primitive: a `SharedChainPush` names a peer's committed
/// edit by its `new_tree` content hash, and the receiver pulls exactly that tree
/// closure into its LOCAL store so it can re-author the edit as its own
/// `shared_pull` commit — the peer's commit row is never transferred or adopted
/// (re-authoring gives each device its own author + signature; convergence is by
/// content, see keeperd's `apply_shared_pull`). Because the source's
/// [`serve_replication`] answers `GetTree`/`GetObject` for any hash, the same
/// unchanged serve loop backs both this and [`pull_replication`].
///
/// Unlike [`pull_replication`] there is no tip announce, no fast-forward walk,
/// and no tip advance — so only the sink's tree/object methods
/// ([`has_tree`](ReplicaSink::has_tree) / [`store_tree`](ReplicaSink::store_tree)
/// / [`has_object`](ReplicaSink::has_object) /
/// [`store_object`](ReplicaSink::store_object)) are exercised, each verifying its
/// content address before storing. Post-order like [`ensure_tree`], so a stored
/// tree still implies its whole subtree is present (the `has_tree` short-circuit
/// stays sound across an interrupted earlier run). The CALLER decides what to do
/// with `root_tree` once its closure is present (keeperd hands it to
/// `apply_shared_pull`). Sends `ReplicaDone` when finished so the source closes.
pub fn pull_subtree<S: Read + Write>(
    session: &mut NoiseSession<S>,
    sink: &mut dyn ReplicaSink,
    root_tree: &[u8; 32],
) -> Result<SubtreeSummary> {
    let already_present = sink.has_tree(root_tree);
    let mut summary = PullSummary::default();
    ensure_tree(session, sink, root_tree, &mut summary)?;
    session.send_frame(&Frame::replica_done())?;
    Ok(SubtreeSummary {
        up_to_date: already_present,
        trees: summary.trees,
        objects: summary.objects,
    })
}

// --- Full-duplex pipelined backfill ----------------------------------------

/// Number of replication requests kept in flight on the full-duplex backfill
/// path. Bounds the unstored bytes buffered in transit while keeping the pipe
/// full enough to hide the per-object round-trip latency the sequential driver
/// pays on every fetch.
const PIPELINE_WINDOW: usize = 32;

/// One outstanding request on the pipelined path, matched to its response by the
/// source's strict FIFO serve order (response N answers request N).
#[derive(Clone, Copy)]
enum Want {
    Tree([u8; 32]),
    Object([u8; 32]),
}

/// A message to the request-writer thread on the full-duplex path. The frame is
/// boxed so the common `Send` variant doesn't bloat every queued message to the
/// size of a full `Frame`.
enum WriterMsg {
    /// Send this request frame.
    Send(Box<Frame>),
    /// All requests are sent — emit the terminal `ReplicaDone` and stop.
    Finish,
}

/// Full-duplex counterpart of [`pull_replication`] for a stream that can
/// [`split`](NoiseSession::split) into independent read/write halves (a
/// LAN-direct `TcpStream`). It runs the same phase-1/2 negotiation, then
/// backfills by **streaming** `GetTree`/`GetObject` requests over a bounded
/// in-flight window ([`PIPELINE_WINDOW`]) while a reader thread concurrently
/// drains the responses — instead of the sequential driver's one strict
/// request→response→request round-trip per object.
///
/// **Verification and storage are identical to [`pull_replication`]:** every
/// commit is Ed25519-verified against the ring identity + owner binding, every
/// tree/object content-address is checked, objects and subtrees are stored
/// **before** the tree that references them (so a stored tree still implies its
/// whole subtree is present), commits apply **oldest→newest**, the mirror tip
/// advances **only at the very end**, and a fork/rollback is rejected before any
/// change. Both drivers therefore produce the same [`PullSummary`] and the same
/// mirror bytes — this is a throughput change only.
///
/// The relay path can't use this: its `RelayStream` tunnels a single multiplexed
/// session that isn't full-duplex-splittable, so it stays on [`pull_replication`].
pub fn pull_replication_pipelined<S>(
    mut session: NoiseSession<S>,
    sink: &mut dyn ReplicaSink,
) -> Result<PullSummary>
where
    S: Read + Write + SplitIo,
{
    let (missing, announced_tip, height) = match negotiate_pull(&mut session, sink)? {
        Plan::Empty => {
            session.send_frame(&Frame::replica_done())?;
            return Ok(PullSummary::default());
        }
        Plan::UpToDate => {
            session.send_frame(&Frame::replica_done())?;
            return Ok(PullSummary {
                up_to_date: true,
                ..Default::default()
            });
        }
        Plan::Backfill {
            missing,
            announced_tip,
            height,
        } => (missing, announced_tip, height),
    };

    // Split the session: the writer half streams requests off the main thread so
    // draining responses never blocks behind a full socket send buffer (the
    // deadlock a single-thread driver would hit if it sent a whole window before
    // reading). Responses come back in strict request order (the source serves
    // sequentially), so a FIFO queue matches each to its request.
    let (mut reader, writer) = session.split()?;
    let (req_tx, req_rx) = std::sync::mpsc::channel::<WriterMsg>();

    std::thread::scope(|scope| -> Result<PullSummary> {
        let writer_thread = scope.spawn(move || run_request_writer(writer, req_rx));

        let result = drive_backfill(&mut reader, sink, &missing, announced_tip, height, &req_tx);

        // Always release the writer (send ReplicaDone) and reclaim it, so a
        // main-thread error can't strand the thread. Surface the main error
        // first; the writer's own error only matters on the success path.
        let _ = req_tx.send(WriterMsg::Finish);
        drop(req_tx);
        let writer_result = writer_thread
            .join()
            .map_err(|_| NetError::Protocol("replication writer thread panicked"))?;
        let summary = result?;
        writer_result?;
        Ok(summary)
    })
}

/// A fetched tree that can't be stored yet. `pending` counts its distinct
/// children (subtrees + blobs) not yet present in the mirror; when it reaches
/// zero the whole subtree is stored, so the tree can be too. Only these *open*
/// trees are buffered — never every tree in the backfill at once.
struct OpenTree {
    data: TreeData,
    pending: usize,
}

#[cfg(test)]
thread_local! {
    /// Peak size of the open-tree buffer on the last `drive_backfill` run on this
    /// thread — lets `pipelined_tree_buffer_stays_bounded` assert the buffer stays
    /// bounded independent of history size. Test-only; `drive_backfill` runs on the
    /// caller's own thread (only the request-writer is spawned), so the value lands
    /// on the thread that called `pull_replication_pipelined`.
    static PEAK_OPEN_TREES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The full-duplex backfill loop. Seeds the request frontier with the missing
/// commits' root trees, then keeps [`PIPELINE_WINDOW`] requests in flight —
/// storing each object as it arrives and storing each **tree the moment its last
/// outstanding child is stored** (an outstanding-child refcount per open tree +
/// a ready-cascade). It descends **depth-first** — a discovered child is
/// scheduled ahead of not-yet-explored roots — so only the open-tree frontier is
/// buffered, never every fetched tree (peak ≈ O(window + open-tree depth), not
/// O(all unique trees)). Trees still land subtree-before-parent (a stored tree
/// implies its whole subtree is present); commits apply oldest→newest; the tip
/// advances last — the exact order [`pull_replication`] applies.
fn drive_backfill<R: Read>(
    reader: &mut NoiseReader<R>,
    sink: &mut dyn ReplicaSink,
    missing: &[CommitData],
    announced_tip: [u8; 32],
    height: u64,
    req_tx: &std::sync::mpsc::Sender<WriterMsg>,
) -> Result<PullSummary> {
    use std::collections::{HashMap, HashSet, VecDeque};

    let mut summary = PullSummary::default();
    let mut frontier: VecDeque<Want> = VecDeque::new();
    let mut outstanding: VecDeque<Want> = VecDeque::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    // Fetched-but-unstored trees (the open frontier) + reverse edges from a
    // not-yet-present child to the open trees waiting on it. Bounded by the DFS
    // descent, not the total tree count.
    let mut open: HashMap<[u8; 32], OpenTree> = HashMap::new();
    let mut waiters: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    #[cfg(test)]
    let mut peak_open = 0usize;

    // Seed: every missing commit's root tree the mirror lacks. Dedup so a tree
    // shared across commits is requested only once.
    for c in missing {
        let root = to_hash32(&c.root_tree)?;
        if seen.insert(root) && !sink.has_tree(&root) {
            frontier.push_back(Want::Tree(root));
        }
    }

    let send = |w: Want| -> Result<()> {
        let frame = match w {
            Want::Tree(h) => Frame::get_tree(h.to_vec()),
            Want::Object(h) => Frame::get_object(h.to_vec()),
        };
        req_tx
            .send(WriterMsg::Send(Box::new(frame)))
            .map_err(|_| NetError::Protocol("replication writer thread ended early"))
    };

    loop {
        // Keep the pipe full: dispatch from the frontier up to the window.
        while outstanding.len() < PIPELINE_WINDOW {
            match frontier.pop_front() {
                Some(w) => {
                    send(w)?;
                    outstanding.push_back(w);
                }
                None => break,
            }
        }
        let Some(want) = outstanding.pop_front() else {
            break; // frontier + in-flight both empty: backfill complete
        };
        let resp = reader.recv_frame()?;
        match (want, resp.kind) {
            (Want::Tree(hash), Some(frame::Kind::TreeData(t))) => {
                if !t.found {
                    return Err(NetError::Protocol("source is missing a requested tree"));
                }
                if to_hash32(&t.hash)? != hash {
                    return Err(NetError::Protocol("tree_data hash does not match request"));
                }
                // Discover the tree's not-yet-present children. Each distinct
                // missing child is one dependency: schedule it (dedup against what
                // we've already requested + what the mirror holds), record a
                // reverse edge, and count it. Children go to the *front* so we
                // finish this subtree before opening unrelated roots (depth-first
                // keeps the open buffer bounded).
                let mut pending = 0usize;
                let mut dep_seen: HashSet<[u8; 32]> = HashSet::new();
                for entry in &t.entries {
                    let target = to_hash32(&entry.target)?;
                    let (present, child) = match entry.kind.as_str() {
                        "tree" => (sink.has_tree(&target), Want::Tree(target)),
                        "blob" => (sink.has_object(&target), Want::Object(target)),
                        _ => return Err(NetError::Protocol("tree entry has unknown kind")),
                    };
                    // A child already in the mirror, or one this tree lists twice
                    // (same content address), is not an extra dependency.
                    if present || !dep_seen.insert(target) {
                        continue;
                    }
                    pending += 1;
                    waiters.entry(target).or_default().push(hash);
                    if seen.insert(target) {
                        frontier.push_front(child);
                    }
                }
                if pending == 0 {
                    // Subtree already complete: store now and satisfy any parents.
                    sink.store_tree(&t)?;
                    summary.trees += 1;
                    cascade(sink, &mut open, &mut waiters, hash, &mut summary)?;
                } else {
                    open.insert(hash, OpenTree { data: t, pending });
                    #[cfg(test)]
                    {
                        peak_open = peak_open.max(open.len());
                    }
                }
            }
            (Want::Object(hash), Some(frame::Kind::ObjectData(o))) => {
                if !o.found {
                    return Err(NetError::Protocol("source is missing a requested object"));
                }
                if to_hash32(&o.hash)? != hash {
                    return Err(NetError::Protocol("object_data hash does not match request"));
                }
                sink.store_object(&hash, &o.payload)?;
                summary.objects += 1;
                // The blob is present now: any tree that was waiting on it may be
                // ready to store.
                cascade(sink, &mut open, &mut waiters, hash, &mut summary)?;
            }
            _ => {
                return Err(NetError::Protocol(
                    "replication response did not match the outstanding request",
                ))
            }
        }
    }

    // Incremental storage means every fetched tree is stored the moment its
    // subtree completes, so nothing may remain open once the pipe drains. A
    // leftover means the source served a tree whose child it never delivered.
    if !open.is_empty() {
        return Err(NetError::Protocol(
            "backfill drained with trees still unstored (inconsistent subtree from source)",
        ));
    }

    // Commits apply oldest -> newest; the tip advances last — the exact order
    // `pull_replication` applies.
    for c in missing.iter().rev() {
        sink.store_commit(c)?;
        summary.commits += 1;
    }
    sink.advance_tip(&announced_tip, height)?;
    summary.new_tip = Some(announced_tip);
    #[cfg(test)]
    PEAK_OPEN_TREES.with(|c| c.set(peak_open));
    Ok(summary)
}

/// A child (tree or object) just became present in the mirror: decrement every
/// open tree waiting on it, store any tree whose last child is now present, and
/// repeat for that newly-stored tree's own parents — a cascade run to a fixpoint
/// over an explicit worklist (the content-addressed tree DAG is acyclic, so it
/// terminates). Stores subtree-before-parent, preserving the invariant that a
/// stored tree implies its whole subtree is present.
fn cascade(
    sink: &mut dyn ReplicaSink,
    open: &mut std::collections::HashMap<[u8; 32], OpenTree>,
    waiters: &mut std::collections::HashMap<[u8; 32], Vec<[u8; 32]>>,
    first: [u8; 32],
    summary: &mut PullSummary,
) -> Result<()> {
    let mut present: Vec<[u8; 32]> = vec![first];
    while let Some(done) = present.pop() {
        let Some(parents) = waiters.remove(&done) else {
            continue;
        };
        for p in parents {
            let ready = {
                let ot = open.get_mut(&p).ok_or(NetError::Protocol(
                    "replication refcount references an unknown open tree",
                ))?;
                ot.pending -= 1;
                ot.pending == 0
            };
            if ready {
                let entry = open
                    .remove(&p)
                    .expect("a ready tree is still in the open set");
                sink.store_tree(&entry.data)?;
                summary.trees += 1;
                present.push(p); // now present for its own parents
            }
        }
    }
    Ok(())
}

/// The request-writer half of the full-duplex path: serialize request sends off
/// the main thread, then emit the terminal `ReplicaDone` on [`WriterMsg::Finish`].
fn run_request_writer<W: Write>(
    mut writer: NoiseWriter<W>,
    rx: std::sync::mpsc::Receiver<WriterMsg>,
) -> Result<()> {
    while let Ok(msg) = rx.recv() {
        match msg {
            WriterMsg::Send(frame) => writer.send_frame(&frame)?,
            WriterMsg::Finish => {
                writer.send_frame(&Frame::replica_done())?;
                return Ok(());
            }
        }
    }
    // The sender was dropped without Finish (the main thread aborted on an
    // error). Nothing more to send; the closing socket lets the source see EOF.
    Ok(())
}

/// Serve as the **source** (owner): answer the sink's requests until it sends
/// `ReplicaDone` or closes the session.
pub fn serve_replication<S: Read + Write>(
    session: &mut NoiseSession<S>,
    src: &dyn ReplicaSource,
) -> Result<ServeSummary> {
    let mut summary = ServeSummary::default();
    loop {
        let frame = match session.recv_frame() {
            Ok(f) => f,
            Err(NetError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(summary); // peer closed cleanly
            }
            Err(e) => return Err(e),
        };
        match frame.kind {
            Some(frame::Kind::GetTip(_)) => {
                session.send_frame(&Frame::tip_announce(src.tip_announce()))?;
            }
            Some(frame::Kind::GetCommit(g)) => {
                let h = to_hash32(&g.hash)?;
                session.send_frame(&Frame::commit_data(src.get_commit(&h)))?;
                summary.commits_served += 1;
            }
            Some(frame::Kind::GetTree(g)) => {
                let h = to_hash32(&g.hash)?;
                session.send_frame(&Frame::tree_data(src.get_tree(&h)))?;
                summary.trees_served += 1;
            }
            Some(frame::Kind::GetObject(g)) => {
                let h = to_hash32(&g.hash)?;
                session.send_frame(&Frame::object_data(src.get_object(&h)))?;
                summary.objects_served += 1;
            }
            Some(frame::Kind::ReplicaDone(_)) => return Ok(summary),
            _ => {
                return Err(NetError::Protocol(
                    "unexpected frame during replication serve",
                ))
            }
        }
    }
}

// --- wire helpers -----------------------------------------------------------

fn to_hash32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| NetError::Protocol("hash field is not 32 bytes"))
}

fn parent_of(c: &CommitData) -> Result<Option<[u8; 32]>> {
    if c.parent.is_empty() {
        Ok(None)
    } else {
        Ok(Some(to_hash32(&c.parent)?))
    }
}

fn expect_tip_announce(frame: Frame) -> Result<TipAnnounce> {
    match frame.kind {
        Some(frame::Kind::TipAnnounce(a)) => Ok(a),
        _ => Err(NetError::Protocol("expected tip_announce")),
    }
}

fn request_commit<S: Read + Write>(
    session: &mut NoiseSession<S>,
    hash: &[u8; 32],
) -> Result<CommitData> {
    session.send_frame(&Frame::get_commit(hash.to_vec()))?;
    let c = match session.recv_frame()?.kind {
        Some(frame::Kind::CommitData(c)) => c,
        _ => return Err(NetError::Protocol("expected commit_data")),
    };
    if !c.found {
        return Err(NetError::Protocol("source is missing a requested commit"));
    }
    if to_hash32(&c.hash)? != *hash {
        return Err(NetError::Protocol("commit_data hash does not match request"));
    }
    Ok(c)
}

fn request_tree<S: Read + Write>(
    session: &mut NoiseSession<S>,
    hash: &[u8; 32],
) -> Result<TreeData> {
    session.send_frame(&Frame::get_tree(hash.to_vec()))?;
    let t = match session.recv_frame()?.kind {
        Some(frame::Kind::TreeData(t)) => t,
        _ => return Err(NetError::Protocol("expected tree_data")),
    };
    if !t.found {
        return Err(NetError::Protocol("source is missing a requested tree"));
    }
    if to_hash32(&t.hash)? != *hash {
        return Err(NetError::Protocol("tree_data hash does not match request"));
    }
    Ok(t)
}

fn request_object<S: Read + Write>(
    session: &mut NoiseSession<S>,
    hash: &[u8; 32],
) -> Result<Vec<u8>> {
    session.send_frame(&Frame::get_object(hash.to_vec()))?;
    let o = match session.recv_frame()?.kind {
        Some(frame::Kind::ObjectData(o)) => o,
        _ => return Err(NetError::Protocol("expected object_data")),
    };
    if !o.found {
        return Err(NetError::Protocol("source is missing a requested object"));
    }
    if to_hash32(&o.hash)? != *hash {
        return Err(NetError::Protocol("object_data hash does not match request"));
    }
    Ok(o.payload)
}

#[cfg(test)]
mod tests {
    //! Protocol + fast-forward/fork logic over an in-process session pair, with
    //! mock source/sink. Real crypto verification + on-disk mirroring is covered
    //! end-to-end against a live `Repo` in keeperd's `tests/m5b_replica.rs`.

    use super::*;
    use crate::proto::{CommitData, ObjectData, TipAnnounce, TreeData, TreeEntryMsg};
    use crate::transport::{xx_initiator, xx_responder};
    use crate::HelloPayload;
    use std::collections::HashMap;
    use std::os::unix::net::UnixStream;
    use std::thread;

    // BLAKE3 of bytes -> [u8;32], to mint self-consistent content addresses.
    fn h(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn canonical_tree_bytes(entries: &[TreeEntryMsg]) -> Vec<u8> {
        // Mirror softfig-vcs's JCS tree encoding closely enough that the mock
        // source + sink agree on tree addresses. (The real encoding is tested
        // in keeperd; here both ends use this same function, so it is internally
        // consistent.)
        let mut v = Vec::new();
        for e in entries {
            v.extend_from_slice(e.name.as_bytes());
            v.push(0);
            v.extend_from_slice(e.kind.as_bytes());
            v.push(0);
            v.extend_from_slice(&e.mode.to_be_bytes());
            v.extend_from_slice(&e.target);
            v.push(0xff);
        }
        v
    }

    /// An in-memory owner chain the mock source serves and the mock sink mirrors.
    #[derive(Clone, Default)]
    struct Chain {
        commits: HashMap<[u8; 32], CommitData>,
        trees: HashMap<[u8; 32], TreeData>,
        objects: HashMap<[u8; 32], Vec<u8>>,
        tip: Option<[u8; 32]>,
        height: u64,
    }

    impl Chain {
        /// Insert a tree (keyed by its canonical address) and return that hash.
        fn add_tree(&mut self, entries: Vec<TreeEntryMsg>) -> [u8; 32] {
            let hash = h(&canonical_tree_bytes(&entries));
            self.trees.insert(
                hash,
                TreeData {
                    found: true,
                    hash: hash.to_vec(),
                    entries,
                },
            );
            hash
        }

        /// Seal a commit over `root_tree`, chaining off the current tip. `tag`
        /// disambiguates the commit hash; the signature is a stub.
        fn seal_commit(&mut self, root_tree: [u8; 32], tag: &[u8]) -> [u8; 32] {
            let parent = self.tip;
            let mut pre = Vec::new();
            if let Some(p) = parent {
                pre.extend_from_slice(&p);
            }
            pre.extend_from_slice(&root_tree);
            pre.extend_from_slice(tag);
            let ch = h(&pre);
            self.commits.insert(
                ch,
                CommitData {
                    found: true,
                    hash: ch.to_vec(),
                    parent: parent.map(|p| p.to_vec()).unwrap_or_default(),
                    root_tree: root_tree.to_vec(),
                    author_device: "owner".into(),
                    author_pubkey: vec![0u8; 32],
                    timestamp: 0,
                    intent: "init".into(),
                    payload: "{}".into(),
                    master_key_id: 0,
                    signature: vec![0u8; 64],
                },
            );
            self.tip = Some(ch);
            self.height += 1;
            ch
        }

        /// A blob entry named `name` whose content is `body`, registering the
        /// object.
        fn blob_entry(&mut self, name: &str, body: Vec<u8>) -> TreeEntryMsg {
            let blob = h(&body);
            self.objects.insert(blob, body);
            TreeEntryMsg {
                name: name.into(),
                kind: "blob".into(),
                mode: 0o100644,
                target: blob.to_vec(),
            }
        }

        /// Append a commit with a single blob whose content is `body`. Returns
        /// the new commit hash.
        fn commit(&mut self, body: &[u8]) -> [u8; 32] {
            let entry = self.blob_entry("file", body.to_vec());
            let troot = self.add_tree(vec![entry]);
            self.seal_commit(troot, body)
        }

        /// Append a commit whose root tree fans out to `width` blobs plus a
        /// nested subtree of another `width` blobs — enough to exceed the
        /// pipeline window and to exercise post-order subtree storage.
        fn commit_wide(&mut self, tag: &str, width: usize) -> [u8; 32] {
            let sub_entries: Vec<TreeEntryMsg> = (0..width)
                .map(|i| self.blob_entry(&format!("s{i}"), format!("{tag}-sub-{i}").into_bytes()))
                .collect();
            let sub_hash = self.add_tree(sub_entries);

            let mut entries: Vec<TreeEntryMsg> = (0..width)
                .map(|i| self.blob_entry(&format!("f{i}"), format!("{tag}-root-{i}").into_bytes()))
                .collect();
            entries.push(TreeEntryMsg {
                name: "dir".into(),
                kind: "tree".into(),
                mode: 0o40000,
                target: sub_hash.to_vec(),
            });
            let troot = self.add_tree(entries);
            self.seal_commit(troot, tag.as_bytes())
        }
    }

    struct MockSource {
        chain: Chain,
    }

    impl ReplicaSource for MockSource {
        fn tip_announce(&self) -> TipAnnounce {
            TipAnnounce {
                chain_id: b"chain".to_vec(),
                tip_hash: self.chain.tip.map(|t| t.to_vec()).unwrap_or_default(),
                height: self.chain.height,
                signature: vec![0u8; 64], // stub; the sink stubs verification
            }
        }
        fn get_commit(&self, hash: &[u8; 32]) -> CommitData {
            self.chain.commits.get(hash).cloned().unwrap_or(CommitData {
                found: false,
                ..Default::default()
            })
        }
        fn get_tree(&self, hash: &[u8; 32]) -> TreeData {
            self.chain.trees.get(hash).cloned().unwrap_or(TreeData {
                found: false,
                ..Default::default()
            })
        }
        fn get_object(&self, hash: &[u8; 32]) -> ObjectData {
            match self.chain.objects.get(hash) {
                Some(bytes) => ObjectData {
                    found: true,
                    hash: hash.to_vec(),
                    payload: bytes.clone(),
                },
                None => ObjectData {
                    found: false,
                    ..Default::default()
                },
            }
        }
    }

    #[derive(Default)]
    struct MockSink {
        commits: HashMap<[u8; 32], CommitData>,
        trees: HashMap<[u8; 32], TreeData>,
        objects: HashMap<[u8; 32], Vec<u8>>,
        tip: Option<[u8; 32]>,
        announce_ok: bool,
    }

    impl ReplicaSink for MockSink {
        fn verify_announce(&self, _ann: &TipAnnounce) -> bool {
            self.announce_ok
        }
        fn stored_tip(&self) -> Option<[u8; 32]> {
            self.tip
        }
        fn has_commit(&self, hash: &[u8; 32]) -> bool {
            self.commits.contains_key(hash)
        }
        fn verify_commit(&self, c: &CommitData) -> Result<()> {
            // Stub: just re-check the content address of the body we hold.
            if c.hash.len() != 32 {
                return Err(NetError::Protocol("bad commit hash length"));
            }
            Ok(())
        }
        fn store_commit(&mut self, c: &CommitData) -> Result<()> {
            self.commits.insert(to_hash32(&c.hash)?, c.clone());
            Ok(())
        }
        fn has_tree(&self, hash: &[u8; 32]) -> bool {
            self.trees.contains_key(hash)
        }
        fn store_tree(&mut self, t: &TreeData) -> Result<()> {
            let want = h(&canonical_tree_bytes(&t.entries));
            if to_hash32(&t.hash)? != want {
                return Err(NetError::Protocol("tree hash mismatch"));
            }
            self.trees.insert(want, t.clone());
            Ok(())
        }
        fn has_object(&self, hash: &[u8; 32]) -> bool {
            self.objects.contains_key(hash)
        }
        fn store_object(&mut self, hash: &[u8; 32], bytes: &[u8]) -> Result<()> {
            if h(bytes) != *hash {
                return Err(NetError::Protocol("object content-address mismatch"));
            }
            self.objects.insert(*hash, bytes.to_vec());
            Ok(())
        }
        fn advance_tip(&mut self, hash: &[u8; 32], _height: u64) -> Result<()> {
            self.tip = Some(*hash);
            Ok(())
        }
    }

    fn hello(name: &str) -> HelloPayload {
        HelloPayload::new(name.as_bytes().to_vec(), name)
    }

    /// Run a source/sink pair over an in-process socket, returning the pull
    /// result and the resulting sink.
    fn run(chain: Chain, mut sink: MockSink) -> (Result<PullSummary>, MockSink) {
        let (a, b) = UnixStream::pair().unwrap();
        let src = MockSource { chain };
        let server = thread::spawn(move || {
            let mut s = xx_responder(b, &[2u8; 32], &hello("owner")).unwrap();
            let _ = serve_replication(&mut s, &src);
        });
        let mut client = xx_initiator(a, &[1u8; 32], &hello("host")).unwrap();
        let result = pull_replication(&mut client, &mut sink);
        // Close the client so the server's serve loop sees EOF and returns even
        // when the pull aborted mid-exchange (fork/verify failure) without a
        // ReplicaDone — otherwise the unbuffered socketpair would deadlock join.
        drop(client);
        server.join().unwrap();
        (result, sink)
    }

    #[test]
    fn full_backfill_into_empty_mirror() {
        let mut chain = Chain::default();
        chain.commit(b"alpha");
        chain.commit(b"beta");
        let tip = chain.commit(b"gamma");

        let sink = MockSink {
            announce_ok: true,
            ..Default::default()
        };
        let (res, sink) = run(chain.clone(), sink);
        let summary = res.unwrap();
        assert_eq!(summary.commits, 3);
        assert_eq!(summary.new_tip, Some(tip));
        assert_eq!(sink.stored_tip(), Some(tip));
        assert_eq!(sink.commits.len(), 3);
        // Each commit introduced one new blob.
        assert_eq!(sink.objects.len(), 3);
    }

    #[test]
    fn fast_forward_only_fetches_the_new_commits() {
        let mut chain = Chain::default();
        chain.commit(b"alpha");
        let tip1 = chain.tip.unwrap();

        // Mirror already at tip1 with that commit/tree/object present.
        let mut sink = MockSink {
            announce_ok: true,
            tip: Some(tip1),
            ..Default::default()
        };
        let c1 = chain.commits.get(&tip1).unwrap().clone();
        sink.commits.insert(tip1, c1.clone());
        let troot = to_hash32(&c1.root_tree).unwrap();
        sink.trees
            .insert(troot, chain.trees.get(&troot).unwrap().clone());
        for (k, v) in &chain.objects {
            sink.objects.insert(*k, v.clone());
        }

        // Owner advances by two commits.
        chain.commit(b"beta");
        let tip3 = chain.commit(b"gamma");

        let (res, sink) = run(chain, sink);
        let summary = res.unwrap();
        assert_eq!(summary.commits, 2, "only the two new commits are fetched");
        assert_eq!(sink.stored_tip(), Some(tip3));
    }

    #[test]
    fn already_up_to_date_is_a_noop() {
        let mut chain = Chain::default();
        chain.commit(b"alpha");
        let tip = chain.tip.unwrap();
        let mut sink = MockSink {
            announce_ok: true,
            tip: Some(tip),
            ..Default::default()
        };
        sink.commits
            .insert(tip, chain.commits.get(&tip).unwrap().clone());

        let (res, sink) = run(chain, sink);
        let summary = res.unwrap();
        assert!(summary.up_to_date);
        assert_eq!(summary.commits, 0);
        assert_eq!(sink.stored_tip(), Some(tip));
    }

    #[test]
    fn divergent_chain_is_rejected_as_a_fork() {
        // Mirror is on chain A (tipA). The source serves an unrelated chain B
        // (different genesis), so walking back from tipB reaches genesis without
        // meeting tipA — a fork. The mirror must be left untouched.
        let mut chain_a = Chain::default();
        chain_a.commit(b"alpha");
        let tip_a = chain_a.tip.unwrap();

        let mut sink = MockSink {
            announce_ok: true,
            tip: Some(tip_a),
            ..Default::default()
        };
        sink.commits
            .insert(tip_a, chain_a.commits.get(&tip_a).unwrap().clone());

        let mut chain_b = Chain::default();
        chain_b.commit(b"bravo"); // different content -> different genesis hash
        chain_b.commit(b"charlie");

        let (res, sink) = run(chain_b, sink);
        assert!(
            matches!(res, Err(NetError::Protocol(_))),
            "a forked chain must be rejected"
        );
        assert_eq!(sink.stored_tip(), Some(tip_a), "mirror tip unchanged");
    }

    #[test]
    fn unverifiable_announce_aborts_before_any_change() {
        let mut chain = Chain::default();
        chain.commit(b"alpha");
        let sink = MockSink {
            announce_ok: false, // signature check fails
            ..Default::default()
        };
        let (res, sink) = run(chain, sink);
        assert!(matches!(res, Err(NetError::Protocol(_))));
        assert!(sink.stored_tip().is_none());
        assert!(sink.commits.is_empty());
    }

    #[test]
    fn tipannounce_signing_bytes_bind_each_field() {
        let base = tipannounce_signing_bytes(b"chain", &[1u8; 32], 7);
        // Distinct height -> distinct bytes.
        assert_ne!(base, tipannounce_signing_bytes(b"chain", &[1u8; 32], 8));
        // Length-prefixing prevents a chain_id/tip_hash boundary shift collision.
        assert_ne!(
            tipannounce_signing_bytes(b"ab", b"c", 0),
            tipannounce_signing_bytes(b"a", b"bc", 0)
        );
    }

    #[test]
    fn grant_signing_bytes_bind_each_field() {
        let base = grant_signing_bytes(&[9u8; 32], b"chain", 100);
        assert_ne!(base, grant_signing_bytes(&[9u8; 32], b"chain", 101));
        assert_ne!(
            grant_signing_bytes(b"ab", b"c", 0),
            grant_signing_bytes(b"a", b"bc", 0)
        );
        // Distinct domain from the tip announce.
        assert_ne!(
            grant_signing_bytes(b"x", b"y", 0),
            tipannounce_signing_bytes(b"x", b"y", 0)
        );
    }

    // --- Full-duplex pipelined driver ------------------------------------

    /// Same as [`run`] but drives the full-duplex pipelined sink over the split
    /// session. Both drivers must produce identical results over the same
    /// chain + mirror.
    fn run_pipelined(chain: Chain, mut sink: MockSink) -> (Result<PullSummary>, MockSink) {
        let (a, b) = UnixStream::pair().unwrap();
        let src = MockSource { chain };
        let server = thread::spawn(move || {
            let mut s = xx_responder(b, &[2u8; 32], &hello("owner")).unwrap();
            let _ = serve_replication(&mut s, &src);
        });
        let client = xx_initiator(a, &[1u8; 32], &hello("host")).unwrap();
        // `pull_replication_pipelined` consumes the session; its split halves
        // drop here, closing the socket so the server's serve loop sees EOF and
        // returns even when the pull aborted mid-exchange without a ReplicaDone.
        let result = pull_replication_pipelined(client, &mut sink);
        server.join().unwrap();
        (result, sink)
    }

    #[test]
    fn pipelined_full_backfill_matches_the_sequential_driver() {
        let mut chain = Chain::default();
        chain.commit(b"alpha");
        chain.commit(b"beta");
        let tip = chain.commit(b"gamma");

        let (seq_res, seq_sink) = run(
            chain.clone(),
            MockSink {
                announce_ok: true,
                ..Default::default()
            },
        );
        let (pipe_res, pipe_sink) = run_pipelined(
            chain.clone(),
            MockSink {
                announce_ok: true,
                ..Default::default()
            },
        );

        let seq_sum = seq_res.unwrap();
        let pipe_sum = pipe_res.unwrap();
        // Identical PullSummary and identical mirror state, byte for byte.
        assert_eq!(seq_sum, pipe_sum);
        assert_eq!(pipe_sum.new_tip, Some(tip));
        assert_eq!(seq_sink.commits, pipe_sink.commits);
        assert_eq!(seq_sink.trees, pipe_sink.trees);
        assert_eq!(seq_sink.objects, pipe_sink.objects);
        assert_eq!(pipe_sink.stored_tip(), Some(tip));
    }

    #[test]
    fn pipelined_many_object_backfill_exercises_the_window() {
        // A commit whose tree fans out well past PIPELINE_WINDOW, plus a nested
        // subtree, so the pipeline keeps a full in-flight window and still
        // stores subtrees post-order before the tree that references them.
        let width = PIPELINE_WINDOW * 2 + 5;
        let mut chain = Chain::default();
        chain.commit(b"genesis");
        let tip = chain.commit_wide("wide", width);

        let (res, sink) = run_pipelined(
            chain.clone(),
            MockSink {
                announce_ok: true,
                ..Default::default()
            },
        );
        let summary = res.unwrap();

        assert_eq!(summary.new_tip, Some(tip));
        assert_eq!(sink.stored_tip(), Some(tip));
        assert_eq!(summary.commits, 2);
        // Every distinct object + tree the owner holds is mirrored, and the
        // summary counts equal what was actually stored (full dedup).
        assert_eq!(sink.objects, chain.objects);
        assert_eq!(sink.trees, chain.trees);
        assert_eq!(summary.objects as usize, chain.objects.len());
        assert_eq!(summary.trees as usize, chain.trees.len());
    }

    #[test]
    fn pipelined_tree_buffer_stays_bounded() {
        // A long, shallow history: many commits, each a distinct single-file tree.
        // The old driver buffered *every* fetched tree until the end (peak = one
        // per commit); the incremental driver stores each tree as soon as its blob
        // lands, so the open-tree buffer stays ~window-bounded no matter how long
        // the history is.
        let n = PIPELINE_WINDOW * 4;
        let mut chain = Chain::default();
        for i in 0..n {
            chain.commit(format!("commit-{i}").as_bytes());
        }
        let tip = chain.tip.unwrap();
        let total_trees = chain.trees.len();
        assert!(
            total_trees >= 4 * PIPELINE_WINDOW,
            "the test needs many more trees ({total_trees}) than the window to be meaningful"
        );

        PEAK_OPEN_TREES.with(|c| c.set(0));
        let (res, sink) = run_pipelined(
            chain.clone(),
            MockSink {
                announce_ok: true,
                ..Default::default()
            },
        );
        let summary = res.unwrap();
        let peak = PEAK_OPEN_TREES.with(|c| c.get());

        // Correct + byte-identical mirror, and the summary counts every unique
        // (the sequential-equivalence invariant, on a many-tree chain).
        assert_eq!(summary.new_tip, Some(tip));
        assert_eq!(sink.stored_tip(), Some(tip));
        assert_eq!(summary.commits as usize, n);
        assert_eq!(sink.trees, chain.trees);
        assert_eq!(sink.objects, chain.objects);
        assert_eq!(summary.trees as usize, total_trees);
        assert_eq!(summary.objects as usize, chain.objects.len());

        // The headline: peak tree buffer is bounded by the in-flight window, NOT
        // by the O(history) total-tree count.
        assert!(
            peak <= PIPELINE_WINDOW,
            "open-tree buffer peaked at {peak}, must stay within the {PIPELINE_WINDOW}-request window"
        );
        assert!(
            peak < total_trees,
            "buffer ({peak}) must stay bounded well below the total tree count ({total_trees})"
        );
    }

    #[test]
    fn pipelined_fast_forward_only_fetches_new_commits() {
        let mut chain = Chain::default();
        chain.commit(b"alpha");
        let tip1 = chain.tip.unwrap();

        let mut sink = MockSink {
            announce_ok: true,
            tip: Some(tip1),
            ..Default::default()
        };
        let c1 = chain.commits.get(&tip1).unwrap().clone();
        sink.commits.insert(tip1, c1.clone());
        let troot = to_hash32(&c1.root_tree).unwrap();
        sink.trees
            .insert(troot, chain.trees.get(&troot).unwrap().clone());
        for (k, v) in &chain.objects {
            sink.objects.insert(*k, v.clone());
        }

        chain.commit(b"beta");
        let tip3 = chain.commit(b"gamma");

        let (res, sink) = run_pipelined(chain, sink);
        let summary = res.unwrap();
        assert_eq!(summary.commits, 2, "only the two new commits are fetched");
        assert_eq!(sink.stored_tip(), Some(tip3));
    }

    #[test]
    fn pipelined_divergent_chain_is_rejected_as_a_fork() {
        // The fork is caught in negotiation (before the session is split), so
        // the mirror is left untouched — same as the sequential driver.
        let mut chain_a = Chain::default();
        chain_a.commit(b"alpha");
        let tip_a = chain_a.tip.unwrap();

        let mut sink = MockSink {
            announce_ok: true,
            tip: Some(tip_a),
            ..Default::default()
        };
        sink.commits
            .insert(tip_a, chain_a.commits.get(&tip_a).unwrap().clone());

        let mut chain_b = Chain::default();
        chain_b.commit(b"bravo");
        chain_b.commit(b"charlie");

        let (res, sink) = run_pipelined(chain_b, sink);
        assert!(
            matches!(res, Err(NetError::Protocol(_))),
            "a forked chain must be rejected"
        );
        assert_eq!(sink.stored_tip(), Some(tip_a), "mirror tip unchanged");
    }

    /// Run a [`pull_subtree`] against a [`serve_replication`] source over an
    /// in-process socket, returning the result and the resulting sink.
    fn run_subtree(
        chain: Chain,
        mut sink: MockSink,
        root: [u8; 32],
    ) -> (Result<SubtreeSummary>, MockSink) {
        let (a, b) = UnixStream::pair().unwrap();
        let src = MockSource { chain };
        let server = thread::spawn(move || {
            let mut s = xx_responder(b, &[2u8; 32], &hello("writer")).unwrap();
            let _ = serve_replication(&mut s, &src);
        });
        let mut client = xx_initiator(a, &[1u8; 32], &hello("receiver")).unwrap();
        let result = pull_subtree(&mut client, &mut sink, &root);
        drop(client);
        server.join().unwrap();
        (result, sink)
    }

    #[test]
    fn pull_subtree_fetches_a_tree_closure_without_the_commit_graph() {
        // A peer commits a shared-subtree edit whose root tree fans out to blobs
        // plus a nested subtree. The receiver pulls exactly that tree closure
        // into an empty store — every tree + object — and NOT the commit row:
        // shared-pull re-authors locally, it never adopts the peer's commit.
        let mut chain = Chain::default();
        let commit = chain.commit_wide("edit", 3);
        let root = to_hash32(&chain.commits.get(&commit).unwrap().root_tree).unwrap();
        let want_objects = chain.objects.len(); // 3 root blobs + 3 sub blobs

        let (res, sink) = run_subtree(chain.clone(), MockSink::default(), root);
        let summary = res.unwrap();
        assert!(!summary.up_to_date);
        assert_eq!(summary.trees, 2, "root tree + nested subtree");
        assert_eq!(summary.objects, want_objects as u64);
        assert!(sink.has_tree(&root), "the named tree landed");
        assert_eq!(sink.objects.len(), want_objects);
        assert!(
            sink.commits.is_empty(),
            "no commit row transferred — shared-pull re-authors locally"
        );
        assert_eq!(sink.stored_tip(), None, "pull_subtree never advances a tip");

        // Idempotent: re-pulling into the now-complete store fetches nothing and
        // reports up_to_date (the `has_tree` short-circuit stays sound).
        let (res2, sink2) = run_subtree(chain, sink, root);
        let s2 = res2.unwrap();
        assert!(s2.up_to_date);
        assert_eq!(s2.trees, 0);
        assert_eq!(s2.objects, 0);
        assert_eq!(sink2.objects.len(), want_objects, "store unchanged");
    }
}
