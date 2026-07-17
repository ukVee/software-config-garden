//! M5b replication: the keeperd-side glue between `softfig-net`'s wire drive
//! loops and the local VCS store + vault.
//!
//! `softfig-net` owns the protocol + the fast-forward policy over two traits;
//! this module implements them with real crypto + storage:
//!
//! * [`RepoSource`] — [`ReplicaSource`] over the owner's own VCS store (a
//!   read-only `Repo` handle) plus a vault-signed [`TipAnnounce`].
//! * [`MirrorStore`] — [`ReplicaSink`] over a **separate** per-peer ciphertext
//!   mirror (`<replica_root>/<owner-id>/.softfig/`, reusing `softfig-store`'s
//!   `Db` + `ObjectStore`). It verifies every commit (signature + hash + that
//!   `author_pubkey` is the chain owner's ring identity), every tree
//!   (`BLAKE3(canonical_tree_bytes)`), and every object (content address), and
//!   **never decrypts** — it holds no key for the chain.
//!
//! Plus the two-sided-consent helpers:
//!
//! * [`GrantLedger`] — the owner's runtime `push_to` allow-list (`replica.toml`,
//!   network state beside `peers.toml`), edited by `replica_grant` / `_revoke`.
//! * [`mint_grant`] / [`verify_grant`] — the signed
//!   [`ReplicaGrant`](softfig_net::ReplicaGrant) the owner presents and the host
//!   checks (grantee == me, signed by the chain owner), realizing the owner's
//!   half of consent on the wire (the host's half is `keeper.toml [replica]
//!   host`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use softfig_net::error::{NetError, Result as NetResult};
use softfig_net::proto::{CommitData, ObjectData, ReplicaGrant, TipAnnounce, TreeData, TreeEntryMsg};
use softfig_net::{
    grant_signing_bytes, tipannounce_signing_bytes, verify_tipannounce, ReplicaSink, ReplicaSource,
};
use softfig_store::{
    put_commit, put_tree, set_ref, CommitRow, Db, Hash, ObjectStore, StorePaths, TreeEntryKind,
    TreeEntryRow,
};
use softfig_vcs::{
    canonical_tree_bytes, log_collect, reachable_from, reachable_from_tree, verify_commit,
    CanonicalCommit, Reachable, Repo, TIP_REF,
};
use softfig_vault::VaultSession;

/// Filename of the owner-side replication grant ledger within `.softfig/`.
pub const REPLICA_FILE: &str = "replica.toml";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn neterr<E: std::fmt::Display>(e: E) -> NetError {
    NetError::Replica(e.to_string())
}

fn h32(bytes: &[u8]) -> NetResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| NetError::Protocol("hash field is not 32 bytes"))
}

// --- Owner-side grant ledger (replica.toml) ---------------------------------

/// Path to the grant ledger: `<state_dir>/.softfig/replica.toml`.
pub fn replica_ledger_path(state_dir: &Path) -> PathBuf {
    state_dir.join(".softfig").join(REPLICA_FILE)
}

/// The owner's per-peer replication grants — which hosts this device pushes its
/// chain to. Runtime-mutable network state (beside `peers.toml`), edited by the
/// `replica_grant` / `replica_revoke` IPC verbs, not by hand-editing
/// `keeper.toml`. Fingerprints are lowercase hex device-ids.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrantLedger {
    #[serde(default)]
    pub push_to: Vec<String>,
}

impl GrantLedger {
    /// Load the ledger (absent file = empty).
    pub fn load(state_dir: &Path) -> io::Result<Self> {
        let path = replica_ledger_path(state_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)?;
        toml::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Atomically write the ledger (temp + rename), creating `.softfig/`.
    pub fn save(&self, state_dir: &Path) -> io::Result<()> {
        let dir = state_dir.join(".softfig");
        fs::create_dir_all(&dir)?;
        let path = dir.join(REPLICA_FILE);
        let raw = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        fs::write(&tmp, raw)?;
        fs::rename(&tmp, &path)
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.push_to.iter().any(|f| f == fingerprint)
    }

    /// Add `fingerprint`; returns false if already present (idempotent).
    pub fn grant(&mut self, fingerprint: &str) -> bool {
        if self.contains(fingerprint) {
            return false;
        }
        self.push_to.push(fingerprint.to_string());
        true
    }

    /// Remove `fingerprint`; returns whether it was present.
    pub fn revoke(&mut self, fingerprint: &str) -> bool {
        let before = self.push_to.len();
        self.push_to.retain(|f| f != fingerprint);
        self.push_to.len() != before
    }
}

// --- Signed grant (owner -> host, on the wire) ------------------------------

/// Mint a signed [`ReplicaGrant`] authorizing `grantee_device_id` to host this
/// device's chain (`chain_id`). The vault produces the signature; the secret
/// never leaves it. The owner mints this only for hosts in its `push_to`.
pub fn mint_grant(
    grantee_device_id: &[u8; 32],
    chain_id: &[u8],
    session: &VaultSession,
) -> ReplicaGrant {
    let issued_at = now_unix();
    let signature = session
        .sign(&grant_signing_bytes(grantee_device_id, chain_id, issued_at))
        .to_bytes()
        .to_vec();
    ReplicaGrant {
        grantee_device_id: grantee_device_id.to_vec(),
        chain_id: chain_id.to_vec(),
        issued_at,
        signature,
    }
}

// Grant *verification* (`softfig_net::verify_grant`) lives in `softfig-net`
// beside the signing-byte helpers + the ed25519 dep; keeperd only *mints* (via
// the vault) and *checks* via that re-export — see `net.rs`'s inbound handler.

// --- Owner-side source ------------------------------------------------------

/// Build the chain's signed [`TipAnnounce`] from an unlocked session. The
/// signature binds `chain_id ‖ tip ‖ height` (see
/// [`tipannounce_signing_bytes`]); the host verifies it against the owner's
/// identity key.
///
/// **Replica isolation invariant (m5c slice 004, user requirement #2):** this
/// announces `repo.tip()` = the **device chain** (`TIP_REF`) only — never
/// `db.list_refs()`. Because the sink's fast-forward walk can only reach the
/// object graph of the announced tip, a shared chain (a separate ref) is
/// **structurally excluded** from every per-peer backup mirror. Do not change
/// this to announce all refs: a shared chain replicates only to its own
/// `S`-audience (m5d/m5e), never folded into the device backup. Enforced by
/// construction here + regression-tested in `tests/m5b_replica.rs`
/// (`device_chain_replica_excludes_a_shared_chain`) and `softfig-vcs`'s
/// `tests/replica_isolation.rs`.
pub fn build_announce(repo: &Repo, session: &VaultSession) -> NetResult<TipAnnounce> {
    let chain_id = repo.repo_id().map_err(neterr)?.into_bytes();
    let (tip_hash, height) = match repo.tip().map_err(neterr)? {
        Some(tip) => {
            let height = log_collect(repo.db(), tip).map_err(neterr)?.len() as u64;
            (tip.as_bytes().to_vec(), height)
        }
        None => (Vec::new(), 0),
    };
    let signature = session
        .sign(&tipannounce_signing_bytes(&chain_id, &tip_hash, height))
        .to_bytes()
        .to_vec();
    Ok(TipAnnounce {
        chain_id,
        tip_hash,
        height,
        signature,
    })
}

/// [`ReplicaSource`] over a read-only handle to the owner's own VCS store. Open
/// a fresh `Repo` for the serve thread (sqlite WAL allows a concurrent reader
/// beside the daemon's writer) and a pre-signed announce snapshotted under the
/// daemon lock.
///
/// **Serve-side scoping (m5c slice 008, finding 6):** the source answers
/// `get_commit`/`get_tree`/`get_object` **only** for objects in the announced
/// tip's reachable closure — computed once at construction from
/// [`reachable_from`]. A chain replicates to exactly its audience *at the
/// source*: a granted backup host that learns some other chain's hash out of
/// band (e.g. a shared-subtree ciphertext hash) gets `found:false`, so a
/// legitimate device-chain session can't be turned into an unscoped hash oracle
/// over the whole `Db`/`ObjectStore`. m5d reuses this serve loop for
/// `S`-members, so the scoping is enforced here before it becomes load-bearing
/// for cross-audience isolation.
pub struct RepoSource {
    repo: Repo,
    announce: TipAnnounce,
    /// The reachable closure of the announced tip — the only objects served.
    served: Reachable,
}

impl std::fmt::Debug for RepoSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoSource")
            .field("height", &self.announce.height)
            .finish_non_exhaustive()
    }
}

impl RepoSource {
    /// Wrap `repo` + its pre-signed `announce`, scoping the served object set to
    /// the announced tip's reachable closure (finding 6). An empty announce (no
    /// commits yet) serves nothing. Fallible: computing the closure reads the
    /// store.
    pub fn new(repo: Repo, announce: TipAnnounce) -> NetResult<Self> {
        let served = if announce.tip_hash.is_empty() {
            Reachable::default()
        } else {
            let tip = Hash::from_bytes(h32(&announce.tip_hash)?);
            reachable_from(repo.db(), tip).map_err(neterr)?
        };
        Ok(Self {
            repo,
            announce,
            served,
        })
    }

    /// Wrap `repo` scoped to a single **subtree** closure — the serve source for
    /// an M5e shared-chain push (slice 002 part 2b-3). `serve_replication` here
    /// answers only `get_tree`/`get_object` for objects reachable from
    /// `root_tree` (the just-committed shared-chain tip's tree the receiver's
    /// [`pull_subtree`](softfig_net::pull_subtree) walks), so a member serving one
    /// chain's edit can't be turned into an unscoped hash oracle over the whole
    /// store — the same finding-6 scoping the device-chain serve gets, rooted at
    /// a tree. The announce is empty: `pull_subtree` never requests a tip or a
    /// commit, so `tip_announce`/`get_commit` are unreachable on this path.
    pub fn for_subtree(repo: Repo, root_tree: [u8; 32]) -> NetResult<Self> {
        let served = reachable_from_tree(repo.db(), Hash::from_bytes(root_tree)).map_err(neterr)?;
        Ok(Self {
            repo,
            announce: TipAnnounce::default(),
            served,
        })
    }
}

impl ReplicaSource for RepoSource {
    fn tip_announce(&self) -> TipAnnounce {
        self.announce.clone()
    }

    fn get_commit(&self, hash: &[u8; 32]) -> CommitData {
        // Off-closure hashes are refused as if absent — the source serves only
        // the announced tip's reachable set (finding 6), never the whole store.
        if !self.served.commits.contains(&Hash::from_bytes(*hash)) {
            return CommitData {
                found: false,
                ..Default::default()
            };
        }
        match self.repo.db().get_commit(&Hash::from_bytes(*hash)) {
            Ok(row) => commit_row_to_data(&row),
            Err(_) => CommitData {
                found: false,
                ..Default::default()
            },
        }
    }

    fn get_tree(&self, hash: &[u8; 32]) -> TreeData {
        if !self.served.trees.contains(&Hash::from_bytes(*hash)) {
            return TreeData {
                found: false,
                ..Default::default()
            };
        }
        match self.repo.db().get_tree(&Hash::from_bytes(*hash)) {
            Ok(entries) => TreeData {
                found: true,
                hash: hash.to_vec(),
                entries: entries.iter().map(entry_to_msg).collect(),
            },
            Err(_) => TreeData {
                found: false,
                ..Default::default()
            },
        }
    }

    fn get_object(&self, hash: &[u8; 32]) -> ObjectData {
        if !self.served.blobs.contains(&Hash::from_bytes(*hash)) {
            return ObjectData {
                found: false,
                ..Default::default()
            };
        }
        match self.repo.objects().get(&Hash::from_bytes(*hash)) {
            Ok(payload) => ObjectData {
                found: true,
                hash: hash.to_vec(),
                payload,
            },
            Err(_) => ObjectData {
                found: false,
                ..Default::default()
            },
        }
    }
}

// --- Host-side mirror sink --------------------------------------------------

/// Per-peer mirror dir: `<replica_root>/<owner-device-id-hex>/`. One subdir per
/// replicated chain, keyed by the owner's stable Ed25519 device id.
pub fn mirror_dir(replica_root: &Path, owner_device_id: &[u8; 32]) -> PathBuf {
    replica_root.join(hex::encode(owner_device_id))
}

/// A zero-knowledge ciphertext mirror of one peer's device chain. Reuses
/// `softfig-store`'s `Db` + `ObjectStore` at the per-peer mirror path — the same
/// schema as the owner's store, but a deliberately separate handle with **no
/// vault key**, so it stores byte-faithful ciphertext it cannot read.
pub struct MirrorStore {
    db: Db,
    objects: ObjectStore,
    /// The chain owner's Ed25519 identity. Every accepted commit must be authored
    /// by this key, and the tip announce must be signed by it.
    owner_pubkey: [u8; 32],
}

impl std::fmt::Debug for MirrorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorStore")
            .field("owner", &hex::encode(self.owner_pubkey))
            .finish_non_exhaustive()
    }
}

impl MirrorStore {
    /// Open the mirror for `owner_device_id`, creating it on first use. The
    /// `chain_id` and `owner_name` are recorded in the mirror's meta for the
    /// status surface; they are advisory (the owner-id keys the dir, and the
    /// per-commit author check binds content).
    pub fn open_or_create(
        replica_root: &Path,
        owner_device_id: &[u8; 32],
        owner_name: &str,
        chain_id: &[u8],
    ) -> NetResult<Self> {
        let dir = mirror_dir(replica_root, owner_device_id);
        let paths = StorePaths::with_state_root(&dir, &dir);
        let objects = ObjectStore::new(paths.clone());
        let db = if paths.exists() {
            Db::open(&paths).map_err(neterr)?
        } else {
            fs::create_dir_all(paths.softfig_dir()).map_err(neterr)?;
            objects.ensure_root().map_err(neterr)?;
            let repo_id = String::from_utf8(chain_id.to_vec())
                .unwrap_or_else(|_| hex::encode(chain_id));
            let mut db = Db::create(&paths, &repo_id, now_unix()).map_err(neterr)?;
            db.meta_put("mirror_owner_device_id", &hex::encode(owner_device_id))
                .map_err(neterr)?;
            db.meta_put("mirror_owner_name", owner_name).map_err(neterr)?;
            db
        };
        Ok(Self {
            db,
            objects,
            owner_pubkey: *owner_device_id,
        })
    }
}

impl ReplicaSink for MirrorStore {
    fn verify_announce(&self, ann: &TipAnnounce) -> bool {
        verify_tipannounce(&self.owner_pubkey, ann)
    }

    fn stored_tip(&self) -> Option<[u8; 32]> {
        self.db
            .try_get_ref(TIP_REF)
            .ok()
            .flatten()
            .map(|h| *h.as_bytes())
    }

    fn has_commit(&self, hash: &[u8; 32]) -> bool {
        self.db
            .commit_exists(&Hash::from_bytes(*hash))
            .unwrap_or(false)
    }

    fn verify_commit(&self, c: &CommitData) -> NetResult<()> {
        // Bind the commit to the chain owner: a valid signature under *some* key
        // is not enough — it must be the owner's identity key from the ring.
        if c.author_pubkey.as_slice() != self.owner_pubkey.as_slice() {
            return Err(NetError::Protocol("commit not authored by the chain owner"));
        }
        let author_pubkey = h32(&c.author_pubkey)?;
        let payload_value: serde_json::Value =
            serde_json::from_str(&c.payload).map_err(neterr)?;
        let parent = match c.parent.is_empty() {
            true => None,
            false => Some(Hash::from_bytes(h32(&c.parent)?)),
        };
        let canon = CanonicalCommit {
            parent,
            root_tree: Hash::from_bytes(h32(&c.root_tree)?),
            author_device: &c.author_device,
            author_pubkey,
            timestamp: c.timestamp,
            intent: &c.intent,
            payload: &payload_value,
            master_key_id: c.master_key_id,
            // Replication announces `repo.tip()` = the device chain (`TIP_REF`)
            // only (M5b), so a mirrored commit is always device-form
            // (`chain_id = None`). If a shared-chain commit ever reached here it
            // would fail hash reconstruction — fail-closed, never mis-accepted.
            // Replicating shared chains would require `CommitData` to carry the
            // chain_id; out of scope until that slice.
            chain_id: None,
        };
        let declared = Hash::from_bytes(h32(&c.hash)?);
        let sig = h32_64(&c.signature)?;
        verify_commit(&canon, declared, &sig)
            .map_err(|e| NetError::Protocol(static_verify_error(&e)))?;
        Ok(())
    }

    fn store_commit(&mut self, c: &CommitData) -> NetResult<()> {
        let row = commit_data_to_row(c)?;
        self.db
            .with_tx(|conn| put_commit(conn, &row))
            .map_err(neterr)?;
        Ok(())
    }

    fn has_tree(&self, hash: &[u8; 32]) -> bool {
        self.db.tree_exists(&Hash::from_bytes(*hash)).unwrap_or(false)
    }

    fn store_tree(&mut self, t: &TreeData) -> NetResult<()> {
        verify_and_put_tree(&mut self.db, t)
    }

    fn has_object(&self, hash: &[u8; 32]) -> bool {
        self.objects.contains(&Hash::from_bytes(*hash))
    }

    fn store_object(&mut self, hash: &[u8; 32], bytes: &[u8]) -> NetResult<()> {
        verify_and_put_object(&self.objects, hash, bytes)
    }

    fn advance_tip(&mut self, hash: &[u8; 32], height: u64) -> NetResult<()> {
        let h = Hash::from_bytes(*hash);
        self.db
            .with_tx(|conn| set_ref(conn, TIP_REF, &h))
            .map_err(neterr)?;
        self.db
            .meta_put("mirror_last_sync_unix", &now_unix().to_string())
            .map_err(neterr)?;
        self.db
            .meta_put("mirror_tip_height", &height.to_string())
            .map_err(neterr)?;
        Ok(())
    }
}

// --- Shared verify-then-store helpers (one address check, two sinks) --------

/// Verify a wire `TreeData` against its claimed canonical hash, then persist the
/// tree row. Shared by every `ReplicaSink` that lands trees ([`MirrorStore`],
/// [`SharedChainSink`]) so the `BLAKE3(canonical_tree_bytes)` address check lives
/// in exactly one place.
fn verify_and_put_tree(db: &mut Db, t: &TreeData) -> NetResult<()> {
    let entries: Vec<TreeEntryRow> = t
        .entries
        .iter()
        .map(msg_to_entry)
        .collect::<NetResult<_>>()?;
    let want = Hash::of(&canonical_tree_bytes(&entries).map_err(neterr)?);
    if want != Hash::from_bytes(h32(&t.hash)?) {
        return Err(NetError::Protocol("tree hash does not match its canonical form"));
    }
    db.with_tx(|conn| put_tree(conn, &want, &entries))
        .map_err(neterr)?;
    Ok(())
}

/// Content-address a wire object (`ObjectStore::put` hashes `bytes` with BLAKE3),
/// reject a mislabeled one, then persist it. Idempotent: re-putting the same
/// bytes returns the same address and stores nothing new.
fn verify_and_put_object(objects: &ObjectStore, hash: &[u8; 32], bytes: &[u8]) -> NetResult<()> {
    let stored = objects.put(bytes).map_err(neterr)?;
    if stored != Hash::from_bytes(*hash) {
        return Err(NetError::Protocol("object content-address mismatch"));
    }
    Ok(())
}

// --- Shared-chain sink (live store) -----------------------------------------

/// A [`ReplicaSink`] that lands a shared-chain subtree's trees + objects into the
/// **live garden store** — the very `Db` + `ObjectStore` the daemon's `Repo`
/// reads from — so `Repo::commit_over_tree` can re-author over the pulled tree.
///
/// Unlike [`MirrorStore`] (a keyless per-peer *mirror* of a whole device chain),
/// this sink is driven only by [`pull_subtree`](softfig_net::pull_subtree): it
/// fetches a single tree closure (trees + objects) with **no** tip announce, no
/// fast-forward walk, and no commit rows. Only the tree/object half of the trait
/// is ever exercised; the commit-graph methods (`verify_announce` / `stored_tip`
/// / `has_commit` / `verify_commit` / `store_commit` / `advance_tip`) are
/// unreachable on this path and are implemented **fail-closed** (falsy / `Err`)
/// rather than `unreachable!`, so a malformed peer degrades to a rejected pull
/// instead of panicking the daemon.
///
/// It opens its own `Db` + `ObjectStore` handles on the live store paths — a
/// *second* connection beside the daemon's `Repo`. WAL plus the store's
/// busy-timeout serialize the two writers safely, and the pull itself runs off
/// the daemon lock (only the local `commit_over_tree`, run after the pull
/// completes, takes the lock). Objects are content-addressed files, so concurrent
/// puts are inherently collision-free and idempotent.
#[derive(Debug)]
pub struct SharedChainSink {
    db: Db,
    objects: ObjectStore,
}

impl SharedChainSink {
    /// Open the live garden store for shared-chain writes. `paths` is the running
    /// daemon repo's `StorePaths` (`repo.paths().clone()`); the store must already
    /// exist (the daemon is unlocked with a live `Repo`).
    pub fn open(paths: &StorePaths) -> NetResult<Self> {
        let db = Db::open(paths).map_err(neterr)?;
        let objects = ObjectStore::new(paths.clone());
        Ok(Self { db, objects })
    }
}

impl ReplicaSink for SharedChainSink {
    // --- commit-graph half: unreachable on the pull_subtree path -------------
    // `pull_subtree` never announces a tip, walks the chain, or ships commit
    // rows, so none of these run. Fail-closed (never trust / never store) rather
    // than `unreachable!`.
    fn verify_announce(&self, _ann: &TipAnnounce) -> bool {
        false
    }

    fn stored_tip(&self) -> Option<[u8; 32]> {
        None
    }

    fn has_commit(&self, _hash: &[u8; 32]) -> bool {
        false
    }

    fn verify_commit(&self, _c: &CommitData) -> NetResult<()> {
        Err(NetError::Protocol(
            "SharedChainSink: commit-graph path is unreachable for a shared-chain pull",
        ))
    }

    fn store_commit(&mut self, _c: &CommitData) -> NetResult<()> {
        Err(NetError::Protocol(
            "SharedChainSink: commit-graph path is unreachable for a shared-chain pull",
        ))
    }

    fn advance_tip(&mut self, _hash: &[u8; 32], _height: u64) -> NetResult<()> {
        Err(NetError::Protocol(
            "SharedChainSink: commit-graph path is unreachable for a shared-chain pull",
        ))
    }

    // --- tree/object half: the transfer target -------------------------------
    fn has_tree(&self, hash: &[u8; 32]) -> bool {
        self.db.tree_exists(&Hash::from_bytes(*hash)).unwrap_or(false)
    }

    fn store_tree(&mut self, t: &TreeData) -> NetResult<()> {
        verify_and_put_tree(&mut self.db, t)
    }

    fn has_object(&self, hash: &[u8; 32]) -> bool {
        self.objects.contains(&Hash::from_bytes(*hash))
    }

    fn store_object(&mut self, hash: &[u8; 32], bytes: &[u8]) -> NetResult<()> {
        verify_and_put_object(&self.objects, hash, bytes)
    }
}

// --- Status surface (backup-health metadata) --------------------------------

/// One peer chain this device mirrors, for the status surface. Metadata only.
#[derive(Debug, Clone)]
pub struct HostedMirror {
    pub fingerprint: String,
    pub name: Option<String>,
    pub tip: Option<String>,
    pub height: u64,
    pub objects: u64,
    pub bytes: u64,
    pub last_sync: Option<i64>,
}

/// Enumerate the mirrors under `replica_root`, reading each one's metadata.
/// Best-effort: a dir that fails to open (corrupt / mid-write) is skipped, so
/// the status surface degrades gracefully rather than erroring.
pub fn list_hosted(replica_root: &Path) -> Vec<HostedMirror> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(replica_root) {
        Ok(e) => e,
        Err(_) => return out, // no mirrors yet
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name_os = entry.file_name();
        let Some(fingerprint) = name_os.to_str() else {
            continue;
        };
        // Only directories named like a device-id (64 hex chars).
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if let Some(mirror) = read_mirror(&entry.path(), fingerprint) {
            out.push(mirror);
        }
    }
    out.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    out
}

fn read_mirror(dir: &Path, fingerprint: &str) -> Option<HostedMirror> {
    let paths = StorePaths::with_state_root(dir, dir);
    if !paths.exists() {
        return None;
    }
    let db = Db::open(&paths).ok()?;
    let objects = ObjectStore::new(paths);
    let tip = db.try_get_ref(TIP_REF).ok().flatten().map(|h| h.to_hex());
    let height = db
        .meta_get("mirror_tip_height")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let last_sync = db
        .meta_get("mirror_last_sync_unix")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok());
    let name = db.meta_get("mirror_owner_name").ok().flatten().filter(|s| !s.is_empty());
    let (objects_count, bytes) = object_stats(&objects);
    Some(HostedMirror {
        fingerprint: fingerprint.to_string(),
        name,
        tip,
        height,
        objects: objects_count,
        bytes,
        last_sync,
    })
}

fn object_stats(objects: &ObjectStore) -> (u64, u64) {
    let mut count = 0u64;
    let mut bytes = 0u64;
    if let Ok(iter) = objects.iter() {
        for item in iter.flatten() {
            count += 1;
            bytes += item.1.len() as u64;
        }
    }
    (count, bytes)
}

// --- wire <-> store row conversions -----------------------------------------

fn commit_row_to_data(row: &CommitRow) -> CommitData {
    CommitData {
        found: true,
        hash: row.hash.as_bytes().to_vec(),
        parent: row.parent.map(|p| p.as_bytes().to_vec()).unwrap_or_default(),
        root_tree: row.root_tree.as_bytes().to_vec(),
        author_device: row.author_device.clone(),
        author_pubkey: row.author_pubkey.to_vec(),
        timestamp: row.timestamp,
        intent: row.intent.clone(),
        payload: row.payload.clone(),
        master_key_id: row.master_key_id,
        signature: row.signature.to_vec(),
    }
}

fn commit_data_to_row(c: &CommitData) -> NetResult<CommitRow> {
    Ok(CommitRow {
        hash: Hash::from_bytes(h32(&c.hash)?),
        parent: if c.parent.is_empty() {
            None
        } else {
            Some(Hash::from_bytes(h32(&c.parent)?))
        },
        root_tree: Hash::from_bytes(h32(&c.root_tree)?),
        author_device: c.author_device.clone(),
        author_pubkey: h32(&c.author_pubkey)?,
        timestamp: c.timestamp,
        intent: c.intent.clone(),
        payload: c.payload.clone(),
        master_key_id: c.master_key_id,
        signature: h32_64(&c.signature)?,
    })
}

fn entry_to_msg(e: &TreeEntryRow) -> TreeEntryMsg {
    TreeEntryMsg {
        name: e.name.clone(),
        kind: e.kind.as_str().to_string(),
        mode: e.mode,
        target: e.target.as_bytes().to_vec(),
    }
}

fn msg_to_entry(m: &TreeEntryMsg) -> NetResult<TreeEntryRow> {
    let kind = TreeEntryKind::parse(&m.kind)
        .ok_or(NetError::Protocol("tree entry has unknown kind"))?;
    Ok(TreeEntryRow {
        name: m.name.clone(),
        kind,
        mode: m.mode,
        target: Hash::from_bytes(h32(&m.target)?),
    })
}

fn h32_64(bytes: &[u8]) -> NetResult<[u8; 64]> {
    bytes
        .try_into()
        .map_err(|_| NetError::Protocol("signature field is not 64 bytes"))
}

/// Map a commit-verification failure to a static, security-relevant message.
fn static_verify_error(e: &softfig_vcs::CoreError) -> &'static str {
    use softfig_vcs::CoreError;
    match e {
        CoreError::BadSignature(_) => "commit signature does not verify",
        CoreError::CommitHashMismatch { .. } => "commit hash does not match its canonical form",
        _ => "commit failed verification",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_ledger_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = GrantLedger::default();
        assert!(ledger.grant("aa"));
        assert!(!ledger.grant("aa"), "second grant is a no-op");
        assert!(ledger.grant("bb"));
        ledger.save(dir.path()).unwrap();

        let back = GrantLedger::load(dir.path()).unwrap();
        assert_eq!(back.push_to, vec!["aa".to_string(), "bb".to_string()]);
        assert!(back.contains("bb"));
    }

    #[test]
    fn grant_ledger_revoke() {
        let mut ledger = GrantLedger::default();
        ledger.grant("aa");
        assert!(ledger.revoke("aa"));
        assert!(!ledger.revoke("aa"), "second revoke is a no-op");
        assert!(ledger.push_to.is_empty());
    }

    #[test]
    fn missing_ledger_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(GrantLedger::load(dir.path()).unwrap().push_to.is_empty());
    }

    #[test]
    fn grant_mint_verify_round_trip() {
        use ed25519_dalek::{Signer, SigningKey};
        use softfig_net::verify_grant;
        // Mint with a raw key the same way the vault would (sign the bytes).
        let owner = SigningKey::from_bytes(&[7u8; 32]);
        let host = [0x42u8; 32];
        let chain = b"chain-123";
        let issued_at = 1_700_000_000;
        let sig = owner
            .sign(&grant_signing_bytes(&host, chain, issued_at))
            .to_bytes()
            .to_vec();
        let grant = ReplicaGrant {
            grantee_device_id: host.to_vec(),
            chain_id: chain.to_vec(),
            issued_at,
            signature: sig,
        };
        let owner_id = owner.verifying_key().to_bytes();
        assert!(verify_grant(&grant, &owner_id, &host));
        // Wrong grantee, wrong owner key, tampered sig all fail.
        assert!(!verify_grant(&grant, &owner_id, &[0x99u8; 32]));
        assert!(!verify_grant(&grant, &[0u8; 32], &host));
        let mut bad = grant.clone();
        bad.signature[0] ^= 1;
        assert!(!verify_grant(&bad, &owner_id, &host));
    }

    #[test]
    fn list_hosted_skips_non_mirror_dirs() {
        let root = tempfile::tempdir().unwrap();
        // A stray non-hex dir + a hex dir with no db are both skipped.
        fs::create_dir_all(root.path().join("not-a-device")).unwrap();
        fs::create_dir_all(root.path().join("ab".repeat(32))).unwrap();
        assert!(list_hosted(root.path()).is_empty());
    }

    // --- SharedChainSink (shared-chain pull into the live store) -------------

    /// Create a fresh live store at `dir` and return its paths. Mirrors the
    /// daemon's on-disk layout closely enough to open a real `Db` + `ObjectStore`
    /// over it. Returns the live `Db` handle too so the test can hold a second
    /// connection open beside the sink (the concurrency scenario).
    fn live_store(dir: &Path) -> (StorePaths, Db) {
        let paths = StorePaths::with_state_root(dir, dir);
        fs::create_dir_all(paths.softfig_dir()).unwrap();
        ObjectStore::new(paths.clone()).ensure_root().unwrap();
        let db = Db::create(&paths, "shared-chain-test", now_unix()).unwrap();
        (paths, db)
    }

    /// Build a one-entry blob tree over `bytes`, returning its wire `TreeData`,
    /// the tree hash, and the object hash (= `BLAKE3(bytes)`).
    fn blob_tree(name: &str, bytes: &[u8]) -> (TreeData, Hash, Hash) {
        let obj_hash = Hash::of(bytes);
        let entries = vec![TreeEntryRow {
            name: name.to_string(),
            kind: TreeEntryKind::Blob,
            mode: 0o100644,
            target: obj_hash,
        }];
        let tree_hash = Hash::of(&canonical_tree_bytes(&entries).unwrap());
        let tree = TreeData {
            found: true,
            hash: tree_hash.as_bytes().to_vec(),
            entries: entries.iter().map(entry_to_msg).collect(),
        };
        (tree, tree_hash, obj_hash)
    }

    #[test]
    fn shared_chain_sink_lands_closure_into_the_live_store() {
        let dir = tempfile::tempdir().unwrap();
        // Hold the creating handle open — the sink is a *second* connection on
        // the same store, exactly as it will be beside the daemon's live `Repo`.
        let (paths, _live_db) = live_store(dir.path());
        let bytes = b"shared-chain payload".as_slice();
        let (tree, tree_hash, obj_hash) = blob_tree("note.md", bytes);
        let obj_arr = *obj_hash.as_bytes();
        let tree_arr = *tree_hash.as_bytes();

        let mut sink = SharedChainSink::open(&paths).unwrap();
        assert!(!sink.has_object(&obj_arr));
        assert!(!sink.has_tree(&tree_arr));
        sink.store_object(&obj_arr, bytes).unwrap();
        sink.store_tree(&tree).unwrap();
        assert!(sink.has_object(&obj_arr));
        assert!(sink.has_tree(&tree_arr));

        // The whole point: a *fresh* handle (what the daemon's `Repo` /
        // `commit_over_tree` uses) reads the pulled closure back — same store,
        // not a per-peer mirror.
        let fresh_db = Db::open(&paths).unwrap();
        let fresh_objects = ObjectStore::new(paths.clone());
        assert!(fresh_db.tree_exists(&tree_hash).unwrap());
        assert!(fresh_objects.contains(&obj_hash));
        assert_eq!(fresh_objects.get(&obj_hash).unwrap(), bytes);

        // Re-pull is idempotent (ping-pong / mesh re-push must not error).
        sink.store_object(&obj_arr, bytes).unwrap();
        sink.store_tree(&tree).unwrap();
    }

    #[test]
    fn shared_chain_sink_rejects_mislabeled_content() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _live_db) = live_store(dir.path());
        let mut sink = SharedChainSink::open(&paths).unwrap();

        // Object claimed under a hash that is not BLAKE3(bytes).
        let wrong = [0x11u8; 32];
        assert!(sink.store_object(&wrong, b"real bytes").is_err());

        // Tree whose declared hash does not match its canonical form.
        let (mut tree, _h, _o) = blob_tree("f.md", b"x");
        tree.hash = vec![0x22u8; 32];
        assert!(sink.store_tree(&tree).is_err());
    }

    #[test]
    fn shared_chain_sink_commit_graph_is_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _live_db) = live_store(dir.path());
        let mut sink = SharedChainSink::open(&paths).unwrap();
        // The commit-graph half is unreachable on the pull_subtree path and must
        // never trust / never store, and must not panic.
        assert!(!sink.verify_announce(&TipAnnounce::default()));
        assert!(sink.stored_tip().is_none());
        assert!(!sink.has_commit(&[0u8; 32]));
        assert!(sink.verify_commit(&CommitData::default()).is_err());
        assert!(sink.store_commit(&CommitData::default()).is_err());
        assert!(sink.advance_tip(&[0u8; 32], 1).is_err());
    }
}
