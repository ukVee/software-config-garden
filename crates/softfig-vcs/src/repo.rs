//! High-level Repo type: open / init / commit / log.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use softfig_store::{
    put_commit, put_tree, set_ref_cas, CommitRow, Db, Hash, ObjectStore, StorePaths,
};
use softfig_vault::{Vault, VaultSession};

use crate::commit::CanonicalCommit;
use crate::error::{CoreError, Result};
use crate::intent::Intent;
use crate::tree::{self, BlobEncryptor, Blueprint, LayerAEncryptor};
use crate::walk::{self, WalkSnapshot};

pub const TIP_REF: &str = "tip";

/// Whether a commit whose tree already matches its parent's is skipped.
///
/// [`SameTreePolicy::Skip`] is the default and the point of the guard: a write
/// that changed no content advances nothing, so it mints nothing.
/// [`SameTreePolicy::Record`] is the deliberate exception — a commit whose
/// value is the *record it carries*, not the tree it lands. The vault's audit
/// intents are the whole set: `vault_reveal` (the log entry the reveal handler
/// treats as a precondition for surfacing a plaintext path) and the
/// `sealed-paths.toml` edits, whose file lives under `.softfig/` and is
/// therefore never in the tree at all. Reach for it only when the absence of a
/// commit would lose a record nothing else holds — never to keep a caller that
/// merely assumes commits are always minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameTreePolicy {
    /// Skip the commit when the tree is unchanged.
    Skip,
    /// Write the commit even when the tree is unchanged.
    Record,
}

/// What a commit call left behind on the chain it targeted.
///
/// **The no-op return contract.** Every commit path here is guarded against
/// minting a commit whose `root_tree` is byte-identical to its parent's: an
/// unchanged tree writes nothing and reports `committed == false`, with `hash`
/// carrying the **untouched parent tip**. So `hash` always answers "where is
/// this chain now?" — never "here is a commit I just wrote". A caller that must
/// distinguish the two (narration, peer-push wakeups, anything counting
/// commits) reads `committed`; a caller that only wants the current tip reads
/// `hash` and can keep using the `Hash`-returning wrappers.
///
/// The guard lives at the writer ([`write_commit_tx`] / [`write_reauthor_tx`])
/// so *every* caller inherits it — the FUSE dirty-set flush, the action verbs
/// (`set_reviewed`, the section verbs), and the m5e `shared_pull` apply alike.
/// Two independent empty-commit sources motivated it: a same-day
/// `set_reviewed` re-stamp (identical bytes, committed unconditionally), and a
/// change confined to a user-`.softfigignore`'d path, which the hot-path
/// built-in ignore predicate lets through `flush()` even though the
/// ignore-filtered snapshot is identical to the tip (task 028).
///
/// On a no-op the `tip_changed` callback does **not** fire. That is load-bearing,
/// not an optimization: the FUSE rotation absorbs the overlay entries a commit
/// captured, and an ignored path is never captured by any commit — firing the
/// callback would drop a staged write that exists nowhere else (the m5c/m5e
/// absorption data-loss family).
///
/// The one deliberate exception is [`SameTreePolicy::Record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    /// The chain's tip after the call: the new commit when one was written,
    /// the unchanged parent when the tree was identical.
    pub hash: Hash,
    /// `true` when a commit row was actually written and the ref advanced.
    pub committed: bool,
}

impl CommitOutcome {
    /// The tree was unchanged, so nothing was written and [`Self::hash`] is the
    /// parent tip.
    pub fn is_no_op(&self) -> bool {
        !self.committed
    }
}

/// Subscriber called after a successful commit advances a chain's ref. It
/// receives the `ref_name` that moved and the new tip hash, so a consumer can
/// invalidate **per chain** (M5c slice 002 union mount): the device chain
/// (`TIP_REF`) and each shared chain fire the same slot, distinguished by
/// `ref_name`. M2a wires the FUSE driver here so it can drop its stat cache and
/// broadcast inval_inode notifications. One slot per repo for v1; if a second
/// consumer ever shows up (sync push?), promote to a Vec.
/// `(ref_name, new_tip_hash, overlay_generation)`. `overlay_generation` is the
/// FUSE-overlay generation the committed snapshot was cut at (`Some` for a
/// commit built from a live overlay, `None` for a disk walk or a network ref
/// advance carrying no local snapshot) — the FUSE driver's rotation absorbs
/// overlay entries at or before that generation for the advanced ref only, so a
/// `None` advance absorbs nothing (m5c-residual slice 012).
pub type TipChangedCallback = Box<dyn Fn(&str, &Hash, Option<u64>) + Send + Sync>;

/// A garden's VCS repository. Holds the path layout, an opened sqlite
/// connection, and the object store. Does not hold a `VaultSession` —
/// callers pass the session to operations that need crypto.
pub struct Repo {
    paths: StorePaths,
    db: Db,
    objects: ObjectStore,
    garden_root: PathBuf,
    tip_changed: Option<TipChangedCallback>,
    /// M2b: optional Layer-B-aware blob encryptor installed by the
    /// daemon at unlock time. `None` = Layer A only (default for direct
    /// CLI mode and M1c-compat M2a/no-Layer-B configs).
    blob_encryptor: Option<Arc<dyn BlobEncryptor>>,
}

impl std::fmt::Debug for Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repo")
            .field("paths", &self.paths)
            .field("db", &self.db)
            .field("objects", &self.objects)
            .field("garden_root", &self.garden_root)
            .field(
                "tip_changed",
                &self.tip_changed.as_ref().map(|_| "<callback>"),
            )
            .field(
                "blob_encryptor",
                &self.blob_encryptor.as_ref().map(|_| "<encryptor>"),
            )
            .finish()
    }
}

impl Repo {
    /// Open an existing repo at `<garden_root>/.softfig/` (M1c-compat).
    pub fn open(garden_root: &Path) -> Result<Self> {
        Self::open_with(garden_root, None)
    }

    /// Open an existing repo whose state lives at a relocated path.
    /// Pass `state_root = None` for the M1c-compat layout, or
    /// `Some(path)` for M2a (path is the dir containing `.softfig/`).
    pub fn open_with(garden_root: &Path, state_root: Option<&Path>) -> Result<Self> {
        let paths = match state_root {
            Some(s) => StorePaths::with_state_root(garden_root, s),
            None => StorePaths::for_garden(garden_root),
        };
        if !paths.exists() {
            return Err(CoreError::RepoMissing(paths.softfig_dir()));
        }
        let db = Db::open(&paths)?;
        let objects = ObjectStore::new(paths.clone());
        Ok(Self {
            paths,
            db,
            objects,
            garden_root: garden_root.to_path_buf(),
            tip_changed: None,
            blob_encryptor: None,
        })
    }

    /// Initialize a fresh repo on top of an existing Vault. Walks the
    /// current working tree, encrypts every blob, builds trees, signs and
    /// records a genesis `init` commit, and sets `tip`.
    ///
    /// Errors if `.softfig/vault/` is absent (run `softfig vault init`
    /// first) or if `.softfig/db.sqlite` is already present.
    pub fn init(garden_root: &Path, session: &VaultSession) -> Result<(Self, Hash)> {
        let paths = StorePaths::for_garden(garden_root);

        let vault = Vault::at(garden_root);
        if !vault.is_initialized() {
            return Err(CoreError::VaultMissing(vault.paths().root.clone()));
        }
        if paths.exists() {
            return Err(CoreError::RepoExists(paths.softfig_dir()));
        }

        std::fs::create_dir_all(paths.softfig_dir())?;
        let objects = ObjectStore::new(paths.clone());
        objects.ensure_root()?;

        let now = unix_seconds();
        let repo_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let mut db = Db::create(&paths, &repo_id, now)?;

        let snapshot = walk::walk(garden_root)?;
        let blueprint = tree::build(&objects, session, &snapshot.root)?;

        let intent = Intent::init("garden initialized");
        // Genesis has no parent, so the same-tree guard never fires here.
        let commit_hash = write_commit_tx(
            &mut db,
            session,
            TIP_REF,
            None,
            &blueprint,
            intent,
            now,
            SameTreePolicy::Skip,
        )?
        .hash;

        Ok((
            Self {
                paths,
                db,
                objects,
                garden_root: garden_root.to_path_buf(),
                tip_changed: None,
                blob_encryptor: None,
            },
            commit_hash,
        ))
    }

    /// Born-in-FUSE: create a fresh garden directly in the relocated
    /// `state_root` layout, skipping the legacy `<garden_root>/.softfig/`
    /// step and the three-phase `migrate`. The Vault must already be
    /// initialized under `state_root` (via `Vault::init(state_root, …)`,
    /// whose `VaultPaths::for_garden` is an alias for `for_state_root`).
    ///
    /// `staging` holds the working-tree content to encrypt into the
    /// genesis commit (e.g. a stamped skeleton in a tempdir); `garden_root`
    /// is the eventual FUSE mount path recorded on the repo. No plaintext
    /// is written under `garden_root` — the daemon serves it via FUSE once
    /// mounted.
    pub fn create_fresh(
        garden_root: &Path,
        state_root: &Path,
        staging: &Path,
        session: &VaultSession,
    ) -> Result<(Self, Hash)> {
        let paths = StorePaths::with_state_root(garden_root, state_root);

        let vault = Vault::at_state_root(state_root);
        if !vault.is_initialized() {
            return Err(CoreError::VaultMissing(vault.paths().root.clone()));
        }
        if paths.exists() {
            return Err(CoreError::RepoExists(paths.softfig_dir()));
        }

        std::fs::create_dir_all(paths.softfig_dir())?;
        let objects = ObjectStore::new(paths.clone());
        objects.ensure_root()?;

        let now = unix_seconds();
        let repo_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let mut db = Db::create(&paths, &repo_id, now)?;

        let snapshot = walk::walk(staging)?;
        let blueprint = tree::build(&objects, session, &snapshot.root)?;

        let intent = Intent::init("garden initialized");
        // Genesis has no parent, so the same-tree guard never fires here.
        let commit_hash = write_commit_tx(
            &mut db,
            session,
            TIP_REF,
            None,
            &blueprint,
            intent,
            now,
            SameTreePolicy::Skip,
        )?
        .hash;

        Ok((
            Self {
                paths,
                db,
                objects,
                garden_root: garden_root.to_path_buf(),
                tip_changed: None,
                blob_encryptor: None,
            },
            commit_hash,
        ))
    }

    pub fn paths(&self) -> &StorePaths {
        &self.paths
    }

    pub fn garden_root(&self) -> &Path {
        &self.garden_root
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn db_mut(&mut self) -> &mut Db {
        &mut self.db
    }

    pub fn objects(&self) -> &ObjectStore {
        &self.objects
    }

    /// Read the repo's persistent identifier from `meta.repo_id`. Used by
    /// `softfig migrate prepare` to derive the XDG state dir for this
    /// garden.
    pub fn repo_id(&self) -> Result<String> {
        self.db
            .meta_get("repo_id")?
            .ok_or_else(|| CoreError::RepoMissing(self.paths.softfig_dir()))
    }

    /// Current device-chain `tip` commit, if any.
    pub fn tip(&self) -> Result<Option<Hash>> {
        self.tip_of(TIP_REF)
    }

    /// Current tip of an arbitrary chain ref, if set. The device chain is
    /// [`TIP_REF`]; a shared chain (m5c) is a different ref sharing this same
    /// `Db`/`ObjectStore`. An unset ref (a chain with no commits yet) is `None`.
    pub fn tip_of(&self, ref_name: &str) -> Result<Option<Hash>> {
        Ok(self.db.try_get_ref(ref_name)?)
    }

    /// Install (or replace) the tip-changed callback. Fired after a
    /// successful `commit_workdir` lands a new tip. M2a wires the FUSE
    /// driver here.
    pub fn set_tip_changed_callback<F>(&mut self, cb: F)
    where
        F: Fn(&str, &Hash, Option<u64>) + Send + Sync + 'static,
    {
        self.tip_changed = Some(Box::new(cb));
    }

    /// Install (or replace) the blob encryptor used by `commit_workdir`.
    /// M2b's daemon registers an encryptor here so sealed paths route
    /// through Layer B; direct-mode CLI callers leave this `None` and
    /// the default Layer A path is used.
    pub fn set_blob_encryptor(&mut self, enc: Arc<dyn BlobEncryptor>) {
        self.blob_encryptor = Some(enc);
    }

    /// Walk the working tree at `garden_root`, build a blueprint, and write
    /// a new commit whose parent is the current tip. Returns the device
    /// chain's tip after the call — the new commit, or the unchanged parent
    /// when the walked tree matched it (see [`CommitOutcome`]); use
    /// [`Repo::commit_snapshot_to_outcome`] when the difference matters.
    ///
    /// This reads the working tree from disk via [`walk::walk`]. A FUSE
    /// daemon must NOT use this for a mounted garden: `garden_root` is the
    /// mount it serves, so walking it self-reads the mount while the daemon
    /// holds its lock — the 2026-06-21 commit-path deadlock. The daemon
    /// builds its in-memory (tip ∪ overlay) tree and calls
    /// [`Repo::commit_snapshot`] instead. Direct-mode CLI and M1c-compat
    /// (non-FUSE) callers keep using this.
    pub fn commit_workdir(
        &mut self,
        session: &VaultSession,
        intent: Intent,
    ) -> Result<Hash> {
        Ok(self.commit_workdir_outcome(session, intent)?.hash)
    }

    /// [`Repo::commit_workdir`], reporting whether a commit was minted — the
    /// disk-walk twin of [`Repo::commit_snapshot_to_outcome`]. A working tree
    /// whose only changes are `.softfigignore`'d walks to the tree already
    /// committed, so this reports a no-op rather than an empty commit.
    pub fn commit_workdir_outcome(
        &mut self,
        session: &VaultSession,
        intent: Intent,
    ) -> Result<CommitOutcome> {
        self.commit_workdir_with(session, intent, SameTreePolicy::Skip)
    }

    /// [`Repo::commit_workdir_outcome`] with an explicit [`SameTreePolicy`] —
    /// the disk-walk twin of [`Repo::commit_snapshot_to_with`].
    pub fn commit_workdir_with(
        &mut self,
        session: &VaultSession,
        intent: Intent,
        policy: SameTreePolicy,
    ) -> Result<CommitOutcome> {
        let snapshot = walk::walk(&self.garden_root)?;
        self.commit_snapshot_to_with(TIP_REF, session, snapshot, intent, policy)
    }

    /// Commit a pre-built working-tree `snapshot` against the current tip,
    /// returning the device chain's tip after the call (the new commit, or the
    /// unchanged parent on a same-tree no-op — see [`CommitOutcome`]).
    /// Identical to [`Repo::commit_workdir`] except the caller supplies the
    /// tree rather than walking `garden_root` — letting the FUSE daemon commit
    /// from its in-memory state without self-reading the mount it serves.
    pub fn commit_snapshot(
        &mut self,
        session: &VaultSession,
        snapshot: WalkSnapshot,
        intent: Intent,
    ) -> Result<Hash> {
        self.commit_snapshot_to(TIP_REF, session, snapshot, intent)
    }

    /// Commit a pre-built `snapshot` against the tip of an arbitrary chain
    /// `ref_name`, advancing that ref only. `commit_snapshot` is the device-chain
    /// (`TIP_REF`) case; a shared chain (m5c) routes here with its own ref so a
    /// write lands on exactly the owning chain and never the device chain's ref.
    ///
    /// The `tip_changed` callback (the FUSE stat-cache invalidation) fires for
    /// **whichever** ref this commit advanced, carrying `ref_name` so the FUSE
    /// driver can recompose the union view and invalidate per chain, plus the
    /// snapshot's `overlay_generation` so the rotation absorbs exactly the
    /// overlay entries this commit captured. A snapshot with no generation (a
    /// network ref advance, a disk walk) fires the callback with `None` and the
    /// rotation absorbs nothing (m5c-residual slice 012).
    pub fn commit_snapshot_to(
        &mut self,
        ref_name: &str,
        session: &VaultSession,
        snapshot: WalkSnapshot,
        intent: Intent,
    ) -> Result<Hash> {
        Ok(self
            .commit_snapshot_to_outcome(ref_name, session, snapshot, intent)?
            .hash)
    }

    /// [`Repo::commit_snapshot_to`], reporting whether a commit was actually
    /// minted. This is the primitive the `Hash`-returning wrappers delegate to;
    /// reach for it when a same-tree no-op must not be narrated, counted, or
    /// signalled onward (the watcher's replica-push wakeup, the action verbs'
    /// commit reporting). See [`CommitOutcome`] for the contract.
    pub fn commit_snapshot_to_outcome(
        &mut self,
        ref_name: &str,
        session: &VaultSession,
        snapshot: WalkSnapshot,
        intent: Intent,
    ) -> Result<CommitOutcome> {
        self.commit_snapshot_to_with(ref_name, session, snapshot, intent, SameTreePolicy::Skip)
    }

    /// [`Repo::commit_snapshot_to_outcome`] with an explicit
    /// [`SameTreePolicy`]. `Record` writes the commit even on an unchanged tree
    /// — see the policy's docs for the one class of caller that wants it.
    pub fn commit_snapshot_to_with(
        &mut self,
        ref_name: &str,
        session: &VaultSession,
        snapshot: WalkSnapshot,
        intent: Intent,
        policy: SameTreePolicy,
    ) -> Result<CommitOutcome> {
        let parent = self.tip_of(ref_name)?;
        let default_enc = LayerAEncryptor;
        let encryptor: &dyn BlobEncryptor = match self.blob_encryptor.as_ref() {
            Some(enc) => enc.as_ref(),
            None => &default_enc,
        };
        let overlay_generation = snapshot.overlay_generation;
        let blueprint = tree::build_with(&self.objects, session, &snapshot.root, encryptor, ref_name)?;
        let now = unix_seconds();
        let outcome = write_commit_tx(
            &mut self.db,
            session,
            ref_name,
            parent,
            &blueprint,
            intent,
            now,
            policy,
        )?;
        // A no-op advanced nothing, so the FUSE view is already correct and its
        // overlay must keep every staged entry (see `CommitOutcome`).
        if outcome.committed {
            if let Some(cb) = &self.tip_changed {
                cb(ref_name, &outcome.hash, overlay_generation);
            }
        }
        Ok(outcome)
    }

    /// Re-author a commit over an **existing** `root_tree` hash on `ref_name`,
    /// advancing that ref to a new commit whose tree is `root_tree` — no
    /// workdir walk, no tree rebuild. The m5e `shared_pull` apply primitive: a
    /// peer's shared-chain tree, already fetched content-addressed into this
    /// store, is re-committed as **this device's own** commit (its own author /
    /// signature / hash) parented on the local chain tip. Convergence is by
    /// content (identical `root_tree`), history is per-device — the peer's exact
    /// commit hash is never adopted and no merge object is ever minted (the
    /// chain stays linear / single-parent, per [[decision-m5e-shared-pull-intent]]).
    ///
    /// Preconditions the caller upholds:
    /// - `root_tree` and its full subtree + blob closure are already in the
    ///   object store (the m5e transfer — M5b content-addressed object pull —
    ///   guarantees this before apply);
    /// - the fast-forward decision (base tree == local tip tree; content dedup)
    ///   is already made upstream. This method only authors + CAS-advances; the
    ///   per-ref CAS still rolls back on a concurrent local advance.
    ///
    /// Fires `tip_changed` with a `None` overlay generation — a network-driven
    /// ref advance carries no local overlay snapshot, so the FUSE rotation
    /// absorbs nothing (it only recomposes the union view; m5c-residual slice
    /// 012, the 014 data-loss family).
    pub fn commit_over_tree(
        &mut self,
        ref_name: &str,
        session: &VaultSession,
        root_tree: Hash,
        intent: Intent,
    ) -> Result<Hash> {
        Ok(self
            .commit_over_tree_outcome(ref_name, session, root_tree, intent)?
            .hash)
    }

    /// [`Repo::commit_over_tree`], reporting whether a commit was minted. The
    /// same-tree guard applies here too: an apply whose peer tree already
    /// equals the local tip's writes nothing and reports `committed == false`.
    /// Upstream normally makes that call first (the fast-forward / content
    /// dedup decision), so this is a backstop, not the primary dedup.
    pub fn commit_over_tree_outcome(
        &mut self,
        ref_name: &str,
        session: &VaultSession,
        root_tree: Hash,
        intent: Intent,
    ) -> Result<CommitOutcome> {
        let parent = self.tip_of(ref_name)?;
        let now = unix_seconds();
        let outcome =
            write_reauthor_tx(&mut self.db, session, ref_name, parent, root_tree, intent, now)?;
        if outcome.committed {
            if let Some(cb) = &self.tip_changed {
                cb(ref_name, &outcome.hash, None);
            }
        }
        Ok(outcome)
    }

    /// The tip of **every ref physically present** in the store
    /// (`db.list_refs()`). This is gc's retention set: a chain is live for gc iff
    /// its ref exists — nothing else gates retention. Enable/disable is a
    /// mount/compose concern (a disabled chain keeps its ref, so its exclusive
    /// blobs survive `disable -> gc -> re-enable`, m5c finding 7), and an
    /// *un-shared* chain keeps its ref + objects until an explicit chain-drop verb
    /// deletes the ref, so `remove -> gc -> re-add` resumes the chain intact
    /// instead of resurrecting a tip whose blobs gc collected (m5c-residual slice
    /// 011, contract (a): every ref is live). Deriving retention from the refs
    /// table — the ground truth — rather than the in-memory registry is exactly
    /// what makes this resurrection-safe: a removed chain is gone from the
    /// registry but its ref still pins its whole closure.
    pub fn live_tips(&self) -> Result<Vec<Hash>> {
        Ok(self
            .db
            .list_refs()?
            .into_iter()
            .map(|r| r.commit_hash)
            .collect())
    }

    /// Per-chain fsck over the chain tracked by `ref_name` (see
    /// [`crate::fsck::run_chain`]).
    pub fn fsck_chain(&self, ref_name: &str) -> Result<crate::fsck::FsckReport> {
        let chain_id = (ref_name != TIP_REF).then_some(ref_name);
        crate::fsck::run_chain(&self.db, &self.objects, self.tip_of(ref_name)?, chain_id)
    }

    /// Collect loose objects unreachable from **every ref's tip**
    /// ([`Self::live_tips`], see [`crate::gc::gc`]). Safe across chains: the
    /// retained set is the union of every ref's reachable blobs — including
    /// disabled and un-shared (removed-but-not-dropped) chains, whose refs still
    /// pin their objects (m5c finding 7; m5c-residual slice 011).
    pub fn gc(&self) -> Result<crate::gc::GcReport> {
        let tips = self.live_tips()?;
        crate::gc::gc(&self.db, &self.objects, &tips)
    }
}

/// Author the signed commit row over a known `root_tree` hash — shared by the
/// snapshot-commit path (trees freshly built into a [`Blueprint`]) and the
/// re-author-over-existing-tree path ([`Repo::commit_over_tree`], the m5e
/// `shared_pull` apply). Pure: no I/O, no ref touched — the caller drives the
/// transaction and decides whether new tree rows accompany the commit.
fn author_commit_row(
    session: &VaultSession,
    ref_name: &str,
    parent: Option<Hash>,
    root_tree: Hash,
    intent: Intent,
    timestamp: i64,
) -> Result<(CommitRow, Hash)> {
    let author_device = local_device_label();
    let author_pubkey = session.identity_pubkey().to_bytes();
    let master_key_id = session.active_master_key_id();
    let (intent_name, intent_payload) = intent.into_parts();

    // Re-canonicalize the payload alone so the row stores the canonical
    // form. Reading back + re-canonicalizing yields identical bytes.
    let payload_canon_bytes = serde_jcs::to_vec(&intent_payload)?;
    let payload_canon_str = String::from_utf8(payload_canon_bytes)
        .expect("JCS output is ASCII-only");
    let payload_canon_value: serde_json::Value =
        serde_json::from_str(&payload_canon_str)?;

    // Bind the commit to its chain (M5d slice 002). The device chain
    // (`TIP_REF`) stays `None` so its canonical bytes — and every historical
    // hash — are unchanged; a shared chain binds its stable `ref_name`.
    let chain_id = (ref_name != TIP_REF).then_some(ref_name);

    let canon = CanonicalCommit {
        parent,
        root_tree,
        author_device: &author_device,
        author_pubkey,
        timestamp,
        intent: &intent_name,
        payload: &payload_canon_value,
        master_key_id,
        chain_id,
    };
    let hash = canon.hash()?;
    let signature_bytes = session.sign(hash.as_bytes()).to_bytes();

    let row = CommitRow {
        hash,
        parent,
        root_tree,
        author_device,
        author_pubkey,
        timestamp,
        intent: intent_name,
        payload: payload_canon_str,
        master_key_id,
        signature: signature_bytes,
    };
    Ok((row, hash))
}

/// True when `root_tree` is byte-identical to the tree `parent` already
/// commits — i.e. writing this commit would advance the chain by nothing.
///
/// This is the same-tree guard's one question, asked once at the writer so both
/// commit paths (snapshot-built trees and re-authored ones) share the answer.
/// Genesis (`parent == None`) is never a no-op. The parent's row is looked up
/// rather than cached: a ref always points at a stored commit (every writer
/// inserts the row inside the tx that CASes the ref), so a missing row means a
/// corrupt store and propagates as such instead of being papered over with an
/// extra empty commit.
///
/// Comparing against the **immediate parent only** is deliberate: a revert to
/// some older tree differs from its parent and still commits, as it must.
fn is_same_tree(db: &Db, parent: Option<Hash>, root_tree: &Hash) -> Result<bool> {
    match parent {
        None => Ok(false),
        Some(p) => Ok(&db.get_commit(&p)?.root_tree == root_tree),
    }
}

/// Transactional commit writer: insert all new tree rows + the commit
/// row + CAS the ref, all in one sqlite tx.
///
/// Guarded by [`is_same_tree`]: an unchanged tree writes **nothing** and
/// returns the parent as a no-op [`CommitOutcome`]. Skipping the tree rows with
/// it is safe by content-addressing — an identical root hash means every
/// subtree row is already stored (the parent commit wrote them), and the
/// blueprint's blobs were written to the object store before this call, where
/// an identical blob is an idempotent re-put.
#[allow(clippy::too_many_arguments)]
fn write_commit_tx(
    db: &mut Db,
    session: &VaultSession,
    ref_name: &str,
    parent: Option<Hash>,
    blueprint: &Blueprint,
    intent: Intent,
    timestamp: i64,
    policy: SameTreePolicy,
) -> Result<CommitOutcome> {
    if policy == SameTreePolicy::Skip && is_same_tree(db, parent, &blueprint.root)? {
        return Ok(CommitOutcome {
            hash: parent.expect("is_same_tree is false without a parent"),
            committed: false,
        });
    }
    let (row, hash) =
        author_commit_row(session, ref_name, parent, blueprint.root, intent, timestamp)?;

    db.with_tx(|conn| {
        for (tree_hash, entries) in &blueprint.trees {
            put_tree(conn, tree_hash, entries)?;
        }
        put_commit(conn, &row)?;
        // CAS the ref against the tip we read as `parent`: the write lands only
        // if no concurrent writer advanced this chain since, else the whole
        // commit tx rolls back. Uncontended (the single-writer device chain)
        // this is identical to a plain advance; it guards a shared chain race.
        set_ref_cas(conn, ref_name, parent.as_ref(), &hash)?;
        Ok(())
    })?;

    Ok(CommitOutcome { hash, committed: true })
}

/// Transactional re-author writer: insert the commit row + CAS the ref, with
/// **no** tree insertion — `root_tree` (and its whole object closure) is
/// already present in the store. The m5e `shared_pull` apply: a peer's
/// shared-chain tree, fetched content-addressed into this store, is
/// re-committed as this device's own commit over the local chain tip.
///
/// Carries the same [`is_same_tree`] guard as [`write_commit_tx`]: re-authoring
/// a tree the local tip already holds would mint an empty commit, so it returns
/// the parent as a no-op instead.
fn write_reauthor_tx(
    db: &mut Db,
    session: &VaultSession,
    ref_name: &str,
    parent: Option<Hash>,
    root_tree: Hash,
    intent: Intent,
    timestamp: i64,
) -> Result<CommitOutcome> {
    if is_same_tree(db, parent, &root_tree)? {
        return Ok(CommitOutcome {
            hash: parent.expect("is_same_tree is false without a parent"),
            committed: false,
        });
    }
    let (row, hash) = author_commit_row(session, ref_name, parent, root_tree, intent, timestamp)?;

    db.with_tx(|conn| {
        put_commit(conn, &row)?;
        // Same per-ref CAS guard as `write_commit_tx`: the apply lands only if
        // the local chain tip is still `parent`, else it rolls back — a
        // concurrent local advance re-opens the fast-forward decision upstream.
        set_ref_cas(conn, ref_name, parent.as_ref(), &hash)?;
        Ok(())
    })?;

    Ok(CommitOutcome { hash, committed: true })
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn local_device_label() -> String {
    hostname::get()
        .ok()
        .and_then(|s| s.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}
