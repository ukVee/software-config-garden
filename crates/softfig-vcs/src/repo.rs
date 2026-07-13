//! High-level Repo type: open / init / commit / log.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use softfig_store::{
    put_commit, put_tree, set_ref, CommitRow, Db, Hash, ObjectStore, StorePaths,
};
use softfig_vault::{Vault, VaultSession};

use crate::chain::ChainRegistry;
use crate::commit::CanonicalCommit;
use crate::error::{CoreError, Result};
use crate::intent::Intent;
use crate::tree::{self, BlobEncryptor, Blueprint, LayerAEncryptor};
use crate::walk::{self, WalkSnapshot};

pub const TIP_REF: &str = "tip";

/// Subscriber called after a successful commit advances a chain's ref. It
/// receives the `ref_name` that moved and the new tip hash, so a consumer can
/// invalidate **per chain** (M5c slice 002 union mount): the device chain
/// (`TIP_REF`) and each shared chain fire the same slot, distinguished by
/// `ref_name`. M2a wires the FUSE driver here so it can drop its stat cache and
/// broadcast inval_inode notifications. One slot per repo for v1; if a second
/// consumer ever shows up (sync push?), promote to a Vec.
pub type TipChangedCallback = Box<dyn Fn(&str, &Hash) + Send + Sync>;

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
        let commit_hash = write_commit_tx(
            &mut db,
            session,
            TIP_REF,
            None,
            &blueprint,
            intent,
            now,
        )?;

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
        let commit_hash = write_commit_tx(&mut db, session, TIP_REF, None, &blueprint, intent, now)?;

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
        F: Fn(&str, &Hash) + Send + Sync + 'static,
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
    /// a new commit whose parent is the current tip. Returns the new commit
    /// hash.
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
        let snapshot = walk::walk(&self.garden_root)?;
        self.commit_snapshot(session, snapshot, intent)
    }

    /// Commit a pre-built working-tree `snapshot` against the current tip,
    /// returning the new commit hash. Identical to [`Repo::commit_workdir`]
    /// except the caller supplies the tree rather than walking
    /// `garden_root` — letting the FUSE daemon commit from its in-memory
    /// state without self-reading the mount it serves.
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
    /// driver can recompose the union view and invalidate per chain.
    pub fn commit_snapshot_to(
        &mut self,
        ref_name: &str,
        session: &VaultSession,
        snapshot: WalkSnapshot,
        intent: Intent,
    ) -> Result<Hash> {
        let parent = self.tip_of(ref_name)?;
        let default_enc = LayerAEncryptor;
        let encryptor: &dyn BlobEncryptor = match self.blob_encryptor.as_ref() {
            Some(enc) => enc.as_ref(),
            None => &default_enc,
        };
        let blueprint = tree::build_with(&self.objects, session, &snapshot.root, encryptor, ref_name)?;
        let now = unix_seconds();
        let hash = write_commit_tx(&mut self.db, session, ref_name, parent, &blueprint, intent, now)?;
        if let Some(cb) = &self.tip_changed {
            cb(ref_name, &hash);
        }
        Ok(hash)
    }

    /// The tips of every **registered** chain in `registry` (device + all shared,
    /// enabled or not), skipping any chain with no commits yet. This is gc's
    /// retention set: a disabled chain's tip is included so its exclusive blobs
    /// survive `disable -> gc -> re-enable` — enablement is a mount concern, not a
    /// retention concern (m5c finding 7). Deriving it from the registry keeps gc
    /// safe by construction: no chain's objects are collected because another
    /// chain was gc'd.
    pub fn live_tips(&self, registry: &ChainRegistry) -> Result<Vec<Hash>> {
        let mut tips = Vec::new();
        for chain in registry.all_chains() {
            if let Some(t) = self.tip_of(&chain.ref_name)? {
                tips.push(t);
            }
        }
        Ok(tips)
    }

    /// Per-chain fsck over the chain tracked by `ref_name` (see
    /// [`crate::fsck::run_chain`]).
    pub fn fsck_chain(&self, ref_name: &str) -> Result<crate::fsck::FsckReport> {
        crate::fsck::run_chain(&self.db, &self.objects, self.tip_of(ref_name)?)
    }

    /// Collect loose objects unreachable from any **registered** chain in
    /// `registry` (see [`crate::gc::gc`]). Safe across chains: the retained set is
    /// the union of every registered chain's reachable blobs — including disabled
    /// chains, whose blobs must not be collected (m5c finding 7).
    pub fn gc(&self, registry: &ChainRegistry) -> Result<crate::gc::GcReport> {
        let tips = self.live_tips(registry)?;
        crate::gc::gc(&self.db, &self.objects, &tips)
    }
}

/// Transactional commit writer: insert all new tree rows + the commit
/// row + bump tip, all in one sqlite tx.
fn write_commit_tx(
    db: &mut Db,
    session: &VaultSession,
    ref_name: &str,
    parent: Option<Hash>,
    blueprint: &Blueprint,
    intent: Intent,
    timestamp: i64,
) -> Result<Hash> {
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

    let canon = CanonicalCommit {
        parent,
        root_tree: blueprint.root,
        author_device: &author_device,
        author_pubkey,
        timestamp,
        intent: &intent_name,
        payload: &payload_canon_value,
        master_key_id,
    };
    let hash = canon.hash()?;
    let signature_bytes = session.sign(hash.as_bytes()).to_bytes();

    let row = CommitRow {
        hash,
        parent,
        root_tree: blueprint.root,
        author_device,
        author_pubkey,
        timestamp,
        intent: intent_name,
        payload: payload_canon_str,
        master_key_id,
        signature: signature_bytes,
    };

    db.with_tx(|conn| {
        for (tree_hash, entries) in &blueprint.trees {
            put_tree(conn, tree_hash, entries)?;
        }
        put_commit(conn, &row)?;
        set_ref(conn, ref_name, &hash)?;
        Ok(())
    })?;

    Ok(hash)
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
