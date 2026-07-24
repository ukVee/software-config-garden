//! M2b Layer B integration: `sealed-paths.toml` matcher, daemon-side
//! pre-commit encryption hook, FUSE [`SealedQuery`] implementation, and
//! the auto-migration walk.
//!
//! Per the locked picks in `meta/spec-vault.md` "M2b implementation
//! slice":
//!
//! * The matcher loads `<state_dir>/.softfig/vault/sealed-paths.toml`
//!   (a Layer A file — never visible through FUSE) and applies union
//!   glob semantics over the entries.
//! * The hook is a [`softfig_vcs::BlobEncryptor`] installed on the
//!   `Repo` at unlock time. For each file's path, it checks the matcher
//!   and routes sealed paths through `VaultSession::encrypt_layer_b`;
//!   the rest stay Layer A.
//! * The same matcher is exposed as [`softfig_fuse::SealedQuery`] so
//!   the FUSE read path can project the `[sealed:<path>]\n` placeholder
//!   instead of decrypted Layer A bytes.
//! * The auto-migration walk runs after a `schema_change` commit that
//!   touched `sealed-paths.toml`: it walks `garden_root`, finds newly
//!   matching tracked files, and triggers a fresh `commit_workdir` with
//!   a `vault_seal` intent.
//!
//! M2c (see [`regions`]) extends the read- and write-path here with
//! inline `<vault id="…">…</vault>` parsing + region-keyed encryption.

pub mod regions;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use softfig_vcs::{BlobEncryptor, Intent, Repo, WalkSnapshot};
use softfig_fuse::SealedQuery;
use softfig_store::{Hash, TreeEntryKind};
use softfig_vault::VaultSession;
use walkdir::WalkDir;

use self::regions::RegionParseError;
use crate::daemon::{KeeperError, Result};

/// Repo-relative location of the sealed-paths file (lives inside
/// `.softfig/vault/` next to the rest of the vault state).
pub const SEALED_PATHS_REL: &str = ".softfig/vault/sealed-paths.toml";

/// Watcher / daemon sub-rule trigger: a `schema_change` whose `kind`
/// equals this string means "reload SealedPaths + run auto-migration".
pub const SEALED_PATHS_CHANGED_KIND: &str = "sealed_paths_changed";

/// Repo-relative path the watcher classifier inspects to detect a
/// sealed-paths edit (relative to garden root; matches what the
/// daemon's FUSE writes report).
pub const SEALED_PATHS_PATH: &str = SEALED_PATHS_REL;

/// On-disk schema for `sealed-paths.toml`. v1 is a bare array of glob
/// strings; structured entries (per-entry overrides, negation) come in
/// v2 if needed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedPathsFile {
    #[serde(default)]
    pub paths: Vec<String>,
}

impl SealedPathsFile {
    pub fn load(state_dir: &Path) -> Result<Self> {
        let path = sealed_paths_file_path(state_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)?;
        toml::from_str(&raw)
            .map_err(|e| KeeperError::Other(format!("parse {}: {e}", path.display())))
    }

    pub fn store(&self, state_dir: &Path) -> Result<()> {
        let path = sealed_paths_file_path(state_dir);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(self)
            .map_err(|e| KeeperError::Other(format!("encode sealed-paths.toml: {e}")))?;
        fs::write(&path, raw)?;
        Ok(())
    }
}

pub fn sealed_paths_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SEALED_PATHS_REL)
}

/// Compiled glob set + a snapshot of the raw glob strings (for
/// `softfig vault list-sealed`).
#[derive(Debug)]
pub struct SealedPaths {
    set: GlobSet,
    raw: Vec<String>,
}

impl SealedPaths {
    pub fn empty() -> Self {
        Self {
            set: GlobSet::empty(),
            raw: Vec::new(),
        }
    }

    /// Compile the glob set. Malformed globs surface as `KeeperError::Other`
    /// — the daemon's caller (the precommit hook or the explicit `vault seal`
    /// IPC verb) chooses how to react.
    pub fn compile(globs: &[String]) -> Result<Self> {
        let mut b = GlobSetBuilder::new();
        for g in globs {
            let glob = Glob::new(g)
                .map_err(|e| KeeperError::Other(format!("invalid glob {g:?}: {e}")))?;
            b.add(glob);
        }
        let set = b
            .build()
            .map_err(|e| KeeperError::Other(format!("globset build: {e}")))?;
        Ok(Self {
            set,
            raw: globs.to_vec(),
        })
    }

    pub fn load(state_dir: &Path) -> Result<Self> {
        let file = SealedPathsFile::load(state_dir)?;
        Self::compile(&file.paths)
    }

    pub fn is_sealed(&self, repo_relative: &str) -> bool {
        if self.raw.is_empty() {
            return false;
        }
        self.set.is_match(repo_relative)
    }

    pub fn globs(&self) -> &[String] {
        &self.raw
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

/// M2c — snapshot of the prior tip's plaintext, indexed by repo-relative
/// path. Populated by the daemon just before each `commit_workdir` so
/// the write-path region encoder can re-embed unchanged `[encrypted]`
/// placeholders byte-identically. Cleared after the commit lands.
#[derive(Debug, Default)]
pub struct PriorTipSnapshot {
    pub plaintext_by_path: HashMap<String, Vec<u8>>,
}

/// Daemon-side Layer B integration: holds the active `SealedPaths` and
/// implements both [`BlobEncryptor`] (for commit-time encryption
/// routing) and [`SealedQuery`] (for the FUSE read-path placeholder).
///
/// Thread-safe — the watcher's `sealed_paths_changed` rule calls
/// [`LayerBHook::reload`] from a different thread than the one running
/// commits.
///
/// M2c extension: the hook also carries an optional [`VaultSession`]
/// (set at unlock so the read-path region redactor can trial-decrypt
/// body candidates without going through `BlobEncryptor::encrypt`) and
/// an optional [`PriorTipSnapshot`] (set just before every
/// `commit_workdir` so placeholder bodies re-embed prior ciphertext).
#[derive(Debug)]
pub struct LayerBHook {
    sealed: RwLock<Arc<SealedPaths>>,
    /// M2c — set at unlock time; used by `redact_regions` to
    /// trial-decrypt inline region bodies. `None` until the daemon
    /// transitions to Unlocked.
    session: RwLock<Option<Arc<VaultSession>>>,
    /// M2c — set just before every `commit_workdir`; consulted by the
    /// write-path region encoder when a Plaintext body equals the
    /// reserved `[encrypted]` placeholder.
    prior_tip: RwLock<Option<Arc<PriorTipSnapshot>>>,
    /// M5d slice 002 — `ref_name` → `(key_id, mount_path)` for every
    /// *keyed* shared chain, refreshed wherever the chain registry is
    /// rebuilt (unlock, subtree add/remove/toggle, ceremony persist). A
    /// shared ref absent here is unkeyed (pre-ceremony) and refuses content
    /// until the ceremony fills the membership row (m5f slice 001,
    /// key-before-content; it replaced the m5c "stays on `M`" status
    /// quo). The mount path rides along because a shared chain's
    /// snapshot paths are chain-relative (`split_snapshot` strips the mount
    /// prefix): the router re-prefixes them so sealed-glob matching and the
    /// Layer-B path salt use the same garden-relative string the read side
    /// passes to `decrypt_tracked_blob`.
    shared_keys: RwLock<HashMap<String, (String, String)>>,
    /// M5d slice 016 (NONCE-2) — the set of shared-chain refs whose **committed
    /// membership row carries a `key_id`**, i.e. the chains that MUST seal under
    /// `S`. Refreshed from the same [`softfig_vcs::ChainRegistry`] as
    /// `shared_keys`, but consulted independently: it is the authoritative
    /// "keyed-ness" derived from committed state, so `encrypt_for_ref` can tell a
    /// *keyed* shared chain that is missing from `shared_keys` (a stale / not-yet-
    /// re-primed router) from a *genuinely unkeyed* (pre-ceremony) one. The former
    /// fails closed rather than silently writing a non-convergent, member-
    /// unreadable `M` blob onto a keyed shared chain.
    keyed_committed_refs: RwLock<Arc<HashSet<String>>>,
}

impl LayerBHook {
    pub fn new(initial: SealedPaths) -> Self {
        Self {
            sealed: RwLock::new(Arc::new(initial)),
            session: RwLock::new(None),
            prior_tip: RwLock::new(None),
            shared_keys: RwLock::new(HashMap::new()),
            keyed_committed_refs: RwLock::new(Arc::new(HashSet::new())),
        }
    }

    pub fn empty() -> Self {
        Self::new(SealedPaths::empty())
    }

    pub fn load(state_dir: &Path) -> Result<Self> {
        Ok(Self::new(SealedPaths::load(state_dir)?))
    }

    pub fn reload(&self, state_dir: &Path) -> Result<()> {
        let next = SealedPaths::load(state_dir)?;
        *self.sealed.write().unwrap() = Arc::new(next);
        Ok(())
    }

    pub fn replace(&self, sealed: SealedPaths) {
        *self.sealed.write().unwrap() = Arc::new(sealed);
    }

    pub fn snapshot(&self) -> Arc<SealedPaths> {
        self.sealed.read().unwrap().clone()
    }

    /// M2c — install the daemon's unlocked session so the read-path
    /// region redactor can trial-decrypt body candidates. Called once
    /// per unlock; `None` clears the slot at shutdown.
    pub fn set_session(&self, session: Option<Arc<VaultSession>>) {
        *self.session.write().unwrap() = session;
    }

    pub fn session(&self) -> Option<Arc<VaultSession>> {
        self.session.read().unwrap().clone()
    }

    /// M2c (020 slice 003) — the ids of the file's *sealed* inline
    /// `<vault id="…">` regions: those the read view projects as `[encrypted]`
    /// and that `vault_reveal --id` can decrypt (i.e. [`RegionKind::Ciphertext`]
    /// spans). Computed with the authoritative region grammar
    /// ([`regions::parse`]) over the decrypted Layer-A `content`, so a frontend
    /// reads the same ids the daemon sealed instead of re-deriving them from the
    /// projected prose. Empty for whole-file-sealed, pre-unlock, malformed, or
    /// region-free files. Read-only companion to [`Self::redact_regions`];
    /// deliberately NOT folded into it so the FUSE read hot path skips this
    /// allocation.
    pub fn region_ids(&self, repo_relative: &str, content: &[u8]) -> Vec<String> {
        if self.snapshot().is_sealed(repo_relative) {
            return Vec::new();
        }
        let Some(session) = self.session() else {
            return Vec::new();
        };
        let parser = regions::parser_for(repo_relative);
        let Ok(spans) = regions::parse(parser, content, &session, repo_relative) else {
            return Vec::new();
        };
        spans
            .into_iter()
            .filter(|s| s.kind == regions::RegionKind::Ciphertext)
            .map(|s| s.id)
            .collect()
    }

    /// M2c — install the prior-tip plaintext snapshot built by
    /// [`build_prior_tip_snapshot`]. Daemon calls this before
    /// `commit_workdir` and clears it after.
    pub fn install_prior_tip(&self, snap: PriorTipSnapshot) {
        *self.prior_tip.write().unwrap() = Some(Arc::new(snap));
    }

    pub fn clear_prior_tip(&self) {
        *self.prior_tip.write().unwrap() = None;
    }

    fn prior_tip_snapshot(&self) -> Option<Arc<PriorTipSnapshot>> {
        self.prior_tip.read().unwrap().clone()
    }

    /// M5d slice 002 — sync the shared-chain key routing with a freshly
    /// derived [`softfig_vcs::ChainRegistry`]. Every *keyed* shared chain
    /// (enabled or not — key routing must never depend on the local mount
    /// toggle) maps its ref to its `key_id` + mount path; unkeyed chains
    /// are absent.
    pub fn set_shared_chain_keys(&self, registry: &softfig_vcs::ChainRegistry) {
        let map: HashMap<String, (String, String)> = registry
            .all_chains()
            .filter(|c| c.kind == softfig_vcs::ChainKind::Shared)
            .filter_map(|c| {
                let key_id = c.key_id.clone()?;
                let mount = c
                    .mount_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                Some((c.ref_name.clone(), (key_id, mount)))
            })
            .collect();
        // M5d slice 016 (NONCE-2): the authoritative keyed-ness set — every
        // shared chain the committed membership says carries a `key_id`. Derived
        // from the same registry so `encrypt_for_ref` never has to guess "unkeyed"
        // from a missing router entry.
        let keyed: HashSet<String> = map.keys().cloned().collect();
        *self.shared_keys.write().unwrap() = map;
        *self.keyed_committed_refs.write().unwrap() = Arc::new(keyed);
    }

    /// The `(key_id, mount_path)` a shared chain's blobs must seal under,
    /// or `None` for an unkeyed (pre-ceremony) chain.
    pub fn shared_key_for(&self, ref_name: &str) -> Option<(String, String)> {
        self.shared_keys.read().unwrap().get(ref_name).cloned()
    }

    /// M5d slice 016 (NONCE-2) — does the committed membership say this shared
    /// ref is keyed (must seal under `S`)? Consulted by [`Self::encrypt_for_ref`]
    /// to distinguish a keyed chain whose router entry is missing (fail closed,
    /// re-queued for a re-primed flush) from a genuinely unkeyed pre-ceremony
    /// chain (refused outright — m5f slice 001 key-before-content).
    pub fn ref_is_keyed_committed(&self, ref_name: &str) -> bool {
        self.keyed_committed_refs.read().unwrap().contains(ref_name)
    }

    /// Test-only: install an inconsistent state (a ref marked keyed in committed
    /// membership but absent from the `S` router) to exercise the NONCE-2 fail-
    /// closed guard directly — the shape a future commit path that advances a
    /// shared ref without re-priming the router would produce.
    #[cfg(test)]
    pub(crate) fn force_keyed_committed_ref(&self, ref_name: &str) {
        let mut set = HashSet::clone(&self.keyed_committed_refs.read().unwrap());
        set.insert(ref_name.to_string());
        *self.keyed_committed_refs.write().unwrap() = Arc::new(set);
    }
}

impl BlobEncryptor for LayerBHook {
    fn encrypt(
        &self,
        path: &str,
        content: &[u8],
        session: &VaultSession,
    ) -> softfig_vcs::Result<Vec<u8>> {
        let sealed_snapshot = self.snapshot();
        if sealed_snapshot.is_sealed(path) {
            // Layer B whole-file path: derive per-file subkey, encrypt
            // convergent under XChaCha20-Poly1305. The blob_file starts
            // with the 0xFF marker so the daemon's FUSE-read path and
            // any future fsck-aware tool can distinguish from Layer A
            // bytes. M2c inline-tag handling is skipped — whole-file
            // seal supersedes per-region encryption.
            let ct = session
                .encrypt_layer_b(path, content)
                .map_err(softfig_vcs::CoreError::Vault)?;
            return Ok(ct);
        }
        // M2c — inline `<vault>` region path. Parse → on error, reject
        // the commit (fail-closed). On success: substitute placeholders
        // / encrypt fresh plaintext, then run the result through Layer
        // A as a single blob.
        let parser = regions::parser_for(path);
        let spans = match regions::parse(parser, content, session, path) {
            Ok(spans) => spans,
            Err(e) => {
                return Err(softfig_vcs::CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed vault tag in {path}: {e}"),
                )));
            }
        };
        if spans.is_empty() {
            // No tags — straight Layer A, behavior identical to M2b.
            return Ok(session.encrypt_blob(content)?);
        }
        let prior = self.prior_tip_snapshot();
        let prior_bytes = prior
            .as_ref()
            .and_then(|s| s.plaintext_by_path.get(path).cloned());
        let prior_spans: Vec<_> = match prior_bytes.as_deref() {
            Some(prior) => regions::parse(parser, prior, session, path)
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let post = regions::apply_write_path(
            content,
            &spans,
            path,
            session,
            prior_bytes.as_deref(),
            &prior_spans,
        )
        .map_err(|e: RegionParseError| {
            softfig_vcs::CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("vault region rewrite for {path}: {e}"),
            ))
        })?;
        Ok(session.encrypt_blob(&post)?)
    }

    /// M5d slice 002 — per-chain key routing. The device chain keeps the
    /// full M path above; a *keyed* shared chain seals everything under its
    /// `S` (spec-sync: convergent across members) and **fails closed** when
    /// the vault doesn't hold that `S` — an M fallback there would commit
    /// member-unreadable, non-convergent blobs onto a keyed chain. An
    /// *unkeyed* shared chain (membership row's `key_id` still empty,
    /// pre-ceremony) **refuses content outright** (m5f slice 001,
    /// key-before-content — this replaced the m5c "unkeyed → M" status quo):
    /// an M-sealed blob on a shared chain is per-device, so no other member
    /// could ever read it, and neither establishment nor the rotation heal
    /// converts M→S (`migrate-into-share` is the only M→S path). The FUSE
    /// write path and the action-verb staging already refuse these up front;
    /// this is the commit-path backstop so NO route silently M-commits onto a
    /// shared chain. The flush treats the error as a failed ref and re-queues
    /// with capped backoff; once the ceremony fills the row, retained overlay
    /// content lands S-keyed from birth.
    fn encrypt_for_ref(
        &self,
        ref_name: &str,
        path: &str,
        content: &[u8],
        session: &VaultSession,
    ) -> softfig_vcs::Result<Vec<u8>> {
        if ref_name == softfig_vcs::TIP_REF {
            return self.encrypt(path, content, session);
        }
        let Some((key_id, mount)) = self.shared_key_for(ref_name) else {
            // No `S` router entry for this ref. M5d slice 016 (NONCE-2): decide M
            // vs fail-closed from the *committed* keyed-ness, not the absence of a
            // cache entry. A shared chain the committed membership marks keyed but
            // that is missing from the router means the router is stale / was not
            // re-primed for this commit — falling back to `M` here would seal a
            // non-convergent, member-unreadable blob onto a keyed shared chain
            // (an isolation + convergence break). Refuse: the flush treats the
            // error as a failed ref and re-queues it, so a subsequent flush (with
            // the router re-primed from committed state) seals it under `S`.
            if self.ref_is_keyed_committed(ref_name) {
                return Err(softfig_vcs::CoreError::Io(std::io::Error::other(format!(
                    "shared ref {ref_name} is keyed in committed membership but the key \
                     router holds no S for it; refusing to seal under the device key M \
                     (re-prime the chain registry / recover S)"
                ))));
            }
            // M5f slice 001 (key-before-content): a genuinely unkeyed
            // (pre-ceremony) shared chain refuses content too — the m5c
            // "unkeyed → M" fallback sealed pre-ceremony writes under the
            // per-device M, unreadable to every other member and never
            // converted by establishment or the rotation heal, so the chain
            // could not converge. Only the device chain (`TIP_REF`, handled
            // above) may seal under M.
            return Err(softfig_vcs::CoreError::Io(std::io::Error::other(format!(
                "shared ref {ref_name} has no established key yet (key-before-content); \
                 refusing to seal content under the device key M — run/accept the \
                 share's key ceremony first (existing device content moves in via \
                 migrate-into-share once keyed)"
            ))));
        };
        // `path` is chain-relative (split_snapshot strips the mount prefix);
        // re-prefix it so glob matching + the Layer-B path salt line up with
        // the garden-relative strings the read side uses.
        let garden_path = if mount.is_empty() {
            path.to_string()
        } else {
            format!("{mount}/{path}")
        };
        if self.snapshot().is_sealed(&garden_path) {
            // A sealed-glob match inside a shared subtree derives its
            // whole-file subkey from S, not M (spec-vault), so the seal
            // stays readable to exactly the chain's members.
            return session
                .encrypt_shared_layer_b(&key_id, &garden_path, content)
                .map_err(softfig_vcs::CoreError::Vault);
        }
        // Inline `<vault>` regions inside shared mounts are gated until the
        // shared-chain commit path gains PriorTipGuard coverage (m5c-review
        // precondition 3): refuse rather than seal them wrong or commit the
        // secret-intent text as ordinary content.
        let parser = regions::parser_for(&garden_path);
        match regions::parse(parser, content, session, &garden_path) {
            Ok(spans) if spans.is_empty() => {}
            Ok(_) => {
                return Err(softfig_vcs::CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "inline <vault> regions are not supported inside a shared subtree yet \
                         (remove the tag from {garden_path} or keep the secret on the device chain)"
                    ),
                )));
            }
            Err(e) => {
                return Err(softfig_vcs::CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed vault tag in {garden_path}: {e}"),
                )));
            }
        }
        session
            .encrypt_shared_blob(&key_id, content)
            .map_err(softfig_vcs::CoreError::Vault)
    }
}

impl SealedQuery for LayerBHook {
    fn is_sealed(&self, repo_relative: &str) -> bool {
        self.snapshot().is_sealed(repo_relative)
    }

    fn redact_regions(&self, repo_relative: &str, content: Vec<u8>) -> Vec<u8> {
        // Whole-file seal is handled by the FUSE driver's
        // `[sealed:<path>]\n` upstream path — short-circuit so we don't
        // try to parse already-projected placeholders.
        if self.snapshot().is_sealed(repo_relative) {
            return content;
        }
        let Some(session) = self.session() else {
            // No session installed yet (pre-unlock); pass through.
            return content;
        };
        let parser = regions::parser_for(repo_relative);
        let spans = match regions::parse(parser, &content, &session, repo_relative) {
            Ok(spans) => spans,
            Err(_) => return regions::malformed_placeholder(repo_relative),
        };
        if spans.is_empty() {
            return content;
        }
        regions::render_read_view(content, &spans)
    }
}

/// M2c — walk the repo's current tip tree and return a snapshot of
/// every blob's plaintext (decrypted under whichever layer it was
/// originally encrypted with). Used by the daemon to populate
/// [`LayerBHook::install_prior_tip`] before each `commit_workdir` so
/// the write-path region encoder can re-embed unchanged placeholders
/// byte-identically.
///
/// O(N files) — fine for the typical garden size (~hundreds of files);
/// lazy on-demand lookup is a future optimization tracked under the
/// region-cache eviction open question.
pub fn build_prior_tip_snapshot(
    repo: &Repo,
    session: &VaultSession,
) -> Result<PriorTipSnapshot> {
    let mut snap = PriorTipSnapshot::default();
    let Some(tip) = repo.tip()? else {
        return Ok(snap);
    };
    let row = repo
        .db()
        .get_commit(&tip)
        .map_err(KeeperError::Store)?;
    walk_tree_into(repo, session, &row.root_tree, "", &mut snap)?;
    Ok(snap)
}

fn walk_tree_into(
    repo: &Repo,
    session: &VaultSession,
    tree: &Hash,
    prefix: &str,
    snap: &mut PriorTipSnapshot,
) -> Result<()> {
    let entries = repo.db().get_tree(tree).map_err(KeeperError::Store)?;
    for e in entries {
        let child_path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        match e.kind {
            TreeEntryKind::Blob => {
                let cipher = repo.objects().get(&e.target).map_err(KeeperError::Store)?;
                let plain = session
                    .decrypt_tracked_blob(&child_path, &cipher)
                    .map_err(KeeperError::Vault)?;
                snap.plaintext_by_path.insert(child_path, plain);
            }
            TreeEntryKind::Tree => {
                walk_tree_into(repo, session, &e.target, &child_path, snap)?;
            }
        }
    }
    Ok(())
}

/// M2c — RAII guard that installs a prior-tip snapshot on a
/// [`LayerBHook`] and clears it on drop. Use this around every
/// `repo.commit_workdir(...)` call site so placeholder preservation
/// has fresh prior-tip context for each commit.
#[derive(Debug)]
pub struct PriorTipGuard<'a> {
    hook: &'a LayerBHook,
}

impl<'a> PriorTipGuard<'a> {
    pub fn install(hook: &'a LayerBHook, repo: &Repo, session: &VaultSession) -> Result<Self> {
        let snap = build_prior_tip_snapshot(repo, session)?;
        hook.install_prior_tip(snap);
        Ok(Self { hook })
    }
}

impl Drop for PriorTipGuard<'_> {
    fn drop(&mut self) {
        self.hook.clear_prior_tip();
    }
}

/// Convenience: snapshot prior tip → commit → clear, in one call.
pub fn commit_with_regions(
    hook: &LayerBHook,
    repo: &mut Repo,
    session: &VaultSession,
    intent: Intent,
) -> Result<Hash> {
    let _guard = PriorTipGuard::install(hook, repo, session)?;
    let hash = repo.commit_workdir(session, intent).map_err(KeeperError::Core)?;
    Ok(hash)
}

/// M2c — watcher classifier sub-rule. For each repo-relative path in
/// `paths`, read its **current working-tree plaintext from `current`**
/// (the same in-memory snapshot the commit will encrypt) and look for
/// inline `<vault id="…">` regions whose ids are present now but absent
/// from the same path's prior-tip plaintext (`prior_snap`).
///
/// Sourcing the current bytes from `current` rather than
/// `fs::read(garden_root.join(rel))` is load-bearing: in FUSE mode the
/// garden root is the mount this daemon serves, so reading it back —
/// under the daemon's `inner` lock, on the flush path — is the
/// 2026-06-21 mount-read deadlock class, and the bytes the kernel
/// returns are the reader-*redacted* view (`[encrypted]`/`[sealed:…]`),
/// not the plaintext the commit encrypts. The snapshot carries the true
/// plaintext (`workdir_snapshot` decrypts tip blobs; the overlay holds
/// raw editor writes), so a new id inside a file that *also* has a
/// sealed region is detected against the truth, never a projection.
///
/// Returns a single batched `vault_seal` [`Intent`] covering every
/// affected path + every newly-introduced id when at least one new
/// id is found. Returns `None` when no path introduces a new id —
/// the watcher then falls through to the original `manual_edit`.
///
/// Edits to *existing* ids (same id, ciphertext body changed) do NOT
/// fire: that case is normal content churn — `vault_reveal` owns
/// audit for plaintext exposure, not re-encryption.
pub fn promote_manual_edit_for_new_ids(
    paths: &[String],
    current: &WalkSnapshot,
    session: &VaultSession,
    prior_snap: &PriorTipSnapshot,
) -> Option<Intent> {
    use std::collections::BTreeSet;

    let mut affected_paths: Vec<String> = Vec::new();
    let mut new_ids: BTreeSet<String> = BTreeSet::new();

    for rel in paths {
        let Some(content) = current.file_content(Path::new(rel)) else {
            continue;
        };
        let parser = regions::parser_for(rel);
        let current_spans = regions::parse(parser, content, session, rel).ok()?;
        if current_spans.is_empty() {
            continue;
        }
        let current_ids: BTreeSet<String> =
            current_spans.iter().map(|s| s.id.clone()).collect();
        let prior_ids: BTreeSet<String> = match prior_snap.plaintext_by_path.get(rel) {
            Some(prior) => regions::parse(parser, prior, session, rel)
                .ok()
                .map(|spans| spans.iter().map(|s| s.id.clone()).collect())
                .unwrap_or_default(),
            None => BTreeSet::new(),
        };
        let added: Vec<String> = current_ids.difference(&prior_ids).cloned().collect();
        if !added.is_empty() {
            affected_paths.push(rel.clone());
            new_ids.extend(added);
        }
    }

    if affected_paths.is_empty() {
        return None;
    }
    let ids_vec: Vec<String> = new_ids.into_iter().collect();
    let intent = Intent::new(
        "vault_seal",
        serde_json::json!({
            "paths": affected_paths,
            "ids": ids_vec,
            "reason": "inline vault tags introduced",
        }),
    )
    .ok()?;
    Some(intent)
}

/// Walk the working tree (rooted at `garden_root`) and return the list
/// of tracked, repo-relative files matched by `sealed`. Used by the
/// auto-migration step and by `softfig vault list-sealed`.
pub fn enumerate_matching(garden_root: &Path, sealed: &SealedPaths) -> Vec<String> {
    if sealed.is_empty() {
        return Vec::new();
    }
    let mut out = BTreeSet::new();
    // Same exclusion set the committer uses (built-ins + `.softfigignore`),
    // loaded once for this scan from the garden root.
    let ignore = softfig_vcs::ignore::Ignore::load(garden_root);
    for entry in WalkDir::new(garden_root)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            e.path()
                .strip_prefix(garden_root)
                .map(|rel| !ignore.is_ignored(rel))
                .unwrap_or(true)
        })
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(rel) = entry.path().strip_prefix(garden_root) else {
            continue;
        };
        let Some(rel_str) = rel.to_str() else { continue };
        // Normalize to forward slashes (already the case on Linux, but
        // be explicit).
        let rel_str = rel_str.replace('\\', "/");
        if sealed.is_sealed(&rel_str) {
            out.insert(rel_str);
        }
    }
    out.into_iter().collect()
}

/// In-memory variant of [`enumerate_matching`]: filter a pre-collected list of
/// repo-relative working-tree paths (e.g. from the FUSE driver's in-memory
/// `live_repo_paths`) by the sealed matcher. Lets a FUSE-mode daemon enumerate
/// sealed files without `WalkDir`-walking the mount it serves under `inner` (the
/// 2026-06-21 commit-path deadlock). Ignore filtering is the caller's job —
/// `live_repo_paths` already applies the same exclusion set `enumerate_matching`
/// loads from disk.
pub fn enumerate_matching_from_paths(paths: &[String], sealed: &SealedPaths) -> Vec<String> {
    if sealed.is_empty() {
        return Vec::new();
    }
    let mut out = BTreeSet::new();
    for rel in paths {
        let rel = rel.replace('\\', "/");
        if sealed.is_sealed(&rel) {
            out.insert(rel);
        }
    }
    out.into_iter().collect()
}

/// Append a glob to `sealed-paths.toml` (creating the file if absent).
/// Returns true if the glob was actually added (false = already present
/// — no-op).
pub fn append_glob(state_dir: &Path, glob: &str) -> Result<bool> {
    let mut file = SealedPathsFile::load(state_dir)?;
    if file.paths.iter().any(|g| g == glob) {
        return Ok(false);
    }
    file.paths.push(glob.to_string());
    file.store(state_dir)?;
    Ok(true)
}

/// Remove a glob from `sealed-paths.toml`. Returns true if it was
/// present (false = no-op).
pub fn remove_glob(state_dir: &Path, glob: &str) -> Result<bool> {
    let mut file = SealedPathsFile::load(state_dir)?;
    let before = file.paths.len();
    file.paths.retain(|g| g != glob);
    if file.paths.len() == before {
        return Ok(false);
    }
    file.store(state_dir)?;
    Ok(true)
}

/// Compose a `schema_change` intent for a sealed-paths.toml edit.
pub fn schema_change_intent(decision_slug: &str, sub_kind: &str) -> softfig_vcs::Result<Intent> {
    Intent::new(
        "schema_change",
        serde_json::json!({
            "decision_slug": decision_slug,
            "paths_changed": [SEALED_PATHS_REL],
            "kind": sub_kind,
        }),
    )
}

/// Compose a `vault_seal` intent for the auto-migration commit.
pub fn vault_seal_intent(paths: &[String], reason: &str) -> softfig_vcs::Result<Intent> {
    Intent::new(
        "vault_seal",
        serde_json::json!({
            "paths": paths,
            "reason": reason,
        }),
    )
}

/// Compose a `vault_reveal` intent (audit-only — no plaintext, no hash).
///
/// M2c — when `id` is `Some(name)` the audit payload gains an `"id"`
/// field; when `None`, the field is omitted entirely so M2b-era commits
/// stay bit-identical on serialization (the
/// `m2b_compat_serialization` regression test pins this invariant).
pub fn vault_reveal_intent(
    path: &str,
    actor: &str,
    timestamp_unix: i64,
    id: Option<&str>,
) -> softfig_vcs::Result<Intent> {
    let mut payload = serde_json::json!({
        "path": path,
        "actor": actor,
        "timestamp": timestamp_unix,
    });
    if let Some(name) = id {
        payload["id"] = serde_json::Value::String(name.to_string());
    }
    Intent::new("vault_reveal", payload)
}

/// True if the schema-change payload describes a sealed-paths.toml edit
/// (used by the watcher classifier to fire the auto-migration walk).
pub fn payload_is_sealed_paths_change(payload: &serde_json::Value) -> bool {
    payload
        .get("kind")
        .and_then(|v| v.as_str())
        .map(|s| s == SEALED_PATHS_CHANGED_KIND)
        .unwrap_or(false)
}

/// Adapter that exposes a [`LayerBHook`] as the trait objects
/// [`BlobEncryptor`] and [`SealedQuery`] expect. Single `Arc` shared
/// across the daemon, the FUSE driver, and the watcher.
pub type SharedLayerB = Arc<LayerBHook>;

/// Convenience: build a shared hook by loading from disk.
pub fn shared_hook_from_disk(state_dir: &Path) -> Result<SharedLayerB> {
    Ok(Arc::new(LayerBHook::load(state_dir)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use softfig_vault::{params::VaultParams, Vault};

    fn write_file(p: &Path, body: &str) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    /// Cheap-KDF vault so the test isn't dominated by Argon2 (mirrors the
    /// `regions` test harness).
    fn fresh_session() -> VaultSession {
        let mut params = VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let tmp = tempfile::tempdir().unwrap();
        let (_v, session, _r) =
            Vault::init_with_params(tmp.path(), b"test-pass", params).unwrap();
        // The session owns no file handles post-unlock; leak the tempdir so it
        // outlives the call without a borrow.
        std::mem::forget(tmp);
        session
    }

    fn snapshot_with(rel: &str, content: &[u8]) -> WalkSnapshot {
        let mut snap = WalkSnapshot::empty();
        snap.insert_file(Path::new(rel), 0o644, content.to_vec()).unwrap();
        snap
    }

    fn prior_with(rel: &str, content: &[u8]) -> PriorTipSnapshot {
        PriorTipSnapshot {
            plaintext_by_path: HashMap::from([(rel.to_string(), content.to_vec())]),
        }
    }

    fn ids_of(intent: &Intent) -> Vec<String> {
        intent.payload()["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn empty_matcher_seals_nothing() {
        let sp = SealedPaths::empty();
        assert!(!sp.is_sealed("anything"));
        assert!(!sp.is_sealed("secrets/foo.toml"));
    }

    #[test]
    fn union_glob_semantics() {
        let sp = SealedPaths::compile(&[
            "secrets/**".to_string(),
            "**/api-keys.toml".to_string(),
        ])
        .unwrap();
        assert!(sp.is_sealed("secrets/foo.toml"));
        assert!(sp.is_sealed("secrets/dir/bar.toml"));
        assert!(sp.is_sealed("anywhere/api-keys.toml"));
        assert!(!sp.is_sealed("readme.md"));
        assert!(!sp.is_sealed("journal/decisions/decision-x.md"));
    }

    #[test]
    fn enumerate_matching_skips_softfig() {
        let tmp = tempfile::tempdir().unwrap();
        let g = tmp.path();
        write_file(&g.join("secrets/foo.toml"), "shh");
        write_file(&g.join("secrets/dir/bar.toml"), "also shh");
        write_file(&g.join("public.md"), "hello");
        write_file(&g.join(".softfig/db.sqlite"), "ignored");
        let sp = SealedPaths::compile(&["secrets/**".to_string()]).unwrap();
        let found = enumerate_matching(g, &sp);
        assert!(found.contains(&"secrets/foo.toml".to_string()));
        assert!(found.contains(&"secrets/dir/bar.toml".to_string()));
        assert!(!found.iter().any(|p| p.starts_with(".softfig")));
        assert!(!found.contains(&"public.md".to_string()));
    }

    #[test]
    fn enumerate_matching_honors_softfigignore() {
        let tmp = tempfile::tempdir().unwrap();
        let g = tmp.path();
        write_file(&g.join("secrets/foo.toml"), "shh");
        write_file(&g.join("scratch/sealed.toml"), "shh too");
        write_file(&g.join(".softfigignore"), "scratch\n");
        // A glob that would otherwise match the scratch file.
        let sp = SealedPaths::compile(&["**/*.toml".to_string()]).unwrap();
        let found = enumerate_matching(g, &sp);
        assert!(found.contains(&"secrets/foo.toml".to_string()));
        // The user-ignored top-level dir is pruned from the scan.
        assert!(!found.iter().any(|p| p.starts_with("scratch")));
    }

    #[test]
    fn sealed_paths_file_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        std::fs::create_dir_all(state_dir.join(".softfig/vault")).unwrap();
        let file = SealedPathsFile {
            paths: vec!["secrets/**".into(), "logs/*.private".into()],
        };
        file.store(state_dir).unwrap();
        let back = SealedPathsFile::load(state_dir).unwrap();
        assert_eq!(back.paths, file.paths);
    }

    #[test]
    fn promotion_detects_a_new_id_in_a_file_that_also_has_a_sealed_region() {
        // Slice 004: promotion sources each path's current bytes from the
        // in-memory snapshot — never an `fs::read` of the garden (= the FUSE
        // mount this daemon serves, read under `inner`). Nothing is written to
        // disk here; the old `fs::read(garden_root.join(rel))` path would find
        // no file and promote nothing, so this is red on the pre-fix code.
        //
        // The snapshot also carries TRUE working-tree plaintext, not the
        // reader-redacted FUSE view: `alpha` is a *real* sealed (ciphertext)
        // region — through the mount its body would project as the `[encrypted]`
        // placeholder (see `regions::render_read_view`), but the snapshot holds
        // the genuine base64 ciphertext. The freshly-typed `beta` is detected
        // against that truth.
        let session = fresh_session();
        let alpha_ct = session
            .encrypt_layer_b_region("notes.md", "alpha", b"first-secret")
            .unwrap();
        let alpha_b64 = B64.encode(&alpha_ct);

        let current = format!(
            "intro\n\n<vault id=\"alpha\">{alpha_b64}</vault>\n\n<vault id=\"beta\">brand-new</vault>\n"
        );
        // Prior tip: the sealed `alpha` region only — `beta` did not exist yet.
        let prior = format!("intro\n\n<vault id=\"alpha\">{alpha_b64}</vault>\n");

        let snapshot = snapshot_with("notes.md", current.as_bytes());
        let prior_snap = prior_with("notes.md", prior.as_bytes());

        let intent = promote_manual_edit_for_new_ids(
            &["notes.md".to_string()],
            &snapshot,
            &session,
            &prior_snap,
        )
        .expect("a new id in a file that also has a sealed region must promote");

        assert_eq!(intent.name(), "vault_seal");
        // Only the new id fires; the pre-existing sealed `alpha` does not re-seal.
        assert_eq!(ids_of(&intent), vec!["beta".to_string()]);
        let paths: Vec<String> = intent.payload()["paths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(paths, vec!["notes.md".to_string()]);
    }

    // --- M5d slice 002: per-chain key routing (`encrypt_for_ref`) -----------

    const S_ID: &str = "S-7f3a9b2c4d5e6f01";
    const S_MATERIAL: [u8; 32] = [0x51; 32];
    const SHARED_REF: &str = "chain/proj";

    /// A hook whose router maps `chain/proj` → `S_ID`, over a session that
    /// holds (or deliberately lacks) the S material.
    fn routed_hook(keyed: bool) -> (LayerBHook, VaultSession) {
        let session = fresh_session();
        if keyed {
            session.store_shared_key(S_ID, &S_MATERIAL).unwrap();
        }
        let mut chain = softfig_vcs::Chain::shared("proj", SHARED_REF, "proj", true);
        chain.key_id = Some(S_ID.to_string());
        let registry =
            softfig_vcs::ChainRegistry::new(softfig_vcs::Chain::device(), vec![chain]);
        let hook = LayerBHook::empty();
        hook.set_shared_chain_keys(&registry);
        (hook, session)
    }

    #[test]
    fn device_chain_stays_on_m_and_keyed_shared_chain_seals_under_s() {
        use softfig_vcs::BlobEncryptor as _;
        let (hook, session) = routed_hook(true);
        let pt = b"content";

        // Device ref: unchanged Layer A under M.
        let dev = hook
            .encrypt_for_ref(softfig_vcs::TIP_REF, "note.md", pt, &session)
            .unwrap();
        assert!(!softfig_vault::is_shared(&dev));
        assert_eq!(session.decrypt_blob(&dev).unwrap(), pt);

        // Keyed shared ref: the 0xFE convergent container under S. Paths reach
        // `encrypt_for_ref` chain-relative — `split_snapshot` strips the mount
        // prefix before the commit walk — and the router re-prefixes with the
        // chain's mount, so tests pass the same chain-relative strings.
        let shared = hook
            .encrypt_for_ref(SHARED_REF, "note.md", pt, &session)
            .unwrap();
        assert!(softfig_vault::is_shared_blob(&shared));
        assert_eq!(session.decrypt_shared_blob(&shared).unwrap(), pt);
        // Convergence through the router: a second member (different M,
        // same S) produces byte-identical ciphertext.
        let (hook_b, session_b) = routed_hook(true);
        let shared_b = hook_b
            .encrypt_for_ref(SHARED_REF, "note.md", pt, &session_b)
            .unwrap();
        assert_eq!(shared, shared_b);
    }

    #[test]
    fn unkeyed_shared_chain_refuses_content_pre_ceremony() {
        // M5f slice 001 (key-before-content): the m5c "unkeyed → M" fallback is
        // gone — a pre-ceremony shared ref refuses content outright, because an
        // M-sealed blob is per-device and nothing (establishment included) ever
        // converts it to S. The device ref is unaffected.
        use softfig_vcs::BlobEncryptor as _;
        let session = fresh_session();
        let hook = LayerBHook::empty(); // router knows no keyed chains
        let err = hook
            .encrypt_for_ref(SHARED_REF, "note.md", b"pre-key", &session)
            .unwrap_err();
        assert!(
            err.to_string().contains("no established key yet"),
            "want the key-before-content refusal, got: {err}"
        );
        // The device chain still seals under M as ever.
        let dev = hook
            .encrypt_for_ref(softfig_vcs::TIP_REF, "note.md", b"pre-key", &session)
            .unwrap();
        assert_eq!(session.decrypt_blob(&dev).unwrap(), b"pre-key");
    }

    #[test]
    fn keyed_chain_with_missing_s_fails_closed_never_falls_back_to_m() {
        use softfig_vcs::BlobEncryptor as _;
        let (hook, session) = routed_hook(false); // key_id routed, S absent
        let err = hook
            .encrypt_for_ref(SHARED_REF, "note.md", b"x", &session)
            .unwrap_err();
        assert!(
            err.to_string().contains("not stored in this vault"),
            "want SharedKeyUnavailable, got: {err}"
        );
    }

    #[test]
    fn set_shared_chain_keys_records_keyed_committed_refs() {
        // The production refresh path (not the test-only forcing helper) must
        // populate the authoritative keyed-ness set the NONCE-2 guard consults.
        let (hook, _session) = routed_hook(true);
        assert!(hook.ref_is_keyed_committed(SHARED_REF));
        assert!(!hook.ref_is_keyed_committed("chain/other"));
    }

    #[test]
    fn keyed_committed_ref_missing_from_the_router_fails_closed_not_m() {
        use softfig_vcs::BlobEncryptor as _;
        // M5d slice 016 (NONCE-2): the committed membership marks the chain keyed,
        // but the S router has no entry (stale / not re-primed for this commit).
        // Falling back to M here would seal a non-convergent, member-unreadable
        // blob onto a keyed shared chain, so the write must fail closed — the flush
        // re-queues it and a later flush (router re-primed from committed state)
        // seals it under S. Distinct from the routed-but-S-absent case above (that
        // one has a router entry and fails in the vault).
        let session = fresh_session();
        let hook = LayerBHook::empty(); // router holds no entry for SHARED_REF
        hook.force_keyed_committed_ref(SHARED_REF);
        let err = hook
            .encrypt_for_ref(SHARED_REF, "note.md", b"x", &session)
            .unwrap_err();
        assert!(
            err.to_string().contains("keyed in committed membership"),
            "want the NONCE-2 fail-closed refusal, got: {err}"
        );
    }

    #[test]
    fn sealed_glob_inside_a_keyed_shared_chain_derives_from_s() {
        use softfig_vcs::BlobEncryptor as _;
        let (hook, session) = routed_hook(true);
        hook.replace(SealedPaths::compile(&["proj/secrets/**".to_string()]).unwrap());
        // Chain-relative in, garden-relative glob out: the router reconstructs
        // `proj/secrets/api.toml`, which the sealed glob matches → shared Layer B.
        let ct = hook
            .encrypt_for_ref(SHARED_REF, "secrets/api.toml", b"shh", &session)
            .unwrap();
        assert!(softfig_vault::is_shared_layer_b(&ct));
        assert_eq!(
            session
                .decrypt_shared_layer_b("proj/secrets/api.toml", &ct)
                .unwrap(),
            b"shh"
        );
        // A non-member session can't read it (needs S, not just any M).
        let outsider = fresh_session();
        assert!(outsider
            .decrypt_shared_layer_b("proj/secrets/api.toml", &ct)
            .is_err());
    }

    #[test]
    fn inline_vault_tags_inside_a_keyed_shared_chain_are_refused() {
        use softfig_vcs::BlobEncryptor as _;
        let (hook, session) = routed_hook(true);
        let content = b"intro\n<vault id=\"a\">secret</vault>\n";
        let err = hook
            .encrypt_for_ref(SHARED_REF, "note.md", content, &session)
            .unwrap_err();
        assert!(
            err.to_string().contains("not supported inside a shared subtree"),
            "want the gated-regions refusal, got: {err}"
        );
    }

    #[test]
    fn promotion_is_none_with_no_new_id_and_skips_paths_absent_from_the_snapshot() {
        // Identical ids in prior + current ⇒ nothing to seal. And a path that is
        // not in the snapshot is silently skipped — there is no `fs::read`
        // fallback that could re-enter the mount.
        let session = fresh_session();
        let content = b"<vault id=\"alpha\">x</vault>\n";
        let snapshot = snapshot_with("notes.md", content);
        let prior_snap = prior_with("notes.md", content);

        let promoted = promote_manual_edit_for_new_ids(
            &["notes.md".to_string(), "not-in-snapshot.md".to_string()],
            &snapshot,
            &session,
            &prior_snap,
        );
        assert!(promoted.is_none());
    }
}
