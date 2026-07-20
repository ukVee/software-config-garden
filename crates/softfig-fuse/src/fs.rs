//! `fuser::Filesystem` implementation.
//!
//! Reads materialize the union (tree-at-tip ∪ overlay). Writes update
//! the overlay and push a `DirtyEvent` into the daemon via the
//! [`DirtyEventSink`] callbacks. Commit lifecycle is owned by the
//! daemon — when its `DirtySetAccumulator` flushes, it commits our
//! in-memory snapshot per owning chain, and each commit's tip-changed
//! callback rotates the view, absorbing exactly the overlay entries
//! that commit captured (slice 006 absorption invariant).

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use softfig_vcs::{ChainRegistry, Ignore, Repo, WalkSnapshot, IGNORE_FILE, TIP_REF};
use softfig_store::{Db, Hash, ObjectStore, StorePaths};
use softfig_vault::VaultSession;

use crate::inodes::{InodeMap, ROOT_INODE};
use crate::overlay::{Overlay, OverlayEntry};
use crate::tree_view::{EntryKind, TreeView};
use crate::{DirtyEventSink, MountHandle, Result, SealedQuery};

const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 512;

/// The mount runs with `DefaultPermissions`, so the kernel checks access
/// against each inode's owner *before* our handlers run. Present every
/// inode as owned by the keeper process (its effective uid/gid) so the
/// non-root daemon can write through its own mount.
///
/// `geteuid`/`getegid` are infallible FFI with no safety preconditions —
/// the only reason they're `unsafe` is the `extern "C"` boundary.
#[allow(unsafe_code)]
static OWNER_UID: LazyLock<u32> = LazyLock::new(|| unsafe { libc::geteuid() });
#[allow(unsafe_code)]
static OWNER_GID: LazyLock<u32> = LazyLock::new(|| unsafe { libc::getegid() });

pub(crate) struct SharedState {
    /// Re-opened sqlite handle for read-only tip resolution. WAL means
    /// this is safe to use concurrently with the daemon's writer.
    db: Mutex<Db>,
    objects: ObjectStore,
    session: Arc<VaultSession>,
    pub(crate) inner: Mutex<Inner>,
    sink: Arc<dyn DirtyEventSink>,
    sealed: Option<Arc<dyn SealedQuery>>,
    /// M5c slice 002 — the chain composition this mount serves. Reads compose
    /// the union across its enabled chains; commits route each path to its
    /// owning chain. Default [`ChainRegistry::device_only`] ⇒ today's behavior.
    /// Behind a `Mutex` so the M5c slice 003 lifecycle verbs can hot-swap it
    /// (add/remove/enable/disable) via [`Self::set_registry`] without a remount.
    registry: Mutex<ChainRegistry>,
    /// M2c — cache of post-`redact_regions` bytes keyed by
    /// repo-relative path. Invalidated on `tip_changed` (broadcast).
    /// Per the M2c open-question 5 lean, unbounded for v1 (same policy
    /// as the M2a tree-view cache); LRU is a future optimization.
    redacted_cache: Mutex<HashMap<PathBuf, Vec<u8>>>,
}

impl std::fmt::Debug for SharedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedState")
            .field("objects", &self.objects)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) inodes: InodeMap,
    pub(crate) tip: Option<Hash>,
    pub(crate) view: TreeView,
    pub(crate) overlay: Overlay,
}

impl SharedState {
    /// Recompose the union view after a ref advanced (`advanced =
    /// Some(ref_name)`, fired by the repo's `tip_changed` callback) or after
    /// a registry hot-swap (`advanced = None`, no commit happened).
    ///
    /// **Absorption invariant (M5c slice 006, bound per-commit in slice 012):**
    /// the rotation clears exactly the overlay entries the new composition
    /// absorbed — those owned by the chain whose ref advanced AND staged
    /// at-or-before `cutoff`, the overlay generation *the firing commit's own
    /// snapshot* captured (carried in with the commit, not read from a shared
    /// mutable slot). `cutoff = None` absorbs nothing: a registry swap
    /// (`advanced = None`) commits nothing, and a ref advance carrying no local
    /// snapshot (`advanced = Some`, `cutoff = None` — the m5e `shared_pull`
    /// shape: a network pull moves a ref forward with no local overlay capture)
    /// must never drop a staged local write it never contained. Other chains'
    /// staged writes and post-snapshot racers always survive. (The old
    /// unconditional `overlay.clear()` was correct only while every rotation
    /// followed a commit of the whole overlay — multi-ref broke that: the
    /// confirmed data-loss family of the 2026-07-11 interim review, findings
    /// 1/2/3/12; slice 012 closes the shared-slot residual, finding 5.)
    pub(crate) fn rotate_tip(&self, advanced: Option<&str>, cutoff: Option<u64>) {
        // M2c — drop the redacted-content cache on every tip change;
        // the new tip may have introduced/removed/re-encrypted vault
        // regions, and the cache key (path) doesn't encode tip hash.
        self.redacted_cache.lock().unwrap().clear();
        // M5c slice 002 — recompose the whole union view from every enabled
        // chain's ref (device tip is kept for reference). Recompose-all on any
        // chain's tip-change is a safe superset of per-chain invalidation; the
        // caller already knows which ref moved and can scope this later.
        let (device_tip, view, registry) = {
            let db = self.db.lock().unwrap();
            // Lock order is always db → registry (the only site holding both).
            let registry = self.registry.lock().unwrap();
            let device_tip = db.try_get_ref(TIP_REF).ok().flatten();
            let view = match TreeView::build_union(&db, &registry) {
                Ok(v) => v,
                Err(e) => {
                    // A failed recompose must not tear down the working state:
                    // keep serving the previous view AND the overlay (a
                    // collapsed-to-empty view + cleared overlay would present
                    // an empty garden and drop pending writes — finding 12).
                    // The next successful rotation recomposes.
                    eprintln!("softfig-fuse: union recompose failed, keeping previous view: {e}");
                    return;
                }
            };
            (device_tip, view, registry.clone())
        };
        let mut inner = self.inner.lock().unwrap();
        inner.tip = device_tip;
        inner.view = view;
        // Re-intern every path so freshly-introduced tip entries have
        // inodes ready for kernel lookups.
        for p in inner.view.paths().map(|p| p.to_path_buf()).collect::<Vec<_>>() {
            inner.inodes.intern(&p);
        }
        if let (Some(ref_name), Some(cutoff)) = (advanced, cutoff) {
            inner
                .overlay
                .remove_absorbed(cutoff, |p| registry.owning_chain(p).ref_name == ref_name);
        }
    }

    /// Reconstruct the current working tree — the committed tip-view
    /// unioned with the pending write overlay — as a
    /// [`WalkSnapshot`], entirely from in-memory state. Nothing is read
    /// back through the kernel/mount.
    ///
    /// This is the FUSE-mode input to
    /// [`softfig_vcs::Repo::commit_snapshot`]. Committing a mounted garden
    /// by walking it ([`softfig_vcs::Repo::commit_workdir`]) self-reads the
    /// mount while the daemon holds `inner` — the 2026-06-21 commit-path
    /// deadlock that slices 1-3 retire. Slice 3 wires keeperd's commits
    /// through here.
    ///
    /// Parity contract: in M2a (no [`SealedQuery`] adapter) the result
    /// matches `softfig_vcs::walk(mount_point)` exactly. It replicates
    /// walk's rule layer — the shared [`Ignore`] top-level predicate
    /// loaded from in-memory `.softfigignore`, the `.keep` empty-dir prune
    /// (here for free: only files are collected, so a directory with no
    /// file descendant never materializes), the `0o7777` mode mask, and
    /// BTreeMap ordering (all via [`WalkSnapshot::insert_file`]).
    ///
    /// It deliberately does NOT apply the read path's sealed-placeholder
    /// or `<vault>`-region redaction: a commit must persist the real
    /// working-tree plaintext (Layer B routing is the committer's job via
    /// the `BlobEncryptor`), never the `[sealed:…]`/`[encrypted]`
    /// projection a reader sees. A whole-file-sealed tip blob is stored as
    /// Layer B (0xFF marker), so it is decrypted under its path-derived
    /// Layer B subkey back to that plaintext (Phase 2) — the committer then
    /// re-seals it convergently into the byte-identical blob. The result
    /// therefore matches a `walk` of the *unsealed plaintext* a direct-mode
    /// (Disk) daemon commits, NOT a `walk(mount_point)` (which would read
    /// the reader-facing `[sealed:…]` placeholder); in M2a, with nothing
    /// sealed, the two coincide and walk-parity holds.
    ///
    /// M5c slice 002 — this is the **unified** tree (every enabled chain
    /// composed). The commit path never commits it whole; it is split by
    /// [`ChainRegistry::split_snapshot`] into per-chain snapshots
    /// ([`Self::chain_snapshots`] / [`Self::workdir_snapshot`]).
    pub(crate) fn unified_snapshot(&self) -> Result<WalkSnapshot> {
        // The in-memory `.softfigignore` (overlay precedence, else the tip
        // blob) drives the same top-level exclusion `walk` applies —
        // loaded from our own state, never via a mount read that would
        // re-enter `inner`.
        let ignore = self.inmem_ignore()?;

        // Phase 1 (under `inner`): collect every live file as
        // (repo-relative path, mode, content source) by recursively
        // descending the (tip-view ∪ overlay) tree from the root,
        // applying `ignore` during descent exactly like walk's
        // `filter_entry`. Overlay bytes are cloned here; tip blobs carry
        // only their hash so the bulk decrypt runs lock-free below.
        let mut files: Vec<(PathBuf, u32, ContentSource)> = Vec::new();
        // Graft points snapshotted before `inner` is locked (the registry and
        // `inner` locks never nest) — `collect_files` needs them for the
        // File-at-mount-root immunity (m5e slice 007).
        let mount_roots = self.enabled_mount_roots();
        let overlay_generation = {
            let inner = self.inner.lock().unwrap();
            // Slice 012 — capture the overlay generation this commit input is cut
            // at, under the same lock the entries are collected, and carry it WITH
            // the returned snapshot (not the shared `inner.snapshot_gen` slot slice
            // 006 used). The commit path threads it to the `tip_changed` callback,
            // so the post-commit rotation absorbs exactly the entries snapshotted
            // here and nothing staged after — and a ref advance with no snapshot (a
            // network pull) carries no generation and absorbs nothing (m5e
            // precondition; the 014 data-loss family, finding 5).
            let captured_gen = inner.overlay.generation();
            collect_files(&inner, &ignore, &mount_roots, Path::new(""), &mut files);
            captured_gen
        };

        // Phase 2: resolve content and assemble. Tip blobs decrypt to their
        // working-tree plaintext — raw Layer A, except a whole-file-sealed
        // blob (Layer B, 0xFF marker) is decrypted under its path-derived
        // Layer B subkey (decrypting it as Layer A would fail the varint/AEAD
        // parse). Region-sealed files are Layer A (inline base64 bodies) and
        // take the raw branch. Mirrors `layer_b::walk_tree_into`. Mode masking
        // + parent-dir creation are walk's shared rule layer
        // (`WalkSnapshot::insert_file`).
        let mut snapshot = WalkSnapshot::empty();
        for (path, mode, source) in files {
            let content = match source {
                ContentSource::Overlay(bytes) => bytes,
                ContentSource::Blob(target) => {
                    let cipher = self.objects.get(&target)?;
                    let rel = path.to_string_lossy().replace('\\', "/");
                    self.session.decrypt_tracked_blob(&rel, &cipher)?
                }
            };
            snapshot.insert_file(&path, mode, content)?;
        }
        // Files-only collection already drops empty dirs, but prune for
        // symmetry with `walk` and robustness if that ever changes.
        snapshot.prune_empty_dirs();
        // Carry the generation captured above with the snapshot, so the commit
        // that lands it fires the rotation with its own cutoff (slice 012).
        snapshot.overlay_generation = Some(overlay_generation);
        Ok(snapshot)
    }

    /// The **device** chain's commit snapshot: the unified working tree carved
    /// to device-owned paths (M5c slice 002 isolation pin). Byte-identical to
    /// [`Self::unified_snapshot`] under a `device_only` registry — the input the
    /// keeperd commit path feeds to `commit_snapshot`/`commit_snapshot_to(TIP_REF)`.
    pub(crate) fn workdir_snapshot(&self) -> Result<WalkSnapshot> {
        let unified = self.unified_snapshot()?;
        Ok(self
            .registry
            .lock()
            .unwrap()
            .split_snapshot(&unified)
            .into_iter()
            .find(|(r, _)| r == TIP_REF)
            .map(|(_, s)| s)
            .unwrap_or_else(WalkSnapshot::empty))
    }

    /// One commit snapshot per enabled chain (device carve-out + shared
    /// prefix-strip), each ready for `commit_snapshot_to(ref, …)` — the
    /// load-bearing write router. A write under a shared mount lands only in
    /// that chain's snapshot, never the device chain's, so it can never advance
    /// the wrong ref.
    pub(crate) fn chain_snapshots(&self) -> Result<Vec<(String, WalkSnapshot)>> {
        let unified = self.unified_snapshot()?;
        Ok(self.registry.lock().unwrap().split_snapshot(&unified))
    }

    /// A clone of the chain registry this mount serves — the keeperd commit path
    /// routes each dirty path through [`ChainRegistry::owning_chain`] to decide
    /// which chains a flush must commit.
    pub(crate) fn registry(&self) -> ChainRegistry {
        self.registry.lock().unwrap().clone()
    }

    /// Whether `path` is **exactly** the mount root of an enabled shared chain
    /// (delegates to [`ChainRegistry::is_enabled_mount_root`] under the registry
    /// lock, no clone). The kernel `create`/`rmdir`/`rename` handlers consult
    /// this to refuse writes at a live graft point with `EBUSY` (m5c residual
    /// finding 2b): a file at the mount root strips to an empty chain-relative
    /// path and reaches no chain's history; removing or moving it detaches the
    /// mount.
    pub(crate) fn is_enabled_mount_root(&self, path: &Path) -> bool {
        self.registry.lock().unwrap().is_enabled_mount_root(path)
    }

    /// M5f slice 001 (key-before-content) — the mount path of the enabled
    /// shared chain that owns `path` while still unkeyed (pre-ceremony), or
    /// `None`. The kernel content ops (`create`/`write`/`mkdir`/`rename`-dest/
    /// staging `setattr`) and the keeperd action-verb staging consult this to
    /// refuse with `EROFS`: content accepted before the key ceremony would seal
    /// under the per-device `M` — unreadable to every other member and never
    /// converted by establishment or the rotation heal — so an unkeyed share is
    /// read-only until keyed. Removals (`unlink`/`rmdir`) and rename-*out*
    /// stay allowed: they add no blob to the chain. Delegates under the
    /// registry lock, like [`Self::is_enabled_mount_root`].
    pub(crate) fn unkeyed_shared_owner(&self, path: &Path) -> Option<String> {
        self.registry
            .lock()
            .unwrap()
            .unkeyed_shared_owner(path)
            .map(|c| {
                c.mount_path
                    .as_deref()
                    .unwrap_or(Path::new(""))
                    .to_string_lossy()
                    .replace('\\', "/")
            })
    }

    /// Every enabled shared chain's mount root — the union graft points, for
    /// [`collect_files`]'s File-at-graft-point immunity (m5e slice 007). The
    /// device chain has no mount path and drops out of the filter_map.
    /// Snapshotted before `inner` is locked so the two locks never nest.
    pub(crate) fn enabled_mount_roots(&self) -> Vec<PathBuf> {
        self.registry
            .lock()
            .unwrap()
            .enabled_chains()
            .filter_map(|c| c.mount_path.clone())
            .collect()
    }

    /// M5c slice 003 — hot-swap the chain registry this mount serves, then
    /// recompose the whole union view from it. The keeperd lifecycle verbs call
    /// this after flipping the local enable/disable sidecar or committing an
    /// add/remove membership change, so the mount reflects the new composition
    /// live — no remount (which would drop the pending write overlay). The
    /// recompose itself preserves the overlay too: no commit happens here, so
    /// the rotation runs with `advanced = None` and absorbs nothing (slice 006
    /// — before that fix this path cleared the whole overlay, review finding 2).
    pub(crate) fn set_registry(&self, registry: ChainRegistry) {
        // Swap under the registry lock; the temporary guard is released at the
        // end of this statement, before `rotate_tip` re-locks it (std `Mutex`
        // is not reentrant).
        *self.registry.lock().unwrap() = registry;
        // No commit happened, so no cutoff — the rotation absorbs nothing.
        self.rotate_tip(None, None);
    }

    /// The refs of every chain that owns at least one staged overlay file or
    /// removal — the chains the next commit must advance for the overlay to be
    /// fully absorbed. `Dir` markers alone don't count (empty directories are
    /// not versioned, so there is nothing to commit). The keeperd action-verb
    /// commit path uses this to route a staged write under a shared mount to
    /// the owning chain's ref instead of silently dropping it via the device
    /// carve-out (slice 006 fix for review finding 1).
    pub(crate) fn pending_chain_refs(&self) -> Vec<String> {
        // Lock order at this second dual-hold site is inner → registry; no
        // path acquires them in the opposite order (rotate_tip's db → registry
        // pair is released before it takes inner).
        let inner = self.inner.lock().unwrap();
        let registry = self.registry.lock().unwrap();
        let mut refs: Vec<String> = Vec::new();
        for (path, entry) in inner.overlay.iter() {
            if matches!(entry, OverlayEntry::Dir { .. }) {
                continue;
            }
            let r = &registry.owning_chain(path).ref_name;
            if !refs.contains(r) {
                refs.push(r.clone());
            }
        }
        refs
    }

    /// The exclusion set in force for this garden, read from the in-memory
    /// `.softfigignore` (overlay precedence, else the committed tip blob)
    /// so reconstruction never `std::fs`-reads it back through the mount.
    /// Absent/removed/dir-shaped ⇒ the built-in defaults only.
    ///
    /// `pub(crate)` so [`MountHandle::inmem_ignore`] can hand the keeperd
    /// watcher this same in-memory set for its `accept()` push-time filter —
    /// never a `std::fs`-read of the mount (audit slice-003 reentrancy).
    pub(crate) fn inmem_ignore(&self) -> Result<Ignore> {
        let blob = {
            let inner = self.inner.lock().unwrap();
            let path = Path::new(IGNORE_FILE);
            match inner.overlay.get(path) {
                Some(OverlayEntry::File { content, .. }) => {
                    return Ok(Ignore::from_contents(&String::from_utf8_lossy(content)));
                }
                // A removal marker or a (nonsensical) dir override both
                // shadow the tip copy — fall back to the built-ins.
                Some(_) => return Ok(Ignore::builtin()),
                None => match inner.view.get(path) {
                    Some(e) if e.kind == EntryKind::Blob => e.target,
                    _ => return Ok(Ignore::builtin()),
                },
            }
        };
        let cipher = self.objects.get(&blob)?;
        let plain = self.session.decrypt_blob(&cipher)?;
        Ok(Ignore::from_contents(&String::from_utf8_lossy(&plain)))
    }

    /// Every live (overlay ∪ tip), ignore-filtered, repo-relative file path as a
    /// forward-slash string — exactly the set [`Self::workdir_snapshot`] would
    /// commit. Lets the daemon enumerate sealed-matching files (`vault seal`,
    /// `vault list-sealed`) from in-memory state rather than `WalkDir`-walking
    /// the mount it serves under `inner` (the 2026-06-21 deadlock). Reuses
    /// `collect_files` so the enumerated set never drifts from the committed
    /// set; content bytes it clones for the overlay case are dropped (the
    /// overlay is normally empty here — the daemon commits before enumerating).
    pub(crate) fn live_repo_paths(&self) -> Result<Vec<String>> {
        let ignore = self.inmem_ignore()?;
        let mut files: Vec<(PathBuf, u32, ContentSource)> = Vec::new();
        let mount_roots = self.enabled_mount_roots();
        {
            let inner = self.inner.lock().unwrap();
            collect_files(&inner, &ignore, &mount_roots, Path::new(""), &mut files);
        }
        Ok(files
            .into_iter()
            .map(|(p, _, _)| p.to_string_lossy().replace('\\', "/"))
            .collect())
    }

    // ===== Overlay-staging + in-memory queries for daemon M3a actions =====
    //
    // The keeperd M3a verbs used to `std::fs`-read/-write `garden_root`, which
    // in FUSE mode is the mount THIS daemon serves — a self-read/-write of the
    // mount while the daemon holds `daemon.inner` (the 2026-06-21 deadlock).
    // These let the daemon read and stage working-tree changes purely against
    // the in-memory (tip ∪ overlay) state, never re-entering the kernel.
    //
    // Writes land in the overlay and are captured by the next
    // `workdir_snapshot` commit; they deliberately do NOT fire the
    // `DirtyEventSink` — the daemon commits them explicitly, so emitting a
    // watcher event would queue a redundant (double) commit. Paths are
    // repo-relative, the same key shape the FUSE handlers use (root = "").

    /// Working-tree bytes for repo-relative `rel`: overlay precedence (a
    /// `File`'s content; a `Removed`/`Dir` marker ⇒ `None`), else the committed
    /// tip blob decrypted to its **plaintext** — raw Layer A, except a
    /// whole-file-sealed (Layer B) blob is decrypted under its path-derived
    /// subkey. No sealed/region projection, matching [`Self::workdir_snapshot`]
    /// (working-tree truth, not the reader's redacted view). `None` when absent
    /// or a directory.
    pub(crate) fn read_workfile(&self, rel: &Path) -> Result<Option<Vec<u8>>> {
        let target = {
            let inner = self.inner.lock().unwrap();
            match inner.overlay.get(rel) {
                Some(OverlayEntry::File { content, .. }) => return Ok(Some(content.clone())),
                Some(OverlayEntry::Removed | OverlayEntry::Dir { .. }) => return Ok(None),
                None => match inner.view.get(rel) {
                    Some(e) if e.kind == EntryKind::Blob => e.target,
                    _ => return Ok(None),
                },
            }
        };
        // Decrypt outside the lock (matches `workdir_snapshot`'s two-phase shape).
        let cipher = self.objects.get(&target)?;
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        Ok(Some(self.session.decrypt_tracked_blob(&rel_str, &cipher)?))
    }

    /// Whether repo-relative `rel` resolves to a live file or directory.
    pub(crate) fn path_exists(&self, rel: &Path) -> bool {
        self.entry_kind(rel).is_some()
    }

    /// Whether `rel` is a directory in the working tree (an overlay `Dir` or a
    /// committed tip tree node). The repo root (`""`) is always a directory.
    pub(crate) fn path_is_dir(&self, rel: &Path) -> bool {
        rel.as_os_str().is_empty() || matches!(self.entry_kind(rel), Some(EntryKind::Dir))
    }

    /// Kind of the working-tree entry at `rel` (overlay precedence), or `None`
    /// if absent / overlay-removed.
    fn entry_kind(&self, rel: &Path) -> Option<EntryKind> {
        entry_kind_of(&self.inner.lock().unwrap(), rel)
    }

    /// One-level children of `dir` (repo-relative; `""` = root) as
    /// `(file_name, is_dir)`, merging overlay over tip and honoring overlay
    /// removals. Order is unspecified — callers sort.
    pub(crate) fn read_dir_entries(&self, dir: &Path) -> Vec<(String, bool)> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<(String, bool)> = Vec::new();
        let mut seen: HashSet<PathBuf> = HashSet::new();
        // Tip children not shadowed by an overlay entry (override or removal).
        for (child, entry) in inner.view.children(dir) {
            if inner.overlay.get(child).is_some() {
                continue;
            }
            seen.insert(child.to_path_buf());
            if let Some(name) = child.file_name().and_then(|n| n.to_str()) {
                out.push((name.to_string(), entry.kind == EntryKind::Dir));
            }
        }
        // Overlay children (new files/dirs + overrides), skipping removals.
        for (path, entry) in inner.overlay.iter() {
            if path.parent() != Some(dir) || matches!(entry, OverlayEntry::Removed) {
                continue;
            }
            if !seen.insert(path.to_path_buf()) {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                out.push((name.to_string(), matches!(entry, OverlayEntry::Dir { .. })));
            }
        }
        out
    }

    /// Stage a create-or-overwrite into the overlay, preserving an existing
    /// file's mode (else `0o100644`, like a plain `std::fs::write`). No kernel
    /// round-trip and no `DirtyEventSink` event.
    pub(crate) fn stage_write(&self, rel: &Path, content: Vec<u8>) {
        let mut inner = self.inner.lock().unwrap();
        let mode = current_mode(&inner, rel).unwrap_or(0o100644);
        ensure_overlay_dirs(&mut inner, rel);
        inner.overlay.insert_file(rel.to_path_buf(), content, mode);
        inner.inodes.intern(rel);
    }

    /// Stage a rename into the overlay. Handles a single file and a directory
    /// (every live descendant — files re-keyed with their bytes, sub-directories
    /// moved as overlay markers). Each moved file's bytes are materialized into
    /// the overlay so the move survives the overlay-clears-on-commit rotation.
    /// This is the single dir-aware rename implementation: the kernel `rename`
    /// handler delegates here too, so a human-facing `mv dir newdir` re-keys the
    /// subtree instead of dropping it.
    ///
    /// Two passes for atomicity. Pass 1 reads every moving file's bytes up front
    /// and returns on the FIRST read error with the overlay byte-for-byte
    /// untouched — a mid-rename store/decrypt failure can never leave a
    /// half-renamed subtree for the next debounce to commit. Pass 2 takes `inner`
    /// once and applies every mutation with no fallible read between them.
    ///
    /// The source directory itself (and every emptied sub-directory) is marked
    /// `Removed`, so it does not linger in the live view; and an empty-directory
    /// rename re-creates the directory at the destination, so `mv` of a dir with
    /// no files is a real move rather than a silent no-op.
    pub(crate) fn stage_rename(&self, from: &Path, to: &Path) -> Result<()> {
        let (file_movers, dir_movers) = self.rename_movers(from);

        // Pass 1 — fallible, no mutation. Read modes under one short lock, then
        // each moving file's bytes lock-free; the first read error aborts here.
        let (file_modes, dir_plan): (Vec<u32>, Vec<(PathBuf, PathBuf, u32)>) = {
            let inner = self.inner.lock().unwrap();
            let modes = file_movers
                .iter()
                .map(|src| current_mode(&inner, src).unwrap_or(0o100644))
                .collect();
            let dirs = dir_movers
                .iter()
                .map(|src| {
                    (
                        src.clone(),
                        remap(from, to, src),
                        current_mode(&inner, src).unwrap_or(0o040755),
                    )
                })
                .collect();
            (modes, dirs)
        };
        let mut file_plan: Vec<(PathBuf, PathBuf, Vec<u8>, u32)> =
            Vec::with_capacity(file_movers.len());
        for (src, mode) in file_movers.iter().zip(file_modes) {
            let content = self.read_workfile(src)?.unwrap_or_default();
            file_plan.push((src.clone(), remap(from, to, src), content, mode));
        }

        // Pass 2 — infallible, one lock. No fallible read between mutations, so
        // the overlay only ever transitions from fully-old to fully-new.
        let mut inner = self.inner.lock().unwrap();
        for (src, dst, content, mode) in file_plan {
            inner.overlay.mark_removed(src.clone());
            ensure_overlay_dirs(&mut inner, &dst);
            inner.overlay.insert_file(dst.clone(), content, mode);
            inner.inodes.rename(&src, &dst);
        }
        for (src, dst, mode) in dir_plan {
            inner.overlay.mark_removed(src.clone());
            inner.overlay.insert_dir(dst.clone(), mode);
            inner.inodes.rename(&src, &dst);
        }
        Ok(())
    }

    /// Partition every live entry under `from` (inclusive) into regular-file
    /// paths (to re-key with their bytes) and directory paths (to move as overlay
    /// markers), honoring overlay precedence and `Removed`. A lone file yields
    /// one file mover and no dirs; a directory yields itself plus every live
    /// descendant. Recording directories — not just files, as the former
    /// files-only enumeration did — is what lets an emptied source dir disappear
    /// and an empty-dir rename actually move. No ignore filtering —
    /// `.softfig`/`.claude` are absent from both the tip tree and the overlay.
    fn rename_movers(&self, from: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let inner = self.inner.lock().unwrap();
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        match entry_kind_of(&inner, from) {
            Some(EntryKind::Blob) => files.push(from.to_path_buf()),
            Some(EntryKind::Dir) => {
                dirs.push(from.to_path_buf());
                collect_live_entries(&inner, from, &mut files, &mut dirs);
            }
            None => {}
        }
        (files, dirs)
    }
}

/// Ensure overlay `Dir` markers exist for every ancestor directory of `file`
/// that isn't already present (overlay entry or committed tip dir), mirroring
/// the `create_dir_all` → kernel `mkdir` chain the old `std::fs` action-write
/// path triggered. Without this, `collect_files` / `collect_live_entries` —
/// which descend *only* through known `Dir` entries — would never reach a file staged
/// under a not-yet-existing directory, silently dropping it from the commit
/// snapshot. The dir mode is cosmetic (the snapshot derives dir nodes from the
/// files' ancestry, not from these markers).
fn ensure_overlay_dirs(inner: &mut Inner, file: &Path) {
    for anc in file.ancestors().skip(1) {
        if anc.as_os_str().is_empty() {
            continue; // the repo root is implicit
        }
        if inner.overlay.get(anc).is_some() {
            continue; // already staged — don't clobber a File/Removed/Dir marker
        }
        if matches!(inner.view.get(anc).map(|e| e.kind), Some(EntryKind::Dir)) {
            continue; // already a committed directory
        }
        inner.overlay.insert_dir(anc.to_path_buf(), 0o040755);
    }
}

/// Mode of the working-tree entry at `path` (overlay precedence), or `None`.
fn current_mode(inner: &Inner, path: &Path) -> Option<u32> {
    if let Some(entry) = inner.overlay.get(path) {
        return match entry {
            OverlayEntry::File { mode, .. } => Some(*mode),
            OverlayEntry::Dir { mode } => Some(*mode),
            OverlayEntry::Removed => None,
        };
    }
    inner.view.get(path).map(|e| e.mode)
}

/// Kind of the working-tree entry at `rel` from a locked [`Inner`] (overlay
/// precedence; a `Removed` marker ⇒ `None`). The lock-holding analogue of
/// [`SharedState::entry_kind`], so [`SharedState::rename_movers`] can classify a
/// path without re-acquiring `inner`.
fn entry_kind_of(inner: &Inner, rel: &Path) -> Option<EntryKind> {
    if let Some(entry) = inner.overlay.get(rel) {
        return match entry {
            OverlayEntry::File { .. } => Some(EntryKind::Blob),
            OverlayEntry::Dir { .. } => Some(EntryKind::Dir),
            OverlayEntry::Removed => None,
        };
    }
    inner.view.get(rel).map(|e| e.kind)
}

/// Map a source path under `from` to its destination under `to`, preserving the
/// sub-path suffix (`from` itself maps to `to`). Backs [`SharedState::stage_rename`].
fn remap(from: &Path, to: &Path, src: &Path) -> PathBuf {
    let suffix = src.strip_prefix(from).unwrap_or(Path::new(""));
    if suffix.as_os_str().is_empty() {
        to.to_path_buf()
    } else {
        to.join(suffix)
    }
}

/// Recursively collect live entries under `dir` (exclusive of `dir` itself),
/// appending regular-file paths to `files` and sub-directory paths to `dirs`,
/// mirroring [`collect_files`]'s precedence (overlay wins; a `Removed` marker
/// hides the tip copy) without the ignore filter or content. The entry-kind
/// analogue of the former files-only enumeration; backs
/// [`SharedState::rename_movers`].
fn collect_live_entries(
    inner: &Inner,
    dir: &Path,
    files: &mut Vec<PathBuf>,
    dirs: &mut Vec<PathBuf>,
) {
    for (path, entry) in inner.overlay.iter() {
        if path.parent() != Some(dir) {
            continue;
        }
        match entry {
            OverlayEntry::Removed => {}
            OverlayEntry::File { .. } => files.push(path.to_path_buf()),
            OverlayEntry::Dir { .. } => {
                dirs.push(path.to_path_buf());
                collect_live_entries(inner, path, files, dirs);
            }
        }
    }
    for (path, entry) in inner.view.children(dir) {
        if inner.overlay.get(path).is_some() {
            continue;
        }
        match entry.kind {
            EntryKind::Blob => files.push(path.to_path_buf()),
            EntryKind::Dir => {
                dirs.push(path.to_path_buf());
                collect_live_entries(inner, path, files, dirs);
            }
        }
    }
}

/// Where a reconstructed file's bytes come from. Overlay content is
/// cloned under the `inner` lock; a tip blob carries only its object
/// hash so decryption happens after the lock is released.
enum ContentSource {
    Overlay(Vec<u8>),
    Blob(Hash),
}

/// Recursively collect the live files under `dir` from the in-memory
/// (tip-view ∪ overlay) state, mirroring [`FuseFs::list_children`]'s
/// precedence: overlay entries win over the tip, and an overlay
/// `Removed` marker hides the tip copy. `ignore` is applied to each
/// child before descending/recording — the in-memory analogue of walk's
/// `filter_entry`, so an ignored top-level dir is never entered. Only
/// files are recorded; directories exist implicitly via their files'
/// ancestry, which reproduces walk's `.keep` empty-dir pruning.
fn collect_files(
    inner: &Inner,
    ignore: &Ignore,
    mount_roots: &[PathBuf],
    dir: &Path,
    out: &mut Vec<(PathBuf, u32, ContentSource)>,
) {
    // Overlay children first — they take precedence over the tip.
    for (path, entry) in inner.overlay.iter() {
        if path.parent() != Some(dir) || ignore.is_ignored(path) {
            continue;
        }
        match entry {
            OverlayEntry::Removed => {}
            OverlayEntry::File { content, mode } => {
                // A File overlay at exactly an enabled mount root can only be
                // a stray staging artifact — every kernel op that could stage
                // one (`create`/`rename`/`setattr`) refuses EBUSY there.
                // Emitting it would shadow the grafted subtree in the tip loop
                // below and drive an empty-carve-out commit of the shared
                // chain — the silent wipe of m5e slice 007 / pre-merge review
                // finding 1. Skip it; the tip loop below treats the graft
                // point as unshadowed, so the subtree survives any source of
                // the artifact, present or future.
                if mount_roots.iter().any(|r| r.as_path() == path) {
                    eprintln!(
                        "keeperd: fuse: ignoring stray staged file at enabled mount root {} \
                         (would shadow the grafted subtree)",
                        path.display()
                    );
                    continue;
                }
                out.push((path.to_path_buf(), *mode, ContentSource::Overlay(content.clone())));
            }
            OverlayEntry::Dir { .. } => collect_files(inner, ignore, mount_roots, path, out),
        }
    }
    // Tip-view children not shadowed by any overlay entry for the same path.
    for (path, entry) in inner.view.children(dir) {
        let shadowed = match inner.overlay.get(path) {
            None => false,
            // The stray File-at-graft-point artifact skipped above must not
            // shadow the graft either, or the subtree still vanishes.
            Some(OverlayEntry::File { .. }) => !mount_roots.iter().any(|r| r.as_path() == path),
            Some(_) => true,
        };
        if shadowed || ignore.is_ignored(path) {
            continue;
        }
        match entry.kind {
            EntryKind::Blob => {
                out.push((path.to_path_buf(), entry.mode, ContentSource::Blob(entry.target)));
            }
            EntryKind::Dir => collect_files(inner, ignore, mount_roots, path, out),
        }
    }
}

/// Public entry point. Builds the shared state, mounts at
/// `garden_root`, and returns the handle.
#[derive(Debug)]
pub struct FuseMount;

impl FuseMount {
    pub fn mount(
        garden_root: &Path,
        state_root: &Path,
        session: Arc<VaultSession>,
        sink: Arc<dyn DirtyEventSink>,
    ) -> Result<MountHandle> {
        Self::mount_with(
            garden_root,
            state_root,
            session,
            sink,
            None,
            ChainRegistry::device_only(),
        )
    }

    /// Like [`Self::mount`] but accepts an optional [`SealedQuery`] adapter
    /// — when present, reads of sealed paths return the
    /// `[sealed:<path>]\n` placeholder instead of decrypted Layer A
    /// bytes. M2b daemons call this; M2a callers can keep using
    /// [`Self::mount`].
    pub fn mount_with(
        garden_root: &Path,
        state_root: &Path,
        session: Arc<VaultSession>,
        sink: Arc<dyn DirtyEventSink>,
        sealed: Option<Arc<dyn SealedQuery>>,
        registry: ChainRegistry,
    ) -> Result<MountHandle> {
        let state = Self::build_state(garden_root, state_root, session, sink, sealed, registry)?;

        let fs = FuseFs {
            state: state.clone(),
        };
        let opts = vec![
            fuser::MountOption::FSName("softfig".into()),
            fuser::MountOption::Subtype("softfig".into()),
            fuser::MountOption::DefaultPermissions,
        ];
        // Deliberately NOT `AutoUnmount`. fuser implicitly appends
        // `allow_other` whenever AutoUnmount is set (see fuser
        // `Session::new`), and `fusermount3` rejects `allow_other` unless
        // `user_allow_other` is enabled in /etc/fuse.conf — which surfaces
        // as an opaque `mount: Operation not permitted (EPERM)`. We never
        // want `allow_other` regardless: the decrypted garden must stay
        // readable only by the owning uid, never other users or root.
        //
        // The daemon already unmounts explicitly on every clean path
        // (entry to `Stopping`, `migrate_finalize`) via
        // `MountHandle::unmount`, so AutoUnmount only ever covered an
        // abnormal daemon death (SIGKILL/OOM/panic) leaving a dead mount.
        // `clear_stale_mount` reclaims that on the next mount instead, so
        // a crashed-then-restarted daemon self-heals without `allow_other`.
        clear_stale_mount(garden_root);
        let bg = fuser::spawn_mount2(fs, garden_root, &opts)?;

        Ok(MountHandle {
            background: Mutex::new(Some(bg)),
            state,
            mount_point: garden_root.to_path_buf(),
        })
    }

    /// Build the shared in-memory state [`Self::mount_with`] wraps a kernel
    /// mount around: store handles, the composed union view, and the write
    /// overlay. Factored out so [`Self::attach_unmounted`] can serve the same
    /// state headlessly.
    fn build_state(
        garden_root: &Path,
        state_root: &Path,
        session: Arc<VaultSession>,
        sink: Arc<dyn DirtyEventSink>,
        sealed: Option<Arc<dyn SealedQuery>>,
        registry: ChainRegistry,
    ) -> Result<Arc<SharedState>> {
        let paths = StorePaths::with_state_root(garden_root, state_root);
        let db = Db::open(&paths)?;
        let objects = ObjectStore::new(paths.clone());

        // M5c slice 002 — compose the initial view across every enabled chain.
        // `device_only` yields exactly the device tip's tree (today's behavior).
        let tip = db.try_get_ref(TIP_REF)?;
        let view = TreeView::build_union(&db, &registry)?;

        let mut inodes = InodeMap::new();
        for p in view.paths().map(|p| p.to_path_buf()).collect::<Vec<_>>() {
            inodes.intern(&p);
        }

        Ok(Arc::new(SharedState {
            db: Mutex::new(db),
            objects,
            session,
            inner: Mutex::new(Inner {
                inodes,
                tip,
                view,
                overlay: Overlay::new(),
            }),
            sink,
            sealed,
            registry: Mutex::new(registry),
            redacted_cache: Mutex::new(HashMap::new()),
        }))
    }

    /// Headless test seam: the full [`MountHandle`] state machine — overlay
    /// staging, union view, snapshot/rotation/absorption, registry hot-swap —
    /// with **no kernel mount** behind it. Lets the overlay-lifecycle and
    /// commit-routing invariants (slice 006) be regression-tested where
    /// `/dev/fuse` is unavailable; every in-memory code path is the production
    /// one, only the fuser session is absent ([`MountHandle::unmount`] is a
    /// no-op). Not for real gardens — production daemons use
    /// [`Self::mount_with`]; the keeperd `fuse_attach_unmounted` config seam
    /// reaches this only from integration tests.
    #[doc(hidden)]
    pub fn attach_unmounted(
        garden_root: &Path,
        state_root: &Path,
        session: Arc<VaultSession>,
        sink: Arc<dyn DirtyEventSink>,
        sealed: Option<Arc<dyn SealedQuery>>,
        registry: ChainRegistry,
    ) -> Result<MountHandle> {
        let state = Self::build_state(garden_root, state_root, session, sink, sealed, registry)?;
        Ok(MountHandle {
            background: Mutex::new(None),
            state,
            mount_point: garden_root.to_path_buf(),
        })
    }

    /// Convenience for the daemon: register `MountHandle::on_tip_changed`
    /// as the repo's tip-changed callback. The closure captures a
    /// `Weak<SharedState>` so dropping the handle doesn't keep the FS
    /// state alive past unmount.
    pub fn install_tip_callback(repo: &mut Repo, handle: &MountHandle) {
        let state = Arc::downgrade(&handle.state);
        repo.set_tip_changed_callback(move |ref_name: &str, _hash: &Hash, cutoff: Option<u64>| {
            if let Some(s) = state.upgrade() {
                s.rotate_tip(Some(ref_name), cutoff);
            }
        });
    }
}

struct FuseFs {
    state: Arc<SharedState>,
}

impl Filesystem for FuseFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.attr_for_child(parent, name) {
            Some(attr) => reply.entry(&TTL, &attr, 0),
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match self.attr_for_inode(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(libc::ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        match self.read_bytes(&path) {
            Ok(bytes) => {
                let start = offset.max(0) as usize;
                if start >= bytes.len() {
                    reply.data(&[]);
                    return;
                }
                let end = (start + size as usize).min(bytes.len());
                reply.data(&bytes[start..end]);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (
                self.parent_inode(&path),
                FileType::Directory,
                "..".to_string(),
            ),
        ];
        for (child_path, kind) in self.list_children(&path) {
            let name = child_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
            let Some(name) = name else { continue };
            let child_inode = {
                let mut inner = self.state.inner.lock().unwrap();
                inner.inodes.intern(&child_path)
            };
            entries.push((child_inode, kind, name));
        }
        for (i, (inode, ftype, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(inode, (i + 1) as i64, ftype, name) {
                break;
            }
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let Some(name_str) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        let path = parent_path.join(name_str);
        // A file can't occupy a live mount root: it strips to an empty
        // chain-relative path in the write router and reaches no chain's
        // history (m5c residual finding 2b). Refuse with EBUSY — the path is
        // the graft point of an active union mount.
        if self.state.is_enabled_mount_root(&path) {
            return reply.error(libc::EBUSY);
        }
        // Key-before-content (m5f slice 001): no new file in an unkeyed share.
        if self.refuses_unkeyed_shared_write(&path, "create") {
            return reply.error(libc::EROFS);
        }
        let ino = {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.insert_file(path.clone(), Vec::new(), mode);
            inner.inodes.intern(&path)
        };
        let rel = path_to_repo_rel(&path);
        self.state.sink.created(&rel);
        self.state.sink.nudge();
        let attr = self
            .attr_for_inode(ino)
            .expect("just-created inode has attrs");
        reply.created(&TTL, &attr, 0, 0, 0);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        // Key-before-content (m5f slice 001): no content into an unkeyed share.
        if self.refuses_unkeyed_shared_write(&path, "write") {
            return reply.error(libc::EROFS);
        }
        let bytes = match self.read_bytes(&path) {
            Ok(b) => b,
            Err(_) => return reply.error(libc::EIO),
        };
        let mode = self.mode_of(ino).unwrap_or(0o100644);
        let start = offset.max(0) as usize;
        let end = start + data.len();
        let mut buf = bytes;
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(data);
        {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.insert_file(path.clone(), buf, mode);
        }
        let rel = path_to_repo_rel(&path);
        self.state.sink.modified(&rel);
        self.state.sink.nudge();
        reply.written(data.len() as u32);
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_path = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let Some(name_str) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        let path = parent_path.join(name_str);
        // Key-before-content (m5f slice 001): an unkeyed share is read-only as
        // a whole — refusing dirs too keeps the posture coherent (a dir that
        // could never receive a file would just dangle un-versioned).
        if self.refuses_unkeyed_shared_write(&path, "mkdir") {
            return reply.error(libc::EROFS);
        }
        let ino = {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.insert_dir(path.clone(), mode);
            inner.inodes.intern(&path)
        };
        // mkdir alone doesn't create a commit-worthy event (empty dirs
        // aren't versioned without a `.keep` file); only nudge the
        // sink so it knows we're alive.
        self.state.sink.nudge();
        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now(),
            mtime: now(),
            ctime: now(),
            crtime: now(),
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: *OWNER_UID,
            gid: *OWNER_GID,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        };
        reply.entry(&TTL, &attr, 0);
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let Some(name_str) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        let path = parent_path.join(name_str);
        if self.path_kind(&path) != Some(EntryKind::Blob) {
            return reply.error(libc::ENOENT);
        }
        {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.mark_removed(path.clone());
            inner.inodes.forget(&path);
        }
        let rel = path_to_repo_rel(&path);
        self.state.sink.removed(&rel);
        self.state.sink.nudge();
        reply.ok();
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let Some(name_str) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        let path = parent_path.join(name_str);
        // A live mount root can't be removed: rmdir'ing the empty-genesis graft
        // dir and then creating a file at its path would route the write into
        // the void (m5c residual finding 2b). Refuse with EBUSY before the
        // dir-kind/emptiness checks — the graft point is a busy mount.
        if self.state.is_enabled_mount_root(&path) {
            return reply.error(libc::EBUSY);
        }
        if self.path_kind(&path) != Some(EntryKind::Dir) {
            return reply.error(libc::ENOENT);
        }
        // FUSE does NOT guarantee the directory is empty before calling us, so
        // POSIX requires the filesystem itself to reject a non-empty rmdir with
        // ENOTEMPTY. Enforce it from the live (overlay ∪ tip) view — without
        // this check, marking a populated dir removed orphans its whole subtree
        // exactly like the directory-rename bug did.
        if !self.state.read_dir_entries(&path).is_empty() {
            return reply.error(libc::ENOTEMPTY);
        }
        {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.mark_removed(path.clone());
            inner.inodes.forget(&path);
        }
        self.state.sink.nudge();
        reply.ok();
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let from_parent = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let to_parent = match self.path_of(newparent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let (Some(n1), Some(n2)) = (name.to_str(), newname.to_str()) else {
            return reply.error(libc::EINVAL);
        };
        let from = from_parent.join(n1);
        let to = to_parent.join(n2);
        if self.path_kind(&from).is_none() {
            return reply.error(libc::ENOENT);
        }
        // Neither end may be a live mount root: moving the graft point away
        // detaches the mount, and moving something *onto* it lands an entry at
        // the empty-strip path that reaches no chain's history (m5c residual
        // finding 2b). Refuse with EBUSY.
        if self.state.is_enabled_mount_root(&from) || self.state.is_enabled_mount_root(&to) {
            return reply.error(libc::EBUSY);
        }
        // Key-before-content (m5f slice 001): a rename may not land content in
        // an unkeyed share. The source side stays unguarded — moving *out* is a
        // removal (no blob enters the chain) and doubles as the rescue path for
        // content stranded pre-enforcement.
        if self.refuses_unkeyed_shared_write(&to, "rename") {
            return reply.error(libc::EROFS);
        }
        // renameat2 flags — previously ignored. RENAME_EXCHANGE (atomic swap)
        // is not implemented; reject it rather than silently doing a one-way
        // move. RENAME_NOREPLACE must fail if the destination exists.
        if flags & libc::RENAME_EXCHANGE != 0 {
            return reply.error(libc::ENOSYS);
        }
        if flags & libc::RENAME_NOREPLACE != 0 && self.path_kind(&to).is_some() {
            return reply.error(libc::EEXIST);
        }
        // Delegate to the one dir-aware staging path the MCP-verb rename also
        // uses: it re-keys every live descendant under the new prefix (and
        // materializes each moved file's plaintext into the overlay so the move
        // survives the overlay-clears-on-commit rotation). A lone file is the
        // degenerate single-mover case. The old inline logic was file-only — it
        // read a directory as empty bytes and minted a 0-byte file at `to`,
        // silently dropping the subtree from the next commit.
        if let Err(e) = self.state.stage_rename(&from, &to) {
            eprintln!("keeperd: fuse: rename staging failed: {e}");
            return reply.error(libc::EIO);
        }
        let from_rel = path_to_repo_rel(&from);
        let to_rel = path_to_repo_rel(&to);
        self.state.sink.renamed(&from_rel, &to_rel);
        self.state.sink.nudge();
        reply.ok();
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        // A live mount root can't be staged as a file: both branches below
        // stage `read_bytes` (empty for a dir) as a File overlay entry at
        // `path`, which at a graft point would shadow the whole grafted
        // subtree in `collect_files` and commit the shared chain as an empty
        // tree — silent data loss (m5e slice 007, pre-merge review finding 1;
        // the guard `create`/`rmdir`/`rename` already carry). A
        // timestamp-only setattr stages nothing and passes through.
        if (mode.is_some() || size.is_some()) && self.state.is_enabled_mount_root(&path) {
            return reply.error(libc::EBUSY);
        }
        // Key-before-content (m5f slice 001): both staging branches below
        // insert a File overlay entry — content the unkeyed chain's commit
        // would have to seal — so they get the same refusal as `write`. A
        // timestamp-only setattr stages nothing and passes through.
        if (mode.is_some() || size.is_some())
            && self.refuses_unkeyed_shared_write(&path, "setattr")
        {
            return reply.error(libc::EROFS);
        }
        // Truncate semantics: a setattr with size=0 + an O_TRUNC open
        // flag from the editor.
        if let Some(new_size) = size {
            let mut bytes = self.read_bytes(&path).unwrap_or_default();
            bytes.resize(new_size as usize, 0);
            let cur_mode = self.mode_of(ino).unwrap_or(0o100644);
            let next_mode = mode.unwrap_or(cur_mode);
            {
                let mut inner = self.state.inner.lock().unwrap();
                inner.overlay.insert_file(path.clone(), bytes, next_mode);
            }
            let rel = path_to_repo_rel(&path);
            self.state.sink.modified(&rel);
            self.state.sink.nudge();
        } else if let Some(new_mode) = mode {
            let bytes = self.read_bytes(&path).unwrap_or_default();
            {
                let mut inner = self.state.inner.lock().unwrap();
                inner.overlay.insert_file(path.clone(), bytes, new_mode);
            }
            let rel = path_to_repo_rel(&path);
            self.state.sink.modified(&rel);
            self.state.sink.nudge();
        }
        match self.attr_for_inode(ino) {
            Some(a) => reply.attr(&TTL, &a),
            None => reply.error(libc::ENOENT),
        }
    }
}

// ---- internal helpers ----

impl FuseFs {
    /// M5f slice 001 (key-before-content) — refuse a kernel content op into an
    /// unkeyed shared mount. `true` = refused (the caller replies `EROFS`);
    /// the reason is journal-surfaced here so the user sees more than a bare
    /// errno. Composes with the mount-root `EBUSY` guards: those protect the
    /// graft point structurally, this makes the whole pre-ceremony subtree
    /// read-only until its `S` is established.
    fn refuses_unkeyed_shared_write(&self, path: &Path, op: &str) -> bool {
        match self.state.unkeyed_shared_owner(path) {
            Some(mount) => {
                eprintln!(
                    "keeperd: fuse: {op} {} refused: shared subtree {mount:?} has no \
                     established key yet (key-before-content) — content is accepted only \
                     after the share's key ceremony; run/accept the share ceremony first",
                    path.display()
                );
                true
            }
            None => false,
        }
    }

    fn path_of(&self, ino: u64) -> Option<PathBuf> {
        let inner = self.state.inner.lock().unwrap();
        inner.inodes.path_of(ino).map(|p| p.to_path_buf())
    }

    fn parent_inode(&self, path: &Path) -> u64 {
        if path.as_os_str().is_empty() {
            return ROOT_INODE;
        }
        let parent = path.parent().unwrap_or(Path::new(""));
        let mut inner = self.state.inner.lock().unwrap();
        inner.inodes.intern(parent)
    }

    fn attr_for_child(&self, parent: u64, name: &OsStr) -> Option<FileAttr> {
        let parent_path = self.path_of(parent)?;
        let name_str = name.to_str()?;
        let path = parent_path.join(name_str);
        let ino = {
            let mut inner = self.state.inner.lock().unwrap();
            inner.inodes.intern(&path)
        };
        self.attr_for_path(&path, ino)
    }

    fn attr_for_inode(&self, ino: u64) -> Option<FileAttr> {
        if ino == ROOT_INODE {
            return Some(self.dir_attr(ROOT_INODE, 0o755));
        }
        let path = self.path_of(ino)?;
        self.attr_for_path(&path, ino)
    }

    fn attr_for_path(&self, path: &Path, ino: u64) -> Option<FileAttr> {
        let inner = self.state.inner.lock().unwrap();
        // Overlay takes precedence.
        if let Some(entry) = inner.overlay.get(path) {
            return match entry {
                OverlayEntry::Removed => None,
                OverlayEntry::File { content, mode } => Some(FileAttr {
                    ino,
                    size: content.len() as u64,
                    blocks: (content.len() as u64).div_ceil(BLOCK_SIZE as u64),
                    atime: now(),
                    mtime: now(),
                    ctime: now(),
                    crtime: now(),
                    kind: FileType::RegularFile,
                    perm: (mode & 0o7777) as u16,
                    nlink: 1,
                    uid: *OWNER_UID,
                    gid: *OWNER_GID,
                    rdev: 0,
                    blksize: BLOCK_SIZE,
                    flags: 0,
                }),
                OverlayEntry::Dir { mode } => Some(self.dir_attr(ino, *mode)),
            };
        }
        // Fall back to tip view.
        let entry = inner.view.get(path)?.clone();
        drop(inner);
        Some(match entry.kind {
            EntryKind::Blob => {
                // We don't know the plaintext size without decrypting; do it
                // here (cached by the kernel via TTL).
                let bytes = self.read_bytes(path).unwrap_or_default();
                FileAttr {
                    ino,
                    size: bytes.len() as u64,
                    blocks: (bytes.len() as u64).div_ceil(BLOCK_SIZE as u64),
                    atime: now(),
                    mtime: now(),
                    ctime: now(),
                    crtime: now(),
                    kind: FileType::RegularFile,
                    perm: (entry.mode & 0o7777) as u16,
                    nlink: 1,
                    uid: *OWNER_UID,
                    gid: *OWNER_GID,
                    rdev: 0,
                    blksize: BLOCK_SIZE,
                    flags: 0,
                }
            }
            EntryKind::Dir => self.dir_attr(ino, entry.mode),
        })
    }

    fn dir_attr(&self, ino: u64, mode: u32) -> FileAttr {
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now(),
            mtime: now(),
            ctime: now(),
            crtime: now(),
            kind: FileType::Directory,
            perm: (mode & 0o7777) as u16,
            nlink: 2,
            uid: *OWNER_UID,
            gid: *OWNER_GID,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        // Overlay precedence (in-flight write, not yet committed; if the
        // overlay holds plaintext that just got dropped by a write to a
        // sealed-matching path, we surface the placeholder so a reader
        // never sees the live plaintext after a `nudge` lands a flush).
        {
            let inner = self.state.inner.lock().unwrap();
            if let Some(entry) = inner.overlay.get(path) {
                return match entry {
                    OverlayEntry::File { content, .. } => {
                        if self.is_sealed_path(path) {
                            Ok(sealed_placeholder(path))
                        } else {
                            // Overlay bytes are pre-commit plaintext —
                            // run them through the M2c region redactor
                            // too so live in-flight reads of an
                            // unsaved edit don't leak the freshly-typed
                            // plaintext body. Not cached: overlay
                            // content is mutable until the commit lands.
                            Ok(self.apply_redactions(path, content.clone()))
                        }
                    }
                    _ => Ok(Vec::new()),
                };
            }
        }
        // Tip view: decrypt the blob (unless this path is sealed).
        if self.is_sealed_path(path) {
            return Ok(sealed_placeholder(path));
        }
        // M2c — cache the post-`redact_regions` bytes per path. Cache
        // is broadcast-invalidated on every `tip_changed`.
        if let Some(cached) = self.state.redacted_cache.lock().unwrap().get(path).cloned() {
            return Ok(cached);
        }
        let inner = self.state.inner.lock().unwrap();
        let entry = match inner.view.get(path) {
            Some(e) if e.kind == EntryKind::Blob => e.clone(),
            _ => return Ok(Vec::new()),
        };
        drop(inner);
        let cipher = self.state.objects.get(&entry.target)?;
        // Shared-chain files flow through this union-view read too; the
        // tracked dispatch resolves whichever container sealed the blob.
        let rel_str = path.to_string_lossy().replace('\\', "/");
        let plain = self.state.session.decrypt_tracked_blob(&rel_str, &cipher)?;
        let redacted = self.apply_redactions(path, plain);
        self.state
            .redacted_cache
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), redacted.clone());
        Ok(redacted)
    }

    /// M2c — funnel post-Layer-A plaintext through the daemon's
    /// region redactor (no-op for `None` sealed adapter or paths with
    /// no `<vault>` regions, by virtue of the default-impl identity).
    fn apply_redactions(&self, path: &Path, content: Vec<u8>) -> Vec<u8> {
        let Some(q) = self.state.sealed.as_ref() else {
            return content;
        };
        q.redact_regions(&path_to_repo_rel(path), content)
    }

    fn is_sealed_path(&self, path: &Path) -> bool {
        let Some(q) = self.state.sealed.as_ref() else {
            return false;
        };
        q.is_sealed(&path_to_repo_rel(path))
    }

    fn path_kind(&self, path: &Path) -> Option<EntryKind> {
        let inner = self.state.inner.lock().unwrap();
        if let Some(entry) = inner.overlay.get(path) {
            return match entry {
                OverlayEntry::File { .. } => Some(EntryKind::Blob),
                OverlayEntry::Dir { .. } => Some(EntryKind::Dir),
                OverlayEntry::Removed => None,
            };
        }
        inner.view.get(path).map(|e| e.kind)
    }

    fn mode_of(&self, ino: u64) -> Option<u32> {
        let path = self.path_of(ino)?;
        self.mode_of_path(&path)
    }

    fn mode_of_path(&self, path: &Path) -> Option<u32> {
        let inner = self.state.inner.lock().unwrap();
        if let Some(entry) = inner.overlay.get(path) {
            return match entry {
                OverlayEntry::File { mode, .. } => Some(*mode),
                OverlayEntry::Dir { mode } => Some(*mode),
                OverlayEntry::Removed => None,
            };
        }
        inner.view.get(path).map(|e| e.mode)
    }

    fn list_children(&self, dir: &Path) -> Vec<(PathBuf, FileType)> {
        let inner = self.state.inner.lock().unwrap();
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        // Tip view first.
        for (child_path, entry) in inner.view.children(dir) {
            seen.insert(child_path.to_path_buf());
            // Hidden by overlay removal?
            if matches!(inner.overlay.get(child_path), Some(OverlayEntry::Removed)) {
                continue;
            }
            // Overridden by overlay? (We'll surface the overlay copy
            // below; skip the tip version here to avoid duplicates.)
            if inner.overlay.get(child_path).is_some() {
                continue;
            }
            let ftype = match entry.kind {
                EntryKind::Blob => FileType::RegularFile,
                EntryKind::Dir => FileType::Directory,
            };
            out.push((child_path.to_path_buf(), ftype));
        }
        // Overlay entries (new files + new dirs + overrides).
        for (path, entry) in inner.overlay.iter() {
            if path.parent() != Some(dir) {
                continue;
            }
            if matches!(entry, OverlayEntry::Removed) {
                continue;
            }
            let p = path.to_path_buf();
            if seen.insert(p.clone()) || !seen.contains(&p) {
                // First-time addition.
            }
            let ftype = match entry {
                OverlayEntry::File { .. } => FileType::RegularFile,
                OverlayEntry::Dir { .. } => FileType::Directory,
                OverlayEntry::Removed => unreachable!(),
            };
            // Deduplicate against any tip entry we already pushed.
            if !out.iter().any(|(q, _)| q == &p) {
                out.push((p, ftype));
            }
        }
        out
    }
}

fn now() -> SystemTime {
    SystemTime::now()
}

fn path_to_repo_rel(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Forward-compatible with M2c's inline `<vault id="...">[sealed]</vault>`
/// placeholder mechanism: same shape — a short ASCII marker computed on
/// each read, never persisted — at a different scope (whole-file here,
/// region in M2c).
fn sealed_placeholder(path: &Path) -> Vec<u8> {
    format!("[sealed:{}]\n", path_to_repo_rel(path)).into_bytes()
}

#[allow(dead_code)]
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Reclaim a stale FUSE mount left at `mount_point` by a previously
/// crashed daemon (one that died without running `MountHandle::unmount`).
///
/// Without `AutoUnmount`, the kernel does not auto-reap such a mount; it
/// lingers as a dead endpoint (`ls` → `ENOTCONN`) and a fresh
/// `spawn_mount2` would stack on top of the corpse. We detect an existing
/// `fuse*` mount exactly at `mount_point` and lazily unmount it via the
/// setuid `fusermount3` helper (`-z` so a busy/dead mount still detaches).
/// No-op when nothing is mounted there — the common case.
///
/// Called both from the FUSE mount path (before each `spawn_mount2`) and
/// from `softfig-keeperd`'s startup, *before* `KeeperConfig::discover`
/// reads `keeper.toml` through the garden root — a dead mount there would
/// otherwise make discovery fall back to the wrong (non-FUSE) layout.
pub fn clear_stale_mount(mount_point: &Path) {
    if !is_fuse_mount(mount_point) {
        return;
    }
    // `fusermount3 -u -q -z` is the same unmount path fuser itself uses;
    // `-z` (lazy) handles the dead/busy endpoint. Failure is non-fatal:
    // the subsequent mount will surface any real problem.
    let _ = std::process::Command::new("fusermount3")
        .arg("-u")
        .arg("-q")
        .arg("-z")
        .arg("--")
        .arg(mount_point)
        .status();
}

/// Forcibly release the FUSE mount at `mount_point` so a *busy* mount can
/// never wedge teardown. Two steps, both best-effort and non-fatal:
///
/// 1. **Abort the kernel FUSE connection** (`/sys/fs/fuse/connections/NN/abort`).
///    This makes every in-flight *and* future request fail with `ENOTCONN`
///    immediately — the background worker's blocking `read(/dev/fuse)`, and
///    crucially any *other* process (including the daemon's own threads)
///    parked in uninterruptible **D-state** on a garden read. Without it a
///    busy mount keeps the connection alive and unserviced after the daemon
///    stops responding, freezing every task that touches the garden until
///    systemd's 90 s SIGKILL — the 2026-06-21 incident. This is the
///    programmatic form of the emergency lever `echo 1 > …/abort`.
/// 2. **Lazily detach the mountpoint** (`fusermount3 -u -q -z`, MNT_DETACH)
///    so it leaves the namespace even while busy.
///
/// No-op when nothing is mounted at `mount_point` (the connection id is read
/// from `/proc/self/mountinfo`, which lists nothing there). Safe on an idle
/// mount: the abort drops zero in-flight requests and the detach unmounts it.
pub fn force_release_mount(mount_point: &Path) {
    // Read the connection id BEFORE detaching — mountinfo drops the entry the
    // moment the mount leaves the namespace.
    if let Some(minor) = fuse_conn_minor(mount_point) {
        let _ = std::fs::write(format!("/sys/fs/fuse/connections/{minor}/abort"), b"1");
    }
    clear_stale_mount(mount_point);
}

/// The kernel FUSE connection minor for the `fuse*` filesystem mounted exactly
/// at `target`, if any. Parsed from `/proc/self/mountinfo` field index 2
/// (`major:minor` — `0:NN` for FUSE), the same `NN` exposed under
/// `/sys/fs/fuse/connections/NN/`.
fn fuse_conn_minor(target: &Path) -> Option<u32> {
    let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let target = target.to_string_lossy();
    for line in content.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let mut fields = pre.split_whitespace();
        let dev = fields.nth(2); // index 2: major:minor
        let mount_point = fields.nth(1); // index 4 (one more skipped past index 3)
        let fstype = post.split_whitespace().next().unwrap_or("");
        if mount_point == Some(target.as_ref()) && fstype.starts_with("fuse") {
            return dev
                .and_then(|d| d.split(':').nth(1))
                .and_then(|m| m.parse().ok());
        }
    }
    None
}

/// True if `/proc/self/mountinfo` shows a `fuse*` filesystem mounted
/// exactly at `target`. Garden roots are plain ASCII paths with no spaces
/// (a garden house rule), so the kernel's octal-escaped mountinfo field
/// compares verbatim.
fn is_fuse_mount(target: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let target = target.to_string_lossy();
    for line in content.lines() {
        // mountinfo: `… root mount_point opts … - fstype source superopts`.
        // Field index 4 (0-based) before " - " is the mount point.
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let mount_point = pre.split_whitespace().nth(4);
        let fstype = post.split_whitespace().next().unwrap_or("");
        if mount_point == Some(target.as_ref()) && fstype.starts_with("fuse") {
            return true;
        }
    }
    false
}
