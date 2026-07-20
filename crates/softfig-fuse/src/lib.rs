//! soft-fig FUSE plaintext-view of the encrypted Layer A working tree.
//!
//! Mounts a userspace filesystem at `garden_root` (the user-visible
//! mount point) backed by:
//!
//! * `softfig-store::ObjectStore` for ciphertext blob lookup,
//! * `softfig-vault::VaultSession` for blob decryption,
//! * `softfig-store::Db` (read-only secondary connection) for the
//!   current tip's tree rows,
//! * an in-memory write overlay buffering changes until the daemon's
//!   M1d `DirtySetAccumulator` flushes them into a commit.
//!
//! The mount handle owns a `fuser::BackgroundSession`; dropping the
//! handle unmounts the FS. The daemon binds the lifecycle to its state
//! machine — mount on `Locked → Unlocked`, unmount on entry to
//! `Stopping`, and remount inside `migrate_finalize`'s
//! unmount → delete → remount dance.
//!
//! Public surface: [`FuseMount::mount`] returns a [`MountHandle`]; the
//! handle exposes [`MountHandle::on_tip_changed`] for the
//! `commit_workdir` callback registered by the daemon, and
//! [`MountHandle::push_callbacks`] so the daemon can wire dirty events
//! straight into its M1d `DirtySetAccumulator`.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

mod fs;
mod inodes;
mod overlay;
mod tree_view;

pub use fs::{clear_stale_mount, force_release_mount, FuseMount};

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FuseError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] softfig_store::StoreError),
    #[error("vault: {0}")]
    Vault(#[from] softfig_vault::VaultError),
    #[error("core: {0}")]
    Core(#[from] softfig_vcs::CoreError),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, FuseError>;

/// Callbacks the FUSE driver fires when the kernel reports an event
/// that should land in the next commit. The daemon implements this by
/// pushing into its M1d `DirtySetAccumulator` (with a deadline that
/// triggers `accumulator.flush()` after the M1d 200 ms quiet window).
pub trait DirtyEventSink: Send + Sync + 'static {
    fn created(&self, repo_relative: &str);
    fn modified(&self, repo_relative: &str);
    fn removed(&self, repo_relative: &str);
    fn renamed(&self, from_repo_relative: &str, to_repo_relative: &str);
    /// Hint that the FS has been quiet for a moment and the
    /// accumulator can flush. The daemon usually wires this to a
    /// debounced flush; the FS calls it after each handler returns so
    /// the daemon can decide.
    fn nudge(&self);
}

/// M2b adapter: lets the FUSE read path ask the daemon "is this path
/// sealed?" so it can return a `[sealed:<path>]\n` placeholder marker
/// instead of decrypted Layer A bytes. Implementation lives in
/// `softfig-keeperd` (so this crate stays vault-ignorant).
///
/// `None` semantics: no Layer B in the system, all reads return Layer A
/// plaintext (M2a-equivalent behavior).
///
/// M2c extends this with [`SealedQuery::redact_regions`] — the
/// post-Layer-A read hook that walks inline `<vault id="…">…</vault>`
/// tags and replaces each ciphertext body with the literal
/// `[encrypted]` placeholder. Default impl is identity so M2a/M2b-only
/// callers and tests are unaffected.
pub trait SealedQuery: Send + Sync + 'static {
    /// True if `repo_relative` is currently sealed (matches a glob in
    /// `sealed-paths.toml`).
    fn is_sealed(&self, repo_relative: &str) -> bool;

    /// M2c read-path hook: rewrite `content` (Layer A decrypted bytes
    /// for a NON-whole-file-sealed path) so every region body is
    /// projected as `[encrypted]`. Whole-file-sealed paths are handled
    /// upstream by [`SealedQuery::is_sealed`] + the
    /// `[sealed:<path>]\n` placeholder — implementations should
    /// short-circuit and return `content` unchanged for those.
    ///
    /// Default impl is identity (returns `content` unchanged), so
    /// M2a/M2b callers that don't care about inline tags need not
    /// change.
    fn redact_regions(&self, _repo_relative: &str, content: Vec<u8>) -> Vec<u8> {
        content
    }
}

/// Owns the FUSE background session. Drop = unmount.
pub struct MountHandle {
    /// `Some` while mounted; `None` after [`MountHandle::unmount`].
    background: Mutex<Option<fuser::BackgroundSession>>,
    state: Arc<fs::SharedState>,
    mount_point: PathBuf,
}

impl std::fmt::Debug for MountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountHandle")
            .field("mount_point", &self.mount_point)
            .field("mounted", &self.background.lock().unwrap().is_some())
            .finish()
    }
}

impl MountHandle {
    pub fn mount_point(&self) -> &std::path::Path {
        &self.mount_point
    }

    /// Rebuild the union view from every chain's tip after an **external** ref
    /// advance (one not driven through `commit_snapshot_to`, e.g. a future
    /// network pull). It carries no local overlay snapshot, so it advances with
    /// no absorption cutoff and drops nothing — a ref moving forward with no
    /// accompanying local capture must never absorb a staged local write it
    /// never contained (slice 012; the m5e `shared_pull` shape). Commits made
    /// through `commit_snapshot_to` instead fire the repo's `tip_changed` hook,
    /// which threads that commit's own snapshot generation as the cutoff.
    pub fn on_tip_changed(&self, advanced_ref: &str) {
        self.state.rotate_tip(Some(advanced_ref), None);
    }

    /// The refs of every chain owning at least one staged overlay write or
    /// removal — the chains a commit must advance for the pending overlay to
    /// be fully absorbed. The keeperd action-verb commit path routes through
    /// this so a staged write under a shared mount commits to the owning
    /// chain instead of vanishing via the device carve-out (slice 006).
    pub fn pending_chain_refs(&self) -> Vec<String> {
        self.state.pending_chain_refs()
    }

    /// Reconstruct the current working tree (committed tip-view ∪ pending
    /// write overlay) as a [`softfig_vcs::WalkSnapshot`], purely from the
    /// FUSE driver's in-memory state — never reading back through the
    /// mount it serves.
    ///
    /// The daemon (slice 3) feeds the result straight to
    /// [`softfig_vcs::Repo::commit_snapshot`] so a FUSE-mode commit can't
    /// self-read the mount under the daemon's lock (the 2026-06-21
    /// commit-path deadlock). In M2a this matches
    /// `softfig_vcs::walk(mount_point)` exactly; see
    /// `SharedState::workdir_snapshot` for the full rule-parity contract.
    pub fn workdir_snapshot(&self) -> Result<softfig_vcs::WalkSnapshot> {
        self.state.workdir_snapshot()
    }

    /// M5c slice 002 — one commit snapshot per enabled chain (`(ref_name,
    /// snapshot)`), routed by the mount's [`softfig_vcs::ChainRegistry`]: the
    /// device chain carved to device-owned paths, each shared chain's subtree
    /// with the mount prefix stripped. The keeperd commit path commits each
    /// affected chain's snapshot to its own ref, so a write under a shared mount
    /// never advances the device ref. `device_only` ⇒ a single `(TIP_REF, …)`
    /// snapshot equal to [`Self::workdir_snapshot`].
    pub fn chain_snapshots(&self) -> Result<Vec<(String, softfig_vcs::WalkSnapshot)>> {
        self.state.chain_snapshots()
    }

    /// A clone of the chain registry this mount serves, for the commit path to
    /// route dirty paths ([`softfig_vcs::ChainRegistry::owning_chain`]) to the
    /// set of chains a flush must commit.
    pub fn registry(&self) -> softfig_vcs::ChainRegistry {
        self.state.registry()
    }

    /// M5c slice 003 — hot-swap the chain registry this mount serves and
    /// recompose the union view live. The keeperd shared-subtree lifecycle verbs
    /// call this after an add/remove membership commit or an enable/disable local
    /// toggle, so the mounted garden reflects the new composition immediately with
    /// no remount (a remount would tear down + drop the pending write overlay).
    pub fn set_registry(&self, registry: softfig_vcs::ChainRegistry) {
        self.state.set_registry(registry);
    }

    /// The exclusion set (built-in defaults ∪ the user `.softfigignore`) in
    /// force for this garden, reconstructed from the FUSE driver's in-memory
    /// state (overlay precedence, else the committed tip blob) — never read
    /// back through the mount it serves.
    ///
    /// The keeperd watcher caches the result so its dirty-set `accept()` filter
    /// can drop user-ignored paths *on the fuser worker thread* without a
    /// `std::fs`-read of `<mount>/.softfigignore`, whose kernel LOOKUP only the
    /// same blocked worker could service — the self-walk-under-mount reentrant
    /// deadlock (audit slice 003). The daemon refreshes its cache from here
    /// whenever `.softfigignore` changes; the edit is already in the overlay
    /// before the `DirtyEventSink` fires, so the returned set reflects it.
    pub fn inmem_ignore(&self) -> Result<softfig_vcs::ignore::Ignore> {
        self.state.inmem_ignore()
    }

    // ===== Overlay-staging + in-memory queries (slice 3b) =====
    //
    // The daemon's M3a write verbs route their working-tree reads and writes
    // through these instead of `std::fs`-ing `garden_root` (= the mount this
    // daemon serves) while holding `daemon.inner` — the 2026-06-21 deadlock.
    // All operate on the in-memory (tip ∪ overlay) state with no kernel
    // round-trip; staged writes are committed by the next `workdir_snapshot`
    // and do not fire the `DirtyEventSink`. Paths are repo-relative (`""` =
    // root). See [`fs::SharedState`] for the precedence contract.

    /// Raw working-tree bytes for `rel` (overlay ∪ tip), or `None` if absent
    /// or a directory.
    pub fn read_workfile(&self, rel: &str) -> Result<Option<Vec<u8>>> {
        self.state.read_workfile(std::path::Path::new(rel))
    }

    /// Whether `rel` resolves to a live file or directory.
    pub fn path_exists(&self, rel: &str) -> bool {
        self.state.path_exists(std::path::Path::new(rel))
    }

    /// Whether `rel` is a directory (overlay `Dir` or committed tip node).
    pub fn path_is_dir(&self, rel: &str) -> bool {
        self.state.path_is_dir(std::path::Path::new(rel))
    }

    /// One-level children of directory `rel` as `(file_name, is_dir)`.
    pub fn read_dir_entries(&self, rel: &str) -> Vec<(String, bool)> {
        self.state.read_dir_entries(std::path::Path::new(rel))
    }

    /// Every live, ignore-filtered, repo-relative file path (forward-slash
    /// strings) — the same set the next [`Self::workdir_snapshot`] commits. The
    /// daemon filters this by the sealed matcher to enumerate sealed files
    /// without walking the mount under `inner`.
    pub fn live_repo_paths(&self) -> Result<Vec<String>> {
        self.state.live_repo_paths()
    }

    /// M5f slice 001 (key-before-content) — the mount path of the enabled
    /// shared chain that owns `rel` while still unkeyed (pre-ceremony), or
    /// `None`. The keeperd action-verb staging (`actions::worktree`) consults
    /// this to refuse up front — mirroring the kernel ops' `EROFS` guard — so
    /// a verb write into an unkeyed share errors cleanly instead of staging
    /// content the commit path must then refuse to seal.
    pub fn unkeyed_shared_owner(&self, rel: &str) -> Option<String> {
        self.state.unkeyed_shared_owner(std::path::Path::new(rel))
    }

    /// Stage a create-or-overwrite into the overlay (mode preserved on
    /// overwrite, else `0o100644`).
    pub fn stage_write(&self, rel: &str, content: Vec<u8>) {
        self.state.stage_write(std::path::Path::new(rel), content)
    }

    /// Stage a file-or-directory rename into the overlay.
    pub fn stage_rename(&self, from: &str, to: &str) -> Result<()> {
        self.state
            .stage_rename(std::path::Path::new(from), std::path::Path::new(to))
    }

    /// Tear down the FUSE session. Idempotent — a second call is a no-op.
    ///
    /// Before dropping the `BackgroundSession`, forcibly release the kernel
    /// mount/connection ([`force_release_mount`]): abort the connection so the
    /// background worker's `read` returns and nothing stays parked in D-state
    /// on a *busy* mount, then lazily detach the mountpoint. Without this, a
    /// SIGTERM/stop delivered while the garden is busy (a cwd inside it, the
    /// growlight loop, in-flight reads) wedged the daemon until systemd's 90 s
    /// SIGKILL — the 2026-06-21 incident.
    pub fn unmount(&self) {
        let Some(bg) = ({ self.background.lock().unwrap().take() }) else {
            return;
        };
        fs::force_release_mount(&self.mount_point);
        drop(bg);
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        self.unmount();
    }
}
