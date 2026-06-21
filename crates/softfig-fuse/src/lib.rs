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

    /// Called by `commit_workdir`'s registered tip-changed hook. Drops
    /// the in-memory write overlay (now subsumed by the new tip),
    /// rebuilds the tree-at-tip cache from the new tip, and broadcasts
    /// `inval_inode` so kernel page cache stops returning stale data.
    pub fn on_tip_changed(&self) {
        self.state.rotate_tip();
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
