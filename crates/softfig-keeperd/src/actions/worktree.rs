//! Mount-safe working-tree access for the M3a garden-write actions.
//!
//! In FUSE mode `garden_root` is the mount this daemon serves, so any
//! `std::fs` read/write/stat/readdir against it **while holding
//! `daemon.inner`** is a self-read/-write of the mount — the 2026-06-21
//! commit-path deadlock (an in-flight FUSE op colliding with the daemon's own
//! blocking I/O wedges the whole garden until SIGKILL). 3a removed the commit
//! self-walk; this is the other half: every per-action working-tree touch goes
//! through here.
//!
//! [`WorkTree::Fuse`] routes reads and writes through the FUSE driver's
//! in-memory (tip ∪ overlay) state with no kernel round-trip; staged writes are
//! captured by the next [`commit_now`](super::commit_now) snapshot.
//! [`WorkTree::Disk`] is the byte-for-byte `std::fs` passthrough for non-FUSE
//! (M1c-compat / direct-CLI) daemons — it also keeps the self-write
//! suppression (`mark_self_write`) the inotify watcher relies on; the FUSE
//! backend needs none (a staged overlay write fires no kernel event).
//!
//! Paths are repo-relative strings (`""` = garden root), the same shape
//! [`conventions`](super::conventions) and the FUSE handlers use.

use std::path::{Path, PathBuf};

use softfig_fuse::MountHandle;
use softfig_ipc::ErrorKind;

use crate::daemon::{Daemon, DaemonInner};

type ActionResult = Result<(), (ErrorKind, String)>;

/// One entry from [`WorkTree::read_dir`].
pub struct DirEntry {
    /// Final path component (file or directory name).
    pub name: String,
    pub is_dir: bool,
}

/// Filesystem access for an M3a action, backed by the FUSE overlay in FUSE
/// mode and by `std::fs` otherwise. See the module docs.
pub enum WorkTree<'a> {
    Disk {
        daemon: &'a Daemon,
        garden_root: &'a Path,
    },
    Fuse {
        mount: &'a MountHandle,
    },
}

impl<'a> WorkTree<'a> {
    /// Pick the backend from the daemon state: the FUSE mount when one is live,
    /// else the on-disk garden root. Borrows `inner` (the mount / garden root)
    /// and `daemon` (the suppression map) immutably, so it coexists with the
    /// `&DaemonInner` the action's other helpers take and must be dropped
    /// before the trailing `&mut inner` commit.
    pub fn new(daemon: &'a Daemon, inner: &'a DaemonInner) -> WorkTree<'a> {
        match inner.fuse.as_ref() {
            Some(mount) => WorkTree::Fuse { mount },
            None => WorkTree::Disk {
                daemon,
                garden_root: &inner.config.garden_root,
            },
        }
    }

    fn abs(garden_root: &Path, rel: &str) -> PathBuf {
        garden_root.join(rel)
    }

    /// Working-tree bytes for repo-relative `rel`, or `None` if absent /
    /// unreadable / a directory.
    pub fn read(&self, rel: &str) -> Option<Vec<u8>> {
        match self {
            WorkTree::Disk { garden_root, .. } => std::fs::read(Self::abs(garden_root, rel)).ok(),
            WorkTree::Fuse { mount } => mount.read_workfile(rel).ok().flatten(),
        }
    }

    /// Working-tree bytes as UTF-8, or `None` if absent / unreadable / not text.
    pub fn read_to_string(&self, rel: &str) -> Option<String> {
        self.read(rel).and_then(|b| String::from_utf8(b).ok())
    }

    /// Whether `rel` resolves to a live file or directory.
    pub fn exists(&self, rel: &str) -> bool {
        match self {
            WorkTree::Disk { garden_root, .. } => Self::abs(garden_root, rel).exists(),
            WorkTree::Fuse { mount } => mount.path_exists(rel),
        }
    }

    /// Whether `rel` is a directory.
    pub fn is_dir(&self, rel: &str) -> bool {
        match self {
            WorkTree::Disk { garden_root, .. } => Self::abs(garden_root, rel).is_dir(),
            WorkTree::Fuse { mount } => mount.path_is_dir(rel),
        }
    }

    /// One-level children of directory `rel` (`""` = garden root). Empty when
    /// the directory is absent. Order is unspecified — callers sort.
    pub fn read_dir(&self, rel: &str) -> Vec<DirEntry> {
        match self {
            WorkTree::Disk { garden_root, .. } => {
                let mut out = Vec::new();
                if let Ok(rd) = std::fs::read_dir(Self::abs(garden_root, rel)) {
                    for e in rd.flatten() {
                        let Ok(name) = e.file_name().into_string() else {
                            continue;
                        };
                        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                        out.push(DirEntry { name, is_dir });
                    }
                }
                out
            }
            WorkTree::Fuse { mount } => mount
                .read_dir_entries(rel)
                .into_iter()
                .map(|(name, is_dir)| DirEntry { name, is_dir })
                .collect(),
        }
    }

    /// M5f slice 001 (key-before-content): refuse an action-verb write landing
    /// under an enabled shared mount whose key ceremony has not run yet. The
    /// commit path's `encrypt_for_ref` backstop would refuse to seal it anyway,
    /// but only after staging — leaving the overlay holding content whose
    /// chain can't advance, and failing the verb *after* its device-chain
    /// commit. Refusing here surfaces the clear error to the caller with
    /// nothing staged. Disk mode has no shared chains (`add` refuses in direct
    /// mode), so only the FUSE arm can trip.
    fn refuse_unkeyed_shared(&self, rel: &str) -> ActionResult {
        if let WorkTree::Fuse { mount } = self {
            if let Some(share) = mount.unkeyed_shared_owner(rel) {
                return Err((
                    ErrorKind::SharedChainUnkeyed,
                    format!(
                        "{rel} is inside shared subtree {share:?}, which has no established \
                         key yet (key-before-content): content is accepted only after the \
                         share's key ceremony — run/accept the ceremony first"
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Create-or-overwrite repo-relative `rel`. Disk: create parent dirs +
    /// register the path for self-write suppression so the watcher drops the
    /// event, then write. FUSE: stage into the overlay (no kernel event).
    pub fn write(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        self.refuse_unkeyed_shared(rel)?;
        match self {
            WorkTree::Disk { daemon, garden_root } => {
                let abs = Self::abs(garden_root, rel);
                daemon.mark_self_write(abs.clone());
                super::write_file(&abs, bytes)
            }
            WorkTree::Fuse { mount } => {
                mount.stage_write(rel, bytes.to_vec());
                Ok(())
            }
        }
    }

    /// Rename `from` → `to` (file or directory). Disk: `std::fs::rename` with
    /// both sides suppressed and the destination parent created. FUSE: re-key
    /// the overlay (descendants included). The destination gets the
    /// key-before-content refusal (m5f slice 001); the source side stays
    /// unguarded — moving *out* of an unkeyed share adds no blob to it.
    pub fn rename(&self, from: &str, to: &str) -> ActionResult {
        self.refuse_unkeyed_shared(to)?;
        match self {
            WorkTree::Disk { daemon, garden_root } => {
                let from_abs = Self::abs(garden_root, from);
                let to_abs = Self::abs(garden_root, to);
                daemon.mark_self_write(from_abs.clone());
                daemon.mark_self_write(to_abs.clone());
                if let Some(parent) = to_abs.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| (ErrorKind::Io, e.to_string()))?;
                }
                std::fs::rename(&from_abs, &to_abs)
                    .map_err(|e| (ErrorKind::Io, format!("rename: {e}")))
            }
            WorkTree::Fuse { mount } => mount
                .stage_rename(from, to)
                .map_err(|e| (ErrorKind::Io, format!("stage rename: {e}"))),
        }
    }

    /// Recursively remove repo-relative `rel` (a file or a whole directory).
    /// Disk: `std::fs` remove with self-write suppression; an already-absent
    /// path is a no-op. FUSE: stage a recursive removal marker into the overlay
    /// (captured by the next [`commit_now`](super::commit_now)). The m5f slice
    /// 004 `migrate-into-share` device-side carve-out — run only AFTER the
    /// content is durably re-committed into the shared chain — is the only
    /// caller today; a removal carries no key-before-content concern (it strips
    /// a blob, never adds one), so no `refuse_unkeyed_shared` guard is needed.
    pub fn remove(&self, rel: &str) -> ActionResult {
        match self {
            WorkTree::Disk { daemon, garden_root } => {
                let abs = Self::abs(garden_root, rel);
                daemon.mark_self_write(abs.clone());
                if abs.is_dir() {
                    std::fs::remove_dir_all(&abs)
                        .map_err(|e| (ErrorKind::Io, format!("remove_dir_all {rel}: {e}")))
                } else {
                    match std::fs::remove_file(&abs) {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(e) => Err((ErrorKind::Io, format!("remove_file {rel}: {e}"))),
                    }
                }
            }
            WorkTree::Fuse { mount } => {
                mount.stage_remove(rel);
                Ok(())
            }
        }
    }
}

/// The minimal working-tree surface a `.seq`-numbered doc store needs: read a
/// file, list a directory, test existence, stage a write. Implemented by
/// [`WorkTree`] for live daemons and by an in-memory fake in unit tests, so the
/// numbered-store machinery ([`super::numbering`] + the growlight chat store)
/// can be exercised with no daemon/mount behind it. The four methods mirror the
/// inherent [`WorkTree`] methods of the same name; generic store code binds to
/// the trait, concrete daemon code keeps calling the inherent methods.
pub trait Tree {
    fn read_to_string(&self, rel: &str) -> Option<String>;
    fn read_dir(&self, rel: &str) -> Vec<DirEntry>;
    fn exists(&self, rel: &str) -> bool;
    fn write(&self, rel: &str, bytes: &[u8]) -> ActionResult;
}

impl Tree for WorkTree<'_> {
    fn read_to_string(&self, rel: &str) -> Option<String> {
        WorkTree::read_to_string(self, rel)
    }
    fn read_dir(&self, rel: &str) -> Vec<DirEntry> {
        WorkTree::read_dir(self, rel)
    }
    fn exists(&self, rel: &str) -> bool {
        WorkTree::exists(self, rel)
    }
    fn write(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        WorkTree::write(self, rel, bytes)
    }
}
