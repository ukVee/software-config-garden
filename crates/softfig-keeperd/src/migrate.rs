//! `softfig migrate` daemon-side orchestration.
//!
//! Phase 1 (`prepare`) is a CLI-only step — it doesn't talk to the
//! daemon. The CLI copies `.softfig/` to the new state root and writes
//! `keeper.toml`. Code lives in `softfig-cli::cmd_migrate`.
//!
//! Phase 3 (`finalize`) is daemon-orchestrated and lives here. It
//! requires a running, FUSE-mounted M2a daemon:
//!
//! 1. Unmount the live FUSE filesystem (so the orphan plaintext under
//!    `garden_root/` becomes visible again).
//! 2. Best-effort delete every plaintext file under `garden_root/`
//!    EXCEPT the `.softfig/` subdir.
//! 3. Best-effort delete the old `garden_root/.softfig/`.
//! 4. Remount FUSE.
//!
//! Per the locked open-question #2 lean: deletion is best-effort. We
//! collect skipped paths into the reply and return success as long as
//! the unmount + remount worked. Orphan plaintext under the FUSE mount
//! is harmless (the mount-over hides it); the user can re-run
//! `finalize` later or clean up manually.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MigrateFinalizeArgs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateFinalizeReply {
    pub unmounted: bool,
    pub plaintext_deleted: usize,
    pub plaintext_skipped: Vec<String>,
    pub old_state_deleted: bool,
    pub old_state_skipped: Vec<String>,
    pub remounted: bool,
}

/// Recursively delete everything under `dir` except entries whose
/// top-level name matches `skip_top`. Collect failures into the
/// `skipped` list rather than aborting.
pub fn delete_tree_except(
    dir: &Path,
    skip_top: &[&str],
    skipped: &mut Vec<String>,
) -> usize {
    let mut deleted = 0;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            skipped.push(format!("{}: {e}", dir.display()));
            return 0;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if skip_top
            .iter()
            .any(|s| name.to_string_lossy().as_ref() == *s)
        {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                skipped.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        if ft.is_dir() {
            match std::fs::remove_dir_all(&path) {
                Ok(_) => deleted += 1,
                Err(e) => skipped.push(format!("{}: {e}", path.display())),
            }
        } else {
            match std::fs::remove_file(&path) {
                Ok(_) => deleted += 1,
                Err(e) => skipped.push(format!("{}: {e}", path.display())),
            }
        }
    }
    deleted
}

/// Remove an entire directory tree. Returns `(success, skipped)`.
pub fn delete_dir(path: &Path) -> (bool, Vec<String>) {
    if !path.exists() {
        return (true, Vec::new());
    }
    match std::fs::remove_dir_all(path) {
        Ok(_) => (true, Vec::new()),
        Err(e) => (false, vec![format!("{}: {e}", path.display())]),
    }
}

#[allow(dead_code)]
pub(crate) fn _placeholder_path() -> PathBuf {
    PathBuf::new()
}
