//! On-disk layout under `<state_root>/.softfig/`.
//!
//! ```text
//! .softfig/
//!   db.sqlite                     -- metadata (commits, trees, refs)
//!   objects/
//!     <aa>/<rest>                 -- ciphertext blobs, BLAKE3-addressed
//!   vault/                        -- owned by softfig-vault, untouched here
//! ```
//!
//! In M1c-compat mode the state root IS the garden root, so `.softfig/`
//! lives directly inside the user-visible garden. In M2a mode the daemon
//! relocates state to `~/.local/share/softfig/<repo_id>/` and mounts the
//! garden as a FUSE filesystem; reads of `.softfig/` then route to the
//! state root, not the mount.

use std::path::{Path, PathBuf};

use crate::hash::Hash;

pub const SOFTFIG_DIR: &str = ".softfig";
pub const DB_FILE: &str = "db.sqlite";
pub const OBJECTS_DIR: &str = "objects";

#[derive(Debug, Clone)]
pub struct StorePaths {
    pub garden_root: PathBuf,
    /// Directory containing the on-disk `.softfig/` tree. M1c default
    /// equals `garden_root`; M2a relocates it (see module docs).
    pub state_root: PathBuf,
}

impl StorePaths {
    /// M1c-compat: `.softfig/` sits inside the garden root.
    pub fn for_garden(garden_root: &Path) -> Self {
        Self {
            garden_root: garden_root.to_path_buf(),
            state_root: garden_root.to_path_buf(),
        }
    }

    /// M2a: `.softfig/` sits at `state_root/.softfig/`, garden root is
    /// the FUSE mount point (or the still-present pre-FUSE plaintext
    /// during the migration window).
    pub fn with_state_root(garden_root: &Path, state_root: &Path) -> Self {
        Self {
            garden_root: garden_root.to_path_buf(),
            state_root: state_root.to_path_buf(),
        }
    }

    pub fn softfig_dir(&self) -> PathBuf {
        self.state_root.join(SOFTFIG_DIR)
    }

    pub fn db_path(&self) -> PathBuf {
        self.softfig_dir().join(DB_FILE)
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.softfig_dir().join(OBJECTS_DIR)
    }

    pub fn object_path(&self, hash: &Hash) -> PathBuf {
        let hex = hash.to_hex();
        let (head, tail) = hex.split_at(2);
        self.objects_dir().join(head).join(tail)
    }

    /// True if a metadata DB exists at the expected path.
    pub fn exists(&self) -> bool {
        self.db_path().exists()
    }
}
