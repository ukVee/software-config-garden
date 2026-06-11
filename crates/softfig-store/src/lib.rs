//! soft-fig low-level store.
//!
//! Two halves:
//!
//! * **Object directory** — content-addressed ciphertext blobs at
//!   `.softfig/objects/<aa>/<rest>`, where `aa` is the first byte of the
//!   BLAKE3 hash in lowercase hex and `rest` is the remaining 31 bytes.
//! * **Metadata database** — a single sqlite file at `.softfig/db.sqlite`
//!   holding `meta`, `refs`, `commits`, `trees`, and `tree_entries`.
//!
//! Higher-level VCS semantics (walking the working tree, building trees,
//! creating signed commits, fsck reachability checks) live in `softfig-vcs`
//! on top of this crate.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod db;
pub mod error;
pub mod hash;
pub mod objects;
pub mod paths;

pub use db::{
    put_commit, put_tree, set_ref, CommitRow, Db, RefRow, TreeEntryKind, TreeEntryRow,
    SCHEMA_VERSION,
};
pub use error::{Result, StoreError};
pub use hash::{Hash, HASH_LEN};
pub use objects::{ObjectIter, ObjectStore};
pub use paths::StorePaths;
