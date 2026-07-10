//! soft-fig VCS core.
//!
//! Sits on top of `softfig-store` (objects + sqlite metadata) and
//! `softfig-vault` (encryption + identity). Owns the working-tree walker,
//! tree builder, commit construction + signing, log iteration, and fsck.
//!
//! The CLI in `softfig-cli` is a thin wrapper around `Repo`. The future
//! daemon (M1c) will sit at the same `Repo` API and add filesystem
//! watching, intent auto-classification, and IPC.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod chain;
pub mod commit;
pub mod error;
pub mod fsck;
pub mod gc;
pub mod ignore;
pub mod intent;
pub mod log;
pub mod repo;
pub mod tree;
pub mod walk;

pub use chain::{Chain, ChainId, ChainKind, ChainRegistry, DEVICE_CHAIN_ID};
pub use commit::{verify_commit, CanonicalCommit};
pub use error::{CoreError, Result};
pub use fsck::{run as fsck, run_chain as fsck_chain, FsckReport};
pub use gc::{gc, live_blobs, reachable_from, GcReport, Reachable};
pub use ignore::{is_ignored, Ignore, IGNORE_FILE, IGNORED_TOP_LEVEL};
pub use intent::{Intent, KNOWN_INTENTS};
pub use log::{collect as log_collect, LogIter};
pub use repo::{Repo, TipChangedCallback, TIP_REF};
pub use tree::{canonical_tree_bytes, BlobEncryptor, Blueprint, LayerAEncryptor};
pub use walk::{walk, walk_filtered, TreeNode, WalkSnapshot};
