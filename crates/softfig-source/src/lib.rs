//! `softfig-source` — the remote runner's source step (spec remote-runner §4):
//! snapshot a git worktree into an immutable tree, transfer only the missing
//! objects over a have/want bundle, and ingest/verify/materialize it on the
//! runner behind the [`SourceBackend`] trait.
//!
//! Git is implementation #1; the trait and the typed [`SourceId`] /
//! [`repo_key`] carry the format + genesis so a softfig project-VCS backend
//! slots in later without a wire change.
//!
//! This crate holds **no signing secrets** and knows nothing about the Noise
//! transport: it produces and consumes bundle bytes, and the caller
//! (`softfig-net` on the requester, `softfig-runnerd` on the runner) moves them
//! as `SourceHave`/`SourceChunk` frames.

#![forbid(unsafe_code)]

pub mod backend;
pub mod error;
pub mod git;
pub mod repo_key;
pub mod source_id;

pub use backend::{bundle, ref_name, snapshot, GitBackend, SourceBackend};
pub use error::{Error, Result};
pub use git::{
    create_bundle, ingest_bundle, materialize, negotiate_tips, object_format, root_commits,
    snapshot_ref, snapshot_repo, verify_snapshot, HaveTips, RUNNER_GIT_CONFIG,
    SNAPSHOT_AUTHOR_EMAIL, SNAPSHOT_AUTHOR_NAME, SNAPSHOT_MESSAGE, Snapshot, SubmodulePolicy,
    TIP_LIMIT,
};
pub use repo_key::{repo_key, REPO_KEY_DOMAIN};
pub use source_id::{SourceFormat, SourceId};
