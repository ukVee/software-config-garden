//! The [`SourceBackend`] trait (spec remote-runner §4.5) and its git
//! implementation.
//!
//! The runner is VCS-neutral by construction: a backend negotiates the
//! have/want tips for a repo key, ingests a requester-supplied payload, verifies
//! the ingested tree against the typed source id, and materializes it into a
//! directory. Git is implementation #1 ([`GitBackend`]); a softfig project-VCS
//! backend (`softfig-blake3-v1`) slots in behind the same trait with no wire
//! change — the source id and repo key already carry the format/genesis.

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::git::{
    create_bundle, ingest_bundle, materialize, negotiate_tips, snapshot_ref, verify_snapshot,
    HaveTips, Snapshot,
};
use crate::source_id::SourceId;

/// The runner-side view of a source backend (spec §4.5): how a runner stores,
/// verifies and materializes a requester's immutable tree for a repo key.
pub trait SourceBackend {
    /// The tips this backend holds for `repo_key` (bounded), for have/want.
    fn negotiate(&self, repo_key: &[u8; 32]) -> Result<HaveTips>;

    /// Ingest a requester payload (a git bundle, today) into the mirror for
    /// `repo_key` + `source_id`.
    fn ingest(&self, repo_key: &[u8; 32], source_id: &SourceId, payload: &[u8]) -> Result<()>;

    /// Verify the ingested snapshot: the mirror's snapshot ref points at
    /// `snapshot_commit`, whose tree is `source_id`.
    fn verify(
        &self,
        repo_key: &[u8; 32],
        source_id: &SourceId,
        snapshot_commit: &[u8],
    ) -> Result<()>;

    /// Materialize the snapshot into `dir`.
    fn materialize(
        &self,
        repo_key: &[u8; 32],
        source_id: &SourceId,
        snapshot_commit: &[u8],
        dir: &Path,
        git_metadata: bool,
    ) -> Result<()>;
}

/// The git backend: one bare mirror per repo key under `repos_dir`
/// (`/var/lib/softfig-runner/repos/<repo_key>.git`), per spec §4.3.
#[derive(Debug, Clone)]
pub struct GitBackend {
    repos_dir: PathBuf,
}

impl GitBackend {
    pub fn new(repos_dir: impl Into<PathBuf>) -> Self {
        Self {
            repos_dir: repos_dir.into(),
        }
    }

    /// The bare mirror path for a repo key.
    pub fn mirror(&self, repo_key: &[u8; 32]) -> PathBuf {
        self.repos_dir.join(format!("{}.git", hex::encode(repo_key)))
    }
}

impl SourceBackend for GitBackend {
    fn negotiate(&self, repo_key: &[u8; 32]) -> Result<HaveTips> {
        negotiate_tips(&self.mirror(repo_key))
    }

    fn ingest(&self, repo_key: &[u8; 32], source_id: &SourceId, payload: &[u8]) -> Result<()> {
        ingest_bundle(&self.mirror(repo_key), source_id, payload)
    }

    fn verify(
        &self,
        repo_key: &[u8; 32],
        source_id: &SourceId,
        snapshot_commit: &[u8],
    ) -> Result<()> {
        verify_snapshot(&self.mirror(repo_key), source_id, snapshot_commit)
    }

    fn materialize(
        &self,
        repo_key: &[u8; 32],
        source_id: &SourceId,
        snapshot_commit: &[u8],
        dir: &Path,
        git_metadata: bool,
    ) -> Result<()> {
        materialize(
            &self.mirror(repo_key),
            source_id,
            snapshot_commit,
            dir,
            git_metadata,
        )
    }
}

// The requester-side mirror image of the backend: snapshot a worktree, fold
// the device id + genesis into a repo key, and build a have/want bundle. These
// are pure functions (the requester runs them in its own repo, no sandbox) and
// are re-exported from `crate::git`.

/// Snapshot a worktree (requester side).
pub fn snapshot(repo: &Path, submodules: crate::git::SubmodulePolicy) -> Result<Snapshot> {
    crate::git::snapshot_repo(repo, submodules)
}

/// Build a have/want bundle (requester side), re-exported for the CLI.
pub fn bundle(
    repo: &Path,
    source_id: &SourceId,
    commit: &[u8],
    haves: &[Vec<u8>],
) -> Result<Vec<u8>> {
    create_bundle(repo, source_id, commit, haves)
}

/// The runner-side snapshot ref for a source id (re-exported so runnerd names
/// the ref in its `SourceHave`/`SourceChunk` handling).
pub fn ref_name(source_id: &SourceId) -> String {
    snapshot_ref(source_id)
}
