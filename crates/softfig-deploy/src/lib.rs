//! soft-fig deploy — **M4a: the static deploy spine** (the toml-bombadil
//! `bombadil link` replacement). Materializes a declarative source→target
//! table out of the garden's `config/` tree onto the real filesystem.
//!
//! The crate is **frontend-neutral** by design (the `softfig-onboard` /
//! M3-actions precedent): [`plan`] + [`apply`] are the whole surface; the
//! `softfig deploy` CLI is a thin wrapper, and a future daemon-mediated
//! `deploy` MCP verb + a TUI deploy screen reuse the same two entry points.
//! Nothing here prompts or reads a TTY.
//!
//! ## The FUSE constraint (why a cache exists)
//!
//! The garden's on-disk store is ciphertext only; plaintext lives **only**
//! in the FUSE mount, which the daemon unmounts whenever the garden locks.
//! So a symlink pointing *straight at a garden source* would dangle the
//! instant the garden locks. The realizable "symlink" is therefore: `apply`
//! (run while unlocked) materializes each source to a **persistent plaintext
//! deploy-cache** (mode `0600`, dir `0700`) and symlinks the target → the
//! cache file — which survives lock, exactly like bombadil's `.dots/`.
//!
//! When a symlink won't do (an app that rejects symlinked configs), a dot
//! can opt into `method = "copy"`, writing the bytes straight to the target
//! with a `# managed by softfig` stamp so a re-deploy can tell its own file
//! from a hand-edited one.
//!
//! ## M4a scope (deliberately thin)
//!
//! * `$HOME` targets only — absolute targets outside `$HOME` are rejected
//!   (the `/etc` slice, with POSIX ACLs / per-service-user ownership, is
//!   deferred).
//! * **Regular-file dots only** — directory dots return
//!   [`DeployError::DirectorySource`] (recursive cache materialization +
//!   the render-per-file interplay land with M4b/dir support).
//! * **No templating, secrets, or posthooks** — those are M4b / M4c. M4a
//!   copies source bytes verbatim.
//!
//! Full design: the garden's `journal/decisions/decision-softfig-m4-impl.md`.

#![forbid(unsafe_code)]

use std::path::PathBuf;

mod apply;
mod config;
mod plan;
mod stamp;

#[cfg(test)]
mod tests;

pub use apply::{apply, ApplyOptions, Report};
pub use config::{DeployConfig, Dot, Method};
pub use plan::{plan, Action, Plan, PlannedEntry};

/// Everything that can go wrong before/while computing or applying a deploy.
#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    /// `config/deploy.toml` is absent. The CLI maps this to an "is the
    /// garden unlocked?" hint — when locked, the FUSE mount (and thus the
    /// config path) is gone.
    #[error("deploy config not found at {0}")]
    ConfigNotFound(PathBuf),
    #[error("deploy config parse error: {0}")]
    ConfigParse(String),
    #[error("dot {name:?}: source not found at {path}")]
    SourceNotFound { name: String, path: PathBuf },
    #[error(
        "dot {name:?}: directory sources are not supported in M4a (file dots only); \
         {path} is a directory"
    )]
    DirectorySource { name: String, path: PathBuf },
    #[error(
        "invalid dot name {0:?}: names must be non-empty, ≤128 bytes, match [A-Za-z0-9._-], \
         and contain no path separators"
    )]
    InvalidName(String),
    #[error("dot {name:?}: invalid target {target:?}: {reason}")]
    InvalidTarget {
        name: String,
        target: String,
        reason: String,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DeployError>;

/// Resolved roots a deploy run operates against. `config_dir` is
/// `<garden_root>/config` (holds `deploy.toml` + `source/`, read through the
/// FUSE plaintext view); `home` is the `$HOME` boundary relative targets
/// resolve against and absolute targets may not escape; `cache_root` is the
/// persistent plaintext deploy-cache base.
#[derive(Debug, Clone)]
pub struct DeployPaths {
    pub config_dir: PathBuf,
    pub home: PathBuf,
    pub cache_root: PathBuf,
}

impl DeployPaths {
    /// `<config_dir>/deploy.toml`.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("deploy.toml")
    }
    /// `<config_dir>/source` — the root every dot's `source` is relative to.
    pub fn source_dir(&self) -> PathBuf {
        self.config_dir.join("source")
    }
}
