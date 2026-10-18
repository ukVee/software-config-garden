//! Source-transfer and skeleton errors.

use std::io;

/// Top-level error for `softfig-source`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("git {cmd} failed: {stderr}")]
    Git { cmd: String, stderr: String },

    #[error("source id: {0}")]
    SourceId(String),

    #[error("the tree contains gitlinks (submodules), which v1 does not ship")]
    Gitlink,

    #[error("source mismatch: {0}")]
    SourceMismatch(String),

    #[error("bundle: {0}")]
    Bundle(String),

    #[error("skeleton: {0}")]
    Skeleton(String),
}

pub type Result<T> = std::result::Result<T, Error>;
