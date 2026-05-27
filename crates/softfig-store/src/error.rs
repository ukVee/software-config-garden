use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store is not initialized at {0}")]
    NotInitialized(std::path::PathBuf),

    #[error("store is already initialized at {0}")]
    AlreadyInitialized(std::path::PathBuf),

    #[error("unsupported store schema version: {0}")]
    UnsupportedSchema(u32),

    #[error("object {0} not found")]
    ObjectNotFound(crate::Hash),

    #[error("object {expected} present on disk but its content hashes to {actual}")]
    ObjectCorrupt {
        expected: crate::Hash,
        actual: crate::Hash,
    },

    #[error("commit {0} not found")]
    CommitNotFound(crate::Hash),

    #[error("tree {0} not found")]
    TreeNotFound(crate::Hash),

    #[error("ref {0} not set")]
    RefNotSet(String),

    #[error("malformed hex hash: {0}")]
    BadHashHex(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;
