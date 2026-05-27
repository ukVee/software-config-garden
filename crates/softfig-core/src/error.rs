use thiserror::Error;
use softfig_store::Hash;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("vault not initialized at {0} — run `softfig vault init` first")]
    VaultMissing(std::path::PathBuf),

    #[error("repository not initialized at {0} — run `softfig init`")]
    RepoMissing(std::path::PathBuf),

    #[error("repository already initialized at {0}")]
    RepoExists(std::path::PathBuf),

    #[error("unknown intent {0:?}; closed enum is {1}")]
    UnknownIntent(String, &'static str),

    #[error("intent {intent} payload must be a JSON object, got {got}")]
    PayloadNotObject {
        intent: String,
        got: &'static str,
    },

    #[error("commit signature invalid for {0}")]
    BadSignature(Hash),

    #[error("commit hash mismatch: row says {row}, derived {derived}")]
    CommitHashMismatch { row: Hash, derived: Hash },

    #[error("tree hash mismatch: row says {row}, derived {derived}")]
    TreeHashMismatch { row: Hash, derived: Hash },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("walkdir: {0}")]
    Walk(#[from] walkdir::Error),

    #[error("store: {0}")]
    Store(#[from] softfig_store::StoreError),

    #[error("vault: {0}")]
    Vault(#[from] softfig_vault::VaultError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("ed25519: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),

    #[error("non-utf8 path encountered: {0}")]
    NonUtf8Path(std::path::PathBuf),
}

pub type Result<T> = std::result::Result<T, CoreError>;
