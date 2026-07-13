use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is not initialized at {0}")]
    NotInitialized(std::path::PathBuf),

    #[error("vault is already initialized at {0}")]
    AlreadyInitialized(std::path::PathBuf),

    #[error("unsupported vault format version: {0}")]
    UnsupportedFormat(u32),

    #[error("malformed on-disk vault file: {0}")]
    Malformed(&'static str),

    #[error("authentication failed (wrong passphrase or tampered ciphertext)")]
    AuthFailed,

    #[error("master key generation {0} not found")]
    UnknownMasterKey(u32),

    #[error("blob is malformed")]
    MalformedBlob,

    #[error("shared key {0} is not stored in this vault")]
    SharedKeyUnavailable(String),

    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,

    #[error("relock token expired")]
    RelockExpired,

    #[error("malformed relock blob: {0}")]
    RelockMalformed(&'static str),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("toml encode: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;
