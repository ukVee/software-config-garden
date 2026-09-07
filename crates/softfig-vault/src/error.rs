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

    #[error("escrow target {0} already exists and differs from this export (pass --force to replace it)")]
    EscrowTargetExists(std::path::PathBuf),

    #[error("malformed escrow bundle: {0}")]
    EscrowMalformed(String),

    #[error("a '{0}' wrapping of K already exists — remove it explicitly before adding another, so a live door is never silently replaced")]
    WrappingExists(crate::recovery_policy::RecoveryPath),

    #[error("there is no '{0}' wrapping of K in this vault to remove")]
    WrappingAbsent(crate::recovery_policy::RecoveryPath),

    #[error("refusing to remove '{0}': it is the only remaining way into this vault, and a vault with no way into K is unrecoverable")]
    LastWrapping(crate::recovery_policy::RecoveryPath),

    #[error("refusing to remove '{removing}': {reason}")]
    NoVerifiedEscrow {
        removing: crate::recovery_policy::RecoveryPath,
        reason: String,
    },

    #[error("refusing to remove '{0}': it is the wrapping this session is authenticated through, and nothing verified would remain")]
    AuthenticatedWrapping(crate::recovery_policy::RecoveryPath),

    #[error("peer wrappings of K are managed by the trust-matrix ledger, not by this verb")]
    PeerWrappingUnsupported,

    #[error("invalid Argon2 parameters {0}")]
    InvalidArgon2Params(String),

    #[error("refusing to rewrap under {target}: that is weaker than {what} ({floor}). Rehardening must never be able to quietly weaken a vault; pass --allow-downgrade to say you mean it")]
    WeakerParams {
        target: String,
        floor: String,
        what: &'static str,
    },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("toml encode: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;
