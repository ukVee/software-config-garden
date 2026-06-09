use serde::{Deserialize, Serialize};

/// Bumped when the on-disk binary or TOML layout changes incompatibly.
pub const CURRENT_FORMAT_VERSION: u32 = 1;

/// Size of the salt (passed to Argon2id when deriving a passphrase-wrapping key).
pub const KEK_SALT_LEN: usize = 16;

/// Nonce size for XChaCha20-Poly1305 (24 bytes).
pub const AEAD_NONCE_LEN: usize = 24;

/// Length of K, M, and the per-blob key (256 bits).
pub const KEY_LEN: usize = 32;

/// AEAD tag length appended to ciphertext.
pub const AEAD_TAG_LEN: usize = 16;

/// AAD strings are domain separators so a ciphertext written for one purpose
/// fails to decrypt under another.
pub mod aad {
    pub const KEK_SELF: &[u8] = b"softfig.kek.self.v1";
    pub const KEK_RECOVERY: &[u8] = b"softfig.kek.recovery.v1";
    pub const IDENTITY: &[u8] = b"softfig.identity.v1";
    /// X25519 transport key — the Noise static key for softfig-net (M5a).
    pub const TRANSPORT: &[u8] = b"softfig.transport.v1";
    pub const BLOB: &[u8] = b"softfig.blob.v1";

    /// Master keys are AAD-bound to their generation id so two generations
    /// can't be swapped on disk without an integrity failure.
    pub fn master(id: u32) -> Vec<u8> {
        format!("softfig.master.v1.{id}").into_bytes()
    }
}

/// Argon2id cost parameters. Recorded on disk so a vault written on a beefy
/// machine still unlocks on a weaker one without re-deriving the cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration count.
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for Argon2Params {
    /// OWASP 2023 second recommendation: m=64 MiB, t=3, p=4.
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl Argon2Params {
    pub fn to_argon2(self) -> argon2::Params {
        argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .expect("argon2 params validated by softfig defaults")
    }
}

/// Plaintext metadata at `.softfig/vault/params.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultParams {
    pub format_version: u32,
    pub argon2: Argon2Params,
}

impl Default for VaultParams {
    fn default() -> Self {
        Self {
            format_version: CURRENT_FORMAT_VERSION,
            argon2: Argon2Params::default(),
        }
    }
}

/// Plaintext pointer at `.softfig/vault/active.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveKey {
    pub master_key_id: u32,
}
