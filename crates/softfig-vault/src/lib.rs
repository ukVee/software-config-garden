//! Single-device Vault for soft-fig.
//!
//! Layer A only: encrypted-at-rest blob storage, identity-key signing for
//! the future VCS layer. Multi-device features (trust matrix, peer unlock,
//! panic counter), Layer B selective secrets, FUSE, and TPM mode are not
//! in this slice — see `meta/spec-vault.md` in the soft-fig garden for the
//! full target.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod blob;
pub mod error;
pub mod identity;
pub mod kek;
pub mod layer_b;
pub mod master;
pub mod params;
pub mod recovery;
pub mod relock;
pub mod session;
pub mod storage;
pub mod transport;
mod vault;

pub use error::{Result, VaultError};
pub use layer_b::{is_layer_b, LayerBKey};
pub use recovery::RecoveryPhrase;
pub use relock::{RelockBlob, RelockToken, RELOCK_TTL_SECS};
pub use session::VaultSession;
pub use storage::{discover_garden, VaultPaths};
pub use vault::Vault;

/// 32 bytes of OS-sourced cryptographically secure randomness. The vault is
/// the workspace's keygen surface (it mints every key), so callers needing
/// fresh key-grade material — e.g. the M5d ceremony nonce and contribution —
/// draw it here instead of growing their own RNG dependency.
pub fn random_bytes32() -> [u8; 32] {
    use rand::RngCore;
    let mut out = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}
