//! The soft-fig Vault: key custody and encryption at rest.
//!
//! - **Layer A** — whole-garden encrypted-at-rest blob storage: convergent
//!   blob encryption under master-key generations `M` (`blob`, `master`),
//!   which are wrapped under the key-encryption key `K` (`kek`); `K` is
//!   wrapped once per door — passphrase, optional recovery phrase (`storage`,
//!   `wrappings`).
//! - **Device keys** — the Ed25519 identity key that signs VCS commits
//!   (`identity`) and the X25519 Noise static key for peer channels
//!   (`transport`).
//! - **Layer B** — per-path and inline-region selective secrets under HKDF
//!   subkeys (`layer_b`).
//! - **Recovery** — the recovery phrase, the declared recovery policy, escrow
//!   export/verify, and Argon2 cost rewrap (`recovery`, `recovery_policy`,
//!   `escrow`, `rewrap`).
//! - **Sessions** — the in-memory unlocked state and the relock token
//!   (`session`, `relock`).
//! - **Shared subtrees** — blob crypto under the collaborative key `S`
//!   (`shared`).
//!
//! Not built: peer unlock, the panic counter, TPM mode. See
//! `meta/spec-vault.md` in the soft-fig garden for the full target.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod blob;
pub mod error;
pub mod escrow;
pub mod identity;
pub mod kek;
pub mod layer_b;
pub mod master;
pub mod params;
pub mod recovery;
pub mod recovery_policy;
pub mod relock;
pub mod rewrap;
pub mod session;
pub mod shared;
pub mod storage;
pub mod transport;
pub mod wrappings;
mod vault;

pub use error::{Result, VaultError};
pub use escrow::{
    EscrowBundle, EscrowLog, ExportSummary, Finding, IntegrityReport, Member, OpenProof,
    VerificationRecord, ESCROW_FORMAT_VERSION,
};
pub use layer_b::{is_layer_b, LayerBKey};
pub use shared::{is_shared, is_shared_blob, is_shared_layer_b};
pub use recovery::RecoveryPhrase;
pub use recovery_policy::{
    DeclaredPolicy, Divergence, RecoveryPath, RecoveryPolicy, RecoveryStatus, Wrappings,
};
pub use relock::{RelockBlob, RelockToken, RELOCK_TTL_SECS};
pub use rewrap::{Calibration, RewrapPlan};
pub use session::VaultSession;
pub use storage::{discover_garden, VaultPaths};
pub use wrappings::DropPlan;
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
