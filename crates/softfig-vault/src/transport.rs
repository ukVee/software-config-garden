//! The device's X25519 transport key — the Noise static key used by
//! `softfig-net` for encrypted peer channels (M5a). Distinct from the Ed25519
//! [`crate::identity`], which is signing-only; a signed pairing attestation
//! (M5a-2) binds the two keys together. The private scalar is stored on disk
//! wrapped under K and zeroized on lock, mirroring [`crate::identity`].
//!
//! Vaults initialised before M5a have no `transport.key`; the key is then
//! auto-generated and persisted on the next unlock — see
//! [`read_or_init_transport`] (called from [`crate::Vault`]'s unlock path).

use std::fs;

use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::kek::{unwrap_under_kek, wrap_under_kek, Kek};
use crate::params::aad;
use crate::storage::VaultPaths;

/// Length of an X25519 secret/public key (256 bits), matching the rest of the
/// vault's key material.
pub const TRANSPORT_KEY_LEN: usize = 32;

/// The X25519 transport keypair. Holds only the secret scalar; the public key
/// is derived on demand. The raw secret is handed to the Noise layer
/// (`softfig-net`) as the local static key.
pub struct TransportKey {
    secret: Zeroizing<[u8; TRANSPORT_KEY_LEN]>,
}

impl TransportKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; TRANSPORT_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self {
            secret: Zeroizing::new(bytes),
        }
    }

    pub fn from_secret_bytes(bytes: [u8; TRANSPORT_KEY_LEN]) -> Self {
        Self {
            secret: Zeroizing::new(bytes),
        }
    }

    /// The raw 32-byte X25519 secret, for handing to the Noise layer. Clamping
    /// is performed by the consumer (snow / x25519) during the DH, so the
    /// stored scalar is the unmodified random bytes.
    pub fn secret_bytes(&self) -> &[u8; TRANSPORT_KEY_LEN] {
        &self.secret
    }

    /// The X25519 public key: the Curve25519 base-point multiplication of the
    /// (clamped) secret scalar. Matches what the Noise handshake exchanges as
    /// this device's static key.
    pub fn pubkey(&self) -> [u8; TRANSPORT_KEY_LEN] {
        x25519_dalek::x25519(*self.secret, x25519_dalek::X25519_BASEPOINT_BYTES)
    }
}

impl std::fmt::Debug for TransportKey {
    /// Never prints the secret scalar — only the public key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportKey")
            .field("pubkey", &hex::encode(self.pubkey()))
            .finish_non_exhaustive()
    }
}

pub fn write_transport(paths: &VaultPaths, kek: &Kek, key: &TransportKey) -> Result<()> {
    let wrapped = wrap_under_kek(kek, key.secret_bytes(), aad::TRANSPORT);
    fs::write(paths.transport(), wrapped)?;
    Ok(())
}

pub fn read_transport(paths: &VaultPaths, kek: &Kek) -> Result<TransportKey> {
    let wrapped = fs::read(paths.transport())?;
    let plaintext = unwrap_under_kek(kek, &wrapped, aad::TRANSPORT)?;
    if plaintext.len() != TRANSPORT_KEY_LEN {
        return Err(VaultError::Malformed("transport secret wrong length"));
    }
    let mut bytes = [0u8; TRANSPORT_KEY_LEN];
    bytes.copy_from_slice(&plaintext);
    Ok(TransportKey::from_secret_bytes(bytes))
}

/// Read the transport key, generating and persisting a fresh one if the file is
/// absent. This is the auto-generate-on-unlock path for vaults initialised
/// before M5a. A present-but-corrupt key is an error (tamper signal), never a
/// silent regeneration.
pub fn read_or_init_transport(paths: &VaultPaths, kek: &Kek) -> Result<TransportKey> {
    if paths.transport().exists() {
        read_transport(paths, kek)
    } else {
        let key = TransportKey::generate();
        write_transport(paths, kek, &key)?;
        Ok(key)
    }
}
