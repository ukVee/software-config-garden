//! K — the key-encryption-key — and the AEAD primitives layered on top of it.
//!
//! K wraps M and the identity key. K itself is wrapped under one or more
//! passphrase-derived keys (the self-path and the recovery path). Bulk blob
//! crypto uses M directly, not K.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use zeroize::{Zeroizing, ZeroizeOnDrop};

use crate::error::{Result, VaultError};
use crate::params::{Argon2Params, AEAD_NONCE_LEN, KEK_SALT_LEN, KEY_LEN};

/// Key-encryption-key. Owned by an unlocked session; zeroed on drop.
#[derive(Debug, ZeroizeOnDrop)]
pub struct Kek(Zeroizing<[u8; KEY_LEN]>);

impl Kek {
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

fn aead_seal(key: &[u8; KEY_LEN], nonce: &[u8; AEAD_NONCE_LEN], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: pt, aad })
        .expect("aead encrypt is infallible for in-memory inputs")
}

fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ct, aad })
        .map_err(|_| VaultError::AuthFailed)
}

/// Stretches a passphrase to a 32-byte AEAD key via Argon2id with the given salt.
fn derive_from_passphrase(
    passphrase: &[u8],
    salt: &[u8; KEK_SALT_LEN],
    params: &Argon2Params,
) -> Zeroizing<[u8; KEY_LEN]> {
    use argon2::{Algorithm, Argon2, Version};
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_argon2());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut())
        .expect("argon2 hash_password_into is infallible for valid params");
    out
}

/// Wrap K under a passphrase. On-disk format: salt(16) || nonce(24) || ciphertext+tag.
pub fn wrap_kek_under_passphrase(
    passphrase: &[u8],
    kek: &Kek,
    params: &Argon2Params,
    aad: &[u8],
) -> Vec<u8> {
    let mut salt = [0u8; KEK_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let derived = derive_from_passphrase(passphrase, &salt, params);
    let ct = aead_seal(&derived, &nonce, aad, kek.expose());

    let mut out = Vec::with_capacity(KEK_SALT_LEN + AEAD_NONCE_LEN + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn unwrap_kek_under_passphrase(
    passphrase: &[u8],
    wrapped: &[u8],
    params: &Argon2Params,
    aad: &[u8],
) -> Result<Kek> {
    if wrapped.len() < KEK_SALT_LEN + AEAD_NONCE_LEN {
        return Err(VaultError::Malformed("wrapped kek too short"));
    }
    let salt: [u8; KEK_SALT_LEN] = wrapped[..KEK_SALT_LEN].try_into().unwrap();
    let nonce: [u8; AEAD_NONCE_LEN] = wrapped[KEK_SALT_LEN..KEK_SALT_LEN + AEAD_NONCE_LEN]
        .try_into()
        .unwrap();
    let ct = &wrapped[KEK_SALT_LEN + AEAD_NONCE_LEN..];

    let derived = derive_from_passphrase(passphrase, &salt, params);
    let pt = aead_open(&derived, &nonce, aad, ct)?;
    if pt.len() != KEY_LEN {
        return Err(VaultError::Malformed("kek plaintext wrong length"));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&pt);
    Ok(Kek::from_bytes(k))
}

/// Derive a 32-byte AEAD key from a full-entropy 256-bit relock token via a
/// single HKDF-SHA256 step. No Argon2: the token is already full-entropy, so
/// stretching it would only add latency. The `info` label domain-separates
/// this key from any other HKDF use of the same token material.
fn derive_from_token(token: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, token);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(crate::params::aad::KEK_RELOCK, out.as_mut())
        .expect("hkdf expand to 32 bytes is infallible");
    out
}

/// Wrap K under a relock token. On-disk format: nonce(24) || ciphertext+tag.
/// No salt — the token is full-entropy and the wrap key is HKDF'd directly
/// (see [`derive_from_token`]). `aad` authenticates the purpose tag, the
/// vault fingerprint, and the token's expiry (see [`crate::relock`]).
pub fn wrap_kek_under_token(token: &[u8; KEY_LEN], kek: &Kek, aad: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let derived = derive_from_token(token);
    let ct = aead_seal(&derived, &nonce, aad, kek.expose());
    let mut out = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn unwrap_kek_under_token(token: &[u8; KEY_LEN], wrapped: &[u8], aad: &[u8]) -> Result<Kek> {
    if wrapped.len() < AEAD_NONCE_LEN {
        return Err(VaultError::Malformed("wrapped relock kek too short"));
    }
    let nonce: [u8; AEAD_NONCE_LEN] = wrapped[..AEAD_NONCE_LEN].try_into().unwrap();
    let ct = &wrapped[AEAD_NONCE_LEN..];
    let derived = derive_from_token(token);
    let pt = aead_open(&derived, &nonce, aad, ct)?;
    if pt.len() != KEY_LEN {
        return Err(VaultError::Malformed("relock kek plaintext wrong length"));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&pt);
    Ok(Kek::from_bytes(k))
}

/// Wrap arbitrary bytes (e.g., M, identity keypair) under K. Format: nonce(24) || ciphertext+tag.
pub fn wrap_under_kek(kek: &Kek, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = aead_seal(kek.expose(), &nonce, aad, plaintext);
    let mut out = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn unwrap_under_kek(kek: &Kek, wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < AEAD_NONCE_LEN {
        return Err(VaultError::Malformed("wrapped secret too short"));
    }
    let nonce: [u8; AEAD_NONCE_LEN] = wrapped[..AEAD_NONCE_LEN].try_into().unwrap();
    let ct = &wrapped[AEAD_NONCE_LEN..];
    aead_open(kek.expose(), &nonce, aad, ct)
}
