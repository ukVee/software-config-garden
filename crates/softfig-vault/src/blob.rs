//! Master-keyed convergent blob encryption.
//!
//! For plaintext `P` under master `M` with id `i`:
//!   nonce         = BLAKE3-keyed(M, P)[..24]
//!   per_blob_key  = HKDF-SHA-256(salt=nonce, ikm=M, info="softfig.blob.v1", L=32)
//!   body          = XChaCha20-Poly1305-Encrypt(per_blob_key, nonce, P, aad="softfig.blob.v1")
//!   blob_file     = varint(i) || nonce || body
//!
//! Same plaintext + same M → same blob_file → same BLAKE3(blob_file), so
//! the future VCS layer can content-address blobs and deduplicate.
//!
//! Note on HKDF orientation: standard `(salt, ikm)` is `(salt=nonce, ikm=M)`,
//! since IKM is the secret material and salt is non-secret randomization.
//! Either ordering would be cryptographically sound here but conventional
//! HKDF usage prefers this one.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::master::{MasterKey, MasterKeyStore};
use crate::params::{aad, AEAD_NONCE_LEN, KEY_LEN};

/// Encrypt a plaintext blob under the active master key. Output is the full
/// content-addressable blob_file.
pub fn encrypt_blob(masters: &MasterKeyStore, plaintext: &[u8]) -> Result<Vec<u8>> {
    let m = masters.active()?;
    encrypt_with(m, plaintext)
}

fn encrypt_with(m: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = derive_nonce(m, plaintext);
    let per_blob_key = derive_per_blob_key(m, &nonce);

    let cipher = XChaCha20Poly1305::new(per_blob_key.as_ref().into());
    let body = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: aad::BLOB,
            },
        )
        .expect("aead encrypt is infallible for in-memory inputs");

    let mut out = Vec::with_capacity(varint_size(m.id) + AEAD_NONCE_LEN + body.len());
    write_varint(&mut out, m.id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decrypt_blob(masters: &MasterKeyStore, blob_file: &[u8]) -> Result<Vec<u8>> {
    let (id, rest) = read_varint(blob_file).ok_or(VaultError::MalformedBlob)?;
    if rest.len() < AEAD_NONCE_LEN {
        return Err(VaultError::MalformedBlob);
    }
    let (nonce_bytes, body) = rest.split_at(AEAD_NONCE_LEN);
    let nonce: [u8; AEAD_NONCE_LEN] = nonce_bytes.try_into().unwrap();

    let m = masters.get(id)?;
    let per_blob_key = derive_per_blob_key(m, &nonce);
    let cipher = XChaCha20Poly1305::new(per_blob_key.as_ref().into());
    let plaintext = cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: body,
                aad: aad::BLOB,
            },
        )
        .map_err(|_| VaultError::AuthFailed)?;
    Ok(plaintext)
}

fn derive_nonce(m: &MasterKey, plaintext: &[u8]) -> [u8; AEAD_NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(m.expose());
    hasher.update(plaintext);
    let mut out = [0u8; AEAD_NONCE_LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn derive_per_blob_key(m: &MasterKey, nonce: &[u8; AEAD_NONCE_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(nonce.as_slice()), m.expose());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(aad::BLOB, out.as_mut())
        .expect("HKDF expand fits within Sha256 output ceiling");
    out
}

// --- minimal LEB128 varint (u32) -----------------------------------------

fn varint_size(mut v: u32) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

fn write_varint(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn read_varint(buf: &[u8]) -> Option<(u32, &[u8])> {
    let mut v: u32 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if shift >= 32 {
            return None;
        }
        v |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Some((v, &buf[i + 1..]));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u32, 1, 127, 128, 300, 16_383, 16_384, u32::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            assert_eq!(buf.len(), varint_size(v));
            let (decoded, rest) = read_varint(&buf).unwrap();
            assert_eq!(decoded, v);
            assert!(rest.is_empty());
        }
    }
}
