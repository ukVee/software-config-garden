//! Layer B per-file selective secrets.
//!
//! For each repo-relative `path` sealed via `.softfig/vault/sealed-paths.toml`:
//!
//! ```text
//! subkey(path)  = HKDF-SHA-256(ikm=M, salt=path-bytes, info=b"softfig:layer-b/v1", L=32)
//! nonce         = BLAKE3-keyed(subkey, plaintext)[..24]
//! body          = XChaCha20-Poly1305-Encrypt(subkey, nonce, plaintext, aad="softfig.layer-b.v1")
//! blob_file     = 0xFF || varint(master_key_id) || nonce || body
//! ```
//!
//! The leading `0xFF` marker distinguishes Layer B blobs from Layer A
//! blobs on the wire — Layer A's first byte is a varint with the high
//! bit set only for ids ≥ 128 (rare in practice), so a sentinel byte
//! disambiguates without ambiguity. The marker also lets the daemon
//! refuse to feed Layer B ciphertext through `decrypt_blob` accidentally.
//!
//! Subkeys are never persisted: they are recomputed from `M` + `path` on
//! every encrypt/decrypt. Compromise of one sealed file's subkey leaks
//! only that file (HKDF separation).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, VaultError};
use crate::master::MasterKey;
use crate::params::{AEAD_NONCE_LEN, KEY_LEN};

/// AAD for Layer B blob bodies. Domain-separates from Layer A
/// (`softfig.blob.v1`) so a swapped ciphertext fails to decrypt under
/// the wrong layer.
pub const LAYER_B_AAD: &[u8] = b"softfig.layer-b.v1";

/// HKDF `info` used when deriving a per-file subkey. Version-prefixed so
/// future Layer B subkey rotations (M2c+) can coexist with v1 blobs.
pub const LAYER_B_HKDF_INFO: &[u8] = b"softfig:layer-b/v1";

/// HKDF `info` used when deriving an inline `<vault>` region subkey
/// (M2c). The `\0`-separated `path||id` salt domain-separates each
/// region key from every other region key in the file and from the
/// whole-file subkey above.
pub const LAYER_B_REGION_HKDF_INFO: &[u8] = b"softfig:layer-b-region/v1";

/// Marker byte at the start of a Layer B blob_file. See module docs.
pub const LAYER_B_MARKER: u8 = 0xFF;

/// Per-file Layer B subkey. 32 bytes of HKDF output, zeroed on drop.
#[derive(Debug)]
pub struct LayerBKey(Zeroizing<[u8; KEY_LEN]>);

impl LayerBKey {
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for LayerBKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Derive the per-file Layer B subkey from a master key and a
/// repo-relative path string. The path is used as the HKDF salt so two
/// different paths produce two unrelated subkeys.
pub fn derive_subkey(master: &MasterKey, path_bytes: &[u8]) -> LayerBKey {
    let hk = Hkdf::<Sha256>::new(Some(path_bytes), master.expose());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(LAYER_B_HKDF_INFO, out.as_mut())
        .expect("HKDF expand fits within Sha256 output ceiling");
    LayerBKey(out)
}

/// Derive a per-region subkey for an inline `<vault id="...">` region
/// (M2c). The salt is `path || 0x00 || id` so `(path, id)` pairs and
/// `(path', id')` pairs with concatenation collisions stay separated,
/// and so the result is HKDF-distinct from [`derive_subkey`]'s
/// whole-file output (different `info`).
pub fn derive_region_subkey(master: &MasterKey, path: &str, id: &str) -> LayerBKey {
    let mut salt = Vec::with_capacity(path.len() + 1 + id.len());
    salt.extend_from_slice(path.as_bytes());
    salt.push(0);
    salt.extend_from_slice(id.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), master.expose());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(LAYER_B_REGION_HKDF_INFO, out.as_mut())
        .expect("HKDF expand fits within Sha256 output ceiling");
    LayerBKey(out)
}

/// Encrypt a plaintext under a Layer B subkey. The output is a complete
/// content-addressable blob_file (with the leading `0xFF` marker, the
/// varint master-key-id, the nonce, and the AEAD body+tag) ready to put
/// in the object store.
pub fn encrypt(master_key_id: u32, plaintext: &[u8], key: &LayerBKey) -> Result<Vec<u8>> {
    let nonce = derive_nonce(key, plaintext);
    let cipher = XChaCha20Poly1305::new(key.expose().as_ref().into());
    let body = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: LAYER_B_AAD,
            },
        )
        .expect("aead encrypt is infallible for in-memory inputs");

    let mut out = Vec::with_capacity(1 + varint_size(master_key_id) + AEAD_NONCE_LEN + body.len());
    out.push(LAYER_B_MARKER);
    write_varint(&mut out, master_key_id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decrypt a Layer B blob_file under the supplied per-file subkey.
/// Returns `MalformedBlob` if the input does not start with the marker
/// byte, or `AuthFailed` if the AEAD body fails to verify.
pub fn decrypt(blob_file: &[u8], key: &LayerBKey) -> Result<Vec<u8>> {
    if blob_file.first().copied() != Some(LAYER_B_MARKER) {
        return Err(VaultError::MalformedBlob);
    }
    let after_marker = &blob_file[1..];
    let (_id, rest) = read_varint(after_marker).ok_or(VaultError::MalformedBlob)?;
    if rest.len() < AEAD_NONCE_LEN {
        return Err(VaultError::MalformedBlob);
    }
    let (nonce_bytes, body) = rest.split_at(AEAD_NONCE_LEN);
    let nonce: [u8; AEAD_NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| VaultError::MalformedBlob)?;

    let cipher = XChaCha20Poly1305::new(key.expose().as_ref().into());
    let plaintext = cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: body,
                aad: LAYER_B_AAD,
            },
        )
        .map_err(|_| VaultError::AuthFailed)?;
    Ok(plaintext)
}

/// True if `blob_file` begins with the Layer B marker. Used by the
/// daemon to route reads.
pub fn is_layer_b(blob_file: &[u8]) -> bool {
    blob_file.first().copied() == Some(LAYER_B_MARKER)
}

fn derive_nonce(key: &LayerBKey, plaintext: &[u8]) -> [u8; AEAD_NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(key.expose());
    hasher.update(plaintext);
    let mut out = [0u8; AEAD_NONCE_LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

// --- minimal LEB128 varint (u32) — kept private; same shape as Layer A's. ---

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
    use crate::master::MasterKey;

    fn fixed_master() -> MasterKey {
        // Deterministic 32-byte key for cross-run test stability.
        let mut bytes = [0u8; KEY_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        MasterKey::from_bytes(1, bytes)
    }

    #[test]
    fn round_trip() {
        let m = fixed_master();
        let path = b"secrets/foo.toml";
        let key = derive_subkey(&m, path);
        let pt = b"api_key = \"hunter2\"\n";
        let ct = encrypt(m.id, pt, &key).unwrap();
        assert_eq!(ct[0], LAYER_B_MARKER);
        let back = decrypt(&ct, &key).unwrap();
        assert_eq!(&back, pt);
    }

    #[test]
    fn deterministic_for_same_path_and_master() {
        let m = fixed_master();
        let path = b"secrets/foo.toml";
        let k1 = derive_subkey(&m, path);
        let k2 = derive_subkey(&m, path);
        assert_eq!(k1.expose(), k2.expose());
    }

    #[test]
    fn different_paths_yield_different_subkeys() {
        let m = fixed_master();
        let k1 = derive_subkey(&m, b"a/x.toml");
        let k2 = derive_subkey(&m, b"a/y.toml");
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn region_subkey_three_way_separation() {
        let m = fixed_master();
        // Two different ids under the same path → different subkeys.
        let ka = derive_region_subkey(&m, "secrets/foo.toml", "a");
        let kb = derive_region_subkey(&m, "secrets/foo.toml", "b");
        assert_ne!(ka.expose(), kb.expose());
        // Region subkey ≠ whole-file subkey for the same path.
        let kfile = derive_subkey(&m, b"secrets/foo.toml");
        assert_ne!(ka.expose(), kfile.expose());
        assert_ne!(kb.expose(), kfile.expose());
        // The `\0` separator prevents (path="ab", id="cd") from
        // colliding with (path="a", id="bcd").
        let k_ab_cd = derive_region_subkey(&m, "ab", "cd");
        let k_a_bcd = derive_region_subkey(&m, "a", "bcd");
        assert_ne!(k_ab_cd.expose(), k_a_bcd.expose());
    }

    #[test]
    fn decrypt_rejects_layer_a_blob() {
        // Construct something that does NOT start with 0xFF (would be a
        // Layer A varint), and confirm Layer B decrypt refuses it.
        let m = fixed_master();
        let key = derive_subkey(&m, b"x");
        let mut bogus = vec![0x01, 0x00];
        bogus.extend_from_slice(&[0u8; AEAD_NONCE_LEN]);
        assert!(matches!(
            decrypt(&bogus, &key),
            Err(VaultError::MalformedBlob)
        ));
    }
}
