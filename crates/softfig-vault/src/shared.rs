//! M5d — shared-subtree blob crypto under the collaborative key `S`.
//!
//! A shared chain's blobs encrypt under that chain's ceremony-derived `S`
//! (`spec-sync.md` §"Crypto — the collaboratively-generated shared key `S`"),
//! not the device master `M`, so every member reads/writes offline and
//! non-members hold nothing readable. The construction is convergent —
//! same plaintext + same `S` → identical ciphertext/hash on every member —
//! which preserves content-addressed dedup and byte-faithful cross-member
//! sync (the same property Layer A gets from `M`).
//!
//! Shared blob (the Layer A analog, spec formula verbatim):
//!
//! ```text
//! nonce         = BLAKE3-keyed(S, plaintext)[..24]
//! per_blob_key  = HKDF-SHA-256(salt=nonce, ikm=S, info="softfig.shared.v1", L=32)
//! body          = XChaCha20-Poly1305-Encrypt(per_blob_key, nonce, P, aad="softfig.shared.v1")
//! blob_file     = 0xFE || len(key_id) || key_id || nonce || body
//! ```
//!
//! Shared Layer B (a whole-file seal *inside* a shared subtree — the
//! `spec-vault.md` "Layer B seals inside a shared subtree derive their
//! subkeys from `S`" rule):
//!
//! ```text
//! subkey(path)  = HKDF-SHA-256(ikm=S, salt=path-bytes, info="softfig:layer-b-shared/v1", L=32)
//! nonce         = BLAKE3-keyed(subkey, plaintext)[..24]
//! body          = XChaCha20-Poly1305-Encrypt(subkey, nonce, P, aad="softfig.layer-b-shared.v1")
//! blob_file     = 0xFD || len(key_id) || key_id || nonce || body
//! ```
//!
//! Inline `<vault id="…">` regions inside a shared subtree derive per-region
//! subkeys the same way ([`derive_region_subkey`], salt `path ‖ 0x00 ‖ id`,
//! its own `info`) and reuse the `0xFD` container — mirroring how M-keyed
//! regions reuse Layer B's `0xFF` container.
//!
//! The embedded `key_id` (`S-<hex>`, ≤ [`MAX_KEY_ID_LEN`] bytes of
//! `[A-Za-z0-9_-]`) makes every shared blob self-describing: a reader
//! resolves the key via `VaultSession::load_shared_key(key_id)` without
//! knowing which chain the blob came from, and after a rotation (slice 003)
//! old blobs still name the `S` generation that sealed them — the exact
//! mirror of the `varint(master_key_id)` Layer A/B embed. All members hold
//! the same `S` and the same `key_id`, so the embed cannot break convergence.
//!
//! Marker bytes `0xFE`/`0xFD` disambiguate from Layer A the same way Layer
//! B's `0xFF` does: a Layer A blob's first byte is a varint with the high
//! bit set only for master ids ≥ 128 (unreachable in practice — ids are
//! small rotation counters).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::layer_b::LayerBKey;
use crate::params::{AEAD_NONCE_LEN, KEY_LEN};

/// Marker byte for a shared-chain blob (the Layer A analog under `S`).
pub const SHARED_BLOB_MARKER: u8 = 0xFE;

/// Marker byte for a shared Layer B blob (whole-file or region seal under
/// an `S`-derived subkey).
pub const SHARED_LAYER_B_MARKER: u8 = 0xFD;

/// AAD for shared blob bodies — doubles as the per-blob HKDF `info`
/// (spec-sync.md fixes both to this string).
pub const SHARED_BLOB_AAD: &[u8] = b"softfig.shared.v1";

/// AAD for shared Layer B bodies. Domain-separates from the M-keyed Layer
/// B (`softfig.layer-b.v1`) and from shared blobs above.
pub const SHARED_LAYER_B_AAD: &[u8] = b"softfig.layer-b-shared.v1";

/// HKDF `info` for a shared per-file Layer B subkey.
pub const SHARED_LAYER_B_HKDF_INFO: &[u8] = b"softfig:layer-b-shared/v1";

/// HKDF `info` for a shared inline-region subkey (salt `path ‖ 0x00 ‖ id`).
pub const SHARED_REGION_HKDF_INFO: &[u8] = b"softfig:layer-b-shared-region/v1";

/// Longest `key_id` the container encodes (matches the session store's
/// `[A-Za-z0-9_-]{1,64}` validation; real ids are `S-<16 hex>` = 18 bytes).
pub const MAX_KEY_ID_LEN: usize = 64;

/// True if `blob_file` is a shared-chain blob (`0xFE`).
pub fn is_shared_blob(blob_file: &[u8]) -> bool {
    blob_file.first().copied() == Some(SHARED_BLOB_MARKER)
}

/// True if `blob_file` is a shared Layer B seal (`0xFD`).
pub fn is_shared_layer_b(blob_file: &[u8]) -> bool {
    blob_file.first().copied() == Some(SHARED_LAYER_B_MARKER)
}

/// True for either shared container — "this blob needs an `S`, not `M`".
pub fn is_shared(blob_file: &[u8]) -> bool {
    is_shared_blob(blob_file) || is_shared_layer_b(blob_file)
}

/// Read the embedded `key_id` from either shared container *without*
/// decrypting — the read path resolves `S` through
/// `VaultSession::load_shared_key` with this. Rejects a malformed or
/// truncated header and any id that fails the charset rule (defense in
/// depth: the id is about to be used as a filename component).
pub fn read_key_id(blob_file: &[u8]) -> Result<String> {
    if !is_shared(blob_file) {
        return Err(VaultError::MalformedBlob);
    }
    let (key_id, _rest) = split_key_id(&blob_file[1..])?;
    Ok(key_id.to_string())
}

/// Encrypt a shared-chain blob under `S` (spec formula). Output is the
/// full content-addressable blob_file.
pub fn encrypt_blob(key_id: &str, s: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = keyed_nonce(s, plaintext);
    let per_blob_key = derive_per_blob_key(s, &nonce);
    seal(SHARED_BLOB_MARKER, key_id, &nonce, &per_blob_key, SHARED_BLOB_AAD, plaintext)
}

/// Decrypt a shared-chain blob under the supplied `S`. The caller resolves
/// `S` from [`read_key_id`] first; a wrong or rotated-away `S` fails the
/// AEAD tag ([`VaultError::AuthFailed`]), never yields bytes.
pub fn decrypt_blob(s: &[u8; KEY_LEN], blob_file: &[u8]) -> Result<Vec<u8>> {
    let (nonce, body) = open_header(SHARED_BLOB_MARKER, blob_file)?;
    let per_blob_key = derive_per_blob_key(s, &nonce);
    unseal(&per_blob_key, &nonce, SHARED_BLOB_AAD, body)
}

/// Derive the shared per-file Layer B subkey from `S` + a repo-relative
/// path — the `S` mirror of [`crate::layer_b::derive_subkey`].
pub fn derive_layer_b_subkey(s: &[u8; KEY_LEN], path_bytes: &[u8]) -> LayerBKey {
    hkdf_subkey(s, path_bytes, SHARED_LAYER_B_HKDF_INFO)
}

/// Derive a shared inline-region subkey from `S` + `(path, id)` — the `S`
/// mirror of [`crate::layer_b::derive_region_subkey`] (same `\0`-separated
/// salt, its own `info`).
pub fn derive_region_subkey(s: &[u8; KEY_LEN], path: &str, id: &str) -> LayerBKey {
    let mut salt = Vec::with_capacity(path.len() + 1 + id.len());
    salt.extend_from_slice(path.as_bytes());
    salt.push(0);
    salt.extend_from_slice(id.as_bytes());
    hkdf_subkey(s, &salt, SHARED_REGION_HKDF_INFO)
}

/// Encrypt a whole-file Layer B seal inside a shared subtree.
pub fn encrypt_layer_b(
    key_id: &str,
    s: &[u8; KEY_LEN],
    path: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let subkey = derive_layer_b_subkey(s, path.as_bytes());
    encrypt_under_subkey(key_id, &subkey, plaintext)
}

/// Decrypt a whole-file shared Layer B blob under the supplied `S`.
pub fn decrypt_layer_b(s: &[u8; KEY_LEN], path: &str, blob_file: &[u8]) -> Result<Vec<u8>> {
    let subkey = derive_layer_b_subkey(s, path.as_bytes());
    decrypt_under_subkey(&subkey, blob_file)
}

/// Encrypt an inline `<vault>` region inside a shared subtree.
pub fn encrypt_region(
    key_id: &str,
    s: &[u8; KEY_LEN],
    path: &str,
    id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let subkey = derive_region_subkey(s, path, id);
    encrypt_under_subkey(key_id, &subkey, plaintext)
}

/// Decrypt an inline shared region under the supplied `S`.
pub fn decrypt_region(
    s: &[u8; KEY_LEN],
    path: &str,
    id: &str,
    blob_file: &[u8],
) -> Result<Vec<u8>> {
    let subkey = derive_region_subkey(s, path, id);
    decrypt_under_subkey(&subkey, blob_file)
}

/// Seal under an already-derived `S` subkey into the `0xFD` container —
/// shared Layer B files and regions share this, exactly as M-keyed files
/// and regions share `layer_b::encrypt`.
fn encrypt_under_subkey(key_id: &str, subkey: &LayerBKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = keyed_nonce(subkey.expose(), plaintext);
    seal(
        SHARED_LAYER_B_MARKER,
        key_id,
        &nonce,
        subkey.expose(),
        SHARED_LAYER_B_AAD,
        plaintext,
    )
}

fn decrypt_under_subkey(subkey: &LayerBKey, blob_file: &[u8]) -> Result<Vec<u8>> {
    let (nonce, body) = open_header(SHARED_LAYER_B_MARKER, blob_file)?;
    unseal(subkey.expose(), &nonce, SHARED_LAYER_B_AAD, body)
}

// --- container plumbing ----------------------------------------------------

/// Validate + split a `len(u8) || key_id || rest` header (after the marker).
fn split_key_id(after_marker: &[u8]) -> Result<(&str, &[u8])> {
    let (&len, rest) = after_marker.split_first().ok_or(VaultError::MalformedBlob)?;
    let len = len as usize;
    if len == 0 || len > MAX_KEY_ID_LEN || rest.len() < len {
        return Err(VaultError::MalformedBlob);
    }
    let (id_bytes, rest) = rest.split_at(len);
    let key_id = std::str::from_utf8(id_bytes).map_err(|_| VaultError::MalformedBlob)?;
    if !key_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(VaultError::MalformedBlob);
    }
    Ok((key_id, rest))
}

fn seal(
    marker: u8,
    key_id: &str,
    nonce: &[u8; AEAD_NONCE_LEN],
    key: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        return Err(VaultError::Malformed(
            "shared key id must be 1-64 chars of [A-Za-z0-9_-]",
        ));
    }
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let body = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("aead encrypt is infallible for in-memory inputs");
    let mut out = Vec::with_capacity(2 + key_id.len() + AEAD_NONCE_LEN + body.len());
    out.push(marker);
    out.push(key_id.len() as u8);
    out.extend_from_slice(key_id.as_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

fn open_header(marker: u8, blob_file: &[u8]) -> Result<([u8; AEAD_NONCE_LEN], &[u8])> {
    if blob_file.first().copied() != Some(marker) {
        return Err(VaultError::MalformedBlob);
    }
    let (_key_id, rest) = split_key_id(&blob_file[1..])?;
    if rest.len() < AEAD_NONCE_LEN {
        return Err(VaultError::MalformedBlob);
    }
    let (nonce_bytes, body) = rest.split_at(AEAD_NONCE_LEN);
    let nonce: [u8; AEAD_NONCE_LEN] = nonce_bytes.try_into().unwrap();
    Ok((nonce, body))
}

fn unseal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    body: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .decrypt(
            nonce.into(),
            Payload { msg: body, aad },
        )
        .map_err(|_| VaultError::AuthFailed)
}

/// Per-blob key for the `0xFE` flavor — spec formula: HKDF(salt=nonce,
/// ikm=S, info="softfig.shared.v1").
fn derive_per_blob_key(
    s: &[u8; KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(nonce.as_slice()), s);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(SHARED_BLOB_AAD, out.as_mut())
        .expect("HKDF expand fits within Sha256 output ceiling");
    out
}

fn keyed_nonce(key: &[u8; KEY_LEN], plaintext: &[u8]) -> [u8; AEAD_NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(plaintext);
    let mut out = [0u8; AEAD_NONCE_LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hkdf_subkey(ikm: &[u8; KEY_LEN], salt: &[u8], info: &[u8]) -> LayerBKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, out.as_mut())
        .expect("HKDF expand fits within Sha256 output ceiling");
    LayerBKey::from_zeroizing(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s_a() -> [u8; KEY_LEN] {
        let mut b = [0u8; KEY_LEN];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(13).wrapping_add(3);
        }
        b
    }

    fn s_b() -> [u8; KEY_LEN] {
        let mut b = s_a();
        b[0] ^= 0xAA;
        b
    }

    const ID: &str = "S-00112233aabbccdd";

    #[test]
    fn shared_blob_round_trip_and_markers() {
        let s = s_a();
        let pt = b"# shared note\nhello members\n";
        let ct = encrypt_blob(ID, &s, pt).unwrap();
        assert!(is_shared_blob(&ct));
        assert!(!is_shared_layer_b(&ct));
        assert!(is_shared(&ct));
        assert_eq!(read_key_id(&ct).unwrap(), ID);
        assert_eq!(decrypt_blob(&s, &ct).unwrap(), pt);
    }

    #[test]
    fn convergent_same_plaintext_same_s_same_bytes() {
        // The load-bearing property for sync/dedup: two members (any device,
        // any master key) sealing the same plaintext under the same S produce
        // byte-identical blob_files → identical BLAKE3 addresses.
        let s = s_a();
        let pt = b"identical on every member";
        assert_eq!(encrypt_blob(ID, &s, pt).unwrap(), encrypt_blob(ID, &s, pt).unwrap());
        let lb1 = encrypt_layer_b(ID, &s, "proj/secrets.toml", pt).unwrap();
        let lb2 = encrypt_layer_b(ID, &s, "proj/secrets.toml", pt).unwrap();
        assert_eq!(lb1, lb2);
    }

    #[test]
    fn different_s_different_bytes_and_no_cross_decrypt() {
        let pt = b"same plaintext";
        let ct_a = encrypt_blob(ID, &s_a(), pt).unwrap();
        let ct_b = encrypt_blob(ID, &s_b(), pt).unwrap();
        assert_ne!(ct_a, ct_b);
        assert!(matches!(decrypt_blob(&s_b(), &ct_a), Err(VaultError::AuthFailed)));
    }

    #[test]
    fn shared_layer_b_round_trip_and_path_separation() {
        let s = s_a();
        let pt = b"sealed inside a shared subtree";
        let ct = encrypt_layer_b(ID, &s, "proj/keys.toml", pt).unwrap();
        assert!(is_shared_layer_b(&ct));
        assert_eq!(read_key_id(&ct).unwrap(), ID);
        assert_eq!(decrypt_layer_b(&s, "proj/keys.toml", &ct).unwrap(), pt);
        // A different path derives a different subkey → decrypt fails.
        assert!(matches!(
            decrypt_layer_b(&s, "proj/other.toml", &ct),
            Err(VaultError::AuthFailed)
        ));
    }

    #[test]
    fn region_round_trip_and_three_way_separation() {
        let s = s_a();
        let pt = b"region secret";
        let ct = encrypt_region(ID, &s, "proj/notes.md", "alpha", pt).unwrap();
        assert_eq!(decrypt_region(&s, "proj/notes.md", "alpha", &ct).unwrap(), pt);
        // Wrong id, wrong path, or the whole-file subkey all fail.
        assert!(decrypt_region(&s, "proj/notes.md", "beta", &ct).is_err());
        assert!(decrypt_region(&s, "proj/x.md", "alpha", &ct).is_err());
        assert!(decrypt_layer_b(&s, "proj/notes.md", &ct).is_err());
        // Concatenation collision guard, mirroring the M-keyed region rule.
        let k1 = derive_region_subkey(&s, "ab", "cd");
        let k2 = derive_region_subkey(&s, "a", "bcd");
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn shared_subkeys_are_domain_separated_from_master_derivations() {
        // The same 32 bytes used as S and as a master key must never yield
        // the same subkey for the same path (different HKDF info).
        let bytes = s_a();
        let m = crate::master::MasterKey::from_bytes(1, bytes);
        let from_m = crate::layer_b::derive_subkey(&m, b"proj/f.toml");
        let from_s = derive_layer_b_subkey(&bytes, b"proj/f.toml");
        assert_ne!(from_m.expose(), from_s.expose());
        let rm = crate::layer_b::derive_region_subkey(&m, "proj/f.md", "a");
        let rs = derive_region_subkey(&bytes, "proj/f.md", "a");
        assert_ne!(rm.expose(), rs.expose());
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let s = s_a();
        // Not a shared marker at all.
        assert!(matches!(read_key_id(b"\x01\x00"), Err(VaultError::MalformedBlob)));
        assert!(matches!(decrypt_blob(&s, b""), Err(VaultError::MalformedBlob)));
        // Marker but truncated before/inside the id.
        assert!(matches!(
            read_key_id(&[SHARED_BLOB_MARKER]),
            Err(VaultError::MalformedBlob)
        ));
        assert!(matches!(
            read_key_id(&[SHARED_BLOB_MARKER, 5, b'S', b'-']),
            Err(VaultError::MalformedBlob)
        ));
        // Zero-length and oversized ids.
        assert!(matches!(
            read_key_id(&[SHARED_BLOB_MARKER, 0, 1, 2]),
            Err(VaultError::MalformedBlob)
        ));
        // Bad charset (a `/` could traverse as a filename).
        let mut bad = vec![SHARED_BLOB_MARKER, 3];
        bad.extend_from_slice(b"a/b");
        bad.extend_from_slice(&[0u8; AEAD_NONCE_LEN]);
        assert!(matches!(read_key_id(&bad), Err(VaultError::MalformedBlob)));
        // Truncated nonce after a valid id.
        let mut short = vec![SHARED_BLOB_MARKER, 1, b'x', 0, 0];
        short.truncate(4);
        assert!(matches!(decrypt_blob(&s, &short), Err(VaultError::MalformedBlob)));
        // Oversized key_id refused at seal time too.
        let long_id = "x".repeat(65);
        assert!(encrypt_blob(&long_id, &s, b"p").is_err());
    }

    #[test]
    fn tampered_body_fails_auth() {
        let s = s_a();
        let mut ct = encrypt_blob(ID, &s, b"payload").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(decrypt_blob(&s, &ct), Err(VaultError::AuthFailed)));
    }
}
