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
use crate::params::{Argon2Params, AEAD_NONCE_LEN, AEAD_TAG_LEN, KEK_SALT_LEN, KEY_LEN};
use crate::rewrap::MAX_CALIBRATED_M_COST;

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

/// Validate and cap Argon2 costs before any derivation runs.
///
/// A v2 header — and, for that matter, the `params.toml` a v1 blob reads its
/// fallback from — is untrusted input: [`Argon2Params::to_argon2`] panics on
/// costs Argon2 rejects, and an absurd `m_cost` turns the derivation into a
/// multi-GiB allocation whose failure aborts the process via `expect`. This is
/// the read-side counterpart of `rewrap::plan`'s operator-input `check`, and
/// the cap is the same one production calibration already refuses to cross
/// ([`MAX_CALIBRATED_M_COST`]).
fn validated_costs(params: &Argon2Params) -> Result<()> {
    params.check().map_err(|e| {
        VaultError::InvalidArgon2Params(format!("in a kek wrapping ({params}): {e}"))
    })?;
    if params.m_cost > MAX_CALIBRATED_M_COST {
        return Err(VaultError::InvalidArgon2Params(format!(
            "in a kek wrapping ({params}): m_cost exceeds the {MAX_CALIBRATED_M_COST} KiB cap \
             this build will derive under"
        )));
    }
    Ok(())
}

/// Stretches a passphrase to a 32-byte AEAD key via Argon2id with the given salt.
fn derive_from_passphrase(
    passphrase: &[u8],
    salt: &[u8; KEK_SALT_LEN],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    validated_costs(params)?;
    use argon2::{Algorithm, Argon2, Version};
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_argon2());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|e| VaultError::InvalidArgon2Params(format!("deriving a kek key failed: {e}")))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// The passphrase wrapping of K, and its two on-disk formats
// ---------------------------------------------------------------------------
//
// **v1** — `salt(16) || nonce(24) || ct+tag(48)`, exactly 88 bytes, with the
// Argon2 costs living only in `params.toml`.
//
// **v2** — `magic(4) || version(1) || m_cost(4) || t_cost(4) || p_cost(4) ||
// salt(16) || nonce(24) || ct+tag`: the costs travel **inside** the blob they
// describe.
//
// v2 exists because `k.self` and `params.toml` are otherwise two files that
// must agree, and POSIX offers no atomic rename of two files. Every ordering of
// a two-file write leaves a crash window in which the stored parameters do not
// derive the key that wraps `K` — a vault no passphrase can open. Embedding
// deletes that failure mode instead of guarding it. Full reasoning:
// slice 005's `## Design locks` in the soft-fig garden.
//
// `params.toml` is **not** rewritten by a rewrap and remains authoritative for
// v1 blobs still on disk. That matters concretely: `rewrap` cannot rewrite
// `k.recovery` (opening it needs the phrase, which may be lost), so a rewrapped
// vault legitimately holds a v2 `k.self` beside a v1 `k.recovery`, and the
// fallback branch below can never be deleted.

/// Magic prefix of a v2 passphrase wrapping.
pub const KEK_V2_MAGIC: &[u8; 4] = b"SFK2";

/// Version byte carried by a v2 wrapping.
pub const KEK_WRAPPING_V2: u8 = 2;

/// magic(4) + version(1) + three u32 costs.
const V2_HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4;

/// The smallest body a v2 wrapping can have: salt, nonce, a `KEY_LEN` key, and
/// the AEAD tag.
const V2_MIN_BODY_LEN: usize = KEK_SALT_LEN + AEAD_NONCE_LEN + KEY_LEN + AEAD_TAG_LEN;

/// Does this blob carry its own parameters?
///
/// Requires the magic **and** a body long enough to be a wrapping, and the
/// length half is what makes the dispatch structural rather than probabilistic.
/// Every v1 blob is exactly `KEK_SALT_LEN + AEAD_NONCE_LEN + KEY_LEN +
/// AEAD_TAG_LEN` = 88 bytes, so read as v2 it would leave 71 body bytes against
/// an 88-byte minimum: **no v1 blob can reach the v2 branch on any input**,
/// including the 2^-32 case where its random salt happens to begin with the
/// magic. Dispatching on the magic alone would put that 2^-32 against a bricked
/// vault, which is not a trade worth making for four bytes of comparison.
///
/// The cost of preferring structure to trust: a *truncated* v2 blob falls to
/// the v1 branch and surfaces as [`VaultError::AuthFailed`] rather than
/// `Malformed`. Diagnosing it precisely would mean trusting the magic alone,
/// which is the brick above.
fn is_v2(wrapped: &[u8]) -> bool {
    wrapped.len() >= V2_HEADER_LEN + V2_MIN_BODY_LEN && &wrapped[..4] == KEK_V2_MAGIC
}

fn encode_v2_header(params: &Argon2Params) -> [u8; V2_HEADER_LEN] {
    let mut h = [0u8; V2_HEADER_LEN];
    h[..4].copy_from_slice(KEK_V2_MAGIC);
    h[4] = KEK_WRAPPING_V2;
    h[5..9].copy_from_slice(&params.m_cost.to_be_bytes());
    h[9..13].copy_from_slice(&params.t_cost.to_be_bytes());
    h[13..17].copy_from_slice(&params.p_cost.to_be_bytes());
    h
}

/// Read a v2 header. Caller must have checked [`is_v2`], which guarantees the
/// length. An unknown version is a hard refusal rather than a v1 fallback: a
/// blob written by a newer soft-fig should say so, not fail as a bad
/// passphrase.
fn decode_v2_header(wrapped: &[u8]) -> Result<Argon2Params> {
    let version = wrapped[4];
    if version != KEK_WRAPPING_V2 {
        return Err(VaultError::UnsupportedFormat(u32::from(version)));
    }
    Ok(Argon2Params {
        m_cost: u32::from_be_bytes(wrapped[5..9].try_into().unwrap()),
        t_cost: u32::from_be_bytes(wrapped[9..13].try_into().unwrap()),
        p_cost: u32::from_be_bytes(wrapped[13..17].try_into().unwrap()),
    })
}

/// AAD for a v2 wrapping: the purpose tag with the header appended.
///
/// The costs sit in the clear so a reader can derive without them being secret,
/// but binding them into the AEAD makes editing them an authentication failure
/// rather than a mystery — the parameters become part of the sealed envelope.
/// The salt is already a KDF input and the nonce is bound by the construction,
/// so the header is the only piece that needed it.
fn v2_aad(base: &[u8], header: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + header.len());
    out.extend_from_slice(base);
    out.extend_from_slice(header);
    out
}

/// The parameters a passphrase wrapping was written under, and where they came
/// from.
#[derive(Debug, Clone, Copy)]
pub struct WrappingParams {
    pub params: Argon2Params,
    /// True when the blob carried its own costs (v2). `vault status` reports
    /// this, because presenting a v1 blob's `params.toml` costs as if they were
    /// self-describing would misrepresent what a rewrap has and has not done.
    pub embedded: bool,
}

/// The parameters a wrapping will actually be opened under: the ones it carries
/// if it is v2, otherwise `fallback` — which is where a v1 blob's parameters
/// live, namely `params.toml`.
///
/// Reads the header only. Opens nothing, so it stays usable on a locked vault.
pub fn wrapping_params(wrapped: &[u8], fallback: &Argon2Params) -> WrappingParams {
    if is_v2(wrapped)
        && let Ok(params) = decode_v2_header(wrapped) {
            return WrappingParams {
                params,
                embedded: true,
            };
        }
    WrappingParams {
        params: *fallback,
        embedded: false,
    }
}

/// Wrap K under a passphrase, in the current (v2) format.
///
/// One writer, one format: `init`, `recover`, `recovery add`, and `rewrap` all
/// come through here, because two writers emitting two formats is exactly the
/// skew embedding exists to prevent. The v1 branch of
/// [`unwrap_kek_under_passphrase`] is a *reader* concession to blobs already on
/// disk, not a live format.
///
/// The costs are validated and capped before deriving (the same guard the
/// unwrap path applies to a blob's embedded costs), so a caller passing costs
/// this build refuses to derive under gets an error, never a panic.
pub fn wrap_kek_under_passphrase(
    passphrase: &[u8],
    kek: &Kek,
    params: &Argon2Params,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let header = encode_v2_header(params);
    let mut salt = [0u8; KEK_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let derived = derive_from_passphrase(passphrase, &salt, params)?;
    let ct = aead_seal(&derived, &nonce, &v2_aad(aad, &header), kek.expose());

    let mut out = Vec::with_capacity(V2_HEADER_LEN + KEK_SALT_LEN + AEAD_NONCE_LEN + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap K from either format.
///
/// `fallback_params` is used **only** for a v1 blob; a v2 blob is opened under
/// the costs it carries. Every caller already passes `params.toml`'s costs,
/// which is precisely the right fallback, so the dispatch needed no call-site
/// changes — including `escrow::prove_openable`, which passes the bundle's own
/// `params.toml` member and thereby prefers the embedded costs automatically.
///
/// Whichever source wins, the costs are validated and capped before any
/// derivation: a blob (or a `params.toml`) carrying costs Argon2 rejects, or an
/// `m_cost` past [`MAX_CALIBRATED_M_COST`], yields an error — this path never
/// panics or aborts on the bytes it is handed.
pub fn unwrap_kek_under_passphrase(
    passphrase: &[u8],
    wrapped: &[u8],
    fallback_params: &Argon2Params,
    aad: &[u8],
) -> Result<Kek> {
    let (params, aad_bytes, body) = if is_v2(wrapped) {
        let params = decode_v2_header(wrapped)?;
        let aad_bytes = v2_aad(aad, &wrapped[..V2_HEADER_LEN]);
        (params, aad_bytes, &wrapped[V2_HEADER_LEN..])
    } else {
        if wrapped.len() < KEK_SALT_LEN + AEAD_NONCE_LEN {
            return Err(VaultError::Malformed("wrapped kek too short"));
        }
        (*fallback_params, aad.to_vec(), wrapped)
    };

    let salt: [u8; KEK_SALT_LEN] = body[..KEK_SALT_LEN].try_into().unwrap();
    let nonce: [u8; AEAD_NONCE_LEN] = body[KEK_SALT_LEN..KEK_SALT_LEN + AEAD_NONCE_LEN]
        .try_into()
        .unwrap();
    let ct = &body[KEK_SALT_LEN + AEAD_NONCE_LEN..];

    let derived = derive_from_passphrase(passphrase, &salt, &params)?;
    let pt = aead_open(&derived, &nonce, &aad_bytes, ct)?;
    if pt.len() != KEY_LEN {
        return Err(VaultError::Malformed("kek plaintext wrong length"));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&pt);
    Ok(Kek::from_bytes(k))
}

/// Write a v1 wrapping — the pre-embedding format, with the costs left in
/// `params.toml`.
///
/// Test-only, and deliberately so: nothing in production writes v1 any more
/// (see [`wrap_kek_under_passphrase`]), but the reader's fallback branch must
/// stay exercised, and the only honest way to test reading a legacy blob is to
/// produce a real one rather than a hand-rolled fixture that drifts.
#[cfg(test)]
pub(crate) fn wrap_kek_under_passphrase_v1(
    passphrase: &[u8],
    kek: &Kek,
    params: &Argon2Params,
    aad: &[u8],
) -> Vec<u8> {
    let mut salt = [0u8; KEK_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let derived =
        derive_from_passphrase(passphrase, &salt, params).expect("test params are validated");
    let ct = aead_seal(&derived, &nonce, aad, kek.expose());

    let mut out = Vec::with_capacity(KEK_SALT_LEN + AEAD_NONCE_LEN + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::aad;

    /// Argon2 at its minimum legal cost — these tests are about the byte
    /// layout, not about how long a derivation takes.
    fn fast() -> Argon2Params {
        Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// Deliberately different costs, used as the `params.toml` fallback to
    /// prove that a v2 blob ignores it.
    fn other() -> Argon2Params {
        Argon2Params {
            m_cost: 16,
            t_cost: 2,
            p_cost: 1,
        }
    }

    fn v1_blob(passphrase: &[u8], kek: &Kek, params: &Argon2Params) -> Vec<u8> {
        wrap_kek_under_passphrase_v1(passphrase, kek, params, aad::KEK_SELF)
    }

    #[test]
    fn a_v2_wrapping_opens_under_its_own_costs_and_ignores_the_fallback() {
        let kek = Kek::generate();
        let blob = wrap_kek_under_passphrase(b"pw", &kek, &fast(), aad::KEK_SELF).expect("wrap");
        // The fallback is wrong on purpose: if it were consulted the derivation
        // would produce a different key and this would fail. Passing means the
        // costs really do travel inside the blob — which is the whole slice.
        let opened = unwrap_kek_under_passphrase(b"pw", &blob, &other(), aad::KEK_SELF).unwrap();
        assert_eq!(opened.expose(), kek.expose());
    }

    #[test]
    fn a_v1_wrapping_still_opens_under_the_fallback_costs() {
        let kek = Kek::generate();
        let blob = v1_blob(b"pw", &kek, &fast());
        let opened = unwrap_kek_under_passphrase(b"pw", &blob, &fast(), aad::KEK_SELF).unwrap();
        assert_eq!(opened.expose(), kek.expose());
        // ...and only under the right ones. A v1 blob has no way to correct a
        // `params.toml` that disagrees with it, which is the failure mode
        // embedding removes.
        assert!(matches!(
            unwrap_kek_under_passphrase(b"pw", &blob, &other(), aad::KEK_SELF),
            Err(VaultError::AuthFailed)
        ));
    }

    #[test]
    fn every_v1_blob_is_exactly_88_bytes_and_never_reads_as_v2() {
        let kek = Kek::generate();
        for _ in 0..8 {
            let blob = v1_blob(b"pw", &kek, &fast());
            assert_eq!(blob.len(), KEK_SALT_LEN + AEAD_NONCE_LEN + KEY_LEN + AEAD_TAG_LEN);
            assert!(!is_v2(&blob));
        }
    }

    #[test]
    fn a_v1_blob_whose_salt_begins_with_the_magic_still_opens() {
        // The 2^-32 collision, constructed rather than waited for. This is the
        // case that would brick a vault under a magic-only dispatch, and it is
        // the reason the reader also requires a body long enough to be a
        // wrapping.
        let kek = Kek::generate();
        let params = fast();
        let mut salt = [7u8; KEK_SALT_LEN];
        salt[..4].copy_from_slice(KEK_V2_MAGIC);
        let nonce = [3u8; AEAD_NONCE_LEN];
        let derived = derive_from_passphrase(b"pw", &salt, &params).expect("validated params");
        let ct = aead_seal(&derived, &nonce, aad::KEK_SELF, kek.expose());

        let mut blob = Vec::new();
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);

        assert_eq!(blob.len(), 88);
        assert!(!is_v2(&blob), "88 bytes is too short to be a v2 wrapping");
        let opened = unwrap_kek_under_passphrase(b"pw", &blob, &params, aad::KEK_SELF).unwrap();
        assert_eq!(opened.expose(), kek.expose());
    }

    #[test]
    fn editing_the_embedded_costs_is_an_authentication_failure() {
        let kek = Kek::generate();
        let mut blob = wrap_kek_under_passphrase(b"pw", &kek, &fast(), aad::KEK_SELF).expect("wrap");
        // Rewrite m_cost in the header to the same value the derivation would
        // have used anyway if the header were not authenticated...
        blob[5..9].copy_from_slice(&16u32.to_be_bytes());
        assert!(matches!(
            unwrap_kek_under_passphrase(b"pw", &blob, &fast(), aad::KEK_SELF),
            Err(VaultError::AuthFailed)
        ));
    }

    #[test]
    fn an_unknown_wrapping_version_is_refused_rather_than_read_as_v1() {
        let kek = Kek::generate();
        let mut blob = wrap_kek_under_passphrase(b"pw", &kek, &fast(), aad::KEK_SELF).expect("wrap");
        blob[4] = 9;
        // A blob from a newer soft-fig must say so, not masquerade as a bad
        // passphrase and send someone re-typing a passphrase that was right.
        assert!(matches!(
            unwrap_kek_under_passphrase(b"pw", &blob, &fast(), aad::KEK_SELF),
            Err(VaultError::UnsupportedFormat(9))
        ));
    }

    #[test]
    fn the_wrong_passphrase_fails_in_both_formats() {
        let kek = Kek::generate();
        let v2 = wrap_kek_under_passphrase(b"pw", &kek, &fast(), aad::KEK_SELF).expect("wrap");
        let v1 = v1_blob(b"pw", &kek, &fast());
        for blob in [v2, v1] {
            assert!(matches!(
                unwrap_kek_under_passphrase(b"nope", &blob, &fast(), aad::KEK_SELF),
                Err(VaultError::AuthFailed)
            ));
        }
    }

    #[test]
    fn a_wrapping_written_for_one_purpose_does_not_open_under_another() {
        // The AAD extension must not have cost the domain separation the
        // constant provided.
        let kek = Kek::generate();
        let blob = wrap_kek_under_passphrase(b"pw", &kek, &fast(), aad::KEK_SELF).expect("wrap");
        assert!(matches!(
            unwrap_kek_under_passphrase(b"pw", &blob, &fast(), aad::KEK_RECOVERY),
            Err(VaultError::AuthFailed)
        ));
    }

    #[test]
    fn wrapping_params_reports_the_source_of_the_costs() {
        let kek = Kek::generate();
        let v2 = wrap_kek_under_passphrase(b"pw", &kek, &fast(), aad::KEK_SELF).expect("wrap");
        let read = wrapping_params(&v2, &other());
        assert!(read.embedded);
        assert_eq!(read.params, fast());

        let v1 = v1_blob(b"pw", &kek, &fast());
        let read = wrapping_params(&v1, &other());
        assert!(!read.embedded);
        assert_eq!(read.params, other(), "a v1 blob reports the fallback");
    }

    /// A hand-crafted v2 blob: valid magic and version, so the reader
    /// dispatches to v2 and takes the header's word for the costs. `t_cost = 0`
    /// is exactly what `to_argon2` panics on — the read path must return an
    /// error instead, and never even start the derivation.
    #[test]
    fn a_v2_blob_carrying_argon2_rejected_costs_is_refused_not_a_panic() {
        let mut blob = vec![0u8; V2_HEADER_LEN + V2_MIN_BODY_LEN];
        blob[..4].copy_from_slice(KEK_V2_MAGIC);
        blob[4] = KEK_WRAPPING_V2;
        // m_cost 8 and p_cost 1 are legal together; t_cost 0 is what Argon2
        // rejects.
        blob[5..9].copy_from_slice(&8u32.to_be_bytes());
        blob[9..13].copy_from_slice(&0u32.to_be_bytes());
        blob[13..17].copy_from_slice(&1u32.to_be_bytes());

        assert!(matches!(
            unwrap_kek_under_passphrase(b"pw", &blob, &fast(), aad::KEK_SELF),
            Err(VaultError::InvalidArgon2Params(_))
        ));
    }

    /// An absurd `m_cost` used to reach Argon2's allocation as a process abort
    /// via the old `.expect`; it must be refused at the cap before any memory
    /// is asked for.
    #[test]
    fn a_v2_blob_carrying_an_absurd_m_cost_is_refused_at_the_cap() {
        let mut blob = vec![0u8; V2_HEADER_LEN + V2_MIN_BODY_LEN];
        blob[..4].copy_from_slice(KEK_V2_MAGIC);
        blob[4] = KEK_WRAPPING_V2;
        blob[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        blob[9..13].copy_from_slice(&1u32.to_be_bytes());
        blob[13..17].copy_from_slice(&1u32.to_be_bytes());

        assert!(matches!(
            unwrap_kek_under_passphrase(b"pw", &blob, &fast(), aad::KEK_SELF),
            Err(VaultError::InvalidArgon2Params(_))
        ));
    }

    /// The v1 fallback is validated too: a `params.toml` with rejected costs
    /// must fail the same way, since it is equally untrusted bytes on disk.
    #[test]
    fn a_v1_blob_under_rejected_fallback_costs_is_refused_not_a_panic() {
        let kek = Kek::generate();
        let blob = v1_blob(b"pw", &kek, &fast());
        let rejected = Argon2Params {
            m_cost: 8,
            t_cost: 0,
            p_cost: 1,
        };
        assert!(matches!(
            unwrap_kek_under_passphrase(b"pw", &blob, &rejected, aad::KEK_SELF),
            Err(VaultError::InvalidArgon2Params(_))
        ));
    }
}
