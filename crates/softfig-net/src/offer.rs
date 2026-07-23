//! M5f share-offer signing (recipient-chosen placement, slice 003).
//!
//! A sharer fans a signed `ShareOffer` to its ring peers so each recipient can
//! adopt the share at a mount path of its *own* choosing
//! ([[decision-shared-subtree-recipient-placement]]). Only the share identity +
//! the sharer's advisory `recommended_path` are signed — the recipient's real
//! placement is per-device state that never crosses the wire. Same
//! domain-separated, length-prefixed, non-canonical-protobuf discipline as the
//! `turn` / `ceremony` / `replica` frames: the driver re-derives these bytes
//! from the wire fields on receive and never signs a protobuf re-serialization.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const SHARE_OFFER_DOMAIN: &[u8] = b"softfig/offer/share/v1";

/// Canonical signed bytes for a `ShareOffer`. Domain-separated + length-prefixed
/// so no two field layouts collide (`recommended_path` is a plain UTF-8 string,
/// empty = no recommendation).
pub fn share_offer_signing_bytes(
    chain_id: &[u8],
    subtree: &str,
    recommended_path: &str,
    device_id: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        SHARE_OFFER_DOMAIN.len()
            + 4
            + chain_id.len()
            + 4
            + subtree.len()
            + 4
            + recommended_path.len()
            + 32,
    );
    m.extend_from_slice(SHARE_OFFER_DOMAIN);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(&(subtree.len() as u32).to_be_bytes());
    m.extend_from_slice(subtree.as_bytes());
    m.extend_from_slice(&(recommended_path.len() as u32).to_be_bytes());
    m.extend_from_slice(recommended_path.as_bytes());
    m.extend_from_slice(device_id);
    m
}

/// Verify a `ShareOffer` signature against the offering device's Ed25519
/// identity key. Never panics — a bad key, wrong-length signature, or a
/// non-verifying signature all return `false` (the fail-closed `turn`/`ceremony`
/// shape). A valid signature proves *who* offered; ring-membership authorization
/// (only a paired peer may offer us a share) is the authenticated Noise
/// session's job in keeperd.
pub fn verify_share_offer_sig(
    chain_id: &[u8],
    subtree: &str,
    recommended_path: &str,
    device_id: &[u8; 32],
    sig: &[u8],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(device_id) else {
        return false;
    };
    let Ok(sig_bytes): std::result::Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    vk.verify(
        &share_offer_signing_bytes(chain_id, subtree, recommended_path, device_id),
        &Signature::from_bytes(&sig_bytes),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let sk = key(7);
        let id = sk.verifying_key().to_bytes();
        let sig = sk
            .sign(&share_offer_signing_bytes(b"chain/wiki", "wiki", "shared/wiki", &id))
            .to_bytes();
        assert!(verify_share_offer_sig(
            b"chain/wiki",
            "wiki",
            "shared/wiki",
            &id,
            &sig
        ));
    }

    #[test]
    fn empty_recommendation_round_trips() {
        let sk = key(9);
        let id = sk.verifying_key().to_bytes();
        let sig = sk
            .sign(&share_offer_signing_bytes(b"chain/x", "x", "", &id))
            .to_bytes();
        assert!(verify_share_offer_sig(b"chain/x", "x", "", &id, &sig));
    }

    #[test]
    fn a_tampered_field_fails_verification() {
        let sk = key(11);
        let id = sk.verifying_key().to_bytes();
        let sig = sk
            .sign(&share_offer_signing_bytes(b"chain/wiki", "wiki", "shared/wiki", &id))
            .to_bytes();
        // Wrong recommended_path, wrong id, wrong subtree — each must reject.
        assert!(!verify_share_offer_sig(b"chain/wiki", "wiki", "elsewhere", &id, &sig));
        assert!(!verify_share_offer_sig(b"chain/wiki", "other", "shared/wiki", &id, &sig));
        let other = key(12).verifying_key().to_bytes();
        assert!(!verify_share_offer_sig(b"chain/wiki", "wiki", "shared/wiki", &other, &sig));
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        let id = [3u8; 32];
        // Shifting a byte across the subtree/recommended_path boundary must
        // produce different signed bytes (length-prefixing, not concatenation).
        let a = share_offer_signing_bytes(b"c", "ab", "cd", &id);
        let b = share_offer_signing_bytes(b"c", "abc", "d", &id);
        assert_ne!(a, b);
    }
}
