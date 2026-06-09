//! The pairing attestation that binds a device's two keys.
//!
//! A device has two long-lived keys (see `softfig-vault`): an **Ed25519
//! identity** (signing-only — VCS commits, ring vouching) and a separate
//! **X25519 transport static** (Noise key agreement). The Noise `XX` handshake
//! authenticates *only* the X25519 static — it proves the peer holds that
//! private scalar, but says nothing about which Ed25519 identity owns it.
//!
//! The attestation closes that gap: each device signs its own X25519 transport
//! public key with its Ed25519 identity key, and ships the signature inside the
//! handshake [`HelloPayload`](crate::proto::HelloPayload) (field 4) alongside
//! its Ed25519 identity pubkey (`device_id`). The verifier checks the signature
//! against the `device_id` and the X25519 static the handshake just
//! authenticated; success means *one device owns both keys*, so the peer ring
//! can key future `IK` reconnects by transport key and verify commits by
//! identity key with confidence they are the same device.
//!
//! The signed message is domain-separated so an attestation signature can never
//! be replayed as (or confused with) a VCS commit signature made by the same
//! Ed25519 key.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Length of an Ed25519 signature.
pub const SIG_LEN: usize = 64;
/// Length of an Ed25519 / X25519 public key.
pub const KEY_LEN: usize = 32;

/// Domain-separation prefix for the transport-key attestation message. Versioned
/// so a future attestation scheme can coexist; distinct from any other context
/// the identity key signs (VCS commits, future ring vouching).
const ATTEST_DOMAIN: &[u8] = b"softfig/pairing/transport-attestation/v1";

/// The exact bytes a device's Ed25519 identity key signs to attest ownership of
/// its X25519 transport static. The vault holder produces the signature with
/// `VaultSession::sign(&static_attestation_message(&transport_pubkey))`; the
/// secret never leaves the vault. The verifier reconstructs the same bytes.
pub fn static_attestation_message(transport_pubkey: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ATTEST_DOMAIN.len() + KEY_LEN);
    msg.extend_from_slice(ATTEST_DOMAIN);
    msg.extend_from_slice(transport_pubkey);
    msg
}

/// Verify that `device_id` (an Ed25519 identity pubkey) signed `transport_pubkey`
/// as its own Noise static. Returns `false` on a malformed key, malformed
/// signature, or a signature that does not verify — never panics, so a hostile
/// peer or a tampered ring row simply fails the check.
pub fn verify_static_attestation(
    device_id: &[u8; KEY_LEN],
    transport_pubkey: &[u8; KEY_LEN],
    attestation: &[u8; SIG_LEN],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(device_id) else {
        return false;
    };
    let signature = Signature::from_bytes(attestation);
    verifying_key
        .verify(&static_attestation_message(transport_pubkey), &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn x25519_pub(seed: u8) -> [u8; KEY_LEN] {
        x25519_dalek::x25519([seed; 32], x25519_dalek::X25519_BASEPOINT_BYTES)
    }

    #[test]
    fn round_trip_verifies() {
        let id = signer(1);
        let tpub = x25519_pub(2);
        let sig = id.sign(&static_attestation_message(&tpub)).to_bytes();
        assert!(verify_static_attestation(
            &id.verifying_key().to_bytes(),
            &tpub,
            &sig
        ));
    }

    #[test]
    fn rejects_wrong_static() {
        let id = signer(3);
        let tpub = x25519_pub(4);
        let sig = id.sign(&static_attestation_message(&tpub)).to_bytes();
        let other = x25519_pub(5);
        assert!(!verify_static_attestation(
            &id.verifying_key().to_bytes(),
            &other,
            &sig
        ));
    }

    #[test]
    fn rejects_wrong_signer() {
        // A different identity key claims the same transport static.
        let real = signer(6);
        let tpub = x25519_pub(7);
        let sig = real.sign(&static_attestation_message(&tpub)).to_bytes();
        let imposter = signer(8).verifying_key().to_bytes();
        assert!(!verify_static_attestation(&imposter, &tpub, &sig));
    }

    #[test]
    fn rejects_tampered_signature() {
        let id = signer(9);
        let tpub = x25519_pub(10);
        let mut sig = id.sign(&static_attestation_message(&tpub)).to_bytes();
        sig[0] ^= 0x01;
        assert!(!verify_static_attestation(
            &id.verifying_key().to_bytes(),
            &tpub,
            &sig
        ));
    }
}
