//! The delegated runner certificate (spec §3.1): a device identity's signature
//! binding a runner's two keys to that device.
//!
//! A runner (`softfig-runnerd`) generates its own **X25519 transport static**
//! and **Ed25519 attest key** at `softfig runner enable`. The runner's device
//! then signs a certificate over both, plus a serial and a validity window,
//! with the device's Ed25519 **identity** key:
//!
//! ```text
//! { device_id, runner_transport_pubkey, runner_attest_pubkey,
//!   serial, issued_at, expires_at }
//! ```
//!
//! The construction mirrors [`crate::attest`] (which binds a device's X25519
//! transport static to its identity so the Noise `XX` handshake can be trusted),
//! but it signs a *different* message under a *different* domain
//! (`softfig/runner/delegation/v1`), so a runner certificate can never be
//! confused with the pairing transport attestation. It is also structurally
//! disjoint from a commit signature: commits sign the BLAKE3 hash of a
//! JCS-canonical JSON object (`softfig-vcs`), a fixed 32-byte digest with no
//! domain byte-prefix, whereas a certificate signs the raw field bytes below.
//! Both separations are tested ([`tests::domain_separation_against_commit_signature`]).
//!
//! Signing goes through keeperd (`VaultSession::sign(&signing_message(&cert))`),
//! so the device identity secret never leaves the vault; this module holds no
//! secrets and only ever verifies. It must therefore never depend on
//! `softfig-vault`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::attest::{KEY_LEN, SIG_LEN};

/// Domain-separation prefix for the runner-certificate signing message.
/// Versioned so a future delegation scheme can coexist; distinct from every
/// other context the identity key signs (the pairing transport attestation,
/// commit signatures, turn leases).
pub const RUNNER_CERT_DOMAIN: &[u8] = b"softfig/runner/delegation/v1";

/// Length in bytes of a runner-certificate serial — a random 128-bit value that
/// is the unit of revocation (`RunnerCertRevoke(serial)`, slice 003).
pub const RUNNER_SERIAL_LEN: usize = 16;

/// Default certificate lifetime in seconds: 90 days (spec §3.1).
pub const RUNNER_DEFAULT_LIFETIME_SECS: i64 = 90 * 24 * 60 * 60;

/// One delegated runner certificate. The exact fields of spec §3.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerCert {
    /// Ed25519 identity public key of the device that signed this certificate —
    /// also the key the requester fetches from its own ring to verify it.
    pub device_id: [u8; KEY_LEN],
    /// The runner's X25519 transport static (Noise key agreement). The
    /// requester checks this equals the handshake's static key on first contact.
    pub runner_transport_pubkey: [u8; KEY_LEN],
    /// The runner's Ed25519 attest key — signs job attestations (§8), nothing
    /// else. A separate key from the transport static, like the device's own
    /// two-key split.
    pub runner_attest_pubkey: [u8; KEY_LEN],
    /// Random 128-bit serial, unique per certificate. The revocation unit.
    pub serial: [u8; RUNNER_SERIAL_LEN],
    /// When the certificate was issued, Unix seconds.
    pub issued_at: i64,
    /// When the certificate expires, Unix seconds (exclusive).
    pub expires_at: i64,
}

impl RunnerCert {
    /// The exact bytes the device identity signs to issue this certificate.
    /// See [`signing_message`].
    pub fn signing_message(&self) -> Vec<u8> {
        signing_message(self)
    }
}

/// The exact bytes a device's Ed25519 identity key signs to issue a runner
/// certificate. The vault holder produces the signature with
/// `VaultSession::sign(&signing_message(&cert))`; the secret never leaves the
/// vault. Verifiers reconstruct the same bytes.
pub fn signing_message(cert: &RunnerCert) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        RUNNER_CERT_DOMAIN.len()
            + KEY_LEN * 3
            + RUNNER_SERIAL_LEN
            + 2 * std::mem::size_of::<i64>(),
    );
    msg.extend_from_slice(RUNNER_CERT_DOMAIN);
    msg.extend_from_slice(&cert.device_id);
    msg.extend_from_slice(&cert.runner_transport_pubkey);
    msg.extend_from_slice(&cert.runner_attest_pubkey);
    msg.extend_from_slice(&cert.serial);
    msg.extend_from_slice(&cert.issued_at.to_le_bytes());
    msg.extend_from_slice(&cert.expires_at.to_le_bytes());
    msg
}

/// Verify a runner certificate against a ring identity and the current time.
///
/// Checks, in order:
/// 1. the certificate's `device_id` equals `ring_identity` (it is signed by the
///    device it claims — the identity the requester already holds in its ring);
/// 2. it has not yet expired (`now < expires_at`);
/// 3. its serial is not in `revoked_serials`;
/// 4. `signature` verifies over [`signing_message`] under `device_id`.
///
/// Returns `false` on a malformed key, malformed signature, expired/revoked
/// cert, wrong identity, or a signature that does not verify — never panics, so
/// a hostile peer or a tampered certificate simply fails the check.
pub fn verify(
    cert: &RunnerCert,
    signature: &[u8; SIG_LEN],
    ring_identity: &[u8; KEY_LEN],
    now: i64,
    revoked_serials: &[[u8; RUNNER_SERIAL_LEN]],
) -> bool {
    // 1. The cert must be signed by the identity the requester holds in its ring.
    if cert.device_id != *ring_identity {
        return false;
    }
    // 2. Not expired. A non-positive window is malformed and rejected too.
    if cert.expires_at <= cert.issued_at || now >= cert.expires_at {
        return false;
    }
    // 3. Not revoked.
    if revoked_serials.contains(&cert.serial) {
        return false;
    }
    // 4. Signature over the canonical bytes.
    let Ok(verifying_key) = VerifyingKey::from_bytes(&cert.device_id) else {
        return false;
    };
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify(&signing_message(cert), &signature)
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

    fn now() -> i64 {
        1_800_000_000
    }

    /// A well-formed, unexpired certificate issued by `id` over runner keys
    /// derived from `seed`.
    fn sample_cert(id: &SigningKey, seed: u8) -> RunnerCert {
        RunnerCert {
            device_id: id.verifying_key().to_bytes(),
            runner_transport_pubkey: x25519_pub(seed),
            runner_attest_pubkey: signer(seed.wrapping_add(100))
                .verifying_key()
                .to_bytes(),
            serial: [seed; RUNNER_SERIAL_LEN],
            issued_at: now() - 100,
            expires_at: now() + RUNNER_DEFAULT_LIFETIME_SECS,
        }
    }

    fn sign_cert(id: &SigningKey, cert: &RunnerCert) -> [u8; SIG_LEN] {
        id.sign(&signing_message(cert)).to_bytes()
    }

    #[test]
    fn round_trip_verifies() {
        let id = signer(1);
        let cert = sample_cert(&id, 2);
        let sig = sign_cert(&id, &cert);
        assert!(verify(
            &cert,
            &sig,
            &id.verifying_key().to_bytes(),
            now(),
            &[]
        ));
    }

    #[test]
    fn wrong_ring_identity_fails() {
        // The cert claims device_id A, but the requester holds B's identity.
        let id = signer(3);
        let cert = sample_cert(&id, 4);
        let sig = sign_cert(&id, &cert);
        let other = signer(5).verifying_key().to_bytes();
        assert!(!verify(&cert, &sig, &other, now(), &[]));
    }

    #[test]
    fn expired_fails() {
        let id = signer(6);
        let cert = sample_cert(&id, 7);
        let sig = sign_cert(&id, &cert);
        assert!(!verify(
            &cert,
            &sig,
            &id.verifying_key().to_bytes(),
            cert.expires_at, // now == expires_at → expired (exclusive)
            &[]
        ));
        assert!(!verify(
            &cert,
            &sig,
            &id.verifying_key().to_bytes(),
            cert.expires_at + 1,
            &[]
        ));
    }

    #[test]
    fn revoked_fails() {
        let id = signer(8);
        let cert = sample_cert(&id, 9);
        let sig = sign_cert(&id, &cert);
        assert!(!verify(
            &cert,
            &sig,
            &id.verifying_key().to_bytes(),
            now(),
            &[cert.serial]
        ));
        // A different serial is not a match.
        assert!(verify(
            &cert,
            &sig,
            &id.verifying_key().to_bytes(),
            now(),
            &[[0xAA; RUNNER_SERIAL_LEN]]
        ));
    }

    #[test]
    fn malformed_window_fails() {
        let id = signer(10);
        let mut cert = sample_cert(&id, 11);
        cert.expires_at = cert.issued_at; // zero-length window
        let sig = sign_cert(&id, &cert);
        assert!(!verify(
            &cert,
            &sig,
            &id.verifying_key().to_bytes(),
            now(),
            &[]
        ));
    }

    #[test]
    fn wrong_signer_fails() {
        // A different identity signs the same cert fields.
        let real = signer(12);
        let cert = sample_cert(&real, 13);
        let imposter = signer(14);
        let sig = imposter.sign(&signing_message(&cert)).to_bytes();
        assert!(!verify(
            &cert,
            &sig,
            &real.verifying_key().to_bytes(),
            now(),
            &[]
        ));
    }

    #[test]
    fn tampered_field_fails() {
        let id = signer(15);
        let cert = sample_cert(&id, 16);
        let sig = sign_cert(&id, &cert);
        // Flip one bit of the attest key after signing.
        let mut tampered = cert.clone();
        tampered.runner_attest_pubkey[0] ^= 0x01;
        assert!(!verify(
            &tampered,
            &sig,
            &id.verifying_key().to_bytes(),
            now(),
            &[]
        ));
    }

    #[test]
    fn tampered_signature_fails() {
        let id = signer(17);
        let cert = sample_cert(&id, 18);
        let mut sig = sign_cert(&id, &cert);
        sig[0] ^= 0x01;
        assert!(!verify(
            &cert,
            &sig,
            &id.verifying_key().to_bytes(),
            now(),
            &[]
        ));
    }

    #[test]
    fn domain_separation_against_transport_attestation() {
        // The same identity key, over the *same* runner transport key, signed
        // under two different domains. Neither signature may verify under the
        // other domain's rules.
        let id = signer(19);
        let cert = sample_cert(&id, 20);
        let transport = cert.runner_transport_pubkey;

        let cert_sig = sign_cert(&id, &cert);
        let attest_sig = id
            .sign(&crate::attest::static_attestation_message(&transport))
            .to_bytes();

        // The cert signature is not a valid transport attestation…
        assert!(!crate::attest::verify_static_attestation(
            &id.verifying_key().to_bytes(),
            &transport,
            &cert_sig,
        ));
        // …and the attestation signature is not a valid runner certificate.
        assert!(!verify(
            &cert,
            &attest_sig,
            &id.verifying_key().to_bytes(),
            now(),
            &[]
        ));
    }

    #[test]
    fn domain_separation_against_commit_signature() {
        // Commit signatures (softfig-vcs) sign the BLAKE3 hash of a
        // JCS-canonical JSON object — a fixed 32-byte digest, no domain
        // byte-prefix. A runner certificate signs the raw field bytes. Signing
        // the same identity key over the commit shape must not verify as a
        // runner cert, and a runner-cert signature must not verify as a commit
        // signature over that digest.
        let id = signer(21);
        let cert = sample_cert(&id, 22);
        let cert_sig = sign_cert(&id, &cert);

        let commit_hash = blake3::hash(br#"{"intent":"gate","root_tree":"00"}"#);
        let commit_sig = id.sign(commit_hash.as_bytes()).to_bytes();

        // A commit-shaped signature does not verify as a runner certificate.
        assert!(!verify(
            &cert,
            &commit_sig,
            &id.verifying_key().to_bytes(),
            now(),
            &[]
        ));
        // A runner-cert signature does not verify as a commit-shaped signature
        // over the BLAKE3 digest.
        let vk = VerifyingKey::from_bytes(&id.verifying_key().to_bytes()).unwrap();
        assert!(
            vk.verify(commit_hash.as_bytes(), &Signature::from_bytes(&cert_sig))
                .is_err()
        );
    }
}
