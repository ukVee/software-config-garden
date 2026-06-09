//! The pairing state machine: Noise `XX` + attestation + SAS → a ring entry.
//!
//! Pairing turns a raw [`NoiseSession`] into a *recognised* peer. The flow,
//! symmetric on both devices:
//!
//! 1. **begin** — run the `XX` handshake ([`pair_initiator`] / [`pair_responder`]),
//!    carrying each device's [`HelloPayload`] (Ed25519 `device_id` + the
//!    self-signed transport attestation) in the encrypted handshake payloads.
//! 2. **verify** — check the peer's attestation binds its advertised `device_id`
//!    to the X25519 static the handshake authenticated. A failure aborts here.
//! 3. **compute SAS** — derive the short code from the handshake hash.
//! 4. **await confirm** — surface the [`Sas`] (shown on both devices) and the
//!    candidate [`RingEntry`]; the user compares the codes out of band.
//! 5. **confirm** — on a match, hand back the ring entry to persist (and the
//!    live session). A mismatch ⇒ drop the [`PendingPair`] (MITM, abort).
//!
//! This crate stays frontend-neutral: the Ed25519 identity secret never enters
//! `softfig-net`. The caller (keeperd, M5a-4) precomputes the attestation with
//! `VaultSession::sign(&static_attestation_message(&transport_pubkey))` and
//! passes it in via [`LocalDevice`]; persistence ([`Ring::save`](crate::ring::Ring::save))
//! and the user-confirm prompt are likewise the host's job. SAS confirmation is
//! out of band by design — there is no "confirm" control frame on the wire, so
//! a MITM cannot forge agreement.

use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::attest::{verify_static_attestation, KEY_LEN, SIG_LEN};
use crate::error::{NetError, Result};
use crate::proto::HelloPayload;
use crate::ring::RingEntry;
use crate::sas::Sas;
use crate::transport::{xx_initiator, xx_responder, NoiseSession};

/// This device's pairing material. The Ed25519 identity secret is *not* here:
/// `static_attestation` is the precomputed signature over this device's own
/// X25519 transport public key (see the module docs), so the vault keeps the
/// secret.
#[derive(Clone)]
pub struct LocalDevice {
    /// Raw X25519 transport secret — the Noise static (`Session::transport_secret`).
    pub transport_secret: [u8; KEY_LEN],
    /// Ed25519 identity public key — this device's id.
    pub device_id: [u8; KEY_LEN],
    /// Human-readable device name.
    pub device_name: String,
    /// Ed25519 signature over this device's own X25519 transport static.
    pub static_attestation: [u8; SIG_LEN],
}

impl LocalDevice {
    /// This device's in-handshake identity payload: Ed25519 `device_id`, name,
    /// and the self-signed transport attestation. Reused by the relay client
    /// (M5a-3) for the outer control connection's handshake.
    pub fn hello(&self) -> HelloPayload {
        let mut hello = HelloPayload::new(self.device_id.to_vec(), self.device_name.clone());
        hello.static_attestation = self.static_attestation.to_vec();
        hello
    }
}

/// A handshake that completed and passed attestation, awaiting the user's SAS
/// confirmation. Holds the live session so the caller can keep using the
/// channel after confirming.
pub struct PendingPair<S> {
    session: NoiseSession<S>,
    sas: Sas,
    peer: RingEntry,
}

impl<S> PendingPair<S> {
    /// The SAS to display. The user confirms it matches the peer device's.
    pub fn sas(&self) -> Sas {
        self.sas
    }

    /// The candidate ring entry for the peer (written on [`Self::confirm`]).
    pub fn peer(&self) -> &RingEntry {
        &self.peer
    }

    /// The established Noise session.
    pub fn session(&self) -> &NoiseSession<S> {
        &self.session
    }

    /// The user confirmed the SAS matched on the other device. Yields the live
    /// session and the [`RingEntry`] to persist via
    /// [`Ring::upsert`](crate::ring::Ring::upsert) + `save`.
    pub fn confirm(self) -> (NoiseSession<S>, RingEntry) {
        (self.session, self.peer)
    }

    /// The SAS did **not** match (suspected MITM): drop the pairing. Provided
    /// for call-site clarity; dropping the value does the same.
    pub fn reject(self) {}
}

/// Begin pairing as the **initiator** (the already-trusted device reaching out
/// to a fresh one).
pub fn pair_initiator<S: Read + Write>(io: S, local: &LocalDevice) -> Result<PendingPair<S>> {
    let session = xx_initiator(io, &local.transport_secret, &local.hello())?;
    settle(session)
}

/// Begin pairing as the **responder** (the fresh device being added).
pub fn pair_responder<S: Read + Write>(io: S, local: &LocalDevice) -> Result<PendingPair<S>> {
    let session = xx_responder(io, &local.transport_secret, &local.hello())?;
    settle(session)
}

/// Post-handshake: verify the peer's attestation, derive the SAS, build the
/// candidate ring entry.
fn settle<S>(session: NoiseSession<S>) -> Result<PendingPair<S>> {
    let hello = session.peer_hello();

    let device_id: [u8; KEY_LEN] = hello
        .device_id
        .as_slice()
        .try_into()
        .map_err(|_| NetError::Protocol("peer device_id wrong length"))?;
    let attestation: [u8; SIG_LEN] = hello
        .static_attestation
        .as_slice()
        .try_into()
        .map_err(|_| NetError::Protocol("peer static_attestation wrong length"))?;
    let transport_pubkey = *session.peer_static();

    // Bind the peer's Ed25519 identity to the X25519 static the XX handshake
    // authenticated. Without this, XX proves only that the peer holds *some*
    // transport key, not which identity owns it.
    if !verify_static_attestation(&device_id, &transport_pubkey, &attestation) {
        return Err(NetError::Protocol(
            "peer attestation does not bind its device_id to its transport key",
        ));
    }

    let sas = Sas::from_handshake_hash(session.handshake_hash());
    let peer = RingEntry {
        device_id,
        name: hello.device_name.clone(),
        transport_pubkey,
        endpoints: Vec::new(), // populated by discovery (M5a-3)
        attestation,
        paired_at: now_unix(),
    };

    Ok(PendingPair { session, sas, peer })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::static_attestation_message;
    use ed25519_dalek::{Signer, SigningKey};
    use std::os::unix::net::UnixStream;
    use std::thread;

    /// Build a `LocalDevice` with a valid self-attestation from raw seeds.
    fn device(name: &str, id_seed: u8, transport_seed: u8) -> LocalDevice {
        let id = SigningKey::from_bytes(&[id_seed; 32]);
        let transport_secret = [transport_seed; 32];
        let transport_pubkey =
            x25519_dalek::x25519(transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        let static_attestation = id
            .sign(&static_attestation_message(&transport_pubkey))
            .to_bytes();
        LocalDevice {
            transport_secret,
            device_id: id.verifying_key().to_bytes(),
            device_name: name.into(),
            static_attestation,
        }
    }

    /// Pair two devices over an in-process socket pair, returning both
    /// `PendingPair`s.
    fn pair(
        a: LocalDevice,
        b: LocalDevice,
    ) -> (
        Result<PendingPair<UnixStream>>,
        Result<PendingPair<UnixStream>>,
    ) {
        let (sa, sb) = UnixStream::pair().unwrap();
        let responder = thread::spawn(move || pair_responder(sb, &b));
        let initiator = pair_initiator(sa, &a);
        (initiator, responder.join().unwrap())
    }

    #[test]
    fn two_devices_pair_with_matching_sas_and_symmetric_entries() {
        let alice = device("alice", 1, 2);
        let bob = device("bob", 3, 4);
        let (init, resp) = pair(alice.clone(), bob.clone());
        let init = init.unwrap();
        let resp = resp.unwrap();

        // Both honest endpoints derive the same SAS.
        assert_eq!(init.sas().code(), resp.sas().code());

        // Symmetric ring entries: each side's candidate describes the *other*.
        let (_s1, alice_sees_bob) = init.confirm();
        let (_s2, bob_sees_alice) = resp.confirm();

        assert_eq!(alice_sees_bob.device_id, bob.device_id);
        assert_eq!(alice_sees_bob.name, "bob");
        assert_eq!(bob_sees_alice.device_id, alice.device_id);
        assert_eq!(bob_sees_alice.name, "alice");

        // The transport key each side stored is the other's real public key,
        // and each stored attestation verifies against the stored id.
        let bob_tpub = x25519_dalek::x25519([4u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        assert_eq!(alice_sees_bob.transport_pubkey, bob_tpub);
        assert!(alice_sees_bob.verify());
        assert!(bob_sees_alice.verify());
    }

    #[test]
    fn mitm_yields_mismatched_sas() {
        // An attacker M sits in the middle, running a separate XX session with
        // each victim using its own keys. Both sessions succeed (M is a valid
        // Noise peer with a valid self-attestation) — but the two handshake
        // hashes differ, so the SAS each victim sees differs and the user
        // catches it.
        let alice = device("alice", 1, 2);
        let mallory = device("mallory", 5, 6);
        let bob = device("bob", 3, 4);

        // Leg 1: alice (initiator) <-> mallory (responder).
        let (a_side, _m1) = pair(alice.clone(), mallory.clone());
        // Leg 2: mallory (initiator) <-> bob (responder).
        let (_m2, b_side) = pair(mallory, bob);

        let alice_sas = a_side.unwrap().sas().code();
        let bob_sas = b_side.unwrap().sas().code();
        assert_ne!(
            alice_sas, bob_sas,
            "the two MITM legs must produce different SAS codes"
        );
    }

    #[test]
    fn initiator_rejects_tampered_responder_attestation() {
        // Bob ships a self-attestation that does not match his transport key
        // (a forged/garbled field 4). Alice — who verifies *Bob's* attestation
        // — must reject. Bob completed his side first (he verified Alice's good
        // attestation), so his result is Ok; the binding check is each side
        // checking the *other's* attestation.
        let alice = device("alice", 1, 2);
        let mut bob = device("bob", 3, 4);
        bob.static_attestation[0] ^= 0x01;

        let (init, resp) = pair(alice, bob);
        assert!(init.is_err(), "initiator must reject bad peer attestation");
        assert!(resp.is_ok());
    }

    #[test]
    fn responder_rejects_tampered_initiator_attestation() {
        // The symmetric case: Alice's attestation is bad, so Bob (responder)
        // must reject — exercises the responder side of the binding check.
        let mut alice = device("alice", 1, 2);
        alice.static_attestation[0] ^= 0x01;
        let bob = device("bob", 3, 4);

        let (init, resp) = pair(alice, bob);
        assert!(resp.is_err(), "responder must reject bad initiator attestation");
        assert!(init.is_ok());
    }

    #[test]
    fn rejects_attestation_for_wrong_transport_key() {
        // Bob's attestation is valid for a *different* transport key than the
        // one he actually handshakes with — the binding check must catch it.
        let alice = device("alice", 1, 2);
        let mut bob = device("bob", 3, 4);
        let id = SigningKey::from_bytes(&[3u8; 32]);
        let other_pub = x25519_dalek::x25519([99u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        bob.static_attestation = id.sign(&static_attestation_message(&other_pub)).to_bytes();

        let (init, _resp) = pair(alice, bob);
        assert!(init.is_err());
    }
}
