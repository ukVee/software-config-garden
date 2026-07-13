//! M5d — keeperd's side of the collaborative key ceremony: the trait impls that
//! bind the pure, transport-agnostic drive loop in [`softfig_net::ceremony`] to
//! this daemon's live state.
//!
//! The protocol, the commit-reveal state machine, and the mesh drive loop all
//! live in `softfig-net` (headlessly mock-tested). keeperd only supplies the
//! seams that need the daemon's real muscle, mirroring how [`crate::replica`]
//! supplies `RepoSource`/`MirrorStore` to the replication drive loop:
//!
//! * [`VaultCeremonySigner`] — a [`CeremonySigner`] over the unlocked vault
//!   session, so a ceremony frame is signed by the device's Ed25519 identity key
//!   (the same key its ring `device_id` is) and verifies on every peer.
//! * [`assemble_member_set`] — turns this device's network ring into the
//!   participating id set the ceremony runs over.
//!
//! Still to land as slice 001's keeperd wiring completes (see the baton): a
//! `CeremonyTransport` over the subtree's live per-peer Noise sessions plus the
//! `SharedKeyCommit`-first inbound dispatch in `net.rs` (the responder path),
//! then the add→ceremony hook that persists the derived `S` + its transcript.

use std::sync::Arc;

use softfig_net::ceremony::CeremonySigner;
use softfig_net::Ring;
use softfig_vault::VaultSession;

/// A [`CeremonySigner`] backed by the daemon's unlocked vault session.
///
/// Signs a ceremony commit/reveal message with the device's Ed25519 **identity**
/// key — the very key its ring `device_id` is — so a peer authenticates the
/// frame with [`verify_commit_sig`](softfig_net::ceremony::verify_commit_sig) /
/// [`verify_reveal_sig`](softfig_net::ceremony::verify_reveal_sig) against the
/// sender's `device_id`. The byte layout signed over lives in `softfig-net`
/// (`commit`/`reveal_signing_bytes`); only the key crosses this boundary — the
/// same signer/driver split [`crate::replica`] uses for the vault-signed tip
/// announce and grant.
#[derive(Debug)]
pub struct VaultCeremonySigner {
    session: Arc<VaultSession>,
}

impl VaultCeremonySigner {
    /// Wrap an unlocked vault session as a ceremony signer.
    pub fn new(session: Arc<VaultSession>) -> Self {
        Self { session }
    }
}

impl CeremonySigner for VaultCeremonySigner {
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        // `VaultSession::sign` uses the identity key; `.to_bytes()` is the wire
        // form the driver's verifiers expect.
        self.session.sign(msg).to_bytes()
    }
}

/// Assemble the ceremony's participating member set from this device's network
/// ring: **this device plus every paired ring peer**.
///
/// This is the v1 member set — the whole ring. The spec's per-subtree `members`
/// subset (`meta/spec-sync.md` §"Allow-list config") is a future extension: once
/// [`SharedSubtreeEntry`](softfig_vcs::SharedSubtreeEntry) carries an explicit
/// member list, that subset is validated here against the ring (each named id
/// must be a real [`Ring::get`] peer) before it reaches the ceremony. The final
/// sort / dedup / `≥ 2` invariants are owned by
/// [`Ceremony::new`](softfig_net::ceremony::Ceremony::new) — the single place
/// they live — so this only gathers the ids; it does not re-impose them.
///
/// A device is never its own ring peer, so `local_id` cannot collide with a peer
/// id; an empty ring yields a one-element set that `Ceremony::new` then rejects
/// (a collaborative key needs at least one collaborator).
pub fn assemble_member_set(ring: &Ring, local_id: [u8; 32]) -> Vec<[u8; 32]> {
    let mut members = Vec::with_capacity(ring.peers().len() + 1);
    members.push(local_id);
    members.extend(ring.peers().iter().map(|p| p.device_id));
    members
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_net::ceremony::{commit_signing_bytes, commitment, verify_commit_sig, Ceremony, Phase};
    use softfig_net::RingEntry;

    /// A minimal ring row carrying just the `device_id` — `assemble_member_set`
    /// reads nothing else, and `Ring::upsert` never verifies the attestation
    /// (only `Ring::load` does), so the other fields can be placeholders.
    fn ring_entry(device_id: [u8; 32]) -> RingEntry {
        RingEntry {
            device_id,
            name: "peer".into(),
            transport_pubkey: [0u8; 32],
            endpoints: vec![],
            attestation: [0u8; 64],
            paired_at: 0,
        }
    }

    #[test]
    fn assembles_local_plus_every_ring_peer() {
        let local = [1u8; 32];
        let mut ring = Ring::default();
        ring.upsert(ring_entry([2u8; 32]));
        ring.upsert(ring_entry([3u8; 32]));

        let set = assemble_member_set(&ring, local);
        assert_eq!(set.len(), 3);
        assert!(set.contains(&local));
        assert!(set.contains(&[2u8; 32]));
        assert!(set.contains(&[3u8; 32]));

        // The set drives the pure ceremony: ≥ 2 members, local included.
        let c = Ceremony::new([7u8; 32], b"chain/x".to_vec(), &set, local, [9u8; 32]).unwrap();
        assert_eq!(c.phase(), Phase::Committing);
    }

    #[test]
    fn empty_ring_yields_a_set_the_ceremony_refuses() {
        let local = [1u8; 32];
        let set = assemble_member_set(&Ring::default(), local);
        assert_eq!(set, vec![local]);
        // A collaborative key needs a collaborator: the one-member set is refused
        // by the single owner of the invariant (`Ceremony::new`).
        assert!(Ceremony::new([7u8; 32], b"chain/x".to_vec(), &set, local, [9u8; 32]).is_err());
    }

    #[test]
    fn vault_signed_commit_verifies_under_the_device_id() {
        use softfig_vault::{params::VaultParams, Vault};

        let tmp = tempfile::tempdir().unwrap();
        let mut params = VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let (_v, session, _r) =
            Vault::init_with_params(tmp.path(), b"correct horse battery staple", params).unwrap();
        let session = Arc::new(session);

        let device_id = session.identity_pubkey().to_bytes();
        let signer = VaultCeremonySigner::new(Arc::clone(&session));

        let nonce = [7u8; 32];
        let chain_id = b"chain/projects";
        let r = [11u8; 32];
        let comm = commitment(&nonce, &device_id, &r);
        let sig = signer.sign(&commit_signing_bytes(&nonce, chain_id, &device_id, &comm));

        // The vault-signed bytes verify byte-for-byte under the driver's verifier
        // — the whole point of the trait impl (the vault-sign ↔ net-verify
        // contract that the live mesh rides on).
        assert!(verify_commit_sig(&nonce, chain_id, &device_id, &comm, &sig));
        // A tampered commitment no longer verifies under the same signature.
        let mut bad = comm;
        bad[0] ^= 1;
        assert!(!verify_commit_sig(&nonce, chain_id, &device_id, &bad, &sig));
    }
}
