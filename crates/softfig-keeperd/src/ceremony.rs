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
//! * [`SessionTransport`] — a [`CeremonyTransport`] over one live per-peer Noise
//!   session (the v1 2-member point-to-point topology), abstracted over a
//!   [`CeremonyLink`] so it is headlessly testable without a Noise handshake.
//!
//! Still to land as slice 001's keeperd wiring completes (see the baton): the
//! establishment glue that dials the peer (initiator) and the
//! `SharedKeyCommit`-first inbound dispatch in `net.rs` (responder) to build and
//! run these transports, then the add→ceremony hook that persists the derived
//! `S` + its transcript.

use std::io::{Read, Write};
use std::sync::Arc;

use softfig_net::ceremony::{CeremonySigner, CeremonyTransport};
use softfig_net::proto::Frame;
use softfig_net::transport::NoiseSession;
use softfig_net::{Result as NetResult, Ring};
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

// --- Live-session transport (slice 001 keeperd wiring) ----------------------
//
// [`softfig_net::ceremony::run_ceremony`] drives the pure state machine over a
// [`CeremonyTransport`]: `broadcast` fans a frame to every *other* member and
// `recv` blocks for the next inbound frame. The headless net tests back that
// trait with in-memory channels; keeperd backs it with a live per-peer Noise
// session — this is that impl.
//
// v1 topology is **2-member point-to-point** (the mission's "two paired
// devices"): the ceremony runs over a single Noise link, so "every other
// member" is the one peer on that link and `recv` reads that one session. A
// larger member set (star-with-initiator-relay or mesh) is a gated follow-up
// whose transport fans one frame to N−1 peers and multiplexes their inbound;
// this point-to-point transport is the crux the two-device case needs, and the
// establishment glue gates N ≥ 3 until that lands.
//
// Liveness (a peer that never sends) is the driver's concern per the
// [`CeremonyTransport`] contract: the underlying Noise session carries a socket
// read timeout (set by the inbound serve / outbound dial), so a silent peer
// makes `recv_frame` — and thus `run_ceremony` — return an error rather than
// block forever. No separate timer lives here.

/// The minimal "send / receive one [`Frame`]" surface a [`SessionTransport`]
/// rides on. Production backs it with a live [`NoiseSession`] over the peer's
/// Noise channel; the headless tests back it with an in-memory link, so the
/// transport's fan-out and buffered-first-frame logic are unit-tested without a
/// Noise handshake — the same real-muscle-behind-a-trait split
/// [`VaultCeremonySigner`] uses for the signer.
pub trait CeremonyLink {
    /// Send one ceremony frame to the peer.
    fn send_frame(&mut self, frame: &Frame) -> NetResult<()>;
    /// Block for the next ceremony frame from the peer.
    fn recv_frame(&mut self) -> NetResult<Frame>;
}

impl<S: Read + Write> CeremonyLink for NoiseSession<S> {
    fn send_frame(&mut self, frame: &Frame) -> NetResult<()> {
        NoiseSession::send_frame(self, frame)
    }
    fn recv_frame(&mut self) -> NetResult<Frame> {
        NoiseSession::recv_frame(self)
    }
}

/// A [`CeremonyTransport`] over one point-to-point [`CeremonyLink`] — the v1
/// (2-member) ceremony topology.
///
/// Both members drive [`run_ceremony`](softfig_net::ceremony::run_ceremony) over
/// their own end of the same Noise link: each `broadcast` writes to the one
/// peer, each `recv` reads from it. The commit→reveal protocol is a natural
/// ping-pong (write our commit, read theirs; write our reveal, read theirs), so
/// the single session is driven sequentially and never needs `.split()`.
#[derive(Debug)]
pub struct SessionTransport<L: CeremonyLink> {
    link: L,
    /// A frame already lifted off the link before the transport was built — the
    /// responder's case (see [`SessionTransport::responder`]). Returned by the
    /// first `recv` before any further read; `None` for the initiator.
    pending: Option<Frame>,
}

impl<L: CeremonyLink> SessionTransport<L> {
    /// The initiator's transport. The initiator dialed the peer and has read
    /// nothing yet, so its first `broadcast` sends our commit and its first
    /// `recv` reads the peer's — nothing is buffered.
    pub fn initiator(link: L) -> Self {
        Self { link, pending: None }
    }

    /// The responder's transport. `serve_established` already read the
    /// initiator's `SharedKeyCommit` off the link to recognize the ceremony and
    /// dispatch here, so that first frame is handed back to be replayed from the
    /// first `recv` — the driver still sees every peer frame, in order, exactly
    /// once.
    pub fn responder(link: L, first_frame: Frame) -> Self {
        Self {
            link,
            pending: Some(first_frame),
        }
    }
}

impl<L: CeremonyLink> CeremonyTransport for SessionTransport<L> {
    fn broadcast(&mut self, frame: &Frame) -> NetResult<()> {
        // v1 is 2-member: "every other member" is the single peer on the link.
        self.link.send_frame(frame)
    }

    fn recv(&mut self) -> NetResult<Frame> {
        match self.pending.take() {
            Some(frame) => Ok(frame),
            None => self.link.recv_frame(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_net::ceremony::{
        commit_signing_bytes, commitment, run_ceremony, verify_commit_sig, Ceremony, Phase,
    };
    use softfig_net::{NetError, RingEntry};

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

    // --- SessionTransport (the live-session CeremonyTransport) --------------

    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::thread;

    /// A vault-backed test device: an unlocked session (its identity key doubles
    /// as the ceremony `device_id`) plus the tempdir the vault initialized in.
    /// The dir is returned so the caller keeps it alive for the test's span; the
    /// session signs from in-memory key material, so signing outlives the dir,
    /// but holding it is tidy and matches the sibling vault test.
    fn device() -> (Arc<VaultSession>, tempfile::TempDir) {
        use softfig_vault::{params::VaultParams, Vault};
        let tmp = tempfile::tempdir().unwrap();
        let mut params = VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let (_v, session, _r) =
            Vault::init_with_params(tmp.path(), b"correct horse battery staple", params).unwrap();
        (Arc::new(session), tmp)
    }

    /// An in-memory point-to-point [`CeremonyLink`]: a `send` fans to the peer's
    /// inbox, a `recv` blocks on our own. Models one keeperd Noise session
    /// without a handshake, so [`SessionTransport`]'s fan-out + first-frame
    /// buffering are exercised directly.
    struct MemLink {
        tx: Sender<Frame>,
        rx: Receiver<Frame>,
    }
    impl CeremonyLink for MemLink {
        fn send_frame(&mut self, frame: &Frame) -> NetResult<()> {
            // A peer that has finished drops its receiver; a closed channel is
            // not an error (it already has what it needs), mirroring the net
            // crate's ChannelTransport.
            let _ = self.tx.send(frame.clone());
            Ok(())
        }
        fn recv_frame(&mut self) -> NetResult<Frame> {
            self.rx
                .recv()
                .map_err(|_| NetError::Protocol("mem link closed"))
        }
    }

    /// A cross-wired pair of [`MemLink`]s: each end sends into the other's inbox.
    fn mem_link_pair() -> (MemLink, MemLink) {
        let (a_tx, a_rx) = channel();
        let (b_tx, b_rx) = channel();
        (
            MemLink { tx: b_tx, rx: a_rx },
            MemLink { tx: a_tx, rx: b_rx },
        )
    }

    /// Two vault-signed drivers run a full 2-member ceremony over a
    /// `SessionTransport` on each end of one link and derive an identical `S` —
    /// the vault-sign ↔ net-verify contract exercised over the real transport
    /// (the pre-live stand-in for the deferred 2-device smoke).
    #[test]
    fn two_drivers_derive_identical_s_over_the_transport() {
        let (sess_a, _tmp_a) = device();
        let (sess_b, _tmp_b) = device();
        let id_a = sess_a.identity_pubkey().to_bytes();
        let id_b = sess_b.identity_pubkey().to_bytes();
        let members = vec![id_a, id_b];
        let nonce = [5u8; 32];
        let chain = b"shared/proj".to_vec();
        let (link_a, link_b) = mem_link_pair();

        let (ma, ca) = (members.clone(), chain.clone());
        let ha = thread::spawn(move || {
            let signer = VaultCeremonySigner::new(sess_a);
            let mut cer = Ceremony::new(nonce, ca, &ma, id_a, [0x11; 32]).unwrap();
            let mut transport = SessionTransport::initiator(link_a);
            run_ceremony(&mut transport, &signer, &mut cer).unwrap()
        });
        let (mb, cb) = (members.clone(), chain.clone());
        let hb = thread::spawn(move || {
            let signer = VaultCeremonySigner::new(sess_b);
            let mut cer = Ceremony::new(nonce, cb, &mb, id_b, [0x22; 32]).unwrap();
            let mut transport = SessionTransport::initiator(link_b);
            run_ceremony(&mut transport, &signer, &mut cer).unwrap()
        });

        let (s_a, t_a) = ha.join().unwrap();
        let (s_b, t_b) = hb.join().unwrap();
        assert_eq!(s_a, s_b);
        assert!(t_a.verify());
        assert_eq!(t_a.key_id, t_b.key_id);
    }

    /// The responder path: mirror `serve_established` by lifting the initiator's
    /// first `SharedKeyCommit` off the link to recognize the ceremony, then hand
    /// it to `SessionTransport::responder`; the driver still completes and both
    /// sides derive the same `S`, proving the consumed frame is replayed.
    #[test]
    fn responder_replays_the_consumed_first_frame() {
        use softfig_net::proto::frame;

        let (sess_a, _tmp_a) = device();
        let (sess_b, _tmp_b) = device();
        let id_a = sess_a.identity_pubkey().to_bytes();
        let id_b = sess_b.identity_pubkey().to_bytes();
        let members = vec![id_a, id_b];
        let nonce = [6u8; 32];
        let chain = b"shared/proj".to_vec();
        let (link_a, mut link_b) = mem_link_pair();

        let (ma, ca) = (members.clone(), chain.clone());
        let ha = thread::spawn(move || {
            let signer = VaultCeremonySigner::new(sess_a);
            let mut cer = Ceremony::new(nonce, ca, &ma, id_a, [0x11; 32]).unwrap();
            let mut transport = SessionTransport::initiator(link_a);
            run_ceremony(&mut transport, &signer, &mut cer).unwrap()
        });

        // Responder side, on this thread: read the dispatch frame off the wire
        // (as net.rs's first-frame match does), confirm it is a commit, then
        // build the responder transport from it.
        let first = link_b.recv_frame().unwrap();
        assert!(matches!(first.kind, Some(frame::Kind::SharedKeyCommit(_))));
        let signer = VaultCeremonySigner::new(sess_b);
        let mut cer = Ceremony::new(nonce, chain, &members, id_b, [0x22; 32]).unwrap();
        let mut transport = SessionTransport::responder(link_b, first);
        let (s_b, t_b) = run_ceremony(&mut transport, &signer, &mut cer).unwrap();

        let (s_a, t_a) = ha.join().unwrap();
        assert_eq!(s_a, s_b);
        assert!(t_b.verify());
        assert_eq!(t_a.key_id, t_b.key_id);
    }

    /// A buffered first frame is returned before the link is ever read: a link
    /// that errors on `recv_frame` proves the first `recv` never touched it, and
    /// the second `recv` then falls through to the (dead) link.
    #[test]
    fn buffered_first_frame_precedes_the_link() {
        struct DeadLink;
        impl CeremonyLink for DeadLink {
            fn send_frame(&mut self, _f: &Frame) -> NetResult<()> {
                Ok(())
            }
            fn recv_frame(&mut self) -> NetResult<Frame> {
                Err(NetError::Protocol("link should not be read"))
            }
        }
        let marker = Frame::pong(42);
        let mut transport = SessionTransport::responder(DeadLink, marker.clone());
        assert_eq!(transport.recv().unwrap(), marker); // buffered — link untouched
        assert!(transport.recv().is_err()); // now falls through to the dead link
    }
}
