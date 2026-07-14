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

// --- Persisting the outcome (slice 001 CHUNK B0) -----------------------------
//
// A completed ceremony leaves two durable artifacts, per
// [[decision-shared-ceremony-transcript-persistence]] (option a — locked):
//
// 1. **`S` under the vault** — `VaultSession::store_shared_key` seals it at
//    `.softfig/vault/shared-keys/<key_id>.key` (master-keyed, unlocked-only).
//    This is what slice 002 reads to `S`-encrypt shared-chain blobs.
// 2. **The signed transcript as a committed record** — the full transcript as
//    `config/shared-ceremonies/<key_id>.toml` on the *device* chain
//    (M-encrypted, M5b-replicated, durable before slice 002 exists), under the
//    `shared_ceremony` intent with the compact payload `{chain_id, key_id}`.
//    Each member commits its own record — no privileged copy.
//
// Both members call [`persist_ceremony_outcome`]: the initiator after its
// `run_ceremony` returns, the responder inline on its serve thread. The device
// chain's membership row (`config/shared-subtrees.toml`), when this device has
// one for the ceremony's chain, gets its `key_id` filled in the same commit —
// atomically pairing "the key exists" with "the subtree uses it".

use serde::{Deserialize, Serialize};
use softfig_net::ceremony::{key_id, SharedKey, Transcript, TranscriptEntry};
use softfig_store::Hash;
use softfig_vcs::Intent;
use softfig_ipc::ErrorKind;

use crate::actions::{commit_now, WorkTree};
use crate::daemon::Daemon;
use crate::handlers::{
    read_committed_shared_subtrees_for_mutation, require_unlocked, shared_subtrees_rel,
};

/// Repo-relative path of a ceremony's committed transcript record.
pub fn ceremony_record_rel(key_id: &str) -> String {
    format!("{}/shared-ceremonies/{key_id}.toml", crate::keeper_toml::CONFIG_DIR)
}

/// The committed record's TOML shape: scalar identity fields, then one
/// `[[member]]` table per contribution, all binary fields hex-encoded.
#[derive(Debug, Serialize, Deserialize)]
struct CeremonyRecordToml {
    key_id: String,
    chain_id: String,
    nonce: String,
    #[serde(rename = "member", default)]
    members: Vec<CeremonyMemberToml>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CeremonyMemberToml {
    device_id: String,
    commitment: String,
    r: String,
}

/// Render a transcript as the committed TOML record. Fails only on a
/// non-UTF-8 chain id (ref names are ASCII by construction).
pub fn render_transcript_record(t: &Transcript) -> Result<String, String> {
    let chain_id = std::str::from_utf8(&t.chain_id)
        .map_err(|_| "transcript chain_id is not UTF-8".to_string())?;
    let record = CeremonyRecordToml {
        key_id: t.key_id.clone(),
        chain_id: chain_id.to_string(),
        nonce: hex::encode(t.nonce),
        members: t
            .members
            .iter()
            .map(|m| CeremonyMemberToml {
                device_id: hex::encode(m.device_id),
                commitment: hex::encode(m.commitment),
                r: hex::encode(m.r),
            })
            .collect(),
    };
    toml::to_string_pretty(&record).map_err(|e| format!("serialize ceremony record: {e}"))
}

/// Parse a committed TOML record back into a [`Transcript`] (the reader for
/// slice 002/003 and audit tooling). Verification is the caller's step —
/// `Transcript::verify` re-checks the whole record from first principles.
pub fn parse_transcript_record(text: &str) -> Result<Transcript, String> {
    let record: CeremonyRecordToml =
        toml::from_str(text).map_err(|e| format!("parse ceremony record: {e}"))?;
    Ok(Transcript {
        nonce: hex32(&record.nonce, "nonce")?,
        chain_id: record.chain_id.into_bytes(),
        members: record
            .members
            .iter()
            .map(|m| {
                Ok(TranscriptEntry {
                    device_id: hex32(&m.device_id, "device_id")?,
                    commitment: hex32(&m.commitment, "commitment")?,
                    r: hex32(&m.r, "r")?,
                })
            })
            .collect::<Result<_, String>>()?,
        key_id: record.key_id,
    })
}

fn hex32(s: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("ceremony record {field}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("ceremony record {field} is not 32 bytes"))
}

/// Persist a completed ceremony's outcome: seal `S` under the vault, commit
/// the transcript record (and fill this device's membership `key_id`, when a
/// row for the chain exists) as one `shared_ceremony` commit on the device
/// chain. Idempotent — a retried call after a partial failure finishes the
/// missing half; a fully-persisted outcome returns the current tip without
/// minting a duplicate commit.
///
/// Takes the daemon (not a locked inner) because its callers — the initiator's
/// add-hook thread and the responder's serve thread — run the network ceremony
/// with the daemon mutex released; only this persistence step locks it.
pub fn persist_ceremony_outcome(
    daemon: &Daemon,
    s: &SharedKey,
    transcript: &Transcript,
) -> Result<Hash, (ErrorKind, String)> {
    // Consistency guards before anything durable happens: the key must be the
    // transcript's, the transcript must re-verify from first principles, and
    // this device must be one of its members (a foreign transcript would store
    // a key for a chain we have no part in).
    if key_id(s) != transcript.key_id {
        return Err((
            ErrorKind::Internal,
            "ceremony outcome mismatch: key_id(S) != transcript.key_id".into(),
        ));
    }
    if !transcript.verify() {
        return Err((
            ErrorKind::Internal,
            "ceremony transcript failed verification; refusing to persist".into(),
        ));
    }
    let chain_id = std::str::from_utf8(&transcript.chain_id)
        .map_err(|_| (ErrorKind::Internal, "ceremony chain_id is not UTF-8".to_string()))?
        .to_string();
    let rel = ceremony_record_rel(&transcript.key_id);
    let record = render_transcript_record(transcript).map_err(|e| (ErrorKind::Internal, e))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    {
        let session = inner.session.as_ref().expect("unlocked");
        if !transcript
            .members
            .iter()
            .any(|m| m.device_id == session.identity_pubkey().to_bytes())
        {
            return Err((
                ErrorKind::Internal,
                "this device is not a member of the ceremony transcript".into(),
            ));
        }
    }

    // Membership fill: when this device's committed allow-list has a row for
    // the ceremony's chain, its `key_id` becomes this ceremony's. A row is not
    // required — the responder may not have added the subtree locally yet.
    let membership_update = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        let mut membership = read_committed_shared_subtrees_for_mutation(repo, session)?;
        let mut changed = false;
        for row in membership.subtrees.iter_mut() {
            if row.ref_name == chain_id && row.key_id.as_deref() != Some(&transcript.key_id) {
                row.key_id = Some(transcript.key_id.clone());
                changed = true;
            }
        }
        if changed {
            Some(membership.to_toml().map_err(|e| {
                (ErrorKind::Internal, format!("serialize shared-subtrees: {e}"))
            })?)
        } else {
            None
        }
    };

    // Seal `S` first: the vault write is idempotent, so a commit failure after
    // it leaves a retryable half-state, never a committed record without a key.
    {
        let session = inner.session.as_ref().expect("unlocked");
        session
            .store_shared_key(&transcript.key_id, s)
            .map_err(|e| (ErrorKind::Internal, format!("store shared key: {e}")))?;
    }

    let record_exists = {
        let wt = WorkTree::new(daemon, &inner);
        wt.exists(&rel)
    };
    if record_exists && membership_update.is_none() {
        // Fully persisted already (a retried responder/initiator call): the
        // committed record is authoritative; do not mint a duplicate commit.
        let repo = inner.repo.as_ref().expect("unlocked");
        let tip = repo
            .tip()
            .map_err(|e| (ErrorKind::Internal, format!("read tip: {e}")))?
            .expect("unlocked repo has a genesis tip");
        return Ok(tip);
    }

    {
        let wt = WorkTree::new(daemon, &inner);
        if !record_exists {
            wt.write(&rel, record.as_bytes())?;
        }
        if let Some(toml) = &membership_update {
            wt.write(&shared_subtrees_rel(), toml.as_bytes())?;
        }
    }
    let intent = Intent::new(
        "shared_ceremony",
        serde_json::json!({ "chain_id": chain_id, "key_id": transcript.key_id }),
    )
    .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;
    // The chain just became keyed (M5d slice 002): recompose the union view
    // and the encrypt router now, so its very next write seals under `S`
    // instead of riding the pre-ceremony M path until a restart.
    if membership_update.is_some() {
        let state_dir = inner.config.state_dir().to_path_buf();
        crate::handlers::refresh_mount_registry(&inner, &state_dir);
    }
    Ok(hash)
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

    // --- persist_ceremony_outcome (CHUNK B0) --------------------------------

    use ed25519_dalek::SigningKey;
    use softfig_net::ceremony::{derive_shared_key, MemberContribution};

    use crate::handlers;
    use crate::KeeperConfig;

    const PASS: &[u8] = b"pw-test-12345";

    /// An unlocked daemon over a fresh tempdir garden, on the slice-007
    /// unmounted-FUSE attach seam (the m5c fixture's harness, without the
    /// serve loop — the handlers are called directly).
    fn unlocked_daemon() -> (Daemon, tempfile::TempDir) {
        use softfig_vault::{params::VaultParams, Vault};
        let tmp = tempfile::tempdir().unwrap();
        let mut params = VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let (_v, session, _r) = Vault::init_with_params(tmp.path(), PASS, params).unwrap();
        softfig_vcs::Repo::init(tmp.path(), &session).unwrap();
        drop(session);

        let daemon = Daemon::new(
            KeeperConfig::new(tmp.path())
                .without_watcher()
                .with_unmounted_fuse_attach(),
        );
        let reply = handlers::unlock(
            &daemon,
            serde_json::json!({ "passphrase": String::from_utf8_lossy(PASS) }),
        );
        assert!(reply.is_ok(), "unlock: {reply:?}");
        (daemon, tmp)
    }

    fn daemon_device_id(daemon: &Daemon) -> [u8; 32] {
        let inner = daemon.inner.lock().unwrap();
        inner
            .session
            .as_ref()
            .expect("unlocked")
            .identity_pubkey()
            .to_bytes()
    }

    /// Fabricate a completed 2-member ceremony outcome for `chain`. The
    /// transcript carries no signatures (commit/reveal auth is the drive
    /// loop's job), so entries for arbitrary device ids — including the
    /// daemon's own — verify from the commitment binding alone.
    fn fabricate_outcome(member_ids: [[u8; 32]; 2], chain: &[u8]) -> (SharedKey, Transcript) {
        let nonce = [7u8; 32];
        let rs = [[0x11u8; 32], [0x22u8; 32]];
        let contributions: Vec<MemberContribution> = member_ids
            .iter()
            .zip(rs.iter())
            .map(|(id, r)| MemberContribution { device_id: *id, r: *r })
            .collect();
        let s = derive_shared_key(&nonce, &contributions);
        let members = contributions
            .iter()
            .map(|mc| TranscriptEntry {
                device_id: mc.device_id,
                commitment: commitment(&nonce, &mc.device_id, &mc.r),
                r: mc.r,
            })
            .collect();
        let transcript = Transcript {
            nonce,
            chain_id: chain.to_vec(),
            members,
            key_id: key_id(&s),
        };
        assert!(transcript.verify());
        (s, transcript)
    }

    fn peer_id(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    #[test]
    fn record_toml_roundtrips_and_reverifies() {
        let (_s, transcript) = fabricate_outcome([peer_id(1), peer_id(2)], b"chain/demo");
        let text = render_transcript_record(&transcript).unwrap();
        // Hex fields + string chain id, per the locked record shape.
        assert!(text.contains(&format!("key_id = \"{}\"", transcript.key_id)));
        assert!(text.contains("chain_id = \"chain/demo\""));
        assert!(text.contains(&format!("nonce = \"{}\"", hex::encode(transcript.nonce))));
        let parsed = parse_transcript_record(&text).unwrap();
        assert_eq!(parsed, transcript);
        assert!(parsed.verify());
    }

    #[test]
    fn persist_seals_s_commits_record_and_fills_membership() {
        let (daemon, _tmp) = unlocked_daemon();
        let add = handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        let (s, transcript) =
            fabricate_outcome([daemon_device_id(&daemon), peer_id(9)], ref_name.as_bytes());
        let hash = persist_ceremony_outcome(&daemon, &s, &transcript).expect("persist");

        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();

        // 1. `S` is sealed under the vault, addressable by key_id.
        assert_eq!(*session.load_shared_key(&transcript.key_id).unwrap(), s);

        // 2. The committed record re-parses + re-verifies, at the locked path.
        let rel = ceremony_record_rel(&transcript.key_id);
        let wt = WorkTree::new(&daemon, &inner);
        let text = wt.read_to_string(&rel).expect("committed record readable");
        let parsed = parse_transcript_record(&text).unwrap();
        assert_eq!(parsed, transcript);
        assert!(parsed.verify());

        // 3. The membership row's key_id is filled, in the same commit.
        let membership = read_committed_shared_subtrees_for_mutation(repo, session).unwrap();
        let row = membership
            .subtrees
            .iter()
            .find(|r| r.ref_name == ref_name)
            .expect("membership row");
        assert_eq!(row.key_id.as_deref(), Some(transcript.key_id.as_str()));

        // 4. The tip is a `shared_ceremony` commit with the compact payload.
        assert_eq!(repo.tip().unwrap().unwrap(), hash);
        let row = repo.db().get_commit(&hash).unwrap();
        assert_eq!(row.intent, "shared_ceremony");
        let payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
        assert_eq!(payload["chain_id"].as_str(), Some(ref_name.as_str()));
        assert_eq!(payload["key_id"].as_str(), Some(transcript.key_id.as_str()));
    }

    #[test]
    fn persist_is_idempotent() {
        let (daemon, _tmp) = unlocked_daemon();
        handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let (s, transcript) =
            fabricate_outcome([daemon_device_id(&daemon), peer_id(9)], b"chain/journals");

        let first = persist_ceremony_outcome(&daemon, &s, &transcript).expect("persist");
        let second = persist_ceremony_outcome(&daemon, &s, &transcript).expect("re-persist");
        // The retry finds everything persisted and mints no duplicate commit.
        assert_eq!(first, second);
        let inner = daemon.inner.lock().unwrap();
        assert_eq!(inner.repo.as_ref().unwrap().tip().unwrap().unwrap(), first);
    }

    /// The responder case: no local membership row for the chain. `S` + the
    /// record still persist; membership is simply untouched.
    #[test]
    fn persist_without_a_membership_row() {
        let (daemon, _tmp) = unlocked_daemon();
        let (s, transcript) =
            fabricate_outcome([daemon_device_id(&daemon), peer_id(9)], b"chain/elsewhere");
        persist_ceremony_outcome(&daemon, &s, &transcript).expect("persist");

        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        assert_eq!(*session.load_shared_key(&transcript.key_id).unwrap(), s);
        let membership = read_committed_shared_subtrees_for_mutation(repo, session).unwrap();
        assert!(membership.subtrees.is_empty());
    }

    #[test]
    fn persist_refuses_inconsistent_or_foreign_outcomes() {
        let (daemon, _tmp) = unlocked_daemon();
        let our_id = daemon_device_id(&daemon);

        // A transcript this device is no member of.
        let (s, foreign) = fabricate_outcome([peer_id(1), peer_id(2)], b"chain/x");
        assert!(persist_ceremony_outcome(&daemon, &s, &foreign).is_err());

        // key_id(S) != transcript.key_id.
        let (s, mut tampered) = fabricate_outcome([our_id, peer_id(9)], b"chain/x");
        tampered.key_id = "S-0000000000000000".into();
        assert!(persist_ceremony_outcome(&daemon, &s, &tampered).is_err());

        // key_id matches but a commitment no longer opens: verify() fails.
        let (s, mut broken) = fabricate_outcome([our_id, peer_id(9)], b"chain/x");
        broken.members[0].commitment[0] ^= 1;
        assert!(persist_ceremony_outcome(&daemon, &s, &broken).is_err());

        // Nothing was persisted by the refused calls.
        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        assert!(!session.has_shared_key(&key_id(&s)));
    }
}
