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
use softfig_store::{Hash, TreeEntryKind};
use softfig_vcs::Intent;
use softfig_ipc::ErrorKind;

use crate::actions::{commit_now, WorkTree};
use crate::daemon::{Daemon, DaemonInner};
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
    /// The member's commit + reveal signatures (hex), retained so the persisted
    /// record proves participation — [`Transcript::verify`] re-checks them. No
    /// serde default: a record missing them is invalid and must fail to parse
    /// (clean break, no pre-hardening unsigned records — the branch is undeployed;
    /// see [[decision-shared-ceremony-transcript-persistence]]).
    commit_sig: String,
    reveal_sig: String,
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
                commit_sig: hex::encode(m.commit_sig),
                reveal_sig: hex::encode(m.reveal_sig),
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
                    commit_sig: hex64(&m.commit_sig, "commit_sig")?,
                    reveal_sig: hex64(&m.reveal_sig, "reveal_sig")?,
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

fn hex64(s: &str, field: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(s).map_err(|e| format!("ceremony record {field}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("ceremony record {field} is not 64 bytes"))
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
    // (once unlocked, below) the transcript's member set must equal this
    // device's committed ring — a foreign or padded transcript would store a
    // key for a member set we never authorized.
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
    // M5d slice 013 pt2 — assert the authorized member set at the persist
    // boundary (defence-in-depth on top of pt1's signed member-set binding).
    // Require the transcript's member id-set to equal `assemble_member_set` of
    // *this device's committed ring*, not merely `self ∈ members`: a
    // validly-signed transcript for a member set this device never consented to
    // (a forged/padded recovery hand-off, or a foreign 3-member set slipped past
    // the drive-layer `>2` gate) is refused before anything durable happens.
    // Ring-equality is strictly stronger than the old `self ∈ members` check —
    // `assemble_member_set` always includes `local_id`, so an equal set always
    // contains this device — and it also enforces the v1 `>2` refusal at persist
    // (a 2-member committed ring can't equal a padded 3-member set). Rotation is
    // deliberately NOT gated this way: `rotate_shared_key` has its own
    // both-sides-stale authorization plus pt1's signed binding, and a strict
    // ring-equality mid-membership-change would refuse the very rotations it
    // exists to perform.
    {
        let local_id = inner
            .session
            .as_ref()
            .expect("unlocked")
            .identity_pubkey()
            .to_bytes();
        let ring = {
            let wt = WorkTree::new(daemon, &inner);
            crate::net::load_ring(&wt, inner.config.state_dir()).unwrap_or_default()
        };
        let expected: std::collections::BTreeSet<[u8; 32]> =
            assemble_member_set(&ring, local_id).into_iter().collect();
        let got: std::collections::BTreeSet<[u8; 32]> =
            transcript.members.iter().map(|m| m.device_id).collect();
        if expected != got {
            return Err((
                ErrorKind::Internal,
                "ceremony transcript member set does not equal this device's \
                 committed ring; refusing to persist a shared key for a member \
                 set this device never authorized"
                    .into(),
            ));
        }
    }

    // Membership fill — M5d slice 006, "fill-if-unkeyed, never overwrite" (the
    // finding-1 engine). When this device's committed allow-list has a row for
    // the ceremony's chain, fill its `key_id` ONLY while the row is still
    // unkeyed. A row already carrying *this* ceremony's key is an idempotent
    // retry (no change). A row carrying a *different* key is a divergence — the
    // one-key-per-chain invariant slice 002's convergent encryption rests on has
    // been violated (with S-encryption live this otherwise presents as silent
    // chain corruption) — so refuse loudly and name it, never a silent swap.
    // Rotation (slice 003's `shared_rekey`) is the ONLY authorized path that may
    // replace a live key. A row is not required — the responder may not have
    // added the subtree locally yet.
    // A divergence detected inside the block below can't take `&mut inner`
    // while the immutable session/repo borrows are live, so it breaks out with
    // the message and we record it + return once those borrows have dropped.
    let mut divergence: Option<String> = None;
    let membership_update = 'mu: {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        let mut membership = read_committed_shared_subtrees_for_mutation(repo, session)?;
        let mut changed = false;
        for row in membership.subtrees.iter_mut() {
            if row.ref_name != chain_id {
                continue;
            }
            match row.key_id.as_deref() {
                None => {
                    row.key_id = Some(transcript.key_id.clone());
                    changed = true;
                }
                // Idempotent re-persist of the same ceremony: leave it untouched.
                Some(existing) if existing == transcript.key_id => {}
                // Already keyed with a different key — a divergence. Refuse
                // before anything durable happens (this runs before the vault
                // seal below, so nothing is sealed or committed on this path).
                Some(existing) => {
                    divergence = Some(format!(
                        "shared-key divergence for chain {chain_id}: membership \
                         row is already keyed {existing}, but this ceremony \
                         produced {}; refusing to overwrite (rotation is the \
                         only authorized re-key path)",
                        transcript.key_id
                    ));
                    break 'mu None;
                }
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
    if let Some(msg) = divergence {
        // Surface it (item 4) so the refusal is visible through `status`, not
        // stderr-only, then refuse — nothing durable has happened yet.
        inner.last_shared_key_divergence = Some(msg.clone());
        return Err((ErrorKind::Internal, msg));
    }

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

/// M5d slice 003 — the **authorized re-key path**: the one path allowed to
/// replace a filled `key_id`, rotating a shared chain from its live `S` to a
/// freshly-derived `S'` (a leave/join re-runs the slice-001 ceremony among the
/// new member set, then hands its outcome here). Slice 006's
/// [`persist_ceremony_outcome`] hard-refuses replacing a live key; this is the
/// distinct, deliberate exception — the plain-ceremony path never reaches it, so
/// the default stays fail-closed ([[decision-m5d-shared-rekey-intent]], the
/// authorized-re-key seam).
///
/// Under the daemon lock: verify the new outcome (the persist guards), confirm
/// the chain's row is currently keyed with a *different* key (rotation replaces a
/// KNOWN key — it never *establishes* one; that is persist's job), seal `S'`
/// beside the old `S`, write the new transcript record + flip the row `key_id`,
/// commit one `shared_rekey` audit record on the device chain, re-point the
/// router so new writes seal under `S'`, then re-encrypt the chain's existing
/// blobs under `S'`.
///
/// A departed member's old `S` then only ever decrypts ciphertext it already
/// held — the honest custody limit (`spec-sync.md` §Crypto), not a bug:
/// collaborative generation protects the key's *birth*, rotation protects its
/// *custody* going forward. Old `S` is intentionally **not** deleted (our own
/// history needs it to read pre-rotation commits). GC of the superseded
/// pre-rotation ciphertext is deferred (open `spec-sync.md` question).
///
/// Failure atomicity: the seal + audit commit + row flip land before the
/// re-encrypt. A re-encrypt error is returned loud, but the key swap is already
/// durable — the chain is then in the documented "new writes seal under `S'`,
/// existing blobs lag under the old key" state (reads still resolve, decrypt
/// being self-describing), recoverable by a re-encrypt pass, never corruption.
pub fn rotate_shared_key(
    daemon: &Daemon,
    s_prime: &SharedKey,
    new_transcript: &Transcript,
) -> Result<Hash, (ErrorKind, String)> {
    // Same consistency guards as persist: the key is the transcript's, the
    // transcript re-verifies from first principles, and this device is a member.
    if key_id(s_prime) != new_transcript.key_id {
        return Err((
            ErrorKind::Internal,
            "rotation outcome mismatch: key_id(S') != transcript.key_id".into(),
        ));
    }
    if !new_transcript.verify() {
        return Err((
            ErrorKind::Internal,
            "rotation transcript failed verification; refusing to rotate".into(),
        ));
    }
    let chain_id = std::str::from_utf8(&new_transcript.chain_id)
        .map_err(|_| (ErrorKind::Internal, "rotation chain_id is not UTF-8".to_string()))?
        .to_string();
    let new_key_id = new_transcript.key_id.clone();
    let rel = ceremony_record_rel(&new_key_id);
    let record = render_transcript_record(new_transcript).map_err(|e| (ErrorKind::Internal, e))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    {
        let session = inner.session.as_ref().expect("unlocked");
        if !new_transcript
            .members
            .iter()
            .any(|m| m.device_id == session.identity_pubkey().to_bytes())
        {
            return Err((
                ErrorKind::Internal,
                "this device is not a member of the rotation transcript".into(),
            ));
        }
    }

    // The authorized-re-key guard. The committed row is the authoritative source
    // of the old key_id (never a caller argument that could drift). The row MUST
    // be currently keyed — no row (or an unkeyed row) is not a rotation but an
    // establishment, which is [`persist_ceremony_outcome`]'s job — and keyed with
    // a *different* key than the target (rotating to the live key is a no-op
    // request, not a rotation).
    let (old_key_id, mount_path) = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        let membership = read_committed_shared_subtrees_for_mutation(repo, session)?;
        let row = membership
            .subtrees
            .iter()
            .find(|r| r.ref_name == chain_id)
            .ok_or((
                ErrorKind::Internal,
                format!(
                    "cannot rotate {chain_id}: no committed membership row \
                     (rotation replaces a live key — add + key the chain first)"
                ),
            ))?;
        let old = row.key_id.clone().ok_or((
            ErrorKind::Internal,
            format!(
                "cannot rotate {chain_id}: the chain is unkeyed \
                 (establishment runs the plain ceremony, not rotation)"
            ),
        ))?;
        if old == new_key_id {
            return Err((
                ErrorKind::Internal,
                format!("cannot rotate {chain_id}: S' equals the live key {old} (rotation needs a fresh key)"),
            ));
        }
        (old, row.mount_path.clone())
    };

    // Seal S' beside the old S (idempotent). Never deletes old S: the departed
    // member's copy stays able to decrypt only ciphertext it already held (the
    // custody limit), and our own pre-rotation history still needs old S to read.
    {
        let session = inner.session.as_ref().expect("unlocked");
        session
            .store_shared_key(&new_key_id, s_prime)
            .map_err(|e| (ErrorKind::Internal, format!("store rotated shared key: {e}")))?;
    }

    // Flip the row key_id → new and stage the new transcript record. Both are
    // device-chain files (under `config/`), committed together as one
    // `shared_rekey` audit record — the same one-record-per-mutation shape persist
    // uses for `shared_ceremony`.
    let membership_toml = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        let mut membership = read_committed_shared_subtrees_for_mutation(repo, session)?;
        for row in membership.subtrees.iter_mut() {
            if row.ref_name == chain_id {
                row.key_id = Some(new_key_id.clone());
            }
        }
        membership
            .to_toml()
            .map_err(|e| (ErrorKind::Internal, format!("serialize shared-subtrees: {e}")))?
    };
    {
        let wt = WorkTree::new(daemon, &inner);
        wt.write(&rel, record.as_bytes())?;
        wt.write(&shared_subtrees_rel(), membership_toml.as_bytes())?;
    }
    // Payload per the LOCKED shape ([[decision-m5d-shared-rekey-intent]]):
    // `members` = the post-rotation set (hex device ids); `ceremony_ref` = the new
    // key_id, addressing the fresh transcript record — one uniform record shape for
    // initial ceremony + rekey.
    let members: Vec<String> = new_transcript
        .members
        .iter()
        .map(|m| hex::encode(m.device_id))
        .collect();
    let intent = Intent::new(
        "shared_rekey",
        serde_json::json!({
            "chain_id": chain_id,
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "members": members,
            "ceremony_ref": new_key_id,
        }),
    )
    .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let audit_hash = commit_now(&mut inner, intent)?;

    // Re-point the router to S' (derives from the now-committed membership), so
    // the chain's next write — including the re-encrypt below — seals under S'.
    {
        let state_dir = inner.config.state_dir().to_path_buf();
        crate::handlers::refresh_mount_registry(&inner, &state_dir);
    }

    // Re-encrypt the chain's existing blobs under S'. Decrypt is self-describing
    // (each container names the S generation — or pre-ceremony M — that sealed it),
    // so this reads the old ciphertext even after the router flip and re-commits
    // identical plaintext, now sealed under S'.
    reencrypt_shared_chain(&mut inner, &chain_id, &mount_path, &old_key_id, &new_key_id)?;

    Ok(audit_hash)
}

/// Re-seal every blob in a shared chain's current tip under the router's current
/// key by round-tripping its plaintext through one fresh commit on the chain ref.
/// The caller has already re-pointed the router (so `encrypt_for_ref` seals under
/// the new key). An empty chain re-seals nothing (no commit).
fn reencrypt_shared_chain(
    inner: &mut DaemonInner,
    chain_id: &str,
    mount_path: &str,
    old_key_id: &str,
    new_key_id: &str,
) -> Result<(), (ErrorKind, String)> {
    let snapshot = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        snapshot_chain_plaintext(repo, session, chain_id, mount_path)?
    };
    if snapshot.files().is_empty() {
        return Ok(());
    }
    let intent = Intent::new(
        "shared_rekey",
        serde_json::json!({
            "chain_id": chain_id,
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "summary": format!("re-encrypt {chain_id} under {new_key_id}"),
        }),
    )
    .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    crate::actions::commit_snapshot_to_now(inner, chain_id, snapshot, intent)?;
    Ok(())
}

/// Materialize a shared chain's current tip as a plaintext [`WalkSnapshot`],
/// decrypting each blob under whichever generation sealed it. The snapshot's
/// paths are **chain-relative** (matching how the chain ref stores them) so a
/// re-commit re-prefixes exactly as the write path expects; decryption uses the
/// **garden** path (mount + chain-relative) so a sealed Layer-B (or pre-ceremony
/// M Layer-B) subkey, which is salted by path, resolves.
fn snapshot_chain_plaintext(
    repo: &softfig_vcs::Repo,
    session: &VaultSession,
    ref_name: &str,
    mount_path: &str,
) -> Result<softfig_vcs::WalkSnapshot, (ErrorKind, String)> {
    let mut snap = softfig_vcs::WalkSnapshot::empty();
    let Some(tip) = repo
        .tip_of(ref_name)
        .map_err(|e| (ErrorKind::Internal, format!("read {ref_name} tip: {e}")))?
    else {
        return Ok(snap);
    };
    let row = repo
        .db()
        .get_commit(&tip)
        .map_err(|e| (ErrorKind::Internal, format!("read {ref_name} tip commit: {e}")))?;
    collect_chain_plaintext(repo, session, &row.root_tree, "", mount_path, &mut snap)?;
    Ok(snap)
}

fn collect_chain_plaintext(
    repo: &softfig_vcs::Repo,
    session: &VaultSession,
    tree: &Hash,
    prefix: &str,
    mount_path: &str,
    snap: &mut softfig_vcs::WalkSnapshot,
) -> Result<(), (ErrorKind, String)> {
    let entries = repo
        .db()
        .get_tree(tree)
        .map_err(|e| (ErrorKind::Internal, format!("read tree: {e}")))?;
    for e in entries {
        let chain_rel = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        match e.kind {
            TreeEntryKind::Blob => {
                let cipher = repo
                    .objects()
                    .get(&e.target)
                    .map_err(|err| (ErrorKind::Internal, format!("read blob {chain_rel}: {err}")))?;
                let garden_path = if mount_path.is_empty() {
                    chain_rel.clone()
                } else {
                    format!("{mount_path}/{chain_rel}")
                };
                let plain = session
                    .decrypt_tracked_blob(&garden_path, &cipher)
                    .map_err(|err| {
                        (ErrorKind::Internal, format!("decrypt {garden_path} for re-encrypt: {err}"))
                    })?;
                snap.insert_file(std::path::Path::new(&chain_rel), e.mode, plain)
                    .map_err(|err| (ErrorKind::Internal, format!("snapshot {chain_rel}: {err}")))?;
            }
            TreeEntryKind::Tree => {
                collect_chain_plaintext(repo, session, &e.target, &chain_rel, mount_path, snap)?;
            }
        }
    }
    Ok(())
}

/// M5d slice 014 (ROTATE-1) — the re-encrypt completeness self-heal pass. A
/// rotation swaps a chain's `key_id` + audit record (durable) and *then*
/// re-encrypts the existing blobs under the new `S'`; if that re-encrypt fails
/// mid-way (a transient blob read/decrypt/commit I/O error) or the daemon
/// crashes between the two, the live tip is left with blobs still sealed under
/// the **old** `S`. Nothing re-fired it: [`crate::net::reconcile_rekeys`] keys
/// only off member-set drift, which the row flip already cleared, so the chain
/// no longer reads as stale. This pass is that missing scan — peer-free and
/// ceremony-free: it detects any keyed chain whose live tip holds a blob under a
/// non-live shared key and re-runs [`reencrypt_shared_chain`] (the router already
/// points at the committed live `S`) until the tip converges. Idempotent — a tip
/// already fully under its live `S` re-encrypts nothing, so a clean chain never
/// churns a no-op commit. Runs each reconcile tick beside the rekey pass, so a
/// rotation whose in-line re-encrypt failed this tick heals the same or next tick
/// with no departed-member window beyond that.
pub(crate) fn reconcile_reencrypt_completeness(daemon: &Daemon) {
    let mut inner = daemon.inner.lock().unwrap();
    if require_unlocked(&inner).is_err() {
        return;
    }
    let lagging = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        match chains_lagging_reencrypt(repo, session) {
            Ok(v) => v,
            Err((_, e)) => {
                eprintln!("keeperd: net: re-encrypt completeness scan skipped: {e}");
                return;
            }
        }
    };
    if lagging.is_empty() {
        return;
    }
    // The re-encrypt seals under whatever key the router maps the chain to — the
    // committed live key after a rotation's row flip + refresh. Re-derive the
    // router from committed state defensively before healing, so a heal that runs
    // after an out-of-band registry change still seals under the row's live `S`.
    {
        let state_dir = inner.config.state_dir().to_path_buf();
        crate::handlers::refresh_mount_registry(&inner, &state_dir);
    }
    for LaggingChain { ref_name, mount_path, live_key_id } in lagging {
        // old == new == the live key: this is a completeness re-seal to the row's
        // committed `S`, not a key change (the audit shape is shared with rotation).
        match reencrypt_shared_chain(&mut inner, &ref_name, &mount_path, &live_key_id, &live_key_id) {
            Ok(()) => eprintln!(
                "keeperd: net: re-encrypt completeness: {ref_name} healed — tip now sealed under {live_key_id}"
            ),
            Err((_, e)) => eprintln!(
                "keeperd: net: re-encrypt completeness: {ref_name} still lagging under an old key: {e}"
            ),
        }
    }
}

/// A committed keyed shared chain whose live tip still holds a blob under a
/// non-live `S` — one [`reconcile_reencrypt_completeness`] work item.
struct LaggingChain {
    ref_name: String,
    mount_path: String,
    live_key_id: String,
}

/// Detection half of [`reconcile_reencrypt_completeness`] (unit-testable without
/// a live peer): the committed *keyed* shared chains whose live tip still holds
/// at least one blob sealed under a shared key other than the row's committed
/// live `key_id` — the signature of an incomplete rotation re-encrypt. Returns
/// `(ref_name, mount_path, live_key_id)` per lagging chain; an unkeyed row is
/// pre-ceremony (establishment's concern) and skipped.
fn chains_lagging_reencrypt(
    repo: &softfig_vcs::Repo,
    session: &VaultSession,
) -> std::result::Result<Vec<LaggingChain>, (ErrorKind, String)> {
    let membership = read_committed_shared_subtrees_for_mutation(repo, session)?;
    let mut lagging = Vec::new();
    for row in membership.subtrees.iter() {
        let Some(live) = row.key_id.as_deref() else {
            continue; // unkeyed → pre-ceremony, not a lagging rotation
        };
        if tip_has_foreign_shared_key(repo, &row.ref_name, live)? {
            lagging.push(LaggingChain {
                ref_name: row.ref_name.clone(),
                mount_path: row.mount_path.clone(),
                live_key_id: live.to_string(),
            });
        }
    }
    Ok(lagging)
}

/// True if `ref_name`'s current tip holds at least one shared blob sealed under a
/// shared `key_id` other than `live_key_id`. Reads only each blob container's
/// header via [`softfig_vault::shared::read_key_id`] — no decrypt, no key needed.
/// A blob not in a shared container (a pre-ceremony `M`-keyed blob) is not
/// "old `S`" and is skipped: rotation completeness is only about superseded
/// shared generations, and folding `M` blobs in here would churn chains that a
/// ceremony establishment, not a rotation, owns.
fn tip_has_foreign_shared_key(
    repo: &softfig_vcs::Repo,
    ref_name: &str,
    live_key_id: &str,
) -> std::result::Result<bool, (ErrorKind, String)> {
    let Some(tip) = repo
        .tip_of(ref_name)
        .map_err(|e| (ErrorKind::Internal, format!("read {ref_name} tip: {e}")))?
    else {
        return Ok(false);
    };
    let row = repo
        .db()
        .get_commit(&tip)
        .map_err(|e| (ErrorKind::Internal, format!("read {ref_name} tip commit: {e}")))?;
    tree_has_foreign_shared_key(repo, &row.root_tree, live_key_id)
}

fn tree_has_foreign_shared_key(
    repo: &softfig_vcs::Repo,
    tree: &Hash,
    live_key_id: &str,
) -> std::result::Result<bool, (ErrorKind, String)> {
    let entries = repo
        .db()
        .get_tree(tree)
        .map_err(|e| (ErrorKind::Internal, format!("read tree for re-encrypt scan: {e}")))?;
    for e in entries {
        match e.kind {
            TreeEntryKind::Blob => {
                let cipher = repo.objects().get(&e.target).map_err(|err| {
                    (ErrorKind::Internal, format!("read blob for re-encrypt scan: {err}"))
                })?;
                if let Ok(kid) = softfig_vault::shared::read_key_id(&cipher) {
                    if kid != live_key_id {
                        return Ok(true);
                    }
                }
            }
            TreeEntryKind::Tree => {
                if tree_has_foreign_shared_key(repo, &e.target, live_key_id)? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_net::ceremony::{
        commit_signing_bytes, commitment, member_set_digest, reveal_signing_bytes, run_ceremony,
        verify_commit_sig, Ceremony, Phase,
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
        // A 2-member set (this device + a peer id) so the signature binds a real
        // member-set digest, per slice 013. The peer id is only hashed into the
        // set digest, so any 32 bytes stand in — only `device_id` must be a real
        // key, since it is what the signature verifies under.
        let peer_id = [9u8; 32];
        let msd = member_set_digest(&[device_id, peer_id]);
        let comm = commitment(&nonce, &device_id, &r);
        let sig = signer.sign(&commit_signing_bytes(&nonce, chain_id, &msd, &device_id, &comm));

        // The vault-signed bytes verify byte-for-byte under the driver's verifier
        // — the whole point of the trait impl (the vault-sign ↔ net-verify
        // contract that the live mesh rides on).
        assert!(verify_commit_sig(&nonce, chain_id, &msd, &device_id, &comm, &sig));
        // A tampered commitment no longer verifies under the same signature.
        let mut bad = comm;
        bad[0] ^= 1;
        assert!(!verify_commit_sig(&nonce, chain_id, &msd, &device_id, &bad, &sig));
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
            run_ceremony(&mut transport, &signer, &mut cer)
                .unwrap()
                .derived()
                .expect("these drivers complete the ceremony, never hand off")
        });
        let (mb, cb) = (members.clone(), chain.clone());
        let hb = thread::spawn(move || {
            let signer = VaultCeremonySigner::new(sess_b);
            let mut cer = Ceremony::new(nonce, cb, &mb, id_b, [0x22; 32]).unwrap();
            let mut transport = SessionTransport::initiator(link_b);
            run_ceremony(&mut transport, &signer, &mut cer)
                .unwrap()
                .derived()
                .expect("these drivers complete the ceremony, never hand off")
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
            run_ceremony(&mut transport, &signer, &mut cer)
                .unwrap()
                .derived()
                .expect("these drivers complete the ceremony, never hand off")
        });

        // Responder side, on this thread: read the dispatch frame off the wire
        // (as net.rs's first-frame match does), confirm it is a commit, then
        // build the responder transport from it.
        let first = link_b.recv_frame().unwrap();
        assert!(matches!(first.kind, Some(frame::Kind::SharedKeyCommit(_))));
        let signer = VaultCeremonySigner::new(sess_b);
        let mut cer = Ceremony::new(nonce, chain, &members, id_b, [0x22; 32]).unwrap();
        let mut transport = SessionTransport::responder(link_b, first);
        let (s_b, t_b) = run_ceremony(&mut transport, &signer, &mut cer)
            .unwrap()
            .derived()
            .expect("responder completes the ceremony, never hands off");

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

    use ed25519_dalek::{Signer, SigningKey};
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

    /// The signing key behind a fabricated peer id: `peer_id(seed)` is its
    /// verifying key, so a test can mint that peer's *real* ceremony signatures.
    fn peer_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn peer_id(seed: u8) -> [u8; 32] {
        peer_sk(seed).verifying_key().to_bytes()
    }

    /// A ceremony member for the signed-outcome builder: `(device_id, r, sign)`,
    /// where `sign` mints that member's Ed25519 signature over given bytes.
    type SignedMember<'a> = ([u8; 32], [u8; 32], &'a dyn Fn(&[u8]) -> [u8; 64]);

    /// Build a fully-signed, verifying 2-member ceremony outcome for `chain`.
    /// Each member's `device_id` MUST be its signer's pubkey or the transcript
    /// will not verify. Since slice 007 the transcript carries real per-member
    /// commit+reveal signatures, so this signs each entry with either a fabricated
    /// peer's known key or the daemon's own vault session.
    fn build_signed_outcome(
        chain: &[u8],
        m0: SignedMember<'_>,
        m1: SignedMember<'_>,
    ) -> (SharedKey, Transcript) {
        build_signed_outcome_n(chain, &[m0, m1])
    }

    /// The N-member generalization: build a fully-signed, verifying ceremony
    /// outcome for `chain` over an arbitrary member list, each member signing its
    /// own entry over the slice-013 member-set-bound signing bytes. Used to
    /// fabricate the padded/>2 shapes the persist ring-equality gate must refuse.
    fn build_signed_outcome_n(chain: &[u8], members: &[SignedMember<'_>]) -> (SharedKey, Transcript) {
        let nonce = [7u8; 32];
        let contributions: Vec<MemberContribution> = members
            .iter()
            .map(|m| MemberContribution { device_id: m.0, r: m.1 })
            .collect();
        let s = derive_shared_key(&nonce, &contributions);
        // Slice 013: every commit/reveal signature binds the member-set digest.
        let ids: Vec<[u8; 32]> = members.iter().map(|m| m.0).collect();
        let msd = member_set_digest(&ids);
        let entries = members
            .iter()
            .map(|(id, r, sign)| {
                let comm = commitment(&nonce, id, r);
                TranscriptEntry {
                    device_id: *id,
                    commitment: comm,
                    r: *r,
                    commit_sig: sign(&commit_signing_bytes(&nonce, chain, &msd, id, &comm)),
                    reveal_sig: sign(&reveal_signing_bytes(&nonce, chain, &msd, id, r)),
                }
            })
            .collect();
        let transcript = Transcript {
            nonce,
            chain_id: chain.to_vec(),
            members: entries,
            key_id: key_id(&s),
        };
        (s, transcript)
    }

    /// Seed the daemon's committed ring for the persist ring-equality gate (M5d
    /// slice 013 pt2). `persist_ceremony_outcome` now requires the transcript's
    /// member set to equal `assemble_member_set(committed ring)`, so a fabricated
    /// `{self, peer_seed…}` outcome only persists when the ring names those peers.
    /// These unit fixtures never pair, so `config/peers.toml` is absent and
    /// `load_ring` falls back to the legacy `.softfig/peers.toml` at `state_dir`
    /// — write it directly. Each seed's `device_id` is `peer_id(seed)` (matching
    /// the fabricated members) with a self-consistent attestation, so
    /// `Ring::load`'s re-verification accepts it. Overwrites any prior seed, so a
    /// test can shift membership between calls.
    fn seed_ring(daemon: &Daemon, peer_seeds: &[u8]) {
        use softfig_net::ring::ring_path;
        use softfig_net::static_attestation_message;
        let mut ring = Ring::default();
        for &seed in peer_seeds {
            let sk = peer_sk(seed);
            let transport_pubkey = [seed ^ 0xFF; 32];
            ring.upsert(RingEntry {
                device_id: sk.verifying_key().to_bytes(),
                name: format!("peer-{seed}"),
                transport_pubkey,
                endpoints: vec![],
                attestation: sk.sign(&static_attestation_message(&transport_pubkey)).to_bytes(),
                paired_at: 1,
            });
        }
        let state_dir = {
            let inner = daemon.inner.lock().unwrap();
            inner.config.state_dir().to_path_buf()
        };
        ring.save(&ring_path(&state_dir)).expect("seed legacy ring");
    }

    /// Fabricate a signed 2-member outcome between two fabricated peers (by seed),
    /// each signing with its own known key — the transcript now verifies from real
    /// signatures, not the keyless commitment binding alone.
    fn fabricate_outcome(seeds: [u8; 2], chain: &[u8]) -> (SharedKey, Transcript) {
        let sk0 = peer_sk(seeds[0]);
        let sk1 = peer_sk(seeds[1]);
        let (s, t) = build_signed_outcome(
            chain,
            (sk0.verifying_key().to_bytes(), [0x11; 32], &|m| sk0.sign(m).to_bytes()),
            (sk1.verifying_key().to_bytes(), [0x22; 32], &|m| sk1.sign(m).to_bytes()),
        );
        assert!(t.verify());
        (s, t)
    }

    /// Fabricate a signed 2-member outcome where member 0 is *this daemon* — its
    /// entry signed with the vault identity key so persist's membership + the new
    /// signature checks both pass — and member 1 is fabricated peer `peer_seed`.
    fn fabricate_outcome_with_self(
        daemon: &Daemon,
        peer_seed: u8,
        chain: &[u8],
    ) -> (SharedKey, Transcript) {
        let session = {
            let inner = daemon.inner.lock().unwrap();
            Arc::clone(inner.session.as_ref().expect("unlocked"))
        };
        let self_id = session.identity_pubkey().to_bytes();
        let peer = peer_sk(peer_seed);
        let (s, t) = build_signed_outcome(
            chain,
            (self_id, [0x11; 32], &|m| session.sign(m).to_bytes()),
            (peer.verifying_key().to_bytes(), [0x22; 32], &|m| peer.sign(m).to_bytes()),
        );
        assert!(t.verify());
        (s, t)
    }

    #[test]
    fn record_toml_roundtrips_and_reverifies() {
        let (_s, transcript) = fabricate_outcome([1, 2], b"chain/demo");
        let text = render_transcript_record(&transcript).unwrap();
        // Hex fields + string chain id, per the locked record shape.
        assert!(text.contains(&format!("key_id = \"{}\"", transcript.key_id)));
        assert!(text.contains("chain_id = \"chain/demo\""));
        assert!(text.contains(&format!("nonce = \"{}\"", hex::encode(transcript.nonce))));
        // The signatures round-trip too — the whole point of slice 007's record.
        assert!(text.contains(&format!("commit_sig = \"{}\"", hex::encode(transcript.members[0].commit_sig))));
        assert!(text.contains(&format!("reveal_sig = \"{}\"", hex::encode(transcript.members[0].reveal_sig))));
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

        seed_ring(&daemon, &[9]); // committed ring == the fabricated {self, peer9} set
        let (s, transcript) = fabricate_outcome_with_self(&daemon, 9, ref_name.as_bytes());
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
        seed_ring(&daemon, &[9]);
        let (s, transcript) = fabricate_outcome_with_self(&daemon, 9, b"chain/journals");

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
        seed_ring(&daemon, &[9]);
        let (s, transcript) = fabricate_outcome_with_self(&daemon, 9, b"chain/elsewhere");
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

        // Ring == {self, peer9} so the `{self, peer9}` cases below clear the
        // set-equality gate and fail on the guard each is probing.
        seed_ring(&daemon, &[9]);

        // A transcript this device is no member of (two fabricated peers): the set
        // {1,2} never equals {self, peer9}, so it is refused.
        let (s, foreign) = fabricate_outcome([1, 2], b"chain/x");
        assert!(persist_ceremony_outcome(&daemon, &s, &foreign).is_err());

        // key_id(S) != transcript.key_id (caught before the membership check).
        let (s, mut tampered) = fabricate_outcome_with_self(&daemon, 9, b"chain/x");
        tampered.key_id = "S-0000000000000000".into();
        assert!(persist_ceremony_outcome(&daemon, &s, &tampered).is_err());

        // key_id matches but a commitment no longer opens: verify() fails.
        let (s, mut broken) = fabricate_outcome_with_self(&daemon, 9, b"chain/x");
        broken.members[0].commitment[0] ^= 1;
        assert!(persist_ceremony_outcome(&daemon, &s, &broken).is_err());

        // Nothing was persisted by the refused calls.
        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        assert!(!session.has_shared_key(&key_id(&s)));
    }

    /// Slice 007 at the persist boundary: a transcript that is internally
    /// consistent — real commitments over this device + a peer, correct `key_id`
    /// — but whose per-member signatures are forged is refused. This isolates the
    /// participation gate: `key_id(S)` matches (the first guard passes) and every
    /// commitment opens, so *only* the new signature check can reject it, and it
    /// does. Nothing is sealed. This is the `fabricate_outcome` inversion the
    /// slice calls for: before hardening, exactly this shape verified + persisted.
    #[test]
    fn persist_refuses_a_forged_unsigned_transcript() {
        let (daemon, _tmp) = unlocked_daemon();
        let our_id = daemon_device_id(&daemon);

        seed_ring(&daemon, &[9]); // set matches → only the forged signatures reject
        let nonce = [7u8; 32];
        let ids = [our_id, peer_id(9)];
        let rs = [[0x11u8; 32], [0x22u8; 32]];
        let contributions: Vec<MemberContribution> = ids
            .iter()
            .zip(rs.iter())
            .map(|(id, r)| MemberContribution { device_id: *id, r: *r })
            .collect();
        let s = derive_shared_key(&nonce, &contributions);
        let members = ids
            .iter()
            .zip(rs.iter())
            .map(|(id, r)| TranscriptEntry {
                device_id: *id,
                commitment: commitment(&nonce, id, r),
                r: *r,
                // Forged: the forger holds neither our identity key nor the peer's.
                commit_sig: [0u8; 64],
                reveal_sig: [0u8; 64],
            })
            .collect();
        let forged = Transcript {
            nonce,
            chain_id: b"chain/x".to_vec(),
            members,
            key_id: key_id(&s),
        };
        // key_id matches (persist's first guard passes) and the commitments open,
        // so the signature check is the sole reason verify() — and persist — fail.
        assert_eq!(key_id(&s), forged.key_id);
        assert!(!forged.verify());
        assert!(persist_ceremony_outcome(&daemon, &s, &forged).is_err());

        let inner = daemon.inner.lock().unwrap();
        assert!(!inner.session.as_ref().unwrap().has_shared_key(&forged.key_id));
    }

    /// One key per chain (slice 006 pin): once a membership row is filled, a
    /// *second* ceremony producing a different key for the same chain is a hard
    /// refusal — never a silent overwrite (the pre-006 code swapped `key_id`
    /// unconditionally, forking slice 002's convergent encryption). Nothing
    /// durable happens on the refused path: no swap, no divergent sealed key, no
    /// commit.
    #[test]
    fn persist_refuses_a_divergent_rekey_of_a_filled_row() {
        let (daemon, _tmp) = unlocked_daemon();
        let add = handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // First ceremony fills the row (ring == {self, peer9}).
        seed_ring(&daemon, &[9]);
        let (s1, t1) = fabricate_outcome_with_self(&daemon, 9, ref_name.as_bytes());
        let tip1 = persist_ceremony_outcome(&daemon, &s1, &t1).expect("first persist");

        // A second ceremony for the same chain with a *different* member set
        // derives a different S → different key_id; persisting it must refuse.
        // Shift the ring to {self, peer10} so this outcome clears the set-equality
        // gate and the one-key-per-chain divergence refusal is what rejects it
        // (not the ring check — that path is proven separately).
        seed_ring(&daemon, &[10]);
        let (s2, t2) = fabricate_outcome_with_self(&daemon, 10, ref_name.as_bytes());
        assert_ne!(t1.key_id, t2.key_id, "test needs two distinct keys");
        assert!(
            persist_ceremony_outcome(&daemon, &s2, &t2).is_err(),
            "divergent re-key must be refused, not silently overwritten"
        );

        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        // The row still carries the first key — no swap.
        let membership = read_committed_shared_subtrees_for_mutation(repo, session).unwrap();
        let row = membership
            .subtrees
            .iter()
            .find(|r| r.ref_name == ref_name)
            .expect("row");
        assert_eq!(row.key_id.as_deref(), Some(t1.key_id.as_str()));
        // The divergent key's S was never sealed, and no divergent commit landed.
        assert!(!session.has_shared_key(&t2.key_id));
        assert_eq!(repo.tip().unwrap().unwrap(), tip1);
    }

    /// M5d slice 013 pt2 — the persist boundary refuses a transcript whose member
    /// set is not this device's committed ring, even when the transcript is
    /// internally flawless (real per-member signatures, `key_id` derives, every
    /// commitment opens → `verify()` passes). This is the CORR-1 belt at persist:
    /// a validly-signed but *padded* set {self, peer9, peer10} served against a v1
    /// 2-member ring {self, peer9} is refused before any durable write — and the
    /// SAME transcript persists once the ring genuinely names both peers, so the
    /// gate keys off ring-equality, not an arbitrary member-count cap.
    #[test]
    fn persist_refuses_a_member_set_that_is_not_the_committed_ring() {
        let (daemon, _tmp) = unlocked_daemon();
        let add = handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // A flawless, fully-signed 3-member outcome {self, peer9, peer10}.
        let session = {
            let inner = daemon.inner.lock().unwrap();
            Arc::clone(inner.session.as_ref().expect("unlocked"))
        };
        let self_id = session.identity_pubkey().to_bytes();
        let sk9 = peer_sk(9);
        let sk10 = peer_sk(10);
        let (s, t) = build_signed_outcome_n(
            ref_name.as_bytes(),
            &[
                (self_id, [0x11; 32], &|m| session.sign(m).to_bytes()),
                (peer_id(9), [0x22; 32], &|m| sk9.sign(m).to_bytes()),
                (peer_id(10), [0x33; 32], &|m| sk10.sign(m).to_bytes()),
            ],
        );
        assert!(
            t.verify(),
            "the transcript is internally valid — only the ring gate can reject it"
        );

        // Committed ring is the v1 2-member {self, peer9}: the padded 3-member set
        // is refused, and nothing is sealed.
        seed_ring(&daemon, &[9]);
        assert!(
            persist_ceremony_outcome(&daemon, &s, &t).is_err(),
            "a member set beyond the committed ring must be refused at persist"
        );
        {
            let inner = daemon.inner.lock().unwrap();
            assert!(
                !inner.session.as_ref().unwrap().has_shared_key(&t.key_id),
                "nothing sealed on the refused path"
            );
        }

        // Once the ring genuinely names both peers, the exact same transcript
        // persists — proving the gate is ring-equality, not a 2-member cap.
        seed_ring(&daemon, &[9, 10]);
        persist_ceremony_outcome(&daemon, &s, &t).expect("persists once the ring matches the set");
        let inner = daemon.inner.lock().unwrap();
        assert_eq!(
            *inner.session.as_ref().unwrap().load_shared_key(&t.key_id).unwrap(),
            s
        );
    }

    /// The read_key_id of the blob committed at chain-relative `name` in a
    /// shared chain's current tip — the S generation that sealed it.
    fn chain_blob_key_id(daemon: &Daemon, ref_name: &str, name: &str) -> String {
        let inner = daemon.inner.lock().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        let tip = repo.tip_of(ref_name).unwrap().unwrap();
        let root = repo.db().get_commit(&tip).unwrap().root_tree;
        let entry = repo
            .db()
            .get_tree(&root)
            .unwrap()
            .into_iter()
            .find(|e| e.name == name)
            .expect("blob present");
        let cipher = repo.objects().get(&entry.target).unwrap();
        softfig_vault::shared::read_key_id(&cipher).unwrap()
    }

    /// Slice 003: the authorized re-key path swaps `key_id` S→S', lands a
    /// `shared_rekey` audit record with the locked payload, commits the new
    /// transcript, and **re-encrypts** the chain's existing blobs under S' — so a
    /// departed member holding only the old S can no longer read post-rotation
    /// ciphertext (its container now names S'). Old S is retained (custody limit),
    /// not deleted. v1 is 2-member point-to-point, so this rotates one 2-member
    /// set to another — the mechanism the fabricated-transcript >2 case reduces to
    /// ([[decision-m5d-shared-rekey-intent]], option a).
    #[test]
    fn rotate_swaps_the_key_reencrypts_and_lands_a_shared_rekey_record() {
        let (daemon, _tmp) = unlocked_daemon();
        let add = handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();
        let our_id = daemon_device_id(&daemon);

        // Establish S over {self, peer 9}, then seed a real blob (sealed under S
        // via the live router that persist re-pointed).
        seed_ring(&daemon, &[9]); // establishment persist needs the ring to match {self, peer9}
        let (s1, t1) = fabricate_outcome_with_self(&daemon, 9, ref_name.as_bytes());
        persist_ceremony_outcome(&daemon, &s1, &t1).expect("initial key");
        {
            let mut inner = daemon.inner.lock().unwrap();
            let mut snap = softfig_vcs::WalkSnapshot::empty();
            snap.insert_file(std::path::Path::new("note.md"), 0o644, b"shared secret".to_vec())
                .unwrap();
            crate::actions::commit_snapshot_to_now(
                &mut inner,
                &ref_name,
                snap,
                Intent::new("shared_subtrees_changed", serde_json::json!({ "summary": "seed" }))
                    .unwrap(),
            )
            .expect("seed blob");
        }
        assert_eq!(chain_blob_key_id(&daemon, &ref_name, "note.md"), t1.key_id);

        // Rotate to S' over {self, peer 10} — as if peer 9 left and the new set
        // re-ran the ceremony.
        let (s2, t2) = fabricate_outcome_with_self(&daemon, 10, ref_name.as_bytes());
        assert_ne!(t1.key_id, t2.key_id, "test needs two distinct keys");
        let audit = rotate_shared_key(&daemon, &s2, &t2).expect("rotate");

        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();

        // 1. The row now carries S'.
        let membership = read_committed_shared_subtrees_for_mutation(repo, session).unwrap();
        let row = membership
            .subtrees
            .iter()
            .find(|r| r.ref_name == ref_name)
            .expect("row");
        assert_eq!(row.key_id.as_deref(), Some(t2.key_id.as_str()));

        // 2. Both keys remain sealed — old S kept (custody limit), new S stored.
        assert!(session.has_shared_key(&t1.key_id));
        assert_eq!(*session.load_shared_key(&t2.key_id).unwrap(), s2);

        // 3. The device tip is a shared_rekey audit record with the locked payload.
        assert_eq!(repo.tip().unwrap().unwrap(), audit);
        let crow = repo.db().get_commit(&audit).unwrap();
        assert_eq!(crow.intent, "shared_rekey");
        let payload: serde_json::Value = serde_json::from_str(&crow.payload).unwrap();
        assert_eq!(payload["chain_id"].as_str(), Some(ref_name.as_str()));
        assert_eq!(payload["old_key_id"].as_str(), Some(t1.key_id.as_str()));
        assert_eq!(payload["new_key_id"].as_str(), Some(t2.key_id.as_str()));
        assert_eq!(payload["ceremony_ref"].as_str(), Some(t2.key_id.as_str()));
        // members = the post-rotation set (both device ids, hex).
        let members: Vec<String> = payload["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(members.contains(&hex::encode(our_id)));
        assert!(members.contains(&hex::encode(peer_id(10))));

        // 4. The new transcript record is committed at its locked path + re-verifies.
        {
            let wt = WorkTree::new(&daemon, &inner);
            let text = wt.read_to_string(&ceremony_record_rel(&t2.key_id)).unwrap();
            assert_eq!(parse_transcript_record(&text).unwrap(), t2);
        }
        drop(inner); // release the guard — `chain_blob_key_id` re-locks it.

        // 5. The chain blob is RE-ENCRYPTED under S': its container now names S'
        //    (a departed old-S-only holder can't read it), and it still decrypts to
        //    the original plaintext.
        assert_eq!(chain_blob_key_id(&daemon, &ref_name, "note.md"), t2.key_id);
        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        let tip = repo.tip_of(&ref_name).unwrap().unwrap();
        let root = repo.db().get_commit(&tip).unwrap().root_tree;
        let entry = repo
            .db()
            .get_tree(&root)
            .unwrap()
            .into_iter()
            .find(|e| e.name == "note.md")
            .unwrap();
        let cipher = repo.objects().get(&entry.target).unwrap();
        assert_eq!(
            session
                .decrypt_tracked_blob("projects/journals/note.md", &cipher)
                .unwrap(),
            b"shared secret"
        );
    }

    /// Slice 014 (ROTATE-1): when a rotation's row flip + audit record commit but
    /// its `reencrypt_shared_chain` pass does not (a transient blob I/O error, or a
    /// daemon crash between the two), the live tip is left with blobs under the
    /// **old** `S` and — because the chain no longer reads as membership-stale —
    /// `reconcile_rekeys` never re-fires. `reconcile_reencrypt_completeness` is the
    /// missing scan: it detects the lagging tip and drives it to fully-`S'`,
    /// peer-free, so no live-tip blob stays readable under the old `S` the departed
    /// member holds. Models the exact half-rotated on-disk state (row = S', tip
    /// blob = old S) rather than fault-injecting, then asserts convergence.
    #[test]
    fn reencrypt_completeness_heals_a_tip_left_under_the_old_key() {
        let (daemon, _tmp) = unlocked_daemon();
        let add = handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // Establish S1 over {self, peer 9} and seed a blob under it.
        seed_ring(&daemon, &[9]);
        let (s1, t1) = fabricate_outcome_with_self(&daemon, 9, ref_name.as_bytes());
        persist_ceremony_outcome(&daemon, &s1, &t1).expect("initial key");
        {
            let mut inner = daemon.inner.lock().unwrap();
            let mut snap = softfig_vcs::WalkSnapshot::empty();
            snap.insert_file(std::path::Path::new("note.md"), 0o644, b"shared secret".to_vec())
                .unwrap();
            crate::actions::commit_snapshot_to_now(
                &mut inner,
                &ref_name,
                snap,
                Intent::new("shared_subtrees_changed", serde_json::json!({ "summary": "seed" }))
                    .unwrap(),
            )
            .expect("seed blob");
        }
        assert_eq!(chain_blob_key_id(&daemon, &ref_name, "note.md"), t1.key_id);

        // Reproduce the failed-re-encrypt state: seal S2, flip the committed row to
        // S2 + land its transcript record (rotation's durable first half), but
        // leave the shared chain's tip blob under S1 — exactly what a re-encrypt
        // that errored (or a crash) after the row flip leaves behind.
        let (s2, t2) = fabricate_outcome_with_self(&daemon, 10, ref_name.as_bytes());
        assert_ne!(t1.key_id, t2.key_id, "test needs two distinct keys");
        {
            let mut inner = daemon.inner.lock().unwrap();
            inner
                .session
                .as_ref()
                .unwrap()
                .store_shared_key(&t2.key_id, &s2)
                .unwrap();
            let membership_toml = {
                let session = inner.session.as_ref().unwrap();
                let repo = inner.repo.as_ref().unwrap();
                let mut membership =
                    read_committed_shared_subtrees_for_mutation(repo, session).unwrap();
                for row in membership.subtrees.iter_mut() {
                    if row.ref_name == ref_name {
                        row.key_id = Some(t2.key_id.clone());
                    }
                }
                membership.to_toml().unwrap()
            };
            let record = render_transcript_record(&t2).unwrap();
            {
                let wt = WorkTree::new(&daemon, &inner);
                wt.write(&ceremony_record_rel(&t2.key_id), record.as_bytes()).unwrap();
                wt.write(&shared_subtrees_rel(), membership_toml.as_bytes()).unwrap();
            }
            commit_now(
                &mut inner,
                Intent::new("shared_rekey", serde_json::json!({ "summary": "flip only" })).unwrap(),
            )
            .unwrap();
            let state_dir = inner.config.state_dir().to_path_buf();
            crate::handlers::refresh_mount_registry(&inner, &state_dir);
        }
        // Half-rotated: the row carries S2 but the tip blob is still under S1.
        {
            let inner = daemon.inner.lock().unwrap();
            let session = inner.session.as_ref().unwrap();
            let repo = inner.repo.as_ref().unwrap();
            let membership = read_committed_shared_subtrees_for_mutation(repo, session).unwrap();
            let row = membership.subtrees.iter().find(|r| r.ref_name == ref_name).unwrap();
            assert_eq!(row.key_id.as_deref(), Some(t2.key_id.as_str()));
        }
        assert_eq!(chain_blob_key_id(&daemon, &ref_name, "note.md"), t1.key_id);

        // One completeness pass heals the tip: peer-free, no ceremony.
        reconcile_reencrypt_completeness(&daemon);

        // The tip blob is now sealed under S2 (its container names S2) and still
        // decrypts to the original plaintext — the departed old-S holder can no
        // longer read it.
        assert_eq!(chain_blob_key_id(&daemon, &ref_name, "note.md"), t2.key_id);
        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        let tip = repo.tip_of(&ref_name).unwrap().unwrap();
        let root = repo.db().get_commit(&tip).unwrap().root_tree;
        let entry = repo
            .db()
            .get_tree(&root)
            .unwrap()
            .into_iter()
            .find(|e| e.name == "note.md")
            .unwrap();
        let cipher = repo.objects().get(&entry.target).unwrap();
        assert_eq!(
            session.decrypt_tracked_blob("projects/journals/note.md", &cipher).unwrap(),
            b"shared secret"
        );
        // No live-tip blob remains decryptable under the old S: S1 fails the AEAD
        // tag against the re-sealed container.
        assert!(
            softfig_vault::shared::decrypt_blob(&s1, &cipher).is_err(),
            "old S must not decrypt a re-sealed blob"
        );
        let healed_tip = repo.tip_of(&ref_name).unwrap();
        drop(inner);

        // Idempotent: a now-clean tip is not re-encrypted, so the pass never churns
        // a no-op commit on an already-converged chain.
        reconcile_reencrypt_completeness(&daemon);
        let inner = daemon.inner.lock().unwrap();
        assert_eq!(
            inner.repo.as_ref().unwrap().tip_of(&ref_name).unwrap(),
            healed_tip,
            "a converged tip must not advance on a second completeness pass"
        );
    }

    /// Rotation refuses to *establish*: an unkeyed chain (no ceremony yet) has no
    /// live key to replace, so `rotate_shared_key` is a hard refusal — the
    /// authorized-re-key seam never doubles as a key-fill backdoor around slice
    /// 006's fill-if-unkeyed persist path.
    #[test]
    fn rotate_refuses_an_unkeyed_or_missing_chain() {
        let (daemon, _tmp) = unlocked_daemon();
        let add = handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // The row exists but is unkeyed — rotation must refuse (establishment is
        // persist's job).
        let (s, t) = fabricate_outcome_with_self(&daemon, 9, ref_name.as_bytes());
        assert!(rotate_shared_key(&daemon, &s, &t).is_err());

        // A chain with no membership row at all — also refused.
        let (s2, t2) = fabricate_outcome_with_self(&daemon, 9, b"chain/nonexistent");
        assert!(rotate_shared_key(&daemon, &s2, &t2).is_err());

        // Nothing durable happened: neither key was sealed.
        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        assert!(!session.has_shared_key(&t.key_id));
        assert!(!session.has_shared_key(&t2.key_id));
    }
}
