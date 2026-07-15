//! M5d — the collaborative commit-reveal key ceremony that derives a shared
//! subtree's key **S**.
//!
//! This module is the cryptographic crux of the shared-subtree model
//! ([`meta/spec-sync.md`] §"Crypto — the collaboratively-generated shared key
//! `S`"). It is deliberately **transport-agnostic and pure**: the state machine
//! and every derivation here run without any I/O, so the whole protocol is
//! unit-testable headlessly (mirroring `replica.rs`, whose signing-byte helpers
//! and `verify_*` shape this follows). keeperd drives it over the mesh — signing
//! with the vault identity key, fanning `shared-key-commit` / `shared-key-reveal`
//! frames to ring members, and logging the transcript in the ring ledger — but
//! none of that machinery lives here.
//!
//! # The protocol
//!
//! Every member *i* picks a random contribution `r_i` and first broadcasts a
//! **signed commitment** `H(nonce ‖ device_id ‖ r_i)` plus the fresh ceremony
//! nonce; only once *all* commitments are in does anyone reveal their `r_i`.
//! Commit-then-reveal denies the last revealer any power to bias the output. The
//! derived key is
//!
//! ```text
//! S = HKDF-SHA-256(
//!         salt = ceremony_nonce,
//!         ikm  = r_1 ‖ r_2 ‖ … ‖ r_n          (members sorted by device id),
//!         info = "softfig.shared-subtree.v1" ‖ sorted(member_pubkeys),
//!     )
//! ```
//!
//! so every honest member derives an identical `S`. Binding the nonce and the
//! member's own device id into each commitment stops a commitment (or a signed
//! reveal) being transplanted onto another ceremony: a reveal minted under one
//! nonce simply fails the commitment check under another.
//!
//! # Honest limit (do not "fix")
//!
//! Collaborative generation protects the key's **birth, not its custody**. Once
//! derived, every member holds full `S` — it must, for offline read/write under
//! convergent encryption. Custody hygiene is *rotation* (slice 3), not this
//! slice.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{NetError, Result};
use crate::proto::{frame, Frame, SharedKeyCommit, SharedKeyHandoff, SharedKeyReveal};

/// A member's secret contribution `r_i`. Random per ceremony; revealed to all
/// members in the reveal phase (so it is public *after* the ceremony, and the
/// transcript can carry it for audit).
pub type Contribution = [u8; 32];

/// The per-ceremony nonce. Chosen fresh by the initiator and bound into every
/// commitment, every signed message, the KDF salt, and the transcript, so no
/// two ceremonies share derived material or can have messages transplanted
/// between them.
pub type CeremonyNonce = [u8; 32];

/// A commitment `H(nonce ‖ device_id ‖ r_i)` — what a member broadcasts before
/// anyone reveals.
pub type Commitment = [u8; 32];

/// A derived shared key `S`. Sensitive: the caller (keeperd) must persist it
/// only through the vault, never in plaintext. Returned as raw bytes to match
/// `replica.rs`'s frontend-neutral surface; this crate stays free of a `zeroize`
/// dependency (its stated design value), so zeroization is the caller's job.
pub type SharedKey = [u8; 32];

/// BLAKE3 domain tag for the commitment hash. Binds the ceremony nonce + the
/// committing member's device id under a versioned, single-purpose label.
const COMMITMENT_DOMAIN: &[u8] = b"softfig/shared-key/commitment/v1";

/// Domain-separation prefix for a `shared-key-commit` message signature.
/// Versioned and distinct from every other context the identity key signs.
const COMMIT_DOMAIN: &[u8] = b"softfig/shared-key/commit/v1";

/// Domain-separation prefix for a `shared-key-reveal` message signature.
const REVEAL_DOMAIN: &[u8] = b"softfig/shared-key/reveal/v1";

/// The `info` prefix for the `S` HKDF, taken verbatim from the spec. The sorted
/// member pubkeys are appended after it (see [`derive_shared_key`]).
const SHARED_KEY_INFO_PREFIX: &[u8] = b"softfig.shared-subtree.v1";

/// BLAKE3 domain tag for the public `key_id` derived from `S`. One-way, so the
/// ledger names a key generation without ever recording `S`.
const KEY_ID_DOMAIN: &[u8] = b"softfig/shared-key/key-id/v1";

/// The commitment a member publishes for contribution `r`:
/// `BLAKE3(COMMITMENT_DOMAIN ‖ nonce ‖ device_id ‖ r)`. Binding the nonce and
/// the device id means a commitment is valid only for *this* ceremony and *this*
/// committer — it cannot be replayed into another ceremony or claimed by another
/// member. All fields after the fixed-length domain tag are themselves
/// fixed-length (32 bytes), so the concatenation is unambiguous.
pub fn commitment(nonce: &CeremonyNonce, device_id: &[u8; 32], r: &Contribution) -> Commitment {
    let mut h = blake3::Hasher::new();
    h.update(COMMITMENT_DOMAIN);
    h.update(nonce);
    h.update(device_id);
    h.update(r);
    *h.finalize().as_bytes()
}

/// The exact bytes a member's Ed25519 identity signs to broadcast its
/// commitment. Length-prefixed + domain-separated so no two distinct tuples
/// share an encoding (the `replica.rs` signing-byte convention).
pub fn commit_signing_bytes(
    nonce: &CeremonyNonce,
    chain_id: &[u8],
    device_id: &[u8; 32],
    commitment: &Commitment,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        COMMIT_DOMAIN.len() + 32 + 4 + chain_id.len() + 32 + 32,
    );
    m.extend_from_slice(COMMIT_DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(device_id);
    m.extend_from_slice(commitment);
    m
}

/// The exact bytes a member's Ed25519 identity signs to reveal its contribution.
/// Carries the nonce + chain id + device id so a signed reveal is bound to this
/// ceremony and cannot be replayed onto another.
pub fn reveal_signing_bytes(
    nonce: &CeremonyNonce,
    chain_id: &[u8],
    device_id: &[u8; 32],
    r: &Contribution,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        REVEAL_DOMAIN.len() + 32 + 4 + chain_id.len() + 32 + 32,
    );
    m.extend_from_slice(REVEAL_DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(device_id);
    m.extend_from_slice(r);
    m
}

/// Verify a commit message's signature against the committing member's Ed25519
/// identity key. Never panics — a bad key, wrong-length signature, or a
/// non-verifying signature all return `false` (the `replica::verify_*` shape).
pub fn verify_commit_sig(
    nonce: &CeremonyNonce,
    chain_id: &[u8],
    device_id: &[u8; 32],
    commitment: &Commitment,
    sig: &[u8],
) -> bool {
    verify_sig(
        device_id,
        &commit_signing_bytes(nonce, chain_id, device_id, commitment),
        sig,
    )
}

/// Verify a reveal message's signature against the revealing member's Ed25519
/// identity key. Never panics.
pub fn verify_reveal_sig(
    nonce: &CeremonyNonce,
    chain_id: &[u8],
    device_id: &[u8; 32],
    r: &Contribution,
    sig: &[u8],
) -> bool {
    verify_sig(
        device_id,
        &reveal_signing_bytes(nonce, chain_id, device_id, r),
        sig,
    )
}

fn verify_sig(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig_bytes): std::result::Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(&sig_bytes)).is_ok()
}

/// One member's audited contribution to the ceremony: its device id (= Ed25519
/// identity public key) and its revealed `r_i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberContribution {
    pub device_id: [u8; 32],
    pub r: Contribution,
}

/// Derive `S` from the members' revealed contributions, per the spec formula.
///
/// The members are sorted by device id so every honest participant, regardless
/// of the order it received reveals, feeds an identical `ikm` (the `r_i` in
/// sorted order) and an identical `info` (`SHARED_KEY_INFO_PREFIX` ‖ the sorted
/// pubkeys) into the KDF, and therefore derives the identical `S`.
pub fn derive_shared_key(
    nonce: &CeremonyNonce,
    contributions: &[MemberContribution],
) -> SharedKey {
    let mut sorted: Vec<&MemberContribution> = contributions.iter().collect();
    sorted.sort_by_key(|a| a.device_id);

    let mut ikm = Vec::with_capacity(sorted.len() * 32);
    let mut info = Vec::with_capacity(SHARED_KEY_INFO_PREFIX.len() + sorted.len() * 32);
    info.extend_from_slice(SHARED_KEY_INFO_PREFIX);
    for mc in &sorted {
        ikm.extend_from_slice(&mc.r);
        info.extend_from_slice(&mc.device_id);
    }

    let hk = Hkdf::<Sha256>::new(Some(nonce), &ikm);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("HKDF expand of 32 bytes fits within the Sha256 output ceiling");
    out
}

/// The public identifier for a key generation: `S-<16 hex>` of a one-way hash of
/// `S`. Stable (same `S` → same id), leaks nothing about `S`, and matches the
/// `key_id = "S-7f3a…"` shape sketched in the spec's `shared-subtrees.toml`.
pub fn key_id(shared_key: &SharedKey) -> String {
    let mut h = blake3::Hasher::new();
    h.update(KEY_ID_DOMAIN);
    h.update(shared_key);
    let digest = h.finalize();
    format!("S-{}", hex::encode(&digest.as_bytes()[..8]))
}

/// The auditable record of a completed ceremony — the "signed transcript logged
/// in the ring ledger" of the spec. Because reveals are public post-ceremony,
/// the transcript carries every `r_i`; any member can recompute each commitment,
/// re-derive `S`, and check the recorded `key_id` — verifying `S` was formed
/// from *all* contributions and chosen *for* no one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    pub nonce: CeremonyNonce,
    pub chain_id: Vec<u8>,
    /// Members in canonical (device-id-sorted) order, each with the commitment
    /// it published and the `r_i` it later revealed.
    pub members: Vec<TranscriptEntry>,
    /// The public id of the key this ceremony produced.
    pub key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptEntry {
    pub device_id: [u8; 32],
    pub commitment: Commitment,
    pub r: Contribution,
    /// The member's Ed25519 signature over its `shared-key-commit` message (the
    /// same signature the live drive loop verified before accepting the
    /// commitment). Retained so the persisted transcript proves *participation*,
    /// not just internal consistency — see [`Transcript::verify`].
    pub commit_sig: [u8; 64],
    /// The member's Ed25519 signature over its `shared-key-reveal` message.
    pub reveal_sig: [u8; 64],
}

impl Transcript {
    /// Re-verify the whole transcript from first principles: for every member,
    /// its commitment matches its revealed `r_i` under this nonce **and** both
    /// its retained commit + reveal signatures verify against its `device_id`
    /// (the Ed25519 identity pubkey) over the exact bytes the live drive loop
    /// signed; then the derived key's `key_id` matches the recorded one. Returns
    /// `false` on any mismatch.
    ///
    /// The signatures are what make the record an *audit* of participation: the
    /// keyless consistency checks alone can be forged over arbitrary device ids
    /// (recompute each commitment, re-derive `S`), but no forger can mint a valid
    /// commit/reveal signature under an identity key it does not hold.
    pub fn verify(&self) -> bool {
        let mut contributions = Vec::with_capacity(self.members.len());
        for e in &self.members {
            if commitment(&self.nonce, &e.device_id, &e.r) != e.commitment {
                return false;
            }
            // Participation proof: the commit + reveal signatures must verify
            // under this member's own identity key over the same signing bytes
            // the drive loop checked live (nonce + chain id + device id +
            // commitment / r). A forged transcript over ids the forger cannot
            // sign for fails here even though the commitment binding passes.
            if !verify_commit_sig(
                &self.nonce,
                &self.chain_id,
                &e.device_id,
                &e.commitment,
                &e.commit_sig,
            ) {
                return false;
            }
            if !verify_reveal_sig(&self.nonce, &self.chain_id, &e.device_id, &e.r, &e.reveal_sig) {
                return false;
            }
            contributions.push(MemberContribution {
                device_id: e.device_id,
                r: e.r,
            });
        }
        let s = derive_shared_key(&self.nonce, &contributions);
        key_id(&s) == self.key_id
    }
}

/// Which phase the ceremony is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Collecting commitments; no reveal is accepted yet.
    Committing,
    /// All commitments in; collecting (and checking) reveals.
    Revealing,
    /// All reveals verified; `S` is derived.
    Derived,
    /// A member revealed a value that did not match its commitment — the
    /// ceremony is dead and must be restarted with a fresh nonce.
    Aborted,
}

/// The pure commit-reveal state machine for one ceremony, from one member's
/// point of view.
///
/// The driver (keeperd) feeds it commitments and reveals as signed frames
/// arrive — after checking each frame's signature with [`verify_commit_sig`] /
/// [`verify_reveal_sig`] and its membership against the ring — and this machine
/// enforces the *protocol*: no reveal before all commitments, one commitment per
/// member, no non-members, and the commit-reveal binding. It holds no secret it
/// did not derive itself; the local `r` is the only secret it stores, and only
/// until the reveal phase.
#[derive(Clone, Debug)]
pub struct Ceremony {
    nonce: CeremonyNonce,
    chain_id: Vec<u8>,
    /// Expected members, device-id-sorted, deduplicated.
    members: Vec<[u8; 32]>,
    local_id: [u8; 32],
    local_r: Contribution,
    phase: Phase,
    /// Received commitments, indexed parallel to `members`.
    commitments: Vec<Option<Commitment>>,
    /// The commit signature accepted with each commitment, indexed parallel to
    /// `members`. Retained so [`maybe_derive`](Self::maybe_derive) can seal them
    /// into the transcript; the local member's own is recorded separately via
    /// [`record_local_commit_sig`](Self::record_local_commit_sig) because
    /// `new` self-seeds the local commitment before a signer exists.
    commit_sigs: Vec<Option<[u8; 64]>>,
    /// Verified reveals, indexed parallel to `members`.
    reveals: Vec<Option<Contribution>>,
    /// The reveal signature accepted with each reveal, indexed parallel to
    /// `members` (the local member's lands through the normal `accept_reveal`
    /// path in the drive loop).
    reveal_sigs: Vec<Option<[u8; 64]>>,
    shared_key: Option<SharedKey>,
    transcript: Option<Transcript>,
}

impl Ceremony {
    /// Start a ceremony from this member's perspective. `members` is the full
    /// participating set (each device's Ed25519 identity key); `local_id` must be
    /// one of them and `local_r` is this device's freshly-generated contribution.
    ///
    /// A single-member set is rejected: a "collaborative" key with one
    /// contributor has no collaborators, and silently allowing it would hand one
    /// device the very unilateral control the ceremony exists to deny.
    pub fn new(
        nonce: CeremonyNonce,
        chain_id: Vec<u8>,
        members: &[[u8; 32]],
        local_id: [u8; 32],
        local_r: Contribution,
    ) -> Result<Self> {
        let mut sorted = members.to_vec();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != members.len() {
            return Err(NetError::Protocol("ceremony member set has duplicates"));
        }
        if sorted.len() < 2 {
            return Err(NetError::Protocol(
                "ceremony needs at least two members (a collaborative key needs collaborators)",
            ));
        }
        if !sorted.contains(&local_id) {
            return Err(NetError::Protocol("local device is not in the member set"));
        }
        let n = sorted.len();
        let mut c = Ceremony {
            nonce,
            chain_id,
            members: sorted,
            local_id,
            local_r,
            phase: Phase::Committing,
            commitments: vec![None; n],
            commit_sigs: vec![None; n],
            reveals: vec![None; n],
            reveal_sigs: vec![None; n],
            shared_key: None,
            transcript: None,
        };
        // Seed our own commitment immediately — a member always commits to its
        // own contribution.
        let idx = c.member_index(&local_id).expect("local id is a member");
        c.commitments[idx] = Some(c.local_commitment());
        c.maybe_advance_to_reveal();
        Ok(c)
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// This member's own commitment, to sign and broadcast.
    pub fn local_commitment(&self) -> Commitment {
        commitment(&self.nonce, &self.local_id, &self.local_r)
    }

    /// This member's own contribution, to sign and broadcast in the reveal phase.
    pub fn local_contribution(&self) -> Contribution {
        self.local_r
    }

    /// The ceremony nonce (bind it into outgoing frames).
    pub fn nonce(&self) -> &CeremonyNonce {
        &self.nonce
    }

    /// The chain this ceremony keys.
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }

    /// This member's own device id (bind it into outgoing frames).
    pub fn local_id(&self) -> [u8; 32] {
        self.local_id
    }

    /// The derived `S`, once [`Phase::Derived`]. `None` until then.
    pub fn shared_key(&self) -> Option<&SharedKey> {
        self.shared_key.as_ref()
    }

    /// The auditable transcript, once [`Phase::Derived`]. `None` until then.
    pub fn transcript(&self) -> Option<&Transcript> {
        self.transcript.as_ref()
    }

    /// Record a member's commitment and the signature it arrived under. The
    /// caller must already have verified `commit_sig` against `from` and that
    /// `from` is a ring member; this enforces the protocol: only an expected
    /// member, exactly once, and only while still committing. The signature is
    /// retained so it can be sealed into the auditable transcript on derivation.
    pub fn accept_commitment(
        &mut self,
        from: &[u8; 32],
        commitment: Commitment,
        commit_sig: [u8; 64],
    ) -> Result<()> {
        if self.phase != Phase::Committing {
            return Err(NetError::Protocol(
                "commitment arrived after the commit phase closed",
            ));
        }
        let idx = self
            .member_index(from)
            .ok_or(NetError::Protocol("commitment from a non-member"))?;
        if self.commitments[idx].is_some() {
            return Err(NetError::Protocol("duplicate commitment from a member"));
        }
        self.commitments[idx] = Some(commitment);
        self.commit_sigs[idx] = Some(commit_sig);
        self.maybe_advance_to_reveal();
        Ok(())
    }

    /// Record this member's own commit signature. `new` self-seeds the local
    /// commitment (a member always commits to its own contribution) before any
    /// signer is available; the drive loop calls this once it has signed that
    /// commitment, so the local entry carries its signature into the transcript
    /// exactly like every peer's. Idempotent overwrite of a `None` slot.
    pub fn record_local_commit_sig(&mut self, commit_sig: [u8; 64]) {
        let idx = self
            .member_index(&self.local_id)
            .expect("local id is a member");
        self.commit_sigs[idx] = Some(commit_sig);
    }

    /// Record and check a member's reveal. Verifies the revealed `r` against the
    /// commitment that member published for *this* ceremony; a mismatch aborts
    /// the whole ceremony (the commit-reveal guarantee — a member cannot change
    /// its contribution after seeing others'). A reveal minted under a different
    /// nonce fails here too, since the nonce is bound into the commitment.
    ///
    /// When the last reveal lands, `S` is derived and the transcript sealed.
    pub fn accept_reveal(
        &mut self,
        from: &[u8; 32],
        r: Contribution,
        reveal_sig: [u8; 64],
    ) -> Result<()> {
        if self.phase != Phase::Revealing {
            return Err(NetError::Protocol(
                "reveal arrived outside the reveal phase",
            ));
        }
        let idx = self
            .member_index(from)
            .ok_or(NetError::Protocol("reveal from a non-member"))?;
        if self.reveals[idx].is_some() {
            return Err(NetError::Protocol("duplicate reveal from a member"));
        }
        let expected = self.commitments[idx]
            .expect("every member has a commitment once the reveal phase is open");
        if commitment(&self.nonce, from, &r) != expected {
            // A contribution that does not open the published commitment (or a
            // reveal transplanted from another ceremony) — the ceremony is
            // compromised; kill it rather than derive a poisoned key.
            self.phase = Phase::Aborted;
            return Err(NetError::Protocol(
                "reveal does not match the member's commitment — ceremony aborted",
            ));
        }
        self.reveals[idx] = Some(r);
        self.reveal_sigs[idx] = Some(reveal_sig);
        self.maybe_derive();
        Ok(())
    }

    fn maybe_advance_to_reveal(&mut self) {
        if self.phase == Phase::Committing && self.commitments.iter().all(|c| c.is_some()) {
            self.phase = Phase::Revealing;
        }
    }

    fn maybe_derive(&mut self) {
        if self.phase != Phase::Revealing || self.reveals.iter().any(|r| r.is_none()) {
            return;
        }
        let mut contributions = Vec::with_capacity(self.members.len());
        let mut entries = Vec::with_capacity(self.members.len());
        for (idx, id) in self.members.iter().enumerate() {
            let r = self.reveals[idx].expect("all reveals present");
            let commitment = self.commitments[idx].expect("all commitments present");
            // Both signatures are present once we reach derivation: every peer's
            // arrived with its commitment/reveal, and the local member's commit
            // sig was recorded by the drive loop before its reveal (the last
            // reveal is what triggers this). A missing one is a driver bug.
            let commit_sig = self.commit_sigs[idx].expect("all commit signatures present");
            let reveal_sig = self.reveal_sigs[idx].expect("all reveal signatures present");
            contributions.push(MemberContribution {
                device_id: *id,
                r,
            });
            entries.push(TranscriptEntry {
                device_id: *id,
                commitment,
                r,
                commit_sig,
                reveal_sig,
            });
        }
        let s = derive_shared_key(&self.nonce, &contributions);
        self.transcript = Some(Transcript {
            nonce: self.nonce,
            chain_id: self.chain_id.clone(),
            members: entries,
            key_id: key_id(&s),
        });
        self.shared_key = Some(s);
        self.phase = Phase::Derived;
    }

    fn member_index(&self, id: &[u8; 32]) -> Option<usize> {
        self.members.iter().position(|m| m == id)
    }
}

/// Sign the commit message for a member — a convenience for the driver and tests
/// so the exact signing-byte layout lives in one place. Production keeperd signs
/// through the vault session (which owns the identity key), so this takes a raw
/// `SigningKey`; it is the byte-for-byte equivalent of what the vault produces.
pub fn sign_commit(
    sk: &SigningKey,
    nonce: &CeremonyNonce,
    chain_id: &[u8],
    device_id: &[u8; 32],
    commitment: &Commitment,
) -> [u8; 64] {
    sk.sign(&commit_signing_bytes(nonce, chain_id, device_id, commitment))
        .to_bytes()
}

/// Sign the reveal message for a member. See [`sign_commit`].
pub fn sign_reveal(
    sk: &SigningKey,
    nonce: &CeremonyNonce,
    chain_id: &[u8],
    device_id: &[u8; 32],
    r: &Contribution,
) -> [u8; 64] {
    sk.sign(&reveal_signing_bytes(nonce, chain_id, device_id, r))
        .to_bytes()
}

// --- The mesh drive loop ----------------------------------------------------
//
// The pure [`Ceremony`] above enforces the *protocol* (phases, one commitment
// per member, the commit-reveal binding) but does no I/O and trusts its caller
// to have authenticated each frame. This section is that caller: a
// transport-agnostic drive loop that signs + broadcasts our own commit/reveal,
// authenticates every inbound frame (signature against the sender's device id,
// nonce + chain id bound to *this* ceremony), and feeds the state machine —
// mirroring how `replica.rs` owns the wire drive loop while the vault (keeperd)
// owns the key and the store owns persistence. keeperd wires [`CeremonySigner`]
// to the vault session and [`CeremonyTransport`] to the live per-peer Noise
// sessions; the headless tests wire both to in-memory channels.

/// Produces the 64-byte Ed25519 signature over a ceremony message's signing
/// bytes. keeperd backs this with the vault session (which owns the identity
/// key: `VaultSession::sign(msg).to_bytes()`); tests back it with a raw
/// `SigningKey`. The byte layout stays here (`commit`/`reveal_signing_bytes`);
/// only the key crosses the trait boundary — the `attest`/`replica` split.
pub trait CeremonySigner {
    /// Sign `msg` with this device's Ed25519 identity key.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

/// The mesh a ceremony runs over: broadcast a frame to every *other* member,
/// and block for the next inbound ceremony frame from any member. keeperd
/// implements it over the ceremony's live per-peer Noise sessions; tests
/// implement it over in-memory queues.
///
/// The driver authenticates every inbound frame by signature against the
/// member set, so `recv` need not report which session a frame arrived on — a
/// frame relayed by the wrong peer still fails the signature or membership
/// check inside [`run_ceremony`]. Liveness (a member that never sends) is the
/// caller's concern: keeperd bounds the wait with a timeout and the deferred
/// live run exercises it; this loop is drained by honest, complete peers.
pub trait CeremonyTransport {
    /// Broadcast `frame` to every other member of the ceremony.
    fn broadcast(&mut self, frame: &Frame) -> Result<()>;
    /// Block for the next inbound ceremony frame from any member.
    fn recv(&mut self) -> Result<Frame>;
}

/// The outcome of driving a ceremony as one member: either the commit-reveal
/// completed and derived `S`, or — when we dialed as a member who lost `S` to a
/// failed persist (M5d slice 008) — a peer that already holds a live, non-stale
/// key for this chain answered our commit with a **recovery hand-off** instead
/// of joining a fresh ceremony. The driver surfaces the raw hand-off frame; the
/// caller (keeperd) verifies it against the vault + committed state and persists
/// through the idempotent ceremony path.
#[derive(Debug)]
pub enum CeremonyOutcome {
    /// The ceremony ran to completion: `S` and its auditable transcript.
    Derived(SharedKey, Transcript),
    /// The peer served a recovery hand-off (slice 008) rather than a ceremony.
    /// Carries the peer's committed transcript record + `S` for the caller to
    /// verify and persist. Only ever produced for the *initiator* role (it is
    /// the response to our commit).
    Handoff(SharedKeyHandoff),
}

impl CeremonyOutcome {
    /// The `(S, transcript)` of a completed ceremony, or `None` for a hand-off.
    /// A convenience for callers (and tests) that only handle the derive path.
    pub fn derived(self) -> Option<(SharedKey, Transcript)> {
        match self {
            CeremonyOutcome::Derived(s, t) => Some((s, t)),
            CeremonyOutcome::Handoff(_) => None,
        }
    }
}

/// Drive `ceremony` to completion from this member's point of view over
/// `transport`, signing our own commit + reveal with `signer`, and return the
/// derived `S` + its auditable [`Transcript`] (or a [`CeremonyOutcome::Handoff`]
/// if a keyed peer served us a slice-008 recovery hand-off in response to our
/// commit).
///
/// The protocol, in order: (1) sign + broadcast our commitment; (2) collect and
/// authenticate peers' commitments until the commit phase closes — buffering any
/// reveal that races ahead of a slow peer's commit (per-session FIFO holds, but
/// cross-peer interleaving does not); (3) sign + broadcast our reveal and record
/// it locally; (4) feed buffered + incoming reveals until `S` is derived. A
/// [`SharedKeyHandoff`] arriving in the commit phase (only the initiator ever
/// sees one — it is the peer's answer to our commit) short-circuits to
/// [`CeremonyOutcome::Handoff`]; the caller verifies + persists it.
///
/// Every inbound frame is authenticated here before it reaches the state
/// machine: a bad signature, a frame bound to another ceremony (nonce/chain
/// mismatch), a non-member, a duplicate, or an out-of-phase message is rejected,
/// and a reveal that does not open its commitment aborts the ceremony (surfaced
/// as an `Err`). On success `S` is returned by value — the caller (keeperd) must
/// persist it only through the vault and zeroize its own copy (this crate stays
/// `zeroize`-free by design).
pub fn run_ceremony<T, K>(
    transport: &mut T,
    signer: &K,
    ceremony: &mut Ceremony,
) -> Result<CeremonyOutcome>
where
    T: CeremonyTransport,
    K: CeremonySigner,
{
    let nonce = *ceremony.nonce();
    let chain_id = ceremony.chain_id().to_vec();
    let local_id = ceremony.local_id();

    // 1. Sign + broadcast our commitment. (The state machine self-seeded it in
    //    `Ceremony::new`; the mesh has to hear it.)
    let commitment = ceremony.local_commitment();
    let csig = signer.sign(&commit_signing_bytes(&nonce, &chain_id, &local_id, &commitment));
    // Retain our own commit signature in the machine — `new` self-seeded the
    // commitment before a signer existed, so the transcript gets ours only here.
    ceremony.record_local_commit_sig(csig);
    transport.broadcast(&Frame::shared_key_commit(SharedKeyCommit {
        nonce: nonce.to_vec(),
        chain_id: chain_id.clone(),
        device_id: local_id.to_vec(),
        commitment: commitment.to_vec(),
        signature: csig.to_vec(),
    }))?;

    // 2. Collect peers' commitments; a reveal that arrives early is buffered.
    let mut buffered: Vec<SharedKeyReveal> = Vec::new();
    while ceremony.phase() == Phase::Committing {
        match transport.recv()?.kind {
            Some(frame::Kind::SharedKeyCommit(c)) => {
                feed_commit(ceremony, &nonce, &chain_id, &c)?;
            }
            Some(frame::Kind::SharedKeyReveal(r)) => buffered.push(r),
            // M5d slice 008: a keyed peer answers our commit with a recovery
            // hand-off instead of joining the ceremony. Surface it — we lost `S`
            // to a failed persist and the peer is closing that gap. The caller
            // authenticates the transcript against the vault before trusting it.
            Some(frame::Kind::SharedKeyHandoff(h)) => {
                return Ok(CeremonyOutcome::Handoff(h))
            }
            _ => {
                return Err(NetError::Protocol(
                    "unexpected frame during the ceremony commit phase",
                ))
            }
        }
    }

    // 3. All commitments in — sign + broadcast our reveal, then record it
    //    locally (the machine self-seeds our commitment but not our reveal).
    let contribution = ceremony.local_contribution();
    let rsig = signer.sign(&reveal_signing_bytes(&nonce, &chain_id, &local_id, &contribution));
    transport.broadcast(&Frame::shared_key_reveal(SharedKeyReveal {
        nonce: nonce.to_vec(),
        chain_id: chain_id.clone(),
        device_id: local_id.to_vec(),
        contribution: contribution.to_vec(),
        signature: rsig.to_vec(),
    }))?;
    ceremony.accept_reveal(&local_id, contribution, rsig)?;

    // 4. Feed buffered reveals, then collect the rest until `S` is derived.
    for r in buffered {
        if ceremony.phase() != Phase::Revealing {
            break;
        }
        feed_reveal(ceremony, &nonce, &chain_id, &r)?;
    }
    while ceremony.phase() == Phase::Revealing {
        match transport.recv()?.kind {
            Some(frame::Kind::SharedKeyReveal(r)) => {
                feed_reveal(ceremony, &nonce, &chain_id, &r)?;
            }
            Some(frame::Kind::SharedKeyCommit(_)) => {
                return Err(NetError::Protocol(
                    "shared-key-commit arrived during the ceremony reveal phase",
                ))
            }
            _ => {
                return Err(NetError::Protocol(
                    "unexpected frame during the ceremony reveal phase",
                ))
            }
        }
    }

    // A reveal that failed to open its commitment aborts inside `accept_reveal`
    // and returns `Err` above, so reaching here in any phase but `Derived` means
    // the machine could not complete.
    match ceremony.phase() {
        Phase::Derived => {
            let s = *ceremony
                .shared_key()
                .expect("a derived ceremony holds its shared key");
            let transcript = ceremony
                .transcript()
                .expect("a derived ceremony holds its transcript")
                .clone();
            Ok(CeremonyOutcome::Derived(s, transcript))
        }
        _ => Err(NetError::Protocol("ceremony ended without deriving a key")),
    }
}

/// Authenticate a `shared-key-commit` frame and feed it to the state machine.
/// Rejects a frame bound to another ceremony (nonce/chain mismatch) or one whose
/// signature does not verify under the claimed device id, *before* the machine's
/// own member/phase/duplicate checks run.
fn feed_commit(
    ceremony: &mut Ceremony,
    nonce: &CeremonyNonce,
    chain_id: &[u8],
    c: &SharedKeyCommit,
) -> Result<()> {
    if c.nonce.as_slice() != nonce || c.chain_id != chain_id {
        return Err(NetError::Protocol(
            "shared-key-commit bound to a different ceremony",
        ));
    }
    let device_id = to_id32(&c.device_id)?;
    let commitment = to_id32(&c.commitment)?;
    if !verify_commit_sig(nonce, chain_id, &device_id, &commitment, &c.signature) {
        return Err(NetError::Protocol(
            "shared-key-commit signature failed to verify",
        ));
    }
    // Retain the verified signature so the transcript records participation.
    let commit_sig = to_sig64(&c.signature)?;
    ceremony.accept_commitment(&device_id, commitment, commit_sig)
}

/// Authenticate a `shared-key-reveal` frame and feed it to the state machine.
/// See [`feed_commit`]; a revealed contribution that does not open the member's
/// commitment aborts the ceremony inside `accept_reveal`.
fn feed_reveal(
    ceremony: &mut Ceremony,
    nonce: &CeremonyNonce,
    chain_id: &[u8],
    r: &SharedKeyReveal,
) -> Result<()> {
    if r.nonce.as_slice() != nonce || r.chain_id != chain_id {
        return Err(NetError::Protocol(
            "shared-key-reveal bound to a different ceremony",
        ));
    }
    let device_id = to_id32(&r.device_id)?;
    let contribution = to_id32(&r.contribution)?;
    if !verify_reveal_sig(nonce, chain_id, &device_id, &contribution, &r.signature) {
        return Err(NetError::Protocol(
            "shared-key-reveal signature failed to verify",
        ));
    }
    // Retain the verified signature so the transcript records participation.
    let reveal_sig = to_sig64(&r.signature)?;
    ceremony.accept_reveal(&device_id, contribution, reveal_sig)
}

/// A fixed-length 32-byte field from a ceremony frame, or a protocol error.
fn to_id32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| NetError::Protocol("ceremony frame field is not 32 bytes"))
}

/// A fixed-length 64-byte Ed25519 signature from a ceremony frame, or a protocol
/// error. Called only after the matching `verify_*_sig` has already succeeded
/// (which requires the 64-byte length), so the error path is defensive.
fn to_sig64(bytes: &[u8]) -> Result<[u8; 64]> {
    bytes
        .try_into()
        .map_err(|_| NetError::Protocol("ceremony frame signature is not 64 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fabricated member: an Ed25519 keypair (its verifying key doubles as the
    /// device id) plus a fixed contribution. Deterministic — no RNG — so the
    /// tests are reproducible.
    struct Member {
        sk: SigningKey,
        id: [u8; 32],
        r: Contribution,
    }

    fn member(seed: u8, r_fill: u8) -> Member {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let id = sk.verifying_key().to_bytes();
        Member {
            sk,
            id,
            r: [r_fill; 32],
        }
    }

    fn ids(members: &[Member]) -> Vec<[u8; 32]> {
        members.iter().map(|m| m.id).collect()
    }

    const NONCE: CeremonyNonce = [7u8; 32];
    const CHAIN: &[u8] = b"chain/projects";

    /// This member's honest commit signature under `NONCE`/`CHAIN` — what the
    /// live drive loop would have verified before accepting the commitment.
    fn honest_csig(m: &Member) -> [u8; 64] {
        sign_commit(&m.sk, &NONCE, CHAIN, &m.id, &commitment(&NONCE, &m.id, &m.r))
    }

    /// This member's honest reveal signature under `NONCE`/`CHAIN`.
    fn honest_rsig(m: &Member) -> [u8; 64] {
        sign_reveal(&m.sk, &NONCE, CHAIN, &m.id, &m.r)
    }

    /// Run a full honest ceremony from `local`'s perspective, feeding the other
    /// members' commitments then reveals. Returns the completed [`Ceremony`].
    fn run_honest(members: &[Member], local: usize) -> Ceremony {
        let mut c = Ceremony::new(
            NONCE,
            CHAIN.to_vec(),
            &ids(members),
            members[local].id,
            members[local].r,
        )
        .unwrap();
        // Our own commitment is self-seeded; the drive loop records its
        // signature, so mirror that here.
        c.record_local_commit_sig(honest_csig(&members[local]));
        // Commit phase: every *other* member's commitment (ours is seeded).
        for (i, m) in members.iter().enumerate() {
            if i == local {
                continue;
            }
            c.accept_commitment(&m.id, commitment(&NONCE, &m.id, &m.r), honest_csig(m))
                .unwrap();
        }
        assert_eq!(c.phase(), Phase::Revealing);
        // Reveal phase: every other member reveals; then ourselves last.
        for (i, m) in members.iter().enumerate() {
            if i == local {
                continue;
            }
            c.accept_reveal(&m.id, m.r, honest_rsig(m)).unwrap();
        }
        c.accept_reveal(&members[local].id, members[local].r, honest_rsig(&members[local]))
            .unwrap();
        assert_eq!(c.phase(), Phase::Derived);
        c
    }

    #[test]
    fn three_honest_members_derive_identical_s() {
        let members = [member(1, 11), member(2, 22), member(3, 33)];
        let a = run_honest(&members, 0);
        let b = run_honest(&members, 1);
        let d = run_honest(&members, 2);
        // Every honest member arrives at the same S and the same public key_id,
        // regardless of the order it saw reveals in.
        assert_eq!(a.shared_key(), b.shared_key());
        assert_eq!(b.shared_key(), d.shared_key());
        assert!(a.shared_key().is_some());
        let id = a.transcript().unwrap().key_id.clone();
        assert_eq!(id, b.transcript().unwrap().key_id);
        assert!(id.starts_with("S-"));
    }

    #[test]
    fn derivation_is_order_independent() {
        // Deriving directly from the member set (any input order) matches the
        // state machine's result.
        let members = [member(1, 11), member(2, 22), member(3, 33)];
        let via_machine = *run_honest(&members, 0).shared_key().unwrap();
        let forward: Vec<_> = members
            .iter()
            .map(|m| MemberContribution { device_id: m.id, r: m.r })
            .collect();
        let mut reversed = forward.clone();
        reversed.reverse();
        assert_eq!(derive_shared_key(&NONCE, &forward), via_machine);
        assert_eq!(derive_shared_key(&NONCE, &reversed), via_machine);
    }

    #[test]
    fn reveal_not_matching_commitment_is_rejected_and_aborts() {
        let members = [member(1, 11), member(2, 22)];
        let mut c = Ceremony::new(
            NONCE,
            CHAIN.to_vec(),
            &ids(&members),
            members[0].id,
            members[0].r,
        )
        .unwrap();
        c.accept_commitment(
            &members[1].id,
            commitment(&NONCE, &members[1].id, &members[1].r),
            honest_csig(&members[1]),
        )
        .unwrap();
        assert_eq!(c.phase(), Phase::Revealing);
        // Member 1 reveals a *different* value than it committed to (validly
        // signed, but it does not open the commitment — the state machine aborts
        // on the commitment mismatch, before the signature is even retained).
        let tampered = [0xAAu8; 32];
        let tsig = sign_reveal(&members[1].sk, &NONCE, CHAIN, &members[1].id, &tampered);
        let err = c.accept_reveal(&members[1].id, tampered, tsig).unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
        assert_eq!(c.phase(), Phase::Aborted);
        assert!(c.shared_key().is_none());
    }

    #[test]
    fn replayed_reveal_from_another_ceremony_is_rejected() {
        let members = [member(1, 11), member(2, 22)];
        // Member 1 ran a *different* ceremony (different nonce) and its reveal
        // there was legitimate. Replaying that reveal into THIS ceremony must
        // fail: member 1's commitment here binds THIS nonce, so the other
        // ceremony's r opens nothing here (and even the same r would need the
        // matching commitment, which binds the nonce).
        let other_nonce = [9u8; 32];
        // In this ceremony member 1 commits under NONCE to r=[22;32]; a reveal
        // carrying a contribution valid only under `other_nonce` won't match.
        let mut c = Ceremony::new(
            NONCE,
            CHAIN.to_vec(),
            &ids(&members),
            members[0].id,
            members[0].r,
        )
        .unwrap();
        // Commitment published for the OTHER ceremony (bound to other_nonce),
        // fed here as if it were member 1's commitment. Its signature is
        // irrelevant to this path — the machine aborts on the reveal below.
        c.accept_commitment(
            &members[1].id,
            commitment(&other_nonce, &members[1].id, &members[1].r),
            honest_csig(&members[1]),
        )
        .unwrap();
        assert_eq!(c.phase(), Phase::Revealing);
        // The honest reveal from the other ceremony does not open the commitment
        // under THIS ceremony's nonce.
        let err = c
            .accept_reveal(&members[1].id, members[1].r, honest_rsig(&members[1]))
            .unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
        assert_eq!(c.phase(), Phase::Aborted);
    }

    #[test]
    fn transcript_verifies_and_tamper_is_caught() {
        let members = [member(1, 11), member(2, 22), member(3, 33)];
        let c = run_honest(&members, 0);
        let mut t = c.transcript().unwrap().clone();
        assert!(t.verify());
        // Tamper a revealed contribution: the commitment no longer opens.
        t.members[1].r = [0xFF; 32];
        assert!(!t.verify());
        // Restore r, tamper the recorded key_id instead: re-derivation catches it.
        let mut t2 = c.transcript().unwrap().clone();
        t2.key_id = "S-0000000000000000".into();
        assert!(!t2.verify());
        // Tamper a retained signature: the commitment binding still passes, but
        // the signature no longer verifies under the member's device id.
        let mut t3 = c.transcript().unwrap().clone();
        t3.members[0].commit_sig[0] ^= 1;
        assert!(!t3.verify());
        let mut t4 = c.transcript().unwrap().clone();
        t4.members[0].reveal_sig[0] ^= 1;
        assert!(!t4.verify());
    }

    #[test]
    fn forged_transcript_without_valid_signatures_is_rejected() {
        // A transcript recomputed over arbitrary device ids the forger cannot
        // sign for: every keyless consistency check passes (each commitment
        // opens its r, the derived key_id matches), but the retained signatures
        // are garbage. Before slice 007 this shape verified — now it must not.
        let ids = [[0x40u8; 32], [0x41u8; 32]];
        let rs = [[0x11u8; 32], [0x22u8; 32]];
        let contributions: Vec<MemberContribution> = ids
            .iter()
            .zip(rs.iter())
            .map(|(id, r)| MemberContribution { device_id: *id, r: *r })
            .collect();
        let s = derive_shared_key(&NONCE, &contributions);
        let members: Vec<TranscriptEntry> = ids
            .iter()
            .zip(rs.iter())
            .map(|(id, r)| TranscriptEntry {
                device_id: *id,
                commitment: commitment(&NONCE, id, r),
                r: *r,
                commit_sig: [0u8; 64],
                reveal_sig: [0u8; 64],
            })
            .collect();
        let forged = Transcript {
            nonce: NONCE,
            chain_id: CHAIN.to_vec(),
            members,
            key_id: key_id(&s),
        };
        // The keyless consistency checks the old verify() relied on still pass...
        for e in &forged.members {
            assert_eq!(commitment(&NONCE, &e.device_id, &e.r), e.commitment);
        }
        // ...but verify() now rejects it: the signatures are not valid.
        assert!(!forged.verify());
    }

    #[test]
    fn non_member_and_duplicate_commitments_rejected() {
        let members = [member(1, 11), member(2, 22)];
        let stranger = member(9, 99);
        let mut c = Ceremony::new(
            NONCE,
            CHAIN.to_vec(),
            &ids(&members),
            members[0].id,
            members[0].r,
        )
        .unwrap();
        // A commitment from a device not in the set is refused.
        let err = c
            .accept_commitment(
                &stranger.id,
                commitment(&NONCE, &stranger.id, &stranger.r),
                honest_csig(&stranger),
            )
            .unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
        // Our own commitment was seeded; a second one for us is a duplicate.
        let err = c
            .accept_commitment(&members[0].id, c.local_commitment(), honest_csig(&members[0]))
            .unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
    }

    #[test]
    fn no_reveal_before_all_commitments() {
        let members = [member(1, 11), member(2, 22)];
        let mut c = Ceremony::new(
            NONCE,
            CHAIN.to_vec(),
            &ids(&members),
            members[0].id,
            members[0].r,
        )
        .unwrap();
        // Still Committing (member 2's commitment hasn't arrived): a reveal is
        // out of phase.
        assert_eq!(c.phase(), Phase::Committing);
        let err = c
            .accept_reveal(&members[0].id, members[0].r, honest_rsig(&members[0]))
            .unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
    }

    #[test]
    fn single_member_ceremony_refused() {
        let m = member(1, 11);
        let err = Ceremony::new(NONCE, CHAIN.to_vec(), &[m.id], m.id, m.r).unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
    }

    #[test]
    fn commit_and_reveal_signatures_roundtrip() {
        let m = member(1, 11);
        let comm = commitment(&NONCE, &m.id, &m.r);
        let csig = sign_commit(&m.sk, &NONCE, CHAIN, &m.id, &comm);
        assert!(verify_commit_sig(&NONCE, CHAIN, &m.id, &comm, &csig));
        // Tampered commitment fails.
        let mut bad = comm;
        bad[0] ^= 1;
        assert!(!verify_commit_sig(&NONCE, CHAIN, &m.id, &bad, &csig));

        let rsig = sign_reveal(&m.sk, &NONCE, CHAIN, &m.id, &m.r);
        assert!(verify_reveal_sig(&NONCE, CHAIN, &m.id, &m.r, &rsig));
        // A reveal signature is not valid under a different nonce (anti-replay at
        // the signature layer, complementing the commitment binding).
        let other_nonce = [8u8; 32];
        assert!(!verify_reveal_sig(&other_nonce, CHAIN, &m.id, &m.r, &rsig));
    }

    // --- drive-loop tests --------------------------------------------------

    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::thread;

    /// Signs with a raw `SigningKey` — the byte-for-byte equivalent of the vault
    /// session keeperd wires in production.
    struct RawSigner(SigningKey);
    impl CeremonySigner for RawSigner {
        fn sign(&self, msg: &[u8]) -> [u8; 64] {
            self.0.sign(msg).to_bytes()
        }
    }

    /// An in-memory mesh link: broadcast fans a frame to every peer's inbound
    /// queue; recv blocks on our own. Models keeperd's per-peer Noise sessions.
    struct ChannelTransport {
        inbound: mpsc::Receiver<Frame>,
        peers: Vec<mpsc::Sender<Frame>>,
    }
    impl CeremonyTransport for ChannelTransport {
        fn broadcast(&mut self, frame: &Frame) -> Result<()> {
            for p in &self.peers {
                // A peer that already finished has dropped its receiver; a closed
                // channel is not an error (it has what it needs).
                let _ = p.send(frame.clone());
            }
            Ok(())
        }
        fn recv(&mut self) -> Result<Frame> {
            self.inbound
                .recv()
                .map_err(|_| NetError::Protocol("ceremony transport closed"))
        }
    }

    /// A single-member harness: hands back scripted inbound frames and records
    /// what the driver broadcast. For the rejection paths (no live peers).
    struct ScriptedTransport {
        inbound: VecDeque<Frame>,
        sent: Vec<Frame>,
    }
    impl CeremonyTransport for ScriptedTransport {
        fn broadcast(&mut self, frame: &Frame) -> Result<()> {
            self.sent.push(frame.clone());
            Ok(())
        }
        fn recv(&mut self) -> Result<Frame> {
            self.inbound
                .pop_front()
                .ok_or(NetError::Protocol("scripted transport exhausted"))
        }
    }

    fn commit_frame(m: &Member, nonce: &CeremonyNonce, chain: &[u8]) -> Frame {
        let comm = commitment(nonce, &m.id, &m.r);
        let sig = sign_commit(&m.sk, nonce, chain, &m.id, &comm);
        Frame::shared_key_commit(SharedKeyCommit {
            nonce: nonce.to_vec(),
            chain_id: chain.to_vec(),
            device_id: m.id.to_vec(),
            commitment: comm.to_vec(),
            signature: sig.to_vec(),
        })
    }

    /// Run one live driver per member over an in-memory broadcast mesh, each on
    /// its own thread, and collect every member's derived `(S, Transcript)`.
    fn run_mesh(members: &[Member]) -> Vec<(SharedKey, Transcript)> {
        let n = members.len();
        let (mut senders, mut receivers) = (Vec::with_capacity(n), Vec::with_capacity(n));
        for _ in 0..n {
            let (tx, rx) = mpsc::channel::<Frame>();
            senders.push(tx);
            receivers.push(rx);
        }
        let all_ids = ids(members);
        let mut handles = Vec::with_capacity(n);
        for (i, rx) in receivers.into_iter().enumerate() {
            let peers: Vec<_> = senders
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, s)| s.clone())
                .collect();
            let member_ids = all_ids.clone();
            let (sk, id, r) = (members[i].sk.clone(), members[i].id, members[i].r);
            handles.push(thread::spawn(move || {
                let mut transport = ChannelTransport { inbound: rx, peers };
                let signer = RawSigner(sk);
                let mut ceremony =
                    Ceremony::new(NONCE, CHAIN.to_vec(), &member_ids, id, r).unwrap();
                run_ceremony(&mut transport, &signer, &mut ceremony)
                    .unwrap()
                    .derived()
                    .expect("mesh members complete the ceremony, never hand off")
            }));
        }
        // Drop the template senders so each inbound closes once every peer's
        // driver (holding the clones) has finished.
        drop(senders);
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    }

    #[test]
    fn mesh_drivers_derive_identical_s_two_members() {
        let members = [member(1, 11), member(2, 22)];
        let results = run_mesh(&members);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, results[1].0);
        assert!(results[0].1.verify());
        assert_eq!(results[0].1.key_id, results[1].1.key_id);
    }

    #[test]
    fn mesh_drivers_derive_identical_s_three_members() {
        let members = [member(1, 11), member(2, 22), member(3, 33)];
        let results = run_mesh(&members);
        assert_eq!(results.len(), 3);
        let s0 = results[0].0;
        let id0 = results[0].1.key_id.clone();
        assert!(id0.starts_with("S-"));
        for (s, transcript) in &results {
            // Every honest member derives the same S + key_id regardless of the
            // (thread-nondeterministic) order it saw frames, and the transcript
            // re-verifies from first principles.
            assert_eq!(*s, s0);
            assert_eq!(transcript.key_id, id0);
            assert!(transcript.verify());
        }
    }

    #[test]
    fn driver_rejects_a_bad_commit_signature() {
        let members = [member(1, 11), member(2, 22)];
        let comm = commitment(&NONCE, &members[1].id, &members[1].r);
        let bad = Frame::shared_key_commit(SharedKeyCommit {
            nonce: NONCE.to_vec(),
            chain_id: CHAIN.to_vec(),
            device_id: members[1].id.to_vec(),
            commitment: comm.to_vec(),
            signature: vec![0u8; 64], // does not verify
        });
        let mut transport = ScriptedTransport {
            inbound: VecDeque::from([bad]),
            sent: Vec::new(),
        };
        let signer = RawSigner(members[0].sk.clone());
        let mut ceremony =
            Ceremony::new(NONCE, CHAIN.to_vec(), &ids(&members), members[0].id, members[0].r)
                .unwrap();
        let err = run_ceremony(&mut transport, &signer, &mut ceremony).unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
        // Our own commitment went out before the peer's frame was rejected.
        assert_eq!(transport.sent.len(), 1);
    }

    #[test]
    fn driver_aborts_on_a_mismatched_reveal() {
        let members = [member(1, 11), member(2, 22)];
        let good_commit = commit_frame(&members[1], &NONCE, CHAIN);
        // A validly-signed reveal, but of a contribution that does not open the
        // commitment member 2 published.
        let wrong = [0xAAu8; 32];
        let rsig = sign_reveal(&members[1].sk, &NONCE, CHAIN, &members[1].id, &wrong);
        let bad_reveal = Frame::shared_key_reveal(SharedKeyReveal {
            nonce: NONCE.to_vec(),
            chain_id: CHAIN.to_vec(),
            device_id: members[1].id.to_vec(),
            contribution: wrong.to_vec(),
            signature: rsig.to_vec(),
        });
        let mut transport = ScriptedTransport {
            inbound: VecDeque::from([good_commit, bad_reveal]),
            sent: Vec::new(),
        };
        let signer = RawSigner(members[0].sk.clone());
        let mut ceremony =
            Ceremony::new(NONCE, CHAIN.to_vec(), &ids(&members), members[0].id, members[0].r)
                .unwrap();
        let err = run_ceremony(&mut transport, &signer, &mut ceremony).unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
        assert_eq!(ceremony.phase(), Phase::Aborted);
    }

    #[test]
    fn driver_rejects_a_commit_from_another_ceremony() {
        let members = [member(1, 11), member(2, 22)];
        // A well-formed, correctly-signed commit — but minted under a different
        // ceremony nonce. The driver's nonce binding rejects it before the state
        // machine sees it.
        let other_nonce = [9u8; 32];
        let comm = commitment(&other_nonce, &members[1].id, &members[1].r);
        let sig = sign_commit(&members[1].sk, &other_nonce, CHAIN, &members[1].id, &comm);
        let foreign = Frame::shared_key_commit(SharedKeyCommit {
            nonce: other_nonce.to_vec(),
            chain_id: CHAIN.to_vec(),
            device_id: members[1].id.to_vec(),
            commitment: comm.to_vec(),
            signature: sig.to_vec(),
        });
        let mut transport = ScriptedTransport {
            inbound: VecDeque::from([foreign]),
            sent: Vec::new(),
        };
        let signer = RawSigner(members[0].sk.clone());
        let mut ceremony =
            Ceremony::new(NONCE, CHAIN.to_vec(), &ids(&members), members[0].id, members[0].r)
                .unwrap();
        let err = run_ceremony(&mut transport, &signer, &mut ceremony).unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));
    }

    /// M5d slice 008: an initiator that dials to re-establish a key it lost
    /// receives a `SharedKeyHandoff` in reply to its commit. The driver
    /// short-circuits to [`CeremonyOutcome::Handoff`], surfacing the frame
    /// verbatim for the caller to verify + persist — it does not try to feed a
    /// hand-off into the state machine.
    #[test]
    fn driver_surfaces_a_handoff_reply_as_the_outcome() {
        let members = [member(1, 11), member(2, 22)];
        let handoff = Frame::shared_key_handoff(SharedKeyHandoff {
            chain_id: CHAIN.to_vec(),
            transcript_record: "record-bytes".to_string(),
            shared_key: vec![7u8; 32],
        });
        let mut transport = ScriptedTransport {
            inbound: VecDeque::from([handoff]),
            sent: Vec::new(),
        };
        let signer = RawSigner(members[0].sk.clone());
        let mut ceremony =
            Ceremony::new(NONCE, CHAIN.to_vec(), &ids(&members), members[0].id, members[0].r)
                .unwrap();
        let outcome = run_ceremony(&mut transport, &signer, &mut ceremony).unwrap();
        let CeremonyOutcome::Handoff(h) = outcome else {
            panic!("expected a hand-off outcome");
        };
        assert_eq!(h.transcript_record, "record-bytes");
        assert_eq!(h.shared_key, vec![7u8; 32]);
        // Our own commitment still went out before the peer's reply, and the
        // machine never advanced past the commit phase (no key derived).
        assert_eq!(transport.sent.len(), 1);
        assert_eq!(ceremony.phase(), Phase::Committing);
    }
}
