//! M5e — the active/idle **write-turn lease** that coordinates shared-chain
//! writers so concurrent edits don't happen in the first place.
//!
//! This module is the coordination core of the shared-subtree model
//! ([`meta/spec-sync.md`] §"Active / idle coordination — a write-turn lease").
//! Like [`crate::ceremony`] it is deliberately **transport-agnostic and pure**:
//! the lease state machine and every signing-byte layout run without any I/O, so
//! the whole protocol is unit-testable headlessly. keeperd drives it over the
//! mesh — signing with the vault identity key, fanning `turn-request` /
//! `turn-yield` / `turn-revoke` / `device-state-announce` frames to the chain's
//! `S`-members, and gating the shared-chain commit boundary on holding the turn —
//! but none of that machinery lives here.
//!
//! # The protocol
//!
//! To commit to a shared subtree, an active member must hold that chain's
//! **turn** (one per chain). Acquire: a requester broadcasts a signed
//! `turn-request`; the current holder, *when it reaches a commit boundary*, stops
//! accepting new commits to that subtree, flushes the in-flight one, and replies
//! `turn-yield` — the go-ahead. The requester then writes, commits, and
//! broadcasts; members apply. **Quiescence is at the commit boundary, never
//! mid-edit; reads never block.**
//!
//! The turn is a **lease, not a lock**. It is time-bounded: if the holder
//! crashes or partitions, the lease expires and the turn returns (`turn-revoke`),
//! so one dead device can never brick a shared subtree. Lease expiry / partition
//! is exactly where the LWW + sidecar conflict fallback (slice 003) takes over.
//! Fairness is FIFO by logical request-time with a deterministic device-id
//! tiebreak, and a **max lease** caps any single hold so an active holder can't
//! starve the queue.
//!
//! # What is pure here vs. what keeperd owns
//!
//! [`WriteTurn`] is a single member's *local view* of a chain's turn. It never
//! preempts a live holder — the turn moves only on a voluntary [`WriteTurn::release`]
//! (the daemon calls it at a commit boundary) or on lease expiry
//! ([`WriteTurn::poll`] past the deadline). Convergence across members rides the
//! signed messages: a `turn-yield` names its `grantee`, a `turn-revoke` names the
//! `epoch` it revokes, so every honest member's local view lands on the same
//! holder. The "yield only at a commit boundary" and "who should I yield to next"
//! policy lives in keeperd; this type just guarantees the lease can never outlive
//! its cap and exposes the queue state the daemon needs.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// A device's shared-coordination state, observable to peers via a signed
/// `device-state-announce` (`meta/spec-sync.md` §"Active / idle coordination").
///
/// Only [`DeviceState::OnlineActive`] members participate in the turn handshake;
/// an `OnlineIdle` member applies incoming shared commits immediately (nothing is
/// editing, so no handshake is needed) and `Offline` implies unreachable. The
/// announce additionally carries an `unlocked` flag (a *locked* online device has
/// no `S` in memory, so it queues `S`-encrypted commits until unlock) — that flag
/// is orthogonal to the state and travels beside it on the wire, not inside this
/// enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// Daemon down / unreachable; FUSE unmounted, the garden isn't even visible
    /// as files.
    Offline,
    /// Daemon up and replicating, but no interactive session is writing. Incoming
    /// shared-chain commits apply immediately; no handshake needed.
    OnlineIdle,
    /// An interactive session (Claude via MCP, or the TUI/GUI) is attached and may
    /// write. Only these members participate in the write-turn handshake.
    OnlineActive,
}

impl DeviceState {
    /// The wire encoding (`DeviceStateAnnounce.state`): `0` offline, `1`
    /// online-idle, `2` online-active.
    pub fn as_u32(self) -> u32 {
        match self {
            DeviceState::Offline => 0,
            DeviceState::OnlineIdle => 1,
            DeviceState::OnlineActive => 2,
        }
    }

    /// Decode the wire value; an unknown code is `None` (a peer sending garbage,
    /// or a newer state this build doesn't know) so the caller fails closed rather
    /// than guessing.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(DeviceState::Offline),
            1 => Some(DeviceState::OnlineIdle),
            2 => Some(DeviceState::OnlineActive),
            _ => None,
        }
    }
}

/// The path-scope of a write-turn lease. v1 is whole-subtree only; the field
/// exists **from day one** (bound into the request signature) so a future
/// path-prefix / single-file narrowing (`meta/spec-sync.md` §"Future: scoped
/// leases") is an extension, not a wire change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseScope {
    /// The lease covers the entire shared subtree (v1).
    WholeSubtree,
}

impl LeaseScope {
    /// The wire encoding (`TurnRequest.scope`): `0` = whole subtree.
    pub fn as_u32(self) -> u32 {
        match self {
            LeaseScope::WholeSubtree => 0,
        }
    }

    /// Decode the wire value; an unknown scope is `None` (fail closed — a build
    /// that doesn't understand a narrowed scope must not treat it as whole-subtree
    /// and over-grant).
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(LeaseScope::WholeSubtree),
            _ => None,
        }
    }
}

/// Timing knobs for a chain's lease. `lease_ttl` is the liveness window — a
/// holder must renew (heartbeat) within it or its lease is presumed dead and
/// revoked (the crash/partition path). `max_lease` is the hard ceiling on any
/// single hold: a lease's revoke deadline is clamped to `granted_at + max_lease`,
/// so even a live, still-renewing holder must give the turn up once the ceiling
/// passes — FIFO fairness / anti-DoS. Both are in whole seconds (the same unit as
/// the signed edit timestamps the conflict fallback compares).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseConfig {
    /// Renew window in seconds; a holder silent longer than this loses the lease.
    pub lease_ttl: i64,
    /// Hard cap in seconds on a single hold, regardless of renewals.
    pub max_lease: i64,
}

impl LeaseConfig {
    /// The v1 default: a 30 s renew window (a crashed holder frees the turn within
    /// ~30 s) under a 5 min hard cap (an active holder yields to a waiting peer
    /// within 5 min even if it never voluntarily releases). `max_lease` clamps the
    /// renew deadline, so it must be `>= lease_ttl` for the knobs to compose;
    /// [`LeaseConfig::sane`] enforces that.
    pub const DEFAULT: LeaseConfig = LeaseConfig {
        lease_ttl: 30,
        max_lease: 300,
    };

    /// Whether the knobs compose: both positive and `max_lease >= lease_ttl` (so
    /// the ceiling never sits *below* the renew window, which would revoke a
    /// freshly-granted lease before its first heartbeat).
    pub fn sane(&self) -> bool {
        self.lease_ttl > 0 && self.max_lease >= self.lease_ttl
    }
}

impl Default for LeaseConfig {
    fn default() -> Self {
        LeaseConfig::DEFAULT
    }
}

/// The device currently holding a chain's turn, in one member's local view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Holder {
    device_id: [u8; 32],
    /// When this lease was granted (seconds). The `max_lease` ceiling is measured
    /// from here.
    granted_at: i64,
    /// The revoke deadline: `now >= revoke_deadline` in [`WriteTurn::poll`] ends
    /// the lease. Advanced by [`WriteTurn::renew`] up to `granted_at + max_lease`.
    revoke_deadline: i64,
    /// The lease generation, bumped on every grant. Binds a `turn-revoke` to the
    /// exact lease it ends (a stale revoke naming an old epoch is ignored).
    epoch: u64,
}

/// A queued turn request, ordered by (`seq`, `device_id`) — logical request-time
/// first, then a deterministic device-id tiebreak so two simultaneous requests
/// (equal `seq`) resolve to one winner with no deadlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Waiter {
    device_id: [u8; 32],
    seq: u64,
}

/// A single member's local view of one shared chain's write-turn lease.
///
/// Pure and deterministic: every transition takes the wall-clock `now` as an
/// argument (never reads it) so the whole lease lifecycle — grant, renew,
/// voluntary release, FIFO queueing, deterministic tiebreak, expiry-revoke, and
/// the max-lease ceiling — is reproducible in tests. See the module docs for the
/// pure-vs-daemon split.
#[derive(Debug, Clone)]
pub struct WriteTurn {
    holder: Option<Holder>,
    waiters: Vec<Waiter>,
    scope: LeaseScope,
    cfg: LeaseConfig,
    /// Next lease generation to hand out; the last granted epoch is `epoch - 1`.
    /// Starts at 1 so `0` is a never-granted sentinel no live lease ever carries.
    epoch: u64,
}

/// A transition surfaced by [`WriteTurn::poll`] that the daemon acts on (fanning
/// the matching signed frame to the chain's members).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseEvent {
    /// The turn passed to `device_id` under lease generation `epoch`. The daemon
    /// broadcasts the corresponding `turn-yield` (grantee = `device_id`) when the
    /// *local* device was the yielding holder.
    Granted { device_id: [u8; 32], epoch: u64 },
    /// `device_id`'s lease (generation `epoch`) expired — it went silent past the
    /// renew window or hit the max-lease ceiling. The turn is now free; the daemon
    /// broadcasts a `turn-revoke` so peers converge. This is the crash/partition
    /// recovery path, and where the slice-003 conflict fallback takes over.
    Revoked { device_id: [u8; 32], epoch: u64 },
}

impl WriteTurn {
    /// A fresh, unheld lease for a chain with the given scope + timing knobs. The
    /// config is sanitised to [`LeaseConfig::DEFAULT`] if the knobs don't compose
    /// ([`LeaseConfig::sane`]), so a misconfigured caller can never produce a lease
    /// whose ceiling sits below its renew window.
    pub fn new(scope: LeaseScope, cfg: LeaseConfig) -> Self {
        WriteTurn {
            holder: None,
            waiters: Vec::new(),
            scope,
            cfg: if cfg.sane() { cfg } else { LeaseConfig::DEFAULT },
            epoch: 1,
        }
    }

    /// A whole-subtree lease with the default timing knobs (the v1 shape).
    pub fn whole_subtree() -> Self {
        WriteTurn::new(LeaseScope::WholeSubtree, LeaseConfig::DEFAULT)
    }

    /// The lease's path-scope (v1 always [`LeaseScope::WholeSubtree`]).
    pub fn scope(&self) -> LeaseScope {
        self.scope
    }

    /// The current holder's device id, or `None` when the turn is free.
    pub fn holder(&self) -> Option<[u8; 32]> {
        self.holder.map(|h| h.device_id)
    }

    /// The current lease generation, or `None` when the turn is free. The daemon
    /// stamps this into an outgoing `turn-revoke`'s `epoch`.
    pub fn epoch(&self) -> Option<u64> {
        self.holder.map(|h| h.epoch)
    }

    /// Whether `device_id` currently holds the turn.
    pub fn is_held_by(&self, device_id: &[u8; 32]) -> bool {
        self.holder.is_some_and(|h| &h.device_id == device_id)
    }

    /// Whether any request is queued behind the current holder. The daemon uses
    /// this at a commit boundary to decide whether the local holder should yield
    /// now (FIFO fairness — hand the turn to a waiting peer) rather than keep it.
    pub fn has_waiters(&self) -> bool {
        !self.waiters.is_empty()
    }

    /// The winner of the queue — the request that a free turn would be granted to
    /// next: the minimum by (`seq`, `device_id`). `None` when no one is waiting.
    /// Deterministic, so every member computes the same next holder.
    pub fn next_in_line(&self) -> Option<[u8; 32]> {
        self.next_grant().map(|(device_id, _)| device_id)
    }

    /// The FIFO winner as `(device_id, seq)` — the queued request a free turn
    /// would grant next, minimum by (`seq`, `device_id`). `None` when no one
    /// waits. Companion to [`WriteTurn::next_in_line`], which drops the `seq`: the
    /// daemon stamps the returned `seq` into an outgoing `turn-yield` so the go-
    /// ahead names the exact granted request (the seq the grantee signed its
    /// `turn-request` with).
    pub fn next_grant(&self) -> Option<([u8; 32], u64)> {
        self.waiters
            .iter()
            .min_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.device_id.cmp(&b.device_id)))
            .map(|w| (w.device_id, w.seq))
    }

    /// Record a turn request from `device_id` at logical request-time `seq`.
    ///
    /// Pure bookkeeping — this never grants (a free turn is handed out by
    /// [`WriteTurn::poll`], keeping "record the request" and "pick the winner"
    /// separate and each independently testable). Idempotent: the current holder
    /// re-requesting is a no-op, and a device already queued keeps its *earliest*
    /// `seq` (a retried request can't jump itself forward in the FIFO order).
    pub fn request(&mut self, device_id: [u8; 32], seq: u64) {
        if self.is_held_by(&device_id) {
            return;
        }
        if let Some(w) = self.waiters.iter_mut().find(|w| w.device_id == device_id) {
            w.seq = w.seq.min(seq);
        } else {
            self.waiters.push(Waiter { device_id, seq });
        }
    }

    /// A holder heartbeat: extend the lease's renew deadline to `now + lease_ttl`,
    /// clamped to the `granted_at + max_lease` ceiling. Accepted (returns `true`)
    /// only from the current holder and only while the lease is still live; once
    /// the ceiling is reached the renew is refused so the max-lease fairness cap
    /// can never be pushed back. A non-holder heartbeat is ignored.
    pub fn renew(&mut self, device_id: &[u8; 32], now: i64) -> bool {
        let ceiling = self.cfg.max_lease;
        if let Some(h) = self.holder.as_mut() {
            if &h.device_id == device_id {
                let hard = h.granted_at.saturating_add(ceiling);
                if now >= hard {
                    return false; // at/over the ceiling — cannot extend past it
                }
                let want = now.saturating_add(self.cfg.lease_ttl);
                h.revoke_deadline = want.min(hard);
                return true;
            }
        }
        false
    }

    /// Voluntarily release the turn — the daemon calls this at a commit boundary
    /// when it (the holder) yields to a waiter, or after finishing its own write.
    /// Only the holder can release; a non-holder call is ignored. The turn becomes
    /// free; the next [`WriteTurn::poll`] grants the FIFO front. This is the "yield
    /// only at a commit boundary" path — nothing here preempts a holder mid-edit.
    pub fn release(&mut self, device_id: &[u8; 32]) {
        if self.is_held_by(device_id) {
            self.holder = None;
        }
    }

    /// Apply an inbound `turn-revoke` for `device_id` at lease generation `epoch`.
    /// Clears the holder only when it matches *both* the device and the exact
    /// epoch, so a stale revoke (naming a lease already superseded) or a revoke of
    /// a device that isn't the current holder is a safe no-op — a late revoke can
    /// never kill a fresh grant. Returns whether it took effect.
    pub fn apply_revoke(&mut self, device_id: &[u8; 32], epoch: u64) -> bool {
        if self
            .holder
            .is_some_and(|h| &h.device_id == device_id && h.epoch == epoch)
        {
            self.holder = None;
            true
        } else {
            false
        }
    }

    /// Apply an inbound `turn-yield` that hands the turn to `grantee`. Used by a
    /// member reconciling its local view to a holder's broadcast: the turn is set
    /// to `grantee` (removing it from the wait queue) under a fresh local epoch.
    /// Idempotent when `grantee` already holds. Returns the granted epoch, or
    /// `None` if the grantee already holds (nothing changed).
    pub fn apply_yield(&mut self, grantee: [u8; 32], now: i64) -> Option<u64> {
        if self.is_held_by(&grantee) {
            return None;
        }
        self.waiters.retain(|w| w.device_id != grantee);
        let epoch = self.epoch;
        self.epoch = self.epoch.wrapping_add(1);
        self.holder = Some(Holder {
            device_id: grantee,
            granted_at: now,
            revoke_deadline: now.saturating_add(self.cfg.lease_ttl),
            epoch,
        });
        Some(epoch)
    }

    /// Drive the lease forward to time `now`, returning the transitions that
    /// occurred (in order). At most one revoke and one grant per call:
    ///
    /// 1. **Expire.** If a holder's `revoke_deadline` has passed, its lease ends
    ///    ([`LeaseEvent::Revoked`]) and the turn frees. Because `renew` clamps the
    ///    deadline to the max-lease ceiling, this covers *both* a silent/crashed
    ///    holder (stopped heartbeating) and a live holder that hit the hard cap.
    /// 2. **Grant.** If the turn is then free and anyone is waiting, the FIFO
    ///    winner (minimum by `seq` then `device_id`) is granted a fresh lease
    ///    ([`LeaseEvent::Granted`]).
    ///
    /// A live, renewing holder is **never** preempted just because a waiter
    /// appeared — the queue only advances when the turn is genuinely free. That is
    /// the "a mid-edit doesn't yield; reads never block" guarantee at the state-
    /// machine level; the daemon layers the graceful commit-boundary yield on top
    /// (see [`WriteTurn::has_waiters`]).
    pub fn poll(&mut self, now: i64) -> Vec<LeaseEvent> {
        let mut events = Vec::new();

        if let Some(h) = self.holder {
            if now >= h.revoke_deadline {
                self.holder = None;
                events.push(LeaseEvent::Revoked {
                    device_id: h.device_id,
                    epoch: h.epoch,
                });
            }
        }

        if self.holder.is_none() {
            if let Some(winner) = self.next_in_line() {
                self.waiters.retain(|w| w.device_id != winner);
                let epoch = self.epoch;
                self.epoch = self.epoch.wrapping_add(1);
                self.holder = Some(Holder {
                    device_id: winner,
                    granted_at: now,
                    revoke_deadline: now.saturating_add(self.cfg.lease_ttl),
                    epoch,
                });
                events.push(LeaseEvent::Granted {
                    device_id: winner,
                    epoch,
                });
            }
        }

        events
    }
}

// --- signed-message byte layouts -------------------------------------------
//
// Each turn message is signed by the sender's Ed25519 identity over a
// domain-separated, length-prefixed encoding — the same convention as
// `ceremony.rs` / `replica.rs`, so no two distinct tuples (or two message kinds)
// ever share signed bytes. keeperd signs these bytes with the vault identity key
// and verifies inbound frames with the `verify_*` helpers below; protobuf is
// never signed or re-serialized for verification.

/// Domain-separation prefix for a `device-state-announce` signature.
const DEVICE_STATE_DOMAIN: &[u8] = b"softfig/turn/device-state/v1";

/// Domain-separation prefix for a `turn-request` signature.
const TURN_REQUEST_DOMAIN: &[u8] = b"softfig/turn/request/v1";

/// Domain-separation prefix for a `turn-yield` signature.
const TURN_YIELD_DOMAIN: &[u8] = b"softfig/turn/yield/v1";

/// Domain-separation prefix for a `turn-revoke` signature.
const TURN_REVOKE_DOMAIN: &[u8] = b"softfig/turn/revoke/v1";

/// Domain-separation prefix for a `shared-chain-push` signature (M5e slice 002).
const SHARED_CHAIN_PUSH_DOMAIN: &[u8] = b"softfig/turn/shared-chain-push/v1";

/// The exact bytes a device's Ed25519 identity signs to announce its state.
/// Binds the device id, the state code, the unlocked flag, and the per-device
/// logical clock `seq` so a stale announce can be ordered against a fresh one and
/// none can be replayed as a newer state.
pub fn device_state_signing_bytes(
    device_id: &[u8; 32],
    state: DeviceState,
    unlocked: bool,
    seq: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(DEVICE_STATE_DOMAIN.len() + 32 + 4 + 1 + 8);
    m.extend_from_slice(DEVICE_STATE_DOMAIN);
    m.extend_from_slice(device_id);
    m.extend_from_slice(&state.as_u32().to_be_bytes());
    m.push(unlocked as u8);
    m.extend_from_slice(&seq.to_be_bytes());
    m
}

/// The exact bytes a member's Ed25519 identity signs to request a chain's turn.
/// Length-prefixes the variable-length `chain_id` and binds the requester id, the
/// FIFO `seq`, and the lease `scope` (from day one) so a request signed for one
/// chain/scope can't be replayed onto another.
pub fn turn_request_signing_bytes(
    chain_id: &[u8],
    device_id: &[u8; 32],
    seq: u64,
    scope: LeaseScope,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(TURN_REQUEST_DOMAIN.len() + 4 + chain_id.len() + 32 + 8 + 4);
    m.extend_from_slice(TURN_REQUEST_DOMAIN);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(device_id);
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&scope.as_u32().to_be_bytes());
    m
}

/// The exact bytes a holder's Ed25519 identity signs to yield the turn. Binds the
/// yielding holder, the `grantee`, and the granted request's `seq`, so the go-
/// ahead names exactly one successor and one request — a forged/stale yield can't
/// redirect the turn.
pub fn turn_yield_signing_bytes(
    chain_id: &[u8],
    device_id: &[u8; 32],
    grantee: &[u8; 32],
    seq: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(TURN_YIELD_DOMAIN.len() + 4 + chain_id.len() + 32 + 32 + 8);
    m.extend_from_slice(TURN_YIELD_DOMAIN);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(device_id);
    m.extend_from_slice(grantee);
    m.extend_from_slice(&seq.to_be_bytes());
    m
}

/// The exact bytes a revoker's Ed25519 identity signs to reclaim an expired
/// holder's turn. Binds the `revoked` holder and the lease `epoch` so a revoke
/// targets exactly one lease generation and can't be replayed against a later
/// grant.
pub fn turn_revoke_signing_bytes(
    chain_id: &[u8],
    device_id: &[u8; 32],
    revoked: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(TURN_REVOKE_DOMAIN.len() + 4 + chain_id.len() + 32 + 32 + 8);
    m.extend_from_slice(TURN_REVOKE_DOMAIN);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(device_id);
    m.extend_from_slice(revoked);
    m.extend_from_slice(&epoch.to_be_bytes());
    m
}

/// The exact bytes the sending device's Ed25519 identity signs to push a
/// committed shared-subtree edit to the chain's other S-members (M5e slice 002).
/// Every variable-length field — the chain ref, the subtree path, the writer's
/// device name, and each edited file path (count-prefixed, then each
/// length-prefixed) — is length-prefixed so no two distinct pushes share an
/// encoding, and the fixed-size content hashes + sender id bind the exact tree
/// transition being adopted. Signing the `new_tree` + `base_tree` pair means a
/// captured push can't be replayed to graft a different tree or a different base
/// onto the chain. The vault produces the signature; keeperd's inbound handler
/// re-derives these bytes from the wire fields (protobuf is not canonical) and
/// checks it against the sender's identity — a valid signature proves *who*
/// pushed; S-membership (a separate committed-state check) proves they may.
#[allow(clippy::too_many_arguments)]
pub fn shared_chain_push_signing_bytes(
    chain_id: &[u8],
    subtree: &str,
    new_tree: &[u8; 32],
    base_tree: &[u8; 32],
    device_id: &[u8; 32],
    writer_device: &str,
    files: &[String],
) -> Vec<u8> {
    let files_len: usize = files.iter().map(|f| 4 + f.len()).sum();
    let mut m = Vec::with_capacity(
        SHARED_CHAIN_PUSH_DOMAIN.len()
            + 4
            + chain_id.len()
            + 4
            + subtree.len()
            + 32
            + 32
            + 32
            + 4
            + writer_device.len()
            + 4
            + files_len,
    );
    m.extend_from_slice(SHARED_CHAIN_PUSH_DOMAIN);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(&(subtree.len() as u32).to_be_bytes());
    m.extend_from_slice(subtree.as_bytes());
    m.extend_from_slice(new_tree);
    m.extend_from_slice(base_tree);
    m.extend_from_slice(device_id);
    m.extend_from_slice(&(writer_device.len() as u32).to_be_bytes());
    m.extend_from_slice(writer_device.as_bytes());
    m.extend_from_slice(&(files.len() as u32).to_be_bytes());
    for f in files {
        m.extend_from_slice(&(f.len() as u32).to_be_bytes());
        m.extend_from_slice(f.as_bytes());
    }
    m
}

/// Verify a `device-state-announce` signature against the announcing device's
/// Ed25519 identity key. Never panics — a bad key, wrong-length signature, or a
/// non-verifying signature all return `false` (the `ceremony`/`replica` shape).
pub fn verify_device_state_sig(
    device_id: &[u8; 32],
    state: DeviceState,
    unlocked: bool,
    seq: u64,
    sig: &[u8],
) -> bool {
    verify_sig(
        device_id,
        &device_state_signing_bytes(device_id, state, unlocked, seq),
        sig,
    )
}

/// Verify a `turn-request` signature against the requesting member's Ed25519
/// identity key. Never panics. Membership authorization (is this device an
/// `S`-member of the chain?) is a separate check keeperd runs against the
/// committed shared-subtree membership — a valid signature proves *who* signed,
/// not that they are entitled to the chain's turn.
pub fn verify_turn_request_sig(
    chain_id: &[u8],
    device_id: &[u8; 32],
    seq: u64,
    scope: LeaseScope,
    sig: &[u8],
) -> bool {
    verify_sig(
        device_id,
        &turn_request_signing_bytes(chain_id, device_id, seq, scope),
        sig,
    )
}

/// Verify a `turn-yield` signature against the yielding holder's Ed25519 identity
/// key. Never panics.
pub fn verify_turn_yield_sig(
    chain_id: &[u8],
    device_id: &[u8; 32],
    grantee: &[u8; 32],
    seq: u64,
    sig: &[u8],
) -> bool {
    verify_sig(
        device_id,
        &turn_yield_signing_bytes(chain_id, device_id, grantee, seq),
        sig,
    )
}

/// Verify a `turn-revoke` signature against the revoker's Ed25519 identity key.
/// Never panics.
pub fn verify_turn_revoke_sig(
    chain_id: &[u8],
    device_id: &[u8; 32],
    revoked: &[u8; 32],
    epoch: u64,
    sig: &[u8],
) -> bool {
    verify_sig(
        device_id,
        &turn_revoke_signing_bytes(chain_id, device_id, revoked, epoch),
        sig,
    )
}

/// Verify a `shared-chain-push` signature against the sending device's Ed25519
/// identity key (M5e slice 002). Never panics. As with the turn frames, a valid
/// signature proves *who* pushed the edit; S-membership authorization (is the
/// sender a member of the chain?) is a separate check keeperd runs against the
/// committed shared-subtree membership before applying.
#[allow(clippy::too_many_arguments)]
pub fn verify_shared_chain_push_sig(
    chain_id: &[u8],
    subtree: &str,
    new_tree: &[u8; 32],
    base_tree: &[u8; 32],
    device_id: &[u8; 32],
    writer_device: &str,
    files: &[String],
    sig: &[u8],
) -> bool {
    verify_sig(
        device_id,
        &shared_chain_push_signing_bytes(
            chain_id,
            subtree,
            new_tree,
            base_tree,
            device_id,
            writer_device,
            files,
        ),
        sig,
    )
}

/// Verify `sig` over `msg` under the Ed25519 public key `pubkey`. Returns `false`
/// (never panics) on a malformed key or signature — the same fail-closed shape as
/// `ceremony::verify_sig` / `replica`'s verifiers. (Kept local to this module so
/// the turn crypto is self-contained and independently reviewable.)
fn verify_sig(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig_bytes): std::result::Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(&sig_bytes)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn dev(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // A test config with tiny windows so time math is easy to read.
    fn cfg() -> LeaseConfig {
        LeaseConfig {
            lease_ttl: 10,
            max_lease: 100,
        }
    }

    fn turn() -> WriteTurn {
        WriteTurn::new(LeaseScope::WholeSubtree, cfg())
    }

    #[test]
    fn free_turn_grants_to_the_sole_requester() {
        let mut t = turn();
        assert_eq!(t.holder(), None);
        t.request(dev(1), 5);
        let ev = t.poll(1_000);
        assert_eq!(
            ev,
            vec![LeaseEvent::Granted {
                device_id: dev(1),
                epoch: 1
            }]
        );
        assert_eq!(t.holder(), Some(dev(1)));
        assert!(!t.has_waiters());
    }

    #[test]
    fn simultaneous_contenders_have_one_deterministic_winner_loser_queues() {
        // Two active members request the free turn at the same logical time.
        let mut t = turn();
        t.request(dev(9), 7);
        t.request(dev(2), 7); // equal seq -> device-id tiebreak: dev(2) < dev(9)
        assert_eq!(t.next_in_line(), Some(dev(2)));
        let ev = t.poll(0);
        assert_eq!(
            ev,
            vec![LeaseEvent::Granted {
                device_id: dev(2),
                epoch: 1
            }]
        );
        assert_eq!(t.holder(), Some(dev(2)));
        // The loser is still queued FIFO, not dropped.
        assert!(t.has_waiters());
        assert_eq!(t.next_in_line(), Some(dev(9)));
    }

    #[test]
    fn next_grant_returns_the_fifo_winner_with_its_seq() {
        // Mirrors `next_in_line`'s ordering but also surfaces the winner's `seq`,
        // which the daemon stamps into the `turn-yield` it signs.
        let mut t = turn();
        assert_eq!(t.next_grant(), None);
        t.request(dev(9), 7);
        t.request(dev(2), 7); // equal seq -> device-id tiebreak: dev(2) < dev(9)
        t.request(dev(5), 3); // lowest seq wins outright
        assert_eq!(t.next_grant(), Some((dev(5), 3)));
        assert_eq!(t.next_in_line(), Some(dev(5)));
    }

    #[test]
    fn lower_seq_wins_before_device_id_tiebreak() {
        let mut t = turn();
        t.request(dev(1), 9); // higher seq
        t.request(dev(8), 4); // lower seq wins despite the larger id
        assert_eq!(t.next_in_line(), Some(dev(8)));
        t.poll(0);
        assert_eq!(t.holder(), Some(dev(8)));
    }

    #[test]
    fn a_live_holder_is_not_preempted_when_a_waiter_appears() {
        // "quiescence at the commit boundary, never mid-edit": a renewing holder
        // keeps the turn even with someone queued — the turn only moves on a
        // voluntary release or on expiry.
        let mut t = turn();
        t.request(dev(1), 1);
        t.poll(0);
        assert_eq!(t.holder(), Some(dev(1)));

        t.request(dev(2), 2); // a waiter appears mid-hold
        for now in [1, 3, 5, 8] {
            assert!(t.renew(&dev(1), now)); // holder heartbeats
            assert_eq!(t.poll(now), vec![]); // no transfer
            assert_eq!(t.holder(), Some(dev(1)));
        }
        assert!(t.has_waiters());
    }

    #[test]
    fn voluntary_release_hands_the_turn_to_the_fifo_front() {
        let mut t = turn();
        t.request(dev(1), 1);
        t.poll(0);
        t.request(dev(2), 2);
        t.request(dev(3), 3);

        t.release(&dev(1)); // holder yields at a commit boundary
        assert_eq!(t.holder(), None);
        let ev = t.poll(5);
        assert_eq!(
            ev,
            vec![LeaseEvent::Granted {
                device_id: dev(2),
                epoch: 2
            }]
        );
        assert_eq!(t.holder(), Some(dev(2)));
        assert_eq!(t.next_in_line(), Some(dev(3)));
    }

    #[test]
    fn a_non_holder_cannot_release_or_renew() {
        let mut t = turn();
        t.request(dev(1), 1);
        t.poll(0);
        assert!(!t.renew(&dev(2), 1)); // not the holder
        t.release(&dev(2)); // no-op
        assert_eq!(t.holder(), Some(dev(1)));
    }

    #[test]
    fn a_silent_holder_lease_expires_and_the_turn_is_revoked_then_regranted() {
        // The crash/partition path: a holder that stops heartbeating loses the
        // lease within lease_ttl, and a queued peer gets the turn.
        let mut t = turn();
        t.request(dev(1), 1);
        t.poll(0); // dev(1) holds, revoke_deadline = 0 + 10
        t.request(dev(2), 2);

        // Before the deadline: still held, no events.
        assert_eq!(t.poll(9), vec![]);
        assert_eq!(t.holder(), Some(dev(1)));

        // At the deadline: revoke + regrant to the waiter, in one poll.
        let ev = t.poll(10);
        assert_eq!(
            ev,
            vec![
                LeaseEvent::Revoked {
                    device_id: dev(1),
                    epoch: 1
                },
                LeaseEvent::Granted {
                    device_id: dev(2),
                    epoch: 2
                },
            ]
        );
        assert_eq!(t.holder(), Some(dev(2)));
    }

    #[test]
    fn a_silent_holder_with_no_waiters_just_frees_the_turn() {
        let mut t = turn();
        t.request(dev(1), 1);
        t.poll(0);
        let ev = t.poll(10);
        assert_eq!(
            ev,
            vec![LeaseEvent::Revoked {
                device_id: dev(1),
                epoch: 1
            }]
        );
        assert_eq!(t.holder(), None);
    }

    #[test]
    fn renew_extends_the_lease_within_the_ttl() {
        let mut t = turn();
        t.request(dev(1), 1);
        t.poll(0); // deadline 10
        assert!(t.renew(&dev(1), 8)); // deadline -> 18
        assert_eq!(t.poll(10), vec![]); // no longer expiring at 10
        assert_eq!(t.holder(), Some(dev(1)));
        // But it does expire once the renewed deadline passes with no heartbeat.
        assert_eq!(
            t.poll(18),
            vec![LeaseEvent::Revoked {
                device_id: dev(1),
                epoch: 1
            }]
        );
    }

    #[test]
    fn max_lease_caps_a_hold_even_when_the_holder_keeps_renewing() {
        // Fairness / anti-DoS: an always-heartbeating holder still yields within
        // max_lease. renew is refused once the ceiling (granted_at + max_lease) is
        // reached, so the clamped deadline expires and the turn frees.
        let mut t = turn(); // lease_ttl 10, max_lease 100
        t.request(dev(1), 1);
        t.poll(0); // granted_at 0, ceiling 100

        // Heartbeat every 9 s right up to the ceiling — all accepted, deadline
        // clamped to 100.
        let mut now = 0;
        while now < 100 {
            assert!(t.renew(&dev(1), now), "renew at {now} should be accepted");
            now += 9;
        }
        // At/after the ceiling, renews are refused.
        assert!(!t.renew(&dev(1), 100));
        assert!(!t.renew(&dev(1), 130));
        // The clamped deadline is 100, so the lease expires there regardless of
        // how long the holder kept heartbeating.
        let ev = t.poll(100);
        assert_eq!(
            ev,
            vec![LeaseEvent::Revoked {
                device_id: dev(1),
                epoch: 1
            }]
        );
    }

    #[test]
    fn request_is_idempotent_and_keeps_the_earliest_seq() {
        let mut t = turn();
        t.request(dev(5), 20);
        t.request(dev(5), 5); // earlier retry -> keeps 5
        t.request(dev(5), 30); // later retry can't push it back
        t.request(dev(3), 10);
        // dev(5) at seq 5 beats dev(3) at seq 10.
        assert_eq!(t.next_in_line(), Some(dev(5)));
        // The holder re-requesting is a no-op (doesn't enqueue itself).
        t.poll(0);
        assert_eq!(t.holder(), Some(dev(5)));
        t.request(dev(5), 1);
        assert!(t.has_waiters()); // only dev(3) remains queued
        assert_eq!(t.next_in_line(), Some(dev(3)));
    }

    #[test]
    fn apply_revoke_only_matches_the_exact_holder_and_epoch() {
        let mut t = turn();
        t.request(dev(1), 1);
        t.poll(0); // dev(1) holds epoch 1

        assert!(!t.apply_revoke(&dev(2), 1)); // wrong device
        assert!(!t.apply_revoke(&dev(1), 99)); // stale epoch
        assert_eq!(t.holder(), Some(dev(1)));
        assert!(t.apply_revoke(&dev(1), 1)); // exact match
        assert_eq!(t.holder(), None);
    }

    #[test]
    fn apply_yield_sets_the_grantee_as_holder_under_a_fresh_epoch() {
        let mut t = turn();
        t.request(dev(7), 3); // dev(7) queued
        let epoch = t.apply_yield(dev(7), 50).expect("granted");
        assert_eq!(epoch, 1);
        assert_eq!(t.holder(), Some(dev(7)));
        assert!(!t.has_waiters()); // removed from the queue
        // Re-applying to the same holder is a no-op.
        assert_eq!(t.apply_yield(dev(7), 60), None);
    }

    #[test]
    fn misconfigured_lease_config_falls_back_to_default() {
        let bad = LeaseConfig {
            lease_ttl: 0,
            max_lease: 5,
        };
        assert!(!bad.sane());
        let t = WriteTurn::new(LeaseScope::WholeSubtree, bad);
        // The lease still functions on the default knobs rather than a ceiling
        // below its renew window.
        assert!(t.cfg.sane());
        assert_eq!(t.cfg, LeaseConfig::DEFAULT);
    }

    #[test]
    fn device_state_wire_roundtrip() {
        for s in [
            DeviceState::Offline,
            DeviceState::OnlineIdle,
            DeviceState::OnlineActive,
        ] {
            assert_eq!(DeviceState::from_u32(s.as_u32()), Some(s));
        }
        assert_eq!(DeviceState::from_u32(3), None); // unknown fails closed
        assert_eq!(LeaseScope::from_u32(0), Some(LeaseScope::WholeSubtree));
        assert_eq!(LeaseScope::from_u32(1), None);
    }

    // --- signature helpers ---------------------------------------------------

    #[test]
    fn turn_request_signature_verifies_and_a_non_member_forgery_is_rejected() {
        let member = SigningKey::from_bytes(&[3u8; 32]);
        let member_id = member.verifying_key().to_bytes();
        let chain = b"chain-abc";
        let bytes = turn_request_signing_bytes(chain, &member_id, 42, LeaseScope::WholeSubtree);
        let sig = member.sign(&bytes).to_bytes();

        assert!(verify_turn_request_sig(
            chain,
            &member_id,
            42,
            LeaseScope::WholeSubtree,
            &sig
        ));

        // A different device signs a request claiming the member's id — the
        // signature is checked against the *claimed* device_id, so the forgery
        // fails (the crypto half of "a forged turn-request is rejected"; keeperd
        // adds the S-membership check on top).
        let attacker = SigningKey::from_bytes(&[4u8; 32]);
        let forged = attacker.sign(&bytes).to_bytes();
        assert!(!verify_turn_request_sig(
            chain,
            &member_id,
            42,
            LeaseScope::WholeSubtree,
            &forged
        ));
    }

    #[test]
    fn turn_request_signature_is_bound_to_chain_seq_and_scope() {
        let k = SigningKey::from_bytes(&[5u8; 32]);
        let id = k.verifying_key().to_bytes();
        let sig = k
            .sign(&turn_request_signing_bytes(b"chain-a", &id, 1, LeaseScope::WholeSubtree))
            .to_bytes();
        // Same signature, different chain / seq -> rejected (no cross-chain or
        // cross-request replay).
        assert!(verify_turn_request_sig(b"chain-a", &id, 1, LeaseScope::WholeSubtree, &sig));
        assert!(!verify_turn_request_sig(b"chain-b", &id, 1, LeaseScope::WholeSubtree, &sig));
        assert!(!verify_turn_request_sig(b"chain-a", &id, 2, LeaseScope::WholeSubtree, &sig));
    }

    #[test]
    fn turn_yield_and_revoke_signatures_verify() {
        let holder = SigningKey::from_bytes(&[6u8; 32]);
        let hid = holder.verifying_key().to_bytes();
        let grantee = dev(2);
        let ysig = holder
            .sign(&turn_yield_signing_bytes(b"c", &hid, &grantee, 9))
            .to_bytes();
        assert!(verify_turn_yield_sig(b"c", &hid, &grantee, 9, &ysig));
        assert!(!verify_turn_yield_sig(b"c", &hid, &dev(3), 9, &ysig)); // wrong grantee

        let rsig = holder
            .sign(&turn_revoke_signing_bytes(b"c", &hid, &grantee, 4))
            .to_bytes();
        assert!(verify_turn_revoke_sig(b"c", &hid, &grantee, 4, &rsig));
        assert!(!verify_turn_revoke_sig(b"c", &hid, &grantee, 5, &rsig)); // wrong epoch
    }

    #[test]
    fn device_state_signature_verifies_and_binds_its_fields() {
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let id = k.verifying_key().to_bytes();
        let sig = k
            .sign(&device_state_signing_bytes(&id, DeviceState::OnlineActive, true, 3))
            .to_bytes();
        assert!(verify_device_state_sig(&id, DeviceState::OnlineActive, true, 3, &sig));
        // Any field change invalidates it.
        assert!(!verify_device_state_sig(&id, DeviceState::OnlineIdle, true, 3, &sig));
        assert!(!verify_device_state_sig(&id, DeviceState::OnlineActive, false, 3, &sig));
        assert!(!verify_device_state_sig(&id, DeviceState::OnlineActive, true, 4, &sig));
    }

    #[test]
    fn shared_chain_push_signature_verifies_and_binds_the_tree_transition() {
        let writer = SigningKey::from_bytes(&[8u8; 32]);
        let id = writer.verifying_key().to_bytes();
        let chain = b"chain/proj";
        let new_tree = [9u8; 32];
        let base_tree = [10u8; 32];
        let files = vec!["proj/a.md".to_string(), "proj/b.md".to_string()];
        let bytes = shared_chain_push_signing_bytes(
            chain, "proj", &new_tree, &base_tree, &id, "peerbox", &files,
        );
        let sig = writer.sign(&bytes).to_bytes();

        assert!(verify_shared_chain_push_sig(
            chain, "proj", &new_tree, &base_tree, &id, "peerbox", &files, &sig
        ));

        // A captured push can't be replayed to graft a different tree, a
        // different base, or onto a different chain/subtree — each field is
        // bound.
        let other = [11u8; 32];
        assert!(!verify_shared_chain_push_sig(
            chain, "proj", &other, &base_tree, &id, "peerbox", &files, &sig
        ));
        assert!(!verify_shared_chain_push_sig(
            chain, "proj", &new_tree, &other, &id, "peerbox", &files, &sig
        ));
        assert!(!verify_shared_chain_push_sig(
            b"chain/other", "proj", &new_tree, &base_tree, &id, "peerbox", &files, &sig
        ));
        assert!(!verify_shared_chain_push_sig(
            chain, "other", &new_tree, &base_tree, &id, "peerbox", &files, &sig
        ));
        // Provenance + the edited-file list are signed too.
        assert!(!verify_shared_chain_push_sig(
            chain, "proj", &new_tree, &base_tree, &id, "otherbox", &files, &sig
        ));
        let fewer = vec!["proj/a.md".to_string()];
        assert!(!verify_shared_chain_push_sig(
            chain, "proj", &new_tree, &base_tree, &id, "peerbox", &fewer, &sig
        ));

        // A forger who re-signs with their own key over the member's claimed id
        // fails: the signature is checked against the *claimed* device_id.
        let attacker = SigningKey::from_bytes(&[12u8; 32]);
        let forged = attacker.sign(&bytes).to_bytes();
        assert!(!verify_shared_chain_push_sig(
            chain, "proj", &new_tree, &base_tree, &id, "peerbox", &files, &forged
        ));
    }

    #[test]
    fn shared_chain_push_length_prefixing_defeats_field_run_together() {
        // Two distinct (subtree, writer_device) splits that would collide under
        // naive concatenation must produce distinct signing bytes — the length
        // prefixes keep the boundary unambiguous.
        let id = [1u8; 32];
        let (nt, bt) = ([2u8; 32], [3u8; 32]);
        let a = shared_chain_push_signing_bytes(b"c", "ab", &nt, &bt, &id, "cd", &[]);
        let b = shared_chain_push_signing_bytes(b"c", "abc", &nt, &bt, &id, "d", &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_signatures_never_panic() {
        assert!(!verify_turn_request_sig(
            b"c",
            &dev(1),
            0,
            LeaseScope::WholeSubtree,
            &[]
        ));
        assert!(!verify_turn_request_sig(
            b"c",
            &dev(1),
            0,
            LeaseScope::WholeSubtree,
            &[0u8; 10]
        ));
        // An all-zero device id is not a valid Ed25519 point -> false, no panic.
        assert!(!verify_device_state_sig(
            &[0u8; 32],
            DeviceState::Offline,
            false,
            0,
            &[0u8; 64]
        ));
    }
}
