//! The holder-identity store + compare-and-swap gate behind the
//! `set_item_status` active claim (milestone #40, slice 002).
//!
//! ## Why this exists
//!
//! growlightd's drive loop already dedups its own assignments in memory (slice
//! 001 seeds the per-tick dedup set from the live `assignments`). But that is
//! the *loop's* bookkeeping. keeperd owns the authoritative queue table, so it
//! is the durable place to refuse a double-claim **even if the loop's
//! `assignments` ever drift** — defense-in-depth, the root-cause second layer,
//! not a patchwork on the loop ([[feedback_no_patchwork_fixes]]).
//!
//! ## Representation — the in-slice decision
//!
//! The holder lives in a keeperd **in-memory** map, NOT a new queue-table
//! column. Two reasons:
//!
//! 1. **Schema stability.** A 6th cell would break the round-tripped queue
//!    table's parse/render (5-cell rows), and would commit agent ids into the
//!    garden on every claim — churn + leakage the managed-region design avoids.
//! 2. **Cross-`daemon cycle` correctness, for free.** The map is part of
//!    `DaemonInner`, which is reconstructed empty on every daemon start. So a
//!    `daemon cycle` that left a part `active` (persisted in the table) records
//!    *no* holder for it after the bounce — an unknown holder, where the first
//!    claimant wins (never a permanent refusal). The loop's persistent
//!    `assignments` is the across-restart authority; this map is the live
//!    fleet's per-process guard. Cross-ref `decision-softfig-commit-from-memory`
//!    (the overlay/worktree split that keeps committed state and live state
//!    distinct).

use std::collections::HashMap;

/// A backlog part's identity in the holder map: its resolved managed-region tag
/// (the queue it lives in) plus its id. Tag-scoped so the same id in two queues
/// (the disambiguated cross-queue collision case) never shares a holder slot.
pub type PartKey = (String, String);

/// keeperd's in-memory active-holder store. See the module docs for why it is
/// in-memory (schema stability + cross-cycle first-claim-wins).
#[derive(Debug, Default)]
pub struct HolderStore {
    held: HashMap<PartKey, String>,
}

/// The CAS decision for an `active` claim, computed purely from the recorded
/// holder and the claimant id — so the three contract cases are unit-proven
/// without a live daemon.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimGate {
    /// Proceed and record `claimant` as the holder. Covers a fresh claim, the
    /// same holder re-claiming (idempotent), and an unknown-holder claim of an
    /// already-`active` part (a post-`daemon cycle` resume — first claim wins).
    Grant,
    /// Refuse: the part is already held `active` by this *different* agent
    /// (carried for the error text). The caller maps it to a fail-closed
    /// `Response::Err`, which growlightd's `claim.rs` turns into a
    /// `ClaimFailed` so the member never spawns on the held part.
    Deny(String),
    /// No claimant id supplied (a CLI/MCP/single-agent write): opt out of the
    /// CAS entirely, leaving the holder map untouched — back-compat.
    Untracked,
}

impl HolderStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide an `active` claim of `key` by `claimant` against the recorded
    /// holder. Pure (no mutation), so the contract is unit-tested directly:
    /// - a *different* holder of an already-held part → [`ClaimGate::Deny`];
    /// - the *same* holder re-claiming → [`ClaimGate::Grant`] (idempotent);
    /// - an *unknown* / unrecorded holder (a fresh claim or a part still
    ///   `active` across a `daemon cycle`) → `Grant` (first claim wins);
    /// - *no* claimant id → [`ClaimGate::Untracked`] (CAS opted out).
    pub fn gate(&self, key: &PartKey, claimant: Option<&str>) -> ClaimGate {
        match claimant {
            None => ClaimGate::Untracked,
            Some(c) => match self.held.get(key) {
                Some(h) if h != c => ClaimGate::Deny(h.clone()),
                _ => ClaimGate::Grant,
            },
        }
    }

    /// Record `holder` as the active holder of `key` (idempotent for the same
    /// holder). Called after a granted `active` claim — both a fresh write and
    /// the already-`active` no-op, so the first post-cycle claimant of an
    /// already-`active` part becomes its holder.
    pub fn record(&mut self, key: PartKey, holder: &str) {
        self.held.insert(key, holder.to_string());
    }

    /// Drop any holder for `key` — called when the part leaves `active`
    /// (done/blocked/queued/deferred), so a later re-activation is a fresh
    /// first-claim. A no-op when no holder is recorded.
    pub fn clear(&mut self, key: &PartKey) {
        self.held.remove(key);
    }

    /// The recorded holder of `key`, if any. Test/inspection only.
    #[cfg(test)]
    pub fn holder_of(&self, key: &PartKey) -> Option<&str> {
        self.held.get(key).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: &str, id: &str) -> PartKey {
        (tag.into(), id.into())
    }

    #[test]
    fn an_unrecorded_part_grants_the_first_claimant_and_records_it() {
        // The fresh-claim AND the post-`daemon cycle` resume case: no holder is
        // recorded (the map starts empty on every daemon start), so the first
        // claimant wins — never a permanent refusal of a part left `active`.
        let mut h = HolderStore::new();
        let k = key("queue", "p1");
        assert_eq!(h.gate(&k, Some("agent-a")), ClaimGate::Grant);
        h.record(k.clone(), "agent-a");
        assert_eq!(h.holder_of(&k), Some("agent-a"));
    }

    #[test]
    fn the_same_holder_reclaiming_is_an_idempotent_grant() {
        // Load-bearing: the SpawnFailed-retry path and resume-after-restart both
        // rely on the holding agent re-claiming its own part as a no-op success.
        let mut h = HolderStore::new();
        let k = key("queue", "p1");
        h.record(k.clone(), "agent-a");
        assert_eq!(h.gate(&k, Some("agent-a")), ClaimGate::Grant);
    }

    #[test]
    fn a_different_holder_is_denied_with_the_current_holder() {
        // The double-claim this milestone closes: a part held by a live peer is
        // refused for a different agent, carrying the current holder for the
        // error text.
        let mut h = HolderStore::new();
        let k = key("queue", "p1");
        h.record(k.clone(), "agent-a");
        assert_eq!(h.gate(&k, Some("agent-b")), ClaimGate::Deny("agent-a".into()));
    }

    #[test]
    fn no_claimant_id_opts_out_of_the_cas() {
        // A CLI/MCP/single-agent write passes no holder → the CAS is untracked
        // (back-compat), regardless of whether a holder is recorded.
        let mut h = HolderStore::new();
        let k = key("queue", "p1");
        assert_eq!(h.gate(&k, None), ClaimGate::Untracked);
        h.record(k.clone(), "agent-a");
        assert_eq!(h.gate(&k, None), ClaimGate::Untracked);
    }

    #[test]
    fn clearing_a_part_lets_the_next_claimant_win() {
        // When a part leaves `active`, its holder is dropped so a later
        // re-activation is a fresh first-claim by whoever picks it up.
        let mut h = HolderStore::new();
        let k = key("queue", "p1");
        h.record(k.clone(), "agent-a");
        h.clear(&k);
        assert_eq!(h.holder_of(&k), None);
        assert_eq!(h.gate(&k, Some("agent-b")), ClaimGate::Grant);
    }

    #[test]
    fn holders_are_scoped_per_part_key() {
        // Two parts (or the same id in two queues) hold independently.
        let mut h = HolderStore::new();
        let k1 = key("queue", "p1");
        let k2 = key("queue:softfig", "p1");
        h.record(k1.clone(), "agent-a");
        assert_eq!(h.gate(&k2, Some("agent-b")), ClaimGate::Grant);
        assert_eq!(h.gate(&k1, Some("agent-b")), ClaimGate::Deny("agent-a".into()));
    }
}
