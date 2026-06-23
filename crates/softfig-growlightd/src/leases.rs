//! Supervisor-arbitrated leases (phase 4, slice 003) — the **pure arbitration
//! core** (spec-growlight-orchestrator §4c/§4d).
//!
//! Dangerous shared actions (a whole-file rewrite, restarting another agent, a
//! build touching a shared dep) do NOT go through chat: an agent *requests*,
//! growlightd *grants / queues / denies*, and agents never act on each other
//! directly (§4c). This module is the decision unit only — a value model of the
//! lease table with **no I/O, no daemon lock, no socket**, exactly like the
//! scheduler's [`crate::scheduler::pick`]. The daemon wires it thin: lock →
//! decide → side effects (perform a daemon-executed restart, clear a thrash
//! flag, publish a `LeaseChanged` event). Keeping the policy pure keeps it
//! provable against fakes (the theory-code proof obligation) and keeps the slice
//! additive.
//!
//! ## The model
//!
//! A lease key is an opaque string naming the shared resource/action being
//! arbitrated — for a contended garden section it is the thrash detector's
//! target label (`"path §heading"` / `"path"`), so a granted lease over a
//! flagged target can clear that flag (the §4d ladder: nudge → **lease** →
//! @human). Each key has at most one **holder** plus a FIFO **wait queue**:
//!
//! - **free** → the requester becomes holder (`Granted`).
//! - **held by the requester** → idempotent re-acquire (`Granted`).
//! - **held by someone else** → the requester joins the wait queue (`Queued`).
//! - the holder **releases** → the head waiter is promoted to holder and
//!   returned, so the daemon can hand the resource on (and emit the event).
//!
//! No lease-reaper and no deadlock: leases are advisory state a crashed agent
//! simply stops renewing; the §5 garden-write safety net is CAS, not these
//! locks. "Deny" (e.g. a self-restart) is an action-layer policy decision the
//! daemon makes *before* touching the table — the table itself only ever grants
//! or queues.
//!
//! ## The thrash hook
//!
//! [`ThrashClear`] is the §4d rung-2 seam. On a `Granted` lease the daemon calls
//! `clear_flag(key)` to resolve any thrash contention flag keeper raised on that
//! target. The trait takes the opaque key (not keeper's `(path, heading)` tuple)
//! so growlightd stays decoupled from the detector's internals; the live
//! cross-process binding to keeperd's `ThrashDetector::clear_flag` rides the
//! growlightd-pulls-from-keeperd bridge and lands with the phase-6 drive loop —
//! here it is proven against a spy. Default is no hook (no keeperd bridge yet),
//! mirroring how the live agent `child` is absent until phase 6.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

/// The §4d rung-2 hook: clear a thrash contention flag on a granted target.
///
/// Implemented (phase 6) over the growlightd→keeperd bridge, which parses the
/// opaque `key` back into the detector's `(path, heading)` target and calls
/// [`softfig_keeperd`'s `ThrashDetector::clear_flag`]. `Send + Sync` because the
/// daemon shares it across connection threads via an `Arc`.
pub trait ThrashClear: Send + Sync + fmt::Debug {
    /// Clear any thrash lease-flag on the target named by `key`. Returns whether
    /// a flag was actually present (so the daemon can log a no-op vs a real
    /// resolution).
    fn clear_flag(&self, key: &str) -> bool;
}

/// The outcome of a [`LeaseTable::request`]. The table only ever grants or
/// queues; an action-layer *denial* (e.g. a self-restart) is decided by the
/// daemon before the table is consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseDecision {
    /// The requester now holds the lease — newly granted, or it already held it
    /// (idempotent re-acquire).
    Granted,
    /// The lease is held by another agent; the requester is waiting. `position`
    /// is its 1-based slot in the FIFO wait queue.
    Queued { position: usize },
}

/// The outcome of a [`LeaseTable::release`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// The holder released the lease. `next_holder` is the waiter promoted to
    /// holder (FIFO), or `None` if the wait queue was empty and the key is now
    /// free.
    Released { next_holder: Option<String> },
    /// The caller was not the current holder — nothing changed. (A non-holder
    /// cannot release another agent's lease.)
    NotHolder,
}

/// One arbitrated lease: its current holder plus the FIFO queue of agents
/// waiting for it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lease {
    holder: String,
    waiters: VecDeque<String>,
}

/// The fleet's lease table — every active lease keyed by its opaque target
/// string. `BTreeMap` for deterministic iteration (a future `leases` roster
/// verb renders it in stable order). Pure: no clock, no I/O, no lock.
#[derive(Debug, Default)]
pub struct LeaseTable {
    held: BTreeMap<String, Lease>,
}

impl LeaseTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request the lease `key` for `agent`. Free → `Granted` (agent becomes
    /// holder); already held by `agent` → `Granted` (idempotent); held by
    /// another → `Queued` at the agent's existing or newly-appended FIFO slot
    /// (re-requesting while already queued returns the same position, never a
    /// duplicate).
    pub fn request(&mut self, key: &str, agent: &str) -> LeaseDecision {
        match self.held.get_mut(key) {
            None => {
                self.held.insert(
                    key.to_string(),
                    Lease {
                        holder: agent.to_string(),
                        waiters: VecDeque::new(),
                    },
                );
                LeaseDecision::Granted
            }
            Some(lease) if lease.holder == agent => LeaseDecision::Granted,
            Some(lease) => {
                if let Some(pos) = lease.waiters.iter().position(|w| w == agent) {
                    // Already waiting — idempotent, report the same slot.
                    return LeaseDecision::Queued { position: pos + 1 };
                }
                lease.waiters.push_back(agent.to_string());
                LeaseDecision::Queued {
                    position: lease.waiters.len(),
                }
            }
        }
    }

    /// Release the lease `key` held by `agent`. Promotes the head waiter to
    /// holder (and returns it) or frees the key when no one is waiting. A
    /// release by a non-holder is a no-op ([`ReleaseOutcome::NotHolder`]).
    pub fn release(&mut self, key: &str, agent: &str) -> ReleaseOutcome {
        match self.held.get_mut(key) {
            Some(lease) if lease.holder == agent => match lease.waiters.pop_front() {
                Some(next) => {
                    lease.holder = next.clone();
                    ReleaseOutcome::Released {
                        next_holder: Some(next),
                    }
                }
                None => {
                    self.held.remove(key);
                    ReleaseOutcome::Released { next_holder: None }
                }
            },
            _ => ReleaseOutcome::NotHolder,
        }
    }

    /// The current holder of `key`, if the lease is held.
    pub fn holder(&self, key: &str) -> Option<&str> {
        self.held.get(key).map(|l| l.holder.as_str())
    }

    /// Whether `key` is currently held by anyone.
    pub fn is_held(&self, key: &str) -> bool {
        self.held.contains_key(key)
    }

    /// Number of agents waiting on `key` (0 if free or held with no queue).
    pub fn waiter_count(&self, key: &str) -> usize {
        self.held.get(key).map(|l| l.waiters.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dock.rs §Layout";

    #[test]
    fn a_free_lease_is_granted_to_the_first_requester() {
        let mut t = LeaseTable::new();
        assert_eq!(t.request(KEY, "a"), LeaseDecision::Granted);
        assert_eq!(t.holder(KEY), Some("a"));
        assert!(t.is_held(KEY));
        assert_eq!(t.waiter_count(KEY), 0);
    }

    #[test]
    fn re_requesting_a_held_lease_as_the_holder_is_idempotent() {
        let mut t = LeaseTable::new();
        assert_eq!(t.request(KEY, "a"), LeaseDecision::Granted);
        // The holder asking again still holds it — no self-queue.
        assert_eq!(t.request(KEY, "a"), LeaseDecision::Granted);
        assert_eq!(t.waiter_count(KEY), 0, "the holder never queues behind itself");
    }

    #[test]
    fn a_second_agent_is_queued_behind_the_holder() {
        let mut t = LeaseTable::new();
        t.request(KEY, "a");
        assert_eq!(t.request(KEY, "b"), LeaseDecision::Queued { position: 1 });
        assert_eq!(t.request(KEY, "c"), LeaseDecision::Queued { position: 2 });
        assert_eq!(t.holder(KEY), Some("a"), "the holder is unchanged");
        assert_eq!(t.waiter_count(KEY), 2);
    }

    #[test]
    fn re_queuing_returns_the_same_slot_not_a_duplicate() {
        let mut t = LeaseTable::new();
        t.request(KEY, "a");
        assert_eq!(t.request(KEY, "b"), LeaseDecision::Queued { position: 1 });
        // b asks again while still waiting → same slot, not appended twice.
        assert_eq!(t.request(KEY, "b"), LeaseDecision::Queued { position: 1 });
        assert_eq!(t.waiter_count(KEY), 1);
    }

    #[test]
    fn release_hands_the_lease_to_the_head_waiter_in_fifo_order() {
        let mut t = LeaseTable::new();
        t.request(KEY, "a");
        t.request(KEY, "b");
        t.request(KEY, "c");
        // a releases → b (head of the FIFO) becomes holder, c stays queued.
        assert_eq!(
            t.release(KEY, "a"),
            ReleaseOutcome::Released {
                next_holder: Some("b".to_string())
            }
        );
        assert_eq!(t.holder(KEY), Some("b"));
        assert_eq!(t.waiter_count(KEY), 1);
        // b releases → c.
        assert_eq!(
            t.release(KEY, "b"),
            ReleaseOutcome::Released {
                next_holder: Some("c".to_string())
            }
        );
        assert_eq!(t.holder(KEY), Some("c"));
    }

    #[test]
    fn releasing_the_last_holder_frees_the_key() {
        let mut t = LeaseTable::new();
        t.request(KEY, "a");
        assert_eq!(
            t.release(KEY, "a"),
            ReleaseOutcome::Released { next_holder: None }
        );
        assert!(!t.is_held(KEY), "no waiters → the key is gone");
        assert_eq!(t.holder(KEY), None);
        // And it can be re-acquired fresh.
        assert_eq!(t.request(KEY, "z"), LeaseDecision::Granted);
    }

    #[test]
    fn a_non_holder_cannot_release_the_lease() {
        let mut t = LeaseTable::new();
        t.request(KEY, "a");
        t.request(KEY, "b");
        // b is only a waiter; it cannot release a's lease.
        assert_eq!(t.release(KEY, "b"), ReleaseOutcome::NotHolder);
        assert_eq!(t.holder(KEY), Some("a"), "the holder is untouched");
        // Releasing an unheld key is also a no-op.
        assert_eq!(t.release("never-held", "a"), ReleaseOutcome::NotHolder);
    }

    #[test]
    fn distinct_keys_are_independent() {
        let mut t = LeaseTable::new();
        assert_eq!(t.request("one", "a"), LeaseDecision::Granted);
        assert_eq!(t.request("two", "b"), LeaseDecision::Granted);
        // Holding "one" does not gate "two".
        assert_eq!(t.holder("one"), Some("a"));
        assert_eq!(t.holder("two"), Some("b"));
        assert_eq!(t.request("two", "a"), LeaseDecision::Queued { position: 1 });
        assert_eq!(t.request("one", "a"), LeaseDecision::Granted, "still holds one");
    }

    #[test]
    fn a_promoted_waiter_can_itself_be_released_to_the_next() {
        // Full hand-down chain a → b → c → free.
        let mut t = LeaseTable::new();
        for who in ["a", "b", "c"] {
            t.request(KEY, who);
        }
        t.release(KEY, "a");
        t.release(KEY, "b");
        assert_eq!(t.holder(KEY), Some("c"));
        assert_eq!(
            t.release(KEY, "c"),
            ReleaseOutcome::Released { next_holder: None }
        );
        assert!(!t.is_held(KEY));
    }
}
