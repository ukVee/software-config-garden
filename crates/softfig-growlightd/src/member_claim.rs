//! The live claim view the opencode spawn path reads to turn a member id into
//! its current `(queue, part)` assignment — the one piece of state the shared
//! `softfig_ipc::spawn_resolve::resolve_from_baton` helper needs beyond the
//! member's seeded baton and the garden layout (folder-grants slice 002 part B).
//!
//! The seam is deliberately narrow — one method, one return — so a backend never
//! reaches into [`crate::drive_loop::DriveLoop`]'s private assignment map and the
//! drive loop never learns a backend's shape. `OpencodeFlavor` holds an
//! `Arc<dyn MemberClaimLookup>`; the production impl ([`SharedClaimView`]) is a
//! shared `BTreeMap` the drive loop writes on claim / release and the flavor
//! reads per spawn.
//!
//! The map is empty until the drive-loop hook lands (slice 002 part B, step 2 in
//! the next iteration). Until then, a lookup returns `None` and the spawn path
//! treats the baton as item-less — the floor-only case — so the backend remains
//! as safe as it was before this seam. The fail-closed refusals in
//! [`softfig_ipc::spawn_resolve`] still land as soon as a `claim_for` returns
//! `Some(..)` and the item's chain or grants are bad.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// How the opencode spawn path learns which `(queue, part)` a member is on, so
/// it can read the item's doc chain and resolve its grants. Pure lookup — no
/// side effects, no I/O — so the trait is cheap to call once per spawn.
///
/// `Debug + Send + Sync` because [`crate::opencode_backend::OpencodeFlavor`]
/// holds it behind an `Arc`, which every spawn's reader thread may clone.
pub trait MemberClaimLookup: std::fmt::Debug + Send + Sync {
    /// `agent`'s current claim as `(queue, part)`, or `None` when the member has
    /// no live assignment (pre-claim, after a release, or because the drive loop
    /// has not yet recorded one). `None` is not an error: it is the floor-only
    /// case, same as a baton with no `item:`.
    fn claim_for(&self, agent: &str) -> Option<(String, String)>;
}

/// The production [`MemberClaimLookup`]: a shared `BTreeMap<agent, (queue, part)>`
/// that the drive loop writes on claim and release, and the opencode spawn path
/// reads per generate. Cheap to clone (two `Arc`s), so the drive loop and every
/// backend keep one.
///
/// Empty by default — the backend treats an empty view as "no live claim", the
/// floor-only case, exactly as it would for an unknown agent. This is the shape
/// the next iteration's drive-loop hook writes into, kept here with the trait so
/// the seam ships as one unit.
#[derive(Clone, Debug, Default)]
pub struct SharedClaimView {
    inner: Arc<Mutex<BTreeMap<String, (String, String)>>>,
}

impl SharedClaimView {
    /// A fresh, empty view. Behaves identically to `Default::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `agent`'s current claim. Overwrites any prior row for `agent`, so
    /// a re-roll onto the same part is idempotent and a rotation onto a new
    /// `(queue, part)` is one write (the drive loop's responsibility to call).
    pub fn record(&self, agent: &str, queue: &str, part: &str) {
        self.inner
            .lock()
            .unwrap()
            .insert(agent.to_string(), (queue.to_string(), part.to_string()));
    }

    /// Drop `agent`'s claim — called by the drive loop when a part is handed off
    /// or an item ends.
    pub fn release(&self, agent: &str) {
        self.inner.lock().unwrap().remove(agent);
    }

    /// A test / debug peek at the full map — one owned clone, so the lock never
    /// escapes.
    #[cfg(any(test, debug_assertions))]
    pub fn snapshot(&self) -> BTreeMap<String, (String, String)> {
        self.inner.lock().unwrap().clone()
    }
}

impl MemberClaimLookup for SharedClaimView {
    fn claim_for(&self, agent: &str) -> Option<(String, String)> {
        self.inner.lock().unwrap().get(agent).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_view_reports_no_claim_for_any_agent() {
        let view = SharedClaimView::new();
        assert_eq!(view.claim_for("a"), None);
        assert_eq!(view.claim_for(""), None);
    }

    #[test]
    fn recording_a_claim_and_reading_it_back_round_trips() {
        let view = SharedClaimView::new();
        view.record("a", "default", "folder-grants");
        assert_eq!(
            view.claim_for("a"),
            Some(("default".to_string(), "folder-grants".to_string())),
        );
        // Another agent is unaffected.
        assert_eq!(view.claim_for("b"), None);
    }

    #[test]
    fn recording_overwrites_a_prior_row_for_the_same_agent() {
        let view = SharedClaimView::new();
        view.record("a", "default", "p1");
        view.record("a", "psy", "psy-booking");
        assert_eq!(
            view.claim_for("a"),
            Some(("psy".to_string(), "psy-booking".to_string())),
        );
    }

    #[test]
    fn releasing_drops_the_claim() {
        let view = SharedClaimView::new();
        view.record("a", "default", "p1");
        view.release("a");
        assert_eq!(view.claim_for("a"), None);
        // A redundant release is a no-op.
        view.release("a");
        assert_eq!(view.claim_for("a"), None);
    }

    #[test]
    fn two_handles_see_the_same_state() {
        let a = SharedClaimView::new();
        let b = a.clone();
        a.record("m", "default", "x");
        assert_eq!(b.claim_for("m"), Some(("default".into(), "x".into())));
        b.release("m");
        assert_eq!(a.claim_for("m"), None);
    }

    /// A fake lookup for backend unit tests — the one that drives
    /// [`crate::opencode_backend::OpencodeFlavor::generate_preapproval`]'s
    /// grant-resolution branch without constructing a drive loop.
    #[derive(Debug, Default)]
    pub struct FakeClaimLookup {
        map: Mutex<BTreeMap<String, (String, String)>>,
    }

    impl FakeClaimLookup {
        pub fn with(agent: &str, queue: &str, part: &str) -> Self {
            let s = Self::default();
            s.map
                .lock()
                .unwrap()
                .insert(agent.to_string(), (queue.into(), part.into()));
            s
        }
    }

    impl MemberClaimLookup for FakeClaimLookup {
        fn claim_for(&self, agent: &str) -> Option<(String, String)> {
            self.map.lock().unwrap().get(agent).cloned()
        }
    }

    #[test]
    fn the_fake_matches_the_shared_view_for_a_single_agent() {
        let fake = FakeClaimLookup::with("a", "default", "folder-grants");
        assert_eq!(
            fake.claim_for("a"),
            Some(("default".to_string(), "folder-grants".to_string())),
        );
        assert_eq!(fake.claim_for("b"), None);
    }
}
