//! The §4d rung-2 thrash→lease bridge (drive-loop slice 004) — the
//! growlightd-local half of binding a granted lease to keeperd's thrash detector.
//!
//! ## The two daemons, and what this slice can and cannot do
//!
//! The §4d ladder is **nudge → lease → @human**. Rung 2 is "a granted lease
//! settles the A↔B ping-pong the detector tripped on": when growlightd grants a
//! lease over a contended garden target, keeperd's [`ThrashDetector`] flag on that
//! target must clear. But the detector lives in **keeperd** (it is fed from the
//! section-edit commit path), and growlightd is a *separate process* — a keeperd
//! client. The lease table ([`crate::leases`]) and its [`ThrashClear`] seam are
//! growlightd's; the flag set is keeperd's.
//!
//! The existing bus bridge ([`crate::bus`]) is **one-way: growlightd PULLS from
//! keeperd** (the read-only `tail_bus` verb). Clearing a flag is the opposite
//! direction — a growlightd→keeperd **write** — and no such verb exists yet. So
//! the live cross-process clear is deferred to the `growlight-wire-loose-ends`
//! milestone, exactly like the deferred committed-bus post behind
//! [`crate::notify_dispatch::BusEmit`].
//!
//! ## What this module IS
//!
//! The growlightd-local piece that *can* be built and proven now: the
//! **key↔target translation**. The daemon holds leases under an opaque string
//! key; for a contended garden section that key is keeperd's
//! `Trip::target_label` — `"path §heading"` (or `"path"` whole-file). keeperd's
//! `ThrashDetector::clear_flag` takes the `(path, heading)` tuple. Something must
//! translate the one into the other, and the natural home is growlightd (the side
//! that holds the opaque key). [`KeeperThrashClear`] is that bridge: a real
//! [`ThrashClear`] impl that [`parse_target`]s the key and delegates the clear to
//! a [`TargetClear`] seam. The seam's *live* impl is the deferred growlightd→
//! keeperd write; here it is proven against a fake, and against the real
//! [`crate::daemon::Daemon`]'s grant path via `with_thrash_clear`.

use std::fmt;

use crate::leases::ThrashClear;

/// The separator keeperd's `Trip::target_label` joins a path and heading with —
/// a space then the section sign (`"{path} §{heading}"`). A whole-file target has
/// no heading and renders as just the bare path.
const TARGET_SEP: &str = " §";

/// Split an opaque lease key back into keeperd's `(path, heading)` thrash target —
/// the exact inverse of keeperd's `Trip::target_label`. `"dock.rs §Layout"` →
/// `("dock.rs", Some("Layout"))`; a key with no separator is a whole-file target,
/// `"shared.rs"` → `("shared.rs", None)`.
///
/// Splits on the FIRST [`TARGET_SEP`]: a garden path is lowercase ASCII with no
/// spaces (house rule), so it never contains `" §"`, making first-split the exact
/// inverse even when the heading itself contains the separator. A key that is not
/// a garden target at all (e.g. a `restart:` lease key) simply parses to a
/// `(key, None)` target that keeperd has never flagged — the clear is then a
/// harmless no-op, so this stays free of any key-namespace policy.
pub fn parse_target(key: &str) -> (String, Option<String>) {
    match key.split_once(TARGET_SEP) {
        Some((path, heading)) => (path.to_string(), Some(heading.to_string())),
        None => (key.to_string(), None),
    }
}

/// The keeperd-facing clear seam: clear keeperd's thrash lease-flag on the parsed
/// `(path, heading)` target, returning whether a flag was actually present.
///
/// **Deferred / default-absent**, mirroring [`crate::notify_dispatch::BusEmit`]:
/// the live impl is a growlightd→keeperd *write*, but the bus bridge is one-way
/// (growlightd pulls; no clear-flag write verb exists yet, a
/// `growlight-wire-loose-ends` concern). So production binds nothing here today;
/// the bridge is proven against a fake. `Send + Sync + Debug` because the daemon
/// shares the [`ThrashClear`] across connection threads via an `Arc`.
pub trait TargetClear: Send + Sync + fmt::Debug {
    /// Clear any thrash lease-flag keeper raised on `(path, heading)`. Returns
    /// whether a flag was present (so the daemon can log a real resolution vs a
    /// no-op).
    fn clear(&self, path: &str, heading: Option<&str>) -> bool;
}

/// The §4d rung-2 bridge: a [`ThrashClear`] that translates the lease table's
/// opaque key into keeperd's `(path, heading)` target ([`parse_target`]) and
/// delegates the clear to a [`TargetClear`]. This is the THIN binding the daemon's
/// `request_lease` calls on a `Granted` lease — the proven pure cores (the lease
/// table, keeperd's detector) stay untouched; this only bridges them.
///
/// The live install is deferred with the [`TargetClear`] transport: until a
/// growlightd→keeperd clear-flag write verb exists, `Daemon::with_thrash_clear`
/// stays unbound in production (`thrash_clear: None`, a no-op grant). When the
/// verb lands (`growlight-wire-loose-ends`), `main` constructs
/// `KeeperThrashClear::new(Box::new(<live TargetClear>))` and installs it.
#[derive(Debug)]
pub struct KeeperThrashClear {
    clearer: Box<dyn TargetClear>,
}

impl KeeperThrashClear {
    pub fn new(clearer: Box<dyn TargetClear>) -> Self {
        Self { clearer }
    }
}

impl ThrashClear for KeeperThrashClear {
    fn clear_flag(&self, key: &str) -> bool {
        let (path, heading) = parse_target(key);
        self.clearer.clear(&path, heading.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GrowlightdConfig;
    use crate::daemon::Daemon;
    use std::sync::{Arc, Mutex};

    /// A recording [`TargetClear`]: captures each parsed `(path, heading)` it was
    /// asked to clear, standing in for the deferred live keeperd write. Reports a
    /// flag was present so a granted lease sees a "real" resolution.
    #[derive(Debug, Default)]
    struct FakeClear {
        cleared: Mutex<Vec<(String, Option<String>)>>,
    }
    impl FakeClear {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn cleared(&self) -> Vec<(String, Option<String>)> {
            self.cleared.lock().unwrap().clone()
        }
    }
    impl TargetClear for Arc<FakeClear> {
        fn clear(&self, path: &str, heading: Option<&str>) -> bool {
            self.cleared
                .lock()
                .unwrap()
                .push((path.to_string(), heading.map(str::to_string)));
            true
        }
    }

    #[test]
    fn parse_target_splits_a_section_key_into_path_and_heading() {
        assert_eq!(
            parse_target("dock.rs §Layout"),
            ("dock.rs".to_string(), Some("Layout".to_string()))
        );
    }

    #[test]
    fn parse_target_treats_a_separatorless_key_as_a_whole_file_target() {
        assert_eq!(parse_target("shared.rs"), ("shared.rs".to_string(), None));
    }

    /// keeperd builds the label as `"{path} §{heading}"`; parsing it back yields
    /// the original tuple — the round-trip the live keeperd clear depends on.
    #[test]
    fn parse_target_is_the_inverse_of_the_label_format() {
        for (path, heading) in [
            ("notes/dock.md", Some("Layout §details")), // heading itself contains the sep
            ("a/b/c.rs", Some("fn run")),
            ("whole-file.md", None),
        ] {
            let key = match heading {
                Some(h) => format!("{path} §{h}"),
                None => path.to_string(),
            };
            assert_eq!(
                parse_target(&key),
                (path.to_string(), heading.map(str::to_string)),
                "round-trip for {key:?}",
            );
        }
    }

    #[test]
    fn the_bridge_parses_the_key_and_delegates_to_the_target_clearer() {
        let fake = FakeClear::new();
        let bridge = KeeperThrashClear::new(Box::new(Arc::clone(&fake)));

        assert!(bridge.clear_flag("doc.md §Layout"), "the fake reports a flag");
        assert!(bridge.clear_flag("whole.rs"));
        assert_eq!(
            fake.cleared(),
            vec![
                ("doc.md".to_string(), Some("Layout".to_string())),
                ("whole.rs".to_string(), None),
            ],
        );
    }

    /// End-to-end through the real daemon grant path: a granted lease over a
    /// contended target drives the bridge, which clears the PARSED keeperd target;
    /// a queued (non-granted) lease over the same target clears nothing new — the
    /// §4d rung-2 binding, proven over the live `request_lease`.
    #[test]
    fn a_granted_lease_clears_the_parsed_target_a_queued_one_does_not() {
        let fake = FakeClear::new();
        let bridge = KeeperThrashClear::new(Box::new(Arc::clone(&fake)));
        let daemon = Daemon::new(GrowlightdConfig::new("/run/g.sock".into(), "/garden".into()))
            .with_thrash_clear(Arc::new(bridge));

        // Grant → the bridge fires, clearing the parsed (path, heading) target.
        let granted = daemon.request_lease("a", "doc.md §Layout");
        assert_eq!(granted.state, "granted");
        assert_eq!(
            fake.cleared(),
            vec![("doc.md".to_string(), Some("Layout".to_string()))],
        );

        // A second agent is queued, NOT granted → no further clear.
        let queued = daemon.request_lease("b", "doc.md §Layout");
        assert_eq!(queued.state, "waiting");
        assert_eq!(fake.cleared().len(), 1, "a queued request clears nothing new");
    }
}
