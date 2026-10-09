//! Shared-chain membership health — the latch that makes a membership split
//! converge, stay quiet, and stay visible (task 059).
//!
//! # The bug this exists for
//!
//! Two ring devices can hold opposite views of who is an S-member of a shared
//! chain, and before this module nothing in the protocol resolved it. The
//! pushing side re-derived its targets from its own membership every reconcile
//! tick (~50s) and pushed forever; the rejecting side logged one line per push,
//! unconditionally, forever. Live on this device that ran **12,854 identical
//! lines over 27 days** with neither side learning anything and no surface
//! outside the journal saying a share had stopped syncing.
//!
//! Three separable defects, and this module is the state all three needed:
//!
//! 1. **No convergence.** A rejection was a log line on the *receiver*; the
//!    sender saw a clean session close, indistinguishable from success. The wire
//!    half of the fix is the `ChainRejected` frame (`control.proto` 209); the
//!    sender's half is [`ChainHealth::pushes_suppressed`], which takes the
//!    rejected chain+peer out of the per-tick fan-out.
//! 2. **Unbounded identical logging.** [`ChainHealth::observe`] is
//!    edge-triggered: it returns a journal line on a class *transition* and then
//!    at most one summary per [`SUMMARY_INTERVAL_SECS`]. N consecutive
//!    rejections inside one window cost one line, not N.
//! 3. **No health surface.** [`ChainHealth::divergences`] is the read model the
//!    CLI + TUI render, so "this chain has been rejecting a peer for a month" is
//!    answerable without reading journald.
//!
//! # Why this one is in-memory when task 058's replica health is on disk
//!
//! A deliberate difference, not an oversight. `replica_health`'s state is a
//! *staleness judgement* ("nobody has mirrored this chain in three weeks"),
//! which is unobservable after a restart unless it was persisted — the absence
//! of a push is not an event. A membership split is the opposite: the condition
//! re-announces itself within one reconcile tick, so in-memory state is
//! reconstructed in ~50s and can never show a fossil. That buys three things on
//! a device where [[feedback_prefer_in_memory_over_disk]] applies for eMMC wear:
//! zero disk writes on the hot path (the alternative wrote a file 1,728 times a
//! day), no stale rows after the human fixes membership, and a free re-probe on
//! every restart.
//!
//! The one accepted trade: counts and outage ages restart from zero on a daemon
//! restart, and each restart re-announces the transition once. That is a feature
//! for a condition that is still broken — one line per restart, versus 12,854.

use std::collections::HashMap;

use softfig_net::ChainRejectReason;

/// How long a latched class stays quiet before `observe` emits one summary line.
/// An hour turns the live 059 case from ~1,728 journal lines a day into 24, and
/// keeps a long split narrated often enough that `journalctl --since` over any
/// plausible window still shows it.
pub const SUMMARY_INTERVAL_SECS: i64 = 3600;

/// How long the sender holds off re-pushing a chain a peer said it is not a
/// member of. Not `forever`: the fix usually lands on the *other* device (a
/// ceremony, or a `shared-subtree remove`), which this device cannot observe, so
/// a permanent stop would convert a fixed share into a silent outage of our own
/// making. One push an hour is 1/72nd of the flood and still converges on its
/// own within an hour of the human's fix.
pub const REPROBE_INTERVAL_SECS: i64 = 3600;

/// Which side of the disagreement a row describes. The two are tracked
/// separately because they have different fixes and can be true at once (each
/// device refusing the other), and because only the outbound one gates pushes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// We refused a peer's push: *they* think we are a member; we hold no row.
    /// The fix is on their side (`shared-subtree remove`, or a ceremony here).
    Inbound,
    /// A peer refused our push: *we* think they are a member; they hold no row.
    /// The fix is on our side, and this is the role that suppresses pushing.
    Outbound,
}

impl Role {
    /// A stable slug for the wire, the CLI and the TUI.
    pub fn slug(self) -> &'static str {
        match self {
            Role::Inbound => "inbound",
            Role::Outbound => "outbound",
        }
    }

    pub fn verb(self) -> &'static str {
        match self {
            Role::Inbound => "rejecting pushes from",
            Role::Outbound => "being rejected by",
        }
    }
}

/// The health class of one (role, chain, peer) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The last observation was a healthy push in this direction. Recorded so a
    /// recovery is an edge the journal reports, not just an absence.
    Ok,
    /// The last observation was a refusal, with the reason the wire carried.
    Rejected(ChainRejectReason),
}

impl Class {
    /// A stable slug for the journal line, the CLI and the TUI.
    pub fn slug(self) -> String {
        match self {
            Class::Ok => "ok".to_string(),
            Class::Rejected(r) => r.slug(),
        }
    }

    /// Whether this class means "stop pushing and ask a human" rather than
    /// "retry". Only the two membership verdicts qualify — see
    /// [`ChainRejectReason::is_terminal_for_sender`].
    pub fn is_terminal(self) -> bool {
        match self {
            Class::Ok => false,
            Class::Rejected(r) => r.is_terminal_for_sender(),
        }
    }
}

/// One latched row. `since` is the start of the *current class*, so an age
/// rendered from it is the length of this outage, not the row's lifetime.
#[derive(Debug, Clone)]
struct Row {
    class: Class,
    since: i64,
    last_seen: i64,
    /// Observations in the current class, including the one that opened it.
    count: u64,
    /// When a line was last emitted for this row (transition or summary).
    last_spoke: i64,
}

/// A read-model row for the health surface: one membership divergence, rendered
/// by `softfig shared-subtree list` and the TUI's shares view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    pub role: Role,
    pub chain: String,
    pub peer: [u8; 32],
    pub class: Class,
    /// Unix seconds the current class began.
    pub since: i64,
    /// How long the current class has held, at the time `divergences` was called.
    pub age_secs: i64,
    /// Observations in the current class.
    pub count: u64,
}

/// The per-daemon latch. Lives in `DaemonInner` beside the other in-memory
/// coordination state (`write_turns`, `ceremonies_in_flight`) and is cleared on
/// lock with them.
#[derive(Debug, Default)]
pub struct ChainHealth {
    rows: HashMap<(Role, String, [u8; 32]), Row>,
}

impl ChainHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observation and return the journal line to print, if any.
    ///
    /// Edge-triggered, which is the whole point: a line comes back only when the
    /// class *changes* or when [`SUMMARY_INTERVAL_SECS`] has passed since this
    /// row last spoke. The first healthy observation of a row is deliberately
    /// silent — a working push is not news — but a recovery *from* a rejection
    /// is reported, because somebody was told it was broken.
    pub fn observe(
        &mut self,
        role: Role,
        chain: &str,
        peer: [u8; 32],
        class: Class,
        now: i64,
    ) -> Option<String> {
        let key = (role, chain.to_string(), peer);
        match self.rows.get_mut(&key) {
            None => {
                self.rows.insert(
                    key,
                    Row {
                        class,
                        since: now,
                        last_seen: now,
                        count: 1,
                        last_spoke: now,
                    },
                );
                match class {
                    // Nothing was ever claimed to be wrong; stay quiet.
                    Class::Ok => None,
                    Class::Rejected(_) => Some(Self::transition_line(role, chain, &peer, class)),
                }
            }
            Some(row) => {
                row.last_seen = now;
                if row.class != class {
                    let previous = row.class;
                    row.class = class;
                    row.since = now;
                    row.count = 1;
                    row.last_spoke = now;
                    return Some(match (previous, class) {
                        (Class::Rejected(_), Class::Ok) => format!(
                            "keeperd: net: shared-chain {chain}: {} {} RECOVERED (was {})",
                            role.verb(),
                            short(&peer),
                            previous.slug(),
                        ),
                        _ => Self::transition_line(role, chain, &peer, class),
                    });
                }
                row.count = row.count.saturating_add(1);
                if now.saturating_sub(row.last_spoke) < SUMMARY_INTERVAL_SECS {
                    return None; // the latch: identical observation, already said
                }
                row.last_spoke = now;
                // An `Ok` row that keeps being Ok says nothing, however long.
                let Class::Rejected(reason) = class else {
                    return None;
                };
                Some(format!(
                    "keeperd: net: shared-chain {chain}: still {} {} ({reason}) — \
                     {} occurrences over {}, unresolved; run `softfig shared-subtree list`",
                    role.verb(),
                    short(&peer),
                    row.count,
                    human_secs(now.saturating_sub(row.since)),
                ))
            }
        }
    }

    fn transition_line(role: Role, chain: &str, peer: &[u8; 32], class: Class) -> String {
        match class {
            Class::Ok => format!(
                "keeperd: net: shared-chain {chain}: {} {} is healthy",
                role.verb(),
                short(peer)
            ),
            Class::Rejected(reason) => match role {
                Role::Inbound => format!(
                    "keeperd: net: shared-chain-push for {chain} from {} refused: {reason}. \
                     Membership disagreement — the peer believes this device is a member. \
                     Further identical rejections are summarized hourly, not logged per push.",
                    short(peer)
                ),
                Role::Outbound => format!(
                    "keeperd: net: shared-chain {chain}: {} refused our push: {reason}. \
                     Pausing pushes of this chain to that peer (re-probing hourly) — \
                     membership here is NOT changed; resolve with `softfig shared-subtree list`.",
                    short(peer)
                ),
            },
        }
    }

    /// Whether the outbound fan-out should skip `(chain, peer)` this tick.
    ///
    /// True only while a *terminal* outbound rejection is latched and the
    /// [`REPROBE_INTERVAL_SECS`] window has not elapsed since the peer last told
    /// us. A transient reason (`NotReady`, or one this build cannot parse) never
    /// suppresses anything — mistaking a brief lock window for a membership
    /// verdict would be the same bug with the sign flipped.
    pub fn pushes_suppressed(&self, chain: &str, peer: &[u8; 32], now: i64) -> bool {
        let Some(row) = self.rows.get(&(Role::Outbound, chain.to_string(), *peer)) else {
            return false;
        };
        row.class.is_terminal() && now.saturating_sub(row.last_seen) < REPROBE_INTERVAL_SECS
    }

    /// Every currently-latched disagreement, newest class first, for the health
    /// surface. `Ok` rows are omitted: this answers "what is wrong", and a
    /// healthy chain is already listed by `shared-subtree list` itself.
    pub fn divergences(&self, now: i64) -> Vec<Divergence> {
        let mut out: Vec<Divergence> = self
            .rows
            .iter()
            .filter(|(_, row)| row.class != Class::Ok)
            .map(|((role, chain, peer), row)| Divergence {
                role: *role,
                chain: chain.clone(),
                peer: *peer,
                class: row.class,
                since: row.since,
                age_secs: now.saturating_sub(row.since),
                count: row.count,
            })
            .collect();
        // Stable, human-useful order: chain, then role, then peer.
        out.sort_by(|a, b| {
            a.chain
                .cmp(&b.chain)
                .then_with(|| a.role.verb().cmp(b.role.verb()))
                .then_with(|| a.peer.cmp(&b.peer))
        });
        out
    }

    /// Drop every row for `chain` — called when this device's membership for it
    /// changes (an accepted offer, a completed ceremony, a `shared-subtree
    /// remove`). The premise of a latched verdict is that nothing changed; once
    /// our own membership moves, the next push must be tried for real rather
    /// than suppressed by a verdict about the old state.
    pub fn forget_chain(&mut self, chain: &str) {
        self.rows.retain(|(_, c, _), _| c != chain);
    }

    /// Drop everything (soft lock / shutdown), beside `write_turns.clear()`.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Row count, for tests and the status surface.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// First 8 hex chars of a device id — the same abbreviation the pairing + ring
/// surfaces use, so a journal line and `softfig peers` name a device the same way.
fn short(device_id: &[u8; 32]) -> String {
    hex::encode(&device_id[..4])
}

/// Render a divergence age for the journal, sharing the one renderer the CLI and
/// TUI use ([`softfig_ipc::verbs::human_age_secs`]) so a split's length reads the
/// same everywhere. Takes `i64` because `since` arithmetic is signed; a clock
/// that went backwards reads as `0s` rather than wrapping to a century.
pub fn human_secs(secs: i64) -> String {
    softfig_ipc::verbs::human_age_secs(secs.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(b: u8) -> [u8; 32] {
        [b; 32]
    }

    const NOT_MEMBER: Class = Class::Rejected(ChainRejectReason::NotAMember);
    const UNKNOWN: Class = Class::Rejected(ChainRejectReason::UnknownChain);
    const NOT_READY: Class = Class::Rejected(ChainRejectReason::NotReady);

    /// The headline regression: the live bug was 12,854 lines for one condition.
    /// 1,800 pushes at the observed ~50s cadence (25 hours) must cost the
    /// transition plus one summary per hour — O(1) per unit time, not O(N).
    #[test]
    fn n_consecutive_rejections_are_o1_lines() {
        let mut h = ChainHealth::new();
        let mut lines = 0;
        for i in 0..1_800 {
            let now = i as i64 * 50;
            if h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, now)
                .is_some()
            {
                lines += 1;
            }
        }
        // 1,800 pushes span 89,950s ≈ 24.99h, so: 1 transition + 24 hourly
        // summaries = 25 lines for 1,800 identical refusals. The pre-059 code
        // emitted 1,800 — which is how 27 days reached 12,854.
        assert_eq!(lines, 25, "expected transition + hourly summaries");
        assert_eq!(h.len(), 1, "one condition is one row");
    }

    #[test]
    fn transition_speaks_once_then_latches_within_the_window() {
        let mut h = ChainHealth::new();
        let first = h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 0);
        assert!(first.is_some());
        for t in (50..SUMMARY_INTERVAL_SECS).step_by(50) {
            assert!(
                h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, t)
                    .is_none(),
                "latched row spoke again at t={t}"
            );
        }
        assert!(
            h.observe(
                Role::Inbound,
                "chain/personal",
                peer(1),
                UNKNOWN,
                SUMMARY_INTERVAL_SECS
            )
            .is_some(),
            "the hourly summary must still arrive"
        );
    }

    #[test]
    fn summary_reports_the_real_count_and_age() {
        let mut h = ChainHealth::new();
        for i in 0..72 {
            h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, i * 50);
        }
        let line = h
            .observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 3_600)
            .expect("summary at the window edge");
        assert!(line.contains("73 occurrences"), "line was: {line}");
        assert!(line.contains("1h"), "line was: {line}");
    }

    /// A class change is news even inside the quiet window — the reason is the
    /// actionable part, so `not-ready` turning into `not-a-member` must be said.
    #[test]
    fn a_changed_reason_speaks_immediately() {
        let mut h = ChainHealth::new();
        assert!(h
            .observe(Role::Outbound, "chain/personal", peer(1), NOT_READY, 0)
            .is_some());
        let line = h
            .observe(Role::Outbound, "chain/personal", peer(1), NOT_MEMBER, 10)
            .expect("a changed class speaks");
        assert!(line.contains("not an S-member"), "line was: {line}");
    }

    #[test]
    fn recovery_is_reported_but_a_first_healthy_push_is_quiet() {
        let mut h = ChainHealth::new();
        assert!(
            h.observe(Role::Outbound, "chain/work", peer(2), Class::Ok, 0)
                .is_none(),
            "a working push is not news"
        );
        h.observe(Role::Outbound, "chain/personal", peer(1), NOT_MEMBER, 0);
        let line = h
            .observe(Role::Outbound, "chain/personal", peer(1), Class::Ok, 500)
            .expect("a recovery speaks");
        assert!(line.contains("RECOVERED"), "line was: {line}");
    }

    #[test]
    fn healthy_rows_never_produce_summaries() {
        let mut h = ChainHealth::new();
        for i in 0..200 {
            assert!(h
                .observe(Role::Outbound, "chain/work", peer(2), Class::Ok, i * 50)
                .is_none());
        }
    }

    /// The two directions, and two peers in one direction, are distinct
    /// conditions — collapsing them would hide the second one.
    #[test]
    fn role_chain_and_peer_are_all_part_of_the_identity() {
        let mut h = ChainHealth::new();
        assert!(h
            .observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 0)
            .is_some());
        assert!(h
            .observe(Role::Outbound, "chain/personal", peer(1), NOT_MEMBER, 0)
            .is_some());
        assert!(h
            .observe(Role::Inbound, "chain/personal", peer(2), UNKNOWN, 0)
            .is_some());
        assert!(h
            .observe(Role::Inbound, "chain/other", peer(1), UNKNOWN, 0)
            .is_some());
        assert_eq!(h.len(), 4);
    }

    #[test]
    fn terminal_outbound_rejection_suppresses_pushes_for_an_hour_then_reprobes() {
        let mut h = ChainHealth::new();
        h.observe(Role::Outbound, "chain/personal", peer(1), NOT_MEMBER, 0);
        assert!(h.pushes_suppressed("chain/personal", &peer(1), 50));
        assert!(h.pushes_suppressed(
            "chain/personal",
            &peer(1),
            REPROBE_INTERVAL_SECS - 1
        ));
        assert!(
            !h.pushes_suppressed("chain/personal", &peer(1), REPROBE_INTERVAL_SECS),
            "a re-probe must be allowed through once the window passes"
        );
    }

    #[test]
    fn a_transient_or_unknown_reason_never_suppresses() {
        let mut h = ChainHealth::new();
        h.observe(Role::Outbound, "chain/personal", peer(1), NOT_READY, 0);
        assert!(!h.pushes_suppressed("chain/personal", &peer(1), 50));
        h.observe(
            Role::Outbound,
            "chain/other",
            peer(1),
            Class::Rejected(ChainRejectReason::Other(99)),
            0,
        );
        assert!(!h.pushes_suppressed("chain/other", &peer(1), 50));
    }

    /// Suppression is per (chain, peer) — never a whole-chain or whole-peer stop.
    #[test]
    fn suppression_does_not_leak_across_chains_or_peers() {
        let mut h = ChainHealth::new();
        h.observe(Role::Outbound, "chain/personal", peer(1), NOT_MEMBER, 0);
        assert!(!h.pushes_suppressed("chain/personal", &peer(2), 50));
        assert!(!h.pushes_suppressed("chain/work", &peer(1), 50));
    }

    /// An INBOUND rejection must not stop us pushing to that peer: "you are not
    /// a member here" and "I am not a member there" are different claims, and
    /// conflating them would let one peer's refusal cut our own sync.
    #[test]
    fn inbound_rejections_do_not_suppress_our_pushes() {
        let mut h = ChainHealth::new();
        h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 0);
        assert!(!h.pushes_suppressed("chain/personal", &peer(1), 50));
    }

    #[test]
    fn recovery_clears_suppression_immediately() {
        let mut h = ChainHealth::new();
        h.observe(Role::Outbound, "chain/personal", peer(1), NOT_MEMBER, 0);
        h.observe(Role::Outbound, "chain/personal", peer(1), Class::Ok, 100);
        assert!(!h.pushes_suppressed("chain/personal", &peer(1), 150));
    }

    #[test]
    fn forget_chain_drops_the_verdict_so_a_membership_change_is_retried() {
        let mut h = ChainHealth::new();
        h.observe(Role::Outbound, "chain/personal", peer(1), NOT_MEMBER, 0);
        h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 0);
        h.observe(Role::Outbound, "chain/work", peer(1), NOT_MEMBER, 0);
        h.forget_chain("chain/personal");
        assert!(!h.pushes_suppressed("chain/personal", &peer(1), 50));
        assert!(
            h.pushes_suppressed("chain/work", &peer(1), 50),
            "an unrelated chain's verdict survives"
        );
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn divergences_lists_only_problems_with_a_real_age() {
        let mut h = ChainHealth::new();
        h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 0);
        h.observe(Role::Outbound, "chain/work", peer(2), Class::Ok, 0);
        for i in 1..100 {
            h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, i * 50);
        }
        let d = h.divergences(5_000);
        assert_eq!(d.len(), 1, "healthy rows are not divergences");
        assert_eq!(d[0].chain, "chain/personal");
        assert_eq!(d[0].role, Role::Inbound);
        assert_eq!(d[0].class, UNKNOWN);
        assert_eq!(d[0].count, 100);
        assert_eq!(d[0].age_secs, 5_000);
    }

    /// The age must be the length of the CURRENT outage, not of the row — a
    /// chain that broke, recovered and broke again is not a 27-day outage.
    #[test]
    fn age_is_measured_from_the_current_class_not_the_row() {
        let mut h = ChainHealth::new();
        h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 0);
        h.observe(Role::Inbound, "chain/personal", peer(1), Class::Ok, 10_000);
        h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 20_000);
        let d = h.divergences(20_100);
        assert_eq!(d[0].age_secs, 100);
        assert_eq!(d[0].count, 1);
    }

    #[test]
    fn divergence_order_is_stable() {
        let mut h = ChainHealth::new();
        h.observe(Role::Outbound, "chain/work", peer(9), NOT_MEMBER, 0);
        h.observe(Role::Inbound, "chain/personal", peer(2), UNKNOWN, 0);
        h.observe(Role::Outbound, "chain/personal", peer(1), NOT_MEMBER, 0);
        let names: Vec<(String, Role)> = h
            .divergences(1)
            .into_iter()
            .map(|d| (d.chain, d.role))
            .collect();
        assert_eq!(
            names,
            vec![
                ("chain/personal".to_string(), Role::Outbound),
                ("chain/personal".to_string(), Role::Inbound),
                ("chain/work".to_string(), Role::Outbound),
            ]
        );
    }

    #[test]
    fn clear_empties_the_latch() {
        let mut h = ChainHealth::new();
        h.observe(Role::Inbound, "chain/personal", peer(1), UNKNOWN, 0);
        assert!(!h.is_empty());
        h.clear();
        assert!(h.is_empty());
        assert!(h.divergences(0).is_empty());
    }

    /// The journal line a human actually has to act on must name the chain, the
    /// peer, the reason, and that local membership was left alone.
    #[test]
    fn the_outbound_transition_line_is_actionable() {
        let mut h = ChainHealth::new();
        let line = h
            .observe(Role::Outbound, "chain/personal", peer(0xab), NOT_MEMBER, 0)
            .unwrap();
        assert!(line.contains("chain/personal"));
        assert!(line.contains("abababab"));
        assert!(line.contains("not an S-member"));
        assert!(line.contains("membership here is NOT changed"));
        assert!(line.contains("shared-subtree list"));
    }

    #[test]
    fn human_secs_reads_as_prose() {
        assert_eq!(human_secs(-5), "0s");
        assert_eq!(human_secs(45), "45s");
        assert_eq!(human_secs(90), "1m");
        assert_eq!(human_secs(3_600), "1h");
        // Delegates to the shared ladder, which carries on into weeks — the live
        // 27-day split reads as "3w" here, in `shared-subtree list` and in the
        // TUI alike.
        assert_eq!(human_secs(27 * 86_400), "3w");
    }
}
