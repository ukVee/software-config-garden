//! The fleet scheduler's **selection policy** (phase 4, slice 002): given a
//! snapshot of every queue's drainable state, pick the next `(queue, part)` for
//! an agent — **pinned-with-fallback**, which is what realizes **pivot-on-block**
//! (spec-growlight-orchestrator §6).
//!
//! ## What this is (and isn't)
//!
//! This is a **pure function** over a value snapshot — [`pick`]`(snapshot, pin)` —
//! with no I/O, no live fleet, no keeperd socket. That is deliberate (the
//! theory-code proof obligation): the policy is the hard part and it is provable in
//! isolation against fake queues. The live wiring — populating a [`Snapshot`] from
//! keeperd's per-queue managed regions (the `queue` / `queue:<name>` item tables
//! slice 001 shipped) and feeding the pick to a real agent at a handoff boundary —
//! is the drive loop's job (phase 6) and rides the same
//! growlightd-pulls-from-keeperd seam the bus bridge already uses ([`crate::bus`]).
//! Keeping selection pure keeps it testable and keeps this slice additive.
//!
//! ## The policy
//!
//! - **A *part* is a queue item** (slice 001: a part = a row in a named queue). The
//!   scheduler's unit of assignment is therefore `(queue-name, part-id)`.
//! - **Pinned-with-fallback.** An agent prefers its own (pinned) queue; it pulls
//!   from another only when its own yields no workable part.
//! - **Pivot-on-block.** A `blocked` (BLOCKED_ON_HUMAN) item at the head of a queue
//!   does NOT halt the fleet: the queue *parks* (its head is surfaced to the §9
//!   alert hook, [`parked`]) and the agent **pivots** to another queue.
//! - **Intra-queue order is honored.** Within a queue the next part is the first
//!   workable row in queue (row) order: `done`/`deferred` rows are rolled past (a
//!   `deferred` item waits for the human and never re-enters the loop, protocol
//!   §7b), and a `blocked` row is head-of-line — it parks the queue rather than
//!   letting a later row jump an intra-queue ordering dependency.
//! - **No cross-queue starvation.** Fallback only takes an *unclaimed* queue (a
//!   `queued` head, never an `active` one). Because keeperd enforces single-active
//!   *per queue* (slice 001), a queue an agent is already draining shows an
//!   `active` head and is skipped by every other agent's fallback — so free agents
//!   flow to distinct unclaimed queues instead of piling onto one.
//! - **Human-only items are never claimed** (task 068). A `queued` part carrying a
//!   [`ClaimHold`] — its item doc declares `> Fleet: no` — is rolled past like a
//!   `deferred` one, by the pinned pick and by fallback alike. It stays `queued`
//!   (it is the human's, not blocked), so nothing parks and nothing pages; the
//!   loop lists it via [`held`] so the skip is journaled and shown in `status`.
//! - **A pinned queue is its pinned member's first** (task 068). Fallback skips a
//!   queue another member still [`reserved`](pick_for) — pinned to it and free to
//!   take its next part, or still draining it — so a drained member cannot take
//!   the next part out from under the member whose work-stream it is.

use std::collections::BTreeSet;

/// A backlog item's status, as the scheduler classifies it. Mirrors the status
/// vocabulary keeperd writes into the queue tables (`queued`/`active`/`done`/
/// `deferred`/`blocked`); any unrecognized string maps to [`PartStatus::Other`]
/// and is treated as non-workable (the scheduler never assigns a status it does
/// not understand).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartStatus {
    /// In progress / claimed by the agent draining this queue (single-active per
    /// queue). The pinned agent resumes it; any other agent's fallback skips it.
    Active,
    /// Ready to start, unclaimed. Workable by the pinned agent and by fallback.
    Queued,
    /// BLOCKED_ON_HUMAN — head-of-line. Parks the queue and triggers a pivot.
    Blocked,
    /// Parked for the human, rolled past by the loop and never re-entered
    /// (protocol §7b). Not workable; not a block.
    Deferred,
    /// Finished. Not workable.
    Done,
    /// An unrecognized status — treated as non-workable, conservatively rolled
    /// past (never assigned).
    Other,
}

impl PartStatus {
    /// Classify a raw status cell from a keeperd queue table.
    pub fn parse(status: &str) -> Self {
        match status {
            "active" => Self::Active,
            "queued" => Self::Queued,
            "blocked" => Self::Blocked,
            "deferred" => Self::Deferred,
            "done" => Self::Done,
            _ => Self::Other,
        }
    }
}

/// Why the fleet must not claim a `queued` part (task 068). Read from the item's
/// own doc, not its status: the part stays `queued` — it is waiting for the human,
/// not blocked — so a hold parks nothing and pages no one; [`classify_queue`]
/// just rolls past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimHold {
    /// The item doc declares `> Fleet: <value>` with any value but `yes` — the
    /// declared value is carried for the journal. Removing the line (or writing
    /// `yes`) makes the item claimable again.
    HumanOnly(String),
    /// The item doc could not be read, so the marker is unknown — fail-closed
    /// for this pass rather than risk claiming human-only work. Carries the error.
    Unreadable(String),
}

impl ClaimHold {
    /// The one-line skip reason the journal and `growlight status` show.
    pub fn reason(&self) -> String {
        match self {
            Self::HumanOnly(value) => format!("human-only (> Fleet: {value})"),
            Self::Unreadable(error) => format!("fleet marker unreadable: {error}"),
        }
    }
}

/// One assignable part — a row in a queue. The scheduler needs the id (what it
/// returns), the status (how it classifies), and any [`ClaimHold`] the item doc
/// declares; title/type are carried by the item docs, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartView {
    pub id: String,
    pub status: PartStatus,
    /// Set on a part the fleet must not claim. Only a `queued` part is ever held:
    /// an `active` part is someone's work already, and is never parked by it.
    pub hold: Option<ClaimHold>,
}

impl PartView {
    /// Convenience constructor from a raw `(id, status-string)` pair, the shape a
    /// keeperd queue row reduces to. No hold — the queue table does not carry one.
    pub fn new(id: impl Into<String>, status: &str) -> Self {
        Self {
            id: id.into(),
            status: PartStatus::parse(status),
            hold: None,
        }
    }

    /// Whether the fleet may start this part: `queued` with no hold.
    fn claimable(&self) -> bool {
        self.status == PartStatus::Queued && self.hold.is_none()
    }
}

/// One queue in the snapshot: a name and its parts **in queue (row) order**. The
/// scheduler relies on that order — intra-queue ordering dependencies are honored
/// by it (slice 001 / spec §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueView {
    pub name: String,
    pub parts: Vec<PartView>,
}

impl QueueView {
    pub fn new(name: impl Into<String>, parts: Vec<PartView>) -> Self {
        Self {
            name: name.into(),
            parts,
        }
    }
}

/// A point-in-time view of every queue the fleet can draw from, in registry
/// order (the default queue first, then named queues as keeperd lists them). The
/// Vec order is the deterministic fallback order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub queues: Vec<QueueView>,
}

impl Snapshot {
    pub fn new(queues: Vec<QueueView>) -> Self {
        Self { queues }
    }

    /// The queue with this name, if present.
    pub fn queue(&self, name: &str) -> Option<&QueueView> {
        self.queues.iter().find(|q| q.name == name)
    }

    /// Stamp `part` in `queue` as [`PartStatus::Active`] — the intra-tick claim
    /// mark the drive loop applies to its *working copy* of the snapshot the
    /// instant a part-claim succeeds, so a later member's [`pick`] in the SAME
    /// tick sees the part already claimed: a fallback agent flows past the now
    /// `active` head, and the queue is reduced to one claimed part. The
    /// point-in-time snapshot alone cannot prevent two idle agents from both
    /// resolving to the same `Ready` head within a tick (the fallback
    /// double-assignment window); this closes the intra-tick half. The
    /// cross-tick half is keeperd's committed `active` write (the claim itself),
    /// surfaced by the next [`QueueSource::snapshot`](crate::drive_loop::QueueSource::snapshot).
    /// A no-op when the queue or part is absent.
    pub fn mark_claimed(&mut self, queue: &str, part: &str) {
        if let Some(q) = self.queues.iter_mut().find(|q| q.name == queue) {
            if let Some(p) = q.parts.iter_mut().find(|p| p.id == part) {
                p.status = PartStatus::Active;
            }
        }
    }

    /// Stamp `part` in `queue` as [`PartStatus::Blocked`] — the intra-tick
    /// **item-park** mark the drive loop applies to its *working copy* the instant a
    /// member exits `BLOCKED_ON_HUMAN` / `STUCK`, the sibling of [`mark_claimed`].
    /// Recording the block on the working snapshot makes BOTH this tick's
    /// parked-head alert ([`parked`]) AND the freed member's [`pick`] see it
    /// immediately: the member pivots past its own now-blocked part to other
    /// workable work this same tick (pivot-on-block), without waiting for the next
    /// snapshot. The cross-tick half is keeperd's committed `blocked` write (the
    /// item-park itself), surfaced by the next
    /// [`QueueSource::snapshot`](crate::drive_loop::QueueSource::snapshot) — exactly
    /// the read/write split [`mark_claimed`] uses for claims. A no-op when the queue
    /// or part is absent.
    pub fn mark_blocked(&mut self, queue: &str, part: &str) {
        if let Some(q) = self.queues.iter_mut().find(|q| q.name == queue) {
            if let Some(p) = q.parts.iter_mut().find(|p| p.id == part) {
                p.status = PartStatus::Blocked;
            }
        }
    }

    /// Put a [`ClaimHold`] on a `queued` `part` in `queue` — the intra-tick mark
    /// for a hold found by the claim-time marker re-read, so a later member's
    /// [`pick`] in the SAME tick rolls past it too. A no-op when the queue or part
    /// is absent, or the part is not `queued` (an `active` part is never held).
    pub fn mark_held(&mut self, queue: &str, part: &str, hold: ClaimHold) {
        if let Some(q) = self.queues.iter_mut().find(|q| q.name == queue) {
            if let Some(p) = q.parts.iter_mut().find(|p| p.id == part) {
                if p.status == PartStatus::Queued {
                    p.hold = Some(hold);
                }
            }
        }
    }
}

/// A queue's drainable state, reduced to its head workable part. Produced by
/// [`classify_queue`]: scan the rows in order and stop at the first that is not
/// rolled past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueState {
    /// Head workable part is `active` — in progress / claimed by its agent. The
    /// pinned agent resumes it; a *fallback* agent treats the queue as taken.
    Active(String),
    /// Head workable part is `queued` — unclaimed, ready to start. Available to
    /// the pinned agent and to fallback.
    Ready(String),
    /// Head workable part is `blocked` (BLOCKED_ON_HUMAN) — the queue parks and
    /// triggers a pivot. Carries the parked part id for the §9 alert hook.
    Blocked(String),
    /// No workable part: every row is `done`/`deferred`/unrecognized (rolled
    /// past) or the queue is empty.
    Empty,
}

/// Reduce a queue to its head workable part by scanning rows in order. The first
/// `active`/`queued`/`blocked` row decides the state; `done`/`deferred`/`other`
/// rows are rolled past (so a `blocked` row is head-of-line — it cannot be jumped
/// by a later `queued` row, honoring intra-queue ordering deps). A held `queued`
/// row ([`ClaimHold`]) is rolled past too: it is the human's work, waiting on
/// them like a `deferred` one, so it neither parks the queue nor gets claimed.
pub fn classify_queue(queue: &QueueView) -> QueueState {
    for part in &queue.parts {
        match part.status {
            PartStatus::Active => return QueueState::Active(part.id.clone()),
            PartStatus::Queued if part.claimable() => return QueueState::Ready(part.id.clone()),
            // Held for the human — rolled past, never claimed (task 068).
            PartStatus::Queued => {}
            PartStatus::Blocked => return QueueState::Blocked(part.id.clone()),
            // Rolled past: finished, parked-for-human, or unrecognized.
            PartStatus::Deferred | PartStatus::Done | PartStatus::Other => {}
        }
    }
    QueueState::Empty
}

/// Pick the next `(queue, part)` for an agent — **pinned-with-fallback**.
///
/// `pin` is the agent's own work-stream (its pinned queue), or `None` for an
/// unpinned agent (which goes straight to fallback). The agent prefers its own
/// queue: it resumes that queue's `active` part or starts its next `queued` part.
/// If its own queue is **blocked** (head parked) or **empty**, the agent pivots —
/// it pulls the first *unclaimed* (`queued`-head) part from another queue, in
/// snapshot order. Returns `None` when nothing is workable anywhere.
///
/// Fallback deliberately ignores other queues whose head is `active` (claimed by
/// the agent draining them — single-active per queue), `blocked` (parked), or
/// empty. That claimed-skip is the anti-starvation mechanism: once an agent takes
/// a queue and its head turns `active`, every other agent's fallback flows past it
/// to a different unclaimed queue.
pub fn pick(snapshot: &Snapshot, pin: Option<&str>) -> Option<(String, String)> {
    pick_for(snapshot, pin, &BTreeSet::new())
}

/// [`pick`] with the queues **`reserved`** for other members left out of the
/// fallback (task 068). The drive loop reserves a queue for the member pinned to
/// it while that member can take its next part — free to start one, or still
/// draining that queue (its part just went terminal and it is on its way out).
/// Without this a drained member's fallback took `psy/psy-booking` while `psy`'s
/// own pinned member was still exiting from `psy-events` (2026-10-16 17:34),
/// and the pinned member came back to find its queue's next part gone.
///
/// Only the fallback reads `reserved`: an agent's own pinned queue is never
/// reserved against it, even when another member shares the pin.
pub fn pick_for(
    snapshot: &Snapshot,
    pin: Option<&str>,
    reserved: &BTreeSet<String>,
) -> Option<(String, String)> {
    // 1. Pinned queue first — prefer the agent's own work-stream.
    if let Some(pin) = pin {
        if let Some(q) = snapshot.queue(pin) {
            match classify_queue(q) {
                // Resume own in-progress part, or start own next part.
                QueueState::Active(id) | QueueState::Ready(id) => {
                    return Some((pin.to_string(), id));
                }
                // Parked or empty → pivot (fall through to fallback). The §9
                // park alert for a Blocked head is fired by the drive loop via
                // `parked`; it is out of scope for the selection itself.
                QueueState::Blocked(_) | QueueState::Empty => {}
            }
        }
    }

    // 2. Fallback — first OTHER queue with an unclaimed (`queued`) head that no
    //    other member has reserved.
    for q in &snapshot.queues {
        if Some(q.name.as_str()) == pin {
            continue; // already considered as the pinned queue
        }
        if reserved.contains(&q.name) {
            continue; // its pinned member can take it — not ours to drain
        }
        if let QueueState::Ready(id) = classify_queue(q) {
            return Some((q.name.clone(), id));
        }
    }

    None
}

/// The park set: every queue whose head workable part is `blocked`
/// (BLOCKED_ON_HUMAN), as `(queue, part)`. This is the hook the §9 notification
/// engine (phase 5) fires its park alerts from — pure here, with the alert
/// channel wired later. A parked queue never halts the fleet ([`pick`] pivots
/// past it); the alert is so the human learns a part needs them.
pub fn parked(snapshot: &Snapshot) -> Vec<(String, String)> {
    snapshot
        .queues
        .iter()
        .filter_map(|q| match classify_queue(q) {
            QueueState::Blocked(id) => Some((q.name.clone(), id)),
            _ => None,
        })
        .collect()
}

/// Every held `queued` part across the snapshot, as `(queue, part, hold)` in
/// snapshot order — what the fleet is leaving for the human (task 068). The drive
/// loop journals a change in this set and `growlight status` lists it, so a skip
/// is always visible; it is not an alert (a hold is not a block).
pub fn held(snapshot: &Snapshot) -> Vec<(String, String, ClaimHold)> {
    snapshot
        .queues
        .iter()
        .flat_map(|q| {
            q.parts.iter().filter_map(move |p| match (&p.status, &p.hold) {
                (PartStatus::Queued, Some(hold)) => Some((q.name.clone(), p.id.clone(), hold.clone())),
                _ => None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a queue from `(id, status)` pairs in row order.
    fn q(name: &str, rows: &[(&str, &str)]) -> QueueView {
        QueueView::new(
            name,
            rows.iter().map(|(id, s)| PartView::new(*id, s)).collect(),
        )
    }

    fn pick_pinned(snapshot: &Snapshot, pin: &str) -> Option<(String, String)> {
        pick(snapshot, Some(pin))
    }

    #[test]
    fn parse_maps_known_statuses_and_falls_back_to_other() {
        assert_eq!(PartStatus::parse("active"), PartStatus::Active);
        assert_eq!(PartStatus::parse("queued"), PartStatus::Queued);
        assert_eq!(PartStatus::parse("blocked"), PartStatus::Blocked);
        assert_eq!(PartStatus::parse("deferred"), PartStatus::Deferred);
        assert_eq!(PartStatus::parse("done"), PartStatus::Done);
        assert_eq!(PartStatus::parse("in_progress"), PartStatus::Other);
        assert_eq!(PartStatus::parse(""), PartStatus::Other);
    }

    #[test]
    fn classify_returns_the_first_workable_row_in_order() {
        // done/deferred are rolled past; the first queued is the head.
        let queue = q("a", &[("1", "done"), ("2", "deferred"), ("3", "queued"), ("4", "queued")]);
        assert_eq!(classify_queue(&queue), QueueState::Ready("3".into()));
    }

    #[test]
    fn classify_prefers_an_active_head_over_a_later_queued() {
        let queue = q("a", &[("1", "active"), ("2", "queued")]);
        assert_eq!(classify_queue(&queue), QueueState::Active("1".into()));
    }

    #[test]
    fn classify_blocks_head_of_line_even_with_a_later_queued_row() {
        // A blocked row parks the queue; a later queued row does NOT jump it
        // (intra-queue ordering dep is honored).
        let queue = q("a", &[("1", "done"), ("2", "blocked"), ("3", "queued")]);
        assert_eq!(classify_queue(&queue), QueueState::Blocked("2".into()));
    }

    #[test]
    fn classify_empty_when_only_terminal_or_no_rows() {
        assert_eq!(classify_queue(&q("a", &[])), QueueState::Empty);
        assert_eq!(
            classify_queue(&q("a", &[("1", "done"), ("2", "deferred")])),
            QueueState::Empty,
        );
    }

    #[test]
    fn pinned_pick_resumes_an_active_part() {
        let snap = Snapshot::new(vec![q("mine", &[("p1", "active"), ("p2", "queued")])]);
        assert_eq!(pick_pinned(&snap, "mine"), Some(("mine".into(), "p1".into())));
    }

    #[test]
    fn pinned_pick_starts_the_next_queued_part() {
        let snap = Snapshot::new(vec![q("mine", &[("p1", "done"), ("p2", "queued")])]);
        assert_eq!(pick_pinned(&snap, "mine"), Some(("mine".into(), "p2".into())));
    }

    #[test]
    fn falls_back_to_another_queue_when_pinned_is_empty() {
        let snap = Snapshot::new(vec![
            q("mine", &[("p1", "done")]),        // empty (all terminal)
            q("other", &[("o1", "queued")]),     // has unclaimed work
        ]);
        assert_eq!(pick_pinned(&snap, "mine"), Some(("other".into(), "o1".into())));
    }

    #[test]
    fn pivots_off_a_blocked_pinned_queue_and_parks_it() {
        // pinned head is blocked → the agent pivots to `other`; the blocked head
        // is surfaced for the §9 park alert.
        let snap = Snapshot::new(vec![
            q("mine", &[("p1", "blocked"), ("p2", "queued")]),
            q("other", &[("o1", "queued")]),
        ]);
        assert_eq!(
            pick_pinned(&snap, "mine"),
            Some(("other".into(), "o1".into())),
            "a blocked pinned head does not halt the agent — it pivots",
        );
        assert_eq!(
            parked(&snap),
            vec![("mine".into(), "p1".into())],
            "the blocked head is parked for the alert hook",
        );
    }

    #[test]
    fn fallback_skips_claimed_blocked_and_empty_others_for_a_ready_one() {
        // pinned empty; the first other is claimed (active head), the second is
        // blocked, the third is empty — only the fourth is takeable.
        let snap = Snapshot::new(vec![
            q("mine", &[]),
            q("claimed", &[("c1", "active")]),
            q("parked", &[("b1", "blocked")]),
            q("drained", &[("d1", "done")]),
            q("free", &[("f1", "queued")]),
        ]);
        assert_eq!(pick_pinned(&snap, "mine"), Some(("free".into(), "f1".into())));
    }

    #[test]
    fn no_starvation_a_second_agent_picks_a_different_queue() {
        // Two free fallback queues. Agent A (pinned empty) takes the first; once
        // that queue's head turns `active` (it is being drained), agent B's
        // fallback flows past it to the second — no single queue is starved.
        let before = Snapshot::new(vec![
            q("mine", &[]),
            q("qa", &[("a1", "queued")]),
            q("qb", &[("b1", "queued")]),
        ]);
        assert_eq!(pick_pinned(&before, "mine"), Some(("qa".into(), "a1".into())));

        // Simulate A having claimed qa/a1 (single-active per queue).
        let after = Snapshot::new(vec![
            q("mine", &[]),
            q("qa", &[("a1", "active")]),
            q("qb", &[("b1", "queued")]),
        ]);
        assert_eq!(
            pick_pinned(&after, "mine"),
            Some(("qb".into(), "b1".into())),
            "the claimed queue is skipped; the free one is chosen",
        );
    }

    #[test]
    fn an_unpinned_agent_takes_the_first_ready_queue() {
        let snap = Snapshot::new(vec![
            q("qa", &[("a1", "active")]), // claimed — skipped
            q("qb", &[("b1", "queued")]),
        ]);
        assert_eq!(pick(&snap, None), Some(("qb".into(), "b1".into())));
    }

    #[test]
    fn pin_to_an_unknown_queue_falls_back() {
        let snap = Snapshot::new(vec![q("qb", &[("b1", "queued")])]);
        assert_eq!(pick_pinned(&snap, "ghost"), Some(("qb".into(), "b1".into())));
    }

    #[test]
    fn nothing_workable_anywhere_is_none() {
        let snap = Snapshot::new(vec![
            q("mine", &[("p1", "done")]),
            q("claimed", &[("c1", "active")]), // claimed by its own agent
            q("parked", &[("b1", "blocked")]),
        ]);
        assert_eq!(pick_pinned(&snap, "mine"), None, "no unclaimed work to pivot to");
        // …but the parked queue is still surfaced for the alert.
        assert_eq!(parked(&snap), vec![("parked".into(), "b1".into())]);
    }

    #[test]
    fn a_pinned_queue_with_its_own_queued_work_is_not_starved_by_fallback() {
        // The agent stays on its own queue when it has work, even if other queues
        // also have work (no needless pivot).
        let snap = Snapshot::new(vec![
            q("mine", &[("p1", "queued")]),
            q("other", &[("o1", "queued")]),
        ]);
        assert_eq!(pick_pinned(&snap, "mine"), Some(("mine".into(), "p1".into())));
    }

    #[test]
    fn mark_claimed_makes_a_ready_head_read_as_claimed_for_fallback() {
        // A free queue with a Ready head; a fallback agent would take it.
        let mut snap = Snapshot::new(vec![
            q("qa", &[("p1", "queued")]),
            q("qb", &[("p2", "queued")]),
        ]);
        assert_eq!(pick(&snap, None), Some(("qa".into(), "p1".into())));

        // Stamp qa/p1 claimed (the intra-tick mark) — fallback now flows past qa
        // to the next unclaimed queue, never re-resolving to the claimed part.
        snap.mark_claimed("qa", "p1");
        assert_eq!(classify_queue(snap.queue("qa").unwrap()), QueueState::Active("p1".into()));
        assert_eq!(
            pick(&snap, None),
            Some(("qb".into(), "p2".into())),
            "a second fallback agent in the same tick picks a different queue",
        );
    }

    #[test]
    fn mark_blocked_parks_a_head_so_a_pivot_skips_it() {
        // A pinned queue whose head an agent is resuming (`active`); item-park it
        // (the member exited BLOCKED_ON_HUMAN) and the pinned pick pivots to the
        // fallback queue while the blocked head is surfaced for the alert.
        let mut snap = Snapshot::new(vec![
            q("mine", &[("p1", "active")]),
            q("other", &[("o1", "queued")]),
        ]);
        assert_eq!(pick_pinned(&snap, "mine"), Some(("mine".into(), "p1".into())));

        snap.mark_blocked("mine", "p1");
        assert_eq!(classify_queue(snap.queue("mine").unwrap()), QueueState::Blocked("p1".into()));
        assert_eq!(
            pick_pinned(&snap, "mine"),
            Some(("other".into(), "o1".into())),
            "the freed member pivots past its own item-parked part",
        );
        assert_eq!(
            parked(&snap),
            vec![("mine".into(), "p1".into())],
            "the item-parked head is surfaced for the §9 alert",
        );
    }

    #[test]
    fn mark_blocked_is_a_no_op_for_an_absent_queue_or_part() {
        let mut snap = Snapshot::new(vec![q("qa", &[("p1", "queued")])]);
        snap.mark_blocked("ghost", "p1"); // unknown queue
        snap.mark_blocked("qa", "nope"); // unknown part
        assert_eq!(
            classify_queue(snap.queue("qa").unwrap()),
            QueueState::Ready("p1".into()),
            "a block against a missing queue/part changes nothing",
        );
    }

    #[test]
    fn mark_claimed_is_a_no_op_for_an_absent_queue_or_part() {
        let mut snap = Snapshot::new(vec![q("qa", &[("p1", "queued")])]);
        snap.mark_claimed("ghost", "p1"); // unknown queue
        snap.mark_claimed("qa", "nope"); // unknown part
        assert_eq!(
            classify_queue(snap.queue("qa").unwrap()),
            QueueState::Ready("p1".into()),
            "a mark against a missing queue/part changes nothing",
        );
    }

    /// A `queued` part whose item doc declares `> Fleet: no`.
    fn human_only(id: &str) -> PartView {
        PartView { hold: Some(ClaimHold::HumanOnly("no".into())), ..PartView::new(id, "queued") }
    }

    #[test]
    fn a_pinned_member_rolls_past_a_human_only_head_to_the_next_part() {
        // The pinned queue's head is the human's; the member takes the part behind
        // it instead of claiming it — and nothing parks (a hold is not a block).
        let snap = Snapshot::new(vec![QueueView::new(
            "mine",
            vec![human_only("h1"), PartView::new("p2", "queued")],
        )]);
        assert_eq!(pick_pinned(&snap, "mine"), Some(("mine".into(), "p2".into())));
        assert!(parked(&snap).is_empty(), "a human-only item never parks its queue");
    }

    #[test]
    fn a_fallback_member_never_claims_a_human_only_part() {
        // The 2026-10-16 sequence: a drained member's fallback walked into
        // human-only items. Every other queue holds only human-only work, so there
        // is nothing to take — not the human's item.
        let snap = Snapshot::new(vec![
            q("mine", &[("p1", "done")]),
            QueueView::new("default", vec![human_only("queue-v2-scheduling")]),
            QueueView::new("hoverview", vec![human_only("hover-view-sticky")]),
        ]);
        assert_eq!(pick_pinned(&snap, "mine"), None);
        assert_eq!(pick(&snap, None), None, "an unpinned member is held off it too");
        assert!(parked(&snap).is_empty());
    }

    #[test]
    fn an_item_that_loses_the_marker_becomes_claimable() {
        let held_snap = Snapshot::new(vec![QueueView::new("default", vec![human_only("h1")])]);
        assert_eq!(pick(&held_snap, None), None);
        // The owner removes the `> Fleet: no` line: the next snapshot carries no
        // hold, and the very same row schedules exactly as an unmarked one.
        let cleared = Snapshot::new(vec![q("default", &[("h1", "queued")])]);
        assert_eq!(pick(&cleared, None), Some(("default".into(), "h1".into())));
    }

    #[test]
    fn held_lists_every_held_queued_part_with_its_reason() {
        let unreadable = PartView {
            hold: Some(ClaimHold::Unreadable("keeperd down".into())),
            ..PartView::new("u1", "queued")
        };
        let snap = Snapshot::new(vec![
            QueueView::new("a", vec![PartView::new("a1", "queued"), human_only("a2")]),
            QueueView::new("b", vec![unreadable]),
        ]);
        let listed = held(&snap);
        assert_eq!(listed.len(), 2);
        assert_eq!((listed[0].0.as_str(), listed[0].1.as_str()), ("a", "a2"));
        assert_eq!(listed[0].2.reason(), "human-only (> Fleet: no)");
        assert_eq!(listed[1].2.reason(), "fleet marker unreadable: keeperd down");
    }

    #[test]
    fn mark_held_holds_a_queued_part_but_never_an_active_one() {
        let mut snap = Snapshot::new(vec![
            q("qa", &[("p1", "queued")]),
            q("qb", &[("p2", "active")]),
        ]);
        snap.mark_held("qa", "p1", ClaimHold::HumanOnly("no".into()));
        assert_eq!(classify_queue(snap.queue("qa").unwrap()), QueueState::Empty);
        // A member is already on p2: the marker never parks work in flight.
        snap.mark_held("qb", "p2", ClaimHold::HumanOnly("no".into()));
        assert_eq!(classify_queue(snap.queue("qb").unwrap()), QueueState::Active("p2".into()));
        assert!(held(&snap).iter().all(|(_, part, _)| part != "p2"));
    }

    #[test]
    fn fallback_leaves_a_reserved_queue_to_its_pinned_member() {
        // The 2026-10-16 17:34 sequence, reduced: `psy`'s head turned `queued` the
        // moment its pinned member's part went terminal, while that member was still
        // exiting. The drained `fid` member's fallback must not take it.
        let snap = Snapshot::new(vec![
            q("fid", &[("f1", "done")]),
            q("psy", &[("psy-events", "deferred"), ("psy-booking", "queued")]),
        ]);
        let reserved: BTreeSet<String> = ["psy".to_string()].into();
        assert_eq!(pick_for(&snap, Some("fid"), &reserved), None);
        // Unreserved (its pinned member is stopped), fallback takes it as before.
        assert_eq!(
            pick_for(&snap, Some("fid"), &BTreeSet::new()),
            Some(("psy".into(), "psy-booking".into())),
        );
        // The pinned member itself is never kept off its own queue.
        assert_eq!(
            pick_for(&snap, Some("psy"), &reserved),
            Some(("psy".into(), "psy-booking".into())),
        );
    }

    #[test]
    fn fallback_flows_past_a_reserved_queue_to_a_free_one() {
        let snap = Snapshot::new(vec![
            q("mine", &[]),
            q("taken", &[("t1", "queued")]),
            q("free", &[("f1", "queued")]),
        ]);
        let reserved: BTreeSet<String> = ["taken".to_string()].into();
        assert_eq!(pick_for(&snap, Some("mine"), &reserved), Some(("free".into(), "f1".into())));
    }

    #[test]
    fn parked_lists_every_blocked_head_across_queues() {
        let snap = Snapshot::new(vec![
            q("a", &[("a1", "blocked")]),
            q("b", &[("b1", "queued")]),
            q("c", &[("c1", "done"), ("c2", "blocked")]),
        ]);
        assert_eq!(
            parked(&snap),
            vec![("a".into(), "a1".into()), ("c".into(), "c2".into())],
        );
    }
}
