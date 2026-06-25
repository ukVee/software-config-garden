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

/// One assignable part — a row in a queue. The scheduler needs only the id (what
/// it returns) and the status (how it classifies); title/type are carried by the
/// item docs, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartView {
    pub id: String,
    pub status: PartStatus,
}

impl PartView {
    /// Convenience constructor from a raw `(id, status-string)` pair, the shape a
    /// keeperd queue row reduces to.
    pub fn new(id: impl Into<String>, status: &str) -> Self {
        Self {
            id: id.into(),
            status: PartStatus::parse(status),
        }
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
/// by a later `queued` row, honoring intra-queue ordering deps).
pub fn classify_queue(queue: &QueueView) -> QueueState {
    for part in &queue.parts {
        match part.status {
            PartStatus::Active => return QueueState::Active(part.id.clone()),
            PartStatus::Queued => return QueueState::Ready(part.id.clone()),
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

    // 2. Fallback — first OTHER queue with an unclaimed (`queued`) head.
    for q in &snapshot.queues {
        if Some(q.name.as_str()) == pin {
            continue; // already considered as the pinned queue
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
