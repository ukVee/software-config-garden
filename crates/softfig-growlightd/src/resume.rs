//! The item-resume control verb (`growlight-fleet-member-model` slice 004): the
//! human-driven **un-block** that flips a parked backlog item `blocked → queued`
//! so the scheduler re-picks it — the inverse of slice 003's item-park.
//!
//! ## What this is
//!
//! Slice 003 made a `BLOCKED_ON_HUMAN` / `STUCK` exit park the **item** (`blocked`
//! in keeperd's queue table) and release the member to pivot. Nothing un-parked
//! it short of hand-editing the queue. This module is the wired un-park: the
//! `resume_item` control verb (CLI/GUI → growlightd → keeperd) reads the item's
//! current status from keeperd and, **iff it is currently `blocked`** (the
//! guard), writes `queued` over the same `set_item_status` round-trip the claim
//! ([`crate::claim::KeeperdPartClaimer`]) and the item-park
//! ([`crate::claim::KeeperdItemParker`]) use — reusing the `item_status_set`
//! commit intent, so no new VCS intent is needed.
//!
//! It composes with the `growlight-coordination-completeness` §8/§13
//! `answer_question` / `reprioritize` verbs: this is the **queue-status half** of
//! a resume (the item goes back to `queued`); delivering a human's *answer* into
//! the re-picked member's seed baton is that milestone's boundary-async lane (§8).
//! Built to dovetail — same control path, not a fork.
//!
//! ## The guard reads, the write commits
//!
//! keeperd's `set_item_status` has no "from-status" guard — it flips any status
//! to the target. So the guard lives here: growlightd first reads the backlog doc
//! (the same read [`crate::queue_source`] does), [`parse_snapshot`]s it, and
//! [`classify_resume`]s the item:
//!
//! - currently `blocked` → write `queued` ([`ResumeOutcome::Resumed`]);
//! - already `queued` → idempotent no-op success ([`ResumeOutcome::AlreadyQueued`]);
//! - any other status (`active`/`done`/`deferred`/unknown) → refused, unchanged
//!   ([`ResumeOutcome::NotBlocked`]) — un-blocking a `done` item would corrupt it;
//! - not present, or present in >1 queue with no `queue` given → reported so the
//!   caller can fix the request ([`ResumeOutcome::NotFound`] / `Ambiguous`).
//!
//! The read→write is two keeperd round-trips, not one atomic op; the small TOCTOU
//! window is benign — only a *fresh* `BLOCKED_ON_HUMAN` exit re-parks an item, and
//! that needs a member assigned to it, which cannot happen while it is `blocked`.
//!
//! ## Testable without keeperd
//!
//! Both I/O legs are seams (mirroring [`crate::queue_source::KeeperdQueueSource`]):
//! a [`BacklogReader`](crate::queue_source) for the read and a [`StatusWriter`] for
//! the write. The decision itself ([`classify_resume`]) is pure over a parsed
//! [`Snapshot`], so the guard is unit-proven against fixtures, and the full
//! [`KeeperdItemResumer`] is proven against faked read/write seams — no live
//! keeperd, no real `claude`.

use std::fmt;
use std::path::PathBuf;

use crate::claim::write_item_status;
use crate::queue_source::{parse_snapshot, BacklogReader, KeeperdBacklogReader};
use crate::scheduler::{PartStatus, Snapshot};

/// The status an un-block writes: a blocked item goes back to the ready pool.
const RESUME_STATUS: &str = "queued";

/// The outcome of a `resume_item` attempt — the daemon maps each variant onto a
/// wire reply (`Resumed`/`AlreadyQueued` → an Ok [`ResumeItemReply`](softfig_ipc::growlightd::ResumeItemReply))
/// or a clear `Response::Err` (everything else).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeOutcome {
    /// The item was `blocked` and was flipped to `queued` in `queue`.
    Resumed { queue: String },
    /// The item was already `queued` in `queue` — an idempotent no-op success
    /// (the un-park goal state is already reached).
    AlreadyQueued { queue: String },
    /// The item exists in `queue` but is not `blocked` (its `status` is given) —
    /// the guard refused: `resume_item` only un-blocks a blocked item.
    NotBlocked { queue: String, status: String },
    /// No backlog item with that id (in the given queue, if one was named).
    NotFound,
    /// The id exists in more than one queue and no `queue` was given to
    /// disambiguate; the colliding queue names are listed.
    Ambiguous { queues: Vec<String> },
    /// keeperd was unreachable / refused the backlog read or the status write —
    /// the reason is surfaced so the caller can retry.
    Unreachable { reason: String },
}

/// The seam the item-resume reaches an [`ItemResumer`] through — owned by the
/// daemon (`Option<Arc<dyn ItemResumer>>`, installed at boot) and called WITHOUT
/// the daemon lock, since the production impl reaches keeperd over the socket and
/// may block (the kill-safety / thrash-clear lock-ordering lesson, incident
/// 20260622). A test installs a spy; production installs [`KeeperdItemResumer`].
pub trait ItemResumer: Send + Sync + fmt::Debug {
    /// Un-block `item` (optionally scoped to `queue`): read its current status,
    /// and iff it is `blocked` flip it to `queued`. Returns the [`ResumeOutcome`].
    fn resume_item(&self, item: &str, queue: Option<&str>) -> ResumeOutcome;
}

/// What an un-block should do, decided **purely** from a parsed [`Snapshot`] — the
/// guard, with no I/O. [`KeeperdItemResumer`] reads the backlog, runs this, then
/// performs the write only for [`ResumeDecision::Unblock`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResumeDecision {
    /// The item is `blocked` in this queue → write `queued`.
    Unblock { queue: String },
    /// The item is already `queued` in this queue → no write, no-op success.
    AlreadyQueued { queue: String },
    /// The item is in this queue but not blocked → refuse (the guard).
    NotBlocked { queue: String, status: PartStatus },
    /// No item with that id (scoped to the requested queue, if any).
    NotFound,
    /// The id is in more than one queue and no queue scoped the request.
    Ambiguous { queues: Vec<String> },
}

/// A human label for a [`PartStatus`] cell, for the guard-refusal message. Mirrors
/// keeperd's status vocabulary (`PartStatus::parse`'s inverse for the named
/// states); `Other` is an unrecognized cell.
fn status_label(status: PartStatus) -> &'static str {
    match status {
        PartStatus::Active => "active",
        PartStatus::Queued => "queued",
        PartStatus::Blocked => "blocked",
        PartStatus::Deferred => "deferred",
        PartStatus::Done => "done",
        PartStatus::Other => "an unrecognized status",
    }
}

/// Decide what a `resume_item(item, queue)` should do, purely from `snap`. Scans
/// every queue (or only `queue`, if given) for a part whose id is `item`, then:
/// no hit → [`ResumeDecision::NotFound`]; the id in more than one distinct queue
/// (only possible with no `queue`) → [`ResumeDecision::Ambiguous`]; exactly one
/// hit → classify on its status (`Blocked` → un-block, `Queued` → no-op, anything
/// else → refuse).
///
/// Passing `queue` scopes the search to that one queue, so a cross-queue id
/// collision is resolved by the caller (never ambiguous when a queue is named).
fn classify_resume(snap: &Snapshot, item: &str, queue: Option<&str>) -> ResumeDecision {
    let mut hits: Vec<(String, PartStatus)> = snap
        .queues
        .iter()
        .filter(|q| queue.is_none_or(|want| q.name == want))
        .flat_map(|q| {
            q.parts
                .iter()
                .filter(|p| p.id == item)
                .map(move |p| (q.name.clone(), p.status))
        })
        .collect();

    match hits.len() {
        0 => ResumeDecision::NotFound,
        1 => {
            let (queue, status) = hits.remove(0);
            match status {
                PartStatus::Blocked => ResumeDecision::Unblock { queue },
                PartStatus::Queued => ResumeDecision::AlreadyQueued { queue },
                other => ResumeDecision::NotBlocked {
                    queue,
                    status: other,
                },
            }
        }
        _ => {
            // Distinct colliding queues, in snapshot order (a well-formed backlog
            // has unique ids per queue, so each name appears once; dedup defends
            // against a hand-malformed table without changing the happy path).
            let mut queues: Vec<String> = Vec::new();
            for (q, _) in hits {
                if !queues.contains(&q) {
                    queues.push(q);
                }
            }
            ResumeDecision::Ambiguous { queues }
        }
    }
}

/// The seam the item-resume **writes** the `queued` status through — the WRITE
/// counterpart to the [`BacklogReader`] read. Production wraps keeperd's
/// `set_item_status` over the socket ([`KeeperdStatusWriter`]); a test scripts the
/// result, so [`KeeperdItemResumer`]'s read→guard→write is proven end to end
/// without a live keeperd.
pub(crate) trait StatusWriter: Send + Sync + fmt::Debug {
    /// Write `status` onto `(queue, item)` in keeperd's queue table. `Ok(())` =
    /// committed (idempotent re-write is also ok); `Err(reason)` = keeperd
    /// refused / was unreachable.
    fn write_status(&self, queue: &str, item: &str, status: &str) -> Result<(), String>;
}

/// Production [`StatusWriter`]: `set_item_status(item, status, queue)` over
/// keeperd's socket, reusing [`write_item_status`] (the same fail-closed
/// round-trip the claim/park writes use, reconnecting through a transient `cycle`).
#[derive(Debug, Clone)]
struct KeeperdStatusWriter {
    keeperd_socket: PathBuf,
}

impl StatusWriter for KeeperdStatusWriter {
    fn write_status(&self, queue: &str, item: &str, status: &str) -> Result<(), String> {
        write_item_status(&self.keeperd_socket, "resume", queue, item, status)
    }
}

/// The live [`ItemResumer`]: read keeperd's backlog, guard on the current status,
/// and flip a blocked item to `queued`. Both I/O legs are seams — the
/// [`BacklogReader`] read (shared with [`crate::queue_source`]) and the
/// [`StatusWriter`] write — so the whole read→guard→write is testable over fakes.
/// Wired onto the daemon at boot ([`crate::daemon::Daemon::with_item_resumer`]),
/// reaching the same keeperd socket the queue source / claimer / parker use.
#[derive(Debug)]
pub struct KeeperdItemResumer {
    reader: Box<dyn BacklogReader>,
    writer: Box<dyn StatusWriter>,
}

impl KeeperdItemResumer {
    /// Bind a resumer to keeperd's listen socket (the read + the write both ride
    /// it). Production constructor — the daemon installs this in `main`.
    pub fn new(keeperd_socket: PathBuf) -> Self {
        Self {
            reader: Box::new(KeeperdBacklogReader::new(keeperd_socket.clone())),
            writer: Box::new(KeeperdStatusWriter { keeperd_socket }),
        }
    }

    /// Build a resumer over injected seams — the test seam (faked read + write),
    /// so the read→guard→write is proven with no keeperd socket.
    #[cfg(test)]
    fn with_seams(reader: Box<dyn BacklogReader>, writer: Box<dyn StatusWriter>) -> Self {
        Self { reader, writer }
    }
}

impl ItemResumer for KeeperdItemResumer {
    fn resume_item(&self, item: &str, queue: Option<&str>) -> ResumeOutcome {
        // Read the authoritative queue state (fail-closed: a read error is
        // surfaced, never silently treated as "not found" — un-blocking nothing
        // is safer than guessing).
        let doc = match self.reader.read_backlog() {
            Ok(doc) => doc,
            Err(reason) => return ResumeOutcome::Unreachable { reason },
        };
        let snap = parse_snapshot(&doc);
        match classify_resume(&snap, item, queue) {
            ResumeDecision::NotFound => ResumeOutcome::NotFound,
            ResumeDecision::Ambiguous { queues } => ResumeOutcome::Ambiguous { queues },
            ResumeDecision::AlreadyQueued { queue } => ResumeOutcome::AlreadyQueued { queue },
            ResumeDecision::NotBlocked { queue, status } => ResumeOutcome::NotBlocked {
                queue,
                status: status_label(status).to_string(),
            },
            ResumeDecision::Unblock { queue } => {
                match self.writer.write_status(&queue, item, RESUME_STATUS) {
                    Ok(()) => ResumeOutcome::Resumed { queue },
                    Err(reason) => ResumeOutcome::Unreachable { reason },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{PartView, QueueView};
    use std::sync::{Arc, Mutex};

    fn snap(queues: Vec<(&str, Vec<(&str, &str)>)>) -> Snapshot {
        Snapshot::new(
            queues
                .into_iter()
                .map(|(name, parts)| {
                    QueueView::new(
                        name,
                        parts
                            .into_iter()
                            .map(|(id, status)| PartView::new(id, status))
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    // ---- the pure guard (classify_resume) ----------------------------------

    #[test]
    fn a_blocked_item_is_unblocked_in_its_queue() {
        let s = snap(vec![("default", vec![("t1", "active"), ("t2", "blocked")])]);
        assert_eq!(
            classify_resume(&s, "t2", None),
            ResumeDecision::Unblock { queue: "default".into() },
        );
    }

    #[test]
    fn an_already_queued_item_is_a_noop_not_an_error() {
        let s = snap(vec![("default", vec![("t1", "queued")])]);
        assert_eq!(
            classify_resume(&s, "t1", None),
            ResumeDecision::AlreadyQueued { queue: "default".into() },
        );
    }

    #[test]
    fn a_non_blocked_item_is_refused_with_its_status() {
        // active / done / deferred / unknown all refuse — un-blocking them would
        // corrupt the item's real state.
        for (status, want) in [
            ("active", PartStatus::Active),
            ("done", PartStatus::Done),
            ("deferred", PartStatus::Deferred),
            ("in_progress", PartStatus::Other),
        ] {
            let s = snap(vec![("default", vec![("x", status)])]);
            assert_eq!(
                classify_resume(&s, "x", None),
                ResumeDecision::NotBlocked { queue: "default".into(), status: want },
                "status {status:?} must refuse",
            );
        }
    }

    #[test]
    fn a_missing_item_is_not_found() {
        let s = snap(vec![("default", vec![("t1", "blocked")])]);
        assert_eq!(classify_resume(&s, "ghost", None), ResumeDecision::NotFound);
        // A queue-scoped request for an id that isn't in THAT queue is also
        // not-found (even though it exists elsewhere).
        let s = snap(vec![
            ("default", vec![("a", "blocked")]),
            ("build", vec![("b", "blocked")]),
        ]);
        assert_eq!(classify_resume(&s, "a", Some("build")), ResumeDecision::NotFound);
    }

    #[test]
    fn a_cross_queue_collision_is_ambiguous_without_a_queue_and_resolved_with_one() {
        // Same id `dup` blocked in two queues. No queue → ambiguous, listing both.
        let s = snap(vec![
            ("default", vec![("dup", "blocked")]),
            ("build", vec![("dup", "blocked")]),
        ]);
        assert_eq!(
            classify_resume(&s, "dup", None),
            ResumeDecision::Ambiguous { queues: vec!["default".into(), "build".into()] },
        );
        // Naming the queue resolves it.
        assert_eq!(
            classify_resume(&s, "dup", Some("build")),
            ResumeDecision::Unblock { queue: "build".into() },
        );
    }

    // ---- the full KeeperdItemResumer over faked read + write seams ----------

    #[derive(Debug)]
    struct FakeReader {
        result: Result<String, String>,
    }
    impl BacklogReader for FakeReader {
        fn read_backlog(&self) -> Result<String, String> {
            self.result.clone()
        }
    }

    #[derive(Debug, Default)]
    struct SpyWriter {
        writes: Mutex<Vec<(String, String, String)>>,
        fail: Option<String>,
    }
    impl SpyWriter {
        fn ok() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn failing(reason: &str) -> Arc<Self> {
            Arc::new(Self {
                writes: Mutex::new(Vec::new()),
                fail: Some(reason.to_string()),
            })
        }
        fn writes(&self) -> Vec<(String, String, String)> {
            self.writes.lock().unwrap().clone()
        }
    }
    impl StatusWriter for Arc<SpyWriter> {
        fn write_status(&self, queue: &str, item: &str, status: &str) -> Result<(), String> {
            if let Some(reason) = &self.fail {
                return Err(reason.clone());
            }
            self.writes
                .lock()
                .unwrap()
                .push((queue.to_string(), item.to_string(), status.to_string()));
            Ok(())
        }
    }

    /// Wrap a queue table in the managed-region markers keeperd renders, so the
    /// resumer's `parse_snapshot` sees a realistic backlog doc.
    fn backlog_doc(rows: &[(&str, &str)]) -> String {
        let mut table =
            String::from("| # | id | type | title | status |\n|---|----|------|-------|--------|");
        for (i, (id, status)) in rows.iter().enumerate() {
            table.push_str(&format!("\n| {} | {id} | task | T | {status} |", i + 1));
        }
        format!("<!-- softfig:queue -->\n\n{table}\n\n<!-- /softfig:queue -->")
    }

    fn resumer(doc_result: Result<String, String>, writer: &Arc<SpyWriter>) -> KeeperdItemResumer {
        KeeperdItemResumer::with_seams(
            Box::new(FakeReader { result: doc_result }),
            Box::new(Arc::clone(writer)),
        )
    }

    #[test]
    fn resume_reads_then_writes_queued_for_a_blocked_item() {
        let writer = SpyWriter::ok();
        let r = resumer(Ok(backlog_doc(&[("t1", "blocked")])), &writer);
        assert_eq!(
            r.resume_item("t1", None),
            ResumeOutcome::Resumed { queue: "default".into() },
        );
        // The guard read the `blocked` status, then the write flipped it queued.
        assert_eq!(
            writer.writes(),
            vec![("default".to_string(), "t1".to_string(), "queued".to_string())],
        );
    }

    #[test]
    fn resume_of_an_already_queued_item_writes_nothing() {
        let writer = SpyWriter::ok();
        let r = resumer(Ok(backlog_doc(&[("t1", "queued")])), &writer);
        assert_eq!(
            r.resume_item("t1", None),
            ResumeOutcome::AlreadyQueued { queue: "default".into() },
        );
        assert!(writer.writes().is_empty(), "an already-queued item is a no-op — no write");
    }

    #[test]
    fn resume_refuses_a_non_blocked_item_and_writes_nothing() {
        let writer = SpyWriter::ok();
        let r = resumer(Ok(backlog_doc(&[("t1", "active")])), &writer);
        assert_eq!(
            r.resume_item("t1", None),
            ResumeOutcome::NotBlocked { queue: "default".into(), status: "active".into() },
        );
        assert!(writer.writes().is_empty(), "the guard refused — no write");
    }

    #[test]
    fn resume_surfaces_not_found_without_a_write() {
        let writer = SpyWriter::ok();
        let r = resumer(Ok(backlog_doc(&[("t1", "blocked")])), &writer);
        assert_eq!(r.resume_item("ghost", None), ResumeOutcome::NotFound);
        assert!(writer.writes().is_empty());
    }

    #[test]
    fn a_backlog_read_error_is_unreachable_not_a_silent_unblock() {
        let writer = SpyWriter::ok();
        let r = resumer(Err("keeperd down".into()), &writer);
        assert_eq!(
            r.resume_item("t1", None),
            ResumeOutcome::Unreachable { reason: "keeperd down".into() },
        );
        assert!(writer.writes().is_empty(), "no write attempted on a read failure");
    }

    #[test]
    fn a_write_failure_after_a_passed_guard_is_unreachable() {
        // The guard passed (item was blocked) but keeperd refused the write — the
        // caller learns it must retry, and the item stays blocked.
        let writer = SpyWriter::failing("keeperd refused resume (Locked)");
        let r = resumer(Ok(backlog_doc(&[("t1", "blocked")])), &writer);
        assert_eq!(
            r.resume_item("t1", None),
            ResumeOutcome::Unreachable { reason: "keeperd refused resume (Locked)".into() },
        );
    }
}
