//! The live [`QueueSource`] (`growlight-live-fleet` slice 002): pull keeperd's
//! per-queue managed regions and reduce them to a scheduler [`Snapshot`].
//!
//! ## What this is
//!
//! Phase 4 modelled the fleet as N named work-stream queues, each an ordered
//! item table living as a daemon-managed region inside the one backlog doc
//! (`growlight/backlog/CLAUDE.md`):
//!
//! - the implicit **`default`** queue is the bare `queue` region (the legacy
//!   single-queue backlog table — `# | id | type | title | status`);
//! - every named queue `X` is its own `queue:X` region of the same shape;
//! - the `queues` *registry* region maps each named queue to its repo path and,
//!   crucially, **fixes their order**.
//!
//! growlightd is keeperd's client (it does not share keeperd's process or link
//! its crate), so it pulls the doc through the read-only `read_file` verb and
//! parses the regions here — the read mirror of [`crate::bus`]'s `tail_bus`
//! pull. The parse is faithful to keeperd's own `managed::region_body` extractor
//! and `queue`/`queues` row parsers; only the two columns the scheduler needs
//! (`id`, `status`) survive into a [`PartView`].
//!
//! ## Order is the contract
//!
//! [`pick`](crate::scheduler::pick) / [`parked`](crate::scheduler::parked) walk
//! the snapshot's queues in order for their deterministic fallback, so
//! [`parse_snapshot`] assembles **the default queue first, then the named queues
//! in registry order** — exactly the order keeperd renders them.
//!
//! ## Fail-closed, ride-out
//!
//! The pull uses [`call_reconnecting`] with the default [`RetryPolicy`] (the same
//! reconnecting client the lease hop uses), so a transient keeperd `cycle` is
//! ridden out within the retry budget rather than surfaced. [`QueueSource::snapshot`]
//! is infallible by contract, so a read that still fails (keeperd genuinely down,
//! or Locked) collapses to an **empty** [`Snapshot`]: the fleet simply idles this
//! tick and the next tick retries — a missed pull is never a scheduling failure.
//! An absent queue/registry region likewise yields an empty [`QueueView`], so an
//! unpopulated work-stream just idles instead of erroring.

use std::path::PathBuf;

use softfig_ipc::item_repo::{item_repo_path, probe, RepoState};
use softfig_ipc::verbs::{op, ListTreeArgs, ListTreeReply, ReadFileArgs, ReadFileReply};
use softfig_ipc::{call_reconnecting, ErrorKind, Request, Response, RetryPolicy};

use crate::drive_loop::{QueueSource, RepoProbe};
use crate::scheduler::{ClaimHold, PartView, QueueView, Snapshot};

/// The garden-relative backlog doc that hosts every queue's managed region
/// (the one definition lives in [`softfig_ipc::backlog_doc`]).
pub use softfig_ipc::backlog_doc::BACKLOG_DOC;
use softfig_ipc::backlog_doc::{
    is_task_id, item_rows, region_body, registry_rows, MILESTONES_DIR, TASKS_DIR,
};

/// The scheduler name of the implicit default queue. Matches keeperd's
/// `DEFAULT_QUEUE` / `add_backlog_item`'s implicit queue, so a fleet member
/// pinned to `"default"` resolves to this queue in [`pick`](crate::scheduler::pick).
pub const DEFAULT_QUEUE_NAME: &str = softfig_ipc::backlog_doc::DEFAULT_QUEUE;

// ---------------------------------------------------------------------------
// Pure parse: an item doc's `> Fleet:` marker -> ClaimHold (task 068).
// ---------------------------------------------------------------------------

/// The claim hold an item doc declares, if any: a `> Fleet: <value>` blockquote
/// line marks the item human-only unless the value is `yes`, so the fleet never
/// claims it. No line means no hold — the item schedules exactly as before.
///
/// Read the way `> Model:` is (`item_model_field`): the first blockquote line
/// whose key is `fleet`, case-insensitive, anywhere in the doc. Lines inside a
/// fenced code block don't count, so a doc that shows the marker as an example
/// does not mark itself. Any value other than `yes` holds — a typo fails closed.
pub fn fleet_marker(doc: &str) -> Option<ClaimHold> {
    let mut fenced = false;
    for line in doc.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix('>') else {
            continue;
        };
        let Some((key, value)) = rest.trim().split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("fleet") {
            let value = value.trim();
            return (!value.eq_ignore_ascii_case("yes"))
                .then(|| ClaimHold::HumanOnly(value.to_string()));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Pure parse: backlog doc markdown -> Snapshot.
// ---------------------------------------------------------------------------

/// Reduce the backlog doc's managed regions to a scheduler [`Snapshot`]: the
/// default queue first (its bare `queue` region), then each named queue in the
/// `queues` registry's order (its `queue:<name>` region). A region that is
/// absent yields an empty [`QueueView`] rather than being dropped, so a
/// registered-but-unpopulated queue idles instead of vanishing.
///
/// Pure over the doc string — the whole parse is provable against fixture
/// region payloads with no keeperd socket (the slice's theory-code proof).
pub fn parse_snapshot(doc: &str) -> Snapshot {
    let mut queues = Vec::new();
    // Default queue first — the deterministic head of the fallback order.
    queues.push(QueueView::new(DEFAULT_QUEUE_NAME, region_parts(doc, "queue")));
    // Named queues, in the registry's row order (what keeperd renders).
    for name in registry_names(doc) {
        let tag = format!("queue:{name}");
        let parts = region_parts(doc, &tag);
        queues.push(QueueView::new(name, parts));
    }
    Snapshot::new(queues)
}

/// The parts of one queue's item-table region, or an empty `Vec` when the region
/// is absent (an empty work-stream, not an error).
fn region_parts(doc: &str, tag: &str) -> Vec<PartView> {
    match region_body(doc, tag) {
        Some(body) => parse_item_rows(&body),
        None => Vec::new(),
    }
}

/// Parse a queue item table's rows into [`PartView`]s, in row order, through
/// the shared table parser ([`item_rows`] — 5-cell data rows, header and
/// separator skipped; the `#` order cell is discarded, the scheduler relies on
/// row order). The status string is classified through [`PartView::new`].
fn parse_item_rows(body: &str) -> Vec<PartView> {
    item_rows(body).into_iter().map(|(id, status)| PartView::new(id, &status)).collect()
}

/// Parse the queue registry region's queue names, in row order — the order the
/// scheduler walks the named queues in.
fn registry_names(doc: &str) -> Vec<String> {
    registry_rows(doc).into_iter().map(|(name, _)| name).collect()
}


// ---------------------------------------------------------------------------
// The live source: read the backlog doc from keeperd, then parse it.
// ---------------------------------------------------------------------------

/// The seam the live [`KeeperdQueueSource`] pulls the raw backlog doc through.
/// Production reads keeperd's read-only `read_file` over [`call_reconnecting`];
/// tests inject fixture markdown or a scripted error, so the parse + fail-closed
/// path is proven without a live keeperd (the same split [`crate::bus`] uses).
/// Also reused by [`crate::resume`]'s item-resume read (the guard that only
/// un-blocks a currently-`blocked` item reads the same backlog doc).
pub(crate) trait BacklogReader: Send + Sync + std::fmt::Debug {
    /// The current redacted content of the backlog doc, or a human error string
    /// when keeperd is unreachable / rejected the read.
    fn read_backlog(&self) -> Result<String, String>;
}

/// Production [`BacklogReader`]: `read_file(BACKLOG_DOC)` over keeperd's socket,
/// reconnecting through a transient keeperd `cycle` (default [`RetryPolicy`]).
#[derive(Debug, Clone)]
pub(crate) struct KeeperdBacklogReader {
    keeperd_socket: PathBuf,
}

impl KeeperdBacklogReader {
    /// Bind a backlog reader to keeperd's listen socket (the same path the queue
    /// source / item-resume use).
    pub(crate) fn new(keeperd_socket: PathBuf) -> Self {
        Self { keeperd_socket }
    }
}

impl BacklogReader for KeeperdBacklogReader {
    fn read_backlog(&self) -> Result<String, String> {
        let args = serde_json::to_value(ReadFileArgs {
            path: BACKLOG_DOC.to_string(),
        })
        .map_err(|e| format!("encode read_file args: {e}"))?;
        let req = Request::new(op::READ_FILE, args);
        match call_reconnecting(&self.keeperd_socket, &req, RetryPolicy::default()) {
            Ok(Response::Ok { data, .. }) => {
                let reply: ReadFileReply = serde_json::from_value(data)
                    .map_err(|e| format!("decode read_file reply: {e}"))?;
                Ok(reply.content)
            }
            // A daemon-side rejection (e.g. Locked) is a successful round-trip;
            // surface it as the read error so snapshot() idles fail-closed.
            Ok(Response::Err { kind, error, .. }) => Err(format!("keeperd {kind:?}: {error}")),
            Err(e) => Err(format!(
                "keeperd unreachable at {}: {e}",
                self.keeperd_socket.display()
            )),
        }
    }
}

/// The seam the claim-time marker read pulls an item's doc through (task 068).
/// Production reads keeperd's `read_file` (and `list_tree`, to find a task's
/// `<id>-<slug>.md`); tests inject fixture docs or a scripted error.
pub(crate) trait ItemDocReader: Send + Sync + std::fmt::Debug {
    /// The item's doc, `Ok(None)` when it has none (no doc, no marker), or an
    /// error string when keeperd could not answer.
    fn read_item_doc(&self, id: &str) -> Result<Option<String>, String>;
}

/// Production [`ItemDocReader`]: an all-digit id is a task (`tasks/<id>-*.md`,
/// found by listing the tasks dir), anything else a milestone
/// (`milestones/<id>/CLAUDE.md`) — the two shapes `add_backlog_item` mints.
#[derive(Debug, Clone)]
pub(crate) struct KeeperdItemDocReader {
    keeperd_socket: PathBuf,
}

impl KeeperdItemDocReader {
    /// One keeperd round-trip; `Ok(None)` for a `NotFound` refusal.
    fn call<T: serde::de::DeserializeOwned>(
        &self,
        verb: &str,
        args: impl serde::Serialize,
    ) -> Result<Option<T>, String> {
        let args = serde_json::to_value(args).map_err(|e| format!("encode {verb} args: {e}"))?;
        let req = Request::new(verb, args);
        match call_reconnecting(&self.keeperd_socket, &req, RetryPolicy::default()) {
            Ok(Response::Ok { data, .. }) => serde_json::from_value(data)
                .map(Some)
                .map_err(|e| format!("decode {verb} reply: {e}")),
            Ok(Response::Err { kind: ErrorKind::NotFound, .. }) => Ok(None),
            Ok(Response::Err { kind, error, .. }) => Err(format!("keeperd {kind:?}: {error}")),
            Err(e) => Err(format!("keeperd unreachable at {}: {e}", self.keeperd_socket.display())),
        }
    }

    fn read(&self, path: String) -> Result<Option<String>, String> {
        let reply: Option<ReadFileReply> = self.call(op::READ_FILE, ReadFileArgs { path })?;
        Ok(reply.map(|r| r.content))
    }
}

impl ItemDocReader for KeeperdItemDocReader {
    fn read_item_doc(&self, id: &str) -> Result<Option<String>, String> {
        if !is_task_id(id) {
            return self.read(format!("{MILESTONES_DIR}/{id}/CLAUDE.md"));
        }
        let listing: Option<ListTreeReply> =
            self.call(op::LIST_TREE, ListTreeArgs { path: Some(TASKS_DIR.to_string()) })?;
        let prefix = format!("{id}-");
        let doc = listing.into_iter().flat_map(|l| l.entries).find(|e| {
            !e.is_dir && e.name.starts_with(&prefix) && e.name.ends_with(".md")
        });
        match doc {
            Some(entry) => self.read(entry.path),
            None => Ok(None),
        }
    }
}

/// The live [`QueueSource`]: pull the backlog doc from keeperd each tick and
/// [`parse_snapshot`] it into the multi-queue view the scheduler picks from.
/// Replaces [`crate::drive_loop::DeferredQueues`] in the live assembly
/// ([`crate::fleet::assemble_fleet`]); the deferred default stays the disabled /
/// test seam.
#[derive(Debug)]
pub struct KeeperdQueueSource {
    reader: Box<dyn BacklogReader>,
    docs: Box<dyn ItemDocReader>,
}

impl KeeperdQueueSource {
    /// Bind the source to keeperd's listen socket (in production the same path
    /// the [`crate::bus::KeeperdBusSource`] tailer reads).
    pub fn new(keeperd_socket: PathBuf) -> Self {
        Self {
            reader: Box::new(KeeperdBacklogReader { keeperd_socket: keeperd_socket.clone() }),
            docs: Box::new(KeeperdItemDocReader { keeperd_socket }),
        }
    }
}

impl QueueSource for KeeperdQueueSource {
    fn snapshot(&self) -> Snapshot {
        match self.reader.read_backlog() {
            Ok(doc) => parse_snapshot(&doc),
            // Fail-closed: a read error (keeperd down past the reconnect budget,
            // or Locked) idles this tick rather than propagating a scheduling
            // failure. The next tick retries the pull.
            Err(e) => {
                eprintln!("growlightd: queue snapshot read failed (idling this tick): {e}");
                Snapshot::default()
            }
        }
    }

    /// Read the part's item doc fresh and parse its `> Fleet:` marker (task 068).
    /// A doc keeperd could not serve holds the part fail-closed
    /// ([`ClaimHold::Unreadable`]); a part with no doc has no marker.
    fn claim_hold(&self, _queue: &str, part: &str) -> Option<ClaimHold> {
        match self.docs.read_item_doc(part) {
            Ok(doc) => doc.as_deref().and_then(fleet_marker),
            Err(e) => Some(ClaimHold::Unreadable(e)),
        }
    }
}

/// The live [`RepoProbe`] (task 069): which repo a part's work lands in, read
/// through the same two keeperd docs the queue source reads — the item doc's
/// `> Worktree:` first, then the queue registry's `repo` cell — and how far it has
/// moved, through [`probe`]. Called on the spin guard's lazy read (once per
/// member session exit) and by the boot dirty-tree guard (task 064, once before
/// each member spawn), so the keeperd reads and the `git` calls never run per
/// tick.
#[derive(Debug)]
pub struct KeeperdRepoProbe {
    backlog: Box<dyn BacklogReader>,
    docs: Box<dyn ItemDocReader>,
    /// What a leading `~` expands against (`$HOME`, read once at assembly).
    home: Option<PathBuf>,
}

impl KeeperdRepoProbe {
    /// Bind the probe to keeperd's listen socket (the queue source's path) and
    /// the daemon's `$HOME`.
    pub fn new(keeperd_socket: PathBuf) -> Self {
        Self {
            backlog: Box::new(KeeperdBacklogReader { keeperd_socket: keeperd_socket.clone() }),
            docs: Box::new(KeeperdItemDocReader { keeperd_socket }),
            home: std::env::var_os("HOME").map(PathBuf::from),
        }
    }
}

impl KeeperdRepoProbe {
    /// Resolve the local repo path for `(queue, part)` through the shared
    /// resolver ([`item_repo_path`]: the doc's `> Worktree:`, then the queue
    /// registry's `repo` cell), journaling an unreadable doc or backlog rather
    /// than guessing. `None` = no repo signal (never an error); an unreadable doc
    /// might name a worktree the registry would contradict, so it is no signal
    /// rather than a registry guess.
    fn resolve(&self, queue: &str, part: &str) -> Option<PathBuf> {
        let doc = self
            .docs
            .read_item_doc(part)
            .inspect_err(|e| {
                eprintln!("growlightd: repo probe: item doc for {queue}/{part} unreadable: {e}");
            })
            .ok()?;
        let backlog = || {
            self.backlog
                .read_backlog()
                .inspect_err(|e| {
                    eprintln!("growlightd: repo probe: backlog unreadable for {queue}/{part}: {e}");
                })
                .ok()
        };
        item_repo_path(doc.as_deref(), queue, backlog, self.home.as_deref())
    }
}

impl RepoProbe for KeeperdRepoProbe {
    /// Every failure is "no repo signal" (the NEXT-ACTION-only guard), never an
    /// error: a doc keeperd can't serve and a repo `git` can't read are journaled,
    /// and the guard decides on NEXT ACTION alone. The path is the one probed
    /// (review 043 G64-9: no second resolution that could name another repo).
    fn repo_state(&self, queue: &str, part: &str) -> Option<(PathBuf, RepoState)> {
        let repo = self.resolve(queue, part)?;
        let state = probe(&repo)
            .inspect_err(|e| eprintln!("growlightd: repo probe: {queue}/{part}: {e}"))
            .ok()?;
        Some((repo, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::PartStatus;
    use softfig_ipc::backlog_doc::registry_repo;
    use std::sync::Mutex;

    /// Wrap a body in the managed-region markers exactly as keeperd's
    /// `managed::upsert` does (one blank pad line each side).
    fn region(tag: &str, body: &str) -> String {
        format!("<!-- softfig:{tag} -->\n\n{body}\n\n<!-- /softfig:{tag} -->")
    }

    fn item_table(rows: &[(&str, &str)]) -> String {
        let mut s = String::from("| # | id | type | title | status |\n|---|----|------|-------|--------|");
        for (i, (id, status)) in rows.iter().enumerate() {
            s.push_str(&format!("\n| {} | {id} | task | T | {status} |", i + 1));
        }
        s
    }

    fn ids_and_status(view: &QueueView) -> Vec<(String, PartStatus)> {
        view.parts.iter().map(|p| (p.id.clone(), p.status)).collect()
    }

    #[test]
    fn region_body_strips_the_blank_padding() {
        let doc = format!("# Doc\n\nlead\n\n{}\n", region("queue", "X\nY"));
        assert_eq!(region_body(&doc, "queue").as_deref(), Some("X\nY"));
        assert_eq!(region_body(&doc, "queues"), None);
    }

    #[test]
    fn region_tags_do_not_collide_by_prefix() {
        // `queue`, `queues`, and `queue:foo` are distinct exact marker lines.
        let doc = format!(
            "{}\n\n{}\n\n{}\n",
            region("queue", "DEFAULT"),
            region("queues", "REGISTRY"),
            region("queue:foo", "FOO"),
        );
        assert_eq!(region_body(&doc, "queue").as_deref(), Some("DEFAULT"));
        assert_eq!(region_body(&doc, "queues").as_deref(), Some("REGISTRY"));
        assert_eq!(region_body(&doc, "queue:foo").as_deref(), Some("FOO"));
    }

    #[test]
    fn default_queue_only_parses_to_one_named_default_queue() {
        let doc = region(
            "queue",
            &item_table(&[("m1", "active"), ("t2", "queued"), ("t3", "blocked")]),
        );
        let snap = parse_snapshot(&doc);
        assert_eq!(snap.queues.len(), 1);
        assert_eq!(snap.queues[0].name, "default");
        assert_eq!(
            ids_and_status(&snap.queues[0]),
            vec![
                ("m1".to_string(), PartStatus::Active),
                ("t2".to_string(), PartStatus::Queued),
                ("t3".to_string(), PartStatus::Blocked),
            ],
            "rows reduce to (id, classified status) in row order",
        );
    }

    #[test]
    fn statuses_classify_through_partview() {
        let doc = region(
            "queue",
            &item_table(&[
                ("a", "queued"),
                ("b", "active"),
                ("c", "blocked"),
                ("d", "deferred"),
                ("e", "done"),
                ("f", "in_progress"), // unrecognized -> Other
            ]),
        );
        let snap = parse_snapshot(&doc);
        assert_eq!(
            snap.queues[0]
                .parts
                .iter()
                .map(|p| p.status)
                .collect::<Vec<_>>(),
            vec![
                PartStatus::Queued,
                PartStatus::Active,
                PartStatus::Blocked,
                PartStatus::Deferred,
                PartStatus::Done,
                PartStatus::Other,
            ],
        );
    }

    #[test]
    fn registry_fixes_the_queue_order_default_first() {
        // Registry lists beta then alpha; the snapshot is default, beta, alpha.
        let registry = "| queue | repo |\n|-------|------|\n| beta | /b |\n| alpha | /a |";
        let doc = format!(
            "{}\n\n{}\n\n{}\n\n{}\n",
            region("queues", registry),
            region("queue", &item_table(&[("d1", "queued")])),
            region("queue:alpha", &item_table(&[("a1", "queued")])),
            region("queue:beta", &item_table(&[("b1", "active")])),
        );
        let snap = parse_snapshot(&doc);
        assert_eq!(
            snap.queues.iter().map(|q| q.name.as_str()).collect::<Vec<_>>(),
            vec!["default", "beta", "alpha"],
            "default first, then named queues in registry row order",
        );
        assert_eq!(ids_and_status(snap.queue("beta").unwrap()), vec![("b1".into(), PartStatus::Active)]);
        assert_eq!(ids_and_status(snap.queue("alpha").unwrap()), vec![("a1".into(), PartStatus::Queued)]);
    }

    #[test]
    fn a_registered_queue_with_no_item_region_is_an_empty_view_not_dropped() {
        // alpha is registered but has no `queue:alpha` region yet.
        let registry = "| queue | repo |\n|-------|------|\n| alpha | /a |";
        let doc = format!(
            "{}\n\n{}\n",
            region("queues", registry),
            region("queue", &item_table(&[("d1", "queued")])),
        );
        let snap = parse_snapshot(&doc);
        assert_eq!(snap.queues.iter().map(|q| q.name.as_str()).collect::<Vec<_>>(), vec!["default", "alpha"]);
        assert!(snap.queue("alpha").unwrap().parts.is_empty(), "absent item region -> empty work-stream, idles");
    }

    #[test]
    fn an_absent_default_region_is_an_empty_default_queue() {
        // A doc with neither a registry nor a `queue` region (degenerate) still
        // yields a present-but-empty default queue, never a panic.
        let snap = parse_snapshot("# backlog\n\nno regions here\n");
        assert_eq!(snap.queues.len(), 1);
        assert_eq!(snap.queues[0].name, "default");
        assert!(snap.queues[0].parts.is_empty());
    }

    #[test]
    fn malformed_and_prose_rows_are_skipped() {
        let body = "| # | id | type | title | status |\n|---|----|------|-------|--------|\n\
                    | 1 | good | task | T | queued |\nstray prose\n| only | three | cells |";
        let doc = region("queue", body);
        let snap = parse_snapshot(&doc);
        assert_eq!(ids_and_status(&snap.queues[0]), vec![("good".into(), PartStatus::Queued)]);
    }

    #[test]
    fn escaped_pipes_in_a_title_round_trip() {
        // A title with an escaped pipe must not bleed into the status column.
        let body = "| # | id | type | title | status |\n|---|----|------|-------|--------|\n\
                    | 1 | x | task | a\\|b path | active |";
        let snap = parse_snapshot(&region("queue", body));
        assert_eq!(ids_and_status(&snap.queues[0]), vec![("x".into(), PartStatus::Active)]);
    }

    // ---- The live source over a faked reader (no keeperd socket) -----------

    #[derive(Debug)]
    struct FakeReader {
        doc: String,
    }
    impl BacklogReader for FakeReader {
        fn read_backlog(&self) -> Result<String, String> {
            Ok(self.doc.clone())
        }
    }

    #[derive(Debug)]
    struct ErrReader;
    impl BacklogReader for ErrReader {
        fn read_backlog(&self) -> Result<String, String> {
            Err("keeperd down".into())
        }
    }

    /// Errors its first `fail_first` reads, then returns `doc` — a transient
    /// keeperd outage that recovers across ticks.
    #[derive(Debug)]
    struct FlakyReader {
        fail_first: Mutex<u32>,
        doc: String,
    }
    impl BacklogReader for FlakyReader {
        fn read_backlog(&self) -> Result<String, String> {
            let mut left = self.fail_first.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err("transient".into());
            }
            Ok(self.doc.clone())
        }
    }

    fn source(reader: Box<dyn BacklogReader>) -> KeeperdQueueSource {
        KeeperdQueueSource { reader, docs: Box::new(FixtureDocs(Ok(None))) }
    }

    /// Every item doc read answers the same scripted result.
    #[derive(Debug)]
    struct FixtureDocs(Result<Option<String>, String>);
    impl ItemDocReader for FixtureDocs {
        fn read_item_doc(&self, _id: &str) -> Result<Option<String>, String> {
            self.0.clone()
        }
    }

    fn with_docs(docs: Result<Option<String>, String>) -> KeeperdQueueSource {
        KeeperdQueueSource { reader: Box::new(ErrReader), docs: Box::new(FixtureDocs(docs)) }
    }

    #[test]
    fn fleet_marker_holds_any_value_but_yes() {
        let doc = "# hover-view-sticky\n\n> Last reviewed: 2026-10-17\n> Fleet: no\n\n## Mission\n";
        assert_eq!(fleet_marker(doc), Some(ClaimHold::HumanOnly("no".into())));
        assert_eq!(fleet_marker("> fleet: No"), Some(ClaimHold::HumanOnly("No".into())));
        // A typo fails closed rather than quietly letting the fleet in.
        assert_eq!(fleet_marker("> Fleet: nope"), Some(ClaimHold::HumanOnly("nope".into())));
        assert_eq!(fleet_marker("> Fleet: yes"), None, "an explicit yes is claimable");
    }

    #[test]
    fn fleet_marker_is_absent_without_a_blockquote_line() {
        assert_eq!(fleet_marker("# t\n\n> Model: claude\n\nFleet: no in prose\n"), None);
        assert_eq!(fleet_marker("Mark it with `> Fleet: no`.\n"), None, "inline code is prose");
        // A fenced example does not mark the doc that shows it.
        assert_eq!(fleet_marker("```\n> Fleet: no\n```\n"), None);
        assert_eq!(
            fleet_marker("```\n> Fleet: no\n```\n> Fleet: no\n"),
            Some(ClaimHold::HumanOnly("no".into())),
            "a real line after the fence still counts",
        );
    }

    #[test]
    fn claim_hold_reads_the_marker_from_the_item_doc() {
        let marked = with_docs(Ok(Some("# x\n> Fleet: no\n".into())));
        assert_eq!(marked.claim_hold("default", "x"), Some(ClaimHold::HumanOnly("no".into())));
        let unmarked = with_docs(Ok(Some("# x\n> Model: claude\n".into())));
        assert_eq!(unmarked.claim_hold("default", "x"), None);
        let no_doc = with_docs(Ok(None));
        assert_eq!(no_doc.claim_hold("default", "x"), None, "no doc, no marker: as before");
    }

    #[test]
    fn an_unreadable_item_doc_holds_fail_closed() {
        let src = with_docs(Err("keeperd Locked: vault is locked".into()));
        assert_eq!(
            src.claim_hold("default", "x"),
            Some(ClaimHold::Unreadable("keeperd Locked: vault is locked".into())),
        );
    }

    #[test]
    fn snapshot_over_a_fixture_reader_matches_the_pure_parse() {
        let doc = region("queue", &item_table(&[("m1", "active"), ("t2", "queued")]));
        let src = source(Box::new(FakeReader { doc: doc.clone() }));
        assert_eq!(src.snapshot(), parse_snapshot(&doc));
    }

    #[test]
    fn a_read_error_idles_with_an_empty_snapshot_not_a_failure() {
        let src = source(Box::new(ErrReader));
        // snapshot() never propagates the error — it returns an empty Snapshot so
        // the drive loop schedules nothing this tick (fail-closed idle).
        assert_eq!(src.snapshot(), Snapshot::default());
    }

    #[test]
    fn a_transient_hiccup_is_ridden_out_then_recovers() {
        let doc = region("queue", &item_table(&[("m1", "queued")]));
        let src = source(Box::new(FlakyReader {
            fail_first: Mutex::new(1),
            doc: doc.clone(),
        }));
        // Tick 1: the read fails -> idle (empty), no scheduling failure surfaced.
        assert_eq!(src.snapshot(), Snapshot::default());
        // Tick 2: keeperd is back -> the real snapshot pulls through.
        assert_eq!(src.snapshot(), parse_snapshot(&doc));
    }

    // ---- task 069: the repo a part lands in --------------------------------

    /// The registry shapes the live backlog carries: a local path (psy) and a
    /// remote one with a note (roadeye). The cell comes back raw.
    #[test]
    fn registry_repo_returns_the_raw_repo_cell_of_a_registered_queue() {
        let registry = "| queue | repo |\n|-------|------|\n\
                        | psy | /home/ukv/projects/psy-website |\n\
                        | roadeye | otg-travel:/srv/roadeye (REMOTE — not on this device) |";
        let doc = format!(
            "{}\n\n{}\n",
            region("queues", registry),
            region("queue", &item_table(&[("d1", "queued")])),
        );
        assert_eq!(registry_repo(&doc, "psy").as_deref(), Some("/home/ukv/projects/psy-website"));
        assert_eq!(
            registry_repo(&doc, "roadeye").as_deref(),
            Some("otg-travel:/srv/roadeye (REMOTE — not on this device)"),
            "raw — resolve_repo is what turns a remote cell into no repo",
        );
        assert_eq!(registry_repo(&doc, "default"), None, "the default queue has no row");
        assert_eq!(registry_repo(&doc, "nope"), None);
        assert_eq!(registry_repo("# no registry here\n", "psy"), None);
        assert_eq!(registry_names(&doc), vec!["psy", "roadeye"], "the queue order is unchanged");
    }

    /// A backlog reader the probe must not touch.
    #[derive(Debug)]
    struct UnreadBacklog;
    impl BacklogReader for UnreadBacklog {
        fn read_backlog(&self) -> Result<String, String> {
            panic!("the registry must not be read here")
        }
    }

    fn repo_probe(
        backlog: Box<dyn BacklogReader>,
        docs: Result<Option<String>, String>,
    ) -> KeeperdRepoProbe {
        KeeperdRepoProbe { backlog, docs: Box::new(FixtureDocs(docs)), home: Some("/home/t".into()) }
    }

    /// A git repo with one committed file and `dirty` untracked ones.
    fn git_repo(dirty: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| softfig_ipc::testing::git(dir.path(), args);
        git(&["init", "-q"]);
        std::fs::write(dir.path().join("base.txt"), "base\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "base"]);
        for i in 0..dirty {
            std::fs::write(dir.path().join(format!("wip{i}.txt")), "wip\n").unwrap();
        }
        dir
    }

    #[test]
    fn the_item_docs_worktree_comes_first_and_skips_the_registry() {
        let repo = git_repo(2);
        let doc = format!("# 069\n> Worktree: `{}`\n", repo.path().display());
        let state = repo_probe(Box::new(UnreadBacklog), Ok(Some(doc))).repo_state("psy", "069");
        assert_eq!(
            state.map(|(path, s)| (path, s.dirty)),
            Some((repo.path().to_path_buf(), 2)),
            "the probed repo's path comes back with its state"
        );

        // A worktree this machine can't probe is no signal — not a registry guess.
        let remote = repo_probe(Box::new(UnreadBacklog), Ok(Some("> Worktree: host:/x\n".into())));
        assert_eq!(remote.repo_state("psy", "069"), None);
    }

    #[test]
    fn the_registry_repo_is_probed_when_the_doc_names_no_worktree() {
        let repo = git_repo(1);
        let registry = format!("| queue | repo |\n|---|---|\n| psy | {} |", repo.path().display());
        let backlog = Box::new(FakeReader { doc: region("queues", &registry) });
        let probe = repo_probe(backlog, Ok(Some("# booking\n> Model: claude\n".into())));
        assert_eq!(probe.repo_state("psy", "booking").map(|(_, s)| s.dirty), Some(1));
        // The default queue has no registry row: no repo until its doc names one.
        assert_eq!(probe.repo_state("default", "booking"), None);
    }

    #[test]
    fn an_unreadable_source_or_repo_is_no_signal() {
        // The item doc failed: whether it names a worktree is unknown.
        let locked = repo_probe(Box::new(UnreadBacklog), Err("Locked".into()));
        assert_eq!(locked.repo_state("psy", "x"), None);
        // The backlog failed.
        assert_eq!(repo_probe(Box::new(ErrReader), Ok(None)).repo_state("psy", "x"), None);
        // The path resolves but is no git repo.
        let not_git = tempfile::tempdir().unwrap();
        let doc = format!("> Worktree: {}\n", not_git.path().display());
        assert_eq!(repo_probe(Box::new(UnreadBacklog), Ok(Some(doc))).repo_state("psy", "x"), None);
    }
}
