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

use softfig_ipc::verbs::{op, ReadFileArgs, ReadFileReply};
use softfig_ipc::{call_reconnecting, Request, Response, RetryPolicy};

use crate::drive_loop::QueueSource;
use crate::scheduler::{PartView, QueueView, Snapshot};

/// The garden-relative backlog doc that hosts every queue's managed region.
pub const BACKLOG_DOC: &str = "growlight/backlog/CLAUDE.md";

/// The scheduler name of the implicit default queue. Matches keeperd's
/// `DEFAULT_QUEUE` / `add_backlog_item`'s implicit queue, so a fleet member
/// pinned to `"default"` resolves to this queue in [`pick`](crate::scheduler::pick).
pub const DEFAULT_QUEUE_NAME: &str = "default";

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

/// Parse a queue item table's rows into [`PartView`]s, in row order. Mirrors
/// keeperd's `queue::parse`: only well-formed 5-cell data rows are kept (`# | id
/// | type | title | status`); the header and separator rows are skipped, and the
/// `#` order cell is discarded (the scheduler relies on row order, not the cell).
/// The status string is classified through [`PartView::new`].
fn parse_item_rows(body: &str) -> Vec<PartView> {
    let mut parts = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells = split_row(line);
        if cells.len() != 5 {
            continue;
        }
        if cells[0] == "#" && cells[1] == "id" {
            continue; // header
        }
        if is_separator_row(&cells) {
            continue;
        }
        parts.push(PartView::new(cells[1].clone(), &cells[4]));
    }
    parts
}

/// Parse the queue registry region's queue names, in row order. Mirrors
/// keeperd's `queues::parse`: 2-cell data rows (`queue | repo`) with a non-empty
/// name, header/separator skipped. Returns just the names — the repo binding is
/// keeperd's concern, not the scheduler's.
fn registry_names(doc: &str) -> Vec<String> {
    let Some(body) = region_body(doc, "queues") else {
        return Vec::new(); // no named queues registered
    };
    let mut names = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells = split_row(line);
        if cells.len() != 2 {
            continue;
        }
        if cells[0] == "queue" && cells[1] == "repo" {
            continue; // header
        }
        if is_separator_row(&cells) {
            continue;
        }
        if cells[0].is_empty() {
            continue;
        }
        names.push(cells[0].clone());
    }
    names
}

/// A markdown table separator row (`|---|---|`): every cell non-empty and made
/// only of `-`/`:`. Mirrors keeperd's row parsers so a hand-edited table parses
/// identically on both sides.
fn is_separator_row(cells: &[String]) -> bool {
    cells
        .iter()
        .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

/// Split one `| a | b | … |` table line into trimmed, `\|`-unescaped cells.
/// A faithful copy of keeperd's `queue::split_row` so escaped pipes in a title
/// round-trip identically.
fn split_row(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                cur.push('|');
                chars.next();
            }
            '|' => {
                cells.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    cells.push(cur.trim().to_string());
    cells
}

/// Extract the inner body of the managed region tagged `tag` — the lines between
/// `<!-- softfig:<tag> -->` and `<!-- /softfig:<tag> -->`, with the one blank pad
/// line on each side stripped, `\n`-joined. `None` when the region is absent.
/// A faithful copy of keeperd's `managed::region_body` (markers matched by their
/// trimmed text, exact line equality, so `queue` / `queues` / `queue:x` never
/// collide).
fn region_body(content: &str, tag: &str) -> Option<String> {
    let open = format!("<!-- softfig:{tag} -->");
    let close = format!("<!-- /softfig:{tag} -->");
    let lines: Vec<&str> = content.split('\n').collect();
    let open_idx = lines.iter().position(|l| l.trim() == open)?;
    let close_rel = lines[open_idx + 1..].iter().position(|l| l.trim() == close)?;
    let close_idx = open_idx + 1 + close_rel;
    let mut body = &lines[open_idx + 1..close_idx];
    while body.first().is_some_and(|l| l.trim().is_empty()) {
        body = &body[1..];
    }
    while body.last().is_some_and(|l| l.trim().is_empty()) {
        body = &body[..body.len() - 1];
    }
    Some(body.join("\n"))
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

/// The live [`QueueSource`]: pull the backlog doc from keeperd each tick and
/// [`parse_snapshot`] it into the multi-queue view the scheduler picks from.
/// Replaces [`crate::drive_loop::DeferredQueues`] in the live assembly
/// ([`crate::fleet::assemble_fleet`]); the deferred default stays the disabled /
/// test seam.
#[derive(Debug)]
pub struct KeeperdQueueSource {
    reader: Box<dyn BacklogReader>,
}

impl KeeperdQueueSource {
    /// Bind the source to keeperd's listen socket (in production the same path
    /// the [`crate::bus::KeeperdBusSource`] tailer reads).
    pub fn new(keeperd_socket: PathBuf) -> Self {
        Self {
            reader: Box::new(KeeperdBacklogReader { keeperd_socket }),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::PartStatus;
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
        KeeperdQueueSource { reader }
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
}
