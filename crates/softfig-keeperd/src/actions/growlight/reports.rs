//! growlight reports — the pillar's filing cabinet for things an agent (or the
//! human) notices but should not silently fix, bury in a baton, or forget: a
//! verb misbehaving, a flaky test, a security gap, docs that drifted, an open
//! question, a blocker, an idea.
//!
//! A report is a numbered doc `growlight/reports/NNN-slug.md` (`.seq`
//! numbering, like `baton-log/`). Everything machine-readable about it is a
//! **semantic tag** on one `> Tags:` line — `namespace:value`, or a bare word:
//!
//! ```text
//! > Tags: type:bug severity:high status:open by:fleet-a item:060 area:softfig-mcp
//! ```
//!
//! A few namespaces carry meaning the daemon enforces; the rest are free-form,
//! so new kinds of report need no code:
//!
//! - `type:` — exactly one, from [`TYPES`] (what kind of report this is);
//! - `severity:` — at most one, from [`SEVERITIES`];
//! - `status:` — daemon-owned lifecycle ([`STATUSES`]), `open` at filing,
//!   moved only by `update_report`;
//! - `by:` — daemon-stamped filer identity;
//! - anything else (`area:`, `item:`, `verb:`, `repo:`, a bare `regression`) —
//!   the caller's vocabulary, queryable with `list_reports`.
//!
//! The routing doc `growlight/reports/CLAUDE.md` carries a daemon-derived
//! `<!-- softfig:reports -->` region — a status summary plus one row per
//! report — re-derived on every report write and on any generic edit that
//! lands in the folder, so like the notes indexes it never needs a hand edit.
//! Unlike `baton-log/` and the bus, reports are durable records and take part
//! in the `[[…]]` backlink graph: a decision a report cites gains a
//! "Referenced by" row pointing back at it.
//!
//! A `blocker`, a `security` report, or anything `severity:critical` also
//! posts one `@human` alert to the coordination bus, so the flag reaches
//! someone instead of only sitting in a folder.

use std::path::Path;

use softfig_fuse::SealedQuery;
use softfig_ipc::verbs::{
    FileReportArgs, FileReportReply, ListReportsArgs, ListReportsReply, ReportRow,
    UpdateReportArgs, UpdateReportReply,
};
use softfig_ipc::ErrorKind;
use softfig_vcs::Intent;

use super::super::{commit_now, conventions, managed, numbering, WorkTree};
use super::{chat, paths};
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{require_unlocked, HandlerResult};

// ---- vocabulary ----------------------------------------------------------

/// The `type:` vocabulary: what kind of report this is, with the one-line
/// meaning the MCP tool description and the routing doc both show.
pub const TYPES: [(&str, &str); 9] = [
    ("bug", "something is broken: wrong output, a crash, lost or corrupted data"),
    ("regression", "worked before, broken now — name the change if known"),
    ("flake", "fails intermittently: a test, a network leg, a race"),
    ("security", "an exposure, a leak, or a trust-boundary gap"),
    ("doc-drift", "docs, spec, or garden say one thing; the code or device another"),
    ("finding", "an observation worth keeping that is not (yet) a defect"),
    ("question", "needs a human decision or answer"),
    ("blocker", "work cannot proceed without a human or external action"),
    ("idea", "an improvement or feature worth considering"),
];

/// The `severity:` scale, most severe first.
pub const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// The `status:` lifecycle: `open` → `triaged` (it has a home — a backlog
/// item, a decision) → one of the closed statuses.
pub const STATUSES: [&str; 5] = ["open", "triaged", "resolved", "wontfix", "duplicate"];

/// Statuses that close a report; moving to one needs a note saying why.
const CLOSED: [&str; 3] = ["resolved", "wontfix", "duplicate"];

/// Types that alert `@human` on filing regardless of severity.
const ALERT_TYPES: [&str; 2] = ["blocker", "security"];

/// Namespaces only the daemon writes.
const DAEMON_NAMESPACES: [&str; 2] = ["status", "by"];

/// The most tags one report may carry.
const MAX_TAGS: usize = 24;

/// Longest accepted title, in characters.
const TITLE_MAX: usize = 160;

/// Managed-region tag of the index in the routing doc.
pub const REPORTS_TAG: &str = "reports";

pub fn reports_dir() -> String {
    format!("{}/reports", paths::PILLAR)
}

pub fn reports_claude() -> String {
    format!("{}/CLAUDE.md", reports_dir())
}

// ---- pure tag core ---------------------------------------------------------

pub mod tags {
    use super::{DAEMON_NAMESPACES, MAX_TAGS, SEVERITIES, STATUSES, TYPES};

    /// The namespace of `tag` (`type` of `type:bug`), `None` for a bare tag.
    pub fn ns(tag: &str) -> Option<&str> {
        tag.split_once(':').map(|(n, _)| n)
    }

    /// The value `tags` carries in namespace `ns`, if any (the first one).
    pub fn value<'a>(tags: &'a [String], ns: &str) -> Option<&'a str> {
        tags.iter()
            .find_map(|t| t.split_once(':').filter(|(n, _)| *n == ns).map(|(_, v)| v))
    }

    fn valid_ns(n: &str) -> bool {
        let mut cs = n.chars();
        n.len() <= 24
            && cs.next().is_some_and(|c| c.is_ascii_lowercase())
            && cs.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }

    fn valid_value(v: &str) -> bool {
        let mut cs = v.chars();
        v.len() <= 64
            && cs.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && cs.all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '/' | '+')
            })
    }

    /// One caller tag, trimmed and lowercased, checked against the grammar:
    /// `namespace:value` (namespace `[a-z][a-z0-9-]*`, ≤24) or a bare value
    /// (`[a-z0-9][a-z0-9._/+-]*`, ≤64). Values in the daemon's own
    /// namespaces are checked against their vocabulary.
    pub fn normalize(raw: &str) -> Result<String, String> {
        let t = raw.trim().to_ascii_lowercase();
        let ok = match t.split_once(':') {
            Some((n, v)) => valid_ns(n) && valid_value(v),
            None => valid_value(&t),
        };
        if !ok {
            return Err(format!(
                "tag {raw:?} is not `namespace:value` or a bare word \
                 (lowercase letters, digits, and - _ . / +)"
            ));
        }
        match t.split_once(':') {
            Some(("type", v)) if !TYPES.iter().any(|(ty, _)| *ty == v) => Err(format!(
                "type:{v} is not a report type — one of: {}",
                TYPES.map(|(ty, _)| ty).join(", ")
            )),
            Some(("severity", v)) if !SEVERITIES.contains(&v) => Err(format!(
                "severity:{v} is not a severity — one of: {}",
                SEVERITIES.join(", ")
            )),
            Some(("status", v)) if !STATUSES.contains(&v) => Err(format!(
                "status:{v} is not a status — one of: {}",
                STATUSES.join(", ")
            )),
            _ => Ok(t),
        }
    }

    /// Normalize a caller tag list, refusing the daemon's own namespaces.
    pub fn normalize_caller(raw: &[String]) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        for r in raw {
            let t = normalize(r)?;
            if let Some(n) = ns(&t).filter(|n| DAEMON_NAMESPACES.contains(n)) {
                return Err(format!(
                    "`{n}:` is stamped by the daemon — {}",
                    if n == "status" {
                        "move it with update_report's `status`"
                    } else {
                        "pass `from` instead"
                    }
                ));
            }
            if !out.contains(&t) {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// The set-level rules: exactly one `type:`, at most one `severity:`,
    /// `status:`, and `by:`, and no more than [`MAX_TAGS`] tags.
    pub fn validate_set(tags: &[String]) -> Result<(), String> {
        let count = |n: &str| tags.iter().filter(|t| ns(t) == Some(n)).count();
        match count("type") {
            1 => {}
            0 => {
                return Err(format!(
                    "a report needs exactly one type: tag — one of: {}",
                    TYPES.map(|(ty, _)| ty).join(", ")
                ))
            }
            _ => return Err("a report carries exactly one type: tag".into()),
        }
        for n in ["severity", "status", "by"] {
            if count(n) > 1 {
                return Err(format!("a report carries at most one {n}: tag"));
            }
        }
        if tags.len() > MAX_TAGS {
            return Err(format!("a report carries at most {MAX_TAGS} tags"));
        }
        Ok(())
    }

    /// Canonical order: `type`, `severity`, `status`, `by`, `item`, then the
    /// rest alphabetically — so the same set always renders the same line.
    pub fn ordered(mut tags: Vec<String>) -> Vec<String> {
        let rank = |t: &str| match ns(t) {
            Some("type") => 0,
            Some("severity") => 1,
            Some("status") => 2,
            Some("by") => 3,
            Some("item") => 4,
            _ => 5,
        };
        tags.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.cmp(b)));
        tags.dedup();
        tags
    }

    /// Add `tag`, replacing the current value of a single-valued namespace
    /// (`type`, `severity`, `status`, `by`).
    pub fn put(tags: &mut Vec<String>, tag: String) {
        if let Some(n) = ns(&tag) {
            if ["type", "severity", "status", "by"].contains(&n) {
                tags.retain(|t| ns(t) != Some(n));
            }
        }
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }

    /// Whether `tags` satisfies one query term: an exact tag, or `ns:*` for
    /// any value in a namespace.
    pub fn matches(tags: &[String], query: &str) -> bool {
        match query.strip_suffix(":*") {
            Some(n) => tags.iter().any(|t| ns(t) == Some(n)),
            None => tags.iter().any(|t| t == query),
        }
    }

    /// Normalize one query term (a tag, or `ns:*`).
    pub fn normalize_query(raw: &str) -> Result<String, String> {
        let t = raw.trim().to_ascii_lowercase();
        match t.strip_suffix(":*") {
            Some(n) if valid_ns(n) => Ok(t),
            Some(_) => Err(format!("query {raw:?}: bad namespace before `:*`")),
            None => normalize(&t),
        }
    }
}

// ---- pure doc core ---------------------------------------------------------

const TAGS_PREFIX: &str = "> Tags:";
const FILED_PREFIX: &str = "> Filed:";
const LOG_HEADING: &str = "Log";

/// A freshly filed report.
pub fn report_doc(title: &str, date: &str, tags: &[String], body: &str) -> String {
    format!(
        "# {title}\n\n\
         > Last reviewed: {date}\n\
         {FILED_PREFIX} {date}\n\
         {TAGS_PREFIX} {}\n\n\
         ## Report\n\n{}\n",
        tags.join(" "),
        body.trim_matches('\n'),
    )
}

/// The tags on a report's `> Tags:` line, `None` if it has none.
pub fn parse_tags(content: &str) -> Option<Vec<String>> {
    content.lines().find_map(|l| {
        l.trim_start()
            .strip_prefix(TAGS_PREFIX)
            .map(|rest| rest.split_whitespace().map(str::to_string).collect())
    })
}

fn parse_filed(content: &str) -> String {
    content
        .lines()
        .find_map(|l| l.trim_start().strip_prefix(FILED_PREFIX))
        .map(|d| d.trim().to_string())
        .unwrap_or_default()
}

/// `content` with its `> Tags:` line rewritten to `tags`; `None` if it has none.
fn with_tags(content: &str, tags: &[String]) -> Option<String> {
    let mut lines: Vec<String> = content.split('\n').map(str::to_string).collect();
    let line = lines.iter_mut().find(|l| l.trim_start().starts_with(TAGS_PREFIX))?;
    *line = format!("{TAGS_PREFIX} {}", tags.join(" "));
    Some(lines.join("\n"))
}

/// `content` with `entry` appended to its `## Log` section (created at the end
/// of the doc on the first update).
fn with_log_entry(content: &str, entry: &str) -> String {
    use crate::actions::sections::edit;
    edit::append_to_section(content, LOG_HEADING, entry)
        .or_else(|_| edit::add_section(content, &format!("## {LOG_HEADING}"), entry))
        .unwrap_or_else(|_| format!("{}\n\n## {LOG_HEADING}\n\n{entry}\n", content.trim_end()))
}

/// The routing doc a first report creates. Navigator: no reviewed stamp; the
/// index region is appended by the first re-derivation.
pub fn reports_claude_stub() -> String {
    let types: Vec<String> = TYPES
        .iter()
        .map(|(ty, meaning)| format!("- `type:{ty}` — {meaning}"))
        .collect();
    format!(
        "# {dir}/\n\n\
         Reports agents (and the human) file about things they notice but should not \
         silently fix or bury in a baton: a verb misbehaving, a flaky test, a security \
         gap, docs that drifted, an open question, a blocker, an idea. One numbered doc \
         per report; every machine-readable fact about it is a **semantic tag** on its \
         `> Tags:` line, so reports can be queried by any combination of tags.\n\n\
         ## Tags\n\n\
         Tags are `namespace:value` or a bare word, lowercase. Four namespaces carry \
         meaning the daemon enforces; every other namespace is yours (`area:`, `item:`, \
         `verb:`, `repo:`, …).\n\n\
         {types}\n\n\
         - `severity:` — optional, one of {sev}.\n\
         - `status:` — daemon-owned: `open` at filing, then `triaged` (it has a home: a \
         backlog item, a decision), then `resolved`, `wontfix`, or `duplicate`.\n\
         - `by:` — daemon-stamped from the filer's `from`.\n\n\
         A blocker, a security report, or anything `severity:critical` also alerts \
         `@human` on the coordination bus.\n\n\
         ## How to behave here\n\n\
         - File with `file_report`, move with `update_report` (closing needs a note: the \
         fixing commit, the task it moved to, the duplicate), query with `list_reports` \
         (`ns:*` matches any value in a namespace). Never edit a report's `> Tags:` line \
         or the index below by hand.\n\
         - A report is not a fix. Turning one into work means a backlog item, then \
         `update_report` to `triaged` with the item named.\n\
         - Don't delete reports — archive them.\n",
        dir = reports_dir(),
        types = types.join("\n"),
        sev = SEVERITIES.map(|s| format!("`{s}`")).join(", "),
    )
}

struct Row {
    number: u32,
    filename: String,
    title: String,
    tags: Vec<String>,
    filed: String,
}

/// Every report in the folder, ascending. Reads go through the read
/// projection like the notes indexes: a whole-file-sealed report shows as
/// `(sealed)` with no tags, and inline `<vault>` regions read as
/// `[encrypted]`, so the unsealed routing doc never carries sealed text.
fn collect(wt: &WorkTree, inner: &DaemonInner) -> Vec<Row> {
    let dir = reports_dir();
    let mut rows = Vec::new();
    for entry in wt.read_dir(&dir) {
        let Some(number) = conventions::parse_note_number(&entry.name) else {
            continue;
        };
        let rel = format!("{dir}/{}", entry.name);
        let (title, tags, filed) = if inner.layer_b.snapshot().is_sealed(&rel) {
            ("(sealed)".to_string(), Vec::new(), String::new())
        } else {
            let bytes = wt.read(&rel).unwrap_or_default();
            let content =
                String::from_utf8(inner.layer_b.redact_regions(&rel, bytes)).unwrap_or_default();
            (
                conventions::note_title(&content)
                    .unwrap_or_else(|| conventions::slug_from_note_name(&entry.name)),
                parse_tags(&content).unwrap_or_default(),
                parse_filed(&content),
            )
        };
        rows.push(Row {
            number,
            filename: entry.name,
            title,
            tags,
            filed,
        });
    }
    rows.sort_by_key(|r| r.number);
    rows
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|")
}

/// The index region body: a status summary, then one row per report.
fn render_index(rows: &[Row]) -> String {
    let status_of = |r: &Row| tags::value(&r.tags, "status").unwrap_or("?").to_string();
    let mut summary: Vec<String> = Vec::new();
    for st in STATUSES {
        let n = rows.iter().filter(|r| status_of(r) == st).count();
        if n > 0 {
            summary.push(format!("{st} {n}"));
        }
    }
    let mut s = format!(
        "_{} report(s){}{}_\n\n\
         | # | Report | Type | Severity | Status | Tags |\n\
         |---|--------|------|----------|--------|------|",
        rows.len(),
        if summary.is_empty() { "" } else { " — " },
        summary.join(" · "),
    );
    for r in rows {
        let rest: Vec<&str> = r
            .tags
            .iter()
            .filter(|t| !matches!(tags::ns(t), Some("type" | "severity" | "status")))
            .map(String::as_str)
            .collect();
        s.push_str(&format!(
            "\n| {:03} | [{}]({}) | {} | {} | {} | {} |",
            r.number,
            cell(&r.title).replace('[', "(").replace(']', ")"),
            r.filename,
            tags::value(&r.tags, "type").unwrap_or(""),
            tags::value(&r.tags, "severity").unwrap_or(""),
            status_of(r),
            cell(&rest.join(" ")),
        ));
    }
    s
}

/// Re-derive the index region in the routing doc from the reports on disk,
/// writing the doc so the caller's in-flight commit folds it in. Best-effort
/// like every index: a missing or vault-protected routing doc is skipped.
/// Returns the routing doc's path when it rewrote it.
pub fn refresh_index(wt: &WorkTree, inner: &DaemonInner) -> Option<String> {
    let host = reports_claude();
    let content = crate::actions::sections::read_if_unprotected(wt, inner, &host)?;
    let rows = collect(wt, inner);
    let new = managed::upsert(&content, REPORTS_TAG, &render_index(&rows));
    if new == content {
        return None;
    }
    wt.write(&host, new.as_bytes()).ok()?;
    Some(host)
}

/// The generic-edit hook (`index::refresh_index_for`): a write landing on the
/// routing doc or on a numbered report re-derives the index, so a hand edit
/// of a report's tags can't leave the table lying.
pub fn refresh_index_for(wt: &WorkTree, inner: &DaemonInner, rel: &str) -> Option<String> {
    let path = Path::new(rel);
    let in_dir = path.parent().and_then(|p| p.to_str()) == Some(reports_dir().as_str());
    let name = path.file_name().and_then(|s| s.to_str())?;
    if in_dir && (name == "CLAUDE.md" || conventions::parse_note_number(name).is_some()) {
        refresh_index(wt, inner)
    } else {
        None
    }
}

// ---- handlers --------------------------------------------------------------

fn bad(msg: String) -> (ErrorKind, String) {
    (ErrorKind::BadArgs, msg)
}

/// A filer/updater identity: one tag value (an agent slug, `human`).
fn identity(from: Option<&str>) -> Result<Option<String>, (ErrorKind, String)> {
    from.map(|f| {
        tags::normalize(f)
            .ok()
            .filter(|t| tags::ns(t).is_none())
            .ok_or_else(|| bad(format!("from {f:?} must be a slug (an agent name or `human`)")))
    })
    .transpose()
}

pub fn file_report(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: FileReportArgs = serde_json::from_value(args)
        .map_err(|e| bad(format!("file_report args: {e}")))?;
    let title = args.title.trim();
    if title.is_empty() || title.contains('\n') || title.chars().count() > TITLE_MAX {
        return Err(bad(format!("title must be one non-empty line of at most {TITLE_MAX} characters")));
    }
    if args.body.trim().is_empty() {
        return Err(bad("body must be non-empty".into()));
    }
    let mut tag_set = tags::normalize_caller(&args.tags).map_err(bad)?;
    if let Some(item) = args.item.as_deref() {
        let t = tags::normalize(&format!("item:{}", item.trim())).map_err(bad)?;
        tags::put(&mut tag_set, t);
    }
    tags::put(&mut tag_set, "status:open".into());
    let by = identity(args.from.as_deref())?;
    if let Some(by) = &by {
        tags::put(&mut tag_set, format!("by:{by}"));
    }
    tags::validate_set(&tag_set).map_err(bad)?;
    let tag_set = tags::ordered(tag_set);
    let slug = match args.slug.as_deref() {
        Some(s) => {
            conventions::validate_slug(s)?;
            s.to_string()
        }
        None => {
            let mut s = conventions::slugify(title);
            s.truncate(48);
            s.trim_end_matches('-').to_string()
        }
    };

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let dir = reports_dir();
    let (rel, number) = {
        let wt = WorkTree::new(daemon, &inner);
        let host = reports_claude();
        if !wt.exists(&host) {
            wt.write(&host, reports_claude_stub().as_bytes())?;
        }
        let number = numbering::next_number(&wt, &dir);
        let rel = format!("{dir}/{}", conventions::note_filename(number, &slug));
        let doc = report_doc(title, &conventions::today_hyphen(), &tag_set, &args.body);
        numbering::write_numbered(&wt, &dir, number, &rel, &doc)?;
        refresh_index(&wt, &inner);
        super::super::backlinks::refresh_all(&wt, &inner);
        (rel, number)
    };

    let kind = tags::value(&tag_set, "type").unwrap_or("").to_string();
    let mut payload = serde_json::json!({ "number": number, "slug": slug, "type": kind });
    if let Some(sev) = tags::value(&tag_set, "severity") {
        payload["severity"] = serde_json::json!(sev);
    }
    let intent = Intent::new("report_filed", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    let alerted = (ALERT_TYPES.contains(&kind.as_str())
        || tags::value(&tag_set, "severity") == Some("critical"))
        && alert_human(daemon, &mut inner, by.as_deref(), number, title, &tag_set, &rel);

    Ok(serde_json::to_value(FileReportReply {
        path: rel,
        number,
        hash: hash.to_string(),
        tags: tag_set,
        alerted,
    })
    .unwrap())
}

/// Post one `@human` alert naming the report, as its own
/// `chat_message_posted` commit after the report's. Best-effort: the report
/// already landed, so a failed post only returns `false`.
fn alert_human(
    daemon: &Daemon,
    inner: &mut DaemonInner,
    by: Option<&str>,
    number: u32,
    title: &str,
    tag_set: &[String],
    rel: &str,
) -> bool {
    let draft = chat::Draft {
        from: by.unwrap_or("growlightd").to_string(),
        to: chat::Recipient::Human,
        kind: chat::MessageKind::Alert,
        body: format!("report #{number:03} [{}] {title} — `{rel}`", tag_set.join(" ")),
    };
    let msg = {
        let wt = WorkTree::new(daemon, inner);
        match chat::append(&wt, &draft, &conventions::now_rfc3339()) {
            Ok(m) => m,
            Err(_) => return false,
        }
    };
    let payload = serde_json::json!({
        "number": msg.number, "from": msg.from, "to": msg.to.to_wire(), "kind": msg.kind.as_wire(),
    });
    Intent::new("chat_message_posted", payload)
        .ok()
        .and_then(|intent| commit_now(inner, intent).ok())
        .is_some()
}

pub fn update_report(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: UpdateReportArgs = serde_json::from_value(args)
        .map_err(|e| bad(format!("update_report args: {e}")))?;
    let by = identity(args.from.as_deref())?;
    let status = args
        .status
        .as_deref()
        .map(|s| tags::normalize(&format!("status:{}", s.trim())))
        .transpose()
        .map_err(bad)?;
    let add = tags::normalize_caller(&args.add_tags).map_err(bad)?;
    let remove: Vec<String> = args
        .remove_tags
        .iter()
        .map(|t| tags::normalize(t))
        .collect::<Result<_, _>>()
        .map_err(bad)?;
    for t in &remove {
        match tags::ns(t) {
            Some("type") => return Err(bad("a report keeps exactly one type: — add the new type instead of removing it".into())),
            Some(n @ ("status" | "by")) => return Err(bad(format!("`{n}:` is daemon-owned and can't be removed"))),
            _ => {}
        }
    }
    let note = args.note.as_deref().map(str::trim).filter(|n| !n.is_empty());
    if note.is_some_and(|n| n.contains('\n')) {
        return Err(bad("note must be one line".into()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let dir = reports_dir();
    let (rel, tag_set, changes) = {
        let wt = WorkTree::new(daemon, &inner);
        let rel = numbering::find_by_id(&wt, &dir, args.number)
            .ok_or_else(|| (ErrorKind::NotFound, format!("{dir}: no report numbered {:03}", args.number)))?;
        let content = crate::actions::sections::load_unprotected(&wt, &inner, &rel)?;
        let before = parse_tags(&content).ok_or_else(|| {
            bad(format!("{rel}: no `> Tags:` line — repair it with patch_file first"))
        })?;

        let mut tag_set = before.clone();
        let mut changes: Vec<String> = Vec::new();
        for t in &remove {
            if !tag_set.contains(t) {
                return Err(bad(format!("{rel}: has no tag {t}")));
            }
            tag_set.retain(|x| x != t);
            changes.push(format!("-{t}"));
        }
        for t in add {
            if !tag_set.contains(&t) {
                tags::put(&mut tag_set, t.clone());
                changes.push(format!("+{t}"));
            }
        }
        if let Some(st) = status {
            let old = tags::value(&before, "status").unwrap_or("?").to_string();
            let new = tags::value(std::slice::from_ref(&st), "status").unwrap_or("?").to_string();
            if old != new {
                if CLOSED.contains(&new.as_str()) && note.is_none() {
                    return Err(bad(format!(
                        "closing a report as {new} needs a note: the fixing commit, the task it \
                         moved to, or the report it duplicates"
                    )));
                }
                tags::put(&mut tag_set, st);
                changes.push(format!("status {old} → {new}"));
            }
        }
        if changes.is_empty() && note.is_none() {
            return Err(bad("nothing to update: pass a status, tags to add or remove, or a note".into()));
        }
        tags::validate_set(&tag_set).map_err(bad)?;
        let tag_set = tags::ordered(tag_set);

        let what = if changes.is_empty() { "note".to_string() } else { changes.join("; ") };
        let entry = format!(
            "- {} · {} · {what}{}",
            conventions::today_hyphen(),
            by.as_deref().unwrap_or("anon"),
            note.map(|n| format!(": {n}")).unwrap_or_default(),
        );
        let next = with_tags(&content, &tag_set).expect("tags line parsed above");
        let next = with_log_entry(&next, &entry);
        let next = crate::actions::sections::edit::set_reviewed(&next, &conventions::today_hyphen())
            .unwrap_or(next);
        wt.write(&rel, next.as_bytes())?;
        refresh_index(&wt, &inner);
        super::super::backlinks::refresh_all(&wt, &inner);
        (rel, tag_set, changes)
    };

    let payload = serde_json::json!({
        "number": args.number,
        "status": tags::value(&tag_set, "status"),
        "changes": changes,
    });
    let intent = Intent::new("report_updated", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;
    Ok(serde_json::to_value(UpdateReportReply {
        path: rel,
        hash: hash.to_string(),
        tags: tag_set,
    })
    .unwrap())
}

pub fn list_reports(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ListReportsArgs = serde_json::from_value(args)
        .map_err(|e| bad(format!("list_reports args: {e}")))?;
    let query: Vec<String> = args
        .tags
        .iter()
        .map(|t| tags::normalize_query(t))
        .collect::<Result<_, _>>()
        .map_err(bad)?;
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let wt = WorkTree::new(daemon, &inner);
    let dir = reports_dir();
    let reports = collect(&wt, &inner)
        .into_iter()
        .filter(|r| query.iter().all(|q| tags::matches(&r.tags, q)))
        .map(|r| ReportRow {
            number: r.number,
            path: format!("{dir}/{}", r.filename),
            title: r.title,
            tags: r.tags,
            filed: r.filed,
        })
        .collect();
    Ok(serde_json::to_value(ListReportsReply { reports }).unwrap())
}

#[cfg(test)]
mod tests {
    use super::tags::*;
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tags_normalize_lowercase_and_check_the_grammar() {
        assert_eq!(normalize(" Area:Softfig-MCP ").unwrap(), "area:softfig-mcp");
        assert_eq!(normalize("verb:edit_section").unwrap(), "verb:edit_section");
        assert_eq!(normalize("regression").unwrap(), "regression");
        assert!(normalize("type:typo").is_err(), "type is a closed vocabulary");
        assert!(normalize("severity:meh").is_err());
        assert!(normalize("has space").is_err());
        assert!(normalize("a:b:c").is_err());
        assert!(normalize(":x").is_err());
        assert!(normalize("").is_err());
    }

    #[test]
    fn caller_tags_cannot_set_daemon_namespaces() {
        assert!(normalize_caller(&v(&["type:bug", "status:resolved"])).is_err());
        assert!(normalize_caller(&v(&["type:bug", "by:someone"])).is_err());
        assert_eq!(
            normalize_caller(&v(&["type:bug", "Type:Bug", "area:x"])).unwrap(),
            v(&["type:bug", "area:x"])
        );
    }

    #[test]
    fn a_report_carries_exactly_one_type() {
        assert!(validate_set(&v(&["area:x"])).is_err());
        assert!(validate_set(&v(&["type:bug", "type:flake"])).is_err());
        assert!(validate_set(&v(&["type:bug", "severity:low", "severity:high"])).is_err());
        assert!(validate_set(&v(&["type:bug", "severity:low", "status:open"])).is_ok());
    }

    #[test]
    fn put_replaces_single_valued_namespaces() {
        let mut t = v(&["type:bug", "severity:low", "area:x"]);
        put(&mut t, "severity:high".into());
        put(&mut t, "type:regression".into());
        put(&mut t, "area:y".into());
        assert_eq!(ordered(t), v(&["type:regression", "severity:high", "area:x", "area:y"]));
    }

    #[test]
    fn queries_match_exact_tags_and_namespace_wildcards() {
        let t = v(&["type:bug", "status:open", "area:fuse"]);
        assert!(matches(&t, "type:bug"));
        assert!(matches(&t, "area:*"));
        assert!(!matches(&t, "severity:*"));
        assert!(!matches(&t, "type:flake"));
        assert_eq!(normalize_query("Area:*").unwrap(), "area:*");
        assert!(normalize_query("type:nope").is_err());
    }

    #[test]
    fn doc_round_trips_its_tags_and_logs_updates() {
        let doc = report_doc("Edit eats the index", "2026-10-10", &v(&["type:bug", "status:open"]), "body");
        assert_eq!(parse_tags(&doc).unwrap(), v(&["type:bug", "status:open"]));
        assert_eq!(parse_filed(&doc), "2026-10-10");
        let doc = with_tags(&doc, &v(&["type:bug", "status:resolved"])).unwrap();
        assert_eq!(parse_tags(&doc).unwrap(), v(&["type:bug", "status:resolved"]));
        let doc = with_log_entry(&doc, "- 2026-10-11 · claude · status open → resolved: fixed");
        let doc = with_log_entry(&doc, "- 2026-10-12 · human · note: confirmed");
        assert!(doc.contains("## Log\n\n- 2026-10-11"), "{doc}");
        assert!(doc.contains("fixed\n- 2026-10-12"), "{doc}");
        assert_eq!(doc.matches("## Log").count(), 1);
    }

    #[test]
    fn index_summarizes_statuses_and_keeps_free_tags() {
        let rows = vec![
            Row {
                number: 1,
                filename: "001-a.md".into(),
                title: "A | pipe [x]".into(),
                tags: v(&["type:bug", "severity:high", "status:open", "area:fuse"]),
                filed: "2026-10-10".into(),
            },
            Row {
                number: 2,
                filename: "002-b.md".into(),
                title: "B".into(),
                tags: v(&["type:idea", "status:resolved"]),
                filed: String::new(),
            },
        ];
        let s = render_index(&rows);
        assert!(s.starts_with("_2 report(s) — open 1 · resolved 1_"), "{s}");
        assert!(s.contains("| 001 | [A \\| pipe (x)](001-a.md) | bug | high | open | area:fuse |"), "{s}");
        assert!(s.contains("| 002 | [B](002-b.md) | idea |  | resolved |  |"), "{s}");
    }

    #[test]
    fn the_stub_lists_every_type() {
        let stub = reports_claude_stub();
        for (ty, _) in TYPES {
            assert!(stub.contains(&format!("`type:{ty}`")), "{ty}");
        }
        assert!(!stub.contains("Last reviewed:"), "navigator docs carry no stamp");
    }
}
