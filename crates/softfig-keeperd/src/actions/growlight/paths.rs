//! growlight pillar path templates, doc templates, and validators.
//!
//! The single source of truth for where every growlight artifact lives and
//! what its daemon-stamped skeleton looks like. The Phase-1 MCP verbs
//! (`log_baton`, `add_backlog_item`, `add_slice`, `set_item_status`) write
//! through here, and the Phase-2 scaffolder (`softfig growlight init`) is
//! meant to reuse the same helpers — spec-growlight.md §11 ("via the same
//! internal machinery as the MCP verbs"). Generalized + lowercase per the
//! garden filename rule; ids are ordinary `[a-z0-9-]` slugs.

use softfig_ipc::ErrorKind;

/// The garden-relative pillar root.
pub const PILLAR: &str = "growlight";

/// Managed-region tag for the authoritative backlog queue table (hosted in
/// `growlight/backlog/CLAUDE.md`). Status + order live only here.
pub const QUEUE_TAG: &str = "queue";

/// The two backlog item kinds.
pub const ITEM_TYPES: [&str; 2] = ["milestone", "task"];
/// The status lattice an item moves through.
pub const STATUSES: [&str; 4] = ["queued", "active", "done", "blocked"];

// ---- path templates ----------------------------------------------------

/// Backlog root. Part of the path vocabulary the Phase-2 `growlight init`
/// scaffolder creates; not yet read by the verbs, which target leaf docs.
#[allow(dead_code)]
pub fn backlog_dir() -> String {
    format!("{PILLAR}/backlog")
}

/// Routing doc that hosts the queue table.
pub fn backlog_claude() -> String {
    format!("{PILLAR}/backlog/CLAUDE.md")
}

/// A milestone's dir. The verbs target [`milestone_claude`] /
/// [`slices_dir`] within it; kept for the Phase-2 scaffolder's reuse.
#[allow(dead_code)]
pub fn milestone_dir(id: &str) -> String {
    format!("{PILLAR}/backlog/milestones/{id}")
}

/// The milestone's mission/finish-criteria doc + slices index host.
pub fn milestone_claude(id: &str) -> String {
    format!("{PILLAR}/backlog/milestones/{id}/CLAUDE.md")
}

/// The milestone's numbered-slices accretive folder.
pub fn slices_dir(id: &str) -> String {
    format!("{PILLAR}/backlog/milestones/{id}/slices")
}

/// Standalone tasks live as numbered notes in one folder.
pub fn tasks_dir() -> String {
    format!("{PILLAR}/backlog/tasks")
}

/// Append-only iteration audit log (numbered notes; never injected).
pub fn baton_log_dir() -> String {
    format!("{PILLAR}/baton-log")
}

// ---- validators --------------------------------------------------------

/// `milestone | task`.
pub fn validate_item_type(ty: &str) -> Result<(), (ErrorKind, String)> {
    if ITEM_TYPES.contains(&ty) {
        Ok(())
    } else {
        Err((
            ErrorKind::BadArgs,
            format!("item_type {ty:?}: must be one of {}", ITEM_TYPES.join(" / ")),
        ))
    }
}

/// `queued | active | done | blocked`.
pub fn validate_status(status: &str) -> Result<(), (ErrorKind, String)> {
    if STATUSES.contains(&status) {
        Ok(())
    } else {
        Err((
            ErrorKind::BadArgs,
            format!("status {status:?}: must be one of {}", STATUSES.join(" / ")),
        ))
    }
}

// ---- doc templates -----------------------------------------------------

/// The backlog routing doc, seeded with an empty queue region so the table
/// always renders under `## Queue`. Created on demand by `add_backlog_item`
/// and idempotently reusable by the Phase-2 scaffolder.
pub fn backlog_claude_stub() -> String {
    let empty = super::queue::render(&[]);
    format!(
        "# {PILLAR}/backlog/\n\n\
         The growlight work queue. Each row is a backlog item the loop drains — a \
         milestone (with ordered slices) or a standalone task. One item is `active` \
         at a time; the loop pulls the next `queued` item by order.\n\n\
         Item docs live in `milestones/<id>/` and `tasks/NNN-<slug>.md`. Status + \
         order are owned by the daemon-managed queue table below — change it only via \
         `add_backlog_item` / `set_item_status`, never by hand.\n\n\
         ## Queue\n\n\
         {}\n\n\
         {}\n\n\
         {}\n",
        super::super::managed::open_marker(QUEUE_TAG),
        empty,
        super::super::managed::close_marker(QUEUE_TAG),
    )
}

/// A milestone's mission/finish-criteria doc. No status line — status lives
/// in the queue table. `add_slice` maintains the `## Slices` index here.
pub fn milestone_doc(id: &str, title: &str, mission: &str, finish: &str) -> String {
    format!(
        "# backlog: {title}\n\n\
         > Milestone `{id}`. Status + queue order live in the backlog queue table \
         (`../../CLAUDE.md`); slices run in order and this item is done only when all \
         are done and integration is verified.\n\n\
         ## Mission\n\n{}\n\n\
         ## Finish criteria\n\n{}\n",
        mission.trim_end_matches('\n'),
        finish.trim_end_matches('\n'),
    )
}

/// A standalone task doc (notes-style: `# title` + reviewed stamp).
pub fn task_doc(title: &str, date_hyphen: &str, mission: &str, finish: &str) -> String {
    format!(
        "# {title}\n\n> Last reviewed: {date_hyphen}\n\n\
         ## Mission\n\n{}\n\n\
         ## Finish criteria\n\n{}\n",
        mission.trim_end_matches('\n'),
        finish.trim_end_matches('\n'),
    )
}

/// One baton-log iteration entry: a `# baton <item> #<iter>` heading, a
/// reviewed stamp, the daemon-stamped metadata block, then the summary body.
#[allow(clippy::too_many_arguments)]
pub fn baton_entry_doc(
    item: &str,
    item_type: &str,
    slice: Option<&str>,
    iteration: u32,
    status: Option<&str>,
    ctx_pct: Option<u32>,
    session_5h_pct: Option<u32>,
    date_hyphen: &str,
    summary: &str,
) -> String {
    let fmt_opt = |o: Option<&str>| o.unwrap_or("—").to_string();
    let fmt_pct = |o: Option<u32>| o.map(|n| format!("{n}%")).unwrap_or_else(|| "—".into());
    format!(
        "# baton {item} #{iteration}\n\n> Last reviewed: {date_hyphen}\n\n\
         - item: `{item}` ({item_type})\n\
         - slice: {}\n\
         - iteration: {iteration}\n\
         - status: {}\n\
         - context: {} · 5h-session: {}\n\n\
         {}\n",
        slice.map(|s| format!("`{s}`")).unwrap_or_else(|| "—".into()),
        fmt_opt(status),
        fmt_pct(ctx_pct),
        fmt_pct(session_5h_pct),
        summary.trim_end_matches('\n'),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::conventions;

    #[test]
    fn paths_are_lowercase_pillar_relative() {
        assert_eq!(backlog_claude(), "growlight/backlog/CLAUDE.md");
        assert_eq!(milestone_dir("m5b"), "growlight/backlog/milestones/m5b");
        assert_eq!(slices_dir("m5b"), "growlight/backlog/milestones/m5b/slices");
        assert_eq!(tasks_dir(), "growlight/backlog/tasks");
        assert_eq!(baton_log_dir(), "growlight/baton-log");
    }

    #[test]
    fn validators_gate_the_closed_sets() {
        assert!(validate_item_type("milestone").is_ok());
        assert!(validate_item_type("task").is_ok());
        assert!(validate_item_type("epic").is_err());
        assert!(validate_status("active").is_ok());
        assert!(validate_status("paused").is_err());
    }

    #[test]
    fn backlog_stub_hosts_an_empty_queue_region() {
        let stub = backlog_claude_stub();
        assert!(stub.contains(&super::super::super::managed::open_marker(QUEUE_TAG)));
        assert!(stub.contains("| # | id | type | title | status |"));
        assert!(stub.contains("## Queue"));
    }

    #[test]
    fn milestone_doc_has_no_status_line() {
        let doc = milestone_doc("m5b", "Zero-knowledge backup", "why", "criteria");
        assert!(doc.starts_with("# backlog: Zero-knowledge backup\n"));
        assert!(doc.contains("## Mission\n\nwhy"));
        assert!(doc.contains("## Finish criteria\n\ncriteria"));
        // Status is owned by the queue table, not the item doc.
        assert!(!doc.contains("status: queued"));
    }

    #[test]
    fn task_doc_is_notes_style() {
        let doc = task_doc("SIGTERM unmount", "2026-06-14", "why", "done when");
        assert!(doc.starts_with("# SIGTERM unmount\n"));
        assert!(doc.contains("> Last reviewed: 2026-06-14\n"));
    }

    #[test]
    fn baton_entry_renders_metadata_and_dashes_for_blanks() {
        let doc = baton_entry_doc(
            "m5b",
            "milestone",
            Some("m5b-1"),
            7,
            Some("IN_PROGRESS"),
            Some(41),
            Some(63),
            "2026-06-14",
            "shipped the secure pipe; see [[journal/decisions/decision-foo]]",
        );
        assert!(doc.starts_with("# baton m5b #7\n"));
        assert!(doc.contains("- slice: `m5b-1`"));
        assert!(doc.contains("- status: IN_PROGRESS"));
        assert!(doc.contains("- context: 41% · 5h-session: 63%"));

        let bare = baton_entry_doc("001", "task", None, 1, None, None, None, "2026-06-14", "x");
        assert!(bare.contains("- slice: —"));
        assert!(bare.contains("- status: —"));
        assert!(bare.contains("- context: — · 5h-session: —"));
    }

    // Keep validators wired to the shared slug rule (ids are lowercase slugs).
    #[test]
    fn ids_reuse_the_slug_charset() {
        assert!(conventions::validate_slug("m5b").is_ok());
        assert!(conventions::validate_slug("M5b").is_err());
    }
}
