//! The §3.4 derived views — read-only markdown renderings of the v2 TOML,
//! upserted as managed regions after every v2 write.
//!
//! - the queue view, region `softfig:queue-v2` in `growlight/backlog/CLAUDE.md`;
//! - the slice-order view, region `softfig:slices-v2` in the milestone's (or
//!   sub-milestone's) `CLAUDE.md`.
//!
//! The renderers are pure: model in, region body out. The presence policy is
//! the verb's (load said `Some` → render; `None` → remove the region) and the
//! mechanics are [`super::write`]'s. Cells escape literal `|` with the same
//! rule as the legacy queue table, and the `#` column is 1-based render-time
//! order — like the legacy table, never parsed back. A view renders only when
//! its TOML file exists (§3.4), so nothing v2-shaped appears in a garden
//! before the first v2 verb creates a file (§11).

use softfig_ipc::queue_v2::{Entry, Lane, SlicesToml, QueueToml};

use crate::actions::growlight::queue;
use crate::actions::growlight::v2::state::milestone_path;

/// Managed-region tag for the derived queue list (§3.4), hosted in the
/// backlog routing doc.
pub const QUEUE_V2_TAG: &str = "queue-v2";

/// Managed-region tag for the derived slice order (§3.4), hosted in the
/// milestone's `CLAUDE.md`.
pub const SLICES_V2_TAG: &str = "slices-v2";

const QUEUE_VIEW_NOTE: &str = "The two-lane list below is derived from `queue.toml` (schema 1). \
keeperd re-renders it after every queue verb; the TOML is the source of truth \
and hand edits to this region are ignored.";

const SLICES_VIEW_NOTE: &str = "The slice order below is derived from `slices.toml` (schema 1). \
keeperd re-renders it after every slices verb; the TOML is the source of truth \
and hand edits to this region are ignored.";

const QUEUE_HEADER: &str = "| # | id | kind | title | project | status | after | branch |";
const QUEUE_SEPARATOR: &str = "|---|----|------|-------|---------|--------|-------|--------|";
const SLICES_HEADER: &str = "| # | kind | id | status | follow_ups |";
const SLICES_SEPARATOR: &str = "|---|------|----|--------|------------|";

/// The doc hosting the queue view (§3.4): the backlog routing doc.
pub fn queue_view_host() -> String {
    crate::actions::growlight::paths::backlog_claude()
}

/// The doc hosting the slices view (§3.3/§3.4): the milestone's own
/// `CLAUDE.md`, routed through the shared [`milestone_path`] so a
/// sub-milestone lands in its `subs/<sub>/` directory.
pub fn slices_view_host(milestone: &str) -> String {
    format!("{}/CLAUDE.md", milestone_path(milestone))
}

/// Render the queue view body: the note, then the urgent lane, then the
/// normal lane, one row per entry in file order (the §3.1 invariant keeps the
/// urgent rows first; the renderer trusts the validator and never re-sorts).
pub fn queue_view(queue: &QueueToml) -> String {
    let mut out = String::from(QUEUE_VIEW_NOTE);
    out.push_str("\n\n### Urgent\n\n");
    lane(&mut out, queue.entries.iter().filter(|e| e.lane == Lane::Urgent));
    out.push_str("### Normal\n\n");
    lane(&mut out, queue.entries.iter().filter(|e| e.lane == Lane::Normal));
    out
}

fn lane<'a>(out: &mut String, rows: impl Iterator<Item = &'a Entry>) {
    out.push_str(QUEUE_HEADER);
    out.push('\n');
    out.push_str(QUEUE_SEPARATOR);
    for (i, e) in rows.enumerate() {
        let after = if e.after.is_empty() {
            "—".to_string()
        } else {
            queue::escape(&e.after.join(", "))
        };
        let branch = if e.branch.is_empty() {
            "—".to_string()
        } else {
            queue::escape(&e.branch)
        };
        // A pending human status change (finding 8, scheduling slice 005) is
        // visible in the view: the row stays `active` until the boundary
        // applies it, and the annotation tells the human the change is
        // recorded, not lost.
        let status = match &e.pending_status {
            Some(p) => format!("{} (pending: {})", e.status, p),
            None => e.status.to_string(),
        };
        out.push_str(&format!(
            "\n| {} | {} | {} | {} | {} | {} | {} | {} |",
            i + 1,
            queue::escape(&e.id),
            queue::escape(&e.kind.to_string()),
            queue::escape(&e.title),
            queue::escape(&e.project),
            queue::escape(&status),
            after,
            branch,
        ));
    }
    out.push('\n');
}

/// Render the slice-order view body: the note, then one row per `[[item]]` in
/// file order — which §3.3 defines as the slice order.
pub fn slices_view(slices: &SlicesToml) -> String {
    let mut out = String::from(SLICES_VIEW_NOTE);
    out.push_str("\n\n");
    out.push_str(SLICES_HEADER);
    out.push('\n');
    out.push_str(SLICES_SEPARATOR);
    for (i, item) in slices.items.iter().enumerate() {
        let follow_ups = match item.follow_ups {
            Some(n) => n.to_string(),
            None => "—".to_string(), // a `sub` item carries none (§3.3)
        };
        out.push_str(&format!(
            "\n| {} | {} | {} | {} | {} |",
            i + 1,
            queue::escape(&item.kind.to_string()),
            queue::escape(&item.id),
            queue::escape(&item.status.to_string()),
            follow_ups,
        ));
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::queue_v2::{
        EntryKind, EntryStatus, Project, SliceItem, SliceKind, SliceStatus,
    };

    fn entry(id: &str, lane: Lane, after: &[&str]) -> Entry {
        Entry {
            id: id.to_string(),
            kind: EntryKind::Milestone,
            title: format!("{id} title"),
            project: "softfig".to_string(),
            lane,
            status: EntryStatus::Queued,
            after: after.iter().map(|s| s.to_string()).collect(),
            added: "2026-10-11T15:04:00Z".to_string(),
            branch: format!("feat/{id}"),
            parent: String::new(),
            base: String::new(),
            claimed: String::new(),
            follow_ups: 0,
            pending_status: None,
        }
    }

    #[test]
    fn queue_view_renders_urgent_before_normal_in_file_order() {
        let q = QueueToml::new(
            vec![Project {
                name: "softfig".to_string(),
                repo: "~/p".to_string(),
                main: "main".to_string(),
            }],
            vec![
                entry("u2", Lane::Urgent, &[]),
                entry("u1", Lane::Urgent, &["u2"]),
                entry("n2", Lane::Normal, &[]),
                entry("n1", Lane::Normal, &["n2"]),
            ],
        );
        let body = queue_view(&q);
        let urgent = body.find("### Urgent").expect("urgent lane");
        let normal = body.find("### Normal").expect("normal lane");
        assert!(urgent < normal, "urgent lane renders first");
        // File order preserved within each lane.
        let u2 = body.find("u2").expect("u2");
        let u1 = body.find("u1").expect("u1");
        assert!(u2 < u1 && u1 < normal, "urgent rows keep file order");
        let n2 = body.find("n2").expect("n2");
        let n1 = body.find("n1").expect("n1");
        assert!(n2 < n1, "normal rows keep file order");
        // The note marks the region as derived.
        assert!(body.contains("derived from `queue.toml`"));
        assert!(body.contains("hand edits to this region are ignored"));
    }

    #[test]
    fn queue_view_cells_show_after_links_branch_and_blanks() {
        let mut linked = entry("a", Lane::Normal, &["x", "y"]);
        linked.kind = EntryKind::Task;
        linked.branch = "fix/012".to_string();
        let mut restack = entry("r", Lane::Urgent, &[]);
        restack.kind = EntryKind::Restack;
        restack.branch = String::new();
        let q = QueueToml::new(vec![], vec![restack, linked]);
        let body = queue_view(&q);
        assert!(body.contains("| x, y |"), "{body}");
        assert!(body.contains("| fix/012 |"), "{body}");
        // A restack has no branch of its own → an em-dash cell.
        assert!(body.contains("| — | — |"), "empty after + branch render dashes, {body}");
        assert!(body.contains("restack"), "{body}");
        assert!(body.contains("task"), "{body}");
    }

    #[test]
    fn queue_view_escapes_pipes_in_cells() {
        let mut piped = entry("a|b", Lane::Normal, &[]);
        piped.title = "title with | pipe".to_string();
        let q = QueueToml::new(vec![], vec![piped]);
        let body = queue_view(&q);
        assert!(body.contains("a\\|b"), "{body}");
        assert!(body.contains("title with \\| pipe"), "{body}");
    }

    #[test]
    fn queue_view_annotates_a_pending_human_status_change() {
        // Finding 8 (scheduling slice 005): the row stays `active` until the
        // handshake applies the human's change; the annotation makes the
        // deferral visible.
        let mut e = entry("a", Lane::Normal, &[]);
        e.status = EntryStatus::Active;
        e.pending_status = Some(EntryStatus::Blocked);
        let q = QueueToml::new(vec![], vec![e]);
        let body = queue_view(&q);
        assert!(body.contains("| active (pending: blocked) |"), "{body}");

        // No pending → the plain status cell, no annotation.
        let mut plain = entry("b", Lane::Normal, &[]);
        plain.status = EntryStatus::Active;
        let body = queue_view(&QueueToml::new(vec![], vec![plain]));
        assert!(body.contains("| active |"), "{body}");
        assert!(!body.contains("(pending:"), "{body}");
    }

    #[test]
    fn slices_view_renders_file_order_and_follow_ups_dash_for_subs() {
        let s = SlicesToml::new(
            "folder-grants".to_string(),
            vec![
                SliceItem {
                    kind: SliceKind::Slice,
                    id: "002".to_string(),
                    status: SliceStatus::Queued,
                    follow_ups: Some(1),
                },
                SliceItem {
                    kind: SliceKind::Slice,
                    id: "001".to_string(),
                    status: SliceStatus::Done,
                    follow_ups: Some(0),
                },
                SliceItem {
                    kind: SliceKind::Sub,
                    id: "fid-pam".to_string(),
                    status: SliceStatus::Queued,
                    follow_ups: None,
                },
            ],
        );
        let body = slices_view(&s);
        // File order is slice order — the view must NOT renumber or reorder.
        let two = body.find("002").expect("002");
        let one = body.find("001").expect("001");
        let sub = body.find("fid-pam").expect("fid-pam");
        assert!(two < one && one < sub, "rows keep file order: {body}");
        assert!(body.contains("| 1 | slice | 002 | queued | 1 |"), "{body}");
        assert!(body.contains("| 3 | sub | fid-pam | queued | — |"), "{body}");
        assert!(body.contains("derived from `slices.toml`"));
    }

    #[test]
    fn view_hosts_route_sub_milestones_through_subs() {
        assert_eq!(queue_view_host(), "growlight/backlog/CLAUDE.md");
        assert_eq!(
            slices_view_host("folder-grants"),
            "growlight/backlog/milestones/folder-grants/CLAUDE.md"
        );
        // Finding 10: a sub-milestone's view host lands in its `subs/` dir.
        assert_eq!(
            slices_view_host("folder-grants/fid-pam"),
            "growlight/backlog/milestones/folder-grants/subs/fid-pam/CLAUDE.md"
        );
    }
}
