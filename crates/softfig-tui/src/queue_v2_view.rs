//! The Growlight tab's queue-v2 two-lane view (queue-v2-git slice 007) — the
//! pure model over a [`QueueShowReply`]: the urgent + normal lanes + a
//! collapsed archive, flattened to navigable rows, and the §6.9 action set
//! (the CLI verbs minus `add`) built as typed, `dry_run`-capable args.
//!
//! Everything here is pure and unit-tested; `app.rs` wires the rows to
//! `ratatui` and the actions to the worker-thread IPC + the confirm overlay.

use std::collections::HashSet;

use softfig_ipc::growlightd::{QueueShowReply, QueueShowTree};
use softfig_ipc::queue_v2::{Lane, SliceStatus};
use softfig_ipc::verbs::{
    op, QueueDropArgs, QueueMoveSpec, QueueStatusArg, QueueUpdateEntryArgs, SliceUpdateArgs,
};

/// The §6.9 action set — the CLI verbs minus `add` (which stays CLI/MCP). Each
/// variant carries the FULL non-dry-run args; the caller issues it with
/// `dry_run: true` first (the reply's `view` previews the result), then again
/// with `dry_run: false` on confirm.
#[derive(Debug, Clone)]
pub enum V2Action {
    EntryUpdate(QueueUpdateEntryArgs),
    Drop(QueueDropArgs),
    SliceUpdate(SliceUpdateArgs),
}

impl V2Action {
    /// The keeperd verb name this action rides.
    pub fn op(&self) -> &'static str {
        match self {
            V2Action::EntryUpdate(_) => op::QUEUE_UPDATE_ENTRY,
            V2Action::Drop(_) => op::QUEUE_DROP,
            V2Action::SliceUpdate(_) => op::SLICE_UPDATE,
        }
    }

    /// Serialize with `dry_run` set, ready to send over the keeperd channel.
    pub fn to_value(&self, dry_run: bool) -> serde_json::Value {
        match self {
            V2Action::EntryUpdate(a) => {
                let mut a = a.clone();
                a.dry_run = dry_run;
                serde_json::to_value(a).expect("queue_update_entry args serialize")
            }
            V2Action::Drop(a) => {
                let mut a = a.clone();
                a.dry_run = dry_run;
                serde_json::to_value(a).expect("queue_drop args serialize")
            }
            V2Action::SliceUpdate(a) => {
                let mut a = a.clone();
                a.dry_run = dry_run;
                serde_json::to_value(a).expect("slice_update args serialize")
            }
        }
    }

    /// The would-be `view` string from a verb reply, decoded by the reply type
    /// this action expects. `value` is the raw `ok` payload.
    pub fn view_from(&self, value: &serde_json::Value) -> Option<String> {
        match self {
            V2Action::EntryUpdate(_) => {
                serde_json::from_value::<softfig_ipc::verbs::QueueUpdateEntryReply>(value.clone())
                    .ok()
                    .map(|r| r.view)
            }
            V2Action::Drop(_) => serde_json::from_value::<softfig_ipc::verbs::QueueDropReply>(
                value.clone(),
            )
            .ok()
            .map(|r| r.view),
            V2Action::SliceUpdate(_) => serde_json::from_value::<softfig_ipc::verbs::SliceUpdateReply>(
                value.clone(),
            )
            .ok()
            .map(|r| r.view),
        }
    }
}

/// The kind of a flattened row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2RowKind {
    /// An urgent-lane entry row.
    Urgent,
    /// A normal-lane entry row.
    Normal,
    /// A slice (or sub-milestone) child of an expanded milestone.
    Slice,
    /// The collapsed/expanded archive section header.
    Archive,
    /// An archive entry row (visible only when the archive is expanded).
    ArchiveEntry,
}

/// One flattened, currently-visible row of the two-lane view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Row {
    pub kind: V2RowKind,
    /// Stable key: the entry id, `"<milestone>/<slice-id>"` for a slice,
    /// `"archive"` for the header, `"archive:<id>"` for an archive entry.
    pub key: String,
    /// The owning entry id (empty for the archive header).
    pub entry_id: String,
    /// The rendered body: entry rows carry `id [project]` + `(open)` + `after`
    /// links; slice rows carry `NNN (kind)`; archive rows carry the id.
    pub label: String,
    /// The status string (entry status, slice status, or archive final status).
    pub status: String,
    pub depth: usize,
    pub expandable: bool,
    pub expanded: bool,
    /// Slice rows: the owning milestone identity + the slice id (`NNN` or the
    /// sub-milestone slug) — the `slice_update` verb's `(milestone, id)`.
    pub milestone: Option<String>,
    pub slice_id: Option<String>,
    /// Whether this entry row is a milestone (expandable to its slice list).
    pub is_milestone: bool,
}

/// The two-lane selection + expansion state. The reply itself lives on `App`
/// (so the detail pane and the `list` gate read it directly); this model only
/// holds where the cursor is and what is expanded, mirroring [`BacklogTree`].
#[derive(Debug, Default)]
pub struct QueueV2View {
    pub selected: usize,
    expanded: HashSet<String>,
    pub archive_expanded: bool,
}

impl QueueV2View {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_expanded(&self, id: &str) -> bool {
        self.expanded.contains(id)
    }

    pub fn expand(&mut self, id: &str) {
        self.expanded.insert(id.to_string());
    }

    pub fn collapse(&mut self, id: &str) {
        self.expanded.remove(id);
    }

    pub fn toggle(&mut self, id: &str) {
        if !self.expanded.remove(id) {
            self.expanded.insert(id.to_string());
        }
    }

    pub fn toggle_archive(&mut self) {
        self.archive_expanded = !self.archive_expanded;
    }

    /// The currently-visible flattened rows for `reply`.
    pub fn rows(&self, reply: &QueueShowReply) -> Vec<V2Row> {
        flatten(reply, &self.expanded, self.archive_expanded)
    }

    pub fn move_up(&mut self, len: usize) {
        self.selected = wrapping_step(self.selected, len, false);
    }

    pub fn move_down(&mut self, len: usize) {
        self.selected = wrapping_step(self.selected, len, true);
    }

    pub fn select(&mut self, index: usize, len: usize) {
        if len > 0 {
            self.selected = index.min(len - 1);
        }
    }

    pub fn clamp(&mut self, len: usize) {
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    /// Drop expansion state for entry ids that no longer exist after a reload.
    pub fn retain(&mut self, live: &HashSet<String>) {
        self.expanded.retain(|id| live.contains(id));
    }
}

fn wrapping_step(selected: usize, len: usize, forward: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if forward {
        if selected + 1 >= len {
            0
        } else {
            selected + 1
        }
    } else if selected == 0 {
        len - 1
    } else {
        selected - 1
    }
}

/// The live entry ids (for [`QueueV2View::retain`]).
pub fn live_entry_ids(reply: &QueueShowReply) -> HashSet<String> {
    reply.entries.iter().map(|e| e.id.clone()).collect()
}

/// The slice tree for a top-level milestone entry, if any.
fn tree_for<'a>(reply: &'a QueueShowReply, entry_id: &str) -> Option<&'a QueueShowTree> {
    reply.trees.iter().find(|t| t.milestone == entry_id)
}

fn flatten(reply: &QueueShowReply, expanded: &HashSet<String>, archive_open: bool) -> Vec<V2Row> {
    let mut out = Vec::new();
    for e in reply.entries.iter().filter(|e| e.lane == "urgent") {
        push_entry(&mut out, reply, expanded, e, V2RowKind::Urgent);
    }
    for e in reply.entries.iter().filter(|e| e.lane == "normal") {
        push_entry(&mut out, reply, expanded, e, V2RowKind::Normal);
    }
    if !reply.archived.is_empty() {
        out.push(V2Row {
            kind: V2RowKind::Archive,
            key: "archive".to_string(),
            entry_id: String::new(),
            label: format!("archive — {} row(s)", reply.archived.len()),
            status: "archive".to_string(),
            depth: 0,
            expandable: true,
            expanded: archive_open,
            milestone: None,
            slice_id: None,
            is_milestone: false,
        });
        if archive_open {
            for a in &reply.archived {
                out.push(V2Row {
                    kind: V2RowKind::ArchiveEntry,
                    key: format!("archive:{}", a.id),
                    entry_id: a.id.clone(),
                    label: a.id.clone(),
                    status: a.status.clone(),
                    depth: 1,
                    expandable: false,
                    expanded: false,
                    milestone: None,
                    slice_id: None,
                    is_milestone: false,
                });
            }
        }
    }
    out
}

fn push_entry(
    out: &mut Vec<V2Row>,
    reply: &QueueShowReply,
    expanded: &HashSet<String>,
    e: &softfig_ipc::growlightd::QueueShowEntry,
    kind: V2RowKind,
) {
    let is_milestone = tree_for(reply, &e.id).is_some();
    let mut label = format!("{} [{}]", e.id, e.project);
    if e.open {
        label.push_str(" (open)");
    }
    if !e.after.is_empty() {
        label.push_str(&format!("  after: {}", e.after.join(", ")));
    }
    out.push(V2Row {
        kind,
        key: e.id.clone(),
        entry_id: e.id.clone(),
        label,
        status: e.status.clone(),
        depth: 0,
        expandable: is_milestone,
        expanded: expanded.contains(&e.id),
        milestone: None,
        slice_id: None,
        is_milestone,
    });
    if expanded.contains(&e.id)
        && let Some(tree) = tree_for(reply, &e.id)
    {
        for s in &tree.slices {
            let kind_label = if s.kind == "sub" { "sub" } else { "" };
            let label = if kind_label.is_empty() {
                s.id.clone()
            } else {
                format!("{} ({})", s.id, kind_label)
            };
            out.push(V2Row {
                kind: V2RowKind::Slice,
                key: format!("{}/{}", e.id, s.id),
                entry_id: e.id.clone(),
                label,
                status: s.status.clone(),
                depth: 1,
                expandable: false,
                expanded: false,
                milestone: Some(e.id.clone()),
                slice_id: Some(s.id.clone()),
                is_milestone: false,
            });
        }
    }
}

// ---- §6.9 action builders (pure; the caller sets dry_run) ------------------

/// The selected row, or `None` (nothing selected). Owned (a `rows()` flatten),
/// so the callers can read `kind`/`entry_id`/… without a borrow into a temp.
fn selected_entry(reply: &QueueShowReply, view: &QueueV2View) -> Option<V2Row> {
    view.rows(reply).into_iter().nth(view.selected)
}

/// Move the selected entry up (`up = true`) or down within its lane. `None`
/// when already at the lane boundary or the selection is not a lane entry.
pub fn entry_move(reply: &QueueShowReply, view: &QueueV2View, up: bool) -> Option<V2Action> {
    let row = selected_entry(reply, view)?;
    if !matches!(row.kind, V2RowKind::Urgent | V2RowKind::Normal) {
        return None;
    }
    let lane = if row.kind == V2RowKind::Urgent { "urgent" } else { "normal" };
    let siblings: Vec<&softfig_ipc::growlightd::QueueShowEntry> =
        reply.entries.iter().filter(|e| e.lane == lane).collect();
    let pos = siblings.iter().position(|e| e.id == row.entry_id)?;
    let (to, ref_id) = if up {
        if pos == 0 {
            return None;
        }
        ("before".to_string(), Some(siblings[pos - 1].id.clone()))
    } else {
        if pos + 1 >= siblings.len() {
            return None;
        }
        ("after".to_string(), Some(siblings[pos + 1].id.clone()))
    };
    Some(V2Action::EntryUpdate(QueueUpdateEntryArgs {
        id: row.entry_id.clone(),
        lane: None,
        move_spec: Some(QueueMoveSpec { to, ref_id }),
        after: None,
        status: None,
        dry_run: false,
    }))
}

/// Toggle the selected entry's lane (`urgent` ↔ `normal`).
pub fn lane_toggle(reply: &QueueShowReply, view: &QueueV2View) -> Option<V2Action> {
    let row = selected_entry(reply, view)?;
    if !matches!(row.kind, V2RowKind::Urgent | V2RowKind::Normal) {
        return None;
    }
    let lane = if row.kind == V2RowKind::Urgent { Lane::Normal } else { Lane::Urgent };
    Some(V2Action::EntryUpdate(QueueUpdateEntryArgs {
        id: row.entry_id.clone(),
        lane: Some(lane),
        move_spec: None,
        after: None,
        status: None,
        dry_run: false,
    }))
}

/// Cycle the selected entry's status through the human statuses
/// `queued → blocked → deferred → done → queued`.
pub fn entry_status_cycle(reply: &QueueShowReply, view: &QueueV2View) -> Option<V2Action> {
    let row = selected_entry(reply, view)?;
    if !matches!(row.kind, V2RowKind::Urgent | V2RowKind::Normal) {
        return None;
    }
    let next = match row.status.as_str() {
        "queued" => QueueStatusArg::Blocked,
        "blocked" => QueueStatusArg::Deferred,
        "deferred" => QueueStatusArg::Done,
        _ => QueueStatusArg::Queued, // done, active, paused, … → queued
    };
    Some(V2Action::EntryUpdate(QueueUpdateEntryArgs {
        id: row.entry_id.clone(),
        lane: None,
        move_spec: None,
        after: None,
        status: Some(next),
        dry_run: false,
    }))
}

/// Replace the selected entry's `after` links (the `edit links` action).
pub fn entry_after(reply: &QueueShowReply, view: &QueueV2View, after: Vec<String>) -> Option<V2Action> {
    let row = selected_entry(reply, view)?;
    if !matches!(row.kind, V2RowKind::Urgent | V2RowKind::Normal) {
        return None;
    }
    Some(V2Action::EntryUpdate(QueueUpdateEntryArgs {
        id: row.entry_id.clone(),
        lane: None,
        move_spec: None,
        after: Some(after),
        status: None,
        dry_run: false,
    }))
}

/// Drop the selected entry (the `drop` action) with `reason`.
pub fn entry_drop(reply: &QueueShowReply, view: &QueueV2View, reason: String) -> Option<V2Action> {
    let row = selected_entry(reply, view)?;
    if !matches!(row.kind, V2RowKind::Urgent | V2RowKind::Normal) {
        return None;
    }
    Some(V2Action::Drop(QueueDropArgs {
        id: row.entry_id.clone(),
        reason,
        dry_run: false,
    }))
}

/// The selected slice row's `(milestone, id)`, when the selection is a
/// `slice` item (a `sub` item carries no slice verb).
fn selected_slice(reply: &QueueShowReply, view: &QueueV2View) -> Option<(String, String)> {
    let row = selected_entry(reply, view)?;
    if row.kind != V2RowKind::Slice {
        return None;
    }
    let milestone = row.milestone.clone()?;
    let id = row.slice_id.clone()?;
    // The sub item's kind is carried on the tree row, not the flattened row;
    // re-derive it so a `sub` item is never addressed as a slice.
    let kind = tree_for(reply, &milestone)
        .and_then(|t| t.slices.iter().find(|s| s.id == id))
        .map(|s| s.kind.as_str());
    if kind == Some("sub") {
        return None;
    }
    Some((milestone, id))
}

/// Move the selected slice up one position within its milestone (before its
/// previous sibling, or `front` when already first).
pub fn slice_move(reply: &QueueShowReply, view: &QueueV2View) -> Option<V2Action> {
    let (milestone, id) = selected_slice(reply, view)?;
    let tree = tree_for(reply, &milestone)?;
    let slices: Vec<&str> = tree
        .slices
        .iter()
        .filter(|s| s.kind == "slice")
        .map(|s| s.id.as_str())
        .collect();
    let pos = slices.iter().position(|s| *s == id)?;
    let (to, ref_id) = if pos == 0 {
        ("front".to_string(), None)
    } else {
        ("before".to_string(), Some(slices[pos - 1].to_string()))
    };
    Some(V2Action::SliceUpdate(SliceUpdateArgs {
        milestone,
        id,
        move_spec: Some(QueueMoveSpec { to, ref_id }),
        status: None,
        dry_run: false,
    }))
}

/// Cycle the selected slice's status through the human statuses
/// `queued → blocked → deferred → done → queued`.
pub fn slice_status_cycle(reply: &QueueShowReply, view: &QueueV2View) -> Option<V2Action> {
    let (milestone, id) = selected_slice(reply, view)?;
    let status = tree_for(reply, &milestone)
        .and_then(|t| t.slices.iter().find(|s| s.id == id))
        .map(|s| s.status.as_str())
        .unwrap_or("queued");
    let next = match status {
        "queued" => SliceStatus::Blocked,
        "blocked" => SliceStatus::Deferred,
        "deferred" => SliceStatus::Done,
        _ => SliceStatus::Queued, // done, active, split → queued
    };
    Some(V2Action::SliceUpdate(SliceUpdateArgs {
        milestone,
        id,
        move_spec: None,
        status: Some(next),
        dry_run: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::growlightd::{QueueShowEntry, QueueShowSlice, QueueShowTree};

    fn entry(id: &str, lane: &str, status: &str, after: &[&str], open: bool) -> QueueShowEntry {
        QueueShowEntry {
            id: id.into(),
            kind: "milestone".into(),
            project: "softfig".into(),
            lane: lane.into(),
            status: status.into(),
            after: after.iter().map(|s| s.to_string()).collect(),
            branch: if open { format!("feat/{id}") } else { String::new() },
            base: String::new(),
            claimed: String::new(),
            open,
        }
    }

    fn slice(id: &str, kind: &str, status: &str) -> QueueShowSlice {
        QueueShowSlice {
            id: id.into(),
            kind: kind.into(),
            status: status.into(),
        }
    }

    fn reply(entries: Vec<QueueShowEntry>, archived: Vec<QueueShowEntry>) -> QueueShowReply {
        QueueShowReply {
            list: true,
            projects: Vec::new(),
            entries,
            archived,
            sessions: Vec::new(),
            trees: vec![QueueShowTree {
                milestone: "m".into(),
                slices: vec![slice("001", "slice", "done"), slice("002", "slice", "queued"), slice("sub-a", "sub", "queued")],
            }],
        }
    }

    #[test]
    fn rows_flatten_lanes_then_archive_with_expansion() {
        // `m` matches the fixture's tree milestone, so it is expandable.
        let r = reply(
            vec![
                entry("u1", "urgent", "active", &[], true),
                entry("m", "normal", "queued", &["done-x"], false),
            ],
            vec![entry("done1", "", "done", &[], false)],
        );
        let mut view = QueueV2View::new();
        let rows = view.rows(&r);
        // urgent first, then normal, then the collapsed archive header.
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(rows[0].key, "u1");
        assert_eq!(rows[0].kind, V2RowKind::Urgent);
        assert!(rows[0].label.contains("(open)"), "{:?}", rows[0].label);
        assert_eq!(rows[1].key, "m");
        assert!(rows[1].label.contains("after: done-x"), "{:?}", rows[1].label);
        assert!(rows[1].expandable, "m is a milestone");
        assert_eq!(rows[2].kind, V2RowKind::Archive);
        assert_eq!(rows[2].label, "archive — 1 row(s)");
        // Expanding the archive reveals its rows.
        view.toggle_archive();
        let rows = view.rows(&r);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[3].kind, V2RowKind::ArchiveEntry);
        assert_eq!(rows[3].entry_id, "done1");
        // Expanding a milestone reveals its slice list.
        view.expand("m");
        let rows = view.rows(&r);
        assert!(rows.iter().any(|x| x.key == "m/001" && x.kind == V2RowKind::Slice));
        assert!(rows.iter().any(|x| x.key == "m/002"));
        assert!(rows.iter().any(|x| x.key == "m/sub-a"));
    }

    #[test]
    fn nav_wraps_at_both_ends() {
        let mut view = QueueV2View::new();
        // Single row: wrap is a no-op.
        view.move_up(1);
        assert_eq!(view.selected, 0);
        view.move_down(1);
        assert_eq!(view.selected, 0);
        // Two rows: wrap top↔bottom.
        view.move_down(2);
        assert_eq!(view.selected, 1);
        view.move_down(2);
        assert_eq!(view.selected, 0, "wraps top↔bottom");
    }

    #[test]
    fn entry_move_stays_in_lane_and_refuses_boundaries() {
        let r = reply(
            vec![
                entry("u1", "urgent", "queued", &[], false),
                entry("u2", "urgent", "queued", &[], false),
                entry("n1", "normal", "queued", &[], false),
            ],
            vec![],
        );
        let mut view = QueueV2View::new();
        view.select(0, 3); // u1 — first in urgent lane
        assert!(entry_move(&r, &view, true).is_none(), "first → no up-move");
        let down = entry_move(&r, &view, false).unwrap();
        let V2Action::EntryUpdate(args) = down else { panic!("expected entry update") };
        assert_eq!(args.id, "u1");
        let m = args.move_spec.unwrap();
        assert_eq!(m.to, "after");
        assert_eq!(m.ref_id.as_deref(), Some("u2"), "stays within the urgent lane");
    }

    #[test]
    fn lane_and_status_cycle() {
        let r = reply(vec![entry("u1", "urgent", "queued", &[], false)], vec![]);
        let view = QueueV2View::new();
        let V2Action::EntryUpdate(args) = lane_toggle(&r, &view).unwrap() else { panic!() };
        assert_eq!(args.lane, Some(Lane::Normal));
        let V2Action::EntryUpdate(args) = entry_status_cycle(&r, &view).unwrap() else { panic!() };
        assert_eq!(args.status, Some(QueueStatusArg::Blocked)); // queued → blocked
        // A non-human status cycles back to `queued`.
        let r = reply(vec![entry("u1", "urgent", "active", &[], false)], vec![]);
        let V2Action::EntryUpdate(args) = entry_status_cycle(&r, &view).unwrap() else { panic!() };
        assert_eq!(args.status, Some(QueueStatusArg::Queued)); // active → queued
    }

    #[test]
    fn slice_move_and_status_address_the_slice() {
        let r = reply(vec![entry("m", "normal", "active", &[], false)], vec![]);
        let mut view = QueueV2View::new();
        view.expand("m");
        let rows = view.rows(&r);
        // Select the second slice ("002").
        let idx = rows.iter().position(|x| x.key == "m/002").unwrap();
        view.select(idx, rows.len());
        let V2Action::SliceUpdate(args) = slice_move(&r, &view).unwrap() else { panic!() };
        assert_eq!((args.milestone.as_str(), args.id.as_str()), ("m", "002"));
        assert_eq!(args.move_spec.as_ref().unwrap().ref_id.as_deref(), Some("001"));
        // A sub item refuses slice verbs.
        let idx = rows.iter().position(|x| x.key == "m/sub-a").unwrap();
        view.select(idx, rows.len());
        assert!(slice_move(&r, &view).is_none());
        assert!(slice_status_cycle(&r, &view).is_none());
    }
}
