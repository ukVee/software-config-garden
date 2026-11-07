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

    /// What the action addresses, for the confirm overlay: the entry id, or
    /// `milestone/slice` for a slice verb. Read from the action itself, never
    /// from the cursor, so the overlay shows what the confirm will hit.
    pub fn target(&self) -> String {
        match self {
            V2Action::EntryUpdate(a) => a.id.clone(),
            V2Action::Drop(a) => a.id.clone(),
            V2Action::SliceUpdate(a) => format!("{}/{}", a.milestone, a.id),
        }
    }

    /// A one-line statement of the change, for the confirm overlay.
    pub fn change(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        match self {
            V2Action::EntryUpdate(a) => {
                if let Some(lane) = a.lane {
                    parts.push(format!("lane → {}", wire_word(&lane)));
                }
                if let Some(m) = &a.move_spec {
                    parts.push(move_words(m));
                }
                if let Some(after) = &a.after {
                    parts.push(format!("after → [{}]", after.join(", ")));
                }
                if let Some(status) = &a.status {
                    parts.push(format!("status → {}", wire_word(status)));
                }
            }
            V2Action::Drop(a) => parts.push(format!("reason: {}", a.reason)),
            V2Action::SliceUpdate(a) => {
                if let Some(m) = &a.move_spec {
                    parts.push(move_words(m));
                }
                if let Some(status) = &a.status {
                    parts.push(format!("status → {}", wire_word(status)));
                }
            }
        }
        parts.join(", ")
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

/// A wire enum's serialized word (`blocked`, `urgent`), so the overlay says
/// what the verb will be sent, not a Rust variant name.
fn wire_word<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn move_words(m: &QueueMoveSpec) -> String {
    match &m.ref_id {
        Some(r) => format!("move {} {r}", m.to),
        None => format!("move {}", m.to),
    }
}

/// The kind of a flattened row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2RowKind {
    /// An urgent-lane entry row.
    Urgent,
    /// A normal-lane entry row.
    Normal,
    /// A slice (or sub-milestone) child of an expanded milestone or sub.
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
    /// Stable key: the entry id, `"<tree>/<slice-id>"` for a slice (for a sub
    /// item that is also its tree's identity),
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
    /// Slice rows: the owning tree's identity + the slice id (`NNN` or the
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

/// The ids an expansion can name: live entries and every tree, sub-trees
/// included (for [`QueueV2View::retain`]).
pub fn live_entry_ids(reply: &QueueShowReply) -> HashSet<String> {
    let entries = reply.entries.iter().map(|e| e.id.clone());
    entries.chain(reply.trees.iter().map(|t| t.milestone.clone())).collect()
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
    if e.open_unknown {
        label.push_str(" (stack unknown)");
    } else if e.open {
        label.push_str(" (open)");
    }
    if let Some(p) = &e.pending_status {
        label.push_str(&format!("  (→ {p} pending)"));
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
        push_tree(out, reply, expanded, &e.id, tree, 1);
    }
}

/// `tree`'s items as rows under `entry_id`, walking into each expanded sub. A
/// sub item's own tree is keyed `<tree>/<id>`, the same string as its row key.
fn push_tree(
    out: &mut Vec<V2Row>,
    reply: &QueueShowReply,
    expanded: &HashSet<String>,
    entry_id: &str,
    tree: &QueueShowTree,
    depth: usize,
) {
    for s in &tree.slices {
        let is_sub = s.kind == "sub";
        let key = format!("{}/{}", tree.milestone, s.id);
        let sub_tree = if is_sub { tree_for(reply, &key) } else { None };
        let open = sub_tree.is_some() && expanded.contains(&key);
        out.push(V2Row {
            kind: V2RowKind::Slice,
            key: key.clone(),
            entry_id: entry_id.to_string(),
            label: if is_sub { format!("{} (sub)", s.id) } else { s.id.clone() },
            status: s.status.clone(),
            depth,
            expandable: sub_tree.is_some(),
            expanded: open,
            milestone: Some(tree.milestone.clone()),
            slice_id: Some(s.id.clone()),
            is_milestone: false,
        });
        if open && let Some(sub) = sub_tree {
            push_tree(out, reply, expanded, entry_id, sub, depth + 1);
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
        fleet: None,
        not_before: None,
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
        fleet: None,
        not_before: None,
        dry_run: false,
    }))
}

/// The human statuses a status picker offers, the same four at both levels
/// (§6.8 entry, §3.3 slice). `active`, `paused` and `split` are daemon-owned
/// and refused by the verbs, so they are never offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanStatus {
    Queued,
    Blocked,
    Deferred,
    Done,
}

impl HumanStatus {
    pub const ALL: [HumanStatus; 4] = [
        HumanStatus::Queued,
        HumanStatus::Blocked,
        HumanStatus::Deferred,
        HumanStatus::Done,
    ];

    /// The wire word, which is also what the rows' `status` carries.
    pub fn word(self) -> &'static str {
        match self {
            HumanStatus::Queued => "queued",
            HumanStatus::Blocked => "blocked",
            HumanStatus::Deferred => "deferred",
            HumanStatus::Done => "done",
        }
    }
}

/// What a status pick addresses, captured when the picker opens (never the
/// cursor row at confirm time — see review 044 V12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusTarget {
    Entry(String),
    Slice { milestone: String, id: String },
}

impl StatusTarget {
    pub fn describe(&self) -> String {
        match self {
            StatusTarget::Entry(id) => format!("entry {id}"),
            StatusTarget::Slice { milestone, id } => format!("slice {milestone}/{id}"),
        }
    }

    /// One line on what picking `status` does, so `done` on an entry is not
    /// mistaken for a label (it archives the entry).
    pub fn hint(&self, status: HumanStatus) -> &'static str {
        match (self, status) {
            (_, HumanStatus::Queued) => "queue it (also unblocks and un-defers)",
            (_, HumanStatus::Blocked) => "hold it out of the pick order",
            (_, HumanStatus::Deferred) => "park it for the human",
            (StatusTarget::Entry(_), HumanStatus::Done) => {
                "archive it (a human override; it leaves the list)"
            }
            (StatusTarget::Slice { .. }, HumanStatus::Done) => "mark the slice done",
        }
    }
}

/// What `s` would change: the selected entry or slice and its current status,
/// or `None` for a row with no status verb (an archive row, a `sub` item).
pub fn status_pick(reply: &QueueShowReply, view: &QueueV2View) -> Option<(StatusTarget, String)> {
    let row = selected_entry(reply, view)?;
    match row.kind {
        V2RowKind::Urgent | V2RowKind::Normal => {
            Some((StatusTarget::Entry(row.entry_id.clone()), row.status.clone()))
        }
        V2RowKind::Slice => {
            let (milestone, id) = selected_slice(reply, view)?;
            Some((StatusTarget::Slice { milestone, id }, row.status.clone()))
        }
        _ => None,
    }
}

/// The action that sets `target` to `status` (the caller sets `dry_run`).
pub fn status_action(target: &StatusTarget, status: HumanStatus) -> V2Action {
    match target {
        StatusTarget::Entry(id) => V2Action::EntryUpdate(QueueUpdateEntryArgs {
            id: id.clone(),
            lane: None,
            move_spec: None,
            after: None,
            status: Some(match status {
                HumanStatus::Queued => QueueStatusArg::Queued,
                HumanStatus::Blocked => QueueStatusArg::Blocked,
                HumanStatus::Deferred => QueueStatusArg::Deferred,
                HumanStatus::Done => QueueStatusArg::Done,
            }),
            fleet: None,
            not_before: None,
            dry_run: false,
        }),
        StatusTarget::Slice { milestone, id } => V2Action::SliceUpdate(SliceUpdateArgs {
            milestone: milestone.clone(),
            id: id.clone(),
            move_spec: None,
            status: Some(match status {
                HumanStatus::Queued => SliceStatus::Queued,
                HumanStatus::Blocked => SliceStatus::Blocked,
                HumanStatus::Deferred => SliceStatus::Deferred,
                HumanStatus::Done => SliceStatus::Done,
            }),
            dry_run: false,
        }),
    }
}

/// The live lane entry `id`, or `None` once a reload has taken it out of the
/// list. The overlay-driven actions (`after`, `drop`) address the id they
/// captured when the overlay opened, never the cursor row at submit time — a
/// reload while the overlay is open moves the rows under the cursor.
fn live_entry<'a>(reply: &'a QueueShowReply, id: &str) -> Option<&'a softfig_ipc::growlightd::QueueShowEntry> {
    reply.entries.iter().find(|e| e.id == id)
}

/// The text the `edit links` overlay opens on: `id`'s current links, so a bare
/// Enter keeps them. Clearing them takes deleting the text.
pub fn after_text(reply: &QueueShowReply, id: &str) -> Option<String> {
    Some(live_entry(reply, id)?.after.join(", "))
}

/// Replace entry `id`'s `after` links (the `edit links` action).
pub fn entry_after(reply: &QueueShowReply, id: &str, after: Vec<String>) -> Option<V2Action> {
    live_entry(reply, id)?;
    Some(V2Action::EntryUpdate(QueueUpdateEntryArgs {
        id: id.to_string(),
        lane: None,
        move_spec: None,
        after: Some(after),
        status: None,
        fleet: None,
        not_before: None,
        dry_run: false,
    }))
}

/// Drop entry `id` (the `drop` action) with `reason`.
pub fn entry_drop(reply: &QueueShowReply, id: &str, reason: String) -> Option<V2Action> {
    live_entry(reply, id)?;
    Some(V2Action::Drop(QueueDropArgs {
        id: id.to_string(),
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

/// Move the selected slice one position up or down within its milestone's
/// slices (a `sub` item is never a sibling). `None` at either boundary.
pub fn slice_move(reply: &QueueShowReply, view: &QueueV2View, up: bool) -> Option<V2Action> {
    let (milestone, id) = selected_slice(reply, view)?;
    let tree = tree_for(reply, &milestone)?;
    let slices: Vec<&str> = tree
        .slices
        .iter()
        .filter(|s| s.kind == "slice")
        .map(|s| s.id.as_str())
        .collect();
    let pos = slices.iter().position(|s| *s == id)?;
    let (to, ref_id) = if up {
        if pos == 0 {
            return None;
        }
        ("before".to_string(), slices[pos - 1].to_string())
    } else {
        if pos + 1 >= slices.len() {
            return None;
        }
        ("after".to_string(), slices[pos + 1].to_string())
    };
    Some(V2Action::SliceUpdate(SliceUpdateArgs {
        milestone,
        id,
        move_spec: Some(QueueMoveSpec { to, ref_id: Some(ref_id) }),
        status: None,
        dry_run: false,
    }))
}

/// `K`/`J`: move the selected row up or down — an entry within its lane, a
/// slice within its milestone.
pub fn move_selected(reply: &QueueShowReply, view: &QueueV2View, up: bool) -> Option<V2Action> {
    match selected_entry(reply, view)?.kind {
        V2RowKind::Slice => slice_move(reply, view, up),
        _ => entry_move(reply, view, up),
    }
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
            pending_status: None,
            open,
            open_unknown: false,
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
    fn a_branch_in_an_unread_repo_is_labelled_unknown_not_closed() {
        let mut wedged = entry("w", "normal", "active", &[], false);
        wedged.branch = "feat/w".into();
        wedged.open_unknown = true;
        let r = reply(vec![wedged], vec![]);
        let rows = QueueV2View::new().rows(&r);
        assert!(rows[0].label.contains("(stack unknown)"), "{:?}", rows[0].label);
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
        assert!(!rows[0].label.contains("stack unknown"), "{:?}", rows[0].label);
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
    fn lane_toggle_flips_the_lane() {
        let r = reply(vec![entry("u1", "urgent", "queued", &[], false)], vec![]);
        let view = QueueV2View::new();
        let V2Action::EntryUpdate(args) = lane_toggle(&r, &view).unwrap() else { panic!() };
        assert_eq!(args.lane, Some(Lane::Normal));
    }

    #[test]
    fn the_status_picker_sets_the_chosen_status_not_the_next_one_in_a_cycle() {
        // A blocked entry used to reach `queued` only by passing through
        // `done`, which archives it.
        let r = reply(vec![entry("u1", "urgent", "blocked", &[], false)], vec![]);
        let view = QueueV2View::new();
        let (target, current) = status_pick(&r, &view).unwrap();
        assert_eq!(target, StatusTarget::Entry("u1".into()));
        assert_eq!(current, "blocked");
        let V2Action::EntryUpdate(args) = status_action(&target, HumanStatus::Queued) else {
            panic!()
        };
        assert_eq!((args.id.as_str(), args.status), ("u1", Some(QueueStatusArg::Queued)));
        // Every offered status maps to its own wire word.
        for s in HumanStatus::ALL {
            let a = status_action(&target, s);
            assert_eq!(a.change(), format!("status → {}", s.word()));
        }
        // An `active` entry is offered the same four; none is `active`.
        let r = reply(vec![entry("u1", "urgent", "active", &[], false)], vec![]);
        let (_, current) = status_pick(&r, &view).unwrap();
        assert_eq!(current, "active");
        assert!(!HumanStatus::ALL.iter().any(|s| s.word() == "active"));
    }

    #[test]
    fn the_status_picker_addresses_slices_and_refuses_sub_items_and_archive_rows() {
        let r = reply(vec![entry("m", "normal", "active", &[], false)], vec![entry("done1", "", "done", &[], false)]);
        let mut view = QueueV2View::new();
        view.expand("m");
        view.toggle_archive();
        let rows = view.rows(&r);
        let at = |key: &str| rows.iter().position(|x| x.key == key).unwrap();
        view.select(at("m/002"), rows.len());
        let (target, current) = status_pick(&r, &view).unwrap();
        assert_eq!(current, "queued");
        assert_eq!(target, StatusTarget::Slice { milestone: "m".into(), id: "002".into() });
        let V2Action::SliceUpdate(args) = status_action(&target, HumanStatus::Deferred) else {
            panic!()
        };
        assert_eq!((args.milestone.as_str(), args.id.as_str()), ("m", "002"));
        assert_eq!(args.status, Some(SliceStatus::Deferred));
        view.select(at("m/sub-a"), rows.len());
        assert!(status_pick(&r, &view).is_none(), "a sub item has no slice verb");
        view.select(at("archive:done1"), rows.len());
        assert!(status_pick(&r, &view).is_none(), "an archive row is not editable");
    }

    /// A reply whose `m` holds a sub `m/sub-a`, which repeats slice `001`.
    fn reply_with_a_sub() -> QueueShowReply {
        let mut r = reply(vec![entry("m", "normal", "active", &[], false)], vec![]);
        r.trees.push(QueueShowTree {
            milestone: "m/sub-a".into(),
            slices: vec![slice("001", "slice", "queued"), slice("002", "slice", "queued")],
        });
        r
    }

    #[test]
    fn a_sub_expands_to_its_own_slices_and_they_address_its_tree() {
        let r = reply_with_a_sub();
        let mut view = QueueV2View::new();
        view.expand("m");
        let rows = view.rows(&r);
        let sub = rows.iter().find(|x| x.key == "m/sub-a").unwrap();
        assert!(sub.expandable && !sub.expanded, "{sub:?}");
        assert!(!rows.iter().any(|x| x.key == "m/sub-a/001"), "collapsed");

        view.expand("m/sub-a");
        let rows = view.rows(&r);
        let at = |key: &str| rows.iter().position(|x| x.key == key).unwrap();
        let child = &rows[at("m/sub-a/001")];
        assert_eq!(child.depth, 2);
        assert_eq!(child.entry_id, "m");
        assert_eq!(child.milestone.as_deref(), Some("m/sub-a"));

        view.select(at("m/sub-a/002"), rows.len());
        let V2Action::SliceUpdate(args) = slice_move(&r, &view, true).unwrap() else { panic!() };
        assert_eq!((args.milestone.as_str(), args.id.as_str()), ("m/sub-a", "002"));
    }

    #[test]
    fn a_sub_with_no_tree_in_the_reply_is_not_expandable() {
        let r = reply(vec![entry("m", "normal", "active", &[], false)], vec![]);
        let mut view = QueueV2View::new();
        view.expand("m");
        let rows = view.rows(&r);
        assert!(!rows.iter().find(|x| x.key == "m/sub-a").unwrap().expandable);
    }

    #[test]
    fn a_reload_keeps_an_open_sub_open() {
        let r = reply_with_a_sub();
        let mut view = QueueV2View::new();
        view.expand("m");
        view.expand("m/sub-a");
        view.retain(&live_entry_ids(&r));
        assert!(view.is_expanded("m/sub-a"));
    }

    #[test]
    fn slices_move_down_as_well_as_up_and_stop_at_the_ends() {
        let r = reply(vec![entry("m", "normal", "active", &[], false)], vec![]);
        let mut view = QueueV2View::new();
        view.expand("m");
        let rows = view.rows(&r);
        let at = |key: &str| rows.iter().position(|x| x.key == key).unwrap();
        // The fixture's slices are 001, 002 (sub-a is not a sibling).
        view.select(at("m/002"), rows.len());
        let V2Action::SliceUpdate(args) = slice_move(&r, &view, true).unwrap() else { panic!() };
        assert_eq!((args.milestone.as_str(), args.id.as_str()), ("m", "002"));
        let mv = args.move_spec.unwrap();
        assert_eq!((mv.to.as_str(), mv.ref_id.as_deref()), ("before", Some("001")));
        assert!(slice_move(&r, &view, false).is_none(), "last slice has no down-move");
        view.select(at("m/001"), rows.len());
        assert!(slice_move(&r, &view, true).is_none(), "first slice has no up-move");
        let V2Action::SliceUpdate(args) = slice_move(&r, &view, false).unwrap() else { panic!() };
        assert_eq!(args.id, "001");
        let mv = args.move_spec.unwrap();
        assert_eq!((mv.to.as_str(), mv.ref_id.as_deref()), ("after", Some("002")));
        // K/J on a slice row routes to the slice verb, not the entry one.
        assert!(matches!(move_selected(&r, &view, false), Some(V2Action::SliceUpdate(_))));
        view.select(at("m"), rows.len());
        assert!(move_selected(&r, &view, false).is_none(), "a lone entry has no sibling");
    }

    #[test]
    fn a_pending_status_is_shown_on_the_row() {
        let mut e = entry("u1", "urgent", "active", &[], false);
        e.pending_status = Some("blocked".into());
        let r = reply(vec![e], vec![]);
        let rows = QueueV2View::new().rows(&r);
        assert!(rows[0].label.contains("→ blocked pending"), "{:?}", rows[0].label);
    }

    #[test]
    fn the_confirm_overlay_names_the_op_the_target_and_the_change() {
        let r = reply(vec![entry("u1", "urgent", "queued", &[], false)], vec![]);
        let view = QueueV2View::new();
        let status = status_action(&StatusTarget::Entry("u1".into()), HumanStatus::Blocked);
        assert_eq!(status.op(), op::QUEUE_UPDATE_ENTRY);
        assert_eq!(status.target(), "u1");
        assert_eq!(status.change(), "status → blocked");
        let drop = entry_drop(&r, "u1", "obsolete".into()).unwrap();
        assert_eq!(drop.op(), op::QUEUE_DROP);
        assert_eq!(drop.target(), "u1");
        assert_eq!(drop.change(), "reason: obsolete");
        let after = entry_after(&r, "u1", vec!["x".into(), "y".into()]).unwrap();
        assert_eq!(after.change(), "after → [x, y]");
        let mv = entry_move(&reply(vec![entry("a", "normal", "queued", &[], false), entry("b", "normal", "queued", &[], false)], vec![]), &view, false).unwrap();
        assert_eq!(mv.change(), "move after b");
    }

    #[test]
    fn a_drop_or_edit_for_an_entry_that_left_the_list_is_none() {
        let r = reply(vec![entry("u1", "urgent", "queued", &[], false)], vec![]);
        assert!(entry_drop(&r, "gone", "r".into()).is_none());
        assert!(entry_after(&r, "gone", vec![]).is_none());
    }
}
