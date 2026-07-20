//! Lazy master-tree model for the Browse pane.
//!
//! Children are populated on demand from `list_tree` replies; the visible
//! flat list is recomputed from the expanded set on every render. Pure
//! state — no IO — so it is fully unit-testable.

use std::collections::{HashMap, HashSet};

use softfig_ipc::TreeEntry;

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
}

/// One rendered row of the flattened, currently-visible tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleRow {
    pub path: String,
    pub name: String,
    pub depth: usize,
    pub is_dir: bool,
    pub expanded: bool,
    pub loaded: bool,
}

#[derive(Debug, Default)]
pub struct TreeModel {
    /// Dir path (`""` = garden root) → its children in display order.
    children: HashMap<String, Vec<Node>>,
    expanded: HashSet<String>,
    pub selected: usize,
}

impl TreeModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the children of `dir` from a `list_tree` reply.
    pub fn set_children(&mut self, dir: &str, entries: Vec<TreeEntry>) {
        let nodes = entries
            .into_iter()
            .map(|e| Node {
                name: e.name,
                path: e.path,
                is_dir: e.is_dir,
            })
            .collect();
        self.children.insert(dir.to_string(), nodes);
    }

    pub fn is_loaded(&self, dir: &str) -> bool {
        self.children.contains_key(dir)
    }

    /// Every directory whose children have been fetched — used to refresh
    /// the visible view after a write lands.
    pub fn loaded_dirs(&self) -> Vec<String> {
        self.children.keys().cloned().collect()
    }

    pub fn is_expanded(&self, dir: &str) -> bool {
        self.expanded.contains(dir)
    }

    pub fn expand(&mut self, dir: &str) {
        self.expanded.insert(dir.to_string());
    }

    pub fn collapse(&mut self, dir: &str) {
        self.expanded.remove(dir);
    }

    /// The currently-visible flattened rows, depth-first from root.
    pub fn visible(&self) -> Vec<VisibleRow> {
        let mut out = Vec::new();
        self.push_level("", 0, &mut out);
        out
    }

    fn push_level(&self, dir: &str, depth: usize, out: &mut Vec<VisibleRow>) {
        let Some(nodes) = self.children.get(dir) else {
            return;
        };
        for node in nodes {
            let expanded = node.is_dir && self.expanded.contains(&node.path);
            out.push(VisibleRow {
                path: node.path.clone(),
                name: node.name.clone(),
                depth,
                is_dir: node.is_dir,
                expanded,
                loaded: self.children.contains_key(&node.path),
            });
            if expanded {
                self.push_level(&node.path, depth + 1, out);
            }
        }
    }

    pub fn selected_row(&self) -> Option<VisibleRow> {
        self.visible().into_iter().nth(self.selected)
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        let len = self.visible().len();
        if len > 0 && self.selected + 1 < len {
            self.selected += 1;
        }
    }

    /// Keep `selected` inside the visible range after a structure change.
    pub fn clamp_selection(&mut self) {
        let len = self.visible().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }
}

// ---- growlight backlog tree (milestone → slice) --------------------------
//
// The read-only `7 growlight` left pane is a two-level tree over the backlog
// queue: milestone/task items at depth 0, a milestone's slices at depth 1.
// It mirrors `TreeModel`'s lazy-load shape (`is_loaded`/`set_slices`, children
// fetched on first expand) but carries backlog-native rows (status, slice
// number) rather than `list_tree` dir entries. Nav wraps top↔bottom via the
// shared `wrapping_step` helper (the growlight-tui-detail-pane milestone's
// explicit ask). Pure state — no IO — so it is fully unit-testable.

/// Move a selection index one step, wrapping at both ends (`len == 0` → 0).
/// Shared so the backlog tree's `k`/`j` wrap top↔bottom.
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

/// One slice parsed from a milestone `CLAUDE.md`'s managed slice index. `path`
/// is the link target verbatim (milestone-relative, e.g.
/// `slices/001-backlog-tree.md`) — the caller resolves it against the milestone
/// dir. `reviewed` is the index's Reviewed cell (`None` when blank = not yet
/// reviewed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceRow {
    pub num: String,
    pub title: String,
    pub path: String,
    pub reviewed: Option<String>,
}

const SLICE_INDEX_OPEN: &str = "<!-- softfig:index slices -->";
const SLICE_INDEX_CLOSE: &str = "<!-- /softfig:index slices -->";

/// Parse the slice rows out of a milestone `CLAUDE.md`'s managed slice index
/// (`<!-- softfig:index slices -->` … `<!-- /softfig:index slices -->`). Each
/// data row is `| NNN | [title](slices/NNN-slug.md) | Reviewed |`; the header,
/// separator, and malformed rows are skipped. Pure — no IO.
pub fn parse_slice_index(md: &str) -> Vec<SliceRow> {
    let mut out = Vec::new();
    let mut in_region = false;
    for line in md.lines() {
        let trimmed = line.trim();
        if trimmed.contains(SLICE_INDEX_CLOSE) {
            break;
        }
        if trimmed.contains(SLICE_INDEX_OPEN) {
            in_region = true;
            continue;
        }
        if !in_region || !trimmed.starts_with('|') {
            continue;
        }
        let cells = split_table_row(trimmed);
        if cells.len() != 3 {
            continue;
        }
        if cells[0].eq_ignore_ascii_case("#") {
            continue; // header
        }
        if cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue; // separator
        }
        let Some((title, path)) = parse_md_link(&cells[1]) else {
            continue;
        };
        let reviewed = match cells[2].trim() {
            "" => None,
            r => Some(r.to_string()),
        };
        out.push(SliceRow {
            num: cells[0].clone(),
            title,
            path,
            reviewed,
        });
    }
    out
}

/// Split a `|`-delimited markdown table row into trimmed cell strings,
/// honouring `\|` as a literal pipe (the managed-table escape) and dropping the
/// border pipes.
fn split_table_row(line: &str) -> Vec<String> {
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

/// Extract `(title, target)` from a `[title](target)` markdown link, or `None`.
fn parse_md_link(cell: &str) -> Option<(String, String)> {
    let rest = cell.trim().strip_prefix('[')?;
    let close = rest.find("](")?;
    let title = rest[..close].to_string();
    let target = rest[close + 2..].strip_suffix(')')?;
    Some((title, target.to_string()))
}

/// A slice's status, derived (no backlog schema change) rather than stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceStatus {
    Active,
    AwaitingSmoke,
    Done,
    Queued,
}

impl SliceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SliceStatus::Active => "active",
            SliceStatus::AwaitingSmoke => "awaiting-smoke",
            SliceStatus::Done => "done",
            SliceStatus::Queued => "queued",
        }
    }
}

/// Derive a slice's **file-derived** status:
/// * `awaiting-smoke` — reviewed **and** its file has a `## Deferred
///   verification` section (a manual smoke still owed);
/// * `done` — reviewed, no pending smoke;
/// * `queued` — not yet reviewed.
///
/// The fourth status, `active` (the slice the live baton is working right now),
/// is **not** derived here: it is a live overlay applied by [`BacklogTree::visible`]
/// from [`BacklogTree::set_active`], because it moves as the loop advances and must
/// not clobber the stored file-derived base status.
///
/// `body` is the slice file's contents when loaded (`None` until the right-pane
/// viewer reads it in slice 002, so the awaiting-smoke refinement lights up
/// then).
pub fn derive_slice_status(reviewed: Option<&str>, body: Option<&str>) -> SliceStatus {
    match reviewed {
        None => SliceStatus::Queued,
        Some(_) if matches!(body, Some(b) if b.contains("## Deferred verification")) => {
            SliceStatus::AwaitingSmoke
        }
        Some(_) => SliceStatus::Done,
    }
}

/// Clamp a slice's file-derived status to its parent milestone's **authoritative**
/// queue-table status (task 045).
///
/// [`derive_slice_status`] reads the slice's "Reviewed" cell, but that is a
/// documentation-freshness stamp set when the slice *spec* was authored — it says
/// nothing about whether the code was built. So a milestone that was spec-reviewed
/// during planning but never started has every slice carrying a Reviewed date, and
/// the raw file-derived status would render them all `done`. There is no
/// machine-readable per-slice completion flag in the backlog; completion is tracked
/// only at the milestone level (the queue table). So the honest display status is
/// the file-derived one clamped to the milestone:
///
/// * milestone `done` ⇒ every slice `done`;
/// * milestone `active` ⇒ keep the file-derived status (the only case where
///   per-slice differentiation is real; the live-baton `active` overlay is applied
///   on top by [`BacklogTree::visible`]);
/// * milestone not-started (`queued`/`deferred`/`blocked`/anything else) ⇒ nothing
///   is built yet, so every slice reads `queued` regardless of its Reviewed cell.
pub fn clamp_slice_status(milestone_status: &str, derived: SliceStatus) -> SliceStatus {
    match milestone_status {
        "done" => SliceStatus::Done,
        "active" => derived,
        _ => SliceStatus::Queued,
    }
}

/// A top-level backlog row (milestone or task) in the growlight tree.
#[derive(Debug, Clone)]
pub struct BacklogItem {
    pub id: String,
    pub title: String,
    /// The queue-table status (`active`/`done`/`deferred`/…).
    pub status: String,
    /// Milestones expand to slices; tasks are leaves.
    pub is_milestone: bool,
}

/// A loaded slice child of a milestone, its derived status baked in and its
/// `path` resolved to a full garden path by the caller. `reviewed` is kept so
/// the status can be re-derived once the slice's body loads (the right-pane read
/// lights up awaiting-smoke — see [`BacklogTree::refine_slice_status`]).
#[derive(Debug, Clone)]
pub struct SliceChild {
    pub num: String,
    pub title: String,
    pub path: String,
    pub reviewed: Option<String>,
    pub status: SliceStatus,
}

/// A loop-context doc surfaced as a browsable tree node (a plain garden read):
/// the injected protocol templates, the session policy, the pillar map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopContextNode {
    pub label: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacklogKind {
    Milestone,
    Task,
    Slice,
    /// A loop-context leaf (protocol / session-policy / pillar doc), rendered as
    /// a top-level section after the backlog items.
    LoopContext,
    /// The single LIVE runtime-baton node (slice 004): a growlightd read, not a
    /// garden path, so it carries no `path` and the detail pane sources it from the
    /// polled `BatonReply` rather than a `read_file`.
    RuntimeBaton,
    /// The coordination-bus history node (slice 005): a keeperd `tail_bus` read, not
    /// a garden path, so it carries no `path` and the detail pane sources it from the
    /// eagerly-loaded bus rows rather than a per-select `read_file`.
    Bus,
    /// The assembled injected-context node (slice 006): the operating protocol
    /// (garden arm) + the live runtime baton (growlightd arm), concatenated in
    /// `inject.sh` boot framing = exactly what a fresh session receives at boot. It
    /// carries no single garden `path` (it assembles two artifacts through the
    /// resolver), so the detail pane sources the protocol half from a per-select
    /// keeperd read and the baton half from the polled runtime baton.
    InjectedContext,
}

/// One rendered row of the flattened, currently-visible backlog tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacklogVisibleRow {
    pub kind: BacklogKind,
    /// Stable per-row key: the item id for milestone/task rows, `"<id>#<num>"`
    /// for a slice.
    pub key: String,
    /// The owning milestone/task id (a slice carries its parent's id).
    pub item_id: String,
    pub label: String,
    /// Display status string (queue status, or a slice's derived status).
    pub status: String,
    pub depth: usize,
    pub expandable: bool,
    pub expanded: bool,
    pub loaded: bool,
    /// A slice / loop-context row's full garden path (for the right-pane read).
    pub path: Option<String>,
    /// A slice row's index (`num`), so the right-pane read can refine that
    /// slice's derived status from the loaded body. `None` for non-slice rows.
    pub slice_num: Option<String>,
}

/// The growlight backlog tree: top-level items + lazily-loaded slice children.
#[derive(Debug, Default)]
pub struct BacklogTree {
    items: Vec<BacklogItem>,
    /// Expanded milestone ids.
    expanded: HashSet<String>,
    /// Milestone id → its slice children (present ⇒ loaded).
    slices: HashMap<String, Vec<SliceChild>>,
    /// Loop-context leaves, emitted as a top-level section after the backlog.
    loop_context: Vec<LoopContextNode>,
    /// Whether to emit the single live runtime-baton node (a growlightd read, not
    /// a garden path) after the loop-context section (slice 004).
    runtime_baton: bool,
    /// Whether to emit the coordination-bus history node (a keeperd `tail_bus`
    /// read, not a garden path) after the runtime-baton node (slice 005).
    bus: bool,
    /// Whether to emit the assembled injected-context node (protocol + live baton)
    /// last, after the bus node (slice 006).
    injected_context: bool,
    /// The `(milestone_id, slice_num)` the live runtime baton is actively working
    /// (`IN_PROGRESS` on it), overlaid as `active` by [`Self::visible`]. A live
    /// pointer, not a stored status — it moves with the baton without re-deriving
    /// the file-derived base status. `None` when the loop is idle/at a boundary or
    /// growlightd is unreachable.
    active: Option<(String, String)>,
    pub selected: usize,
}

impl BacklogTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the top-level rows (a fresh queue + milestone classification),
    /// dropping expansion/slice state for ids that no longer exist.
    pub fn set_items(&mut self, items: Vec<BacklogItem>) {
        let live: HashSet<&str> = items.iter().map(|i| i.id.as_str()).collect();
        self.expanded.retain(|id| live.contains(id.as_str()));
        self.slices.retain(|id, _| live.contains(id.as_str()));
        self.items = items;
        self.clamp_selection();
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn is_expanded(&self, id: &str) -> bool {
        self.expanded.contains(id)
    }

    pub fn is_loaded(&self, id: &str) -> bool {
        self.slices.contains_key(id)
    }

    pub fn expand(&mut self, id: &str) {
        self.expanded.insert(id.to_string());
    }

    pub fn collapse(&mut self, id: &str) {
        self.expanded.remove(id);
    }

    /// Record a milestone's slice children from its parsed `CLAUDE.md`.
    pub fn set_slices(&mut self, id: &str, slices: Vec<SliceChild>) {
        self.slices.insert(id.to_string(), slices);
    }

    /// Replace the loop-context section (a static set of garden-read leaves).
    pub fn set_loop_context(&mut self, nodes: Vec<LoopContextNode>) {
        self.loop_context = nodes;
        self.clamp_selection();
    }

    /// Toggle the single live runtime-baton node (slice 004), emitted after the
    /// loop-context section. Off by default so a bare tree (tests, pre-load) has no
    /// growlightd-sourced row; the growlight page turns it on when it rebuilds.
    pub fn set_runtime_baton(&mut self, present: bool) {
        self.runtime_baton = present;
        self.clamp_selection();
    }

    /// Toggle the coordination-bus history node (slice 005), emitted last — after
    /// the runtime-baton node. Off by default so a bare tree (tests, pre-load) has
    /// no keeper-sourced bus row; the growlight page turns it on when it rebuilds.
    pub fn set_bus(&mut self, present: bool) {
        self.bus = present;
        self.clamp_selection();
    }

    /// Toggle the assembled injected-context node (slice 006), emitted last — after
    /// the bus node. Off by default so a bare tree (tests, pre-load) has no assembled
    /// row; the growlight page turns it on when it rebuilds.
    pub fn set_injected_context(&mut self, present: bool) {
        self.injected_context = present;
        self.clamp_selection();
    }

    /// Refine a loaded slice's derived status now that its body is known (the
    /// right-pane read): re-derive so a reviewed slice carrying a `## Deferred
    /// verification` section lights up as awaiting-smoke. No-op if the milestone
    /// or slice isn't loaded.
    pub fn refine_slice_status(&mut self, milestone: &str, num: &str, body: &str) {
        if let Some(children) = self.slices.get_mut(milestone) {
            if let Some(child) = children.iter_mut().find(|c| c.num == num) {
                child.status = derive_slice_status(child.reviewed.as_deref(), Some(body));
            }
        }
    }

    /// Set the slice the live runtime baton is actively working (`(milestone_id,
    /// slice_num)`), overlaid as `active` by [`Self::visible`]. `None` clears it
    /// (loop idle / at an item boundary / baton unreachable). A live overlay — it
    /// does not touch any stored `SliceChild::status`, so the file-derived base
    /// status reappears the moment the baton moves off the slice.
    pub fn set_active(&mut self, active: Option<(String, String)>) {
        self.active = active;
    }

    /// Whether `(milestone, num)` is the live baton's active slice.
    fn is_active_slice(&self, milestone: &str, num: &str) -> bool {
        self.active
            .as_ref()
            .is_some_and(|(m, n)| m == milestone && n == num)
    }

    /// The currently-visible flattened rows: backlog items (with any expanded
    /// slices) first, then the loop-context section.
    pub fn visible(&self) -> Vec<BacklogVisibleRow> {
        let mut out = Vec::new();
        for item in &self.items {
            let expanded = item.is_milestone && self.expanded.contains(&item.id);
            out.push(BacklogVisibleRow {
                kind: if item.is_milestone {
                    BacklogKind::Milestone
                } else {
                    BacklogKind::Task
                },
                key: item.id.clone(),
                item_id: item.id.clone(),
                label: item.title.clone(),
                status: item.status.clone(),
                depth: 0,
                expandable: item.is_milestone,
                expanded,
                loaded: self.slices.contains_key(&item.id),
                path: None,
                slice_num: None,
            });
            if expanded {
                if let Some(children) = self.slices.get(&item.id) {
                    for s in children {
                        // Clamp the stored file-derived status to the parent
                        // milestone's authoritative queue status (task 045): a
                        // spec-reviewed slice of a not-yet-started milestone reads
                        // `queued`, not `done`. `active` is then a live overlay from
                        // the baton pointer, applied on top (only ever set for the
                        // active milestone's slice).
                        let clamped = clamp_slice_status(&item.status, s.status);
                        let status = if self.is_active_slice(&item.id, &s.num) {
                            SliceStatus::Active.as_str()
                        } else {
                            clamped.as_str()
                        };
                        out.push(BacklogVisibleRow {
                            kind: BacklogKind::Slice,
                            key: format!("{}#{}", item.id, s.num),
                            item_id: item.id.clone(),
                            label: format!("{} {}", s.num, s.title),
                            status: status.to_string(),
                            depth: 1,
                            expandable: false,
                            expanded: false,
                            loaded: true,
                            path: Some(s.path.clone()),
                            slice_num: Some(s.num.clone()),
                        });
                    }
                }
            }
        }
        for ctx in &self.loop_context {
            out.push(BacklogVisibleRow {
                kind: BacklogKind::LoopContext,
                key: format!("ctx:{}", ctx.path),
                item_id: String::new(),
                label: ctx.label.clone(),
                status: "context".to_string(),
                depth: 0,
                expandable: false,
                expanded: false,
                loaded: true,
                path: Some(ctx.path.clone()),
                slice_num: None,
            });
        }
        // The live runtime-baton node: a growlightd read (no garden `path`), sourced
        // from the polled `BatonReply` by the detail pane.
        if self.runtime_baton {
            out.push(BacklogVisibleRow {
                kind: BacklogKind::RuntimeBaton,
                key: "runtime-baton".to_string(),
                item_id: String::new(),
                label: "live runtime baton".to_string(),
                status: "live".to_string(),
                depth: 0,
                expandable: false,
                expanded: false,
                loaded: true,
                path: None,
                slice_num: None,
            });
        }
        // The coordination-bus history node: a keeperd `tail_bus` read (no garden
        // `path`), sourced from the eagerly-loaded bus rows.
        if self.bus {
            out.push(BacklogVisibleRow {
                kind: BacklogKind::Bus,
                key: "bus".to_string(),
                item_id: String::new(),
                label: "coordination bus".to_string(),
                status: "history".to_string(),
                depth: 0,
                expandable: false,
                expanded: false,
                loaded: true,
                path: None,
                slice_num: None,
            });
        }
        // The assembled injected-context node closes the tree: protocol (garden arm)
        // + live baton (growlightd arm), no single garden `path` — the detail pane
        // assembles it from a per-select protocol read + the polled runtime baton.
        if self.injected_context {
            out.push(BacklogVisibleRow {
                kind: BacklogKind::InjectedContext,
                key: "injected-context".to_string(),
                item_id: String::new(),
                label: "injected context".to_string(),
                status: "boot-preview".to_string(),
                depth: 0,
                expandable: false,
                expanded: false,
                loaded: true,
                path: None,
                slice_num: None,
            });
        }
        out
    }

    pub fn selected_row(&self) -> Option<BacklogVisibleRow> {
        self.visible().into_iter().nth(self.selected)
    }

    pub fn move_up(&mut self) {
        let len = self.visible().len();
        self.selected = wrapping_step(self.selected, len, false);
    }

    pub fn move_down(&mut self) {
        let len = self.visible().len();
        self.selected = wrapping_step(self.selected, len, true);
    }

    /// Keep `selected` inside the visible range after a collapse/reload.
    pub fn clamp_selection(&mut self) {
        let len = self.visible().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, parent: &str, is_dir: bool) -> TreeEntry {
        let path = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        TreeEntry {
            name: name.to_string(),
            path,
            is_dir,
        }
    }

    #[test]
    fn root_listing_visible() {
        let mut t = TreeModel::new();
        t.set_children(
            "",
            vec![
                entry("meta", "", true),
                entry("CLAUDE.md", "", false),
            ],
        );
        let vis = t.visible();
        assert_eq!(vis.len(), 2);
        assert_eq!(vis[0].name, "meta");
        assert!(vis[0].is_dir);
        assert!(!vis[0].expanded);
        assert!(!vis[1].is_dir);
    }

    #[test]
    fn expand_reveals_children_lazily() {
        let mut t = TreeModel::new();
        t.set_children("", vec![entry("journal", "", true)]);
        // expanded but children not loaded yet → still just the dir row
        t.expand("journal");
        assert_eq!(t.visible().len(), 1);
        assert!(t.visible()[0].expanded);
        assert!(!t.visible()[0].loaded);

        // load children → they appear nested at depth 1
        t.set_children(
            "journal",
            vec![entry("decisions", "journal", true), entry("CLAUDE.md", "journal", false)],
        );
        let vis = t.visible();
        assert_eq!(vis.len(), 3);
        assert_eq!(vis[1].path, "journal/decisions");
        assert_eq!(vis[1].depth, 1);

        // collapse hides them again
        t.collapse("journal");
        assert_eq!(t.visible().len(), 1);
    }

    #[test]
    fn selection_movement_and_clamp() {
        let mut t = TreeModel::new();
        t.set_children("", vec![entry("a", "", false), entry("b", "", false)]);
        assert_eq!(t.selected, 0);
        t.move_up(); // no underflow
        assert_eq!(t.selected, 0);
        t.move_down();
        assert_eq!(t.selected, 1);
        t.move_down(); // no overflow past last
        assert_eq!(t.selected, 1);
        // shrink the tree, selection clamps
        t.set_children("", vec![entry("a", "", false)]);
        t.clamp_selection();
        assert_eq!(t.selected, 0);
    }

    // ---- growlight backlog tree -----------------------------------------

    const SAMPLE_INDEX: &str = "\
# backlog: some milestone

<!-- softfig:index slices -->

| # | Note | Reviewed |
|---|------|----------|
| 001 | [Left pane \\| navigable tree](slices/001-backlog-tree.md) | 2026-07-14 |
| 002 | [Right-pane md viewer](slices/002-right-pane-md-viewer.md) |  |

<!-- /softfig:index slices -->

## Not the index
| 999 | [ignored](slices/999-nope.md) | 2020-01-01 |
";

    #[test]
    fn parse_slice_index_extracts_link_and_reviewed() {
        let rows = parse_slice_index(SAMPLE_INDEX);
        assert_eq!(rows.len(), 2, "only the two in-region rows");
        assert_eq!(rows[0].num, "001");
        // the `\|` escape in the title round-trips to a literal pipe
        assert_eq!(rows[0].title, "Left pane | navigable tree");
        assert_eq!(rows[0].path, "slices/001-backlog-tree.md");
        assert_eq!(rows[0].reviewed.as_deref(), Some("2026-07-14"));
        // a blank Reviewed cell → not-yet-reviewed
        assert_eq!(rows[1].num, "002");
        assert_eq!(rows[1].path, "slices/002-right-pane-md-viewer.md");
        assert_eq!(rows[1].reviewed, None);
    }

    #[test]
    fn parse_slice_index_absent_region_is_empty() {
        assert!(parse_slice_index("# just a doc\n\nno index here").is_empty());
    }

    #[test]
    fn derive_slice_status_each_state() {
        // reviewed + a Deferred verification section → awaiting-smoke
        let smoke = "## Finish criteria\n...\n## Deferred verification\nrun on-device";
        assert_eq!(
            derive_slice_status(Some("2026-07-14"), Some(smoke)),
            SliceStatus::AwaitingSmoke
        );
        // reviewed, no pending smoke → done
        assert_eq!(
            derive_slice_status(Some("2026-07-14"), Some("## Finish criteria\nall unit")),
            SliceStatus::Done
        );
        // reviewed but body not yet loaded → done (no smoke signal)
        assert_eq!(
            derive_slice_status(Some("2026-07-14"), None),
            SliceStatus::Done
        );
        // not reviewed → queued
        assert_eq!(derive_slice_status(None, None), SliceStatus::Queued);
    }

    fn milestone_st(id: &str, title: &str, status: &str) -> BacklogItem {
        BacklogItem {
            id: id.into(),
            title: title.into(),
            status: status.into(),
            is_milestone: true,
        }
    }

    fn milestone(id: &str, title: &str) -> BacklogItem {
        milestone_st(id, title, "deferred")
    }

    fn task(id: &str, title: &str) -> BacklogItem {
        BacklogItem {
            id: id.into(),
            title: title.into(),
            status: "queued".into(),
            is_milestone: false,
        }
    }

    fn slice_child(num: &str) -> SliceChild {
        SliceChild {
            num: num.into(),
            title: format!("slice {num}"),
            path: format!("growlight/backlog/milestones/m/slices/{num}.md"),
            reviewed: None,
            status: SliceStatus::Queued,
        }
    }

    fn ctx(label: &str, path: &str) -> LoopContextNode {
        LoopContextNode {
            label: label.into(),
            path: path.into(),
        }
    }

    #[test]
    fn backlog_tree_expand_collapse_lazily() {
        let mut t = BacklogTree::new();
        t.set_items(vec![milestone("m", "Milestone m"), task("042", "a task")]);
        assert_eq!(t.visible().len(), 2);
        assert!(t.visible()[0].expandable);
        assert!(!t.visible()[1].expandable, "task is a leaf");

        // expand before children load → still just the two rows, marked expanded
        t.expand("m");
        assert_eq!(t.visible().len(), 2);
        assert!(t.visible()[0].expanded);
        assert!(!t.visible()[0].loaded);

        // load slices → they appear nested at depth 1
        t.set_slices("m", vec![slice_child("001"), slice_child("002")]);
        let vis = t.visible();
        assert_eq!(vis.len(), 4);
        assert_eq!(vis[1].kind, BacklogKind::Slice);
        assert_eq!(vis[1].depth, 1);
        assert_eq!(vis[1].item_id, "m");
        assert_eq!(vis[1].key, "m#001");
        assert!(vis[0].loaded);

        // collapse hides them again
        t.collapse("m");
        assert_eq!(t.visible().len(), 2);
    }

    #[test]
    fn backlog_tree_nav_wraps_at_both_ends() {
        let mut t = BacklogTree::new();
        t.set_items(vec![milestone("m", "m"), task("042", "t")]);
        assert_eq!(t.selected, 0);
        // move_up at the top wraps to the last row
        t.move_up();
        assert_eq!(t.selected, 1);
        // move_down at the bottom wraps back to the top
        t.move_down();
        assert_eq!(t.selected, 0);
        // ordinary steps in between
        t.move_down();
        assert_eq!(t.selected, 1);
        t.move_up();
        assert_eq!(t.selected, 0);
    }

    #[test]
    fn loop_context_section_follows_the_backlog_and_carries_paths() {
        let mut t = BacklogTree::new();
        t.set_loop_context(vec![
            ctx("protocol.md", "growlight/protocol.md"),
            ctx("session-policy.md", "growlight/session-policy.md"),
        ]);
        t.set_items(vec![task("042", "t")]);
        let vis = t.visible();
        assert_eq!(vis.len(), 3, "task + 2 loop-context rows");
        assert_eq!(vis[0].kind, BacklogKind::Task);
        assert_eq!(vis[1].kind, BacklogKind::LoopContext);
        assert_eq!(vis[1].label, "protocol.md");
        assert_eq!(vis[1].status, "context");
        assert!(!vis[1].expandable);
        assert_eq!(vis[1].path.as_deref(), Some("growlight/protocol.md"));
        assert_eq!(vis[2].path.as_deref(), Some("growlight/session-policy.md"));
        // Nav wraps across the whole list, backlog + context together.
        assert_eq!(t.selected, 0);
        t.move_up();
        assert_eq!(t.selected, 2, "wrap up from the top lands on the last context row");
    }

    #[test]
    fn runtime_baton_node_closes_the_tree_and_nav_reaches_it() {
        let mut t = BacklogTree::new();
        t.set_loop_context(vec![ctx("protocol.md", "growlight/protocol.md")]);
        t.set_items(vec![task("042", "t")]);
        // Off by default → no baton row.
        assert!(
            t.visible().iter().all(|r| r.kind != BacklogKind::RuntimeBaton),
            "the baton node is off until turned on",
        );
        // Turned on → one node, last, after the loop-context section.
        t.set_runtime_baton(true);
        let vis = t.visible();
        assert_eq!(vis.len(), 3, "task + 1 loop-context + the baton node");
        let last = vis.last().unwrap();
        assert_eq!(last.kind, BacklogKind::RuntimeBaton);
        assert_eq!(last.label, "live runtime baton");
        assert_eq!(last.status, "live");
        assert!(!last.expandable);
        assert_eq!(last.path, None, "a growlightd read carries no garden path");
        // Nav wraps onto it: from the top row, move_up lands on the baton node.
        t.selected = 0;
        t.move_up();
        assert_eq!(t.selected, 2, "wrap-up lands on the last row (the baton node)");
    }

    #[test]
    fn bus_node_closes_the_tree_after_the_baton_and_nav_reaches_it() {
        let mut t = BacklogTree::new();
        t.set_loop_context(vec![ctx("protocol.md", "growlight/protocol.md")]);
        t.set_items(vec![task("042", "t")]);
        t.set_runtime_baton(true);
        // Off by default → no bus row.
        assert!(
            t.visible().iter().all(|r| r.kind != BacklogKind::Bus),
            "the bus node is off until turned on",
        );
        // Turned on → one node, last, after the runtime-baton node.
        t.set_bus(true);
        let vis = t.visible();
        assert_eq!(vis.len(), 4, "task + 1 loop-context + baton + the bus node");
        // The baton node still precedes the bus, which now closes the tree.
        assert_eq!(vis[2].kind, BacklogKind::RuntimeBaton);
        let last = vis.last().unwrap();
        assert_eq!(last.kind, BacklogKind::Bus);
        assert_eq!(last.label, "coordination bus");
        assert_eq!(last.status, "history");
        assert!(!last.expandable);
        assert_eq!(last.path, None, "a keeperd tail_bus read carries no garden path");
        // Nav wraps onto it: from the top row, move_up lands on the bus node.
        t.selected = 0;
        t.move_up();
        assert_eq!(t.selected, 3, "wrap-up lands on the last row (the bus node)");
    }

    #[test]
    fn injected_context_node_closes_the_tree_after_the_bus_and_nav_reaches_it() {
        let mut t = BacklogTree::new();
        t.set_loop_context(vec![ctx("protocol.md", "growlight/protocol.md")]);
        t.set_items(vec![task("042", "t")]);
        t.set_runtime_baton(true);
        t.set_bus(true);
        // Off by default → no injected-context row.
        assert!(
            t.visible().iter().all(|r| r.kind != BacklogKind::InjectedContext),
            "the injected-context node is off until turned on",
        );
        // Turned on → one node, last, after the bus node.
        t.set_injected_context(true);
        let vis = t.visible();
        assert_eq!(vis.len(), 5, "task + 1 loop-context + baton + bus + injected-context");
        // The bus node still precedes it; injected-context now closes the tree.
        assert_eq!(vis[3].kind, BacklogKind::Bus);
        let last = vis.last().unwrap();
        assert_eq!(last.kind, BacklogKind::InjectedContext);
        assert_eq!(last.label, "injected context");
        assert_eq!(last.status, "boot-preview");
        assert!(!last.expandable);
        assert_eq!(last.path, None, "an assembled node carries no garden path");
        // Nav wraps onto it: from the top row, move_up lands on the injected node.
        t.selected = 0;
        t.move_up();
        assert_eq!(t.selected, 4, "wrap-up lands on the last row (the injected-context node)");
    }

    #[test]
    fn refine_slice_status_lights_up_awaiting_smoke_from_the_body() {
        let mut t = BacklogTree::new();
        // Milestone `active` so the file-derived base status shows through the
        // task-045 clamp (a non-active milestone would force every slice `queued`).
        t.set_items(vec![milestone_st("m", "m", "active")]);
        t.expand("m");
        // A reviewed slice whose body isn't loaded reads as done.
        t.set_slices(
            "m",
            vec![SliceChild {
                num: "001".into(),
                title: "s".into(),
                path: "growlight/backlog/milestones/m/slices/001.md".into(),
                reviewed: Some("2026-07-14".into()),
                status: SliceStatus::Done,
            }],
        );
        // Its body arrives with a Deferred verification section → awaiting-smoke.
        t.refine_slice_status("m", "001", "## Finish\n## Deferred verification\nsmoke");
        assert_eq!(t.visible()[1].status, "awaiting-smoke");
        // A body without one keeps it done.
        t.refine_slice_status("m", "001", "## Finish\nall unit-covered");
        assert_eq!(t.visible()[1].status, "done");
        // Unknown milestone/slice is a no-op (no panic).
        t.refine_slice_status("nope", "001", "x");
        t.refine_slice_status("m", "999", "x");
    }

    #[test]
    fn set_active_overlays_active_on_the_baton_slice_without_clobbering_base() {
        let mut t = BacklogTree::new();
        // Milestone `active` so per-slice differentiation + the baton overlay are
        // live (the only regime where the file-derived base is real; task 045).
        t.set_items(vec![milestone_st("m", "m", "active")]);
        t.expand("m");
        t.set_slices(
            "m",
            vec![
                SliceChild {
                    num: "001".into(),
                    title: "s1".into(),
                    path: "growlight/backlog/milestones/m/slices/001.md".into(),
                    reviewed: Some("2026-07-14".into()),
                    status: SliceStatus::Done,
                },
                SliceChild {
                    num: "002".into(),
                    title: "s2".into(),
                    path: "growlight/backlog/milestones/m/slices/002.md".into(),
                    reviewed: None,
                    status: SliceStatus::Queued,
                },
            ],
        );
        // No baton pointer → stored base statuses show through.
        assert_eq!(t.visible()[1].status, "done");
        assert_eq!(t.visible()[2].status, "queued");
        // Baton is IN_PROGRESS on m/002 → that row overlays `active`; 001 unchanged.
        t.set_active(Some(("m".into(), "002".into())));
        assert_eq!(t.visible()[1].status, "done");
        assert_eq!(t.visible()[2].status, "active");
        // A pointer at a different milestone doesn't match here.
        t.set_active(Some(("other".into(), "002".into())));
        assert_eq!(t.visible()[2].status, "queued");
        // Cleared → the base status reappears (no clobber of the stored value).
        t.set_active(None);
        assert_eq!(t.visible()[2].status, "queued");
    }

    #[test]
    fn clamp_slice_status_by_milestone() {
        use SliceStatus::*;
        // Milestone in flight → the file-derived status passes through unchanged.
        assert_eq!(clamp_slice_status("active", Done), Done);
        assert_eq!(clamp_slice_status("active", AwaitingSmoke), AwaitingSmoke);
        assert_eq!(clamp_slice_status("active", Queued), Queued);
        // Milestone finished → every slice is done.
        assert_eq!(clamp_slice_status("done", Queued), Done);
        assert_eq!(clamp_slice_status("done", AwaitingSmoke), Done);
        // Not started (any non-active/done status) → queued, Reviewed cell or not.
        for st in ["queued", "deferred", "blocked", "unknown"] {
            assert_eq!(clamp_slice_status(st, Done), Queued, "{st}");
            assert_eq!(clamp_slice_status(st, AwaitingSmoke), Queued, "{st}");
        }
    }

    #[test]
    fn slice_status_clamps_to_the_parent_milestone_queue_status() {
        // A milestone spec-reviewed during planning but never started: every slice
        // row carries a Reviewed date, so its raw file-derived status is `done` /
        // `awaiting-smoke`. This is the m5e-write-turn case (queued milestone, all
        // slices reviewed 2026-07-01) that task 045 fixes.
        let reviewed_slices = || {
            vec![
                SliceChild {
                    num: "001".into(),
                    title: "s1".into(),
                    path: "growlight/backlog/milestones/m/slices/001.md".into(),
                    reviewed: Some("2026-07-01".into()),
                    status: SliceStatus::Done,
                },
                SliceChild {
                    num: "002".into(),
                    title: "s2".into(),
                    path: "growlight/backlog/milestones/m/slices/002.md".into(),
                    reviewed: Some("2026-07-01".into()),
                    status: SliceStatus::AwaitingSmoke,
                },
            ]
        };

        // queued / deferred / blocked = not started → all slices read `queued`.
        for st in ["queued", "deferred", "blocked"] {
            let mut t = BacklogTree::new();
            t.set_items(vec![milestone_st("m", "m", st)]);
            t.expand("m");
            t.set_slices("m", reviewed_slices());
            let vis = t.visible();
            assert_eq!(vis[1].status, "queued", "milestone {st} → slice 001 queued");
            assert_eq!(vis[2].status, "queued", "milestone {st} → slice 002 queued");
        }

        // done milestone → every slice is done (even one whose body owes a smoke).
        let mut t = BacklogTree::new();
        t.set_items(vec![milestone_st("m", "m", "done")]);
        t.expand("m");
        t.set_slices("m", reviewed_slices());
        let vis = t.visible();
        assert_eq!(vis[1].status, "done");
        assert_eq!(vis[2].status, "done");

        // active milestone → the file-derived base shows through (real per-slice case).
        let mut t = BacklogTree::new();
        t.set_items(vec![milestone_st("m", "m", "active")]);
        t.expand("m");
        t.set_slices("m", reviewed_slices());
        let vis = t.visible();
        assert_eq!(vis[1].status, "done");
        assert_eq!(vis[2].status, "awaiting-smoke");
    }

    #[test]
    fn backlog_tree_set_items_drops_stale_and_clamps() {
        let mut t = BacklogTree::new();
        t.set_items(vec![milestone("m", "m")]);
        t.expand("m");
        t.set_slices("m", vec![slice_child("001")]);
        // select the slice row
        t.move_down();
        assert_eq!(t.selected, 1);
        // reload without milestone m → its expansion/slices drop, selection clamps
        t.set_items(vec![task("042", "t")]);
        assert!(!t.is_expanded("m"));
        assert!(!t.is_loaded("m"));
        assert_eq!(t.visible().len(), 1);
        assert_eq!(t.selected, 0);
    }
}
