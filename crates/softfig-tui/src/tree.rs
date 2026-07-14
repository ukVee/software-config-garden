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

/// Derive a slice's status:
/// * `active` — it is the live baton's active slice (`is_active`, wired by the
///   growlightd `baton` verb in slice 004);
/// * `awaiting-smoke` — reviewed **and** its file has a `## Deferred
///   verification` section (a manual smoke still owed);
/// * `done` — reviewed, no pending smoke;
/// * `queued` — not yet reviewed.
///
/// `body` is the slice file's contents when loaded (`None` until the right-pane
/// viewer reads it in slice 002, so the awaiting-smoke refinement lights up
/// then).
pub fn derive_slice_status(
    is_active: bool,
    reviewed: Option<&str>,
    body: Option<&str>,
) -> SliceStatus {
    if is_active {
        return SliceStatus::Active;
    }
    match reviewed {
        None => SliceStatus::Queued,
        Some(_) if matches!(body, Some(b) if b.contains("## Deferred verification")) => {
            SliceStatus::AwaitingSmoke
        }
        Some(_) => SliceStatus::Done,
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
/// `path` resolved to a full garden path by the caller.
#[derive(Debug, Clone)]
pub struct SliceChild {
    pub num: String,
    pub title: String,
    pub path: String,
    pub status: SliceStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacklogKind {
    Milestone,
    Task,
    Slice,
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
    /// A slice row's full garden path (for the slice-002 right-pane read).
    pub path: Option<String>,
}

/// The growlight backlog tree: top-level items + lazily-loaded slice children.
#[derive(Debug, Default)]
pub struct BacklogTree {
    items: Vec<BacklogItem>,
    /// Expanded milestone ids.
    expanded: HashSet<String>,
    /// Milestone id → its slice children (present ⇒ loaded).
    slices: HashMap<String, Vec<SliceChild>>,
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

    /// The currently-visible flattened rows, items then any expanded slices.
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
            });
            if expanded {
                if let Some(children) = self.slices.get(&item.id) {
                    for s in children {
                        out.push(BacklogVisibleRow {
                            kind: BacklogKind::Slice,
                            key: format!("{}#{}", item.id, s.num),
                            item_id: item.id.clone(),
                            label: format!("{} {}", s.num, s.title),
                            status: s.status.as_str().to_string(),
                            depth: 1,
                            expandable: false,
                            expanded: false,
                            loaded: true,
                            path: Some(s.path.clone()),
                        });
                    }
                }
            }
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
        // active wins regardless of the rest
        assert_eq!(
            derive_slice_status(true, Some("2026-07-14"), None),
            SliceStatus::Active
        );
        // reviewed + a Deferred verification section → awaiting-smoke
        let smoke = "## Finish criteria\n...\n## Deferred verification\nrun on-device";
        assert_eq!(
            derive_slice_status(false, Some("2026-07-14"), Some(smoke)),
            SliceStatus::AwaitingSmoke
        );
        // reviewed, no pending smoke → done
        assert_eq!(
            derive_slice_status(false, Some("2026-07-14"), Some("## Finish criteria\nall unit")),
            SliceStatus::Done
        );
        // reviewed but body not yet loaded → done (no smoke signal)
        assert_eq!(
            derive_slice_status(false, Some("2026-07-14"), None),
            SliceStatus::Done
        );
        // not reviewed → queued
        assert_eq!(derive_slice_status(false, None, None), SliceStatus::Queued);
    }

    fn milestone(id: &str, title: &str) -> BacklogItem {
        BacklogItem {
            id: id.into(),
            title: title.into(),
            status: "deferred".into(),
            is_milestone: true,
        }
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
            status: SliceStatus::Queued,
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
