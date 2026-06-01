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
}
