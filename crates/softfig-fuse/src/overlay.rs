//! In-memory write overlay buffering filesystem mutations between
//! commits.
//!
//! When a kernel write/create/unlink/rename arrives we record the new
//! state here. The materialized FUSE view at any moment is
//! `(tree-at-tip) ∪ overlay`, with overlay precedence:
//!
//! * `Present(File { .. })` — file exists with these bytes/mode (new
//!   file or modified existing one).
//! * `Present(Dir { mode })` — directory exists (new mkdir).
//! * `Removed` — path is hidden from the view; reads/lookups fail with
//!   `ENOENT` even if the tip still has the entry.
//!
//! On `tip_changed` the overlay is cleared — the new tip absorbed
//! everything we'd been buffering.
//!
//! A note on `commit_workdir`'s reentrant walk: when the daemon
//! commits, it walks `garden_root` (= the FUSE mount) which calls back
//! into our `read` handler; we MUST serve overlay bytes there so the
//! commit captures them. The handler reads through this same overlay
//! map, so the round-trip is consistent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum OverlayEntry {
    File { content: Vec<u8>, mode: u32 },
    Dir { mode: u32 },
    Removed,
}

#[derive(Debug, Default)]
pub struct Overlay {
    by_path: HashMap<PathBuf, OverlayEntry>,
}

impl Overlay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, path: &Path) -> Option<&OverlayEntry> {
        self.by_path.get(path)
    }

    pub fn insert_file(&mut self, path: PathBuf, content: Vec<u8>, mode: u32) {
        self.by_path
            .insert(path, OverlayEntry::File { content, mode });
    }

    pub fn insert_dir(&mut self, path: PathBuf, mode: u32) {
        self.by_path.insert(path, OverlayEntry::Dir { mode });
    }

    pub fn mark_removed(&mut self, path: PathBuf) {
        self.by_path.insert(path, OverlayEntry::Removed);
    }

    #[allow(dead_code)]
    pub fn rename(&mut self, from: &Path, to: PathBuf) {
        if let Some(entry) = self.by_path.remove(from) {
            self.by_path.insert(to, entry);
        }
        // Removal-marker for the old name so the tip's entry stays
        // hidden after the rename.
        self.by_path
            .insert(from.to_path_buf(), OverlayEntry::Removed);
    }

    pub fn clear(&mut self) {
        self.by_path.clear();
    }

    /// Iterate all overlay paths, used during readdir to merge with
    /// tree-at-tip children.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, &OverlayEntry)> {
        self.by_path.iter().map(|(p, e)| (p.as_path(), e))
    }
}
