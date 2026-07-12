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
//! **Absorption invariant (M5c slice 006):** a rotation may clear only
//! the entries the new composition absorbed. Every mutation stamps a
//! monotonic generation; the commit path records the generation it
//! snapshotted ([`Overlay::generation`]), and after the commit lands
//! [`Overlay::remove_absorbed`] drops exactly the entries that are (a)
//! owned by the chain whose ref advanced and (b) staged at-or-before
//! that snapshot. An unconditional `clear()` was only correct in the
//! single-chain world where every rotation followed a commit that had
//! absorbed the whole overlay; multi-ref rotations absorb one chain's
//! carve-out (or, for a registry hot-swap, nothing at all).
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

/// One staged entry plus the generation of the mutation that staged it.
#[derive(Debug)]
struct Slot {
    generation: u64,
    entry: OverlayEntry,
}

#[derive(Debug, Default)]
pub struct Overlay {
    by_path: HashMap<PathBuf, Slot>,
    /// Monotonic mutation counter; bumped on every insert/remove-mark so
    /// [`Overlay::remove_absorbed`] can distinguish entries a snapshot
    /// captured from ones staged after it.
    generation: u64,
}

impl Overlay {
    pub fn new() -> Self {
        Self::default()
    }

    /// The generation of the most recent mutation. A snapshot capture reads
    /// this under the same lock it collects entries, so "gen ≤ captured"
    /// exactly means "this entry was part of the snapshot".
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn get(&self, path: &Path) -> Option<&OverlayEntry> {
        self.by_path.get(path).map(|s| &s.entry)
    }

    fn stage(&mut self, path: PathBuf, entry: OverlayEntry) {
        self.generation += 1;
        self.by_path.insert(path, Slot { generation: self.generation, entry });
    }

    pub fn insert_file(&mut self, path: PathBuf, content: Vec<u8>, mode: u32) {
        self.stage(path, OverlayEntry::File { content, mode });
    }

    pub fn insert_dir(&mut self, path: PathBuf, mode: u32) {
        self.stage(path, OverlayEntry::Dir { mode });
    }

    pub fn mark_removed(&mut self, path: PathBuf) {
        self.stage(path, OverlayEntry::Removed);
    }

    #[allow(dead_code)]
    pub fn rename(&mut self, from: &Path, to: PathBuf) {
        if let Some(slot) = self.by_path.remove(from) {
            self.stage(to, slot.entry);
        }
        // Removal-marker for the old name so the tip's entry stays
        // hidden after the rename.
        self.mark_removed(from.to_path_buf());
    }

    /// Drop the entries a just-landed commit absorbed: those staged at or
    /// before the `cutoff` generation the commit's snapshot captured AND
    /// owned (per `owned`) by the chain whose ref the commit advanced.
    /// Everything else — another chain's staged writes, and writes that
    /// raced in after the snapshot — survives the rotation.
    ///
    /// `Dir` markers get one extra guard: a marker is kept while any
    /// surviving entry lives beneath it, because an empty directory is not
    /// versioned — the commit may not have materialized the dir in the new
    /// tip, and dropping the marker would orphan the surviving descendant
    /// (the view descends only through known dirs).
    pub fn remove_absorbed(&mut self, cutoff: u64, owned: impl Fn(&Path) -> bool) {
        self.by_path.retain(|path, slot| {
            slot.generation > cutoff
                || matches!(slot.entry, OverlayEntry::Dir { .. })
                || !owned(path)
        });
        // Second pass for absorbed Dir markers, now that the surviving
        // file/removed set is final.
        let survivors: Vec<PathBuf> = self
            .by_path
            .iter()
            .filter(|(_, s)| !matches!(s.entry, OverlayEntry::Dir { .. }))
            .map(|(p, _)| p.clone())
            .collect();
        self.by_path.retain(|path, slot| {
            if !matches!(slot.entry, OverlayEntry::Dir { .. }) {
                return true;
            }
            slot.generation > cutoff
                || !owned(path)
                || survivors.iter().any(|f| f.starts_with(path) && f != path)
        });
    }

    /// Iterate all overlay paths, used during readdir to merge with
    /// tree-at-tip children.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, &OverlayEntry)> {
        self.by_path.iter().map(|(p, s)| (p.as_path(), &s.entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_absorbed_honors_cutoff_ownership_and_dir_shelter() {
        let mut o = Overlay::new();
        o.insert_file(PathBuf::from("note.md"), b"n".to_vec(), 0o100644); // gen 1
        o.insert_file(PathBuf::from("proj/x.md"), b"x".to_vec(), 0o100644); // gen 2
        let cutoff = o.generation();
        o.insert_file(PathBuf::from("late.md"), b"l".to_vec(), 0o100644); // gen 3, after snapshot

        // Device commit landed: clear device-owned entries captured by the
        // snapshot. "proj/" belongs to a shared chain here.
        o.remove_absorbed(cutoff, |p| !p.starts_with("proj"));
        assert!(o.get(Path::new("note.md")).is_none(), "absorbed device entry cleared");
        assert!(o.get(Path::new("proj/x.md")).is_some(), "other chain's entry survives");
        assert!(o.get(Path::new("late.md")).is_some(), "post-snapshot write survives");
    }

    #[test]
    fn dir_marker_survives_while_a_descendant_survives() {
        let mut o = Overlay::new();
        o.insert_dir(PathBuf::from("scratch"), 0o040755); // gen 1
        let cutoff = o.generation();
        o.insert_file(PathBuf::from("scratch/a.md"), b"a".to_vec(), 0o100644); // gen 2

        // The commit captured only the (fileless) marker — the new tip has no
        // `scratch/` dir, so the marker must stay to keep `a.md` reachable.
        o.remove_absorbed(cutoff, |_| true);
        assert!(o.get(Path::new("scratch")).is_some());
        assert!(o.get(Path::new("scratch/a.md")).is_some());

        // Once the descendant is absorbed too, a later rotation drops both.
        let cutoff = o.generation();
        o.remove_absorbed(cutoff, |_| true);
        assert!(o.get(Path::new("scratch")).is_none());
        assert!(o.get(Path::new("scratch/a.md")).is_none());
    }
}
