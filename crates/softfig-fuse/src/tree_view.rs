//! Resolve repo-relative paths against a committed tree.
//!
//! At each tip rotation the FUSE driver rebuilds a flat
//! `BTreeMap<PathBuf, Entry>` from the root tree. Lookups during
//! `lookup` / `getattr` / `readdir` hit the map; reads decrypt the
//! referenced blob via the object store + vault session.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use softfig_store::{Db, Hash, TreeEntryKind, TreeEntryRow};

use crate::Result;

/// Materialized tree-at-tip entry.
#[derive(Debug, Clone)]
pub struct Entry {
    pub kind: EntryKind,
    pub mode: u32,
    /// Hash of the blob (for `Blob`) or the tree row (for `Dir`).
    pub target: Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Blob,
    Dir,
}

/// Flat path-keyed view of a committed tree. The root entry is keyed
/// by the empty path; every interior + leaf has its own row.
#[derive(Debug, Default)]
pub struct TreeView {
    by_path: BTreeMap<PathBuf, Entry>,
}

impl TreeView {
    pub fn empty() -> Self {
        let mut by_path = BTreeMap::new();
        by_path.insert(
            PathBuf::new(),
            Entry {
                kind: EntryKind::Dir,
                mode: 0o040755,
                target: Hash::of(&[]),
            },
        );
        Self { by_path }
    }

    /// Build a view from the tip commit's root tree by recursively
    /// expanding every nested tree row.
    pub fn build(db: &Db, root_tree_hash: &Hash) -> Result<Self> {
        let mut by_path = BTreeMap::new();
        by_path.insert(
            PathBuf::new(),
            Entry {
                kind: EntryKind::Dir,
                mode: 0o040755,
                target: *root_tree_hash,
            },
        );
        expand(db, &mut by_path, &PathBuf::new(), root_tree_hash)?;
        Ok(Self { by_path })
    }

    pub fn get(&self, path: &Path) -> Option<&Entry> {
        self.by_path.get(path)
    }

    /// Iterate immediate children of a directory path.
    pub fn children<'a>(
        &'a self,
        dir: &'a Path,
    ) -> impl Iterator<Item = (&'a Path, &'a Entry)> + 'a {
        self.by_path.iter().filter_map(move |(p, e)| {
            if p == dir {
                return None;
            }
            let parent = p.parent()?;
            if parent != dir {
                return None;
            }
            Some((p.as_path(), e))
        })
    }

    pub fn paths(&self) -> impl Iterator<Item = &Path> + '_ {
        self.by_path.keys().map(|p| p.as_path())
    }
}

fn expand(
    db: &Db,
    out: &mut BTreeMap<PathBuf, Entry>,
    parent: &Path,
    tree_hash: &Hash,
) -> Result<()> {
    let entries = db.get_tree(tree_hash)?;
    for row in entries {
        let TreeEntryRow {
            name,
            kind,
            mode,
            target,
        } = row;
        let path = parent.join(&name);
        match kind {
            TreeEntryKind::Blob => {
                out.insert(
                    path,
                    Entry {
                        kind: EntryKind::Blob,
                        mode,
                        target,
                    },
                );
            }
            TreeEntryKind::Tree => {
                out.insert(
                    path.clone(),
                    Entry {
                        kind: EntryKind::Dir,
                        mode,
                        target,
                    },
                );
                expand(db, out, &path, &target)?;
            }
        }
    }
    Ok(())
}
