//! Bidirectional inode ↔ repo-relative path mapping.
//!
//! FUSE requires every entity (file, directory) to have a stable u64
//! inode. We allocate them lazily in insertion order; root is fixed at
//! [`ROOT_INODE`] = 1 (FUSE convention). Rebuilds on tip rotation
//! preserve the mapping for paths that still exist (so the kernel's
//! cache stays valid for them) and free inodes whose paths are gone.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const ROOT_INODE: u64 = 1;

/// Bijection between repo-relative paths and u64 inodes. The empty
/// path (`""`) maps to [`ROOT_INODE`].
#[derive(Debug)]
pub struct InodeMap {
    by_path: HashMap<PathBuf, u64>,
    by_inode: HashMap<u64, PathBuf>,
    next: u64,
}

impl InodeMap {
    pub fn new() -> Self {
        let mut by_path = HashMap::new();
        let mut by_inode = HashMap::new();
        by_path.insert(PathBuf::new(), ROOT_INODE);
        by_inode.insert(ROOT_INODE, PathBuf::new());
        Self {
            by_path,
            by_inode,
            next: ROOT_INODE + 1,
        }
    }

    /// Return the existing inode for `path`, or allocate a new one.
    pub fn intern(&mut self, path: &Path) -> u64 {
        if let Some(&i) = self.by_path.get(path) {
            return i;
        }
        let i = self.next;
        self.next += 1;
        self.by_path.insert(path.to_path_buf(), i);
        self.by_inode.insert(i, path.to_path_buf());
        i
    }

    #[allow(dead_code)]
    pub fn lookup(&self, path: &Path) -> Option<u64> {
        self.by_path.get(path).copied()
    }

    pub fn path_of(&self, inode: u64) -> Option<&Path> {
        self.by_inode.get(&inode).map(|p| p.as_path())
    }

    /// Drop a path from the mapping. The inode is NOT reused — that
    /// would let the kernel's cached attribute for the old name
    /// silently apply to a new entity.
    pub fn forget(&mut self, path: &Path) {
        if let Some(i) = self.by_path.remove(path) {
            self.by_inode.remove(&i);
        }
    }

    /// Rename a path. The inode survives so the kernel cache for the
    /// old name follows the file to its new name (POSIX semantics).
    pub fn rename(&mut self, from: &Path, to: &Path) {
        if let Some(i) = self.by_path.remove(from) {
            self.by_inode.insert(i, to.to_path_buf());
            self.by_path.insert(to.to_path_buf(), i);
        }
    }

    #[allow(dead_code)]
    pub fn all_inodes(&self) -> impl Iterator<Item = u64> + '_ {
        self.by_inode.keys().copied()
    }
}

impl Default for InodeMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_one() {
        let m = InodeMap::new();
        assert_eq!(m.lookup(Path::new("")), Some(ROOT_INODE));
        assert_eq!(m.path_of(ROOT_INODE), Some(Path::new("")));
    }

    #[test]
    fn intern_is_idempotent() {
        let mut m = InodeMap::new();
        let a = m.intern(Path::new("a.md"));
        let b = m.intern(Path::new("a.md"));
        assert_eq!(a, b);
    }

    #[test]
    fn rename_preserves_inode() {
        let mut m = InodeMap::new();
        let i = m.intern(Path::new("a.md"));
        m.rename(Path::new("a.md"), Path::new("b.md"));
        assert_eq!(m.lookup(Path::new("a.md")), None);
        assert_eq!(m.lookup(Path::new("b.md")), Some(i));
    }
}
