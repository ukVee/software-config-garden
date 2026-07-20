//! Garden filesystem walker.
//!
//! Produces an in-memory snapshot of the working tree as a recursive
//! `TreeNode`. The snapshot drives tree-building in `tree.rs` —
//! every dir becomes a tree row, every file becomes a blob.
//!
//! Rules:
//!
//! * Skip VCS-ignored top-level directories (`.softfig`, `.claude`, …) — see
//!   [`crate::ignore`] for the single source of truth.
//! * Empty directories are tracked iff they contain a `.keep` sentinel
//!   file. Empty-and-sentinel-free directories are dropped from the
//!   snapshot — same convention git uses with `.gitkeep`.
//! * Symlinks are not followed and not recorded in v1. The deploy pillar
//!   (M4) introduces symlink semantics with proper handling.
//! * File mode is the unix mode bits read from `stat`, masked to the
//!   permission bits we care about (0o7777).
//!
//! The walker reads the entire garden into memory. For the v1 use case
//! (tens of MB of markdown + small scripts) that's fine; the daemon will
//! introduce streaming + dirty-set walks later.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::error::{CoreError, Result};

#[derive(Debug, PartialEq, Eq)]
pub enum TreeNode {
    Dir(BTreeMap<String, TreeNode>),
    File { mode: u32, content: Vec<u8> },
}

impl TreeNode {
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir(_))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct WalkSnapshot {
    pub root: TreeNode,
}

impl WalkSnapshot {
    /// An empty snapshot — the root is always a `Dir`, even with no
    /// entries. The shared starting point for both [`walk`] and the FUSE
    /// driver's in-memory reconstruction (`MountHandle::workdir_snapshot`).
    pub fn empty() -> Self {
        WalkSnapshot {
            root: TreeNode::Dir(BTreeMap::new()),
        }
    }

    /// Insert a file at a repo-relative path, creating parent dirs as
    /// `Dir` nodes along the way. `mode` is masked to the permission bits
    /// the VCS tracks ([`MODE_MASK`]) — the single place that rule lives,
    /// so every snapshot source agrees. A non-UTF-8 path component is an
    /// error.
    pub fn insert_file(&mut self, rel: &Path, mode: u32, content: Vec<u8>) -> Result<()> {
        let components = path_components(rel)?;
        insert_file(self.root_children_mut(), &components, mode, content);
        Ok(())
    }

    /// Ensure the directory at a repo-relative path exists as a `Dir`
    /// node (no-op if already present). Empty dirs created this way are
    /// dropped by [`Self::prune_empty_dirs`] unless they gain a `.keep`.
    pub fn ensure_dir(&mut self, rel: &Path) -> Result<()> {
        let components = path_components(rel)?;
        ensure_dir(self.root_children_mut(), &components);
        Ok(())
    }

    /// Bottom-up prune of empty, `.keep`-sentinel-free directories — the
    /// same convention git uses with `.gitkeep`. Shared by every snapshot
    /// builder so the pruning rule has one implementation.
    pub fn prune_empty_dirs(&mut self) {
        prune_empty_dirs(self.root_children_mut());
    }

    /// The file content at a repo-relative path, or `None` when the path is
    /// absent or resolves to a directory. The in-memory, plaintext counterpart
    /// to a `std::fs::read(garden_root.join(rel))`: a consumer reads a path's
    /// current working-tree plaintext straight from the snapshot the commit
    /// will use, rather than reading the garden back through the filesystem —
    /// which in FUSE mode is the mount the daemon serves (the mount-read
    /// deadlock class). Components resolve exactly as [`Self::insert_file`]
    /// stored them, so a lookup never drifts from an insert.
    pub fn file_content(&self, rel: &Path) -> Option<&[u8]> {
        let components = path_components(rel).ok()?;
        let mut node = &self.root;
        for comp in &components {
            let TreeNode::Dir(children) = node else {
                return None;
            };
            node = children.get(comp.as_str())?;
        }
        match node {
            TreeNode::File { content, .. } => Some(content),
            TreeNode::Dir(_) => None,
        }
    }

    /// Every tracked file as `(repo-relative path, mode, content)`, depth-first
    /// in BTreeMap order. The read-side counterpart to [`Self::insert_file`]:
    /// the union-mount router ([`crate::ChainRegistry::split_snapshot`]) walks
    /// these to route each path to its owning chain. Directories are implicit in
    /// the returned paths' ancestry, exactly as `insert_file` reconstructs them.
    pub fn files(&self) -> Vec<(PathBuf, u32, &[u8])> {
        let mut out = Vec::new();
        if let TreeNode::Dir(children) = &self.root {
            collect_files(children, Path::new(""), &mut out);
        }
        out
    }

    fn root_children_mut(&mut self) -> &mut BTreeMap<String, TreeNode> {
        match &mut self.root {
            TreeNode::Dir(children) => children,
            TreeNode::File { .. } => unreachable!("WalkSnapshot root is always a Dir"),
        }
    }
}

fn collect_files<'a>(
    children: &'a BTreeMap<String, TreeNode>,
    prefix: &Path,
    out: &mut Vec<(PathBuf, u32, &'a [u8])>,
) {
    for (name, node) in children {
        let path = prefix.join(name);
        match node {
            TreeNode::File { mode, content } => out.push((path, *mode, content.as_slice())),
            TreeNode::Dir(sub) => collect_files(sub, &path, out),
        }
    }
}

const KEEP_FILE: &str = ".keep";
const MODE_MASK: u32 = 0o7777;

/// Walk a garden rooted at `root` and return its full content as a
/// `WalkSnapshot`. The root node is always a `Dir`, even for an empty
/// garden.
pub fn walk(root: &Path) -> Result<WalkSnapshot> {
    walk_filtered(root, |_| true)
}

/// Walk `root`, keeping only paths for which `keep(rel)` is true, applied on
/// top of the built-in + `.softfigignore` exclusions. The per-path hook is the
/// union-mount router carve-out: a device-chain snapshot is
/// `walk_filtered(garden_root, |p| registry.is_device_owned(p))`, which prunes
/// a shared chain's subtree out of the device walk (M5c slice 002 "Design lock
/// 2026-07-05"). This predicate is distinct from `.softfigignore`: an ignored
/// path means *no chain tracks it*, whereas a filtered-out path means *a
/// different chain tracks it*. Returning `false` for a directory prunes its
/// whole subtree, so an owned mount prefix is never descended into.
pub fn walk_filtered<F>(root: &Path, keep: F) -> Result<WalkSnapshot>
where
    F: Fn(&Path) -> bool,
{
    let mut snapshot = WalkSnapshot::empty();

    // Load the exclusion set (built-ins + the garden's `.softfigignore`) once
    // per walk, so every commit reflects the current ignore file with no
    // daemon restart. See [`crate::ignore`] for the single source of truth.
    let ignore = crate::ignore::Ignore::load(root);

    for entry in WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            // Strip to a repo-relative path so the shared ignore predicate
            // matches on the top-level component. The root itself strips to
            // an empty path (never ignored) and is excluded by min_depth(1).
            e.path()
                .strip_prefix(root)
                .map(|rel| !ignore.is_ignored(rel) && keep(rel))
                .unwrap_or(true)
        })
    {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("walkdir starts under root");

        let file_type = entry.file_type();
        if file_type.is_symlink() {
            // Skip — see module note. Daemon may opt in later.
            continue;
        }

        if file_type.is_dir() {
            snapshot.ensure_dir(relative)?;
        } else if file_type.is_file() {
            let meta = fs::metadata(path)?;
            let content = fs::read(path)?;
            // `insert_file` masks the mode — the rule lives in one place.
            snapshot.insert_file(relative, meta.permissions().mode(), content)?;
        }
        // Other file types (sockets, fifos, devices) are silently skipped.
    }

    snapshot.prune_empty_dirs();
    Ok(snapshot)
}

fn path_components(relative: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for c in relative.components() {
        match c.as_os_str().to_str() {
            Some(s) => out.push(s.to_string()),
            None => return Err(CoreError::NonUtf8Path(relative.to_path_buf())),
        }
    }
    Ok(out)
}

fn ensure_dir(root: &mut BTreeMap<String, TreeNode>, components: &[String]) {
    let mut here = root;
    for comp in components {
        let entry = here
            .entry(comp.clone())
            .or_insert_with(|| TreeNode::Dir(BTreeMap::new()));
        match entry {
            TreeNode::Dir(children) => here = children,
            TreeNode::File { .. } => {
                // Path component collision — should be unreachable since walkdir
                // visits dirs before their files. Bail on a file-shaped node.
                return;
            }
        }
    }
}

fn insert_file(
    root: &mut BTreeMap<String, TreeNode>,
    components: &[String],
    mode: u32,
    content: Vec<u8>,
) {
    if components.is_empty() {
        return;
    }
    let (last, parents) = components.split_last().unwrap();
    let mut here = root;
    for comp in parents {
        let entry = here
            .entry(comp.clone())
            .or_insert_with(|| TreeNode::Dir(BTreeMap::new()));
        match entry {
            TreeNode::Dir(children) => here = children,
            TreeNode::File { .. } => return,
        }
    }
    here.insert(
        last.clone(),
        TreeNode::File {
            mode: mode & MODE_MASK,
            content,
        },
    );
}

/// Remove empty directories that don't have a `.keep` marker. Recursively
/// applied bottom-up. Directories that contained only an empty directory
/// (which itself got pruned) are then themselves empty and prunable.
fn prune_empty_dirs(node: &mut BTreeMap<String, TreeNode>) {
    let names: Vec<String> = node.keys().cloned().collect();
    for name in names {
        if let Some(TreeNode::Dir(children)) = node.get_mut(&name) {
            prune_empty_dirs(children);
            let has_keep = children.contains_key(KEEP_FILE);
            if children.is_empty() && !has_keep {
                node.remove(&name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ignore::IGNORE_FILE;

    fn top_level(snap: &WalkSnapshot) -> &BTreeMap<String, TreeNode> {
        match &snap.root {
            TreeNode::Dir(children) => children,
            TreeNode::File { .. } => panic!("root is always a Dir"),
        }
    }

    /// Lay out a small garden with a top-level `scratch/` dir and one tracked
    /// markdown file, returning the tempdir.
    fn garden() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("scratch")).unwrap();
        fs::write(dir.path().join("scratch/draft.md"), b"wip").unwrap();
        fs::write(dir.path().join("a.md"), b"keep me").unwrap();
        dir
    }

    #[test]
    fn absent_softfigignore_tracks_everything() {
        let dir = garden();
        let snap = walk(dir.path()).unwrap();
        let tl = top_level(&snap);
        assert!(tl.contains_key("scratch"));
        assert!(tl.contains_key("a.md"));
    }

    #[test]
    fn softfigignore_excludes_a_top_level_dir_but_keeps_itself() {
        let dir = garden();
        fs::write(dir.path().join(IGNORE_FILE), "scratch\n").unwrap();
        let snap = walk(dir.path()).unwrap();
        let tl = top_level(&snap);
        // The listed dir is gone from the snapshot...
        assert!(!tl.contains_key("scratch"));
        // ...but unlisted content and the (tracked) ignore file itself remain.
        assert!(tl.contains_key("a.md"));
        assert!(tl.contains_key(IGNORE_FILE));
    }

    #[test]
    fn file_content_reads_nested_paths_from_the_snapshot() {
        // The in-memory plaintext lookup the daemon uses instead of an
        // fs::read(garden_root.join(rel)) of the mount it serves.
        let mut snap = WalkSnapshot::empty();
        snap.insert_file(Path::new("a.md"), 0o644, b"top".to_vec()).unwrap();
        snap.insert_file(Path::new("d/nested.md"), 0o644, b"deep".to_vec())
            .unwrap();

        assert_eq!(snap.file_content(Path::new("a.md")), Some(&b"top"[..]));
        assert_eq!(snap.file_content(Path::new("d/nested.md")), Some(&b"deep"[..]));
        // A directory node and an absent path both yield None (no panic).
        assert_eq!(snap.file_content(Path::new("d")), None);
        assert_eq!(snap.file_content(Path::new("missing.md")), None);
        assert_eq!(snap.file_content(Path::new("a.md/x")), None);
        assert_eq!(snap.file_content(Path::new("")), None);
    }

    #[test]
    fn removing_the_entry_restores_tracking() {
        let dir = garden();
        let ignore_path = dir.path().join(IGNORE_FILE);
        fs::write(&ignore_path, "scratch\n").unwrap();
        assert!(!top_level(&walk(dir.path()).unwrap()).contains_key("scratch"));
        // Emptying the file (here, removing it) restores the prior behavior.
        fs::remove_file(&ignore_path).unwrap();
        assert!(top_level(&walk(dir.path()).unwrap()).contains_key("scratch"));
    }
}
