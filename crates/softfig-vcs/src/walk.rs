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
use std::path::Path;

use walkdir::WalkDir;

use crate::error::{CoreError, Result};

#[derive(Debug)]
pub enum TreeNode {
    Dir(BTreeMap<String, TreeNode>),
    File { mode: u32, content: Vec<u8> },
}

impl TreeNode {
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir(_))
    }
}

#[derive(Debug)]
pub struct WalkSnapshot {
    pub root: TreeNode,
}

const KEEP_FILE: &str = ".keep";
const MODE_MASK: u32 = 0o7777;

/// Walk a garden rooted at `root` and return its full content as a
/// `WalkSnapshot`. The root node is always a `Dir`, even for an empty
/// garden.
pub fn walk(root: &Path) -> Result<WalkSnapshot> {
    let mut root_node = BTreeMap::<String, TreeNode>::new();

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
                .map(|rel| !ignore.is_ignored(rel))
                .unwrap_or(true)
        })
    {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("walkdir starts under root")
            .to_path_buf();

        let file_type = entry.file_type();
        if file_type.is_symlink() {
            // Skip — see module note. Daemon may opt in later.
            continue;
        }

        let components: Vec<String> = path_components(&relative)?;

        if file_type.is_dir() {
            ensure_dir(&mut root_node, &components);
        } else if file_type.is_file() {
            let meta = fs::metadata(path)?;
            let mode = meta.permissions().mode() & MODE_MASK;
            let content = fs::read(path)?;
            insert_file(&mut root_node, &components, mode, content);
        }
        // Other file types (sockets, fifos, devices) are silently skipped.
    }

    prune_empty_dirs(&mut root_node);

    Ok(WalkSnapshot {
        root: TreeNode::Dir(root_node),
    })
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
    here.insert(last.clone(), TreeNode::File { mode, content });
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
