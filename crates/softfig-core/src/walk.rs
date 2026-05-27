//! Garden filesystem walker.
//!
//! Produces an in-memory snapshot of the working tree as a recursive
//! `TreeNode`. The snapshot drives tree-building in `tree.rs` —
//! every dir becomes a tree row, every file becomes a blob.
//!
//! Rules:
//!
//! * Skip the entire `.softfig/` directory (the VCS's own state).
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

const SOFTFIG_DIR_NAME: &str = ".softfig";
const KEEP_FILE: &str = ".keep";
const MODE_MASK: u32 = 0o7777;

/// Walk a garden rooted at `root` and return its full content as a
/// `WalkSnapshot`. The root node is always a `Dir`, even for an empty
/// garden.
pub fn walk(root: &Path) -> Result<WalkSnapshot> {
    let mut root_node = BTreeMap::<String, TreeNode>::new();

    for entry in WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| !is_softfig(e.path(), root))
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

fn is_softfig(path: &Path, root: &Path) -> bool {
    if let Ok(rel) = path.strip_prefix(root) {
        let mut comps = rel.components();
        if let Some(first) = comps.next() {
            return first.as_os_str() == SOFTFIG_DIR_NAME;
        }
    }
    false
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
