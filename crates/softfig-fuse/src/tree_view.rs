//! Resolve repo-relative paths against a committed tree.
//!
//! At each tip rotation the FUSE driver rebuilds a flat
//! `BTreeMap<PathBuf, Entry>` from the root tree. Lookups during
//! `lookup` / `getattr` / `readdir` hit the map; reads decrypt the
//! referenced blob via the object store + vault session.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use softfig_store::{Db, Hash, TreeEntryKind, TreeEntryRow};
use softfig_vcs::ChainRegistry;

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

    /// Build the **union-mount** view (M5c slice 002): the device chain's tree
    /// at the garden root, with each **enabled** shared chain's tree grafted at
    /// its mount prefix so reads compose. A shared chain owns its prefix
    /// ([`ChainRegistry::owning_chain`]), so any device-side entry under a mount
    /// is dropped before the graft and the shared tree wins — a **disabled**
    /// shared chain is simply not grafted, so its subtree falls back to the
    /// device chain. A `device_only` registry grafts nothing, yielding exactly
    /// today's device-chain view (byte-identical, off by default).
    pub fn build_union(db: &Db, registry: &ChainRegistry) -> Result<Self> {
        let device = registry.device();
        let mut view = match db.try_get_ref(&device.ref_name)? {
            Some(h) => Self::build(db, &db.get_commit(&h)?.root_tree)?,
            None => Self::empty(),
        };
        for chain in registry.shared() {
            if !chain.enabled {
                continue;
            }
            let Some(mount) = &chain.mount_path else {
                continue;
            };
            if let Some(h) = db.try_get_ref(&chain.ref_name)? {
                let sub = Self::build(db, &db.get_commit(&h)?.root_tree)?;
                view.graft(&sub, mount);
            }
        }
        Ok(view)
    }

    /// Graft `other` (a shared chain's mount-relative tree) into this view at
    /// `prefix`. The prefix subtree is first cleared (the shared chain owns it),
    /// then every `other` entry is re-keyed under `prefix` — its root maps to
    /// `prefix` itself. Missing ancestor directories of `prefix` are synthesized
    /// so the kernel can traverse to the graft point.
    fn graft(&mut self, other: &TreeView, prefix: &Path) {
        self.by_path.retain(|p, _| !p.starts_with(prefix));
        for anc in prefix.ancestors().skip(1) {
            if anc.as_os_str().is_empty() {
                continue;
            }
            self.by_path.entry(anc.to_path_buf()).or_insert(Entry {
                kind: EntryKind::Dir,
                mode: 0o040755,
                target: Hash::of(&[]),
            });
        }
        for (p, e) in &other.by_path {
            let dst = if p.as_os_str().is_empty() {
                prefix.to_path_buf()
            } else {
                prefix.join(p)
            };
            self.by_path.insert(dst, e.clone());
        }
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

#[cfg(test)]
mod tests {
    //! M5c slice 002 — reads compose the union: the device chain at the root
    //! with each enabled shared chain grafted at its mount prefix. Headless
    //! (Db-backed, no `/dev/fuse`); the live union render is a deferred smoke.
    use super::*;
    use softfig_vcs::{walk, Chain, ChainRegistry, Intent, Repo};
    use softfig_vault::{params::VaultParams, Vault};

    const PASS: &[u8] = b"correct horse battery staple";
    const B_REF: &str = "chain-b";

    fn fast_params() -> VaultParams {
        let mut p = VaultParams::default();
        p.argon2.m_cost = 8;
        p.argon2.t_cost = 1;
        p.argon2.p_cost = 1;
        p
    }

    /// A device chain (`device.md` at root) plus a shared `chain-b` whose own
    /// tree is mount-relative (`app.md`, `sub/deep.md`).
    fn two_chain_repo() -> (tempfile::TempDir, Repo) {
        let garden = tempfile::tempdir().unwrap();
        std::fs::write(garden.path().join("device.md"), "device").unwrap();
        let (_v, session, _r) =
            Vault::init_with_params(garden.path(), PASS, fast_params()).unwrap();
        let (mut repo, _genesis) = Repo::init(garden.path(), &session).unwrap();

        let stage = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(stage.path().join("sub")).unwrap();
        std::fs::write(stage.path().join("app.md"), "app").unwrap();
        std::fs::write(stage.path().join("sub/deep.md"), "deep").unwrap();
        repo.commit_snapshot_to(
            B_REF,
            &session,
            walk::walk(stage.path()).unwrap(),
            Intent::init("seed b"),
        )
        .unwrap();
        (garden, repo)
    }

    #[test]
    fn union_composes_device_plus_shared_grafted_at_prefix() {
        let (_g, repo) = two_chain_repo();
        let reg = ChainRegistry::new(
            Chain::device(),
            vec![Chain::shared("c-b", B_REF, "projects", true)],
        );
        let view = TreeView::build_union(repo.db(), &reg).unwrap();

        assert!(view.get(Path::new("device.md")).is_some());
        assert_eq!(
            view.get(Path::new("projects")).map(|e| e.kind),
            Some(EntryKind::Dir),
            "the mount point itself resolves as a directory"
        );
        assert_eq!(
            view.get(Path::new("projects/app.md")).map(|e| e.kind),
            Some(EntryKind::Blob)
        );
        assert_eq!(
            view.get(Path::new("projects/sub/deep.md")).map(|e| e.kind),
            Some(EntryKind::Blob)
        );
        // The shared chain's mount-relative path is only visible prefixed.
        assert!(view.get(Path::new("app.md")).is_none());
    }

    #[test]
    fn disabled_shared_chain_is_not_composed() {
        let (_g, repo) = two_chain_repo();
        let reg = ChainRegistry::new(
            Chain::device(),
            vec![Chain::shared("c-b", B_REF, "projects", false)],
        );
        let view = TreeView::build_union(repo.db(), &reg).unwrap();
        assert!(view.get(Path::new("device.md")).is_some());
        assert!(
            view.get(Path::new("projects")).is_none(),
            "a disabled chain contributes nothing to the view"
        );
        assert!(view.get(Path::new("projects/app.md")).is_none());
    }

    #[test]
    fn device_only_union_is_just_the_device_tree() {
        let (_g, repo) = two_chain_repo();
        let view = TreeView::build_union(repo.db(), &ChainRegistry::device_only()).unwrap();
        assert!(view.get(Path::new("device.md")).is_some());
        assert!(view.get(Path::new("projects")).is_none());
    }
}
