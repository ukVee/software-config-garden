//! Chains: a garden is a composition of chains, not a single linear history
//! (`meta/spec-sync.md` "A garden is a composition of chains").
//!
//! The **device chain** (key `M`, ref [`crate::TIP_REF`]) is always present and
//! owns the garden root. Zero or more **shared chains** mount at a conventional
//! garden-relative path and own everything under that prefix. The mapping from a
//! path to its owning chain is the single routing primitive slices 001–004 build
//! on:
//!
//! ```text
//! owning_chain(path) -> Chain   // longest ENABLED shared-mount prefix, else device
//! ```
//!
//! **The registry is config-derived** — chain *tips* live in the existing `refs`
//! table (multi-row already); chain *metadata* (kind, mount path, key id) comes
//! from `config/shared-subtrees.toml` (slice 003), NOT a DB migration. m5c's key
//! id is a placeholder (`None`); the collaborative `S` key lands in m5d.
//!
//! An **empty allow-list** (no shared chains) makes `owning_chain` return the
//! device chain for every path, so every path routes to `TIP_REF` — byte-for-byte
//! today's behavior. This is the additive, off-by-default guarantee.

use std::path::{Path, PathBuf};

use crate::repo::TIP_REF;
use crate::walk::WalkSnapshot;

/// A chain's stable identifier. The device chain uses [`DEVICE_CHAIN_ID`]; a
/// shared chain's id is assigned when it is added (slice 003).
pub type ChainId = String;

/// The device chain's well-known id.
pub const DEVICE_CHAIN_ID: &str = "device";

/// What key a chain is encrypted under and what role it plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    /// The device chain — key `M`, the M5b replica source, owns the root.
    Device,
    /// A shared subtree chain — its own collaborative key `S` (m5d) and audience.
    Shared,
}

/// One chain in the garden's composition: an id, a kind, the `refs`-table ref
/// that holds its tip, an optional garden-relative mount prefix (`None` = the
/// garden root, i.e. the device chain), an optional key id (a placeholder until
/// m5d), and a per-device enabled toggle (slice 003 — the device chain is always
/// enabled).
#[derive(Debug, Clone)]
pub struct Chain {
    pub id: ChainId,
    pub kind: ChainKind,
    pub ref_name: String,
    pub mount_path: Option<PathBuf>,
    pub key_id: Option<String>,
    pub enabled: bool,
}

impl Chain {
    /// The device chain: id [`DEVICE_CHAIN_ID`], ref [`TIP_REF`], mounted at the
    /// garden root, always enabled.
    pub fn device() -> Self {
        Self {
            id: DEVICE_CHAIN_ID.to_string(),
            kind: ChainKind::Device,
            ref_name: TIP_REF.to_string(),
            mount_path: None,
            key_id: None,
            enabled: true,
        }
    }

    /// A shared chain mounted at `mount_path` (garden-relative), tracked by
    /// `ref_name`. `enabled` is the per-device local toggle; `key_id` is a
    /// placeholder in m5c.
    pub fn shared(
        id: impl Into<ChainId>,
        ref_name: impl Into<String>,
        mount_path: impl Into<PathBuf>,
        enabled: bool,
    ) -> Self {
        Self {
            id: id.into(),
            kind: ChainKind::Shared,
            ref_name: ref_name.into(),
            mount_path: Some(mount_path.into()),
            key_id: None,
            enabled,
        }
    }
}

/// The garden's chain composition. The device chain is always present; shared
/// chains are added from `config/shared-subtrees.toml` (slice 003). v1 shares
/// have **disjoint** mount prefixes (validated at add-time in slice 003 via
/// `validate_share_add`), so at most one shared chain can own any path.
///
/// Nesting is a **write-side** capability only. The write router
/// ([`Self::owning_chain`] / [`Self::split_snapshot`]) routes each path to its
/// longest-prefix owner, so a deeper mount would correctly claim its subtree
/// even inside a shallower one. The **read side** does not compose that way:
/// the FUSE `build_union` graft clears and overlays each enabled chain in
/// registry order, not depth order, so a shallower mount grafted after a deeper
/// one would wipe the deeper mount's reads. Nesting therefore stays unreachable
/// in v1 by the disjoint add-time rule; relaxing it would first require
/// grafting reads shallow→deep to match the router.
#[derive(Debug, Clone)]
pub struct ChainRegistry {
    device: Chain,
    shared: Vec<Chain>,
}

impl ChainRegistry {
    /// The default: device chain only, no shared subtrees. `owning_chain`
    /// returns the device chain for every path — today's behavior exactly.
    pub fn device_only() -> Self {
        Self {
            device: Chain::device(),
            shared: Vec::new(),
        }
    }

    /// Build a registry from the device chain plus a set of shared chains.
    pub fn new(device: Chain, shared: Vec<Chain>) -> Self {
        Self { device, shared }
    }

    pub fn device(&self) -> &Chain {
        &self.device
    }

    pub fn shared(&self) -> &[Chain] {
        &self.shared
    }

    /// The chain that owns `path` (garden-relative): the longest **enabled**
    /// shared-mount prefix, else the device chain. A disabled shared chain is
    /// transparent — its subtree falls back to the device chain (the local
    /// enable/disable toggle, slice 003).
    pub fn owning_chain(&self, path: &Path) -> &Chain {
        let mut best: Option<&Chain> = None;
        let mut best_depth = 0usize;
        for c in &self.shared {
            if !c.enabled {
                continue;
            }
            let Some(mount) = &c.mount_path else {
                continue;
            };
            if path.starts_with(mount) {
                // Component count, not string length — "projects" must not
                // out-rank a deeper "projects/app" nor match "projects-x".
                let depth = mount.components().count();
                if depth >= best_depth {
                    best_depth = depth;
                    best = Some(c);
                }
            }
        }
        best.unwrap_or(&self.device)
    }

    /// Whether `path` is owned by the device chain (the router carve-out slice
    /// 002's device-tree walk keeps, and slice 004's isolation depends on).
    pub fn is_device_owned(&self, path: &Path) -> bool {
        matches!(self.owning_chain(path).kind, ChainKind::Device)
    }

    /// The device chain plus every **enabled** shared chain — the *compose* set:
    /// what the union mount projects and [`Self::split_snapshot`] routes writes
    /// into. Enablement is a mount concern, so a disabled chain is absent here.
    /// For gc **retention**, use [`Self::all_chains`] instead — a disabled
    /// chain's objects must still be retained (m5c finding 7).
    pub fn enabled_chains(&self) -> impl Iterator<Item = &Chain> {
        std::iter::once(&self.device).chain(self.shared.iter().filter(|c| c.enabled))
    }

    /// Every chain in the registry — the device chain plus **all** shared chains,
    /// enabled or not. This is gc's **retention** set: a chain that has a ref is
    /// live for garbage collection regardless of its per-device enable/disable
    /// toggle. Disabling is a mount/compose concern, never a retention concern —
    /// if gc keyed on [`Self::enabled_chains`], `disable -> gc -> re-enable` would
    /// destroy the disabled chain's exclusive blobs and break the local toggle's
    /// "cheap, reversible" contract (m5c finding 7).
    pub fn all_chains(&self) -> impl Iterator<Item = &Chain> {
        std::iter::once(&self.device).chain(self.shared.iter())
    }

    /// Route a unified (garden-root-relative) working-tree snapshot into one
    /// snapshot per **enabled** chain — the union-mount write router (M5c slice
    /// 002). Every file is placed by [`Self::owning_chain`]:
    ///
    /// * the **device** chain keeps only device-owned paths (garden-root-relative)
    ///   — the carve-out that keeps a shared chain's content out of the device
    ///   chain's ref (and thus out of the M5b replica, slice 004);
    /// * each **shared** chain gets its subtree with the mount prefix **stripped**,
    ///   so the chain's committed tree is self-contained + mount-relative, exactly
    ///   as a `walk(mount_point)` would produce.
    ///
    /// Returns `(ref_name, snapshot)` for every enabled chain, including any that
    /// own nothing (an empty snapshot). A **`device_only`** registry routes every
    /// path to the device chain unchanged, so the single returned snapshot is
    /// byte-identical to `unified` — the additive, off-by-default guarantee.
    ///
    /// A file at **exactly** a mount path (not under it) would strip to an empty
    /// relative path and be silently dropped here. That shape is unreachable in
    /// v1: `add` refuses a mount path that already holds committed device content
    /// (the populated-dir guard), and once grafted the mount is a directory, so
    /// no file can occupy the mount path itself.
    pub fn split_snapshot(&self, unified: &WalkSnapshot) -> Vec<(String, WalkSnapshot)> {
        let mut snaps: Vec<(String, WalkSnapshot)> = self
            .enabled_chains()
            .map(|c| (c.ref_name.clone(), WalkSnapshot::empty()))
            .collect();
        for (path, mode, content) in unified.files() {
            let chain = self.owning_chain(&path);
            let rel = match &chain.mount_path {
                // `path == mount` (a file at the mount path itself) → empty `rel`
                // → a dropped no-op insert; unreachable in v1 (see the doc note).
                Some(mount) => path.strip_prefix(mount).unwrap_or(&path).to_path_buf(),
                None => path.clone(),
            };
            if let Some((_, snap)) = snaps.iter_mut().find(|(r, _)| *r == chain.ref_name) {
                // `path` came from a UTF-8 snapshot, so re-inserting can't fail.
                let _ = snap.insert_file(&rel, mode, content.to_vec());
            }
        }
        for (_, snap) in snaps.iter_mut() {
            snap.prune_empty_dirs();
        }
        snaps
    }
}

impl Default for ChainRegistry {
    fn default() -> Self {
        Self::device_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_only_owns_everything() {
        let reg = ChainRegistry::device_only();
        for p in ["a.md", "projects/app/x", "hardware/cpu", ""] {
            let c = reg.owning_chain(Path::new(p));
            assert_eq!(c.kind, ChainKind::Device);
            assert_eq!(c.ref_name, TIP_REF);
        }
        // Only the device chain is live.
        assert_eq!(reg.enabled_chains().count(), 1);
    }

    #[test]
    fn shared_mount_owns_its_prefix_only() {
        let reg = ChainRegistry::new(
            Chain::device(),
            vec![Chain::shared("c-proj", "ref-proj", "projects", true)],
        );
        // Under the mount → shared chain.
        assert_eq!(reg.owning_chain(Path::new("projects")).id, "c-proj");
        assert_eq!(reg.owning_chain(Path::new("projects/app/main.rs")).id, "c-proj");
        // A sibling that merely shares a string prefix → device chain.
        assert!(reg.is_device_owned(Path::new("projects-scratch/x")));
        // Elsewhere → device chain.
        assert!(reg.is_device_owned(Path::new("notes/a.md")));
        assert_eq!(reg.enabled_chains().count(), 2);
    }

    #[test]
    fn disabled_shared_falls_back_to_device() {
        let reg = ChainRegistry::new(
            Chain::device(),
            vec![Chain::shared("c-proj", "ref-proj", "projects", false)],
        );
        // Disabled → transparent: the device chain owns the subtree again.
        assert!(reg.is_device_owned(Path::new("projects/app/x")));
        // ...and it drops out of the live set.
        assert_eq!(reg.enabled_chains().count(), 1);
    }

    #[test]
    fn longest_prefix_wins_when_nested() {
        // Disjoint is the v1 rule, but longest-prefix routing must be correct
        // if it ever relaxes: the deeper mount owns the deeper path.
        let reg = ChainRegistry::new(
            Chain::device(),
            vec![
                Chain::shared("c-proj", "ref-proj", "projects", true),
                Chain::shared("c-app", "ref-app", "projects/app", true),
            ],
        );
        assert_eq!(reg.owning_chain(Path::new("projects/readme")).id, "c-proj");
        assert_eq!(reg.owning_chain(Path::new("projects/app/main.rs")).id, "c-app");
    }
}
