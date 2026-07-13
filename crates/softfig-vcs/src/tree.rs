//! Tree blueprint: turn a `WalkSnapshot` into a set of (tree_hash, entries)
//! rows ready to insert, plus encrypted blobs already written to the
//! object store.
//!
//! Two phases:
//!
//! 1. Build phase (this module): walk the snapshot, encrypt each file
//!    with the active [`BlobEncryptor`] (Layer A by default; M2b's
//!    daemon installs one that routes sealed paths through Layer B),
//!    write the ciphertext to the object store, compute each tree's
//!    canonical form + hash, and accumulate `(hash, entries)` pairs in
//!    memory.
//! 2. Persist phase: the caller takes the `Blueprint` and inserts rows
//!    inside a single sqlite transaction along with the commit row.
//!
//! The build phase doesn't touch sqlite at all — blobs land on disk
//! durably, but trees only become visible to the DB after the
//! transactional persist.

use std::collections::BTreeMap;

use serde_json::json;
use softfig_store::{Hash, ObjectStore, TreeEntryKind, TreeEntryRow};
use softfig_vault::VaultSession;

use crate::error::Result;
use crate::walk::TreeNode;

/// How a file's bytes become a blob_file in the object store.
///
/// Default impl ([`LayerAEncryptor`]) feeds plaintext through
/// `VaultSession::encrypt_blob` — the existing M1b/c/M2a behavior.
/// M2b's daemon installs an encryptor that consults the
/// `sealed-paths.toml` matcher and routes sealed paths through
/// `VaultSession::encrypt_layer_b` instead.
pub trait BlobEncryptor: Send + Sync {
    /// Produce the on-disk blob_file bytes for a file. `path` is the
    /// repo-relative path (forward slashes, no leading `./`).
    fn encrypt(&self, path: &str, content: &[u8], session: &VaultSession) -> Result<Vec<u8>>;

    /// Chain-aware variant (M5d slice 002): `ref_name` names the chain this
    /// commit is being built for, so an encryptor can key a shared chain's
    /// blobs under that chain's `S` instead of the device master `M`.
    /// Default delegates to [`Self::encrypt`] — chain-blind encryptors
    /// (Layer A, tests) need no change.
    fn encrypt_for_ref(
        &self,
        _ref_name: &str,
        path: &str,
        content: &[u8],
        session: &VaultSession,
    ) -> Result<Vec<u8>> {
        self.encrypt(path, content, session)
    }
}

/// Default encryptor: Layer A only. Every blob is master-keyed
/// convergent. Identical behavior to M1b/c/M2a.
#[derive(Debug, Default)]
pub struct LayerAEncryptor;

impl BlobEncryptor for LayerAEncryptor {
    fn encrypt(&self, _path: &str, content: &[u8], session: &VaultSession) -> Result<Vec<u8>> {
        Ok(session.encrypt_blob(content)?)
    }
}

const DIR_MODE: u32 = 0o040755;

/// A planned write set: the trees to insert, plus the root tree hash.
#[derive(Debug)]
pub struct Blueprint {
    /// All new tree rows, keyed by tree hash. Insert order doesn't matter
    /// (sqlite handles foreign-key insertion ordering as long as it's all
    /// in one transaction).
    pub trees: BTreeMap<Hash, Vec<TreeEntryRow>>,
    /// Hash of the root tree.
    pub root: Hash,
}

/// Build a blueprint from a walk snapshot using the default Layer A
/// encryptor. Backwards-compat alias for callers that don't need
/// Layer B routing.
pub fn build(
    objects: &ObjectStore,
    session: &VaultSession,
    root: &TreeNode,
) -> Result<Blueprint> {
    build_with(objects, session, root, &LayerAEncryptor, crate::repo::TIP_REF)
}

/// Build a blueprint from a walk snapshot. Each file is encrypted via
/// `encryptor.encrypt_for_ref(ref_name, path, content, session)` so the
/// daemon can route sealed paths through Layer B — and a shared chain's
/// files through its `S` (M5d) — without touching this module's internals.
pub fn build_with(
    objects: &ObjectStore,
    session: &VaultSession,
    root: &TreeNode,
    encryptor: &dyn BlobEncryptor,
    ref_name: &str,
) -> Result<Blueprint> {
    let mut bp = Blueprint {
        trees: BTreeMap::new(),
        root: Hash::of(&[]),
    };
    bp.root = build_node(&mut bp, objects, session, encryptor, ref_name, root, "")?;
    Ok(bp)
}

fn build_node(
    bp: &mut Blueprint,
    objects: &ObjectStore,
    session: &VaultSession,
    encryptor: &dyn BlobEncryptor,
    ref_name: &str,
    node: &TreeNode,
    prefix: &str,
) -> Result<Hash> {
    let children = match node {
        TreeNode::Dir(c) => c,
        TreeNode::File { .. } => {
            // build_node is only called on directories from build() and from
            // recursive sub-tree handling below.
            unreachable!("build_node called on a file");
        }
    };

    let mut entries = Vec::with_capacity(children.len());
    for (name, child) in children {
        let child_path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        match child {
            TreeNode::File { mode, content } => {
                let cipher = encryptor.encrypt_for_ref(ref_name, &child_path, content, session)?;
                let blob_hash = objects.put(&cipher)?;
                entries.push(TreeEntryRow {
                    name: name.clone(),
                    kind: TreeEntryKind::Blob,
                    mode: *mode,
                    target: blob_hash,
                });
            }
            TreeNode::Dir(_) => {
                let sub = build_node(bp, objects, session, encryptor, ref_name, child, &child_path)?;
                entries.push(TreeEntryRow {
                    name: name.clone(),
                    kind: TreeEntryKind::Tree,
                    mode: DIR_MODE,
                    target: sub,
                });
            }
        }
    }

    // Tree entries are inserted in name-sorted order (BTreeMap iteration
    // already gives us that, but make it explicit for the canonical form).
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let canonical = canonical_tree_bytes(&entries)?;
    let hash = Hash::of(&canonical);
    bp.trees.entry(hash).or_insert(entries);
    Ok(hash)
}

/// Canonical (JCS) byte representation of a tree's entry list.
/// `tree_hash = BLAKE3(canonical_tree_bytes(entries))`.
pub fn canonical_tree_bytes(entries: &[TreeEntryRow]) -> Result<Vec<u8>> {
    let value = json!({
        "entries": entries
            .iter()
            .map(|e| json!({
                "name":   e.name,
                "kind":   e.kind.as_str(),
                "mode":   e.mode,
                "target": e.target.to_hex(),
            }))
            .collect::<Vec<_>>()
    });
    Ok(serde_jcs::to_vec(&value)?)
}
