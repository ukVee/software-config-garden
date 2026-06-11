//! Filesystem-and-DB consistency check.
//!
//! What v1 verifies (per `meta/spec-vcs.md` "fsck / gc"):
//!
//! * Every commit's declared `hash` matches `BLAKE3(canonical_commit_bytes)`.
//! * Every commit's signature verifies under its `author_pubkey`.
//! * Every commit's `parent` (when set) and `root_tree` exist in their
//!   tables.
//! * Every tree's declared hash matches `BLAKE3(canonical_tree_bytes)`.
//! * Every `tree_entries.target_hash` referenced as a `tree` exists in
//!   the trees table.
//! * Every `tree_entries.target_hash` referenced as a `blob` exists in
//!   `objects/` and the on-disk content hashes back to itself.
//! * Every loose object on disk hashes to its filename. (Catches bit rot
//!   even on objects no commit references.)
//!
//! gc and reachability pruning are deferred to v2; orphaned objects are
//! reported, not deleted.

use std::collections::HashSet;

use softfig_store::{Db, Hash, ObjectStore, TreeEntryKind};

use crate::commit::{verify_commit, CanonicalCommit};
use crate::error::Result;
use crate::tree::canonical_tree_bytes;

#[derive(Debug, Default)]
pub struct FsckReport {
    pub commits_checked: usize,
    pub trees_checked: usize,
    pub objects_checked: usize,
    pub orphan_objects: Vec<Hash>,
    pub problems: Vec<String>,
}

impl FsckReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

pub fn run(db: &Db, objects: &ObjectStore) -> Result<FsckReport> {
    let mut report = FsckReport::default();

    // Commits.
    let commits = db.list_commits()?;
    let mut commit_hashes = HashSet::with_capacity(commits.len());
    for c in &commits {
        commit_hashes.insert(c.hash);
    }
    for c in &commits {
        report.commits_checked += 1;

        let payload_value: serde_json::Value = match serde_json::from_str(&c.payload) {
            Ok(v) => v,
            Err(e) => {
                report
                    .problems
                    .push(format!("commit {}: payload not valid json: {e}", c.hash));
                continue;
            }
        };

        let canon = CanonicalCommit {
            parent: c.parent,
            root_tree: c.root_tree,
            author_device: &c.author_device,
            author_pubkey: c.author_pubkey,
            timestamp: c.timestamp,
            intent: &c.intent,
            payload: &payload_value,
            master_key_id: c.master_key_id,
        };
        if let Err(e) = verify_commit(&canon, c.hash, &c.signature) {
            report.problems.push(format!("commit {}: {e}", c.hash));
        }

        if let Some(p) = c.parent {
            if !commit_hashes.contains(&p) {
                report
                    .problems
                    .push(format!("commit {}: parent {} missing", c.hash, p));
            }
        }
        if !db.tree_exists(&c.root_tree)? {
            report.problems.push(format!(
                "commit {}: root_tree {} missing",
                c.hash, c.root_tree
            ));
        }
    }

    // Trees + their entries.
    let tree_hashes = db.list_tree_hashes()?;
    let tree_set: HashSet<Hash> = tree_hashes.iter().copied().collect();
    let mut referenced_blobs: HashSet<Hash> = HashSet::new();

    for th in &tree_hashes {
        report.trees_checked += 1;
        let entries = db.get_tree(th)?;
        let canonical = canonical_tree_bytes(&entries)?;
        let derived = Hash::of(&canonical);
        if derived != *th {
            report
                .problems
                .push(format!("tree {th}: derived hash {derived} mismatch"));
        }
        for e in &entries {
            match e.kind {
                TreeEntryKind::Tree => {
                    if !tree_set.contains(&e.target) {
                        report.problems.push(format!(
                            "tree {th}: entry {} -> tree {} missing",
                            e.name, e.target
                        ));
                    }
                }
                TreeEntryKind::Blob => {
                    referenced_blobs.insert(e.target);
                    if !objects.contains(&e.target) {
                        report.problems.push(format!(
                            "tree {th}: entry {} -> blob {} missing",
                            e.name, e.target
                        ));
                    }
                }
            }
        }
    }

    // Loose objects.
    let mut on_disk: HashSet<Hash> = HashSet::new();
    for entry in objects.iter()? {
        let (declared, bytes) = entry?;
        report.objects_checked += 1;
        let derived = Hash::of(&bytes);
        if derived != declared {
            report.problems.push(format!(
                "object {declared}: bytes hash to {derived}"
            ));
        }
        on_disk.insert(declared);
    }

    // Anything on disk not referenced as a blob is an orphan (not a
    // problem — fsck reports them; gc would later collect them).
    for h in &on_disk {
        if !referenced_blobs.contains(h) {
            report.orphan_objects.push(*h);
        }
    }

    Ok(report)
}
