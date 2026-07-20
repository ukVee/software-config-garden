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

/// Per-chain fsck: verify integrity of everything reachable from a single
/// chain's tip (`meta/spec-sync.md` "A garden is a composition of chains" — each
/// chain is fsck'd from its own tip). Unlike [`run`], which sweeps the whole
/// store, this restricts to the chain's object closure, so an unrelated chain's
/// objects neither pad the counts nor mask a problem. `tip = None` (an empty
/// chain) is trivially clean.
///
/// Checks, over the reachable closure: each commit's declared hash + signature;
/// each tree's canonical hash + that its subtree/blob targets exist (subtrees
/// as tree rows, blobs present on disk). Orphan detection is a whole-store
/// notion and stays with [`run`].
///
/// fsck **reports** corruption; it does not abort on it. A missing commit or
/// tree row is recorded as a problem and stepped over, so a damaged store still
/// yields a report. This is why the walk is fault-tolerant here rather than
/// reusing gc's fail-closed [`crate::gc::reachable_from`] (which *must* error
/// out so gc never under-retains — the retention path stays fail-closed).
pub fn run_chain(db: &Db, objects: &ObjectStore, tip: Option<Hash>) -> Result<FsckReport> {
    let mut report = FsckReport::default();
    let Some(tip) = tip else {
        return Ok(report);
    };

    let mut seen_commits: HashSet<Hash> = HashSet::new();
    let mut seen_trees: HashSet<Hash> = HashSet::new();
    let mut referenced_blobs: HashSet<Hash> = HashSet::new();
    // Every commit's root tree seeds the tree walk; a missing root tree surfaces
    // there as a `tree ...` problem, so there is no separate root-tree probe.
    let mut tree_stack: Vec<Hash> = Vec::new();

    // Commit ancestry from the tip. A missing commit row is a problem, not an
    // abort — record it and stop descending that branch.
    let mut commit_stack = vec![tip];
    while let Some(ch) = commit_stack.pop() {
        if !seen_commits.insert(ch) {
            continue;
        }
        report.commits_checked += 1;
        let c = match db.get_commit(&ch) {
            Ok(c) => c,
            Err(e) => {
                report.problems.push(format!("commit {ch}: {e}"));
                continue;
            }
        };
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
        tree_stack.push(c.root_tree);
        if let Some(p) = c.parent {
            commit_stack.push(p);
        }
    }

    // Trees + their entries, from every commit's root tree down. A missing tree
    // row is a problem, not an abort.
    while let Some(th) = tree_stack.pop() {
        if !seen_trees.insert(th) {
            continue;
        }
        report.trees_checked += 1;
        let entries = match db.get_tree(&th) {
            Ok(e) => e,
            Err(e) => {
                report.problems.push(format!("tree {th}: {e}"));
                continue;
            }
        };
        let derived = Hash::of(&canonical_tree_bytes(&entries)?);
        if derived != th {
            report
                .problems
                .push(format!("tree {th}: derived hash {derived} mismatch"));
        }
        for e in &entries {
            match e.kind {
                TreeEntryKind::Tree => tree_stack.push(e.target),
                TreeEntryKind::Blob => {
                    // Check + count each referenced blob once, with the context of
                    // the first tree that names it.
                    if referenced_blobs.insert(e.target) {
                        report.objects_checked += 1;
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
    }

    Ok(report)
}
