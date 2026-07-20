//! Per-chain reachability + garbage collection.
//!
//! A garden holds N chains sharing one object store and one `Db` (distinct
//! rows in the `refs` table, `meta/spec-vcs.md` "fsck / gc"). Reachability and
//! gc are therefore **per chain tip, unioned across all chains**:
//!
//! * [`reachable_from`] walks everything reachable from one chain tip — the
//!   commit ancestry, each commit's root tree (recursively), and the blobs
//!   those trees name.
//! * [`gc`] collects loose objects reachable from **no** live tip. Its
//!   `live_tips` MUST be the tip of every **ref physically present** in the store
//!   (`db.list_refs()`); the caller derives them via [`crate::Repo::live_tips`],
//!   so gc is safe by construction: an object live in a *different* chain is in
//!   the union and is never collected. Retention is keyed on **ref existence
//!   alone** — enable/disable is a mount/compose concern (a **disabled** chain
//!   keeps its ref, so `disable -> gc -> re-enable` can't destroy its exclusive
//!   blobs, m5c finding 7), and an **un-shared** chain keeps its ref too, so
//!   `remove -> gc -> re-add` resumes it intact rather than resurrecting a tip
//!   whose blobs were collected (m5c-residual slice 011, contract (a): every ref
//!   is live). Running gc while a second chain exists must not touch the other
//!   chain's objects.
//!
//! gc collects only loose **objects** (blobs on disk); pruning unreachable
//! commit/tree *rows* is deferred to a future explicit chain-drop verb. No verb
//! drops a chain today — `remove` un-shares but keeps the ref (contract (a)) — so
//! every commit/tree row stays reachable from some ref and nothing dangles; the
//! row-pruning path has no trigger yet (m5c-residual slice 011).

use std::collections::HashSet;

use softfig_store::{Db, Hash, ObjectStore, TreeEntryKind};

use crate::error::Result;

/// The object closure of a single chain tip.
#[derive(Debug, Default)]
pub struct Reachable {
    pub commits: HashSet<Hash>,
    pub trees: HashSet<Hash>,
    pub blobs: HashSet<Hash>,
}

/// Walk everything reachable from `tip`: the commit ancestry (via `parent`),
/// each commit's root tree (recursively through subtrees), and the blob targets
/// those trees name.
pub fn reachable_from(db: &Db, tip: Hash) -> Result<Reachable> {
    let mut r = Reachable::default();
    let mut commit_stack = vec![tip];
    while let Some(ch) = commit_stack.pop() {
        if !r.commits.insert(ch) {
            continue;
        }
        let commit = db.get_commit(&ch)?;
        walk_tree(db, commit.root_tree, &mut r)?;
        if let Some(parent) = commit.parent {
            commit_stack.push(parent);
        }
    }
    Ok(r)
}

/// The object closure of a single **tree** root — the tree, its subtrees, and
/// the blobs they name (no commit ancestry). The tree-rooted counterpart of
/// [`reachable_from`], used by the m5e shared-chain push serve to scope its
/// `serve_replication` source to exactly the pushed subtree's closure: the same
/// "a serve answers only for its announced closure, never the whole store"
/// property finding 6 gives the device-chain serve, rooted at a tree instead of
/// a commit tip. `commits` stays empty (the shared-chain transfer ships trees +
/// objects only, never the peer's commit graph).
pub fn reachable_from_tree(db: &Db, root_tree: Hash) -> Result<Reachable> {
    let mut r = Reachable::default();
    walk_tree(db, root_tree, &mut r)?;
    Ok(r)
}

/// Add `root` and every subtree/blob under it to `r`.
fn walk_tree(db: &Db, root: Hash, r: &mut Reachable) -> Result<()> {
    let mut stack = vec![root];
    while let Some(th) = stack.pop() {
        if !r.trees.insert(th) {
            continue;
        }
        for e in db.get_tree(&th)? {
            match e.kind {
                TreeEntryKind::Tree => stack.push(e.target),
                TreeEntryKind::Blob => {
                    r.blobs.insert(e.target);
                }
            }
        }
    }
    Ok(())
}

/// The union of blobs reachable from every tip in `live_tips`.
pub fn live_blobs(db: &Db, live_tips: &[Hash]) -> Result<HashSet<Hash>> {
    let mut live = HashSet::new();
    for t in live_tips {
        live.extend(reachable_from(db, *t)?.blobs);
    }
    Ok(live)
}

/// What a gc pass did.
#[derive(Debug, Default)]
pub struct GcReport {
    /// Loose objects scanned on disk.
    pub scanned: usize,
    /// Objects retained because they are reachable from some live tip.
    pub kept: usize,
    /// Objects collected (unreachable from every live tip).
    pub collected: Vec<Hash>,
}

/// Collect every loose object unreachable from **all** `live_tips`.
///
/// `live_tips` must be the tip of every **ref present in the store**
/// (`db.list_refs()`) — pass [`crate::Repo::live_tips`]. Because the retained set
/// is the union over all of them, an object that belongs to a different chain —
/// including a *disabled* or *un-shared* one whose ref still exists — is never
/// collected (m5c finding 7; m5c-residual slice 011). Deletion is idempotent
/// (a concurrently-removed object is not an error).
pub fn gc(db: &Db, objects: &ObjectStore, live_tips: &[Hash]) -> Result<GcReport> {
    let live = live_blobs(db, live_tips)?;
    let mut report = GcReport::default();
    // Collect the doomed hashes before deleting — don't mutate the directory
    // mid-walk.
    let mut doomed = Vec::new();
    for entry in objects.iter()? {
        let (declared, _bytes) = entry?;
        report.scanned += 1;
        if live.contains(&declared) {
            report.kept += 1;
        } else {
            doomed.push(declared);
        }
    }
    for h in doomed {
        objects.remove(&h)?;
        report.collected.push(h);
    }
    Ok(report)
}
