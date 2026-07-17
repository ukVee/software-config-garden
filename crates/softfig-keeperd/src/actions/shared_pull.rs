//! M5e slice 002 — the local **apply core** for a peer's shared-chain edit.
//!
//! A peer commits an edit to a shared chain and pushes it to the chain's
//! `S`-members; each member applies it as a **local `shared_pull` commit** on
//! that chain's `chain/<id>` ref. This module is the local, net-free half: it
//! decides whether an incoming edit is a clean fast-forward, an already-held
//! no-op, or a genuine conflict, and — for the fast-forward — re-authors the
//! peer's tree as **this device's own** commit ([`Repo::commit_over_tree`]).
//!
//! **Everything here compares TREES, never commit hashes.** Under the locked
//! re-author model each device has its own commit hashes (convergence is by
//! content, history is per-device), and the receiver never holds the peer's
//! commit objects — the m5e transfer lands only the peer commit's *tree* +
//! new objects content-addressed, not its commit graph (unlike M5b's keyless
//! verbatim mirror). So the payload `base_hash` is carried as the base **tree**
//! hash (the content the peer authored over), and the fast-forward / dedup /
//! conflict decision is a pure tree comparison. See
//! [[decision-m5e-shared-pull-intent]] "Update 2026-07-17 — apply mechanics".
//!
//! Part 2 (the net wire — the `SharedChainSink` that lands the transfer, the
//! inbound-push dispatch, and the S-member re-push driver) is the production
//! caller of [`apply_shared_pull`]; Part 1 lands this core + its unit tests.

use serde_json::json;

use softfig_ipc::ErrorKind;
use softfig_store::Hash;
use softfig_vcs::Intent;

use crate::daemon::DaemonInner;
use crate::server::err_to_response;

/// The inbound edit to apply: the peer commit's tree (already content-addressed
/// into this store by the transfer), the base tree it was authored over, and
/// the metadata that becomes the `shared_pull` commit payload.
#[allow(dead_code)] // Part 2 (net receive/push wire) constructs + consumes this.
#[derive(Debug, Clone)]
pub(crate) struct SharedPullInput {
    /// The shared chain's ref (`chain/<id>`).
    pub chain_ref: String,
    /// The peer commit's `root_tree` — already in this store (transfer, Part 2).
    /// The tree we re-author over on a clean fast-forward.
    pub peer_tree: Hash,
    /// The payload `base_hash`: the **tree** the peer authored its edit over
    /// (content, not a commit hash — see the module note). Drives the
    /// fast-forward decision and is the key slice 003 (`sync_conflict`) uses.
    pub base_hash: Hash,
    /// The authoring member (payload `writer_device`).
    pub writer_device: String,
    /// The shared chain's mount subtree (payload `subtree`).
    pub subtree: String,
    /// The changed paths (payload `files`).
    pub files: Vec<String>,
}

/// The result of applying one inbound peer edit.
#[allow(dead_code)] // Variants are matched by Part 2's dispatch + these tests.
#[derive(Debug)]
pub(crate) enum SharedPullOutcome {
    /// Re-authored a local `shared_pull` commit; the chain ref fast-forwarded
    /// to this hash.
    Applied(Hash),
    /// The peer's tree already equals our chain tip's tree — nothing to do.
    /// The bidirectional **ping-pong terminator**: a member must not re-apply
    /// a peer's edit it already holds, or two members re-push forever. Dedup is
    /// by content (tree), never by commit hash.
    AlreadyPresent,
    /// The peer authored over a base our tip has diverged from *and* our content
    /// differs from the peer's — a genuine concurrent-edit conflict. Out of
    /// scope for slice 002 (clean fast-forward only); slice 003 (`sync_conflict`,
    /// LWW + sidecar) resolves it. Carries the bases it keys off.
    Conflict {
        base_hash: Hash,
        local_tree: Option<Hash>,
    },
}

/// Apply a peer's shared-chain edit to the local chain — the m5e slice 002
/// clean-fast-forward apply. Returns the [`SharedPullOutcome`]; does **not**
/// pass through the write-turn commit gate (`gate_shared_chain_commit`): an
/// inbound apply is not a local write contending for the turn — turn ordering
/// is enforced on the writer side (an online-active receiver yields the turn
/// before calling this; Part 3 wires that). The caller holds the inner lock and
/// has verified the vault is unlocked.
#[allow(dead_code)] // Part 2 (net receive/push wire) is the production caller.
pub(crate) fn apply_shared_pull(
    inner: &mut DaemonInner,
    input: SharedPullInput,
) -> Result<SharedPullOutcome, (ErrorKind, String)> {
    // Resolve the local chain tip's TREE (content), the sole basis for every
    // decision below — commit hashes differ per device under re-authoring.
    let local_tree = {
        let repo = inner
            .repo
            .as_ref()
            .ok_or((ErrorKind::VaultLocked, "vault locked".to_string()))?;
        match repo
            .tip_of(&input.chain_ref)
            .map_err(|e| err_to_response(e.into()))?
        {
            Some(tip) => Some(
                repo.db()
                    .get_commit(&tip)
                    .map_err(|e| err_to_response(e.into()))?
                    .root_tree,
            ),
            None => None,
        }
    };

    // (1) Already present — dedup by content. The ping-pong terminator.
    if local_tree == Some(input.peer_tree) {
        return Ok(SharedPullOutcome::AlreadyPresent);
    }

    // (2) Clean fast-forward. Either the peer authored over exactly our current
    // content (base tree == our tip tree), or our chain is unborn locally (a
    // catch-up-from-empty — nothing to conflict with, adopt the peer's tree as
    // this device's genesis for the chain). Otherwise it's a conflict.
    let fast_forward = match local_tree {
        Some(tip_tree) => tip_tree == input.base_hash,
        None => true,
    };
    if !fast_forward {
        // (3) Base diverged AND our content differs from the peer's → conflict.
        return Ok(SharedPullOutcome::Conflict {
            base_hash: input.base_hash,
            local_tree,
        });
    }

    // Re-author the peer's tree as THIS device's own `shared_pull` commit on the
    // chain ref: linear / single-parent (parent = local tip), root_tree =
    // peer_tree, convergence by content. Payload stays free-form JSON in v1
    // (typed structs later); `base_hash` is carried as the base tree hex.
    let payload = json!({
        "chain_id": input.chain_ref,
        "subtree": input.subtree,
        "files": input.files,
        "writer_device": input.writer_device,
        "base_hash": input.base_hash.to_hex(),
    });
    let intent = Intent::new("shared_pull", payload).map_err(|e| err_to_response(e.into()))?;

    let session = inner.session.clone().expect("unlocked");
    let repo = inner.repo.as_mut().expect("unlocked");
    let hash = repo
        .commit_over_tree(&input.chain_ref, &session, input.peer_tree, intent)
        .map_err(|e| err_to_response(e.into()))?;
    Ok(SharedPullOutcome::Applied(hash))
}

#[cfg(test)]
mod tests {
    //! Part 1 covers the three-way apply decision headlessly (NO net), against
    //! a real Vault + Repo with a genesis'd shared chain. The peer's tree is
    //! staged into the store via a throwaway ref (stands in for the transfer
    //! that Part 2 wires), then handed to `apply_shared_pull` by tree hash.

    use std::path::Path;
    use std::sync::Arc;

    use softfig_store::Hash;
    use softfig_vault::{params::VaultParams, Vault, VaultSession};
    use softfig_vcs::{Intent, Repo, WalkSnapshot};

    use super::{apply_shared_pull, SharedPullInput, SharedPullOutcome};
    use crate::config::KeeperConfig;
    use crate::daemon::DaemonInner;
    use crate::state::State;

    const PASS: &[u8] = b"pw-test-12345";
    const SHARED_REF: &str = "chain/proj";

    /// An Unlocked `DaemonInner` over a tempdir garden whose shared chain has
    /// an (empty) genesis ref — m5c/m5d have mounted+keyed it by the time m5e
    /// apply runs, so the ref already exists. No FUSE: apply operates on the
    /// repo directly.
    fn unlocked_inner(garden: &Path) -> (DaemonInner, Arc<VaultSession>) {
        let mut p = VaultParams::default();
        p.argon2.m_cost = 8;
        p.argon2.t_cost = 1;
        p.argon2.p_cost = 1;
        let (_v, session, _recovery) = Vault::init_with_params(garden, PASS, p).unwrap();
        let session = Arc::new(session);
        let (mut repo, _genesis) = Repo::init(garden, &session).unwrap();
        repo.commit_snapshot_to(SHARED_REF, &session, WalkSnapshot::empty(), Intent::init("genesis"))
            .unwrap();
        let mut inner = DaemonInner::new(KeeperConfig::new(garden));
        inner.state = State::Unlocked;
        inner.session = Some(session.clone());
        inner.repo = Some(repo);
        (inner, session)
    }

    /// The tip tree of a ref, or `None` if unborn.
    fn tree_of(inner: &DaemonInner, ref_name: &str) -> Option<Hash> {
        let repo = inner.repo.as_ref().unwrap();
        repo.tip_of(ref_name)
            .unwrap()
            .map(|tip| repo.db().get_commit(&tip).unwrap().root_tree)
    }

    /// Land a tree with `content` at `path` in the store via a throwaway ref,
    /// returning its root tree hash — stands in for a peer's tree arriving
    /// content-addressed through the transfer path (Part 2).
    fn stage_tree(inner: &mut DaemonInner, throwaway_ref: &str, path: &str, content: &[u8]) -> Hash {
        let session = inner.session.clone().unwrap();
        let repo = inner.repo.as_mut().unwrap();
        let mut snap = WalkSnapshot::empty();
        snap.insert_file(Path::new(path), 0o100644, content.to_vec())
            .unwrap();
        let commit = repo
            .commit_snapshot_to(throwaway_ref, &session, snap, Intent::init("peer-edit"))
            .unwrap();
        repo.db().get_commit(&commit).unwrap().root_tree
    }

    fn input(chain_ref: &str, peer_tree: Hash, base_hash: Hash, files: &[&str]) -> SharedPullInput {
        SharedPullInput {
            chain_ref: chain_ref.to_string(),
            peer_tree,
            base_hash,
            writer_device: "peerbox".to_string(),
            subtree: "proj".to_string(),
            files: files.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn fast_forward_reauthors_over_the_peer_tree() {
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = unlocked_inner(garden.path());

        // Peer authored over our current (empty genesis) content.
        let base = tree_of(&inner, SHARED_REF).unwrap();
        let peer_tree = stage_tree(&mut inner, "chain/peer-src", "proj/a.md", b"peer content");
        let tip_before = inner.repo.as_ref().unwrap().tip_of(SHARED_REF).unwrap();

        let outcome =
            apply_shared_pull(&mut inner, input(SHARED_REF, peer_tree, base, &["proj/a.md"]))
                .unwrap();
        let new_hash = match outcome {
            SharedPullOutcome::Applied(h) => h,
            other => panic!("expected Applied, got {other:?}"),
        };

        let repo = inner.repo.as_ref().unwrap();
        assert_eq!(
            repo.tip_of(SHARED_REF).unwrap(),
            Some(new_hash),
            "the chain fast-forwarded to the re-authored commit"
        );
        let row = repo.db().get_commit(&new_hash).unwrap();
        assert_eq!(row.root_tree, peer_tree, "re-authored over the peer's tree");
        assert_eq!(row.parent, tip_before, "linear/single-parent on the local tip");
        assert_eq!(row.intent, "shared_pull");
        // Re-authored LOCALLY: this device's author, not the peer's — history is
        // per-device, convergence by content.
        assert_ne!(
            row.author_device, "peerbox",
            "the commit is re-authored by this device, not adopted from the peer"
        );
        let payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
        assert_eq!(payload["chain_id"], SHARED_REF);
        assert_eq!(payload["writer_device"], "peerbox");
        assert_eq!(payload["base_hash"], base.to_hex());
        assert_eq!(payload["files"][0], "proj/a.md");
    }

    #[test]
    fn already_present_peer_tree_is_a_noop() {
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = unlocked_inner(garden.path());

        // Apply a peer edit so our tip tree == peer_tree.
        let base = tree_of(&inner, SHARED_REF).unwrap();
        let peer_tree = stage_tree(&mut inner, "chain/peer-src", "proj/a.md", b"peer content");
        let applied = apply_shared_pull(&mut inner, input(SHARED_REF, peer_tree, base, &["proj/a.md"]))
            .unwrap();
        let tip_after_apply = match applied {
            SharedPullOutcome::Applied(h) => h,
            other => panic!("expected Applied, got {other:?}"),
        };

        // The ping-pong: the same content comes back (e.g. a member re-pushes an
        // edit we already hold). It must be a no-op, or two members re-push
        // forever. base_hash is irrelevant here — dedup is on tree content.
        let stale_base = stage_tree(&mut inner, "chain/other", "proj/z.md", b"unrelated");
        let outcome =
            apply_shared_pull(&mut inner, input(SHARED_REF, peer_tree, stale_base, &["proj/a.md"]))
                .unwrap();
        assert!(
            matches!(outcome, SharedPullOutcome::AlreadyPresent),
            "a tree we already hold must dedup, got {outcome:?}"
        );
        assert_eq!(
            inner.repo.as_ref().unwrap().tip_of(SHARED_REF).unwrap(),
            Some(tip_after_apply),
            "an already-present apply must not advance the chain"
        );
    }

    #[test]
    fn base_mismatch_with_divergence_is_a_conflict() {
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = unlocked_inner(garden.path());

        // First peer edit applies cleanly → our tip tree becomes t1.
        let base0 = tree_of(&inner, SHARED_REF).unwrap();
        let t1 = stage_tree(&mut inner, "chain/src1", "proj/a.md", b"first");
        apply_shared_pull(&mut inner, input(SHARED_REF, t1, base0, &["proj/a.md"])).unwrap();

        // A second, divergent peer edit authored over the STALE base (base0),
        // whose content (t2) differs from our current tip (t1): a genuine
        // conflict — out of scope for slice 002, deferred to slice 003.
        let t2 = stage_tree(&mut inner, "chain/src2", "proj/a.md", b"second-divergent");
        let tip_before = inner.repo.as_ref().unwrap().tip_of(SHARED_REF).unwrap();

        let outcome =
            apply_shared_pull(&mut inner, input(SHARED_REF, t2, base0, &["proj/a.md"])).unwrap();
        match outcome {
            SharedPullOutcome::Conflict {
                base_hash,
                local_tree,
            } => {
                assert_eq!(base_hash, base0, "carries the peer's base for slice 003");
                assert_eq!(local_tree, Some(t1), "carries our diverged tip tree");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        assert_eq!(
            inner.repo.as_ref().unwrap().tip_of(SHARED_REF).unwrap(),
            tip_before,
            "a conflict must NOT advance the chain (no apply)"
        );
    }
}
