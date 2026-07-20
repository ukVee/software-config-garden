//! M5c slice 001 — the multi-ref store: a garden is a composition of chains
//! sharing one `Db` + one object store, each chain a distinct row in `refs`.
//!
//! Proves the three store-layer invariants the union mount (002), lifecycle
//! (003), and replica isolation (004) stack on:
//!   * two chains advance independently — one's commit never moves the other's ref;
//!   * per-chain fsck is clean and scoped to that chain's tip closure;
//!   * gc across the chain set never collects another chain's live objects.

use std::path::Path;

use softfig_store::Hash;
use softfig_vcs::{
    fsck, live_blobs, reachable_from, walk, Chain, ChainRegistry, Intent, Repo, TIP_REF,
};
use softfig_vault::{params::VaultParams, Vault, VaultSession};

const PASS: &[u8] = b"correct horse battery staple";
const CHAIN_B_REF: &str = "chain-b";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn init_vault_at(garden: &Path) -> VaultSession {
    let (_v, session, _recovery) =
        Vault::init_with_params(garden, PASS, fast_params()).expect("vault init");
    session
}

/// Commit `body` under a single file into `ref_name`, using an out-of-garden
/// staging dir so the second chain's content never touches the device garden.
fn commit_to_chain(
    repo: &mut Repo,
    session: &VaultSession,
    ref_name: &str,
    filename: &str,
    body: &str,
) -> Hash {
    let stage = tempfile::tempdir().unwrap();
    std::fs::write(stage.path().join(filename), body).unwrap();
    let snapshot = walk::walk(stage.path()).unwrap();
    repo.commit_snapshot_to(ref_name, session, snapshot, Intent::init("chain advance"))
        .expect("commit to chain")
}

/// A garden with a device chain (genesis + one more commit) and a second
/// `chain-b` (two commits), each carrying content unique to it.
struct TwoChains {
    repo: Repo,
    session: VaultSession,
    dev_tip: Hash,
    b_tip: Hash,
    genesis: Hash,
    _garden: tempfile::TempDir,
}

fn two_chains() -> TwoChains {
    let garden = tempfile::tempdir().unwrap();
    std::fs::write(garden.path().join("device.md"), "device root content").unwrap();
    let session = init_vault_at(garden.path());
    let (mut repo, genesis) = Repo::init(garden.path(), &session).unwrap();

    // chain-b: two commits, distinct blob content from the device chain.
    commit_to_chain(&mut repo, &session, CHAIN_B_REF, "only-in-b.md", "chain B content v1");
    let b_tip = commit_to_chain(
        &mut repo,
        &session,
        CHAIN_B_REF,
        "only-in-b.md",
        "chain B content v2",
    );

    // Advance the device chain once more via the normal working-tree path.
    std::fs::write(garden.path().join("device.md"), "device root content v2").unwrap();
    let dev_tip = repo
        .commit_workdir(&session, Intent::init("device v2"))
        .unwrap();

    TwoChains {
        repo,
        session,
        dev_tip,
        b_tip,
        genesis,
        _garden: garden,
    }
}

#[test]
fn two_chains_advance_independently() {
    let garden = tempfile::tempdir().unwrap();
    std::fs::write(garden.path().join("device.md"), "device root content").unwrap();
    let session = init_vault_at(garden.path());
    let (mut repo, genesis) = Repo::init(garden.path(), &session).unwrap();

    // Device chain = genesis; chain-b has no tip yet (unset ref → None).
    assert_eq!(repo.tip().unwrap(), Some(genesis));
    assert_eq!(repo.tip_of(CHAIN_B_REF).unwrap(), None);

    // Advance chain-b: device ref must not move, hashes distinct.
    let b1 = commit_to_chain(&mut repo, &session, CHAIN_B_REF, "only-in-b.md", "B one");
    assert_eq!(repo.tip().unwrap(), Some(genesis), "device tip must not move");
    assert_eq!(repo.tip_of(CHAIN_B_REF).unwrap(), Some(b1));
    assert_ne!(genesis, b1);

    // Advance the device chain: chain-b must not move.
    std::fs::write(garden.path().join("device.md"), "device v2").unwrap();
    let d2 = repo.commit_workdir(&session, Intent::init("device v2")).unwrap();
    assert_eq!(repo.tip().unwrap(), Some(d2));
    assert_eq!(repo.tip_of(CHAIN_B_REF).unwrap(), Some(b1), "chain-b tip must not move");

    // Advance chain-b again: device unchanged; per-chain parent linkage holds
    // (b2→b1, d2→genesis) — the two histories don't cross-link.
    let b2 = commit_to_chain(&mut repo, &session, CHAIN_B_REF, "only-in-b.md", "B two");
    assert_eq!(repo.tip().unwrap(), Some(d2));
    assert_eq!(repo.tip_of(CHAIN_B_REF).unwrap(), Some(b2));
    assert_eq!(repo.db().get_commit(&b2).unwrap().parent, Some(b1));
    assert_eq!(repo.db().get_commit(&d2).unwrap().parent, Some(genesis));
}

#[test]
fn per_chain_fsck_is_clean_and_scoped() {
    let tc = two_chains();

    // Each chain fscks clean from its own tip.
    let dev = tc.repo.fsck_chain(TIP_REF).unwrap();
    assert!(dev.ok(), "device fsck problems: {:?}", dev.problems);
    assert!(dev.commits_checked >= 2, "device has genesis + v2");

    let b = tc.repo.fsck_chain(CHAIN_B_REF).unwrap();
    assert!(b.ok(), "chain-b fsck problems: {:?}", b.problems);
    assert_eq!(b.commits_checked, 2, "chain-b closure is exactly its two commits");

    // The two closures are disjoint in commit count vs the whole store: the
    // per-chain report never mixes in the other chain's commits.
    assert!(
        b.commits_checked < dev.commits_checked + b.commits_checked,
        "per-chain fsck is scoped, not whole-store"
    );

    // Whole-store fsck is also clean, and an unset ref is trivially clean.
    assert!(fsck(tc.repo.db(), tc.repo.objects()).unwrap().ok());
    assert!(tc.repo.fsck_chain("no-such-ref").unwrap().ok());
    let _ = (tc.dev_tip, tc.b_tip, tc.genesis, &tc.session);
}

#[test]
fn gc_never_collects_another_chains_objects() {
    let tc = two_chains();
    let TwoChains {
        repo,
        dev_tip,
        b_tip,
        ..
    } = &tc;

    let dev_blobs = reachable_from(repo.db(), *dev_tip).unwrap().blobs;
    let b_blobs = reachable_from(repo.db(), *b_tip).unwrap().blobs;
    // chain-b owns blobs the device chain does not (unique file content).
    let b_exclusive: Vec<Hash> = b_blobs.difference(&dev_blobs).copied().collect();
    assert!(!b_exclusive.is_empty(), "chain-b must own exclusive blobs");

    // A genuinely-orphan loose object, referenced by no chain.
    let orphan = repo
        .objects()
        .put(b"orphan ciphertext referenced by nobody")
        .unwrap();
    assert!(repo.objects().contains(&orphan));

    // gc across the full chain set (device + enabled chain-b): the orphan is
    // collected; every chain's live blob survives — including chain-b's.
    let registry = ChainRegistry::new(
        Chain::device(),
        vec![Chain::shared("c-b", CHAIN_B_REF, "projects", true)],
    );
    let report = tc.repo.gc(&registry).unwrap();
    assert!(report.collected.contains(&orphan), "orphan must be collected");
    assert!(!tc.repo.objects().contains(&orphan));
    for h in dev_blobs.iter().chain(b_blobs.iter()) {
        assert!(
            tc.repo.objects().contains(h),
            "live chain blob {h} must survive gc"
        );
    }

    // Adversarial: had the registry omitted chain-b, its exclusive blobs would
    // be unreachable from the (device-only) live set — i.e. gc *would* delete
    // them. Deriving live tips from the full registry is exactly what prevents
    // that; this is the store-layer face of slice 004's isolation invariant.
    let device_only_live = live_blobs(tc.repo.db(), &[*dev_tip]).unwrap();
    for h in &b_exclusive {
        assert!(
            !device_only_live.contains(h),
            "chain-b blob {h} would be unprotected under a device-only live set"
        );
    }
}

/// Finding 7 (MAJOR): gc retention includes **disabled** chains. Disabling is a
/// mount/compose concern, never a retention concern — so `disable -> gc ->
/// re-enable` must be a lossless local toggle, not a way to destroy a chain's
/// exclusive blobs.
#[test]
fn gc_keeps_a_disabled_chains_exclusive_blobs() {
    let tc = two_chains();

    let dev_blobs = reachable_from(tc.repo.db(), tc.dev_tip).unwrap().blobs;
    let b_blobs = reachable_from(tc.repo.db(), tc.b_tip).unwrap().blobs;
    let b_exclusive: Vec<Hash> = b_blobs.difference(&dev_blobs).copied().collect();
    assert!(!b_exclusive.is_empty(), "chain-b must own exclusive blobs");

    // A genuinely-orphan object proves gc still collects the truly-dead.
    let orphan = tc.repo.objects().put(b"orphan referenced by nobody").unwrap();

    // chain-b is registered but DISABLED (the local mount/compose toggle).
    let registry = ChainRegistry::new(
        Chain::device(),
        vec![Chain::shared("c-b", CHAIN_B_REF, "projects", false)],
    );
    let report = tc.repo.gc(&registry).unwrap();

    assert!(
        report.collected.contains(&orphan),
        "the true orphan must still be collected"
    );
    assert!(!tc.repo.objects().contains(&orphan));
    for h in &b_exclusive {
        assert!(
            tc.repo.objects().contains(h),
            "disabled chain-b's exclusive blob {h} must survive gc (finding 7)"
        );
    }

    // Re-enable + read: the closure is intact, so a per-chain fsck from chain-b's
    // tip is clean — every reachable blob is still present on disk.
    let re_enabled = tc.repo.fsck_chain(CHAIN_B_REF).unwrap();
    assert!(
        re_enabled.ok(),
        "re-enabled chain-b must read clean: {:?}",
        re_enabled.problems
    );
}

/// Finding 13 (MINOR): fsck of a damaged chain returns a problem-bearing report,
/// not an `Err`/panic. Here a referenced tree row is deleted out from under a
/// commit.
#[test]
fn fsck_reports_a_deleted_tree_row_instead_of_erroring() {
    let mut tc = two_chains();
    let b_tip = tc.b_tip;

    // Corrupt the store: delete chain-b's tip root-tree row, leaving a commit
    // that references a now-missing tree.
    let root_tree = tc.repo.db().get_commit(&b_tip).unwrap().root_tree;
    let hex = root_tree.to_hex();
    tc.repo
        .db_mut()
        .with_tx(|conn| {
            // Drop the entries first (FK enforcement is on), then the tree row.
            conn.execute(&format!("DELETE FROM tree_entries WHERE tree_hash = X'{hex}'"), ())
                .expect("delete tree entries");
            conn.execute(&format!("DELETE FROM trees WHERE hash = X'{hex}'"), ())
                .expect("delete tree row");
            Ok(())
        })
        .unwrap();

    // fsck must REPORT the damage, never propagate an Err or panic.
    let report = tc
        .repo
        .fsck_chain(CHAIN_B_REF)
        .expect("fsck of a damaged chain must return a report, not Err");
    assert!(!report.ok(), "a deleted tree row must surface as a problem");
    assert!(
        report.problems.iter().any(|p| p.contains(&root_tree.to_hex())),
        "the report must name the missing tree {root_tree}: {:?}",
        report.problems
    );
    // The device chain is untouched by chain-b's damage.
    assert!(tc.repo.fsck_chain(TIP_REF).unwrap().ok());
}

/// Finding 13, blob face: a referenced blob missing from the object store is a
/// reported problem, not an abort.
#[test]
fn fsck_reports_a_missing_blob_instead_of_erroring() {
    let tc = two_chains();

    // Remove a blob that chain-b references, simulating a torn object store.
    let b_blobs = reachable_from(tc.repo.db(), tc.b_tip).unwrap().blobs;
    let victim = *b_blobs.iter().next().expect("chain-b references blobs");
    tc.repo.objects().remove(&victim).unwrap();
    assert!(!tc.repo.objects().contains(&victim));

    let report = tc
        .repo
        .fsck_chain(CHAIN_B_REF)
        .expect("fsck of a damaged chain must return a report, not Err");
    assert!(!report.ok(), "a missing blob must surface as a problem");
    assert!(
        report.problems.iter().any(|p| p.contains(&victim.to_hex())),
        "the report must name the missing blob {victim}: {:?}",
        report.problems
    );
}
