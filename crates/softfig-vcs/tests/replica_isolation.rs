//! M5c slice 004 — replica isolation at the **store layer** (user requirement #2).
//!
//! The M5b replica push serves `repo.tip()` = the device ref (`TIP_REF`) only,
//! so what it can ever ship a backup host is exactly the device tip's reachable
//! object set. This test proves the load-bearing half of the isolation
//! invariant: a write under a shared mount is carved out of the device snapshot
//! (slice 002's `split_snapshot`) and committed to the shared chain's OWN ref,
//! so the shared blob **never enters the device tip's reachable object graph**.
//! If this carve-out ever regressed, the replica would happily replicate the
//! shared content — hence enforce it by construction here, not by a post-hoc
//! filter (the one-bug-leaks failure mode `spec-sync.md` calls out).
//!
//! The end-to-end mirror-excludes-the-shared-chain proof rides the real Noise
//! serve/pull path in keeperd's `tests/m5b_replica.rs`
//! (`device_chain_replica_excludes_a_shared_chain`); this is its store-level
//! foundation over a live `Repo`.

use std::path::Path;

use softfig_store::Hash;
use softfig_vcs::{reachable_from, Chain, ChainRegistry, Intent, Repo, WalkSnapshot};
use softfig_vault::{params::VaultParams, Vault, VaultSession};

const PASS: &[u8] = b"correct horse battery staple";
const SHARED_REF: &str = "chain/journals";
const MOUNT: &str = "projects/journals";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn init_vault_at(garden: &Path) -> VaultSession {
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS, fast_params()).expect("vault init");
    session
}

/// A write under the shared mount is carved out of the device snapshot and
/// committed to the shared chain's own ref, so the shared ciphertext blob never
/// becomes reachable from the device tip — the object set the replica push ships.
#[test]
fn shared_blob_never_enters_the_device_tips_reachable_set() {
    let garden = tempfile::tempdir().unwrap();
    std::fs::write(garden.path().join("device.md"), "device-only content").unwrap();
    let session = init_vault_at(garden.path());
    let (mut repo, genesis) = Repo::init(garden.path(), &session).unwrap();

    // A registry with one enabled shared subtree at `projects/journals`.
    let reg = ChainRegistry::new(
        Chain::device(),
        vec![Chain::shared("c-journals", SHARED_REF, MOUNT, true)],
    );

    // A unified union-mount working tree: one device-owned file plus a file under
    // the shared mount, each carrying content unique to it. This is the tree the
    // FUSE write path presents; route it exactly as slice 002 does.
    let shared_body = b"SHARED-SUBTREE-SECRET that must never reach a backup mirror".to_vec();
    let mut unified = WalkSnapshot::empty();
    unified
        .insert_file(Path::new("device.md"), 0o100644, b"device-only content".to_vec())
        .unwrap();
    unified
        .insert_file(
            Path::new("projects/journals/entry.md"),
            0o100644,
            shared_body.clone(),
        )
        .unwrap();

    // Split + commit each carved snapshot to its owning chain's ref.
    for (ref_name, snap) in reg.split_snapshot(&unified) {
        repo.commit_snapshot_to(&ref_name, &session, snap, Intent::init("union write"))
            .unwrap();
    }

    let dev_tip = repo.tip().unwrap().unwrap();
    let shared_tip = repo.tip_of(SHARED_REF).unwrap().unwrap();
    assert_ne!(dev_tip, genesis, "the device chain advanced with its own file");
    assert_ne!(shared_tip, dev_tip, "the shared chain has its own distinct tip");

    // Reachability closures from each tip.
    let dev_blobs = reachable_from(repo.db(), dev_tip).unwrap().blobs;
    let shared_blobs = reachable_from(repo.db(), shared_tip).unwrap().blobs;

    // The device tip carries its own content — so the exclusive-blob assertion
    // below is not vacuously true (an empty device graph would trivially
    // "exclude" everything).
    assert!(!dev_blobs.is_empty(), "device tip must carry its own blob");

    // The load-bearing invariant (m5c slice 008, finding 15): the shared chain
    // owns at least one ciphertext blob NOT reachable from the device tip — the
    // secret that must stay out of every backup mirror, since the replica push
    // walks only `repo.tip()` (= the device ref). This is the difference-set
    // assertion, and it is the correct invariant for m5c.
    let shared_exclusive: Vec<Hash> = shared_blobs.difference(&dev_blobs).copied().collect();
    assert!(
        !shared_exclusive.is_empty(),
        "the shared chain must own a blob the device chain does not reach"
    );

    // We deliberately do NOT assert FULL set disjointness
    // (`shared_blobs.is_disjoint(&dev_blobs)`). Under m5c both chains encrypt
    // with the same master key M, so convergent encryption maps identical
    // plaintext in both chains to the same blob hash — a legitimately *shared*
    // blob, not a leak (a backup host that already holds it via the device chain
    // learns nothing new). Full disjointness becomes a true invariant only in
    // m5d, when a shared chain gets its own key S ≠ M and its ciphertext can no
    // longer collide with the device chain's. The isolation guarantee that
    // matters here is the exclusive-blob carve-out above, not full disjointness.
}
