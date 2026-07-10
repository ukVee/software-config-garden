//! M5c slice 002 — the union-mount **write router**: a unified working-tree
//! snapshot splits into one snapshot per enabled chain, and a write under a
//! shared mount advances only that chain's ref — never the device ref.
//!
//! These are the headless core of slice 002 (the live FUSE union render is a
//! deferred, `/dev/fuse`-gated smoke). They prove the `split_snapshot` router
//! and the `walk_filtered` carve-out at the store layer, exactly where slice
//! 004's isolation invariant is enforced by construction.

use std::path::{Path, PathBuf};

use softfig_vcs::{
    walk, walk_filtered, Chain, ChainRegistry, Intent, Repo, WalkSnapshot, TIP_REF,
};
use softfig_vault::{params::VaultParams, Vault, VaultSession};

const PASS: &[u8] = b"correct horse battery staple";
const B_REF: &str = "chain-b";
const MOUNT: &str = "projects";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn init_vault_at(garden: &Path) -> VaultSession {
    let (_v, session, _r) = Vault::init_with_params(garden, PASS, fast_params()).expect("vault init");
    session
}

/// The forward-slash file paths in a snapshot, sorted — the committed set.
fn paths(snap: &WalkSnapshot) -> Vec<String> {
    let mut v: Vec<String> = snap
        .files()
        .into_iter()
        .map(|(p, _, _)| p.to_string_lossy().replace('\\', "/"))
        .collect();
    v.sort();
    v
}

fn snap_for(reg: &ChainRegistry, snaps: &[(String, WalkSnapshot)], ref_name: &str) -> Vec<String> {
    let s = snaps
        .iter()
        .find(|(r, _)| r == ref_name)
        .map(|(_, s)| s)
        .unwrap_or_else(|| panic!("no snapshot for ref {ref_name} in {reg:?}"));
    paths(s)
}

/// A unified working tree: one device-owned file + a two-deep shared subtree.
fn unified_tree() -> (tempfile::TempDir, WalkSnapshot) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("device.md"), "device").unwrap();
    std::fs::create_dir_all(dir.path().join("projects/sub")).unwrap();
    std::fs::write(dir.path().join("projects/app.md"), "app").unwrap();
    std::fs::write(dir.path().join("projects/sub/deep.md"), "deep").unwrap();
    let snap = walk::walk(dir.path()).unwrap();
    (dir, snap)
}

#[test]
fn split_routes_device_and_shared_prefix_stripped() {
    let (_d, unified) = unified_tree();
    let reg = ChainRegistry::new(
        Chain::device(),
        vec![Chain::shared("c-b", B_REF, MOUNT, true)],
    );
    let snaps = reg.split_snapshot(&unified);

    // Device chain keeps ONLY its own path — the carve-out (slice 004 pin).
    assert_eq!(snap_for(&reg, &snaps, TIP_REF), vec!["device.md"]);
    // Shared chain gets its subtree with the `projects/` prefix stripped, so its
    // committed tree is self-contained + mount-relative.
    assert_eq!(
        snap_for(&reg, &snaps, B_REF),
        vec!["app.md", "sub/deep.md"]
    );
    // No shared path ever leaks into the device snapshot.
    assert!(paths(
        snaps.iter().find(|(r, _)| r == TIP_REF).map(|(_, s)| s).unwrap()
    )
    .iter()
    .all(|p| !p.starts_with("projects")));
}

#[test]
fn device_only_split_is_byte_identical() {
    let (_d, unified) = unified_tree();
    let reg = ChainRegistry::device_only();
    let snaps = reg.split_snapshot(&unified);
    // Exactly one chain (device) and it carries the whole tree unchanged.
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].0, TIP_REF);
    assert_eq!(paths(&snaps[0].1), paths(&unified));
}

#[test]
fn disabled_shared_falls_back_into_the_device_snapshot() {
    let (_d, unified) = unified_tree();
    let reg = ChainRegistry::new(
        Chain::device(),
        vec![Chain::shared("c-b", B_REF, MOUNT, false)],
    );
    let snaps = reg.split_snapshot(&unified);
    // Disabled shared chain is not a live chain → no snapshot for it...
    assert!(snaps.iter().all(|(r, _)| r != B_REF));
    // ...and its subtree routes back to the device chain (transparent).
    assert_eq!(
        snap_for(&reg, &snaps, TIP_REF),
        vec!["device.md", "projects/app.md", "projects/sub/deep.md"]
    );
}

#[test]
fn walk_filtered_carves_out_a_shared_mount() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("device.md"), "device").unwrap();
    std::fs::create_dir_all(dir.path().join("projects")).unwrap();
    std::fs::write(dir.path().join("projects/app.md"), "app").unwrap();
    let reg = ChainRegistry::new(
        Chain::device(),
        vec![Chain::shared("c-b", B_REF, MOUNT, true)],
    );
    // The device-chain disk walk keeps only device-owned paths — the same
    // carve-out `split_snapshot` gives the in-memory FUSE tree.
    let snap = walk_filtered(dir.path(), |p: &Path| reg.is_device_owned(p)).unwrap();
    assert_eq!(paths(&snap), vec!["device.md"]);
}

/// The load-bearing correctness bit: a write under the shared mount commits to
/// the shared chain's ref and leaves the device ref exactly where it was.
#[test]
fn write_under_subpath_advances_only_the_shared_ref() {
    let garden = tempfile::tempdir().unwrap();
    std::fs::write(garden.path().join("device.md"), "device v1").unwrap();
    let session = init_vault_at(garden.path());
    let (mut repo, genesis) = Repo::init(garden.path(), &session).unwrap();

    let reg = ChainRegistry::new(
        Chain::device(),
        vec![Chain::shared("c-b", B_REF, MOUNT, true)],
    );

    // Seed the shared chain once (its own ref), device ref must not move.
    let stage = tempfile::tempdir().unwrap();
    std::fs::write(stage.path().join("app.md"), "app v1").unwrap();
    let b1 = repo
        .commit_snapshot_to(B_REF, &session, walk::walk(stage.path()).unwrap(), Intent::init("seed b"))
        .unwrap();
    assert_eq!(repo.tip().unwrap(), Some(genesis), "seeding b must not move device");

    // A write lands ONLY under `projects/` — the unified tree now has a new
    // shared file. Route it: the affected chain is chain-b; the device chain
    // owns no touched path, so it is not committed.
    let mut unified = WalkSnapshot::empty();
    unified.insert_file(Path::new("device.md"), 0o100644, b"device v1".to_vec()).unwrap();
    unified.insert_file(Path::new("projects/app.md"), 0o100644, b"app v2".to_vec()).unwrap();
    let snaps = reg.split_snapshot(&unified);

    let touched = [PathBuf::from("projects/app.md")];
    let affected: Vec<String> = touched
        .iter()
        .map(|p| reg.owning_chain(p).ref_name.clone())
        .collect();
    assert_eq!(affected, vec![B_REF.to_string()], "a projects/ write routes to chain-b");

    for (ref_name, snap) in snaps {
        if affected.contains(&ref_name) {
            repo.commit_snapshot_to(&ref_name, &session, snap, Intent::init("shared write"))
                .unwrap();
        }
    }

    // Device ref untouched; chain-b advanced past its seed.
    assert_eq!(repo.tip().unwrap(), Some(genesis), "device ref must NOT move on a shared write");
    let b2 = repo.tip_of(B_REF).unwrap().unwrap();
    assert_ne!(b2, b1, "chain-b ref advanced");
    assert_eq!(repo.db().get_commit(&b2).unwrap().parent, Some(b1), "b2 → b1 linkage");
}
