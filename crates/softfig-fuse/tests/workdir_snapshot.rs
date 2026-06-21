//! Live-mount parity test for `MountHandle::workdir_snapshot`.
//!
//! Slice 2 of the 2026-06-21 commit-path busy-mount deadlock fix.
//! Reconstructing the working tree from the FUSE driver's in-memory
//! (tip-view ∪ overlay) state must match a real `softfig_vcs::walk` of
//! the mount over the full matrix — create / modify / delete / rename /
//! mkdir / `.keep` / ignored paths — so that the daemon can commit from
//! the snapshot without self-reading the mount it serves. That is the
//! slice acceptance: `commit_snapshot(workdir_snapshot()) ==
//! commit_workdir()`.
//!
//! Needs a working `/dev/fuse`; skipped with a note when it is absent
//! (CI sandboxes, containers without the device).

use std::fs;
use std::path::Path;
use std::sync::Arc;

use softfig_fuse::{DirtyEventSink, FuseMount};
use softfig_store::{ObjectStore, StorePaths};
use softfig_vault::{params::VaultParams, Vault};
use softfig_vcs::{walk, Repo, TreeNode, WalkSnapshot};

const PASS: &[u8] = b"correct horse battery staple";

/// Minimum-cost Argon2 so vault init stays well under a second.
fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

/// No-op dirty sink — the parity check doesn't drive the commit
/// debounce, only the in-memory reconstruction.
struct NoopSink;
impl DirtyEventSink for NoopSink {
    fn created(&self, _: &str) {}
    fn modified(&self, _: &str) {}
    fn removed(&self, _: &str) {}
    fn renamed(&self, _: &str, _: &str) {}
    fn nudge(&self) {}
}

fn write(root: &Path, rel: &str, body: &[u8]) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn top_level_names(snap: &WalkSnapshot) -> Vec<String> {
    match &snap.root {
        TreeNode::Dir(children) => children.keys().cloned().collect(),
        TreeNode::File { .. } => panic!("snapshot root is always a Dir"),
    }
}

#[test]
fn workdir_snapshot_matches_a_live_walk_of_the_mount() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping workdir_snapshot parity: /dev/fuse unavailable in this environment");
        return;
    }

    let state = tempfile::tempdir().unwrap(); // .softfig + vault live here
    let staging = tempfile::tempdir().unwrap(); // genesis working-tree content
    let mount = tempfile::tempdir().unwrap(); // FUSE mount point

    // Genesis tip: a small tree plus a `.softfigignore` excluding `scratch`,
    // a `.keep`-held dir, and a single-file dir we'll later empty.
    write(staging.path(), "a.md", b"genesis-a");
    write(staging.path(), "mod.md", b"before");
    write(staging.path(), "del.md", b"doomed");
    write(staging.path(), "ren_src.md", b"rename me");
    write(staging.path(), "keepme/.keep", b"");
    write(staging.path(), "subdel/only.md", b"sole");
    write(staging.path(), "nested/deep/leaf.md", b"deep");
    write(staging.path(), ".softfigignore", b"scratch\n");

    let (_vault, session, _recovery) =
        Vault::init_with_params(state.path(), PASS, fast_params()).expect("vault init");
    let (_repo, _genesis) = Repo::create_fresh(mount.path(), state.path(), staging.path(), &session)
        .expect("create_fresh");

    let session = Arc::new(session);
    let handle = FuseMount::mount(mount.path(), state.path(), session.clone(), Arc::new(NoopSink))
        .expect("mount");

    let m = mount.path();
    // --- mutate through the kernel, exercising every overlay code path ---
    fs::write(m.join("mod.md"), b"after").unwrap(); // modify an existing tip file
    fs::remove_file(m.join("del.md")).unwrap(); // unlink a tip file
    fs::rename(m.join("ren_src.md"), m.join("ren_dst.md")).unwrap(); // rename a tip file
    fs::write(m.join("new.md"), b"brand new").unwrap(); // create a new file
    fs::remove_file(m.join("subdel/only.md")).unwrap(); // empties subdel/ -> pruned
    fs::create_dir(m.join("emptydir")).unwrap(); // mkdir, no .keep -> pruned
    fs::create_dir(m.join("keptdir")).unwrap(); // mkdir ...
    fs::write(m.join("keptdir/.keep"), b"").unwrap(); //   ... held by a .keep sentinel
    fs::create_dir(m.join(".claude")).unwrap(); // built-in ignored top-level
    fs::write(m.join(".claude/settings.local.json"), b"{}").unwrap();
    fs::create_dir(m.join("scratch")).unwrap(); // .softfigignore'd top-level
    fs::write(m.join("scratch/junk.md"), b"noise").unwrap();

    // The whole point: the in-memory reconstruction (no kernel round-trip)
    // versus a real walk that reads back *through* the mount.
    let snapshot = handle.workdir_snapshot().expect("workdir_snapshot");
    let walked = walk(m).expect("walk mount");

    assert_eq!(
        snapshot, walked,
        "in-memory (tip ∪ overlay) reconstruction must match a live walk of the mount"
    );

    // Literal acceptance: the *commit tree* of each is identical — same
    // root_tree hash out of `tree::build`, which is exactly what
    // `commit_snapshot` / `commit_workdir` feed into the commit.
    let objects = ObjectStore::new(StorePaths::with_state_root(m, state.path()));
    let from_snapshot = softfig_vcs::tree::build(&objects, &session, &snapshot.root)
        .expect("build tree from snapshot")
        .root;
    let from_walk = softfig_vcs::tree::build(&objects, &session, &walked.root)
        .expect("build tree from walk")
        .root;
    assert_eq!(
        from_snapshot, from_walk,
        "commit_snapshot(workdir_snapshot()) and commit_workdir() must build the same root tree"
    );

    // Guard against both sides sharing the same bug: confirm the matrix
    // actually landed the way we intended.
    let names = top_level_names(&walked);
    for present in [
        "a.md",
        "mod.md",
        "ren_dst.md",
        "new.md",
        "keepme",
        "keptdir",
        "nested",
        ".softfigignore",
    ] {
        assert!(
            names.contains(&present.to_string()),
            "{present} should be tracked: {names:?}"
        );
    }
    for absent in ["del.md", "ren_src.md", "subdel", "emptydir", ".claude", "scratch"] {
        assert!(
            !names.contains(&absent.to_string()),
            "{absent} should be gone or ignored: {names:?}"
        );
    }

    handle.unmount();
}
