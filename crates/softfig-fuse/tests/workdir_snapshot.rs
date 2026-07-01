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

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use softfig_fuse::{DirtyEventSink, FuseMount, MountHandle};
use softfig_store::{ObjectStore, StorePaths};
use softfig_vault::{params::VaultParams, Vault};
use softfig_vcs::{walk, Repo, TreeNode, WalkSnapshot};

const PASS: &[u8] = b"correct horse battery staple";

/// Serializes the FUSE mount/unmount lifecycle across the tests in this binary.
/// `cargo test` runs tests on parallel threads, and concurrent fusermount3
/// mount/unmount against `/dev/fuse` races in restricted sandboxes ("Operation
/// not permitted" / "Permission denied" on the mountpoint) — a pre-existing
/// flake the parity suite already hit before the dir-rename regressions below
/// were added. Each mount test holds this lock for its whole lifetime; it is
/// poison-tolerant so one failing test does not cascade into the rest.
static MOUNT_GUARD: Mutex<()> = Mutex::new(());

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

/// Flatten a snapshot to `repo/relative/path -> content`, so a test can
/// assert on the surviving file set after a directory-shaped op. A path that
/// resolves to a directory simply doesn't appear (only leaf files are keyed),
/// which is exactly what lets us catch the "directory became a 0-byte file"
/// corruption — a corrupted `renamed` would show up here as a key.
fn files_of(snap: &WalkSnapshot) -> BTreeMap<String, Vec<u8>> {
    fn rec(prefix: &str, node: &TreeNode, out: &mut BTreeMap<String, Vec<u8>>) {
        match node {
            TreeNode::Dir(children) => {
                for (name, child) in children {
                    let path = if prefix.is_empty() {
                        name.clone()
                    } else {
                        format!("{prefix}/{name}")
                    };
                    rec(&path, child, out);
                }
            }
            TreeNode::File { content, .. } => {
                out.insert(prefix.to_string(), content.clone());
            }
        }
    }
    let mut out = BTreeMap::new();
    rec("", &snap.root, &mut out);
    out
}

/// Vault-init + genesis-commit + mount, mirroring the inline setup the parity
/// test uses. The genesis content is whatever was staged under `staging`
/// before the call.
fn mount_genesis(state: &Path, staging: &Path, mount: &Path) -> MountHandle {
    let (_vault, session, _recovery) =
        Vault::init_with_params(state, PASS, fast_params()).expect("vault init");
    let (_repo, _genesis) =
        Repo::create_fresh(mount, state, staging, &session).expect("create_fresh");
    FuseMount::mount(mount, state, Arc::new(session), Arc::new(NoopSink)).expect("mount")
}

#[test]
fn workdir_snapshot_matches_a_live_walk_of_the_mount() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping workdir_snapshot parity: /dev/fuse unavailable in this environment");
        return;
    }
    let _mount_guard = MOUNT_GUARD.lock().unwrap_or_else(|e| e.into_inner());

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

/// Audit slice 002 (the no-op-commit-churn fix): the keeperd watcher's dirty-set
/// `accept()` filter caches the exclusion set from [`MountHandle::inmem_ignore`]
/// so it can drop user-`.softfigignore`'d paths on the fuser worker thread
/// *without* `std::fs`-reading the mount it serves (the slice-003 reentrant
/// deadlock). This proves the seam it caches from: `inmem_ignore` reflects the
/// committed-tip `.softfigignore`, and — crucially for "takes effect on the next
/// save" — an *uncommitted* overlay edit too, since the FUSE write handler
/// updates the overlay before the sink fires. No read goes back through the mount.
#[test]
fn inmem_ignore_reflects_the_softfigignore_including_an_uncommitted_overlay_edit() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping inmem_ignore: /dev/fuse unavailable in this environment");
        return;
    }
    let _mount_guard = MOUNT_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    let state = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let mount = tempfile::tempdir().unwrap();

    // Genesis tip excludes `scratch`.
    write(staging.path(), "a.md", b"genesis");
    write(staging.path(), ".softfigignore", b"scratch\n");
    let handle = mount_genesis(state.path(), staging.path(), mount.path());

    // From the committed tip: built-ins (`.softfig`, `.claude`) ∪ `scratch`.
    let ig = handle.inmem_ignore().expect("inmem_ignore from tip");
    assert!(ig.is_ignored(Path::new("scratch/junk.md")));
    assert!(ig.is_ignored(Path::new(".softfig/objects/aa/bb"))); // built-in
    assert!(ig.is_ignored(Path::new(".claude/settings.local.json"))); // built-in
    assert!(!ig.is_ignored(Path::new("journal/decisions/d.md")));
    assert!(!ig.is_ignored(Path::new("notes/n.md"))); // not yet listed

    // Edit `.softfigignore` through the mount to also exclude `notes`. The write
    // lands in the overlay; `inmem_ignore` takes overlay precedence, so the new
    // rule is in force *before* any commit — the exact freshness the watcher's
    // accept cache relies on, reconstructed with no read back through the mount.
    fs::write(mount.path().join(".softfigignore"), b"scratch\nnotes\n").unwrap();
    let ig2 = handle.inmem_ignore().expect("inmem_ignore from overlay");
    assert!(ig2.is_ignored(Path::new("notes/n.md")));
    assert!(ig2.is_ignored(Path::new("scratch/junk.md")));
    assert!(!ig2.is_ignored(Path::new("journal/decisions/d.md")));

    handle.unmount();
}

/// Regression for the HIGH data-loss finding `kernel-rename-directory-data-loss`
/// (audit slice 002). A human-facing `mv dir newdir` through the kernel must
/// re-key every descendant under the new prefix, not materialize a 0-byte file
/// and silently drop the subtree from the next commit.
///
/// Before the fix this fails: `renamed` is a 0-byte regular file and
/// `renamed/a.md` / `renamed/sub/b.md` are absent from the snapshot.
#[test]
fn kernel_rename_of_a_directory_preserves_the_whole_subtree() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping dir-rename data-loss test: /dev/fuse unavailable in this environment");
        return;
    }
    let _mount_guard = MOUNT_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    let state = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let mount = tempfile::tempdir().unwrap();

    // A directory with a file at its top and one nested a level deeper, plus an
    // unrelated sibling that must stay put.
    write(staging.path(), "docs/a.md", b"alpha");
    write(staging.path(), "docs/sub/b.md", b"beta");
    write(staging.path(), "keep.md", b"unrelated");

    let handle = mount_genesis(state.path(), staging.path(), mount.path());
    let m = mount.path();

    // The human-facing kernel op: `mv docs renamed`.
    fs::rename(m.join("docs"), m.join("renamed")).expect("rename a directory through the kernel");

    let snapshot = handle.workdir_snapshot().expect("workdir_snapshot");
    let files = files_of(&snapshot);

    // The subtree survives, byte-for-byte, under the new prefix...
    assert_eq!(
        files.get("renamed/a.md").map(Vec::as_slice),
        Some(b"alpha".as_ref()),
        "top-level file must move with its directory: {:?}",
        files.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        files.get("renamed/sub/b.md").map(Vec::as_slice),
        Some(b"beta".as_ref()),
        "nested file must move with its directory: {:?}",
        files.keys().collect::<Vec<_>>()
    );
    // ...nothing lingers under the old prefix...
    assert!(
        !files.keys().any(|k| k == "docs" || k.starts_with("docs/")),
        "the old directory prefix must be gone: {:?}",
        files.keys().collect::<Vec<_>>()
    );
    // ...the destination is a directory, never the 0-byte file the bug minted...
    assert!(
        !files.contains_key("renamed"),
        "`renamed` must be a directory, not a 0-byte regular file"
    );
    // ...and the unrelated sibling is untouched.
    assert_eq!(
        files.get("keep.md").map(Vec::as_slice),
        Some(b"unrelated".as_ref())
    );

    // The in-memory reconstruction must still match a real walk back through
    // the mount — the live tree and what we'd commit agree.
    let walked = walk(m).expect("walk mount");
    assert_eq!(
        snapshot, walked,
        "in-memory (tip ∪ overlay) reconstruction must match a live walk after a dir rename"
    );

    handle.unmount();
}

/// Regression for the second half of audit slice 002: FUSE does not guarantee
/// the directory is empty before calling `rmdir`, so the filesystem must return
/// ENOTEMPTY rather than orphaning the contents by marking the dir removed.
///
/// Before the fix this fails: `remove_dir` succeeds and `full/keepme.md`
/// vanishes from the snapshot.
#[test]
fn kernel_rmdir_of_a_nonempty_directory_is_refused() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping rmdir ENOTEMPTY test: /dev/fuse unavailable in this environment");
        return;
    }
    let _mount_guard = MOUNT_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    let state = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let mount = tempfile::tempdir().unwrap();

    write(staging.path(), "full/keepme.md", b"data");
    write(staging.path(), "solo.md", b"x");

    let handle = mount_genesis(state.path(), staging.path(), mount.path());
    let m = mount.path();

    // rmdir on a populated directory must fail with ENOTEMPTY.
    let err = fs::remove_dir(m.join("full")).expect_err("rmdir of a non-empty dir must fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTEMPTY),
        "expected ENOTEMPTY, got {err:?}"
    );

    // The contents must still be present and intact after the refusal.
    let snapshot = handle.workdir_snapshot().expect("workdir_snapshot");
    let files = files_of(&snapshot);
    assert_eq!(
        files.get("full/keepme.md").map(Vec::as_slice),
        Some(b"data".as_ref()),
        "a refused rmdir must not orphan the directory's contents: {:?}",
        files.keys().collect::<Vec<_>>()
    );

    // An empty directory, by contrast, removes cleanly.
    fs::create_dir(m.join("empty")).expect("mkdir");
    fs::remove_dir(m.join("empty")).expect("rmdir of an empty dir must succeed");

    handle.unmount();
}

/// Regression for `audit-hardening-regressions` slice 001, hole #2 of audit
/// slice 002's `stage_rename`: the rename re-keyed only *file* descendants and
/// never the directory markers, so the emptied source dir lingered in the live
/// view. Asserted through `read_dir_entries` (the one-level live view), which —
/// unlike `files_of` / a `walk` — does NOT prune empty directories, so the
/// leftover source dir is observable (the slice-002 test catches neither this
/// nor the empty-dir no-op below).
#[test]
fn dir_rename_leaves_no_empty_source_dir_in_the_live_view() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping dir-rename leftover-source-dir test: /dev/fuse unavailable");
        return;
    }
    let _mount_guard = MOUNT_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    let state = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let mount = tempfile::tempdir().unwrap();

    write(staging.path(), "docs/a.md", b"alpha");
    write(staging.path(), "docs/sub/b.md", b"beta");
    write(staging.path(), "keep.md", b"unrelated");

    let handle = mount_genesis(state.path(), staging.path(), mount.path());
    let m = mount.path();

    fs::rename(m.join("docs"), m.join("renamed")).expect("rename a directory through the kernel");

    // The emptied source dir must not linger; the destination dir and the
    // unrelated sibling must be present.
    let root: Vec<String> = handle
        .read_dir_entries("")
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(
        !root.iter().any(|n| n == "docs"),
        "the emptied source directory must not linger in the live view: {root:?}"
    );
    assert!(
        root.iter().any(|n| n == "renamed"),
        "the destination directory must appear: {root:?}"
    );
    assert!(
        root.iter().any(|n| n == "keep.md"),
        "the unrelated sibling must remain: {root:?}"
    );

    // The re-keyed subtree is reachable under the new prefix (dirs included)...
    assert!(handle.path_is_dir("renamed"), "renamed must be a directory");
    assert!(handle.path_is_dir("renamed/sub"), "the nested dir must move too");
    assert_eq!(
        handle.read_workfile("renamed/a.md").unwrap().as_deref(),
        Some(b"alpha".as_ref())
    );
    assert_eq!(
        handle.read_workfile("renamed/sub/b.md").unwrap().as_deref(),
        Some(b"beta".as_ref())
    );
    // ...and nothing — file or directory — remains reachable under the old one.
    assert!(!handle.path_exists("docs"), "the source dir must be gone");
    assert!(!handle.path_exists("docs/a.md"), "the source file must be gone");
    assert!(!handle.path_exists("docs/sub"), "the source subdir must be gone");

    handle.unmount();
}

/// Regression for `audit-hardening-regressions` slice 001, the empty-directory
/// half of hole #2: a `mv emptydir newname` enumerated zero file movers, so the
/// old loop ran zero iterations and returned `Ok` while nothing moved — a silent
/// no-op the kernel reported as success. The dir-aware rename must move the
/// marker so the destination appears and the source disappears.
#[test]
fn empty_dir_rename_is_not_a_silent_no_op() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping empty-dir rename test: /dev/fuse unavailable");
        return;
    }
    let _mount_guard = MOUNT_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    let state = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let mount = tempfile::tempdir().unwrap();

    write(staging.path(), "keep.md", b"x"); // a non-empty genesis
    let handle = mount_genesis(state.path(), staging.path(), mount.path());
    let m = mount.path();

    fs::create_dir(m.join("foo")).expect("mkdir an empty dir");
    fs::rename(m.join("foo"), m.join("bar")).expect("rename the empty dir through the kernel");

    let root: Vec<String> = handle
        .read_dir_entries("")
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(
        !root.iter().any(|n| n == "foo"),
        "the renamed-away empty source dir must disappear: {root:?}"
    );
    assert!(
        root.iter().any(|n| n == "bar"),
        "the empty dir must appear at its destination, not be silently dropped: {root:?}"
    );
    assert!(handle.path_is_dir("bar"), "the destination must be a directory");
    assert!(!handle.path_exists("foo"), "the source must be gone");

    handle.unmount();
}

/// Regression for `audit-hardening-regressions` slice 001, hole #1 of audit
/// slice 002: `stage_rename` read each mover's bytes *inside* the mutation loop,
/// so a read failure on a later mover left earlier movers already re-keyed in the
/// overlay — a half-renamed subtree the next debounce would commit. The two-pass
/// fix reads every mover up front and aborts with the overlay untouched.
///
/// `docs/a.md` is staged into the overlay (so it reads from memory and is
/// enumerated before the tip blob `docs/b.md`); the object store is then dropped
/// so reading `docs/b.md` fails. The old in-loop code re-keyed `a.md` before
/// hitting `b.md`'s failing read; the fix must leave nothing moved.
#[test]
fn dir_rename_aborts_with_no_partial_mutation_on_a_read_failure() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping rename-atomicity test: /dev/fuse unavailable");
        return;
    }
    let _mount_guard = MOUNT_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    let state = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let mount = tempfile::tempdir().unwrap();

    write(staging.path(), "docs/b.md", b"beta");
    write(staging.path(), "keep.md", b"unrelated");
    let handle = mount_genesis(state.path(), staging.path(), mount.path());

    handle.stage_write("docs/a.md", b"alpha".to_vec());

    // Make every committed object unreadable, so reading the tip blob `docs/b.md`
    // fails while the overlay file `docs/a.md` still reads from memory.
    let objects = StorePaths::with_state_root(mount.path(), state.path()).objects_dir();
    fs::remove_dir_all(&objects).expect("drop the object store to force a read failure");

    let result = handle.stage_rename("docs", "renamed");
    assert!(
        result.is_err(),
        "a mover read failure must surface as an error, got {result:?}"
    );

    // Nothing partially moved: no destination staged, the readable mover is still
    // at its original path, and the source dir still lists both files.
    assert!(
        !handle.path_exists("renamed"),
        "no destination subtree may be staged after an aborted rename"
    );
    assert!(
        !handle.path_exists("renamed/a.md"),
        "the readable mover must NOT have been re-keyed"
    );
    assert_eq!(
        handle.read_workfile("docs/a.md").unwrap().as_deref(),
        Some(b"alpha".as_ref()),
        "the overlay mover must remain byte-for-byte at its original path"
    );
    let docs: Vec<String> = handle
        .read_dir_entries("docs")
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(
        docs.iter().any(|n| n == "a.md") && docs.iter().any(|n| n == "b.md"),
        "the source directory must still list both files: {docs:?}"
    );

    handle.unmount();
}
