//! Integration tests for the git source transfer (spec remote-runner §4.2–§4.4)
//! against a real `git` binary: the full snapshot → bundle → ingest → verify →
//! materialize round trip, plus the hardening properties a hostile tree must
//! not defeat (symlink escape, `.git`-shaped paths, `export-subst`, gitlinks).

use std::path::Path;
use std::process::{Command, Stdio};

use softfig_source::{
    create_bundle, ingest_bundle, materialize, snapshot_repo, verify_snapshot, SubmodulePolicy,
};

/// Run `git -C <dir> <args>`, asserting success.
fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("run git");
    assert!(ok.success(), "git {args:?} failed");
}

/// A fresh repo with a fixed identity and one committed file.
fn repo_with_file(content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(dir.path(), &["config", "user.email", "t@t"]);
    git(dir.path(), &["config", "user.name", "t"]);
    git(dir.path(), &["config", "commit.gpgsign", "false"]);
    std::fs::write(dir.path().join("f.txt"), content).unwrap();
    git(dir.path(), &["add", "f.txt"]);
    git(dir.path(), &["commit", "-q", "-m", "c1"]);
    dir
}

/// A bare mirror + a fresh `/src`, ready for ingest/materialize.
fn mirror_and_src() -> (tempfile::TempDir, std::path::PathBuf) {
    let base = tempfile::tempdir().unwrap();
    let src = base.path().join("src");
    (base, src)
}

/// Snapshot → bundle → ingest → verify → materialize, returning `src`.
fn ship_and_materialize(
    repo: &Path,
    device_id: &[u8; 32],
    git_metadata: bool,
) -> (tempfile::TempDir, std::path::PathBuf, softfig_source::SourceId, Vec<u8>) {
    let snap = snapshot_repo(repo, SubmodulePolicy::Refuse).unwrap();
    let haves: Vec<Vec<u8>> = Vec::new();
    let bundle = create_bundle(repo, &snap.source_id, &snap.commit, &haves).unwrap();

    let (base, src) = mirror_and_src();
    let mirror = base.path().join("m.git");
    ingest_bundle(&mirror, &snap.source_id, &bundle).unwrap();
    verify_snapshot(&mirror, &snap.source_id, &snap.commit).unwrap();
    materialize(&mirror, &snap.source_id, &snap.commit, &src, git_metadata).unwrap();
    let _ = device_id;
    (base, src, snap.source_id, snap.commit)
}

#[test]
fn full_round_trip_includes_dirty_and_untracked_excludes_ignored() {
    let dir = repo_with_file("one\n");
    std::fs::write(dir.path().join("f.txt"), "two\n").unwrap();
    std::fs::write(dir.path().join("untracked.txt"), "u\n").unwrap();
    std::fs::write(dir.path().join(".gitignore"), "ignored.txt\n").unwrap();
    std::fs::write(dir.path().join("ignored.txt"), "i\n").unwrap();

    let (_base, src, _sid, _c) = ship_and_materialize(dir.path(), &[1u8; 32], false);

    assert_eq!(std::fs::read_to_string(src.join("f.txt")).unwrap(), "two\n");
    assert_eq!(std::fs::read_to_string(src.join("untracked.txt")).unwrap(), "u\n");
    assert!(!src.join("ignored.txt").exists(), "ignored file must be excluded");
}

#[test]
fn symlink_out_is_materialized_as_a_symlink_not_followed() {
    let dir = repo_with_file("x\n");
    // Two symlinks pointing outside the tree: at /etc/passwd and at a
    // "keys"-shaped sentinel file (the runner's trust material).
    let keys = dir.path().parent().unwrap().join("runner-keys-sentinel");
    std::fs::write(&keys, "secret-key-material\n").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", dir.path().join("evil")).unwrap();
    std::os::unix::fs::symlink(&keys, dir.path().join("evil-keys")).unwrap();
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-q", "-m", "c2"]);

    let (_base, src, _sid, _c) = ship_and_materialize(dir.path(), &[2u8; 32], false);

    // Materialized as symlinks (lstat, never followed).
    let evil_meta = std::fs::symlink_metadata(src.join("evil")).unwrap();
    assert!(evil_meta.file_type().is_symlink(), "evil must be a symlink");
    assert_eq!(std::fs::read_link(src.join("evil")).unwrap(), std::path::Path::new("/etc/passwd"));

    let keys_meta = std::fs::symlink_metadata(src.join("evil-keys")).unwrap();
    assert!(keys_meta.file_type().is_symlink(), "evil-keys must be a symlink");

    // The targets were not written through: the sentinel is untouched.
    assert_eq!(
        std::fs::read_to_string(&keys).unwrap(),
        "secret-key-material\n",
        "materialize must not write through a symlink to the keys sentinel"
    );
}

#[test]
fn export_subst_is_not_applied() {
    let dir = repo_with_file("x\n");
    std::fs::write(dir.path().join(".gitattributes"), "*.txt export-subst\n").unwrap();
    std::fs::write(dir.path().join("fmt.txt"), "hash=$Format:%H$\n").unwrap();
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-q", "-m", "c2"]);

    let (_base, src, _sid, _c) = ship_and_materialize(dir.path(), &[3u8; 32], false);

    // read-tree + checkout-index preserves the literal placeholder; git archive
    // would have substituted the commit hash (which is exactly why it is banned).
    assert_eq!(
        std::fs::read_to_string(src.join("fmt.txt")).unwrap(),
        "hash=$Format:%H$\n"
    );
}

/// Build a tree + commit from a flat list of `(mode, type, sha, path)` entries,
/// nested paths included, via `git mktree` bottom-up.
fn mktree(repo: &Path, entries: &[(String, String, String, String)]) -> String {
    // group by top-level component; recurse for nested paths
    use std::collections::BTreeMap;
    let mut top: BTreeMap<String, Vec<(String, String, String, String)>> = BTreeMap::new();
    for (mode, ty, sha, path) in entries {
        let (first, rest) = match path.split_once('/') {
            Some((f, r)) => (f.to_string(), r.to_string()),
            None => (path.clone(), String::new()),
        };
        top.entry(first).or_default().push((mode.clone(), ty.clone(), sha.clone(), rest));
    }
    let mut input = String::new();
    for (name, kids) in top {
        if kids.len() == 1 && kids[0].3.is_empty() {
            let (mode, ty, sha, _) = &kids[0];
            input.push_str(&format!("{mode} {ty} {sha}\t{name}\n"));
        } else {
            // a subtree
            let sub_tree = mktree(repo, &kids);
            input.push_str(&format!("040000 tree {sub_tree}\t{name}\n"));
        }
    }
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["mktree"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("mktree");
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(input.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "mktree failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn write_blob(repo: &Path, content: &[u8]) -> String {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hash-object");
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(content).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "hash-object failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Build a commit from entries `(mode, path, content)` in a repo; returns
/// `(tree_hex, commit_hex)`. For `120000` the content is the link target; for
/// `160000` it is the submodule commit sha.
fn commit_from_entries(repo: &Path, entries: &[(String, String, String)]) -> (String, String) {
    let mut tree_entries: Vec<(String, String, String, String)> = Vec::new();
    for (mode, path, content) in entries {
        let (sha, ty) = match mode.as_str() {
            // A gitlink references the submodule commit by raw sha.
            "160000" => (content.clone(), "commit".to_string()),
            // A symlink stores the link target as a blob.
            "120000" => (write_blob(repo, content.as_bytes()), "blob".to_string()),
            _ => (write_blob(repo, content.as_bytes()), "blob".to_string()),
        };
        tree_entries.push((mode.clone(), ty, sha, path.clone()));
    }
    let tree = mktree(repo, &tree_entries);
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["commit-tree", &tree, "-m", "evil"])
        .output()
        .unwrap();
    assert!(out.status.success());
    (tree, String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Ingest + materialize an arbitrary commit built from entries.
fn materialize_entries(entries: &[(String, String, String)]) -> (tempfile::TempDir, std::path::PathBuf) {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "-q"]);
    git(repo.path(), &["config", "user.email", "t@t"]);
    git(repo.path(), &["config", "user.name", "t"]);
    let (tree_hex, commit_hex) = commit_from_entries(repo.path(), entries);
    let source_id = softfig_source::SourceId::from_git_hash(&tree_hex).unwrap();
    let commit = hex::decode(&commit_hex).unwrap();
    let bundle = create_bundle(repo.path(), &source_id, &commit, &[]).unwrap();

    let (base, src) = mirror_and_src();
    let mirror = base.path().join("m.git");
    ingest_bundle(&mirror, &source_id, &bundle).unwrap();
    verify_snapshot(&mirror, &source_id, &commit).unwrap();
    materialize(&mirror, &source_id, &commit, &src, false).unwrap();
    (base, src)
}

#[test]
fn dotgit_hooks_path_is_rejected_at_materialize() {
    // A tree with `.git/hooks/pre-commit` must be rejected by materialize
    // (read-tree refuses a `.git` path component), so a hostile tree cannot
    // plant a hook in the runner's git dir.
    let entries = vec![(
        "100644".to_string(),
        ".git/hooks/pre-commit".to_string(),
        "#!/bin/sh\ntouch /tmp/pwned\n".to_string(),
    )];
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "-q"]);
    git(repo.path(), &["config", "user.email", "t@t"]);
    git(repo.path(), &["config", "user.name", "t"]);
    let (tree_hex, commit_hex) = commit_from_entries(repo.path(), &entries);
    let source_id = softfig_source::SourceId::from_git_hash(&tree_hex).unwrap();
    let commit = hex::decode(&commit_hex).unwrap();
    let bundle = create_bundle(repo.path(), &source_id, &commit, &[]).unwrap();

    let (base, _src) = mirror_and_src();
    let mirror = base.path().join("m.git");

    // fsck (transfer.fsckObjects) rejects a tree containing a `.git` entry at
    // INGEST — the bundle never lands, so the hook can never be planted.
    assert!(
        ingest_bundle(&mirror, &source_id, &bundle).is_err(),
        "ingest must reject a tree containing a .git path (fsck hasDotgit)"
    );
}

#[test]
fn gitlink_materializes_as_an_empty_directory() {
    // A gitlink (mode 160000) materializes as an empty directory — never a
    // populated submodule, so a `.gitmodules` path-traversal cannot fetch
    // anything or write outside /src.
    let entries = vec![
        ("100644".to_string(), "keep.txt".to_string(), "keep\n".to_string()),
        (
            "160000".to_string(),
            "sub".to_string(),
            "0123456789012345678901234567890123456789".to_string(),
        ),
    ];
    let (_base, src) = materialize_entries(&entries);

    assert_eq!(std::fs::read_to_string(src.join("keep.txt")).unwrap(), "keep\n");
    let sub_meta = std::fs::symlink_metadata(src.join("sub")).unwrap();
    assert!(sub_meta.is_dir(), "a gitlink materializes as a directory");
    assert!(
        std::fs::read_dir(src.join("sub")).unwrap().next().is_none(),
        "the gitlink directory must be empty (never populated)"
    );
}
