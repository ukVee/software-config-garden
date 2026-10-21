//! The build script's re-run set must move on a same-branch commit (report
//! 073). Before the fix it watched only `HEAD`, which a commit on a branch
//! never touches, so `git pull` + rebuild kept the previous commit's build id
//! and `stage_and_swap` no-oped the upgrade.

#[path = "../build_support/git_watch.rs"]
mod git_watch;

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed");
}

fn commit(dir: &Path, n: u32) {
    std::fs::write(dir.join("f"), n.to_string()).unwrap();
    git(dir, &["add", "f"]);
    git(dir, &["commit", "-q", "-m", &format!("c{n}")]);
}

/// Each watched path's bytes, `None` when absent — what cargo's mtime check
/// would see change.
fn snapshot(paths: &[PathBuf]) -> Vec<Option<Vec<u8>>> {
    paths.iter().map(|p| std::fs::read(p).ok()).collect()
}

fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    commit(dir.path(), 1);
    dir
}

#[test]
fn a_same_branch_commit_moves_a_watched_path() {
    let dir = repo();
    let paths = git_watch::watched_paths(dir.path());
    let head = paths.iter().find(|p| p.ends_with("HEAD")).expect("HEAD is watched").clone();
    let before = snapshot(&paths);
    let head_before = std::fs::read(&head).unwrap();

    commit(dir.path(), 2);

    // The 073 regression: HEAD alone does not move on a branch commit.
    assert_eq!(std::fs::read(&head).unwrap(), head_before);
    assert_ne!(snapshot(&paths), before, "no watched path moved: {paths:?}");
}

#[test]
fn a_commit_on_a_packed_branch_moves_a_watched_path() {
    let dir = repo();
    git(dir.path(), &["pack-refs", "--all"]);
    let paths = git_watch::watched_paths(dir.path());
    // The branch's loose ref is gone; it stays on the list (cargo re-runs on
    // a missing path) and packed-refs joins it.
    assert!(paths.iter().any(|p| p.ends_with("refs/heads/main") && !p.exists()), "{paths:?}");
    assert!(paths.iter().any(|p| p.ends_with("packed-refs")), "{paths:?}");
    let before = snapshot(&paths);

    commit(dir.path(), 2);

    assert_ne!(snapshot(&paths), before, "no watched path moved: {paths:?}");
}

#[test]
fn a_detached_head_commit_moves_head() {
    let dir = repo();
    git(dir.path(), &["checkout", "-q", "--detach"]);
    let paths = git_watch::watched_paths(dir.path());
    let before = snapshot(&paths);

    commit(dir.path(), 2);

    assert_ne!(snapshot(&paths), before, "no watched path moved: {paths:?}");
}

#[test]
fn outside_a_checkout_nothing_is_watched() {
    let dir = tempfile::tempdir().unwrap();
    // Guard against a temp dir that happens to sit inside a checkout.
    if git_watch::git(dir.path(), &["rev-parse", "--git-dir"]).is_none() {
        assert!(git_watch::watched_paths(dir.path()).is_empty());
    }
}
