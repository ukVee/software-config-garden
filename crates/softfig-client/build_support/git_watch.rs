//! Which git files decide the build identity. `build.rs` emits a
//! `cargo:rerun-if-changed` for each, and `tests/build_id_watch.rs` proves a
//! same-branch commit moves at least one of them (report 073).
//!
//! Emitting any `rerun-if-changed` replaces cargo's default rerun rule, so
//! this list is the *only* thing that re-runs the build script. It has to name
//! every file a commit can change, not just `HEAD`: on a branch checkout
//! `HEAD` holds `ref: refs/heads/<branch>` and is untouched by a commit, a
//! `git pull` or a fast-forward.

use std::path::{Path, PathBuf};
use std::process::Command;

/// `git <args>` run in `dir`, trimmed stdout on success. `--no-optional-locks`
/// keeps a read from refreshing the index as a side effect.
pub fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("--no-optional-locks")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// The files whose change can mean `HEAD` names a different commit:
///
/// - `HEAD` itself: a branch switch, or a commit on a detached `HEAD`;
/// - the loose ref `HEAD` points at: a commit, pull, fast-forward or reset on
///   the current branch. It is listed even when it does not exist (the ref is
///   packed): cargo then re-runs the script on every build until the next
///   commit writes the loose file — conservative, and only until then;
/// - `packed-refs`, when present: a ref that lives only there moves when the
///   file is rewritten.
///
/// `--git-path` resolves each name for this checkout's layout — a plain
/// clone, a linked worktree (whose refs live in the common dir), or a bare
/// repo's worktree alike. Empty outside a git checkout.
pub fn watched_paths(dir: &Path) -> Vec<PathBuf> {
    let resolve = |name: &str| {
        git(dir, &["rev-parse", "--git-path", name]).map(|p| {
            let p = PathBuf::from(p);
            if p.is_relative() { dir.join(p) } else { p }
        })
    };
    let mut paths = Vec::new();
    paths.extend(resolve("HEAD"));
    if let Some(branch_ref) = git(dir, &["symbolic-ref", "-q", "HEAD"]) {
        paths.extend(resolve(&branch_ref));
    }
    if let Some(packed) = resolve("packed-refs")
        && packed.exists()
    {
        paths.push(packed);
    }
    paths
}
