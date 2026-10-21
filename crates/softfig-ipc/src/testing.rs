//! Test support shared across the workspace (task 064 review G64-4). `pub` only
//! because growlightd's and the CLI's tests need it too — the reason
//! softfig-net's `testing` module is public. No shipped code path calls it.

use std::path::Path;
use std::process::{Command, Stdio};

/// The `-c` flags every test `git` call carries: a throwaway author identity
/// and no signing. A CI runner has no global `user.name` / `user.email`, so a
/// bare `git commit` fails there ("Author identity unknown") while passing on a
/// dev machine that has one (review 043 G64-4).
pub const GIT_TEST_CONFIG: [&str; 6] =
    ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"];

/// Run `git -C <repo> <args>` with [`GIT_TEST_CONFIG`] and `stdin`, panicking
/// with git's stderr on a non-zero exit. The global and system git configs are
/// shut out, so a test behaves here exactly as on a CI runner that has none —
/// a call that would need the developer's own identity fails locally too.
pub fn git_with_stdin(repo: &Path, args: &[&str], stdin: Stdio) {
    let out = Command::new("git")
        .args(GIT_TEST_CONFIG)
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(stdin)
        .stdout(Stdio::null())
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} in {}: {}",
        repo.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// [`git_with_stdin`] with stdin closed — the usual test call.
pub fn git(repo: &Path, args: &[&str]) {
    git_with_stdin(repo, args, Stdio::null());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The helper commits with no global identity in reach — what a CI runner
    /// sees. Without [`GIT_TEST_CONFIG`] this exact sequence fails.
    #[test]
    fn a_commit_needs_no_global_identity() {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        std::fs::write(dir.path().join("a.txt"), "a\n").unwrap();
        git(dir.path(), &["add", "."]);
        git(dir.path(), &["commit", "-q", "-m", "base"]);
    }
}
