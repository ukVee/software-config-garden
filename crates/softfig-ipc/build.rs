//! Emit the build identity — the git commit this tree was built from, plus a
//! `-dirty` marker when the tree had uncommitted changes. This is what makes a
//! same-version rebuild distinguishable: every pre-release commit shares one
//! `CARGO_PKG_VERSION`, but not one commit (release-pipeline task 077).
//!
//! The identity is read from git at build time and injected as
//! `SOFTFIG_BUILD_ID`, which `compat.rs` folds into the on-disk build stamp.
//! The `rerun-if-changed` on the checkout's HEAD file makes cargo re-run this
//! script — and therefore recompile softfig-ipc and relink every dependent —
//! when the commit moves, so a `git pull` + rebuild lands a fresh identity in
//! every installed binary, not just the crates whose source happened to change.

use std::process::Command;

fn main() {
    // An explicit override (CI sets SOFTFIG_BUILD_ID to a run-unique id) wins.
    if let Ok(id) = std::env::var("SOFTFIG_BUILD_ID") {
        if !id.is_empty() {
            emit(&id);
            return;
        }
    }

    let id = git_build_id().unwrap_or_else(|| "nogit".to_string());
    emit(&id);

    // Re-run when the checked-out commit moves. `--git-path HEAD` names the
    // HEAD file for this checkout — a bare-repo worktree's, a linked checkout's,
    // or a plain clone's alike — so the trigger is right for every layout.
    if let Ok(head) = Command::new("git").args(["rev-parse", "--git-path", "HEAD"]).output() {
        if head.status.success() {
            let path = String::from_utf8_lossy(&head.stdout).trim().to_string();
            if !path.is_empty() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
}

fn emit(id: &str) {
    println!("cargo:rustc-env=SOFTFIG_BUILD_ID={id}");
}

/// `HEAD`'s short commit, plus `-dirty` when the tree has uncommitted changes.
fn git_build_id() -> Option<String> {
    let head = Command::new("git").args(["rev-parse", "HEAD"]).output().ok()?;
    if !head.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&head.stdout);
    let sha = sha.trim();
    if sha.len() < 12 {
        return None;
    }
    let mut id = sha[..12].to_string();
    if let Ok(status) = Command::new("git").args(["status", "--porcelain"]).output() {
        if status.status.success() && !status.stdout.is_empty() {
            id.push_str("-dirty");
        }
    }
    Some(id)
}
