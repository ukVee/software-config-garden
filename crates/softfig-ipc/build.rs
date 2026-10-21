//! Emit the build identity — the git commit this tree was built from, plus a
//! `-dirty` marker when the tree had uncommitted changes. This is what makes a
//! same-version rebuild distinguishable: every pre-release commit shares one
//! `CARGO_PKG_VERSION`, but not one commit (release-pipeline task 077).
//!
//! The identity is read from git at build time and injected as
//! `SOFTFIG_BUILD_ID`, which `compat.rs` folds into the on-disk build stamp.
//! The script re-runs — recompiling softfig-ipc and relinking every
//! dependent — when the checked-out commit moves: the `rerun-if-changed` set
//! is `HEAD`, the branch ref it points at and `packed-refs`
//! (`build_support/git_watch.rs`; report 073). So a `git pull` or a commit +
//! rebuild lands a fresh identity in every installed binary.
//!
//! The `-dirty` marker is only as fresh as the script's last run: an edit to
//! a working-tree file does not re-run it. That is why `stage_and_swap` never
//! treats equal identities alone as "nothing to swap" — it also requires the
//! binaries to be byte-identical.

#[path = "build_support/git_watch.rs"]
mod git_watch;

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=SOFTFIG_BUILD_ID");

    // An explicit override wins. No workflow sets it today: a CI run is a
    // fresh checkout, so the git identity is already right there.
    if let Ok(id) = std::env::var("SOFTFIG_BUILD_ID")
        && !id.is_empty()
    {
        emit(&id);
        return;
    }

    let here = Path::new(".");
    let id = git_build_id(here).unwrap_or_else(|| "nogit".to_string());
    emit(&id);

    for path in git_watch::watched_paths(here) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn emit(id: &str) {
    println!("cargo:rustc-env=SOFTFIG_BUILD_ID={id}");
}

/// `HEAD`'s short commit, plus `-dirty` when the tree has uncommitted changes.
fn git_build_id(dir: &Path) -> Option<String> {
    let sha = git_watch::git(dir, &["rev-parse", "HEAD"])?;
    if sha.len() < 12 {
        return None;
    }
    let mut id = sha[..12].to_string();
    if git_watch::git(dir, &["status", "--porcelain"]).is_some() {
        id.push_str("-dirty");
    }
    Some(id)
}
