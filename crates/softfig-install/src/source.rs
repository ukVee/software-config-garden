//! Canonical program source for install + upgrade (task 078 M8).
//!
//! Both front doors (`softfig-install` and `softfig upgrade`) must resolve a
//! *real* source — never silently build the current directory. A released
//! binary carries its own provenance: the workspace `repository` and the
//! `v{version}` release tag, baked in at compile time. Resolution order:
//!
//! 1. an explicit `--source` checkout (build it as-is / pull it);
//! 2. an explicit `--repo` + `--ref` (clone the tagged source);
//! 3. the source recorded at install (upgrade only);
//! 4. the baked repo + tag (clone the tag this binary was cut from);
//! 5. otherwise fail with the explicit `--repo`/`--ref` instruction.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// The workspace repository baked into this crate at build time. Empty only
/// when a crate is built without `[package] repository` — never the case in
/// this workspace (every member inherits `repository.workspace = true`).
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The release tag this binary corresponds to: the workspace version with a
/// leading `v` (the release workflow's `v*` tag — `meta/spec-release.md`).
pub fn baked_tag() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// The baked `(repo, tag)` a front door can clone, when this crate carries a
/// repository URL. The clone is the tagged source the release was cut from, so
/// a downloaded helper reinstalls exactly its own version.
pub fn baked_source() -> Option<(&'static str, String)> {
    if REPOSITORY.is_empty() {
        None
    } else {
        Some((REPOSITORY, baked_tag()))
    }
}

/// A resolved source: an existing checkout (pull + build) or a fresh clone of
/// a pinned tag (already at the tag — no pull). The `Clone` variant owns its
/// temp dir, so the source stays on disk for the whole build.
pub enum Source {
    Checkout(PathBuf),
    Clone { path: PathBuf, keep: tempfile::TempDir },
}

impl Source {
    pub fn path(&self) -> &Path {
        match self {
            Source::Checkout(p) => p,
            Source::Clone { path, .. } => path,
        }
    }

    pub fn is_checkout(&self) -> bool {
        matches!(self, Source::Checkout(_))
    }
}

/// Resolve the source for a front door. `--repo` without `--ref` is refused; a
/// missing everything falls back to the baked tag, then fails with the
/// explicit `--repo`/`--ref` instruction. `recorded` is the source recorded at
/// install (upgrade only — `None` for a fresh install).
pub fn resolve(
    explicit_source: Option<&Path>,
    repo: Option<&str>,
    r#ref: Option<&str>,
    recorded: Option<&Path>,
) -> Result<Source> {
    if let Some(path) = explicit_source {
        return Ok(Source::Checkout(path.to_path_buf()));
    }
    if let Some(repo) = repo {
        let tag = r#ref
            .ok_or_else(|| anyhow::anyhow!("--repo requires --ref <tag> (the tagged source to build)"))?;
        return clone(repo, tag);
    }
    if let Some(path) = recorded {
        return Ok(Source::Checkout(path.to_path_buf()));
    }
    if let Some((repo, tag)) = baked_source() {
        return clone(repo, &tag);
    }
    bail!(
        "no source to build: this binary carries no baked repository, and no \
         --source checkout was given.\n  Build the tagged source explicitly:\n    \
         --repo <url> --ref <tag>\n  …or point at an existing checkout:\n    \
         --source <path>"
    )
}

/// `git clone --depth 1 --branch <tag> <repo>` into a kept-alive temp dir.
fn clone(repo: &str, tag: &str) -> Result<Source> {
    println!("cloning {repo} at {tag}…");
    let dir = tempfile::Builder::new()
        .prefix("softfig-src-")
        .tempdir()
        .context("creating a temp dir for the clone")?;
    let status = Command::new("git")
        .args(["clone", "--depth", "1", "--branch", tag, repo])
        .arg(dir.path())
        .status()
        .context("running git clone")?;
    if !status.success() {
        bail!("git clone failed (exit {status})");
    }
    Ok(Source::Clone {
        path: dir.path().to_path_buf(),
        keep: dir,
    })
}

/// The file in the install prefix recording the `--source` checkout the
/// install was built from, so a later `upgrade`/`uninstall` can name it.
pub const SOURCE_RECORD: &str = ".softfig-source";

/// Record `source` (an explicit `--source` checkout) in the install prefix,
/// canonicalized to an absolute path so the record survives a cwd change.
pub fn record_source(prefix: &Path, source: &Path) -> std::io::Result<()> {
    let abs = std::fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf());
    std::fs::write(prefix.join(SOURCE_RECORD), format!("{}\n", abs.display()))
}

/// The source recorded at install, if any.
pub fn recorded_source(prefix: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(prefix.join(SOURCE_RECORD)).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
}

/// Remove the source record (uninstall). A missing record is not an error.
pub fn remove_source_record(prefix: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(prefix.join(SOURCE_RECORD)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_baked_tag_is_the_version_with_a_leading_v() {
        assert_eq!(baked_tag(), format!("v{}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn the_baked_source_names_the_workspace_repository() {
        assert_eq!(baked_source().map(|(r, _)| r), Some(REPOSITORY));
    }

    #[test]
    fn an_explicit_source_wins_over_everything_else() {
        let s = resolve(Some(Path::new("/checkout")), Some("repo"), Some("v1"), None).unwrap();
        assert!(matches!(s, Source::Checkout(p) if p == Path::new("/checkout")));
    }

    #[test]
    fn a_repo_without_a_ref_is_refused() {
        assert!(resolve(None, Some("repo"), None, None).is_err());
    }

    #[test]
    fn a_recorded_source_is_used_before_the_baked_tag() {
        let s = resolve(None, None, None, Some(Path::new("/recorded"))).unwrap();
        assert!(matches!(s, Source::Checkout(p) if p == Path::new("/recorded")));
    }

    #[test]
    fn source_records_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        record_source(dir.path(), Path::new("/some/checkout")).unwrap();
        assert_eq!(recorded_source(dir.path()).as_deref(), Some(Path::new("/some/checkout")));
        remove_source_record(dir.path()).unwrap();
        assert_eq!(recorded_source(dir.path()), None);
        // Removing an absent record is not an error.
        assert!(remove_source_record(dir.path()).is_ok());
    }

    #[test]
    fn an_empty_record_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SOURCE_RECORD), "\n").unwrap();
        assert_eq!(recorded_source(dir.path()), None);
    }
}
