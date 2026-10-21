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
//!
//! `upgrade` differs at step 4 ([`resolve_upgrade`]): it clones the baked
//! repo's newest release tag *newer than the running binary*, or reports it is
//! already current. Cloning the running binary's own tag — right for a
//! reinstall — rebuilt the installed version and never reached a newer one
//! (report 076).

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

/// Which source [`resolve`] would pick, in words, without fetching anything
/// — what a `--dry-run` prints (report 081 item 6).
pub fn describe(explicit_source: Option<&Path>, repo: Option<&str>, r#ref: Option<&str>, recorded: Option<&Path>) -> String {
    if let Some(path) = explicit_source {
        return format!("the checkout {}", path.display());
    }
    if let Some(repo) = repo {
        return format!("a clone of {repo} at {}", r#ref.unwrap_or("(missing --ref)"));
    }
    if let Some(path) = recorded {
        return format!("the checkout recorded at install, {}", path.display());
    }
    match baked_source() {
        Some((repo, tag)) => format!("a clone of {repo} at {tag}"),
        None => "none (pass --source or --repo/--ref)".to_string(),
    }
}

/// What `softfig upgrade` resolved to.
pub enum UpgradeSource {
    /// Build this source.
    Build(Source),
    /// No source was named and the baked repo has no release newer than the
    /// running binary: there is nothing to upgrade to.
    UpToDate { newest: String },
}

/// Resolve `upgrade`'s source. An explicit `--source`, `--repo`/`--ref` or the
/// recorded install source behave as in [`resolve`]. With none of them, the
/// baked repo's newest release tag newer than `running` is cloned
/// ([`newest_release`]); never `running`'s own tag.
pub fn resolve_upgrade(
    explicit_source: Option<&Path>,
    repo: Option<&str>,
    r#ref: Option<&str>,
    recorded: Option<&Path>,
    running: &semver::Version,
) -> Result<UpgradeSource> {
    if explicit_source.is_some() || repo.is_some() || recorded.is_some() {
        return resolve(explicit_source, repo, r#ref, recorded).map(UpgradeSource::Build);
    }
    let Some((repo, _)) = baked_source() else {
        return resolve(None, None, None, None).map(UpgradeSource::Build);
    };
    let tags = remote_tags(repo)?;
    match newest_release(&tags, running) {
        Some(tag) => clone(repo, &tag).map(UpgradeSource::Build),
        None => Ok(UpgradeSource::UpToDate {
            newest: format!("v{running}"),
        }),
    }
}

/// The tag names `repo` publishes (`git ls-remote --tags --refs`).
pub fn remote_tags(repo: &str) -> Result<Vec<String>> {
    println!("checking {repo} for a newer release…");
    let out = Command::new("git")
        .args(["ls-remote", "--tags", "--refs", repo])
        .output()
        .context("running git ls-remote")?;
    if !out.status.success() {
        bail!(
            "could not list the releases at {repo} (git ls-remote exit {}): {}\n  \
             Name the release to build instead: --repo <url> --ref vX.Y.Z",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.split('\t').nth(1)?.strip_prefix("refs/tags/"))
        .map(str::to_string)
        .collect())
}

/// The newest `v<semver>` release tag strictly newer than `running`, or `None`
/// when `running` is already the newest. A stable `running` only moves to
/// stable releases; a pre-release `running` also takes newer pre-releases.
/// Tags that are not `v<semver>` are ignored.
pub fn newest_release(tags: &[String], running: &semver::Version) -> Option<String> {
    tags.iter()
        .filter_map(|tag| Some((semver::Version::parse(tag.strip_prefix('v')?).ok()?, tag)))
        .filter(|(v, _)| v > running && (v.pre.is_empty() || !running.pre.is_empty()))
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, tag)| tag.clone())
}

/// Where a clone and its release build go: `$XDG_CACHE_HOME/softfig/src`
/// (else `~/.cache/softfig/src`). Not `/tmp`, which is a RAM-backed tmpfs on
/// Arch and Fedora — a full workspace release build there competes with RAM
/// or runs out of space (report 076).
fn clone_parent() -> Result<PathBuf> {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| anyhow::anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
    let dir = cache.join("softfig/src");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// `git clone --depth 1 --branch <tag> <repo>` into a kept-alive dir under
/// [`clone_parent`], removed when the [`Source`] drops.
fn clone(repo: &str, tag: &str) -> Result<Source> {
    println!("cloning {repo} at {tag}…");
    let dir = tempfile::Builder::new()
        .prefix("softfig-src-")
        .tempdir_in(clone_parent()?)
        .context("creating a dir for the clone")?;
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

    fn tags(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    /// Report 081 item 6: a dry run names the source without fetching it.
    #[test]
    fn describe_names_the_source_without_fetching() {
        assert_eq!(describe(Some(Path::new("/src")), None, None, None), "the checkout /src");
        assert_eq!(describe(None, Some("https://r"), Some("v1.2.0"), None), "a clone of https://r at v1.2.0");
        assert!(describe(None, None, None, Some(Path::new("/rec"))).contains("/rec"));
    }

    /// Report 076: the default upgrade target is never the running version's
    /// own tag, and nothing newer means "up to date", not a rebuild.
    #[test]
    fn newest_release_never_picks_the_running_version() {
        let all = tags(&["v1.0.0", "v0.9.0"]);
        assert_eq!(newest_release(&all, &v("1.0.0")), None);
        assert_eq!(newest_release(&all, &v("0.9.0")).as_deref(), Some("v1.0.0"));
    }

    #[test]
    fn newest_release_takes_the_maximum_and_ignores_non_release_tags() {
        let all = tags(&["v1.0.1", "v1.2.0", "v1.10.0", "nightly", "v1.3", "release-2.0.0"]);
        assert_eq!(newest_release(&all, &v("1.0.0")).as_deref(), Some("v1.10.0"));
    }

    #[test]
    fn a_stable_install_skips_pre_releases_and_a_pre_release_takes_them() {
        let all = tags(&["v1.0.0-alpha.1", "v1.0.0-alpha.2", "v1.1.0-beta.1"]);
        assert_eq!(newest_release(&all, &v("1.0.0")), None);
        assert_eq!(newest_release(&all, &v("1.0.0-alpha.1")).as_deref(), Some("v1.1.0-beta.1"));
        let with_final = tags(&["v1.0.0-alpha.2", "v1.0.0"]);
        assert_eq!(newest_release(&with_final, &v("1.0.0-alpha.1")).as_deref(), Some("v1.0.0"));
    }

    /// `remote_tags` reads a real remote: a local repo with two tags.
    #[test]
    fn remote_tags_lists_a_repos_tags() {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"])
                .args(["-c", "tag.gpgsign=false"])
                .args(args)
                .current_dir(dir.path())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&["commit", "-q", "--allow-empty", "-m", "c"]);
        git(&["tag", "v1.0.0"]);
        git(&["tag", "-a", "v1.1.0", "-m", "annotated"]);

        let mut found = remote_tags(dir.path().to_str().unwrap()).unwrap();
        found.sort();
        assert_eq!(found, tags(&["v1.0.0", "v1.1.0"]));
    }

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
