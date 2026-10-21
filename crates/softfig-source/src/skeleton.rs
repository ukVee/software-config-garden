//! Skeleton extraction (spec remote-runner §7.2, slice 005): reduce a
//! materialized source tree to its dependency *shape* — the `Cargo.toml`
//! manifests, `Cargo.lock` and `rust-toolchain(.toml)` files, with empty dummy
//! target stubs — so `cargo fetch --locked` can resolve and download the whole
//! dependency graph with **no repo-authored code present**.
//!
//! This is cargo-chef's "recipe" idea, hand-rolled (no dependency taken — the
//! probe in slice 005 showed cargo needs only the *target* files to exist, not
//! their contents, and never runs build scripts during fetch). What the
//! skeleton deliberately leaves out:
//!
//! - **`.cargo/config.toml` (and `.cargo/config`)** — can name credential
//!   providers or target runners, i.e. programs to execute;
//! - **`build.rs` and all source** — no repo-authored code can run in the fetch
//!   step. A build script is *not* required for `cargo fetch` to succeed (a
//!   declared `build = "build.rs"` with the file absent still fetches cleanly;
//!   `[build-dependencies]` are already pinned in `Cargo.lock`, which
//!   `--locked` downloads as-is), so no stub is emitted for it.
//!
//! The fetch step runs `cargo fetch --locked` against the skeleton; the **run**
//! step uses the full materialized tree (real source, real `build.rs`), so the
//! skeleton's dummy targets never get compiled.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// The extracted skeleton: where it lives, what it named, and a few counts for
/// diagnostics and the runner's run log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton {
    /// The skeleton root (manifests + lockfile + toolchain file + empty stubs).
    pub root: PathBuf,
    /// The toolchain the tree pins, if a `rust-toolchain(.toml)` was present.
    /// The runner honors it only if it already has that toolchain (spec §7.2);
    /// a missing one rejects the job with `toolchain-missing`.
    pub toolchain: Option<String>,
    /// Number of `Cargo.toml` manifests copied.
    pub manifests: usize,
    /// Number of `Cargo.lock` files copied.
    pub lockfiles: usize,
    /// Number of empty target stubs created.
    pub stubs: usize,
}

/// Directories a tree walk skips (build artifacts and the VCS itself). A
/// manifest under these is never a workspace member; `vendor/` (cargo's vendored
/// dependencies) is not skipped here because vendored dirs sit *beside* the
/// workspace and are not referenced by `[workspace] members`, so their
/// manifests are inert to `cargo fetch` either way.
fn skip_dir(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir()
        && matches!(entry.file_name().to_str(), Some(".git") | Some("target"))
}

/// Extract a skeleton of `src` into `dest`. `src` is the materialized tree; the
/// skeleton preserves relative paths so the workspace shape (member dirs) is
/// intact.
pub fn extract_skeleton(src: &Path, dest: &Path) -> Result<Skeleton> {
    fs::create_dir_all(dest)?;
    // Resolved once, so every stub can be proven to land under it (B1).
    let root = dest.canonicalize()?;

    let mut manifests = 0usize;
    let mut lockfiles = 0usize;
    let mut stubs = 0usize;
    let mut toolchain: Option<String> = None;

    for entry in walkdir::WalkDir::new(src).into_iter().filter_entry(|e| !skip_dir(e)) {
        let entry = entry.map_err(|e| Error::Skeleton(format!("walk: {e}")))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(src)
            .map_err(|e| Error::Skeleton(format!("path escapes source tree: {e}")))?;

        match entry.file_name().to_str() {
            Some("Cargo.toml") => {
                copy_into(src, rel, dest)?;
                manifests += 1;
                stubs += emit_stubs(src, &root, entry.path())?;
            }
            Some("Cargo.lock") => {
                copy_into(src, rel, dest)?;
                lockfiles += 1;
            }
            Some("rust-toolchain") => {
                copy_into(src, rel, dest)?;
                toolchain = Some(read_toolchain_file(entry.path())?);
            }
            Some("rust-toolchain.toml") => {
                copy_into(src, rel, dest)?;
                toolchain = Some(read_toolchain_toml(entry.path())?);
            }
            // `.cargo/config.toml`, `build.rs` and all source: deliberately
            // dropped. Nothing else is copied.
            _ => {}
        }
    }

    Ok(Skeleton {
        root: dest.to_path_buf(),
        toolchain,
        manifests,
        lockfiles,
        stubs,
    })
}

/// Copy `src/rel` into `dest/rel`, preserving relative layout and creating
/// parent dirs.
fn copy_into(src: &Path, rel: &Path, dest: &Path) -> Result<()> {
    let target = dest.join(rel);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src.join(rel), &target)?;
    Ok(())
}

/// Create empty stubs for a package's targets, so `cargo fetch` finds the
/// targets its manifest declares (or auto-detects) without their contents.
/// `root` is the canonical skeleton root. Returns the number of stubs written.
fn emit_stubs(src: &Path, root: &Path, manifest: &Path) -> Result<usize> {
    // The package directory (the manifest's parent), relative to `src`.
    let pkg_dir = manifest
        .parent()
        .ok_or_else(|| Error::Skeleton("manifest has no parent dir".into()))?;
    let pkg_rel = pkg_dir
        .strip_prefix(src)
        .map_err(|e| Error::Skeleton(format!("package dir escapes source tree: {e}")))?;

    let parsed: toml::Value = fs::read_to_string(manifest)
        .map_err(|e| Error::Skeleton(format!("read {}: {e}", manifest.display())))?
        .parse()
        .map_err(|e| Error::Skeleton(format!("parse {}: {e}", manifest.display())))?;

    // A virtual workspace root (a `[workspace]` with no `[package]`) declares no
    // targets of its own.
    if parsed.get("package").is_none() {
        return Ok(0);
    }

    // Target paths, relative to the package dir, that need empty stubs: the
    // union of (a) explicit `[lib]`/`[[bin]]` paths and (b) the files cargo
    // auto-detects. Gated on file existence for (b), so a stub is only emitted
    // when the real tree actually has that target.
    let mut targets: Vec<PathBuf> = Vec::new();

    let manifest_rel = pkg_rel.join("Cargo.toml");
    if let Some(lib) = parsed.get("lib").and_then(|v| v.get("path")).and_then(|p| p.as_str()) {
        targets.push(checked_target("[lib] path", lib, &manifest_rel)?);
    } else if pkg_dir.join("src/lib.rs").is_file() {
        targets.push(PathBuf::from("src/lib.rs"));
    }

    if let Some(bins) = parsed.get("bin").and_then(|v| v.as_array()) {
        for bin in bins {
            if let Some(p) = bin.get("path").and_then(|p| p.as_str()) {
                targets.push(checked_target("[[bin]] path", p, &manifest_rel)?);
            }
        }
    } else {
        if pkg_dir.join("src/main.rs").is_file() {
            targets.push(PathBuf::from("src/main.rs"));
        }
        let bin_dir = pkg_dir.join("src/bin");
        if bin_dir.is_dir() {
            for bin in fs::read_dir(&bin_dir)? {
                let bin = bin?;
                if bin.file_type()?.is_file() && bin.path().extension().is_some_and(|e| e == "rs") {
                    targets.push(PathBuf::from("src/bin").join(bin.file_name()));
                }
            }
        }
    }

    let mut written = 0usize;
    for t in targets {
        write_stub(root, &root.join(pkg_rel).join(&t))?;
        written += 1;
    }
    Ok(written)
}

/// Refuse a manifest-declared target path (`field` names the key) unless it is
/// a relative path that names a file and never climbs out with `..` (pre-merge
/// review B1). The manifest is repo-authored and this runs before any sandbox,
/// so the path is joined onto the skeleton root only once it is known to stay
/// there. A leading `./` is ordinary cargo spelling and is allowed.
fn checked_target(field: &str, t: &str, manifest: &Path) -> Result<PathBuf> {
    let p = Path::new(t);
    let refuse = |why: &str| {
        Error::Skeleton(format!(
            "{} {field} {t:?} {why}; a stub target must be a relative path inside the package",
            manifest.display()
        ))
    };
    if p.is_absolute() {
        return Err(refuse("is absolute"));
    }
    for c in p.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => return Err(refuse("has a `..` component")),
            Component::RootDir | Component::Prefix(_) => {
                return Err(refuse("has a root or prefix component"))
            }
        }
    }
    if p.file_name().is_none() {
        return Err(refuse("names no file"));
    }
    Ok(p.to_path_buf())
}

/// Write one empty stub at `target`, refusing unless it resolves under `root`
/// (the canonical skeleton root; pre-merge review B1). [`checked_target`] keeps
/// the path's spelling inside `root`; this guards the other way out, a symlink
/// on the path. The nearest existing ancestor is resolved *before*
/// `create_dir_all`, so not even a directory is made outside `root`, and a
/// symlink at the stub's own path is refused rather than written through.
fn write_stub(root: &Path, target: &Path) -> Result<()> {
    let outside = || {
        Error::Skeleton(format!("stub {} resolves outside the skeleton root", target.display()))
    };
    let parent = target.parent().ok_or_else(outside)?;
    let mut existing = parent;
    while fs::symlink_metadata(existing).is_err() {
        existing = existing.parent().ok_or_else(outside)?;
    }
    if !existing.canonicalize()?.starts_with(root) {
        return Err(outside());
    }
    fs::create_dir_all(parent)?;
    if fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::Skeleton(format!(
            "stub {} is a symlink; refusing to write through it",
            target.display()
        )));
    }
    // `fs::write` overwrites a duplicate path (an explicit + auto-detected
    // collision); that is fine — the stub is empty either way.
    fs::write(target, b"")?;
    Ok(())
}

/// Read a bare `rust-toolchain` file: the channel is the first non-empty line.
fn read_toolchain_file(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Skeleton(format!("read {}: {e}", path.display())))?;
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .ok_or_else(|| Error::Skeleton(format!("{} names no toolchain", path.display())))
}

/// Read a `rust-toolchain.toml`: the channel is `[toolchain] channel`.
fn read_toolchain_toml(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Skeleton(format!("read {}: {e}", path.display())))?;
    let parsed: toml::Value = text
        .parse()
        .map_err(|e| Error::Skeleton(format!("parse {}: {e}", path.display())))?;
    parsed
        .get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(|c| c.as_str())
        .map(str::to_string)
        .ok_or_else(|| Error::Skeleton(format!("{} has no [toolchain] channel", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture repo shaped like a small workspace: a lib member with a build
    /// script that would write a marker if it ran, and a `.cargo/config.toml`
    /// that would name a credential provider. Neither may survive into the
    /// skeleton.
    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"mem\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
        fs::write(root.join("rust-toolchain.toml"), "[toolchain]\nchannel = \"1.85.0\"\n")
            .unwrap();

        let mem = root.join("mem");
        fs::create_dir_all(mem.join("src")).unwrap();
        fs::write(
            mem.join("Cargo.toml"),
            "[package]\nname = \"mem\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
        )
        .unwrap();
        fs::write(
            mem.join("build.rs"),
            "fn main() { std::fs::write(\"MARKER\", \"ran\").unwrap(); }\n",
        )
        .unwrap();
        fs::write(mem.join("src/lib.rs"), "pub fn m() -> i32 { 1 }\n").unwrap();

        fs::create_dir_all(mem.join(".cargo")).unwrap();
        fs::write(
            mem.join(".cargo/config.toml"),
            "[registry]\nglobal-credential-providers = [\"cargo:token-from-env\"]\n",
        )
        .unwrap();

        dir
    }

    #[test]
    fn copies_manifests_lock_and_toolchain_and_extracts_channel() {
        let dir = fixture();
        let out = tempfile::tempdir().unwrap();
        let skel = extract_skeleton(dir.path(), out.path()).unwrap();

        assert_eq!(skel.manifests, 2, "root workspace + mem member");
        assert_eq!(skel.lockfiles, 1);
        assert_eq!(skel.toolchain.as_deref(), Some("1.85.0"));
        assert!(out.path().join("Cargo.toml").is_file());
        assert!(out.path().join("Cargo.lock").is_file());
        assert!(out.path().join("rust-toolchain.toml").is_file());
        assert!(out.path().join("mem/Cargo.toml").is_file());
    }

    #[test]
    fn strips_build_rs_cargo_config_and_source_but_stubs_the_lib_target() {
        let dir = fixture();
        let out = tempfile::tempdir().unwrap();
        let skel = extract_skeleton(dir.path(), out.path()).unwrap();

        assert!(!out.path().join("mem/build.rs").exists(), "build.rs must be stripped");
        assert!(
            !out.path().join("mem/.cargo/config.toml").exists(),
            ".cargo/config.toml must be stripped"
        );
        let stub = out.path().join("mem/src/lib.rs");
        assert!(stub.is_file());
        assert_eq!(fs::read_to_string(&stub).unwrap(), "", "stub must be empty");
        assert!(skel.stubs >= 1);

        // The marker build.rs in the fixture never ran (it is not copied, and
        // nothing here executes it) — the fixture still has no MARKER.
        assert!(!dir.path().join("MARKER").exists());
    }

    #[test]
    fn virtual_workspace_root_declares_no_targets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let skel = extract_skeleton(dir.path(), out.path()).unwrap();
        assert_eq!(skel.stubs, 0);
    }

    #[test]
    fn explicit_bin_path_is_stubbed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n").unwrap();
        fs::create_dir_all(dir.path().join("src/bin")).unwrap();
        fs::write(dir.path().join("src/bin/tool.rs"), "fn main() {}\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        extract_skeleton(dir.path(), out.path()).unwrap();
        assert!(out.path().join("src/bin/tool.rs").is_file());
        assert_eq!(
            fs::read_to_string(out.path().join("src/bin/tool.rs")).unwrap(),
            ""
        );
    }

    /// A one-package repo whose `Cargo.toml` ends with `targets` verbatim.
    fn hostile_repo(targets: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            format!("[package]\nname = \"h\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{targets}"),
        )
        .unwrap();
        dir
    }

    /// Every non-directory under `root` that is not under `dest`: what a stub
    /// escaping `dest` leaves behind.
    fn files_outside(root: &Path, dest: &Path) -> Vec<PathBuf> {
        walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !e.file_type().is_dir() && !e.path().starts_with(dest))
            .map(|e| e.path().to_path_buf())
            .collect()
    }

    #[test]
    fn absolute_lib_path_is_refused_and_nothing_is_truncated() {
        // B1: `[lib] path = "/…"` was joined verbatim, so the empty stub
        // replaced whatever file the path named.
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("cert.toml");
        fs::write(&victim, "precious").unwrap();
        let repo = hostile_repo(&format!("[lib]\npath = {:?}\n", victim.to_str().unwrap()));

        let out = tempfile::tempdir().unwrap();
        let err = extract_skeleton(repo.path(), out.path()).unwrap_err().to_string();
        assert!(err.contains("is absolute"), "unexpected error: {err}");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    }

    #[test]
    fn parent_dir_bin_path_is_refused_and_nothing_is_written() {
        // B1: `[[bin]] path = "../../…"` climbed out of `dest`. `dest` sits two
        // levels inside a test-owned root, so an escape lands where it shows.
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("a/dest");
        let repo = hostile_repo("[[bin]]\nname = \"b\"\npath = \"../../pwned.rs\"\n");

        let err = extract_skeleton(repo.path(), &dest).unwrap_err().to_string();
        assert!(err.contains("`..`"), "unexpected error: {err}");
        assert_eq!(files_outside(root.path(), &dest), Vec::<PathBuf>::new());
    }

    #[test]
    fn stub_through_a_symlinked_dir_in_dest_is_refused() {
        // B1: containment is checked on the resolved path, not its spelling, so
        // a symlink inside `dest` can't carry a stub (or a dir) outside it.
        let outside = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        std::os::unix::fs::symlink(outside.path(), dest.join("src")).unwrap();
        let repo = hostile_repo("[lib]\npath = \"src/deep/lib.rs\"\n");

        let err = extract_skeleton(repo.path(), &dest).unwrap_err().to_string();
        assert!(err.contains("outside the skeleton"), "unexpected error: {err}");
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn stub_onto_a_symlinked_leaf_is_refused() {
        // B1: a symlink at the stub's own path is refused, not followed and
        // truncated through.
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("accept.toml");
        fs::write(&victim, "precious").unwrap();
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("dest");
        fs::create_dir_all(dest.join("src")).unwrap();
        std::os::unix::fs::symlink(&victim, dest.join("src/lib.rs")).unwrap();
        let repo = hostile_repo("[lib]\npath = \"src/lib.rs\"\n");

        let err = extract_skeleton(repo.path(), &dest).unwrap_err().to_string();
        assert!(err.contains("symlink"), "unexpected error: {err}");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    }

    #[test]
    fn dot_prefixed_target_is_still_stubbed() {
        // `./src/lib.rs` is an ordinary cargo spelling: the B1 check refuses
        // climbing out, not a leading `.`.
        let repo = hostile_repo("[lib]\npath = \"./src/lib.rs\"\n");
        let out = tempfile::tempdir().unwrap();
        let skel = extract_skeleton(repo.path(), out.path()).unwrap();
        assert_eq!(skel.stubs, 1);
        assert!(out.path().join("src/lib.rs").is_file());
    }
}
