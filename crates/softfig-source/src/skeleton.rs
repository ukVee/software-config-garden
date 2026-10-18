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
use std::path::{Path, PathBuf};

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
                stubs += emit_stubs(src, dest, entry.path())?;
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
/// Returns the number of stubs written.
fn emit_stubs(src: &Path, dest: &Path, manifest: &Path) -> Result<usize> {
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

    if let Some(lib) = parsed.get("lib").and_then(|v| v.get("path")).and_then(|p| p.as_str()) {
        targets.push(PathBuf::from(lib));
    } else if pkg_dir.join("src/lib.rs").is_file() {
        targets.push(PathBuf::from("src/lib.rs"));
    }

    if let Some(bins) = parsed.get("bin").and_then(|v| v.as_array()) {
        for bin in bins {
            if let Some(p) = bin.get("path").and_then(|p| p.as_str()) {
                targets.push(PathBuf::from(p));
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
        let target = dest.join(pkg_rel).join(&t);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        // `fs::write` overwrites a duplicate path (an explicit + auto-detected
        // collision); that is fine — the stub is empty either way.
        fs::write(&target, b"")?;
        written += 1;
    }
    Ok(written)
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
}
