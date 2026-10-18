//! Staging + atomic install of the freshly-built installed set, shared by the
//! install front door (`softfig-install`, workstream B) and `softfig upgrade`
//! (workstream C). Both build the set into `source/target/release` and swap it
//! into `prefix`; this module is the one routine that does the staging, so the
//! two can never drift apart on the staging step either.

use std::path::Path;

use anyhow::{Context, Result};
use softfig_ipc::compat::{SetReport, INSTALLED_SET};

use crate::swap::swap_binaries;

/// What [`stage_and_swap`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// The installed set already matches the built set at this identity
    /// (`version`, `build_id`); nothing changed (a re-run converges to a no-op,
    /// the idempotency property).
    Noop { version: String, build_id: String },
    /// The staged set was swapped into `prefix` at `version`. `from` is the
    /// consistent `(version, build_id)` the prefix carried before the swap —
    /// `None` for a fresh or partial prefix (the swap installs or repairs it).
    Swapped {
        version: String,
        build_id: String,
        from: Option<(String, String)>,
    },
}

impl StageOutcome {
    /// The version the installed set is at now (the built version either way).
    pub fn version(&self) -> &str {
        match self {
            StageOutcome::Noop { version, .. } | StageOutcome::Swapped { version, .. } => version,
        }
    }

    /// The build identity the installed set is at now.
    pub fn build_id(&self) -> &str {
        match self {
            StageOutcome::Noop { build_id, .. } | StageOutcome::Swapped { build_id, .. } => build_id,
        }
    }

    /// The consistent identity this swap replaced, if there was one.
    pub fn from(&self) -> Option<&(String, String)> {
        match self {
            StageOutcome::Swapped { from, .. } => from.as_ref(),
            StageOutcome::Noop { .. } => None,
        }
    }

    /// True when nothing was written to the prefix.
    pub fn is_noop(&self) -> bool {
        matches!(self, StageOutcome::Noop { .. })
    }
}

/// Stage the five freshly-built binaries from `source/target/release` into a
/// same-filesystem temp dir beside `prefix`, then swap them in atomically
/// (all-or-nothing to the limit `rename(2)` allows — see [`crate::swap`]).
///
/// Idempotent by *identity*, not version: a prefix already carrying a
/// consistent set at the built `(version, build_id)` is a no-op, so re-running
/// an install or upgrade is a repair, not a duplicate. Two builds at one
/// version carry different ids, so a same-version rebuild swaps instead of
/// silently no-op-ing onto the old binary. `force` re-swaps even when the
/// identities already match.
pub fn stage_and_swap(source: &Path, prefix: &Path, force: bool) -> Result<StageOutcome> {
    let target_dir = source.join("target/release");

    let installed = SetReport::scan(prefix);
    let built_report = SetReport::scan(&target_dir);

    // The built set must itself be one consistent identity before anything is
    // renamed — a half-built target would otherwise install a partial set, the
    // exact state the atomic swap exists to prevent.
    let Some((built_version, built_id)) = built_report.consistent_identity() else {
        anyhow::bail!(
            "built binary set is not one consistent version: {} — did \
             `cargo build --release` produce the installed set?",
            built_report
        );
    };

    // Idempotency short-circuit: the installed set and the built set agree on
    // one `(version, build_id)` ⇒ nothing to do, unless `--force` asks to
    // re-install anyway.
    let installed_id = installed.consistent_identity();
    if !force
        && let Some((installed_version, installed_build)) = installed_id
        && installed_version == built_version
        && installed_build == built_id
    {
        return Ok(StageOutcome::Noop {
            version: built_version.to_string(),
            build_id: built_id.to_string(),
        });
    }

    std::fs::create_dir_all(prefix).with_context(|| format!("creating {}", prefix.display()))?;
    // Stage beside the prefix (same filesystem), never /tmp on a tmpfs — the
    // crate doc's same-filesystem note (`rename(2)` fails EXDEV across them).
    let staging = tempfile::Builder::new()
        .prefix(".softfig-stage-")
        .tempdir_in(prefix.parent().unwrap_or(prefix))
        .context("creating the staging dir")?;
    for name in INSTALLED_SET {
        let from = target_dir.join(name);
        if !from.is_file() {
            anyhow::bail!(
                "built binary missing: {} — did `cargo build --release` produce the installed set?",
                from.display()
            );
        }
        std::fs::copy(&from, staging.path().join(name))
            .with_context(|| format!("staging {}", from.display()))?;
    }

    swap_binaries(staging.path(), prefix, &INSTALLED_SET)
        .map_err(|e| anyhow::anyhow!("atomic install failed: {e}"))?;
    Ok(StageOutcome::Swapped {
        version: built_version.to_string(),
        build_id: built_id.to_string(),
        from: installed_id.map(|(v, b)| (v.to_string(), b.to_string())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use softfig_ipc::compat::stamp_with_identity;

    /// Write a fake binary carrying the build stamp for `version` and the
    /// placeholder identity `"test"`, mode `0755`.
    fn write_binary(dir: &Path, name: &str, version: &str) {
        write_binary_id(dir, name, version, "test");
    }

    /// Write a fake binary carrying the build stamp for `version` built from
    /// `build_id`, mode `0755`.
    fn write_binary_id(dir: &Path, name: &str, version: &str, build_id: &str) {
        let path = dir.join(name);
        let mut bytes = b"\x7fELF fake".to_vec();
        bytes.extend_from_slice(&stamp_with_identity(version, build_id));
        std::fs::write(&path, bytes).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }

    fn write_set(dir: &Path, version: &str) {
        write_set_id(dir, version, "test");
    }

    fn write_set_id(dir: &Path, version: &str, build_id: &str) {
        for name in INSTALLED_SET {
            write_binary_id(dir, name, version, build_id);
        }
    }

    /// A `source/target/release` tree holding the built set at `version`.
    fn source_with(version: &str) -> tempfile::TempDir {
        source_with_id(version, "test")
    }

    /// A `source/target/release` tree holding the built set at `version`, built
    /// from `build_id`.
    fn source_with_id(version: &str, build_id: &str) -> tempfile::TempDir {
        let source = tempfile::tempdir().unwrap();
        let target = source.path().join("target/release");
        std::fs::create_dir_all(&target).unwrap();
        write_set_id(&target, version, build_id);
        source
    }

    #[test]
    fn a_fresh_prefix_swaps_in_the_built_set() {
        let source = source_with("1.0.1");
        let prefix = tempfile::tempdir().unwrap().path().join(".local/bin");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert_eq!(outcome.version(), "1.0.1");
        assert!(!outcome.is_noop());
        assert_eq!(outcome.from().map(|(v, b)| (v.as_str(), b.as_str())), None);
        assert_eq!(SetReport::scan(&prefix).consistent_version(), Some("1.0.1"));
    }

    /// Idempotency criterion: a re-run over an already-upgraded prefix is a
    /// no-op, not a rewrite.
    #[test]
    fn a_rerun_over_a_matching_prefix_is_a_noop() {
        let source = source_with("1.0.1");
        let prefix = tempfile::tempdir().unwrap().path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set(&prefix, "1.0.1");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(outcome.is_noop(), "{outcome:?}");
        assert_eq!(outcome.version(), "1.0.1");
    }

    /// A partial built set must abort before any rename — the staging step
    /// inherits the swap's "no half-swap" guarantee.
    #[test]
    fn a_partial_built_set_refuses() {
        let source = tempfile::tempdir().unwrap();
        let target = source.path().join("target/release");
        std::fs::create_dir_all(&target).unwrap();
        // Only four of the five.
        for name in &INSTALLED_SET[..4] {
            write_binary(&target, name, "1.0.1");
        }
        let prefix = tempfile::tempdir().unwrap().path().join(".local/bin");

        let err = stage_and_swap(source.path(), &prefix, false).unwrap_err();
        assert!(format!("{err:#}").contains("not one consistent version"), "{err:#}");
    }

    /// The core of task 077: a same-version rebuild (same version, different
    /// build id) swaps — it is not a no-op — and reports the prior identity.
    #[test]
    fn a_same_version_rebuild_swaps_not_noop() {
        let source = source_with_id("1.0.0-alpha.1", "bbb");
        let prefix = tempfile::tempdir().unwrap().path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set_id(&prefix, "1.0.0-alpha.1", "aaa");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(!outcome.is_noop(), "same version, new build must swap: {outcome:?}");
        assert_eq!(outcome.version(), "1.0.0-alpha.1");
        assert_eq!(outcome.build_id(), "bbb");
        assert_eq!(
            outcome.from().map(|(v, b)| (v.as_str(), b.as_str())),
            Some(("1.0.0-alpha.1", "aaa"))
        );
        // The prefix now carries the new build.
        assert_eq!(
            SetReport::scan(&prefix).consistent_identity(),
            Some(("1.0.0-alpha.1", "bbb"))
        );
    }

    /// A version bump records the replaced version.
    #[test]
    fn a_version_bump_records_the_replaced_version() {
        let source = source_with_id("1.0.1", "bbb");
        let prefix = tempfile::tempdir().unwrap().path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set_id(&prefix, "1.0.0", "aaa");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(!outcome.is_noop());
        assert_eq!(outcome.version(), "1.0.1");
        assert_eq!(
            outcome.from().map(|(v, b)| (v.as_str(), b.as_str())),
            Some(("1.0.0", "aaa"))
        );
    }

    /// `--force` re-swaps even when the identities already match.
    #[test]
    fn force_reswaps_an_identical_identity() {
        let source = source_with_id("1.0.1", "bbb");
        let prefix = tempfile::tempdir().unwrap().path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set_id(&prefix, "1.0.1", "bbb");

        // Without --force: no-op.
        let noop = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(noop.is_noop(), "{noop:?}");

        // With --force: swaps anyway, replacing the identical identity.
        let outcome = stage_and_swap(source.path(), &prefix, true).unwrap();
        assert!(!outcome.is_noop(), "--force must re-swap: {outcome:?}");
        assert_eq!(
            outcome.from().map(|(v, b)| (v.as_str(), b.as_str())),
            Some(("1.0.1", "bbb"))
        );
        assert_eq!(
            SetReport::scan(&prefix).consistent_identity(),
            Some(("1.0.1", "bbb"))
        );
    }
}
