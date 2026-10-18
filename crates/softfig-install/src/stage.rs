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
    /// The installed set already matches the built set at `version`; nothing
    /// changed (a re-run converges to a no-op, the idempotency property).
    Noop { version: String },
    /// The staged set was swapped into `prefix` at `version`.
    Swapped { version: String },
}

impl StageOutcome {
    /// The version the installed set is at now (the built version either way).
    pub fn version(&self) -> &str {
        match self {
            StageOutcome::Noop { version } | StageOutcome::Swapped { version } => version,
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
/// Idempotent: a prefix already carrying a consistent set at the built version
/// is a no-op, so re-running an install or upgrade is a repair, not a duplicate.
pub fn stage_and_swap(source: &Path, prefix: &Path) -> Result<StageOutcome> {
    let target_dir = source.join("target/release");

    // Idempotency short-circuit: the installed set and the built set agree on
    // one version ⇒ nothing to do.
    let installed = SetReport::scan(prefix).consistent_version().map(str::to_string);
    let built = SetReport::scan(&target_dir).consistent_version().map(str::to_string);
    if let (Some(a), Some(b)) = (&installed, &built)
        && a == b
    {
        return Ok(StageOutcome::Noop { version: a.clone() });
    }

    // The built set must itself be one consistent version before anything is
    // renamed — a half-built target would otherwise install a partial set, the
    // exact state the atomic swap exists to prevent.
    let Some(built_version) = built else {
        anyhow::bail!(
            "built binary set is not one consistent version: {} — did \
             `cargo build --release` produce the installed set?",
            SetReport::scan(&target_dir)
        );
    };

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
        version: built_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use softfig_ipc::compat::stamp_for;

    /// Write a fake binary carrying the build stamp for `version`, `0755`.
    fn write_binary(dir: &Path, name: &str, version: &str) {
        let path = dir.join(name);
        let mut bytes = b"\x7fELF fake".to_vec();
        bytes.extend_from_slice(&stamp_for(version));
        std::fs::write(&path, bytes).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }

    fn write_set(dir: &Path, version: &str) {
        for name in INSTALLED_SET {
            write_binary(dir, name, version);
        }
    }

    /// A `source/target/release` tree holding the built set at `version`.
    fn source_with(version: &str) -> tempfile::TempDir {
        let source = tempfile::tempdir().unwrap();
        let target = source.path().join("target/release");
        std::fs::create_dir_all(&target).unwrap();
        write_set(&target, version);
        source
    }

    #[test]
    fn a_fresh_prefix_swaps_in_the_built_set() {
        let source = source_with("1.0.1");
        let prefix = tempfile::tempdir().unwrap().path().join(".local/bin");

        let outcome = stage_and_swap(source.path(), &prefix).unwrap();
        assert_eq!(outcome.version(), "1.0.1");
        assert!(!outcome.is_noop());
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

        let outcome = stage_and_swap(source.path(), &prefix).unwrap();
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

        let err = stage_and_swap(source.path(), &prefix).unwrap_err();
        assert!(format!("{err:#}").contains("not one consistent version"), "{err:#}");
    }
}
