//! Staging + atomic install of the freshly-built installed set, shared by the
//! install front door (`softfig-install`, workstream B) and `softfig upgrade`
//! (workstream C). Both build the set into `source/target/release` and swap it
//! into `prefix`; this module is the one routine that does the staging, so the
//! two can never drift apart on the staging step either.

use std::path::Path;

use anyhow::{Context, Result};
use softfig_ipc::compat::{SetReport, INSTALLED_SET};

use crate::swap::swap_binaries;

/// The directory inside the install prefix that holds the one superseded
/// install set — the binaries the current set replaced — so
/// `softfig upgrade --rollback` can restore them. One level deep: exactly one
/// previous set, never a history stack (a new swap discards the prior one).
pub const PREVIOUS_SET_DIR: &str = ".previous";

/// The advisory lock file the stage+swap takes in the install prefix, so two
/// concurrent installs/upgrades cannot interleave their swaps.
pub const INSTALL_LOCK_FILE: &str = ".softfig.lock";

/// What [`stage_and_swap`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// The installed set already matches the built set at this identity
    /// (`version`, `build_id`), byte for byte; nothing changed (a re-run converges to a no-op,
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
    // one `(version, build_id)` *and* every binary is byte-identical ⇒ nothing
    // to do, unless `--force` asks to re-install anyway. The bytes are the
    // check that cannot go stale: the build id is only as fresh as the build
    // script's last run (an uncommitted edit does not re-run it, and a source
    // tree with no `.git` has no commit to name), so equal ids alone once
    // no-oped an upgrade onto changed binaries (report 073).
    let installed_id = installed.consistent_identity();
    if !force
        && let Some((installed_version, installed_build)) = installed_id
        && installed_version == built_version
        && installed_build == built_id
        && sets_byte_identical(prefix, &target_dir)
    {
        return Ok(StageOutcome::Noop {
            version: built_version.to_string(),
            build_id: built_id.to_string(),
        });
    }

    std::fs::create_dir_all(prefix).with_context(|| format!("creating {}", prefix.display()))?;

    // Serialise the whole stage+swap: an advisory `flock` on a lock file in
    // the prefix. A concurrent `upgrade`/`install` finds it held and refuses
    // with a non-zero exit — two swaps can never interleave (the lock is held
    // for the life of `_lock`, released when it drops on return).
    let _lock = acquire_install_lock(prefix)?;

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

    // fsync each staged binary before the renames, so a crash mid-swap cannot
    // leave a half-flushed staged file (pairs with the swap-in-progress marker
    // the swap writes on the *target* side).
    fsync_staged(staging.path())?;

    // Keep the superseded set recoverable: link the current binaries into the
    // one `.previous` sibling before the swap, so `--rollback` can restore
    // them.
    save_previous(prefix)?;

    swap_binaries(staging.path(), prefix, &INSTALLED_SET)
        .map_err(|e| anyhow::anyhow!("atomic install failed: {e}"))?;

    // fsync the prefix directory so the renames' dirents are durable, not just
    // the binaries' data — a crash right after the last rename can otherwise
    // drop the new entries on some filesystems.
    fsync_dir(prefix)?;

    Ok(StageOutcome::Swapped {
        version: built_version.to_string(),
        build_id: built_id.to_string(),
        from: installed_id.map(|(v, b)| (v.to_string(), b.to_string())),
    })
}

/// What [`rollback`] restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackOutcome {
    pub version: String,
    pub build_id: String,
}

/// Restore the one previous install set (kept at [`PREVIOUS_SET_DIR`] inside
/// `prefix`) over the current set, atomically. This is `softfig upgrade
/// --rollback`: the superseded binaries come back, all or nothing, through the
/// same shared swap routine. An absent or partial previous set is an error —
/// there is nothing to roll back to. The restore consumes the previous set (a
/// rollback has no previous set of its own).
pub fn rollback(prefix: &Path) -> Result<RollbackOutcome> {
    std::fs::create_dir_all(prefix).with_context(|| format!("creating {}", prefix.display()))?;
    let _lock = acquire_install_lock(prefix)?;

    let previous = prefix.join(PREVIOUS_SET_DIR);
    let report = SetReport::scan(&previous);
    let Some((version, build_id)) = report.consistent_identity() else {
        anyhow::bail!(
            "no previous set to roll back to in {} — run an install or upgrade \
             first, then roll back from the set it superseded",
            previous.display()
        );
    };

    swap_binaries(&previous, prefix, &INSTALLED_SET)
        .map_err(|e| anyhow::anyhow!("rollback failed: {e}"))?;
    fsync_dir(prefix)?;

    Ok(RollbackOutcome {
        version: version.to_string(),
        build_id: build_id.to_string(),
    })
}

/// Every member of the installed set in `a` has exactly the bytes of its
/// counterpart in `b`. A missing or unreadable file on either side is a
/// difference. Streams in fixed chunks so a release binary is never held in
/// memory twice.
fn sets_byte_identical(a: &Path, b: &Path) -> bool {
    INSTALLED_SET
        .iter()
        .all(|name| files_identical(&a.join(name), &b.join(name)).unwrap_or(false))
}

fn files_identical(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    if std::fs::metadata(a)?.len() != std::fs::metadata(b)?.len() {
        return Ok(false);
    }
    let (mut fa, mut fb) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
    let (mut ba, mut bb) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
    loop {
        let n = fa.read(&mut ba)?;
        if n == 0 {
            return Ok(true);
        }
        fb.read_exact(&mut bb[..n])?;
        if ba[..n] != bb[..n] {
            return Ok(false);
        }
    }
}

/// Take the advisory exclusive `flock` on the install lock file in `prefix`,
/// non-blocking: a concurrent install/upgrade holds it, so this one refuses
/// (no interleaved swaps). The returned handle owns the lock; dropping it
/// releases it. The lock file is created (and left behind) on purpose — a
/// persistent file is what a second process opens and flocks against.
fn acquire_install_lock(prefix: &Path) -> Result<std::fs::File> {
    let path = prefix.join(INSTALL_LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening the install lock {}", path.display()))?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            anyhow::bail!(
                "another install or upgrade is already in progress (lock held on {}) — \
                 wait for it to finish, then re-run",
                path.display()
            );
        }
        Err(e) => Err(e).with_context(|| format!("locking {}", path.display())),
    }
}

/// Keep the superseded set recoverable for `--rollback`: hard-link each
/// installed binary into a fresh `.previous` (copying where the filesystem
/// refuses a link). The prefix itself is untouched until the swap renames the
/// new set over it, so it never goes empty and each name still flips by one
/// atomic rename (report 074). A prefix with nothing installed leaves no
/// `.previous` at all.
///
/// Only a *consistent* installed set replaces `.previous` (one set, never a
/// stack). A PARTIAL prefix — an interrupted swap's marker, or a mix of
/// builds — is half old and half new, while the intact old set already sits
/// in `.previous`; deleting that would lose `--rollback` exactly when it is
/// needed. So a partial prefix keeps `.previous` as it is.
fn save_previous(prefix: &Path) -> Result<()> {
    if SetReport::scan(prefix).consistent_identity().is_none() {
        return Ok(());
    }
    let previous = prefix.join(PREVIOUS_SET_DIR);
    if previous.exists() {
        std::fs::remove_dir_all(&previous)
            .with_context(|| format!("removing the prior previous set {}", previous.display()))?;
    }
    std::fs::create_dir_all(&previous).with_context(|| format!("creating {}", previous.display()))?;
    for name in INSTALLED_SET {
        let (from, to) = (prefix.join(name), previous.join(name));
        if std::fs::hard_link(&from, &to).is_err() {
            std::fs::copy(&from, &to)
                .with_context(|| format!("keeping {} in {}", from.display(), previous.display()))?;
            std::fs::File::open(&to)
                .and_then(|f| f.sync_all())
                .with_context(|| format!("fsyncing {}", to.display()))?;
        }
    }
    fsync_dir(&previous)
}

/// `fsync` every staged binary (the freshly-copied set) so each is durable
/// before the swap renames it.
fn fsync_staged(staging: &Path) -> Result<()> {
    for name in INSTALLED_SET {
        let path = staging.join(name);
        std::fs::File::open(&path)
            .with_context(|| format!("opening {} for fsync", path.display()))?
            .sync_all()
            .with_context(|| format!("fsyncing {}", path.display()))?;
    }
    Ok(())
}

/// `fsync` a directory so its entries (renames) are durable. On Linux, opening
/// a directory and calling `sync_all` fsyncs the directory inode.
fn fsync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .with_context(|| format!("opening directory {} for fsync", dir.display()))?
        .sync_all()
        .with_context(|| format!("fsyncing directory {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use softfig_ipc::compat::{stamp_with_identity, SWAP_IN_PROGRESS_MARKER};

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
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert_eq!(outcome.version(), "1.0.1");
        assert!(!outcome.is_noop());
        assert_eq!(outcome.from().map(|(v, b)| (v.as_str(), b.as_str())), None);
        assert_eq!(SetReport::scan(&prefix).consistent_version(), Some("1.0.1"));
    }

    /// A clean swap through the shared routine leaves no swap-in-progress
    /// marker behind (release-pipeline slice 003).
    #[test]
    fn a_clean_swap_leaves_no_swap_marker() {
        let source = source_with("1.0.1");
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(!outcome.is_noop());

        let report = SetReport::scan(&prefix);
        assert_eq!(report.consistent_version(), Some("1.0.1"));
        assert!(!report.swap_in_progress, "a clean swap must not leave the marker");
        assert!(!prefix.join(SWAP_IN_PROGRESS_MARKER).exists());
    }

    /// Idempotency criterion: a re-run over an already-upgraded prefix is a
    /// no-op, not a rewrite.
    #[test]
    fn a_rerun_over_a_matching_prefix_is_a_noop() {
        let source = source_with("1.0.1");
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set(&prefix, "1.0.1");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(outcome.is_noop(), "{outcome:?}");
        assert_eq!(outcome.version(), "1.0.1");
    }

    /// Report 073: equal `(version, build_id)` is not enough for a no-op.
    /// A stale build id (an edit the build script never saw) on changed
    /// binaries must still swap them in.
    #[test]
    fn a_matching_identity_with_different_bytes_swaps() {
        let source = source_with("1.0.1");
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set(&prefix, "1.0.1");
        // Same stamp, different code: what a stale-id rebuild produces.
        let built = source.path().join("target/release/softfig-keeperd");
        let mut bytes = std::fs::read(&built).unwrap();
        bytes.extend_from_slice(b"changed code");
        std::fs::write(&built, &bytes).unwrap();

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(!outcome.is_noop(), "changed bytes must swap: {outcome:?}");
        assert_eq!(std::fs::read(prefix.join("softfig-keeperd")).unwrap(), bytes);
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
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");

        let err = stage_and_swap(source.path(), &prefix, false).unwrap_err();
        assert!(format!("{err:#}").contains("not one consistent version"), "{err:#}");
    }

    /// The core of task 077: a same-version rebuild (same version, different
    /// build id) swaps — it is not a no-op — and reports the prior identity.
    #[test]
    fn a_same_version_rebuild_swaps_not_noop() {
        let source = source_with_id("1.0.0-alpha.1", "bbb");
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
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

    /// The precise 077 regression: a mid-swap mix of two same-version builds
    /// reads as one *version* but not one *identity*, so a re-run swaps —
    /// never a no-op — and the mix converges instead of persisting.
    #[test]
    fn a_same_version_mixed_prefix_swaps_not_noop() {
        let source = source_with_id("1.0.0-alpha.1", "bbb");
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        // Mid-swap: three binaries already at the new build, two still the old
        // build — same version throughout, no marker.
        for (i, &name) in INSTALLED_SET.iter().enumerate() {
            let id = if i < 3 { "bbb" } else { "aaa" };
            write_binary_id(&prefix, name, "1.0.0-alpha.1", id);
        }

        let before = SetReport::scan(&prefix);
        // The version agrees — the pre-077 idempotency key would have called
        // this clean and kept the mix.
        assert_eq!(before.consistent_version(), Some("1.0.0-alpha.1"), "{before}");
        assert_eq!(
            before.consistent_identity(),
            None,
            "mixed build ids at one version must read partial: {before}"
        );

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(!outcome.is_noop(), "a mixed prefix must be repaired, not kept: {outcome:?}");
        assert_eq!(
            SetReport::scan(&prefix).consistent_identity(),
            Some(("1.0.0-alpha.1", "bbb"))
        );
    }

    /// A re-run over an interrupted same-version swap converges to a clean set:
    /// the marker is cleared and every binary lands on the one new build.
    #[test]
    fn a_rerun_repairs_an_interrupted_same_version_swap() {
        let source = source_with_id("1.0.0-alpha.1", "bbb");
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        // Mid-rename: some binaries at the new build, some at the old, and the
        // swap-in-progress marker left behind by the crash.
        for (i, &name) in INSTALLED_SET.iter().enumerate() {
            let id = if i < 3 { "bbb" } else { "aaa" };
            write_binary_id(&prefix, name, "1.0.0-alpha.1", id);
        }
        std::fs::write(prefix.join(SWAP_IN_PROGRESS_MARKER), b"version 1.0.0-alpha.1\n").unwrap();

        let before = SetReport::scan(&prefix);
        assert!(before.swap_in_progress);
        assert_eq!(before.consistent_identity(), None, "a marked set reads partial: {before}");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(!outcome.is_noop(), "an interrupted swap must be repaired, not skipped: {outcome:?}");

        let after = SetReport::scan(&prefix);
        assert!(!after.swap_in_progress, "the repair must clear the marker: {after}");
        assert_eq!(after.consistent_identity(), Some(("1.0.0-alpha.1", "bbb")));
        assert!(!prefix.join(SWAP_IN_PROGRESS_MARKER).exists());
    }

    /// A version bump records the replaced version.
    #[test]
    fn a_version_bump_records_the_replaced_version() {
        let source = source_with_id("1.0.1", "bbb");
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
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
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
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

    // ---- M3: one previous set + rollback + lock + fsync ----

    /// A second swap keeps exactly one previous set: the prior `.previous` is
    /// discarded and replaced by the set this swap superseded (one level deep,
    /// never a history stack).
    #[test]
    fn a_second_swap_keeps_exactly_one_previous_set() {
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set_id(&prefix, "1.0.0", "aaa");

        let first = source_with_id("1.0.1", "bbb");
        stage_and_swap(first.path(), &prefix, false).unwrap();
        assert_eq!(
            SetReport::scan(&prefix).consistent_identity(),
            Some(("1.0.1", "bbb"))
        );
        assert_eq!(
            SetReport::scan(&prefix.join(PREVIOUS_SET_DIR)).consistent_identity(),
            Some(("1.0.0", "aaa"))
        );

        let second = source_with_id("1.0.2", "ccc");
        stage_and_swap(second.path(), &prefix, false).unwrap();
        assert_eq!(
            SetReport::scan(&prefix).consistent_identity(),
            Some(("1.0.2", "ccc"))
        );
        // The prior previous set (1.0.0) is gone; the previous set is now the
        // set the second swap superseded (1.0.1) — exactly one, no stack.
        let prev = prefix.join(PREVIOUS_SET_DIR);
        let report = SetReport::scan(&prev);
        assert_eq!(report.consistent_identity(), Some(("1.0.1", "bbb")));
        let names: Vec<_> = std::fs::read_dir(&prev)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), INSTALLED_SET.len(), "exactly the set, no stack: {names:?}");
        for name in INSTALLED_SET {
            assert!(names.contains(&name.to_string()), "missing {name} in {names:?}");
        }
    }

    /// A fresh install (nothing previously installed) keeps no `.previous` —
    /// there is no superseded set to roll back to.
    /// Report 074: a re-run after a swap interrupted part-way keeps the
    /// intact `.previous` set, so `--rollback` still restores the original.
    #[test]
    fn a_rerun_after_an_interrupted_swap_keeps_the_rollback_set() {
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set_id(&prefix, "1.0.0", "old");
        // The first upgrade saved the old set, then died after two renames.
        let previous = prefix.join(PREVIOUS_SET_DIR);
        std::fs::create_dir_all(&previous).unwrap();
        write_set_id(&previous, "1.0.0", "old");
        for name in &INSTALLED_SET[..2] {
            write_binary_id(&prefix, name, "1.0.1", "new");
        }
        std::fs::write(prefix.join(SWAP_IN_PROGRESS_MARKER), "remaining …\n").unwrap();

        let source = source_with_id("1.0.1", "new");
        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(!outcome.is_noop());
        assert_eq!(SetReport::scan(&prefix).consistent_identity(), Some(("1.0.1", "new")));
        assert_eq!(SetReport::scan(&previous).consistent_identity(), Some(("1.0.0", "old")));

        let restored = rollback(&prefix).unwrap();
        assert_eq!((restored.version.as_str(), restored.build_id.as_str()), ("1.0.0", "old"));
        assert_eq!(SetReport::scan(&prefix).consistent_identity(), Some(("1.0.0", "old")));
    }

    /// Report 074: saving the previous set leaves the prefix whole — the old
    /// binaries stay in place until the swap renames the new ones over them.
    #[test]
    fn saving_the_previous_set_never_empties_the_prefix() {
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set_id(&prefix, "1.0.0", "old");

        save_previous(&prefix).unwrap();

        assert_eq!(SetReport::scan(&prefix).consistent_identity(), Some(("1.0.0", "old")));
        let previous = prefix.join(PREVIOUS_SET_DIR);
        assert_eq!(SetReport::scan(&previous).consistent_identity(), Some(("1.0.0", "old")));
        assert!(sets_byte_identical(&prefix, &previous));
    }

    #[test]
    fn a_fresh_install_keeps_no_previous_set() {
        let source = source_with("1.0.1");
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");

        let outcome = stage_and_swap(source.path(), &prefix, false).unwrap();
        assert!(!outcome.is_noop());
        assert!(
            !prefix.join(PREVIOUS_SET_DIR).exists(),
            "a fresh install has no superseded set"
        );
    }

    /// A held lock refuses a concurrent swap: two swaps cannot interleave.
    /// (`flock` is per open-file-description, so two `open`s on the same lock
    /// file in one process still conflict.)
    #[test]
    fn a_held_lock_refuses_a_concurrent_swap() {
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set(&prefix, "1.0.0");

        // Simulate another install/upgrade already holding the lock.
        let lock_path = prefix.join(".softfig.lock");
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .unwrap();
        rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();

        let source = source_with("1.0.1");
        let err = stage_and_swap(source.path(), &prefix, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("already in progress"),
            "a held lock must refuse: {err:#}"
        );
        // Nothing was swapped.
        assert_eq!(SetReport::scan(&prefix).consistent_identity(), Some(("1.0.0", "test")));
    }

    /// `rollback` restores the one previous set over the current set.
    #[test]
    fn rollback_restores_the_previous_set() {
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set_id(&prefix, "1.0.0", "aaa");

        let source = source_with_id("1.0.1", "bbb");
        stage_and_swap(source.path(), &prefix, false).unwrap();
        assert_eq!(
            SetReport::scan(&prefix).consistent_identity(),
            Some(("1.0.1", "bbb"))
        );

        let outcome = rollback(&prefix).unwrap();
        assert_eq!(outcome.version, "1.0.0");
        assert_eq!(outcome.build_id, "aaa");
        assert_eq!(
            SetReport::scan(&prefix).consistent_identity(),
            Some(("1.0.0", "aaa"))
        );
    }

    /// `rollback` errors when there is no previous set, and leaves the current
    /// set untouched.
    #[test]
    fn rollback_errors_when_there_is_no_previous_set() {
        let prefix_root = tempfile::tempdir().unwrap();
        let prefix = prefix_root.path().join(".local/bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_set(&prefix, "1.0.0");

        let err = rollback(&prefix).unwrap_err();
        assert!(
            format!("{err:#}").contains("no previous set"),
            "an absent previous set must error: {err:#}"
        );
        assert_eq!(SetReport::scan(&prefix).consistent_version(), Some("1.0.0"));
    }
}
