//! The atomic installed-set swap. One routine, shared by install and upgrade,
//! so neither reimplements the all-or-nothing dance and the two can never
//! drift apart.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use softfig_ipc::compat::{SetReport, SWAP_IN_PROGRESS_MARKER};

/// Everything that can go wrong swapping the installed set.
#[derive(Debug, thiserror::Error)]
pub enum SwapError {
    /// One or more staged binaries are missing, not regular files, or not
    /// executable. The swap aborted **before touching the target directory**,
    /// so a half-swap can never start from an incomplete staged set.
    #[error("staged set incomplete: {}", .0.join(", "))]
    StagedIncomplete(Vec<String>),
    /// A filesystem operation failed. `path` names the file involved.
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

pub type Result<T> = std::result::Result<T, SwapError>;

/// Swap the installed set from `staged_dir` into `target_dir`, all-or-nothing
/// to the limit `rename(2)` allows. See the crate-level doc for the
/// crash-window analysis, the ordering rationale, and the same-filesystem
/// requirement.
///
/// `set` is the list of binary names to swap, in the order they are renamed.
/// Callers pass `softfig_ipc::compat::INSTALLED_SET` — the one code-side copy
/// of the set — rather than restating it here.
pub fn swap_binaries(staged_dir: &Path, target_dir: &Path, set: &[&str]) -> Result<()> {
    swap_binaries_inner(staged_dir, target_dir, set, &mut |_| Ok(()))
}

/// Test seam. The public [`swap_binaries`] passes a hook that never fires;
/// tests pass a hook that fails after N renames to simulate a crash and then
/// inspect the partial state the crash left behind.
type BeforeRename<'a> = dyn FnMut(&str) -> Result<()> + 'a;

fn swap_binaries_inner(
    staged_dir: &Path,
    target_dir: &Path,
    set: &[&str],
    before_rename: &mut BeforeRename<'_>,
) -> Result<()> {
    // Phase 1 — validate. Read-only: nothing here mutates the target, so a
    // missing or non-executable staged binary aborts before the first rename.
    let mut problems = Vec::new();
    for &name in set {
        let path = staged_dir.join(name);
        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() && meta.permissions().mode() & 0o111 != 0 => {}
            Ok(_) => problems.push(format!("{name}: not an executable file")),
            Err(e) => problems.push(format!("{name}: {e}")),
        }
    }
    if !problems.is_empty() {
        return Err(SwapError::StagedIncomplete(problems));
    }

    // Phase 2 — swap. rename(2) replaces `target_dir/name` atomically, per
    // file; there is no multi-file atomic rename, so the set order (documented
    // at the crate level) is what keeps the crash window recoverable.
    std::fs::create_dir_all(target_dir).map_err(|source| SwapError::Io {
        path: target_dir.to_path_buf(),
        source,
    })?;

    // Mark the swap in progress before the first rename. The marker's presence
    // is what makes a crash mid-swap detectable even when the binaries happen
    // to read as one consistent build — the same-version rebuild case, where
    // every binary carries the same version string. It records the staged
    // identity and the names still owed, then shrinks as each rename lands.
    let staged_identity = SetReport::scan(staged_dir)
        .consistent_identity()
        .map(|(version, build_id)| (version.to_string(), build_id.to_string()));
    write_swap_marker(target_dir, staged_identity.as_ref(), set)?;

    for (i, &name) in set.iter().enumerate() {
        before_rename(name)?;
        let from = staged_dir.join(name);
        let to = target_dir.join(name);
        std::fs::rename(&from, &to).map_err(|source| SwapError::Io {
            path: from,
            source,
        })?;
        write_swap_marker(target_dir, staged_identity.as_ref(), &set[i + 1..])?;
    }

    // Every rename landed; the marker goes, leaving a clean set behind.
    remove_swap_marker(target_dir)?;
    Ok(())
}

/// Write the swap-in-progress marker into `target_dir`: the staged identity
/// (so a post-crash human can see what was being installed) and the names the
/// swap still owes. Written before the first rename and shrunk after each one.
fn write_swap_marker(
    target_dir: &Path,
    staged_identity: Option<&(String, String)>,
    remaining: &[&str],
) -> Result<()> {
    let mut content = String::new();
    match staged_identity {
        Some((version, build_id)) => {
            content.push_str(&format!("version {version}\nbuild_id {build_id}\n"));
        }
        None => content.push_str("version unknown\nbuild_id unknown\n"),
    }
    content.push_str(&format!("remaining {}\n", remaining.join(" ")));
    let path = target_dir.join(SWAP_IN_PROGRESS_MARKER);
    std::fs::write(&path, content).map_err(|source| SwapError::Io { path, source })
}

/// Remove the swap-in-progress marker after the last rename. A missing marker
/// is already the goal state (an earlier remove won the race), so that is not
/// an error.
fn remove_swap_marker(target_dir: &Path) -> Result<()> {
    let path = target_dir.join(SWAP_IN_PROGRESS_MARKER);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SwapError::Io { path, source }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::compat::{stamp_for, SetReport, INSTALLED_SET};

    /// Write a fake binary carrying the build stamp for `version`, mode `0755`
    /// so it passes the executable check. The swap never reads the contents —
    /// the stamp is only there so `SetReport` can tell the builds apart.
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

    /// A hook that returns `Ok` for the first `after` renames and then fails,
    /// simulating a crash before the `(after + 1)`th rename.
    fn interrupt_after(after: usize) -> impl FnMut(&str) -> Result<()> {
        let mut remaining = after;
        move |_name| {
            if remaining == 0 {
                Err(SwapError::Io {
                    path: PathBuf::from("<simulated interrupt>"),
                    source: io::Error::other("simulated crash between renames"),
                })
            } else {
                remaining -= 1;
                Ok(())
            }
        }
    }

    #[test]
    fn a_full_swap_replaces_the_whole_set() {
        let staged = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        write_set(staged.path(), "1.0.1");
        write_set(target.path(), "1.0.0");

        swap_binaries(staged.path(), target.path(), &INSTALLED_SET).unwrap();

        let report = SetReport::scan(target.path());
        assert_eq!(report.consistent_version(), Some("1.0.1"));
        assert!(!report.swap_in_progress, "a clean swap must not leave the marker");
        assert!(!target.path().join(SWAP_IN_PROGRESS_MARKER).exists());
    }

    #[test]
    fn a_missing_staged_binary_aborts_before_the_first_rename() {
        let staged = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        write_set(target.path(), "1.0.0");
        // Stage only four of the five (skip the last), so the swap must refuse
        // before renaming anything.
        for name in &INSTALLED_SET[..4] {
            write_binary(staged.path(), name, "1.0.1");
        }

        let err = swap_binaries(staged.path(), target.path(), &INSTALLED_SET).unwrap_err();
        assert!(matches!(err, SwapError::StagedIncomplete(_)), "{err:?}");

        // The target directory is untouched: still the old build, all of it.
        assert_eq!(SetReport::scan(target.path()).consistent_version(), Some("1.0.0"));
    }

    #[test]
    fn a_non_executable_staged_binary_aborts() {
        let staged = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        write_set(target.path(), "1.0.0");
        write_set(staged.path(), "1.0.1");
        // Drop the execute bits on one staged binary.
        let one = staged.path().join("softfig");
        let mut perms = std::fs::metadata(&one).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&one, perms).unwrap();

        let err = swap_binaries(staged.path(), target.path(), &INSTALLED_SET).unwrap_err();
        assert!(matches!(err, SwapError::StagedIncomplete(_)), "{err:?}");
        assert_eq!(SetReport::scan(target.path()).consistent_version(), Some("1.0.0"));
    }

    #[test]
    fn an_interrupt_leaves_a_detectable_partial_state_and_rerun_converges() {
        let staged = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        write_set(staged.path(), "1.0.1");
        write_set(target.path(), "1.0.0");

        // Crash after two renames (softfig, softfig-keeperd).
        let mut hook = interrupt_after(2);
        let err =
            swap_binaries_inner(staged.path(), target.path(), &INSTALLED_SET, &mut hook)
                .unwrap_err();
        assert!(matches!(err, SwapError::Io { .. }), "{err:?}");

        // Two of five are at the new build; the rest are still the old build.
        // The version handshake must be able to see that.
        let report = SetReport::scan(target.path());
        assert_eq!(report.consistent_version(), None, "partial install must be detectable: {report}");
        assert!(report.swap_in_progress, "an interrupt must leave the marker");
        assert!(target.path().join(SWAP_IN_PROGRESS_MARKER).exists());

        // Re-stage (the upgrade path re-stages from the build output) and
        // re-run: the swap converges to the new set and clears the marker.
        write_set(staged.path(), "1.0.1");
        swap_binaries(staged.path(), target.path(), &INSTALLED_SET).unwrap();
        let converged = SetReport::scan(target.path());
        assert_eq!(converged.consistent_version(), Some("1.0.1"));
        assert!(!converged.swap_in_progress, "a re-run must clear the marker");
        assert!(!target.path().join(SWAP_IN_PROGRESS_MARKER).exists());
    }

    #[test]
    fn a_fresh_install_swaps_into_an_empty_target() {
        let staged = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        write_set(staged.path(), "1.0.1");
        // target_dir does not exist yet (a fresh box); only the tempdir parent
        // does, so swap into a subdir that is absent.
        let fresh = target.path().join(".local/bin");

        swap_binaries(staged.path(), &fresh, &INSTALLED_SET).unwrap();

        assert_eq!(SetReport::scan(&fresh).consistent_version(), Some("1.0.1"));
    }
}
