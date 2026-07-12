//! Applying a [`Plan`]. Per-entry atomic (temp + rename), whole-run
//! idempotent and re-runnable; no global transactional rollback in M4a (a
//! recorded hardening follow-up). Returns a [`Report`] of what happened.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::Method;
use crate::plan::{Action, Plan, PlannedEntry};
use crate::stamp;
use crate::{DeployPaths, Result};

/// Deploy-cache files (and copied targets) are owner-only — they are
/// declassified plaintext, kept as tight as the consuming app allows.
const FILE_MODE: u32 = 0o600;
/// The deploy-cache root is owner-only.
const CACHE_DIR_MODE: u32 = 0o700;

#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Back up a conflicting target to `<target>.softfig-bak` and overwrite
    /// it, instead of refusing.
    pub force: bool,
}

/// What `apply` did, by category. Names are dot names (copy/forced carry a
/// little extra context).
#[derive(Debug, Default)]
pub struct Report {
    pub created: Vec<String>,
    pub replaced: Vec<String>,
    pub copied: Vec<String>,
    pub skipped: Vec<String>,
    /// Conflicts that were refused (no `--force`), with their reasons.
    pub conflicts: Vec<String>,
    /// Conflicts overridden with `--force` (target backed up first).
    pub forced: Vec<String>,
    pub warnings: Vec<String>,
}

/// Apply a plan. Mutates the filesystem (cache + targets).
pub fn apply(plan: &Plan, paths: &DeployPaths, opts: &ApplyOptions) -> Result<Report> {
    let mut report = Report::default();

    // Create the cache root (0700) once, only if some symlink dot will write.
    if plan
        .entries
        .iter()
        .any(|e| e.method == Method::Symlink && e.action != Action::SkipUnchanged)
    {
        ensure_cache_root(&paths.cache_root)?;
    }

    for e in &plan.entries {
        match e.action {
            Action::SkipUnchanged => report.skipped.push(e.name.clone()),
            Action::CreateSymlink => {
                materialize(e, &mut report)?;
                report.created.push(e.name.clone());
            }
            Action::ReplaceManaged => {
                materialize(e, &mut report)?;
                report.replaced.push(e.name.clone());
            }
            Action::CopyStamped => {
                materialize(e, &mut report)?;
                report.copied.push(e.name.clone());
            }
            Action::Conflict => {
                if opts.force {
                    backup_existing(&e.target_abs)?;
                    materialize(e, &mut report)?;
                    report.forced.push(e.name.clone());
                } else {
                    report.conflicts.push(format!(
                        "{} ({})",
                        e.name,
                        e.conflict_reason.as_deref().unwrap_or("conflict")
                    ));
                }
            }
        }
    }

    Ok(report)
}

/// Realize one entry's desired state (used by Create / Replace / Copy and by
/// a forced Conflict, after the existing target has been backed up). Writes the
/// source bytes captured at plan time — never re-reads the source (which for a
/// FUSE-mode daemon would be a self-read of its own mount).
fn materialize(e: &PlannedEntry, report: &mut Report) -> Result<()> {
    let src = &e.source_bytes;
    match e.method {
        Method::Symlink => {
            write_atomic(&e.cache_abs, src, FILE_MODE)?;
            place_symlink(&e.target_abs, &e.cache_abs)?;
        }
        Method::Copy => {
            let (bytes, stamped) = stamp::compose_copy(&e.target_abs, src, &e.source_rel);
            if !stamped {
                report.warnings.push(format!(
                    "{}: no known comment syntax for {} — copied without a managed-by stamp \
                     (a re-deploy will treat it as a conflict; use --force)",
                    e.name,
                    e.target_abs.display()
                ));
            }
            write_atomic(&e.target_abs, &bytes, FILE_MODE)?;
        }
    }
    Ok(())
}

fn ensure_cache_root(root: &Path) -> Result<()> {
    fs::create_dir_all(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(CACHE_DIR_MODE))?;
    Ok(())
}

/// Write `bytes` to `path` atomically (temp file in the same dir + rename),
/// at `mode`. Replaces an existing file at `path`.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = parent_of(path)?;
    fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all().ok();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode))?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Create a symlink `target -> dest` atomically (temp symlink + rename),
/// replacing whatever (non-directory) currently sits at `target`.
fn place_symlink(target: &Path, dest: &Path) -> Result<()> {
    let parent = parent_of(target)?;
    fs::create_dir_all(parent)?;
    let tmp = unique_tmp(parent, "lnk");
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(dest, &tmp)?;
    fs::rename(&tmp, target)?;
    Ok(())
}

/// Move an existing target out of the way to `<target>.softfig-bak`.
fn backup_existing(target: &Path) -> Result<()> {
    let mut name = target
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no file name")
        })?
        .to_os_string();
    name.push(".softfig-bak");
    let bak = target.with_file_name(name);
    fs::rename(target, &bak)?;
    Ok(())
}

fn parent_of(path: &Path) -> Result<&Path> {
    path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent dir").into()
    })
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_tmp(parent: &Path, kind: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(".softfig-{kind}-{}-{n}", std::process::id()))
}
