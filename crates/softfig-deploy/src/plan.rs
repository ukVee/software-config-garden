//! Planning — diff the deploy table against the live filesystem and decide,
//! per dot, what `apply` would do. This reads the filesystem (it has to, to
//! diff against current state) but **never mutates it**, so `--dry-run` is
//! just "compute a plan and print it".

use std::io;
use std::path::{Component, Path, PathBuf};

use crate::config::{DeployConfig, Method};
use crate::source::{SourceEntry, SourceReader};
use crate::stamp;
use crate::{DeployError, DeployPaths, Result};

/// What `apply` will do with one dot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Target is absent → create the cache file + symlink.
    CreateSymlink,
    /// Target is already ours but stale (cache content changed, or a managed
    /// copy's bytes changed) → refresh it.
    ReplaceManaged,
    /// `method = "copy"` and the target is absent → write the stamped copy.
    CopyStamped,
    /// Target already matches the desired state → do nothing.
    SkipUnchanged,
    /// Target exists and is **not** ours → refuse unless `--force`.
    Conflict,
}

/// One fully-resolved planned dot.
#[derive(Debug, Clone)]
pub struct PlannedEntry {
    pub name: String,
    pub method: Method,
    /// The source's plaintext bytes, captured at plan time from the
    /// [`SourceReader`]. `apply` re-materializes exactly these — it never reads
    /// the source again (which, for a FUSE-mode daemon, would be a self-read of
    /// the very mount it serves).
    pub source_bytes: Vec<u8>,
    /// The dot's `source` string (for the copy stamp's provenance line).
    pub source_rel: String,
    /// Resolved absolute target path.
    pub target_abs: PathBuf,
    /// Deploy-cache path (used only for `Method::Symlink`).
    pub cache_abs: PathBuf,
    pub action: Action,
    /// Human reason, set only when `action == Conflict`.
    pub conflict_reason: Option<String>,
}

/// The full set of planned dots, in stable (name) order.
#[derive(Debug, Clone)]
pub struct Plan {
    pub entries: Vec<PlannedEntry>,
}

impl Plan {
    pub fn has_conflicts(&self) -> bool {
        self.entries.iter().any(|e| e.action == Action::Conflict)
    }
}

/// Compute the plan. Reads each dot's source through `source` (never `std::fs`
/// directly — see [`crate::source`]) and stats targets/caches on the real
/// filesystem; mutates nothing.
pub fn plan(config: &DeployConfig, paths: &DeployPaths, source: &dyn SourceReader) -> Result<Plan> {
    let source_dir = paths.source_dir();
    let mut entries = Vec::with_capacity(config.dots.len());

    for (name, dot) in &config.dots {
        validate_name(name)?;

        // Display-only absolute path for the not-found / directory errors; the
        // bytes themselves come from `source`, never a mount `fs::read`.
        let source_abs = || source_dir.join(&dot.source);
        let src_bytes = match source.read_source(&dot.source)? {
            SourceEntry::Directory => {
                return Err(DeployError::DirectorySource {
                    name: name.clone(),
                    path: source_abs(),
                });
            }
            SourceEntry::Missing => {
                return Err(DeployError::SourceNotFound {
                    name: name.clone(),
                    path: source_abs(),
                });
            }
            SourceEntry::File(bytes) => bytes,
        };

        let target_abs = resolve_target(&paths.home, &paths.garden_root, &dot.target, name)?;
        let cache_abs = paths.cache_root.join(name);

        let (action, conflict_reason) =
            decide(dot.method, &target_abs, &cache_abs, &src_bytes, &dot.source)?;

        entries.push(PlannedEntry {
            name: name.clone(),
            method: dot.method,
            source_bytes: src_bytes,
            source_rel: dot.source.clone(),
            target_abs,
            cache_abs,
            action,
            conflict_reason,
        });
    }

    Ok(Plan { entries })
}

/// Resolve + validate a dot's target into an absolute path. Rejects `..`
/// traversal, (M4a) absolute targets outside `$HOME`, and any target that
/// resolves **inside `garden_root`** (a self-write of the garden mount / an
/// uncommitted garden mutation — deploy writes real dotfiles, never the garden).
fn resolve_target(home: &Path, garden_root: &Path, target: &str, name: &str) -> Result<PathBuf> {
    let invalid = |reason: &str| DeployError::InvalidTarget {
        name: name.to_string(),
        target: target.to_string(),
        reason: reason.to_string(),
    };

    if target.is_empty() {
        return Err(invalid("empty target"));
    }
    let p = Path::new(target);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(invalid("`..` is not allowed in a target"));
    }
    let resolved = if p.is_absolute() {
        if !p.starts_with(home) {
            return Err(invalid(
                "absolute targets outside $HOME are deferred to the /etc slice",
            ));
        }
        p.to_path_buf()
    } else {
        home.join(p)
    };
    if resolved.starts_with(garden_root) {
        return Err(invalid(
            "target resolves inside the garden — deploying into the garden mount is refused",
        ));
    }
    Ok(resolved)
}

/// Dot names key the flat deploy-cache, so they must be safe filename
/// fragments: no separators, no `.`/`..`.
fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(DeployError::InvalidName(name.to_string()))
    }
}

/// The live state of a target path.
enum TargetState {
    Missing,
    Symlink(PathBuf),
    File,
    Dir,
}

fn target_state(p: &Path) -> Result<TargetState> {
    match std::fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(TargetState::Missing),
        Err(e) => Err(e.into()),
        Ok(md) => {
            let ft = md.file_type();
            if ft.is_symlink() {
                Ok(TargetState::Symlink(std::fs::read_link(p)?))
            } else if ft.is_dir() {
                Ok(TargetState::Dir)
            } else {
                Ok(TargetState::File)
            }
        }
    }
}

fn cache_matches(cache_abs: &Path, src_bytes: &[u8]) -> Result<bool> {
    match std::fs::read(cache_abs) {
        Ok(cur) => Ok(cur == src_bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn decide(
    method: Method,
    target: &Path,
    cache: &Path,
    src: &[u8],
    source_rel: &str,
) -> Result<(Action, Option<String>)> {
    let conflict = |reason: &str| (Action::Conflict, Some(reason.to_string()));

    Ok(match method {
        Method::Symlink => match target_state(target)? {
            TargetState::Missing => (Action::CreateSymlink, None),
            TargetState::Symlink(dest) if dest == *cache => {
                if cache_matches(cache, src)? {
                    (Action::SkipUnchanged, None)
                } else {
                    (Action::ReplaceManaged, None)
                }
            }
            TargetState::Symlink(_) => {
                conflict("target is a symlink to a non-softfig location")
            }
            TargetState::File => conflict("target is an existing file (not a softfig symlink)"),
            TargetState::Dir => conflict("target is an existing directory"),
        },
        Method::Copy => {
            let (desired, _stamped) = stamp::compose_copy(target, src, source_rel);
            match target_state(target)? {
                TargetState::Missing => (Action::CopyStamped, None),
                TargetState::File => {
                    let cur = std::fs::read(target)?;
                    if cur == desired {
                        (Action::SkipUnchanged, None)
                    } else if stamp::has_managed_stamp(&cur) {
                        (Action::ReplaceManaged, None)
                    } else {
                        conflict("target is an existing unmanaged file")
                    }
                }
                TargetState::Symlink(_) => {
                    conflict("target is a symlink (copy mode expects a regular file)")
                }
                TargetState::Dir => conflict("target is an existing directory"),
            }
        }
    })
}
