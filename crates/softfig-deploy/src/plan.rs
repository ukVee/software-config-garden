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

    // Both garden-boundary checks below compare against the *canonical* garden
    // root, so an unresolved symlink component in the configured path (`/home`
    // → `/var/home` systems) can't silently disarm them. Safe here: `plan` runs
    // outside the daemon's `inner` scope (the no-canonicalize discipline is an
    // under-`inner` rule).
    let garden_canon = canonicalize_deepest_existing(&paths.garden_root)?;

    // A deploy-cache inside the garden would make every symlink dot a write
    // into (and a dangle-on-lock read from) the garden mount — refuse the
    // config foot-gun outright. The default cache root is outside the garden.
    let cache_canon = canonicalize_deepest_existing(&paths.cache_root)?;
    if cache_canon.starts_with(&garden_canon) {
        return Err(DeployError::CacheRootInsideGarden(paths.cache_root.clone()));
    }

    for (name, dot) in &config.dots {
        validate_name(name)?;
        validate_source(name, &dot.source)?;

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

        let target_abs = resolve_target(&paths.home, &garden_canon, &dot.target, name)?;
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
/// resolves **inside the garden** (a self-write of the garden mount / an
/// uncommitted garden mutation — deploy writes real dotfiles, never the garden).
///
/// The garden check is canonicalization-based, against `garden_canon` (the
/// already-canonicalized garden root): apply's writes all go *through the
/// target's parent* (`create_dir_all` + tempfile + rename in the parent dir),
/// so the parent chain's symlinks are resolved — a `~/.config/foo →
/// <garden>/x` symlink-parent can't smuggle the write into the garden. The
/// final component is deliberately left unresolved: apply atomically
/// *replaces* a target symlink, never follows it, so a direct target symlink
/// keeps its existing Conflict semantics instead of becoming a hard error.
fn resolve_target(home: &Path, garden_canon: &Path, target: &str, name: &str) -> Result<PathBuf> {
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
    let file_name = resolved
        .file_name()
        .ok_or_else(|| invalid("target has no file name"))?
        .to_os_string();
    let parent = resolved
        .parent()
        .expect("an absolute path with a file name has a parent");
    let canon = canonicalize_deepest_existing(parent)?.join(file_name);
    if canon.starts_with(garden_canon) {
        return Err(invalid(
            "target resolves inside the garden — deploying into the garden mount is refused",
        ));
    }
    Ok(resolved)
}

/// Canonicalize `path` even when its tail doesn't exist yet: canonicalize the
/// deepest existing ancestor (resolving its symlinks), then re-append the
/// remaining not-yet-created components verbatim. A component that exists but
/// can't be fully resolved (a broken symlink) is treated as not-yet-existing —
/// apply's `create_dir_all`/rename would fail on it rather than escape.
fn canonicalize_deepest_existing(path: &Path) -> Result<PathBuf> {
    let mut existing = path;
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match std::fs::canonicalize(existing) {
            Ok(canon) => {
                let mut out = canon;
                for c in tail.iter().rev() {
                    out.push(c);
                }
                return Ok(out);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => match existing.parent() {
                Some(parent) => {
                    // `file_name()` is None only for `..`/root components, which
                    // the target validation above already rejects.
                    match existing.file_name() {
                        Some(name) => tail.push(name.to_os_string()),
                        None => return Ok(path.to_path_buf()),
                    }
                    existing = parent;
                }
                None => return Ok(path.to_path_buf()),
            },
            Err(e) => return Err(e.into()),
        }
    }
}

/// A dot's `source` addresses a file *under* `config/source/` — refuse absolute
/// paths and `..` traversal so a `deploy.toml` row can't read (and deploy) an
/// arbitrary garden or host file. In daemon mode the source string is also the
/// working-tree read key, so this guards the plaintext snapshot path too.
fn validate_source(name: &str, source: &str) -> Result<()> {
    let p = Path::new(source);
    let escapes = source.is_empty()
        || p.is_absolute()
        || p.components()
            .any(|c| !matches!(c, Component::Normal(_)));
    if escapes {
        Err(DeployError::InvalidSource {
            name: name.to_string(),
            source_rel: source.to_string(),
        })
    } else {
        Ok(())
    }
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
