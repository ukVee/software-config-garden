//! The v2 file paths and the fail-closed loaders.
//!
//! Loaders read through the worktree (FUSE overlay or disk), parse with the
//! shared `softfig-ipc` types, and run slice 002's invariant validation. An
//! invalid file is a typed [`V2FileError`] — never a fallback to an empty
//! model, never a partial read. Absence is not an error: `Ok(None)` is the
//! "no v2 state yet" answer a verb turns into a first creation (§3.4: views
//! render only when their TOML exists, so an absent file means no view).
//!
//! The paths are the `softfig-ipc` constants, re-exported here so keeperd's
//! v2 code imports them from one module. [`milestone_path`] is the single
//! translation from a milestone identity (`"<parent>/<sub-slug>"` for a
//! sub-milestone) to its on-disk directory — §3.3 inserts a literal `subs/`
//! segment after the top-level milestone (finding 10).

use std::fmt;

use softfig_ipc::queue_v2::{
    QueueArchiveToml, QueueRefusal, QueueToml, QueueV2Error, SlicesToml,
};
use softfig_store::Hash;

use crate::actions::{sections, WorkTree};
use crate::daemon::DaemonInner;

pub use softfig_ipc::queue_v2::{
    milestone_path, slices_file, MILESTONES_DIR, QUEUE_ARCHIVE_FILE, QUEUE_FILE,
};
/// A v2 file that exists but could not be loaded. Every variant is typed and
/// carries the file's path. The verbs (slices 004–006) map these onto an
/// internal-error refusal: the §6.8 codes describe state the verb can *act
/// on*, while a corrupt file is fail-closed — alerted once, and growlightd
/// schedules nothing from it (§3).
#[derive(Debug)]
pub enum V2FileError {
    /// Sealed, carrying inline vault regions, or otherwise not readable as
    /// plaintext. The v2 files must be plaintext TOML.
    Unreadable { rel: String },
    /// Does not parse as the file it claims to be: malformed TOML, a missing
    /// or unknown field, a value outside a closed vocabulary, or a schema
    /// this build does not write.
    InvalidToml { rel: String, source: QueueV2Error },
    /// Parses, but violates a §3.1/§3.3 writer invariant (slice 002).
    InvalidState { rel: String, refusal: QueueRefusal },
}

impl fmt::Display for V2FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { rel } => write!(
                f,
                "{rel}: unreadable or vault-protected (v2 files must be plaintext TOML)"
            ),
            Self::InvalidToml { rel, source } => write!(f, "{rel}: {source}"),
            Self::InvalidState { rel, refusal } => write!(f, "{rel}: {refusal}"),
        }
    }
}

impl std::error::Error for V2FileError {}

/// A loaded v2 file plus the whole-file content version of the bytes read —
/// the CAS token every write of that file must present, or `None` when the
/// file was absent (this write is the first creation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedFile<T> {
    pub model: T,
    pub version: Option<String>,
}

/// The live list plus the archive, loaded together: [`QueueToml::validate`]
/// resolves `after` links and id uniqueness against the archive, so neither
/// file is ever accepted alone. `queue.version` is `Some` whenever this is
/// `Some`; `archive.version` is `None` when the archive file does not exist
/// yet (an empty archive validates — nothing has left the list).
#[derive(Debug)]
pub struct QueueState {
    pub queue: LoadedFile<QueueToml>,
    pub archive: LoadedFile<QueueArchiveToml>,
}

/// Load `growlight/backlog/queue.toml` (and the archive it validates
/// against). `Ok(None)` = no queue file — there is no v2 state yet.
pub fn load_queue_state(
    wt: &WorkTree,
    inner: &DaemonInner,
) -> Result<Option<QueueState>, V2FileError> {
    let Some(text) = read_file(wt, inner, QUEUE_FILE)? else {
        return Ok(None);
    };
    let queue = LoadedFile {
        model: QueueToml::parse(&text).map_err(|source| V2FileError::InvalidToml {
            rel: QUEUE_FILE.to_string(),
            source,
        })?,
        version: Some(version_of(&text)),
    };
    let archive = match read_file(wt, inner, QUEUE_ARCHIVE_FILE)? {
        Some(text) => LoadedFile {
            model: QueueArchiveToml::parse(&text).map_err(|source| {
                V2FileError::InvalidToml {
                    rel: QUEUE_ARCHIVE_FILE.to_string(),
                    source,
                }
            })?,
            version: Some(version_of(&text)),
        },
        None => LoadedFile {
            model: QueueArchiveToml::new(Vec::new()),
            version: None,
        },
    };
    queue.model.validate(&archive.model).map_err(|refusal| {
        V2FileError::InvalidState {
            rel: QUEUE_FILE.to_string(),
            refusal,
        }
    })?;
    Ok(Some(QueueState { queue, archive }))
}

/// Load one milestone's `slices.toml` (§3.3). `Ok(None)` = the file does not
/// exist (a milestone with no slices yet — and no view, §3.4).
pub fn load_slices(
    wt: &WorkTree,
    inner: &DaemonInner,
    milestone: &str,
) -> Result<Option<LoadedFile<SlicesToml>>, V2FileError> {
    let rel = slices_file(milestone);
    let Some(text) = read_file(wt, inner, &rel)? else {
        return Ok(None);
    };
    let model = SlicesToml::parse(&text).map_err(|source| V2FileError::InvalidToml {
        rel: rel.clone(),
        source,
    })?;
    model.validate(milestone).map_err(|refusal| V2FileError::InvalidState { rel, refusal })?;
    Ok(Some(LoadedFile {
        model,
        version: Some(version_of(&text)),
    }))
}

/// Read a v2 file through the worktree, refusing (not skipping) files that
/// cannot be read as plaintext — the same guard the legacy section edits use.
/// `Ok(None)` only when the file is genuinely absent.
fn read_file(
    wt: &WorkTree,
    inner: &DaemonInner,
    rel: &str,
) -> Result<Option<String>, V2FileError> {
    if !wt.exists(rel) {
        return Ok(None);
    }
    sections::read_if_unprotected(wt, inner, rel)
        .ok_or(V2FileError::Unreadable { rel: rel.to_string() })
        .map(Some)
}

/// The whole-file content version: the hash of exactly the bytes the caller
/// read. This is the token [`super::write`]'s CAS check re-derives from the
/// current worktree bytes, so a write is refused the moment the file moved.
fn version_of(text: &str) -> String {
    Hash::of(text.as_bytes()).to_hex()
}
