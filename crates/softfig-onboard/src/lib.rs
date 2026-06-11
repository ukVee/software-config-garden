//! soft-fig onboarding: scaffold a fresh garden from an embedded
//! default-layout skeleton, then bring it up as a born-in-FUSE,
//! signed-and-encrypted garden.
//!
//! The crate is **frontend-agnostic** by design (M-onboard pick #3): the
//! CLI wizard is one caller; a future MCP onboarding tool wraps the same
//! [`onboard`] entry point. Nothing here prompts or reads a TTY — the
//! passphrase is passed in by the frontend.
//!
//! Two layers:
//!
//! * [`plan`] / [`apply`] — pure template stamping: take an embedded
//!   skeleton, substitute `{{machine}}` / `{{garden_path}}` / `{{date}}`
//!   placeholders, filter by selected concept dirs, materialize the file
//!   set into a staging directory. This is *dumb one-shot substitution*,
//!   deliberately NOT the templating pillar (no Tera, no profiles).
//! * [`onboard`] — orchestration: init the Vault under the state root,
//!   stamp the skeleton into a throwaway staging dir, write a born-in-FUSE
//!   genesis commit (encrypting the skeleton into the object store), drop
//!   the plaintext staging, and write the `keeper.toml` pointer the daemon
//!   uses to discover the relocated state on `softfig daemon start`.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use include_dir::{include_dir, Dir, DirEntry};
use softfig_vcs::Repo;
use softfig_vault::params::VaultParams;
use softfig_vault::Vault;

mod keeper_pointer;

/// The embedded default-garden skeleton (device-agnostic parts extracted
/// from the original garden: conventions, reserved-filenames, the routing
/// `CLAUDE.md` pattern, and empty concept-dir stubs).
static TEMPLATE: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../templates/default-garden");

/// Top-level dirs that are always scaffolded regardless of selection.
pub const ALWAYS_DIRS: &[&str] = &["meta", "journal", "inbox"];

/// Toggleable top-level concept dirs (the default-on set the user may
/// trim during `--customize`).
pub const CONCEPT_DIRS: &[&str] = &[
    "packages", "services", "os", "input", "hardware", "storage", "audio", "users", "shell",
    "snapshots", "projects",
];

/// Empty dirs whose `.keep` sentinel must survive into the commit so the
/// walker (which prunes sentinel-free empty dirs) keeps them.
const KEEP_DIRS: &[&str] = &[
    "journal/decisions",
    "journal/incidents",
    "journal/archive",
];

#[derive(Debug, thiserror::Error)]
pub enum OnboardError {
    #[error("garden already exists at {0} (state dir present)")]
    AlreadyExists(PathBuf),
    #[error("non-UTF-8 template path: {0}")]
    NonUtf8(PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Vault(#[from] softfig_vault::VaultError),
    #[error(transparent)]
    Core(#[from] softfig_vcs::CoreError),
}

pub type Result<T> = std::result::Result<T, OnboardError>;

/// Inputs to a scaffold/onboard run. `state_root` holds the on-disk
/// `.softfig/` (relocated, XDG state); `garden_root` is the eventual FUSE
/// mount path.
#[derive(Debug, Clone)]
pub struct OnboardOptions {
    pub garden_root: PathBuf,
    pub state_root: PathBuf,
    /// Machine identity, substituted for `{{machine}}` (e.g. `$HOSTNAME`).
    pub machine: String,
    /// ISO date, substituted for `{{date}}`.
    pub date: String,
    /// Concept dirs to include. `None` = the full default set; `Some(set)`
    /// = only those concept dirs (always-on dirs are kept regardless).
    pub include: Option<BTreeSet<String>>,
}

/// One file in a [`ScaffoldPlan`], path relative to the garden root.
#[derive(Debug, Clone)]
pub struct ScaffoldFile {
    pub path: PathBuf,
    pub contents: Vec<u8>,
}

/// The fully-resolved set of files a scaffold would write — after
/// placeholder substitution and concept-dir filtering. Pure data; no I/O.
#[derive(Debug, Clone)]
pub struct ScaffoldPlan {
    pub files: Vec<ScaffoldFile>,
}

impl ScaffoldPlan {
    pub fn len(&self) -> usize {
        self.files.len()
    }
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
    pub fn contains(&self, rel: &str) -> bool {
        let p = Path::new(rel);
        self.files.iter().any(|f| f.path == p)
    }
}

/// Result of a completed [`onboard`] run, returned to the frontend so it
/// can show the recovery phrase and next steps.
#[derive(Debug)]
pub struct OnboardOutcome {
    pub genesis: String,
    /// The 12-word recovery phrase — show ONCE, never persisted.
    pub recovery_phrase: String,
    pub garden_root: PathBuf,
    pub state_root: PathBuf,
    pub file_count: usize,
}

/// Build the file set that would be written, applying placeholder
/// substitution and concept-dir filtering. Pure — no filesystem access.
pub fn plan(opts: &OnboardOptions) -> Result<ScaffoldPlan> {
    let mut files = Vec::new();
    collect(&TEMPLATE, opts, &mut files)?;

    // Defensively guarantee the empty journal dirs survive the walker even
    // if the embedder dropped their dotfile sentinels.
    for d in KEEP_DIRS {
        let rel = PathBuf::from(d).join(".keep");
        if !files.iter().any(|f| f.path == rel) {
            files.push(ScaffoldFile { path: rel, contents: Vec::new() });
        }
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(ScaffoldPlan { files })
}

fn collect(dir: &Dir, opts: &OnboardOptions, out: &mut Vec<ScaffoldFile>) -> Result<()> {
    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(d) => collect(d, opts, out)?,
            DirEntry::File(f) => {
                let path = f.path();
                if !is_included(path, opts) {
                    continue;
                }
                let contents = substitute(f.contents(), opts);
                out.push(ScaffoldFile {
                    path: path.to_path_buf(),
                    contents,
                });
            }
        }
    }
    Ok(())
}

/// A path is included unless its top-level component is a concept dir the
/// caller excluded. Top-level files and always-on dirs are always kept.
fn is_included(path: &Path, opts: &OnboardOptions) -> bool {
    let Some(include) = &opts.include else {
        return true;
    };
    let first = path.components().next().and_then(|c| c.as_os_str().to_str());
    match first {
        Some(top) if CONCEPT_DIRS.contains(&top) => include.contains(top),
        _ => true, // top-level file, or an always-on dir
    }
}

/// Substitute `{{machine}}` / `{{garden_path}}` / `{{date}}` in UTF-8
/// content; binary content passes through untouched.
fn substitute(raw: &[u8], opts: &OnboardOptions) -> Vec<u8> {
    match std::str::from_utf8(raw) {
        Ok(text) => text
            .replace("{{machine}}", &opts.machine)
            .replace("{{garden_path}}", &opts.garden_root.display().to_string())
            .replace("{{date}}", &opts.date)
            .into_bytes(),
        Err(_) => raw.to_vec(),
    }
}

/// Write a plan's files into `staging` (created if absent). Parent dirs
/// are created as needed. Used by [`onboard`] against a throwaway tempdir,
/// and directly by tests.
pub fn apply(plan: &ScaffoldPlan, staging: &Path) -> Result<()> {
    for file in &plan.files {
        let dest = staging.join(&file.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &file.contents)?;
    }
    Ok(())
}

/// Full born-in-FUSE onboarding. Frontend supplies the passphrase
/// (prompted however it likes); this never touches a TTY.
///
/// Steps: init the Vault under `state_root` → stamp the skeleton into a
/// throwaway tempdir → write a genesis commit encrypting it into
/// `state_root/.softfig/` → drop the plaintext staging → write the
/// `keeper.toml` state-root pointer (at both the garden root and the state
/// root) so `softfig daemon start --garden <garden_root>` can discover and
/// FUSE-mount it.
pub fn onboard(opts: &OnboardOptions, passphrase: &[u8]) -> Result<OnboardOutcome> {
    onboard_with_params(opts, passphrase, VaultParams::default())
}

/// Like [`onboard`] but with explicit Vault parameters — used by tests to
/// dial Argon2id cost down so the suite runs in well under a second.
pub fn onboard_with_params(
    opts: &OnboardOptions,
    passphrase: &[u8],
    params: VaultParams,
) -> Result<OnboardOutcome> {
    // Refuse to clobber an existing garden's state.
    let state_softfig = opts.state_root.join(".softfig");
    if state_softfig.join("db.sqlite").exists() {
        return Err(OnboardError::AlreadyExists(state_softfig));
    }

    std::fs::create_dir_all(&opts.garden_root)?;
    std::fs::create_dir_all(&opts.state_root)?;

    // Vault::init writes to VaultPaths::for_garden(arg), an alias for
    // for_state_root — so passing the state root puts the vault under
    // state_root/.softfig/vault/.
    let (_vault, session, recovery) =
        Vault::init_with_params(&opts.state_root, passphrase, params)?;

    // Stamp the skeleton into a throwaway staging dir (auto-removed on
    // drop), commit it, then let the tempdir clean up — no plaintext is
    // left at the garden root, honoring encryption-at-rest from commit one.
    let staging = tempfile::tempdir()?;
    let plan = plan(opts)?;
    apply(&plan, staging.path())?;

    let (_repo, genesis) =
        Repo::create_fresh(&opts.garden_root, &opts.state_root, staging.path(), &session)?;

    keeper_pointer::write(&opts.garden_root, &opts.state_root)?;

    Ok(OnboardOutcome {
        genesis: genesis.to_hex(),
        recovery_phrase: recovery.display(),
        garden_root: opts.garden_root.clone(),
        state_root: opts.state_root.clone(),
        file_count: plan.len(),
    })
}

#[cfg(test)]
mod tests;
