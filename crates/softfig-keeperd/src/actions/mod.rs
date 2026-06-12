//! M3a — typed, daemon-mediated garden write actions.
//!
//! Each verb takes high-level args (`log_decision({slug, body})`) and the
//! daemon — not the calling Claude session — stamps the garden-convention
//! path, header, intent, and payload from one source of truth
//! ([`conventions`]). All five actions share the same skeleton:
//!
//! 1. parse + validate args (charset, date, snapshot-prefix rules),
//! 2. resolve the garden-relative path(s) from [`conventions`],
//! 3. reject-on-exists for create-style actions,
//! 4. register each path in the daemon's self-event suppression map,
//! 5. write the bytes (or `rename`, for `archive`),
//! 6. exactly one `commit_workdir` under a [`PriorTipGuard`], with the
//!    explicit intent (already present in `KNOWN_INTENTS`).
//!
//! Module shape resolves the decision file's first open question in favor
//! of per-action files + a shared `conventions` module. The server
//! dispatches straight here (no pass-through layer in `handlers.rs`); the
//! `HandlerResult` type alias is reused so the wire-error contract is
//! identical to every other verb.

pub mod conventions;

mod add_note;
mod add_project;
mod archive;
mod backlinks;
mod index;
mod log_decision;
mod log_incident;
mod managed;
mod refresh_snapshot;
mod sections;
mod split;

pub use add_note::{add_note, revise_note};
pub use add_project::add_project;
pub use archive::archive;
pub use log_decision::log_decision;
pub use log_incident::log_incident;
pub use refresh_snapshot::refresh_snapshot;
pub use sections::{add_section, append_to_section, edit_section, set_reviewed};
pub use split::migrate_split;

use std::path::Path;

use softfig_vcs::Intent;
use softfig_ipc::ErrorKind;
use softfig_store::Hash;

use crate::daemon::DaemonInner;
use crate::layer_b::PriorTipGuard;
use crate::server::err_to_response;

/// Create the parent dir (if needed) and write `bytes` to `abs`.
pub(crate) fn write_file(abs: &Path, bytes: &[u8]) -> Result<(), (ErrorKind, String)> {
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| (ErrorKind::Io, e.to_string()))?;
    }
    std::fs::write(abs, bytes).map_err(|e| (ErrorKind::Io, e.to_string()))
}

/// Run one `commit_workdir` under a fresh [`PriorTipGuard`], mirroring the
/// M2c-aware commit at every other daemon write site. The caller must hold
/// the inner lock, have already written every file into the working tree,
/// and have registered each path in the suppression map.
pub(crate) fn commit_now(
    inner: &mut DaemonInner,
    intent: Intent,
) -> Result<Hash, (ErrorKind, String)> {
    let hook = inner.layer_b.clone();
    let session = inner.session.as_ref().expect("unlocked");
    let repo = inner.repo.as_mut().expect("unlocked");
    let _guard = PriorTipGuard::install(&hook, repo, session).map_err(err_to_response)?;
    repo.commit_workdir(session, intent)
        .map_err(|e| err_to_response(e.into()))
}
