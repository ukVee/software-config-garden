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
mod growlight;
mod index;
mod log_decision;
mod log_incident;
mod managed;
mod migrate_config;
mod numbering;
mod refresh_snapshot;
pub(crate) mod sections;
mod split;
mod thrash;
mod worktree;

pub use add_note::{add_note, revise_note};
pub use add_project::add_project;
pub use archive::archive;
pub use growlight::{
    add_backlog_item, add_queue, add_slice, growlight_init, log_baton, post_message, read_inbox,
    release_lease, reorder_backlog_item, request_lease, set_item_status, tail_bus,
};
pub use log_decision::log_decision;
pub use log_incident::log_incident;
pub use migrate_config::migrate_config;
pub use refresh_snapshot::refresh_snapshot;
pub use sections::{add_section, append_to_section, edit_section, set_reviewed};
pub use split::migrate_split;
pub use thrash::ThrashDetector;
pub(crate) use worktree::{Tree, WorkTree};

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

/// Run one commit under a fresh [`PriorTipGuard`], mirroring the M2c-aware
/// commit at every other daemon write site. The caller must hold the inner
/// lock, have already written every file into the working tree, and have
/// registered each path in the suppression map.
///
/// In FUSE mode the daemon serves `garden_root` itself, so the legacy
/// `commit_workdir` (which walks `garden_root`) would recursively self-read
/// the mount while we hold `inner` — the 2026-06-21 commit-path deadlock.
/// We commit from the FUSE driver's in-memory (tip ∪ overlay) snapshot
/// instead. The snapshot is captured **before** the commit because
/// `commit_snapshot`'s `tip_changed` rotates the tip and clears the overlay.
/// [`MountHandle::workdir_snapshot`](softfig_fuse::MountHandle::workdir_snapshot)
/// locks the *FUSE* `SharedState` mutex (a different lock from `daemon.inner`)
/// and never re-enters the kernel, so it is safe under `inner`. Non-FUSE /
/// M1c-compat callers keep walking the working tree via `commit_workdir`.
pub(crate) fn commit_now(
    inner: &mut DaemonInner,
    intent: Intent,
) -> Result<Hash, (ErrorKind, String)> {
    // Reborrow `inner.fuse` on its own (disjoint from `repo`/`session`/`hook`
    // below) and finish the snapshot into an owned value before touching the
    // repo, so no two `DaemonInner` fields are borrowed at once.
    let fuse_snapshot = match inner.fuse.as_ref() {
        Some(mount) => Some(
            mount
                .workdir_snapshot()
                .map_err(|e| (ErrorKind::Io, format!("workdir snapshot: {e}")))?,
        ),
        None => None,
    };
    let hook = inner.layer_b.clone();
    let session = inner.session.as_ref().expect("unlocked");
    let repo = inner.repo.as_mut().expect("unlocked");
    let _guard = PriorTipGuard::install(&hook, repo, session).map_err(err_to_response)?;
    match fuse_snapshot {
        Some(snapshot) => repo.commit_snapshot(session, snapshot, intent),
        None => repo.commit_workdir(session, intent),
    }
    .map_err(|e| err_to_response(e.into()))
}
