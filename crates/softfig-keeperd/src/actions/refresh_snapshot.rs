//! `refresh_snapshot` — write caller-supplied content to a path under
//! `snapshots/`, commit `snapshot_refresh` (Pick F: content-bearing, the
//! daemon never executes user code). Unlike the create-style actions this
//! overwrites: a refresh replaces the previous snapshot data.

use softfig_vcs::Intent;
use softfig_ipc::verbs::{RefreshSnapshotArgs, RefreshSnapshotReply};
use softfig_ipc::ErrorKind;

use super::{commit_now, write_file};
use crate::daemon::Daemon;
use crate::handlers::{path_to_repo_rel_string, require_unlocked, validate_repo_path, HandlerResult};

pub fn refresh_snapshot(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: RefreshSnapshotArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("refresh_snapshot args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let abs = validate_repo_path(&garden_root, &args.path)
        .map_err(|m| (ErrorKind::InvalidSnapshotPath, m))?;
    let rel = path_to_repo_rel_string(&garden_root, &abs)
        .ok_or((ErrorKind::InvalidSnapshotPath, "path outside garden root".into()))?;
    if !rel.starts_with("snapshots/") {
        return Err((
            ErrorKind::InvalidSnapshotPath,
            format!("{rel}: must be under snapshots/"),
        ));
    }

    // Require the parent dir to already exist (decision lean): refuse to
    // mint a snapshot subtree from a typo. The matching
    // `snapshots/<area>/` should already be in place.
    let parent = abs
        .parent()
        .ok_or((ErrorKind::InvalidSnapshotPath, "no parent dir".into()))?;
    if !parent.is_dir() {
        return Err((
            ErrorKind::InvalidSnapshotPath,
            format!("{rel}: parent directory does not exist"),
        ));
    }

    daemon.mark_self_write(abs.clone());
    write_file(&abs, args.content.as_bytes())?;

    let intent = Intent::new("snapshot_refresh", serde_json::json!({ "path": rel.clone() }))
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    Ok(serde_json::to_value(RefreshSnapshotReply {
        path: rel,
        hash: hash.to_string(),
    })
    .unwrap())
}
