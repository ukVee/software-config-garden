//! `archive` — move a tracked path under `journal/archive/<name>/`,
//! commit `archive_move`. Per the decision file, a non-existent source is
//! a hard error (the MCP action is explicit, unlike the watcher's
//! observed-rename classifier).

use std::path::Path;

use softfig_vcs::Intent;
use softfig_ipc::verbs::{ArchiveArgs, ArchiveReply};
use softfig_ipc::ErrorKind;

use super::commit_now;
use crate::daemon::Daemon;
use crate::handlers::{path_to_repo_rel_string, require_unlocked, validate_repo_path, HandlerResult};

pub fn archive(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ArchiveArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("archive args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let src_abs = validate_repo_path(&garden_root, &args.src).map_err(|m| (ErrorKind::BadArgs, m))?;
    let src_rel = path_to_repo_rel_string(&garden_root, &src_abs)
        .ok_or((ErrorKind::BadArgs, "src outside garden root".into()))?;
    if !src_abs.exists() {
        return Err((ErrorKind::SourceNotFound, format!("{src_rel}: no such path")));
    }

    let basename = Path::new(&src_rel)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or((ErrorKind::BadArgs, "src has no basename".into()))?
        .to_string();

    let archive_name = args.archive_name.clone().unwrap_or_else(|| basename.clone());
    if archive_name.is_empty()
        || archive_name.contains('/')
        || archive_name.contains('\\')
        || archive_name == "."
        || archive_name == ".."
    {
        return Err((
            ErrorKind::BadArgs,
            format!("archive_name {archive_name:?}: must be a single path component"),
        ));
    }

    let dst_rel = format!("journal/archive/{archive_name}/{basename}");
    let dst_abs = garden_root.join(&dst_rel);
    if dst_abs.exists() {
        return Err((ErrorKind::PathAlreadyExists, format!("{dst_rel}: already exists")));
    }
    if let Some(parent) = dst_abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| (ErrorKind::Io, e.to_string()))?;
    }

    daemon.mark_self_write(src_abs.clone());
    daemon.mark_self_write(dst_abs.clone());
    std::fs::rename(&src_abs, &dst_abs).map_err(|e| (ErrorKind::Io, format!("rename: {e}")))?;

    let intent = Intent::new(
        "archive_move",
        serde_json::json!({ "from": src_rel.clone(), "to": dst_rel.clone() }),
    )
    .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    Ok(serde_json::to_value(ArchiveReply {
        from: src_rel,
        to: dst_rel,
        hash: hash.to_string(),
    })
    .unwrap())
}
