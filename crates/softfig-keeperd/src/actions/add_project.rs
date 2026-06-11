//! `add_project` — atomically stamp the four reserved-name stubs under
//! `projects/<name>/` and commit a single `project_added` (Pick G).

use softfig_vcs::Intent;
use softfig_ipc::verbs::{AddProjectArgs, AddProjectReply};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, write_file};
use crate::daemon::Daemon;
use crate::handlers::{require_unlocked, HandlerResult};

pub fn add_project(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddProjectArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_project args: {e}")))?;
    conventions::validate_project_name(&args.name)?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let dir_rel = conventions::project_dir(&args.name);
    let dir_abs = garden_root.join(&dir_rel);
    if dir_abs.exists() {
        return Err((ErrorKind::PathAlreadyExists, format!("{dir_rel}: already exists")));
    }

    let date = conventions::today_hyphen();
    let repo_path = args.repo_path.as_deref();
    let summary = args.summary.as_deref();

    // Render all four stubs up front; reserved-name set matches every
    // existing project dir in the OG garden.
    let files: Vec<(String, String)> = vec![
        (
            format!("{dir_rel}/CLAUDE.md"),
            conventions::project_claude_md(&args.name, repo_path, summary),
        ),
        (
            format!("{dir_rel}/instructions.md"),
            conventions::project_instructions_md(&args.name, &date),
        ),
        (
            format!("{dir_rel}/notes.md"),
            conventions::project_notes_md(&args.name, &date),
        ),
        (
            format!("{dir_rel}/refs.md"),
            conventions::project_refs_md(&args.name, &date, repo_path),
        ),
    ];

    // Register every path in the suppression map BEFORE any IO so the
    // watcher (if running) drops the events, then write them all. The
    // single `commit_workdir` below makes the four-file write atomic.
    let mut written = Vec::with_capacity(files.len());
    for (rel, content) in &files {
        let abs = garden_root.join(rel);
        daemon.mark_self_write(abs.clone());
        write_file(&abs, content.as_bytes())?;
        written.push(rel.clone());
    }

    let payload = serde_json::json!({
        "name": args.name,
        "repo_path": args.repo_path.unwrap_or_default(),
    });
    let intent =
        Intent::new("project_added", payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    Ok(serde_json::to_value(AddProjectReply {
        path: dir_rel,
        hash: hash.to_string(),
        files: written,
    })
    .unwrap())
}
