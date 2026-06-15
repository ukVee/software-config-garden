//! `add_note` / `revise_note` — Slice 1 of the small-files redesign.
//!
//! Accretive notes live as numbered single-docs `NNN-slug.md` inside a
//! `notes/` or `troubleshooting/` folder. The daemon owns every mechanical
//! field: it assigns `NNN` from the folder's `.seq` high-water mark, stamps
//! the `# <title>` header + `> Last reviewed:` line, and names the file —
//! the caller emits only irreducible new content (slug + body, optional
//! title). See `meta/spec-small-files.md`.
//!
//! Numbering is per-folder, monotonic `+1`, never reused. The `.seq` file
//! is the source of truth so archiving the newest note can't hand its
//! number to the next one; we still take `max(.seq, highest live file)` as
//! a belt-and-braces guard against a missing/stale `.seq` (e.g. a folder
//! created before this feature), which can only ever raise the next id.

use softfig_vcs::Intent;
use softfig_ipc::verbs::{AddNoteArgs, AddNoteReply, ReviseNoteArgs, ReviseNoteReply};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, numbering, write_file};
use crate::daemon::Daemon;
use crate::handlers::{
    path_to_repo_rel_string, require_unlocked, validate_repo_path, HandlerResult,
};

pub fn add_note(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddNoteArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_note args: {e}")))?;
    conventions::validate_slug(&args.slug)?;
    if args.body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let dir_abs = validate_repo_path(&garden_root, &args.dir).map_err(|m| (ErrorKind::BadArgs, m))?;
    let dir_rel = path_to_repo_rel_string(&garden_root, &dir_abs)
        .ok_or((ErrorKind::BadArgs, "dir outside garden root".into()))?;
    if !conventions::is_accretive_dir(&dir_rel) {
        return Err((
            ErrorKind::NotAccretiveDir,
            format!(
                "{dir_rel}: notes live only in an accretive folder ({})",
                conventions::ACCRETIVE_FOLDERS.join(" / ")
            ),
        ));
    }
    // The concept dir must already exist — `add_note` materializes the
    // accretive folder on demand, but won't fabricate an arbitrary tree.
    match dir_abs.parent() {
        Some(p) if p.is_dir() => {}
        _ => {
            return Err((
                ErrorKind::NotFound,
                format!("{dir_rel}: parent concept dir does not exist"),
            ))
        }
    }

    let number = numbering::next_number(&dir_abs);
    let filename = conventions::note_filename(number, &args.slug);
    let note_rel = format!("{dir_rel}/{filename}");

    let title = args.title.as_deref().unwrap_or(&args.slug);
    let content = conventions::note_doc(title, &conventions::today_hyphen(), &args.body);

    // Bump the high-water mark in the same commit as the new note.
    numbering::write_numbered(daemon, &dir_abs, number, &filename, &note_rel, &content)?;

    // Slice 4: refresh this folder's index table in the parent CLAUDE.md,
    // folded into the same commit (best-effort — never blocks the note).
    super::index::refresh_folder_index(daemon, &inner, &garden_root, &dir_rel);
    // Slice 5: a new note may carry `[[…]]` refs and may itself satisfy a
    // previously-dangling ref, so recompute the backlink graph.
    super::backlinks::refresh_all(daemon, &inner, &garden_root);

    let payload = serde_json::json!({ "dir": dir_rel, "slug": args.slug, "number": number });
    let intent =
        Intent::new("note_added", payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    Ok(serde_json::to_value(AddNoteReply {
        path: note_rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

pub fn revise_note(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ReviseNoteArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("revise_note args: {e}")))?;
    if args.body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let dir_abs = validate_repo_path(&garden_root, &args.dir).map_err(|m| (ErrorKind::BadArgs, m))?;
    let dir_rel = path_to_repo_rel_string(&garden_root, &dir_abs)
        .ok_or((ErrorKind::BadArgs, "dir outside garden root".into()))?;
    if !conventions::is_accretive_dir(&dir_rel) {
        return Err((
            ErrorKind::NotAccretiveDir,
            format!("{dir_rel}: not an accretive note folder"),
        ));
    }

    let note_abs = numbering::find_by_id(&dir_abs, args.id).ok_or((
        ErrorKind::NotFound,
        format!("{dir_rel}: no note numbered {:03}", args.id),
    ))?;
    let note_rel = path_to_repo_rel_string(&garden_root, &note_abs)
        .ok_or((ErrorKind::BadArgs, "note outside garden root".into()))?;

    // Preserve the title (immutable). Re-stamp the reviewed date and swap
    // the body wholesale — header/slug/number are left untouched.
    let existing = std::fs::read_to_string(&note_abs)
        .map_err(|e| (ErrorKind::Io, format!("read {note_rel}: {e}")))?;
    let filename = note_abs.file_name().and_then(|s| s.to_str()).unwrap_or("note.md");
    let title = conventions::note_title(&existing)
        .unwrap_or_else(|| conventions::slug_from_note_name(filename));
    let content = conventions::note_doc(&title, &conventions::today_hyphen(), &args.body);

    daemon.mark_self_write(note_abs.clone());
    write_file(&note_abs, content.as_bytes())?;

    // Slice 4: re-stamping the reviewed date changes the index's Reviewed
    // column, so refresh the folder's table in the parent CLAUDE.md too.
    super::index::refresh_folder_index(daemon, &inner, &garden_root, &dir_rel);
    // Slice 5: revising the body rewrites it from the note template (dropping
    // any prior backlinks region) and may add/remove `[[…]]` refs — recompute
    // so the region is restored and edges stay accurate.
    super::backlinks::refresh_all(daemon, &inner, &garden_root);

    let payload = serde_json::json!({ "dir": dir_rel, "id": args.id });
    let intent =
        Intent::new("note_revised", payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    Ok(serde_json::to_value(ReviseNoteReply {
        path: note_rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

