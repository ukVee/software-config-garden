//! `add_note` / `revise_note` — Slice 1 of the small-files redesign — plus
//! the shared accretive-write core (`add_numbered_doc`) that `add_code_review`
//! (task 020) reuses with its own [`DocGenre`].
//!
//! Accretive docs live as numbered single-docs `NNN-slug.md` inside a
//! reserved accretive folder (`notes/`, `troubleshooting/`, `code-reviews/`).
//! The daemon owns every mechanical field: it assigns `NNN` from the folder's
//! `.seq` high-water mark, stamps the `# <title>` header + `> Last reviewed:`
//! line, and names the file — the caller emits only irreducible new content
//! (slug + body, optional title). See `meta/spec-small-files.md`.
//!
//! Numbering is per-folder, monotonic `+1`, never reused. The `.seq` file
//! is the source of truth so archiving the newest note can't hand its
//! number to the next one; we still take `max(.seq, highest live file)` as
//! a belt-and-braces guard against a missing/stale `.seq` (e.g. a folder
//! created before this feature), which can only ever raise the next id.

use std::path::Path;

use softfig_vcs::Intent;
use softfig_ipc::verbs::{AddNoteArgs, AddNoteReply, ReviseNoteArgs, ReviseNoteReply};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, numbering, WorkTree};
use crate::daemon::Daemon;
use crate::handlers::{
    path_to_repo_rel_string, require_unlocked, validate_repo_path, HandlerResult,
};

/// The genre-specific knobs of the shared accretive-write core: which
/// reserved folder basenames the verb may write into (and the label its
/// gate error uses), the VCS intent it mints, and the header stamper.
/// `add_note` and `add_code_review` (task 020) differ only in these.
pub(super) struct DocGenre {
    pub allowed: &'static [&'static str],
    pub label: &'static str,
    pub intent: &'static str,
    pub doc: fn(title: &str, date_hyphen: &str, body: &str) -> String,
}

/// The shared accretive-write core: validate, gate `dir` on the genre's
/// allowed basenames, assign the next `.seq` number, stamp + write the doc,
/// refresh the parent index + backlinks, and mint one genre-intent commit.
/// Returns the garden-relative path written + the commit hash.
pub(super) fn add_numbered_doc(
    daemon: &Daemon,
    dir: &str,
    slug: &str,
    title: Option<&str>,
    body: &str,
    genre: &DocGenre,
) -> Result<(String, String), (ErrorKind, String)> {
    conventions::validate_slug(slug)?;
    if body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let dir_abs = validate_repo_path(&garden_root, dir).map_err(|m| (ErrorKind::BadArgs, m))?;
    let dir_rel = path_to_repo_rel_string(&garden_root, &dir_abs)
        .ok_or((ErrorKind::BadArgs, "dir outside garden root".into()))?;
    if !conventions::dir_basename_in(&dir_rel, genre.allowed) {
        return Err((
            ErrorKind::NotAccretiveDir,
            format!(
                "{dir_rel}: {} live only in an accretive folder ({})",
                genre.label,
                genre.allowed.join(" / ")
            ),
        ));
    }

    let (note_rel, number) = {
        let wt = WorkTree::new(daemon, &inner);
        // The concept dir must already exist — the add verbs materialize the
        // accretive folder on demand, but won't fabricate an arbitrary tree.
        let parent_rel = Path::new(&dir_rel).parent().and_then(|p| p.to_str()).unwrap_or("");
        if !wt.is_dir(parent_rel) {
            return Err((
                ErrorKind::NotFound,
                format!("{dir_rel}: parent concept dir does not exist"),
            ));
        }

        let number = numbering::next_number(&wt, &dir_rel);
        let filename = conventions::note_filename(number, slug);
        let note_rel = format!("{dir_rel}/{filename}");

        let content = (genre.doc)(
            title.unwrap_or(slug),
            &conventions::today_hyphen(),
            body,
        );

        // Bump the high-water mark in the same commit as the new doc.
        numbering::write_numbered(&wt, &dir_rel, number, &note_rel, &content)?;

        // Slice 4: refresh this folder's index table in the parent CLAUDE.md,
        // folded into the same commit (best-effort — never blocks the doc).
        super::index::refresh_folder_index(&wt, &inner, &dir_rel);
        // Slice 5: a new doc may carry `[[…]]` refs and may itself satisfy a
        // previously-dangling ref, so recompute the backlink graph.
        super::backlinks::refresh_all(&wt, &inner);
        (note_rel, number)
    };

    let payload = serde_json::json!({ "dir": dir_rel, "slug": slug, "number": number });
    let intent =
        Intent::new(genre.intent, payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    Ok((note_rel, hash.to_string()))
}

pub fn add_note(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddNoteArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_note args: {e}")))?;
    const GENRE: DocGenre = DocGenre {
        allowed: &conventions::NOTE_FOLDERS,
        label: "notes",
        intent: "note_added",
        doc: conventions::note_doc,
    };
    let (path, hash) = add_numbered_doc(
        daemon,
        &args.dir,
        &args.slug,
        args.title.as_deref(),
        &args.body,
        &GENRE,
    )?;
    Ok(serde_json::to_value(AddNoteReply { path, hash }).unwrap())
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

    let note_rel = {
        let wt = WorkTree::new(daemon, &inner);
        let note_rel = numbering::find_by_id(&wt, &dir_rel, args.id).ok_or((
            ErrorKind::NotFound,
            format!("{dir_rel}: no note numbered {:03}", args.id),
        ))?;

        // Preserve the title (immutable). Re-stamp the reviewed date and swap
        // the body wholesale — header/slug/number are left untouched.
        let existing = wt
            .read_to_string(&note_rel)
            .ok_or((ErrorKind::Io, format!("read {note_rel}: not found")))?;
        let filename = Path::new(&note_rel)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("note.md");
        let title = conventions::note_title(&existing)
            .unwrap_or_else(|| conventions::slug_from_note_name(filename));
        let content = conventions::note_doc(&title, &conventions::today_hyphen(), &args.body);

        wt.write(&note_rel, content.as_bytes())?;

        // Slice 4: re-stamping the reviewed date changes the index's Reviewed
        // column, so refresh the folder's table in the parent CLAUDE.md too.
        super::index::refresh_folder_index(&wt, &inner, &dir_rel);
        // Slice 5: revising the body rewrites it from the note template (dropping
        // any prior backlinks region) and may add/remove `[[…]]` refs — recompute
        // so the region is restored and edges stay accurate.
        super::backlinks::refresh_all(&wt, &inner);
        note_rel
    };

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

