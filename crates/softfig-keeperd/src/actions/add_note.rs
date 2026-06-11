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

use std::path::{Path, PathBuf};

use softfig_vcs::Intent;
use softfig_ipc::verbs::{AddNoteArgs, AddNoteReply, ReviseNoteArgs, ReviseNoteReply};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, write_file};
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

    let number = next_number(&dir_abs);
    let filename = conventions::note_filename(number, &args.slug);
    let note_rel = format!("{dir_rel}/{filename}");
    let note_abs = garden_root.join(&note_rel);
    // The number is fresh, so this can only collide if `.seq` was corrupt
    // and a live file already squats the slot — refuse rather than clobber.
    if note_abs.exists() {
        return Err((ErrorKind::PathAlreadyExists, format!("{note_rel}: already exists")));
    }

    let title = args.title.as_deref().unwrap_or(&args.slug);
    let content = conventions::note_doc(title, &conventions::today_hyphen(), &args.body);

    // Bump the high-water mark in the same commit as the new note.
    let seq_abs = dir_abs.join(conventions::SEQ_FILE);
    daemon.mark_self_write(seq_abs.clone());
    daemon.mark_self_write(note_abs.clone());
    write_file(&seq_abs, format!("{number}\n").as_bytes())?;
    write_file(&note_abs, content.as_bytes())?;

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

    let note_abs = find_note_by_id(&dir_abs, args.id).ok_or((
        ErrorKind::NotFound,
        format!("{dir_rel}: no note numbered {:03}", args.id),
    ))?;
    let note_rel = path_to_repo_rel_string(&garden_root, &note_abs)
        .ok_or((ErrorKind::BadArgs, "note outside garden root".into()))?;

    // Preserve the title (immutable). Re-stamp the reviewed date and swap
    // the body wholesale — header/slug/number are left untouched.
    let existing = std::fs::read_to_string(&note_abs)
        .map_err(|e| (ErrorKind::Io, format!("read {note_rel}: {e}")))?;
    let title = extract_title(&existing).unwrap_or_else(|| slug_from_filename(&note_abs));
    let content = conventions::note_doc(&title, &conventions::today_hyphen(), &args.body);

    daemon.mark_self_write(note_abs.clone());
    write_file(&note_abs, content.as_bytes())?;

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

// ---- numbering + lookup helpers ---------------------------------------

/// The next note number for `dir_abs`: one past the larger of the `.seq`
/// high-water mark and the highest live `NNN-*.md` file. A fresh/missing
/// `.seq` reads as 0; the live-file floor guarantees we never re-issue a
/// number already in use even if `.seq` lags.
fn next_number(dir_abs: &Path) -> u32 {
    read_seq(dir_abs).max(highest_live_number(dir_abs)) + 1
}

fn read_seq(dir_abs: &Path) -> u32 {
    std::fs::read_to_string(dir_abs.join(conventions::SEQ_FILE))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn highest_live_number(dir_abs: &Path) -> u32 {
    let mut max = 0;
    if let Ok(rd) = std::fs::read_dir(dir_abs) {
        for entry in rd.flatten() {
            if let Some(n) = entry
                .file_name()
                .to_str()
                .and_then(parse_leading_number)
            {
                max = max.max(n);
            }
        }
    }
    max
}

/// Parse the `NNN` from a `NNN-<slug>.md` filename (exactly three leading
/// digits then a dash). Anything else (incl. `.seq`) is `None`.
fn parse_leading_number(name: &str) -> Option<u32> {
    let bytes = name.as_bytes();
    if name.ends_with(".md")
        && bytes.len() >= 5
        && bytes[3] == b'-'
        && bytes[..3].iter().all(u8::is_ascii_digit)
    {
        name[..3].parse().ok()
    } else {
        None
    }
}

fn find_note_by_id(dir_abs: &Path, id: u32) -> Option<PathBuf> {
    let prefix = format!("{id:03}-");
    std::fs::read_dir(dir_abs).ok()?.flatten().find_map(|entry| {
        let name = entry.file_name();
        let name = name.to_str()?;
        (name.starts_with(&prefix) && name.ends_with(".md")).then(|| entry.path())
    })
}

/// First `# <title>` heading line, title text trimmed. `None` if the file
/// has no top-level heading (manually mangled) — the caller falls back to
/// the filename slug so a revise never drops the title.
fn extract_title(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        line.strip_prefix("# ").map(|rest| rest.trim().to_string())
    })
}

/// The `<slug>` of a `NNN-<slug>.md` path, used only as a title fallback.
fn slug_from_filename(note_abs: &Path) -> String {
    note_abs
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|name| name.strip_suffix(".md"))
        .and_then(|stem| stem.split_once('-').map(|(_, slug)| slug.to_string()))
        .unwrap_or_else(|| "note".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_leading_number_accepts_notes_only() {
        assert_eq!(parse_leading_number("001-container.md"), Some(1));
        assert_eq!(parse_leading_number("042-gpu-passthrough.md"), Some(42));
        assert_eq!(parse_leading_number(".seq"), None);
        assert_eq!(parse_leading_number("01-short.md"), None);
        assert_eq!(parse_leading_number("001-x.txt"), None);
        assert_eq!(parse_leading_number("abc-x.md"), None);
        assert_eq!(parse_leading_number("001x.md"), None);
    }

    #[test]
    fn extract_title_reads_first_heading() {
        let doc = "# GPU passthrough\n\n> Last reviewed: 2026-06-10\n\nbody\n";
        assert_eq!(extract_title(doc).as_deref(), Some("GPU passthrough"));
        assert_eq!(extract_title("no heading here\n"), None);
    }

    #[test]
    fn slug_from_filename_strips_number_and_ext() {
        assert_eq!(slug_from_filename(Path::new("a/b/004-adb-port.md")), "adb-port");
        assert_eq!(slug_from_filename(Path::new("001-x.md")), "x");
    }
}
