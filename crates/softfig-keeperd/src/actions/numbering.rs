//! Shared monotonic note-numbering for `.seq`-backed numbered-doc folders.
//!
//! Extracted from `add_note` (Slice 1) so every accretive-style folder reuses
//! one numbering rule: `notes/` and `troubleshooting/` (the small-files
//! redesign) plus growlight's `baton-log/`, `tasks/`, and per-milestone
//! `slices/`. Numbering is per-folder, monotonic `+1`, never reused. The
//! `.seq` file is the source of truth so archiving the newest doc can't hand
//! its number to the next one; `max(.seq, highest live file)` is a
//! belt-and-braces guard against a missing/stale `.seq` (a folder created
//! before this feature, or one seeded with no notes yet), which can only ever
//! raise the next id.

use std::path::{Path, PathBuf};

use softfig_ipc::ErrorKind;

use super::{conventions, write_file};
use crate::daemon::Daemon;

/// The next note number for `dir_abs`: one past the larger of the `.seq`
/// high-water mark and the highest live `NNN-*.md` file.
pub fn next_number(dir_abs: &Path) -> u32 {
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
                .and_then(conventions::parse_note_number)
            {
                max = max.max(n);
            }
        }
    }
    max
}

/// Locate the `NNN-*.md` doc numbered `id` in `dir_abs`.
pub fn find_by_id(dir_abs: &Path, id: u32) -> Option<PathBuf> {
    let prefix = format!("{id:03}-");
    std::fs::read_dir(dir_abs).ok()?.flatten().find_map(|entry| {
        let name = entry.file_name();
        let name = name.to_str()?;
        (name.starts_with(&prefix) && name.ends_with(".md")).then(|| entry.path())
    })
}

/// Stamp the next numbered doc into `dir_abs`: bump `.seq` to `number` and
/// write `filename`/`content`, registering both paths for self-write
/// suppression so the caller's in-flight `commit_workdir` folds them into one
/// commit. Refuses if the target already exists (the only way that happens is
/// a corrupt `.seq` whose number squats a live slot — refuse rather than
/// clobber). `note_rel` is the garden-relative path used only in the
/// collision message.
pub fn write_numbered(
    daemon: &Daemon,
    dir_abs: &Path,
    number: u32,
    filename: &str,
    note_rel: &str,
    content: &str,
) -> Result<(), (ErrorKind, String)> {
    let note_abs = dir_abs.join(filename);
    if note_abs.exists() {
        return Err((
            ErrorKind::PathAlreadyExists,
            format!("{note_rel}: already exists"),
        ));
    }
    let seq_abs = dir_abs.join(conventions::SEQ_FILE);
    daemon.mark_self_write(seq_abs.clone());
    daemon.mark_self_write(note_abs.clone());
    write_file(&seq_abs, format!("{number}\n").as_bytes())?;
    write_file(&note_abs, content.as_bytes())?;
    Ok(())
}
