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

use softfig_ipc::ErrorKind;

use super::{conventions, Tree};

/// The next note number for accretive folder `dir_rel`: one past the larger of
/// the `.seq` high-water mark and the highest live `NNN-*.md` file. Reads run
/// through the [`Tree`] (a [`super::WorkTree`] in the daemon) so a FUSE-mode
/// commit never stats the mount.
pub fn next_number<T: Tree>(wt: &T, dir_rel: &str) -> u32 {
    read_seq(wt, dir_rel).max(highest_live_number(wt, dir_rel)) + 1
}

fn read_seq<T: Tree>(wt: &T, dir_rel: &str) -> u32 {
    wt.read_to_string(&format!("{dir_rel}/{}", conventions::SEQ_FILE))
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn highest_live_number<T: Tree>(wt: &T, dir_rel: &str) -> u32 {
    wt.read_dir(dir_rel)
        .iter()
        .filter_map(|e| conventions::parse_note_number(&e.name))
        .max()
        .unwrap_or(0)
}

/// Garden-relative path of the `NNN-*.md` doc numbered `id` in `dir_rel`.
pub fn find_by_id<T: Tree>(wt: &T, dir_rel: &str, id: u32) -> Option<String> {
    let prefix = format!("{id:03}-");
    wt.read_dir(dir_rel).into_iter().find_map(|e| {
        (e.name.starts_with(&prefix) && e.name.ends_with(".md"))
            .then(|| format!("{dir_rel}/{}", e.name))
    })
}

/// Stamp the next numbered doc into `dir_rel`: bump `.seq` to `number` and
/// write `note_rel`/`content` through the [`WorkTree`] (which registers both
/// for self-write suppression in disk mode) so the caller's in-flight commit
/// folds them into one commit. Refuses if the target already exists (the only
/// way that happens is a corrupt `.seq` whose number squats a live slot —
/// refuse rather than clobber). `note_rel` is the garden-relative path of the
/// new doc (`dir_rel/filename`).
pub fn write_numbered<T: Tree>(
    wt: &T,
    dir_rel: &str,
    number: u32,
    note_rel: &str,
    content: &str,
) -> Result<(), (ErrorKind, String)> {
    if wt.exists(note_rel) {
        return Err((
            ErrorKind::PathAlreadyExists,
            format!("{note_rel}: already exists"),
        ));
    }
    let seq_rel = format!("{dir_rel}/{}", conventions::SEQ_FILE);
    wt.write(&seq_rel, format!("{number}\n").as_bytes())?;
    wt.write(note_rel, content.as_bytes())?;
    Ok(())
}
