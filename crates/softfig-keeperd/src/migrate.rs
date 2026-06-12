//! `softfig migrate` daemon-side orchestration.
//!
//! Phase 1 (`prepare`) is a CLI-only step — it doesn't talk to the
//! daemon. The CLI copies `.softfig/` to the new state root and writes
//! `keeper.toml`. Code lives in `softfig-cli::cmd_migrate`.
//!
//! Phase 3 (`finalize`) is daemon-orchestrated and lives here. It
//! requires a running, FUSE-mounted M2a daemon:
//!
//! 1. Unmount the live FUSE filesystem (so the orphan plaintext under
//!    `garden_root/` becomes visible again).
//! 2. Best-effort delete every plaintext file under `garden_root/`
//!    EXCEPT the `.softfig/` subdir.
//! 3. Best-effort delete the old `garden_root/.softfig/`.
//! 4. Remount FUSE.
//!
//! Per the locked open-question #2 lean: deletion is best-effort. We
//! collect skipped paths into the reply and return success as long as
//! the unmount + remount worked. Orphan plaintext under the FUSE mount
//! is harmless (the mount-over hides it); the user can re-run
//! `finalize` later or clean up manually.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::actions::conventions;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MigrateFinalizeArgs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateFinalizeReply {
    pub unmounted: bool,
    pub plaintext_deleted: usize,
    pub plaintext_skipped: Vec<String>,
    pub old_state_deleted: bool,
    pub old_state_skipped: Vec<String>,
    pub remounted: bool,
}

/// Recursively delete everything under `dir` except entries whose
/// top-level name matches `skip_top`. Collect failures into the
/// `skipped` list rather than aborting.
pub fn delete_tree_except(
    dir: &Path,
    skip_top: &[&str],
    skipped: &mut Vec<String>,
) -> usize {
    let mut deleted = 0;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            skipped.push(format!("{}: {e}", dir.display()));
            return 0;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if skip_top
            .iter()
            .any(|s| name.to_string_lossy().as_ref() == *s)
        {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                skipped.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        if ft.is_dir() {
            match std::fs::remove_dir_all(&path) {
                Ok(_) => deleted += 1,
                Err(e) => skipped.push(format!("{}: {e}", path.display())),
            }
        } else {
            match std::fs::remove_file(&path) {
                Ok(_) => deleted += 1,
                Err(e) => skipped.push(format!("{}: {e}", path.display())),
            }
        }
    }
    deleted
}

/// Remove an entire directory tree. Returns `(success, skipped)`.
pub fn delete_dir(path: &Path) -> (bool, Vec<String>) {
    if !path.exists() {
        return (true, Vec::new());
    }
    match std::fs::remove_dir_all(path) {
        Ok(_) => (true, Vec::new()),
        Err(e) => (false, vec![format!("{}: {e}", path.display())]),
    }
}

#[allow(dead_code)]
pub(crate) fn _placeholder_path() -> PathBuf {
    PathBuf::new()
}

// ---- Slice 1 (small-files): accretive monolith → numbered notes -------
//
// One-time splitter that turns a monolithic `notes.md` / `troubleshooting.md`
// into a folder of `NNN-slug.md` single-docs. The core ([`split_monolith`] /
// [`plan_split`]) is a pure transform so it's exhaustively unit-testable; the
// production trigger (materialize the folder, archive the monolith, commit)
// belongs to the migrate/onboard command flow and is wired separately.
//
// Splitting rule: each level-2 (`## `) heading starts a note — its heading
// text is the title, the lines beneath it (up to the next `## `) are the body.
// The file preamble (the `# <doc>` title, the `> Last reviewed:` stamp, and
// any intro paragraph before the first section) describes the folder, not a
// note, so it's dropped. A monolith with no `## ` sections collapses to a
// single note so nothing is lost. Empty-bodied sections are skipped.

/// One section of a split monolith, pre-render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitNote {
    pub slug: String,
    pub title: String,
    pub body: String,
}

/// The rendered plan for one accretive folder: numbered note files (in
/// document order) plus the `.seq` high-water mark to seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPlan {
    /// `(filename, content)` for each note, e.g. `("001-foo.md", "# foo\n…")`.
    pub notes: Vec<(String, String)>,
    /// Value to write into the folder's `.seq` (= note count).
    pub seq: u32,
}

/// Parse a monolith into ordered, un-numbered notes. Pure.
pub fn split_monolith(content: &str) -> Vec<SplitNote> {
    let lines: Vec<&str> = content.lines().collect();
    let heads: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| is_h2(l))
        .map(|(i, _)| i)
        .collect();

    if heads.is_empty() {
        return single_note(&lines);
    }

    let mut out = Vec::new();
    for (k, &start) in heads.iter().enumerate() {
        let end = heads.get(k + 1).copied().unwrap_or(lines.len());
        let title = heading_text(lines[start]);
        let body = trim_blank_lines(&lines[start + 1..end]).join("\n");
        if body.trim().is_empty() {
            continue;
        }
        out.push(SplitNote {
            slug: conventions::slugify(&title),
            title,
            body,
        });
    }
    out
}

/// Split + number + render each note with the daemon's note template.
pub fn plan_split(content: &str, date_hyphen: &str) -> SplitPlan {
    let notes: Vec<(String, String)> = split_monolith(content)
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let number = (i + 1) as u32;
            (
                conventions::note_filename(number, &n.slug),
                conventions::note_doc(&n.title, date_hyphen, &n.body),
            )
        })
        .collect();
    let seq = notes.len() as u32;
    SplitPlan { notes, seq }
}

fn is_h2(line: &str) -> bool {
    line.starts_with("## ")
}

/// Strip the leading `#` run + surrounding whitespace from a heading line.
fn heading_text(line: &str) -> String {
    line.trim_start_matches('#').trim().to_string()
}

/// Monolith with no `## ` sections → at most one note from the body that
/// remains after dropping the `# <title>` line and a `> Last reviewed:`
/// stamp. Empty body ⇒ no note.
fn single_note(lines: &[&str]) -> Vec<SplitNote> {
    let mut i = 0;
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }
    let mut title = String::new();
    if i < lines.len() && lines[i].starts_with("# ") {
        title = heading_text(lines[i]);
        i += 1;
    }
    while i < lines.len()
        && (lines[i].trim().is_empty()
            || lines[i].trim_start().starts_with("> Last reviewed"))
    {
        i += 1;
    }
    let body = trim_blank_lines(&lines[i..]).join("\n");
    if body.trim().is_empty() {
        return Vec::new();
    }
    if title.is_empty() {
        title = "notes".to_string();
    }
    vec![SplitNote {
        slug: conventions::slugify(&title),
        title,
        body,
    }]
}

// ---- Slice 1 production trigger: discover + address monoliths ---------
//
// `softfig migrate split` walks the working tree for the legacy `notes.md` /
// `troubleshooting.md` monoliths and rewrites each into its sibling accretive
// folder (`notes/` / `troubleshooting/`). The pure pieces — which path is a
// monolith, what folder it maps to, and where its archived copy lands — live
// here next to [`plan_split`]; the daemon orchestration (materialize, archive,
// commit) is `crate::actions::migrate_split`.

/// A monolith found in the working tree and the accretive folder it splits
/// into. Both are garden-relative, `/`-separated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Monolith {
    pub path: String,
    pub folder: String,
}

/// If `rel` names a splittable monolith — a `notes.md` / `troubleshooting.md`
/// outside `journal/archive/` — return `(target_folder_rel, kind)`. The folder
/// is the sibling accretive dir (`<parent>/notes`); a top-level monolith maps
/// to a root-level folder. Pure.
pub fn monolith_target(rel: &str) -> Option<(String, &'static str)> {
    if rel == "journal/archive" || rel.starts_with("journal/archive/") {
        return None;
    }
    let path = Path::new(rel);
    let kind = match path.file_name()?.to_str()? {
        "notes.md" => "notes",
        "troubleshooting.md" => "troubleshooting",
        _ => return None,
    };
    let parent = path.parent().and_then(|p| p.to_str()).unwrap_or("");
    let folder = if parent.is_empty() {
        kind.to_string()
    } else {
        format!("{parent}/{kind}")
    };
    Some((folder, kind))
}

/// Collision-free archive bucket for a monolith whose target folder is
/// `folder_rel`. Multiple `notes.md` across the tree would otherwise collide
/// on one `journal/archive/notes/` bucket, so flatten the path to a single
/// component (`projects/foo/notes` → `projects-foo-notes`). Pure.
pub fn archive_bucket(folder_rel: &str) -> String {
    folder_rel.replace('/', "-")
}

/// Walk `garden_root`'s working tree for monoliths. Returns the splittable ones
/// (whose target folder doesn't yet exist), sorted by path, plus `(path,
/// reason)` pairs for monoliths skipped because their folder already exists (a
/// partial or repeated migration). Skips `.softfig/` and `journal/archive/`.
pub fn discover_monoliths(garden_root: &Path) -> (Vec<Monolith>, Vec<(String, String)>) {
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    walk_tree(garden_root, garden_root, &mut |rel| {
        if let Some((folder, _kind)) = monolith_target(rel) {
            if garden_root.join(&folder).exists() {
                skipped.push((
                    rel.to_string(),
                    format!("target folder {folder}/ already exists"),
                ));
            } else {
                found.push(Monolith {
                    path: rel.to_string(),
                    folder,
                });
            }
        }
    });
    found.sort_by(|a, b| a.path.cmp(&b.path));
    skipped.sort();
    (found, skipped)
}

fn walk_tree(root: &Path, dir: &Path, visit: &mut impl FnMut(&str)) {
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let path = entry.path();
        if ft.is_dir() {
            if entry.file_name() == ".softfig" {
                continue;
            }
            if rel_of(root, &path).as_deref() == Some("journal/archive") {
                continue;
            }
            walk_tree(root, &path, visit);
        } else if ft.is_file() {
            if let Some(rel) = rel_of(root, &path) {
                visit(&rel);
            }
        }
    }
}

fn rel_of(root: &Path, path: &Path) -> Option<String> {
    Some(path.strip_prefix(root).ok()?.to_str()?.replace('\\', "/"))
}

/// Drop leading + trailing all-whitespace lines from a slice.
fn trim_blank_lines<'a>(lines: &'a [&'a str]) -> &'a [&'a str] {
    let mut start = 0;
    let mut end = lines.len();
    while start < end && lines[start].trim().is_empty() {
        start += 1;
    }
    while end > start && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    &lines[start..end]
}

#[cfg(test)]
mod split_tests {
    use super::*;

    const MONOLITH: &str = "\
# notes

> Last reviewed: 2026-05-30

Running decision log for `waydroid`.

## container networking

Waydroid uses an internal bridge.
Second line of the section.

## GPU passthrough

Needs the venus driver.

### sub-detail

Nested content stays in the section.
";

    #[test]
    fn splits_on_level_two_headings() {
        let notes = split_monolith(MONOLITH);
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].title, "container networking");
        assert_eq!(notes[0].slug, "container-networking");
        assert_eq!(
            notes[0].body,
            "Waydroid uses an internal bridge.\nSecond line of the section."
        );
        assert_eq!(notes[1].title, "GPU passthrough");
        assert_eq!(notes[1].slug, "gpu-passthrough");
        // A `###` subsection is part of its parent section's body.
        assert!(notes[1].body.contains("### sub-detail"));
        assert!(notes[1].body.contains("Nested content"));
        // The preamble (title, reviewed stamp, intro) is dropped.
        assert!(!notes.iter().any(|n| n.body.contains("Running decision log")));
    }

    #[test]
    fn plan_numbers_and_stamps() {
        let plan = plan_split(MONOLITH, "2026-06-10");
        assert_eq!(plan.seq, 2);
        assert_eq!(plan.notes[0].0, "001-container-networking.md");
        assert_eq!(plan.notes[1].0, "002-gpu-passthrough.md");
        assert!(plan.notes[0].1.starts_with("# container networking\n"));
        assert!(plan.notes[0].1.contains("> Last reviewed: 2026-06-10\n"));
        assert!(plan.notes[0].1.ends_with("Second line of the section.\n"));
    }

    #[test]
    fn empty_sections_are_skipped() {
        let src = "## kept\n\nhas body\n\n## dropped\n\n## also-kept\n\nbody2\n";
        let notes = split_monolith(src);
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].title, "kept");
        assert_eq!(notes[1].title, "also-kept");
    }

    #[test]
    fn no_headings_collapses_to_single_note() {
        let src = "# notes\n\n> Last reviewed: 2026-05-30\n\nJust a blob of prose.\nNo sections here.\n";
        let notes = split_monolith(src);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].title, "notes");
        assert_eq!(notes[0].body, "Just a blob of prose.\nNo sections here.");
    }

    #[test]
    fn header_only_monolith_yields_nothing() {
        let src = "# notes\n\n> Last reviewed: 2026-05-30\n";
        assert!(split_monolith(src).is_empty());
        assert_eq!(plan_split(src, "2026-06-10").seq, 0);
    }
}

#[cfg(test)]
mod discover_tests {
    use super::*;

    #[test]
    fn monolith_target_addresses_both_kinds() {
        assert_eq!(
            monolith_target("notes.md"),
            Some(("notes".into(), "notes"))
        );
        assert_eq!(
            monolith_target("projects/foo/notes.md"),
            Some(("projects/foo/notes".into(), "notes"))
        );
        assert_eq!(
            monolith_target("services/x/troubleshooting.md"),
            Some(("services/x/troubleshooting".into(), "troubleshooting"))
        );
    }

    #[test]
    fn monolith_target_rejects_non_monoliths() {
        // Archived copies, already-numbered notes, and unrelated docs.
        assert_eq!(monolith_target("journal/archive/old-notes/notes.md"), None);
        assert_eq!(monolith_target("notes/001-foo.md"), None);
        assert_eq!(monolith_target("README.md"), None);
        assert_eq!(monolith_target("instructions.md"), None);
    }

    #[test]
    fn archive_bucket_flattens_path() {
        assert_eq!(archive_bucket("notes"), "notes");
        assert_eq!(archive_bucket("projects/foo/notes"), "projects-foo-notes");
    }

    #[test]
    fn discover_finds_unmigrated_skips_existing_and_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let write = |rel: &str, body: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };

        // A top-level monolith with no sibling folder → splittable.
        write("notes.md", "## a\n\nbody\n");
        // A nested monolith → splittable.
        write("projects/foo/notes.md", "## b\n\nbody\n");
        // A monolith whose accretive folder already exists → skipped.
        write("services/x/troubleshooting.md", "## c\n\nbody\n");
        write("services/x/troubleshooting/.seq", "0\n");
        // Already-archived monolith + the daemon state dir → ignored entirely.
        write("journal/archive/old/notes.md", "## d\n\nbody\n");
        write(".softfig/keeper.toml", "x = 1\n");

        let (found, skipped) = discover_monoliths(root);
        let found_paths: Vec<&str> = found.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(found_paths, ["notes.md", "projects/foo/notes.md"]);
        assert_eq!(found[0].folder, "notes");
        assert_eq!(found[1].folder, "projects/foo/notes");
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "services/x/troubleshooting.md");
    }
}
