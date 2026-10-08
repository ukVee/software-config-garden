//! Slice 4 of the small-files redesign — daemon-maintained TOC tables for
//! accretive note folders.
//!
//! After every write that can touch a numbered note the daemon regenerates a
//! terse index table in a managed
//! region inside the folder's **parent concept-dir `CLAUDE.md`** — the
//! routing doc Claude already reads, so the index is discoverable where it
//! matters. The table is a TOC (number, linked title, reviewed date), never
//! a rolled-up body view:
//!
//! ```text
//! <!-- softfig:index notes -->
//!
//! | # | Note | Reviewed |
//! |---|------|----------|
//! | 001 | [Container networking](notes/001-container-networking.md) | 2026-06-10 |
//!
//! <!-- /softfig:index notes -->
//! ```
//!
//! Index maintenance is **secondary and best-effort**: the note write is the
//! primary op, folded into the same commit, so a missing or vault-protected
//! host `CLAUDE.md` is silently skipped rather than failing the write. The
//! daemon never fabricates a routing doc.
//!
//! **Who owns the table (task 060).** Every cell is *derived* — the number and
//! link from the filename, the title from the note's `# ` heading, the
//! `Reviewed` date from its own `> Last reviewed:` line. No verb sets a cell;
//! the daemon re-derives the whole region on any write that could have moved
//! one, and a value typed into the region by hand is overwritten on the next
//! write rather than kept. Two entry points:
//!
//! - [`refresh_folder_index`] — the folder-keyed call, for verbs that already
//!   know the folder (`add_note` / `add_code_review` / `revise_note` /
//!   `add_slice` / `archive` / `split` / `batch`'s note ops).
//! - [`refresh_index_for`] — the path-keyed call, for the generic doc-edit
//!   verbs that know only a path (`set_reviewed`, the section verbs,
//!   `patch_file`, `replace_file`, `batch`'s plain writes).
//!
//! Before 060 only the add verbs and `revise_note` refreshed, so `set_reviewed`
//! — the verb whose entire job is moving that date — left the index behind, and
//! every index in the garden drifted a little further from the notes it
//! summarizes.

use std::path::{Path, PathBuf};

use crate::actions::{conventions, managed, WorkTree};
use crate::daemon::DaemonInner;

struct Row {
    number: u32,
    title: String,
    reviewed: String,
    filename: String,
}

/// Managed-region tag for an accretive folder's index, e.g. `index notes`.
/// The folder basename keys the region so a concept dir with both `notes/`
/// and `troubleshooting/` carries two independent index tables.
fn region_tag(folder_name: &str) -> String {
    format!("index {folder_name}")
}

/// Garden-relative path of the host `CLAUDE.md` for accretive folder
/// `folder_rel` (its parent concept dir). `None` if `folder_rel` has no
/// parent (it shouldn't — accretive folders always nest under a concept dir).
fn host_rel(folder_rel: &str) -> Option<String> {
    let parent = Path::new(folder_rel).parent()?;
    let host = if parent.as_os_str().is_empty() {
        PathBuf::from("CLAUDE.md")
    } else {
        parent.join("CLAUDE.md")
    };
    Some(host.to_str()?.replace('\\', "/"))
}

/// Refresh the index table for accretive folder `folder_rel` in its parent
/// concept dir's `CLAUDE.md`, writing the host file so the caller's in-flight
/// `commit_workdir` folds it into the same commit. Returns the host's abs
/// path when it rewrote it, else `None` (no host file, vault-protected host,
/// or no net change). Never errors — index upkeep must not block the note
/// write.
pub fn refresh_folder_index(
    wt: &WorkTree,
    inner: &DaemonInner,
    folder_rel: &str,
) -> Option<String> {
    let folder_name = Path::new(folder_rel).file_name()?.to_str()?.to_string();
    let host_rel = host_rel(folder_rel)?;
    // Read the host CLAUDE.md only if it exists and is safe to rewrite (not
    // vault-protected). A missing host yields `None` — index maintenance
    // never fabricates a routing doc nor clobbers ciphertext.
    let content = super::sections::read_if_unprotected(wt, inner, &host_rel)?;

    let rows = collect_rows(wt, folder_rel);
    let tag = region_tag(&folder_name);
    let new = if rows.is_empty() {
        // Folder emptied (last note archived) → drop the region entirely so
        // the routing doc stays clean; re-adding a note recreates it.
        managed::remove(&content, &tag)
    } else {
        managed::upsert(&content, &tag, &render_table(&folder_name, &rows))
    };
    if new == content {
        return None;
    }
    wt.write(&host_rel, new.as_bytes()).ok()?;
    Some(host_rel)
}

/// Re-derive every index table a write to `rel` can have invalidated, writing
/// the host doc(s) so the caller's in-flight `commit_workdir` folds them into
/// the same commit. Returns the host paths actually rewritten (empty when
/// nothing was keyed to `rel`, or nothing changed).
///
/// Task 060: the `Reviewed` cell is **derived** from each note's own
/// `> Last reviewed:` header, so it is only honest if *every* verb that can
/// move that header re-derives the table. `add_note` / `revise_note` /
/// `add_slice` / `archive` / `split` call [`refresh_folder_index`] directly
/// because they already know the folder; this is the arm for the generic
/// doc-edit verbs (`set_reviewed`, the section verbs, `patch_file`,
/// `replace_file`, `batch`), which know only a path. Two arms, because a path
/// reaches the table from either side:
///
/// 1. `rel` is a numbered doc inside an indexed folder (`…/notes/001-x.md`) →
///    refresh that folder's table.
/// 2. `rel` **is** a host `CLAUDE.md` → re-derive each `index <folder>` region
///    it already carries, so a `Reviewed` cell patched by hand straight into
///    the managed region is corrected rather than persisted.
///
/// Best-effort like the rest of index upkeep: never errors, never fabricates a
/// region (arm 2 only touches regions whose backing folder exists), and
/// silently skips vault-protected hosts.
pub fn refresh_index_for(wt: &WorkTree, inner: &DaemonInner, rel: &str) -> Vec<String> {
    let path = Path::new(rel);
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    // `""` for a doc at the garden root — a valid folder_rel prefix, not a miss.
    let dir = path.parent().and_then(|p| p.to_str()).unwrap_or("");

    let mut hosts = Vec::new();
    if let Some(folder_rel) = indexed_folder_of(rel) {
        hosts.extend(refresh_folder_index(wt, inner, folder_rel));
    }
    if name == "CLAUDE.md" {
        hosts.extend(refresh_host_regions(wt, inner, rel, dir));
    }
    hosts
}

/// Arm 1's keying: the indexed folder a write to `rel` belongs to, i.e. `rel`'s
/// parent iff `rel` is a `NNN-slug.md` numbered doc directly inside an
/// [`INDEXED_FOLDERS`](conventions::INDEXED_FOLDERS) folder. `None` for a
/// `.seq`, a non-numbered name, or any other folder. Split out from
/// [`refresh_index_for`] so the keying is unit-testable without a worktree.
fn indexed_folder_of(rel: &str) -> Option<&str> {
    let path = Path::new(rel);
    let name = path.file_name()?.to_str()?;
    conventions::parse_note_number(name)?;
    let dir = path.parent()?.to_str()?;
    conventions::is_indexed_dir(dir).then_some(dir)
}

/// Arm 2 of [`refresh_index_for`]: re-derive the `index <folder>` regions host
/// doc `host_rel` already carries. Each [`refresh_folder_index`] call re-reads
/// the host, so a doc with both a `notes/` and a `troubleshooting/` table lands
/// both. Regions whose backing folder is absent are left untouched — dropping
/// one is `archive`'s job, not an unrelated edit's.
fn refresh_host_regions(
    wt: &WorkTree,
    inner: &DaemonInner,
    host_rel: &str,
    host_dir: &str,
) -> Vec<String> {
    let Some(content) = super::sections::read_if_unprotected(wt, inner, host_rel) else {
        return Vec::new();
    };
    let folders: Vec<String> = managed::regions(&content)
        .into_iter()
        .filter_map(|(tag, _)| tag.strip_prefix("index ").map(|f| f.trim().to_string()))
        .filter(|folder| !folder.is_empty())
        .map(|folder| {
            if host_dir.is_empty() {
                folder
            } else {
                format!("{host_dir}/{folder}")
            }
        })
        .filter(|folder_rel| conventions::is_indexed_dir(folder_rel) && wt.is_dir(folder_rel))
        .collect();

    folders
        .iter()
        .filter_map(|folder_rel| refresh_folder_index(wt, inner, folder_rel))
        .collect()
}

/// Enumerate the numbered notes in accretive folder `folder_rel`, newest-number
/// last. Each row carries the note's number, `# ` title (falling back to its
/// filename slug), and `Last reviewed:` date (empty if unstamped). Reads run
/// through the [`WorkTree`] so a FUSE-mode commit never stats the mount.
fn collect_rows(wt: &WorkTree, folder_rel: &str) -> Vec<Row> {
    let mut rows = Vec::new();
    for entry in wt.read_dir(folder_rel) {
        let Some(number) = conventions::parse_note_number(&entry.name) else {
            continue;
        };
        let content = wt
            .read_to_string(&format!("{folder_rel}/{}", entry.name))
            .unwrap_or_default();
        let title = conventions::note_title(&content)
            .unwrap_or_else(|| conventions::slug_from_note_name(&entry.name));
        let reviewed = conventions::note_reviewed(&content).unwrap_or_default();
        rows.push(Row {
            number,
            title,
            reviewed,
            filename: entry.name,
        });
    }
    rows.sort_by_key(|r| r.number);
    rows
}

/// Render the TOC table body (no surrounding newlines — `managed::upsert`
/// owns the blank padding). Links are relative to the host `CLAUDE.md`, i.e.
/// `<folder_name>/<filename>`.
fn render_table(folder_name: &str, rows: &[Row]) -> String {
    let mut s = String::from("| # | Note | Reviewed |\n|---|------|----------|");
    for r in rows {
        let link = format!(
            "[{}]({}/{})",
            escape_link_text(&r.title),
            folder_name,
            r.filename
        );
        s.push_str(&format!(
            "\n| {:03} | {} | {} |",
            r.number,
            link,
            escape_cell(&r.reviewed)
        ));
    }
    s
}

/// Escape a literal `|` so it doesn't split the table cell.
fn escape_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

/// Sanitize link text: escape `|`, and neutralize `[`/`]` so a bracket in a
/// title can't break the `[text](target)` link syntax.
fn escape_link_text(s: &str) -> String {
    s.replace('|', "\\|").replace('[', "(").replace(']', ")")
}

// ---- unlink reference refusal ------------------------------------------

/// Host docs whose managed `<!-- softfig:index … -->` regions list `rel` —
/// the `unlink` reference refusal's index arm (a `.seq` slot / TOC row /
/// slice row is history; deleting through it would corrupt the table's
/// invariants — `archive` is the tool that does it right). Each entry names
/// the host + region tag, e.g. `services/waydroid/CLAUDE.md (softfig:index
/// notes)`. Index rows link targets **relative to the host doc**, so both
/// the repo-relative and the host-relative form of `rel` are checked.
/// Whole-garden walk, best-effort like the maintenance itself:
/// vault-protected or unreadable hosts are skipped.
pub fn index_listings(wt: &WorkTree, inner: &DaemonInner, rel: &str) -> Vec<String> {
    let mut out = Vec::new();
    for host in super::backlinks::collect_md(wt) {
        let Some(content) = super::sections::read_if_unprotected(wt, inner, &host) else {
            continue;
        };
        let host_dir = Path::new(&host)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("");
        let host_rel = rel.strip_prefix(host_dir).and_then(|s| s.strip_prefix('/'));
        for (tag, body) in managed::regions(&content) {
            if !tag.starts_with("index ") {
                continue;
            }
            let listed = mentions(&body, rel)
                || host_rel.is_some_and(|r| !r.is_empty() && mentions(&body, r));
            if listed {
                out.push(format!("{host} (softfig:{tag})"));
            }
        }
    }
    out.sort();
    out
}

/// Whether a managed-region body lists `rel` — a path-shaped mention bounded
/// by non-path characters on both sides, so `notes/002-gpu.md` doesn't match
/// inside `notes/002-gpu.md.backup`. Region bodies are daemon-rendered:
/// index rows link `[title](<rel>)`, so both `(`/`)` delimit — the boundary
/// check is exact.
fn mentions(body: &str, rel: &str) -> bool {
    if rel.is_empty() {
        return false;
    }
    let path_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/');
    let mut rest = body;
    while let Some(i) = rest.find(rel) {
        let before = rest[..i].chars().next_back();
        let after = rest[i + rel.len()..].chars().next();
        if before.is_none_or(|c| !path_char(c)) && after.is_none_or(|c| !path_char(c)) {
            return true;
        }
        rest = &rest[i + rel.len()..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<Row> {
        vec![
            Row {
                number: 2,
                title: "GPU passthrough".into(),
                reviewed: "2026-05-30".into(),
                filename: "002-gpu-passthrough.md".into(),
            },
            Row {
                number: 1,
                title: "Container networking".into(),
                reviewed: "2026-06-10".into(),
                filename: "001-container-networking.md".into(),
            },
        ]
    }

    #[test]
    fn host_rel_is_parent_claude_md() {
        assert_eq!(
            host_rel("services/waydroid/notes").as_deref(),
            Some("services/waydroid/CLAUDE.md")
        );
        assert_eq!(host_rel("notes").as_deref(), Some("CLAUDE.md"));
    }

    #[test]
    fn region_tag_keys_on_folder_name() {
        assert_eq!(region_tag("notes"), "index notes");
        assert_eq!(region_tag("troubleshooting"), "index troubleshooting");
    }

    #[test]
    fn render_table_sorts_and_links_relative_to_host() {
        let mut rs = rows();
        rs.sort_by_key(|r| r.number);
        let table = render_table("notes", &rs);
        assert_eq!(
            table,
            "| # | Note | Reviewed |\n|---|------|----------|\n\
             | 001 | [Container networking](notes/001-container-networking.md) | 2026-06-10 |\n\
             | 002 | [GPU passthrough](notes/002-gpu-passthrough.md) | 2026-05-30 |"
        );
    }

    #[test]
    fn render_escapes_pipes_and_brackets() {
        let rs = vec![Row {
            number: 1,
            title: "a|b [v2]".into(),
            reviewed: String::new(),
            filename: "001-a.md".into(),
        }];
        let table = render_table("notes", &rs);
        assert!(table.contains("[a\\|b (v2)](notes/001-a.md)"), "{table}");
        // Empty reviewed renders as an empty cell, not a panic.
        assert!(table.ends_with("|  |"));
    }

    /// Task 060: arm 1 keys a plain doc-edit write back to the folder whose
    /// index derives from it — numbered docs in an indexed folder only.
    #[test]
    fn indexed_folder_of_keys_numbered_docs_in_indexed_folders() {
        assert_eq!(
            indexed_folder_of("services/waydroid/notes/001-a.md"),
            Some("services/waydroid/notes")
        );
        assert_eq!(
            indexed_folder_of("projects/p/code-reviews/012-sweep.md"),
            Some("projects/p/code-reviews")
        );
        assert_eq!(
            indexed_folder_of("growlight/backlog/milestones/m5b/slices/003-x.md"),
            Some("growlight/backlog/milestones/m5b/slices")
        );
        assert_eq!(indexed_folder_of("notes/001-a.md"), Some("notes"));
        // Not a numbered doc, or not an indexed folder → no index keys to it.
        assert_eq!(indexed_folder_of("services/waydroid/notes/.seq"), None);
        assert_eq!(indexed_folder_of("services/waydroid/notes/README.md"), None);
        assert_eq!(indexed_folder_of("journal/decisions/001-a.md"), None);
        assert_eq!(indexed_folder_of("services/waydroid/CLAUDE.md"), None);
        assert_eq!(indexed_folder_of(""), None);
    }

    #[test]
    fn mentions_requires_path_shaped_boundaries() {
        // Link-target form (index rows) and backtick form (backlink rows).
        assert!(mentions("| 001 | [A](notes/002-gpu.md) | 2026 |", "notes/002-gpu.md"));
        assert!(mentions("- `notes/002-gpu.md`", "notes/002-gpu.md"));
        // A bare token at the start / end of the body counts too.
        assert!(mentions("notes/002-gpu.md\n", "notes/002-gpu.md"));
        // Substring-of-a-path mentions don't: the neighbor is a path char.
        assert!(!mentions("(notes/002-gpu.md.backup)", "notes/002-gpu.md"));
        assert!(!mentions("(xnotes/002-gpu.md)", "notes/002-gpu.md"));
        // Only `index *` tags are scanned, so the empty needle never loops.
        assert!(!mentions("anything", ""));
    }
}
