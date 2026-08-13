//! Slice 4 of the small-files redesign — daemon-maintained TOC tables for
//! accretive note folders.
//!
//! After every note mutation (`add_note` / `revise_note` / `archive` of a
//! numbered note) the daemon regenerates a terse index table in a managed
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
