//! The growlight backlog doc's queue tables, read the way every reader reads
//! them (task 064 review G64-3). growlightd's queue source and repo probe and
//! the CLI's semi-auto boot check all parse `growlight/backlog/CLAUDE.md`
//! through here, so they cannot disagree about which queue an item lives in or
//! which repo a queue binds. Pure over the doc text: each caller fetches it its
//! own way (growlightd over keeperd's socket, the CLI off the garden mount).
//!
//! The parsers mirror keeperd's own (`queue::parse`, `queues::parse`), so a
//! hand-edited table reads identically on both sides.

/// The garden-relative backlog doc that hosts every queue's managed region.
pub const BACKLOG_DOC: &str = "growlight/backlog/CLAUDE.md";
/// Where a milestone's doc lives: `<MILESTONES_DIR>/<id>/CLAUDE.md`.
pub const MILESTONES_DIR: &str = "growlight/backlog/milestones";
/// Where a task's doc lives: `<TASKS_DIR>/<id>-<slug>.md` (a task id is its number).
pub const TASKS_DIR: &str = "growlight/backlog/tasks";
/// The implicit default queue's name: its item table is the bare `queue` region
/// and it never has a registry row.
pub const DEFAULT_QUEUE: &str = "default";

/// Whether `id` names a task (an all-digit number) rather than a milestone —
/// the two shapes `add_backlog_item` mints. A task's doc is
/// `<TASKS_DIR>/<id>-*.md`, a milestone's `<MILESTONES_DIR>/<id>/CLAUDE.md`;
/// slice and sub-milestone docs are not an item's own doc.
pub fn is_task_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_digit())
}

/// A managed region's body (`<!-- softfig:<tag> -->` … `<!-- /softfig:<tag> -->`,
/// exact marker lines), with the blank padding keeperd's `managed::upsert` adds
/// on each side stripped. `None` when the region is absent.
pub fn region_body(content: &str, tag: &str) -> Option<String> {
    let open = format!("<!-- softfig:{tag} -->");
    let close = format!("<!-- /softfig:{tag} -->");
    let lines: Vec<&str> = content.split('\n').collect();
    let open_idx = lines.iter().position(|l| l.trim() == open)?;
    let close_rel = lines[open_idx + 1..].iter().position(|l| l.trim() == close)?;
    let close_idx = open_idx + 1 + close_rel;
    let mut body = &lines[open_idx + 1..close_idx];
    while body.first().is_some_and(|l| l.trim().is_empty()) {
        body = &body[1..];
    }
    while body.last().is_some_and(|l| l.trim().is_empty()) {
        body = &body[..body.len() - 1];
    }
    Some(body.join("\n"))
}

/// One queue item table's rows as `(id, status)`, in row order. Only
/// well-formed 5-cell data rows count (`# | id | type | title | status`); the
/// header and separator rows are skipped.
pub fn item_rows(body: &str) -> Vec<(String, String)> {
    table_rows(body, 5, ("#", "id"))
        .into_iter()
        .map(|cells| (cells[1].clone(), cells[4].clone()))
        .collect()
}

/// The queue registry region's `(queue, repo)` rows, in row order: 2-cell data
/// rows with a non-empty name, header and separator skipped.
pub fn registry_rows(doc: &str) -> Vec<(String, String)> {
    let Some(body) = region_body(doc, "queues") else {
        return Vec::new(); // no named queues registered
    };
    table_rows(&body, 2, ("queue", "repo"))
        .into_iter()
        .filter(|cells| !cells[0].is_empty())
        .map(|cells| (cells[0].clone(), cells[1].clone()))
        .collect()
}

/// The registry's `repo` cell for `queue`, raw. [`crate::item_repo::resolve_repo`]
/// decides whether it is a path this machine can probe — a remote `host:/path`
/// cell is returned as-is here. `None` for an unregistered queue (the default
/// queue never has a row).
pub fn registry_repo(doc: &str, queue: &str) -> Option<String> {
    registry_rows(doc).into_iter().find(|(name, _)| name == queue).map(|(_, repo)| repo)
}

/// The queue whose item table lists `item`: [`DEFAULT_QUEUE`] for the bare
/// `queue` region, else the registered queue's name (registry order). `None`
/// when no table lists it. The semi-auto baton names only the item, so the CLI
/// finds its queue here; growlightd already knows it.
pub fn queue_of(doc: &str, item: &str) -> Option<String> {
    let listed = |tag: &str| {
        region_body(doc, tag).is_some_and(|body| item_rows(&body).iter().any(|(id, _)| id == item))
    };
    if listed("queue") {
        return Some(DEFAULT_QUEUE.to_string());
    }
    registry_rows(doc)
        .into_iter()
        .map(|(name, _)| name)
        .find(|name| listed(&format!("queue:{name}")))
}

/// The data rows of a table body with exactly `width` cells, the header row
/// (its first two cells `header`) and separator rows skipped.
fn table_rows(body: &str, width: usize, header: (&str, &str)) -> Vec<Vec<String>> {
    body.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .map(split_row)
        .filter(|cells| cells.len() == width)
        .filter(|cells| !(cells[0] == header.0 && cells[1] == header.1))
        .filter(|cells| !is_separator_row(cells))
        .collect()
}

/// A markdown table separator row (`|---|---|`): every cell non-empty and made
/// only of `-`/`:`.
pub fn is_separator_row(cells: &[String]) -> bool {
    cells
        .iter()
        .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

/// Split one `| a | b | … |` table line into trimmed, `\|`-unescaped cells — a
/// faithful copy of keeperd's `queue::split_row`, so escaped pipes in a title
/// round-trip identically.
pub fn split_row(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                cur.push('|');
                chars.next();
            }
            '|' => {
                cells.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    cells.push(cur.trim().to_string());
    cells
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(tag: &str, body: &str) -> String {
        format!("<!-- softfig:{tag} -->\n\n{body}\n\n<!-- /softfig:{tag} -->")
    }

    fn items(rows: &[(&str, &str)]) -> String {
        let mut s = String::from("| # | id | type | title | status |\n|---|----|------|-------|--------|");
        for (i, (id, status)) in rows.iter().enumerate() {
            s.push_str(&format!("\n| {} | {id} | task | T | {status} |", i + 1));
        }
        s
    }

    #[test]
    fn queue_of_finds_the_table_listing_an_item_and_registry_repo_its_repo() {
        let doc = format!(
            "{}\n\n{}\n\n{}\n\n{}\n",
            region("queue", &items(&[("074", "deferred")])),
            region("queues", "| queue | repo |\n|---|---|\n| fid | /home/u/fid |\n| psy | /home/u/psy |"),
            region("queue:fid", &items(&[("072", "queued")])),
            region("queue:psy", &items(&[("psy-booking", "queued")])),
        );
        assert_eq!(queue_of(&doc, "074").as_deref(), Some(DEFAULT_QUEUE));
        assert_eq!(queue_of(&doc, "072").as_deref(), Some("fid"));
        assert_eq!(queue_of(&doc, "psy-booking").as_deref(), Some("psy"));
        assert_eq!(queue_of(&doc, "999"), None);
        assert_eq!(registry_repo(&doc, "fid").as_deref(), Some("/home/u/fid"));
        assert_eq!(registry_repo(&doc, DEFAULT_QUEUE), None, "the default queue has no row");
        assert_eq!(item_rows(&items(&[("a", "active"), ("b", "done")])), vec![
            ("a".to_string(), "active".to_string()),
            ("b".to_string(), "done".to_string()),
        ]);
    }

    #[test]
    fn a_task_id_is_all_digits() {
        assert!(is_task_id("064"));
        assert!(!is_task_id("queue-v2-git"));
        assert!(!is_task_id(""));
    }
}
