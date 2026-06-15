//! The authoritative backlog queue table.
//!
//! Per the locked design (spec-growlight.md §4 + the Phase-1 schema pick),
//! a backlog item's status + order live ONLY in the daemon-managed `queue`
//! region inside `growlight/backlog/CLAUDE.md` — the item docs carry mission
//! and slices, never status. So unlike the derived slice/notes index, this
//! table is *round-tripped*: `add_backlog_item` parses it, appends a row, and
//! re-renders; `set_item_status` parses it, flips one cell, and re-renders.
//!
//! The `#` column is render-time row order (1-based) — the queue order the
//! loop drains in — and is recomputed on every render, never parsed back.

/// One backlog item's authoritative queue state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRow {
    pub id: String,
    pub item_type: String,
    pub title: String,
    pub status: String,
}

const HEADER: &str = "| # | id | type | title | status |";
const SEPARATOR: &str = "|---|----|------|-------|--------|";

/// Render the full table (header + separator + one line per row), with the
/// `#` column as the 1-based row order. No surrounding blank lines —
/// `managed::upsert` owns the region padding.
pub fn render(rows: &[QueueRow]) -> String {
    let mut s = String::from(HEADER);
    s.push('\n');
    s.push_str(SEPARATOR);
    for (i, r) in rows.iter().enumerate() {
        s.push_str(&format!(
            "\n| {} | {} | {} | {} | {} |",
            i + 1,
            escape(&r.id),
            escape(&r.item_type),
            escape(&r.title),
            escape(&r.status),
        ));
    }
    s
}

/// Parse the rows out of a rendered region body, skipping the header and
/// separator. Tolerant of hand-edits: only well-formed 5-cell data rows are
/// kept; the `#` order cell is discarded (recomputed on render).
pub fn parse(body: &str) -> Vec<QueueRow> {
    let mut rows = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells = split_row(line);
        if cells.len() != 5 {
            continue;
        }
        if cells[0] == "#" && cells[1] == "id" {
            continue; // header
        }
        if cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue; // separator
        }
        rows.push(QueueRow {
            id: cells[1].clone(),
            item_type: cells[2].clone(),
            title: cells[3].clone(),
            status: cells[4].clone(),
        });
    }
    rows
}

/// Escape a literal `|` so it doesn't split a table cell.
fn escape(s: &str) -> String {
    s.replace('|', "\\|")
}

/// Split one `| a | b | … |` line into trimmed, `\|`-unescaped cells.
fn split_row(line: &str) -> Vec<String> {
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

    fn row(id: &str, ty: &str, title: &str, status: &str) -> QueueRow {
        QueueRow {
            id: id.into(),
            item_type: ty.into(),
            title: title.into(),
            status: status.into(),
        }
    }

    #[test]
    fn empty_table_is_header_plus_separator() {
        assert_eq!(render(&[]), format!("{HEADER}\n{SEPARATOR}"));
        assert!(parse(&render(&[])).is_empty());
    }

    #[test]
    fn render_numbers_rows_one_based() {
        let rows = vec![
            row("m5b", "milestone", "Zero-knowledge backup", "active"),
            row("001", "task", "SIGTERM unmount", "queued"),
        ];
        let table = render(&rows);
        assert!(table.contains("| 1 | m5b | milestone | Zero-knowledge backup | active |"));
        assert!(table.contains("| 2 | 001 | task | SIGTERM unmount | queued |"));
    }

    #[test]
    fn round_trips_rows() {
        let rows = vec![
            row("m5b", "milestone", "Backup", "active"),
            row("001", "task", "Unmount", "done"),
        ];
        assert_eq!(parse(&render(&rows)), rows);
    }

    #[test]
    fn title_pipes_survive_round_trip() {
        let rows = vec![row("m5b", "milestone", "a|b path | x", "queued")];
        let table = render(&rows);
        assert!(table.contains("a\\|b path \\| x"));
        assert_eq!(parse(&table), rows);
    }

    #[test]
    fn parse_ignores_prose_and_malformed_lines() {
        let body = format!(
            "{HEADER}\n{SEPARATOR}\n| 1 | m5b | milestone | Backup | active |\nstray prose\n| bad | row |"
        );
        let rows = parse(&body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "m5b");
    }
}
