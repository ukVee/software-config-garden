//! The queue *registry* — the named work-streams the fleet scheduler drains.
//!
//! Phase 4 (spec-growlight-orchestrator §6) generalizes the single backlog
//! queue into N named queues, each ≈ a work-stream/project with its own bound
//! repo path and its own ordered backlog. This module owns the registry table
//! (the `queues` managed region in `growlight/backlog/CLAUDE.md`) that maps a
//! queue name to its repo path; the per-queue *item* tables stay the existing
//! [`super::queue`] tables, one managed region per queue:
//!
//! - the implicit **`default`** queue keeps the original `queue` region — the
//!   legacy single-queue garden is byte-for-byte unchanged (back-compat);
//! - every named queue `X` gets its own `queue:X` region.
//!
//! So adding queues never touches the default table, and the item-row
//! render/parse/reorder in [`super::queue`] is reused verbatim per region —
//! "multiple queues" is *more regions of the same shape*, not a wider schema.

use softfig_ipc::ErrorKind;

use super::super::conventions;

/// The implicit, always-present queue. Its items live in the original `queue`
/// region; it carries no repo binding and never appears in the registry.
pub const DEFAULT_QUEUE: &str = "default";

/// One registered queue: a name + the repo path its parts build against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueDef {
    pub name: String,
    pub repo: String,
}

const HEADER: &str = "| queue | repo |";
const SEPARATOR: &str = "|-------|------|";

/// The managed-region tag hosting a queue's item table: the bare `queue`
/// region for the default queue, `queue:<name>` for any named queue. Distinct
/// tags so [`super::super::managed`] keeps each queue's backlog independent and
/// `locate` never confuses `queue` with `queue:softfig` (exact line match).
pub fn item_region_tag(queue: &str) -> String {
    if queue == DEFAULT_QUEUE {
        "queue".to_string()
    } else {
        format!("queue:{queue}")
    }
}

/// Render the registry table (header + separator + one row per queue), with no
/// surrounding blank lines — `managed::upsert` owns the region padding. Cells
/// round-trip through [`super::queue`]'s shared `escape`/`split_row`.
pub fn render(defs: &[QueueDef]) -> String {
    let mut s = String::from(HEADER);
    s.push('\n');
    s.push_str(SEPARATOR);
    for d in defs {
        s.push_str(&format!(
            "\n| {} | {} |",
            super::queue::escape(&d.name),
            super::queue::escape(&d.repo),
        ));
    }
    s
}

/// Parse the registry rows out of a rendered region body, skipping the header
/// and separator. Tolerant of hand-edits: only well-formed 2-cell data rows
/// with a non-empty name are kept.
pub fn parse(body: &str) -> Vec<QueueDef> {
    let mut defs = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells = super::queue::split_row(line);
        if cells.len() != 2 {
            continue;
        }
        if cells[0] == "queue" && cells[1] == "repo" {
            continue; // header
        }
        if cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue; // separator
        }
        if cells[0].is_empty() {
            continue;
        }
        defs.push(QueueDef {
            name: cells[0].clone(),
            repo: cells[1].clone(),
        });
    }
    defs
}

/// Whether `name` is the default queue or a registered one.
pub fn is_known(defs: &[QueueDef], name: &str) -> bool {
    name == DEFAULT_QUEUE || defs.iter().any(|d| d.name == name)
}

/// Validate a queue name: a lowercase `[a-z0-9-]` slug, and not the reserved
/// `default` (which is implicit — its repo isn't registered here).
pub fn validate_queue_name(name: &str) -> Result<(), (ErrorKind, String)> {
    if name == DEFAULT_QUEUE {
        return Err((
            ErrorKind::BadArgs,
            format!("queue name {name:?} is reserved (the default queue is implicit)"),
        ));
    }
    conventions::validate_slug(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(name: &str, repo: &str) -> QueueDef {
        QueueDef {
            name: name.into(),
            repo: repo.into(),
        }
    }

    #[test]
    fn empty_registry_is_header_plus_separator() {
        assert_eq!(render(&[]), format!("{HEADER}\n{SEPARATOR}"));
        assert!(parse(&render(&[])).is_empty());
    }

    #[test]
    fn round_trips_rows() {
        let defs = vec![
            def("softfig", "~/projects/software-config_garden"),
            def("phone", "~/projects/phone-peer"),
        ];
        assert_eq!(parse(&render(&defs)), defs);
    }

    #[test]
    fn repo_pipes_survive_round_trip() {
        let defs = vec![def("weird", "a|b/repo")];
        let table = render(&defs);
        assert!(table.contains("a\\|b/repo"));
        assert_eq!(parse(&table), defs);
    }

    #[test]
    fn parse_ignores_prose_and_malformed_lines() {
        let body = format!(
            "{HEADER}\n{SEPARATOR}\n| softfig | ~/p/s |\nstray prose\n| only-one-cell |"
        );
        let defs = parse(&body);
        assert_eq!(defs, vec![def("softfig", "~/p/s")]);
    }

    #[test]
    fn item_region_tag_is_distinct_per_queue() {
        assert_eq!(item_region_tag(DEFAULT_QUEUE), "queue");
        assert_eq!(item_region_tag("softfig"), "queue:softfig");
        // The default tag is a strict prefix of named tags but never equal —
        // managed::locate matches the whole marker line, so they don't collide.
        assert_ne!(item_region_tag("queue"), item_region_tag(DEFAULT_QUEUE));
    }

    #[test]
    fn is_known_covers_default_and_registered() {
        let defs = vec![def("softfig", "~/p/s")];
        assert!(is_known(&defs, DEFAULT_QUEUE));
        assert!(is_known(&defs, "softfig"));
        assert!(!is_known(&defs, "phone"));
    }

    #[test]
    fn validate_queue_name_gates_default_and_charset() {
        assert!(validate_queue_name("softfig").is_ok());
        assert!(validate_queue_name("default").is_err()); // reserved
        assert!(validate_queue_name("Softfig").is_err()); // charset
        assert!(validate_queue_name("").is_err());
    }
}
