//! The growlight **queue v2** state model — the typed shape of the three TOML
//! files that hold the v2 backlog, shared by the one writer (keeperd, through
//! the §6.8 human verbs) and the one reader (growlightd's v2 queue source) so
//! the file shape can never drift between them. Spec: `meta/spec-growlight-queue.md`
//! §3.1–§3.3.
//!
//! The three files:
//! - [`QueueToml`] — `growlight/backlog/queue.toml`, the one global list (§3.1);
//! - [`QueueArchiveToml`] — `growlight/backlog/queue-archive.toml`, the rows
//!   that left the list (§3.2);
//! - [`SlicesToml`] — `growlight/backlog/milestones/<id>/slices.toml`, one
//!   milestone's slice order (§3.3).
//!
//! Parsing is **fail-closed**, deliberately:
//!
//! - no `Default` fallback anywhere — a malformed file is an error, never an
//!   empty list that silently schedules nothing;
//! - `schema` must be exactly [`SCHEMA_VERSION`] — a file from a future build
//!   is refused, not half-read;
//! - every field is required (no `#[serde(default)]` on the file shapes):
//!   keeperd writes every field on every write, so a missing one means the
//!   file was hand-edited or corrupted — refuse it;
//! - the closed vocabularies (kind, lane, status, …) are enums, so a stray
//!   string fails to parse instead of being carried as data;
//! - unknown fields are refused ([`serde(deny_unknown_fields)`]) — one
//!   exception: [`ArchivedEntry`] flattens [`Entry`], which serde forbids
//!   combining with `deny_unknown_fields`; unknown keys inside an archived
//!   row are therefore ignored (still an error if a required key is missing).
//!   The invariant validation (slice 002) is the second guard on read.
//!
//! **File order is list order** (§3.1, §3.3): the vectors here preserve it and
//! nothing in this module ever sorts. The *writer invariants* (unique ids,
//! urgent-before-normal, link integrity, …) are validation, not this file —
//! they live in [`validate`], the milestone's slice 002.

mod validate;

pub use validate::{sub_depth, QueueRefusal};

use serde::{Deserialize, Serialize};

/// The schema version every file writes and the only version parsing accepts.
/// Bump only with a migration: a reader of the old build refuses the new file
/// fail-closed rather than misreading it.
pub const SCHEMA_VERSION: u32 = 1;

/// `<garden>/growlight/backlog/queue.toml` — the live v2 list (§3.1).
pub const QUEUE_FILE: &str = "growlight/backlog/queue.toml";

/// `<garden>/growlight/backlog/queue-archive.toml` — finished + dropped rows,
/// which `after` links resolve against (§3.2).
pub const QUEUE_ARCHIVE_FILE: &str = "growlight/backlog/queue-archive.toml";

/// The milestones directory prefix; a milestone's state lives under
/// `milestones/<id>/` (§3.3).
pub const MILESTONES_DIR: &str = "growlight/backlog/milestones";

/// The `slices.toml` path for a milestone or sub-milestone (§3.3). A
/// sub-milestone passes `"<parent>/<sub-slug>"`.
pub fn slices_file(milestone: &str) -> String {
    format!("{MILESTONES_DIR}/{milestone}/slices.toml")
}

/// A v2-file read or write that failed. All failures are typed; there is no
/// fallback value and no lossy recovery.
#[derive(Debug, thiserror::Error)]
pub enum QueueV2Error {
    /// The TOML does not parse: a syntax error, a wrong type, a missing
    /// required field, an unknown field, or a value outside a closed
    /// vocabulary.
    #[error("invalid TOML: {0}")]
    InvalidToml(#[from] toml::de::Error),
    /// The file declares a schema version this build does not understand.
    #[error("unsupported schema {found} (this build writes {SCHEMA_VERSION})")]
    UnsupportedSchema { found: u32 },
    /// Serializing failed. Cannot happen for these shapes (every value is
    /// plain data), but a write path never unwraps.
    #[error("serialize: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// `growlight/backlog/queue.toml` (§3.1): the one global v2 list, two lanes in
/// file order. `projects` first, then `entries`; **file order is list order**,
/// so nothing here sorts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueToml {
    /// Must be [`SCHEMA_VERSION`]; [`QueueToml::parse`] refuses anything else.
    pub schema: u32,
    #[serde(rename = "project")]
    pub projects: Vec<Project>,
    #[serde(rename = "entry")]
    pub entries: Vec<Entry>,
}

/// A `[[project]]` row (§3.1): a name bound to one repo and its merge branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// `[a-z0-9-]+` — the project name, referenced by entries' `project`.
    pub name: String,
    /// A local path (`~` allowed) or `host:path` (§1, §8 remote proxy).
    pub repo: String,
    /// The branch merges land on.
    pub main: String,
}

/// An entry's `kind` (§1, §3.1): one milestone, task or restack in the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A milestone with `slices.toml` + `slices/` under `milestones/<id>/`.
    Milestone,
    /// A standalone unit: the doc at `tasks/NNN-<slug>.md` is the work.
    Task,
    /// A stack-repair run generated by growlightd (§8). Always urgent, no
    /// branch of its own.
    Restack,
}

/// An entry's `lane` (§2): the urgent lane always drains first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Urgent,
    Normal,
}

/// An entry's `status` (§2). `done` and `dropped` live in the archive only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    Queued,
    Active,
    Paused,
    Blocked,
    Deferred,
}

/// A `[[entry]]` row (§3.1) — exactly the spec's field set, every field
/// required and written on every write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Unique id: a milestone's dir name, or a task's/restack's NNN. Unique
    /// across the live file and the archive (writer invariant, slice 002).
    pub id: String,
    pub kind: EntryKind,
    pub title: String,
    /// The owning [`Project::name`].
    pub project: String,
    pub lane: Lane,
    pub status: EntryStatus,
    /// Ids that must be finished (archived `done`) before this entry is
    /// eligible (§2). Links only order the list; they have no git meaning.
    pub after: Vec<String>,
    /// Enqueue time, UTC, `YYYY-MM-DDTHH:MM:SSZ` (§3.1 example). The writer
    /// stamps it; this module treats it as an opaque string.
    pub added: String,
    /// Set at enqueue: `feat/<id>` for milestones, `fix/<id>` for tasks, `""`
    /// for a restack (§8).
    pub branch: String,
    /// Set at first claim: the entry whose branch this was cut from; `""`
    /// means `main` (§8).
    pub parent: String,
    /// Set at first claim: the commit cut from (local) or the parent branch
    /// name (remote) (§8). `""` = never claimed.
    pub base: String,
    /// First-claim time, UTC; orders the stack (§8). `""` = never claimed.
    pub claimed: String,
    /// Consecutive follow-ups — task, restack and a milestone's close-out
    /// only (§7); slices keep theirs in `slices.toml`.
    pub follow_ups: u64,
}

/// The archive's outcome (§3.2): `done` satisfies `after` links, `dropped`
/// satisfies none (a `dropped` entry never satisfies a link — §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalStatus {
    Done,
    Dropped,
}

/// `growlight/backlog/queue-archive.toml` (§3.2): rows that left the list,
/// appended in the order they left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueArchiveToml {
    /// Must be [`SCHEMA_VERSION`].
    pub schema: u32,
    #[serde(rename = "entry")]
    pub entries: Vec<ArchivedEntry>,
}

/// One archived row (§3.2): the entry's row — moved, not copied — plus
/// `finished`, `final_status` and an optional `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedEntry {
    /// The entry's own row, flattened into this table so the archive row is
    /// literally "the entry fields + the archive fields" (§3.2). Flatten is
    /// why this struct alone cannot `deny_unknown_fields` (serde forbids the
    /// pair); see the module docs.
    #[serde(flatten)]
    pub row: Entry,
    /// When the entry left the list, UTC.
    pub finished: String,
    /// The outcome: `done` or `dropped`.
    #[serde(rename = "final_status")]
    pub final_status: FinalStatus,
    /// `queue_drop`'s reason. Only a `dropped` row carries one; a `done` row
    /// omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A milestone's `slices.toml` (§3.3): the slice + sub-milestone order, in
/// file order. Tasks and restacks have no `slices.toml` (§4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlicesToml {
    /// Must be [`SCHEMA_VERSION`].
    pub schema: u32,
    /// The owning entry id; a sub-milestone uses `"<parent>/<sub-slug>"`.
    pub milestone: String,
    #[serde(rename = "item")]
    pub items: Vec<SliceItem>,
}

/// A slice item's `kind` (§3.3): a slice of this milestone, or a nested
/// sub-milestone holding its own slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SliceKind {
    Slice,
    Sub,
}

/// A slice item's `status` (§3.3, §7): `split` means the remaining work moved
/// into a sub-milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SliceStatus {
    Queued,
    Active,
    Done,
    Split,
    Blocked,
    Deferred,
}

/// A `[[item]]` row (§3.3). File order is slice order; the `NNN-` filename
/// number is a stable id only, never order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SliceItem {
    pub kind: SliceKind,
    /// `slice`: the `NNN` of `slices/NNN-<slug>.md`; `sub`: the sub-milestone
    /// slug.
    pub id: String,
    pub status: SliceStatus,
    /// Slice only (§3.3): consecutive follow-ups, reset to 0 on done. A `sub`
    /// item omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_ups: Option<u64>,
}

impl QueueToml {
    /// A queue file with `schema = 1` and the given rows, in the given order.
    pub fn new(projects: Vec<Project>, entries: Vec<Entry>) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            projects,
            entries,
        }
    }

    /// Parse fail-closed: malformed TOML, a missing or unknown field, and any
    /// `schema != 1` are all typed errors — never a partial read.
    pub fn parse(raw: &str) -> Result<Self, QueueV2Error> {
        let parsed: Self = toml::from_str(raw)?;
        check_schema(parsed.schema)?;
        Ok(parsed)
    }

    /// Render this file as TOML. Also refuses a `schema != 1` (a file we could
    /// not re-read is never written).
    pub fn to_toml(&self) -> Result<String, QueueV2Error> {
        check_schema(self.schema)?;
        Ok(toml::to_string_pretty(self)?)
    }
}

impl QueueArchiveToml {
    /// An archive file with `schema = 1` and the given rows, in the given
    /// order.
    pub fn new(entries: Vec<ArchivedEntry>) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            entries,
        }
    }

    /// Parse fail-closed, exactly as [`QueueToml::parse`].
    pub fn parse(raw: &str) -> Result<Self, QueueV2Error> {
        let parsed: Self = toml::from_str(raw)?;
        check_schema(parsed.schema)?;
        Ok(parsed)
    }

    /// Render this file as TOML; refuses `schema != 1`.
    pub fn to_toml(&self) -> Result<String, QueueV2Error> {
        check_schema(self.schema)?;
        Ok(toml::to_string_pretty(self)?)
    }
}

impl SlicesToml {
    /// A slices file with `schema = 1` for the given milestone, in the given
    /// order.
    pub fn new(milestone: String, items: Vec<SliceItem>) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            milestone,
            items,
        }
    }

    /// Parse fail-closed, exactly as [`QueueToml::parse`].
    pub fn parse(raw: &str) -> Result<Self, QueueV2Error> {
        let parsed: Self = toml::from_str(raw)?;
        check_schema(parsed.schema)?;
        Ok(parsed)
    }

    /// Render this file as TOML; refuses `schema != 1`.
    pub fn to_toml(&self) -> Result<String, QueueV2Error> {
        check_schema(self.schema)?;
        Ok(toml::to_string_pretty(self)?)
    }
}

fn check_schema(schema: u32) -> Result<(), QueueV2Error> {
    if schema == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(QueueV2Error::UnsupportedSchema { found: schema })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The §3.1 example, verbatim: one project and the folder-grants entry with
    // every field. It doubles as the spec-fidelity fixture.
    const SPEC_QUEUE: &str = r#"schema = 1

[[project]]
name = "softfig"
repo = "~/projects/software-config_garden/codebase/main"
main = "main"

[[entry]]
id         = "folder-grants"
kind       = "milestone"
title      = "Folder grants — per-item allowed folders for fleet members"
project    = "softfig"
lane       = "normal"
status     = "queued"
after      = []
added      = "2026-10-11T15:04:00Z"
branch     = "feat/folder-grants"
parent     = ""
base       = ""
claimed    = ""
follow_ups = 0
"#;

    // The §3.3 example, verbatim.
    const SPEC_SLICES: &str = r#"schema = 1
milestone = "folder-grants"

[[item]]
kind       = "slice"
id         = "001"
status     = "done"
follow_ups = 0
"#;

    fn entry(id: &str) -> Entry {
        Entry {
            id: id.to_string(),
            kind: EntryKind::Milestone,
            title: format!("{id} title"),
            project: "softfig".to_string(),
            lane: Lane::Normal,
            status: EntryStatus::Queued,
            after: vec![],
            added: "2026-10-11T15:04:00Z".to_string(),
            branch: format!("feat/{id}"),
            parent: String::new(),
            base: String::new(),
            claimed: String::new(),
            follow_ups: 0,
        }
    }

    fn item(kind: SliceKind, id: &str, status: SliceStatus) -> SliceItem {
        SliceItem {
            kind,
            id: id.to_string(),
            status,
            follow_ups: (kind == SliceKind::Slice).then_some(0),
        }
    }

    #[test]
    fn spec_queue_example_parses_exactly() {
        let q = QueueToml::parse(SPEC_QUEUE).expect("the §3.1 example must parse");
        assert_eq!(q.schema, 1);
        assert_eq!(q.projects.len(), 1);
        assert_eq!(q.projects[0].name, "softfig");
        assert_eq!(q.projects[0].main, "main");
        assert_eq!(q.entries.len(), 1);
        let e = &q.entries[0];
        assert_eq!(e.id, "folder-grants");
        assert_eq!(e.kind, EntryKind::Milestone);
        assert_eq!(e.lane, Lane::Normal);
        assert_eq!(e.status, EntryStatus::Queued);
        assert!(e.after.is_empty());
        assert_eq!(e.added, "2026-10-11T15:04:00Z");
        assert_eq!(e.branch, "feat/folder-grants");
        assert_eq!(e.parent, "");
        assert_eq!(e.base, "");
        assert_eq!(e.claimed, "");
        assert_eq!(e.follow_ups, 0);
    }

    #[test]
    fn spec_slices_example_parses_exactly() {
        let s = SlicesToml::parse(SPEC_SLICES).expect("the §3.3 example must parse");
        assert_eq!(s.schema, 1);
        assert_eq!(s.milestone, "folder-grants");
        assert_eq!(s.items.len(), 1);
        let i = &s.items[0];
        assert_eq!(i.kind, SliceKind::Slice);
        assert_eq!(i.id, "001");
        assert_eq!(i.status, SliceStatus::Done);
        assert_eq!(i.follow_ups, Some(0));
    }

    #[test]
    fn queue_round_trip_preserves_file_order() {
        let q = QueueToml::new(
            vec![
                Project {
                    name: "softfig".into(),
                    repo: "~/projects/software-config_garden/codebase/main".into(),
                    main: "main".into(),
                },
                Project {
                    name: "roadeye".into(),
                    repo: "phone:roadeye".into(),
                    main: "main".into(),
                },
            ],
            vec![
                {
                    let mut e = entry("urgent-one");
                    e.lane = Lane::Urgent;
                    e
                },
                entry("normal-a"),
                entry("normal-b"),
            ],
        );
        let text = q.to_toml().expect("serialize");
        let back = QueueToml::parse(&text).expect("re-parse");
        assert_eq!(back, q, "round-trip must be exact");

        // File order is list order: nothing reorders, so the ids appear in
        // the serialized text in the same order they were given.
        let a = text.find("\"normal-a\"").expect("entry normal-a present");
        let b = text.find("\"normal-b\"").expect("entry normal-b present");
        assert!(a < b, "normal-a precedes normal-b in file order");
        let softfig = text.find("\"softfig\"").expect("project softfig present");
        let roadeye = text.find("\"roadeye\"").expect("project roadeye present");
        assert!(softfig < roadeye, "project order preserved");

        // Serialization always writes schema = 1.
        assert!(text.starts_with("schema = 1\n"), "schema first, = 1");
        // And the tables keep their spec names.
        assert!(text.contains("[[project]]") && text.contains("[[entry]]"));
    }

    #[test]
    fn archive_round_trip_done_dropped_reason() {
        let arch = QueueArchiveToml::new(vec![
            ArchivedEntry {
                row: {
                    let mut e = entry("done-one");
                    e.status = EntryStatus::Active;
                    e
                },
                finished: "2026-10-11T15:40:00Z".into(),
                final_status: FinalStatus::Done,
                reason: None,
            },
            ArchivedEntry {
                row: entry("dropped-two"),
                finished: "2026-10-11T16:00:00Z".into(),
                final_status: FinalStatus::Dropped,
                reason: Some("superseded".into()),
            },
        ]);
        let text = arch.to_toml().expect("serialize");
        let back = QueueArchiveToml::parse(&text).expect("re-parse");
        assert_eq!(back, arch);

        // A done row omits `reason`; a dropped row carries it; the entry's
        // own fields sit flat at the row's top level (the §3.2 "moves its
        // row here" shape).
        let done_block = text.split("[[entry]]").nth(1).expect("first row");
        assert!(!done_block.contains("reason"), "done rows omit reason");
        assert!(done_block.contains("final_status = \"done\""));
        assert!(done_block.contains("id = \"done-one\""));
        let dropped_block = text.split("[[entry]]").nth(2).expect("second row");
        assert!(dropped_block.contains("reason = \"superseded\""));
        assert!(dropped_block.contains("final_status = \"dropped\""));
    }

    #[test]
    fn slices_round_trip_sub_omits_follow_ups() {
        let s = SlicesToml::new(
            "folder-grants".into(),
            vec![
                item(SliceKind::Slice, "001", SliceStatus::Done),
                item(SliceKind::Slice, "002", SliceStatus::Queued),
                item(SliceKind::Sub, "fid-pam", SliceStatus::Queued),
            ],
        );
        let text = s.to_toml().expect("serialize");
        let back = SlicesToml::parse(&text).expect("re-parse");
        assert_eq!(back, s);

        let sub_block = text.split("[[item]]").nth(3).expect("sub row");
        assert!(
            !sub_block.contains("follow_ups"),
            "sub items omit follow_ups (§3.3 'slice only')"
        );
    }

    #[test]
    fn schema_mismatch_fails_closed_on_all_three_files() {
        let q2 = SPEC_QUEUE.replace("schema = 1", "schema = 2");
        assert!(matches!(
            QueueToml::parse(&q2),
            Err(QueueV2Error::UnsupportedSchema { found: 2 })
        ));
        assert!(matches!(
            QueueToml::parse(&SPEC_QUEUE.replace("schema = 1", "schema = 0")),
            Err(QueueV2Error::UnsupportedSchema { found: 0 })
        ));

        let a1 = QueueArchiveToml::new(vec![ArchivedEntry {
            row: entry("x"),
            finished: "2026-10-11T15:40:00Z".into(),
            final_status: FinalStatus::Done,
            reason: None,
        }]);
        let a2 = a1.to_toml().unwrap().replace("schema = 1", "schema = 7");
        assert!(matches!(
            QueueArchiveToml::parse(&a2),
            Err(QueueV2Error::UnsupportedSchema { found: 7 })
        ));

        let s2 = SPEC_SLICES.replace("schema = 1", "schema = 99");
        assert!(matches!(
            SlicesToml::parse(&s2),
            Err(QueueV2Error::UnsupportedSchema { found: 99 })
        ));
    }

    #[test]
    fn malformed_toml_fails() {
        for raw in [
            "schema = ",                       // truncated
            "not toml {{{",                    // garbage
            "schema = 1\n[[entry]\nid = 1\n",  // wrong type for id
        ] {
            assert!(
                matches!(QueueToml::parse(raw), Err(QueueV2Error::InvalidToml(_))),
                "must refuse malformed TOML: {raw:?}"
            );
        }
    }

    #[test]
    fn missing_required_fields_fail() {
        // No `[[entry]]` table at all — the field is required, not defaulted.
        assert!(matches!(
            QueueToml::parse("schema = 1\n"),
            Err(QueueV2Error::InvalidToml(_))
        ));
        // An entry missing `title` (and nothing else).
        let no_title = SPEC_QUEUE.replace("title      = \"Folder grants — per-item allowed folders for fleet members\"\n", "");
        assert!(matches!(
            QueueToml::parse(&no_title),
            Err(QueueV2Error::InvalidToml(_))
        ));
        // An item missing `status`.
        let no_status = SPEC_SLICES.replace("status     = \"done\"\n", "");
        assert!(matches!(
            SlicesToml::parse(&no_status),
            Err(QueueV2Error::InvalidToml(_))
        ));
    }

    #[test]
    fn unknown_vocabulary_values_fail() {
        for bad_kind in ["mileston", "Milestone", "task-force"] {
            let raw = SPEC_QUEUE.replace("kind       = \"milestone\"", &format!("kind       = \"{bad_kind}\""));
            assert!(
                matches!(QueueToml::parse(&raw), Err(QueueV2Error::InvalidToml(_))),
                "kind {bad_kind:?} must be refused"
            );
        }
        let bad_status = SPEC_QUEUE.replace("status     = \"queued\"", "status     = \"QUEUED\"");
        assert!(matches!(
            QueueToml::parse(&bad_status),
            Err(QueueV2Error::InvalidToml(_))
        ));
    }

    #[test]
    fn unknown_fields_are_refused() {
        // A misspelled hand-edited field must fail closed, not be carried.
        let stray_entry_key = SPEC_QUEUE.replace("follow_ups = 0\n", "follow_ups = 0\nstatusz    = \"queued\"\n");
        assert!(matches!(
            QueueToml::parse(&stray_entry_key),
            Err(QueueV2Error::InvalidToml(_))
        ));
        let stray_top_key = SPEC_QUEUE.replace("[[project]]", "foo = 1\n\n[[project]]");
        assert!(matches!(
            QueueToml::parse(&stray_top_key),
            Err(QueueV2Error::InvalidToml(_))
        ));
        let stray_item_key = SPEC_SLICES.replace("follow_ups = 0\n", "follow_ups = 0\nkindx      = \"slice\"\n");
        assert!(matches!(
            SlicesToml::parse(&stray_item_key),
            Err(QueueV2Error::InvalidToml(_))
        ));
    }

    #[test]
    fn writing_a_non_unit_schema_is_refused() {
        // to_toml must never emit a schema this build couldn't re-read.
        let mut q = QueueToml::new(vec![], vec![entry("x")]);
        q.schema = 2;
        assert!(matches!(
            q.to_toml(),
            Err(QueueV2Error::UnsupportedSchema { found: 2 })
        ));
    }

    #[test]
    fn constructors_stamp_the_current_schema() {
        assert_eq!(QueueToml::new(vec![], vec![]).schema, SCHEMA_VERSION);
        assert_eq!(QueueArchiveToml::new(vec![]).schema, SCHEMA_VERSION);
        assert_eq!(
            SlicesToml::new("m".into(), vec![]).schema,
            SCHEMA_VERSION
        );
    }

    #[test]
    fn spec_examples_pass_validation() {
        // The verbatim §3.1 and §3.3 examples must be valid files: slice
        // 002's invariants accept what the spec itself writes.
        let q = QueueToml::parse(SPEC_QUEUE).expect("the §3.1 example parses");
        q.validate(&QueueArchiveToml::new(vec![]))
            .expect("the §3.1 example is valid");
        let s = SlicesToml::parse(SPEC_SLICES).expect("the §3.3 example parses");
        s.validate("folder-grants")
            .expect("the §3.3 example is valid");
    }
}
