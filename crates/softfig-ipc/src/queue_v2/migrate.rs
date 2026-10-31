//! The queue v2 **migration converter** (spec-growlight-queue §11, milestone
//! `queue-v2-migrate`): the legacy backlog — the default + named queue tables
//! in `growlight/backlog/CLAUDE.md`, the item docs and their slice folders, and
//! the in-flight member batons — converted into the v2 files of §3.1–§3.3 plus
//! the §3.6 per-entry batons.
//!
//! Pure, in three steps, so the dry run and the apply compute the same plan:
//!
//! 1. [`LegacyFiles`] — the caller's snapshot of the garden files the converter
//!    reads (the CLI reads them off the mount for `--dry-run`; keeperd reads its
//!    own working tree for the apply op). Nothing here touches a filesystem.
//! 2. [`LegacyBacklog`] — the legacy model parsed out of it (slice 002).
//! 3. [`MigrationPlan`] — the v2 files, the baton moves and the
//!    [`JudgmentCall`] list, mapped from the model under the owner's
//!    [`Answers`] (slice 003).
//!
//! **It never guesses.** A construct that does not map with certainty becomes
//! a [`JudgmentCall`] with a stable [`CallKey`], its class, the evidence, and a
//! proposed default. The owner settles calls in the answers file; the apply is
//! refused while any call is open. A construct the converter cannot represent
//! at all is a [`Refusal`]; any refusal fails the whole plan.
//!
//! **It never flips `queue = "v2"`** and never edits the legacy tables. The
//! apply refusals (fleet armed, switch already `v2`, v2 files present, legacy
//! tables changed since the dry run) are keeperd's, at write time — see
//! [`ApplyRefusal`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{QueueArchiveToml, QueueToml, SlicesToml};
use crate::backlog_doc::{self, BACKLOG_DOC, DEFAULT_QUEUE, MILESTONES_DIR, TASKS_DIR};
use crate::{baton, item_meta};

/// The answers-file schema version [`Answers`] accepts.
pub const ANSWERS_SCHEMA_VERSION: u32 = 1;

/// The caller's read-only snapshot of every garden file the converter reads,
/// keyed by garden-relative path. Directory listings are implied by the keys:
/// a milestone's slices are the `growlight/backlog/milestones/<id>/slices/NNN-*.md`
/// keys present. Batons are runtime state outside the garden, so they ride
/// separately, keyed by their path under the growlight runtime dir
/// (`baton.md`, `agents/<id>/baton.md`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyFiles {
    /// Garden-relative path → content (the backlog doc, item docs, slice docs).
    pub garden: BTreeMap<String, String>,
    /// Runtime-relative baton path → content.
    pub batons: BTreeMap<String, String>,
}

/// The legacy backlog, parsed (slice 002). File order is kept everywhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyBacklog {
    /// The queues: `default` first, then the registry's named queues in
    /// registry order.
    pub queues: Vec<LegacyQueue>,
    /// The in-flight batons found, in path order.
    pub batons: Vec<LegacyBaton>,
    /// `softfig:queue:<name>` tables with no registry row, in doc order. Every
    /// legacy reader ignores them, so their rows are invisible to the loop
    /// today; the mapping must not drop them silently either.
    pub orphan_tables: Vec<String>,
}

/// One legacy queue: its registry repo cell (none for `default`) and its rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyQueue {
    pub name: String,
    /// The registry's `repo` cell, verbatim (it may carry trailing prose).
    pub repo: Option<String>,
    pub items: Vec<LegacyItem>,
}

/// One queue-table row plus what its item doc declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyItem {
    pub id: String,
    /// The `type` cell, verbatim (`milestone` / `task`; anything else is a call).
    pub kind: String,
    /// The `title` cell, verbatim — `[blocked on X]` tags still in it.
    pub title: String,
    /// The title's bracket tags (`blocked on X`, `human/semi-auto`), trimmed,
    /// in title order. A markdown link's `[text](…)` is not a tag.
    pub tags: Vec<String>,
    /// The `status` cell, verbatim.
    pub status: String,
    /// Every item doc found for the id, in path order: a milestone's
    /// `milestones/<id>/CLAUDE.md`, a task's `tasks/<id>-*.md`. Exactly one is
    /// mechanical; none or several is a call.
    pub docs: Vec<String>,
    /// The metadata the doc declares (`None` = the line is absent). Read only
    /// when exactly one doc was found.
    pub meta: ItemMeta,
    /// `## Branch policy` section text, verbatim, when present (one doc only).
    pub branch_policy: Option<String>,
    /// Slice numbers (`NNN` of `slices/NNN-*.md`), in filename-number order.
    /// A repeated number is kept twice; v2 cannot represent it.
    pub slices: Vec<String>,
    /// Sub-milestone dirs under `milestones/<id>/subs/`, in path order. Legacy
    /// never writes one, so any is a refusal.
    pub subs: Vec<String>,
}

/// The item-doc metadata lines the mapping reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemMeta {
    pub fleet: Option<String>,
    pub not_before: Option<String>,
    pub worktree: Option<String>,
    pub model: Option<String>,
}

/// One runtime baton naming an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyBaton {
    /// Runtime-relative path the baton was read from.
    pub path: String,
    /// The head's `item:` value (a baton naming no item is not collected).
    pub item: String,
    /// The head's `status:` value, `None` when the head carries none.
    pub status: Option<String>,
}

/// Why [`read_legacy`] could not build a model at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// The snapshot has no [`BACKLOG_DOC`].
    #[error("the snapshot has no {BACKLOG_DOC}")]
    NoBacklogDoc,
}

/// Parse the legacy backlog out of `files` (slice 002): the default table,
/// then each registry queue's table in registry order, every row joined to its
/// item doc, metadata, branch policy and slice folder, plus the member batons.
/// Pure and total over a present backlog doc: everything odd is recorded for
/// the mapping to judge, never resolved here.
pub fn read_legacy(files: &LegacyFiles) -> Result<LegacyBacklog, ReadError> {
    let doc = files.garden.get(BACKLOG_DOC).ok_or(ReadError::NoBacklogDoc)?;
    let registry = backlog_doc::registry_rows(doc);
    let table = |tag: &str| backlog_doc::region_body(doc, tag).unwrap_or_default();

    let mut queues = vec![LegacyQueue {
        name: DEFAULT_QUEUE.to_string(),
        repo: None,
        items: read_items(files, &table("queue")),
    }];
    for (name, repo) in &registry {
        queues.push(LegacyQueue {
            name: name.clone(),
            repo: Some(repo.clone()),
            items: read_items(files, &table(&format!("queue:{name}"))),
        });
    }

    Ok(LegacyBacklog {
        queues,
        batons: read_batons(&files.batons),
        orphan_tables: orphan_tables(doc, &registry),
    })
}

fn read_items(files: &LegacyFiles, body: &str) -> Vec<LegacyItem> {
    backlog_doc::item_table(body)
        .into_iter()
        .map(|row| {
            let docs = item_docs(&files.garden, &row.id);
            let doc = match docs.as_slice() {
                [only] => files.garden.get(only).map(String::as_str),
                _ => None,
            };
            let field = |key| doc.and_then(|d| item_meta::field(d, key)).map(str::to_string);
            let meta = ItemMeta {
                fleet: field(item_meta::FLEET),
                not_before: field(item_meta::NOT_BEFORE),
                worktree: field(item_meta::WORKTREE),
                model: field(item_meta::MODEL),
            };
            let dir = format!("{MILESTONES_DIR}/{}/", row.id);
            LegacyItem {
                tags: title_tags(&row.title),
                branch_policy: doc.and_then(|d| section(d, "Branch policy")),
                slices: slice_numbers(&files.garden, &dir),
                subs: sub_dirs(&files.garden, &dir),
                docs,
                meta,
                id: row.id,
                kind: row.item_type,
                title: row.title,
                status: row.status,
            }
        })
        .collect()
}

/// Every doc path that is `id`'s own doc: `tasks/<id>-*.md` for a task id,
/// `milestones/<id>/CLAUDE.md` otherwise (the [`backlog_doc::is_task_id`] split).
fn item_docs(garden: &BTreeMap<String, String>, id: &str) -> Vec<String> {
    if !backlog_doc::is_task_id(id) {
        let path = format!("{MILESTONES_DIR}/{id}/CLAUDE.md");
        return garden.contains_key(&path).then_some(path).into_iter().collect();
    }
    let prefix = format!("{TASKS_DIR}/{id}-");
    garden
        .keys()
        .filter(|path| {
            path.strip_prefix(&prefix)
                .is_some_and(|name| name.ends_with(".md") && !name.contains('/'))
        })
        .cloned()
        .collect()
}

/// The `NNN` of every `<dir>slices/NNN-*.md`, sorted by number (ties by path).
fn slice_numbers(garden: &BTreeMap<String, String>, dir: &str) -> Vec<String> {
    let prefix = format!("{dir}slices/");
    let mut slices: Vec<(u64, &str, String)> = garden
        .keys()
        .filter_map(|path| {
            let name = path.strip_prefix(&prefix)?;
            if name.contains('/') || !name.ends_with(".md") {
                return None;
            }
            let (number, _) = name.split_once('-')?;
            if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((number.parse().ok()?, path.as_str(), number.to_string()))
        })
        .collect();
    slices.sort();
    slices.into_iter().map(|(_, _, number)| number).collect()
}

/// The distinct first path segments under `<dir>subs/`.
fn sub_dirs(garden: &BTreeMap<String, String>, dir: &str) -> Vec<String> {
    let prefix = format!("{dir}subs/");
    let mut subs: Vec<String> = garden
        .keys()
        .filter_map(|path| path.strip_prefix(&prefix)?.split('/').next())
        .filter(|slug| !slug.is_empty())
        .map(str::to_string)
        .collect();
    subs.dedup(); // the keys are sorted, so a dir's files are adjacent
    subs
}

/// The `[…]` tags in a title, in order; a `[text](…)` markdown link is skipped.
fn title_tags(title: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut rest = title;
    while let Some(open) = rest.find('[') {
        let Some(len) = rest[open + 1..].find(']') else {
            break;
        };
        let close = open + 1 + len;
        if !rest[close + 1..].starts_with('(') {
            tags.push(rest[open + 1..close].trim().to_string());
        }
        rest = &rest[close + 1..];
    }
    tags
}

/// The body of the first `## <heading>` section outside fenced code, up to the
/// next `#` / `##` heading, blank padding trimmed. `None` when absent.
fn section(doc: &str, heading: &str) -> Option<String> {
    let mut fenced = false;
    let mut body: Option<Vec<&str>> = None;
    for line in doc.lines() {
        let fence = line.trim_start().starts_with("```") || line.trim_start().starts_with("~~~");
        if fence {
            fenced = !fenced;
        }
        let level = (!fenced && !fence)
            .then(|| line.strip_prefix("# ").or_else(|| line.strip_prefix("## ")))
            .flatten();
        match (&mut body, level) {
            (None, Some(title)) if line.starts_with("## ") && title.trim() == heading => {
                body = Some(Vec::new());
            }
            (Some(_), Some(_)) => break,
            (Some(lines), None) => lines.push(line),
            _ => {}
        }
    }
    let lines = body?;
    Some(lines.join("\n").trim().to_string())
}

/// The batons at `baton.md` and `agents/<id>/baton.md` that name an item, in
/// path order. Parked copies and other runtime files are not batons.
fn read_batons(batons: &BTreeMap<String, String>) -> Vec<LegacyBaton> {
    batons
        .iter()
        .filter(|(path, _)| {
            *path == "baton.md"
                || path
                    .strip_prefix("agents/")
                    .and_then(|rest| rest.strip_suffix("/baton.md"))
                    .is_some_and(|member| !member.is_empty() && !member.contains('/'))
        })
        .filter_map(|(path, content)| {
            let head = baton::parse_baton(content);
            Some(LegacyBaton { path: path.clone(), item: head.item?, status: head.status })
        })
        .collect()
}

/// The `softfig:queue:<name>` region names with no registry row, in doc order.
fn orphan_tables(doc: &str, registry: &[(String, String)]) -> Vec<String> {
    doc.lines()
        .filter_map(|line| line.trim().strip_prefix("<!-- softfig:queue:")?.strip_suffix(" -->"))
        .filter(|name| !registry.iter().any(|(registered, _)| registered == name))
        .map(str::to_string)
        .collect()
}

/// The owner's settlements, read from the answers file (`--answers <toml>`).
/// A class-wide answer settles every call of that class; a per-key answer
/// overrides it for one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answers {
    pub schema: u32,
    /// Class → the answer for every call of that class.
    #[serde(default)]
    pub class: BTreeMap<CallClass, String>,
    /// [`CallKey`] (rendered) → the answer for that one call.
    #[serde(default)]
    pub call: BTreeMap<String, String>,
}

/// The closed list of judgment-call classes (the milestone doc's `## Mapping`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallClass {
    /// How the per-queue orders interleave into the one global list.
    ListOrder,
    /// A project's `repo`: no registry cell (`default`), trailing prose, or a
    /// value `RepoLocality` calls ambiguous.
    ProjectRepo,
    /// A project's `main` branch (legacy records none).
    ProjectMain,
    /// Two projects naming one repository under different spellings.
    SameRepo,
    /// A `type` or `status` cell outside the legacy vocabulary.
    UnknownCell,
    /// An item id that appears in more than one queue table.
    DuplicateId,
    /// A live item with no item doc, or more than one.
    ItemDoc,
    /// A `[blocked on X]` tag whose X names no known item.
    BlockedOn,
    /// `## Branch policy` prose that names no single branch, or a branch other
    /// than the v2 default (`feat/<id>` / `fix/<id>`).
    Branch,
    /// A started item's `parent` / `base` the prose does not state.
    StackBase,
    /// A started milestone's per-slice progress (legacy records none).
    SliceProgress,
    /// A `> Not before:` value that does not parse.
    NotBefore,
    /// A `> Model:` line the v2 resolver refuses (a comma list before the flip).
    Model,
    /// More than one `active` normal-lane entry for one repo (§3.1 invariant).
    ActivePerRepo,
    /// A baton naming an item that is not live, or two batons naming one item.
    Baton,
}

/// A judgment call's stable key: class + subject (`<class>:<subject>`), the
/// key the answers file's `call` table uses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallKey {
    pub class: CallClass,
    /// The entry id, project name, or baton path the call is about.
    pub subject: String,
}

/// One thing the converter will not decide alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgmentCall {
    pub key: CallKey,
    /// What was found, verbatim enough to settle the call without opening docs.
    pub evidence: String,
    /// The answer the converter proposes; never applied unless the owner
    /// writes it.
    pub proposed: String,
    /// The settled answer, when the answers file carries one.
    pub settled: Option<String>,
}

/// A construct the v2 model cannot represent; any refusal fails the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub subject: String,
    pub reason: String,
}

/// A runtime baton copy: `from` (runtime-relative) → `entries/<entry>/baton.md`.
/// A copy, never a move: the legacy baton stays where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatonMove {
    pub from: String,
    pub entry: String,
}

/// The whole conversion: the v2 files, the baton copies, every judgment call
/// (settled or open) and every refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub queue: QueueToml,
    pub archive: QueueArchiveToml,
    /// `(milestone id, its slices.toml)`, in list order.
    pub slices: Vec<(String, SlicesToml)>,
    pub batons: Vec<BatonMove>,
    pub calls: Vec<JudgmentCall>,
    pub refusals: Vec<Refusal>,
}

impl MigrationPlan {
    /// The calls the answers file has not settled. The apply needs none.
    pub fn open_calls(&self) -> impl Iterator<Item = &JudgmentCall> {
        self.calls.iter().filter(|c| c.settled.is_none())
    }

    /// Whether keeperd may write this plan: no refusal and no open call.
    pub fn applicable(&self) -> bool {
        self.refusals.is_empty() && self.open_calls().next().is_none()
    }
}

/// Why keeperd refuses the apply op (slice 005). Checked before anything is
/// written; the legacy tables are never edited either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyRefusal {
    /// `config/growlight.toml` has `fleet_enabled = true`.
    FleetArmed,
    /// `config/growlight.toml` already says `queue = "v2"`.
    SwitchIsV2,
    /// `queue.toml`, `queue-archive.toml` or a `slices.toml` already exists.
    V2FilesPresent,
    /// The backlog doc's version is not the one the dry run read (CAS).
    LegacyChanged,
    /// The recomputed plan has refusals or open calls.
    NotApplicable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(garden: &[(&str, &str)], batons: &[(&str, &str)]) -> LegacyFiles {
        let map = |pairs: &[(&str, &str)]| {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        LegacyFiles { garden: map(garden), batons: map(batons) }
    }

    fn table(tag: &str, rows: &[(&str, &str, &str)]) -> String {
        let mut s = format!("<!-- softfig:{tag} -->\n\n| # | id | type | title | status |\n|---|---|---|---|---|");
        for (i, (id, kind, title)) in rows.iter().enumerate() {
            s.push_str(&format!("\n| {} | {id} | {kind} | {title} | queued |", i + 1));
        }
        s + &format!("\n\n<!-- /softfig:{tag} -->\n")
    }

    #[test]
    fn no_backlog_doc_is_an_error() {
        assert_eq!(read_legacy(&LegacyFiles::default()), Err(ReadError::NoBacklogDoc));
    }

    #[test]
    fn task_docs_are_every_numbered_file_and_meta_needs_exactly_one() {
        let doc = table("queue", &[("007", "task", "T"), ("008", "task", "T"), ("009", "task", "T")]);
        let read = read_legacy(&files(
            &[
                (BACKLOG_DOC, &doc),
                ("growlight/backlog/tasks/007-a.md", "> Fleet: no\n"),
                ("growlight/backlog/tasks/008-a.md", "> Fleet: no\n"),
                ("growlight/backlog/tasks/008-b.md", ""),
                ("growlight/backlog/tasks/0070-not-007.md", ""),
            ],
            &[],
        ))
        .unwrap();
        let items = &read.queues[0].items;
        assert_eq!(items[0].docs, vec!["growlight/backlog/tasks/007-a.md"]);
        assert_eq!(items[0].meta.fleet.as_deref(), Some("no"));
        assert_eq!(items[1].docs.len(), 2, "two docs for one number are both kept");
        assert_eq!(items[1].meta, ItemMeta::default(), "no meta is read from an ambiguous doc");
        assert!(items[2].docs.is_empty());
    }

    #[test]
    fn slices_sort_by_number_and_subs_and_orphan_tables_are_recorded() {
        let doc = table("queue", &[("m", "milestone", "M")]) + &table("queue:ghost", &[("g", "task", "G")]);
        let dir = "growlight/backlog/milestones/m";
        let read = read_legacy(&files(
            &[
                (BACKLOG_DOC, &doc),
                (&format!("{dir}/CLAUDE.md"), "# m\n"),
                (&format!("{dir}/slices/10-late.md"), ""),
                (&format!("{dir}/slices/002-b.md"), ""),
                (&format!("{dir}/slices/002-dup.md"), ""),
                (&format!("{dir}/slices/001-a.md"), ""),
                (&format!("{dir}/slices/notes.md"), ""),
                (&format!("{dir}/slices/+3-signed.md"), ""),
                (&format!("{dir}/subs/s1/CLAUDE.md"), ""),
                (&format!("{dir}/subs/s1/slices/001-x.md"), ""),
            ],
            &[],
        ))
        .unwrap();
        let m = &read.queues[0].items[0];
        assert_eq!(m.slices, vec!["001", "002", "002", "10"]);
        assert_eq!(m.subs, vec!["s1"]);
        assert_eq!(read.queues.len(), 1, "an unregistered table is not a queue");
        assert_eq!(read.orphan_tables, vec!["ghost"]);
    }

    #[test]
    fn title_tags_skip_links_and_keep_order() {
        assert_eq!(title_tags("[blocked on x] see [the doc](a.md) [human/semi-auto]"), vec![
            "blocked on x",
            "human/semi-auto"
        ]);
        assert!(title_tags("unclosed [tag").is_empty());
    }

    #[test]
    fn branch_policy_section_stops_at_the_next_heading_but_not_inside_a_fence() {
        let doc = "# t\n\n## Branch policy\n\nBranch `feat/x` off `main`.\n```\n## not a heading\n```\n\n## Next\nno";
        assert_eq!(
            section(doc, "Branch policy").as_deref(),
            Some("Branch `feat/x` off `main`.\n```\n## not a heading\n```")
        );
        assert_eq!(section(doc, "Missing"), None);
    }

    #[test]
    fn batons_are_root_and_member_batons_that_name_an_item() {
        let head = |item: &str| format!("---\nstatus: IN_PROGRESS\nitem: {item}\n---\n");
        let read = read_legacy(&files(&[(BACKLOG_DOC, "")], &[
            ("baton.md", &head("a")),
            ("agents/b/baton.md", &head("b")),
            ("agents/c/baton.md", "---\nstatus: IN_PROGRESS\n---\n"),
            ("agents/d/scratch/baton.md", &head("d")),
            ("baton.e.parked.md", &head("e")),
        ]))
        .unwrap();
        let named: Vec<_> = read.batons.iter().map(|b| (b.path.as_str(), b.item.as_str())).collect();
        assert_eq!(named, vec![("agents/b/baton.md", "b"), ("baton.md", "a")]);
        assert_eq!(read.batons[0].status.as_deref(), Some("IN_PROGRESS"));
    }
}
