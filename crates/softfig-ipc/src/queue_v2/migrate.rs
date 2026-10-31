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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::{
    ArchivedEntry, Entry, EntryKind, EntryStatus, FinalStatus, Lane, Project, QueueArchiveToml,
    QueueToml, RepoLocality, SliceItem, SliceKind, SliceStatus, SlicesToml,
};
use crate::backlog_doc::{self, BACKLOG_DOC, DEFAULT_QUEUE, MILESTONES_DIR, TASKS_DIR};
use crate::model_choice::{self, Declaration};
use crate::{baton, fleet, item_meta};

/// The v2 project the legacy `default` queue becomes (the milestone's
/// `## Mapping`; its repo and `main` are still calls).
pub const DEFAULT_PROJECT: &str = "softfig";

/// The `list_order` proposal: the `default` table, then the named queues in
/// registry order. Any other answer is a comma list of queue names.
pub const LIST_ORDER_PROPOSAL: &str = "default-then-registry";

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

impl CallClass {
    /// The class's answers-file name — its serde wire name.
    pub fn name(self) -> &'static str {
        match self {
            CallClass::ListOrder => "list_order",
            CallClass::ProjectRepo => "project_repo",
            CallClass::ProjectMain => "project_main",
            CallClass::SameRepo => "same_repo",
            CallClass::UnknownCell => "unknown_cell",
            CallClass::DuplicateId => "duplicate_id",
            CallClass::ItemDoc => "item_doc",
            CallClass::BlockedOn => "blocked_on",
            CallClass::Branch => "branch",
            CallClass::StackBase => "stack_base",
            CallClass::SliceProgress => "slice_progress",
            CallClass::NotBefore => "not_before",
            CallClass::Model => "model",
            CallClass::ActivePerRepo => "active_per_repo",
            CallClass::Baton => "baton",
        }
    }
}

impl fmt::Display for CallKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.class.name(), self.subject)
    }
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

/// Map the legacy model to the v2 files under the owner's `answers` (slice
/// 003), one `## Mapping` row at a time. `now` stamps `added` and an archived
/// row's `finished` (apply time; legacy keeps neither).
///
/// Pure and total: every construct maps, becomes a [`JudgmentCall`], or
/// becomes a [`Refusal`]. Where the files need a value to render, an open
/// call renders its proposal, so the dry run shows a whole plan; nothing
/// applies while a call is open ([`MigrationPlan::applicable`]). The one
/// exception is `stack_base`: an unsettled base stays empty, never proposed.
/// Archived (`done`) rows are history, so their branch, base and doc
/// metadata raise no calls.
///
/// The produced files go through v2's own `validate`; a failure is a
/// converter bug and lands as a refusal, never as a plan that could apply.
pub fn plan(legacy: &LegacyBacklog, answers: &Answers, now: &str) -> MigrationPlan {
    let mut p = Planner { answers, calls: Vec::new(), refusals: Vec::new() };
    if answers.schema != ANSWERS_SCHEMA_VERSION {
        p.refuse("answers", format!("schema {} (this build reads {ANSWERS_SCHEMA_VERSION})", answers.schema));
    }
    for name in &legacy.orphan_tables {
        p.refuse(
            &format!("queue:{name}"),
            "a `softfig:queue:<name>` table with no `## Queues` registry row; no legacy reader sees its rows, \
             so register the queue or remove the table first"
                .to_string(),
        );
    }

    let projects = plan_projects(&mut p, &legacy.queues);
    let order = list_order(&mut p, &legacy.queues);
    let known: BTreeSet<&str> =
        legacy.queues.iter().flat_map(|q| q.items.iter().map(|i| i.id.as_str())).collect();
    let owners = duplicate_owners(&mut p, &order);

    let mut entries = Vec::new();
    let mut archived = Vec::new();
    let mut slices = Vec::new();
    for queue in &order {
        for item in &queue.items {
            if owners.get(item.id.as_str()).is_some_and(|keep| *keep != queue.name) {
                continue;
            }
            let started_by_baton = legacy.batons.iter().any(|b| b.item == item.id);
            let ctx = ItemCtx { queue, known: &known, started_by_baton, now };
            match plan_item(&mut p, &ctx, item) {
                Planned::Live(entry, slice_file) => {
                    slices.extend(slice_file.map(|s| (entry.id.clone(), s)));
                    entries.push(entry);
                }
                Planned::Done(entry) => archived.push(ArchivedEntry {
                    row: entry,
                    finished: now.to_string(),
                    final_status: FinalStatus::Done,
                    reason: None,
                }),
                Planned::Skipped => {}
            }
        }
    }
    active_per_repo(&mut p, &projects, &mut entries);
    let batons = plan_batons(&mut p, &legacy.batons, &entries);

    let queue = QueueToml::new(projects, entries);
    let archive = QueueArchiveToml::new(archived);
    if let Err(refusal) = queue.validate(&archive) {
        p.refuse("queue.toml", format!("v2 validate refused the converted list (converter bug): {refusal}"));
    }
    for (id, file) in &slices {
        if let Err(refusal) = file.validate(id) {
            p.refuse(id, format!("v2 validate refused the converted slices.toml (converter bug): {refusal}"));
        }
    }
    MigrationPlan { queue, archive, slices, batons, calls: p.calls, refusals: p.refusals }
}

/// The call + refusal accumulator, and the one place an answer is looked up.
struct Planner<'a> {
    answers: &'a Answers,
    calls: Vec<JudgmentCall>,
    refusals: Vec<Refusal>,
}

impl Planner<'_> {
    /// Record a call and return its settled answer: the per-key answer, else
    /// the class answer, else `None`.
    fn call(&mut self, class: CallClass, subject: &str, evidence: String, proposed: String) -> Option<String> {
        let key = CallKey { class, subject: subject.to_string() };
        let settled =
            self.answers.call.get(&key.to_string()).or_else(|| self.answers.class.get(&class)).cloned();
        self.calls.push(JudgmentCall { key, evidence, proposed, settled: settled.clone() });
        settled
    }

    /// [`Planner::call`], rendering the proposal while the call is open.
    fn decide(&mut self, class: CallClass, subject: &str, evidence: String, proposed: String) -> String {
        self.call(class, subject, evidence, proposed.clone()).unwrap_or(proposed)
    }

    fn refuse(&mut self, subject: &str, reason: String) {
        self.refusals.push(Refusal { subject: subject.to_string(), reason });
    }
}

/// One `[[project]]` per legacy queue, in registry order (`default` first).
fn plan_projects(p: &mut Planner, queues: &[LegacyQueue]) -> Vec<Project> {
    let mut projects: Vec<Project> = queues
        .iter()
        .map(|queue| {
            let name = project_name(&queue.name).to_string();
            let repo = match queue.repo.as_deref().map(str::trim) {
                None => p.decide(
                    CallClass::ProjectRepo,
                    &name,
                    format!("the `{DEFAULT_QUEUE}` queue has no `## Queues` registry row, so no repo"),
                    String::new(),
                ),
                Some(cell) if mechanical_repo(cell) => cell.to_string(),
                Some(cell) => p.decide(
                    CallClass::ProjectRepo,
                    &name,
                    format!("registry repo cell `{cell}` carries prose or is not provably local or remote"),
                    cell.split_whitespace().next().unwrap_or_default().to_string(),
                ),
            };
            if !repo.is_empty() && RepoLocality::for_current_user(&repo) == RepoLocality::Ambiguous {
                p.refuse(&name, format!("repo `{repo}` is neither provably local nor remote"));
            }
            let main = p.decide(
                CallClass::ProjectMain,
                &name,
                "legacy records no merge branch".to_string(),
                "main".to_string(),
            );
            Project { name, repo, main }
        })
        .collect();
    same_repo(p, &mut projects);
    projects
}

fn project_name(queue: &str) -> &str {
    if queue == DEFAULT_QUEUE { DEFAULT_PROJECT } else { queue }
}

/// A registry cell that maps as-is: one token, local or remote.
fn mechanical_repo(cell: &str) -> bool {
    !cell.is_empty()
        && !cell.contains(char::is_whitespace)
        && RepoLocality::for_current_user(cell) != RepoLocality::Ambiguous
}

/// Projects whose repos are one path spelled two ways: `same_repo`, answered
/// with the one spelling every project in the group uses.
fn same_repo(p: &mut Planner, projects: &mut [Project]) {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, project) in projects.iter().enumerate() {
        if !project.repo.is_empty() {
            groups.entry(normalized_repo(&project.repo)).or_default().push(i);
        }
    }
    for members in groups.into_values() {
        let spellings: BTreeSet<&str> = members.iter().map(|&i| projects[i].repo.as_str()).collect();
        if spellings.len() < 2 {
            continue;
        }
        let subject = members.iter().map(|&i| projects[i].name.as_str()).collect::<Vec<_>>().join("+");
        let evidence = members
            .iter()
            .map(|&i| format!("{} = `{}`", projects[i].name, projects[i].repo))
            .collect::<Vec<_>>()
            .join(", ");
        let proposed = projects[members[0]].repo.clone();
        let spelling = p.decide(CallClass::SameRepo, &subject, evidence, proposed);
        for &i in &members {
            projects[i].repo = spelling.clone();
        }
    }
}

/// A repo path with `~/` expanded and a trailing `/` dropped — only for
/// spotting two spellings of one path, never written.
fn normalized_repo(repo: &str) -> String {
    let repo = repo.trim().trim_end_matches('/');
    match (repo.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{}/{rest}", home.trim_end_matches('/')),
        _ if repo == "~" => std::env::var("HOME").unwrap_or_else(|_| repo.to_string()),
        _ => repo.to_string(),
    }
}

/// The queues in the one global list's order (`list_order`, always a call).
fn list_order<'a>(p: &mut Planner, queues: &'a [LegacyQueue]) -> Vec<&'a LegacyQueue> {
    let evidence = queues
        .iter()
        .map(|q| format!("{} ({} rows)", q.name, q.items.len()))
        .collect::<Vec<_>>()
        .join(", ");
    let answer = p.decide(CallClass::ListOrder, "list", evidence, LIST_ORDER_PROPOSAL.to_string());
    if answer == LIST_ORDER_PROPOSAL {
        return queues.iter().collect();
    }
    let names: Vec<&str> = answer.split(',').map(str::trim).collect();
    let ordered: Vec<&LegacyQueue> =
        names.iter().filter_map(|name| queues.iter().find(|q| q.name == *name)).collect();
    if ordered.len() != queues.len() || names.len() != queues.len() {
        p.refuse("list", format!("list_order answer `{answer}` is not an ordering of every queue"));
        return queues.iter().collect();
    }
    ordered
}

/// For each id in more than one queue table, the queue whose row is kept
/// (`duplicate_id`; proposed: the first in list order).
fn duplicate_owners<'a>(p: &mut Planner, order: &[&'a LegacyQueue]) -> BTreeMap<&'a str, String> {
    let mut seen: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for queue in order {
        for item in &queue.items {
            seen.entry(item.id.as_str()).or_default().push(queue.name.as_str());
        }
    }
    let mut owners = BTreeMap::new();
    for (id, in_queues) in seen.into_iter().filter(|(_, qs)| qs.len() > 1) {
        let keep = p.decide(
            CallClass::DuplicateId,
            id,
            format!("rows in queues {}", in_queues.join(", ")),
            in_queues[0].to_string(),
        );
        if !in_queues.contains(&keep.as_str()) {
            p.refuse(id, format!("duplicate_id answer `{keep}` is not one of {}", in_queues.join(", ")));
        }
        owners.insert(id, keep);
    }
    owners
}

struct ItemCtx<'a> {
    queue: &'a LegacyQueue,
    known: &'a BTreeSet<&'a str>,
    started_by_baton: bool,
    now: &'a str,
}

enum Planned {
    Live(Entry, Option<SlicesToml>),
    Done(Entry),
    Skipped,
}

/// The legacy `status` cell, mapped: a live status, or `None` for `done`.
enum LegacyStatus {
    Live(EntryStatus),
    Done,
}

fn parse_status(cell: &str) -> Option<LegacyStatus> {
    Some(match cell {
        "queued" => LegacyStatus::Live(EntryStatus::Queued),
        "active" => LegacyStatus::Live(EntryStatus::Active),
        "deferred" => LegacyStatus::Live(EntryStatus::Deferred),
        "blocked" => LegacyStatus::Live(EntryStatus::Blocked),
        "done" => LegacyStatus::Done,
        _ => return None,
    })
}

fn plan_item(p: &mut Planner, ctx: &ItemCtx, item: &LegacyItem) -> Planned {
    let id = item.id.as_str();
    let kind = match item.kind.as_str() {
        "milestone" => EntryKind::Milestone,
        "task" => EntryKind::Task,
        other => {
            let proposed = if backlog_doc::is_task_id(id) { "task" } else { "milestone" };
            let evidence = format!("type cell `{other}`");
            match p.decide(CallClass::UnknownCell, &format!("{id}.type"), evidence, proposed.to_string()).as_str() {
                "milestone" => EntryKind::Milestone,
                "task" => EntryKind::Task,
                bad => {
                    p.refuse(id, format!("unknown_cell answer `{bad}` is not `milestone` or `task`"));
                    return Planned::Skipped;
                }
            }
        }
    };
    let status = match parse_status(&item.status) {
        Some(status) => status,
        None => {
            let evidence = format!("status cell `{}`", item.status);
            let answer = p.decide(CallClass::UnknownCell, &format!("{id}.status"), evidence, "queued".to_string());
            match parse_status(&answer) {
                Some(status) => status,
                None => {
                    p.refuse(id, format!("unknown_cell answer `{answer}` is not a legacy status"));
                    return Planned::Skipped;
                }
            }
        }
    };
    let default_branch = match kind {
        EntryKind::Task => format!("fix/{id}"),
        _ => format!("feat/{id}"),
    };
    let (title, after) = title_and_after(p, ctx, item);
    let mut entry = Entry {
        id: id.to_string(),
        kind,
        title,
        project: project_name(&ctx.queue.name).to_string(),
        lane: Lane::Normal,
        status: EntryStatus::Active,
        after,
        added: ctx.now.to_string(),
        branch: default_branch.clone(),
        parent: String::new(),
        base: String::new(),
        claimed: String::new(),
        follow_ups: 0,
        pending_status: None,
        fleet: item.meta.fleet.as_deref().is_none_or(|v| v.eq_ignore_ascii_case("yes")),
        not_before: None,
    };
    let status = match status {
        LegacyStatus::Done => return Planned::Done(entry),
        LegacyStatus::Live(status) => status,
    };
    entry.status = status;

    if item.docs.len() != 1 {
        let evidence = match item.docs.as_slice() {
            [] => "no item doc".to_string(),
            docs => format!("{} docs: {}", docs.len(), docs.join(", ")),
        };
        p.call(CallClass::ItemDoc, id, evidence, item.docs.first().cloned().unwrap_or_default());
    }
    entry.branch = plan_branch(p, id, item.branch_policy.as_deref(), &default_branch);
    let started = status != EntryStatus::Queued || ctx.started_by_baton;
    if started {
        plan_stack_base(p, &mut entry, item.branch_policy.as_deref(), ctx.now);
    }
    entry.not_before = plan_not_before(p, id, item.meta.not_before.as_deref());
    plan_model(p, id, item.meta.model.as_deref());

    let slice_file = (kind == EntryKind::Milestone).then(|| plan_slices(p, item, status, started));
    match slice_file {
        Some(None) => Planned::Skipped,
        Some(file) => Planned::Live(entry, file),
        None => Planned::Live(entry, None),
    }
}

/// The title minus each resolved `[blocked on X]` tag, and the resolved `after`.
fn title_and_after(p: &mut Planner, ctx: &ItemCtx, item: &LegacyItem) -> (String, Vec<String>) {
    let mut title = item.title.clone();
    let mut after = Vec::new();
    let blocked_on = item.tags.iter().filter_map(|tag| {
        let rest = tag.get(..11).filter(|head| head.eq_ignore_ascii_case("blocked on "))?;
        Some((tag, tag[rest.len()..].trim()))
    });
    for (tag, target) in blocked_on.collect::<Vec<_>>() {
        let resolved = if ctx.known.contains(target) && target != item.id {
            Some(target.to_string())
        } else {
            let evidence = format!("title tag `[{tag}]`: `{target}` names no known item");
            match p.call(CallClass::BlockedOn, &item.id, evidence, "none".to_string()).as_deref() {
                None | Some("none") => None,
                Some(id) if ctx.known.contains(id) => Some(id.to_string()),
                Some(bad) => {
                    p.refuse(&item.id, format!("blocked_on answer `{bad}` names no known item"));
                    None
                }
            }
        };
        if let Some(target) = resolved {
            title = strip_tag(&title, tag);
            after.push(target);
        }
    }
    (title, after)
}

/// `title` without its `[tag]` bracket and the space beside it.
fn strip_tag(title: &str, tag: &str) -> String {
    let mut rest = title;
    let mut out = String::new();
    while let Some(open) = rest.find('[') {
        let Some(len) = rest[open + 1..].find(']') else { break };
        let close = open + 1 + len;
        if rest[open + 1..close].trim() == tag {
            out.push_str(&rest[..open]);
            out.push_str(&rest[close + 1..]);
            return out.split_whitespace().collect::<Vec<_>>().join(" ");
        }
        out.push_str(&rest[..=close]);
        rest = &rest[close + 1..];
    }
    title.to_string()
}

/// The backticked tokens in `text` that read as branch names (`feat/x`).
fn branch_names(text: &str) -> Vec<&str> {
    let mut names: Vec<&str> = text
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|t| {
            t.contains('/')
                && !t.starts_with(['/', '~', '.'])
                && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_/".contains(&b))
        })
        .collect();
    names.dedup();
    let mut seen = BTreeSet::new();
    names.retain(|n| seen.insert(*n));
    names
}

fn plan_branch(p: &mut Planner, id: &str, policy: Option<&str>, default: &str) -> String {
    let Some(policy) = policy else { return default.to_string() };
    let names = branch_names(policy);
    if names == [default] {
        return default.to_string();
    }
    let evidence = match names.as_slice() {
        [] => "`## Branch policy` names no branch".to_string(),
        names => format!("`## Branch policy` names {}", names.join(", ")),
    };
    let proposed = match names.as_slice() {
        [only] => only.to_string(),
        _ => default.to_string(),
    };
    p.decide(CallClass::Branch, id, evidence, proposed)
}

/// A started entry's `parent`/`base`: only from a settled `stack_base` answer
/// (`parent=<id> base=<commit>`; an empty parent means `main`).
fn plan_stack_base(p: &mut Planner, entry: &mut Entry, policy: Option<&str>, now: &str) {
    let evidence = policy.map_or("no `## Branch policy`".to_string(), |text| format!("`## Branch policy`: {text}"));
    let proposed = policy.map(stack_proposal).unwrap_or_default();
    let Some(answer) = p.call(CallClass::StackBase, &entry.id, evidence, proposed) else { return };
    let (mut parent, mut base, mut stray) = (None, None, false);
    for word in answer.split_whitespace() {
        match word.split_once('=') {
            Some(("parent", v)) => parent = Some(v),
            Some(("base", v)) => base = Some(v),
            _ => stray = true,
        }
    }
    match (parent, base) {
        (Some(parent), Some(base)) if !stray && !base.is_empty() => {
            entry.parent = parent.to_string();
            entry.base = base.to_string();
            entry.claimed = now.to_string();
        }
        _ => p.refuse(&entry.id, format!("stack_base answer `{answer}` is not `parent=<id> base=<commit>`")),
    }
}

/// The `stack_base` proposal read off branch-policy prose: "off `main`
/// `<sha>`" → `parent= base=<sha>`; "stacked on `feat/Y`" → `parent=Y`.
fn stack_proposal(policy: &str) -> String {
    let tokens: Vec<&str> = policy.split('`').skip(1).step_by(2).collect();
    let is_sha = |t: &str| (7..=40).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_hexdigit());
    if let Some(i) = tokens.iter().position(|t| *t == "main")
        && let Some(sha) = tokens.get(i + 1).filter(|t| is_sha(t))
    {
        return format!("parent= base={sha}");
    }
    let lower = policy.to_ascii_lowercase();
    if let Some(at) = lower.find("stacked on `") {
        let rest = &policy[at + "stacked on `".len()..];
        let branch = rest.split('`').next().unwrap_or_default();
        let parent = branch.split_once('/').map_or(branch, |(_, id)| id);
        return format!("parent={parent} base=");
    }
    String::new()
}

fn plan_not_before(p: &mut Planner, id: &str, value: Option<&str>) -> Option<String> {
    let value = value?;
    let Err(why) = fleet::parse_not_before(value) else { return Some(value.to_string()) };
    let answer = p.decide(CallClass::NotBefore, id, format!("`> Not before: {value}`: {why}"), value.to_string());
    if answer == "none" {
        return None;
    }
    if answer != value && fleet::parse_not_before(&answer).is_err() {
        p.refuse(id, format!("not_before answer `{answer}` does not parse"));
    }
    Some(answer)
}

/// `> Model:` stays in the doc; a line the resolver refuses as one entry is a
/// call whose answer only acknowledges it.
fn plan_model(p: &mut Planner, id: &str, value: Option<&str>) {
    let Some(value) = value else { return };
    let problem = match model_choice::parse_declaration(value) {
        Ok(Declaration::Auto) => return,
        Ok(Declaration::List(list)) if list.entries().len() == 1 => return,
        Ok(Declaration::List(list)) => format!("a {}-entry list", list.entries().len()),
        Err(e) => format!("{e:#}"),
    };
    p.call(CallClass::Model, id, format!("`> Model: {value}`: {problem}"), "keep".to_string());
}

/// A live milestone's `slices.toml`; `None` when the folder cannot be
/// represented (a refusal is recorded).
fn plan_slices(p: &mut Planner, item: &LegacyItem, status: EntryStatus, started: bool) -> Option<SlicesToml> {
    let id = item.id.as_str();
    if !item.subs.is_empty() {
        p.refuse(id, format!("`subs/` under a legacy milestone ({}); legacy never writes one", item.subs.join(", ")));
        return None;
    }
    let mut seen = BTreeSet::new();
    if let Some(dup) = item.slices.iter().find(|n| !seen.insert(n.as_str())) {
        p.refuse(id, format!("two `slices/{dup}-*.md` docs; v2 cannot hold one number twice"));
        return None;
    }
    let mut statuses = vec![SliceStatus::Queued; item.slices.len()];
    if started {
        let proposed = if status == EntryStatus::Deferred { "done" } else { "" };
        let evidence = format!("{} slices ({}); legacy records no per-slice status", item.slices.len(), item.slices.join(", "));
        let answer = p.decide(CallClass::SliceProgress, id, evidence, proposed.to_string());
        if !answer.is_empty() && !apply_slice_progress(&answer, &item.slices, &mut statuses) {
            p.refuse(id, format!("slice_progress answer `{answer}` is not `<status>` or `NNN=<status>, …`"));
        }
    }
    let items = item
        .slices
        .iter()
        .zip(statuses)
        .map(|(n, status)| SliceItem { kind: SliceKind::Slice, id: n.clone(), status, follow_ups: Some(0) })
        .collect();
    Some(SlicesToml::new(id.to_string(), items))
}

fn parse_slice_status(word: &str) -> Option<SliceStatus> {
    Some(match word {
        "queued" => SliceStatus::Queued,
        "active" => SliceStatus::Active,
        "done" => SliceStatus::Done,
        "blocked" => SliceStatus::Blocked,
        "deferred" => SliceStatus::Deferred,
        _ => return None,
    })
}

/// A `slice_progress` answer: one status for every slice, or `NNN=<status>`
/// pairs (unnamed slices stay `queued`). `false` when it does not parse.
fn apply_slice_progress(answer: &str, slices: &[String], statuses: &mut [SliceStatus]) -> bool {
    if let Some(all) = parse_slice_status(answer.trim()) {
        statuses.fill(all);
        return true;
    }
    for pair in answer.split(',').map(str::trim) {
        let Some((n, word)) = pair.split_once('=') else { return false };
        let (Some(i), Some(status)) = (slices.iter().position(|s| s == n.trim()), parse_slice_status(word.trim()))
        else {
            return false;
        };
        statuses[i] = status;
    }
    true
}

/// §3.1 invariant 5: at most one `active` normal-lane entry per repo. More is
/// `active_per_repo`, answered with the id that stays active; the rest queue.
fn active_per_repo(p: &mut Planner, projects: &[Project], entries: &mut [Entry]) {
    let repo_of = |project: &str| projects.iter().find(|pr| pr.name == project).map(|pr| pr.repo.clone());
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, e) in entries.iter().enumerate() {
        if e.lane == Lane::Normal && matches!(e.status, EntryStatus::Active | EntryStatus::Paused) {
            let repo = repo_of(&e.project).filter(|r| !r.is_empty()).unwrap_or_else(|| format!("project:{}", e.project));
            groups.entry(normalized_repo(&repo)).or_default().push(i);
        }
    }
    for (repo, members) in groups.into_iter().filter(|(_, m)| m.len() > 1) {
        let ids: Vec<String> = members.iter().map(|&i| entries[i].id.clone()).collect();
        let keep = p.decide(CallClass::ActivePerRepo, &repo, format!("active: {}", ids.join(", ")), ids[0].clone());
        if !ids.contains(&keep) {
            p.refuse(&repo, format!("active_per_repo answer `{keep}` is not one of {}", ids.join(", ")));
        }
        for &i in &members {
            if entries[i].id != keep {
                entries[i].status = EntryStatus::Queued;
            }
        }
    }
}

/// The §3.6 baton copies. One `IN_PROGRESS` baton naming one live entry
/// copies; anything else is a `baton` call answered `copy` or `skip`.
fn plan_batons(p: &mut Planner, batons: &[LegacyBaton], entries: &[Entry]) -> Vec<BatonMove> {
    let mut moves: Vec<BatonMove> = Vec::new();
    for b in batons {
        let live = entries.iter().any(|e| e.id == b.item);
        let namesakes = batons.iter().filter(|o| o.item == b.item).count();
        let status = b.status.as_deref().unwrap_or("");
        if live && namesakes == 1 && status == "IN_PROGRESS" {
            moves.push(BatonMove { from: b.path.clone(), entry: b.item.clone() });
            continue;
        }
        let mut why = Vec::new();
        if !live {
            why.push(format!("`{}` is not a live entry", b.item));
        }
        if namesakes > 1 {
            why.push(format!("{namesakes} batons name `{}`", b.item));
        }
        if status != "IN_PROGRESS" {
            why.push(format!("status `{status}`"));
        }
        let evidence = format!("item `{}`: {}", b.item, why.join("; "));
        match p.call(CallClass::Baton, &b.path, evidence, "skip".to_string()).as_deref() {
            Some("copy") if !live => p.refuse(&b.path, format!("baton answer `copy`, but `{}` is not live", b.item)),
            Some("copy") if moves.iter().any(|m| m.entry == b.item) => {
                p.refuse(&b.path, format!("a second baton copied to `entries/{}/baton.md`", b.item));
            }
            Some("copy") => moves.push(BatonMove { from: b.path.clone(), entry: b.item.clone() }),
            None | Some("skip") => {}
            Some(bad) => p.refuse(&b.path, format!("baton answer `{bad}` is not `copy` or `skip`")),
        }
    }
    moves
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

    const NOW: &str = "2026-11-01T00:00:00Z";

    fn item(id: &str, kind: &str, status: &str) -> LegacyItem {
        LegacyItem {
            id: id.to_string(),
            kind: kind.to_string(),
            title: format!("T {id}"),
            tags: Vec::new(),
            status: status.to_string(),
            docs: vec![format!("doc/{id}")],
            meta: ItemMeta::default(),
            branch_policy: None,
            slices: Vec::new(),
            subs: Vec::new(),
        }
    }

    fn backlog(default: Vec<LegacyItem>, named: Vec<(&str, &str, Vec<LegacyItem>)>) -> LegacyBacklog {
        let mut queues = vec![LegacyQueue { name: DEFAULT_QUEUE.to_string(), repo: None, items: default }];
        queues.extend(named.into_iter().map(|(name, repo, items)| LegacyQueue {
            name: name.to_string(),
            repo: Some(repo.to_string()),
            items,
        }));
        LegacyBacklog { queues, ..LegacyBacklog::default() }
    }

    /// Answers that settle the three calls every backlog raises.
    fn base_answers() -> Answers {
        Answers {
            schema: ANSWERS_SCHEMA_VERSION,
            class: BTreeMap::from([
                (CallClass::ListOrder, LIST_ORDER_PROPOSAL.to_string()),
                (CallClass::ProjectMain, "main".to_string()),
            ]),
            call: BTreeMap::from([("project_repo:softfig".to_string(), "/srv/softfig".to_string())]),
        }
    }

    fn classes(plan: &MigrationPlan) -> Vec<String> {
        plan.calls.iter().map(|c| c.key.to_string()).collect()
    }

    #[test]
    fn mechanical_rows_map_and_validate() {
        let mut m = item("m", "milestone", "queued");
        m.slices = vec!["001".into(), "002".into()];
        m.meta.fleet = Some("no".into());
        let mut t = item("007", "task", "queued");
        t.title = "[blocked on m] fix it".into();
        t.tags = vec!["blocked on m".into()];
        t.meta.not_before = Some("2026-11-02 02:00 -04:00".into());
        let done = item("old", "milestone", "done");
        let plan = plan(&backlog(vec![m, t, done], vec![]), &base_answers(), NOW);
        assert!(plan.refusals.is_empty(), "{:?}", plan.refusals);
        assert!(plan.applicable(), "open: {:?}", plan.open_calls().collect::<Vec<_>>());

        let [m, t] = plan.queue.entries.as_slice() else { panic!("{:?}", plan.queue.entries) };
        assert_eq!((m.branch.as_str(), m.fleet, m.status), ("feat/m", false, EntryStatus::Queued));
        assert_eq!((t.branch.as_str(), t.title.as_str(), t.after.as_slice()), ("fix/007", "fix it", &["m".to_string()][..]));
        assert_eq!(t.not_before.as_deref(), Some("2026-11-02 02:00 -04:00"));
        assert_eq!((t.added.as_str(), t.base.as_str(), t.claimed.as_str()), (NOW, "", ""));
        assert_eq!(plan.queue.projects[0], Project { name: "softfig".into(), repo: "/srv/softfig".into(), main: "main".into() });
        assert_eq!(plan.archive.entries[0].row.id, "old");
        assert_eq!(plan.archive.entries[0].finished, NOW);

        let [(id, slices)] = plan.slices.as_slice() else { panic!("{:?}", plan.slices) };
        assert_eq!(id, "m");
        assert!(slices.items.iter().all(|s| s.status == SliceStatus::Queued && s.follow_ups == Some(0)));
    }

    #[test]
    fn every_backlog_raises_order_repo_and_main_and_stays_unapplicable_until_answered() {
        let none = Answers { schema: ANSWERS_SCHEMA_VERSION, class: BTreeMap::new(), call: BTreeMap::new() };
        let plan = plan(&backlog(vec![], vec![("psy", "/home/u/psy", vec![])]), &none, NOW);
        assert_eq!(classes(&plan), vec![
            "project_repo:softfig",
            "project_main:softfig",
            "project_main:psy",
            "list_order:list"
        ]);
        assert!(!plan.applicable());
        assert_eq!(plan.queue.projects[1].repo, "/home/u/psy", "a clean registry cell is mechanical");
    }

    #[test]
    fn repo_prose_and_two_spellings_are_calls() {
        let home = std::env::var("HOME").unwrap_or_default();
        let b = backlog(vec![], vec![
            ("road", "phone:/p/road (REMOTE — ssh phone)", vec![]),
            ("a", "~/code", vec![]),
            ("b", &format!("{home}/code/"), vec![]),
        ]);
        let plan = plan(&b, &base_answers(), NOW);
        let keys = classes(&plan);
        assert!(keys.contains(&"project_repo:road".to_string()));
        assert_eq!(plan.queue.projects[1].repo, "phone:/p/road", "prose proposal = the first token");
        assert!(keys.contains(&"same_repo:a+b".to_string()), "{keys:?}");
        assert_eq!(plan.queue.projects[3].repo, "~/code", "both spell it the first project's way");
    }

    #[test]
    fn started_entries_need_a_settled_stack_base() {
        let mut a = item("a", "milestone", "active");
        a.branch_policy = Some("Branch `feat/a` off `main` `abc1234`.".into());
        let mut answers = base_answers();
        let open = plan(&backlog(vec![a.clone()], vec![]), &answers, NOW);
        let call = open.calls.iter().find(|c| c.key.class == CallClass::StackBase).unwrap();
        assert_eq!(call.proposed, "parent= base=abc1234");
        assert_eq!(open.queue.entries[0].base, "", "a proposal is never applied unasked");
        assert!(open.calls.iter().any(|c| c.key.to_string() == "slice_progress:a"));

        answers.call.insert("stack_base:a".into(), "parent= base=abc1234".into());
        answers.call.insert("slice_progress:a".into(), "queued".into());
        let settled = plan(&backlog(vec![a], vec![]), &answers, NOW);
        let e = &settled.queue.entries[0];
        assert_eq!((e.branch.as_str(), e.parent.as_str(), e.base.as_str(), e.claimed.as_str()), ("feat/a", "", "abc1234", NOW));
        assert!(settled.applicable(), "{:?}", settled.refusals);
    }

    #[test]
    fn branch_policy_naming_another_branch_is_a_call() {
        let mut t = item("009", "task", "queued");
        t.branch_policy = Some("Work on `fix/009-long-name` stacked on `feat/x`.".into());
        let plan = plan(&backlog(vec![t], vec![]), &base_answers(), NOW);
        let call = plan.calls.iter().find(|c| c.key.class == CallClass::Branch).unwrap();
        assert_eq!(call.evidence, "`## Branch policy` names fix/009-long-name, feat/x");
        assert_eq!(plan.queue.entries[0].branch, "fix/009");
    }

    #[test]
    fn unrepresentable_shapes_are_refusals() {
        let mut subs = item("s", "milestone", "queued");
        subs.subs = vec!["x".into()];
        let mut dup = item("d", "milestone", "queued");
        dup.slices = vec!["001".into(), "001".into()];
        let mut b = backlog(vec![subs, dup], vec![]);
        b.orphan_tables = vec!["ghost".into()];
        let plan = plan(&b, &base_answers(), NOW);
        let subjects: Vec<_> = plan.refusals.iter().map(|r| r.subject.as_str()).collect();
        assert_eq!(subjects, vec!["queue:ghost", "s", "d"]);
        assert!(plan.queue.entries.is_empty() && !plan.applicable());
    }

    #[test]
    fn cells_ids_docs_tags_and_meta_outside_the_vocabulary_are_calls() {
        let mut odd = item("o", "epic", "parked");
        odd.docs.clear();
        odd.tags = vec!["blocked on …".into()];
        odd.title = "[blocked on …] odd".into();
        odd.meta.not_before = Some("tomorrow".into());
        odd.meta.model = Some("claude, flash".into());
        let two = item("w", "task", "queued");
        let plan = plan(&backlog(vec![odd, two.clone()], vec![("q", "/r", vec![two])]), &base_answers(), NOW);
        let keys = classes(&plan);
        for key in ["unknown_cell:o.type", "unknown_cell:o.status", "item_doc:o", "blocked_on:o", "not_before:o", "model:o", "duplicate_id:w"] {
            assert!(keys.contains(&key.to_string()), "{key} missing from {keys:?}");
        }
        assert_eq!(plan.queue.entries.iter().filter(|e| e.id == "w").count(), 1);
        assert_eq!(plan.queue.entries[0].title, "[blocked on …] odd", "an unresolved tag stays");
    }

    #[test]
    fn two_actives_in_one_repo_and_odd_batons_are_calls() {
        let b = LegacyBacklog {
            batons: vec![
                LegacyBaton { path: "agents/a/baton.md".into(), item: "x".into(), status: Some("IN_PROGRESS".into()) },
                LegacyBaton { path: "agents/b/baton.md".into(), item: "gone".into(), status: Some("IN_PROGRESS".into()) },
            ],
            ..backlog(vec![item("x", "task", "active"), item("y", "task", "active")], vec![])
        };
        let plan = plan(&b, &base_answers(), NOW);
        let keys = classes(&plan);
        assert!(keys.contains(&"active_per_repo:/srv/softfig".to_string()), "{keys:?}");
        assert!(keys.contains(&"baton:agents/b/baton.md".to_string()));
        assert_eq!(plan.queue.entries[1].status, EntryStatus::Queued, "the proposal keeps the first active");
        assert_eq!(plan.batons, vec![BatonMove { from: "agents/a/baton.md".into(), entry: "x".into() }]);
    }
}
