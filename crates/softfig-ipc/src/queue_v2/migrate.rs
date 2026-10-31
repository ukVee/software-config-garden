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
    /// The `status` cell, verbatim.
    pub status: String,
    /// The item doc's garden path, when exactly one was found.
    pub doc_path: Option<String>,
    /// The metadata the doc declares (`None` = the line is absent).
    pub meta: ItemMeta,
    /// `## Branch policy` section text, verbatim, when present.
    pub branch_policy: Option<String>,
    /// Slice ids (`NNN`) from the slice folder, in filename-number order.
    pub slices: Vec<String>,
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
    /// The head's `item:` value.
    pub item: String,
    /// The head's `status:` value.
    pub status: String,
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
