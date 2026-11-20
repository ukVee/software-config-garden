//! The migrate verbs' wire types: the answers file, the baton copies, and the
//! restack stack a restack doc renders from. They cross the keeperd wire, so
//! they live here rather than in `softfig-ipc`'s converter
//! (`meta/spec-softfig-tui-frontend-split.md` §3.1; milestone
//! `tui-split-protocol-merge` slice 003). The IO-bound remainder of the
//! converter — the legacy snapshot, the plan and the apply — stays in
//! `softfig-ipc::queue_v2::migrate`, which re-exports these four types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One branch in a restack's ordered stack (§8): what to rebase, and onto what.
/// growlightd resolves `onto` (keeperd runs no git); the restack doc
/// (`tasks/NNN-restack-<project>.md`) renders one step per branch from these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestackBranch {
    /// The branch to rebase (`feat/<id>` / `fix/<id>`).
    pub branch: String,
    /// The recorded `parent` — the entry this branch was cut from; `""` =
    /// `main` (§8).
    pub parent: String,
    /// The recorded `base` — the commit cut from (local) / the parent branch
    /// name (remote).
    pub base: String,
    /// The `--onto` target: the parent's branch, or `main` for a main-rooted
    /// branch. growlightd resolves it from the parent entry's branch.
    pub onto: String,
}

/// The owner's settlements, read from the answers file (`--answers <toml>`).
/// A class-wide answer settles every call of that class; a per-key answer
/// overrides it for one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answers {
    pub schema: u32,
    /// Class -> the answer for every call of that class.
    #[serde(default)]
    pub class: BTreeMap<CallClass, String>,
    /// `CallKey` (rendered) -> the answer for that one call. The key type stays
    /// with the converter in `softfig-ipc`; only its rendering crosses here.
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
    /// A live item with no item doc, or more than one. Acknowledgment only:
    /// v2 finds the doc by its path, so the answer is never read.
    ItemDoc,
    /// A `[blocked on X]` tag whose X names no known item.
    BlockedOn,
    /// `## Branch policy` prose that names no single branch, or a branch other
    /// than the v2 default (`feat/<id>` / `fix/<id>`).
    Branch,
    /// A started item's `parent` / `base` the prose does not state.
    StackBase,
    /// A started milestone's per-slice progress (legacy records none); a
    /// milestone with no slices raises none.
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

/// A runtime baton copy: `from` (runtime-relative) -> `entries/<entry>/baton.md`.
/// A copy, never a move: the legacy baton stays where it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatonMove {
    pub from: String,
    pub entry: String,
}
