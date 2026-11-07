//! The v2 scheduler's **selection policy** (queue-v2-scheduling slice 002):
//! the pure `pick_v2` over a v2 snapshot, the same theory-code discipline the
//! legacy [`crate::scheduler`] applies to the named queues — no I/O, no live
//! fleet, no keeperd socket, fully testable against fixtures. Spec:
//! `meta/spec-growlight-queue.md` §2 (eligibility + the four-step pick) and §4
//! (the unit walk).
//!
//! ## The split
//!
//! This module owns only the policy. The v2 queue source (slice 003) assembles
//! the [`V2Snapshot`] from `queue.toml` / `queue-archive.toml` / `slices.toml`
//! — including the chain-resolved `> Model:` declarations each unit carries,
//! which is why [`pick_v2`] itself can stay pure. The drive loop (slice 006)
//! feeds the pick to a real member at a handshake boundary and applies the
//! pause semantics of §6.3 step 5.
//!
//! ## The policy
//!
//! - **One global list, two lanes** (§2): `urgent` drains first. Within a lane,
//!   **file order is list order** — nothing here sorts.
//! - **Eligibility** ([`eligible`]) is the conjunction of §2's clauses, checked
//!   in the spec's order: status, `after` links, the repo rule, the holder
//!   rule, the remote rule (grants §9), the unit walk, and the §6.4 backend
//!   match.
//! - **The four-step pick** ([`pick_v2`]): (1) urgent lane, pinned project;
//!   (2) the member's own last `active`/`paused` entry; (3) normal lane,
//!   pinned project; (4) fallback — 1 and 3 again, unfiltered.
//! - **The unit walk** ([`next_unit`], §4): a milestone's `slices.toml` in file
//!   order, recursing into `sub` items; `done`/`split`/`deferred` are rolled
//!   past, the first `queued`/`active` is taken, a `blocked` item stops the
//!   entry, and an exhausted tree yields the close-out. Tasks and restacks are
//!   their own unit. A missing tree is **no unit** — fail closed, never a
//!   guessed close-out over unseen work.
//! - **Skip-reason reporting**: the outcome carries every skipped entry with
//!   its reason, in list (file) order — `queue pick` (slice 012) prints them.

use std::collections::{BTreeMap, BTreeSet};

use softfig_ipc::model_choice::{Backend, ModelList};
use softfig_ipc::queue_v2::{EntryKind, EntryStatus, Lane, RepoLocality, SliceKind, SliceStatus};

/// A member asking the scheduler what to run next — the `pick_v2(member)`
/// input (§2). Pure data; the caller fills it from the roster and runtime
/// state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The member's roster id — the holder identity (§2 "held by exactly one
    /// running member") and the step-2 resume preference.
    pub id: String,
    /// The backend the member runs on (§6.4 backend match; grants §9 remote).
    pub backend: Backend,
    /// The member's pinned **project** (§2: a pin names a project, not a
    /// queue). `None` = unpinned: steps 1/3 scan with no project filter, so
    /// the urgent lane still comes first (§9) and the fallback adds nothing.
    pub pin: Option<String>,
}

/// One `[[project]]` row, reduced to what the pick needs (§3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectView {
    pub name: String,
    /// The repo path or `host:path`, as written. The repo rule keys on this.
    pub repo: String,
    /// Where `repo` lives, classified once by the v2 source
    /// ([`Project::locality`](softfig_ipc::queue_v2::Project::locality),
    /// report 062) — the remote rule reads this, never the string.
    pub locality: RepoLocality,
    /// The branch merges land on (§3.1). The stack computation (queue-v2-git
    /// §8) reads it as the cut-from branch when the stack is empty.
    pub main: String,
}

/// One `[[entry]]` row plus the runtime fields the pick needs (§3.1). The v2
/// source assembles these from `queue.toml` and growlightd's runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryView {
    pub id: String,
    pub kind: EntryKind,
    /// The owning [`ProjectView::name`] — the source also carries the
    /// projects, and the pick joins on this.
    pub project: String,
    pub lane: Lane,
    pub status: EntryStatus,
    /// Ids that must be archived `done` first (§2 links).
    pub after: Vec<String>,
    /// The entry's branch (`feat/<id>` / `fix/<id>`; `""` for a restack) — set
    /// at enqueue (§3.1). Carried so the first-claim stack computation
    /// (queue-v2-git §8) sees each live entry's branch; the pick ignores it.
    pub branch: String,
    /// First-claim time, UTC (§3.1). Carried for completeness; the pick does
    /// not order by it (stack order is `queue-v2-git`'s row).
    pub claimed: String,
    /// The recorded `parent` — the entry whose branch this was cut from;
    /// `""` = `main` (§8). Carried so restack detection (`queue-v2-git` slice
    /// 003) can compare each branch's recorded base against its parent's tip.
    pub parent: String,
    /// The recorded `base` — the commit cut from (local) / the parent branch
    /// name (remote) (§8). `""` = never claimed. Carried for restack
    /// detection.
    pub base: String,
    /// Consecutive follow-ups (§7) — the cap's count for a task, restack or
    /// close-out unit ([`crate::member_verbs`]); the pick itself ignores it.
    pub follow_ups: u64,
    /// A human status change recorded on this `active` entry and not yet
    /// applied (finding 8, §6.8): the handshake applies it at the boundary.
    /// The pick ignores it — the entry is `active` until then.
    pub pending: Option<EntryStatus>,
    /// `false` marks a human-only entry (§2 **Holds**, §3.1 `fleet`): the
    /// fleet never claims it and never resumes it while no live member holds
    /// it. Default `true`.
    pub fleet: bool,
    /// The entry's start time as written (§2 **Holds**, §3.1 `not_before`):
    /// a `queued` entry is not claimed before it. Kept raw, so a malformed
    /// value reaches the pick and holds (fail closed) rather than vanishing.
    pub not_before: Option<String>,
    /// Who holds the entry. An `active` entry → the running member, or `None`
    /// when no running member holds it (an orphan any member resumes); a
    /// `paused` entry → the member that paused it (the step-2 resume
    /// preference), or `None` for a backend-mismatch pause (§6.3 step 5).
    /// Runtime state, not TOML — growlightd knows both at the moment they
    /// happen.
    pub holder: Option<String>,
    /// The chain-resolved `> Model:` declaration for a **task/restack unit**
    /// (whose chain is just its doc). A milestone carries `None` here — its
    /// units resolve inside the trees.
    pub models: Option<ModelList>,
}

/// One milestone's (or sub-milestone's) slice tree: its `slices.toml` items in
/// file order (§3.3), plus the chain-resolved declaration of the milestone's
/// own `CLAUDE.md` — the close-out unit's allowed list (§6.4 chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeView {
    pub items: Vec<ItemView>,
    pub models: Option<ModelList>,
}

/// One `[[item]]` row (§3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemView {
    pub kind: SliceKind,
    /// `slice`: the `NNN` of `slices/NNN-<slug>.md`; `sub`: the sub-milestone
    /// slug.
    pub id: String,
    pub status: SliceStatus,
    /// Slice only: the chain-resolved `> Model:` declaration for **this slice
    /// unit** (slice doc → enclosing sub `CLAUDE.md`s → the milestone
    /// `CLAUDE.md`). A `sub` item carries `None`: its units resolve inside the
    /// sub's own tree.
    pub models: Option<ModelList>,    /// Slice only: consecutive follow-ups (§7), the cap's per-slice count —
    /// `slices.toml`'s `follow_ups` (absent = 0). A `sub` item carries 0.
    pub follow_ups: u64,
}

/// A point-in-time view of the whole v2 list (§2, §3): every live entry in
/// file order, the live milestones' slice trees, and the archive's `done` ids
/// for `after` resolution. Assembled and validated by the v2 source (slice
/// 003); the pick never reads a file. `Default` is the empty list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V2Snapshot {
    pub projects: Vec<ProjectView>,
    /// Live entries in **file order** (urgent lane first per the §3.1 writer
    /// invariant). File order is list order.
    pub entries: Vec<EntryView>,
    /// Every live milestone's slice tree, keyed by milestone identity
    /// (`"<id>"`, or `"<parent>/<sub>"` for a sub-milestone — §3.3), each in
    /// file order, including each sub-milestone's own tree.
    pub trees: BTreeMap<String, TreeView>,
    /// Archive rows with `final_status = done` — `after` links resolve against
    /// these (§3.2). A `dropped` row is deliberately absent, so it never
    /// satisfies a link (§2).
    pub done_ids: BTreeSet<String>,
    /// The clock the `not_before` hold reads, UNIX seconds. The v2 source
    /// leaves it 0; whoever picks stamps it from its own clock — the drive
    /// loop's injected `now`, `queue pick`'s wall clock. Unstamped, every
    /// start time is still ahead, so a forgotten stamp holds, never starts
    /// early.
    pub now_unix: i64,
    /// The branch of each archive row with `final_status = done` (id →
    /// branch; rows that never got a branch are absent). The loop never merges,
    /// so a `done` entry's branch is usually still unmerged work: restack
    /// detection resolves a child's archived parent through it (queue-v2-git
    /// §8, V7).
    pub done_branches: BTreeMap<String, String>,
    /// The project of each archive row with `final_status = done`: the row left
    /// `entries`, and a handoff scan still has to find its repo (§8, V17).
    pub done_projects: BTreeMap<String, String>,
    /// Archived restack rows still owed their §8 re-record, by project (project
    /// → row ids). Read from the archive, so a daemon restart doesn't lose them.
    pub re_records_due: BTreeMap<String, Vec<String>>,
}

/// One unit of work growlightd assigns (§4): a slice, a close-out, or the
/// task/restack entry itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unit {
    /// A milestone's (or sub-milestone's) slice — `slice` is the `NNN` of
    /// `slices/NNN-<slug>.md`, `milestone` the (possibly nested) identity.
    Slice { milestone: String, slice: String },
    /// A milestone's (or sub-milestone's) close-out session (§6.5).
    CloseOut { milestone: String },
    /// A task or restack: the entry itself is the unit (§4).
    Entry,
}

/// Why an entry was examined and not picked. `queue pick` (slice 012) prints
/// one per skipped entry. The spec never enumerates the reasons (§6.9 says
/// only "every skip reason"); the set covers each eligibility clause plus the
/// pin filter, so the report is truthful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Status is `blocked` or `deferred` — never eligible (§2).
    NotEligible,
    /// An `after` id is not archived `done` (§2).
    AfterNotDone,
    /// The repo rule: another normal-lane entry on the same repo is
    /// `active`/`paused` (§2 — only those two hold the repo).
    RepoHeld,
    /// A restack owns this entry's repo (§2 restack rule): a normal entry
    /// waits out any live restack there, an urgent one a started restack.
    RestackLive,
    /// This restack waits: another entry in its repo is `active`, so a live
    /// session may hold a branch it would rewrite (§2 restack rule).
    RestackWaits,
    /// An `active` entry held by a different member (§2 — an active entry is
    /// held by exactly one running member).
    Held,
    /// The entry's project is remote and the member runs opencode (grants §9,
    /// queue-v2-state finding 1).
    Remote,
    /// The entry's project repo is neither provably local nor `host:path`
    /// (report 062) and the member runs opencode — never guessed local.
    AmbiguousRepo,
    /// No next unit: the walk found neither a slice nor a close-out — e.g. the
    /// milestone's tree is missing from the snapshot. Fail closed, never
    /// guessed.
    NoUnit,
    /// The walk stopped at a `blocked` item (§2) — the entry has no next
    /// slice.
    BlockedWalk,
    /// The unit's declared `> Model:` list has no model the member's backend
    /// can run (§6.4 backend match).
    BackendMismatch,
    /// The entry's project is not the member's pinned project (steps 1/3).
    NotPinned,
    /// A human-only entry (`fleet = false`, §2 **Holds**) that no live member
    /// holds: `queued`, `paused`, or an orphaned `active` entry.
    HumanOnly,
    /// A `queued` entry whose `not_before` start time is still ahead (§2
    /// **Holds**).
    NotYet,
    /// A `queued` entry whose `not_before` doesn't parse: held, so a typo
    /// never starts work early (§2 **Holds**, fail closed).
    BadStartTime,
}

impl SkipReason {
    /// The stable slug `queue pick` prints and its reply carries.
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::NotEligible => "not_eligible",
            SkipReason::AfterNotDone => "after_not_done",
            SkipReason::RepoHeld => "repo_held",
            SkipReason::RestackLive => "restack_live",
            SkipReason::RestackWaits => "restack_waits",
            SkipReason::Held => "held",
            SkipReason::Remote => "remote",
            SkipReason::AmbiguousRepo => "ambiguous_repo",
            SkipReason::NoUnit => "no_unit",
            SkipReason::BlockedWalk => "blocked_walk",
            SkipReason::BackendMismatch => "backend_mismatch",
            SkipReason::NotPinned => "not_pinned",
            SkipReason::HumanOnly => "human_only",
            SkipReason::NotYet => "not_yet",
            SkipReason::BadStartTime => "bad_start_time",
        }
    }

    /// How `growlight status` lists a hold under `held:`, beside the legacy
    /// pass's `human-only (> Fleet: no)`. `None` for every reason that is not
    /// a §2 hold, which is what makes a reason a hold.
    pub fn hold_label(self) -> Option<&'static str> {
        match self {
            SkipReason::HumanOnly => Some("human-only (fleet = false)"),
            SkipReason::NotYet => Some("not yet (not_before)"),
            SkipReason::BadStartTime => Some("bad start time (not_before)"),
            _ => None,
        }
    }

    /// The `held:` row for `entry` held for this reason: the label, with the
    /// start time as written for a `NotYet` hold, the way the legacy pass
    /// carries `> Not before:`. `None` exactly when the reason is not a hold.
    pub fn hold_text(self, entry: &EntryView) -> Option<String> {
        match (self, entry.not_before.as_deref()) {
            (SkipReason::NotYet, Some(at)) => Some(format!("not yet (not_before {at})")),
            _ => self.hold_label().map(str::to_string),
        }
    }

    /// What the reason means, for a reader of `queue pick`.
    pub fn describe(self) -> &'static str {
        match self {
            SkipReason::NotEligible => "its status is not queued, active or paused (§2)",
            SkipReason::AfterNotDone => "an `after` link is not archived done yet (§2)",
            SkipReason::RepoHeld => {
                "another normal-lane entry on its repo is active or paused (§2 repo rule)"
            }
            SkipReason::RestackLive => "a restack owns its repo until it finishes (§2 restack rule)",
            SkipReason::RestackWaits => {
                "another entry on its repo is active, so a live session may hold a branch it rewrites (§2 restack rule)"
            }
            SkipReason::Held => "it is active and another running member holds it (§2)",
            SkipReason::Remote => "a remote project, which an opencode member never takes",
            SkipReason::AmbiguousRepo => {
                "its repo is neither provably local nor host:path, so an opencode member \
                 never takes it (report 062)"
            }
            SkipReason::NoUnit => "no next unit: its slice list is missing (§4, fail closed)",
            SkipReason::BlockedWalk => "its walk stops at a blocked item, which needs a human (§2)",
            SkipReason::BackendMismatch => {
                "its next unit declares no model this member's backend runs (§6.4)"
            }
            SkipReason::NotPinned => "outside the member's pinned project (§2 steps 1 and 3)",
            SkipReason::HumanOnly => {
                "a human-only entry (`fleet = false`) that no live member holds (§2 Holds)"
            }
            SkipReason::NotYet => {
                "a queued entry whose `not_before` start time is still ahead (§2 Holds)"
            }
            SkipReason::BadStartTime => {
                "a queued entry whose `not_before` doesn't parse, held until fixed (§2 Holds)"
            }
        }
    }
}

/// The assignment the pick produced: the entry, its next unit, and the unit's
/// declared allowed model list. The drive loop (slice 006) resolves the
/// concrete model — `declared`'s first backend-runnable entry, or the member
/// default when `None` — and spawns with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    pub entry: String,
    pub unit: Unit,
    /// The unit's chain-resolved `> Model:` declaration; `None` = nothing
    /// declared, so the member default applies (§6.4) and every backend runs
    /// it.
    pub declared: Option<ModelList>,
}

/// One skipped entry, for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skip {
    pub entry: String,
    pub reason: SkipReason,
}

/// The pick's verdict: the assignment (if any) plus every skipped entry in
/// **list (file) order** with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickOutcome {
    /// `None` when nothing is workable anywhere for this member.
    pub picked: Option<Pick>,
    pub skips: Vec<Skip>,
}

/// The walk's verdict for an entry (§4): the next unit, a stop, or nothing.
/// `Blocked` and `NoUnit` both leave the entry ineligible — they carry their
/// own [`SkipReason`] in [`eligible`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkOutcome {
    Unit {
        unit: Unit,
        models: Option<ModelList>,
    },
    /// The walk stopped at a `blocked` item: the entry has no next slice.
    /// `at` is that item's address, `<milestone>:<id>` (a sub-milestone's
    /// slice reads `<parent>/<sub>:<id>`) — what the §2 alert names.
    Blocked { at: String },
    /// No unit at all — a missing tree (fail closed; a close-out is never
    /// guessed over unseen work).
    NoUnit,
}

impl V2Snapshot {
    /// The entries on `repo`, whichever project each belongs to: the stack is
    /// per repo (§8). Repos compare as the strings the projects record, as
    /// [`repo_of`]'s other callers and the §3.1 per-repo invariants do.
    pub fn entries_in_repo<'a>(&'a self, repo: &'a str) -> impl Iterator<Item = &'a EntryView> {
        self.entries.iter().filter(move |e| repo_of(self, e) == Some(repo))
    }
}

/// The project an entry belongs to, joined from the snapshot's projects. A
/// validated snapshot guarantees every entry's project exists (writer
/// invariant 4); `None` is the defensive, fail-closed case.
pub(crate) fn project_of<'a>(snapshot: &'a V2Snapshot, entry: &EntryView) -> Option<&'a ProjectView> {
    snapshot.projects.iter().find(|p| p.name == entry.project)
}

/// The repo an entry works on ([`project_of`]'s `repo`).
fn repo_of<'a>(snapshot: &'a V2Snapshot, entry: &EntryView) -> Option<&'a str> {
    project_of(snapshot, entry).map(|p| p.repo.as_str())
}

/// [`repo_of`]'s locality: where the entry's project repo lives.
fn locality_of(snapshot: &V2Snapshot, entry: &EntryView) -> Option<RepoLocality> {
    project_of(snapshot, entry).map(|p| p.locality)
}

/// The §4 unit walk for a picked entry: a milestone walks its slice tree (in
/// file order, recursing into `sub` items); a task or restack is its own unit.
/// Pure over the snapshot.
pub fn next_unit(snapshot: &V2Snapshot, entry: &EntryView) -> WalkOutcome {
    match entry.kind {
        EntryKind::Task | EntryKind::Restack => WalkOutcome::Unit {
            unit: Unit::Entry,
            models: entry.models.clone(),
        },
        EntryKind::Milestone => walk_tree(snapshot, &entry.id),
    }
}

/// Walk one milestone's tree (§4): skip `done`/`split`/`deferred`, take the
/// first `queued`/`active` (recursing into a `queued`/`active` `sub`'s own
/// tree), stop at `blocked`, and yield the close-out when nothing is open. A
/// tree missing from the snapshot is [`WalkOutcome::NoUnit`] — the source
/// failed to assemble it, and scheduling a close-out over unseen slices would
/// be wrong.
fn walk_tree(snapshot: &V2Snapshot, milestone: &str) -> WalkOutcome {
    let Some(tree) = snapshot.trees.get(milestone) else {
        return WalkOutcome::NoUnit;
    };
    for item in &tree.items {
        match item.kind {
            SliceKind::Slice => match item.status {
                SliceStatus::Queued | SliceStatus::Active => {
                    return WalkOutcome::Unit {
                        unit: Unit::Slice {
                            milestone: milestone.to_string(),
                            slice: item.id.clone(),
                        },
                        models: item.models.clone(),
                    };
                }
                SliceStatus::Blocked => {
                    return WalkOutcome::Blocked {
                        at: format!("{milestone}:{}", item.id),
                    }
                }
                // Rolled past (§2).
                SliceStatus::Done | SliceStatus::Split | SliceStatus::Deferred => {}
            },
            SliceKind::Sub => match item.status {
                SliceStatus::Queued | SliceStatus::Active => {
                    // Recurse into the sub-milestone's own tree (§3.3: the
                    // sub's identity is "<parent>/<sub-slug>"). Its unit keeps
                    // the sub's identity; its blocked/no-unit verdict stops
                    // the whole entry.
                    return walk_tree(snapshot, &format!("{milestone}/{}", item.id));
                }
                SliceStatus::Blocked => {
                    return WalkOutcome::Blocked {
                        at: format!("{milestone}:{}", item.id),
                    }
                }
                // `split` is a slice-only state in meaning (§3.3); treat a
                // split sub as done, defensively.
                SliceStatus::Done | SliceStatus::Split | SliceStatus::Deferred => {}
            },
        }
    }
    WalkOutcome::Unit {
        unit: Unit::CloseOut {
            milestone: milestone.to_string(),
        },
        models: tree.models.clone(),
    }
}

/// §2 clause 1: only a `queued`, `active` or `paused` entry is ever eligible.
fn status_eligible(entry: &EntryView) -> bool {
    matches!(
        entry.status,
        EntryStatus::Queued | EntryStatus::Active | EntryStatus::Paused
    )
}

/// The §2 **Holds**, which depend on the entry alone, never on the member. A
/// human-only entry is never claimed, and never resumed while no live member
/// holds it — so `queued`, `paused` and an orphaned `active` entry are all held
/// (report 086). Only an `active` entry a live member still holds runs on, to
/// its next handshake; whether *this* member is that holder is clause 4's call.
/// Then the start time, which only gates a claim: a `queued` entry is held
/// before its `not_before` (`now` is UNIX seconds), and one whose value doesn't
/// parse is held outright. An `active` or `paused` entry is past its claim, so
/// the time no longer applies. Human-only wins when both hold.
fn hold(entry: &EntryView, now: i64) -> Option<SkipReason> {
    let live_held = entry.status == EntryStatus::Active && entry.holder.is_some();
    if !entry.fleet && !live_held {
        return Some(SkipReason::HumanOnly);
    }
    if entry.status != EntryStatus::Queued {
        return None;
    }
    match softfig_ipc::fleet::parse_not_before(entry.not_before.as_deref()?) {
        Ok(at) if now < at => Some(SkipReason::NotYet),
        Ok(_) => None,
        Err(_) => Some(SkipReason::BadStartTime),
    }
}

/// Every status-eligible entry a §2 hold keeps from every member, in file
/// order: what `growlight status` lists under `held:`. The same two checks
/// `eligible` opens with, so the list and the pick can't disagree.
pub fn held_entries(snapshot: &V2Snapshot) -> Vec<(&EntryView, SkipReason)> {
    snapshot
        .entries
        .iter()
        .filter(|entry| status_eligible(entry))
        .filter_map(|entry| hold(entry, snapshot.now_unix).map(|reason| (entry, reason)))
        .collect()
}

/// The §2 restack rule: a restack rewrites branches in its repo, so it never
/// runs beside a session that may hold one. `None` for an `active` entry, which
/// always keeps going: a restack waits for it, and refusing it here would
/// strand both. Otherwise a restack waits for every `active` entry in the repo,
/// a normal entry waits out any live restack there (a blocked one included,
/// since it stopped partway through the stack), and an urgent entry waits only
/// for a started one, so urgent work never waits on a human.
fn restack_hold(snapshot: &V2Snapshot, entry: &EntryView, repo: &str) -> Option<SkipReason> {
    if entry.status == EntryStatus::Active {
        return None;
    }
    let mut others = snapshot
        .entries
        .iter()
        .filter(|other| other.id != entry.id && repo_of(snapshot, other) == Some(repo));
    if entry.kind == EntryKind::Restack {
        return others
            .any(|other| other.status == EntryStatus::Active)
            .then_some(SkipReason::RestackWaits);
    }
    others
        .any(|other| {
            other.kind == EntryKind::Restack
                && (entry.lane == Lane::Normal
                    || matches!(other.status, EntryStatus::Active | EntryStatus::Paused))
        })
        .then_some(SkipReason::RestackLive)
}

/// §2 eligibility for a member taking an entry: the conjunction of every
/// clause, checked in the spec's order, with the first failure as the skip
/// reason. On success the next unit and its declared model list come back
/// (re-running the walk once per scan is cheap and pure).
pub fn eligible(
    snapshot: &V2Snapshot,
    member: &Member,
    entry: &EntryView,
) -> Result<(Unit, Option<ModelList>), SkipReason> {
    // 1. Status.
    if !status_eligible(entry) {
        return Err(SkipReason::NotEligible);
    }
    // Holds (§2), right after the status clause.
    if let Some(reason) = hold(entry, snapshot.now_unix) {
        return Err(reason);
    }
    // 2. `after` links: every listed id is archived `done`. A `dropped` id is
    // simply absent from `done_ids`, so it never satisfies (§2).
    if entry.after.iter().any(|id| !snapshot.done_ids.contains(id)) {
        return Err(SkipReason::AfterNotDone);
    }
    // The repo, joined from the projects. A missing project cannot appear in
    // a validated snapshot; fail closed rather than guess.
    let repo = repo_of(snapshot, entry).ok_or(SkipReason::NotEligible)?;
    // 3. The repo rule — normal lane only, urgent exempt (§2): at most one
    // normal-lane entry per repo is `active`/`paused`, and the entry itself
    // (the holder) doesn't count against itself.
    if entry.lane == Lane::Normal
        && snapshot.entries.iter().any(|other| {
            other.id != entry.id
                && other.lane == Lane::Normal
                && matches!(other.status, EntryStatus::Active | EntryStatus::Paused)
                && repo_of(snapshot, other) == Some(repo)
        })
    {
        return Err(SkipReason::RepoHeld);
    }
    // 3b. The restack rule (§2).
    if let Some(reason) = restack_hold(snapshot, entry, repo) {
        return Err(reason);
    }
    // 4. The holder rule: an `active` entry is held by exactly one running
    // member, and no other member takes it (§2). A `paused` entry has no
    // holder — anyone may resume it. `holder` is runtime state the drive loop
    // overlays from its live members, so an `active` entry reading `None` has
    // no running member at all — the boot reaper killed its session on a
    // growlightd restart, or its spawn failed after the claim landed. That is
    // an orphan, not a hold: any member resumes it, exactly as a paused entry.
    // Refusing it would strand it `active` forever, holding its repo with it.
    if entry.status == EntryStatus::Active
        && entry
            .holder
            .as_deref()
            .is_some_and(|holder| holder != member.id)
    {
        return Err(SkipReason::Held);
    }
    // 5. The remote rule: an opencode member takes only a project provably on
    // this machine (grants §9; queue-v2-state finding 1). A `host:path` repo
    // is remote; one neither local nor remote (report 062) is never guessed
    // local. A claude member is unaffected.
    if member.backend == Backend::Opencode {
        match locality_of(snapshot, entry) {
            Some(RepoLocality::Local) => {}
            Some(RepoLocality::Remote) => return Err(SkipReason::Remote),
            Some(RepoLocality::Ambiguous) | None => return Err(SkipReason::AmbiguousRepo),
        }
    }
    // 6 + 7. The next unit, then the §6.4 backend match on its declared list
    // (`None` = the member default, which always runs on the member's own
    // backend).
    match next_unit(snapshot, entry) {
        WalkOutcome::Unit { unit, models } => {
            if let Some(list) = &models
                && !list.backend_can_run(member.backend) {
                    return Err(SkipReason::BackendMismatch);
                }
            Ok((unit, models))
        }
        WalkOutcome::Blocked { .. } => Err(SkipReason::BlockedWalk),
        WalkOutcome::NoUnit => Err(SkipReason::NoUnit),
    }
}

/// Record a skip reason. The first real (non-[`SkipReason::NotPinned`]) reason
/// wins — the clause order is deterministic, so a re-scan re-derives the same
/// one — and a real reason replaces an earlier `NotPinned` from a pinned scan,
/// because the fallback's verdict is the more informative one.
fn record(reasons: &mut [Option<SkipReason>], index: usize, reason: SkipReason) {
    let replace = match reasons[index] {
        None => true,
        Some(existing) => {
            existing == SkipReason::NotPinned && reason != SkipReason::NotPinned
        }
    };
    if replace {
        reasons[index] = Some(reason);
    }
}

/// Scan one lane in file order and take the first eligible entry; every
/// examined entry that is not taken gets its reason recorded. `pin` restricts
/// the scan to the pinned project (steps 1/3 — entries outside it record
/// [`SkipReason::NotPinned`]); `None` is the unfiltered fallback scan (step 4).
fn scan_lane(
    snapshot: &V2Snapshot,
    member: &Member,
    lane: Lane,
    pin: Option<&str>,
    reasons: &mut [Option<SkipReason>],
) -> Option<(usize, Unit, Option<ModelList>)> {
    for (index, entry) in snapshot.entries.iter().enumerate() {
        if entry.lane != lane {
            continue;
        }
        if let Some(pin) = pin
            && entry.project != pin {
                record(reasons, index, SkipReason::NotPinned);
                continue;
            }
        match eligible(snapshot, member, entry) {
            Ok((unit, models)) => return Some((index, unit, models)),
            Err(reason) => record(reasons, index, reason),
        }
    }
    None
}

/// Pick the next `(entry, unit)` for a member — §2's four steps, pure over the
/// snapshot:
///
/// 1. the urgent lane in file order, first eligible entry in the pinned
///    project;
/// 2. else the member's own last `active`/`paused` entry, if eligible;
/// 3. else the normal lane in file order, first eligible entry in the pinned
///    project;
/// 4. else steps 1 and 3 again with no pin filter (the fallback).
///
/// An unpinned member runs steps 1/3 with no project filter: the urgent lane
/// still precedes its own resume, so urgent work takes every member at its
/// next handshake (§9), pinned or not; step 4 then has nothing left to add.
/// `None` when nothing is workable for this member anywhere.
pub fn pick_v2(snapshot: &V2Snapshot, member: &Member) -> PickOutcome {
    let mut reasons: Vec<Option<SkipReason>> = vec![None; snapshot.entries.len()];
    // 1. Urgent lane, pinned project (every project for an unpinned member).
    let mut picked: Option<(usize, Unit, Option<ModelList>)> = scan_lane(
        snapshot,
        member,
        Lane::Urgent,
        member.pin.as_deref(),
        &mut reasons,
    );

    // 2. Resume the member's own last active|paused entry.
    if picked.is_none() {
        let own: Vec<usize> = snapshot
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.holder.as_deref() == Some(member.id.as_str())
                    && matches!(entry.status, EntryStatus::Active | EntryStatus::Paused)
            })
            .map(|(index, _)| index)
            .collect();
        if !own.is_empty() {
            // Priority: the active entry first (it is the one the member is
            // running — at most one), then the paused ones, each group
            // most-recent-first. The snapshot carries no engagement clock, so
            // "last" is the last in file order — the deterministic proxy.
            let mut order: Vec<usize> = Vec::new();
            if let Some(&index) = own
                .iter()
                .rev()
                .find(|&&i| snapshot.entries[i].status == EntryStatus::Active)
            {
                order.push(index);
            }
            order.extend(
                own.iter()
                    .rev()
                    .copied()
                    .filter(|&i| snapshot.entries[i].status == EntryStatus::Paused),
            );
            for &index in &order {
                match eligible(snapshot, member, &snapshot.entries[index]) {
                    Ok((unit, models)) => {
                        picked = Some((index, unit, models));
                        break;
                    }
                    Err(reason) => record(&mut reasons, index, reason),
                }
            }
        }
    }

    // 3. Normal lane, pinned project (every project for an unpinned member).
    if picked.is_none() {
        picked = scan_lane(
            snapshot,
            member,
            Lane::Normal,
            member.pin.as_deref(),
            &mut reasons,
        );
    }

    // 4. Fallback: repeat 1 and 3 with no pin filter (an unpinned member's
    // steps 1/3 already had none).
    if picked.is_none() && member.pin.is_some() {
        picked = scan_lane(snapshot, member, Lane::Urgent, None, &mut reasons);
    }
    if picked.is_none() && member.pin.is_some() {
        picked = scan_lane(snapshot, member, Lane::Normal, None, &mut reasons);
    }

    if let Some((index, _, _)) = &picked {
        reasons[*index] = None; // the assignment is never reported as a skip
    }
    let skips = reasons
        .iter()
        .enumerate()
        .filter_map(|(index, reason)| {
            reason.map(|reason| Skip {
                entry: snapshot.entries[index].id.clone(),
                reason,
            })
        })
        .collect();
    let picked = picked.map(|(index, unit, declared)| Pick {
        entry: snapshot.entries[index].id.clone(),
        unit,
        declared,
    });
    PickOutcome { picked, skips }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(name: &str, repo: &str) -> ProjectView {
        ProjectView {
            name: name.into(),
            repo: repo.into(),
            locality: RepoLocality::of(repo, Some("u")),
            main: "main".into(),
        }
    }

    fn entry(id: &str) -> EntryView {
        EntryView {
            id: id.into(),
            kind: EntryKind::Milestone,
            project: "softfig".into(),
            lane: Lane::Normal,
            status: EntryStatus::Queued,
            after: vec![],
            branch: String::new(),
            claimed: String::new(),
            parent: String::new(),
            base: String::new(),
            follow_ups: 0,
            pending: None,
            fleet: true,
            not_before: None,
            holder: None,
            models: None,
        }
    }

    fn tree(items: Vec<ItemView>) -> TreeView {
        TreeView {
            items,
            models: None,
        }
    }

    fn item(kind: SliceKind, id: &str, status: SliceStatus) -> ItemView {
        ItemView {
            kind,
            id: id.into(),
            status,
            models: None,
            follow_ups: 0,
        }
    }

    fn snap(projects: Vec<ProjectView>, entries: Vec<EntryView>) -> V2Snapshot {
        V2Snapshot {
            projects,
            entries,
            trees: BTreeMap::new(),
            done_ids: BTreeSet::new(),
            now_unix: 0,
            done_branches: Default::default(),
            done_projects: Default::default(),
            re_records_due: Default::default(),
        }
    }

    fn member(id: &str) -> Member {
        Member {
            id: id.into(),
            backend: Backend::Opencode,
            pin: None,
        }
    }

    /// A claude member (the other backend).
    fn claude(id: &str) -> Member {
        Member {
            id: id.into(),
            backend: Backend::Claude,
            pin: None,
        }
    }

    /// A slice tree with one open slice, carrying `models`.
    fn declared(models: Option<ModelList>) -> Vec<ItemView> {
        vec![ItemView {
            kind: SliceKind::Slice,
            id: "001".into(),
            status: SliceStatus::Queued,
            models,
            follow_ups: 0,
        }]
    }

    fn list(spec: &str) -> ModelList {
        match softfig_ipc::model_choice::parse_declaration(spec).unwrap() {
            softfig_ipc::model_choice::Declaration::List(list) => list,
            softfig_ipc::model_choice::Declaration::Auto => panic!("a list, not auto"),
        }
    }

    // ---- eligibility: status --------------------------------------------

    #[test]
    fn blocked_and_deferred_entries_are_not_eligible() {
        let mut blocked = entry("b");
        blocked.status = EntryStatus::Blocked;
        let mut deferred = entry("d");
        deferred.status = EntryStatus::Deferred;

        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![blocked.clone(), deferred.clone()],
        );
        snapshot.trees.insert("b".into(), tree(declared(None)));
        snapshot.trees.insert("d".into(), tree(declared(None)));

        assert_eq!(
            eligible(&snapshot, &member("m"), &blocked),
            Err(SkipReason::NotEligible)
        );
        assert_eq!(
            eligible(&snapshot, &member("m"), &deferred),
            Err(SkipReason::NotEligible)
        );
    }

    #[test]
    fn queued_active_and_paused_are_eligible_statuses() {
        for status in [EntryStatus::Queued, EntryStatus::Active, EntryStatus::Paused] {
            let mut e = entry("e");
            e.status = status;
            if status == EntryStatus::Active {
                e.holder = Some("m".into());
            }
            let mut snapshot = snap(
                vec![project("softfig", "~/projects/softfig")],
                vec![e.clone()],
            );
            snapshot.trees.insert("e".into(), tree(declared(None)));
            assert!(eligible(&snapshot, &member("m"), &e).is_ok(), "{status:?}");
        }
    }

    // ---- eligibility: after links ---------------------------------------

    #[test]
    fn after_links_need_every_id_archived_done() {
        let mut e = entry("e");
        e.after = vec!["a".into(), "b".into()];
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));

        // Nothing archived yet → ineligible.
        assert_eq!(
            eligible(&snapshot, &member("m"), &e),
            Err(SkipReason::AfterNotDone)
        );

        // One of two → still ineligible.
        let mut partial = snapshot.clone();
        partial.done_ids.insert("a".into());
        assert_eq!(
            eligible(&partial, &member("m"), &e),
            Err(SkipReason::AfterNotDone)
        );

        // Both done → eligible.
        let mut full = partial;
        full.done_ids.insert("b".into());
        assert!(eligible(&full, &member("m"), &e).is_ok());
    }

    #[test]
    fn a_dropped_id_never_satisfies_a_link() {
        // The archive's dropped rows never enter done_ids, so a link naming a
        // dropped entry stays unsatisfied — by construction, not by luck.
        let mut e = entry("e");
        e.after = vec!["dropped-one".into()];
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));
        assert_eq!(
            eligible(&snapshot, &member("m"), &e),
            Err(SkipReason::AfterNotDone)
        );
    }

    // ---- eligibility: the repo rule --------------------------------------

    #[test]
    fn an_active_or_paused_normal_entry_holds_its_repo() {
        for holding in [EntryStatus::Active, EntryStatus::Paused] {
            let mut holder = entry("holder");
            holder.status = holding;
            holder.holder = Some("other".into());
            let mut candidate = entry("candidate");
            candidate.project = "other-project".into(); // same repo, other project
            let mut snapshot = snap(
                vec![
                    project("softfig", "~/projects/shared"),
                    project("other-project", "~/projects/shared"),
                ],
                vec![holder.clone(), candidate.clone()],
            );
            snapshot
                .trees
                .insert("candidate".into(), tree(declared(None)));
            assert_eq!(
                eligible(&snapshot, &member("m"), &candidate),
                Err(SkipReason::RepoHeld),
                "a {holding:?} sibling holds the shared repo"
            );
        }
    }

    #[test]
    fn blocked_and_deferred_entries_do_not_hold_the_repo() {
        // §2: only active/paused hold it — a blocked sibling doesn't stall the
        // project's next milestone.
        for parked in [EntryStatus::Blocked, EntryStatus::Deferred] {
            let mut sibling = entry("sibling");
            sibling.status = parked;
            let mut candidate = entry("candidate");
            candidate.project = "other-project".into();
            let mut snapshot = snap(
                vec![
                    project("softfig", "~/projects/shared"),
                    project("other-project", "~/projects/shared"),
                ],
                vec![sibling.clone(), candidate.clone()],
            );
            snapshot
                .trees
                .insert("candidate".into(), tree(declared(None)));
            assert!(
                eligible(&snapshot, &member("m"), &candidate).is_ok(),
                "a {parked:?} sibling must not hold the repo"
            );
        }
    }

    #[test]
    fn different_repos_never_collide() {
        let mut holder = entry("holder");
        holder.status = EntryStatus::Active;
        holder.holder = Some("other".into());
        let mut candidate = entry("candidate");
        candidate.project = "other-project".into();
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/a"),
                project("other-project", "~/projects/b"),
            ],
            vec![holder.clone(), candidate.clone()],
        );
        snapshot
            .trees
            .insert("candidate".into(), tree(declared(None)));
        assert!(eligible(&snapshot, &member("m"), &candidate).is_ok());
    }

    #[test]
    fn urgent_entries_are_exempt_from_the_repo_rule() {
        // An urgent entry ignores an active normal sibling on the same repo,
        // but a normal sibling is still held by that active normal entry (§2:
        // the exemption runs one way).
        let mut holder = entry("holder");
        holder.status = EntryStatus::Active;
        holder.holder = Some("other".into());
        let mut urgent = entry("urgent");
        urgent.lane = Lane::Urgent;
        let mut normal = entry("normal");
        normal.project = "other-project".into();

        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/shared"),
                project("other-project", "~/projects/shared"),
            ],
            vec![urgent.clone(), holder.clone(), normal.clone()],
        );
        snapshot.trees.insert("urgent".into(), tree(declared(None)));
        snapshot
            .trees
            .insert("normal".into(), tree(declared(None)));
        assert!(eligible(&snapshot, &member("m"), &urgent).is_ok());
        assert_eq!(
            eligible(&snapshot, &member("m"), &normal),
            Err(SkipReason::RepoHeld)
        );
    }

    #[test]
    fn the_entry_itself_holds_its_own_repo() {
        // An active entry doesn't conflict with itself: its own member keeps
        // resuming it (the repo rule looks at OTHER entries only).
        let mut e = entry("e");
        e.status = EntryStatus::Active;
        e.holder = Some("m".into());
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));
        assert!(eligible(&snapshot, &member("m"), &e).is_ok());
    }

    // ---- eligibility: holder + remote ------------------------------------

    #[test]
    fn an_active_entry_is_taken_only_by_its_holder() {
        let mut e = entry("e");
        e.status = EntryStatus::Active;
        e.holder = Some("alice".into());
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));
        assert_eq!(
            eligible(&snapshot, &member("bob"), &e),
            Err(SkipReason::Held)
        );
        assert!(eligible(&snapshot, &member("alice"), &e).is_ok());
    }

    /// Review R1: `holder` is runtime state, so after a growlightd restart (or a
    /// spawn that failed after its claim) an `active` entry reads `None`. No
    /// running member holds it, so any member resumes it — it must not read
    /// `Held` to everyone, which would strand it and its repo for good.
    #[test]
    fn an_active_entry_with_no_running_holder_is_resumable_by_any_member() {
        let mut e = entry("e");
        e.status = EntryStatus::Active;
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));
        assert!(eligible(&snapshot, &member("alice"), &e).is_ok());
        assert!(eligible(&snapshot, &member("bob"), &e).is_ok());
    }

    /// Review R1, through the pick: the orphaned `active` entry still holds its
    /// repo against the next normal-lane entry, and the pick hands the member
    /// the orphan itself rather than nothing.
    #[test]
    fn the_pick_resumes_an_orphaned_active_entry_ahead_of_its_repo_peers() {
        let mut orphan = entry("orphan");
        orphan.status = EntryStatus::Active;
        let next = entry("next");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![next.clone(), orphan.clone()],
        );
        snapshot.trees.insert("orphan".into(), tree(declared(None)));
        snapshot.trees.insert("next".into(), tree(declared(None)));
        let outcome = pick_v2(&snapshot, &member("bob"));
        assert_eq!(outcome.picked.map(|p| p.entry), Some("orphan".to_string()));
        assert_eq!(
            outcome.skips,
            vec![Skip {
                entry: "next".into(),
                reason: SkipReason::RepoHeld,
            }],
        );
    }

    #[test]
    fn a_paused_entry_has_no_holder_and_any_member_resumes_it() {
        let mut e = entry("e");
        e.status = EntryStatus::Paused;
        e.holder = Some("alice".into()); // paused by alice — a preference, not a lock
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));
        assert!(eligible(&snapshot, &member("bob"), &e).is_ok());
        assert!(eligible(&snapshot, &member("alice"), &e).is_ok());
    }

    // ---- holds: human-only (`fleet = false`) -----------------------------

    /// §2 **Holds**: a queued human-only entry is rolled past like a deferred
    /// one — it is not claimed, it holds no repo, and the entry behind it on
    /// the same repo is picked.
    #[test]
    fn a_human_only_entry_is_rolled_past_and_the_next_one_is_picked() {
        let mut held = entry("held");
        held.fleet = false;
        let next = entry("next");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![held.clone(), next.clone()],
        );
        snapshot.trees.insert("held".into(), tree(declared(None)));
        snapshot.trees.insert("next".into(), tree(declared(None)));
        let outcome = pick_v2(&snapshot, &member("m"));
        assert_eq!(outcome.picked.map(|p| p.entry), Some("next".to_string()));
        assert_eq!(
            outcome.skips,
            vec![Skip {
                entry: "held".into(),
                reason: SkipReason::HumanOnly,
            }],
        );
    }

    /// Task 068's parity: a pinned member whose project has nothing workable
    /// falls back across projects (step 4), and that fallback never lands on a
    /// human-only entry — the reason it records is the hold, not `NotPinned`.
    #[test]
    fn a_fallback_member_never_lands_on_a_human_only_entry() {
        let mut pinned = entry("pinned");
        pinned.status = EntryStatus::Blocked; // nothing in-pin is eligible
        let mut held = entry("held");
        held.project = "other".into();
        held.fleet = false;
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![pinned.clone(), held.clone()],
        );
        snapshot.trees.insert("pinned".into(), tree(declared(None)));
        snapshot.trees.insert("held".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        let outcome = pick_v2(&snapshot, &m);
        assert_eq!(outcome.picked, None);
        assert_eq!(
            outcome.skips,
            vec![
                Skip {
                    entry: "pinned".into(),
                    reason: SkipReason::NotEligible,
                },
                Skip {
                    entry: "held".into(),
                    reason: SkipReason::HumanOnly,
                },
            ]
        );
    }

    /// Report 086's parity: a human-only entry no live member holds is never
    /// resumed — neither an orphaned `active` one (holder `None`) nor a
    /// `paused` one, not even by the member that paused it. Both still hold
    /// their repo, which they held already.
    #[test]
    fn a_human_only_orphaned_active_or_paused_entry_is_not_resumed() {
        let mut orphan = entry("orphan");
        orphan.status = EntryStatus::Active;
        orphan.fleet = false;
        let mut paused = entry("paused");
        paused.project = "other".into();
        paused.status = EntryStatus::Paused;
        paused.holder = Some("alice".into());
        paused.fleet = false;
        let next = entry("next");
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![orphan.clone(), paused.clone(), next.clone()],
        );
        for id in ["orphan", "paused", "next"] {
            snapshot.trees.insert(id.into(), tree(declared(None)));
        }
        for who in ["alice", "bob"] {
            assert_eq!(
                eligible(&snapshot, &member(who), &orphan),
                Err(SkipReason::HumanOnly)
            );
            assert_eq!(
                eligible(&snapshot, &member(who), &paused),
                Err(SkipReason::HumanOnly)
            );
        }
        // Through the pick: alice's step-2 resume of her own paused entry is
        // held too, and the orphan still holds `next`'s repo.
        let outcome = pick_v2(&snapshot, &member("alice"));
        assert_eq!(outcome.picked, None);
        assert_eq!(
            outcome.skips,
            vec![
                Skip {
                    entry: "orphan".into(),
                    reason: SkipReason::HumanOnly,
                },
                Skip {
                    entry: "paused".into(),
                    reason: SkipReason::HumanOnly,
                },
                Skip {
                    entry: "next".into(),
                    reason: SkipReason::RepoHeld,
                },
            ]
        );
    }

    /// The hold's one exception: an `active` human-only entry a live member
    /// still holds runs on, to its next handshake. Its holder keeps it; any
    /// other member is refused by the holder rule, as for any active entry.
    #[test]
    fn a_live_held_human_only_active_entry_keeps_its_holder() {
        let mut e = entry("e");
        e.status = EntryStatus::Active;
        e.holder = Some("alice".into());
        e.fleet = false;
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));
        assert!(eligible(&snapshot, &member("alice"), &e).is_ok());
        assert_eq!(
            eligible(&snapshot, &member("bob"), &e),
            Err(SkipReason::Held)
        );
        let outcome = pick_v2(&snapshot, &member("alice"));
        assert_eq!(outcome.picked.map(|p| p.entry), Some("e".to_string()));
        // So `growlight status` doesn't list it as held either.
        assert!(held_entries(&snapshot).is_empty());
    }

    /// `growlight status`'s v2 `held:` list (slice 002, row 2): exactly the
    /// status-eligible entries the hold keeps from every member, in file order,
    /// each labelled. A `deferred` human-only entry is ineligible on status, not
    /// held; a fleet entry is never held.
    #[test]
    fn held_entries_lists_each_held_entry_in_file_order() {
        let human_only = |id: &str, status| {
            let mut e = entry(id);
            e.status = status;
            e.fleet = false;
            e
        };
        let snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![
                human_only("paused", EntryStatus::Paused),
                entry("free"),
                human_only("parked", EntryStatus::Deferred),
                human_only("queued", EntryStatus::Queued),
            ],
        );
        let held: Vec<(&str, Option<&str>)> = held_entries(&snapshot)
            .into_iter()
            .map(|(e, reason)| (e.id.as_str(), reason.hold_label()))
            .collect();
        let label = Some("human-only (fleet = false)");
        assert_eq!(held, vec![("paused", label), ("queued", label)]);
        assert_eq!(SkipReason::Held.hold_label(), None, "not every skip is a hold");
    }

    /// The slice 003 start time, and its UNIX seconds through the one parser.
    const START: &str = "2026-10-31 02:00 -04:00";

    fn start_unix() -> i64 {
        softfig_ipc::fleet::parse_not_before(START).expect("valid start time")
    }

    fn starting(id: &str, at: &str) -> EntryView {
        let mut e = entry(id);
        e.not_before = Some(at.into());
        e
    }

    /// Two queued entries on one repo, the first not due yet: the pick rolls
    /// past it to the second, and `growlight status` lists it as held. An
    /// unstamped snapshot (`now_unix` 0) holds it too: a forgotten clock never
    /// starts work early.
    #[test]
    fn a_queued_entry_before_its_start_time_is_rolled_past() {
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![starting("later", START), entry("now")],
        );
        snapshot.trees.insert("later".into(), tree(declared(None)));
        snapshot.trees.insert("now".into(), tree(declared(None)));
        for now in [0, start_unix() - 1] {
            snapshot.now_unix = now;
            let outcome = pick_v2(&snapshot, &member("m"));
            assert_eq!(outcome.picked.map(|p| p.entry), Some("now".to_string()));
            assert_eq!(
                outcome.skips,
                vec![Skip {
                    entry: "later".into(),
                    reason: SkipReason::NotYet,
                }]
            );
            let held: Vec<(&str, Option<String>)> = held_entries(&snapshot)
                .into_iter()
                .map(|(e, reason)| (e.id.as_str(), reason.hold_text(e)))
                .collect();
            let text = Some(format!("not yet (not_before {START})"));
            assert_eq!(held, vec![("later", text)]);
        }
    }

    /// The start time is inclusive: at it, and after it, the entry is picked
    /// and nothing is held.
    #[test]
    fn at_and_after_the_start_time_it_is_picked() {
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![starting("e", START)],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));
        for now in [start_unix(), start_unix() + 1] {
            snapshot.now_unix = now;
            let outcome = pick_v2(&snapshot, &member("m"));
            assert_eq!(outcome.picked.map(|p| p.entry), Some("e".to_string()));
            assert!(outcome.skips.is_empty());
            assert!(held_entries(&snapshot).is_empty());
        }
    }

    /// A start time that doesn't parse (here, no offset) holds at any clock,
    /// so a typo never starts an entry early.
    #[test]
    fn a_bad_start_time_holds_fail_closed() {
        let bad = starting("e", "2026-10-31 02:00");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![bad.clone()],
        );
        snapshot.trees.insert("e".into(), tree(declared(None)));
        snapshot.now_unix = i64::MAX;
        assert_eq!(
            eligible(&snapshot, &member("m"), &bad),
            Err(SkipReason::BadStartTime)
        );
        let held: Vec<(&str, Option<String>)> = held_entries(&snapshot)
            .into_iter()
            .map(|(e, reason)| (e.id.as_str(), reason.hold_text(e)))
            .collect();
        assert_eq!(held, vec![("e", Some("bad start time (not_before)".into()))]);
    }

    /// A human-only entry with a start time reads human-only, whether the time
    /// is ahead or doesn't parse: lifting the time alone would not free it.
    #[test]
    fn human_only_wins_over_not_before() {
        for at in [START, "not a time"] {
            let mut e = starting("e", at);
            e.fleet = false;
            let mut snapshot = snap(
                vec![project("softfig", "~/projects/softfig")],
                vec![e.clone()],
            );
            snapshot.trees.insert("e".into(), tree(declared(None)));
            assert_eq!(
                eligible(&snapshot, &member("m"), &e),
                Err(SkipReason::HumanOnly)
            );
        }
    }

    /// The start time gates only a claim. An orphaned `active` entry and a
    /// `paused` one are past theirs, so neither a time still ahead nor one
    /// that doesn't parse holds them.
    #[test]
    fn an_active_or_paused_entry_ignores_not_before() {
        for status in [EntryStatus::Active, EntryStatus::Paused] {
            for at in [START, "not a time"] {
                let mut e = starting("e", at);
                e.status = status;
                let mut snapshot = snap(
                    vec![project("softfig", "~/projects/softfig")],
                    vec![e.clone()],
                );
                snapshot.trees.insert("e".into(), tree(declared(None)));
                assert!(
                    eligible(&snapshot, &member("m"), &e).is_ok(),
                    "{status:?} with not_before {at:?}"
                );
                assert!(held_entries(&snapshot).is_empty());
            }
        }
    }

    #[test]
    fn a_remote_project_is_never_eligible_for_an_opencode_member() {
        // Grants §9 / queue-v2-state finding 1: repo contains ':' → remote.
        let mut remote = entry("remote");
        remote.project = "roadeye".into();
        let mut snapshot = snap(vec![project("roadeye", "phone:roadeye")], vec![remote.clone()]);
        snapshot
            .trees
            .insert("remote".into(), tree(declared(None)));
        assert_eq!(
            eligible(&snapshot, &member("m"), &remote),
            Err(SkipReason::Remote)
        );
        // A claude member is unaffected.
        assert!(eligible(&snapshot, &claude("m"), &remote).is_ok());
    }

    #[test]
    fn the_remote_rule_reads_the_classified_locality() {
        // Report 062: the clause goes through `RepoLocality`, not a `:` test.
        // Home-tilde, the current user's named home and an absolute path with
        // a colon are local; another user's home and a relative path are
        // ambiguous, which an opencode member never takes either.
        let cases = [
            ("~/projects/softfig", Ok(())),
            ("~u/projects/softfig", Ok(())),
            ("/srv/a:b", Ok(())),
            ("host:/srv/p", Err(SkipReason::Remote)),
            ("~bob/projects/softfig", Err(SkipReason::AmbiguousRepo)),
            ("projects/softfig", Err(SkipReason::AmbiguousRepo)),
        ];
        for (repo, want) in cases {
            let e = entry("e");
            let mut snapshot = snap(vec![project("softfig", repo)], vec![e.clone()]);
            snapshot.trees.insert("e".into(), tree(declared(None)));
            assert_eq!(eligible(&snapshot, &member("m"), &e).map(|_| ()), want, "{repo}");
            assert!(eligible(&snapshot, &claude("m"), &e).is_ok(), "{repo}: claude unaffected");
        }
    }

    // ---- eligibility: backend match (§6.4) -------------------------------

    #[test]
    fn the_unit_model_gates_the_member_by_backend() {
        let e = entry("e");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        // The slice declares an opencode-only model.
        snapshot
            .trees
            .insert("e".into(), tree(declared(Some(list("reasoning")))));
        assert!(eligible(&snapshot, &member("m"), &e).is_ok()); // opencode runs reasoning
        assert_eq!(
            eligible(&snapshot, &claude("c"), &e),
            Err(SkipReason::BackendMismatch)
        );

        // A mixed list runs on both backends.
        let mut mixed = snapshot.clone();
        mixed
            .trees
            .insert("e".into(), tree(declared(Some(list("reasoning, claude")))));
        assert!(eligible(&mixed, &member("m"), &e).is_ok());
        assert!(eligible(&mixed, &claude("c"), &e).is_ok());

        // Undeclared → the member default, which always runs.
        let mut undeclared = snapshot.clone();
        undeclared.trees.insert("e".into(), tree(declared(None)));
        assert!(eligible(&undeclared, &member("m"), &e).is_ok());
        assert!(eligible(&undeclared, &claude("c"), &e).is_ok());
    }

    #[test]
    fn a_task_unit_uses_the_entrys_own_declaration() {
        let mut t = entry("047");
        t.kind = EntryKind::Task;
        t.models = Some(list("claude"));
        let snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![t.clone()],
        );
        assert_eq!(
            eligible(&snapshot, &member("m"), &t),
            Err(SkipReason::BackendMismatch)
        );
        assert!(eligible(&snapshot, &claude("c"), &t).is_ok());
    }

    // ---- the unit walk (§4) ----------------------------------------------

    #[test]
    fn the_walk_rolls_past_done_split_deferred_and_takes_the_first_open_slice() {
        let items = vec![
            item(SliceKind::Slice, "001", SliceStatus::Done),
            item(SliceKind::Slice, "002", SliceStatus::Split),
            item(SliceKind::Slice, "003", SliceStatus::Deferred),
            item(SliceKind::Slice, "004", SliceStatus::Queued),
            item(SliceKind::Slice, "005", SliceStatus::Queued),
        ];
        let e = entry("e");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(items));
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Unit {
                unit: Unit::Slice {
                    milestone: "e".into(),
                    slice: "004".into(),
                },
                models: None,
            }
        );
    }

    #[test]
    fn the_walk_prefers_an_active_slice_over_a_later_queued_one() {
        let items = vec![
            item(SliceKind::Slice, "001", SliceStatus::Done),
            item(SliceKind::Slice, "002", SliceStatus::Active),
            item(SliceKind::Slice, "003", SliceStatus::Queued),
        ];
        let e = entry("e");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(items));
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Unit {
                unit: Unit::Slice {
                    milestone: "e".into(),
                    slice: "002".into(),
                },
                models: None,
            }
        );
    }

    #[test]
    fn the_walk_stops_at_a_blocked_slice_even_with_later_open_work() {
        let items = vec![
            item(SliceKind::Slice, "001", SliceStatus::Done),
            item(SliceKind::Slice, "002", SliceStatus::Blocked),
            item(SliceKind::Slice, "003", SliceStatus::Queued),
        ];
        let e = entry("e");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("e".into(), tree(items));
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Blocked { at: "e:002".into() }
        );
        assert_eq!(
            eligible(&snapshot, &member("m"), &e),
            Err(SkipReason::BlockedWalk)
        );
    }

    #[test]
    fn the_walk_recurses_into_a_sub_and_yields_the_subs_unit() {
        // Parent: [sub queued]. Sub tree: [001 done, 002 queued] → the sub's
        // slice 002, with the sub's identity.
        let parent_items = vec![item(SliceKind::Sub, "fid-pam", SliceStatus::Queued)];
        let sub_items = vec![
            item(SliceKind::Slice, "001", SliceStatus::Done),
            item(SliceKind::Slice, "002", SliceStatus::Queued),
        ];
        let e = entry("m");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("m".into(), tree(parent_items));
        snapshot.trees.insert("m/fid-pam".into(), tree(sub_items));
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Unit {
                unit: Unit::Slice {
                    milestone: "m/fid-pam".into(),
                    slice: "002".into(),
                },
                models: None,
            }
        );
    }

    #[test]
    fn a_done_or_deferred_sub_is_rolled_past() {
        let parent_items = vec![
            item(SliceKind::Sub, "done-sub", SliceStatus::Done),
            item(SliceKind::Slice, "001", SliceStatus::Queued),
        ];
        let e = entry("m");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        // No tree for done-sub — it must not be consulted.
        snapshot.trees.insert("m".into(), tree(parent_items));
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Unit {
                unit: Unit::Slice {
                    milestone: "m".into(),
                    slice: "001".into(),
                },
                models: None,
            }
        );
    }

    #[test]
    fn a_block_inside_a_sub_stops_the_whole_entry() {
        let parent_items = vec![item(SliceKind::Sub, "s", SliceStatus::Queued)];
        let sub_items = vec![
            item(SliceKind::Slice, "001", SliceStatus::Done),
            item(SliceKind::Slice, "002", SliceStatus::Blocked),
        ];
        let e = entry("m");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("m".into(), tree(parent_items));
        snapshot.trees.insert("m/s".into(), tree(sub_items));
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Blocked { at: "m/s:002".into() }
        );
    }

    #[test]
    fn a_blocked_sub_item_stops_the_walk() {
        let parent_items = vec![
            item(SliceKind::Sub, "s", SliceStatus::Blocked),
            item(SliceKind::Slice, "001", SliceStatus::Queued),
        ];
        let e = entry("m");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("m".into(), tree(parent_items));
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Blocked { at: "m:s".into() }
        );
    }

    #[test]
    fn an_exhausted_tree_yields_the_close_out_with_the_milestones_models() {
        let items = vec![
            item(SliceKind::Slice, "001", SliceStatus::Done),
            item(SliceKind::Sub, "s", SliceStatus::Done),
        ];
        let mut exhausted = tree(items);
        exhausted.models = Some(list("flash"));
        let e = entry("m");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("m".into(), exhausted);
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Unit {
                unit: Unit::CloseOut {
                    milestone: "m".into(),
                },
                models: Some(list("flash")),
            }
        );
    }

    #[test]
    fn a_sub_whose_tree_is_exhausted_yields_the_subs_close_out() {
        let parent_items = vec![item(SliceKind::Sub, "s", SliceStatus::Active)];
        let sub_items = vec![item(SliceKind::Slice, "001", SliceStatus::Done)];
        let e = entry("m");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot.trees.insert("m".into(), tree(parent_items));
        snapshot.trees.insert("m/s".into(), tree(sub_items));
        assert_eq!(
            next_unit(&snapshot, &e),
            WalkOutcome::Unit {
                unit: Unit::CloseOut {
                    milestone: "m/s".into(),
                },
                models: None,
            }
        );
    }

    #[test]
    fn tasks_and_restacks_are_their_own_unit() {
        for kind in [EntryKind::Task, EntryKind::Restack] {
            let mut t = entry("047");
            t.kind = kind;
            t.models = Some(list("flash"));
            let snapshot = snap(
                vec![project("softfig", "~/projects/softfig")],
                vec![t.clone()],
            );
            // No tree at all — a task needs none.
            assert_eq!(
                next_unit(&snapshot, &t),
                WalkOutcome::Unit {
                    unit: Unit::Entry,
                    models: Some(list("flash")),
                }
            );
            assert!(eligible(&snapshot, &member("m"), &t).is_ok());
        }
    }

    #[test]
    fn a_missing_tree_is_no_unit_not_a_guessed_close_out() {
        let e = entry("m");
        let snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        // No tree for "m" — fail closed.
        assert_eq!(next_unit(&snapshot, &e), WalkOutcome::NoUnit);
        assert_eq!(
            eligible(&snapshot, &member("m"), &e),
            Err(SkipReason::NoUnit)
        );
    }

    // ---- the four-step pick ----------------------------------------------

    #[test]
    fn step_1_takes_the_first_eligible_urgent_entry_in_the_pinned_project() {
        let mut u1 = entry("u1");
        u1.lane = Lane::Urgent;
        u1.project = "other".into(); // not pinned — skipped
        let mut u2 = entry("u2");
        u2.lane = Lane::Urgent;
        let n = entry("n");
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![u1.clone(), u2.clone(), n.clone()],
        );
        snapshot.trees.insert("u1".into(), tree(declared(None)));
        snapshot.trees.insert("u2".into(), tree(declared(None)));
        snapshot.trees.insert("n".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        let outcome = pick_v2(&snapshot, &m);
        assert_eq!(
            outcome.picked.as_ref().map(|p| (p.entry.as_str(), &p.unit)),
            Some((
                "u2",
                &Unit::Slice {
                    milestone: "u2".into(),
                    slice: "001".into(),
                }
            ))
        );
        assert_eq!(
            outcome.skips,
            vec![Skip {
                entry: "u1".into(),
                reason: SkipReason::NotPinned,
            }]
        );
    }

    #[test]
    fn step_1_urgent_work_preempts_a_resume_at_the_boundary() {
        // §9: an eligible urgent entry wins over resuming the member's own
        // active entry — pick scans the urgent lane first.
        let mut urgent = entry("urgent");
        urgent.lane = Lane::Urgent;
        let mut own = entry("own");
        own.status = EntryStatus::Active;
        own.holder = Some("m".into());
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![urgent.clone(), own.clone()],
        );
        snapshot.trees.insert("urgent".into(), tree(declared(None)));
        snapshot.trees.insert("own".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        assert_eq!(
            pick_v2(&snapshot, &m).picked.as_ref().map(|p| p.entry.as_str()),
            Some("urgent")
        );
    }

    #[test]
    fn step_2_resumes_the_members_own_active_entry_when_no_urgent_work_waits() {
        // The urgent lane holds nothing the member can run (claude-only unit,
        // opencode member) → step 2 resumes the member's own active entry.
        let mut urgent = entry("urgent");
        urgent.lane = Lane::Urgent;
        let mut own = entry("own");
        own.status = EntryStatus::Active;
        own.holder = Some("m".into());
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![urgent.clone(), own.clone()],
        );
        snapshot
            .trees
            .insert("urgent".into(), tree(declared(Some(list("claude")))));
        snapshot.trees.insert("own".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        let outcome = pick_v2(&snapshot, &m);
        assert_eq!(outcome.picked.as_ref().map(|p| p.entry.as_str()), Some("own"));
        assert_eq!(
            outcome
                .skips
                .iter()
                .find(|s| s.entry == "urgent")
                .map(|s| s.reason),
            Some(SkipReason::BackendMismatch)
        );
    }

    #[test]
    fn step_2_resumes_the_members_own_paused_entry_over_open_work() {
        let open = entry("open");
        let mut own = entry("own");
        own.status = EntryStatus::Paused;
        own.holder = Some("m".into());
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![open.clone(), own.clone()],
        );
        snapshot.trees.insert("open".into(), tree(declared(None)));
        snapshot.trees.insert("own".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        assert_eq!(
            pick_v2(&snapshot, &m).picked.as_ref().map(|p| p.entry.as_str()),
            Some("own")
        );
    }

    #[test]
    fn step_2_resume_is_a_preference_not_a_lock() {
        // Alice resumes the paused entry she holds (step 2), even though open
        // work precedes it in file order; bob (who doesn't hold it) takes the
        // first open entry instead. The entries live in different repos —
        // alices' pause holds its repo, so same-repo open work would be
        // repo-held anyway (§2).
        let mut open = entry("open");
        open.project = "other".into();
        let mut alices = entry("alices");
        alices.status = EntryStatus::Paused;
        alices.holder = Some("alice".into());
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![open.clone(), alices.clone()],
        );
        snapshot.trees.insert("open".into(), tree(declared(None)));
        snapshot
            .trees
            .insert("alices".into(), tree(declared(None)));

        let mut alice = member("alice");
        alice.pin = Some("softfig".into());
        assert_eq!(
            pick_v2(&snapshot, &alice)
                .picked
                .as_ref()
                .map(|p| p.entry.as_str()),
            Some("alices")
        );

        let mut bob = member("bob");
        bob.pin = Some("other".into());
        assert_eq!(
            pick_v2(&snapshot, &bob).picked.as_ref().map(|p| p.entry.as_str()),
            Some("open")
        );
    }

    #[test]
    fn step_2_falls_through_when_the_own_entry_is_ineligible() {
        // The member's own active entry's next unit needs claude; the member
        // is opencode → ineligible. The active entry still holds its repo
        // (§2), so the fallback takes open work in another repo instead.
        let mut own = entry("own");
        own.status = EntryStatus::Active;
        own.holder = Some("m".into());
        let mut open = entry("open");
        open.project = "other".into();
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![own.clone(), open.clone()],
        );
        snapshot
            .trees
            .insert("own".into(), tree(declared(Some(list("claude")))));
        snapshot.trees.insert("open".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        let outcome = pick_v2(&snapshot, &m);
        assert_eq!(
            outcome.picked.as_ref().map(|p| p.entry.as_str()),
            Some("open")
        );
        assert_eq!(
            outcome.skips.iter().find(|s| s.entry == "own").map(|s| s.reason),
            Some(SkipReason::BackendMismatch),
            "the member's own ineligible entry is reported, not silently dropped"
        );
    }

    #[test]
    fn step_3_takes_the_first_eligible_normal_entry_in_the_pinned_project() {
        let mut a = entry("a");
        a.project = "other".into(); // not pinned — skipped
        let b = entry("b");
        let c = entry("c");
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![a.clone(), b.clone(), c.clone()],
        );
        snapshot.trees.insert("a".into(), tree(declared(None)));
        snapshot.trees.insert("b".into(), tree(declared(None)));
        snapshot.trees.insert("c".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        assert_eq!(
            pick_v2(&snapshot, &m).picked.as_ref().map(|p| p.entry.as_str()),
            Some("b")
        );
    }

    #[test]
    fn step_4_falls_back_across_projects_when_nothing_is_pinned() {
        // Nothing in the pinned project is eligible → the fallback takes the
        // first eligible entry anywhere.
        let mut pinned_blocked = entry("pinned-blocked");
        pinned_blocked.status = EntryStatus::Blocked;
        let mut other = entry("other");
        other.project = "other".into();
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![pinned_blocked.clone(), other.clone()],
        );
        snapshot
            .trees
            .insert("pinned-blocked".into(), tree(declared(None)));
        snapshot.trees.insert("other".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        let outcome = pick_v2(&snapshot, &m);
        assert_eq!(
            outcome.picked.as_ref().map(|p| p.entry.as_str()),
            Some("other")
        );
    }

    #[test]
    fn step_4_scans_urgent_before_normal_unfiltered() {
        let n = entry("n");
        let mut urgent = entry("u");
        urgent.lane = Lane::Urgent;
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![n.clone(), urgent.clone()],
        );
        snapshot.trees.insert("n".into(), tree(declared(None)));
        snapshot.trees.insert("u".into(), tree(declared(None)));

        // Unpinned: steps 1/3 are no-ops; the fallback's urgent scan wins.
        assert_eq!(
            pick_v2(&snapshot, &member("m"))
                .picked
                .as_ref()
                .map(|p| p.entry.as_str()),
            Some("u")
        );
    }

    /// §9 (queue-v2-scheduling slice 009): an unpinned member's step 1 scans
    /// the urgent lane too, so an eligible urgent entry wins over resuming its
    /// own active entry — preemption at the handshake holds for every member,
    /// not only pinned ones.
    #[test]
    fn an_unpinned_member_takes_urgent_work_before_resuming_its_own() {
        let mut own = entry("own");
        own.status = EntryStatus::Active;
        own.holder = Some("m".into());
        let mut urgent = entry("u");
        urgent.lane = Lane::Urgent;
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![urgent.clone(), own.clone()],
        );
        snapshot.trees.insert("own".into(), tree(declared(None)));
        snapshot.trees.insert("u".into(), tree(declared(None)));
        let outcome = pick_v2(&snapshot, &member("m"));
        assert_eq!(outcome.picked.as_ref().map(|p| p.entry.as_str()), Some("u"));
    }

    #[test]
    fn an_unpinned_member_takes_the_first_eligible_normal_entry() {
        let a = entry("a");
        let b = entry("b");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![a.clone(), b.clone()],
        );
        snapshot.trees.insert("a".into(), tree(declared(None)));
        snapshot.trees.insert("b".into(), tree(declared(None)));
        assert_eq!(
            pick_v2(&snapshot, &member("m"))
                .picked
                .as_ref()
                .map(|p| p.entry.as_str()),
            Some("a")
        );
    }

    #[test]
    fn an_active_entry_held_by_another_member_is_not_taken_by_anyone_else() {
        // Bob's fallback must not take an entry alice is running, even though
        // it would otherwise be the first eligible one. The open work lives in
        // another repo — alice's active entry holds hers (§2).
        let mut alices = entry("alices");
        alices.status = EntryStatus::Active;
        alices.holder = Some("alice".into());
        let mut open = entry("open");
        open.project = "other".into();
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![alices.clone(), open.clone()],
        );
        snapshot
            .trees
            .insert("alices".into(), tree(declared(None)));
        snapshot.trees.insert("open".into(), tree(declared(None)));

        let outcome = pick_v2(&snapshot, &member("bob"));
        assert_eq!(
            outcome.picked.as_ref().map(|p| p.entry.as_str()),
            Some("open")
        );
        assert_eq!(
            outcome
                .skips
                .iter()
                .find(|s| s.entry == "alices")
                .map(|s| s.reason),
            Some(SkipReason::Held)
        );
    }

    #[test]
    fn nothing_workable_anywhere_is_none_with_every_reason_reported() {
        let mut after = entry("after");
        after.after = vec!["missing".into()];
        let mut blocked = entry("blocked");
        blocked.status = EntryStatus::Blocked;
        let mut held = entry("held");
        held.status = EntryStatus::Active;
        held.holder = Some("alice".into());
        let mut repo = entry("repo");
        repo.project = "other".into(); // shares the repo `held` holds
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/softfig"),
            ],
            vec![after.clone(), blocked.clone(), held.clone(), repo.clone()],
        );
        snapshot.trees.insert("after".into(), tree(declared(None)));
        snapshot.trees.insert("blocked".into(), tree(declared(None)));
        snapshot.trees.insert("held".into(), tree(declared(None)));
        snapshot.trees.insert("repo".into(), tree(declared(None)));

        let outcome = pick_v2(&snapshot, &member("bob"));
        assert_eq!(outcome.picked, None);
        assert_eq!(
            outcome.skips,
            vec![
                Skip {
                    entry: "after".into(),
                    reason: SkipReason::AfterNotDone,
                },
                Skip {
                    entry: "blocked".into(),
                    reason: SkipReason::NotEligible,
                },
                Skip {
                    entry: "held".into(),
                    reason: SkipReason::Held,
                },
                Skip {
                    entry: "repo".into(),
                    reason: SkipReason::RepoHeld,
                },
            ]
        );
    }

    #[test]
    fn the_pick_reports_skips_in_file_order_and_never_the_assignment() {
        let mut u1 = entry("u1");
        u1.lane = Lane::Urgent;
        u1.project = "other".into();
        let mut u2 = entry("u2");
        u2.lane = Lane::Urgent;
        let n = entry("n");
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![u1.clone(), u2.clone(), n.clone()],
        );
        snapshot.trees.insert("u1".into(), tree(declared(None)));
        snapshot.trees.insert("u2".into(), tree(declared(None)));
        snapshot.trees.insert("n".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        let outcome = pick_v2(&snapshot, &m);
        assert_eq!(outcome.picked.as_ref().map(|p| p.entry.as_str()), Some("u2"));
        assert_eq!(
            outcome.skips,
            vec![Skip {
                entry: "u1".into(),
                reason: SkipReason::NotPinned,
            }],
            "only u1 was examined and skipped; the picked entry never appears"
        );
    }

    #[test]
    fn the_fallback_replaces_a_not_pinned_reason_with_the_real_one() {
        // In the pinned scans u1 records NotPinned; the fallback re-examines it
        // and finds the real reason (its after link is unfinished).
        let mut u1 = entry("u1");
        u1.lane = Lane::Urgent;
        u1.project = "other".into();
        u1.after = vec!["missing".into()];
        let mut pinned = entry("pinned");
        pinned.status = EntryStatus::Blocked; // nothing in-pin is eligible
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![u1.clone(), pinned.clone()],
        );
        snapshot.trees.insert("u1".into(), tree(declared(None)));
        snapshot
            .trees
            .insert("pinned".into(), tree(declared(None)));

        let mut m = member("m");
        m.pin = Some("softfig".into());
        let outcome = pick_v2(&snapshot, &m);
        assert_eq!(outcome.picked, None);
        assert_eq!(
            outcome.skips,
            vec![
                Skip {
                    entry: "u1".into(),
                    reason: SkipReason::AfterNotDone,
                },
                Skip {
                    entry: "pinned".into(),
                    reason: SkipReason::NotEligible,
                },
            ]
        );
    }

    #[test]
    fn step_2_prefers_the_active_entry_over_a_paused_one() {
        // The member holds an active entry AND a paused one: the active (the
        // running session's) wins. The active entry is urgent — the §9
        // preemption shape (the member rolled off the normal entry onto an
        // urgent one), and urgent is repo-rule exempt.
        let mut active = entry("active");
        active.lane = Lane::Urgent;
        active.status = EntryStatus::Active;
        active.holder = Some("m".into());
        let mut paused = entry("paused");
        paused.status = EntryStatus::Paused;
        paused.holder = Some("m".into());
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![paused.clone(), active.clone()],
        );
        snapshot.trees.insert("active".into(), tree(declared(None)));
        snapshot.trees.insert("paused".into(), tree(declared(None)));
        assert_eq!(
            pick_v2(&snapshot, &member("m"))
                .picked
                .as_ref()
                .map(|p| p.entry.as_str()),
            Some("active")
        );
    }

    #[test]
    fn step_2_prefers_the_last_paused_entry_in_file_order() {
        // Two paused-by-the-member entries: "last" is the last in file order —
        // the deterministic proxy the snapshot carries. Different repos, since
        // each pause holds its entry's repo (§2).
        let mut first = entry("first");
        first.status = EntryStatus::Paused;
        first.holder = Some("m".into());
        let mut last = entry("last");
        last.project = "other".into();
        last.status = EntryStatus::Paused;
        last.holder = Some("m".into());
        let mut snapshot = snap(
            vec![
                project("softfig", "~/projects/softfig"),
                project("other", "~/projects/other"),
            ],
            vec![first.clone(), last.clone()],
        );
        snapshot.trees.insert("first".into(), tree(declared(None)));
        snapshot.trees.insert("last".into(), tree(declared(None)));
        assert_eq!(
            pick_v2(&snapshot, &member("m"))
                .picked
                .as_ref()
                .map(|p| p.entry.as_str()),
            Some("last")
        );
    }

    #[test]
    fn the_picked_assignment_carries_the_units_declared_models() {
        let e = entry("e");
        let mut snapshot = snap(
            vec![project("softfig", "~/projects/softfig")],
            vec![e.clone()],
        );
        snapshot
            .trees
            .insert("e".into(), tree(declared(Some(list("reasoning, claude")))));
        let outcome = pick_v2(&snapshot, &claude("c"));
        let picked = outcome.picked.expect("the claude member takes the mixed list");
        assert_eq!(picked.entry, "e");
        assert_eq!(
            picked.unit,
            Unit::Slice {
                milestone: "e".into(),
                slice: "001".into(),
            }
        );
        assert_eq!(picked.declared, Some(list("reasoning, claude")));
    }

    // ---- the restack rule (§2, review 044 V8, report 123) -----------------

    /// A restack row: urgent, no branch of its own, no slice tree.
    fn restack(id: &str, status: EntryStatus) -> EntryView {
        let mut e = entry(id);
        e.kind = EntryKind::Restack;
        e.lane = Lane::Urgent;
        e.status = status;
        e
    }

    /// One project, these rows, and an open slice tree for every milestone.
    fn repo_snapshot(entries: Vec<EntryView>) -> V2Snapshot {
        let ids: Vec<String> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Milestone)
            .map(|e| e.id.clone())
            .collect();
        let mut snapshot = snap(vec![project("softfig", "~/projects/softfig")], entries);
        for id in ids {
            snapshot.trees.insert(id, tree(declared(None)));
        }
        snapshot
    }

    fn reason_for(outcome: &PickOutcome, id: &str) -> Option<SkipReason> {
        outcome.skips.iter().find(|s| s.entry == id).map(|s| s.reason)
    }

    #[test]
    fn a_live_restack_of_any_status_holds_its_repos_normal_entries() {
        for status in [
            EntryStatus::Queued,
            EntryStatus::Active,
            EntryStatus::Paused,
            EntryStatus::Blocked,
            EntryStatus::Deferred,
        ] {
            let mut r = restack("r", status);
            r.holder = (status == EntryStatus::Active).then(|| "other".to_string());
            let snapshot = repo_snapshot(vec![r, entry("n")]);
            assert_eq!(
                eligible(&snapshot, &member("m"), &snapshot.entries[1]),
                Err(SkipReason::RestackLive),
                "a {status:?} restack",
            );
        }
    }

    #[test]
    fn a_paused_normal_entry_does_not_resume_while_a_restack_is_live() {
        let mut paused = entry("n");
        paused.status = EntryStatus::Paused;
        paused.holder = Some("m".into());
        let snapshot = repo_snapshot(vec![restack("r", EntryStatus::Queued), paused]);

        let outcome = pick_v2(&snapshot, &member("m"));

        assert_eq!(
            outcome.picked.map(|p| p.entry),
            Some("r".to_string()),
            "a paused entry holds no session, so the restack starts",
        );
        assert_eq!(
            eligible(&snapshot, &member("m"), &snapshot.entries[1]),
            Err(SkipReason::RestackLive),
        );
    }

    #[test]
    fn queue_pick_lists_the_entry_a_live_restack_holds() {
        let snapshot = repo_snapshot(vec![restack("r", EntryStatus::Blocked), entry("n")]);
        let outcome = pick_v2(&snapshot, &member("m"));
        assert_eq!(outcome.picked, None);
        assert_eq!(reason_for(&outcome, "n"), Some(SkipReason::RestackLive));
    }

    #[test]
    fn an_active_entry_keeps_going_and_the_restack_waits_for_it() {
        let mut active = entry("n");
        active.status = EntryStatus::Active;
        active.holder = Some("alice".into());
        let snapshot = repo_snapshot(vec![restack("r", EntryStatus::Queued), active]);

        let holder = pick_v2(&snapshot, &member("alice"));
        assert_eq!(
            holder.picked.as_ref().map(|p| p.entry.as_str()),
            Some("n"),
            "a re-roll keeps going, so a restack can wait a whole entry",
        );
        assert_eq!(reason_for(&holder, "r"), Some(SkipReason::RestackWaits));

        let other = pick_v2(&snapshot, &member("bob"));
        assert_eq!(other.picked, None, "no member takes the restack");
        assert_eq!(reason_for(&other, "r"), Some(SkipReason::RestackWaits));
    }

    #[test]
    fn an_orphaned_active_entry_is_resumed_so_the_restack_is_not_stranded() {
        let mut orphan = entry("n");
        orphan.status = EntryStatus::Active;
        let snapshot = repo_snapshot(vec![restack("r", EntryStatus::Queued), orphan]);

        assert_eq!(
            pick_v2(&snapshot, &member("m")).picked.map(|p| p.entry),
            Some("n".to_string()),
        );
    }

    #[test]
    fn a_blocked_or_deferred_entry_does_not_hold_a_restack_back() {
        for status in [EntryStatus::Blocked, EntryStatus::Deferred, EntryStatus::Queued] {
            let mut waiting = entry("n");
            waiting.status = status;
            let snapshot = repo_snapshot(vec![restack("r", EntryStatus::Queued), waiting]);
            assert_eq!(
                pick_v2(&snapshot, &member("m")).picked.map(|p| p.entry),
                Some("r".to_string()),
                "a {status:?} entry runs no session",
            );
        }
    }

    #[test]
    fn the_restack_rule_keys_on_the_repo_not_the_project() {
        let repo = "~/projects/softfig";
        let mut sibling = entry("n");
        sibling.project = "sibling".into();
        let mut elsewhere = entry("x");
        elsewhere.project = "elsewhere".into();
        let mut snapshot = snap(
            vec![
                project("softfig", repo),
                project("sibling", repo),
                project("elsewhere", "~/projects/elsewhere"),
            ],
            vec![restack("r", EntryStatus::Blocked), sibling, elsewhere],
        );
        snapshot.trees.insert("n".into(), tree(declared(None)));
        snapshot.trees.insert("x".into(), tree(declared(None)));

        let outcome = pick_v2(&snapshot, &member("m"));

        assert_eq!(outcome.picked.as_ref().map(|p| p.entry.as_str()), Some("x"));
        assert_eq!(reason_for(&outcome, "n"), Some(SkipReason::RestackLive));
    }

    /// A restack names urgent branches too: they are stack candidates, and
    /// `main` moves under them like any other (§8). So the exclusion is both
    /// ways for an urgent entry that holds a session, though only a started
    /// restack stops one, and one waiting on a human never does.
    #[test]
    fn an_urgent_entry_and_a_restack_never_overlap() {
        let mut urgent = entry("u");
        urgent.lane = Lane::Urgent;
        urgent.status = EntryStatus::Active;
        urgent.holder = Some("alice".into());
        let snapshot = repo_snapshot(vec![urgent.clone(), restack("r", EntryStatus::Queued)]);
        assert_eq!(
            eligible(&snapshot, &member("bob"), &snapshot.entries[1]),
            Err(SkipReason::RestackWaits),
        );

        let mut paused = urgent.clone();
        paused.status = EntryStatus::Paused;
        paused.holder = None;
        for (status, verdict) in [
            (EntryStatus::Active, Some(SkipReason::RestackLive)),
            (EntryStatus::Paused, Some(SkipReason::RestackLive)),
            (EntryStatus::Queued, None),
            (EntryStatus::Blocked, None),
        ] {
            let snapshot = repo_snapshot(vec![restack("r", status), paused.clone()]);
            assert_eq!(
                eligible(&snapshot, &member("m"), &snapshot.entries[1]).err(),
                verdict,
                "beside a {status:?} restack",
            );
        }
    }

    #[test]
    fn a_second_restack_waits_for_the_running_one() {
        let mut first = restack("r1", EntryStatus::Active);
        first.holder = Some("alice".into());
        let snapshot = repo_snapshot(vec![first, restack("r2", EntryStatus::Queued)]);
        assert_eq!(
            eligible(&snapshot, &member("bob"), &snapshot.entries[1]),
            Err(SkipReason::RestackWaits),
        );
    }

    #[test]
    fn a_running_restack_keeps_going() {
        let mut running = restack("r", EntryStatus::Active);
        running.holder = Some("m".into());
        let snapshot = repo_snapshot(vec![running, entry("n")]);
        assert_eq!(
            pick_v2(&snapshot, &member("m")).picked.map(|p| p.entry),
            Some("r".to_string()),
        );
    }

    #[test]
    fn the_restack_skips_have_stable_slugs_and_say_what_they_mean() {
        assert_eq!(SkipReason::RestackLive.as_str(), "restack_live");
        assert_eq!(SkipReason::RestackWaits.as_str(), "restack_waits");
        assert!(SkipReason::RestackLive.describe().contains("restack"));
        assert!(SkipReason::RestackWaits.describe().contains("active"));
    }
}
