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
use softfig_ipc::queue_v2::{EntryKind, EntryStatus, Lane, SliceKind, SliceStatus};

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
    /// queue). `None` = unpinned: steps 1/3 have no filter to apply and the
    /// member goes straight to step 2 then the fallback.
    pub pin: Option<String>,
}

/// One `[[project]]` row, reduced to what the pick needs (§3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectView {
    pub name: String,
    /// The repo path or `host:path`. The repo rule keys on this; a value
    /// containing `:` is a remote project (grants §9).
    pub repo: String,
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
    /// First-claim time, UTC (§3.1). Carried for completeness; the pick does
    /// not order by it (stack order is `queue-v2-git`'s row).
    pub claimed: String,
    /// Consecutive follow-ups (§7). Carried for completeness; the cap is
    /// slice 010's row.
    pub follow_ups: u64,
    /// Who holds the entry. An `active` entry → the running member; a `paused`
    /// entry → the member that paused it (the step-2 resume preference), or
    /// `None` for a backend-mismatch pause (§6.3 step 5). Runtime state, not
    /// TOML — growlightd knows both at the moment they happen.
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
    pub models: Option<ModelList>,
}

/// A point-in-time view of the whole v2 list (§2, §3): every live entry in
/// file order, the live milestones' slice trees, and the archive's `done` ids
/// for `after` resolution. Assembled and validated by the v2 source (slice
/// 003); the pick never reads a file.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// An `active` entry held by a different member (§2 — an active entry is
    /// held by exactly one running member).
    Held,
    /// The entry's project is remote and the member runs opencode (grants §9,
    /// queue-v2-state finding 1).
    Remote,
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
    Blocked,
    /// No unit at all — a missing tree (fail closed; a close-out is never
    /// guessed over unseen work).
    NoUnit,
}

/// The repo an entry works on, joined from the snapshot's projects. A
/// validated snapshot guarantees every entry's project exists (writer
/// invariant 4); `None` is the defensive, fail-closed case.
fn repo_of<'a>(snapshot: &'a V2Snapshot, entry: &EntryView) -> Option<&'a str> {
    snapshot
        .projects
        .iter()
        .find(|p| p.name == entry.project)
        .map(|p| p.repo.as_str())
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
                SliceStatus::Blocked => return WalkOutcome::Blocked,
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
                SliceStatus::Blocked => return WalkOutcome::Blocked,
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
    if !matches!(
        entry.status,
        EntryStatus::Queued | EntryStatus::Active | EntryStatus::Paused
    ) {
        return Err(SkipReason::NotEligible);
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
    // 4. The holder rule: an `active` entry is held by exactly one running
    // member, and no other member takes it (§2). A `paused` entry has no
    // holder — anyone may resume it.
    if entry.status == EntryStatus::Active && entry.holder.as_deref() != Some(member.id.as_str())
    {
        return Err(SkipReason::Held);
    }
    // 5. The remote rule: an opencode member never takes a remote project's
    // entries (grants §9; queue-v2-state finding 1 — the repo is `host:path`).
    // A claude member is unaffected.
    if member.backend == Backend::Opencode && repo.contains(':') {
        return Err(SkipReason::Remote);
    }
    // 6 + 7. The next unit, then the §6.4 backend match on its declared list
    // (`None` = the member default, which always runs on the member's own
    // backend).
    match next_unit(snapshot, entry) {
        WalkOutcome::Unit { unit, models } => {
            if let Some(list) = &models {
                if !list.backend_can_run(member.backend) {
                    return Err(SkipReason::BackendMismatch);
                }
            }
            Ok((unit, models))
        }
        WalkOutcome::Blocked => Err(SkipReason::BlockedWalk),
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
        if let Some(pin) = pin {
            if entry.project != pin {
                record(reasons, index, SkipReason::NotPinned);
                continue;
            }
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
/// An unpinned member skips steps 1/3 (there is no pinned project to filter
/// by) and lands on step 2 then the fallback. `None` when nothing is workable
/// for this member anywhere.
pub fn pick_v2(snapshot: &V2Snapshot, member: &Member) -> PickOutcome {
    let mut reasons: Vec<Option<SkipReason>> = vec![None; snapshot.entries.len()];
    let mut picked: Option<(usize, Unit, Option<ModelList>)> = None;

    // 1. Urgent lane, pinned project.
    if member.pin.is_some() {
        picked = scan_lane(
            snapshot,
            member,
            Lane::Urgent,
            member.pin.as_deref(),
            &mut reasons,
        );
    }

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

    // 3. Normal lane, pinned project.
    if picked.is_none() && member.pin.is_some() {
        picked = scan_lane(
            snapshot,
            member,
            Lane::Normal,
            member.pin.as_deref(),
            &mut reasons,
        );
    }

    // 4. Fallback: repeat 1 and 3 with no pin filter.
    if picked.is_none() {
        picked = scan_lane(snapshot, member, Lane::Urgent, None, &mut reasons);
    }
    if picked.is_none() {
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
            claimed: String::new(),
            follow_ups: 0,
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
        }
    }

    fn snap(projects: Vec<ProjectView>, entries: Vec<EntryView>) -> V2Snapshot {
        V2Snapshot {
            projects,
            entries,
            trees: BTreeMap::new(),
            done_ids: BTreeSet::new(),
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
        assert_eq!(next_unit(&snapshot, &e), WalkOutcome::Blocked);
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
        assert_eq!(next_unit(&snapshot, &e), WalkOutcome::Blocked);
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
        assert_eq!(next_unit(&snapshot, &e), WalkOutcome::Blocked);
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
}
