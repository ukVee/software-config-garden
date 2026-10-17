//! The queue-v2 handshake's **execution** half (queue-v2-scheduling slice
//! 009): spec-growlight-queue §6.3 step 3 for a member verb that
//! [`crate::member_verbs::validate`] passed — keeperd commits the state change,
//! growlightd stores the baton as the entry's (§3.6), and the reply names what
//! runs next. Steps 4–5 (terminate after `roll_grace_secs`, then pick) are the
//! drive loop's: the server hands it a [`V2Handoff`] through the daemon.
//!
//! ## Shape
//!
//! [`plan`] is pure: from the validated call and the snapshot it was validated
//! against, the ordered keeperd writes ([`KeeperOp`], slice 005's daemon ops
//! plus the human `slice_insert` for `new_scope`) and what runs next.
//! [`execute`] issues them through the [`V2Keeper`] seam and stores the baton.
//!
//! ## The commit point
//!
//! keeperd's ops are one commit each, so a handoff is several commits, not one
//! transaction. The **first** op is the commit point: it is always the §3.5
//! session-log line, so if it fails nothing has changed and the call errors
//! with the session still running (the agent retries). Once it lands the
//! handoff stands — a retry would re-log and then refuse on the moved state —
//! so every later write is best-effort: a failure becomes a reply warning and
//! a journal line, never a half-handed-off session left waiting.
//!
//! The ops after the log are ordered so a later failure leaves the list
//! coherent: `new_scope` re-queues the raised-from slice BEFORE inserting the
//! new one (a failed insert just resumes the same slice; the reverse order
//! would leave two `active` candidates and a refused claim), and a pending
//! human status change (finding 8) is applied last, so a failure leaves it
//! pending for the next boundary.

use std::fmt;

use softfig_ipc::growlightd::{
    AddSubMilestoneArgs, BlockKind, CompleteEntryArgs, EntryOutcome, NewSliceArgs, NextUnit,
    RollReason,
};
use softfig_ipc::model_choice::ModelChoice;
use softfig_ipc::queue_v2::{EntryStatus, SliceKind, SliceStatus};
use softfig_ipc::verbs::{DaemonStatusArg, DeferredTestSpec};

use crate::baton_store::FsEntryBatonStore;
use crate::drive_loop::{model_ref_label, V2Assignment};
use crate::member_verbs::{unit_label, MemberVerb, Validated};
use crate::scheduler_v2::{next_unit, ItemView, TreeView, Unit, V2Snapshot, WalkOutcome};

/// The cost field of a §3.5 session-log line. The verb ends the session from
/// inside it, so the session's spend is not known yet (an opencode session's
/// final cost settles only after it exits); the field keeps its position for
/// the reliability ledger's parse and says so.
pub const COST_UNKNOWN: &str = "$?";

/// One keeperd write the handshake issues, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeeperOp {
    /// `queue_v2_session_log` — the §3.5 line's tail (keeperd stamps the time).
    SessionLog {
        entry: String,
        unit: Option<String>,
        line: String,
    },
    /// `queue_v2_set_status` — entry level when `unit` is `None`.
    SetStatus {
        entry: String,
        unit: Option<String>,
        new: DaemonStatusArg,
    },
    /// `queue_v2_follow_ups` — the absolute count (§7).
    FollowUps {
        entry: String,
        unit: Option<String>,
        count: u64,
    },
    /// `queue_v2_deferred` — §6.5's `deferred_tests`.
    Deferred {
        entry: String,
        tests: Vec<DeferredTestSpec>,
    },
    /// `slice_insert` — `new_scope`'s slice, placed immediately before the
    /// slice it was raised from (§4: "immediately next").
    SliceInsert {
        milestone: String,
        slug: String,
        title: String,
        body: String,
        before: String,
    },
    /// `queue_v2_add_sub` — §7: keeperd creates `<milestone>/<slug>` from the
    /// member's fields and marks `slice` `split`, placing the sub right after
    /// it (or at the end with `at_end`), in one commit.
    AddSub {
        milestone: String,
        slice: String,
        slug: String,
        title: String,
        mission: String,
        finish_criteria: String,
        slices: Vec<NewSliceArgs>,
        at_end: bool,
    },
}

impl KeeperOp {
    /// The op's wire name, for warnings and the journal.
    pub fn name(&self) -> &'static str {
        match self {
            KeeperOp::SessionLog { .. } => "queue_v2_session_log",
            KeeperOp::SetStatus { .. } => "queue_v2_set_status",
            KeeperOp::FollowUps { .. } => "queue_v2_follow_ups",
            KeeperOp::Deferred { .. } => "queue_v2_deferred",
            KeeperOp::SliceInsert { .. } => "slice_insert",
            KeeperOp::AddSub { .. } => "queue_v2_add_sub",
        }
    }
}

/// What a landed [`KeeperOp`] reported back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeeperOutcome {
    /// Written; nothing to report.
    Done,
    /// `queue_v2_set_status`: the status that actually landed (a pending
    /// human change overrides the requested one).
    Status(String),
    /// `slice_insert`: the new slice's id.
    Inserted(String),
}

/// growlightd's write seam into keeperd for the handshake's commit. The live
/// impl is [`crate::claim::KeeperdV2Keeper`] over the keeperd socket; tests
/// record the ops.
pub trait V2Keeper: Send + Sync + fmt::Debug {
    /// Issue one op. `Err` carries keeperd's refusal or the transport failure.
    fn apply(&self, op: &KeeperOp) -> Result<KeeperOutcome, String>;

    /// Issue a human verb to keeperd as growlightd's own client — no member
    /// on the request — and return keeperd's response verbatim, refusal
    /// included: a member's §6.7-checked `slice_insert` / `slice_update`
    /// ([`crate::member_slices`]), whose reply the member reads as keeperd's.
    fn relay(&self, req: &softfig_ipc::Request) -> softfig_ipc::Response;
}

/// The server-side handshake seams, installed on the daemon at boot
/// ([`crate::daemon::Daemon::with_v2_handoff`]).
#[derive(Debug)]
pub struct HandoffSeams {
    /// keeperd's v2 write ops.
    pub keeper: Box<dyn V2Keeper>,
    /// The per-entry baton store (§3.6) — the same runtime namespace the drive
    /// loop copies from at spawn.
    pub entries: FsEntryBatonStore,
}

/// A committed handoff, handed from the server to the drive loop through the
/// daemon: what step 4 terminates and step 5 picks after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Handoff {
    /// The assignment the session held.
    pub assignment: V2Assignment,
    /// The verb that ended it.
    pub verb: &'static str,
    /// Whether the entry is still `active` work after the commit — the member
    /// re-picks with it reserved, and it becomes `paused` if the member moves
    /// on (§6.3 step 5). `false` once it completed, deferred or blocked.
    pub continues: bool,
    /// A model change the next session of the same unit runs on (§6.4).
    pub next_model: Option<ModelChoice>,
    /// `growlight_block`'s `@human` alert text (§6.6).
    pub alert: Option<String>,
}

impl V2Handoff {
    /// The top-level entry id (the queue.toml row the assignment names).
    pub fn entry_top(&self) -> &str {
        entry_top(&self.assignment.entry)
    }
}

/// What [`execute`] did, for the reply and the drive loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    pub handoff: V2Handoff,
    /// What runs next for the entry (§6.3 step 3's `next`); `None` once the
    /// entry is no longer active work.
    pub next: Option<NextUnit>,
    /// Writes that failed after the commit point; the handoff stands.
    pub warnings: Vec<String>,
}

/// What runs next, as far as the plan knows before executing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextPlan {
    /// The entry leaves active work (completed, deferred, blocked).
    None,
    /// A known unit.
    Unit(NextUnit),
    /// `new_scope`'s slice, whose id keeperd assigns at insert; if the insert
    /// fails, the raised-from unit runs next instead.
    Inserted { milestone: String, fallback: NextUnit },
    /// `growlight_add_sub_milestone`: `next` once keeperd created the sub (its
    /// slice ids are known in advance — a new folder numbers from 001); if the
    /// creation fails after the commit point, nothing was split and the slice
    /// it was filed from (`fallback`) runs again.
    SubAdded { next: Option<NextUnit>, fallback: NextUnit },
}

/// The ordered keeperd writes plus what follows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// In issue order; `ops[0]` is the commit point (always the session log).
    pub ops: Vec<KeeperOp>,
    /// Whether the entry stays active work (before any pending human change).
    pub continues: bool,
    pub next: NextPlan,
    /// `growlight_block`'s alert text.
    pub alert: Option<String>,
}

fn entry_top(entry: &str) -> &str {
    entry.split('/').next().unwrap_or(entry)
}

/// Where a unit's unit-level ops are addressed (slice 005's addressing): a
/// slice by its milestone identity + id, a close-out by its milestone, a task
/// or restack by the entry itself.
fn unit_addr(entry: &str, unit: &Unit) -> (String, Option<String>) {
    match unit {
        Unit::Slice { milestone, slice } => (milestone.clone(), Some(slice.clone())),
        Unit::CloseOut { milestone } => (milestone.clone(), None),
        Unit::Entry => (entry.to_string(), None),
    }
}

/// `unit` as a [`NextUnit`]: a slice names its milestone identity, anything
/// else the entry.
pub fn next_of(entry: &str, unit: &Unit) -> NextUnit {
    NextUnit {
        entry: match unit {
            Unit::Slice { milestone, .. } | Unit::CloseOut { milestone } => milestone.clone(),
            Unit::Entry => entry.to_string(),
        },
        unit: unit_label(unit),
    }
}

/// The §3.5 line's tail (keeperd stamps `- <utc> · `): the second field is the
/// roll reason or `completed` / `deferred` / `blocked`, then the session's
/// model, the member and the cost, then the verb's own note (a summary or the
/// block reason) when it has one.
pub fn session_line(kind: &str, assignment: &V2Assignment, member: &str, note: Option<&str>) -> String {
    let mut line = format!(
        "{kind} · {} · member {member} · {COST_UNKNOWN}",
        model_ref_label(&assignment.resolved_model)
    );
    if let Some(note) = note.map(str::trim).filter(|n| !n.is_empty()) {
        line.push_str(" · ");
        // The log is one line per session; fold any newline the agent sent.
        line.push_str(&note.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    line
}

fn pending_arg(status: EntryStatus) -> Option<DaemonStatusArg> {
    match status {
        EntryStatus::Queued => Some(DaemonStatusArg::Queued),
        EntryStatus::Paused => Some(DaemonStatusArg::Paused),
        EntryStatus::Blocked => Some(DaemonStatusArg::Blocked),
        EntryStatus::Deferred => Some(DaemonStatusArg::Deferred),
        EntryStatus::Active => None,
    }
}

/// The unit's consecutive follow-ups (§7): the slice's own, or the entry's
/// for a task, restack or close-out.
fn follow_ups(snapshot: &V2Snapshot, entry: &str, unit: &Unit) -> u64 {
    match unit {
        Unit::Slice { milestone, slice } => snapshot
            .trees
            .get(milestone)
            .and_then(|t| t.items.iter().find(|i| i.kind == SliceKind::Slice && &i.id == slice))
            .map_or(0, |i| i.follow_ups),
        Unit::CloseOut { .. } | Unit::Entry => snapshot
            .entries
            .iter()
            .find(|e| e.id == entry)
            .map_or(0, |e| e.follow_ups),
    }
}

/// The entry's next unit over `after` (the snapshot as the commit leaves it):
/// the §4 walk. `None` when the walk stops (a `blocked` item, a missing tree).
fn walk_next(after: &V2Snapshot, entry: &str) -> Option<NextUnit> {
    let view = after.entries.iter().find(|e| e.id == entry)?;
    match next_unit(after, view) {
        WalkOutcome::Unit { unit, .. } => Some(next_of(entry, &unit)),
        WalkOutcome::Blocked | WalkOutcome::NoUnit => None,
    }
}

/// The snapshot with one item of `milestone`'s tree set to `status`.
fn with_item(snapshot: &V2Snapshot, milestone: &str, kind: SliceKind, id: &str, status: SliceStatus) -> V2Snapshot {
    let mut after = snapshot.clone();
    if let Some(item) = after
        .trees
        .get_mut(milestone)
        .and_then(|t| t.items.iter_mut().find(|i| i.kind == kind && i.id == id))
    {
        item.status = status;
    }
    after
}

/// The entry's next unit once `slice` of `milestone` is done.
fn next_after_done(snapshot: &V2Snapshot, entry: &str, milestone: &str, slice: &str) -> Option<NextUnit> {
    walk_next(
        &with_item(snapshot, milestone, SliceKind::Slice, slice, SliceStatus::Done),
        entry,
    )
}

/// The entry's next unit once `slice` of `milestone` is `split` into a new sub
/// `<milestone>/<slug>` placed as keeperd's `queue_v2_add_sub` places it:
/// right after the slice, or at the end with `at_end`. The new tree's slices
/// are `001…` (a new folder), all `queued`, inheriting the parent's chain.
fn next_after_split(
    snapshot: &V2Snapshot,
    entry: &str,
    milestone: &str,
    slice: &str,
    a: &AddSubMilestoneArgs,
) -> Option<NextUnit> {
    let mut after = with_item(snapshot, milestone, SliceKind::Slice, slice, SliceStatus::Split);
    let tree = after.trees.get_mut(milestone)?;
    let models = tree.models.clone();
    let sub = ItemView {
        kind: SliceKind::Sub,
        id: a.slug.clone(),
        status: SliceStatus::Queued,
        models: None,
        follow_ups: 0,
    };
    let at = if a.do_not_prioritize {
        tree.items.len()
    } else {
        tree.items.iter().position(|i| i.kind == SliceKind::Slice && i.id == slice)? + 1
    };
    tree.items.insert(at, sub);
    let items = (1..=a.slices.len())
        .map(|n| ItemView {
            kind: SliceKind::Slice,
            id: format!("{n:03}"),
            status: SliceStatus::Queued,
            models: models.clone(),
            follow_ups: 0,
        })
        .collect();
    after
        .trees
        .insert(format!("{milestone}/{}", a.slug), TreeView { items, models });
    walk_next(&after, entry)
}

/// §6.3 step 3, planned: the keeperd writes for a validated verb and what runs
/// next. Pure over the snapshot the call was validated against. `None` only
/// for a verb on a unit its validation never passes (`complete_slice` or
/// `add_sub_milestone` off a slice).
pub fn plan(v: &Validated, snapshot: &V2Snapshot) -> Option<Plan> {
    let a = &v.assignment;
    let entry = entry_top(&a.entry);
    let (uentry, uunit) = unit_addr(entry, &a.unit);
    let log = |kind: &str, note: Option<&str>| KeeperOp::SessionLog {
        entry: uentry.clone(),
        unit: uunit.clone(),
        line: session_line(kind, a, &v.member, note),
    };
    let entry_status = |new| KeeperOp::SetStatus {
        entry: entry.to_string(),
        unit: None,
        new,
    };

    let mut plan = match &v.verb {
        MemberVerb::AddFollowUpSession(args) => {
            let reason = v.reason.unwrap_or(RollReason::SessionFault);
            let mut ops = vec![log(reason.as_str(), None)];
            let current = next_of(entry, &a.unit);
            let mut next = NextPlan::Unit(current.clone());
            if let (RollReason::NewScope, Unit::Slice { milestone, slice }, Some(new)) =
                (reason, &a.unit, &args.new_slice)
            {
                // The raised-from slice steps back to `queued` first, so the
                // new slice in front of it is the walk's first open item and
                // the claim never meets two `active` slices.
                ops.push(KeeperOp::SetStatus {
                    entry: milestone.clone(),
                    unit: Some(slice.clone()),
                    new: DaemonStatusArg::Queued,
                });
                ops.push(KeeperOp::SliceInsert {
                    milestone: milestone.clone(),
                    slug: new.slug.clone(),
                    title: new.title.clone(),
                    body: new.body.clone(),
                    before: slice.clone(),
                });
                next = NextPlan::Inserted {
                    milestone: milestone.clone(),
                    fallback: current,
                };
            }
            if reason.counts_toward_cap() {
                // §7: every reason but `preempted` adds one, on the unit it
                // was raised from.
                ops.push(KeeperOp::FollowUps {
                    entry: uentry.clone(),
                    unit: uunit.clone(),
                    count: follow_ups(snapshot, entry, &a.unit) + 1,
                });
            }
            Plan {
                ops,
                continues: true,
                next,
                alert: None,
            }
        }
        MemberVerb::CompleteSlice(args) => {
            let Unit::Slice { milestone, slice } = &a.unit else {
                return None; // validated: complete_slice runs on a slice only
            };
            // `done` resets the slice's follow_ups (slice 005's op), so the
            // §7 completion reset needs no write of its own.
            let ops = vec![
                log("completed", Some(&args.summary)),
                KeeperOp::SetStatus {
                    entry: milestone.clone(),
                    unit: Some(slice.clone()),
                    new: DaemonStatusArg::Done,
                },
            ];
            let next = match next_after_done(snapshot, entry, milestone, slice) {
                Some(next) => NextPlan::Unit(next),
                None => NextPlan::None,
            };
            Plan {
                ops,
                continues: true,
                next,
                alert: None,
            }
        }
        MemberVerb::CompleteEntry(args) => {
            if let Unit::CloseOut { milestone } = &a.unit {
                if milestone.contains('/') {
                    return Some(plan_sub_close_out(v, snapshot, milestone, args, log));
                }
            }
            let ops = match args.outcome {
                // The log lands before `done` archives the row (the op
                // addresses live rows only).
                EntryOutcome::Done => vec![
                    log("completed", Some(&args.summary)),
                    entry_status(DaemonStatusArg::Done),
                ],
                EntryOutcome::Deferred => {
                    let mut ops = vec![
                        log("deferred", Some(&args.summary)),
                        KeeperOp::Deferred {
                            entry: entry.to_string(),
                            tests: args.deferred_tests.clone().unwrap_or_default(),
                        },
                    ];
                    // §7: completion resets the entry's counter.
                    if follow_ups(snapshot, entry, &Unit::Entry) > 0 {
                        ops.push(KeeperOp::FollowUps {
                            entry: entry.to_string(),
                            unit: None,
                            count: 0,
                        });
                    }
                    ops.push(entry_status(DaemonStatusArg::Deferred));
                    ops
                }
            };
            Plan {
                ops,
                continues: false,
                next: NextPlan::None,
                alert: None,
            }
        }
        MemberVerb::Block(args) => {
            let kind = match args.kind {
                BlockKind::Human => "human",
                BlockKind::Stuck => "stuck",
            };
            let note = format!("{kind}: {}", args.reason);
            Plan {
                // §6.6: the entry blocks; the unit stays `active` and keeps
                // its counter, and the block never counts toward the cap.
                ops: vec![log("blocked", Some(&note)), entry_status(DaemonStatusArg::Blocked)],
                continues: false,
                next: NextPlan::None,
                alert: Some(format!("{} ({note})", a.entry)),
            }
        }
        MemberVerb::AddSubMilestone(args) => {
            let Unit::Slice { milestone, slice } = &a.unit else {
                return None; // validated: a sub-milestone is filed from a slice only
            };
            let identity = format!("{milestone}/{}", args.slug);
            // §3.5 has no reason word for a split; the line records the
            // slice's resulting status and the sub that took its work.
            let note = format!("sub-milestone {identity}: {}", args.title);
            Plan {
                ops: vec![
                    log("split", Some(&note)),
                    KeeperOp::AddSub {
                        milestone: milestone.clone(),
                        slice: slice.clone(),
                        slug: args.slug.clone(),
                        title: args.title.clone(),
                        mission: args.mission.clone(),
                        finish_criteria: args.finish_criteria.clone(),
                        slices: args.slices.clone(),
                        at_end: args.do_not_prioritize,
                    },
                ],
                continues: true,
                next: NextPlan::SubAdded {
                    next: next_after_split(snapshot, entry, milestone, slice, args),
                    fallback: next_of(entry, &a.unit),
                },
                alert: None,
            }
        }
    };

    apply_pending(&mut plan, snapshot, entry);
    Some(plan)
}

/// Finding 8 (§6.8): a human status change recorded on the active entry takes
/// effect at this boundary. A verb that sets the entry's status anyway gets it
/// applied by that op (pending wins); one that leaves the entry active applies
/// it here, last.
fn apply_pending(plan: &mut Plan, snapshot: &V2Snapshot, entry: &str) {
    if !plan.continues {
        return;
    }
    if let Some(pending) = snapshot
        .entries
        .iter()
        .find(|e| e.id == entry)
        .and_then(|e| e.pending)
        .and_then(pending_arg)
    {
        plan.ops.push(KeeperOp::SetStatus {
            entry: entry.to_string(),
            unit: None,
            new: pending,
        });
    }
}

/// `growlight_complete_entry` on a sub-milestone's close-out (§6.5 applied to
/// a sub): it completes the SUB — its item in the parent's list goes `done`
/// or `deferred` — and never the entry, which stays active work on the
/// parent's next unit. `deferred` writes the tests into the sub's own
/// `## Deferred verification`. The close-out's follow-ups count on the
/// entry's counter (§6.5), so completing it resets that counter (§7).
fn plan_sub_close_out(
    v: &Validated,
    snapshot: &V2Snapshot,
    milestone: &str,
    args: &CompleteEntryArgs,
    log: impl Fn(&str, Option<&str>) -> KeeperOp,
) -> Plan {
    let entry = entry_top(&v.assignment.entry);
    let (parent, sub) = milestone.rsplit_once('/').expect("a sub-milestone identity");
    let (kind, status, arg) = match args.outcome {
        EntryOutcome::Done => ("completed", SliceStatus::Done, DaemonStatusArg::Done),
        EntryOutcome::Deferred => ("deferred", SliceStatus::Deferred, DaemonStatusArg::Deferred),
    };
    let mut ops = vec![log(kind, Some(&args.summary))];
    if args.outcome == EntryOutcome::Deferred {
        ops.push(KeeperOp::Deferred {
            entry: milestone.to_string(),
            tests: args.deferred_tests.clone().unwrap_or_default(),
        });
    }
    if follow_ups(snapshot, entry, &v.assignment.unit) > 0 {
        ops.push(KeeperOp::FollowUps {
            entry: milestone.to_string(),
            unit: None,
            count: 0,
        });
    }
    // Last: once the item closes, the walk moves on past the sub.
    ops.push(KeeperOp::SetStatus {
        entry: parent.to_string(),
        unit: Some(sub.to_string()),
        new: arg,
    });
    let after = with_item(snapshot, parent, SliceKind::Sub, sub, status);
    let mut plan = Plan {
        ops,
        continues: true,
        next: match walk_next(&after, entry) {
            Some(next) => NextPlan::Unit(next),
            None => NextPlan::None,
        },
        alert: None,
    };
    apply_pending(&mut plan, snapshot, entry);
    plan
}

/// §6.3 step 3: issue the planned writes and store the baton as the entry's.
/// `Err` only when the commit point (the first op) failed — nothing changed,
/// and the session keeps running so the agent can retry.
pub fn execute(v: &Validated, snapshot: &V2Snapshot, seams: &HandoffSeams) -> Result<Executed, String> {
    let plan = plan(v, snapshot)
        .ok_or_else(|| format!("{} has no handshake execution here", v.verb.name()))?;
    let entry = entry_top(&v.assignment.entry).to_string();
    let mut warnings = Vec::new();
    let mut entry_landed: Option<String> = None;
    let mut inserted: Option<String> = None;
    let mut sub_added = false;
    for (i, op) in plan.ops.iter().enumerate() {
        let landed = seams.keeper.apply(op);
        if landed.is_ok() && matches!(op, KeeperOp::AddSub { .. }) {
            sub_added = true;
        }
        match landed {
            Ok(KeeperOutcome::Status(status)) => {
                if matches!(op, KeeperOp::SetStatus { unit: None, .. }) {
                    entry_landed = Some(status);
                }
            }
            Ok(KeeperOutcome::Inserted(id)) => inserted = Some(id),
            Ok(KeeperOutcome::Done) => {}
            Err(e) if i == 0 => {
                return Err(format!(
                    "the handoff did not commit ({} failed: {e}) — nothing was written; \
                     this session keeps running, so retry the call",
                    op.name()
                ))
            }
            Err(e) => warnings.push(format!("{} failed after the handoff committed: {e}", op.name())),
        }
    }
    // §3.6: the verb's baton becomes the entry's, whichever member resumes it.
    if let Err(e) = seams.entries.write(&entry, v.verb.baton()) {
        warnings.push(format!(
            "storing the baton as entry {entry}'s failed: {e} — the next session resumes \
             from the previous one"
        ));
    }
    // A pending human change that landed takes the entry out of active work.
    let continues = plan.continues && entry_landed.as_deref().is_none_or(|s| s == "active");
    let next = if !continues {
        None
    } else {
        match plan.next {
            NextPlan::None => None,
            NextPlan::Unit(next) => Some(next),
            NextPlan::Inserted { milestone, fallback } => Some(match inserted {
                Some(id) => NextUnit {
                    entry: milestone,
                    unit: id,
                },
                None => fallback,
            }),
            NextPlan::SubAdded { next, fallback } => {
                if sub_added {
                    next
                } else {
                    Some(fallback)
                }
            }
        }
    };
    Ok(Executed {
        handoff: V2Handoff {
            assignment: v.assignment.clone(),
            verb: v.verb.name(),
            continues,
            next_model: v.next_model.clone(),
            alert: plan.alert,
        },
        next,
        warnings,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    use softfig_ipc::growlightd::{
        AddFollowUpSessionArgs, AddSubMilestoneArgs, BlockArgs, CompleteEntryArgs,
        CompleteSliceArgs, NewSliceArgs,
    };
    use softfig_ipc::queue_v2::{EntryKind, Lane};

    use crate::scheduler_v2::{EntryView, ItemView, ProjectView, TreeView};

    /// A recording [`V2Keeper`]: every op lands, or the op at `fail_at` fails.
    #[derive(Debug, Default)]
    pub(crate) struct SpyKeeper {
        pub ops: Mutex<Vec<KeeperOp>>,
        pub fail_at: Option<usize>,
        /// What an entry-level `set_status` reports landed (a pending override).
        pub entry_status: Option<String>,
        /// Every human verb relayed to keeperd ([`V2Keeper::relay`]).
        pub relayed: Mutex<Vec<softfig_ipc::Request>>,
    }

    impl V2Keeper for SpyKeeper {
        fn apply(&self, op: &KeeperOp) -> Result<KeeperOutcome, String> {
            let mut ops = self.ops.lock().unwrap();
            let i = ops.len();
            ops.push(op.clone());
            if self.fail_at == Some(i) {
                return Err("keeperd unreachable".into());
            }
            Ok(match op {
                KeeperOp::SetStatus { unit: None, new, .. } => KeeperOutcome::Status(
                    self.entry_status
                        .clone()
                        .unwrap_or_else(|| serde_json::to_value(new).unwrap().as_str().unwrap().into()),
                ),
                KeeperOp::SetStatus { new, .. } => {
                    KeeperOutcome::Status(serde_json::to_value(new).unwrap().as_str().unwrap().into())
                }
                KeeperOp::SliceInsert { .. } => KeeperOutcome::Inserted("004".into()),
                _ => KeeperOutcome::Done,
            })
        }

        /// Records the relayed request; answers as keeperd would on a pass.
        fn relay(&self, req: &softfig_ipc::Request) -> softfig_ipc::Response {
            self.relayed.lock().unwrap().push(req.clone());
            softfig_ipc::Response::ok(serde_json::json!({ "relayed": req.op }))
        }
    }

    /// The `Arc` shape, so a test keeps a handle on the ops the seam's box
    /// recorded.
    impl V2Keeper for std::sync::Arc<SpyKeeper> {
        fn apply(&self, op: &KeeperOp) -> Result<KeeperOutcome, String> {
            (**self).apply(op)
        }

        fn relay(&self, req: &softfig_ipc::Request) -> softfig_ipc::Response {
            (**self).relay(req)
        }
    }

    const BATON: &str = "---\nstatus: IN_PROGRESS\nitem: m1\n---\n# NEXT ACTION\nnext\n";

    fn slice(id: &str, status: SliceStatus, follow_ups: u64) -> ItemView {
        ItemView {
            kind: SliceKind::Slice,
            id: id.into(),
            status,
            models: None,
            follow_ups,
        }
    }

    fn snapshot(items: Vec<ItemView>) -> V2Snapshot {
        V2Snapshot {
            projects: vec![ProjectView {
                name: "softfig".into(),
                repo: "/garden".into(),
            }],
            entries: vec![EntryView {
                id: "m1".into(),
                kind: EntryKind::Milestone,
                project: "softfig".into(),
                lane: Lane::Normal,
                status: EntryStatus::Active,
                after: vec![],
                claimed: "2026-10-14T00:00Z".into(),
                follow_ups: 2,
                pending: None,
                holder: None,
                models: None,
            }],
            trees: [(
                "m1".to_string(),
                TreeView {
                    items,
                    models: None,
                },
            )]
            .into_iter()
            .collect(),
            done_ids: Default::default(),
        }
    }

    fn assignment(unit: Unit) -> V2Assignment {
        V2Assignment {
            agent: "a1".into(),
            entry: "m1".into(),
            unit,
            resolved_model: ModelChoice::opencode("deepseek/deepseek-flash"),
        }
    }

    fn on_slice(id: &str) -> Unit {
        Unit::Slice {
            milestone: "m1".into(),
            slice: id.into(),
        }
    }

    fn validated(unit: Unit, verb: MemberVerb, reason: Option<RollReason>) -> Validated {
        Validated {
            member: "a1".into(),
            assignment: assignment(unit),
            verb,
            reason,
            next_model: None,
        }
    }

    fn follow_up(reason: RollReason, new_slice: Option<NewSliceArgs>) -> Validated {
        validated(
            on_slice("002"),
            MemberVerb::AddFollowUpSession(AddFollowUpSessionArgs {
                reason: reason.as_str().into(),
                baton: BATON.into(),
                model: None,
                variant: None,
                new_slice,
            }),
            Some(reason),
        )
    }

    fn log_line(ops: &[KeeperOp]) -> &str {
        match &ops[0] {
            KeeperOp::SessionLog { line, .. } => line,
            other => panic!("the commit point is the session log, not {other:?}"),
        }
    }

    fn seams(keeper: SpyKeeper) -> (HandoffSeams, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "handoff-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        (
            HandoffSeams {
                keeper: Box::new(keeper),
                entries: FsEntryBatonStore::new(dir.clone(), "garden"),
            },
            dir,
        )
    }

    #[test]
    fn a_counted_follow_up_logs_then_counts_on_its_slice_and_resumes_it() {
        let snap = snapshot(vec![
            slice("001", SliceStatus::Done, 0),
            slice("002", SliceStatus::Active, 3),
        ]);
        let p = plan(&follow_up(RollReason::ContextFull, None), &snap).unwrap();
        assert_eq!(
            log_line(&p.ops),
            "context_full · deepseek/deepseek-flash · member a1 · $?"
        );
        assert_eq!(
            p.ops[1..],
            [KeeperOp::FollowUps {
                entry: "m1".into(),
                unit: Some("002".into()),
                count: 4,
            }],
            "the slice's counter goes 3 → 4; no status moves",
        );
        assert!(p.continues);
        assert_eq!(
            p.next,
            NextPlan::Unit(NextUnit {
                entry: "m1".into(),
                unit: "002".into()
            })
        );
    }

    #[test]
    fn a_preempted_follow_up_only_logs() {
        let snap = snapshot(vec![slice("002", SliceStatus::Active, 3)]);
        let p = plan(&follow_up(RollReason::Preempted, None), &snap).unwrap();
        assert_eq!(p.ops.len(), 1, "§5/§7: preempted never counts: {:?}", p.ops);
    }

    #[test]
    fn new_scope_requeues_the_slice_before_inserting_the_new_one_in_front() {
        let snap = snapshot(vec![slice("002", SliceStatus::Active, 0)]);
        let new = NewSliceArgs {
            slug: "found-work".into(),
            title: "Found work".into(),
            body: "do it".into(),
        };
        let p = plan(&follow_up(RollReason::NewScope, Some(new)), &snap).unwrap();
        assert_eq!(
            p.ops[1..],
            [
                KeeperOp::SetStatus {
                    entry: "m1".into(),
                    unit: Some("002".into()),
                    new: DaemonStatusArg::Queued,
                },
                KeeperOp::SliceInsert {
                    milestone: "m1".into(),
                    slug: "found-work".into(),
                    title: "Found work".into(),
                    body: "do it".into(),
                    before: "002".into(),
                },
                KeeperOp::FollowUps {
                    entry: "m1".into(),
                    unit: Some("002".into()),
                    count: 1,
                },
            ],
        );
        assert!(matches!(p.next, NextPlan::Inserted { .. }));
    }

    #[test]
    fn complete_slice_marks_it_done_and_names_the_next_unit_or_the_close_out() {
        let snap = snapshot(vec![
            slice("001", SliceStatus::Active, 2),
            slice("002", SliceStatus::Queued, 0),
        ]);
        let verb = |unit| {
            validated(
                unit,
                MemberVerb::CompleteSlice(CompleteSliceArgs {
                    summary: "built\nthe thing".into(),
                    baton: BATON.into(),
                }),
                None,
            )
        };
        let p = plan(&verb(on_slice("001")), &snap).unwrap();
        assert_eq!(
            log_line(&p.ops),
            "completed · deepseek/deepseek-flash · member a1 · $? · built the thing"
        );
        assert_eq!(
            p.ops[1],
            KeeperOp::SetStatus {
                entry: "m1".into(),
                unit: Some("001".into()),
                new: DaemonStatusArg::Done,
            }
        );
        assert_eq!(p.ops.len(), 2, "done resets the counter inside keeperd's op");
        assert_eq!(
            p.next,
            NextPlan::Unit(NextUnit {
                entry: "m1".into(),
                unit: "002".into()
            })
        );

        // The last open slice: the next unit is the close-out (§6.2).
        let last = snapshot(vec![
            slice("001", SliceStatus::Done, 0),
            slice("002", SliceStatus::Active, 0),
        ]);
        let p = plan(&verb(on_slice("002")), &last).unwrap();
        assert_eq!(
            p.next,
            NextPlan::Unit(NextUnit {
                entry: "m1".into(),
                unit: "close-out".into()
            })
        );
    }

    #[test]
    fn complete_entry_logs_before_archiving_and_writes_deferred_tests() {
        let snap = snapshot(vec![slice("001", SliceStatus::Done, 0)]);
        let close_out = Unit::CloseOut {
            milestone: "m1".into(),
        };
        let done = validated(
            close_out.clone(),
            MemberVerb::CompleteEntry(CompleteEntryArgs {
                outcome: EntryOutcome::Done,
                summary: "shipped".into(),
                deferred_tests: None,
                baton: BATON.into(),
            }),
            None,
        );
        let p = plan(&done, &snap).unwrap();
        assert!(matches!(&p.ops[0], KeeperOp::SessionLog { entry, unit: None, .. } if entry == "m1"));
        assert_eq!(
            p.ops[1],
            KeeperOp::SetStatus {
                entry: "m1".into(),
                unit: None,
                new: DaemonStatusArg::Done,
            }
        );
        assert!(!p.continues && p.next == NextPlan::None);

        let tests = vec![DeferredTestSpec {
            what: "run it on the device".into(),
            expected: "it works".into(),
        }];
        let deferred = validated(
            close_out,
            MemberVerb::CompleteEntry(CompleteEntryArgs {
                outcome: EntryOutcome::Deferred,
                summary: "built".into(),
                deferred_tests: Some(tests.clone()),
                baton: BATON.into(),
            }),
            None,
        );
        let p = plan(&deferred, &snap).unwrap();
        assert!(log_line(&p.ops).starts_with("deferred · "));
        assert_eq!(
            p.ops[1..],
            [
                KeeperOp::Deferred {
                    entry: "m1".into(),
                    tests,
                },
                // The entry had 2 follow-ups; completion resets them.
                KeeperOp::FollowUps {
                    entry: "m1".into(),
                    unit: None,
                    count: 0,
                },
                KeeperOp::SetStatus {
                    entry: "m1".into(),
                    unit: None,
                    new: DaemonStatusArg::Deferred,
                },
            ],
        );
    }

    #[test]
    fn block_logs_the_reason_blocks_the_entry_and_raises_the_alert() {
        let snap = snapshot(vec![slice("001", SliceStatus::Active, 4)]);
        let v = validated(
            on_slice("001"),
            MemberVerb::Block(BlockArgs {
                kind: BlockKind::Stuck,
                reason: "the cap is spent".into(),
                baton: BATON.into(),
            }),
            None,
        );
        let p = plan(&v, &snap).unwrap();
        let line = log_line(&p.ops);
        assert!(line.starts_with("blocked · ") && line.ends_with(" · stuck: the cap is spent"), "{line}");
        assert_eq!(
            p.ops[1],
            KeeperOp::SetStatus {
                entry: "m1".into(),
                unit: None,
                new: DaemonStatusArg::Blocked,
            },
            "the entry blocks; the slice stays active with its counter",
        );
        assert_eq!(p.ops.len(), 2, "a block never counts");
        assert_eq!(p.alert.as_deref(), Some("m1 (stuck: the cap is spent)"));
    }

    #[test]
    fn a_pending_human_change_is_applied_last_at_the_boundary() {
        let mut snap = snapshot(vec![slice("001", SliceStatus::Active, 0)]);
        snap.entries[0].pending = Some(EntryStatus::Blocked);
        let p = plan(&follow_up(RollReason::McpUpdated, None), &snap).unwrap();
        assert_eq!(
            p.ops.last(),
            Some(&KeeperOp::SetStatus {
                entry: "m1".into(),
                unit: None,
                new: DaemonStatusArg::Blocked,
            })
        );
    }

    #[test]
    fn execute_stores_the_baton_and_reports_the_next_unit() {
        let snap = snapshot(vec![slice("002", SliceStatus::Active, 0)]);
        let (seams, dir) = seams(SpyKeeper::default());
        let done = execute(&follow_up(RollReason::ContextFull, None), &snap, &seams).unwrap();
        assert!(done.warnings.is_empty(), "{:?}", done.warnings);
        assert!(done.handoff.continues);
        assert_eq!(
            done.next,
            Some(NextUnit {
                entry: "m1".into(),
                unit: "002".into()
            })
        );
        assert_eq!(seams.entries.read("m1").as_deref(), Some(BATON), "the baton is the entry's");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_commit_point_changes_nothing_and_errors() {
        let snap = snapshot(vec![slice("002", SliceStatus::Active, 0)]);
        let (seams, dir) = seams(SpyKeeper {
            fail_at: Some(0),
            ..Default::default()
        });
        let err = execute(&follow_up(RollReason::ContextFull, None), &snap, &seams).unwrap_err();
        assert!(err.contains("keeps running"), "{err}");
        assert_eq!(seams.entries.read("m1"), None, "no baton stored without a commit");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_later_failure_is_a_warning_and_the_handoff_stands() {
        let snap = snapshot(vec![slice("002", SliceStatus::Active, 0)]);
        let (seams, dir) = seams(SpyKeeper {
            fail_at: Some(1),
            ..Default::default()
        });
        let done = execute(&follow_up(RollReason::ContextFull, None), &snap, &seams).unwrap();
        assert_eq!(done.warnings.len(), 1, "{:?}", done.warnings);
        assert!(done.warnings[0].starts_with("queue_v2_follow_ups failed"));
        assert_eq!(seams.entries.read("m1").as_deref(), Some(BATON));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_landed_pending_change_ends_the_entrys_active_work() {
        let mut snap = snapshot(vec![slice("002", SliceStatus::Active, 0)]);
        snap.entries[0].pending = Some(EntryStatus::Deferred);
        let (seams, dir) = seams(SpyKeeper {
            entry_status: Some("deferred".into()),
            ..Default::default()
        });
        let done = execute(&follow_up(RollReason::ContextFull, None), &snap, &seams).unwrap();
        assert!(!done.handoff.continues, "the entry left active work at the boundary");
        assert_eq!(done.next, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn new_scope_reports_the_inserted_slice_as_next() {
        let snap = snapshot(vec![slice("002", SliceStatus::Active, 0)]);
        let (seams, dir) = seams(SpyKeeper::default());
        let new = NewSliceArgs {
            slug: "found".into(),
            title: "Found".into(),
            body: "b".into(),
        };
        let done = execute(&follow_up(RollReason::NewScope, Some(new)), &snap, &seams).unwrap();
        assert_eq!(
            done.next,
            Some(NextUnit {
                entry: "m1".into(),
                unit: "004".into()
            })
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // ---- slice 010: the sub-milestone and its close-out ----------------------

    fn add_sub(do_not_prioritize: bool) -> Validated {
        validated(
            on_slice("001"),
            MemberVerb::AddSubMilestone(AddSubMilestoneArgs {
                slug: "rest".into(),
                title: "The rest".into(),
                mission: "finish 001".into(),
                finish_criteria: "001's criteria hold".into(),
                slices: vec![
                    NewSliceArgs {
                        slug: "a".into(),
                        title: "A".into(),
                        body: "do a".into(),
                    },
                    NewSliceArgs {
                        slug: "b".into(),
                        title: "B".into(),
                        body: "do b".into(),
                    },
                ],
                do_not_prioritize,
                baton: BATON.into(),
            }),
            None,
        )
    }

    fn next(entry: &str, unit: &str) -> NextUnit {
        NextUnit {
            entry: entry.into(),
            unit: unit.into(),
        }
    }

    #[test]
    fn a_sub_milestone_logs_the_split_then_has_keeperd_file_it_and_runs_next() {
        let snap = snapshot(vec![
            slice("001", SliceStatus::Active, 5),
            slice("002", SliceStatus::Queued, 0),
        ]);
        let p = plan(&add_sub(false), &snap).unwrap();
        assert_eq!(
            log_line(&p.ops),
            "split · deepseek/deepseek-flash · member a1 · $? · sub-milestone m1/rest: The rest"
        );
        assert!(matches!(&p.ops[0], KeeperOp::SessionLog { entry, unit: Some(u), .. } if entry == "m1" && u == "001"));
        assert_eq!(
            p.ops[1],
            KeeperOp::AddSub {
                milestone: "m1".into(),
                slice: "001".into(),
                slug: "rest".into(),
                title: "The rest".into(),
                mission: "finish 001".into(),
                finish_criteria: "001's criteria hold".into(),
                slices: match &add_sub(false).verb {
                    MemberVerb::AddSubMilestone(a) => a.slices.clone(),
                    _ => unreachable!(),
                },
                at_end: false,
            },
        );
        assert_eq!(p.ops.len(), 2, "the split slice's counter is moot; a sub never counts");
        assert!(p.continues);
        assert_eq!(
            p.next,
            NextPlan::SubAdded {
                next: Some(next("m1/rest", "001")),
                fallback: next("m1", "001"),
            },
            "§7 default: the sub runs next, from its first slice",
        );

        // do_not_prioritize: the sub waits at the end; 002 runs next.
        let p = plan(&add_sub(true), &snap).unwrap();
        assert!(matches!(&p.ops[1], KeeperOp::AddSub { at_end: true, .. }));
        assert_eq!(
            p.next,
            NextPlan::SubAdded {
                next: Some(next("m1", "002")),
                fallback: next("m1", "001"),
            },
        );
        // … unless nothing else is open, when the sub at the end is next anyway.
        let alone = snapshot(vec![slice("001", SliceStatus::Active, 5)]);
        assert!(matches!(
            plan(&add_sub(true), &alone).unwrap().next,
            NextPlan::SubAdded { next: Some(n), .. } if n == next("m1/rest", "001")
        ));
    }

    #[test]
    fn a_failed_sub_creation_after_the_commit_point_resumes_the_slice() {
        let snap = snapshot(vec![slice("001", SliceStatus::Active, 5)]);
        let (seams, dir) = seams(SpyKeeper {
            fail_at: Some(1),
            ..Default::default()
        });
        let done = execute(&add_sub(false), &snap, &seams).unwrap();
        assert_eq!(done.next, Some(next("m1", "001")), "nothing split: the slice runs again");
        assert!(done.warnings[0].starts_with("queue_v2_add_sub failed"), "{:?}", done.warnings);
        assert!(done.handoff.continues);

        let (seams, dir2) = seams_ok();
        let done = execute(&add_sub(false), &snap, &seams).unwrap();
        assert_eq!(done.next, Some(next("m1/rest", "001")));
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    fn seams_ok() -> (HandoffSeams, std::path::PathBuf) {
        seams(SpyKeeper::default())
    }

    /// m1: 001 split, the sub `rest` (its one slice done), then 002 queued.
    fn with_finished_sub() -> V2Snapshot {
        let mut snap = snapshot(vec![
            slice("001", SliceStatus::Split, 5),
            ItemView {
                kind: SliceKind::Sub,
                id: "rest".into(),
                status: SliceStatus::Queued,
                models: None,
                follow_ups: 0,
            },
            slice("002", SliceStatus::Queued, 0),
        ]);
        snap.trees.insert(
            "m1/rest".into(),
            TreeView {
                items: vec![slice("001", SliceStatus::Done, 0)],
                models: None,
            },
        );
        snap
    }

    fn close_sub(outcome: EntryOutcome) -> Validated {
        validated(
            Unit::CloseOut {
                milestone: "m1/rest".into(),
            },
            MemberVerb::CompleteEntry(CompleteEntryArgs {
                outcome,
                summary: "the rest is built".into(),
                deferred_tests: (outcome == EntryOutcome::Deferred).then(|| {
                    vec![DeferredTestSpec {
                        what: "run it".into(),
                        expected: "it works".into(),
                    }]
                }),
                baton: BATON.into(),
            }),
            None,
        )
    }

    #[test]
    fn a_sub_close_out_completes_the_sub_and_the_entry_runs_on() {
        let snap = with_finished_sub();
        let p = plan(&close_sub(EntryOutcome::Done), &snap).unwrap();
        assert_eq!(
            p.ops,
            vec![
                KeeperOp::SessionLog {
                    entry: "m1/rest".into(),
                    unit: None,
                    line: "completed · deepseek/deepseek-flash · member a1 · $? · the rest is built".into(),
                },
                // The close-out's follow-ups ride the entry's counter (2): reset.
                KeeperOp::FollowUps {
                    entry: "m1/rest".into(),
                    unit: None,
                    count: 0,
                },
                KeeperOp::SetStatus {
                    entry: "m1".into(),
                    unit: Some("rest".into()),
                    new: DaemonStatusArg::Done,
                },
            ],
            "the sub's own doc gets the line; its item in m1 closes; nothing archives",
        );
        assert!(p.continues, "the entry is still active work");
        assert_eq!(p.next, NextPlan::Unit(next("m1", "002")));
        assert!(p.alert.is_none());

        let p = plan(&close_sub(EntryOutcome::Deferred), &snap).unwrap();
        assert!(log_line(&p.ops).starts_with("deferred · "));
        assert_eq!(
            p.ops[1],
            KeeperOp::Deferred {
                entry: "m1/rest".into(),
                tests: vec![DeferredTestSpec {
                    what: "run it".into(),
                    expected: "it works".into(),
                }],
            },
            "the tests land in the sub's own doc",
        );
        assert_eq!(
            p.ops.last(),
            Some(&KeeperOp::SetStatus {
                entry: "m1".into(),
                unit: Some("rest".into()),
                new: DaemonStatusArg::Deferred,
            })
        );
        assert_eq!(p.next, NextPlan::Unit(next("m1", "002")), "a deferred sub is rolled past");

        // The parent's last open item was the sub: its close-out is next.
        let mut last = with_finished_sub();
        last.trees.get_mut("m1").unwrap().items.pop();
        let p = plan(&close_sub(EntryOutcome::Done), &last).unwrap();
        assert_eq!(p.next, NextPlan::Unit(next("m1", "close-out")));

        // A pending human change still lands last, at the boundary.
        let mut pending = with_finished_sub();
        pending.entries[0].pending = Some(EntryStatus::Paused);
        let p = plan(&close_sub(EntryOutcome::Done), &pending).unwrap();
        assert_eq!(
            p.ops.last(),
            Some(&KeeperOp::SetStatus {
                entry: "m1".into(),
                unit: None,
                new: DaemonStatusArg::Paused,
            })
        );
    }
}
