//! The queue-v2 member verbs' **validation** (queue-v2-scheduling slice 008):
//! spec-growlight-queue §6.3 step 2, in the spec's order, over a v2 snapshot
//! and the caller's live assignment. Pure — no socket, no file, no fleet — so
//! every refusal code is unit-tested against fixtures, like
//! [`crate::scheduler_v2`].
//!
//! ## Where it sits
//!
//! A member session calls one of the five `growlight_*` verbs as its last call
//! (§6). softfig-mcp wraps the model's arguments in a
//! [`MemberCall`](softfig_ipc::growlightd::MemberCall) carrying the identity it
//! read from `SOFTFIG_MEMBER`, keeperd relays it, and growlightd's server runs:
//!
//! 1. **identity** ([`identity`]) — no member → `not_a_member`;
//! 2. **assignment** — the member's live v2 assignment, mirrored from the drive
//!    loop ([`crate::daemon::Daemon::v2_assignment`]); none → `not_your_session`;
//! 3. the rest here, in [`validate`]: the assignment still matches the list
//!    (`not_your_session`), the reason, the cap, the model rule, the member
//!    write limits on any slice body, and the baton head. Ahead of those, it
//!    refuses malformed arguments the closed code list has no name for (an
//!    empty summary, `deferred_tests` on a `done`) as [`VerbError::BadArgs`].
//!
//! **A refusal leaves the session running** (§6.3): nothing here, nor in the
//! server on a refusal, touches the session — the agent reads the refusal text
//! and corrects itself. A pass returns the [`Validated`] action; executing it
//! (commit, store the baton) is [`crate::member_handoff`], and terminating the
//! session after the grace and picking is the drive loop's.
//!
//! ## Decisions recorded in the slice doc
//!
//! - The verbs carry no session or entry argument (§6.1–§6.6 are exact), so
//!   "a call about a session that isn't the caller's own" is checked against
//!   the caller's live assignment: it must exist, its entry must still be
//!   `active` in the list, and its unit must still be the open unit it names.
//!   The baton's `item:` must name the same top-level entry (`bad_baton`).
//! - Each handoff's baton status is fixed by the verb: a session that continues
//!   the work hands on `IN_PROGRESS`; `complete_entry` carries `ITEM_COMPLETE`
//!   (`done`) or `ITEM_DEFERRED` (`deferred`) as §6.5 says; `block` carries the
//!   protocol's own `BLOCKED_ON_HUMAN` / `STUCK`. One exception (slice 010):
//!   `complete_entry` on a sub-milestone's close-out continues the entry, so
//!   it hands on `IN_PROGRESS`.
//! - `model_change` without `model` has no code of its own in §6.3; it is
//!   refused `model_not_allowed` (the request names no allowed model).
//! - A `preempted` follow-up never counts, so it is never capped.
//! - `depth_limit` is checked here with the rest of the cap step (§7's code in
//!   §6.3's list); building the sub-milestone is [`crate::member_handoff`]'s.
//! - Slice 010: §6.7's `field_not_allowed` for a sub-milestone's text is
//!   checked here, in the write-limits step — its one placement on the
//!   member path (011 does not add another). Slugs keeperd would refuse (bad
//!   shape, a sub slug already in the parent's list) are refused here as
//!   malformed arguments, because keeperd's refusal would come after the
//!   handshake's commit point and end the session with nothing filed.

use softfig_ipc::baton::validate_head;
use softfig_ipc::growlightd::{
    op, AddFollowUpSessionArgs, AddSubMilestoneArgs, BlockArgs, BlockKind, CompleteEntryArgs,
    CompleteSliceArgs, EntryOutcome, NewSliceArgs, RefusalCode, RollReason, NOT_A_MEMBER_MESSAGE,
};
use softfig_ipc::model_choice::{
    item_model_field, parse_declaration, parse_model_spec, validate_declared_subset,
    validate_model_change, Declaration, ModelChoice, ModelList, ModelSpec,
};
use softfig_ipc::queue_v2::{
    sub_depth, sub_doc_violation, EntryKind, EntryStatus, SliceKind, SliceStatus, SubSliceText,
};

use crate::drive_loop::V2Assignment;
use crate::scheduler_v2::{EntryView, TreeView, Unit, V2Snapshot};

/// The cap (§7): 5 consecutive follow-ups per unit; the 6th is refused.
pub const FOLLOW_UP_CAP: u64 = 5;

/// One member verb's arguments, as growlightd received them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberVerb {
    AddFollowUpSession(AddFollowUpSessionArgs),
    CompleteSlice(CompleteSliceArgs),
    CompleteEntry(CompleteEntryArgs),
    Block(BlockArgs),
    AddSubMilestone(AddSubMilestoneArgs),
}

impl MemberVerb {
    /// The verb's wire name.
    pub fn name(&self) -> &'static str {
        match self {
            MemberVerb::AddFollowUpSession(_) => op::GROWLIGHT_ADD_FOLLOW_UP_SESSION,
            MemberVerb::CompleteSlice(_) => op::GROWLIGHT_COMPLETE_SLICE,
            MemberVerb::CompleteEntry(_) => op::GROWLIGHT_COMPLETE_ENTRY,
            MemberVerb::Block(_) => op::GROWLIGHT_BLOCK,
            MemberVerb::AddSubMilestone(_) => op::GROWLIGHT_ADD_SUB_MILESTONE,
        }
    }

    /// The baton the verb carries (every verb carries one).
    pub fn baton(&self) -> &str {
        match self {
            MemberVerb::AddFollowUpSession(a) => &a.baton,
            MemberVerb::CompleteSlice(a) => &a.baton,
            MemberVerb::CompleteEntry(a) => &a.baton,
            MemberVerb::Block(a) => &a.baton,
            MemberVerb::AddSubMilestone(a) => &a.baton,
        }
    }

    /// The baton statuses this handoff may carry (§6.3's head check).
    fn baton_statuses(&self) -> &'static [&'static str] {
        match self {
            MemberVerb::AddFollowUpSession(_)
            | MemberVerb::CompleteSlice(_)
            | MemberVerb::AddSubMilestone(_) => &["IN_PROGRESS"],
            MemberVerb::CompleteEntry(a) => match a.outcome {
                EntryOutcome::Done => &["ITEM_COMPLETE"],
                EntryOutcome::Deferred => &["ITEM_DEFERRED"],
            },
            MemberVerb::Block(a) => match a.kind {
                BlockKind::Human => &["BLOCKED_ON_HUMAN"],
                BlockKind::Stuck => &["STUCK"],
            },
        }
    }
}

/// A §6.3 refusal: the code plus what the agent should correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: RefusalCode,
    pub message: String,
}

fn refuse<T>(code: RefusalCode, message: impl Into<String>) -> Result<T, VerbError> {
    Err(VerbError::Refused(Refusal {
        code,
        message: message.into(),
    }))
}

/// Why a verb did not validate: a §6.3 refusal, or malformed arguments the
/// closed code list has no name for (an empty summary, `deferred_tests` on a
/// `done`). Both leave the session running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerbError {
    Refused(Refusal),
    BadArgs(String),
}

/// A verb that passed every §6.3 check: what the handshake's execution half
/// commits. No side effect has happened yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    /// The calling member.
    pub member: String,
    /// The assignment the call was validated against (entry, unit, the
    /// session's model).
    pub assignment: V2Assignment,
    /// The verb and its arguments.
    pub verb: MemberVerb,
    /// `add_follow_up_session` only: the parsed §5 reason.
    pub reason: Option<RollReason>,
    /// `add_follow_up_session` only: the next session's model when the call
    /// changes it (model or variant); `None` keeps the current one.
    pub next_model: Option<ModelChoice>,
}

/// §6.3 step 2, first check: the caller's identity. `None` (softfig-mcp found
/// no `SOFTFIG_MEMBER`) is `not_a_member` — semi-auto and human-directed
/// sessions keep their legacy handoff.
pub fn identity(member: Option<&str>) -> Result<&str, Refusal> {
    member.ok_or_else(|| Refusal {
        code: RefusalCode::NotAMember,
        message: NOT_A_MEMBER_MESSAGE.into(),
    })
}

/// The `not_your_session` refusal for a member with no live v2 assignment.
pub fn no_assignment(member: &str) -> Refusal {
    Refusal {
        code: RefusalCode::NotYourSession,
        message: format!(
            "member {member} holds no live queue-v2 assignment, so this session has \
             nothing to hand off (it was already rolled, or the fleet schedules from the \
             legacy queue)"
        ),
    }
}

/// How a unit renders in replies and messages: the slice id, `close-out`, or
/// `entry` for a task/restack.
pub fn unit_label(unit: &Unit) -> String {
    match unit {
        Unit::Slice { slice, .. } => slice.clone(),
        Unit::CloseOut { .. } => "close-out".to_string(),
        Unit::Entry => "entry".to_string(),
    }
}

/// The rest of §6.3 step 2, in order — assignment match, reason, cap, model
/// rule, member write limits, baton — for a caller whose identity and live
/// assignment are already established. Pure over the snapshot.
pub fn validate(
    member: &str,
    assignment: &V2Assignment,
    snapshot: &V2Snapshot,
    verb: MemberVerb,
) -> Result<Validated, VerbError> {
    check_shape(&verb)?;
    let ctx = assignment_match(assignment, snapshot)?;

    // The reason (and the verb's own unit-kind rules, which §5/§6.2/§6.5 file
    // under it).
    let reason = check_reason(&verb, &ctx)?;
    // The cap (§7), then where a sub-milestone would go.
    check_cap(&verb, reason, &ctx)?;
    check_sub_placement(&verb, &ctx)?;
    // The model rule (§6.4).
    let next_model = match &verb {
        MemberVerb::AddFollowUpSession(a) => check_model(a, reason, assignment, &ctx)?,
        _ => None,
    };
    // The member write limits (§6.7): the sub-milestone text's reserved
    // lines, then the subset rule on any slice body.
    check_sub_fields(&verb)?;
    check_slice_bodies(&verb, &ctx)?;
    // The baton parses with its required head fields.
    check_baton(&verb, &ctx)?;

    Ok(Validated {
        member: member.to_string(),
        assignment: assignment.clone(),
        verb,
        reason,
        next_model,
    })
}

/// What the assignment-match step resolved from the snapshot, for the later
/// steps.
struct Ctx<'a> {
    /// The snapshot the call is validated against.
    snapshot: &'a V2Snapshot,
    /// The entry's top-level row (the queue.toml id).
    entry: &'a EntryView,
    /// The assignment's unit.
    unit: &'a Unit,
    /// The unit's declared allowed list (`None` = undeclared → member default).
    declared: Option<&'a ModelList>,
    /// The unit's consecutive follow-ups (§7): the slice's own, or the entry's
    /// for a task, restack or close-out.
    follow_ups: u64,
    /// For a slice unit: its milestone's tree — the inheritance a new slice in
    /// it gets (the tree's chain-resolved list) and the sub-milestone depth.
    tree: Option<(&'a str, &'a TreeView)>,
}

/// keeperd's slug rule (`conventions::validate_slug`: 1–64 bytes of
/// `[a-z0-9-]`), checked here so a slug keeperd would refuse is refused
/// before the handshake commits rather than after its commit point.
const SLUG_MAX: usize = 64;

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= SLUG_MAX
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Arguments the closed code list doesn't name: refused as malformed.
fn check_shape(verb: &MemberVerb) -> Result<(), VerbError> {
    fn non_empty(field: &str, value: &str) -> Result<(), VerbError> {
        if value.trim().is_empty() {
            Err(VerbError::BadArgs(format!("`{field}` must be non-empty")))
        } else {
            Ok(())
        }
    }
    fn slug(field: &str, value: &str) -> Result<(), VerbError> {
        if is_slug(value) {
            Ok(())
        } else {
            Err(VerbError::BadArgs(format!(
                "`{field}` must be a slug: 1–{SLUG_MAX} of [a-z0-9-], got {value:?}"
            )))
        }
    }
    fn slice(prefix: &str, s: &NewSliceArgs) -> Result<(), VerbError> {
        slug(&format!("{prefix}.slug"), &s.slug)?;
        non_empty(&format!("{prefix}.title"), &s.title)?;
        non_empty(&format!("{prefix}.body"), &s.body)
    }
    match verb {
        MemberVerb::AddFollowUpSession(a) => {
            if let Some(s) = &a.new_slice {
                slice("new_slice", s)?;
            }
        }
        MemberVerb::CompleteSlice(a) => non_empty("summary", &a.summary)?,
        MemberVerb::CompleteEntry(a) => {
            non_empty("summary", &a.summary)?;
            match (a.outcome, &a.deferred_tests) {
                (EntryOutcome::Deferred, None) => {
                    return Err(VerbError::BadArgs(
                        "`deferred_tests` is required when `outcome = deferred`".into(),
                    ))
                }
                (EntryOutcome::Deferred, Some(tests)) if tests.is_empty() => {
                    return Err(VerbError::BadArgs(
                        "`deferred_tests` needs at least one pending manual test".into(),
                    ))
                }
                (EntryOutcome::Deferred, Some(tests)) => {
                    for (i, t) in tests.iter().enumerate() {
                        non_empty(&format!("deferred_tests[{i}].what"), &t.what)?;
                        non_empty(&format!("deferred_tests[{i}].expected"), &t.expected)?;
                    }
                }
                (EntryOutcome::Done, Some(_)) => {
                    return Err(VerbError::BadArgs(
                        "`deferred_tests` is only for `outcome = deferred`".into(),
                    ))
                }
                (EntryOutcome::Done, None) => {}
            }
        }
        MemberVerb::Block(a) => non_empty("reason", &a.reason)?,
        MemberVerb::AddSubMilestone(a) => {
            slug("slug", &a.slug)?;
            non_empty("title", &a.title)?;
            non_empty("mission", &a.mission)?;
            non_empty("finish_criteria", &a.finish_criteria)?;
            if a.slices.is_empty() {
                return Err(VerbError::BadArgs(
                    "a sub-milestone needs at least one slice".into(),
                ));
            }
            for (i, s) in a.slices.iter().enumerate() {
                slice(&format!("slices[{i}]"), s)?;
            }
        }
    }
    Ok(())
}

/// The assignment still matches the list: its entry is live and `active`, and
/// its unit is still the open unit it names. Anything else means this session
/// no longer holds what it was spawned on — `not_your_session`.
fn assignment_match<'a>(
    assignment: &'a V2Assignment,
    snapshot: &'a V2Snapshot,
) -> Result<Ctx<'a>, VerbError> {
    let top = assignment.entry.split('/').next().unwrap_or(&assignment.entry);
    let Some(entry) = snapshot.entries.iter().find(|e| e.id == top) else {
        return refuse(
            RefusalCode::NotYourSession,
            format!("your entry {top} is no longer in the queue-v2 list"),
        );
    };
    if entry.status != EntryStatus::Active {
        return refuse(
            RefusalCode::NotYourSession,
            format!(
                "your entry {top} is {}, not active — this session no longer holds it",
                entry.status
            ),
        );
    }
    let unit = &assignment.unit;
    let gone = |what: String| -> Result<Ctx<'a>, VerbError> {
        refuse(RefusalCode::NotYourSession, what)
    };
    match unit {
        Unit::Entry => {
            if entry.kind == EntryKind::Milestone {
                return gone(format!("your assignment names entry {top} itself, but it is a milestone"));
            }
            Ok(Ctx {
                snapshot,
                entry,
                unit,
                declared: entry.models.as_ref(),
                follow_ups: entry.follow_ups,
                tree: None,
            })
        }
        Unit::CloseOut { milestone } => {
            let Some(tree) = snapshot.trees.get(milestone) else {
                return gone(format!("milestone {milestone}'s slice list is gone"));
            };
            Ok(Ctx {
                snapshot,
                entry,
                unit,
                declared: tree.models.as_ref(),
                // §6.5: follow-ups during a close-out count on the entry's.
                follow_ups: entry.follow_ups,
                tree: None,
            })
        }
        Unit::Slice { milestone, slice } => {
            let Some(tree) = snapshot.trees.get(milestone) else {
                return gone(format!("milestone {milestone}'s slice list is gone"));
            };
            let Some(item) = tree
                .items
                .iter()
                .find(|i| i.kind == SliceKind::Slice && &i.id == slice)
            else {
                return gone(format!("slice {slice} is no longer in milestone {milestone}"));
            };
            if item.status != SliceStatus::Active {
                return gone(format!(
                    "slice {slice} of {milestone} is {}, not active — this session no longer holds it",
                    item.status
                ));
            }
            Ok(Ctx {
                snapshot,
                entry,
                unit,
                declared: item.models.as_ref(),
                follow_ups: item.follow_ups,
                tree: Some((milestone.as_str(), tree)),
            })
        }
    }
}

/// The reason step: the §5 closed list and its `new_slice` pairing, plus each
/// verb's unit-kind rule (`task_has_no_slices`, `open_items`).
fn check_reason(verb: &MemberVerb, ctx: &Ctx<'_>) -> Result<Option<RollReason>, VerbError> {
    let on_slice = matches!(ctx.unit, Unit::Slice { .. });
    let no_slices = |what: &str| -> Result<Option<RollReason>, VerbError> {
        refuse(
            RefusalCode::TaskHasNoSlices,
            format!(
                "{what} needs a slice, and this session's unit is {} — {}",
                describe_unit(ctx),
                "file found work as a new entry (queue_add_entry), finish with \
                 growlight_complete_entry, or block"
            ),
        )
    };
    match verb {
        MemberVerb::AddFollowUpSession(a) => {
            let Some(reason) = RollReason::parse(&a.reason) else {
                let list: Vec<&str> = RollReason::ALL.iter().map(|r| r.as_str()).collect();
                return refuse(
                    RefusalCode::UnknownReason,
                    format!("`{}` is not a roll reason; use one of: {}", a.reason, list.join(", ")),
                );
            };
            if reason == RollReason::NewScope {
                if !on_slice {
                    return no_slices("new_scope");
                }
                if a.new_slice.is_none() {
                    return refuse(
                        RefusalCode::MissingNewSlice,
                        "new_scope requires `new_slice` {slug, title, body}: the slice that \
                         runs next, before this one resumes",
                    );
                }
            } else if a.new_slice.is_some() {
                return refuse(
                    RefusalCode::NewSliceNotAllowed,
                    format!("`new_slice` goes only with reason new_scope, not {reason}"),
                );
            }
            Ok(Some(reason))
        }
        MemberVerb::CompleteSlice(_) => {
            if on_slice {
                Ok(None)
            } else {
                no_slices("growlight_complete_slice")
            }
        }
        MemberVerb::AddSubMilestone(_) => {
            if on_slice {
                Ok(None)
            } else {
                no_slices("growlight_add_sub_milestone")
            }
        }
        MemberVerb::CompleteEntry(_) => match ctx.unit {
            Unit::Entry => Ok(None),
            Unit::Slice { milestone, slice } => refuse(
                RefusalCode::OpenItems,
                format!(
                    "milestone {milestone} still has open items (this session's own slice \
                     {slice}, at least) — finish it with growlight_complete_slice; the \
                     close-out session completes the entry"
                ),
            ),
            Unit::CloseOut { milestone } => {
                let open = open_items(milestone, ctx);
                if open.is_empty() {
                    Ok(None)
                } else {
                    refuse(
                        RefusalCode::OpenItems,
                        format!(
                            "milestone {milestone} has open items: {} — every item must be \
                             done, split or deferred before the entry completes",
                            open.join(", ")
                        ),
                    )
                }
            }
        },
        MemberVerb::Block(_) => Ok(None),
    }
}

/// The items of `milestone`'s tree (recursing into subs) that are not `done`,
/// `split` or `deferred` (§6.5), as `<milestone>:<id>` labels. A missing tree
/// counts as open: fail closed, never a completion over unseen work.
fn open_items(milestone: &str, ctx: &Ctx<'_>) -> Vec<String> {
    let mut open = Vec::new();
    collect_open(ctx.snapshot, milestone, &mut open);
    open
}

fn collect_open(snapshot: &V2Snapshot, milestone: &str, open: &mut Vec<String>) {
    let Some(tree) = snapshot.trees.get(milestone) else {
        open.push(format!("{milestone} (slice list missing)"));
        return;
    };
    for item in &tree.items {
        match item.status {
            SliceStatus::Done | SliceStatus::Split | SliceStatus::Deferred => {}
            _ => open.push(format!("{milestone}:{}", item.id)),
        }
    }
}

fn describe_unit(ctx: &Ctx<'_>) -> String {
    match ctx.unit {
        Unit::Slice { milestone, slice } => format!("slice {slice} of {milestone}"),
        Unit::CloseOut { milestone } => format!("the close-out of {milestone}"),
        Unit::Entry => format!("the {} {} itself", ctx.entry.kind, ctx.entry.id),
    }
}

/// The cap step (§7): the 6th consecutive counted follow-up is refused, and a
/// sub-milestone can't nest past 2 deep.
fn check_cap(verb: &MemberVerb, reason: Option<RollReason>, ctx: &Ctx<'_>) -> Result<(), VerbError> {
    match verb {
        MemberVerb::AddFollowUpSession(_) => {
            let counts = reason.is_some_and(RollReason::counts_toward_cap);
            if counts && ctx.follow_ups >= FOLLOW_UP_CAP {
                let next = if matches!(ctx.unit, Unit::Slice { .. }) {
                    "file this slice's remaining work as a sub-milestone \
                     (growlight_add_sub_milestone)"
                } else {
                    "there is nothing to split into: end with growlight_block kind = stuck, \
                     describing the remaining work, and the human re-files it"
                };
                return refuse(
                    RefusalCode::CapReached,
                    format!(
                        "{} has had {} consecutive follow-ups, the cap — {next}",
                        describe_unit(ctx),
                        ctx.follow_ups
                    ),
                );
            }
            Ok(())
        }
        MemberVerb::AddSubMilestone(a) => {
            let (milestone, _) = ctx.tree.expect("a slice unit carries its tree");
            if sub_depth(&format!("{milestone}/{}", a.slug)).is_err() {
                return refuse(
                    RefusalCode::DepthLimit,
                    format!(
                        "{milestone} is already a sub-milestone 2 deep, so it can't file \
                         another level — end with growlight_block kind = stuck"
                    ),
                );
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// A sub-milestone's slug becomes an item id in the parent's list, so it must
/// be free there: keeperd refuses a taken one (`exists`), and that refusal
/// would land after the handshake's commit point. The closed code list has no
/// name for it, so it is malformed arguments.
fn check_sub_placement(verb: &MemberVerb, ctx: &Ctx<'_>) -> Result<(), VerbError> {
    let MemberVerb::AddSubMilestone(a) = verb else {
        return Ok(());
    };
    let (milestone, tree) = ctx.tree.expect("a slice unit carries its tree");
    if tree.items.iter().any(|i| i.id == a.slug) {
        return Err(VerbError::BadArgs(format!(
            "`slug` {:?} is already an item of {milestone}'s slice list; pick a slug no \
             slice or sub-milestone there uses",
            a.slug
        )));
    }
    Ok(())
}

/// §6.7, sub-milestone docs: keeperd writes them from the structured fields,
/// so a member's mission, criteria and slice titles may carry no `> Model:`,
/// `> Grants:` or `> Worktree:` line, and its slice bodies no `> Grants:` or
/// `> Worktree:` (a body's `> Model:` is the subset rule's, next). The rule is
/// `softfig_ipc::queue_v2::sub_doc_violation`, which keeperd's
/// `queue_v2_add_sub` re-checks as the writer's backstop.
fn check_sub_fields(verb: &MemberVerb) -> Result<(), VerbError> {
    let MemberVerb::AddSubMilestone(a) = verb else {
        return Ok(());
    };
    let slices: Vec<SubSliceText<'_>> = a
        .slices
        .iter()
        .map(|s| SubSliceText {
            title: &s.title,
            body: &s.body,
        })
        .collect();
    match sub_doc_violation(&a.mission, &a.finish_criteria, &slices) {
        Some(v) => refuse(RefusalCode::FieldNotAllowed, v.message()),
        None => Ok(()),
    }
}

/// The model rule (§6.4) for a follow-up's `model`/`variant`: the next
/// session's model, `None` when it keeps the current one.
fn check_model(
    args: &AddFollowUpSessionArgs,
    reason: Option<RollReason>,
    assignment: &V2Assignment,
    ctx: &Ctx<'_>,
) -> Result<Option<ModelChoice>, VerbError> {
    let not_allowed = |why: String| -> Result<Option<ModelChoice>, VerbError> {
        refuse(RefusalCode::ModelNotAllowed, why)
    };
    let current = &assignment.resolved_model;
    let is_model_change = reason == Some(RollReason::ModelChange);
    let requested = match (&args.model, &args.variant) {
        (None, _) if is_model_change => {
            return not_allowed(
                "model_change requires `model`: one of the unit's allowed models".into(),
            )
        }
        (None, None) => return Ok(None),
        (None, Some(variant)) => ModelChoice {
            variant: Some(variant.clone()),
            ..current.clone()
        },
        (Some(spec), variant) => {
            let mut choice = match parse_model_spec(spec) {
                Ok(ModelSpec::Fixed(choice)) => choice,
                Ok(ModelSpec::Auto) => {
                    return not_allowed("`auto` is not a model; name one of the unit's allowed models".into())
                }
                Err(e) => return not_allowed(format!("`{spec}` is not a model spec: {e:#}")),
            };
            if let Some(variant) = variant {
                match &choice.variant {
                    Some(inline) if inline != variant => {
                        return not_allowed(format!(
                            "`{spec}` names variant {inline} but `variant` says {variant}"
                        ))
                    }
                    _ => choice.variant = Some(variant.clone()),
                }
            }
            choice
        }
    };
    if &requested == current {
        return Ok(None);
    }
    // An undeclared unit's allowed list is the member default — exactly the
    // model this session was spawned on — and allows no change at all.
    let undeclared = ModelList::single(current.clone());
    let (allowed, declared) = match ctx.declared {
        Some(list) => (list, true),
        None => (&undeclared, false),
    };
    match validate_model_change(allowed, &requested, declared) {
        Ok(()) => Ok(Some(requested)),
        Err(_) if !declared => not_allowed(format!(
            "{} declares no `> Model:`, so it runs on the member default and allows no \
             model or variant change",
            describe_unit(ctx)
        )),
        Err(_) => not_allowed(format!(
            "{} is not in {}'s allowed list ({}); a follow-up may request only a listed \
             model, with any variant",
            render(&requested),
            describe_unit(ctx),
            allowed.entries().iter().map(render).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// A model choice as the `> Model:` grammar spells it.
fn render(choice: &ModelChoice) -> String {
    match choice.backend {
        softfig_ipc::model_choice::Backend::Claude => "claude".to_string(),
        softfig_ipc::model_choice::Backend::Opencode => choice.opencode_model_ref(),
    }
}

/// The §6.7 subset rule on every slice body the verb files: a `new_scope`
/// slice and each sub-milestone slice inherit the current unit's milestone
/// chain (the tree's resolved list — a sub's generated `CLAUDE.md` declares
/// nothing), and may declare only a subset of it.
fn check_slice_bodies(verb: &MemberVerb, ctx: &Ctx<'_>) -> Result<(), VerbError> {
    let bodies: Vec<&NewSliceArgs> = match verb {
        MemberVerb::AddFollowUpSession(a) => a.new_slice.iter().collect(),
        MemberVerb::AddSubMilestone(a) => a.slices.iter().collect(),
        _ => return Ok(()),
    };
    if bodies.is_empty() {
        return Ok(());
    }
    let (milestone, tree) = ctx.tree.expect("only a slice unit files slices");
    for slice in bodies {
        if let Some(why) = body_model_refusal(&slice.slug, &slice.body, milestone, tree.models.as_ref())
        {
            return refuse(RefusalCode::ModelNotAllowed, why);
        }
    }
    Ok(())
}

/// §6.7's subset rule on one new slice body filed into `milestone`, whose
/// tree resolves to `inherited` (`None` = nothing declared): `Some(why)` when
/// the body's `> Model:` line doesn't parse or declares more than a subset of
/// it. One rule for every path a member files a slice body down — the member
/// verbs' `new_slice` and sub slices, and a member's `slice_insert`
/// ([`crate::member_slices`]).
pub(crate) fn body_model_refusal(
    slug: &str,
    body: &str,
    milestone: &str,
    inherited: Option<&ModelList>,
) -> Option<String> {
    let field = item_model_field(body)?;
    let declared = match parse_declaration(field) {
        // `auto` is circular on an item doc and resolves as no declaration.
        Ok(Declaration::Auto) => return None,
        Ok(Declaration::List(list)) => list,
        Err(e) => return Some(format!("slice {slug}'s `> Model: {field}` does not parse: {e:#}")),
    };
    validate_declared_subset(inherited, &declared).err()?;
    let why = match inherited {
        None => format!("{milestone} declares no `> Model:`, so a new slice in it may declare none"),
        Some(list) => format!(
            "a new slice in {milestone} may declare only a subset of its inherited list ({})",
            list.entries().iter().map(render).collect::<Vec<_>>().join(", ")
        ),
    };
    Some(format!("slice {slug}'s `> Model: {field}` is refused: {why}"))
}

/// The baton step: the head parses with its required fields, its status is the
/// one this handoff carries, and its `item:` names this session's entry.
fn check_baton(verb: &MemberVerb, ctx: &Ctx<'_>) -> Result<(), VerbError> {
    // A sub-milestone's close-out completes the sub, not the entry, which runs
    // on into its parent's next unit: its baton is for that work, so it hands
    // on IN_PROGRESS like every handoff that continues the entry.
    let statuses = match (verb, ctx.unit) {
        (MemberVerb::CompleteEntry(_), Unit::CloseOut { milestone }) if milestone.contains('/') => {
            &["IN_PROGRESS"][..]
        }
        _ => verb.baton_statuses(),
    };
    let view = match validate_head(verb.baton(), statuses) {
        Ok(view) => view,
        Err(e) => return refuse(RefusalCode::BadBaton, e.to_string()),
    };
    let item = view.item.as_deref().unwrap_or_default();
    let item_top = item.split('/').next().unwrap_or(item);
    if item_top != ctx.entry.id {
        return refuse(
            RefusalCode::BadBaton,
            format!(
                "the baton's `item: {item}` is not this session's entry {}",
                ctx.entry.id
            ),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use softfig_ipc::growlightd::{BlockKind, EntryOutcome};
    use softfig_ipc::model_choice::{DEEPSEEK_FLASH, DEEPSEEK_REASONING};
    use softfig_ipc::queue_v2::Lane;
    use softfig_ipc::verbs::DeferredTestSpec;

    use crate::scheduler_v2::{ItemView, ProjectView};

    const MEMBER: &str = "oc";

    fn list(spec: &str) -> ModelList {
        match parse_declaration(spec).unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list, not auto"),
        }
    }

    fn entry(id: &str, kind: EntryKind, status: EntryStatus) -> EntryView {
        EntryView {
            id: id.into(),
            kind,
            project: "softfig".into(),
            lane: Lane::Normal,
            status,
            after: vec![],
            claimed: "2026-10-14T00:00Z".into(),
            follow_ups: 0,
            pending: None,
            holder: None,
            models: None,
        }
    }

    fn slice(id: &str, status: SliceStatus) -> ItemView {
        ItemView {
            kind: SliceKind::Slice,
            id: id.into(),
            status,
            models: None,
            follow_ups: 0,
        }
    }

    fn sub(id: &str, status: SliceStatus) -> ItemView {
        ItemView {
            kind: SliceKind::Sub,
            ..slice(id, status)
        }
    }

    /// Milestone `m` (active) with slices 001 done, 002 active (this session's),
    /// 003 queued — plus task `042` (active). No `> Model:` anywhere.
    fn snapshot() -> V2Snapshot {
        V2Snapshot {
            projects: vec![ProjectView {
                name: "softfig".into(),
                repo: "/r".into(),
            }],
            entries: vec![
                entry("m", EntryKind::Milestone, EntryStatus::Active),
                entry("042", EntryKind::Task, EntryStatus::Active),
            ],
            trees: BTreeMap::from([(
                "m".to_string(),
                TreeView {
                    items: vec![
                        slice("001", SliceStatus::Done),
                        slice("002", SliceStatus::Active),
                        slice("003", SliceStatus::Queued),
                    ],
                    models: None,
                },
            )]),
            done_ids: BTreeSet::new(),
        }
    }

    fn on_slice(milestone: &str, id: &str) -> V2Assignment {
        V2Assignment {
            agent: MEMBER.into(),
            entry: milestone.into(),
            unit: Unit::Slice {
                milestone: milestone.into(),
                slice: id.into(),
            },
            resolved_model: ModelChoice::opencode(DEEPSEEK_FLASH),
        }
    }

    fn on_task(id: &str) -> V2Assignment {
        V2Assignment {
            unit: Unit::Entry,
            ..on_slice(id, "-")
        }
    }

    fn on_close_out(milestone: &str) -> V2Assignment {
        V2Assignment {
            unit: Unit::CloseOut {
                milestone: milestone.into(),
            },
            ..on_slice(milestone, "-")
        }
    }

    fn baton(status: &str, item: &str) -> String {
        format!("---\nstatus: {status}\nitem: {item}\n---\n# NEXT ACTION\nnext\n")
    }

    fn follow_up(reason: &str) -> AddFollowUpSessionArgs {
        AddFollowUpSessionArgs {
            reason: reason.into(),
            baton: baton("IN_PROGRESS", "m"),
            model: None,
            variant: None,
            new_slice: None,
        }
    }

    fn new_slice(body: &str) -> NewSliceArgs {
        NewSliceArgs {
            slug: "found-work".into(),
            title: "Found work".into(),
            body: body.into(),
        }
    }

    fn complete_slice() -> MemberVerb {
        MemberVerb::CompleteSlice(CompleteSliceArgs {
            summary: "did it".into(),
            baton: baton("IN_PROGRESS", "m"),
        })
    }

    fn complete_entry(outcome: EntryOutcome, item: &str) -> MemberVerb {
        let (status, tests) = match outcome {
            EntryOutcome::Done => ("ITEM_COMPLETE", None),
            EntryOutcome::Deferred => (
                "ITEM_DEFERRED",
                Some(vec![DeferredTestSpec {
                    what: "run the smoke".into(),
                    expected: "it passes".into(),
                }]),
            ),
        };
        MemberVerb::CompleteEntry(CompleteEntryArgs {
            outcome,
            summary: "closed".into(),
            deferred_tests: tests,
            baton: baton(status, item),
        })
    }

    fn block(kind: BlockKind) -> MemberVerb {
        let status = match kind {
            BlockKind::Human => "BLOCKED_ON_HUMAN",
            BlockKind::Stuck => "STUCK",
        };
        MemberVerb::Block(BlockArgs {
            kind,
            reason: "needs a decision".into(),
            baton: baton(status, "m"),
        })
    }

    fn add_sub(slug: &str, bodies: &[&str]) -> MemberVerb {
        MemberVerb::AddSubMilestone(AddSubMilestoneArgs {
            slug: slug.into(),
            title: "Sub".into(),
            mission: "the rest".into(),
            finish_criteria: "done".into(),
            slices: bodies.iter().map(|b| new_slice(b)).collect(),
            do_not_prioritize: false,
            baton: baton("IN_PROGRESS", "m"),
        })
    }

    fn run(a: &V2Assignment, s: &V2Snapshot, verb: MemberVerb) -> Result<Validated, VerbError> {
        validate(MEMBER, a, s, verb)
    }

    #[track_caller]
    fn refused(result: Result<Validated, VerbError>, code: RefusalCode) -> String {
        match result {
            Err(VerbError::Refused(r)) => {
                assert_eq!(r.code, code, "{}", r.message);
                r.message
            }
            other => panic!("expected {code}, got {other:?}"),
        }
    }

    // ---- each verb's happy path: the validated action, no side effects ----

    #[test]
    fn each_verb_validates_on_its_own_unit() {
        let s = snapshot();
        let v = run(&on_slice("m", "002"), &s, MemberVerb::AddFollowUpSession(follow_up("context_full"))).unwrap();
        assert_eq!(v.member, MEMBER);
        assert_eq!(v.reason, Some(RollReason::ContextFull));
        assert_eq!(v.next_model, None, "no model asked → keep the current one");
        assert_eq!(v.assignment, on_slice("m", "002"));

        let v = run(&on_slice("m", "002"), &s, complete_slice()).unwrap();
        assert_eq!((v.reason, v.next_model), (None, None));

        run(&on_slice("m", "002"), &s, block(BlockKind::Human)).unwrap();
        run(&on_slice("m", "002"), &s, block(BlockKind::Stuck)).unwrap();
        run(&on_slice("m", "002"), &s, add_sub("rest", &["body"])).unwrap();

        // A task completes itself, done or deferred.
        run(&on_task("042"), &s, complete_entry(EntryOutcome::Done, "042")).unwrap();
        run(&on_task("042"), &s, complete_entry(EntryOutcome::Deferred, "042")).unwrap();

        // A close-out completes once every item is done/split/deferred.
        let mut closed = s.clone();
        closed.trees.get_mut("m").unwrap().items = vec![
            slice("001", SliceStatus::Done),
            slice("002", SliceStatus::Split),
            slice("003", SliceStatus::Deferred),
            sub("rest", SliceStatus::Done),
        ];
        run(&on_close_out("m"), &closed, complete_entry(EntryOutcome::Done, "m")).unwrap();
    }

    // ---- identity + assignment ----

    #[test]
    fn identity_and_assignment_refusals() {
        assert_eq!(identity(Some("oc")), Ok("oc"));
        assert_eq!(identity(None).unwrap_err().code, RefusalCode::NotAMember);
        assert_eq!(no_assignment("oc").code, RefusalCode::NotYourSession);

        let s = snapshot();
        // The entry left the list.
        refused(run(&on_slice("gone", "001"), &s, complete_slice()), RefusalCode::NotYourSession);
        // The entry is no longer active (e.g. the human dropped it back).
        let mut paused = s.clone();
        paused.entries[0].status = EntryStatus::Paused;
        refused(run(&on_slice("m", "002"), &paused, complete_slice()), RefusalCode::NotYourSession);
        // The slice isn't the active one this session was spawned on.
        refused(run(&on_slice("m", "003"), &s, complete_slice()), RefusalCode::NotYourSession);
        // The slice is gone.
        refused(run(&on_slice("m", "009"), &s, complete_slice()), RefusalCode::NotYourSession);
        // A unit naming a missing sub tree.
        refused(run(&on_slice("m/sub", "001"), &s, complete_slice()), RefusalCode::NotYourSession);
    }

    // ---- the reason step ----

    #[test]
    fn reason_step_refusals() {
        let s = snapshot();
        let a = on_slice("m", "002");
        let msg = refused(
            run(&a, &s, MemberVerb::AddFollowUpSession(follow_up("rate_limited"))),
            RefusalCode::UnknownReason,
        );
        assert!(msg.contains("context_full"), "the refusal lists the reasons: {msg}");

        refused(
            run(&a, &s, MemberVerb::AddFollowUpSession(follow_up("new_scope"))),
            RefusalCode::MissingNewSlice,
        );
        let mut with_slice = follow_up("context_full");
        with_slice.new_slice = Some(new_slice("b"));
        refused(
            run(&a, &s, MemberVerb::AddFollowUpSession(with_slice)),
            RefusalCode::NewSliceNotAllowed,
        );
        let mut scoped = follow_up("new_scope");
        scoped.new_slice = Some(new_slice("b"));
        let v = run(&a, &s, MemberVerb::AddFollowUpSession(scoped.clone())).unwrap();
        assert_eq!(v.reason, Some(RollReason::NewScope));

        // task_has_no_slices: on a task, and on a close-out.
        scoped.baton = baton("IN_PROGRESS", "042");
        refused(
            run(&on_task("042"), &s, MemberVerb::AddFollowUpSession(scoped.clone())),
            RefusalCode::TaskHasNoSlices,
        );
        refused(run(&on_task("042"), &s, complete_slice()), RefusalCode::TaskHasNoSlices);
        refused(run(&on_task("042"), &s, add_sub("rest", &["b"])), RefusalCode::TaskHasNoSlices);
        scoped.baton = baton("IN_PROGRESS", "m");
        refused(
            run(&on_close_out("m"), &s, MemberVerb::AddFollowUpSession(scoped)),
            RefusalCode::TaskHasNoSlices,
        );
        refused(run(&on_close_out("m"), &s, complete_slice()), RefusalCode::TaskHasNoSlices);

        // open_items: from a slice, and from a close-out with an open item.
        refused(
            run(&a, &s, complete_entry(EntryOutcome::Done, "m")),
            RefusalCode::OpenItems,
        );
        let msg = refused(
            run(&on_close_out("m"), &s, complete_entry(EntryOutcome::Deferred, "m")),
            RefusalCode::OpenItems,
        );
        assert!(msg.contains("m:002") && msg.contains("m:003"), "{msg}");
        let mut blocked_sub = s.clone();
        blocked_sub.trees.get_mut("m").unwrap().items =
            vec![slice("001", SliceStatus::Done), sub("rest", SliceStatus::Blocked)];
        refused(
            run(&on_close_out("m"), &blocked_sub, complete_entry(EntryOutcome::Done, "m")),
            RefusalCode::OpenItems,
        );
    }

    // ---- the cap step ----

    #[test]
    fn the_sixth_counted_follow_up_is_refused_and_preempted_never_is() {
        let mut s = snapshot();
        let a = on_slice("m", "002");
        s.trees.get_mut("m").unwrap().items[1].follow_ups = 4;
        run(&a, &s, MemberVerb::AddFollowUpSession(follow_up("session_fault"))).unwrap();

        s.trees.get_mut("m").unwrap().items[1].follow_ups = FOLLOW_UP_CAP;
        let msg = refused(
            run(&a, &s, MemberVerb::AddFollowUpSession(follow_up("context_full"))),
            RefusalCode::CapReached,
        );
        assert!(msg.contains("growlight_add_sub_milestone"), "a slice files a sub: {msg}");
        // `preempted` doesn't count, so it is never capped.
        run(&a, &s, MemberVerb::AddFollowUpSession(follow_up("preempted"))).unwrap();
        // The cap's remedy itself isn't capped.
        run(&a, &s, add_sub("rest", &["b"])).unwrap();

        // A task (and a close-out) counts on the entry; its end is a stuck block.
        s.entries[1].follow_ups = FOLLOW_UP_CAP;
        let mut task_follow_up = follow_up("mcp_updated");
        task_follow_up.baton = baton("IN_PROGRESS", "042");
        let msg = refused(
            run(&on_task("042"), &s, MemberVerb::AddFollowUpSession(task_follow_up)),
            RefusalCode::CapReached,
        );
        assert!(msg.contains("growlight_block kind = stuck"), "{msg}");
        s.entries[0].follow_ups = FOLLOW_UP_CAP;
        refused(
            run(&on_close_out("m"), &s, MemberVerb::AddFollowUpSession(follow_up("context_full"))),
            RefusalCode::CapReached,
        );
    }

    #[test]
    fn a_sub_milestone_two_deep_cannot_file_another_level() {
        let mut s = snapshot();
        for id in ["m/a", "m/a/b"] {
            s.trees.insert(
                id.to_string(),
                TreeView {
                    items: vec![slice("001", SliceStatus::Active)],
                    models: None,
                },
            );
        }
        run(&on_slice("m/a", "001"), &s, add_sub("deeper", &["b"])).unwrap();
        let msg = refused(
            run(&on_slice("m/a/b", "001"), &s, add_sub("deeper", &["b"])),
            RefusalCode::DepthLimit,
        );
        assert!(msg.contains("growlight_block kind = stuck"), "{msg}");
    }

    // ---- the model rule (§6.4 matrix) ----

    fn with_model(reason: &str, model: Option<&str>, variant: Option<&str>) -> MemberVerb {
        let mut a = follow_up(reason);
        a.model = model.map(str::to_string);
        a.variant = variant.map(str::to_string);
        MemberVerb::AddFollowUpSession(a)
    }

    #[test]
    fn model_change_may_request_any_listed_model_with_any_variant() {
        let mut s = snapshot();
        s.trees.get_mut("m").unwrap().items[1].models = Some(list("reasoning, flash"));
        let mut a = on_slice("m", "002");
        a.resolved_model = ModelChoice::opencode(DEEPSEEK_REASONING);

        let v = run(&a, &s, with_model("model_change", Some("flash"), None)).unwrap();
        assert_eq!(v.next_model, Some(ModelChoice::opencode(DEEPSEEK_FLASH)));
        let v = run(&a, &s, with_model("model_change", Some("flash"), Some("high"))).unwrap();
        assert_eq!(v.next_model.unwrap().variant.as_deref(), Some("high"));
        // A variant change alone is free within an allowed model.
        let v = run(&a, &s, with_model("context_full", None, Some("max"))).unwrap();
        assert_eq!(
            v.next_model,
            Some(ModelChoice {
                variant: Some("max".into()),
                ..ModelChoice::opencode(DEEPSEEK_REASONING)
            })
        );
        // Asking for the model it already runs is no change.
        let v = run(&a, &s, with_model("context_full", Some("reasoning"), None)).unwrap();
        assert_eq!(v.next_model, None);

        // Outside the list — including a pricier backend — is refused.
        let msg = refused(run(&a, &s, with_model("model_change", Some("claude"), None)), RefusalCode::ModelNotAllowed);
        assert!(msg.contains("allowed list"), "{msg}");
        refused(
            run(&a, &s, with_model("model_change", Some("anthropic/opus"), None)),
            RefusalCode::ModelNotAllowed,
        );
        // model_change names a model; `auto` and garbage aren't one.
        refused(run(&a, &s, with_model("model_change", None, Some("high"))), RefusalCode::ModelNotAllowed);
        refused(run(&a, &s, with_model("model_change", Some("auto"), None)), RefusalCode::ModelNotAllowed);
        refused(
            run(&a, &s, with_model("model_change", Some("flash variant=low"), Some("high"))),
            RefusalCode::ModelNotAllowed,
        );
    }

    #[test]
    fn a_single_entry_list_allows_variant_only_and_undeclared_allows_nothing() {
        let mut s = snapshot();
        s.trees.get_mut("m").unwrap().items[1].models = Some(list("flash"));
        let a = on_slice("m", "002");
        run(&a, &s, with_model("model_change", Some("flash variant=high"), None)).unwrap();
        refused(run(&a, &s, with_model("model_change", Some("reasoning"), None)), RefusalCode::ModelNotAllowed);

        // Undeclared: the member default, no change at all — not even a variant.
        let s = snapshot();
        let msg = refused(run(&a, &s, with_model("model_change", Some("reasoning"), None)), RefusalCode::ModelNotAllowed);
        assert!(msg.contains("declares no `> Model:`"), "{msg}");
        refused(run(&a, &s, with_model("context_full", None, Some("high"))), RefusalCode::ModelNotAllowed);
        // …but keeping the current model is fine.
        run(&a, &s, with_model("context_full", Some("flash"), None)).unwrap();
    }

    // ---- the member write limits on slice bodies (§6.7 subset rule) ----

    #[test]
    fn a_filed_slice_may_declare_only_a_subset_of_its_inheritance() {
        let mut s = snapshot();
        s.trees.get_mut("m").unwrap().models = Some(list("reasoning, flash"));
        let a = on_slice("m", "002");
        let scoped = |body: &str| {
            let mut f = follow_up("new_scope");
            f.new_slice = Some(new_slice(body));
            MemberVerb::AddFollowUpSession(f)
        };
        run(&a, &s, scoped("> Model: flash\n\nwork")).unwrap();
        run(&a, &s, scoped("no declaration")).unwrap();
        run(&a, &s, add_sub("rest", &["> Model: reasoning\n\nx", "plain"])).unwrap();
        let msg = refused(run(&a, &s, scoped("> Model: flash, claude\n\nwork")), RefusalCode::ModelNotAllowed);
        assert!(msg.contains("subset"), "{msg}");
        refused(run(&a, &s, add_sub("rest", &["plain", "> Model: claude"])), RefusalCode::ModelNotAllowed);
        refused(run(&a, &s, scoped("> Model: reasoning,\n")), RefusalCode::ModelNotAllowed);

        // Inherited nothing ⇒ declare nothing.
        let s = snapshot();
        let msg = refused(run(&a, &s, scoped("> Model: flash\n")), RefusalCode::ModelNotAllowed);
        assert!(msg.contains("may declare none"), "{msg}");
        run(&a, &s, scoped("plain")).unwrap();
    }

    // ---- the baton step ----

    #[test]
    fn the_baton_must_carry_the_handoff_status_and_name_this_entry() {
        let s = snapshot();
        let a = on_slice("m", "002");
        let with_baton = |b: String| {
            MemberVerb::CompleteSlice(CompleteSliceArgs {
                summary: "s".into(),
                baton: b,
            })
        };
        refused(run(&a, &s, with_baton("no head".into())), RefusalCode::BadBaton);
        refused(run(&a, &s, with_baton(baton("ITEM_COMPLETE", "m"))), RefusalCode::BadBaton);
        let msg = refused(run(&a, &s, with_baton(baton("IN_PROGRESS", "other"))), RefusalCode::BadBaton);
        assert!(msg.contains("not this session's entry m"), "{msg}");
        // A sub-milestone path under the same top-level entry names it.
        run(&a, &s, with_baton(baton("IN_PROGRESS", "m/sub"))).unwrap();

        // Each verb's status: complete_entry by outcome, block by kind.
        refused(
            run(&on_task("042"), &s, MemberVerb::CompleteEntry(CompleteEntryArgs {
                outcome: EntryOutcome::Done,
                summary: "s".into(),
                deferred_tests: None,
                baton: baton("ITEM_DEFERRED", "042"),
            })),
            RefusalCode::BadBaton,
        );
        refused(
            run(&a, &s, MemberVerb::Block(BlockArgs {
                kind: BlockKind::Stuck,
                reason: "r".into(),
                baton: baton("BLOCKED_ON_HUMAN", "m"),
            })),
            RefusalCode::BadBaton,
        );
    }

    // ---- the §6.3 order + malformed arguments ----

    #[test]
    fn checks_run_in_the_spec_order() {
        let mut s = snapshot();
        s.trees.get_mut("m").unwrap().items[1].follow_ups = FOLLOW_UP_CAP;
        let a = on_slice("m", "002");
        let mut bad = follow_up("bogus");
        bad.baton = "no head".into();
        // reason before baton
        refused(run(&a, &s, MemberVerb::AddFollowUpSession(bad.clone())), RefusalCode::UnknownReason);
        // assignment before reason
        refused(run(&on_slice("m", "003"), &s, MemberVerb::AddFollowUpSession(bad.clone())), RefusalCode::NotYourSession);
        // cap before model and baton
        bad.reason = "model_change".into();
        bad.model = Some("claude".into());
        refused(run(&a, &s, MemberVerb::AddFollowUpSession(bad.clone())), RefusalCode::CapReached);
        // model before baton
        s.trees.get_mut("m").unwrap().items[1].follow_ups = 0;
        refused(run(&a, &s, MemberVerb::AddFollowUpSession(bad)), RefusalCode::ModelNotAllowed);
    }

    #[test]
    fn arguments_the_code_list_does_not_name_are_bad_args() {
        let s = snapshot();
        let t = on_task("042");
        let bad = |verb| matches!(run(&t, &s, verb), Err(VerbError::BadArgs(_)));
        assert!(bad(MemberVerb::CompleteEntry(CompleteEntryArgs {
            outcome: EntryOutcome::Deferred,
            summary: "s".into(),
            deferred_tests: None,
            baton: baton("ITEM_DEFERRED", "042"),
        })));
        assert!(bad(MemberVerb::CompleteEntry(CompleteEntryArgs {
            outcome: EntryOutcome::Done,
            summary: "s".into(),
            deferred_tests: Some(vec![]),
            baton: baton("ITEM_COMPLETE", "042"),
        })));
        assert!(bad(MemberVerb::CompleteSlice(CompleteSliceArgs {
            summary: "  ".into(),
            baton: baton("IN_PROGRESS", "042"),
        })));
        assert!(bad(add_sub("rest", &[])));
    }

    // ---- slice 010: the cap's ends, the sub-milestone's slug and text ----

    /// §7: at the cap, a milestone slice files its remaining work as a
    /// sub-milestone — the refusal names that move, and the verb validates.
    #[test]
    fn at_the_cap_a_milestone_slice_files_a_sub_milestone() {
        let mut s = snapshot();
        s.trees.get_mut("m").unwrap().items[1].follow_ups = FOLLOW_UP_CAP;
        let a = on_slice("m", "002");
        let msg = refused(
            run(&a, &s, MemberVerb::AddFollowUpSession(follow_up("context_full"))),
            RefusalCode::CapReached,
        );
        assert!(msg.contains("growlight_add_sub_milestone"), "{msg}");
        run(&a, &s, add_sub("rest", &["body"])).unwrap();
    }

    /// §7: a task, a restack or a close-out at the cap has nothing to split
    /// into — the refusal names `growlight_block kind = stuck`, a sub-milestone
    /// is refused, and the stuck block validates and executes as a block (the
    /// entry `blocked`, @human alerted).
    #[test]
    fn at_the_cap_a_task_restack_or_close_out_ends_in_a_stuck_block() {
        let mut s = snapshot();
        s.entries.push(entry("043", EntryKind::Restack, EntryStatus::Active));
        s.entries.push(entry("c", EntryKind::Milestone, EntryStatus::Active));
        s.trees.insert(
            "c".into(),
            TreeView {
                items: vec![slice("001", SliceStatus::Done)],
                models: None,
            },
        );
        for e in &mut s.entries {
            e.follow_ups = FOLLOW_UP_CAP;
        }
        for (a, item) in [(on_task("042"), "042"), (on_task("043"), "043"), (on_close_out("c"), "c")] {
            let mut f = follow_up("session_fault");
            f.baton = baton("IN_PROGRESS", item);
            let msg = refused(run(&a, &s, MemberVerb::AddFollowUpSession(f)), RefusalCode::CapReached);
            assert!(msg.contains("growlight_block kind = stuck"), "{item}: {msg}");
            refused(run(&a, &s, add_sub("rest", &["b"])), RefusalCode::TaskHasNoSlices);

            let stuck = MemberVerb::Block(BlockArgs {
                kind: BlockKind::Stuck,
                reason: "the cap is spent; left: the parser".into(),
                baton: baton("STUCK", item),
            });
            let v = run(&a, &s, stuck).unwrap();
            let p = crate::member_handoff::plan(&v, &s).unwrap();
            assert_eq!(
                p.ops.last(),
                Some(&crate::member_handoff::KeeperOp::SetStatus {
                    entry: item.into(),
                    unit: None,
                    new: softfig_ipc::verbs::DaemonStatusArg::Blocked,
                }),
                "{item}",
            );
            assert!(p.alert.is_some_and(|t| t.contains("stuck: the cap is spent")), "{item}");
        }
    }

    fn with_sub(edit: impl FnOnce(&mut AddSubMilestoneArgs)) -> MemberVerb {
        let MemberVerb::AddSubMilestone(mut args) = add_sub("rest", &["work"]) else {
            unreachable!()
        };
        edit(&mut args);
        MemberVerb::AddSubMilestone(args)
    }

    /// §6.7: keeperd writes the sub's docs from its fields, so the member's
    /// text may set no model, grants or worktree there; a slice body's
    /// `> Model:` is the subset rule's instead.
    #[test]
    fn a_sub_milestones_text_may_not_carry_reserved_lines() {
        let s = snapshot();
        let a = on_slice("m", "002");
        let msg = refused(
            run(&a, &s, with_sub(|x| x.mission.push_str("\n> Model: claude"))),
            RefusalCode::FieldNotAllowed,
        );
        assert!(msg.contains("`mission` carries a `> Model:` line"), "{msg}");
        refused(
            run(&a, &s, with_sub(|x| x.finish_criteria = "> Worktree: /tmp/w".into())),
            RefusalCode::FieldNotAllowed,
        );
        refused(
            run(&a, &s, with_sub(|x| x.slices[0].title = "> Grants: ~/projects".into())),
            RefusalCode::FieldNotAllowed,
        );
        let msg = refused(
            run(&a, &s, with_sub(|x| x.slices[0].body = "> Grants: ~/projects\n\nwork".into())),
            RefusalCode::FieldNotAllowed,
        );
        assert!(msg.contains("`slices[0].body`"), "{msg}");
        // m declares nothing, so a body may declare nothing (the subset rule).
        refused(
            run(&a, &s, with_sub(|x| x.slices[0].body = "> Model: flash\n\nwork".into())),
            RefusalCode::ModelNotAllowed,
        );
    }

    /// A slug keeperd would refuse is refused here, before the handshake's
    /// commit point: a bad shape, or a sub slug some item of the parent's list
    /// already uses.
    #[test]
    fn a_slug_keeperd_would_refuse_is_bad_args_before_anything_commits() {
        let s = snapshot();
        let a = on_slice("m", "002");
        let bad = |r: Result<Validated, VerbError>, needle: &str| match r {
            Err(VerbError::BadArgs(m)) => assert!(m.contains(needle), "{m}"),
            other => panic!("expected bad args naming {needle}, got {other:?}"),
        };
        bad(run(&a, &s, add_sub("The_Rest", &["b"])), "`slug`");
        bad(run(&a, &s, add_sub("003", &["b"])), "already an item of m's slice list");
        bad(run(&a, &s, with_sub(|x| x.slices[0].slug = "two words".into())), "`slices[0].slug`");
        let mut f = follow_up("new_scope");
        f.new_slice = Some(NewSliceArgs {
            slug: "x".repeat(SLUG_MAX + 1),
            ..new_slice("b")
        });
        bad(run(&a, &s, MemberVerb::AddFollowUpSession(f)), "`new_slice.slug`");
    }

    /// A sub-milestone's close-out completes the sub and the entry runs on, so
    /// its baton hands on IN_PROGRESS — a terminal one is refused.
    #[test]
    fn a_sub_close_out_hands_on_an_in_progress_baton() {
        let mut s = snapshot();
        s.trees.get_mut("m").unwrap().items[1] = slice("002", SliceStatus::Split);
        s.trees.get_mut("m").unwrap().items.insert(2, sub("rest", SliceStatus::Queued));
        s.trees.insert(
            "m/rest".into(),
            TreeView {
                items: vec![slice("001", SliceStatus::Done)],
                models: None,
            },
        );
        let a = on_close_out("m/rest");
        refused(run(&a, &s, complete_entry(EntryOutcome::Done, "m")), RefusalCode::BadBaton);
        let MemberVerb::CompleteEntry(mut args) = complete_entry(EntryOutcome::Done, "m") else {
            unreachable!()
        };
        args.baton = baton("IN_PROGRESS", "m");
        run(&a, &s, MemberVerb::CompleteEntry(args)).unwrap();
    }
}
