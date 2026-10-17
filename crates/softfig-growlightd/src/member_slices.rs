//! A fleet member's two §6.8 slice verbs (spec-growlight-queue §6.7,
//! queue-v2-scheduling slice 011): `slice_insert`, and `slice_update` with
//! `move` only — both **within the member's own current entry**, and never
//! moving its own `active` slice. Pure, like [`crate::member_verbs`].
//!
//! ## Where it sits
//!
//! softfig-mcp stamps a member session's identity on the request; keeperd
//! sees a stamped `slice_insert` / `slice_update` and relays it here as a
//! [`MemberCall`](softfig_ipc::growlightd::MemberCall), because only
//! growlightd knows which entry the member holds (the drive loop's mirror,
//! [`crate::daemon::Daemon::v2_assignment`]). The server checks it here, then
//! issues the plain human verb to keeperd as its own client — no member, so
//! keeperd serves it as any human call and applies the §6.8 rules every
//! caller gets (`started` for a started item, `unknown_id`, …) — and relays
//! keeperd's reply verbatim. growlightd's own `new_scope` insert (slice 009)
//! never comes through here: it is a daemon call, not a member's.
//!
//! softfig-mcp has already refused everything else a member may not call
//! (`member_not_allowed`, before any socket); a stamped `status` change is
//! refused here too, since this is where a member's slice call is validated.
//!
//! ## Decisions recorded in the slice doc
//!
//! - "Within the member's own current entry" is the entry's whole tree: the
//!   queue entry the assignment names (its top-level id) and every
//!   sub-milestone under it. A member that holds no v2 entry has none, so
//!   every slice call is refused.
//! - Moving its own `active` slice is refused `member_not_allowed` here, ahead
//!   of keeperd's `started` for any active item, so the member reads why.
//! - A `slice_insert` body may declare a `> Model:` list only as a subset of
//!   what the new slice inherits (`model_not_allowed` otherwise), the one rule
//!   [`crate::member_verbs`] holds a member verb's slice bodies to. A milestone
//!   the snapshot has no tree for has nothing to take a subset of: a body that
//!   declares a model there is refused; one that declares none is left to
//!   keeperd.

use softfig_ipc::verbs::{SliceInsertArgs, SliceUpdateArgs};

use crate::drive_loop::V2Assignment;
use crate::member_verbs::body_model_refusal;
use crate::scheduler_v2::{Unit, V2Snapshot};

/// The spec citation every refusal here ends with.
const RULE: &str = "spec-growlight-queue §6.7";

/// Hold a member's `slice_insert` to §6.7. `Err` is the wire message, led by
/// its code (`member_not_allowed` or `model_not_allowed`).
pub fn check_insert(
    member: &str,
    assignment: Option<&V2Assignment>,
    snapshot: &V2Snapshot,
    args: &SliceInsertArgs,
) -> Result<(), String> {
    let assignment = held_entry(member, assignment, "slice_insert")?;
    within_entry(member, assignment, "slice_insert", &args.milestone)?;
    let inherited = match snapshot.trees.get(&args.milestone) {
        Some(tree) => tree.models.as_ref(),
        None if softfig_ipc::model_choice::item_model_field(&args.body).is_some() => {
            return Err(format!(
                "model_not_allowed: {} has no slice list in the v2 queue, so a new slice there \
                 has nothing to declare a subset of ({RULE})",
                args.milestone
            ))
        }
        None => return Ok(()),
    };
    match body_model_refusal(&args.slug, &args.body, &args.milestone, inherited) {
        Some(why) => Err(format!("model_not_allowed: {why} ({RULE})")),
        None => Ok(()),
    }
}

/// Hold a member's `slice_update` to §6.7: `move` only, within its own entry,
/// and never its own `active` slice.
pub fn check_update(
    member: &str,
    assignment: Option<&V2Assignment>,
    args: &SliceUpdateArgs,
) -> Result<(), String> {
    if args.status.is_some() {
        return Err(format!(
            "member_not_allowed: a fleet member's slice_update may only `move` — a slice's status \
             is the human's or the daemon's ({RULE})"
        ));
    }
    let assignment = held_entry(member, assignment, "slice_update")?;
    within_entry(member, assignment, "slice_update", &args.milestone)?;
    if let Unit::Slice { milestone, slice } = &assignment.unit {
        if *milestone == args.milestone && *slice == args.id {
            return Err(format!(
                "member_not_allowed: slice {} in {milestone} is the slice member {member} is \
                 working, and a member may not move its own active slice ({RULE})",
                args.id
            ));
        }
    }
    Ok(())
}

/// The member's live assignment, or the refusal for a member holding none.
fn held_entry<'a>(
    member: &str,
    assignment: Option<&'a V2Assignment>,
    verb: &str,
) -> Result<&'a V2Assignment, String> {
    assignment.ok_or_else(|| {
        format!(
            "member_not_allowed: member {member} holds no v2 entry, and a member's {verb} reaches \
             only its own current entry ({RULE})"
        )
    })
}

/// Refuse a `milestone` outside the assignment's entry tree.
fn within_entry(
    member: &str,
    assignment: &V2Assignment,
    verb: &str,
    milestone: &str,
) -> Result<(), String> {
    let entry = assignment.entry.split('/').next().unwrap_or_default();
    let inside = milestone
        .strip_prefix(entry)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
    if inside {
        return Ok(());
    }
    Err(format!(
        "member_not_allowed: {milestone} is outside member {member}'s own entry {entry}, and a \
         member's {verb} reaches only its own current entry ({RULE})"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use softfig_ipc::model_choice::{parse_declaration, Declaration, ModelChoice, ModelList};
    use softfig_ipc::queue_v2::SliceStatus;
    use softfig_ipc::verbs::QueueMoveSpec;

    use crate::scheduler_v2::TreeView;

    fn list(spec: &str) -> ModelList {
        match parse_declaration(spec).unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("{spec} is auto"),
        }
    }

    fn assignment(entry: &str, unit: Unit) -> V2Assignment {
        V2Assignment {
            agent: "c".into(),
            entry: entry.into(),
            unit,
            resolved_model: ModelChoice::claude(),
        }
    }

    fn on_slice(milestone: &str, slice: &str) -> V2Assignment {
        let entry = milestone.split('/').next().unwrap();
        let unit = Unit::Slice { milestone: milestone.into(), slice: slice.into() };
        assignment(if milestone.contains('/') { milestone } else { entry }, unit)
    }

    /// `m` inherits `claude, flash`; its sub `m/s` resolves the same; `bare`
    /// declares nothing.
    fn snapshot() -> V2Snapshot {
        let tree = |models: Option<ModelList>| TreeView { items: vec![], models };
        let mut trees = BTreeMap::new();
        trees.insert("m".to_string(), tree(Some(list("claude, flash"))));
        trees.insert("m/s".to_string(), tree(Some(list("claude, flash"))));
        trees.insert("bare".to_string(), tree(None));
        V2Snapshot {
            projects: vec![],
            entries: vec![],
            trees,
            done_ids: BTreeSet::new(),
        }
    }

    fn insert(milestone: &str, body: &str) -> SliceInsertArgs {
        SliceInsertArgs {
            milestone: milestone.into(),
            slug: "found".into(),
            title: None,
            body: body.into(),
            position: None,
            ref_id: None,
            dry_run: false,
        }
    }

    fn update(milestone: &str, id: &str) -> SliceUpdateArgs {
        SliceUpdateArgs {
            milestone: milestone.into(),
            id: id.into(),
            move_spec: Some(QueueMoveSpec { to: "front".into(), ref_id: None }),
            status: None,
            dry_run: false,
        }
    }

    fn code(r: Result<(), String>) -> String {
        let msg = r.unwrap_err();
        msg.split(':').next().unwrap().to_string()
    }

    #[test]
    fn an_insert_reaches_only_the_members_own_entry_tree() {
        let a = on_slice("m/s", "002");
        let snap = snapshot();
        assert_eq!(check_insert("c", Some(&a), &snap, &insert("m", "work")), Ok(()), "the entry");
        assert_eq!(check_insert("c", Some(&a), &snap, &insert("m/s", "work")), Ok(()), "its sub");
        assert_eq!(check_insert("c", Some(&a), &snap, &insert("m/t", "work")), Ok(()), "a sibling sub");
        assert_eq!(code(check_insert("c", Some(&a), &snap, &insert("bare", "work"))), "member_not_allowed");
        assert_eq!(code(check_insert("c", Some(&a), &snap, &insert("mx", "work"))), "member_not_allowed", "a prefix is not a tree");
        assert_eq!(code(check_insert("c", None, &snap, &insert("m", "work"))), "member_not_allowed", "no entry held");
    }

    /// The subset matrix: an allowed subset, `auto`, and nothing declared pass;
    /// a superset, a foreign model, an unparsable line, and any declaration
    /// where nothing is inherited (or nothing is known) are `model_not_allowed`.
    #[test]
    fn an_inserted_body_may_declare_only_a_subset_of_what_it_inherits() {
        let snap = snapshot();
        let m = on_slice("m", "001");
        let ok = |body: &str| check_insert("c", Some(&m), &snap, &insert("m", body));
        assert_eq!(ok("> Model: flash\n\nwork"), Ok(()), "a subset");
        assert_eq!(ok("> Model: claude, flash\n\nwork"), Ok(()), "the whole list");
        assert_eq!(ok("> Model: auto\n\nwork"), Ok(()), "auto declares nothing");
        assert_eq!(ok("work, no model"), Ok(()));
        assert_eq!(code(ok("> Model: reasoning\n\nwork")), "model_not_allowed", "outside the list");
        assert_eq!(code(ok("> Model: claude, flash, reasoning\n")), "model_not_allowed", "a superset");
        assert_eq!(code(ok("> Model: ???\n")), "model_not_allowed", "unparsable");

        let bare = assignment("bare", Unit::Slice { milestone: "bare".into(), slice: "001".into() });
        let msg = check_insert("c", Some(&bare), &snap, &insert("bare", "> Model: flash\n")).unwrap_err();
        assert!(msg.starts_with("model_not_allowed:") && msg.contains("may declare none"), "{msg}");
        assert_eq!(check_insert("c", Some(&bare), &snap, &insert("bare", "work")), Ok(()));

        let unknown = check_insert("c", Some(&m), &snap, &insert("m/new", "> Model: flash\n"));
        assert_eq!(code(unknown), "model_not_allowed", "no tree, nothing to take a subset of");
        assert_eq!(check_insert("c", Some(&m), &snap, &insert("m/new", "work")), Ok(()), "keeperd decides");
    }

    #[test]
    fn an_update_is_a_move_within_the_entry_never_of_the_members_own_slice() {
        let a = on_slice("m", "002");
        assert_eq!(check_update("c", Some(&a), &update("m", "003")), Ok(()));
        assert_eq!(check_update("c", Some(&a), &update("m/s", "002")), Ok(()), "same id, other tree");
        let own = check_update("c", Some(&a), &update("m", "002")).unwrap_err();
        assert!(own.starts_with("member_not_allowed:") && own.contains("own active slice"), "{own}");
        assert_eq!(code(check_update("c", Some(&a), &update("other", "001"))), "member_not_allowed");
        assert_eq!(code(check_update("c", None, &update("m", "003"))), "member_not_allowed");

        let mut status = update("m", "003");
        status.status = Some(SliceStatus::Done);
        let msg = check_update("c", Some(&a), &status).unwrap_err();
        assert!(msg.starts_with("member_not_allowed:") && msg.contains("only `move`"), "{msg}");

        let close_out = assignment("m", Unit::CloseOut { milestone: "m".into() });
        assert_eq!(check_update("c", Some(&close_out), &update("m", "002")), Ok(()), "no active slice");
    }
}
