//! The queue v2 §6.8 human verbs — `queue_add_project`, `queue_add_entry`
//! (all three kinds) and `queue_update_entry` — the v2 writers end to end
//! (milestone `queue-v2-state`, slices 004–005).
//!
//! Each verb follows [`super::v2::write`]'s contract: load
//! ([`super::v2::state`]), mutate the in-memory models, validate (the
//! slice-002 [`QueueRefusal`] vocabulary), stage the entry's docs through
//! the worktree, then call [`apply`] once with every changed TOML file and
//! every view that must re-render — the whole-file CAS checks, the view
//! upserts, and exactly one commit land together; the verb never commits
//! itself. A `dry_run` stops before `apply`: everything is computed,
//! validated and rendered, nothing is committed, and the reply carries the
//! would-be queue view so the §6.9 CLI can print it. A no-op
//! `queue_update_entry` edit mints no commit, like the legacy reorder verb.
//!
//! Refusals leave as wire errors whose message is the [`QueueRefusal`]
//! display — which leads with the wire code ([`QueueRefusal::code`]), the
//! stable prefix a client can branch on. Shape errors (an empty field, an
//! unknown placement keyword, an arg a kind does not take) are plain
//! `BadArgs`.

use std::collections::HashSet;

use softfig_ipc::queue_v2::{
    ArchivedEntry, Entry, EntryKind, EntryStatus, FinalStatus, Lane, Project, QueueArchiveToml,
    QueueRefusal, QueueToml, SliceItem, SliceKind, SliceStatus, SlicesToml, QUEUE_ARCHIVE_FILE,
};
use softfig_ipc::verbs::{
    QueueAddEntryArgs, QueueAddEntryReply, QueueAddProjectArgs, QueueAddProjectReply,
    QueueStatusArg, QueueUpdateEntryArgs, QueueUpdateEntryReply,
};
use softfig_ipc::ErrorKind;

use super::super::numbering;
use super::v2::{
    apply, load_queue_state, milestone_path, queue_view, queue_view_host, slices_file,
    slices_view, slices_view_host, FileWrite, ViewWrite, QUEUE_FILE, QUEUE_V2_TAG, SLICES_V2_TAG,
};
use super::{conventions, paths, queue, WorkTree};
use crate::actions::backlinks;
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{require_unlocked, HandlerResult};
use crate::server::err_to_response;

// ---- queue_add_project -------------------------------------------------

pub fn queue_add_project(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueAddProjectArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_add_project args: {e}")))?;
    // Shape + name checks before the lock, like the legacy verbs.
    if conventions::validate_slug(&args.name).is_err() {
        return Err(refuse(QueueRefusal::BadName { name: args.name.clone() }));
    }
    if args.repo.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "repo must be non-empty".to_string()));
    }
    let main = args.main.as_deref().unwrap_or("main");
    if main.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "main must be non-empty".to_string()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    // Load the live list (fail-closed), refuse a duplicate name, and append
    // the row. A new project cannot violate a §3.1 invariant (no entry
    // references it yet, and the duplicate check covers id uniqueness), so
    // no re-validation is needed here.
    let (mut queue, queue_version) = {
        let wt = WorkTree::new(daemon, &inner);
        match load_queue_state(&wt, &inner) {
            Ok(Some(qs)) => {
                if qs.queue.model.projects.iter().any(|p| p.name == args.name) {
                    return Err(refuse(QueueRefusal::Exists { id: args.name.clone() }));
                }
                (qs.queue.model, qs.queue.version)
            }
            Ok(None) => (QueueToml::new(vec![], vec![]), None),
            Err(e) => return Err((ErrorKind::Internal, e.to_string())),
        }
    };
    queue.projects.push(Project {
        name: args.name.clone(),
        repo: args.repo.clone(),
        main: main.to_string(),
    });
    let bytes = queue
        .to_toml()
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?
        .into_bytes();
    // The §3.4 region re-renders the lane view; the reply's "would-be list"
    // is the projects table — projects don't appear in the queue view.
    let view = queue_view(&queue);
    let list = projects_view(&queue.projects);

    if args.dry_run {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueAddProjectReply {
            name: args.name,
            view: list,
            hash,
        })
        .unwrap());
    }

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({
            "verb": "queue_add_project",
            "name": args.name,
            "repo": args.repo,
            "main": main,
        }),
        &[FileWrite {
            rel: QUEUE_FILE.to_string(),
            expected: queue_version,
            bytes,
        }],
        &[ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(view.clone()),
        }],
    )?;

    Ok(serde_json::to_value(QueueAddProjectReply {
        name: args.name,
        view: list,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- queue_add_entry (all three kinds) ---------------------------------

pub fn queue_add_entry(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueAddEntryArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_add_entry args: {e}")))?;
    match args.kind {
        EntryKind::Milestone => add_milestone(daemon, args),
        EntryKind::Task => add_task(daemon, args),
        EntryKind::Restack => add_restack(daemon, args),
    }
}

/// A required non-empty `Option` arg (the wire structs keep the per-kind
/// required fields optional so `restack` can refuse them all with one rule).
fn required(opt: Option<String>, field: &str) -> Result<String, (ErrorKind, String)> {
    match opt {
        Some(v) if !v.trim().is_empty() => Ok(v),
        _ => Err((ErrorKind::BadArgs, format!("{field} must be non-empty"))),
    }
}

/// Load the live v2 state for an entry-adding verb and refuse an unknown
/// project and unresolvable `after` links (a link resolves to a live entry or
/// a `done`-archived row, §3.1 invariant 3). `Ok(None)` state (no v2 files
/// yet) means no projects exist, so every project is unknown.
fn load_for_add(
    wt: &WorkTree,
    inner: &DaemonInner,
    project: &str,
    after: &[String],
) -> Result<(QueueToml, Option<String>, QueueArchiveToml), (ErrorKind, String)> {
    match load_queue_state(wt, inner) {
        Ok(Some(qs)) => {
            if !qs.queue.model.projects.iter().any(|p| p.name == project) {
                return Err(refuse(QueueRefusal::UnknownProject {
                    project: project.to_string(),
                }));
            }
            let done: HashSet<&str> = qs
                .archive
                .model
                .entries
                .iter()
                .filter(|a| a.final_status == FinalStatus::Done)
                .map(|a| a.row.id.as_str())
                .collect();
            for link in after {
                if !qs.queue.model.entries.iter().any(|e| &e.id == link)
                    && !done.contains(link.as_str())
                {
                    return Err(refuse(QueueRefusal::UnknownId { id: link.clone() }));
                }
            }
            Ok((qs.queue.model, qs.queue.version, qs.archive.model))
        }
        Ok(None) => Err(refuse(QueueRefusal::UnknownProject {
            project: project.to_string(),
        })),
        Err(e) => Err((ErrorKind::Internal, e.to_string())),
    }
}

fn add_milestone(daemon: &Daemon, args: QueueAddEntryArgs) -> HandlerResult {
    let slug = required(args.slug, "slug")?;
    let title = required(args.title, "title")?;
    let mission = required(args.mission, "mission")?;
    let finish = required(args.finish_criteria, "finish_criteria")?;
    if conventions::validate_slug(&slug).is_err() {
        return Err(refuse(QueueRefusal::BadName { name: slug.clone() }));
    }
    let lane = args.lane.unwrap_or(Lane::Normal);
    let position = parse_position(args.position.as_deref(), args.ref_id.as_deref())?;
    for spec in &args.slices {
        if conventions::validate_slug(&spec.slug).is_err() {
            return Err(refuse(QueueRefusal::BadName { name: spec.slug.clone() }));
        }
        if spec.body.trim().is_empty() {
            return Err((
                ErrorKind::BadArgs,
                format!("slices: body must be non-empty for {:?}", spec.slug),
            ));
        }
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    // The milestone's main doc is the dir's canary: it and every file under
    // it (the slice docs, `.seq`, `slices.toml`) are new, so each is a
    // first-creation write.
    let doc_rel = slices_view_host(&slug);
    let slices_dir = format!("{}/slices", milestone_path(&slug));

    let (mut queue, queue_version, archive) = {
        let wt = WorkTree::new(daemon, &inner);
        if wt.exists(&doc_rel) {
            return Err(refuse(QueueRefusal::Exists { id: slug.clone() }));
        }
        load_for_add(&wt, &inner, &args.project, &args.after)?
    };

    let added = conventions::now_rfc3339();
    let date = conventions::today_hyphen();
    let doc_content = milestone_doc_v2(&slug, &title, &mission, &finish);

    // The slice set, numbered deterministically: the milestone dir was just
    // proven absent, so the first slice is 001 and `.seq` ends at the count.
    let (slice_docs, items, seq): (Vec<(String, String)>, Vec<SliceItem>, u32) =
        if args.slices.is_empty() {
            // §4: a milestone given no slices gets the generated planning
            // slice, so every milestone starts with a slice.
            (
                vec![(
                    format!("{slices_dir}/{}", conventions::note_filename(1, "plan")),
                    conventions::note_doc("Plan", &date, &plan_slice_body(&mission)),
                )],
                vec![slice_item(1)],
                1,
            )
        } else {
            let n = args.slices.len() as u32;
            let mut docs = Vec::with_capacity(n as usize);
            let mut items = Vec::with_capacity(n as usize);
            for (i, spec) in args.slices.iter().enumerate() {
                let number = i as u32 + 1;
                let title = spec.title.as_deref().unwrap_or(&spec.slug);
                docs.push((
                    format!("{slices_dir}/{}", conventions::note_filename(number, &spec.slug)),
                    conventions::note_doc(title, &date, &spec.body),
                ));
                items.push(slice_item(number));
            }
            (docs, items, n)
        };
    let slices_model = SlicesToml::new(slug.clone(), items);

    // The entry row, placed inside its lane (§6.8: `front | back | before |
    // after`, with `ref` for the last two; a `back` entry appends to its
    // lane's back, the §2 default).
    let entry = Entry {
        id: slug.clone(),
        kind: EntryKind::Milestone,
        title,
        project: args.project.clone(),
        lane,
        status: EntryStatus::Queued,
        after: args.after.clone(),
        added,
        branch: format!("feat/{slug}"),
        parent: String::new(),
        base: String::new(),
        claimed: String::new(),
        follow_ups: 0,
    };
    let idx = place_entry(&queue.entries, lane, &position).map_err(refuse)?;
    queue.entries.insert(idx, entry);

    // Backstop: the mutated file must still satisfy every §3.1 invariant.
    // The pre-checks cover the project, the links and the milestone dir, but
    // e.g. a milestone slug equal to a task's NNN only surfaces here (ids
    // are one namespace across the live file and the archive). Fail closed,
    // refuse the write.
    queue.validate(&archive).map_err(refuse)?;

    let files = [
        FileWrite {
            rel: QUEUE_FILE.to_string(),
            expected: queue_version,
            bytes: queue
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_bytes(),
        },
        FileWrite {
            rel: slices_file(&slug),
            expected: None,
            bytes: slices_model
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_bytes(),
        },
    ];
    let view = queue_view(&queue);
    let views = [
        ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(view.clone()),
        },
        ViewWrite {
            host: doc_rel.clone(),
            tag: SLICES_V2_TAG,
            body: Some(slices_view(&slices_model)),
        },
    ];

    if args.dry_run {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueAddEntryReply {
            id: slug,
            path: doc_rel,
            view,
            hash,
        })
        .unwrap());
    }

    // Stage the entry's docs through the worktree (like `add_backlog_item`),
    // refresh backlinks, then let `apply` carry everything in its one commit.
    {
        let wt = WorkTree::new(daemon, &inner);
        wt.write(&doc_rel, doc_content.as_bytes())?;
        wt.write(&format!("{slices_dir}/{}", conventions::SEQ_FILE), format!("{seq}\n").as_bytes())?;
        for (rel, content) in &slice_docs {
            wt.write(rel, content.as_bytes())?;
        }
        backlinks::refresh_all(&wt, &inner);
    }

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({
            "verb": "queue_add_entry",
            "id": slug,
            "kind": "milestone",
            "project": args.project,
        }),
        &files,
        &views,
    )?;

    Ok(serde_json::to_value(QueueAddEntryReply {
        id: slug,
        path: doc_rel,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
}

/// `queue_add_entry`, task kind: a numbered standalone doc
/// `tasks/NNN-<slug>.md` (the tasks `.seq` shared with restacks, as the
/// legacy `add_backlog_item` does), id = the NNN, `branch = fix/<NNN>` —
/// §3.1's `fix/<id>` where the id is only known after numbering (finding 4).
/// Tasks have no `slices.toml` (§4), so a non-empty `slices` arg is refused.
fn add_task(daemon: &Daemon, args: QueueAddEntryArgs) -> HandlerResult {
    let slug = required(args.slug, "slug")?;
    let title = required(args.title, "title")?;
    let mission = required(args.mission, "mission")?;
    let finish = required(args.finish_criteria, "finish_criteria")?;
    if conventions::validate_slug(&slug).is_err() {
        return Err(refuse(QueueRefusal::BadName { name: slug.clone() }));
    }
    if !args.slices.is_empty() {
        return Err((
            ErrorKind::BadArgs,
            "task kind takes no slices: tasks have no slices.toml (§4)".to_string(),
        ));
    }
    let lane = args.lane.unwrap_or(Lane::Normal);
    let position = parse_position(args.position.as_deref(), args.ref_id.as_deref())?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let tasks_dir = paths::tasks_dir();
    let (number, task_rel) = {
        let wt = WorkTree::new(daemon, &inner);
        let number = numbering::next_number(&wt, &tasks_dir);
        let task_rel = format!("{tasks_dir}/{}", conventions::note_filename(number, &slug));
        if wt.exists(&task_rel) {
            // A corrupt `.seq` squatting a live slot (write_numbered refuses
            // the same way); surface it as the spec's `exists` refusal.
            return Err(refuse(QueueRefusal::Exists {
                id: format!("{number:03}"),
            }));
        }
        (number, task_rel)
    };
    let id = format!("{number:03}");

    let (mut queue, queue_version, archive) = {
        let wt = WorkTree::new(daemon, &inner);
        load_for_add(&wt, &inner, &args.project, &args.after)?
    };

    let entry = Entry {
        id: id.clone(),
        kind: EntryKind::Task,
        title: title.clone(),
        project: args.project.clone(),
        lane,
        status: EntryStatus::Queued,
        after: args.after.clone(),
        added: conventions::now_rfc3339(),
        branch: format!("fix/{id}"),
        parent: String::new(),
        base: String::new(),
        claimed: String::new(),
        follow_ups: 0,
    };
    let doc_content = task_doc_v2(&id, &title, &mission, &finish);
    let idx = place_entry(&queue.entries, lane, &position).map_err(refuse)?;
    queue.entries.insert(idx, entry);
    queue.validate(&archive).map_err(refuse)?;

    let files = [FileWrite {
        rel: QUEUE_FILE.to_string(),
        expected: queue_version,
        bytes: queue
            .to_toml()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
            .into_bytes(),
    }];
    let view = queue_view(&queue);

    if args.dry_run {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueAddEntryReply {
            id: id.clone(),
            path: task_rel,
            view,
            hash,
        })
        .unwrap());
    }

    {
        let wt = WorkTree::new(daemon, &inner);
        numbering::write_numbered(&wt, &tasks_dir, number, &task_rel, &doc_content)?;
        backlinks::refresh_all(&wt, &inner);
    }

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({
            "verb": "queue_add_entry",
            "id": id,
            "kind": "task",
            "project": args.project,
        }),
        &files,
        &[ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(view.clone()),
        }],
    )?;

    Ok(serde_json::to_value(QueueAddEntryReply {
        id,
        path: task_rel,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
}

/// `queue_add_entry`, restack kind (§8): keeperd's half of the auto-restack
/// enqueue — `project` only, every other arg refused as `BadArgs` (finding 5:
/// the §6.8 state-refusal list has no code for a shape mismatch). The doc is
/// the minimal placeholder `tasks/NNN-restack-<project>.md` (the full
/// generated template — stack in order, steps, gate — is `queue-v2-git`'s);
/// the row is urgent-lane, no branch, appended to the urgent lane's back.
fn add_restack(daemon: &Daemon, args: QueueAddEntryArgs) -> HandlerResult {
    for (name, given) in [
        ("slug", args.slug.is_some()),
        ("title", args.title.is_some()),
        ("mission", args.mission.is_some()),
        ("finish_criteria", args.finish_criteria.is_some()),
        ("lane", args.lane.is_some()),
        ("position", args.position.is_some()),
        ("ref", args.ref_id.is_some()),
        ("after", !args.after.is_empty()),
        ("slices", !args.slices.is_empty()),
    ] {
        if given {
            return Err((
                ErrorKind::BadArgs,
                format!("restack kind takes only kind + project: {name} is not allowed"),
            ));
        }
    }
    if args.project.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "project must be non-empty".to_string()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let tasks_dir = paths::tasks_dir();
    let (number, task_rel) = {
        let wt = WorkTree::new(daemon, &inner);
        let number = numbering::next_number(&wt, &tasks_dir);
        let slug = format!("restack-{}", args.project);
        let task_rel = format!("{tasks_dir}/{}", conventions::note_filename(number, &slug));
        if wt.exists(&task_rel) {
            return Err(refuse(QueueRefusal::Exists {
                id: format!("{number:03}"),
            }));
        }
        (number, task_rel)
    };
    let id = format!("{number:03}");

    let (mut queue, queue_version, archive) = {
        let wt = WorkTree::new(daemon, &inner);
        load_for_add(&wt, &inner, &args.project, &[])?
    };

    let entry = Entry {
        id: id.clone(),
        kind: EntryKind::Restack,
        title: format!("Restack {}", args.project),
        project: args.project.clone(),
        lane: Lane::Urgent,
        status: EntryStatus::Queued,
        after: vec![],
        added: conventions::now_rfc3339(),
        branch: String::new(),
        parent: String::new(),
        base: String::new(),
        claimed: String::new(),
        follow_ups: 0,
    };
    // §6.8/§8: urgent lane, appended at the urgent lane's back — the
    // position args were refused above, so the placement is fixed.
    let idx = place_entry(&queue.entries, Lane::Urgent, &V2Position::Back).map_err(refuse)?;
    queue.entries.insert(idx, entry);
    queue.validate(&archive).map_err(refuse)?;

    let files = [FileWrite {
        rel: QUEUE_FILE.to_string(),
        expected: queue_version,
        bytes: queue
            .to_toml()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
            .into_bytes(),
    }];
    let view = queue_view(&queue);

    if args.dry_run {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueAddEntryReply {
            id: id.clone(),
            path: task_rel,
            view,
            hash,
        })
        .unwrap());
    }

    {
        let wt = WorkTree::new(daemon, &inner);
        let content = restack_doc(&args.project, &conventions::today_hyphen());
        numbering::write_numbered(&wt, &tasks_dir, number, &task_rel, &content)?;
        backlinks::refresh_all(&wt, &inner);
    }

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({
            "verb": "queue_add_entry",
            "id": id,
            "kind": "restack",
            "project": args.project,
        }),
        &files,
        &[ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(view.clone()),
        }],
    )?;

    Ok(serde_json::to_value(QueueAddEntryReply {
        id,
        path: task_rel,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- queue_update_entry -------------------------------------------------

pub fn queue_update_entry(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueUpdateEntryArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_update_entry args: {e}")))?;
    if args.id.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "id must be non-empty".to_string()));
    }
    // The move's shape (the position keyword + its ref rule) checks before
    // the lock, like the add verbs'.
    let move_pos = match &args.move_spec {
        Some(m) => Some(parse_position(Some(&m.to), m.ref_id.as_deref())?),
        None => None,
    };

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    // Load the live list + archive, keeping the loaded models for the no-op
    // guard (an edit that changes nothing mints no commit).
    let (mut queue, queue_version, mut archive, archive_version, loaded_queue, loaded_archive) = {
        let wt = WorkTree::new(daemon, &inner);
        match load_queue_state(&wt, &inner) {
            Ok(Some(qs)) => (
                qs.queue.model.clone(),
                qs.queue.version,
                qs.archive.model.clone(),
                qs.archive.version,
                qs.queue.model,
                qs.archive.model,
            ),
            Ok(None) => return Err(refuse(QueueRefusal::UnknownId { id: args.id.clone() })),
            Err(e) => return Err((ErrorKind::Internal, e.to_string())),
        }
    };
    if !queue.entries.iter().any(|e| e.id == args.id) {
        return Err(refuse(QueueRefusal::UnknownId { id: args.id.clone() }));
    }

    // 1. lane: to urgent appends at the urgent lane's back; to normal puts it
    // at the normal lane's front (§6.8). `parent`/`base`/`claimed` stay — the
    // row moves, and its own `lane` field must move with it (position and
    // field always agree).
    if let Some(new_lane) = args.lane {
        if queue.entries[idx_of(&queue, &args.id)].lane != new_lane {
            let mut e = queue.entries.remove(idx_of(&queue, &args.id));
            e.lane = new_lane;
            let at = match new_lane {
                Lane::Urgent => place_entry(&queue.entries, Lane::Urgent, &V2Position::Back),
                Lane::Normal => place_entry(&queue.entries, Lane::Normal, &V2Position::Front),
            }
            .map_err(refuse)?;
            queue.entries.insert(at, e);
        }
    }

    // 2. move: within the lane. Refused `started` once the entry is claimed
    // (the stack order is the claim order, §8); a ref in the other lane is
    // `lane_mismatch`; a self-ref is a shape error (the legacy reorder verb's
    // RefIsSelf rule).
    if let Some(pos) = move_pos {
        if matches!(
            &pos,
            V2Position::Before(r) | V2Position::After(r) if r == &args.id
        ) {
            return Err((
                ErrorKind::BadArgs,
                format!("cannot move entry {:?} relative to itself", args.id),
            ));
        }
        let idx = idx_of(&queue, &args.id);
        if !queue.entries[idx].claimed.is_empty() {
            return Err(refuse(QueueRefusal::Started { id: args.id.clone() }));
        }
        let e = queue.entries.remove(idx);
        let at = place_entry(&queue.entries, e.lane, &pos).map_err(refuse)?;
        queue.entries.insert(at, e);
    }

    // 3. after: replaces the whole link list (`[]` clears it). Every id must
    // resolve to a live entry or a `done`-archived row; a cycle cannot pass
    // the backstop validate below (the new list is live edges only).
    if let Some(links) = args.after {
        let done: HashSet<&str> = archive
            .entries
            .iter()
            .filter(|a| a.final_status == FinalStatus::Done)
            .map(|a| a.row.id.as_str())
            .collect();
        for link in &links {
            if !queue.entries.iter().any(|e| &e.id == link) && !done.contains(link.as_str()) {
                return Err(refuse(QueueRefusal::UnknownId { id: link.clone() }));
            }
        }
        let idx = idx_of(&queue, &args.id);
        queue.entries[idx].after = links;
    }

    // 4. status. `done` is the human's override — no open-items check — and
    // moves the row to the archive (appended, `finished` stamped,
    // `final_status = done`, which still satisfies `after` links).
    let mut archived = false;
    if let Some(status) = args.status {
        match status {
            QueueStatusArg::Active | QueueStatusArg::Paused | QueueStatusArg::Split => {
                return Err(refuse(QueueRefusal::DaemonOwned { id: args.id.clone() }))
            }
            QueueStatusArg::Done => {
                let idx = idx_of(&queue, &args.id);
                // §6.8: done (or a drop) of an `active` entry is refused
                // `running` — the running session is never killed. A paused /
                // blocked / deferred entry has no running session, so the
                // human override stands.
                if queue.entries[idx].status == EntryStatus::Active {
                    return Err(refuse(QueueRefusal::Running { id: args.id.clone() }));
                }
                let row = queue.entries.remove(idx);
                archive.entries.push(ArchivedEntry {
                    row,
                    finished: conventions::now_rfc3339(),
                    final_status: FinalStatus::Done,
                    reason: None,
                });
                archived = true;
            }
            // Finding 8: other status changes on an `active` entry are
            // applied immediately here. The spec's "takes effect at the next
            // handshake" deferral needs the handshake itself, which
            // queue-v2-scheduling builds; the running session is never
            // killed either way.
            QueueStatusArg::Queued => {
                let idx = idx_of(&queue, &args.id);
                queue.entries[idx].status = EntryStatus::Queued; // also unblocks and un-defers
            }
            QueueStatusArg::Blocked => {
                let idx = idx_of(&queue, &args.id);
                queue.entries[idx].status = EntryStatus::Blocked;
            }
            QueueStatusArg::Deferred => {
                let idx = idx_of(&queue, &args.id);
                queue.entries[idx].status = EntryStatus::Deferred;
            }
        }
    }

    // No-op guard: an edit that changed nothing (same lane, same position,
    // same links, same status) mints no commit — the legacy reorder verb's
    // idempotence. Return the untouched tip without touching apply.
    if queue == loaded_queue && archive == loaded_archive {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueUpdateEntryReply {
            id: args.id,
            view: queue_view(&queue),
            hash,
        })
        .unwrap());
    }

    // Backstop: every §3.1 invariant still holds (a fresh `after` cycle, an
    // urgent→normal move colliding with the one-active-per-repo rule, …).
    queue.validate(&archive).map_err(refuse)?;

    let view = queue_view(&queue);
    if args.dry_run {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueUpdateEntryReply {
            id: args.id,
            view,
            hash,
        })
        .unwrap());
    }

    let mut files = vec![FileWrite {
        rel: QUEUE_FILE.to_string(),
        expected: queue_version,
        bytes: queue
            .to_toml()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
            .into_bytes(),
    }];
    if archived {
        files.push(FileWrite {
            rel: QUEUE_ARCHIVE_FILE.to_string(),
            expected: archive_version,
            bytes: archive
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_bytes(),
        });
    }

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({ "verb": "queue_update_entry", "id": args.id }),
        &files,
        &[ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(view.clone()),
        }],
    )?;

    Ok(serde_json::to_value(QueueUpdateEntryReply {
        id: args.id,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
}

/// The entry's index; the verb proved the id exists, so this never misses.
fn idx_of(queue: &QueueToml, id: &str) -> usize {
    queue
        .entries
        .iter()
        .position(|e| e.id == id)
        .expect("the entry exists")
}

// ---- shared helpers ----------------------------------------------------

/// A §6.8 state refusal as a wire error: the most semantic [`ErrorKind`] for
/// the transport, with the refusal's display as the message — it leads with
/// the wire code ([`QueueRefusal::code`]), the stable prefix a client can
/// branch on.
fn refuse(r: QueueRefusal) -> (ErrorKind, String) {
    let kind = match &r {
        QueueRefusal::Exists { .. } => ErrorKind::PathAlreadyExists,
        QueueRefusal::BadName { .. } => ErrorKind::InvalidSlug,
        QueueRefusal::UnknownProject { .. } | QueueRefusal::UnknownId { .. } => {
            ErrorKind::NotFound
        }
        _ => ErrorKind::BadArgs,
    };
    (kind, r.to_string())
}

/// The untouched tip hash — a dry run's reply `hash` (no commit is minted).
fn current_tip(inner: &DaemonInner) -> Result<String, (ErrorKind, String)> {
    let tip = inner
        .repo
        .as_ref()
        .expect("unlocked")
        .tip()
        .map_err(|e| err_to_response(e.into()))?
        .map(|h| h.to_string())
        .unwrap_or_default();
    Ok(tip)
}

/// A freshly written slice's `slices.toml` item (§3.3): `follow_ups` starts
/// at 0.
fn slice_item(number: u32) -> SliceItem {
    SliceItem {
        kind: SliceKind::Slice,
        id: format!("{number:03}"),
        status: SliceStatus::Queued,
        follow_ups: Some(0),
    }
}

/// The projects table a `queue_add_project` reply carries — the "would-be
/// list" a §6.9 `--dry-run` prints. Reply-only: it is not a §3.4 derived
/// region (the spec's derived views are the queue list and the slice order),
/// and projects appear nowhere in the queue view.
fn projects_view(projects: &[Project]) -> String {
    let mut out = String::from("| name | repo | main |\n|---|------|------|");
    for p in projects {
        out.push_str(&format!(
            "\n| {} | {} | {} |",
            queue::escape(&p.name),
            queue::escape(&p.repo),
            queue::escape(&p.main),
        ));
    }
    out.push('\n');
    out
}

/// `queue_add_entry`'s placement keyword (§6.8): `front | back | before |
/// after`, inside the entry's own lane.
enum V2Position {
    Front,
    Back,
    Before(String),
    After(String),
}

fn parse_position(
    position: Option<&str>,
    ref_id: Option<&str>,
) -> Result<V2Position, (ErrorKind, String)> {
    let position = position.unwrap_or("back");
    let ref_id = ref_id.map(str::trim).filter(|s| !s.is_empty());
    match position {
        "front" | "back" => {
            if ref_id.is_some() {
                return Err((ErrorKind::BadArgs, format!("position {position:?} takes no ref")));
            }
            Ok(if position == "front" {
                V2Position::Front
            } else {
                V2Position::Back
            })
        }
        "before" | "after" => {
            let r = ref_id
                .ok_or_else(|| (ErrorKind::BadArgs, format!("position {position:?} requires ref")))?;
            Ok(if position == "before" {
                V2Position::Before(r.to_string())
            } else {
                V2Position::After(r.to_string())
            })
        }
        other => Err((
            ErrorKind::BadArgs,
            format!("position {other:?}: must be one of front / back / before / after"),
        )),
    }
}

/// The front of `lane` in file order — index 0 for the urgent lane (the §3.1
/// invariant keeps urgent rows ahead of normal ones), the end of the list for
/// the normal lane.
fn lane_front(entries: &[Entry], lane: Lane) -> usize {
    match entries.iter().position(|e| e.lane == lane) {
        Some(i) => i,
        None => match lane {
            Lane::Urgent => 0,
            Lane::Normal => entries.len(),
        },
    }
}

/// The index where a new `lane` entry lands for `position`, staying within
/// the lane (§6.8). `before`/`after` place around `ref`, which must be a live
/// entry in the same lane.
fn place_entry(
    entries: &[Entry],
    lane: Lane,
    position: &V2Position,
) -> Result<usize, QueueRefusal> {
    match position {
        V2Position::Front => Ok(lane_front(entries, lane)),
        V2Position::Back => Ok(match entries.iter().rposition(|e| e.lane == lane) {
            Some(i) => i + 1,
            None => lane_front(entries, lane),
        }),
        V2Position::Before(r) => ref_index(entries, lane, r),
        V2Position::After(r) => Ok(ref_index(entries, lane, r)? + 1),
    }
}

fn ref_index(entries: &[Entry], lane: Lane, r: &str) -> Result<usize, QueueRefusal> {
    let idx = entries
        .iter()
        .position(|e| e.id == r)
        .ok_or_else(|| QueueRefusal::UnknownId { id: r.to_string() })?;
    if entries[idx].lane != lane {
        return Err(QueueRefusal::LaneMismatch { id: r.to_string() });
    }
    Ok(idx)
}

/// The v2 milestone doc: the legacy `milestone_doc` shape (mission + finish
/// criteria) plus the one-line pointer that status, lane, links and branch
/// live in `queue.toml`, not prose (§6.8, "docs as add_backlog_item does").
fn milestone_doc_v2(id: &str, title: &str, mission: &str, finish: &str) -> String {
    format!(
        "# backlog: {title}\n\n\
         > Milestone `{id}`. Status, lane, `after` links and branch live in \
         `queue.toml` (the derived `softfig:queue-v2` table in `../../CLAUDE.md`); \
         slices run in `slices.toml` order (the derived table below) and this item \
         is done only when all are done and integration is verified.\n\n\
         ## Mission\n\n{}\n\n\
         ## Finish criteria\n\n{}\n",
        mission.trim_end_matches('\n'),
        finish.trim_end_matches('\n'),
    )
}

/// §4's generated planning slice, numbered `001-plan`: every milestone starts
/// with a slice, so there is no unplanned case.
fn plan_slice_body(mission: &str) -> String {
    format!(
        "> Model: reasoning\n\n\
         This milestone was added without slices. Plan it:\n\n\
         1. Read the mission below (it lives in `../../CLAUDE.md`) and the spec it names.\n\
         2. Write the milestone's slices with `slice_insert`, each sized to one \
            session (the protocol's 25–50% context band), each declaring a \
            single-entry `> Model:`.\n\
         3. End with `growlight_complete_slice`.\n\n\
         Mission:\n\n{}",
        mission.trim_end_matches('\n')
    )
}

/// The v2 task doc: the legacy `task_doc` shape (notes-style heading +
/// reviewed stamp + mission + finish criteria) plus the same queue.toml
/// pointer the milestone doc carries — the doc never holds status, and the
/// pointer is `../CLAUDE.md` from `tasks/`.
fn task_doc_v2(id: &str, title: &str, mission: &str, finish: &str) -> String {
    format!(
        "# {title}\n\n\
         > Task `{id}`. Status, lane, `after` links and branch live in \
         `queue.toml` (the derived `softfig:queue-v2` table in `../CLAUDE.md`).\n\n\
         > Last reviewed: {}\n\n\
         ## Mission\n\n{}\n\n\
         ## Finish criteria\n\n{}\n",
        conventions::today_hyphen(),
        mission.trim_end_matches('\n'),
        finish.trim_end_matches('\n'),
    )
}

/// The minimal restack doc this milestone writes: §8's full template — the
/// stack in order with each branch's `parent` and `base`, the steps, the gate
/// command — is `queue-v2-git`'s (the milestone finish criteria say so).
/// Until then the doc is a placeholder carrying the one pointer that matters.
fn restack_doc(project: &str, date_hyphen: &str) -> String {
    format!(
        "# Restack {project}\n\n\
         > Last reviewed: {date_hyphen}\n\n\
         > Generated restack entry for project `{project}` (queue v2 §8). Lane, \
         status and branch live in `queue.toml` (the derived `softfig:queue-v2` \
         table in `../CLAUDE.md`). The full doc — the stack in order, the steps, \
         the gate command — is generated by `queue-v2-git`.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::growlight::v2::write::tests::unlocked;
    use crate::actions::managed;
    use softfig_ipc::queue_v2::{
        ArchivedEntry, FinalStatus, Project, QueueArchiveToml, SlicesToml, QUEUE_ARCHIVE_FILE,
    };
    use softfig_vcs::{log, TIP_REF};

    fn commit_count(daemon: &Daemon) -> usize {
        let inner = daemon.inner.lock().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        let tip = repo.tip_of(TIP_REF).unwrap().expect("genesis tip");
        log::collect(repo.db(), tip).unwrap().len()
    }

    fn project() -> Project {
        Project {
            name: "softfig".to_string(),
            repo: "~/p".to_string(),
            main: "main".to_string(),
        }
    }

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

    fn add_project(daemon: &Daemon, name: &str, repo: &str) -> QueueAddProjectReply {
        let v = queue_add_project(daemon, serde_json::json!({ "name": name, "repo": repo }))
            .expect("add_project");
        serde_json::from_value(v).unwrap()
    }

    fn add_entry(
        daemon: &Daemon,
        args: serde_json::Value,
    ) -> Result<QueueAddEntryReply, (ErrorKind, String)> {
        queue_add_entry(daemon, args).map(|v| serde_json::from_value(v).unwrap())
    }

    /// `queue_add_entry` args for a milestone, plus `extra` keys merged in.
    fn milestone_args(slug: &str, project: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut a = serde_json::json!({
            "kind": "milestone",
            "slug": slug,
            "title": format!("{slug} title"),
            "mission": format!("{slug} mission"),
            "finish_criteria": format!("{slug} criteria"),
            "project": project,
        });
        if let (serde_json::Value::Object(m), serde_json::Value::Object(x)) = (&mut a, extra) {
            for (k, v) in x {
                m.insert(k, v);
            }
        }
        a
    }

    #[test]
    fn add_project_creates_the_first_v2_file_and_renders_the_view() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let before = commit_count(&daemon);

        let reply = add_project(&daemon, "softfig", "~/p");

        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit per verb");
        assert!(reply.view.contains("| name | repo | main |"), "{:?}", reply.view);
        assert!(reply.view.contains("softfig"), "{:?}", reply.view);

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        // The file round-trips through the fail-closed loader.
        let qs = load_queue_state(&wt, &inner).unwrap().expect("queue exists");
        assert_eq!(qs.queue.model.projects.len(), 1);
        assert_eq!(qs.queue.model.projects[0].name, "softfig");
        assert_eq!(qs.queue.model.projects[0].repo, "~/p");
        assert_eq!(qs.queue.model.projects[0].main, "main");
        // The view rendered into the backlog doc, inside the managed region —
        // the lane view, not the reply's projects table.
        let backlog = wt.read_to_string(&queue_view_host()).unwrap();
        assert!(managed::has_region(&backlog, QUEUE_V2_TAG));
        let region = managed::region_body(&backlog, QUEUE_V2_TAG).expect("region body");
        assert!(region.contains("### Urgent") && region.contains("### Normal"), "{region}");
        assert!(!region.contains("| name | repo | main |"), "{region}");
    }

    #[test]
    fn add_project_appends_refuses_duplicates_and_bad_shapes() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_project(&daemon, "other", "host:r");

        // Appends preserve order.
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
            let names: Vec<&str> = qs.queue.model.projects.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, ["softfig", "other"]);
        }

        // Duplicate name → `exists`, no commit minted.
        let before = commit_count(&daemon);
        let err = queue_add_project(&daemon, serde_json::json!({ "name": "softfig", "repo": "~/x" }))
            .unwrap_err();
        assert_eq!(err.0, ErrorKind::PathAlreadyExists);
        assert!(err.1.starts_with("exists:"), "{:?}", err.1);

        // Bad name → `bad_name`; empty repo is a shape error.
        let err = queue_add_project(&daemon, serde_json::json!({ "name": "Bad Name", "repo": "~/x" }))
            .unwrap_err();
        assert!(err.1.starts_with("bad_name:"), "{:?}", err.1);
        let err = queue_add_project(&daemon, serde_json::json!({ "name": "ok", "repo": "  " }))
            .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs);
        assert_eq!(commit_count(&daemon), before, "refusals mint no commit");
    }

    #[test]
    fn add_project_dry_run_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let before = commit_count(&daemon);

        let v = queue_add_project(
            &daemon,
            serde_json::json!({ "name": "softfig", "repo": "~/p", "dry_run": true }),
        )
        .expect("dry run computes");
        let reply: QueueAddProjectReply = serde_json::from_value(v).unwrap();

        assert_eq!(commit_count(&daemon), before, "no commit on a dry run");
        assert!(!garden.path().join(QUEUE_FILE).exists(), "no queue.toml written");
        assert!(reply.view.contains("softfig"), "the would-be list: {:?}", reply.view);
    }

    #[test]
    fn add_entry_unplanned_milestone_generates_the_001_plan_slice() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        let before = commit_count(&daemon);

        let reply = add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({})))
            .expect("add entry");
        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit per verb");
        assert_eq!(reply.id, "m1");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt
            .read_to_string("growlight/backlog/milestones/m1/CLAUDE.md")
            .expect("milestone doc");
        assert!(doc.contains("## Mission") && doc.contains("m1 mission"), "{doc}");
        assert!(doc.contains("queue.toml"), "the branch/status pointer, {doc}");
        assert!(managed::has_region(&doc, SLICES_V2_TAG), "slices view rendered");

        let plan = wt
            .read_to_string("growlight/backlog/milestones/m1/slices/001-plan.md")
            .expect("generated plan slice");
        assert!(plan.starts_with("# Plan\n"), "{plan}");
        assert!(plan.contains("> Model: reasoning"), "{plan}");
        assert!(plan.contains("slice_insert"), "{plan}");
        assert!(plan.contains("m1 mission"), "the mission rides the plan body, {plan}");
        assert_eq!(
            wt.read_to_string("growlight/backlog/milestones/m1/slices/.seq").unwrap(),
            "1\n"
        );

        let s = SlicesToml::parse(&wt.read_to_string(&slices_file("m1")).expect("slices.toml"))
            .expect("slices.toml parses");
        assert_eq!(s.items.len(), 1);
        assert_eq!(s.items[0].id, "001");
        assert_eq!(s.items[0].status, SliceStatus::Queued);

        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let e = &qs.queue.model.entries[0];
        assert_eq!(e.id, "m1");
        assert_eq!(e.kind, EntryKind::Milestone);
        assert_eq!(e.branch, "feat/m1");
        assert_eq!(e.status, EntryStatus::Queued);
        assert_eq!(e.lane, Lane::Normal);
        assert!(!e.added.is_empty());

        let backlog = wt.read_to_string(&queue_view_host()).unwrap();
        let body = managed::region_body(&backlog, QUEUE_V2_TAG).expect("queue view");
        assert!(body.contains("m1"), "{body}");
    }

    #[test]
    fn add_entry_planned_milestone_writes_the_given_slices() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");

        add_entry(
            &daemon,
            milestone_args(
                "m2",
                "softfig",
                serde_json::json!({
                    "slices": [
                        { "slug": "types", "body": "build the types" },
                        { "slug": "verbs", "title": "The verbs", "body": "build the verbs" }
                    ]
                }),
            ),
        )
        .expect("add entry");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let a = wt
            .read_to_string("growlight/backlog/milestones/m2/slices/001-types.md")
            .expect("slice 001");
        assert!(a.starts_with("# types\n"), "default title = slug, {a}");
        assert!(a.contains("build the types"));
        let b = wt
            .read_to_string("growlight/backlog/milestones/m2/slices/002-verbs.md")
            .expect("slice 002");
        assert!(b.starts_with("# The verbs\n"), "given title wins, {b}");
        assert_eq!(
            wt.read_to_string("growlight/backlog/milestones/m2/slices/.seq").unwrap(),
            "2\n"
        );
        assert!(!wt.exists("growlight/backlog/milestones/m2/slices/001-plan.md"));

        let s = SlicesToml::parse(&wt.read_to_string(&slices_file("m2")).expect("slices.toml"))
            .expect("slices.toml parses");
        assert_eq!(s.items.len(), 2);
        assert_eq!(s.items[0].id, "001");
        assert_eq!(s.items[1].id, "002");
        assert!(s.items.iter().all(|i| i.follow_ups == Some(0)));
    }

    #[test]
    fn add_entry_places_entries_within_their_lane() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("n1", "softfig", serde_json::json!({}))).unwrap();
        // Urgent with default back lands at the urgent lane's front (there is
        // no urgent lane yet, and urgent rows precede normal ones).
        add_entry(
            &daemon,
            milestone_args("u1", "softfig", serde_json::json!({ "lane": "urgent" })),
        )
        .unwrap();
        // Front within the normal lane.
        add_entry(
            &daemon,
            milestone_args("n0", "softfig", serde_json::json!({ "position": "front" })),
        )
        .unwrap();
        // Before a normal ref.
        add_entry(
            &daemon,
            milestone_args(
                "nx",
                "softfig",
                serde_json::json!({ "position": "before", "ref": "n1" }),
            ),
        )
        .unwrap();
        // After an urgent ref, and one more urgent back (appends after u2).
        add_entry(
            &daemon,
            milestone_args(
                "u2",
                "softfig",
                serde_json::json!({ "lane": "urgent", "position": "after", "ref": "u1" }),
            ),
        )
        .unwrap();
        add_entry(
            &daemon,
            milestone_args("u3", "softfig", serde_json::json!({ "lane": "urgent" })),
        )
        .unwrap();

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["u1", "u2", "u3", "n0", "nx", "n1"]);
    }

    #[test]
    fn add_entry_refuses_each_failure_path() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");

        // Unknown project.
        let err = add_entry(&daemon, milestone_args("x", "ghost", serde_json::json!({}))).unwrap_err();
        assert!(err.1.starts_with("unknown_project:"), "{:?}", err.1);
        // Bad slug.
        let err = add_entry(&daemon, milestone_args("Bad Slug", "softfig", serde_json::json!({})))
            .unwrap_err();
        assert!(err.1.starts_with("bad_name:"), "{:?}", err.1);
        // Duplicate milestone.
        add_entry(&daemon, milestone_args("dup", "softfig", serde_json::json!({}))).unwrap();
        let err = add_entry(&daemon, milestone_args("dup", "softfig", serde_json::json!({})))
            .unwrap_err();
        assert!(err.1.starts_with("exists:"), "{:?}", err.1);
        // after-link to nowhere.
        let err = add_entry(
            &daemon,
            milestone_args("y", "softfig", serde_json::json!({ "after": ["ghost"] })),
        )
        .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{:?}", err.1);
        // Cross-lane before-ref.
        let err = add_entry(
            &daemon,
            milestone_args(
                "z",
                "softfig",
                serde_json::json!({ "lane": "urgent", "position": "before", "ref": "dup" }),
            ),
        )
        .unwrap_err();
        assert!(err.1.starts_with("lane_mismatch:"), "{:?}", err.1);
        // Unknown placement ref.
        let err = add_entry(
            &daemon,
            milestone_args("w", "softfig", serde_json::json!({ "position": "before", "ref": "ghost" })),
        )
        .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{:?}", err.1);
        // An unknown position keyword is a shape error.
        let err = add_entry(
            &daemon,
            milestone_args("v", "softfig", serde_json::json!({ "position": "sideways" })),
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs);

        // None of the refusals minted a commit beyond the one real entry.
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        assert_eq!(qs.queue.model.entries.len(), 1, "only 'dup' was added");
    }

    #[test]
    fn add_entry_after_link_to_a_done_archive_row_is_accepted() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // Seed: the project + an archived `done` row "old".
        {
            let q = QueueToml::new(vec![project()], vec![]);
            let archive = QueueArchiveToml::new(vec![ArchivedEntry {
                row: entry("old"),
                finished: "2026-10-11T16:00:00Z".to_string(),
                final_status: FinalStatus::Done,
                reason: None,
            }]);
            let mut inner = daemon.inner.lock().unwrap();
            apply(
                &daemon,
                &mut inner,
                "queue_v2_updated",
                serde_json::json!({}),
                &[
                    FileWrite {
                        rel: QUEUE_FILE.to_string(),
                        expected: None,
                        bytes: q.to_toml().unwrap().into_bytes(),
                    },
                    FileWrite {
                        rel: QUEUE_ARCHIVE_FILE.to_string(),
                        expected: None,
                        bytes: archive.to_toml().unwrap().into_bytes(),
                    },
                ],
                &[],
            )
            .expect("seed");
        }

        let reply = add_entry(
            &daemon,
            milestone_args("m", "softfig", serde_json::json!({ "after": ["old"] })),
        )
        .expect("a done archive row satisfies the link");
        assert_eq!(reply.id, "m");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        assert_eq!(qs.queue.model.entries[0].after, vec!["old".to_string()]);
    }

    #[test]
    fn add_entry_backstop_refuses_an_id_collision_with_a_live_task() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // Seed a task whose id collides with the milestone slug: no
        // milestones/123/ dir exists, so only the final validate can see it
        // (ids are one namespace across the live file and the archive).
        {
            let mut task = entry("123");
            task.kind = EntryKind::Task;
            task.branch = "fix/123".to_string();
            let q = QueueToml::new(vec![project()], vec![task]);
            let mut inner = daemon.inner.lock().unwrap();
            apply(
                &daemon,
                &mut inner,
                "queue_v2_updated",
                serde_json::json!({}),
                &[FileWrite {
                    rel: QUEUE_FILE.to_string(),
                    expected: None,
                    bytes: q.to_toml().unwrap().into_bytes(),
                }],
                &[],
            )
            .expect("seed");
        }

        let err = add_entry(&daemon, milestone_args("123", "softfig", serde_json::json!({})))
            .unwrap_err();
        assert!(err.1.starts_with("exists:"), "{:?}", err.1);
    }

    #[test]
    fn add_entry_dry_run_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        let before = commit_count(&daemon);

        let reply = add_entry(
            &daemon,
            milestone_args("m", "softfig", serde_json::json!({ "dry_run": true })),
        )
        .expect("dry run computes");
        assert_eq!(commit_count(&daemon), before, "no commit on a dry run");
        assert!(
            !garden.path().join("growlight/backlog/milestones/m/CLAUDE.md").exists(),
            "no docs written"
        );
        assert!(!garden.path().join(slices_file("m")).exists(), "no slices.toml written");
        assert!(reply.view.contains("m"), "the would-be list: {:?}", reply.view);
    }

    // ---- slice 005: task + restack kinds, queue_update_entry -------------

    fn task_args(slug: &str, project: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut a = serde_json::json!({
            "kind": "task",
            "slug": slug,
            "title": format!("{slug} title"),
            "mission": format!("{slug} mission"),
            "finish_criteria": format!("{slug} criteria"),
            "project": project,
        });
        if let (serde_json::Value::Object(m), serde_json::Value::Object(x)) = (&mut a, extra) {
            for (k, v) in x {
                m.insert(k, v);
            }
        }
        a
    }

    fn restack_args(project: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut a = serde_json::json!({ "kind": "restack", "project": project });
        if let (serde_json::Value::Object(m), serde_json::Value::Object(x)) = (&mut a, extra) {
            for (k, v) in x {
                m.insert(k, v);
            }
        }
        a
    }

    fn update_entry(
        daemon: &Daemon,
        args: serde_json::Value,
    ) -> Result<QueueUpdateEntryReply, (ErrorKind, String)> {
        queue_update_entry(daemon, args).map(|v| serde_json::from_value(v).unwrap())
    }

    /// Seed the v2 files straight through the real writer (no view), so the
    /// CAS tokens line up for the next verb — the hand-seeded claimed/active
    /// rows the started/running refusals need, since no claim machinery
    /// exists until queue-v2-scheduling (finding 7).
    fn seed_queue(
        daemon: &Daemon,
        projects: Vec<Project>,
        entries: Vec<Entry>,
        archive: Option<QueueArchiveToml>,
    ) {
        let mut inner = daemon.inner.lock().unwrap();
        let mut files = vec![FileWrite {
            rel: QUEUE_FILE.to_string(),
            expected: None,
            bytes: QueueToml::new(projects, entries)
                .to_toml()
                .unwrap()
                .into_bytes(),
        }];
        if let Some(a) = archive {
            files.push(FileWrite {
                rel: QUEUE_ARCHIVE_FILE.to_string(),
                expected: None,
                bytes: a.to_toml().unwrap().into_bytes(),
            });
        }
        apply(
            daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({ "test": true }),
            &files,
            &[],
        )
        .expect("seed");
    }

    #[test]
    fn add_entry_task_kind_numbers_docs_and_sets_branch() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        let before = commit_count(&daemon);

        let reply = add_entry(&daemon, task_args("fix-login", "softfig", serde_json::json!({})))
            .expect("add task");
        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit per verb");
        assert_eq!(reply.id, "001");
        assert!(
            reply
                .path
                .ends_with("growlight/backlog/tasks/001-fix-login.md"),
            "{:?}",
            reply.path
        );

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt
            .read_to_string("growlight/backlog/tasks/001-fix-login.md")
            .expect("task doc");
        assert!(doc.starts_with("# fix-login title\n"), "{doc}");
        assert!(doc.contains("> Task `001`."), "the queue.toml pointer, {doc}");
        assert!(doc.contains("## Mission") && doc.contains("fix-login mission"), "{doc}");
        assert!(
            doc.contains("## Finish criteria") && doc.contains("fix-login criteria"),
            "{doc}"
        );
        assert_eq!(wt.read_to_string("growlight/backlog/tasks/.seq").unwrap(), "1\n");

        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let e = &qs.queue.model.entries[0];
        assert_eq!(e.id, "001");
        assert_eq!(e.kind, EntryKind::Task);
        assert_eq!(e.branch, "fix/001", "§3.1's fix/<id>, id known after numbering");
        assert_eq!(e.lane, Lane::Normal);
        assert_eq!(e.status, EntryStatus::Queued);
        assert!(e.parent.is_empty() && e.base.is_empty() && e.claimed.is_empty());
        // Tasks have no slices.toml (§4) — not even an empty one.
        assert!(!wt.exists(&slices_file("001")));
        drop(inner);

        // A second task numbers onward through the shared tasks `.seq`.
        let reply2 = add_entry(&daemon, task_args("fix-logout", "softfig", serde_json::json!({})))
            .expect("second task");
        assert_eq!(reply2.id, "002");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        assert!(wt.exists("growlight/backlog/tasks/002-fix-logout.md"));
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["001", "002"], "normal-lane tasks keep file order");
    }

    #[test]
    fn add_entry_task_refuses_slices_and_shape_errors() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        let before = commit_count(&daemon);

        // Slices have no meaning on a task (§4): shape error.
        let err = add_entry(
            &daemon,
            task_args(
                "t1",
                "softfig",
                serde_json::json!({ "slices": [{ "slug": "x", "body": "y" }] }),
            ),
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
        // A missing required field is a shape error too.
        let err = add_entry(
            &daemon,
            serde_json::json!({
                "kind": "task", "slug": "t2", "mission": "m", "finish_criteria": "f",
                "project": "softfig",
            }),
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
        // Unknown project → unknown_project; bad slug → bad_name; a dangling
        // after-link → unknown_id.
        let err = add_entry(&daemon, task_args("t3", "ghost", serde_json::json!({}))).unwrap_err();
        assert!(err.1.starts_with("unknown_project:"), "{err:?}");
        let err = add_entry(&daemon, task_args("Bad Slug", "softfig", serde_json::json!({})))
            .unwrap_err();
        assert!(err.1.starts_with("bad_name:"), "{err:?}");
        let err = add_entry(
            &daemon,
            task_args("t4", "softfig", serde_json::json!({ "after": ["ghost"] })),
        )
        .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        assert_eq!(commit_count(&daemon), before, "refusals mint no commit");
    }

    #[test]
    fn add_entry_restack_writes_the_minimal_urgent_row() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        // A normal milestone first, so the restack's urgent placement shows.
        add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({}))).unwrap();
        let before = commit_count(&daemon);

        let reply = add_entry(&daemon, restack_args("softfig", serde_json::json!({})))
            .expect("add restack");
        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit per verb");
        assert_eq!(reply.id, "001");
        assert!(
            reply
                .path
                .ends_with("growlight/backlog/tasks/001-restack-softfig.md"),
            "{:?}",
            reply.path
        );

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt
            .read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc");
        assert!(doc.starts_with("# Restack softfig\n"), "{doc}");
        assert!(
            doc.contains("queue-v2-git"),
            "the full template's owner is named, {doc}"
        );

        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["001", "m1"], "the urgent restack precedes the normal milestone");
        let e = &qs.queue.model.entries[0];
        assert_eq!(e.kind, EntryKind::Restack);
        assert_eq!(e.lane, Lane::Urgent);
        assert_eq!(e.branch, "", "a restack has no branch of its own (§8)");
        assert_eq!(e.title, "Restack softfig");
        drop(inner);

        // A second restack appends to the urgent lane's back.
        let reply2 = add_entry(&daemon, restack_args("softfig", serde_json::json!({})))
            .expect("second restack");
        assert_eq!(reply2.id, "002");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["001", "002", "m1"], "urgent entries keep file order: oldest first");
    }

    #[test]
    fn add_entry_restack_refuses_args_beyond_kind_and_project() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        let before = commit_count(&daemon);

        // Finding 5: args beyond kind + project are BadArgs, one per arg.
        for (name, extra) in [
            ("slug", serde_json::json!({ "slug": "r" })),
            ("title", serde_json::json!({ "title": "t" })),
            ("mission", serde_json::json!({ "mission": "m" })),
            ("finish_criteria", serde_json::json!({ "finish_criteria": "f" })),
            ("lane", serde_json::json!({ "lane": "normal" })),
            ("position", serde_json::json!({ "position": "front" })),
            ("ref", serde_json::json!({ "ref": "001" })),
            ("after", serde_json::json!({ "after": ["001"] })),
            ("slices", serde_json::json!({ "slices": [{ "slug": "x", "body": "y" }] })),
        ] {
            let err = add_entry(&daemon, restack_args("softfig", extra)).unwrap_err();
            assert_eq!(err.0, ErrorKind::BadArgs, "{name}: {err:?}");
            assert!(err.1.contains(name), "{name}: {err:?}");
        }
        // An unknown project keeps the §6.8 refusal, not a shape error.
        let err = add_entry(&daemon, restack_args("ghost", serde_json::json!({}))).unwrap_err();
        assert!(err.1.starts_with("unknown_project:"), "{err:?}");
        assert_eq!(commit_count(&daemon), before, "refusals mint no commit");
    }

    #[test]
    fn update_entry_changes_lane_move_after_and_status_atomically() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("a", "softfig", serde_json::json!({}))).unwrap();
        add_entry(&daemon, milestone_args("b", "softfig", serde_json::json!({}))).unwrap();
        add_entry(&daemon, milestone_args("c", "softfig", serde_json::json!({}))).unwrap();
        add_entry(
            &daemon,
            milestone_args("u", "softfig", serde_json::json!({ "lane": "urgent" })),
        )
        .unwrap();
        let before = commit_count(&daemon);

        // One call: lane → move → after → status, all in one commit.
        let reply = update_entry(
            &daemon,
            serde_json::json!({
                "id": "c",
                "lane": "urgent",                        // urgent back: after u
                "move": { "to": "before", "ref": "u" },  // within the urgent lane
                "after": ["a"],                          // the new link list
                "status": "blocked",
            }),
        )
        .expect("update");
        assert_eq!(commit_count(&daemon), before + 1, "one atomic edit, one commit");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["c", "u", "a", "b"], "lane then move: c before u in the urgent lane");
        let c = qs.queue.model.entries.iter().find(|e| e.id == "c").unwrap();
        assert_eq!(c.after, vec!["a".to_string()], "after replaces the link list");
        assert_eq!(c.status, EntryStatus::Blocked);
        assert!(reply.view.contains("c"), "{:?}", reply.view);
    }

    #[test]
    fn update_entry_lane_change_keeps_parent_base_and_claimed() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // A started (claimed) entry may change lane (§6.8); its git state
        // stays put.
        let mut started = entry("s");
        started.claimed = "2026-10-11T12:00:00Z".to_string();
        started.parent = "p".to_string();
        started.base = "abc123".to_string();
        seed_queue(
            &daemon,
            vec![project()],
            vec![entry("other"), started],
            None,
        );

        update_entry(&daemon, serde_json::json!({ "id": "s", "lane": "urgent" }))
            .expect("started entries may change lane");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["s", "other"], "the urgent lane precedes the normal one");
        let s = &qs.queue.model.entries[0];
        assert_eq!(s.parent, "p", "parent stays");
        assert_eq!(s.base, "abc123", "base stays");
        assert_eq!(s.claimed, "2026-10-11T12:00:00Z", "claimed stays");
    }

    #[test]
    fn update_entry_refuses_each_failure_path() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // Hand-seed a claimed entry, an active one and an urgent one (finding
        // 7: no claim machinery exists this milestone).
        let mut claimed = entry("started");
        claimed.claimed = "2026-10-11T12:00:00Z".to_string();
        let mut active = entry("running");
        active.status = EntryStatus::Active;
        active.claimed = "2026-10-11T12:00:00Z".to_string();
        let mut urgent = entry("ur");
        urgent.lane = Lane::Urgent;
        seed_queue(
            &daemon,
            vec![project()],
            vec![urgent, claimed, active, entry("ok")],
            None,
        );
        let before = commit_count(&daemon);

        // Unknown id.
        let err = update_entry(&daemon, serde_json::json!({ "id": "ghost", "status": "blocked" }))
            .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        // Move on a claimed entry → started (the stack order is claim order).
        let err = update_entry(&daemon, serde_json::json!({ "id": "started", "move": { "to": "front" } }))
            .unwrap_err();
        assert!(err.1.starts_with("started:"), "{err:?}");
        // Cross-lane ref → lane_mismatch; unknown ref → unknown_id; self-ref
        // → shape error (the legacy reorder RefIsSelf rule).
        let err = update_entry(&daemon, serde_json::json!({ "id": "ok", "move": { "to": "before", "ref": "ur" } }))
            .unwrap_err();
        assert!(err.1.starts_with("lane_mismatch:"), "{err:?}");
        let err = update_entry(&daemon, serde_json::json!({ "id": "ok", "move": { "to": "before", "ref": "ghost" } }))
            .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        let err = update_entry(&daemon, serde_json::json!({ "id": "ok", "move": { "to": "before", "ref": "ok" } }))
            .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
        // A dangling after-link → unknown_id; a self-cycle → link_cycle (the
        // backstop validate catches it).
        let err = update_entry(&daemon, serde_json::json!({ "id": "ok", "after": ["ghost"] }))
            .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        let err = update_entry(&daemon, serde_json::json!({ "id": "ok", "after": ["ok"] }))
            .unwrap_err();
        assert!(err.1.starts_with("link_cycle:"), "{err:?}");
        // Daemon-owned statuses → daemon_owned.
        for status in ["active", "paused", "split"] {
            let err = update_entry(&daemon, serde_json::json!({ "id": "ok", "status": status }))
                .unwrap_err();
            assert!(err.1.starts_with("daemon_owned:"), "{status}: {err:?}");
        }
        // done on an active entry → running (the running session is never
        // killed).
        let err = update_entry(&daemon, serde_json::json!({ "id": "running", "status": "done" }))
            .unwrap_err();
        assert!(err.1.starts_with("running:"), "{err:?}");

        assert_eq!(commit_count(&daemon), before, "refusals mint no commit");
    }

    #[test]
    fn update_entry_done_archives_the_row_and_still_satisfies_links() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("a", "softfig", serde_json::json!({}))).unwrap();
        add_entry(
            &daemon,
            milestone_args("b", "softfig", serde_json::json!({ "after": ["a"] })),
        )
        .unwrap();
        let before = commit_count(&daemon);

        let reply = update_entry(&daemon, serde_json::json!({ "id": "a", "status": "done" }))
            .expect("done");
        assert_eq!(commit_count(&daemon), before + 1, "one commit for the archive move");
        assert!(
            !reply.view.contains("| a | milestone"),
            "a's own row left the live view, {reply:?}"
        );
        assert!(reply.view.contains("| b | milestone"), "b's row remains, {reply:?}");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["b"], "a left the live file");
        assert_eq!(qs.archive.model.entries.len(), 1);
        let archived = &qs.archive.model.entries[0];
        assert_eq!(archived.row.id, "a");
        assert_eq!(archived.final_status, FinalStatus::Done);
        assert!(!archived.finished.is_empty());
        assert!(archived.reason.is_none());
        // The whole state round-trips through the validating loader above —
        // b's link to the done row still resolves.
        assert_eq!(qs.queue.model.entries[0].after, vec!["a".to_string()]);
        assert!(wt.exists(QUEUE_ARCHIVE_FILE), "the archive file is real");
        drop(inner);

        // The archive appends: a second done adds, never replaces.
        update_entry(&daemon, serde_json::json!({ "id": "b", "status": "done" }))
            .expect("second done");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        assert!(qs.queue.model.entries.is_empty(), "the live file is empty now");
        let ids: Vec<&str> = qs
            .archive
            .model
            .entries
            .iter()
            .map(|e| e.row.id.as_str())
            .collect();
        assert_eq!(ids, ["a", "b"], "archive rows keep arrival order");
    }

    #[test]
    fn update_entry_noop_edit_mints_no_commit() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("a", "softfig", serde_json::json!({}))).unwrap();
        let before = commit_count(&daemon);

        // The same lane, the same position, the same links, the same status:
        // nothing changes, nothing commits (the legacy reorder idempotence).
        for args in [
            serde_json::json!({ "id": "a", "lane": "normal" }),
            serde_json::json!({ "id": "a", "move": { "to": "front" } }),
            serde_json::json!({ "id": "a", "after": [] }),
            serde_json::json!({ "id": "a", "status": "queued" }),
            serde_json::json!({
                "id": "a", "lane": "normal", "move": { "to": "back" },
                "after": [], "status": "queued",
            }),
        ] {
            let reply = update_entry(&daemon, args).expect("a no-op edit computes");
            assert_eq!(commit_count(&daemon), before, "a no-op edit mints no commit");
            assert!(reply.view.contains("a"), "the reply still renders the list");
        }
    }

    #[test]
    fn update_entry_dry_run_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("a", "softfig", serde_json::json!({}))).unwrap();
        let before = commit_count(&daemon);

        let reply = update_entry(
            &daemon,
            serde_json::json!({ "id": "a", "status": "blocked", "dry_run": true }),
        )
        .expect("dry run computes");
        assert_eq!(commit_count(&daemon), before, "no commit on a dry run");
        assert!(reply.view.contains("a"), "{reply:?}");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        assert_eq!(qs.queue.model.entries[0].status, EntryStatus::Queued, "nothing landed");
        assert!(qs.archive.model.entries.is_empty());
        drop(inner);

        // A done dry run shows the would-be archived state, writing nothing.
        let reply = update_entry(
            &daemon,
            serde_json::json!({ "id": "a", "status": "done", "dry_run": true }),
        )
        .expect("dry run computes");
        assert!(
            !reply.view.contains("| a | milestone"),
            "the would-be state archives a, {reply:?}"
        );
        assert_eq!(commit_count(&daemon), before, "no commit on a dry run");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        assert_eq!(qs.queue.model.entries.len(), 1, "the row is still live");
        assert!(qs.archive.model.entries.is_empty());
    }

    #[test]
    fn update_entry_queued_unblocks_and_undeferres() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut blocked = entry("b");
        blocked.status = EntryStatus::Blocked;
        let mut deferred = entry("d");
        deferred.status = EntryStatus::Deferred;
        seed_queue(&daemon, vec![project()], vec![blocked, deferred], None);

        for id in ["b", "d"] {
            update_entry(&daemon, serde_json::json!({ "id": id, "status": "queued" }))
                .expect("unblock");
        }
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        assert!(
            qs.queue.model.entries.iter().all(|e| e.status == EntryStatus::Queued),
            "queued unblocks and un-defers"
        );
    }
}
