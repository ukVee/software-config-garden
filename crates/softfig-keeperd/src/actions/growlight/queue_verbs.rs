//! The queue v2 §6.8 human verbs — `queue_add_project`, `queue_add_entry`
//! (all three kinds), `queue_update_entry`, `slice_insert`, `slice_update`
//! and `queue_drop` — the v2 writers end to end (milestone `queue-v2-state`,
//! slices 004–006).
//!
//! Each verb follows [`super::v2::write`]'s contract: load
//! ([`super::v2::state`]), mutate the in-memory models, validate (the
//! slice-002 [`QueueRefusal`] vocabulary), then call [`apply`] once with
//! every changed TOML file, every view that must re-render, and every
//! companion doc it creates passed as `extras` — the whole-file CAS checks,
//! the view upserts, the backlink refresh, and exactly one commit land
//! together; the verb never stages or commits itself. A `dry_run` stops
//! before `apply`: everything is computed, validated and rendered, nothing
//! is committed, and the reply carries the would-be queue view so the §6.9
//! CLI can print it. A no-op `queue_update_entry` edit mints no commit, like
//! the legacy reorder verb.
//!
//! Refusals leave as wire errors whose message is the [`QueueRefusal`]
//! display — which leads with the wire code ([`QueueRefusal::code`]), the
//! stable prefix a client can branch on. Shape errors (an empty field, an
//! unknown placement keyword, an arg a kind does not take) are plain
//! `BadArgs`.

use std::collections::HashSet;

use softfig_ipc::queue_v2::{
    sub_depth, ArchivedEntry, Entry, EntryKind, EntryStatus, FinalStatus, Lane, Project,
    QueueArchiveToml, QueueRefusal, QueueToml, SliceItem, SliceKind, SliceStatus, SlicesToml,
    QUEUE_ARCHIVE_FILE,
};
use softfig_ipc::verbs::{
    QueueAddEntryArgs, QueueAddEntryReply, QueueAddProjectArgs, QueueAddProjectReply,
    QueueDropArgs, QueueDropReply, QueueStatusArg, QueueUpdateEntryArgs, QueueUpdateEntryReply,
    SliceInsertArgs, SliceInsertReply, SliceUpdateArgs, SliceUpdateReply,
};
use softfig_ipc::ErrorKind;

use super::super::numbering;
use super::v2::{
    apply, load_queue_state, load_slices, milestone_path, queue_view, queue_view_host, slices_file,
    slices_view, slices_view_host, ExtraWrites, FileWrite, ViewWrite, QUEUE_FILE, QUEUE_V2_TAG,
    SLICES_V2_TAG,
};
use super::{conventions, paths, queue, WorkTree};
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
        &ExtraWrites::NONE,
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
        pending_status: None,
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

    // The entry's docs ride `apply`'s one commit as extras — checked in its
    // pass 1 (first-creation: each must still be absent) and staged in its
    // pass 2 with the backlink refresh, so a refusal leaves no orphan docs
    // and no burned `.seq` number.
    let mut extras = vec![FileWrite {
        rel: doc_rel.clone(),
        expected: None,
        bytes: doc_content.into_bytes(),
    }];
    extras.push(FileWrite {
        rel: format!("{slices_dir}/{}", conventions::SEQ_FILE),
        expected: None,
        bytes: format!("{seq}\n").into_bytes(),
    });
    for (rel, content) in slice_docs {
        extras.push(FileWrite {
            rel,
            expected: None,
            bytes: content.into_bytes(),
        });
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
        &ExtraWrites {
            writes: &extras,
            refresh_backlinks: true,
        },
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
        pending_status: None,
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

    // The task doc + its `.seq` bump ride `apply`'s one commit as extras; the
    // `.seq` carries its pre-bump content version so a hand-edited counter
    // refuses the verb instead of being silently clobbered.
    let seq_expected = {
        let wt = WorkTree::new(daemon, &inner);
        numbering::seq_version(&wt, &tasks_dir)
    };
    let extras = [
        FileWrite {
            rel: task_rel.clone(),
            expected: None,
            bytes: doc_content.into_bytes(),
        },
        FileWrite {
            rel: format!("{tasks_dir}/{}", conventions::SEQ_FILE),
            expected: seq_expected,
            bytes: format!("{number}\n").into_bytes(),
        },
    ];

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
        &ExtraWrites {
            writes: &extras,
            refresh_backlinks: true,
        },
    )?;

    Ok(serde_json::to_value(QueueAddEntryReply {
        id,
        path: task_rel,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
}

/// A restack row built into the live list plus its pending doc write.
struct RestackStaged {
    id: String,
    number: u32,
    rel: String,
    content: String,
}

/// The restack-creation core (§8), shared by `add_restack` (slice 005) and
/// `queue_drop`'s drop→restack path (slice 006): build the urgent no-branch
/// row for `project` and insert it at the urgent lane's back, numbered `n`
/// (the caller numbers, so one verb enqueuing several restacks hands out
/// distinct numbers before any `.seq` write lands). The doc itself is staged
/// by the caller (so a dry run can compute the row without writing anything).
/// The caller proves the project exists before calling — its entry rows
/// validated on load.
fn restack_core(
    wt: &WorkTree,
    queue: &mut QueueToml,
    project: &str,
    number: u32,
) -> Result<RestackStaged, (ErrorKind, String)> {
    let tasks_dir = paths::tasks_dir();
    let slug = format!("restack-{project}");
    let rel = format!("{tasks_dir}/{}", conventions::note_filename(number, &slug));
    if wt.exists(&rel) {
        // A corrupt `.seq` squatting a live slot (write_numbered refuses the
        // same way); surface it as the spec's `exists` refusal.
        return Err(refuse(QueueRefusal::Exists {
            id: format!("{number:03}"),
        }));
    }
    let id = format!("{number:03}");
    let entry = Entry {
        id: id.clone(),
        kind: EntryKind::Restack,
        title: format!("Restack {project}"),
        project: project.to_string(),
        lane: Lane::Urgent,
        status: EntryStatus::Queued,
        after: vec![],
        added: conventions::now_rfc3339(),
        branch: String::new(),
        parent: String::new(),
        base: String::new(),
        claimed: String::new(),
        follow_ups: 0,
        pending_status: None,
    };
    // §6.8/§8: urgent lane, appended at the urgent lane's back.
    let idx = place_entry(&queue.entries, Lane::Urgent, &V2Position::Back).map_err(refuse)?;
    queue.entries.insert(idx, entry);
    Ok(RestackStaged {
        id,
        number,
        content: restack_doc(project, &conventions::today_hyphen()),
        rel,
    })
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

    let (mut queue, queue_version, archive) = {
        let wt = WorkTree::new(daemon, &inner);
        load_for_add(&wt, &inner, &args.project, &[])?
    };

    let restack = {
        let wt = WorkTree::new(daemon, &inner);
        let number = numbering::next_number(&wt, &paths::tasks_dir());
        restack_core(&wt, &mut queue, &args.project, number)?
    };
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
            id: restack.id,
            path: restack.rel,
            view,
            hash,
        })
        .unwrap());
    }

    // The restack doc + its `.seq` bump ride `apply`'s one commit as extras
    // (same envelope as the task kind).
    let seq_expected = {
        let wt = WorkTree::new(daemon, &inner);
        numbering::seq_version(&wt, &paths::tasks_dir())
    };
    let extras = [
        FileWrite {
            rel: restack.rel.clone(),
            expected: None,
            bytes: restack.content.clone().into_bytes(),
        },
        FileWrite {
            rel: format!("{}/{}", paths::tasks_dir(), conventions::SEQ_FILE),
            expected: seq_expected,
            bytes: format!("{}\n", restack.number).into_bytes(),
        },
    ];

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({
            "verb": "queue_add_entry",
            "id": restack.id,
            "kind": "restack",
            "project": args.project,
        }),
        &files,
        &[ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(view.clone()),
        }],
        &ExtraWrites {
            writes: &extras,
            refresh_backlinks: true,
        },
    )?;

    Ok(serde_json::to_value(QueueAddEntryReply {
        id: restack.id,
        path: restack.rel,
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
        &ExtraWrites::NONE,
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

// ---- slice_insert -------------------------------------------------------

/// `slice_insert` (§6.8): a numbered slice doc plus its `slices.toml` item,
/// for a milestone or sub-milestone (`"<parent>/<sub>"`, ≤ 2 deep — §3.3's
/// nesting bound via `sub_depth`, which refuses deeper as `bad_name`). The
/// milestone must already have a `slices.toml` (every milestone is born with
/// one, §4 — a sub-milestone gets its own at its creation); anything else is
/// `unknown_id`. The item lands at `front | back | before | after` in file
/// order, which §3.3 defines as the slice order; the `NNN-` filename number
/// is a stable id only (from the folder's `.seq`, as `add_slice` does today).
pub fn slice_insert(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: SliceInsertArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("slice_insert args: {e}")))?;
    if conventions::validate_slug(&args.slug).is_err() {
        return Err(refuse(QueueRefusal::BadName { name: args.slug.clone() }));
    }
    if args.body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "body must be non-empty".to_string()));
    }
    if args.milestone.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "milestone must be non-empty".to_string()));
    }
    sub_depth(&args.milestone).map_err(refuse)?;
    let position = parse_position(args.position.as_deref(), args.ref_id.as_deref())?;
    let title = args.title.as_deref().unwrap_or(&args.slug);

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let milestone = args.milestone.clone();
    let slices_dir = format!("{}/slices", milestone_path(&milestone));
    let (mut model, version) = {
        let wt = WorkTree::new(daemon, &inner);
        match load_slices(&wt, &inner, &milestone) {
            Ok(Some(loaded)) => (loaded.model, loaded.version),
            Ok(None) => {
                return Err(refuse(QueueRefusal::UnknownId { id: milestone.clone() }))
            }
            Err(e) => return Err((ErrorKind::Internal, e.to_string())),
        }
    };

    let (number, slice_rel) = {
        let wt = WorkTree::new(daemon, &inner);
        let number = numbering::next_number(&wt, &slices_dir);
        let slice_rel = format!("{slices_dir}/{}", conventions::note_filename(number, &args.slug));
        if wt.exists(&slice_rel) {
            // A corrupt `.seq` squatting a live slot (write_numbered refuses
            // the same way); surface it as the spec's `exists` refusal.
            return Err(refuse(QueueRefusal::Exists {
                id: format!("{number:03}"),
            }));
        }
        (number, slice_rel)
    };
    let id = format!("{number:03}");

    let idx = place_item(&model.items, &position).map_err(refuse)?;
    model.items.insert(idx, slice_item(number));
    // Backstop: a corrupt `.seq` whose number collides with a live item id
    // only surfaces here (item ids are unique per file, §3.3).
    model.validate(&milestone).map_err(refuse)?;

    let view = slices_view(&model);
    if args.dry_run {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(SliceInsertReply {
            milestone,
            id,
            path: slice_rel,
            view,
            hash,
        })
        .unwrap());
    }

    // The slice doc + its `.seq` bump ride `apply`'s one commit as extras
    // (same envelope as the milestone/task kinds).
    let content = conventions::note_doc(title, &conventions::today_hyphen(), &args.body);
    let seq_expected = {
        let wt = WorkTree::new(daemon, &inner);
        numbering::seq_version(&wt, &slices_dir)
    };
    let extras = [
        FileWrite {
            rel: slice_rel.clone(),
            expected: None,
            bytes: content.into_bytes(),
        },
        FileWrite {
            rel: format!("{slices_dir}/{}", conventions::SEQ_FILE),
            expected: seq_expected,
            bytes: format!("{number}\n").into_bytes(),
        },
    ];

    let files = [FileWrite {
        rel: slices_file(&milestone),
        expected: version,
        bytes: model
            .to_toml()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
            .into_bytes(),
    }];
    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({ "verb": "slice_insert", "milestone": milestone, "id": id }),
        &files,
        &[ViewWrite {
            host: slices_view_host(&milestone),
            tag: SLICES_V2_TAG,
            body: Some(view.clone()),
        }],
        &ExtraWrites {
            writes: &extras,
            refresh_backlinks: true,
        },
    )?;

    Ok(serde_json::to_value(SliceInsertReply {
        milestone,
        id,
        path: slice_rel,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- slice_update -------------------------------------------------------

/// `slice_update` (§6.8): one atomic edit on a `slices.toml` item — `move`
/// within file order and/or `status`, applied in that order. The move is
/// refused `started` for `active`/`done`/`split` items (§6.8: the slice order
/// is the run order) — the check reads the pre-edit status, so a `status`
/// change cannot launder a move. `status` takes the human statuses
/// (`queued` also unblocks and un-defers; `done` resets `follow_ups` to 0,
/// §3.3); `active`/`split` are refused `daemon_owned`.
pub fn slice_update(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: SliceUpdateArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("slice_update args: {e}")))?;
    if args.milestone.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "milestone must be non-empty".to_string()));
    }
    if args.id.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "id must be non-empty".to_string()));
    }
    // The move's shape (the position keyword + its ref rule) checks before
    // the lock, like the entry verbs'.
    let move_pos = match &args.move_spec {
        Some(m) => Some(parse_position(Some(&m.to), m.ref_id.as_deref())?),
        None => None,
    };

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let milestone = args.milestone.clone();
    let (mut model, version, loaded) = {
        let wt = WorkTree::new(daemon, &inner);
        match load_slices(&wt, &inner, &milestone) {
            Ok(Some(loaded)) => (loaded.model.clone(), loaded.version, loaded.model),
            Ok(None) => {
                return Err(refuse(QueueRefusal::UnknownId { id: milestone.clone() }))
            }
            Err(e) => return Err((ErrorKind::Internal, e.to_string())),
        }
    };
    if !model.items.iter().any(|i| i.id == args.id) {
        return Err(refuse(QueueRefusal::UnknownId { id: args.id.clone() }));
    }

    // 1. move: within `slices.toml` file order. A self-ref is a shape error
    // (the legacy reorder RefIsSelf rule).
    if let Some(pos) = move_pos {
        if matches!(
            &pos,
            V2Position::Before(r) | V2Position::After(r) if r == &args.id
        ) {
            return Err((
                ErrorKind::BadArgs,
                format!("cannot move slice {:?} relative to itself", args.id),
            ));
        }
        let idx = slice_idx(&model, &args.id);
        if matches!(
            model.items[idx].status,
            SliceStatus::Active | SliceStatus::Done | SliceStatus::Split
        ) {
            return Err(refuse(QueueRefusal::Started { id: args.id.clone() }));
        }
        let item = model.items.remove(idx);
        let at = place_item(&model.items, &pos).map_err(refuse)?;
        model.items.insert(at, item);
    }

    // 2. status: the human statuses.
    if let Some(status) = args.status {
        match status {
            SliceStatus::Active | SliceStatus::Split => {
                return Err(refuse(QueueRefusal::DaemonOwned { id: args.id.clone() }))
            }
            SliceStatus::Done => {
                let idx = slice_idx(&model, &args.id);
                model.items[idx].status = SliceStatus::Done;
                // §3.3: follow_ups resets to 0 on done — slice rows only. A
                // `sub` omits the field, so setting it would trip the shape
                // backstop below and refuse a human's `done` on a sub.
                if model.items[idx].kind == SliceKind::Slice {
                    model.items[idx].follow_ups = Some(0);
                }
            }
            SliceStatus::Queued | SliceStatus::Blocked | SliceStatus::Deferred => {
                let idx = slice_idx(&model, &args.id);
                model.items[idx].status = status; // queued also unblocks and un-defers
            }
        }
    }

    // No-op guard: an edit that changed nothing (same position, same status)
    // mints no commit — the legacy reorder verb's idempotence.
    if model == loaded {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(SliceUpdateReply {
            milestone,
            id: args.id,
            view: slices_view(&model),
            hash,
        })
        .unwrap());
    }

    // Backstop: the mutated file must still satisfy every §3.3 rule.
    model.validate(&milestone).map_err(refuse)?;

    let view = slices_view(&model);
    if args.dry_run {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(SliceUpdateReply {
            milestone,
            id: args.id,
            view,
            hash,
        })
        .unwrap());
    }

    let files = [FileWrite {
        rel: slices_file(&milestone),
        expected: version,
        bytes: model
            .to_toml()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
            .into_bytes(),
    }];
    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({ "verb": "slice_update", "milestone": milestone, "id": args.id }),
        &files,
        &[ViewWrite {
            host: slices_view_host(&milestone),
            tag: SLICES_V2_TAG,
            body: Some(view.clone()),
        }],
        &ExtraWrites::NONE,
    )?;

    Ok(serde_json::to_value(SliceUpdateReply {
        milestone,
        id: args.id,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- queue_drop ---------------------------------------------------------

/// `queue_drop` (§6.8, §8): the only way abandoned work leaves the stack. The
/// row moves to the archive as `dropped` with `finished` + `reason` — a
/// `dropped` row satisfies no `after` links (§3.2). Refused `linked_from`
/// while a live entry's `after` names the id (the link would resolve to
/// nothing), and `running` for an `active` entry (the running session is
/// never killed; a paused/blocked/deferred/queued entry has none). If a live
/// entry's `parent` is the dropped id — a stacked branch was cut from it,
/// §8 — one restack is enqueued per distinct child project (the restack
/// covers a repo's stack; its doc names `queue-v2-git` for the rebase steps).
pub fn queue_drop(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueDropArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_drop args: {e}")))?;
    if args.id.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "id must be non-empty".to_string()));
    }
    if args.reason.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "reason must be non-empty".to_string()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let (mut queue, queue_version, mut archive, archive_version) = {
        let wt = WorkTree::new(daemon, &inner);
        match load_queue_state(&wt, &inner) {
            Ok(Some(qs)) => (
                qs.queue.model,
                qs.queue.version,
                qs.archive.model,
                qs.archive.version,
            ),
            Ok(None) => return Err(refuse(QueueRefusal::UnknownId { id: args.id.clone() })),
            Err(e) => return Err((ErrorKind::Internal, e.to_string())),
        }
    };
    if !queue.entries.iter().any(|e| e.id == args.id) {
        return Err(refuse(QueueRefusal::UnknownId { id: args.id.clone() }));
    }
    if queue.entries.iter().any(|e| e.after.contains(&args.id)) {
        return Err(refuse(QueueRefusal::LinkedFrom { id: args.id.clone() }));
    }
    let idx = idx_of(&queue, &args.id);
    if queue.entries[idx].status == EntryStatus::Active {
        return Err(refuse(QueueRefusal::Running { id: args.id.clone() }));
    }

    // The drop→restack path (§8): live children cut from the dropped entry,
    // one restack per distinct child project. Collected before the row leaves
    // the list.
    let child_projects: HashSet<String> = queue
        .entries
        .iter()
        .filter(|e| e.parent == args.id)
        .map(|e| e.project.clone())
        .collect();

    let row = queue.entries.remove(idx);
    archive.entries.push(ArchivedEntry {
        row,
        finished: conventions::now_rfc3339(),
        final_status: FinalStatus::Dropped,
        reason: Some(args.reason.clone()),
    });

    // Dry runs compute the restack rows too (the would-be view shows them)
    // but stage no docs. Numbers come from one high-water read plus the
    // range's own bump, so several restacks in this one verb get distinct
    // numbers even before any `.seq` write lands.
    let restacks: Vec<RestackStaged> = {
        let wt = WorkTree::new(daemon, &inner);
        (numbering::next_number(&wt, &paths::tasks_dir())..)
            .zip(child_projects.iter())
            .map(|(number, p)| restack_core(&wt, &mut queue, p, number))
            .collect::<Result<_, _>>()?
    };

    // Backstop: every §3.1 invariant still holds (the restack rows are
    // urgent-lane, fresh task-NNN ids — a milestone id colliding with one
    // only surfaces here).
    queue.validate(&archive).map_err(refuse)?;

    let view = queue_view(&queue);
    if args.dry_run {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueDropReply {
            id: args.id,
            view,
            hash,
        })
        .unwrap());
    }

    // The restack docs + one `.seq` bump ride `apply`'s one commit as extras
    // (the drop→restack path stages no docs outside the envelope).
    let mut extras = Vec::new();
    if !restacks.is_empty() {
        let seq_expected = {
            let wt = WorkTree::new(daemon, &inner);
            numbering::seq_version(&wt, &paths::tasks_dir())
        };
        for r in &restacks {
            extras.push(FileWrite {
                rel: r.rel.clone(),
                expected: None,
                bytes: r.content.clone().into_bytes(),
            });
        }
        extras.push(FileWrite {
            rel: format!("{}/{}", paths::tasks_dir(), conventions::SEQ_FILE),
            expected: seq_expected,
            bytes: format!("{}\n", restacks.last().expect("non-empty").number).into_bytes(),
        });
    }

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
            rel: QUEUE_ARCHIVE_FILE.to_string(),
            expected: archive_version,
            bytes: archive
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_bytes(),
        },
    ];
    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({
            "verb": "queue_drop",
            "id": args.id,
            "reason": args.reason,
            "restacks": restacks.len(),
        }),
        &files,
        &[ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(view.clone()),
        }],
        &ExtraWrites {
            writes: &extras,
            refresh_backlinks: !extras.is_empty(),
        },
    )?;

    Ok(serde_json::to_value(QueueDropReply {
        id: args.id,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
}

/// The item's index; the verb proved the id exists, so this never misses.
fn slice_idx(slices: &SlicesToml, id: &str) -> usize {
    slices
        .items
        .iter()
        .position(|i| i.id == id)
        .expect("the item exists")
}

/// The index where a new `slices.toml` item lands for `position`, within file
/// order (§3.3: file order is slice order — no lanes here, unlike the entry
/// list).
fn place_item(items: &[SliceItem], position: &V2Position) -> Result<usize, QueueRefusal> {
    match position {
        V2Position::Front => Ok(0),
        V2Position::Back => Ok(items.len()),
        V2Position::Before(r) => item_index(items, r),
        V2Position::After(r) => Ok(item_index(items, r)? + 1),
    }
}

fn item_index(items: &[SliceItem], id: &str) -> Result<usize, QueueRefusal> {
    items
        .iter()
        .position(|i| i.id == id)
        .ok_or_else(|| QueueRefusal::UnknownId { id: id.to_string() })
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
    use softfig_vcs::{log, Intent, TIP_REF};

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
            pending_status: None,
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
                &ExtraWrites::NONE,
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
                &ExtraWrites::NONE,
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
            &ExtraWrites::NONE,
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

    // ---- slice 006: slice_insert, slice_update, queue_drop -------------

    fn insert_slice(
        daemon: &Daemon,
        args: serde_json::Value,
    ) -> Result<SliceInsertReply, (ErrorKind, String)> {
        slice_insert(daemon, args).map(|v| serde_json::from_value(v).unwrap())
    }

    fn update_slice(
        daemon: &Daemon,
        args: serde_json::Value,
    ) -> Result<SliceUpdateReply, (ErrorKind, String)> {
        slice_update(daemon, args).map(|v| serde_json::from_value(v).unwrap())
    }

    fn drop_entry(
        daemon: &Daemon,
        args: serde_json::Value,
    ) -> Result<QueueDropReply, (ErrorKind, String)> {
        queue_drop(daemon, args).map(|v| serde_json::from_value(v).unwrap())
    }

    /// Seed one milestone's `slices.toml` straight through the real writer
    /// (overwriting under the real CAS token when the file already exists),
    /// with its view, so the next verb's CAS lines up — e.g. the hand-seeded
    /// sub-milestone and the started-slice rows the slice refusals need
    /// (finding 7: no claim machinery exists until queue-v2-scheduling).
    fn seed_slices(daemon: &Daemon, milestone: &str, items: Vec<SliceItem>) {
        let model = SlicesToml::new(milestone.to_string(), items);
        let mut inner = daemon.inner.lock().unwrap();
        let expected = {
            let wt = WorkTree::new(daemon, &inner);
            load_slices(&wt, &inner, milestone)
                .expect("load")
                .and_then(|l| l.version)
        };
        apply(
            daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({ "test": true }),
            &[FileWrite {
                rel: slices_file(milestone),
                expected,
                bytes: model.to_toml().unwrap().into_bytes(),
            }],
            &[ViewWrite {
                host: slices_view_host(milestone),
                tag: SLICES_V2_TAG,
                body: Some(slices_view(&model)),
            }],
            &ExtraWrites::NONE,
        )
        .expect("seed slices");
    }

    fn loaded_slices(daemon: &Daemon, milestone: &str) -> SlicesToml {
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(daemon, &inner);
        load_slices(&wt, &inner, milestone)
            .expect("load")
            .expect("slices exist")
            .model
    }

    #[test]
    fn slice_insert_numbers_writes_and_places_the_item() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(
            &daemon,
            milestone_args(
                "m1",
                "softfig",
                serde_json::json!({
                    "slices": [
                        { "slug": "types", "body": "build the types" },
                        { "slug": "verbs", "body": "build the verbs" }
                    ]
                }),
            ),
        )
        .expect("milestone with two slices");
        let before = commit_count(&daemon);

        // Default placement is back (appends), and the NNN comes from the
        // folder's .seq — the filename number is a stable id, never order.
        let reply = insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "slug": "ui", "body": "build the ui" }),
        )
        .expect("insert");
        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit per verb");
        assert_eq!(reply.id, "003");
        assert!(reply.path.ends_with("m1/slices/003-ui.md"), "{:?}", reply.path);

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt
            .read_to_string("growlight/backlog/milestones/m1/slices/003-ui.md")
            .expect("slice doc");
        assert!(doc.starts_with("# ui\n"), "default title = slug, {doc}");
        assert!(doc.contains("> Last reviewed:"), "{doc}");
        assert!(doc.contains("build the ui"), "{doc}");
        assert_eq!(
            wt.read_to_string("growlight/backlog/milestones/m1/slices/.seq").unwrap(),
            "3\n"
        );

        // Load through the same worktree — the guard is already held (the
        // mutex is not reentrant, so no verb/loader call that locks again).
        let s = load_slices(&wt, &inner, "m1")
            .expect("load")
            .expect("slices exist")
            .model;
        let ids: Vec<&str> = s.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["001", "002", "003"], "back appends in file order");
        assert_eq!(s.items[2].status, SliceStatus::Queued);
        assert_eq!(s.items[2].follow_ups, Some(0));

        // The view re-rendered in the milestone doc's managed region.
        let host = wt
            .read_to_string("growlight/backlog/milestones/m1/CLAUDE.md")
            .unwrap();
        let body = managed::region_body(&host, SLICES_V2_TAG).expect("slices region");
        assert!(body.contains("| 3 | slice | 003 | queued | 0 |"), "{body}");
        drop(inner);

        // Placement keywords: front, then before a ref.
        insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "slug": "first", "body": "x", "position": "front" }),
        )
        .expect("front");
        insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "slug": "mid", "body": "x", "position": "before", "ref": "002" }),
        )
        .expect("before");
        let s = loaded_slices(&daemon, "m1");
        let ids: Vec<&str> = s.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            ["004", "001", "005", "002", "003"],
            "front leads; before lands ahead of the ref"
        );
    }

    #[test]
    fn slice_insert_targets_a_sub_milestone_through_the_subs_path() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // Finding 10: a sub-milestone lives at milestones/<parent>/subs/<sub>/,
        // and its slices.toml carries the "<parent>/<sub>" identity. Seed its
        // doc + file (the verb that creates a sub belongs to a later slice's
        // split flow).
        {
            let mut inner = daemon.inner.lock().unwrap();
            {
                let wt = WorkTree::new(&daemon, &inner);
                wt.write("growlight/backlog/milestones/m/subs/s/CLAUDE.md", b"# backlog: m/s\n")
                    .unwrap();
                // A real sub-milestone is born with its own slices dir, .seq
                // and first slice doc (the split flow creates them together);
                // seed the consistent state so slice_insert numbers onward
                // instead of colliding fail-closed.
                wt.write("growlight/backlog/milestones/m/subs/s/slices/.seq", b"1\n")
                    .unwrap();
                wt.write(
                    "growlight/backlog/milestones/m/subs/s/slices/001-plan.md",
                    b"# Plan\n",
                )
                .unwrap();
            }
            crate::actions::commit_now(&mut inner, Intent::init("seed sub doc")).unwrap();
        }
        seed_slices(&daemon, "m/s", vec![slice_item(1)]);

        let reply = insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m/s", "slug": "types", "body": "x" }),
        )
        .expect("insert into the sub-milestone");
        assert_eq!(reply.id, "002");
        assert!(
            reply
                .path
                .contains("milestones/m/subs/s/slices/002-types.md"),
            "{:?}",
            reply.path
        );

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        assert!(
            wt.exists("growlight/backlog/milestones/m/subs/s/slices/002-types.md"),
            "the doc landed in the sub's slices dir"
        );
        assert_eq!(
            wt.read_to_string("growlight/backlog/milestones/m/subs/s/slices/.seq").unwrap(),
            "2\n",
            "the sub's own .seq numbered"
        );
        let s = SlicesToml::parse(
            &wt.read_to_string(&slices_file("m/s")).expect("slices.toml"),
        )
        .expect("parses");
        assert_eq!(s.milestone, "m/s", "the file carries the sub identity");
        assert_eq!(s.items.len(), 2);
    }

    #[test]
    fn slice_insert_refuses_each_failure_path() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({}))).unwrap();
        let before = commit_count(&daemon);

        // Unknown milestone → unknown_id.
        let err = insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "ghost", "slug": "x", "body": "y" }),
        )
        .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        // Bad slug → bad_name; empty body is a shape error.
        let err = insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "slug": "Bad Slug", "body": "y" }),
        )
        .unwrap_err();
        assert!(err.1.starts_with("bad_name:"), "{err:?}");
        let err = insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "slug": "x", "body": "   " }),
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
        // An unknown placement ref → unknown_id.
        let err = insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "slug": "x", "body": "y", "position": "before", "ref": "ghost" }),
        )
        .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        // Deeper than §3.3's nesting bound → bad_name (sub_depth).
        let err = insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1/a/b/c", "slug": "x", "body": "y" }),
        )
        .unwrap_err();
        assert!(err.1.starts_with("bad_name:"), "{err:?}");

        assert_eq!(commit_count(&daemon), before, "refusals mint no commit");
        // The milestone's file was untouched: still just the generated plan.
        let s = loaded_slices(&daemon, "m1");
        assert_eq!(s.items.len(), 1);
    }

    #[test]
    fn slice_insert_dry_run_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({}))).unwrap();
        let before = commit_count(&daemon);

        let reply = insert_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "slug": "ui", "body": "x", "dry_run": true }),
        )
        .expect("dry run computes");
        assert_eq!(commit_count(&daemon), before, "no commit on a dry run");
        assert_eq!(reply.id, "002");
        assert!(
            !garden.path().join("growlight/backlog/milestones/m1/slices/002-ui.md").exists(),
            "no doc written"
        );
        assert!(reply.view.contains("| 2 | slice | 002 |"), "{reply:?}");
        let s = loaded_slices(&daemon, "m1");
        assert_eq!(s.items.len(), 1, "nothing landed");
    }

    #[test]
    fn slice_update_moves_and_sets_status_atomically() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(
            &daemon,
            milestone_args(
                "m1",
                "softfig",
                serde_json::json!({
                    "slices": [
                        { "slug": "a", "body": "x" },
                        { "slug": "b", "body": "x" },
                        { "slug": "c", "body": "x" },
                        { "slug": "d", "body": "x" }
                    ]
                }),
            ),
        )
        .unwrap();
        let before = commit_count(&daemon);

        let reply = update_slice(
            &daemon,
            serde_json::json!({
                "milestone": "m1",
                "id": "004",
                "move": { "to": "before", "ref": "002" },
                "status": "blocked",
            }),
        )
        .expect("update");
        assert_eq!(commit_count(&daemon), before + 1, "one atomic edit, one commit");

        let s = loaded_slices(&daemon, "m1");
        let ids: Vec<&str> = s.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["001", "004", "002", "003"], "the move landed in file order");
        let moved = s.items.iter().find(|i| i.id == "004").unwrap();
        assert_eq!(moved.status, SliceStatus::Blocked);
        assert!(reply.view.contains("| 2 | slice | 004 | blocked | 0 |"), "{reply:?}");
    }

    #[test]
    fn slice_update_refuses_each_failure_path() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({}))).unwrap();
        // Hand-seed the started statuses no human verb can set (finding 7).
        let mut active = slice_item(1);
        active.status = SliceStatus::Active;
        let mut done = slice_item(2);
        done.status = SliceStatus::Done;
        let mut split = slice_item(3);
        split.status = SliceStatus::Split;
        seed_slices(&daemon, "m1", vec![active, done, split, slice_item(4)]);
        let before = commit_count(&daemon);

        // Unknown milestone → unknown_id; unknown item → unknown_id.
        let err = update_slice(&daemon, serde_json::json!({ "milestone": "ghost", "id": "001", "status": "queued" }))
            .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        let err = update_slice(&daemon, serde_json::json!({ "milestone": "m1", "id": "ghost", "status": "queued" }))
            .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        // Moves on active/done/split items → started (the slice order is the
        // run order).
        for id in ["001", "002", "003"] {
            let err = update_slice(&daemon, serde_json::json!({ "milestone": "m1", "id": id, "move": { "to": "front" } }))
                .unwrap_err();
            assert!(err.1.starts_with("started:"), "{id}: {err:?}");
        }
        // Daemon-owned statuses → daemon_owned.
        for status in ["active", "split"] {
            let err = update_slice(&daemon, serde_json::json!({ "milestone": "m1", "id": "004", "status": status }))
                .unwrap_err();
            assert!(err.1.starts_with("daemon_owned:"), "{status}: {err:?}");
        }
        // A self-ref move → shape error; an unknown ref → unknown_id.
        let err = update_slice(&daemon, serde_json::json!({ "milestone": "m1", "id": "004", "move": { "to": "before", "ref": "004" } }))
            .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
        let err = update_slice(&daemon, serde_json::json!({ "milestone": "m1", "id": "004", "move": { "to": "before", "ref": "ghost" } }))
            .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");

        assert_eq!(commit_count(&daemon), before, "refusals mint no commit");
    }

    #[test]
    fn slice_update_done_resets_follow_ups_and_noop_mints_no_commit() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({}))).unwrap();
        let mut item = slice_item(1);
        item.follow_ups = Some(3);
        seed_slices(&daemon, "m1", vec![item]);
        let before = commit_count(&daemon);

        // A no-op edit mints no commit (the legacy reorder idempotence).
        update_slice(&daemon, serde_json::json!({ "milestone": "m1", "id": "001", "status": "queued" }))
            .expect("no-op computes");
        assert_eq!(commit_count(&daemon), before, "a no-op edit mints no commit");

        // done resets follow_ups to 0 (§3.3).
        update_slice(&daemon, serde_json::json!({ "milestone": "m1", "id": "001", "status": "done" }))
            .expect("done");
        assert_eq!(commit_count(&daemon), before + 1);
        let s = loaded_slices(&daemon, "m1");
        assert_eq!(s.items[0].status, SliceStatus::Done);
        assert_eq!(s.items[0].follow_ups, Some(0), "reset to 0 on done");
    }

    #[test]
    fn slice_update_done_on_a_sub_keeps_the_sub_shape() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({}))).unwrap();
        // A sub item carries no follow_ups (§3.3: slice only).
        seed_slices(
            &daemon,
            "m1",
            vec![SliceItem {
                kind: SliceKind::Sub,
                id: "sub-a".into(),
                status: SliceStatus::Queued,
                follow_ups: None,
            }],
        );

        // done on a sub sets the status and leaves the shape alone — the
        // reset is slice-only, and a `Some(0)` here would trip the §3.3
        // shape backstop and refuse the edit.
        let reply = update_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "id": "sub-a", "status": "done" }),
        )
        .expect("a human can mark a sub done");
        assert!(
            reply.view.contains("| 1 | sub | sub-a | done | — |"),
            "the sub row renders done with no follow_ups: {:?}",
            reply.view
        );
        let s = loaded_slices(&daemon, "m1");
        assert_eq!(s.items[0].status, SliceStatus::Done);
        assert_eq!(s.items[0].follow_ups, None, "a sub never gains follow_ups");
    }

    #[test]
    fn slice_update_dry_run_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({}))).unwrap();
        let before = commit_count(&daemon);

        let reply = update_slice(
            &daemon,
            serde_json::json!({ "milestone": "m1", "id": "001", "status": "blocked", "dry_run": true }),
        )
        .expect("dry run computes");
        assert_eq!(commit_count(&daemon), before, "no commit on a dry run");
        assert!(reply.view.contains("| 1 | slice | 001 | blocked |"), "{reply:?}");
        let s = loaded_slices(&daemon, "m1");
        assert_eq!(s.items[0].status, SliceStatus::Queued, "nothing landed");
    }

    #[test]
    fn queue_drop_archives_the_row_and_enqueues_a_restack_for_the_child() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // A stacked child b was cut from a (finding 7: hand-seeded parent —
        // claims are not file state, and no claim machinery exists yet).
        let mut a = entry("a");
        a.claimed = "2026-10-11T12:00:00Z".to_string();
        let mut b = entry("b");
        b.parent = "a".to_string();
        b.base = "abc123".to_string();
        b.claimed = "2026-10-11T12:10:00Z".to_string();
        seed_queue(&daemon, vec![project()], vec![a, b, entry("c")], None);
        let before = commit_count(&daemon);

        let reply = drop_entry(
            &daemon,
            serde_json::json!({ "id": "a", "reason": "superseded by the rewrite" }),
        )
        .expect("drop");
        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit per verb");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        // The drop→restack path (§8): one restack for the child's project,
        // urgent lane, no branch — ahead of the remaining normal rows.
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["001", "b", "c"], "restack enqueued, a left the list");
        let r = &qs.queue.model.entries[0];
        assert_eq!(r.kind, EntryKind::Restack);
        assert_eq!(r.lane, Lane::Urgent);
        assert_eq!(r.branch, "", "a restack has no branch of its own");
        assert_eq!(r.project, "softfig");
        // The child keeps its recorded parent as history (the restack itself
        // computes the rebase in queue-v2-git).
        let b = qs.queue.model.entries.iter().find(|e| e.id == "b").unwrap();
        assert_eq!(b.parent, "a");

        // The archive row: dropped, stamped, with the reason.
        assert_eq!(qs.archive.model.entries.len(), 1);
        let archived = &qs.archive.model.entries[0];
        assert_eq!(archived.row.id, "a");
        assert_eq!(archived.final_status, FinalStatus::Dropped);
        assert_eq!(archived.reason.as_deref(), Some("superseded by the rewrite"));
        assert!(!archived.finished.is_empty());
        assert!(wt.exists(QUEUE_ARCHIVE_FILE));

        // The minimal restack doc landed through the shared tasks .seq.
        let doc = wt
            .read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc");
        assert!(doc.starts_with("# Restack softfig\n"), "{doc}");
        assert_eq!(wt.read_to_string("growlight/backlog/tasks/.seq").unwrap(), "1\n");
        // The dropped entry left the list view.
        assert!(!reply.view.contains("| a | milestone"), "{reply:?}");
        assert!(reply.view.contains("| 001 | restack"), "{reply:?}");
        drop(inner);

        // Dropping c (no children) appends to the archive and enqueues
        // nothing further.
        let reply = drop_entry(&daemon, serde_json::json!({ "id": "c", "reason": "merged away" }))
            .expect("drop");
        assert!(!reply.view.contains("| c | milestone"), "{reply:?}");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["001", "b"], "no second restack for a childless drop");
        let archived: Vec<&str> = qs
            .archive
            .model
            .entries
            .iter()
            .map(|a| a.row.id.as_str())
            .collect();
        assert_eq!(archived, ["a", "c"], "archive rows keep arrival order");
    }

    #[test]
    fn queue_drop_dedupes_restacks_per_project() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // Two children of a in the same project: one restack covers the
        // repo's stack (§8).
        let mut a = entry("a");
        a.claimed = "2026-10-11T12:00:00Z".to_string();
        let mut b = entry("b");
        b.parent = "a".to_string();
        let mut c = entry("c");
        c.parent = "a".to_string();
        seed_queue(&daemon, vec![project()], vec![a, b, c], None);

        drop_entry(&daemon, serde_json::json!({ "id": "a", "reason": "gone" })).expect("drop");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["001", "b", "c"], "exactly one restack per project");
        assert!(!wt.exists("growlight/backlog/tasks/002-restack-softfig.md"));
    }

    #[test]
    fn queue_drop_refuses_each_failure_path() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut linked = entry("linked");
        linked.after = vec!["victim".to_string()];
        let mut active = entry("running");
        active.status = EntryStatus::Active;
        active.claimed = "2026-10-11T12:00:00Z".to_string();
        seed_queue(
            &daemon,
            vec![project()],
            vec![entry("victim"), linked, active],
            None,
        );
        let before = commit_count(&daemon);

        // Unknown id.
        let err = drop_entry(&daemon, serde_json::json!({ "id": "ghost", "reason": "x" }))
            .unwrap_err();
        assert!(err.1.starts_with("unknown_id:"), "{err:?}");
        // A live after-link still names the id → linked_from.
        let err = drop_entry(&daemon, serde_json::json!({ "id": "victim", "reason": "x" }))
            .unwrap_err();
        assert!(err.1.starts_with("linked_from:"), "{err:?}");
        // An active entry's session is never killed → running.
        let err = drop_entry(&daemon, serde_json::json!({ "id": "running", "reason": "x" }))
            .unwrap_err();
        assert!(err.1.starts_with("running:"), "{err:?}");
        // An empty reason is a shape error.
        let err = drop_entry(&daemon, serde_json::json!({ "id": "victim", "reason": "   " }))
            .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");

        assert_eq!(commit_count(&daemon), before, "refusals mint no commit");
    }

    #[test]
    fn queue_drop_dry_run_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut a = entry("a");
        a.claimed = "2026-10-11T12:00:00Z".to_string();
        let mut b = entry("b");
        b.parent = "a".to_string();
        seed_queue(&daemon, vec![project()], vec![a, b], None);
        let before = commit_count(&daemon);

        let reply = drop_entry(
            &daemon,
            serde_json::json!({ "id": "a", "reason": "x", "dry_run": true }),
        )
        .expect("dry run computes");
        assert_eq!(commit_count(&daemon), before, "no commit on a dry run");
        assert!(!garden.path().join(QUEUE_ARCHIVE_FILE).exists(), "no archive written");
        assert!(
            !garden.path().join("growlight/backlog/tasks/001-restack-softfig.md").exists(),
            "no restack doc staged"
        );
        // The would-be list: a is gone, the restack row shows.
        assert!(!reply.view.contains("| a | milestone"), "{reply:?}");
        assert!(reply.view.contains("| 001 | restack"), "{reply:?}");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"], "nothing landed");
        assert!(qs.archive.model.entries.is_empty());
    }
}
