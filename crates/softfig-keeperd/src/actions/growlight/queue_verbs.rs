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
    QueueArchiveToml, QueueRefusal, QueueToml, RestackBranch, SliceItem, SliceKind, SliceStatus,
    SlicesToml, QUEUE_ARCHIVE_FILE,
};
use softfig_ipc::verbs::{
    QueueAddEntryArgs, QueueAddEntryReply, QueueAddProjectArgs, QueueAddProjectReply,
    QueueDropArgs, QueueDropReply, QueueStatusArg, QueueUpdateEntryArgs, QueueUpdateEntryReply,
    QueueV2EnqueueRestackArgs, QueueV2EnqueueRestackReply, SliceInsertArgs, SliceInsertReply,
    SliceUpdateArgs, SliceUpdateReply,
};
use softfig_ipc::ErrorKind;
use softfig_store::Hash;

use super::super::numbering;
use super::v2::{
    apply, load_queue_state, load_slices, milestone_path, queue_view, queue_view_host, slices_file,
    slices_view, slices_view_host, unit_doc_rel, ExtraWrites, FileWrite, ViewWrite, QUEUE_FILE,
    QUEUE_V2_TAG, SLICES_V2_TAG,
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
    if let Some(member) = crate::caller::member()
        && let Some((field, key)) = member_reserved_field(&args) {
            let key = softfig_ipc::item_meta::display_key(key);
            return Err((
                ErrorKind::BadArgs,
                format!(
                    "field_not_allowed: `{field}` carries a `> {key}:` line, and fleet member \
                     {member} may not write `> Model:`, `> Grants:` or `> Worktree:` into the \
                     docs queue_add_entry writes (spec-growlight-queue §6.7) — keeperd renders \
                     the entry's docs from these fields, and a new entry declares no model, so \
                     its slices may declare none"
                ),
            ));
        }
    match args.kind {
        EntryKind::Milestone => add_milestone(daemon, args),
        EntryKind::Task => add_task(daemon, args),
        EntryKind::Restack => add_restack(daemon, args),
    }
}

/// §6.7 for a member's `queue_add_entry`: the first text field carrying a
/// reserved `> Model:` / `> Grants:` / `> Worktree:` line, as `(field, key)`.
/// keeperd renders the entry's docs from these fields through the structured
/// writer, outside the worktree's member guard, so the guard runs here on the
/// member's own text — and not on keeperd's generated `001-plan` slice, whose
/// `> Model:` line is the daemon's. `queue_add_entry` is not one of §6.7's
/// slice-body exceptions, so a slice body may declare nothing either (the new
/// milestone declares nothing to take a subset of): all three keys are refused
/// in every field, slice bodies included.
fn member_reserved_field(args: &QueueAddEntryArgs) -> Option<(String, &'static str)> {
    use softfig_ipc::queue_v2::{reserved_field, SUB_DOC_RESERVED};
    let declares = |text: Option<&str>| text.and_then(|t| reserved_field(t, &SUB_DOC_RESERVED));
    let entry_fields = [
        ("title", args.title.as_deref()),
        ("mission", args.mission.as_deref()),
        ("finish_criteria", args.finish_criteria.as_deref()),
    ];
    if let Some((field, key)) = entry_fields
        .iter()
        .find_map(|(field, text)| declares(*text).map(|key| (field.to_string(), key)))
    {
        return Some((field, key));
    }
    args.slices.iter().enumerate().find_map(|(i, s)| {
        declares(s.title.as_deref())
            .map(|key| (format!("slices[{i}].title"), key))
            .or_else(|| declares(Some(&s.body)).map(|key| (format!("slices[{i}].body"), key)))
    })
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

/// A project's restack row, new or live, plus its pending writes. `doc` is
/// `None` when the live row's doc already says everything; `number` is set for
/// a new row only, whose `.seq` bump rides with its doc.
struct RestackStaged {
    id: String,
    rel: String,
    doc: Option<FileWrite>,
    number: Option<u32>,
}

/// The project's live restack row: at most one, whatever its status (§3.1).
fn live_restack<'q>(queue: &'q QueueToml, project: &str) -> Option<&'q Entry> {
    queue
        .entries
        .iter()
        .find(|e| e.kind == EntryKind::Restack && e.project == project)
}

/// Whether a session holds this row's doc (§8): it read the steps at its start
/// and works from them, so a re-render would never reach it. A `blocked`,
/// `deferred` or `queued` row has no session, and the next one reads the doc.
fn session_holds_doc(restack: &Entry) -> bool {
    matches!(restack.status, EntryStatus::Active | EntryStatus::Paused)
}

/// The restack-creation core (§8), shared by `add_restack` (slice 005),
/// `queue_drop`'s drop→restack path (slice 006), and the daemon's auto-enqueue
/// (`queue_v2_enqueue_restack`, slice 003), so one project never has two rows.
/// With no live row, build the urgent no-branch row for `project` at the urgent
/// lane's back, numbered `*next` (the caller reads the high water, so one verb
/// enqueuing several restacks hands out distinct numbers before any `.seq`
/// write lands). With a live row, merge `stack` into its doc
/// ([`merge_into_live_restack`]), or refuse `started` if a session holds that
/// doc. The doc write is staged, not made (so a dry run can compute the row
/// without writing anything), rendered from `stack` (the §8 full template when
/// non-empty; the caller passes the git-resolved stack, or `&[]` when it has
/// none). The caller proves the project exists before calling — its entry rows
/// validated on load.
fn restack_core(
    wt: &WorkTree,
    queue: &mut QueueToml,
    archive: &QueueArchiveToml,
    project: &str,
    next: &mut u32,
    stack: &[RestackBranch],
) -> Result<RestackStaged, (ErrorKind, String)> {
    if let Some(live) = live_restack(queue, project) {
        if session_holds_doc(live) {
            return Err(refuse(QueueRefusal::Started { id: live.id.clone() }));
        }
        return merge_into_live_restack(wt, &live.id, archive, project, stack);
    }

    let number = *next;
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
    *next += 1;
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
        doc: Some(FileWrite {
            rel: rel.clone(),
            expected: None,
            bytes: restack_doc(project, &conventions::today_hyphen(), stack).into_bytes(),
        }),
        number: Some(number),
        rel,
    })
}

/// Fold `stack` into the doc of the live row `id` (§8). The row keeps its place
/// and status; only the doc changes, and only when the merge changes a step, so
/// a detection that finds the same stack every scan commits nothing. Its steps
/// may be partly done: each is tested right before it runs, so the re-render is
/// safe. The sections keeperd stamps below the template survive it.
fn merge_into_live_restack(
    wt: &WorkTree,
    id: &str,
    archive: &QueueArchiveToml,
    project: &str,
    stack: &[RestackBranch],
) -> Result<RestackStaged, (ErrorKind, String)> {
    let rel = unit_doc_rel(wt, EntryKind::Restack, id, None)?;
    let live_doc = wt
        .read_to_string(&rel)
        .ok_or_else(|| (ErrorKind::NotFound, format!("no restack doc at {rel}")))?;
    let live = stack_of_doc(&live_doc);
    let merged = merge_stacks(&live, stack, archive);

    let date = conventions::today_hyphen();
    let doc = restack_doc(project, &date, &merged);
    let doc = (doc != restack_doc(project, &date, &live)).then(|| FileWrite {
        rel: rel.clone(),
        expected: Some(Hash::of(live_doc.as_bytes()).to_hex()),
        bytes: match stamped_sections(&live_doc) {
            "" => doc.clone().into_bytes(),
            stamped => format!("{}\n\n{stamped}", doc.trim_end()).into_bytes(),
        },
    });
    Ok(RestackStaged {
        id: id.to_string(),
        rel,
        doc,
        number: None,
    })
}

/// The stack a restack doc carries: what [`restack_doc`] rendered, read back
/// from its `## Stack` lines and the `--onto` of each step. The doc is the only
/// record of a drop's steps, whose upstream is the dropped branch rather than
/// the child's recorded base. A branch with no recorded base or no `--onto`
/// target has no step, so its `onto` reads back empty.
fn stack_of_doc(doc: &str) -> Vec<RestackBranch> {
    let mut stack: Vec<RestackBranch> = doc
        .lines()
        .filter_map(|line| {
            let (branch, rest) = line.strip_prefix("- `")?.split_once("` — parent: `")?;
            let (parent, base) = rest.split_once("`, base: `")?;
            Some(RestackBranch {
                branch: branch.to_string(),
                parent: parent.to_string(),
                base: base.strip_suffix('`')?.to_string(),
                onto: String::new(),
            })
        })
        .collect();
    let steps = doc
        .lines()
        .filter_map(|line| line.strip_prefix("- `git rebase --onto ")?.strip_suffix('`'));
    for step in steps {
        let mut operands = step.split(' ');
        let (Some(onto), Some(_), Some(branch)) =
            (operands.next(), operands.next(), operands.next())
        else {
            continue;
        };
        if let Some(b) = stack.iter_mut().find(|b| b.branch == branch) {
            b.onto = onto.to_string();
        }
    }
    stack
}

/// `new` folded into the `live` stack. A branch in both keeps its older `base`,
/// which is what says where its own commits start (a later view of the list can
/// lag it: a drop's step cuts at the dropped branch), and takes the newer `onto`,
/// which is where it belongs now. So two drops under one branch compose into
/// one step that cuts both, and a list-state stack can't bring dropped commits
/// back. A dropped branch leaves the stack: it's abandoned, nothing rebases it.
fn merge_stacks(
    live: &[RestackBranch],
    new: &[RestackBranch],
    archive: &QueueArchiveToml,
) -> Vec<RestackBranch> {
    let mut merged = live.to_vec();
    for step in new {
        match merged.iter_mut().find(|b| b.branch == step.branch) {
            Some(b) => {
                b.parent = step.parent.clone();
                if b.base.is_empty() {
                    b.base = step.base.clone();
                }
                if !step.onto.is_empty() {
                    b.onto = step.onto.clone();
                }
            }
            None => merged.push(step.clone()),
        }
    }
    merged.retain(|b| {
        !archive
            .entries
            .iter()
            .any(|a| a.final_status == FinalStatus::Dropped && a.row.branch == b.branch)
    });
    bottom_first(merged)
}

/// `stack` with every branch after the branch it goes onto, otherwise in the
/// order given: a merge can add a parent after its child.
fn bottom_first(mut pending: Vec<RestackBranch>) -> Vec<RestackBranch> {
    let mut ordered = Vec::with_capacity(pending.len());
    while !pending.is_empty() {
        let ready = pending
            .iter()
            .position(|b| !pending.iter().any(|p| p.branch == b.onto))
            .unwrap_or(0);
        ordered.push(pending.remove(ready));
    }
    ordered
}

/// The headings [`restack_doc`] renders. Anything else in a restack doc was
/// stamped there later.
const RESTACK_TEMPLATE_HEADINGS: [&str; 5] =
    ["## Stack", "## Before you rebase", "## Protect the work", "## Steps", "## Gate"];

/// `doc` from its first section the template doesn't render: `## Sessions`,
/// `## Deferred verification`. Empty when it has none.
fn stamped_sections(doc: &str) -> &str {
    let mut at = 0;
    for line in doc.split_inclusive('\n') {
        if line.starts_with("## ") && !RESTACK_TEMPLATE_HEADINGS.contains(&line.trim_end()) {
            return &doc[at..];
        }
        at += line.len();
    }
    ""
}

/// The doc writes of `restacks`, plus one `.seq` bump to the highest number a
/// new row took. They ride `apply`'s one commit as extras.
fn restack_extras(wt: &WorkTree, restacks: &[RestackStaged]) -> Vec<FileWrite> {
    let mut extras: Vec<FileWrite> = restacks.iter().filter_map(|r| r.doc.clone()).collect();
    if let Some(number) = restacks.iter().filter_map(|r| r.number).max() {
        extras.push(FileWrite {
            rel: format!("{}/{}", paths::tasks_dir(), conventions::SEQ_FILE),
            expected: numbering::seq_version(wt, &paths::tasks_dir()),
            bytes: format!("{number}\n").into_bytes(),
        });
    }
    extras
}

/// The stack of `project` as the list records it (§8's remote proxy): every
/// live entry with a branch that has been claimed, in claim order, each with
/// its recorded `parent` and `base`, and `onto` from [`onto_of_parent`]. Empty
/// when nothing of the project has been claimed.
fn stack_from_list(
    queue: &QueueToml,
    archive: &QueueArchiveToml,
    project: &str,
) -> Vec<RestackBranch> {
    let mut started: Vec<&Entry> = queue
        .entries
        .iter()
        .filter(|e| e.project == project && !e.branch.is_empty() && !e.claimed.is_empty())
        .collect();
    started.sort_by(|a, b| a.claimed.cmp(&b.claimed));
    started
        .into_iter()
        .map(|e| RestackBranch {
            branch: e.branch.clone(),
            parent: e.parent.clone(),
            base: e.base.clone(),
            onto: onto_of_parent(queue, archive, project, &e.parent),
        })
        .collect()
}

/// Where a branch of `project` cut from the entry `parent` belongs, as the list
/// records it: the parent's branch while the parent is live, else the branch of
/// a `done` archive row (an archived but unmerged parent still holds the child's
/// prerequisite commits, V7), else the project's `main`.
fn onto_of_parent(
    queue: &QueueToml,
    archive: &QueueArchiveToml,
    project: &str,
    parent: &str,
) -> String {
    let parent_branch = queue
        .entries
        .iter()
        .find(|p| !parent.is_empty() && p.id == parent)
        .map(|p| p.branch.clone())
        .or_else(|| {
            archive
                .entries
                .iter()
                .find(|a| {
                    !parent.is_empty()
                        && a.row.id == parent
                        && a.final_status == FinalStatus::Done
                })
                .map(|a| a.row.branch.clone())
        })
        .filter(|b| !b.is_empty());
    parent_branch.unwrap_or_else(|| {
        queue
            .projects
            .iter()
            .find(|p| p.name == project)
            .map(|p| p.main.clone())
            .unwrap_or_else(|| "main".to_string())
    })
}

/// `queue_add_entry`, restack kind (§8): `project` only, every other arg
/// refused as `BadArgs` (finding 5: the §6.8 state-refusal list has no code
/// for a shape mismatch). This is the human-enqueued restack — the only kind a
/// remote project gets. keeperd runs no git, so the doc's stack is rendered
/// from list state ([`stack_from_list`]); the placeholder form is left for a
/// project with nothing claimed. The row is urgent-lane, no branch, appended
/// to the urgent lane's back. A live row takes the stack instead
/// ([`restack_core`]), and the reply names that row.
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

    // keeperd runs no git, but it holds the list: render the stack from it, the
    // same way for a remote project (which growlightd never resolves) and a
    // local one a human enqueues by hand (V4).
    let stack = stack_from_list(&queue, &archive, &args.project);
    let restack = {
        let wt = WorkTree::new(daemon, &inner);
        let mut next = numbering::next_number(&wt, &paths::tasks_dir());
        restack_core(&wt, &mut queue, &archive, &args.project, &mut next, &stack)?
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

    // Nothing new for the live row is the same answer as a dry run: its id and
    // path, and no commit.
    if args.dry_run || restack.doc.is_none() {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueAddEntryReply {
            id: restack.id,
            path: restack.rel,
            view,
            hash,
        })
        .unwrap());
    }

    // The restack doc + any `.seq` bump ride `apply`'s one commit as extras
    // (same envelope as the task kind).
    let extras = {
        let wt = WorkTree::new(daemon, &inner);
        restack_extras(&wt, std::slice::from_ref(&restack))
    };

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

/// `queue_v2_enqueue_restack` (queue-v2-git slice 003): keeperd↔growlightd only —
/// the daemon detected a stale stack (§8, read-only git) and enqueues ONE urgent
/// restack row for `project`, rendering the full restack doc from `stack` (each
/// branch's `parent`/`base` and the resolved `--onto`, the steps, the gate).
/// A live row takes the stack instead ([`restack_core`]). Idempotent per project:
/// `id`/`path` are `None` and nothing commits when the live row's doc already
/// carries the stack, or a session holds that doc, where detection is
/// level-triggered and finds the stack again once the row ends. One commit,
/// `queue_v2_updated`; the restack doc + any `.seq` bump ride it as extras.
pub fn queue_v2_enqueue_restack(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2EnqueueRestackArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_enqueue_restack args: {e}")))?;
    if args.project.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "project must be non-empty".to_string()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let (mut queue, queue_version, archive) = {
        let wt = WorkTree::new(daemon, &inner);
        load_for_add(&wt, &inner, &args.project, &[])?
    };

    let held = live_restack(&queue, &args.project).is_some_and(session_holds_doc);
    let restack = if held {
        None
    } else {
        let wt = WorkTree::new(daemon, &inner);
        let mut next = numbering::next_number(&wt, &paths::tasks_dir());
        Some(restack_core(&wt, &mut queue, &archive, &args.project, &mut next, &args.stack)?)
    };
    // Nothing to write: the reply carries no id/path, just the current tip.
    let Some(restack) = restack.filter(|r| r.doc.is_some()) else {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueV2EnqueueRestackReply {
            id: None,
            path: None,
            hash,
        })
        .unwrap());
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

    // The restack doc + any `.seq` bump ride `apply`'s one commit as extras
    // (the same envelope as `add_restack`).
    let extras = {
        let wt = WorkTree::new(daemon, &inner);
        restack_extras(&wt, std::slice::from_ref(&restack))
    };

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_updated",
        serde_json::json!({
            "verb": "queue_v2_enqueue_restack",
            "id": restack.id,
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

    Ok(serde_json::to_value(QueueV2EnqueueRestackReply {
        id: Some(restack.id),
        path: Some(restack.rel),
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
    if let Some(new_lane) = args.lane
        && queue.entries[idx_of(&queue, &args.id)].lane != new_lane {
            let mut e = queue.entries.remove(idx_of(&queue, &args.id));
            e.lane = new_lane;
            let at = match new_lane {
                Lane::Urgent => place_entry(&queue.entries, Lane::Urgent, &V2Position::Back),
                Lane::Normal => place_entry(&queue.entries, Lane::Normal, &V2Position::Front),
            }
            .map_err(refuse)?;
            queue.entries.insert(at, e);
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
        // A link could name an entry the restack's own repo hold keeps waiting
        // (§2), and neither would ever run. `[]` still clears a hand-made one.
        if queue.entries[idx].kind == EntryKind::Restack && !links.is_empty() {
            return Err((
                ErrorKind::BadArgs,
                format!("entry {:?} is a restack: a restack takes no after links", args.id),
            ));
        }
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
            // Finding 8 (§6.8): a status change on an `active` entry takes
            // effect at its session's next handshake, never mid-session. The
            // row keeps `active` (the repo rule and the scheduler keep
            // working) and records the change as `pending_status`; the view
            // annotates it, and the handshake's `queue_v2_set_status` applies
            // it at the boundary. Any other entry changes now.
            QueueStatusArg::Queued | QueueStatusArg::Blocked | QueueStatusArg::Deferred => {
                let new = match status {
                    QueueStatusArg::Queued => EntryStatus::Queued, // also unblocks and un-defers
                    QueueStatusArg::Blocked => EntryStatus::Blocked,
                    _ => EntryStatus::Deferred,
                };
                let idx = idx_of(&queue, &args.id);
                let row = &mut queue.entries[idx];
                if row.status == EntryStatus::Active {
                    row.pending_status = Some(new);
                } else {
                    row.status = new;
                }
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
/// §8 — the children are re-parented in the same write (`parent` := the
/// dropped entry's parent; each keeps its `base`, which still says where its
/// own commits start) and one restack is enqueued per distinct project of the
/// whole descendant subtree, not just the direct children (the restack covers
/// a repo's stack; its generated doc carries the rebase steps).
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

    // The drop→restack path (§8, queue-v2-git slices 004 + 006): the live
    // subtree cut from the dropped entry, one restack per distinct project.
    // The direct children move off the abandoned commits (`git rebase --onto
    // <new parent's branch> <dropped branch> <child>`) and are re-parented in
    // this same write, so later rewrites of the real parent are still detected
    // (V5). A child keeps its recorded `base`: the dropped commits are still in
    // it, so that base is what keeps them out of any later step rendered from
    // the list (F4), and the re-record moves it once the rewrite lands. That
    // leaves the dropped entry's own base unfit as a target, since after a
    // chained drop it still holds what the earlier drop abandoned. Their
    // descendants keep their parents and recorded bases and follow their
    // parent's new tip (`--onto <parent branch> <own base>`). Collected before
    // the row leaves the list; bottom first, so a parent is always rebased
    // before the branches cut from it.
    let dropped_parent = queue.entries[idx].parent.clone();
    let dropped_branch = queue.entries[idx].branch.clone();
    let mut subtree: Vec<(String, RestackBranch)> = Vec::new();
    let mut seen: Vec<String> = vec![args.id.clone()];
    let mut cursor = 0;
    while cursor < seen.len() {
        let at = seen[cursor].clone();
        cursor += 1;
        for e in queue.entries.iter().filter(|e| e.parent == at) {
            if seen.contains(&e.id) {
                continue;
            }
            seen.push(e.id.clone());
            let rb = if at == args.id {
                RestackBranch {
                    branch: e.branch.clone(),
                    parent: dropped_parent.clone(),
                    base: dropped_branch.clone(),
                    onto: onto_of_parent(&queue, &archive, &e.project, &dropped_parent),
                }
            } else {
                RestackBranch {
                    branch: e.branch.clone(),
                    parent: at.clone(),
                    base: e.base.clone(),
                    onto: onto_of_parent(&queue, &archive, &e.project, &at),
                }
            };
            subtree.push((e.project.clone(), rb));
        }
    }
    for e in queue.entries.iter_mut().filter(|e| e.parent == args.id) {
        e.parent = dropped_parent.clone();
    }

    let row = queue.entries.remove(idx);
    archive.entries.push(ArchivedEntry {
        row,
        finished: conventions::now_rfc3339(),
        final_status: FinalStatus::Dropped,
        reason: Some(args.reason.clone()),
    });

    // Dry runs compute the restack rows too (the would-be view shows them)
    // but stage no docs. Numbers come from one high-water read plus the
    // core's own bump, so several restacks in this one verb get distinct
    // numbers even before any `.seq` write lands. A project with a live row
    // merges into it, and a session holding that row's doc refuses the drop:
    // the steps below exist only in this write, so they can't be left out.
    let restacks: Vec<RestackStaged> = {
        let wt = WorkTree::new(daemon, &inner);
        // Group the stack per project (project order = first-branch order,
        // branch order = bottom first, siblings in list order — the claim
        // order §8).
        let mut by_project: Vec<(String, Vec<RestackBranch>)> = Vec::new();
        for (project, rb) in subtree {
            if let Some((_, stack)) = by_project.iter_mut().find(|(p, _)| *p == project) {
                stack.push(rb);
            } else {
                by_project.push((project, vec![rb]));
            }
        }
        let mut next = numbering::next_number(&wt, &paths::tasks_dir());
        by_project
            .iter()
            .map(|(p, stack)| restack_core(&wt, &mut queue, &archive, p, &mut next, stack))
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
    let extras = {
        let wt = WorkTree::new(daemon, &inner);
        restack_extras(&wt, &restacks)
    };

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

/// The upstream rule every restack doc carries (§8, V1): a branch that tracks
/// an upstream may be pushed, so the loop never rewrites it. The agent checks
/// BEFORE the first rebase and blocks for the human instead. growlightd also
/// withholds the auto-enqueue when it sees one, so this covers a human-enqueued
/// restack and a branch pushed after detection.
const RESTACK_UPSTREAM_RULE: &str = "## Before you rebase\n\n\
     Never rewrite a branch that tracks an upstream — it may be pushed. Check \
     every branch of the restack first, before any rebase:\n\n\
     ```\n\
     git for-each-ref --format='%(upstream)' refs/heads/<branch>\n\
     ```\n\n\
     If it prints a ref for ANY branch, do not rebase anything: end with \
     `growlight_block`, `kind = human`, naming the branch. A command that fails \
     is not an answer — treat it as tracked and block.\n";

/// What a restack session must do before it touches a branch (§8, V4). The
/// steps are bare `git rebase --onto` lines, so everything that keeps the work
/// they rewrite safe lives here: which worktree runs them (a branch checked out
/// in one worktree cannot be rebased from another), a clean tree, a backup ref,
/// and what a session killed mid-rebase leaves for the next one.
///
/// The skip test is the whole post-condition of `rebase --onto <onto> <base>
/// <branch>`, for every step the doc can carry: containing `<onto>` is only half
/// of it, because a drop's direct child contains its `--onto` commit (its new
/// parent's tip) before its step has run (review 055 F1). It is run per step,
/// not as a pre-flight, because a grandchild contains its parent's tip until the
/// parent's own step moves that tip.
///
/// The resume abort is keyed on the rebase's `head-name`, because a worktree
/// mid-rebase lists as `detached`, with no `branch` line, and a rebase that isn't
/// this stack's may hold someone's half-done resolution (review 055 F5). A branch
/// no worktree holds runs in a scratch worktree beside the main one, because a
/// rebase leaves its branch checked out wherever it ran. Not under `.git`: tools
/// a project's gate runs (jest, for one) ignore any path with a `.git` component.
const RESTACK_SAFETY_RULE: &str = "## Protect the work\n\n\
     1. **Resume first.** A previous session may have died mid-rebase on one of \
     this restack's branches. Run this for each `<branch>` of the stack; it aborts \
     only a rebase of that branch, which goes back to its pre-rebase tip, so \
     nothing is lost:\n\n\
     ```\n\
     git worktree list --porcelain | sed -n 's/^worktree //p' | while IFS= read -r wt; do\n\
     \x20\x20for dir in rebase-merge rebase-apply; do\n\
     \x20\x20\x20\x20name=$(git -C \"$wt\" rev-parse --path-format=absolute --git-path \"$dir/head-name\")\n\
     \x20\x20\x20\x20if [ \"$(cat \"$name\" 2>/dev/null)\" = refs/heads/<branch> ]; then git -C \"$wt\" rebase --abort; fi\n\
     \x20\x20done\n\
     done\n\
     ```\n\n\
     Leave every other rebase alone, whether it names another branch or none: \
     it isn't this restack's, and it may hold someone's half-done resolution. \
     Then, if `<scratch>` (step 3) is listed, run \
     `git worktree remove --force <scratch>`: a dead session left it, and it holds \
     no work, because a rebase moves its branch only when it finishes.\n\
     2. **Skip only a finished step.** Test each step right before you reach it, \
     once the steps above it have landed, never up front: a branch contains its \
     parent's old tip until the parent moves. `git rebase --onto <onto> <base> \
     <branch>` already happened if `git merge-base --is-ancestor <onto> <branch>` \
     and `git merge-base --is-ancestor \"$(git merge-base <base> <branch>)\" <onto>` \
     both succeed: the branch stands on `<onto>` and holds nothing of `<base>` \
     that `<onto>` lacks. Only then skip its step. Containing `<onto>` alone \
     proves nothing: the child of a dropped entry contains it from the start.\n\
     3. **Use the branch's worktree.** Run each step from the worktree that has \
     the branch checked out (the `worktree` block of `git worktree list \
     --porcelain` whose `branch` is `refs/heads/<branch>`). If none has it, use a \
     scratch worktree, never one you keep: a rebase leaves its branch checked out \
     wherever it ran, and git then refuses that branch to every other worktree. \
     `<scratch>` is the path \
     `git worktree list --porcelain | sed -n '1s/^worktree //;1s/$/.restack-scratch/p'` \
     prints, beside the main worktree:\n\n\
     ```\n\
     git worktree add --detach <scratch> <branch>\n\
     git -C <scratch> rebase --onto <onto> <base> <branch>\n\
     ```\n\n\
     It is that step's `<worktree>` in the rules below, and the gate runs in it. \
     Once the branch's gate has run, pass or fail, and before any \
     `growlight_block`, run `git worktree remove --force <scratch>`.\n\
     4. **Clean tree.** `git -C <worktree> status --porcelain` must print \
     nothing. If it prints anything, rebase nothing: `growlight_block`, \
     `kind = human`, naming the worktree. Never stash, reset or discard.\n\
     5. **Back up.** Before a branch's rebase run \
     `git branch restack-backup/<branch> <branch>`. If that ref already exists \
     an earlier attempt made it: keep it, it holds the original tip. Never \
     delete a backup ref; the human does, after review.\n\
     6. **On a conflict, abort and block.** Run `git -C <worktree> rebase \
     --abort`, then end with `growlight_block`, `kind = human`, naming the \
     branch and its backup ref. Do not resolve the conflict and do not rebase \
     any later branch.\n";

/// The gate every restack doc names (§8, V4): the project's own, never a
/// hard-coded command — `cargo test --workspace` is wrong for a project that is
/// not a Cargo workspace.
const RESTACK_GATE_RULE: &str = "## Gate\n\n\
     After each rebase, run the project's own gate before the next branch and \
     before `growlight_complete_entry`: the build/test/lint command the \
     project's own `CLAUDE.md` names. Do not assume one. If the project names \
     no gate, or the gate fails, end with `growlight_block`, `kind = human`, \
     naming the branch and its `restack-backup/<branch>` ref.\n";

/// The §8 restack doc (queue-v2-git slice 003, V4): with a `stack` (growlightd's
/// git-resolved one, or keeperd's list-state one for a human-enqueued restack),
/// the full template — the stack in order (each branch's `parent` and `base`),
/// the safety rules, the steps (one `git rebase --onto` per unmerged branch in
/// stack order) and the gate. With an empty `stack` (nothing of the project is
/// claimed) the doc is a placeholder naming `queue show` as the way to re-derive
/// it. Both forms carry [`RESTACK_UPSTREAM_RULE`] and [`RESTACK_SAFETY_RULE`]:
/// the loop never rewrites a branch that tracks an upstream (§8, V1), and never
/// rebases without a worktree, a clean tree and a backup (V4).
fn restack_doc(project: &str, date_hyphen: &str, stack: &[RestackBranch]) -> String {
    if stack.is_empty() {
        return format!(
            "# Restack {project}\n\n\
             > Last reviewed: {date_hyphen}\n\n\
             > Generated restack entry for project `{project}` (queue v2 §8). Lane, \
             status and branch live in `queue.toml` (the derived `softfig:queue-v2` \
             table in `../CLAUDE.md`). No stack was recorded at enqueue — re-derive \
             it from `softfig growlight queue show` before rebasing.\n\n\
             {RESTACK_UPSTREAM_RULE}\n{RESTACK_SAFETY_RULE}\n{RESTACK_GATE_RULE}"
        );
    }
    let mut doc = format!(
        "# Restack {project}\n\n\
         > Last reviewed: {date_hyphen}\n\n\
         > Generated restack entry for project `{project}` (queue v2 §8): `main` \
         moved under an open stack, so each unmerged branch must be rebased in \
         stack order. Lane, status and branch live in `queue.toml` (the derived \
         `softfig:queue-v2` table in `../CLAUDE.md`).\n\n\
         ## Stack\n\n"
    );
    for b in stack {
        let parent = if b.parent.is_empty() { "main" } else { &b.parent };
        doc.push_str(&format!(
            "- `{}` — parent: `{parent}`, base: `{}`\n",
            b.branch, b.base
        ));
    }
    doc.push('\n');
    doc.push_str(RESTACK_UPSTREAM_RULE);
    doc.push('\n');
    doc.push_str(RESTACK_SAFETY_RULE);
    doc.push_str(
        "\n## Steps\n\n\
         Rebase each branch in stack order (bottom first), each from its own \
         worktree and after its backup ref exists. If an `--onto` branch no longer \
         exists it was merged: use `main` instead.\n\n",
    );
    for b in stack {
        if b.base.is_empty() {
            // No recorded base: the step cannot be written, and a guessed one
            // could drop or duplicate commits.
            doc.push_str(&format!(
                "- `{}`: no base is recorded for it, so do not guess one — \
                 `growlight_block`, `kind = human`, naming the branch\n",
                b.branch
            ));
            continue;
        }
        if b.onto.is_empty() {
            // A stack handed in without a target: `--onto  <base> <branch>`
            // would read as a different rebase (report 136).
            doc.push_str(&format!(
                "- `{}`: nothing is recorded to rebase it onto, so do not guess \
                 it — `growlight_block`, `kind = human`, naming the branch\n",
                b.branch
            ));
            continue;
        }
        doc.push_str(&format!(
            "- `git rebase --onto {} {} {}`\n",
            b.onto, b.base, b.branch
        ));
    }
    doc.push('\n');
    doc.push_str(RESTACK_GATE_RULE);
    doc
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

    /// §6.7 for a member's found work: its text fields may carry no reserved
    /// `> Model:` / `> Grants:` / `> Worktree:` line (refused
    /// `field_not_allowed`, nothing committed), but an unplanned milestone still
    /// gets keeperd's own `001-plan` slice with the daemon's `> Model:` line.
    /// A human's identical call is unrestricted.
    #[test]
    fn a_members_add_entry_may_not_declare_a_reserved_line_but_still_gets_the_plan_slice() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        let before = commit_count(&daemon);
        let declaring = [
            ("mission", milestone_args("m1", "softfig", serde_json::json!({ "mission": "x\n> Model: claude" }))),
            ("finish_criteria", milestone_args("m1", "softfig", serde_json::json!({ "finish_criteria": "> model: flash" }))),
            ("title", milestone_args("m1", "softfig", serde_json::json!({ "title": "T\n> Grants: ~/x" }))),
            ("mission", milestone_args("m1", "softfig", serde_json::json!({ "mission": "x\n> Worktree: /tmp/x" }))),
            ("slices[1].title", milestone_args("m1", "softfig", serde_json::json!({ "slices": [
                { "slug": "a", "title": "A", "body": "plain" },
                { "slug": "b", "title": "> Worktree: /tmp/x", "body": "work" },
            ] }))),
            ("slices[1].body", milestone_args("m1", "softfig", serde_json::json!({ "slices": [
                { "slug": "a", "title": "A", "body": "plain" },
                { "slug": "b", "title": "B", "body": "> Model: flash\n\nwork" },
            ] }))),
            ("slices[1].body", milestone_args("m1", "softfig", serde_json::json!({ "slices": [
                { "slug": "a", "title": "A", "body": "plain" },
                { "slug": "b", "title": "B", "body": "> Grants: ~/x\n\nwork" },
            ] }))),
        ];
        {
            let _member = crate::caller::enter(Some("c".into()));
            for (field, args) in &declaring {
                let err = add_entry(&daemon, args.clone()).unwrap_err();
                assert_eq!(err.0, ErrorKind::BadArgs);
                assert!(
                    err.1.starts_with("field_not_allowed:") && err.1.contains(&format!("`{field}`")),
                    "{field}: {err:?}"
                );
            }
            assert_eq!(commit_count(&daemon), before, "a refusal commits nothing");
            add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({})))
                .expect("a member's plain found work lands");
            // A prose mention of a key is not a blockquote metadata line.
            add_entry(
                &daemon,
                milestone_args("m2", "softfig", serde_json::json!({ "mission": "Model: claude in prose" })),
            )
            .expect("a prose mention is not a metadata line");
        }
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            let plan = wt
                .read_to_string("growlight/backlog/milestones/m1/slices/001-plan.md")
                .expect("generated plan slice");
            assert!(plan.contains("> Model: reasoning"), "keeperd's own line, {plan}");
        }
        let (_, human) = &declaring[5];
        let mut human = human.clone();
        human["slug"] = serde_json::json!("m3");
        add_entry(&daemon, human).expect("a human may declare a slice model");
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
            doc.contains("No stack was recorded at enqueue"),
            "the placeholder names the re-derivation path, {doc}"
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

        // Another project's restack appends to the urgent lane's back.
        add_project(&daemon, "other", "~/other");
        let reply2 = add_entry(&daemon, restack_args("other", serde_json::json!({})))
            .expect("second restack");
        assert_eq!(reply2.id, "002");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["001", "002", "m1"], "urgent entries keep file order: oldest first");
    }

    /// A link could point a restack at an entry its own repo hold keeps
    /// waiting, and neither would ever run.
    #[test]
    fn update_entry_refuses_a_link_on_a_restack() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut r = entry("r");
        r.kind = EntryKind::Restack;
        r.lane = Lane::Urgent;
        seed_queue(&daemon, vec![project()], vec![r, entry("n")], None);

        let err = queue_update_entry(&daemon, serde_json::json!({ "id": "r", "after": ["n"] }))
            .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
        assert!(err.1.contains("restack"), "{err:?}");
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

    // ---- slice 003: queue_v2_enqueue_restack (the auto-detection path) ----

    fn rb(branch: &str, parent: &str, base: &str, onto: &str) -> RestackBranch {
        RestackBranch {
            branch: branch.into(),
            parent: parent.into(),
            base: base.into(),
            onto: onto.into(),
        }
    }

    fn enqueue_restack(
        daemon: &Daemon,
        project: &str,
        stack: Vec<RestackBranch>,
    ) -> Result<QueueV2EnqueueRestackReply, (ErrorKind, String)> {
        queue_v2_enqueue_restack(
            daemon,
            serde_json::json!({ "project": project, "stack": stack }),
        )
        .map(|v| serde_json::from_value(v).unwrap())
    }

    #[test]
    fn enqueue_restack_writes_one_urgent_row_and_the_full_doc() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        add_entry(&daemon, milestone_args("m1", "softfig", serde_json::json!({}))).unwrap();
        let before = commit_count(&daemon);

        let stack = vec![
            rb("feat/one", "", "abc123", "main"),
            rb("feat/two", "one", "def456", "feat/one"),
        ];
        let reply = enqueue_restack(&daemon, "softfig", stack).expect("enqueue");
        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit per enqueue");
        assert_eq!(reply.id.as_deref(), Some("001"));
        assert!(reply.path.as_deref().unwrap().ends_with("tasks/001-restack-softfig.md"));

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);

        // One urgent, branchless row, ahead of the normal milestone.
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let ids: Vec<&str> = qs.queue.model.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["001", "m1"], "the urgent restack precedes the normal milestone");
        let r = &qs.queue.model.entries[0];
        assert_eq!(r.kind, EntryKind::Restack);
        assert_eq!(r.lane, Lane::Urgent);
        assert_eq!(r.branch, "", "a restack has no branch of its own");
        assert_eq!(r.project, "softfig");

        // The full §8 template: stack, steps, gate.
        let doc = wt
            .read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc");
        assert!(doc.starts_with("# Restack softfig
"), "{doc}");
        assert!(doc.contains("## Stack"), "{doc}");
        assert!(doc.contains("- `feat/one` — parent: `main`, base: `abc123`"), "{doc}");
        assert!(doc.contains("- `feat/two` — parent: `one`, base: `def456`"), "{doc}");
        assert!(doc.contains("## Steps"), "{doc}");
        assert!(doc.contains("- `git rebase --onto main abc123 feat/one`"), "{doc}");
        assert!(doc.contains("- `git rebase --onto feat/one def456 feat/two`"), "{doc}");
        assert!(doc.contains("## Gate"), "{doc}");
        // V4: the gate comes from the project, not a hard-coded cargo command.
        assert!(doc.contains("the project's own `CLAUDE.md`"), "{doc}");
        assert!(!doc.contains("cargo test --workspace"), "{doc}");
        // V1: the upstream rule comes before the first rebase step.
        let rule = doc.find("## Before you rebase").expect("the upstream rule");
        assert!(rule < doc.find("## Steps").unwrap(), "{doc}");
        assert!(doc.contains("git for-each-ref --format='%(upstream)' refs/heads/<branch>"), "{doc}");
        assert!(doc.contains("`growlight_block`, `kind = human`"), "{doc}");
        assert_eq!(wt.read_to_string("growlight/backlog/tasks/.seq").unwrap(), "1
");
        drop(inner);
    }

    /// The V4 safety rules every restack doc carries, in the order a session
    /// meets them: before the first `git rebase --onto` step.
    fn assert_carries_the_safety_rules(doc: &str) {
        let protect = doc.find("## Protect the work").unwrap_or_else(|| panic!("{doc}"));
        for needle in [
            "git worktree list --porcelain",
            "--git-path \"$dir/head-name\"",
            "= refs/heads/<branch> ]",
            "rebase --abort",
            "git worktree add --detach <scratch> <branch>",
            "git worktree remove --force <scratch>",
            "git merge-base --is-ancestor <onto> <branch>",
            "$(git merge-base <base> <branch>)",
            "git -C <worktree> status --porcelain",
            "git branch restack-backup/<branch> <branch>",
            "`growlight_block`, `kind = human`",
        ] {
            assert!(doc[protect..].contains(needle), "missing {needle}\n{doc}");
        }
        if let Some(steps) = doc.find("## Steps") {
            assert!(protect < steps, "the safety rules precede the steps\n{doc}");
        }
    }

    #[test]
    fn the_restack_doc_protects_the_work_it_rewrites() {
        let doc = restack_doc("softfig", "2026-10-30", &[rb("feat/one", "", "abc123", "main")]);
        assert_carries_the_safety_rules(&doc);
        assert!(doc.contains("- `git rebase --onto main abc123 feat/one`"), "{doc}");
        // The placeholder form carries them too.
        assert_carries_the_safety_rules(&restack_doc("softfig", "2026-10-30", &[]));
    }

    #[test]
    fn a_stack_branch_without_a_recorded_base_renders_no_broken_step() {
        let doc = restack_doc(
            "softfig",
            "2026-10-30",
            &[rb("feat/one", "", "", "main"), rb("feat/two", "one", "def456", "feat/one")],
        );
        assert!(!doc.contains("--onto main  feat/one"), "{doc}");
        assert!(!doc.contains("git rebase --onto main"), "{doc}");
        assert!(
            doc.contains("- `feat/one`: no base is recorded for it, so do not guess one"),
            "{doc}"
        );
        assert!(doc.contains("- `git rebase --onto feat/one def456 feat/two`"), "{doc}");
    }

    #[test]
    fn a_human_enqueued_restack_renders_the_stack_from_list_state() {
        // No git here: keeperd holds the list, so a hand-enqueued restack (the
        // only kind a remote project gets) carries the full template, not a
        // stackless placeholder (V4).
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut one = entry("one");
        one.claimed = "2026-10-11T12:00:00Z".to_string();
        one.base = "main-tip".to_string();
        let mut two = entry("two");
        two.parent = "one".to_string();
        two.claimed = "2026-10-12T12:00:00Z".to_string();
        two.base = "feat/one".to_string(); // a remote base is the parent's branch name
        let unstarted = entry("three"); // never claimed: not in the stack
        seed_queue(&daemon, vec![project()], vec![two, one, unstarted], None);

        add_entry(&daemon, restack_args("softfig", serde_json::json!({}))).expect("restack");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt
            .read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc");
        assert!(!doc.contains("No stack was recorded"), "{doc}");
        let steps = [
            "- `git rebase --onto main main-tip feat/one`",
            "- `git rebase --onto feat/one feat/one feat/two`",
        ]
        .map(|s| doc.find(s).unwrap_or_else(|| panic!("missing {s}\n{doc}")));
        assert!(steps[0] < steps[1], "claim order, bottom first\n{doc}");
        assert!(doc.contains("- `feat/one` — parent: `main`, base: `main-tip`"), "{doc}");
        assert!(doc.contains("- `feat/two` — parent: `one`"), "{doc}");
        assert!(!doc.contains("feat/three"), "an unstarted entry is not in the stack\n{doc}");
        assert_carries_the_safety_rules(&doc);
    }

    #[test]
    fn list_state_stack_targets_an_archived_unmerged_parent_not_main() {
        // V7 on the list-state path: `done` archives the parent but the loop
        // never merges it, so the child must stay on the parent's branch.
        let mut parent = entry("a");
        parent.claimed = "2026-10-11T12:00:00Z".to_string();
        let mut child = entry("b");
        child.parent = "a".to_string();
        child.claimed = "2026-10-12T12:00:00Z".to_string();
        child.base = "a-tip".to_string();
        let archive = QueueArchiveToml::new(vec![ArchivedEntry {
            row: parent,
            finished: "2026-10-13T12:00:00Z".to_string(),
            final_status: FinalStatus::Done,
            reason: None,
        }]);
        let queue = QueueToml::new(vec![project()], vec![child]);
        let stack = stack_from_list(&queue, &archive, "softfig");
        assert_eq!(stack, vec![rb("feat/b", "a", "a-tip", "feat/a")]);
    }

    #[test]
    fn the_placeholder_restack_doc_also_carries_the_upstream_rule() {
        // A human/drop-enqueued restack has no resolved stack, yet the agent
        // still must not rewrite a pushed branch (V1).
        let doc = restack_doc("softfig", "2026-10-30", &[]);
        assert!(doc.contains("## Before you rebase"), "{doc}");
        assert!(doc.contains("git for-each-ref --format='%(upstream)'"), "{doc}");
        assert!(doc.contains("`growlight_block`, `kind = human`"), "{doc}");
    }

    #[test]
    fn enqueue_restack_is_idempotent_per_project() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");

        let stack = vec![rb("feat/one", "", "abc123", "main")];
        let first = enqueue_restack(&daemon, "softfig", stack.clone()).expect("first");
        assert_eq!(first.id.as_deref(), Some("001"));
        let after_first = commit_count(&daemon);

        // A second detection of the same stale stack is a no-op — the live
        // restack row already exists, so no second entry and no commit.
        let second = enqueue_restack(&daemon, "softfig", stack).expect("second");
        assert_eq!(second.id, None, "idempotent: no new entry");
        assert_eq!(second.path, None);
        assert_eq!(commit_count(&daemon), after_first, "no commit on the no-op");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        assert_eq!(qs.queue.model.entries.len(), 1, "still exactly one restack row");
        assert!(!wt.exists("growlight/backlog/tasks/002-restack-softfig.md"));
        drop(inner);
    }

    #[test]
    fn enqueue_restack_refuses_an_unknown_project() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        let before = commit_count(&daemon);

        let err = enqueue_restack(&daemon, "ghost", vec![rb("feat/one", "", "abc123", "main")])
            .unwrap_err();
        assert!(err.1.starts_with("unknown_project:"), "{err:?}");
        assert_eq!(commit_count(&daemon), before, "a refusal mints no commit");
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

    /// Finding 8 (§6.8, queue-v2-scheduling slice 009): a human status change
    /// on an ACTIVE entry is recorded as `pending_status` and the row stays
    /// `active` — the running session is never interrupted; its next handshake
    /// applies it. A later change overwrites the pending one, and the view
    /// shows it.
    #[test]
    fn update_entry_on_an_active_entry_records_a_pending_status() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut running = entry("r");
        running.status = EntryStatus::Active;
        running.claimed = "2026-10-14T00:00:00Z".into();
        seed_queue(&daemon, vec![project()], vec![running], None);

        let reply = update_entry(&daemon, serde_json::json!({ "id": "r", "status": "blocked" }))
            .expect("recorded");
        assert!(reply.view.contains("active (pending: blocked)"), "{}", reply.view);
        update_entry(&daemon, serde_json::json!({ "id": "r", "status": "deferred" }))
            .expect("overwritten");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let r = &qs.queue.model.entries[0];
        assert_eq!(r.status, EntryStatus::Active, "the running entry keeps active");
        assert_eq!(r.pending_status, Some(EntryStatus::Deferred), "the latest change is pending");
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
        a.base = "parent-commit".to_string();
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
        // The child is re-parented in the same write (V5): a had no parent,
        // so b is main-rooted now. Its base stays until the rewrite lands (F4).
        let b = qs.queue.model.entries.iter().find(|e| e.id == "b").unwrap();
        assert_eq!(b.parent, "");
        assert_eq!(b.base, "abc123");

        // The archive row: dropped, stamped, with the reason.
        assert_eq!(qs.archive.model.entries.len(), 1);
        let archived = &qs.archive.model.entries[0];
        assert_eq!(archived.row.id, "a");
        assert_eq!(archived.final_status, FinalStatus::Dropped);
        assert_eq!(archived.reason.as_deref(), Some("superseded by the rewrite"));
        assert!(!archived.finished.is_empty());
        assert!(wt.exists(QUEUE_ARCHIVE_FILE));

        // The restack doc landed through the shared tasks .seq, carrying the
        // §8 --onto rebase (queue-v2-git slice 004): the child moves off the
        // dropped branch onto its new parent, here the project's main.
        let doc = wt
            .read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc");
        assert!(doc.starts_with("# Restack softfig\n"), "{doc}");
        assert!(
            doc.contains("- `git rebase --onto main feat/a feat/b`"),
            "{doc}"
        );
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
    fn queue_drop_of_a_middle_entry_reparents_and_restacks_the_whole_subtree() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // A 4-deep stack r → m → g → h; m (the middle) is dropped. Hand-seeded
        // like the other stack tests: claims are not file state.
        let stamp = "2026-10-11T12:00:00Z".to_string();
        let mut r = entry("r");
        r.claimed = stamp.clone();
        r.base = "r-base".to_string();
        let mut m = entry("m");
        m.parent = "r".to_string();
        m.base = "m-base".to_string();
        m.claimed = stamp.clone();
        let mut g = entry("g");
        g.parent = "m".to_string();
        g.base = "g-base".to_string();
        g.claimed = stamp.clone();
        let mut h = entry("h");
        h.parent = "g".to_string();
        h.base = "h-base".to_string();
        h.claimed = stamp;
        seed_queue(&daemon, vec![project()], vec![r, m, g, h], None);

        drop_entry(&daemon, serde_json::json!({ "id": "m", "reason": "abandoned" }))
            .expect("drop");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        let row = |id: &str| qs.queue.model.entries.iter().find(|e| e.id == id).unwrap();
        // The direct child takes the dropped entry's parent, in the same write
        // that archives the row, and keeps its base until the rewrite lands ...
        assert_eq!(row("g").parent, "r");
        assert_eq!(row("g").base, "g-base");
        // ... and the grandchild keeps its own parent and recorded base.
        assert_eq!(row("h").parent, "g");
        assert_eq!(row("h").base, "h-base");

        // One restack covers the whole subtree, bottom first: g leaves the
        // abandoned commits, then h follows g's rebased tip (not main).
        let doc = wt
            .read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc");
        let steps = [
            "- `git rebase --onto feat/r feat/m feat/g`",
            "- `git rebase --onto feat/g h-base feat/h`",
        ]
        .map(|s| doc.find(s).unwrap_or_else(|| panic!("missing {s}\n{doc}")));
        assert!(steps[0] < steps[1], "parents rebase before their children\n{doc}");
        assert!(doc.contains("- `feat/g` — parent: `r`"), "{doc}");
        assert!(doc.contains("- `feat/h` — parent: `g`"), "{doc}");
    }

    #[test]
    fn queue_drop_dedupes_restacks_per_project() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // Two children of a in the same project: one restack covers the
        // repo's stack (§8).
        let mut a = entry("a");
        a.claimed = "2026-10-11T12:00:00Z".to_string();
        a.base = "parent-commit".to_string();
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
        // Both children's --onto steps ride the one restack doc, in list order.
        let doc = wt
            .read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc");
        assert!(
            doc.contains("- `git rebase --onto main feat/a feat/b`"),
            "{doc}"
        );
        assert!(
            doc.contains("- `git rebase --onto main feat/a feat/c`"),
            "{doc}"
        );
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

    // ---- review 055 F1: a restack doc, followed literally in a real repo ----

    /// A throwaway repo to follow a generated restack doc in.
    struct StackRepo {
        dir: tempfile::TempDir,
    }

    impl StackRepo {
        fn new() -> Self {
            let repo = StackRepo { dir: tempfile::tempdir().unwrap() };
            repo.git(&["init", "-q", "-b", "main"]);
            // The doc's own commands run through `sh`, in every worktree.
            repo.git(&["config", "user.name", "t"]);
            repo.git(&["config", "user.email", "t@t"]);
            repo.git(&["config", "commit.gpgsign", "false"]);
            repo.commit("root");
            repo
        }

        fn git(&self, args: &[&str]) -> String {
            let out = std::process::Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
                .args(args)
                .current_dir(self.dir.path())
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "git {args:?}: {stderr}");
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        }

        /// Whether a shell command the doc names succeeds here.
        fn sh(&self, command: &str) -> bool {
            std::process::Command::new("sh")
                .args(["-c", command])
                .current_dir(self.dir.path())
                .status()
                .unwrap()
                .success()
        }

        /// What a shell command the doc names prints here.
        fn sh_out(&self, command: &str) -> String {
            let out = std::process::Command::new("sh")
                .args(["-c", command])
                .current_dir(self.dir.path())
                .output()
                .unwrap();
            assert!(out.status.success(), "{command}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        }

        /// The worktree `branch` is checked out in, by `git worktree list`.
        fn holder(&self, branch: &str) -> Option<String> {
            let listing = self.git(&["worktree", "list", "--porcelain"]);
            let wanted = format!("branch refs/heads/{branch}");
            listing
                .split("\n\n")
                .find(|block| block.lines().any(|l| l == wanted))
                .and_then(|block| block.lines().next())
                .and_then(|l| l.strip_prefix("worktree "))
                .map(str::to_string)
        }

        /// A linked worktree on `branch`, stopped on a conflict partway through
        /// rebasing it. The conflicted file is `clash`.
        fn linked_mid_rebase(&self, branch: &str) -> tempfile::TempDir {
            let start = self.git(&["rev-parse", "HEAD"]);
            let onto = format!("{branch}-onto");
            for (name, body) in [(&onto, "theirs"), (&branch.to_string(), "mine")] {
                self.git(&["checkout", "-qb", name, &start]);
                std::fs::write(self.dir.path().join("clash"), body).unwrap();
                self.git(&["add", "clash"]);
                self.git(&["commit", "-qm", body]);
            }
            self.git(&["checkout", "-q", "--detach", &start]);
            let linked = tempfile::tempdir().unwrap();
            let path = linked.path().to_str().unwrap();
            self.git(&["worktree", "add", "-q", "--force", path, branch]);
            let rebase = format!("git -C {path} rebase -q {onto}");
            assert!(!self.sh(&rebase), "the rebase must stop on its conflict");
            assert!(is_mid_rebase(linked.path()), "{path}");
            linked
        }

        /// One new file on the checked-out branch, its name as the subject.
        fn commit(&self, name: &str) -> String {
            std::fs::write(self.dir.path().join(name), name).unwrap();
            self.git(&["add", name]);
            self.git(&["commit", "-qm", name]);
            self.git(&["rev-parse", "HEAD"])
        }

        fn tip(&self, branch: &str) -> String {
            self.git(&["rev-parse", branch])
        }

        /// `branch`'s commit subjects, oldest first.
        fn subjects(&self, branch: &str) -> Vec<String> {
            self.git(&["log", "--reverse", "--format=%s", branch])
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    /// Whether the worktree at `path` has a rebase in progress.
    fn is_mid_rebase(path: &std::path::Path) -> bool {
        let git_dir = std::process::Command::new("git")
            .args(["rev-parse", "--path-format=absolute", "--git-path", "rebase-merge"])
            .current_dir(path)
            .output()
            .unwrap();
        let git_dir = String::from_utf8(git_dir.stdout).unwrap();
        std::path::Path::new(git_dir.trim()).is_dir()
    }

    /// The fenced command block of `doc` that contains `needle`.
    fn doc_block(doc: &str, needle: &str) -> String {
        doc.split("```")
            .skip(1)
            .step_by(2)
            .find(|block| block.contains(needle))
            .unwrap_or_else(|| panic!("no block with {needle}\n{doc}"))
            .trim()
            .to_string()
    }

    /// The path the doc's `<scratch>` stands for in `repo`.
    fn scratch_of(repo: &StackRepo, doc: &str) -> String {
        let command = doc
            .split('`')
            .find(|span| span.contains("restack-scratch"))
            .unwrap_or_else(|| panic!("the doc names no scratch worktree\n{doc}"));
        repo.sh_out(command)
    }

    /// Step 1 of a doc, run the way a session does: its command for each branch
    /// of the stack, then the scratch worktree's removal if one is listed.
    fn resume_restack_doc(repo: &StackRepo, doc: &str) {
        let resume = doc_block(doc, "rebase --abort");
        for b in stack_of_doc(doc) {
            assert!(repo.sh(&resume.replace("<branch>", &b.branch)), "{doc}");
        }
        let scratch = scratch_of(repo, doc);
        let listed = format!("worktree {scratch}");
        if repo.git(&["worktree", "list", "--porcelain"]).lines().any(|l| l == listed) {
            assert!(doc.contains("`git worktree remove --force <scratch>`"), "{doc}");
            repo.git(&["worktree", "remove", "--force", &scratch]);
        }
    }

    /// Cut a stack in `repo` from `(id, parent id)` pairs, parents first: each
    /// gets `feat/<id>` with one commit named `<id>`, cut from its parent's tip
    /// (`main` for `""`). Returns the live rows, that tip recorded as `base`.
    fn cut_stack(repo: &StackRepo, stack: &[(&str, &str)]) -> Vec<Entry> {
        stack
            .iter()
            .map(|(id, parent)| {
                let mut row = entry(id);
                let from = if parent.is_empty() { "main".to_string() } else { format!("feat/{parent}") };
                row.parent = parent.to_string();
                row.base = repo.tip(&from);
                row.claimed = "2026-10-11T12:00:00Z".to_string();
                repo.git(&["checkout", "-qb", &row.branch, &from]);
                repo.commit(id);
                row
            })
            .collect()
    }

    /// The doc `queue_drop` writes when `id` is dropped from `entries`.
    fn drop_doc(entries: Vec<Entry>, id: &str) -> String {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queue(&daemon, vec![project()], entries, None);
        drop_entry(&daemon, serde_json::json!({ "id": id, "reason": "abandoned" })).expect("drop");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        wt.read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc")
    }

    /// Follow the first `limit` of a doc's `## Steps` the way a session does:
    /// resume first; right before each step, run the doc's own skip test on that
    /// step's operands; and run the step unless the test says it already
    /// happened, from the worktree that holds the branch or else through the
    /// doc's scratch worktree.
    fn follow_restack_doc(repo: &StackRepo, doc: &str, limit: usize) {
        resume_restack_doc(repo, doc);
        let rule = doc
            .lines()
            .find(|l| l.contains("skip its step"))
            .unwrap_or_else(|| panic!("no skip rule\n{doc}"));
        let tests: Vec<&str> = rule
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|span| span.starts_with("git merge-base"))
            .collect();
        assert!(!tests.is_empty(), "the skip rule names no test\n{doc}");
        let steps = &doc[doc.find("## Steps").expect("steps")..];
        let steps = steps.lines().filter_map(|l| l.strip_prefix("- `git rebase --onto "));
        for step in steps.take(limit) {
            let operands: Vec<&str> = step.trim_end_matches('`').split(' ').collect();
            let [onto, base, branch] = operands[..] else { panic!("bad step {step}\n{doc}") };
            let done = tests.iter().all(|test| {
                repo.sh(&test.replace("<onto>", onto).replace("<base>", base).replace("<branch>", branch))
            });
            if done {
                continue;
            }
            if let Some(holder) = repo.holder(branch) {
                repo.git(&["-C", &holder, "rebase", "-q", "--onto", onto, base, branch]);
                continue;
            }
            let scratch = scratch_of(repo, doc);
            let block = doc_block(doc, "git worktree add --detach <scratch> <branch>");
            let run = block
                .replace("<scratch>", &scratch)
                .replace("<onto>", onto)
                .replace("<base>", base)
                .replace("<branch>", branch)
                .replace('\n', " && ");
            assert!(repo.sh(&run), "{run}\n{doc}");
            assert!(doc.contains("`git worktree remove --force <scratch>`"), "{doc}");
            repo.git(&["worktree", "remove", "--force", &scratch]);
        }
    }

    #[test]
    fn following_a_drop_doc_takes_the_abandoned_commits_out_of_the_child() {
        // Never restacked: the child still contains its new parent's tip, which is
        // its `--onto` tip, and that must not read as "already done".
        let repo = StackRepo::new();
        let entries = cut_stack(&repo, &[("a", ""), ("b", "a"), ("c", "b")]);
        let doc = drop_doc(entries, "b");
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/c"), ["root", "a", "c"], "{doc}");
    }

    #[test]
    fn following_a_drop_doc_moves_the_whole_subtree() {
        let repo = StackRepo::new();
        let entries = cut_stack(&repo, &[("r", ""), ("m", "r"), ("g", "m"), ("h", "g")]);
        let doc = drop_doc(entries, "m");
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/g"), ["root", "r", "g"], "{doc}");
        assert_eq!(repo.subjects("feat/h"), ["root", "r", "g", "h"], "{doc}");
    }

    #[test]
    fn following_a_drop_doc_covers_a_dropped_branch_that_grew_after_the_cut() {
        // The child holds m but not m2, so it never contains the dropped tip:
        // "the dropped branch is not in it" would read as done here.
        let repo = StackRepo::new();
        let entries = cut_stack(&repo, &[("r", ""), ("m", "r"), ("g", "m")]);
        repo.git(&["checkout", "-q", "feat/m"]);
        repo.commit("m2");
        let doc = drop_doc(entries, "m");
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/g"), ["root", "r", "g"], "{doc}");
    }

    #[test]
    fn a_session_resuming_a_drop_doc_skips_only_the_finished_steps() {
        let repo = StackRepo::new();
        let entries = cut_stack(&repo, &[("r", ""), ("m", "r"), ("g", "m"), ("h", "g")]);
        let doc = drop_doc(entries, "m");

        // The first session dies after the child's step ...
        follow_restack_doc(&repo, &doc, 1);
        let child = repo.tip("feat/g");
        assert_eq!(repo.subjects("feat/h"), ["root", "r", "m", "g", "h"], "{doc}");

        // ... so the next skips that step and still moves the grandchild.
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.tip("feat/g"), child, "a finished step is not re-run\n{doc}");
        assert_eq!(repo.subjects("feat/h"), ["root", "r", "g", "h"], "{doc}");

        // A third pass finds nothing left to do.
        let grandchild = repo.tip("feat/h");
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.tip("feat/g"), child, "{doc}");
        assert_eq!(repo.tip("feat/h"), grandchild, "{doc}");
    }

    #[test]
    fn a_finished_step_of_a_plain_restack_is_skipped() {
        let repo = StackRepo::new();
        let entries = cut_stack(&repo, &[("a", ""), ("b", "a")]);
        repo.git(&["checkout", "-q", "feat/a"]);
        repo.git(&["commit", "-q", "--amend", "-m", "a2"]);
        let stack = [rb("feat/b", "a", &entries[1].base, "feat/a")];
        let doc = restack_doc("softfig", "2026-11-07", &stack);

        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/b"), ["root", "a2", "b"], "{doc}");
        let tip = repo.tip("feat/b");
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.tip("feat/b"), tip, "{doc}");
    }

    // ---- review 055 F5: the resume rule touches only this restack's branches ----

    #[test]
    fn resuming_a_restack_leaves_an_unrelated_rebase_alone() {
        let repo = StackRepo::new();
        let start = repo.tip("main");
        let theirs = repo.linked_mid_rebase("human");
        let resolution = theirs.path().join("clash");
        std::fs::write(&resolution, "half-resolved").unwrap();
        repo.git(&["branch", "feat/x", &start]);
        let doc = restack_doc("softfig", "2026-11-07", &[rb("feat/x", "", &start, "main")]);

        resume_restack_doc(&repo, &doc);

        assert!(is_mid_rebase(theirs.path()), "someone else's rebase was aborted\n{doc}");
        assert_eq!(std::fs::read_to_string(&resolution).unwrap(), "half-resolved");
    }

    #[test]
    fn resuming_a_restack_leaves_a_rebase_that_names_no_branch_alone() {
        let repo = StackRepo::new();
        let start = repo.tip("main");
        let theirs = repo.linked_mid_rebase("human");
        let path = theirs.path().to_str().unwrap();
        repo.git(&["-C", path, "rebase", "--abort"]);
        repo.git(&["-C", path, "checkout", "-q", "--detach", "human"]);
        assert!(!repo.sh(&format!("git -C {path} rebase -q human-onto")));
        assert!(is_mid_rebase(theirs.path()), "{path}");
        repo.git(&["branch", "feat/x", &start]);
        let doc = restack_doc("softfig", "2026-11-07", &[rb("feat/x", "", &start, "main")]);

        resume_restack_doc(&repo, &doc);

        assert!(is_mid_rebase(theirs.path()), "a detached rebase was aborted\n{doc}");
    }

    #[test]
    fn resuming_a_restack_aborts_a_rebase_of_its_own_branch() {
        let repo = StackRepo::new();
        let start = repo.tip("main");
        let dead = repo.linked_mid_rebase("feat/x");
        let tip = repo.tip("feat/x");
        let doc = restack_doc("softfig", "2026-11-07", &[rb("feat/x", "", &start, "main")]);

        resume_restack_doc(&repo, &doc);

        assert!(!is_mid_rebase(dead.path()), "{doc}");
        assert_eq!(repo.tip("feat/x"), tip, "back on its pre-rebase tip\n{doc}");
        assert!(repo.holder("feat/x").is_some(), "{doc}");
    }

    #[test]
    fn a_step_no_worktree_holds_leaves_the_branch_checked_out_nowhere() {
        let repo = StackRepo::new();
        let rows = cut_stack(&repo, &[("a", ""), ("b", "a")]);
        // A parked branch: its worktree is gone. The main worktree holds other
        // work, uncommitted, and the step must not disturb it.
        repo.git(&["checkout", "-q", "main"]);
        repo.commit("fix");
        std::fs::write(repo.dir.path().join("wip"), "uncommitted").unwrap();
        let stack = [
            rb("feat/a", "", &rows[0].base, "main"),
            rb("feat/b", "a", &rows[1].base, "feat/a"),
        ];
        let doc = restack_doc("softfig", "2026-11-07", &stack);

        follow_restack_doc(&repo, &doc, usize::MAX);

        assert_eq!(repo.subjects("feat/a"), ["root", "fix", "a"], "{doc}");
        assert_eq!(repo.subjects("feat/b"), ["root", "fix", "a", "b"], "{doc}");
        let listing = repo.git(&["worktree", "list", "--porcelain"]);
        assert!(!listing.contains("refs/heads/feat/"), "{listing}\n{doc}");
        assert_eq!(listing.matches("worktree ").count(), 1, "{listing}\n{doc}");
        assert_eq!(repo.git(&["rev-parse", "--abbrev-ref", "HEAD"]), "main", "{doc}");
        let wip = std::fs::read_to_string(repo.dir.path().join("wip")).unwrap();
        assert_eq!(wip, "uncommitted", "{doc}");
    }

    #[test]
    fn a_step_a_linked_worktree_holds_runs_there_and_stays_there() {
        let repo = StackRepo::new();
        let rows = cut_stack(&repo, &[("a", "")]);
        repo.git(&["checkout", "-q", "main"]);
        repo.commit("fix");
        let linked = tempfile::tempdir().unwrap();
        let path = linked.path().to_str().unwrap();
        repo.git(&["worktree", "add", "-q", "--force", path, "feat/a"]);
        let holder = repo.holder("feat/a").expect("held");
        let doc = restack_doc("softfig", "2026-11-07", &[rb("feat/a", "", &rows[0].base, "main")]);

        follow_restack_doc(&repo, &doc, usize::MAX);

        assert_eq!(repo.subjects("feat/a"), ["root", "fix", "a"], "{doc}");
        assert_eq!(repo.holder("feat/a"), Some(holder), "{doc}");
    }

    #[test]
    fn a_session_killed_in_the_scratch_worktree_leaves_nothing_behind() {
        let repo = StackRepo::new();
        let rows = cut_stack(&repo, &[("a", "")]);
        repo.git(&["checkout", "-q", "main"]);
        std::fs::write(repo.dir.path().join("a"), "clashes with a").unwrap();
        repo.git(&["add", "a"]);
        repo.git(&["commit", "-qm", "fix"]);
        let tip = repo.tip("feat/a");
        let doc = restack_doc("softfig", "2026-11-07", &[rb("feat/a", "", &rows[0].base, "main")]);

        // The first session stops on the conflict and dies there.
        let scratch = scratch_of(&repo, &doc);
        repo.git(&["worktree", "add", "-q", "--detach", &scratch, "feat/a"]);
        let rebase = format!("git -C {scratch} rebase -q --onto main {} feat/a", rows[0].base);
        assert!(!repo.sh(&rebase), "the rebase must stop on its conflict");

        resume_restack_doc(&repo, &doc);

        assert_eq!(repo.tip("feat/a"), tip, "{doc}");
        let listing = repo.git(&["worktree", "list", "--porcelain"]);
        assert!(!listing.contains("restack-scratch"), "{listing}\n{doc}");
        assert!(!listing.contains("refs/heads/feat/a"), "{listing}\n{doc}");
        assert!(!std::path::Path::new(&scratch).exists(), "{doc}");
    }

    // ---- review 055 F3: one restack row per project, whatever enqueued it ----

    fn restack_rows(daemon: &Daemon) -> Vec<Entry> {
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().unwrap();
        qs.queue.model.entries.into_iter().filter(|e| e.kind == EntryKind::Restack).collect()
    }

    /// The doc of the project's first restack, numbered `001`.
    fn first_restack_doc(daemon: &Daemon) -> String {
        let inner = daemon.inner.lock().unwrap();
        WorkTree::new(daemon, &inner)
            .read_to_string("growlight/backlog/tasks/001-restack-softfig.md")
            .expect("restack doc")
    }

    fn add_hand_restack(daemon: &Daemon) -> Result<QueueAddEntryReply, (ErrorKind, String)> {
        add_entry(daemon, serde_json::json!({ "kind": "restack", "project": "softfig" }))
    }

    fn step_count(doc: &str, branch: &str) -> usize {
        let tail = format!(" {branch}`");
        doc.lines().filter(|l| l.starts_with("- `git rebase") && l.ends_with(&tail)).count()
    }

    #[derive(Clone, Copy, Debug)]
    enum Enqueue {
        Drop(&'static str),
        Hand,
    }

    fn run_enqueue(daemon: &Daemon, how: Enqueue) {
        match how {
            Enqueue::Drop(id) => {
                drop_entry(daemon, serde_json::json!({ "id": id, "reason": "abandoned" }))
                    .map(|_| ())
                    .expect("drop");
            }
            Enqueue::Hand => {
                add_hand_restack(daemon).expect("hand restack");
            }
        }
    }

    #[test]
    fn two_drops_and_a_hand_restack_leave_one_row_in_any_order() {
        use Enqueue::{Drop, Hand};
        let orders = [
            [Drop("m"), Drop("n"), Hand],
            [Drop("m"), Hand, Drop("n")],
            [Drop("n"), Drop("m"), Hand],
            [Drop("n"), Hand, Drop("m")],
            [Hand, Drop("m"), Drop("n")],
            [Hand, Drop("n"), Drop("m")],
        ];
        for order in orders {
            let repo = StackRepo::new();
            let rows = cut_stack(&repo, &[("m", ""), ("c", "m"), ("n", ""), ("d", "n")]);
            let garden = tempfile::tempdir().unwrap();
            let daemon = unlocked(garden.path());
            seed_queue(&daemon, vec![project()], rows, None);
            for how in order {
                run_enqueue(&daemon, how);
            }

            let restacks = restack_rows(&daemon);
            assert_eq!(restacks.len(), 1, "{order:?}: {restacks:?}");
            let doc = first_restack_doc(&daemon);
            assert_eq!(step_count(&doc, "feat/c"), 1, "{order:?}\n{doc}");
            assert_eq!(step_count(&doc, "feat/d"), 1, "{order:?}\n{doc}");
            assert_eq!(step_count(&doc, "feat/m"), 0, "dropped work is not rebased\n{doc}");
            assert_eq!(step_count(&doc, "feat/n"), 0, "dropped work is not rebased\n{doc}");

            follow_restack_doc(&repo, &doc, usize::MAX);
            assert_eq!(repo.subjects("feat/c"), ["root", "c"], "{order:?}\n{doc}");
            assert_eq!(repo.subjects("feat/d"), ["root", "d"], "{order:?}\n{doc}");
        }
    }

    #[test]
    fn chained_drops_take_every_abandoned_commit_out_of_the_stack() {
        for order in [["a", "b"], ["b", "a"]] {
            let repo = StackRepo::new();
            let rows = cut_stack(&repo, &[("a", ""), ("b", "a"), ("c", "b"), ("d", "c")]);
            let garden = tempfile::tempdir().unwrap();
            let daemon = unlocked(garden.path());
            seed_queue(&daemon, vec![project()], rows, None);
            for id in order {
                run_enqueue(&daemon, Enqueue::Drop(id));
            }

            assert_eq!(restack_rows(&daemon).len(), 1, "{order:?}");
            let doc = first_restack_doc(&daemon);
            follow_restack_doc(&repo, &doc, usize::MAX);
            assert_eq!(repo.subjects("feat/c"), ["root", "c"], "{order:?}\n{doc}");
            assert_eq!(repo.subjects("feat/d"), ["root", "c", "d"], "{order:?}\n{doc}");
        }
    }

    #[test]
    fn a_drop_merged_into_a_half_run_restack_finishes_the_stack() {
        // A `queued` row can be a re-rolled session's: its first step already
        // ran when the second drop re-renders the doc.
        let repo = StackRepo::new();
        let rows = cut_stack(&repo, &[("m", ""), ("c", "m"), ("n", ""), ("d", "n")]);
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queue(&daemon, vec![project()], rows, None);
        run_enqueue(&daemon, Enqueue::Drop("m"));
        follow_restack_doc(&repo, &first_restack_doc(&daemon), 1);
        assert_eq!(repo.subjects("feat/c"), ["root", "c"]);

        run_enqueue(&daemon, Enqueue::Drop("n"));
        let doc = first_restack_doc(&daemon);
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/c"), ["root", "c"], "{doc}");
        assert_eq!(repo.subjects("feat/d"), ["root", "d"], "{doc}");
    }

    /// A project with `m <- c` and `n <- d`, and a live restack of `status`.
    fn beside_a_restack(garden: &std::path::Path, status: EntryStatus) -> Daemon {
        let daemon = unlocked(garden);
        let mut restack = entry("001");
        restack.kind = EntryKind::Restack;
        restack.lane = Lane::Urgent;
        restack.branch = String::new();
        restack.status = status;
        let mut c = entry("c");
        c.parent = "m".to_string();
        let mut m = entry("m");
        m.base = "m-base".to_string();
        seed_queue(&daemon, vec![project()], vec![restack, m, c], None);
        daemon
    }

    #[test]
    fn a_restack_a_session_holds_is_never_rewritten() {
        for status in [EntryStatus::Active, EntryStatus::Paused] {
            let garden = tempfile::tempdir().unwrap();
            let daemon = beside_a_restack(garden.path(), status);
            let before = commit_count(&daemon);

            // A drop's steps exist only in this write: it cannot land and leave
            // them out, so it is refused and the human drops again afterwards.
            let err = drop_entry(&daemon, serde_json::json!({ "id": "m", "reason": "x" }))
                .unwrap_err();
            assert!(err.1.starts_with("started: '001'"), "{status:?}: {err:?}");
            let err = add_hand_restack(&daemon).unwrap_err();
            assert!(err.1.starts_with("started: '001'"), "{status:?}: {err:?}");

            // Detection is level-triggered: it finds the stack again next scan.
            let reply = enqueue_restack(&daemon, "softfig", vec![rb("feat/c", "m", "b", "feat/m")])
                .expect("a no-op, not a refusal");
            assert_eq!(reply.id, None, "{status:?}");
            assert_eq!(commit_count(&daemon), before, "{status:?}: nothing landed");
            assert_eq!(restack_rows(&daemon).len(), 1, "{status:?}");
        }
    }

    #[test]
    fn a_blocked_or_deferred_restack_takes_the_merge() {
        // No session holds these: whoever picks the row up next reads the doc.
        for status in ["blocked", "deferred"] {
            let repo = StackRepo::new();
            let rows = cut_stack(&repo, &[("m", ""), ("c", "m"), ("n", ""), ("d", "n")]);
            let garden = tempfile::tempdir().unwrap();
            let daemon = unlocked(garden.path());
            seed_queue(&daemon, vec![project()], rows, None);
            run_enqueue(&daemon, Enqueue::Drop("m"));
            queue_update_entry(&daemon, serde_json::json!({ "id": "001", "status": status }))
                .expect("park the row");

            run_enqueue(&daemon, Enqueue::Drop("n"));
            let restacks = restack_rows(&daemon);
            assert_eq!(restacks.len(), 1, "{status}: {restacks:?}");
            assert_eq!(restacks[0].status.to_string(), status, "the merge keeps the status");
            let doc = first_restack_doc(&daemon);
            assert_eq!(step_count(&doc, "feat/c"), 1, "{doc}");
            assert_eq!(step_count(&doc, "feat/d"), 1, "{doc}");
        }
    }

    #[test]
    fn a_merge_keeps_the_sections_stamped_after_the_template() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut m = entry("m");
        m.base = "m-base".to_string();
        let mut c = entry("c");
        c.parent = "m".to_string();
        let mut n = entry("n");
        n.base = "n-base".to_string();
        let mut d = entry("d");
        d.parent = "n".to_string();
        seed_queue(&daemon, vec![project()], vec![m, c, n, d], None);
        run_enqueue(&daemon, Enqueue::Drop("m"));
        crate::actions::add_section(
            &daemon,
            serde_json::json!({
                "path": "growlight/backlog/tasks/001-restack-softfig.md",
                "heading": "Sessions",
                "body": "- 2026-11-07 stamped by keeperd",
            }),
        )
        .expect("stamp a session line");

        run_enqueue(&daemon, Enqueue::Drop("n"));
        let doc = first_restack_doc(&daemon);
        assert_eq!(step_count(&doc, "feat/d"), 1, "{doc}");
        assert!(doc.contains("## Sessions\n\n- 2026-11-07 stamped by keeperd"), "{doc}");
        assert_eq!(doc.matches("## Gate").count(), 1, "{doc}");
    }

    #[test]
    fn a_repeated_detection_commits_nothing_and_a_new_branch_merges() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        add_project(&daemon, "softfig", "~/p");
        let one = rb("feat/one", "", "abc123", "main");
        let two = rb("feat/two", "one", "def456", "feat/one");

        enqueue_restack(&daemon, "softfig", vec![one.clone()]).expect("enqueue");
        let before = commit_count(&daemon);
        let again = enqueue_restack(&daemon, "softfig", vec![one.clone()]).expect("again");
        assert_eq!(again.id, None, "every scan re-detects: no churn");
        assert_eq!(commit_count(&daemon), before);

        let merged = enqueue_restack(&daemon, "softfig", vec![one, two]).expect("merge");
        assert_eq!(merged.id.as_deref(), Some("001"), "the live row, not a sibling");
        assert_eq!(commit_count(&daemon), before + 1);
        assert_eq!(restack_rows(&daemon).len(), 1);
        let doc = first_restack_doc(&daemon);
        assert!(doc.contains("- `git rebase --onto main abc123 feat/one`"), "{doc}");
        assert!(doc.contains("- `git rebase --onto feat/one def456 feat/two`"), "{doc}");
    }

    #[test]
    fn a_hand_restack_with_nothing_new_returns_the_live_row() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut a = entry("a");
        a.base = "abc123".to_string();
        a.claimed = "2026-10-11T12:00:00Z".to_string();
        seed_queue(&daemon, vec![project()], vec![a], None);

        let first = add_hand_restack(&daemon).expect("first");
        let before = commit_count(&daemon);
        let second = add_hand_restack(&daemon).expect("second");
        assert_eq!(second.id, first.id);
        assert_eq!(second.path, first.path);
        assert_eq!(commit_count(&daemon), before, "nothing to write");
        assert_eq!(restack_rows(&daemon).len(), 1);
    }

    #[test]
    fn a_rendered_stack_reads_back_from_its_doc() {
        let stack = [
            rb("feat/one", "", "abc123", "main"),
            rb("feat/two", "one", "", "feat/one"),
            rb("feat/three", "two", "def456", "feat/two"),
        ];
        let doc = restack_doc("softfig", "2026-11-07", &stack);
        let read = stack_of_doc(&doc);
        assert_eq!(restack_doc("softfig", "2026-11-07", &read), doc);
        assert_eq!(read[2].onto, "feat/two");
        assert!(stack_of_doc(&restack_doc("softfig", "2026-11-07", &[])).is_empty());
    }

    #[test]
    fn a_merge_puts_a_new_parent_before_its_child() {
        let live = [rb("feat/c", "b", "c-base", "feat/b")];
        let new = [rb("feat/b", "", "b-base", "main")];
        let merged = merge_stacks(&live, &new, &QueueArchiveToml::new(vec![]));
        let order: Vec<&str> = merged.iter().map(|b| b.branch.as_str()).collect();
        assert_eq!(order, ["feat/b", "feat/c"]);
    }

    #[test]
    fn a_merge_into_a_row_with_no_doc_refuses_rather_than_lose_its_steps() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = beside_a_restack(garden.path(), EntryStatus::Queued);
        let before = commit_count(&daemon);
        let err = drop_entry(&daemon, serde_json::json!({ "id": "m", "reason": "x" })).unwrap_err();
        assert_eq!(err.0, ErrorKind::NotFound, "{err:?}");
        assert_eq!(commit_count(&daemon), before);
    }

    // ---- review 055 F4: a restack from list state, after a drop ----

    /// Drop `dropped` from `rows`, drop the restack row that made, and enqueue
    /// a restack by hand: the list is all that's left to render it from.
    fn hand_restack_with_the_drops_row_gone(rows: Vec<Entry>, dropped: &[&'static str]) -> String {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queue(&daemon, vec![project()], rows, None);
        for id in dropped {
            run_enqueue(&daemon, Enqueue::Drop(id));
        }
        drop_entry(&daemon, serde_json::json!({ "id": "001", "reason": "not now" }))
            .expect("drop the restack row");
        let path = add_hand_restack(&daemon).expect("hand restack").path;
        let inner = daemon.inner.lock().unwrap();
        WorkTree::new(&daemon, &inner).read_to_string(&path).expect("restack doc")
    }

    #[test]
    fn a_list_state_restack_after_a_drop_takes_the_dropped_commits_out() {
        let repo = StackRepo::new();
        let rows = cut_stack(&repo, &[("a", ""), ("b", "a"), ("c", "b")]);
        let doc = hand_restack_with_the_drops_row_gone(rows, &["b"]);
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/c"), ["root", "a", "c"], "{doc}");
    }

    #[test]
    fn a_list_state_restack_after_a_drop_does_not_replay_them_onto_a_moved_parent() {
        // The parent moved, so the step runs: its range is what must exclude b.
        let repo = StackRepo::new();
        let rows = cut_stack(&repo, &[("a", ""), ("b", "a"), ("c", "b")]);
        repo.git(&["checkout", "-q", "feat/a"]);
        repo.commit("a2");
        let doc = hand_restack_with_the_drops_row_gone(rows, &["b"]);
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/c"), ["root", "a", "a2", "c"], "{doc}");
    }

    #[test]
    fn a_list_state_restack_after_chained_drops_takes_every_dropped_commit_out() {
        for order in [["a", "b"], ["b", "a"]] {
            let repo = StackRepo::new();
            let rows = cut_stack(&repo, &[("a", ""), ("b", "a"), ("c", "b"), ("d", "c")]);
            let doc = hand_restack_with_the_drops_row_gone(rows, &order);
            follow_restack_doc(&repo, &doc, usize::MAX);
            assert_eq!(repo.subjects("feat/c"), ["root", "c"], "{order:?}\n{doc}");
            assert_eq!(repo.subjects("feat/d"), ["root", "c", "d"], "{order:?}\n{doc}");
        }
    }

    // ---- report 136: a drop's target doesn't come from the dropped base ----

    #[test]
    fn dropping_an_entry_with_no_base_still_moves_its_child() {
        let repo = StackRepo::new();
        let mut rows = cut_stack(&repo, &[("m", ""), ("g", "m")]);
        rows[0].base = String::new();
        let doc = drop_doc(rows, "m");
        assert!(!doc.contains("--onto  "), "{doc}");
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/g"), ["root", "g"], "{doc}");
    }

    #[test]
    fn a_drop_lands_the_child_on_its_new_parents_tip() {
        // The parent moved after the dropped entry was cut from it.
        let repo = StackRepo::new();
        let rows = cut_stack(&repo, &[("a", ""), ("b", "a"), ("c", "b")]);
        repo.git(&["checkout", "-q", "feat/a"]);
        repo.commit("a2");
        let doc = drop_doc(rows, "b");
        follow_restack_doc(&repo, &doc, usize::MAX);
        assert_eq!(repo.subjects("feat/c"), ["root", "a", "a2", "c"], "{doc}");
    }

    #[test]
    fn a_stack_with_no_onto_blocks_that_branch_and_a_later_stack_fills_it() {
        let stack = [rb("feat/g", "", "feat/m", "")];
        let doc = restack_doc("softfig", "2026-11-07", &stack);
        assert!(!doc.contains("--onto  "), "{doc}");
        assert!(doc.contains("- `feat/g`: nothing is recorded to rebase it onto"), "{doc}");

        let read = stack_of_doc(&doc);
        assert_eq!(read, [rb("feat/g", "main", "feat/m", "")], "{doc}");
        let new = [rb("feat/g", "", "g-base", "main")];
        let merged = merge_stacks(&read, &new, &QueueArchiveToml::new(vec![]));
        assert_eq!(merged, [rb("feat/g", "", "feat/m", "main")]);
    }
}
