//! The queue v2 §6.8 human verbs — `queue_add_project` and `queue_add_entry`
//! (milestone kind) — the first v2 writers end to end (milestone
//! `queue-v2-state`, slice 004).
//!
//! Each verb follows [`super::v2::write`]'s contract: load
//! ([`super::v2::state`]), mutate the in-memory models, validate (the
//! slice-002 [`QueueRefusal`] vocabulary), stage the entry's docs through
//! the worktree, then call [`apply`] once with every changed TOML file and
//! every view that must re-render — the whole-file CAS checks, the view
//! upserts, and exactly one commit land together; the verb never commits
//! itself. A `dry_run` stops before `apply`: everything is computed,
//! validated and rendered, nothing is committed, and the reply carries the
//! would-be queue view so the §6.9 CLI can print it.
//!
//! Refusals leave as wire errors whose message is the [`QueueRefusal`]
//! display — which leads with the wire code ([`QueueRefusal::code`]), the
//! stable prefix a client can branch on. Shape errors (an empty repo, an
//! unknown placement keyword, a kind this build does not implement yet) are
//! plain `BadArgs`.

use std::collections::HashSet;

use softfig_ipc::queue_v2::{
    Entry, EntryKind, EntryStatus, FinalStatus, Lane, Project, QueueRefusal, QueueToml, SliceItem,
    SliceKind, SliceStatus, SlicesToml,
};
use softfig_ipc::verbs::{
    QueueAddEntryArgs, QueueAddEntryReply, QueueAddProjectArgs, QueueAddProjectReply,
};
use softfig_ipc::ErrorKind;

use super::v2::{
    apply, load_queue_state, milestone_path, queue_view, queue_view_host, slices_file,
    slices_view, slices_view_host, FileWrite, ViewWrite, QUEUE_FILE, QUEUE_V2_TAG, SLICES_V2_TAG,
};
use super::{conventions, queue, WorkTree};
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

// ---- queue_add_entry (milestone kind) -----------------------------------

pub fn queue_add_entry(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueAddEntryArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_add_entry args: {e}")))?;
    if args.kind != EntryKind::Milestone {
        return Err((
            ErrorKind::BadArgs,
            format!(
                "queue_add_entry: kind {}: only milestone is implemented in this build (slice 004)",
                args.kind
            ),
        ));
    }
    if conventions::validate_slug(&args.slug).is_err() {
        return Err(refuse(QueueRefusal::BadName { name: args.slug.clone() }));
    }
    for (field, value) in [
        ("title", &args.title),
        ("mission", &args.mission),
        ("finish_criteria", &args.finish_criteria),
        ("project", &args.project),
    ] {
        if value.trim().is_empty() {
            return Err((ErrorKind::BadArgs, format!("{field} must be non-empty")));
        }
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
    let doc_rel = slices_view_host(&args.slug);
    let slices_dir = format!("{}/slices", milestone_path(&args.slug));

    let (mut queue, queue_version, archive) = {
        let wt = WorkTree::new(daemon, &inner);
        if wt.exists(&doc_rel) {
            return Err(refuse(QueueRefusal::Exists { id: args.slug.clone() }));
        }
        match load_queue_state(&wt, &inner) {
            Ok(Some(qs)) => {
                if !qs.queue.model.projects.iter().any(|p| p.name == args.project) {
                    return Err(refuse(QueueRefusal::UnknownProject {
                        project: args.project.clone(),
                    }));
                }
                (qs.queue.model, qs.queue.version, qs.archive.model)
            }
            Ok(None) => {
                // No v2 files yet: no projects, so every project is unknown.
                return Err(refuse(QueueRefusal::UnknownProject {
                    project: args.project.clone(),
                }));
            }
            Err(e) => return Err((ErrorKind::Internal, e.to_string())),
        }
    };

    // after-links resolve to a live entry or a done-archived row (§3.1
    // invariant 3; a dropped row satisfies no link). A cycle cannot form
    // here — the new entry is a source of edges only, nothing links to it
    // yet — so the final validate below is the backstop for it.
    let done: HashSet<&str> = archive
        .entries
        .iter()
        .filter(|a| a.final_status == FinalStatus::Done)
        .map(|a| a.row.id.as_str())
        .collect();
    for link in &args.after {
        if !queue.entries.iter().any(|e| &e.id == link) && !done.contains(link.as_str()) {
            return Err(refuse(QueueRefusal::UnknownId { id: link.clone() }));
        }
    }

    let added = conventions::now_rfc3339();
    let date = conventions::today_hyphen();

    // The slice set, numbered deterministically: the milestone dir was just
    // proven absent, so the first slice is 001 and `.seq` ends at the count.
    let (slice_docs, items, seq): (Vec<(String, String)>, Vec<SliceItem>, u32) =
        if args.slices.is_empty() {
            // §4: a milestone given no slices gets the generated planning
            // slice, so every milestone starts with a slice.
            (
                vec![(
                    format!("{slices_dir}/{}", conventions::note_filename(1, "plan")),
                    conventions::note_doc("Plan", &date, &plan_slice_body(&args.mission)),
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
    let slices_model = SlicesToml::new(args.slug.clone(), items);

    // The entry row, placed inside its lane (§6.8: `front | back | before |
    // after`, with `ref` for the last two; a `back` entry appends to its
    // lane's back, the §2 default).
    let entry = Entry {
        id: args.slug.clone(),
        kind: EntryKind::Milestone,
        title: args.title.clone(),
        project: args.project.clone(),
        lane,
        status: EntryStatus::Queued,
        after: args.after.clone(),
        added,
        branch: format!("feat/{}", args.slug),
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
            rel: slices_file(&args.slug),
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
            id: args.slug,
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
        wt.write(
            &doc_rel,
            milestone_doc_v2(&args.slug, &args.title, &args.mission, &args.finish_criteria)
                .as_bytes(),
        )?;
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
            "id": args.slug,
            "kind": "milestone",
            "project": args.project,
        }),
        &files,
        &views,
    )?;

    Ok(serde_json::to_value(QueueAddEntryReply {
        id: args.slug,
        path: doc_rel,
        view,
        hash: hash.to_string(),
    })
    .unwrap())
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
        // A non-milestone kind and an unknown position keyword are shape errors.
        let err = add_entry(&daemon, milestone_args("t", "softfig", serde_json::json!({ "kind": "task" })))
            .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs);
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
}
