//! growlight Phase 1 — the work-loop pillar's garden-write verbs.
//!
//! Four MCP verbs that maintain the `growlight/` pillar (spec-growlight.md
//! §10), all reusing the small-files machinery:
//!
//! - [`log_baton`] — append a numbered audit entry to `baton-log/`
//!   (mirrors `add_note`; numbered via [`super::numbering`]).
//! - [`add_backlog_item`] — seed a milestone dir or a numbered task doc and
//!   enqueue it (mirrors `add_project`).
//! - [`add_slice`] — append a numbered slice under a milestone + refresh its
//!   slices index (reuses [`super::index`]).
//! - [`set_item_status`] — flip one cell in the authoritative queue table
//!   (reuses [`super::managed`]).
//!
//! Like `add_project`, the verbs self-materialize the leaf structure they own
//! (folders, `.seq` seeds, the backlog routing doc) so they run before the
//! Phase-2 `softfig growlight init` scaffolder exists. Status + queue order
//! live only in the `queue` region of `growlight/backlog/CLAUDE.md`; item docs
//! never carry status (the locked Phase-1 schema pick).

mod chat;
mod init;
mod paths;
mod queue;

pub use init::growlight_init;

use softfig_vcs::Intent;
use softfig_ipc::verbs::{
    AddBacklogItemArgs, AddBacklogItemReply, AddSliceArgs, AddSliceReply, LogBatonArgs,
    LogBatonReply, ReorderBacklogItemArgs, ReorderBacklogItemReply, SetItemStatusArgs,
    SetItemStatusReply,
};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, managed, numbering, WorkTree};
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{require_unlocked, HandlerResult};
use crate::server::err_to_response;

fn non_empty(field: &str, value: &str) -> Result<(), (ErrorKind, String)> {
    if value.trim().is_empty() {
        Err((ErrorKind::BadArgs, format!("{field} must be non-empty")))
    } else {
        Ok(())
    }
}

// ---- log_baton ---------------------------------------------------------

pub fn log_baton(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: LogBatonArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("log_baton args: {e}")))?;
    non_empty("item", &args.item)?;
    non_empty("summary", &args.summary)?;
    if let Some(ref ty) = args.item_type {
        paths::validate_item_type(ty)?;
    }
    if let Some(ref status) = args.status {
        non_empty("status", status)?;
    }
    // The filename slug is either caller-supplied or derived from the cursor.
    let slug = match args.slug {
        Some(ref s) => {
            conventions::validate_slug(s)?;
            s.clone()
        }
        None => conventions::slugify(&format!("{}-iter-{}", args.item, args.iteration)),
    };

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let dir_rel = paths::baton_log_dir();
    let item_type = args.item_type.as_deref().unwrap_or("milestone");
    let content = paths::baton_entry_doc(
        &args.item,
        item_type,
        args.slice.as_deref(),
        args.iteration,
        args.status.as_deref(),
        args.ctx_pct,
        args.session_5h_pct,
        &conventions::today_hyphen(),
        &args.summary,
    );

    let (note_rel, number) = {
        let wt = WorkTree::new(daemon, &inner);
        let number = numbering::next_number(&wt, &dir_rel);
        let filename = conventions::note_filename(number, &slug);
        let note_rel = format!("{dir_rel}/{filename}");
        numbering::write_numbered(&wt, &dir_rel, number, &note_rel, &content)?;
        // No index, no backlinks: baton-log is append-only audit, never injected,
        // and excluded from the `[[…]]` graph so entries don't pollute item docs.
        (note_rel, number)
    };

    let payload = serde_json::json!({
        "item": args.item, "iteration": args.iteration, "slug": slug, "number": number,
    });
    let intent =
        Intent::new("baton_logged", payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(LogBatonReply { path: note_rel, hash: hash.to_string() }).unwrap())
}

// ---- add_backlog_item --------------------------------------------------

pub fn add_backlog_item(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddBacklogItemArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_backlog_item args: {e}")))?;
    paths::validate_item_type(&args.item_type)?;
    conventions::validate_slug(&args.slug)?;
    non_empty("title", &args.title)?;
    non_empty("mission", &args.mission)?;
    non_empty("finish_criteria", &args.finish_criteria)?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let date = conventions::today_hyphen();

    let (item_rel, queue_id) = {
        let wt = WorkTree::new(daemon, &inner);

        // Write the item's own doc(s) and compute the id it carries in the queue.
        let (item_rel, queue_id) = if args.item_type == "milestone" {
            let claude_rel = paths::milestone_claude(&args.slug);
            if wt.exists(&claude_rel) {
                return Err((
                    ErrorKind::PathAlreadyExists,
                    format!("{claude_rel}: milestone already exists"),
                ));
            }
            let content =
                paths::milestone_doc(&args.slug, &args.title, &args.mission, &args.finish_criteria);
            wt.write(&claude_rel, content.as_bytes())?;
            // Seed slices/.seq so the first add_slice counts from 001.
            let seq_rel = format!("{}/{}", paths::slices_dir(&args.slug), conventions::SEQ_FILE);
            wt.write(&seq_rel, b"0\n")?;
            (claude_rel, args.slug.clone())
        } else {
            let dir_rel = paths::tasks_dir();
            let number = numbering::next_number(&wt, &dir_rel);
            let filename = conventions::note_filename(number, &args.slug);
            let task_rel = format!("{dir_rel}/{filename}");
            let content = paths::task_doc(&args.title, &date, &args.mission, &args.finish_criteria);
            numbering::write_numbered(&wt, &dir_rel, number, &task_rel, &content)?;
            (task_rel, format!("{number:03}"))
        };

        // Enqueue (status `queued`), folded into the same commit.
        let row = queue::QueueRow {
            id: queue_id.clone(),
            item_type: args.item_type.clone(),
            title: args.title.clone(),
            status: "queued".into(),
        };
        enqueue(&wt, &inner, row)?;
        // Item bodies may carry `[[…]]` refs into the rest of the garden.
        super::backlinks::refresh_all(&wt, &inner);
        (item_rel, queue_id)
    };

    let payload = serde_json::json!({
        "id": queue_id, "item_type": args.item_type, "slug": args.slug,
    });
    let intent = Intent::new("backlog_item_added", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(AddBacklogItemReply {
        id: queue_id,
        path: item_rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- add_slice ---------------------------------------------------------

pub fn add_slice(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddSliceArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_slice args: {e}")))?;
    conventions::validate_slug(&args.milestone)?;
    conventions::validate_slug(&args.slug)?;
    non_empty("body", &args.body)?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let (note_rel, number) = {
        let wt = WorkTree::new(daemon, &inner);

        // The milestone must exist (its routing doc hosts the slices index).
        if !wt.exists(&paths::milestone_claude(&args.milestone)) {
            return Err((
                ErrorKind::NotFound,
                format!("milestone {:?}: no such backlog milestone", args.milestone),
            ));
        }

        let dir_rel = paths::slices_dir(&args.milestone);
        let number = numbering::next_number(&wt, &dir_rel);
        let filename = conventions::note_filename(number, &args.slug);
        let note_rel = format!("{dir_rel}/{filename}");

        let title = args.title.as_deref().unwrap_or(&args.slug);
        let content = conventions::note_doc(title, &conventions::today_hyphen(), &args.body);
        numbering::write_numbered(&wt, &dir_rel, number, &note_rel, &content)?;

        // Refresh the milestone's slices index (derived, like the notes index)
        // and recompute backlinks for any `[[…]]` the slice carries.
        super::index::refresh_folder_index(&wt, &inner, &dir_rel);
        super::backlinks::refresh_all(&wt, &inner);
        (note_rel, number)
    };

    let payload = serde_json::json!({
        "milestone": args.milestone, "slug": args.slug, "number": number,
    });
    let intent =
        Intent::new("slice_added", payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(AddSliceReply { path: note_rel, hash: hash.to_string() }).unwrap())
}

// ---- set_item_status ---------------------------------------------------

pub fn set_item_status(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: SetItemStatusArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("set_item_status args: {e}")))?;
    non_empty("id", &args.id)?;
    paths::validate_status(&args.status)?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let rel = paths::backlog_claude();
    {
        let wt = WorkTree::new(daemon, &inner);
        if !wt.exists(&rel) {
            return Err((ErrorKind::NotFound, format!("{rel}: no backlog yet")));
        }
        let content = super::sections::read_if_unprotected(&wt, &inner, &rel)
            .ok_or((ErrorKind::VaultProtected, format!("{rel}: unreadable or vault-protected")))?;
        let mut rows = managed::region_body(&content, paths::QUEUE_TAG)
            .map(|b| queue::parse(&b))
            .unwrap_or_default();

        let idx = rows
            .iter()
            .position(|r| r.id == args.id)
            .ok_or((ErrorKind::NotFound, format!("no backlog item with id {:?}", args.id)))?;

        // Idempotent re-set: no tree change, so return the current tip rather
        // than minting an empty commit.
        if rows[idx].status == args.status {
            let tip = inner
                .repo
                .as_ref()
                .expect("unlocked")
                .tip()
                .map_err(|e| err_to_response(e.into()))?
                .map(|h| h.to_string())
                .unwrap_or_default();
            return Ok(serde_json::to_value(SetItemStatusReply {
                id: args.id,
                status: args.status,
                path: rel,
                hash: tip,
            })
            .unwrap());
        }

        // Single-active invariant: only one item may be `active` at a time.
        if args.status == "active" {
            if let Some(other) = rows
                .iter()
                .enumerate()
                .find(|(i, r)| *i != idx && r.status == "active")
            {
                return Err((
                    ErrorKind::BadArgs,
                    format!(
                        "item {:?} is already active; set it done/blocked first",
                        other.1.id
                    ),
                ));
            }
        }
        rows[idx].status = args.status.clone();

        let new = managed::upsert(&content, paths::QUEUE_TAG, &queue::render(&rows));
        wt.write(&rel, new.as_bytes())?;
    }

    let payload = serde_json::json!({ "id": args.id, "status": args.status });
    let intent = Intent::new("item_status_set", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(SetItemStatusReply {
        id: args.id,
        status: args.status,
        path: rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- reorder_backlog_item ----------------------------------------------

pub fn reorder_backlog_item(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ReorderBacklogItemArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("reorder_backlog_item args: {e}")))?;
    non_empty("id", &args.id)?;
    let position = paths::parse_position(&args.position, args.ref_id.as_deref())?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let rel = paths::backlog_claude();
    let index = {
        let wt = WorkTree::new(daemon, &inner);
        if !wt.exists(&rel) {
            return Err((ErrorKind::NotFound, format!("{rel}: no backlog yet")));
        }
        let content = super::sections::read_if_unprotected(&wt, &inner, &rel)
            .ok_or((ErrorKind::VaultProtected, format!("{rel}: unreadable or vault-protected")))?;
        let rows = managed::region_body(&content, paths::QUEUE_TAG)
            .map(|b| queue::parse(&b))
            .unwrap_or_default();

        let from = rows
            .iter()
            .position(|r| r.id == args.id)
            .ok_or((ErrorKind::NotFound, format!("no backlog item with id {:?}", args.id)))?;

        let moved = queue::reordered(&rows, from, &position).map_err(reorder_err)?;
        let new_index = moved
            .iter()
            .position(|r| r.id == args.id)
            .expect("moved row is still present")
            + 1;

        // Idempotent: a move that doesn't change the order (e.g. to-top of the
        // already-top row) writes nothing and mints no commit — return the
        // current tip, exactly like set_item_status's no-op guard.
        if moved == rows {
            let tip = inner
                .repo
                .as_ref()
                .expect("unlocked")
                .tip()
                .map_err(|e| err_to_response(e.into()))?
                .map(|h| h.to_string())
                .unwrap_or_default();
            return Ok(serde_json::to_value(ReorderBacklogItemReply {
                id: args.id,
                index: new_index,
                path: rel,
                hash: tip,
            })
            .unwrap());
        }

        // Reorder is orthogonal to status: only the row order changes, every
        // status cell (and which single item is `active`) is preserved.
        let new = managed::upsert(&content, paths::QUEUE_TAG, &queue::render(&moved));
        wt.write(&rel, new.as_bytes())?;
        new_index
    };

    let payload = serde_json::json!({ "id": args.id, "index": index });
    let intent = Intent::new("backlog_item_reordered", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(ReorderBacklogItemReply {
        id: args.id,
        index,
        path: rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

/// Map a queue reorder failure onto an IPC error (a bad `before`/`after`
/// reference id).
fn reorder_err(e: queue::ReorderError) -> (ErrorKind, String) {
    match e {
        queue::ReorderError::RefNotFound(id) => (
            ErrorKind::NotFound,
            format!("no backlog item with id {id:?} to position relative to"),
        ),
        queue::ReorderError::RefIsSelf(id) => {
            (ErrorKind::BadArgs, format!("cannot move item {id:?} relative to itself"))
        }
    }
}

// ---- shared helpers ----------------------------------------------------

/// Read the backlog routing doc (seeding the stub if absent), append `row`
/// to the queue region — rejecting a duplicate id — and write it back so the
/// caller's in-flight commit folds it in.
fn enqueue(
    wt: &WorkTree,
    inner: &DaemonInner,
    row: queue::QueueRow,
) -> Result<(), (ErrorKind, String)> {
    let rel = paths::backlog_claude();
    let content = if wt.exists(&rel) {
        super::sections::read_if_unprotected(wt, inner, &rel)
            .ok_or((ErrorKind::VaultProtected, format!("{rel}: unreadable or vault-protected")))?
    } else {
        paths::backlog_claude_stub()
    };

    let mut rows = managed::region_body(&content, paths::QUEUE_TAG)
        .map(|b| queue::parse(&b))
        .unwrap_or_default();
    if rows.iter().any(|r| r.id == row.id) {
        return Err((
            ErrorKind::PathAlreadyExists,
            format!("backlog already has an item with id {:?}", row.id),
        ));
    }
    rows.push(row);
    let new = managed::upsert(&content, paths::QUEUE_TAG, &queue::render(&rows));
    wt.write(&rel, new.as_bytes())?;
    Ok(())
}
