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

// `pub(crate)` so the section-edit path (`actions::sections`) can post a
// thrash nudge through the same store as `post_message` (spec §4d).
pub(crate) mod chat;
mod init;
mod paths;
mod queue;
mod queues;

pub use init::growlight_init;

use softfig_vcs::Intent;
use softfig_ipc::verbs::{
    AddBacklogItemArgs, AddBacklogItemReply, AddQueueArgs, AddQueueReply, AddSliceArgs,
    AddSliceReply, ChatMessage, LogBatonArgs, LogBatonReply, PostMessageArgs, PostMessageReply,
    ReadInboxArgs, ReadInboxReply, ReorderBacklogItemArgs, ReorderBacklogItemReply,
    SetItemStatusArgs, SetItemStatusReply, TailBusArgs, TailBusReply,
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

// ---- coordination bus: post_message / read_inbox ----------------------

/// Append a message to the coordination bus. Mirrors `log_baton`: build the
/// numbered doc through the `WorkTree`, then `commit_now` one
/// `chat_message_posted` intent. The store ([`chat::append`]) validates the
/// sender, the direct-recipient slug, and a non-empty body; here we map the
/// wire `to`/`kind` strings to the store enums and reject an unknown `kind`.
pub fn post_message(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: PostMessageArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("post_message args: {e}")))?;
    let kind = chat::MessageKind::parse(&args.kind)
        .ok_or((ErrorKind::BadArgs, format!("post_message: unknown kind {:?}", args.kind)))?;
    let draft = chat::Draft {
        from: args.from,
        to: chat::Recipient::parse(&args.to),
        kind,
        body: args.body,
    };

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let ts = conventions::now_rfc3339();
    let (msg, note_rel) = {
        let wt = WorkTree::new(daemon, &inner);
        let msg = chat::append(&wt, &draft, &ts)?;
        let note_rel = chat::message_rel(msg.number, &draft);
        (msg, note_rel)
    };

    let payload = serde_json::json!({
        "number": msg.number, "from": msg.from, "to": msg.to.to_wire(), "kind": msg.kind.as_wire(),
    });
    let intent = Intent::new("chat_message_posted", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(PostMessageReply {
        number: msg.number,
        path: note_rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

/// Read an agent's unread bus inbox (its lane messages since its cursor) and
/// advance the cursor past them. The cursor write is the only mutation, and
/// only when the inbox is non-empty — `unread` returns lane messages numbered
/// strictly above the cursor, so a non-empty result always moves it. This
/// is the boot-inbox seam slice 003's SessionStart inject renders from. The
/// read-mints-a-commit fork is documented in the slice-001 Outcome; it is wired
/// here as decided, not redesigned.
pub fn read_inbox(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ReadInboxArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("read_inbox args: {e}")))?;
    conventions::validate_slug(&args.agent)?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let (messages, advanced_to) = {
        let wt = WorkTree::new(daemon, &inner);
        let unread = chat::unread(&wt, &args.agent);
        let advanced_to = unread.iter().map(|m| m.number).max();
        if let Some(n) = advanced_to {
            chat::advance_cursor(&wt, &args.agent, n)?;
        }
        let messages: Vec<ChatMessage> = unread.into_iter().map(to_wire_message).collect();
        (messages, advanced_to)
    };

    if let Some(n) = advanced_to {
        let payload = serde_json::json!({ "agent": args.agent, "through": n });
        let intent = Intent::new("inbox_read", payload)
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        commit_now(&mut inner, intent)?;
    }

    Ok(serde_json::to_value(ReadInboxReply { messages }).unwrap())
}

/// Tail the coordination bus for the orchestrator daemon (growlightd): every
/// message numbered above `since`, in total order — the WHOLE channel, not a
/// per-agent lane (so `@all`/`@human`/direct all surface; the groupchat shows
/// the human as a member). A pure read: no cursor advance, no commit (mirrors
/// `read_file`/`list_tree`). growlightd polls this over keeperd's socket and
/// republishes each as a `subscribe` `Event::BusMessage`; keeperd owns the
/// store, growlightd owns the stream (spec §2, two separate daemons).
pub fn tail_bus(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: TailBusArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("tail_bus args: {e}")))?;

    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let messages: Vec<ChatMessage> = {
        let wt = WorkTree::new(daemon, &inner);
        chat::all_messages(&wt)
            .into_iter()
            .filter(|m| m.number > args.since)
            .map(to_wire_message)
            .collect()
    };

    Ok(serde_json::to_value(TailBusReply { messages }).unwrap())
}

/// Project a stored bus [`chat::Message`] onto its wire [`ChatMessage`] form —
/// the single mapping shared by `read_inbox` (per-agent lane) and `tail_bus`
/// (the whole channel).
fn to_wire_message(m: chat::Message) -> ChatMessage {
    ChatMessage {
        number: m.number,
        from: m.from,
        to: m.to.to_wire(),
        kind: m.kind.as_wire().to_string(),
        body: m.body,
        ts: m.ts,
    }
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

    // The target work-stream queue (default unless named). A named queue must
    // already be registered (`add_queue`); the default queue is implicit.
    let queue = args.queue.as_deref().unwrap_or(queues::DEFAULT_QUEUE).to_string();
    let item_tag = queues::item_region_tag(&queue);

    let (item_rel, queue_id) = {
        let wt = WorkTree::new(daemon, &inner);

        if queue != queues::DEFAULT_QUEUE {
            let rel = paths::backlog_claude();
            let content = if wt.exists(&rel) {
                super::sections::read_if_unprotected(&wt, &inner, &rel).ok_or((
                    ErrorKind::VaultProtected,
                    format!("{rel}: unreadable or vault-protected"),
                ))?
            } else {
                paths::backlog_claude_stub()
            };
            if !queues::is_known(&registry_of(&content), &queue) {
                return Err((
                    ErrorKind::NotFound,
                    format!("no such queue {queue:?}; register it with add_queue first"),
                ));
            }
        }

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

        // Enqueue (status `queued`) into the target queue's region, folded into
        // the same commit.
        let row = queue::QueueRow {
            id: queue_id.clone(),
            item_type: args.item_type.clone(),
            title: args.title.clone(),
            status: "queued".into(),
        };
        enqueue(&wt, &inner, &item_tag, row)?;
        // Item bodies may carry `[[…]]` refs into the rest of the garden.
        super::backlinks::refresh_all(&wt, &inner);
        (item_rel, queue_id)
    };

    let payload = serde_json::json!({
        "id": queue_id, "item_type": args.item_type, "slug": args.slug, "queue": queue,
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

// ---- add_queue ---------------------------------------------------------

/// Register a named work-stream queue with a bound repo path (spec
/// orchestrator §6). Seeds the registry table (`queues` region) and an empty
/// per-queue item table (`queue:<name>` region under its own heading) in
/// `growlight/backlog/CLAUDE.md`, folded into one `queue_added` commit. The
/// implicit `default` queue is never registered here — it keeps the original
/// `queue` region, so a default-only garden is untouched until the first
/// `add_queue`.
pub fn add_queue(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddQueueArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_queue args: {e}")))?;
    queues::validate_queue_name(&args.name)?;
    non_empty("repo", &args.repo)?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let rel = paths::backlog_claude();
    {
        let wt = WorkTree::new(daemon, &inner);
        let content = if wt.exists(&rel) {
            super::sections::read_if_unprotected(&wt, &inner, &rel).ok_or((
                ErrorKind::VaultProtected,
                format!("{rel}: unreadable or vault-protected"),
            ))?
        } else {
            paths::backlog_claude_stub()
        };

        let mut registry = managed::region_body(&content, paths::QUEUES_TAG)
            .map(|b| queues::parse(&b))
            .unwrap_or_default();
        if registry.iter().any(|d| d.name == args.name) {
            return Err((
                ErrorKind::PathAlreadyExists,
                format!("queue {:?} is already registered", args.name),
            ));
        }
        registry.push(queues::QueueDef {
            name: args.name.clone(),
            repo: args.repo.clone(),
        });

        // Registry table, then the new queue's (empty) item table — each under
        // its own heading so a fresh region carries one even though
        // `managed::upsert` alone would append it heading-less.
        let content =
            upsert_section_region(&content, "Queues", paths::QUEUES_TAG, &queues::render(&registry));
        let item_tag = queues::item_region_tag(&args.name);
        let heading = format!("Queue: {}", args.name);
        let content = upsert_section_region(&content, &heading, &item_tag, &queue::render(&[]));
        wt.write(&rel, content.as_bytes())?;
    }

    let payload = serde_json::json!({ "name": args.name, "repo": args.repo });
    let intent =
        Intent::new("queue_added", payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(AddQueueReply {
        name: args.name,
        repo: args.repo,
        path: rel,
        hash: hash.to_string(),
    })
    .unwrap())
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
        let registry = registry_of(&content);
        let tag = resolve_item_region(&content, &registry, &args.id, args.queue.as_deref())?;
        let mut rows = managed::region_body(&content, &tag)
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

        // Single-active invariant, now *per queue*: only one item may be
        // `active` within a given queue at a time. Scoping it to the resolved
        // region is exactly what lets the fleet run one active part per queue
        // concurrently; a default-only garden keeps the old global behaviour.
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

        let new = managed::upsert(&content, &tag, &queue::render(&rows));
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
        let registry = registry_of(&content);
        let tag = resolve_item_region(&content, &registry, &args.id, args.queue.as_deref())?;
        let rows = managed::region_body(&content, &tag)
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
        // status cell (and which single item is `active`) is preserved. Scoped
        // to the resolved queue's region, so order is reprioritized per queue.
        let new = managed::upsert(&content, &tag, &queue::render(&moved));
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
/// to the queue item region tagged `tag` — rejecting a duplicate id within that
/// queue — and write it back so the caller's in-flight commit folds it in.
fn enqueue(
    wt: &WorkTree,
    inner: &DaemonInner,
    tag: &str,
    row: queue::QueueRow,
) -> Result<(), (ErrorKind, String)> {
    let rel = paths::backlog_claude();
    let content = if wt.exists(&rel) {
        super::sections::read_if_unprotected(wt, inner, &rel)
            .ok_or((ErrorKind::VaultProtected, format!("{rel}: unreadable or vault-protected")))?
    } else {
        paths::backlog_claude_stub()
    };

    let mut rows = managed::region_body(&content, tag)
        .map(|b| queue::parse(&b))
        .unwrap_or_default();
    if rows.iter().any(|r| r.id == row.id) {
        return Err((
            ErrorKind::PathAlreadyExists,
            format!("backlog already has an item with id {:?}", row.id),
        ));
    }
    rows.push(row);
    let new = managed::upsert(&content, tag, &queue::render(&rows));
    wt.write(&rel, new.as_bytes())?;
    Ok(())
}

/// Parse the queue registry out of the backlog doc (the `queues` region), empty
/// when none has been created yet (a default-only garden).
fn registry_of(content: &str) -> Vec<queues::QueueDef> {
    managed::region_body(content, paths::QUEUES_TAG)
        .map(|b| queues::parse(&b))
        .unwrap_or_default()
}

/// Every item-region `(queue_name, tag)` to search for an id: the implicit
/// `default` queue first, then each registered queue in registry order.
fn item_regions(registry: &[queues::QueueDef]) -> Vec<(String, String)> {
    let mut v = vec![(
        queues::DEFAULT_QUEUE.to_string(),
        queues::item_region_tag(queues::DEFAULT_QUEUE),
    )];
    for d in registry {
        v.push((d.name.clone(), queues::item_region_tag(&d.name)));
    }
    v
}

/// Resolve which queue's item region hosts `id`, returning its managed-region
/// tag. With an explicit `queue`, that queue must be known (the row's presence
/// is checked by the caller against the region). Without one, the id is located
/// across all queues: a unique hit resolves, zero is `NotFound`, and a
/// same-id-in-multiple-queues collision is a `BadArgs` "pass queue to
/// disambiguate" — so bare-id addressing keeps working while it stays
/// unambiguous (every real id is globally unique today: milestone dirs and the
/// task `.seq` guarantee it).
fn resolve_item_region(
    content: &str,
    registry: &[queues::QueueDef],
    id: &str,
    queue: Option<&str>,
) -> Result<String, (ErrorKind, String)> {
    if let Some(q) = queue {
        if !queues::is_known(registry, q) {
            return Err((ErrorKind::NotFound, format!("no such queue {q:?}")));
        }
        return Ok(queues::item_region_tag(q));
    }
    let mut hits: Vec<String> = item_regions(registry)
        .into_iter()
        .filter(|(_, tag)| {
            managed::region_body(content, tag)
                .map(|b| queue::parse(&b))
                .unwrap_or_default()
                .iter()
                .any(|r| r.id == id)
        })
        .map(|(name, _)| name)
        .collect();
    match hits.len() {
        0 => Err((ErrorKind::NotFound, format!("no backlog item with id {id:?}"))),
        1 => Ok(queues::item_region_tag(&hits.remove(0))),
        _ => Err((
            ErrorKind::BadArgs,
            format!("item id {id:?} exists in multiple queues ({}); pass queue to disambiguate", hits.join(", ")),
        )),
    }
}

/// Ensure a `## <heading>` section hosting managed region `tag` exists, then
/// upsert `body` into it. When the region is present we replace its body in
/// place (the heading is left untouched); when absent we append the heading +
/// region at end-of-doc, since `managed::upsert` alone would drop the heading.
fn upsert_section_region(content: &str, heading: &str, tag: &str, body: &str) -> String {
    if managed::has_region(content, tag) {
        managed::upsert(content, tag, body)
    } else {
        let core = content.trim_end_matches('\n');
        let mut s = String::from(core);
        if !s.is_empty() {
            s.push_str("\n\n");
        }
        s.push_str(&format!("## {heading}\n"));
        managed::upsert(&s, tag, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str) -> queue::QueueRow {
        queue::QueueRow {
            id: id.into(),
            item_type: "task".into(),
            title: id.into(),
            status: "queued".into(),
        }
    }

    /// A backlog doc whose default queue holds `default_ids` and whose named
    /// queue `name` (registered to `repo`) holds `named_ids` — built through the
    /// same region machinery the handlers use.
    fn doc_with(
        default_ids: &[&str],
        name: &str,
        repo: &str,
        named_ids: &[&str],
    ) -> (String, Vec<queues::QueueDef>) {
        let drows: Vec<_> = default_ids.iter().map(|i| row(i)).collect();
        let mut content =
            managed::upsert(&paths::backlog_claude_stub(), paths::QUEUE_TAG, &queue::render(&drows));
        let registry = vec![queues::QueueDef {
            name: name.into(),
            repo: repo.into(),
        }];
        content = upsert_section_region(
            &content,
            "Queues",
            paths::QUEUES_TAG,
            &queues::render(&registry),
        );
        let nrows: Vec<_> = named_ids.iter().map(|i| row(i)).collect();
        content = upsert_section_region(
            &content,
            &format!("Queue: {name}"),
            &queues::item_region_tag(name),
            &queue::render(&nrows),
        );
        (content, registry)
    }

    #[test]
    fn resolve_scopes_to_explicit_or_locates_unique() {
        let (content, registry) = doc_with(&["a"], "softfig", "~/p", &["b"]);
        // explicit queue → that queue's tag
        assert_eq!(
            resolve_item_region(&content, &registry, "b", Some("softfig")).unwrap(),
            "queue:softfig"
        );
        // omitted → located by unique id (back-compat bare-id addressing)
        assert_eq!(resolve_item_region(&content, &registry, "a", None).unwrap(), "queue");
        assert_eq!(
            resolve_item_region(&content, &registry, "b", None).unwrap(),
            "queue:softfig"
        );
    }

    #[test]
    fn resolve_rejects_unknown_queue_and_missing_id() {
        let (content, registry) = doc_with(&["a"], "softfig", "~/p", &["b"]);
        assert_eq!(
            resolve_item_region(&content, &registry, "a", Some("ghost")).unwrap_err().0,
            ErrorKind::NotFound
        );
        assert_eq!(
            resolve_item_region(&content, &registry, "zzz", None).unwrap_err().0,
            ErrorKind::NotFound
        );
    }

    #[test]
    fn resolve_flags_cross_queue_id_collision() {
        // The same id in two queues is ambiguous unless a queue is named.
        let (content, registry) = doc_with(&["dup"], "softfig", "~/p", &["dup"]);
        let err = resolve_item_region(&content, &registry, "dup", None).unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs);
        assert!(err.1.contains("multiple queues"), "{}", err.1);
        // Disambiguated either way.
        assert_eq!(
            resolve_item_region(&content, &registry, "dup", Some("default")).unwrap(),
            "queue"
        );
        assert_eq!(
            resolve_item_region(&content, &registry, "dup", Some("softfig")).unwrap(),
            "queue:softfig"
        );
    }

    #[test]
    fn upsert_section_region_adds_heading_once_then_replaces_in_place() {
        let base = "# backlog/\n\nlead\n";
        let once = upsert_section_region(base, "Queues", paths::QUEUES_TAG, "BODY1");
        assert!(once.contains("## Queues\n"), "{once}");
        assert!(once.contains("BODY1"));
        let twice = upsert_section_region(&once, "Queues", paths::QUEUES_TAG, "BODY2");
        assert_eq!(twice.matches("## Queues").count(), 1);
        assert!(twice.contains("BODY2") && !twice.contains("BODY1"));
    }
}
