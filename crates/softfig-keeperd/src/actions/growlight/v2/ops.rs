//! The queue v2 **daemon ops** — keeperd's write surface for growlightd's
//! handshake (spec §6.3 step 3), milestone `queue-v2-scheduling` slice 005.
//!
//! Six ops over the keeperd socket, keeperd↔growlightd only (never
//! agent-facing MCP verbs — growlightd calls them the way it calls the legacy
//! `set_item_status`, `crates/softfig-growlightd/src/claim.rs`'s pattern):
//!
//! - [`queue_v2_claim`] — the claim at assignment: entry `queued | paused →
//!   active` plus the unit slice `queued → active`, idempotent;
//! - [`queue_v2_set_status`] — the daemon-owned transitions (§6.8): entry
//!   `active → paused | blocked | deferred | queued | done` (`done` archives),
//!   slice `active → done | split | blocked | deferred | queued`;
//! - [`queue_v2_follow_ups`] — the §7 counter, written as an absolute value;
//! - [`queue_v2_session_log`] — the §3.5 line, appended to the unit doc's
//!   `## Sessions` (a milestone close-out's to its `sessions.md`);
//! - [`queue_v2_deferred`] — the §6.5/protocol §7b `## Deferred verification`
//!   section.
//! - [`queue_v2_add_sub`] (slice 010) — the §7 sub-milestone: its docs and
//!   `slices.toml`, the parent slice `split`, the placement — one commit.
//!
//! `queue_v2_set_status` also closes a `sub` item (slice 010): a sub is never
//! claimed (its slices are), so it closes from `queued` to `done | deferred`
//! once its own tree has nothing open.
//!
//! Each op follows the human verbs' discipline ([`super::queue_verbs`]):
//! load-validate fail-closed, mutate the in-memory models, then one
//! [`apply`] with the whole-file CAS tokens from the load, the views to
//! re-render, and exactly one commit naming the op. Refusals are typed:
//! [`QueueRefusal`] for state the file vocabulary describes (`unknown_id`,
//! `started`, …), `BadArgs` for wire-shape and from-status violations (a
//! daemon op talking to the wrong state is a protocol bug, not a file
//! invariant), and `ErrorKind::Internal` for a corrupt v2 file — the two
//! validation-only codes, mapped fail-closed exactly as the human verbs do.
//!
//! ## Addressing
//!
//! `entry` is the **milestone identity as the assignment carries it** — a
//! top-level id, or `"<parent>/<sub>"` for a sub-milestone (the
//! [`Unit::Slice::milestone`](softfig_ipc::queue_v2) shape). The
//! `queue.toml` row id is the identity's first path component
//! ([`row_id_of`]): a sub-milestone runs inside its top-level entry (§3.6),
//! so its status lives on the top-level row. `unit` is the `slices.toml`
//! item id — a slice `NNN`, or a sub-milestone slug for the sub's own
//! close-out — and is omitted for a task, a restack, or a close-out.
//!
//! ## Finding 8 — pending human status changes
//!
//! A human status change on an `active` entry takes effect at its session's
//! next handshake (§6.8), never mid-session. The mechanism this slice
//! designs (recorded in the slice doc): keeperd's human `queue_update_entry`
//! (slice 009) writes the requested status into the row's `pending_status`
//! field instead of applying it; the file keeps `active`, so the repo rule
//! and the scheduler keep working. At the boundary, growlightd's handshake
//! calls [`queue_v2_set_status`] and the op applies the **pending** status
//! instead of the requested one — the pending value wins over
//! `paused`/`deferred`/`queued`, is cleared in the same commit, and the
//! reply's `status` reports what actually landed. Two exceptions, where the
//! pending request dies instead: a `done` close-out archives the row (the
//! work is finished; parking it is moot), and a requested `blocked` lands
//! (the member's own stop on a question only the human can answer, which is
//! newer than the pending change — review R4). `pending_status` is not a
//! §3.1 invariant — it parses, and the boundary ops act on it only at the
//! `active → …` transition.

use softfig_ipc::queue_v2::{
    sub_depth, sub_doc_violation, ArchivedEntry, EntryKind, EntryStatus, FinalStatus,
    QueueRefusal, SliceItem, SliceKind, SliceStatus, SlicesToml, SubSliceText,
    QUEUE_ARCHIVE_FILE,
};
use std::collections::BTreeMap;

use softfig_ipc::backlog_doc::BACKLOG_DOC;
use softfig_ipc::queue_v2::migrate::{self, ApplyRefusal};
use softfig_ipc::verbs::{
    DaemonStatusArg, QueueV2AddSubArgs, QueueV2AddSubReply, QueueV2ClaimArgs, QueueV2ClaimReply,
    QueueV2DeferredArgs,
    QueueV2DeferredReply, QueueV2FollowUpsArgs, QueueV2FollowUpsReply,
    QueueV2MigrateApplyArgs, QueueV2MigrateApplyReply,
    QueueV2ReRecordBasesArgs, QueueV2ReRecordBasesReply, QueueV2SessionLogArgs,
    QueueV2SessionLogReply, QueueV2SetStatusArgs, QueueV2SetStatusReply,
};
use softfig_ipc::{ErrorKind, GARDEN_CONFIG_DIR, GROWLIGHT_CONFIG_FILE};
use softfig_fuse::SealedQuery;

use softfig_ipc::queue_v2::{milestone_doc, sessions_file};

use super::{
    apply, load_queue_state, load_slices, milestone_path, queue_view, queue_view_host, slices_file,
    slices_view, slices_view_host, ExtraWrites, FileWrite, ViewWrite, QUEUE_FILE, QUEUE_V2_TAG,
    SLICES_V2_TAG,
};
use crate::actions::growlight::paths;
use crate::actions::numbering;
use crate::actions::sections::{self, edit};
use crate::actions::{conventions, WorkTree};
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{require_unlocked, HandlerResult};
use crate::layer_b::LayerBHook;
use crate::server::err_to_response;

/// The `queue.toml` row id for an op's `entry` argument: the first path
/// component of a milestone identity (`"parent"` of `"parent/sub"`). A task's
/// or restack's NNN passes through unchanged.
fn row_id_of(entry: &str) -> &str {
    entry.split('/').next().unwrap_or(entry)
}

/// A §6.8 state refusal as a wire error (the same mapping as the human
/// verbs' `refuse`, duplicated here so the two writer modules stay
/// independent).
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

/// The untouched tip hash — a no-op write's reply `hash` (no commit minted).
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

/// The live v2 state addressed at an entry: the queue + archive models with
/// their whole-file CAS tokens, plus the entry's row index in the live list.
struct LoadedEntry {
    queue: softfig_ipc::queue_v2::QueueToml,
    queue_version: Option<String>,
    archive: softfig_ipc::queue_v2::QueueArchiveToml,
    archive_version: Option<String>,
    entry_idx: usize,
}

/// Load the live queue + the entry's row index, fail-closed. `entry` is the
/// op's argument; the row is addressed by its first path component
/// ([`row_id_of`]).
fn load_entry_row(
    wt: &WorkTree,
    inner: &DaemonInner,
    entry: &str,
) -> Result<LoadedEntry, (ErrorKind, String)> {
    let row_id = row_id_of(entry).to_string();
    let qs = match load_queue_state(wt, inner) {
        Ok(Some(qs)) => qs,
        Ok(None) => return Err(refuse(QueueRefusal::UnknownId { id: row_id })),
        Err(e) => return Err((ErrorKind::Internal, e.to_string())),
    };
    let idx = qs
        .queue
        .model
        .entries
        .iter()
        .position(|e| e.id == row_id)
        .ok_or_else(|| refuse(QueueRefusal::UnknownId { id: row_id }))?;
    Ok(LoadedEntry {
        queue: qs.queue.model,
        queue_version: qs.queue.version,
        archive: qs.archive.model,
        archive_version: qs.archive.version,
        entry_idx: idx,
    })
}

/// The unit doc's garden-relative path for `entry`/`unit` (the `## Deferred
/// verification` target, §6.5, and the `## Sessions` one, §3.5, for all but a
/// milestone close-out — see [`session_log_rel`]): a milestone's
/// `CLAUDE.md` for a close-out, its `slices/NNN-<slug>.md` for a unit (the
/// NNN resolves through the folder, since `slices.toml` carries no slug), a
/// task's or restack's `tasks/NNN-<slug>.md` otherwise.
pub(in crate::actions::growlight) fn unit_doc_rel(
    wt: &WorkTree,
    kind: EntryKind,
    entry: &str,
    unit: Option<&str>,
) -> Result<String, (ErrorKind, String)> {
    match kind {
        EntryKind::Milestone => match unit {
            None => Ok(milestone_doc(entry)),
            Some(id) => {
                let n: u32 = id.parse().map_err(|_| {
                    (
                        ErrorKind::BadArgs,
                        format!("unit must be the slice's NNN, got {id:?}"),
                    )
                })?;
                let dir = format!("{}/slices", milestone_path(entry));
                numbering::find_by_id(wt, &dir, n).ok_or_else(|| {
                    (
                        ErrorKind::NotFound,
                        format!("no slice doc numbered {id:?} in {dir}"),
                    )
                })
            }
        },
        EntryKind::Task | EntryKind::Restack => {
            if unit.is_some() {
                return Err((
                    ErrorKind::BadArgs,
                    format!("{kind} entries have no slices — omit the unit"),
                ));
            }
            let n: u32 = entry.parse().map_err(|_| {
                (
                    ErrorKind::BadArgs,
                    format!("a {kind} entry id must be its NNN, got {entry:?}"),
                )
            })?;
            numbering::find_by_id(wt, &paths::tasks_dir(), n).ok_or_else(|| {
                (
                    ErrorKind::NotFound,
                    format!("no {kind} doc numbered {entry:?} in {}", paths::tasks_dir()),
                )
            })
        }
    }
}

/// Where §3.5 puts the session line for `entry`/`unit`, and whether the op
/// may create that doc. A milestone close-out's line goes to the milestone's
/// `sessions.md` (live state stays out of `CLAUDE.md`, task 104), which its
/// first line creates — but only beside an existing milestone doc, so a
/// close-out for a milestone with no doc is refused, not given a directory.
/// Every other line goes to its [`unit_doc_rel`], which must exist.
fn session_log_rel(
    wt: &WorkTree,
    kind: EntryKind,
    entry: &str,
    unit: Option<&str>,
) -> Result<(String, bool), (ErrorKind, String)> {
    let rel = unit_doc_rel(wt, kind, entry, unit)?;
    match (kind, unit) {
        (EntryKind::Milestone, None) => match wt.exists(&rel) {
            true => Ok((sessions_file(entry), true)),
            false => Err((ErrorKind::NotFound, format!("{rel}: unit doc missing"))),
        },
        _ => Ok((rel, false)),
    }
}

/// What a milestone's `sessions.md` holds before its first line.
const SESSIONS_DOC_STUB: &str = "# Session log\n\n\
Written by keeperd when a session closes the milestone out (spec-growlight-queue §3.5).\n";

/// Read a unit doc as plaintext for a doc-level op, refusing (not skipping)
/// files that are sealed, vault-tagged or missing. Returns the content and
/// its whole-file CAS token.
fn load_unit_doc(
    wt: &WorkTree,
    inner: &DaemonInner,
    rel: &str,
) -> Result<(String, String), (ErrorKind, String)> {
    if !wt.exists(rel) {
        return Err((ErrorKind::NotFound, format!("{rel}: unit doc missing")));
    }
    let content = sections::read_if_unprotected(wt, inner, rel)
        .ok_or((ErrorKind::VaultProtected, format!("{rel}: unreadable or vault-protected")))?;
    let version = softfig_store::Hash::of(content.as_bytes()).to_hex();
    Ok((content, version))
}

/// The `queue_v2_set_status` level-vocabulary mapping: `paused | blocked |
/// deferred | queued` onto the entry statuses, `None` for `done` (the archive
/// path) and `split` (a slice word).
fn entry_status_of(new: DaemonStatusArg) -> Option<EntryStatus> {
    match new {
        DaemonStatusArg::Paused => Some(EntryStatus::Paused),
        DaemonStatusArg::Blocked => Some(EntryStatus::Blocked),
        DaemonStatusArg::Deferred => Some(EntryStatus::Deferred),
        DaemonStatusArg::Queued => Some(EntryStatus::Queued),
        DaemonStatusArg::Done | DaemonStatusArg::Split => None,
    }
}

/// The slice-level mapping: `done | split | blocked | deferred | queued`,
/// `None` for `paused` (an entry word).
fn slice_status_of(new: DaemonStatusArg) -> Option<SliceStatus> {
    match new {
        DaemonStatusArg::Done => Some(SliceStatus::Done),
        DaemonStatusArg::Split => Some(SliceStatus::Split),
        DaemonStatusArg::Blocked => Some(SliceStatus::Blocked),
        DaemonStatusArg::Deferred => Some(SliceStatus::Deferred),
        DaemonStatusArg::Queued => Some(SliceStatus::Queued),
        DaemonStatusArg::Paused => None,
    }
}

/// The §3.5 timestamp prefix: `YYYY-MM-DDTHH:MMZ` (the spec's example form —
/// minute precision), stamped by keeperd.
fn session_ts() -> String {
    conventions::now_rfc3339_minute()
}

// ---- queue_v2_claim ------------------------------------------------------

pub fn queue_v2_claim(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2ClaimArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_claim args: {e}")))?;
    if args.entry.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "entry must be non-empty".to_string()));
    }
    if let Some(u) = args.unit.as_deref()
        && u.trim().is_empty() {
            return Err((ErrorKind::BadArgs, "unit must be non-empty".to_string()));
        }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let loaded = {
        let wt = WorkTree::new(daemon, &inner);
        load_entry_row(&wt, &inner, &args.entry)?
    };
    let mut queue = loaded.queue;
    let queue_version = loaded.queue_version;
    let archive = loaded.archive;
    let eidx = loaded.entry_idx;
    let kind = queue.entries[eidx].kind;

    // Entry transition: `queued | paused → active` (§2: a paused entry is
    // resumable by any member — the slice doc's "queued → active" is the
    // first-claim case, the resume is the §2 case); `active` is an
    // idempotent re-claim; anything else is a protocol bug, refused loud.
    //
    // §8 first claim (queue-v2-git slice 002): a never-claimed entry records
    // the `parent`/`base` growlightd computed from the stack, and keeperd (the
    // writer) stamps `claimed` itself. A resume or a re-claim — `claimed`
    // already set — leaves all three untouched, so an already-recorded base is
    // never overwritten by a stale first-claim attempt.
    let first_claim = queue.entries[eidx].claimed.is_empty();
    let entry_changed = match queue.entries[eidx].status {
        EntryStatus::Queued | EntryStatus::Paused => {
            queue.entries[eidx].status = EntryStatus::Active;
            if first_claim {
                queue.entries[eidx].claimed = conventions::now_rfc3339();
                if let Some(parent) = args.parent.as_deref() {
                    queue.entries[eidx].parent = parent.to_string();
                }
                if let Some(base) = args.base.as_deref() {
                    queue.entries[eidx].base = base.to_string();
                }
                // A branch that pre-existed its claim is resumed work, not the
                // loop's to rewrite: hold it out of the automatic restack until a
                // human opts it in (review 061 F1, report 178).
                if args.existing {
                    queue.entries[eidx].auto_restack = false;
                }
            }
            true
        }
        EntryStatus::Active => false,
        s => {
            return Err((
                ErrorKind::BadArgs,
                format!(
                    "entry {:?} is {s}; the daemon claim requires queued, paused, \
                     or active (a re-claim)",
                    queue.entries[eidx].id
                ),
            ));
        }
    };

    // Unit transition: the slice `queued → active`; `active` is an idempotent
    // re-claim; another active item in the same tree is a double assignment,
    // refused `started`.
    let mut slice_changed = false;
    let mut slices: Option<(softfig_ipc::queue_v2::SlicesToml, Option<String>)> = None;
    if let Some(unit) = args.unit.as_deref() {
        if kind != EntryKind::Milestone {
            return Err((
                ErrorKind::BadArgs,
                format!("entry {:?} is a {kind}; only milestones have slices", args.entry),
            ));
        }
        let (mut model, version) = {
            let wt = WorkTree::new(daemon, &inner);
            match load_slices(&wt, &inner, &args.entry) {
                Ok(Some(l)) => (l.model, l.version),
                Ok(None) => {
                    return Err(refuse(QueueRefusal::UnknownId { id: args.entry.clone() }))
                }
                Err(e) => return Err((ErrorKind::Internal, e.to_string())),
            }
        };
        let sidx = model
            .items
            .iter()
            .position(|i| i.id == unit)
            .ok_or_else(|| refuse(QueueRefusal::UnknownId { id: unit.to_string() }))?;
        if let Some(other) = model
            .items
            .iter()
            .enumerate()
            .find(|(i, it)| *i != sidx && it.status == SliceStatus::Active)
        {
            return Err(refuse(QueueRefusal::Started { id: other.1.id.clone() }));
        }
        match model.items[sidx].status {
            SliceStatus::Queued => {
                model.items[sidx].status = SliceStatus::Active;
                slice_changed = true;
            }
            SliceStatus::Active => {}
            s => {
                return Err((
                    ErrorKind::BadArgs,
                    format!(
                        "slice {unit:?} is {s}; the daemon claim requires queued \
                         or active (a re-claim)"
                    ),
                ));
            }
        }
        if slice_changed {
            slices = Some((model, version));
        }
    }

    // Backstop: every §3.1 invariant still holds (the claim is what takes a
    // second entry in a repo `active` — invariant 5 refuses it here, and
    // invariant 6 refuses a restack beside any active entry in its repo).
    queue.validate(&archive).map_err(refuse)?;

    if !entry_changed && !slice_changed {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueV2ClaimReply {
            entry: args.entry.clone(),
            unit: args.unit.clone(),
            hash,
        })
        .unwrap());
    }

    let mut files = Vec::new();
    let mut views = Vec::new();
    if entry_changed {
        files.push(FileWrite {
            rel: QUEUE_FILE.to_string(),
            expected: queue_version,
            bytes: queue
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_bytes(),
        });
        views.push(ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(queue_view(&queue)),
        });
    }
    if let Some((model, version)) = &slices {
        files.push(FileWrite {
            rel: slices_file(&args.entry),
            expected: version.clone(),
            bytes: model
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_bytes(),
        });
        views.push(ViewWrite {
            host: slices_view_host(&args.entry),
            tag: SLICES_V2_TAG,
            body: Some(slices_view(model)),
        });
    }

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_claimed",
        serde_json::json!({ "entry": args.entry, "unit": args.unit }),
        &files,
        &views,
        &ExtraWrites::NONE,
    )?;

    Ok(serde_json::to_value(QueueV2ClaimReply {
        entry: args.entry,
        unit: args.unit,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- queue_v2_set_status ---------------------------------------------------

pub fn queue_v2_set_status(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2SetStatusArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_set_status args: {e}")))?;
    if args.entry.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "entry must be non-empty".to_string()));
    }
    if let Some(u) = args.unit.as_deref()
        && u.trim().is_empty() {
            return Err((ErrorKind::BadArgs, "unit must be non-empty".to_string()));
        }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    match args.unit.as_deref() {
        Some(unit) => {
            // ---- slice level: `active → done | split | blocked | deferred | queued`
            let (mut model, version) = {
                let wt = WorkTree::new(daemon, &inner);
                match load_slices(&wt, &inner, &args.entry) {
                    Ok(Some(l)) => (l.model, l.version),
                    Ok(None) => {
                        return Err(refuse(QueueRefusal::UnknownId { id: args.entry.clone() }))
                    }
                    Err(e) => return Err((ErrorKind::Internal, e.to_string())),
                }
            };
            let sidx = model
                .items
                .iter()
                .position(|i| i.id == unit)
                .ok_or_else(|| refuse(QueueRefusal::UnknownId { id: unit.to_string() }))?;
            let new = slice_status_of(args.new).ok_or_else(|| {
                (
                    ErrorKind::BadArgs,
                    format!("{:?} is an entry status, not a slice status", args.new),
                )
            })?;
            match model.items[sidx].kind {
                SliceKind::Slice => {
                    if model.items[sidx].status != SliceStatus::Active {
                        return Err((
                            ErrorKind::BadArgs,
                            format!(
                                "slice {unit:?} is {}; the daemon status write requires active",
                                model.items[sidx].status
                            ),
                        ));
                    }
                }
                SliceKind::Sub => {
                    let wt = WorkTree::new(daemon, &inner);
                    check_sub_close(&wt, &inner, &args.entry, unit, model.items[sidx].status, new)?;
                }
            }
            model.items[sidx].status = new;
            if new == SliceStatus::Done && model.items[sidx].kind == SliceKind::Slice {
                // §3.3: completion resets the counter — slice rows only.
                model.items[sidx].follow_ups = Some(0);
            }

            model.validate(&args.entry).map_err(refuse)?;

            let view = slices_view(&model);
            let hash = apply(
                daemon,
                &mut inner,
                "queue_v2_status_set",
                serde_json::json!({ "entry": args.entry, "unit": args.unit, "new": args.new }),
                &[FileWrite {
                    rel: slices_file(&args.entry),
                    expected: version,
                    bytes: model
                        .to_toml()
                        .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                        .into_bytes(),
                }],
                &[ViewWrite {
                    host: slices_view_host(&args.entry),
                    tag: SLICES_V2_TAG,
                    body: Some(view),
                }],
                &ExtraWrites::NONE,
            )?;

            Ok(serde_json::to_value(QueueV2SetStatusReply {
                entry: args.entry,
                unit: args.unit,
                status: new.to_string(),
                hash: hash.to_string(),
            })
            .unwrap())
        }
        None => {
            // ---- entry level: `active → paused | blocked | deferred | queued | done`
            let loaded = {
                let wt = WorkTree::new(daemon, &inner);
                load_entry_row(&wt, &inner, &args.entry)?
            };
            let mut queue = loaded.queue;
            let queue_version = loaded.queue_version;
            let mut archive = loaded.archive;
            let archive_version = loaded.archive_version;
            let eidx = loaded.entry_idx;
            let row_id = queue.entries[eidx].id.clone();
            if queue.entries[eidx].status != EntryStatus::Active {
                return Err((
                    ErrorKind::BadArgs,
                    format!(
                        "entry {row_id:?} is {}; the daemon status write requires active",
                        queue.entries[eidx].status
                    ),
                ));
            }

            if matches!(args.new, DaemonStatusArg::Split) {
                return Err((
                    ErrorKind::BadArgs,
                    format!("{:?} is a slice status, not an entry status", args.new),
                ));
            }
            let mut files = Vec::new();
            let effective: String;
            match args.new {
                // `done` is the §6.5 close-out: the row moves to the archive
                // (final_status done). A pending human change dies with the
                // row — the work is finished, parking it is moot.
                DaemonStatusArg::Done => {
                    let mut row = queue.entries.remove(eidx);
                    row.pending_status = None;
                    let re_record_due = row.kind == EntryKind::Restack;
                    archive.entries.push(ArchivedEntry {
                        row,
                        finished: conventions::now_rfc3339(),
                        final_status: FinalStatus::Done,
                        reason: None,
                        re_record_due,
                    });
                    effective = "done".to_string();
                    files.push(FileWrite {
                        rel: QUEUE_ARCHIVE_FILE.to_string(),
                        expected: archive_version,
                        bytes: archive
                            .to_toml()
                            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                            .into_bytes(),
                    });
                }
                other => {
                    // Finding 8: a pending human change wins over the
                    // requested status and is cleared here — except over
                    // `blocked`. growlightd asks for `blocked` only for the
                    // member's own stop (`growlight_block`, or an exit on a
                    // BLOCKED_ON_HUMAN baton): the session hit a question only
                    // the human can answer, and its alert is on the way. The
                    // pending change predates that question, and applying it
                    // could undo the stop (a `queued` makes the entry eligible
                    // again, to hit the same question). So the block lands and
                    // the pending change is dropped; the human answering the
                    // alert sets the status directly on the now-inactive
                    // entry (review R4).
                    let new = entry_status_of(other).expect("done/split handled above");
                    let pending = queue.entries[eidx].pending_status.take();
                    let pending_was = pending.is_some();
                    let applied = match pending {
                        Some(_) if new == EntryStatus::Blocked => new,
                        pending => pending.unwrap_or(new),
                    };
                    let changed = queue.entries[eidx].status != applied || pending_was;
                    queue.entries[eidx].status = applied;
                    effective = applied.to_string();
                    if !changed {
                        // A no-op (pending absent and the status already the
                        // target — unreachable under the from-status guard,
                        // but kept defensive like the human verbs').
                        let hash = current_tip(&inner)?;
                        return Ok(serde_json::to_value(QueueV2SetStatusReply {
                            entry: args.entry.clone(),
                            unit: args.unit.clone(),
                            status: effective,
                            hash,
                        })
                        .unwrap());
                    }
                }
            }
            // Backstop: every §3.1 invariant still holds.
            queue.validate(&archive).map_err(refuse)?;

            files.push(FileWrite {
                rel: QUEUE_FILE.to_string(),
                expected: queue_version,
                bytes: queue
                    .to_toml()
                    .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                    .into_bytes(),
            });

            let hash = apply(
                daemon,
                &mut inner,
                "queue_v2_status_set",
                serde_json::json!({ "entry": args.entry, "unit": args.unit, "new": args.new }),
                &files,
                &[ViewWrite {
                    host: queue_view_host(),
                    tag: QUEUE_V2_TAG,
                    body: Some(queue_view(&queue)),
                }],
                &ExtraWrites::NONE,
            )?;

            Ok(serde_json::to_value(QueueV2SetStatusReply {
                entry: args.entry,
                unit: args.unit,
                status: effective,
                hash: hash.to_string(),
            })
            .unwrap())
        }
    }
}

/// The daemon write that closes a `sub` item (slice 010): its close-out
/// completed (§6.5 on a sub-milestone). A sub item is never claimed — its
/// slices are — so it sits `queued` while they run (`active` is accepted too);
/// it closes to `done` or `deferred` only, and only once its own tree holds
/// nothing open (every item `done`, `split` or `deferred`): the backstop for
/// §6.5's `open_items`, so no caller can close a sub over unfinished work.
fn check_sub_close(
    wt: &WorkTree,
    inner: &DaemonInner,
    parent: &str,
    sub: &str,
    from: SliceStatus,
    to: SliceStatus,
) -> Result<(), (ErrorKind, String)> {
    if !matches!(to, SliceStatus::Done | SliceStatus::Deferred) {
        return Err((
            ErrorKind::BadArgs,
            format!("sub-milestone {sub:?} closes to done or deferred only, not {to}"),
        ));
    }
    if !matches!(from, SliceStatus::Queued | SliceStatus::Active) {
        return Err((
            ErrorKind::BadArgs,
            format!("sub-milestone {sub:?} is {from}; only an open sub closes"),
        ));
    }
    let identity = format!("{parent}/{sub}");
    let tree = match load_slices(wt, inner, &identity) {
        Ok(Some(l)) => l.model,
        Ok(None) => return Err(refuse(QueueRefusal::UnknownId { id: identity })),
        Err(e) => return Err((ErrorKind::Internal, e.to_string())),
    };
    let open: Vec<&str> = tree
        .items
        .iter()
        .filter(|i| !matches!(i.status, SliceStatus::Done | SliceStatus::Split | SliceStatus::Deferred))
        .map(|i| i.id.as_str())
        .collect();
    if !open.is_empty() {
        return Err((
            ErrorKind::BadArgs,
            format!("open_items: sub-milestone {identity} still has open items: {}", open.join(", ")),
        ));
    }
    Ok(())
}

// ---- queue_v2_follow_ups ----------------------------------------------------

pub fn queue_v2_follow_ups(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2FollowUpsArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_follow_ups args: {e}")))?;
    if args.entry.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "entry must be non-empty".to_string()));
    }
    if let Some(u) = args.unit.as_deref()
        && u.trim().is_empty() {
            return Err((ErrorKind::BadArgs, "unit must be non-empty".to_string()));
        }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    match args.unit.as_deref() {
        Some(unit) => {
            // A slice item's counter — slice rows only (§3.3).
            let (mut model, version) = {
                let wt = WorkTree::new(daemon, &inner);
                match load_slices(&wt, &inner, &args.entry) {
                    Ok(Some(l)) => (l.model, l.version),
                    Ok(None) => {
                        return Err(refuse(QueueRefusal::UnknownId { id: args.entry.clone() }))
                    }
                    Err(e) => return Err((ErrorKind::Internal, e.to_string())),
                }
            };
            let sidx = model
                .items
                .iter()
                .position(|i| i.id == unit)
                .ok_or_else(|| refuse(QueueRefusal::UnknownId { id: unit.to_string() }))?;
            if model.items[sidx].kind != SliceKind::Slice {
                return Err((
                    ErrorKind::BadArgs,
                    format!("follow_ups is slice-only (§3.3); {unit:?} is a sub"),
                ));
            }
            if model.items[sidx].follow_ups == Some(args.count) {
                let hash = current_tip(&inner)?;
                return Ok(serde_json::to_value(QueueV2FollowUpsReply {
                    entry: args.entry.clone(),
                    unit: args.unit.clone(),
                    hash,
                })
                .unwrap());
            }
            model.items[sidx].follow_ups = Some(args.count);
            model.validate(&args.entry).map_err(refuse)?;

            let hash = apply(
                daemon,
                &mut inner,
                "queue_v2_follow_ups_set",
                serde_json::json!({ "entry": args.entry, "unit": args.unit, "count": args.count }),
                &[FileWrite {
                    rel: slices_file(&args.entry),
                    expected: version,
                    bytes: model
                        .to_toml()
                        .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                        .into_bytes(),
                }],
                &[ViewWrite {
                    host: slices_view_host(&args.entry),
                    tag: SLICES_V2_TAG,
                    body: Some(slices_view(&model)),
                }],
                &ExtraWrites::NONE,
            )?;

            Ok(serde_json::to_value(QueueV2FollowUpsReply {
                entry: args.entry,
                unit: args.unit,
                hash: hash.to_string(),
            })
            .unwrap())
        }
        None => {
            // The entry's own counter — task, restack, or a close-out (§7).
            let loaded = {
                let wt = WorkTree::new(daemon, &inner);
                load_entry_row(&wt, &inner, &args.entry)?
            };
            let mut queue = loaded.queue;
            let queue_version = loaded.queue_version;
            let archive = loaded.archive;
            let eidx = loaded.entry_idx;
            if queue.entries[eidx].follow_ups == args.count {
                let hash = current_tip(&inner)?;
                return Ok(serde_json::to_value(QueueV2FollowUpsReply {
                    entry: args.entry.clone(),
                    unit: args.unit.clone(),
                    hash,
                })
                .unwrap());
            }
            queue.entries[eidx].follow_ups = args.count;
            queue.validate(&archive).map_err(refuse)?;

            let hash = apply(
                daemon,
                &mut inner,
                "queue_v2_follow_ups_set",
                serde_json::json!({ "entry": args.entry, "unit": args.unit, "count": args.count }),
                &[FileWrite {
                    rel: QUEUE_FILE.to_string(),
                    expected: queue_version,
                    bytes: queue
                        .to_toml()
                        .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                        .into_bytes(),
                }],
                &[ViewWrite {
                    host: queue_view_host(),
                    tag: QUEUE_V2_TAG,
                    body: Some(queue_view(&queue)),
                }],
                &ExtraWrites::NONE,
            )?;

            Ok(serde_json::to_value(QueueV2FollowUpsReply {
                entry: args.entry,
                unit: args.unit,
                hash: hash.to_string(),
            })
            .unwrap())
        }
    }
}

// ---- queue_v2_session_log -----------------------------------------------------

pub fn queue_v2_session_log(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2SessionLogArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_session_log args: {e}")))?;
    if args.entry.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "entry must be non-empty".to_string()));
    }
    if args.line.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "line must be non-empty".to_string()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let (rel, content, version) = {
        let wt = WorkTree::new(daemon, &inner);
        let loaded = load_entry_row(&wt, &inner, &args.entry)?;
        let kind = loaded.queue.entries[loaded.entry_idx].kind;
        let (rel, creatable) = session_log_rel(&wt, kind, &args.entry, args.unit.as_deref())?;
        // A close-out's `sessions.md` is made by its first line: `None` is the
        // first-creation CAS token.
        let (content, version) = match creatable && !wt.exists(&rel) {
            true => (SESSIONS_DOC_STUB.to_string(), None),
            false => load_unit_doc(&wt, &inner, &rel).map(|(c, v)| (c, Some(v)))?,
        };
        (rel, content, version)
    };

    // §3.5: `- <utc> · <reason|…> · <model ref> · member <id> · $cost` —
    // keeperd stamps the timestamp prefix; the caller supplies the tail.
    let stamped = format!("- {} · {}", session_ts(), args.line.trim());
    let new = match edit::append_to_section(&content, "## Sessions", &stamped) {
        Ok(n) => n,
        Err(edit::SectionError::NotFound) => edit::add_section(&content, "## Sessions", &stamped)
            .map_err(|e| sections::section_err(&rel, "Sessions", e))?,
        Err(e) => return Err(sections::section_err(&rel, "Sessions", e)),
    };

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_session_logged",
        serde_json::json!({ "entry": args.entry, "unit": args.unit }),
        &[FileWrite {
            rel: rel.clone(),
            expected: version,
            bytes: new.into_bytes(),
        }],
        &[],
        &ExtraWrites::NONE,
    )?;

    Ok(serde_json::to_value(QueueV2SessionLogReply {
        entry: args.entry,
        unit: args.unit,
        path: rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- queue_v2_deferred ----------------------------------------------------------

pub fn queue_v2_deferred(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2DeferredArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_deferred args: {e}")))?;
    if args.entry.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "entry must be non-empty".to_string()));
    }
    if args.tests.is_empty() {
        return Err((ErrorKind::BadArgs, "tests must not be empty".to_string()));
    }
    for t in &args.tests {
        if t.what.trim().is_empty() || t.expected.trim().is_empty() {
            return Err((
                ErrorKind::BadArgs,
                "each deferred test needs a non-empty what and expected".to_string(),
            ));
        }
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let (rel, content, version) = {
        let wt = WorkTree::new(daemon, &inner);
        let loaded = load_entry_row(&wt, &inner, &args.entry)?;
        let kind = loaded.queue.entries[loaded.entry_idx].kind;
        let rel = unit_doc_rel(&wt, kind, &args.entry, None)?;
        let (content, version) = load_unit_doc(&wt, &inner, &rel)?;
        (rel, content, version)
    };

    // §6.5/protocol §7b: what to run + the expected result, one bullet each.
    let mut body = String::new();
    for t in &args.tests {
        body.push_str(&format!("- {} — expected: {}\n", t.what.trim(), t.expected.trim()));
    }
    let body = body.trim_end().to_string();

    // Replace the section in place when it exists (a re-roll after an earlier
    // deferred write overwrites, not duplicates); create it otherwise.
    let new = match edit::edit_section(&content, "## Deferred verification", &body) {
        Ok(n) => n,
        Err(edit::SectionError::NotFound) => {
            edit::add_section(&content, "## Deferred verification", &body)
                .map_err(|e| sections::section_err(&rel, "Deferred verification", e))?
        }
        Err(e) => return Err(sections::section_err(&rel, "Deferred verification", e)),
    };

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_deferred_set",
        serde_json::json!({ "entry": args.entry, "tests": args.tests.len() }),
        &[FileWrite {
            rel: rel.clone(),
            expected: Some(version),
            bytes: new.into_bytes(),
        }],
        &[],
        &ExtraWrites::NONE,
    )?;

    Ok(serde_json::to_value(QueueV2DeferredReply {
        entry: args.entry,
        path: rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

// ---- queue_v2_add_sub ------------------------------------------------------

/// A sub-milestone's `CLAUDE.md`, written from the member's structured fields
/// (§6.7: keeperd writes it; the member never authors the file). It declares
/// no `> Model:`, so the sub's slices inherit the parent's chain (§6.4).
fn sub_doc(identity: &str, parent: &str, slice: &str, title: &str, mission: &str, finish: &str) -> String {
    format!(
        "# backlog: {title}\n\n\
         > Sub-milestone `{identity}`, filed from slice {slice} of `{parent}` when its work \
         outgrew it (spec-growlight-queue §7). It runs inside its top-level entry and \
         shares that entry's baton; its status is its item in `{parent}`'s `slices.toml`, \
         its slices run in the order of the derived table in `slices.md`, and it is done \
         when its close-out completes.\n\n\
         ## Mission\n\n{}\n\n\
         ## Finish criteria\n\n{}\n",
        mission.trim_end_matches('\n'),
        finish.trim_end_matches('\n'),
    )
}

pub fn queue_v2_add_sub(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2AddSubArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_add_sub args: {e}")))?;
    for (field, value) in [
        ("milestone", &args.milestone),
        ("slice", &args.slice),
        ("title", &args.title),
        ("mission", &args.mission),
        ("finish_criteria", &args.finish_criteria),
    ] {
        if value.trim().is_empty() {
            return Err((ErrorKind::BadArgs, format!("{field} must be non-empty")));
        }
    }
    if conventions::validate_slug(&args.slug).is_err() {
        return Err(refuse(QueueRefusal::BadName { name: args.slug.clone() }));
    }
    if args.slices.is_empty() {
        return Err((ErrorKind::BadArgs, "a sub-milestone needs at least one slice".to_string()));
    }
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
    let identity = format!("{}/{}", args.milestone, args.slug);
    // §3.3: at most 2 deep below the top-level milestone.
    sub_depth(&identity).map_err(refuse)?;
    // §6.7's backstop: growlightd refuses these before the handshake commits,
    // so a hit here means a caller skipped that validation.
    let texts: Vec<SubSliceText<'_>> = args
        .slices
        .iter()
        .map(|s| SubSliceText {
            title: s.title.as_deref().unwrap_or(&s.slug),
            body: &s.body,
        })
        .collect();
    if let Some(v) = sub_doc_violation(&args.mission, &args.finish_criteria, &texts) {
        return Err((ErrorKind::BadArgs, format!("field_not_allowed: {}", v.message())));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let doc_rel = milestone_doc(&identity);
    let slices_dir = format!("{}/slices", milestone_path(&identity));
    let (mut parent, parent_version) = {
        let wt = WorkTree::new(daemon, &inner);
        // The sub's main doc is its dir's canary, as a milestone's is: every
        // file under it is a first-creation write.
        if wt.exists(&doc_rel) {
            return Err(refuse(QueueRefusal::Exists { id: identity.clone() }));
        }
        match load_slices(&wt, &inner, &args.milestone) {
            Ok(Some(l)) => (l.model, l.version),
            Ok(None) => return Err(refuse(QueueRefusal::UnknownId { id: args.milestone.clone() })),
            Err(e) => return Err((ErrorKind::Internal, e.to_string())),
        }
    };

    // The split: an `active` slice item gives its remaining work to the sub.
    let sidx = parent
        .items
        .iter()
        .position(|i| i.id == args.slice)
        .ok_or_else(|| refuse(QueueRefusal::UnknownId { id: args.slice.clone() }))?;
    let item = &parent.items[sidx];
    if item.kind != SliceKind::Slice || item.status != SliceStatus::Active {
        return Err((
            ErrorKind::BadArgs,
            format!(
                "{} {:?} is {}; only an active slice splits into a sub-milestone",
                item.kind, args.slice, item.status
            ),
        ));
    }
    parent.items[sidx].status = SliceStatus::Split;
    // §7 placement. The split slice was the walk's first open item, so right
    // after it is the front of the parent's remaining items (it runs next);
    // `do_not_prioritize` appends at the end instead.
    let at = if args.at_end { parent.items.len() } else { sidx + 1 };
    parent.items.insert(
        at,
        SliceItem {
            kind: SliceKind::Sub,
            id: args.slug.clone(),
            status: SliceStatus::Queued,
            follow_ups: None,
        },
    );
    // Backstop: the slug must be a free item id in the parent's list.
    parent.validate(&args.milestone).map_err(refuse)?;

    // The sub's own list, numbered deterministically: its folder was just
    // proven absent, so the first slice is 001 and `.seq` ends at the count.
    let date = conventions::today_hyphen();
    let mut slice_docs = Vec::with_capacity(args.slices.len());
    let mut items = Vec::with_capacity(args.slices.len());
    for (i, spec) in args.slices.iter().enumerate() {
        let number = i as u32 + 1;
        slice_docs.push(FileWrite {
            rel: format!("{slices_dir}/{}", conventions::note_filename(number, &spec.slug)),
            expected: None,
            bytes: conventions::note_doc(spec.title.as_deref().unwrap_or(&spec.slug), &date, &spec.body)
                .into_bytes(),
        });
        items.push(SliceItem {
            kind: SliceKind::Slice,
            id: format!("{number:03}"),
            status: SliceStatus::Queued,
            follow_ups: Some(0),
        });
    }
    let ids: Vec<String> = items.iter().map(|i| i.id.clone()).collect();
    let sub = SlicesToml::new(identity.clone(), items);
    sub.validate(&identity).map_err(refuse)?;

    let files = [
        FileWrite {
            rel: slices_file(&args.milestone),
            expected: parent_version,
            bytes: parent
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_bytes(),
        },
        FileWrite {
            rel: slices_file(&identity),
            expected: None,
            bytes: sub
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_bytes(),
        },
    ];
    let views = [
        ViewWrite {
            host: slices_view_host(&args.milestone),
            tag: SLICES_V2_TAG,
            body: Some(slices_view(&parent)),
        },
        ViewWrite {
            host: slices_view_host(&identity),
            tag: SLICES_V2_TAG,
            body: Some(slices_view(&sub)),
        },
    ];
    // The sub's docs ride the one commit as first-creation extras (the
    // milestone kind of `queue_add_entry` does the same), so a refusal leaves
    // no orphan docs.
    let mut extras = vec![
        FileWrite {
            rel: doc_rel.clone(),
            expected: None,
            bytes: sub_doc(
                &identity,
                &args.milestone,
                &args.slice,
                &args.title,
                &args.mission,
                &args.finish_criteria,
            )
            .into_bytes(),
        },
        FileWrite {
            rel: format!("{slices_dir}/{}", conventions::SEQ_FILE),
            expected: None,
            bytes: format!("{}\n", args.slices.len()).into_bytes(),
        },
    ];
    extras.extend(slice_docs);

    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_sub_added",
        serde_json::json!({
            "milestone": args.milestone,
            "slice": args.slice,
            "sub": identity,
            "at_end": args.at_end,
        }),
        &files,
        &views,
        &ExtraWrites {
            writes: &extras,
            refresh_backlinks: true,
        },
    )?;

    Ok(serde_json::to_value(QueueV2AddSubReply {
        milestone: identity,
        slices: ids,
        path: doc_rel,
        hash: hash.to_string(),
    })
    .unwrap())
}

/// `queue_v2_re_record_bases` (queue-v2-git slice 004): keeperd↔growlightd only —
/// growlightd recomputed each restacked branch's base read-only after the
/// restack completed (§8, `git merge-base`) and writes them back: each named
/// live entry's `base` is replaced, and each `settled` archive row stops being
/// due, so the bases and the answered trigger can't land apart. An all-no-op
/// write (every `base` already the given value, nothing due) mints no commit.
/// One commit, `queue_v2_bases_rerecorded`; the derived view re-renders.
pub fn queue_v2_re_record_bases(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2ReRecordBasesArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_re_record_bases args: {e}")))?;
    if args.entries.is_empty() && args.settled.is_empty() {
        return Err((ErrorKind::BadArgs, "entries and settled are both empty".to_string()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let (mut queue, queue_version, mut archive, archive_version) = {
        let wt = WorkTree::new(daemon, &inner);
        match load_queue_state(&wt, &inner) {
            Ok(Some(qs)) => (qs.queue.model, qs.queue.version, qs.archive.model, qs.archive.version),
            Ok(None) => {
                return Err((
                    ErrorKind::NotFound,
                    "no queue.toml — there is no v2 state".to_string(),
                ))
            }
            Err(e) => return Err((ErrorKind::Internal, e.to_string())),
        }
    };

    let mut changed = false;
    for rec in &args.entries {
        let Some(e) = queue.entries.iter_mut().find(|e| e.id == rec.entry) else {
            return Err(refuse(QueueRefusal::UnknownId { id: rec.entry.clone() }));
        };
        if e.base != rec.base {
            e.base = rec.base.clone();
            changed = true;
        }
    }
    let mut settled = false;
    for id in &args.settled {
        let Some(a) = archive.entries.iter_mut().find(|a| a.row.id == *id) else {
            return Err(refuse(QueueRefusal::UnknownId { id: id.clone() }));
        };
        settled |= std::mem::take(&mut a.re_record_due);
    }
    queue.validate(&archive).map_err(refuse)?;

    if !changed && !settled {
        let hash = current_tip(&inner)?;
        return Ok(serde_json::to_value(QueueV2ReRecordBasesReply { hash }).unwrap());
    }

    let mut files = vec![FileWrite {
        rel: QUEUE_FILE.to_string(),
        expected: queue_version,
        bytes: queue
            .to_toml()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
            .into_bytes(),
    }];
    if settled {
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
        "queue_v2_bases_rerecorded",
        serde_json::json!({ "entries": args.entries.len(), "settled": args.settled }),
        &files,
        &[ViewWrite {
            host: queue_view_host(),
            tag: QUEUE_V2_TAG,
            body: Some(queue_view(&queue)),
        }],
        &ExtraWrites::NONE,
    )?;

    Ok(serde_json::to_value(QueueV2ReRecordBasesReply { hash: hash.to_string() }).unwrap())
}

// ---- queue_v2_migrate_apply ----------------------------------------------

/// An [`ApplyRefusal`] as a wire error; the message leads with its code.
/// `legacy_changed` is the CAS miss, so it is `Conflict` like every stale
/// write; `v2_files_present` is `PathAlreadyExists`; the rest are state
/// refusals, `BadArgs` as [`refuse`] maps them.
fn apply_refusal(r: ApplyRefusal, detail: impl std::fmt::Display) -> (ErrorKind, String) {
    let kind = match r {
        ApplyRefusal::LegacyChanged => ErrorKind::Conflict,
        ApplyRefusal::V2FilesPresent => ErrorKind::PathAlreadyExists,
        _ => ErrorKind::BadArgs,
    };
    (kind, format!("{}: {detail}", r.code()))
}

/// The apply's half of the dry run's snapshot, read through the worktree.
struct BacklogSnapshot {
    /// Every `.md` under the backlog dir, garden-relative path → text as the
    /// redacted read view serves it ([`read_view`]).
    md: BTreeMap<String, String>,
    /// The v2 files already present there (`queue.toml`,
    /// `queue-archive.toml`, any `slices.toml`, sub-milestones included), in
    /// path order.
    v2_present: Vec<String>,
}

fn migrate_snapshot(wt: &WorkTree, hook: &LayerBHook) -> Result<BacklogSnapshot, (ErrorKind, String)> {
    fn walk(
        wt: &WorkTree,
        hook: &LayerBHook,
        dir: &str,
        md: &mut BTreeMap<String, String>,
        v2: &mut Vec<String>,
    ) -> Result<(), (ErrorKind, String)> {
        let mut children = wt.read_dir(dir);
        children.sort_by(|a, b| a.name.cmp(&b.name));
        for child in children {
            let rel = format!("{dir}/{}", child.name);
            if child.is_dir {
                walk(wt, hook, &rel, md, v2)?;
            } else if rel == QUEUE_FILE || rel == QUEUE_ARCHIVE_FILE || child.name == "slices.toml" {
                v2.push(rel);
            } else if child.name.ends_with(".md") {
                let text = read_view(wt, hook, &rel).ok_or_else(|| (ErrorKind::Io, format!("{rel}: unreadable")))?;
                md.insert(rel, text);
            }
        }
        Ok(())
    }
    let dir = BACKLOG_DOC.rsplit_once('/').expect("BACKLOG_DOC has a parent").0;
    let mut snap = BacklogSnapshot { md: BTreeMap::new(), v2_present: Vec::new() };
    walk(wt, hook, dir, &mut snap.md, &mut snap.v2_present)?;
    Ok(snap)
}

/// `rel`'s working-tree text projected the way `read_file` and the FUSE mount
/// serve it (`reads::read_committed_file`): a whole-file-sealed doc is its
/// `[sealed:<path>]` placeholder, an inline region's body `[encrypted]`. The
/// converter then reads the bytes the CLI's dry run reads, so the two plans
/// agree, and `item_meta::unreadable_metadata` sees what hides a metadata line
/// (report 128) instead of base64 ciphertext or a sealed envelope.
fn read_view(wt: &WorkTree, hook: &LayerBHook, rel: &str) -> Option<String> {
    if hook.snapshot().is_sealed(rel) {
        return Some(format!("[sealed:{rel}]\n"));
    }
    String::from_utf8(hook.redact_regions(rel, wt.read(rel)?)).ok()
}

/// `queue_v2_migrate_apply` (`queue-v2-migrate` slice 005, spec §11): the
/// legacy→v2 converter's write. keeperd rebuilds the snapshot from its own
/// worktree (the runtime batons ride in the args), recomputes the plan under
/// the owner's answers, and checks every [`ApplyRefusal`] before anything is
/// staged: the fleet armed, the switch already `v2`, any v2 file present, the
/// snapshot (backlog files plus batons, [`migrate::LegacyFiles::digest`]) not
/// the `expect` version, a plan refusal or open call.
/// Otherwise `queue.toml`, `queue-archive.toml` and every `slices.toml`, with
/// their §3.4 views, land in one commit, `queue_v2_migrated`. The legacy
/// tables are never edited and the switch is never flipped; the reply's baton
/// copies are the caller's to make.
pub fn queue_v2_migrate_apply(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2MigrateApplyArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_migrate_apply args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let (plan, version) = {
        let wt = WorkTree::new(daemon, &inner);
        let config = format!("{GARDEN_CONFIG_DIR}/{GROWLIGHT_CONFIG_FILE}");
        let text = match wt.exists(&config) {
            true => Some(
                wt.read_to_string(&config)
                    .ok_or_else(|| (ErrorKind::Io, format!("{config}: unreadable")))?,
            ),
            false => None,
        };
        let switches = crate::growlight_unit::migrate_switches(text.as_deref()).map_err(|e| {
            (ErrorKind::BadArgs, format!("{config}: {e}; the apply refuses under a config it cannot read"))
        })?;
        if switches.fleet_enabled {
            return Err(apply_refusal(
                ApplyRefusal::FleetArmed,
                format!("{config} has `fleet_enabled = true`; disarm the fleet first"),
            ));
        }
        if switches.queue_v2 {
            return Err(apply_refusal(
                ApplyRefusal::SwitchIsV2,
                format!("{config} already says `queue = \"v2\"`; the migration runs before the flip"),
            ));
        }
        let BacklogSnapshot { md: garden, v2_present } = migrate_snapshot(&wt, &inner.layer_b)?;
        if !v2_present.is_empty() {
            return Err(apply_refusal(ApplyRefusal::V2FilesPresent, v2_present.join(", ")));
        }
        if !garden.contains_key(BACKLOG_DOC) {
            return Err((ErrorKind::NotFound, format!("no {BACKLOG_DOC}")));
        }
        let files = migrate::LegacyFiles { garden, batons: args.batons };
        let version = files.digest();
        if version != args.expect {
            return Err(apply_refusal(
                ApplyRefusal::LegacyChanged,
                format!(
                    "the snapshot ({} backlog files, {} batons) is version {version}, not --expect {}; \
                     a file the plan reads changed since the dry run, so re-run it",
                    files.garden.len(),
                    files.batons.len(),
                    args.expect
                ),
            ));
        }
        let legacy =
            migrate::read_legacy(&files).map_err(|e| apply_refusal(ApplyRefusal::NotApplicable, e))?;
        let plan = migrate::plan(&legacy, &args.answers, &conventions::now_rfc3339());
        if !plan.applicable() {
            return Err(apply_refusal(
                ApplyRefusal::NotApplicable,
                format!(
                    "{} refusal(s), {} open call(s); re-run the dry run until none remain",
                    plan.refusals.len(),
                    plan.open_calls().count()
                ),
            ));
        }
        (plan, version)
    };

    let toml_err = |e: softfig_ipc::queue_v2::QueueV2Error| (ErrorKind::Internal, e.to_string());
    let mut files = vec![
        FileWrite {
            rel: QUEUE_FILE.to_string(),
            expected: None,
            bytes: plan.queue.to_toml().map_err(toml_err)?.into_bytes(),
        },
        FileWrite {
            rel: QUEUE_ARCHIVE_FILE.to_string(),
            expected: None,
            bytes: plan.archive.to_toml().map_err(toml_err)?.into_bytes(),
        },
    ];
    let mut views = vec![ViewWrite {
        host: queue_view_host(),
        tag: QUEUE_V2_TAG,
        body: Some(queue_view(&plan.queue)),
    }];
    for (milestone, slices) in &plan.slices {
        files.push(FileWrite {
            rel: slices_file(milestone),
            expected: None,
            bytes: slices.to_toml().map_err(toml_err)?.into_bytes(),
        });
        views.push(ViewWrite {
            host: slices_view_host(milestone),
            tag: SLICES_V2_TAG,
            body: Some(slices_view(slices)),
        });
    }
    let (entries, archived, slices) =
        (plan.queue.entries.len(), plan.archive.entries.len(), plan.slices.len());
    let hash = apply(
        daemon,
        &mut inner,
        "queue_v2_migrated",
        serde_json::json!({
            "version": version,
            "entries": entries,
            "archived": archived,
            "slices": slices,
        }),
        &files,
        &views,
        &ExtraWrites::NONE,
    )?;

    Ok(serde_json::to_value(QueueV2MigrateApplyReply {
        hash: hash.to_string(),
        entries,
        archived,
        slices,
        batons: plan.batons,
    })
    .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::growlight::queue_verbs::{
        queue_add_entry, queue_add_project, queue_drop, queue_update_entry, slice_update,
    };
    use crate::actions::growlight::v2::write::tests::unlocked;
    use crate::actions::managed;
    use softfig_ipc::queue_v2::{Lane, Project, QueueToml, SlicesToml};
    use softfig_ipc::verbs::QueueAddEntryReply;
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

    fn entry(id: &str, lane: Lane, status: EntryStatus) -> softfig_ipc::queue_v2::Entry {
        softfig_ipc::queue_v2::Entry {
            id: id.to_string(),
            kind: EntryKind::Milestone,
            title: format!("{id} title"),
            project: "softfig".to_string(),
            lane,
            status,
            after: vec![],
            added: "2026-10-11T15:04:00Z".to_string(),
            branch: format!("feat/{id}"),
            parent: String::new(),
            base: String::new(),
            claimed: String::new(),
            follow_ups: 0,
            pending_status: None,
            auto_restack: true,
            fleet: true,
            not_before: None,
        }
    }

    /// Seed a project + a milestone with two slices through the real human
    /// verbs, then claim slice 001 — the standing "an entry is running"
    /// fixture.
    fn seed_running_milestone(daemon: &Daemon, slug: &str) {
        // `Exists` is fine when a helper runs twice in one garden; a missing
        // project surfaces later as `unknown_project` on the add.
        let _ = queue_add_project(daemon, serde_json::json!({ "name": "softfig", "repo": "~/p" }));
        queue_add_entry(
            daemon,
            serde_json::json!({
                "kind": "milestone",
                "slug": slug,
                "title": format!("{slug} title"),
                "mission": format!("{slug} mission"),
                "finish_criteria": format!("{slug} criteria"),
                "project": "softfig",
                "slices": [
                    { "slug": "first", "title": "First slice", "body": "# 001\n\nwork" },
                    { "slug": "second", "title": "Second slice", "body": "# 002\n\nwork" },
                ],
            }),
        )
        .expect("add_entry");
        claim(daemon, slug, Some("001")).expect("seed claim");
    }

    /// Seed the project + a single-slice milestone, left `queued`.
    fn seed_queued_milestone(daemon: &Daemon, slug: &str) {
        let _ = queue_add_project(daemon, serde_json::json!({ "name": "softfig", "repo": "~/p" }));
        queue_add_entry(
            daemon,
            serde_json::json!({
                "kind": "milestone",
                "slug": slug,
                "title": format!("{slug} title"),
                "mission": format!("{slug} mission"),
                "finish_criteria": format!("{slug} criteria"),
                "project": "softfig",
                "slices": [ { "slug": "one", "body": "# 001\n\nwork" } ],
            }),
        )
        .expect("add_entry");
    }

    /// Seed the project + a task; returns the task's NNN id.
    fn seed_task(daemon: &Daemon, slug: &str) -> String {
        let _ = queue_add_project(daemon, serde_json::json!({ "name": "softfig", "repo": "~/p" }));
        let reply: QueueAddEntryReply = serde_json::from_value(
            queue_add_entry(
                daemon,
                serde_json::json!({
                    "kind": "task",
                    "slug": slug,
                    "title": format!("{slug} title"),
                    "mission": format!("{slug} mission"),
                    "finish_criteria": format!("{slug} criteria"),
                    "project": "softfig",
                }),
            )
            .expect("add task"),
        )
        .unwrap();
        reply.id
    }

    fn claim(daemon: &Daemon, entry: &str, unit: Option<&str>) -> Result<QueueV2ClaimReply, (ErrorKind, String)> {
        let v = queue_v2_claim(daemon, serde_json::json!({ "entry": entry, "unit": unit }))?;
        Ok(serde_json::from_value(v).unwrap())
    }

    /// A claim carrying the §8 first-claim `parent`/`base` (queue-v2-git slice
    /// 002) — the shape growlightd sends for a never-claimed entry.
    fn claim_first(
        daemon: &Daemon,
        entry: &str,
        unit: Option<&str>,
        parent: &str,
        base: &str,
    ) -> Result<QueueV2ClaimReply, (ErrorKind, String)> {
        let v = queue_v2_claim(
            daemon,
            serde_json::json!({ "entry": entry, "unit": unit, "parent": parent, "base": base }),
        )?;
        Ok(serde_json::from_value(v).unwrap())
    }

    fn set_status(
        daemon: &Daemon,
        entry: &str,
        unit: Option<&str>,
        new: &str,
    ) -> Result<QueueV2SetStatusReply, (ErrorKind, String)> {
        let v = queue_v2_set_status(daemon, serde_json::json!({ "entry": entry, "unit": unit, "new": new }))?;
        Ok(serde_json::from_value(v).unwrap())
    }

    fn follow_ups(daemon: &Daemon, entry: &str, unit: Option<&str>, count: u64) -> Result<QueueV2FollowUpsReply, (ErrorKind, String)> {
        let v = queue_v2_follow_ups(daemon, serde_json::json!({ "entry": entry, "unit": unit, "count": count }))?;
        Ok(serde_json::from_value(v).unwrap())
    }

    fn session_log(daemon: &Daemon, entry: &str, unit: Option<&str>, line: &str) -> Result<QueueV2SessionLogReply, (ErrorKind, String)> {
        let v = queue_v2_session_log(daemon, serde_json::json!({ "entry": entry, "unit": unit, "line": line }))?;
        Ok(serde_json::from_value(v).unwrap())
    }

    fn deferred(daemon: &Daemon, entry: &str, tests: serde_json::Value) -> Result<QueueV2DeferredReply, (ErrorKind, String)> {
        let v = queue_v2_deferred(daemon, serde_json::json!({ "entry": entry, "tests": tests }))?;
        Ok(serde_json::from_value(v).unwrap())
    }

    fn loaded_queue(daemon: &Daemon) -> (QueueToml, softfig_ipc::queue_v2::QueueArchiveToml) {
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(daemon, &inner);
        let qs = load_queue_state(&wt, &inner).unwrap().expect("queue exists");
        (qs.queue.model, qs.archive.model)
    }

    fn loaded_slices(daemon: &Daemon, milestone: &str) -> SlicesToml {
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(daemon, &inner);
        load_slices(&wt, &inner, milestone).unwrap().expect("slices exist").model
    }

    /// Write a file straight into the garden behind the worktree — the
    /// hand-edit shape a FUSE mount would stage.
    fn hand_write(garden: &std::path::Path, rel: &str, content: &str) {
        let abs = garden.join(rel);
        std::fs::create_dir_all(abs.parent().expect("nested path")).unwrap();
        std::fs::write(abs, content).unwrap();
    }

    /// Seed the queue.toml directly with the given rows (bypassing the human
    /// verbs, for states only keeperd writes).
    fn seed_queue_rows(daemon: &Daemon, entries: Vec<softfig_ipc::queue_v2::Entry>) {
        let q = QueueToml::new(vec![project()], entries);
        let mut inner = daemon.inner.lock().unwrap();
        crate::actions::growlight::v2::write::apply(
            daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({ "test": true }),
            &[FileWrite {
                rel: QUEUE_FILE.to_string(),
                expected: None,
                bytes: q.to_toml().unwrap().into_bytes(),
            }],
            &[ViewWrite {
                host: queue_view_host(),
                tag: QUEUE_V2_TAG,
                body: Some(queue_view(&q)),
            }],
            &ExtraWrites::NONE,
        )
        .expect("seed");
    }

    // ---- claim -------------------------------------------------------------

    #[test]
    fn claim_flips_entry_and_slice_active_in_one_commit_and_renders_both_views() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queued_milestone(&daemon, "m");
        let before = commit_count(&daemon);

        let reply = claim(&daemon, "m", Some("001")).expect("claim");

        assert_eq!(commit_count(&daemon), before + 1, "one commit for both files");
        let (queue, _archive) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].status, EntryStatus::Active);
        let slices = loaded_slices(&daemon, "m");
        assert_eq!(slices.items[0].status, SliceStatus::Active);
        // Both derived views re-rendered.
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let backlog = wt.read_to_string(&queue_view_host()).unwrap();
        let queue_region = managed::region_body(&backlog, QUEUE_V2_TAG).unwrap();
        assert!(queue_region.contains("| active |"), "{queue_region}");
        let claude = wt.read_to_string(&slices_view_host("m")).unwrap();
        let slices_region = managed::region_body(&claude, SLICES_V2_TAG).unwrap();
        assert!(slices_region.contains("| slice | 001 | active |"), "{slices_region}");
        assert!(!reply.hash.is_empty());
    }

    #[test]
    fn first_claim_records_parent_base_and_claimed_and_resume_keeps_them() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queued_milestone(&daemon, "m");

        claim_first(&daemon, "m", Some("001"), "other", "deadbeef").expect("first claim");

        let (queue, _) = loaded_queue(&daemon);
        let e = &queue.entries[0];
        assert_eq!(e.parent, "other", "parent recorded at first claim");
        assert_eq!(e.base, "deadbeef", "base recorded at first claim");
        assert!(
            e.claimed.starts_with("20") && e.claimed.ends_with('Z'),
            "claimed stamped by keeperd: {}",
            e.claimed
        );

        // A resume (pause → active) without parent/base must not overwrite the
        // recorded base.
        set_status(&daemon, "m", None, "paused").expect("pause");
        claim(&daemon, "m", None).expect("resume");
        let (queue, _) = loaded_queue(&daemon);
        let e = &queue.entries[0];
        assert_eq!(e.parent, "other", "parent unchanged by a resume");
        assert_eq!(e.base, "deadbeef", "base unchanged by a resume");
        assert!(
            e.claimed.starts_with("20") && e.claimed.ends_with('Z'),
            "claimed unchanged by a resume: {}",
            e.claimed
        );
    }

    /// Review 061 F1 (report 178): a first claim that resumed an existing
    /// branch records `auto_restack = false` on the row; a fleet-cut claim, a
    /// resume and a re-claim leave the flag alone. The flag is read back from
    /// the committed `queue.toml`, so it survives a keeperd write/read round
    /// trip. Fails on `1ad3a01`, where `existing` is never persisted.
    #[test]
    fn a_first_claim_that_resumed_a_branch_holds_it_out_of_the_auto_restack() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queued_milestone(&daemon, "m");

        // The fleet cut the branch (a second garden: one entry per repo starts):
        // the default stands.
        let other_garden = tempfile::tempdir().unwrap();
        let other = unlocked(other_garden.path());
        seed_queued_milestone(&other, "n");
        claim_first(&other, "n", Some("001"), "", "cafe").expect("fleet-cut claim");
        let (queue, _) = loaded_queue(&other);
        assert!(queue.entries[0].auto_restack);

        let v = queue_v2_claim(
            &daemon,
            serde_json::json!({ "entry": "m", "unit": "001", "parent": "", "base": "deadbeef", "existing": true }),
        );
        v.expect("resuming claim");
        let (queue, _) = loaded_queue(&daemon);
        let m = queue.entries.iter().find(|e| e.id == "m").unwrap();
        assert!(!m.auto_restack, "a resumed branch is held out of the auto restack");
        assert_eq!(m.base, "deadbeef");
        let text = queue.to_toml().unwrap();
        assert!(text.contains("auto_restack = false"), "{text}");
        assert_eq!(QueueToml::parse(&text).unwrap(), queue, "round-trips");

        // A resume of the same entry (no `existing`) does not re-enable it.
        set_status(&daemon, "m", None, "paused").expect("pause");
        claim(&daemon, "m", None).expect("resume");
        let (queue, _) = loaded_queue(&daemon);
        assert!(!queue.entries.iter().find(|e| e.id == "m").unwrap().auto_restack);
    }

    #[test]
    fn a_first_claim_without_parent_or_base_stamps_claimed_and_leaves_them_empty() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queued_milestone(&daemon, "m");

        // A restack (or any branchless first claim) sends no parent/base —
        // `claimed` is still stamped, parent/base stay empty.
        claim(&daemon, "m", Some("001")).expect("first claim, no base");

        let (queue, _) = loaded_queue(&daemon);
        let e = &queue.entries[0];
        assert_eq!(e.parent, "", "no parent without a base line");
        assert_eq!(e.base, "", "no base without a base line");
        assert!(
            e.claimed.starts_with("20") && e.claimed.ends_with('Z'),
            "claimed still stamped: {}",
            e.claimed
        );
    }

    #[test]
    fn claim_is_idempotent_and_resumes_a_paused_entry() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        let before = commit_count(&daemon);

        // A re-claim of the same unit is a no-op — no new commit.
        let reply = claim(&daemon, "m", Some("001")).expect("re-claim");
        assert_eq!(commit_count(&daemon), before, "idempotent re-claim mints no commit");
        assert!(!reply.hash.is_empty(), "the no-op still reports the tip");

        // Pause the entry, then resume it through a claim (§2: any eligible
        // member may resume a paused entry).
        set_status(&daemon, "m", None, "paused").expect("pause");
        claim(&daemon, "m", None).expect("entry resume");
        let (queue, _) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].status, EntryStatus::Active, "paused → active");
        // The still-active slice 001 blocks a claim of a *different* unit
        // (one active unit per tree), which is exactly the double-assignment
        // guard; finish 001 first, then 002 claims cleanly.
        set_status(&daemon, "m", Some("001"), "done").expect("slice 001 done");
        claim(&daemon, "m", Some("002")).expect("next slice");
        let slices = loaded_slices(&daemon, "m");
        assert_eq!(
            slices.items.iter().map(|i| (i.id.as_str(), i.status)).collect::<Vec<_>>(),
            vec![("001", SliceStatus::Done), ("002", SliceStatus::Active)],
        );
    }

    #[test]
    fn claim_refuses_unknown_double_assignment_and_wrong_state() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");

        // Unknown entry.
        let err = claim(&daemon, "ghost", Some("001")).unwrap_err();
        assert_eq!(err.0, ErrorKind::NotFound, "{err:?}");
        assert!(err.1.contains("unknown_id"), "{err:?}");
        // A second active unit in the same tree is a double assignment.
        let err = claim(&daemon, "m", Some("002")).unwrap_err();
        assert!(err.1.contains("started"), "{err:?}");
        // An unknown unit.
        let err = claim(&daemon, "m", Some("999")).unwrap_err();
        assert_eq!(err.0, ErrorKind::NotFound, "{err:?}");

        // A blocked entry cannot be claimed.
        seed_queued_milestone(&daemon, "b");
        queue_update_entry(&daemon, serde_json::json!({ "id": "b", "status": "blocked" }))
            .expect("human block");
        let err = claim(&daemon, "b", Some("001")).unwrap_err();
        assert!(err.1.contains("is blocked"), "{err:?}");
    }

    /// F2 + V8: a drop does not refuse for an active child. It re-parents the
    /// child in the same write, and its restack can't be claimed until the
    /// child's session has handed off. Once the restack runs, the claim
    /// refuses the other way round.
    #[test]
    fn the_restack_of_a_drop_waits_for_the_active_child() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut parent = entry("a", Lane::Normal, EntryStatus::Queued);
        parent.branch = "feat/a".to_string();
        parent.base = "main-commit".to_string();
        parent.claimed = "2026-10-11T12:00:00Z".to_string();
        let mut child = entry("b", Lane::Normal, EntryStatus::Active);
        child.branch = "feat/b".to_string();
        child.parent = "a".to_string();
        child.base = "a-commit".to_string();
        child.claimed = "2026-10-11T12:10:00Z".to_string();
        seed_queue_rows(&daemon, vec![parent, child]);

        queue_drop(&daemon, serde_json::json!({ "id": "a", "reason": "abandoned" }))
            .expect("the drop proceeds over an active child");
        let (queue, _) = loaded_queue(&daemon);
        let restack = queue
            .entries
            .iter()
            .find(|e| e.kind == EntryKind::Restack)
            .expect("the drop enqueued a restack")
            .id
            .clone();
        let child = queue.entries.iter().find(|e| e.id == "b").unwrap();
        assert_eq!(child.status, EntryStatus::Active, "the live session runs on");
        assert_eq!((child.parent.as_str(), child.base.as_str()), ("", "a-commit"));

        let err = claim(&daemon, &restack, None).unwrap_err();
        assert!(err.1.contains("started"), "{err:?}");

        set_status(&daemon, "b", None, "paused").expect("the child hands off");
        claim(&daemon, &restack, None).expect("no session holds a branch now");

        let err = claim(&daemon, "b", None).unwrap_err();
        assert!(err.1.contains("started"), "{err:?}");
    }

    #[test]
    fn claim_on_a_task_has_no_unit_and_flips_the_entry_alone() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let id = seed_task(&daemon, "fix-thing");
        let reply = claim(&daemon, &id, None).expect("task claim");
        assert!(!reply.hash.is_empty());
        let (queue, _) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].status, EntryStatus::Active);
        // A task with a unit is refused.
        let err = claim(&daemon, &id, Some("001")).unwrap_err();
        assert!(err.1.contains("only milestones have slices"), "{err:?}");
    }

    // ---- set_status -----------------------------------------------------------

    #[test]
    fn set_status_writes_each_entry_and_slice_transition() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");

        // Entry: active → paused → (resume) → blocked → (human unblock) →
        // deferred → (human unblock) → queued.
        let reply = set_status(&daemon, "m", None, "paused").expect("pause");
        assert_eq!(reply.status, "paused");
        assert_eq!(loaded_queue(&daemon).0.entries[0].status, EntryStatus::Paused);
        // The from-status guard: a paused row refuses a further daemon write.
        let err = set_status(&daemon, "m", None, "blocked").unwrap_err();
        assert!(err.1.contains("requires active"), "{err:?}");

        claim(&daemon, "m", None).expect("resume");
        set_status(&daemon, "m", None, "blocked").expect("block");
        queue_update_entry(&daemon, serde_json::json!({ "id": "m", "status": "queued" }))
            .expect("human unblock");
        claim(&daemon, "m", None).expect("resume");
        set_status(&daemon, "m", None, "deferred").expect("defer");
        queue_update_entry(&daemon, serde_json::json!({ "id": "m", "status": "queued" }))
            .expect("human un-defer");
        claim(&daemon, "m", None).expect("resume");
        set_status(&daemon, "m", None, "queued").expect("queued");
        assert_eq!(loaded_queue(&daemon).0.entries[0].status, EntryStatus::Queued);

        // Slice: active → done resets follow_ups; blocked/deferred/queued/split
        // keep them (the human re-queues between daemon writes).
        claim(&daemon, "m", Some("001")).expect("re-activate slice");
        follow_ups(&daemon, "m", Some("001"), 4).expect("bump counter");
        set_status(&daemon, "m", Some("001"), "done").expect("slice done");
        let slices = loaded_slices(&daemon, "m");
        assert_eq!(slices.items[0].status, SliceStatus::Done);
        assert_eq!(slices.items[0].follow_ups, Some(0), "done resets the counter");

        claim(&daemon, "m", Some("002")).expect("next slice");
        set_status(&daemon, "m", Some("002"), "blocked").expect("slice blocked");
        slice_update(&daemon, serde_json::json!({ "milestone": "m", "id": "002", "status": "queued" }))
            .expect("human slice unblock");
        claim(&daemon, "m", Some("002")).expect("re-activate");
        set_status(&daemon, "m", Some("002"), "deferred").expect("slice deferred");
        slice_update(&daemon, serde_json::json!({ "milestone": "m", "id": "002", "status": "queued" }))
            .expect("human slice un-defer");
        claim(&daemon, "m", Some("002")).expect("re-activate");
        set_status(&daemon, "m", Some("002"), "queued").expect("slice queued");
        claim(&daemon, "m", Some("002")).expect("re-activate");
        set_status(&daemon, "m", Some("002"), "split").expect("slice split");
        assert_eq!(loaded_slices(&daemon, "m").items[1].status, SliceStatus::Split);
    }

    #[test]
    fn set_status_done_archives_the_row() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        let before = commit_count(&daemon);

        let reply = set_status(&daemon, "m", None, "done").expect("close out");
        assert_eq!(reply.status, "done");
        assert_eq!(commit_count(&daemon), before + 1, "one commit for both files");

        let (queue, archive) = loaded_queue(&daemon);
        assert!(queue.entries.is_empty(), "the row left the live list");
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].final_status, FinalStatus::Done);
        assert_eq!(archive.entries[0].row.id, "m");
        assert!(archive.entries[0].finished.starts_with("20"), "finished stamped");
    }

    /// §8: a restack's re-record is owed from the commit that archives it, so
    /// a restart can't lose it. Only `done` owes one, and only a restack.
    #[test]
    fn set_status_done_marks_a_restack_row_due_and_nothing_else() {
        // One row per garden: a repo holds one active entry at a time.
        let run = |kind, status| {
            let garden = tempfile::tempdir().unwrap();
            let daemon = unlocked(garden.path());
            let mut row = entry("r", Lane::Urgent, EntryStatus::Active);
            row.kind = kind;
            row.branch = String::new();
            seed_queue_rows(&daemon, vec![row]);
            set_status(&daemon, "r", None, status).expect("status");
            loaded_queue(&daemon).1.entries.first().map(|a| a.re_record_due)
        };
        assert_eq!(run(EntryKind::Restack, "done"), Some(true));
        assert_eq!(run(EntryKind::Task, "done"), Some(false));
        assert_eq!(run(EntryKind::Restack, "deferred"), None, "the row stays live");
    }

    #[test]
    fn set_status_applies_a_pending_human_change_and_reports_it() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // Seed directly: an active entry carrying a pending human status (what
        // slice 009's human-verb recording will write; here hand-built).
        let mut e = entry("m", Lane::Normal, EntryStatus::Active);
        e.pending_status = Some(EntryStatus::Blocked);
        seed_queue_rows(&daemon, vec![e]);

        // While recorded, the derived view annotates the deferral.
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            let backlog = wt.read_to_string(&queue_view_host()).unwrap();
            let region = managed::region_body(&backlog, QUEUE_V2_TAG).unwrap();
            assert!(region.contains("active (pending: blocked)"), "{region}");
        }

        // The handshake asks for `paused`; the pending `blocked` wins.
        let reply = set_status(&daemon, "m", None, "paused").expect("boundary write");
        assert_eq!(reply.status, "blocked", "the reply reports what landed");
        let (queue, _) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].status, EntryStatus::Blocked);
        assert_eq!(queue.entries[0].pending_status, None, "pending cleared in the same commit");
    }

    /// Review R4: a member's own `blocked` (its stop on a question for the
    /// human) lands over a pending human change, which is dropped — a pending
    /// `queued` would otherwise make the entry eligible to hit the same
    /// question again.
    #[test]
    fn set_status_blocked_wins_over_a_pending_change() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut e = entry("m", Lane::Normal, EntryStatus::Active);
        e.pending_status = Some(EntryStatus::Queued);
        seed_queue_rows(&daemon, vec![e]);

        let reply = set_status(&daemon, "m", None, "blocked").expect("boundary write");
        assert_eq!(reply.status, "blocked", "the member's block lands");
        let (queue, _) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].status, EntryStatus::Blocked);
        assert_eq!(queue.entries[0].pending_status, None, "the pending change is dropped");
    }

    #[test]
    fn set_status_done_wins_over_a_pending_change() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut e = entry("m", Lane::Normal, EntryStatus::Active);
        e.pending_status = Some(EntryStatus::Deferred);
        seed_queue_rows(&daemon, vec![e]);

        // The work is finished: `done` archives the row and the pending
        // request dies with it (parking a completed entry is moot).
        let reply = set_status(&daemon, "m", None, "done").expect("close out");
        assert_eq!(reply.status, "done");
        let (queue, archive) = loaded_queue(&daemon);
        assert!(queue.entries.is_empty());
        assert_eq!(archive.entries[0].row.pending_status, None, "archive rows carry no pending");
    }

    #[test]
    fn set_status_refuses_bad_vocabulary_and_wrong_levels() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");

        // `split` is a slice word.
        let err = set_status(&daemon, "m", None, "split").unwrap_err();
        assert!(err.1.contains("entry status"), "{err:?}");
        // `paused` is an entry word.
        let err = set_status(&daemon, "m", Some("001"), "paused").unwrap_err();
        assert!(err.1.contains("slice status"), "{err:?}");
        // An unknown entry/slice.
        assert_eq!(set_status(&daemon, "ghost", None, "paused").unwrap_err().0, ErrorKind::NotFound);
        assert_eq!(set_status(&daemon, "m", Some("999"), "done").unwrap_err().0, ErrorKind::NotFound);
    }

    // ---- follow_ups -----------------------------------------------------------

    #[test]
    fn follow_ups_writes_slice_and_entry_counters_and_no_ops_on_same_count() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");

        // Slice counter, absolute (the increment arithmetic is growlightd's).
        follow_ups(&daemon, "m", Some("001"), 1).expect("slice 1");
        follow_ups(&daemon, "m", Some("001"), 5).expect("slice 5");
        assert_eq!(loaded_slices(&daemon, "m").items[0].follow_ups, Some(5));
        // The same count again is a no-op — no new commit.
        let at = commit_count(&daemon);
        follow_ups(&daemon, "m", Some("001"), 5).expect("no-op");
        assert_eq!(commit_count(&daemon), at, "same count mints no commit");

        // Entry counter (the close-out counter, §7).
        follow_ups(&daemon, "m", None, 2).expect("entry counter");
        assert_eq!(loaded_queue(&daemon).0.entries[0].follow_ups, 2);
    }

    #[test]
    fn follow_ups_refuses_subs_unknown_and_missing_files() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        // A `sub` item carries no counter (§3.3): append one to the tree, then
        // refuse a counter write on it.
        {
            let mut inner = daemon.inner.lock().unwrap();
            let (mut model, version) = {
                let wt = WorkTree::new(&daemon, &inner);
                let loaded = load_slices(&wt, &inner, "m").unwrap().unwrap();
                (loaded.model, loaded.version)
            };
            model.items.push(softfig_ipc::queue_v2::SliceItem {
                kind: SliceKind::Sub,
                id: "sub-a".to_string(),
                status: SliceStatus::Queued,
                follow_ups: None,
            });
            crate::actions::growlight::v2::write::apply(
                &daemon,
                &mut inner,
                "queue_v2_updated",
                serde_json::json!({ "test": true }),
                &[FileWrite {
                    rel: slices_file("m"),
                    expected: version,
                    bytes: model.to_toml().unwrap().into_bytes(),
                }],
                &[ViewWrite {
                    host: slices_view_host("m"),
                    tag: SLICES_V2_TAG,
                    body: Some(slices_view(&model)),
                }],
                &ExtraWrites::NONE,
            )
            .expect("sub seeded");
        }
        let err = follow_ups(&daemon, "m", Some("sub-a"), 1).unwrap_err();
        assert!(err.1.contains("slice-only"), "{err:?}");
        assert_eq!(follow_ups(&daemon, "ghost", None, 1).unwrap_err().0, ErrorKind::NotFound);
        assert_eq!(follow_ups(&daemon, "m", Some("999"), 1).unwrap_err().0, ErrorKind::NotFound);
    }

    // ---- session_log -----------------------------------------------------------

    #[test]
    fn session_log_lands_in_the_slice_doc_and_stamps_the_utc_prefix() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");

        let reply = session_log(
            &daemon,
            "m",
            Some("001"),
            "context_full · deepseek/deepseek-v4-pro#high · member oc · $0.04",
        )
        .expect("slice log");
        assert_eq!(reply.path, "growlight/backlog/milestones/m/slices/001-first.md");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt.read_to_string(&reply.path).unwrap();
        assert!(doc.contains("## Sessions"), "{doc}");
        // The §3.5 shape: `- <utc> · <reason> · <model> · member <id> · $cost`,
        // keeperd-stamped at minute precision (the spec's example form).
        let line = doc.lines().find(|l| l.starts_with("- 20")).expect("a stamped line");
        // The keeperd stamp is exactly `- YYYY-MM-DDTHH:MMZ · ` — minute
        // precision, the spec's §3.5 example form.
        assert!(line.len() > 18);
        let ts = &line[2..18];
        assert!(ts[4..5] == *"-" && ts[7..8] == *"-" && ts[10..11] == *"T" && ts[13..14] == *":", "{line}");
        assert!(ts.chars().all(|c| c.is_ascii_digit() || c == '-' || c == 'T' || c == ':'), "{line}");
        assert_eq!(line.as_bytes()[18], b'Z', "{line}");
        assert!(
            line.contains("· context_full · deepseek/deepseek-v4-pro#high · member oc · $0.04"),
            "{line}"
        );
        drop(inner);

        // A second log appends after the first (order preserved).
        session_log(&daemon, "m", Some("001"), "completed · reasoning · member oc · $0.01")
            .expect("second log");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt.read_to_string(&reply.path).unwrap();
        let first = doc.find("context_full").unwrap();
        let second = doc.find("completed").unwrap();
        assert!(first < second, "lines append in order");
    }

    #[test]
    fn session_log_targets_the_close_out_and_task_docs() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        let claude = "growlight/backlog/milestones/m/CLAUDE.md";
        let doc_before = {
            let inner = daemon.inner.lock().unwrap();
            WorkTree::new(&daemon, &inner).read_to_string(claude).unwrap()
        };
        // Close-out: the milestone's `sessions.md` (task 104), created by the
        // first line and appended to by the next; the milestone doc is left
        // alone.
        let reply = session_log(&daemon, "m", None, "deferred · reasoning · member oc · $0.02")
            .expect("close-out log");
        assert_eq!(reply.path, "growlight/backlog/milestones/m/sessions.md");
        session_log(&daemon, "m", None, "completed · reasoning · member oc · $0.03")
            .expect("second close-out log");
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            let log = wt.read_to_string(&reply.path).unwrap();
            assert!(log.starts_with(SESSIONS_DOC_STUB), "{log}");
            assert_eq!(log.matches("## Sessions").count(), 1, "{log}");
            assert!(log.contains("· deferred ·") && log.contains("· completed ·"), "{log}");
            assert_eq!(wt.read_to_string(claude).unwrap(), doc_before);
        }

        // Task: the numbered task doc.
        let id = seed_task(&daemon, "fix-x");
        let reply = session_log(&daemon, &id, None, "blocked · claude · member a · $0.00")
            .expect("task log");
        assert_eq!(reply.path, "growlight/backlog/tasks/001-fix-x.md");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt.read_to_string(&reply.path).unwrap();
        assert!(doc.contains("## Sessions"), "{doc}");
        assert!(doc.contains("member a"), "{doc}");
    }

    #[test]
    fn session_log_refuses_missing_bad_and_wrong_kind_targets() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");

        assert_eq!(session_log(&daemon, "ghost", None, "x").unwrap_err().0, ErrorKind::NotFound);
        let err = session_log(&daemon, "m", Some("abc"), "x").unwrap_err();
        assert!(err.1.contains("NNN"), "{err:?}");
        let err = session_log(&daemon, "m", Some("999"), "x").unwrap_err();
        assert_eq!(err.0, ErrorKind::NotFound, "{err:?}");
        // An empty line is a shape error.
        let err = session_log(&daemon, "m", Some("001"), "   ").unwrap_err();
        assert!(err.1.contains("line"), "{err:?}");
        // A task with a unit.
        let id = seed_task(&daemon, "fix-y");
        let err = session_log(&daemon, &id, Some("001"), "x").unwrap_err();
        assert!(err.1.contains("have no slices"), "{err:?}");
    }

    // ---- deferred ----------------------------------------------------------------

    #[test]
    fn deferred_writes_and_replaces_the_section_in_the_entry_doc() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");

        let reply = deferred(
            &daemon,
            "m",
            serde_json::json!([
                { "what": "run the two-device pair smoke", "expected": "the offer lands on the peer" },
                { "what": "verify the TUI pane", "expected": "the backlog tree renders" },
            ]),
        )
        .expect("deferred");
        assert_eq!(reply.path, "growlight/backlog/milestones/m/CLAUDE.md");

        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            let doc = wt.read_to_string(&reply.path).unwrap();
            assert!(doc.contains("## Deferred verification"), "{doc}");
            assert!(
                doc.contains("- run the two-device pair smoke — expected: the offer lands on the peer"),
                "{doc}"
            );
            assert!(doc.contains("— expected: the backlog tree renders"), "{doc}");
        }

        // A re-write replaces, never duplicates.
        deferred(
            &daemon,
            "m",
            serde_json::json!([ { "what": "only one now", "expected": "one bullet" } ]),
        )
        .expect("rewrite");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt.read_to_string(&reply.path).unwrap();
        assert_eq!(doc.matches("— expected:").count(), 1, "replaced in place: {doc}");
        assert!(!doc.contains("two-device pair smoke"), "{doc}");
    }

    #[test]
    fn deferred_lands_in_the_task_doc_and_refuses_empty_tests() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let id = seed_task(&daemon, "fix-z");
        let reply = deferred(
            &daemon,
            &id,
            serde_json::json!([ { "what": "on-device pass", "expected": "no regressions" } ]),
        )
        .expect("task deferred");
        assert_eq!(reply.path, "growlight/backlog/tasks/001-fix-z.md");

        let err = deferred(&daemon, &id, serde_json::json!([])).unwrap_err();
        assert!(err.1.contains("tests"), "{err:?}");
        let err = deferred(&daemon, &id, serde_json::json!([{ "what": "", "expected": "x" }])).unwrap_err();
        assert!(err.1.contains("non-empty"), "{err:?}");
    }

    // ---- fail-closed + CAS -------------------------------------------------------

    #[test]
    fn a_hand_edited_file_refuses_the_op_and_mints_no_commit() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        let before = commit_count(&daemon);

        // A hand-edit lands behind the worktree (the FUSE hand-edit shape).
        // In disk mode the op's own load sees the drift, so the refusal is the
        // semantic from-status guard; the pure stale-token `Conflict` refusal
        // is the same `apply` path `write::tests::cas_refuses_*` already
        // proves. Either way nothing is staged and no commit is minted.
        let current = loaded_slices(&daemon, "m").to_toml().unwrap();
        hand_write(
            garden.path(),
            &slices_file("m"),
            &current.replace("status = \"active\"", "status = \"done\""),
        );

        let err = set_status(&daemon, "m", Some("001"), "blocked").unwrap_err();
        assert!(err.1.contains("requires active"), "{err:?}");
        assert_eq!(commit_count(&daemon), before, "a refused write mints no commit");
        // The hand-edited bytes stand.
        let on_disk = std::fs::read_to_string(garden.path().join(slices_file("m"))).unwrap();
        assert!(on_disk.contains("status = \"done\""), "{on_disk}");
    }

    #[test]
    fn a_corrupt_v2_file_fails_closed_with_nothing_staged() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        let before = commit_count(&daemon);

        hand_write(garden.path(), QUEUE_FILE, "not toml {{{");

        // Every op fails closed on the corrupt file — an internal error, never
        // a fallback to an empty model.
        for err in [
            claim(&daemon, "m", Some("002")).unwrap_err(),
            set_status(&daemon, "m", None, "paused").unwrap_err(),
            follow_ups(&daemon, "m", None, 3).unwrap_err(),
            session_log(&daemon, "m", Some("001"), "x").unwrap_err(),
            deferred(&daemon, "m", serde_json::json!([{ "what": "w", "expected": "e" }])).unwrap_err(),
        ] {
            assert_eq!(err.0, ErrorKind::Internal, "{err:?}");
        }
        assert_eq!(commit_count(&daemon), before, "nothing staged");
    }

    // ---- addressing ----------------------------------------------------------------

    #[test]
    fn a_sub_milestone_identity_addresses_the_sub_tree_and_the_top_level_row() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queued_milestone(&daemon, "m");
        {
            let mut inner = daemon.inner.lock().unwrap();
            {
                let wt = WorkTree::new(&daemon, &inner);
                // The sub's own docs + slices.toml.
                wt.write(
                    &format!("{}/CLAUDE.md", milestone_path("m/sub-a")),
                    b"# backlog: m/sub-a\n\n## Mission\n\nsub work\n",
                )
                .unwrap();
            }
            crate::actions::commit_now(&mut inner, softfig_vcs::Intent::init("seed sub doc"))
                .unwrap();
            let model = SlicesToml::new(
                "m/sub-a".to_string(),
                vec![softfig_ipc::queue_v2::SliceItem {
                    kind: SliceKind::Slice,
                    id: "001".to_string(),
                    status: SliceStatus::Queued,
                    follow_ups: Some(0),
                }],
            );
            {
                let wt = WorkTree::new(&daemon, &inner);
                wt.write(
                    &format!("{}/slices/001-first.md", milestone_path("m/sub-a")),
                    b"# 001-first\n\nwork\n",
                )
                .unwrap();
            }
            crate::actions::growlight::v2::write::apply(
                &daemon,
                &mut inner,
                "queue_v2_updated",
                serde_json::json!({ "test": true }),
                &[FileWrite {
                    rel: slices_file("m/sub-a"),
                    expected: None,
                    bytes: model.to_toml().unwrap().into_bytes(),
                }],
                &[ViewWrite {
                    host: slices_view_host("m/sub-a"),
                    tag: SLICES_V2_TAG,
                    body: Some(slices_view(&model)),
                }],
                &ExtraWrites::NONE,
            )
            .expect("sub tree seeded");
        }

        // The claim addresses the sub tree by the nested identity, and the
        // entry row by its top-level component.
        claim(&daemon, "m", Some("001")).expect("claim top slice");
        claim(&daemon, "m/sub-a", Some("001")).expect("claim sub slice");
        let (queue, _) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].status, EntryStatus::Active, "the top-level row is active");
        assert_eq!(loaded_slices(&daemon, "m/sub-a").items[0].status, SliceStatus::Active);
        // The sub's close-out session-log lands in the sub's own sessions.md.
        let reply = session_log(&daemon, "m/sub-a", None, "completed · reasoning · member oc · $0.00")
            .expect("sub close-out log");
        assert_eq!(reply.path, "growlight/backlog/milestones/m/subs/sub-a/sessions.md");
    }

    // ---- view hosts (task 104) ---------------------------------------------

    /// Every `.md` under the garden, garden-relative, skipping keeperd's state.
    fn garden_docs(root: &std::path::Path) -> Vec<String> {
        fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap().map(Result::unwrap) {
                let path = e.path();
                if e.file_name() == ".softfig" {
                    continue;
                }
                if path.is_dir() {
                    walk(root, &path, out);
                } else if path.extension().is_some_and(|x| x == "md") {
                    out.push(path.strip_prefix(root).unwrap().to_string_lossy().into_owned());
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out
    }

    #[test]
    fn no_v2_write_adds_a_region_to_any_claude_md() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // Project, milestone (with its generated views), task, claim, a sub,
        // status and follow-up writes, and both kinds of session line.
        seed_running_milestone(&daemon, "m");
        let task = seed_task(&daemon, "fix-x");
        add_sub(&daemon, sub_args("m", "001", "deeper", false)).expect("add_sub");
        follow_ups(&daemon, "m", Some("002"), 1).expect("follow_ups");
        session_log(&daemon, "m", None, "completed · reasoning · member oc · $0.01").expect("close-out");
        session_log(&daemon, &task, None, "blocked · claude · member a · $0.00").expect("task log");

        let docs = garden_docs(garden.path());
        for rel in docs.iter().filter(|r| r.ends_with("CLAUDE.md")) {
            let text = std::fs::read_to_string(garden.path().join(rel)).unwrap();
            for tag in [QUEUE_V2_TAG, SLICES_V2_TAG] {
                assert!(!managed::has_region(&text, tag), "{rel} carries softfig:{tag}:\n{text}");
            }
        }
        // The views live in their own docs instead.
        let has = |rel: &str, tag| {
            let text = std::fs::read_to_string(garden.path().join(rel)).unwrap_or_default();
            managed::has_region(&text, tag)
        };
        assert!(has("growlight/backlog/queue.md", QUEUE_V2_TAG), "{docs:?}");
        assert!(has("growlight/backlog/milestones/m/slices.md", SLICES_V2_TAG), "{docs:?}");
        assert!(has("growlight/backlog/milestones/m/subs/deeper/slices.md", SLICES_V2_TAG), "{docs:?}");
        assert!(docs.iter().any(|r| r == "growlight/backlog/milestones/m/sessions.md"), "{docs:?}");
    }

    // ---- add_sub (slice 010) ----------------------------------------------

    fn add_sub(daemon: &Daemon, args: serde_json::Value) -> Result<QueueV2AddSubReply, (ErrorKind, String)> {
        let v = queue_v2_add_sub(daemon, args)?;
        Ok(serde_json::from_value(v).unwrap())
    }

    fn sub_args(milestone: &str, slice: &str, slug: &str, at_end: bool) -> serde_json::Value {
        serde_json::json!({
            "milestone": milestone,
            "slice": slice,
            "slug": slug,
            "title": format!("{slug} title"),
            "mission": "finish what the slice could not",
            "finish_criteria": "- [ ] it is done",
            "slices": [
                { "slug": "first", "title": "First", "body": "> Model: flash\n\nwork one" },
                { "slug": "second", "body": "work two" },
            ],
            "at_end": at_end,
        })
    }

    fn kinds(model: &SlicesToml) -> Vec<(SliceKind, String, SliceStatus)> {
        model.items.iter().map(|i| (i.kind, i.id.clone(), i.status)).collect()
    }

    #[test]
    fn add_sub_creates_the_sub_splits_the_slice_and_places_it_next_in_one_commit() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        let before = commit_count(&daemon);

        let reply = add_sub(&daemon, sub_args("m", "001", "deeper", false)).expect("add_sub");

        assert_eq!(commit_count(&daemon), before + 1, "one commit for the whole sub");
        assert_eq!(reply.milestone, "m/deeper");
        assert_eq!(reply.slices, vec!["001".to_string(), "002".to_string()]);
        assert_eq!(reply.path, "growlight/backlog/milestones/m/subs/deeper/CLAUDE.md");
        assert_eq!(
            kinds(&loaded_slices(&daemon, "m")),
            vec![
                (SliceKind::Slice, "001".to_string(), SliceStatus::Split),
                (SliceKind::Sub, "deeper".to_string(), SliceStatus::Queued),
                (SliceKind::Slice, "002".to_string(), SliceStatus::Queued),
            ],
            "the slice splits and the sub runs next, in front of the remaining items",
        );
        let sub = loaded_slices(&daemon, "m/deeper");
        assert_eq!(
            kinds(&sub),
            vec![
                (SliceKind::Slice, "001".to_string(), SliceStatus::Queued),
                (SliceKind::Slice, "002".to_string(), SliceStatus::Queued),
            ],
        );
        assert!(sub.items.iter().all(|i| i.follow_ups == Some(0)));

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let doc = wt.read_to_string(&reply.path).unwrap();
        assert!(doc.starts_with("# backlog: deeper title\n"), "{doc}");
        assert!(doc.contains("## Mission\n\nfinish what the slice could not"), "{doc}");
        assert!(doc.contains("## Finish criteria\n\n- [ ] it is done"), "{doc}");
        assert_eq!(
            softfig_ipc::model_choice::item_model_field(&doc),
            None,
            "the generated doc declares no model, so the sub inherits the parent's chain",
        );
        assert!(!managed::has_region(&doc, SLICES_V2_TAG), "the view is in slices.md: {doc}");
        let view = wt.read_to_string(&slices_view_host("m/deeper")).unwrap();
        let region = managed::region_body(&view, SLICES_V2_TAG).unwrap();
        assert!(region.contains("| slice | 001 | queued |"), "{region}");
        let parent = wt.read_to_string(&slices_view_host("m")).unwrap();
        let region = managed::region_body(&parent, SLICES_V2_TAG).unwrap();
        assert!(region.contains("| slice | 001 | split |") && region.contains("| sub | deeper | queued |"), "{region}");
        let first = wt
            .read_to_string("growlight/backlog/milestones/m/subs/deeper/slices/001-first.md")
            .unwrap();
        assert!(first.contains("> Model: flash") && first.contains("work one"), "{first}");
        assert!(wt.exists("growlight/backlog/milestones/m/subs/deeper/slices/002-second.md"));
        assert_eq!(
            wt.read_to_string("growlight/backlog/milestones/m/subs/deeper/slices/.seq").unwrap().trim(),
            "2",
        );
    }

    #[test]
    fn add_sub_with_at_end_appends_and_nests_one_more_level_only() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        add_sub(&daemon, sub_args("m", "001", "later", true)).expect("add_sub at end");
        assert_eq!(
            kinds(&loaded_slices(&daemon, "m")),
            vec![
                (SliceKind::Slice, "001".to_string(), SliceStatus::Split),
                (SliceKind::Slice, "002".to_string(), SliceStatus::Queued),
                (SliceKind::Sub, "later".to_string(), SliceStatus::Queued),
            ],
            "do_not_prioritize: the sub waits at the end of the list",
        );

        // One level down: a running slice of m/later splits into m/later/x …
        claim(&daemon, "m/later", Some("001")).expect("claim the sub's slice");
        let reply = add_sub(&daemon, sub_args("m/later", "001", "x", false)).expect("2 deep");
        assert_eq!(reply.path, "growlight/backlog/milestones/m/subs/later/subs/x/CLAUDE.md");
        // … and that is the §3.3 bound: m/later/x can't file m/later/x/y.
        claim(&daemon, "m/later/x", Some("001")).expect("claim 2 deep");
        let before = commit_count(&daemon);
        let err = add_sub(&daemon, sub_args("m/later/x", "001", "y", false)).unwrap_err();
        assert_eq!(err.0, ErrorKind::InvalidSlug, "{err:?}");
        assert_eq!(commit_count(&daemon), before);
    }

    #[test]
    fn add_sub_refuses_a_slice_that_is_not_running_a_taken_slug_and_reserved_lines() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        let before = commit_count(&daemon);

        // 002 is queued, not the running slice.
        let err = add_sub(&daemon, sub_args("m", "002", "s", false)).unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
        // A slug that is already an item id in the parent's list.
        let err = add_sub(&daemon, sub_args("m", "001", "002", false)).unwrap_err();
        assert_eq!(err.0, ErrorKind::PathAlreadyExists, "{err:?}");
        // A bad slug.
        let err = add_sub(&daemon, sub_args("m", "001", "Not_A_Slug", false)).unwrap_err();
        assert_eq!(err.0, ErrorKind::InvalidSlug, "{err:?}");
        // §6.7's backstop: a member's mission may not set the sub's model.
        let mut args = sub_args("m", "001", "s", false);
        args["mission"] = serde_json::json!("do it\n> Model: claude");
        let err = add_sub(&daemon, args).unwrap_err();
        assert!(err.0 == ErrorKind::BadArgs && err.1.starts_with("field_not_allowed: `mission`"), "{err:?}");
        let mut args = sub_args("m", "001", "s", false);
        args["slices"][1]["body"] = serde_json::json!("> Grants: ~/projects/x\n\nwork");
        let err = add_sub(&daemon, args).unwrap_err();
        assert!(err.1.starts_with("field_not_allowed: `slices[1].body`"), "{err:?}");
        // No slices.
        let mut args = sub_args("m", "001", "s", false);
        args["slices"] = serde_json::json!([]);
        assert_eq!(add_sub(&daemon, args).unwrap_err().0, ErrorKind::BadArgs);

        assert_eq!(commit_count(&daemon), before, "every refusal writes nothing");
        assert_eq!(loaded_slices(&daemon, "m").items[0].status, SliceStatus::Active);

        // A sub folder already on disk, though not in the list, is refused too.
        hand_write(garden.path(), "growlight/backlog/milestones/m/subs/orphan/CLAUDE.md", "# stray\n");
        let err = add_sub(&daemon, sub_args("m", "001", "orphan", false)).unwrap_err();
        assert_eq!(err.0, ErrorKind::PathAlreadyExists, "{err:?}");
        assert_eq!(loaded_slices(&daemon, "m").items[0].status, SliceStatus::Active);
    }

    #[test]
    fn set_status_closes_a_sub_only_once_its_tree_is_finished() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_running_milestone(&daemon, "m");
        add_sub(&daemon, sub_args("m", "001", "s", false)).expect("add_sub");
        claim(&daemon, "m/s", Some("001")).expect("claim");

        // Open items: refused, nothing written.
        let before = commit_count(&daemon);
        let err = set_status(&daemon, "m", Some("s"), "done").unwrap_err();
        assert!(err.0 == ErrorKind::BadArgs && err.1.starts_with("open_items:"), "{err:?}");
        assert_eq!(commit_count(&daemon), before);

        set_status(&daemon, "m/s", Some("001"), "done").expect("slice 001 done");
        claim(&daemon, "m/s", Some("002")).expect("claim 002");
        set_status(&daemon, "m/s", Some("002"), "deferred").expect("slice 002 deferred");

        // A sub closes to done | deferred only.
        let err = set_status(&daemon, "m", Some("s"), "blocked").unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
        // The sub item was never claimed: it closes from `queued`.
        let reply = set_status(&daemon, "m", Some("s"), "done").expect("close the sub");
        assert_eq!(reply.status, "done");
        assert_eq!(
            kinds(&loaded_slices(&daemon, "m")),
            vec![
                (SliceKind::Slice, "001".to_string(), SliceStatus::Split),
                (SliceKind::Sub, "s".to_string(), SliceStatus::Done),
                (SliceKind::Slice, "002".to_string(), SliceStatus::Queued),
            ],
        );
        let (queue, _) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].status, EntryStatus::Active, "the entry stays active work");
        // Closed is closed.
        let err = set_status(&daemon, "m", Some("s"), "deferred").unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
    }

    /// Pins the §3.5 session-log stamp's shape: exactly
    /// `YYYY-MM-DDTHH:MMZ` (17 bytes), so a change to any date-time
    /// formatting fails here instead of mangling a session-log line.
    #[test]
    fn session_ts_shape_is_minute_precision_rfc3339() {
        let ts = session_ts();
        assert_eq!(ts.len(), 17, "minute-precision RFC3339 must be 17 bytes, got {ts:?}");
        for (i, c) in ts.bytes().enumerate() {
            match i {
                4 | 7 => assert_eq!(c, b'-', "`-` separator at byte {i} in {ts:?}"),
                10 => assert_eq!(c, b'T', "`T` at byte 10 in {ts:?}"),
                13 => assert_eq!(c, b':', "`:` at byte 13 in {ts:?}"),
                16 => assert_eq!(c, b'Z', "`Z` at byte 16 in {ts:?}"),
                _ => assert!(c.is_ascii_digit(), "digit at byte {i} in {ts:?}"),
            }
        }
    }

    // ---- slice 004: queue_v2_re_record_bases ----------------------------

    fn re_record(
        daemon: &Daemon,
        entries: Vec<(&str, &str)>,
    ) -> Result<QueueV2ReRecordBasesReply, (ErrorKind, String)> {
        let v = queue_v2_re_record_bases(
            daemon,
            serde_json::json!({
                "entries": entries
                    .iter()
                    .map(|(e, b)| serde_json::json!({ "entry": e, "base": b }))
                    .collect::<Vec<_>>(),
            }),
        )?;
        Ok(serde_json::from_value(v).unwrap())
    }

    #[test]
    fn re_record_replaces_each_named_entry_base_in_one_commit() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut a = entry("a", Lane::Normal, EntryStatus::Queued);
        a.claimed = "2026-10-11T12:00:00Z".to_string();
        a.base = "abc123".to_string();
        let mut b = entry("b", Lane::Normal, EntryStatus::Queued);
        b.claimed = "2026-10-11T12:10:00Z".to_string();
        b.base = "def456".to_string();
        b.parent = "a".to_string();
        seed_queue_rows(&daemon, vec![a, b]);
        let before = commit_count(&daemon);

        let reply = re_record(&daemon, vec![("a", "111aaa"), ("b", "222bbb")]).expect("re-record");
        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit");
        assert!(!reply.hash.is_empty());

        let (queue, _) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].base, "111aaa");
        assert_eq!(queue.entries[1].base, "222bbb");
        // parent/claimed/status are untouched by a re-record.
        assert_eq!(queue.entries[1].parent, "a");
        assert_eq!(queue.entries[0].claimed, "2026-10-11T12:00:00Z");
        assert_eq!(queue.entries[0].status, EntryStatus::Queued);
    }

    #[test]
    fn re_record_refuses_an_unknown_entry_and_a_noop_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let mut a = entry("a", Lane::Normal, EntryStatus::Queued);
        a.base = "abc123".to_string();
        seed_queue_rows(&daemon, vec![a]);
        let before = commit_count(&daemon);

        // An unknown entry is refused, nothing written.
        let err = re_record(&daemon, vec![("ghost", "x")]).unwrap_err();
        assert_eq!(err.0, ErrorKind::NotFound, "{err:?}");
        assert_eq!(commit_count(&daemon), before, "a refusal mints no commit");

        // An all-no-op write (base already the given value) mints no commit.
        re_record(&daemon, vec![("a", "abc123")]).expect("no-op re-record");
        assert_eq!(commit_count(&daemon), before, "no commit for a no-op");
    }

    #[test]
    fn re_record_refuses_an_empty_entries_list() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_queue_rows(&daemon, vec![entry("a", Lane::Normal, EntryStatus::Queued)]);
        let err = re_record(&daemon, vec![]).unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
    }

    // ---- queue_v2_migrate_apply ------------------------------------------

    /// The converter's fixture (softfig-ipc `tests/fixtures/migrate/`): a
    /// live-shaped legacy backlog, its runtime batons and the answers that
    /// settle every call it raises.
    fn migrate_fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../softfig-ipc/tests/fixtures/migrate")
    }

    fn load_tree(root: &std::path::Path, dir: &std::path::Path, into: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                load_tree(root, &path, into);
            } else {
                let key = path.strip_prefix(root).unwrap().to_str().unwrap().to_string();
                into.insert(key, std::fs::read_to_string(&path).unwrap());
            }
        }
    }

    /// The fixture's legacy files as the CLI's dry run reads them: the garden
    /// half off disk, the batons the apply sends.
    fn fixture_files() -> migrate::LegacyFiles {
        let mut files = migrate::LegacyFiles::default();
        let root = migrate_fixture();
        load_tree(&root.join("garden"), &root.join("garden"), &mut files.garden);
        load_tree(&root.join("batons"), &root.join("batons"), &mut files.batons);
        files
    }

    /// Seed the fixture's legacy backlog into the garden as one commit; return
    /// the snapshot's version as the dry run prints it (the `--expect`).
    fn seed_legacy(daemon: &Daemon, garden: &std::path::Path) -> String {
        let files = fixture_files();
        for (rel, text) in &files.garden {
            hand_write(garden, rel, text);
        }
        let mut inner = daemon.inner.lock().unwrap();
        crate::actions::commit_now(&mut inner, softfig_vcs::Intent::init("seed legacy backlog")).unwrap();
        files.digest()
    }

    fn migrate_args(expect: &str, answers: bool) -> serde_json::Value {
        let batons = fixture_files().batons;
        let answers: migrate::Answers = match answers {
            true => toml::from_str(&std::fs::read_to_string(migrate_fixture().join("answers.toml")).unwrap())
                .unwrap(),
            false => migrate::Answers {
                schema: migrate::ANSWERS_SCHEMA_VERSION,
                class: Default::default(),
                call: Default::default(),
            },
        };
        serde_json::to_value(QueueV2MigrateApplyArgs { answers, expect: expect.to_string(), batons }).unwrap()
    }

    /// The version a dry run would print now: keeperd's own read of the garden
    /// (the bytes the mount serves, report 128) plus the fixture's batons.
    fn snapshot_version(daemon: &Daemon) -> String {
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(daemon, &inner);
        let garden = migrate_snapshot(&wt, &inner.layer_b).map_err(|e| e.1).unwrap().md;
        migrate::LegacyFiles { garden, batons: fixture_files().batons }.digest()
    }

    fn migrate_apply(daemon: &Daemon, args: serde_json::Value) -> Result<QueueV2MigrateApplyReply, (ErrorKind, String)> {
        queue_v2_migrate_apply(daemon, args).map(|v| serde_json::from_value(v).unwrap())
    }

    fn backlog_doc(garden: &std::path::Path) -> String {
        std::fs::read_to_string(garden.join(BACKLOG_DOC)).unwrap()
    }

    #[test]
    fn migrate_apply_writes_every_v2_file_in_one_commit_and_leaves_the_legacy_tables() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let expect = seed_legacy(&daemon, garden.path());
        let claude_docs = |root: &std::path::Path| -> Vec<(String, String)> {
            let mut docs: Vec<_> = garden_docs(root)
                .into_iter()
                .filter(|r| r.ends_with("CLAUDE.md"))
                .map(|r| {
                    let text = std::fs::read_to_string(root.join(&r)).unwrap();
                    (r, text)
                })
                .collect();
            docs.sort();
            docs
        };
        let before_claude = claude_docs(garden.path());

        let before = commit_count(&daemon);

        let reply = migrate_apply(&daemon, migrate_args(&expect, true)).unwrap();
        assert_eq!(commit_count(&daemon), before + 1, "one commit");

        // The commit is the new intent, carrying the CAS version + counts.
        {
            let inner = daemon.inner.lock().unwrap();
            let repo = inner.repo.as_ref().unwrap();
            let tip = repo.tip_of(TIP_REF).unwrap().unwrap();
            let head = &log::collect(repo.db(), tip).unwrap()[0];
            assert_eq!(head.intent, "queue_v2_migrated");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&head.payload).unwrap(),
                serde_json::json!({
                    "version": expect,
                    "entries": reply.entries,
                    "archived": reply.archived,
                    "slices": reply.slices,
                })
            );
        }

        // The written files are the plan the dry run computes.
        let fixture = {
            let files = fixture_files();
            let args: QueueV2MigrateApplyArgs = serde_json::from_value(migrate_args(&expect, true)).unwrap();
            migrate::plan(&migrate::read_legacy(&files).unwrap(), &args.answers, "2026-11-01T00:00:00Z")
        };
        let (queue, archive) = loaded_queue(&daemon);
        let ids = |q: &QueueToml| q.entries.iter().map(|e| e.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&queue), ids(&fixture.queue));
        assert_eq!(archive.entries.len(), fixture.archive.entries.len());
        assert_eq!((reply.entries, reply.archived), (fixture.queue.entries.len(), fixture.archive.entries.len()));
        assert_eq!(reply.slices, fixture.slices.len());
        assert!(reply.slices > 0, "the fixture has live milestones");
        for (milestone, slices) in &fixture.slices {
            assert_eq!(&loaded_slices(&daemon, milestone).items, &slices.items, "{milestone}");
            let doc = std::fs::read_to_string(garden.path().join(slices_view_host(milestone))).unwrap();
            assert!(managed::has_region(&doc, SLICES_V2_TAG), "{milestone}: slices view rendered");
        }
        assert_eq!(reply.batons, fixture.batons, "the caller's baton copies");

        // Legacy untouched: no `CLAUDE.md` changed at all (task 104) — the
        // views went to `queue.md` and each milestone's `slices.md`.
        assert!(before_claude.iter().any(|(r, _)| r == "growlight/backlog/CLAUDE.md"));
        assert_eq!(claude_docs(garden.path()), before_claude, "no CLAUDE.md changes");
        let view = std::fs::read_to_string(garden.path().join(queue_view_host())).unwrap();
        assert!(managed::has_region(&view, QUEUE_V2_TAG), "{view}");
        assert!(!garden.path().join("config/growlight.toml").exists(), "the switch is never written");

        // A second apply refuses: the v2 files exist now.
        let (kind, msg) = migrate_apply(&daemon, migrate_args(&expect, true)).unwrap_err();
        assert_eq!(kind, ErrorKind::PathAlreadyExists);
        assert!(msg.starts_with("v2_files_present: "), "{msg}");
        assert_eq!(commit_count(&daemon), before + 1);
    }

    /// F12: a commit that fails leaves nothing staged, so the failure is
    /// distinguishable from a landed apply and the same args retry cleanly.
    /// The failure is real: the object store is read-only, so the commit
    /// can't write its blobs.
    #[test]
    fn a_failed_migrate_commit_unstages_so_the_retry_applies() {
        use std::os::unix::fs::PermissionsExt;
        fn set_mode(dir: &std::path::Path, mode: u32) {
            for entry in walkdir_dirs(dir) {
                std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        fn walkdir_dirs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            let mut out = vec![dir.to_path_buf()];
            for e in std::fs::read_dir(dir).unwrap() {
                let path = e.unwrap().path();
                if path.is_dir() {
                    out.extend(walkdir_dirs(&path));
                }
            }
            out
        }
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let expect = seed_legacy(&daemon, garden.path());
        let before_doc = backlog_doc(garden.path());
        let before = commit_count(&daemon);
        let objects = garden.path().join(".softfig/objects");

        set_mode(&objects, 0o555);
        let failed = migrate_apply(&daemon, migrate_args(&expect, true));
        set_mode(&objects, 0o755);
        let (_, msg) = failed.unwrap_err();
        assert!(msg.ends_with("; nothing was committed and the staged files were put back"), "{msg}");
        assert_eq!(commit_count(&daemon), before, "nothing landed");
        assert!(!garden.path().join(QUEUE_FILE).exists(), "queue.toml unstaged");
        assert!(!garden.path().join(QUEUE_ARCHIVE_FILE).exists(), "queue-archive.toml unstaged");
        assert_eq!(backlog_doc(garden.path()), before_doc, "the backlog doc untouched");
        assert!(!garden.path().join(queue_view_host()).exists(), "queue.md unstaged");
        let fixture_slices = {
            let files = fixture_files();
            let args: QueueV2MigrateApplyArgs = serde_json::from_value(migrate_args(&expect, true)).unwrap();
            migrate::plan(&migrate::read_legacy(&files).unwrap(), &args.answers, "2026-11-01T00:00:00Z").slices
        };
        for (milestone, _) in &fixture_slices {
            assert!(!garden.path().join(slices_file(milestone)).exists(), "{milestone}: slices.toml unstaged");
            let host = slices_view_host(milestone);
            assert!(!garden.path().join(&host).exists(), "{host}: view unstaged");
        }
        assert_eq!(snapshot_version(&daemon), expect, "the tree is back at the dry run's snapshot");

        // The same args now apply, and a landed apply is what refuses.
        migrate_apply(&daemon, migrate_args(&expect, true)).unwrap();
        assert_eq!(commit_count(&daemon), before + 1);
        let (_, msg) = migrate_apply(&daemon, migrate_args(&expect, true)).unwrap_err();
        assert!(msg.starts_with("v2_files_present: "), "{msg}");
    }

    #[test]
    fn migrate_apply_refuses_before_any_write() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let expect = seed_legacy(&daemon, garden.path());
        let config = garden.path().join("config/growlight.toml");
        let refused = |args: serde_json::Value, code: &str, want: ErrorKind| {
            let at = commit_count(&daemon);
            let (kind, msg) = migrate_apply(&daemon, args).unwrap_err();
            assert_eq!(kind, want, "{code}: {msg}");
            assert!(msg.starts_with(&format!("{code}: ")), "{msg}");
            assert_eq!(commit_count(&daemon), at, "{code} mints no commit");
            assert!(!garden.path().join(QUEUE_FILE).exists(), "{code} stages nothing");
        };

        hand_write(garden.path(), "config/growlight.toml", "fleet_enabled = true\nqueue = \"legacy\"\n");
        refused(migrate_args(&expect, true), "fleet_armed", ErrorKind::BadArgs);
        hand_write(garden.path(), "config/growlight.toml", "queue = \"v2\"\n");
        refused(migrate_args(&expect, true), "switch_is_v2", ErrorKind::BadArgs);
        // A config the apply cannot read is refused too, never defaulted.
        hand_write(garden.path(), "config/growlight.toml", "queue = \"v3\"\n");
        let (kind, _) = migrate_apply(&daemon, migrate_args(&expect, true)).unwrap_err();
        assert_eq!(kind, ErrorKind::BadArgs);
        std::fs::remove_file(&config).unwrap();

        refused(migrate_args("0000", true), "legacy_changed", ErrorKind::Conflict);
        refused(migrate_args(&expect, false), "not_applicable", ErrorKind::BadArgs);

        // Any one v2 file — here a lone sub-milestone's slices.toml.
        let stray = "growlight/backlog/milestones/folder-grants/subs/x/slices.toml";
        hand_write(garden.path(), stray, "schema = 1\n");
        let (kind, msg) = migrate_apply(&daemon, migrate_args(&expect, true)).unwrap_err();
        assert_eq!(kind, ErrorKind::PathAlreadyExists);
        assert_eq!(msg, format!("v2_files_present: {stray}"));
        std::fs::remove_file(garden.path().join(stray)).unwrap();

        // With every gate clear the same args apply.
        migrate_apply(&daemon, migrate_args(&expect, true)).unwrap();
    }

    /// Report 132: `--expect` is a CAS over every file the plan reads, not the
    /// backlog doc alone. An item doc edited, a slice doc added or a baton
    /// moved between the dry run and the apply each refuse `legacy_changed`;
    /// put back, the same `--expect` applies.
    #[test]
    fn migrate_apply_refuses_when_any_snapshot_file_moved_since_the_dry_run() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let expect = seed_legacy(&daemon, garden.path());
        let at = commit_count(&daemon);
        let refused = |args: serde_json::Value, what: &str| {
            let (kind, msg) = migrate_apply(&daemon, args).unwrap_err();
            assert_eq!(kind, ErrorKind::Conflict, "{what}: {msg}");
            assert!(msg.starts_with("legacy_changed: the snapshot ("), "{what}: {msg}");
            assert!(msg.contains(&format!("not --expect {expect}")), "{what}: {msg}");
            assert_eq!(commit_count(&daemon), at, "{what} mints no commit");
            assert!(!garden.path().join(QUEUE_FILE).exists(), "{what} stages nothing");
        };

        let item = "growlight/backlog/milestones/roadeye-m2-daemon-core/CLAUDE.md";
        let doc = std::fs::read_to_string(garden.path().join(item)).unwrap();
        hand_write(garden.path(), item, &format!("{doc}\n> Fleet: no\n"));
        refused(migrate_args(&expect, true), "item doc edited");
        hand_write(garden.path(), item, &doc);

        let slice = "growlight/backlog/milestones/roadeye-m2-daemon-core/slices/999-late.md";
        hand_write(garden.path(), slice, "# Added after the dry run\n");
        refused(migrate_args(&expect, true), "slice doc added");
        std::fs::remove_file(garden.path().join(slice)).unwrap();

        let mut args = migrate_args(&expect, true);
        args["batons"]["baton.md"] = serde_json::json!("moved since the dry run\n");
        refused(args, "baton moved");

        assert_eq!(snapshot_version(&daemon), expect, "put back, the snapshot is the dry run's");
        migrate_apply(&daemon, migrate_args(&expect, true)).unwrap();
    }

    /// Report 128: the apply reads the backlog as the redacted view serves it,
    /// so a `> Fleet: no` inside a sealed region refuses the plan instead of
    /// migrating as `fleet = true` off the region's base64 ciphertext.
    #[test]
    fn migrate_apply_refuses_a_doc_whose_hold_sits_in_a_sealed_region() {
        use base64::Engine as _;
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_legacy(&daemon, garden.path());
        let rel = "growlight/backlog/milestones/roadeye-m2-daemon-core/CLAUDE.md";
        let session = daemon.inner.lock().unwrap().layer_b.session().unwrap();
        let ct = session.encrypt_layer_b_region(rel, "h", b"> Fleet: no").unwrap();
        let region = base64::engine::general_purpose::STANDARD.encode(ct);
        hand_write(garden.path(), rel, &format!("# roadeye\n\n<vault id=\"h\">{region}</vault>\n"));
        let at = commit_count(&daemon);
        let expect = snapshot_version(&daemon);

        let (kind, msg) = migrate_apply(&daemon, migrate_args(&expect, true)).unwrap_err();
        assert_eq!(kind, ErrorKind::BadArgs, "{msg}");
        assert!(msg.starts_with("not_applicable: 1 refusal(s)"), "{msg}");
        assert_eq!(commit_count(&daemon), at);
        assert!(!garden.path().join(QUEUE_FILE).exists());
    }

    /// A due restack `r` archived, with one live entry `a` left on the list.
    fn seed_due_restack(daemon: &Daemon) {
        let mut restack = entry("r", Lane::Urgent, EntryStatus::Active);
        restack.kind = EntryKind::Restack;
        restack.branch = String::new();
        let mut a = entry("a", Lane::Normal, EntryStatus::Queued);
        a.base = "abc123".to_string();
        seed_queue_rows(daemon, vec![restack, a]);
        set_status(daemon, "r", None, "done").expect("restack done");
    }

    fn settle(
        daemon: &Daemon,
        entries: serde_json::Value,
        settled: &[&str],
    ) -> Result<serde_json::Value, (ErrorKind, String)> {
        queue_v2_re_record_bases(daemon, serde_json::json!({ "entries": entries, "settled": settled }))
    }

    #[test]
    fn re_record_writes_the_bases_and_settles_the_row_in_one_commit() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_due_restack(&daemon);
        let before = commit_count(&daemon);

        settle(&daemon, serde_json::json!([{ "entry": "a", "base": "111aaa" }]), &["r"])
            .expect("re-record");

        assert_eq!(commit_count(&daemon), before + 1, "one commit for both files");
        let (queue, archive) = loaded_queue(&daemon);
        assert_eq!(queue.entries[0].base, "111aaa");
        assert!(!archive.entries[0].re_record_due);
    }

    /// A pass that found nothing to move still answers the row, or it would
    /// retry forever; repeating that answer changes nothing.
    #[test]
    fn re_record_settles_with_no_bases_and_a_repeat_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_due_restack(&daemon);
        let before = commit_count(&daemon);

        settle(&daemon, serde_json::json!([]), &["r"]).expect("settle");
        assert_eq!(commit_count(&daemon), before + 1);
        assert!(!loaded_queue(&daemon).1.entries[0].re_record_due);

        settle(&daemon, serde_json::json!([]), &["r"]).expect("repeat");
        assert_eq!(commit_count(&daemon), before + 1, "no commit for a no-op");
    }

    #[test]
    fn re_record_refuses_an_unknown_settled_row_and_writes_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        seed_due_restack(&daemon);
        let before = commit_count(&daemon);

        let err = settle(&daemon, serde_json::json!([{ "entry": "a", "base": "111aaa" }]), &["ghost"])
            .unwrap_err();

        assert_eq!(err.0, ErrorKind::NotFound, "{err:?}");
        assert_eq!(commit_count(&daemon), before, "a refusal mints no commit");
        assert_eq!(loaded_queue(&daemon).0.entries[0].base, "abc123");
    }
}
