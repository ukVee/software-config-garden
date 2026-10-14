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
//!   `## Sessions`;
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
//! `paused`/`blocked`/`deferred`/`queued`, is cleared in the same commit,
//! and the reply's `status` reports what actually landed. One exception: a
//! `done` close-out archives the row and the pending request dies with it
//! (the work is finished; parking it is moot). `pending_status` is not a
//! §3.1 invariant — it parses, and the boundary ops act on it only at the
//! `active → …` transition.

use softfig_ipc::queue_v2::{
    sub_depth, sub_doc_violation, ArchivedEntry, EntryKind, EntryStatus, FinalStatus,
    QueueRefusal, SliceItem, SliceKind, SliceStatus, SlicesToml, SubSliceText,
    QUEUE_ARCHIVE_FILE,
};
use softfig_ipc::verbs::{
    DaemonStatusArg, QueueV2AddSubArgs, QueueV2AddSubReply, QueueV2ClaimArgs, QueueV2ClaimReply,
    QueueV2DeferredArgs,
    QueueV2DeferredReply, QueueV2FollowUpsArgs, QueueV2FollowUpsReply, QueueV2SessionLogArgs,
    QueueV2SessionLogReply, QueueV2SetStatusArgs, QueueV2SetStatusReply,
};
use softfig_ipc::ErrorKind;

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

/// The unit doc's garden-relative path for `entry`/`unit` (the `## Sessions`
/// and `## Deferred verification` target, §3.5/§6.5): a milestone's
/// `CLAUDE.md` for a close-out, its `slices/NNN-<slug>.md` for a unit (the
/// NNN resolves through the folder, since `slices.toml` carries no slug), a
/// task's or restack's `tasks/NNN-<slug>.md` otherwise.
fn unit_doc_rel(
    wt: &WorkTree,
    kind: EntryKind,
    entry: &str,
    unit: Option<&str>,
) -> Result<String, (ErrorKind, String)> {
    match kind {
        EntryKind::Milestone => match unit {
            None => Ok(format!("{}/CLAUDE.md", milestone_path(entry))),
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
    let ts = conventions::now_rfc3339();
    format!("{}Z", &ts[..16])
}

// ---- queue_v2_claim ------------------------------------------------------

pub fn queue_v2_claim(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: QueueV2ClaimArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("queue_v2_claim args: {e}")))?;
    if args.entry.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "entry must be non-empty".to_string()));
    }
    if let Some(u) = args.unit.as_deref() {
        if u.trim().is_empty() {
            return Err((ErrorKind::BadArgs, "unit must be non-empty".to_string()));
        }
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
    let entry_changed = match queue.entries[eidx].status {
        EntryStatus::Queued | EntryStatus::Paused => {
            queue.entries[eidx].status = EntryStatus::Active;
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
    // second entry in a repo `active` — invariant 5 refuses it here).
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
    if let Some(u) = args.unit.as_deref() {
        if u.trim().is_empty() {
            return Err((ErrorKind::BadArgs, "unit must be non-empty".to_string()));
        }
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
                    archive.entries.push(ArchivedEntry {
                        row,
                        finished: conventions::now_rfc3339(),
                        final_status: FinalStatus::Done,
                        reason: None,
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
                    // requested status and is cleared here.
                    let new = entry_status_of(other).expect("done/split handled above");
                    let pending_was = queue.entries[eidx].pending_status.is_some();
                    let applied = queue.entries[eidx].pending_status.take().unwrap_or(new);
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
    if let Some(u) = args.unit.as_deref() {
        if u.trim().is_empty() {
            return Err((ErrorKind::BadArgs, "unit must be non-empty".to_string()));
        }
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
        let rel = unit_doc_rel(&wt, kind, &args.entry, args.unit.as_deref())?;
        let (content, version) = load_unit_doc(&wt, &inner, &rel)?;
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
            expected: Some(version),
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
         its slices run in the order of the derived table below, and it is done when its \
         close-out completes.\n\n\
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

    let doc_rel = slices_view_host(&identity);
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
            host: doc_rel.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::growlight::queue_verbs::{queue_add_entry, queue_add_project, queue_update_entry, slice_update};
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
        // Close-out: the milestone's own CLAUDE.md.
        let reply = session_log(&daemon, "m", None, "deferred · reasoning · member oc · $0.02")
            .expect("close-out log");
        assert_eq!(reply.path, "growlight/backlog/milestones/m/CLAUDE.md");

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
        // The sub's close-out session-log lands in the sub's own CLAUDE.md.
        let reply = session_log(&daemon, "m/sub-a", None, "completed · reasoning · member oc · $0.00")
            .expect("sub close-out log");
        assert_eq!(reply.path, "growlight/backlog/milestones/m/subs/sub-a/CLAUDE.md");
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
        let region = managed::region_body(&doc, SLICES_V2_TAG).unwrap();
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
}
