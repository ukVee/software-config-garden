//! mcp-surgical-writes slice 004 — `unlink`, guarded whole-file deletion
//! (spec: `meta/spec-mcp-writes/spec-unlink.md`).
//!
//! The deliberate exception to the garden's "don't delete, archive" rule: a
//! file that deserves to be gone (inbox junk, a wrong-path duplicate) can
//! only be cut if nothing points at it. The **reference refusal** is the
//! safety heart — the file must not be listed in a daemon-managed
//! `<!-- softfig:index … -->` region ([`index::index_listings`]) and must
//! have no inbound `[[…]]` backlinks ([`backlinks::inbound_refs`]); either →
//! `ReferencedElsewhere`, naming the refs and suggesting `archive` (which
//! does the bookkeeping rewrite). Files only — no directories, no recursion.
//!
//! No vault refusal — deletion of a sealed blob is allowed: history keeps
//! every committed byte (`softfig show` / rollback recover it), and refusal
//! would make sealed-file cleanup impossible. When the deleted content WAS
//! vault-tagged the commit payload marks `sealed: true` so history shows it
//! mattered. Optional whole-file CAS (deleting-what-you-read); the removal
//! is one [`commit_now`] (`file_unlinked`) — a tree mutation, not a
//! filesystem shortcut — with the removed path registered for self-write
//! suppression ([`WorkTree::remove`]) and the backlink graph refreshed (so
//! no host keeps a dangling region row naming the deleted file). Thrash
//! registration on the whole-file target, like `patch_file`.

use softfig_ipc::verbs::{UnlinkArgs, UnlinkReply};
use softfig_ipc::ErrorKind;
use softfig_vcs::Intent;

use super::sections::{note_edit_for_thrash, resolve};
use super::{commit_now, WorkTree};
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{cas_check_whole_file, require_unlocked, HandlerResult};

pub fn unlink(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: UnlinkArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("unlink args: {e}")))?;
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let rel = resolve(&garden_root, &args.path)?;

    let sealed = {
        let wt = WorkTree::new(daemon, &inner);
        if wt.is_dir(&rel) {
            return Err((
                ErrorKind::BadArgs,
                format!(
                    "{rel}: is a directory — unlink is files-only (no recursion); \
                     `archive` moves trees"
                ),
            ));
        }
        if !wt.exists(&rel) {
            return Err((ErrorKind::NotFound, format!("{rel}: not found")));
        }
        cas_check_whole_file(&wt, &rel, &args.expected_version)?;
        // Reference refusal — the safety heart: an index row or an inbound
        // backlink means something points here, so this isn't a leaf.
        let mut refs = super::index::index_listings(&wt, &inner, &rel);
        refs.extend(super::backlinks::inbound_refs(&wt, &inner, &rel));
        if !refs.is_empty() {
            return Err(referenced_err(&rel, &refs));
        }
        deleted_was_vault_tagged(&wt, &inner, &rel)
    };

    {
        let wt = WorkTree::new(daemon, &inner);
        // Disk mode marks the path self-suppressed so the watcher doesn't
        // re-fire; FUSE mode stages a removal captured by the next commit.
        wt.remove(&rel)?;
        // Drop the deleted file from the backlink graph so no doc keeps a
        // dangling region row naming it (best-effort, folded into the commit).
        super::backlinks::refresh_all(&wt, &inner);
    }

    let mut payload = serde_json::json!({ "path": rel });
    if sealed {
        payload["sealed"] = serde_json::json!(true);
    }
    let intent = Intent::new("file_unlinked", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    let reply = serde_json::to_value(UnlinkReply {
        path: rel.clone(),
        hash: hash.to_string(),
    })
    .unwrap();
    note_edit_for_thrash(daemon, inner, &rel, None, args.editor.as_deref());
    Ok(reply)
}

fn referenced_err(rel: &str, refs: &[String]) -> (ErrorKind, String) {
    (
        ErrorKind::ReferencedElsewhere,
        format!(
            "{rel}: referenced elsewhere — {}\nunlink only cuts unreferenced leaves; use \
             `archive` instead (it rewrites the references)",
            refs.join(", ")
        ),
    )
}

/// Whether the deleted working-tree content was vault-tagged — whole-file
/// sealed, or carrying an inline `<vault>` region (malformed tags count:
/// fail-closed toward `sealed: true`). The commit payload's `sealed` flag
/// comes from here; the deletion itself never refuses on vaults.
fn deleted_was_vault_tagged(wt: &WorkTree, inner: &DaemonInner, rel: &str) -> bool {
    if inner.layer_b.snapshot().is_sealed(rel) {
        return true;
    }
    let Some(bytes) = wt.read(rel) else {
        return false;
    };
    let Some(session) = inner.session.as_ref() else {
        return false;
    };
    let parser = crate::layer_b::regions::parser_for(rel);
    !matches!(
        crate::layer_b::regions::parse(parser, &bytes, session, rel),
        Ok(spans) if spans.is_empty()
    )
}
