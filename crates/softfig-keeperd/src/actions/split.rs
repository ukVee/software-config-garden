//! `migrate_split` — Slice 1's one-time production trigger.
//!
//! `softfig migrate split [--apply]` rewrites every legacy `notes.md` /
//! `troubleshooting.md` monolith in the working tree into its sibling
//! accretive folder of numbered `NNN-slug.md` notes, archives the monolith,
//! and commits one `monolith_split` per file. Without `--apply` it's a
//! read-only dry run: discover + plan, commit nothing.
//!
//! The pure transform ([`crate::migrate::plan_split`]) and the path addressing
//! ([`crate::migrate::discover_monoliths`]) live in `migrate`; this module is
//! the daemon orchestration. It reuses the same materialize-folder / archive /
//! index+backlinks / commit machinery as `add_note` + `archive`, so a split is
//! indistinguishable from having created the notes by hand.

use std::path::Path;

use softfig_vcs::Intent;
use softfig_ipc::verbs::{MigrateSplitArgs, MigrateSplitReply, SplitOutcome, SplitSkip};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, write_file};
use crate::daemon::Daemon;
use crate::handlers::{require_unlocked, HandlerResult};
use crate::migrate::{archive_bucket, discover_monoliths, plan_split};

pub fn migrate_split(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: MigrateSplitArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("migrate_split args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let (candidates, raw_skips) = discover_monoliths(&garden_root);
    let mut skipped: Vec<SplitSkip> = raw_skips
        .into_iter()
        .map(|(path, reason)| SplitSkip { path, reason })
        .collect();
    let date = conventions::today_hyphen();
    let mut splits = Vec::new();

    for cand in candidates {
        let from_abs = garden_root.join(&cand.path);
        let content = match std::fs::read_to_string(&from_abs) {
            Ok(c) => c,
            Err(e) => {
                skipped.push(SplitSkip {
                    path: cand.path,
                    reason: format!("read failed: {e}"),
                });
                continue;
            }
        };
        let plan = plan_split(&content, &date);
        if plan.notes.is_empty() {
            skipped.push(SplitSkip {
                path: cand.path,
                reason: "no level-2 (`## `) sections to split".into(),
            });
            continue;
        }
        let notes = plan.notes.len();

        if !args.apply {
            splits.push(SplitOutcome {
                from: cand.path,
                folder: cand.folder,
                notes,
                archived_to: None,
                hash: None,
            });
            continue;
        }

        // ---- apply: materialize the folder, archive the monolith, commit ----
        let folder_abs = garden_root.join(&cand.folder);
        for (filename, body) in &plan.notes {
            let note_abs = folder_abs.join(filename);
            daemon.mark_self_write(note_abs.clone());
            write_file(&note_abs, body.as_bytes())?;
        }
        let seq_abs = folder_abs.join(conventions::SEQ_FILE);
        daemon.mark_self_write(seq_abs.clone());
        write_file(&seq_abs, format!("{}\n", plan.seq).as_bytes())?;

        let basename = Path::new(&cand.path)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or((ErrorKind::Internal, "monolith has no basename".into()))?;
        let archived_rel =
            format!("journal/archive/{}/{}", archive_bucket(&cand.folder), basename);
        let archived_abs = garden_root.join(&archived_rel);
        if let Some(parent) = archived_abs.parent() {
            std::fs::create_dir_all(parent).map_err(|e| (ErrorKind::Io, e.to_string()))?;
        }
        daemon.mark_self_write(from_abs.clone());
        daemon.mark_self_write(archived_abs.clone());
        std::fs::rename(&from_abs, &archived_abs)
            .map_err(|e| (ErrorKind::Io, format!("archive {}: {e}", cand.path)))?;

        // Mirror add_note + archive upkeep: index the new folder, repoint
        // inbound refs at the archived monolith, recompute the backlink graph
        // — all folded into this commit (best-effort, never blocks the split).
        super::index::refresh_folder_index(daemon, &inner, &garden_root, &cand.folder);
        super::backlinks::rewrite_refs_to_archived(
            daemon,
            &inner,
            &garden_root,
            &cand.path,
            &archived_rel,
        );
        super::backlinks::refresh_all(daemon, &inner, &garden_root);

        let payload = serde_json::json!({
            "from": cand.path,
            "folder": cand.folder,
            "to": archived_rel,
            "notes": notes,
        });
        let intent = Intent::new("monolith_split", payload)
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        let hash = commit_now(&mut inner, intent)?;

        splits.push(SplitOutcome {
            from: cand.path,
            folder: cand.folder,
            notes,
            archived_to: Some(archived_rel),
            hash: Some(hash.to_string()),
        });
    }

    Ok(serde_json::to_value(MigrateSplitReply {
        applied: args.apply,
        splits,
        skipped,
    })
    .unwrap())
}
