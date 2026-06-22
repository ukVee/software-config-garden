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

use super::{commit_now, conventions, WorkTree};
use crate::daemon::Daemon;
use crate::handlers::{require_unlocked, HandlerResult};
use crate::migrate::{archive_bucket, monolith_target, plan_split, Monolith};

pub fn migrate_split(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: MigrateSplitArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("migrate_split args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    // Discovery is read-only; run it against the worktree (in FUSE mode the
    // in-memory tree, never a self-walk of the mount under `inner`).
    let (candidates, raw_skips) = {
        let wt = WorkTree::new(daemon, &inner);
        discover(&wt)
    };
    let mut skipped: Vec<SplitSkip> = raw_skips
        .into_iter()
        .map(|(path, reason)| SplitSkip { path, reason })
        .collect();
    let date = conventions::today_hyphen();
    let mut splits = Vec::new();

    for cand in candidates {
        let content = {
            let wt = WorkTree::new(daemon, &inner);
            wt.read_to_string(&cand.path)
        };
        let Some(content) = content else {
            skipped.push(SplitSkip {
                path: cand.path,
                reason: "read failed".into(),
            });
            continue;
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
        let basename = Path::new(&cand.path)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or((ErrorKind::Internal, "monolith has no basename".into()))?;
        let archived_rel = format!("journal/archive/{}/{}", archive_bucket(&cand.folder), basename);

        {
            let wt = WorkTree::new(daemon, &inner);
            for (filename, body) in &plan.notes {
                wt.write(&format!("{}/{filename}", cand.folder), body.as_bytes())?;
            }
            wt.write(
                &format!("{}/{}", cand.folder, conventions::SEQ_FILE),
                format!("{}\n", plan.seq).as_bytes(),
            )?;
            wt.rename(&cand.path, &archived_rel)?;

            // Mirror add_note + archive upkeep: index the new folder, repoint
            // inbound refs at the archived monolith, recompute the backlink graph
            // — all folded into this commit (best-effort, never blocks the split).
            super::index::refresh_folder_index(&wt, &inner, &cand.folder);
            super::backlinks::rewrite_refs_to_archived(&wt, &inner, &cand.path, &archived_rel);
            super::backlinks::refresh_all(&wt, &inner);
        }

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

/// Worktree-backed mirror of [`crate::migrate::discover_monoliths`]: find the
/// splittable `notes.md` / `troubleshooting.md` monoliths (target folder absent)
/// plus the skipped ones (folder already exists), reading the in-memory tree in
/// FUSE mode so discovery never self-walks the mount under `inner`.
fn discover(wt: &WorkTree) -> (Vec<Monolith>, Vec<(String, String)>) {
    let mut files = Vec::new();
    collect_files(wt, "", &mut files);
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    for rel in files {
        if let Some((folder, _kind)) = monolith_target(&rel) {
            if wt.exists(&folder) {
                skipped.push((rel, format!("target folder {folder}/ already exists")));
            } else {
                found.push(Monolith { path: rel, folder });
            }
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    skipped.sort();
    (found, skipped)
}

/// Every file repo-path under `dir_rel`, skipping `.softfig/` and the
/// `journal/archive/` graveyard — matching `discover_monoliths`' `walk_tree`.
fn collect_files(wt: &WorkTree, dir_rel: &str, out: &mut Vec<String>) {
    for entry in wt.read_dir(dir_rel) {
        let rel = if dir_rel.is_empty() {
            entry.name.clone()
        } else {
            format!("{dir_rel}/{}", entry.name)
        };
        if entry.is_dir {
            if entry.name == ".softfig" || rel == "journal/archive" {
                continue;
            }
            collect_files(wt, &rel, out);
        } else {
            out.push(rel);
        }
    }
}
