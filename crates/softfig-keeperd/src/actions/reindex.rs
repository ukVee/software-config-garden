//! `migrate_reindex` — task 060's re-runnable index sweep.
//!
//! `softfig migrate reindex [--apply]` re-derives every
//! `<!-- softfig:index <folder> -->` table in every host `CLAUDE.md` from the
//! numbered docs it summarizes, and commits one `index_reindexed` over every
//! host that drifted. Without `--apply` it is a read-only report.
//!
//! Every write verb already re-derives the tables it can invalidate (see
//! [`super::index`]), so on a garden kept by a current daemon the sweep finds
//! nothing. It exists for drift that arrived by a path no verb sees — a garden
//! last written by a pre-060 daemon (the backfill), or a hand edit straight
//! through the FUSE mount, which the watcher commits as `manual_edit` without
//! any index upkeep. The derivation is a fixed point, so a second run reports
//! no regions and commits nothing.

use softfig_ipc::verbs::{MigrateReindexArgs, MigrateReindexReply};
use softfig_ipc::ErrorKind;
use softfig_vcs::Intent;

use super::{commit_now, WorkTree};
use crate::daemon::Daemon;
use crate::handlers::{require_unlocked, HandlerResult};

pub fn migrate_reindex(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: MigrateReindexArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("migrate_reindex args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    // Planning reads the worktree (in FUSE mode the in-memory tree, never a
    // self-walk of the mount under `inner`).
    let (hosts, skipped) = {
        let wt = WorkTree::new(daemon, &inner);
        super::index::plan_reindex(&wt, &inner)
    };
    let regions: Vec<_> = hosts.iter().flat_map(|h| h.regions.clone()).collect();

    let mut hash = None;
    if args.apply && !hosts.is_empty() {
        {
            // Planning already ran `check_write` over every host, so a write
            // here can only fail on I/O. If one does, restore the hosts
            // written before it: the sweep is all-or-nothing, and a staged
            // half would otherwise ride the next unrelated commit under the
            // wrong intent (review 031 gap 3).
            let wt = WorkTree::new(daemon, &inner);
            for (i, h) in hosts.iter().enumerate() {
                if let Err(e) = wt.write(&h.host, h.content.as_bytes()) {
                    for done in &hosts[..i] {
                        let _ = wt.write(&done.host, done.original.as_bytes());
                    }
                    return Err(e);
                }
            }
        }
        let payload = serde_json::json!({
            "hosts": hosts.iter().map(|h| h.host.as_str()).collect::<Vec<_>>(),
            "regions": regions.len(),
        });
        let intent = Intent::new("index_reindexed", payload)
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        hash = Some(commit_now(&mut inner, intent)?.to_string());
    }

    Ok(serde_json::to_value(MigrateReindexReply {
        applied: args.apply,
        regions,
        skipped,
        hash,
    })
    .unwrap())
}
