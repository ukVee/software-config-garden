//! `migrate_config` — one-time lift of the daemon's per-garden state out of the
//! local `.softfig/` files into the in-garden `config/` dir.
//!
//! `softfig migrate config [--apply]` migrates two files in **one**
//! `config_migrated` commit:
//!
//! * `config/keeper.toml` ← the post-unlock policy half of the `.softfig/`
//!   pointer (`[net]`/`[relay]`/`[replica]`/`[reveal]`; defaults for a
//!   born-minimal pointer).
//! * `config/peers.toml` ← the **membership** of the legacy `.softfig/peers.toml`
//!   trust ring (endpoints stripped — those stay in the volatile sidecar). A
//!   garden that never paired has no legacy ring, so peers migration is a no-op
//!   (we don't create an empty file).
//!
//! Each file is independent: a re-run that finds one already present skips it
//! and migrates the other (the reply's `migrated` / `skipped` lists carry the
//! partial state). Without `--apply` it's a dry run — report, write nothing.
//!
//! The pointer is **not** rewritten. While the daemon runs, the garden-root
//! pointer is shadowed by the FUSE mount; and once `config/keeper.toml` exists
//! the unlock overlay gives it precedence (see `handlers::apply_garden_config`),
//! so any policy still in the pointer is inert. `state_root` and `[growlight]
//! allow_relock` stay in the pointer by design.

use softfig_ipc::verbs::{MigrateConfigArgs, MigrateConfigReply};
use softfig_ipc::ErrorKind;
use softfig_net::endpoint_cache::{endpoint_cache_path, EndpointCache};
use softfig_net::ring::{ring_path, Ring, RING_FILE};
use softfig_vcs::Intent;

use super::{commit_now, WorkTree};
use crate::daemon::Daemon;
use crate::handlers::{require_unlocked, HandlerResult};
use crate::keeper_toml::{GardenConfig, KeeperToml, CONFIG_DIR, KEEPER_TOML};

pub fn migrate_config(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: MigrateConfigArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("migrate_config args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    let mut migrated: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    // Planned writes: (garden-relative path, bytes). Built before any IO so a
    // dry run can report without touching the tree.
    let mut writes: Vec<(String, Vec<u8>)> = Vec::new();
    // The legacy ring whose endpoints we re-seed into the sidecar on apply (so
    // reconnect-after-restart survives the migration). `None` ⇒ no peers move.
    let mut peers_legacy_ring: Option<Ring> = None;

    let keeper_rel = format!("{CONFIG_DIR}/{KEEPER_TOML}");
    let peers_rel = format!("{CONFIG_DIR}/{RING_FILE}");

    {
        let wt = WorkTree::new(daemon, &inner);

        // --- config/keeper.toml (policy) ---
        if wt.exists(&keeper_rel) {
            skipped.push(keeper_rel.clone());
        } else {
            let pointer = KeeperToml::load(&state_dir).map_err(|e| {
                (
                    ErrorKind::Io,
                    format!("read pointer keeper.toml at {}: {e}", state_dir.display()),
                )
            })?;
            let toml = GardenConfig::from_keeper(&pointer)
                .to_toml()
                .map_err(|e| (ErrorKind::Internal, format!("serialize keeper config: {e}")))?;
            writes.push((keeper_rel.clone(), toml.into_bytes()));
            migrated.push(keeper_rel.clone());
        }

        // --- config/peers.toml (membership) ---
        if wt.exists(&peers_rel) {
            skipped.push(peers_rel.clone());
        } else {
            let legacy = ring_path(&state_dir);
            if legacy.exists() {
                // `Ring::load` re-verifies every attestation — a tampered legacy
                // ring is rejected here, not silently carried into the garden.
                let ring = Ring::load(&legacy)
                    .map_err(|e| (ErrorKind::Io, format!("load legacy peers.toml: {e}")))?;
                if !ring.is_empty() {
                    let toml = ring
                        .to_membership_toml()
                        .map_err(|e| (ErrorKind::Internal, format!("serialize membership: {e}")))?;
                    writes.push((peers_rel.clone(), toml.into_bytes()));
                    migrated.push(peers_rel.clone());
                    peers_legacy_ring = Some(ring);
                }
                // An empty legacy ring → nothing worth a file.
            }
            // No legacy ring (never paired) → peers migration is a no-op.
        }

        // Apply: stage every planned file through the worktree (mount-safe in
        // FUSE mode); the single `config_migrated` commit below folds them in.
        if args.apply && !writes.is_empty() {
            for (rel, bytes) in &writes {
                wt.write(rel, bytes)?;
            }
        }
    }

    // Dry run, or nothing left to migrate: report, commit nothing.
    if !args.apply || writes.is_empty() {
        return reply(migrated, skipped, false, None);
    }

    let payload = serde_json::json!({
        "summary": format!("migrated config: {}", migrated.join(", ")),
        "paths": migrated.clone(),
    });
    let intent = Intent::new("config_migrated", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    // Re-seed the volatile endpoint sidecar from the legacy ring (never
    // committed) so a migrated, already-paired garden keeps its peers reachable
    // across the next restart without waiting on a fresh mDNS sighting.
    if let Some(ring) = peers_legacy_ring {
        if let Err(e) = EndpointCache::capture(&ring).save(&endpoint_cache_path(&state_dir)) {
            eprintln!("keeperd: migrate config: endpoint sidecar seed: {e}");
        }
    }

    reply(migrated, skipped, true, Some(hash.to_string()))
}

fn reply(
    migrated: Vec<String>,
    skipped: Vec<String>,
    applied: bool,
    hash: Option<String>,
) -> HandlerResult {
    Ok(serde_json::to_value(MigrateConfigReply {
        migrated,
        skipped,
        applied,
        hash,
    })
    .unwrap())
}
