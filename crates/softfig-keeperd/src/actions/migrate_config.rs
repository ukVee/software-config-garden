//! `migrate_config` — one-time lift of the post-unlock daemon policy out of the
//! local `.softfig/keeper.toml` pointer into the in-garden `config/keeper.toml`.
//!
//! `softfig migrate config [--apply]` reads whatever `[net]`/`[relay]`/
//! `[replica]`/`[reveal]` the pointer carries (defaults for a born-minimal
//! pointer), writes them into the garden's `config/keeper.toml`, and commits one
//! `config_migrated`. Without `--apply` it's a dry run: report the path, write
//! nothing.
//!
//! The pointer is **not** rewritten. While the daemon runs, the garden-root
//! pointer is shadowed by the FUSE mount; and once `config/keeper.toml` exists
//! the unlock overlay gives it precedence (see `handlers::apply_garden_config`),
//! so any policy still sitting in the pointer is inert. `state_root` and
//! `[growlight] allow_relock` stay in the pointer by design.

use softfig_ipc::verbs::{MigrateConfigArgs, MigrateConfigReply};
use softfig_ipc::ErrorKind;
use softfig_vcs::Intent;

use super::{commit_now, write_file};
use crate::daemon::Daemon;
use crate::handlers::{require_unlocked, HandlerResult};
use crate::keeper_toml::{GardenConfig, KeeperToml, CONFIG_DIR};

pub fn migrate_config(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: MigrateConfigArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("migrate_config args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let state_dir = inner.config.state_dir().to_path_buf();

    let rel_path = format!("{CONFIG_DIR}/{}", crate::keeper_toml::KEEPER_TOML);
    let abs_path = GardenConfig::path(&garden_root);

    // Idempotent: a garden that already has config/keeper.toml is done.
    if abs_path.exists() {
        return reply(rel_path, false, true, None);
    }

    // Lift the policy half of the pointer (defaults for a minimal pointer).
    let pointer = KeeperToml::load(&state_dir).map_err(|e| {
        (
            ErrorKind::Io,
            format!("read pointer keeper.toml at {}: {e}", state_dir.display()),
        )
    })?;
    let garden_cfg = GardenConfig::from_keeper(&pointer);
    let toml = garden_cfg
        .to_toml()
        .map_err(|e| (ErrorKind::Internal, format!("serialize config: {e}")))?;

    if !args.apply {
        return reply(rel_path, false, false, None);
    }

    daemon.mark_self_write(abs_path.clone());
    write_file(&abs_path, toml.as_bytes())?;

    let payload = serde_json::json!({ "path": rel_path });
    let intent = Intent::new("config_migrated", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    reply(rel_path, true, false, Some(hash.to_string()))
}

fn reply(path: String, applied: bool, already: bool, hash: Option<String>) -> HandlerResult {
    Ok(serde_json::to_value(MigrateConfigReply {
        path,
        applied,
        already,
        hash,
    })
    .unwrap())
}
