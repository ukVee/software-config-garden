//! `softfig migrate {prepare, finalize}` + no-arg status.
//!
//! The slice scope locks a non-destructive three-phase flow:
//!
//! * **prepare** — copies `.softfig/` to `~/.local/share/softfig/<repo_id>/`,
//!   writes `keeper.toml` with the new `state_root`. No deletion. Refuses
//!   if a daemon is reachable on the keeperd socket (the daemon would
//!   become inconsistent mid-copy).
//! * **start** — `softfig daemon start` picks up the new `keeper.toml`
//!   and mounts FUSE. No CLI verb here; the daemon's existing start
//!   path is sufficient.
//! * **finalize** — IPC verb to the running M2a daemon. Daemon
//!   orchestrates unmount → delete plaintext → delete old `.softfig/`
//!   → remount.
//!
//! No-arg `softfig migrate` prints phase status (read keeper.toml +
//! filesystem state, report what `finalize` would do).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use softfig_ipc::{
    runtime_socket_path,
    verbs::{op, MigrateFinalizeArgs, MigrateFinalizeReply, MigrateSplitArgs, MigrateSplitReply},
    ClientError,
};
use softfig_vault::{discover_garden, Vault};
use softfig_vcs::Repo;

use crate::cmd_daemon::try_daemon_call;

const KEEPER_TOML: &str = "keeper.toml";

#[derive(Subcommand, Debug)]
pub enum MigrateCmd {
    /// Phase 1: copy `.softfig/` to the XDG state dir and write
    /// `keeper.toml`. No deletion. Refuses if a daemon is reachable.
    Prepare(PrepareArgs),
    /// Phase 3: ask the running M2a daemon to delete the orphan
    /// plaintext working tree and the legacy `.softfig/` (best-effort)
    /// and remount FUSE.
    Finalize(FinalizeArgs),
    /// One-time small-files split: rewrite every `notes.md` /
    /// `troubleshooting.md` monolith into its sibling numbered-note folder
    /// and archive the original. Dry-run preview unless `--apply`.
    Split(SplitArgs),
}

#[derive(Args, Debug)]
pub struct PrepareArgs {
    /// Garden root. Defaults to discovered `.softfig/` ancestor.
    #[arg(long)]
    pub garden: Option<PathBuf>,
    /// Override the XDG state target. Defaults to
    /// `$XDG_DATA_HOME/softfig/<repo_id>/` (or
    /// `~/.local/share/softfig/<repo_id>/`).
    #[arg(long)]
    pub state_root: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct FinalizeArgs {
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SplitArgs {
    /// Commit the split. Without it, only a dry-run preview is printed.
    #[arg(long)]
    pub apply: bool,
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug, Default)]
pub struct StatusArgs {
    #[arg(long)]
    pub garden: Option<PathBuf>,
}

pub fn run(cmd: Option<MigrateCmd>, status: StatusArgs) -> Result<()> {
    match cmd {
        Some(MigrateCmd::Prepare(args)) => prepare(args),
        Some(MigrateCmd::Finalize(args)) => finalize(args),
        Some(MigrateCmd::Split(args)) => split(args),
        None => print_status(status),
    }
}

fn prepare(args: PrepareArgs) -> Result<()> {
    let garden = resolve_garden(args.garden)?;
    let softfig_in_garden = garden.join(".softfig");
    if !softfig_in_garden.is_dir() {
        return Err(anyhow!(
            "no .softfig/ at {} — run `softfig vault init && softfig init` first",
            garden.display()
        ));
    }

    // Refuse if a daemon socket is reachable. Half-finished prepare
    // against a running daemon would corrupt the running session.
    let socket = runtime_socket_path();
    if socket.exists() {
        return Err(anyhow!(
            "daemon socket present at {} — stop the daemon (`softfig daemon stop`) before prepare",
            socket.display()
        ));
    }

    // Resolve the destination state root. Need the repo_id, so open
    // the repo (M1c-compat) read-only — opens require neither the
    // session nor a write lock.
    let repo_id = Repo::open(&garden)
        .with_context(|| format!("open repo at {}", garden.display()))?
        .repo_id()
        .with_context(|| "read meta.repo_id")?;

    let state_root = match args.state_root {
        Some(p) => p,
        None => default_state_root(&repo_id)?,
    };

    if state_root.join(".softfig").exists() {
        return Err(anyhow!(
            "{} already populated — refusing to overwrite. Inspect or remove it manually.",
            state_root.display()
        ));
    }

    fs::create_dir_all(&state_root)
        .with_context(|| format!("create state root {}", state_root.display()))?;
    let dest_softfig = state_root.join(".softfig");
    copy_dir_recursive(&softfig_in_garden, &dest_softfig).with_context(|| {
        format!(
            "copy {} → {}",
            softfig_in_garden.display(),
            dest_softfig.display()
        )
    })?;

    // Write keeper.toml in BOTH locations so the daemon can pick it up
    // before AND after finalize. The pre-finalize daemon discovers via
    // garden_root/.softfig/keeper.toml; the finalized layout has the
    // same file inside the new state root.
    write_keeper_toml(&softfig_in_garden, &state_root)?;
    write_keeper_toml(&dest_softfig, &state_root)?;

    println!("prepared:");
    println!("  garden       {}", garden.display());
    println!("  state_root   {}", state_root.display());
    println!(
        "  copied       {}/.softfig → {}/.softfig",
        garden.display(),
        state_root.display()
    );
    println!();
    println!("next: `softfig daemon start` (or restart) to pick up the new keeper.toml,");
    println!("then verify FUSE mount, then `softfig migrate finalize`.");
    Ok(())
}

fn finalize(args: FinalizeArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let req_args = serde_json::to_value(MigrateFinalizeArgs::default())?;
    match try_daemon_call(&socket, op::MIGRATE_FINALIZE, req_args) {
        Ok(Some(value)) => {
            let reply: MigrateFinalizeReply = serde_json::from_value(value)?;
            println!("unmounted          {}", reply.unmounted);
            println!("plaintext_deleted  {}", reply.plaintext_deleted);
            if !reply.plaintext_skipped.is_empty() {
                println!("plaintext_skipped:");
                for p in &reply.plaintext_skipped {
                    println!("  {p}");
                }
            }
            println!("old_state_deleted  {}", reply.old_state_deleted);
            if !reply.old_state_skipped.is_empty() {
                println!("old_state_skipped:");
                for p in &reply.old_state_skipped {
                    println!("  {p}");
                }
            }
            println!("remounted          {}", reply.remounted);
            if !reply.remounted {
                return Err(anyhow!("daemon failed to remount; investigate logs"));
            }
            Ok(())
        }
        Ok(None) => Err(anyhow!(
            "no daemon at {} — start one first (`softfig daemon start`)",
            socket.display()
        )),
        Err(ClientError::Daemon { kind, message }) => {
            Err(anyhow!("daemon error ({:?}): {message}", kind))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

fn split(args: SplitArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let req_args = serde_json::to_value(MigrateSplitArgs { apply: args.apply })?;
    match try_daemon_call(&socket, op::MIGRATE_SPLIT, req_args) {
        Ok(Some(value)) => {
            let reply: MigrateSplitReply = serde_json::from_value(value)?;
            if reply.splits.is_empty() && reply.skipped.is_empty() {
                println!("no monoliths to split.");
                return Ok(());
            }
            if reply.applied {
                for s in &reply.splits {
                    let short = s.hash.as_deref().map(short_hash).unwrap_or("???????");
                    println!("split {} -> {} notes  [{short}]", s.from, s.notes);
                }
            } else if !reply.splits.is_empty() {
                println!("would split:");
                for s in &reply.splits {
                    println!("  {}  -> {}/ ({} notes)", s.from, s.folder, s.notes);
                }
            }
            if !reply.skipped.is_empty() {
                println!("skipped:");
                for s in &reply.skipped {
                    println!("  {}: {}", s.path, s.reason);
                }
            }
            if !reply.applied && !reply.splits.is_empty() {
                println!();
                println!("re-run with --apply to commit.");
            }
            Ok(())
        }
        Ok(None) => Err(anyhow!(
            "no daemon at {} — start one first (`softfig daemon start`)",
            socket.display()
        )),
        Err(ClientError::Daemon { kind, message }) => {
            Err(anyhow!("daemon error ({:?}): {message}", kind))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

fn short_hash(hash: &str) -> &str {
    &hash[..hash.len().min(8)]
}

fn print_status(args: StatusArgs) -> Result<()> {
    let garden = resolve_garden(args.garden)?;
    let softfig = garden.join(".softfig");
    let keeper_toml = softfig.join(KEEPER_TOML);

    let cfg = if keeper_toml.exists() {
        let raw = fs::read_to_string(&keeper_toml)?;
        Some(toml::from_str::<KeeperToml>(&raw)?)
    } else {
        None
    };

    println!("garden            {}", garden.display());
    if let Some(c) = &cfg {
        match &c.state_root {
            Some(p) => {
                println!("phase             prepared (or finalized)");
                println!("state_root        {}", p.display());
                let plaintext_present = garden_has_plaintext(&garden);
                let old_state_present = softfig.is_dir();
                println!("plaintext_present {plaintext_present}");
                println!("old_state_present {old_state_present}");
                if plaintext_present || old_state_present {
                    println!(
                        "next              run `softfig migrate finalize` once FUSE is mounted"
                    );
                } else {
                    println!("next              fully migrated; nothing to do");
                }
            }
            None => println!("phase             unmigrated (keeper.toml has no state_root)"),
        }
    } else {
        println!("phase             unmigrated (no keeper.toml)");
    }
    Ok(())
}

// ---- helpers ----

#[derive(serde::Deserialize)]
struct KeeperToml {
    state_root: Option<PathBuf>,
}

fn resolve_garden(garden: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = garden {
        return Ok(p);
    }
    let here = std::env::current_dir().context("could not read $PWD")?;
    discover_garden(&here)
        .ok_or_else(|| anyhow!("no .softfig/ found in {} or any parent", here.display()))
}

fn default_state_root(repo_id: &str) -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("$HOME not set"))?;
            PathBuf::from(home).join(".local/share")
        }
    };
    Ok(base.join("softfig").join(repo_id))
}

fn write_keeper_toml(softfig_dir: &Path, state_root: &Path) -> Result<()> {
    let path = softfig_dir.join(KEEPER_TOML);
    let body = format!("state_root = {:?}\n", state_root);
    fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ft.is_file() {
            fs::copy(&from, &to)?;
        }
        // Symlinks under .softfig/ are not expected; skip.
    }
    Ok(())
}

fn garden_has_plaintext(garden: &Path) -> bool {
    let entries = match fs::read_dir(garden) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        if entry.file_name() != ".softfig" {
            return true;
        }
    }
    false
}

/// Vault initialization sanity check used by tests / future callers
/// that want to confirm the destination state is mountable before
/// proceeding.
#[allow(dead_code)]
pub fn assert_state_mountable(state_root: &Path) -> Result<()> {
    let vault = Vault::at_state_root(state_root);
    if !vault.is_initialized() {
        return Err(anyhow!(
            "no vault at {}/.softfig/vault — copy step incomplete",
            state_root.display()
        ));
    }
    Ok(())
}
