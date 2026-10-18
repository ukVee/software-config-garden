//! `softfig uninstall` — clean removal (release-pipeline slice 007,
//! `meta/spec-install.md` workstream D). Removes the installed-set binaries,
//! the systemd unit, and the MCP registration — and **refuses** to touch the
//! encrypted store or the garden content without a separate, explicit
//! confirmation that names exactly what would be removed.
//!
//! An opt-in `growlight-gui` sits outside the installed set
//! (`meta/spec-release.md` → **Binary set**), so uninstall *states* what it
//! does with it — here, it is removed with the program — rather than leaving
//! it behind silently.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use softfig_install::prompt::{Answer, Consent, Fixed, Offer, Tty};
use softfig_ipc::compat::INSTALLED_SET;
use softfig_ipc::{runtime_socket_path, verbs::op, StatusReply};

use crate::cmd_daemon::try_daemon_call;

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// The install directory to remove the binaries from (default: the
    /// directory this `softfig` runs from).
    #[arg(long)]
    pub prefix: Option<PathBuf>,
    /// Override the keeperd socket path. Defaults to the runtime socket.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Also remove the encrypted store + garden content (requires a second,
    /// explicit confirmation naming each path). Without this flag, the store
    /// and garden are never touched.
    #[arg(long)]
    pub remove_data: bool,
    /// Consent to every prompt without asking (still never removes data
    /// unless `--remove-data` is also given).
    #[arg(long)]
    pub yes: bool,
    /// Decline every prompt without asking.
    #[arg(long)]
    pub no: bool,
    /// Print exactly what would be removed, then stop.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(args: UninstallArgs) -> Result<()> {
    let prefix = args.prefix.clone().unwrap_or_else(default_prefix);
    let socket = args.socket.clone().unwrap_or_else(runtime_socket_path);

    let mut consent: Box<dyn Consent> = if args.yes {
        Box::new(Fixed(Answer::Yes))
    } else if args.no {
        Box::new(Fixed(Answer::No))
    } else {
        Box::new(Tty)
    };

    let plan = removal_plan(&prefix);
    let store_paths = discover_garden(&socket).map(|g| resolve_store_paths(&g));

    print_plan(&plan, store_paths.as_ref());
    if args.dry_run {
        println!("dry run: nothing removed.");
        return Ok(());
    }

    // Offer 1 — the program (never the data).
    let offer = Offer {
        id: "remove-program",
        summary: format!(
            "Remove the soft-fig program: {} binary/ies from {}, the systemd \
             user unit, and the MCP registration? (your store and garden will \
             NOT be touched)",
            plan.binaries.len(),
            prefix.display()
        ),
        undo: "re-run softfig-install".to_string(),
    };
    if consent.ask(&offer) != Answer::Yes {
        println!("nothing removed.");
        return Ok(());
    }

    stop_daemon(&socket);
    remove_binaries(&plan);
    remove_unit();
    remove_mcp();

    // Offer 2 — the data, only on --remove-data, and only after the first
    // removal is done. The summary names every path that would be removed.
    match &store_paths {
        Some(sp) if args.remove_data => {
            let data_offer = Offer {
                id: "remove-data",
                summary: data_removal_summary(sp),
                undo: "restore from your backup".to_string(),
            };
            if consent.ask(&data_offer) == Answer::Yes {
                remove_data(sp)?;
            } else {
                print_data_untouched(sp);
            }
        }
        Some(sp) => print_data_untouched(sp),
        None => println!("no garden or store found — nothing else to remove."),
    }

    println!("uninstall complete.");
    Ok(())
}

/// The default install directory: the directory this `softfig` was started
/// from, falling back to `~/.local/bin`.
fn default_prefix() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local/bin")
        })
}

/// What `uninstall` will remove from `prefix`: the installed-set members that
/// exist, plus an opt-in `growlight-gui` if present (named, never left behind
/// silently).
pub fn removal_plan(prefix: &Path) -> RemovalPlan {
    let mut binaries = Vec::new();
    for name in INSTALLED_SET {
        let p = prefix.join(name);
        if p.is_file() {
            binaries.push(p);
        }
    }
    // Opt-in growlight-gui sits outside the set (`spec-release.md` → Binary
    // set); state + remove it with the program rather than leave it silently.
    let gui = prefix.join("growlight-gui");
    if gui.is_file() {
        binaries.push(gui);
    }
    let has_unit = unit_path().map(|p| p.is_file()).unwrap_or(false);
    let has_mcp = which_claude();
    RemovalPlan {
        binaries,
        has_unit,
        has_mcp,
    }
}

/// The full list of what `uninstall` removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalPlan {
    /// Absolute paths of the binaries to remove (installed set + opt-in GUI).
    pub binaries: Vec<PathBuf>,
    /// The systemd user unit exists.
    pub has_unit: bool,
    /// The `claude` CLI is present, so an MCP registration may exist (removal
    /// is attempted best-effort).
    pub has_mcp: bool,
}

fn print_plan(plan: &RemovalPlan, store: Option<&StorePaths>) {
    println!("soft-fig uninstall — will remove:");
    if plan.binaries.is_empty() {
        println!("  binaries      (none found in this directory)");
    } else {
        for b in &plan.binaries {
            println!("  binary        {}", b.display());
        }
    }
    println!(
        "  systemd unit  {}",
        if plan.has_unit { "softfig-keeperd.service (disable + remove)" } else { "(none)" }
    );
    println!(
        "  MCP           {}",
        if plan.has_mcp { "softfig-mcp registration (best-effort)" } else { "(claude CLI not found)" }
    );
    match store {
        Some(sp) => {
            println!("  data          NOT removed unless you pass --remove-data and confirm:");
            println!("    garden      {}", sp.garden.display());
            match &sp.store {
                Some(s) => println!("    store       {}", s.display()),
                None => println!("    store       (at the XDG state root — see `softfig migrate`)"),
            }
        }
        None => println!("  data          (no garden found)"),
    }
}

fn stop_daemon(socket: &Path) {
    match try_daemon_call(socket, op::SHUTDOWN, serde_json::Value::Null) {
        Ok(Some(_)) => println!("daemon: stopping"),
        Ok(None) => println!("daemon: not running"),
        Err(e) => println!("daemon stop failed (continuing): {e}"),
    }
}

fn remove_binaries(plan: &RemovalPlan) {
    for b in &plan.binaries {
        match std::fs::remove_file(b) {
            Ok(()) => println!("removed {}", b.display()),
            Err(e) => println!("could not remove {}: {e}", b.display()),
        }
    }
}

fn unit_path() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(config.join("systemd/user/softfig-keeperd.service"))
}

fn remove_unit() {
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "softfig-keeperd.service"])
        .status();
    if let Some(p) = unit_path()
        && p.is_file()
    {
        match std::fs::remove_file(&p) {
            Ok(()) => println!("removed unit {}", p.display()),
            Err(e) => println!("could not remove {}: {e}", p.display()),
        }
    }
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
}

fn which_claude() -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| dir.join("claude").is_file())
    })
}

fn remove_mcp() {
    if !which_claude() {
        println!("'claude' CLI not found — skipping MCP deregistration.");
        return;
    }
    let status = std::process::Command::new("claude")
        .args(["mcp", "remove", "--scope", "user", "softfig-mcp"])
        .status();
    match status {
        Ok(s) if s.success() => println!("removed softfig-mcp MCP registration"),
        Ok(s) => println!("MCP deregistration exited {s}"),
        Err(e) => println!("MCP deregistration failed: {e}"),
    }
}

/// The two data paths: the encrypted store and the garden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePaths {
    pub garden: PathBuf,
    /// The encrypted store, or `None` when it can't be named from the garden
    /// (post-`finalize` the store lives at the XDG state root, and the
    /// `keeper.toml` that names it was deleted from the garden).
    pub store: Option<PathBuf>,
}

pub fn resolve_store_paths(garden: &Path) -> StorePaths {
    // Post-migrate the store lives at the `state_root` recorded in
    // `keeper.toml`; pre-migrate it is the garden's own `.softfig`; once
    // finalized, neither is discoverable from the garden and the store is
    // reported as unknown (the refusal still holds).
    let store = if let Some(root) = read_state_root(garden) {
        Some(root.join(".softfig"))
    } else if garden.join(".softfig").is_dir() {
        Some(garden.join(".softfig"))
    } else {
        None
    };
    StorePaths {
        garden: garden.to_path_buf(),
        store,
    }
}

/// Read the `state_root` out of `<garden>/.softfig/keeper.toml`, if present.
fn read_state_root(garden: &Path) -> Option<PathBuf> {
    let raw = std::fs::read_to_string(garden.join(".softfig/keeper.toml")).ok()?;
    #[derive(serde::Deserialize)]
    struct KeeperToml {
        state_root: Option<PathBuf>,
    }
    toml::from_str::<KeeperToml>(&raw).ok().and_then(|c| c.state_root)
}

fn data_removal_summary(sp: &StorePaths) -> String {
    match &sp.store {
        Some(s) => format!(
            "Permanently delete your data: the encrypted store at {} and the \
             garden content at {}? (this cannot be undone — back up first)",
            s.display(),
            sp.garden.display()
        ),
        None => format!(
            "Permanently delete your data: the garden content at {}? (the \
             encrypted store lives at your XDG state root and is NOT removed by \
             this — back up first)",
            sp.garden.display()
        ),
    }
}

fn print_data_untouched(sp: &StorePaths) {
    println!();
    println!("data left untouched (as promised):");
    println!("  garden  {}", sp.garden.display());
    match &sp.store {
        Some(s) => {
            println!("  store   {}", s.display());
            println!("remove them by hand, if you really mean to:");
            println!("  rm -rf {}", s.display());
            println!("  rm -rf {}", sp.garden.display());
        }
        None => {
            println!("  store   (at the XDG state root — remove it by hand if you really mean to)");
            println!("remove the garden by hand, if you really mean to:");
            println!("  rm -rf {}", sp.garden.display());
        }
    }
}

fn remove_data(sp: &StorePaths) -> Result<()> {
    // Post-migrate the store lives outside the garden; pre-migrate it is
    // inside it and removing the garden removes both. When the store is
    // unknown (finalized), only the garden is removed and the store is left
    // for the user — never guessed at.
    if let Some(store) = &sp.store {
        if store.starts_with(&sp.garden) {
            println!(
                "store {} lives inside the garden — removing the garden removes both.",
                store.display()
            );
        } else {
            std::fs::remove_dir_all(store)
                .with_context(|| format!("removing store {}", store.display()))?;
            println!("removed store {}", store.display());
        }
    } else {
        println!(
            "note: the encrypted store (at your XDG state root) was not named and is \
             left in place — remove it by hand if you mean to."
        );
    }
    std::fs::remove_dir_all(&sp.garden)
        .with_context(|| format!("removing garden {}", sp.garden.display()))?;
    println!("removed garden {}", sp.garden.display());
    Ok(())
}

/// Find the garden: first by walking up from the cwd for a `.softfig`
/// (pre-migrate), then by asking a running daemon for its `garden_root`
/// (post-`finalize` the garden's `.softfig` is gone, but the daemon still
/// knows where it mounts).
fn discover_garden(socket: &Path) -> Option<PathBuf> {
    if let Some(g) = std::env::current_dir()
        .ok()
        .and_then(|here| softfig_vault::discover_garden(&here))
    {
        return Some(g);
    }
    match try_daemon_call(socket, op::STATUS, serde_json::Value::Null) {
        Ok(Some(v)) => serde_json::from_value::<StatusReply>(v)
            .ok()
            .map(|r| PathBuf::from(r.garden_root)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::compat::stamp_for;

    /// Write a fake binary carrying the build stamp, so `is_file` is what the
    /// plan keys on (the plan never reads contents).
    fn write_binary(dir: &Path, name: &str) {
        let mut bytes = b"\x7fELF fake".to_vec();
        bytes.extend_from_slice(&stamp_for("1.0.0"));
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    #[test]
    fn the_plan_names_the_installed_set_and_an_opt_in_gui() {
        let dir = tempfile::tempdir().unwrap();
        for name in INSTALLED_SET {
            write_binary(dir.path(), name);
        }
        write_binary(dir.path(), "growlight-gui");
        // A stray non-softfig binary is NOT in the plan.
        write_binary(dir.path(), "something-else");

        let plan = removal_plan(dir.path());
        let names: Vec<_> = plan
            .binaries
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let mut want: Vec<String> = INSTALLED_SET.iter().map(|s| s.to_string()).collect();
        want.push("growlight-gui".to_string());
        assert_eq!(names, want);
    }

    #[test]
    fn a_partial_install_names_only_what_exists() {
        let dir = tempfile::tempdir().unwrap();
        write_binary(dir.path(), "softfig");
        write_binary(dir.path(), "softfig-keeperd");
        let plan = removal_plan(dir.path());
        assert_eq!(plan.binaries.len(), 2);
    }

    #[test]
    fn the_store_path_tracks_state_root_after_migration() {
        let dir = tempfile::tempdir().unwrap();
        let garden = dir.path().join("garden");
        let state_root = dir.path().join(".local/share/softfig/abc");
        std::fs::create_dir_all(garden.join(".softfig")).unwrap();
        std::fs::write(
            garden.join(".softfig/keeper.toml"),
            format!("state_root = {:?}\n", state_root),
        )
        .unwrap();

        let sp = resolve_store_paths(&garden);
        assert_eq!(sp.garden, garden);
        assert_eq!(sp.store.as_deref(), Some(state_root.join(".softfig").as_path()));
    }

    #[test]
    fn the_store_is_the_garden_state_pre_migration() {
        let dir = tempfile::tempdir().unwrap();
        let garden = dir.path().join("garden");
        std::fs::create_dir_all(garden.join(".softfig")).unwrap();
        // No keeper.toml ⇒ pre-migrate: the store is the garden's .softfig.
        let sp = resolve_store_paths(&garden);
        assert_eq!(sp.store.as_deref(), Some(garden.join(".softfig").as_path()));
    }

    /// Post-`finalize` the garden's `.softfig` is gone, so neither the state
    /// root nor a pre-migrate store can be named from the garden — the store
    /// is `None` (unknown), never guessed at.
    #[test]
    fn a_finalized_garden_has_no_discoverable_store() {
        let dir = tempfile::tempdir().unwrap();
        let garden = dir.path().join("garden");
        std::fs::create_dir_all(&garden).unwrap(); // no .softfig
        let sp = resolve_store_paths(&garden);
        assert_eq!(sp.store, None);
        assert_eq!(sp.garden, garden);
    }
}
