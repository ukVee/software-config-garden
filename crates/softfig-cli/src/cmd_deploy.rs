//! `softfig deploy` — materialize the garden's `config/deploy.toml` table
//! onto the real filesystem (the `bombadil link` replacement, M4a). A thin
//! TTY frontend over the frontend-neutral `softfig-deploy` core; a future
//! daemon-mediated MCP `deploy` verb wraps the same `plan`/`apply`.
//!
//! Reads sources + the table from the garden root (the FUSE plaintext view)
//! and writes targets/cache directly — native filesystem ops, no daemon
//! round-trip. Requires the garden unlocked: when locked, the FUSE mount
//! (and thus `config/deploy.toml`) is gone, which surfaces as a clear
//! "is the garden unlocked?" hint.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Args;
use softfig_deploy::{
    apply, plan, ApplyOptions, DeployConfig, DeployError, DeployPaths, FsSource, Plan,
};

#[derive(Args, Debug)]
pub struct DeployArgs {
    /// Garden root (the FUSE mount path). Defaults to `~/soft-fig_garden`.
    #[arg(long)]
    pub garden_root: Option<PathBuf>,
    /// Deploy-cache root. Defaults to `$XDG_DATA_HOME/softfig/deployed`
    /// (or `~/.local/share/softfig/deployed`).
    #[arg(long)]
    pub cache_root: Option<PathBuf>,
    /// Show the plan and exit without touching anything.
    #[arg(long)]
    pub dry_run: bool,
    /// Back up a conflicting target to `<target>.softfig-bak` and overwrite
    /// it, instead of refusing.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: DeployArgs) -> Result<()> {
    let home = home_dir()?;
    let garden_root = args
        .garden_root
        .unwrap_or_else(|| home.join("soft-fig_garden"));
    let cache_root = match args.cache_root {
        Some(p) => p,
        None => default_cache_root(&home)?,
    };
    let paths = DeployPaths {
        config_dir: garden_root.join("config"),
        garden_root,
        home,
        cache_root,
    };

    let config = DeployConfig::load(&paths.config_file()).map_err(|e| match e {
        DeployError::ConfigNotFound(p) => anyhow!(
            "deploy config not found at {} — is the garden unlocked? \
             run `softfig daemon unlock` first",
            p.display()
        ),
        other => anyhow!(other),
    })?;

    let plan = plan(&config, &paths, &FsSource::new(&paths))?;
    print_plan(&plan);

    if args.dry_run {
        println!("\n(dry run — nothing changed)");
        return Ok(());
    }

    let report = apply(&plan, &paths, &ApplyOptions { force: args.force })?;
    print_report(&report);

    if !report.conflicts.is_empty() {
        return Err(anyhow!(
            "{} target(s) conflicted — re-run with --force to back up and overwrite",
            report.conflicts.len()
        ));
    }
    Ok(())
}

fn print_plan(plan: &Plan) {
    use softfig_deploy::Action;
    if plan.entries.is_empty() {
        println!("No dots in config/deploy.toml.");
        return;
    }
    println!("Plan ({} dot(s)):", plan.entries.len());
    for e in &plan.entries {
        let verb = match e.action {
            Action::CreateSymlink => "symlink",
            Action::ReplaceManaged => "replace",
            Action::CopyStamped => "copy",
            Action::SkipUnchanged => "skip",
            Action::Conflict => "CONFLICT",
        };
        let extra = e
            .conflict_reason
            .as_deref()
            .map(|r| format!(" — {r}"))
            .unwrap_or_default();
        println!(
            "  {verb:>8}  {}  →  {}{}",
            e.name,
            e.target_abs.display(),
            extra
        );
    }
}

fn print_report(r: &softfig_deploy::Report) {
    println!(
        "\nApplied: {} created, {} replaced, {} copied, {} skipped, {} forced.",
        r.created.len(),
        r.replaced.len(),
        r.copied.len(),
        r.skipped.len(),
        r.forced.len(),
    );
    for w in &r.warnings {
        println!("  warning: {w}");
    }
    for c in &r.conflicts {
        println!("  conflict (skipped): {c}");
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("$HOME not set"))
}

fn default_cache_root(home: &std::path::Path) -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home.join(".local/share"),
    };
    Ok(base.join("softfig").join("deployed"))
}
