//! `softfig deploy` — materialize the garden's `config/deploy.toml` table
//! onto the real filesystem (the `bombadil link` replacement, M4a). A thin
//! TTY frontend over keeperd's `deploy_plan` / `deploy_apply` verbs, the same
//! two the TUI's Deploy tab drives.
//!
//! The daemon is the one source reader. It reads `config/deploy.toml` and each
//! dot's `config/source/` file through its mount-safe working tree, so a Layer-B
//! sealed source deploys its plaintext. The CLI never reads `config/source/`
//! itself: on a live device `~/soft-fig_garden` is the FUSE mount, which serves
//! a sealed file as the reader-redacted `[sealed:<path>]` projection (report
//! 168). Targets and the deploy cache are written by the daemon too, so the
//! garden must be running and unlocked.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::Args;
use softfig_ipc::{
    runtime_socket_path,
    verbs::{
        op, DeployApplyArgs, DeployApplyReply, DeployPlanArgs, DeployPlanReply,
    },
    ErrorKind, Request,
};

#[derive(Args, Debug)]
pub struct DeployArgs {
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Show the plan and exit without touching anything.
    #[arg(long)]
    pub dry_run: bool,
    /// Back up a conflicting target to `<target>.softfig-bak` and overwrite
    /// it, instead of refusing.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: DeployArgs) -> Result<()> {
    let socket = args.socket.map_or_else(runtime_socket_path, Ok)?;

    let plan: DeployPlanReply = serde_json::from_value(daemon_call(
        &socket,
        op::DEPLOY_PLAN,
        serde_json::to_value(DeployPlanArgs {})?,
    )?)?;
    print_plan(&plan);

    if args.dry_run {
        println!("\n(dry run — nothing changed)");
        return Ok(());
    }

    // The daemon recomputes the plan under its deploy gate rather than trusting
    // the one just printed, so a target that changed in between is planned
    // against its current state.
    let report: DeployApplyReply = serde_json::from_value(daemon_call(
        &socket,
        op::DEPLOY_APPLY,
        serde_json::to_value(DeployApplyArgs { force: args.force })?,
    )?)?;
    print_report(&report);

    if !report.conflicts.is_empty() {
        return Err(anyhow!(
            "{} target(s) conflicted — re-run with --force to back up and overwrite",
            report.conflicts.len()
        ));
    }
    Ok(())
}

/// Call keeperd. Deploy has no direct-mode fallback: reading the sources
/// without the daemon is exactly the mount read this verb exists to avoid.
fn daemon_call(socket: &Path, op: &str, args: serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = softfig_ipc::connect(socket).map_err(|e| {
        if e.is_daemon_absent() {
            anyhow!(
                "daemon not running — start it with `softfig daemon start` and \
                 unlock the garden with `softfig daemon unlock`"
            )
        } else {
            anyhow!("{e}")
        }
    })?;
    let resp = softfig_ipc::call(&mut stream, &Request::new(op, args))?;
    resp.into_result().map_err(|(kind, message)| match kind {
        ErrorKind::VaultLocked => anyhow!(
            "garden is locked — run `softfig daemon unlock` first ({message})"
        ),
        _ => anyhow!("{message}").context(format!("daemon error ({kind:?})")),
    })
}

fn print_plan(plan: &DeployPlanReply) {
    if plan.entries.is_empty() {
        println!("No dots in config/deploy.toml.");
        return;
    }
    println!("Plan ({} dot(s)):", plan.entries.len());
    for e in &plan.entries {
        let verb = e.action.verb();
        let extra = e
            .conflict_reason
            .as_deref()
            .map(|r| format!(" — {r}"))
            .unwrap_or_default();
        println!("  {verb:>8}  {}  →  {}{}", e.name, e.target, extra);
    }
}

fn print_report(r: &DeployApplyReply) {
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
