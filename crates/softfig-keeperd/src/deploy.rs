//! M4 deploy verbs (`deploy_plan` / `deploy_apply`) — the TUI Deploy tab's
//! daemon seam.
//!
//! `softfig-deploy` (M4a) is a native-FS op with **no IPC surface**: it reads
//! the garden's `config/deploy.toml` + `config/source/` (the FUSE plaintext
//! view) and writes targets/cache directly. The TUI only talks to the daemon
//! over IPC and must never touch the filesystem itself, so these two verbs let
//! the daemon — which owns the unlocked session + mount — run `softfig-deploy`'s
//! existing `plan`/`apply` on the TUI's behalf and return a metadata-only
//! projection of the `Plan` / `Report`. No deploy-engine change: this is a pure
//! wrapper. Both require Unlocked and reject a locked garden up front with
//! `VaultLocked` (via `require_unlocked`, before any config read — asserted by
//! `deploy_refuses_when_locked`). The `NotFound` "is the garden unlocked?" hint
//! is the *unlocked-but-config-absent* case: the FUSE mount is up but
//! `config/deploy.toml` isn't there yet — same hint the CLI prints.

use softfig_deploy::{apply, plan, Action, ApplyOptions, DeployConfig, DeployError, DeployPaths};
use softfig_ipc::verbs::{
    DeployAction, DeployApplyArgs, DeployApplyReply, DeployPlanEntry, DeployPlanReply,
};
use softfig_ipc::ErrorKind;

use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{require_unlocked, HandlerResult};

/// Build the `DeployPaths` the same way `softfig deploy` does, but sourced from
/// the daemon's own config: `config/` under the (unlocked) garden mount, the
/// deploy `$HOME` boundary, and the persistent plaintext deploy-cache root.
fn deploy_paths(inner: &DaemonInner) -> std::result::Result<DeployPaths, (ErrorKind, String)> {
    let home = inner.config.deploy_home().ok_or((
        ErrorKind::Internal,
        "cannot resolve deploy $HOME (neither an override nor $HOME is set)".to_string(),
    ))?;
    Ok(DeployPaths {
        config_dir: inner.config.garden_root.join("config"),
        home,
        cache_root: inner.config.deploy_cache_root(),
    })
}

/// Load `config/deploy.toml`, mapping deploy errors onto wire kinds. A missing
/// config surfaces as `NotFound` with the CLI's "is the garden unlocked?" hint.
fn load_config(paths: &DeployPaths) -> std::result::Result<DeployConfig, (ErrorKind, String)> {
    DeployConfig::load(&paths.config_file()).map_err(map_deploy_err)
}

fn map_deploy_err(e: DeployError) -> (ErrorKind, String) {
    match e {
        DeployError::ConfigNotFound(p) => (
            ErrorKind::NotFound,
            format!(
                "deploy config not found at {} — is the garden unlocked?",
                p.display()
            ),
        ),
        DeployError::ConfigParse(_)
        | DeployError::SourceNotFound { .. }
        | DeployError::DirectorySource { .. }
        | DeployError::InvalidName(_)
        | DeployError::InvalidTarget { .. } => (ErrorKind::BadArgs, e.to_string()),
        DeployError::Io(_) => (ErrorKind::Io, e.to_string()),
    }
}

fn project_action(a: Action) -> DeployAction {
    match a {
        Action::CreateSymlink => DeployAction::CreateSymlink,
        Action::ReplaceManaged => DeployAction::ReplaceManaged,
        Action::CopyStamped => DeployAction::CopyStamped,
        Action::SkipUnchanged => DeployAction::SkipUnchanged,
        Action::Conflict => DeployAction::Conflict,
    }
}

/// `deploy_plan` — read-only diff. Never mutates the filesystem, never commits.
pub fn deploy_plan(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let paths = deploy_paths(&inner)?;
    let config = load_config(&paths)?;
    let plan = plan(&config, &paths).map_err(map_deploy_err)?;

    let entries = plan
        .entries
        .iter()
        .map(|e| DeployPlanEntry {
            name: e.name.clone(),
            action: project_action(e.action),
            target: e.target_abs.display().to_string(),
            conflict_reason: e.conflict_reason.clone(),
        })
        .collect();

    Ok(serde_json::to_value(DeployPlanReply {
        entries,
        has_conflicts: plan.has_conflicts(),
    })
    .unwrap())
}

/// `deploy_apply` — materialize the plan (deploy-cache + targets). Mutates the
/// filesystem; a native-FS op, so no VCS commit (M4a defers deploy-as-VCS-event).
pub fn deploy_apply(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: DeployApplyArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("deploy_apply args: {e}")))?;

    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let paths = deploy_paths(&inner)?;
    let config = load_config(&paths)?;
    let plan = plan(&config, &paths).map_err(map_deploy_err)?;
    let report =
        apply(&plan, &paths, &ApplyOptions { force: args.force }).map_err(map_deploy_err)?;

    Ok(serde_json::to_value(DeployApplyReply {
        created: report.created,
        replaced: report.replaced,
        copied: report.copied,
        skipped: report.skipped,
        conflicts: report.conflicts,
        forced: report.forced,
        warnings: report.warnings,
    })
    .unwrap())
}
