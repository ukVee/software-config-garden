//! M4 deploy verbs (`deploy_plan` / `deploy_apply`) — the TUI Deploy tab's
//! daemon seam.
//!
//! `softfig-deploy` (M4a) is frontend-neutral: its `plan`/`apply` read the
//! garden's `config/deploy.toml` + `config/source/` and write targets/cache
//! directly. The TUI only talks to the daemon over IPC and must never touch the
//! filesystem itself, so these two verbs let the daemon — which owns the
//! unlocked session + mount — run `plan`/`apply` on the TUI's behalf and return
//! a metadata-only projection of the `Plan` / `Report`. Both require Unlocked
//! and reject a locked garden up front with `VaultLocked` (via
//! `require_unlocked`, before any config read — asserted by
//! `deploy_refuses_when_locked`). The `NotFound` "is the garden unlocked?" hint
//! is the *unlocked-but-config-absent* case: the FUSE mount is up but
//! `config/deploy.toml` isn't there yet — same hint the CLI prints.
//!
//! ## Mount-safety (the reason this is not a naive `fs::read` wrapper)
//!
//! In FUSE mode `garden_root` **is** the mount this daemon serves, so a
//! `std::fs::read` of `config/deploy.toml` / `config/source/` from here, while
//! holding `daemon.inner`, is a self-read of its own mount — the 2026-06-21
//! deadlock class ([`crate::actions::WorkTree`] / `workdir_snapshot`), and the
//! kernel would hand back the **reader-redacted projection**, so a Layer-B
//! sealed source would deploy `[sealed:…]` placeholder bytes into a live
//! dotfile. Instead we [`snapshot_deploy_inputs`] every garden-side input
//! through the mount-safe working tree (in-memory tip ∪ overlay **plaintext**,
//! no kernel round-trip, no redaction) *while* holding `inner`, then
//! `drop(inner)` before the blocking target/cache diff — so a deploy can never
//! wedge the daemon and never stalls other IPC verbs.

use softfig_deploy::{
    apply, plan, Action, ApplyOptions, DeployConfig, DeployError, DeployPaths, MemSource,
};
use softfig_ipc::verbs::{
    DeployAction, DeployApplyArgs, DeployApplyReply, DeployPlanEntry, DeployPlanReply,
};
use softfig_ipc::ErrorKind;

use crate::actions::WorkTree;
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{require_unlocked, HandlerResult};

/// Build the `DeployPaths` the same way `softfig deploy` does, but sourced from
/// the daemon's own config: the garden mount root (the no-target boundary),
/// `config/` under it, the deploy `$HOME` boundary, and the persistent
/// plaintext deploy-cache root.
fn deploy_paths(inner: &DaemonInner) -> std::result::Result<DeployPaths, (ErrorKind, String)> {
    let home = inner.config.deploy_home().ok_or((
        ErrorKind::Internal,
        "cannot resolve deploy $HOME (neither an override nor $HOME is set)".to_string(),
    ))?;
    Ok(DeployPaths {
        garden_root: inner.config.garden_root.clone(),
        config_dir: inner.config.garden_root.join("config"),
        home,
        cache_root: inner.config.deploy_cache_root(),
    })
}

/// Snapshot every garden-side deploy input — `config/deploy.toml` and each
/// dot's `config/source/` file — through the mount-safe working tree, returning
/// them as owned, lock-free values so the caller can `drop(inner)` before the
/// blocking `plan`/`apply`.
///
/// Reads route through [`WorkTree`], which in FUSE mode serves the driver's
/// in-memory (tip ∪ overlay) **plaintext** with no kernel round-trip: no
/// self-read of the mount under `inner`, and no reader-redacted `[sealed:…]`
/// projection (a Layer-B-sealed source is decrypted to plaintext, so the deploy
/// writes the real bytes, never a placeholder). In non-FUSE (M1c-compat) mode
/// it is a plain `std::fs` passthrough on a real directory.
fn snapshot_deploy_inputs(
    daemon: &Daemon,
    inner: &DaemonInner,
) -> std::result::Result<(DeployPaths, DeployConfig, MemSource), (ErrorKind, String)> {
    let paths = deploy_paths(inner)?;
    let tree = WorkTree::new(daemon, inner);

    // `config/deploy.toml` — plaintext, mount-safe. Absent ⇒ NotFound with the
    // CLI's "is the garden unlocked?" hint (when locked the mount is gone).
    let toml_bytes = tree.read("config/deploy.toml").ok_or_else(|| {
        (
            ErrorKind::NotFound,
            format!(
                "deploy config not found at {} — is the garden unlocked?",
                paths.config_file().display()
            ),
        )
    })?;
    let toml_src = String::from_utf8(toml_bytes)
        .map_err(|_| (ErrorKind::BadArgs, "deploy.toml is not valid UTF-8".to_string()))?;
    let config = DeployConfig::parse(&toml_src).map_err(map_deploy_err)?;

    // Each dot's source, plaintext, via the working tree. A dot referencing an
    // absent source is left unset so the planner raises the usual
    // `SourceNotFound`; a directory source is recorded so it raises
    // `DirectorySource`, exactly as an on-disk stat would.
    let mut source = MemSource::new();
    for dot in config.dots.values() {
        let rel = format!("config/source/{}", dot.source);
        if tree.is_dir(&rel) {
            source.insert_directory(dot.source.clone());
        } else if let Some(bytes) = tree.read(&rel) {
            source.insert_file(dot.source.clone(), bytes);
        }
    }

    Ok((paths, config, source))
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
        | DeployError::InvalidTarget { .. }
        | DeployError::InvalidSource { .. }
        | DeployError::CacheRootInsideGarden(_) => (ErrorKind::BadArgs, e.to_string()),
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
    // Deploy gate first, `inner` second (the daemon-wide lock order for the
    // deploy verbs): a plan issued while an apply is in flight waits for it
    // and diffs the settled state instead of a torn mid-apply one.
    let _gate = daemon.deploy_gate.lock().unwrap();
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let (paths, config, source) = snapshot_deploy_inputs(daemon, &inner)?;
    // Release `inner` before the (blocking) target/cache diff — the garden-side
    // inputs are now owned in memory, so nothing below touches the mount.
    drop(inner);

    let plan = plan(&config, &paths, &source).map_err(map_deploy_err)?;

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
///
/// Recomputes the plan itself rather than trusting a previously returned
/// `deploy_plan` (there is no cross-verb plan etag yet — a recorded follow-up):
/// the target/cache state may have changed since the client planned, and the
/// [`Daemon::deploy_gate`] only serializes deploys against *each other*, not
/// against arbitrary filesystem writers.
pub fn deploy_apply(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: DeployApplyArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("deploy_apply args: {e}")))?;

    // Hold the deploy gate across the whole plan+apply (acquired before
    // `inner`, the deploy verbs' lock order): concurrent applies serialize, so
    // two forced applies can never interleave the conflict-backup dance (the
    // second would rename the first's fresh symlink over `<target>.softfig-bak`,
    // destroying the only backup of the user's original file).
    let _gate = daemon.deploy_gate.lock().unwrap();
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let (paths, config, source) = snapshot_deploy_inputs(daemon, &inner)?;
    // Release `inner` before the (blocking) cache/target writes — the source
    // plaintext is captured, so the materialization never touches the mount.
    drop(inner);

    let plan = plan(&config, &paths, &source).map_err(map_deploy_err)?;
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
