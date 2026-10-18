//! `softfig upgrade` — the missing command (release-pipeline slice 007,
//! `meta/spec-install.md` workstream C). One command encapsulates the
//! hand-done dance:
//!
//! 1. fetch new source (`git pull` for a source checkout);
//! 2. `cargo build --release --locked`;
//! 3. the support-window pre-check (refuse from older than the previous
//!    minor — `meta/spec-release.md` → "Support window");
//! 4. stage + atomic install of the reconciled set (slice 003's swap);
//! 5. safely cycle the daemon (the `daemon cycle` relock-token path);
//! 6. run pending migrations (`migrate` status → `migrate finalize` if
//!    prepared);
//! 7. confirm the running daemon now reports the new version (slice 002's
//!    handshake, checked against the *built* version — this process is the
//!    pre-upgrade binary, so `binary_version()` is the old one).
//!
//! Plus the live-loop caveat (`spec-growlight` §12): a running growlight
//! orchestrator can't restart its own launcher, so `upgrade` detects one and
//! warns instead of stranding it silently running the old binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Args;
use semver::Version;
use softfig_install::detect::Supervisor;
use softfig_install::stage::{stage_and_swap, StageOutcome};
use softfig_ipc::compat::SetReport;
use softfig_ipc::{
    growlightd_runtime_socket_path, runtime_socket_path,
    verbs::{op, StatusReply},
};

use crate::cmd_daemon::{cycle, try_daemon_call, CycleArgs, CYCLE_RESTART_TIMEOUT_SECS};

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// Build an existing source checkout at this path (default: the current dir).
    #[arg(long)]
    pub source: Option<PathBuf>,
    /// Install the binaries here (default: the directory this `softfig` runs from).
    #[arg(long)]
    pub prefix: Option<PathBuf>,
    /// Override the keeperd socket path. Defaults to the runtime socket.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Seconds to wait for the daemon to come back after the cycle.
    #[arg(long, default_value_t = CYCLE_RESTART_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Skip the `git pull` (build the checkout exactly as it is).
    #[arg(long)]
    pub no_pull: bool,
    /// Skip the migration step (build + swap + cycle only).
    #[arg(long)]
    pub no_migrate: bool,
    /// Pull + build + check, then stop before the swap.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(args: UpgradeArgs) -> Result<()> {
    let source = args.source.clone().unwrap_or_else(|| PathBuf::from("."));
    let prefix = args.prefix.clone().unwrap_or_else(default_prefix);
    let socket = args.socket.clone().unwrap_or_else(runtime_socket_path);

    // 1. Fetch new source.
    pull(&source, args.no_pull)?;

    // 2. Build the program from source (the same build the release workflow
    //    runs — `--locked` against the committed Cargo.lock).
    build_program(&source)?;

    // The freshly-built version is the upgrade target. Read it out of the
    // built set (this process is still the old binary, so `binary_version()`
    // is the origin, not the destination).
    let target_dir = source.join("target/release");
    let target = SetReport::scan(&target_dir)
        .consistent_version()
        .map(str::to_string)
        .context(
            "the freshly built binary set is not one consistent version — did \
             `cargo build --release` produce the installed set?",
        )?;

    // 3. Support-window pre-check: refuse from older than the previous minor,
    //    before anything is swapped.
    check_support_window(&prefix, &target)?;

    if args.dry_run {
        println!(
            "dry run: pulled + built {target} + support-window check passed; \
             stopping before the swap."
        );
        return Ok(());
    }

    // 4. Stage + atomically install the reconciled set (idempotent).
    match stage_and_swap(&source, &prefix)? {
        StageOutcome::Noop { version } => {
            println!("already at {version} in {} — nothing to swap", prefix.display());
        }
        StageOutcome::Swapped { version } => {
            println!("installed: {} ({version})", SetReport::scan(&prefix));
        }
    }

    // 5. Warn about a live growlight loop (spec-growlight §12), then cycle the
    //    daemon if one is running.
    warn_if_growlight_live();

    if daemon_running(&socket) {
        match Supervisor::detect() {
            Supervisor::SystemdUser => {
                cycle(CycleArgs {
                    socket: Some(socket.clone()),
                    timeout: args.timeout,
                })?;
            }
            Supervisor::None => {
                // No supervisor to respawn the daemon: `cycle` would stop it
                // and wait forever. Say what the human must do instead, and do
                // not strand the daemon Locked mid-upgrade.
                println!(
                    "no systemd user bus detected — the daemon cannot auto-respawn.\n\
                     stop + restart it by hand after this upgrade:\n  \
                     softfig daemon stop\n  softfig daemon start\n  softfig daemon unlock"
                );
            }
        }
    } else {
        println!("daemon not running — nothing to cycle; start it with `softfig daemon start`.");
    }

    // 6. Run pending migrations via the *newly-installed* binary (it matches
    //    the new daemon; this process would be refused as a stale client).
    if !args.no_migrate {
        run_migrations(&prefix);
    }

    // 7. Confirm the running daemon now reports the new version.
    confirm_upgraded(&socket, &target)?;

    println!("upgrade complete: soft-fig is now {target}.");
    Ok(())
}

/// The default install directory: the directory this `softfig` was started
/// from (the install puts the whole set in one dir), falling back to
/// `~/.local/bin`.
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

/// `git pull` in a source checkout. A non-git source dir (a tarball unpack,
/// say) is fine — the pull is skipped with a note. A real checkout whose pull
/// fails is a hard stop: the upgrade must not build a half-updated tree.
fn pull(source: &Path, no_pull: bool) -> Result<()> {
    if !source.join(".git").is_dir() {
        println!("not a git checkout — building {source} as-is.", source = source.display());
        return Ok(());
    }
    if no_pull {
        println!("skipping git pull (--no-pull) — building the checkout as-is.");
        return Ok(());
    }
    println!("pulling latest source…");
    let status = Command::new("git")
        .args(["pull", "--ff-only"])
        .current_dir(source)
        .status()
        .context("running git pull")?;
    if !status.success() {
        bail!("git pull failed (exit {status}) — fix the checkout, or re-run with --no-pull");
    }
    Ok(())
}

/// `cargo build --release --locked` in the source root — the same build the
/// release workflow runs.
fn build_program(source: &Path) -> Result<()> {
    println!("building the program from source (cargo build --release --locked)…");
    let status = Command::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(source)
        .status()
        .context("running cargo build")?;
    if !status.success() {
        bail!("cargo build failed (exit {status})");
    }
    Ok(())
}

/// The support window (`meta/spec-release.md` → "Support window"): pre-1.0,
/// the previous minor is the only supported upgrade origin. A same-minor step
/// (patch / pre-release) and a one-minor step are allowed; anything older — a
/// skipped minor or a cross-major jump — is refused with instructions, never a
/// half-migrated attempt.
pub fn support_window_allows(current: &Version, target: &Version) -> bool {
    // A downgrade is never an upgrade.
    if target < current {
        return false;
    }
    if current.major != target.major {
        return false;
    }
    // Same minor: patch / pre-release within the minor. One minor forward:
    // the previous-minor origin. Anything more is outside the window.
    target.minor <= current.minor + 1
}

/// Refuse an upgrade whose origin is older than the supported window, naming
/// both versions and the remedy. A prefix with no consistent version (a fresh
/// box, or a partial install the swap is about to repair) has no "origin" to
/// be older than the window, so it passes.
fn check_support_window(prefix: &Path, target: &str) -> Result<()> {
    let report = SetReport::scan(prefix);
    let Some(current_str) = report.consistent_version() else {
        return Ok(());
    };
    let Ok(current) = Version::parse(current_str) else {
        // A stamp that doesn't parse can't be window-checked (find_stamp
        // already requires semver, so this is unreachable in practice).
        return Ok(());
    };
    let target = Version::parse(target).context("built version does not parse as semver")?;
    if support_window_allows(&current, &target) {
        Ok(())
    } else {
        bail!(
            "upgrading from {current} to {target} is outside the supported window.\n\
             soft-fig supports upgrading from the previous minor only; from anything \
             older, migrate through the intervening releases or reinstall with \
             `softfig-install`. Nothing was swapped — your data and binaries are \
             untouched."
        )
    }
}

/// Is a keeperd listening at `socket`?
fn daemon_running(socket: &Path) -> bool {
    matches!(
        try_daemon_call(socket, op::STATUS, serde_json::Value::Null),
        Ok(Some(_))
    )
}

/// The live-loop caveat (`spec-growlight` §12): a running growlightd launches
/// agents with the binary it was started from, so it keeps executing the
/// pre-upgrade build until it is restarted. `upgrade` detects the orchestrator
/// socket and warns rather than silently stranding a stale loop.
fn warn_if_growlight_live() {
    if growlightd_runtime_socket_path().exists() {
        println!(
            "WARNING: a growlight orchestrator appears to be running. It was started \
             with the pre-upgrade binary and will keep executing it until restarted — \
             restart the growlight loop by hand (`softfig growlight` restart, or \
             `systemctl --user restart softfig-growlightd.service`)."
        );
    }
}

/// Run pending migrations with the newly-installed `softfig` binary: print
/// `migrate` status, and if the garden is mid-migration (`prepared`), run
/// `migrate finalize`. The one-time `split` / `config` / `reindex` conversions
/// are idempotent and remain manual. Best-effort — the version confirmation
/// below is the hard gate; the store schema check is the daemon's own boot
/// gate (a refused schema shows up as a failed cycle above).
fn run_migrations(prefix: &Path) {
    let softfig = prefix.join("softfig");
    println!("checking migrations (`softfig migrate`)…");
    let status = match run_captured(&softfig, &["migrate"]) {
        Ok(out) => {
            print!("{out}");
            out
        }
        Err(e) => {
            println!("migrate status failed: {e:#}");
            return;
        }
    };
    if status.contains("prepared (or finalized)")
        && status.contains("run `softfig migrate finalize`")
    {
        println!("finalizing the migration (`softfig migrate finalize`)…");
        match run_captured(&softfig, &["migrate", "finalize"]) {
            Ok(out) => print!("{out}"),
            Err(e) => println!("migrate finalize failed: {e:#} — run it by hand after the daemon is up"),
        }
    }
}

/// Run `program args…`, returning combined stdout+stderr.
fn run_captured(program: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(program).args(args).output().with_context(|| {
        format!("running {} {}", program.display(), args.join(" "))
    })?;
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    if !out.status.success() {
        bail!("{} exited {}", program.display(), out.status);
    }
    Ok(combined)
}

/// Confirm the running daemon reports the *built* version, and that its
/// executable was not replaced on disk since it started (slice 002). This
/// process is the pre-upgrade binary, so the check is against `target`, not
/// `binary_version()`. A missing daemon is reported, not fatal — the swap and
/// cycle have already done their work.
fn confirm_upgraded(socket: &Path, target: &str) -> Result<()> {
    match try_daemon_call(socket, op::STATUS, serde_json::Value::Null) {
        Ok(Some(v)) => {
            let reply: StatusReply = serde_json::from_value(v)?;
            let mut problems = Vec::new();
            match reply.axes.as_ref().map(|a| a.binary.as_str()) {
                Some(b) if b == target => println!("daemon version  {b} (upgraded)"),
                Some(b) => {
                    println!("daemon version  {b}");
                    problems.push(format!(
                        "the running daemon reports {b}, expected {target} — the cycle \
                         did not land on the new build; cycle again (`softfig daemon cycle`)"
                    ));
                }
                None => problems.push(
                    "the daemon does not report a binary version (predates stamping) — \
                     cannot confirm the upgrade"
                        .to_string(),
                ),
            }
            if let Some(exe) = &reply.exe
                && let Some(replaced) = exe.strip_suffix(" (deleted)")
            {
                println!("daemon exe      {replaced} (replaced on disk since it started)");
                problems.push(format!(
                    "the running daemon's binary {replaced} was replaced on disk after it \
                     started — cycle the daemon again"
                ));
            }
            if problems.is_empty() {
                Ok(())
            } else {
                bail!("{}", problems.join("\n"))
            }
        }
        Ok(None) => {
            println!("daemon not running — start it with `softfig daemon start` to confirm.");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn same_minor_and_previous_minor_are_allowed() {
        // Patch / pre-release within a minor.
        assert!(support_window_allows(&v("1.0.0"), &v("1.0.1")));
        assert!(support_window_allows(&v("1.0.0-alpha.1"), &v("1.0.0")));
        // Previous minor.
        assert!(support_window_allows(&v("1.0.0"), &v("1.1.0")));
        assert!(support_window_allows(&v("0.1.0"), &v("0.2.0")));
    }

    #[test]
    fn older_than_the_previous_minor_is_refused() {
        // Skipped a minor.
        assert!(!support_window_allows(&v("1.0.0"), &v("1.2.0")));
        // Cross-major.
        assert!(!support_window_allows(&v("0.1.0"), &v("1.0.0")));
        assert!(!support_window_allows(&v("1.9.0"), &v("2.0.0")));
    }

    #[test]
    fn a_downgrade_is_never_an_upgrade() {
        assert!(!support_window_allows(&v("1.1.0"), &v("1.0.0")));
        assert!(!support_window_allows(&v("1.0.1"), &v("1.0.0")));
    }
}
