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

use crate::cmd_daemon::{cycle, stop_daemon, try_daemon_call, CycleArgs, CYCLE_RESTART_TIMEOUT_SECS};

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
    /// Re-install even when the installed set already matches the built set
    /// (same version *and* same build id).
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: UpgradeArgs) -> Result<()> {
    let source = args.source.clone().unwrap_or_else(|| PathBuf::from("."));
    let prefix = args.prefix.clone().unwrap_or_else(default_prefix);
    let socket = args.socket.clone().unwrap_or_else(runtime_socket_path);

    // 0. Preflight the daemon ONCE, before anything is swapped: is one
    //    running, is it locked, and can it be relock-cycled? The cycle
    //    capability must be known *before* the swap — after the swap the only
    //    safe non-cycle move is a shutdown (the running daemon is the old
    //    binary against a new set).
    let supervisor = Supervisor::detect();
    let daemon = daemon_state(&socket);
    let cycle_ok = can_cycle(supervisor, &daemon);

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

    // 4. Stage + atomically install the reconciled set (idempotent by
    //    identity; --force re-swaps even an identical identity).
    match stage_and_swap(&source, &prefix, args.force)? {
        StageOutcome::Noop { version, .. } => {
            println!("already at {version} in {} — nothing to swap", prefix.display());
        }
        StageOutcome::Swapped { version, build_id, from } => match from {
            Some((prev_version, prev_build_id)) if prev_version == version => {
                println!(
                    "installed: same version {version}, new build {build_id}                      (was {prev_build_id}) in {}",
                    prefix.display()
                );
            }
            Some((prev_version, _)) => {
                println!(
                    "installed: upgraded {prev_version} → {version} (build {build_id}) in {}",
                    prefix.display()
                );
            }
            None => {
                println!("installed: {version} (build {build_id}) in {}", prefix.display());
            }
        },
    }

    // 5. Run pending migrations with the newly-installed binary, BEFORE the
    //    daemon cycle. A schema-bumping release must apply its migration while
    //    the old daemon is still up, not after the new daemon boots and refuses
    //    the old store (report 055). The garden is resolved from the daemon
    //    explicitly — this process's cwd is the source checkout, never the
    //    garden.
    if !args.no_migrate {
        run_migrations(&prefix, daemon.garden_root.as_deref())?;
    }

    // 6. Warn about a live growlight loop (spec-growlight §12), then cycle the
    //    daemon onto the new build — or, when a cycle is impossible, stop it so
    //    it is not left running the old binary against the new set.
    warn_if_growlight_live();

    if cycle_ok {
        // Running, unlocked, relock-enabled, and a systemd user bus will
        // respawn it — the clean relock cycle.
        cycle(CycleArgs {
            socket: Some(socket.clone()),
            timeout: args.timeout,
        })?;
        // 7. Confirm the running daemon now reports the new version.
        confirm_upgraded(&socket, &target)?;
    } else if daemon.running {
        // A running daemon we cannot cycle (no supervisor, locked, or relock
        // disabled): stop it, tell the human how to bring it back, and skip the
        // confirm — the daemon is down, so confirming would only report it
        // absent.
        stop_daemon(&socket)?;
        println!(
            "cannot cycle the daemon automatically ({}); stopped it so it does not\n\
             keep running the pre-upgrade binary. Start + unlock it by hand:\n  \
             softfig daemon start\n  softfig daemon unlock",
            no_cycle_reason(supervisor, &daemon)
        );
    } else {
        println!("daemon not running — start it with `softfig daemon start`.");
    }

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

/// The keeperd's state, read ONCE before the swap so the upgrade can decide
/// its cycle path up front (M1). `relock_enabled` is the `[growlight]
/// allow_relock` opt-in surfaced in [`StatusReply`]; a daemon older than that
/// field reads `false` — the fail-closed default, i.e. no cycle.
struct DaemonState {
    running: bool,
    locked: bool,
    relock_enabled: bool,
    garden_root: Option<String>,
}

/// Read the daemon's state in one `status` call. A missing daemon (or an
/// unparseable reply — a pre-stamp build, say) reports a fail-closed state:
/// no cycle, no garden.
fn daemon_state(socket: &Path) -> DaemonState {
    match try_daemon_call(socket, op::STATUS, serde_json::Value::Null) {
        Ok(Some(v)) => match serde_json::from_value::<StatusReply>(v) {
            Ok(r) => DaemonState {
                running: true,
                locked: r.state == "locked",
                relock_enabled: r.relock_enabled,
                garden_root: (!r.garden_root.is_empty()).then_some(r.garden_root),
            },
            Err(_) => DaemonState {
                running: true,
                locked: false,
                relock_enabled: false,
                garden_root: None,
            },
        },
        _ => DaemonState {
            running: false,
            locked: false,
            relock_enabled: false,
            garden_root: None,
        },
    }
}

/// Can the upgrade cycle the daemon onto the new build? Only when a systemd
/// user bus will respawn it, the daemon is running and unlocked, and relock is
/// enabled (`[growlight] allow_relock`). Every other case takes the shutdown
/// path instead of a cycle that would bail mid-flight.
fn can_cycle(supervisor: Supervisor, daemon: &DaemonState) -> bool {
    supervisor == Supervisor::SystemdUser
        && daemon.running
        && !daemon.locked
        && daemon.relock_enabled
}

/// Why a running daemon cannot be cycled, for the shutdown path's message. The
/// three cases are mutually exclusive by [`can_cycle`]'s construction (a
/// running, unlocked, relock-enabled daemon with a systemd bus cycles).
fn no_cycle_reason(supervisor: Supervisor, daemon: &DaemonState) -> &'static str {
    if supervisor != Supervisor::SystemdUser {
        "no systemd user bus detected"
    } else if daemon.locked {
        "the daemon is locked"
    } else {
        "relock is disabled (`[growlight] allow_relock` not set)"
    }
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

/// Run pending migrations with the newly-installed `softfig` binary, BEFORE the
/// daemon cycle (report 055): print `migrate` status against the daemon's garden
/// (resolved explicitly — never from this process's cwd, which is the source
/// checkout), and if the garden is mid-migration (`prepared`), run
/// `migrate finalize`. A failed migration now fails the upgrade with the remedy
/// instead of being swallowed. The one-time `split` / `config` / `reindex`
/// conversions are idempotent and remain manual.
fn run_migrations(prefix: &Path, garden_root: Option<&str>) -> Result<()> {
    let softfig = prefix.join("softfig");

    // No daemon ⇒ no garden to migrate: the store-schema gate runs the
    // migration at the next daemon boot, so there is nothing to do here.
    let Some(garden) = garden_root else {
        println!("daemon not running — migrations will run at the next daemon boot.");
        return Ok(());
    };

    println!("checking migrations (`softfig migrate --garden {garden}`)…");
    let status = run_captured(&softfig, &["migrate", "--garden", garden])
        .with_context(|| "migration check failed — fix it by hand (`softfig migrate`), then re-run `softfig upgrade`")?;
    print!("{status}");
    if needs_finalize(&status) {
        println!("finalizing the migration (`softfig migrate finalize`)…");
        let out = run_captured(&softfig, &["migrate", "finalize"])
            .with_context(|| "migration failed — fix it by hand (`softfig migrate`), then re-run `softfig upgrade`")?;
        print!("{out}");
    }
    Ok(())
}

/// Does a `migrate` status output name a prepared-but-not-finalized garden?
fn needs_finalize(status: &str) -> bool {
    status.contains("prepared (or finalized)")
        && status.contains("run `softfig migrate finalize`")
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

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread::JoinHandle;

    use serde_json::json;
    use softfig_ipc::{Request, Response, PROTOCOL_VERSION};

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

    #[test]
    fn finalize_is_gated_on_both_status_markers() {
        // A prepared-but-not-finalized garden prints both markers.
        let prepared = "phase             prepared (or finalized)\n\
                        next              run `softfig migrate finalize` once FUSE is mounted\n";
        assert!(needs_finalize(prepared));
        // A garden with a state_root but nothing left to delete prints the
        // phase marker without the finalize instruction — not a finalize.
        let migrated = "phase             prepared (or finalized)\n\
                        next              fully migrated; nothing to do\n";
        assert!(!needs_finalize(migrated));
        // An unmigrated garden prints neither.
        assert!(!needs_finalize("phase             unmigrated (no keeper.toml)\n"));
    }

    // ---- M1: the daemon-state preflight + cycle decision ----

    /// A one-connection mock keeperd answering `status` with `reply`, so
    /// `daemon_state` can be read against a scripted daemon (locked,
    /// relock-disabled, etc.).
    fn spawn_status_daemon(socket: &std::path::Path, reply: serde_json::Value) -> JoinHandle<()> {
        let listener = UnixListener::bind(socket).expect("bind mock socket");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap()).read_line(&mut line).unwrap();
            let req: Request = serde_json::from_str(line.trim_end()).unwrap();
            assert_eq!(req.op, op::STATUS);
            let mut bytes = serde_json::to_vec(&Response::ok(reply)).unwrap();
            bytes.push(b'\n');
            stream.write_all(&bytes).unwrap();
        })
    }

    fn status_json(state: &str, relock_enabled: bool) -> serde_json::Value {
        json!({
            "state": state,
            "tip": null,
            "garden_root": "/g",
            "protocol_version": PROTOCOL_VERSION,
            "relock_enabled": relock_enabled,
        })
    }

    fn state(running: bool, locked: bool, relock_enabled: bool) -> DaemonState {
        DaemonState {
            running,
            locked,
            relock_enabled,
            garden_root: None,
        }
    }

    #[test]
    fn daemon_state_reads_running_locked_and_relock() {
        let dir = tempfile::tempdir().unwrap();

        // Unlocked + relock-enabled: a cycle candidate.
        let socket = dir.path().join("unlocked.sock");
        let mock = spawn_status_daemon(&socket, status_json("unlocked", true));
        let s = daemon_state(&socket);
        mock.join().unwrap();
        assert!(s.running);
        assert!(!s.locked);
        assert!(s.relock_enabled);
        assert_eq!(s.garden_root.as_deref(), Some("/g"));

        // Locked.
        let socket = dir.path().join("locked.sock");
        let mock = spawn_status_daemon(&socket, status_json("locked", true));
        let s = daemon_state(&socket);
        mock.join().unwrap();
        assert!(s.running);
        assert!(s.locked);
        assert!(s.relock_enabled);

        // Relock-disabled.
        let socket = dir.path().join("relock-off.sock");
        let mock = spawn_status_daemon(&socket, status_json("unlocked", false));
        let s = daemon_state(&socket);
        mock.join().unwrap();
        assert!(s.running);
        assert!(!s.locked);
        assert!(!s.relock_enabled);
    }

    #[test]
    fn daemon_state_reports_an_absent_daemon_as_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let s = daemon_state(&dir.path().join("absent.sock"));
        assert!(!s.running);
        assert!(!s.locked);
        assert!(!s.relock_enabled);
        assert_eq!(s.garden_root, None);
    }

    #[test]
    fn can_cycle_requires_supervisor_running_unlocked_and_relock() {
        // The one combination that cycles.
        assert!(can_cycle(Supervisor::SystemdUser, &state(true, false, true)));
        // Supervisor::None → no respawn, shutdown path.
        assert!(!can_cycle(Supervisor::None, &state(true, false, true)));
        // Locked → cycle can only resume an unlocked session.
        assert!(!can_cycle(Supervisor::SystemdUser, &state(true, true, true)));
        // Relock disabled → the mint would bail.
        assert!(!can_cycle(Supervisor::SystemdUser, &state(true, false, false)));
        // Not running → nothing to cycle.
        assert!(!can_cycle(Supervisor::SystemdUser, &state(false, false, true)));
    }

    #[test]
    fn no_cycle_reason_names_each_failure() {
        assert_eq!(
            no_cycle_reason(Supervisor::None, &state(true, false, true)),
            "no systemd user bus detected"
        );
        assert_eq!(
            no_cycle_reason(Supervisor::SystemdUser, &state(true, true, true)),
            "the daemon is locked"
        );
        assert_eq!(
            no_cycle_reason(Supervisor::SystemdUser, &state(true, false, false)),
            "relock is disabled (`[growlight] allow_relock` not set)"
        );
    }
}
