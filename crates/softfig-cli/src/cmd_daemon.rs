//! `softfig daemon {start, stop, status, unlock}`.
//!
//! `start` is foreground/dev-mode — systemd's user unit handles boot in
//! the long run. `unlock` reads the passphrase via `rpassword` and
//! forwards it to a running daemon over the IPC socket. `stop` sends
//! `shutdown`. `status` queries `state`, every version axis, and checks that
//! this `softfig`, the running daemon, and the installed set are one build.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;
use softfig_ipc::{
    compat::{binary_version, SetReport, SWAP_IN_PROGRESS_MARKER},
    runtime_socket_path,
    verbs::{op, RelockMintReply, StatusReply, UnlockArgs, UnlockReply},
    ClientError, ErrorKind, Request,
};

/// How long `cycle` waits for systemd to respawn the daemon Locked.
pub(crate) const CYCLE_RESTART_TIMEOUT_SECS: u64 = 30;

#[derive(Subcommand, Debug)]
pub enum DaemonCmd {
    /// Run the daemon in the foreground until killed.
    Start(StartArgs),
    /// Send `shutdown` to a running daemon.
    Stop(BasicArgs),
    /// Query the daemon's current state.
    Status(BasicArgs),
    /// Prompt for the vault passphrase and forward it to the daemon.
    Unlock(BasicArgs),
    /// Growlight: atomically cycle the daemon onto a rebuilt binary and resume
    /// the session without the passphrase. Arms a one-time relock token on
    /// `0600` tmpfs, stops the daemon, waits for systemd to respawn it Locked,
    /// then redeems the token (the daemon reads its own token file — the bytes
    /// never enter this process or the model's context). Arming *before* the
    /// stop makes an aborted cycle recoverable with `softfig daemon relock`
    /// instead of a cold passphrase unlock. Requires `[growlight] allow_relock`.
    Cycle(CycleArgs),
    /// Growlight (fallback): arm a relock token for an out-of-band restart.
    /// Persists the one-time token to a `0600` tmpfs file and prints its path;
    /// restart the daemon however you like, then run `softfig daemon relock`.
    /// Prefer `cycle` — `arm` leaves the token briefly at rest beside the blob.
    RelockArm(BasicArgs),
    /// Growlight (fallback): redeem the token armed by `relock-arm` after the
    /// daemon has restarted Locked. The daemon reads its own persisted token
    /// file — no token bytes pass through this command.
    Relock(BasicArgs),
}

#[derive(Args, Debug)]
pub struct CycleArgs {
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Seconds to wait for the daemon to come back Locked after the stop.
    #[arg(long, default_value_t = CYCLE_RESTART_TIMEOUT_SECS)]
    pub timeout: u64,
}

#[derive(Args, Debug)]
pub struct StartArgs {
    /// Garden root. Defaults to the current directory.
    #[arg(long)]
    pub garden: Option<PathBuf>,
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct BasicArgs {
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

pub fn run(cmd: DaemonCmd) -> Result<()> {
    match cmd {
        DaemonCmd::Start(args) => start(args),
        DaemonCmd::Stop(args) => stop(args),
        DaemonCmd::Status(args) => status(args),
        DaemonCmd::Unlock(args) => unlock(args),
        DaemonCmd::Cycle(args) => cycle(args),
        DaemonCmd::RelockArm(args) => relock_arm(args),
        DaemonCmd::Relock(args) => relock(args),
    }
}

fn start(args: StartArgs) -> Result<()> {
    // Foreground/dev mode: exec the bundled binary.
    let bin = which_keeperd()?;
    let garden = args
        .garden
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| anyhow!("could not determine garden root"))?;

    let mut cmd = std::process::Command::new(bin);
    cmd.arg("--garden").arg(&garden);
    if let Some(s) = args.socket {
        cmd.arg("--socket").arg(s);
    }
    let status = cmd.status().context("failed to launch softfig-keeperd")?;
    std::process::exit(status.code().unwrap_or(1));
}

fn stop(args: BasicArgs) -> Result<()> {
    let path = args.socket.unwrap_or_else(runtime_socket_path);
    stop_daemon(&path)
}

/// Send `shutdown` to a running daemon, tolerating a connection drop around
/// the stop as the stop itself (incident 20260622). Prints the outcome and
/// returns `Ok(())` whether the daemon was running or not — stopping an absent
/// daemon is not an error. Shared by the `stop` command and `upgrade`'s
/// non-cycle path (which stops the daemon so it is not left running the old
/// binary against a newly-swapped set).
pub(crate) fn stop_daemon(socket: &Path) -> Result<()> {
    match send_shutdown_tolerating_close(socket)? {
        StopOutcome::Stopped => {
            println!("daemon: stopping");
            Ok(())
        }
        StopOutcome::NotRunning => {
            println!("daemon: not running");
            Ok(())
        }
    }
}

/// Outcome of asking the daemon to stop.
enum StopOutcome {
    /// The daemon acked the stop, or it closed the connection as it tore down —
    /// both mean the stop is under way.
    Stopped,
    /// No daemon was listening to begin with.
    NotRunning,
}

/// Send `shutdown`, treating a connection drop around the stop as the stop
/// itself rather than an error. A daemon that tears its socket/mount down while
/// stopping can close without acking (and even an ack-before-teardown daemon can
/// race a fast process exit); for the *stop* op that close IS the daemon going
/// down, not a failure. Incident 20260622: the old hard-error here aborted
/// `cycle` before the redeem and stranded the daemon Locked.
fn send_shutdown_tolerating_close(socket: &Path) -> Result<StopOutcome> {
    match call_simple(socket, op::SHUTDOWN, serde_json::Value::Null) {
        Ok(_) => Ok(StopOutcome::Stopped),
        Err(e) if e.is_daemon_absent() => Ok(StopOutcome::NotRunning),
        Err(e) if is_connection_drop(&e) => Ok(StopOutcome::Stopped),
        Err(e) => Err(anyhow!("daemon stop failed: {e}")),
    }
}

/// True when the call failed because the connection dropped (no reply / reset /
/// broken pipe) rather than the daemon returning an error. For the stop op a
/// dropped connection means the daemon went down.
fn is_connection_drop(e: &ClientError) -> bool {
    use std::io::ErrorKind as Io;
    match e {
        ClientError::UnexpectedEof => true,
        ClientError::Io(io) => matches!(io.kind(), Io::ConnectionReset | Io::BrokenPipe),
        _ => false,
    }
}

fn status(args: BasicArgs) -> Result<()> {
    let path = args.socket.unwrap_or_else(runtime_socket_path);
    report_status(&path, SetReport::scan_own_dir())
}

/// Print the daemon's state and the version report, then fail if anything in
/// it means the install is not one build (release-pipeline slice 002):
///
/// - the handshake: this `softfig` against the running daemon;
/// - the daemon's executable replaced on disk since it started, which is the
///   same-version rebuild the handshake alone can't see;
/// - the installed set: every binary in this one's directory at one version,
///   so a partial install is named even when the daemon isn't running.
///
/// The report always prints in full first, so the failure has its evidence.
fn report_status(socket: &Path, set: std::io::Result<SetReport>) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();
    // slice 004: the daemon's executable directory, compared to this binary's
    // own directory after the installed set is read, so two installs at one
    // version are named (the version handshake alone can't see them).
    let mut daemon_exe_dir: Option<PathBuf> = None;
    // Whether the version handshake passed. The install-dir comparison is only
    // meaningful when the daemon is this same build; a version mismatch is
    // already named by the handshake.
    let mut handshake_ok = false;
    match call_simple(socket, op::STATUS, serde_json::Value::Null) {
        Ok(data) => {
            let reply: StatusReply = serde_json::from_value(data)?;
            println!("state           {}", reply.state);
            println!("garden          {}", reply.garden_root);
            println!(
                "tip             {}",
                reply.tip.as_deref().unwrap_or("(none)")
            );
            println!("protocol        v{}", reply.protocol_version);
            if reply.relock_pending {
                match reply.relock_expires_at {
                    Some(exp) => println!("relock          armed (expires_at {exp})"),
                    None => println!("relock          armed"),
                }
            }
            match &reply.axes {
                Some(axes) => println!("versions        {axes}"),
                None => println!("versions        (not reported: the daemon predates version stamping)"),
            }
            if let Some(exe) = &reply.exe {
                let exe_path = match exe.strip_suffix(" (deleted)") {
                    Some(replaced) => {
                        println!("daemon exe      {replaced} (replaced on disk since it started)");
                        problems.push(format!(
                            "the running daemon's binary {replaced} was replaced on disk after it \
                             started — cycle the daemon (`softfig daemon cycle`)"
                        ));
                        replaced
                    }
                    None => {
                        println!("daemon exe      {exe}");
                        exe.as_str()
                    }
                };
                daemon_exe_dir = Path::new(exe_path).parent().map(Path::to_path_buf);
            }
            handshake_ok = match reply.version_check() {
                Ok(()) => {
                    println!("handshake       ok ({} on both sides)", binary_version());
                    true
                }
                Err(mismatch) => {
                    println!("handshake       REFUSED");
                    problems.push(mismatch.to_string());
                    false
                }
            };
        }
        Err(e) if e.is_daemon_absent() => println!("daemon: not running"),
        Err(e) => return Err(anyhow!("{e}")),
    }
    match set {
        Ok(set) => {
            println!("installed set   {set}");
            if set.swap_in_progress {
                problems.push(format!(
                    "an interrupted swap left {SWAP_IN_PROGRESS_MARKER} in {} — \
                     re-run the install/upgrade to converge",
                    set.dir.display()
                ));
            } else if set.consistent_identity().is_none() {
                // Identity, not version: a same-version mix of two builds is
                // as partial as two versions (report 073).
                problems.push(format!("partial install: {set}"));
            }
            if handshake_ok
                && let Some(daemon_dir) = &daemon_exe_dir
                && daemon_dir != &set.dir
            {
                problems.push(format!(
                    "two installs at one version: the daemon runs from {} but this \
                     `softfig` is in {}",
                    daemon_dir.display(),
                    set.dir.display(),
                ));
            }
        }
        Err(e) => println!("installed set   (could not find this binary's directory: {e})"),
    }
    if problems.is_empty() {
        Ok(())
    } else {
        bail!("{}", problems.join("\n"))
    }
}

fn unlock(args: BasicArgs) -> Result<()> {
    let path = args.socket.unwrap_or_else(runtime_socket_path);
    let passphrase = rpassword::prompt_password("Vault passphrase: ")
        .context("could not read passphrase from tty")?;
    let req_args = serde_json::to_value(UnlockArgs { passphrase })?;
    let data = call_simple(&path, op::UNLOCK, req_args).map_err(|e| anyhow!("{e}"))?;
    let reply: UnlockReply = serde_json::from_value(data)?;
    println!("daemon: {}", reply.state);
    Ok(())
}

/// Growlight `cycle`: arm → stop → wait-for-Locked → redeem in one process. The
/// token is armed (persisted `0600` on tmpfs, like `relock-arm`) *before* the
/// stop, and a socket close during the stop is treated as the stop completing —
/// so an abort at any step after the mint leaves the token still armed and
/// recoverable with `softfig daemon relock`, never stranding the daemon Locked
/// (incident 20260622). Both artifacts are single-use, deleted on a clean
/// redeem, and tmpfs-only (wiped on reboot); the token bytes never enter this
/// process or the model's context (the daemon reads its own token file).
pub(crate) fn cycle(args: CycleArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);

    // 1. Arm a relock token, PERSISTED to the 0600 tmpfs path. Arming before the
    //    stop is what makes a cycle abort recoverable: if any later step fails,
    //    the token is still armed and `softfig daemon relock` finishes the unlock
    //    — no cold passphrase, no strand. The daemon writes the token bytes
    //    itself; they never enter this process or the model's context.
    let mint: RelockMintReply = match try_daemon_call(
        &socket,
        op::RELOCK_MINT,
        json!({ "persist": true }),
    ) {
        Ok(Some(v)) => serde_json::from_value(v)?,
        Ok(None) => bail!(
            "no running daemon at {} to cycle",
            socket.display()
        ),
        Err(ClientError::Daemon { kind: ErrorKind::RelockDisabled, .. }) => bail!(
            "relock is disabled. Enable it by hand (security-relevant, human-only):\n  \
             set `[growlight] allow_relock = true` in .softfig/keeper.toml, then re-run.\n  \
             An autonomous loop must instead set BLOCKED_ON_HUMAN and stop."
        ),
        Err(ClientError::Daemon { kind: ErrorKind::VaultLocked, .. }) => bail!(
            "the daemon is locked — cycle can only resume an already-unlocked session"
        ),
        Err(e) => bail!("relock mint failed: {e}"),
    };
    let expires_at = mint.expires_at;
    println!("cycle: relock token armed (expires_at {expires_at}); stopping daemon…");

    // 2. Stop the daemon (systemd respawns it onto the new binary, Locked). A
    //    socket close without an ack here IS the stop completing, not a failure.
    send_shutdown_tolerating_close(&socket)?;

    // 3. Wait for the respawned daemon to bind + report Locked. The old daemon
    //    was Unlocked, so the first `locked` we see is unambiguously the new
    //    one (no risk of redeeming against the dying process).
    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        if let Ok(Some(v)) = try_daemon_call(&socket, op::STATUS, json!({}))
            && let Ok(s) = serde_json::from_value::<StatusReply>(v)
                && s.state == "locked" {
                    break;
                }
        if Instant::now() >= deadline {
            bail!(
                "daemon did not come back Locked within {}s. Is the \
                 softfig-keeperd user service set to auto-restart? The relock \
                 token is still armed on tmpfs (expires_at {expires_at}); once the \
                 daemon is back Locked, run `softfig daemon relock` to resume \
                 without the passphrase (or `softfig daemon unlock`).",
                args.timeout
            );
        }
    }
    println!("cycle: daemon restarted; redeeming…");

    // 4. Redeem token-less: the daemon reads its own persisted token file and
    //    rebuilds the session → Unlocked. Single-use: blob + token deleted on
    //    success. If this step fails the token stays armed for a manual
    //    `softfig daemon relock` retry.
    let data = call_simple(&socket, op::RELOCK_REDEEM, json!({}))
        .map_err(|e| {
            anyhow!(
                "relock redeem failed: {e}. The token is still armed on tmpfs; \
                 retry `softfig daemon relock`, or re-unlock with `softfig daemon unlock`."
            )
        })?;
    let state = data
        .get("state")
        .and_then(|s| s.as_str())
        .unwrap_or("unlocked");
    println!("cycle: daemon resumed ({state})");
    Ok(())
}

/// Growlight `relock-arm`: persist a one-time token + the wrapped-KEK blob to
/// tmpfs for an out-of-band restart, then print the paths. This command never
/// sees the token bytes — the daemon writes them and we only relay the path.
fn relock_arm(args: BasicArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let mint: RelockMintReply = match try_daemon_call(&socket, op::RELOCK_MINT, json!({ "persist": true })) {
        Ok(Some(v)) => serde_json::from_value(v)?,
        Ok(None) => bail!("no running daemon at {} to arm", socket.display()),
        Err(ClientError::Daemon { kind: ErrorKind::RelockDisabled, .. }) => bail!(
            "relock is disabled. Set `[growlight] allow_relock = true` in \
             .softfig/keeper.toml by hand (human-only), then re-run."
        ),
        Err(ClientError::Daemon { kind: ErrorKind::VaultLocked, .. }) => {
            bail!("the daemon is locked — relock can only resume an already-unlocked session")
        }
        Err(e) => bail!("relock arm failed: {e}"),
    };
    println!("relock: armed (expires_at {})", mint.expires_at);
    if let Some(tp) = &mint.token_path {
        println!("token   {tp}");
    }
    println!("blob    {}", mint.blob_path);
    println!("restart the daemon, then run: softfig daemon relock");
    Ok(())
}

/// Growlight `relock`: redeem the armed token after the daemon restarted.
/// Sends no token — the daemon reads its own persisted token file.
fn relock(args: BasicArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let data = match try_daemon_call(&socket, op::RELOCK_REDEEM, json!({})) {
        Ok(Some(v)) => v,
        Ok(None) => bail!("no running daemon at {} to relock", socket.display()),
        Err(ClientError::Daemon { kind: ErrorKind::NotFound, message }) => bail!(
            "nothing to redeem: {message}. Did you `softfig daemon relock-arm` first \
             (and has the token not expired)?"
        ),
        Err(e) => bail!(
            "relock redeem failed: {e}. The garden remains locked; re-unlock with \
             `softfig daemon unlock`."
        ),
    };
    let state = data.get("state").and_then(|s| s.as_str()).unwrap_or("unlocked");
    println!("relock: daemon resumed ({state})");
    Ok(())
}

// ---- helpers used by other CLI commands for the bridge fast path ----

/// Try to call the daemon. Returns `Ok(None)` when the daemon socket
/// is absent (the only condition where direct mode is allowed); returns
/// `Ok(Some(value))` on a successful daemon reply; bubbles other errors
/// (including daemon-side errors like `vault_locked`) verbatim.
pub fn try_daemon_call(
    socket: &Path,
    op: &str,
    args: serde_json::Value,
) -> Result<Option<serde_json::Value>, ClientError> {
    match softfig_ipc::connect(socket) {
        Ok(mut stream) => {
            let req = Request::new(op, args);
            let resp = softfig_ipc::call(&mut stream, &req)?;
            match resp.into_result() {
                Ok(v) => Ok(Some(v)),
                Err((kind, message)) => Err(ClientError::Daemon { kind, message }),
            }
        }
        Err(e) if e.is_daemon_absent() => Ok(None),
        Err(e) => Err(e),
    }
}

fn call_simple(
    socket: &Path,
    op: &str,
    args: serde_json::Value,
) -> std::result::Result<serde_json::Value, ClientError> {
    let mut stream = softfig_ipc::connect(socket)?;
    let req = Request::new(op, args);
    let resp = softfig_ipc::call(&mut stream, &req)?;
    match resp.into_result() {
        Ok(v) => Ok(v),
        Err((kind, message)) => Err(ClientError::Daemon { kind, message }),
    }
}

fn which_keeperd() -> Result<PathBuf> {
    // Prefer a sibling binary in the same directory as the running CLI
    // (cargo target dir or installed prefix). Fall back to PATH.
    if let Ok(self_path) = std::env::current_exe()
        && let Some(dir) = self_path.parent() {
            let cand = dir.join("softfig-keeperd");
            if cand.exists() {
                return Ok(cand);
            }
        }
    Ok(PathBuf::from("softfig-keeperd"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use softfig_ipc::{Response, PROTOCOL_VERSION};

    /// A scripted mock keeperd reproducing incident 20260622: its `shutdown`
    /// drops the connection **without** an ack. It then answers `status=locked`
    /// and `relock_redeem=unlocked`, so a robust `cycle` must drive through to a
    /// successful (token-less) redeem despite the missing stop-ack — never
    /// aborting at the stop and stranding the daemon.
    fn spawn_mock_daemon(socket: PathBuf, redeemed: Arc<AtomicBool>) -> JoinHandle<()> {
        let listener = UnixListener::bind(&socket).expect("bind mock socket");
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let mut stream = match conn {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let req: Request = serde_json::from_str(line.trim_end()).unwrap();
                let resp = match req.op.as_str() {
                    // cycle arms with persist=true → reply carries the token PATH,
                    // never the bytes (token redeemed server-side).
                    op::RELOCK_MINT => Some(Response::ok(json!({
                        "persisted": true,
                        "expires_at": 9_999_999_999i64,
                        "blob_path": "/dev/null/mock.blob",
                        "token_path": "/dev/null/mock.token",
                    }))),
                    op::STATUS => Some(Response::ok(json!({
                        "state": "locked",
                        "tip": null,
                        "garden_root": "/mock-garden",
                        "protocol_version": PROTOCOL_VERSION,
                        "relock_pending": true,
                        "relock_expires_at": 9_999_999_999i64,
                    }))),
                    op::RELOCK_REDEEM => {
                        redeemed.store(true, Ordering::SeqCst);
                        Some(Response::ok(json!({ "state": "unlocked" })))
                    }
                    // The bug under repair: the stop closes the socket with NO reply.
                    op::SHUTDOWN => None,
                    other => {
                        Some(Response::err(ErrorKind::BadArgs, format!("unexpected op {other}")))
                    }
                };
                if let Some(resp) = resp {
                    let mut bytes = serde_json::to_vec(&resp).unwrap();
                    bytes.push(b'\n');
                    let _ = stream.write_all(&bytes);
                    let _ = stream.flush();
                }
                // SHUTDOWN falls through here: `stream` drops unwritten → client EOF.
                if redeemed.load(Ordering::SeqCst) {
                    break;
                }
            }
        })
    }

    /// A one-connection mock keeperd answering `status` with `reply`.
    fn spawn_status_daemon(socket: PathBuf, reply: serde_json::Value) -> JoinHandle<()> {
        let listener = UnixListener::bind(&socket).expect("bind mock socket");
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

    fn status_of_build(binary: &str) -> serde_json::Value {
        status_of_build_with_exe(binary, "/usr/bin/softfig-keeperd")
    }

    /// `status_of_build` with the daemon's `exe` path set explicitly, so a test
    /// can place the daemon in this binary's own directory (one install) or
    /// elsewhere (a second install at the same version).
    fn status_of_build_with_exe(binary: &str, exe: &str) -> serde_json::Value {
        let mut axes = softfig_ipc::compat::VersionAxes::this_build(1, 1);
        axes.binary = binary.to_string();
        json!({
            "state": "unlocked",
            "tip": null,
            "garden_root": "/mock-garden",
            "protocol_version": PROTOCOL_VERSION,
            "axes": axes,
            "exe": exe,
        })
    }

    /// An installed set in a tempdir: every binary stamped `version`, except
    /// the overrides (`None` = an unstamped, pre-stamp build).
    fn fake_set(versions: &[(&str, Option<&str>)], version: &str) -> (tempfile::TempDir, SetReport) {
        let dir = tempfile::tempdir().unwrap();
        for name in softfig_ipc::compat::INSTALLED_SET {
            let stamp = versions.iter().find(|(n, _)| *n == name).map_or(Some(version), |(_, v)| *v);
            let bytes = stamp.map_or_else(|| b"old build".to_vec(), softfig_ipc::compat::stamp_for);
            std::fs::write(dir.path().join(name), bytes).unwrap();
        }
        let set = SetReport::scan(dir.path());
        (dir, set)
    }

    /// release-pipeline slice 002: a CLI and a daemon of different builds — the
    /// daemon's reply carries the wrong version — are refused with the
    /// handshake's message, even when the installed set itself is consistent.
    #[test]
    fn status_refuses_a_daemon_of_another_build() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let mock = spawn_status_daemon(socket.clone(), status_of_build("0.0.1"));
        let (_set_dir, set) = fake_set(&[], binary_version());
        let err = report_status(&socket, Ok(set)).unwrap_err().to_string();
        mock.join().unwrap();
        assert_eq!(
            err,
            format!(
                "your `softfig` ({}) is newer than the running daemon (0.0.1) — cycle the daemon \
                 (`softfig daemon cycle`) so it runs the installed build",
                binary_version()
            )
        );
    }

    /// Three of five binaries replaced: the daemon matches this CLI, but the
    /// set doesn't, and `status` names every binary.
    #[test]
    fn status_names_a_partial_install() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let (_set_dir, set) =
            fake_set(&[("softfig-tui", Some("0.0.1")), ("softfig-growlightd", None)], binary_version());
        let exe = set.dir.join("softfig-keeperd");
        let mock = spawn_status_daemon(
            socket.clone(),
            status_of_build_with_exe(binary_version(), &exe.to_string_lossy()),
        );
        let err = report_status(&socket, Ok(set)).unwrap_err().to_string();
        mock.join().unwrap();
        assert!(err.starts_with("partial install: PARTIAL in "), "{err}");
        assert!(
            err.contains(&format!("3 at {} (softfig, softfig-keeperd, softfig-mcp)", binary_version()))
                && err.contains("1 at 0.0.1 (softfig-tui)")
                && err.contains("1 unstamped, older than version stamping (softfig-growlightd)"),
            "{err}"
        );
    }

    /// The set is checked with no daemon at all: a partial install needs no
    /// running daemon to be one.
    #[test]
    fn status_checks_the_set_when_the_daemon_is_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("absent.sock");
        let (_set_dir, set) = fake_set(&[("softfig-mcp", Some("0.0.1"))], binary_version());
        let err = report_status(&socket, Ok(set)).unwrap_err().to_string();
        assert!(err.contains("1 at 0.0.1 (softfig-mcp)"), "{err}");
        let (_set_dir, set) = fake_set(&[], binary_version());
        report_status(&socket, Ok(set)).expect("a consistent set and no daemon is fine");
    }

    /// Report 073: one version at two build ids is a partial install, and
    /// the report names the builds. `consistent_version()` passed this.
    #[test]
    fn status_flags_a_same_version_mix_of_two_builds() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("absent.sock");
        let set_dir = tempfile::tempdir().unwrap();
        for (i, name) in softfig_ipc::compat::INSTALLED_SET.iter().enumerate() {
            let id = if i == 0 { "aaa" } else { "bbb" };
            let bytes = softfig_ipc::compat::stamp_with_identity(binary_version(), id);
            std::fs::write(set_dir.path().join(name), bytes).unwrap();
        }
        let set = SetReport::scan(set_dir.path());
        assert_eq!(set.consistent_version(), Some(binary_version()));
        let err = report_status(&socket, Ok(set)).unwrap_err().to_string();
        assert!(err.starts_with("partial install: PARTIAL in "), "{err}");
        assert!(err.contains(&format!("at {} build aaa", binary_version())), "{err}");
        assert!(err.contains(&format!("at {} build bbb", binary_version())), "{err}");
    }

    #[test]
    fn status_passes_one_build_and_flags_a_replaced_daemon_binary() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let (_set_dir, set) = fake_set(&[], binary_version());
        let exe = set.dir.join("softfig-keeperd");
        let mock = spawn_status_daemon(
            socket.clone(),
            status_of_build_with_exe(binary_version(), &exe.to_string_lossy()),
        );
        report_status(&socket, Ok(set)).expect("one build everywhere");
        mock.join().unwrap();

        // A fresh socket path: the first mock's socket file is still bound.
        let socket = dir.path().join("keeperd-replaced.sock");
        let (_set_dir, set) = fake_set(&[], binary_version());
        let exe = set.dir.join("softfig-keeperd (deleted)");
        let mock = spawn_status_daemon(
            socket.clone(),
            status_of_build_with_exe(binary_version(), &exe.to_string_lossy()),
        );
        let err = report_status(&socket, Ok(set)).unwrap_err().to_string();
        mock.join().unwrap();
        assert!(err.contains("was replaced on disk"), "{err}");
    }

    /// slice 004: a daemon at the same version but running from a different
    /// directory than this binary is named — two installs at one version.
    #[test]
    fn status_names_a_daemon_in_another_install_dir() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        let (_set_dir, set) = fake_set(&[], binary_version());
        let own_dir = set.dir.display().to_string();
        let mock = spawn_status_daemon(
            socket.clone(),
            status_of_build_with_exe(binary_version(), "/usr/local/bin/softfig-keeperd"),
        );
        let err = report_status(&socket, Ok(set)).unwrap_err().to_string();
        mock.join().unwrap();
        assert!(
            err.contains("/usr/local/bin")
                && err.contains(&own_dir)
                && err.contains("two installs at one version"),
            "{err}"
        );
    }

    /// criterion 4: a stop that closes the socket without an ack must not strand
    /// the daemon — `cycle` tolerates the close and still reaches the redeem.
    #[test]
    fn cycle_redeems_even_when_stop_closes_without_ack() {
        let dir =
            std::env::temp_dir().join(format!("softfig-cycle-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("keeperd.sock");
        let _ = std::fs::remove_file(&socket);

        let redeemed = Arc::new(AtomicBool::new(false));
        let _mock = spawn_mock_daemon(socket.clone(), redeemed.clone());
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let res = cycle(CycleArgs { socket: Some(socket.clone()), timeout: 5 });
        assert!(res.is_ok(), "cycle should redeem despite a missing stop-ack: {res:?}");
        assert!(
            redeemed.load(Ordering::SeqCst),
            "cycle must reach the redeem (no strand) after a stop that closed without acking"
        );

        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_dir(&dir);
    }

    /// A clean ack-on-stop also drives the redeem (the daemon-fixed happy path).
    #[test]
    fn is_connection_drop_classifies_eof_and_resets() {
        use std::io::{Error, ErrorKind as Io};
        assert!(is_connection_drop(&ClientError::UnexpectedEof));
        assert!(is_connection_drop(&ClientError::Io(Error::from(Io::ConnectionReset))));
        assert!(is_connection_drop(&ClientError::Io(Error::from(Io::BrokenPipe))));
        // A daemon-side error is NOT a connection drop — it must still surface.
        assert!(!is_connection_drop(&ClientError::Daemon {
            kind: ErrorKind::Internal,
            message: "boom".into(),
        }));
    }
}
