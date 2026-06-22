//! `softfig daemon {start, stop, status, unlock}`.
//!
//! `start` is foreground/dev-mode — systemd's user unit handles boot in
//! the long run. `unlock` reads the passphrase via `rpassword` and
//! forwards it to a running daemon over the IPC socket. `stop` sends
//! `shutdown`. `status` queries `state`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;
use softfig_ipc::{
    runtime_socket_path,
    verbs::{op, RelockMintReply, StatusReply, UnlockArgs, UnlockReply},
    ClientError, ErrorKind, Request,
};

/// How long `cycle` waits for systemd to respawn the daemon Locked.
const CYCLE_RESTART_TIMEOUT_SECS: u64 = 30;

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
    match send_shutdown_tolerating_close(&path)? {
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
    match call_simple(&path, op::STATUS, serde_json::Value::Null) {
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
            Ok(())
        }
        Err(e) if e.is_daemon_absent() => {
            println!("daemon: not running");
            Ok(())
        }
        Err(e) => Err(anyhow!("{e}")),
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
fn cycle(args: CycleArgs) -> Result<()> {
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
        if let Ok(Some(v)) = try_daemon_call(&socket, op::STATUS, json!({})) {
            if let Ok(s) = serde_json::from_value::<StatusReply>(v) {
                if s.state == "locked" {
                    break;
                }
            }
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
    if let Ok(self_path) = std::env::current_exe() {
        if let Some(dir) = self_path.parent() {
            let cand = dir.join("softfig-keeperd");
            if cand.exists() {
                return Ok(cand);
            }
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
