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
use zeroize::Zeroizing;

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
    /// the session without the passphrase. Mints a one-time relock token,
    /// stops the daemon, waits for systemd to respawn it Locked, then redeems
    /// the token — held in this process's RAM the whole time, never on disk or
    /// in the model's context. Requires `[growlight] allow_relock = true`.
    Cycle(CycleArgs),
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
    match call_simple(&path, op::SHUTDOWN, serde_json::Value::Null) {
        Ok(_) => {
            println!("daemon: stopping");
            Ok(())
        }
        Err(e) if e.is_daemon_absent() => {
            println!("daemon: not running");
            Ok(())
        }
        Err(e) => Err(anyhow!("{e}")),
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

/// Growlight `cycle`: mint → stop → wait-for-Locked → redeem, all in this one
/// process so the token never touches disk or the model's context. The only
/// at-rest artifact is the wrapped-KEK blob on tmpfs, useless without the
/// token. If anything aborts mid-cycle the token in RAM is lost and the blob
/// expires — the garden stays locked and the human re-unlocks (safe failure).
fn cycle(args: CycleArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);

    // 1. Mint a non-persisted token (returned in the reply, held in RAM).
    let mut mint: RelockMintReply = match try_daemon_call(
        &socket,
        op::RELOCK_MINT,
        json!({ "persist": false }),
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
    // Move the token into a zeroizing holder and clear the reply's copy.
    let token = Zeroizing::new(
        mint.token
            .take()
            .ok_or_else(|| anyhow!("daemon did not return a cycle token"))?,
    );
    let expires_at = mint.expires_at;
    println!("cycle: relock token minted (expires_at {expires_at}); stopping daemon…");

    // 2. Stop the daemon (systemd respawns it onto the new binary, Locked).
    call_simple(&socket, op::SHUTDOWN, serde_json::Value::Null)
        .map_err(|e| anyhow!("daemon stop failed: {e}"))?;

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
                 softfig-keeperd user service set to auto-restart? The in-RAM \
                 relock token is now lost and the tmpfs blob will expire \
                 (expires_at {expires_at}); the garden stays locked — re-unlock \
                 with `softfig daemon unlock` once the daemon is back.",
                args.timeout
            );
        }
    }
    println!("cycle: daemon restarted; redeeming…");

    // 4. Redeem with the in-RAM token → Unlocked. Zeroized on drop.
    let data = call_simple(&socket, op::RELOCK_REDEEM, json!({ "token": token.as_str() }))
        .map_err(|e| {
            anyhow!(
                "relock redeem failed: {e}. The garden remains locked; \
                 re-unlock with `softfig daemon unlock`."
            )
        })?;
    let state = data
        .get("state")
        .and_then(|s| s.as_str())
        .unwrap_or("unlocked");
    println!("cycle: daemon resumed ({state})");
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
