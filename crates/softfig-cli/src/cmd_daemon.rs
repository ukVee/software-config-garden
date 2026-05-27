//! `softfig daemon {start, stop, status, unlock}`.
//!
//! `start` is foreground/dev-mode — systemd's user unit handles boot in
//! the long run. `unlock` reads the passphrase via `rpassword` and
//! forwards it to a running daemon over the IPC socket. `stop` sends
//! `shutdown`. `status` queries `state`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use softfig_ipc::{
    runtime_socket_path,
    verbs::{op, StatusReply, UnlockArgs, UnlockReply},
    ClientError, Request,
};

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
    let status = cmd
        .status()
        .context("failed to launch softfig-keeperd")?;
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
