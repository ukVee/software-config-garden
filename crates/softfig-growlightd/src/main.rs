use std::path::PathBuf;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use softfig_growlightd::{garden_root_via_keeperd, Daemon, GrowlightdConfig, Policy};
use softfig_ipc::{growlightd_runtime_socket_path, runtime_socket_path};

#[derive(Parser, Debug)]
#[command(
    name = "softfig-growlightd",
    version,
    about = "soft-fig multi-agent orchestrator daemon",
    long_about = None,
)]
struct Cli {
    /// growlightd's own listen socket. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-growlightd.sock`.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// keeperd's socket, queried once (read-only `status`) to derive the garden
    /// root. Defaults to `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    keeperd_socket: Option<PathBuf>,
    /// Use this garden root instead of asking keeperd (skips the `status`
    /// handshake; mainly for tests / unusual setups).
    #[arg(long)]
    garden_root: Option<PathBuf>,
    /// Override the per-device max concurrent agents (default: policy default).
    #[arg(long)]
    max_concurrent_agents: Option<u32>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Derive the garden root the same way `softfig growlight start` does — a
    // read-only keeperd `status`, never a literal path (spec §2/§12). An
    // explicit `--garden-root` short-circuits it.
    let keeperd_socket = cli.keeperd_socket.unwrap_or_else(runtime_socket_path);
    let garden_root = match cli.garden_root {
        Some(p) => p,
        None => garden_root_via_keeperd(&keeperd_socket)
            .context("deriving garden root from keeperd")?,
    };

    let socket = cli.socket.unwrap_or_else(growlightd_runtime_socket_path);
    let mut policy = Policy::default();
    if let Some(n) = cli.max_concurrent_agents {
        policy.max_concurrent_agents = n;
    }
    let config = GrowlightdConfig::new(socket, garden_root.clone()).with_policy(policy);

    let daemon = Daemon::new(config);
    let handle = daemon.start()?;

    eprintln!(
        "softfig-growlightd: listening on {} (garden: {})",
        handle.socket_path().display(),
        garden_root.display(),
    );

    // SIGTERM / SIGINT run the same graceful teardown as the `shutdown` IPC op,
    // delivered through signal-hook's self-pipe so the teardown runs in normal
    // thread context. Once `request_shutdown` flips the daemon to `Stopping`,
    // the accept loop exits on its next poll and `handle.join()` returns.
    let shutdown_daemon = handle.daemon.clone();
    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    thread::Builder::new()
        .name("growlightd-signal".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                eprintln!("softfig-growlightd: caught signal {sig}; shutting down");
                shutdown_daemon.request_shutdown();
            }
        })?;

    handle.join()?;
    Ok(())
}
