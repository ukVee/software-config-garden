use std::path::PathBuf;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use std::sync::Arc;

use softfig_growlightd::{
    garden_root_via_keeperd, load_fleet_config, reconcile_on_boot, spawn_bus_tailer, spawn_fleet,
    Daemon, GrowlightdConfig, KeeperdBusSource, KeeperdItemResumer, KeeperdResourcePersister,
    Policy, BUS_POLL_MS,
};
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

    // Install the live item-resume hook (the `resume_item` verb un-blocks a
    // human-parked backlog item over keeperd's `set_item_status`) + the build-cap
    // persist hook (a live `set_resources` writes the new default back into
    // `config/growlight.toml` via keeperd's commit path) — both bound to the same
    // keeperd socket the queue source / claimer / parker use.
    let daemon = Daemon::new(config)
        .with_item_resumer(Arc::new(KeeperdItemResumer::new(keeperd_socket.clone())))
        .with_resource_persister(Arc::new(KeeperdResourcePersister::new(keeperd_socket.clone())));
    let handle = daemon.start()?;

    eprintln!(
        "softfig-growlightd: listening on {} (garden: {})",
        handle.socket_path().display(),
        garden_root.display(),
    );

    // Fan the coordination bus onto `subscribe`: a background tailer polls
    // keeperd's read-only `tail_bus` and republishes each new message as an
    // `Event::BusMessage` (spec §13 Coordinate / the coordination-bus milestone).
    // keeperd owns the store; growlightd owns the stream — the tailer is the
    // one-way client bridge between the two separate daemons. A keeperd blip just
    // fails a poll and retries; it never brings growlightd down.
    let bus_tailer = spawn_bus_tailer(
        handle.daemon.clone(),
        Box::new(KeeperdBusSource::new(keeperd_socket.clone())),
        std::time::Duration::from_millis(BUS_POLL_MS),
    )?;

    // Assemble + spawn the live fleet drive loop, but ONLY when the off-by-default
    // `fleet_enabled` gate in the in-garden `config/growlight.toml` (read through
    // the mount) is on. Gate off ⇒ `None`, nothing constructed or spawned, so
    // growlightd is byte-identical to today.
    let fleet_config = load_fleet_config(&garden_root);
    // Record the gate + roster so `growlight status` reports the configured fleet
    // even when it's disarmed (no drive loop spawned). config-in-garden slice 3.
    handle.daemon.set_fleet_config(fleet_config.clone());

    // Boot reconcile — ONLY when the fleet is armed, and BEFORE `spawn_fleet` starts
    // the drive loop's first claim tick (crash-diagnostics slice 002). It runs
    // synchronously here, so the reset always completes before the loop's first
    // `pick()`. Two steps: SIGKILL stray `growlight-agent-*.scope` units from a prior
    // generation, then reset every orphaned-`active` item (no live holder exists
    // post-restart) to `queued` so the scheduler can re-pick it. Gate off ⇒ skipped,
    // so growlightd stays byte-identical to today when disarmed.
    if fleet_config.enabled {
        reconcile_on_boot(&keeperd_socket);
    }

    let drive_loop = spawn_fleet(&handle.daemon, &fleet_config, &keeperd_socket)
        .context("spawning the live fleet drive loop")?;
    if drive_loop.is_some() {
        eprintln!(
            "softfig-growlightd: fleet ENABLED — drive loop running ({} member(s))",
            fleet_config.members.len(),
        );
    }

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
    // The daemon is `Stopping` now; the tailer + drive loop each notice on their
    // next tick and exit.
    let _ = bus_tailer.join();
    if let Some(drive) = drive_loop {
        let _ = drive.join();
    }
    Ok(())
}
