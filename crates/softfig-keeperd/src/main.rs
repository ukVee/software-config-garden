use std::path::PathBuf;

use clap::Parser;
use softfig_keeperd::{Daemon, KeeperConfig};

#[derive(Parser, Debug)]
#[command(
    name = "softfig-keeperd",
    version,
    about = "soft-fig per-device daemon",
    long_about = None,
)]
struct Cli {
    /// Garden root. Required.
    #[arg(long)]
    garden: PathBuf,
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Don't start the filesystem watcher (useful for headless / test).
    #[arg(long)]
    no_watcher: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // A prior daemon that died abnormally (crash/SIGKILL, or a SIGTERM that
    // skipped graceful unmount) leaves a *dead* FUSE mount at the garden
    // root — reads through it fail with ENOTCONN. `discover` below reads
    // `<garden>/.softfig/keeper.toml` *through* that path, so a stale mount
    // would make it silently fall back to M1c-compat (no FUSE, wrong vault
    // path) and the daemon could never self-heal (the FUSE mount path that
    // also clears stale mounts is never reached in M1c-compat). Reclaim any
    // stale mount FIRST so discovery sees the real on-disk tree. No-op when
    // nothing is mounted there (the common case).
    softfig_fuse::clear_stale_mount(&cli.garden);
    // Resolve `state_root` from `<garden>/.softfig/keeper.toml` so a
    // born-in-FUSE (or migrated) garden boots straight into FUSE mode. A
    // garden without keeper.toml resolves to M1c-compat (state_root None),
    // identical to the old `KeeperConfig::new` behavior.
    let mut config = KeeperConfig::discover(&cli.garden)?;
    if let Some(s) = cli.socket {
        config = config.with_socket(s);
    }
    if cli.no_watcher {
        config = config.without_watcher();
    }

    let daemon = Daemon::new(config);
    let handle = daemon.start()?;

    eprintln!(
        "softfig-keeperd: listening on {} (state: locked)",
        handle.socket_path().display()
    );

    handle.join()?;
    Ok(())
}
