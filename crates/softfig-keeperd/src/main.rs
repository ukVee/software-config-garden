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
