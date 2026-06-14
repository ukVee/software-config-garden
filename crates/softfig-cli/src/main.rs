use clap::{Args, Parser, Subcommand};

mod cmd_daemon;
mod cmd_deploy;
mod cmd_migrate;
mod cmd_onboard;
mod cmd_pair;
mod cmd_replica;
mod cmd_repo;
mod cmd_reveal;
mod cmd_vault;

#[derive(Parser, Debug)]
#[command(name = "softfig", version, about = "soft-fig: garden tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scaffold a fresh garden from the default skeleton, init the Vault,
    /// and write a born-in-FUSE genesis commit (first-run wizard).
    Onboard(cmd_onboard::OnboardArgs),

    /// Manage the on-disk Vault (encryption keys, identity, recovery).
    #[command(subcommand)]
    Vault(cmd_vault::VaultCmd),

    /// Initialize a fresh repository in the current garden.
    Init(cmd_repo::InitArgs),
    /// Snapshot the current working tree as a new commit.
    Commit(cmd_repo::CommitArgs),
    /// Show the commit history starting at tip.
    Log(cmd_repo::LogArgs),
    /// Show a single commit + its root tree entries.
    Show(cmd_repo::ShowArgs),
    /// Verify object hashes, tree hashes, signatures, and reachability.
    Fsck(cmd_repo::FsckArgs),

    /// Per-device daemon controls (start/stop/status/unlock).
    #[command(subcommand)]
    Daemon(cmd_daemon::DaemonCmd),

    /// Migrate this garden into M2a's daemon-mounted FUSE layout. With
    /// no subcommand, prints the current migration phase.
    Migrate(MigrateCli),

    /// Reveal a sealed Layer B file's plaintext into
    /// `$XDG_RUNTIME_DIR` (mode 0600); records an audit `vault_reveal`
    /// commit.
    Reveal(cmd_reveal::RevealArgs),

    /// Deploy the garden's `config/deploy.toml` table onto the filesystem
    /// (the `bombadil link` replacement; M4a static spine). Requires the
    /// garden unlocked.
    Deploy(cmd_deploy::DeployArgs),

    /// Pair with another device over the network trust ring (M5a). Runs the
    /// Noise `XX` handshake + SAS confirmation, then persists the peer.
    Pair(cmd_pair::PairArgs),
    /// List paired devices (the network trust ring) + any pending pairings.
    Peers(cmd_pair::PeersArgs),
    /// Remove a device from the ring (unpair) by fingerprint.
    Unpair(cmd_pair::UnpairArgs),

    /// Zero-knowledge device-chain replication (M5b): grant/revoke which paired
    /// hosts may back up this device's chain, and show backup health.
    #[command(subcommand)]
    Replica(cmd_replica::ReplicaCmd),
}

#[derive(Args, Debug)]
struct MigrateCli {
    #[command(subcommand)]
    cmd: Option<cmd_migrate::MigrateCmd>,
    #[command(flatten)]
    status: cmd_migrate::StatusArgs,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Onboard(args) => cmd_onboard::run(args),
        Cmd::Vault(cmd) => cmd_vault::run(cmd),
        Cmd::Init(args) => cmd_repo::init(args),
        Cmd::Commit(args) => cmd_repo::commit(args),
        Cmd::Log(args) => cmd_repo::log(args),
        Cmd::Show(args) => cmd_repo::show(args),
        Cmd::Fsck(args) => cmd_repo::fsck(args),
        Cmd::Daemon(cmd) => cmd_daemon::run(cmd),
        Cmd::Migrate(args) => cmd_migrate::run(args.cmd, args.status),
        Cmd::Reveal(args) => cmd_reveal::run(args),
        Cmd::Deploy(args) => cmd_deploy::run(args),
        Cmd::Pair(args) => cmd_pair::pair(args),
        Cmd::Peers(args) => cmd_pair::peers(args),
        Cmd::Unpair(args) => cmd_pair::unpair(args),
        Cmd::Replica(cmd) => cmd_replica::run(cmd),
    }
}
