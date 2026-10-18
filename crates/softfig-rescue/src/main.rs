//! `softfig-rescue` — the recovery wedge (`meta/spec-packs.md` phase 1,
//! `meta/spec-release.md` → Artifacts #3): a single prebuilt binary that runs
//! from a live USB or chroot with no install, no daemon, no FUSE, no vault
//! unlock, and no network. It writes the carry-file (phase 1's one portable
//! output) and declares the packs seam. Diagnosis-and-fix is
//! `recovery-pack-v1`'s job; this binary is the profile it rides on.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use softfig_rescue::carry::{CarryError, CarryFile};
use softfig_rescue::packs::{self, PACKS_EMBED_NOTE};

#[derive(Parser, Debug)]
#[command(name = "softfig-rescue", version, about = "soft-fig rescue: the recovery wedge")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Write a fresh carry-file (header + version + plaintext declaration).
    Write {
        /// Where to write the carry-file (default: carry.toml in the current dir).
        #[arg(long)]
        carry_file: Option<PathBuf>,
    },
    /// Read a carry-file back and validate it (the check `onboard` shares).
    Read {
        /// The carry-file to read.
        #[arg(long)]
        carry_file: PathBuf,
    },
    /// Report the packs seam: where packs would be looked up.
    Packs {
        /// Override the packs directory.
        #[arg(long)]
        packs: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("softfig-rescue: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), CarryError> {
    match cli.command {
        Command::Write { carry_file } => {
            let path = carry_file.unwrap_or_else(|| PathBuf::from("carry.toml"));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let carry = CarryFile::new(now);
            carry.write_to(&path)?;
            println!("wrote {} (carry format v{})", path.display(), carry.carry_format_version);
        }
        Command::Read { carry_file } => {
            let carry = CarryFile::read_from(&carry_file)?;
            println!("{carry}");
        }
        Command::Packs { packs } => {
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("."));
            let root = packs::packs_root(packs.as_deref(), &exe_dir);
            println!("packs root: {}", root.display());
            println!("{PACKS_EMBED_NOTE}");
        }
    }
    Ok(())
}
