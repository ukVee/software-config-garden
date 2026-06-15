use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use softfig_ipc::{
    runtime_socket_path,
    verbs::{
        op, VaultListSealedReply, VaultSealArgs, VaultSealReply, VaultUnsealArgs, VaultUnsealReply,
    },
};
use softfig_vault::{discover_garden, RecoveryPhrase, Vault};

use crate::cmd_daemon::try_daemon_call;

#[derive(Subcommand, Debug)]
pub enum VaultCmd {
    /// Initialize a fresh vault under <garden>/.softfig/vault/.
    Init {
        /// Garden root. Defaults to the current directory.
        #[arg(long)]
        garden: Option<PathBuf>,
    },
    /// Print vault status (active key id, generations on disk, identity fingerprint).
    Status {
        #[arg(long)]
        garden: Option<PathBuf>,
    },
    /// Generate a new master-key generation and make it active.
    RotateKey {
        #[arg(long)]
        garden: Option<PathBuf>,
    },
    /// Unlock with the recovery phrase and re-wrap K under a new passphrase.
    Recover {
        #[arg(long)]
        garden: Option<PathBuf>,
    },
    /// M2b: append a glob to `.softfig/vault/sealed-paths.toml` (daemon
    /// commits a `schema_change` and auto-encrypts matching files).
    Seal {
        /// Glob pattern (`**`, `*`, `?`, `[…]`, `{a,b}`).
        pattern: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// M2b: remove a glob from `sealed-paths.toml`. Does NOT bulk-decrypt
    /// already-sealed blobs (rewrite through FUSE if you want Layer A
    /// bytes back).
    Unseal {
        pattern: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// M2b: print the current globs and the tracked files that match
    /// them.
    ListSealed {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

pub fn run(cmd: VaultCmd) -> Result<()> {
    match cmd {
        VaultCmd::Init { garden } => init(resolve_for_init(garden)?),
        VaultCmd::Status { garden } => status(resolve(garden)?),
        VaultCmd::RotateKey { garden } => rotate_key(resolve(garden)?),
        VaultCmd::Recover { garden } => recover(resolve(garden)?),
        VaultCmd::Seal { pattern, socket } => seal(pattern, socket),
        VaultCmd::Unseal { pattern, socket } => unseal(pattern, socket),
        VaultCmd::ListSealed { socket } => list_sealed(socket),
    }
}

fn seal(pattern: String, socket: Option<PathBuf>) -> Result<()> {
    let socket = socket.unwrap_or_else(runtime_socket_path);
    let args = serde_json::to_value(VaultSealArgs { pattern })?;
    let reply = try_daemon_call(&socket, op::VAULT_SEAL, args)
        .map_err(|e| anyhow!("{e}"))?
        .ok_or_else(|| anyhow!("daemon not running"))?;
    let r: VaultSealReply = serde_json::from_value(reply)?;
    println!("schema_change   {}", r.schema_commit);
    if let Some(h) = &r.seal_commit {
        println!("vault_seal      {h}");
        println!("newly sealed ({}):", r.newly_sealed.len());
        for p in &r.newly_sealed {
            println!("  {p}");
        }
    } else {
        println!("no tracked files matched the new glob — nothing to migrate");
    }
    Ok(())
}

fn unseal(pattern: String, socket: Option<PathBuf>) -> Result<()> {
    let socket = socket.unwrap_or_else(runtime_socket_path);
    let args = serde_json::to_value(VaultUnsealArgs { pattern })?;
    let reply = try_daemon_call(&socket, op::VAULT_UNSEAL, args)
        .map_err(|e| anyhow!("{e}"))?
        .ok_or_else(|| anyhow!("daemon not running"))?;
    let r: VaultUnsealReply = serde_json::from_value(reply)?;
    if r.removed {
        println!("schema_change   {}", r.schema_commit);
        println!("(already-sealed blobs remain Layer-B-encrypted on disk)");
    } else {
        println!("pattern not present — no change");
    }
    Ok(())
}

fn list_sealed(socket: Option<PathBuf>) -> Result<()> {
    let socket = socket.unwrap_or_else(runtime_socket_path);
    let reply = try_daemon_call(&socket, op::VAULT_LIST_SEALED, serde_json::Value::Null)
        .map_err(|e| anyhow!("{e}"))?
        .ok_or_else(|| anyhow!("daemon not running"))?;
    let r: VaultListSealedReply = serde_json::from_value(reply)?;
    println!("globs:");
    for g in &r.globs {
        println!("  {g}");
    }
    println!("matching files:");
    for p in &r.matching_files {
        println!("  {p}");
    }
    Ok(())
}

/// For `init`: caller can specify a garden, otherwise we use $PWD as-is.
/// We don't walk up — `init` always creates a new `.softfig/` here.
fn resolve_for_init(garden: Option<PathBuf>) -> Result<PathBuf> {
    Ok(match garden {
        Some(p) => p,
        None => std::env::current_dir().context("could not read $PWD")?,
    })
}

/// For other commands: walk up from $PWD (or `garden`) looking for `.softfig/`.
fn resolve(garden: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = garden {
        return Ok(p);
    }
    let here = std::env::current_dir().context("could not read $PWD")?;
    discover_garden(&here)
        .ok_or_else(|| anyhow!("no .softfig/ found in {} or any parent", here.display()))
}

fn init(garden: PathBuf) -> Result<()> {
    if !garden.is_dir() {
        std::fs::create_dir_all(&garden)
            .with_context(|| format!("could not create garden dir {}", garden.display()))?;
    }
    println!("Initializing vault at {}/.softfig/vault/", garden.display());
    let pass1 = prompt_passphrase("Choose a passphrase: ")?;
    let pass2 = prompt_passphrase("Confirm passphrase: ")?;
    if pass1 != pass2 {
        return Err(anyhow!("passphrases do not match"));
    }

    let (_vault, session, recovery) = Vault::init(&garden, pass1.as_bytes())?;
    print_recovery(&recovery);

    println!();
    println!("Vault initialized.");
    println!(
        "  active master_key_id : {}",
        session.active_master_key_id()
    );
    println!(
        "  identity pubkey      : {}",
        hex::encode(session.identity_pubkey().to_bytes())
    );
    Ok(())
}

fn status(garden: PathBuf) -> Result<()> {
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        println!("no vault at {}", vault.paths().root.display());
        return Ok(());
    }
    let pass = prompt_passphrase("Passphrase: ")?;
    let session = vault.unlock(pass.as_bytes())?;
    println!("Vault: {}", vault.paths().root.display());
    println!(
        "  active master_key_id : {}",
        session.active_master_key_id()
    );
    println!(
        "  generations on disk  : {:?}",
        session.known_master_key_ids()
    );
    println!(
        "  identity pubkey      : {}",
        hex::encode(session.identity_pubkey().to_bytes())
    );
    Ok(())
}

fn rotate_key(garden: PathBuf) -> Result<()> {
    let vault = Vault::at(&garden);
    let pass = prompt_passphrase("Passphrase: ")?;
    let mut session = vault.unlock(pass.as_bytes())?;
    let new_id = session.rotate_master_key()?;
    println!("Rotated. New active master_key_id = {new_id}");
    println!(
        "Generations on disk now: {:?}",
        session.known_master_key_ids()
    );
    Ok(())
}

fn recover(garden: PathBuf) -> Result<()> {
    let vault = Vault::at(&garden);
    println!("Enter your 12-word recovery phrase (single line, words separated by spaces):");
    let phrase_input = read_line()?;
    let phrase = RecoveryPhrase::parse(&phrase_input)?;
    let new_pass1 = prompt_passphrase("New passphrase: ")?;
    let new_pass2 = prompt_passphrase("Confirm new passphrase: ")?;
    if new_pass1 != new_pass2 {
        return Err(anyhow!("passphrases do not match"));
    }
    vault.recover(&phrase, new_pass1.as_bytes())?;
    println!("Recovery successful. Self-path passphrase has been replaced.");
    Ok(())
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("could not read passphrase from tty")
}

fn read_line() -> Result<String> {
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .context("could not read line from stdin")?;
    Ok(s)
}

fn print_recovery(recovery: &RecoveryPhrase) {
    println!();
    println!("==============================================================");
    println!("RECOVERY PHRASE — store this somewhere safe and OFFLINE.");
    println!("It is the ONLY way to unlock this vault if you forget your");
    println!("passphrase. It is shown ONCE and never written to disk in");
    println!("plaintext. Anyone who learns it can unlock your vault.");
    println!("--------------------------------------------------------------");
    println!("    {}", recovery.display());
    println!("==============================================================");
}

// allow unused so the path-only Vault::at signature matches the import
#[allow(dead_code)]
fn _root_marker(_: &Path) {}
