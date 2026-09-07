use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use softfig_ipc::{
    runtime_socket_path,
    verbs::{
        op, VaultListSealedReply, VaultSealArgs, VaultSealReply, VaultUnsealArgs, VaultUnsealReply,
    },
};
use softfig_store::StorePaths;
use softfig_vault::escrow::{self, ExportSummary};
use softfig_vault::recovery_policy::{self, RecoveryStatus, Wrappings};
use softfig_vault::storage;
use softfig_vault::{discover_garden, DeclaredPolicy, RecoveryPhrase, RecoveryPolicy, Vault};

use crate::cmd_daemon::try_daemon_call;

#[derive(Subcommand, Debug)]
pub enum VaultCmd {
    /// Initialize a fresh vault under <garden>/.softfig/vault/.
    Init {
        /// Garden root. Defaults to the current directory.
        #[arg(long)]
        garden: Option<PathBuf>,
    },
    /// Print vault status: the declared recovery policy, the wrappings of K
    /// actually on disk, and any divergence between them, plus the master-key
    /// generations.
    ///
    /// Readable on a **locked** vault — it opens nothing and asks for no
    /// passphrase. Pass `--identity` to additionally unlock and print the
    /// identity fingerprint, the one fact here that cannot be read otherwise.
    Status {
        #[arg(long)]
        garden: Option<PathBuf>,
        /// Also prompt for the passphrase and print the identity public key.
        #[arg(long)]
        identity: bool,
    },
    /// Manage the garden's declared recovery policy.
    Recovery {
        #[command(subcommand)]
        cmd: RecoveryCmd,
    },
    /// Escrow the vault's key material: the small, inert bundle that makes a
    /// passphrase-only garden recoverable.
    Escrow {
        #[command(subcommand)]
        cmd: EscrowCmd,
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

#[derive(Subcommand, Debug)]
pub enum RecoveryCmd {
    /// Declare the recovery shape this garden is meant to have.
    ///
    /// POLICY is `passphrase-only`, `passphrase+phrase`, `passphrase+peers`,
    /// or any `+`-joined combination of `passphrase`, `phrase`, and `peers`.
    ///
    /// This records **intent only**. It adds and removes no wrapping and
    /// touches no key material — declaring a door you do not have is legal,
    /// and `vault status` will report it as a divergence rather than refuse.
    Declare {
        /// The policy to declare.
        policy: String,
        #[arg(long)]
        garden: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum EscrowCmd {
    /// Write every wrapping of K, plus the parameters needed to use them, to
    /// one file safe to copy anywhere.
    ///
    /// Takes **no passphrase and opens nothing** — every byte in the bundle is
    /// already sealed ciphertext or non-secret parameters, so this works on a
    /// vault you cannot currently unlock, which is when you most need it.
    ///
    /// The result is inert without the master passphrase and is about a
    /// kilobyte. Copy it to excess: losing it is the one unrecoverable
    /// failure a passphrase-only garden has.
    Export {
        #[arg(long)]
        garden: Option<PathBuf>,
        /// Where to write the bundle.
        #[arg(long, short)]
        out: PathBuf,
        /// Replace an existing bundle that differs from this export.
        #[arg(long)]
        force: bool,
    },
}

pub fn run(cmd: VaultCmd) -> Result<()> {
    match cmd {
        VaultCmd::Init { garden } => init(resolve_for_init(garden)?),
        VaultCmd::Status { garden, identity } => status(resolve(garden)?, identity),
        VaultCmd::Recovery { cmd } => match cmd {
            RecoveryCmd::Declare { policy, garden } => declare(resolve(garden)?, &policy),
        },
        VaultCmd::Escrow { cmd } => match cmd {
            EscrowCmd::Export { garden, out, force } => {
                escrow_export(resolve(garden)?, out, force)
            }
        },
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

/// `vault status` observes; `vault escrow verify` proves. Nothing here opens a
/// wrapping, which is what keeps status usable on a locked vault — and is why
/// the passphrase prompt moved behind `--identity` rather than gating the whole
/// command. The active key id and the generation list were never secret: they
/// are `active.toml` and the filenames under `master/`.
fn status(garden: PathBuf, identity: bool) -> Result<()> {
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        println!("no vault at {}", vault.paths().root.display());
        return Ok(());
    }
    println!("Vault: {}", vault.paths().root.display());
    print_recovery_status(&RecoveryStatus::read(vault.paths()));

    println!();
    match storage::load_active(vault.paths()) {
        Ok(active) => println!("  active master_key_id : {}", active.master_key_id),
        Err(e) => println!("  active master_key_id : (unreadable: {e})"),
    }
    match storage::list_master_ids(vault.paths()) {
        Ok(ids) => println!("  generations on disk  : {ids:?}"),
        Err(e) => println!("  generations on disk  : (unreadable: {e})"),
    }

    if identity {
        let pass = prompt_passphrase("Passphrase: ")?;
        let session = vault.unlock(pass.as_bytes())?;
        println!(
            "  identity pubkey      : {}",
            hex::encode(session.identity_pubkey().to_bytes())
        );
    } else {
        println!("  identity pubkey      : (locked — re-run with --identity to show)");
    }
    Ok(())
}

/// Record the operator's intent, then immediately show what that intent looks
/// like against the disk. A declaration that introduces a divergence is
/// accepted and reported, not refused: "I mean to have a phrase, and I am about
/// to add one" is a legitimate thing to say.
fn declare(garden: PathBuf, policy: &str) -> Result<()> {
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        return Err(anyhow!("no vault at {}", vault.paths().root.display()));
    }
    let policy = RecoveryPolicy::parse(policy).map_err(|e| anyhow!("{e}"))?;
    recovery_policy::store_declared_policy(vault.paths(), &policy)?;
    println!("Declared recovery policy: {policy}");
    println!();
    println!("Vault: {}", vault.paths().root.display());
    print_recovery_status(&RecoveryStatus::read(vault.paths()));
    Ok(())
}

fn print_recovery_status(st: &RecoveryStatus) {
    let effective = st.effective();
    let provenance = match &st.declared {
        DeclaredPolicy::Declared(_) => "declared",
        DeclaredPolicy::Undeclared => "inferred from disk — not declared",
        DeclaredPolicy::Unreadable(_) => "inferred from disk — the declaration is unreadable",
    };
    println!("  recovery policy      : {effective}  ({provenance})");
    // The reason gets its own line: a TOML parse error is long, and burying it
    // in a parenthetical is how an operator ends up not reading it.
    if let DeclaredPolicy::Unreadable(reason) = &st.declared {
        println!(
            "    ! {}: {reason}",
            storage::RECOVERY_POLICY_FILE
        );
    }
    println!(
        "  wrappings on disk    : {}",
        describe_wrappings(&st.wrappings)
    );

    if st.divergences.is_empty() {
        match &st.declared {
            DeclaredPolicy::Declared(_) => println!("  divergence           : none"),
            DeclaredPolicy::Undeclared => {
                println!("  divergence           : (nothing declared, so nothing to diverge from)")
            }
            DeclaredPolicy::Unreadable(_) => {
                println!("  divergence           : (unchecked — the declaration could not be read)")
            }
        }
    } else {
        println!("  divergence           :");
        for d in &st.divergences {
            println!("    ! {d}");
        }
    }

    if st.is_inferred() {
        println!();
        match &st.declared {
            DeclaredPolicy::Unreadable(_) => println!(
                "  The declaration above could not be read, so the shape was taken from the"
            ),
            _ => println!(
                "  No recovery policy is declared, so the shape above was taken from the"
            ),
        }
        println!("  disk rather than from you — which means nothing here can tell you a door");
        println!("  is missing. State what you intend:");
        println!("      softfig vault recovery declare {effective}");
    }

    if st.wrappings.count() == 1 {
        println!();
        println!("  Note: exactly one wrapping of K exists. Recovery is your passphrase AND");
        println!("  that file — the passphrase alone opens nothing, because no server holds a");
        println!("  copy. Keep the vault directory backed up somewhere off this device.");
    }
}

/// Name the file behind each door. A divergence the operator cannot locate is
/// most of the way to no divergence report at all.
fn describe_wrappings(w: &Wrappings) -> String {
    let mut parts = Vec::new();
    if w.passphrase {
        parts.push(format!("passphrase ({})", storage::KEK_SELF_FILE));
    }
    if w.phrase {
        parts.push(format!("phrase ({})", storage::KEK_RECOVERY_FILE));
    }
    if !w.peers.is_empty() {
        parts.push(format!(
            "peers ({}/: {})",
            storage::PEER_KEKS_DIR,
            w.peers.join(", ")
        ));
    }
    if parts.is_empty() {
        "(none — this vault cannot be opened)".to_string()
    } else {
        parts.join(", ")
    }
}

/// Copy-and-describe, never a crypto operation: no passphrase is read here,
/// which is what lets the bundle be produced for a vault whose passphrase has
/// been forgotten — the vault most worth escrowing.
fn escrow_export(garden: PathBuf, out: PathBuf, force: bool) -> Result<()> {
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        return Err(anyhow!("no vault at {}", vault.paths().root.display()));
    }
    // The label, not the store: a read-only peek that leaves the database
    // untouched, and an unlabelled bundle if there is no readable one. The
    // vault crate stays free of the store dependency, so the id is passed in.
    let garden_id = softfig_store::peek_repo_id(&StorePaths::for_garden(&garden));
    let summary = escrow::export(vault.paths(), garden_id.as_deref(), &out, force)?;
    print_export(&summary);
    Ok(())
}

fn print_export(s: &ExportSummary) {
    println!("Escrow bundle written: {}", s.dest.display());
    println!();
    if s.garden_id.is_empty() {
        println!("  garden id            : (unlabelled — no readable store database)");
    } else {
        println!("  garden id            : {}", s.garden_id);
    }
    println!("  recovery policy      : {}  ({})", s.policy, s.policy_source);
    if !s.policy_note.is_empty() {
        println!("    ! {}", s.policy_note);
    }
    println!("  members ({})          :", s.members.len());
    for m in &s.members {
        println!("      {m}");
    }
    // Absence is the reportable fact on a passphrase-only garden: "no
    // k.recovery" is why this bundle matters.
    if !s.absent.is_empty() {
        println!("  not present          : {}", s.absent.join(", "));
    }
    println!("  size                 : {} bytes", s.bytes);
    println!("  blake3               : {}", s.bundle_blake3);
    println!();
    println!("  This file is inert without your master passphrase — no server holds a copy,");
    println!("  and nothing in it opens on its own. Recovery needs the passphrase AND these");
    println!("  bytes. It is small and it does not change until you rotate: copy it to every");
    println!("  backup target you have. Re-exporting an unchanged vault gives byte-identical");
    println!("  output, so copies can be compared by the hash above.");
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
