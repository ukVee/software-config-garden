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
use softfig_vault::recovery_policy::{self, RecoveryPath, RecoveryStatus, Wrappings};
use softfig_vault::params::{Argon2Params, OWASP_BASELINE};
use softfig_vault::rewrap;
use softfig_vault::wrappings;
use softfig_vault::storage;
use softfig_vault::{
    discover_garden, DeclaredPolicy, RecoveryPhrase, RecoveryPolicy, Vault, VaultError,
};

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
    /// Re-derive k.self under heavier Argon2 parameters, without touching any
    /// data.
    ///
    /// This rewrites about a hundred bytes. `M` is untouched, every blob is
    /// untouched, every commit hash is untouched, and no replica resyncs —
    /// that is what the KEK indirection is for. If you have been putting this
    /// off because rehardening sounds like re-encrypting the garden: it is not,
    /// and it takes a second.
    ///
    /// With no cost flags it measures this machine and picks `m_cost` to hit
    /// `--target-ms`. It will not go below the recommended baseline or below
    /// what this vault already uses.
    Rewrap {
        #[arg(long)]
        garden: Option<PathBuf>,
        /// Calibrate m_cost so unlocking takes roughly this long, in ms.
        #[arg(long, default_value_t = 1000)]
        target_ms: u64,
        /// Set the memory cost in KiB explicitly, skipping calibration.
        #[arg(long)]
        m_cost: Option<u32>,
        /// Set the iteration count. Defaults to this vault's current value.
        #[arg(long)]
        t_cost: Option<u32>,
        /// Set the parallelism. Defaults to this vault's current value.
        #[arg(long)]
        p_cost: Option<u32>,
        /// Also change the master passphrase in the same operation.
        #[arg(long)]
        new_passphrase: bool,
        /// Permit parameters weaker than the baseline or than this vault's
        /// current ones. Weakening a vault should be an explicit act.
        #[arg(long)]
        allow_downgrade: bool,
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
    /// Add a wrapping of K — a new way into this vault.
    ///
    /// PATH is `phrase`: generate a fresh 12-word recovery phrase, wrap K
    /// under it, and declare it. The phrase is displayed **once** and is not
    /// stored anywhere.
    ///
    /// Refuses if that door already exists — replacing one is `drop` then
    /// `add`, said explicitly, so a live door is never silently swapped out
    /// from under whoever wrote the old phrase down.
    Add {
        /// The wrapping to add (`phrase`).
        path: String,
        #[arg(long)]
        garden: Option<PathBuf>,
    },
    /// Remove a wrapping of K, and update the declared policy with it.
    ///
    /// Authorized by this session, never by the door being removed: a
    /// `k.recovery` whose phrase is lost is removable without it. Refuses to
    /// remove the last remaining wrapping, to remove one without a *verified*
    /// escrow copy of what would remain, or to remove the door this session is
    /// authenticated through.
    Drop {
        /// The wrapping to remove (`phrase` or `passphrase`).
        path: String,
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
    /// Prove that an escrow bundle is intact AND that it opens — without
    /// installing it over the live vault.
    ///
    /// Two stages. The first re-hashes every member against the manifest and
    /// checks that the bundle carries every door its declared policy claims.
    /// The second prompts for the master passphrase and actually unwraps K
    /// from the bundle's own `k.self`, then every master generation it
    /// carries: a bundle whose bytes are fine but whose passphrase is
    /// misremembered is worthless, and only an unwrap catches that.
    ///
    /// This is what turns a copied file into a backup. It cannot modify the
    /// vault — verification runs entirely on the bundle in memory — and
    /// verifying an old bundle against a rotated vault is expected: it is a
    /// valid historical artifact and is never "repaired".
    Verify {
        /// The bundle to verify.
        path: PathBuf,
        /// The vault to record the result against. Defaults to the garden
        /// found from the current directory; recording is skipped when there
        /// is none, or when the bundle belongs to a different garden.
        #[arg(long)]
        garden: Option<PathBuf>,
        /// Check the bytes only: no passphrase prompt, and NO proof that the
        /// bundle opens. Useful for checking a remote copy for rot without
        /// typing the master passphrase — but it does not verify a backup,
        /// and nothing is recorded.
        #[arg(long)]
        integrity_only: bool,
        /// Verify without writing the verification record.
        #[arg(long)]
        no_record: bool,
    },
}

pub fn run(cmd: VaultCmd) -> Result<()> {
    match cmd {
        VaultCmd::Init { garden } => init(resolve_for_init(garden)?),
        VaultCmd::Status { garden, identity } => status(resolve(garden)?, identity),
        VaultCmd::Recovery { cmd } => match cmd {
            RecoveryCmd::Declare { policy, garden } => declare(resolve(garden)?, &policy),
            RecoveryCmd::Add { path, garden } => recovery_add(resolve(garden)?, &path),
            RecoveryCmd::Drop { path, garden } => recovery_drop(resolve(garden)?, &path),
        },
        VaultCmd::Escrow { cmd } => match cmd {
            EscrowCmd::Export { garden, out, force } => {
                escrow_export(resolve(garden)?, out, force)
            }
            EscrowCmd::Verify {
                path,
                garden,
                integrity_only,
                no_record,
            } => escrow_verify(path, garden, integrity_only, no_record),
        },
        VaultCmd::Rewrap {
            garden,
            target_ms,
            m_cost,
            t_cost,
            p_cost,
            new_passphrase,
            allow_downgrade,
        } => rewrap(
            resolve(garden)?,
            RewrapArgs {
                target_ms,
                m_cost,
                t_cost,
                p_cost,
                new_passphrase,
                allow_downgrade,
            },
        ),
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

    println!();
    print_kdf_status(vault.paths());

    println!();
    print_escrow_status(vault.paths());

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

/// Add a door. Today that means the recovery phrase: `k.self` always exists
/// (changing the secret behind it is `vault recover`), and peer wrappings
/// belong to the trust-matrix ledger.
fn recovery_add(garden: PathBuf, path: &str) -> Result<()> {
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        return Err(anyhow!("no vault at {}", vault.paths().root.display()));
    }
    let target = parse_path(path)?;
    // Refuse before the prompt: a passphrase typed only to be told the door
    // already exists is a passphrase typed at a prompt nobody read.
    wrappings::check_can_add(vault.paths(), target)?;

    // Announce the cost the new door will carry, before anything is typed. A
    // door inherits the vault's current strength, and on a rehardened vault
    // that is a real unlock latency on whatever machine this phrase is
    // eventually typed into — a fact to state at minting time, not one to
    // discover on the worst day.
    if let Ok(current) = wrappings::self_wrapping_params(vault.paths()) {
        println!(
            "The new door will derive at {} — the cost {} uses today.",
            current.params,
            storage::KEK_SELF_FILE
        );
        println!();
    }

    let pass = prompt_passphrase("Passphrase: ")?;
    let session = vault.unlock(pass.as_bytes())?;
    let phrase = wrappings::add_wrapping(&session, target)?;

    print_recovery(&phrase);
    println!();
    println!("This phrase is a second way into this vault. It was shown once and is not");
    println!("stored anywhere: nothing in soft-fig can print it again.");
    println!();
    println!("Vault: {}", vault.paths().root.display());
    print_recovery_status(&RecoveryStatus::read(vault.paths()));
    Ok(())
}

/// Remove a door.
///
/// Authorized by the live session, never by the door being removed — a
/// `k.recovery` whose phrase is lost must still be removable, or the tool
/// strands the exact state this milestone exists to fix. The guards are
/// evaluated first and shown to the user before anything is typed, so a
/// refusal costs no passphrase; `drop_wrapping` re-evaluates them all before
/// it touches the filesystem.
fn recovery_drop(garden: PathBuf, path: &str) -> Result<()> {
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        return Err(anyhow!("no vault at {}", vault.paths().root.display()));
    }
    let target = parse_path(path)?;
    let plan = wrappings::plan_drop(vault.paths(), target, RecoveryPath::Passphrase)?;

    println!("Vault: {}", vault.paths().root.display());
    println!();
    println!("  removing              : '{}' ({})", plan.removing, plan.location);
    println!(
        "  remaining afterwards  : {}",
        plan.remaining
            .iter()
            .map(|p| format!("'{}' ({})", p.token(), p.location()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  licensed by           : escrow bundle {}",
        plan.certified_by.bundle_blake3
    );
    println!(
        "                          verified {}, and it escrows the {} that remains",
        age_phrase(now_unix() - plan.certified_by.verified_at),
        storage::KEK_SELF_FILE
    );
    println!();
    println!("  This removes a way into your garden. It cannot be undone from this side:");
    println!("  re-adding a door mints a NEW secret, it does not restore the old one.");
    println!();
    print!("  Type '{}' to remove that door, anything else to cancel: ", plan.removing);
    std::io::Write::flush(&mut std::io::stdout()).ok();

    // Specific consent, not a blanket yes: the user names the door. A prompt
    // that takes `y` is a prompt that gets answered without being read.
    if read_line()?.trim() != plan.removing.token() {
        println!("  cancelled — nothing was changed.");
        return Ok(());
    }

    let pass = prompt_passphrase("Passphrase: ")?;
    let session = vault.unlock(pass.as_bytes())?;
    let done = wrappings::drop_wrapping(&session, target, RecoveryPath::Passphrase)?;

    println!();
    println!("Removed '{}' ({}).", done.removing, done.location);
    println!();
    print_recovery_status(&RecoveryStatus::read(vault.paths()));
    Ok(())
}

fn parse_path(path: &str) -> Result<RecoveryPath> {
    RecoveryPath::parse(path).ok_or_else(|| {
        anyhow!(
            "'{path}' is not a recovery path — expected one of: {}",
            RecoveryPath::ALL
                .iter()
                .map(|p| p.token())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
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

/// `status` observes, `verify` proves — and proving means unwrapping, which
/// means a passphrase. Nothing on this path can write to the vault: the
/// verification functions hold no vault path at all, and the one call that
/// does write (the record) happens after the proof, only when the bundle is
/// established to belong to this garden.
fn escrow_verify(
    path: PathBuf,
    garden: Option<PathBuf>,
    integrity_only: bool,
    no_record: bool,
) -> Result<()> {
    let raw = std::fs::read(&path)
        .with_context(|| format!("could not read {}", path.display()))?;
    let digest = escrow::bundle_blake3(&raw);
    // A bundle is text by construction, so bytes that are not UTF-8 are a
    // damaged copy or the wrong file — worth saying plainly rather than
    // surfacing as an encoding error from three layers down.
    let text = String::from_utf8(raw).map_err(|_| {
        anyhow!(
            "{} is not valid UTF-8 — this is not an escrow bundle, or the copy is damaged",
            path.display()
        )
    })?;
    let bundle = escrow::parse(&text)
        .with_context(|| format!("{} is not a readable escrow bundle", path.display()))?;

    let report = escrow::check_integrity(&bundle);
    print_integrity(&path, &digest, &report);
    if !report.is_intact() {
        return Err(anyhow!(
            "INTEGRITY FAILED — {} problem(s) above. The passphrase was not asked for and \
             nothing was recorded: a bundle with a damaged member is not a backup, whether or \
             not the rest of it would open. Verify another copy.",
            report.findings.len()
        ));
    }

    if integrity_only {
        println!();
        println!("  INTACT — every member hashes as the manifest says, and every door the");
        println!("  declared policy names is carried.");
        println!();
        println!("  This is NOT a verified backup: --integrity-only skips the proof that the");
        println!("  bundle opens, which is the half that catches a misremembered passphrase or");
        println!("  inconsistent parameters. Nothing was recorded. Re-run without the flag.");
        return Ok(());
    }

    println!();
    let pass = prompt_passphrase("Master passphrase (to prove this bundle opens): ")?;
    let proof = match escrow::prove_openable(&bundle, pass.as_bytes()) {
        Ok(p) => p,
        Err(VaultError::AuthFailed) => {
            return Err(anyhow!(
                "OPENABILITY FAILED — the bundle is intact, but K did not unwrap under that \
                 passphrase.\nThe bytes are fine; the passphrase is wrong, or this bundle is an \
                 escrow of a vault with a different one.\nNothing was recorded and nothing was \
                 changed."
            ))
        }
        Err(e) => return Err(anyhow::Error::new(e).context("openability proof failed")),
    };
    print_proof(&proof);

    if no_record {
        println!();
        println!("  not recorded          : --no-record");
        return Ok(());
    }
    record_verification(&garden, &bundle, &report, &digest)
}

/// Write the proof down, but only against the vault it is actually a proof
/// for. A record naming another garden's bundle would be a lie that
/// `vault recovery drop` later gates on.
fn record_verification(
    garden: &Option<PathBuf>,
    bundle: &softfig_vault::EscrowBundle,
    report: &escrow::IntegrityReport,
    digest: &str,
) -> Result<()> {
    println!();
    let Some(garden) = garden.clone().or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|d| discover_garden(&d))
    }) else {
        println!("  not recorded          : no garden here — pass --garden to record this proof");
        return Ok(());
    };
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        println!(
            "  not recorded          : no vault at {}",
            vault.paths().root.display()
        );
        return Ok(());
    }
    let live_id = softfig_store::peek_repo_id(&StorePaths::for_garden(&garden));
    match (bundle.garden_id.as_str(), live_id.as_deref()) {
        ("", _) => {
            println!(
                "  not recorded          : the bundle is unlabelled, so it cannot be tied to \
                 this vault"
            );
            return Ok(());
        }
        (_, None) => {
            println!(
                "  not recorded          : this garden has no readable store database to check \
                 the bundle's id against"
            );
            return Ok(());
        }
        (b, Some(l)) if b != l => {
            println!("  not recorded          : this bundle escrows garden {b},");
            println!("                          but {} is garden {l}", garden.display());
            return Ok(());
        }
        _ => {}
    }

    let entry = escrow::VerificationRecord {
        bundle_blake3: digest.to_string(),
        self_blake3: report.self_blake3.clone(),
        garden_id: bundle.garden_id.clone(),
        policy: bundle.policy.clone(),
        member_count: bundle.members.len(),
        outcome: escrow::OUTCOME_OPENABLE.to_string(),
        verified_at: 0,
    };
    let written = escrow::record_verification(vault.paths(), entry, now_unix())?;
    println!(
        "  recorded              : {}",
        vault.paths().escrow_record().display()
    );

    // A stale-but-valid proof is the case `drop` will have to reason about, so
    // say it here rather than leaving it to be discovered later.
    match escrow::current_self_blake3(vault.paths()) {
        Ok(live) if live == written.self_blake3 => {
            println!("                          this bundle escrows the vault's current k.self");
        }
        Ok(_) => {
            println!(
                "    ! this bundle carries an OLDER k.self than the vault has now — it is a \
                 valid"
            );
            println!(
                "      historical copy, but it is not a proof that today's vault can be \
                 reopened."
            );
            println!("      Re-export and verify the new bundle.");
        }
        Err(e) => println!("    ! could not read the live k.self to compare: {e}"),
    }
    Ok(())
}

fn print_integrity(path: &Path, digest: &str, r: &escrow::IntegrityReport) {
    println!("Escrow bundle: {}", path.display());
    println!();
    println!("  blake3                : {digest}");
    if r.garden_id.is_empty() {
        println!("  garden id             : (unlabelled)");
    } else {
        println!("  garden id             : {}", r.garden_id);
    }
    println!(
        "  recovery policy       : {}  ({})",
        r.policy, r.policy_source
    );
    if !r.policy_note.is_empty() {
        println!("    ! {}", r.policy_note);
    }
    println!(
        "  members               : {} ({} bytes of key material)",
        r.members.len(),
        r.key_material_bytes
    );
    if !r.undeclared_doors.is_empty() {
        println!(
            "  undeclared doors      : {} (carried, but the declared policy does not name it)",
            r.undeclared_doors.join(", ")
        );
    }
    if r.findings.is_empty() {
        println!("  integrity             : intact");
    } else {
        println!("  integrity             : FAILED");
        for f in &r.findings {
            println!("    ! {f}");
        }
    }
}

fn print_proof(p: &escrow::OpenProof) {
    println!();
    println!("  VERIFIED — this bundle opens.");
    println!();
    println!(
        "  K unwrapped from the bundle's own k.self under its own Argon2 parameters, and"
    );
    let generations: Vec<String> = p
        .generations_proved
        .iter()
        .map(|id| id.to_string())
        .collect();
    println!(
        "  master generation{} {} opened under it (active: {}).",
        if generations.len() == 1 { "" } else { "s" },
        generations.join(", "),
        p.active_master_key_id
    );
    if !p.unproved_doors.is_empty() {
        println!();
        println!("  Not proved            : {}", p.unproved_doors.join(", "));
        println!("                          Those doors open under the recovery phrase or a peer");
        println!("                          key, not the master passphrase, so this verb cannot");
        println!("                          test them. Their bytes are intact.");
    }
}

/// Escrow freshness, for `vault status`. Reads a plaintext record and hashes
/// `k.self`; opens nothing, so it stays usable on a locked vault.
fn print_escrow_status(paths: &softfig_vault::VaultPaths) {
    let log = match escrow::read_verifications(paths) {
        Ok(log) => log,
        Err(e) => {
            println!("  escrow verified      : (unreadable: {e})");
            return;
        }
    };
    let Some(latest) = log.latest() else {
        println!("  escrow verified      : never — no copy of this vault's key material has");
        println!("                         been proved to open");
        println!("      softfig vault escrow export -o <file>");
        println!("      softfig vault escrow verify <file>");
        return;
    };
    println!(
        "  escrow verified      : {} ({} on record)",
        age_phrase(now_unix() - latest.verified_at),
        if log.entries.len() == 1 {
            "1 copy".to_string()
        } else {
            format!("{} copies", log.entries.len())
        }
    );
    println!("                         bundle {}", latest.bundle_blake3);
    match escrow::current_self_blake3(paths) {
        Ok(live) if live == latest.self_blake3 => {
            println!("                         escrows the current k.self")
        }
        Ok(_) => println!(
            "    ! the newest verified copy predates the current {} — re-export and re-verify",
            storage::KEK_SELF_FILE
        ),
        Err(e) => println!("    ! could not read {} to compare: {e}", storage::KEK_SELF_FILE),
    }
}

/// The Argon2 costs each door actually opens under, and where those costs come
/// from. Parameters nobody can see are parameters nobody will raise, which is
/// most of why this milestone found a vault still on its 2024 defaults.
///
/// Reads headers and a TOML file; opens nothing, so it stays usable on a locked
/// vault like the rest of `status`.
fn print_kdf_status(paths: &softfig_vault::VaultPaths) {
    let fallback = match softfig_vault::storage::load_params(paths) {
        Ok(p) => p.argon2,
        Err(e) => {
            println!("  key derivation       : (unreadable: {e})");
            return;
        }
    };
    let Ok(self_bytes) = std::fs::read(paths.kek_self()) else {
        println!("  key derivation       : (no {} to read)", storage::KEK_SELF_FILE);
        return;
    };
    let current = softfig_vault::kek::wrapping_params(&self_bytes, &fallback);
    println!(
        "  key derivation       : {}  ({})",
        current.params,
        if current.embedded {
            format!("embedded in {}", storage::KEK_SELF_FILE)
        } else {
            format!("from {}", softfig_vault::storage::PARAMS_FILE)
        }
    );

    // The plain-language read the slice asked for. Argon2 cost is not a number
    // most people have a feel for, and "is this enough" is the only question
    // being asked.
    if current.params.at_least_as_strong_as(OWASP_BASELINE) {
        println!(
            "                         at or above the recommended baseline ({OWASP_BASELINE})"
        );
    } else {
        println!("    ! below the recommended baseline ({OWASP_BASELINE}) — in a passphrase-only");
        println!("      posture this cost is the whole brute-force defence of the garden:");
        println!("          softfig vault rewrap");
    }

    // A door still in the pre-embedding format reads its costs from
    // params.toml, and a rewrap deliberately leaves both alone. Saying so is
    // the difference between a legible vault and a surprising one.
    if let Ok(recovery_bytes) = std::fs::read(paths.kek_recovery()) {
        let phrase = softfig_vault::kek::wrapping_params(&recovery_bytes, &fallback);
        if !phrase.embedded {
            println!(
                "                         {} still derives from {} ({})",
                storage::KEK_RECOVERY_FILE,
                softfig_vault::storage::PARAMS_FILE,
                phrase.params
            );
        } else if phrase.params != current.params {
            println!(
                "                         {} derives at {}",
                storage::KEK_RECOVERY_FILE,
                phrase.params
            );
        }
    }
}

/// Flags for [`rewrap`], grouped so the function keeps a readable signature.
struct RewrapArgs {
    target_ms: u64,
    m_cost: Option<u32>,
    t_cost: Option<u32>,
    p_cost: Option<u32>,
    new_passphrase: bool,
    allow_downgrade: bool,
}

/// Reharden the passphrase wrapping.
///
/// Structure mirrors slice 004's `drop`: the whole plan is computed and shown
/// **before** a passphrase is typed, so a refusal never costs a prompt, and the
/// library re-evaluates every guard before it writes.
fn rewrap(garden: PathBuf, args: RewrapArgs) -> Result<()> {
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        return Err(anyhow!("no vault at {}", vault.paths().root.display()));
    }
    let paths = vault.paths();

    let current = wrappings::self_wrapping_params(paths)?;

    // Unspecified costs inherit from the vault rather than from a constant: a
    // vault someone deliberately set to t=6 must not be quietly returned to the
    // default because they only wanted to raise the memory.
    let t_cost = args.t_cost.unwrap_or(current.params.t_cost);
    let p_cost = args.p_cost.unwrap_or(current.params.p_cost);

    println!("Vault: {}", paths.root.display());
    println!();
    println!(
        "  current   : {}  ({})",
        current.params,
        if current.embedded {
            format!("embedded in {}", storage::KEK_SELF_FILE)
        } else {
            format!("from {}", softfig_vault::storage::PARAMS_FILE)
        }
    );

    let target = match args.m_cost {
        Some(m_cost) => Argon2Params {
            m_cost,
            t_cost,
            p_cost,
        },
        None => {
            println!(
                "  measuring this machine for a ~{} ms unlock...",
                args.target_ms
            );
            let c = rewrap::calibrate(args.target_ms, t_cost, p_cost)?;
            println!(
                "  calibrated: {} in {} ms over {} probe(s){}",
                c.params,
                c.measured_ms,
                c.probes,
                if c.clamped {
                    " — clamped, not the target"
                } else {
                    ""
                }
            );
            c.params
        }
    };

    let mut plan = rewrap::plan(paths, target, args.allow_downgrade)?;
    plan.changes_passphrase = args.new_passphrase;

    println!("  target    : {}", plan.target);
    if plan.is_noop() {
        println!();
        println!("  Already at these parameters, and the passphrase is unchanged — nothing to");
        println!("  do. Pass --m-cost/--target-ms to raise them, or --new-passphrase to change");
        println!("  the secret.");
        return Ok(());
    }
    if plan.is_downgrade {
        println!("    ! this WEAKENS the vault, permitted by --allow-downgrade");
    }
    if args.new_passphrase {
        println!("  the master passphrase will also be replaced");
    }
    println!();
    println!("  This rewrites {} only — about a hundred bytes.", storage::KEK_SELF_FILE);
    println!("  M, every blob, and every commit hash are untouched, and no replica resyncs.");

    // Two consequences that must be announced rather than discovered. The
    // relock one surfaces at the next `softfig daemon cycle`; the escrow one
    // surfaces the next time a door is dropped. Both are bad moments.
    println!();
    println!("  Afterwards:");
    println!(
        "    - any outstanding growlight relock token becomes invalid (the vault fingerprint"
    );
    println!("      is a hash of {}), so the next daemon restart needs the passphrase", storage::KEK_SELF_FILE);
    if plan.invalidates_escrow_proof {
        println!("    - your verified escrow copy becomes HISTORICAL: it proves the old");
        println!("      wrapping. Re-run 'vault escrow export' + 'vault escrow verify', or");
        println!("      'vault recovery drop' will refuse until you do");
    }
    for door in &plan.legacy_doors {
        println!(
            "    - '{}' ({}) keeps its old cost and keeps reading {} — a rewrap cannot",
            door.token(),
            door.location(),
            softfig_vault::storage::PARAMS_FILE
        );
        println!("      re-derive it, because opening it needs its own secret");
    }

    println!();
    let pass = prompt_passphrase("Current passphrase: ")?;
    let new_secret = if args.new_passphrase {
        let p1 = prompt_passphrase("New passphrase: ")?;
        let p2 = prompt_passphrase("Confirm new passphrase: ")?;
        if p1 != p2 {
            return Err(anyhow!("passphrases do not match — nothing was changed"));
        }
        Some(p1)
    } else {
        None
    };

    rewrap::apply(
        paths,
        &plan,
        pass.as_bytes(),
        new_secret.as_ref().map(|s| s.as_bytes()),
    )?;

    println!();
    println!("Rewrapped. {} now derives at {}.", storage::KEK_SELF_FILE, plan.target);
    println!();
    print_kdf_status(paths);
    Ok(())
}

/// Whole days, because that is the resolution the fact deserves: "is my escrow
/// copy months old" is the question, and no date library is worth pulling in
/// to answer it more precisely.
fn age_phrase(secs: i64) -> String {
    if secs < 0 {
        return "in the future (check the clock)".to_string();
    }
    match secs / 86_400 {
        0 => "today".to_string(),
        1 => "1 day ago".to_string(),
        d => format!("{d} days ago"),
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

    // `recover` rewrites the same file `rewrap` does, so it owes the same
    // announcement: the cost the replacement will carry, and the two things
    // replacing `k.self` breaks. Printed before the phrase and the new
    // passphrase are typed, because that is when the operator can still stop.
    match wrappings::self_wrapping_params(vault.paths()) {
        Ok(current) => println!(
            "The replacement {} will derive at {} — the cost it uses today.",
            storage::KEK_SELF_FILE, current.params
        ),
        Err(_) => println!(
            "{} cannot be read, so the replacement will derive at the {} cost.",
            storage::KEK_SELF_FILE,
            softfig_vault::storage::PARAMS_FILE
        ),
    }
    println!(
        "Replacing it invalidates every outstanding relock blob, and turns a current"
    );
    println!(
        "escrow proof into a historical one — `recovery drop` refuses to act on a"
    );
    println!("stale proof, so re-export and re-verify afterwards.");
    println!();
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
    println!();
    print_kdf_status(vault.paths());
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
