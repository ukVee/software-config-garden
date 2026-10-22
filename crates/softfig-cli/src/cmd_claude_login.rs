//! `softfig claude-login {list, capture, use, login, status}` — a two-account
//! Anthropic login switcher for Claude Code.
//!
//! Shape (milestone `claude-login-switcher`, slice 001):
//!
//! * A profile store at `~/.claude/credentials.d/<name>.json`, each file mode
//!   `0600`, dir mode `0700`.
//! * `~/.claude/.credentials.json` becomes a *relative* symlink into the store
//!   (e.g. `credentials.d/slot1.json`). The relative form matters for the
//!   per-member overlay HOMEs that slice 002 will build.
//! * Switching accounts is retargeting the symlink; interactive `claude` keeps
//!   working, and `claude auth login` writes through the symlink.
//!
//! Fleet / overlay / growlightd integration is slices 002–004 — none of that
//! lives here.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use serde::Deserialize;
use softfig_growlightd::FleetConfig;

use crate::overlay_map::{overlay_map, PathClass};

#[derive(Subcommand, Debug)]
pub enum ClaudeLoginCmd {
    /// List the profiles in `~/.claude/credentials.d/`, marking the active one.
    List,
    /// Snapshot the current `~/.claude/.credentials.json` into
    /// `credentials.d/<name>.json` (0600) and swap the top-level file for a
    /// symlink into it.
    Capture(CaptureArgs),
    /// Retarget the top-level symlink to a named slot.
    Use(UseArgs),
    /// `use <name>`, then run `claude auth login`; if that write replaced the
    /// symlink with a regular file, fold the new creds into the slot and
    /// restore the symlink.
    Login(LoginArgs),
    /// Print the current symlink target and per-slot account summaries.
    Status,
    /// Build per-member overlay HOMEs under
    /// `$XDG_CONFIG_HOME/softfig/growlight/agents/<id>/home/`, one for each
    /// `[[fleet]]` member in `growlight.toml`. Idempotent; preserves existing
    /// per-member content.
    RefreshMembers(RefreshMembersArgs),
}

#[derive(Args, Debug)]
pub struct CaptureArgs {
    /// Slot name — the filename stem under `credentials.d/`.
    pub name: String,
    /// Overwrite a slot that already exists with different contents.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct UseArgs {
    pub name: String,
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    pub name: String,
}

#[derive(Args, Debug)]
pub struct RefreshMembersArgs {
    /// Path to the fleet config (`<garden>/config/growlight.toml`). Required
    /// in this slice; slice 003 wires garden-root auto-discovery.
    #[arg(long)]
    pub config: PathBuf,
    /// Agents runtime dir. Defaults to
    /// `$XDG_CONFIG_HOME/softfig/growlight/agents/`
    /// (or `~/.config/softfig/growlight/agents/`).
    #[arg(long)]
    pub agents_dir: Option<PathBuf>,
    /// Print the plan without touching the filesystem.
    #[arg(long)]
    pub dry_run: bool,
    /// Remove overlay HOMEs for members no longer in the config. Without this
    /// flag, stale overlays warn but are preserved — a member's per-member
    /// mutable state is not lost by a config edit.
    #[arg(long)]
    pub prune: bool,
}

pub fn run(cmd: ClaudeLoginCmd) -> Result<()> {
    let home = resolve_claude_home()?;
    let paths = Paths::new(&home);
    match cmd {
        ClaudeLoginCmd::List => list(&paths),
        ClaudeLoginCmd::Capture(a) => capture(&paths, &a.name, a.force),
        ClaudeLoginCmd::Use(a) => use_slot(&paths, &a.name),
        ClaudeLoginCmd::Login(a) => login(&paths, &a.name),
        ClaudeLoginCmd::Status => status(&paths),
        ClaudeLoginCmd::RefreshMembers(a) => {
            let agents_dir = match a.agents_dir {
                Some(p) => p,
                None => default_agents_dir()?,
            };
            let plan = plan_refresh(&paths, &a.config, &agents_dir, a.prune)?;
            let mut out = std::io::stdout().lock();
            apply_plan(&mut out, &plan, a.dry_run)
        }
    }
}

/// `$XDG_CONFIG_HOME/softfig/growlight/agents/`, falling back to
/// `$HOME/.config/softfig/growlight/agents/`. Same resolution rule the rest
/// of the growlight runtime uses, so a member's overlay HOME lands as a
/// sibling of its already-generated loop/mcp configs.
fn default_agents_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or_else(|| anyhow!("HOME is not set"))?;
            home.join(".config")
        }
    };
    Ok(base.join("softfig").join("growlight").join("agents"))
}

fn resolve_claude_home() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(home.join(".claude"))
}

struct Paths {
    claude_home: PathBuf,
    store: PathBuf,
    top_level: PathBuf,
}

impl Paths {
    fn new(claude_home: &Path) -> Self {
        Self {
            claude_home: claude_home.to_path_buf(),
            store: claude_home.join("credentials.d"),
            top_level: claude_home.join(".credentials.json"),
        }
    }

    fn slot(&self, name: &str) -> PathBuf {
        self.store.join(format!("{name}.json"))
    }

    /// The relative target we store in the top-level symlink: literally
    /// `credentials.d/<name>.json`, so an overlay HOME's symlink resolves
    /// within its own `.claude/` subtree.
    fn rel_slot_target(&self, name: &str) -> PathBuf {
        PathBuf::from("credentials.d").join(format!("{name}.json"))
    }
}

/// What the top-level `.credentials.json` currently is.
#[derive(Debug)]
enum TopLevel {
    /// No file at all.
    Missing,
    /// A regular file — either upstream `claude auth login` wrote here before
    /// the switcher adopted it, or a `rename(2)` later replaced our symlink.
    Plain,
    /// A symlink into our store: `credentials.d/<name>.json`.
    SymlinkIn { slot_name: String },
    /// A symlink pointing elsewhere, or absolute, or dangling at an outside
    /// location. Treated as unmanaged.
    SymlinkOut { target: PathBuf },
}

fn inspect_top_level(paths: &Paths) -> Result<TopLevel> {
    let md = match fs::symlink_metadata(&paths.top_level) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(TopLevel::Missing),
        Err(e) => return Err(e).context("stat .credentials.json"),
    };
    if !md.file_type().is_symlink() {
        return Ok(TopLevel::Plain);
    }
    let target = fs::read_link(&paths.top_level).context("read .credentials.json symlink")?;
    // Match the exact relative shape we write: `credentials.d/<stem>.json`.
    // Reject names a slot can't have, so a crafted `credentials.d/../x.json`
    // or similar classes as SymlinkOut rather than being treated as a slot.
    let in_store = target.parent() == Some(Path::new("credentials.d"))
        && target.extension().and_then(|s| s.to_str()) == Some("json");
    if in_store
        && let Some(stem) = target.file_stem().and_then(|s| s.to_str())
        && validate_slot_name(stem).is_ok()
    {
        return Ok(TopLevel::SymlinkIn {
            slot_name: stem.to_string(),
        });
    }
    Ok(TopLevel::SymlinkOut { target })
}

/// Shape we parse out of a slot file. API-key auth has no `claudeAiOauth`
/// block, which is how we refuse it.
#[derive(Deserialize)]
struct OauthWire {
    #[serde(rename = "claudeAiOauth")]
    claude_ai_oauth: Option<OauthFields>,
}

#[derive(Deserialize)]
struct OauthFields {
    #[serde(rename = "subscriptionType")]
    subscription_type: Option<String>,
    #[serde(rename = "rateLimitTier")]
    rate_limit_tier: Option<String>,
    #[serde(rename = "accountEmail")]
    account_email: Option<String>,
}

#[derive(Debug, Default)]
struct AccountSummary {
    subscription_type: Option<String>,
    rate_limit_tier: Option<String>,
    account_email: Option<String>,
    /// Set when the bytes aren't a Claude OAuth bundle.
    unparseable: Option<String>,
}

fn parse_account(bytes: &[u8]) -> AccountSummary {
    match serde_json::from_slice::<OauthWire>(bytes) {
        Ok(w) => match w.claude_ai_oauth {
            Some(o) => AccountSummary {
                subscription_type: o.subscription_type,
                rate_limit_tier: o.rate_limit_tier,
                account_email: o.account_email,
                unparseable: None,
            },
            None => AccountSummary {
                unparseable: Some("no `claudeAiOauth` block (API-key auth?)".into()),
                ..Default::default()
            },
        },
        Err(e) => AccountSummary {
            unparseable: Some(format!("invalid json: {e}")),
            ..Default::default()
        },
    }
}

fn fmt_account(a: &AccountSummary) -> String {
    if let Some(reason) = &a.unparseable {
        return format!("<{reason}>");
    }
    let sub = a.subscription_type.as_deref().unwrap_or("?");
    let tier = a.rate_limit_tier.as_deref().unwrap_or("?");
    match &a.account_email {
        Some(e) => format!("{sub} / tier {tier} / {e}"),
        None => format!("{sub} / tier {tier}"),
    }
}

#[derive(Debug)]
struct SlotInfo {
    name: String,
    mode: u32,
    account: AccountSummary,
}

fn read_slots(paths: &Paths) -> Result<Vec<SlotInfo>> {
    let dir = match fs::read_dir(&paths.store) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("read credentials.d/"),
    };
    let mut out = Vec::new();
    for ent in dir {
        let ent = ent?;
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let md = fs::symlink_metadata(&path).context("stat slot file")?;
        if !md.file_type().is_file() {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("read slot {name}"))?;
        out.push(SlotInfo {
            name,
            mode: md.permissions().mode(),
            account: parse_account(&bytes),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Slot-name charset: `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
/// Rejects anything with a path separator or leading-dot (so `..` and
/// `/etc/passwd` both fail), which is also what the symlink-reader uses to
/// decide whether a top-level symlink names a well-formed slot.
fn validate_slot_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("slot name length must be 1..=64 bytes (got {})", name.len());
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        bail!("slot name must start with [A-Za-z0-9]");
    }
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
            bail!("slot name may only contain [A-Za-z0-9._-]");
        }
    }
    Ok(())
}

fn ensure_store_dir(paths: &Paths) -> Result<()> {
    match fs::symlink_metadata(&paths.store) {
        Ok(md) if md.file_type().is_dir() => {
            // Make sure the mode is tight; a 0755 from a careless mkdir -p
            // would leak later writes to other users on multi-user hosts.
            let mode = md.permissions().mode() & 0o777;
            if mode != 0o700 {
                fs::set_permissions(&paths.store, fs::Permissions::from_mode(0o700))
                    .context("chmod 0700 credentials.d/")?;
            }
            Ok(())
        }
        Ok(_) => bail!(
            "`{}` exists but is not a directory",
            paths.store.display()
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !paths.claude_home.exists() {
                fs::create_dir_all(&paths.claude_home)
                    .with_context(|| format!("create {}", paths.claude_home.display()))?;
            }
            fs::create_dir(&paths.store).context("create credentials.d/")?;
            fs::set_permissions(&paths.store, fs::Permissions::from_mode(0o700))
                .context("chmod 0700 credentials.d/")?;
            Ok(())
        }
        Err(e) => Err(e).context("stat credentials.d/"),
    }
}

/// Monotone counter so repeated writes in the same microsecond don't collide
/// on the tempfile name.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_sibling(path: &Path) -> Result<PathBuf> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
    let fname = path
        .file_name()
        .ok_or_else(|| anyhow!("path has no file name: {}", path.display()))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(fname);
    name.push(format!(".tmp.{pid}.{nanos}.{seq}", pid = std::process::id()));
    Ok(dir.join(name))
}

/// Atomic write with explicit mode. Same-filesystem tempfile + `rename(2)`.
fn atomic_write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = tmp_sibling(path)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("create tempfile {}", tmp.display()))?;
    let r = f.write_all(bytes).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = r {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!(e).context("write tempfile"));
    }
    // Defensive: process umask could have stripped bits off `.mode()` on
    // non-Linux unixes; be explicit about the final mode.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
        .context("chmod tempfile before rename")?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Atomic symlink create/retarget. `target` is written literally — a relative
/// path means "relative to the link's directory".
fn atomic_symlink(target: &Path, link_path: &Path) -> Result<()> {
    let tmp = tmp_sibling(link_path)?;
    symlink(target, &tmp)
        .with_context(|| format!("symlink {} -> {}", tmp.display(), target.display()))?;
    fs::rename(&tmp, link_path).with_context(|| {
        format!(
            "rename symlink {} -> {}",
            tmp.display(),
            link_path.display()
        )
    })?;
    Ok(())
}

// ---- subcommands -----------------------------------------------------------

fn list(paths: &Paths) -> Result<()> {
    let top = inspect_top_level(paths)?;
    let active: Option<&str> = match &top {
        TopLevel::SymlinkIn { slot_name } => Some(slot_name.as_str()),
        _ => None,
    };

    match &top {
        TopLevel::Missing => println!(
            "top-level: {} (missing — run `claude auth login`)",
            paths.top_level.display()
        ),
        TopLevel::Plain => println!(
            "top-level: {} (plain file — run `softfig claude-login capture <name>` to adopt)",
            paths.top_level.display()
        ),
        TopLevel::SymlinkIn { slot_name } => println!(
            "top-level: {} -> credentials.d/{slot_name}.json",
            paths.top_level.display()
        ),
        TopLevel::SymlinkOut { target } => println!(
            "top-level: {} -> {} (outside credentials.d/)",
            paths.top_level.display(),
            target.display()
        ),
    }

    let slots = read_slots(paths)?;
    if slots.is_empty() {
        println!("profiles: (none)");
        return Ok(());
    }
    println!("profiles:");
    for s in &slots {
        let marker = if Some(s.name.as_str()) == active { "*" } else { " " };
        let mode_tag = if s.mode & 0o777 == 0o600 {
            String::new()
        } else {
            format!(" [mode {:o}]", s.mode & 0o777)
        };
        println!("  {marker} {}  {}{}", s.name, fmt_account(&s.account), mode_tag);
    }
    Ok(())
}

fn capture(paths: &Paths, name: &str, force: bool) -> Result<()> {
    validate_slot_name(name)?;
    let top = inspect_top_level(paths)?;

    if matches!(top, TopLevel::Missing) {
        bail!(
            "no `{}` to capture — run `claude auth login` first",
            paths.top_level.display()
        );
    }

    // `fs::read` follows a symlink, so this gets the live creds whether the
    // top-level is a plain file or already a symlink into the store.
    let bytes = fs::read(&paths.top_level).with_context(|| {
        format!(
            "read `{}` (dangling symlink?)",
            paths.top_level.display()
        )
    })?;

    let acc = parse_account(&bytes);
    if let Some(reason) = &acc.unparseable {
        bail!(
            "current `.credentials.json` is not a Claude OAuth bundle: {reason} \
             (API-key auth is out of scope for this switcher)"
        );
    }

    ensure_store_dir(paths)?;
    let slot_path = paths.slot(name);
    let wrote_slot = match fs::read(&slot_path) {
        Ok(existing) if existing == bytes => {
            println!("slot `{name}` already captured (bytes identical)");
            false
        }
        Ok(_) if !force => bail!(
            "slot `{name}` already exists with different contents at {}; \
             pass --force to overwrite",
            slot_path.display()
        ),
        Ok(_) => {
            atomic_write_mode(&slot_path, &bytes, 0o600)?;
            println!("overwrote slot `{name}` → {} (0600)", slot_path.display());
            true
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            atomic_write_mode(&slot_path, &bytes, 0o600)?;
            println!("wrote slot `{name}` → {} (0600)", slot_path.display());
            true
        }
        Err(e) => return Err(e).context("read existing slot"),
    };

    // Always re-point the top-level, even if the slot bytes were identical —
    // capture's job is to leave the switcher in a managed state.
    let rel = paths.rel_slot_target(name);
    atomic_symlink(&rel, &paths.top_level)?;
    if !wrote_slot
        && matches!(&top, TopLevel::SymlinkIn { slot_name } if slot_name == name)
    {
        // Nothing moved; keep the output quiet.
    } else {
        println!(
            "top-level: {} -> {} (symlink)",
            paths.top_level.display(),
            rel.display()
        );
    }
    Ok(())
}

fn use_slot(paths: &Paths, name: &str) -> Result<()> {
    validate_slot_name(name)?;
    let slot = paths.slot(name);
    let slot_md = fs::symlink_metadata(&slot);
    match &slot_md {
        Ok(md) if md.file_type().is_file() => {}
        Ok(_) => bail!(
            "slot `{name}` at {} is not a regular file; refusing to point at it",
            slot.display()
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => bail!(
            "slot `{name}` does not exist ({}); see `softfig claude-login list`",
            slot.display()
        ),
        Err(e) => return Err(anyhow!(e.to_string())).context("stat slot file"),
    }

    let top = inspect_top_level(paths)?;
    let rel = paths.rel_slot_target(name);
    match top {
        TopLevel::Missing => {
            atomic_symlink(&rel, &paths.top_level)?;
            println!("active profile: `{name}` (new symlink)");
        }
        TopLevel::Plain => bail!(
            "`{}` is a regular file, not managed by this switcher. \
             Run `softfig claude-login capture <name>` to adopt the current creds first, \
             or move the file aside manually.",
            paths.top_level.display()
        ),
        TopLevel::SymlinkIn { slot_name } if slot_name == name => {
            println!("already active: `{name}`");
        }
        TopLevel::SymlinkIn { .. } | TopLevel::SymlinkOut { .. } => {
            atomic_symlink(&rel, &paths.top_level)?;
            println!("active profile: `{name}`");
        }
    }
    Ok(())
}

fn login(paths: &Paths, name: &str) -> Result<()> {
    use_slot(paths, name)?;

    // Spawn (not exec) — we need to inspect the top-level after `claude`
    // exits in case its atomic write replaced the symlink.
    let status = Command::new("claude")
        .args(["auth", "login"])
        .status()
        .context("spawn `claude auth login`")?;
    if !status.success() {
        bail!("`claude auth login` exited with status {status}");
    }

    match inspect_top_level(paths)? {
        TopLevel::SymlinkIn { slot_name } if slot_name == name => {
            println!("login OK; symlink intact (`{name}`)");
        }
        TopLevel::Plain => {
            // `claude auth login` wrote via `rename(2)` and replaced our
            // symlink with a regular file. Fold the new creds into the slot
            // and restore the link.
            let bytes = fs::read(&paths.top_level)
                .context("read .credentials.json after login")?;
            let acc = parse_account(&bytes);
            if acc.unparseable.is_some() {
                bail!(
                    "after `claude auth login`, `.credentials.json` is not a Claude OAuth bundle; \
                     refusing to repair the symlink. Inspect `{}` manually.",
                    paths.top_level.display()
                );
            }
            atomic_write_mode(&paths.slot(name), &bytes, 0o600)?;
            fs::remove_file(&paths.top_level)
                .context("remove plain .credentials.json before relink")?;
            atomic_symlink(&paths.rel_slot_target(name), &paths.top_level)?;
            println!("login OK; re-linked `.credentials.json` into slot `{name}`");
        }
        TopLevel::Missing => bail!(
            "after `claude auth login`, `.credentials.json` is missing; inspect `{}` manually",
            paths.claude_home.display()
        ),
        TopLevel::SymlinkIn { slot_name } => bail!(
            "after `claude auth login`, top-level points at slot `{slot_name}` (expected `{name}`); \
             inspect manually"
        ),
        TopLevel::SymlinkOut { target } => bail!(
            "after `claude auth login`, top-level points outside the store ({}); inspect manually",
            target.display()
        ),
    }
    Ok(())
}

fn status(paths: &Paths) -> Result<()> {
    list(paths)?;
    println!();
    println!("(per-member pins: not yet; see slice 003)");
    Ok(())
}

// ---- refresh-members -------------------------------------------------------

/// One leaf operation inside an overlay HOME. `apply_plan` is total over this
/// enum, and `--dry-run` prints it one op per line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    /// Ensure the overlay HOME chain `<agents_dir>/<member>/home/.claude/`
    /// exists.
    EnsureOverlayDir { member: String, overlay_claude: PathBuf },
    /// Create or retarget an absolute symlink at
    /// `overlay/.claude/<name> -> <target>`.
    Symlink { member: String, link: PathBuf, target: PathBuf, kind: SymlinkKind },
    /// Ensure a per-member directory exists (preserving its content).
    EnsureDir { member: String, path: PathBuf },
    /// Ensure a per-member file exists, empty (preserving its content).
    EnsureFile { member: String, path: PathBuf },
    /// Known-but-ignored name — no filesystem change; appears in the plan
    /// for traceability only.
    SkipIgnored { member: String, name: String },
    /// Prune an overlay HOME that corresponds to no live member.
    PruneOverlay { member: String, overlay_root: PathBuf },
    /// A stale overlay was found but `--prune` was not passed. The plan
    /// records it; `apply_plan` prints a warning (never a mutation).
    WarnStale { member: String, overlay_root: PathBuf },
}

/// Why a symlink exists — tagged on each [`Op::Symlink`] so `--dry-run`
/// output reads at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymlinkKind {
    Shared,
    PerSession,
}

#[derive(Debug)]
struct Plan {
    /// Where real `~/.claude/` content is shared from (absolute).
    source_claude: PathBuf,
    /// The agents runtime dir (absolute, as computed/overridden).
    agents_dir: PathBuf,
    /// Live members, in config order.
    live_members: Vec<String>,
    /// Overlay HOMEs found under `agents_dir` that do not belong to a live
    /// member. Empty under normal operation.
    stale_overlays: Vec<String>,
    /// Whether `--prune` was requested — governs how `stale_overlays`
    /// translate into ops.
    prune: bool,
    /// The ordered op stream.
    ops: Vec<Op>,
}

/// Walk growlight.toml for the live member list and build the full op plan,
/// without touching the filesystem. The function READS the agents dir
/// (`fs::read_dir`) to discover stale overlays, and resolves the top-level
/// `.credentials.json` target for the PerSession symlink — both read-only.
fn plan_refresh(
    claude_paths: &Paths,
    config_path: &Path,
    agents_dir: &Path,
    prune: bool,
) -> Result<Plan> {
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let fleet = FleetConfig::from_growlight_toml(&raw)
        .map_err(|e| anyhow!("parse {}: {e}", config_path.display()))?;
    let live_members: Vec<String> = fleet.members.iter().map(|m| m.agent.clone()).collect();

    let source_claude = claude_paths.claude_home.clone();

    // Resolve the per-session target once: the overlay's `.credentials.json`
    // points at an absolute path under `~/.claude/`. If the top-level is a
    // managed symlink into `credentials.d/`, resolve against the real home;
    // if it is a plain file (not yet captured), point at it directly; if it
    // is missing, we still write a (dangling) symlink to the expected path
    // so an overlay-rooted `claude auth login` can write through it.
    let session_target = resolve_session_target(claude_paths)?;

    let mut ops: Vec<Op> = Vec::new();

    for member in &live_members {
        let overlay_claude = agents_dir.join(member).join("home").join(".claude");
        ops.push(Op::EnsureOverlayDir {
            member: member.clone(),
            overlay_claude: overlay_claude.clone(),
        });

        for entry in overlay_map() {
            let dst = overlay_claude.join(entry.name);
            match entry.class {
                PathClass::Shared => {
                    let target = source_claude.join(entry.name);
                    ops.push(Op::Symlink {
                        member: member.clone(),
                        link: dst,
                        target,
                        kind: SymlinkKind::Shared,
                    });
                }
                PathClass::PerMemberDir => ops.push(Op::EnsureDir {
                    member: member.clone(),
                    path: dst,
                }),
                PathClass::PerMemberFile => ops.push(Op::EnsureFile {
                    member: member.clone(),
                    path: dst,
                }),
                PathClass::PerSession => ops.push(Op::Symlink {
                    member: member.clone(),
                    link: dst,
                    target: session_target.clone(),
                    kind: SymlinkKind::PerSession,
                }),
                PathClass::Ignored => ops.push(Op::SkipIgnored {
                    member: member.clone(),
                    name: entry.name.to_string(),
                }),
            }
        }
    }

    // Scan for stale overlays — a subdir of agents_dir whose name is not a
    // live member. Fail-closed: an unreadable agents_dir yields an empty
    // stale list rather than aborting the plan (fresh install, nothing to
    // prune).
    let stale_overlays = scan_stale_overlays(agents_dir, &live_members).unwrap_or_default();
    for member in &stale_overlays {
        let overlay_root = agents_dir.join(member);
        if prune {
            ops.push(Op::PruneOverlay {
                member: member.clone(),
                overlay_root,
            });
        } else {
            ops.push(Op::WarnStale {
                member: member.clone(),
                overlay_root,
            });
        }
    }

    Ok(Plan {
        source_claude,
        agents_dir: agents_dir.to_path_buf(),
        live_members,
        stale_overlays,
        prune,
        ops,
    })
}

/// The target an overlay's `.credentials.json` symlink should point to, as an
/// absolute path. Follows slice 001's `inspect_top_level` classes:
/// a managed symlink resolves to `~/.claude/credentials.d/<slot>.json`
/// (absolute), a plain file resolves to `~/.claude/.credentials.json`, and a
/// missing/outside-of-store top-level falls back to that same path so an
/// overlay-rooted login writes to the real `~/.claude/.credentials.json`.
fn resolve_session_target(paths: &Paths) -> Result<PathBuf> {
    match inspect_top_level(paths)? {
        TopLevel::SymlinkIn { slot_name } => Ok(paths.store.join(format!("{slot_name}.json"))),
        TopLevel::Plain | TopLevel::Missing | TopLevel::SymlinkOut { .. } => {
            Ok(paths.top_level.clone())
        }
    }
}

/// Direct children of `agents_dir` whose names are not in `live_members`.
/// A non-dir entry (file, broken symlink) is ignored — the overlay root is
/// always a dir, so a stray file is user content we don't own.
fn scan_stale_overlays(agents_dir: &Path, live_members: &[String]) -> Result<Vec<String>> {
    let dir = match fs::read_dir(agents_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", agents_dir.display())),
    };
    let live: std::collections::HashSet<&str> =
        live_members.iter().map(|s| s.as_str()).collect();
    let mut out = Vec::new();
    for ent in dir {
        let ent = ent?;
        let md = match ent.file_type() {
            Ok(ft) if ft.is_dir() => ent.metadata().ok(),
            _ => continue,
        };
        if md.is_none() {
            continue;
        }
        let name = match ent.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue, // non-UTF-8 member id can't come from the parser
        };
        if !live.contains(name.as_str()) {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

/// Execute (or `--dry-run` print) the plan. Writes the plan header + one
/// line per op to `out`.
///
/// In **apply** mode we execute each op FIRST, then write its line, and
/// swallow a stdout `BrokenPipe` so a user piping through `head` / `less`
/// (and quitting mid-stream) does not abandon work that is already in
/// progress. The next refresh is idempotent either way. In **dry-run** mode
/// a write failure is propagated — there is no fallback behavior to continue.
fn apply_plan<W: Write>(out: &mut W, plan: &Plan, dry_run: bool) -> Result<()> {
    let mut output_live = true;
    let header_result = write_plan_header(out, plan, dry_run);
    output_live &= handle_write(header_result, dry_run)?;

    for op in &plan.ops {
        if !dry_run {
            execute_op(op)?;
        }
        if output_live {
            let r = write_op_line(out, op);
            output_live &= handle_write(r, dry_run)?;
        }
    }
    Ok(())
}

/// Return `Ok(true)` if the write succeeded and output is still live,
/// `Ok(false)` to go silent (apply + `BrokenPipe`), or `Err` otherwise.
fn handle_write(r: Result<()>, dry_run: bool) -> Result<bool> {
    match r {
        Ok(()) => Ok(true),
        Err(e) if !dry_run && is_broken_pipe(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Walk an anyhow error chain for a `BrokenPipe` `io::Error`.
fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|s| s.downcast_ref::<io::Error>())
        .any(|ioe| ioe.kind() == io::ErrorKind::BrokenPipe)
}

fn write_plan_header<W: Write>(out: &mut W, plan: &Plan, dry_run: bool) -> Result<()> {
    let mode = if dry_run { "dry-run" } else { "apply" };
    writeln!(
        out,
        "claude-login refresh-members ({mode}): {} member(s), source {}",
        plan.live_members.len(),
        plan.source_claude.display()
    )?;
    writeln!(out, "  agents-dir: {}", plan.agents_dir.display())?;
    if plan.live_members.is_empty() {
        writeln!(
            out,
            "  (no [[fleet]] members in the config — nothing to materialize)"
        )?;
    } else {
        writeln!(out, "  members: {}", plan.live_members.join(", "))?;
    }
    if !plan.stale_overlays.is_empty() {
        writeln!(
            out,
            "  stale overlays: {} ({} --prune)",
            plan.stale_overlays.join(", "),
            if plan.prune { "will remove via" } else { "preserved; pass" }
        )?;
    }
    writeln!(out)?;
    Ok(())
}

fn write_op_line<W: Write>(out: &mut W, op: &Op) -> Result<()> {
    match op {
        Op::EnsureOverlayDir { member, overlay_claude } => {
            writeln!(out, "  [{member}] overlay-dir   {}", overlay_claude.display())?;
        }
        Op::Symlink { member, link, target, kind } => {
            let tag = match kind {
                SymlinkKind::Shared => "symlink-sh",
                SymlinkKind::PerSession => "symlink-sess",
            };
            writeln!(out, "  [{member}] {tag}  {} -> {}", link.display(), target.display())?;
        }
        Op::EnsureDir { member, path } => {
            writeln!(out, "  [{member}] ensure-dir    {}", path.display())?;
        }
        Op::EnsureFile { member, path } => {
            writeln!(out, "  [{member}] ensure-file   {}", path.display())?;
        }
        Op::SkipIgnored { member, name } => {
            writeln!(out, "  [{member}] skip-ignored  {name}")?;
        }
        Op::PruneOverlay { member, overlay_root } => {
            writeln!(out, "  [{member}] prune-stale   {}", overlay_root.display())?;
        }
        Op::WarnStale { member, overlay_root } => {
            writeln!(
                out,
                "  [{member}] warn-stale    {} (pass --prune to remove)",
                overlay_root.display()
            )?;
        }
    }
    Ok(())
}

fn execute_op(op: &Op) -> Result<()> {
    match op {
        Op::EnsureOverlayDir { overlay_claude, .. } => {
            ensure_overlay_claude_dir(overlay_claude)?;
        }
        Op::Symlink { link, target, .. } => {
            ensure_symlink(link, target)?;
        }
        Op::EnsureDir { path, .. } => {
            ensure_per_member_dir(path)?;
        }
        Op::EnsureFile { path, .. } => {
            ensure_per_member_file(path)?;
        }
        Op::SkipIgnored { .. } => {}
        Op::PruneOverlay { overlay_root, .. } => {
            match fs::remove_dir_all(overlay_root) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("prune stale overlay {}", overlay_root.display())
                    });
                }
            }
        }
        Op::WarnStale { .. } => {
            // The warning is already printed; nothing to execute.
        }
    }
    Ok(())
}

/// Create the overlay HOME chain `<agents_dir>/<member>/home/.claude/` (0700
/// on the leaf, matching the real `~/.claude/`). Parent dirs are mkdir -p
/// without a tightened mode — they live under `$XDG_CONFIG_HOME/softfig/`,
/// which the growlight runtime already owns, and we don't want to clobber
/// a mode the owner tightened intentionally.
fn ensure_overlay_claude_dir(overlay_claude: &Path) -> Result<()> {
    if let Some(parent) = overlay_claude.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    match fs::symlink_metadata(overlay_claude) {
        Ok(md) if md.file_type().is_dir() => {
            let mode = md.permissions().mode() & 0o777;
            if mode != 0o700 {
                fs::set_permissions(overlay_claude, fs::Permissions::from_mode(0o700))
                    .context("chmod 0700 overlay .claude/")?;
            }
            Ok(())
        }
        Ok(md) => bail!(
            "{} exists but is not a directory ({:?})",
            overlay_claude.display(),
            md.file_type()
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(overlay_claude)
                .with_context(|| format!("create {}", overlay_claude.display()))?;
            fs::set_permissions(overlay_claude, fs::Permissions::from_mode(0o700))
                .context("chmod 0700 overlay .claude/")?;
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("stat {}", overlay_claude.display())),
    }
}

/// Create or retarget `link -> target` atomically. If `link` is already a
/// symlink with the identical target, this is a no-op (so a dry-run of a
/// steady-state system plans the symlink but execute is cheap, and an
/// idempotent re-run makes no filesystem writes).
fn ensure_symlink(link: &Path, target: &Path) -> Result<()> {
    match fs::read_link(link) {
        Ok(existing) if existing == target => return Ok(()),
        Ok(_) => {
            // Different target or non-symlink content at `link` — retarget
            // via atomic replace below. We allow replacing a plain file here
            // (growlightd may have retargeted at session start by writing a
            // placeholder), but only through `atomic_symlink`'s rename, so
            // this is still crash-safe.
        }
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
            // `link` exists but is not a symlink — replace it.
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Create below.
        }
        Err(e) => {
            return Err(e).with_context(|| format!("read_link {}", link.display()));
        }
    }
    atomic_symlink(target, link)
}

/// Create a per-member directory if it is missing. Never recursive; the
/// overlay HOME chain is created by [`ensure_overlay_claude_dir`]. Mode is
/// `0700` on first create to match the real `~/.claude/`'s sensitive dirs;
/// existing dirs are preserved as-is (do not clobber a mode the member set).
fn ensure_per_member_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_dir() => Ok(()),
        Ok(md) => bail!(
            "{} exists but is not a directory ({:?})",
            path.display(),
            md.file_type()
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).with_context(|| format!("create {}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", path.display()))?;
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("stat {}", path.display())),
    }
}

/// Create an empty per-member file if it is missing. Mode `0600`.
fn ensure_per_member_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_file() => Ok(()),
        Ok(md) => bail!(
            "{} exists but is not a regular file ({:?})",
            path.display(),
            md.file_type()
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("create {}", path.display()))?;
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("stat {}", path.display())),
    }
}

// ---- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const OAUTH1: &str = r#"{"claudeAiOauth":{"subscriptionType":"pro","rateLimitTier":"standard","accountEmail":"a@example.com","accessToken":"x","refreshToken":"y","expiresAt":0,"scopes":[]}}"#;
    const OAUTH2: &str = r#"{"claudeAiOauth":{"subscriptionType":"pro","rateLimitTier":"standard","accountEmail":"b@example.com","accessToken":"z","refreshToken":"w","expiresAt":0,"scopes":[]}}"#;

    fn setup() -> (TempDir, Paths) {
        let td = TempDir::new().unwrap();
        let claude_home = td.path().join(".claude");
        fs::create_dir_all(&claude_home).unwrap();
        let paths = Paths::new(&claude_home);
        (td, paths)
    }

    fn write_plain_top_level(paths: &Paths, contents: &str) {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&paths.top_level)
            .unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn fresh_install_capture_refused() {
        let (_td, paths) = setup();
        let err = capture(&paths, "slot1", false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no `"), "unexpected: {msg}");
    }

    #[test]
    fn capture_creates_store_slot_and_symlink() {
        let (_td, paths) = setup();
        write_plain_top_level(&paths, OAUTH1);
        capture(&paths, "slot1", false).unwrap();

        // Store dir is 0700.
        let store_md = fs::metadata(&paths.store).unwrap();
        assert_eq!(store_md.permissions().mode() & 0o777, 0o700);

        // Slot file is 0600 with the exact captured bytes.
        let slot = paths.slot("slot1");
        let slot_md = fs::symlink_metadata(&slot).unwrap();
        assert!(slot_md.file_type().is_file());
        assert_eq!(slot_md.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&slot).unwrap(), OAUTH1);

        // Top-level is now a *relative* symlink into the store.
        let top_md = fs::symlink_metadata(&paths.top_level).unwrap();
        assert!(top_md.file_type().is_symlink());
        assert_eq!(
            fs::read_link(&paths.top_level).unwrap(),
            PathBuf::from("credentials.d/slot1.json")
        );
    }

    #[test]
    fn capture_refuses_overwrite_without_force() {
        let (_td, paths) = setup();
        write_plain_top_level(&paths, OAUTH1);
        capture(&paths, "slot1", false).unwrap();

        // Different live creds; naming the same slot without --force must fail.
        fs::remove_file(&paths.top_level).unwrap();
        write_plain_top_level(&paths, OAUTH2);
        let err = capture(&paths, "slot1", false).unwrap_err();
        assert!(
            format!("{err:#}").contains("already exists"),
            "unexpected: {err:#}"
        );

        // With --force it succeeds and the slot is updated.
        capture(&paths, "slot1", true).unwrap();
        assert_eq!(fs::read_to_string(paths.slot("slot1")).unwrap(), OAUTH2);
    }

    #[test]
    fn capture_idempotent_when_bytes_match() {
        let (_td, paths) = setup();
        write_plain_top_level(&paths, OAUTH1);
        capture(&paths, "slot1", false).unwrap();
        // Second call reads the same bytes through the symlink → identical → OK.
        capture(&paths, "slot1", false).unwrap();
    }

    #[test]
    fn capture_refuses_non_oauth() {
        let (_td, paths) = setup();
        write_plain_top_level(&paths, r#"{"apiKey":"sk-ant-xxx"}"#);
        let err = capture(&paths, "slot1", false).unwrap_err();
        assert!(
            format!("{err:#}").contains("API-key"),
            "unexpected: {err:#}"
        );
    }

    #[test]
    fn use_requires_existing_slot() {
        let (_td, paths) = setup();
        let err = use_slot(&paths, "nope").unwrap_err();
        assert!(
            format!("{err:#}").contains("does not exist"),
            "unexpected: {err:#}"
        );
    }

    #[test]
    fn use_refuses_plain_top_level_before_capture() {
        let (_td, paths) = setup();
        ensure_store_dir(&paths).unwrap();
        atomic_write_mode(&paths.slot("slot1"), OAUTH1.as_bytes(), 0o600).unwrap();
        write_plain_top_level(&paths, OAUTH1);

        let err = use_slot(&paths, "slot1").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("regular file"), "unexpected: {msg}");
        assert!(msg.contains("capture"), "should guide to capture: {msg}");
    }

    #[test]
    fn use_retargets_symlink_and_is_idempotent() {
        let (_td, paths) = setup();
        write_plain_top_level(&paths, OAUTH1);
        capture(&paths, "slot1", false).unwrap();
        atomic_write_mode(&paths.slot("slot2"), OAUTH2.as_bytes(), 0o600).unwrap();

        // Retarget to slot2.
        use_slot(&paths, "slot2").unwrap();
        assert_eq!(
            fs::read_link(&paths.top_level).unwrap(),
            PathBuf::from("credentials.d/slot2.json")
        );
        // Repeat use `slot2` — must be idempotent (link unchanged).
        use_slot(&paths, "slot2").unwrap();
        assert_eq!(
            fs::read_link(&paths.top_level).unwrap(),
            PathBuf::from("credentials.d/slot2.json")
        );
        // Flip back.
        use_slot(&paths, "slot1").unwrap();
        assert_eq!(
            fs::read_link(&paths.top_level).unwrap(),
            PathBuf::from("credentials.d/slot1.json")
        );
    }

    #[test]
    fn slot_mode_preserved_across_rewrites() {
        let (_td, paths) = setup();
        write_plain_top_level(&paths, OAUTH1);
        capture(&paths, "slot1", false).unwrap();
        // Rewrite with --force; mode must stay 0600.
        capture(&paths, "slot1", true).unwrap();
        let md = fs::symlink_metadata(paths.slot("slot1")).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn ensure_store_dir_tightens_loose_mode() {
        let (_td, paths) = setup();
        fs::create_dir(&paths.store).unwrap();
        fs::set_permissions(&paths.store, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_store_dir(&paths).unwrap();
        let md = fs::metadata(&paths.store).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn validate_slot_name_rules() {
        assert!(validate_slot_name("").is_err());
        assert!(validate_slot_name("/bad").is_err());
        assert!(validate_slot_name("..").is_err());
        assert!(validate_slot_name(".leading").is_err());
        assert!(validate_slot_name("has space").is_err());
        assert!(validate_slot_name("has\nnewline").is_err());
        assert!(validate_slot_name(&"x".repeat(65)).is_err());

        assert!(validate_slot_name("good").is_ok());
        assert!(validate_slot_name("slot1").is_ok());
        assert!(validate_slot_name("my.slot_1-a").is_ok());
    }

    #[test]
    fn inspect_top_level_classifies_variants() {
        let (_td, paths) = setup();
        assert!(matches!(inspect_top_level(&paths).unwrap(), TopLevel::Missing));

        write_plain_top_level(&paths, OAUTH1);
        assert!(matches!(inspect_top_level(&paths).unwrap(), TopLevel::Plain));

        // Symlink-in.
        fs::remove_file(&paths.top_level).unwrap();
        ensure_store_dir(&paths).unwrap();
        atomic_write_mode(&paths.slot("slot1"), OAUTH1.as_bytes(), 0o600).unwrap();
        atomic_symlink(
            &PathBuf::from("credentials.d/slot1.json"),
            &paths.top_level,
        )
        .unwrap();
        match inspect_top_level(&paths).unwrap() {
            TopLevel::SymlinkIn { slot_name } => assert_eq!(slot_name, "slot1"),
            other => panic!("expected SymlinkIn, got {other:?}"),
        }

        // Symlink-out (absolute target → not in store).
        fs::remove_file(&paths.top_level).unwrap();
        atomic_symlink(Path::new("/dev/null"), &paths.top_level).unwrap();
        assert!(matches!(
            inspect_top_level(&paths).unwrap(),
            TopLevel::SymlinkOut { .. }
        ));
    }

    // ---- refresh-members tests ---------------------------------------------

    /// A `growlight.toml` with the two live members slice 002's finish check
    /// names (`a` and `d`). `fleet_enabled` stays `true` so the parser builds
    /// a non-disabled config; the overlay builder itself doesn't read the
    /// gate.
    const FLEET_TOML: &str = r#"
fleet_enabled = true
[[fleet]]
agent = "a"
pin = "default"

[[fleet]]
agent = "d"
pin = "remote-runner"
"#;

    /// Shape of a fake `~/.claude/` with every top-level name the inventory
    /// test covers. Dirs vs files chosen to match the real device.
    fn make_fake_claude_home(claude_home: &Path) {
        fs::create_dir_all(claude_home).unwrap();
        for d in &[
            "plugins",
            "skills",
            "shell-snapshots",
            "backups",
            "projects",
            "cache",
            "sessions",
            "tasks",
            "telemetry",
            "jobs",
            "paste-cache",
            "file-history",
            "session-env",
            "state",
            "plans",
            "daemon",
            "chrome",
            "downloads",
        ] {
            fs::create_dir_all(claude_home.join(d)).unwrap();
        }
        for f in &[
            "settings.json",
            "settings.local.json",
            "statusline-command.sh",
            ".last-cleanup",
            ".last-update-result.json",
            "CLAUDE.md",
            "history.jsonl",
            "stats-cache.json",
            "daemon.lock",
            "daemon.log",
            "daemon.status.json",
            ".credentials.json",
        ] {
            fs::write(claude_home.join(f), b"").unwrap();
        }
    }

    fn write_toml(dir: &Path) -> PathBuf {
        let p = dir.join("growlight.toml");
        fs::write(&p, FLEET_TOML).unwrap();
        p
    }

    fn refresh(claude_home: &Path, config: &Path, agents_dir: &Path, prune: bool) -> Plan {
        let paths = Paths::new(claude_home);
        let plan = plan_refresh(&paths, config, agents_dir, prune).unwrap();
        let mut sink: Vec<u8> = Vec::new();
        apply_plan(&mut sink, &plan, false).unwrap();
        plan
    }

    #[test]
    fn refresh_builds_overlay_for_both_members() {
        let td = TempDir::new().unwrap();
        let claude_home = td.path().join(".claude");
        make_fake_claude_home(&claude_home);
        let config = write_toml(td.path());
        let agents_dir = td.path().join("agents");

        let plan = refresh(&claude_home, &config, &agents_dir, false);
        assert_eq!(plan.live_members, vec!["a".to_string(), "d".to_string()]);
        for m in &["a", "d"] {
            let overlay = agents_dir.join(m).join("home").join(".claude");
            assert!(overlay.is_dir(), "overlay dir missing for {m}");

            // Shared symlink shape.
            let settings = overlay.join("settings.json");
            let md = fs::symlink_metadata(&settings).unwrap();
            assert!(md.file_type().is_symlink());
            assert_eq!(fs::read_link(&settings).unwrap(), claude_home.join("settings.json"));

            // Per-member dir created, 0700.
            let projects = overlay.join("projects");
            let pmd = fs::symlink_metadata(&projects).unwrap();
            assert!(pmd.file_type().is_dir());
            assert_eq!(pmd.permissions().mode() & 0o777, 0o700);

            // Per-member file created, 0600.
            let hist = overlay.join("history.jsonl");
            let hmd = fs::symlink_metadata(&hist).unwrap();
            assert!(hmd.file_type().is_file());
            assert_eq!(hmd.permissions().mode() & 0o777, 0o600);

            // Per-session symlink points at the real top-level fallback.
            let cred = overlay.join(".credentials.json");
            let cmd_md = fs::symlink_metadata(&cred).unwrap();
            assert!(cmd_md.file_type().is_symlink());
            assert_eq!(
                fs::read_link(&cred).unwrap(),
                claude_home.join(".credentials.json")
            );

            // Ignored names never materialize.
            assert!(!overlay.join("chrome").exists());
            assert!(!overlay.join("downloads").exists());
        }

        // Overlay HOME is 0700.
        let overlay_a = agents_dir.join("a").join("home").join(".claude");
        let md = fs::symlink_metadata(&overlay_a).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn refresh_dry_run_touches_nothing() {
        let td = TempDir::new().unwrap();
        let claude_home = td.path().join(".claude");
        make_fake_claude_home(&claude_home);
        let config = write_toml(td.path());
        let agents_dir = td.path().join("agents");

        let paths = Paths::new(&claude_home);
        let plan = plan_refresh(&paths, &config, &agents_dir, false).unwrap();
        let mut sink: Vec<u8> = Vec::new();
        apply_plan(&mut sink, &plan, /*dry_run*/ true).unwrap();

        // Not even the top-level agents_dir exists.
        assert!(!agents_dir.exists(), "dry-run must not create agents_dir");
        // Output names the mode + at least one plan op.
        let s = String::from_utf8(sink).unwrap();
        assert!(s.contains("(dry-run)"), "output: {s}");
        assert!(s.contains("overlay-dir"), "output: {s}");
    }

    #[test]
    fn refresh_is_idempotent_and_preserves_mutable_content() {
        let td = TempDir::new().unwrap();
        let claude_home = td.path().join(".claude");
        make_fake_claude_home(&claude_home);
        let config = write_toml(td.path());
        let agents_dir = td.path().join("agents");

        refresh(&claude_home, &config, &agents_dir, false);

        // Write a sentinel into a per-member dir.
        let overlay_a_projects = agents_dir.join("a").join("home").join(".claude").join("projects");
        fs::write(overlay_a_projects.join("my-project.sentinel"), b"keep me").unwrap();

        // Capture every post-refresh path's inode so a second refresh can be
        // proven to not relink the symlinks either.
        fn snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, (u64, u64)> {
            let mut out = std::collections::BTreeMap::new();
            fn walk(root: &Path, acc: &mut std::collections::BTreeMap<PathBuf, (u64, u64)>) {
                for ent in fs::read_dir(root).unwrap().flatten() {
                    let p = ent.path();
                    let md = fs::symlink_metadata(&p).unwrap();
                    use std::os::unix::fs::MetadataExt;
                    acc.insert(p.clone(), (md.ino(), md.dev()));
                    if md.file_type().is_dir() {
                        walk(&p, acc);
                    }
                }
            }
            walk(root, &mut out);
            out
        }
        let before = snapshot(&agents_dir);

        refresh(&claude_home, &config, &agents_dir, false);

        let after = snapshot(&agents_dir);
        assert_eq!(before, after, "refresh is not idempotent");

        // Sentinel still there.
        assert_eq!(
            fs::read_to_string(overlay_a_projects.join("my-project.sentinel")).unwrap(),
            "keep me"
        );
    }

    #[test]
    fn refresh_retargets_session_symlink_to_managed_slot() {
        let td = TempDir::new().unwrap();
        let claude_home = td.path().join(".claude");
        make_fake_claude_home(&claude_home);
        // Replace the plain `.credentials.json` with slice 001's managed form:
        // `credentials.d/slot1.json` + a symlink into it.
        fs::remove_file(claude_home.join(".credentials.json")).unwrap();
        let paths = Paths::new(&claude_home);
        ensure_store_dir(&paths).unwrap();
        atomic_write_mode(&paths.slot("slot1"), OAUTH1.as_bytes(), 0o600).unwrap();
        atomic_symlink(
            &PathBuf::from("credentials.d/slot1.json"),
            &paths.top_level,
        )
        .unwrap();

        let config = write_toml(td.path());
        let agents_dir = td.path().join("agents");
        refresh(&claude_home, &config, &agents_dir, false);

        // Overlay's `.credentials.json` resolves to the ABSOLUTE slot path.
        let cred = agents_dir.join("a").join("home").join(".claude").join(".credentials.json");
        assert_eq!(
            fs::read_link(&cred).unwrap(),
            claude_home.join("credentials.d").join("slot1.json")
        );
    }

    #[test]
    fn refresh_without_prune_warns_but_keeps_stale_overlay() {
        let td = TempDir::new().unwrap();
        let claude_home = td.path().join(".claude");
        make_fake_claude_home(&claude_home);
        let config = write_toml(td.path());
        let agents_dir = td.path().join("agents");

        // Pre-seed a stale overlay for a retired member `x` with mutable
        // content that must survive a refresh.
        let stale_overlay = agents_dir.join("x").join("home").join(".claude").join("projects");
        fs::create_dir_all(&stale_overlay).unwrap();
        fs::write(stale_overlay.join("preserved.sentinel"), b"keep").unwrap();

        let paths = Paths::new(&claude_home);
        let plan = plan_refresh(&paths, &config, &agents_dir, false).unwrap();
        assert_eq!(plan.stale_overlays, vec!["x".to_string()]);
        let mut sink: Vec<u8> = Vec::new();
        apply_plan(&mut sink, &plan, false).unwrap();
        let s = String::from_utf8(sink).unwrap();
        assert!(s.contains("warn-stale"), "output: {s}");

        // Stale overlay still intact.
        assert!(stale_overlay.join("preserved.sentinel").exists());
    }

    #[test]
    fn refresh_with_prune_removes_stale_overlay() {
        let td = TempDir::new().unwrap();
        let claude_home = td.path().join(".claude");
        make_fake_claude_home(&claude_home);
        let config = write_toml(td.path());
        let agents_dir = td.path().join("agents");

        let stale_root = agents_dir.join("x");
        fs::create_dir_all(stale_root.join("home").join(".claude").join("projects")).unwrap();
        fs::write(
            stale_root.join("home").join(".claude").join("projects").join("gone.sentinel"),
            b"gone",
        )
        .unwrap();

        refresh(&claude_home, &config, &agents_dir, /*prune*/ true);
        assert!(!stale_root.exists(), "--prune should have removed {}", stale_root.display());
    }
}
