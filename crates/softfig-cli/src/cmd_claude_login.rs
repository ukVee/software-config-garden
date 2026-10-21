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

pub fn run(cmd: ClaudeLoginCmd) -> Result<()> {
    let home = resolve_claude_home()?;
    let paths = Paths::new(&home);
    match cmd {
        ClaudeLoginCmd::List => list(&paths),
        ClaudeLoginCmd::Capture(a) => capture(&paths, &a.name, a.force),
        ClaudeLoginCmd::Use(a) => use_slot(&paths, &a.name),
        ClaudeLoginCmd::Login(a) => login(&paths, &a.name),
        ClaudeLoginCmd::Status => status(&paths),
    }
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
}
