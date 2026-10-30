//! `softfig claude-login`: a two-account Anthropic login switcher for Claude
//! Code (milestone `claude-login-switcher`; the slot-store model of slice
//! 006, decision `decision-claude-login-config-dir-slots`).
//!
//! * A **slot** is a real `CLAUDE_CONFIG_DIR` in the profile store,
//!   `$XDG_DATA_HOME/softfig/claude-profiles/<slot>/`
//!   ([`softfig_ipc::claude_profiles`] is the one resolver, shared with
//!   growlightd). Claude owns `.credentials.json`, `.claude.json` and the
//!   refresh lock inside it. Shared configuration is symlinked in from
//!   `~/.claude/` ([`crate::slot_layout`]). `HOME` is never overridden.
//! * The reserved slot `home` is Claude's default config dir with the env
//!   var unset: the state before `migrate`, and the fallback.
//! * `<store>/active` names the everyday terminal's slot. The bash `claude()`
//!   shim in `~/dotfiles` asks `claude-login dir --active` at every exec, so
//!   a running session is never retargeted.
//! * **A credential is moved, never copied.** Refresh-token rotation turns a
//!   copy into a time bomb: whichever copy refreshes first kills the other.
//!   `migrate` moves the home account into the store; `add` logs a new
//!   account in with Claude's own `claude auth login`.
//!
//! `migrate` is resumable. It assembles the slot in a staging dir
//! `<store>/.migrate-<slot>/`, moving each account file with `rename(2)` (or
//! copy + fsync + unlink across filesystems), then renames the staging dir to
//! `<slot>` in one step. A re-run after an interruption finishes the job: a
//! file already in staging is not moved again, and a file present in both
//! places with identical bytes (an interrupted cross-filesystem move) has its
//! source removed. Different bytes in both places mean a login ran after the
//! interruption, so the re-run refuses rather than guess which token is live.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use serde_json::{Map, Value};
use softfig_ipc::claude_profiles::{
    self as profiles, ACCOUNT_FILE, ACTIVE_LINK, CONFIG_DIR_ENV, CREDENTIALS_FILE,
    CredentialState, HOME_SLOT, SlotDir, credential_state, read_active, resolve_active,
};

use crate::slot_layout::{classify, shared_names};

#[derive(Subcommand, Debug)]
pub enum ClaudeLoginCmd {
    /// List the slots (`home` plus the store) with each one's account email.
    /// `*` marks the active slot.
    List,
    /// Create a store slot: link the shared config from `~/.claude/`, seed
    /// `.claude.json` from an allow-list (MCP servers, onboarding,
    /// per-project trust; never the account or caches), then run
    /// `claude auth login` in it.
    Add(AddArgs),
    /// One time: move the home account (`~/.claude/.credentials.json` and
    /// `~/.claude.json`) into a new store slot and make it active. Refuses
    /// while any claude process, the daemon included, is running.
    Migrate(SlotArg),
    /// Point `active` at a slot. Only claude sessions started afterwards
    /// follow it; running ones keep their slot.
    Use(SlotArg),
    /// Run a command with `CLAUDE_CONFIG_DIR` set to a slot (unset for
    /// `home`). `HOME` is left alone.
    Run(RunArgs),
    /// Print a slot's config dir, or nothing for `home`. For the shell shim
    /// and scripts.
    Dir(DirArgs),
    /// Read-only health check of the store, every slot and `~/.claude/`.
    /// Exits non-zero when it finds a problem.
    Doctor,
    /// `list`, plus each slot's 5h budget headroom and the fleet members'
    /// profile pins.
    Status,
}

#[derive(Args, Debug)]
pub struct SlotArg {
    /// Slot name, `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. `home` is reserved.
    pub slot: String,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// The new slot's name.
    pub slot: String,
    /// The slot whose `.claude.json` seeds the new one. Defaults to the
    /// active slot.
    #[arg(long)]
    pub from: Option<String>,
    /// Create the slot but skip `claude auth login`.
    #[arg(long)]
    pub no_login: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// The slot to run under.
    pub slot: String,
    /// The command and its arguments, after `--`. Defaults to `claude`.
    #[arg(last = true)]
    pub argv: Vec<OsString>,
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct DirArgs {
    /// The slot to print.
    pub slot: Option<String>,
    /// Print the active slot's dir instead.
    #[arg(long)]
    pub active: bool,
}

pub fn run(cmd: ClaudeLoginCmd) -> Result<()> {
    let env = Env::from_process()?;
    let mut out = io::stdout().lock();
    match cmd {
        ClaudeLoginCmd::List => list(&env, &mut out),
        ClaudeLoginCmd::Add(a) => add_then_login(&env, &a, &mut out, &mut |mut c| c.status()),
        ClaudeLoginCmd::Migrate(a) => {
            let procs = ProcScan::system()?;
            migrate(&env, &a.slot, &procs, rename_file, &mut out)
        }
        ClaudeLoginCmd::Use(a) => use_slot(&env, &a.slot, &mut out),
        ClaudeLoginCmd::Run(a) => {
            let mut cmd = run_command(&env, &a.slot, &a.argv)?;
            let err = cmd.exec();
            Err(err).with_context(|| format!("exec {:?}", cmd.get_program()))
        }
        ClaudeLoginCmd::Dir(a) => dir(&env, &a, &mut out),
        ClaudeLoginCmd::Doctor => doctor(&env, &mut out),
        ClaudeLoginCmd::Status => status(&env, &mut out),
    }
}

/// Where everything lives, resolved once from the process environment (or a
/// tempdir in tests).
#[derive(Debug, Clone)]
struct Env {
    /// The shared config dir `~/.claude/`, which is also the `home` slot's
    /// config dir.
    claude_home: PathBuf,
    /// `~/.claude.json`, the `home` slot's account file.
    home_account: PathBuf,
    /// The profile store.
    store: PathBuf,
}

impl Env {
    fn from_process() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is not set"))?;
        let store = profiles::store_root(std::env::var_os("XDG_DATA_HOME").as_deref(), &home);
        Ok(Self::rooted(&home, store))
    }

    fn rooted(home: &Path, store: PathBuf) -> Self {
        Self {
            claude_home: home.join(".claude"),
            home_account: home.join(ACCOUNT_FILE),
            store,
        }
    }

    /// Shape-check a slot name and say where it points, without touching
    /// the disk.
    fn resolve(&self, slot: &str) -> Result<SlotDir> {
        profiles::slot_dir(&self.store, slot).map_err(|e| anyhow!("slot {slot:?}: {e}"))
    }

    /// [`Env::resolve`], requiring a store slot's directory to exist.
    fn existing(&self, slot: &str) -> Result<SlotDir> {
        let dir = self.resolve(slot)?;
        if let SlotDir::Store(p) = &dir
            && !is_real_dir(p)
        {
            bail!(
                "no slot {slot:?} in {} (see `softfig claude-login list`)",
                self.store.display()
            );
        }
        Ok(dir)
    }

    /// A new store slot's path: refuses `home` and malformed names.
    fn new_store_slot(&self, slot: &str) -> Result<PathBuf> {
        match self.resolve(slot)? {
            SlotDir::Home => bail!(
                "`{HOME_SLOT}` is reserved: it means Claude's default config dir (~/.claude)"
            ),
            SlotDir::Store(p) => Ok(p),
        }
    }

    fn config_dir(&self, dir: &SlotDir) -> PathBuf {
        match dir {
            SlotDir::Home => self.claude_home.clone(),
            SlotDir::Store(p) => p.clone(),
        }
    }

    fn account_file(&self, dir: &SlotDir) -> PathBuf {
        match dir {
            SlotDir::Home => self.home_account.clone(),
            SlotDir::Store(p) => p.join(ACCOUNT_FILE),
        }
    }
}

fn is_real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

fn lstat(p: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(p) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("stat {}", p.display())),
    }
}

/// The store's slot directories, sorted. `home`, dot-entries, `*.lock` and
/// anything that is not a real directory are not slots.
fn store_slots(store: &Path) -> Result<Vec<String>> {
    let rd = match fs::read_dir(store) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", store.display())),
    };
    let mut out = Vec::new();
    for ent in rd {
        let ent = ent?;
        let Some(name) = ent.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name != HOME_SLOT
            && softfig_ipc::validate_slot_name(&name).is_ok()
            && ent.file_type().is_ok_and(|t| t.is_dir())
        {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

// ---- small fs helpers -------------------------------------------------------

/// Monotone counter so two temp names in one process never collide.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_sibling(path: &Path) -> Result<PathBuf> {
    let fname = path
        .file_name()
        .ok_or_else(|| anyhow!("path has no file name: {}", path.display()))?;
    let mut name = OsString::from(".");
    name.push(fname);
    name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(path.with_file_name(name))
}

/// fsync a directory so a rename or unlink inside it survives a power cut
/// (this device has thermal power cuts).
fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("fsync {}", dir.display()))
}

fn sync_parent(p: &Path) -> Result<()> {
    match p.parent() {
        Some(d) => sync_dir(d),
        None => Ok(()),
    }
}

/// Create `dir` with `mode`, or tighten an existing one we own to it.
fn ensure_dir_mode(dir: &Path, mode: u32) -> Result<()> {
    match lstat(dir)? {
        Some(md) if md.is_dir() => {
            if md.permissions().mode() & 0o777 != mode {
                fs::set_permissions(dir, fs::Permissions::from_mode(mode))
                    .with_context(|| format!("chmod {mode:o} {}", dir.display()))?;
            }
            Ok(())
        }
        Some(_) => bail!("{} exists but is not a directory", dir.display()),
        None => {
            if let Some(parent) = dir.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            fs::create_dir(dir).with_context(|| format!("create {}", dir.display()))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(mode))
                .with_context(|| format!("chmod {mode:o} {}", dir.display()))
        }
    }
}

/// Write a file that must not exist yet, with `mode`, and fsync it.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .with_context(|| format!("write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

/// Create or atomically retarget `link` to the literal `target`. The temp
/// link is removed if the rename fails.
fn atomic_symlink(target: &Path, link: &Path) -> Result<()> {
    let tmp = tmp_sibling(link)?;
    symlink(target, &tmp).with_context(|| format!("symlink {}", tmp.display()))?;
    if let Err(e) = fs::rename(&tmp, link) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename into {}", link.display()));
    }
    sync_parent(link)
}

// ---- the active pointer -----------------------------------------------------

/// Point `<store>/active` at `slot`. `home` removes the pointer, which reads
/// back as `home`.
fn set_active(store: &Path, slot: &str) -> Result<()> {
    let link = store.join(ACTIVE_LINK);
    if slot == HOME_SLOT {
        return match lstat(&link)? {
            None => Ok(()),
            Some(md) if md.file_type().is_symlink() => {
                fs::remove_file(&link).with_context(|| format!("remove {}", link.display()))?;
                sync_dir(store)
            }
            Some(_) => bail!("{} is not a symlink; refusing to remove it", link.display()),
        };
    }
    if lstat(&link)?.is_some_and(|m| !m.file_type().is_symlink()) {
        bail!("{} is not a symlink; refusing to replace it", link.display());
    }
    atomic_symlink(Path::new(slot), &link)
}

// ---- account files ----------------------------------------------------------

/// Top-level `.claude.json` keys a new slot inherits.
const SEED_TOP: &[&str] = &["mcpServers", "hasCompletedOnboarding"];
/// Per-project `.claude.json` keys a new slot inherits.
const SEED_PROJECT: &[&str] = &[
    "hasTrustDialogAccepted",
    "mcpServers",
    "enabledMcpjsonServers",
    "disabledMcpjsonServers",
    "allowedTools",
];

/// The allow-listed projection of a `.claude.json`: what `add` seeds and
/// what `doctor` compares across slots. Everything else (`oauthAccount`,
/// `userID`, every cache) is account-bound and never crosses slots.
fn seed_projection(src: &Value) -> Value {
    let mut out = Map::new();
    for k in SEED_TOP {
        if let Some(v) = src.get(*k) {
            out.insert((*k).to_string(), v.clone());
        }
    }
    if let Some(projects) = src.get("projects").and_then(Value::as_object) {
        let mut seeded = Map::new();
        for (path, p) in projects {
            let picked: Map<String, Value> = SEED_PROJECT
                .iter()
                .filter_map(|k| p.get(*k).map(|v| ((*k).to_string(), v.clone())))
                .collect();
            if !picked.is_empty() {
                seeded.insert(path.clone(), Value::Object(picked));
            }
        }
        if !seeded.is_empty() {
            out.insert("projects".into(), Value::Object(seeded));
        }
    }
    Value::Object(out)
}

/// Parse an account file. `Ok(None)` when absent. A parse error names the
/// position only, never the text, so it cannot quote a secret.
fn read_account(path: &Path) -> Result<Option<Value>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) if v.is_object() => Ok(Some(v)),
        Ok(_) => bail!("{} is not a JSON object", path.display()),
        Err(e) => bail!(
            "{} is not valid JSON (line {}, column {})",
            path.display(),
            e.line(),
            e.column()
        ),
    }
}

fn account_email(v: &Value) -> Option<&str> {
    v.get("oauthAccount")?.get("emailAddress")?.as_str()
}

// ---- list -------------------------------------------------------------------

#[derive(Debug)]
struct SlotRow {
    name: String,
    active: bool,
    email: Option<String>,
    creds: CredentialState,
}

/// `home` first, then the store slots. A broken active pointer marks no row
/// active (`doctor` reports it).
fn slot_rows(env: &Env) -> Result<Vec<SlotRow>> {
    let active = read_active(&env.store).ok();
    let mut names = vec![HOME_SLOT.to_string()];
    names.extend(store_slots(&env.store)?);
    names
        .into_iter()
        .map(|name| {
            let dir = env.resolve(&name)?;
            let creds = credential_state(&env.config_dir(&dir))
                .with_context(|| format!("inspect slot {name}'s credentials"))?;
            let email = read_account(&env.account_file(&dir))
                .ok()
                .flatten()
                .and_then(|v| account_email(&v).map(str::to_owned));
            Ok(SlotRow {
                active: active.as_deref() == Some(name.as_str()),
                name,
                email,
                creds,
            })
        })
        .collect()
}

fn fmt_row(r: &SlotRow) -> String {
    let who = r.email.as_deref().unwrap_or("(no account email)");
    match r.creds {
        CredentialState::Ok => who.to_string(),
        CredentialState::Missing => "(logged out)".to_string(),
        CredentialState::NotRegular => {
            format!("{who} [credentials are not a regular file: see doctor]")
        }
        CredentialState::LoosePerms(m) => format!("{who} [credentials mode {m:o}]"),
    }
}

fn list(env: &Env, out: &mut dyn Write) -> Result<()> {
    let rows = slot_rows(env)?;
    writeln!(out, "store: {}", env.store.display())?;
    let width = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for r in &rows {
        let marker = if r.active { "*" } else { " " };
        writeln!(out, "{marker} {:<width$}  {}", r.name, fmt_row(r))?;
    }
    Ok(())
}

// ---- add --------------------------------------------------------------------

/// Link every Shared name whose `~/.claude/` source exists into `slot_dir`.
/// A link that is already correct is kept, so a resumed `migrate` can call
/// this again; anything else in the way is refused.
fn link_shared(claude_home: &Path, slot_dir: &Path) -> Result<Vec<&'static str>> {
    let mut linked = Vec::new();
    for name in shared_names() {
        let src = claude_home.join(name);
        if !src.exists() {
            continue;
        }
        let dst = slot_dir.join(name);
        match lstat(&dst)? {
            None => {
                symlink(&src, &dst).with_context(|| format!("symlink {}", dst.display()))?
            }
            Some(md) if md.file_type().is_symlink() && fs::read_link(&dst)? == src => {}
            Some(_) => bail!("{} exists and is not the shared link", dst.display()),
        }
        linked.push(name);
    }
    Ok(linked)
}

/// Create the store slot `slot` (layout, links, seeded `.claude.json`) and
/// return its dir. Never logs in: [`add_then_login`] does that.
fn add(env: &Env, slot: &str, from: Option<&str>, out: &mut dyn Write) -> Result<PathBuf> {
    let dest = env.new_store_slot(slot)?;
    if lstat(&dest)?.is_some() {
        bail!(
            "slot {slot:?} already exists at {}; to log it in again run \
             `softfig claude-login run {slot} -- claude auth login`",
            dest.display()
        );
    }
    let source_name = match from {
        Some(s) => s.to_string(),
        None => read_active(&env.store).map_err(|e| anyhow!("{e}; pass --from <slot>"))?,
    };
    let source = env.existing(&source_name)?;
    let seed = read_account(&env.account_file(&source))?.map(|v| seed_projection(&v));

    ensure_dir_mode(&env.store, 0o700)?;
    let staging = tmp_sibling(&env.store.join(format!("add-{slot}")))?;
    fs::create_dir(&staging).with_context(|| format!("create {}", staging.display()))?;
    let built = (|| -> Result<Vec<&'static str>> {
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
        let linked = link_shared(&env.claude_home, &staging)?;
        if let Some(seed) = &seed {
            let bytes = serde_json::to_vec_pretty(seed)?;
            write_new(&staging.join(ACCOUNT_FILE), &bytes, 0o600)?;
        }
        sync_dir(&staging)?;
        fs::rename(&staging, &dest)
            .with_context(|| format!("rename {} -> {}", staging.display(), dest.display()))?;
        sync_dir(&env.store)?;
        Ok(linked)
    })();
    let linked = match built {
        Ok(l) => l,
        Err(e) => {
            // The staging dir only ever holds links and the seed: never a
            // credential, so removing it loses nothing.
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    writeln!(out, "created slot {slot} at {}", dest.display())?;
    writeln!(out, "  shared links: {}", if linked.is_empty() { "(none)".into() } else { linked.join(", ") })?;
    match &seed {
        Some(v) => {
            let mcp = v.get("mcpServers").and_then(Value::as_object).map_or(0, Map::len);
            let projects = v.get("projects").and_then(Value::as_object).map_or(0, Map::len);
            writeln!(
                out,
                "  .claude.json seeded from {source_name}: {mcp} MCP server(s), {projects} project(s)"
            )?;
        }
        None => writeln!(out, "  .claude.json: {source_name} has none, so nothing seeded")?,
    }
    Ok(dest)
}

/// `add`, then (unless `--no-login`) `claude auth login` inside the new slot
/// through `launch`, the process seam tests replace.
fn add_then_login(
    env: &Env,
    a: &AddArgs,
    out: &mut dyn Write,
    launch: &mut dyn FnMut(Command) -> io::Result<ExitStatus>,
) -> Result<()> {
    let dest = add(env, &a.slot, a.from.as_deref(), out)?;
    let slot = &a.slot;
    if a.no_login {
        writeln!(out, "  skipped login; run `softfig claude-login run {slot} -- claude auth login`")?;
        return Ok(());
    }
    out.flush()?;
    let argv = ["claude", "auth", "login"].map(OsString::from);
    let status = launch(run_command(env, slot, &argv)?).context("launch `claude auth login`")?;
    if !status.success() {
        bail!(
            "`claude auth login` exited with {status}; the slot exists without credentials. \
             Retry with `softfig claude-login run {slot} -- claude auth login`"
        );
    }
    match credential_state(&dest)? {
        CredentialState::Ok => writeln!(out, "slot {slot} is logged in")?,
        other => writeln!(out, "warning: slot {slot}'s credentials after login: {other:?}")?,
    }
    Ok(())
}

// ---- migrate ----------------------------------------------------------------

/// One live claude process, as `migrate` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveClaude {
    pid: u32,
    cmdline: String,
}

/// The pid-probe seam `migrate` refuses on.
trait ClaudeProcesses {
    fn live(&self) -> Result<Vec<LiveClaude>>;
}

/// Scans a procfs root (`/proc` in production) for this user's claude
/// processes: the CLI, the daemon, `bg-pty-host` and spares alike.
struct ProcScan {
    root: PathBuf,
    own_pid: u32,
    own_uid: u32,
}

impl ProcScan {
    fn system() -> Result<Self> {
        let root = PathBuf::from("/proc");
        let own_uid = fs::metadata(root.join("self"))
            .context("stat /proc/self (needed to check for running claude)")?
            .uid();
        Ok(Self { root, own_pid: std::process::id(), own_uid })
    }
}

impl ClaudeProcesses for ProcScan {
    fn live(&self) -> Result<Vec<LiveClaude>> {
        let rd = fs::read_dir(&self.root)
            .with_context(|| format!("scan {} for running claude", self.root.display()))?;
        let mut live = Vec::new();
        for ent in rd.flatten() {
            let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let dir = ent.path();
            if pid == self.own_pid || !fs::metadata(&dir).is_ok_and(|m| m.uid() == self.own_uid)
            {
                continue;
            }
            let Ok(raw) = fs::read(dir.join("cmdline")) else {
                continue;
            };
            let argv: Vec<String> = raw
                .split(|&b| b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            let exe = fs::read_link(dir.join("exe")).ok();
            if is_claude(&argv, exe.as_deref()) {
                let mut cmdline = argv.join(" ");
                cmdline.truncate(100);
                live.push(LiveClaude { pid, cmdline });
            }
        }
        live.sort_by_key(|l| l.pid);
        Ok(live)
    }
}

/// A claude process: launched as `claude`, running a native build from
/// `…/claude/versions/<ver>` (whose `comm` is the version string), or the
/// npm package under node.
fn is_claude(argv: &[String], exe: Option<&Path>) -> bool {
    let Some(argv0) = argv.first() else {
        return false;
    };
    Path::new(argv0).file_name().is_some_and(|n| n == "claude")
        || exe.is_some_and(|e| e.parent().is_some_and(|p| p.ends_with("claude/versions")))
        || argv.iter().take(2).any(|a| a.contains("@anthropic-ai/claude-code"))
}

/// `rename(2)`, the production mover. Tests swap in one that fails with
/// `EXDEV` to drive the copy fallback.
type RenameFn = fn(&Path, &Path) -> io::Result<()>;

fn rename_file(src: &Path, dst: &Path) -> io::Result<()> {
    fs::rename(src, dst)
}

/// Move `src` to `dst` (which must not exist): `rename(2)`, or across
/// filesystems copy to a temp + fsync + rename + unlink the source. No
/// claude is running (`migrate` checked), so the brief two-copy window of the
/// fallback can't race a token refresh.
fn move_file(src: &Path, dst: &Path, rename: RenameFn) -> Result<()> {
    match rename(src, dst) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            let bytes = fs::read(src).with_context(|| format!("read {}", src.display()))?;
            let tmp = tmp_sibling(dst)?;
            if let Err(e) = write_new(&tmp, &bytes, 0o600).and_then(|_| {
                fs::rename(&tmp, dst)
                    .with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()))
            }) {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
            sync_parent(dst)?;
            fs::remove_file(src).with_context(|| format!("remove {}", src.display()))?;
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("move {} -> {}", src.display(), dst.display()));
        }
    }
    sync_parent(dst)?;
    sync_parent(src)
}

/// What [`move_once`] did.
#[derive(Debug, PartialEq, Eq)]
enum MoveOutcome {
    Moved,
    AlreadyThere,
    /// Both copies existed with identical bytes (an interrupted
    /// cross-filesystem move); the source was removed.
    FinishedInterrupted,
    NothingToMove,
}

/// The resumable step of `migrate`: move `src` into staging unless an
/// earlier, interrupted run already did.
fn move_once(src: &Path, dst: &Path, rename: RenameFn) -> Result<MoveOutcome> {
    match (lstat(src)?, lstat(dst)?) {
        (Some(s), _) if !s.is_file() => bail!(
            "{} is not a regular file; migrate only moves a real file",
            src.display()
        ),
        (Some(_), None) => move_file(src, dst, rename).map(|_| MoveOutcome::Moved),
        (None, Some(_)) => Ok(MoveOutcome::AlreadyThere),
        (None, None) => Ok(MoveOutcome::NothingToMove),
        (Some(_), Some(_)) => {
            if fs::read(src)? == fs::read(dst)? {
                fs::remove_file(src).with_context(|| format!("remove {}", src.display()))?;
                sync_parent(src)?;
                Ok(MoveOutcome::FinishedInterrupted)
            } else {
                bail!(
                    "both {} and {} exist and differ: a login probably ran after an \
                     interrupted migrate. Keep the live one by hand, remove the other, then \
                     re-run",
                    src.display(),
                    dst.display()
                )
            }
        }
    }
}

fn migrate(
    env: &Env,
    slot: &str,
    procs: &dyn ClaudeProcesses,
    rename: RenameFn,
    out: &mut dyn Write,
) -> Result<()> {
    let dest = env.new_store_slot(slot)?;
    if lstat(&dest)?.is_some() {
        bail!(
            "slot {slot:?} already exists at {}; migrate is one-time (`use {slot}` switches to it)",
            dest.display()
        );
    }
    let live = procs.live()?;
    if !live.is_empty() {
        let list: Vec<String> = live.iter().map(|l| format!("  {}  {}", l.pid, l.cmdline)).collect();
        bail!(
            "refusing to migrate while claude is running: a token refresh mid-move could \
             lose the account. Close these first, the daemon included:\n{}",
            list.join("\n")
        );
    }

    let src_creds = env.claude_home.join(CREDENTIALS_FILE);
    let staging = env.store.join(format!(".migrate-{slot}"));
    let staged_creds = staging.join(CREDENTIALS_FILE);
    let resuming = is_real_dir(&staging);
    // Pre-flight before creating anything: each source is absent or a real
    // file (a symlinked credential is not ours to move).
    for src in [&src_creds, &env.home_account] {
        if lstat(src)?.is_some_and(|m| !m.is_file()) {
            bail!("{} is not a regular file; migrate only moves a real file", src.display());
        }
    }
    if lstat(&src_creds)?.is_none() && !(resuming && lstat(&staged_creds)?.is_some()) {
        bail!(
            "no {} to migrate: log in with `claude auth login` first, or create an empty \
             slot with `softfig claude-login add {slot}`",
            src_creds.display()
        );
    }

    ensure_dir_mode(&env.store, 0o700)?;
    ensure_dir_mode(&staging, 0o700)?;
    let creds = move_once(&src_creds, &staged_creds, rename)?;
    let account = move_once(&env.home_account, &staging.join(ACCOUNT_FILE), rename)?;
    let linked = link_shared(&env.claude_home, &staging)?;
    sync_dir(&staging)?;
    fs::rename(&staging, &dest)
        .with_context(|| format!("rename {} -> {}", staging.display(), dest.display()))?;
    sync_dir(&env.store)?;
    set_active(&env.store, slot)?;

    if resuming {
        writeln!(out, "resumed an interrupted migrate of {slot}")?;
    }
    writeln!(out, "migrated the home account into slot {slot} at {}", dest.display())?;
    writeln!(out, "  .credentials.json: {creds:?}; .claude.json: {account:?}")?;
    writeln!(out, "  shared links: {}", linked.join(", "))?;
    writeln!(out, "active: {slot}")?;
    writeln!(
        out,
        "Plain `claude` now needs the shell shim (or `softfig claude-login run {slot} -- claude`)."
    )?;
    Ok(())
}

// ---- use / run / dir --------------------------------------------------------

fn use_slot(env: &Env, slot: &str, out: &mut dyn Write) -> Result<()> {
    let dir = env.existing(slot)?;
    let creds = credential_state(&env.config_dir(&dir))?;
    set_active(&env.store, slot)?;
    writeln!(
        out,
        "active: {slot}. New claude sessions use it; running ones keep their slot."
    )?;
    if creds != CredentialState::Ok {
        writeln!(
            out,
            "warning: slot {slot}'s credentials are {creds:?}; \
             run `softfig claude-login run {slot} -- claude auth login`"
        )?;
    }
    Ok(())
}

/// The `Command` for `run <slot> -- <argv…>`: only `CLAUDE_CONFIG_DIR`
/// changes (set for a store slot, removed for `home`). `HOME` is untouched.
fn run_command(env: &Env, slot: &str, argv: &[OsString]) -> Result<Command> {
    let dir = env.existing(slot)?;
    let (prog, args) = match argv.split_first() {
        Some((p, rest)) => (p.clone(), rest),
        None => (OsString::from("claude"), &[][..]),
    };
    let mut cmd = Command::new(prog);
    cmd.args(args);
    match dir.config_dir_env() {
        Some(p) => cmd.env(CONFIG_DIR_ENV, p),
        None => cmd.env_remove(CONFIG_DIR_ENV),
    };
    Ok(cmd)
}

fn dir(env: &Env, a: &DirArgs, out: &mut dyn Write) -> Result<()> {
    let d = match &a.slot {
        Some(slot) => env.existing(slot)?,
        None => {
            resolve_active(&env.store)
                .map_err(|e| anyhow!("{e} (see `softfig claude-login doctor`)"))?
                .1
        }
    };
    if let Some(p) = d.config_dir_env() {
        writeln!(out, "{}", p.display())?;
    }
    Ok(())
}

// ---- doctor -----------------------------------------------------------------

/// One problem `doctor` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    /// A dir or account file is open to group/other.
    LoosePerms { path: PathBuf, mode: u32, want: u32 },
    /// Claude replaced a Shared link with a real file or dir (rename-on-write).
    SharedReplaced { slot: String, name: &'static str },
    /// A Shared link points somewhere other than `~/.claude/<name>`.
    SharedRetargeted { slot: String, name: &'static str, target: PathBuf },
    /// A Shared link whose `~/.claude/<name>` source is gone.
    SharedDangling { slot: String, name: &'static str },
    /// `~/.claude/<name>` exists but the slot has no link to it.
    SharedMissing { slot: String, name: &'static str },
    /// A top-level name the slot layout doesn't classify.
    UnknownName { place: String, name: String },
    CredentialsMissing { slot: String },
    CredentialsNotRegular { slot: String },
    /// `.claude.json` is a symlink or another non-regular file.
    AccountNotRegular { slot: String },
    AccountUnreadable { slot: String, why: String },
    /// An allow-listed `.claude.json` field differs from the active slot's.
    AccountDrift { slot: String, active: String, detail: String },
    /// `<store>/active` does not resolve.
    ActiveBroken(String),
    /// Something in the store root that is neither a slot nor `active`.
    StrayStoreEntry { name: String, why: &'static str },
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Finding::*;
        match self {
            LoosePerms { path, mode, want } => {
                write!(f, "{} has mode {mode:o}; want {want:o} (chmod {want:o})", path.display())
            }
            SharedReplaced { slot, name } => write!(
                f,
                "slot {slot}: {name} is a real file, not the shared link (Claude rewrote it \
                 by rename). Merge it into ~/.claude/{name} by hand, then re-link"
            ),
            SharedRetargeted { slot, name, target } => write!(
                f,
                "slot {slot}: {name} links to {}, not ~/.claude/{name}",
                target.display()
            ),
            SharedDangling { slot, name } => {
                write!(f, "slot {slot}: {name} links to ~/.claude/{name}, which is gone")
            }
            SharedMissing { slot, name } => write!(
                f,
                "slot {slot}: no {name} link, but ~/.claude/{name} exists \
                 (ln -s ~/.claude/{name} into the slot)"
            ),
            UnknownName { place, name } => write!(
                f,
                "{place}: unclassified name {name:?} (new Claude Code state? \
                 classify it in slot_layout.rs)"
            ),
            CredentialsMissing { slot } => write!(
                f,
                "slot {slot}: no .credentials.json \
                 (softfig claude-login run {slot} -- claude auth login)"
            ),
            CredentialsNotRegular { slot } => write!(
                f,
                "slot {slot}: .credentials.json is not a regular file \
                 (Claude refuses symlinked credentials)"
            ),
            AccountNotRegular { slot } => {
                write!(f, "slot {slot}: .claude.json is not a regular file")
            }
            AccountUnreadable { slot, why } => write!(f, "slot {slot}: {why}"),
            AccountDrift { slot, active, detail } => {
                write!(f, "slot {slot} differs from active slot {active}: {detail}")
            }
            ActiveBroken(why) => write!(f, "{why}"),
            StrayStoreEntry { name, why } => write!(f, "store: {name:?} {why}"),
        }
    }
}

/// Perms check: a finding when `md` grants anything outside `want`.
fn check_mode(path: &Path, md: &fs::Metadata, want: u32, findings: &mut Vec<Finding>) {
    let mode = md.permissions().mode() & 0o777;
    if mode & !want != 0 {
        findings.push(Finding::LoosePerms { path: path.to_path_buf(), mode, want });
    }
}

/// Every top-level name in `dir` the layout doesn't know.
fn unknown_names(dir: &Path, place: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    let mut names: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| classify(n).is_none())
        .collect();
    names.sort();
    findings.extend(names.into_iter().map(|name| Finding::UnknownName {
        place: place.to_string(),
        name,
    }));
    Ok(())
}

fn check_credentials(
    slot: &str,
    config_dir: &Path,
    missing_is_a_problem: bool,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    match credential_state(config_dir)? {
        CredentialState::Ok => {}
        CredentialState::Missing if missing_is_a_problem => {
            findings.push(Finding::CredentialsMissing { slot: slot.into() })
        }
        CredentialState::Missing => {}
        CredentialState::NotRegular => {
            findings.push(Finding::CredentialsNotRegular { slot: slot.into() })
        }
        CredentialState::LoosePerms(mode) => findings.push(Finding::LoosePerms {
            path: config_dir.join(CREDENTIALS_FILE),
            mode,
            want: 0o600,
        }),
    }
    Ok(())
}

/// Lstat-check an account file; return its projection when readable.
fn check_account(slot: &str, path: &Path, findings: &mut Vec<Finding>) -> Result<Option<Value>> {
    let Some(md) = lstat(path)? else {
        return Ok(None);
    };
    if !md.is_file() {
        findings.push(Finding::AccountNotRegular { slot: slot.into() });
        return Ok(None);
    }
    check_mode(path, &md, 0o600, findings);
    match read_account(path) {
        Ok(v) => Ok(v.map(|v| seed_projection(&v))),
        Err(e) => {
            findings.push(Finding::AccountUnreadable { slot: slot.into(), why: e.to_string() });
            Ok(None)
        }
    }
}

fn check_shared_links(env: &Env, slot: &str, dir: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    for name in shared_names() {
        let src = env.claude_home.join(name);
        let dst = dir.join(name);
        let slot = slot.to_string();
        match lstat(&dst)? {
            None if src.exists() => findings.push(Finding::SharedMissing { slot, name }),
            None => {}
            Some(md) if md.file_type().is_symlink() => {
                let target = fs::read_link(&dst)?;
                if target != src {
                    findings.push(Finding::SharedRetargeted { slot, name, target });
                } else if !dst.exists() {
                    findings.push(Finding::SharedDangling { slot, name });
                }
            }
            Some(_) => findings.push(Finding::SharedReplaced { slot, name }),
        }
    }
    Ok(())
}

/// Allow-listed differences between two account projections, one line each.
fn account_drift(active: &Value, other: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let empty = Map::new();
    let obj = |v: &Value, k: &str| -> Map<String, Value> {
        v.get(k).and_then(Value::as_object).cloned().unwrap_or_default()
    };

    let (a_mcp, o_mcp) = (obj(active, "mcpServers"), obj(other, "mcpServers"));
    let only = |x: &Map<String, Value>, y: &Map<String, Value>| -> Vec<String> {
        x.keys().filter(|k| !y.contains_key(*k)).cloned().collect()
    };
    let only_active = only(&a_mcp, &o_mcp);
    let only_other = only(&o_mcp, &a_mcp);
    let differ: Vec<String> = a_mcp
        .iter()
        .filter(|(k, v)| o_mcp.get(*k).is_some_and(|ov| ov != *v))
        .map(|(k, _)| k.clone())
        .collect();
    if !only_active.is_empty() {
        lines.push(format!("MCP servers missing here: {}", only_active.join(", ")));
    }
    if !only_other.is_empty() {
        lines.push(format!("MCP servers only here: {}", only_other.join(", ")));
    }
    if !differ.is_empty() {
        lines.push(format!("MCP servers configured differently: {}", differ.join(", ")));
    }
    if active.get("hasCompletedOnboarding") != other.get("hasCompletedOnboarding") {
        lines.push("hasCompletedOnboarding differs".into());
    }

    let (a_proj, o_proj) = (obj(active, "projects"), obj(other, "projects"));
    let trusted = |p: Option<&Value>| {
        p.and_then(|p| p.get("hasTrustDialogAccepted")).and_then(Value::as_bool) == Some(true)
    };
    let mut trust_lost = Vec::new();
    let mut trust_extra = Vec::new();
    let mut settings = Vec::new();
    for path in a_proj.keys().chain(o_proj.keys().filter(|k| !a_proj.contains_key(*k))) {
        let (a, o) = (a_proj.get(path), o_proj.get(path));
        match (trusted(a), trusted(o)) {
            (true, false) => trust_lost.push(path.clone()),
            (false, true) => trust_extra.push(path.clone()),
            _ => {}
        }
        let strip = |p: Option<&Value>| -> Map<String, Value> {
            let mut m = p.and_then(Value::as_object).unwrap_or(&empty).clone();
            m.remove("hasTrustDialogAccepted");
            m
        };
        if strip(a) != strip(o) {
            settings.push(path.clone());
        }
    }
    let sample = |v: &[String]| v.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if !trust_lost.is_empty() {
        lines.push(format!(
            "{} project(s) trusted in the active slot but not here (e.g. {})",
            trust_lost.len(),
            sample(&trust_lost)
        ));
    }
    if !trust_extra.is_empty() {
        lines.push(format!(
            "{} project(s) trusted here but not in the active slot (e.g. {})",
            trust_extra.len(),
            sample(&trust_extra)
        ));
    }
    if !settings.is_empty() {
        lines.push(format!(
            "per-project MCP/tool settings differ for {} project(s) (e.g. {})",
            settings.len(),
            sample(&settings)
        ));
    }
    lines
}

/// The read-only health check behind `doctor`.
fn diagnose(env: &Env) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if let Some(md) = lstat(&env.store)? {
        check_mode(&env.store, &md, 0o700, &mut findings);
    }
    let active = match resolve_active(&env.store) {
        Ok((name, _)) => Some(name),
        Err(e) => {
            findings.push(Finding::ActiveBroken(e.to_string()));
            None
        }
    };

    // The store root holds slots, `active`, and Claude's legacy `<slot>.lock`
    // dirs. Anything else is a leftover worth a look.
    if let Ok(rd) = fs::read_dir(&env.store) {
        let slots = store_slots(&env.store)?;
        let mut names: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let why = if name == ACTIVE_LINK || slots.contains(&name) || name.ends_with(".lock") {
                continue;
            } else if name.starts_with(".migrate-") {
                "is an interrupted migrate (re-run `migrate` to finish it)"
            } else if name.starts_with(".add-") {
                "is an interrupted add (holds no credential; inspect and remove it)"
            } else if name == HOME_SLOT {
                "is shadowed by the reserved slot `home`"
            } else {
                "is not a slot directory"
            };
            findings.push(Finding::StrayStoreEntry { name, why });
        }
    }

    // home: the shared dir itself. Its credentials matter only while it is
    // the active slot (after `migrate` it has none, by design).
    unknown_names(&env.claude_home, "~/.claude", &mut findings)?;
    let home_active = active.as_deref() == Some(HOME_SLOT);
    check_credentials(HOME_SLOT, &env.claude_home, home_active, &mut findings)?;
    let mut projections: Vec<(String, Value)> = Vec::new();
    if let Some(p) = check_account(HOME_SLOT, &env.home_account, &mut findings)? {
        projections.push((HOME_SLOT.into(), p));
    }

    for slot in store_slots(&env.store)? {
        let dir = env.store.join(&slot);
        if let Some(md) = lstat(&dir)? {
            check_mode(&dir, &md, 0o700, &mut findings);
        }
        check_credentials(&slot, &dir, true, &mut findings)?;
        if let Some(p) = check_account(&slot, &dir.join(ACCOUNT_FILE), &mut findings)? {
            projections.push((slot.clone(), p));
        }
        check_shared_links(env, &slot, &dir, &mut findings)?;
        unknown_names(&dir, &format!("slot {slot}"), &mut findings)?;
    }

    if let Some(active) = &active
        && let Some((_, reference)) = projections.iter().find(|(s, _)| s == active)
    {
        for (slot, p) in projections.iter().filter(|(s, _)| s != active) {
            for detail in account_drift(reference, p) {
                findings.push(Finding::AccountDrift {
                    slot: slot.clone(),
                    active: active.clone(),
                    detail,
                });
            }
        }
    }
    Ok(findings)
}

fn doctor(env: &Env, out: &mut dyn Write) -> Result<()> {
    let findings = diagnose(env)?;
    if findings.is_empty() {
        writeln!(out, "ok: the store, every slot and ~/.claude look healthy")?;
        return Ok(());
    }
    for f in &findings {
        writeln!(out, "- {f}")?;
    }
    bail!("doctor found {} problem(s)", findings.len())
}

// ---- status -----------------------------------------------------------------

fn status(env: &Env, out: &mut dyn Write) -> Result<()> {
    list(env, out)?;
    writeln!(out)?;
    let growlight = softfig_growlightd::fleet::runtime_growlight_dir();
    print_profile_headroom(env, &growlight.join("usage.by-profile"), out)?;
    writeln!(out)?;
    writeln!(out, "per-member profile pins:")?;
    print_member_pins(&growlight.join("agents"), out)
}

/// Per-slot 5h headroom from the budget-aware picker's samples (slice 004).
/// The read is the same pure
/// [`softfig_growlightd::profile_budget::headroom_from`] the picker calls, so
/// what this prints is what the next spawn's pick sees.
fn print_profile_headroom(env: &Env, by_profile_dir: &Path, out: &mut dyn Write) -> Result<()> {
    use softfig_growlightd::profile_budget::{headroom_from, read_profile_budget};

    writeln!(out, "budget headroom (5h window, from usage.by-profile/):")?;
    let now = unix_now_seconds();
    let rows = slot_rows(env)?;
    let width = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for row in rows {
        let snap = read_profile_budget(by_profile_dir, &row.name);
        let hr = headroom_from(snap.as_ref(), now);
        let last_seen = snap
            .as_ref()
            .map(|s| format_age(now, s.ts as i64))
            .unwrap_or_else(|| "never".to_string());
        writeln!(
            out,
            "  {:<width$}  headroom {:>3}%   last-seen {last_seen}{}",
            row.name,
            hr.pct,
            flag_for_headroom(&hr)
        )?;
    }
    Ok(())
}

/// `(WARN)` below the picker's warn threshold, `(STALL)` at or below its
/// stall floor; the same constants the picker uses, so the label never
/// drifts from what the picker does.
fn flag_for_headroom(hr: &softfig_growlightd::profile_budget::Headroom) -> &'static str {
    use softfig_growlightd::profile_pin::{HEADROOM_STALL_PCT, HEADROOM_WARN_PCT};
    if hr.pct <= HEADROOM_STALL_PCT {
        "   (STALL)"
    } else if hr.pct < HEADROOM_WARN_PCT {
        "   (WARN)"
    } else {
        ""
    }
}

/// A timestamp's age as a short string, or `never` for the epoch
/// (default-constructed), which the picker also treats as "no reading".
fn format_age(now: i64, ts: i64) -> String {
    if ts <= 0 {
        return "never".into();
    }
    let secs = now.saturating_sub(ts).max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3_600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3_600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

fn unix_now_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Each fleet member's current profile pin. A member with no pin follows the
/// active slot (or `home`).
fn print_member_pins(agents_dir: &Path, out: &mut dyn Write) -> Result<()> {
    use softfig_growlightd::profile_pin::{pin_paths, read_pin};

    let mut members: Vec<String> = fs::read_dir(agents_dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    members.sort();
    if members.is_empty() {
        writeln!(out, "  (no fleet members under {})", agents_dir.display())?;
        return Ok(());
    }
    for m in members {
        match read_pin(&pin_paths(agents_dir, &m)) {
            Some(p) => writeln!(
                out,
                "  {m}: {} (picked_at={}, session={})",
                p.profile, p.picked_at, p.session_id
            )?,
            None => writeln!(out, "  {m}: unpinned (follows the active slot)")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use tempfile::TempDir;

    /// A fake credential bundle. Never a real token.
    const FAKE_CREDS: &str = r#"{"claudeAiOauth":{"accessToken":"fake-a","refreshToken":"fake-r","expiresAt":0,"scopes":[],"subscriptionType":"pro"}}"#;

    /// A tempdir HOME with a "shared" `~/.claude/` and a store under it.
    struct Fixture {
        _td: TempDir,
        home: PathBuf,
        env: Env,
    }

    impl Fixture {
        fn new() -> Self {
            let td = TempDir::new().unwrap();
            let home = td.path().to_path_buf();
            let env = Env::rooted(&home, home.join(".local/share/softfig/claude-profiles"));
            fs::create_dir_all(&env.claude_home).unwrap();
            for f in ["settings.json", "CLAUDE.md", "statusline-command.sh"] {
                fs::write(env.claude_home.join(f), "x").unwrap();
            }
            for d in ["skills", "plugins", "projects", "sessions"] {
                fs::create_dir(env.claude_home.join(d)).unwrap();
            }
            Self { _td: td, home, env }
        }

        /// Log the home slot in: fake credentials + an account file.
        fn home_logged_in(&self, account: &Value) {
            write_new(&self.env.claude_home.join(CREDENTIALS_FILE), FAKE_CREDS.as_bytes(), 0o600)
                .unwrap();
            write_new(&self.env.home_account, account.to_string().as_bytes(), 0o600).unwrap();
        }

        fn slot(&self, name: &str) -> PathBuf {
            self.env.store.join(name)
        }

        /// A healthy, logged-in store slot built the supported way.
        fn add_logged_in(&self, name: &str) -> PathBuf {
            let dir = add(&self.env, name, Some(HOME_SLOT), &mut Vec::new()).unwrap();
            write_new(&dir.join(CREDENTIALS_FILE), FAKE_CREDS.as_bytes(), 0o600).unwrap();
            dir
        }
    }

    fn account_fixture() -> Value {
        serde_json::json!({
            "oauthAccount": {"emailAddress": "a@example.com", "accountUuid": "u"},
            "userID": "deadbeef",
            "cachedGrowthBookFeatures": {"f": 1},
            "statsigCache": {"x": 1},
            "hasCompletedOnboarding": true,
            "numStartups": 42,
            "mcpServers": {"softfig-mcp": {"command": "softfig-mcp"}},
            "projects": {
                "/w/one": {
                    "hasTrustDialogAccepted": true,
                    "allowedTools": ["Bash"],
                    "mcpServers": {},
                    "lastCost": 1.5,
                    "exampleFiles": ["a.rs"]
                },
                "/w/two": {"lastSessionId": "s"}
            }
        })
    }

    struct NoClaude;
    impl ClaudeProcesses for NoClaude {
        fn live(&self) -> Result<Vec<LiveClaude>> {
            Ok(Vec::new())
        }
    }

    struct SomeClaude;
    impl ClaudeProcesses for SomeClaude {
        fn live(&self) -> Result<Vec<LiveClaude>> {
            Ok(vec![LiveClaude { pid: 4242, cmdline: "claude daemon run".into() }])
        }
    }

    fn cross_device(_: &Path, _: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::CrossesDevices))
    }

    fn mode_of(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn names_in(dir: &Path) -> BTreeSet<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    // ---- add ----

    #[test]
    fn add_builds_layout_links_and_perms() {
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        let dir = add(&fx.env, "slot2", None, &mut Vec::new()).unwrap();

        assert_eq!(dir, fx.slot("slot2"));
        assert_eq!(mode_of(&fx.env.store), 0o700);
        assert_eq!(mode_of(&dir), 0o700);
        for name in ["settings.json", "CLAUDE.md", "statusline-command.sh", "skills", "plugins", "projects"] {
            let link = dir.join(name);
            assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "{name}");
            assert_eq!(fs::read_link(&link).unwrap(), fx.env.claude_home.join(name), "{name}");
        }
        // Shared names with no source are not linked; per-slot names are
        // Claude's to create; credentials come only from `auth login`.
        for absent in ["agents", "commands", "keybindings.json", "sessions", CREDENTIALS_FILE] {
            assert!(lstat(&dir.join(absent)).unwrap().is_none(), "{absent}");
        }
        assert_eq!(mode_of(&dir.join(ACCOUNT_FILE)), 0o600);
        assert_eq!(
            names_in(&fx.env.store),
            BTreeSet::from(["slot2".to_string()]),
            "no staging leftovers",
        );
    }

    #[test]
    fn add_seeds_exactly_the_allow_list() {
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        let dir = add(&fx.env, "slot2", Some(HOME_SLOT), &mut Vec::new()).unwrap();
        let seeded: Value =
            serde_json::from_slice(&fs::read(dir.join(ACCOUNT_FILE)).unwrap()).unwrap();
        assert_eq!(
            seeded,
            serde_json::json!({
                "hasCompletedOnboarding": true,
                "mcpServers": {"softfig-mcp": {"command": "softfig-mcp"}},
                "projects": {
                    "/w/one": {
                        "hasTrustDialogAccepted": true,
                        "allowedTools": ["Bash"],
                        "mcpServers": {}
                    }
                }
            })
        );
        let text = fs::read_to_string(dir.join(ACCOUNT_FILE)).unwrap();
        for leaked in ["oauthAccount", "userID", "cachedGrowthBookFeatures", "statsigCache", "a@example.com"] {
            assert!(!text.contains(leaked), "{leaked} must not cross slots");
        }
    }

    #[test]
    fn add_with_no_source_account_seeds_nothing() {
        let fx = Fixture::new();
        let dir = add(&fx.env, "slot2", None, &mut Vec::new()).unwrap();
        assert!(lstat(&dir.join(ACCOUNT_FILE)).unwrap().is_none());
    }

    #[test]
    fn add_refuses_home_existing_bad_and_missing_source() {
        let fx = Fixture::new();
        assert!(add(&fx.env, HOME_SLOT, None, &mut Vec::new()).is_err());
        assert!(add(&fx.env, "../x", None, &mut Vec::new()).is_err());
        assert!(add(&fx.env, "x.lock", None, &mut Vec::new()).is_err());
        assert!(add(&fx.env, "slot3", Some("ghost"), &mut Vec::new()).is_err());
        add(&fx.env, "slot2", None, &mut Vec::new()).unwrap();
        let err = add(&fx.env, "slot2", None, &mut Vec::new()).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
    }

    #[test]
    fn add_no_login_never_launches_and_login_runs_in_the_slot() {
        let fx = Fixture::new();
        let mut launched: Vec<Command> = Vec::new();
        let a = AddArgs { slot: "slot2".into(), from: None, no_login: true };
        add_then_login(&fx.env, &a, &mut Vec::new(), &mut |c| {
            launched.push(c);
            Ok(ExitStatus::default())
        })
        .unwrap();
        assert!(launched.is_empty(), "--no-login must not launch claude");

        let a = AddArgs { slot: "slot3".into(), from: None, no_login: false };
        add_then_login(&fx.env, &a, &mut Vec::new(), &mut |c| {
            launched.push(c);
            Ok(ExitStatus::default())
        })
        .unwrap();
        let [c] = &launched[..] else { panic!("one launch") };
        assert_eq!(c.get_program(), "claude");
        assert_eq!(c.get_args().collect::<Vec<_>>(), ["auth", "login"]);
        let envs: Vec<_> = c.get_envs().collect();
        assert_eq!(envs, [(OsStr::new(CONFIG_DIR_ENV), Some(fx.slot("slot3").as_os_str()))]);
    }

    // ---- migrate ----

    #[test]
    fn migrate_moves_not_copies() {
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        let creds = fx.env.claude_home.join(CREDENTIALS_FILE);
        let (creds_ino, account_ino) =
            (fs::metadata(&creds).unwrap().ino(), fs::metadata(&fx.env.home_account).unwrap().ino());

        migrate(&fx.env, "slot1", &NoClaude, rename_file, &mut Vec::new()).unwrap();

        let dir = fx.slot("slot1");
        assert!(lstat(&creds).unwrap().is_none(), "source credential is gone");
        assert!(lstat(&fx.env.home_account).unwrap().is_none(), "source account file is gone");
        assert_eq!(fs::metadata(dir.join(CREDENTIALS_FILE)).unwrap().ino(), creds_ino);
        assert_eq!(fs::metadata(dir.join(ACCOUNT_FILE)).unwrap().ino(), account_ino);
        assert_eq!(fs::read_to_string(dir.join(CREDENTIALS_FILE)).unwrap(), FAKE_CREDS);
        assert_eq!(fs::read_link(dir.join("projects")).unwrap(), fx.env.claude_home.join("projects"));
        assert_eq!(read_active(&fx.env.store).unwrap(), "slot1");
        assert_eq!(names_in(&fx.env.store), BTreeSet::from(["active".into(), "slot1".into()]));
    }

    #[test]
    fn migrate_refuses_with_a_live_claude_and_moves_nothing() {
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        let err = migrate(&fx.env, "slot1", &SomeClaude, rename_file, &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("4242") && err.contains("claude daemon run"), "{err}");
        assert!(fx.env.claude_home.join(CREDENTIALS_FILE).is_file());
        assert!(fx.env.home_account.is_file());
        assert!(lstat(&fx.env.store).unwrap().is_none(), "no store, no staging");
    }

    #[test]
    fn migrate_refuses_an_existing_slot_home_and_nothing_to_move() {
        let fx = Fixture::new();
        let err = migrate(&fx.env, "slot1", &NoClaude, rename_file, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("no "), "{err}");
        fx.home_logged_in(&account_fixture());
        assert!(migrate(&fx.env, HOME_SLOT, &NoClaude, rename_file, &mut Vec::new()).is_err());
        fs::create_dir_all(fx.slot("slot1")).unwrap();
        let err = migrate(&fx.env, "slot1", &NoClaude, rename_file, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert!(fx.env.claude_home.join(CREDENTIALS_FILE).is_file(), "untouched");
    }

    #[test]
    fn migrate_refuses_a_symlinked_credential() {
        let fx = Fixture::new();
        fs::write(fx.home.join("elsewhere.json"), FAKE_CREDS).unwrap();
        symlink(fx.home.join("elsewhere.json"), fx.env.claude_home.join(CREDENTIALS_FILE)).unwrap();
        let err = migrate(&fx.env, "slot1", &NoClaude, rename_file, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert!(lstat(&fx.slot("slot1")).unwrap().is_none());
    }

    #[test]
    fn migrate_resumes_after_an_interruption() {
        // Interrupted after the credential moved into staging but before the
        // account file did: the re-run finishes without moving it twice.
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        let staging = fx.env.store.join(".migrate-slot1");
        ensure_dir_mode(&fx.env.store, 0o700).unwrap();
        ensure_dir_mode(&staging, 0o700).unwrap();
        fs::rename(fx.env.claude_home.join(CREDENTIALS_FILE), staging.join(CREDENTIALS_FILE)).unwrap();

        let mut out = Vec::new();
        migrate(&fx.env, "slot1", &NoClaude, rename_file, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("resumed"), "{out}");
        assert!(out.contains(".credentials.json: AlreadyThere; .claude.json: Moved"), "{out}");
        assert!(fx.slot("slot1").join(CREDENTIALS_FILE).is_file());
        assert!(fx.slot("slot1").join(ACCOUNT_FILE).is_file());
        assert!(lstat(&staging).unwrap().is_none());
        assert_eq!(read_active(&fx.env.store).unwrap(), "slot1");
    }

    #[test]
    fn migrate_finishes_an_interrupted_copy_and_refuses_diverged_copies() {
        // Same bytes in both places: an interrupted cross-device move.
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        let staging = fx.env.store.join(".migrate-slot1");
        ensure_dir_mode(&fx.env.store, 0o700).unwrap();
        ensure_dir_mode(&staging, 0o700).unwrap();
        write_new(&staging.join(CREDENTIALS_FILE), FAKE_CREDS.as_bytes(), 0o600).unwrap();
        migrate(&fx.env, "slot1", &NoClaude, rename_file, &mut Vec::new()).unwrap();
        assert!(lstat(&fx.env.claude_home.join(CREDENTIALS_FILE)).unwrap().is_none());
        assert_eq!(fs::read_to_string(fx.slot("slot1").join(CREDENTIALS_FILE)).unwrap(), FAKE_CREDS);

        // Different bytes: a login happened after the interruption. Refuse,
        // and keep both.
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        let staging = fx.env.store.join(".migrate-slot1");
        ensure_dir_mode(&fx.env.store, 0o700).unwrap();
        ensure_dir_mode(&staging, 0o700).unwrap();
        write_new(&staging.join(CREDENTIALS_FILE), b"{\"older\":1}", 0o600).unwrap();
        let err = migrate(&fx.env, "slot1", &NoClaude, rename_file, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("differ"), "{err}");
        assert!(fx.env.claude_home.join(CREDENTIALS_FILE).is_file());
        assert!(staging.join(CREDENTIALS_FILE).is_file());
        assert!(lstat(&fx.slot("slot1")).unwrap().is_none());
    }

    #[test]
    fn migrate_falls_back_to_copy_across_filesystems_without_leaving_two_copies() {
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        migrate(&fx.env, "slot1", &NoClaude, cross_device, &mut Vec::new()).unwrap();
        let dir = fx.slot("slot1");
        assert!(lstat(&fx.env.claude_home.join(CREDENTIALS_FILE)).unwrap().is_none());
        assert!(lstat(&fx.env.home_account).unwrap().is_none());
        assert_eq!(fs::read_to_string(dir.join(CREDENTIALS_FILE)).unwrap(), FAKE_CREDS);
        assert_eq!(mode_of(&dir.join(CREDENTIALS_FILE)), 0o600);
        assert!(!names_in(&dir).iter().any(|n| n.contains(".tmp.")), "no temp left behind");
    }

    // ---- use / dir / run ----

    #[test]
    fn use_swaps_the_pointer_and_dir_active_follows() {
        let fx = Fixture::new();
        let dir_active = || {
            let mut out = Vec::new();
            dir(&fx.env, &DirArgs { slot: None, active: true }, &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        assert_eq!(dir_active(), "", "no store yet: home, prints nothing");

        fx.add_logged_in("slot2");
        use_slot(&fx.env, "slot2", &mut Vec::new()).unwrap();
        assert_eq!(fs::read_link(fx.env.store.join(ACTIVE_LINK)).unwrap(), Path::new("slot2"));
        assert_eq!(dir_active(), format!("{}\n", fx.slot("slot2").display()));

        use_slot(&fx.env, HOME_SLOT, &mut Vec::new()).unwrap();
        assert!(lstat(&fx.env.store.join(ACTIVE_LINK)).unwrap().is_none());
        assert_eq!(dir_active(), "");
        assert!(!names_in(&fx.env.store).iter().any(|n| n.contains(".tmp.")));
    }

    #[test]
    fn use_and_dir_refuse_a_missing_slot_and_a_broken_pointer() {
        let fx = Fixture::new();
        assert!(use_slot(&fx.env, "ghost", &mut Vec::new()).is_err());
        assert!(dir(&fx.env, &DirArgs { slot: Some("ghost".into()), active: false }, &mut Vec::new()).is_err());
        ensure_dir_mode(&fx.env.store, 0o700).unwrap();
        symlink("ghost", fx.env.store.join(ACTIVE_LINK)).unwrap();
        assert!(dir(&fx.env, &DirArgs { slot: None, active: true }, &mut Vec::new()).is_err());
    }

    #[test]
    fn dir_prints_a_slot_or_nothing_for_home() {
        let fx = Fixture::new();
        fx.add_logged_in("slot2");
        let mut out = Vec::new();
        dir(&fx.env, &DirArgs { slot: Some("slot2".into()), active: false }, &mut out).unwrap();
        dir(&fx.env, &DirArgs { slot: Some(HOME_SLOT.into()), active: false }, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("{}\n", fx.slot("slot2").display()));
    }

    #[test]
    fn run_sets_only_claude_config_dir_and_never_home() {
        let fx = Fixture::new();
        fx.add_logged_in("slot2");
        let argv = ["claude", "--version"].map(OsString::from);
        let c = run_command(&fx.env, "slot2", &argv).unwrap();
        assert_eq!(c.get_program(), "claude");
        assert_eq!(c.get_args().collect::<Vec<_>>(), ["--version"]);
        let envs: Vec<_> = c.get_envs().collect();
        assert_eq!(envs, [(OsStr::new(CONFIG_DIR_ENV), Some(fx.slot("slot2").as_os_str()))]);

        let c = run_command(&fx.env, HOME_SLOT, &[]).unwrap();
        assert_eq!(c.get_program(), "claude", "argv defaults to claude");
        let envs: Vec<_> = c.get_envs().collect();
        assert_eq!(envs, [(OsStr::new(CONFIG_DIR_ENV), None)], "home unsets, never sets HOME");

        assert!(run_command(&fx.env, "ghost", &argv).is_err(), "fails closed on a missing slot");
    }

    // ---- list ----

    #[test]
    fn list_shows_each_slot_email_and_the_active_marker() {
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        let dir = fx.add_logged_in("slot2");
        fs::write(dir.join(ACCOUNT_FILE), r#"{"oauthAccount":{"emailAddress":"b@example.com"}}"#).unwrap();
        add(&fx.env, "slot3", None, &mut Vec::new()).unwrap();
        use_slot(&fx.env, "slot2", &mut Vec::new()).unwrap();

        let mut out = Vec::new();
        list(&fx.env, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = out.lines().skip(1).collect();
        assert_eq!(
            lines,
            ["  home   a@example.com", "* slot2  b@example.com", "  slot3  (logged out)"],
            "{out}"
        );
    }

    // ---- doctor ----

    fn doctor_findings(fx: &Fixture) -> Vec<Finding> {
        diagnose(&fx.env).unwrap()
    }

    /// A healthy migrated store: slot1 active, slot2 added from it.
    fn healthy() -> Fixture {
        let fx = Fixture::new();
        fx.home_logged_in(&account_fixture());
        migrate(&fx.env, "slot1", &NoClaude, rename_file, &mut Vec::new()).unwrap();
        let d = add(&fx.env, "slot2", None, &mut Vec::new()).unwrap();
        write_new(&d.join(CREDENTIALS_FILE), FAKE_CREDS.as_bytes(), 0o600).unwrap();
        fx
    }

    #[test]
    fn doctor_is_quiet_on_a_healthy_store() {
        let fx = healthy();
        let f = doctor_findings(&fx);
        assert!(f.is_empty(), "{f:?}");
        doctor(&fx.env, &mut Vec::new()).unwrap();
    }

    #[test]
    fn doctor_flags_a_shared_link_claude_replaced() {
        let fx = healthy();
        let link = fx.slot("slot2").join("settings.json");
        fs::remove_file(&link).unwrap();
        fs::write(&link, "{}").unwrap();
        assert_eq!(
            doctor_findings(&fx),
            [Finding::SharedReplaced { slot: "slot2".into(), name: "settings.json" }]
        );
        assert!(doctor(&fx.env, &mut Vec::new()).is_err(), "non-zero exit on a finding");
    }

    #[test]
    fn doctor_flags_retargeted_dangling_and_missing_links() {
        let fx = healthy();
        let d = fx.slot("slot2");
        fs::remove_file(d.join("CLAUDE.md")).unwrap();
        symlink("/elsewhere/CLAUDE.md", d.join("CLAUDE.md")).unwrap();
        fs::remove_dir(fx.env.claude_home.join("plugins")).unwrap();
        fs::remove_file(d.join("statusline-command.sh")).unwrap();
        let f = doctor_findings(&fx);
        assert!(f.contains(&Finding::SharedRetargeted {
            slot: "slot2".into(),
            name: "CLAUDE.md",
            target: "/elsewhere/CLAUDE.md".into()
        }), "{f:?}");
        assert!(f.contains(&Finding::SharedDangling { slot: "slot1".into(), name: "plugins" }), "{f:?}");
        assert!(f.contains(&Finding::SharedMissing { slot: "slot2".into(), name: "statusline-command.sh" }), "{f:?}");
    }

    #[test]
    fn doctor_runtime_inventory_reports_unknown_names() {
        let fx = healthy();
        fs::create_dir(fx.env.claude_home.join("brand-new-state")).unwrap();
        fs::write(fx.slot("slot1").join("mystery.json"), "{}").unwrap();
        // Known per-slot state Claude creates is not noise.
        fs::create_dir(fx.slot("slot1").join("sessions")).unwrap();
        assert_eq!(
            doctor_findings(&fx),
            [
                Finding::UnknownName { place: "~/.claude".into(), name: "brand-new-state".into() },
                Finding::UnknownName { place: "slot slot1".into(), name: "mystery.json".into() },
            ]
        );
    }

    #[test]
    fn doctor_flags_loose_perms() {
        let fx = healthy();
        let chmod = |p: PathBuf, m| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
        chmod(fx.env.store.clone(), 0o755);
        chmod(fx.slot("slot2"), 0o750);
        chmod(fx.slot("slot2").join(CREDENTIALS_FILE), 0o644);
        chmod(fx.slot("slot1").join(ACCOUNT_FILE), 0o640);
        let f = doctor_findings(&fx);
        let loose: BTreeSet<(PathBuf, u32)> = f
            .iter()
            .filter_map(|x| match x {
                Finding::LoosePerms { path, mode, .. } => Some((path.clone(), *mode)),
                _ => None,
            })
            .collect();
        assert_eq!(
            loose,
            BTreeSet::from([
                (fx.env.store.clone(), 0o755),
                (fx.slot("slot2"), 0o750),
                (fx.slot("slot2").join(CREDENTIALS_FILE), 0o644),
                (fx.slot("slot1").join(ACCOUNT_FILE), 0o640),
            ])
        );
        assert_eq!(f.len(), 4, "{f:?}");
    }

    #[test]
    fn doctor_flags_missing_and_non_regular_credentials() {
        let fx = healthy();
        fs::remove_file(fx.slot("slot2").join(CREDENTIALS_FILE)).unwrap();
        let c1 = fx.slot("slot1").join(CREDENTIALS_FILE);
        fs::rename(&c1, fx.home.join("moved.json")).unwrap();
        symlink(fx.home.join("moved.json"), &c1).unwrap();
        assert_eq!(
            doctor_findings(&fx),
            [
                Finding::CredentialsNotRegular { slot: "slot1".into() },
                Finding::CredentialsMissing { slot: "slot2".into() },
            ]
        );
    }

    #[test]
    fn doctor_reports_home_credentials_only_while_home_is_active() {
        let fx = Fixture::new();
        assert_eq!(doctor_findings(&fx), [Finding::CredentialsMissing { slot: HOME_SLOT.into() }]);
        let fx = healthy();
        let f = doctor_findings(&fx);
        assert!(f.is_empty(), "a migrated home has no credentials by design: {f:?}");
    }

    #[test]
    fn doctor_reports_account_drift_against_the_active_slot() {
        let fx = healthy();
        let p = fx.slot("slot2").join(ACCOUNT_FILE);
        let mut v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        v["mcpServers"] = serde_json::json!({"other": {"command": "x"}});
        v["projects"]["/w/one"]["hasTrustDialogAccepted"] = Value::Bool(false);
        fs::write(&p, v.to_string()).unwrap();
        let details: Vec<String> = doctor_findings(&fx)
            .into_iter()
            .map(|f| match f {
                Finding::AccountDrift { slot, active, detail } => {
                    assert_eq!((slot.as_str(), active.as_str()), ("slot2", "slot1"));
                    detail
                }
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(
            details,
            [
                "MCP servers missing here: softfig-mcp",
                "MCP servers only here: other",
                "1 project(s) trusted in the active slot but not here (e.g. /w/one)",
            ]
        );
    }

    #[test]
    fn doctor_flags_an_active_pointer_that_does_not_resolve() {
        let fx = healthy();
        fs::remove_file(fx.env.store.join(ACTIVE_LINK)).unwrap();
        symlink("ghost", fx.env.store.join(ACTIVE_LINK)).unwrap();
        let f = doctor_findings(&fx);
        assert!(matches!(&f[..], [Finding::ActiveBroken(why)] if why.contains("ghost")), "{f:?}");
    }

    #[test]
    fn doctor_flags_stray_store_entries_and_ignores_claude_lock_dirs() {
        let fx = healthy();
        fs::create_dir(fx.env.store.join(".migrate-slot3")).unwrap();
        fs::create_dir(fx.env.store.join(HOME_SLOT)).unwrap();
        fs::create_dir(fx.env.store.join("slot1.lock")).unwrap();
        fs::write(fx.env.store.join("notes.txt"), "").unwrap();
        let strays: Vec<String> = doctor_findings(&fx)
            .into_iter()
            .map(|f| match f {
                Finding::StrayStoreEntry { name, .. } => name,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(strays, [".migrate-slot3", "home", "notes.txt"]);
    }

    // ---- clap surface ----

    #[derive(clap::Parser, Debug)]
    struct Cli {
        #[command(subcommand)]
        cmd: ClaudeLoginCmd,
    }

    fn parse(args: &[&str]) -> Result<ClaudeLoginCmd, clap::Error> {
        use clap::Parser;
        Cli::try_parse_from(std::iter::once("claude-login").chain(args.iter().copied()))
            .map(|c| c.cmd)
    }

    #[test]
    fn dir_takes_exactly_one_of_a_slot_or_active() {
        assert!(matches!(parse(&["dir", "--active"]), Ok(ClaudeLoginCmd::Dir(DirArgs { slot: None, active: true }))));
        assert!(matches!(parse(&["dir", "slot2"]), Ok(ClaudeLoginCmd::Dir(DirArgs { slot: Some(_), active: false }))));
        assert!(parse(&["dir"]).is_err());
        assert!(parse(&["dir", "slot2", "--active"]).is_err());
    }

    #[test]
    fn run_passes_everything_after_the_separator_through() {
        let Ok(ClaudeLoginCmd::Run(a)) = parse(&["run", "slot2", "--", "claude", "--resume", "-p"]) else {
            panic!("run should parse");
        };
        assert_eq!(a.slot, "slot2");
        assert_eq!(a.argv, ["claude", "--resume", "-p"].map(OsString::from));
        let Ok(ClaudeLoginCmd::Run(a)) = parse(&["run", "home"]) else { panic!() };
        assert!(a.argv.is_empty());
    }

    // ---- process probe ----

    #[test]
    fn proc_scan_finds_every_shape_of_claude_but_not_itself() {
        let td = TempDir::new().unwrap();
        let root = td.path();
        let proc = |pid: u32, argv: &[&str], exe: Option<&str>| {
            let d = root.join(pid.to_string());
            fs::create_dir(&d).unwrap();
            fs::write(d.join("cmdline"), argv.join("\0") + "\0").unwrap();
            if let Some(e) = exe {
                symlink(e, d.join("exe")).unwrap();
            }
        };
        proc(10, &["/home/u/.local/bin/claude", "daemon", "run"], None);
        proc(11, &["2.1.308", "--resume", "x"], Some("/home/u/.local/share/claude/versions/2.1.308"));
        proc(12, &["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"], None);
        proc(13, &["bash"], Some("/usr/bin/bash"));
        proc(14, &["claude"], None);
        fs::create_dir(root.join("self")).unwrap();

        let uid = fs::metadata(root).unwrap().uid();
        let scan = ProcScan { root: root.to_path_buf(), own_pid: 14, own_uid: uid };
        let pids: Vec<u32> = scan.live().unwrap().iter().map(|l| l.pid).collect();
        assert_eq!(pids, [10, 11, 12]);

        let other_user = ProcScan { root: root.to_path_buf(), own_pid: 0, own_uid: uid + 1 };
        assert!(other_user.live().unwrap().is_empty(), "another user's claude is not ours");
        let gone = ProcScan { root: root.join("missing"), own_pid: 0, own_uid: uid };
        assert!(gone.live().is_err(), "an unreadable procfs fails closed");
    }

    // ---- status (slice 004 helpers) ----

    #[test]
    fn status_headroom_flag_matches_picker_thresholds() {
        use softfig_growlightd::profile_budget::Headroom;
        use softfig_growlightd::profile_pin::{HEADROOM_STALL_PCT, HEADROOM_WARN_PCT};
        let flag = |pct| flag_for_headroom(&Headroom { pct, resets_at: None });
        assert_eq!(flag(100), "");
        assert_eq!(flag(HEADROOM_WARN_PCT), "", "the warn branch is `<`");
        assert_eq!(flag(HEADROOM_WARN_PCT - 1), "   (WARN)");
        assert_eq!(flag(HEADROOM_STALL_PCT), "   (STALL)", "the stall floor is `<=`");
        assert_eq!(flag(0), "   (STALL)");
    }

    #[test]
    fn status_last_seen_formats_match_each_time_bucket() {
        assert_eq!(format_age(1_000, 0), "never");
        assert_eq!(format_age(1_000, -5), "never");
        assert_eq!(format_age(1_030, 1_000), "30s ago");
        assert_eq!(format_age(1_000 + 90, 1_000), "1m ago");
        assert_eq!(format_age(1_000 + 3 * 3_600, 1_000), "3h ago");
        assert_eq!(format_age(1_000 + 2 * 86_400, 1_000), "2d ago");
    }

    #[test]
    fn status_renders_headroom_rows_for_home_and_store_slots() {
        let fx = healthy();
        let mut out = Vec::new();
        print_profile_headroom(&fx.env, &fx.home.join("no-samples"), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let rows: Vec<&str> = out.lines().skip(1).collect();
        assert_eq!(
            rows,
            [
                "  home   headroom 100%   last-seen never",
                "  slot1  headroom 100%   last-seen never",
                "  slot2  headroom 100%   last-seen never",
            ],
            "{out}"
        );
    }
}
