//! `softfig growlight {init, start}` — the work-loop pillar scaffolder + the
//! loop launcher.
//!
//! `init` (Phase 2a) asks the running daemon to materialize the durable
//! `growlight/` garden pillar (idempotent, mirrors `migrate split`).
//!
//! `start` (Phase 2b) sets up the **churny runtime** under
//! `$XDG_CONFIG_HOME/softfig/growlight/` and launches the agent in loop mode.
//! The runtime lives *outside* the garden and is written with plain filesystem
//! ops — no IPC, no commit (spec-growlight.md §3 garden/runtime split). The
//! only daemon contact is a read-only STATUS query to derive the garden root
//! (so `protocol.md`'s injection path is never a literal). Generated files
//! (`loop.json` + the two helper scripts) are refreshed every launch so they
//! self-heal; live state (`baton.md`, `questions.md`) is seeded once and never
//! clobbered.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand, ValueEnum};
use softfig_ipc::{
    ClientError, Request, growlightd_runtime_socket_path, runtime_socket_path,
    growlightd::{
        self, AgentDeltaKind, Event, FleetStatusReply, ForceStopArgs, PausedReply,
        ResumeItemArgs, ResumeItemReply, StopLevel, StopReply,
    },
    verbs::{GrowlightInitArgs, GrowlightInitReply, PostMessageArgs, PostMessageReply, StatusReply, op},
};

use softfig_growlightd_client::{decode_frame, Frame};

use crate::cmd_daemon::try_daemon_call;

/// Agent backend (spec §12: a documented, swappable seam). Claude Code is the
/// supported backend; `--name` tags the loop session, `--settings` loads the
/// generated isolated hooks so normal `claude` stays untouched.
const AGENT_BIN: &str = "claude";
const AGENT_NAME: &str = "softfig-loop";

#[derive(Subcommand, Debug)]
pub enum GrowlightCmd {
    /// Scaffold the `growlight/` pillar in this garden (idempotent retrofit):
    /// routing docs, the operating protocol + session policy, the backlog +
    /// baton-log skeleton, and the garden nav wiring. Re-running fills only
    /// what's missing and makes no commit if nothing changed. Requires the
    /// garden unlocked.
    Init(InitArgs),

    /// Set up the loop runtime under `$XDG_CONFIG_HOME/softfig/growlight/`
    /// (generated hook settings + helper scripts, seeded baton + questions
    /// form) and launch the agent in loop mode. Requires the garden unlocked
    /// and `growlight init` already run.
    Start(StartArgs),

    /// Show the orchestrator daemon's fleet status — a one-shot query to
    /// growlightd's own IPC socket: state, garden root, policy, the admission
    /// gate (`paused`), and the (phase-1 empty) agent list.
    Status(ClientArgs),

    /// Tail growlightd's live event stream (the `subscribe` verb): agent
    /// thoughts/tool-calls, budget changes, lease changes, and bus messages,
    /// rendered as they arrive. Runs until the daemon stops or you Ctrl-C.
    Watch(ClientArgs),

    /// Stop one agent at a chosen level (spec §8). `--level after-slice`
    /// (default) / `after-iteration` record a boundary intent the drive loop
    /// honours at the next handoff; `hard-kill` interrupts immediately.
    Stop(StopArgs),

    /// Engage the fleet admission gate — the scheduler admits no new/rolling
    /// agents until `resume`. Idempotent.
    Pause(ClientArgs),

    /// Clear the fleet admission gate (no `<item>`), OR un-block one parked
    /// backlog item (`growlight resume <item>`): flip a `blocked` item back to
    /// `queued` so the scheduler re-picks it — the inverse of the drive loop's
    /// item-park (spec §6). The item form only acts on a currently-blocked item
    /// (guarded); pass `--queue` if the same id lives in more than one queue.
    Resume(ResumeArgs),

    /// Post a message to the coordination bus AS THE HUMAN (`from: @human`). The
    /// human is a first-class bus member (spec §4a): agents read it in their inbox
    /// at their next boot, and `growlight watch` shows it live. Routes to keeperd
    /// (which owns the bus store), unlike the growlightd client verbs above.
    Say(SayArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct StartArgs {
    /// Override the socket path used to derive the garden root. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Use this garden root instead of asking the daemon (skips the STATUS
    /// query; mainly for tests or unusual setups).
    #[arg(long)]
    pub garden_root: Option<PathBuf>,
    /// Override the runtime dir. Defaults to
    /// `$XDG_CONFIG_HOME/softfig/growlight` (or `~/.config/softfig/growlight`).
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
    /// Generate/refresh the runtime files but don't launch the agent.
    #[arg(long)]
    pub no_launch: bool,
}

/// Args for `say` — the human-post seam. Unlike the growlightd client verbs,
/// posting writes the bus store, which keeperd owns, so this targets keeperd's
/// socket (spec §2: keeperd owns the store, growlightd owns the stream).
#[derive(Args, Debug)]
pub struct SayArgs {
    /// keeperd socket (the bus store lives in keeperd). Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Addressee: an agent slug, `@all` (default — every agent's lane), or
    /// `@human`.
    #[arg(long, default_value = "@all")]
    pub to: String,
    /// Message kind (default `info`): info | coord-request | lease-request |
    /// question | alert | restart-request.
    #[arg(long, default_value = "info")]
    pub kind: String,
    /// The message text.
    pub body: String,
}

/// Shared args for the growlight client subcommands. They talk to growlightd's
/// OWN socket (a separate process from keeperd — spec §2/§13), so the override
/// defaults to the growlightd socket, not keeperd's.
#[derive(Args, Debug)]
pub struct ClientArgs {
    /// Override the growlightd socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-growlightd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

/// Args for `resume`. With no `item` it clears the fleet-wide admission gate
/// (the original meaning); with an `item` it un-blocks that one backlog item —
/// two distinct growlightd verbs (`resume` vs `resume_item`) behind one CLI word,
/// chosen by whether an item is named.
#[derive(Args, Debug)]
pub struct ResumeArgs {
    /// Override the growlightd socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-growlightd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// A parked backlog item to un-block (`blocked → queued`). Omit to clear the
    /// fleet admission gate instead.
    pub item: Option<String>,
    /// Which queue the item lives in — only needed to disambiguate the same id
    /// across queues. Ignored when no `item` is given.
    #[arg(long)]
    pub queue: Option<String>,
}

#[derive(Args, Debug)]
pub struct StopArgs {
    /// Override the growlightd socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-growlightd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// The agent (work-stream) id to stop.
    #[arg(long)]
    pub agent: String,
    /// Stop level (spec §8): the gentlest graceful boundary by default.
    #[arg(long, value_enum, default_value = "after-slice")]
    pub level: StopLevelArg,
}

/// CLI surface for [`StopLevel`]. clap renders these kebab-case on the command
/// line (`after-slice` / `after-iteration` / `hard-kill`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum StopLevelArg {
    AfterSlice,
    AfterIteration,
    HardKill,
}

impl From<StopLevelArg> for StopLevel {
    fn from(arg: StopLevelArg) -> Self {
        match arg {
            StopLevelArg::AfterSlice => StopLevel::AfterSlice,
            StopLevelArg::AfterIteration => StopLevel::AfterIteration,
            StopLevelArg::HardKill => StopLevel::HardKill,
        }
    }
}

pub fn run(cmd: GrowlightCmd) -> Result<()> {
    match cmd {
        GrowlightCmd::Init(args) => init(args),
        GrowlightCmd::Start(args) => start(args),
        GrowlightCmd::Status(args) => client_status(args),
        GrowlightCmd::Watch(args) => client_watch(args),
        GrowlightCmd::Stop(args) => client_stop(args),
        GrowlightCmd::Pause(args) => client_pause(args),
        GrowlightCmd::Resume(args) => client_resume(args),
        GrowlightCmd::Say(args) => client_say(args),
    }
}

// ---- init (Phase 2a) ---------------------------------------------------

fn init(args: InitArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let req_args = serde_json::to_value(GrowlightInitArgs::default())?;
    match try_daemon_call(&socket, op::GROWLIGHT_INIT, req_args) {
        Ok(Some(value)) => {
            let reply: GrowlightInitReply = serde_json::from_value(value)?;
            print_init_reply(&reply);
            Ok(())
        }
        Ok(None) => Err(anyhow!(
            "no daemon at {} — start one first (`softfig daemon start`)",
            socket.display()
        )),
        Err(ClientError::Daemon { kind, message }) => {
            Err(anyhow!("daemon error ({:?}): {message}", kind))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

fn print_init_reply(reply: &GrowlightInitReply) {
    if reply.created.is_empty() && reply.nav_wired.is_empty() {
        println!("growlight already set up — nothing to do.");
        if !reply.skipped.is_empty() {
            println!("  ({} pillar file(s) already present)", reply.skipped.len());
        }
        return;
    }
    if !reply.created.is_empty() {
        println!("created:");
        for p in &reply.created {
            println!("  {p}");
        }
    }
    if !reply.skipped.is_empty() {
        println!("kept (already present):");
        for p in &reply.skipped {
            println!("  {p}");
        }
    }
    if !reply.nav_wired.is_empty() {
        println!("nav wired:");
        for p in &reply.nav_wired {
            println!("  {p}");
        }
    }
    if reply.committed {
        println!();
        println!("committed {}", short_hash(&reply.hash));
    }
    println!();
    println!("the growlight pillar is ready — queue work with the `add_backlog_item` MCP verb.");
}

fn short_hash(hash: &str) -> &str {
    &hash[..hash.len().min(8)]
}

// ---- start (Phase 2b): runtime + launcher ------------------------------

fn start(args: StartArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let garden_root = resolve_garden_root(&socket, args.garden_root)?;

    // The hook injects this on every (re)start; its absence means the durable
    // pillar was never scaffolded.
    let protocol = garden_root.join(PILLAR).join("protocol.md");
    if !protocol.exists() {
        return Err(anyhow!(
            "growlight pillar not found ({} missing) — run `softfig growlight init` first",
            protocol.display()
        ));
    }

    let runtime = runtime_dir(args.config_dir)?;
    fs::create_dir_all(&runtime)
        .with_context(|| format!("creating runtime dir {}", runtime.display()))?;

    let loop_path = runtime.join("loop.json");
    let mcp_path = runtime.join("mcp.json");
    let inject_path = runtime.join("inject.sh");
    let statusline_path = runtime.join("statusline.sh");
    let baton_path = runtime.join("baton.md");
    let questions_path = runtime.join("questions.md");

    // Generated + derived → always refreshed (self-heal if paths moved).
    // `~/.claude/projects` is granted to the loop so it can keep its own
    // claude-memory pointers in sync (they live outside the garden workspace).
    let claude_projects = home_dir()?.join(".claude").join("projects");
    write_file(
        &loop_path,
        &loop_json(
            &inject_path,
            &statusline_path,
            &garden_root,
            &claude_projects,
        ),
    )?;
    // `--settings` only *permits* softfig-mcp; this *attaches* it, so the
    // garden verbs exist regardless of where the loop is launched from (the
    // project-scoped registration in ~/.claude.json only loads with cwd in the
    // garden). Without it every state-advancing iteration STUCKs (auto-run log).
    write_file(&mcp_path, &mcp_json(&softfig_mcp_path()))?;
    write_script(&inject_path, &inject_script(&protocol, &baton_path))?;
    write_script(
        &statusline_path,
        &statusline_script(&runtime.join("usage.json")),
    )?;

    // Live loop state → seed once, never clobber an in-flight loop.
    let garden_name = garden_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("garden");
    let baton_seeded = seed_if_absent(&baton_path, &seed_baton(garden_name, &today_iso()))?;
    let questions_seeded = seed_if_absent(&questions_path, SEED_QUESTIONS)?;

    print_setup(&runtime, &loop_path, baton_seeded, questions_seeded);

    // The statusline budget dump is jq-based (spec §6). Without jq it degrades
    // to 0% — which would let the loop run past its budgets silently — so warn
    // loudly rather than fail quietly.
    if !jq_present() {
        eprintln!(
            "warning: `jq` not found on PATH — the statusline can't write usage.json, so the \
             loop's budget tracking (context / 5h) won't work. Install jq."
        );
    }

    if args.no_launch {
        println!(
            "\n(--no-launch) runtime ready. launch with:\n  {AGENT_BIN} --name {AGENT_NAME} \
             --settings {} --mcp-config {}",
            loop_path.display(),
            mcp_path.display()
        );
        return Ok(());
    }
    launch_agent(&loop_path, &mcp_path)
}

/// Ask the daemon where the garden is mounted (so injection paths are derived,
/// never literal — spec §3/§12). `--garden-root` bypasses the query.
fn resolve_garden_root(socket: &Path, override_: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_ {
        return Ok(p);
    }
    match try_daemon_call(socket, op::STATUS, serde_json::Value::Null) {
        Ok(Some(value)) => {
            let reply: StatusReply = serde_json::from_value(value)?;
            if reply.state != "unlocked" {
                return Err(anyhow!(
                    "garden is {} — unlock it first (`softfig daemon unlock`); the loop reads \
                     the protocol from the mounted garden",
                    reply.state
                ));
            }
            Ok(PathBuf::from(reply.garden_root))
        }
        Ok(None) => Err(anyhow!(
            "no daemon at {} — the garden must be unlocked and mounted to launch the loop \
             (`softfig daemon unlock`), or pass --garden-root",
            socket.display()
        )),
        Err(ClientError::Daemon { kind, message }) => {
            Err(anyhow!("daemon error ({:?}): {message}", kind))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

fn launch_agent(loop_path: &Path, mcp_path: &Path) -> Result<()> {
    println!("\nlaunching {AGENT_BIN} --name {AGENT_NAME} …\n");
    let status = std::process::Command::new(AGENT_BIN)
        .arg("--name")
        .arg(AGENT_NAME)
        .arg("--settings")
        .arg(loop_path)
        .arg("--mcp-config")
        .arg(mcp_path)
        .status()
        .with_context(|| format!("failed to launch `{AGENT_BIN}` — is it on PATH?"))?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Whether `jq` is callable — the statusline's budget read path needs it.
fn jq_present() -> bool {
    std::process::Command::new("jq")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn print_setup(runtime: &Path, loop_path: &Path, baton_seeded: bool, questions_seeded: bool) {
    println!("runtime: {}", runtime.display());
    println!("  refreshed  loop.json, inject.sh, statusline.sh");
    println!(
        "  baton.md   {}",
        if baton_seeded {
            "seeded"
        } else {
            "kept (in-flight)"
        }
    );
    println!(
        "  questions.md {}",
        if questions_seeded { "seeded" } else { "kept" }
    );
    let _ = loop_path;
}

// ---- runtime path derivation -------------------------------------------

/// Garden-relative pillar name (matches the daemon-side `paths::PILLAR`).
const PILLAR: &str = "growlight";

/// `$XDG_CONFIG_HOME/softfig/growlight` (fallback `~/.config/...`). Never a
/// literal — derived from the environment per spec §3/§12.
fn runtime_dir(override_: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_ {
        return Ok(p);
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home_dir()?.join(".config"),
    };
    Ok(base.join("softfig").join(PILLAR))
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("$HOME not set"))
}

// ---- file writers ------------------------------------------------------

fn write_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("writing {}", path.display()))
}

fn write_script(path: &Path, content: &str) -> Result<()> {
    write_file(path, content)?;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).with_context(|| format!("chmod {}", path.display()))
}

/// Write `content` to `path` only if it doesn't already exist. Returns whether
/// it was written (so the caller can report "seeded" vs "kept").
fn seed_if_absent(path: &Path, content: &str) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    write_file(path, content)?;
    Ok(true)
}

// ---- generated content (pure, unit-testable) ---------------------------

/// The isolated settings file the launcher passes to `--settings`. A
/// SessionStart hook re-injects `inject.sh` on both `startup` and `clear`
/// (so `/clear` is the roll mechanism, spec §2); the statusLine tees the
/// budgets to `usage.json` (spec §6).
///
/// The `permissions` block lets the loop agent actually do its job: a headless
/// `-p` iteration can't answer a permission prompt, so without an allow-list it
/// silently fails to advance the baton (the trial-run STUCK finding). The agent
/// works the garden the normal way — through `softfig-mcp` — and the code repos
/// through git/cargo/shell. Raw `Edit`/`Write` into the garden tree are DENIED
/// so the MCP-only convention (CLAUDE.md house-rule 1; never raw mv/sed/git) is
/// enforced structurally, not just by instruction — `deny` overrides `allow`.
/// The garden path is anchored absolute (`//…`, spec the box's settings use).
///
/// `claude_projects` (`~/.claude/projects`) is added to `additionalDirectories`
/// so the loop can update its own claude-memory pointers, which live *outside*
/// the garden workspace. The Edit/Write tools refuse any path outside cwd +
/// `additionalDirectories` before permission rules are even consulted, so
/// without this entry the loop can't touch `~/.claude` at all (it just flags the
/// human — the old behaviour). We grant the `projects/` subtree, not all of
/// `~/.claude`: per-project memory + transcripts are reachable, but the OAuth
/// token (`.credentials.json`) and harness settings stay out of an unattended
/// loop run's reach.
fn loop_json(
    inject: &Path,
    statusline: &Path,
    garden_root: &Path,
    claude_projects: &Path,
) -> String {
    let inject = inject.display().to_string();
    let session_start_block = |source: &str| {
        serde_json::json!({
            "matcher": source,
            "hooks": [ { "type": "command", "command": inject } ]
        })
    };
    let garden = garden_root.display();
    let v = serde_json::json!({
        "permissions": {
            "allow": [
                "mcp__softfig-mcp",
                "Read",
                "Edit",
                "Write",
                "Bash"
            ],
            "deny": [
                format!("Edit(/{garden}/**)"),
                format!("Write(/{garden}/**)")
            ],
            "additionalDirectories": [
                claude_projects.display().to_string()
            ]
        },
        "statusLine": {
            "type": "command",
            "command": statusline.display().to_string()
        },
        "hooks": {
            "SessionStart": [
                session_start_block("startup"),
                session_start_block("clear"),
            ]
        }
    });
    format!("{}\n", serde_json::to_string_pretty(&v).unwrap())
}

/// The `--mcp-config` file the launcher passes alongside `--settings`. The
/// settings `permissions.allow` entry only *grants* `mcp__softfig-mcp`; it
/// can't conjure a server that isn't registered. softfig-mcp is normally a
/// *project-scoped* entry in `~/.claude.json`, which loads only when the agent
/// runs with cwd inside the garden — but the loop launches from wherever the
/// human invoked `growlight start`, so the server never attached and every
/// state-advancing iteration STUCKed (the real cause behind the "permission
/// gap" trial finding). Attaching it here makes the garden verbs exist for the
/// loop session regardless of cwd, with no dependency on the user's global
/// Claude config — the AUR-distributable posture (no hardcoded host paths).
fn mcp_json(mcp_bin: &Path) -> String {
    let v = serde_json::json!({
        "mcpServers": {
            "softfig-mcp": {
                "type": "stdio",
                "command": mcp_bin.display().to_string(),
                "args": [],
                "env": {}
            }
        }
    });
    format!("{}\n", serde_json::to_string_pretty(&v).unwrap())
}

/// Resolve the `softfig-mcp` bridge binary. It ships beside the `softfig`
/// launcher (same `cargo install` / AUR package), so prefer the sibling of the
/// running exe — that keeps a dev build pointing at its own freshly-built
/// bridge rather than whatever stale copy is on PATH. Fall back to a bare
/// `softfig-mcp` (PATH lookup by Claude Code's stdio launcher) when the exe
/// path can't be resolved or the sibling is missing.
fn softfig_mcp_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("softfig-mcp");
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from("softfig-mcp")
}

/// SessionStart hook body: emit the fixed protocol (from the garden pillar) +
/// the current runtime baton to stdout, which Claude Code adds to the fresh
/// session's context.
fn inject_script(protocol: &Path, baton: &Path) -> String {
    const TPL: &str = r#"#!/usr/bin/env bash
# GENERATED by `softfig growlight start` — do not edit (refreshed each launch).
# SessionStart hook: injects the fixed operating protocol + the current baton
# into a fresh loop session on startup and on /clear. stdout becomes context.
set -u
printf '=== SOFT-FIG GROWLIGHT · OPERATING PROTOCOL ===\n\n'
cat @PROTOCOL@ 2>/dev/null || printf '(protocol.md missing — run `softfig growlight init`)\n'
printf '\n\n=== CURRENT BATON (your only carried state) ===\n\n'
cat @BATON@ 2>/dev/null || printf '(no baton yet — run `softfig growlight start`)\n'
"#;
    TPL.replace("@PROTOCOL@", &shell_quote(protocol))
        .replace("@BATON@", &shell_quote(baton))
}

/// statusLine hook body: on every render, tee the two budgets to `usage.json`
/// (the loop's budget read path) and print a compact mode + budget line.
fn statusline_script(usage: &Path) -> String {
    const TPL: &str = r#"#!/usr/bin/env bash
# GENERATED by `softfig growlight start` — do not edit (refreshed each launch).
# statusLine hook: tee the two budgets to usage.json (spec-growlight.md §6, the
# loop's budget read path) and print a compact mode + budget line.
set -u
input=$(cat)
# Claude Code derives context_window.used_percentage from a cumulative token
# total over the window, so it can exceed 100 in a long session. Clamp it to a
# sane 0..100 the governor can trust (spec-growlight.md §6) BEFORE teeing — but
# only when it is actually a number, so a missing % stays absent (never coerced
# to a false 0), and keep remaining_percentage consistent with the clamp.
printf '%s' "$input" | jq '
  (if (.context_window.used_percentage | type) == "number" then
        .context_window.used_percentage |= ([., 100] | min) | .context_window.used_percentage |= ([., 0] | max)
      | .context_window.remaining_percentage = (100 - .context_window.used_percentage)
   else . end)
  | {context_window, rate_limits, ts: now}' > @USAGE@ 2>/dev/null || true
ctx=$(printf '%s' "$input" | jq -r '([(.context_window.used_percentage // 0), 100] | min)' 2>/dev/null || echo 0)
five=$(printf '%s' "$input" | jq -r '.rate_limits.five_hour.used_percentage // 0' 2>/dev/null || echo 0)
printf 'softfig-loop · ctx %s%% · 5h %s%%' "$ctx" "$five"
"#;
    TPL.replace("@USAGE@", &shell_quote(usage))
}

/// The initial baton (spec §5). Seeded once; the loop rewrites it each handoff.
/// A fresh garden has an empty backlog, so the seed points the loop at the
/// queue table and tells it to either reseed from a queued item or surface that
/// there's nothing to do.
fn seed_baton(garden_name: &str, date: &str) -> String {
    format!(
        "---\n\
         loop: {garden_name}\n\
         mode: semi\n\
         status: QUEUE_EMPTY\n\
         item: null\n\
         item_type: null\n\
         slice: null\n\
         iteration: 0\n\
         updated: {date}\n\
         ctx_pct: 0\n\
         session_5h_pct: 0\n\
         ---\n\n\
         # NEXT ACTION\n\
         Bootstrap. Read `growlight/backlog/CLAUDE.md` (the authoritative queue table). If a\n\
         `queued` item exists: `set_item_status` it `active`, reseed this baton from its spec\n\
         (mission + finish criteria + first slice/step), and begin. If the queue is empty, this\n\
         loop has no work — surface that to the human and ask what to queue (`add_backlog_item`).\n\n\
         # FINISH CRITERIA\n\
         (none yet — seeded from the first backlog item when it goes active)\n\n\
         # MISSION\n\
         Drain the growlight backlog one item at a time, handing off via this baton instead of\n\
         `/compact`.\n\n\
         # READ FIRST\n\
         - `growlight/backlog/CLAUDE.md` — the authoritative queue table (status + order)\n\
         - `growlight/session-policy.md` — the two budgets + value-max strategy\n\n\
         # LOCKED DECISIONS\n\
         (none yet)\n\n\
         # STATE\n\
         Fresh runtime — `softfig growlight start` generated this seed baton.\n\n\
         # FOR THE HUMAN\n\
         (no open questions)\n\n\
         # SCRATCH\n\
         (empty)\n"
    )
}

/// The offline answer form (spec §9). Seeded empty; the loop appends questions
/// and regenerates it.
const SEED_QUESTIONS: &str = "# growlight questions\n\n\
The offline answer form. When the loop needs a human decision while you're away, it appends a\n\
question here. Type your answer after `>>>` and save; the loop folds each one in and regenerates\n\
this file with whatever is left. A blank answer proceeds on the stated default (flagged in the\n\
baton-log) — being away never hard-blocks the loop.\n\n\
(no open questions)\n";

/// Single-quote a path for safe embedding in a generated shell script.
fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
}

/// Today's UTC date as `YYYY-MM-DD`. Hand-rolled civil-from-days (Howard
/// Hinnant) so the CLI needs no chrono/time dependency — same approach as
/// `cmd_onboard`.
fn today_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ---- growlight client subcommands (slice 004) --------------------------
//
// Thin clients over growlightd's IPC socket (spec §11/§13), proving the socket
// is usable from a client without the GUI. They talk to growlightd's OWN socket
// — a separate process from keeperd — and REPLACE nothing: the interactive
// `start` launcher above stays intact (autonomous runs are growlightd's; the
// standalone `--auto` twin was retired).
// `status`/`stop`/`pause`/`resume` are one-shot `call`s reusing the
// keeperd client idiom (`try_daemon_call`); `watch` tails the one STREAMING verb
// (`subscribe`) with a `read_line` → decode-`Event` loop, mirroring growlightd's
// `tests/subscribe_stream.rs`.

/// Resolve growlightd's socket: the `--socket` override, else
/// `$XDG_RUNTIME_DIR/softfig-growlightd.sock` (distinct from keeperd's).
fn growlight_socket(override_: Option<PathBuf>) -> PathBuf {
    override_.unwrap_or_else(growlightd_runtime_socket_path)
}

/// One-shot growlightd client call: connect → `call` → decode the typed reply
/// `T`. Maps the daemon-absent and daemon-error cases to friendly CLI errors
/// (the keeperd client idiom from `cmd_daemon`, pointed at growlightd's socket).
fn growlight_call<T: serde::de::DeserializeOwned>(
    socket: &Path,
    op: &str,
    args: serde_json::Value,
) -> Result<T> {
    match try_daemon_call(socket, op, args) {
        Ok(Some(value)) => Ok(serde_json::from_value(value)?),
        Ok(None) => Err(anyhow!(
            "no growlightd listening at {} — is the orchestrator daemon running?",
            socket.display()
        )),
        Err(ClientError::Daemon { kind, message }) => {
            Err(anyhow!("growlightd error ({kind:?}): {message}"))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

fn client_status(args: ClientArgs) -> Result<()> {
    let socket = growlight_socket(args.socket);
    let reply: FleetStatusReply =
        growlight_call(&socket, growlightd::op::STATUS, serde_json::Value::Null)?;
    print_fleet_status(&reply);
    Ok(())
}

/// Render a [`FleetStatusReply`] for the terminal.
fn print_fleet_status(r: &FleetStatusReply) {
    println!("state         {}", r.state);
    println!("garden        {}", r.garden_root);
    println!("protocol      v{}", r.protocol_version);
    // The config-level arm/disarm gate (`config/growlight.toml fleet_enabled`),
    // distinct from `paused` (the runtime admission gate over an armed fleet).
    println!("fleet         {}", if r.fleet_enabled { "enabled" } else { "disabled" });
    println!("paused        {}", r.paused);
    println!(
        "policy        max_agents={} ctx_roll={}% ctx_handoff={}% 5h_halt={}% 7d_halt={}%",
        r.policy.max_concurrent_agents,
        r.policy.ctx_roll_pct,
        r.policy.ctx_handoff_pct,
        r.policy.session_5h_halt_pct,
        r.policy.session_7d_halt_pct,
    );
    // The configured roster (from config/growlight.toml) — shown even when the
    // gate is off and no agents have spawned, so the fleet is self-explaining.
    if r.roster.is_empty() {
        println!("roster        (none)");
    } else {
        println!("roster:");
        for m in &r.roster {
            match &m.pin {
                Some(pin) => println!("  {:<16} pin={pin}", m.agent),
                None => println!("  {:<16} (fallback)", m.agent),
            }
        }
    }
    // The live per-agent runtime state (empty until the fleet spawns agents).
    if r.agents.is_empty() {
        println!("agents        (none)");
    } else {
        println!("agents:");
        for a in &r.agents {
            println!("  {:<16} {}", a.id, a.status);
        }
    }
}

fn client_pause(args: ClientArgs) -> Result<()> {
    let socket = growlight_socket(args.socket);
    let reply: PausedReply =
        growlight_call(&socket, growlightd::op::PAUSE, serde_json::Value::Null)?;
    println!("fleet {}", gate_label(reply.paused));
    Ok(())
}

fn client_resume(args: ResumeArgs) -> Result<()> {
    let socket = growlight_socket(args.socket);
    match args.item {
        // `growlight resume <item>` — un-block one parked backlog item. A distinct
        // growlightd verb (`resume_item`) from the gate `resume` below; the guard
        // (only un-blocks a blocked item) lives daemon-side, surfaced here as a
        // clear error.
        Some(item) => {
            let reply: ResumeItemReply = growlight_call(
                &socket,
                growlightd::op::RESUME_ITEM,
                serde_json::to_value(ResumeItemArgs {
                    item,
                    queue: args.queue,
                })?,
            )?;
            if reply.resumed {
                println!("resumed {} in queue {} (blocked → queued)", reply.item, reply.queue);
            } else {
                println!("{} is already queued in queue {} — nothing to do", reply.item, reply.queue);
            }
            Ok(())
        }
        // `growlight resume` — clear the fleet-wide admission gate (unchanged).
        None => {
            let reply: PausedReply =
                growlight_call(&socket, growlightd::op::RESUME, serde_json::Value::Null)?;
            println!("fleet {}", gate_label(reply.paused));
            Ok(())
        }
    }
}

fn gate_label(paused: bool) -> &'static str {
    if paused { "paused" } else { "resumed" }
}

fn client_stop(args: StopArgs) -> Result<()> {
    let socket = growlight_socket(args.socket);
    let force = ForceStopArgs {
        agent: args.agent,
        level: args.level.into(),
    };
    let reply: StopReply =
        growlight_call(&socket, growlightd::op::FORCE_STOP, serde_json::to_value(force)?)?;
    println!(
        "stop {}: agent {} ({})",
        if reply.immediate {
            "applied now"
        } else {
            "recorded for the next boundary"
        },
        reply.agent,
        stop_level_label(reply.level),
    );
    Ok(())
}

fn stop_level_label(level: StopLevel) -> &'static str {
    match level {
        StopLevel::AfterSlice => "after-slice",
        StopLevel::AfterIteration => "after-iteration",
        StopLevel::HardKill => "hard-kill",
    }
}

/// `watch`: open a `subscribe` stream and render each [`Event`] as it arrives.
/// Unlike the one-shot verbs this tails a long-lived stream — it returns when the
/// daemon stops (EOF) or the user interrupts. The framing (newline-delimited
/// `Event` JSON, NOT `Response` envelopes) mirrors growlightd's
/// `tests/subscribe_stream.rs`.
fn client_watch(args: ClientArgs) -> Result<()> {
    let socket = growlight_socket(args.socket);
    let mut stream = softfig_ipc::connect(&socket).map_err(|e| {
        if e.is_daemon_absent() {
            anyhow!(
                "no growlightd listening at {} — is the orchestrator daemon running?",
                socket.display()
            )
        } else {
            anyhow!("connecting to growlightd: {e}")
        }
    })?;
    send_subscribe(&mut stream)?;
    eprintln!("watching growlightd at {} — Ctrl-C to stop", socket.display());
    let mut reader = BufReader::new(stream);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    watch_stream(&mut reader, &mut out)
}

/// Send the streaming `subscribe` request — the one verb that takes over the
/// connection. Mirrors the wire write in `tests/subscribe_stream.rs`.
fn send_subscribe(stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    let mut bytes = serde_json::to_vec(&Request::new(
        growlightd::op::SUBSCRIBE,
        serde_json::Value::Null,
    ))?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// Read newline-framed [`Event`] frames from `reader` and render each to `out`
/// until EOF — the pure stream-rendering core of `watch`, so it's unit-tested
/// with a scripted reader (no socket). Decoding is delegated to the shared
/// `softfig-growlightd-client` crate (the one tolerant-framing rule every
/// frontend uses): a frame that fails to decode is noted and skipped, never
/// fatal (forward-compatible with event variants this build predates — e.g.
/// `BusMessage` before the bus exists).
fn watch_stream(reader: &mut dyn BufRead, out: &mut dyn Write) -> Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(()); // EOF: the daemon stopped or the connection closed.
        }
        match decode_frame(&line) {
            Frame::Blank => continue,
            Frame::Event(event) => writeln!(out, "{}", render_event(&event))?,
            Frame::Undecodable(e) => writeln!(out, "(unrecognized event frame: {e})")?,
        }
    }
}

/// Render one [`Event`] as a single terminal line.
fn render_event(e: &Event) -> String {
    match e {
        Event::AgentDelta { agent, kind, text } => {
            format!("[{agent}] {} {text}", delta_kind_label(*kind))
        }
        Event::BudgetChanged {
            agent,
            ctx_pct,
            session_5h_pct,
            session_7d_pct,
        } => {
            let who = agent.as_deref().unwrap_or("fleet");
            let mut parts = Vec::new();
            if let Some(c) = ctx_pct {
                parts.push(format!("ctx {c}%"));
            }
            if let Some(f) = session_5h_pct {
                parts.push(format!("5h {f}%"));
            }
            if let Some(s) = session_7d_pct {
                parts.push(format!("7d {s}%"));
            }
            let body = if parts.is_empty() {
                "(no reading)".to_string()
            } else {
                parts.join(" · ")
            };
            format!("[{who}] budget {body}")
        }
        Event::LeaseChanged {
            lease,
            holder,
            state,
        } => {
            format!(
                "lease {lease} {state} (holder {})",
                holder.as_deref().unwrap_or("-")
            )
        }
        Event::BusMessage {
            from,
            to,
            kind,
            body,
        } => format!("bus {from}→{to} [{kind}] {body}"),
    }
}

/// `say`: post to the coordination bus as the human. The store lives in keeperd,
/// so this routes to keeperd's `post_message` (NOT growlightd) — the human-post
/// half of the bus's async turn-boundary model: agents read it in their inbox at
/// their next boot (spec §4a). The GUI input box is the same seam later.
fn client_say(args: SayArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let post = human_say_args(&args.to, &args.kind, &args.body);
    match try_daemon_call(&socket, op::POST_MESSAGE, serde_json::to_value(post)?) {
        Ok(Some(value)) => {
            let reply: PostMessageReply = serde_json::from_value(value)?;
            println!(
                "posted msg {} → {} [{}]  ({})",
                reply.number,
                args.to,
                args.kind,
                short_hash(&reply.hash)
            );
            Ok(())
        }
        Ok(None) => Err(anyhow!(
            "no daemon at {} — unlock the garden first (`softfig daemon unlock`)",
            socket.display()
        )),
        Err(ClientError::Daemon { kind, message }) => {
            Err(anyhow!("daemon error ({kind:?}): {message}"))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

/// Build the `post_message` args for a human-originated bus post: the sender is
/// ALWAYS `@human` (the human is a first-class member, never an agent slug); the
/// CLI only chooses the recipient, kind, and body. Pure, so the human-post seam
/// is unit-tested without a live daemon.
fn human_say_args(to: &str, kind: &str, body: &str) -> PostMessageArgs {
    PostMessageArgs {
        from: "@human".to_string(),
        to: to.to_string(),
        kind: kind.to_string(),
        body: body.to_string(),
    }
}

/// Short tag for an [`AgentDeltaKind`] in the `watch` stream.
fn delta_kind_label(kind: AgentDeltaKind) -> &'static str {
    match kind {
        AgentDeltaKind::Assistant => "say",
        AgentDeltaKind::ToolCall => "tool",
        AgentDeltaKind::Thinking => "think",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_tmp(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "softfig-growlight-{tag}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn loop_json_wires_both_session_starts_and_the_statusline() {
        let inject = Path::new("/run/softfig/growlight/inject.sh");
        let statusline = Path::new("/run/softfig/growlight/statusline.sh");
        let garden = Path::new("/home/ukv/soft-fig_garden");
        let claude_projects = Path::new("/home/ukv/.claude/projects");
        let json: serde_json::Value =
            serde_json::from_str(&loop_json(inject, statusline, garden, claude_projects))
                .expect("valid JSON");

        assert_eq!(json["statusLine"]["type"], "command");
        assert_eq!(
            json["statusLine"]["command"],
            statusline.display().to_string()
        );

        let starts = json["hooks"]["SessionStart"].as_array().unwrap();
        let sources: Vec<&str> = starts
            .iter()
            .map(|b| b["matcher"].as_str().unwrap())
            .collect();
        assert_eq!(sources, vec!["startup", "clear"]);
        for b in starts {
            let cmd = &b["hooks"][0];
            assert_eq!(cmd["type"], "command");
            assert_eq!(cmd["command"], inject.display().to_string());
        }
    }

    #[test]
    fn loop_json_grants_mcp_but_denies_raw_garden_writes() {
        // Without this block a headless `-p` iteration can't advance the baton
        // (the trial-run STUCK finding). The garden is reachable only via
        // softfig-mcp; raw file writes into the garden tree are denied so the
        // MCP-only convention holds even under broad shell/file access.
        let garden = Path::new("/home/ukv/soft-fig_garden");
        let claude_projects = Path::new("/home/ukv/.claude/projects");
        let json: serde_json::Value = serde_json::from_str(&loop_json(
            Path::new("/run/softfig/growlight/inject.sh"),
            Path::new("/run/softfig/growlight/statusline.sh"),
            garden,
            claude_projects,
        ))
        .expect("valid JSON");

        let allow: Vec<&str> = json["permissions"]["allow"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(allow.contains(&"mcp__softfig-mcp"), "garden via MCP allowed");

        let deny: Vec<&str> = json["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // `//…` is the absolute-path anchor (one literal slash + the rooted path).
        assert!(deny.contains(&"Edit(//home/ukv/soft-fig_garden/**)"));
        assert!(deny.contains(&"Write(//home/ukv/soft-fig_garden/**)"));

        // The loop must be able to update its own claude-memory pointers, which
        // sit outside the garden workspace — granted via additionalDirectories,
        // scoped to `projects/` so credentials/settings stay unreachable.
        let extra: Vec<&str> = json["permissions"]["additionalDirectories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(extra, vec!["/home/ukv/.claude/projects"]);
        assert!(
            !extra.contains(&"/home/ukv/.claude"),
            "must not grant all of ~/.claude (credentials live there)"
        );
    }

    #[test]
    fn human_say_always_posts_as_the_human() {
        // The CLI chooses recipient/kind/body; the sender is forced to @human so
        // a human post can never masquerade as an agent.
        let a = human_say_args("@all", "alert", "deploy starting");
        assert_eq!(a.from, "@human");
        assert_eq!(a.to, "@all");
        assert_eq!(a.kind, "alert");
        assert_eq!(a.body, "deploy starting");

        // Defaults (a bare `say "hi"`) address @all with kind info.
        let d = human_say_args("@all", "info", "hi");
        assert_eq!(d.to, "@all");
        assert_eq!(d.kind, "info");
        assert_eq!(d.from, "@human");
    }

    #[test]
    fn mcp_json_attaches_softfig_mcp_as_a_stdio_server() {
        // The settings allow-list only *permits* the server; this file is what
        // actually *registers* it, so the garden verbs exist under the loop's
        // launch cwd (not just when cwd is the garden). Without it the headless
        // loop STUCKs trying to write the baton/commit (auto-run.log).
        let bin = Path::new("/opt/softfig/bin/softfig-mcp");
        let json: serde_json::Value =
            serde_json::from_str(&mcp_json(bin)).expect("valid JSON");
        let server = &json["mcpServers"]["softfig-mcp"];
        assert_eq!(server["type"], "stdio");
        assert_eq!(server["command"], bin.display().to_string());
        assert_eq!(server["args"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn inject_script_cats_protocol_then_baton() {
        let s = inject_script(
            Path::new("/garden/growlight/protocol.md"),
            Path::new("/cfg/softfig/growlight/baton.md"),
        );
        assert!(s.starts_with("#!/usr/bin/env bash"));
        assert!(s.contains("cat '/garden/growlight/protocol.md'"));
        assert!(s.contains("cat '/cfg/softfig/growlight/baton.md'"));
        // protocol injected before the baton.
        assert!(s.find("protocol.md").unwrap() < s.find("baton.md").unwrap());
    }

    #[test]
    fn statusline_script_tees_both_budgets_to_usage_json() {
        let s = statusline_script(Path::new("/cfg/softfig/growlight/usage.json"));
        assert!(s.starts_with("#!/usr/bin/env bash"));
        assert!(s.contains("> '/cfg/softfig/growlight/usage.json'"));
        assert!(s.contains("context_window"));
        assert!(s.contains("rate_limits"));
        assert!(s.contains("five_hour.used_percentage"));
        // The tee must clamp a >100 used_percentage (spec §6) — see the
        // behavioral test below for the runtime proof.
        assert!(s.contains("used_percentage |= ([., 100] | min)"));
    }

    // Run the generated statusline through real jq+bash to prove the clamp.
    // Self-skips when jq is unavailable (the script can't write usage.json then
    // anyway — see the jq warning in `cmd_growlight`).
    fn run_statusline(input: &str) -> serde_json::Value {
        let dir = std::env::temp_dir().join(format!(
            "softfig-statusline-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let usage = dir.join("usage.json");
        let script = dir.join("statusline.sh");
        std::fs::write(&script, statusline_script(&usage)).unwrap();

        let mut child = std::process::Command::new("bash")
            .arg(&script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait().unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&usage).unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        v
    }

    #[test]
    fn statusline_clamps_an_over_100_used_percentage_but_keeps_missing_absent() {
        if !jq_present() {
            return; // jq-gated, like the live statusline path itself.
        }
        // Claude Code emitting 255% (cumulative tokens over the window) must be
        // floored to 100 with remaining 0 — never teed through as garbage.
        let over = r#"{"context_window":{"used_percentage":255,"remaining_percentage":0,"context_window_size":1000000},"rate_limits":{"five_hour":{"used_percentage":12}}}"#;
        let v = run_statusline(over);
        assert_eq!(v["context_window"]["used_percentage"], 100);
        assert_eq!(v["context_window"]["remaining_percentage"], 0);
        assert_eq!(v["rate_limits"]["five_hour"]["used_percentage"], 12);

        // A sane value passes through untouched.
        let sane = r#"{"context_window":{"used_percentage":69,"remaining_percentage":31,"context_window_size":1000000},"rate_limits":{}}"#;
        let v = run_statusline(sane);
        assert_eq!(v["context_window"]["used_percentage"], 69);
        assert_eq!(v["context_window"]["remaining_percentage"], 31);

        // A MISSING used_percentage must stay absent — never coerced to a false
        // 0 the governor could read as a false all-clear (the slice-001 rule).
        let missing = r#"{"context_window":{"context_window_size":1000000},"rate_limits":{}}"#;
        let v = run_statusline(missing);
        assert!(
            v["context_window"]["used_percentage"].is_null(),
            "missing % must not be coerced to 0: {v}"
        );
    }

    #[test]
    fn seed_baton_has_frontmatter_and_priority_sections() {
        let b = seed_baton("soft-fig_garden", "2026-06-14");
        assert!(b.starts_with("---\n"));
        assert!(b.contains("loop: soft-fig_garden\n"));
        assert!(b.contains("status: QUEUE_EMPTY\n"));
        assert!(b.contains("updated: 2026-06-14\n"));
        for section in [
            "# NEXT ACTION",
            "# FINISH CRITERIA",
            "# MISSION",
            "# READ FIRST",
            "# LOCKED DECISIONS",
            "# STATE",
            "# FOR THE HUMAN",
            "# SCRATCH",
        ] {
            assert!(b.contains(section), "baton missing section {section}");
        }
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quotes() {
        assert_eq!(shell_quote(Path::new("/a/b")), "'/a/b'");
        assert_eq!(shell_quote(Path::new("/a'b")), "'/a'\\''b'");
    }

    #[test]
    fn runtime_dir_prefers_explicit_override() {
        let p = PathBuf::from("/tmp/custom/runtime");
        assert_eq!(runtime_dir(Some(p.clone())).unwrap(), p);
    }

    #[test]
    fn write_script_is_executable_and_seed_is_idempotent() {
        let dir = unique_tmp("writers");
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("inject.sh");
        write_script(&script, "#!/usr/bin/env bash\necho hi\n").unwrap();
        let mode = fs::metadata(&script).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "script should be 0755");

        let baton = dir.join("baton.md");
        assert!(
            seed_if_absent(&baton, "first").unwrap(),
            "first seed writes"
        );
        assert!(
            !seed_if_absent(&baton, "second").unwrap(),
            "second seed is a no-op"
        );
        assert_eq!(
            fs::read_to_string(&baton).unwrap(),
            "first",
            "live state not clobbered"
        );

        fs::remove_dir_all(&dir).ok();
    }

    // ---- growlight IPC clients (slice 004) -----------------------------
    //
    // The fake-agent fixture is a REAL `softfig_growlightd::Daemon` booted on a
    // temp socket; scripted events are published through its hub (the seam a
    // real `claude -p` tailer feeds), exactly as growlightd's own integration
    // tests do — no `claude` is ever spawned.

    use softfig_growlightd::{Daemon, DaemonHandle, GrowlightdConfig};
    use softfig_ipc::connect;

    /// Boot a real growlightd on a temp socket; returns the handle, its socket,
    /// and the temp dir to clean up.
    fn boot_growlightd(tag: &str) -> (DaemonHandle, PathBuf, PathBuf) {
        let dir = unique_tmp(tag);
        fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("growlightd.sock");
        let garden = dir.join("garden");
        let handle = Daemon::new(GrowlightdConfig::new(socket.clone(), garden))
            .start()
            .expect("growlightd boots");
        (handle, socket, dir)
    }

    /// Wait until `cond` holds (subscription registered, etc.) or panic.
    fn wait_until(mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "condition not met in time");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn status_client_reads_the_fleet_over_the_socket() {
        let (handle, socket, dir) = boot_growlightd("client-status");
        // The typed reply path the `status` subcommand decodes.
        let reply: FleetStatusReply =
            growlight_call(&socket, growlightd::op::STATUS, serde_json::Value::Null).unwrap();
        assert_eq!(reply.state, "running");
        assert!(reply.garden_root.ends_with("garden"));
        assert!(!reply.paused, "starts un-paused");
        assert_eq!(reply.policy.max_concurrent_agents, 2);
        assert!(reply.agents.is_empty(), "phase-1 fleet is empty");
        // The whole subcommand entry point dispatches + decodes without error.
        client_status(ClientArgs { socket: Some(socket.clone()) }).unwrap();
        handle.shutdown();
        handle.join().unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pause_resume_clients_flip_the_gate_and_status_reflects_it() {
        let (handle, socket, dir) = boot_growlightd("client-pause");
        let p: PausedReply =
            growlight_call(&socket, growlightd::op::PAUSE, serde_json::Value::Null).unwrap();
        assert!(p.paused);
        let s: FleetStatusReply =
            growlight_call(&socket, growlightd::op::STATUS, serde_json::Value::Null).unwrap();
        assert!(s.paused, "pause surfaces in status over the socket");
        let r: PausedReply =
            growlight_call(&socket, growlightd::op::RESUME, serde_json::Value::Null).unwrap();
        assert!(!r.paused);
        // Entry points dispatch cleanly (idempotent — re-pausing stays paused).
        // The no-item `resume` keeps clearing the admission gate (back-compat).
        client_pause(ClientArgs { socket: Some(socket.clone()) }).unwrap();
        client_resume(ResumeArgs {
            socket: Some(socket.clone()),
            item: None,
            queue: None,
        })
        .unwrap();
        handle.shutdown();
        handle.join().unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stop_client_applies_each_level_over_the_socket() {
        let (handle, socket, dir) = boot_growlightd("client-stop");
        // Graceful: records a boundary intent (immediate=false), honoured once.
        let r: StopReply = growlight_call(
            &socket,
            growlightd::op::FORCE_STOP,
            serde_json::to_value(ForceStopArgs {
                agent: "loop-1".into(),
                level: StopLevel::AfterIteration,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(r.agent, "loop-1");
        assert_eq!(r.level, StopLevel::AfterIteration);
        assert!(!r.immediate);
        assert_eq!(
            handle.daemon.take_pending_stop("loop-1"),
            Some(StopLevel::AfterIteration)
        );
        // hard-kill acts immediately (no live child in phase 1, but reports it).
        let r: StopReply = growlight_call(
            &socket,
            growlightd::op::FORCE_STOP,
            serde_json::to_value(ForceStopArgs {
                agent: "loop-1".into(),
                level: StopLevel::HardKill,
            })
            .unwrap(),
        )
        .unwrap();
        assert!(r.immediate, "hard-kill is the immediate escape hatch");
        // The subcommand entry point maps the clap arg → wire level and records it.
        client_stop(StopArgs {
            socket: Some(socket.clone()),
            agent: "loop-1".into(),
            level: StopLevelArg::AfterSlice,
        })
        .unwrap();
        assert_eq!(
            handle.daemon.take_pending_stop("loop-1"),
            Some(StopLevel::AfterSlice),
            "client_stop recorded the after-slice boundary intent",
        );
        handle.shutdown();
        handle.join().unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn watch_stream_renders_each_event_kind_and_stops_at_eof() {
        let frames = [
            Event::agent_delta("loop-1", AgentDeltaKind::Assistant, "hello"),
            Event::agent_delta("loop-1", AgentDeltaKind::Thinking, "hmm"),
            Event::BudgetChanged {
                agent: Some("loop-1".into()),
                ctx_pct: Some(42),
                session_5h_pct: Some(12),
                session_7d_pct: None,
            },
            Event::LeaseChanged {
                lease: "snapshot:pkgs".into(),
                holder: Some("loop-1".into()),
                state: "granted".into(),
            },
            Event::BusMessage {
                from: "human".into(),
                to: "all".into(),
                kind: "note".into(),
                body: "hi".into(),
            },
        ];
        let mut input = String::new();
        for f in &frames {
            input.push_str(&serde_json::to_string(f).unwrap());
            input.push('\n');
        }
        // A blank line + a garbage frame must be tolerated, not fatal.
        input.push('\n');
        input.push_str("{not json}\n");

        let mut reader = std::io::Cursor::new(input.into_bytes());
        let mut out = Vec::new();
        watch_stream(&mut reader, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("[loop-1] say hello"), "{text}");
        assert!(text.contains("[loop-1] think hmm"), "{text}");
        assert!(text.contains("[loop-1] budget ctx 42% · 5h 12%"), "{text}");
        assert!(text.contains("lease snapshot:pkgs granted (holder loop-1)"), "{text}");
        assert!(text.contains("bus human→all [note] hi"), "{text}");
        assert!(
            text.contains("unrecognized event frame"),
            "a bad frame is noted, not fatal: {text}"
        );
    }

    /// THE milestone e2e (finish criterion): growlightd drives a fake agent
    /// (scripted events via the hub) while a CLI client observes the `watch`
    /// stream AND exercises a control verb (pause → status shows `paused:true`),
    /// all over the real IPC socket.
    #[test]
    fn e2e_client_watches_a_fake_agent_and_controls_over_the_real_socket() {
        let (handle, socket, dir) = boot_growlightd("client-e2e");

        // Observe leg: the `watch` wire path — connect + send the streaming
        // subscribe, exactly as `client_watch` does.
        let mut stream = connect(&socket).expect("client connects");
        send_subscribe(&mut stream).unwrap();
        // Register before publishing, else the events race ahead of the
        // subscriber and are dropped (mirrors subscribe_stream.rs).
        wait_until(|| handle.daemon.hub.subscriber_count() >= 1);

        // The fake agent backend: growlightd publishes scripted deltas through
        // the same hub seam a real `claude -p` tailer would.
        let scripted = [
            Event::agent_delta("loop-1", AgentDeltaKind::Assistant, "starting slice 004"),
            Event::agent_delta("loop-1", AgentDeltaKind::ToolCall, "edit(cmd_growlight.rs)"),
        ];
        for e in &scripted {
            handle.daemon.hub.publish(e.clone());
        }

        // Read them back live as newline-framed Event JSON and render each
        // through the watch path (read_line → decode Event → render_event).
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        for expected in &scripted {
            let mut line = String::new();
            let n = reader.read_line(&mut line).expect("read event frame");
            assert!(n > 0, "stream closed early");
            let got: Event = serde_json::from_str(line.trim_end()).expect("decode Event");
            assert_eq!(&got, expected);
            assert!(
                render_event(&got).starts_with("[loop-1] "),
                "the watch renderer formats the live frame"
            );
        }

        // Control leg: pause over the socket, then the status client reflects it
        // — a CLI control verb observable through another CLI client, end to end.
        let p: PausedReply =
            growlight_call(&socket, growlightd::op::PAUSE, serde_json::Value::Null).unwrap();
        assert!(p.paused);
        let s: FleetStatusReply =
            growlight_call(&socket, growlightd::op::STATUS, serde_json::Value::Null).unwrap();
        assert!(s.paused, "the pause is visible via the status client");
        assert!(handle.daemon.is_paused(), "and to the drive loop's gate");

        handle.shutdown();
        handle.join().unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    /// Surface (finish criterion): `start` keeps its interactive flags and the
    /// growlightd client subcommands are purely additive (no shadowing), while
    /// the retired `--auto`/`--max-iterations` flags are gone — growlightd is the
    /// single autonomous control plane now (milestone
    /// growlightd-single-control-plane). No real `claude` is spawned — we only
    /// parse.
    #[test]
    fn start_keeps_interactive_flags_and_clients_are_additive_with_auto_retired() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: GrowlightCmd,
        }

        // `start --no-launch` still parses (the interactive launcher surface).
        match TestCli::try_parse_from(["g", "start", "--no-launch"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Start(a) => assert!(a.no_launch),
            other => panic!("expected Start, got {other:?}"),
        }
        // The retired headless flags no longer parse (`--auto` was growlightd's
        // redundant standalone twin).
        assert!(
            TestCli::try_parse_from(["g", "start", "--auto"]).is_err(),
            "--auto is retired"
        );
        assert!(
            TestCli::try_parse_from(["g", "start", "--max-iterations", "3"]).is_err(),
            "--max-iterations is retired"
        );

        // The new client subcommands parse without shadowing init/start.
        assert!(matches!(
            TestCli::try_parse_from(["g", "status"]).unwrap().cmd,
            GrowlightCmd::Status(_)
        ));
        assert!(matches!(
            TestCli::try_parse_from(["g", "watch"]).unwrap().cmd,
            GrowlightCmd::Watch(_)
        ));
        assert!(matches!(
            TestCli::try_parse_from(["g", "pause"]).unwrap().cmd,
            GrowlightCmd::Pause(_)
        ));
        assert!(matches!(
            TestCli::try_parse_from(["g", "resume"]).unwrap().cmd,
            GrowlightCmd::Resume(_)
        ));
        assert!(matches!(
            TestCli::try_parse_from(["g", "init"]).unwrap().cmd,
            GrowlightCmd::Init(_)
        ));

        // `stop` takes a required --agent and an optional kebab-case --level.
        match TestCli::try_parse_from(["g", "stop", "--agent", "loop-1", "--level", "hard-kill"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Stop(a) => {
                assert_eq!(a.agent, "loop-1");
                assert_eq!(a.level, StopLevelArg::HardKill);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
        // Default level is after-slice; missing --agent is a parse error.
        match TestCli::try_parse_from(["g", "stop", "--agent", "a1"]).unwrap().cmd {
            GrowlightCmd::Stop(a) => assert_eq!(a.level, StopLevelArg::AfterSlice),
            other => panic!("expected Stop, got {other:?}"),
        }
        assert!(TestCli::try_parse_from(["g", "stop"]).is_err());
    }
}
