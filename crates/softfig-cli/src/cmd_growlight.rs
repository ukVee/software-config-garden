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
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use softfig_ipc::{
    ClientError, runtime_socket_path,
    verbs::{GrowlightInitArgs, GrowlightInitReply, StatusReply, op},
};

use crate::cmd_daemon::try_daemon_call;
use crate::growlight_backend::{AgentBackend, ClaudeBackend, IterationOutcome, IterationRequest};

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
    /// Headless full-auto orchestrator (spec §13 phase 5): instead of the
    /// interactive loop, drive `claude -p` in a loop — a fresh process per
    /// iteration (the context ROLL), the baton the only carried state, budgets
    /// parsed from each result (the §6 full-auto read path) — until the baton
    /// reaches a terminal status, the spin guard trips, or `--max-iterations` is
    /// hit. Semi-auto interactive stays the default.
    #[arg(long)]
    pub auto: bool,
    /// Cap on `--auto` iterations (default: unbounded — drive until a terminal
    /// baton status). `--max-iterations 1` reproduces a single headless shot.
    /// Ignored without `--auto`.
    #[arg(long)]
    pub max_iterations: Option<u64>,
}

pub fn run(cmd: GrowlightCmd) -> Result<()> {
    match cmd {
        GrowlightCmd::Init(args) => init(args),
        GrowlightCmd::Start(args) => start(args),
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
    let inject_path = runtime.join("inject.sh");
    let statusline_path = runtime.join("statusline.sh");
    let baton_path = runtime.join("baton.md");
    let questions_path = runtime.join("questions.md");

    // Generated + derived → always refreshed (self-heal if paths moved).
    write_file(&loop_path, &loop_json(&inject_path, &statusline_path))?;
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
    // loudly rather than fail quietly. The headless `--auto` path reads budgets
    // from the `-p` result instead of the statusline, so it doesn't need jq.
    if !args.auto && !jq_present() {
        eprintln!(
            "warning: `jq` not found on PATH — the statusline can't write usage.json, so the \
             loop's budget tracking (context / 5h) won't work. Install jq."
        );
    }

    if args.no_launch {
        println!(
            "\n(--no-launch) runtime ready. launch with:\n  {AGENT_BIN} --name {AGENT_NAME} \
             --settings {}",
            loop_path.display()
        );
        return Ok(());
    }
    if args.auto {
        let backend = ClaudeBackend::new(AGENT_BIN);
        let usage_path = runtime.join("usage.json");
        let log_path = runtime.join("auto-run.log");
        let mut log = open_run_log(&log_path)?;
        println!(
            "\n(--auto) headless orchestrator: driving `{AGENT_BIN} -p` until terminal baton \
             status …\n"
        );
        let summary = run_auto_loop(
            &backend,
            &loop_path,
            &baton_path,
            &usage_path,
            args.max_iterations,
            &mut log,
        )?;
        print_loop_summary(&summary, &usage_path, &log_path);
        return Ok(());
    }
    launch_agent(&loop_path)
}

// ---- headless orchestrator (full-auto, slices 001-002) -----------------

/// The prompt that kicks a headless iteration. The SessionStart hook (which
/// fires under `-p`) injects the full protocol + baton; this just tells the
/// agent to boot and act on it.
const KICK_PROMPT: &str = "Begin this growlight iteration. The operating protocol and your \
    current baton have been injected above — boot per protocol step 1, execute NEXT ACTION as one \
    coherent chunk, then hand off by rewriting the baton.";

/// Baton statuses on which the orchestrator keeps driving (re-invokes a fresh
/// iteration). Everything else — QUEUE_EMPTY / STUCK / BLOCKED_ON_HUMAN /
/// HALTED_RATE_LIMIT, and any unrecognized or missing status — stops the loop.
/// (Pausing and resuming on HALTED_RATE_LIMIT is slice 003's budget governor;
/// here it just stops.)
fn is_continue_status(status: &str) -> bool {
    matches!(status, "IN_PROGRESS" | "ITEM_COMPLETE")
}

/// Trip the spin guard once the baton's NEXT ACTION repeats unchanged across
/// this many consecutive iterations (protocol step 6) — the orchestrator's
/// backstop for an agent that keeps reporting IN_PROGRESS without moving.
const STALL_LIMIT: usize = 2;

/// Why the `--auto` loop stopped.
#[derive(Debug, PartialEq)]
enum StopReason {
    /// The last iteration wrote a terminal baton status (carried here).
    Terminal(String),
    /// NEXT ACTION was unchanged across `STALL_LIMIT` iterations → STUCK.
    SpinGuard,
    /// `--max-iterations` was reached with a still-non-terminal baton.
    MaxIterations,
}

/// The outcome of an `--auto` loop run, for the closing summary.
#[derive(Debug)]
struct LoopSummary {
    iterations: u64,
    stop: StopReason,
    last_status: String,
    last_item: Option<String>,
}

/// Drive the agent headlessly in a loop: re-invoke a fresh process per iteration
/// (the fresh process *is* the context ROLL; the baton is the only carried
/// state) until the baton reaches a terminal status, the spin guard trips, or
/// `max_iterations` is hit. Each iteration persists budgets to `usage.json` (via
/// [`run_auto`]) and is recorded to `log` — the orchestrator's run log, which
/// lives in the runtime dir, never the garden (spec §3). Generic over the
/// backend so the driver is testable with a scripted fake — no `claude` spawn.
fn run_auto_loop(
    backend: &dyn AgentBackend,
    loop_path: &Path,
    baton_path: &Path,
    usage_path: &Path,
    max_iterations: Option<u64>,
    log: &mut dyn Write,
) -> Result<LoopSummary> {
    let bound = max_iterations
        .map(|m| m.to_string())
        .unwrap_or_else(|| "unbounded".to_string());
    let _ = writeln!(log, "--- growlight --auto run (max_iterations={bound}) ---");

    let mut iterations: u64 = 0;
    let mut prev_next_action: Option<String> = None;
    let mut same_streak: usize = 0;
    let mut last_status = "UNKNOWN".to_string();
    let mut last_item: Option<String> = None;

    loop {
        // Don't start an iteration past the cap (or after a terminal status,
        // which returns below before looping).
        if let Some(max) = max_iterations {
            if iterations >= max {
                let _ = writeln!(log, "stop: --max-iterations ({max}) reached");
                return Ok(LoopSummary {
                    iterations,
                    stop: StopReason::MaxIterations,
                    last_status,
                    last_item,
                });
            }
        }

        let (outcome, view) = run_auto(backend, loop_path, baton_path, usage_path)?;
        iterations += 1;

        let status = view.status.clone().unwrap_or_else(|| "UNKNOWN".to_string());
        last_status = status.clone();
        last_item = view.item.clone();

        let line = format!(
            "iter {iterations}: item={} baton_iter={} status={}{} ctx={}%",
            view.item.as_deref().unwrap_or("-"),
            view.iteration
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".to_string()),
            status,
            if outcome.is_error { " (agent ERROR)" } else { "" },
            outcome.usage.context_window.used_percentage,
        );
        let _ = writeln!(log, "{line}");
        println!("  {line}");
        if let Some(text) = outcome.result_text.as_deref().map(str::trim) {
            if !text.is_empty() {
                let preview = first_line_preview(text, 100);
                let _ = writeln!(log, "       said: {preview}");
                println!("       {preview}");
            }
        }

        // Terminal status → stop before starting another iteration.
        if !is_continue_status(&status) {
            let _ = writeln!(log, "stop: terminal baton status {status}");
            return Ok(LoopSummary {
                iterations,
                stop: StopReason::Terminal(status),
                last_status,
                last_item,
            });
        }

        // Spin guard (protocol step 6): NEXT ACTION unchanged across iterations.
        let stalled = match (prev_next_action.as_deref(), view.next_action.as_deref()) {
            (Some(p), Some(c)) => p == c,
            _ => false,
        };
        same_streak = if stalled { same_streak + 1 } else { 1 };
        prev_next_action = view.next_action.clone();
        if same_streak >= STALL_LIMIT {
            let _ = writeln!(
                log,
                "stop: spin guard — NEXT ACTION unchanged across {same_streak} iterations (STUCK)"
            );
            return Ok(LoopSummary {
                iterations,
                stop: StopReason::SpinGuard,
                last_status,
                last_item,
            });
        }
    }
}

/// Drive ONE headless iteration through the agent-backend seam: invoke, persist
/// the parsed budgets in the `usage.json` shape (so semi-auto and full-auto are
/// interchangeable downstream), and re-read the baton. Generic over the backend
/// so the driver is testable with a scripted fake; the loop is the caller.
fn run_auto(
    backend: &dyn AgentBackend,
    loop_path: &Path,
    baton_path: &Path,
    usage_path: &Path,
) -> Result<(IterationOutcome, BatonView)> {
    let req = IterationRequest {
        settings: loop_path.to_path_buf(),
        prompt: KICK_PROMPT.to_string(),
    };
    let outcome = backend.run_iteration(&req)?;

    // The §6 full-auto budget read path: persist the parsed budgets where the
    // semi-auto statusline would have teed them.
    let usage_json = format!("{}\n", serde_json::to_string_pretty(&outcome.usage)?);
    write_file(usage_path, &usage_json)?;

    let baton = fs::read_to_string(baton_path).unwrap_or_default();
    Ok((outcome, parse_baton(&baton)))
}

fn print_loop_summary(summary: &LoopSummary, usage_path: &Path, log_path: &Path) {
    println!(
        "\norchestrator stopped after {} iteration(s):",
        summary.iterations
    );
    match &summary.stop {
        StopReason::Terminal(s) => println!("  reason   terminal baton status: {s}"),
        StopReason::SpinGuard => {
            println!("  reason   spin guard — NEXT ACTION unchanged (STUCK)")
        }
        StopReason::MaxIterations => println!("  reason   --max-iterations reached"),
    }
    println!("  item     {}", summary.last_item.as_deref().unwrap_or("-"));
    println!("  status   {}", summary.last_status);
    println!("  budgets  {}", usage_path.display());
    println!("  run log  {}", log_path.display());
}

/// Open (creating if needed) the orchestrator's run log in append mode. The log
/// lives in the runtime dir, never the garden (spec §3 garden/runtime split).
fn open_run_log(path: &Path) -> Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening run log {}", path.display()))
}

/// First line of `text`, truncated to at most `max` chars, with an ellipsis if
/// anything was dropped. Char-boundary safe.
fn first_line_preview(text: &str, max: usize) -> String {
    let line = text.lines().next().unwrap_or("");
    let mut out: String = line.chars().take(max).collect();
    if line.chars().count() > max || text.lines().nth(1).is_some() {
        out.push('…');
    }
    out
}

/// The fields the orchestrator reads back from the runtime baton each iteration:
/// the terminal-status signal plus the progress signal (item / iteration /
/// NEXT ACTION) the spin guard keys off.
struct BatonView {
    status: Option<String>,
    item: Option<String>,
    iteration: Option<u64>,
    next_action: Option<String>,
}

/// Parse the runtime baton: `status` / `item` / `iteration` from the YAML
/// frontmatter and the `# NEXT ACTION` section body. Pure; the orchestrator
/// re-reads this after every iteration to decide whether to keep driving.
fn parse_baton(baton: &str) -> BatonView {
    let mut status = None;
    let mut item = None;
    let mut iteration = None;

    let mut lines = baton.lines();
    // Frontmatter opens with a `---` fence.
    if lines.next().map(str::trim) == Some("---") {
        for line in lines.by_ref() {
            let line = line.trim();
            if line == "---" {
                break;
            }
            if let Some(v) = line.strip_prefix("status:") {
                let v = v.trim();
                if !v.is_empty() {
                    status = Some(v.to_string());
                }
            } else if let Some(v) = line.strip_prefix("item:") {
                let v = v.trim();
                if !v.is_empty() && v != "null" {
                    item = Some(v.to_string());
                }
            } else if let Some(v) = line.strip_prefix("iteration:") {
                iteration = v.trim().parse::<u64>().ok();
            }
        }
    }

    BatonView {
        status,
        item,
        iteration,
        next_action: extract_section(baton, "# NEXT ACTION"),
    }
}

/// Extract a top-level (`# `) section body from the baton — everything between
/// `heading` and the next `# ` heading — trimmed. `None` if absent or empty.
fn extract_section(baton: &str, heading: &str) -> Option<String> {
    let mut body: Vec<&str> = Vec::new();
    let mut in_section = false;
    for line in baton.lines() {
        if in_section {
            if line.starts_with("# ") {
                break;
            }
            body.push(line);
        } else if line.trim() == heading {
            in_section = true;
        }
    }
    if !in_section {
        return None;
    }
    let trimmed = body.join("\n").trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
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

fn launch_agent(loop_path: &Path) -> Result<()> {
    println!("\nlaunching {AGENT_BIN} --name {AGENT_NAME} …\n");
    let status = std::process::Command::new(AGENT_BIN)
        .arg("--name")
        .arg(AGENT_NAME)
        .arg("--settings")
        .arg(loop_path)
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
fn loop_json(inject: &Path, statusline: &Path) -> String {
    let inject = inject.display().to_string();
    let session_start_block = |source: &str| {
        serde_json::json!({
            "matcher": source,
            "hooks": [ { "type": "command", "command": inject } ]
        })
    };
    let v = serde_json::json!({
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
printf '%s' "$input" | jq '{context_window, rate_limits, ts: now}' > @USAGE@ 2>/dev/null || true
ctx=$(printf '%s' "$input" | jq -r '.context_window.used_percentage // 0' 2>/dev/null || echo 0)
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
        let json: serde_json::Value =
            serde_json::from_str(&loop_json(inject, statusline)).expect("valid JSON");

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

    // ---- headless single-shot driver (slice 001) -----------------------

    use std::cell::Cell;

    use crate::growlight_backend::{
        ContextWindow, IterationOutcome, RateLimits, RateWindow, UsageSnapshot,
    };

    #[test]
    fn first_line_preview_truncates_on_chars_and_extra_lines() {
        assert_eq!(first_line_preview("short", 100), "short");
        assert_eq!(first_line_preview("one\ntwo", 100), "one…"); // more lines
        assert_eq!(first_line_preview("abcdef", 3), "abc…"); // char limit
        // Multibyte: must not split a char (no panic) and counts by char.
        assert_eq!(first_line_preview("héllo", 2), "hé…");
    }

    #[test]
    fn parse_baton_reads_frontmatter_and_the_next_action_section() {
        let baton = "---\nloop: g\nstatus: QUEUE_EMPTY\nitem: full-auto-orchestrator\n\
                     item_type: milestone\niteration: 4\n---\n# NEXT ACTION\ndo the thing\n\
                     more detail\n\n# FINISH CRITERIA\nstatus: not-this\n";
        let v = parse_baton(baton);
        assert_eq!(v.status.as_deref(), Some("QUEUE_EMPTY"));
        // `item:` must not be confused with `item_type:`.
        assert_eq!(v.item.as_deref(), Some("full-auto-orchestrator"));
        assert_eq!(v.iteration, Some(4));
        // NEXT ACTION stops at the next `# ` heading and ignores the body's
        // `status:` line.
        assert_eq!(v.next_action.as_deref(), Some("do the thing\nmore detail"));

        // No frontmatter fence → no fields.
        let none = parse_baton("status: nope\n");
        assert!(none.status.is_none());
        assert!(none.next_action.is_none());

        // `item: null` is treated as absent.
        let nullish = parse_baton("---\nstatus: IN_PROGRESS\nitem: null\n---\n# NEXT ACTION\nx\n");
        assert!(nullish.item.is_none());
        assert_eq!(nullish.status.as_deref(), Some("IN_PROGRESS"));
        assert_eq!(nullish.next_action.as_deref(), Some("x"));
    }

    /// A scripted backend (the §12 seam's test double) so the driver runs with
    /// no `claude` spawn.
    struct FakeBackend {
        is_error: bool,
        ctx_pct: u8,
    }

    impl AgentBackend for FakeBackend {
        fn run_iteration(&self, req: &IterationRequest) -> Result<IterationOutcome> {
            // The driver must hand us the generated settings + a real kick.
            assert!(!req.settings.as_os_str().is_empty());
            assert!(!req.prompt.is_empty());
            Ok(IterationOutcome {
                is_error: self.is_error,
                result_text: Some("done".to_string()),
                usage: UsageSnapshot {
                    context_window: ContextWindow {
                        used_percentage: self.ctx_pct,
                        remaining_percentage: 100 - self.ctx_pct,
                        context_window_size: 1_000_000,
                        current_tokens: 12_345,
                    },
                    rate_limits: RateLimits {
                        five_hour: RateWindow {
                            used_percentage: None,
                            resets_at: Some(1781666400),
                            status: Some("allowed".to_string()),
                        },
                        seven_day: RateWindow::default(),
                    },
                    ts: 42.0,
                },
            })
        }
    }

    #[test]
    fn run_auto_persists_usage_in_the_usage_json_shape_and_reads_back_status() {
        let dir = unique_tmp("auto");
        fs::create_dir_all(&dir).unwrap();
        let loop_path = dir.join("loop.json");
        fs::write(&loop_path, "{}").unwrap();
        let baton = dir.join("baton.md");
        fs::write(&baton, "---\nstatus: BLOCKED_ON_HUMAN\nitem: null\n---\n# NEXT ACTION\n").unwrap();
        let usage = dir.join("usage.json");

        let (outcome, view) = run_auto(
            &FakeBackend {
                is_error: false,
                ctx_pct: 7,
            },
            &loop_path,
            &baton,
            &usage,
        )
        .unwrap();

        // Baton fields read back through the seam.
        assert_eq!(view.status.as_deref(), Some("BLOCKED_ON_HUMAN"));
        assert!(!outcome.is_error);
        assert_eq!(outcome.usage.context_window.used_percentage, 7);
        assert_eq!(
            outcome.usage.rate_limits.five_hour.status.as_deref(),
            Some("allowed")
        );

        // usage.json persisted in the statusline-compatible shape.
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&usage).unwrap()).unwrap();
        assert_eq!(v["context_window"]["used_percentage"], 7);
        assert_eq!(v["context_window"]["context_window_size"], 1_000_000);
        assert_eq!(v["rate_limits"]["five_hour"]["status"], "allowed");
        assert_eq!(v["rate_limits"]["five_hour"]["resets_at"], 1781666400i64);
        // Headless: no rate-limit percentage.
        assert!(v["rate_limits"]["five_hour"]["used_percentage"].is_null());

        fs::remove_dir_all(&dir).ok();
    }

    // ---- the orchestration loop (slice 002) ----------------------------

    /// A scripted backend (the §12 seam's test double) that simulates the
    /// agent's per-iteration baton write: each call writes the next scripted
    /// baton to `baton_path`, so the driver re-reads a *changing* baton with no
    /// `claude` spawn. The call count proves fresh-process-per-iteration and
    /// that no iteration runs after a terminal status.
    struct ScriptedBackend {
        baton_path: PathBuf,
        batons: Vec<String>,
        calls: Cell<usize>,
    }

    impl ScriptedBackend {
        fn new(baton_path: &Path, batons: Vec<String>) -> Self {
            Self {
                baton_path: baton_path.to_path_buf(),
                batons,
                calls: Cell::new(0),
            }
        }
    }

    impl AgentBackend for ScriptedBackend {
        fn run_iteration(&self, req: &IterationRequest) -> Result<IterationOutcome> {
            // The driver must hand us the generated settings + a real kick.
            assert!(!req.settings.as_os_str().is_empty());
            assert!(!req.prompt.is_empty());
            let i = self.calls.get();
            let content = self
                .batons
                .get(i)
                .or_else(|| self.batons.last())
                .cloned()
                .unwrap_or_default();
            fs::write(&self.baton_path, content).unwrap();
            self.calls.set(i + 1);
            Ok(IterationOutcome {
                is_error: false,
                result_text: Some(format!("iteration {i} done")),
                usage: UsageSnapshot {
                    context_window: ContextWindow {
                        used_percentage: 10,
                        remaining_percentage: 90,
                        context_window_size: 1_000_000,
                        current_tokens: 100_000,
                    },
                    rate_limits: RateLimits::default(),
                    ts: 0.0,
                },
            })
        }
    }

    /// A baton with the given frontmatter status/item and NEXT ACTION body.
    fn fm(status: &str, item: &str, next_action: &str) -> String {
        format!("---\nstatus: {status}\nitem: {item}\niteration: 1\n---\n# NEXT ACTION\n{next_action}\n")
    }

    /// `(dir, loop_path, baton, usage)` for a loop test; the loop file is a stub
    /// (the scripted backend never reads it, only asserts it's non-empty).
    fn loop_paths(tag: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let dir = unique_tmp(tag);
        fs::create_dir_all(&dir).unwrap();
        let loop_path = dir.join("loop.json");
        fs::write(&loop_path, "{}").unwrap();
        (dir.clone(), loop_path, dir.join("baton.md"), dir.join("usage.json"))
    }

    #[test]
    fn loop_stops_on_each_terminal_status_without_an_extra_iteration() {
        for status in ["QUEUE_EMPTY", "STUCK", "BLOCKED_ON_HUMAN"] {
            let (dir, loop_path, baton, usage) = loop_paths(&format!("term-{status}"));
            let backend = ScriptedBackend::new(&baton, vec![fm(status, "x", "na")]);
            let mut log = Vec::new();
            let summary =
                run_auto_loop(&backend, &loop_path, &baton, &usage, None, &mut log).unwrap();
            assert_eq!(summary.iterations, 1, "{status}: exactly one iteration");
            assert_eq!(summary.stop, StopReason::Terminal(status.to_string()));
            // No iteration started after the terminal status was written.
            assert_eq!(backend.calls.get(), 1, "{status}: backend called once");
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn loop_drains_a_multi_iteration_backlog_to_queue_empty() {
        let (dir, loop_path, baton, usage) = loop_paths("drain");
        // Fresh process per iteration: each call writes a different baton, the
        // last one terminal. ITEM_COMPLETE is a continue-status.
        let backend = ScriptedBackend::new(
            &baton,
            vec![
                fm("IN_PROGRESS", "item-a", "step 1"),
                fm("IN_PROGRESS", "item-a", "step 2"),
                fm("ITEM_COMPLETE", "item-a", "wrap up"),
                fm("QUEUE_EMPTY", "null", "nothing left"),
            ],
        );
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &loop_path, &baton, &usage, None, &mut log).unwrap();
        assert_eq!(summary.iterations, 4);
        assert_eq!(summary.stop, StopReason::Terminal("QUEUE_EMPTY".to_string()));
        assert_eq!(backend.calls.get(), 4);
        // Budgets persisted each iteration (last write present).
        assert!(usage.exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loop_spin_guard_trips_when_next_action_is_unchanged() {
        let (dir, loop_path, baton, usage) = loop_paths("spin");
        // Same NEXT ACTION every iteration → no progress → STUCK.
        let stuck = fm("IN_PROGRESS", "item-a", "the exact same next action");
        let backend = ScriptedBackend::new(&baton, vec![stuck.clone(), stuck]);
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &loop_path, &baton, &usage, None, &mut log).unwrap();
        assert_eq!(summary.stop, StopReason::SpinGuard);
        assert_eq!(summary.iterations, STALL_LIMIT as u64);
        assert_eq!(backend.calls.get(), STALL_LIMIT);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loop_respects_max_iterations_on_a_progressing_baton() {
        let (dir, loop_path, baton, usage) = loop_paths("maxiter");
        // Always IN_PROGRESS with a *different* NEXT ACTION → never terminal,
        // never spin-guarded; only --max-iterations stops it.
        let backend = ScriptedBackend::new(
            &baton,
            vec![
                fm("IN_PROGRESS", "item-a", "step 1"),
                fm("IN_PROGRESS", "item-a", "step 2"),
                fm("IN_PROGRESS", "item-a", "step 3"),
                fm("IN_PROGRESS", "item-a", "step 4"),
            ],
        );
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &loop_path, &baton, &usage, Some(3), &mut log).unwrap();
        assert_eq!(summary.stop, StopReason::MaxIterations);
        assert_eq!(summary.iterations, 3);
        assert_eq!(backend.calls.get(), 3);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn max_iterations_one_reproduces_the_single_shot() {
        let (dir, loop_path, baton, usage) = loop_paths("single");
        let backend =
            ScriptedBackend::new(&baton, vec![fm("IN_PROGRESS", "item-a", "keep going")]);
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &loop_path, &baton, &usage, Some(1), &mut log).unwrap();
        assert_eq!(summary.iterations, 1);
        assert_eq!(summary.stop, StopReason::MaxIterations);
        assert_eq!(backend.calls.get(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_log_records_iterations_and_the_stop_reason() {
        let (dir, loop_path, baton, usage) = loop_paths("log");
        let backend = ScriptedBackend::new(
            &baton,
            vec![
                fm("IN_PROGRESS", "item-a", "go"),
                fm("QUEUE_EMPTY", "null", "done"),
            ],
        );
        let mut log = Vec::new();
        run_auto_loop(&backend, &loop_path, &baton, &usage, None, &mut log).unwrap();
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("iter 1:"), "log: {text}");
        assert!(text.contains("iter 2:"), "log: {text}");
        assert!(text.contains("status=QUEUE_EMPTY"), "log: {text}");
        assert!(
            text.contains("stop: terminal baton status QUEUE_EMPTY"),
            "log: {text}"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
