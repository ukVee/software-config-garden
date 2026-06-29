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
    baton::{parse_baton, BatonDisposition, BatonView},
    growlightd::{
        self, AgentDeltaKind, BuildCapsSummary, Event, FleetStatusReply, ForceStopArgs,
        PausedReply, ResumeItemArgs, ResumeItemReply, SetResourcesArgs, SetResourcesReply,
        StopLevel, StopReply,
    },
    verbs::{GrowlightInitArgs, GrowlightInitReply, PostMessageArgs, PostMessageReply, StatusReply, op},
};

use softfig_growlightd_client::{decode_frame, Frame};

use crate::cmd_daemon::try_daemon_call;
use crate::growlight_backend::{
    AgentBackend, ClaudeBackend, Clock, ExeIdentity, ExeProbe, IterationOutcome, IterationRequest,
    RateWindow, SystemClock, SystemExeProbe, UsageSnapshot,
};

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

    /// Inspect or adjust the GENTLE per-agent build-resource caps LIVE
    /// (peer-isolation slice 003): the SOFT throttle (`CARGO_BUILD_JOBS` /
    /// `MemoryHigh` / `CPUWeight`) each agent's transient scope is capped with. A
    /// live `set` adjusts a running fleet without a daemon restart and stays
    /// throttle-not-kill (no hard `MemoryMax` cap).
    Resources(ResourcesArgs),
}

/// `growlight resources {show, set}` — the live build-resource-cap surface.
#[derive(Args, Debug)]
pub struct ResourcesArgs {
    #[command(subcommand)]
    pub cmd: ResourcesCmd,
}

#[derive(Subcommand, Debug)]
pub enum ResourcesCmd {
    /// Show the current build-resource caps — the live default the NEXT spawned
    /// agent's scope is throttled with — plus the roster scopes a live `set` would
    /// reconcile.
    Show(ClientArgs),

    /// Adjust the caps LIVE. Each omitted flag keeps its current value (a partial
    /// update). `--memory-high`/`--cpu-weight` apply to running scopes immediately;
    /// `--build-jobs` (`CARGO_BUILD_JOBS`) takes effect at the next spawn. There is
    /// no hard-cap flag — a change can only slow a build, never abort it.
    Set(ResourcesSetArgs),
}

#[derive(Args, Debug)]
pub struct ResourcesSetArgs {
    /// Override the growlightd socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-growlightd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// New `CARGO_BUILD_JOBS` (parallel-`rustc` ceiling; ≥ 1). Next spawn only.
    #[arg(long)]
    pub build_jobs: Option<u32>,
    /// New `MemoryHigh` SOFT throttle (a systemd memory value, e.g. `4G` / `70%`).
    /// Applied to running scopes immediately.
    #[arg(long)]
    pub memory_high: Option<String>,
    /// New `CPUWeight` (1..=10000). Applied to running scopes immediately.
    #[arg(long)]
    pub cpu_weight: Option<u32>,
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
        GrowlightCmd::Resources(args) => client_resources(args),
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
             --settings {} --mcp-config {}",
            loop_path.display(),
            mcp_path.display()
        );
        return Ok(());
    }
    if args.auto {
        let backend = ClaudeBackend::new(AGENT_BIN);
        let clock = SystemClock;
        // Captured before the loop, while our own binary is still the live inode;
        // re-statted between iterations to catch a mid-run reinstall (task 007).
        let exe = SystemExeProbe::capture();
        let usage_path = runtime.join("usage.json");
        let log_path = runtime.join("auto-run.log");
        let mut log = open_run_log(&log_path)?;
        println!(
            "\n(--auto) headless orchestrator: driving `{AGENT_BIN} -p` until terminal baton \
             status …\n"
        );
        let summary = run_auto_loop(
            &backend,
            &clock,
            &exe,
            &loop_path,
            &mcp_path,
            &baton_path,
            &usage_path,
            args.max_iterations,
            &mut log,
        )?;
        print_loop_summary(&summary, &usage_path, &log_path);
        return Ok(());
    }
    launch_agent(&loop_path, &mcp_path)
}

// ---- headless orchestrator (full-auto, slices 001-002) -----------------

/// The prompt that kicks a headless iteration. The SessionStart hook (which
/// fires under `-p`) injects the full protocol + baton; this just tells the
/// agent to boot and act on it.
const KICK_PROMPT: &str = "Begin this growlight iteration. The operating protocol and your \
    current baton have been injected above — boot per protocol step 1, execute NEXT ACTION as one \
    coherent chunk, then hand off by rewriting the baton.";

/// Trip the spin guard once the baton's NEXT ACTION repeats unchanged across
/// this many consecutive iterations (protocol step 6) — the orchestrator's
/// backstop for an agent that keeps reporting IN_PROGRESS without moving.
const STALL_LIMIT: usize = 2;

/// Reserve thresholds (spec §6 / session-policy): stop *starting* iterations once
/// a window crosses these, until it resets. Headless `-p` reports no rate-limit
/// percentage, so the governor's primary signal is the window `status`
/// (non-"allowed"); these percentages apply only to a backend that does report
/// one — and a *missing* percentage is NEVER read as 0 (slice 001's correction).
const FIVE_HOUR_RESERVE_PCT: u8 = 85;
const SEVEN_DAY_RESERVE_PCT: u8 = 90;

/// Why the `--auto` loop stopped.
#[derive(Debug, PartialEq)]
enum StopReason {
    /// The last iteration wrote a terminal baton status (QUEUE_EMPTY, an
    /// agent-written STUCK, an un-resumable HALTED_RATE_LIMIT, or anything
    /// unrecognized) — carried here.
    Terminal(String),
    /// BLOCKED_ON_HUMAN — a hard block with no safe default. Surfaced loudly so
    /// an away human sees the loop needs them (distinct from a clean QUEUE_EMPTY:
    /// the loop must never fabricate the human's decision — protocol step 4/3b).
    BlockedOnHuman,
    /// NEXT ACTION was unchanged across `STALL_LIMIT` iterations → STUCK.
    SpinGuard,
    /// `--max-iterations` was reached with a still-non-terminal baton.
    MaxIterations,
    /// The on-disk `softfig` at the orchestrator's launch path changed mid-run
    /// (a reinstall) → the loop is about to drive another iteration on superseded
    /// code. Per spec §12 the long-lived orchestrator does NOT self-restart, so
    /// this stops loudly for a human-driven relaunch rather than silently
    /// spinning stale flags (the iter-5/6 `--mcp-config` regression).
    BinarySuperseded,
}

/// The orchestrator's between-iteration decision, from the just-finished result.
#[derive(Debug, PartialEq)]
enum LoopStep {
    /// Start the next iteration immediately.
    Continue,
    /// A rate window is exhausted — wait until its reset, then resume.
    Pause(PauseInfo),
    /// Stop the loop.
    Stop(StopReason),
}

/// A budget-governor pause: which window, when it resets, and why (for the log).
#[derive(Debug, PartialEq)]
struct PauseInfo {
    reset_at: i64,
    window: &'static str,
    reason: String,
}

/// Whether a rate window is at/over its reserve: a non-"allowed" headless status,
/// or — for a backend that reports one — a used-percentage at/over `reserve_pct`.
/// A *missing* percentage never trips (slice 001: never read it as `0`).
fn window_tripped(w: &RateWindow, reserve_pct: u8) -> bool {
    matches!(w.status.as_deref(), Some(s) if s != "allowed")
        || matches!(w.used_percentage, Some(p) if p >= reserve_pct)
}

/// If a rate window is over reserve *and* we know when it resets, the pause to
/// take. 7d takes precedence over 5h (the longer wall). `None` when nothing is
/// tripped, or when a tripped window has no known reset (can't time a resume —
/// the caller surfaces that rather than sleeping blind).
fn pause_for(usage: &UsageSnapshot) -> Option<PauseInfo> {
    let seven = &usage.rate_limits.seven_day;
    if window_tripped(seven, SEVEN_DAY_RESERVE_PCT) {
        return seven.resets_at.map(|reset_at| PauseInfo {
            reset_at,
            window: "seven_day",
            reason: format!(
                "7d window {} (reserve {SEVEN_DAY_RESERVE_PCT}%)",
                seven.status.as_deref().unwrap_or("over-reserve")
            ),
        });
    }
    let five = &usage.rate_limits.five_hour;
    if window_tripped(five, FIVE_HOUR_RESERVE_PCT) {
        return five.resets_at.map(|reset_at| PauseInfo {
            reset_at,
            window: "five_hour",
            reason: format!(
                "5h window {} (reserve {FIVE_HOUR_RESERVE_PCT}%)",
                five.status.as_deref().unwrap_or("over-reserve")
            ),
        });
    }
    None
}

/// The soonest known reset across both windows (5h preferred — it's the session
/// budget). Used to time the resume for an agent-declared HALTED_RATE_LIMIT whose
/// window status didn't independently trip the governor.
fn any_reset(usage: &UsageSnapshot) -> Option<(i64, &'static str)> {
    usage
        .rate_limits
        .five_hour
        .resets_at
        .map(|r| (r, "five_hour"))
        .or_else(|| {
            usage
                .rate_limits
                .seven_day
                .resets_at
                .map(|r| (r, "seven_day"))
        })
}

/// The between-iteration decision (pure): from the just-finished baton status +
/// parsed budgets + whether the spin streak hit its limit, decide whether to
/// continue, pause for a rate window, or stop. Effects (log / stamp / sleep) are
/// the loop's — so the governor is unit-tested without real time or a real agent.
///
/// `is_error` alone is *not* a pause trigger: an error without a non-"allowed"
/// window has no reset time to wait for, so it's logged and the agent's baton
/// status governs; the spin guard is the backstop if it makes no progress.
fn decide_step(view: &BatonView, usage: &UsageSnapshot, stalled: bool) -> LoopStep {
    // The status vocabulary is shared with the fleet supervisor
    // ([`softfig_ipc::baton`]); this single-agent driver layers its budget-governor
    // pause + spin guard on top of that classification. The driver folds
    // QueueEmpty/Stuck into one terminal stop (a one-shot session just ends),
    // where the fleet tells them apart.
    match view.classify() {
        // Agent halted on a rate limit → resume at the reset (governor pause),
        // never a terminal stop. Prefer an independently-tripped window, else the
        // soonest known reset; no reset time at all → can't time a resume, so
        // surface it as terminal rather than spin.
        BatonDisposition::RateLimited => pause_for(usage)
            .or_else(|| {
                any_reset(usage).map(|(reset_at, window)| PauseInfo {
                    reset_at,
                    window,
                    reason: "agent HALTED_RATE_LIMIT".to_string(),
                })
            })
            .map(LoopStep::Pause)
            .unwrap_or_else(|| {
                LoopStep::Stop(StopReason::Terminal("HALTED_RATE_LIMIT".to_string()))
            }),
        // Hard human block — surfaced distinctly, never worked around.
        BatonDisposition::BlockedOnHuman => LoopStep::Stop(StopReason::BlockedOnHuman),
        // A drained queue and an agent STUCK/unknown both end this one-shot session.
        BatonDisposition::QueueEmpty => {
            LoopStep::Stop(StopReason::Terminal("QUEUE_EMPTY".to_string()))
        }
        BatonDisposition::Stuck(s) => LoopStep::Stop(StopReason::Terminal(s)),
        // A within-item continue (`IN_PROGRESS`) or an item boundary
        // (`ITEM_COMPLETE` / `ITEM_DEFERRED`): the single-agent driver has no
        // orchestrator, so on a boundary it self-pulls the next item exactly as it
        // keeps driving within an item — both keep going. (The fleet, which DOES
        // have an orchestrator, tells these apart: a boundary releases the member's
        // slot for the orchestrator to re-claim.) Stop if stalled, else pause if a
        // window is over reserve, else keep driving.
        BatonDisposition::Continue | BatonDisposition::ItemBoundary => {
            if stalled {
                LoopStep::Stop(StopReason::SpinGuard)
            } else if let Some(p) = pause_for(usage) {
                LoopStep::Pause(p)
            } else {
                LoopStep::Continue
            }
        }
    }
}

/// Has the launch binary been superseded since startup? True only when both the
/// startup baseline and the current on-disk identity are known *and* differ — a
/// missing reading (un-stattable path) never trips, so the guard can't false-stop
/// a still-current loop. Pure, so the stale-orchestrator guard (task 007) is
/// unit-tested without a real reinstall (the [`ExeProbe`] seam supplies both ends).
fn superseded(baseline: Option<&ExeIdentity>, current: Option<&ExeIdentity>) -> bool {
    matches!((baseline, current), (Some(b), Some(c)) if b != c)
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
// The trailing four paths (loop.json, mcp.json, baton, usage) are one cohesive
// runtime-paths set, all derived together in `start()`; threading them as a
// bundle struct would only obscure a flat driver signature.
#[allow(clippy::too_many_arguments)]
fn run_auto_loop(
    backend: &dyn AgentBackend,
    clock: &dyn Clock,
    exe: &dyn ExeProbe,
    loop_path: &Path,
    mcp_path: &Path,
    baton_path: &Path,
    usage_path: &Path,
    max_iterations: Option<u64>,
    log: &mut dyn Write,
) -> Result<LoopSummary> {
    let bound = max_iterations
        .map(|m| m.to_string())
        .unwrap_or_else(|| "unbounded".to_string());
    let _ = writeln!(log, "--- growlight --auto run (max_iterations={bound}) ---");

    // Stale-orchestrator guard baseline (task 007): the identity of the binary
    // we launched from, captured now and re-checked between iterations.
    let exe_baseline = exe.current_identity();

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

        // Stale-orchestrator guard (task 007). A reinstall during the run replaces
        // the binary at our launch path, but this long-lived process keeps running
        // the OLD code — and would spawn the next `claude -p` child with stale flags
        // (the iter-5/6 `--mcp-config` regression that looked like a code-fix
        // failure and cost two iterations + a human restart to root-cause). Detect
        // the swap *before* spawning the next child and stop loudly. Per spec §12
        // the orchestrator does not self-restart (a launcher upgrade is a human-
        // driven relaunch), so this converts a silent stale spin into an actionable
        // stop. Skipped on the first pass (`iterations == 0`): the baseline was just
        // captured, so it can't yet differ from itself.
        if iterations > 0 && superseded(exe_baseline.as_ref(), exe.current_identity().as_ref()) {
            log_stop(&StopReason::BinarySuperseded, same_streak, log);
            surface_superseded(log);
            return Ok(LoopSummary {
                iterations,
                stop: StopReason::BinarySuperseded,
                last_status,
                last_item,
            });
        }

        let (outcome, view) = run_auto(backend, loop_path, mcp_path, baton_path, usage_path)?;
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

        // Spin streak (protocol step 6): consecutive iterations with an unchanged
        // NEXT ACTION. Computed every iteration; only acted on for a continue-
        // status (a terminal status stops first, in `decide_step`).
        let same = matches!(
            (prev_next_action.as_deref(), view.next_action.as_deref()),
            (Some(p), Some(c)) if p == c
        );
        same_streak = if same { same_streak + 1 } else { 1 };
        prev_next_action = view.next_action.clone();
        let stalled = same_streak >= STALL_LIMIT;

        match decide_step(&view, &outcome.usage, stalled) {
            // Budget governor (between iterations): wait out the rate window, then
            // drive the next iteration on the refreshed budget. The in-session
            // protocol (2b) can only stop the current process; this owns what
            // happens *between* processes.
            LoopStep::Pause(p) => governor_pause(clock, baton_path, &p, log)?,
            LoopStep::Continue => {}
            LoopStep::Stop(reason) => {
                log_stop(&reason, same_streak, log);
                if reason == StopReason::BlockedOnHuman {
                    surface_blocked(&view, log);
                }
                return Ok(LoopSummary {
                    iterations,
                    stop: reason,
                    last_status,
                    last_item,
                });
            }
        }
    }
}

/// Apply a governor pause: surface it (run log + stdout), stamp the runtime baton
/// HALTED_RATE_LIMIT so a human peeking mid-pause sees the halt, then sleep until
/// the reset via the [`Clock`] seam. Returns after the wait; the loop then drives
/// the next iteration on the refreshed budget.
fn governor_pause(
    clock: &dyn Clock,
    baton_path: &Path,
    p: &PauseInfo,
    log: &mut dyn Write,
) -> Result<()> {
    let wait = (p.reset_at - clock.now_unix()).max(0);
    let _ = writeln!(
        log,
        "governor: HALTED_RATE_LIMIT — {} ; pausing {wait}s until reset {}",
        p.reason, p.reset_at
    );
    println!(
        "  governor: rate limit ({}) — pausing {wait}s until reset {}",
        p.window, p.reset_at
    );
    stamp_baton_status(baton_path, "HALTED_RATE_LIMIT")?;
    clock.sleep_until(p.reset_at);
    let _ = writeln!(log, "governor: resumed after rate-limit pause ({})", p.window);
    Ok(())
}

/// Loudly surface a BLOCKED_ON_HUMAN stop: the loop can't proceed without a human
/// and must never fabricate the decision (protocol step 4/3b). Goes to the run
/// log and stderr; the baton's NEXT ACTION carries what's needed.
fn surface_blocked(view: &BatonView, log: &mut dyn Write) {
    let na = view
        .next_action
        .as_deref()
        .map(|n| first_line_preview(n, 200))
        .unwrap_or_else(|| "(see baton NEXT ACTION)".to_string());
    let _ = writeln!(log, "BLOCKED_ON_HUMAN: needs a human decision — {na}");
    eprintln!("\n*** growlight --auto BLOCKED_ON_HUMAN — needs you ***");
    eprintln!("  {na}");
}

/// Loudly surface a [`StopReason::BinarySuperseded`] stop: the orchestrator's own
/// `softfig` was reinstalled mid-run, so it's now executing stale code. Per spec
/// §12 it does not self-restart — tell the human to relaunch onto the new binary.
fn surface_superseded(log: &mut dyn Write) {
    let action = "restart it: `softfig growlight start --auto`";
    let _ = writeln!(
        log,
        "binary superseded: `softfig` was reinstalled while this --auto orchestrator was \
         running — {action}"
    );
    eprintln!("\n*** growlight --auto stopped: binary superseded (reinstalled mid-run) ***");
    eprintln!("  it would keep driving stale code — {action}");
}

/// Record a stop in the run log.
fn log_stop(reason: &StopReason, same_streak: usize, log: &mut dyn Write) {
    let msg = match reason {
        StopReason::Terminal(s) => format!("stop: terminal baton status {s}"),
        StopReason::BlockedOnHuman => "stop: BLOCKED_ON_HUMAN (needs a human)".to_string(),
        StopReason::SpinGuard => format!(
            "stop: spin guard — NEXT ACTION unchanged across {same_streak} iterations (STUCK)"
        ),
        StopReason::MaxIterations => "stop: --max-iterations reached".to_string(),
        StopReason::BinarySuperseded => {
            "stop: binary superseded — `softfig` reinstalled mid-run (stale orchestrator)"
                .to_string()
        }
    };
    let _ = writeln!(log, "{msg}");
}

/// Stamp the runtime baton's frontmatter `status:` (best-effort surfacing for a
/// human peeking mid-pause; the next iteration's agent rewrites the baton). A
/// no-op if the baton can't be read or has no frontmatter status line.
fn stamp_baton_status(baton_path: &Path, new_status: &str) -> Result<()> {
    let Ok(baton) = fs::read_to_string(baton_path) else {
        return Ok(());
    };
    let restamped = restamp_status(&baton, new_status);
    if restamped != baton {
        write_file(baton_path, &restamped)?;
    }
    Ok(())
}

/// Replace the frontmatter `status:` line with `status: <new>` (only within the
/// opening `---` fence — never a `status:` in the body). Returns the input
/// unchanged if there's no frontmatter. Pure.
fn restamp_status(baton: &str, new_status: &str) -> String {
    let mut lines: Vec<String> = baton.lines().map(str::to_string).collect();
    if lines.first().map(|l| l.trim()) != Some("---") {
        return baton.to_string();
    }
    for line in lines.iter_mut().skip(1) {
        if line.trim() == "---" {
            break; // end of frontmatter
        }
        if line.trim_start().starts_with("status:") {
            *line = format!("status: {new_status}");
            break;
        }
    }
    let mut out = lines.join("\n");
    if baton.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Drive ONE headless iteration through the agent-backend seam: invoke, persist
/// the parsed budgets in the `usage.json` shape (so semi-auto and full-auto are
/// interchangeable downstream), and re-read the baton. Generic over the backend
/// so the driver is testable with a scripted fake; the loop is the caller.
fn run_auto(
    backend: &dyn AgentBackend,
    loop_path: &Path,
    mcp_path: &Path,
    baton_path: &Path,
    usage_path: &Path,
) -> Result<(IterationOutcome, BatonView)> {
    let req = IterationRequest {
        settings: loop_path.to_path_buf(),
        mcp_config: mcp_path.to_path_buf(),
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
        StopReason::BlockedOnHuman => {
            println!("  reason   BLOCKED_ON_HUMAN — needs a human (never fabricated)")
        }
        StopReason::SpinGuard => {
            println!("  reason   spin guard — NEXT ACTION unchanged (STUCK)")
        }
        StopReason::MaxIterations => println!("  reason   --max-iterations reached"),
        StopReason::BinarySuperseded => {
            println!("  reason   binary superseded — `softfig` reinstalled mid-run; restart --auto")
        }
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
/// `--auto` run's reach.
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
// — a separate process from keeperd — and REPLACE nothing: the foreground
// `--auto` launcher above stays intact (the milestone's non-disruption
// criterion). `status`/`stop`/`pause`/`resume` are one-shot `call`s reusing the
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

fn client_resources(args: ResourcesArgs) -> Result<()> {
    match args.cmd {
        // `resources show` — the live default caps (off `status`) + the roster
        // scopes a live `set` reconciles. (Per-scope LIVE values via `systemctl
        // show` are an on-device read deferred to the §7b verify.)
        ResourcesCmd::Show(a) => {
            let socket = growlight_socket(a.socket);
            let reply: FleetStatusReply =
                growlight_call(&socket, growlightd::op::STATUS, serde_json::Value::Null)?;
            print!("{}", render_build_caps(&reply.build_caps));
            if reply.roster.is_empty() {
                println!("scopes        (none — fleet disarmed)");
            } else {
                let scopes: Vec<String> = reply
                    .roster
                    .iter()
                    .map(|m| format!("growlight-agent-{}.scope", m.agent))
                    .collect();
                println!("scopes        {}", scopes.join(", "));
            }
            Ok(())
        }
        // `resources set` — adjust the caps live. The all-empty case is refused
        // here (a no-op `set` is almost certainly a mistake) before any daemon call.
        ResourcesCmd::Set(a) => {
            let socket = growlight_socket(a.socket);
            let set_args = build_set_resources_args(a.build_jobs, a.memory_high, a.cpu_weight)?;
            let reply: SetResourcesReply = growlight_call(
                &socket,
                growlightd::op::SET_RESOURCES,
                serde_json::to_value(set_args)?,
            )?;
            print!("{}", render_set_resources_reply(&reply));
            Ok(())
        }
    }
}

/// Build the `set_resources` wire args from the CLI flags, refusing the all-empty
/// case (nothing to set is almost certainly a mistake). Pure — unit-tested.
fn build_set_resources_args(
    build_jobs: Option<u32>,
    memory_high: Option<String>,
    cpu_weight: Option<u32>,
) -> Result<SetResourcesArgs> {
    if build_jobs.is_none() && memory_high.is_none() && cpu_weight.is_none() {
        return Err(anyhow!(
            "nothing to set — pass at least one of --build-jobs / --memory-high / --cpu-weight"
        ));
    }
    Ok(SetResourcesArgs {
        build_jobs,
        memory_high,
        cpu_weight,
    })
}

/// Render the live build-resource caps for the terminal. Pure (returns the text)
/// so it is unit-tested without a daemon.
fn render_build_caps(c: &BuildCapsSummary) -> String {
    let jobs = c
        .cargo_build_jobs
        .map(|j| j.to_string())
        .unwrap_or_else(|| "(unset)".to_string());
    let weight = c
        .cpu_weight
        .map(|w| w.to_string())
        .unwrap_or_else(|| "(unset)".to_string());
    let mem = c.memory_high.as_deref().unwrap_or("(unset)");
    format!(
        "build caps    (live default — the next spawn's throttle)\n  \
         cargo_build_jobs  {jobs}\n  memory_high       {mem}\n  cpu_weight        {weight}\n",
    )
}

/// Render a `set_resources` reply: the new caps + the now-vs-next-spawn surface.
/// Pure (returns the text) so it is unit-tested without a daemon.
fn render_set_resources_reply(r: &SetResourcesReply) -> String {
    let mut out = render_build_caps(&r.build_caps);
    let targeted = r.scopes_targeted.len();
    if r.applied_live.is_empty() {
        // Distinguish "no running scopes" from "targeted N but none took it" — never
        // assert a cause we can't know (slice 003/004). A nothing-changed-live (only
        // build_jobs) also lands here with no scopes targeted.
        if targeted == 0 {
            out.push_str("applied live  (none — no running agent scopes)\n");
        } else {
            out.push_str(&format!(
                "applied live  (none — 0 of {targeted} scope(s) took the update): {}\n",
                r.scopes_targeted.join(", "),
            ));
        }
    } else {
        out.push_str(&format!(
            "applied live  {} on {} of {} scope(s): {}\n",
            r.applied_live.join(", "),
            r.scopes_applied,
            targeted,
            r.scopes_targeted.join(", "),
        ));
    }
    if !r.next_spawn.is_empty() {
        out.push_str(&format!("next spawn    {}\n", r.next_spawn.join(", ")));
    }
    out
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
    fn build_set_resources_args_refuses_an_empty_update() {
        // Every flag omitted ⇒ a no-op set is rejected before any daemon call.
        assert!(build_set_resources_args(None, None, None).is_err());
        // Any single flag present ⇒ a partial update is built, the rest left None.
        let args = build_set_resources_args(None, Some("4G".into()), None)
            .expect("one knob is enough");
        assert_eq!(args.memory_high.as_deref(), Some("4G"));
        assert_eq!(args.build_jobs, None);
        assert_eq!(args.cpu_weight, None);
    }

    #[test]
    fn render_build_caps_shows_unset_knobs_explicitly() {
        let text = render_build_caps(&BuildCapsSummary {
            cargo_build_jobs: Some(2),
            memory_high: Some("3G".into()),
            cpu_weight: None,
        });
        assert!(text.contains("cargo_build_jobs  2"));
        assert!(text.contains("memory_high       3G"));
        assert!(text.contains("cpu_weight        (unset)"), "an unset knob reads (unset): {text}");
    }

    #[test]
    fn render_set_resources_reply_surfaces_now_vs_next_spawn() {
        // No running scopes: applied-live is the explicit (none) line; build-jobs is
        // reported as next-spawn.
        let disarmed = render_set_resources_reply(&SetResourcesReply {
            build_caps: BuildCapsSummary {
                cargo_build_jobs: Some(2),
                memory_high: Some("6G".into()),
                cpu_weight: Some(70),
            },
            applied_live: vec![],
            next_spawn: vec!["CARGO_BUILD_JOBS".into()],
            scopes_targeted: vec![],
            scopes_applied: 0,
        });
        assert!(disarmed.contains("applied live  (none — no running agent scopes)"));
        assert!(disarmed.contains("next spawn    CARGO_BUILD_JOBS"));

        // With running scopes: the live props + applied M of N targeted (slice 004).
        let live = render_set_resources_reply(&SetResourcesReply {
            build_caps: BuildCapsSummary::default(),
            applied_live: vec!["MemoryHigh".into(), "CPUWeight".into()],
            next_spawn: vec![],
            scopes_targeted: vec![
                "growlight-agent-builder-3.scope".into(),
                "growlight-agent-reviewer-4.scope".into(),
            ],
            scopes_applied: 2,
        });
        assert!(live.contains("applied live  MemoryHigh, CPUWeight on 2 of 2 scope(s)"));
        assert!(live.contains("growlight-agent-builder-3.scope"));

        // Targeted but NONE took it (slice 003/004): distinct from "no scopes".
        let all_failed = render_set_resources_reply(&SetResourcesReply {
            build_caps: BuildCapsSummary::default(),
            applied_live: vec![],
            next_spawn: vec!["MemoryHigh".into()],
            scopes_targeted: vec!["growlight-agent-builder-3.scope".into()],
            scopes_applied: 0,
        });
        assert!(
            all_failed.contains("0 of 1 scope(s) took the update"),
            "targeted-but-all-failed renders distinctly from no-scopes: {all_failed}",
        );
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

    use std::cell::{Cell, RefCell};

    use crate::growlight_backend::{
        ContextWindow, IterationOutcome, RateLimits, RateWindow, UsageSnapshot,
    };

    /// A [`Clock`] test double: records every `sleep_until` target instead of
    /// blocking, and advances virtual time to it (so the governor's wait is
    /// asserted without real sleeps).
    struct FakeClock {
        now: Cell<i64>,
        sleeps: RefCell<Vec<i64>>,
    }

    impl FakeClock {
        fn new(now: i64) -> Self {
            Self {
                now: Cell::new(now),
                sleeps: RefCell::new(Vec::new()),
            }
        }
    }

    impl Clock for FakeClock {
        fn now_unix(&self) -> i64 {
            self.now.get()
        }
        fn sleep_until(&self, unix: i64) {
            self.sleeps.borrow_mut().push(unix);
            if unix > self.now.get() {
                self.now.set(unix);
            }
        }
    }

    fn exe_id(ino: u64) -> ExeIdentity {
        ExeIdentity { dev: 1, ino, mtime: 1, size: 1 }
    }

    /// An [`ExeProbe`] whose binary never changes — the launch binary stays the
    /// live inode, so the stale-orchestrator guard must never trip. Used by every
    /// existing loop test that isn't exercising the guard.
    struct StableExe;
    impl ExeProbe for StableExe {
        fn current_identity(&self) -> Option<ExeIdentity> {
            Some(exe_id(1))
        }
    }

    /// An [`ExeProbe`] that reports one identity for its first `flip_after` calls
    /// to `current_identity()`, then a different one — simulating a reinstall
    /// mid-run without touching the filesystem. Call order in the loop is:
    /// baseline (1), then one guard check per pass with `iterations > 0`.
    struct FlipExe {
        calls: Cell<usize>,
        flip_after: usize,
    }
    impl FlipExe {
        fn new(flip_after: usize) -> Self {
            Self { calls: Cell::new(0), flip_after }
        }
    }
    impl ExeProbe for FlipExe {
        fn current_identity(&self) -> Option<ExeIdentity> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            Some(exe_id(if n >= self.flip_after { 222 } else { 111 }))
        }
    }

    #[test]
    fn superseded_trips_only_on_a_definite_known_change() {
        let a = exe_id(1);
        let b = exe_id(2);
        assert!(!superseded(Some(&a), Some(&a)), "same identity → no trip");
        assert!(superseded(Some(&a), Some(&b)), "changed identity → trip");
        // A missing reading on either side must never trip (no false stop).
        assert!(!superseded(None, Some(&a)));
        assert!(!superseded(Some(&a), None));
        assert!(!superseded(None, None));
    }

    #[test]
    fn first_line_preview_truncates_on_chars_and_extra_lines() {
        assert_eq!(first_line_preview("short", 100), "short");
        assert_eq!(first_line_preview("one\ntwo", 100), "one…"); // more lines
        assert_eq!(first_line_preview("abcdef", 3), "abc…"); // char limit
        // Multibyte: must not split a char (no panic) and counts by char.
        assert_eq!(first_line_preview("héllo", 2), "hé…");
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
        let mcp = dir.join("mcp.json");
        fs::write(&mcp, "{}").unwrap();
        let baton = dir.join("baton.md");
        fs::write(&baton, "---\nstatus: BLOCKED_ON_HUMAN\nitem: null\n---\n# NEXT ACTION\n").unwrap();
        let usage = dir.join("usage.json");

        let (outcome, view) = run_auto(
            &FakeBackend {
                is_error: false,
                ctx_pct: 7,
            },
            &loop_path,
            &mcp,
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

    /// `(dir, loop_path, mcp, baton, usage)` for a loop test; the loop + mcp
    /// files are stubs (the scripted backend never reads them, only the real
    /// `ClaudeBackend` passes them through to `claude`).
    fn loop_paths(tag: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let dir = unique_tmp(tag);
        fs::create_dir_all(&dir).unwrap();
        let loop_path = dir.join("loop.json");
        fs::write(&loop_path, "{}").unwrap();
        let mcp = dir.join("mcp.json");
        fs::write(&mcp, "{}").unwrap();
        (dir.clone(), loop_path, mcp, dir.join("baton.md"), dir.join("usage.json"))
    }

    #[test]
    fn loop_stops_on_each_terminal_status_without_an_extra_iteration() {
        // QUEUE_EMPTY / STUCK are generic terminal stops; BLOCKED_ON_HUMAN gets
        // its own surfaced variant (slice 003).
        for (status, expected) in [
            ("QUEUE_EMPTY", StopReason::Terminal("QUEUE_EMPTY".to_string())),
            ("STUCK", StopReason::Terminal("STUCK".to_string())),
            ("BLOCKED_ON_HUMAN", StopReason::BlockedOnHuman),
        ] {
            let (dir, loop_path, mcp, baton, usage) = loop_paths(&format!("term-{status}"));
            let backend = ScriptedBackend::new(&baton, vec![fm(status, "x", "na")]);
            let clock = FakeClock::new(0);
            let mut log = Vec::new();
            let summary =
                run_auto_loop(&backend, &clock, &StableExe, &loop_path, &mcp, &baton, &usage, None, &mut log).unwrap();
            assert_eq!(summary.iterations, 1, "{status}: exactly one iteration");
            assert_eq!(summary.stop, expected, "{status}");
            // No iteration started after the terminal status was written.
            assert_eq!(backend.calls.get(), 1, "{status}: backend called once");
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn loop_drains_a_multi_iteration_backlog_to_queue_empty() {
        let (dir, loop_path, mcp, baton, usage) = loop_paths("drain");
        // Fresh process per iteration: each call writes a different baton, the
        // last one terminal. ITEM_COMPLETE is an item boundary the single-agent
        // driver self-pulls past (keeps driving), so the loop runs on to the next.
        let backend = ScriptedBackend::new(
            &baton,
            vec![
                fm("IN_PROGRESS", "item-a", "step 1"),
                fm("IN_PROGRESS", "item-a", "step 2"),
                fm("ITEM_COMPLETE", "item-a", "wrap up"),
                fm("QUEUE_EMPTY", "null", "nothing left"),
            ],
        );
        let clock = FakeClock::new(0);
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &clock, &StableExe, &loop_path, &mcp, &baton, &usage, None, &mut log).unwrap();
        assert_eq!(summary.iterations, 4);
        assert_eq!(summary.stop, StopReason::Terminal("QUEUE_EMPTY".to_string()));
        assert_eq!(backend.calls.get(), 4);
        // Budgets persisted each iteration (last write present).
        assert!(usage.exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loop_spin_guard_trips_when_next_action_is_unchanged() {
        let (dir, loop_path, mcp, baton, usage) = loop_paths("spin");
        // Same NEXT ACTION every iteration → no progress → STUCK.
        let stuck = fm("IN_PROGRESS", "item-a", "the exact same next action");
        let backend = ScriptedBackend::new(&baton, vec![stuck.clone(), stuck]);
        let clock = FakeClock::new(0);
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &clock, &StableExe, &loop_path, &mcp, &baton, &usage, None, &mut log).unwrap();
        assert_eq!(summary.stop, StopReason::SpinGuard);
        assert_eq!(summary.iterations, STALL_LIMIT as u64);
        assert_eq!(backend.calls.get(), STALL_LIMIT);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loop_respects_max_iterations_on_a_progressing_baton() {
        let (dir, loop_path, mcp, baton, usage) = loop_paths("maxiter");
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
        let clock = FakeClock::new(0);
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &clock, &StableExe, &loop_path, &mcp, &baton, &usage, Some(3), &mut log).unwrap();
        assert_eq!(summary.stop, StopReason::MaxIterations);
        assert_eq!(summary.iterations, 3);
        assert_eq!(backend.calls.get(), 3);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn max_iterations_one_reproduces_the_single_shot() {
        let (dir, loop_path, mcp, baton, usage) = loop_paths("single");
        let backend =
            ScriptedBackend::new(&baton, vec![fm("IN_PROGRESS", "item-a", "keep going")]);
        let clock = FakeClock::new(0);
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &clock, &StableExe, &loop_path, &mcp, &baton, &usage, Some(1), &mut log).unwrap();
        assert_eq!(summary.iterations, 1);
        assert_eq!(summary.stop, StopReason::MaxIterations);
        assert_eq!(backend.calls.get(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_log_records_iterations_and_the_stop_reason() {
        let (dir, loop_path, mcp, baton, usage) = loop_paths("log");
        let backend = ScriptedBackend::new(
            &baton,
            vec![
                fm("IN_PROGRESS", "item-a", "go"),
                fm("QUEUE_EMPTY", "null", "done"),
            ],
        );
        let clock = FakeClock::new(0);
        let mut log = Vec::new();
        run_auto_loop(&backend, &clock, &StableExe, &loop_path, &mcp, &baton, &usage, None, &mut log).unwrap();
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

    // ---- stale-orchestrator guard (task 007) ---------------------------

    #[test]
    fn binary_superseded_guard_stops_before_spawning_a_stale_iteration() {
        let (dir, loop_path, mcp, baton, usage) = loop_paths("superseded");
        // Distinct NEXT ACTIONs so the spin guard never fires first; this baton
        // never goes terminal, so without the stale-binary guard the loop would
        // keep driving (here it'd exhaust the scripted batons, then repeat the
        // last forever). The guard is the only thing that should stop it.
        let backend = ScriptedBackend::new(
            &baton,
            vec![
                fm("IN_PROGRESS", "item-a", "step 1"),
                fm("IN_PROGRESS", "item-a", "step 2"),
                fm("IN_PROGRESS", "item-a", "step 3"),
            ],
        );
        let clock = FakeClock::new(0);
        // Identity calls in order: baseline (n=0), guard before iter 2 (n=1),
        // guard before iter 3 (n=2 → flips) → the reinstall is caught before the
        // 3rd (stale) iteration ever spawns.
        let exe = FlipExe::new(2);
        let mut log = Vec::new();
        let summary = run_auto_loop(
            &backend, &clock, &exe, &loop_path, &mcp, &baton, &usage, None, &mut log,
        )
        .unwrap();
        assert_eq!(summary.stop, StopReason::BinarySuperseded);
        assert_eq!(summary.iterations, 2, "stops before the 3rd (stale) iteration");
        assert_eq!(backend.calls.get(), 2, "no stale child spawned");
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("binary superseded"), "log: {text}");
        fs::remove_dir_all(&dir).ok();
    }

    // ---- budget governor (slice 003) -----------------------------------

    /// A [`UsageSnapshot`] with the given `(status, resets_at)` per window.
    fn usage(five: (Option<&str>, Option<i64>), seven: (Option<&str>, Option<i64>)) -> UsageSnapshot {
        let win = |(status, resets_at): (Option<&str>, Option<i64>)| RateWindow {
            used_percentage: None,
            resets_at,
            status: status.map(str::to_string),
        };
        UsageSnapshot {
            context_window: ContextWindow {
                used_percentage: 10,
                remaining_percentage: 90,
                context_window_size: 1_000_000,
                current_tokens: 100_000,
            },
            rate_limits: RateLimits {
                five_hour: win(five),
                seven_day: win(seven),
            },
            ts: 0.0,
        }
    }

    /// A [`BatonView`] with the given status + NEXT ACTION.
    fn view(status: &str, next: &str) -> BatonView {
        BatonView {
            status: Some(status.to_string()),
            item: Some("item-a".to_string()),
            iteration: Some(1),
            next_action: Some(next.to_string()),
        }
    }

    #[test]
    fn window_tripped_keys_off_status_and_present_percentage_never_missing_as_zero() {
        let allowed = RateWindow {
            used_percentage: None,
            resets_at: Some(1),
            status: Some("allowed".to_string()),
        };
        assert!(!window_tripped(&allowed, 85));
        // Non-"allowed" status trips regardless of percentage.
        let rejected = RateWindow {
            status: Some("rejected".to_string()),
            ..RateWindow::default()
        };
        assert!(window_tripped(&rejected, 85));
        // A present percentage at/over reserve trips (future percentage backend).
        let over = RateWindow {
            used_percentage: Some(90),
            ..RateWindow::default()
        };
        assert!(window_tripped(&over, 85));
        let under = RateWindow {
            used_percentage: Some(50),
            ..RateWindow::default()
        };
        assert!(!window_tripped(&under, 85));
        // Missing everything → never trips (NOT read as 0%).
        assert!(!window_tripped(&RateWindow::default(), 85));
    }

    #[test]
    fn pause_for_prefers_seven_day_and_needs_a_reset_time() {
        // 7d takes precedence over 5h.
        let both = usage((Some("rejected"), Some(100)), (Some("rejected"), Some(200)));
        let p = pause_for(&both).expect("a window is over reserve");
        assert_eq!(p.window, "seven_day");
        assert_eq!(p.reset_at, 200);
        // Only 5h tripped.
        let five = usage((Some("rejected"), Some(777)), (Some("allowed"), None));
        let p = pause_for(&five).unwrap();
        assert_eq!(p.window, "five_hour");
        assert_eq!(p.reset_at, 777);
        // Nothing tripped → no pause.
        assert!(pause_for(&usage((Some("allowed"), Some(1)), (None, None))).is_none());
        // Tripped but no reset time → can't time a resume → no pause.
        assert!(pause_for(&usage((Some("rejected"), None), (None, None))).is_none());
    }

    #[test]
    fn decide_step_classifies_each_outcome() {
        let ok = usage((Some("allowed"), Some(1)), (None, None));
        // Clean continue.
        assert_eq!(decide_step(&view("IN_PROGRESS", "go"), &ok, false), LoopStep::Continue);
        // A deferred item is a clean handoff → keep driving the next item.
        assert_eq!(decide_step(&view("ITEM_DEFERRED", "go"), &ok, false), LoopStep::Continue);
        // Stalled continue → spin guard (before the governor).
        assert_eq!(
            decide_step(&view("IN_PROGRESS", "go"), &ok, true),
            LoopStep::Stop(StopReason::SpinGuard)
        );
        // Terminal statuses.
        assert_eq!(
            decide_step(&view("QUEUE_EMPTY", "-"), &ok, false),
            LoopStep::Stop(StopReason::Terminal("QUEUE_EMPTY".to_string()))
        );
        assert_eq!(
            decide_step(&view("STUCK", "-"), &ok, false),
            LoopStep::Stop(StopReason::Terminal("STUCK".to_string()))
        );
        // BLOCKED_ON_HUMAN is distinct.
        assert_eq!(
            decide_step(&view("BLOCKED_ON_HUMAN", "-"), &ok, false),
            LoopStep::Stop(StopReason::BlockedOnHuman)
        );
        // Over-reserve on a continue status → pause (even when not stalled).
        let rejected = usage((Some("rejected"), Some(900)), (None, None));
        match decide_step(&view("IN_PROGRESS", "go"), &rejected, false) {
            LoopStep::Pause(p) => {
                assert_eq!(p.window, "five_hour");
                assert_eq!(p.reset_at, 900);
            }
            other => panic!("expected pause, got {other:?}"),
        }
    }

    #[test]
    fn decide_step_routes_halted_rate_limit_to_a_pause_or_terminal() {
        // HALTED_RATE_LIMIT with an independently-tripped window → that reset.
        let tripped = usage((Some("rejected"), Some(500)), (None, None));
        match decide_step(&view("HALTED_RATE_LIMIT", "-"), &tripped, false) {
            LoopStep::Pause(p) => assert_eq!(p.reset_at, 500),
            other => panic!("expected pause, got {other:?}"),
        }
        // HALTED_RATE_LIMIT, no tripped window but a known reset → fall back to it.
        let allowed_with_reset = usage((Some("allowed"), Some(900)), (None, None));
        match decide_step(&view("HALTED_RATE_LIMIT", "-"), &allowed_with_reset, false) {
            LoopStep::Pause(p) => assert_eq!(p.reset_at, 900),
            other => panic!("expected pause, got {other:?}"),
        }
        // HALTED_RATE_LIMIT with no reset time at all → terminal (can't resume).
        assert_eq!(
            decide_step(&view("HALTED_RATE_LIMIT", "-"), &usage((None, None), (None, None)), false),
            LoopStep::Stop(StopReason::Terminal("HALTED_RATE_LIMIT".to_string()))
        );
    }

    #[test]
    fn restamp_status_replaces_only_the_frontmatter_status() {
        let baton = "---\nloop: g\nstatus: IN_PROGRESS\nitem: x\n---\n# NEXT ACTION\nstatus: not-this\n";
        let out = restamp_status(baton, "HALTED_RATE_LIMIT");
        assert!(out.contains("status: HALTED_RATE_LIMIT\n"));
        assert!(out.contains("status: not-this\n"), "body `status:` untouched");
        assert!(out.ends_with('\n'));
        // No frontmatter fence → unchanged.
        assert_eq!(restamp_status("status: x\n", "Y"), "status: x\n");
    }

    /// A scripted backend that pairs each iteration's baton with a five_hour
    /// `(status, resets_at)` so the governor's pause/resume is driven end to end.
    struct GovernorBackend {
        baton_path: PathBuf,
        steps: Vec<(String, Option<&'static str>, Option<i64>)>,
        calls: Cell<usize>,
    }

    impl AgentBackend for GovernorBackend {
        fn run_iteration(&self, req: &IterationRequest) -> Result<IterationOutcome> {
            assert!(!req.settings.as_os_str().is_empty());
            assert!(!req.prompt.is_empty());
            let i = self.calls.get();
            let (baton, status, reset) = self
                .steps
                .get(i)
                .or_else(|| self.steps.last())
                .cloned()
                .unwrap_or_default();
            fs::write(&self.baton_path, &baton).unwrap();
            self.calls.set(i + 1);
            Ok(IterationOutcome {
                is_error: false,
                result_text: Some(format!("iter {i}")),
                usage: usage((status, reset), (None, None)),
            })
        }
    }

    #[test]
    fn governor_pauses_until_reset_then_resumes() {
        let (dir, loop_path, mcp, baton, usage_path) = loop_paths("governor");
        let reset = 5_000;
        let backend = GovernorBackend {
            baton_path: baton.clone(),
            steps: vec![
                // iter 1: progressing, but the 5h window is rejected → pause.
                (fm("IN_PROGRESS", "item-a", "step 1"), Some("rejected"), Some(reset)),
                // iter 2: window allowed again → drains to QUEUE_EMPTY.
                (fm("QUEUE_EMPTY", "null", "done"), Some("allowed"), None),
            ],
            calls: Cell::new(0),
        };
        let clock = FakeClock::new(1_000);
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &clock, &StableExe, &loop_path, &mcp, &baton, &usage_path, None, &mut log).unwrap();

        assert_eq!(summary.iterations, 2);
        assert_eq!(summary.stop, StopReason::Terminal("QUEUE_EMPTY".to_string()));
        // Paused exactly once, waiting until the recorded reset (no real sleep).
        assert_eq!(*clock.sleeps.borrow(), vec![reset]);
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("governor: HALTED_RATE_LIMIT"), "log: {text}");
        assert!(text.contains("governor: resumed"), "log: {text}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn blocked_on_human_stops_distinctly_and_never_sleeps() {
        // Mirrors protocol 3b: a step that needs the daemon cycled but relock is
        // disabled → the agent writes BLOCKED_ON_HUMAN; the orchestrator surfaces
        // it and stops, never a cold unlock, never a fabricated decision.
        let (dir, loop_path, mcp, baton, usage_path) = loop_paths("blocked");
        let backend = ScriptedBackend::new(
            &baton,
            vec![fm(
                "BLOCKED_ON_HUMAN",
                "item-a",
                "needs daemon restart; relock disabled — set [growlight] allow_relock",
            )],
        );
        let clock = FakeClock::new(0);
        let mut log = Vec::new();
        let summary =
            run_auto_loop(&backend, &clock, &StableExe, &loop_path, &mcp, &baton, &usage_path, None, &mut log).unwrap();
        assert_eq!(summary.iterations, 1);
        assert_eq!(summary.stop, StopReason::BlockedOnHuman);
        assert_eq!(backend.calls.get(), 1, "no iteration after the block");
        assert!(clock.sleeps.borrow().is_empty(), "must not sleep on a human block");
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("BLOCKED_ON_HUMAN"), "log: {text}");
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

    /// Non-disruption (finish criterion): the existing foreground `--auto`
    /// orchestrator surface still parses + dispatches, and the new client
    /// subcommands are purely additive (no shadowing). No real `claude` is
    /// spawned — we only parse; `run_auto_loop` itself is exercised, unchanged,
    /// by the loop tests above.
    #[test]
    fn auto_loop_surface_is_intact_and_new_clients_are_additive() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: GrowlightCmd,
        }

        // `--auto` still parses and maps to StartArgs.auto.
        match TestCli::try_parse_from(["g", "start", "--auto", "--no-launch"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Start(a) => {
                assert!(a.auto, "--auto still parses");
                assert!(a.no_launch);
            }
            other => panic!("expected Start, got {other:?}"),
        }
        // --max-iterations still rides --auto.
        match TestCli::try_parse_from(["g", "start", "--auto", "--max-iterations", "3"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Start(a) => assert_eq!(a.max_iterations, Some(3)),
            other => panic!("expected Start, got {other:?}"),
        }

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
