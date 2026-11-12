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
use std::io::{BufRead, BufReader, IsTerminal, Write, stdin};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand, ValueEnum};
use softfig_ipc::{
    ClientError, ErrorKind, Request, growlightd_runtime_socket_path, runtime_socket_path,
    baton::parse_baton,
    claude_profiles,
    growlightd::{
        self, AgentDeltaKind, BuildCapsSummary, Event, FleetStatusReply, ForceStopArgs,
        PausedReply, QueueShowEntry, QueueShowReply, ResumeItemArgs, ResumeItemReply,
        SetResourcesArgs, SetResourcesReply, StopLevel, StopReply,
    },
    backlog_doc::BACKLOG_DOC,
    queue_v2::{migrate, Entry, EntryKind, Lane as QueueLane, QueueToml, SliceStatus, QUEUE_FILE},
    verbs::{
        GrowlightInitArgs, GrowlightInitReply, ListReportsArgs, ListReportsReply, PostMessageArgs,
        PostMessageReply, QueueAddEntryReply, QueueAddProjectReply, QueueDropReply, QueueMoveSpec,
        QueueStatusArg, QueueUpdateEntryReply, QueueV2MigrateApplyArgs, QueueV2MigrateApplyReply,
        ReadFileArgs, ReadFileReply, ReportRow,
        SliceInsertReply, SliceUpdateReply, StatusReply, op,
    },
};

use softfig_growlightd_client::{decode_frame, Frame};

use crate::cmd_daemon::try_daemon_call;
use crate::growlight_backend::{
    Backend, DEEPSEEK_FLASH, DEEPSEEK_REASONING, InteractiveLaunch, LaunchSlot, ModelChoice,
    ModelSpec, OpencodeConfigInputs, agent_bin, interactive_command, item_doc_candidates,
    opencode_config, opencode_context, opencode_interactive_args, parse_model_spec,
    resolve_item_models,
};
use crate::opencode_catalog;

/// Agent backend (spec §12: a documented, swappable seam). Claude Code is the
/// supported backend; `--name` tags the loop session, `--settings` loads the
/// generated isolated hooks so normal `claude` stays untouched.
const AGENT_BIN: &str = "claude";
const AGENT_NAME: &str = "softfig-loop";

/// The opencode model used when a launch selects opencode without naming a model
/// (a bare `--backend opencode` / `--opencode`, or a "let growlight decide" that
/// finds no declaration on the active backlog item). Cheap by default — reasoning
/// is opt-in, per the human's 2026-08-08 call closing the slice-005 sub-question.
const DEFAULT_OPENCODE_MODEL: &str = DEEPSEEK_FLASH;

/// The first-turn kick for an interactive **opencode** launch (`--prompt`).
/// opencode has no SessionStart hook, so — unlike claude's TUI, where the
/// injected protocol+baton sit as context and the human types the first turn —
/// the opencode session needs a nudge to begin. Its agent prompt already carries
/// the protocol + the step-0 "read your baton" bootstrap (slice 002), so this
/// just says "start". Kept short + generic; the real reseed work is the agent
/// prompt's step 0, not this line.
const OPENCODE_KICK: &str = "Begin your growlight iteration: complete step 0 (read your baton) \
    and follow the operating protocol in your instructions.";

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

    /// Print the boot dirty-tree signal for the root baton's item (task 064):
    /// the line `start` prints, for the SessionStart hook to inject on every
    /// boot — a `/clear` re-boot included — so it lands in the agent's own
    /// context. Prints nothing when the tree is clean or the check can't run;
    /// never fails, and never reverts, stages or commits.
    BootCheck(BootCheckArgs),

    /// Show the orchestrator daemon's fleet status — a one-shot query to
    /// growlightd's own IPC socket: state, garden root, policy, the admission
    /// gate (`paused`), and one row per live agent.
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

    /// List the filed growlight reports (`growlight/reports/`) — bugs, flakes,
    /// security gaps, doc drift, findings, questions, blockers, ideas — that
    /// carry every `--tag` given (`ns:*` matches any value in a namespace).
    /// Without tags, lists the reports that are still open or triaged; pass
    /// `--all` for closed ones too. Routes to keeperd, which owns the folder.
    Reports(ReportsArgs),

    /// Inspect or adjust the GENTLE per-agent build-resource caps LIVE
    /// (peer-isolation slice 003): the SOFT throttle (`CARGO_BUILD_JOBS` /
    /// `MemoryHigh` / `CPUWeight`) each agent's transient scope is capped with. A
    /// live `set` adjusts a running fleet without a daemon restart and stays
    /// throttle-not-kill (no hard `MemoryMax` cap).
    Resources(ResourcesArgs),

    /// The queue v2 human surface (§6.9): `queue show` and the mutating forms —
    /// `project add`, `project set-repo`, `add`, `move`, `lane`, `after`, `status`, `repair`, `drop`. Each is
    /// a thin client over the matching §6.8 keeperd verb, with `--dry-run`
    /// (compute + validate + render the would-be list, write nothing), plus the
    /// read-only `queue pick`. These verbs touch only the v2 files; the fleet
    /// schedules from them only under `queue = "v2"` in `config/growlight.toml`
    /// (default `legacy`, §11).
    Queue(QueueArgs),

    /// The queue v2 slice surface (§6.9): `insert`, `move` and `status` inside a
    /// milestone's `slices.toml`, each a thin client over the matching §6.8
    /// keeperd verb with `--dry-run`.
    Slice(SliceArgs),
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
pub struct ReportsArgs {
    /// A tag every listed report must carry, e.g. `type:bug`, `area:*`.
    /// Repeatable.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// Include resolved / wontfix / duplicate reports.
    #[arg(long)]
    pub all: bool,
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
    /// Which agent backend the interactive loop runs on (spec-agents §4.1).
    /// `claude` (the default when nothing is chosen) is byte-identical to before;
    /// `opencode` runs the same human-driven loop on opencode. Omitting it on a
    /// TTY brings up the picker instead.
    #[arg(long, value_parser = parse_backend_arg)]
    pub backend: Option<Backend>,
    /// Shorthand for `--backend opencode`.
    #[arg(long, conflicts_with = "backend")]
    pub opencode: bool,
    /// Backend + model in one word, bypassing the picker:
    /// `claude` | `claude:<alias|id>[1m]` | `reasoning` | `flash` |
    /// `auto` | `provider/model`, with an optional ` variant=<v>` (alias
    /// ` effort=<v>`) tail. On opencode `variant` is free-form; on claude the
    /// effort set is closed to `low|medium|high|xhigh|max`. A bare `claude` is
    /// the harness default (no `--model`/`--effort`); `claude:opus` becomes
    /// `--model opus`; `claude:claude-opus-4-7 effort=high` becomes
    /// `--model claude-opus-4-7 --effort high`.
    /// `auto` = "let growlight decide": use the model the active backlog item
    /// declares in its `> Model:` line, defaulting to deepseek flash.
    #[arg(long, conflicts_with_all = ["backend", "opencode"])]
    pub model: Option<String>,
    /// The claude-login slot the claude session runs on (its
    /// `CLAUDE_CONFIG_DIR`; `home` = Claude's default config dir). Defaults to
    /// the store's active slot (`softfig claude-login use`). claude only.
    #[arg(long, value_name = "SLOT")]
    pub profile: Option<String>,
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
/// Args for `boot-check`. Both paths are passed by the generated `inject.sh`,
/// so the hook needs no daemon round-trip to find them.
#[derive(Args, Debug)]
pub struct BootCheckArgs {
    /// The garden root (the mount the loop's docs are read from).
    #[arg(long)]
    pub garden_root: PathBuf,
    /// The semi-auto root baton whose item to check.
    #[arg(long)]
    pub baton: PathBuf,
}

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
        GrowlightCmd::BootCheck(args) => {
            boot_check(&args);
            Ok(())
        }
        GrowlightCmd::Status(args) => client_status(args),
        GrowlightCmd::Watch(args) => client_watch(args),
        GrowlightCmd::Stop(args) => client_stop(args),
        GrowlightCmd::Pause(args) => client_pause(args),
        GrowlightCmd::Resume(args) => client_resume(args),
        GrowlightCmd::Say(args) => client_say(args),
        GrowlightCmd::Reports(args) => client_reports(args),
        GrowlightCmd::Resources(args) => client_resources(args),
        GrowlightCmd::Queue(args) => client_queue(args),
        GrowlightCmd::Slice(args) => client_slice(args),
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
    let socket = args.socket.clone().unwrap_or_else(runtime_socket_path);
    let garden_root = resolve_garden_root(&socket, args.garden_root.clone())?;

    // The hook injects this on every (re)start; its absence means the durable
    // pillar was never scaffolded.
    let protocol = garden_root.join(PILLAR).join("protocol.md");
    if !protocol.exists() {
        return Err(anyhow!(
            "growlight pillar not found ({} missing) — run `softfig growlight init` first",
            protocol.display()
        ));
    }

    let runtime = runtime_dir(args.config_dir.clone())?;
    fs::create_dir_all(&runtime)
        .with_context(|| format!("creating runtime dir {}", runtime.display()))?;

    let loop_path = runtime.join("loop.json");
    let mcp_path = runtime.join("mcp.json");
    let opencode_path = runtime.join("opencode.json");
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
            &softfig_bin_path(),
            &runtime,
        ),
    )?;
    // `--settings` only *permits* softfig-mcp; this *attaches* it, so the
    // garden verbs exist regardless of where the loop is launched from (the
    // project-scoped registration in ~/.claude.json only loads with cwd in the
    // garden). Without it every state-advancing iteration STUCKs (auto-run log).
    write_file(&mcp_path, &mcp_json(&softfig_mcp_path()))?;
    write_script(
        &inject_path,
        &inject_script(&protocol, &baton_path, &softfig_bin_path(), &garden_root),
    )?;
    // Slice 009 S9: the per-profile dir rides next to usage.json under the
    // same runtime grant, so the statusline needs no new permission to tee
    // into it. The active-link path is baked in at launch — a session that
    // outlives a `claude-login use` keeps writing to its per-profile file
    // either way (slice 009 S8 statusline half).
    let by_profile_dir = runtime.join("usage.by-profile");
    let active_link = claude_profiles::store_root_from_env()
        .map(|s| s.join(claude_profiles::ACTIVE_LINK))
        // No slot store (no `$HOME`): a sentinel path under the runtime that
        // will never exist, so the `[ -L ]` guard falls through to the
        // `home` default and the shared `usage.json` is written as before.
        .unwrap_or_else(|| runtime.join("no-store-active-sentinel"));
    write_script(
        &statusline_path,
        &statusline_script(&runtime.join("usage.json"), &by_profile_dir, &active_link),
    )?;

    // Live loop state → seed once, never clobber an in-flight loop.
    let garden_name = garden_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("garden");
    let baton_seeded = seed_if_absent(&baton_path, &seed_baton(garden_name, &today_iso()))?;
    let questions_seeded = seed_if_absent(&questions_path, SEED_QUESTIONS)?;

    // Task 064: surface a repo whose dirt the baton doesn't know about (report
    // 001's cut-off signature) BEFORE anything is launched: dirt newer than a
    // carried baton's last write, or any dirt under a baton just seeded (review
    // 043 G64-2 — a fresh seed's own mtime is "now", which no dirt is newer than).
    // Read-only and best-effort; a failed probe never blocks a launch.
    if let Some(line) = boot_dirty_check(&garden_root, &baton_path, baton_seeded) {
        eprintln!("{line}");
    }

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

    // Resolve WHAT to launch — backend + (for opencode) model + variant — from an
    // explicit flag, else the interactive picker, else claude. Deliberately after
    // the setup print and before anything is launched: the picker is the last thing
    // between the human and the running agent. The baton is seeded by now, so a
    // "let growlight decide" can read the active item's declaration.
    let choice = resolve_model_choice(&args, &garden_root, &baton_path)?;
    let backend = choice.backend;
    // The claude-login slot, resolved and checked before anything launches
    // (claude-login-switcher slice 007): the same resolver growlightd's spawn
    // seam uses, so a slot the fleet would refuse is refused here too.
    let claude_slot = match backend {
        Backend::Claude => Some(resolve_launch_slot(
            claude_profiles::store_root_from_env().as_deref(),
            args.profile.as_deref(),
        )?),
        Backend::Opencode if args.profile.is_some() => {
            bail!("--profile selects a claude-login slot; it has no meaning for opencode")
        }
        Backend::Opencode => None,
    };

    // The opencode-native equivalent of loop.json + mcp.json (`softfig-loop` agent
    // = protocol-by-reference + step-0 baton boot + the session context (garden
    // map, memory rules, memory index); the shared permission floor, garden write
    // guard included; explicit softfig-mcp block). Refreshed every launch like
    // the claude files, on both backends (self-heal; inert for a claude run) — and
    // written HERE, after resolution, because the resolved model + variant go into
    // it.
    let opencode_data = softfig_ipc::opencode::opencode_data_dir(
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        &home_dir()?,
    );
    let opencode_cfg = opencode_context(&garden_root, &claude_projects).and_then(|context| {
        opencode_config(&OpencodeConfigInputs {
            agent_name: AGENT_NAME,
            protocol: &protocol,
            baton: &baton_path,
            context: &context,
            runtime_root: runtime_grant_root(&runtime),
            mcp_bin: &softfig_mcp_path(),
            claude_projects: &claude_projects,
            opencode_data: &opencode_data,
            model: choice.opencode_model(),
            variant: choice.variant.as_deref(),
        })
    });
    match backend {
        // Inert for a claude run, so a permission floor it cannot build (say, a
        // relative `--config-dir`) or a context path it cannot reference is
        // reported, not allowed to block claude.
        Backend::Claude => match opencode_cfg {
            Ok(cfg) => write_file(&opencode_path, &cfg)?,
            Err(e) => eprintln!("warning: opencode config not refreshed: {e:#}"),
        },
        // An opencode launch carries its model in the config's top-level `model`,
        // which 2.x does NOT fail closed on: a bad id silently runs on
        // opencode/exo-free (opencode-v2-repin slice 001, L7). So the config is
        // staged, checked against opencode's live catalog, and only then moved to
        // the path a launch (or the --no-launch hint) reads. A refused config never
        // lands where a human could start it by hand.
        Backend::Opencode => {
            // Fail-closed: no floor, no launch.
            let opencode_cfg = opencode_cfg?;
            let staged = runtime.join("opencode.json.unverified");
            write_file(&staged, &opencode_cfg)?;
            println!(
                "checking {} against opencode's model catalog …",
                choice.opencode_model_ref()
            );
            let checked = opencode_catalog::verify_model(
                agent_bin(backend),
                &staged,
                &garden_root,
                choice.opencode_model(),
                choice.variant.as_deref(),
                opencode_catalog::CATALOG_DEADLINE,
            );
            if let Err(e) = checked {
                let _ = fs::remove_file(&staged);
                return Err(e);
            }
            fs::rename(&staged, &opencode_path).with_context(|| {
                format!("moving the checked config into {}", opencode_path.display())
            })?;
        }
    }

    // Built BEFORE the `--no-launch` branch, not just before the spawn, so the
    // printed hint and the real launch are derived from the same value and cannot
    // drift apart (they did: the hint kept naming the pre-slice-006 runtime cwd
    // long after the launch had moved to the garden).
    let launch = InteractiveLaunch {
        agent_name: AGENT_NAME,
        loop_settings: &loop_path,
        mcp_config: &mcp_path,
        // BOTH backends now root at the garden: claude for slice 005's auto-cd,
        // opencode since slice 006 so garden docs are ordinary in-project reads.
        // See the field's doc on `InteractiveLaunch`.
        garden_root: &garden_root,
        opencode_config: &opencode_path,
        boot_prompt: OPENCODE_KICK,
        claude_slot: claude_slot.as_ref(),
    };

    if args.no_launch {
        println!("\n{}", no_launch_hint(&choice, &launch));
        return Ok(());
    }
    launch_agent(&choice, &launch)
}

/// Task 064 — the semi-auto/CLI half of the boot-time dirty-tree guard: at
/// `start`, resolve the root baton's active item repo ([`baton_item_repo`]) and
/// return the signal growlightd journals before a member spawn
/// ([`softfig_ipc::item_repo::boot_signal`] — the same text, so the human
/// launching the loop sees it before the agent does new work). `seeded` says
/// the baton was just written (no prior handoff, so any dirt surfaces);
/// otherwise its last write is the handoff. Read-only: it only ever
/// *surfaces* the answer, never reverts, stages or commits. Best-effort — a
/// missing item, an unprobeable repo or a `git` failure is `None`, never a
/// launch failure.
fn boot_dirty_check(garden_root: &Path, baton_path: &Path, seeded: bool) -> Option<String> {
    use softfig_ipc::item_repo::{boot_signal, probe, Handoff};
    let view = parse_baton(&fs::read_to_string(baton_path).ok()?);
    let item = view.item.as_deref()?;
    let repo = baton_item_repo(garden_root, item)?;
    let state = probe(&repo).ok()?;
    let handoff = if seeded {
        Handoff::Fresh
    } else {
        Handoff::At(fs::metadata(baton_path).and_then(|md| md.modified()).ok()?)
    };
    boot_signal(item, &repo, &state, handoff).map(|signal| format!("growlight: {signal}"))
}

/// The repo the semi-auto baton's item lands in, through the one resolver
/// growlightd's repo probe uses (review 043 G64-3,
/// [`softfig_ipc::item_repo::item_repo_path`]): the item's own doc's
/// `> Worktree:`, else its queue's `## Queues` registry cell. The baton names
/// no queue, so the queue is the table that lists the item — semi-auto runs
/// named queues (psy, fid, irface, roadeye), whose items rarely carry
/// `> Worktree:`.
fn baton_item_repo(garden_root: &Path, item: &str) -> Option<PathBuf> {
    use softfig_ipc::backlog_doc::{queue_of, BACKLOG_DOC, DEFAULT_QUEUE};
    let backlog = fs::read_to_string(garden_root.join(BACKLOG_DOC)).ok();
    let queue = backlog
        .as_deref()
        .and_then(|doc| queue_of(doc, item))
        .unwrap_or_else(|| DEFAULT_QUEUE.to_string());
    let doc = item_own_doc(garden_root, item).ok()?;
    let home = home_dir().ok();
    softfig_ipc::item_repo::item_repo_path(doc.as_deref(), &queue, || backlog, home.as_deref())
}

/// The item's own doc off the garden mount — the doc growlightd's claim-time
/// reader reads, never a slice or sub-milestone doc: a task's
/// `tasks/<id>-*.md`, else the milestone's `CLAUDE.md`. It fails closed the way
/// growlightd's reader does, so the two give the same answer: two docs
/// claiming the number ([`unique_numbered`](softfig_ipc::model_choice::unique_numbered),
/// review 042 G74-2) or metadata the read view hides
/// ([`unreadable_metadata`](softfig_ipc::item_meta::unreadable_metadata), G74-4)
/// is an `Err`, and the caller gives no repo signal rather than a registry guess.
fn item_own_doc(garden_root: &Path, item: &str) -> Result<Option<String>, String> {
    use softfig_ipc::backlog_doc::{is_task_id, MILESTONES_DIR, TASKS_DIR};
    let path = if is_task_id(item) {
        let tasks = garden_root.join(TASKS_DIR);
        let names: Vec<String> = match fs::read_dir(&tasks) {
            Ok(dir) => dir.flatten().filter_map(|e| e.file_name().into_string().ok()).collect(),
            Err(_) => return Ok(None),
        };
        match softfig_ipc::model_choice::unique_numbered(names.iter().map(String::as_str), item)? {
            Some(name) => tasks.join(name),
            None => return Ok(None),
        }
    } else {
        garden_root.join(MILESTONES_DIR).join(item).join("CLAUDE.md")
    };
    let Ok(doc) = fs::read_to_string(path) else { return Ok(None) };
    match softfig_ipc::item_meta::unreadable_metadata(&doc) {
        Some(why) => Err(why.to_string()),
        None => Ok(Some(doc)),
    }
}

/// The slot an interactive claude session runs on: `--profile`, else the
/// store's `active` pointer, checked by the resolver growlightd's spawn seam
/// uses ([`claude_profiles::launch_slot`]), so a missing dir or an unusable
/// credential refuses the launch rather than run on another account. With no
/// store (no `$HOME`) only `home` exists.
fn resolve_launch_slot(store: Option<&Path>, profile: Option<&str>) -> Result<LaunchSlot> {
    let (name, dir) = match (store, profile) {
        (Some(store), Some(slot)) => (slot.to_string(), claude_profiles::launch_slot(store, slot)?),
        (Some(store), None) => claude_profiles::launch_active(store)?,
        (None, None | Some(claude_profiles::HOME_SLOT)) => {
            (claude_profiles::HOME_SLOT.to_string(), claude_profiles::SlotDir::Home)
        }
        (None, Some(slot)) => bail!(
            "claude-login slot {slot:?}: no slot store can be named (is $HOME set?)"
        ),
    };
    Ok(LaunchSlot { name, dir })
}

/// The copy-pasteable manual launch printed by `--no-launch`, per backend. Pure,
/// and built from the very [`InteractiveLaunch`] the spawn would consume, so a
/// test can assert the hint names the same cwd the launcher really uses.
///
/// That equivalence is load-bearing for opencode: the generated config grants
/// only the runtime root + the claude-memory tree via `external_directory`, so a
/// session started from anywhere other than the garden cannot read the garden at
/// all — the exact failure slice 006 removed. A hint that names the wrong cwd
/// hands the human a session that looks fine and is blind.
///
/// The `cd` is shown for both backends because the launcher pins the cwd for both
/// (slice 005's auto-cd for claude, slice 006 for opencode); a hint that silently
/// inherited the human's cwd would reproduce neither.
fn no_launch_hint(choice: &ModelChoice, launch: &InteractiveLaunch) -> String {
    let garden = launch.garden_root.display();
    match choice.backend {
        // The slot goes through `env`, which also bypasses the bash `claude()`
        // shim: a bare `claude` there would re-resolve the active slot, and
        // `--profile` may have named another one.
        Backend::Claude => format!(
            "(--no-launch) runtime ready{}. launch with:\n  cd {garden} && {}{AGENT_BIN} \
             --name {AGENT_NAME} --settings {} --mcp-config {}{}",
            launch
                .claude_slot
                .map(|s| format!(" (claude-login slot {})", s.name))
                .unwrap_or_default(),
            match launch.claude_slot.map(|s| &s.dir) {
                Some(claude_profiles::SlotDir::Store(dir)) => {
                    format!("env {}={} ", claude_profiles::CONFIG_DIR_ENV, dir.display())
                }
                Some(claude_profiles::SlotDir::Home) => {
                    format!("env -u {} ", claude_profiles::CONFIG_DIR_ENV)
                }
                None => String::new(),
            },
            launch.loop_settings.display(),
            launch.mcp_config.display(),
            // Slice 002: the `--model`/`--effort` tail only prints when one is
            // pinned; `claude` on the harness default stays byte-identical to
            // the pre-slice-002 hint.
            {
                let argv = choice.claude_argv();
                if argv.is_empty() {
                    String::new()
                } else {
                    format!(" {}", argv.join(" "))
                }
            },
        ),
        // The opencode config is handed over via `OPENCODE_CONFIG` (its analog of
        // claude's `--settings`), so there is no `--settings`/`--mcp-config` here.
        // `growlight start --opencode` does the cd + first-turn kick for you; this
        // is the manual equivalent minus the `--prompt`, which the human types
        // instead. The model is already baked into the config just written, and
        // the args come from the same function the launch uses, so the hint keeps
        // `--standalone` (without it the shared service would ignore the config).
        Backend::Opencode => format!(
            "(--no-launch) runtime ready ({}). launch with:\n  cd {garden} && OPENCODE_CONFIG={} \
             {} {}",
            choice.opencode_model_ref(),
            launch.opencode_config.display(),
            agent_bin(choice.backend),
            opencode_interactive_args().join(" "),
        ),
    }
}

// ---- backend + model resolution (slice 005) ----------------------------

/// Resolve the interactive launch target: an explicit flag wins, else the picker
/// (TTY only), else claude.
///
/// `--backend`/`--opencode` choose a backend at its default model;
/// `--model <spec>` chooses backend AND model in one word (and can itself be
/// `auto`). With nothing given, a TTY gets the picker and everything else gets
/// claude — the launcher must never block on stdin in a script, a pipe, or a
/// headless run.
fn resolve_model_choice(
    args: &StartArgs,
    garden_root: &Path,
    baton_path: &Path,
) -> Result<ModelChoice> {
    let flagged = args.opencode || args.backend.is_some() || args.model.is_some();

    let spec = if should_prompt(flagged, args.no_launch, stdin().is_terminal()) {
        // Slice 002: the picker lists all available claude models. The extras
        // come from two best-effort sources — the active slot's `.claude.json`
        // `additionalModelOptionsCache[].value` (pre-switcher-merge the slot's
        // `.claude.json` is `~/.claude.json`) and `config/growlight.toml`
        // `[claude] models = [...]`, in that order, deduped first-wins. Any
        // read error → the row is simply absent.
        let claude_json = home_dir().ok().map(|h| h.join(".claude.json"));
        let growlight_toml = garden_root
            .join("config")
            .join(softfig_ipc::GROWLIGHT_CONFIG_FILE);
        let extras = claude_picker_extras(claude_json.as_deref(), Some(&growlight_toml));
        let mut stdin = BufReader::new(stdin().lock());
        prompt_for_model_in(&mut stdin, &extras)?
    } else if let Some(spec) = flag_spec(args)? {
        spec
    } else {
        // Nothing chosen and nobody to ask (non-TTY or `--no-launch`):
        // the documented default, never a prompt into a stdin that can't answer.
        ModelSpec::Fixed(ModelChoice::claude())
    };

    Ok(match spec {
        ModelSpec::Fixed(choice) => choice,
        ModelSpec::Auto => declared_model(garden_root, baton_path),
    })
}

/// The `--backend` value parser. `Backend` moved to `softfig-ipc` (queue v2
/// §6.4) and no longer derives clap's `ValueEnum`, so this maps the word with
/// the same spelling the flag always accepted.
fn parse_backend_arg(s: &str) -> Result<Backend, String> {
    s.parse()
        .map_err(|_| format!("expected `claude` or `opencode`, got `{s}`"))
}

/// The spec the command line asked for, if any. `--opencode` is shorthand for
/// `--backend opencode`, and `--model` carries backend + model together; clap
/// keeps all three mutually exclusive, so at most one arm can fire.
fn flag_spec(args: &StartArgs) -> Result<Option<ModelSpec>> {
    if args.opencode {
        return Ok(Some(ModelSpec::Fixed(ModelChoice::opencode(
            DEFAULT_OPENCODE_MODEL,
        ))));
    }
    if let Some(backend) = args.backend {
        return Ok(Some(ModelSpec::Fixed(match backend {
            Backend::Claude => ModelChoice::claude(),
            Backend::Opencode => ModelChoice::opencode(DEFAULT_OPENCODE_MODEL),
        })));
    }
    args.model
        .as_deref()
        .map(parse_model_spec)
        .transpose()
        .context("--model")
}

/// Whether `growlight start` should bring up the backend/model picker. Pure, so
/// the "never hang waiting on stdin" rule is unit-tested rather than trusted: a
/// prompt happens only when the human made no choice on the command line, a human
/// is actually there (stdin is a TTY), and something is being launched at all
/// (`--no-launch` launches nothing to pick for).
fn should_prompt(flagged: bool, no_launch: bool, stdin_is_tty: bool) -> bool {
    !flagged && !no_launch && stdin_is_tty
}

/// The claude-alias rows the picker always shows after `1) claude`, in menu
/// order: `opus | sonnet | haiku | fable`. Slice 002 widened the picker to
/// cover claude's full family without the human having to type the suffix.
const CLAUDE_PICKER_ALIASES: &[&str] = &["opus", "sonnet", "haiku", "fable"];

/// The interactive picker (slice 002). Thin wrapper around
/// [`prompt_for_model_in`] that locks real stdin.
fn prompt_for_model_in<R: BufRead>(reader: &mut R, extras: &[String]) -> Result<ModelSpec> {
    // The extras list is capped only by what the sources deliver; the picker
    // never limits it, so a human who added five entries to `[claude] models`
    // can select any of them by number.
    let first_extra = 2 + CLAUDE_PICKER_ALIASES.len();
    loop {
        println!("\nbackend + model:");
        println!("  1) claude                (harness default)");
        for (i, alias) in CLAUDE_PICKER_ALIASES.iter().enumerate() {
            println!("  {}) claude:{alias}", 2 + i);
        }
        for (i, extra) in extras.iter().enumerate() {
            println!("  {}) claude:{extra}", first_extra + i);
        }
        println!("  r) reasoning            ({DEEPSEEK_REASONING})");
        println!("  f) flash                ({DEEPSEEK_FLASH})");
        println!("  a) let growlight decide (the active backlog item's `> Model:`, else flash)");
        println!("     or type any spec, e.g. `claude:claude-opus-4-7 effort=high`");
        print!("choice [1]: ");
        // The prompt has no newline, so it sits in the line buffer until flushed.
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap_or(0);
        if n == 0 {
            // EOF (stdin closed mid-run): fall back to the documented default
            // rather than loop forever on empty reads.
            println!();
            return Ok(ModelSpec::Fixed(ModelChoice::claude()));
        }
        let input = line.trim();
        if let Some(spec) = picker_fixed_choice(input, extras)? {
            return Ok(spec);
        }
        // Typed input: route through the shared grammar so the words that work
        // here, on `--model`, and on `> Model:` lines stay the same.
        match parse_model_spec(input) {
            Ok(spec) => return Ok(spec),
            Err(e) => {
                // A bad typed spec re-prompts rather than failing the launch —
                // the picker is the last thing between the human and the agent.
                eprintln!("  not understood ({e}); try again");
            }
        }
    }
}

/// Resolve one picker key — the fixed menu rows (`1`, `2..=5`, extras numbers,
/// `r`/`R`, `f`/`F`, `a`/`A`, empty) to a `ModelSpec`. Returns `Ok(None)` for
/// anything that isn't a menu key, so the caller can try the typed-spec path.
/// Pure, so the number mapping (aliases + extras ordering) is unit-testable
/// without the stdin seam.
fn picker_fixed_choice(input: &str, extras: &[String]) -> Result<Option<ModelSpec>> {
    let first_extra = 2 + CLAUDE_PICKER_ALIASES.len();
    Ok(Some(match input {
        "" | "1" => ModelSpec::Fixed(ModelChoice::claude()),
        "r" | "R" => ModelSpec::Fixed(ModelChoice::opencode(DEEPSEEK_REASONING)),
        "f" | "F" => ModelSpec::Fixed(ModelChoice::opencode(DEEPSEEK_FLASH)),
        "a" | "A" => ModelSpec::Auto,
        other => {
            if let Ok(n) = other.parse::<usize>() {
                if (2..first_extra).contains(&n) {
                    let alias = CLAUDE_PICKER_ALIASES[n - 2];
                    return Ok(Some(ModelSpec::Fixed(ModelChoice::claude_on(
                        Some(alias.to_string()),
                        None,
                    ))));
                }
                if n >= first_extra && n < first_extra + extras.len() {
                    let m = &extras[n - first_extra];
                    // Validate through the shared parser so a slot-local id
                    // picked by number produces the same argv a typed
                    // `claude:<m>` would.
                    return Ok(Some(parse_model_spec(&format!("claude:{m}")).with_context(
                        || format!("picker extra `claude:{m}` (from .claude.json / growlight.toml)"),
                    )?));
                }
            }
            return Ok(None);
        }
    }))
}

/// The extras list the picker shows under `6…)`: the active slot's
/// `.claude.json` `additionalModelOptionsCache[].value` first, then
/// `config/growlight.toml`'s `[claude] models = [...]`, deduped **first-wins**.
/// Any read / parse error → the source is simply absent (best-effort), because
/// a stale user file must never block the launch picker. An entry that duplicates
/// a built-in alias (`opus`/`sonnet`/`haiku`/`fable`) is dropped — the alias
/// already has a numbered row.
fn claude_picker_extras(
    claude_json: Option<&Path>,
    growlight_toml: Option<&Path>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(path) = claude_json {
        out.extend(read_claude_json_models(path));
    }
    if let Some(path) = growlight_toml {
        out.extend(read_growlight_toml_claude_models(path));
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    out.retain(|v| {
        if CLAUDE_PICKER_ALIASES.contains(&v.as_str()) {
            return false;
        }
        seen.insert(v.clone())
    });
    out
}

/// Pull `additionalModelOptionsCache[].value` out of a `.claude.json`
/// (claude-login-switcher-aware eventually; today it points at the active slot's
/// `.claude.json`, else `~/.claude.json`). Best-effort: an absent file, an
/// unreadable file, malformed JSON or a missing/wrong-shaped key all yield an
/// empty list — the picker row is quietly absent, never a launch failure.
fn read_claude_json_models(path: &Path) -> Vec<String> {
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    let Some(arr) = root
        .get("additionalModelOptionsCache")
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|entry| entry.get("value").and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Pull `[claude] models = [...]` out of `config/growlight.toml`. Same
/// best-effort posture as [`read_claude_json_models`]: a missing file / bad
/// TOML / wrong-shaped section is an empty list. The growlightd parse of the
/// same file does not know about `[claude]` and ignores it (the top-level
/// `Doc` struct has no `deny_unknown_fields`), so adding this section cannot
/// disable the fleet.
fn read_growlight_toml_claude_models(path: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(root) = text.parse::<toml::Value>() else {
        return Vec::new();
    };
    let Some(arr) = root
        .get("claude")
        .and_then(|c| c.get("models"))
        .and_then(|m| m.as_array())
    else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// "Let growlight decide": use the model the ACTIVE backlog item declares for
/// itself. The judgement of which model suits a piece of work belongs to whoever
/// queued it, so the launcher reads rather than guesses — the active slice doc's
/// optional `> Model:` line, falling back to the milestone doc (declare once for a
/// whole milestone), then to [`DEFAULT_OPENCODE_MODEL`].
///
/// Never fails the launch: an unreadable baton, an item whose doc has moved, or a
/// malformed declaration all fall through to the default with a printed reason —
/// a bad metadata line must not stand between the human and their loop.
fn declared_model(garden_root: &Path, baton_path: &Path) -> ModelChoice {
    let default = || ModelChoice::opencode(DEFAULT_OPENCODE_MODEL);

    let Ok(baton) = fs::read_to_string(baton_path) else {
        println!("growlight decides: {DEFAULT_OPENCODE_MODEL} (no readable baton)");
        return default();
    };
    let view = parse_baton(&baton);
    let Some(item) = view.item.as_deref() else {
        println!("growlight decides: {DEFAULT_OPENCODE_MODEL} (baton names no active item)");
        return default();
    };

    let candidates = match item_doc_candidates(garden_root, item, view.slice.as_deref()) {
        Ok(candidates) => candidates,
        Err(e) => {
            println!("growlight decides: {DEFAULT_OPENCODE_MODEL} — ignoring the declarations: {e}");
            return default();
        }
    };
    let docs = candidates
        .into_iter()
        .map(|doc_path| {
            let label = doc_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| item.to_string());
            let content = fs::read_to_string(&doc_path).ok();
            (label, content)
        });
    match resolve_item_models(docs) {
        Ok(Some(resolved)) => {
            println!(
                "growlight decides: {} (declared by {})",
                resolved.field, resolved.origin
            );
            // §6.4 legacy trap: a comma list resolves to its first entry here
            // (single-entry lines behave exactly as before).
            resolved.list.first().clone()
        }
        Ok(None) => {
            println!("growlight decides: {DEFAULT_OPENCODE_MODEL} (no `> Model:` declared by {item})");
            default()
        }
        Err(e) => {
            println!("growlight decides: {DEFAULT_OPENCODE_MODEL} — ignoring: {e}");
            default()
        }
    }
}

/// Ask the daemon where the garden is mounted (so injection paths are derived,
/// never literal — spec §3/§12). `--garden-root` bypasses the query.
pub(crate) fn resolve_garden_root(socket: &Path, override_: Option<PathBuf>) -> Result<PathBuf> {
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

/// The ` --model <m> --effort <e>` fragment the claude banner echoes when
/// either is pinned, built from the same `claude_argv()` the spawn argv uses so
/// the two cannot drift. Returns an empty string on the harness default (so
/// `launching claude --name softfig-loop …` stays byte-identical to today).
fn banner_model_tail(choice: &ModelChoice) -> String {
    let argv = choice.claude_argv();
    if argv.is_empty() {
        String::new()
    } else {
        format!(" {}", argv.join(" "))
    }
}

fn launch_agent(choice: &ModelChoice, launch: &InteractiveLaunch) -> Result<()> {
    // The interactive argv/env/cwd is owned by the backend seam; for `claude`
    // this is the original hardwired argv rooted at the garden plus the slice
    // 002 `--model`/`--effort` tail, and for `opencode` it wires
    // `OPENCODE_CONFIG` + the runtime cwd + the first-turn kick (slice 003).
    let backend = choice.backend;
    let claude_argv = choice.claude_argv();
    let mut cmd = interactive_command(backend, launch, &claude_argv)?;
    let bin = agent_bin(backend);
    match backend {
        Backend::Claude => {
            let slot = launch
                .claude_slot
                .map(|s| format!(" on claude-login slot {}", s.name))
                .unwrap_or_default();
            // Name the model + effort when either is pinned, so the human can
            // see what is about to launch; `claude` on the harness default
            // stays "launching claude --name …" exactly as before.
            let tail = banner_model_tail(choice);
            println!("\nlaunching {bin} --name {AGENT_NAME}{slot}{tail} …\n");
        }
        // Name the model: with four ways to pick one, the human should never have
        // to guess which one is about to burn tokens.
        Backend::Opencode => {
            let variant = choice
                .variant
                .as_deref()
                .map(|v| format!(" ({v})"))
                .unwrap_or_default();
            println!(
                "\nlaunching {bin} {} on {}{variant} …\n",
                opencode_interactive_args().join(" "),
                choice.opencode_model()
            );
        }
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to launch `{bin}` — is it on PATH?"))?;
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
    println!("  refreshed  loop.json, mcp.json, opencode.json, inject.sh, statusline.sh");
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
/// Which directory the opencode agent is granted via `external_directory` so it
/// can read and rewrite its baton (slice 006).
///
/// In the standard layout the runtime dir is `<config>/softfig/growlight`, and the
/// grant is its **parent** — `<config>/softfig` — so sibling runtime state (usage,
/// per-member `agents/`, anything the daemon adds later) is covered by the same
/// rule rather than needing a new one each time. Under a `--config-dir` override
/// the runtime dir is wherever the caller said, and its parent is none of our
/// business — grant exactly that directory.
fn runtime_grant_root(runtime: &Path) -> &Path {
    match runtime.parent() {
        Some(parent) if runtime.file_name() == Some(std::ffi::OsStr::new(PILLAR)) => parent,
        _ => runtime,
    }
}

pub(crate) fn runtime_dir(override_: Option<PathBuf>) -> Result<PathBuf> {
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
/// budgets to `usage.json` (spec §6); the SessionEnd hook ingests the
/// session's transcript into the telemetry db (spec-token-telemetry §4.2).
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
/// token (`.credentials.json`) and harness settings stay out of the loop's
/// reach.
fn loop_json(
    inject: &Path,
    statusline: &Path,
    garden_root: &Path,
    claude_projects: &Path,
    softfig: &Path,
    runtime: &Path,
) -> String {
    let inject = inject.display().to_string();
    // The garden root + runtime dir are baked in so the rows are priced from,
    // and keyed by, the same garden and root baton this launch used, with no
    // daemon round-trip at session end. The verb always exits 0.
    let session_end = format!(
        "{} telemetry ingest-transcript --garden-root {} --config-dir {}",
        shell_quote(softfig),
        shell_quote(garden_root),
        shell_quote(runtime)
    );
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
            ],
            "SessionEnd": [
                { "hooks": [ { "type": "command", "command": session_end } ] }
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
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent() {
            let sibling = dir.join("softfig-mcp");
            if sibling.is_file() {
                return sibling;
            }
        }
    PathBuf::from("softfig-mcp")
}

/// SessionStart hook body: emit the fixed protocol (from the garden pillar) +
/// the current runtime baton + the boot dirty-tree check (task 064, protocol
/// step 1b) to stdout, which Claude Code adds to the fresh session's context.
fn inject_script(protocol: &Path, baton: &Path, softfig: &Path, garden_root: &Path) -> String {
    const TPL: &str = r#"#!/usr/bin/env bash
# GENERATED by `softfig growlight start` — do not edit (refreshed each launch).
# SessionStart hook: injects the fixed operating protocol + the current baton
# into a fresh loop session on startup and on /clear. stdout becomes context.
set -u
printf '=== SOFT-FIG GROWLIGHT · OPERATING PROTOCOL ===\n\n'
cat @PROTOCOL@ 2>/dev/null || printf '(protocol.md missing — run `softfig growlight init`)\n'
printf '\n\n=== CURRENT BATON (your only carried state) ===\n\n'
cat @BATON@ 2>/dev/null || printf '(no baton yet — run `softfig growlight start`)\n'
@SOFTFIG@ growlight boot-check --garden-root @GARDEN@ --baton @BATON@ 2>/dev/null || true
"#;
    TPL.replace("@PROTOCOL@", &shell_quote(protocol))
        .replace("@BATON@", &shell_quote(baton))
        .replace("@SOFTFIG@", &shell_quote(softfig))
        .replace("@GARDEN@", &shell_quote(garden_root))
}

/// `softfig growlight boot-check`: print the boot dirty-tree signal under a
/// heading, or nothing. The baton is a carried one here (the hook runs on a
/// boot or a `/clear`, never right after `start` seeds it), so its last write
/// is the handoff.
fn boot_check(args: &BootCheckArgs) {
    if let Some(line) = boot_dirty_check(&args.garden_root, &args.baton, false) {
        println!("\n\n=== BOOT DIRTY-TREE CHECK (protocol step 1b) ===\n\n{line}");
    }
}

/// The running `softfig` binary, for the generated hook to call back into —
/// the absolute path of this executable, else `softfig` on `PATH`.
fn softfig_bin_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("softfig"))
}

/// statusLine hook body: on every render, tee the two budgets to `usage.json`
/// (the loop's budget read path) and print a compact mode + budget line.
///
/// Slice 009 S9: the snapshot is tagged with the slot derived from
/// `CLAUDE_CONFIG_DIR` (a store path gives `<slot>`, unset gives `home`), and
/// a copy is teed into the per-profile file `usage.by-profile/<slot>.json` —
/// which is the write that makes the budget picker's per-profile
/// vouchable-pct path live for an interactive session.
///
/// Slice 009 S8 (statusline half): the SHARED `usage.json` is only written
/// when the session's slot matches the active-pointer slot. A session against
/// an inactive slot leaves no mark on the shared file, so §2b on an active
/// slot cannot halt on another slot's reading. The active-pointer path is
/// baked in at launch; a session that outlives a `claude-login use` keeps
/// writing to the per-profile file either way, so no slot's reading is lost.
fn statusline_script(usage: &Path, by_profile_dir: &Path, active_link: &Path) -> String {
    const TPL: &str = r#"#!/usr/bin/env bash
# GENERATED by `softfig growlight start` — do not edit (refreshed each launch).
# statusLine hook: tee the two budgets to usage.json (spec-growlight.md §6, the
# loop's budget read path) and print a compact mode + budget line.
set -u
input=$(cat)
# Slice 009 S9: derive the slot from CLAUDE_CONFIG_DIR — a store path gives
# <slot>, unset gives "home" (the fallback slot). The slot tags every snapshot
# and names the per-profile file, so the picker's per-profile vouchable-pct
# path is live for this session.
slot=home
if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
    slot=$(basename -- "$CLAUDE_CONFIG_DIR")
fi
# Claude Code derives context_window.used_percentage from a cumulative token
# total over the window, so it can exceed 100 in a long session. Clamp it to a
# sane 0..100 the governor can trust (spec-growlight.md §6) BEFORE teeing — but
# only when it is actually a number, so a missing % stays absent (never coerced
# to a false 0), and keep remaining_percentage consistent with the clamp.
snap=$(printf '%s' "$input" | jq --arg profile "$slot" '
  (if (.context_window.used_percentage | type) == "number" then
        .context_window.used_percentage |= ([., 100] | min) | .context_window.used_percentage |= ([., 0] | max)
      | .context_window.remaining_percentage = (100 - .context_window.used_percentage)
   else . end)
  | {context_window, rate_limits, ts: now, profile: $profile}' 2>/dev/null) || snap=
if [ -n "$snap" ]; then
    # Slice 009 S9: per-profile tee. The dir rides the same runtime grant as
    # usage.json, so a member's permission floor already covers it.
    mkdir -p @BY_PROFILE_DIR@ 2>/dev/null || true
    printf '%s' "$snap" > @BY_PROFILE_DIR@/"$slot".json 2>/dev/null || true
    # Slice 009 S8: the shared usage.json holds the active slot ONLY. An
    # inactive-slot session (e.g. one started before a `claude-login use`
    # swap) tees to its per-profile file above and no further — the shared
    # file never mixes accounts, and §2b on the active slot cannot halt on
    # a stale sibling's reading.
    active=home
    if [ -L @ACTIVE_LINK@ ]; then
        active=$(readlink @ACTIVE_LINK@ 2>/dev/null || echo home)
    fi
    if [ "$slot" = "$active" ]; then
        printf '%s' "$snap" > @USAGE@ 2>/dev/null || true
    fi
fi
ctx=$(printf '%s' "$input" | jq -r '([(.context_window.used_percentage // 0), 100] | min)' 2>/dev/null || echo 0)
five=$(printf '%s' "$input" | jq -r '.rate_limits.five_hour.used_percentage // 0' 2>/dev/null || echo 0)
printf 'softfig-loop · ctx %s%% · 5h %s%%' "$ctx" "$five"
"#;
    TPL.replace("@USAGE@", &shell_quote(usage))
        .replace("@BY_PROFILE_DIR@", &shell_quote(by_profile_dir))
        .replace("@ACTIVE_LINK@", &shell_quote(active_link))
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
// — a separate process from keeperd — and REPLACE nothing: the semi-auto
// interactive launcher above stays intact (growlightd is the one control plane
// for autonomous runs). `status`/`stop`/`pause`/`resume` are one-shot `call`s
// reusing the keeperd client idiom (`try_daemon_call`); `watch` tails the one
// STREAMING verb (`subscribe`) with a `read_line` → decode-`Event` loop,
// mirroring growlightd's `tests/subscribe_stream.rs`.

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
    // The v2 queue view (§6.9): both lanes, the stack per repo, and the
    // session log — the same annotations `queue show` layers onto its TOML.
    // Best-effort: the fleet status above is the core render.
    if let Some(view) = fetch_queue_view(&socket)? {
        let rendered = render_status_queue(&view);
        if !rendered.is_empty() {
            println!();
            print!("{rendered}");
        }
    }
    Ok(())
}

/// The queue block `status` appends to the fleet status: nothing at all when
/// there is no v2 list (`status` is not the place to explain an absent
/// `queue.toml` — `queue show` is).
fn render_status_queue(view: &QueueShowReply) -> String {
    if !view.list {
        return String::new();
    }
    format!(
        "queue v2\n{}{}",
        render_queue_lanes(view),
        render_annotations(view)
    )
}

/// `QUEUE_SHOW` against growlightd, best-effort: it is an annotation layered
/// onto a verb that already has its own answer, so a daemon that cannot serve
/// it must not fail the verb. `None` when growlightd is absent, or when it
/// rejects the call with `BadArgs` — what a daemon older than the verb says,
/// whether for the unknown op or a protocol-version mismatch (growlightd
/// reports both as `BadArgs`); that case also leaves one line on stderr. Any
/// other daemon error is still surfaced.
fn fetch_queue_view(socket: &Path) -> Result<Option<QueueShowReply>> {
    match try_daemon_call(socket, growlightd::op::QUEUE_SHOW, serde_json::Value::Null) {
        Ok(Some(value)) => Ok(Some(serde_json::from_value(value)?)),
        Ok(None) => Ok(None),
        Err(ClientError::Daemon { kind: ErrorKind::BadArgs, message }) => {
            eprintln!("queue annotations unavailable — growlightd rejected queue show ({message})");
            Ok(None)
        }
        Err(ClientError::Daemon { kind, message }) => {
            Err(anyhow!("growlightd error ({kind:?}): {message}"))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

/// The §11 switch's status line. `protocol` above is the wire version and stays
/// `v1` under either queue, so this is the line that shows a flip took. A
/// growlightd older than the field sends nothing, which says nothing about which
/// queue it runs, so no line is printed.
fn queue_switch_line(r: &FleetStatusReply) -> Option<String> {
    (!r.queue.is_empty()).then(|| format!("queue         {}", r.queue))
}

/// Render a [`FleetStatusReply`] for the terminal.
fn print_fleet_status(r: &FleetStatusReply) {
    println!("state         {}", r.state);
    println!("garden        {}", r.garden_root);
    println!("protocol      v{}", r.protocol_version);
    // The config-level arm/disarm gate (`config/growlight.toml fleet_enabled`),
    // distinct from `paused` (the runtime admission gate over an armed fleet).
    println!("fleet         {}", if r.fleet_enabled { "enabled" } else { "disabled" });
    if let Some(line) = queue_switch_line(r) {
        println!("{line}");
    }
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
    // The live per-agent runtime state — one row per member of an ARMED fleet
    // (empty while disarmed, when `roster` above is the whole truth).
    if r.agents.is_empty() {
        println!("agents        (none)");
    } else {
        println!("agents:");
        for a in &r.agents {
            println!("{}", agent_row(a));
        }
    }
    // The parts the fleet is leaving for the human (task 068), with the skip reason
    // the journal gave. Each stays `queued` and pages no one, so this is where a
    // hold shows; dropping the item's `> Fleet:` line frees it.
    if r.held.is_empty() {
        println!("held          (none)");
    } else {
        println!("held:");
        for h in &r.held {
            println!("  {:<32} {}", format!("{}/{}", h.queue, h.part), h.reason);
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    print!("{}", render_schedule(r.schedule.as_ref(), now));
    print!("{}", render_build_caps(&r.build_caps));
}

/// One `agents:` row: id, status, the claude-login slot the member's last
/// session ran on (claude-login-switcher slice 007; blank for opencode or a
/// member not yet spawned), then [`agent_accounting`]. Pure over the reply.
fn agent_row(a: &growlightd::AgentSummary) -> String {
    let profile = a
        .profile
        .as_deref()
        .map(|p| format!("profile={p}"))
        .unwrap_or_default();
    format!("  {:<16} {:<12} {:<16} {}", a.id, a.status, profile, agent_accounting(a))
}

/// The accounting half of an `agents:` row: which backend serves the member and —
/// when that backend is metered — the model and what it has cost this session.
///
/// A subscription (claude) member shows its backend and nothing more. That absence
/// is the point: its cost is the shared 5h/7d reserve printed on the `policy` line
/// above, not a per-member figure, so there is no dollar column to leave blank and
/// no empty reserve gauge drawn against a metered member either. Pure over the
/// reply, so it is unit-proven without a daemon.
fn agent_accounting(a: &growlightd::AgentSummary) -> String {
    let mut out = a.backend.clone();
    if let Some(model) = &a.model {
        out.push_str(" · ");
        out.push_str(model);
    }
    if let Some(spend) = &a.spend {
        out.push_str(&format!(
            " · {} this session ({} step{})",
            spend.dollars(),
            spend.steps,
            if spend.steps == 1 { "" } else { "s" },
        ));
    }
    out
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
        // `resources show` — the live default caps (off `status`) + the RUNNING
        // scope units a live `set` reconciles, taken verbatim from `status`
        // (`live_scopes`) — never reconstructed CLI-side, since slice 002 made the
        // unit name carry a per-spawn generation. (Per-scope LIVE values via
        // `systemctl show` are an on-device read deferred to the §7b verify.)
        ResourcesCmd::Show(a) => {
            let socket = growlight_socket(a.socket);
            let reply: FleetStatusReply =
                growlight_call(&socket, growlightd::op::STATUS, serde_json::Value::Null)?;
            print!("{}", render_resources_show(&reply));
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
    let quota = c.cpu_quota.as_deref().unwrap_or("(unset)");
    let threads = c
        .test_threads
        .map(|t| t.to_string())
        .unwrap_or_else(|| "(unset)".to_string());
    format!(
        "build caps    (live default — the next spawn's throttle)\n  \
         cargo_build_jobs  {jobs}\n  memory_high       {mem}\n  cpu_weight        {weight}\n  \
         cpu_quota         {quota}\n  test_threads      {threads}\n",
    )
}

/// Render the `[schedule]` block of `status` (growlight-schedule slice 006).
/// `now` (Unix seconds) turns a reserve's reset into "resets in …". Pure, so
/// it is unit-tested without a daemon.
fn render_schedule(s: Option<&growlightd::ScheduleSummary>, now: i64) -> String {
    let Some(s) = s else {
        return "schedule      (none)\n".to_string();
    };
    let state = if s.open { "open" } else { "closed" };
    let mut out = format!("schedule      {state} (zone {})\n", s.zone);
    if !s.current_windows.is_empty() {
        out += &format!("  open now      {}\n", s.current_windows.join(", "));
    }
    // No edge in the week ahead: an open schedule stays open throughout, a
    // closed one has no window that opens.
    let edge = s.next_edge_local.as_deref().unwrap_or(if s.open {
        "(none within a week — open throughout)"
    } else {
        "(none within a week — no window opens)"
    });
    out += &format!("  next edge     {edge}\n");
    for h in &s.held_members {
        out += &format!("  held          {:<16} {}\n", h.agent, h.reason);
    }
    for item in &s.held_items {
        out += &format!("  waiting       {item}\n");
    }
    for r in &s.reserve {
        let used = r.used_7d_pct.map_or_else(|| "unknown".to_string(), |p| format!("{p}%"));
        let state = if r.held { "held" } else { "clear" };
        let resets = r
            .resets_at
            .map(|at| format!(", resets in {}", softfig_ipc::human_age_secs(at.saturating_sub(now).max(0) as u64)))
            .unwrap_or_default();
        out += &format!(
            "  reserve       {:<16} keep {}% · 7d used {used} · {state}{resets}\n",
            r.slot, r.reserve_pct
        );
    }
    for p in &s.projection {
        out += &format!("  projection    {:<16} {:<12} {}\n", p.slot, projection_label(p), projection_eta(p, now));
    }
    out
}

/// Which cap a projection row runs to: `5h`, `7d`, or `reserve 80%`.
fn projection_label(p: &growlightd::PoolProjection) -> String {
    if p.window == "reserve" { format!("reserve {}%", p.target_pct) } else { p.window.clone() }
}

/// A projection row's range, relative to `now` (§3.11): never a point.
fn projection_eta(p: &growlightd::PoolProjection, now: i64) -> String {
    let until = |at: i64| softfig_ipc::human_age_secs(at.saturating_sub(now).max(0) as u64);
    let resets = p.resets_at.map(|at| format!(", resets in {}", until(at))).unwrap_or_default();
    match (p.cap_at_earliest, p.cap_at_latest) {
        (Some(e), Some(l)) => match (until(e), until(l)) {
            (e, l) if e == l => format!("cap in ~{e}{resets}"),
            (e, l) => format!("cap in {e}–{l}{resets}"),
        },
        (Some(e), None) => format!("cap in {} at the earliest, or resets first{resets}", until(e)),
        (None, _) if p.resets_first => format!("resets first{resets}"),
        (None, _) => "unknown".to_string(),
    }
}

/// Render `resources show`: the live default caps + the genuinely-running scope
/// units (`status.live_scopes`, verbatim — not reconstructed CLI-side, slice 006).
/// Pure (returns the text) so it is unit-tested without a daemon.
fn render_resources_show(reply: &FleetStatusReply) -> String {
    let mut out = render_build_caps(&reply.build_caps);
    if reply.live_scopes.is_empty() {
        // No running scopes: distinguish a disarmed fleet from an armed-but-idle one
        // so the operator isn't misled (the roster is configured, nothing spawned).
        if reply.fleet_enabled {
            out.push_str("scopes        (none running)\n");
        } else {
            out.push_str("scopes        (none — fleet disarmed)\n");
        }
    } else {
        out.push_str(&format!("scopes        {}\n", reply.live_scopes.join(", ")));
    }
    out
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
    // For an immediate hard-kill, report whether a live agent was actually
    // terminated (`performed`) — a no-op kill (nothing running behind the id) must
    // NOT read as success (the audit-005 false-success fix). A boundary stop only
    // records an intent.
    let outcome = if !reply.immediate {
        "recorded for the next boundary"
    } else if reply.performed {
        "applied now — killed a live agent"
    } else {
        "no-op — no live agent to kill"
    };
    println!(
        "stop {}: agent {} ({})",
        outcome,
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
    // `subscribe` is a long-lived stream: connect WITHOUT a read timeout so an
    // idle daemon (no events) blocks for the next frame instead of the read
    // timing out into a fatal EAGAIN (os error 11). Ctrl-C / EOF are the only
    // exits — the verb's contract. (One-shot verbs use `softfig_ipc::connect`.)
    let mut stream = softfig_ipc::connect_stream(&socket).map_err(|e| {
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

fn client_reports(args: ReportsArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let req = ListReportsArgs { tags: args.tags.clone() };
    match try_daemon_call(&socket, op::LIST_REPORTS, serde_json::to_value(req)?) {
        Ok(Some(value)) => {
            let reply: ListReportsReply = serde_json::from_value(value)?;
            let shown = unresolved_unless_all(reply.reports, args.all || has_status_tag(&args.tags));
            if shown.is_empty() {
                println!("no matching reports");
            }
            for r in &shown {
                println!("{}", report_line(r));
            }
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

/// Whether the caller already filtered on status (then `--all` is implied).
fn has_status_tag(tags: &[String]) -> bool {
    tags.iter().any(|t| t.trim().to_ascii_lowercase().starts_with("status:"))
}

/// Drop closed reports (`resolved` / `wontfix` / `duplicate`) unless `all`.
fn unresolved_unless_all(reports: Vec<ReportRow>, all: bool) -> Vec<ReportRow> {
    const CLOSED: [&str; 3] = ["status:resolved", "status:wontfix", "status:duplicate"];
    reports
        .into_iter()
        .filter(|r| all || !r.tags.iter().any(|t| CLOSED.contains(&t.as_str())))
        .collect()
}

/// One report as a terminal line: number, title, then its tags.
fn report_line(r: &ReportRow) -> String {
    format!("#{:03}  {}  [{}]", r.number, r.title, r.tags.join(" "))
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

// ---- queue v2 §6.9 CLI forms (queue-v2-state slice 009) ----------------

/// The queue v2 human surface (§6.9): `show` and the mutating forms — `project
/// add`, `add`, `move`, `lane`, `after`, `status`, `drop`. Each mutating form
/// is a thin client over the matching §6.8 keeperd verb, with `--dry-run`
/// (compute + validate + render the would-be list, write nothing), plus the
/// read-only `pick` (growlightd's `pick_v2`). The verbs touch only the v2
/// files; the fleet schedules from them only under `queue = "v2"` in
/// `config/growlight.toml` (default `legacy`, §11).
#[derive(Args, Debug)]
pub struct QueueArgs {
    /// keeperd socket. Defaults to `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// growlightd socket, for `show`'s live git-stack + session annotations
    /// (growlightd runs the read-only git) and for `pick`. Goes before the
    /// subcommand, like `--socket`. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-growlightd.sock`.
    #[arg(long, value_name = "SOCKET")]
    pub growlightd_socket: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Option<QueueSub>,
}

#[derive(Subcommand, Debug)]
pub enum QueueSub {
    /// (default) show the live v2 list from `queue.toml` — both lanes, one row
    /// per entry in file order: id, kind, title, project, lane, status, the
    /// `after` links, and the stack columns (branch/base/claimed) verbatim
    /// from the TOML. Then, when growlightd answers, the live annotations:
    /// the open flag per branch, the stack per repo and the session log.
    /// Best-effort — a stopped or older growlightd just omits them.
    Show,

    /// Read-only: what `pick_v2` assigns a member now, and why every skipped
    /// entry was skipped (§6.9). This form is **growlightd's** verb (the pick
    /// lives there, not in keeperd), so it answers on `--growlightd-socket`.
    Pick {
        /// A roster member id. Omitted: an unpinned member on the default
        /// backend.
        #[arg(long)]
        member: Option<String>,
    },

    /// Append a `[[project]]` row — `queue project add`.
    Project {
        #[command(subcommand)]
        cmd: QueueProjectSub,
    },

    /// Create a backlog entry — a milestone (docs + `slices.toml` + the
    /// generated `001-plan` slice), a numbered task (`fix/<NNN>` branch), or an
    /// urgent no-branch restack — plus its lane-placed row in `queue.toml`.
    Add(QueueAddArgs),

    /// Move an entry within its own lane (`front | back | before <ref> |
    /// behind <ref>`).
    Move(QueueMoveArgs),

    /// Change an entry's lane (`urgent | normal`).
    Lane(QueueLaneArgs),

    /// Replace an entry's `after` links; no ids clears them.
    After(QueueAfterArgs),

    /// Set an entry's status (`queued | blocked | deferred | done`).
    Status(QueueStatusArgs),

    /// Hold an entry for the human (`no`: the fleet never claims it) or
    /// release it to the fleet (`yes`) — the row's `fleet` field.
    Fleet(QueueFleetArgs),

    /// Set an entry's start time (the row's `not_before`): a `queued` entry
    /// is held until then. `""` clears it.
    NotBefore(QueueNotBeforeArgs),

    /// Opt a resumed branch into the loop's automatic restack (`yes`), or hold
    /// a fleet-cut branch out of it (`no`) — the row's `auto_restack` field. A
    /// first claim that finds the branch already existing writes `no`.
    AutoRestack(QueueAutoRestackArgs),

    /// Repair a migrated entry's `branch`, `base` or `project` (report 171).
    /// Refused `running` only while a live session holds the entry (an `active`
    /// entry nothing holds takes it).
    Repair(QueueRepairArgs),

    /// Drop an entry — its row moves to `queue-archive.toml` as `dropped`.
    Drop(QueueDropArgs),

    /// Convert the legacy backlog to the v2 files (§11). `--dry-run` reads the
    /// backlog off the mount and the runtime batons, and prints the plan,
    /// every judgment call and every refusal. It writes nothing and calls no
    /// daemon. `--apply` has keeperd write the v2 files in one commit, then
    /// copies the in-flight batons into `entries/<id>/baton.md`.
    Migrate(QueueMigrateArgs),
}

#[derive(Args, Debug)]
pub struct QueueMigrateArgs {
    /// Print the plan; write nothing.
    #[arg(long, required_unless_present = "apply", conflicts_with = "apply")]
    pub dry_run: bool,
    /// Write the v2 files in one keeperd commit. keeperd refuses while the
    /// fleet is armed, the switch says v2, a v2 file exists, the snapshot
    /// moved off `--expect`, or a call is still open. Never flips the switch.
    #[arg(long, requires = "answers", requires = "expect")]
    pub apply: bool,
    /// The owner's settlements (`schema = 1`, `[class]`, `[call]`).
    /// Omitted: every call stays open.
    #[arg(long, value_name = "TOML")]
    pub answers: Option<PathBuf>,
    /// The snapshot version the dry run printed; `--apply` refuses if any
    /// backlog file or baton has changed since.
    #[arg(long, value_name = "VERSION", requires = "apply")]
    pub expect: Option<String>,
    /// The mounted garden the dry run reads. Defaults to `~/soft-fig_garden`.
    /// Refused with `--apply`: keeperd reads its own garden, so a path here
    /// would name a copy the apply never looks at.
    #[arg(long, value_name = "PATH", conflicts_with = "apply")]
    pub garden: Option<PathBuf>,
    /// With `--dry-run`: ask git for every open `stack_base` call and write
    /// the answers to OUT as an answers file you review, edit, and pass back
    /// as `--answers`. Nothing applies it by itself. An existing OUT is refused.
    #[arg(long, value_name = "OUT", requires = "dry_run", conflicts_with = "apply")]
    pub stack_answers: Option<PathBuf>,
    /// The growlight runtime dir the batons live in. Defaults to
    /// `$XDG_CONFIG_HOME/softfig/growlight`.
    #[arg(long, value_name = "PATH")]
    pub config_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum QueueProjectSub {
    /// Append a `[[project]]` row: a name bound to a repo and its merge branch.
    Add(QueueProjectAddArgs),
    /// Correct an existing project's repo (and optionally its merge branch):
    /// the repair `add` cannot make, since a repeat is refused `exists`.
    /// Refused `running` only while a live session holds one of the project's
    /// `active` entries.
    SetRepo(QueueProjectSetRepoArgs),
}

#[derive(Args, Debug)]
pub struct QueueProjectSetRepoArgs {
    /// The existing project's name.
    pub name: String,
    /// A local path (absolute, `~`, `~/…` or `~<you>/…`) or `host:path`, as
    /// for `project add`.
    pub repo: String,
    /// The branch merges land on; omitted keeps the project's current one.
    #[arg(long)]
    pub main: Option<String>,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct QueueProjectAddArgs {
    /// `[a-z0-9-]+` — the project name entries reference.
    pub name: String,
    /// A local path (absolute, `~`, `~/…` or `~<you>/…`) or `host:path`.
    /// Another user's `~<name>/…` or a relative path is refused.
    pub repo: String,
    /// The branch merges land on; defaults to `main`.
    #[arg(long)]
    pub main: Option<String>,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// The `queue add` kinds (§6.9): milestone | task | restack.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum AddKind {
    Milestone,
    Task,
    Restack,
}

#[derive(Args, Debug)]
pub struct QueueAddArgs {
    /// milestone | task | restack. A milestone gets its docs + `slices.toml` +
    /// the generated `001-plan` slice; a task its numbered doc; a restack a
    /// generated urgent doc (project only — every other arg is refused).
    pub kind: AddKind,
    /// The entry id / dir name — required for milestone and task; forbidden
    /// for restack (its slug is `restack-<project>`).
    pub slug: Option<String>,
    /// The owning project's name — must already exist (`queue project add`).
    #[arg(long)]
    pub project: String,
    /// Human title shown in the queue view + the doc heading.
    #[arg(long)]
    pub title: Option<String>,
    /// Why this entry exists (the doc's `## Mission`). A `@file` value is read
    /// from that file.
    #[arg(long)]
    pub mission: Option<String>,
    /// Checkable completion criteria (the doc's `## Finish criteria`). A
    /// `@file` value is read from that file.
    #[arg(long)]
    pub criteria: Option<String>,
    /// Place the entry in the urgent lane (default: normal).
    #[arg(long)]
    pub urgent: bool,
    /// Entry ids that must finish first; comma-separated.
    #[arg(long, value_delimiter = ',')]
    pub after: Vec<String>,
    /// Place at the front of the lane (default: back).
    #[arg(long, conflicts_with_all = ["before", "behind"])]
    pub front: bool,
    /// Place before this entry id.
    #[arg(long, conflicts_with_all = ["front", "behind"])]
    pub before: Option<String>,
    /// Place after this entry id (`behind` is the CLI spelling of the verbs'
    /// `after` position, §6.9).
    #[arg(long, conflicts_with_all = ["front", "before"])]
    pub behind: Option<String>,
    /// Make the entry human-only (`fleet = false`): the fleet never claims it.
    #[arg(long)]
    pub no_fleet: bool,
    /// Hold the entry until this time (`not_before`): `YYYY-MM-DD HH:MM
    /// ±HH:MM`, offset required.
    #[arg(long, value_name = "TIME")]
    pub not_before: Option<String>,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// The placement words (§6.9): front | back | before | behind. `behind` is the
/// CLI spelling of the verbs' `after` position, so it can't be confused with
/// `after` links (§6.9).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum MoveTarget {
    Front,
    Back,
    Before,
    Behind,
}

/// The human lane words (§6.9).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum LaneArg {
    Urgent,
    Normal,
}

/// The human status words (§6.9): queued | blocked | deferred | done.
/// `active`/`paused`/`split` are daemon-owned, so they are not CLI words.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum HumanStatus {
    Queued,
    Blocked,
    Deferred,
    Done,
}

#[derive(Args, Debug)]
pub struct QueueMoveArgs {
    /// The live entry id to move.
    pub id: String,
    /// Where to move it, inside its own lane. `before`/`behind` place relative
    /// to <ref>.
    pub to: MoveTarget,
    /// The reference entry id for `before`/`behind`.
    pub ref_id: Option<String>,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct QueueLaneArgs {
    /// The live entry id.
    pub id: String,
    /// urgent appends at the urgent lane's back; normal puts the entry at the
    /// normal lane's front (§6.8).
    pub lane: LaneArg,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct QueueAfterArgs {
    /// The live entry id.
    pub id: String,
    /// The new link list — replaces the whole list; no ids clears it.
    pub ids: Vec<String>,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct QueueStatusArgs {
    /// The live entry id.
    pub id: String,
    /// queued (also unblocks/un-defers) | blocked | deferred | done (archives
    /// the row).
    pub status: HumanStatus,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// The `queue fleet` words: yes (the fleet may claim it) | no (human-only).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum FleetArg {
    Yes,
    No,
}

#[derive(Args, Debug)]
pub struct QueueFleetArgs {
    /// The live entry id.
    pub id: String,
    /// yes releases the entry to the fleet; no holds it for the human. A
    /// live-held active entry keeps running.
    pub fleet: FleetArg,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct QueueAutoRestackArgs {
    /// The live entry id.
    pub id: String,
    /// yes lets the loop restack the entry's branch (it rewrites it, so only
    /// for a branch no session outside the queue is using); no holds it out.
    pub auto_restack: FleetArg,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct QueueNotBeforeArgs {
    /// The live entry id.
    pub id: String,
    /// `YYYY-MM-DD HH:MM ±HH:MM` (offset required; `T` and `Z` allowed), or
    /// `""` to clear the start time. An entry that has started ignores it.
    pub time: String,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
#[command(group(
    clap::ArgGroup::new("repair")
        .required(true)
        .multiple(true)
        .args(["branch", "base", "project"])
))]
pub struct QueueRepairArgs {
    /// The live entry id.
    pub id: String,
    /// The branch the entry's work lives on, a valid git branch name.
    #[arg(long)]
    pub branch: Option<String>,
    /// The commit or parent branch the entry was cut from; `""` clears it.
    #[arg(long)]
    pub base: Option<String>,
    /// Move the entry to another existing project.
    #[arg(long)]
    pub project: Option<String>,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct QueueDropArgs {
    /// The live entry id to drop.
    pub id: String,
    /// Why the work is abandoned — recorded on the archived row. A `@file`
    /// value is read from that file.
    #[arg(long)]
    pub reason: String,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// The queue v2 slice surface (§6.9): `insert`, `move` and `status` inside a
/// milestone's `slices.toml`, thin clients over the §6.8 keeperd verbs, each
/// with `--dry-run`.
#[derive(Args, Debug)]
pub struct SliceArgs {
    /// keeperd socket. Defaults to `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: SliceSub,
}

#[derive(Subcommand, Debug)]
pub enum SliceSub {
    /// Append a numbered slice — writes `slices/NNN-<slug>.md` (NNN from the
    /// milestone's `.seq`) and inserts the queued item into `slices.toml`.
    Insert(SliceInsertArgs),
    /// Move a slice item within `slices.toml` file order.
    Move(SliceMoveArgs),
    /// Set a slice item's status.
    Status(SliceStatusArgs),
}

#[derive(Args, Debug)]
pub struct SliceInsertArgs {
    /// The owning milestone: a top-level id, or `<parent>/<sub>` for a
    /// sub-milestone (≤ 2 deep).
    pub milestone: String,
    /// `[a-z0-9-]+` — the slice's terse filename address (`NNN-<slug>.md`).
    pub slug: String,
    /// Slice heading title; defaults to the slug.
    #[arg(long)]
    pub title: Option<String>,
    /// The slice's plan/spec markdown body. A `@file` value is read from that
    /// file.
    #[arg(long)]
    pub body: String,
    /// Where to insert (default: back). `before`/`behind` place relative to
    /// <ref>.
    pub position: Option<MoveTarget>,
    /// The reference item for `before`/`behind`.
    pub ref_id: Option<String>,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct SliceMoveArgs {
    /// The owning milestone (a top-level id, or `<parent>/<sub>`).
    pub milestone: String,
    /// The `[[item]]` id to move (the NNN, or a sub-milestone slug).
    pub id: String,
    /// Where to move it, within `slices.toml` file order.
    pub to: MoveTarget,
    /// The reference item for `before`/`behind`.
    pub ref_id: Option<String>,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct SliceStatusArgs {
    /// The owning milestone (a top-level id, or `<parent>/<sub>`).
    pub milestone: String,
    /// The `[[item]]` id (the NNN, or a sub-milestone slug).
    pub id: String,
    /// queued (also unblocks/un-defers) | blocked | deferred | done (resets
    /// follow_ups).
    pub status: HumanStatus,
    /// Compute + validate + render the would-be state, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

fn client_queue(args: QueueArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let growlightd_socket = growlight_socket(args.growlightd_socket);
    match args.cmd.unwrap_or(QueueSub::Show) {
        QueueSub::Show => queue_show(&socket, &growlightd_socket),
        QueueSub::Pick { member } => queue_pick(&growlightd_socket, member.as_deref()),
        QueueSub::Project { cmd } => match cmd {
            QueueProjectSub::Add(a) => queue_project_add(&socket, a),
            QueueProjectSub::SetRepo(a) => queue_project_set_repo(&socket, a),
        },
        QueueSub::Add(a) => queue_add(&socket, a),
        QueueSub::Move(a) => queue_move(&socket, a),
        QueueSub::Lane(a) => queue_lane(&socket, a),
        QueueSub::After(a) => queue_after(&socket, a),
        QueueSub::Status(a) => queue_status(&socket, a),
        QueueSub::Fleet(a) => queue_fleet(&socket, a),
        QueueSub::NotBefore(a) => queue_not_before(&socket, a),
        QueueSub::AutoRestack(a) => queue_auto_restack(&socket, a),
        QueueSub::Repair(a) => queue_repair(&socket, a),
        QueueSub::Drop(a) => queue_drop(&socket, a),
        QueueSub::Migrate(a) => queue_migrate(&socket, a),
    }
}

fn client_slice(args: SliceArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    match args.cmd {
        SliceSub::Insert(a) => slice_insert(&socket, a),
        SliceSub::Move(a) => slice_move(&socket, a),
        SliceSub::Status(a) => slice_status(&socket, a),
    }
}

/// The shared daemon-reply handling for the mutating forms: `Ok(None)` means
/// no daemon; a daemon error's message already leads with the refusal code
/// ([`softfig_ipc::queue_v2::QueueRefusal::code`]), so it is surfaced as-is
/// without a `kind:` decoration.
fn queue_call(socket: &Path, op_name: &str, args: serde_json::Value) -> Result<serde_json::Value> {
    match try_daemon_call(socket, op_name, args) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(anyhow!(
            "no daemon at {} — unlock the garden first (`softfig daemon unlock`)",
            socket.display()
        )),
        Err(ClientError::Daemon { message, .. }) => Err(anyhow!("{message}")),
        Err(e) => Err(anyhow!("{e}")),
    }
}

/// Print a verb reply the way §6.9 wants: the rendered view, plus a dry-run
/// marker (nothing was written) or the commit on a real write. The view is the
/// same body the §6.9 MCP verbs render in their summaries.
fn print_verb_reply(dry_run: bool, view: &str, hash: &str) {
    if dry_run {
        println!("dry run — nothing written; would-be list:");
    }
    print!("{view}");
    if !dry_run {
        println!("commit {}", short_hash(hash));
    }
}

/// The edit's notes — what it kept but does not do (a start time on an
/// entry it cannot hold, F2) — one `note:` line each, after the list.
fn print_notes(notes: &[String]) {
    for note in notes {
        println!("note: {note}");
    }
}

/// §6.9: a value starting with `@` is read from that file. Anything else
/// passes through unchanged.
fn value_or_file(value: &str) -> Result<String> {
    match value.strip_prefix('@') {
        Some(path) if !path.is_empty() => {
            Ok(fs::read_to_string(path).with_context(|| format!("reading {path}"))?)
        }
        Some(_) => bail!("`@` needs a file path after it (`@path/to/file`)"),
        None => Ok(value.to_string()),
    }
}

/// The placement words → the verbs' `position`/`to` vocabulary (§6.9):
/// `behind` is the CLI spelling of the verbs' `after` position, so it can't be
/// confused with `after` links. `before`/`behind` need a `<ref>`; `front`/`back`
/// take none.
fn placement(to: MoveTarget, ref_id: Option<String>) -> Result<(String, Option<String>)> {
    match (to, ref_id) {
        (MoveTarget::Front, None) => Ok(("front".to_string(), None)),
        (MoveTarget::Back, None) => Ok(("back".to_string(), None)),
        (MoveTarget::Before, Some(r)) => Ok(("before".to_string(), Some(r))),
        (MoveTarget::Behind, Some(r)) => Ok(("after".to_string(), Some(r))),
        (MoveTarget::Before, None) | (MoveTarget::Behind, None) => {
            bail!("`before`/`behind` need a <ref> to place relative to")
        }
        (MoveTarget::Front, Some(_)) | (MoveTarget::Back, Some(_)) => {
            bail!("`front`/`back` take no <ref>")
        }
    }
}

fn queue_show(socket: &Path, growlightd_socket: &Path) -> Result<()> {
    let read = try_daemon_call(
        socket,
        op::READ_FILE,
        serde_json::to_value(ReadFileArgs {
            path: QUEUE_FILE.to_string(),
        })?,
    );
    match read {
        Ok(Some(value)) => {
            let reply: ReadFileReply = serde_json::from_value(value)?;
            let queue = QueueToml::parse(&reply.content).map_err(|e| {
                anyhow!("{QUEUE_FILE} does not parse ({e}) — keeperd writes it, so this is corruption")
            })?;
            print!("{}", render_queue_show(&queue));
            // The live git-stack + session annotations (queue-v2-git slice
            // 006) — growlightd runs the read-only git, keeperd can't (§8).
            // Best-effort: a stopped growlightd, or one too old to know the
            // verb, just skips the annotations (the TOML table above is the
            // core render).
            if let Some(view) = fetch_queue_view(growlightd_socket)?
                && view.list
            {
                print!("{}", render_doc_hold_warnings(&view));
                print!("{}", render_annotations(&view));
            }
            Ok(())
        }
        // §3.4: the view renders only when the TOML file exists. A missing
        // file is the expected fresh-garden state, not an error.
        Err(ClientError::Daemon { kind: ErrorKind::NotFound, .. }) => {
            println!("{}", queue_empty_line());
            Ok(())
        }
        Ok(None) => Err(anyhow!(
            "no daemon at {} — unlock the garden first (`softfig daemon unlock`)",
            socket.display()
        )),
        Err(ClientError::Daemon { message, .. }) => Err(anyhow!("{message}")),
        Err(e) => Err(anyhow!("{e}")),
    }
}

/// The §3.4 nothing-to-show line: shared by `queue show` and `queue pick` so the
/// two can never drift into saying different things about the same absent file.
fn queue_empty_line() -> String {
    format!(
        "no {QUEUE_FILE} — the v2 queue is empty (§3.4: the view renders only when the file exists)"
    )
}

/// `queue pick` (§6.9): a read-only **growlightd** call (the pick and the v2
/// source live there). No `--member`: an unpinned member on the default
/// backend. The reply carries the assignment and every skip reason; nothing is
/// written.
fn queue_pick(socket: &Path, member: Option<&str>) -> Result<()> {
    let args = growlightd::QueuePickArgs {
        member: member.map(str::to_string),
    };
    let reply: growlightd::QueuePickReply =
        growlight_call(socket, growlightd::op::QUEUE_PICK, serde_json::to_value(args)?)?;
    print!("{}", render_queue_pick(&reply));
    Ok(())
}

/// `queue migrate`. `--dry-run`: snapshot the legacy files, plan, print —
/// plain file reads, no daemon call. `--apply`: see [`queue_migrate_apply`].
fn queue_migrate(socket: &Path, args: QueueMigrateArgs) -> Result<()> {
    let runtime = runtime_dir(args.config_dir)?;
    let answers = match &args.answers {
        Some(path) => {
            let text = fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            toml::from_str::<migrate::Answers>(&text)
                .with_context(|| format!("parsing {}", path.display()))?
        }
        None => migrate::Answers {
            schema: migrate::ANSWERS_SCHEMA_VERSION,
            class: Default::default(),
            call: Default::default(),
        },
    };
    if args.apply {
        let expect = args.expect.ok_or_else(|| anyhow!("--apply needs --expect"))?;
        return queue_migrate_apply(socket, &runtime, answers, expect);
    }
    let garden = match args.garden {
        Some(p) => p,
        None => home_dir()?.join("soft-fig_garden"),
    };
    let files = migrate_snapshot(&garden, &runtime)?;
    if !files.garden.contains_key(BACKLOG_DOC) {
        bail!("no {BACKLOG_DOC} under {}", garden.display());
    }
    let version = files.digest();
    let legacy = migrate::read_legacy(&files)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let plan = migrate::plan(&legacy, &answers, &crate::cmd_repo::iso8601(now));
    print!("{}", render_migrate_dry_run(&plan, &version));
    if let Some(out) = &args.stack_answers {
        let home = home_dir().ok();
        let user = std::env::var("USER").ok();
        let lines: Vec<_> = migrate::stack_base_questions(&plan)
            .into_iter()
            .map(|q| {
                let answer = stack_base_from_git(&q, home.as_deref(), user.as_deref());
                (q.id, answer)
            })
            .collect();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out)
            .with_context(|| format!("creating {} (an existing file is never overwritten)", out.display()))?;
        file.write_all(render_stack_answers(&lines, &version).as_bytes())
            .with_context(|| format!("writing {}", out.display()))?;
        let count = |f: fn(&StackAnswer) -> bool| lines.iter().filter(|(_, a)| f(a)).count();
        println!(
            "stack answers: {} known, {} unknown base, {} left open -> {}",
            count(|a| matches!(a, StackAnswer::Known { .. })),
            count(|a| matches!(a, StackAnswer::Unknown { .. })),
            count(|a| matches!(a, StackAnswer::Open { .. })),
            out.display()
        );
    }
    Ok(())
}

/// The overall git budget for one `stack_base` question: each call keeps its
/// own timeout inside it, so a wedged repo costs one budget, not one per call.
const STACK_ANSWER_GIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// What git says about one open `stack_base` call (slice 006).
#[derive(Debug, Clone, PartialEq, Eq)]
enum StackAnswer {
    /// The branch is live and unmerged: `base` is its merge-base with the
    /// parent's branch, else with `main`.
    Known { parent: String, base: String, why: String },
    /// The branch is gone or merged into `main`: the explicit unknown base.
    Unknown { parent: String, why: String },
    /// Git can't settle it here; the call stays open.
    Open { why: String },
}

/// Ask git about `q` in the project's repo, read-only. A repo that is remote,
/// ambiguous or unreadable leaves the call open, never guessed.
fn stack_base_from_git(q: &migrate::StackBaseQuestion, home: Option<&Path>, user: Option<&str>) -> StackAnswer {
    use softfig_ipc::queue_v2::RepoLocality;
    if let Some(named) = &q.stray_parent {
        return StackAnswer::Open { why: format!("the prose names parent `{named}`, which is no other item") };
    }
    if q.repo.trim().is_empty() {
        return StackAnswer::Open { why: "the project has no repo yet; settle its `project_repo` call and re-run".into() };
    }
    let repo = match RepoLocality::of(&q.repo, user) {
        RepoLocality::Local => softfig_ipc::item_repo::expand_home(q.repo.trim(), home, user),
        RepoLocality::Remote => {
            return StackAnswer::Open { why: format!("repo `{}` is on another machine; answer it there", q.repo) };
        }
        RepoLocality::Ambiguous => None,
    };
    let Some(repo) = repo else {
        return StackAnswer::Open { why: format!("repo `{}` is not a local path here", q.repo) };
    };
    let git = softfig_growlightd::git_stack::Git::new(repo)
        .with_deadline(std::time::Instant::now() + STACK_ANSWER_GIT_BUDGET);
    stack_base_git(&git, q).unwrap_or_else(|e| StackAnswer::Open { why: format!("git can't read the repo ({e})") })
}

fn stack_base_git(
    git: &softfig_growlightd::git_stack::Git,
    q: &migrate::StackBaseQuestion,
) -> Result<StackAnswer, softfig_growlightd::git_stack::GitError> {
    let parent = q.parent.as_ref().map_or("", |(id, _)| id.as_str()).to_string();
    let (branch, main) = (q.branch.as_str(), q.main.as_str());
    if !git.branch_exists(main)? {
        return Ok(StackAnswer::Open { why: format!("the repo has no `{main}` branch") });
    }
    if !git.branch_exists(branch)? {
        // A missing branch says nothing about a name the owner hasn't settled.
        if q.branch_open {
            return Ok(StackAnswer::Open {
                why: format!("`{branch}` is not in the repo, and it is only the open `branch:{}` call's proposal; settle that and re-run", q.id),
            });
        }
        return Ok(StackAnswer::Unknown { parent, why: format!("`{branch}` is gone") });
    }
    if git.is_ancestor(branch, main)? {
        return Ok(StackAnswer::Unknown { parent, why: format!("`{branch}` is merged into `{main}`") });
    }
    let onto = match &q.parent {
        Some((_, theirs)) if !theirs.is_empty() && git.branch_exists(theirs)? => theirs.as_str(),
        _ => main,
    };
    let base = git.merge_base(branch, onto)?;
    Ok(StackAnswer::Known { parent, base, why: format!("merge-base of `{branch}` and `{onto}`") })
}

/// The `--stack-answers` file: an answers file (`schema`, `[call]`) with one
/// commented line per call saying where its answer came from. A call git
/// can't settle is written commented out, so feeding the file back leaves it
/// open.
fn render_stack_answers(lines: &[(String, StackAnswer)], version: &str) -> String {
    let quote = |s: &str| toml::Value::String(s.to_string()).to_string();
    let mut out = format!(
        "# stack_base answers from git (`queue migrate --stack-answers`), snapshot {version}.\n\
         # Review every line: nothing applies this file by itself. Pass it alone as\n\
         # --answers, or paste the lines below `[call]` into your answers file's own\n\
         # `[call]` table. A commented-out line is a call git could not settle here.\n\
         schema = {}\n\n[call]\n",
        migrate::ANSWERS_SCHEMA_VERSION
    );
    for (id, answer) in lines {
        let key = quote(&format!("stack_base:{id}"));
        let line = match answer {
            StackAnswer::Known { parent, base, why } => format!("# {why}\n{key} = {}\n", quote(&format!("parent={parent} base={base}"))),
            StackAnswer::Unknown { parent, why } => format!("# {why}\n{key} = {}\n", quote(&format!("parent={parent} base="))),
            StackAnswer::Open { why } => format!("# left open: {why}\n# {key} = \"parent= base=\"\n"),
        };
        out.push_str(&line);
    }
    out
}

/// `queue migrate --apply`: a thin client. keeperd reads the garden half from
/// its own WorkTree and recomputes the plan; the runtime batons, which keeperd
/// cannot see, ride in the args. Once the commit lands, the batons the plan
/// names are copied into the per-entry store (§3.6).
fn queue_migrate_apply(
    socket: &Path,
    runtime: &Path,
    answers: migrate::Answers,
    expect: String,
) -> Result<()> {
    let batons = migrate_batons(runtime)?;
    let wire = QueueV2MigrateApplyArgs { answers, expect, batons: batons.clone() };
    let value = queue_call(socket, op::QUEUE_V2_MIGRATE_APPLY, serde_json::to_value(wire)?)?;
    let reply: QueueV2MigrateApplyReply = serde_json::from_value(value)?;
    println!("queue migrate --apply — commit {}", short_hash(&reply.hash));
    println!(
        "wrote: {} entries, {} archived, {} slices files",
        reply.entries, reply.archived, reply.slices
    );
    println!("baton copies: {}", reply.batons.len());
    copy_migrated_batons(runtime, &batons, &reply.batons, |line| println!("{line}"))
        .with_context(|| format!("after commit {}", short_hash(&reply.hash)))?;
    println!("the switch is unchanged; flip `queue = \"v2\"` yourself, with the fleet disarmed");
    Ok(())
}

/// Run every §3.6 copy under `<runtime>/entries`, reporting one line each
/// through `report`. Any failure is an error, after `report` has printed the
/// shell command that finishes each failed copy: the commit has landed, so a
/// second `--apply` refuses `v2_files_present` and those commands are the
/// only way to finish. `cp -n` keeps the copy's never-overwrite rule.
fn copy_migrated_batons(
    runtime: &Path,
    sent: &std::collections::BTreeMap<String, String>,
    moves: &[migrate::BatonMove],
    mut report: impl FnMut(String),
) -> Result<()> {
    let entries = runtime.join("entries");
    let mut failed = Vec::new();
    for mv in moves {
        let outcome = match copy_migrated_baton(&entries, sent, mv) {
            Ok(BatonCopy::Copied) => "copied".to_string(),
            Ok(BatonCopy::TargetExists) => "skipped, target exists".to_string(),
            Err(e) => {
                let dir = entries.join(&mv.entry);
                failed.push(format!(
                    "mkdir -p {} && cp -n {} {}",
                    shell_quote(&dir),
                    shell_quote(&runtime.join(&mv.from)),
                    shell_quote(&dir.join("baton.md")),
                ));
                format!("FAILED, {e:#}")
            }
        };
        report(format!("  {} -> entries/{}/baton.md: {outcome}", mv.from, mv.entry));
    }
    if failed.is_empty() {
        return Ok(());
    }
    report("the v2 files are committed; finish each failed copy by hand:".to_string());
    for cmd in &failed {
        report(format!("  {cmd}"));
    }
    bail!("{} of {} baton copies failed", failed.len(), moves.len())
}

/// What one §3.6 baton copy did.
#[derive(Debug, PartialEq, Eq)]
enum BatonCopy {
    Copied,
    TargetExists,
}

/// Copy one planned baton into `<entries>/<entry>/baton.md`. The bytes are
/// the ones sent to keeperd, so what lands is what the plan judged. A copy
/// never overwrites a target (`create_new`, so no check-then-write race) and
/// never touches the source.
fn copy_migrated_baton(
    entries: &Path,
    sent: &std::collections::BTreeMap<String, String>,
    mv: &migrate::BatonMove,
) -> Result<BatonCopy> {
    let mut parts = Path::new(&mv.entry).components();
    if !matches!((parts.next(), parts.next()), (Some(std::path::Component::Normal(_)), None)) {
        bail!("entry id {:?} is not a single path component", mv.entry);
    }
    let text = sent
        .get(&mv.from)
        .ok_or_else(|| anyhow!("{} was not among the batons sent", mv.from))?;
    let dir = entries.join(&mv.entry);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let target = dir.join("baton.md");
    let mut file = match fs::OpenOptions::new().write(true).create_new(true).open(&target) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(BatonCopy::TargetExists),
        Err(e) => return Err(e).with_context(|| format!("creating {}", target.display())),
    };
    if let Err(e) = file.write_all(text.as_bytes()) {
        // A partial target would read as `TargetExists` to every later copy.
        drop(file);
        let _ = fs::remove_file(&target);
        return Err(e).with_context(|| format!("writing {}", target.display()));
    }
    Ok(BatonCopy::Copied)
}

/// The converter's snapshot: every `.md` under the garden's
/// `growlight/backlog/` (garden-relative keys), plus the runtime's root
/// `baton.md` and each `agents/<id>/baton.md` (runtime-relative keys).
fn migrate_snapshot(garden: &Path, runtime: &Path) -> Result<migrate::LegacyFiles> {
    fn walk(root: &Path, dir: &Path, into: &mut std::collections::BTreeMap<String, String>) -> Result<()> {
        let entries = fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                walk(root, &path, into)?;
            } else if kind.is_file() && path.extension().is_some_and(|e| e == "md") {
                let rel = path.strip_prefix(root).expect("walked under root");
                let key = rel.to_str().ok_or_else(|| anyhow!("non-UTF-8 path {}", path.display()))?;
                let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
                into.insert(key.to_string(), text);
            }
        }
        Ok(())
    }
    let mut files = migrate::LegacyFiles::default();
    let backlog = garden.join(BACKLOG_DOC);
    let backlog_dir = backlog.parent().expect("BACKLOG_DOC has a parent");
    walk(garden, backlog_dir, &mut files.garden)?;
    files.batons = migrate_batons(runtime)?;
    Ok(files)
}

/// The runtime half of the snapshot: the root `baton.md` and each
/// `agents/<id>/baton.md`, keyed runtime-relative.
fn migrate_batons(runtime: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    let mut batons = vec![PathBuf::from("baton.md")];
    if let Ok(agents) = fs::read_dir(runtime.join("agents")) {
        for agent in agents.flatten() {
            if agent.file_type().is_ok_and(|k| k.is_dir()) {
                batons.push(Path::new("agents").join(agent.file_name()).join("baton.md"));
            }
        }
    }
    for rel in batons {
        let path = runtime.join(&rel);
        if path.is_file() {
            let key = rel.to_str().ok_or_else(|| anyhow!("non-UTF-8 path {}", path.display()))?;
            let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            out.insert(key.to_string(), text);
        }
    }
    Ok(out)
}

/// The `queue migrate --dry-run` rendering: the snapshot's version, the
/// counts, the projects, the entries in list order, the slices files, the
/// baton copies, every call (open and settled), every refusal, and the
/// `N calls need you` line last.
fn render_migrate_dry_run(plan: &migrate::MigrationPlan, version: &str) -> String {
    let mut out = String::from("queue migrate --dry-run — nothing written\n");
    out.push_str(&format!("snapshot version: {version}\n"));
    out.push_str(&format!(
        "plan: {} projects, {} entries, {} archived, {} slices files, {} baton copies\n",
        plan.queue.projects.len(),
        plan.queue.entries.len(),
        plan.archive.entries.len(),
        plan.slices.len(),
        plan.batons.len(),
    ));

    out.push_str("\nprojects:\n");
    for p in &plan.queue.projects {
        out.push_str(&format!("  {}  repo={}  main={}\n", p.name, p.repo, p.main));
    }

    out.push_str("\nentries (list order):\n");
    for e in &plan.queue.entries {
        let mut line = format!("  {} {} {} {} {}", e.id, e.kind, e.project, e.lane, e.status);
        if !e.fleet {
            line.push_str(" fleet=false");
        }
        if let Some(t) = &e.not_before {
            line.push_str(&format!(" not_before={t}"));
        }
        if !e.after.is_empty() {
            line.push_str(&format!(" after={}", e.after.join(",")));
        }
        if !e.branch.is_empty() {
            line.push_str(&format!(" branch={}", e.branch));
        }
        if !e.base.is_empty() {
            line.push_str(&format!(" parent={} base={}", e.parent, e.base));
        }
        out.push_str(&line);
        out.push('\n');
    }

    out.push_str(&format!("\narchived: {} rows\n", plan.archive.entries.len()));

    if !plan.slices.is_empty() {
        out.push_str("\nslices:\n");
        for (id, slices) in &plan.slices {
            let done = slices.items.iter().filter(|s| s.status == SliceStatus::Done).count();
            out.push_str(&format!("  {id}: {} items, {done} done\n", slices.items.len()));
        }
    }

    if !plan.batons.is_empty() {
        out.push_str("\nbaton copies:\n");
        for b in &plan.batons {
            out.push_str(&format!("  {} -> entries/{}/baton.md\n", b.from, b.entry));
        }
    }

    let open = plan.open_calls().count();
    out.push_str(&format!(
        "\njudgment calls: {} ({open} open, {} settled)\n",
        plan.calls.len(),
        plan.calls.len() - open
    ));
    for c in &plan.calls {
        match &c.settled {
            Some(answer) => out.push_str(&format!("  [settled] {} = {}\n", c.key, hang(answer, 6))),
            None => out.push_str(&format!("  [open] {}\n", c.key)),
        }
        out.push_str(&format!("      evidence: {}\n", hang(&c.evidence, 16)));
        out.push_str(&format!("      proposed: {}\n", hang(&c.proposed, 16)));
    }

    out.push_str(&format!("\nrefusals: {}\n", plan.refusals.len()));
    for r in &plan.refusals {
        out.push_str(&format!("  {}: {}\n", r.subject, hang(&r.reason, 4)));
    }

    out.push('\n');
    if !plan.refusals.is_empty() {
        let n = plan.refusals.len();
        out.push_str(&match n {
            1 => "1 refusal blocks the apply\n".to_string(),
            n => format!("{n} refusals block the apply\n"),
        });
    }
    out.push_str(&match open {
        1 => "1 call needs you\n".to_string(),
        n => format!("{n} calls need you\n"),
    });
    out
}

/// `text` with every continuation line indented by `indent` spaces, so a
/// multi-line value (branch-policy prose quoted as evidence) stays inside its
/// call's block instead of spilling into the list; blank lines stay blank.
fn hang(text: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    text.lines()
        .enumerate()
        .map(|(i, line)| if i == 0 || line.is_empty() { line.to_string() } else { format!("{pad}{line}") })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The `queue pick` rendering: who the pick ran for, the assignment (or its
/// absence), and one line per skipped entry with its stable reason slug and a
/// sentence explaining it.
fn render_queue_pick(reply: &growlightd::QueuePickReply) -> String {
    if !reply.list {
        return format!("{}\n", queue_empty_line());
    }
    let mut out = String::from("queue pick\n");
    let member = match &reply.member {
        Some(id) => format!("member {id}"),
        None => "an unpinned member".to_string(),
    };
    let pin = match &reply.pin {
        Some(pin) => format!(", pin {pin}"),
        None => ", no pin".to_string(),
    };
    out.push_str(&format!("{member} (backend {}{pin})\n", reply.backend));

    match &reply.picked {
        Some(picked) => {
            out.push_str(&format!("picked: {} / {}\n", picked.entry, picked.unit));
            match &picked.declared {
                Some(models) => out.push_str(&format!("model: {models}\n")),
                None => out.push_str("model: undeclared — the member default (§6.4)\n"),
            }
        }
        None => out.push_str("picked: nothing workable for this member\n"),
    }
    out.push_str("schedule: not applied — a member the [schedule] holds is not handed this\n");

    if reply.skips.is_empty() {
        out.push_str("skipped: none\n");
    } else {
        out.push_str(&format!("skipped: {}\n", reply.skips.len()));
        for skip in &reply.skips {
            out.push_str(&format!(
                "  - {}: {} — {}\n",
                skip.entry, skip.reason, skip.detail
            ));
        }
    }
    out
}

const SHOW_HEADER: &str =
    "| # | id | kind | title | project | lane | status | after | branch | base | claimed |";
const SHOW_SEPARATOR: &str =
    "|---|----|------|-------|---------|------|--------|-------|--------|------|---------|";

/// The `queue show` rendering (§6.9): both lanes, one row per entry in file
/// order, with the stack columns verbatim from the TOML. TOML state only — the
/// live git-stack annotations come from growlightd and are rendered after it by
/// [`render_annotations`]. Same cell rules as the §3.4 derived view (literal `|` escaped,
/// empty cells an em-dash).
fn render_queue_show(queue: &QueueToml) -> String {
    let mut out = String::from("queue.toml (schema ");
    out.push_str(&queue.schema.to_string());
    out.push_str(")\n");
    show_lane(
        &mut out,
        "Urgent",
        queue.entries.iter().filter(|e| e.lane == QueueLane::Urgent),
    );
    show_lane(
        &mut out,
        "Normal",
        queue.entries.iter().filter(|e| e.lane == QueueLane::Normal),
    );
    out
}

fn show_lane<'a>(out: &mut String, name: &str, rows: impl Iterator<Item = &'a Entry>) {
    let cell = |s: &str| {
        if s.is_empty() {
            "—".to_string()
        } else {
            s.replace('|', "\\|")
        }
    };
    out.push_str(&format!("\n### {name}\n\n"));
    out.push_str(SHOW_HEADER);
    out.push('\n');
    out.push_str(SHOW_SEPARATOR);
    for (i, e) in rows.enumerate() {
        let after = if e.after.is_empty() {
            String::new()
        } else {
            e.after.join(", ")
        };
        // The §2 Holds beside the status: a human-only entry (`fleet = false`)
        // is left for the human whatever the status reads, and a start time
        // (`not_before`) is shown as written, whether or not it is still ahead.
        let status = format!(
            "{}{}",
            e.status,
            softfig_ipc::queue_v2::hold_annotation(e.fleet, e.not_before.as_deref(), e.auto_restack)
        );
        out.push_str(&format!(
            "\n| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            i + 1,
            cell(&e.id),
            cell(&e.kind.to_string()),
            cell(&e.title),
            cell(&e.project),
            cell(&e.lane.to_string()),
            cell(&status),
            cell(&after),
            cell(&e.branch),
            cell(&e.base),
            cell(&e.claimed),
        ));
    }
    out.push('\n');
}

/// The `growlight status` queue v2 lanes (§6.9): both lanes, one row per entry
/// in file order — id, status, project, the `after` links, and the branch with
/// its live open annotation (the git-stack flag). `queue show` keeps
/// [`render_queue_show`]'s TOML table instead; this is the growlightd-side
/// form, so it omits the TOML-only columns (kind/title/base/claimed).
fn render_queue_lanes(view: &QueueShowReply) -> String {
    let mut out = String::from("### Urgent\n\n");
    lane_rows(&mut out, view.entries.iter().filter(|e| e.lane == "urgent"));
    out.push_str("\n### Normal\n\n");
    lane_rows(&mut out, view.entries.iter().filter(|e| e.lane == "normal"));
    out
}

fn lane_rows<'a>(out: &mut String, rows: impl Iterator<Item = &'a QueueShowEntry>) {
    let cell = |s: &str| {
        if s.is_empty() {
            "—".to_string()
        } else {
            s.replace('|', "\\|")
        }
    };
    out.push_str("| id | status | project | after | branch |\n|---|---|---|---|---|");
    for e in rows {
        let after = if e.after.is_empty() {
            String::new()
        } else {
            e.after.join(", ")
        };
        let branch = if e.open_unknown {
            format!("{} (stack unknown)", e.branch)
        } else if e.open {
            format!("{} (open)", e.branch)
        } else {
            e.branch.clone()
        };
        // A recorded human status change on an `active` entry applies at the
        // session's next handshake; show it rather than a plain `active`. The
        // §2 holds follow, as `queue show` prints them.
        let mut status = match &e.pending_status {
            Some(p) => format!("{} (→ {p} pending)", e.status),
            None => e.status.clone(),
        };
        status.push_str(&e.hold_annotation());
        out.push_str(&format!(
            "\n| {} | {} | {} | {} | {} |",
            cell(&e.id),
            cell(&status),
            cell(&e.project),
            cell(&after),
            cell(&branch),
        ));
    }
    out.push('\n');
}

/// `queue show`'s doc-line warnings: one line per entry whose doc carries a
/// `> Fleet:` or `> Not before:` line that disagrees with the entry
/// ([`QueueShowEntry::doc_hold_warning`]). Under v2 those lines hold nothing,
/// so a human who wrote one by habit learns it here. Empty when none disagree.
/// The doc lines come from growlightd, so a stopped growlightd shows none.
fn render_doc_hold_warnings(view: &QueueShowReply) -> String {
    let lines: Vec<String> = view.entries.iter().filter_map(QueueShowEntry::doc_hold_warning).collect();
    if lines.is_empty() {
        return String::new();
    }
    format!("\n{}\n", lines.join("\n"))
}

/// The §6.9 live annotations layered onto both surfaces (queue-v2-git slice
/// 006): the stack per repo (the git-stack candidates in claim order) and the
/// §3.5 session log. Shared by `queue show` and `growlight status` so the two
/// surfaces can never drift about the same stack.
fn render_annotations(view: &QueueShowReply) -> String {
    let mut out = String::from("\n### Stack per repo\n\n");
    if view.projects.is_empty() {
        out.push_str("(no projects)\n");
    }
    for p in &view.projects {
        let kind = if p.local { "local" } else { "remote" };
        out.push_str(&format!("- {} ({}, main = {}) {}\n", p.name, kind, p.main, p.repo));
        if let Some(reason) = &p.stack_unknown {
            out.push_str(&format!("  (stack unknown — {reason})\n"));
        } else if p.stack.is_empty() {
            out.push_str("  (empty — the next branch cuts from main)\n");
        } else {
            for b in &p.stack {
                let parent = if b.parent.is_empty() { "main".to_string() } else { b.parent.clone() };
                out.push_str(&format!(
                    "  - {}  parent={}  base={}  claimed={}\n",
                    b.branch, parent, b.base, b.claimed
                ));
            }
        }
    }
    out.push_str("\n### Sessions\n\n");
    if view.sessions.is_empty() {
        out.push_str("(no sessions logged)\n");
    }
    for s in &view.sessions {
        let unit = match &s.unit {
            Some(u) => format!("/{u}"),
            None => String::new(),
        };
        let tree = s.tree.as_deref().unwrap_or(&s.entry);
        out.push_str(&format!("{tree}{unit} ({})\n", s.path));
        for line in &s.lines {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out
}

fn queue_project_add(socket: &Path, args: QueueProjectAddArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueAddProjectArgs {
        name: args.name,
        repo: args.repo,
        main: args.main,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_ADD_PROJECT, serde_json::to_value(wire)?)?;
    let reply: QueueAddProjectReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    Ok(())
}

fn queue_project_set_repo(socket: &Path, args: QueueProjectSetRepoArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueSetProjectRepoArgs {
        name: args.name,
        repo: args.repo,
        main: args.main,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_SET_PROJECT_REPO, serde_json::to_value(wire)?)?;
    let reply: QueueAddProjectReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    Ok(())
}

fn queue_add(socket: &Path, args: QueueAddArgs) -> Result<()> {
    // The CLI grammar (§6.9): a milestone/task carries its slug positionally;
    // a restack takes `--project` only. keeperd still owns the full arg rules
    // (it refuses the restack extras as BadArgs, finding 5).
    let slug = match (args.kind, args.slug) {
        (AddKind::Restack, Some(_)) => {
            bail!("`queue add restack` takes no <slug> (its slug is restack-<project>)")
        }
        (AddKind::Restack, None) => None,
        (_, Some(s)) => Some(s),
        (_, None) => bail!("`queue add` needs a <slug> for the milestone and task kinds"),
    };
    let (position, ref_id) = match (args.front, args.before, args.behind) {
        (true, None, None) => (Some("front".to_string()), None),
        (false, Some(r), None) => (Some("before".to_string()), Some(r)),
        (false, None, Some(r)) => (Some("after".to_string()), Some(r)),
        (false, None, None) => (None, None),
        _ => bail!("choose at most one of --front / --before / --behind"),
    };
    let wire = softfig_ipc::verbs::QueueAddEntryArgs {
        kind: match args.kind {
            AddKind::Milestone => EntryKind::Milestone,
            AddKind::Task => EntryKind::Task,
            AddKind::Restack => EntryKind::Restack,
        },
        slug,
        title: args.title,
        mission: args.mission.as_deref().map(value_or_file).transpose()?,
        finish_criteria: args.criteria.as_deref().map(value_or_file).transpose()?,
        project: args.project,
        lane: args.urgent.then_some(QueueLane::Urgent),
        after: args.after,
        position,
        ref_id,
        slices: Vec::new(),
        fleet: args.no_fleet.then_some(false),
        not_before: args.not_before,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_ADD_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueAddEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    Ok(())
}

fn queue_move(socket: &Path, args: QueueMoveArgs) -> Result<()> {
    let (to, ref_id) = placement(args.to, args.ref_id)?;
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: None,
        move_spec: Some(QueueMoveSpec { to, ref_id }),
        after: None,
        status: None,
        fleet: None,
        not_before: None,
        auto_restack: None,
        branch: None,
        base: None,
        project: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    print_notes(&reply.notes);
    Ok(())
}

fn queue_lane(socket: &Path, args: QueueLaneArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: Some(match args.lane {
            LaneArg::Urgent => QueueLane::Urgent,
            LaneArg::Normal => QueueLane::Normal,
        }),
        move_spec: None,
        after: None,
        status: None,
        fleet: None,
        not_before: None,
        auto_restack: None,
        branch: None,
        base: None,
        project: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    print_notes(&reply.notes);
    Ok(())
}

fn queue_after(socket: &Path, args: QueueAfterArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: None,
        move_spec: None,
        after: Some(args.ids),
        status: None,
        fleet: None,
        not_before: None,
        auto_restack: None,
        branch: None,
        base: None,
        project: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    print_notes(&reply.notes);
    Ok(())
}

fn queue_status(socket: &Path, args: QueueStatusArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: None,
        move_spec: None,
        after: None,
        status: Some(match args.status {
            HumanStatus::Queued => QueueStatusArg::Queued,
            HumanStatus::Blocked => QueueStatusArg::Blocked,
            HumanStatus::Deferred => QueueStatusArg::Deferred,
            HumanStatus::Done => QueueStatusArg::Done,
        }),
        fleet: None,
        not_before: None,
        auto_restack: None,
        branch: None,
        base: None,
        project: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    print_notes(&reply.notes);
    Ok(())
}

fn queue_fleet(socket: &Path, args: QueueFleetArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: None,
        move_spec: None,
        after: None,
        status: None,
        fleet: Some(args.fleet == FleetArg::Yes),
        not_before: None,
        auto_restack: None,
        branch: None,
        base: None,
        project: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    print_notes(&reply.notes);
    Ok(())
}

fn queue_auto_restack(socket: &Path, args: QueueAutoRestackArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: None,
        move_spec: None,
        after: None,
        status: None,
        fleet: None,
        not_before: None,
        auto_restack: Some(args.auto_restack == FleetArg::Yes),
        branch: None,
        base: None,
        project: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    print_notes(&reply.notes);
    Ok(())
}

fn queue_not_before(socket: &Path, args: QueueNotBeforeArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: None,
        move_spec: None,
        after: None,
        status: None,
        fleet: None,
        not_before: Some(args.time),
        auto_restack: None,
        branch: None,
        base: None,
        project: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    print_notes(&reply.notes);
    Ok(())
}

fn queue_repair(socket: &Path, args: QueueRepairArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: None,
        move_spec: None,
        after: None,
        status: None,
        fleet: None,
        not_before: None,
        auto_restack: None,
        branch: args.branch,
        base: args.base,
        project: args.project,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    print_notes(&reply.notes);
    Ok(())
}

fn queue_drop(socket: &Path, args: QueueDropArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueDropArgs {
        id: args.id,
        reason: value_or_file(&args.reason)?,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_DROP, serde_json::to_value(wire)?)?;
    let reply: QueueDropReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    Ok(())
}

fn slice_insert(socket: &Path, args: SliceInsertArgs) -> Result<()> {
    let (position, ref_id) = match args.position {
        None => (None, None),
        Some(to) => {
            let (p, r) = placement(to, args.ref_id)?;
            (Some(p), r)
        }
    };
    let wire = softfig_ipc::verbs::SliceInsertArgs {
        milestone: args.milestone,
        slug: args.slug,
        title: args.title,
        body: value_or_file(&args.body)?,
        position,
        ref_id,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::SLICE_INSERT, serde_json::to_value(wire)?)?;
    let reply: SliceInsertReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    Ok(())
}

fn slice_move(socket: &Path, args: SliceMoveArgs) -> Result<()> {
    let (to, ref_id) = placement(args.to, args.ref_id)?;
    let wire = softfig_ipc::verbs::SliceUpdateArgs {
        milestone: args.milestone,
        id: args.id,
        move_spec: Some(QueueMoveSpec { to, ref_id }),
        status: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::SLICE_UPDATE, serde_json::to_value(wire)?)?;
    let reply: SliceUpdateReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    Ok(())
}

fn slice_status(socket: &Path, args: SliceStatusArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::SliceUpdateArgs {
        milestone: args.milestone,
        id: args.id,
        move_spec: None,
        status: Some(match args.status {
            HumanStatus::Queued => SliceStatus::Queued,
            HumanStatus::Blocked => SliceStatus::Blocked,
            HumanStatus::Deferred => SliceStatus::Deferred,
            HumanStatus::Done => SliceStatus::Done,
        }),
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::SLICE_UPDATE, serde_json::to_value(wire)?)?;
    let reply: SliceUpdateReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn reports_listing_hides_closed_reports_unless_asked() {
        let row = |n: u32, status: &str| ReportRow {
            number: n,
            path: format!("growlight/reports/{n:03}-x.md"),
            title: "x".into(),
            tags: vec!["type:bug".into(), format!("status:{status}")],
            filed: String::new(),
        };
        let rows = || vec![row(1, "open"), row(2, "resolved"), row(3, "triaged")];
        let open: Vec<u32> = unresolved_unless_all(rows(), false).iter().map(|r| r.number).collect();
        assert_eq!(open, [1, 3]);
        assert_eq!(unresolved_unless_all(rows(), true).len(), 3);
        assert!(has_status_tag(&["Status:resolved".to_string()]));
        assert_eq!(report_line(&row(7, "open")), "#007  x  [type:bug status:open]");
    }

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
    fn loop_json_wires_the_session_hooks_and_the_statusline() {
        let inject = Path::new("/run/softfig/growlight/inject.sh");
        let statusline = Path::new("/run/softfig/growlight/statusline.sh");
        let garden = Path::new("/home/ukv/soft-fig_garden");
        let claude_projects = Path::new("/home/ukv/.claude/projects");
        let softfig = Path::new("/home/ukv/.local/bin/soft fig");
        let runtime = Path::new("/home/ukv/.config/softfig/growlight");
        let json: serde_json::Value = serde_json::from_str(&loop_json(
            inject,
            statusline,
            garden,
            claude_projects,
            softfig,
            runtime,
        ))
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

        // SessionEnd runs the semi-auto telemetry ingest (spec-token-telemetry
        // §4.2) on every end reason, so it carries no matcher. Each path is
        // single-quoted, so a space in one survives the hook's shell.
        let ends = json["hooks"]["SessionEnd"].as_array().unwrap();
        assert_eq!(ends.len(), 1);
        assert!(ends[0].get("matcher").is_none());
        let cmd = &ends[0]["hooks"][0];
        assert_eq!(cmd["type"], "command");
        assert_eq!(
            cmd["command"],
            "'/home/ukv/.local/bin/soft fig' telemetry ingest-transcript \
             --garden-root '/home/ukv/soft-fig_garden' \
             --config-dir '/home/ukv/.config/softfig/growlight'"
        );
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
            Path::new("/usr/bin/softfig"),
            Path::new("/run/softfig/growlight"),
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
            Path::new("/opt/bin/softfig"),
            Path::new("/garden"),
        );
        assert!(s.starts_with("#!/usr/bin/env bash"));
        assert!(s.contains("cat '/garden/growlight/protocol.md'"));
        assert!(s.contains("cat '/cfg/softfig/growlight/baton.md'"));
        // protocol injected before the baton.
        assert!(s.find("protocol.md").unwrap() < s.find("baton.md").unwrap());
        // Task 064 review G64-7: the boot dirty-tree check runs on every boot,
        // after the baton, and never fails the hook.
        let check = "'/opt/bin/softfig' growlight boot-check --garden-root '/garden' \
                     --baton '/cfg/softfig/growlight/baton.md' 2>/dev/null || true";
        assert!(s.contains(check), "{s}");
        assert!(s.find("cat '/cfg/softfig/growlight/baton.md'").unwrap() < s.find("boot-check").unwrap());
    }

    #[test]
    fn statusline_script_tees_both_budgets_to_usage_json() {
        let s = statusline_script(
            Path::new("/cfg/softfig/growlight/usage.json"),
            Path::new("/cfg/softfig/growlight/usage.by-profile"),
            Path::new("/d/claude-profiles/active"),
        );
        assert!(s.starts_with("#!/usr/bin/env bash"));
        assert!(s.contains("> '/cfg/softfig/growlight/usage.json'"));
        assert!(s.contains("context_window"));
        assert!(s.contains("rate_limits"));
        assert!(s.contains("five_hour.used_percentage"));
        // The tee must clamp a >100 used_percentage (spec §6) — see the
        // behavioral test below for the runtime proof.
        assert!(s.contains("used_percentage |= ([., 100] | min)"));
        // Slice 009 S9: snapshot carries the slot tag + is teed to the
        // per-profile file. The exact paths are baked at launch, so the
        // script references both the profile tag JSON key and the dir.
        assert!(s.contains("profile: $profile"), "snapshot tagged with slot: {s}");
        assert!(
            s.contains("'/cfg/softfig/growlight/usage.by-profile'"),
            "per-profile dir baked in: {s}",
        );
        // Slice 009 S8: the shared file write is now guarded on slot==active.
        assert!(s.contains("if [ \"$slot\" = \"$active\" ]; then"));
    }

    // Run the generated statusline through real jq+bash to prove the clamp.
    // Self-skips when jq is unavailable (the script can't write usage.json then
    // anyway — see the jq warning in `cmd_growlight`).
    fn run_statusline(input: &str) -> serde_json::Value {
        // No CLAUDE_CONFIG_DIR, no active-link ⇒ slot = active = home, so the
        // shared file is written exactly as before the switcher.
        let (shared, _per_slot) = run_statusline_full(input, &[], None);
        shared.expect("home slot's shared usage.json is always written")
    }

    /// Run the statusline against a controlled slot (`CLAUDE_CONFIG_DIR` env)
    /// and an optional active-pointer link. Returns `(shared, per_slot_for_env)`
    /// where `shared` is `None` when the slot-vs-active guard suppressed the
    /// shared write.
    fn run_statusline_full(
        input: &str,
        env: &[(&str, &str)],
        active_link_target: Option<&str>,
    ) -> (Option<serde_json::Value>, serde_json::Value) {
        let dir = std::env::temp_dir().join(format!(
            "softfig-statusline-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let usage = dir.join("usage.json");
        let by_profile_dir = dir.join("usage.by-profile");
        let active_link = dir.join("active");
        if let Some(target) = active_link_target {
            std::os::unix::fs::symlink(target, &active_link).unwrap();
        }
        let script = dir.join("statusline.sh");
        std::fs::write(
            &script,
            statusline_script(&usage, &by_profile_dir, &active_link),
        )
        .unwrap();

        let mut cmd = std::process::Command::new("bash");
        cmd.arg(&script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null());
        // Scrub CLAUDE_CONFIG_DIR by default so the host env can't leak in;
        // explicit overrides below set it when the test wants an inactive slot.
        cmd.env_remove("CLAUDE_CONFIG_DIR");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        use std::io::Write as _;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait().unwrap();

        // Derive the slot the way the script does, so the test reads the same
        // per-profile file the script wrote.
        let slot = env
            .iter()
            .find(|(k, _)| *k == "CLAUDE_CONFIG_DIR")
            .map(|(_, v)| std::path::Path::new(v).file_name().unwrap().to_string_lossy().into_owned())
            .unwrap_or_else(|| "home".to_string());
        let per_slot_path = by_profile_dir.join(format!("{slot}.json"));
        let per_slot: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&per_slot_path).unwrap()).unwrap();
        let shared = std::fs::read_to_string(&usage)
            .ok()
            .map(|raw| serde_json::from_str(&raw).unwrap());
        std::fs::remove_dir_all(&dir).ok();
        (shared, per_slot)
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
    fn statusline_under_claude_config_dir_slot2_tees_to_slot2_json() {
        // Slice 009 S9 finish-check: a session with CLAUDE_CONFIG_DIR pointing
        // at <store>/slot2 derives slot=slot2, tags the snapshot with it, and
        // writes to `usage.by-profile/slot2.json`.
        if !jq_present() {
            return;
        }
        let input = r#"{"context_window":{"used_percentage":12},"rate_limits":{"five_hour":{"used_percentage":37,"status":"allowed_warning"}}}"#;
        // Active pointer names "slot1", so slot2 is INACTIVE and the shared
        // file should NOT be written (slice 009 S8 half).
        let (shared, per_slot) = run_statusline_full(
            input,
            &[("CLAUDE_CONFIG_DIR", "/some/store/slot2")],
            Some("slot1"),
        );
        assert_eq!(
            per_slot["profile"], "slot2",
            "snapshot carries the slot tag: {per_slot}",
        );
        assert_eq!(per_slot["rate_limits"]["five_hour"]["status"], "allowed_warning");
        assert!(
            shared.is_none(),
            "the shared usage.json is only written when slot == active (S8): {shared:?}",
        );
    }

    #[test]
    fn statusline_shared_write_fires_when_the_session_is_on_the_active_slot() {
        // Slice 009 S8 counter-case: when CLAUDE_CONFIG_DIR's slot IS the
        // active pointer's slot, the shared file writes normally — this is
        // the common everyday case (one slot, interactive).
        if !jq_present() {
            return;
        }
        let input = r#"{"context_window":{"used_percentage":5},"rate_limits":{"five_hour":{"used_percentage":10,"status":"allowed"}}}"#;
        let (shared, per_slot) = run_statusline_full(
            input,
            &[("CLAUDE_CONFIG_DIR", "/some/store/slot1")],
            Some("slot1"),
        );
        let shared = shared.expect("slot == active ⇒ shared is written");
        assert_eq!(shared["profile"], "slot1");
        assert_eq!(per_slot["profile"], "slot1");
        assert_eq!(shared["rate_limits"]["five_hour"]["status"], "allowed");
    }

    #[test]
    fn statusline_home_slot_without_an_active_link_still_writes_the_shared_file() {
        // Back-compat: a human not using the switcher has no store, no active
        // link, CLAUDE_CONFIG_DIR unset. slot = active = home ⇒ the shared
        // file is written exactly as before slice 009 landed.
        if !jq_present() {
            return;
        }
        let input = r#"{"context_window":{"used_percentage":5},"rate_limits":{"five_hour":{"used_percentage":1,"status":"allowed"}}}"#;
        let (shared, per_slot) = run_statusline_full(input, &[], None);
        let shared = shared.expect("home slot's shared file is always written");
        assert_eq!(shared["profile"], "home");
        assert_eq!(per_slot["profile"], "home");
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
            cpu_quota: Some("50%".into()),
            test_threads: Some(2),
        });
        assert!(text.contains("cargo_build_jobs  2"));
        assert!(text.contains("memory_high       3G"));
        assert!(text.contains("cpu_weight        (unset)"), "an unset knob reads (unset): {text}");
        assert!(text.contains("cpu_quota         50%"));
        assert!(text.contains("test_threads      2"));
    }

    #[test]
    fn render_schedule_shows_the_edge_the_holds_and_the_reserves() {
        assert_eq!(render_schedule(None, 0), "schedule      (none)\n");
        let s = growlightd::ScheduleSummary {
            open: true,
            current_windows: vec!["daily 23:00-07:00 [claude]".into()],
            next_edge: Some(1_000),
            next_edge_local: Some("2026-11-01 07:00 -05:00".into()),
            zone: "America/New_York".into(),
            held_members: vec![
                growlightd::ScheduleHeld { agent: "b1".into(), reason: "backend not in window".into() },
                growlightd::ScheduleHeld { agent: "a2".into(), reason: "overrun".into() },
            ],
            held_items: vec!["default/084 at 2026-11-01 02:00 -04:00".into()],
            reserve: vec![
                growlightd::ReserveSummary {
                    slot: "slot1".into(),
                    reserve_pct: 20,
                    used_7d_pct: Some(85),
                    held: true,
                    resets_at: Some(7_200),
                },
                growlightd::ReserveSummary {
                    slot: "slot2".into(),
                    reserve_pct: 20,
                    used_7d_pct: None,
                    held: false,
                    resets_at: None,
                },
            ],
            projection: vec![
                projection("slot1", "7d", 100, (Some(3_600), Some(10_800)), false),
                projection("slot1", "reserve", 80, (Some(3_600), None), false),
                projection("slot1", "5h", 100, (None, None), true),
                projection("slot2", "7d", 100, (None, None), false),
            ],
        };
        let text = render_schedule(Some(&s), 0);
        assert!(text.starts_with("schedule      open (zone America/New_York)\n"), "{text}");
        assert!(text.contains("  open now      daily 23:00-07:00 [claude]\n"));
        assert!(text.contains("  next edge     2026-11-01 07:00 -05:00\n"));
        assert!(text.contains("  held          b1               backend not in window\n"));
        assert!(text.contains("  held          a2               overrun\n"));
        assert!(text.contains("  waiting       default/084 at 2026-11-01 02:00 -04:00\n"));
        assert!(text.contains("slot1            keep 20% · 7d used 85% · held, resets in 2h\n"), "{text}");
        assert!(text.contains("slot2            keep 20% · 7d used unknown · clear\n"), "{text}");
        assert!(text.contains("projection    slot1            7d           cap in 1h–3h, resets in 2h\n"), "{text}");
        assert!(text.contains("slot1            reserve 80%  cap in 1h at the earliest, or resets first, resets in 2h\n"), "{text}");
        assert!(text.contains("slot1            5h           resets first, resets in 2h\n"), "{text}");
        assert!(text.contains("projection    slot2            7d           unknown\n"), "{text}");
    }

    #[test]
    fn render_schedule_says_why_there_is_no_next_edge() {
        let mut s = growlightd::ScheduleSummary { open: true, zone: "UTC".into(), ..Default::default() };
        let open = render_schedule(Some(&s), 0);
        assert!(open.contains("  next edge     (none within a week — open throughout)\n"), "{open}");
        s.open = false;
        let closed = render_schedule(Some(&s), 0);
        assert!(closed.contains("  next edge     (none within a week — no window opens)\n"), "{closed}");
    }

    fn projection(
        slot: &str,
        window: &str,
        target_pct: u8,
        (cap_at_earliest, cap_at_latest): (Option<i64>, Option<i64>),
        resets_first: bool,
    ) -> growlightd::PoolProjection {
        let resets_at = (slot == "slot1").then_some(7_200);
        growlightd::PoolProjection {
            slot: slot.into(),
            window: window.into(),
            target_pct,
            cap_at_earliest,
            cap_at_latest,
            resets_at,
            resets_first,
        }
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
                cpu_quota: None,
                test_threads: Some(2),
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

    /// slice 006: `resources show` prints the daemon's `live_scopes` VERBATIM (the
    /// generation-suffixed running units), never a CLI-reconstructed name, and
    /// distinguishes disarmed from armed-but-idle.
    #[test]
    fn render_resources_show_prints_the_running_units_verbatim() {
        let base = |enabled: bool, live: Vec<String>| FleetStatusReply {
            state: "running".into(),
            garden_root: "/g".into(),
            protocol_version: 1,
            policy: growlightd::PolicySummary {
                max_concurrent_agents: 2,
                ctx_roll_pct: 50,
                ctx_handoff_pct: 60,
                session_5h_halt_pct: 85,
                session_7d_halt_pct: 90,
            },
            build_caps: BuildCapsSummary::default(),
            paused: false,
            fleet_enabled: enabled,
            queue: "legacy".into(),
            roster: Vec::new(),
            agents: Vec::new(),
            live_scopes: live,
            held: Vec::new(),
            schedule: None,
        };

        // Running scopes: the exact gen-suffixed unit names, verbatim.
        let running = render_resources_show(&base(
            true,
            vec![
                "growlight-agent-a-5.scope".into(),
                "growlight-agent-b-6.scope".into(),
            ],
        ));
        assert!(running.contains("growlight-agent-a-5.scope, growlight-agent-b-6.scope"));

        // Armed but nothing running vs disarmed read differently.
        assert!(render_resources_show(&base(true, vec![])).contains("scopes        (none running)"));
        assert!(render_resources_show(&base(false, vec![])).contains("(none — fleet disarmed)"));
    }

    /// V23: the status line names the switch's value, and an older growlightd
    /// that sends none gets no line rather than a guess.
    #[test]
    fn status_names_the_queue_switch_and_guesses_nothing() {
        let reply = |queue: Option<&str>| {
            let mut json = serde_json::json!({
                "state": "running",
                "garden_root": "/g",
                "protocol_version": 1,
                "policy": {
                    "max_concurrent_agents": 2,
                    "ctx_roll_pct": 50,
                    "ctx_handoff_pct": 60,
                    "session_5h_halt_pct": 85,
                    "session_7d_halt_pct": 90
                }
            });
            if let Some(queue) = queue {
                json["queue"] = serde_json::json!(queue);
            }
            serde_json::from_value::<FleetStatusReply>(json).unwrap()
        };
        assert_eq!(queue_switch_line(&reply(Some("v2"))).as_deref(), Some("queue         v2"));
        assert_eq!(
            queue_switch_line(&reply(Some("legacy"))).as_deref(),
            Some("queue         legacy")
        );
        assert_eq!(queue_switch_line(&reply(None)), None);
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
    fn an_agents_row_shows_metered_spend_and_leaves_a_subscription_member_bare() {
        use softfig_ipc::growlightd::{AgentSpendSummary, AgentSummary};

        // The operator-facing line slice 006 exists for: a metered member reads as
        // "opencode · <model> · $0.14 this session" instead of showing an empty
        // Anthropic reserve gauge and looking broken.
        let metered = AgentSummary::new("b", "running", true).on_opencode(
            Some("deepseek/deepseek-flash (high)".into()),
            AgentSpendSummary { micro_usd: 140_000, steps: 3 },
        );
        assert_eq!(
            agent_accounting(&metered),
            "opencode · deepseek/deepseek-flash (high) · $0.14 this session (3 steps)",
        );

        // A subscription member ends at its backend name. The absence is the point:
        // its cost is the shared 5h/7d reserve on the `policy` line above, a
        // FLEET-level reading — so there is no per-member dollar column to leave
        // blank, and nothing invites a reader to compare "$0.14" against a blank.
        assert_eq!(agent_accounting(&AgentSummary::new("a", "running", true)), "claude");

        // A metered member yet to bill still names its pool, at zero.
        let fresh = AgentSummary::new("c", "idle", false)
            .on_opencode(Some("deepseek/deepseek-v4-pro".into()), AgentSpendSummary::default());
        assert_eq!(
            agent_accounting(&fresh),
            "opencode · deepseek/deepseek-v4-pro · $0.00 this session (0 steps)",
        );

        // One step is singular — the line is read by a human.
        let one = AgentSummary::new("d", "running", true)
            .on_opencode(None, AgentSpendSummary { micro_usd: 43, steps: 1 });
        assert_eq!(agent_accounting(&one), "opencode · $0.00 this session (1 step)");
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
        // No live rows: this daemon boots with the fleet DISARMED, so nothing is
        // assembled and there is no per-agent runtime state to report.
        assert!(reply.agents.is_empty(), "a disarmed fleet has no live rows");
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
        // hard-kill acts immediately. No live agent is registered in this booted
        // daemon, so it kills nothing and honestly reports `performed=false` — a
        // no-op kill must never read as success (the audit-005 fix).
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
        assert!(!r.performed, "no live agent was running, so nothing was killed");
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

    // ---- slice 005: picker suppression + item-declared model ------------

    #[test]
    fn the_picker_prompts_only_for_an_unflagged_interactive_launch() {
        // The one case a human is asked: no flag, a TTY, and a real launch.
        assert!(should_prompt(false, false, true));

        // Never prompt when the human already chose on the command line …
        assert!(!should_prompt(true, false, true));
        // … when nothing is being launched …
        assert!(!should_prompt(false, true, true), "--no-launch launches nothing");
        // … and above all NEVER without a TTY: a pipe/cron/script must not block
        // forever on a read that can't be answered.
        assert!(!should_prompt(false, false, false));
        assert!(!should_prompt(true, true, false));
    }

    #[test]
    fn the_no_launch_hint_names_the_same_cwd_the_launcher_really_uses() {
        // The hint is what a human copy-pastes INSTEAD of the spawn, so it must
        // reproduce it. Both are derived from one `InteractiveLaunch` here, and
        // the test compares the printed `cd` against the command's real cwd —
        // the drift that shipped in slice 006 (hint said the runtime dir, the
        // launch had moved to the garden) fails this.
        let garden = Path::new("/home/u/garden");
        let launch = InteractiveLaunch {
            agent_name: AGENT_NAME,
            loop_settings: Path::new("/rt/loop.json"),
            mcp_config: Path::new("/rt/mcp.json"),
            garden_root: garden,
            opencode_config: Path::new("/rt/opencode.json"),
            boot_prompt: OPENCODE_KICK,
            claude_slot: None,
        };

        for choice in [
            ModelChoice::claude(),
            ModelChoice::opencode(DEEPSEEK_FLASH),
        ] {
            let hint = no_launch_hint(&choice, &launch);
            let cwd = interactive_command(choice.backend, &launch, &choice.claude_argv())
                .unwrap()
                .get_current_dir()
                .map(Path::to_path_buf)
                .expect("the launcher pins a cwd on both backends");
            assert_eq!(cwd, garden);
            assert!(
                hint.contains(&format!("cd {}", cwd.display())),
                "hint must name the launch cwd, got: {hint}"
            );
        }

        // An opencode hint carries the config over OPENCODE_CONFIG and names the
        // resolved model, never claude's --settings/--mcp-config.
        let opencode = no_launch_hint(&ModelChoice::opencode(DEEPSEEK_REASONING), &launch);
        assert!(opencode.contains("OPENCODE_CONFIG=/rt/opencode.json"));
        assert!(opencode.contains(DEEPSEEK_REASONING), "name the model: {opencode}");
        assert!(!opencode.contains("--settings") && !opencode.contains("--mcp-config"));

        // opencode-v2-repin slice 002: the hint must keep `--standalone`, or the
        // pasted command attaches to the shared service, which ignores
        // OPENCODE_CONFIG (slice 001 finding 1). The hint's argv is the launch's
        // argv minus the trailing `--prompt <kick>`, which the human types instead.
        let spawned: Vec<String> = interactive_command(Backend::Opencode, &launch, &[])
            .unwrap()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let prompt_at = spawned.iter().position(|a| a == "--prompt").expect("a kick");
        assert_eq!(&spawned[prompt_at..], ["--prompt", OPENCODE_KICK]);
        let hinted = format!("opencode {}", spawned[..prompt_at].join(" "));
        assert!(
            opencode.ends_with(&hinted),
            "hint argv == launch argv minus the kick: {opencode:?} vs {hinted:?}",
        );
        assert!(hinted.contains("--standalone"), "{hinted}");

        // A declared variant is shown the way the config spells it.
        let mut high = ModelChoice::opencode(DEEPSEEK_FLASH);
        high.variant = Some("high".into());
        assert!(no_launch_hint(&high, &launch).contains("deepseek/deepseek-flash#high"));

        // The claude hint keeps the settings pair it always had.
        let claude = no_launch_hint(&ModelChoice::claude(), &launch);
        assert!(claude.contains("--settings /rt/loop.json"));
        assert!(claude.contains("--mcp-config /rt/mcp.json"));
        assert!(!claude.contains("OPENCODE_CONFIG"));
    }

    /// claude-login-switcher slice 007 finish-check: `growlight start --profile
    /// slot2 --no-launch` prints a hint that carries `CLAUDE_CONFIG_DIR`, with
    /// the claude argv otherwise unchanged; `home` unsets it.
    #[test]
    fn the_no_launch_hint_carries_the_claude_login_slot() {
        let launch_on = |slot: Option<&LaunchSlot>| -> String {
            let launch = InteractiveLaunch {
                agent_name: AGENT_NAME,
                loop_settings: Path::new("/rt/loop.json"),
                mcp_config: Path::new("/rt/mcp.json"),
                garden_root: Path::new("/g"),
                opencode_config: Path::new("/rt/opencode.json"),
                boot_prompt: OPENCODE_KICK,
                claude_slot: slot,
            };
            no_launch_hint(&ModelChoice::claude(), &launch)
        };
        let argv = format!("{AGENT_BIN} --name {AGENT_NAME} --settings /rt/loop.json --mcp-config /rt/mcp.json");

        let td = tempfile::tempdir().unwrap();
        let store = td.path();
        std::fs::create_dir(store.join("slot2")).unwrap();
        let creds = store.join("slot2").join(claude_profiles::CREDENTIALS_FILE);
        std::fs::write(&creds, "{}").unwrap();
        std::fs::set_permissions(&creds, fs::Permissions::from_mode(0o600)).unwrap();
        let slot2 = resolve_launch_slot(Some(store), Some("slot2")).unwrap();
        let hint = launch_on(Some(&slot2));
        assert!(
            hint.ends_with(&format!(
                "cd /g && env CLAUDE_CONFIG_DIR={} {argv}",
                store.join("slot2").display()
            )),
            "{hint}"
        );
        assert!(hint.contains("(claude-login slot slot2)"), "{hint}");

        let home = resolve_launch_slot(Some(store), Some("home")).unwrap();
        assert!(launch_on(Some(&home)).ends_with(&format!("cd /g && env -u CLAUDE_CONFIG_DIR {argv}")));
        assert!(launch_on(None).ends_with(&format!("cd /g && {argv}")), "no slot ⇒ the old hint");
    }

    #[test]
    fn the_launch_slot_defaults_to_active_and_fails_closed() {
        let td = tempfile::tempdir().unwrap();
        let store = td.path();
        // No pointer ⇒ home; no store at all ⇒ home too, but a named slot needs one.
        assert_eq!(resolve_launch_slot(Some(store), None).unwrap().name, "home");
        assert_eq!(resolve_launch_slot(None, None).unwrap().dir, claude_profiles::SlotDir::Home);
        assert!(resolve_launch_slot(None, Some("slot1")).is_err());

        // A slot with no credential is refused by name, whether named or active.
        std::fs::create_dir(store.join("slot1")).unwrap();
        let err = resolve_launch_slot(Some(store), Some("slot1")).unwrap_err().to_string();
        assert!(err.contains("\"slot1\"") && err.contains("not logged in"), "{err}");
        std::os::unix::fs::symlink("slot1", store.join(claude_profiles::ACTIVE_LINK)).unwrap();
        assert!(resolve_launch_slot(Some(store), None).is_err());
        assert!(resolve_launch_slot(Some(store), Some("ghost")).is_err());
    }

    #[test]
    fn an_agents_row_shows_the_claude_login_slot() {
        use softfig_ipc::growlightd::AgentSummary;
        let row = agent_row(&AgentSummary::new("a", "running", true).with_profile(Some("slot2".into())));
        assert!(row.contains(" profile=slot2 "), "{row:?}");
        assert!(row.ends_with("claude"), "{row:?}");
        let bare = agent_row(&AgentSummary::new("oc", "idle", false));
        assert!(!bare.contains("profile="), "{bare:?}");
        // The accounting column starts at the same offset either way.
        assert_eq!(row.find("claude"), bare.find("claude"));
    }

    #[test]
    fn start_args_parse_the_model_flag_and_keep_the_selectors_exclusive() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: GrowlightCmd,
        }
        let start = |args: &[&str]| match TestCli::try_parse_from(args).map(|c| c.cmd) {
            Ok(GrowlightCmd::Start(a)) => Ok(a),
            Ok(other) => panic!("expected Start, got {other:?}"),
            Err(e) => Err(e),
        };

        // Nothing chosen → no backend, no model (the picker's cue).
        let bare = start(&["g", "start"]).unwrap();
        assert_eq!(bare.backend, None);
        assert!(!bare.opencode);
        assert_eq!(bare.model, None);

        assert_eq!(
            start(&["g", "start", "--model", "flash effort=high"])
                .unwrap()
                .model
                .as_deref(),
            Some("flash effort=high")
        );
        assert_eq!(
            start(&["g", "start", "--backend", "opencode"]).unwrap().backend,
            Some(Backend::Opencode)
        );
        assert!(start(&["g", "start", "--opencode"]).unwrap().opencode);

        // The three selectors are mutually exclusive — two disagreeing choices
        // must be a parse error, never a silent precedence rule.
        assert!(start(&["g", "start", "--model", "flash", "--opencode"]).is_err());
        assert!(start(&["g", "start", "--model", "claude", "--backend", "claude"]).is_err());
        assert!(start(&["g", "start", "--opencode", "--backend", "claude"]).is_err());

        // claude-login-switcher slice 007: `--profile` names the slot.
        assert_eq!(bare.profile, None, "default = the store's active slot");
        assert_eq!(
            start(&["g", "start", "--profile", "slot2", "--no-launch"]).unwrap().profile.as_deref(),
            Some("slot2")
        );
    }

    /// A garden with one milestone (slices + CLAUDE.md) and one task, plus a
    /// baton pointing at a chosen item/slice.
    fn declaring_garden(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("sf-declmodel-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let backlog = root.join(PILLAR).join("backlog");
        let slices = backlog.join("milestones").join("m-x").join("slices");
        fs::create_dir_all(&slices).unwrap();
        fs::create_dir_all(backlog.join("tasks")).unwrap();

        // Slice 005 declares reasoning; slice 006 declares nothing (so it inherits
        // the milestone's flash); the milestone declares flash for everything else.
        fs::write(slices.join("005-picker.md"), "# Picker\n\n> Model: reasoning\n").unwrap();
        fs::write(slices.join("006-focus.md"), "# Focus\n\n> Last reviewed: 2026-08-08\n").unwrap();
        fs::write(
            backlog.join("milestones").join("m-x").join("CLAUDE.md"),
            "# backlog: m-x\n\n> Model: flash effort=low\n",
        )
        .unwrap();
        fs::write(
            backlog.join("tasks").join("047-a-task.md"),
            "# A task\n\n> Model: claude\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn growlight_decides_takes_a_comma_lists_first_entry() {
        // §6.4 legacy trap: semi-auto's "let growlight decide" runs the first
        // entry of a comma list (single-entry lines behave as before), and a
        // malformed list still never fails the launch.
        let root = declaring_garden("list");
        let slices = root
            .join(PILLAR)
            .join("backlog")
            .join("milestones")
            .join("m-x")
            .join("slices");
        fs::write(
            slices.join("007-list.md"),
            "# List\n\n> Model: reasoning, claude\n",
        )
        .unwrap();

        // The list's first entry wins: reasoning (opencode v4-pro).
        let on_007 = declared_model(&root, &baton_at(&root, "m-x", "007"));
        assert_eq!(on_007, ModelChoice::opencode(DEEPSEEK_REASONING));

        // A malformed comma list is reported and defaulted, never a launch error.
        fs::write(slices.join("008-bad.md"), "# Bad\n\n> Model: reasoning,\n").unwrap();
        assert_eq!(
            declared_model(&root, &baton_at(&root, "m-x", "008")),
            ModelChoice::opencode(DEFAULT_OPENCODE_MODEL)
        );

        fs::remove_dir_all(&root).ok();
    }

    fn baton_at(root: &Path, item: &str, slice: &str) -> PathBuf {
        let path = root.join(format!("baton-{item}-{slice}.md"));
        fs::write(
            &path,
            format!("---\nstatus: IN_PROGRESS\nitem: {item}\nslice: {slice}\n---\n# NEXT ACTION\ngo\n"),
        )
        .unwrap();
        path
    }

    // The workspace's one test `git` helper (review 043 G64-4): it carries a
    // throwaway identity, so the commit below passes on a CI runner too.
    use softfig_ipc::testing::git as run_git;

    /// Backdate a file's mtime to 2000-01-01, so a later tree edit is provably
    /// NEWER than the baton it is compared against (the boot guard's whole test).
    fn backdate_mtime(path: &Path) {
        let out = std::process::Command::new("touch")
            .arg("-d")
            .arg("2000-01-01T00:00:00")
            .arg(path)
            .output()
            .expect("run touch");
        assert!(out.status.success(), "touch failed");
    }

    /// TASK 064 — the CLI boot dirty-tree guard surfaces an item repo left dirty
    /// AND newer than the root baton's last handoff, and stays silent for a
    /// clean tree / a missing item / a baton with no active item. Read-only:
    /// nothing is reverted/staged/committed — the only observable effect is the
    /// returned journal line.
    #[test]
    fn boot_dirty_check_surfaces_a_dirty_tree_newer_than_the_baton() {
        let root = unique_tmp("boot-dirty");
        let _ = fs::remove_dir_all(&root);
        let tasks = root.join(PILLAR).join("backlog").join("tasks");
        fs::create_dir_all(&tasks).unwrap();
        let repo = root.join("repo");
        fs::create_dir_all(&repo).unwrap();

        // A real repo: one committed base file.
        run_git(&repo, &["init", "-q"]);
        fs::write(repo.join("a.txt"), "base\n").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-q", "-m", "base"]);

        fs::write(
            tasks.join("200-a-task.md"),
            format!("# Task\n\n> Worktree: {}\n", repo.display()),
        )
        .unwrap();
        let baton = root.join("baton.md");

        // No active item -> no signal.
        fs::write(&baton, "---\nstatus: IN_PROGRESS\nitem: null\n---\n").unwrap();
        assert!(boot_dirty_check(&root, &baton, false).is_none());

        // A baton naming the item, backdated before the tree's last edit.
        fs::write(&baton, "---\nstatus: IN_PROGRESS\nitem: 200\n---\n").unwrap();
        backdate_mtime(&baton);
        // Clean tree -> no signal.
        assert!(boot_dirty_check(&root, &baton, false).is_none());

        // Leave one uncommitted edit, newer than the (backdated) baton.
        fs::write(repo.join("a.txt"), "dirty\n").unwrap();
        let line = boot_dirty_check(&root, &baton, false)
            .expect("a dirty tree newer than the baton handoff surfaces");
        assert!(line.contains("200"), "names the item: {line}");
        assert!(
            line.contains(&repo.display().to_string()),
            "names the repo: {line}"
        );
        assert!(line.contains("1 uncommitted path"), "names the count: {line}");

        fs::remove_dir_all(&root).ok();
    }

    /// Review 043 G64-3: a semi-auto item in a named queue whose doc names no
    /// `> Worktree:` resolves through the queue's `## Queues` registry cell, the
    /// way growlightd's repo probe resolves it — the fid shape that started
    /// task 064. A slice doc's `> Worktree:` is not the item's (growlightd never
    /// reads it), so it does not count.
    #[test]
    fn boot_dirty_check_resolves_a_named_queue_item_through_the_registry() {
        let root = unique_tmp("boot-dirty-registry");
        let _ = fs::remove_dir_all(&root);
        let backlog = root.join(PILLAR).join("backlog");
        let milestone = backlog.join("milestones").join("fid-pam");
        fs::create_dir_all(milestone.join("slices")).unwrap();
        let repo = root.join("fid-repo");
        fs::create_dir_all(&repo).unwrap();
        run_git(&repo, &["init", "-q"]);
        fs::write(repo.join("gate.rs"), "base\n").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-q", "-m", "base"]);

        let region = |tag: &str, body: &str| format!("<!-- softfig:{tag} -->\n\n{body}\n\n<!-- /softfig:{tag} -->");
        let items = "| # | id | type | title | status |\n|---|----|------|-------|--------|\n\
                     | 1 | fid-pam | milestone | P3 | active |";
        fs::write(
            backlog.join("CLAUDE.md"),
            format!(
                "# backlog\n\n{}\n\n{}\n\n{}\n",
                region("queue", "| # | id | type | title | status |\n|---|----|------|-------|--------|"),
                region("queues", &format!("| queue | repo |\n|---|---|\n| fid | {} |", repo.display())),
                region("queue:fid", items),
            ),
        )
        .unwrap();
        fs::write(milestone.join("CLAUDE.md"), "# fid-pam\n\n> Model: claude\n").unwrap();
        fs::write(milestone.join("slices").join("001-probes.md"), "# probes\n\n> Worktree: /nowhere\n")
            .unwrap();

        let baton = root.join("baton.md");
        fs::write(&baton, "---\nstatus: IN_PROGRESS\nitem: fid-pam\nslice: 001\n---\n").unwrap();
        backdate_mtime(&baton);
        fs::write(repo.join("gate.rs"), "cut off mid-slice\n").unwrap();

        let line = boot_dirty_check(&root, &baton, false).expect("the registry names the fid repo");
        assert!(line.contains(&repo.display().to_string()), "names the registry's repo: {line}");

        // Review 043 G64-2: a baton `start` just seeded has no handoff, so the
        // dirt surfaces even though the seed's mtime is newer than every edit.
        fs::write(&baton, "---\nstatus: IN_PROGRESS\nitem: fid-pam\n---\n").unwrap();
        assert!(boot_dirty_check(&root, &baton, false).is_none(), "a just-written carried baton is newer");
        let fresh = boot_dirty_check(&root, &baton, true).expect("a fresh seed surfaces any dirt");
        assert!(fresh.contains("fresh"), "{fresh}");
        fs::remove_dir_all(&root).ok();
    }

    /// Reviews 042 G74-2 / G74-4 meet 043 G64-3: an item doc growlightd's
    /// reader refuses (a shadow `<id>-*.md` beside the real one, or a sealed
    /// region that could hide a `> Worktree:`) gives the CLI no repo signal
    /// either. Before the merge fix-up the CLI read "two docs" as "no doc" and
    /// fell through to the registry cell, naming a repo growlightd never would.
    #[test]
    fn boot_dirty_check_gives_no_signal_for_a_doc_growlightd_refuses() {
        let root = unique_tmp("boot-dirty-refused");
        let _ = fs::remove_dir_all(&root);
        let backlog = root.join(PILLAR).join("backlog");
        let tasks = backlog.join("tasks");
        fs::create_dir_all(&tasks).unwrap();
        let repo = root.join("fid-repo");
        fs::create_dir_all(&repo).unwrap();
        run_git(&repo, &["init", "-q"]);
        fs::write(repo.join("gate.rs"), "base\n").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-q", "-m", "base"]);

        let region = |tag: &str, body: &str| format!("<!-- softfig:{tag} -->\n\n{body}\n\n<!-- /softfig:{tag} -->");
        let items = "| # | id | type | title | status |\n|---|----|------|-------|--------|\n\
                     | 1 | 201 | task | gate | active |";
        fs::write(
            backlog.join("CLAUDE.md"),
            format!(
                "# backlog\n\n{}\n\n{}\n\n{}\n",
                region("queue", "| # | id | type | title | status |\n|---|----|------|-------|--------|"),
                region("queues", &format!("| queue | repo |\n|---|---|\n| fid | {} |", repo.display())),
                region("queue:fid", items),
            ),
        )
        .unwrap();
        fs::write(tasks.join("201-gate.md"), "# gate\n").unwrap();

        let baton = root.join("baton.md");
        fs::write(&baton, "---\nstatus: IN_PROGRESS\nitem: 201\n---\n").unwrap();
        backdate_mtime(&baton);
        fs::write(repo.join("gate.rs"), "cut off mid-slice\n").unwrap();
        assert!(boot_dirty_check(&root, &baton, false).is_some(), "one readable doc: the registry repo");

        fs::write(tasks.join("201-shadow.md"), "# shadow\n").unwrap();
        assert!(boot_dirty_check(&root, &baton, false).is_none(), "two docs for 201: no signal");

        fs::remove_file(tasks.join("201-shadow.md")).unwrap();
        fs::write(tasks.join("201-gate.md"), "# gate\n\n<vault id=\"w\">[encrypted]</vault>\n").unwrap();
        assert!(boot_dirty_check(&root, &baton, false).is_none(), "a sealed region: no signal");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn growlight_decides_reads_the_slice_then_the_milestone_then_falls_back() {
        let root = declaring_garden("chain");

        // The active slice's own declaration wins.
        let on_005 = declared_model(&root, &baton_at(&root, "m-x", "005"));
        assert_eq!(on_005, ModelChoice::opencode(DEEPSEEK_REASONING));

        // A slice that declares nothing inherits the milestone's — including its
        // variant, so a milestone can set effort once for all its slices.
        let on_006 = declared_model(&root, &baton_at(&root, "m-x", "006"));
        assert_eq!(on_006.model.as_deref(), Some(DEEPSEEK_FLASH));
        assert_eq!(on_006.variant.as_deref(), Some("low"));

        // The baton writes the slice unpadded as often as padded; both resolve.
        assert_eq!(declared_model(&root, &baton_at(&root, "m-x", "5")), on_005);

        // A standalone task has one doc, and may name claude just as a slice can.
        assert_eq!(
            declared_model(&root, &baton_at(&root, "047", "")),
            ModelChoice::claude()
        );

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn growlight_decides_falls_back_to_flash_and_never_fails_the_launch() {
        let root = declaring_garden("fallback");
        let flash = ModelChoice::opencode(DEFAULT_OPENCODE_MODEL);

        // No baton at all / a baton naming no item / an item with no doc anywhere:
        // all resolve to the cheap default rather than erroring out of a launch.
        assert_eq!(declared_model(&root, &root.join("nope.md")), flash);
        let itemless = root.join("itemless.md");
        fs::write(&itemless, "---\nstatus: IN_PROGRESS\nitem: null\n---\n").unwrap();
        assert_eq!(declared_model(&root, &itemless), flash);
        assert_eq!(declared_model(&root, &baton_at(&root, "ghost", "001")), flash);

        // A milestone slice that exists but declares nothing, under a milestone
        // that also declares nothing.
        let bare = root.join(PILLAR).join("backlog").join("milestones").join("m-bare");
        fs::create_dir_all(bare.join("slices")).unwrap();
        fs::write(bare.join("slices").join("001-x.md"), "# X\n").unwrap();
        assert_eq!(declared_model(&root, &baton_at(&root, "m-bare", "001")), flash);

        // A MALFORMED declaration is reported and defaulted, never propagated as a
        // launch failure — a bad metadata line must not stand between the human and
        // their loop.
        fs::write(bare.join("slices").join("002-bad.md"), "# X\n\n> Model: gpt-9\n").unwrap();
        assert_eq!(declared_model(&root, &baton_at(&root, "m-bare", "002")), flash);

        fs::remove_dir_all(&root).ok();
    }

    // ---- queue v2 §6.9 CLI forms (queue-v2-state slice 009) ------------

    #[test]
    fn queue_v2_forms_parse_exactly_as_the_spec_spells_them() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: GrowlightCmd,
        }

        // `queue` with no subcommand defaults to show.
        match TestCli::try_parse_from(["g", "queue"]).unwrap().cmd {
            GrowlightCmd::Queue(a) => assert!(a.cmd.is_none(), "bare queue = show"),
            other => panic!("expected Queue, got {other:?}"),
        }
        assert!(matches!(
            TestCli::try_parse_from(["g", "queue", "show"]).unwrap().cmd,
            GrowlightCmd::Queue(_)
        ));

        // report 171 repair forms
        match TestCli::try_parse_from(["g", "queue", "project", "set-repo", "p", "~/r", "--main", "dev"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Queue(q) => match q.cmd {
                Some(QueueSub::Project { cmd: QueueProjectSub::SetRepo(p) }) => {
                    assert_eq!((p.name.as_str(), p.repo.as_str()), ("p", "~/r"));
                    assert_eq!(p.main.as_deref(), Some("dev"));
                }
                other => panic!("expected project set-repo, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from([
            "g", "queue", "repair", "089", "--branch", "feat/remote-runner", "--base", "", "--project", "remote-runner",
        ])
        .unwrap()
        .cmd
        {
            GrowlightCmd::Queue(q) => match q.cmd {
                Some(QueueSub::Repair(r)) => {
                    assert_eq!(r.id, "089");
                    assert_eq!(r.branch.as_deref(), Some("feat/remote-runner"));
                    assert_eq!(r.base.as_deref(), Some(""));
                    assert_eq!(r.project.as_deref(), Some("remote-runner"));
                }
                other => panic!("expected repair, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        // `repair` with nothing to repair is a usage error, not a no-op call.
        assert!(TestCli::try_parse_from(["g", "queue", "repair", "089"]).is_err());

        // project add
        match TestCli::try_parse_from([
            "g",
            "queue",
            "project",
            "add",
            "softfig",
            "~/p",
            "--main",
            "main",
        ])
        .unwrap()
        .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Project { cmd } => match cmd {
                    QueueProjectSub::Add(p) => {
                        assert_eq!(p.name, "softfig");
                        assert_eq!(p.repo, "~/p");
                        assert_eq!(p.main.as_deref(), Some("main"));
                        assert!(!p.dry_run);
                    }
                    other => panic!("expected project add, got {other:?}"),
                },
                other => panic!("expected project add, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }

        // add milestone with every flag — @file values, urgent, comma-separated
        // after links, behind placement, dry-run.
        match TestCli::try_parse_from([
            "g",
            "queue",
            "add",
            "milestone",
            "folder-grants",
            "--project",
            "softfig",
            "--title",
            "Folder grants",
            "--mission",
            "@m.md",
            "--criteria",
            "none",
            "--urgent",
            "--after",
            "a,b",
            "--behind",
            "m1",
            "--dry-run",
        ])
        .unwrap()
        .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Add(q) => {
                    assert_eq!(q.kind, AddKind::Milestone);
                    assert_eq!(q.slug.as_deref(), Some("folder-grants"));
                    assert_eq!(q.project, "softfig");
                    assert_eq!(q.mission.as_deref(), Some("@m.md"));
                    assert!(q.urgent);
                    assert_eq!(q.after, ["a", "b"]);
                    assert_eq!(q.behind.as_deref(), Some("m1"));
                    assert!(q.dry_run);
                }
                other => panic!("expected add, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }

        // add restack — project only, no slug.
        match TestCli::try_parse_from(["g", "queue", "add", "restack", "--project", "softfig"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Add(q) => {
                    assert_eq!(q.kind, AddKind::Restack);
                    assert!(q.slug.is_none());
                }
                other => panic!("expected add, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }

        // move / lane / after / status / drop.
        match TestCli::try_parse_from(["g", "queue", "move", "m1", "behind", "m2"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Move(m) => {
                    assert_eq!(m.id, "m1");
                    assert_eq!(m.to, MoveTarget::Behind);
                    assert_eq!(m.ref_id.as_deref(), Some("m2"));
                }
                other => panic!("expected move, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from(["g", "queue", "lane", "m1", "urgent"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Lane(l) => {
                    assert_eq!(l.id, "m1");
                    assert_eq!(l.lane, LaneArg::Urgent);
                }
                other => panic!("expected lane, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from(["g", "queue", "after", "m1", "a", "b"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::After(l) => {
                    assert_eq!(l.id, "m1");
                    assert_eq!(l.ids, ["a", "b"]);
                }
                other => panic!("expected after, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from(["g", "queue", "status", "m1", "done"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Status(s) => {
                    assert_eq!(s.id, "m1");
                    assert_eq!(s.status, HumanStatus::Done);
                }
                other => panic!("expected status, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from(["g", "queue", "fleet", "m1", "no"]).unwrap().cmd {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Fleet(f) => {
                    assert_eq!(f.id, "m1");
                    assert_eq!(f.fleet, FleetArg::No);
                }
                other => panic!("expected fleet, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from([
            "g", "queue", "add", "task", "t1", "--project", "softfig", "--no-fleet",
        ])
        .unwrap()
        .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Add(q) => assert!(q.no_fleet),
                other => panic!("expected add, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from(["g", "queue", "not-before", "m1", ""]).unwrap().cmd {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::NotBefore(n) => {
                    assert_eq!(n.id, "m1");
                    assert_eq!(n.time, "", "an empty time clears it");
                }
                other => panic!("expected not-before, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from([
            "g", "queue", "add", "task", "t1", "--project", "softfig", "--not-before",
            "2026-11-01 02:00 -04:00",
        ])
        .unwrap()
        .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Add(q) => {
                    assert_eq!(q.not_before.as_deref(), Some("2026-11-01 02:00 -04:00"))
                }
                other => panic!("expected add, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }
        match TestCli::try_parse_from(["g", "queue", "drop", "m1", "--reason", "@why.md"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Queue(a) => match a.cmd.unwrap() {
                QueueSub::Drop(d) => {
                    assert_eq!(d.id, "m1");
                    assert_eq!(d.reason, "@why.md");
                }
                other => panic!("expected drop, got {other:?}"),
            },
            other => panic!("expected Queue, got {other:?}"),
        }

        // slice insert with positional placement + @file body.
        match TestCli::try_parse_from([
            "g",
            "slice",
            "insert",
            "m1",
            "002",
            "--title",
            "t",
            "--body",
            "@b.md",
            "behind",
            "001",
        ])
        .unwrap()
        .cmd
        {
            GrowlightCmd::Slice(a) => match a.cmd {
                SliceSub::Insert(s) => {
                    assert_eq!(s.milestone, "m1");
                    assert_eq!(s.slug, "002");
                    assert_eq!(s.body, "@b.md");
                    assert_eq!(s.position, Some(MoveTarget::Behind));
                    assert_eq!(s.ref_id.as_deref(), Some("001"));
                }
                other => panic!("expected insert, got {other:?}"),
            },
            other => panic!("expected Slice, got {other:?}"),
        }
        match TestCli::try_parse_from(["g", "slice", "move", "m1", "001", "front"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Slice(a) => match a.cmd {
                SliceSub::Move(m) => {
                    assert_eq!(m.milestone, "m1");
                    assert_eq!(m.id, "001");
                    assert_eq!(m.to, MoveTarget::Front);
                    assert!(m.ref_id.is_none());
                }
                other => panic!("expected move, got {other:?}"),
            },
            other => panic!("expected Slice, got {other:?}"),
        }
        match TestCli::try_parse_from(["g", "slice", "status", "m1", "001", "deferred"])
            .unwrap()
            .cmd
        {
            GrowlightCmd::Slice(a) => match a.cmd {
                SliceSub::Status(s) => {
                    assert_eq!(s.milestone, "m1");
                    assert_eq!(s.id, "001");
                    assert_eq!(s.status, HumanStatus::Deferred);
                }
                other => panic!("expected status, got {other:?}"),
            },
            other => panic!("expected Slice, got {other:?}"),
        }

        // The CLI grammar refuses what the spec refuses to spell.
        assert!(
            TestCli::try_parse_from([
                "g", "queue", "add", "milestone", "x", "--project", "p", "--front", "--behind", "y"
            ])
            .is_err(),
            "the position flags are exclusive"
        );
        assert!(
            TestCli::try_parse_from(["g", "queue", "lane", "m1", "active"]).is_err(),
            "daemon-owned words are not CLI words"
        );
        assert!(
            TestCli::try_parse_from(["g", "slice", "status", "m1", "001", "split"]).is_err(),
            "daemon-owned words are not CLI words"
        );
    }

    #[test]
    fn placement_maps_behind_to_the_verbs_after_position() {
        assert_eq!(
            placement(MoveTarget::Front, None).unwrap(),
            ("front".to_string(), None)
        );
        assert_eq!(
            placement(MoveTarget::Back, None).unwrap(),
            ("back".to_string(), None)
        );
        assert_eq!(
            placement(MoveTarget::Before, Some("m1".into())).unwrap(),
            ("before".to_string(), Some("m1".to_string()))
        );
        // `behind` is the CLI spelling of the verbs' `after` position (§6.9).
        assert_eq!(
            placement(MoveTarget::Behind, Some("m1".into())).unwrap(),
            ("after".to_string(), Some("m1".to_string()))
        );
        assert!(placement(MoveTarget::Before, None).is_err());
        assert!(placement(MoveTarget::Behind, None).is_err());
        assert!(placement(MoveTarget::Front, Some("x".into())).is_err());
        assert!(placement(MoveTarget::Back, Some("x".into())).is_err());
    }

    #[test]
    fn at_values_read_from_files_and_plain_values_pass_through() {
        let dir = unique_tmp("queue-at-file");
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("mission.md");
        fs::write(&f, "the mission\n").unwrap();
        assert_eq!(
            value_or_file(&format!("@{}", f.display())).unwrap(),
            "the mission\n"
        );
        assert_eq!(value_or_file("plain text").unwrap(), "plain text");
        assert!(value_or_file("@").is_err(), "bare @ has no path");
        assert!(value_or_file("@/nonexistent/x").is_err(), "missing file errors");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn queue_pick_renders_the_assignment_and_every_skip_reason() {
        let reply = growlightd::QueuePickReply {
            list: true,
            member: Some("c".into()),
            pin: Some("default".into()),
            backend: "claude".into(),
            picked: Some(growlightd::QueuePickAssignment {
                entry: "m".into(),
                unit: "slice 002 of m".into(),
                declared: Some("reasoning, flash".into()),
            }),
            skips: vec![
                growlightd::QueuePickSkip {
                    entry: "n".into(),
                    reason: "blocked_walk".into(),
                    detail: "its walk stops at a blocked item, which needs a human (§2)".into(),
                },
                growlightd::QueuePickSkip {
                    entry: "t".into(),
                    reason: "not_yet".into(),
                    detail: "a queued entry whose `not_before` start time is still ahead (§2 Holds)"
                        .into(),
                },
            ],
        };
        let out = render_queue_pick(&reply);
        assert!(out.contains("member c (backend claude, pin default)"), "{out}");
        assert!(out.contains("picked: m / slice 002 of m"), "{out}");
        assert!(out.contains("model: reasoning, flash"), "{out}");
        assert!(out.contains("skipped: 2"), "{out}");
        assert!(out.contains("  - n: blocked_walk — its walk stops"), "{out}");
        assert!(out.contains("  - t: not_yet — a queued entry whose `not_before`"), "{out}");
        assert!(out.contains("schedule: not applied"), "the dry-run says it ignores the schedule: {out}");
    }

    #[test]
    fn queue_pick_absent_list_prints_the_same_line_as_queue_show() {
        let reply = growlightd::QueuePickReply {
            list: false,
            member: None,
            pin: None,
            backend: "claude".into(),
            picked: None,
            skips: vec![],
        };
        assert_eq!(render_queue_pick(&reply), format!("{}\n", queue_empty_line()));
        assert!(queue_empty_line().contains("the v2 queue is empty (§3.4"));
    }

    #[test]
    fn status_prints_no_queue_block_when_there_is_no_v2_list() {
        let none = QueueShowReply {
            list: false,
            projects: vec![],
            entries: vec![],
            archived: vec![],
            sessions: vec![],
            trees: vec![],
        };
        assert_eq!(render_status_queue(&none), "");
    }

    #[test]
    fn queue_show_renders_both_lanes_and_the_stack_columns_verbatim() {
        use softfig_ipc::queue_v2::{EntryStatus, Lane, Project};
        let e = |id: &str, lane: Lane, branch: &str, base: &str| Entry {
            id: id.into(),
            kind: EntryKind::Milestone,
            title: format!("{id} title"),
            project: "softfig".into(),
            lane,
            status: EntryStatus::Queued,
            after: vec![],
            added: "2026-10-11T15:04:00Z".into(),
            branch: branch.into(),
            parent: String::new(),
            base: base.into(),
            claimed: String::new(),
            follow_ups: 0,
            pending_status: None,
            auto_restack: true,
            fleet: true,
            not_before: None,
        };
        let mut linked = e("normal-a", Lane::Normal, "feat/normal-a", "");
        linked.after = vec!["u1".into()];
        let mut claimed = e("u1", Lane::Urgent, "", "abc123");
        claimed.claimed = "2026-10-11T15:04:00Z".into();
        let queue = QueueToml::new(
            vec![Project {
                name: "softfig".into(),
                repo: "~/p".into(),
                main: "main".into(),
            }],
            vec![claimed, linked],
        );
        let body = render_queue_show(&queue);
        // The schema line heads the rendering; both lanes follow, urgent first
        // (the validator's invariant — the renderer never re-sorts).
        assert!(body.starts_with("queue.toml (schema 1)\n"), "{body}");
        let urgent = body.find("### Urgent").expect("urgent lane");
        let normal = body.find("### Normal").expect("normal lane");
        assert!(urgent < normal);
        // The stack columns are the TOML's own values: branch/base/claimed
        // verbatim, dashes for the empty cells.
        assert!(
            body.contains(
                "| u1 | milestone | u1 title | softfig | urgent | queued | — | — | abc123 | 2026-10-11T15:04:00Z |"
            ),
            "{body}"
        );
        assert!(
            body.contains(
                "| normal-a | milestone | normal-a title | softfig | normal | queued | u1 | feat/normal-a | — | — |"
            ),
            "{body}"
        );
        // Literal pipes are escaped, like the §3.4 view.
        let mut piped = e("p|1", Lane::Normal, "", "");
        piped.title = "a | b".into();
        let piped_body = render_queue_show(&QueueToml::new(vec![], vec![piped]));
        assert!(piped_body.contains("a \\| b"), "{piped_body}");
        assert!(piped_body.contains("p\\|1"), "{piped_body}");
        // A human-only entry is marked beside its status (queue-v2-parity
        // slice 002); a fleet entry's status cell stays bare, as above.
        let mut human = e("h1", Lane::Normal, "", "");
        human.fleet = false;
        let human_body = render_queue_show(&QueueToml::new(vec![], vec![human]));
        assert!(
            human_body.contains("| h1 | milestone | h1 title | softfig | normal | queued (human-only) |"),
            "{human_body}"
        );
        // A start time is shown as written (slice 003), after the human-only
        // marker when both apply.
        let mut timed = e("t1", Lane::Normal, "", "");
        timed.not_before = Some("2026-10-31 02:00 -04:00".into());
        let mut both = e("t2", Lane::Normal, "", "");
        both.not_before = Some("2026-10-31 02:00 -04:00".into());
        both.fleet = false;
        let timed_body = render_queue_show(&QueueToml::new(vec![], vec![timed, both]));
        assert!(
            timed_body.contains("| normal | queued (not before 2026-10-31 02:00 -04:00) |"),
            "{timed_body}"
        );
        assert!(
            timed_body
                .contains("| normal | queued (human-only) (not before 2026-10-31 02:00 -04:00) |"),
            "{timed_body}"
        );
    }

    #[test]
    fn queue_show_lanes_render_status_project_links_and_the_open_flag() {
        let entries = vec![
            QueueShowEntry {
                id: "u1".into(),
                kind: "milestone".into(),
                project: "softfig".into(),
                lane: "urgent".into(),
                status: "active".into(),
                after: vec!["done-x".into()],
                branch: "feat/u1".into(),
                base: String::new(),
                claimed: "2026-10-11T15:04:00Z".into(),
                pending_status: Some("blocked".into()),
                open: true,
                open_unknown: false,
                fleet: true,
                auto_restack: true,
                not_before: None,
                doc_fleet: None,
                doc_not_before: None,
            },
            QueueShowEntry {
                id: "n1".into(),
                kind: "milestone".into(),
                project: "softfig".into(),
                lane: "normal".into(),
                status: "queued".into(),
                after: vec![],
                branch: String::new(),
                base: String::new(),
                claimed: String::new(),
                pending_status: None,
                open: false,
                open_unknown: false,
                fleet: false,
                auto_restack: true,
                not_before: Some("2026-11-08 09:00Z".into()),
                doc_fleet: None,
                doc_not_before: None,
            },
            QueueShowEntry {
                id: "w1".into(),
                kind: "milestone".into(),
                project: "wedged".into(),
                lane: "normal".into(),
                status: "active".into(),
                after: vec![],
                branch: "feat/w1".into(),
                base: String::new(),
                claimed: "2026-10-11T15:04:00Z".into(),
                pending_status: None,
                open: false,
                open_unknown: true,
                fleet: true,
                auto_restack: true,
                not_before: None,
                doc_fleet: Some("no".into()),
                doc_not_before: None,
            },
        ];
        let view = QueueShowReply {
            list: true,
            projects: Vec::new(),
            entries,
            archived: Vec::new(),
            sessions: Vec::new(),
            trees: Vec::new(),
        };
        let body = render_queue_lanes(&view);
        let urgent = body.find("### Urgent").expect("urgent lane");
        let normal = body.find("### Normal").expect("normal lane");
        assert!(urgent < normal, "urgent lane renders first: {body}");
        // status, project and after links; the open branch carries its flag.
        assert!(
            body.contains("| u1 | active (→ blocked pending) | softfig | done-x | feat/u1 (open) |"),
            "{body}"
        );
        // The §2 holds, worded as `queue show` words them.
        assert!(
            body.contains("| n1 | queued (human-only) (not before 2026-11-08 09:00Z) | softfig | — | — |"),
            "{body}"
        );
        // A branch whose repo couldn't be read is not shown as merged.
        assert!(body.contains("| w1 | active | wedged | — | feat/w1 (stack unknown) |"), "{body}");

        // `queue show` warns once for the entry whose doc line disagrees (w1's
        // `> Fleet: no` on a claimable entry), and not for n1, whose doc has no
        // lines. The lanes themselves don't carry the warning.
        assert!(!body.contains("warning"), "{body}");
        let warnings = render_doc_hold_warnings(&view);
        let lines: Vec<&str> = warnings.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1, "{warnings}");
        assert!(lines[0].starts_with("warning: w1: its doc says `> Fleet: no`"), "{warnings}");
        let quiet = QueueShowReply { entries: view.entries[..2].to_vec(), ..view };
        assert_eq!(render_doc_hold_warnings(&quiet), "", "no disagreement, no output");
    }

    /// One flag, one place: `pick` reads the `queue`-level socket, and the old
    /// per-`pick` spelling is refused rather than beating it silently (V21).
    #[test]
    fn queue_pick_answers_on_the_queue_level_growlightd_socket() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: GrowlightCmd,
        }

        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone.sock");
        let gone_str = gone.to_str().unwrap();
        let cli = TestCli::try_parse_from(["g", "queue", "--growlightd-socket", gone_str, "pick"])
            .unwrap();
        let GrowlightCmd::Queue(args) = cli.cmd else { panic!("expected Queue") };
        let err = client_queue(args).unwrap_err().to_string();
        assert!(err.contains(gone_str), "{err}");

        assert!(
            TestCli::try_parse_from(["g", "queue", "pick", "--growlightd-socket", gone_str]).is_err(),
            "a second spelling of the flag must not parse"
        );
    }

    /// A growlightd stand-in on a real socket that answers one call with
    /// `reply` and hands back the op it was asked for.
    fn one_shot_growlightd(
        dir: &Path,
        reply: softfig_ipc::Response,
    ) -> (PathBuf, std::thread::JoinHandle<String>) {
        use std::io::{BufRead, BufReader, Write};
        let sock = dir.join("growlightd.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let served = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let req: softfig_ipc::Request = serde_json::from_str(&line).unwrap();
            let mut bytes = serde_json::to_vec(&reply).unwrap();
            bytes.push(b'\n');
            stream.write_all(&bytes).unwrap();
            req.op
        });
        (sock, served)
    }

    #[test]
    fn a_queue_view_from_growlightd_is_decoded_and_returned() {
        let dir = tempfile::tempdir().unwrap();
        let reply = softfig_ipc::Response::ok(serde_json::json!({
            "list": true,
            "projects": [{
                "name": "softfig", "repo": "~/p", "main": "main", "local": true, "stack": [],
            }],
        }));
        let (sock, served) = one_shot_growlightd(dir.path(), reply);
        let view = fetch_queue_view(&sock).unwrap().expect("a reply is a view");
        assert_eq!(served.join().unwrap(), growlightd::op::QUEUE_SHOW);
        assert!(view.list);
        assert_eq!(view.projects[0].name, "softfig");
    }

    #[test]
    fn a_growlightd_too_old_for_queue_show_costs_only_the_annotations() {
        let dir = tempfile::tempdir().unwrap();
        let reply = softfig_ipc::Response::err(ErrorKind::BadArgs, "unknown op");
        let (sock, served) = one_shot_growlightd(dir.path(), reply);
        assert_eq!(fetch_queue_view(&sock).unwrap(), None);
        served.join().unwrap();
    }

    #[test]
    fn any_other_growlightd_error_is_surfaced() {
        let dir = tempfile::tempdir().unwrap();
        let reply = softfig_ipc::Response::err(ErrorKind::Internal, "boom");
        let (sock, served) = one_shot_growlightd(dir.path(), reply);
        let err = fetch_queue_view(&sock).unwrap_err().to_string();
        assert!(err.contains("boom"), "{err}");
        served.join().unwrap();
    }

    #[test]
    fn no_growlightd_at_all_is_no_view() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(fetch_queue_view(&dir.path().join("absent.sock")).unwrap(), None);
    }

    #[test]
    fn queue_show_annotations_render_stack_and_sessions() {
        use softfig_ipc::growlightd::{QueueProjectStack, QueueShowSession, QueueStackBranch};
        let view = QueueShowReply {
            list: true,
            projects: vec![
                QueueProjectStack {
                    name: "softfig".into(),
                    repo: "~/p".into(),
                    main: "main".into(),
                    local: true,
                    stack: vec![QueueStackBranch {
                        entry: "one".into(),
                        branch: "feat/one".into(),
                        parent: String::new(),
                        base: "abc123".into(),
                        claimed: "2026-10-11T15:04:00Z".into(),
                    }],
                    stack_unknown: None,
                },
                QueueProjectStack {
                    name: "wedged".into(),
                    repo: "~/w".into(),
                    main: "main".into(),
                    local: true,
                    stack: Vec::new(),
                    stack_unknown: Some("git probe in ~/w: timed out after 10s".into()),
                },
            ],
            entries: Vec::new(),
            archived: Vec::new(),
            sessions: vec![QueueShowSession {
                entry: "one".into(),
                tree: None,
                unit: None,
                path: "growlight/backlog/milestones/one/CLAUDE.md".into(),
                lines: vec!["- 2026-10-11T15:40Z · completed · reasoning · member oc · $0.04".into()],
            }],
            trees: Vec::new(),
        };
        let body = render_annotations(&view);
        assert!(body.contains("### Stack per repo"), "{body}");
        assert!(
            body.contains("- softfig (local, main = main) ~/p"),
            "{body}"
        );
        assert!(
            body.contains("- feat/one  parent=main  base=abc123  claimed=2026-10-11T15:04:00Z"),
            "{body}"
        );
        // An unread stack says so, with the reason, and never reads as empty.
        assert!(
            body.contains("- wedged (local, main = main) ~/w\n  (stack unknown — git probe in ~/w: timed out after 10s)\n"),
            "{body}"
        );
        assert!(body.contains("### Sessions"), "{body}");
        assert!(body.contains("one (growlight/backlog/milestones/one/CLAUDE.md)"), "{body}");
        assert!(body.contains("  - 2026-10-11T15:40Z · completed"), "{body}");
    }

    // The e2e fixture: a REAL keeperd on a temp garden (no FUSE, no watcher,
    // temp socket) — the same shape keeperd's own e2e suite boots — so the
    // §6.9 forms are exercised over the wire exactly as the binary sends them,
    // without ever touching the live garden (spec §11). The installed-binary
    // sweep happens at close-out, when the human reviews.

    use softfig_keeperd::{Daemon as KeeperDaemon, DaemonHandle as KeeperDaemonHandle, KeeperConfig};
    use softfig_vault::{Vault, params::VaultParams};
    use softfig_vcs::Repo;

    const E2E_PASS: &str = "pw-test-12345";

    /// Boot keeperd on a fresh temp garden + unlock it; return (handle,
    /// socket, dir).
    fn boot_keeperd(tag: &str) -> (KeeperDaemonHandle, PathBuf, PathBuf) {
        let dir = unique_tmp(tag);
        let garden = dir.join("garden");
        fs::create_dir_all(&garden).unwrap();

        // Minimum-cost Argon2 so the fixture stays fast (the keeperd suite's
        // convention).
        let mut params = VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let (_v, session, _r) = Vault::init_with_params(&garden, E2E_PASS.as_bytes(), params).unwrap();
        Repo::init(&garden, &session).unwrap();
        drop(session);

        let socket = dir.join("keeperd.sock");
        let config = KeeperConfig::new(&garden)
            .with_socket(&socket)
            .without_watcher()
            .without_net()
            .without_fuse();
        let daemon = KeeperDaemon::new(config);
        let handle = daemon.start().expect("keeperd boots");
        wait_until(|| socket.exists());

        let mut stream = connect(&socket).expect("connect");
        let req = Request::new(op::UNLOCK, serde_json::json!({ "passphrase": E2E_PASS }));
        let resp = softfig_ipc::call(&mut stream, &req).expect("unlock call");
        assert!(matches!(resp, softfig_ipc::Response::Ok { .. }), "unlock: {resp:?}");
        (handle, socket, dir)
    }

    /// Read a garden file back through the daemon (the same `read_file` seam
    /// `queue show` uses), for asserting on the resulting v2 state.
    fn e2e_read(socket: &Path, path: &str) -> String {
        let mut stream = connect(socket).expect("connect");
        let req = Request::new(op::READ_FILE, serde_json::json!({ "path": path }));
        match softfig_ipc::call(&mut stream, &req).expect("read") {
            softfig_ipc::Response::Ok { data, .. } => {
                let reply: ReadFileReply = serde_json::from_value(data).unwrap();
                reply.content
            }
            other => panic!("read {path}: {other:?}"),
        }
    }

    fn e2e_queue(socket: &Path) -> QueueToml {
        QueueToml::parse(&e2e_read(socket, QUEUE_FILE)).expect("queue.toml parses")
    }

    fn e2e_archive(socket: &Path) -> softfig_ipc::queue_v2::QueueArchiveToml {
        softfig_ipc::queue_v2::QueueArchiveToml::parse(&e2e_read(
            socket,
            softfig_ipc::queue_v2::QUEUE_ARCHIVE_FILE,
        ))
        .expect("queue-archive.toml parses")
    }

    fn milestone_args(
        slug: &str,
        mission: &str,
        criteria: &str,
        dry_run: bool,
    ) -> QueueAddArgs {
        QueueAddArgs {
            kind: AddKind::Milestone,
            slug: Some(slug.into()),
            project: "softfig".into(),
            title: Some(format!("{slug} title")),
            mission: Some(mission.into()),
            criteria: Some(criteria.into()),
            urgent: false,
            after: vec![],
            front: false,
            before: None,
            behind: None,
            no_fleet: false,
            not_before: None,
            dry_run,
        }
    }

    #[test]
    fn queue_v2_forms_round_trip_against_a_real_keeperd() {
        let (handle, socket, dir) = boot_keeperd("queue-v2-forms");

        // Fresh garden: no queue.toml — `queue show` exits clean with the
        // §3.4 "renders only when the file exists" message.
        queue_show(&socket, &dir.join("growlightd-absent.sock")).unwrap();

        // project add → ok; a duplicate is refused and the wire code leads.
        queue_project_add(
            &socket,
            QueueProjectAddArgs {
                name: "softfig".into(),
                repo: "~/p".into(),
                main: None,
                dry_run: false,
            },
        )
        .unwrap();
        let err = queue_project_add(
            &socket,
            QueueProjectAddArgs {
                name: "softfig".into(),
                repo: "~/p".into(),
                main: None,
                dry_run: false,
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("exists"), "{err:#}");

        // A dry-run project add writes nothing (the projects list is unchanged
        // one row).
        queue_project_add(
            &socket,
            QueueProjectAddArgs {
                name: "roadeye".into(),
                repo: "phone:roadeye".into(),
                main: None,
                dry_run: true,
            },
        )
        .unwrap();
        assert_eq!(e2e_queue(&socket).projects.len(), 1, "dry run wrote nothing");

        // milestone add — the row lands with its branch seed.
        queue_add(&socket, milestone_args("m1", "do the thing", "done when done", false)).unwrap();
        let q = e2e_queue(&socket);
        assert_eq!(q.entries.len(), 1);
        assert_eq!(q.entries[0].id, "m1");
        assert_eq!(q.entries[0].branch, "feat/m1");
        assert_eq!(q.entries[0].lane, QueueLane::Normal);

        // task add DRY RUN → nothing written.
        let task = QueueAddArgs {
            kind: AddKind::Task,
            slug: Some("t1".into()),
            project: "softfig".into(),
            title: Some("T1".into()),
            mission: Some("m".into()),
            criteria: Some("c".into()),
            urgent: false,
            after: vec![],
            front: false,
            before: None,
            behind: None,
            no_fleet: false,
            not_before: None,
            dry_run: true,
        };
        queue_add(&socket, task).unwrap();
        assert_eq!(e2e_queue(&socket).entries.len(), 1, "task dry run wrote nothing");

        // restack add — urgent lane, no branch of its own.
        queue_add(
            &socket,
            QueueAddArgs {
                kind: AddKind::Restack,
                slug: None,
                project: "softfig".into(),
                title: None,
                mission: None,
                criteria: None,
                urgent: false,
                after: vec![],
                front: false,
                before: None,
                behind: None,
                no_fleet: false,
                not_before: None,
                dry_run: false,
            },
        )
        .unwrap();
        let q = e2e_queue(&socket);
        let restack = q.entries.iter().find(|e| e.kind == EntryKind::Restack).expect("restack row");
        assert_eq!(restack.lane, QueueLane::Urgent);
        assert!(restack.branch.is_empty());
        let restack_id = restack.id.clone();

        // lane change → urgent lane.
        queue_lane(
            &socket,
            QueueLaneArgs { id: "m1".into(), lane: LaneArg::Urgent, dry_run: false },
        )
        .unwrap();
        assert_eq!(
            e2e_queue(&socket).entries.iter().find(|e| e.id == "m1").unwrap().lane,
            QueueLane::Urgent
        );

        // after links: replace the whole list (the restack's NNN resolves).
        queue_after(
            &socket,
            QueueAfterArgs { id: "m1".into(), ids: vec![restack_id.clone()], dry_run: false },
        )
        .unwrap();
        assert_eq!(
            e2e_queue(&socket).entries.iter().find(|e| e.id == "m1").unwrap().after,
            vec![restack_id.clone()],
            "the link list is replaced, not merged"
        );

        // move within the lane (behind → the verbs' after position).
        queue_move(
            &socket,
            QueueMoveArgs {
                id: "m1".into(),
                to: MoveTarget::Behind,
                ref_id: Some(restack_id),
                dry_run: false,
            },
        )
        .unwrap();

        // fleet: hold for the human, then release.
        let fleet_of = |socket: &Path| {
            e2e_queue(socket).entries.iter().find(|e| e.id == "m1").unwrap().fleet
        };
        queue_fleet(&socket, QueueFleetArgs { id: "m1".into(), fleet: FleetArg::No, dry_run: false })
            .unwrap();
        assert!(!fleet_of(&socket), "queue fleet m1 no holds it");
        queue_fleet(&socket, QueueFleetArgs { id: "m1".into(), fleet: FleetArg::Yes, dry_run: false })
            .unwrap();
        assert!(fleet_of(&socket), "queue fleet m1 yes releases it");

        // not-before: schedule, refuse a bad time, then clear.
        let nb_of = |socket: &Path| {
            e2e_queue(socket).entries.iter().find(|e| e.id == "m1").unwrap().not_before.clone()
        };
        let at = "2026-11-01 02:00 -04:00";
        let nb = |time: &str| QueueNotBeforeArgs { id: "m1".into(), time: time.into(), dry_run: false };
        queue_not_before(&socket, nb(at)).unwrap();
        assert_eq!(nb_of(&socket).as_deref(), Some(at), "queue not-before m1 <time> schedules it");
        let err = queue_not_before(&socket, nb("tomorrow")).unwrap_err();
        assert!(format!("{err:#}").contains("bad_start_time"), "{err:#}");
        assert_eq!(nb_of(&socket).as_deref(), Some(at), "a refused time changes nothing");
        queue_not_before(&socket, nb("")).unwrap();
        assert_eq!(nb_of(&socket), None, "queue not-before m1 \"\" clears it");

        // A dry-run status edit leaves the state untouched.
        queue_status(
            &socket,
            QueueStatusArgs { id: "m1".into(), status: HumanStatus::Blocked, dry_run: true },
        )
        .unwrap();
        assert_eq!(
            e2e_queue(&socket).entries.iter().find(|e| e.id == "m1").unwrap().status,
            softfig_ipc::queue_v2::EntryStatus::Queued,
            "dry run wrote nothing"
        );

        // slice insert (the generated 001-plan exists; 002 appends), then move
        // and status inside slices.toml.
        slice_insert(
            &socket,
            SliceInsertArgs {
                milestone: "m1".into(),
                slug: "002".into(),
                title: Some("the second slice".into()),
                body: "do the second thing".into(),
                position: None,
                ref_id: None,
                dry_run: false,
            },
        )
        .unwrap();
        let s = softfig_ipc::queue_v2::SlicesToml::parse(&e2e_read(
            &socket,
            &softfig_ipc::queue_v2::slices_file("m1"),
        ))
        .expect("slices.toml parses");
        assert_eq!(s.items.len(), 2);
        assert_eq!(s.items[0].id, "001");
        assert_eq!(s.items[1].id, "002");

        slice_move(
            &socket,
            SliceMoveArgs {
                milestone: "m1".into(),
                id: "002".into(),
                to: MoveTarget::Front,
                ref_id: None,
                dry_run: false,
            },
        )
        .unwrap();
        let s = softfig_ipc::queue_v2::SlicesToml::parse(&e2e_read(
            &socket,
            &softfig_ipc::queue_v2::slices_file("m1"),
        ))
        .expect("slices.toml parses");
        assert_eq!(s.items[0].id, "002", "front move reorders");

        slice_status(
            &socket,
            SliceStatusArgs {
                milestone: "m1".into(),
                id: "002".into(),
                status: HumanStatus::Done,
                dry_run: false,
            },
        )
        .unwrap();
        let s = softfig_ipc::queue_v2::SlicesToml::parse(&e2e_read(
            &socket,
            &softfig_ipc::queue_v2::slices_file("m1"),
        ))
        .expect("slices.toml parses");
        assert_eq!(s.items[0].status, SliceStatus::Done);

        // `done` archives the milestone; the archive row is `done` with no
        // reason, and the live list loses the row.
        queue_status(
            &socket,
            QueueStatusArgs { id: "m1".into(), status: HumanStatus::Done, dry_run: false },
        )
        .unwrap();
        assert!(
            e2e_queue(&socket).entries.iter().all(|e| e.id != "m1"),
            "done leaves the live list"
        );
        let arch = e2e_archive(&socket);
        let m1 = arch.entries.iter().find(|e| e.row.id == "m1").expect("m1 archived");
        assert_eq!(m1.final_status, softfig_ipc::queue_v2::FinalStatus::Done);
        assert!(m1.reason.is_none(), "done rows omit reason");

        // drop archives a second entry as `dropped` with the reason.
        queue_add(&socket, milestone_args("m2", "later work", "never", false)).unwrap();
        queue_drop(
            &socket,
            QueueDropArgs {
                id: "m2".into(),
                reason: "superseded".into(),
                dry_run: false,
            },
        )
        .unwrap();
        let arch = e2e_archive(&socket);
        let m2 = arch.entries.iter().find(|e| e.row.id == "m2").expect("m2 archived");
        assert_eq!(m2.final_status, softfig_ipc::queue_v2::FinalStatus::Dropped);
        assert_eq!(m2.reason.as_deref(), Some("superseded"));

        // A bad slug surfaces the wire refusal code, unadorned.
        let err = queue_add(&socket, milestone_args("Bad_Name!", "x", "y", false)).unwrap_err();
        assert!(format!("{err:#}").contains("bad_name"), "{err:#}");

        // `queue show` still renders the surviving state end to end.
        queue_show(&socket, &dir.join("growlightd-absent.sock")).unwrap();

        handle.shutdown();
        handle.join().unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    // ---- slice 002: launch argv, picker, extras, auto resolution ---------

    /// claude-model-select slice 002 argv check: `claude` on the harness
    /// default is byte-identical to today, `claude:opus` becomes
    /// `--model opus`, and `claude:claude-opus-4-7 effort=high` becomes
    /// `--model claude-opus-4-7 --effort high`. Together with
    /// `claude_interactive_command_is_the_hardwired_argv_rooted_at_the_garden`
    /// in `growlight_backend` (the no-model case), this covers the finish-check
    /// matrix for argv construction.
    #[test]
    fn slice_002_claude_argv_covers_default_alias_and_full_id_with_effort() {
        use std::ffi::OsString;
        let launch = InteractiveLaunch {
            agent_name: AGENT_NAME,
            loop_settings: Path::new("/rt/loop.json"),
            mcp_config: Path::new("/rt/mcp.json"),
            garden_root: Path::new("/g"),
            opencode_config: Path::new("/rt/opencode.json"),
            boot_prompt: OPENCODE_KICK,
            claude_slot: None,
        };
        let argv_of = |choice: &ModelChoice| -> Vec<String> {
            interactive_command(choice.backend, &launch, &choice.claude_argv())
                .unwrap()
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };

        // Harness default: no `--model`/`--effort` tail at all.
        let default = argv_of(&ModelChoice::claude());
        assert_eq!(
            default,
            vec![
                "--name".to_string(),
                AGENT_NAME.to_string(),
                "--settings".to_string(),
                "/rt/loop.json".to_string(),
                "--mcp-config".to_string(),
                "/rt/mcp.json".to_string(),
            ],
            "the harness default argv must be byte-identical to the pre-slice-002 invocation",
        );

        // Alias: `claude:opus` → `--model opus`.
        let opus = match parse_model_spec("claude:opus").unwrap() {
            ModelSpec::Fixed(c) => c,
            ModelSpec::Auto => panic!("`claude:opus` must not resolve to auto"),
        };
        assert_eq!(
            argv_of(&opus).into_iter().rev().take(2).collect::<Vec<_>>(),
            vec!["opus".to_string(), "--model".to_string()],
            "claude:opus must land on `--model opus`",
        );
        // ... and never leaks an `--effort` when none was declared.
        assert!(!argv_of(&opus).iter().any(|a| a == "--effort"));

        // Full id + closed-set effort: `claude:claude-opus-4-7 effort=high`
        // → `--model claude-opus-4-7 --effort high`.
        let full = match parse_model_spec("claude:claude-opus-4-7 effort=high").unwrap() {
            ModelSpec::Fixed(c) => c,
            ModelSpec::Auto => panic!("not auto"),
        };
        let full_argv = argv_of(&full);
        let tail: Vec<OsString> = full_argv
            .iter()
            .skip_while(|a| a.as_str() != "--model")
            .map(OsString::from)
            .collect();
        assert_eq!(
            tail,
            vec![
                OsString::from("--model"),
                OsString::from("claude-opus-4-7"),
                OsString::from("--effort"),
                OsString::from("high"),
            ],
            "argv tail for a declared model + effort",
        );
    }

    /// The picker's number mapping is pure: `1`/Enter is the harness default,
    /// `2..=5` are the aliases in menu order, `6..` are the extras in the
    /// order the dedup produced, and `r`/`f`/`a` take DeepSeek + auto. A key
    /// outside the menu returns `None` so the caller tries a typed spec.
    #[test]
    fn slice_002_picker_number_mapping_covers_aliases_and_extras() {
        let extras = vec!["claude-opus-4-7".to_string(), "claude-fable-5-1[1m]".to_string()];

        // Enter and `1` both resolve to the harness default (muscle memory).
        for key in ["", "1"] {
            match picker_fixed_choice(key, &extras).unwrap().unwrap() {
                ModelSpec::Fixed(c) => assert_eq!(c, ModelChoice::claude()),
                ModelSpec::Auto => panic!("`{key}` must not resolve to auto"),
            }
        }

        // 2..=5 → opus/sonnet/haiku/fable, in menu order.
        for (n, alias) in ["2", "3", "4", "5"].iter().zip(CLAUDE_PICKER_ALIASES) {
            match picker_fixed_choice(n, &extras).unwrap().unwrap() {
                ModelSpec::Fixed(c) => assert_eq!(
                    c,
                    ModelChoice::claude_on(Some((*alias).to_string()), None),
                    "`{n}` must map to `claude:{alias}`",
                ),
                ModelSpec::Auto => panic!("`{n}` must not resolve to auto"),
            }
        }

        // 6/7 are the two extras — same identity as a typed `claude:<extra>`
        // (validated through `parse_model_spec`).
        let typed6 = match parse_model_spec("claude:claude-opus-4-7").unwrap() {
            ModelSpec::Fixed(c) => c,
            ModelSpec::Auto => unreachable!(),
        };
        match picker_fixed_choice("6", &extras).unwrap().unwrap() {
            ModelSpec::Fixed(c) => assert_eq!(c, typed6),
            ModelSpec::Auto => panic!(),
        }
        let typed7 = match parse_model_spec("claude:claude-fable-5-1[1m]").unwrap() {
            ModelSpec::Fixed(c) => c,
            ModelSpec::Auto => unreachable!(),
        };
        match picker_fixed_choice("7", &extras).unwrap().unwrap() {
            ModelSpec::Fixed(c) => assert_eq!(c, typed7),
            ModelSpec::Auto => panic!(),
        }

        // Letter keys cover opencode + auto.
        match picker_fixed_choice("r", &extras).unwrap().unwrap() {
            ModelSpec::Fixed(c) => assert_eq!(c, ModelChoice::opencode(DEEPSEEK_REASONING)),
            ModelSpec::Auto => panic!(),
        }
        match picker_fixed_choice("f", &extras).unwrap().unwrap() {
            ModelSpec::Fixed(c) => assert_eq!(c, ModelChoice::opencode(DEEPSEEK_FLASH)),
            ModelSpec::Auto => panic!(),
        }
        match picker_fixed_choice("a", &extras).unwrap().unwrap() {
            ModelSpec::Fixed(_) => panic!("`a` is let-growlight-decide"),
            ModelSpec::Auto => {}
        }

        // Out-of-range numbers and arbitrary words aren't menu keys — the
        // caller must try the typed-spec path, not refuse the launch.
        assert!(picker_fixed_choice("8", &extras).unwrap().is_none());
        assert!(picker_fixed_choice("99", &extras).unwrap().is_none());
        assert!(picker_fixed_choice("claude:opus", &extras).unwrap().is_none());
    }

    /// The picker stdin seam carries typed specs through the shared grammar;
    /// an unparseable one re-prompts rather than fails the launch.
    #[test]
    fn slice_002_picker_typed_spec_through_shared_grammar_and_reprompts() {
        // Typed `claude:opus` resolves to the same choice the number row does.
        let mut r = std::io::Cursor::new(b"claude:opus\n".to_vec());
        match prompt_for_model_in(&mut r, &[]).unwrap() {
            ModelSpec::Fixed(c) => {
                assert_eq!(c, ModelChoice::claude_on(Some("opus".to_string()), None))
            }
            ModelSpec::Auto => panic!("typed `claude:opus` must not be auto"),
        }

        // A bad spec re-prompts; the second line is a good one.
        let mut r = std::io::Cursor::new(b"not-a-model\nclaude\n".to_vec());
        match prompt_for_model_in(&mut r, &[]).unwrap() {
            ModelSpec::Fixed(c) => assert_eq!(c, ModelChoice::claude()),
            ModelSpec::Auto => panic!(),
        }

        // EOF (closed stdin mid-run) falls back to the harness default rather
        // than looping — the same posture as the pre-slice-002 picker.
        let mut r = std::io::Cursor::new(Vec::new());
        match prompt_for_model_in(&mut r, &[]).unwrap() {
            ModelSpec::Fixed(c) => assert_eq!(c, ModelChoice::claude()),
            ModelSpec::Auto => panic!(),
        }
    }

    /// `claude_picker_extras` orders .claude.json first, then growlight.toml,
    /// first-wins dedup across the two sources, and drops entries that
    /// duplicate a built-in alias row.
    #[test]
    fn slice_002_claude_picker_extras_order_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let claude_json = dir.path().join(".claude.json");
        // One real id, one duplicate of a built-in alias (must be dropped), one
        // id that growlight.toml will also list (first-wins dedup).
        fs::write(
            &claude_json,
            r#"{"additionalModelOptionsCache":[
                {"value":"claude-opus-4-7"},
                {"value":"opus"},
                {"value":"claude-fable-5-1[1m]"}
            ]}"#,
        )
        .unwrap();
        let growlight = dir.path().join("growlight.toml");
        // Overlaps `claude-opus-4-7` (dropped by dedup since .claude.json wins
        // on order) and adds a new id.
        fs::write(
            &growlight,
            "[claude]\nmodels = [\"claude-opus-4-7\", \"claude-sonnet-5-5\"]\n",
        )
        .unwrap();

        let extras = claude_picker_extras(Some(&claude_json), Some(&growlight));
        assert_eq!(
            extras,
            vec![
                "claude-opus-4-7".to_string(),
                "claude-fable-5-1[1m]".to_string(),
                "claude-sonnet-5-5".to_string(),
            ],
        );
    }

    /// The .claude.json reader is best-effort: an absent file, malformed JSON,
    /// and a missing/wrong-shaped key all yield an empty list rather than
    /// failing the launch.
    #[test]
    fn slice_002_read_claude_json_models_is_best_effort() {
        let dir = tempfile::tempdir().unwrap();

        // Absent file → empty.
        let missing = dir.path().join("none.json");
        assert!(read_claude_json_models(&missing).is_empty());

        // Malformed JSON → empty, no panic.
        let bad = dir.path().join("bad.json");
        fs::write(&bad, b"this is not json").unwrap();
        assert!(read_claude_json_models(&bad).is_empty());

        // Missing key → empty.
        let no_key = dir.path().join("no-key.json");
        fs::write(&no_key, b"{\"other\": []}").unwrap();
        assert!(read_claude_json_models(&no_key).is_empty());

        // Normal list → entries, in file order; non-string / missing-value
        // entries are quietly skipped.
        let good = dir.path().join("good.json");
        fs::write(
            &good,
            r#"{"additionalModelOptionsCache":[
                {"value":"claude-opus-4-7","label":"Opus"},
                {"label":"no value"},
                {"value":""},
                {"value":"claude-fable-5-1[1m]"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            read_claude_json_models(&good),
            vec![
                "claude-opus-4-7".to_string(),
                "claude-fable-5-1[1m]".to_string()
            ],
        );
    }

    /// A slice doc's `> Model: claude:claude-opus-4-7` overrides a milestone's
    /// `> Model: claude` under the `--model auto` path — the finish-check for
    /// "`auto` honours a `claude:` declaration".
    #[test]
    fn slice_002_auto_resolution_slice_claude_id_overrides_milestone_claude() {
        let docs = [
            ("005-pick-opus.md", Some("> Model: claude:claude-opus-4-7\n")),
            ("CLAUDE.md", Some("> Model: claude\n")),
        ];
        let resolved = resolve_item_models(docs).unwrap().unwrap();
        assert_eq!(resolved.origin, "005-pick-opus.md");
        let first = resolved.list.first().clone();
        assert_eq!(first.backend, Backend::Claude);
        assert_eq!(first.model.as_deref(), Some("claude-opus-4-7"));
        // Resolved choice → `--model claude-opus-4-7` on the spawn argv.
        assert_eq!(
            first.claude_argv(),
            vec!["--model".to_string(), "claude-opus-4-7".to_string()],
        );
    }

    /// `--no-launch` hint carries the `--model <m>` tail when the choice names
    /// one; a bare `claude` keeps the old settings-pair-only hint byte-identical.
    #[test]
    fn slice_002_no_launch_hint_names_the_model() {
        let launch = InteractiveLaunch {
            agent_name: AGENT_NAME,
            loop_settings: Path::new("/rt/loop.json"),
            mcp_config: Path::new("/rt/mcp.json"),
            garden_root: Path::new("/g"),
            opencode_config: Path::new("/rt/opencode.json"),
            boot_prompt: OPENCODE_KICK,
            claude_slot: None,
        };
        let bare = no_launch_hint(&ModelChoice::claude(), &launch);
        assert!(!bare.contains("--model"));
        assert!(!bare.contains("--effort"));

        let opus = ModelChoice::claude_on(Some("opus".to_string()), None);
        let hint = no_launch_hint(&opus, &launch);
        assert!(
            hint.contains("--mcp-config /rt/mcp.json --model opus"),
            "hint carries --model after --mcp-config: {hint}",
        );

        let o47h = ModelChoice::claude_on(
            Some("claude-opus-4-7".to_string()),
            Some("high".to_string()),
        );
        let hint = no_launch_hint(&o47h, &launch);
        assert!(
            hint.ends_with("--model claude-opus-4-7 --effort high"),
            "hint tail: {hint}",
        );
    }

    /// `queue migrate` takes exactly one of `--dry-run` / `--apply`;
    /// `--apply` needs `--answers` and `--expect`, and `--expect` only means
    /// something under `--apply` (queue-v2-migrate slice 005).
    #[test]
    fn migrate_modes_are_an_either_or_and_apply_needs_its_inputs() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: GrowlightCmd,
        }
        let parse = |tail: &[&str]| {
            let argv = ["g", "queue", "migrate"].iter().chain(tail).copied();
            TestCli::try_parse_from(argv).map(|c| match c.cmd {
                GrowlightCmd::Queue(q) => match q.cmd {
                    Some(QueueSub::Migrate(m)) => m,
                    other => panic!("expected migrate, got {other:?}"),
                },
                other => panic!("expected Queue, got {other:?}"),
            })
        };
        assert!(parse(&[]).is_err(), "a mode is required");
        assert!(parse(&["--dry-run", "--apply", "--answers", "a.toml", "--expect", "v"]).is_err());
        assert!(parse(&["--apply"]).is_err(), "--apply without --answers/--expect");
        assert!(parse(&["--apply", "--answers", "a.toml"]).is_err(), "--apply without --expect");
        assert!(parse(&["--apply", "--expect", "v"]).is_err(), "--apply without --answers");
        assert!(parse(&["--dry-run", "--expect", "v"]).is_err(), "--expect is an apply input");
        assert!(
            parse(&["--apply", "--answers", "a.toml", "--expect", "v", "--garden", "/tmp/copy"]).is_err(),
            "--garden is a dry-run input; the apply reads keeperd's garden"
        );
        assert!(parse(&["--dry-run", "--garden", "/tmp/copy"]).unwrap().garden.is_some());
        assert!(
            parse(&["--apply", "--answers", "a.toml", "--expect", "v", "--stack-answers", "o.toml"]).is_err(),
            "--stack-answers never rides an apply"
        );
        assert!(parse(&["--stack-answers", "o.toml"]).is_err(), "--stack-answers needs --dry-run");
        assert!(parse(&["--dry-run", "--stack-answers", "o.toml"]).unwrap().stack_answers.is_some());
        let dry = parse(&["--dry-run", "--answers", "a.toml"]).unwrap();
        assert!(dry.dry_run && !dry.apply);
        let apply = parse(&["--apply", "--answers", "a.toml", "--expect", "v1"]).unwrap();
        assert!(apply.apply && !apply.dry_run);
        assert_eq!(apply.expect.as_deref(), Some("v1"));
    }

    /// The §3.6 copy after `--apply`: the bytes the plan saw land at
    /// `entries/<id>/baton.md`; an existing target is skipped, never
    /// overwritten; the source is never touched; an id that is not one path
    /// component, or a `from` that was never sent, is refused.
    #[test]
    fn migrated_baton_copy_never_overwrites_and_never_moves() {
        let runtime = tempfile::tempdir().unwrap();
        let entries = runtime.path().join("entries");
        fs::create_dir_all(runtime.path().join("agents/a")).unwrap();
        let source = runtime.path().join("agents/a/baton.md");
        fs::write(&source, "on disk\n").unwrap();
        let sent: std::collections::BTreeMap<String, String> =
            [("agents/a/baton.md".to_string(), "sent\n".to_string())].into();
        let mv = |entry: &str, from: &str| migrate::BatonMove { from: from.into(), entry: entry.into() };

        let first = copy_migrated_baton(&entries, &sent, &mv("001", "agents/a/baton.md")).unwrap();
        assert_eq!(first, BatonCopy::Copied);
        assert_eq!(fs::read_to_string(entries.join("001/baton.md")).unwrap(), "sent\n");

        fs::create_dir_all(entries.join("002")).unwrap();
        fs::write(entries.join("002/baton.md"), "existing\n").unwrap();
        let skip = copy_migrated_baton(&entries, &sent, &mv("002", "agents/a/baton.md")).unwrap();
        assert_eq!(skip, BatonCopy::TargetExists);
        assert_eq!(fs::read_to_string(entries.join("002/baton.md")).unwrap(), "existing\n");
        // A re-run is a skip too, not a second write.
        let again = copy_migrated_baton(&entries, &sent, &mv("001", "agents/a/baton.md")).unwrap();
        assert_eq!(again, BatonCopy::TargetExists);

        assert_eq!(fs::read_to_string(&source).unwrap(), "on disk\n", "the source stays put");
        for bad in ["../x", "a/b", "", ".", "/abs"] {
            assert!(copy_migrated_baton(&entries, &sent, &mv(bad, "agents/a/baton.md")).is_err(), "{bad:?}");
        }
        assert!(copy_migrated_baton(&entries, &sent, &mv("003", "baton.md")).is_err(), "never sent");
        assert!(!entries.join("003").exists());
    }

    /// A copy that fails after the commit (queue-v2-migrate-fixes F11) is an
    /// error, not a printed line: the others still run, and the report ends
    /// with the exact command that finishes the failed one.
    #[test]
    fn a_failed_baton_copy_errors_and_prints_its_recovery() {
        let runtime = tempfile::tempdir().unwrap();
        let entries = runtime.path().join("entries");
        fs::create_dir_all(&entries).unwrap();
        // `entries/002` is a file, so its directory can't be made.
        fs::write(entries.join("002"), "in the way\n").unwrap();
        let sent: std::collections::BTreeMap<String, String> = [
            ("agents/a/baton.md".to_string(), "a\n".to_string()),
            ("agents/b/baton.md".to_string(), "b\n".to_string()),
        ]
        .into();
        let moves = [
            migrate::BatonMove { from: "agents/a/baton.md".into(), entry: "001".into() },
            migrate::BatonMove { from: "agents/b/baton.md".into(), entry: "002".into() },
        ];
        let mut lines = Vec::new();
        let err = copy_migrated_batons(runtime.path(), &sent, &moves, |l| lines.push(l)).unwrap_err();
        assert_eq!(err.to_string(), "1 of 2 baton copies failed");
        assert_eq!(fs::read_to_string(entries.join("001/baton.md")).unwrap(), "a\n", "the good copy ran");
        assert_eq!(lines[0], "  agents/a/baton.md -> entries/001/baton.md: copied");
        assert!(lines[1].starts_with("  agents/b/baton.md -> entries/002/baton.md: FAILED, "), "{lines:?}");
        let rt = runtime.path().display();
        assert_eq!(
            lines.last().unwrap(),
            &format!("  mkdir -p '{rt}/entries/002' && cp -n '{rt}/agents/b/baton.md' '{rt}/entries/002/baton.md'")
        );
        // Nothing failed: Ok, and no recovery block.
        let mut quiet = Vec::new();
        copy_migrated_batons(runtime.path(), &sent, &moves[..1], |l| quiet.push(l)).unwrap();
        assert_eq!(quiet, ["  agents/a/baton.md -> entries/001/baton.md: skipped, target exists"]);
    }

    /// `queue migrate --dry-run` (queue-v2-migrate slice 004): the snapshot
    /// takes the backlog's `.md` files and the root + member batons only, and
    /// the rendering carries the version, the counts, every call with its
    /// evidence and proposal, every refusal, and the open-call line last.
    #[test]
    fn migrate_dry_run_snapshot_and_rendering() {
        let garden = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let backlog = garden.path().join("growlight/backlog");
        fs::create_dir_all(backlog.join("tasks")).unwrap();
        let doc = "# backlog\n\n<!-- softfig:queue -->\n\n| # | id | type | title | status |\n\
                   |---|----|------|-------|--------|\n| 1 | 001 | task | First | queued |\n\n\
                   <!-- /softfig:queue -->\n\n<!-- softfig:queue:ghost -->\n<!-- /softfig:queue:ghost -->\n";
        fs::write(backlog.join("CLAUDE.md"), doc).unwrap();
        let task = "# First\n\n## Branch policy\n\nOff `main`.\n\nSecond paragraph.\n";
        fs::write(backlog.join("tasks/001-first.md"), task).unwrap();
        fs::write(backlog.join("tasks/.seq"), "1\n").unwrap();
        fs::create_dir_all(runtime.path().join("agents/a")).unwrap();
        let head = "---\nstatus: IN_PROGRESS\nitem: 001\n---\n";
        fs::write(runtime.path().join("agents/a/baton.md"), head).unwrap();
        fs::write(runtime.path().join("baton.x.parked.md"), head).unwrap();

        let files = migrate_snapshot(garden.path(), runtime.path()).unwrap();
        let keys: Vec<_> = files.garden.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["growlight/backlog/CLAUDE.md", "growlight/backlog/tasks/001-first.md"]);
        let batons: Vec<_> = files.batons.keys().map(String::as_str).collect();
        assert_eq!(batons, vec!["agents/a/baton.md"]);

        let answers = migrate::Answers {
            schema: migrate::ANSWERS_SCHEMA_VERSION,
            class: Default::default(),
            call: [("project_main:softfig".to_string(), "main".to_string())].into(),
        };
        let legacy = migrate::read_legacy(&files).unwrap();
        let plan = migrate::plan(&legacy, &answers, "2026-11-01T00:00:00Z");
        let out = render_migrate_dry_run(&plan, "v123");

        assert!(out.starts_with("queue migrate --dry-run — nothing written\nsnapshot version: v123\n"));
        assert!(out.contains("plan: 1 projects, 1 entries, 0 archived, 0 slices files, 1 baton copies\n"));
        assert!(out.contains("  001 task softfig normal "), "{out}");
        assert!(out.contains("  agents/a/baton.md -> entries/001/baton.md\n"), "{out}");
        assert!(out.contains("  [settled] project_main:softfig = main\n"), "{out}");
        assert!(out.contains("  [open] project_repo:softfig\n      evidence: "), "{out}");
        assert!(out.contains("\n      proposed: "), "{out}");
        assert!(out.contains("refusals: 1\n  queue:ghost: "), "{out}");
        // Multi-line policy prose quoted as evidence hangs under its call
        // instead of spilling into the list (the live dry run's 71 stray lines).
        assert!(out.contains("Off `main`.\n\n                Second paragraph.\n      proposed: "), "{out}");
        let calls = &out[out.find("\njudgment calls:").unwrap() + 1..out.find("\nrefusals:").unwrap()];
        for line in calls.lines().skip(1).filter(|l| !l.is_empty()) {
            assert!(line.starts_with("  "), "unindented line in the call list: {line:?}\n{out}");
        }
        let open = plan.open_calls().count();
        assert!(open > 0);
        let last = if open == 1 { "1 call needs you\n".to_string() } else { format!("{open} calls need you\n") };
        assert!(out.ends_with(&format!("1 refusal blocks the apply\n{last}")), "{out}");
    }

    /// `queue migrate --stack-answers` (queue-v2-migrate-fixes slice 006): git
    /// answers each open `stack_base` call. A live stacked branch gets its
    /// merge-base with the parent's branch, a live branch off `main` its
    /// merge-base with `main`, a merged or gone branch the explicit unknown
    /// base. Fed back as answers, no `stack_base` call stays open.
    #[test]
    fn stack_answers_come_from_git_and_settle_every_stack_base_call() {
        use softfig_ipc::testing::git;
        let repo = tempfile::tempdir().unwrap();
        let r = repo.path();
        let commit = |msg: &str| {
            fs::write(r.join("f.txt"), msg).unwrap();
            git(r, &["add", "."]);
            git(r, &["commit", "-q", "-m", msg]);
        };
        let head = || {
            let out = std::process::Command::new("git").arg("-C").arg(r).args(["rev-parse", "HEAD"]).output().unwrap();
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        git(r, &["init", "-q", "-b", "main"]);
        commit("c0");
        let c0 = head();
        git(r, &["checkout", "-q", "-b", "fix/002"]);
        commit("parent");
        let parent_tip = head();
        git(r, &["checkout", "-q", "-b", "fix/001"]);
        commit("child");
        git(r, &["checkout", "-q", "fix/002"]);
        commit("parent moves on");
        git(r, &["checkout", "-q", "-b", "fix/003", "main"]);
        commit("merged");
        git(r, &["checkout", "-q", "main"]);
        git(r, &["merge", "-q", "--no-ff", "-m", "merge 003", "fix/003"]);
        // fix/004 was never cut (or was deleted after its merge).

        let garden = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let backlog = garden.path().join("growlight/backlog");
        fs::create_dir_all(backlog.join("tasks")).unwrap();
        let doc = "# backlog\n\n<!-- softfig:queue -->\n\n| # | id | type | title | status |\n\
                   |---|----|------|-------|--------|\n| 1 | 001 | task | Child | active |\n\
                   | 2 | 002 | task | Parent | blocked |\n| 3 | 003 | task | Merged | blocked |\n\
                   | 4 | 004 | task | Gone | blocked |\n| 5 | 005 | task | Unsettled | blocked |\n\n\
                   <!-- /softfig:queue -->\n";
        fs::write(backlog.join("CLAUDE.md"), doc).unwrap();
        let tasks = [
            ("001-child", "Branch `fix/001`, stacked on `fix/002`."),
            ("002-parent", "Branch `fix/002` off `main`."),
            ("003-merged", "Branch `fix/003` off `main`."),
            ("004-gone", "Branch `fix/004` off `main`."),
            ("005-unsettled", "Branch `fix/005` or `fix/005-b`."),
        ];
        for (name, policy) in tasks {
            fs::write(backlog.join(format!("tasks/{name}.md")), format!("# t\n\n## Branch policy\n\n{policy}\n")).unwrap();
        }
        let mut answers = migrate::Answers {
            schema: migrate::ANSWERS_SCHEMA_VERSION,
            class: Default::default(),
            call: [
                ("project_main:softfig".to_string(), "main".to_string()),
                ("project_repo:softfig".to_string(), r.display().to_string()),
            ]
            .into(),
        };
        let files = migrate_snapshot(garden.path(), runtime.path()).unwrap();
        let legacy = migrate::read_legacy(&files).unwrap();
        let plan = migrate::plan(&legacy, &answers, "2026-11-01T00:00:00Z");
        let questions = migrate::stack_base_questions(&plan);
        assert_eq!(questions.iter().map(|q| q.id.as_str()).collect::<Vec<_>>(), ["001", "002", "003", "004", "005"]);
        assert_eq!(questions[0].parent, Some(("002".to_string(), "fix/002".to_string())));

        let lines: Vec<_> =
            questions.iter().map(|q| (q.id.clone(), stack_base_from_git(q, None, None))).collect();
        let answer = |id: &str| lines.iter().find(|(i, _)| i == id).map(|(_, a)| a.clone()).unwrap();
        assert!(
            matches!(answer("001"), StackAnswer::Known { parent, base, .. } if parent == "002" && base == parent_tip),
            "the parent's tip the child was cut from, not the parent's moved tip: {:?}",
            answer("001")
        );
        assert!(matches!(answer("002"), StackAnswer::Known { parent, base, .. } if parent.is_empty() && base == c0));
        assert!(matches!(answer("003"), StackAnswer::Unknown { why, .. } if why.contains("merged")), "{:?}", answer("003"));
        assert!(matches!(answer("004"), StackAnswer::Unknown { why, .. } if why.contains("gone")), "{:?}", answer("004"));
        // 005's branch is an open `branch` call: a missing proposal is no verdict.
        assert!(matches!(answer("005"), StackAnswer::Open { why } if why.contains("branch:005")), "{:?}", answer("005"));

        let text = render_stack_answers(&lines, "v1");
        assert!(text.contains(&format!("\"stack_base:001\" = \"parent=002 base={parent_tip}\"\n")), "{text}");
        assert!(text.contains("\"stack_base:004\" = \"parent= base=\"\n"), "{text}");
        let generated: migrate::Answers = toml::from_str(&text).unwrap();
        answers.call.extend(generated.call);
        let settled = migrate::plan(&legacy, &answers, "2026-11-01T00:00:00Z");
        assert!(settled.refusals.is_empty(), "{:?}", settled.refusals);
        let open: Vec<_> = settled
            .open_calls()
            .filter(|c| c.key.class == migrate::CallClass::StackBase)
            .map(|c| c.key.subject.as_str())
            .collect();
        assert_eq!(open, ["005"], "only the call git left open");
        let child = settled.queue.entries.iter().find(|e| e.id == "001").unwrap();
        assert_eq!((child.parent.as_str(), child.base.as_str()), ("002", parent_tip.as_str()));
    }

    /// A repo git can't read here leaves its call open with the reason, and the
    /// rendered line is commented out, so feeding the file back keeps it open.
    #[test]
    fn stack_answers_leave_a_remote_or_unreadable_repo_open() {
        let q = |repo: &str| migrate::StackBaseQuestion {
            id: "x".into(),
            branch: "fix/x".into(),
            branch_open: false,
            repo: repo.into(),
            main: "main".into(),
            parent: None,
            stray_parent: None,
        };
        let remote = stack_base_from_git(&q("build-host:/srv/repo"), None, Some("u"));
        assert!(matches!(&remote, StackAnswer::Open { why } if why.contains("another machine")), "{remote:?}");
        let other_user = stack_base_from_git(&q("~someone/repo"), Some(Path::new("/home/u")), Some("u"));
        assert!(matches!(&other_user, StackAnswer::Open { why } if why.contains("not a local path")), "{other_user:?}");
        let not_a_repo = tempfile::tempdir().unwrap();
        let unreadable = stack_base_from_git(&q(&not_a_repo.path().display().to_string()), None, None);
        assert!(matches!(&unreadable, StackAnswer::Open { .. }), "{unreadable:?}");
        assert!(matches!(&unreadable, StackAnswer::Open { why } if why.starts_with("git can't read the repo")));
        let unsettled = stack_base_from_git(&q(""), None, None);
        assert!(matches!(&unsettled, StackAnswer::Open { why } if why.contains("project_repo")), "{unsettled:?}");
        let stray = migrate::StackBaseQuestion { stray_parent: Some("ghost".into()), ..q("/r") };
        assert!(matches!(stack_base_from_git(&stray, None, None), StackAnswer::Open { why } if why.contains("ghost")));

        let text = render_stack_answers(&[("x".to_string(), remote)], "v1");
        assert!(text.contains("# left open: repo `build-host:/srv/repo` is on another machine"), "{text}");
        let parsed: migrate::Answers = toml::from_str(&text).unwrap();
        assert!(parsed.call.is_empty(), "an open call writes no live line: {text}");
    }
}
