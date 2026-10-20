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
    growlightd::{
        self, AgentDeltaKind, BuildCapsSummary, Event, FleetStatusReply, ForceStopArgs,
        PausedReply, ResumeItemArgs, ResumeItemReply, SetResourcesArgs, SetResourcesReply,
        StopLevel, StopReply,
    },
    queue_v2::{Entry, EntryKind, Lane as QueueLane, QueueToml, SliceStatus, QUEUE_FILE},
    verbs::{
        GrowlightInitArgs, GrowlightInitReply, ListReportsArgs, ListReportsReply, PostMessageArgs,
        PostMessageReply, QueueAddEntryReply, QueueAddProjectReply, QueueDropReply, QueueMoveSpec,
        QueueStatusArg, QueueUpdateEntryReply, ReadFileArgs, ReadFileReply, ReportRow,
        SliceInsertReply, SliceUpdateReply, StatusReply, op,
    },
};

use softfig_growlightd_client::{decode_frame, Frame};

use crate::cmd_daemon::try_daemon_call;
use crate::growlight_backend::{
    Backend, DEEPSEEK_FLASH, DEEPSEEK_REASONING, InteractiveLaunch, ModelChoice, ModelSpec,
    OpencodeConfigInputs, agent_bin, interactive_command, item_doc_candidates, opencode_config,
    opencode_context, opencode_interactive_args, parse_model_spec, resolve_item_models,
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
    /// `project add`, `add`, `move`, `lane`, `after`, `status`, `drop`. Each is
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
    /// `claude` | `reasoning` | `flash` | `auto` | `provider/model`, with an
    /// optional ` variant=<v>` (alias ` effort=<v>`) tail for opencode.
    /// `auto` = "let growlight decide": use the model the active backlog item
    /// declares in its `> Model:` line, defaulting to deepseek flash.
    #[arg(long, conflicts_with_all = ["backend", "opencode"])]
    pub model: Option<String>,
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

    // Task 064: surface a repo left dirty AND newer than the baton's last handoff
    // (report 001's cut-off signature) BEFORE anything is launched. The baton is
    // seeded by now, so its mtime is the prior handoff — or the just-now seed,
    // against which a stale tree reads as NOT newer and stays silent. Read-only
    // and best-effort; a failed probe never blocks a launch.
    if let Some(line) = boot_dirty_check(&garden_root, &baton_path) {
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
    };

    if args.no_launch {
        println!("\n{}", no_launch_hint(&choice, &launch));
        return Ok(());
    }
    launch_agent(&choice, &launch)
}

/// Task 064 — the semi-auto/CLI half of the boot-time dirty-tree guard: at
/// `start`, resolve the root baton's active item repo (the item doc's
/// `> Worktree:` line — the `default` queue the semi-auto loop runs on has no
/// `## Queues` registry row, so there is no registry fallback) and, when the
/// repo is dirty AND newer than the baton's last handoff, return the same
/// journal line growlightd prints before a member spawn, so the human launching
/// the loop sees it before the agent does new work. Read-only: it only ever
/// *surfaces* the answer, never reverts, stages or commits. Best-effort — a
/// missing item, an unprobeable repo or a `git` failure is `None`, never a
/// launch failure.
fn boot_dirty_check(garden_root: &Path, baton_path: &Path) -> Option<String> {
    let view = parse_baton(&fs::read_to_string(baton_path).ok()?);
    let item = view.item.as_deref()?;
    let worktree = item_doc_candidates(garden_root, item, view.slice.as_deref())
        .into_iter()
        .find_map(|doc| {
            let content = fs::read_to_string(&doc).ok()?;
            softfig_ipc::item_repo::worktree_field(&content).map(str::to_string)
        });
    let repo = softfig_ipc::item_repo::resolve_repo(
        worktree.as_deref(),
        None,
        home_dir().ok().as_deref(),
    )?;
    let state = softfig_ipc::item_repo::probe(&repo).ok()?;
    let baton_mtime = fs::metadata(baton_path).and_then(|md| md.modified()).ok()?;
    if !softfig_ipc::item_repo::dirty_newer_than(&state, baton_mtime) {
        return None;
    }
    let dirty = state.dirty;
    Some(
        match state
            .newest_dirty_mtime
            .and_then(|m| m.duration_since(baton_mtime).ok())
        {
            Some(newer_by) => format!(
                "growlight: boot dirty tree: {item}: {} has {dirty} uncommitted path(s), newest ~{}s newer than the baton handoff",
                repo.display(),
                newer_by.as_secs(),
            ),
            None => format!(
                "growlight: boot dirty tree: {item}: {} has {dirty} uncommitted path(s), newest newer than the baton handoff",
                repo.display(),
            ),
        },
    )
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
        Backend::Claude => format!(
            "(--no-launch) runtime ready. launch with:\n  cd {garden} && {AGENT_BIN} \
             --name {AGENT_NAME} --settings {} --mcp-config {}",
            launch.loop_settings.display(),
            launch.mcp_config.display(),
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
        prompt_for_model()?
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

/// The interactive picker (spec: the confirmed `1/2/3/4` UX). Reads one line from
/// stdin; a bare Enter takes option 1, and EOF (stdin closed mid-run) falls back
/// to the same default rather than erroring out of a launch the human asked for.
fn prompt_for_model() -> Result<ModelSpec> {
    println!("\nbackend + model:");
    println!("  1) claude                (default)");
    println!("  2) deepseek reasoning    ({DEEPSEEK_REASONING})");
    println!("  3) deepseek flash        ({DEEPSEEK_FLASH})");
    println!("  4) let growlight decide  (the active backlog item's `> Model:`, else flash)");
    print!("choice [1]: ");
    // The prompt has no newline, so it sits in the line buffer until flushed.
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let mut line = String::new();
    if stdin().read_line(&mut line).unwrap_or(0) == 0 {
        println!();
    }
    Ok(match line.trim() {
        "" | "1" => ModelSpec::Fixed(ModelChoice::claude()),
        "2" => ModelSpec::Fixed(ModelChoice::opencode(DEEPSEEK_REASONING)),
        "3" => ModelSpec::Fixed(ModelChoice::opencode(DEEPSEEK_FLASH)),
        "4" => ModelSpec::Auto,
        // A typo shouldn't silently run the wrong (possibly pricier) model.
        other => bail!("unknown choice `{other}` — pick 1, 2, 3, or 4"),
    })
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

    let docs = item_doc_candidates(garden_root, item, view.slice.as_deref())
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

fn launch_agent(choice: &ModelChoice, launch: &InteractiveLaunch) -> Result<()> {
    // The interactive argv/env/cwd is owned by the backend seam; for `claude`
    // this is the original hardwired argv rooted at the garden, and for
    // `opencode` it wires `OPENCODE_CONFIG` + the runtime cwd + the first-turn
    // kick (slice 003).
    let backend = choice.backend;
    let mut cmd = interactive_command(backend, launch)?;
    let bin = agent_bin(backend);
    match backend {
        Backend::Claude => println!("\nlaunching {bin} --name {AGENT_NAME} …\n"),
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
/// token (`.credentials.json`) and harness settings stay out of the loop's
/// reach.
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
    // The live per-agent runtime state — one row per member of an ARMED fleet
    // (empty while disarmed, when `roster` above is the whole truth).
    if r.agents.is_empty() {
        println!("agents        (none)");
    } else {
        println!("agents:");
        for a in &r.agents {
            println!("  {:<16} {:<12} {}", a.id, a.status, agent_accounting(a));
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
    format!(
        "build caps    (live default — the next spawn's throttle)\n  \
         cargo_build_jobs  {jobs}\n  memory_high       {mem}\n  cpu_weight        {weight}\n",
    )
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
    #[command(subcommand)]
    pub cmd: Option<QueueSub>,
}

#[derive(Subcommand, Debug)]
pub enum QueueSub {
    /// (default) show the live v2 list from `queue.toml` — both lanes, one row
    /// per entry in file order: id, kind, title, project, lane, status, the
    /// `after` links, and the stack columns (branch/base/claimed) verbatim
    /// from the TOML. TOML state only — the live git-stack annotations
    /// (merge-base / restack flags) are queue-v2-git's (finding 3).
    Show,

    /// Read-only: what `pick_v2` assigns a member now, and why every skipped
    /// entry was skipped (§6.9). This form is **growlightd's** verb (the pick
    /// lives there, not in keeperd), so it takes its own socket flag.
    Pick {
        /// A roster member id. Omitted: an unpinned member on the default
        /// backend.
        #[arg(long)]
        member: Option<String>,
        /// growlightd's socket. Defaults to
        /// `$XDG_RUNTIME_DIR/softfig-growlightd.sock`.
        #[arg(long, value_name = "SOCKET")]
        growlightd_socket: Option<PathBuf>,
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

    /// Drop an entry — its row moves to `queue-archive.toml` as `dropped`.
    Drop(QueueDropArgs),
}

#[derive(Subcommand, Debug)]
pub enum QueueProjectSub {
    /// Append a `[[project]]` row: a name bound to a repo and its merge branch.
    Add(QueueProjectAddArgs),
}

#[derive(Args, Debug)]
pub struct QueueProjectAddArgs {
    /// `[a-z0-9-]+` — the project name entries reference.
    pub name: String,
    /// A local path (`~` allowed) or `host:path`.
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
    match args.cmd.unwrap_or(QueueSub::Show) {
        QueueSub::Show => queue_show(&socket),
        QueueSub::Pick {
            member,
            growlightd_socket,
        } => queue_pick(&growlight_socket(growlightd_socket), member.as_deref()),
        QueueSub::Project { cmd } => match cmd {
            QueueProjectSub::Add(a) => queue_project_add(&socket, a),
        },
        QueueSub::Add(a) => queue_add(&socket, a),
        QueueSub::Move(a) => queue_move(&socket, a),
        QueueSub::Lane(a) => queue_lane(&socket, a),
        QueueSub::After(a) => queue_after(&socket, a),
        QueueSub::Status(a) => queue_status(&socket, a),
        QueueSub::Drop(a) => queue_drop(&socket, a),
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

fn queue_show(socket: &Path) -> Result<()> {
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
/// live git-stack annotations (merge-base / restack flags) are queue-v2-git's
/// (finding 3). Same cell rules as the §3.4 derived view (literal `|` escaped,
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
        out.push_str(&format!(
            "\n| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            i + 1,
            cell(&e.id),
            cell(&e.kind.to_string()),
            cell(&e.title),
            cell(&e.project),
            cell(&e.lane.to_string()),
            cell(&e.status.to_string()),
            cell(&after),
            cell(&e.branch),
            cell(&e.base),
            cell(&e.claimed),
        ));
    }
    out.push('\n');
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
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
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
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
    Ok(())
}

fn queue_after(socket: &Path, args: QueueAfterArgs) -> Result<()> {
    let wire = softfig_ipc::verbs::QueueUpdateEntryArgs {
        id: args.id,
        lane: None,
        move_spec: None,
        after: Some(args.ids),
        status: None,
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
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
        dry_run: args.dry_run,
    };
    let value = queue_call(socket, op::QUEUE_UPDATE_ENTRY, serde_json::to_value(wire)?)?;
    let reply: QueueUpdateEntryReply = serde_json::from_value(value)?;
    print_verb_reply(args.dry_run, &reply.view, &reply.hash);
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
            roster: Vec::new(),
            agents: Vec::new(),
            live_scopes: live,
            held: Vec::new(),
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
        };

        for choice in [
            ModelChoice::claude(),
            ModelChoice::opencode(DEEPSEEK_FLASH),
        ] {
            let hint = no_launch_hint(&choice, &launch);
            let cwd = interactive_command(choice.backend, &launch)
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
        let spawned: Vec<String> = interactive_command(Backend::Opencode, &launch)
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
        assert!(boot_dirty_check(&root, &baton).is_none());

        // A baton naming the item, backdated before the tree's last edit.
        fs::write(&baton, "---\nstatus: IN_PROGRESS\nitem: 200\n---\n").unwrap();
        backdate_mtime(&baton);
        // Clean tree -> no signal.
        assert!(boot_dirty_check(&root, &baton).is_none());

        // Leave one uncommitted edit, newer than the (backdated) baton.
        fs::write(repo.join("a.txt"), "dirty\n").unwrap();
        let line = boot_dirty_check(&root, &baton)
            .expect("a dirty tree newer than the baton handoff surfaces");
        assert!(line.contains("200"), "names the item: {line}");
        assert!(
            line.contains(&repo.display().to_string()),
            "names the repo: {line}"
        );
        assert!(line.contains("1 uncommitted path"), "names the count: {line}");

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
            skips: vec![growlightd::QueuePickSkip {
                entry: "n".into(),
                reason: "blocked_walk".into(),
                detail: "its walk stops at a blocked item, which needs a human (§2)".into(),
            }],
        };
        let out = render_queue_pick(&reply);
        assert!(out.contains("member c (backend claude, pin default)"), "{out}");
        assert!(out.contains("picked: m / slice 002 of m"), "{out}");
        assert!(out.contains("model: reasoning, flash"), "{out}");
        assert!(out.contains("skipped: 1"), "{out}");
        assert!(out.contains("  - n: blocked_walk — its walk stops"), "{out}");
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
            dry_run,
        }
    }

    #[test]
    fn queue_v2_forms_round_trip_against_a_real_keeperd() {
        let (handle, socket, dir) = boot_keeperd("queue-v2-forms");

        // Fresh garden: no queue.toml — `queue show` exits clean with the
        // §3.4 "renders only when the file exists" message.
        queue_show(&socket).unwrap();

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
        queue_show(&socket).unwrap();

        handle.shutdown();
        handle.join().unwrap();
        fs::remove_dir_all(&dir).ok();
    }
}
