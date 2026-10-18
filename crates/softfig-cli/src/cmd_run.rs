//! `softfig run …` — the requester surface of the remote runner (spec §9).
//!
//! Explicit, not transparent (decided): the caller names `softfig run`, so
//! every gate line says where the job ran. Exit codes follow §9 exactly — the
//! job's own code on success, **254** for runner-side failures (with the
//! reason printed), and local fallback only on the §9 triggers.
//!
//! This chunk wires config load + resolve + local fallback + exit codes. The
//! remote execution path (snapshot → signed offer → `connect_runner` →
//! `run_job`) and the keeperd `runner_sign_offer` verb land in the next
//! slice-007 chunk, along with the keeperd job table that backs
//! `ls`/`show`/`logs`/`attach`/`cancel`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand, ValueEnum};
use softfig_ipc::{
    runtime_socket_path,
    verbs::{op, ReadFileArgs, ReadFileReply},
    Request,
};
use softfig_net::{
    fallback_action, outcome_exit_code, Fallback, FallbackAction, ResolvedRun, RunFailure,
    RunnerConfig,
};

/// The per-call `--fallback` override (mirrors `[use] fallback`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum FallbackArg {
    Local,
    Wait,
    Fail,
}

impl From<FallbackArg> for Fallback {
    fn from(f: FallbackArg) -> Self {
        match f {
            FallbackArg::Local => Fallback::Local,
            FallbackArg::Wait => Fallback::Wait,
            FallbackArg::Fail => Fallback::Fail,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum RunCmd {
    /// Run a job on a runner, falling back locally per spec §9.
    Run(RunArgs),
    /// List recent jobs (needs the keeperd job table — a later chunk).
    Ls,
    /// Show one job's result (needs the keeperd job table).
    Show(JobArgs),
    /// Print a job's log (needs the keeperd job table).
    Logs(LogsArgs),
    /// Re-attach to a detached job (needs the keeperd job table).
    Attach(JobArgs),
    /// Cancel a running job (needs the keeperd job table).
    Cancel(JobArgs),
    /// Fetch a job's artifact (parked on report #057).
    Fetch(FetchArgs),
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Run on this runner peer (ring name or device-id fingerprint).
    #[arg(long)]
    on: Option<String>,
    /// Use this named profile from the matched `[[project]]`.
    #[arg(long)]
    profile: Option<String>,
    /// Override `[use] fallback` for this call.
    #[arg(long, value_enum)]
    fallback: Option<FallbackArg>,
    /// Detach and resume later (needs the keeperd job table — later chunk).
    #[arg(long)]
    detach: bool,
    /// Artifact glob to fetch after the job (parked on report #057).
    #[arg(long)]
    fetch: Vec<String>,
    /// The ad-hoc command to run (`softfig run -- <cmd…>`).
    #[arg(last = true)]
    cmd: Vec<String>,
    /// The keeperd socket path.
    #[arg(long)]
    daemon_socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct JobArgs {
    /// The job id to inspect.
    job: String,
    /// Show the signed attestation (with `show`).
    #[arg(long)]
    attestation: bool,
}

#[derive(Args, Debug)]
pub struct LogsArgs {
    /// The job id whose log to print.
    job: String,
    /// Follow the log live.
    #[arg(short = 'f', long)]
    follow: bool,
}

#[derive(Args, Debug)]
pub struct FetchArgs {
    /// The job id whose artifact to fetch.
    job: String,
    /// The artifact path within the job.
    path: String,
    /// Write the artifact here instead of next to cwd.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

pub fn run(cmd: RunCmd) -> Result<()> {
    match cmd {
        RunCmd::Run(args) => run_job(args),
        RunCmd::Ls
        | RunCmd::Show(_)
        | RunCmd::Logs(_)
        | RunCmd::Attach(_)
        | RunCmd::Cancel(_) => Err(anyhow!(
            "job history (ls/show/logs/attach/cancel) needs the keeperd job table — a later slice-007 chunk"
        )),
        RunCmd::Fetch(_) => Err(anyhow!(
            "artifact fetch is parked on report #057 (the artifact glob base)"
        )),
    }
}

fn daemon_socket(explicit: &Option<PathBuf>) -> PathBuf {
    explicit.clone().unwrap_or_else(runtime_socket_path)
}

/// Call keeperd, surfacing an absent daemon as a clear error.
fn daemon_call(socket: &Path, op: &str, args: serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = softfig_ipc::connect(socket).map_err(|e| {
        if e.is_daemon_absent() {
            anyhow!("daemon not running — start it and unlock the vault first")
        } else {
            anyhow!("{e}")
        }
    })?;
    let resp = softfig_ipc::call(&mut stream, &Request::new(op, args))?;
    match resp.into_result() {
        Ok(v) => Ok(v),
        Err((kind, message)) => Err(anyhow!("{message}").context(format!("daemon error ({kind:?})"))),
    }
}

/// Read + parse the garden's `config/runner.toml` `[use]`/`[[project]]` tables
/// through keeperd (works in FUSE and Disk modes alike), rejecting bad config.
fn load_config(socket: &Path) -> Result<RunnerConfig> {
    let read: ReadFileReply = serde_json::from_value(daemon_call(
        socket,
        op::READ_FILE,
        serde_json::to_value(ReadFileArgs {
            path: "config/runner.toml".to_string(),
        })?,
    )?)?;
    if read.sealed {
        return Err(anyhow!("config/runner.toml is sealed; cannot read the requester tables"));
    }
    RunnerConfig::parse(&read.content).map_err(|e| anyhow!("config/runner.toml: {e}"))
}

fn run_job(args: RunArgs) -> Result<()> {
    if args.detach {
        return Err(anyhow!(
            "--detach needs the keeperd job table — a later slice-007 chunk"
        ));
    }
    if !args.fetch.is_empty() {
        return Err(anyhow!(
            "--fetch is parked on report #057 (the artifact glob base)"
        ));
    }
    let socket = daemon_socket(&args.daemon_socket);
    let config = load_config(&socket)?;

    let cwd = std::env::current_dir().map_err(|e| anyhow!("cwd: {e}"))?;
    let ad_hoc = if args.cmd.is_empty() {
        None
    } else {
        Some(args.cmd.clone())
    };
    let resolved = config.resolve(&cwd, args.profile.as_deref(), ad_hoc)?;

    let cli_fallback = args.fallback.map(Fallback::from);

    match attempt_runner(&resolved, args.on.as_deref()) {
        Ok(outcome) => {
            // A real runner result — exit with the job's own code (or 254 on a
            // reject). `attempt_runner` returns a reject as `Ok(Rejected(..))`,
            // so `outcome_exit_code` yields 254 here, not a fallback.
            std::process::exit(outcome_exit_code(&outcome));
        }
        Err(failure) => match fallback_action(config.use_.fallback, cli_fallback, &failure) {
            Some(FallbackAction::RunLocal) => run_local(&resolved, &failure),
            Some(FallbackAction::Wait) => {
                // `wait` retries until `wait_timeout`; the retry loop lands
                // with the remote execution path (next chunk). For now it is
                // indistinguishable from `fail` here — see the slice doc.
                eprintln!("runner: {}", failure.reason());
                eprintln!("fallback = wait is pending the remote execution path");
                std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
            }
            Some(FallbackAction::Fail) => {
                eprintln!("runner: {}", failure.reason());
                std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
            }
            None => {
                // Not a fallback trigger — a permanent runner-side failure.
                eprintln!("runner: {}", failure.reason());
                std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
            }
        },
    }
}

/// Attempt the remote runner path. This chunk returns `NoRunner` until the
/// remote execution (snapshot → signed offer → `connect_runner` → `run_job`)
/// lands in the next slice-007 chunk; the decision function is already the
/// tested [`fallback_action`]/[`outcome_exit_code`].
fn attempt_runner(_resolved: &ResolvedRun, _on: Option<&str>) -> std::result::Result<softfig_net::JobOutcome, RunFailure> {
    // TODO(slice-007 chunk 2): snapshot the repo, build the offer, sign it via
    // the keeperd `runner_sign_offer` verb, discover the runner endpoint
    // (mDNS `_softfig-runner._tcp` — manual smoke), connect, and `run_job`.
    Err(RunFailure::NoRunner)
}

/// Run the resolved command locally in the repo (spec §9 local fallback): not
/// sandboxed (same as running locally today), and it propagates the command's
/// own exit code. Never returns.
fn run_local(resolved: &ResolvedRun, reason: &RunFailure) -> ! {
    eprintln!("ran LOCALLY: {}", reason.reason());
    let (program, rest) = resolved.cmd.split_first().expect("resolved cmd is non-empty");
    let status = Command::new(program)
        .args(rest)
        .envs(&resolved.env)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("failed to run {program:?}: {e}");
            std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
        });
    std::process::exit(status.code().unwrap_or(1));
}
