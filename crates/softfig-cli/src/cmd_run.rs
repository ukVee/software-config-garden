//! `softfig run …` — the requester surface of the remote runner (spec §9).
//!
//! Explicit, not transparent (decided): the caller names `softfig run`, so
//! every gate line says where the job ran. Exit codes follow §9 exactly — the
//! job's own code on success, **254** for runner-side failures (with the
//! reason printed), and local fallback only on the §9 triggers.
//!
//! The run/attach/cancel orchestration (snapshot → sign → connect → run) lives
//! in [`softfig_run`] and is shared with `softfig-mcp`'s `run_job`/`job_log`/
//! `job_cancel` verbs; this module is the CLI's thin dispatch + exit-code +
//! fallback layer. Runner discovery (mDNS `_softfig-runner._tcp` + relay) is a
//! later chunk / slice-008 manual smoke — today a peer's endpoint comes from
//! its ring entry and `--on host:port` dials a runner directly (the
//! loopback/test form).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand, ValueEnum};
use softfig_ipc::{
    runtime_socket_path,
    verbs::{op, RunnerJobLsReply, RunnerJobShowReply},
};
use softfig_net::{
    fallback_action, is_fallback_trigger, outcome_exit_code, CancelOutcome, Fallback,
    FallbackAction, ResolvedRun, RunFailure,
};
use softfig_run::{
    attach_job, cancel_job, load_config, log_bytes, read_job_log, run_remote_job,
    start_detached_job, AttemptFailure,
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
    /// Run on this runner: `host:port` (direct) or a peer name/fingerprint.
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
        RunCmd::Ls => job_ls(),
        RunCmd::Show(args) => job_show(&args),
        RunCmd::Logs(args) => job_log(&args),
        RunCmd::Attach(args) => job_attach(&args),
        RunCmd::Cancel(args) => job_cancel(&args),
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
    let resp = softfig_ipc::call(&mut stream, &softfig_ipc::Request::new(op, args))?;
    match resp.into_result() {
        Ok(v) => Ok(v),
        Err((kind, message)) => Err(anyhow!("{message}").context(format!("daemon error ({kind:?})"))),
    }
}

fn run_job(args: RunArgs) -> Result<()> {
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

    // Detached (spec §6): start on the runner, record a `running` row, print the
    // job id, and exit 0 — no local fallback (a detached job is remote by
    // definition, so a runner-side failure exits 254).
    if args.detach {
        match start_detached_job(&socket, &cwd, &resolved, &config.use_.peers, args.on.as_deref()) {
            Ok(job_id) => {
                println!("{job_id}");
                return Ok(());
            }
            Err(AttemptFailure::Fatal(e)) => return Err(e),
            Err(AttemptFailure::Runner(f)) => {
                eprintln!("runner: {}", f.reason());
                std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
            }
        }
    }

    let cli_fallback = args.fallback.map(Fallback::from);

    match run_remote_job(&socket, &cwd, &resolved, &config.use_.peers, args.on.as_deref()) {
        Ok(completed) => std::process::exit(outcome_exit_code(&completed.outcome)),
        Err(AttemptFailure::Fatal(e)) => Err(e),
        Err(AttemptFailure::Runner(failure)) => {
            match fallback_action(config.use_.fallback, cli_fallback, &failure) {
                Some(FallbackAction::RunLocal) => run_local(&resolved, &failure),
                Some(FallbackAction::Wait) => wait_and_retry(
                    &socket,
                    &cwd,
                    &resolved,
                    &config.use_.peers,
                    args.on.as_deref(),
                    &config.use_.wait_timeout,
                    &failure,
                ),
                Some(FallbackAction::Fail) => {
                    eprintln!("runner: {}", failure.reason());
                    std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
                }
                None => {
                    eprintln!("runner: {}", failure.reason());
                    std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
                }
            }
        }
    }
}

/// `softfig run ls` — list the bounded job table (newest first).
fn job_ls() -> Result<()> {
    let socket = daemon_socket(&None);
    let reply: RunnerJobLsReply = serde_json::from_value(daemon_call(
        &socket,
        op::RUNNER_JOB_LS,
        serde_json::json!({}),
    )?)?;
    if reply.jobs.is_empty() {
        println!("(no jobs recorded)");
        return Ok(());
    }
    for j in &reply.jobs {
        let id = &j.job_id[..j.job_id.len().min(12)];
        let exit = j
            .exit
            .map(|e| e.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{id}  {:<7}  {:<8}  exit {exit:>3}  {}",
            j.where_,
            j.state,
            j.cmd.join(" ")
        );
    }
    Ok(())
}

/// `softfig run show <job>` — the full row for one job.
fn job_show(args: &JobArgs) -> Result<()> {
    let socket = daemon_socket(&None);
    let reply: RunnerJobShowReply = serde_json::from_value(daemon_call(
        &socket,
        op::RUNNER_JOB_SHOW,
        serde_json::json!({ "job_id": args.job }),
    )?)?;
    println!("job:         {}", reply.job_id);
    println!("requester:   {}", reply.requester_device);
    println!("repo_key:    {}", reply.repo_key);
    println!("source_id:   {}", reply.source_id);
    println!("snapshot:    {}", reply.snapshot_commit);
    println!("profile:     {}", reply.profile);
    println!("cmd:         {}", reply.cmd.join(" "));
    println!("env:         {}", reply.env_names.join(", "));
    println!("toolchain:   {}", reply.toolchain);
    println!("cache:       {}", reply.cache);
    println!("where:       {}", reply.where_);
    println!("state:       {}", reply.state);
    println!("started_at:  {}", reply.started_at);
    if let Some(t) = reply.finished_at {
        println!("finished_at: {t}");
    }
    if let Some(e) = reply.exit {
        println!("exit:        {e}");
    }
    match reply.attestation_hash {
        Some(h) if args.attestation => {
            println!("attestation: {h} (BLAKE3 of the signed attestation)");
        }
        Some(_) => {} // shown only with --attestation
        None if args.attestation => println!("attestation: (none — local run)"),
        None => {}
    }
    println!("log:         {} bytes", reply.log_bytes);
    Ok(())
}

/// `softfig run logs <job>` — the job's log ring, control sequences stripped
/// (spec §6 Logs). Always sanitizes: logs are untrusted bytes.
fn job_log(args: &LogsArgs) -> Result<()> {
    let socket = daemon_socket(&None);
    let bytes = read_job_log(&socket, &args.job)?;
    let mut stdout = std::io::stdout().lock();
    use std::io::Write as _;
    stdout.write_all(&bytes)?;
    if args.follow {
        eprintln!("note: `-f` (live follow) needs the detached-job session — a later slice-007 chunk");
    }
    Ok(())
}

/// `softfig run attach <job>` (spec §6): resume a detached job — replay the
/// retained log tail, record the terminal row, and exit with the job's code.
fn job_attach(args: &JobArgs) -> Result<()> {
    use std::io::Write as _;

    let socket = daemon_socket(&None);
    match attach_job(&socket, &args.job) {
        Ok(completed) => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&log_bytes(&completed.logs))?;
            stdout.flush()?;
            let code = outcome_exit_code(&completed.outcome);
            eprintln!("job {} exit {code}", completed.job_id);
            std::process::exit(code);
        }
        Err(e) => Err(e),
    }
}

/// `softfig run cancel <job>` (spec §6): re-dial and send `JobCancel`; the
/// runner marks the job cancelled and stops its unit. Records a `cancelled` row.
fn job_cancel(args: &JobArgs) -> Result<()> {
    let socket = daemon_socket(&None);
    match cancel_job(&socket, &args.job) {
        Ok(CancelOutcome::Cancelled) => {
            println!("cancelled {}", args.job);
            Ok(())
        }
        Ok(CancelOutcome::Lost) => {
            eprintln!("job {} is no longer held by the runner (expired past the TTL)", args.job);
            std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
        }
        Ok(CancelOutcome::Rejected(reason)) => {
            eprintln!("runner: {}", reason.as_str());
            std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
        }
        Err(e) => Err(e),
    }
}

/// Retry the remote path until `wait_timeout` elapses (`fallback = wait`, spec
/// §9). A non-trigger failure is permanent and stops the retry immediately.
/// Never returns.
fn wait_and_retry(
    socket: &Path,
    cwd: &Path,
    resolved: &ResolvedRun,
    peers: &[String],
    on: Option<&str>,
    wait_timeout: &str,
    first: &RunFailure,
) -> ! {
    eprintln!("runner: {}", first.reason());
    let wait_secs = softfig_net::parse_runner_duration(wait_timeout).unwrap_or(1200);
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    let mut last = first.clone();
    loop {
        if Instant::now() >= deadline {
            eprintln!("runner: gave up after wait_timeout (last: {})", last.reason());
            std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
        }
        std::thread::sleep(Duration::from_secs(2));
        match run_remote_job(socket, cwd, resolved, peers, on) {
            Ok(completed) => std::process::exit(outcome_exit_code(&completed.outcome)),
            Err(AttemptFailure::Fatal(e)) => {
                eprintln!("runner: {e:#}");
                std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
            }
            Err(AttemptFailure::Runner(f)) => {
                last = f.clone();
                if !is_fallback_trigger(&f) {
                    eprintln!("runner: {}", f.reason());
                    std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
                }
            }
        }
    }
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
