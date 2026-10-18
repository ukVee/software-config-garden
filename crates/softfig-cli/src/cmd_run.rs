//! `softfig run …` — the requester surface of the remote runner (spec §9).
//!
//! Explicit, not transparent (decided): the caller names `softfig run`, so
//! every gate line says where the job ran. Exit codes follow §9 exactly — the
//! job's own code on success, **254** for runner-side failures (with the
//! reason printed), and local fallback only on the §9 triggers.
//!
//! Chunk 1 wired config load + resolve + local fallback + exit codes. Chunk 2
//! lands the remote execution path: snapshot → `runner_sign_offer` keeperd
//! verb → `connect_runner`/`run_job` (via `softfig_net::run_remote`). Runner
//! discovery (mDNS `_softfig-runner._tcp` + relay) is a later chunk / slice-008
//! manual smoke — today a peer's endpoint comes from its ring entry and
//! `--on host:port` dials a runner directly (the loopback/test form).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand, ValueEnum};
use softfig_ipc::{
    runtime_socket_path,
    verbs::{
        op, PairListReply, ReadFileArgs, ReadFileReply, RunnerJobLogReply, RunnerJobLsReply,
        RunnerJobRecordArgs, RunnerJobShowReply, RunnerLocalDeviceReply, RunnerOfferEnv,
        RunnerSignOfferArgs, RunnerSignOfferReply, StatusReply,
    },
    Request,
};
use softfig_net::proto::{EnvEntry, JobLog, JobOffer};
use softfig_net::{
    fallback_action, is_fallback_trigger, outcome_exit_code, run_remote_attach, run_remote_cancel,
    run_remote_collecting, run_remote_start, runner_cache_path, strip_control_sequences,
    CancelOutcome, Fallback, FallbackAction, JobOutcome, LocalDevice, ResolvedRun, RunFailure,
    RunnerCache, RunnerConfig,
};
use softfig_source::{create_bundle, repo_key, root_commits, snapshot_repo, SubmodulePolicy};

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

/// The failure modes `attempt_runner` reports: a §9 fallback-driving
/// [`RunFailure`], or a requester-side error that aborts without fallback
/// (snapshot, sign, or config — never a "runner unavailable" event).
enum AttemptFailure {
    Runner(RunFailure),
    Fatal(anyhow::Error),
}

impl From<anyhow::Error> for AttemptFailure {
    fn from(e: anyhow::Error) -> Self {
        AttemptFailure::Fatal(e)
    }
}

impl From<RunFailure> for AttemptFailure {
    fn from(f: RunFailure) -> Self {
        AttemptFailure::Runner(f)
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
        match detach_job(&socket, &cwd, &resolved, &config.use_.peers, args.on.as_deref()) {
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

    match attempt_runner(&socket, &cwd, &resolved, &config.use_.peers, args.on.as_deref()) {
        Ok(outcome) => std::process::exit(outcome_exit_code(&outcome)),
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

/// The remote execution path (spec §3.3, §4, §6, §9): snapshot the repo, build
/// the offer, sign it via keeperd, resolve the runner, then
/// [`run_remote`]. Returns the job outcome, or a fallback-driving failure.
fn attempt_runner(
    socket: &Path,
    cwd: &Path,
    resolved: &ResolvedRun,
    peers: &[String],
    on: Option<&str>,
) -> std::result::Result<JobOutcome, AttemptFailure> {
    // This device's transport material (the identity signing secret never
    // leaves the vault; only the X25519 static is handed to this process).
    let local = local_device(socket)?;

    // Snapshot the worktree (immutable tree + synthetic commit), leaving refs,
    // index and worktree byte-identical (spec §4.2).
    let submodules = match resolved.submodules {
        softfig_net::Submodules::Refuse => SubmodulePolicy::Refuse,
        softfig_net::Submodules::Ignore => SubmodulePolicy::Ignore,
    };
    let snapshot = snapshot_repo(cwd, submodules).map_err(|e| anyhow!("snapshot: {e}"))?;
    let roots = root_commits(cwd).map_err(|e| anyhow!("root commits: {e}"))?;
    let repo_key = repo_key(&local.device_id, &roots);

    let mut offer = build_offer(&snapshot, &repo_key, resolved);
    offer.signature = sign_offer(socket, &offer)?;

    let (endpoint, ring_identity) = resolve_runner(socket, on, peers)?;

    // Load the cert sidecar so `--detach`/`attach`/`cancel` share one cache; a
    // missing/corrupt cache is empty (certs are re-learnable via XX).
    let (mut cache, cache_path) = load_runner_cache(socket)?;

    let source_id = snapshot.source_id;
    let commit = snapshot.commit;
    let repo = cwd.to_path_buf();
    let now = unix_now();
    let started_at = now;
    let (outcome, logs, _events) = run_remote_collecting(
        &local,
        &ring_identity,
        &endpoint,
        &mut cache,
        &offer,
        move |haves: &[Vec<u8>]| {
            create_bundle(&repo, &source_id, &commit, haves).map_err(|e| e.to_string())
        },
        now,
    )
    .map_err(AttemptFailure::Runner)?;
    let _ = cache.save(&cache_path);

    // Record the completed job into keeperd's bounded in-memory table (spec §6,
    // §8), which backs `softfig run ls|show|logs`. Best-effort: a recording
    // failure never changes the job's own exit code.
    record_job(
        socket,
        &local,
        &offer,
        &outcome,
        &logs,
        started_at,
        (endpoint.as_str(), &ring_identity),
    );

    Ok(outcome)
}

/// The terminal row fields for an outcome + log frames: exit code, attestation
/// hash (BLAKE3 of the signed attestation), and the ordered log bytes as base64.
fn outcome_row(outcome: &JobOutcome, logs: &[JobLog]) -> (Option<i32>, Option<String>, String) {
    use base64::Engine as _;

    let (exit, attestation_hash) = match outcome {
        JobOutcome::Accepted(result) => {
            let hash = if result.attestation.is_empty() {
                None
            } else {
                Some(hex::encode(blake3::hash(&result.attestation).as_bytes()))
            };
            (Some(result.exit_code), hash)
        }
        JobOutcome::Rejected(_) => (None, None),
    };

    let mut ordered: Vec<&JobLog> = logs.iter().collect();
    ordered.sort_by_key(|l| l.seq);
    let mut buf = Vec::new();
    for l in ordered {
        buf.extend_from_slice(&l.bytes);
    }

    (
        exit,
        attestation_hash,
        base64::engine::general_purpose::STANDARD.encode(&buf),
    )
}

/// Record a completed remote job into keeperd's bounded in-memory table (spec
/// §6, §8). The log frames are interleaved in arrival order (like a terminal);
/// the attestation hash is the BLAKE3 of the signed attestation bytes. Never
/// fails the run — a recording problem is a warning, not a different exit code.
fn record_job(
    socket: &Path,
    local: &LocalDevice,
    offer: &JobOffer,
    outcome: &JobOutcome,
    logs: &[JobLog],
    started_at: i64,
    target: (&str, &[u8; 32]),
) {
    let (exit, attestation_hash, log_base64) = outcome_row(outcome, logs);

    let mut env_names: Vec<String> = offer.env.iter().map(|e| e.name.clone()).collect();
    env_names.sort();

    let args = RunnerJobRecordArgs {
        job_id: hex::encode(&offer.job_id),
        requester_device: local.device_name.clone(),
        repo_key: hex::encode(&offer.repo_key),
        source_id: hex::encode(&offer.source_id),
        snapshot_commit: hex::encode(&offer.snapshot_commit),
        profile: offer.profile.clone(),
        cmd: offer.cmd.clone(),
        env_names,
        toolchain: offer.toolchain.clone(),
        cache: offer.cache.clone(),
        where_: "remote".to_string(),
        started_at,
        exit,
        attestation_hash,
        finished_at: Some(unix_now()),
        log_base64,
        endpoint: target.0.to_string(),
        runner_identity: hex::encode(target.1),
        cancelled: false,
    };

    if let Err(e) = daemon_call(socket, op::RUNNER_JOB_RECORD, serde_json::to_value(args).unwrap()) {
        eprintln!("warning: could not record job in the keeperd table: {e:#}");
    }
}

/// Record a `running` row (the start of a detached job, spec §6): no exit, no
/// finish, an empty log ring. Reads as state `running` until a terminal record
/// lands via `attach`/`cancel`.
fn record_start(
    socket: &Path,
    local: &LocalDevice,
    offer: &JobOffer,
    endpoint: &str,
    runner_identity: &[u8; 32],
    started_at: i64,
) {
    let mut env_names: Vec<String> = offer.env.iter().map(|e| e.name.clone()).collect();
    env_names.sort();

    let args = RunnerJobRecordArgs {
        job_id: hex::encode(&offer.job_id),
        requester_device: local.device_name.clone(),
        repo_key: hex::encode(&offer.repo_key),
        source_id: hex::encode(&offer.source_id),
        snapshot_commit: hex::encode(&offer.snapshot_commit),
        profile: offer.profile.clone(),
        cmd: offer.cmd.clone(),
        env_names,
        toolchain: offer.toolchain.clone(),
        cache: offer.cache.clone(),
        where_: "remote".to_string(),
        started_at,
        exit: None,
        attestation_hash: None,
        finished_at: None,
        log_base64: String::new(),
        endpoint: endpoint.to_string(),
        runner_identity: hex::encode(runner_identity),
        cancelled: false,
    };

    if let Err(e) = daemon_call(socket, op::RUNNER_JOB_RECORD, serde_json::to_value(args).unwrap()) {
        eprintln!("warning: could not record the running job in the keeperd table: {e:#}");
    }
}

/// Record the terminal outcome of an `attach` (spec §6): upserts the existing
/// row, appending the resumed log and setting exit/attestation/finish.
fn record_attach_terminal(
    socket: &Path,
    job_id: &str,
    outcome: &JobOutcome,
    logs: &[JobLog],
    started_at: i64,
) {
    let (exit, attestation_hash, log_base64) = outcome_row(outcome, logs);
    let args = RunnerJobRecordArgs {
        job_id: job_id.to_string(),
        requester_device: String::new(),
        repo_key: String::new(),
        source_id: String::new(),
        snapshot_commit: String::new(),
        profile: String::new(),
        cmd: Vec::new(),
        env_names: Vec::new(),
        toolchain: String::new(),
        cache: String::new(),
        where_: String::new(),
        started_at,
        exit,
        attestation_hash,
        finished_at: Some(unix_now()),
        log_base64,
        endpoint: String::new(),
        runner_identity: String::new(),
        cancelled: false,
    };

    if let Err(e) = daemon_call(socket, op::RUNNER_JOB_RECORD, serde_json::to_value(args).unwrap()) {
        eprintln!("warning: could not record the attached job in the keeperd table: {e:#}");
    }
}

/// Mark a row `cancelled` (spec §6): upserts the existing row with `cancelled`
/// and a finished time; no exit code or log.
fn record_cancel(socket: &Path, job_id: &str, started_at: i64) {
    let args = RunnerJobRecordArgs {
        job_id: job_id.to_string(),
        requester_device: String::new(),
        repo_key: String::new(),
        source_id: String::new(),
        snapshot_commit: String::new(),
        profile: String::new(),
        cmd: Vec::new(),
        env_names: Vec::new(),
        toolchain: String::new(),
        cache: String::new(),
        where_: String::new(),
        started_at,
        exit: None,
        attestation_hash: None,
        finished_at: Some(unix_now()),
        log_base64: String::new(),
        endpoint: String::new(),
        runner_identity: String::new(),
        cancelled: true,
    };

    if let Err(e) = daemon_call(socket, op::RUNNER_JOB_RECORD, serde_json::to_value(args).unwrap()) {
        eprintln!("warning: could not record the cancelled job in the keeperd table: {e:#}");
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
    use base64::Engine as _;
    let socket = daemon_socket(&None);
    let reply: RunnerJobLogReply = serde_json::from_value(daemon_call(
        &socket,
        op::RUNNER_JOB_LOG,
        serde_json::json!({ "job_id": args.job }),
    )?)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(reply.log_base64.trim())
        .map_err(|e| anyhow!("runner_job_log: bad base64: {e}"))?;
    let bytes = strip_control_sequences(&raw);
    let mut stdout = std::io::stdout().lock();
    use std::io::Write as _;
    stdout.write_all(&bytes)?;
    if args.follow {
        eprintln!("note: `-f` (live follow) needs the detached-job session — a later slice-007 chunk");
    }
    Ok(())
}

/// The garden root (state root), read from keeperd's `status` — locates the
/// never-committed `.softfig/runners.toml` cert sidecar (spec §3.1).
fn garden_root(socket: &Path) -> Result<PathBuf> {
    let reply: StatusReply = serde_json::from_value(daemon_call(
        socket,
        op::STATUS,
        serde_json::Value::Null,
    )?)?;
    Ok(PathBuf::from(reply.garden_root))
}

/// Load (or empty) the runner cert cache from `<garden>/.softfig/runners.toml`
/// (spec §3.1). A missing or corrupt cache is empty — certs are re-learnable
/// via an `XX` handshake.
fn load_runner_cache(socket: &Path) -> Result<(RunnerCache, PathBuf)> {
    let root = garden_root(socket)?;
    let path = runner_cache_path(&root);
    let cache = RunnerCache::load(&path).unwrap_or_default();
    Ok((cache, path))
}

/// The `--detach` path (spec §6): snapshot, sign, resolve, then start the job on
/// the runner and return its id — WITHOUT waiting for logs or the result. The
/// runner runs to completion independently. No local fallback: a detached job is
/// remote by definition, so a runner-side failure exits 254.
fn detach_job(
    socket: &Path,
    cwd: &Path,
    resolved: &ResolvedRun,
    peers: &[String],
    on: Option<&str>,
) -> std::result::Result<String, AttemptFailure> {
    let local = local_device(socket)?;
    let submodules = match resolved.submodules {
        softfig_net::Submodules::Refuse => SubmodulePolicy::Refuse,
        softfig_net::Submodules::Ignore => SubmodulePolicy::Ignore,
    };
    let snapshot = snapshot_repo(cwd, submodules).map_err(|e| anyhow!("snapshot: {e}"))?;
    let roots = root_commits(cwd).map_err(|e| anyhow!("root commits: {e}"))?;
    let repo_key = repo_key(&local.device_id, &roots);
    let mut offer = build_offer(&snapshot, &repo_key, resolved);
    offer.signature = sign_offer(socket, &offer)?;
    let (endpoint, ring_identity) = resolve_runner(socket, on, peers)?;

    let (mut cache, cache_path) = load_runner_cache(socket)?;
    let source_id = snapshot.source_id;
    let commit = snapshot.commit;
    let repo = cwd.to_path_buf();
    let now = unix_now();
    run_remote_start(
        &local,
        &ring_identity,
        &endpoint,
        &mut cache,
        &offer,
        move |haves: &[Vec<u8>]| {
            create_bundle(&repo, &source_id, &commit, haves).map_err(|e| e.to_string())
        },
        now,
    )
    .map_err(AttemptFailure::Runner)?;
    let _ = cache.save(&cache_path);

    record_start(socket, &local, &offer, &endpoint, &ring_identity, now);
    Ok(hex::encode(&offer.job_id))
}

/// `softfig run attach <job>` (spec §6): re-dial the runner (IK via the cached
/// static) and resume a detached job — replay the retained log tail, record the
/// terminal row, and exit with the job's own exit code.
fn job_attach(args: &JobArgs) -> Result<()> {
    use std::io::Write as _;

    let socket = daemon_socket(&None);
    let row: RunnerJobShowReply = serde_json::from_value(daemon_call(
        &socket,
        op::RUNNER_JOB_SHOW,
        serde_json::json!({ "job_id": args.job }),
    )?)?;
    if row.endpoint.is_empty() || row.runner_identity.is_empty() {
        return Err(anyhow!(
            "job {:?} has no recorded runner — was it started with `--detach`?",
            args.job
        ));
    }
    let local = local_device(&socket)?;
    let ring_identity = fixed_bytes::<32>(&row.runner_identity, "runner_identity")?;
    let job_id = hex::decode(&row.job_id).map_err(|e| anyhow!("job_id: {e}"))?;
    let (mut cache, cache_path) = load_runner_cache(&socket)?;

    let (outcome, logs, _events) = run_remote_attach(
        &local,
        &ring_identity,
        &row.endpoint,
        &mut cache,
        &job_id,
        0,
        unix_now(),
    )
    .map_err(|f| anyhow!("attach: {}", f.reason()))?;
    let _ = cache.save(&cache_path);

    // Replay the resumed log tail (sanitized; logs are untrusted bytes).
    let mut ordered: Vec<&JobLog> = logs.iter().collect();
    ordered.sort_by_key(|l| l.seq);
    let mut stdout = std::io::stdout().lock();
    for l in ordered {
        let bytes = strip_control_sequences(&l.bytes);
        stdout.write_all(&bytes)?;
    }
    stdout.flush()?;

    record_attach_terminal(&socket, &row.job_id, &outcome, &logs, row.started_at);

    let code = outcome_exit_code(&outcome);
    eprintln!("job {} exit {code}", row.job_id);
    std::process::exit(code);
}

/// `softfig run cancel <job>` (spec §6): re-dial and send `JobCancel`; the
/// runner marks the job cancelled and stops its unit. Records a `cancelled` row.
fn job_cancel(args: &JobArgs) -> Result<()> {
    let socket = daemon_socket(&None);
    let row: RunnerJobShowReply = serde_json::from_value(daemon_call(
        &socket,
        op::RUNNER_JOB_SHOW,
        serde_json::json!({ "job_id": args.job }),
    )?)?;
    if row.endpoint.is_empty() || row.runner_identity.is_empty() {
        return Err(anyhow!(
            "job {:?} has no recorded runner — was it started with `--detach`?",
            args.job
        ));
    }
    let local = local_device(&socket)?;
    let ring_identity = fixed_bytes::<32>(&row.runner_identity, "runner_identity")?;
    let job_id = hex::decode(&row.job_id).map_err(|e| anyhow!("job_id: {e}"))?;
    let (mut cache, cache_path) = load_runner_cache(&socket)?;

    match run_remote_cancel(&local, &ring_identity, &row.endpoint, &mut cache, &job_id, unix_now())
    {
        Ok(CancelOutcome::Cancelled) => {
            let _ = cache.save(&cache_path);
            record_cancel(&socket, &row.job_id, row.started_at);
            println!("cancelled {}", row.job_id);
            Ok(())
        }
        Ok(CancelOutcome::Lost) => {
            eprintln!(
                "job {} is no longer held by the runner (expired past the TTL)",
                row.job_id
            );
            std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
        }
        Ok(CancelOutcome::Rejected(reason)) => {
            eprintln!("runner: {}", reason.as_str());
            std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
        }
        Err(f) => {
            eprintln!("runner: {}", f.reason());
            std::process::exit(softfig_net::RUNNER_FAILURE_EXIT);
        }
    }
}

/// Build the unsigned [`JobOffer`] from a snapshot + resolved run (spec §6 step
/// 1). The signature is filled by keeperd's `runner_sign_offer` afterwards.
fn build_offer(snapshot: &softfig_source::Snapshot, repo_key: &[u8; 32], resolved: &ResolvedRun) -> JobOffer {
    JobOffer {
        job_id: random_job_id(),
        repo_key: repo_key.to_vec(),
        source_id: snapshot.source_id.encode(),
        snapshot_commit: snapshot.commit.clone(),
        profile: resolved.profile.clone(),
        cmd: resolved.cmd.clone(),
        env: resolved
            .env
            .iter()
            .map(|(name, value)| EnvEntry {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        toolchain: resolved.toolchain.clone(),
        network: resolved.network.clone(),
        cache: resolved.cache.clone(),
        artifacts: resolved.artifacts.clone(),
        requested_at: unix_now(),
        signature: Vec::new(),
    }
}

/// This device's transport material, read back from keeperd.
fn local_device(socket: &Path) -> Result<LocalDevice> {
    let reply: RunnerLocalDeviceReply = serde_json::from_value(daemon_call(
        socket,
        op::RUNNER_LOCAL_DEVICE,
        serde_json::json!({}),
    )?)?;
    Ok(LocalDevice {
        transport_secret: fixed_bytes::<32>(&reply.transport_secret, "transport_secret")?,
        device_id: fixed_bytes::<32>(&reply.device_id, "device_id")?,
        device_name: reply.device_name,
        static_attestation: fixed_bytes::<64>(&reply.static_attestation, "static_attestation")?,
    })
}

/// Sign the offer's canonical bytes via keeperd (the identity secret never
/// leaves the vault); the reply signature (hex) becomes `offer.signature`.
fn sign_offer(socket: &Path, offer: &JobOffer) -> Result<Vec<u8>> {
    let reply: RunnerSignOfferReply = serde_json::from_value(daemon_call(
        socket,
        op::RUNNER_SIGN_OFFER,
        serde_json::to_value(RunnerSignOfferArgs {
            job_id: hex::encode(&offer.job_id),
            repo_key: hex::encode(&offer.repo_key),
            source_id: hex::encode(&offer.source_id),
            snapshot_commit: hex::encode(&offer.snapshot_commit),
            profile: offer.profile.clone(),
            cmd: offer.cmd.clone(),
            env: offer
                .env
                .iter()
                .map(|e| RunnerOfferEnv {
                    name: e.name.clone(),
                    value: e.value.clone(),
                })
                .collect(),
            toolchain: offer.toolchain.clone(),
            network: offer.network.clone(),
            cache: offer.cache.clone(),
            artifacts: offer.artifacts.clone(),
            requested_at: offer.requested_at,
        })?,
    )?)?;
    let sig = hex::decode(&reply.signature).map_err(|e| anyhow!("runner_sign_offer: bad hex: {e}"))?;
    if sig.len() != 64 {
        return Err(anyhow!("runner_sign_offer: signature wrong length"));
    }
    Ok(sig)
}

/// Resolve the runner endpoint + the owner identity (for cert verification).
/// `on` may be a literal `host:port` (direct dial) or a peer name/fingerprint;
/// otherwise the first `[use] peers` entry names the peer. Runner mDNS browse
/// (`_softfig-runner._tcp`) and the relay are a later chunk / slice-008 manual
/// smoke — a peer's endpoint today comes from its ring entry (filled by
/// discovery), and `--on host:port` dials a runner directly.
fn resolve_runner(
    socket: &Path,
    on: Option<&str>,
    peers: &[String],
) -> std::result::Result<(String, [u8; 32]), RunFailure> {
    // Direct dial: `--on host:port`.
    if let Some(hostport) = on
        && looks_like_hostport(hostport)
    {
        let ring = first_peer_identity(socket, peers)?;
        return Ok((hostport.to_string(), ring));
    }
    // A peer by name/fingerprint (from `--on`, else the first `[use] peers`).
    let query = on.map(str::to_string).or_else(|| peers.first().cloned());
    let query = query.ok_or(RunFailure::NoRunner)?;
    let peer = resolve_peer(socket, &query).map_err(|_| RunFailure::NoRunner)?;
    let device_id = fixed_bytes::<32>(&peer.fingerprint, "peer fingerprint")
        .map_err(|_| RunFailure::NoRunner)?;
    let endpoint = peer.endpoints.first().cloned().ok_or(RunFailure::NoRunner)?;
    Ok((endpoint, device_id))
}

/// The identity of the first `[use] peers` entry (the runner owner, whose
/// identity signed the runner certificate).
fn first_peer_identity(socket: &Path, peers: &[String]) -> std::result::Result<[u8; 32], RunFailure> {
    let query = peers.first().ok_or(RunFailure::NoRunner)?;
    let peer = resolve_peer(socket, query).map_err(|_| RunFailure::NoRunner)?;
    fixed_bytes::<32>(&peer.fingerprint, "peer fingerprint").map_err(|_| RunFailure::NoRunner)
}

/// Resolve a peer name/fingerprint to its ring entry (via keeperd `pair_list`).
fn resolve_peer(socket: &Path, query: &str) -> Result<softfig_ipc::verbs::PairPeer> {
    let reply: PairListReply = serde_json::from_value(daemon_call(
        socket,
        op::PAIR_LIST,
        serde_json::json!({}),
    )?)?;
    let q = query.to_lowercase();
    reply
        .peers
        .into_iter()
        .find(|p| p.name == query || p.fingerprint == q || p.fingerprint.starts_with(&q))
        .ok_or_else(|| anyhow!("no ring peer matches {query:?} — pair it first"))
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
        match attempt_runner(socket, cwd, resolved, peers, on) {
            Ok(outcome) => std::process::exit(outcome_exit_code(&outcome)),
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

/// A random 128-bit job id (spec §6 step 1), from `/dev/urandom`.
fn random_job_id() -> Vec<u8> {
    use std::io::Read;
    let mut b = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok()
    {
        return b.to_vec();
    }
    // Fallback: still unique per invocation (time + pid).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut m = [0u8; 16];
    m[..8].copy_from_slice(&now.to_be_bytes());
    m[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    m.to_vec()
}

/// Decode a lowercase-hex string into a fixed-size byte array.
fn fixed_bytes<const N: usize>(hex_s: &str, what: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(hex_s.trim()).map_err(|e| anyhow!("{what}: bad hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{what}: wrong length (want {N} bytes)"))
}

/// Whether `s` looks like a direct `host:port` dial (an IPv4/IPv6 literal or a
/// bare hostname followed by a numeric port).
fn looks_like_hostport(s: &str) -> bool {
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => return false,
    };
    if host.contains('/') || host.contains(' ') {
        return false;
    }
    port.parse::<u16>().is_ok()
}

/// Current unix time in seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
