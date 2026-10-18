//! softfig-run — the requester client for the remote runner (spec remote-runner
//! §3.3, §4, §6, §9).
//!
//! Shared by `softfig run` (the CLI) and `softfig-mcp`'s `run_job`/`job_log`/
//! `job_cancel` verbs. keeperd stays the thin identity + job-table service: it
//! signs the offer (`runner_sign_offer`), hands out this device's transport
//! material (`runner_local_device`), and stores the bounded job table
//! (`runner_job_*`) — this crate owns the orchestration that blocks on git
//! (snapshot + bundle) and the network (dial → Noise handshake → transfer →
//! run/attach/cancel), which therefore lives in the caller's process, never in
//! the daemon's IPC loop.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use softfig_ipc::{
    verbs::{
        op, PairListReply, ReadFileArgs, ReadFileReply, RunnerJobLogReply, RunnerJobRecordArgs,
        RunnerJobShowReply, RunnerLocalDeviceReply, RunnerOfferEnv, RunnerSignOfferArgs,
        RunnerSignOfferReply, StatusReply,
    },
    Request,
};
use softfig_net::proto::{EnvEntry, JobLog, JobOffer};
use softfig_net::{
    run_remote_attach, run_remote_cancel, run_remote_collecting, run_remote_start,
    runner_cache_path, strip_control_sequences, LocalDevice,
    ResolvedRun, RunFailure, RunnerCache, RunnerConfig,
};
use softfig_source::{create_bundle, repo_key, root_commits, snapshot_repo, SubmodulePolicy};

// Re-export the run-facing net types so a consumer (softfig-mcp) depends on
// this one crate rather than reaching into softfig-net for variant matching.
pub use softfig_net::{CancelOutcome, JobOutcome};

/// The failure modes a remote run reports: a §9 fallback-driving [`RunFailure`]
/// (a transient availability/trust problem), or a requester-side error that
/// aborts without fallback (snapshot, sign, or config — never a "runner
/// unavailable" event).
#[derive(Debug)]
pub enum AttemptFailure {
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

/// A completed remote run: the job id (lowercase hex), the outcome, and the
/// ordered log frames (unsorted — call [`log_tail`] to render).
pub struct CompletedRun {
    pub job_id: String,
    pub outcome: JobOutcome,
    pub logs: Vec<JobLog>,
}

/// Read + parse the garden's `config/runner.toml` `[use]`/`[[project]]` tables
/// through keeperd (works in FUSE and Disk modes alike), rejecting bad config.
pub fn load_config(socket: &Path) -> Result<RunnerConfig> {
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

/// Run one job on a runner (spec §3.3, §4, §6, §9): snapshot the worktree,
/// build + sign the offer via keeperd, resolve the runner, transfer the source,
/// and wait for the result. Records the completed job into keeperd's bounded
/// in-memory table (best-effort — a recording failure never changes the job's
/// own outcome). Returns the outcome, or a fallback-driving failure.
pub fn run_remote_job(
    socket: &Path,
    cwd: &Path,
    resolved: &ResolvedRun,
    peers: &[String],
    on: Option<&str>,
) -> Result<CompletedRun, AttemptFailure> {
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

    let job_id = hex::encode(&offer.job_id);
    record_job(
        socket,
        &local,
        &offer,
        &outcome,
        &logs,
        started_at,
        (&endpoint, &ring_identity),
    );

    Ok(CompletedRun { job_id, outcome, logs })
}

/// The `--detach` path (spec §6): snapshot, sign, resolve, then start the job on
/// the runner and return its id (hex) — WITHOUT waiting for logs or the result.
/// The runner runs to completion independently. No local fallback: a detached
/// job is remote by definition, so a runner-side failure is a [`RunFailure`].
pub fn start_detached_job(
    socket: &Path,
    cwd: &Path,
    resolved: &ResolvedRun,
    peers: &[String],
    on: Option<&str>,
) -> Result<String, AttemptFailure> {
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

    let job_id = hex::encode(&offer.job_id);
    record_start(socket, &local, &offer, &endpoint, &ring_identity, now);
    Ok(job_id)
}

/// `attach` a detached job (spec §6): re-dial the runner (IK via the cached
/// static) and resume — replay the retained log tail, record the terminal row.
/// Returns the outcome + the replayed log frames (unsorted — call [`log_tail`]).
pub fn attach_job(socket: &Path, job_id: &str) -> Result<CompletedRun> {
    let row: RunnerJobShowReply = serde_json::from_value(daemon_call(
        socket,
        op::RUNNER_JOB_SHOW,
        serde_json::json!({ "job_id": job_id }),
    )?)?;
    if row.endpoint.is_empty() || row.runner_identity.is_empty() {
        return Err(anyhow!(
            "job {job_id:?} has no recorded runner — was it started with `--detach`?"
        ));
    }
    let local = local_device(socket)?;
    let ring_identity = fixed_bytes::<32>(&row.runner_identity, "runner_identity")?;
    let job_id_bytes = hex::decode(&row.job_id).map_err(|e| anyhow!("job_id: {e}"))?;
    let (mut cache, cache_path) = load_runner_cache(socket)?;

    let (outcome, logs, _events) = run_remote_attach(
        &local,
        &ring_identity,
        &row.endpoint,
        &mut cache,
        &job_id_bytes,
        0,
        unix_now(),
    )
    .map_err(|f| anyhow!("attach: {}", f.reason()))?;
    let _ = cache.save(&cache_path);

    record_attach_terminal(socket, &row.job_id, &outcome, &logs, row.started_at);

    Ok(CompletedRun {
        job_id: row.job_id,
        outcome,
        logs,
    })
}

/// `cancel` a running job (spec §6): re-dial and send `JobCancel`; the runner
/// marks the job cancelled and stops its unit. Records a `cancelled` row on
/// success. `Lost`/`Rejected` are returned (not errors) so the caller can
/// render them distinctly.
pub fn cancel_job(socket: &Path, job_id: &str) -> Result<CancelOutcome> {
    let row: RunnerJobShowReply = serde_json::from_value(daemon_call(
        socket,
        op::RUNNER_JOB_SHOW,
        serde_json::json!({ "job_id": job_id }),
    )?)?;
    if row.endpoint.is_empty() || row.runner_identity.is_empty() {
        return Err(anyhow!(
            "job {job_id:?} has no recorded runner — was it started with `--detach`?"
        ));
    }
    let local = local_device(socket)?;
    let ring_identity = fixed_bytes::<32>(&row.runner_identity, "runner_identity")?;
    let job_id_bytes = hex::decode(&row.job_id).map_err(|e| anyhow!("job_id: {e}"))?;
    let (mut cache, cache_path) = load_runner_cache(socket)?;

    match run_remote_cancel(
        &local,
        &ring_identity,
        &row.endpoint,
        &mut cache,
        &job_id_bytes,
        unix_now(),
    ) {
        Ok(CancelOutcome::Cancelled) => {
            let _ = cache.save(&cache_path);
            record_cancel(socket, &row.job_id, row.started_at);
            Ok(CancelOutcome::Cancelled)
        }
        Ok(other) => Ok(other),
        Err(f) => Err(anyhow!("cancel: {}", f.reason())),
    }
}

/// Read one job's stored log ring from keeperd, control sequences stripped
/// (logs are untrusted bytes — spec §6 Logs). The full sanitized bytes.
pub fn read_job_log(socket: &Path, job_id: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;

    let reply: RunnerJobLogReply = serde_json::from_value(daemon_call(
        socket,
        op::RUNNER_JOB_LOG,
        serde_json::json!({ "job_id": job_id }),
    )?)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(reply.log_base64.trim())
        .map_err(|e| anyhow!("runner_job_log: bad base64: {e}"))?;
    Ok(strip_control_sequences(&raw))
}

/// A run's log frames ordered by `JobLog.seq` and concatenated, control
/// sequences stripped (logs are untrusted bytes). The full sanitized bytes.
pub fn log_bytes(logs: &[JobLog]) -> Vec<u8> {
    let mut ordered: Vec<&JobLog> = logs.iter().collect();
    ordered.sort_by_key(|l| l.seq);
    let mut buf = Vec::new();
    for l in ordered {
        buf.extend_from_slice(&l.bytes);
    }
    strip_control_sequences(&buf)
}

/// The last `lines` lines of a run's log (by `JobLog.seq`), control sequences
/// stripped, joined as text. Bounded so an agent surface never ships the whole
/// log by default.
pub fn log_tail(logs: &[JobLog], lines: usize) -> String {
    let stripped = log_bytes(logs);
    let text = String::from_utf8_lossy(&stripped);
    let mut ls: Vec<&str> = text.lines().collect();
    if ls.len() > lines {
        ls = ls.split_off(ls.len() - lines);
    }
    ls.join("\n")
}

/// The job's own exit code, or `None` when the runner rejected the offer.
pub fn exit_code(outcome: &JobOutcome) -> Option<i32> {
    match outcome {
        JobOutcome::Accepted(result) => Some(result.exit_code),
        JobOutcome::Rejected(_) => None,
    }
}

/// BLAKE3 of the signed attestation (spec §8), `None` when the run produced no
/// attestation (a reject, or a result with an empty attestation).
pub fn attestation_hash(outcome: &JobOutcome) -> Option<String> {
    match outcome {
        JobOutcome::Accepted(result) if !result.attestation.is_empty() => {
            Some(hex::encode(blake3::hash(&result.attestation).as_bytes()))
        }
        _ => None,
    }
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
/// fails the run — a recording problem is a warning, not a different outcome.
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
) -> Result<(String, [u8; 32]), RunFailure> {
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
fn first_peer_identity(socket: &Path, peers: &[String]) -> Result<[u8; 32], RunFailure> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostport_detection() {
        assert!(looks_like_hostport("127.0.0.1:8080"));
        assert!(looks_like_hostport("[::1]:8080"));
        assert!(looks_like_hostport("runner.lan:9999"));
        assert!(!looks_like_hostport("no-port"));
        assert!(!looks_like_hostport("http://x/y:80"));
        assert!(!looks_like_hostport("host:notaport"));
    }

    #[test]
    fn fixed_bytes_round_trip() {
        let hex_s = "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff";
        let bytes: [u8; 32] = fixed_bytes(hex_s, "test").unwrap();
        assert_eq!(hex::encode(bytes), hex_s);
        assert!(fixed_bytes::<32>("short", "test").is_err());
        assert!(fixed_bytes::<32>("zz", "test").is_err());
    }

    #[test]
    fn exit_and_attestation_of_reject_are_none() {
        use softfig_net::proto::JobResult;
        let rejected = JobOutcome::Rejected(softfig_net::JobRejectReason::Disabled);
        assert_eq!(exit_code(&rejected), None);
        assert_eq!(attestation_hash(&rejected), None);

        let empty = JobOutcome::Accepted(JobResult::default());
        assert_eq!(exit_code(&empty), Some(0));
        assert_eq!(attestation_hash(&empty), None);
    }

    #[test]
    fn log_tail_sorts_by_seq_and_bounds() {
        let mk = |seq: u64, bytes: &[u8]| JobLog {
            job_id: Vec::new(),
            seq,
            stream: 0,
            bytes: bytes.to_vec(),
        };
        let logs = vec![mk(1, b"one\n"), mk(0, b"zero\n"), mk(2, b"two\n")];
        assert_eq!(log_tail(&logs, 2), "one\ntwo");
        assert_eq!(log_tail(&logs, 10), "zero\none\ntwo");
    }
}
