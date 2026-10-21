//! The runner's job listener (spec remote-runner §3.3, §6): one Noise
//! connection per job, requester device key <-> runner key.
//!
//! runnerd binds a TCP listener on its own port and, for each connection, runs
//! the runner handshake ([`softfig_net::runner_responder`] — `XX` on first
//! contact, `IK` on reconnect, discriminated by the first-message length),
//! presenting the delegated runner certificate in the handshake payload. It
//! then verifies the requester (self-attestation binding identity to the
//! handshake static + the `accept.toml` allowlist), advertises [`RunnerCaps`],
//! reads the signed [`JobOffer`], and replies [`JobAccept`] / [`JobReject`]
//! with spec §6's closed reason enum.
//!
//! There is **no real execution yet** (slice 003): an accepted offer gets a
//! canned [`JobResult`] from a stub executor, so the wire can be tested end to
//! end on its own. The runner never reads a garden; its trust material is the
//! `cert.toml` + `accept.toml` + `serve.toml` in its own state root.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use softfig_net::proto::{
    frame, Frame, JobAccept, JobAttach, JobCancel, JobEvent, JobLog, JobReject, JobResult,
    RunnerCaps, RunnerHandshake, SourceHave,
};
use softfig_net::JobState;
use softfig_sandbox::JobContext;
use softfig_source::SourceBackend;

use crate::attestation::{
    ArtifactEntry, EnvBinding, ExitInfo, JobAttestation, SignedAttestation, SourceRef,
};
use crate::cert::StoredCert;
use crate::config::{AcceptConfig, ServeConfig};
use crate::error::{Error, Result};
use crate::etc;
use crate::executor::{self, SandboxBinaries};
use crate::jobs::{append_ndjson, Job, JobKey, JobRecord, JobTable};
use crate::keys::RunnerKeys;
use crate::log::{read_framed_chunks, JobLogs, LogSink};
use crate::state::StateRoot;
use crate::systemd::{
    battery_reject, on_battery, run_unit, stop_unit, unit_name, Caps, CapsHit, EnvSpec, JobReport,
    JobSpec, Manager, UnitResult, POWER_SUPPLY_PATH,
};

/// The default hold for a finished job's result + log tail (spec §6 TTL).
const DEFAULT_TTL_SECS: i64 = 24 * 60 * 60;

/// The runner's job listener. Owns its `TcpListener` and the long-lived
/// transport static; the certificate and the `accept.toml` / `serve.toml`
/// configs are reloaded per connection, so a grant / revoke / apply /
/// disable takes effect on the next connection without restarting.
pub struct WireServer {
    listener: TcpListener,
    root: StateRoot,
    transport_secret: [u8; 32],
    /// The Ed25519 attest key — signs job attestations (spec §8).
    attest_signing: ed25519_dalek::SigningKey,
    sandbox_bins: SandboxBinaries,
    /// Which systemd manager a job's transient unit runs under (spec §7.1
    /// layer 2). `System` in production; `Direct` runs the executor in-process
    /// (tests); `User` is the loopback path.
    manager: Manager,
    /// The sysfs power-supply root for the `on_battery` check (spec §5.2).
    power_supply_path: PathBuf,
    /// The runnerd binary the transient unit re-invokes as its payload
    /// (`--run-job`). Production uses `current_exe`; tests point it at the
    /// built binary.
    runnerd_bin: PathBuf,
    /// The job table (attach/cancel/TTL, spec §6).
    jobs: JobTable,
    /// How long a finished job's result + log tail are held (spec §6 TTL).
    ttl_secs: i64,
}

impl WireServer {
    /// Bind the job listener on `addr`, loading the runner's transport static
    /// and resolving the sandbox helpers from beside the running binary. Fails
    /// if the keys have not been generated (a not-yet-enabled runner).
    /// Production: transient units run under the **system** manager.
    pub fn bind(root: StateRoot, addr: &str) -> Result<Self> {
        let mut s = Self::bind_with_bins(root, addr, SandboxBinaries::next_to_runnerd()?)?;
        s.manager = Manager::System;
        Ok(s)
    }

    /// Bind with explicit sandbox helper paths. Tests use this (they cannot rely
    /// on the install layout); production goes through [`Self::bind`]. Defaults
    /// to [`Manager::Direct`] (the executor runs in-process) so the wire tests
    /// don't need a systemd manager; the transient-unit tests switch it with
    /// [`Self::set_manager`].
    pub fn bind_with_bins(
        root: StateRoot,
        addr: &str,
        sandbox_bins: SandboxBinaries,
    ) -> Result<Self> {
        let keys = RunnerKeys::load(&root.keys_dir())?;
        let listener = TcpListener::bind(addr).map_err(|e| {
            Error::Protocol(format!("could not bind the runner listener on {addr}: {e}"))
        })?;
        Ok(Self {
            listener,
            root,
            transport_secret: *keys.transport_secret(),
            attest_signing: keys.attest_signing().clone(),
            sandbox_bins,
            manager: Manager::Direct,
            power_supply_path: PathBuf::from(POWER_SUPPLY_PATH),
            runnerd_bin: std::env::current_exe().unwrap_or_else(|_| "softfig-runnerd".into()),
            jobs: JobTable::new(),
            ttl_secs: DEFAULT_TTL_SECS,
        })
    }

    /// Switch the transient-unit manager (tests: [`Manager::User`]).
    pub fn set_manager(&mut self, manager: Manager) {
        self.manager = manager;
    }

    /// Point the power check at a fixture sysfs dir (tests).
    pub fn set_power_supply_path(&mut self, path: PathBuf) {
        self.power_supply_path = path;
    }

    /// Point the transient-unit payload at a specific runnerd binary (tests).
    pub fn set_runnerd_bin(&mut self, bin: PathBuf) {
        self.runnerd_bin = bin;
    }

    /// Point the TTL at a short window (tests). Default 24 h (spec §6).
    pub fn set_ttl_secs(&mut self, secs: i64) {
        self.ttl_secs = secs;
    }

    /// The bound address (useful for tests and for the mDNS announce).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// The underlying listener, so tests can bound an accept with
    /// `softfig_net::testing::accept_within`.
    pub fn listener(&self) -> &TcpListener {
        &self.listener
    }

    /// Accept one connection. Exposed so tests can drive the server side
    /// deterministically; production uses [`run`](Self::run).
    pub fn accept(&self) -> Result<TcpStream> {
        Ok(self.listener.accept()?.0)
    }

    /// Run the accept loop, serving each connection on its own thread
    /// (thread-per-connection, matching `softfig-net`'s concurrency model).
    pub fn run(self: Arc<Self>) -> Result<()> {
        for conn in self.listener.incoming() {
            let conn = conn?;
            let me = Arc::clone(&self);
            std::thread::spawn(move || {
                let _ = me.serve_connection(conn);
            });
        }
        Ok(())
    }

    /// Serve one connection: handshake, requester verification, caps, offer,
    /// accept/reject, and the stub result. Errors are per-connection (the
    /// caller drops them); a refused requester sees a `JobReject`, and a failed
    /// handshake / attestation sees the connection close.
    pub fn serve_connection(&self, stream: TcpStream) -> Result<()> {
        let cert = StoredCert::load(&self.root.cert_toml())
            .map_err(|_| Error::Protocol("runner has no certificate (run `softfig runner enable`)".into()))?;
        let handshake = build_runner_handshake(&cert)?;

        let mut session = softfig_net::runner_responder(stream, &self.transport_secret, &handshake)?;

        // Verify the requester's identity<->static binding before trusting the
        // claimed device_id for the allowlist + signature checks.
        let device_id = self.verify_requester(&session)?;

        let accept = AcceptConfig::load(&self.root.accept_toml())?;
        let serve = ServeConfig::load(&self.root.serve_toml())?;

        // Sweep jobs whose TTL elapsed before serving this connection.
        self.sweep_expired();

        // Advertise capabilities (public), then read the first frame: an offer
        // (a new job) or an attach/cancel for an existing one (spec §6).
        session.send_frame(&Frame::runner_caps(self.runner_caps(&serve)))?;
        let first = session.recv_frame()?;
        match first.kind {
            Some(frame::Kind::JobOffer(offer)) => {
                match self.authorize(&offer, &device_id, session.peer_static(), &accept, &serve) {
                    None => {
                        // The job's name on this runner (m2). A `job_id` that isn't
                        // 16 bytes drops the connection like any malformed offer,
                        // before anything is accepted or written.
                        let key = JobKey::new(device_id, &offer.job_id)?;
                        // Power state (spec §6 step 1): refuse on battery when the
                        // `[serve]` table says refuse, before any source transfer.
                        let on_batt = on_battery(&self.power_supply_path)?;
                        if let Some(reason) = battery_reject(&serve, on_batt) {
                            session.send_frame(&Frame::job_reject(JobReject {
                                job_id: offer.job_id.clone(),
                                reason: reason.to_u32(),
                            }))?;
                            return Ok(());
                        }
                        session.send_frame(&Frame::job_accept(JobAccept {
                            job_id: offer.job_id.clone(),
                            queue_pos: 0,
                        }))?;
                        self.serve_source(session, &offer, &serve, on_batt, key, &cert)?;
                    }
                    Some(reason) => {
                        session.send_frame(&Frame::job_reject(JobReject {
                            job_id: offer.job_id,
                            reason: reason.to_u32(),
                        }))?;
                    }
                }
            }
            Some(frame::Kind::JobAttach(attach)) => {
                self.serve_attach(session, attach, &device_id, &accept, &serve)?;
            }
            Some(frame::Kind::JobCancel(cancel)) => {
                self.serve_cancel(session, cancel, &device_id, &accept, &serve)?;
            }
            _ => return Err(Error::Protocol("expected JobOffer, JobAttach or JobCancel".into())),
        }
        Ok(())
    }

    /// Verify the requester's self-attestation (its identity key signed its
    /// handshake static) and return its claimed device id. A failure closes the
    /// connection (the peer cannot prove who it is).
    fn verify_requester(&self, session: &softfig_net::NoiseSession<TcpStream>) -> Result<[u8; 32]> {
        let hello = session.peer_hello();
        let device_id: [u8; 32] = hello
            .device_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::Protocol("requester device_id wrong length".into()))?;
        let attestation: [u8; 64] = hello
            .static_attestation
            .as_slice()
            .try_into()
            .map_err(|_| Error::Protocol("requester attestation wrong length".into()))?;
        if !softfig_net::verify_static_attestation(&device_id, session.peer_static(), &attestation) {
            return Err(Error::Protocol("requester attestation does not verify".into()));
        }
        Ok(device_id)
    }

    /// The allowlist + enabled check shared by offer/attach/cancel (spec §6).
    /// `None` means the requester is granted and the runner is enabled.
    fn granted(
        &self,
        device_id: &[u8; 32],
        peer_static: &[u8; 32],
        accept: &AcceptConfig,
        serve: &ServeConfig,
    ) -> Option<softfig_net::JobRejectReason> {
        if !serve.enabled {
            return Some(softfig_net::JobRejectReason::Disabled);
        }
        let Some(granted) = accept
            .peer
            .iter()
            .find(|p| p.device_id == hex::encode(device_id))
        else {
            return Some(softfig_net::JobRejectReason::NotGranted);
        };
        // The handshake static must be the one `grant` recorded for this identity.
        if hex::decode(&granted.transport_pubkey).ok().as_deref() != Some(peer_static) {
            return Some(softfig_net::JobRejectReason::NotGranted);
        }
        None
    }

    /// Decide accept vs reject for an offer. The order of checks is the closed
    /// reason list: disabled first, then the allowlist (identity + static), then
    /// the offer signature against the granted identity.
    fn authorize(
        &self,
        offer: &softfig_net::proto::JobOffer,
        device_id: &[u8; 32],
        peer_static: &[u8; 32],
        accept: &AcceptConfig,
        serve: &ServeConfig,
    ) -> Option<softfig_net::JobRejectReason> {
        if let Some(reason) = self.granted(device_id, peer_static, accept, serve) {
            return Some(reason);
        }
        if !softfig_net::verify_offer_sig(offer, device_id, &offer.signature) {
            return Some(softfig_net::JobRejectReason::NotGranted);
        }
        None
    }

    /// Advertise this runner's capabilities (spec §11 frame 300). Placeholder
    /// where the field needs a dependency not yet present; slice 006/007 fill
    /// the real values.
    fn runner_caps(&self, serve: &ServeConfig) -> RunnerCaps {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(0);
        RunnerCaps {
            arch: std::env::consts::ARCH.to_string(),
            triple: String::new(),
            cores,
            mem_bytes: 0,
            toolchains: serve.toolchains.clone(),
            max_jobs: serve.max_jobs,
            active_jobs: 0,
            power: "unknown".into(),
        }
    }
    /// Serve the source step for an accepted job (spec §4.3): advertise the
    /// have/want tips, read the bundle chunks, ingest + verify (a tree mismatch
    /// is a `source-mismatch` [`JobReject`]), then materialize into a scratch
    /// dir and return the stub result. The sandbox-wrapped ingest/materialize
    /// and the real run step land in slice 006; here the git calls run under
    /// `softfig_source`'s hardening config (hooks off, no network, fsck on).
    fn serve_source(
        &self,
        mut session: softfig_net::NoiseSession<TcpStream>,
        offer: &softfig_net::proto::JobOffer,
        serve: &ServeConfig,
        on_battery: bool,
        key: JobKey,
        cert: &StoredCert,
    ) -> Result<()> {
        let source_id = softfig_source::SourceId::decode(&offer.source_id)
            .ok_or_else(|| Error::Protocol("malformed source id in offer".into()))?;
        let repo_key: [u8; 32] = offer
            .repo_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Protocol("repo_key wrong length".into()))?;
        let backend = softfig_source::GitBackend::new(self.root.repos_dir());

        let haves = backend
            .negotiate(&repo_key)
            .map_err(|e| Error::Protocol(format!("negotiate failed: {e}")))?;
        session.send_frame(&Frame::source_have(SourceHave {
            repo_key: offer.repo_key.clone(),
            tips: haves.tips,
            recent_commits: haves.commits,
        }))?;

        // Read the bundle chunks until the `last` flag.
        let mut bundle = Vec::new();
        loop {
            match session.recv_frame()?.kind {
                Some(frame::Kind::SourceChunk(c)) => {
                    bundle.extend_from_slice(&c.payload);
                    if c.last {
                        break;
                    }
                }
                _ => return Err(Error::Protocol("expected SourceChunk during transfer".into())),
            }
        }

        backend
            .ingest(&repo_key, &source_id, &bundle)
            .map_err(|e| Error::Protocol(format!("ingest failed: {e}")))?;
        if let Err(e) = backend.verify(&repo_key, &source_id, &offer.snapshot_commit) {
            if matches!(e, softfig_source::Error::SourceMismatch(_)) {
                session.send_frame(&Frame::job_reject(JobReject {
                    job_id: offer.job_id.clone(),
                    reason: softfig_net::JobRejectReason::SourceMismatch.to_u32(),
                }))?;
                return Ok(());
            }
            return Err(Error::Protocol(format!("verify failed: {e}")));
        }

        // Materialize into the job's scratch dir under the state root (never
        // `/tmp`: the unit's `PrivateTmp` hides `/tmp` from its payload, and
        // `ProtectSystem=strict` re-opens only the state root via
        // `ReadWritePaths`). Then run the real fetch → run → collect sequence.
        let job_dir = key.scratch_dir(&self.root);
        std::fs::create_dir_all(&job_dir)?;
        let src_dir = job_dir.join("src");
        backend
            .materialize(
                &repo_key,
                &source_id,
                &offer.snapshot_commit,
                &src_dir,
                false,
            )
            .map_err(|e| Error::Protocol(format!("materialize failed: {e}")))?;

        // The target cache: shared across a repo key, or a fresh empty dir when
        // the offer demands `cache = "fresh"` (spec §7.3).
        let target_cache = if offer.cache == "fresh" {
            job_dir.join("fresh-cache")
        } else {
            self.root
                .cache_dir()
                .join(hex::encode(repo_key))
                .join("target")
        };

        // A minimal `/etc` (spec §7.1) per job, never the host's: the run etc
        // has no resolver; the fetch step's sibling carries `resolv.conf`.
        let etc_dir = job_dir.join("etc");
        etc::build_minimal_etc(&etc_dir, Path::new("/etc"), false)?;
        etc::build_minimal_etc(&etc::fetch_etc_for(&etc_dir), Path::new("/etc"), true)?;

        let ctx = JobContext {
            src: src_dir,
            target_cache,
            toolchain: self.root.rustup_home(),
            cargo_home: self.root.cargo_home_dir(),
            etc: etc_dir,
            scratch_size: executor::parse_size(&serve.scratch_max)?,
        };
        // bwrap binds require the source paths to exist.
        std::fs::create_dir_all(&ctx.cargo_home)?;
        std::fs::create_dir_all(&ctx.target_cache)?;

        // Split the Noise session: the source transfer is done, and from here the
        // runner only sends (live logs, then the result). The drain thread owns
        // the write half and streams `JobLog` frames as the run produces them;
        // it hands the writer back once the job is done.
        let (reader, writer) = session
            .split()
            .map_err(|e| Error::Protocol(format!("session split: {e}")))?;
        drop(reader);

        // The shared log collector, registered in the job table before the run so
        // attach/cancel can find the job while it is still running (spec §6).
        let logs = JobLogs::new();
        let job = Arc::new(Job {
            key,
            unit: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            logs: logs.clone(),
            started_at: now_unix(),
            finished_at: Mutex::new(None),
            result: Mutex::new(None),
        });
        self.jobs.insert(job.clone());

        let done = Arc::new(AtomicBool::new(false));
        let drain_done = Arc::clone(&done);
        let drain_job_id = offer.job_id.clone();
        let rx = logs.subscribe();
        let drain = std::thread::spawn(move || {
            let mut w = writer;
            loop {
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(chunk) => {
                        let f = Frame::job_log(JobLog {
                            job_id: drain_job_id.clone(),
                            seq: chunk.seq,
                            stream: chunk.stream as u32,
                            bytes: chunk.bytes,
                        });
                        if w.send_frame(&f).is_err() {
                            // The requester disconnected mid-run; stop streaming
                            // (the job runs to completion regardless — detach).
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if drain_done.load(Ordering::SeqCst) {
                            // Drain any queued chunks before handing back the writer.
                            while let Ok(chunk) = rx.try_recv() {
                                let f = Frame::job_log(JobLog {
                                    job_id: drain_job_id.clone(),
                                    seq: chunk.seq,
                                    stream: chunk.stream as u32,
                                    bytes: chunk.bytes,
                                });
                                if w.send_frame(&f).is_err() {
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            w
        });

        // Direct mode streams the run step's output live into the sink; the
        // transient-unit path runs in the unit and reads the payload's framed log
        // file back after the unit completes (unit-mode log capture).
        let started_at = now_unix();
        let unit = if matches!(self.manager, Manager::System | Manager::User) {
            let name = unit_name(&key);
            *job.unit.lock().unwrap() = Some(name.clone());
            Some(name)
        } else {
            None
        };
        let run = match self.manager {
            Manager::Direct => {
                self.run_job(&ctx, serve, offer, on_battery, &job_dir, Some(&logs.sink()), None, &job)
            }
            Manager::System | Manager::User => {
                let r = self.run_job(&ctx, serve, offer, on_battery, &job_dir, None, unit.as_deref(), &job);
                // Stream the payload's framed log file back into the shared sink.
                let _ = stream_unit_log(&job_dir, &logs);
                r
            }
        };
        let finished_at = now_unix();

        // Mark the job done and join the drain before sending the result.
        *job.finished_at.lock().unwrap() = Some(finished_at);
        done.store(true, Ordering::SeqCst);
        let writer = match drain.join() {
            Ok(w) => w,
            Err(_) => {
                self.jobs.remove(&key);
                return Err(Error::Protocol("log drain thread panicked".into()));
            }
        };

        match run {
            Ok((outcome, caps_hit)) => {
                if let Some(hit) = caps_hit {
                    eprintln!(
                        "softfig-runnerd: job {} killed by the {} cap",
                        hex::encode(&offer.job_id),
                        hit.as_str()
                    );
                }
                let mut attestation = build_attestation(
                    offer,
                    &source_id,
                    &repo_key,
                    &outcome,
                    caps_hit,
                    key.device_id(),
                    cert,
                    &logs,
                    started_at,
                    finished_at,
                )?;
                // A cancelled job (unit stopped mid-run) records `cancelled`.
                let cancelled =
                    job.is_cancelled() && !matches!(self.manager, Manager::Direct);
                if cancelled {
                    attestation.exit = ExitInfo::reason("cancelled");
                }
                let exit_code =
                    if cancelled { crate::systemd::CANCELLED_EXIT } else { outcome.exit_code };

                // The durable run-log row (spec §6 step 9). `attestation_hash` is
                // the bare canonical digest, distinct from the signing message.
                let mut env_names: Vec<String> = offer.env.iter().map(|e| e.name.clone()).collect();
                env_names.sort_unstable();
                let record = JobRecord {
                    job_id: attestation.job_id.clone(),
                    requester_device: attestation.requester_device.clone(),
                    repo_key: attestation.repo_key.clone(),
                    source_id: source_id.hex(),
                    snapshot_commit: hex::encode(&offer.snapshot_commit),
                    profile: attestation.profile.clone(),
                    cmd: attestation.cmd.clone(),
                    env_names,
                    toolchain: attestation.toolchain.clone(),
                    caps_hit: caps_hit.map(|h| h.as_str().to_string()),
                    cache_mode: offer.cache.clone(),
                    started_at: attestation.started_at,
                    finished_at: attestation.finished_at,
                    exit: attestation.exit.clone(),
                    log_blake3: attestation.log_blake3.clone(),
                    attestation_hash: hex::encode(attestation.hash()?),
                    where_route: "lan".to_string(),
                };
                append_ndjson(&self.root, &record)?;

                let signature = attestation.sign(&self.attest_signing)?;
                let signed = SignedAttestation { attestation, signature: hex::encode(signature) };
                let result = JobResult {
                    job_id: offer.job_id.clone(),
                    exit_code,
                    attestation: signed.to_bytes()?,
                };
                *job.result.lock().unwrap() = Some(result.clone());
                let mut w = writer;
                w.send_frame(&Frame::job_result(result))?;
            }
            Err(Error::ToolchainMissing(add_cmd)) => {
                // The `JobReject` frame has no message field, so the exact
                // `softfig runner toolchain add <spec>` rides the runner log.
                eprintln!(
                    "softfig-runnerd: job {} rejected (toolchain-missing): {add_cmd}",
                    hex::encode(&offer.job_id)
                );
                self.jobs.remove(&key);
                let mut w = writer;
                w.send_frame(&Frame::job_reject(JobReject {
                    job_id: offer.job_id.clone(),
                    reason: softfig_net::JobRejectReason::ToolchainMissing.to_u32(),
                }))?;
            }
            Err(e) => {
                self.jobs.remove(&key);
                return Err(e);
            }
        }

        // Best-effort cleanup of the per-job scratch (the shared target cache
        // stays; a fresh cache dies with the job, spec §6 step 8). The job's
        // result + log tail stay in the table for the TTL.
        let _ = std::fs::remove_dir_all(&job_dir);
        Ok(())
    }

    /// Run a job's fetch → run → collect: in-process (the `Direct` test seam)
    /// or inside the transient unit (production + loopback).
    #[allow(clippy::too_many_arguments)]
    fn run_job(
        &self,
        ctx: &JobContext,
        serve: &ServeConfig,
        offer: &softfig_net::proto::JobOffer,
        on_battery: bool,
        job_dir: &std::path::Path,
        log: Option<&LogSink>,
        unit: Option<&str>,
        job: &Job,
    ) -> Result<(executor::RunOutcome, Option<CapsHit>)> {
        match self.manager {
            Manager::Direct => {
                executor::execute(ctx, serve, offer, &self.sandbox_bins, log).map(|o| (o, None))
            }
            Manager::System | Manager::User => self.run_in_unit(
                ctx,
                serve,
                offer,
                on_battery,
                job_dir,
                unit.expect("the unit name is set in unit mode"),
                job,
            ),
        }
    }

    /// Run the executor inside a `systemd-run` transient unit: serialize the
    /// job spec, re-invoke runnerd with `--run-job`, and read its report.
    #[allow(clippy::too_many_arguments)]
    fn run_in_unit(
        &self,
        ctx: &JobContext,
        serve: &ServeConfig,
        offer: &softfig_net::proto::JobOffer,
        on_battery: bool,
        job_dir: &std::path::Path,
        unit: &str,
        job: &Job,
    ) -> Result<(executor::RunOutcome, Option<CapsHit>)> {
        // A job cancelled before the unit launched never starts.
        if job.is_cancelled() {
            return Ok((
                executor::RunOutcome { exit_code: crate::systemd::CANCELLED_EXIT, ..Default::default() },
                None,
            ));
        }

        let spec = JobSpec {
            ctx: ctx.clone(),
            egress: serve.egress.clone(),
            toolchains: serve.toolchains.clone(),
            cmd: offer.cmd.clone(),
            env: offer
                .env
                .iter()
                .map(|e| EnvSpec { name: e.name.clone(), value: e.value.clone() })
                .collect(),
            network: offer.network.clone(),
            artifacts: offer.artifacts.clone(),
        };
        let spec_path = job_dir.join("spec.json");
        let result_path = job_dir.join("result.json");
        std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;

        let caps = Caps::resolve(serve, on_battery)?;
        let payload = vec![
            self.runnerd_bin.display().to_string(),
            "--run-job".to_string(),
            spec_path.display().to_string(),
            result_path.display().to_string(),
        ];
        let (unit_result, _code) = run_unit(
            self.manager,
            unit,
            &caps,
            &payload,
            &[self.root.root().to_path_buf()],
        )?;

        // A cancelled job (its unit was stopped) has no result file.
        if job.is_cancelled() {
            return Ok((
                executor::RunOutcome { exit_code: crate::systemd::CANCELLED_EXIT, ..Default::default() },
                None,
            ));
        }

        // A cap kill leaves no result file: map it to a sentinel exit + CapsHit.
        let caps_hit = match unit_result {
            UnitResult::TimedOut => Some(CapsHit::Time),
            UnitResult::OomKilled => Some(CapsHit::Memory),
            _ => None,
        };
        if let Some(hit) = caps_hit {
            return Ok((executor::RunOutcome { exit_code: hit.exit_code(), ..Default::default() }, caps_hit));
        }

        let report: JobReport = serde_json::from_slice(&std::fs::read(&result_path)?)?;
        if let Some(err) = report.error {
            if let Some(rest) = err.strip_prefix("toolchain-missing:") {
                return Err(Error::ToolchainMissing(rest.trim().to_string()));
            }
            return Err(Error::Protocol(format!("job payload failed: {err}")));
        }
        let outcome = report
            .outcome
            .ok_or_else(|| Error::Protocol("job payload returned neither outcome nor error".into()))?;
        Ok((outcome, None))
    }

    /// Serve a `JobAttach` (spec §6): resume a detached job's log from `from_seq`
    /// and deliver its result. Authorized to the submitting requester only.
    fn serve_attach(
        &self,
        mut session: softfig_net::NoiseSession<TcpStream>,
        attach: JobAttach,
        device_id: &[u8; 32],
        accept: &AcceptConfig,
        serve: &ServeConfig,
    ) -> Result<()> {
        if let Some(reason) = self.granted(device_id, session.peer_static(), accept, serve) {
            session.send_frame(&Frame::job_reject(JobReject {
                job_id: attach.job_id.clone(),
                reason: reason.to_u32(),
            }))?;
            return Ok(());
        }
        // Keyed by the authenticated requester, so another requester's job
        // (and a malformed id) is simply not found.
        let job = JobKey::new(*device_id, &attach.job_id).ok().and_then(|k| self.jobs.get(&k));
        let Some(job) = job else {
            session.send_frame(&Frame::job_event(JobEvent {
                job_id: attach.job_id.clone(),
                state: JobState::Lost as u32,
                detail: "no such job".into(),
            }))?;
            return Ok(());
        };

        // Replay the retained ring from `from_seq`, then follow live until the
        // result is set (the job completed and stored it).
        let (rx, replay) = job.logs.subscribe_and_replay(attach.from_seq);
        for chunk in replay {
            if session
                .send_frame(&Frame::job_log(JobLog {
                    job_id: attach.job_id.clone(),
                    seq: chunk.seq,
                    stream: chunk.stream as u32,
                    bytes: chunk.bytes,
                }))
                .is_err()
            {
                return Ok(());
            }
        }
        loop {
            if let Some(result) = job.result.lock().unwrap().clone() {
                session.send_frame(&Frame::job_result(result))?;
                return Ok(());
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(chunk) => {
                    if session
                        .send_frame(&Frame::job_log(JobLog {
                            job_id: attach.job_id.clone(),
                            seq: chunk.seq,
                            stream: chunk.stream as u32,
                            bytes: chunk.bytes,
                        }))
                        .is_err()
                    {
                        return Ok(());
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => continue,
            }
        }
    }

    /// Serve a `JobCancel` (spec §6): mark the job cancelled and stop its
    /// transient unit (killing the whole cgroup).
    fn serve_cancel(
        &self,
        mut session: softfig_net::NoiseSession<TcpStream>,
        cancel: JobCancel,
        device_id: &[u8; 32],
        accept: &AcceptConfig,
        serve: &ServeConfig,
    ) -> Result<()> {
        if let Some(reason) = self.granted(device_id, session.peer_static(), accept, serve) {
            session.send_frame(&Frame::job_reject(JobReject {
                job_id: cancel.job_id.clone(),
                reason: reason.to_u32(),
            }))?;
            return Ok(());
        }
        // Keyed by the authenticated requester, so another requester's job
        // (and a malformed id) is simply not found.
        let job = JobKey::new(*device_id, &cancel.job_id).ok().and_then(|k| self.jobs.get(&k));
        let Some(job) = job else {
            session.send_frame(&Frame::job_event(JobEvent {
                job_id: cancel.job_id.clone(),
                state: JobState::Lost as u32,
                detail: "no such job".into(),
            }))?;
            return Ok(());
        };
        job.cancelled.store(true, Ordering::SeqCst);
        if let Some(unit) = job.unit.lock().unwrap().as_ref() {
            stop_unit(self.manager, unit);
        }
        session.send_frame(&Frame::job_event(JobEvent {
            job_id: cancel.job_id.clone(),
            state: JobState::Cancelled as u32,
            detail: String::new(),
        }))?;
        Ok(())
    }

    /// Remove jobs whose TTL elapsed, plus their scratch dirs.
    fn sweep_expired(&self) {
        let expired = self.jobs.sweep(self.ttl_secs);
        for key in expired {
            let _ = std::fs::remove_dir_all(key.scratch_dir(&self.root));
        }
    }
}

/// Read the transient unit's framed log file (`job_dir/run.log`) and stream its
/// chunks into `logs` (unit-mode log capture). Best-effort: a missing or empty
/// file (no run step, or a cap-killed payload) is not an error.
fn stream_unit_log(job_dir: &std::path::Path, logs: &JobLogs) -> Result<()> {
    let path = job_dir.join("run.log");
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };
    let sink = logs.sink();
    for (stream, bytes) in read_framed_chunks(&mut f)? {
        sink.push(stream, &bytes);
    }
    Ok(())
}

/// Build the in-handshake [`RunnerHandshake`] from the stored certificate
/// (hex-string form) plus its signature.
fn build_runner_handshake(cert: &StoredCert) -> Result<RunnerHandshake> {
    let rc = softfig_net::proto::RunnerCert {
        device_id: decode_hex(&cert.device_id, "cert device_id")?.to_vec(),
        runner_transport_pubkey: decode_hex(&cert.runner_transport_pubkey, "cert transport key")?
            .to_vec(),
        runner_attest_pubkey: decode_hex(&cert.runner_attest_pubkey, "cert attest key")?.to_vec(),
        serial: decode_hex(&cert.serial, "cert serial")?.to_vec(),
        issued_at: cert.issued_at,
        expires_at: cert.expires_at,
    };
    let signature = decode_hex(&cert.signature, "cert signature")?.to_vec();
    Ok(RunnerHandshake {
        cert: Some(rc),
        signature,
    })
}

/// Decode a lowercase-hex field into a byte vector, mapping a malformed or
/// wrong-length value to a `Malformed` error naming the field.
fn decode_hex(s: &str, what: &'static str) -> Result<Vec<u8>> {
    hex::decode(s.trim()).map_err(|e| Error::malformed(what, e.to_string()))
}

/// The current time in Unix seconds (the attestation's `started_at`/`finished_at`).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the [`JobAttestation`] for a completed job (spec §8): the source id,
/// the offer fields, the toolchain, the sandbox-policy fingerprint, the exit
/// (code / signal / cap reason), the artifacts, and the log hash. The caller
/// signs it with the runner's attest key.
#[allow(clippy::too_many_arguments)]
fn build_attestation(
    offer: &softfig_net::proto::JobOffer,
    source_id: &softfig_source::SourceId,
    repo_key: &[u8; 32],
    outcome: &executor::RunOutcome,
    caps_hit: Option<CapsHit>,
    requester_device: [u8; 32],
    cert: &StoredCert,
    logs: &JobLogs,
    started_at: i64,
    finished_at: i64,
) -> Result<JobAttestation> {
    let mut env: Vec<EnvBinding> = offer
        .env
        .iter()
        .map(|e| EnvBinding { name: e.name.clone(), value: e.value.clone() })
        .collect();
    env.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    let exit = match caps_hit {
        Some(hit) => ExitInfo::reason(hit.as_str()),
        None => match outcome.signal {
            Some(sig) => ExitInfo::signal(sig),
            None => ExitInfo::code(outcome.exit_code),
        },
    };

    let artifacts = outcome
        .artifacts
        .iter()
        .map(|a| ArtifactEntry { path: a.path.clone(), size: a.size, blake3: a.blake3.clone() })
        .collect();

    Ok(JobAttestation {
        job_id: hex::encode(&offer.job_id),
        requester_device: hex::encode(requester_device),
        runner_device: cert.device_id.clone(),
        runner_cert_serial: cert.serial.clone(),
        source: SourceRef {
            format: source_id.format.as_str().to_string(),
            root: source_id.hex(),
            commit: hex::encode(&offer.snapshot_commit),
        },
        repo_key: hex::encode(repo_key),
        profile: offer.profile.clone(),
        cmd: offer.cmd.clone(),
        env,
        network: offer.network.clone(),
        cache: offer.cache.clone(),
        toolchain: outcome.toolchain.clone(),
        sandbox_policy: outcome.sandbox_policy.clone(),
        exit,
        started_at,
        finished_at,
        artifacts,
        log_blake3: hex::encode(logs.log_blake3()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::StoredCert;
    use crate::state::StateRoot;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex_id(id: &SigningKey) -> String {
        hex::encode(id.verifying_key().to_bytes())
    }

    #[test]
    fn build_handshake_decodes_hex_cert() {
        let id = SigningKey::from_bytes(&[1u8; 32]);
        let cert = StoredCert {
            device_id: hex_id(&id),
            runner_transport_pubkey: "ab".repeat(32),
            runner_attest_pubkey: "cd".repeat(32),
            serial: "ef".repeat(16),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_000 + 90 * 24 * 60 * 60,
            signature: "11".repeat(64),
        };
        let h = build_runner_handshake(&cert).unwrap();
        let c = h.cert.unwrap();
        assert_eq!(c.device_id, id.verifying_key().to_bytes().to_vec());
        assert_eq!(c.serial, vec![0xef; 16]);
        assert_eq!(h.signature, vec![0x11; 64]);
    }

    #[test]
    fn build_handshake_rejects_malformed_hex() {
        let cert = StoredCert {
            device_id: "zz".repeat(32),
            runner_transport_pubkey: "ab".repeat(32),
            runner_attest_pubkey: "cd".repeat(32),
            serial: "ef".repeat(16),
            issued_at: 0,
            expires_at: 0,
            signature: "11".repeat(64),
        };
        assert!(build_runner_handshake(&cert).is_err());
    }

    #[test]
    fn bind_generates_address_and_loads_keys() {
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path());
        root.ensure_dirs().unwrap();
        RunnerKeys::generate().persist(&root.keys_dir()).unwrap();
        let server = WireServer::bind(root, "127.0.0.1:0").unwrap();
        assert!(server.local_addr().unwrap().port() != 0);
    }

    #[test]
    fn authorize_order_and_reasons() {
        let dir = tempfile::tempdir().unwrap();
        let server = {
            let root = StateRoot::new(dir.path());
            root.ensure_dirs().unwrap();
            RunnerKeys::generate().persist(&root.keys_dir()).unwrap();
            WireServer::bind(root, "127.0.0.1:0").unwrap()
        };

        let id = SigningKey::from_bytes(&[2u8; 32]);
        let device_id = id.verifying_key().to_bytes();
        let static_ = [3u8; 32];

        let mut serve = ServeConfig::default(); // enabled: false
        let empty = AcceptConfig::default();
        let mut offer = softfig_net::proto::JobOffer {
            signature: vec![0u8; 64],
            ..Default::default()
        };

        // Disabled wins.
        assert_eq!(
            server.authorize(&offer, &device_id, &static_, &empty, &serve),
            Some(softfig_net::JobRejectReason::Disabled)
        );

        serve.enabled = true;
        // Not granted wins when enabled but absent from the allowlist.
        assert_eq!(
            server.authorize(&offer, &device_id, &static_, &empty, &serve),
            Some(softfig_net::JobRejectReason::NotGranted)
        );

        // Granted with the right static but an unsigned offer: still refused.
        let mut accept = AcceptConfig::default();
        accept.grant(crate::config::AcceptedPeer {
            device_id: hex::encode(device_id),
            transport_pubkey: hex::encode(static_),
            name: "tablet".into(),
        });
        assert_eq!(
            server.authorize(&offer, &device_id, &static_, &accept, &serve),
            Some(softfig_net::JobRejectReason::NotGranted)
        );

        // A valid offer (signed by the granted identity) is accepted.
        offer.signature = id.sign(&softfig_net::offer_signing_bytes(&offer)).to_bytes().to_vec();
        assert_eq!(server.authorize(&offer, &device_id, &static_, &accept, &serve), None);
    }
}
