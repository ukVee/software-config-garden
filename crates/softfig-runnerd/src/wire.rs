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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use softfig_net::proto::{frame, Frame, JobAccept, JobLog, JobReject, JobResult, RunnerCaps, RunnerHandshake, SourceHave};
use softfig_sandbox::JobContext;
use softfig_source::SourceBackend;

use crate::attestation::{
    ArtifactEntry, EnvBinding, ExitInfo, JobAttestation, SignedAttestation, SourceRef,
};
use crate::cert::StoredCert;
use crate::config::{AcceptConfig, ServeConfig};
use crate::error::{Error, Result};
use crate::executor::{self, SandboxBinaries};
use crate::keys::RunnerKeys;
use crate::log::{JobLogs, LogSink};
use crate::state::StateRoot;
use crate::systemd::{
    battery_reject, on_battery, run_unit, Caps, CapsHit, EnvSpec, JobReport, JobSpec, Manager,
    UnitResult, POWER_SUPPLY_PATH,
};

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

        // Advertise capabilities (public), then read the offer.
        session.send_frame(&Frame::runner_caps(self.runner_caps(&serve)))?;
        let offer = match session.recv_frame()?.kind {
            Some(frame::Kind::JobOffer(o)) => o,
            _ => return Err(Error::Protocol("expected JobOffer".into())),
        };

        match self.authorize(&offer, &device_id, session.peer_static(), &accept, &serve) {
            None => {
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
                // Slice 004: the source step — negotiate have/want, read the
                // bundle, ingest + verify (rejecting `source-mismatch`), and
                // materialize. Slice 006 then runs the real fetch → run →
                // collect sequence (in the transient unit) and returns the
                // real result.
                self.serve_source(session, &offer, &serve, on_batt, device_id, &cert)?;
            }
            Some(reason) => {
                session.send_frame(&Frame::job_reject(JobReject {
                    job_id: offer.job_id,
                    reason: reason.to_u32(),
                }))?;
            }
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
        // The handshake static must be the one `grant` recorded for this
        // identity, and the offer must be signed by that identity.
        if hex::decode(&granted.transport_pubkey).ok().as_deref() != Some(peer_static) {
            return Some(softfig_net::JobRejectReason::NotGranted);
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
        requester_device: [u8; 32],
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
        let job_dir = self.root.jobs_dir().join(hex::encode(&offer.job_id));
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

        let ctx = JobContext {
            src: src_dir,
            target_cache,
            toolchain: self.root.rustup_home(),
            cargo_home: self.root.cargo_home_dir(),
            etc: std::path::PathBuf::from("/etc"),
            scratch_size: executor::parse_size(&serve.scratch_max)?,
        };
        // bwrap binds require the source paths to exist.
        std::fs::create_dir_all(&ctx.cargo_home)?;
        std::fs::create_dir_all(&ctx.target_cache)?;

        // Split the Noise session: the source transfer is done, and from here the
        // runner only sends (live logs, then the result). The drain thread owns
        // the write half and streams `JobLog` frames as the run produces them;
        // it hands the writer back once the log channel closes.
        let (reader, writer) = session
            .split()
            .map_err(|e| Error::Protocol(format!("session split: {e}")))?;
        drop(reader);

        let (mut logs, rx) = JobLogs::new();
        let job_id = offer.job_id.clone();
        let drain = std::thread::spawn(move || {
            let mut w = writer;
            for chunk in rx {
                if w.send_frame(&Frame::job_log(JobLog {
                    job_id: job_id.clone(),
                    seq: chunk.seq,
                    stream: chunk.stream as u32,
                    bytes: chunk.bytes,
                }))
                .is_err()
                {
                    // The requester disconnected mid-run; stop streaming (the
                    // job runs to completion regardless — detach is chunk 4).
                    break;
                }
            }
            w
        });

        // Direct mode streams the run step's output live into the sink; the
        // transient-unit path buffers (unit log capture + attach/cancel land in
        // chunk 4).
        let log = match self.manager {
            Manager::Direct => Some(logs.sink()),
            Manager::System | Manager::User => None,
        };
        let started_at = now_unix();
        let run = self.run_job(&ctx, serve, offer, on_battery, &job_dir, log.as_ref());
        let finished_at = now_unix();

        // Every producer clone is dropped when run_job returns; drop our sink
        // clone and then close the master sender so the drain thread's channel
        // closes and it hands back the writer.
        drop(log);
        logs.close();
        let writer = match drain.join() {
            Ok(w) => w,
            Err(_) => return Err(Error::Protocol("log drain thread panicked".into())),
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
                let attestation = build_attestation(
                    offer,
                    &source_id,
                    &repo_key,
                    &outcome,
                    caps_hit,
                    requester_device,
                    cert,
                    &logs,
                    started_at,
                    finished_at,
                )?;
                let signature = attestation.sign(&self.attest_signing)?;
                let signed = SignedAttestation { attestation, signature: hex::encode(signature) };
                let mut w = writer;
                w.send_frame(&Frame::job_result(JobResult {
                    job_id: offer.job_id.clone(),
                    exit_code: outcome.exit_code,
                    attestation: signed.to_bytes()?,
                }))?;
            }
            Err(Error::ToolchainMissing(add_cmd)) => {
                // The `JobReject` frame has no message field, so the exact
                // `softfig runner toolchain add <spec>` rides the runner log.
                eprintln!(
                    "softfig-runnerd: job {} rejected (toolchain-missing): {add_cmd}",
                    hex::encode(&offer.job_id)
                );
                let mut w = writer;
                w.send_frame(&Frame::job_reject(JobReject {
                    job_id: offer.job_id.clone(),
                    reason: softfig_net::JobRejectReason::ToolchainMissing.to_u32(),
                }))?;
            }
            Err(e) => return Err(e),
        }

        // Best-effort cleanup of the per-job scratch (the shared target cache
        // stays; a fresh cache dies with the job, spec §6 step 8).
        let _ = std::fs::remove_dir_all(&job_dir);
        Ok(())
    }

    /// Run a job's fetch → run → collect: in-process (the `Direct` test seam)
    /// or inside the transient unit (production + loopback).
    fn run_job(
        &self,
        ctx: &JobContext,
        serve: &ServeConfig,
        offer: &softfig_net::proto::JobOffer,
        on_battery: bool,
        job_dir: &std::path::Path,
        log: Option<&LogSink>,
    ) -> Result<(executor::RunOutcome, Option<CapsHit>)> {
        match self.manager {
            Manager::Direct => {
                executor::execute(ctx, serve, offer, &self.sandbox_bins, log).map(|o| (o, None))
            }
            Manager::System | Manager::User => {
                self.run_in_unit(ctx, serve, offer, on_battery, job_dir)
            }
        }
    }

    /// Run the executor inside a `systemd-run` transient unit: serialize the
    /// job spec, re-invoke runnerd with `--run-job`, and read its report.
    fn run_in_unit(
        &self,
        ctx: &JobContext,
        serve: &ServeConfig,
        offer: &softfig_net::proto::JobOffer,
        on_battery: bool,
        job_dir: &std::path::Path,
    ) -> Result<(executor::RunOutcome, Option<CapsHit>)> {
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
        let unit = format!("softfig-runner-{}", hex::encode(&offer.job_id));
        let payload = vec![
            self.runnerd_bin.display().to_string(),
            "--run-job".to_string(),
            spec_path.display().to_string(),
            result_path.display().to_string(),
        ];
        let (unit_result, _code) = run_unit(
            self.manager,
            &unit,
            &caps,
            &payload,
            &[self.root.root().to_path_buf()],
        )?;

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
