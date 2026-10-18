//! Remote-runner wire support (spec remote-runner §3.3, §11): the requester
//! side of a one-connection-per-job session, first-contact certificate
//! verification, the never-committed `.softfig/runners.toml` sidecar, and the
//! `JobOffer` / `RunnerCertRevoke` signing bytes.
//!
//! This crate stays frontend-neutral and holds **no signing secrets**. The
//! requester's Ed25519 identity secret lives in keeperd's vault; keeperd signs
//! a `JobOffer` with [`offer_signing_bytes`] (like it precomputes the transport
//! attestation for [`crate::pairing::LocalDevice`]) and passes the signature in.
//! The runner certificate is *verified* here (never signed): signing goes
//! through keeperd's `runner_sign_cert` (slice 002), which holds the device
//! identity secret.
//!
//! protobuf is not canonical: a signed frame's signature is over
//! domain-separated, length-prefixed bytes re-derived from the fields, never a
//! re-serialization (same discipline as `turn` / `ceremony` / `offer`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::attest::{KEY_LEN, SIG_LEN};
use crate::error::{NetError, Result};
use crate::pairing::LocalDevice;
use crate::proto::{self, frame, Frame, JobEvent, JobLog, JobOffer, JobResult, RunnerCaps, RunnerCertRevoke, SourceChunk};
use crate::runner_cert::{self, RUNNER_SERIAL_LEN};
use crate::transport::{runner_ik_initiator, runner_xx_initiator, RunnerSession};

// --- Closed reason enum (spec §6) -----------------------------------------

/// The closed list of `JobReject` reasons (spec §6 step 1). The discriminant is
/// the wire value; an unknown value is read as "other", never as success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobRejectReason {
    /// The requester is not in the runner's `accept.toml`.
    NotGranted = 1,
    /// The runner is disabled.
    Disabled = 2,
    /// The runner is draining (stopping).
    Draining = 3,
    /// The runner's queue is full and the wait timed out.
    BusyTimeout = 4,
    /// On battery and `on_battery = "refuse"`.
    OnBattery = 5,
    /// The requested toolchain is not installed.
    ToolchainMissing = 6,
    /// The requested limits exceed `[serve]`.
    LimitsExceed = 7,
    /// The offered source id does not match the ingested tree.
    SourceMismatch = 8,
}

impl JobRejectReason {
    /// The wire value (field 2 of `JobReject`).
    pub fn to_u32(self) -> u32 {
        self as u32
    }

    /// Parse a wire value. `None` on an unknown discriminant — the caller must
    /// treat an unknown reason as a rejection, never as success.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::NotGranted),
            2 => Some(Self::Disabled),
            3 => Some(Self::Draining),
            4 => Some(Self::BusyTimeout),
            5 => Some(Self::OnBattery),
            6 => Some(Self::ToolchainMissing),
            7 => Some(Self::LimitsExceed),
            8 => Some(Self::SourceMismatch),
            _ => None,
        }
    }

    /// The reason's wire name (spec §6), for logs and rejection surfaces.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotGranted => "not-granted",
            Self::Disabled => "disabled",
            Self::Draining => "draining",
            Self::BusyTimeout => "busy-timeout",
            Self::OnBattery => "on-battery",
            Self::ToolchainMissing => "toolchain-missing",
            Self::LimitsExceed => "limits-exceed",
            Self::SourceMismatch => "source-mismatch",
        }
    }
}

/// The job lifecycle states (spec remote-runner §6). The discriminant is the
/// `JobEvent.state` wire value. `Lost` is the terminal state for a job the
/// runner no longer holds (expired past the TTL).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Queued = 0,
    Ingesting = 1,
    Fetching = 2,
    Running = 3,
    Collecting = 4,
    Done = 5,
    Failed = 6,
    Cancelled = 7,
    Lost = 8,
}

// --- Certificate conversion + verification --------------------------------

/// Decode a fixed-size byte field, mapping a wrong length to a protocol error.
fn fixed<const N: usize>(b: &[u8], what: &'static str) -> Result<[u8; N]> {
    b.try_into().map_err(|_| NetError::Protocol(what))
}

impl TryFrom<proto::RunnerCert> for runner_cert::RunnerCert {
    type Error = NetError;

    fn try_from(m: proto::RunnerCert) -> Result<Self> {
        Ok(runner_cert::RunnerCert {
            device_id: fixed::<KEY_LEN>(&m.device_id, "runner cert device_id wrong length")?,
            runner_transport_pubkey: fixed::<KEY_LEN>(
                &m.runner_transport_pubkey,
                "runner cert transport key wrong length",
            )?,
            runner_attest_pubkey: fixed::<KEY_LEN>(
                &m.runner_attest_pubkey,
                "runner cert attest key wrong length",
            )?,
            serial: fixed::<RUNNER_SERIAL_LEN>(&m.serial, "runner cert serial wrong length")?,
            issued_at: m.issued_at,
            expires_at: m.expires_at,
        })
    }
}

/// Verify a runner's handshake certificate against a ring identity, the revoked
/// serials, and the handshake's authenticated static key. The cert itself
/// (signature, expiry, identity, serial) is checked by
/// [`runner_cert::verify`]; this additionally binds the certificate to *this*
/// handshake by requiring `handshake_static == cert.runner_transport_pubkey`.
/// Returns `false` on any failure — a certificate that fails verification never
/// gets a job (it is a local-fallback trigger, slice 007).
pub fn verify_runner_handshake(
    cert: &runner_cert::RunnerCert,
    signature: &[u8; SIG_LEN],
    ring_identity: &[u8; KEY_LEN],
    now: i64,
    revoked_serials: &[[u8; RUNNER_SERIAL_LEN]],
    handshake_static: &[u8; KEY_LEN],
) -> bool {
    runner_cert::verify(cert, signature, ring_identity, now, revoked_serials)
        && &cert.runner_transport_pubkey == handshake_static
}

/// Verify a `RunnerCertRevoke` frame: the signature is the *device identity*'s
/// over [`runner_cert::revocation_message`], so a stolen runner key cannot
/// revoke itself (spec §3.1). Never panics.
pub fn verify_runner_cert_revoke(revoke: &RunnerCertRevoke) -> bool {
    let Ok(device_id) = fixed::<KEY_LEN>(&revoke.device_id, "revoke device_id wrong length")
    else {
        return false;
    };
    let Ok(serial) = fixed::<RUNNER_SERIAL_LEN>(&revoke.serial, "revoke serial wrong length")
    else {
        return false;
    };
    let Ok(sig) = <[u8; SIG_LEN]>::try_from(revoke.signature.as_slice()) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&device_id) else {
        return false;
    };
    vk.verify(
        &runner_cert::revocation_message(&device_id, &serial),
        &Signature::from_bytes(&sig),
    )
    .is_ok()
}

// --- JobOffer signing -----------------------------------------------------

/// Domain-separation prefix for the `JobOffer` signature.
const JOB_OFFER_DOMAIN: &[u8] = b"softfig/runner/job-offer/v1";

fn put_len(m: &mut Vec<u8>, n: usize) {
    m.extend_from_slice(&(n as u32).to_be_bytes());
}

fn put_bytes(m: &mut Vec<u8>, b: &[u8]) {
    put_len(m, b.len());
    m.extend_from_slice(b);
}

fn put_str(m: &mut Vec<u8>, s: &str) {
    put_bytes(m, s.as_bytes());
}

/// The exact bytes a requester's Ed25519 identity signs to issue a `JobOffer`.
/// Covers every field except the signature itself; `env` is sorted by name so
/// the bytes are canonical regardless of map/entry order. The verifier
/// re-derives these bytes from the received fields.
pub fn offer_signing_bytes(offer: &JobOffer) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(JOB_OFFER_DOMAIN);
    put_bytes(&mut m, &offer.job_id);
    put_bytes(&mut m, &offer.repo_key);
    put_bytes(&mut m, &offer.source_id);
    put_bytes(&mut m, &offer.snapshot_commit);
    put_str(&mut m, &offer.profile);
    for c in &offer.cmd {
        put_str(&mut m, c);
    }
    let mut env: Vec<(&str, &str)> = offer
        .env
        .iter()
        .map(|e| (e.name.as_str(), e.value.as_str()))
        .collect();
    env.sort_unstable();
    for (name, value) in env {
        put_str(&mut m, name);
        put_str(&mut m, value);
    }
    put_str(&mut m, &offer.toolchain);
    put_str(&mut m, &offer.network);
    put_str(&mut m, &offer.cache);
    for a in &offer.artifacts {
        put_str(&mut m, a);
    }
    m.extend_from_slice(&offer.requested_at.to_le_bytes());
    m
}

/// Verify a `JobOffer` signature against the requester's Ed25519 identity key.
/// Never panics — a bad key, wrong-length signature, or a non-verifying
/// signature all return `false`. Proves *who* offered; the allowlist check
/// (`accept.toml`) is the runner's separate job.
pub fn verify_offer_sig(offer: &JobOffer, requester_id: &[u8; KEY_LEN], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(requester_id) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; SIG_LEN]>::try_from(sig) else {
        return false;
    };
    vk.verify(
        &offer_signing_bytes(offer),
        &Signature::from_bytes(&sig_bytes),
    )
    .is_ok()
}

// --- The never-committed sidecar: `.softfig/runners.toml` -----------------

/// Filename of the runner-certificate sidecar within `.softfig/`.
pub const RUNNER_CACHE_FILE: &str = "runners.toml";

/// Path to the sidecar for a given state root:
/// `<state_root>/.softfig/runners.toml`. Like `peers-endpoints.toml`, it is
/// volatile (certificates can be re-learned by re-running `XX`) and never
/// committed.
pub fn runner_cache_path(state_root: &Path) -> PathBuf {
    state_root.join(".softfig").join(RUNNER_CACHE_FILE)
}

/// One cached, previously-verified runner certificate plus its signature. The
/// `cert` serializes to its hex-string wire form; `signature` is the device
/// identity's Ed25519 signature as lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedRunner {
    pub cert: runner_cert::RunnerCert,
    pub signature: String,
}

impl CachedRunner {
    /// The signature bytes, decoded from hex. `None` on a malformed (tampered)
    /// cache entry — the caller treats that as "no cache".
    pub fn signature_bytes(&self) -> Option<[u8; SIG_LEN]> {
        let bytes = hex::decode(self.signature.trim()).ok()?;
        bytes.try_into().ok()
    }
}

/// The requester's runner-certificate cache + revoked serials, keyed by the
/// runner device's lowercase-hex `device_id`. `BTreeMap` keeps the on-disk key
/// order stable. Never committed; a lost cache costs one extra `XX` handshake.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunnerCache {
    /// `device_id` (lowercase hex) → the last verified certificate.
    #[serde(default)]
    runners: BTreeMap<String, CachedRunner>,
    /// Revoked serials (lowercase hex), across all runner devices. Filled by
    /// `RunnerCertRevoke` fan-out and checked during certificate verification.
    #[serde(default)]
    revoked_serials: Vec<String>,
}

impl RunnerCache {
    /// Load the sidecar. A missing file is an empty cache.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }

    /// Atomically write the sidecar (temp + rename), creating `.softfig/`.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(self)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        fs::write(&tmp, raw)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// The cached certificate for `device_id` (hex), if any.
    pub fn get(&self, device_id: &str) -> Option<&CachedRunner> {
        self.runners.get(device_id)
    }

    /// Store (or refresh) a verified certificate for `device_id` (hex).
    pub fn put(&mut self, device_id: &str, cached: CachedRunner) {
        self.runners.insert(device_id.to_string(), cached);
    }

    /// Record a revoked serial (deduplicated). Returns `true` if it was new.
    pub fn revoke(&mut self, serial_hex: &str) -> bool {
        if self.revoked_serials.iter().any(|s| s == serial_hex) {
            return false;
        }
        self.revoked_serials.push(serial_hex.to_string());
        true
    }

    /// The revoked serials as byte arrays for verification.
    pub fn revoked_serial_bytes(&self) -> Vec<[u8; RUNNER_SERIAL_LEN]> {
        self.revoked_serials
            .iter()
            .filter_map(|s| {
                let b = hex::decode(s).ok()?;
                b.try_into().ok()
            })
            .collect()
    }

    /// Whether `serial` (bytes) is revoked.
    pub fn is_serial_revoked(&self, serial: &[u8; RUNNER_SERIAL_LEN]) -> bool {
        self.revoked_serials.iter().any(|s| s == &hex::encode(serial))
    }

    pub fn is_empty(&self) -> bool {
        self.runners.is_empty() && self.revoked_serials.is_empty()
    }
}

// --- Requester client -----------------------------------------------------

/// The outcome of one job offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    /// The runner accepted and (in slice 003) returned a stub [`JobResult`].
    Accepted(JobResult),
    /// The runner refused, with the closed reason.
    Rejected(JobRejectReason),
}

/// Connect to a runner for one job (spec §3.3): `XX` on first contact, `IK` on
/// reconnect (keyed by the cached static). Verifies the certificate — signature
/// against the runner device's ring identity, expiry, revoked serials, and the
/// handshake-static binding — and returns the session plus the verified cert so
/// the caller can (re)cache it. A certificate that fails verification is a
/// [`NetError::RunnerCert`], never a job.
pub fn connect_runner<S: Read + Write>(
    io: S,
    local: &LocalDevice,
    ring_identity: &[u8; KEY_LEN],
    cached: Option<&CachedRunner>,
    revoked_serials: &[[u8; RUNNER_SERIAL_LEN]],
    now: i64,
) -> Result<(RunnerSession<S>, runner_cert::RunnerCert)> {
    let session = match cached {
        Some(c) => runner_ik_initiator(
            io,
            &local.transport_secret,
            &c.cert.runner_transport_pubkey,
            &local.hello(),
        )?,
        None => runner_xx_initiator(io, &local.transport_secret, &local.hello())?,
    };
    let cert = runner_cert::RunnerCert::try_from(session.cert().clone())?;
    if !verify_runner_handshake(
        &cert,
        session.signature(),
        ring_identity,
        now,
        revoked_serials,
        session.peer_static(),
    ) {
        return Err(NetError::RunnerCert(
            "runner certificate failed verification".into(),
        ));
    }
    Ok((session, cert))
}

/// Run one job over an established runner session, including the source
/// transfer (spec §4.3, §6): read the runner's [`RunnerCaps`], send the signed
/// [`JobOffer`], read [`JobAccept`]/[`JobReject`], then — on accept — read the
/// runner's [`SourceHave`] and stream the have/want bundle (produced by
/// `make_bundle`) as [`SourceChunk`]s before reading the [`JobResult`] (or a
/// [`JobReject`] carrying `source-mismatch`). The caller signs the offer
/// (keeperd holds the secret); `make_bundle` receives the runner's tips +
/// parents and returns the bundle bytes (`softfig_source::create_bundle`).
pub fn run_job<S, F, E>(
    session: &mut RunnerSession<S>,
    offer: &JobOffer,
    make_bundle: F,
) -> Result<(RunnerCaps, JobOutcome)>
where
    S: Read + Write,
    F: FnOnce(&[Vec<u8>]) -> std::result::Result<Vec<u8>, E>,
    E: std::fmt::Display,
{
    let (caps, outcome, _logs, _events) = run_job_inner(session, offer, make_bundle)?;
    Ok((caps, outcome))
}

/// [`run_job`], but also returns the live `JobLog`/`JobEvent` frames the runner
/// streamed before the result. The `JobOutcome` (accept/reject) is unchanged;
/// this is the collector variant the log-rendering surface (slice 007) and the
/// loopback streaming test use.
pub fn run_job_collecting<S, F, E>(
    session: &mut RunnerSession<S>,
    offer: &JobOffer,
    make_bundle: F,
) -> Result<(RunnerCaps, JobOutcome, Vec<JobLog>, Vec<JobEvent>)>
where
    S: Read + Write,
    F: FnOnce(&[Vec<u8>]) -> std::result::Result<Vec<u8>, E>,
    E: std::fmt::Display,
{
    run_job_inner(session, offer, make_bundle)
}

/// Drive one job, reading the interleaved [`JobLog`]/[`JobEvent`] frames the
/// runner streams ahead of the terminal [`JobResult`]/[`JobReject`] (spec §6).
fn run_job_inner<S, F, E>(
    session: &mut RunnerSession<S>,
    offer: &JobOffer,
    make_bundle: F,
) -> Result<(RunnerCaps, JobOutcome, Vec<JobLog>, Vec<JobEvent>)>
where
    S: Read + Write,
    F: FnOnce(&[Vec<u8>]) -> std::result::Result<Vec<u8>, E>,
    E: std::fmt::Display,
{
    let caps = match session.recv_frame()?.kind {
        Some(frame::Kind::RunnerCaps(c)) => c,
        _ => return Err(NetError::Protocol("expected RunnerCaps after handshake")),
    };
    session.send_frame(&Frame::job_offer(offer.clone()))?;
    let mut logs = Vec::new();
    let mut events = Vec::new();
    match session.recv_frame()?.kind {
        Some(frame::Kind::JobAccept(_)) => {
            let haves = match session.recv_frame()?.kind {
                Some(frame::Kind::SourceHave(h)) => h,
                _ => return Err(NetError::Protocol("expected SourceHave after JobAccept")),
            };
            let mut have_list: Vec<Vec<u8>> = Vec::new();
            have_list.extend(haves.tips);
            have_list.extend(haves.recent_commits);
            let bundle = make_bundle(&have_list).map_err(|e| NetError::Source(e.to_string()))?;
            stream_chunks(session, &offer.job_id, &bundle)?;
            // The runner streams JobLog/JobEvent frames before the terminal
            // JobResult/JobReject; consume them in arrival order.
            loop {
                match session.recv_frame()?.kind {
                    Some(frame::Kind::JobResult(r)) => {
                        return Ok((caps, JobOutcome::Accepted(r), logs, events));
                    }
                    Some(frame::Kind::JobReject(r)) => {
                        let reason = JobRejectReason::from_u32(r.reason).ok_or(
                            NetError::Protocol("runner sent an unknown reject reason"),
                        )?;
                        return Ok((caps, JobOutcome::Rejected(reason), logs, events));
                    }
                    Some(frame::Kind::JobLog(l)) => logs.push(l),
                    Some(frame::Kind::JobEvent(e)) => events.push(e),
                    _ => {
                        return Err(NetError::Protocol(
                            "expected JobResult or JobReject after transfer",
                        ));
                    }
                }
            }
        }
        Some(frame::Kind::JobReject(r)) => {
            let reason = JobRejectReason::from_u32(r.reason)
                .ok_or(NetError::Protocol("runner sent an unknown reject reason"))?;
            Ok((caps, JobOutcome::Rejected(reason), logs, events))
        }
        _ => Err(NetError::Protocol("expected JobAccept or JobReject")),
    }
}

/// Stream `bundle` as [`SourceChunk`] frames (bounded chunks, `seq` + `last`).
fn stream_chunks<S: Read + Write>(
    session: &mut RunnerSession<S>,
    job_id: &[u8],
    bundle: &[u8],
) -> Result<()> {
    const CHUNK: usize = 256 * 1024;
    let chunks: Vec<&[u8]> = if bundle.is_empty() {
        vec![bundle]
    } else {
        bundle.chunks(CHUNK).collect()
    };
    let n = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        session.send_frame(&Frame::source_chunk(SourceChunk {
            job_id: job_id.to_vec(),
            seq: i as u64,
            last: i == n - 1,
            payload: chunk.to_vec(),
        }))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{EnvEntry, JobOffer};
    use ed25519_dalek::{Signer, SigningKey};

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn offer() -> JobOffer {
        JobOffer {
            job_id: vec![0xAB; 16],
            repo_key: vec![0x11; 32],
            source_id: vec![0x22; 32],
            snapshot_commit: vec![0x33; 32],
            profile: "gate".into(),
            cmd: vec!["cargo".into(), "test".into()],
            env: vec![
                EnvEntry {
                    name: "B".into(),
                    value: "2".into(),
                },
                EnvEntry {
                    name: "A".into(),
                    value: "1".into(),
                },
            ],
            toolchain: "rust".into(),
            network: "none".into(),
            cache: "shared".into(),
            artifacts: vec!["target/release/softfig".into()],
            requested_at: 1_800_000_000,
            signature: Vec::new(),
        }
    }

    #[test]
    fn offer_sign_then_verify_round_trips() {
        let id = sk(1);
        let o = offer();
        let sig = id.sign(&offer_signing_bytes(&o)).to_bytes();
        assert!(verify_offer_sig(&o, &id.verifying_key().to_bytes(), &sig));
    }

    #[test]
    fn offer_env_order_is_canonical() {
        // The same logical offer with env in a different order signs the same
        // bytes (env is sorted by name), so a reordered message still verifies.
        let mut a = offer();
        let mut b = offer();
        b.env.reverse();
        assert_eq!(offer_signing_bytes(&a), offer_signing_bytes(&b));
        let _ = &mut a;
    }

    #[test]
    fn offer_tampered_field_fails() {
        let id = sk(2);
        let o = offer();
        let sig = id.sign(&offer_signing_bytes(&o)).to_bytes();
        let mut tampered = offer();
        tampered.cmd = vec!["cargo".into(), "build".into()];
        assert!(!verify_offer_sig(
            &tampered,
            &id.verifying_key().to_bytes(),
            &sig
        ));
    }

    #[test]
    fn offer_signed_by_wrong_key_fails() {
        let o = offer();
        let other = sk(3);
        let sig = other.sign(&offer_signing_bytes(&o)).to_bytes();
        let claimed = sk(4).verifying_key().to_bytes();
        assert!(!verify_offer_sig(&o, &claimed, &sig));
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // Shifting a byte across the profile/cmd boundary produces different
        // signed bytes (length-prefixing, not concatenation).
        let a = offer_signing_bytes(&JobOffer {
            profile: "ab".into(),
            cmd: vec!["cd".into()],
            ..offer()
        });
        let b = offer_signing_bytes(&JobOffer {
            profile: "a".into(),
            cmd: vec!["bcd".into()],
            ..offer()
        });
        assert_ne!(a, b);
    }

    #[test]
    fn runner_cache_round_trips_and_tracks_revocations() {
        let id = sk(5);
        let cert = runner_cert::RunnerCert {
            device_id: id.verifying_key().to_bytes(),
            runner_transport_pubkey: [1u8; 32],
            runner_attest_pubkey: [2u8; 32],
            serial: [9u8; RUNNER_SERIAL_LEN],
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_000 + 90 * 24 * 60 * 60,
        };
        let sig = id.sign(&cert.signing_message()).to_bytes();

        let mut cache = RunnerCache::default();
        cache.put(
            &hex::encode(cert.device_id),
            CachedRunner {
                cert: cert.clone(),
                signature: hex::encode(sig),
            },
        );
        assert!(cache.revoke(&hex::encode(cert.serial)));
        assert!(!cache.revoke(&hex::encode(cert.serial))); // dedup

        assert_eq!(
            cache.get(&hex::encode(cert.device_id)).unwrap().cert,
            cert
        );
        assert!(cache.is_serial_revoked(&cert.serial));
        assert_eq!(cache.revoked_serial_bytes().len(), 1);

        // Round-trip through the sidecar.
        let dir = tempfile::tempdir().unwrap();
        let path = runner_cache_path(dir.path());
        cache.save(&path).unwrap();
        let loaded = RunnerCache::load(&path).unwrap();
        assert!(loaded.is_serial_revoked(&cert.serial));
        assert_eq!(
            loaded.get(&hex::encode(cert.device_id)).unwrap().cert,
            cert
        );
    }

    #[test]
    fn revoke_frame_verifies_and_rejects_forgery() {
        let id = sk(6);
        let device_id = id.verifying_key().to_bytes();
        let serial = [7u8; RUNNER_SERIAL_LEN];
        let sig = id
            .sign(&runner_cert::revocation_message(&device_id, &serial))
            .to_bytes();

        let good = RunnerCertRevoke {
            device_id: device_id.to_vec(),
            serial: serial.to_vec(),
            signature: sig.to_vec(),
        };
        assert!(verify_runner_cert_revoke(&good));

        // A runner (attest) key cannot forge a revocation — only the identity
        // key's signature verifies.
        let forged = RunnerCertRevoke {
            device_id: device_id.to_vec(),
            serial: serial.to_vec(),
            signature: sk(8)
                .sign(&runner_cert::revocation_message(&device_id, &serial))
                .to_bytes()
                .to_vec(),
        };
        assert!(!verify_runner_cert_revoke(&forged));
    }
}
