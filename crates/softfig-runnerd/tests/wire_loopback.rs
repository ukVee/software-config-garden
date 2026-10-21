//! Loopback integration test for the runner wire (spec remote-runner §3.3,
//! §11): a real `WireServer` on a temp state root, driven over loopback TCP by
//! a real requester (`softfig_net::connect_runner` + `run_job`).
//!
//! Covers the slice-003 "done when" plus slice-006 chunk 1: the happy path
//! (offer → accept → the real `JobResult`), a `toolchain-missing` reject, a
//! full loopback fetch → build → collect, an unknown requester refused, an
//! expired certificate refused,
//! a revoked serial refused, an offer signed by the wrong key refused, and a
//! second connection using `IK`. mDNS announce/browse is a manual smoke (needs
//! multicast on a real interface); its pure TXT encode/parse is unit-tested in
//! `softfig-net`'s `discovery` module.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use softfig_net::proto::{frame, Frame, JobAttach, JobCancel, JobLog};
use softfig_net::runner_cert::RunnerCert;
use softfig_net::{
    offer_signing_bytes, run_job_collecting, run_remote, static_attestation_message, testing,
    CachedRunner, JobOutcome, JobRejectReason, JobState, LocalDevice, RunFailure, RunnerCache,
};
use softfig_source::{create_bundle, repo_key, root_commits, snapshot_repo, SubmodulePolicy};
use softfig_runnerd::cert::StoredCert;
use softfig_runnerd::config::{AcceptConfig, AcceptedPeer, ServeConfig};
use softfig_runnerd::keys::RunnerKeys;
use softfig_runnerd::state::StateRoot;
use softfig_runnerd::wire::WireServer;
use softfig_runnerd::{Manager, SandboxBinaries};

/// A fixed "now" so certificate expiry is deterministic.
const NOW: i64 = 1_800_000_000;

fn xpub(secret: [u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// A requester: Ed25519 identity + X25519 transport static + self-attestation.
struct Requester {
    id: SigningKey,
    transport_secret: [u8; 32],
    device_id: [u8; 32],
    transport_pubkey: [u8; 32],
}

impl Requester {
    fn new(id_seed: u8, tk_seed: u8) -> Self {
        let id = SigningKey::from_bytes(&[id_seed; 32]);
        let transport_secret = [tk_seed; 32];
        Self {
            device_id: id.verifying_key().to_bytes(),
            transport_pubkey: xpub(transport_secret),
            id,
            transport_secret,
        }
    }

    fn local(&self) -> LocalDevice {
        let attestation = self
            .id
            .sign(&static_attestation_message(&self.transport_pubkey))
            .to_bytes();
        LocalDevice {
            transport_secret: self.transport_secret,
            device_id: self.device_id,
            device_name: "requester".into(),
            static_attestation: attestation,
        }
    }

    fn sign_offer(&self, offer: &softfig_net::proto::JobOffer) -> Vec<u8> {
        self.id.sign(&offer_signing_bytes(offer)).to_bytes().to_vec()
    }
}

/// A runner fixture: temp state root with keys, a signed certificate, an
/// enabled `serve.toml`, and a bound `WireServer`.
struct RunnerFixture {
    _dir: Option<tempfile::TempDir>,
    _shm_root: Option<PathBuf>,
    root: StateRoot,
    server: Arc<WireServer>,
    signer: SigningKey,
    cert: RunnerCert,
}

impl RunnerFixture {
    fn new(serial: [u8; 16], expires_at: i64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path());
        let (server, signer, cert) = Self::setup(
            root.clone(),
            serial,
            expires_at,
            Manager::Direct,
            std::env::current_exe().unwrap(),
        );
        Self {
            _dir: Some(dir),
            _shm_root: None,
            root,
            server,
            signer,
            cert,
        }
    }

    /// A runner whose jobs run in `systemd-run --user` transient units, rooted
    /// under `/dev/shm` (not `/tmp`, which the unit's `PrivateTmp` hides from
    /// its payload). `shm_root` must already be a fresh, writable dir; the
    /// caller removes it.
    fn new_transient_unit(shm_root: PathBuf, serial: [u8; 16], expires_at: i64) -> Self {
        let root = StateRoot::new(&shm_root);
        let staged = stage_runnerd(&shm_root);
        let (server, signer, cert) = Self::setup(
            root.clone(),
            serial,
            expires_at,
            Manager::User,
            staged,
        );
        Self {
            _dir: None,
            _shm_root: Some(shm_root),
            root,
            server,
            signer,
            cert,
        }
    }

    /// Shared setup: state-root dirs, keys, a signed certificate, an enabled
    /// `serve.toml`, and a `WireServer` bound with the given manager.
    fn setup(
        root: StateRoot,
        serial: [u8; 16],
        expires_at: i64,
        manager: Manager,
        runnerd_bin: PathBuf,
    ) -> (Arc<WireServer>, SigningKey, RunnerCert) {
        root.ensure_dirs().unwrap();
        let keys = RunnerKeys::generate();
        keys.persist(&root.keys_dir()).unwrap();

        let signer = SigningKey::from_bytes(&[0x42; 32]);
        let cert = RunnerCert {
            device_id: signer.verifying_key().to_bytes(),
            runner_transport_pubkey: keys.transport_pubkey(),
            runner_attest_pubkey: keys.attest_pubkey(),
            serial,
            issued_at: NOW - 100,
            expires_at,
        };
        let cert_sig = signer.sign(&cert.signing_message()).to_bytes();

        StoredCert {
            device_id: hex::encode(cert.device_id),
            runner_transport_pubkey: hex::encode(cert.runner_transport_pubkey),
            runner_attest_pubkey: hex::encode(cert.runner_attest_pubkey),
            serial: hex::encode(cert.serial),
            issued_at: cert.issued_at,
            expires_at: cert.expires_at,
            signature: hex::encode(cert_sig),
        }
        .save(&root.cert_toml())
        .unwrap();

        let serve = ServeConfig {
            enabled: true,
            toolchains: vec!["rust".into()],
            egress: vec![
                "index.crates.io".into(),
                "static.crates.io".into(),
                "crates.io".into(),
                "github.com".into(),
                "codeload.github.com".into(),
            ],
            ..ServeConfig::default()
        };
        serve.save(&root.serve_toml()).unwrap();

        let mut server =
            WireServer::bind_with_bins(root.clone(), "127.0.0.1:0", sandbox_bins()).unwrap();
        server.set_manager(manager);
        if !matches!(manager, Manager::Direct) {
            server.set_runnerd_bin(runnerd_bin);
        }
        (Arc::new(server), signer, cert)
    }

    /// The runner device's ring identity (the cert's signing device).
    fn ring_identity(&self) -> [u8; 32] {
        self.signer.verifying_key().to_bytes()
    }

    /// The bound job-listener address.
    fn addr(&self) -> String {
        self.server.local_addr().unwrap().to_string()
    }

    /// Grant a requester into `accept.toml`.
    fn grant(&self, req: &Requester) {
        let mut accept = AcceptConfig::load(&self.root.accept_toml()).unwrap();
        accept.grant(AcceptedPeer {
            device_id: hex::encode(req.device_id),
            transport_pubkey: hex::encode(req.transport_pubkey),
            name: "requester".into(),
        });
        accept.save(&self.root.accept_toml()).unwrap();
    }

    /// Spawn a thread that accepts one connection and serves it.
    fn serve_one(&self) {
        let s = Arc::clone(&self.server);
        std::thread::spawn(move || {
            let stream = testing::accept_within(s.listener(), "runner");
            let _ = s.serve_connection(stream);
        });
    }
}

/// The built `softfig-runnerd` binary, beside this test's target dir (the
/// transient unit's `--run-job` payload).
fn runnerd_bin() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join("softfig-runnerd")
}

/// Stage the runnerd binary into `dir` (non-`/tmp`, so the unit's `PrivateTmp`
/// doesn't hide it) and return the staged path.
fn stage_runnerd(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let src = runnerd_bin();
    assert!(src.exists(), "build softfig-runnerd first: {}", src.display());
    let dst = dir.join("softfig-runnerd");
    std::fs::copy(&src, &dst).unwrap();
    let mut perms = std::fs::metadata(&dst).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&dst, perms).unwrap();
    dst
}

/// The sandbox helper binaries live beside this test's own target dir:
/// `<target>/<profile>/deps/<test-binary>` → `<target>/<profile>/<name>`.
fn sandbox_bins() -> SandboxBinaries {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap();
    SandboxBinaries::new(
        profile_dir.join("softfig-sandbox-init"),
        profile_dir.join("softfig-sandbox-forward"),
        profile_dir.join("softfig-sandbox-collect"),
    )
}

/// `true` when the sandbox preconditions for the loopback executor test are
/// unmet, after printing a loud skip.
fn sandbox_skip() -> bool {
    if !Command::new("bwrap").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
        || !Command::new("unshare").args(["-Ur", "true"]).status().map(|s| s.success()).unwrap_or(false)
    {
        eprintln!("SKIPPED: bwrap or user namespaces unavailable; cannot run the loopback executor test");
        return true;
    }
    if !Command::new("cargo").arg("--version").output().map(|o| o.status.success()).unwrap_or(false) {
        eprintln!("SKIPPED: cargo unavailable; cannot run the loopback executor test");
        return true;
    }
    if std::net::TcpStream::connect(("index.crates.io", 443)).is_err() {
        eprintln!("SKIPPED: no network to index.crates.io; cannot run the loopback executor test");
        return true;
    }
    false
}

fn job_offer() -> softfig_net::proto::JobOffer {
    softfig_net::proto::JobOffer {
        job_id: vec![0x01; 16],
        repo_key: vec![0x02; 32],
        source_id: vec![0x03; 32],
        snapshot_commit: vec![0x04; 32],
        profile: "gate".into(),
        cmd: vec!["cargo".into(), "test".into()],
        env: vec![],
        toolchain: "rust".into(),
        network: "none".into(),
        cache: "shared".into(),
        artifacts: vec![],
        requested_at: NOW,
        signature: Vec::new(),
    }
}

fn connect(
    req: &Requester,
    fx: &RunnerFixture,
    cached: Option<&CachedRunner>,
    revoked: &[[u8; 16]],
) -> (softfig_net::RunnerSession<TcpStream>, RunnerCert) {
    let stream = testing::connect_within(fx.addr(), "runner");
    softfig_net::connect_runner(stream, &req.local(), &fx.ring_identity(), cached, revoked, NOW)
        .unwrap()
}

/// A requester-side git repo + snapshot: the offer fields the source step fills.
struct SnapshotFixture {
    _repo: tempfile::TempDir,
    repo_path: std::path::PathBuf,
    source_id: softfig_source::SourceId,
    commit: Vec<u8>,
    repo_key: [u8; 32],
}

impl SnapshotFixture {
    fn new(device_id: [u8; 32]) -> Self {
        Self::build(device_id, None)
    }

    /// A fixture whose tree pins a `rust-toolchain.toml` channel, for the
    /// toolchain-missing reject test.
    fn with_toolchain(device_id: [u8; 32], channel: &str) -> Self {
        Self::build(device_id, Some(channel))
    }

    fn build(device_id: [u8; 32], toolchain: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let g = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
            assert!(ok.success(), "git {args:?} failed");
        };
        g(&["init", "-q"]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        g(&["config", "commit.gpgsign", "false"]);
        std::fs::write(dir.path().join("f.txt"), "hello\n").unwrap();
        if let Some(channel) = toolchain {
            std::fs::write(
                dir.path().join("rust-toolchain.toml"),
                format!("[toolchain]\nchannel = \"{channel}\"\n"),
            )
            .unwrap();
        }
        g(&["add", "-A"]);
        g(&["commit", "-q", "-m", "c1"]);

        let snap = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();
        let roots = root_commits(dir.path()).unwrap();
        let repo_key = repo_key(&device_id, &roots);
        let repo_path = dir.path().to_path_buf();
        Self {
            _repo: dir,
            repo_path,
            source_id: snap.source_id,
            commit: snap.commit,
            repo_key,
        }
    }

    fn offer(&self) -> softfig_net::proto::JobOffer {
        softfig_net::proto::JobOffer {
            job_id: vec![0x01; 16],
            repo_key: self.repo_key.to_vec(),
            source_id: self.source_id.encode(),
            snapshot_commit: self.commit.clone(),
            profile: "gate".into(),
            // No command: the wire happy-path test exercises the round trip
            // without needing bwrap/cargo (the fetch→build→collect mechanics are
            // proven by the loopback executor test).
            cmd: vec![],
            env: vec![],
            toolchain: "rust".into(),
            network: "none".into(),
            cache: "shared".into(),
            artifacts: vec![],
            requested_at: NOW,
            signature: Vec::new(),
        }
    }

    fn make_bundle(&self, haves: &[Vec<u8>]) -> softfig_source::Result<Vec<u8>> {
        create_bundle(&self.repo_path, &self.source_id, &self.commit, haves)
    }
}

/// A requester-side *cargo* repo + snapshot: the loopback executor test's
/// fixture. The tree carries a real registry dependency, so the runner's fetch
/// step actually downloads through the proxy and the run step builds offline.
struct CargoSnapshotFixture {
    _repo: tempfile::TempDir,
    repo_path: std::path::PathBuf,
    source_id: softfig_source::SourceId,
    commit: Vec<u8>,
    repo_key: [u8; 32],
}

impl CargoSnapshotFixture {
    fn new(device_id: [u8; 32]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"job\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nlibc = \"0.2.191\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn m() -> i32 { 42 }\n").unwrap();
        // Pin the lockfile (host cargo fetch into a throwaway home) so the
        // fetch step's `--locked` has a lockfile to honor.
        let pin = tempfile::tempdir().unwrap();
        let out = std::process::Command::new("cargo")
            .env("CARGO_HOME", pin.path())
            .arg("fetch")
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "pin lockfile failed: {}", String::from_utf8_lossy(&out.stderr));

        let g = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
            assert!(ok.success(), "git {args:?} failed");
        };
        g(&["init", "-q"]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        g(&["config", "commit.gpgsign", "false"]);
        g(&["add", "-A"]);
        g(&["commit", "-q", "-m", "c1"]);

        let snap = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();
        let roots = root_commits(dir.path()).unwrap();
        let repo_key = repo_key(&device_id, &roots);
        let repo_path = dir.path().to_path_buf();
        Self {
            _repo: dir,
            repo_path,
            source_id: snap.source_id,
            commit: snap.commit,
            repo_key,
        }
    }

    fn offer(&self) -> softfig_net::proto::JobOffer {
        softfig_net::proto::JobOffer {
            job_id: vec![0x01; 16],
            repo_key: self.repo_key.to_vec(),
            source_id: self.source_id.encode(),
            snapshot_commit: self.commit.clone(),
            profile: "gate".into(),
            cmd: vec!["cargo".into(), "build".into(), "--offline".into()],
            env: vec![],
            toolchain: "rust".into(),
            network: "none".into(),
            cache: "shared".into(),
            artifacts: vec!["Cargo.lock".into()],
            requested_at: NOW,
            signature: Vec::new(),
        }
    }

    fn make_bundle(&self, haves: &[Vec<u8>]) -> softfig_source::Result<Vec<u8>> {
        create_bundle(&self.repo_path, &self.source_id, &self.commit, haves)
    }
}

/// The bundle is never requested for a job the runner rejects up front.
fn no_bundle(_haves: &[Vec<u8>]) -> softfig_source::Result<Vec<u8>> {
    unreachable!("the source bundle is never requested for a rejected job")
}

#[test]
fn happy_path_offer_accept_result() {
    let req = Requester::new(1, 2);
    let fx = RunnerFixture::new([0xAA; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let (mut session, cert) = connect(&req, &fx, None, &[]);
    assert_eq!(cert.device_id, fx.ring_identity());

    let snap = SnapshotFixture::new([1u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);
    let (_caps, outcome) =
        softfig_net::run_job(&mut session, &offer, |haves| snap.make_bundle(haves)).unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.job_id, offer.job_id);
    // Chunk 3: the result carries a signed, verifiable attestation.
    let signed = softfig_runnerd::SignedAttestation::from_bytes(&result.attestation).unwrap();
    assert!(signed.verify(&cert.runner_attest_pubkey));
}

#[test]
fn run_remote_happy_path_returns_the_job_code() {
    let req = Requester::new(21, 22);
    let fx = RunnerFixture::new([0x21; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let snap = SnapshotFixture::new([21u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);

    let mut cache = RunnerCache::default();
    let outcome = run_remote(
        &req.local(),
        &fx.ring_identity(),
        &fx.addr(),
        &mut cache,
        &offer,
        |haves| snap.make_bundle(haves),
        NOW,
    )
    .unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.job_id, offer.job_id);
}

#[test]
fn run_remote_maps_a_reject_to_a_run_failure() {
    let req = Requester::new(31, 32);
    let fx = RunnerFixture::new([0x31; 16], NOW + 90 * 24 * 60 * 60);
    // No grant: the runner refuses with `not-granted` before any bundle.
    fx.serve_one();

    let snap = SnapshotFixture::new([31u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);

    let mut cache = RunnerCache::default();
    let err = run_remote(
        &req.local(),
        &fx.ring_identity(),
        &fx.addr(),
        &mut cache,
        &offer,
        no_bundle,
        NOW,
    )
    .unwrap_err();
    assert_eq!(err, RunFailure::Rejected(JobRejectReason::NotGranted));
}

#[test]
fn run_remote_maps_a_cert_failure_to_invalid_cert() {
    let req = Requester::new(41, 42);
    let fx = RunnerFixture::new([0x41; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let snap = SnapshotFixture::new([41u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);

    // A ring identity that is NOT the signer of the certificate: the cert
    // signature fails to verify, so `run_remote` reports `InvalidCert`.
    let wrong_ring: [u8; 32] = [0xEE; 32];
    let mut cache = RunnerCache::default();
    let err = run_remote(
        &req.local(),
        &wrong_ring,
        &fx.addr(),
        &mut cache,
        &offer,
        no_bundle,
        NOW,
    )
    .unwrap_err();
    assert_eq!(err, RunFailure::InvalidCert);
}

#[test]
fn run_remote_maps_an_unreachable_runner_to_no_runner() {
    let req = Requester::new(51, 52);
    let snap = SnapshotFixture::new([51u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);

    // Dial a port nobody is listening on: connection refused -> NoRunner.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);

    let mut cache = RunnerCache::default();
    let err = run_remote(
        &req.local(),
        &[0u8; 32],
        &addr,
        &mut cache,
        &offer,
        no_bundle,
        NOW,
    )
    .unwrap_err();
    assert_eq!(err, RunFailure::NoRunner);
}

#[test]
fn second_connection_uses_ik() {
    let req = Requester::new(3, 4);
    let fx = RunnerFixture::new([0xBB; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);

    // First contact: XX, then cache the verified certificate.
    fx.serve_one();
    let (session, cert) = connect(&req, &fx, None, &[]);
    let mut cache = RunnerCache::default();
    cache.put(
        &hex::encode(fx.ring_identity()),
        CachedRunner {
            cert: cert.clone(),
            signature: hex::encode(session.signature()),
        },
    );
    drop(session);

    // Second connection: IK keyed by the cached static, then a full job.
    fx.serve_one();
    let cached = cache.get(&hex::encode(fx.ring_identity())).unwrap().clone();
    let (mut session2, cert2) = connect(&req, &fx, Some(&cached), &[]);
    assert_eq!(cert2, cert, "IK reconnect must re-present and re-verify the same cert");

    let snap = SnapshotFixture::new([3u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);
    let (_caps, outcome) =
        softfig_net::run_job(&mut session2, &offer, |haves| snap.make_bundle(haves)).unwrap();
    assert!(matches!(outcome, JobOutcome::Accepted(_)));
}

#[test]
fn source_tree_mismatch_is_rejected_over_the_wire() {
    let req = Requester::new(13, 14);
    let fx = RunnerFixture::new([0x10; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let (mut session, _cert) = connect(&req, &fx, None, &[]);

    let snap = SnapshotFixture::new([13u8; 32]);
    // A wrong source id (same format, different root): the offer claims it, but
    // the bundle ships `snap.commit` whose tree is the honest one.
    let wrong = softfig_source::SourceId::from_git_hash(&"ff".repeat(20)).unwrap();
    let mut offer = snap.offer();
    offer.source_id = wrong.encode();
    offer.signature = req.sign_offer(&offer);

    let (_caps, outcome) = softfig_net::run_job(&mut session, &offer, |haves| {
        create_bundle(&snap.repo_path, &wrong, &snap.commit, haves)
    })
    .unwrap();
    assert_eq!(outcome, JobOutcome::Rejected(JobRejectReason::SourceMismatch));
}

#[test]
fn unknown_requester_is_refused() {
    let req = Requester::new(5, 6); // not granted
    let fx = RunnerFixture::new([0xCC; 16], NOW + 90 * 24 * 60 * 60);
    fx.serve_one();

    let (mut session, _cert) = connect(&req, &fx, None, &[]);
    let mut offer = job_offer();
    offer.signature = req.sign_offer(&offer);
    let (_caps, outcome) = softfig_net::run_job(&mut session, &offer, no_bundle).unwrap();
    assert_eq!(outcome, JobOutcome::Rejected(JobRejectReason::NotGranted));
}

#[test]
fn malformed_job_id_is_refused_and_never_wipes_jobs_dir() {
    // m2: an empty `job_id` made the job's scratch dir `jobs/` itself, so the
    // post-job cleanup wiped every other job's scratch. A short id is just as
    // malformed. Both are refused at intake, before any scratch dir exists.
    for job_id in [Vec::new(), vec![0x6d; 15]] {
        let req = Requester::new(60, 61);
        let fx = RunnerFixture::new([0x60; 16], NOW + 90 * 24 * 60 * 60);
        fx.grant(&req);
        fx.serve_one();
        let (mut session, _cert) = connect(&req, &fx, None, &[]);

        // Another job's scratch, which this offer must leave alone.
        let other = fx.root.jobs_dir().join("other-job");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("keep"), "keep").unwrap();

        let snap = SnapshotFixture::new([60u8; 32]);
        let mut offer = snap.offer();
        offer.job_id = job_id.clone();
        offer.signature = req.sign_offer(&offer);
        let res = softfig_net::run_job(&mut session, &offer, |haves| snap.make_bundle(haves));

        assert!(other.join("keep").exists(), "a {}-byte job_id wiped jobs/", job_id.len());
        assert!(res.is_err(), "a {}-byte job_id was accepted", job_id.len());
        let names: Vec<_> = std::fs::read_dir(fx.root.jobs_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["other-job"], "a refused offer creates no scratch dir");
    }
}

#[test]
fn offer_signed_by_wrong_key_is_refused() {
    let req = Requester::new(7, 8);
    let fx = RunnerFixture::new([0xDD; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let (mut session, _cert) = connect(&req, &fx, None, &[]);
    let mut offer = job_offer();
    let other = SigningKey::from_bytes(&[0x99; 32]);
    offer.signature = other.sign(&offer_signing_bytes(&offer)).to_bytes().to_vec();
    let (_caps, outcome) = softfig_net::run_job(&mut session, &offer, no_bundle).unwrap();
    assert_eq!(outcome, JobOutcome::Rejected(JobRejectReason::NotGranted));
}

#[test]
fn expired_certificate_is_refused() {
    let req = Requester::new(9, 10);
    let fx = RunnerFixture::new([0xEE; 16], NOW - 1); // already expired
    fx.grant(&req);
    fx.serve_one();

    let stream = testing::connect_within(fx.addr(), "runner");
    let err = softfig_net::connect_runner(
        stream,
        &req.local(),
        &fx.ring_identity(),
        None,
        &[],
        NOW,
    )
    .err()
    .expect("connect must fail");
    assert!(
        matches!(err, softfig_net::NetError::RunnerCert(_)),
        "expected a RunnerCert error for an expired certificate, got {err:?}"
    );
}

#[test]
fn revoked_serial_is_refused() {
    let req = Requester::new(11, 12);
    let fx = RunnerFixture::new([0xFF; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let stream = testing::connect_within(fx.addr(), "runner");
    let err = softfig_net::connect_runner(
        stream,
        &req.local(),
        &fx.ring_identity(),
        None,
        &[fx.cert.serial],
        NOW,
    )
    .err()
    .expect("connect must fail");
    assert!(
        matches!(err, softfig_net::NetError::RunnerCert(_)),
        "expected a RunnerCert error for a revoked serial, got {err:?}"
    );
}

/// mDNS announce/browse is a **manual smoke** (multicast is unavailable on the
/// headless build host). The pure TXT encode/parse for `_softfig-runner._tcp`
/// is unit-tested in `softfig-net`'s `discovery` module
/// (`runner_txt_round_trips_and_rejects_malformed`); the on-wire announce/browse
/// runs in slice 008's on-device smoke.
#[test]
fn mdns_announce_is_a_documented_manual_smoke() {
    // Nothing to run here: this test exists to make the skip explicit and
    // discoverable rather than silently absent.
    assert_eq!(
        softfig_net::discovery::RUNNER_SERVICE_TYPE,
        "_softfig-runner._tcp.local."
    );
}

/// A job whose tree pins a toolchain the runner does not serve is rejected with
/// `toolchain-missing` (spec §7.2) — over the wire, before any sandbox runs, so
/// this needs no bwrap/cargo/network, only git (snapshot + materialize).
#[test]
fn toolchain_missing_is_rejected_over_the_wire() {
    let req = Requester::new(30, 31);
    let fx = RunnerFixture::new([0x30; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let (mut session, _cert) = connect(&req, &fx, None, &[]);

    let snap = SnapshotFixture::with_toolchain([30u8; 32], "1.85.0");
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);

    let (_caps, outcome) =
        softfig_net::run_job(&mut session, &offer, |haves| snap.make_bundle(haves)).unwrap();
    assert_eq!(outcome, JobOutcome::Rejected(JobRejectReason::ToolchainMissing));
}

/// The slice-006 chunk-1 "done when": a loopback job runs fetch → build →
/// collect in real sandboxes and returns a real (non-stub) `JobResult` — the
/// run step's real exit code, with the attestation still empty (signing is
/// chunk 2). Skips loudly when the sandbox stack is unavailable.
#[test]
fn loopback_job_runs_fetch_build_collect_over_the_wire() {
    if sandbox_skip() {
        return;
    }

    let req = Requester::new(40, 41);
    let fx = RunnerFixture::new([0x40; 16], NOW + 90 * 24 * 60 * 60);
    // Point the runner's rustup home at the build host's real toolchains
    // (production installs them into the state root with `runner toolchain
    // add`; bwrap resolves the symlink when it binds `/opt/toolchain`).
    std::os::unix::fs::symlink("/home/ukv/.rustup", fx.root.rustup_home()).unwrap();
    fx.grant(&req);
    fx.serve_one();

    let (mut session, cert) = connect(&req, &fx, None, &[]);

    let snap = CargoSnapshotFixture::new([40u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);

    let (_caps, outcome) =
        softfig_net::run_job(&mut session, &offer, |haves| snap.make_bundle(haves)).unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(result.exit_code, 0, "the offline build must succeed over the wire");
    let signed = softfig_runnerd::SignedAttestation::from_bytes(&result.attestation).unwrap();
    assert!(signed.verify(&cert.runner_attest_pubkey));
}

/// `true` when `systemd-run --user` can't run a unit, after a loud skip.
fn systemd_skip() -> bool {
    let ok = Command::new("systemd-run")
        .args(["--user", "--wait", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIPPED: systemd-run --user unavailable; cannot run the transient-unit loopback test");
    }
    !ok
}

/// The slice-006 chunk-2 "done when": a loopback job runs fetch → run → collect
/// **inside a `systemd-run --user` transient unit** (the real `serve_source`
/// path — spec §7.1 layer 2), with a no-manifest tree and an empty command so
/// the sequence needs no bwrap/cargo/network yet still exercises the unit +
/// spec/report round-trip. Skips loudly when systemd-run is unavailable.
#[test]
fn loopback_job_runs_in_a_transient_unit() {
    if systemd_skip() {
        return;
    }

    let req = Requester::new(42, 43);
    let shm_root = std::path::PathBuf::from("/dev/shm").join(format!(
        "softfig-wire-unit-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&shm_root).unwrap();
    let fx = RunnerFixture::new_transient_unit(shm_root.clone(), [0x42; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let (mut session, cert) = connect(&req, &fx, None, &[]);

    // A no-manifest tree + empty command: the executor runs fetch(skip) →
    // run(skip) → collect(skip) entirely inside the transient unit.
    let snap = SnapshotFixture::new([42u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);

    let (_caps, outcome) =
        softfig_net::run_job(&mut session, &offer, |haves| snap.make_bundle(haves)).unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(result.exit_code, 0, "the empty job must run inside the unit and exit 0");
    let signed = softfig_runnerd::SignedAttestation::from_bytes(&result.attestation).unwrap();
    assert!(signed.verify(&cert.runner_attest_pubkey));

    let _ = std::fs::remove_dir_all(&shm_root);
}

/// A job is rejected with `on-battery` when the runner is on battery and
/// `[serve] on_battery = "refuse"` (spec §6 step 1) — over the wire, before any
/// source transfer. The power check reads the fixture's sysfs dir (Mains
/// offline, Battery present), so this needs no real battery.
#[test]
fn battery_refused_over_the_wire() {
    let req = Requester::new(44, 45);
    let mut fx = RunnerFixture::new([0x44; 16], NOW + 90 * 24 * 60 * 60);

    // A fixture power_supply tree that reports "on battery".
    let ps = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(ps.path().join("AC0")).unwrap();
    std::fs::write(ps.path().join("AC0/type"), "Mains").unwrap();
    std::fs::write(ps.path().join("AC0/online"), "0").unwrap();
    std::fs::create_dir_all(ps.path().join("BAT0")).unwrap();
    std::fs::write(ps.path().join("BAT0/type"), "Battery").unwrap();

    // Refuse on battery + point the check at the fixture.
    let mut serve = ServeConfig::load(&fx.root.serve_toml()).unwrap();
    serve.on_battery = "refuse".into();
    serve.save(&fx.root.serve_toml()).unwrap();
    Arc::get_mut(&mut fx.server).unwrap().set_power_supply_path(ps.path().to_path_buf());

    fx.grant(&req);
    fx.serve_one();

    let (mut session, _cert) = connect(&req, &fx, None, &[]);
    let snap = SnapshotFixture::new([44u8; 32]);
    let mut offer = snap.offer();
    offer.signature = req.sign_offer(&offer);

    let (_caps, outcome) =
        softfig_net::run_job(&mut session, &offer, no_bundle).unwrap();
    assert_eq!(outcome, JobOutcome::Rejected(JobRejectReason::OnBattery));
}

/// The slice-006 chunk-3 "done when": a loopback job (a no-manifest tree with a
/// command that emits both stdout and stderr) streams its logs live as
/// `JobLog` frames and returns a signed attestation whose signature verifies
/// against the cached certificate's attest key, while a tampered attestation is
/// rejected. Runs in `Direct` mode (the executor in-process), where log
/// streaming is live. Skips loudly when the sandbox stack is unavailable.
#[test]
fn loopback_job_streams_logs_and_returns_verified_attestation() {
    if sandbox_skip() {
        return;
    }

    let req = Requester::new(50, 51);
    let fx = RunnerFixture::new([0x50; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let (mut session, cert) = connect(&req, &fx, None, &[]);

    let snap = SnapshotFixture::new([50u8; 32]);
    let mut offer = snap.offer();
    // A command that emits a distinct line to each stream: proves stdout (0)
    // and stderr (1) are both streamed, and that the run step's output — not
    // the fetch step's — is what flows back.
    offer.cmd = vec![
        "sh".into(),
        "-c".into(),
        "echo HELLO_STDOUT; echo HELLO_STDERR >&2".into(),
    ];
    offer.signature = req.sign_offer(&offer);

    let (_caps, outcome, logs, _events) =
        run_job_collecting(&mut session, &offer, |haves| snap.make_bundle(haves)).unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(result.exit_code, 0, "the echo job must exit 0");

    // Both streams arrived, in order, via JobLog frames.
    let stdout: String = logs
        .iter()
        .filter(|l| l.stream == 0)
        .flat_map(|l| l.bytes.iter().copied())
        .map(char::from)
        .collect();
    let stderr: String = logs
        .iter()
        .filter(|l| l.stream == 1)
        .flat_map(|l| l.bytes.iter().copied())
        .map(char::from)
        .collect();
    assert!(stdout.contains("HELLO_STDOUT"), "stdout streamed: {stdout:?}");
    assert!(stderr.contains("HELLO_STDERR"), "stderr streamed: {stderr:?}");

    // The attestation verifies against the cached certificate's attest key.
    let signed = softfig_runnerd::SignedAttestation::from_bytes(&result.attestation).unwrap();
    assert!(signed.verify(&cert.runner_attest_pubkey));
    // Its source/cmd/exit fields reflect what was offered and run.
    assert_eq!(signed.attestation.job_id, hex::encode(&offer.job_id));
    assert_eq!(signed.attestation.cmd, offer.cmd);
    assert_eq!(signed.attestation.exit.code, Some(0));
    // The log hash in the attestation matches the streamed bytes' BLAKE3.
    let mut combined: Vec<u8> = Vec::new();
    for l in &logs {
        combined.extend_from_slice(&l.bytes);
    }
    assert_eq!(
        signed.attestation.log_blake3,
        hex::encode(*blake3::hash(&combined).as_bytes()),
        "attestation log_blake3 must be the BLAKE3 of the streamed log"
    );

    // A tampered attestation is rejected: flip the exit code and re-verify.
    let mut tampered = signed.clone();
    tampered.attestation.exit = softfig_runnerd::ExitInfo::code(99);
    let tampered_bytes = tampered.to_bytes().unwrap();
    let tampered = softfig_runnerd::SignedAttestation::from_bytes(&tampered_bytes).unwrap();
    assert!(!tampered.verify(&cert.runner_attest_pubkey));
}



/// Copy the sandbox helper binaries into `dir`, beside the staged runnerd, so
/// the transient unit's `--run-job` payload (which resolves them via
/// `next_to_runnerd`) can reach them when it runs a bwrap step.
fn stage_sandbox_bins(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let bins = sandbox_bins();
    for (src, name) in [
        (bins.init, "softfig-sandbox-init"),
        (bins.forwarder, "softfig-sandbox-forward"),
        (bins.collect, "softfig-sandbox-collect"),
    ] {
        let dst = dir.join(name);
        std::fs::copy(&src, &dst).unwrap();
        let mut perms = std::fs::metadata(&dst).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dst, perms).unwrap();
    }
}

/// The slice-006 chunk-4 "done when": a loopback job is cancelled mid-run and
/// leaves no stray pid in its cgroup. A no-manifest tree with a long `sleep`
/// runs inside a `systemd-run --user` unit; a second connection sends
/// `JobCancel`, which stops the unit. Skips loudly when systemd-run/bwrap are
/// unavailable.
#[test]
fn loopback_job_can_be_cancelled_mid_run() {
    if systemd_skip() {
        return;
    }
    if sandbox_skip() {
        return;
    }

    let req = Requester::new(60, 61);
    let shm_root = std::path::PathBuf::from("/dev/shm").join(format!(
        "softfig-wire-cancel-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&shm_root).unwrap();
    let fx =
        RunnerFixture::new_transient_unit(shm_root.clone(), [0x60; 16], NOW + 90 * 24 * 60 * 60);
    // Stage the sandbox helpers beside the staged runnerd so the payload can run
    // the (bwrap) run step.
    stage_sandbox_bins(&shm_root);
    fx.grant(&req);
    fx.serve_one(); // the job connection
    fx.serve_one(); // the cancel connection

    let snap = SnapshotFixture::new([60u8; 32]);
    let mut offer = snap.offer();
    offer.cmd = vec!["sh".into(), "-c".into(), "sleep 30".into()];
    offer.signature = req.sign_offer(&offer);
    let job_id = offer.job_id.clone();

    let (mut job_session, _cert) = connect(&req, &fx, None, &[]);
    let offer2 = offer.clone();
    let job_handle = std::thread::spawn(move || {
        run_job_collecting(&mut job_session, &offer2, |haves| snap.make_bundle(haves))
    });

    // Wait for the transient unit to be running before cancelling.
    let unit = softfig_runnerd::unit_name(&softfig_runnerd::JobKey::new(req.device_id, &job_id).unwrap());
    let mut saw_active = false;
    for _ in 0..150 {
        let out = Command::new("systemctl")
            .args(["--user", "show", &unit, "--property=ActiveState"])
            .output();
        if let Ok(o) = out {
            let t = String::from_utf8_lossy(&o.stdout).to_string();
            if t.contains("ActiveState=active") {
                saw_active = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(saw_active, "the job's transient unit should be active before cancel");

    // Cancel over a second connection.
    let (mut cancel_session, _c) = connect(&req, &fx, None, &[]);
    match cancel_session.recv_frame().unwrap().kind {
        Some(frame::Kind::RunnerCaps(_)) => {}
        other => panic!("expected RunnerCaps, got {other:?}"),
    }
    cancel_session
        .send_frame(&Frame::job_cancel(JobCancel { job_id: job_id.clone() }))
        .unwrap();
    let ev = match cancel_session.recv_frame().unwrap().kind {
        Some(frame::Kind::JobEvent(e)) => e,
        other => panic!("expected JobEvent, got {other:?}"),
    };
    assert_eq!(ev.state, JobState::Cancelled as u32, "cancel must report cancelled");

    // The job thread's run returns the (cancelled) result.
    let (_caps, outcome, _logs, _events) = job_handle.join().unwrap().unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(
        result.exit_code,
        softfig_runnerd::CANCELLED_EXIT,
        "a cancelled job reports the cancelled exit code"
    );

    // No stray pids: the unit is gone and its cgroup is empty.
    let out = Command::new("systemctl")
        .args([
            "--user",
            "show",
            &unit,
            "--property=ActiveState",
            "--property=TasksCurrent",
        ])
        .output()
        .unwrap();
    let t = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        t.contains("ActiveState=inactive") || t.contains("ActiveState=failed"),
        "the unit must be stopped after cancel: {t}"
    );
    // No stray pids: the cgroup is empty (TasksCurrent=0) or already torn down
    // (property not set) — never a positive count.
    assert!(
        t.contains("TasksCurrent=0") || t.contains("TasksCurrent=[not set]"),
        "no stray pids may remain in the cgroup after cancel: {t}"
    );

    let _ = std::fs::remove_dir_all(&shm_root);
}

/// The slice-006 chunk-4 "done when": a finished job can be re-attached from a
/// `from_seq`, replaying exactly the retained tail (seq >= from_seq) and the
/// stored result. Direct mode (in-process executor) keeps the job in the table.
#[test]
fn loopback_job_can_be_reattached_from_a_seq() {
    if sandbox_skip() {
        return;
    }

    let req = Requester::new(52, 53);
    let fx = RunnerFixture::new([0x52; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);

    // Connection 1: run the job and collect its logs.
    fx.serve_one();
    let (mut session, _cert) = connect(&req, &fx, None, &[]);
    let snap = SnapshotFixture::new([52u8; 32]);
    let mut offer = snap.offer();
    offer.cmd = vec![
        "sh".into(),
        "-c".into(),
        "echo AAA; sleep 0.3; echo BBB; sleep 0.3; echo CCC".into(),
    ];
    offer.signature = req.sign_offer(&offer);
    let (_caps, outcome, logs, _events) =
        run_job_collecting(&mut session, &offer, |haves| snap.make_bundle(haves)).unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(result.exit_code, 0, "the echo job must exit 0");
    drop(session);

    let stdout_seqs: Vec<u64> = logs.iter().filter(|l| l.stream == 0).map(|l| l.seq).collect();
    assert!(
        stdout_seqs.len() >= 2,
        "expected multiple stdout chunks, got seqs {stdout_seqs:?}"
    );

    // Connection 2: attach from seq 1.
    fx.serve_one();
    let (mut session2, _cert2) = connect(&req, &fx, None, &[]);
    match session2.recv_frame().unwrap().kind {
        Some(frame::Kind::RunnerCaps(_)) => {}
        other => panic!("expected RunnerCaps, got {other:?}"),
    }
    session2
        .send_frame(&Frame::job_attach(JobAttach { job_id: offer.job_id.clone(), from_seq: 1 }))
        .unwrap();
    let mut replayed: Vec<JobLog> = Vec::new();
    let result2 = loop {
        match session2.recv_frame().unwrap().kind {
            Some(frame::Kind::JobLog(l)) => replayed.push(l),
            Some(frame::Kind::JobResult(r)) => break r,
            other => panic!("expected JobLog/JobResult, got {other:?}"),
        }
    };
    assert_eq!(result2.job_id, offer.job_id);
    assert_eq!(
        result2.attestation, result.attestation,
        "attach must re-deliver the same signed attestation"
    );

    // Replayed chunks all carry seq >= 1, and their bytes match the original tail.
    assert!(replayed.iter().all(|l| l.seq >= 1), "from_seq=1 must not replay seq 0");
    let replayed_stdout: String = replayed
        .iter()
        .filter(|l| l.stream == 0)
        .flat_map(|l| l.bytes.iter().copied())
        .map(char::from)
        .collect();
    let original_tail: String = logs
        .iter()
        .filter(|l| l.stream == 0 && l.seq >= 1)
        .flat_map(|l| l.bytes.iter().copied())
        .map(char::from)
        .collect();
    assert_eq!(replayed_stdout, original_tail, "attach replays exactly the seq>=1 tail");
    assert!(
        replayed_stdout.contains("BBB") && replayed_stdout.contains("CCC"),
        "the replayed tail carries the later chunks: {replayed_stdout:?}"
    );
}

/// The slice-006 chunk-4 "done when": every job leaves a `jobs.ndjson` row whose
/// `attestation_hash` matches the returned attestation's digest (spec §6 step 9).
#[test]
fn loopback_job_leaves_a_jobs_ndjson_row() {
    if sandbox_skip() {
        return;
    }

    let req = Requester::new(54, 55);
    let fx = RunnerFixture::new([0x54; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let (mut session, _cert) = connect(&req, &fx, None, &[]);
    let snap = SnapshotFixture::new([54u8; 32]);
    let mut offer = snap.offer();
    offer.cmd = vec!["sh".into(), "-c".into(), "echo NDJSON_TEST".into()];
    offer.signature = req.sign_offer(&offer);
    let (_caps, outcome, _logs, _events) =
        run_job_collecting(&mut session, &offer, |haves| snap.make_bundle(haves)).unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    let signed = softfig_runnerd::SignedAttestation::from_bytes(&result.attestation).unwrap();
    let expected_hash = hex::encode(signed.attestation.hash().unwrap());

    let text = std::fs::read_to_string(fx.root.log_dir().join("jobs.ndjson")).unwrap();
    let mut found = None;
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        if v["job_id"] == serde_json::Value::String(hex::encode(&offer.job_id)) {
            found = Some(v);
        }
    }
    let row = found.expect("the job must leave a jobs.ndjson row");
    assert_eq!(
        row["attestation_hash"], expected_hash,
        "attestation_hash must match the returned attestation"
    );
    assert_eq!(row["where_route"], "lan");
    assert_eq!(row["cache_mode"], "shared");
    assert_eq!(row["exit"]["code"], 0);
}
