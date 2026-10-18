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
use std::process::Command;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use softfig_net::runner_cert::RunnerCert;
use softfig_net::{
    offer_signing_bytes, static_attestation_message, testing, CachedRunner, JobOutcome,
    JobRejectReason, LocalDevice, RunnerCache,
};
use softfig_source::{create_bundle, repo_key, root_commits, snapshot_repo, SubmodulePolicy};
use softfig_runnerd::cert::StoredCert;
use softfig_runnerd::config::{AcceptConfig, AcceptedPeer, ServeConfig};
use softfig_runnerd::keys::RunnerKeys;
use softfig_runnerd::state::StateRoot;
use softfig_runnerd::wire::WireServer;
use softfig_runnerd::SandboxBinaries;

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
    _dir: tempfile::TempDir,
    root: StateRoot,
    server: Arc<WireServer>,
    signer: SigningKey,
    cert: RunnerCert,
}

impl RunnerFixture {
    fn new(serial: [u8; 16], expires_at: i64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path());
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

        let server = Arc::new(
            WireServer::bind_with_bins(root.clone(), "127.0.0.1:0", sandbox_bins()).unwrap(),
        );
        Self {
            _dir: dir,
            root,
            server,
            signer,
            cert,
        }
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
    assert!(result.attestation.is_empty(), "chunk 1 leaves the attestation empty");
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

    let (mut session, _cert) = connect(&req, &fx, None, &[]);

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
    assert!(result.attestation.is_empty(), "chunk 1 leaves the attestation empty");
}
