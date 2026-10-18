//! Loopback integration test for the runner wire (spec remote-runner §3.3,
//! §11): a real `WireServer` on a temp state root, driven over loopback TCP by
//! a real requester (`softfig_net::connect_runner` + `run_job`).
//!
//! Covers the slice-003 "done when": the happy path (offer → accept → stub
//! `JobResult`), an unknown requester refused, an expired certificate refused,
//! a revoked serial refused, an offer signed by the wrong key refused, and a
//! second connection using `IK`. mDNS announce/browse is a manual smoke (needs
//! multicast on a real interface); its pure TXT encode/parse is unit-tested in
//! `softfig-net`'s `discovery` module.

use std::net::TcpStream;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use softfig_net::runner_cert::RunnerCert;
use softfig_net::{
    offer_signing_bytes, static_attestation_message, testing, CachedRunner, JobOutcome,
    JobRejectReason, LocalDevice, RunnerCache,
};
use softfig_runnerd::cert::StoredCert;
use softfig_runnerd::config::{AcceptConfig, AcceptedPeer, ServeConfig};
use softfig_runnerd::keys::RunnerKeys;
use softfig_runnerd::state::StateRoot;
use softfig_runnerd::wire::WireServer;

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
            ..ServeConfig::default()
        };
        serve.save(&root.serve_toml()).unwrap();

        let server = Arc::new(WireServer::bind(root.clone(), "127.0.0.1:0").unwrap());
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

#[test]
fn happy_path_offer_accept_stub_result() {
    let req = Requester::new(1, 2);
    let fx = RunnerFixture::new([0xAA; 16], NOW + 90 * 24 * 60 * 60);
    fx.grant(&req);
    fx.serve_one();

    let (mut session, cert) = connect(&req, &fx, None, &[]);
    assert_eq!(cert.device_id, fx.ring_identity());

    let mut offer = job_offer();
    offer.signature = req.sign_offer(&offer);
    let (_caps, outcome) = softfig_net::run_job(&mut session, &offer).unwrap();
    let result = match outcome {
        JobOutcome::Accepted(r) => r,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.job_id, offer.job_id);
    assert!(result.attestation.is_empty(), "stub has no attestation yet");
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

    let mut offer = job_offer();
    offer.signature = req.sign_offer(&offer);
    let (_caps, outcome) = softfig_net::run_job(&mut session2, &offer).unwrap();
    assert!(matches!(outcome, JobOutcome::Accepted(_)));
}

#[test]
fn unknown_requester_is_refused() {
    let req = Requester::new(5, 6); // not granted
    let fx = RunnerFixture::new([0xCC; 16], NOW + 90 * 24 * 60 * 60);
    fx.serve_one();

    let (mut session, _cert) = connect(&req, &fx, None, &[]);
    let mut offer = job_offer();
    offer.signature = req.sign_offer(&offer);
    let (_caps, outcome) = softfig_net::run_job(&mut session, &offer).unwrap();
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
    let (_caps, outcome) = softfig_net::run_job(&mut session, &offer).unwrap();
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
