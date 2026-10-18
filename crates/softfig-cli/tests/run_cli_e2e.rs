//! slice 007 chunk 5 — the binary-spawn CLI end-to-end test (spec remote-runner
//! §9): the built `softfig` executable spawned over argv against a real keeperd
//! on a temp garden + a real runnerd `WireServer` on loopback + a seeded ring,
//! asserting the full §9 fallback/exit-code coverage — the job's own exit code
//! passed through (including a non-zero "ran and failed" code), 254 + reason on
//! a runner-side failure, and the fallback triggers (no-runner, a `disabled`
//! reject) with `--fallback fail` vs the decided `local` fallback.
//!
//! The fallback *trigger set* itself (no-runner, invalid/revoked cert, and the
//! `disabled`/`draining`/`on-battery`/`busy-timeout` rejects) is already
//! unit-tested in `softfig-net::run_plan` (`triggers_match_spec_9_exactly`) and
//! its wire-level mapping in `softfig-runnerd/tests/wire_loopback.rs`; this
//! suite covers the **process seam** on top — real arg parsing, real keeperd
//! IPC (config load + `runner_local_device` + `runner_sign_offer` + `pair_list`),
//! a real git snapshot → bundle → ingest → materialize → sandboxed run, a real
//! Noise handshake + cert verification against the seeded ring identity, and the
//! real exit code flowing back out of the process.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use softfig_ipc::{
    connect,
    verbs::{op, ReplaceFileArgs, RunnerLocalDeviceReply},
    Request, Response,
};
use softfig_keeperd::{Daemon, KeeperConfig};
use softfig_net::{static_attestation_message, Ring, RingEntry};
use softfig_runnerd::{
    cert::StoredCert,
    config::{AcceptConfig, AcceptedPeer, ServeConfig},
    keys::RunnerKeys,
    state::StateRoot,
    wire::WireServer,
    SandboxBinaries,
};
use softfig_vault::{params::VaultParams, Vault};
use softfig_vcs::Repo;

const PASS: &str = "pw-test-12345";
/// A fixed "now" so the runner certificate's expiry is deterministic.
const NOW: i64 = 1_800_000_000;

/// The runner's delegated-certificate signer (its device identity) — a fixed
/// seed, so the forged ring entry and the certificate always agree.
fn runner_signer() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

/// Minimum-cost Argon2 so the fixture boots fast (the keeperd suite's
/// convention).
fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

/// One keeperd request over a fresh connection; panics on any keeperd error.
fn rpc(socket: &Path, op: &str, args: serde_json::Value) -> serde_json::Value {
    let mut stream = connect(socket).expect("connect keeperd");
    let req = Request::new(op, args);
    match softfig_ipc::call(&mut stream, &req).expect("keeperd call") {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("keeperd {op}: {kind:?}: {error}"),
    }
}

/// The sandbox helper binaries, beside this test's own target dir:
/// `<target>/<profile>/deps/<test>` → `<target>/<profile>/<name>`.
fn sandbox_bins() -> SandboxBinaries {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap();
    SandboxBinaries::new(
        profile_dir.join("softfig-sandbox-init"),
        profile_dir.join("softfig-sandbox-forward"),
        profile_dir.join("softfig-sandbox-collect"),
    )
}

/// `true` when the sandbox helper binaries (built under `cargo test
/// --workspace`, not by a bare `-p softfig-cli`) are absent, after a loud skip.
fn sandbox_bins_missing() -> bool {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap();
    !profile_dir.join("softfig-sandbox-init").exists()
}

/// `true` when the execution e2e test cannot run a real sandboxed command
/// (no bwrap, or the sandbox helper bins are absent), after a loud skip.
fn execution_skip() -> bool {
    if !Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIPPED: bwrap unavailable; cannot run the execution e2e test");
        return true;
    }
    if sandbox_bins_missing() {
        eprintln!(
            "SKIPPED: sandbox helper binaries absent (build --workspace); cannot run the execution e2e test"
        );
        return true;
    }
    false
}

struct Fixture {
    _tmp: tempfile::TempDir,
    _handle: softfig_keeperd::DaemonHandle,
    /// The per-process runtime dir (`XDG_RUNTIME_DIR` for spawned binaries) —
    /// keeperd's socket lives here as `softfig-keeperd.sock`, matching
    /// `softfig_ipc::runtime_socket_path()`.
    xdg: PathBuf,
    runner: Arc<WireServer>,
    addr: String,
    repo: PathBuf,
}

/// Boot keeperd (unlocked) on a temp garden + socket, seed the ring with a
/// forged runner peer (the runner cert's signer), stand up a runnerd WireServer
/// on loopback, and create a git repo to run jobs from.
fn boot(serve_enabled: bool, grant: bool) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().to_path_buf();
    let garden = xdg.join("garden");
    let socket = xdg.join("softfig-keeperd.sock");
    std::fs::create_dir_all(&garden).unwrap();

    let (_v, session, _r) = Vault::init_with_params(&garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(&garden, &session).unwrap();
    drop(session);

    let config = KeeperConfig::new(&garden)
        .with_socket(&socket)
        .without_watcher()
        .without_net()
        .without_fuse();
    let handle = Daemon::new(config).start().expect("keeperd boots");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(std::time::Instant::now() < deadline, "socket never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }
    rpc(&socket, op::UNLOCK, json!({ "passphrase": PASS }));

    // The requester config: the job dir as a [[project]], one runner peer, and
    // the decided `local` fallback (individual tests override per-call).
    let repo = xdg.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let cfg = format!(
        "version = 1\n\n[use]\npeers = [\"testrunner\"]\nfallback = \"local\"\nconnect_timeout = \"3s\"\n\n[[project]]\nname = \"e2e\"\nrepo = \"{}\"\ntoolchain = \"rust\"\nfetch = \"none\"\n",
        xdg.display()
    );
    rpc(
        &socket,
        op::REPLACE_FILE,
        serde_json::to_value(ReplaceFileArgs {
            path: "config/runner.toml".into(),
            content: cfg,
            expected_version: None,
        })
        .unwrap(),
    );

    // The requester identity (keeperd's) — read back to grant into accept.toml.
    let ld: RunnerLocalDeviceReply =
        serde_json::from_value(rpc(&socket, op::RUNNER_LOCAL_DEVICE, json!({}))).unwrap();
    let device_id: [u8; 32] = hex::decode(&ld.device_id).unwrap().try_into().unwrap();
    let transport_secret: [u8; 32] =
        hex::decode(&ld.transport_secret).unwrap().try_into().unwrap();
    let transport_pubkey =
        x25519_dalek::x25519(transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

    // Seed the ring: a peer whose device_id is the runner cert's signer, with a
    // valid self-attestation (Ring::load re-verifies). `--on host:port` resolves
    // the runner's identity from the first `[use] peers` entry via `pair_list`.
    let signer = runner_signer();
    let ring_transport = [0xAB; 32];
    let mut ring = Ring::default();
    ring.upsert(RingEntry {
        device_id: signer.verifying_key().to_bytes(),
        name: "testrunner".into(),
        transport_pubkey: ring_transport,
        endpoints: vec![],
        attestation: signer.sign(&static_attestation_message(&ring_transport)).to_bytes(),
        paired_at: 1,
    });
    ring.save(&softfig_net::ring_path(&garden)).expect("seed ring");

    // The runner: state root + keys + a signed cert + serve/accept configs.
    let state_dir = xdg.join("runner-state");
    let root = StateRoot::new(&state_dir);
    root.ensure_dirs().unwrap();
    let keys = RunnerKeys::generate();
    keys.persist(&root.keys_dir()).unwrap();

    let cert = softfig_net::RunnerCert {
        device_id: signer.verifying_key().to_bytes(),
        runner_transport_pubkey: keys.transport_pubkey(),
        runner_attest_pubkey: keys.attest_pubkey(),
        serial: [0xAA; softfig_net::RUNNER_SERIAL_LEN],
        issued_at: NOW - 100,
        expires_at: NOW + 90 * 24 * 60 * 60,
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
        enabled: serve_enabled,
        toolchains: vec!["rust".into()],
        egress: vec![
            "index.crates.io".into(),
            "static.crates.io".into(),
            "crates.io".into(),
        ],
        ..ServeConfig::default()
    };
    serve.save(&root.serve_toml()).unwrap();

    if grant {
        let mut accept = AcceptConfig::load(&root.accept_toml()).unwrap();
        accept.grant(AcceptedPeer {
            device_id: hex::encode(device_id),
            transport_pubkey: hex::encode(transport_pubkey),
            name: "requester".into(),
        });
        accept.save(&root.accept_toml()).unwrap();
    }

    // The rustup home must exist for bwrap's read-only `/opt/toolchain` bind.
    std::fs::create_dir_all(root.rustup_home()).unwrap();

    let server = Arc::new(
        WireServer::bind_with_bins(root, "127.0.0.1:0", sandbox_bins()).expect("runner binds"),
    );
    let addr = server.local_addr().unwrap().to_string();

    // A git repo to run jobs from (the CLI snapshots its cwd).
    let g = |args: &[&str]| {
        let ok = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .status()
            .expect("run git");
        assert!(ok.success(), "git {args:?} failed");
    };
    g(&["init", "-q"]);
    g(&["config", "user.email", "t@t"]);
    g(&["config", "user.name", "t"]);
    g(&["config", "commit.gpgsign", "false"]);
    std::fs::write(repo.join("f.txt"), "hello\n").unwrap();
    g(&["add", "-A"]);
    g(&["commit", "-q", "-m", "c1"]);

    Fixture {
        _tmp: tmp,
        _handle: handle,
        xdg,
        runner: server,
        addr,
        repo,
    }
}

/// Spawn a thread that accepts one runner connection and serves it.
fn serve_one(fx: &Fixture) {
    let s = Arc::clone(&fx.runner);
    std::thread::spawn(move || {
        let stream = softfig_net::testing::accept_within(s.listener(), "runner");
        let _ = s.serve_connection(stream);
    });
}

/// One `softfig run run --on <on> [extra…]` invocation, with `XDG_RUNTIME_DIR`
/// pointed at the fixture so the CLI resolves the keeperd socket. (`run` is a
/// subcommand group: the outer `run` is `Cmd::Run`, the inner `run` is
/// `RunCmd::Run(RunArgs)` — see the slice doc's note on the spec §9 wording.)
fn run_on(fx: &Fixture, on: &str, extra: &[&str]) -> Output {
    let mut argv: Vec<String> = vec!["run".into(), "run".into(), "--on".into(), on.to_string()];
    argv.extend(extra.iter().map(|s| s.to_string()));
    Command::new(env!("CARGO_BIN_EXE_softfig"))
        .args(&argv)
        .env("XDG_RUNTIME_DIR", &fx.xdg)
        .current_dir(&fx.repo)
        .output()
        .expect("softfig runs")
}

fn code(out: &Output) -> Option<i32> {
    out.status.code()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The happy path: a granted job's own exit code passes straight through the
/// process — including a non-zero "ran and failed" code, which is a real
/// result, never a fallback trigger (spec §9).
#[test]
fn run_returns_the_jobs_own_exit_code() {
    if execution_skip() {
        return;
    }
    let fx = boot(true, true);

    // exit 0 passes through.
    serve_one(&fx);
    let out = run_on(&fx, &fx.addr, &["--", "sh", "-c", "exit 0"]);
    assert_eq!(code(&out), Some(0), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));

    // A non-zero "ran and failed" code passes through unchanged (NOT a fallback).
    serve_one(&fx);
    let out = run_on(&fx, &fx.addr, &["--", "sh", "-c", "exit 7"]);
    assert_eq!(code(&out), Some(7), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
}

/// A runner-side failure that is NOT a fallback trigger (an ungranted requester
/// → `not-granted`) exits 254 with the reason — no local fallback (spec §9).
#[test]
fn run_returns_254_and_reason_on_a_not_granted_reject() {
    let fx = boot(true, false); // enabled, but the requester is not granted

    serve_one(&fx);
    let out = run_on(&fx, &fx.addr, &["--", "sh", "-c", "exit 0"]);
    assert_eq!(code(&out), Some(254), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
    assert!(
        stderr(&out).contains("runner rejected: not-granted"),
        "stderr: {}",
        stderr(&out)
    );
}

/// A fallback-trigger reject (`disabled`) with `--fallback fail` exits 254 with
/// the reason, without running the command (spec §9).
#[test]
fn run_returns_254_on_a_disabled_reject_with_fallback_fail() {
    let fx = boot(false, false); // runner disabled

    serve_one(&fx);
    let out = run_on(&fx, &fx.addr, &["--fallback", "fail", "--", "sh", "-c", "exit 0"]);
    assert_eq!(code(&out), Some(254), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
    assert!(
        stderr(&out).contains("runner rejected: disabled"),
        "stderr: {}",
        stderr(&out)
    );
}

/// A `no-runner` fallback trigger with `--fallback fail` exits 254 (spec §9).
#[test]
fn run_returns_254_on_no_runner_with_fallback_fail() {
    let fx = boot(true, true);

    // A guaranteed-dead loopback port: bind, learn the addr, then drop.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = listener.local_addr().unwrap().to_string();
    drop(listener);

    let out = run_on(&fx, &dead, &["--fallback", "fail", "--", "sh", "-c", "exit 0"]);
    assert_eq!(code(&out), Some(254), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
    assert!(
        stderr(&out).contains("no runner reachable"),
        "stderr: {}",
        stderr(&out)
    );
}

/// The decided `local` fallback (spec §9): a `no-runner` trigger runs the same
/// command locally in the repo, prints a loud `ran LOCALLY: <reason>` line, and
/// propagates the local command's own exit code.
#[test]
fn run_falls_back_locally_on_no_runner() {
    let fx = boot(true, true);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = listener.local_addr().unwrap().to_string();
    drop(listener);

    let out = run_on(&fx, &dead, &["--", "sh", "-c", "exit 0"]);
    assert_eq!(code(&out), Some(0), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
    assert!(
        stderr(&out).contains("ran LOCALLY: no runner reachable"),
        "stderr: {}",
        stderr(&out)
    );
}
