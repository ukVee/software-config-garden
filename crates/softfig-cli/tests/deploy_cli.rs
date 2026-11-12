//! sweep-fixes slice 006 (report 168): `softfig deploy`, exercised as the
//! **binary** sends it — the built executable against a real keeperd on a temp
//! garden + temp socket (no FUSE, no watcher).
//!
//! The bug: the CLI read `config/source/` off `~/soft-fig_garden`, which on a
//! live device is the FUSE mount, and the mount serves a Layer-B sealed file as
//! the reader-redacted `[sealed:<path>]` projection — so a sealed dotfile source
//! deployed placeholder bytes into the live config. keeperd's `deploy_plan` /
//! `deploy_apply` read the plaintext through the mount-safe working tree
//! instead, and the CLI is now a thin client over them.
//!
//! The fixture stands in for the mount without needing `/dev/fuse`: keeperd's
//! garden holds the real plaintext, while `$HOME/soft-fig_garden` (the path the
//! old CLI defaulted to) holds the redacted projection. Any CLI path that reads
//! sources off that directory deploys the placeholder and fails the assertions
//! below. The CLI finds the daemon through `$XDG_RUNTIME_DIR`, as it does on a
//! device, so no flag differs between the two behaviours.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use serde_json::json;
use softfig_ipc::{connect, verbs::op, Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::{params::VaultParams, Vault};
use softfig_vcs::Repo;

const PASS: &str = "pw-test-12345";
const SECRET: &str = "this is SECRET sealed content\n";
const DEPLOY_TOML: &str = r#"[dots]
sealed-test = { source = "sealed-source", target = ".config/secret-target" }
"#;

struct Fixture {
    root: PathBuf,
    handle: Option<DaemonHandle>,
}

impl Fixture {
    /// `unlock = false` leaves the daemon locked; `daemon = false` boots none.
    fn start(tag: &str, daemon: bool, unlock: bool) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "softfig-cli-deploy-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let (home, garden, run) = (root.join("home"), root.join("garden"), root.join("run"));
        for d in [&home, &garden, &run] {
            fs::create_dir_all(d).unwrap();
        }

        // The mount's view: a sealed source reads as its redacted projection.
        let mount = home.join("soft-fig_garden");
        fs::create_dir_all(mount.join("config/source")).unwrap();
        fs::write(mount.join("config/deploy.toml"), DEPLOY_TOML).unwrap();
        fs::write(
            mount.join("config/source/sealed-source"),
            "[sealed:config/source/sealed-source]\n",
        )
        .unwrap();

        // keeperd's own garden: the plaintext the daemon reads through its
        // working tree.
        let mut params = VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let (_v, session, _r) = Vault::init_with_params(&garden, PASS.as_bytes(), params).unwrap();
        Repo::init(&garden, &session).unwrap();
        drop(session);
        fs::create_dir_all(garden.join("config/source")).unwrap();
        fs::write(garden.join("config/deploy.toml"), DEPLOY_TOML).unwrap();
        fs::write(garden.join("config/source/sealed-source"), SECRET).unwrap();

        let handle = daemon.then(|| {
            let socket = run.join("softfig-keeperd.sock");
            let config = KeeperConfig::new(&garden)
                .with_socket(&socket)
                .without_watcher()
                .without_net()
                .without_fuse()
                .with_deploy_home(&home)
                .with_deploy_cache_root(root.join("data/softfig/deployed"));
            let handle = Daemon::new(config).start().expect("keeperd boots");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !socket.exists() {
                assert!(std::time::Instant::now() < deadline, "socket never appeared");
                std::thread::sleep(Duration::from_millis(10));
            }
            if unlock {
                let mut stream = connect(&socket).expect("connect");
                let req = Request::new(op::UNLOCK, json!({ "passphrase": PASS }));
                let resp = softfig_ipc::call(&mut stream, &req).expect("unlock call");
                assert!(matches!(resp, Response::Ok { .. }), "unlock: {resp:?}");
            }
            handle
        });
        Fixture { root, handle }
    }

    fn target(&self) -> PathBuf {
        self.root.join("home/.config/secret-target")
    }

    /// The daemon's socket, where `$XDG_RUNTIME_DIR` points the default lookup.
    fn socket(&self) -> PathBuf {
        self.root.join("run/softfig-keeperd.sock")
    }

    fn deploy(&self, args: &[&str]) -> Output {
        self.deploy_in(&self.root.join("run"), args)
    }

    /// `softfig deploy` with `$XDG_RUNTIME_DIR` set to `runtime`.
    fn deploy_in(&self, runtime: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_softfig"))
            .arg("deploy")
            .args(args)
            .env("HOME", self.root.join("home"))
            .env("XDG_RUNTIME_DIR", runtime)
            .env("XDG_DATA_HOME", self.root.join("data"))
            .output()
            .expect("softfig runs")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
            let _ = handle.join();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "expected success, got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn refused(out: &Output) -> String {
    assert!(
        !out.status.success(),
        "expected refusal, got exit 0\nstdout: {}",
        String::from_utf8_lossy(&out.stdout),
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn a_sealed_source_deploys_plaintext_never_the_redacted_projection() {
    let fx = Fixture::start("sealed", true, true);
    let out = ok(&fx.deploy(&[]));
    assert!(out.contains("sealed-test"), "plan names the dot: {out}");

    let deployed = read(&fx.target());
    assert!(
        !deployed.contains("[sealed:"),
        "the redacted projection reached the target: {deployed:?}"
    );
    assert_eq!(deployed, SECRET);

    // The CLI and the daemon agree on a second run (report 168: each frontend
    // used to undo the other's plan for a sealed dot).
    let again = ok(&fx.deploy(&["--dry-run"]));
    assert!(again.contains("skip"), "second plan is a skip: {again}");
}

#[test]
fn dry_run_prints_the_plan_and_touches_nothing() {
    let fx = Fixture::start("dry", true, true);
    let out = ok(&fx.deploy(&["--dry-run"]));
    assert!(out.contains("symlink") && out.contains("sealed-test"), "plan: {out}");
    assert!(out.contains("dry run"), "dry-run notice: {out}");
    assert!(!fx.target().exists() && fs::symlink_metadata(fx.target()).is_err());
}

#[test]
fn a_conflict_is_refused_and_force_backs_up_then_deploys() {
    let fx = Fixture::start("force", true, true);
    fs::create_dir_all(fx.target().parent().unwrap()).unwrap();
    fs::write(fx.target(), "hand-written\n").unwrap();

    let err = refused(&fx.deploy(&[]));
    assert!(err.contains("--force"), "refusal points at --force: {err}");
    assert_eq!(read(&fx.target()), "hand-written\n");

    ok(&fx.deploy(&["--force"]));
    assert_eq!(read(&fx.target()), SECRET);
    let backup = fx.target().with_file_name("secret-target.softfig-bak");
    assert_eq!(read(&backup), "hand-written\n");
}

#[test]
fn no_daemon_is_a_clear_error_not_a_direct_read_of_the_mount() {
    let fx = Fixture::start("absent", false, false);
    let err = refused(&fx.deploy(&[]));
    assert!(err.contains("daemon"), "error names the daemon: {err}");
    assert!(fs::symlink_metadata(fx.target()).is_err(), "nothing deployed");
}

#[test]
fn a_locked_daemon_asks_for_an_unlock() {
    let fx = Fixture::start("locked", true, false);
    let err = refused(&fx.deploy(&[]));
    assert!(err.contains("unlock"), "error says to unlock: {err}");
    assert!(fs::symlink_metadata(fx.target()).is_err(), "nothing deployed");
}

/// Review 061 F15: `--socket` reaches a daemon the default lookup cannot. The
/// runtime dir the CLI would search holds no socket, so only the flag can find
/// the fixture's daemon — and without it the same call finds none.
#[test]
fn socket_flag_reaches_a_daemon_outside_the_runtime_dir() {
    let fx = Fixture::start("socket-flag", true, true);
    let empty = fx.root.join("elsewhere");
    fs::create_dir_all(&empty).unwrap();

    let err = refused(&fx.deploy_in(&empty, &[]));
    assert!(err.contains("daemon not running"), "no socket in the default dir: {err}");
    assert!(fs::symlink_metadata(fx.target()).is_err(), "nothing deployed");

    let socket = fx.socket();
    let socket = socket.to_str().unwrap();
    let out = ok(&fx.deploy_in(&empty, &["--socket", socket]));
    assert!(out.contains("sealed-test"), "plan names the dot: {out}");
    assert_eq!(read(&fx.target()), SECRET);
}

/// `--socket` pointing at nothing is the daemon-absent error, not a silent
/// fall-back to the default socket (which here exists and would deploy).
#[test]
fn socket_flag_does_not_fall_back_to_the_default_socket() {
    let fx = Fixture::start("socket-miss", true, true);
    let missing = fx.root.join("elsewhere/none.sock");
    let err = refused(&fx.deploy(&["--socket", missing.to_str().unwrap()]));
    assert!(err.contains("daemon not running"), "{err}");
    assert!(fs::symlink_metadata(fx.target()).is_err(), "nothing deployed");
}

/// The flags this branch removed are refused by the parser, not ignored.
#[test]
fn the_retired_source_flags_are_refused() {
    let fx = Fixture::start("retired", true, true);
    for flag in ["--garden-root", "--cache-root"] {
        let out = fx.deploy(&[flag, "/nonexistent"]);
        let err = refused(&out);
        assert!(err.contains(flag) && err.contains("unexpected"), "{flag}: {err}");
        assert!(fs::symlink_metadata(fx.target()).is_err(), "{flag}: nothing deployed");
    }
}
