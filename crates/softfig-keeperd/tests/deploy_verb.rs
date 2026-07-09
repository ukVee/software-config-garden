//! M4 deploy verbs (`deploy_plan` / `deploy_apply`) integration — the TUI
//! Deploy tab's daemon seam. Mirrors the M4a `softfig-deploy` tests, but drives
//! them *through the daemon* over IPC (the property the slice buys: the TUI
//! never touches the filesystem itself).
//!
//! The garden is M1c-compat (no `state_root` → no FUSE), so the suite runs
//! without `/dev/fuse`. The deploy verbs read `config/deploy.toml` +
//! `config/source/` straight off the garden root (a native-FS op by design),
//! and the daemon's `deploy_home` / `deploy_cache_root` overrides keep every
//! target + cache write inside the tempdir.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use softfig_ipc::verbs::{op, DeployAction, DeployApplyReply, DeployPlanReply};
use softfig_ipc::{ErrorKind, Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::{params::VaultParams, Vault};
use softfig_vcs::Repo;

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn init_garden(garden: &Path) {
    let (_vault, session, _recovery) =
        Vault::init_with_params(garden, PASS, fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            if let Ok(stream) = UnixStream::connect(path) {
                drop(stream);
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("socket {} did not appear", path.display());
}

fn send(socket: &Path, req: &Request) -> Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    let mut bytes = serde_json::to_vec(req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

struct Fixture {
    socket: PathBuf,
    garden: PathBuf,
    home: PathBuf,
    handle: Option<DaemonHandle>,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn start(unlock: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        // Garden under $HOME (as on-device: ~/soft-fig_garden), so a target can
        // resolve into it — the self-write case the deploy verbs must refuse.
        let garden = home.join("garden");
        std::fs::create_dir_all(&garden).unwrap();
        init_garden(&garden);

        let cache = tmp.path().join("cache");

        let socket = tmp.path().join("sock");
        let config = KeeperConfig::new(&garden)
            .without_watcher()
            .with_socket(&socket)
            .with_deploy_home(&home)
            .with_deploy_cache_root(&cache);
        let handle = Daemon::new(config).start().unwrap();
        wait_for_socket(&socket);
        if unlock {
            let resp = send(
                &socket,
                &Request::new(op::UNLOCK, serde_json::json!({ "passphrase": PASS_STR })),
            );
            assert!(matches!(resp, Response::Ok { .. }), "unlock: {resp:?}");
        }
        Fixture {
            socket,
            garden,
            home,
            handle: Some(handle),
            _tmp: tmp,
        }
    }

    fn call(&self, op_name: &str, args: serde_json::Value) -> Response {
        send(&self.socket, &Request::new(op_name, args))
    }

    /// Write `config/deploy.toml` directly into the garden root (the deploy
    /// verbs read it off the FS, exactly as they would through the FUSE mount).
    fn write_config(&self, toml: &str) {
        let dir = self.garden.join("config");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deploy.toml"), toml).unwrap();
    }

    /// Write a source file under `config/source/`.
    fn write_source(&self, rel: &str, bytes: &[u8]) {
        let p = self.garden.join("config").join("source").join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn target(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    fn plan(&self) -> DeployPlanReply {
        serde_json::from_value(ok_data(self.call(op::DEPLOY_PLAN, serde_json::json!({})))).unwrap()
    }

    fn apply(&self, force: bool) -> DeployApplyReply {
        serde_json::from_value(ok_data(
            self.call(op::DEPLOY_APPLY, serde_json::json!({ "force": force })),
        ))
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
            let _ = handle.join();
        }
    }
}

fn ok_data(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("expected Ok, got {kind:?}: {error}"),
    }
}

fn err_kind(resp: Response) -> ErrorKind {
    match resp {
        Response::Err { kind, .. } => kind,
        Response::Ok { data, .. } => panic!("expected Err, got Ok: {data}"),
    }
}

// ---- plan + apply (symlink create → skip) ----------------------------

#[test]
fn plan_create_then_apply_then_skip() {
    let fx = Fixture::start(true);
    fx.write_config(r#"[dots]
bashrc = { source = "bashrc", target = ".bashrc" }
"#);
    fx.write_source("bashrc", b"export EDITOR=vim\n");

    // Plan: target absent → create_symlink, no conflicts.
    let plan = fx.plan();
    assert_eq!(plan.entries.len(), 1);
    assert_eq!(plan.entries[0].name, "bashrc");
    assert_eq!(plan.entries[0].action, DeployAction::CreateSymlink);
    assert!(!plan.has_conflicts);

    // Apply: materializes the cache file + symlink.
    let report = fx.apply(false);
    assert_eq!(report.created, vec!["bashrc".to_string()]);
    assert!(report.conflicts.is_empty());
    let target = fx.target(".bashrc");
    assert!(
        std::fs::symlink_metadata(&target).unwrap().file_type().is_symlink(),
        "target should be a symlink"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"export EDITOR=vim\n");

    // Re-plan: nothing changed → skip_unchanged (idempotent).
    let plan2 = fx.plan();
    assert_eq!(plan2.entries[0].action, DeployAction::SkipUnchanged);
    let report2 = fx.apply(false);
    assert_eq!(report2.skipped, vec!["bashrc".to_string()]);
    assert!(report2.created.is_empty());
}

// ---- conflict refusal + --force --------------------------------------

#[test]
fn conflict_is_refused_then_forced() {
    let fx = Fixture::start(true);
    fx.write_config(r#"[dots]
vimrc = { source = "vimrc", target = ".vimrc" }
"#);
    fx.write_source("vimrc", b"set number\n");
    // An unmanaged file already sits at the target.
    std::fs::write(fx.target(".vimrc"), b"hand-written\n").unwrap();

    // Plan flags the conflict.
    let plan = fx.plan();
    assert_eq!(plan.entries[0].action, DeployAction::Conflict);
    assert!(plan.has_conflicts);
    assert!(plan.entries[0].conflict_reason.is_some());

    // Apply without force → refused, target untouched.
    let report = fx.apply(false);
    assert_eq!(report.conflicts.len(), 1);
    assert!(report.conflicts[0].contains("vimrc"));
    assert!(report.forced.is_empty());
    assert_eq!(std::fs::read(fx.target(".vimrc")).unwrap(), b"hand-written\n");

    // Apply with force → backed up + overwritten.
    let report2 = fx.apply(true);
    assert_eq!(report2.forced, vec!["vimrc".to_string()]);
    assert_eq!(
        std::fs::read(fx.target(".vimrc.softfig-bak")).unwrap(),
        b"hand-written\n"
    );
    assert_eq!(std::fs::read(fx.target(".vimrc")).unwrap(), b"set number\n");
}

// ---- copy method -----------------------------------------------------

#[test]
fn copy_method_plan_and_apply() {
    let fx = Fixture::start(true);
    fx.write_config(r#"[dots]
gitconfig = { source = "gitconfig", target = ".gitconfig", method = "copy" }
"#);
    fx.write_source("gitconfig", b"# gitconfig\n[user]\n  name = x\n");

    let plan = fx.plan();
    assert_eq!(plan.entries[0].action, DeployAction::CopyStamped);

    let report = fx.apply(false);
    assert_eq!(report.copied, vec!["gitconfig".to_string()]);
    let target = fx.target(".gitconfig");
    assert!(
        !std::fs::symlink_metadata(&target).unwrap().file_type().is_symlink(),
        "copy method writes a regular file, not a symlink"
    );
    let bytes = std::fs::read(&target).unwrap();
    assert!(bytes.windows(4).any(|w| w == b"name"), "source bytes present");
}

// ---- error paths -----------------------------------------------------

#[test]
fn missing_config_is_not_found() {
    let fx = Fixture::start(true);
    // No config/deploy.toml written.
    assert_eq!(
        err_kind(fx.call(op::DEPLOY_PLAN, serde_json::json!({}))),
        ErrorKind::NotFound
    );
}

#[test]
fn garden_internal_target_is_refused() {
    // A target that resolves inside the garden mount is a self-write / an
    // uncommitted garden mutation — the deploy verbs refuse it end-to-end
    // (task 036 finding c). `garden/…` is home-relative and the garden lives at
    // <home>/garden, so it lands inside garden_root.
    let fx = Fixture::start(true);
    fx.write_config(
        r#"[dots]
sneaky = { source = "s", target = "garden/config/source/evil" }
"#,
    );
    fx.write_source("s", b"x\n");
    assert_eq!(
        err_kind(fx.call(op::DEPLOY_PLAN, serde_json::json!({}))),
        ErrorKind::BadArgs,
        "an InvalidTarget inside the garden maps to BadArgs"
    );
}

#[test]
fn deploy_refuses_when_locked() {
    let fx = Fixture::start(false); // do NOT unlock
    fx.write_config(r#"[dots]
bashrc = { source = "bashrc", target = ".bashrc" }
"#);
    assert_eq!(
        err_kind(fx.call(op::DEPLOY_PLAN, serde_json::json!({}))),
        ErrorKind::VaultLocked
    );
    assert_eq!(
        err_kind(fx.call(op::DEPLOY_APPLY, serde_json::json!({ "force": false }))),
        ErrorKind::VaultLocked
    );
}
