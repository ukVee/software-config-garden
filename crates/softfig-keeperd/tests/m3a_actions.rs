//! M3a integration: the five typed, daemon-mediated garden-write verbs
//! end to end (happy path + rejection cases per action).
//!
//! All gardens are M1c-compat (no `state_root` → no FUSE), so the suite
//! runs without `/dev/fuse`. The watcher is disabled for predictable
//! runtime; each action registers its own paths in the suppression map
//! regardless.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use softfig_vcs::Repo;
use softfig_ipc::verbs::{
    op, AddProjectArgs, AddProjectReply, ArchiveArgs, ArchiveReply, LogDecisionArgs,
    LogDecisionReply, LogIncidentArgs, LogIncidentReply, RefreshSnapshotArgs,
    RefreshSnapshotReply,
};
use softfig_ipc::{ErrorKind, Request, Response};
use softfig_keeperd::actions::conventions;
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::{params::VaultParams, Vault};

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
    handle: Option<DaemonHandle>,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn start() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let garden = tmp.path().to_path_buf();
        init_garden(&garden);
        let socket = garden.join("sock");
        let config = KeeperConfig::new(&garden)
            .without_watcher()
            .with_socket(&socket);
        let handle = Daemon::new(config).start().unwrap();
        wait_for_socket(&socket);
        let resp = send(
            &socket,
            &Request::new(op::UNLOCK, serde_json::json!({ "passphrase": PASS_STR })),
        );
        assert!(matches!(resp, Response::Ok { .. }), "unlock: {resp:?}");
        Fixture {
            socket,
            garden,
            handle: Some(handle),
            _tmp: tmp,
        }
    }

    fn call(&self, op_name: &str, args: serde_json::Value) -> Response {
        send(&self.socket, &Request::new(op_name, args))
    }

    /// Intent + payload of the current tip commit (read via a fresh repo
    /// handle; WAL lets it coexist with the daemon's connection).
    fn tip_intent(&self) -> (String, serde_json::Value) {
        let repo = Repo::open(&self.garden).unwrap();
        let tip = repo.tip().unwrap().unwrap();
        let row = repo.db().get_commit(&tip).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
        (row.intent, payload)
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

// ---- log_decision -----------------------------------------------------

#[test]
fn log_decision_happy() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::LOG_DECISION,
        serde_json::to_value(LogDecisionArgs {
            slug: "use-foo".into(),
            summary: None,
            body: "We chose foo over bar.".into(),
        })
        .unwrap(),
    );
    let reply: LogDecisionReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "journal/decisions/decision-use-foo.md");

    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(content.starts_with("# decision: use-foo\n"), "header: {content:?}");
    assert!(content.contains(&format!("\n\nDate: {}\n", conventions::today_hyphen())));
    assert!(content.contains("We chose foo over bar."));

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "decision_logged");
    assert_eq!(payload["slug"], "use-foo");
}

#[test]
fn log_decision_uses_summary_as_title() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::LOG_DECISION,
        serde_json::to_value(LogDecisionArgs {
            slug: "pick-iced".into(),
            summary: Some("adopt Iced for the GUI".into()),
            body: "Rationale...".into(),
        })
        .unwrap(),
    );
    let reply: LogDecisionReply = serde_json::from_value(ok_data(resp)).unwrap();
    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(content.starts_with("# decision: adopt Iced for the GUI\n"));
}

#[test]
fn log_decision_rejects_bad_slug() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::LOG_DECISION,
        serde_json::json!({ "slug": "Bad_Slug", "body": "x" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::InvalidSlug);
}

#[test]
fn log_decision_rejects_on_exists() {
    let fx = Fixture::start();
    let args = serde_json::json!({ "slug": "dup", "body": "first" });
    assert!(matches!(fx.call(op::LOG_DECISION, args.clone()), Response::Ok { .. }));
    assert_eq!(
        err_kind(fx.call(op::LOG_DECISION, args)),
        ErrorKind::PathAlreadyExists
    );
}

// ---- log_incident -----------------------------------------------------

#[test]
fn log_incident_happy_with_explicit_date() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::LOG_INCIDENT,
        serde_json::to_value(LogIncidentArgs {
            slug: "tty-loop".into(),
            summary: "tty1 boot loop".into(),
            body: "It looped; fixed by X.".into(),
            date: Some("20260426".into()),
        })
        .unwrap(),
    );
    let reply: LogIncidentReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "journal/incidents/incident-20260426-tty-loop.md");

    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(
        content.starts_with("# 2026-04-26 — tty1 boot loop\n"),
        "header: {content:?}"
    );

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "incident_logged");
    assert_eq!(payload["slug"], "incident-20260426-tty-loop");
}

#[test]
fn log_incident_defaults_date_to_today() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::LOG_INCIDENT,
        serde_json::json!({ "slug": "x", "summary": "s", "body": "b" }),
    );
    let reply: LogIncidentReply = serde_json::from_value(ok_data(resp)).unwrap();
    let expected = format!(
        "journal/incidents/incident-{}-x.md",
        conventions::today_compact()
    );
    assert_eq!(reply.path, expected);
    assert_eq!(fx.tip_intent().0, "incident_logged");
}

#[test]
fn log_incident_rejects_bad_date() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::LOG_INCIDENT,
        serde_json::json!({ "slug": "x", "summary": "s", "body": "b", "date": "2026-04-26" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::BadArgs);
}

// ---- archive ----------------------------------------------------------

#[test]
fn archive_happy_with_explicit_name() {
    let fx = Fixture::start();
    std::fs::create_dir_all(fx.garden.join("inbox")).unwrap();
    std::fs::write(fx.garden.join("inbox/note.md"), "stale note").unwrap();

    let resp = fx.call(
        op::ARCHIVE,
        serde_json::to_value(ArchiveArgs {
            src: "inbox/note.md".into(),
            archive_name: Some("old-notes".into()),
        })
        .unwrap(),
    );
    let reply: ArchiveReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.from, "inbox/note.md");
    assert_eq!(reply.to, "journal/archive/old-notes/note.md");
    assert!(!fx.garden.join("inbox/note.md").exists());
    assert!(fx.garden.join(&reply.to).exists());

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "archive_move");
    assert_eq!(payload["from"], "inbox/note.md");
    assert_eq!(payload["to"], "journal/archive/old-notes/note.md");
}

#[test]
fn archive_defaults_name_to_basename() {
    let fx = Fixture::start();
    std::fs::create_dir_all(fx.garden.join("inbox")).unwrap();
    std::fs::write(fx.garden.join("inbox/widget.md"), "x").unwrap();

    let resp = fx.call(op::ARCHIVE, serde_json::json!({ "src": "inbox/widget.md" }));
    let reply: ArchiveReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.to, "journal/archive/widget.md/widget.md");
}

#[test]
fn archive_rejects_missing_source() {
    let fx = Fixture::start();
    let resp = fx.call(op::ARCHIVE, serde_json::json!({ "src": "nope/gone.md" }));
    assert_eq!(err_kind(resp), ErrorKind::SourceNotFound);
}

#[test]
fn archive_rejects_existing_destination() {
    let fx = Fixture::start();
    std::fs::write(fx.garden.join("a.md"), "x").unwrap();
    std::fs::create_dir_all(fx.garden.join("journal/archive/bucket")).unwrap();
    std::fs::write(fx.garden.join("journal/archive/bucket/a.md"), "occupied").unwrap();

    let resp = fx.call(
        op::ARCHIVE,
        serde_json::json!({ "src": "a.md", "archive_name": "bucket" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::PathAlreadyExists);
}

// ---- add_project ------------------------------------------------------

#[test]
fn add_project_happy_creates_four_stubs() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::ADD_PROJECT,
        serde_json::to_value(AddProjectArgs {
            name: "cool-proj".into(),
            repo_path: Some("/home/ukv/projects/cool-proj".into()),
            summary: Some("a cool project".into()),
        })
        .unwrap(),
    );
    let reply: AddProjectReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "projects/cool-proj");
    assert_eq!(reply.files.len(), 4);
    for stub in ["CLAUDE.md", "instructions.md", "notes.md", "refs.md"] {
        assert!(
            fx.garden.join(format!("projects/cool-proj/{stub}")).exists(),
            "missing {stub}"
        );
    }
    let claude = std::fs::read_to_string(fx.garden.join("projects/cool-proj/CLAUDE.md")).unwrap();
    assert!(claude.contains("/home/ukv/projects/cool-proj"));
    let instructions =
        std::fs::read_to_string(fx.garden.join("projects/cool-proj/instructions.md")).unwrap();
    assert!(instructions.contains("Last reviewed:"));

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "project_added");
    assert_eq!(payload["name"], "cool-proj");
    assert_eq!(payload["repo_path"], "/home/ukv/projects/cool-proj");
}

#[test]
fn add_project_omits_repo_sentence_when_absent() {
    let fx = Fixture::start();
    fx.call(op::ADD_PROJECT, serde_json::json!({ "name": "bare" }));
    let claude = std::fs::read_to_string(fx.garden.join("projects/bare/CLAUDE.md")).unwrap();
    assert!(!claude.contains("The actual code lives at"));
    assert_eq!(fx.tip_intent().1["repo_path"], "");
}

#[test]
fn add_project_rejects_existing() {
    let fx = Fixture::start();
    let args = serde_json::json!({ "name": "dup-proj" });
    assert!(matches!(fx.call(op::ADD_PROJECT, args.clone()), Response::Ok { .. }));
    assert_eq!(
        err_kind(fx.call(op::ADD_PROJECT, args)),
        ErrorKind::PathAlreadyExists
    );
}

#[test]
fn add_project_rejects_bad_name() {
    let fx = Fixture::start();
    let resp = fx.call(op::ADD_PROJECT, serde_json::json!({ "name": "-bad" }));
    assert_eq!(err_kind(resp), ErrorKind::InvalidProjectName);
}

// ---- refresh_snapshot -------------------------------------------------

#[test]
fn refresh_snapshot_happy() {
    let fx = Fixture::start();
    std::fs::create_dir_all(fx.garden.join("snapshots/packages")).unwrap();
    let resp = fx.call(
        op::REFRESH_SNAPSHOT,
        serde_json::to_value(RefreshSnapshotArgs {
            path: "snapshots/packages/pacman.md".into(),
            content: "# pacman packages\n\nfoo 1.0\n".into(),
        })
        .unwrap(),
    );
    let reply: RefreshSnapshotReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "snapshots/packages/pacman.md");
    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(content.contains("foo 1.0"));

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "snapshot_refresh");
    assert_eq!(payload["path"], "snapshots/packages/pacman.md");
}

#[test]
fn refresh_snapshot_overwrites() {
    let fx = Fixture::start();
    std::fs::create_dir_all(fx.garden.join("snapshots")).unwrap();
    let args = serde_json::json!({ "path": "snapshots/x.md", "content": "v1" });
    assert!(matches!(fx.call(op::REFRESH_SNAPSHOT, args), Response::Ok { .. }));
    let args2 = serde_json::json!({ "path": "snapshots/x.md", "content": "v2" });
    assert!(matches!(fx.call(op::REFRESH_SNAPSHOT, args2), Response::Ok { .. }));
    let content = std::fs::read_to_string(fx.garden.join("snapshots/x.md")).unwrap();
    assert_eq!(content, "v2");
}

#[test]
fn refresh_snapshot_rejects_outside_snapshots() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::REFRESH_SNAPSHOT,
        serde_json::json!({ "path": "inbox/x.md", "content": "c" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::InvalidSnapshotPath);
}

#[test]
fn refresh_snapshot_rejects_missing_parent() {
    let fx = Fixture::start();
    std::fs::create_dir_all(fx.garden.join("snapshots")).unwrap();
    let resp = fx.call(
        op::REFRESH_SNAPSHOT,
        serde_json::json!({ "path": "snapshots/nope/x.md", "content": "c" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::InvalidSnapshotPath);
}
