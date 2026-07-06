//! M3a integration: the typed, daemon-mediated garden-write verbs end to
//! end (happy path + rejection cases per action). Covers the original five
//! M3a verbs plus the Slice 1 small-files note verbs (`add_note` /
//! `revise_note`), which share the same harness and contract.
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
    op, AddCodeReviewArgs, AddCodeReviewReply, AddNoteArgs, AddNoteReply, AddProjectArgs,
    AddProjectReply, AddSectionArgs,
    AppendToSectionArgs, ArchiveArgs, ArchiveReply, DocEditReply, EditSectionArgs,
    LogDecisionArgs, LogDecisionReply, LogIncidentArgs, LogIncidentReply, MigrateConfigReply,
    MigrateSplitReply,
    RefreshSnapshotArgs, RefreshSnapshotReply, ReviseNoteArgs, ReviseNoteReply, SetReviewedArgs,
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
    // Slice 1: `notes` is now a numbered-note folder seeded with `.seq`,
    // not a `notes.md` monolith.
    for stub in ["CLAUDE.md", "instructions.md", "notes/.seq", "refs.md"] {
        assert!(
            fx.garden.join(format!("projects/cool-proj/{stub}")).exists(),
            "missing {stub}"
        );
    }
    assert!(!fx.garden.join("projects/cool-proj/notes.md").exists());
    assert_eq!(
        std::fs::read_to_string(fx.garden.join("projects/cool-proj/notes/.seq")).unwrap(),
        "0\n"
    );
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

// ---- add_note / revise_note (Slice 1) ---------------------------------

/// Create a concept dir so its accretive `notes/` folder has a parent to
/// be materialized under.
fn make_concept_dir(fx: &Fixture, rel: &str) {
    std::fs::create_dir_all(fx.garden.join(rel)).unwrap();
}

#[test]
fn add_note_happy_assigns_001_and_seq() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "services/waydroid");
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::to_value(AddNoteArgs {
            dir: "services/waydroid/notes".into(),
            slug: "container-networking".into(),
            title: Some("Container networking".into()),
            body: "Waydroid uses an internal bridge.".into(),
        })
        .unwrap(),
    );
    let reply: AddNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "services/waydroid/notes/001-container-networking.md");

    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(content.starts_with("# Container networking\n"), "header: {content:?}");
    assert!(content.contains(&format!("> Last reviewed: {}\n", conventions::today_hyphen())));
    assert!(content.contains("Waydroid uses an internal bridge."));

    // `.seq` high-water mark bumped to 1.
    assert_eq!(
        std::fs::read_to_string(fx.garden.join("services/waydroid/notes/.seq")).unwrap(),
        "1\n"
    );

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "note_added");
    assert_eq!(payload["number"], 1);
    assert_eq!(payload["slug"], "container-networking");
    assert_eq!(payload["dir"], "services/waydroid/notes");
}

#[test]
fn add_note_title_defaults_to_slug() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "input");
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "input/notes", "slug": "stylus-tilt", "body": "b" }),
    );
    let reply: AddNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(content.starts_with("# stylus-tilt\n"));
}

#[test]
fn add_note_increments_per_folder() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "services/waydroid");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "one", "body": "a" }),
    );
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "two", "body": "b" }),
    );
    let reply: AddNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "services/waydroid/notes/002-two.md");
    // troubleshooting/ in the same concept dir is an independent sequence.
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/troubleshooting", "slug": "adb", "body": "c" }),
    );
    let reply: AddNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "services/waydroid/troubleshooting/001-adb.md");
}

/// The core invariant: archiving the newest note must NOT hand its number
/// to the next `add_note` — `.seq` guards against reuse even though the
/// live-file floor dropped back.
#[test]
fn add_note_archive_leaves_a_gap() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "services/waydroid");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "one", "body": "a" }),
    );
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "two", "body": "b" }),
    );
    // Archive the newest (002). `.seq` stays at 2.
    let resp = fx.call(
        op::ARCHIVE,
        serde_json::json!({ "src": "services/waydroid/notes/002-two.md" }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "archive: {resp:?}");
    // Next note is 003, not a reused 002.
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "three", "body": "c" }),
    );
    let reply: AddNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "services/waydroid/notes/003-three.md");
    assert_eq!(
        std::fs::read_to_string(fx.garden.join("services/waydroid/notes/.seq")).unwrap(),
        "3\n"
    );
}

#[test]
fn add_note_into_seeded_project_folder() {
    let fx = Fixture::start();
    // add_project seeds notes/.seq = 0; the first note must count from 001.
    fx.call(op::ADD_PROJECT, serde_json::json!({ "name": "demo" }));
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "projects/demo/notes", "slug": "kickoff", "body": "start" }),
    );
    let reply: AddNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "projects/demo/notes/001-kickoff.md");
}

#[test]
fn add_note_rejects_non_accretive_dir() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "services/waydroid");
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid", "slug": "x", "body": "b" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::NotAccretiveDir);
}

#[test]
fn add_note_rejects_bad_slug() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "services/waydroid");
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "Bad_Slug", "body": "b" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::InvalidSlug);
}

#[test]
fn add_note_rejects_missing_parent_dir() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "nope/notes", "slug": "x", "body": "b" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::NotFound);
}

// ---- add_code_review (task 020) ----------------------------------------

#[test]
fn add_code_review_happy_assigns_001_and_seq() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "projects/demo");
    let resp = fx.call(
        op::ADD_CODE_REVIEW,
        serde_json::to_value(AddCodeReviewArgs {
            dir: "projects/demo/code-reviews".into(),
            slug: "fleet-loop-spin".into(),
            title: Some("Code review: fleet-loop-spin".into()),
            body: "## Verdict\n\nPass, no defects.".into(),
        })
        .unwrap(),
    );
    let reply: AddCodeReviewReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "projects/demo/code-reviews/001-fleet-loop-spin.md");

    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(content.starts_with("# Code review: fleet-loop-spin\n"), "header: {content:?}");
    assert!(content.contains(&format!("> Last reviewed: {}\n", conventions::today_hyphen())));
    assert!(content.contains("Pass, no defects."));

    // `.seq` high-water mark bumped to 1 — an independent sequence.
    assert_eq!(
        std::fs::read_to_string(fx.garden.join("projects/demo/code-reviews/.seq")).unwrap(),
        "1\n"
    );

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "code_review_added");
    assert_eq!(payload["number"], 1);
    assert_eq!(payload["slug"], "fleet-loop-spin");
    assert_eq!(payload["dir"], "projects/demo/code-reviews");
}

/// `code-reviews/` numbers independently of a sibling `notes/` — each
/// accretive folder is its own sequence.
#[test]
fn add_code_review_numbers_independently_of_notes() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "projects/demo");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "projects/demo/notes", "slug": "one", "body": "a" }),
    );
    let resp = fx.call(
        op::ADD_CODE_REVIEW,
        serde_json::json!({ "dir": "projects/demo/code-reviews", "slug": "first", "body": "b" }),
    );
    let reply: AddCodeReviewReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "projects/demo/code-reviews/001-first.md");
}

/// The genre gates are mutual: `add_code_review` refuses a `notes/` dir and
/// `add_note` refuses a `code-reviews/` dir — a review is a distinct genre.
#[test]
fn add_verbs_gate_on_their_genre_folder() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "projects/demo");
    let resp = fx.call(
        op::ADD_CODE_REVIEW,
        serde_json::json!({ "dir": "projects/demo/notes", "slug": "x", "body": "b" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::NotAccretiveDir);
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "projects/demo/code-reviews", "slug": "x", "body": "b" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::NotAccretiveDir);
}

/// `revise_note` treats `code-reviews/` as accretive — a review body can be
/// revised in place (re-stamped reviewed date), same contract as notes.
#[test]
fn revise_note_works_on_code_reviews() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "projects/demo");
    fx.call(
        op::ADD_CODE_REVIEW,
        serde_json::json!({ "dir": "projects/demo/code-reviews", "slug": "first", "body": "old" }),
    );
    let resp = fx.call(
        op::REVISE_NOTE,
        serde_json::json!({ "dir": "projects/demo/code-reviews", "id": 1, "body": "new verdict" }),
    );
    let reply: ReviseNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(content.starts_with("# first\n"));
    assert!(content.contains("new verdict"));
    assert!(!content.contains("old"));
}

#[test]
fn revise_note_replaces_body_keeps_title() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "services/waydroid");
    fx.call(
        op::ADD_NOTE,
        serde_json::to_value(AddNoteArgs {
            dir: "services/waydroid/notes".into(),
            slug: "gpu".into(),
            title: Some("GPU passthrough".into()),
            body: "old body".into(),
        })
        .unwrap(),
    );
    let resp = fx.call(
        op::REVISE_NOTE,
        serde_json::to_value(ReviseNoteArgs {
            dir: "services/waydroid/notes".into(),
            id: 1,
            body: "new body with venus".into(),
        })
        .unwrap(),
    );
    let reply: ReviseNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "services/waydroid/notes/001-gpu.md");

    let content = std::fs::read_to_string(fx.garden.join(&reply.path)).unwrap();
    assert!(content.starts_with("# GPU passthrough\n"), "title preserved: {content:?}");
    assert!(content.contains("new body with venus"));
    assert!(!content.contains("old body"));

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "note_revised");
    assert_eq!(payload["id"], 1);
}

#[test]
fn revise_note_rejects_missing_id() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "services/waydroid");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "x", "body": "b" }),
    );
    let resp = fx.call(
        op::REVISE_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "id": 99, "body": "b" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::NotFound);
}

// ---- section ops + set_reviewed (Slice 2) -----------------------------

/// Write a markdown doc straight into the working tree so the section verbs
/// have a real file to operate on (they read the working tree like
/// `revise_note`, then snapshot it on commit).
fn write_doc(fx: &Fixture, rel: &str, content: &str) {
    let abs = fx.garden.join(rel);
    std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
    std::fs::write(abs, content).unwrap();
}

#[test]
fn edit_section_replaces_body_keeps_siblings() {
    let fx = Fixture::start();
    write_doc(&fx, "x.md", "# Doc\n\n## Alpha\n\nold alpha\n\n## Beta\n\nbeta body\n");
    let resp = fx.call(
        op::EDIT_SECTION,
        serde_json::to_value(EditSectionArgs {
            path: "x.md".into(),
            heading: "Alpha".into(),
            body: "new alpha".into(),
            expected_version: None,
            editor: None,
        })
        .unwrap(),
    );
    let reply: DocEditReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "x.md");
    let content = std::fs::read_to_string(fx.garden.join("x.md")).unwrap();
    assert_eq!(content, "# Doc\n\n## Alpha\n\nnew alpha\n\n## Beta\n\nbeta body\n");

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "section_edited");
    assert_eq!(payload["path"], "x.md");
    assert_eq!(payload["heading"], "Alpha");
}

#[test]
fn append_to_section_adds_row() {
    let fx = Fixture::start();
    write_doc(&fx, "refs.md", "# refs\n\n## Cross-refs\n\n- foo\n- bar\n");
    let resp = fx.call(
        op::APPEND_TO_SECTION,
        serde_json::to_value(AppendToSectionArgs {
            path: "refs.md".into(),
            heading: "## Cross-refs".into(),
            text: "- baz".into(),
            expected_version: None,
            editor: None,
        })
        .unwrap(),
    );
    assert!(matches!(resp, Response::Ok { .. }), "append: {resp:?}");
    let content = std::fs::read_to_string(fx.garden.join("refs.md")).unwrap();
    assert_eq!(content, "# refs\n\n## Cross-refs\n\n- foo\n- bar\n- baz\n");
    assert_eq!(fx.tip_intent().0, "section_appended");
}

#[test]
fn add_section_appends_new_section() {
    let fx = Fixture::start();
    write_doc(&fx, "x.md", "# Doc\n\n## Alpha\n\na\n");
    let resp = fx.call(
        op::ADD_SECTION,
        serde_json::to_value(AddSectionArgs {
            path: "x.md".into(),
            heading: "Gamma".into(),
            body: "g body".into(),
        })
        .unwrap(),
    );
    assert!(matches!(resp, Response::Ok { .. }), "add: {resp:?}");
    let content = std::fs::read_to_string(fx.garden.join("x.md")).unwrap();
    assert_eq!(content, "# Doc\n\n## Alpha\n\na\n\n## Gamma\n\ng body\n");
    assert_eq!(fx.tip_intent().0, "section_added");
}

#[test]
fn edit_section_rejects_missing_and_ambiguous() {
    let fx = Fixture::start();
    write_doc(&fx, "x.md", "## A\n\nx\n\n## A\n\ny\n");
    assert_eq!(
        err_kind(fx.call(
            op::EDIT_SECTION,
            serde_json::json!({ "path": "x.md", "heading": "Nope", "body": "z" }),
        )),
        ErrorKind::NotFound
    );
    assert_eq!(
        err_kind(fx.call(
            op::EDIT_SECTION,
            serde_json::json!({ "path": "x.md", "heading": "A", "body": "z" }),
        )),
        ErrorKind::BadArgs
    );
}

#[test]
fn add_section_rejects_existing_heading() {
    let fx = Fixture::start();
    write_doc(&fx, "x.md", "## Alpha\n\na\n");
    let resp = fx.call(
        op::ADD_SECTION,
        serde_json::json!({ "path": "x.md", "heading": "Alpha", "body": "b" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::PathAlreadyExists);
}

#[test]
fn section_op_refuses_inline_vault_region() {
    let fx = Fixture::start();
    // A doc carrying a real inline region: editing any of its sections
    // would risk clobbering ciphertext, so the daemon refuses outright.
    write_doc(
        &fx,
        "x.md",
        "# Doc\n\n## Secrets\n\nkey: <vault id=\"api\">SECRET</vault>\n",
    );
    let resp = fx.call(
        op::EDIT_SECTION,
        serde_json::json!({ "path": "x.md", "heading": "Secrets", "body": "z" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::VaultProtected);
    // The file is untouched (no clobber, no commit of a redacted body).
    let content = std::fs::read_to_string(fx.garden.join("x.md")).unwrap();
    assert!(content.contains("<vault id=\"api\">SECRET</vault>"));
}

#[test]
fn set_reviewed_bumps_date() {
    let fx = Fixture::start();
    write_doc(&fx, "n.md", "# Note\n\n> Last reviewed: 2020-01-01\n\nbody\n");
    let resp = fx.call(
        op::SET_REVIEWED,
        serde_json::to_value(SetReviewedArgs { path: "n.md".into() }).unwrap(),
    );
    assert!(matches!(resp, Response::Ok { .. }), "set_reviewed: {resp:?}");
    let content = std::fs::read_to_string(fx.garden.join("n.md")).unwrap();
    assert_eq!(
        content,
        format!("# Note\n\n> Last reviewed: {}\n\nbody\n", conventions::today_hyphen())
    );
    assert_eq!(fx.tip_intent().0, "reviewed_stamped");
}

#[test]
fn set_reviewed_rejects_missing_line() {
    let fx = Fixture::start();
    write_doc(&fx, "n.md", "# Note\n\nno stamp here\n");
    let resp = fx.call(op::SET_REVIEWED, serde_json::json!({ "path": "n.md" }));
    assert_eq!(err_kind(resp), ErrorKind::NotFound);
}

// ---- auto index tables (Slice 4) --------------------------------------

/// `add_note` into a folder whose parent concept dir has a `CLAUDE.md`
/// injects + grows a daemon-owned index region in that routing doc.
#[test]
fn add_note_builds_index_in_parent_claude_md() {
    let fx = Fixture::start();
    write_doc(&fx, "services/waydroid/CLAUDE.md", "# services/waydroid/\n\nrouting prose\n");

    fx.call(
        op::ADD_NOTE,
        serde_json::to_value(AddNoteArgs {
            dir: "services/waydroid/notes".into(),
            slug: "container-networking".into(),
            title: Some("Container networking".into()),
            body: "uses a bridge".into(),
        })
        .unwrap(),
    );
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({
            "dir": "services/waydroid/notes",
            "slug": "gpu-passthrough",
            "title": "GPU passthrough",
            "body": "venus driver",
        }),
    );

    let claude =
        std::fs::read_to_string(fx.garden.join("services/waydroid/CLAUDE.md")).unwrap();
    // Hand-authored prose preserved.
    assert!(claude.starts_with("# services/waydroid/\n\nrouting prose\n"));
    // Managed region present with both rows, linked relative to the host.
    assert!(claude.contains("<!-- softfig:index notes -->"), "{claude}");
    assert!(claude.contains("<!-- /softfig:index notes -->"), "{claude}");
    assert!(claude.contains(
        "| 001 | [Container networking](notes/001-container-networking.md) |"
    ));
    assert!(claude.contains("| 002 | [GPU passthrough](notes/002-gpu-passthrough.md) |"));

    // The index write rides along inside the `note_added` commit.
    assert_eq!(fx.tip_intent().0, "note_added");
}

/// `revise_note` re-stamps the reviewed date, so the index's Reviewed
/// column must follow.
#[test]
fn revise_note_updates_index_reviewed_column() {
    let fx = Fixture::start();
    write_doc(&fx, "input/CLAUDE.md", "# input/\n");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "input/notes", "slug": "tilt", "title": "Stylus tilt", "body": "old" }),
    );
    // Backdate the note's reviewed line, then revise it.
    let note = fx.garden.join("input/notes/001-tilt.md");
    let stale = std::fs::read_to_string(&note)
        .unwrap()
        .replace(&conventions::today_hyphen(), "2020-01-01");
    std::fs::write(&note, stale).unwrap();

    fx.call(
        op::REVISE_NOTE,
        serde_json::json!({ "dir": "input/notes", "id": 1, "body": "new" }),
    );
    let claude = std::fs::read_to_string(fx.garden.join("input/CLAUDE.md")).unwrap();
    assert!(
        claude.contains(&format!(
            "| 001 | [Stylus tilt](notes/001-tilt.md) | {} |",
            conventions::today_hyphen()
        )),
        "{claude}"
    );
}

/// Archiving the only note empties the folder, so its index region is
/// dropped from the routing doc; a re-added note recreates it.
#[test]
fn archive_last_note_removes_index_region() {
    let fx = Fixture::start();
    write_doc(&fx, "audio/CLAUDE.md", "# audio/\n\nhow audio fits.\n");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "audio/notes", "slug": "pw", "title": "Pipewire", "body": "x" }),
    );
    assert!(std::fs::read_to_string(fx.garden.join("audio/CLAUDE.md"))
        .unwrap()
        .contains("<!-- softfig:index notes -->"));

    let resp = fx.call(
        op::ARCHIVE,
        serde_json::json!({ "src": "audio/notes/001-pw.md" }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "archive: {resp:?}");
    let claude = std::fs::read_to_string(fx.garden.join("audio/CLAUDE.md")).unwrap();
    assert!(!claude.contains("softfig:index notes"), "region should be gone: {claude}");
    // Hand-authored prose survives the removal.
    assert!(claude.contains("how audio fits."));
}

/// No host `CLAUDE.md` → index maintenance is silently skipped (the note
/// still lands). Guards the best-effort contract.
#[test]
fn add_note_without_host_claude_md_still_succeeds() {
    let fx = Fixture::start();
    make_concept_dir(&fx, "storage");
    let resp = fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "storage/notes", "slug": "luks", "body": "b" }),
    );
    let reply: AddNoteReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "storage/notes/001-luks.md");
    assert!(!fx.garden.join("storage/CLAUDE.md").exists());
}

// ---- auto backlinks (Slice 5) -----------------------------------------

/// A `[[NNN-slug]]` sibling ref in one note grows a backlinks region in the
/// referenced note (listing the referrer's garden-relative path).
#[test]
fn add_note_sibling_ref_creates_backlink() {
    let fx = Fixture::start();
    write_doc(&fx, "services/waydroid/CLAUDE.md", "# services/waydroid/\n");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "base", "title": "Base", "body": "the base" }),
    );
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "services/waydroid/notes", "slug": "uses", "title": "Uses", "body": "builds on [[001-base]]." }),
    );

    let base =
        std::fs::read_to_string(fx.garden.join("services/waydroid/notes/001-base.md")).unwrap();
    assert!(base.contains("<!-- softfig:backlinks -->"), "{base}");
    assert!(base.contains("- `services/waydroid/notes/002-uses.md`"), "{base}");
    // The referencing note keeps its `[[…]]` body verbatim.
    let uses =
        std::fs::read_to_string(fx.garden.join("services/waydroid/notes/002-uses.md")).unwrap();
    assert!(uses.contains("builds on [[001-base]]."));
}

/// A `[[path]]` ref authored in a non-accretive doc resolves once the target
/// is created — the previously-dangling edge lights up on `add_note`.
#[test]
fn path_ref_backlink_appears_when_target_added() {
    let fx = Fixture::start();
    write_doc(
        &fx,
        "storage/CLAUDE.md",
        "# storage/\n\nsee [[storage/notes/001-luks.md]] for the setup.\n",
    );
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "storage/notes", "slug": "luks", "title": "LUKS", "body": "disk crypto" }),
    );
    let note = std::fs::read_to_string(fx.garden.join("storage/notes/001-luks.md")).unwrap();
    assert!(note.contains("- `storage/CLAUDE.md`"), "{note}");
}

/// Revising a note to drop its only `[[…]]` ref removes the now-stale
/// backlinks region from the former target.
#[test]
fn revise_note_dropping_ref_removes_backlink() {
    let fx = Fixture::start();
    write_doc(&fx, "input/CLAUDE.md", "# input/\n");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "input/notes", "slug": "base", "title": "Base", "body": "b" }),
    );
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "input/notes", "slug": "uses", "title": "Uses", "body": "see [[001-base]]" }),
    );
    assert!(std::fs::read_to_string(fx.garden.join("input/notes/001-base.md"))
        .unwrap()
        .contains("softfig:backlinks"));

    fx.call(
        op::REVISE_NOTE,
        serde_json::json!({ "dir": "input/notes", "id": 2, "body": "no more refs" }),
    );
    let base = std::fs::read_to_string(fx.garden.join("input/notes/001-base.md")).unwrap();
    assert!(!base.contains("softfig:backlinks"), "stale region remained: {base}");
}

/// Archiving a referenced note repoints inbound `[[…]]` refs at the archived
/// location so they don't dangle.
#[test]
fn archive_repoints_inbound_refs() {
    let fx = Fixture::start();
    write_doc(&fx, "audio/CLAUDE.md", "# audio/\n");
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "audio/notes", "slug": "base", "title": "Base", "body": "b" }),
    );
    fx.call(
        op::ADD_NOTE,
        serde_json::json!({ "dir": "audio/notes", "slug": "uses", "title": "Uses", "body": "see [[001-base]]" }),
    );

    let resp = fx.call(
        op::ARCHIVE,
        serde_json::json!({ "src": "audio/notes/001-base.md", "archive_name": "base" }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "archive: {resp:?}");

    let uses = std::fs::read_to_string(fx.garden.join("audio/notes/002-uses.md")).unwrap();
    assert!(
        uses.contains("[[journal/archive/base/001-base.md]]"),
        "ref not repointed: {uses}"
    );
    assert!(!uses.contains("[[001-base]]"), "old ref remained: {uses}");
}

// ---- migrate_split (one-time monolith → numbered notes) ---------------

#[test]
fn migrate_split_dry_run_then_apply_then_idempotent() {
    let fx = Fixture::start();
    // A concept dir with a legacy monolith carrying two `## ` sections plus
    // a preamble (title + reviewed stamp + intro) that the split drops.
    write_doc(&fx, "services/waydroid/CLAUDE.md", "# services/waydroid\n");
    write_doc(
        &fx,
        "services/waydroid/notes.md",
        "# notes\n\n> Last reviewed: 2026-05-01\n\nintro prose\n\n\
         ## container networking\n\nWaydroid uses an internal bridge.\n\n\
         ## GPU passthrough\n\nNeeds the venus driver.\n",
    );

    // Dry run: discovers the monolith, plans 2 notes, writes/commits nothing.
    let resp = fx.call(op::MIGRATE_SPLIT, serde_json::json!({ "apply": false }));
    let reply: MigrateSplitReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(!reply.applied);
    assert_eq!(reply.splits.len(), 1);
    let s = &reply.splits[0];
    assert_eq!(s.from, "services/waydroid/notes.md");
    assert_eq!(s.folder, "services/waydroid/notes");
    assert_eq!(s.notes, 2);
    assert!(s.hash.is_none() && s.archived_to.is_none());
    assert!(reply.skipped.is_empty());
    // Nothing materialized by a dry run.
    assert!(!fx.garden.join("services/waydroid/notes").exists());
    assert!(fx.garden.join("services/waydroid/notes.md").exists());

    // Apply: materialize the folder, archive the monolith, commit.
    let resp = fx.call(op::MIGRATE_SPLIT, serde_json::json!({ "apply": true }));
    let reply: MigrateSplitReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(reply.applied);
    assert_eq!(reply.splits.len(), 1);
    let s = &reply.splits[0];
    assert_eq!(s.notes, 2);
    assert_eq!(
        s.archived_to.as_deref(),
        Some("journal/archive/services-waydroid-notes/notes.md")
    );
    assert!(s.hash.is_some());

    // Numbered notes + seq materialized; the monolith left its old path.
    let n1 = std::fs::read_to_string(
        fx.garden.join("services/waydroid/notes/001-container-networking.md"),
    )
    .unwrap();
    assert!(n1.starts_with("# container networking\n"), "header: {n1:?}");
    assert!(n1.contains(&format!("> Last reviewed: {}", conventions::today_hyphen())));
    assert!(n1.contains("internal bridge"));
    let n2 =
        std::fs::read_to_string(fx.garden.join("services/waydroid/notes/002-gpu-passthrough.md"))
            .unwrap();
    assert!(n2.contains("venus driver"));
    let seq = std::fs::read_to_string(fx.garden.join("services/waydroid/notes/.seq")).unwrap();
    assert_eq!(seq.trim(), "2");
    assert!(!fx.garden.join("services/waydroid/notes.md").exists());
    assert!(fx
        .garden
        .join("journal/archive/services-waydroid-notes/notes.md")
        .exists());

    // The commit is a monolith_split with the right payload.
    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "monolith_split");
    assert_eq!(payload["from"], "services/waydroid/notes.md");
    assert_eq!(payload["folder"], "services/waydroid/notes");
    assert_eq!(payload["notes"], 2);

    // Idempotent: the monolith is archived out of the tree, so a re-run finds
    // nothing to split and makes no further changes.
    let resp = fx.call(op::MIGRATE_SPLIT, serde_json::json!({ "apply": true }));
    let reply: MigrateSplitReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(reply.splits.is_empty(), "re-run split: {:?}", reply.splits);
    assert!(reply.skipped.is_empty(), "re-run skipped: {:?}", reply.skipped);
}

/// A monolith whose accretive folder already exists (a partial/prior
/// migration) is reported as skipped, never clobbered.
#[test]
fn migrate_split_skips_when_folder_exists() {
    let fx = Fixture::start();
    write_doc(&fx, "audio/CLAUDE.md", "# audio\n");
    write_doc(&fx, "audio/troubleshooting.md", "## x\n\nbody\n");
    write_doc(&fx, "audio/troubleshooting/.seq", "0\n");

    let resp = fx.call(op::MIGRATE_SPLIT, serde_json::json!({ "apply": true }));
    let reply: MigrateSplitReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(reply.splits.is_empty());
    assert_eq!(reply.skipped.len(), 1);
    assert_eq!(reply.skipped[0].path, "audio/troubleshooting.md");
    assert!(reply.skipped[0].reason.contains("already exists"));
    assert!(fx.garden.join("audio/troubleshooting.md").exists());
}

// ---- migrate_config (one-time keeper.toml → config/keeper.toml) --------

#[test]
fn migrate_config_dry_run_then_apply_then_idempotent() {
    use softfig_keeperd::keeper_toml::GardenConfig;
    let fx = Fixture::start();

    // Dry run: reports the path it would write; writes/commits nothing. This
    // garden never paired, so only keeper.toml is in play (no peers.toml).
    let resp = fx.call(op::MIGRATE_CONFIG, serde_json::json!({ "apply": false }));
    let reply: MigrateConfigReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(!reply.applied);
    assert_eq!(reply.migrated, vec!["config/keeper.toml".to_string()]);
    assert!(reply.skipped.is_empty());
    assert!(reply.hash.is_none());
    assert!(!fx.garden.join("config/keeper.toml").exists());

    // Apply: write + commit config/keeper.toml.
    let resp = fx.call(op::MIGRATE_CONFIG, serde_json::json!({ "apply": true }));
    let reply: MigrateConfigReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(reply.applied);
    assert_eq!(reply.migrated, vec!["config/keeper.toml".to_string()]);
    assert!(reply.hash.is_some());

    // The committed file parses and — from a born-minimal pointer — equals the
    // default policy.
    let gc = GardenConfig::load(&fx.garden).unwrap().unwrap();
    assert_eq!(gc, GardenConfig::default());

    // The commit is a `config_migrated` naming the migrated paths.
    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "config_migrated");
    assert_eq!(payload["paths"][0], "config/keeper.toml");

    // Idempotent: a re-run finds keeper.toml present (skipped) and, with no
    // legacy ring, nothing else to do — no write, no commit.
    let resp = fx.call(op::MIGRATE_CONFIG, serde_json::json!({ "apply": true }));
    let reply: MigrateConfigReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(!reply.applied);
    assert!(reply.migrated.is_empty());
    assert_eq!(reply.skipped, vec!["config/keeper.toml".to_string()]);
    assert!(reply.hash.is_none());
}
