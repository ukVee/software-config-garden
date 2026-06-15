//! growlight Phase 1 integration: the four work-loop pillar verbs end to
//! end (`log_baton`, `add_backlog_item`, `add_slice`, `set_item_status`),
//! happy paths + the key invariants — per-folder numbering, the authoritative
//! queue table (status + order in one managed region), the single-active
//! rule, and idempotent re-sets.
//!
//! Same harness as `m3a_actions` (M1c-compat garden, no FUSE, watcher off);
//! each action registers its own paths in the suppression map.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use softfig_ipc::verbs::{
    op, AddBacklogItemReply, AddSliceReply, LogBatonReply, SetItemStatusReply,
};
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

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.garden.join(rel)).unwrap()
    }

    fn backlog(&self) -> String {
        self.read("growlight/backlog/CLAUDE.md")
    }

    fn tip_intent(&self) -> (String, serde_json::Value) {
        let repo = Repo::open(&self.garden).unwrap();
        let tip = repo.tip().unwrap().unwrap();
        let row = repo.db().get_commit(&tip).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
        (row.intent, payload)
    }

    fn add_milestone(&self, slug: &str, title: &str) -> AddBacklogItemReply {
        let resp = self.call(
            op::ADD_BACKLOG_ITEM,
            serde_json::json!({
                "item_type": "milestone", "slug": slug, "title": title,
                "mission": "why it exists", "finish_criteria": "done when X",
            }),
        );
        serde_json::from_value(ok_data(resp)).unwrap()
    }

    fn add_task(&self, slug: &str, title: &str) -> AddBacklogItemReply {
        let resp = self.call(
            op::ADD_BACKLOG_ITEM,
            serde_json::json!({
                "item_type": "task", "slug": slug, "title": title,
                "mission": "m", "finish_criteria": "f",
            }),
        );
        serde_json::from_value(ok_data(resp)).unwrap()
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

// ---- log_baton --------------------------------------------------------

#[test]
fn log_baton_assigns_001_and_stamps_metadata() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::LOG_BATON,
        serde_json::json!({
            "item": "m5b", "item_type": "milestone", "slice": "m5b-1",
            "iteration": 7, "status": "IN_PROGRESS", "ctx_pct": 41, "session_5h_pct": 63,
            "summary": "shipped the secure pipe; next: SAS ring",
        }),
    );
    let reply: LogBatonReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "growlight/baton-log/001-m5b-iter-7.md");

    let content = fx.read(&reply.path);
    assert!(content.starts_with("# baton m5b #7\n"), "header: {content:?}");
    assert!(content.contains("- slice: `m5b-1`"));
    assert!(content.contains("- status: IN_PROGRESS"));
    assert!(content.contains("- context: 41% · 5h-session: 63%"));
    assert!(content.contains("shipped the secure pipe"));
    assert_eq!(fx.read("growlight/baton-log/.seq"), "1\n");

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "baton_logged");
    assert_eq!(payload["item"], "m5b");
    assert_eq!(payload["number"], 1);
}

#[test]
fn log_baton_increments_and_honors_custom_slug() {
    let fx = Fixture::start();
    fx.call(
        op::LOG_BATON,
        serde_json::json!({ "item": "m5b", "iteration": 1, "summary": "a" }),
    );
    let resp = fx.call(
        op::LOG_BATON,
        serde_json::json!({ "item": "m5b", "iteration": 2, "summary": "b", "slug": "halt" }),
    );
    let reply: LogBatonReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.path, "growlight/baton-log/002-halt.md");
}

#[test]
fn log_baton_rejects_empty_summary() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::LOG_BATON,
        serde_json::json!({ "item": "m5b", "iteration": 1, "summary": "   " }),
    );
    assert_eq!(err_kind(resp), ErrorKind::BadArgs);
}

// ---- add_backlog_item -------------------------------------------------

#[test]
fn add_milestone_scaffolds_and_enqueues_queued() {
    let fx = Fixture::start();
    let reply = fx.add_milestone("m5b", "Zero-knowledge backup");
    assert_eq!(reply.id, "m5b");
    assert_eq!(reply.path, "growlight/backlog/milestones/m5b/CLAUDE.md");

    // Mission/finish doc, no status line (status lives in the queue table).
    let doc = fx.read(&reply.path);
    assert!(doc.starts_with("# backlog: Zero-knowledge backup\n"));
    assert!(doc.contains("## Mission\n\nwhy it exists"));
    assert!(doc.contains("## Finish criteria\n\ndone when X"));
    assert!(!doc.contains("status:"));
    // slices/ seeded so the first slice counts from 001.
    assert_eq!(fx.read("growlight/backlog/milestones/m5b/slices/.seq"), "0\n");

    // Enqueued as `queued` in the authoritative queue table.
    let backlog = fx.backlog();
    assert!(backlog.contains("<!-- softfig:queue -->"));
    assert!(backlog.contains("| 1 | m5b | milestone | Zero-knowledge backup | queued |"));

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "backlog_item_added");
    assert_eq!(payload["id"], "m5b");
}

#[test]
fn add_task_numbers_and_enqueues() {
    let fx = Fixture::start();
    let reply = fx.add_task("sigterm-unmount", "SIGTERM graceful unmount");
    assert_eq!(reply.id, "001");
    assert_eq!(reply.path, "growlight/backlog/tasks/001-sigterm-unmount.md");
    let doc = fx.read(&reply.path);
    assert!(doc.starts_with("# SIGTERM graceful unmount\n"));
    assert!(doc.contains("> Last reviewed:"));

    assert!(fx
        .backlog()
        .contains("| 1 | 001 | task | SIGTERM graceful unmount | queued |"));
}

#[test]
fn backlog_orders_items_by_insertion() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    fx.add_task("unmount", "Unmount");
    fx.add_milestone("m4b", "MiniJinja");
    let backlog = fx.backlog();
    let pos = |needle: &str| backlog.find(needle).unwrap();
    assert!(pos("| 1 | m5b ") < pos("| 2 | 001 ") && pos("| 2 | 001 ") < pos("| 3 | m4b "));
}

#[test]
fn add_backlog_item_rejects_duplicate_milestone() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    let resp = fx.call(
        op::ADD_BACKLOG_ITEM,
        serde_json::json!({
            "item_type": "milestone", "slug": "m5b", "title": "again",
            "mission": "m", "finish_criteria": "f",
        }),
    );
    assert_eq!(err_kind(resp), ErrorKind::PathAlreadyExists);
}

#[test]
fn add_backlog_item_rejects_bad_type_and_slug() {
    let fx = Fixture::start();
    assert_eq!(
        err_kind(fx.call(
            op::ADD_BACKLOG_ITEM,
            serde_json::json!({ "item_type": "epic", "slug": "x", "title": "t", "mission": "m", "finish_criteria": "f" }),
        )),
        ErrorKind::BadArgs
    );
    assert_eq!(
        err_kind(fx.call(
            op::ADD_BACKLOG_ITEM,
            serde_json::json!({ "item_type": "milestone", "slug": "M5b", "title": "t", "mission": "m", "finish_criteria": "f" }),
        )),
        ErrorKind::InvalidSlug
    );
}

// ---- add_slice --------------------------------------------------------

#[test]
fn add_slice_numbers_and_indexes_under_milestone() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    let resp = fx.call(
        op::ADD_SLICE,
        serde_json::json!({
            "milestone": "m5b", "slug": "secure-pipe",
            "title": "Secure pipe", "body": "Build the Noise channel.",
        }),
    );
    let reply: AddSliceReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(
        reply.path,
        "growlight/backlog/milestones/m5b/slices/001-secure-pipe.md"
    );
    let slice = fx.read(&reply.path);
    assert!(slice.starts_with("# Secure pipe\n"));

    // The milestone's CLAUDE.md grows a derived slices index.
    let milestone = fx.read("growlight/backlog/milestones/m5b/CLAUDE.md");
    assert!(milestone.contains("<!-- softfig:index slices -->"));
    assert!(milestone.contains("[Secure pipe](slices/001-secure-pipe.md)"));

    let (intent, _) = fx.tip_intent();
    assert_eq!(intent, "slice_added");
}

#[test]
fn add_slice_rejects_unknown_milestone() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::ADD_SLICE,
        serde_json::json!({ "milestone": "nope", "slug": "x", "body": "b" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::NotFound);
}

// ---- set_item_status --------------------------------------------------

#[test]
fn set_item_status_flips_one_cell() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    let resp = fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "active" }));
    let reply: SetItemStatusReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.status, "active");
    assert_eq!(reply.path, "growlight/backlog/CLAUDE.md");
    assert!(fx
        .backlog()
        .contains("| 1 | m5b | milestone | Backup | active |"));

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "item_status_set");
    assert_eq!(payload["status"], "active");
}

#[test]
fn set_item_status_enforces_single_active() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    fx.add_task("unmount", "Unmount");
    assert!(matches!(
        fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "active" })),
        Response::Ok { .. }
    ));
    // A second `active` is refused while m5b is active.
    assert_eq!(
        err_kind(fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "001", "status": "active" }))),
        ErrorKind::BadArgs
    );
    // After m5b is done, the task may go active.
    assert!(matches!(
        fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "done" })),
        Response::Ok { .. }
    ));
    assert!(matches!(
        fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "001", "status": "active" })),
        Response::Ok { .. }
    ));
    let backlog = fx.backlog();
    assert!(backlog.contains("| 1 | m5b | milestone | Backup | done |"));
    assert!(backlog.contains("| 2 | 001 | task | Unmount | active |"));
}

#[test]
fn set_item_status_is_idempotent_without_empty_commit() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "active" }));
    let tip_before = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    // Re-setting the same status is a no-op: returns the current tip, no commit.
    let resp = fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "active" }));
    let reply: SetItemStatusReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.hash, tip_before);
    let tip_after = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    assert_eq!(tip_after, tip_before, "no new commit for a no-op status set");
}

#[test]
fn set_item_status_rejects_unknown_id_and_bad_status() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    assert_eq!(
        err_kind(fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "ghost", "status": "done" }))),
        ErrorKind::NotFound
    );
    assert_eq!(
        err_kind(fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "paused" }))),
        ErrorKind::BadArgs
    );
}

#[test]
fn set_item_status_without_backlog_is_not_found() {
    let fx = Fixture::start();
    assert_eq!(
        err_kind(fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "active" }))),
        ErrorKind::NotFound
    );
}

#[test]
fn baton_log_is_excluded_from_backlinks() {
    // A milestone with a `[[…]]` ref to a doc, then a baton entry that also
    // references it: only the milestone forges a backlink; the audit entry
    // must not. (Uses the milestone doc itself as the referenced target.)
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    // Reference the milestone from a slice (a real source) and from a baton.
    fx.call(
        op::ADD_SLICE,
        serde_json::json!({
            "milestone": "m5b", "slug": "ref",
            "body": "see [[growlight/backlog/milestones/m5b/CLAUDE]]",
        }),
    );
    fx.call(
        op::LOG_BATON,
        serde_json::json!({
            "item": "m5b", "iteration": 1,
            "summary": "see [[growlight/backlog/milestones/m5b/CLAUDE]]",
        }),
    );
    let milestone = fx.read("growlight/backlog/milestones/m5b/CLAUDE.md");
    // The slice's edge shows up; the baton entry's does not.
    assert!(milestone.contains("<!-- softfig:backlinks -->"));
    assert!(milestone.contains("slices/001-ref.md"));
    assert!(
        !milestone.contains("baton-log"),
        "baton-log must not appear as a backlink source"
    );
}
