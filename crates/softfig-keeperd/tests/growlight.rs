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
    op, AddBacklogItemReply, AddQueueReply, AddSliceReply, GrowlightInitReply,
    GrowlightSetResourcesReply, LogBatonReply, PostMessageReply, ReadInboxReply,
    ReorderBacklogItemReply, SetItemStatusReply, TailBusReply,
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

    /// Cycle the daemon on the SAME garden + socket: shut the current one down
    /// and start a fresh `Daemon` over the persisted garden, then re-unlock. The
    /// committed queue table survives (on-disk), but every in-memory `DaemonInner`
    /// field — including the holder-identity store — is reconstructed empty, so
    /// this exercises the cross-`daemon cycle` first-claim-wins path.
    fn restart(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
            let _ = handle.join();
        }
        let config = KeeperConfig::new(&self.garden)
            .without_watcher()
            .with_socket(&self.socket);
        let handle = Daemon::new(config).start().unwrap();
        wait_for_socket(&self.socket);
        let resp = send(
            &self.socket,
            &Request::new(op::UNLOCK, serde_json::json!({ "passphrase": PASS_STR })),
        );
        assert!(matches!(resp, Response::Ok { .. }), "re-unlock: {resp:?}");
        self.handle = Some(handle);
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

    fn add_queue(&self, name: &str, repo: &str) -> AddQueueReply {
        let resp = self.call(op::ADD_QUEUE, serde_json::json!({ "name": name, "repo": repo }));
        serde_json::from_value(ok_data(resp)).unwrap()
    }

    fn add_milestone_in(&self, slug: &str, title: &str, queue: &str) -> AddBacklogItemReply {
        let resp = self.call(
            op::ADD_BACKLOG_ITEM,
            serde_json::json!({
                "item_type": "milestone", "slug": slug, "title": title,
                "mission": "why", "finish_criteria": "done", "queue": queue,
            }),
        );
        serde_json::from_value(ok_data(resp)).unwrap()
    }

    /// The text inside one managed item/registry region of the backlog doc.
    /// `queue`/`queue:<name>`/`queues` don't collide as substrings (the markers
    /// differ after the tag), so a plain split is precise.
    fn region(&self, tag: &str) -> String {
        let backlog = self.backlog();
        let open = format!("<!-- softfig:{tag} -->");
        let close = format!("<!-- /softfig:{tag} -->");
        let after = backlog.split_once(&open).expect("open marker present").1;
        after.split_once(&close).expect("close marker present").0.to_string()
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

// ---- set_item_status: holder-identity CAS (milestone #40) -------------

/// (a) A claim of a part already `active` under a DIFFERENT holder is refused
/// (fail-closed `BadArgs`); (b) the SAME holder re-claiming stays an idempotent
/// `Ok` with no new commit (the load-bearing SpawnFailed-retry / resume path).
#[test]
fn active_claim_refuses_a_different_holder_but_not_the_same_one() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    // agent-a claims the part (queued → active), recording the holder.
    assert!(matches!(
        fx.call(
            op::SET_ITEM_STATUS,
            serde_json::json!({ "id": "m5b", "status": "active", "holder": "agent-a" })
        ),
        Response::Ok { .. }
    ));
    // (a) A DIFFERENT holder claiming the already-active part is refused.
    let denied = fx.call(
        op::SET_ITEM_STATUS,
        serde_json::json!({ "id": "m5b", "status": "active", "holder": "agent-b" }),
    );
    assert_eq!(err_kind(denied), ErrorKind::BadArgs);
    // (b) agent-a re-claiming its own part is an idempotent Ok — no new commit.
    let tip_before = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    let resp = fx.call(
        op::SET_ITEM_STATUS,
        serde_json::json!({ "id": "m5b", "status": "active", "holder": "agent-a" }),
    );
    let reply: SetItemStatusReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.hash, tip_before, "same-holder re-claim mints no commit");
    assert_eq!(
        Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string(),
        tip_before
    );
}

/// (c) An unknown/unrecorded holder claiming an already-`active` part wins
/// (first-claim-wins) — the post-`daemon cycle` resume case. Activating WITHOUT
/// a holder leaves the holder map empty (exactly the state a cycled daemon
/// starts in); the first holdered claim then records the holder.
#[test]
fn an_unknown_holder_claim_of_an_active_part_wins_first() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    // Active, no holder → CAS untracked, holder map stays empty.
    assert!(matches!(
        fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "active" })),
        Response::Ok { .. }
    ));
    // The first holdered claim of the already-active part is granted + recorded.
    assert!(matches!(
        fx.call(
            op::SET_ITEM_STATUS,
            serde_json::json!({ "id": "m5b", "status": "active", "holder": "resumer" })
        ),
        Response::Ok { .. }
    ));
    // ...so a different agent is now refused (the resumer owns it).
    assert_eq!(
        err_kind(fx.call(
            op::SET_ITEM_STATUS,
            serde_json::json!({ "id": "m5b", "status": "active", "holder": "intruder" })
        )),
        ErrorKind::BadArgs
    );
}

/// The in-memory holder store is reset on every daemon start, so a part left
/// `active` across a real `daemon cycle` records no holder — a different agent
/// re-claims it (first-claim-wins), never a permanent refusal.
#[test]
fn the_holder_map_is_reset_across_a_daemon_cycle() {
    let mut fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    assert!(matches!(
        fx.call(
            op::SET_ITEM_STATUS,
            serde_json::json!({ "id": "m5b", "status": "active", "holder": "agent-a" })
        ),
        Response::Ok { .. }
    ));
    // Before the cycle, a different agent is refused.
    assert_eq!(
        err_kind(fx.call(
            op::SET_ITEM_STATUS,
            serde_json::json!({ "id": "m5b", "status": "active", "holder": "agent-b" })
        )),
        ErrorKind::BadArgs
    );
    // Cycle the daemon on the same garden: the row stays `active` (persisted),
    // but the holder map starts empty.
    fx.restart();
    assert!(
        fx.backlog().contains("| 1 | m5b | milestone | Backup | active |"),
        "the active row survives the cycle"
    );
    // agent-b now wins — unknown holder after the reset → first claim.
    assert!(matches!(
        fx.call(
            op::SET_ITEM_STATUS,
            serde_json::json!({ "id": "m5b", "status": "active", "holder": "agent-b" })
        ),
        Response::Ok { .. }
    ));
}

/// When a part leaves `active` (blocked → queued), its holder is dropped, so a
/// re-activation by a *different* agent is a fresh first-claim — the holder gate
/// only applies for the lifetime of the active claim.
#[test]
fn leaving_active_drops_the_holder() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    fx.call(
        op::SET_ITEM_STATUS,
        serde_json::json!({ "id": "m5b", "status": "active", "holder": "agent-a" }),
    );
    // Park then resume (active → blocked → queued), each dropping the holder.
    fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "blocked" }));
    fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "queued" }));
    // A different agent now claims it active — granted (the part was freed).
    assert!(matches!(
        fx.call(
            op::SET_ITEM_STATUS,
            serde_json::json!({ "id": "m5b", "status": "active", "holder": "agent-b" })
        ),
        Response::Ok { .. }
    ));
}

// ---- reorder_backlog_item ---------------------------------------------

#[test]
fn reorder_moves_a_row_without_touching_status() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup"); // 1
    fx.add_task("a", "A"); // 001 -> 2
    fx.add_task("b", "B"); // 002 -> 3
    fx.add_task("c", "C"); // 003 -> 4
    // Statuses we expect reorder to leave untouched.
    fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "active" }));
    fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "001", "status": "done" }));

    // Float the newest task (003) to the top of the queue.
    let resp = fx.call(op::REORDER_BACKLOG_ITEM, serde_json::json!({ "id": "003", "position": "top" }));
    let reply: ReorderBacklogItemReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.id, "003");
    assert_eq!(reply.index, 1);
    assert_eq!(reply.path, "growlight/backlog/CLAUDE.md");

    // New order 003, m5b, 001, 002 — every status cell preserved.
    let backlog = fx.backlog();
    assert!(backlog.contains("| 1 | 003 | task | C | queued |"));
    assert!(backlog.contains("| 2 | m5b | milestone | Backup | active |"));
    assert!(backlog.contains("| 3 | 001 | task | A | done |"));
    assert!(backlog.contains("| 4 | 002 | task | B | queued |"));

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "backlog_item_reordered");
    assert_eq!(payload["id"], "003");
    assert_eq!(payload["index"], 1);
}

#[test]
fn reorder_before_after_and_past_done_and_deferred_rows() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup"); // 1
    fx.add_task("a", "A"); // 001 -> 2
    fx.add_task("b", "B"); // 002 -> 3
    fx.add_task("c", "C"); // 003 -> 4
    fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m5b", "status": "done" }));
    fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "001", "status": "deferred" }));

    // Move 003 before 001 — jumps past the done milestone, lands ahead of the
    // deferred task. Order becomes m5b, 003, 001, 002.
    fx.call(
        op::REORDER_BACKLOG_ITEM,
        serde_json::json!({ "id": "003", "position": "before", "ref_id": "001" }),
    );
    // Sink the done milestone to the bottom via `after` the last row.
    let resp = fx.call(
        op::REORDER_BACKLOG_ITEM,
        serde_json::json!({ "id": "m5b", "position": "after", "ref_id": "002" }),
    );
    let reply: ReorderBacklogItemReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.index, 4);

    // Final order 003, 001, 002, m5b with statuses intact.
    let backlog = fx.backlog();
    assert!(backlog.contains("| 1 | 003 | task | C | queued |"));
    assert!(backlog.contains("| 2 | 001 | task | A | deferred |"));
    assert!(backlog.contains("| 3 | 002 | task | B | queued |"));
    assert!(backlog.contains("| 4 | m5b | milestone | Backup | done |"));
}

#[test]
fn reorder_is_idempotent_without_empty_commit() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    fx.add_task("a", "A");
    let tip_before = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    // m5b is already first; moving it to top changes nothing.
    let resp = fx.call(op::REORDER_BACKLOG_ITEM, serde_json::json!({ "id": "m5b", "position": "top" }));
    let reply: ReorderBacklogItemReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert_eq!(reply.hash, tip_before);
    assert_eq!(reply.index, 1);
    let tip_after = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    assert_eq!(tip_after, tip_before, "no new commit for a no-op reorder");
}

#[test]
fn reorder_rejects_unknown_ids_and_bad_position() {
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    fx.add_task("a", "A"); // 001
    // The item to move doesn't exist.
    assert_eq!(
        err_kind(fx.call(op::REORDER_BACKLOG_ITEM, serde_json::json!({ "id": "ghost", "position": "top" }))),
        ErrorKind::NotFound
    );
    // The before/after reference doesn't exist.
    assert_eq!(
        err_kind(fx.call(
            op::REORDER_BACKLOG_ITEM,
            serde_json::json!({ "id": "001", "position": "before", "ref_id": "ghost" })
        )),
        ErrorKind::NotFound
    );
    // Positioning an item relative to itself is rejected.
    assert_eq!(
        err_kind(fx.call(
            op::REORDER_BACKLOG_ITEM,
            serde_json::json!({ "id": "001", "position": "after", "ref_id": "001" })
        )),
        ErrorKind::BadArgs
    );
    // Bad position keyword, and before/after without a ref_id.
    assert_eq!(
        err_kind(fx.call(op::REORDER_BACKLOG_ITEM, serde_json::json!({ "id": "001", "position": "sideways" }))),
        ErrorKind::BadArgs
    );
    assert_eq!(
        err_kind(fx.call(op::REORDER_BACKLOG_ITEM, serde_json::json!({ "id": "001", "position": "before" }))),
        ErrorKind::BadArgs
    );
}

// ---- growlight init (Phase 2a scaffolder) -----------------------------

/// A default-garden-shaped root `CLAUDE.md`: the two nav headings the
/// scaffolder edits, each with a trailing trap (`---` after the map, prose
/// after the boundary table) that a naive section-append would land in.
const SEED_CLAUDE: &str = "# test garden\n\n\
    ## Where does X belong? (boundary decision table)\n\n\
    | If about... | Read first | Then |\n\
    |---|---|---|\n\
    | packages | `packages/` | snapshots |\n\n\
    Boundary rule: own each concept once.\n\n\
    ---\n\n\
    ## Top-level map\n\n\
    - `meta/` — docs about the garden.\n\
    - `journal/` — dated decisions.\n\n\
    ---\n\n\
    ## How to behave\n\n\
    route via the table.\n";

const SEED_RESERVED: &str = "# Reserved filenames\n\n## v1 reserved set\n\n\
    | Name | Purpose |\n|---|---|\n| `CLAUDE.md` | navigator |\n";

const SEED_CONVENTIONS: &str =
    "# Conventions\n\n## Concept folders vs snapshots folders\n\nstable vs mutating.\n";

#[test]
fn growlight_init_scaffolds_the_pillar_and_commits() {
    let fx = Fixture::start();
    let resp = fx.call(op::GROWLIGHT_INIT, serde_json::json!({}));
    let reply: GrowlightInitReply = serde_json::from_value(ok_data(resp)).unwrap();

    assert!(reply.committed);
    // All eight pillar files + the in-garden fleet config are created on a fresh
    // garden.
    for rel in [
        "growlight/CLAUDE.md",
        "growlight/protocol.md",
        "growlight/protocol-fleet.md",
        "growlight/session-policy.md",
        "growlight/backlog/CLAUDE.md",
        "growlight/backlog/tasks/.seq",
        "growlight/baton-log/CLAUDE.md",
        "growlight/baton-log/.seq",
        "config/growlight.toml",
    ] {
        assert!(reply.created.contains(&rel.to_string()), "missing {rel}");
    }
    // config-in-garden: the fleet config is seeded gate-off.
    assert!(fx.read("config/growlight.toml").contains("fleet_enabled = false"));

    // Routing doc maps its children; protocol + policy come from the templates.
    assert!(fx.read("growlight/CLAUDE.md").contains("## Children"));
    assert!(fx
        .read("growlight/protocol.md")
        .contains("SOFT-FIG GROWLIGHT — operating protocol"));
    // The fleet variant ships too, with the no-self-pull step 7 (slice 002).
    let fleet = fx.read("growlight/protocol-fleet.md");
    assert!(fleet.contains("SOFT-FIG GROWLIGHT — operating protocol"));
    assert!(!fleet.contains("pull the next"), "fleet protocol must not self-pull");
    assert!(fx
        .read("growlight/session-policy.md")
        .contains("## The two budgets"));
    // The backlog routing doc is the same stub the MCP verbs seed (empty queue).
    assert!(fx.backlog().contains("<!-- softfig:queue -->"));
    // Numbered folders start clean so their first entry is 001.
    assert_eq!(fx.read("growlight/backlog/tasks/.seq"), "0\n");
    assert_eq!(fx.read("growlight/baton-log/.seq"), "0\n");

    let (intent, _) = fx.tip_intent();
    assert_eq!(intent, "growlight_initialized");
}

#[test]
fn growlight_init_is_idempotent_without_an_empty_commit() {
    let fx = Fixture::start();
    fx.call(op::GROWLIGHT_INIT, serde_json::json!({}));
    let tip_before = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();

    let resp = fx.call(op::GROWLIGHT_INIT, serde_json::json!({}));
    let reply: GrowlightInitReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(!reply.committed, "re-run must not commit");
    assert!(reply.created.is_empty());
    assert_eq!(reply.hash, tip_before, "re-run returns the current tip");
    // The eight pillar files + config/growlight.toml are reported kept, not recreated.
    assert_eq!(reply.skipped.len(), 9);

    let tip_after = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    assert_eq!(tip_after, tip_before, "no new commit on a no-op init");
}

#[test]
fn growlight_init_wires_nav_when_docs_are_present() {
    let fx = Fixture::start();
    std::fs::write(fx.garden.join("CLAUDE.md"), SEED_CLAUDE).unwrap();
    std::fs::create_dir_all(fx.garden.join("meta")).unwrap();
    std::fs::write(fx.garden.join("meta/reserved-filenames.md"), SEED_RESERVED).unwrap();
    std::fs::write(fx.garden.join("meta/conventions.md"), SEED_CONVENTIONS).unwrap();

    let resp = fx.call(op::GROWLIGHT_INIT, serde_json::json!({}));
    let reply: GrowlightInitReply = serde_json::from_value(ok_data(resp)).unwrap();
    for rel in ["CLAUDE.md", "meta/reserved-filenames.md", "meta/conventions.md"] {
        assert!(reply.nav_wired.contains(&rel.to_string()), "nav missed {rel}");
    }

    let root = fx.read("CLAUDE.md");
    // Map bullet lands after the last bullet, before the trailing `---`.
    assert!(root.contains("- `journal/` — dated decisions.\n- `growlight/` — the autonomous"));
    // Boundary row lands after the last table row, before the prose.
    assert!(root.contains("| packages | `packages/` | snapshots |\n| the autonomous work loop"));
    assert!(fx
        .read("meta/reserved-filenames.md")
        .contains("## growlight pillar reserved names"));
    assert!(fx
        .read("meta/conventions.md")
        .contains("## Agent runtime state lives outside the garden"));

    // Re-running does not duplicate the wiring.
    let before = fx.read("CLAUDE.md");
    let resp2 = fx.call(op::GROWLIGHT_INIT, serde_json::json!({}));
    let reply2: GrowlightInitReply = serde_json::from_value(ok_data(resp2)).unwrap();
    assert!(reply2.nav_wired.is_empty());
    assert_eq!(fx.read("CLAUDE.md"), before, "nav wiring is idempotent");
}

#[test]
fn growlight_init_coexists_with_phase1_verbs() {
    // The MCP verbs self-materialize backlog/CLAUDE.md; init must keep it.
    let fx = Fixture::start();
    fx.add_milestone("m5b", "Backup");
    let resp = fx.call(op::GROWLIGHT_INIT, serde_json::json!({}));
    let reply: GrowlightInitReply = serde_json::from_value(ok_data(resp)).unwrap();

    assert!(
        reply.skipped.contains(&"growlight/backlog/CLAUDE.md".to_string()),
        "must not clobber an existing backlog"
    );
    assert!(reply.created.contains(&"growlight/protocol.md".to_string()));
    // The queued item survived the scaffold.
    assert!(fx
        .backlog()
        .contains("| 1 | m5b | milestone | Backup | queued |"));
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

// ---- coordination bus: post_message / read_inbox ----------------------

fn post(fx: &Fixture, from: &str, to: &str, kind: &str, body: &str) -> PostMessageReply {
    let resp = fx.call(
        op::POST_MESSAGE,
        serde_json::json!({ "from": from, "to": to, "kind": kind, "body": body }),
    );
    serde_json::from_value(ok_data(resp)).unwrap()
}

fn inbox(fx: &Fixture, agent: &str) -> ReadInboxReply {
    let resp = fx.call(op::READ_INBOX, serde_json::json!({ "agent": agent }));
    serde_json::from_value(ok_data(resp)).unwrap()
}

#[test]
fn post_message_writes_numbered_doc_and_commits() {
    let fx = Fixture::start();
    let reply = post(&fx, "agent-a", "agent-b", "coord-request", "please rebase");
    assert_eq!(reply.number, 1);
    assert_eq!(reply.path, "growlight/chat/messages/001-agent-a-to-agent-b.md");

    let doc = fx.read(&reply.path);
    assert!(doc.contains("- from: `agent-a`"));
    assert!(doc.contains("- to: `agent-b`"));
    assert!(doc.contains("- kind: `coord-request`"));
    assert!(doc.contains("please rebase"));
    assert_eq!(fx.read("growlight/chat/messages/.seq"), "1\n");

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "chat_message_posted");
    assert_eq!(payload["number"], 1);
    assert_eq!(payload["to"], "agent-b");
}

#[test]
fn two_agents_exchange_and_read_inbox_is_since_cursor() {
    let fx = Fixture::start();
    // A posts a direct message to B: B's inbox sees it, A's (the author) does not.
    post(&fx, "agent-a", "agent-b", "info", "hi b");
    let b = inbox(&fx, "agent-b");
    assert_eq!(b.messages.len(), 1);
    assert_eq!(b.messages[0].number, 1);
    assert_eq!(b.messages[0].from, "agent-a");
    assert_eq!(b.messages[0].to, "agent-b");
    assert_eq!(b.messages[0].kind, "info");
    assert_eq!(b.messages[0].body, "hi b");
    assert!(!b.messages[0].ts.is_empty());
    assert!(inbox(&fx, "agent-a").messages.is_empty());

    // Reading advanced B's cursor: a re-read is empty until a new message lands.
    assert!(inbox(&fx, "agent-b").messages.is_empty());
    post(&fx, "agent-a", "agent-b", "info", "and again");
    let b2 = inbox(&fx, "agent-b");
    assert_eq!(b2.messages.len(), 1);
    assert_eq!(b2.messages[0].number, 2);
    assert_eq!(b2.messages[0].body, "and again");
}

#[test]
fn at_all_reaches_every_agent_and_human_posts_are_readable() {
    let fx = Fixture::start();
    // An @all message fans into every other agent's lane.
    post(&fx, "agent-a", "@all", "info", "standup in 5");
    assert_eq!(inbox(&fx, "agent-b").messages.len(), 1);
    assert_eq!(inbox(&fx, "agent-c").messages.len(), 1);
    assert!(inbox(&fx, "agent-a").messages.is_empty()); // not the author's own post

    // The human is a first-class member: a message FROM @human is readable.
    post(&fx, "@human", "agent-b", "question", "what's the status?");
    let b = inbox(&fx, "agent-b");
    assert_eq!(b.messages.len(), 1);
    assert_eq!(b.messages[0].from, "@human");
    assert_eq!(b.messages[0].kind, "question");
    assert_eq!(b.messages[0].body, "what's the status?");
}

#[test]
fn empty_read_inbox_makes_no_commit() {
    let fx = Fixture::start();
    post(&fx, "agent-a", "@all", "info", "x");
    let tip_before = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    // agent-a is the author, so its inbox is empty → no cursor write, no commit.
    assert!(inbox(&fx, "agent-a").messages.is_empty());
    let tip_after = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    assert_eq!(tip_after, tip_before, "an empty read must not mint a commit");
}

#[test]
fn post_message_rejects_unknown_kind_and_bad_sender() {
    let fx = Fixture::start();
    // An unknown kind token is rejected by the verb.
    assert_eq!(
        err_kind(fx.call(
            op::POST_MESSAGE,
            serde_json::json!({ "from": "agent-a", "to": "@all", "kind": "shout", "body": "x" }),
        )),
        ErrorKind::BadArgs
    );
    // A non-slug sender is rejected by the store's validation.
    assert_eq!(
        err_kind(fx.call(
            op::POST_MESSAGE,
            serde_json::json!({ "from": "Bad Sender", "to": "@all", "kind": "info", "body": "x" }),
        )),
        ErrorKind::InvalidSlug
    );
    // An empty body is rejected.
    assert_eq!(
        err_kind(fx.call(
            op::POST_MESSAGE,
            serde_json::json!({ "from": "agent-a", "to": "@all", "kind": "info", "body": "  " }),
        )),
        ErrorKind::BadArgs
    );
}

// ---- coordination bus: tail_bus (the growlightd subscribe fan-out source) ----

fn tail(fx: &Fixture, since: u32) -> TailBusReply {
    let resp = fx.call(op::TAIL_BUS, serde_json::json!({ "since": since }));
    serde_json::from_value(ok_data(resp)).unwrap()
}

#[test]
fn tail_bus_returns_the_whole_channel_since_a_watermark() {
    let fx = Fixture::start();
    post(&fx, "agent-a", "@all", "info", "one");
    post(&fx, "agent-a", "agent-b", "coord-request", "two");
    post(&fx, "@human", "agent-b", "question", "three");

    // since=0 → the whole channel in total order, INCLUDING the @human-addressed
    // message (tail_bus is the bus observer, not a per-agent lane like read_inbox).
    let all = tail(&fx, 0);
    let nums: Vec<u32> = all.messages.iter().map(|m| m.number).collect();
    assert_eq!(nums, vec![1, 2, 3]);
    assert_eq!(all.messages[2].from, "@human");
    assert_eq!(all.messages[2].to, "agent-b");
    assert_eq!(all.messages[1].kind, "coord-request");

    // The watermark is exclusive: since=2 skips #1 and #2.
    let tailed = tail(&fx, 2);
    assert_eq!(tailed.messages.iter().map(|m| m.number).collect::<Vec<_>>(), vec![3]);

    // Past the tip → empty.
    assert!(tail(&fx, 3).messages.is_empty());
}

#[test]
fn tail_bus_is_a_pure_read_and_mints_no_commit() {
    let fx = Fixture::start();
    post(&fx, "agent-a", "@all", "info", "x");
    let tip_before = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    // Tailing reads the channel without advancing any cursor or committing —
    // unlike read_inbox, which advances the reader's cursor.
    assert_eq!(tail(&fx, 0).messages.len(), 1);
    assert_eq!(tail(&fx, 0).messages.len(), 1, "still there — no cursor consumed it");
    let tip_after = Repo::open(&fx.garden).unwrap().tip().unwrap().unwrap().to_string();
    assert_eq!(tip_after, tip_before, "tail_bus must never mint a commit");
}

#[test]
fn a_human_posted_message_is_in_an_agents_inbox_at_next_boot() {
    // The human-post seam (the `say` CLI / GUI input box): a `from: @human`
    // message lands in the addressed agent's inbox at its next boot (the agents
    // read at boot, post at handoff — async turn-boundary, spec §4a). Reuses the
    // slice-002 read_inbox harness.
    let fx = Fixture::start();
    post(&fx, "@human", "agent-b", "question", "what's blocking 003?");
    let b = inbox(&fx, "agent-b");
    assert_eq!(b.messages.len(), 1);
    assert_eq!(b.messages[0].from, "@human");
    assert_eq!(b.messages[0].body, "what's blocking 003?");
    // And it surfaces on the bus observer too (what growlightd fans to subscribe).
    assert_eq!(tail(&fx, 0).messages[0].from, "@human");
}

// ---- phase 4 slice 001: multiple named queues + part-unit assignment ---

#[test]
fn add_queue_registers_and_seeds_its_own_region() {
    let fx = Fixture::start();
    let reply = fx.add_queue("softfig", "~/projects/software-config_garden");
    assert_eq!(reply.name, "softfig");
    assert_eq!(reply.path, "growlight/backlog/CLAUDE.md");

    let backlog = fx.backlog();
    // Registry row + a fresh, empty per-queue item table under its own heading.
    assert!(backlog.contains("## Queues"));
    assert!(fx
        .region("queues")
        .contains("| softfig | ~/projects/software-config_garden |"));
    assert!(backlog.contains("## Queue: softfig"));
    assert!(backlog.contains("<!-- softfig:queue:softfig -->"));
    assert!(fx.region("queue:softfig").contains("| # | id | type | title | status |"));
    // The default queue's region is still present and untouched.
    assert!(backlog.contains("<!-- softfig:queue -->"));

    let (intent, payload) = fx.tip_intent();
    assert_eq!(intent, "queue_added");
    assert_eq!(payload["name"], "softfig");
}

#[test]
fn add_queue_rejects_duplicate_and_the_reserved_default() {
    let fx = Fixture::start();
    fx.add_queue("softfig", "~/p");
    let dup = fx.call(op::ADD_QUEUE, serde_json::json!({ "name": "softfig", "repo": "~/p2" }));
    assert_eq!(err_kind(dup), ErrorKind::PathAlreadyExists);
    let reserved = fx.call(op::ADD_QUEUE, serde_json::json!({ "name": "default", "repo": "~/p" }));
    assert_eq!(err_kind(reserved), ErrorKind::BadArgs);
    let empty = fx.call(op::ADD_QUEUE, serde_json::json!({ "name": "phone", "repo": "" }));
    assert_eq!(err_kind(empty), ErrorKind::BadArgs);
}

#[test]
fn an_item_lands_in_its_queues_region_not_the_default() {
    let fx = Fixture::start();
    fx.add_queue("softfig", "~/p");
    fx.add_milestone_in("m-stream", "Stream work", "softfig");
    // Lands in the softfig region; the default region never sees it.
    assert!(fx.region("queue:softfig").contains("| 1 | m-stream | milestone | Stream work | queued |"));
    assert!(!fx.region("queue").contains("m-stream"));

    // A bare add still goes to the default queue (back-compat).
    fx.add_task("plain", "Plain task");
    assert!(fx.region("queue").contains("| 1 | 001 | task | Plain task | queued |"));
    assert!(!fx.region("queue:softfig").contains("Plain task"));
}

#[test]
fn add_item_into_an_unregistered_queue_is_not_found() {
    let fx = Fixture::start();
    let resp = fx.call(
        op::ADD_BACKLOG_ITEM,
        serde_json::json!({
            "item_type": "task", "slug": "x", "title": "t",
            "mission": "m", "finish_criteria": "f", "queue": "ghost",
        }),
    );
    assert_eq!(err_kind(resp), ErrorKind::NotFound);
}

#[test]
fn active_is_enforced_per_queue_not_globally() {
    // The fleet invariant: one active part *per queue*, so two queues can each
    // run an active item concurrently — but a second active in the SAME queue
    // is still refused (back-compat for the default queue).
    let fx = Fixture::start();
    fx.add_milestone("m-def", "Default work");
    let a = fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m-def", "status": "active" }));
    assert!(matches!(a, Response::Ok { .. }));

    fx.add_queue("softfig", "~/p");
    fx.add_milestone_in("m-sf", "Stream work", "softfig");
    // Activating in the OTHER queue succeeds despite m-def being active.
    let b = fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m-sf", "status": "active" }));
    assert!(matches!(b, Response::Ok { .. }), "per-queue active should allow it: {b:?}");
    let r: SetItemStatusReply = serde_json::from_value(ok_data(b)).unwrap();
    assert_eq!(r.status, "active");
    assert!(fx.region("queue:softfig").contains("| 1 | m-sf | milestone | Stream work | active |"));

    // A second active within softfig is rejected.
    fx.add_milestone_in("m-sf2", "More", "softfig");
    let c = fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m-sf2", "status": "active" }));
    assert_eq!(err_kind(c), ErrorKind::BadArgs);
}

#[test]
fn status_and_reorder_resolve_a_named_queue_by_bare_id() {
    // Bare-id addressing keeps working across queues while ids stay unique:
    // set_item_status / reorder with no `queue` locate the item in softfig.
    let fx = Fixture::start();
    fx.add_queue("softfig", "~/p");
    fx.add_milestone_in("m-a", "A", "softfig");
    fx.add_milestone_in("m-b", "B", "softfig");
    fx.add_milestone_in("m-c", "C", "softfig");

    // status by bare id flips the cell in the softfig region.
    let s = fx.call(op::SET_ITEM_STATUS, serde_json::json!({ "id": "m-b", "status": "done" }));
    assert!(matches!(s, Response::Ok { .. }));
    assert!(fx.region("queue:softfig").contains("| 2 | m-b | milestone | B | done |"));

    // reorder by bare id is scoped to softfig's order (m-c to top).
    let r = fx.call(
        op::REORDER_BACKLOG_ITEM,
        serde_json::json!({ "id": "m-c", "position": "top" }),
    );
    let rr: ReorderBacklogItemReply = serde_json::from_value(ok_data(r)).unwrap();
    assert_eq!(rr.index, 1);
    let region = fx.region("queue:softfig");
    assert!(region.contains("| 1 | m-c "));
    assert!(region.contains("| 2 | m-a "));
    // The default queue stayed empty throughout.
    assert!(!fx.region("queue").contains("milestone"));
}

#[test]
fn passing_a_queue_scopes_status_resolution() {
    let fx = Fixture::start();
    fx.add_queue("softfig", "~/p");
    fx.add_milestone_in("m-x", "X", "softfig");
    // Wrong queue → NotFound; right queue → ok.
    let wrong = fx.call(
        op::SET_ITEM_STATUS,
        serde_json::json!({ "id": "m-x", "status": "done", "queue": "default" }),
    );
    assert_eq!(err_kind(wrong), ErrorKind::NotFound);
    let right = fx.call(
        op::SET_ITEM_STATUS,
        serde_json::json!({ "id": "m-x", "status": "done", "queue": "softfig" }),
    );
    assert!(matches!(right, Response::Ok { .. }));
}

// ---- growlight_set_resources: the keeperd persist handler glue (slice 010) ----

/// End-to-end over a live unlocked daemon (slice 010 — the pure `apply_build_caps`
/// is unit-tested, but the handler glue — WorkTree read, the idempotent no-commit
/// guard, the `growlight_resources_set` commit — was not): a first persist writes
/// `[build_caps]` and commits; an identical re-persist mints no commit; a changed
/// value commits again; and the surrounding fleet config + comments survive.
#[test]
fn growlight_set_resources_writes_the_table_commits_and_is_idempotent() {
    let fx = Fixture::start();
    // `growlight init` seeds config/growlight.toml (no `[build_caps]` table yet).
    fx.call(op::GROWLIGHT_INIT, serde_json::json!({}));

    // (a) First persist → committed, with a fresh `[build_caps]` table.
    let resp = fx.call(
        op::GROWLIGHT_SET_RESOURCES,
        serde_json::json!({ "cargo_build_jobs": 4, "memory_high": "5G", "cpu_weight": 80 }),
    );
    let reply: GrowlightSetResourcesReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(reply.committed, "a first persist commits");
    assert_eq!(reply.path, "config/growlight.toml");
    let cfg = fx.read("config/growlight.toml");
    assert!(cfg.contains("[build_caps]"));
    assert!(cfg.contains("cargo_build_jobs = 4"));
    assert!(cfg.contains("memory_high = \"5G\""));
    assert!(cfg.contains("cpu_weight = 80"));
    // The surrounding fleet config + its heavy comments are byte-preserved.
    assert!(cfg.contains("fleet_enabled = false"), "fleet gate preserved");
    assert!(cfg.contains("# soft-fig growlight fleet config."), "header comment preserved");
    // The commit carries the `growlight_resources_set` intent (note the verb-last
    // spelling — slice 008).
    let (intent, _) = fx.tip_intent();
    assert_eq!(intent, "growlight_resources_set");

    // (b) Re-persist the SAME caps → idempotent no-commit: committed=false and the
    // tip is unchanged (the (a) commit hash).
    let resp = fx.call(
        op::GROWLIGHT_SET_RESOURCES,
        serde_json::json!({ "cargo_build_jobs": 4, "memory_high": "5G", "cpu_weight": 80 }),
    );
    let reply2: GrowlightSetResourcesReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(!reply2.committed, "an identical re-persist mints no commit");
    assert_eq!(reply2.hash, reply.hash, "the tip is unchanged on the idempotent no-op");

    // (c) A different value commits again, updating the key in place.
    let resp = fx.call(
        op::GROWLIGHT_SET_RESOURCES,
        serde_json::json!({ "cargo_build_jobs": 2, "memory_high": "5G", "cpu_weight": 80 }),
    );
    let reply3: GrowlightSetResourcesReply = serde_json::from_value(ok_data(resp)).unwrap();
    assert!(reply3.committed, "a changed value commits");
    assert_ne!(reply3.hash, reply.hash, "a new commit advances the tip");
    let cfg = fx.read("config/growlight.toml");
    assert!(cfg.contains("cargo_build_jobs = 2"));
    assert!(!cfg.contains("cargo_build_jobs = 4"), "the old value is gone");
}

/// The absent-config branch: `growlight_set_resources` on a garden that never ran
/// `growlight init` (no config/growlight.toml) is a clean `NotFound`, not a panic
/// or a stray commit (slice 010).
#[test]
fn growlight_set_resources_is_not_found_when_the_config_is_absent() {
    let fx = Fixture::start(); // no growlight init ⇒ config/growlight.toml absent
    let resp = fx.call(
        op::GROWLIGHT_SET_RESOURCES,
        serde_json::json!({ "cargo_build_jobs": 4 }),
    );
    assert_eq!(err_kind(resp), ErrorKind::NotFound);
}
