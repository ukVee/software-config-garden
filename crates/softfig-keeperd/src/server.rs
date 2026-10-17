//! Accept loop. Binds the socket with restrictive perms, polls in a
//! short loop so the Stopping state takes effect promptly, and spawns
//! one thread per accepted connection.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use softfig_ipc::{ErrorKind, Request, Response};

use crate::daemon::{Daemon, DaemonHandle, KeeperError, Result};
use crate::handlers;
use crate::peer;
use crate::state::State;
use crate::watcher;

const ACCEPT_POLL_MS: u64 = 100;

/// Current unix time in seconds (for relock-blob expiry pruning).
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn start(daemon: Daemon) -> Result<DaemonHandle> {
    let socket_path = daemon
        .inner
        .lock()
        .unwrap()
        .config
        .socket_path
        .clone();

    // Stale socket from a previous unclean exit.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let listener = UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;
    let mut perms = std::fs::metadata(&socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&socket_path, perms)?;

    // Growlight: drop any *expired* relock blob from a previous run. A live one
    // (a `cycle`/`relock` minted just before this restart) is left in place to
    // be redeemed; tmpfs already wiped it on a reboot.
    {
        let inner = daemon.inner.lock().unwrap();
        crate::relock::prune_expired(inner.config.state_dir(), now_secs());
    }

    let daemon_for_thread = daemon.clone();
    let socket_for_thread = socket_path.clone();
    let thread = thread::Builder::new()
        .name("keeperd-accept".into())
        .spawn(move || accept_loop(listener, daemon_for_thread, socket_for_thread))?;

    let watcher_thread = {
        let inner = daemon.inner.lock().unwrap();
        if !inner.config.enable_watcher {
            None
        } else if let Some(state_root) = inner.config.state_root.clone() {
            // M2a: retarget the watcher at the relocated state root so
            // any tampering under `.softfig/` shows up; FUSE writes
            // feed the same shared accumulator via the sink adapter.
            drop(inner);
            Some(watcher::spawn_with_target(daemon.clone(), state_root))
        } else {
            // M1c-compat.
            drop(inner);
            Some(watcher::spawn(daemon.clone()))
        }
    };

    Ok(DaemonHandle {
        daemon,
        thread: Some(thread),
        watcher: watcher_thread,
        socket_path,
    })
}

fn accept_loop(
    listener: UnixListener,
    daemon: Daemon,
    socket_path: PathBuf,
) -> Result<()> {
    loop {
        if daemon.state() == State::Stopping {
            break;
        }

        match listener.accept() {
            Ok((stream, _addr)) => {
                if let Err(e) = peer::require_same_uid(&stream) {
                    eprintln!("keeperd: rejecting peer: {e}");
                    drop(stream);
                    continue;
                }
                let d = daemon.clone();
                thread::Builder::new()
                    .name("keeperd-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(d, stream) {
                            eprintln!("keeperd: connection error: {e}");
                        }
                    })
                    .ok();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
            Err(e) => {
                eprintln!("keeperd: accept error: {e}");
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

fn handle_connection(daemon: Daemon, mut stream: UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(());
    }

    // Parse first so a `shutdown` can be told apart: its teardown must run only
    // AFTER the ack is flushed, never before (see below).
    let parsed = serde_json::from_str::<Request>(line.trim_end_matches('\n'));
    let is_shutdown = matches!(&parsed, Ok(req) if req.op == softfig_ipc::op::SHUTDOWN);
    let resp = match parsed {
        Ok(req) => dispatch(&daemon, req),
        Err(e) => Response::err(ErrorKind::BadArgs, format!("decode: {e}")),
    };

    let mut bytes = serde_json::to_vec(&resp)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;

    // Ack-before-teardown. The `shutdown` handler deliberately does NOT tear
    // down; we do it here, only after the reply is on the wire. `write_all` has
    // already handed the ack to the kernel socket buffer (the peer can still
    // read it after we exit), so the client is guaranteed its ack before
    // `request_shutdown` flips the daemon to `Stopping` — which ends the accept
    // loop and lets `main` race to process exit. The old order (ack written
    // after teardown) lost that race and surfaced to the client as "daemon
    // closed connection without replying" (incident 20260622).
    if is_shutdown {
        daemon.request_shutdown();
    }
    Ok(())
}

/// Does this op represent a **local, user-initiated garden-content write**? Used
/// only to stamp [`DaemonInner::last_write_at`] for the M5e device-state
/// activity window (part 3a) — a local authoring commit lifts this device to
/// `OnlineActive` for its S-members. This is a coarse "is the user actively
/// editing" hint, so over/under-inclusion at the margins is benign; the safe
/// default is an allow-list (a new verb reads as *not* active until listed,
/// never wrongly active). Intentionally excluded: reads (`status`/`log`/
/// `read_file`/…), one-time/structural ops (`migrate_*`, `growlight_init`,
/// `vault_reveal` — a read-to-tmpfile), pairing/replica/relock/shared-subtree
/// control, lease bookkeeping, and `deploy_*` (writes the filesystem, not the
/// garden VCS).
fn op_is_local_write(op: &str) -> bool {
    use softfig_ipc::op;
    matches!(
        op,
        op::COMMIT
            | op::REPLACE_FILE
            | op::LOG_DECISION
            | op::LOG_INCIDENT
            | op::ADD_NOTE
            | op::REVISE_NOTE
            | op::ADD_CODE_REVIEW
            | op::ADD_SECTION
            | op::EDIT_SECTION
            | op::APPEND_TO_SECTION
            | op::SET_REVIEWED
            | op::LOG_BATON
            | op::ADD_BACKLOG_ITEM
            | op::ADD_QUEUE
            | op::ADD_SLICE
            | op::SET_ITEM_STATUS
            | op::REORDER_BACKLOG_ITEM
            | op::QUEUE_ADD_PROJECT
            | op::QUEUE_ADD_ENTRY
            | op::QUEUE_UPDATE_ENTRY
            | op::SLICE_INSERT
            | op::SLICE_UPDATE
            | op::QUEUE_DROP
            | op::GROWLIGHT_SET_RESOURCES
            | op::POST_MESSAGE
            | op::FILE_REPORT
            | op::UPDATE_REPORT
            | op::ARCHIVE
            | op::ADD_PROJECT
            | op::REFRESH_SNAPSHOT
            | op::VAULT_SEAL
            | op::VAULT_UNSEAL
            // mcp-surgical-writes: the surgical write verbs are local writes
            // like every other authoring op — they must stamp the activity
            // window too (slices 002–004 predate the batch slice, which closes
            // this gap for the whole family at once).
            | op::PATCH_FILE
            | op::REMOVE_SECTION
            | op::UNLINK
            | op::BATCH
    )
}

fn dispatch(daemon: &Daemon, req: Request) -> Response {
    use softfig_ipc::op;

    if req.v != softfig_ipc::PROTOCOL_VERSION {
        return Response::err(
            ErrorKind::BadArgs,
            format!("unsupported protocol version {} (want {})", req.v, softfig_ipc::PROTOCOL_VERSION),
        );
    }

    // §6.7: a member session's softfig-mcp stamps its identity on every
    // request; the write limits read it from this scope, for this request only.
    // A stamp that can't name a member is refused — a garbled member must not
    // be served as a human, the same fail-closed rule softfig-mcp applies.
    if let Some(member) = req.member.as_deref() {
        if !softfig_ipc::is_safe_member_id(member) {
            return Response::err(
                ErrorKind::BadArgs,
                format!("request member {member:?} is not a safe member id"),
            );
        }
    }
    let _caller = crate::caller::enter(req.member.clone());

    let result = match req.op.as_str() {
        op::STATUS => handlers::status(daemon, req.args),
        op::UNLOCK => handlers::unlock(daemon, req.args),
        op::COMMIT => handlers::commit(daemon, req.args),
        op::LOG => handlers::log(daemon, req.args),
        op::SHOW => handlers::show(daemon, req.args),
        op::FSCK => handlers::fsck(daemon, req.args),
        op::REPLACE_FILE => handlers::replace_file(daemon, req.args),
        op::MIGRATE_FINALIZE => handlers::migrate_finalize(daemon, req.args),
        op::MIGRATE_SPLIT => crate::actions::migrate_split(daemon, req.args),
        op::MIGRATE_REINDEX => crate::actions::migrate_reindex(daemon, req.args),
        op::MIGRATE_CONFIG => crate::actions::migrate_config(daemon, req.args),
        op::VAULT_REVEAL => handlers::vault_reveal(daemon, req.args),
        op::VAULT_SEAL => handlers::vault_seal(daemon, req.args),
        op::VAULT_UNSEAL => handlers::vault_unseal(daemon, req.args),
        op::VAULT_LIST_SEALED => handlers::vault_list_sealed(daemon, req.args),
        op::LOG_DECISION => crate::actions::log_decision(daemon, req.args),
        op::LOG_INCIDENT => crate::actions::log_incident(daemon, req.args),
        op::ADD_NOTE => crate::actions::add_note(daemon, req.args),
        op::REVISE_NOTE => crate::actions::revise_note(daemon, req.args),
        op::ADD_CODE_REVIEW => crate::actions::add_code_review(daemon, req.args),
        op::ADD_SECTION => crate::actions::add_section(daemon, req.args),
        op::EDIT_SECTION => crate::actions::edit_section(daemon, req.args),
        op::APPEND_TO_SECTION => crate::actions::append_to_section(daemon, req.args),
        op::SET_REVIEWED => crate::actions::set_reviewed(daemon, req.args),
        op::LOG_BATON => crate::actions::log_baton(daemon, req.args),
        op::ADD_BACKLOG_ITEM => crate::actions::add_backlog_item(daemon, req.args),
        op::ADD_QUEUE => crate::actions::add_queue(daemon, req.args),
        op::ADD_SLICE => crate::actions::add_slice(daemon, req.args),
        op::SET_ITEM_STATUS => crate::actions::set_item_status(daemon, req.args),
        op::REORDER_BACKLOG_ITEM => crate::actions::reorder_backlog_item(daemon, req.args),
        op::QUEUE_ADD_PROJECT => crate::actions::queue_add_project(daemon, req.args),
        op::QUEUE_ADD_ENTRY => crate::actions::queue_add_entry(daemon, req.args),
        op::QUEUE_UPDATE_ENTRY => crate::actions::queue_update_entry(daemon, req.args),
        // A member's slice verbs are held to its own current entry, which only
        // growlightd knows: relayed there, and growlightd issues the human verb
        // back to keeperd once it passes (§6.7).
        op::SLICE_INSERT => match req.member.as_deref() {
            Some(member) => crate::actions::member_slice_insert(daemon, member, req.args),
            None => crate::actions::slice_insert(daemon, req.args),
        },
        op::SLICE_UPDATE => match req.member.as_deref() {
            Some(member) => crate::actions::member_slice_update(daemon, member, req.args),
            None => crate::actions::slice_update(daemon, req.args),
        },
        op::QUEUE_DROP => crate::actions::queue_drop(daemon, req.args),
        op::QUEUE_V2_CLAIM => crate::actions::queue_v2_claim(daemon, req.args),
        op::QUEUE_V2_SET_STATUS => crate::actions::queue_v2_set_status(daemon, req.args),
        op::QUEUE_V2_FOLLOW_UPS => crate::actions::queue_v2_follow_ups(daemon, req.args),
        op::QUEUE_V2_SESSION_LOG => crate::actions::queue_v2_session_log(daemon, req.args),
        op::QUEUE_V2_DEFERRED => crate::actions::queue_v2_deferred(daemon, req.args),
        op::QUEUE_V2_ADD_SUB => crate::actions::queue_v2_add_sub(daemon, req.args),
        op::GROWLIGHT_INIT => crate::actions::growlight_init(daemon, req.args),
        op::GROWLIGHT_SET_RESOURCES => crate::actions::growlight_set_resources(daemon, req.args),
        op::POST_MESSAGE => crate::actions::post_message(daemon, req.args),
        op::READ_INBOX => crate::actions::read_inbox(daemon, req.args),
        op::TAIL_BUS => crate::actions::tail_bus(daemon, req.args),
        op::FILE_REPORT => crate::actions::file_report(daemon, req.args),
        op::UPDATE_REPORT => crate::actions::update_report(daemon, req.args),
        op::LIST_REPORTS => crate::actions::list_reports(daemon, req.args),
        op::REQUEST_LEASE => crate::actions::request_lease(daemon, req.args),
        op::RELEASE_LEASE => crate::actions::release_lease(daemon, req.args),
        op::GROWLIGHT_ADD_FOLLOW_UP_SESSION => {
            crate::actions::growlight_add_follow_up_session(daemon, req.args)
        }
        op::GROWLIGHT_COMPLETE_SLICE => crate::actions::growlight_complete_slice(daemon, req.args),
        op::GROWLIGHT_COMPLETE_ENTRY => crate::actions::growlight_complete_entry(daemon, req.args),
        op::GROWLIGHT_BLOCK => crate::actions::growlight_block(daemon, req.args),
        op::GROWLIGHT_ADD_SUB_MILESTONE => {
            crate::actions::growlight_add_sub_milestone(daemon, req.args)
        }
        op::RELOCK_MINT => handlers::relock_mint(daemon, req.args),
        op::RELOCK_REDEEM => handlers::relock_redeem(daemon, req.args),
        op::ARCHIVE => crate::actions::archive(daemon, req.args),
        op::ADD_PROJECT => crate::actions::add_project(daemon, req.args),
        op::REFRESH_SNAPSHOT => crate::actions::refresh_snapshot(daemon, req.args),
        op::LIST_TREE => crate::reads::list_tree(daemon, req.args),
        op::READ_FILE => crate::reads::read_file(daemon, req.args),
        op::READ_VERSIONS => crate::reads::read_versions(daemon, req.args),
        op::PATCH_FILE => crate::actions::patch_file(daemon, req.args),
        op::REMOVE_SECTION => crate::actions::sections::remove_section(daemon, req.args),
        op::UNLINK => crate::actions::unlink(daemon, req.args),
        op::BATCH => crate::actions::batch(daemon, req.args),
        op::FILE_PROVENANCE => crate::reads::file_provenance(daemon, req.args),
        op::GROWLIGHT_QUEUE => crate::reads::growlight_queue(daemon, req.args),
        op::PAIR_BEGIN => handlers::pair_begin(daemon, req.args),
        op::PAIR_CONFIRM => handlers::pair_confirm(daemon, req.args),
        op::PAIR_LIST => handlers::pair_list(daemon, req.args),
        op::PAIR_REMOVE => handlers::pair_remove(daemon, req.args),
        op::DISCOVER_LIST => handlers::discover_list(daemon, req.args),
        op::REPLICA_GRANT => handlers::replica_grant(daemon, req.args),
        op::REPLICA_REVOKE => handlers::replica_revoke(daemon, req.args),
        op::REPLICA_STATUS => handlers::replica_status(daemon, req.args),
        op::COORDINATION_STATUS => handlers::coordination_status(daemon, req.args),
        op::SHARED_SUBTREE_ADD => handlers::shared_subtree_add(daemon, req.args),
        op::SHARED_SUBTREE_REMOVE => handlers::shared_subtree_remove(daemon, req.args),
        op::SHARED_SUBTREE_ENABLE => handlers::shared_subtree_enable(daemon, req.args),
        op::SHARED_SUBTREE_DISABLE => handlers::shared_subtree_disable(daemon, req.args),
        op::SHARED_SUBTREE_LIST => handlers::shared_subtree_list(daemon, req.args),
        op::SHARED_SUBTREE_ACCEPT => handlers::shared_subtree_accept(daemon, req.args),
        op::MIGRATE_INTO_SHARE => handlers::migrate_into_share(daemon, req.args),
        op::DEPLOY_PLAN => crate::deploy::deploy_plan(daemon, req.args),
        op::DEPLOY_APPLY => crate::deploy::deploy_apply(daemon, req.args),
        op::SHUTDOWN => handlers::shutdown(daemon, req.args),
        other => Err((
            ErrorKind::BadArgs,
            format!("unknown op {other:?}"),
        )),
    };

    // M5e part 3a: a successful local authoring write stamps the activity window,
    // lifting this device to `OnlineActive` on the next reconcile tick. Only local
    // IPC writes reach `dispatch` — peer-applied and ceremony/replica-internal
    // commits go through the net path, not here — so this stamp never fires for a
    // write we didn't originate.
    if result.is_ok() && op_is_local_write(&req.op) {
        daemon.inner.lock().unwrap().last_write_at = Some(Instant::now());
    }

    match result {
        Ok(data) => Response::ok(data),
        Err((kind, message)) => Response::err(kind, message),
    }
}

/// Convert an opaque `KeeperError` into the wire kind+message pair.
pub fn err_to_response(e: KeeperError) -> (ErrorKind, String) {
    let msg = e.to_string();
    let kind = match e {
        KeeperError::Vault(_) => ErrorKind::AuthFailed,
        KeeperError::Store(softfig_store::StoreError::Sqlite(ref se))
            if format!("{se}").contains("database is locked") =>
        {
            ErrorKind::SqliteBusy
        }
        KeeperError::Io(_) => ErrorKind::Io,
        KeeperError::Json(_) => ErrorKind::BadArgs,
        KeeperError::Core(_) | KeeperError::Store(_) => ErrorKind::Internal,
        KeeperError::AlreadyStopping | KeeperError::Other(_) => ErrorKind::Internal,
    };
    (kind, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    use crate::actions::WorkTree;
    use softfig_ipc::growlightd::MemberCall;
    use softfig_ipc::verbs::SliceInsertArgs;

    fn unlocked() -> (tempfile::TempDir, Daemon) {
        let garden = tempfile::tempdir().unwrap();
        let daemon = crate::actions::growlight_test_daemon(garden.path());
        (garden, daemon)
    }

    fn err_of(resp: Response) -> (ErrorKind, String) {
        match resp {
            Response::Err { kind, error, .. } => (kind, error),
            Response::Ok { data, .. } => panic!("expected a refusal, got {data}"),
        }
    }

    /// A stamp that can't name a member is refused before any verb runs — a
    /// garbled member is never served as a human.
    #[test]
    fn a_garbled_member_stamp_is_refused() {
        let (_g, daemon) = unlocked();
        let req = Request::new(softfig_ipc::op::STATUS, serde_json::json!({})).with_member(Some("../x"));
        let (kind, msg) = err_of(dispatch(&daemon, req));
        assert_eq!(kind, ErrorKind::BadArgs);
        assert!(msg.contains("not a safe member id"), "{msg}");
    }

    /// The stamp reaches the write: a member's `replace_file` that adds a
    /// `> Model:` line under the backlog is refused `field_not_allowed`; the
    /// same request without the stamp lands. The scope ends with the request.
    #[test]
    fn the_member_stamp_holds_a_raw_write_to_the_model_guard() {
        let (_g, daemon) = unlocked();
        let args = serde_json::json!({
            "path": "growlight/backlog/milestones/m/slices/001-a.md",
            "content": "# a\n\n> Model: claude\n",
        });
        let member = Request::new(softfig_ipc::op::REPLACE_FILE, args.clone()).with_member(Some("c"));
        let (_, msg) = err_of(dispatch(&daemon, member));
        assert!(msg.starts_with("field_not_allowed:") && msg.contains("member c"), "{msg}");
        assert_eq!(crate::caller::member(), None, "the scope ended with the request");
        let human = dispatch(&daemon, Request::new(softfig_ipc::op::REPLACE_FILE, args));
        assert!(matches!(human, Response::Ok { .. }), "{human:?}");
    }

    /// A member's `slice_insert` is relayed to growlightd as a member call
    /// around the human verb's args (growlightd holds it to the member's own
    /// entry); a human's is served by keeperd as before, never relayed.
    #[test]
    fn a_members_slice_insert_is_relayed_to_growlightd() {
        let (_g, daemon) = unlocked();
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("growlightd.sock");
        daemon.inner.lock().unwrap().config.growlightd_socket = Some(socket.clone());
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap()).read_line(&mut line).unwrap();
            let reply = Response::ok(serde_json::json!({ "relayed": true }));
            let mut bytes = serde_json::to_vec(&reply).unwrap();
            bytes.push(b'\n');
            stream.write_all(&bytes).unwrap();
            serde_json::from_str::<Request>(line.trim_end()).unwrap()
        });
        let args = serde_json::json!({ "milestone": "m", "slug": "found", "body": "work" });
        let req = Request::new(softfig_ipc::op::SLICE_INSERT, args.clone()).with_member(Some("c"));
        let resp = dispatch(&daemon, req);
        assert!(matches!(&resp, Response::Ok { data, .. } if data["relayed"] == true), "{resp:?}");
        let relayed = server.join().unwrap();
        assert_eq!(relayed.op, softfig_ipc::growlightd::op::MEMBER_SLICE_INSERT);
        assert_eq!(relayed.member, None, "growlightd reads the identity from the envelope");
        let call: MemberCall<SliceInsertArgs> = serde_json::from_value(relayed.args).unwrap();
        assert_eq!(call.member.as_deref(), Some("c"));
        assert_eq!((call.args.milestone.as_str(), call.args.slug.as_str()), ("m", "found"));

        // The human path never dials growlightd: the listener is gone, and
        // keeperd answers from its own v2 state (here: no queue at all).
        let human = dispatch(&daemon, Request::new(softfig_ipc::op::SLICE_INSERT, args));
        let (_, msg) = err_of(human);
        assert!(!msg.contains("growlightd"), "{msg}");
        let inner = daemon.inner.lock().unwrap();
        assert!(!WorkTree::new(&daemon, &inner).exists("growlight/backlog/milestones/m/slices"));
    }
}
