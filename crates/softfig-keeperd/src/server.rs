//! Accept loop. Binds the socket with restrictive perms, polls in a
//! short loop so the Stopping state takes effect promptly, and spawns
//! one thread per accepted connection.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

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

fn dispatch(daemon: &Daemon, req: Request) -> Response {
    use softfig_ipc::op;

    if req.v != softfig_ipc::PROTOCOL_VERSION {
        return Response::err(
            ErrorKind::BadArgs,
            format!("unsupported protocol version {} (want {})", req.v, softfig_ipc::PROTOCOL_VERSION),
        );
    }

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
        op::MIGRATE_CONFIG => crate::actions::migrate_config(daemon, req.args),
        op::VAULT_REVEAL => handlers::vault_reveal(daemon, req.args),
        op::VAULT_SEAL => handlers::vault_seal(daemon, req.args),
        op::VAULT_UNSEAL => handlers::vault_unseal(daemon, req.args),
        op::VAULT_LIST_SEALED => handlers::vault_list_sealed(daemon, req.args),
        op::LOG_DECISION => crate::actions::log_decision(daemon, req.args),
        op::LOG_INCIDENT => crate::actions::log_incident(daemon, req.args),
        op::ADD_NOTE => crate::actions::add_note(daemon, req.args),
        op::REVISE_NOTE => crate::actions::revise_note(daemon, req.args),
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
        op::GROWLIGHT_INIT => crate::actions::growlight_init(daemon, req.args),
        op::GROWLIGHT_SET_RESOURCES => crate::actions::growlight_set_resources(daemon, req.args),
        op::POST_MESSAGE => crate::actions::post_message(daemon, req.args),
        op::READ_INBOX => crate::actions::read_inbox(daemon, req.args),
        op::TAIL_BUS => crate::actions::tail_bus(daemon, req.args),
        op::REQUEST_LEASE => crate::actions::request_lease(daemon, req.args),
        op::RELEASE_LEASE => crate::actions::release_lease(daemon, req.args),
        op::RELOCK_MINT => handlers::relock_mint(daemon, req.args),
        op::RELOCK_REDEEM => handlers::relock_redeem(daemon, req.args),
        op::ARCHIVE => crate::actions::archive(daemon, req.args),
        op::ADD_PROJECT => crate::actions::add_project(daemon, req.args),
        op::REFRESH_SNAPSHOT => crate::actions::refresh_snapshot(daemon, req.args),
        op::LIST_TREE => crate::reads::list_tree(daemon, req.args),
        op::READ_FILE => crate::reads::read_file(daemon, req.args),
        op::FILE_PROVENANCE => crate::reads::file_provenance(daemon, req.args),
        op::PAIR_BEGIN => handlers::pair_begin(daemon, req.args),
        op::PAIR_CONFIRM => handlers::pair_confirm(daemon, req.args),
        op::PAIR_LIST => handlers::pair_list(daemon, req.args),
        op::PAIR_REMOVE => handlers::pair_remove(daemon, req.args),
        op::DISCOVER_LIST => handlers::discover_list(daemon, req.args),
        op::REPLICA_GRANT => handlers::replica_grant(daemon, req.args),
        op::REPLICA_REVOKE => handlers::replica_revoke(daemon, req.args),
        op::REPLICA_STATUS => handlers::replica_status(daemon, req.args),
        op::DEPLOY_PLAN => crate::deploy::deploy_plan(daemon, req.args),
        op::DEPLOY_APPLY => crate::deploy::deploy_apply(daemon, req.args),
        op::SHUTDOWN => handlers::shutdown(daemon, req.args),
        other => Err((
            ErrorKind::BadArgs,
            format!("unknown op {other:?}"),
        )),
    };

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
