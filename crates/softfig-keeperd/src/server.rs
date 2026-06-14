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

    let resp = match serde_json::from_str::<Request>(line.trim_end_matches('\n')) {
        Ok(req) => dispatch(&daemon, req),
        Err(e) => Response::err(ErrorKind::BadArgs, format!("decode: {e}")),
    };

    let mut bytes = serde_json::to_vec(&resp)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
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
        op::ARCHIVE => crate::actions::archive(daemon, req.args),
        op::ADD_PROJECT => crate::actions::add_project(daemon, req.args),
        op::REFRESH_SNAPSHOT => crate::actions::refresh_snapshot(daemon, req.args),
        op::LIST_TREE => crate::reads::list_tree(daemon, req.args),
        op::READ_FILE => crate::reads::read_file(daemon, req.args),
        op::PAIR_BEGIN => handlers::pair_begin(daemon, req.args),
        op::PAIR_CONFIRM => handlers::pair_confirm(daemon, req.args),
        op::PAIR_LIST => handlers::pair_list(daemon, req.args),
        op::PAIR_REMOVE => handlers::pair_remove(daemon, req.args),
        op::DISCOVER_LIST => handlers::discover_list(daemon, req.args),
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
