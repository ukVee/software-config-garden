//! `Daemon` is the long-lived owner of growlightd's state — the bound socket,
//! the policy, and (in later phases) the agent fleet registry. Mirrors the
//! keeperd `Daemon`/`DaemonHandle` split: the accept loop hands `Arc`-shared
//! clones to each connection handler.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use thiserror::Error;

use crate::config::GrowlightdConfig;
use crate::state::State;

#[derive(Debug, Error)]
pub enum GrowlightdError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, GrowlightdError>;

#[derive(Debug)]
pub struct DaemonInner {
    pub state: State,
    pub config: GrowlightdConfig,
    // Phase 6 (concurrency milestone) adds the agent registry here: the live
    // `claude -p` child handles + per-agent status. Hard-stop teardown of those
    // children rides the same kill-safety discipline as keeperd's FUSE/commit
    // path (spec §8) — a clean per-agent SIGKILL is safe because each agent's
    // keeperd writes already commit from an in-memory snapshot, never mid-walk.
}

impl DaemonInner {
    pub fn new(config: GrowlightdConfig) -> Self {
        Self {
            state: State::Running,
            config,
        }
    }
}

/// Thread-safe handle the accept loop and (future) supervisor both share.
#[derive(Debug, Clone)]
pub struct Daemon {
    pub inner: Arc<Mutex<DaemonInner>>,
}

impl Daemon {
    pub fn new(config: GrowlightdConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DaemonInner::new(config))),
        }
    }

    /// Bind the socket and run the accept loop. Returns a handle that stays
    /// live until [`DaemonHandle::shutdown`] is called.
    pub fn start(self) -> Result<DaemonHandle> {
        crate::server::start(self)
    }

    pub fn state(&self) -> State {
        self.inner.lock().unwrap().state
    }

    pub fn socket_path(&self) -> PathBuf {
        self.inner.lock().unwrap().config.socket_path.clone()
    }

    /// Graceful teardown shared by every shutdown trigger — the IPC `shutdown`
    /// op, a caught SIGTERM/SIGINT, and [`DaemonHandle`]'s `Drop`. Marks the
    /// daemon `Stopping`; the accept loop notices on its next poll and exits.
    ///
    /// Phase 6 hooks fleet teardown in here: take the child handles out under
    /// the lock, release it, then SIGKILL them outside the lock (never hold the
    /// mutex across a blocking child wait — the lock-ordering lesson from
    /// keeperd's `request_shutdown`). The hard-kill is safe per spec §8 because
    /// each agent's garden writes commit from an in-memory snapshot. Idempotent.
    pub fn request_shutdown(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.state = State::Stopping;
    }
}

/// Handle to a running daemon. Owns the accept-thread join handle and the bound
/// socket path so it can clean up on drop.
#[derive(Debug)]
pub struct DaemonHandle {
    pub daemon: Daemon,
    pub thread: Option<JoinHandle<Result<()>>>,
    pub socket_path: PathBuf,
}

impl DaemonHandle {
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Request orderly shutdown: the accept loop notices `Stopping` on its next
    /// poll iteration and exits.
    pub fn shutdown(&self) {
        self.daemon.request_shutdown();
    }

    /// Block until the accept loop exits. Returns its result.
    pub fn join(mut self) -> Result<()> {
        if let Some(t) = self.thread.take() {
            t.join()
                .map_err(|_| GrowlightdError::Other("accept thread panicked".into()))?
        } else {
            Ok(())
        }
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        // Best-effort cleanup if the caller forgot to shutdown.
        self.shutdown();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
