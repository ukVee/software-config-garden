//! `Daemon` is the long-lived owner of the unlocked Vault session, repo
//! handle, watcher state, and self-event suppression map. The accept
//! loop hands `Arc<Mutex<DaemonInner>>` clones to each connection
//! handler.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use softfig_core::Repo;
use softfig_fuse::MountHandle;
use softfig_vault::VaultSession;
use thiserror::Error;

use crate::config::KeeperConfig;
use crate::layer_b::SharedLayerB;
use crate::state::State;
use crate::watcher::DirtySetAccumulator;

/// Window during which a path written by the daemon itself is
/// considered "self-event" and watcher events touching it are dropped.
pub const SUPPRESS_WINDOW_MS: u64 = 500;

#[derive(Debug, Error)]
pub enum KeeperError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault: {0}")]
    Vault(#[from] softfig_vault::VaultError),
    #[error("core: {0}")]
    Core(#[from] softfig_core::CoreError),
    #[error("store: {0}")]
    Store(#[from] softfig_store::StoreError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("daemon already stopping")]
    AlreadyStopping,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, KeeperError>;

#[derive(Debug)]
pub struct DaemonInner {
    pub state: State,
    pub config: KeeperConfig,
    /// Held in an `Arc` so the FUSE driver can share the same
    /// (non-clonable) session for blob decryption without taking the
    /// daemon's mutex on every read.
    pub session: Option<Arc<VaultSession>>,
    pub repo: Option<Repo>,
    /// In M2a (FUSE) mode, the live mount handle. Dropping unmounts the
    /// FUSE filesystem; the handle is replaced by `migrate_finalize`
    /// during the unmount → delete → remount dance.
    pub fuse: Option<MountHandle>,
    /// M2b: shared Layer B hook — `BlobEncryptor` for commit-time
    /// routing AND `SealedQuery` for the FUSE read-path placeholder.
    /// Initialized to "empty" (no globs) so M2b is inert until the
    /// user writes a `sealed-paths.toml`.
    pub layer_b: SharedLayerB,
    /// M2b: timestamp of the most recent successful `softfig reveal`.
    /// Used by the idle-window check in `handle_vault_reveal` —
    /// `None` means no recent reveal, prompt required.
    pub last_reveal_at: Option<Instant>,
}

impl DaemonInner {
    pub fn new(config: KeeperConfig) -> Self {
        Self {
            state: State::Locked,
            config,
            session: None,
            repo: None,
            fuse: None,
            layer_b: Arc::new(crate::layer_b::LayerBHook::empty()),
            last_reveal_at: None,
        }
    }
}

/// Thread-safe handle that the accept loop and watcher both share.
#[derive(Debug, Clone)]
pub struct Daemon {
    pub inner: Arc<Mutex<DaemonInner>>,
    pub suppress: Arc<Mutex<HashMap<PathBuf, Instant>>>,
    /// Single classifier pipeline per the M1d picks: shared by the
    /// inotify driver and (in M2a) the FUSE driver. Initialized in
    /// `Daemon::new` so any subsystem can `push` without taking the
    /// daemon's main mutex.
    pub accumulator: Arc<DirtySetAccumulator>,
}

impl Daemon {
    pub fn new(config: KeeperConfig) -> Self {
        let garden_root = config.garden_root.clone();
        let inner = Arc::new(Mutex::new(DaemonInner::new(config)));
        let suppress: Arc<Mutex<HashMap<PathBuf, Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let accumulator = DirtySetAccumulator::new(
            inner.clone(),
            suppress.clone(),
            garden_root,
        );
        Self {
            inner,
            suppress,
            accumulator,
        }
    }

    /// Bind the socket and run the accept loop. Returns a handle that
    /// stays live until [`DaemonHandle::shutdown`] is called.
    pub fn start(self) -> Result<DaemonHandle> {
        crate::server::start(self)
    }

    pub fn state(&self) -> State {
        self.inner.lock().unwrap().state
    }

    /// Mark a path as "written by the daemon itself" — watcher events
    /// for that path are dropped until the suppression window expires.
    pub fn mark_self_write(&self, path: PathBuf) {
        let until =
            Instant::now() + std::time::Duration::from_millis(SUPPRESS_WINDOW_MS);
        self.suppress.lock().unwrap().insert(path, until);
    }

    /// Drop expired suppression entries. Called lazily on each watcher
    /// event arrival.
    pub fn prune_suppress(&self) {
        let now = Instant::now();
        let mut map = self.suppress.lock().unwrap();
        map.retain(|_, until| *until > now);
    }

    pub fn is_self_write(&self, path: &std::path::Path) -> bool {
        self.prune_suppress();
        self.suppress.lock().unwrap().contains_key(path)
    }
}

/// Handle to a running daemon. Owns the accept-thread join handle and
/// owns the path of the bound socket so it can clean up on drop.
#[derive(Debug)]
pub struct DaemonHandle {
    pub daemon: Daemon,
    pub thread: Option<JoinHandle<Result<()>>>,
    pub watcher: Option<JoinHandle<()>>,
    pub socket_path: PathBuf,
}

impl DaemonHandle {
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Request orderly shutdown. Sets state to Stopping; the accept
    /// loop notices on its next poll iteration and exits.
    pub fn shutdown(&self) {
        let mut inner = self.daemon.inner.lock().unwrap();
        inner.state = State::Stopping;
        // Drop the FUSE mount BEFORE the session — the FS handlers
        // need the session for any in-flight reads, and unmount blocks
        // until the kernel acknowledges all in-flight requests.
        let _ = inner.fuse.take();
        // Drop the unlocked session — no need to wait for the
        // accept loop to exit before zeroizing keys.
        inner.session = None;
        inner.repo = None;
    }

    /// Block until the accept loop exits. Returns its result. Also
    /// joins the watcher thread (best-effort) so its `Debouncer` is
    /// dropped before this returns — important for tests so the tempdir
    /// can be cleaned up without dangling inotify watches.
    pub fn join(mut self) -> Result<()> {
        let accept_result = if let Some(t) = self.thread.take() {
            t.join().map_err(|_| {
                KeeperError::Other("accept thread panicked".to_string())
            })?
        } else {
            Ok(())
        };
        if let Some(w) = self.watcher.take() {
            let _ = w.join();
        }
        accept_result
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        // Best-effort cleanup if the caller forgot to shutdown.
        self.shutdown();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
