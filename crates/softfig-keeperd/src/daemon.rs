//! `Daemon` is the long-lived owner of the unlocked Vault session, repo
//! handle, watcher state, and self-event suppression map. The accept
//! loop hands `Arc<Mutex<DaemonInner>>` clones to each connection
//! handler.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use softfig_vcs::Repo;
use softfig_fuse::MountHandle;
use softfig_vault::VaultSession;
use thiserror::Error;

use crate::config::KeeperConfig;
use crate::layer_b::SharedLayerB;
use crate::net::{NetRuntime, PendingPairs};
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
    Core(#[from] softfig_vcs::CoreError),
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
    /// M5a-4: the live `softfig-net` host (inbound listener + mDNS +
    /// optional relay). `Some` while unlocked and `[net] enabled`;
    /// dropped on lock/shutdown (which stops its threads + unregisters
    /// the mDNS service).
    pub net: Option<NetRuntime>,
    /// M5a-4: pairings whose `XX` handshake completed and are awaiting
    /// the user's out-of-band SAS confirmation (`pair_confirm`). Each
    /// holds a live socket, so they are pruned + dropped on lock.
    pub pending_pairs: PendingPairs,
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
            net: None,
            pending_pairs: PendingPairs::default(),
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

    /// The graceful teardown shared by every shutdown trigger — the IPC
    /// `shutdown` op (`softfig daemon stop`), a SIGTERM/SIGINT caught in
    /// `main`, and [`DaemonHandle`]'s explicit shutdown + `Drop`. Marks
    /// the daemon `Stopping`, takes the blocking-to-drop handles out of
    /// `inner`, then **releases the lock before dropping them**.
    ///
    /// Lock ordering is load-bearing: dropping the FUSE mount unmounts and
    /// blocks until the kernel drains all in-flight requests — on a *busy*
    /// mount (active reads/writes, a process with its cwd inside the
    /// garden) that can block indefinitely — and dropping `net` joins its
    /// threads. The accept loop polls [`Daemon::state`], which locks
    /// `inner`. If we held `inner` across those blocking drops, the accept
    /// loop would starve, never observe `Stopping`, and `handle.join()` in
    /// `main` would never return — so a SIGTERM caught mid-use wedged the
    /// process (holding `/dev/fuse` open but unserviced → D-state for
    /// anything touching the garden) until systemd's 90 s SIGKILL. Taking
    /// the handles out under the lock and dropping them after it is
    /// released lets the accept loop exit and the process terminate
    /// promptly even while the unmount is still draining; when the mount is
    /// idle the unmount still completes cleanly. The session is an `Arc`
    /// the FUSE driver also holds, so clearing `inner.session` here only
    /// drops the daemon's reference — the keys aren't zeroized until the
    /// mount (and its worker) are gone too, preserving "mount down before
    /// keys vanish". Idempotent — safe to call more than once (e.g. a
    /// signal followed by `DaemonHandle::drop`).
    pub fn request_shutdown(&self) {
        let (fuse, net) = {
            let mut inner = self.inner.lock().unwrap();
            inner.state = State::Stopping;
            // Growlight: prune an *expired* relock blob, but never a live one — a
            // graceful `daemon stop` is exactly the bounce a pending `cycle` relies
            // on, so the unexpired blob must survive for the new daemon to redeem.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            crate::relock::prune_expired(inner.config.state_dir(), now);
            let fuse = inner.fuse.take();
            let net = inner.net.take();
            inner.pending_pairs.clear();
            inner.session = None;
            inner.repo = None;
            (fuse, net)
        };
        // Lock released — now run the potentially-blocking drops outside it.
        drop(fuse);
        drop(net);
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

    /// Request orderly shutdown: runs the shared graceful teardown
    /// ([`Daemon::request_shutdown`]); the accept loop notices the
    /// `Stopping` state on its next poll iteration and exits.
    pub fn shutdown(&self) {
        self.daemon.request_shutdown();
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
