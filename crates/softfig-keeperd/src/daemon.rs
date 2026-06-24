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
    /// Phase 3 (slice 002): ping-pong contention detector (spec §4d). Fed one
    /// `(target, editor)` per committed section edit; on an A↔B thrash it
    /// returns a `Trip` so the edit path posts a single coordination-bus nudge
    /// and flags the target for a lease. Lives here (under `inner`'s mutex) so
    /// every serialized edit sees one consistent history.
    pub thrash: crate::actions::ThrashDetector,
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
            thrash: crate::actions::ThrashDetector::new(),
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
    /// The garden mount point, held outside `inner` so the shutdown path can
    /// forcibly release a wedged FUSE mount **without** taking the daemon
    /// mutex — the lock a thread blocked on garden I/O may be holding. See
    /// [`Daemon::request_shutdown`].
    pub garden_root: PathBuf,
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
            garden_root.clone(),
        );
        Self {
            inner,
            suppress,
            accumulator,
            garden_root,
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

    /// growlightd's socket path for the keeperd→growlightd lease hop (spec §4c):
    /// the configured override, else the default
    /// [`softfig_ipc::growlightd_runtime_socket_path`].
    pub fn growlightd_socket(&self) -> PathBuf {
        self.inner
            .lock()
            .unwrap()
            .config
            .growlightd_socket
            .clone()
            .unwrap_or_else(softfig_ipc::growlightd_runtime_socket_path)
    }

    /// The graceful teardown shared by every shutdown trigger — the IPC
    /// `shutdown` op (`softfig daemon stop`), a SIGTERM/SIGINT caught in
    /// `main`, and [`DaemonHandle`]'s explicit shutdown + `Drop`. Marks
    /// the daemon `Stopping`, takes the blocking-to-drop handles out of
    /// `inner`, then **releases the lock before dropping them**.
    ///
    /// Busy-mount safety has two layers. **First, lock-free:** we abort the
    /// FUSE connection ([`softfig_fuse::force_release_mount`]) *before*
    /// touching `inner`. On a busy mount a thread can be parked in
    /// uninterruptible D-state on a garden read while holding `inner` (the
    /// FUSE worker, or a handler / net task mid-read); aborting the connection
    /// makes that read fail with `ENOTCONN` so the lock is released and the
    /// accept loop (which also polls [`Daemon::state`] under `inner`) keeps
    /// running. Without it we'd deadlock trying to lock `inner` here and
    /// `handle.join()` in `main` would never return — systemd's 90 s SIGKILL,
    /// the 2026-06-21 wedge. **Second, lock ordering:** even with the mount
    /// gone, dropping `net` joins its threads, so we take the handles out
    /// under the lock and drop them *after releasing it* — never hold `inner`
    /// across a blocking drop, or the accept loop starves and `main` hangs.
    /// The session is an `Arc`
    /// the FUSE driver also holds, so clearing `inner.session` here only
    /// drops the daemon's reference — the keys aren't zeroized until the
    /// mount (and its worker) are gone too, preserving "mount down before
    /// keys vanish". Idempotent — safe to call more than once (e.g. a
    /// signal followed by `DaemonHandle::drop`).
    pub fn request_shutdown(&self) {
        // LOCK-FREE FIRST: forcibly release the FUSE mount/connection before
        // touching `inner`. On a *busy* mount a thread can be parked in D-state
        // on a garden read — the FUSE worker, or a connection handler / net
        // task mid-read — while holding `inner`. If we tried to lock `inner`
        // first we'd deadlock behind it (and the accept loop, also polling
        // `state()`, would starve), so `main`'s `handle.join()` never returns
        // and systemd SIGKILLs us after 90 s (the 2026-06-21 wedge). Aborting
        // the kernel connection makes those reads fail with ENOTCONN at once,
        // releasing the lock holder so the teardown below — and the whole
        // process — can finish promptly. No-op when not FUSE-mounted.
        softfig_fuse::force_release_mount(&self.garden_root);
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
