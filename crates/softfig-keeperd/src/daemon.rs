//! `Daemon` is the long-lived owner of the unlocked Vault session, repo
//! handle, watcher state, and self-event suppression map. The accept
//! loop hands `Arc<Mutex<DaemonInner>>` clones to each connection
//! handler.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use softfig_vcs::Repo;
use softfig_fuse::MountHandle;
use softfig_net::{DeviceState, WriteTurn};
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
    /// Milestone #40: the holder-identity store behind the `set_item_status`
    /// active-claim CAS. Maps a backlog part `(region_tag, id)` to the agent
    /// that holds it `active`, so a claim of an already-`active` part by a
    /// *different* agent is refused while the same holder's re-claim stays
    /// idempotent (the durable defense-in-depth behind growlightd's own
    /// `assignments` dedup). **In-memory by design:** it is reset to empty on
    /// every daemon start, so a `daemon cycle` that leaves a part `active` with
    /// no live fleet records no holder — the rightful resumer's first claim
    /// wins, never a permanent refusal. Cleared per part when it leaves
    /// `active`. See [`crate::actions::growlight`].
    pub holders: crate::actions::HolderStore,
    /// M5d slice 006 part 2 — shared-key ceremony convergence state (all
    /// in-memory: a restart just re-derives them; no ceremony survives a
    /// restart, and the tie-break clock re-counting only costs one extra tick).
    ///
    /// In-flight dedup: chains with a ceremony currently running on this device
    /// (initiator or responder). A per-chain guard so one device never drives
    /// two concurrent ceremonies for one chain — an overlapping reconcile tick,
    /// or the reconcile-initiator racing the inbound-responder. Inserted before
    /// an initiate/serve leg and removed when it ends (RAII
    /// [`crate::net::CeremonyGuard`]).
    pub ceremonies_in_flight: HashSet<String>,
    /// Tie-break clock: chains this device saw still pending (unkeyed) in a
    /// *prior* reconcile pass. The lexically-higher device defers initiating
    /// until a chain is here, so in the symmetric dual-add case the lower
    /// device's ceremony lands (and fills the higher's row as responder) before
    /// the higher ever initiates — exactly one ceremony per chain per window.
    pub ceremony_seen_pending: HashSet<String>,
    /// Tie-break clock for **rotation** (M5d slice 003), the keyed-chain analogue
    /// of [`Self::ceremony_seen_pending`]: chains this device saw keyed-but-stale
    /// (committed transcript members != current ring) in a *prior* rekey pass. A
    /// chain is either unkeyed-pending or keyed-stale, never both, so this is a
    /// separate set from the establishment clock — `reconcile_rekeys` takes/rebuilds
    /// it independently of `reconcile_ceremonies`, and the same `should_initiate_now`
    /// tie-break makes exactly one device initiate each rotation window.
    pub rekey_seen_stale: HashSet<String>,
    /// Divergence surface (item 4): the most recent shared-key divergence
    /// message (a completed ceremony that met a row already keyed with a
    /// *different* key — the one-key-per-chain invariant violated). Surfaced
    /// through the `status` verb so a divergence is visible, not stderr-only;
    /// with S-encryption live it otherwise presents as silent chain corruption.
    pub last_shared_key_divergence: Option<String>,
    /// M5e slice 001 part 2 — this device's shared-coordination state, announced
    /// to S-members via a signed `DeviceStateAnnounce`. The lifecycle sets the
    /// floor: `Offline` while `Locked` (this field is reset to `Offline` on lock,
    /// below). On unlock the reconcile tick lifts it to `OnlineIdle`, then flips
    /// `OnlineIdle`↔`OnlineActive` from recent local write activity — the IPC is
    /// per-call (no persistent write session to refcount), so "actively writing"
    /// is derived from an [`Self::last_write_at`] activity window (part 3a) rather
    /// than a session attach/detach. Each change bumps [`Self::announce_seq`] and
    /// re-announces exactly once.
    pub device_state: DeviceState,
    /// M5e part 3a — monotonic (`Instant`) stamp of the most recent local,
    /// user-initiated garden write (set by the IPC dispatch, never by a
    /// peer-applied or ceremony/replica-internal commit). The reconcile tick reads
    /// it: a write within [`crate::net::WRITE_ACTIVITY_WINDOW`] ⇒ `OnlineActive`,
    /// else `OnlineIdle`. `None` = no write since unlock. Reset on lock so a stale
    /// pre-lock write can't read as active after the next unlock.
    pub last_write_at: Option<Instant>,
    /// M5e — this device's monotonic announce clock. Bumped on every state change
    /// so a peer can order a stale `DeviceStateAnnounce` against a fresh one and
    /// none can be replayed as a newer state. In-memory: a restart re-announces
    /// from a low seq, which a peer accepts as the fresh generation of a restarted
    /// device (its prior view is only kept while that device was reachable).
    pub announce_seq: u64,
    /// M5e — peers' most-recently-announced coordination state, keyed by device
    /// id, kept current by the inbound `DeviceStateAnnounce` handler (an announce
    /// with a `seq` at or below the stored one is ignored as stale). Read by the
    /// turn driver to know which S-members are online-active.
    pub peer_states: HashMap<[u8; 32], crate::net::PeerAnnounce>,
    /// M5e — this device's local view of each shared chain's write-turn lease,
    /// keyed by `ref_name`. Driven by the inbound turn handlers (this slice) and,
    /// in part 2b, the outbound broadcast driver + the commit boundary. In-memory
    /// by design (like [`Self::ceremonies_in_flight`]): a restart drops it and the
    /// lease re-derives from live announces under the lease TTL, so no turn
    /// survives a bounce — a crashed holder's lease simply expires.
    pub write_turns: HashMap<String, WriteTurn>,
    /// M5e part 3b-ii — coordination frames the shared-chain commit boundary
    /// decided to send (a `TurnRequest` when a local write wants the turn, a
    /// `TurnYield` when we hold + quiesce with a peer queued), queued under the
    /// daemon lock and drained + signed + fanned off-lock by
    /// [`crate::net::reconcile_write_turns`] on its commit-driven wake — the same
    /// snapshot-under-lock / IO-off-lock discipline as the expiry-revoke path.
    /// In-memory; cleared on soft lock alongside [`Self::write_turns`].
    pub pending_turn_broadcasts: Vec<crate::net::PendingTurnBroadcast>,
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
            holders: crate::actions::HolderStore::new(),
            ceremonies_in_flight: HashSet::new(),
            ceremony_seen_pending: HashSet::new(),
            rekey_seen_stale: HashSet::new(),
            last_shared_key_divergence: None,
            device_state: DeviceState::Offline,
            last_write_at: None,
            announce_seq: 0,
            peer_states: HashMap::new(),
            write_turns: HashMap::new(),
            pending_turn_broadcasts: Vec::new(),
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
    /// Serializes the deploy verbs (task 036 follow-up): they drop `inner`
    /// before their blocking filesystem work, so without this two concurrent
    /// forced applies could interleave the conflict-backup dance and destroy
    /// the only backup of a user file. Its own lock, NOT `inner` — `status`
    /// etc. stay unblocked while a deploy runs. Lock order: the gate is
    /// acquired *before* `inner` and nothing acquires the gate while holding
    /// `inner`, so no cycle is possible.
    pub deploy_gate: Arc<Mutex<()>>,
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
            deploy_gate: Arc::new(Mutex::new(())),
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
        let (fuse, net, supervise, resume_pending) = {
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
            // A still-armed (unexpired) blob after pruning means a `daemon cycle`/
            // `relock` is pending — a *resume*, not a terminal lock. That decides
            // whether the growlightd unit is stopped below (config-in-garden
            // slice 2 / locked-decision 5): a resume leaves the fleet running to
            // ride the bounce via its reconnecting IPC; a terminal lock stops it.
            let resume_pending =
                crate::relock::pending_expires_at(inner.config.state_dir(), now).is_some();
            let supervise = inner.config.enable_growlight_supervision;
            let fuse = inner.fuse.take();
            let net = inner.net.take();
            inner.pending_pairs.clear();
            // M5e: drop all shared-coordination state — the net runtime is going
            // away, so leases/peer views are meaningless, and returning
            // `device_state` to `Offline` makes the next unlock re-announce the
            // `Offline`→`OnlineIdle` lift (the "I'm back online" beacon). Keep
            // `announce_seq` monotonic across a soft lock so a peer never accepts a
            // regressed post-unlock announce as stale.
            inner.device_state = DeviceState::Offline;
            inner.last_write_at = None;
            inner.write_turns.clear();
            inner.pending_turn_broadcasts.clear();
            inner.peer_states.clear();
            inner.session = None;
            inner.repo = None;
            (fuse, net, supervise, resume_pending)
        };
        // Lock released — now run the potentially-blocking drops outside it.
        drop(fuse);
        drop(net);
        // Terminal lock (no pending resume) ⇒ ask systemd to stop the growlightd
        // user unit. Spawned without waiting so growlightd's graceful boundary
        // exit never stalls keeperd's own teardown (the 2026-06-21/22 wedge class).
        crate::growlight_unit::stop_on_terminal_lock(supervise, resume_pending);
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
