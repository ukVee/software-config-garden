//! M5a-4: keeperd hosts the `softfig-net` instance.
//!
//! On unlock the daemon builds a [`LocalDevice`] from the vault session (the
//! X25519 transport secret + the Ed25519 identity + a freshly-signed transport
//! attestation), then — if `[net] enabled` — starts the live networking:
//!
//! * an **inbound TCP listener** for Noise sessions. A device whose ring is
//!   still empty (a *fresh* device being added) serves the pairing *responder*
//!   role ([`pair_responder`]); once it has at least one peer it serves the
//!   *reconnect* role ([`ik_responder`]) and a `Ping`/`Pong` liveness echo for
//!   authenticated ring members. This derives the responder/initiator split
//!   straight from ring state, so it needs no extra wire discriminator (none
//!   exists in `softfig-net`, and M5a-4 adds no new protocol).
//! * the **mDNS responder** — announce `_softfig._tcp` and a browse loop that
//!   folds resolved peers' endpoints into the ring ([`refresh_ring_endpoints`])
//!   and a discovery cache that `pair_begin` consults to resolve a fingerprint
//!   to an endpoint.
//! * the **relay listener**, when `[relay] enabled` — a blind, ring-authorized
//!   dumb pipe ([`Relay`]) for off-LAN peers.
//!
//! The pairing *initiator* path ([`initiate_pairing`]) is driven by the
//! `pair_begin` IPC verb and does **not** depend on the listener: it dials the
//! peer outbound, so it is exercised headless (loopback TCP) in the tests while
//! the listener / mDNS / relay are the documented manual real-machine smoke
//! step (same posture as FUSE / TUI), gated off in tests via
//! [`KeeperConfig::without_net`](crate::config::KeeperConfig::without_net).
//!
//! **Frontend-neutral logic stays in `softfig-net`.** This module is the thin
//! host: it owns the live sockets, the threads, and the lock-free snapshotting
//! that keeps network IO off the daemon mutex.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};
use softfig_ipc::verbs::DiscoveredDevice;
use softfig_ipc::ErrorKind;
use softfig_net::discovery::{self, Advertisement};
use softfig_net::endpoint_cache::{endpoint_cache_path, EndpointCache};
use softfig_net::pairing::{pair_initiator, pair_responder, LocalDevice, PendingPair};
use softfig_net::proto::{frame, Frame, ReplicaGrant, TipAnnounce};
use softfig_net::connect::{plan_routes, Route};
use softfig_net::relay::{relay_connect, Relay, RelayStream};
use softfig_net::ring::{ring_path, Ring, RingEntry, RING_FILE};
use softfig_net::transport::{ik_initiator, ik_responder, NoiseSession};
use softfig_net::{
    pull_replication_pipelined, serve_replication, static_attestation_message, verify_grant,
    NetError, ServeSummary,
};
use softfig_store::Hash;
use softfig_vault::VaultSession;
use softfig_vcs::{Intent, Repo};

use crate::actions::WorkTree;
use crate::config::KeeperConfig;
use crate::daemon::{Daemon, DaemonInner};
use crate::keeper_toml::CONFIG_DIR;
use crate::replica::{self, MirrorStore, RepoSource};
use crate::state::State;

/// How long a parked (initiator- or responder-side) pairing lives before it is
/// pruned. The user confirms the SAS out of band; this bounds the live socket a
/// parked pairing holds open so a half-finished pairing can't leak forever.
const PAIRING_TTL: Duration = Duration::from_secs(300);

/// Poll cadence for the interruptible accept / browse loops, so a lock (drop of
/// the runtime) is honoured promptly without a blocking accept.
const POLL_MS: u64 = 150;

/// How long a discovered device lingers in the pick-list after its last mDNS
/// sighting before it is treated as gone. Generous so a momentarily-quiet
/// device doesn't drop out of the list mid-pair.
const DISCOVERY_TTL: Duration = Duration::from_secs(300);

/// M5b: how often the owner's replica loop re-pushes its chain to each granted,
/// reachable host. The host's pull short-circuits when already up to date, so
/// each reconcile is cheap; the loop doubles as catch-up (a host that was
/// offline is reached on a later tick — the tip-driven reconcile, not a queue).
/// (Real-time push-on-commit is a noted follow-up; this interval bounds latency.)
const REPLICA_RECONCILE_INTERVAL: Duration = Duration::from_secs(20);

/// A short settle delay before the first replica reconcile, so unlock finishes
/// and mDNS has a chance to populate ring endpoints first.
const REPLICA_INITIAL_DELAY: Duration = Duration::from_secs(2);

/// Per-attempt dial timeout for an outbound replication push.
const PUSH_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Read/write timeout on an outbound replication push once connected — bounds a
/// stalled peer (or a stalled relay leg) without blocking the reconcile thread
/// forever. Applied to the socket, so on the relay route it bounds the outer
/// device↔relay leg the inner `RelayStream` rides on.
const PUSH_IO_TIMEOUT: Duration = Duration::from_secs(30);

// --- Discovery cache (Slice A pick-list) ------------------------------------

/// One nearby device the mDNS browse loop has resolved, cached for the
/// `discover_list` pick-list and for `pair_begin` endpoint resolution. The
/// `name` is a convenience hint from the peer's TXT `nm` field — addressing,
/// not authentication (the SAS still authenticates).
#[derive(Clone, Debug)]
pub struct DiscoveredEntry {
    /// The peer's advertised friendly name (TXT `nm`), if any.
    pub name: Option<String>,
    /// Reachable `host:port` endpoints from the resolved mDNS addresses.
    pub endpoints: Vec<String>,
    /// The peer's self-reported paired flag (TXT `pr`). Informational only —
    /// the pick-list filters on *our* ring membership, not this.
    pub paired: bool,
    /// When this device was last resolved on the LAN.
    pub last_seen: Instant,
}

/// Build the pick-list of discovered-but-unpaired nearby devices from the
/// browse cache. Filters out our own announcement, current ring members, and
/// sightings older than [`DISCOVERY_TTL`]; sorts by name then fingerprint for a
/// stable display. Pure (no sockets / clock beyond the passed `now`) so it is
/// unit-tested headless — the live mDNS that fills the cache is the manual
/// real-machine smoke step.
fn build_discover_list(
    cache: &HashMap<String, DiscoveredEntry>,
    ring: &Ring,
    local_fingerprint: &str,
    now: Instant,
) -> Vec<DiscoveredDevice> {
    let ring_fps: HashSet<String> = ring.peers().iter().map(|p| p.fingerprint()).collect();
    let mut devices: Vec<DiscoveredDevice> = cache
        .iter()
        .filter(|(fp, entry)| {
            fp.as_str() != local_fingerprint
                && !ring_fps.contains(*fp)
                && now.saturating_duration_since(entry.last_seen) < DISCOVERY_TTL
        })
        .map(|(fp, entry)| DiscoveredDevice {
            name: entry.name.clone(),
            fingerprint: fp.clone(),
            endpoint: entry.endpoints.first().cloned(),
            last_seen_secs: now.saturating_duration_since(entry.last_seen).as_secs(),
        })
        .collect();
    devices.sort_by(|a, b| {
        a.name
            .as_deref()
            .unwrap_or("")
            .cmp(b.name.as_deref().unwrap_or(""))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    devices
}

/// Build this device's [`LocalDevice`] pairing material from an unlocked vault
/// session. The Ed25519 identity secret never leaves the vault — the
/// attestation is a precomputed signature over our own X25519 transport static
/// (see [`softfig_net::attest`]).
pub fn build_local_device(session: &VaultSession, device_name: String) -> LocalDevice {
    let transport_secret = *session.transport_secret();
    let transport_pubkey = session.transport_pubkey();
    let device_id = session.identity_pubkey().to_bytes();
    let static_attestation = session
        .sign(&static_attestation_message(&transport_pubkey))
        .to_bytes();
    LocalDevice {
        transport_secret,
        device_id,
        device_name,
        static_attestation,
    }
}

/// Resolve the device name: the `[net] device_name` override, else the system
/// hostname, else a constant fallback. Read from `/proc/sys/kernel/hostname`
/// (Linux live hostname) so no `unsafe` `gethostname` is needed.
pub fn device_name(config: &KeeperConfig) -> String {
    if let Some(name) = &config.net.device_name {
        if !name.trim().is_empty() {
            return name.clone();
        }
    }
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "softfig-device".to_string())
}

// --- Parked pairings --------------------------------------------------------

/// A pairing whose Noise `XX` handshake completed and passed attestation,
/// awaiting the user's SAS confirmation. Holds the live session (via
/// [`PendingPair`]) plus the display metadata.
pub struct ParkedPairing {
    pub pending: PendingPair<TcpStream>,
    pub sas: String,
    pub fingerprint: String,
    pub name: String,
    pub created: Instant,
}

impl std::fmt::Debug for ParkedPairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PendingPair holds a live session and is not Debug; surface only the
        // display metadata.
        f.debug_struct("ParkedPairing")
            .field("fingerprint", &self.fingerprint)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// In-memory parked pairings, keyed by an opaque `pairing_id`. Ephemeral —
/// each holds a live socket, so they are pruned past [`PAIRING_TTL`] and
/// dropped on lock/shutdown. Lives in `DaemonInner` behind the daemon mutex.
#[derive(Default)]
pub struct PendingPairs {
    map: HashMap<String, ParkedPairing>,
    next_id: u64,
}

impl std::fmt::Debug for PendingPairs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPairs")
            .field("count", &self.map.len())
            .finish()
    }
}

impl PendingPairs {
    /// Drop parked pairings older than [`PAIRING_TTL`], then park `parked`
    /// under a fresh id (returned).
    pub fn park(&mut self, parked: ParkedPairing) -> String {
        self.prune();
        let id = {
            self.next_id += 1;
            format!("pair-{:x}", self.next_id)
        };
        self.map.insert(id.clone(), parked);
        id
    }

    pub fn take(&mut self, id: &str) -> Option<ParkedPairing> {
        self.prune();
        self.map.remove(id)
    }

    /// A snapshot of live parked pairings for `pair_list` (id + display fields).
    pub fn list(&self) -> Vec<(String, String, String, String)> {
        self.map
            .iter()
            .filter(|(_, p)| p.created.elapsed() < PAIRING_TTL)
            .map(|(id, p)| {
                (
                    id.clone(),
                    p.sas.clone(),
                    p.fingerprint.clone(),
                    p.name.clone(),
                )
            })
            .collect()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    fn prune(&mut self) {
        self.map.retain(|_, p| p.created.elapsed() < PAIRING_TTL);
    }
}

// --- Initiator path (drives its own outbound socket; no listener needed) ----

/// Dial `endpoint`, run the Noise `XX` pairing handshake as the **initiator**,
/// and return the [`PendingPair`] (attestation already verified inside
/// `softfig-net`). The caller surfaces the SAS and parks the result.
pub fn initiate_pairing(local: &LocalDevice, endpoint: &str) -> Result<PendingPair<TcpStream>, NetError> {
    let addr: SocketAddr = endpoint
        .to_socket_addrs()?
        .next()
        .ok_or(NetError::Protocol("could not resolve pairing endpoint"))?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    pair_initiator(stream, local)
}

// --- Ring persistence: split membership (garden) from endpoints (sidecar) ----
//
// Membership (device id / name / transport key / attestation / paired_at) is
// the **source of truth** and lives inside the garden at `config/peers.toml`
// (encrypted, versioned, M5b-backed). Volatile endpoints live in a local
// `.softfig/peers-endpoints.toml` sidecar, never committed — so an mDNS sighting
// never dirties the garden. Membership writes go through the pairing handlers
// (`mark_self_write` + one self-write + a `peers_changed` commit), not here.

/// Repo-relative path of the membership ring within the garden:
/// `config/peers.toml`. WorkTree paths are repo-relative with `/` separators
/// (`""` = garden root), so membership reads/writes go through the overlay and
/// never touch an absolute mount path under `inner`.
fn membership_rel() -> String {
    format!("{CONFIG_DIR}/{RING_FILE}")
}

/// Load the live ring: membership from the garden `config/peers.toml` read
/// through the `worktree` (FUSE overlay / Disk passthrough — never the absolute
/// mount path under `inner`), falling back to the legacy `.softfig/peers.toml`
/// when the in-garden file is absent (non-breaking; once the garden file exists
/// the legacy one is ignored), then merge volatile endpoints from the sidecar.
/// `from_toml_str`/`Ring::load` re-verify every attestation, so a tampered
/// membership file is rejected.
pub(crate) fn load_ring(worktree: &WorkTree, state_dir: &std::path::Path) -> Result<Ring, NetError> {
    let rel = membership_rel();
    let mut ring = if worktree.exists(&rel) {
        // Present-but-unreadable membership is a tamper signal, not a silent
        // fall-through to the legacy ring.
        let raw = worktree
            .read_to_string(&rel)
            .ok_or(NetError::Protocol("membership peers.toml unreadable"))?;
        Ring::from_toml_str(&raw)?
    } else {
        // The legacy ring lives in `.softfig/` (the daemon state dir, outside
        // the mount), so this direct read is not mount I/O.
        Ring::load(&ring_path(state_dir))?
    };
    EndpointCache::load(&endpoint_cache_path(state_dir))?.apply(&mut ring);
    Ok(ring)
}

/// Persist a membership change (pair confirm / unpair) at the structural root:
/// serialize the ring's **membership** (endpoints stripped) and stage it to the
/// garden's `config/peers.toml` through the [`WorkTree`] (the FUSE overlay in
/// mount mode, a self-write-suppressed `std::fs` write on Disk — never a raw
/// write to the mount path under `inner`), commit `peers_changed` from the
/// in-memory snapshot via [`commit_now`](crate::actions::commit_now), then
/// refresh the volatile endpoint sidecar from the same ring so
/// reconnect-after-restart still works. The caller holds `inner` (the commit
/// needs it), has already up/removed the ring row, and passes the `daemon` (for
/// the WorkTree / self-write suppression map).
pub fn write_and_commit_membership(
    daemon: &Daemon,
    inner: &mut DaemonInner,
    state_dir: &std::path::Path,
    ring: &Ring,
) -> Result<Hash, (ErrorKind, String)> {
    let toml = ring
        .to_membership_toml()
        .map_err(|e| (ErrorKind::Internal, format!("serialize membership: {e}")))?;
    // Stage the write through the WorkTree; the next `commit_now` snapshot
    // (tip ∪ overlay) captures it, so no mount I/O happens under `inner`.
    {
        let wt = WorkTree::new(daemon, inner);
        wt.write(&membership_rel(), toml.as_bytes())?;
    }

    let payload = serde_json::json!({ "summary": format!("{} ring members", ring.len()) });
    let intent = Intent::new("peers_changed", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = crate::actions::commit_now(inner, intent)?;

    // Refresh the volatile endpoint sidecar (never committed) so a known peer's
    // endpoints survive a restart. Best-effort: a sidecar failure must not undo
    // the committed membership change.
    if let Err(e) = EndpointCache::capture(ring).save(&endpoint_cache_path(state_dir)) {
        eprintln!("keeperd: net: endpoint sidecar save: {e}");
    }
    Ok(hash)
}

// --- The live runtime: listener + mDNS + optional relay ---------------------

/// The live `softfig-net` host for an unlocked daemon. Dropping it stops every
/// thread (they poll the shutdown flag) and unregisters the mDNS service.
pub struct NetRuntime {
    /// The live ring, shared with the listener (IK authorization) and the
    /// browse loop (endpoint refresh). `peers.toml` on disk stays the source of
    /// truth; this mirror is kept in step by the pairing verbs.
    ring: Arc<Mutex<Ring>>,
    /// Discovery cache: fingerprint -> the device's last mDNS sighting (name,
    /// endpoints, paired flag, timestamp), filled by the browse loop.
    /// `pair_begin` consults it to resolve a fingerprint; `discover_list`
    /// surfaces it as the pick-list.
    discovery_cache: Arc<Mutex<HashMap<String, DiscoveredEntry>>>,
    stop: Arc<AtomicBool>,
    /// Wakes the replica push loop on each local commit (slice 1 event-driven
    /// push). Signalled by the daemon's commit drivers via [`Self::signal_commit`].
    replica_signal: Arc<ReplicaSignal>,
    threads: Vec<JoinHandle<()>>,
    /// The mDNS daemon handle + the registered fullname, retained to
    /// unregister + shut down on drop.
    mdns: Option<(ServiceDaemon, String)>,
    listen_addr: Option<SocketAddr>,
    relay_listen: Option<SocketAddr>,
}

impl std::fmt::Debug for NetRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetRuntime")
            .field("listen", &self.listen_addr)
            .field("relay_listen", &self.relay_listen)
            .field("peers", &self.ring.lock().map(|r| r.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl NetRuntime {
    /// Start the runtime for an unlocked daemon. Best-effort: a failure to bind
    /// the listener, create the mDNS daemon, or start the relay is logged and
    /// skipped (the network is a manual real-machine smoke step), never fatal
    /// to `unlock`. The live `ring` is loaded by the caller *under* `inner`
    /// (mount-safe via the `WorkTree`) and handed in, so this network setup runs
    /// entirely off the daemon mutex.
    pub fn start(daemon: &Daemon, config: &KeeperConfig, local: LocalDevice, ring: Ring) -> Self {
        let state_dir = config.state_dir().to_path_buf();
        let ring = Arc::new(Mutex::new(ring));
        let discovery_cache: Arc<Mutex<HashMap<String, DiscoveredEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        // Inbound Noise listener.
        let listen_addr = match config.net.listen.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(addr) => match TcpListener::bind(addr) {
                Ok(listener) => {
                    let _ = listener.set_nonblocking(true);
                    let bound = listener.local_addr().ok();
                    threads.push(spawn_inbound_loop(
                        listener,
                        daemon.clone(),
                        local.clone(),
                        ring.clone(),
                        stop.clone(),
                    ));
                    bound
                }
                Err(e) => {
                    eprintln!("keeperd: net: bind {} failed ({e}); inbound listener off", addr);
                    None
                }
            },
            None => {
                eprintln!(
                    "keeperd: net: could not resolve [net] listen {:?}; inbound listener off",
                    config.net.listen
                );
                None
            }
        };

        // mDNS announce + browse.
        let mut mdns = None;
        if let Some(addr) = listen_addr {
            match ServiceDaemon::new() {
                Ok(svc) => {
                    let paired = ring.lock().map(|r| !r.is_empty()).unwrap_or(false);
                    // Slice A: publish the friendly name unless the deployment
                    // opted into a fingerprint-only broadcast.
                    let name = config
                        .net
                        .advertise_name
                        .then(|| local.device_name.clone());
                    let ad = Advertisement {
                        device_id: local.device_id,
                        paired,
                        port: addr.port(),
                        name,
                    };
                    let fullname = announce_best_effort(&svc, &ad);
                    threads.push(spawn_browse_loop(
                        svc.clone(),
                        ring.clone(),
                        discovery_cache.clone(),
                        state_dir.clone(),
                        stop.clone(),
                    ));
                    mdns = Some((svc, fullname));
                }
                Err(e) => eprintln!("keeperd: net: mDNS daemon unavailable ({e}); discovery off"),
            }
        }

        // Optional relay listener.
        let relay_listen = if config.relay.enabled {
            match start_relay(config, &local, &ring, &stop) {
                Ok((addr, handle)) => {
                    threads.push(handle);
                    Some(addr)
                }
                Err(e) => {
                    eprintln!("keeperd: net: relay listener failed ({e}); relay off");
                    None
                }
            }
        } else {
            None
        };

        if let Some(addr) = listen_addr {
            eprintln!(
                "keeperd: net: hosting softfig-net on {addr} (device {})",
                hex::encode(local.device_id)
            );
        }

        // M5b: the owner-side replica push loop. Outbound-only, so it runs even
        // if the inbound listener failed to bind; it no-ops when this device has
        // granted no hosts (empty push_to). Slice 1: woken event-driven on each
        // local commit via `replica_signal`, with the interval as the fallback.
        let replica_signal = Arc::new(ReplicaSignal::default());
        threads.push(spawn_replica_loop(
            daemon.clone(),
            local.clone(),
            stop.clone(),
            replica_signal.clone(),
        ));

        Self {
            ring,
            discovery_cache,
            stop,
            replica_signal,
            threads,
            mdns,
            listen_addr,
            relay_listen,
        }
    }

    /// Wake the replica push loop after a local commit advanced the tip, so the
    /// owner pushes to online granted hosts immediately instead of waiting on the
    /// next reconcile tick. Called by the daemon's commit drivers; cheap + never
    /// blocks (the actual push runs on the replica thread, off the caller).
    pub fn signal_commit(&self) {
        self.replica_signal.signal_commit();
    }

    /// Look up an endpoint for `fingerprint` (full or unique prefix) from the
    /// discovery cache. `None` ⇒ not currently discovered.
    pub fn resolve_endpoint(&self, fingerprint: &str) -> Option<String> {
        let cache = self.discovery_cache.lock().ok()?;
        // Exact match first, then a unique prefix.
        if let Some(entry) = cache.get(fingerprint) {
            return entry.endpoints.first().cloned();
        }
        let mut hit = None;
        for (fp, entry) in cache.iter() {
            if fp.starts_with(fingerprint) {
                if hit.is_some() {
                    return None; // ambiguous prefix
                }
                hit = entry.endpoints.first().cloned();
            }
        }
        hit
    }

    /// Snapshot the discovery pick-list (Slice A): nearby devices that are not
    /// us and not already in `ring`, freshest sightings only. Empty if
    /// discovery has resolved nothing yet.
    pub fn discover_list(&self, ring: &Ring, local_fingerprint: &str) -> Vec<DiscoveredDevice> {
        let cache = match self.discovery_cache.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        build_discover_list(&cache, ring, local_fingerprint, Instant::now())
    }

    /// Mirror a ring change (pair confirm / unpair) into the live ring so the
    /// inbound listener's IK authorization sees it without a restart.
    pub fn sync_ring(&self, ring: &Ring) {
        if let Ok(mut live) = self.ring.lock() {
            *live = ring.clone();
        }
    }
}

impl Drop for NetRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the replica loop out of its condvar wait so it observes `stop`
        // promptly instead of parking up to a full reconcile interval.
        self.replica_signal.signal_stop();
        if let Some((svc, fullname)) = self.mdns.take() {
            let _ = svc.unregister(&fullname);
            let _ = svc.shutdown();
        }
        // Threads poll `stop` and exit within ~POLL_MS; join so their
        // LocalDevice/key copies are dropped before unlock returns.
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

// --- Thread bodies ----------------------------------------------------------

/// Inbound listener: derive role from ring state. Empty ring ⇒ pairing
/// responder; non-empty ⇒ IK reconnect + liveness echo for ring members.
fn spawn_inbound_loop(
    listener: TcpListener,
    daemon: Daemon,
    local: LocalDevice,
    ring: Arc<Mutex<Ring>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("keeperd-net-accept".into())
        .spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _addr)) => {
                        let daemon = daemon.clone();
                        let local = local.clone();
                        let ring = ring.clone();
                        thread::spawn(move || serve_inbound(daemon, &local, &ring, conn));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(POLL_MS));
                    }
                    Err(e) => {
                        eprintln!("keeperd: net: accept error: {e}");
                        thread::sleep(Duration::from_millis(POLL_MS));
                    }
                }
            }
        })
        .expect("spawn net accept thread")
}

/// Handle one inbound connection per the ring-state role split.
fn serve_inbound(daemon: Daemon, local: &LocalDevice, ring: &Arc<Mutex<Ring>>, conn: TcpStream) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(30)));
    let ring_empty = ring.lock().map(|r| r.is_empty()).unwrap_or(true);

    if ring_empty {
        // Fresh device: serve the pairing responder role and park the result
        // for the user to confirm (surfaced via `pair_list`).
        match pair_responder(conn, local) {
            Ok(pending) => {
                let peer = pending.peer();
                let parked = ParkedPairing {
                    sas: pending.sas().grouped(),
                    fingerprint: peer.fingerprint(),
                    name: peer.name.clone(),
                    created: Instant::now(),
                    pending,
                };
                let (fp, sas) = (parked.fingerprint.clone(), parked.sas.clone());
                let id = daemon.inner.lock().unwrap().pending_pairs.park(parked);
                eprintln!(
                    "keeperd: net: incoming pairing {id} from {fp}; SAS {sas}; \
                     confirm with `softfig pair {fp}` once the codes match"
                );
            }
            Err(e) => eprintln!("keeperd: net: inbound pairing failed: {e}"),
        }
    } else {
        // Established device: IK reconnect, authorize against the ring, then
        // dispatch on the first frame (liveness ping vs. a replication push).
        match ik_responder(conn, &local.transport_secret, &local.hello()) {
            Ok(session) => match ring_member_entry(ring, session.peer_static()) {
                Some(owner) => serve_established(&daemon, local, &owner, session),
                None => {
                    eprintln!("keeperd: net: rejecting reconnect from unknown transport key")
                }
            },
            Err(e) => eprintln!("keeperd: net: inbound IK handshake failed: {e}"),
        }
    }
}

/// Dispatch an established inbound session on its first frame: a `Ping` is a
/// liveness probe (echo loop); a `ReplicaGrant` is an owner pushing its chain to
/// us as a backup host (verify the grant, then mirror via `pull_replication`).
fn serve_established(
    daemon: &Daemon,
    local: &LocalDevice,
    owner: &RingEntry,
    mut session: NoiseSession<TcpStream>,
) {
    let Ok(frame) = session.recv_frame() else {
        return; // peer closed or errored before the first frame
    };
    match frame.kind {
        Some(frame::Kind::Ping(p)) => {
            // Answer the probe, then keep echoing; a failed send just makes the
            // echo loop's next read fail and return.
            let _ = session.send_frame(&Frame::pong(p.nonce));
            serve_echo(session);
        }
        Some(frame::Kind::ReplicaGrant(grant)) => {
            serve_replica_ingest(daemon, local, owner, grant, session)
        }
        // Anything else ends the session cleanly.
        _ => {}
    }
}

/// Host side of a replication push: confirm we opted in (`[replica] host`),
/// verify the owner's signed grant names *us* as grantee, then mirror the chain
/// into the per-peer ciphertext store via the fast-forward-only sink. A pull
/// failure (notably a non-fast-forward fork) is logged as an ALARM — the mirror
/// is left untouched, never force-updated.
fn serve_replica_ingest(
    daemon: &Daemon,
    local: &LocalDevice,
    owner: &RingEntry,
    grant: ReplicaGrant,
    session: NoiseSession<TcpStream>,
) {
    let (host_enabled, replica_root) = {
        let inner = daemon.inner.lock().unwrap();
        (inner.config.replica.host, inner.config.replica_root())
    };
    let owner_fp = owner.fingerprint();
    if !host_enabled {
        eprintln!(
            "keeperd: net: replica grant from {owner_fp} ignored ([replica] host = false)"
        );
        return;
    }
    if !verify_grant(&grant, &owner.device_id, &local.device_id) {
        eprintln!("keeperd: net: replica grant from {owner_fp} rejected (bad/foreign grant)");
        return;
    }
    let mut mirror = match MirrorStore::open_or_create(
        &replica_root,
        &owner.device_id,
        &owner.name,
        &grant.chain_id,
    ) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("keeperd: net: replica mirror open for {owner_fp} failed: {e}");
            return;
        }
    };
    // LAN-direct sessions are full-duplex-splittable, so use the pipelined
    // driver (streamed requests over a bounded in-flight window). It verifies +
    // stores identically to the sequential driver; the relay ingest path, whose
    // `RelayStream` can't split, stays on `pull_replication`.
    match pull_replication_pipelined(session, &mut mirror) {
        Ok(summary) => {
            if summary.commits > 0 {
                eprintln!(
                    "keeperd: net: mirrored {owner_fp}: +{} commits, +{} objects",
                    summary.commits, summary.objects
                );
            }
        }
        Err(e) => eprintln!(
            "keeperd: net: replica INGEST REJECTED from {owner_fp} (tamper/fork alarm): {e}"
        ),
    }
}

/// The ring member owning `transport_pubkey`, if any — the IK-authenticated
/// peer's authoritative identity (the ring binds device-id ↔ transport key, so
/// this is trusted over the handshake `HelloPayload`).
fn ring_member_entry(ring: &Arc<Mutex<Ring>>, transport_pubkey: &[u8; 32]) -> Option<RingEntry> {
    ring.lock()
        .ok()?
        .peers()
        .iter()
        .find(|p| &p.transport_pubkey == transport_pubkey)
        .cloned()
}

/// Minimal liveness service over an established reconnect session: answer each
/// `Ping` with a `Pong`. The data plane is M5b; this proves the channel is up.
fn serve_echo(mut session: NoiseSession<TcpStream>) {
    loop {
        match session.recv_frame() {
            Ok(frame) => match frame.kind {
                Some(frame::Kind::Ping(p)) => {
                    if session.send_frame(&Frame::pong(p.nonce)).is_err() {
                        return;
                    }
                }
                // Anything else (or a closed peer) ends the session cleanly.
                _ => return,
            },
            Err(_) => return,
        }
    }
}

/// mDNS browse loop: drain resolved peers, fold their endpoints into the live
/// ring + discovery cache, and persist the ring so the endpoints survive a
/// restart.
fn spawn_browse_loop(
    svc: ServiceDaemon,
    ring: Arc<Mutex<Ring>>,
    discovery_cache: Arc<Mutex<HashMap<String, DiscoveredEntry>>>,
    state_dir: std::path::PathBuf,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("keeperd-net-browse".into())
        .spawn(move || {
            let receiver = match discovery::browse(&svc) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("keeperd: net: browse failed ({e}); discovery off");
                    return;
                }
            };
            while !stop.load(Ordering::SeqCst) {
                match receiver.recv_timeout(Duration::from_millis(POLL_MS)) {
                    Ok(ServiceEvent::ServiceResolved(resolved)) => {
                        if let Some(peer) = discovery::resolved_to_peer(&resolved) {
                            // Cache for `pair_begin` endpoint resolution + the
                            // `discover_list` pick-list (name from TXT `nm`),
                            // then fold into a ring member if known.
                            if let Ok(mut cache) = discovery_cache.lock() {
                                cache.insert(
                                    peer.txt.fingerprint.clone(),
                                    DiscoveredEntry {
                                        name: peer.txt.name.clone(),
                                        endpoints: peer.endpoints.clone(),
                                        paired: peer.txt.paired,
                                        last_seen: Instant::now(),
                                    },
                                );
                            }
                            let persist = {
                                let mut r = ring.lock().unwrap();
                                discovery::refresh_ring_endpoints(&mut r, &peer)
                            };
                            if persist {
                                // A known peer's endpoints changed — refresh the
                                // volatile sidecar (NOT the committed membership
                                // file), so an mDNS sighting never dirties the
                                // garden.
                                let snapshot = ring.lock().unwrap().clone();
                                let cache = EndpointCache::capture(&snapshot);
                                if let Err(e) = cache.save(&endpoint_cache_path(&state_dir)) {
                                    eprintln!("keeperd: net: endpoint sidecar save: {e}");
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {} // timeout (poll) or channel closed
                }
            }
        })
        .expect("spawn net browse thread")
}

/// Bind + run the blind relay accept loop (interruptible, so a lock drops the
/// relay's transport-secret copy). Mirrors `softfig_net::relay::run` but polls
/// the shutdown flag instead of blocking forever on `incoming()`.
fn start_relay(
    config: &KeeperConfig,
    local: &LocalDevice,
    ring: &Arc<Mutex<Ring>>,
    stop: &Arc<AtomicBool>,
) -> Result<(SocketAddr, JoinHandle<()>), String> {
    let listen = config
        .relay
        .listen
        .as_deref()
        .ok_or_else(|| "[relay] enabled but no listen address".to_string())?;
    let addr: SocketAddr = listen
        .to_socket_addrs()
        .map_err(|e| format!("resolve {listen}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {listen}"))?;
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    listener.set_nonblocking(true).ok();
    let bound = listener.local_addr().unwrap_or(addr);

    // Authorize against the ring as it stands at relay start (M5a-3 follow-up:
    // a re-pair mid-flight needs a relay restart to be authorized).
    let relay = Relay::new(local, ring.lock().unwrap().clone());
    let stop = stop.clone();
    let handle = thread::Builder::new()
        .name("keeperd-net-relay".into())
        .spawn(move || {
            eprintln!("keeperd: net: relay listening on {bound}");
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _addr)) => {
                        let relay = Arc::clone(&relay);
                        thread::spawn(move || {
                            let _ = relay.serve(conn);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(POLL_MS));
                    }
                    Err(e) => {
                        eprintln!("keeperd: net: relay accept error: {e}");
                        thread::sleep(Duration::from_millis(POLL_MS));
                    }
                }
            }
        })
        .map_err(|e| format!("spawn relay thread: {e}"))?;
    Ok((bound, handle))
}

// --- M5b owner-side replica push loop ---------------------------------------

/// Wakes the owner-side replica push loop the instant a local commit advances the
/// tip, so replication fires **event-driven** rather than on the ~20s reconcile
/// poll (M5b-hardening slice 1). The keeper authors every commit, so the daemon's
/// commit drivers ([`crate::actions::commit_now`] + the watcher flush) signal this
/// on each successful tip advance. The periodic reconcile stays as the offline
/// catch-up fallback — a host offline at commit time still converges on a later
/// tick, so no commit-time queue is needed.
#[derive(Default)]
struct ReplicaSignal {
    state: Mutex<ReplicaSignalState>,
    cv: Condvar,
}

#[derive(Default)]
struct ReplicaSignalState {
    /// A tip-advancing commit landed since the loop last drained the flag.
    commit: bool,
    /// The runtime is shutting down: wake and exit without a final reconcile.
    stop: bool,
}

impl ReplicaSignal {
    /// Note a local commit and wake the push loop out of its interval sleep.
    fn signal_commit(&self) {
        let mut s = self.state.lock().unwrap();
        s.commit = true;
        self.cv.notify_all();
    }

    /// Wake the push loop for shutdown so it exits promptly instead of parking
    /// until the reconcile interval elapses.
    fn signal_stop(&self) {
        let mut s = self.state.lock().unwrap();
        s.stop = true;
        self.cv.notify_all();
    }

    /// Block up to `dur` waiting for a commit signal. Returns `true` if a commit
    /// woke it (draining the flag), `false` on timeout or shutdown. The mutex is
    /// released while parked and never held across the caller's reconcile.
    fn wait_for_commit(&self, dur: Duration) -> bool {
        let mut s = self.state.lock().unwrap();
        let deadline = Instant::now() + dur;
        loop {
            if s.stop {
                return false;
            }
            if s.commit {
                s.commit = false;
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, _timeout) = self.cv.wait_timeout(s, deadline - now).unwrap();
            s = guard;
        }
    }
}

/// The owner's replica push loop. It reconciles immediately on each local commit
/// (woken via [`ReplicaSignal`]) and otherwise every [`REPLICA_RECONCILE_INTERVAL`]
/// as the offline catch-up fallback, re-pushing this device's chain to each
/// granted host that has a known endpoint. Outbound-only; quiet when nothing is
/// granted or no host is reachable.
fn spawn_replica_loop(
    daemon: Daemon,
    local: LocalDevice,
    stop: Arc<AtomicBool>,
    signal: Arc<ReplicaSignal>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("keeperd-net-replica".into())
        .spawn(move || {
            // Short settle so unlock finishes wiring before the first push; an
            // early commit during the settle brings the reconcile forward.
            signal.wait_for_commit(REPLICA_INITIAL_DELAY);
            while !stop.load(Ordering::SeqCst) {
                reconcile_replicas(&daemon, &local);
                signal.wait_for_commit(REPLICA_RECONCILE_INTERVAL);
            }
        })
        .expect("spawn net replica thread")
}

/// One reconcile pass: snapshot the signed announce + per-host grants under the
/// daemon lock, then push to each granted, reachable host with the lock
/// released (never hold the mutex across network IO).
fn reconcile_replicas(daemon: &Daemon, local: &LocalDevice) {
    let snapshot = {
        let inner = daemon.inner.lock().unwrap();
        if inner.state != State::Unlocked {
            return;
        }
        let (Some(session), Some(repo)) = (inner.session.as_ref(), inner.repo.as_ref()) else {
            return;
        };
        let state_dir = inner.config.state_dir().to_path_buf();
        let ledger = replica::GrantLedger::load(&state_dir).unwrap_or_default();
        if ledger.push_to.is_empty() {
            return;
        }
        let announce = match replica::build_announce(repo, session) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("keeperd: net: replica announce build failed: {e}");
                return;
            }
        };
        let ring = {
            let wt = WorkTree::new(daemon, &inner);
            load_ring(&wt, &state_dir).unwrap_or_default()
        };
        // Slice 2: the client-side relay dial target (`[relay] endpoint` +
        // `static_key`), if configured. Its presence makes a host with no LAN
        // endpoint still reachable — `plan_routes` appends a relay fallback.
        let relay_client = relay_client_config(&inner.config);
        let relay_available = relay_client.is_some();
        let mut targets: Vec<(RingEntry, ReplicaGrant)> = Vec::new();
        for fp in &ledger.push_to {
            if let Some(host) = ring.peers().iter().find(|p| &p.fingerprint() == fp) {
                if plan_routes(host, relay_available).is_empty() {
                    // No LAN endpoint and no relay — unreachable this tick; the
                    // reconcile loop catches it up once a route appears.
                    continue;
                }
                let grant = replica::mint_grant(&host.device_id, &announce.chain_id, session);
                targets.push((host.clone(), grant));
            }
        }
        let garden_root = inner.config.garden_root.clone();
        let state_root = inner.config.state_root.clone();
        (announce, garden_root, state_root, targets, relay_client)
    };
    let (announce, garden_root, state_root, targets, relay_client) = snapshot;

    for (host, grant) in targets {
        match push_to_host(
            local,
            &host,
            &announce,
            &grant,
            &garden_root,
            state_root.as_deref(),
            relay_client.as_ref(),
        ) {
            Ok(summary) if summary.commits_served > 0 => eprintln!(
                "keeperd: net: pushed chain to {}: served {} commits",
                host.fingerprint(),
                summary.commits_served
            ),
            Ok(_) => {} // host already up to date
            Err(e) => eprintln!(
                "keeperd: net: replica push to {} skipped: {e}",
                host.fingerprint()
            ),
        }
    }
}

/// Parse the client-side relay dial target from `[relay] endpoint` +
/// `static_key` into a `(host:port, 32-byte X25519 static)` pair. `None` when
/// either is unset or the key is not 32 hex bytes — the push then has no relay
/// fallback (LAN-direct only), never a hard error. (`[relay] enabled` is the
/// unrelated *hosting* switch; this reads only the client dial fields.)
fn relay_client_config(config: &KeeperConfig) -> Option<(String, [u8; 32])> {
    let endpoint = config.relay.endpoint.clone()?;
    let key_hex = config.relay.static_key.as_ref()?;
    let key: [u8; 32] = hex::decode(key_hex.trim()).ok()?.as_slice().try_into().ok()?;
    Some((endpoint, key))
}

/// Push this device's chain to one host, preferring a LAN-direct dial and
/// falling back to the zero-trust relay when the host has no LAN-reachable
/// endpoint (or every LAN dial fails). [`plan_routes`] orders the attempts:
/// each known endpoint as a [`Route::Direct`], then a [`Route::Relay`] iff a
/// client relay is configured. On each route we run the Noise `IK` handshake
/// keyed by the host's stored transport static — end-to-end even over the relay,
/// which only forwards opaque `RelayData` and stays blind — present the signed
/// grant, then serve the chain while the host pulls + verifies + fast-forwards.
/// A dial/handshake/grant failure falls through to the next route; once serving
/// begins the result is returned (a mid-serve error is not retried elsewhere).
fn push_to_host(
    local: &LocalDevice,
    host: &RingEntry,
    announce: &TipAnnounce,
    grant: &ReplicaGrant,
    garden_root: &std::path::Path,
    state_root: Option<&std::path::Path>,
    relay_client: Option<&(String, [u8; 32])>,
) -> Result<ServeSummary, String> {
    let routes = plan_routes(host, relay_client.is_some());
    if routes.is_empty() {
        return Err("no route to host (no LAN endpoint, no relay)".to_string());
    }
    let mut last_err = "no route to host".to_string();
    for route in &routes {
        match route {
            Route::Direct(endpoint) => match dial_direct(local, host, endpoint) {
                Ok(mut session) => {
                    if let Err(e) = session.send_frame(&Frame::replica_grant(grant.clone())) {
                        last_err = format!("send grant (direct {endpoint}): {e}");
                        continue;
                    }
                    return serve_chain(&mut session, announce, garden_root, state_root);
                }
                Err(e) => {
                    last_err = e;
                    continue;
                }
            },
            Route::Relay => {
                // `plan_routes` only emits `Relay` when `relay_client.is_some()`.
                let (relay_endpoint, relay_static) =
                    relay_client.expect("relay route planned without a relay client");
                match dial_relay(local, host, relay_endpoint, relay_static) {
                    Ok(mut session) => {
                        if let Err(e) = session.send_frame(&Frame::replica_grant(grant.clone())) {
                            last_err = format!("send grant (relay {relay_endpoint}): {e}");
                            continue;
                        }
                        return serve_chain(&mut session, announce, garden_root, state_root);
                    }
                    Err(e) => {
                        last_err = e;
                        continue;
                    }
                }
            }
        }
    }
    Err(last_err)
}

/// Dial a host's LAN endpoint and run the Noise `IK` initiator handshake keyed
/// by the host's stored transport static. Resolve/connect/handshake failures are
/// returned as a message so the caller can fall through to the next route.
fn dial_direct(
    local: &LocalDevice,
    host: &RingEntry,
    endpoint: &str,
) -> Result<NoiseSession<TcpStream>, String> {
    let addr = endpoint
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| format!("could not resolve {endpoint}"))?;
    let stream = TcpStream::connect_timeout(&addr, PUSH_DIAL_TIMEOUT)
        .map_err(|e| format!("connect {endpoint}: {e}"))?;
    let _ = stream.set_read_timeout(Some(PUSH_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PUSH_IO_TIMEOUT));
    ik_initiator(stream, &local.transport_secret, &host.transport_pubkey, &local.hello())
        .map_err(|e| format!("IK handshake {endpoint}: {e}"))
}

/// Dial the configured relay and run [`relay_connect`]: the outer IK to the
/// relay, then the **inner** end-to-end IK to `host` tunnelled over a
/// [`RelayStream`] of blind `RelayData` frames. The returned session is the
/// end-to-end one (keyed by the host's static, verified by the host) — the relay
/// holds none of its keys. Used only as the LAN-fallback route, so failures are
/// returned as a message.
fn dial_relay(
    local: &LocalDevice,
    host: &RingEntry,
    relay_endpoint: &str,
    relay_static: &[u8; 32],
) -> Result<NoiseSession<RelayStream<TcpStream>>, String> {
    let addr = relay_endpoint
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| format!("could not resolve relay {relay_endpoint}"))?;
    let stream = TcpStream::connect_timeout(&addr, PUSH_DIAL_TIMEOUT)
        .map_err(|e| format!("connect relay {relay_endpoint}: {e}"))?;
    let _ = stream.set_read_timeout(Some(PUSH_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PUSH_IO_TIMEOUT));
    relay_connect(stream, relay_static, local, &host.device_id, &host.transport_pubkey)
        .map_err(|e| format!("relay connect to {} via {relay_endpoint}: {e}", host.fingerprint()))
}

/// Serve this device's chain over an established (direct or relayed) session:
/// open a fresh read-only `Repo` handle, wrap it as a [`RepoSource`] with the
/// signed announce, and drive [`serve_replication`] while the host pulls +
/// verifies + fast-forwards. Generic over the stream so the same drive runs on
/// a LAN `TcpStream` or a relayed `RelayStream`.
fn serve_chain<S: std::io::Read + std::io::Write>(
    session: &mut NoiseSession<S>,
    announce: &TipAnnounce,
    garden_root: &std::path::Path,
    state_root: Option<&std::path::Path>,
) -> Result<ServeSummary, String> {
    let repo = Repo::open_with(garden_root, state_root).map_err(|e| format!("open repo: {e}"))?;
    let source = RepoSource::new(repo, announce.clone()).map_err(|e| format!("scope source: {e}"))?;
    serve_replication(session, &source).map_err(|e| e.to_string())
}

/// Announce on the LAN, returning the registered fullname (empty on failure).
/// Best-effort — announce needs real multicast (the manual smoke step).
fn announce_best_effort(svc: &ServiceDaemon, ad: &Advertisement) -> String {
    let instance = format!("softfig-{}", &ad.fingerprint()[..12.min(ad.fingerprint().len())]);
    let host = match primary_local_ip() {
        Some(ip) => {
            let addrs = [ip];
            match discovery::announce(svc, ad, &instance, &format!("{instance}.local."), &addrs) {
                Ok(fullname) => return fullname,
                Err(e) => {
                    eprintln!("keeperd: net: mDNS announce failed ({e}); browse-only");
                    return String::new();
                }
            }
        }
        None => "no-local-ip",
    };
    eprintln!("keeperd: net: could not determine a local IP ({host}); mDNS announce skipped");
    String::new()
}

/// Best-effort primary LAN IP via a connected (but unsent) UDP socket to the
/// mDNS multicast group — sets the local address to the default egress
/// interface without needing any internet route. `None` ⇒ skip announce.
fn primary_local_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("224.0.0.251:5353").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_unspecified() {
        None
    } else {
        Some(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The relay host-leg test drives the sequential driver directly (a
    // `RelayStream` can't split); production LAN ingest uses the pipelined one.
    use softfig_net::pull_replication;

    fn id_bytes(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn fp_hex(seed: u8) -> String {
        hex::encode(id_bytes(seed))
    }

    /// A ring holding the given device-id seeds. Attestation is irrelevant here
    /// (`upsert` does not verify), so the rows are built directly.
    fn ring_with(seeds: &[u8]) -> Ring {
        let mut ring = Ring::default();
        for &s in seeds {
            ring.upsert(RingEntry {
                device_id: id_bytes(s),
                name: format!("peer-{s}"),
                transport_pubkey: [0u8; 32],
                endpoints: vec![],
                attestation: [0u8; 64],
                paired_at: 1,
            });
        }
        ring
    }

    fn entry(name: Option<&str>, last_seen: Instant) -> DiscoveredEntry {
        DiscoveredEntry {
            name: name.map(str::to_string),
            endpoints: vec!["192.168.1.9:9100".into()],
            paired: false,
            last_seen,
        }
    }

    #[test]
    fn discover_list_filters_self_ring_and_stale() {
        let me = fp_hex(1);
        let paired = fp_hex(2);
        let nearby = fp_hex(3);
        let stale = fp_hex(4);

        // `base` is "real now"; `now` is far enough ahead that a `base`-stamped
        // sighting is past the TTL while `now`-stamped ones are fresh. Built
        // additively so the test never underflows the monotonic clock.
        let base = Instant::now();
        let now = base + DISCOVERY_TTL * 2;

        let ring = ring_with(&[2]); // the `paired` device is in our ring

        let mut cache = HashMap::new();
        cache.insert(me.clone(), entry(Some("self"), now));
        cache.insert(paired.clone(), entry(Some("tablet"), now));
        cache.insert(nearby.clone(), entry(Some("laptop"), now));
        cache.insert(stale.clone(), entry(Some("ghost"), base));

        let list = build_discover_list(&cache, &ring, &me, now);

        // Only the fresh, unpaired, non-self device survives.
        assert_eq!(list.len(), 1, "got {list:?}");
        assert_eq!(list[0].fingerprint, nearby);
        assert_eq!(list[0].name.as_deref(), Some("laptop"));
        assert_eq!(list[0].endpoint.as_deref(), Some("192.168.1.9:9100"));
        assert_eq!(list[0].last_seen_secs, 0);
    }

    #[test]
    fn discover_list_sorts_by_name_then_fingerprint() {
        let now = Instant::now();
        let mut cache = HashMap::new();
        // `apple` < `banana`; the unnamed one sorts first (empty name) but after
        // by fingerprint among unnamed.
        cache.insert(fp_hex(20), entry(Some("banana"), now));
        cache.insert(fp_hex(21), entry(Some("apple"), now));
        cache.insert(fp_hex(22), entry(None, now));

        let list = build_discover_list(&cache, &Ring::default(), &fp_hex(99), now);
        let names: Vec<_> = list.iter().map(|d| d.name.clone()).collect();
        assert_eq!(
            names,
            vec![None, Some("apple".into()), Some("banana".into())]
        );
    }

    // --- slice 1: event-driven replica push signal ---------------------------

    /// A commit signalled while the push loop is parked must cut its interval
    /// sleep short — the whole point of slice 1 (push fires event-driven, not on
    /// the ~20s reconcile poll).
    #[test]
    fn replica_signal_commit_wakes_before_the_reconcile_interval() {
        let signal = Arc::new(ReplicaSignal::default());
        let waiter = {
            let signal = signal.clone();
            thread::spawn(move || {
                let start = Instant::now();
                // Park for a full reconcile interval; a commit must cut it short.
                let woke = signal.wait_for_commit(REPLICA_RECONCILE_INTERVAL);
                (woke, start.elapsed())
            })
        };
        thread::sleep(Duration::from_millis(50)); // let the waiter park
        signal.signal_commit();
        let (woke, elapsed) = waiter.join().unwrap();
        assert!(woke, "commit signal should wake the parked push loop");
        assert!(
            elapsed < REPLICA_RECONCILE_INTERVAL / 2,
            "woke after {elapsed:?} — not event-driven"
        );
    }

    /// Without a commit the wait falls back to the interval (the offline
    /// catch-up path) and reports a timeout, not a spurious wake.
    #[test]
    fn replica_signal_falls_back_to_the_interval_without_a_commit() {
        let signal = ReplicaSignal::default();
        let start = Instant::now();
        let woke = signal.wait_for_commit(Duration::from_millis(80));
        assert!(!woke, "no commit → should time out, not wake");
        assert!(start.elapsed() >= Duration::from_millis(70));
    }

    /// A commit signalled just before the loop parks must not be lost, and the
    /// flag drains so the next wait times out normally.
    #[test]
    fn replica_signal_commit_before_wait_is_not_lost() {
        let signal = ReplicaSignal::default();
        signal.signal_commit();
        assert!(
            signal.wait_for_commit(Duration::from_millis(0)),
            "a commit set before waiting must still wake"
        );
        assert!(
            !signal.wait_for_commit(Duration::from_millis(20)),
            "the flag should have drained on the first wait"
        );
    }

    /// Shutdown wakes a parked loop promptly (returns `false`, not a commit), so
    /// `NetRuntime::drop` doesn't block on a full interval before joining.
    #[test]
    fn replica_signal_stop_wakes_the_waiter_for_shutdown() {
        let signal = Arc::new(ReplicaSignal::default());
        let waiter = {
            let signal = signal.clone();
            thread::spawn(move || {
                let start = Instant::now();
                let woke = signal.wait_for_commit(REPLICA_RECONCILE_INTERVAL);
                (woke, start.elapsed())
            })
        };
        thread::sleep(Duration::from_millis(50));
        signal.signal_stop();
        let (woke, elapsed) = waiter.join().unwrap();
        assert!(!woke, "stop wakes the waiter but is not a commit");
        assert!(
            elapsed < REPLICA_RECONCILE_INTERVAL / 2,
            "stop should wake promptly, took {elapsed:?}"
        );
    }

    // --- Slice 2: relayed off-LAN push -------------------------------------

    /// A synthetic transport device (Ed25519 id + X25519 static + self-
    /// attestation) plus the ring row a peer stores for it — mirrors the
    /// `relay_tcp.rs` harness. Its ring row has no LAN endpoint.
    fn transport_device(id_seed: u8, tk_seed: u8, name: &str) -> (LocalDevice, RingEntry) {
        use ed25519_dalek::{Signer, SigningKey};
        let id = SigningKey::from_bytes(&[id_seed; 32]);
        let transport_secret = [tk_seed; 32];
        let transport_pubkey =
            x25519_dalek::x25519(transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        let attestation = id
            .sign(&static_attestation_message(&transport_pubkey))
            .to_bytes();
        let local = LocalDevice {
            transport_secret,
            device_id: id.verifying_key().to_bytes(),
            device_name: name.into(),
            static_attestation: attestation,
        };
        let entry = RingEntry {
            device_id: local.device_id,
            name: name.into(),
            transport_pubkey,
            endpoints: vec![],
            attestation,
            paired_at: 1,
        };
        (local, entry)
    }

    /// The ring row a peer stores for a `LocalDevice` (e.g. an owner built from a
    /// real vault session) — its attested transport static, no LAN endpoint.
    fn ring_entry_for(local: &LocalDevice) -> RingEntry {
        let transport_pubkey =
            x25519_dalek::x25519(local.transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        RingEntry {
            device_id: local.device_id,
            name: local.device_name.clone(),
            transport_pubkey,
            endpoints: vec![],
            attestation: local.static_attestation,
            paired_at: 1,
        }
    }

    #[test]
    fn relay_client_config_parses_only_a_complete_hex_target() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = KeeperConfig::new(tmp.path());
        // Unset by default → no relay fallback.
        assert!(relay_client_config(&cfg).is_none());
        // Endpoint alone is incomplete (no key).
        cfg.relay.endpoint = Some("relay.example:9301".into());
        assert!(relay_client_config(&cfg).is_none());
        // A key that is not 32 bytes is rejected.
        cfg.relay.static_key = Some("abcd".into());
        assert!(relay_client_config(&cfg).is_none());
        // A full 32-byte hex key parses into a dial target.
        let key = [7u8; 32];
        cfg.relay.static_key = Some(hex::encode(key));
        assert_eq!(
            relay_client_config(&cfg),
            Some(("relay.example:9301".to_string(), key))
        );
    }

    /// End-to-end: an owner whose granted host has **no LAN endpoint** pushes its
    /// signed chain through the blind relay (the `push_to_host` relay-fallback
    /// route), and the host mirrors it fast-forward-only + fsck-clean. Proves the
    /// relay leg carries a full backfill without changing the verified-mirror
    /// semantics; the relay only ever forwards opaque `RelayData` (its `splice`
    /// forwards nothing else — see `relay_tcp.rs`).
    #[test]
    fn push_to_host_falls_back_to_the_relay_when_no_lan_endpoint() {
        use softfig_store::{Db, ObjectStore, StorePaths};
        use softfig_vault::{params::VaultParams, Vault};

        // --- Owner: a real garden (vault + signed chain). ---
        let owner_tmp = tempfile::tempdir().unwrap();
        let garden = owner_tmp.path().to_path_buf();
        let mut params = VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let (_v, session, _r) =
            Vault::init_with_params(&garden, b"correct horse battery staple", params).unwrap();
        let (mut repo, _genesis) = Repo::init(&garden, &session).unwrap();

        let mut commit = |rel: &str, body: &str| -> Hash {
            let p = garden.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, body).unwrap();
            let intent = Intent::new("manual_edit", serde_json::json!({ "path": rel })).unwrap();
            repo.commit_workdir(&session, intent).unwrap()
        };
        commit("a.md", "alpha");
        commit("dir/b.md", "beta");
        let tip = commit("dir/c.md", "gamma");

        let announce = replica::build_announce(&repo, &session).unwrap();
        let owner_ld = build_local_device(&session, "owner".into());
        let owner_entry = ring_entry_for(&owner_ld);

        // --- Host: a synthetic backup device, no LAN endpoint → relay-only. ---
        let (host_ld, host_entry) = transport_device(3, 4, "host");
        let grant = replica::mint_grant(&host_entry.device_id, &announce.chain_id, &session);

        // --- Relay: blind, ring-authorized (owner + host are members). ---
        let (relay_ld, _relay_entry) = transport_device(100, 101, "relay");
        let relay_static =
            x25519_dalek::x25519(relay_ld.transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        let mut ring = Ring::default();
        ring.upsert(owner_entry);
        ring.upsert(host_entry.clone());
        let relay = Relay::new(&relay_ld, ring);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();
        {
            let relay = Arc::clone(&relay);
            thread::spawn(move || {
                let _ = softfig_net::relay::run(relay, listener);
            });
        }

        // --- Host leg: register at the relay, then mirror the pushed chain
        //     exactly as `serve_replica_ingest` does (verify grant, then pull). ---
        let replica_root = tempfile::tempdir().unwrap();
        let replica_root_path = replica_root.path().to_path_buf();
        let owner_device_id = owner_ld.device_id;
        let (tx, rx) = std::sync::mpsc::channel();
        let host_thread = {
            let relay_addr = relay_addr.clone();
            thread::spawn(move || {
                let conn = TcpStream::connect(&relay_addr).expect("host connect relay");
                let _ = conn.set_read_timeout(Some(Duration::from_secs(15)));
                let _ = conn.set_write_timeout(Some(Duration::from_secs(15)));
                let mut session = match softfig_net::relay::relay_accept(conn, &relay_static, &host_ld)
                {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tx.send(Err(format!("relay_accept: {e}")));
                        return;
                    }
                };
                let grant = match session.recv_frame().map(|f| f.kind) {
                    Ok(Some(frame::Kind::ReplicaGrant(g))) => g,
                    other => {
                        let _ = tx.send(Err(format!("first frame not a grant: {other:?}")));
                        return;
                    }
                };
                if !verify_grant(&grant, &owner_device_id, &host_ld.device_id) {
                    let _ = tx.send(Err("grant did not verify".into()));
                    return;
                }
                let mut mirror = MirrorStore::open_or_create(
                    &replica_root_path,
                    &owner_device_id,
                    "owner",
                    &grant.chain_id,
                )
                .unwrap();
                let result = pull_replication(&mut session, &mut mirror).map_err(|e| e.to_string());
                drop(mirror);
                let _ = tx.send(result);
            })
        };

        // Don't push until the host has parked at the relay.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !relay.is_registered(&host_entry.device_id) {
            assert!(Instant::now() < deadline, "host never registered at the relay");
            thread::sleep(Duration::from_millis(10));
        }

        // --- Owner push: host has no LAN endpoint, so `push_to_host` must take
        //     the relay route and serve the whole chain end-to-end. ---
        let relay_client = (relay_addr, relay_static);
        let served = push_to_host(
            &owner_ld,
            &host_entry,
            &announce,
            &grant,
            &garden,
            None,
            Some(&relay_client),
        )
        .expect("relayed push should succeed over the relay route");
        assert!(
            served.commits_served > 0,
            "owner served commits over the relay, got {}",
            served.commits_served
        );

        // Host mirrored the whole chain (genesis + 3 content commits) over relay.
        let pull = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("host result")
            .expect("host pull over the relay");
        assert_eq!(pull.commits, 4, "genesis + three content commits");
        assert_eq!(pull.new_tip, Some(*tip.as_bytes()));
        host_thread.join().unwrap();

        // Fast-forward-only + fsck-clean: the relayed transport didn't change the
        // verified-mirror semantics.
        let dir = replica::mirror_dir(replica_root.path(), &owner_ld.device_id);
        let paths = StorePaths::with_state_root(&dir, &dir);
        let db = Db::open(&paths).unwrap();
        let objects = ObjectStore::new(paths);
        let report = softfig_vcs::fsck(&db, &objects).unwrap();
        assert!(
            report.ok(),
            "relayed mirror not fsck-clean: {:?}",
            report.problems
        );
        assert_eq!(report.commits_checked, 4);
    }
}
