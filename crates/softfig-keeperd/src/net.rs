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
use softfig_net::ceremony::{
    nonce_is_fresh, run_ceremony, Ceremony, CeremonyOutcome, SharedKey,
};
use softfig_net::discovery::{self, Advertisement};
use softfig_net::endpoint_cache::{endpoint_cache_path, EndpointCache};
use softfig_net::pairing::{pair_initiator, pair_responder, LocalDevice, PendingPair};
use softfig_net::proto::{
    frame, DeviceStateAnnounce, Frame, ReplicaGrant, SharedChainPush, SharedKeyCommit,
    SharedKeyHandoff, TipAnnounce, TurnRequest, TurnRevoke, TurnYield,
};
use softfig_net::connect::{plan_routes, Route};
use softfig_net::relay::{relay_connect, Relay, RelayStream};
use softfig_net::ring::{ring_path, Ring, RingEntry, RING_FILE};
use softfig_net::transport::{ik_initiator, ik_responder, NoiseSession};
use softfig_net::{
    device_state_signing_bytes, pull_replication_pipelined, pull_subtree, serve_replication,
    shared_chain_push_signing_bytes, static_attestation_message, turn_request_signing_bytes,
    turn_revoke_signing_bytes,
    turn_yield_signing_bytes, verify_device_state_sig, verify_grant, verify_shared_chain_push_sig,
    verify_turn_request_sig, verify_turn_revoke_sig, verify_turn_yield_sig, DeviceState, LeaseEvent,
    LeaseScope, NetError, ServeSummary, WriteTurn,
};
use softfig_store::Hash;
use softfig_vault::VaultSession;
use softfig_vcs::{Intent, Repo};

use crate::actions::{
    apply_shared_pull, resolve_sync_conflict, ConflictResolution, ConflictSides, SharedPullInput,
    SharedPullOutcome, WorkTree,
};
use crate::ceremony::{
    assemble_member_set, persist_ceremony_outcome, rotate_shared_key, CeremonyLink,
    SessionTransport, VaultCeremonySigner,
};
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

/// M5e part 3a: how long after a local authoring write this device advertises
/// `OnlineActive` before decaying back to `OnlineIdle`. Because the flip is
/// re-evaluated on the reconcile tick ([`REPLICA_RECONCILE_INTERVAL`], ~20s),
/// the window is kept comfortably wider than the tick so a write is reliably
/// observed as active on the following tick and the active state spans a few
/// ticks — the same coarse-latency tolerance the lease poll already accepts. It
/// is the one tuning knob the activity-window design (vs a session attach/detach
/// verb) introduces.
pub(crate) const WRITE_ACTIVITY_WINDOW: Duration = Duration::from_secs(60);

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
                Some(owner) => serve_established(&daemon, local, &owner, ring, session),
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
/// us as a backup host (verify the grant, then mirror via `pull_replication`); a
/// `SharedKeyCommit` is a member initiating the M5d shared-key ceremony (serve
/// the responder role inline on this thread).
// `pub` + `#[doc(hidden)]` is a deliberate **test seam** (not general API): the
// m5e slice-002 loopback integration tests (`tests/m5e_shared_pull.rs`) drive
// the inbound shared-chain-push dispatch directly over a hand-built Noise session
// — the 2b-3 push/apply/re-push path is otherwise only reachable through the live
// net runtime. Same rationale for `serve_shared_subtree` / `build_shared_chain_push_frame`.
#[doc(hidden)]
pub fn serve_established(
    daemon: &Daemon,
    local: &LocalDevice,
    owner: &RingEntry,
    ring: &Arc<Mutex<Ring>>,
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
        Some(frame::Kind::SharedKeyCommit(commit)) => {
            serve_ceremony_responder(daemon, local, owner, ring, commit, session)
        }
        // M5e slice 001 part 2 — write-turn coordination gossip. Each is a
        // one-shot frame (the sender broadcast it; we apply it to our local view
        // and the session closes). Every one is signature-verified against its
        // claimed sender AND S-member-authorized against committed membership
        // before it touches the lease — the security spine the slice requires.
        Some(frame::Kind::DeviceStateAnnounce(a)) => {
            handle_device_state_announce(daemon, owner, a)
        }
        Some(frame::Kind::TurnRequest(req)) => {
            handle_turn_request(daemon, local, owner, ring, req)
        }
        Some(frame::Kind::TurnYield(y)) => handle_turn_yield(daemon, local, owner, ring, y),
        Some(frame::Kind::TurnRevoke(rv)) => handle_turn_revoke(daemon, local, owner, ring, rv),
        // M5e slice 002 part 2b — a chain S-member pushed a committed edit for us
        // to adopt. Unlike the one-shot gossip arms above, this SERVES the
        // sender's `serve_replication` on the same session: authorize, pull the
        // edit's tree closure into the live store, re-author it locally.
        Some(frame::Kind::SharedChainPush(p)) => {
            serve_shared_chain_push(daemon, local, owner, ring, p, session)
        }
        // Anything else ends the session cleanly.
        _ => {}
    }
}

// --- M5e write-turn coordination (inbound handlers) -------------------------
//
// The turn protocol is gossip, not request-reply: an active member broadcasts a
// signed `TurnRequest` to the chain's S-members; the holder broadcasts a signed
// `TurnYield` (the go-ahead) at its commit boundary; any member broadcasts a
// signed `TurnRevoke` when a holder's lease expires; every online member
// broadcasts a signed `DeviceStateAnnounce` on a state change. These handlers are
// the RECEIVE half — apply one gossiped frame to this device's local view of the
// lease (the pure `softfig_net::WriteTurn` state machine, part 1) after verifying
// its signature and authorizing its sender against committed S-membership. The
// SEND half (broadcasting our own request/yield/revoke/announce by dialing the
// chain's members) is the outbound driver in part 2b, mirroring
// [`ceremony_with_host`]. Splitting receive from send keeps the security spine —
// "membership-authorize every message" — landable and testable on its own.

/// A peer's most-recently-announced coordination state, stored in
/// [`DaemonInner::peer_states`]. Ordered by `seq` (per-device monotonic) so a
/// stale announce never overwrites a fresh one.
#[derive(Debug, Clone, Copy)]
pub struct PeerAnnounce {
    pub state: DeviceState,
    pub unlocked: bool,
    pub seq: u64,
}

/// Wall-clock seconds — the lease state machine's time base. `WriteTurn` never
/// reads the clock itself (every transition takes `now`), so the daemon stamps it
/// here at handler time. Seconds are the same unit as the signed edit timestamps
/// the conflict fallback (slice 003) compares.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The daemon S-membership authorization for an inbound turn message, pulled out
/// pure so it is unit-testable without a live session (the same "detection half"
/// shape as [`chains_awaiting_key`] / [`should_initiate_now`]): the chain must be
/// a committed shared subtree AND `sender` must be among its resolved members.
/// This is the daemon half of "a forged turn-request from a non-member is
/// rejected" — the signature (verified separately) proves *who* signed; this
/// proves they are entitled to the chain's turn.
fn turn_sender_is_member(
    membership: &softfig_vcs::SharedSubtreesConfig,
    chain: &str,
    members: &[[u8; 32]],
    sender: &[u8; 32],
) -> bool {
    membership.subtrees.iter().any(|r| r.ref_name == chain) && members.contains(sender)
}

/// Read committed state and resolve `(membership, S-member set)` for `chain`. The
/// member set is derived from committed/ring state, **never the wire**: a keyed
/// chain's members are its committed transcript's; an unkeyed chain (pre-ceremony)
/// falls back to the current ring (`assemble_member_set`) — in v1 point-to-point
/// the two coincide. `None` (and a log) when the daemon is locked mid-serve or
/// committed state can't be read; the sender simply retries on its next tick.
fn resolve_chain_members(
    daemon: &Daemon,
    ring: &Arc<Mutex<Ring>>,
    local: &LocalDevice,
    chain: &str,
) -> Option<(softfig_vcs::SharedSubtreesConfig, Vec<[u8; 32]>)> {
    // Ring member set first, off the daemon mutex — never nest `ring` inside
    // `inner` (the ceremony responder keeps this same lock ordering).
    let ring_members = {
        let ring = ring.lock().unwrap();
        assemble_member_set(&ring, local.device_id)
    };
    let inner = daemon.inner.lock().unwrap();
    let (Some(session), Some(repo)) = (inner.session.as_ref(), inner.repo.as_ref()) else {
        return None; // locked mid-serve
    };
    let membership =
        match crate::handlers::read_committed_shared_subtrees_for_mutation(repo, session) {
            Ok(m) => m,
            Err((_, e)) => {
                eprintln!("keeperd: net: turn for {chain}: cannot read committed membership: {e}");
                return None;
            }
        };
    let members = chain_members(&membership, &ring_members, repo, session, chain);
    Some((membership, members))
}

/// The S-member device-id set for `chain`: a keyed chain's are its committed
/// ceremony transcript's members; an unkeyed chain (pre-ceremony) falls back to
/// `ring_members` — the current ring, which in v1 point-to-point coincides. A
/// keyed row whose transcript can't be read yet also falls back to the ring
/// rather than dropping to empty (a read glitch must not silently disenfranchise
/// the chain). Shared by the inbound authorization ([`resolve_chain_members`])
/// and the outbound fan-out ([`reconcile_write_turns`]) so both derive the same
/// set from the same committed state.
fn chain_members(
    membership: &softfig_vcs::SharedSubtreesConfig,
    ring_members: &[[u8; 32]],
    repo: &Repo,
    session: &VaultSession,
    chain: &str,
) -> Vec<[u8; 32]> {
    match membership
        .subtrees
        .iter()
        .find(|r| r.ref_name == chain)
        .and_then(|r| r.key_id.as_deref())
    {
        Some(key_id) => crate::handlers::read_committed_transcript(repo, session, key_id)
            .ok()
            .flatten()
            .map(|t| t.members.iter().map(|m| m.device_id).collect())
            .unwrap_or_else(|| ring_members.to_vec()),
        None => ring_members.to_vec(),
    }
}

/// Apply an inbound `DeviceStateAnnounce`: verify the signature, confirm the
/// authenticated peer is announcing its own id, and record the state if it is
/// fresher (`seq` strictly greater) than what we last saw for that device.
fn handle_device_state_announce(daemon: &Daemon, owner: &RingEntry, a: DeviceStateAnnounce) {
    let Ok(dev) = <[u8; 32]>::try_from(a.device_id.as_slice()) else {
        eprintln!("keeperd: net: device-state-announce device_id is not 32 bytes");
        return;
    };
    // v1 point-to-point: the authenticated session peer speaks only for itself.
    if dev != owner.device_id {
        eprintln!("keeperd: net: device-state-announce device_id != authenticated peer; ignoring");
        return;
    }
    let Some(state) = DeviceState::from_u32(a.state) else {
        eprintln!(
            "keeperd: net: device-state-announce from {} has unknown state {}; ignoring",
            hex::encode(dev),
            a.state
        );
        return;
    };
    if !verify_device_state_sig(&dev, state, a.unlocked, a.seq, &a.signature) {
        eprintln!("keeperd: net: device-state-announce signature invalid; ignoring");
        return;
    }
    let mut inner = daemon.inner.lock().unwrap();
    // Monotonic per device: a `seq` at or below the stored one is a replay or a
    // reordered stale frame — drop it, never let it clobber a fresher state.
    if inner.peer_states.get(&dev).is_some_and(|prev| prev.seq >= a.seq) {
        return;
    }
    inner.peer_states.insert(
        dev,
        PeerAnnounce {
            state,
            unlocked: a.unlocked,
            seq: a.seq,
        },
    );
    eprintln!(
        "keeperd: net: device-state from {}: {state:?} unlocked={} seq={}",
        hex::encode(dev),
        a.unlocked,
        a.seq
    );
}

/// Apply an inbound `TurnRequest`: verify the signature, authorize the requester
/// as an S-member of the chain, then record the request in our local lease view
/// (FIFO by `(seq, device_id)`). Granting the turn to a waiter — broadcasting the
/// go-ahead `TurnYield` when we are the holder quiescing at a commit boundary —
/// is the outbound driver (part 2b); this handler only records the request.
fn handle_turn_request(
    daemon: &Daemon,
    local: &LocalDevice,
    owner: &RingEntry,
    ring: &Arc<Mutex<Ring>>,
    req: TurnRequest,
) {
    let chain = String::from_utf8_lossy(&req.chain_id).into_owned();
    let Ok(sender) = <[u8; 32]>::try_from(req.device_id.as_slice()) else {
        eprintln!("keeperd: net: turn-request device_id is not 32 bytes");
        return;
    };
    let Some(scope) = LeaseScope::from_u32(req.scope) else {
        eprintln!(
            "keeperd: net: turn-request for {chain} has unknown scope {}; rejecting",
            req.scope
        );
        return;
    };
    if sender != owner.device_id {
        eprintln!("keeperd: net: turn-request device_id != authenticated peer; rejecting");
        return;
    }
    if !verify_turn_request_sig(&req.chain_id, &sender, req.seq, scope, &req.signature) {
        eprintln!("keeperd: net: turn-request for {chain} signature invalid; rejecting");
        return;
    }
    let Some((membership, members)) = resolve_chain_members(daemon, ring, local, &chain) else {
        return;
    };
    if !turn_sender_is_member(&membership, &chain, &members, &sender) {
        eprintln!(
            "keeperd: net: turn-request for {chain} from non-member {}; rejecting",
            hex::encode(sender)
        );
        return;
    }
    let mut inner = daemon.inner.lock().unwrap();
    inner
        .write_turns
        .entry(chain.clone())
        .or_insert_with(WriteTurn::whole_subtree)
        .request(sender, req.seq);
    eprintln!(
        "keeperd: net: turn-request for {chain} from {} queued (seq {})",
        hex::encode(sender),
        req.seq
    );
}

/// Apply an inbound `TurnYield`: verify the signature, authorize the yielder as
/// an S-member, then converge our local view onto the named `grantee` under a
/// fresh epoch (idempotent when it already holds).
fn handle_turn_yield(
    daemon: &Daemon,
    local: &LocalDevice,
    owner: &RingEntry,
    ring: &Arc<Mutex<Ring>>,
    y: TurnYield,
) {
    let chain = String::from_utf8_lossy(&y.chain_id).into_owned();
    let Ok(yielder) = <[u8; 32]>::try_from(y.device_id.as_slice()) else {
        eprintln!("keeperd: net: turn-yield device_id is not 32 bytes");
        return;
    };
    let Ok(grantee) = <[u8; 32]>::try_from(y.grantee.as_slice()) else {
        eprintln!("keeperd: net: turn-yield grantee is not 32 bytes");
        return;
    };
    if yielder != owner.device_id {
        eprintln!("keeperd: net: turn-yield device_id != authenticated peer; rejecting");
        return;
    }
    if !verify_turn_yield_sig(&y.chain_id, &yielder, &grantee, y.seq, &y.signature) {
        eprintln!("keeperd: net: turn-yield for {chain} signature invalid; rejecting");
        return;
    }
    let Some((membership, members)) = resolve_chain_members(daemon, ring, local, &chain) else {
        return;
    };
    if !turn_sender_is_member(&membership, &chain, &members, &yielder) {
        eprintln!(
            "keeperd: net: turn-yield for {chain} from non-member {}; rejecting",
            hex::encode(yielder)
        );
        return;
    }
    let now = now_secs();
    let mut inner = daemon.inner.lock().unwrap();
    if let Some(epoch) = inner
        .write_turns
        .entry(chain.clone())
        .or_insert_with(WriteTurn::whole_subtree)
        .apply_yield(grantee, now)
    {
        eprintln!(
            "keeperd: net: turn for {chain} granted to {} (epoch {epoch})",
            hex::encode(grantee)
        );
    }
}

/// Apply an inbound `TurnRevoke`: verify the signature, authorize the revoker as
/// an S-member, then clear the holder — but only when it matches both the named
/// device and the exact lease `epoch` (a stale revoke can never kill a fresh
/// grant). A revoke for a chain we hold no view of is a safe no-op.
fn handle_turn_revoke(
    daemon: &Daemon,
    local: &LocalDevice,
    owner: &RingEntry,
    ring: &Arc<Mutex<Ring>>,
    rv: TurnRevoke,
) {
    let chain = String::from_utf8_lossy(&rv.chain_id).into_owned();
    let Ok(revoker) = <[u8; 32]>::try_from(rv.device_id.as_slice()) else {
        eprintln!("keeperd: net: turn-revoke device_id is not 32 bytes");
        return;
    };
    let Ok(revoked) = <[u8; 32]>::try_from(rv.revoked.as_slice()) else {
        eprintln!("keeperd: net: turn-revoke revoked is not 32 bytes");
        return;
    };
    if revoker != owner.device_id {
        eprintln!("keeperd: net: turn-revoke device_id != authenticated peer; rejecting");
        return;
    }
    if !verify_turn_revoke_sig(&rv.chain_id, &revoker, &revoked, rv.epoch, &rv.signature) {
        eprintln!("keeperd: net: turn-revoke for {chain} signature invalid; rejecting");
        return;
    }
    let Some((membership, members)) = resolve_chain_members(daemon, ring, local, &chain) else {
        return;
    };
    if !turn_sender_is_member(&membership, &chain, &members, &revoker) {
        eprintln!(
            "keeperd: net: turn-revoke for {chain} from non-member {}; rejecting",
            hex::encode(revoker)
        );
        return;
    }
    let mut inner = daemon.inner.lock().unwrap();
    if let Some(turn) = inner.write_turns.get_mut(&chain) {
        if turn.apply_revoke(&revoked, rv.epoch) {
            eprintln!(
                "keeperd: net: turn for {chain} revoked (holder {} epoch {})",
                hex::encode(revoked),
                rv.epoch
            );
        }
    }
}

// --- M5e write-turn coordination (outbound driver + expiry poll) ------------
//
// The SEND half of the gossip protocol, mirroring the ceremony/replica push:
// this device signs its own coordination frames with the vault identity and fans
// them to the chain's reachable S-members (self excluded), LAN-direct-first with
// the relay as fallback — exactly [`push_to_host`]'s route policy. Turn gossip is
// one-shot and fire-and-forget: dial, send, drop the session; the receiver's
// inbound handler applies it after re-verifying the signature + S-membership. All
// four triggers land here — a device-state change (Offline→OnlineIdle on unlock)
// and an expiry-revoke (the poll loop), plus (part 3b-ii) the `TurnRequest` /
// `TurnYield` broadcasts at the shared-chain commit boundary: those two decide
// under the daemon lock at the boundary ([`decide_turn_gate`] /
// [`gate_shared_chain_commit`]), queue a [`PendingTurnBroadcast`], and are
// signed + fanned off-lock by [`reconcile_write_turns`] on its commit-driven
// wake — never as dead code, always with their call site.

/// A coordination frame the shared-chain commit boundary decided to send,
/// queued on [`DaemonInner::pending_turn_broadcasts`] under the daemon lock for
/// [`reconcile_write_turns`] to resolve S-members + sign + fan off-lock (the
/// expiry-revoke discipline). Carries only the plaintext fields; the signature
/// is minted at fan time from the live vault session.
#[derive(Debug)]
pub enum PendingTurnBroadcast {
    /// A local shared-chain write wants the turn — fan a signed `TurnRequest` so
    /// the current holder yields at its next commit boundary (and peers queue
    /// behind us rather than double-granting a free turn).
    Request { chain: String, seq: u64 },
    /// We held the turn, committed, and a peer is queued behind us — fan a signed
    /// `TurnYield` naming the FIFO winner `grantee` (stamping the `seq` it
    /// requested with) so it may write next.
    Yield {
        chain: String,
        grantee: [u8; 32],
        seq: u64,
    },
}

/// What the shared-chain commit boundary must do for one chain, decided from +
/// applied to our local lease view by [`decide_turn_gate`].
#[derive(Debug, PartialEq, Eq)]
enum TurnGateAction {
    /// We already hold the turn and no peer is queued — advance the ref, keep the
    /// turn (a bursty local writer holds its lease across commits). No broadcast.
    Proceed,
    /// A free/expired turn we just self-acquired (uncontested) — advance the ref
    /// and announce the claim with a `TurnRequest` so peers converge on us as the
    /// active writer instead of double-granting.
    ProceedRequest { seq: u64 },
    /// We hold the turn, are flushing this commit, and a peer is queued — advance
    /// the ref, then yield at this boundary: released locally + a `TurnYield`
    /// names the FIFO winner.
    ProceedYield { grantee: [u8; 32], seq: u64 },
    /// A peer holds the turn — quiesce: do NOT advance the ref; request the turn
    /// so the holder yields at its next boundary. The staged write stays in the
    /// FUSE overlay and lands on a later boundary once we are granted the turn
    /// (the watcher's requeue-retry drives that; reads never reach here).
    Defer { seq: u64 },
}

/// Decide + apply the write-turn gate at a shared-chain commit boundary, over
/// our local lease `turn` for that chain. Pure over the state machine (`local` /
/// `seq` / `now` are passed, no IO) so the "holder yields only at a commit
/// boundary" policy is unit-tested headlessly, mirroring [`poll_expiries`].
///
/// Three shapes (self-acquire keeps a solo device from deadlocking on its own
/// free turn):
/// - **We hold it.** Advance. If a peer is queued, yield here (finish our commit,
///   then hand the turn on) — the [`TurnGateAction::ProceedYield`] path the slice
///   test exercises. Else keep the lease ([`TurnGateAction::Proceed`]).
/// - **Free / expired turn.** [`WriteTurn::request`] + [`WriteTurn::poll`] grants
///   the deterministic FIFO winner; if that is us we advance + announce
///   ([`TurnGateAction::ProceedRequest`]). (A revoke `poll` may consume is not
///   re-broadcast here — peers self-expire on the same lease TTL; the reconcile
///   tick is the revoke path.)
/// - **A peer won / holds it.** Quiesce: request the turn and defer the ref
///   advance ([`TurnGateAction::Defer`]).
fn decide_turn_gate(turn: &mut WriteTurn, local: &[u8; 32], seq: u64, now: i64) -> TurnGateAction {
    if turn.is_held_by(local) {
        if let Some((grantee, grantee_seq)) = turn.next_grant() {
            turn.release(local);
            return TurnGateAction::ProceedYield {
                grantee,
                seq: grantee_seq,
            };
        }
        return TurnGateAction::Proceed;
    }
    // We don't hold it: record our request and let the queue advance (a free or
    // just-expired turn is granted to the deterministic FIFO winner).
    turn.request(*local, seq);
    turn.poll(now);
    if turn.is_held_by(local) {
        TurnGateAction::ProceedRequest { seq }
    } else {
        TurnGateAction::Defer { seq }
    }
}

/// Consult + advance the write-turn at a shared-chain commit boundary, under the
/// daemon lock. Returns whether the shared-chain ref advance may proceed now;
/// queues any `TurnRequest`/`TurnYield` into [`DaemonInner::pending_turn_broadcasts`]
/// for [`reconcile_write_turns`] to sign + fan off-lock, and wakes that loop
/// (via `signal_commit`) so the frame goes out promptly rather than on the next
/// ~20 s tick.
///
/// **Fast-path proceed** when there is no mesh (`net` is down / no session): a
/// solo daemon has nothing to coordinate, so gating is a no-op and every
/// existing single-device commit path is byte-unchanged. Only a live net engages
/// the lease — and even then a chain with no reachable S-members resolves to an
/// empty fan (skipped), so the only real quiesce is a genuine peer contending.
pub(crate) fn gate_shared_chain_commit(inner: &mut DaemonInner, chain: &str) -> bool {
    if inner.net.is_none() {
        return true;
    }
    let Some(session) = inner.session.as_ref() else {
        return true;
    };
    let local_id = session.identity_pubkey().to_bytes();
    let now = now_secs();
    // Logical request-time for FIFO fairness = wall-clock seconds, the shared
    // time base across devices (and the unit the LWW conflict fallback compares).
    // Cross-device clock skew is the documented v1 open question, not this gate's.
    let seq = now.max(0) as u64;
    let turn = inner
        .write_turns
        .entry(chain.to_string())
        .or_insert_with(WriteTurn::whole_subtree);
    let action = decide_turn_gate(turn, &local_id, seq, now);
    let (proceed, broadcast) = match action {
        TurnGateAction::Proceed => (true, None),
        TurnGateAction::ProceedRequest { seq } => (
            true,
            Some(PendingTurnBroadcast::Request {
                chain: chain.to_string(),
                seq,
            }),
        ),
        TurnGateAction::ProceedYield { grantee, seq } => (
            true,
            Some(PendingTurnBroadcast::Yield {
                chain: chain.to_string(),
                grantee,
                seq,
            }),
        ),
        TurnGateAction::Defer { seq } => (
            false,
            Some(PendingTurnBroadcast::Request {
                chain: chain.to_string(),
                seq,
            }),
        ),
    };
    if let Some(b) = broadcast {
        inner.pending_turn_broadcasts.push(b);
        if let Some(net) = inner.net.as_ref() {
            net.signal_commit();
        }
    }
    proceed
}

/// Send one signed, one-shot coordination frame to a single ring peer,
/// best-effort. Mirrors [`push_to_host`]'s route policy — each known LAN endpoint
/// as a [`Route::Direct`], then a [`Route::Relay`] iff a client relay is
/// configured — but sends a single fire-and-forget frame instead of driving a
/// serve loop. A dial/send failure falls through to the next route; the last
/// error is returned for the caller to log.
fn send_turn_frame_to(
    local: &LocalDevice,
    host: &RingEntry,
    relay_client: Option<&(String, [u8; 32])>,
    frame: &Frame,
) -> Result<(), String> {
    let routes = plan_routes(host, relay_client.is_some());
    if routes.is_empty() {
        return Err("no route (no LAN endpoint, no relay)".to_string());
    }
    let mut last_err = "no route".to_string();
    for route in &routes {
        match route {
            Route::Direct(endpoint) => match dial_direct(local, host, endpoint) {
                Ok(mut session) => {
                    return session
                        .send_frame(frame)
                        .map_err(|e| format!("send (direct {endpoint}): {e}"));
                }
                Err(e) => {
                    last_err = e;
                    continue;
                }
            },
            Route::Relay => {
                let (relay_endpoint, relay_static) =
                    relay_client.expect("relay route planned without a relay client");
                match dial_relay(local, host, relay_endpoint, relay_static) {
                    Ok(mut session) => {
                        return session
                            .send_frame(frame)
                            .map_err(|e| format!("send (relay {relay_endpoint}): {e}"));
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

/// Fan one signed frame to every reachable target, best-effort; log each miss.
/// A dropped frame is only a delay — the lease re-derives under its TTL and the
/// periodic driver re-broadcasts — never a stuck turn, so a failed dial is logged
/// and the fan continues to the next peer.
fn fan_turn_frame(
    local: &LocalDevice,
    targets: &[RingEntry],
    relay_client: Option<&(String, [u8; 32])>,
    frame: &Frame,
    what: &str,
) {
    for host in targets {
        if let Err(e) = send_turn_frame_to(local, host, relay_client, frame) {
            eprintln!("keeperd: net: {what} to {} skipped: {e}", host.fingerprint());
        }
    }
}

/// The reachable ring peers to fan a chain's turn frame to: its `S`-members
/// minus this device, each with a viable route ([`plan_routes`]). Shared by the
/// expiry-revoke and the commit-boundary request/yield fan-outs so every turn
/// message targets the same set derived from the same committed membership. An
/// empty result ⇒ nothing to send (the caller skips the frame — e.g. a solo
/// device whose chain has no online peer).
#[allow(clippy::too_many_arguments)]
fn resolve_turn_targets(
    membership: &softfig_vcs::SharedSubtreesConfig,
    ring: &Ring,
    ring_members: &[[u8; 32]],
    repo: &Repo,
    session: &VaultSession,
    local_id: &[u8; 32],
    relay_available: bool,
    chain: &str,
) -> Vec<RingEntry> {
    let members = chain_members(membership, ring_members, repo, session, chain);
    members
        .iter()
        .filter(|id| *id != local_id)
        .filter_map(|id| ring.peers().iter().find(|p| &p.device_id == id).cloned())
        .filter(|host| !plan_routes(host, relay_available).is_empty())
        .collect()
}

/// Poll every chain's lease forward to `now`, returning the `(chain,
/// revoked_device, epoch)` of each lease that just expired — the daemon then
/// signs + fans a `TurnRevoke` for each. Pure over the map (the `now` is passed,
/// never read, and there is no IO) so the "silent holder → expiry → revoke"
/// slice test runs headlessly. [`LeaseEvent::Granted`] is intentionally dropped:
/// after a revoke every member re-derives the same deterministic FIFO winner
/// locally ([`WriteTurn::poll`]), so a grant needs no broadcast — only the
/// revoke, the crash/partition signal, is gossiped.
fn poll_expiries(
    write_turns: &mut HashMap<String, WriteTurn>,
    now: i64,
) -> Vec<(String, [u8; 32], u64)> {
    let mut revokes = Vec::new();
    let chains: Vec<String> = write_turns.keys().cloned().collect();
    for chain in chains {
        if let Some(turn) = write_turns.get_mut(&chain) {
            for ev in turn.poll(now) {
                if let LeaseEvent::Revoked { device_id, epoch } = ev {
                    revokes.push((chain.clone(), device_id, epoch));
                }
            }
        }
    }
    revokes
}

/// Derive this device's coordination state from recent local write activity:
/// `OnlineActive` while a local authoring write landed within
/// [`WRITE_ACTIVITY_WINDOW`], else `OnlineIdle`. Pure over its input (the elapsed
/// duration is passed, [`Instant::duration_since`] is saturating so there is no
/// clock IO or panic) so the part-3a activity-window flip is unit-tested
/// headlessly. Called only while unlocked; `Offline` is the locked floor, set by
/// the lifecycle, and is never derived here.
fn active_or_idle(since_last_write: Option<Duration>) -> DeviceState {
    match since_last_write {
        Some(elapsed) if elapsed < WRITE_ACTIVITY_WINDOW => DeviceState::OnlineActive,
        _ => DeviceState::OnlineIdle,
    }
}

/// Whether an **inbound** shared-chain apply must yield the write turn *before*
/// applying (M5e slice 002 part 3 — turn-ordering compose). The apply itself is
/// not a local write (part 1), so it never runs [`gate_shared_chain_commit`]; but
/// an **online-active** receiver that currently holds this chain's turn is mid-
/// authoring with the lease in hand, and applying a peer's edit under our own
/// held turn would race our next local commit against it. So at the receive
/// boundary such a holder yields the turn to the incoming writer first (released
/// locally + a `TurnYield` fanned so the mesh converges on that writer as the
/// current holder), then applies — the receive-side mirror of the commit-boundary
/// gate's [`TurnGateAction::ProceedYield`].
///
/// Returns `false` (apply immediately, no handshake) for every other case:
/// - an **online-idle** receiver — nothing is editing, so there is no local write
///   to race (`meta/spec-sync.md` §"Sync semantics": "online-idle members just
///   apply");
/// - an active receiver that does **not** hold the turn — its staged write is
///   already quiesced, gated behind the turn it lacks ([`TurnGateAction::Defer`]),
///   so no held lease can race the apply.
///
/// Pure over its lease view (mirrors [`decide_turn_gate`]) so the active-vs-idle
/// receive branch is unit-tested headlessly; the caller performs the release +
/// broadcast + `signal_commit` under the daemon lock.
fn active_receiver_must_yield(state: DeviceState, turn: &WriteTurn, local: &[u8; 32]) -> bool {
    state == DeviceState::OnlineActive && turn.is_held_by(local)
}

/// Sign and frame a `DeviceStateAnnounce` for `state` at `seq`. The `seq` bump
/// and the `device_state` write are the caller's (done under the lock); this only
/// signs + frames, so the unlock lift and the `OnlineIdle`↔`OnlineActive`
/// activity flip share one signing path. `unlocked` is always `true` here — the
/// reconcile pass runs only while unlocked (`Offline` is announced by nothing;
/// the net runtime is already gone by the time we lock).
fn build_device_state_announce(
    session: &VaultSession,
    local: &LocalDevice,
    state: DeviceState,
    seq: u64,
) -> Frame {
    let signature = session
        .sign(&device_state_signing_bytes(&local.device_id, state, true, seq))
        .to_bytes()
        .to_vec();
    Frame::device_state_announce(DeviceStateAnnounce {
        device_id: local.device_id.to_vec(),
        state: state.as_u32(),
        unlocked: true,
        seq,
        signature,
    })
}

/// One write-turn reconcile pass, run on the replica loop's tick (M5e slice 001
/// part 2b + 3a). Two outbound duties, both snapshotted under the daemon lock so
/// the network IO runs off the mutex (the ceremony/replica discipline):
///
/// 1. **Device-state announce.** Recompute this device's coordination state and
///    fan a signed [`DeviceStateAnnounce`] to every ring peer *only when it
///    changes* — a state-change trigger, not a periodic beacon. The first
///    post-unlock tick lifts `Offline`→`OnlineIdle` (the "I'm online" beacon);
///    later ticks flip `OnlineIdle`↔`OnlineActive` from the local-write activity
///    window ([`active_or_idle`], part 3a). A tick with no change sends nothing.
/// 2. **Expiry-revoke.** [`poll_expiries`] revokes any lease whose holder went
///    silent past its renew window (or hit the max-lease ceiling); each revoke is
///    signed and fanned to the chain's reachable S-members. This is the
///    crash/partition recovery path — without it one dead holder would brick the
///    subtree's turn forever.
fn reconcile_write_turns(daemon: &Daemon, local: &LocalDevice) {
    let now = now_secs();
    let now_instant = Instant::now();
    let mut announce_frame: Option<(Frame, Vec<RingEntry>)> = None;
    let mut revoke_frames: Vec<(Frame, Vec<RingEntry>)> = Vec::new();
    // Part 3b-ii: commit-boundary `TurnRequest`/`TurnYield` frames, each labelled
    // for its fan-out log line.
    let mut turn_frames: Vec<(Frame, Vec<RingEntry>, &'static str)> = Vec::new();
    let relay_client;
    {
        let mut inner = daemon.inner.lock().unwrap();
        if inner.state != State::Unlocked {
            return;
        }
        let Some(session) = inner.session.clone() else {
            return;
        };
        relay_client = relay_client_config(&inner.config);
        let relay_available = relay_client.is_some();
        let state_dir = inner.config.state_dir().to_path_buf();
        // Load the live ring once (mount-safe under the lock via the WorkTree),
        // reused for the device-state fan-out and each revoke's S-member fan-out.
        let ring = {
            let wt = WorkTree::new(daemon, &inner);
            load_ring(&wt, &state_dir).unwrap_or_default()
        };

        // (1) Recompute the coordination state from local write activity and
        // announce any change. On the first post-unlock tick `device_state` is
        // `Offline`, so this fires the `OnlineIdle` (or `OnlineActive`, if a write
        // already landed) lift; later ticks flip `OnlineIdle`↔`OnlineActive` as the
        // write window opens and decays.
        let desired_state =
            active_or_idle(inner.last_write_at.map(|t| now_instant.duration_since(t)));
        if inner.device_state != desired_state {
            inner.device_state = desired_state;
            inner.announce_seq += 1;
            let seq = inner.announce_seq;
            let frame = build_device_state_announce(&session, local, desired_state, seq);
            // Device state is global (not per-chain), so it fans to every ring
            // peer; in v1 point-to-point a ring peer is exactly an S-member.
            let targets: Vec<RingEntry> = ring
                .peers()
                .iter()
                .filter(|h| !plan_routes(h, relay_available).is_empty())
                .cloned()
                .collect();
            announce_frame = Some((frame, targets));
        }

        // (2) Expiry-revoke (poll) + commit-boundary broadcasts (part 3b-ii) →
        // resolve S-member targets + sign each, off the lock's IO. Both need the
        // committed membership + the ring member set, so load once and serve both;
        // `pending` is drained by value so a membership-read glitch re-queues it
        // (a request/yield must not be silently dropped).
        let revokes = poll_expiries(&mut inner.write_turns, now);
        let pending = std::mem::take(&mut inner.pending_turn_broadcasts);
        if !revokes.is_empty() || !pending.is_empty() {
            let membership = inner.repo.as_ref().and_then(|repo| {
                crate::handlers::read_committed_shared_subtrees_for_mutation(repo, &session).ok()
            });
            match (membership, inner.repo.as_ref()) {
                (Some(membership), Some(repo)) => {
                    let ring_members = assemble_member_set(&ring, local.device_id);
                    // Expiry-revokes: the crash/partition recovery path.
                    for (chain, revoked, epoch) in revokes {
                        let targets = resolve_turn_targets(
                            &membership,
                            &ring,
                            &ring_members,
                            repo,
                            &session,
                            &local.device_id,
                            relay_available,
                            &chain,
                        );
                        if targets.is_empty() {
                            continue;
                        }
                        let signature = session
                            .sign(&turn_revoke_signing_bytes(
                                chain.as_bytes(),
                                &local.device_id,
                                &revoked,
                                epoch,
                            ))
                            .to_bytes()
                            .to_vec();
                        let frame = Frame::turn_revoke(TurnRevoke {
                            chain_id: chain.into_bytes(),
                            device_id: local.device_id.to_vec(),
                            revoked: revoked.to_vec(),
                            epoch,
                            signature,
                        });
                        revoke_frames.push((frame, targets));
                    }
                    // Commit-boundary `TurnRequest`/`TurnYield` the gate queued.
                    for b in pending {
                        let (chain, frame, what) = match b {
                            PendingTurnBroadcast::Request { chain, seq } => {
                                let signature = session
                                    .sign(&turn_request_signing_bytes(
                                        chain.as_bytes(),
                                        &local.device_id,
                                        seq,
                                        LeaseScope::WholeSubtree,
                                    ))
                                    .to_bytes()
                                    .to_vec();
                                let frame = Frame::turn_request(TurnRequest {
                                    chain_id: chain.clone().into_bytes(),
                                    device_id: local.device_id.to_vec(),
                                    seq,
                                    scope: LeaseScope::WholeSubtree.as_u32(),
                                    signature,
                                });
                                (chain, frame, "turn-request")
                            }
                            PendingTurnBroadcast::Yield {
                                chain,
                                grantee,
                                seq,
                            } => {
                                let signature = session
                                    .sign(&turn_yield_signing_bytes(
                                        chain.as_bytes(),
                                        &local.device_id,
                                        &grantee,
                                        seq,
                                    ))
                                    .to_bytes()
                                    .to_vec();
                                let frame = Frame::turn_yield(TurnYield {
                                    chain_id: chain.clone().into_bytes(),
                                    device_id: local.device_id.to_vec(),
                                    grantee: grantee.to_vec(),
                                    seq,
                                    signature,
                                });
                                (chain, frame, "turn-yield")
                            }
                        };
                        let targets = resolve_turn_targets(
                            &membership,
                            &ring,
                            &ring_members,
                            repo,
                            &session,
                            &local.device_id,
                            relay_available,
                            &chain,
                        );
                        if targets.is_empty() {
                            continue;
                        }
                        turn_frames.push((frame, targets, what));
                    }
                }
                _ => {
                    // Committed membership unreadable this tick (a transient
                    // glitch): re-queue the commit-boundary broadcasts so the next
                    // tick retries them. Revokes are dropped as before — the lease
                    // already expired locally and peers self-expire on the same TTL.
                    inner.pending_turn_broadcasts = pending;
                }
            }
        }
    }
    // Lock released — the dials run off the daemon mutex.
    if let Some((frame, targets)) = announce_frame {
        fan_turn_frame(
            local,
            &targets,
            relay_client.as_ref(),
            &frame,
            "device-state-announce",
        );
    }
    for (frame, targets) in revoke_frames {
        fan_turn_frame(local, &targets, relay_client.as_ref(), &frame, "turn-revoke");
    }
    for (frame, targets, what) in turn_frames {
        fan_turn_frame(local, &targets, relay_client.as_ref(), &frame, what);
    }
}

/// Responder side of the M5d shared-key ceremony, dispatched on the session's
/// first `SharedKeyCommit`. The ceremony parameters split by trust: the nonce
/// and chain id ride the initiator's (signed) commit, but the **member set is
/// assembled from our own ring** — never from the wire — so both sides bind the
/// identical sorted set and a rogue frame cannot vote members in or out. The
/// session peer is already ring-authenticated (IK + [`ring_member_entry`]), and
/// [`run_ceremony`] signature-verifies every frame against the member set.
/// Generic over the link so the full responder path runs headlessly in tests.
///
/// `owner` is that ring-authenticated peer (resolved from the Noise static in
/// [`serve_established`]) — the requester's *cryptographic* identity, which the
/// slice-008 recovery hand-off gates on (we serve `S` only to a peer our own
/// committed transcript names). It is the authenticated identity, not the
/// unverified `commit.device_id` wire field.
fn serve_ceremony_responder<L: CeremonyLink>(
    daemon: &Daemon,
    local: &LocalDevice,
    owner: &RingEntry,
    ring: &Arc<Mutex<Ring>>,
    commit: SharedKeyCommit,
    link: L,
) {
    use zeroize::Zeroize;

    /// What this device's committed state says to do with an inbound commit.
    enum ResponderAction {
        /// No key (or no row) for this chain yet → run the ceremony + persist.
        Establish,
        /// Keyed but stale (member set changed) → run the ceremony + rotate.
        Rotate,
        /// Keyed, not stale, and the authenticated requester is a member this
        /// live transcript names but who lacks usable `S` (slice 008): serve the
        /// recovery hand-off instead of running a ceremony. Carries the record
        /// TOML + the loaded `S`; no ceremony is driven.
        Handoff {
            key_id: String,
            record: String,
            s: zeroize::Zeroizing<[u8; 32]>,
        },
    }

    let members = {
        let ring = ring.lock().unwrap();
        assemble_member_set(&ring, local.device_id)
    };
    if members.len() > 2 {
        eprintln!(
            "keeperd: net: shared-key ceremony refused: >2 ring members not yet supported \
             (v1 is point-to-point)"
        );
        return;
    }
    let Ok(nonce) = <[u8; 32]>::try_from(commit.nonce.as_slice()) else {
        eprintln!("keeperd: net: shared-key-commit nonce is not 32 bytes");
        return;
    };
    let chain = String::from_utf8_lossy(&commit.chain_id).into_owned();

    // M5d slice 006 (finding 3) + slice 003 rotation + slice 008 recovery: a
    // chain this device already holds a key for is not re-keyed at a ring peer's
    // whim (else a peer whose own persist keeps failing would re-initiate every
    // tick, minting a fresh key + `key_id` flip forever). Its verdict follows
    // this device's committed state:
    //   * unkeyed / no row  → establishment (persist seals `S`).
    //   * keyed + stale (committed transcript members != current ring) → an
    //     authorized rotation (routes to `rotate_shared_key`). Both sides derive
    //     staleness from committed state, so a peer cannot rotate a non-stale
    //     chain.
    //   * keyed + not stale + the authenticated requester is a member this live
    //     transcript names → a slice-008 recovery HAND-OFF: the peer lost `S` to
    //     a failed persist and re-dials, so serve it `{committed transcript, S}`
    //     over this ring-authenticated session instead of refusing. Gated on the
    //     *authenticated* `owner`, never the wire `commit.device_id`, and only
    //     when we ourselves hold usable `S` (`load_shared_key`, never
    //     `has_shared_key` — a torn corpse must not masquerade as serveable).
    //   * keyed + not stale + requester NOT a transcript member → hold the
    //     slice-006 refusal (defensive; unreachable in a v1 2-member ring where
    //     a non-stale transcript equals the ring).
    let action = {
        let inner = daemon.inner.lock().unwrap();
        let (Some(session), Some(repo)) = (inner.session.as_ref(), inner.repo.as_ref()) else {
            return; // locked mid-serve — the initiator retries a later tick
        };
        let membership =
            match crate::handlers::read_committed_shared_subtrees_for_mutation(repo, session) {
                Ok(m) => m,
                Err((_, e)) => {
                    eprintln!(
                        "keeperd: net: shared-key ceremony for {chain} refused: cannot read \
                         committed membership: {e}"
                    );
                    return;
                }
            };
        match membership
            .subtrees
            .iter()
            .find(|r| r.ref_name == chain)
            .and_then(|r| r.key_id.as_deref())
        {
            None => ResponderAction::Establish, // unkeyed or no row
            Some(existing) => {
                let transcript =
                    match crate::handlers::read_committed_transcript(repo, session, existing) {
                        Ok(Some(t)) => t,
                        // No readable transcript for the live key → can't judge
                        // staleness or membership; hold the slice-006 refusal.
                        Ok(None) => {
                            eprintln!(
                                "keeperd: net: shared-key ceremony for {chain} refused: chain is \
                                 already keyed {existing} and its transcript is unavailable to \
                                 judge staleness (rotation is the only authorized re-key path)"
                            );
                            return;
                        }
                        Err(e) => {
                            eprintln!(
                                "keeperd: net: shared-key ceremony for {chain} refused: cannot \
                                 read transcript for live key {existing}: {e}"
                            );
                            return;
                        }
                    };
                let tmembers: Vec<[u8; 32]> =
                    transcript.members.iter().map(|m| m.device_id).collect();
                if shared_chain_is_stale(&tmembers, &members) {
                    // M5d slice 017 / CORR-3: a rotation must derive `S'` under a
                    // salt distinct from the generation it replaces. The
                    // initiator mints a fresh random nonce per session, so an
                    // honest rotation never reuses one — refuse a replay against
                    // committed state (the live transcript's nonce) rather than
                    // trust freshness. Cheap: `transcript` is already in hand.
                    if !nonce_is_fresh(&nonce, &[transcript.nonce]) {
                        eprintln!(
                            "keeperd: net: shared-key rotation for {chain} refused: the ceremony \
                             nonce reuses the live generation's salt (a rotation must derive S' \
                             under a fresh nonce)"
                        );
                        return;
                    }
                    ResponderAction::Rotate // stale — an authorized rotation
                } else if tmembers.contains(&owner.device_id) {
                    // The requester is a member this live transcript names but is
                    // re-dialing → it lost `S` (failed persist). Serve the
                    // recovery hand-off, but only if WE hold usable `S`: load it
                    // (fails closed on a torn corpse), never trust file presence.
                    match session.load_shared_key(existing) {
                        Ok(s) => {
                            let record = match crate::ceremony::render_transcript_record(
                                &transcript,
                            ) {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!(
                                        "keeperd: net: shared-key hand-off for {chain} refused: \
                                         cannot render transcript {existing}: {e}"
                                    );
                                    return;
                                }
                            };
                            ResponderAction::Handoff {
                                key_id: existing.to_string(),
                                record,
                                s,
                            }
                        }
                        Err(e) => {
                            // We are a transcript member too, but our own `S` is
                            // missing/corrupt — we cannot serve. The requester
                            // keeps dialing; another holder (or our own recovery)
                            // may close the gap.
                            eprintln!(
                                "keeperd: net: shared-key hand-off for {chain} declined: this \
                                 device lacks usable S for {existing} ({e})"
                            );
                            return;
                        }
                    }
                } else {
                    eprintln!(
                        "keeperd: net: shared-key ceremony for {chain} refused: chain is already \
                         keyed {existing} and not stale, and the requester is not a member of its \
                         transcript (rotation is the only authorized re-key path)"
                    );
                    return;
                }
            }
        }
    };

    // Recovery hand-off short-circuits the ceremony: send the committed
    // transcript + `S` over this ring-authenticated session and return — no
    // ceremony is driven, nothing on this device changes (we already hold the
    // authoritative key + record). Establishment/rotation fall through to run it.
    let is_rotation = match action {
        ResponderAction::Handoff { key_id, record, s } => {
            let handoff = Frame::shared_key_handoff(SharedKeyHandoff {
                chain_id: commit.chain_id.clone(),
                transcript_record: record,
                shared_key: s.to_vec(),
            });
            let mut link = link;
            match link.send_frame(&handoff) {
                Ok(()) => eprintln!(
                    "keeperd: net: shared-key hand-off served for {chain}: {key_id}"
                ),
                Err(e) => eprintln!(
                    "keeperd: net: shared-key hand-off for {chain} failed to send: {e}"
                ),
            }
            return;
        }
        ResponderAction::Rotate => true,
        ResponderAction::Establish => false,
    };

    // In-flight dedup (M5d slice 006 part 2): refuse if a ceremony for this
    // chain is already running on this device — our own reconcile sweep is
    // initiating it, or an earlier inbound leg is still mid-protocol. Serving a
    // second concurrent ceremony would mint a divergent key the persist backstop
    // then has to refuse; refuse earlier, before driving the transport. The
    // guard drops when this responder leg ends (success or failure).
    let Some(_guard) = CeremonyGuard::try_acquire(daemon, &chain) else {
        eprintln!(
            "keeperd: net: shared-key ceremony for {chain} refused: a ceremony for \
             this chain is already in flight on this device"
        );
        return;
    };

    let contribution = softfig_vault::random_bytes32();
    let mut ceremony = match Ceremony::new(
        nonce,
        commit.chain_id.clone(),
        &members,
        local.device_id,
        contribution,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("keeperd: net: shared-key ceremony for {chain} refused: {e}");
            return;
        }
    };
    let signer = {
        let inner = daemon.inner.lock().unwrap();
        let Some(session) = inner.session.as_ref() else {
            return; // locked mid-serve — the initiator retries a later tick
        };
        VaultCeremonySigner::new(Arc::clone(session))
    };
    // The dispatch consumed the initiator's first frame; the responder
    // transport replays it so the driver sees every frame exactly once.
    let first = Frame::shared_key_commit(commit);
    let mut transport = SessionTransport::responder(link, first);
    match run_ceremony(&mut transport, &signer, &mut ceremony) {
        Ok(CeremonyOutcome::Derived(mut s, transcript)) => {
            let key_id = transcript.key_id.clone();
            // Route by the gate's verdict: a stale keyed chain is an authorized
            // rotation (flip + re-encrypt); anything else is an establishment
            // (persist seals `S`, filling this device's row if it has one).
            let outcome = if is_rotation {
                rotate_shared_key(daemon, &s, &transcript)
            } else {
                persist_ceremony_outcome(daemon, &s, &transcript)
            };
            let (verb, gerund) = if is_rotation {
                ("rotation", "rotating")
            } else {
                ("ceremony", "persisting")
            };
            match outcome {
                Ok(_) => eprintln!(
                    "keeperd: net: shared-key {verb} complete for {chain}: {key_id}"
                ),
                Err((_, e)) => eprintln!(
                    "keeperd: net: shared-key {verb} for {chain} derived {key_id} but \
                     {gerund} failed: {e}"
                ),
            }
            s.zeroize();
        }
        // The responder is the one that SERVES a hand-off; it never receives one
        // (a hand-off is only ever the reply to an initiator's commit). A peer
        // sending us one here is confused — drop it.
        Ok(CeremonyOutcome::Handoff(_)) => eprintln!(
            "keeperd: net: shared-key ceremony for {chain}: unexpected hand-off frame from the \
             initiator; ignoring"
        ),
        Err(e) => eprintln!("keeperd: net: shared-key ceremony for {chain} failed: {e}"),
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

/// Serve an inbound `SharedChainPush` (M5e slice 002, part 2b): a chain
/// S-member pushed a committed edit for us to adopt. The choreography mirrors
/// [`serve_replica_ingest`] — the sender dialed, sent this frame, and is now
/// serving [`serve_replication`] on the same session — so we receive-then-pull:
/// authorize the push, PULL its tree closure into the LIVE store, then re-author
/// it as a local `shared_pull` commit.
///
/// Auth is the same spine as the turn handlers: the Ed25519 signature proves
/// *who* signed (and must be the authenticated session peer), and committed
/// S-membership proves they *may* push to this chain. A forged push — bad
/// signature, spoofed sender, or non-member — is rejected before any store write.
///
/// The pull runs **off the daemon lock** (only the store paths are read under a
/// brief lock; the network round trips hold nothing). Only the post-pull
/// re-author ([`apply_shared_pull`]) takes the lock. See the store-handle LOCKED
/// DECISION: the sink is a second WAL connection on the live store, serialized
/// against the daemon's `Repo` by the store's busy-timeout.
fn serve_shared_chain_push(
    daemon: &Daemon,
    local: &LocalDevice,
    owner: &RingEntry,
    ring: &Arc<Mutex<Ring>>,
    p: SharedChainPush,
    mut session: NoiseSession<TcpStream>,
) {
    let chain = String::from_utf8_lossy(&p.chain_id).into_owned();
    let Ok(sender) = <[u8; 32]>::try_from(p.device_id.as_slice()) else {
        eprintln!("keeperd: net: shared-chain-push device_id is not 32 bytes");
        return;
    };
    let Ok(new_tree) = <[u8; 32]>::try_from(p.new_tree.as_slice()) else {
        eprintln!("keeperd: net: shared-chain-push for {chain} new_tree is not 32 bytes");
        return;
    };
    let Ok(base_tree) = <[u8; 32]>::try_from(p.base_tree.as_slice()) else {
        eprintln!("keeperd: net: shared-chain-push for {chain} base_tree is not 32 bytes");
        return;
    };
    // v1 point-to-point: the signed sender must be the authenticated peer.
    if sender != owner.device_id {
        eprintln!("keeperd: net: shared-chain-push device_id != authenticated peer; rejecting");
        return;
    }
    if !verify_shared_chain_push_sig(
        &p.chain_id,
        &p.subtree,
        &new_tree,
        &base_tree,
        &sender,
        &p.writer_device,
        &p.files,
        p.timestamp,
        &p.signature,
    ) {
        eprintln!("keeperd: net: shared-chain-push for {chain} signature invalid; rejecting");
        return;
    }
    let Some((membership, members)) = resolve_chain_members(daemon, ring, local, &chain) else {
        return; // locked mid-serve — the sender retries on its next tick
    };
    if !turn_sender_is_member(&membership, &chain, &members, &sender) {
        eprintln!(
            "keeperd: net: shared-chain-push for {chain} from non-member {}; rejecting",
            hex::encode(sender)
        );
        return;
    }

    // Pull the edit's tree closure into the LIVE store OFF the daemon lock: read
    // the store paths under a brief lock, release it, then run the network pull
    // (GetTree/GetObject round trips against the still-connected sender) holding
    // no lock. Only the post-pull re-author takes the lock.
    let paths = {
        let inner = daemon.inner.lock().unwrap();
        let Some(repo) = inner.repo.as_ref() else {
            return; // locked mid-serve
        };
        repo.paths().clone()
    };
    let mut sink = match replica::SharedChainSink::open(&paths) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("keeperd: net: shared-chain-push for {chain}: sink open failed: {e}");
            return;
        }
    };
    if let Err(e) = pull_subtree(&mut session, &mut sink, &new_tree) {
        eprintln!(
            "keeperd: net: shared-chain-push for {chain} PULL REJECTED (tamper/transfer): {e}"
        );
        return;
    }

    // Provenance for the mesh re-push (part 2b-3 (B)), cloned before `input`
    // consumes the frame: the forwarded edit carries the ORIGINATING author +
    // files verbatim, never re-attributed to this relaying device.
    let repush_subtree = p.subtree.clone();
    let repush_writer = p.writer_device.clone();
    let repush_files = p.files.clone();
    // The originating edit's signed timestamp is propagated verbatim on the mesh
    // re-push (the LWW key must survive relays intact — a re-stamp would make a
    // relayed edit look newer than it is).
    let repush_timestamp = p.timestamp;

    // The closure is fully stored; re-author it as this device's own shared_pull
    // commit under the daemon lock, then DROP the lock before any network
    // re-push. On a fresh `Applied`, capture the vault session + config the
    // off-lock fan-out needs (`Some` ⇒ re-push).
    let input = SharedPullInput {
        chain_ref: chain.clone(),
        peer_tree: Hash::from_bytes(new_tree),
        base_hash: Hash::from_bytes(base_tree),
        writer_device: p.writer_device,
        subtree: p.subtree,
        files: p.files,
    };
    let repush = {
        let mut inner = daemon.inner.lock().unwrap();
        // Part 3 (turn-ordering compose): before applying, an online-active
        // receiver that holds this chain's turn yields it to the incoming writer
        // (`sender`) so the peer's edit can't race our own held-turn local commit;
        // an online-idle receiver — or an active one that does not hold the turn —
        // applies straight through (`meta/spec-sync.md` §"Sync semantics"). The
        // apply is not a local write, so this is the receive-side counterpart to
        // `gate_shared_chain_commit`, never a second pass through it.
        let our_state =
            active_or_idle(inner.last_write_at.map(|t| Instant::now().duration_since(t)));
        let yield_turn = {
            let turn = inner
                .write_turns
                .entry(chain.clone())
                .or_insert_with(WriteTurn::whole_subtree);
            let must = active_receiver_must_yield(our_state, turn, &local.device_id);
            if must {
                turn.release(&local.device_id);
            }
            must
        };
        if yield_turn {
            let seq = now_secs().max(0) as u64;
            inner
                .pending_turn_broadcasts
                .push(PendingTurnBroadcast::Yield {
                    chain: chain.clone(),
                    grantee: sender,
                    seq,
                });
            if let Some(net) = inner.net.as_ref() {
                net.signal_commit();
            }
            eprintln!(
                "keeperd: net: shared-chain-push for {chain}: online-active receiver \
                 yielded the turn to {} before applying",
                hex::encode(sender)
            );
        }
        match apply_shared_pull(&mut inner, input) {
            Ok(SharedPullOutcome::Applied(hash)) => {
                eprintln!(
                    "keeperd: net: shared-chain-push for {chain} applied as {} (writer {})",
                    hash.to_hex(),
                    hex::encode(sender)
                );
                // Mesh forward (part 2b-3 (B)): re-push the just-applied edit to
                // the OTHER S-members. `AlreadyPresent` on those hops terminates
                // the ping-pong (a member that already holds the tree never
                // re-pushes). Deliberately NOT wired to `signal_commit` — the
                // apply core omits it precisely so the re-push rides THIS path.
                inner.session.clone().map(|session| {
                    (
                        session,
                        relay_client_config(&inner.config),
                        inner.config.garden_root.clone(),
                        inner.config.state_root.clone(),
                    )
                })
            }
            Ok(SharedPullOutcome::AlreadyPresent) => {
                eprintln!(
                    "keeperd: net: shared-chain-push for {chain} already present (ping-pong terminated)"
                );
                None
            }
            Ok(SharedPullOutcome::Conflict {
                base_hash,
                local_tree,
            }) => {
                // Slice 003: resolve the conflict LWW+sidecar rather than skip.
                // A conflict implies a born local tip (slice 002: apply returns
                // Conflict only when the tip tree diverged), so `local_tree` is
                // always `Some`; read that tip commit for its LWW key (signed
                // timestamp + author device — `p.timestamp` is the incoming key).
                let local_meta = inner.repo.as_ref().and_then(|repo| {
                    let tip = repo.tip_of(&chain).ok().flatten()?;
                    let row = repo.db().get_commit(&tip).ok()?;
                    Some((row.timestamp, row.author_device))
                });
                match (local_tree, local_meta) {
                    (Some(local_tree), Some((local_ts, local_device))) => {
                        let sides = ConflictSides {
                            chain_ref: chain.clone(),
                            subtree: repush_subtree.clone(),
                            path: repush_files.first().cloned().unwrap_or_default(),
                            base_hash,
                            incoming_tree: Hash::from_bytes(new_tree),
                            incoming_device: repush_writer.clone(),
                            incoming_ts: repush_timestamp,
                            local_tree,
                            local_device,
                            local_ts,
                        };
                        match resolve_sync_conflict(&mut inner, sides) {
                            Ok(ConflictResolution::Resolved {
                                hash,
                                kept_device,
                                loser_sidecar,
                            }) => {
                                eprintln!(
                                    "keeperd: net: shared-chain-push for {chain} CONFLICT resolved \
                                     (kept {kept_device}, loser -> {loser_sidecar}, commit {})",
                                    hash.to_hex()
                                );
                                // Propagate the resolution tip like a local write:
                                // the M5b push-on-commit sweep fans it to other
                                // S-members (a 3rd device catches up as a normal
                                // fast-forward). No in-arm re-push — convergence
                                // by construction means every conflicting member
                                // reconstructs the identical winner-tree+sidecar,
                                // so only the tip propagates, never the sidecar.
                                if let Some(net) = inner.net.as_ref() {
                                    net.signal_commit();
                                }
                                None
                            }
                            Ok(ConflictResolution::LoserUnresolvable { path }) => {
                                eprintln!(
                                    "keeperd: net: shared-chain-push for {chain} CONFLICT: could not \
                                     locate loser bytes for {path}; left unresolved (no work dropped)"
                                );
                                None
                            }
                            Err((_, e)) => {
                                eprintln!(
                                    "keeperd: net: shared-chain-push for {chain} CONFLICT resolve \
                                     failed: {e}"
                                );
                                None
                            }
                        }
                    }
                    _ => {
                        eprintln!(
                            "keeperd: net: shared-chain-push for {chain} CONFLICT on an unborn/ \
                             unreadable local tip (base {}); skipped",
                            base_hash.to_hex()
                        );
                        None
                    }
                }
            }
            Err((_, e)) => {
                eprintln!("keeperd: net: shared-chain-push for {chain} apply failed: {e}");
                None
            }
        }
    };

    // Lock released — the mesh re-push dials run off the daemon mutex. Targets:
    // the chain's S-members minus THIS device and minus the sender it arrived
    // from. The re-push base is the incoming `base_tree`: an `Applied` outcome
    // means our pre-apply tip tree equalled `base_tree` (a clean fast-forward)
    // or our chain was unborn — in both cases `base_tree` is the shared-history
    // base a downstream member fast-forwards from, so re-derives to it exactly.
    if let Some((session, relay_client, garden_root, state_root)) = repush {
        let relay_available = relay_client.is_some();
        let ring_snapshot = ring.lock().unwrap().clone();
        let targets: Vec<RingEntry> = members
            .iter()
            .filter(|id| **id != local.device_id && **id != sender)
            .filter_map(|id| ring_snapshot.peers().iter().find(|p| &p.device_id == id).cloned())
            .filter(|host| !plan_routes(host, relay_available).is_empty())
            .collect();
        if !targets.is_empty() {
            let frame = build_shared_chain_push_frame(
                &session,
                local,
                &chain,
                &repush_subtree,
                &new_tree,
                &base_tree,
                &repush_writer,
                &repush_files,
                repush_timestamp,
            );
            for host in &targets {
                if let Err(e) = push_shared_chain_to_host(
                    local,
                    host,
                    &frame,
                    &new_tree,
                    &garden_root,
                    state_root.as_deref(),
                    relay_client.as_ref(),
                ) {
                    eprintln!(
                        "keeperd: net: shared-chain re-push of {chain} to {} skipped: {e}",
                        host.fingerprint()
                    );
                }
            }
        }
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
                // M5d: pending shared-key ceremonies first, so a ceremony's
                // `shared_ceremony` commit rides this same tick's replica push.
                // The membership commit from `shared_subtree_add` signals this
                // loop, which makes the add→ceremony hook event-driven; the
                // interval is the offline-member retry (the locked liveness
                // default: the row lands with `key_id` empty and the ceremony
                // fills it when members next online — never an inline block).
                reconcile_ceremonies(&daemon, &local);
                // M5d slice 003: rotate any shared chain whose membership went
                // stale (join/leave) — after establishment, before the replica
                // push, so a rotation's `shared_rekey` commit rides this tick.
                reconcile_rekeys(&daemon, &local);
                // M5d slice 014 (ROTATE-1): drive any keyed chain whose live tip
                // still holds old-`S` ciphertext (a rotation whose in-line
                // re-encrypt failed, or a crash between the row flip and the
                // re-encrypt) back to fully-`S'` — peer-free, so it converges even
                // if the departed member never returns. After the rekey pass so a
                // rotation that just half-landed heals this same tick, and before
                // the replica push so a heal's commit rides it.
                crate::ceremony::reconcile_reencrypt_completeness(&daemon);
                reconcile_replicas(&daemon, &local);
                // M5e slice 002 part 2b-3 (A): push each shared chain's current
                // tip to its S-members. Rides the SAME commit-driven wake as the
                // device-chain replica push (a shared-subtree commit fires
                // `signal_commit`), so one signal covers both — the loop stays
                // single. Idempotent; quiet when no chain is member-reachable.
                reconcile_shared_pushes(&daemon, &local);
                // M5e slice 001 part 2b: announce our device state (once, on the
                // unlock lift) and expire any silent write-turn holder, fanning a
                // signed `TurnRevoke` so the mesh reclaims the turn — the
                // crash/partition recovery path. Rides this same loop (like the
                // ceremony/rekey passes) so the whole coordination plane shares
                // one outbound tick + its commit-driven wake.
                reconcile_write_turns(&daemon, &local);
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

/// One shared-chain content push pass (M5e slice 002 part 2b-3 (A)): for every
/// shared chain this device is an `S`-member of that holds an edit beyond
/// genesis, push its current tip to the chain's reachable `S`-members. Woken by
/// the same [`ReplicaSignal`] `signal_commit` as the device-chain replica push
/// (a local shared-subtree commit fires it via `commit_now`/the watcher flush),
/// with the reconcile interval as the offline catch-up fallback — the M5b
/// push-loop model, but the targets are the chain's `S`-members
/// ([`resolve_turn_targets`]) not `ledger.push_to`, and the transfer is the
/// subtree closure (`SharedChainPush` + [`serve_shared_subtree`]) not the whole
/// device chain. Idempotent: a member already at the tip dedups to
/// `AlreadyPresent` (one round-trip), so re-pushing the current tip every tick is
/// safe (the same posture as `reconcile_replicas`). All snapshotting is under the
/// daemon lock; every dial runs off it.
fn reconcile_shared_pushes(daemon: &Daemon, local: &LocalDevice) {
    struct SharedPush {
        chain: String,
        new_tree: [u8; 32],
        frame: Frame,
        targets: Vec<RingEntry>,
    }
    let (pushes, garden_root, state_root, relay_client) = {
        let inner = daemon.inner.lock().unwrap();
        if inner.state != State::Unlocked {
            return;
        }
        let (Some(session), Some(repo)) = (inner.session.clone(), inner.repo.as_ref()) else {
            return; // locked mid-tick
        };
        let membership =
            match crate::handlers::read_committed_shared_subtrees_for_mutation(repo, &session) {
                Ok(m) => m,
                Err((_, e)) => {
                    eprintln!("keeperd: net: shared-chain push skipped: cannot read membership: {e}");
                    return;
                }
            };
        if membership.subtrees.is_empty() {
            return; // no shared chains — quiet
        }
        let state_dir = inner.config.state_dir().to_path_buf();
        let ring = {
            let wt = WorkTree::new(daemon, &inner);
            load_ring(&wt, &state_dir).unwrap_or_default()
        };
        let ring_members = assemble_member_set(&ring, local.device_id);
        let relay_client = relay_client_config(&inner.config);
        let relay_available = relay_client.is_some();

        let mut pushes: Vec<SharedPush> = Vec::new();
        for entry in &membership.subtrees {
            let chain = entry.ref_name.clone();
            // The edit to propagate + the base a member fast-forwards from. An
            // unborn chain (no tip) or a genesis-only chain (tip has no parent)
            // has no edit to push — skip it.
            let Some(tip) = repo.tip_of(&chain).ok().flatten() else {
                continue;
            };
            let Ok(tip_row) = repo.db().get_commit(&tip) else {
                continue;
            };
            let Some(parent) = tip_row.parent else {
                continue;
            };
            let Ok(parent_row) = repo.db().get_commit(&parent) else {
                continue;
            };
            let new_tree = *tip_row.root_tree.as_bytes();
            let base_tree = *parent_row.root_tree.as_bytes();
            let targets = resolve_turn_targets(
                &membership,
                &ring,
                &ring_members,
                repo,
                &session,
                &local.device_id,
                relay_available,
                &chain,
            );
            if targets.is_empty() {
                continue; // no reachable S-member this tick
            }
            let (writer_device, files) = shared_push_provenance(&tip_row.payload, &local.device_name);
            let frame = build_shared_chain_push_frame(
                &session,
                local,
                &chain,
                &entry.mount_path,
                &new_tree,
                &base_tree,
                &writer_device,
                &files,
                tip_row.timestamp,
            );
            pushes.push(SharedPush {
                chain,
                new_tree,
                frame,
                targets,
            });
        }
        if pushes.is_empty() {
            return; // nothing member-reachable to push
        }
        let garden_root = inner.config.garden_root.clone();
        let state_root = inner.config.state_root.clone();
        (pushes, garden_root, state_root, relay_client)
    };
    // Lock released — every dial + serve runs off the daemon mutex.
    for push in pushes {
        for host in &push.targets {
            if let Err(e) = push_shared_chain_to_host(
                local,
                host,
                &push.frame,
                &push.new_tree,
                &garden_root,
                state_root.as_deref(),
                relay_client.as_ref(),
            ) {
                eprintln!(
                    "keeperd: net: shared-chain push of {} to {} skipped: {e}",
                    push.chain,
                    host.fingerprint()
                );
            }
        }
    }
}

/// Tie-break for concurrent dual-initiation (M5d slice 006 part 2). When both
/// devices add the same mount path — the designed onboarding flow — both derive
/// the same `chain/<id>`, both get a pending row, and both sweeps would initiate
/// within one ~20s window, dueling to two different keys. To make convergence
/// provable rather than racy, the lexically-lower `device_id` initiates
/// immediately; the higher device **defers** until it has seen the chain pending
/// across a prior reconcile pass (`seen_before`) — by then the lower device's
/// ceremony has normally landed and filled the higher's row *as responder*, so
/// it never initiates and there is exactly one ceremony per chain per window.
///
/// The defer is time-bounded, never permanent, because of the **hard
/// constraint**: in the asymmetric flow only one device holds a row (the other
/// is a responder that hasn't added the subtree), and that device might be the
/// higher one. A permanent "only the lower initiates" would strand it. So the
/// higher device still initiates once it has seen the chain pending before
/// (`seen_before`) — one extra tick of latency, never a stall. The in-flight
/// guard + part 1's fail-closed persist are the safety net if both still race.
fn should_initiate_now(local_id: &[u8; 32], peer_id: &[u8; 32], seen_before: bool) -> bool {
    local_id < peer_id || seen_before
}

/// RAII guard over [`DaemonInner::ceremonies_in_flight`] (M5d slice 006 part 2).
/// Acquired before an initiate/serve leg for a chain and removed on drop (the
/// leg ended, success or failure) so one device never runs two concurrent
/// ceremonies for one chain. Holds a `Daemon` clone so it can re-lock `inner`
/// on drop after the network IO (which runs with the mutex released).
struct CeremonyGuard {
    daemon: Daemon,
    chain: String,
}

impl CeremonyGuard {
    /// Insert `chain` into the in-flight set, returning the guard — or `None`
    /// when a ceremony for this chain is already in flight on this device, in
    /// which case the caller must not start a second.
    fn try_acquire(daemon: &Daemon, chain: &str) -> Option<Self> {
        let mut inner = daemon.inner.lock().unwrap();
        if !inner.ceremonies_in_flight.insert(chain.to_string()) {
            return None;
        }
        Some(Self {
            daemon: daemon.clone(),
            chain: chain.to_string(),
        })
    }
}

impl Drop for CeremonyGuard {
    fn drop(&mut self) {
        let mut inner = self.daemon.inner.lock().unwrap();
        inner.ceremonies_in_flight.remove(&self.chain);
    }
}

/// One ceremony reconcile pass (M5d, initiator side): find committed shared
/// subtrees still awaiting their key (`key_id` empty), and for each run the
/// commit-reveal ceremony with the ring peer, then persist the outcome —
/// filling the row's `key_id`. Snapshot under the daemon lock, ceremony with
/// the lock released (never hold the mutex across network IO); a failed
/// attempt (peer offline, mid-protocol error) leaves the row pending for the
/// next tick — the deferred/retried liveness model, mirroring
/// [`reconcile_replicas`]' per-tick catch-up.
/// Detection half of the establishment/recovery reconcile (unit-testable
/// without a live peer): the ref_names of committed shared chains that need a
/// dial this pass — either an **unkeyed** row (establishment: the ceremony
/// derives + seals `S`) OR a **keyed** row whose sealed `S` will not load (M5d
/// slice 016 ROTATE-2: bit-rot / torn write / deletion left the device holding
/// a `key_id` but no usable key). A keyed row with usable `S` is skipped.
///
/// ROTATE-2 rationale: `reconcile_rekeys` only re-dials on member-set staleness
/// and this pass otherwise skips every keyed row, so a keyed-but-unusable `S`
/// had no recovery trigger — the device stayed silently locked out of a chain it
/// legitimately belongs to, forever. Re-dialing routes it to the same slice-008
/// hand-off requester: a keyed peer that names us serves `{transcript, S}` and
/// [`accept_handoff`] → [`crate::ceremony::persist_ceremony_outcome`] re-seals
/// `S` idempotently (same `key_id` ⇒ no divergence, no duplicate commit). The
/// read/encrypt paths already fail closed on the missing `S`, so this only turns
/// a permanent lock-out into self-healing. Mirrors [`stale_keyed_chains`] (the
/// rotation detector) so both live-peer sweeps keep a headless-testable core.
fn chains_awaiting_key(
    repo: &Repo,
    session: &VaultSession,
) -> std::result::Result<Vec<String>, (ErrorKind, String)> {
    let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(repo, session)?;
    Ok(membership
        .subtrees
        .iter()
        .filter(|row| match row.key_id.as_deref() {
            None => true,
            Some(key_id) => session.load_shared_key(key_id).is_err(),
        })
        .map(|row| row.ref_name.clone())
        .collect())
}

fn reconcile_ceremonies(daemon: &Daemon, local: &LocalDevice) {
    use zeroize::Zeroize;

    let snapshot = {
        let inner = daemon.inner.lock().unwrap();
        if inner.state != State::Unlocked {
            return;
        }
        let (Some(session), Some(repo)) = (inner.session.as_ref(), inner.repo.as_ref()) else {
            return;
        };
        let pending: Vec<String> = match chains_awaiting_key(repo, session) {
            Ok(p) => p,
            Err((_, e)) => {
                eprintln!("keeperd: net: ceremony reconcile skipped: {e}");
                return;
            }
        };
        if pending.is_empty() {
            return;
        }
        let state_dir = inner.config.state_dir().to_path_buf();
        let ring = {
            let wt = WorkTree::new(daemon, &inner);
            load_ring(&wt, &state_dir).unwrap_or_default()
        };
        let relay_client = relay_client_config(&inner.config);
        let signer = VaultCeremonySigner::new(Arc::clone(session));
        (pending, ring, relay_client, signer)
    };
    let (pending, ring, relay_client, signer) = snapshot;

    let members = assemble_member_set(&ring, local.device_id);
    if members.len() < 2 {
        // No paired peer yet — a collaborative key has no collaborator. Quiet:
        // this is the normal share-before-pairing state, resolved by pairing.
        return;
    }
    if members.len() > 2 {
        eprintln!(
            "keeperd: net: {} shared subtree(s) await a key, but the ring has {} members — \
             ceremony >2 members not yet supported (v1 is point-to-point)",
            pending.len(),
            members.len() - 1
        );
        return;
    }
    let host = ring.peers()[0].clone();

    // Tie-break bookkeeping (M5d slice 006 part 2): note which pending chains
    // were already seen pending in a *prior* pass, then refresh the seen set to
    // the current pending list (dropping any that keyed since). Under a brief
    // lock of its own — the snapshot above holds live session/repo borrows.
    let seen_before: HashSet<String> = {
        let mut inner = daemon.inner.lock().unwrap();
        let prior = std::mem::take(&mut inner.ceremony_seen_pending);
        let seen_before = pending.iter().filter(|c| prior.contains(*c)).cloned().collect();
        inner.ceremony_seen_pending = pending.iter().cloned().collect();
        seen_before
    };

    for ref_name in pending {
        // Tie-break: the lexically-higher device defers a freshly-pending chain
        // one tick so the lower device's ceremony lands (and fills our row as
        // responder) first — exactly one ceremony per chain per window. The
        // asymmetric flow still converges: the sole row-holder initiates once it
        // has seen the chain pending before, higher or not (`should_initiate_now`).
        if !should_initiate_now(&local.device_id, &host.device_id, seen_before.contains(&ref_name)) {
            continue;
        }
        // In-flight dedup: never run a second concurrent ceremony for this chain
        // on this device (an inbound responder leg, or an overlapping tick). The
        // guard drops at the end of the iteration, after persist.
        let Some(_guard) = CeremonyGuard::try_acquire(daemon, &ref_name) else {
            continue;
        };
        match ceremony_with_host(local, &host, relay_client.as_ref(), &signer, &members, &ref_name)
        {
            Ok(CeremonyOutcome::Derived(mut s, transcript)) => {
                let key_id = transcript.key_id.clone();
                match persist_ceremony_outcome(daemon, &s, &transcript) {
                    Ok(_) => eprintln!(
                        "keeperd: net: shared-key ceremony complete for {ref_name}: {key_id}"
                    ),
                    Err((_, e)) => eprintln!(
                        "keeperd: net: shared-key ceremony for {ref_name} derived {key_id} \
                         but persisting failed: {e}"
                    ),
                }
                s.zeroize();
            }
            // M5d slice 008: the peer served a recovery hand-off (it already
            // holds a live key for this chain that names us, and we lost `S`).
            // Verify + persist it through the idempotent ceremony path.
            Ok(CeremonyOutcome::Handoff(handoff)) => {
                match accept_handoff(daemon, &ref_name, handoff) {
                    Ok(key_id) => eprintln!(
                        "keeperd: net: shared-key recovered for {ref_name} via hand-off: {key_id}"
                    ),
                    Err(e) => eprintln!(
                        "keeperd: net: shared-key hand-off for {ref_name} rejected: {e}"
                    ),
                }
            }
            Err(e) => eprintln!(
                "keeperd: net: shared-key ceremony for {ref_name} skipped: {e}"
            ),
        }
    }
}

/// M5d slice 008 — accept a recovery hand-off served by a keyed peer in reply to
/// our re-dial. We lost `S` to a failed persist; the peer, holding a live
/// non-stale key for this chain that names us, sent back `{committed transcript,
/// S}` over the ring-authenticated Noise session. Verify and persist it through
/// the idempotent [`persist_ceremony_outcome`], which re-checks the transcript
/// from first principles (`verify`, `key_id(S) == transcript.key_id`, self ∈
/// members) before anything durable — so a forged or foreign hand-off is refused
/// there. Bind the transcript to the chain we actually dialed for (defense in
/// depth: a keyed peer must not answer a probe for chain X with a key for Y).
/// Returns the recovered `key_id`.
fn accept_handoff(
    daemon: &Daemon,
    ref_name: &str,
    handoff: SharedKeyHandoff,
) -> std::result::Result<String, String> {
    use zeroize::Zeroize;

    let mut s: [u8; 32] = handoff
        .shared_key
        .as_slice()
        .try_into()
        .map_err(|_| "hand-off shared key is not 32 bytes".to_string())?;
    let transcript = match crate::ceremony::parse_transcript_record(&handoff.transcript_record) {
        Ok(t) => t,
        Err(e) => {
            s.zeroize();
            return Err(format!("hand-off transcript unparseable: {e}"));
        }
    };
    if transcript.chain_id != ref_name.as_bytes() {
        s.zeroize();
        return Err(format!(
            "hand-off transcript is for a different chain than {ref_name}"
        ));
    }
    let key_id = transcript.key_id.clone();
    // persist re-verifies the transcript + key_id(S) binding + our membership and
    // is idempotent: a boundary-B device that already sealed S just commits the
    // record + fills its row. Wrap S in the zeroizing `SharedKey` newtype for the
    // persist call (slice 015); the stack copy in `s` is `Copy`, so the newtype
    // holds an independent copy that zeroizes on its own drop, and we still wipe
    // the stack copy explicitly below.
    let shared = SharedKey::from_bytes(s);
    let result = persist_ceremony_outcome(daemon, &shared, &transcript).map_err(|(_, e)| e);
    s.zeroize();
    result.map(|_| key_id)
}

/// A keyed shared chain is **stale** — it needs a rotation — when its committed
/// ceremony transcript's member set no longer equals the current ring's member
/// set (a join added a member, or a leave removed one). Both protocol sides
/// derive this independently from committed state (no `SharedKeyCommit` wire
/// field), mirroring how `reconcile_ceremonies` derives the unkeyed-detection —
/// so a rotation is authorized only when both sides agree, and a peer cannot
/// re-key a chain it does not itself see as stale. Order-insensitive: the ring
/// is unsorted (`assemble_member_set` returns `[local, ...peers]`), so both
/// sides fold into a `BTreeSet` before comparing.
fn shared_chain_is_stale(transcript_members: &[[u8; 32]], current_members: &[[u8; 32]]) -> bool {
    let committed: std::collections::BTreeSet<[u8; 32]> =
        transcript_members.iter().copied().collect();
    let current: std::collections::BTreeSet<[u8; 32]> = current_members.iter().copied().collect();
    committed != current
}

/// Detection half of the rekey reconcile (unit-testable without a live peer):
/// the ref_names of committed *keyed* chains whose committed transcript member
/// set differs from `current_members`. Reads each keyed row's transcript
/// ([`crate::handlers::read_committed_transcript`]); an unkeyed row is
/// establishment's job (`reconcile_ceremonies`) and skipped, and a keyed row
/// whose transcript can't be read yet is skipped rather than assumed stale (a
/// read glitch must never trigger a rotation — a later tick retries).
fn stale_keyed_chains(
    repo: &Repo,
    session: &VaultSession,
    current_members: &[[u8; 32]],
) -> std::result::Result<Vec<String>, (ErrorKind, String)> {
    let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(repo, session)?;
    let mut stale = Vec::new();
    for row in membership.subtrees.iter() {
        let Some(kid) = row.key_id.as_deref() else {
            continue; // unkeyed → establishment (reconcile_ceremonies), not rotation
        };
        let transcript = match crate::handlers::read_committed_transcript(repo, session, kid) {
            Ok(Some(t)) => t,
            Ok(None) => continue, // no readable transcript yet — don't guess stale
            Err(e) => {
                eprintln!(
                    "keeperd: net: rekey reconcile: cannot read transcript for {} ({kid}): {e}",
                    row.ref_name
                );
                continue;
            }
        };
        let tmembers: Vec<[u8; 32]> = transcript.members.iter().map(|m| m.device_id).collect();
        if shared_chain_is_stale(&tmembers, current_members) {
            stale.push(row.ref_name.clone());
        }
    }
    Ok(stale)
}

/// One rotation reconcile pass (M5d slice 003, initiator side): find committed
/// keyed shared subtrees whose membership went stale (a join/leave changed the
/// ring), and for each re-run the commit-reveal ceremony over the **current**
/// member set, then route the outcome to [`rotate_shared_key`] — the authorized
/// re-key path that swaps `S`→`S'` and re-encrypts the chain. Snapshot + detect
/// under the daemon lock, ceremony with the lock released; a failed attempt
/// leaves the chain stale for the next tick — the same deferred/retried liveness
/// model `reconcile_ceremonies` uses. The responder mirrors the staleness check
/// so both sides independently authorize the rotation (see
/// [`shared_chain_is_stale`]).
fn reconcile_rekeys(daemon: &Daemon, local: &LocalDevice) {
    use zeroize::Zeroize;

    let snapshot = {
        let inner = daemon.inner.lock().unwrap();
        if inner.state != State::Unlocked {
            return;
        }
        let (Some(session), Some(repo)) = (inner.session.as_ref(), inner.repo.as_ref()) else {
            return;
        };
        let state_dir = inner.config.state_dir().to_path_buf();
        let ring = {
            let wt = WorkTree::new(daemon, &inner);
            load_ring(&wt, &state_dir).unwrap_or_default()
        };
        let members = assemble_member_set(&ring, local.device_id);
        let stale = match stale_keyed_chains(repo, session, &members) {
            Ok(s) => s,
            Err((_, e)) => {
                eprintln!("keeperd: net: rekey reconcile skipped: {e}");
                return;
            }
        };
        if stale.is_empty() {
            return;
        }
        let relay_client = relay_client_config(&inner.config);
        let signer = VaultCeremonySigner::new(Arc::clone(session));
        (stale, ring, members, relay_client, signer)
    };
    let (stale, ring, members, relay_client, signer) = snapshot;

    // A rotation is still a collaborative ceremony over the CURRENT members — the
    // same v1 point-to-point gates `reconcile_ceremonies` applies.
    if members.len() < 2 {
        // Stale but now solo (a 2→1 leave): a collaborative rekey has no
        // collaborator. The honest custody limit (`spec-sync.md` §Crypto) — the
        // departed member keeps only ciphertext it already held, we cannot rotate
        // alone. Quiet: resolved if a member re-pairs.
        return;
    }
    if members.len() > 2 {
        eprintln!(
            "keeperd: net: {} shared subtree(s) need a rekey, but the ring has {} members — \
             >2 rotation not yet supported (v1 is point-to-point)",
            stale.len(),
            members.len() - 1
        );
        return;
    }
    let host = ring.peers()[0].clone();

    // Tie-break bookkeeping (keyed-chain analogue of `reconcile_ceremonies`'):
    // note which stale chains were already seen stale in a *prior* pass, then
    // refresh the seen set to the current stale list (dropping any that rotated
    // since). A separate set from the establishment clock (a chain is unkeyed or
    // keyed-stale, never both).
    let seen_before: HashSet<String> = {
        let mut inner = daemon.inner.lock().unwrap();
        let prior = std::mem::take(&mut inner.rekey_seen_stale);
        let seen_before = stale.iter().filter(|c| prior.contains(*c)).cloned().collect();
        inner.rekey_seen_stale = stale.iter().cloned().collect();
        seen_before
    };

    for ref_name in stale {
        // Tie-break: the lexically-higher device defers a freshly-stale chain one
        // tick so the lower device's rotation lands (and this device responds)
        // first — one rotation per chain per window, so both sides converge on one
        // `S'` instead of racing to two.
        if !should_initiate_now(&local.device_id, &host.device_id, seen_before.contains(&ref_name)) {
            continue;
        }
        // In-flight dedup: never run a second concurrent ceremony for this chain
        // on this device (an inbound responder leg, or an overlapping tick).
        let Some(_guard) = CeremonyGuard::try_acquire(daemon, &ref_name) else {
            continue;
        };
        match ceremony_with_host(local, &host, relay_client.as_ref(), &signer, &members, &ref_name) {
            Ok(CeremonyOutcome::Derived(mut s, transcript)) => {
                let key_id = transcript.key_id.clone();
                match rotate_shared_key(daemon, &s, &transcript) {
                    Ok(_) => eprintln!(
                        "keeperd: net: shared-key rotation complete for {ref_name}: {key_id}"
                    ),
                    Err((_, e)) => eprintln!(
                        "keeperd: net: shared-key rotation for {ref_name} derived {key_id} \
                         but rotating failed: {e}"
                    ),
                }
                s.zeroize();
            }
            // We dialed to ROTATE a chain we see as stale, but the peer answered
            // with a recovery hand-off — i.e. it does NOT see the chain as stale
            // (a transient membership-view disagreement). Do not feed the current
            // key into `rotate_shared_key` (which expects a fresh, different key);
            // skip and let a later tick re-evaluate once both views converge.
            Ok(CeremonyOutcome::Handoff(_)) => eprintln!(
                "keeperd: net: shared-key rotation for {ref_name} skipped: peer served a recovery \
                 hand-off (it does not see the chain as stale); re-evaluating next tick"
            ),
            Err(e) => eprintln!("keeperd: net: shared-key rotation for {ref_name} skipped: {e}"),
        }
    }
}

/// Run the initiator side of one ceremony with the (single, v1) other member,
/// preferring a LAN-direct dial and falling back to the relay — the
/// [`push_to_host`] route model. Once a session is established the ceremony's
/// result is final for this attempt (no route fallthrough mid-protocol); the
/// reconcile tick retries with a fresh nonce.
fn ceremony_with_host(
    local: &LocalDevice,
    host: &RingEntry,
    relay_client: Option<&(String, [u8; 32])>,
    signer: &VaultCeremonySigner,
    members: &[[u8; 32]],
    ref_name: &str,
) -> Result<CeremonyOutcome, String> {
    let routes = plan_routes(host, relay_client.is_some());
    if routes.is_empty() {
        return Err("no route to member (no LAN endpoint, no relay)".to_string());
    }
    let mut last_err = "no route to member".to_string();
    for route in &routes {
        match route {
            Route::Direct(endpoint) => match dial_direct(local, host, endpoint) {
                Ok(session) => return drive_initiator(session, signer, members, local, ref_name),
                Err(e) => {
                    last_err = e;
                    continue;
                }
            },
            Route::Relay => {
                let (relay_endpoint, relay_static) =
                    relay_client.expect("relay route planned without a relay client");
                match dial_relay(local, host, relay_endpoint, relay_static) {
                    Ok(session) => {
                        return drive_initiator(session, signer, members, local, ref_name)
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

/// Drive one initiator ceremony over an established link: mint a fresh nonce +
/// contribution from the vault's RNG, then run the commit-reveal protocol. The
/// nonce is minted here — per established session — so no two attempts (or
/// routes) ever share ceremony material.
fn drive_initiator<L: CeremonyLink>(
    link: L,
    signer: &VaultCeremonySigner,
    members: &[[u8; 32]],
    local: &LocalDevice,
    ref_name: &str,
) -> Result<CeremonyOutcome, String> {
    let nonce = softfig_vault::random_bytes32();
    let contribution = softfig_vault::random_bytes32();
    let mut ceremony = Ceremony::new(
        nonce,
        ref_name.as_bytes().to_vec(),
        members,
        local.device_id,
        contribution,
    )
    .map_err(|e| format!("ceremony setup: {e}"))?;
    let mut transport = SessionTransport::initiator(link);
    run_ceremony(&mut transport, signer, &mut ceremony).map_err(|e| format!("ceremony: {e}"))
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

/// Sign + frame a [`SharedChainPush`] for one shared-chain edit (M5e slice 002
/// part 2b-3). Shared by the push-on-local-commit sweep
/// ([`reconcile_shared_pushes`]) and the inbound mesh re-push
/// ([`serve_shared_chain_push`]'s `Applied` arm) so both sign the exact bytes
/// [`verify_shared_chain_push_sig`] checks. `device_id` is always THIS device
/// (the immediate sender, which must equal the authenticated session peer);
/// `writer_device` carries the ORIGINATING author's name verbatim — on a re-push
/// it is the upstream member's name, not ours (advisory provenance; a re-pusher
/// can forge it in v1 — locked, don't fix).
#[doc(hidden)] // test seam — see `serve_established`.
#[allow(clippy::too_many_arguments)]
pub fn build_shared_chain_push_frame(
    session: &VaultSession,
    local: &LocalDevice,
    chain: &str,
    subtree: &str,
    new_tree: &[u8; 32],
    base_tree: &[u8; 32],
    writer_device: &str,
    files: &[String],
    timestamp: i64,
) -> Frame {
    let signature = session
        .sign(&shared_chain_push_signing_bytes(
            chain.as_bytes(),
            subtree,
            new_tree,
            base_tree,
            &local.device_id,
            writer_device,
            files,
            timestamp,
        ))
        .to_bytes()
        .to_vec();
    Frame::shared_chain_push(SharedChainPush {
        chain_id: chain.as_bytes().to_vec(),
        subtree: subtree.to_string(),
        new_tree: new_tree.to_vec(),
        base_tree: base_tree.to_vec(),
        device_id: local.device_id.to_vec(),
        writer_device: writer_device.to_string(),
        files: files.to_vec(),
        signature,
        timestamp,
    })
}

/// Serve one shared-chain subtree closure over an established (direct or
/// relayed) session: open a fresh read-only `Repo` handle, scope a
/// [`RepoSource`] to `root_tree`'s tree closure ([`RepoSource::for_subtree`]),
/// and drive [`serve_replication`] while the receiver's
/// [`pull_subtree`](softfig_net::pull_subtree) fetches the trees + objects it
/// lacks. The send-frame-then-serve choreography's second half (the caller sent
/// the frame). Generic over the stream so the same drive runs LAN-direct or
/// relayed. The just-committed tree closure is durable in the store before this
/// runs, so a fresh reader beside the daemon's writer (sqlite WAL) serves it.
#[doc(hidden)] // test seam — see `serve_established`.
pub fn serve_shared_subtree<S: std::io::Read + std::io::Write>(
    session: &mut NoiseSession<S>,
    root_tree: &[u8; 32],
    garden_root: &std::path::Path,
    state_root: Option<&std::path::Path>,
) -> Result<(), String> {
    let repo = Repo::open_with(garden_root, state_root).map_err(|e| format!("open repo: {e}"))?;
    let source =
        RepoSource::for_subtree(repo, *root_tree).map_err(|e| format!("scope source: {e}"))?;
    serve_replication(session, &source)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Push one shared-chain edit to one `S`-member, preferring a LAN-direct dial and
/// falling back to the zero-trust relay ([`plan_routes`] / [`push_to_host`] route
/// model). On each route: run the Noise `IK` handshake, send the signed
/// `SharedChainPush` `frame`, then serve `new_tree`'s subtree closure while the
/// receiver pulls + applies it as a local `shared_pull` commit. A
/// dial/handshake/send failure falls through to the next route; once serving
/// begins the result is returned (a mid-serve error is not retried elsewhere).
#[doc(hidden)] // test seam — see `serve_established`. Drives the outbound push
               // primitive directly so the 3-daemon mesh test can seed A→B over
               // a real dial (the same path the `Applied`-arm re-push uses).
#[allow(clippy::too_many_arguments)]
pub fn push_shared_chain_to_host(
    local: &LocalDevice,
    host: &RingEntry,
    frame: &Frame,
    new_tree: &[u8; 32],
    garden_root: &std::path::Path,
    state_root: Option<&std::path::Path>,
    relay_client: Option<&(String, [u8; 32])>,
) -> Result<(), String> {
    let routes = plan_routes(host, relay_client.is_some());
    if routes.is_empty() {
        return Err("no route to member (no LAN endpoint, no relay)".to_string());
    }
    let mut last_err = "no route to member".to_string();
    for route in &routes {
        match route {
            Route::Direct(endpoint) => match dial_direct(local, host, endpoint) {
                Ok(mut session) => {
                    if let Err(e) = session.send_frame(frame) {
                        last_err = format!("send push (direct {endpoint}): {e}");
                        continue;
                    }
                    return serve_shared_subtree(&mut session, new_tree, garden_root, state_root);
                }
                Err(e) => {
                    last_err = e;
                    continue;
                }
            },
            Route::Relay => {
                let (relay_endpoint, relay_static) =
                    relay_client.expect("relay route planned without a relay client");
                match dial_relay(local, host, relay_endpoint, relay_static) {
                    Ok(mut session) => {
                        if let Err(e) = session.send_frame(frame) {
                            last_err = format!("send push (relay {relay_endpoint}): {e}");
                            continue;
                        }
                        return serve_shared_subtree(&mut session, new_tree, garden_root, state_root);
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

/// Derive a shared-chain push's advisory provenance (`writer_device`, `files`)
/// from the tip commit's payload. A re-authored `shared_pull` tip carries the
/// upstream `writer_device` + `files` verbatim (propagate the origin, exactly as
/// the mesh re-push does); a locally-authored edit (e.g. `manual_edit`, with no
/// such fields) is attributed to THIS device with an empty file list. Advisory
/// only — the receiver stores it as provenance; the tree is the source of truth.
fn shared_push_provenance(payload: &str, local_name: &str) -> (String, Vec<String>) {
    let json: serde_json::Value =
        serde_json::from_str(payload).unwrap_or(serde_json::Value::Null);
    let writer = json
        .get("writer_device")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| local_name.to_string());
    let files = json
        .get("files")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|f| f.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    (writer, files)
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
    // Used only by the ceremony/transcript test fixtures (production paths now
    // route these types through `CeremonyOutcome`).
    use softfig_net::ceremony::{SharedKey, Transcript};

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

    // --- m5e slice 001 part 2: write-turn S-membership authorization ----------

    /// A shared-subtrees membership holding a single chain, for the turn
    /// authorization tests. `key_id` stays `None` (an unkeyed chain resolves its
    /// members from the ring in production; here we pass the member set directly).
    fn membership_with_chain(chain: &str) -> softfig_vcs::SharedSubtreesConfig {
        softfig_vcs::SharedSubtreesConfig {
            subtrees: vec![softfig_vcs::SharedSubtreeEntry {
                id: "sub-1".into(),
                mount_path: "projects/journal".into(),
                ref_name: chain.into(),
                key_id: None,
            }],
        }
    }

    /// The daemon half of "a forged turn-request from a non-member is rejected":
    /// a valid signature proves *who* signed (the crypto half, in `turn.rs`), but
    /// the turn only moves for a device that is an S-member of *this* chain. A
    /// non-member id, or any id on a chain we don't share, is refused before it
    /// touches the lease.
    #[test]
    fn turn_sender_authorized_only_for_members_of_the_named_chain() {
        let chain = "chain/journal";
        let membership = membership_with_chain(chain);
        let members = vec![id_bytes(1), id_bytes(2)];

        // An S-member of the named chain is authorized.
        assert!(turn_sender_is_member(
            &membership,
            chain,
            &members,
            &id_bytes(1)
        ));

        // A well-signed request from a device outside the member set is rejected —
        // the forged-non-member daemon guard.
        assert!(!turn_sender_is_member(
            &membership,
            chain,
            &members,
            &id_bytes(9)
        ));

        // A genuine member, but for a chain this device shares no subtree for, is
        // also rejected (can't borrow membership of one chain to act on another).
        assert!(!turn_sender_is_member(
            &membership,
            "chain/unknown",
            &members,
            &id_bytes(1)
        ));
    }

    /// The daemon half of "silent holder → expiry → revoke" (part 2b poll loop).
    /// `poll_expiries` must revoke exactly the lease whose holder went silent past
    /// its renew window, name that holder + its lease epoch (so the fanned
    /// `TurnRevoke` binds to one generation), clear it locally, and leave a still-
    /// live holder untouched — the crash/partition recovery path, minus the dial.
    #[test]
    fn poll_expiries_revokes_only_the_silent_holder() {
        let mut turns: HashMap<String, WriteTurn> = HashMap::new();

        // chain/a: dev(1) granted at t=0 → deadline 30 (default ttl). At t=100 it
        // has long gone silent.
        let mut a = WriteTurn::whole_subtree();
        assert_eq!(a.apply_yield(id_bytes(1), 0), Some(1)); // first grant → epoch 1
        turns.insert("chain/a".to_string(), a);

        // chain/b: dev(2) granted at t=90 → deadline 120, still live at t=100.
        let mut b = WriteTurn::whole_subtree();
        b.apply_yield(id_bytes(2), 90);
        turns.insert("chain/b".to_string(), b);

        let revokes = poll_expiries(&mut turns, 100);

        assert_eq!(revokes.len(), 1, "only the silent holder is revoked");
        assert_eq!(revokes[0], ("chain/a".to_string(), id_bytes(1), 1));
        // The expired lease is cleared locally; the live one is untouched.
        assert!(turns["chain/a"].holder().is_none());
        assert_eq!(turns["chain/b"].holder(), Some(id_bytes(2)));

        // Idempotent: a second poll at the same instant has nothing left to revoke
        // (the turn is free with no waiters — no phantom re-revoke of a gone lease).
        assert!(poll_expiries(&mut turns, 100).is_empty());
    }

    /// Part 3b-ii — the pure commit-boundary gate over one chain's local lease
    /// (the decision `reconcile_write_turns` acts on). Mirrors the `poll_expiries`
    /// headless shape: no IO, `now`/`seq` passed in.
    #[test]
    fn commit_gate_self_acquires_a_free_turn() {
        // A solo/uncontended write: the turn is free, so we take it and proceed,
        // announcing the claim with a request — no deadlock without a grantor.
        let mut t = WriteTurn::whole_subtree();
        let action = decide_turn_gate(&mut t, &id_bytes(1), 100, 100);
        assert_eq!(action, TurnGateAction::ProceedRequest { seq: 100 });
        assert!(t.is_held_by(&id_bytes(1)));
    }

    #[test]
    fn commit_gate_proceeds_while_we_hold_with_no_waiters() {
        // We already hold the lease: a follow-up commit proceeds and keeps the
        // turn — a bursty writer isn't forced to re-handshake every commit.
        let mut t = WriteTurn::whole_subtree();
        t.apply_yield(id_bytes(1), 100);
        let action = decide_turn_gate(&mut t, &id_bytes(1), 200, 200);
        assert_eq!(action, TurnGateAction::Proceed);
        assert!(t.is_held_by(&id_bytes(1)));
    }

    #[test]
    fn commit_gate_yields_at_the_boundary_when_a_peer_is_queued() {
        // THE slice test at the daemon layer — "a holder yields only at a commit
        // boundary": we hold, a peer requested behind us, so this commit flushes
        // and then yields, naming the FIFO winner + the seq it requested with (for
        // the signed `turn-yield`). A mid-edit never triggers this; only a boundary.
        let mut t = WriteTurn::whole_subtree();
        t.apply_yield(id_bytes(1), 100); // we hold
        t.request(id_bytes(2), 150); // a peer queues mid-hold
        let action = decide_turn_gate(&mut t, &id_bytes(1), 200, 200);
        assert_eq!(
            action,
            TurnGateAction::ProceedYield {
                grantee: id_bytes(2),
                seq: 150,
            }
        );
        // Released at the boundary (the yield hands the turn on); the ref advance
        // still proceeded — we flushed this commit first.
        assert!(!t.is_held_by(&id_bytes(1)));
    }

    #[test]
    fn commit_gate_defers_when_a_peer_holds_a_live_turn() {
        // A peer holds a live lease: we must NOT advance the shared ref (quiesce).
        // We request the turn (so the holder yields at its next boundary) + defer;
        // the watcher's requeue-retry lands the staged write once we're granted.
        let mut t = WriteTurn::whole_subtree();
        t.apply_yield(id_bytes(2), 100); // peer holds, deadline 100+30=130
        let action = decide_turn_gate(&mut t, &id_bytes(1), 120, 120); // 120 < 130 → live
        assert_eq!(action, TurnGateAction::Defer { seq: 120 });
        assert!(t.is_held_by(&id_bytes(2))); // peer still holds
        assert_eq!(t.next_in_line(), Some(id_bytes(1))); // we're queued behind it
    }

    #[test]
    fn commit_gate_takes_over_an_expired_peer_lease() {
        // The peer's lease has expired (crash/partition): the boundary poll revokes
        // it and grants us, so we proceed — no write is stuck behind a dead holder.
        let mut t = WriteTurn::whole_subtree();
        t.apply_yield(id_bytes(2), 0); // peer granted at 0, deadline 30
        let action = decide_turn_gate(&mut t, &id_bytes(1), 100, 100); // long past 30
        assert_eq!(action, TurnGateAction::ProceedRequest { seq: 100 });
        assert!(t.is_held_by(&id_bytes(1)));
    }

    /// The part-3a activity-window derivation: a recent local write reads as
    /// `OnlineActive`, a stale one (or none) as `OnlineIdle`. `Offline` is never
    /// produced here — it is the locked floor, set by the lifecycle.
    #[test]
    fn active_or_idle_reflects_the_write_window() {
        // No write since unlock → idle.
        assert_eq!(active_or_idle(None), DeviceState::OnlineIdle);
        // A write just now (and one right at the far edge) → active.
        assert_eq!(
            active_or_idle(Some(Duration::from_secs(0))),
            DeviceState::OnlineActive
        );
        assert_eq!(
            active_or_idle(Some(WRITE_ACTIVITY_WINDOW - Duration::from_secs(1))),
            DeviceState::OnlineActive
        );
        // At/after the window boundary the active hint has decayed → idle.
        assert_eq!(
            active_or_idle(Some(WRITE_ACTIVITY_WINDOW)),
            DeviceState::OnlineIdle
        );
        assert_eq!(
            active_or_idle(Some(WRITE_ACTIVITY_WINDOW + Duration::from_secs(60))),
            DeviceState::OnlineIdle
        );
    }

    /// Part 3 receive-boundary decision (`active_receiver_must_yield`): an
    /// ONLINE-ACTIVE receiver holding the chain's turn must yield it *before*
    /// applying an inbound edit (else the apply races our own held-turn commit); an
    /// ONLINE-IDLE holder — and an active receiver that does *not* hold the turn
    /// (its staged write already deferred behind the turn it lacks) — apply
    /// immediately, no handshake.
    #[test]
    fn active_holder_yields_before_apply_idle_and_non_holder_do_not() {
        let local = id_bytes(1);
        // We hold the turn (mid-authoring): active → yield first, idle → apply now.
        let mut held = WriteTurn::whole_subtree();
        held.apply_yield(local, 0);
        assert!(held.is_held_by(&local));
        assert!(active_receiver_must_yield(
            DeviceState::OnlineActive,
            &held,
            &local
        ));
        assert!(!active_receiver_must_yield(
            DeviceState::OnlineIdle,
            &held,
            &local
        ));
        // A PEER holds the turn (our write is deferred behind it) → nothing of ours
        // to race, so an active receiver applies immediately.
        let mut peer_held = WriteTurn::whole_subtree();
        peer_held.apply_yield(id_bytes(2), 0);
        assert!(!active_receiver_must_yield(
            DeviceState::OnlineActive,
            &peer_held,
            &local
        ));
        // Free turn, no holder → nothing to yield even while active.
        let free = WriteTurn::whole_subtree();
        assert!(!active_receiver_must_yield(
            DeviceState::OnlineActive,
            &free,
            &local
        ));
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
    // --- M5d slice 001 CHUNK B1: the shared-key ceremony wiring --------------

    use softfig_net::static_attestation_message;

    const CEREMONY_PASS: &str = "pw-test-12345";

    /// An unlocked daemon on the unmounted-FUSE attach seam (the m5c/m5d
    /// harness): handlers are called directly, no serve loop, no kernel mount.
    fn ceremony_daemon() -> (Daemon, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let mut params = softfig_vault::params::VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let (_v, session, _r) =
            softfig_vault::Vault::init_with_params(tmp.path(), CEREMONY_PASS.as_bytes(), params)
                .unwrap();
        softfig_vcs::Repo::init(tmp.path(), &session).unwrap();
        drop(session);
        let daemon = Daemon::new(
            KeeperConfig::new(tmp.path())
                .without_watcher()
                .with_unmounted_fuse_attach(),
        );
        let reply = crate::handlers::unlock(
            &daemon,
            serde_json::json!({ "passphrase": CEREMONY_PASS }),
        );
        assert!(reply.is_ok(), "unlock: {reply:?}");
        (daemon, tmp)
    }

    fn device_of(daemon: &Daemon, name: &str) -> LocalDevice {
        let inner = daemon.inner.lock().unwrap();
        build_local_device(inner.session.as_ref().unwrap(), name.to_string())
    }

    /// A real ring row for a live daemon: its actual identity + transport keys
    /// and a genuine attestation, so `Ring::load` (which verifies) accepts it.
    fn ring_entry_of(daemon: &Daemon, name: &str, endpoints: Vec<String>) -> RingEntry {
        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let transport_pubkey = session.transport_pubkey();
        RingEntry {
            device_id: session.identity_pubkey().to_bytes(),
            name: name.into(),
            transport_pubkey,
            endpoints,
            attestation: session
                .sign(&static_attestation_message(&transport_pubkey))
                .to_bytes(),
            paired_at: 1,
        }
    }

    /// A forged (non-live) ring member with a self-consistent attestation —
    /// enough to pass `Ring::load`'s verification without a daemon behind it.
    fn forged_peer(seed: u8) -> RingEntry {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let transport_pubkey = [seed ^ 0xFF; 32];
        RingEntry {
            device_id: sk.verifying_key().to_bytes(),
            name: format!("peer-{seed}"),
            transport_pubkey,
            endpoints: vec![],
            attestation: sk
                .sign(&static_attestation_message(&transport_pubkey))
                .to_bytes(),
            paired_at: 1,
        }
    }

    /// End to end over loopback TCP with real Noise and real vaults: A adds a
    /// shared subtree (row lands with `key_id` empty — the locked liveness
    /// default), the reconcile sweep dials B through the production route
    /// model, both sides drive the commit-reveal ceremony through the real
    /// inbound dispatch, and both persist — `S` sealed in each vault, a
    /// committed `shared_ceremony` record on each device chain, and A's
    /// membership row `key_id` filled. The pre-live stand-in for the deferred
    /// 2-device smoke.
    #[test]
    fn ceremony_end_to_end_over_loopback() {
        let (daemon_a, tmp_a) = ceremony_daemon();
        let (daemon_b, tmp_b) = ceremony_daemon();
        let local_a = device_of(&daemon_a, "dev-a");
        let local_b = device_of(&daemon_b, "dev-b");

        // B listens on an ephemeral loopback port; its ring holds A.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let ring_b = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(ring_entry_of(&daemon_a, "dev-a", vec![]));
            r
        }));
        let b_thread = {
            let daemon_b = daemon_b.clone();
            let local_b = local_b.clone();
            let ring_b = ring_b.clone();
            thread::spawn(move || {
                let (conn, _) = listener.accept().unwrap();
                serve_inbound(daemon_b, &local_b, &ring_b, conn);
            })
        };

        // A's persisted (legacy-path) ring holds B at the loopback endpoint,
        // where the sweep's `load_ring` finds it.
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(
                &daemon_b,
                "dev-b",
                vec![format!("127.0.0.1:{port}")],
            ));
            ring.save(&ring_path(tmp_a.path())).unwrap();
        }
        // B's committed ring holds A too, so B's responder-side persist clears
        // the M5d slice-013-pt2 member-set==ring gate (its `load_ring` reads the
        // legacy path at B's own state dir).
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(&daemon_a, "dev-a", vec![]));
            ring.save(&ring_path(tmp_b.path())).unwrap();
        }

        let add = crate::handlers::shared_subtree_add(
            &daemon_a,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();
        {
            // The add's row awaits its key — the deferred default, not a block.
            let inner = daemon_a.inner.lock().unwrap();
            let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
                inner.repo.as_ref().unwrap(),
                inner.session.as_ref().unwrap(),
            )
            .unwrap();
            assert!(membership.subtrees[0].key_id.is_none());
        }

        // The production initiator path (what the replica loop tick runs).
        reconcile_ceremonies(&daemon_a, &local_a);
        b_thread.join().unwrap();

        // A: key_id filled, S sealed, committed record re-verifies.
        let (kid, s_a) = {
            let inner = daemon_a.inner.lock().unwrap();
            let session = inner.session.as_ref().unwrap();
            let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
                inner.repo.as_ref().unwrap(),
                session,
            )
            .unwrap();
            let kid = membership.subtrees[0]
                .key_id
                .clone()
                .expect("ceremony filled the membership key_id");
            let s = *session.load_shared_key(&kid).expect("S sealed on A");
            let wt = WorkTree::new(&daemon_a, &inner);
            let text = wt
                .read_to_string(&crate::ceremony::ceremony_record_rel(&kid))
                .expect("A committed its record");
            let t = crate::ceremony::parse_transcript_record(&text).unwrap();
            assert!(t.verify());
            assert_eq!(t.key_id, kid);
            assert_eq!(t.chain_id, ref_name.as_bytes());
            (kid, s)
        };

        // B: the identical S under the same key_id, its own committed record,
        // and no membership row (it never ran `add`).
        {
            let inner = daemon_b.inner.lock().unwrap();
            let session = inner.session.as_ref().unwrap();
            let s_b = session.load_shared_key(&kid).expect("S sealed on B");
            assert_eq!(*s_b, s_a, "both members derived the identical S");
            let wt = WorkTree::new(&daemon_b, &inner);
            let text = wt
                .read_to_string(&crate::ceremony::ceremony_record_rel(&kid))
                .expect("B committed its record");
            assert!(crate::ceremony::parse_transcript_record(&text).unwrap().verify());
            let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
                inner.repo.as_ref().unwrap(),
                session,
            )
            .unwrap();
            assert!(membership.subtrees.is_empty());
        }
    }

    /// A stable non-live device id from a seed (a forged member's identity),
    /// matching `forged_peer(seed).device_id`.
    fn peer_id(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    /// A signing closure for a fabricated peer identified by seed: `peer_id(seed)`
    /// / `forged_peer(seed).device_id` is its pubkey, so it mints that peer's real
    /// ceremony signatures.
    fn seed_sign(seed: u8) -> impl Fn(&[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        move |m: &[u8]| sk.sign(m).to_bytes()
    }

    /// A signing closure for a live daemon: signs with its vault identity key, so
    /// a transcript entry for the daemon's own device id verifies (since slice 007
    /// persist checks both membership *and* the per-member signature).
    fn session_sign(daemon: &Daemon) -> impl Fn(&[u8]) -> [u8; 64] {
        let session = {
            let inner = daemon.inner.lock().unwrap();
            Arc::clone(inner.session.as_ref().unwrap())
        };
        move |m: &[u8]| session.sign(m).to_bytes()
    }

    /// A ceremony member for [`build_signed_transcript`]: `(device_id, r, sign)`,
    /// where `sign` mints that member's Ed25519 commit+reveal signature and
    /// `device_id` is the signer's pubkey.
    type SignedMember<'a> = ([u8; 32], [u8; 32], &'a dyn Fn(&[u8]) -> [u8; 64]);

    /// Build a fully-signed, verifying ceremony transcript for `chain` over the
    /// given members. Since slice 007 the transcript carries real signatures (a
    /// leave reduces a keyed 3-member state — v1 can't *establish* a 3-member key,
    /// so tests fabricate that starting state per
    /// [[decision-m5d-shared-rekey-intent]] option a — with each live member
    /// signed through its session and any forged member through its seed key).
    fn build_signed_transcript(
        nonce: [u8; 32],
        chain: &[u8],
        members: &[SignedMember<'_>],
    ) -> (SharedKey, Transcript) {
        use softfig_net::ceremony::{
            commit_signing_bytes, commitment, derive_shared_key, key_id, member_set_digest,
            reveal_signing_bytes, MemberContribution, TranscriptEntry,
        };
        let contributions: Vec<MemberContribution> = members
            .iter()
            .map(|(id, r, _)| MemberContribution { device_id: *id, r: *r })
            .collect();
        let s = derive_shared_key(&nonce, &contributions);
        // Slice 013: every commit/reveal signature binds the whole member set.
        let member_ids: Vec<[u8; 32]> = members.iter().map(|(id, _, _)| *id).collect();
        let msd = member_set_digest(&member_ids);
        let entries = members
            .iter()
            .map(|(id, r, sign)| {
                let comm = commitment(&nonce, id, r);
                TranscriptEntry {
                    device_id: *id,
                    commitment: comm,
                    r: *r,
                    commit_sig: sign(&commit_signing_bytes(&nonce, chain, &msd, id, &comm)),
                    reveal_sig: sign(&reveal_signing_bytes(&nonce, chain, &msd, id, r)),
                }
            })
            .collect();
        let transcript = Transcript {
            nonce,
            chain_id: chain.to_vec(),
            members: entries,
            key_id: key_id(&s),
        };
        assert!(transcript.verify());
        (s, transcript)
    }

    /// M5d slice 016 (ROTATE-2) — the establishment/recovery detector re-drives
    /// a keyed row whose sealed `S` went unusable. An unkeyed row is always a
    /// candidate (establishment); a keyed row with usable `S` is left alone; a
    /// keyed row whose `S` was deleted (stand-in for bit-rot / torn write) re-
    /// enters the dial set so a keyed peer can hand `S` back and persist re-seals
    /// it — closing the "keyed but locked out forever" gap.
    #[test]
    fn chains_awaiting_key_redrives_a_keyed_row_whose_s_is_unusable() {
        let (daemon, tmp) = ceremony_daemon();
        let local = device_of(&daemon, "dev-b");
        let peer = forged_peer(2);
        // Committed ring == the transcript member set, so persist's slice-013-pt2
        // ring-equality gate passes.
        {
            let mut ring = Ring::default();
            ring.upsert(peer.clone());
            ring.save(&ring_path(tmp.path())).unwrap();
        }
        let add = crate::handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // Unkeyed → always an establishment candidate.
        {
            let inner = daemon.inner.lock().unwrap();
            let (session, repo) =
                (inner.session.as_ref().unwrap(), inner.repo.as_ref().unwrap());
            assert!(
                chains_awaiting_key(repo, session).unwrap().contains(&ref_name),
                "an unkeyed row awaits establishment"
            );
        }

        // Key the row + seal S through the real persist path.
        let self_sign = session_sign(&daemon);
        let peer_sign = seed_sign(2);
        let (s, transcript) = build_signed_transcript(
            [8u8; 32],
            ref_name.as_bytes(),
            &[
                (local.device_id, [0x11u8; 32], &self_sign),
                (peer.device_id, [0x22u8; 32], &peer_sign),
            ],
        );
        let kid = transcript.key_id.clone();
        persist_ceremony_outcome(&daemon, &s, &transcript).expect("persist keys row + seals S");
        assert_eq!(row_key_id(&daemon, &ref_name).as_deref(), Some(kid.as_str()));

        // Keyed + usable S → NOT a candidate.
        {
            let inner = daemon.inner.lock().unwrap();
            let (session, repo) =
                (inner.session.as_ref().unwrap(), inner.repo.as_ref().unwrap());
            assert!(session.load_shared_key(&kid).is_ok(), "S usable after persist");
            assert!(
                !chains_awaiting_key(repo, session).unwrap().contains(&ref_name),
                "a keyed row with usable S is left alone"
            );
        }

        // The sealed S becomes unusable (deletion stands in for bit-rot / torn
        // write). ROTATE-2: the keyed row must re-enter the dial set.
        {
            let dir = tmp.path().join(".softfig/vault/shared-keys");
            for entry in std::fs::read_dir(&dir).expect("shared-keys dir") {
                std::fs::remove_file(entry.unwrap().path()).unwrap();
            }
        }
        {
            let inner = daemon.inner.lock().unwrap();
            let (session, repo) =
                (inner.session.as_ref().unwrap(), inner.repo.as_ref().unwrap());
            assert!(session.load_shared_key(&kid).is_err(), "S now unusable");
            assert!(
                chains_awaiting_key(repo, session).unwrap().contains(&ref_name),
                "ROTATE-2: a keyed-but-unusable-S row is re-driven through recovery"
            );
        }
    }

    /// The pure staleness predicate: order-insensitive set comparison of the
    /// committed transcript members against the current ring — the load-bearing
    /// both-sides rotation trigger.
    #[test]
    fn stale_iff_member_sets_differ() {
        let a = peer_id(1);
        let b = peer_id(2);
        let c = peer_id(3);
        // Same set, any order → not stale.
        assert!(!shared_chain_is_stale(&[a, b], &[b, a]));
        assert!(!shared_chain_is_stale(&[a, b, c], &[c, a, b]));
        // A leave (3→2) and a join (2→3) → stale.
        assert!(shared_chain_is_stale(&[a, b, c], &[a, b]));
        assert!(shared_chain_is_stale(&[a, b], &[a, b, c]));
        // A swap (same size, different member) → stale.
        assert!(shared_chain_is_stale(&[a, b], &[a, c]));
    }

    /// The detection half of `reconcile_rekeys`, exercised without a live peer:
    /// a keyed chain whose committed 3-member transcript no longer matches the
    /// current ring is reported stale; the same chain measured against its own
    /// 3-member set is not; and an unkeyed chain is never reported (that is
    /// establishment's job). This drives the real reader + staleness path over
    /// committed daemon state.
    #[test]
    fn stale_keyed_chains_detects_a_departed_member() {
        let (daemon, tmp) = ceremony_daemon();
        let our_id = {
            let inner = daemon.inner.lock().unwrap();
            inner.session.as_ref().unwrap().identity_pubkey().to_bytes()
        };

        let add = crate::handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // The committed ring names peer9 + peer10, so the 3-member establishment
        // persist below clears the M5d slice-013-pt2 member-set==ring gate. (The
        // staleness checks that follow pass explicit member arrays, so they are
        // unaffected by the committed ring.)
        {
            let mut ring = Ring::default();
            ring.upsert(forged_peer(9));
            ring.upsert(forged_peer(10));
            ring.save(&ring_path(tmp.path())).unwrap();
        }

        // Key it with a fabricated (signed) 3-member outcome {self, peer9, peer10}.
        let self_sign = session_sign(&daemon);
        let sign9 = seed_sign(9);
        let sign10 = seed_sign(10);
        let (s, t) = build_signed_transcript(
            [7u8; 32],
            ref_name.as_bytes(),
            &[
                (our_id, [0x11u8; 32], &self_sign),
                (peer_id(9), [0x22u8; 32], &sign9),
                (peer_id(10), [0x33u8; 32], &sign10),
            ],
        );
        persist_ceremony_outcome(&daemon, &s, &t).expect("key the chain");

        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();

        // Current ring dropped peer9 → {self, peer10}: the chain is stale.
        let after_leave = [our_id, peer_id(10)];
        assert_eq!(
            stale_keyed_chains(repo, session, &after_leave).unwrap(),
            vec![ref_name.clone()]
        );
        // Still the full set → not stale.
        let unchanged = [our_id, peer_id(9), peer_id(10)];
        assert!(stale_keyed_chains(repo, session, &unchanged).unwrap().is_empty());
    }

    /// End to end over loopback: a keyed shared chain whose membership went stale
    /// (a third member left) rotates through the production sweep + inbound
    /// responder. Both A and B hold a keyed 3-member row; the ring drops to
    /// {A, B}; A's `reconcile_rekeys` detects the staleness, dials B, both drive
    /// the ceremony, and both route the outcome to `rotate_shared_key` — so both
    /// converge on one fresh `S'`, A re-encrypts its chain blob under it, and the
    /// departed member's old `S` can no longer read post-rotation ciphertext. The
    /// pre-live stand-in for the deferred 2-device rotation smoke.
    #[test]
    fn rekey_end_to_end_over_loopback() {
        let (daemon_a, tmp_a) = ceremony_daemon();
        let (daemon_b, tmp_b) = ceremony_daemon();
        let local_a = device_of(&daemon_a, "dev-a");
        let local_b = device_of(&daemon_b, "dev-b");

        // Both devices add the shared subtree → both get a row for the same
        // ref_name (the mount path derives it deterministically).
        let add_a = crate::handlers::shared_subtree_add(
            &daemon_a,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add a");
        let ref_name = add_a["ref_name"].as_str().unwrap().to_string();
        let add_b = crate::handlers::shared_subtree_add(
            &daemon_b,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add b");
        assert_eq!(add_b["ref_name"].as_str().unwrap(), ref_name);

        // Fabricate a keyed 3-member state {A, B, C} on both (C is the member who
        // will "leave"). Persist fills each row's key_id, seals S1, commits the
        // transcript — the pre-rotation live state.
        let c_id = forged_peer(3).device_id;
        let sign_a = session_sign(&daemon_a);
        let sign_b = session_sign(&daemon_b);
        let sign_c = seed_sign(3);
        let (s1, t1) = build_signed_transcript(
            [7u8; 32],
            ref_name.as_bytes(),
            &[
                (local_a.device_id, [0x11u8; 32], &sign_a),
                (local_b.device_id, [0x22u8; 32], &sign_b),
                (c_id, [0x33u8; 32], &sign_c),
            ],
        );
        // Establishment ring: both A and B commit the full pre-rotation set
        // {A, B, C} (C = forged peer 3), so each side's persist clears the M5d
        // slice-013-pt2 member-set==ring gate. The ring shrinks to {A, B} below
        // when "C leaves", which is what makes the chain stale for rotation.
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(&daemon_b, "dev-b", vec![]));
            ring.upsert(forged_peer(3));
            ring.save(&ring_path(tmp_a.path())).unwrap();
        }
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(&daemon_a, "dev-a", vec![]));
            ring.upsert(forged_peer(3));
            ring.save(&ring_path(tmp_b.path())).unwrap();
        }
        persist_ceremony_outcome(&daemon_a, &s1, &t1).expect("key a");
        persist_ceremony_outcome(&daemon_b, &s1, &t1).expect("key b");
        let old_kid = t1.key_id.clone();

        // Seed a real blob on A's chain, sealed under S1 via the live router.
        {
            let mut inner = daemon_a.inner.lock().unwrap();
            let mut snap = softfig_vcs::WalkSnapshot::empty();
            snap.insert_file(std::path::Path::new("note.md"), 0o644, b"shared secret".to_vec())
                .unwrap();
            crate::actions::commit_snapshot_to_now(
                &mut inner,
                &ref_name,
                snap,
                Intent::new("shared_subtrees_changed", serde_json::json!({ "summary": "seed" }))
                    .unwrap(),
            )
            .expect("seed blob");
        }

        // C leaves: the current ring is {A, B}. B listens on loopback; its ring
        // holds A. A's persisted ring holds B at the loopback endpoint.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let ring_b = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(ring_entry_of(&daemon_a, "dev-a", vec![]));
            r
        }));
        let b_thread = {
            let daemon_b = daemon_b.clone();
            let local_b = local_b.clone();
            let ring_b = ring_b.clone();
            thread::spawn(move || {
                let (conn, _) = listener.accept().unwrap();
                serve_inbound(daemon_b, &local_b, &ring_b, conn);
            })
        };
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(
                &daemon_b,
                "dev-b",
                vec![format!("127.0.0.1:{port}")],
            ));
            ring.save(&ring_path(tmp_a.path())).unwrap();
        }
        // B's committed ring shrinks to {A} too, so B independently sees the
        // 3-member chain as stale (`shared_chain_is_stale`) and authorizes the
        // rotation the responder is asked to drive.
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(&daemon_a, "dev-a", vec![]));
            ring.save(&ring_path(tmp_b.path())).unwrap();
        }

        // Pre-seed A's tie-break clock as if it had seen the chain stale a prior
        // tick, so it initiates this tick regardless of device-id ordering (the
        // ids are random per vault). This is exactly the second-tick state.
        {
            let mut inner = daemon_a.inner.lock().unwrap();
            inner.rekey_seen_stale.insert(ref_name.clone());
        }

        // The production initiator path (what the replica loop tick runs).
        reconcile_rekeys(&daemon_a, &local_a);
        b_thread.join().unwrap();

        // A: the row now carries a fresh key (≠ old), a shared_rekey record
        // landed, and the chain blob is re-encrypted under S' (its container names
        // the new key, so a departed old-S-only holder can't read it), still
        // decrypting to the original plaintext.
        let new_kid = {
            let inner = daemon_a.inner.lock().unwrap();
            let session = inner.session.as_ref().unwrap();
            let repo = inner.repo.as_ref().unwrap();
            let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
                repo, session,
            )
            .unwrap();
            let kid = membership
                .subtrees
                .iter()
                .find(|r| r.ref_name == ref_name)
                .unwrap()
                .key_id
                .clone()
                .expect("A's row is keyed");
            assert_ne!(kid, old_kid, "A rotated to a fresh key");
            assert!(session.has_shared_key(&old_kid), "old S retained (custody limit)");
            assert!(session.has_shared_key(&kid), "new S' sealed");

            let tip = repo.tip_of(&ref_name).unwrap().unwrap();
            let root = repo.db().get_commit(&tip).unwrap().root_tree;
            let entry = repo
                .db()
                .get_tree(&root)
                .unwrap()
                .into_iter()
                .find(|e| e.name == "note.md")
                .unwrap();
            let cipher = repo.objects().get(&entry.target).unwrap();
            assert_eq!(
                softfig_vault::shared::read_key_id(&cipher).unwrap(),
                kid,
                "blob re-encrypted under S'"
            );
            assert_eq!(
                session
                    .decrypt_tracked_blob("projects/journals/note.md", &cipher)
                    .unwrap(),
                b"shared secret"
            );
            kid
        };

        // B: converged on the identical S' and flipped its own row to it.
        {
            let inner = daemon_b.inner.lock().unwrap();
            let session = inner.session.as_ref().unwrap();
            let repo = inner.repo.as_ref().unwrap();
            assert!(session.has_shared_key(&new_kid), "B sealed the same S'");
            let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
                repo, session,
            )
            .unwrap();
            assert_eq!(
                membership
                    .subtrees
                    .iter()
                    .find(|r| r.ref_name == ref_name)
                    .unwrap()
                    .key_id
                    .as_deref(),
                Some(new_kid.as_str()),
                "B's row rotated to S' too"
            );
        }
    }

    /// End to end over loopback: the M5d slice-008 recovery hand-off closes a
    /// stranded-responder gap with no manual step. A ceremony ran, A persisted
    /// (keyed), but B's persist failed — B is left a transcript member with an
    /// unkeyed row and no `S` (crash boundary A). B's `reconcile_ceremonies`
    /// re-dials (its row is unkeyed); A, holding a live non-stale key that names
    /// B, serves the hand-off instead of refusing (slice 006); B verifies +
    /// persists it and ends holding the same `S`. The pre-live stand-in for the
    /// deferred 2-device kill-9-mid-persist smoke.
    #[test]
    fn handoff_recovers_a_stranded_member_over_loopback() {
        let (daemon_a, tmp_a) = ceremony_daemon();
        let (daemon_b, tmp_b) = ceremony_daemon();
        let local_a = device_of(&daemon_a, "dev-a");
        let local_b = device_of(&daemon_b, "dev-b");
        // A's committed ring holds B, so A's establishment persist below clears
        // the M5d slice-013-pt2 member-set==ring gate (A is the keyed peer that
        // later serves the recovery hand-off).
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(&daemon_b, "dev-b", vec![]));
            ring.save(&ring_path(tmp_a.path())).unwrap();
        }

        // Both devices add the shared subtree → both get an unkeyed row for the
        // same ref_name (the mount path derives it deterministically).
        let add_a = crate::handlers::shared_subtree_add(
            &daemon_a,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add a");
        let ref_name = add_a["ref_name"].as_str().unwrap().to_string();
        let add_b = crate::handlers::shared_subtree_add(
            &daemon_b,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add b");
        assert_eq!(add_b["ref_name"].as_str().unwrap(), ref_name);

        // Key ONLY A with a fabricated (signed) 2-member {A, B} outcome; B never
        // persists, so it is the stranded responder — unkeyed row, no S (the
        // crash-boundary-A state the hand-off exists to heal).
        let sign_a = session_sign(&daemon_a);
        let sign_b = session_sign(&daemon_b);
        let (s, t) = build_signed_transcript(
            [7u8; 32],
            ref_name.as_bytes(),
            &[
                (local_a.device_id, [0x11u8; 32], &sign_a),
                (local_b.device_id, [0x22u8; 32], &sign_b),
            ],
        );
        persist_ceremony_outcome(&daemon_a, &s, &t).expect("key a");
        let expected_kid = t.key_id.clone();

        // Precondition: B really is stranded — its row is unkeyed and it holds no
        // usable S (the honest `load_shared_key` probe, not `has_shared_key`).
        {
            let inner = daemon_b.inner.lock().unwrap();
            let session = inner.session.as_ref().unwrap();
            let repo = inner.repo.as_ref().unwrap();
            assert!(session.load_shared_key(&expected_kid).is_err(), "B starts without S");
            let membership =
                crate::handlers::read_committed_shared_subtrees_for_mutation(repo, session)
                    .unwrap();
            assert!(
                membership
                    .subtrees
                    .iter()
                    .find(|r| r.ref_name == ref_name)
                    .unwrap()
                    .key_id
                    .is_none(),
                "B's row is unkeyed"
            );
        }

        // A holds the key + listens; its ring holds B. B's persisted ring holds A
        // at the loopback endpoint (so its reconcile sweep dials A).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let ring_a = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(ring_entry_of(&daemon_b, "dev-b", vec![]));
            r
        }));
        let a_thread = {
            let daemon_a = daemon_a.clone();
            let local_a = local_a.clone();
            let ring_a = ring_a.clone();
            thread::spawn(move || {
                let (conn, _) = listener.accept().unwrap();
                serve_inbound(daemon_a, &local_a, &ring_a, conn);
            })
        };
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(
                &daemon_a,
                "dev-a",
                vec![format!("127.0.0.1:{port}")],
            ));
            ring.save(&ring_path(tmp_b.path())).unwrap();
        }

        // Pre-seed B's tie-break clock as if it had seen the chain pending a prior
        // tick, so it initiates this tick regardless of device-id ordering.
        {
            let mut inner = daemon_b.inner.lock().unwrap();
            inner.ceremony_seen_pending.insert(ref_name.clone());
        }

        // The production initiator sweep on the stranded device.
        reconcile_ceremonies(&daemon_b, &local_b);
        a_thread.join().unwrap();

        // B recovered: its row is now keyed with A's key_id, it holds the same
        // usable S, and it committed its own ceremony record — no manual step.
        let inner = daemon_b.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        let membership =
            crate::handlers::read_committed_shared_subtrees_for_mutation(repo, session).unwrap();
        assert_eq!(
            membership
                .subtrees
                .iter()
                .find(|r| r.ref_name == ref_name)
                .unwrap()
                .key_id
                .as_deref(),
            Some(expected_kid.as_str()),
            "B's row keyed via the hand-off"
        );
        assert!(
            session.load_shared_key(&expected_kid).is_ok(),
            "B now holds usable S"
        );
        assert!(
            crate::handlers::read_committed_transcript(repo, session, &expected_kid)
                .unwrap()
                .is_some(),
            "B committed the ceremony record"
        );
    }

    /// M5d slice 008 crash-boundary B: a member that sealed `S` but crashed
    /// before committing (S present on disk, row still unkeyed) recovers
    /// idempotently. `accept_handoff` re-seals the same `S` (a no-op) and commits
    /// the record + fills the row — no duplicate key, no wedge, exactly one
    /// sealed key. Exercises the accept path directly (the loopback test covers
    /// boundary A, where `S` is absent).
    #[test]
    fn accept_handoff_is_idempotent_when_s_already_sealed() {
        let (daemon, tmp) = ceremony_daemon();
        let local = device_of(&daemon, "dev-b");
        let peer = forged_peer(2);
        // The committed ring holds the peer, so `accept_handoff`'s persist clears
        // the M5d slice-013-pt2 member-set==ring gate.
        {
            let mut ring = Ring::default();
            ring.upsert(peer.clone());
            ring.save(&ring_path(tmp.path())).unwrap();
        }

        let add = crate::handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // A valid signed {this device, peer} transcript for the chain.
        let self_sign = session_sign(&daemon);
        let peer_sign = seed_sign(2);
        let (s, transcript) = build_signed_transcript(
            [8u8; 32],
            ref_name.as_bytes(),
            &[
                (local.device_id, [0x11u8; 32], &self_sign),
                (peer.device_id, [0x22u8; 32], &peer_sign),
            ],
        );
        let kid = transcript.key_id.clone();

        // Boundary B: seal S, but leave the row unkeyed (crash before commit).
        {
            let inner = daemon.inner.lock().unwrap();
            inner
                .session
                .as_ref()
                .unwrap()
                .store_shared_key(&kid, s.expose())
                .expect("pre-seal S");
        }
        assert!(row_key_id(&daemon, &ref_name).is_none(), "row still unkeyed");

        // The hand-off frame the keyed peer would send, carrying the same S.
        let handoff = SharedKeyHandoff {
            chain_id: ref_name.clone().into_bytes(),
            transcript_record: crate::ceremony::render_transcript_record(&transcript).unwrap(),
            shared_key: s.expose().to_vec(),
        };
        let recovered = accept_handoff(&daemon, &ref_name, handoff).expect("accept hand-off");
        assert_eq!(recovered, kid);

        // Row filled, record committed, S still the single sealed key.
        assert_eq!(row_key_id(&daemon, &ref_name).as_deref(), Some(kid.as_str()));
        let inner = daemon.inner.lock().unwrap();
        let session = inner.session.as_ref().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        assert!(session.load_shared_key(&kid).is_ok());
        assert!(
            crate::handlers::read_committed_transcript(repo, session, &kid)
                .unwrap()
                .is_some()
        );
    }

    /// The initiator sweep gates a >2-member ring (v1 is point-to-point): the
    /// row stays pending, nothing dials, nothing is stored.
    #[test]
    fn ceremony_sweep_gates_three_member_rings() {
        let (daemon, tmp) = ceremony_daemon();
        let local = device_of(&daemon, "dev-a");
        {
            let mut ring = Ring::default();
            ring.upsert(forged_peer(1));
            ring.upsert(forged_peer(2));
            ring.save(&ring_path(tmp.path())).unwrap();
        }
        crate::handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");

        reconcile_ceremonies(&daemon, &local);

        let inner = daemon.inner.lock().unwrap();
        let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
            inner.repo.as_ref().unwrap(),
            inner.session.as_ref().unwrap(),
        )
        .unwrap();
        assert!(membership.subtrees[0].key_id.is_none());
        assert!(!tmp.path().join(".softfig/vault/shared-keys").exists());
    }

    /// With no paired peer the sweep is a quiet no-op (the normal
    /// share-before-pairing state) — the row simply waits.
    #[test]
    fn ceremony_sweep_waits_for_a_peer() {
        let (daemon, tmp) = ceremony_daemon();
        let local = device_of(&daemon, "dev-a");
        crate::handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");

        reconcile_ceremonies(&daemon, &local);

        let inner = daemon.inner.lock().unwrap();
        let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
            inner.repo.as_ref().unwrap(),
            inner.session.as_ref().unwrap(),
        )
        .unwrap();
        assert!(membership.subtrees[0].key_id.is_none());
        assert!(!tmp.path().join(".softfig/vault/shared-keys").exists());
    }

    /// The responder refuses a ceremony when its own ring says >2 members —
    /// the member set comes from the ring, never the wire.
    #[test]
    fn responder_gates_three_member_rings() {
        let (daemon, tmp) = ceremony_daemon();
        let local = device_of(&daemon, "dev-b");
        let ring = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(forged_peer(1));
            r.upsert(forged_peer(2));
            r
        }));

        struct DeadLink;
        impl CeremonyLink for DeadLink {
            fn send_frame(&mut self, _f: &Frame) -> Result<(), NetError> {
                Ok(())
            }
            fn recv_frame(&mut self) -> Result<Frame, NetError> {
                Err(NetError::Protocol("gated responder must not drive the link"))
            }
        }
        let commit = SharedKeyCommit {
            nonce: vec![7u8; 32],
            chain_id: b"chain/journals".to_vec(),
            device_id: vec![0u8; 32],
            commitment: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        serve_ceremony_responder(&daemon, &local, &forged_peer(1), &ring, commit, DeadLink);
        assert!(!tmp.path().join(".softfig/vault/shared-keys").exists());
    }

    /// M5d slice 008: when the responder already holds a live, non-stale key for
    /// a chain and the *authenticated* requester is a member its committed
    /// transcript names, it serves a recovery HAND-OFF (the committed transcript
    /// plus `S`) rather than refusing (slice 006's refusal now covers only a
    /// non-member requester). It sends exactly one hand-off frame and never
    /// drives a ceremony (a capturing link that errors on `recv` proves it); its
    /// own committed state — the row's `key_id`, the tip — is untouched.
    #[test]
    fn responder_hands_off_s_to_a_stranded_member() {
        let (daemon, tmp) = ceremony_daemon();
        let local = device_of(&daemon, "dev-a");
        let peer = forged_peer(1);
        let ring = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(peer.clone());
            r
        }));
        // The committed ring holds the peer too, so the establishment persist
        // below clears the M5d slice-013-pt2 member-set==ring gate.
        {
            let mut disk_ring = Ring::default();
            disk_ring.upsert(peer.clone());
            disk_ring.save(&ring_path(tmp.path())).unwrap();
        }

        let add = crate::handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // Key the chain via a fabricated (signed) 2-member outcome over (this
        // device, the peer). `peer = forged_peer(1)` signs with seed key 1.
        let self_sign = session_sign(&daemon);
        let peer_sign = seed_sign(1);
        let (s, transcript) = build_signed_transcript(
            [7u8; 32],
            ref_name.as_bytes(),
            &[
                (local.device_id, [0x11u8; 32], &self_sign),
                (peer.device_id, [0x22u8; 32], &peer_sign),
            ],
        );
        persist_ceremony_outcome(&daemon, &s, &transcript).expect("key the chain");
        let keyed_tip = {
            let inner = daemon.inner.lock().unwrap();
            inner.repo.as_ref().unwrap().tip().unwrap().unwrap()
        };

        // A link that captures whatever the responder sends and refuses reads —
        // a hand-off sends one frame and never enters the ceremony recv loop.
        #[derive(Clone)]
        struct CaptureLink {
            sent: Arc<Mutex<Vec<Frame>>>,
        }
        impl CeremonyLink for CaptureLink {
            fn send_frame(&mut self, f: &Frame) -> Result<(), NetError> {
                self.sent.lock().unwrap().push(f.clone());
                Ok(())
            }
            fn recv_frame(&mut self) -> Result<Frame, NetError> {
                Err(NetError::Protocol("hand-off responder must not read the link"))
            }
        }
        let sent = Arc::new(Mutex::new(Vec::new()));
        let link = CaptureLink { sent: sent.clone() };

        // The stranded member (the peer, an authenticated ring `owner`) dials
        // with an ordinary commit; the responder answers with a hand-off.
        let commit = SharedKeyCommit {
            nonce: vec![9u8; 32],
            chain_id: ref_name.clone().into_bytes(),
            device_id: peer.device_id.to_vec(),
            commitment: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        serve_ceremony_responder(&daemon, &local, &peer, &ring, commit, link);

        // Exactly one hand-off frame went out, carrying the committed record + S.
        let frames = sent.lock().unwrap();
        assert_eq!(frames.len(), 1, "one hand-off frame, no ceremony driven");
        let Some(frame::Kind::SharedKeyHandoff(h)) = &frames[0].kind else {
            panic!("expected a hand-off frame, got {:?}", frames[0].kind);
        };
        assert_eq!(h.chain_id, ref_name.as_bytes());
        assert_eq!(h.shared_key, s.expose().to_vec(), "S served verbatim");
        let served = crate::ceremony::parse_transcript_record(&h.transcript_record)
            .expect("served record parses");
        assert_eq!(served.key_id, transcript.key_id);
        assert!(served.verify(), "served transcript verifies");
        drop(frames);

        // The responder's own state is untouched: same key, no new commit.
        let inner = daemon.inner.lock().unwrap();
        let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
            inner.repo.as_ref().unwrap(),
            inner.session.as_ref().unwrap(),
        )
        .unwrap();
        let row = membership
            .subtrees
            .iter()
            .find(|r| r.ref_name == ref_name)
            .expect("row");
        assert_eq!(row.key_id.as_deref(), Some(transcript.key_id.as_str()));
        assert_eq!(inner.repo.as_ref().unwrap().tip().unwrap().unwrap(), keyed_tip);
    }

    /// The committed membership row's `key_id` for a chain, if keyed.
    fn row_key_id(daemon: &Daemon, ref_name: &str) -> Option<String> {
        let inner = daemon.inner.lock().unwrap();
        let membership = crate::handlers::read_committed_shared_subtrees_for_mutation(
            inner.repo.as_ref().unwrap(),
            inner.session.as_ref().unwrap(),
        )
        .unwrap();
        membership
            .subtrees
            .iter()
            .find(|r| r.ref_name == ref_name)
            .and_then(|r| r.key_id.clone())
    }

    /// Slice 006 part 2 tie-break decision: the lexically-lower device_id
    /// initiates immediately; the higher device defers a *freshly*-pending chain
    /// (unseen in a prior pass) so the lower's ceremony lands first — but STILL
    /// initiates once it has seen the chain pending before, so the sole
    /// row-holder in the asymmetric flow (which may be the higher device) is
    /// never stranded (the hard constraint).
    #[test]
    fn tiebreak_lower_initiates_higher_defers_until_seen() {
        let low = id_bytes(1);
        let high = id_bytes(2);
        assert!(low < high);
        // Lower initiates immediately, seen before or not.
        assert!(should_initiate_now(&low, &high, false));
        assert!(should_initiate_now(&low, &high, true));
        // Higher defers a freshly-pending chain...
        assert!(!should_initiate_now(&high, &low, false));
        // ...but still initiates once it has seen the chain pending before.
        assert!(should_initiate_now(&high, &low, true));
    }

    /// Slice 006 part 2 in-flight dedup: while a ceremony for a chain is already
    /// running on this device (an initiator sweep leg, held here via a live
    /// [`CeremonyGuard`]), an inbound responder for the SAME chain is refused
    /// before the transport is ever driven (a `DeadLink` proves it) — one device
    /// never runs two concurrent ceremonies for one chain. Nothing is minted.
    #[test]
    fn responder_refuses_a_chain_with_a_ceremony_in_flight() {
        let (daemon, tmp) = ceremony_daemon();
        let local = device_of(&daemon, "dev-a");
        let peer = forged_peer(1);
        let ring = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(peer.clone());
            r
        }));
        let add = crate::handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();

        // An initiator leg is already in flight for this chain on this device.
        let guard = CeremonyGuard::try_acquire(&daemon, &ref_name).expect("acquire");
        let keyed_tip = {
            let inner = daemon.inner.lock().unwrap();
            inner.repo.as_ref().unwrap().tip().unwrap().unwrap()
        };

        struct DeadLink;
        impl CeremonyLink for DeadLink {
            fn send_frame(&mut self, _f: &Frame) -> Result<(), NetError> {
                Ok(())
            }
            fn recv_frame(&mut self) -> Result<Frame, NetError> {
                Err(NetError::Protocol("in-flight responder must not drive the link"))
            }
        }
        let commit = SharedKeyCommit {
            nonce: vec![9u8; 32],
            chain_id: ref_name.clone().into_bytes(),
            device_id: vec![0u8; 32],
            commitment: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        serve_ceremony_responder(&daemon, &local, &peer, &ring, commit, DeadLink);

        // The row is untouched, no key sealed, no new commit minted.
        assert!(row_key_id(&daemon, &ref_name).is_none());
        assert!(!tmp.path().join(".softfig/vault/shared-keys").exists());
        assert_eq!(
            daemon.inner.lock().unwrap().repo.as_ref().unwrap().tip().unwrap().unwrap(),
            keyed_tip
        );
        drop(guard);
    }

    /// M5d slice 017 / CORR-3: the responder refuses a rotation whose ceremony
    /// nonce **reuses** the live generation's salt. A keyed 3-member chain goes
    /// stale (a member left → current ring is 2), so an inbound commit for it is
    /// a rotation — but this one replays the establishment nonce (`[7u8; 32]`).
    /// The guard fires against committed state (the live transcript's nonce)
    /// *before* the ceremony is driven, so `run_ceremony` never broadcasts the
    /// responder's commitment: zero frames leave the link, and the row keeps its
    /// original key. A rotation under a *fresh* nonce would fall through to the
    /// transport and send that first frame — which is exactly what a live
    /// initiator (a fresh random nonce per session) always presents.
    #[test]
    fn responder_refuses_a_rotation_that_reuses_the_live_nonce() {
        let (daemon, tmp) = ceremony_daemon();
        let local = device_of(&daemon, "dev-a");
        let peer1 = forged_peer(1); // the requester (an authenticated ring owner)
        let peer2 = forged_peer(2); // the member who later "leaves"

        // Key a 3-member chain {local, peer1, peer2} under nonce [7u8; 32]. The
        // committed ring must equal that set at persist time (slice-013-pt2
        // member-set==ring gate), so seed {peer1, peer2} on disk before persist.
        {
            let mut disk_ring = Ring::default();
            disk_ring.upsert(peer1.clone());
            disk_ring.upsert(peer2.clone());
            disk_ring.save(&ring_path(tmp.path())).unwrap();
        }
        let add = crate::handlers::shared_subtree_add(
            &daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();
        let self_sign = session_sign(&daemon);
        let sign1 = seed_sign(1);
        let sign2 = seed_sign(2);
        let (s, transcript) = build_signed_transcript(
            [7u8; 32],
            ref_name.as_bytes(),
            &[
                (local.device_id, [0x11u8; 32], &self_sign),
                (peer1.device_id, [0x22u8; 32], &sign1),
                (peer2.device_id, [0x33u8; 32], &sign2),
            ],
        );
        persist_ceremony_outcome(&daemon, &s, &transcript).expect("key the chain");
        let keyed_kid = row_key_id(&daemon, &ref_name).expect("row is keyed");
        let keyed_tip = {
            let inner = daemon.inner.lock().unwrap();
            inner.repo.as_ref().unwrap().tip().unwrap().unwrap()
        };

        // Current ring drops peer2 → {local, peer1}: the chain is now stale, so
        // the inbound commit is treated as a rotation.
        let ring = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(peer1.clone());
            r
        }));

        // A link that records sends and refuses reads. A driven ceremony
        // broadcasts the responder's commitment *first* (`run_ceremony` step 1),
        // so any send here would mean the guard failed to fire.
        #[derive(Clone)]
        struct CaptureLink {
            sent: Arc<Mutex<Vec<Frame>>>,
        }
        impl CeremonyLink for CaptureLink {
            fn send_frame(&mut self, f: &Frame) -> Result<(), NetError> {
                self.sent.lock().unwrap().push(f.clone());
                Ok(())
            }
            fn recv_frame(&mut self) -> Result<Frame, NetError> {
                Err(NetError::Protocol("refused rotation must not drive the link"))
            }
        }
        let sent = Arc::new(Mutex::new(Vec::new()));
        let link = CaptureLink { sent: sent.clone() };

        // peer1 (an authenticated owner) dials with a commit that REUSES the
        // live nonce.
        let commit = SharedKeyCommit {
            nonce: vec![7u8; 32],
            chain_id: ref_name.clone().into_bytes(),
            device_id: peer1.device_id.to_vec(),
            commitment: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        serve_ceremony_responder(&daemon, &local, &peer1, &ring, commit, link);

        // The guard fired before the transport: nothing was sent, the row keeps
        // its original key, and no new commit landed.
        assert!(
            sent.lock().unwrap().is_empty(),
            "a nonce-reusing rotation is refused before the ceremony broadcasts"
        );
        assert_eq!(
            row_key_id(&daemon, &ref_name).as_deref(),
            Some(keyed_kid.as_str()),
            "the chain keeps its original key"
        );
        assert_eq!(
            daemon.inner.lock().unwrap().repo.as_ref().unwrap().tip().unwrap().unwrap(),
            keyed_tip,
            "no rotation was persisted"
        );
    }

    /// Slice 006 part 2 headline: **symmetric dual-add converges on ONE key**.
    /// Both devices add the same mount path, so both hold a pending row for the
    /// same `chain/<id>` and both sweeps reach the tie-break. Only the lower
    /// device initiates; the higher defers (and is filled as responder). Driven
    /// with the higher device's sweep run BOTH before and after the lower's, the
    /// two members converge on one `key_id` + identical `S`, with no divergence
    /// recorded on either side. The convergent-encryption invariant slice 002
    /// rests on now holds provably, not racily.
    #[test]
    fn symmetric_dual_add_converges_on_one_key() {
        let (daemon_a, tmp_a) = ceremony_daemon();
        let (daemon_b, tmp_b) = ceremony_daemon();
        let local_a = device_of(&daemon_a, "dev-a");
        let local_b = device_of(&daemon_b, "dev-b");

        // Orient by device_id: the lower initiates; the higher responds + defers.
        let (lower_daemon, lower_tmp, lower_local, higher_daemon, higher_tmp, higher_local) =
            if local_a.device_id < local_b.device_id {
                (&daemon_a, &tmp_a, &local_a, &daemon_b, &tmp_b, &local_b)
            } else {
                (&daemon_b, &tmp_b, &local_b, &daemon_a, &tmp_a, &local_a)
            };

        // Both add the same mount → both rows land pending for one ref_name.
        let add = crate::handlers::shared_subtree_add(
            lower_daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("lower add");
        let ref_name = add["ref_name"].as_str().unwrap().to_string();
        crate::handlers::shared_subtree_add(
            higher_daemon,
            serde_json::json!({ "mount_path": "projects/journals" }),
        )
        .expect("higher add");

        // The higher device is the responder: it listens on loopback, its
        // inbound ring holds the lower, and it serves one inbound connection.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let higher_inbound_ring = Arc::new(Mutex::new({
            let mut r = Ring::default();
            r.upsert(ring_entry_of(lower_daemon, "lower", vec![]));
            r
        }));
        let responder = {
            let higher_daemon = higher_daemon.clone();
            let higher_local = higher_local.clone();
            let ring = higher_inbound_ring.clone();
            thread::spawn(move || {
                let (conn, _) = listener.accept().unwrap();
                serve_inbound(higher_daemon, &higher_local, &ring, conn);
            })
        };

        // The lower's sweep-ring holds the higher at the real listener endpoint.
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(
                higher_daemon,
                "higher",
                vec![format!("127.0.0.1:{port}")],
            ));
            ring.save(&ring_path(lower_tmp.path())).unwrap();
        }
        // The higher's sweep-ring holds the lower with NO endpoint (no route),
        // so the higher reaches the tie-break (>=2 members) and — if its defer
        // were ever broken — could not hang the test by dialing.
        {
            let mut ring = Ring::default();
            ring.upsert(ring_entry_of(lower_daemon, "lower", vec![]));
            ring.save(&ring_path(higher_tmp.path())).unwrap();
        }

        // Higher sweeps FIRST: it defers the freshly-pending chain (unseen in a
        // prior pass) → no ceremony, both rows still unkeyed.
        reconcile_ceremonies(higher_daemon, higher_local);
        assert!(row_key_id(higher_daemon, &ref_name).is_none());
        assert!(!higher_tmp.path().join(".softfig/vault/shared-keys").exists());

        // Lower sweeps: it initiates the one ceremony; the higher serves it.
        reconcile_ceremonies(lower_daemon, lower_local);
        responder.join().unwrap();

        // Higher sweeps AGAIN (the "other order"): its row is now keyed → no-op.
        reconcile_ceremonies(higher_daemon, higher_local);

        // Converged: one key_id on both rows, identical S in both vaults.
        let lower_kid = row_key_id(lower_daemon, &ref_name).expect("lower keyed");
        let higher_kid = row_key_id(higher_daemon, &ref_name).expect("higher keyed");
        assert_eq!(lower_kid, higher_kid, "both members converged on one key_id");
        let s_lower = {
            let inner = lower_daemon.inner.lock().unwrap();
            *inner.session.as_ref().unwrap().load_shared_key(&lower_kid).expect("S lower")
        };
        let s_higher = {
            let inner = higher_daemon.inner.lock().unwrap();
            *inner.session.as_ref().unwrap().load_shared_key(&higher_kid).expect("S higher")
        };
        assert_eq!(s_lower, s_higher, "both members hold the identical S");
        assert!(daemon_a.inner.lock().unwrap().last_shared_key_divergence.is_none());
        assert!(daemon_b.inner.lock().unwrap().last_shared_key_divergence.is_none());
    }

}
