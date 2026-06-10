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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};
use softfig_net::discovery::{self, Advertisement};
use softfig_net::pairing::{pair_initiator, pair_responder, LocalDevice, PendingPair};
use softfig_net::proto::{frame, Frame};
use softfig_net::relay::Relay;
use softfig_net::ring::{ring_path, Ring, RingEntry};
use softfig_net::transport::{ik_responder, NoiseSession};
use softfig_net::{static_attestation_message, NetError};
use softfig_vault::VaultSession;

use crate::config::KeeperConfig;
use crate::daemon::Daemon;

/// How long a parked (initiator- or responder-side) pairing lives before it is
/// pruned. The user confirms the SAS out of band; this bounds the live socket a
/// parked pairing holds open so a half-finished pairing can't leak forever.
const PAIRING_TTL: Duration = Duration::from_secs(300);

/// Poll cadence for the interruptible accept / browse loops, so a lock (drop of
/// the runtime) is honoured promptly without a blocking accept.
const POLL_MS: u64 = 150;

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

// --- Ring persistence helpers (peers.toml is the source of truth) -----------

/// Upsert `entry` into the on-disk ring and persist it atomically.
pub fn persist_ring_entry(state_dir: &std::path::Path, entry: RingEntry) -> Result<(), NetError> {
    let path = ring_path(state_dir);
    let mut ring = Ring::load(&path)?;
    ring.upsert(entry);
    ring.save(&path)
}

/// Load the on-disk ring (an absent file is an empty ring).
pub fn load_ring(state_dir: &std::path::Path) -> Result<Ring, NetError> {
    Ring::load(&ring_path(state_dir))
}

// --- The live runtime: listener + mDNS + optional relay ---------------------

/// The live `softfig-net` host for an unlocked daemon. Dropping it stops every
/// thread (they poll the shutdown flag) and unregisters the mDNS service.
pub struct NetRuntime {
    /// The live ring, shared with the listener (IK authorization) and the
    /// browse loop (endpoint refresh). `peers.toml` on disk stays the source of
    /// truth; this mirror is kept in step by the pairing verbs.
    ring: Arc<Mutex<Ring>>,
    /// Discovery cache: fingerprint -> reachable `host:port` endpoints, filled
    /// by the browse loop. `pair_begin` consults it to resolve a fingerprint.
    discovery_cache: Arc<Mutex<HashMap<String, Vec<String>>>>,
    stop: Arc<AtomicBool>,
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
    /// to `unlock`.
    pub fn start(daemon: &Daemon, config: &KeeperConfig, local: LocalDevice) -> Self {
        let state_dir = config.state_dir().to_path_buf();
        let ring = Arc::new(Mutex::new(load_ring(&state_dir).unwrap_or_default()));
        let discovery_cache: Arc<Mutex<HashMap<String, Vec<String>>>> =
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
                    let ad = Advertisement {
                        device_id: local.device_id,
                        paired,
                        port: addr.port(),
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

        Self {
            ring,
            discovery_cache,
            stop,
            threads,
            mdns,
            listen_addr,
            relay_listen,
        }
    }

    /// Look up an endpoint for `fingerprint` (full or unique prefix) from the
    /// discovery cache. `None` ⇒ not currently discovered.
    pub fn resolve_endpoint(&self, fingerprint: &str) -> Option<String> {
        let cache = self.discovery_cache.lock().ok()?;
        // Exact match first, then a unique prefix.
        if let Some(eps) = cache.get(fingerprint) {
            return eps.first().cloned();
        }
        let mut hit = None;
        for (fp, eps) in cache.iter() {
            if fp.starts_with(fingerprint) {
                if hit.is_some() {
                    return None; // ambiguous prefix
                }
                hit = eps.first().cloned();
            }
        }
        hit
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
        // Established device: IK reconnect, authorize against the ring, echo.
        match ik_responder(conn, &local.transport_secret, &local.hello()) {
            Ok(session) => {
                if is_ring_member(ring, session.peer_static()) {
                    serve_echo(session);
                } else {
                    eprintln!("keeperd: net: rejecting reconnect from unknown transport key");
                }
            }
            Err(e) => eprintln!("keeperd: net: inbound IK handshake failed: {e}"),
        }
    }
}

/// Whether `transport_pubkey` belongs to a current ring member.
fn is_ring_member(ring: &Arc<Mutex<Ring>>, transport_pubkey: &[u8; 32]) -> bool {
    ring.lock()
        .map(|r| r.peers().iter().any(|p| &p.transport_pubkey == transport_pubkey))
        .unwrap_or(false)
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
    discovery_cache: Arc<Mutex<HashMap<String, Vec<String>>>>,
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
                            // Cache for `pair_begin` endpoint resolution (paired
                            // or not), then fold into a ring member if known.
                            if let Ok(mut cache) = discovery_cache.lock() {
                                cache.insert(peer.txt.fingerprint.clone(), peer.endpoints.clone());
                            }
                            let persist = {
                                let mut r = ring.lock().unwrap();
                                discovery::refresh_ring_endpoints(&mut r, &peer)
                            };
                            if persist {
                                let snapshot = ring.lock().unwrap().clone();
                                if let Err(e) = snapshot.save(&ring_path(&state_dir)) {
                                    eprintln!("keeperd: net: ring save after discovery: {e}");
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
