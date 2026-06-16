//! The zero-trust relay: off-LAN reachability without trusting the middle.
//!
//! Two NAT'd peers cannot connect directly, so each keeps a standing outbound
//! connection to an always-on **relay** (a ring member with a stable endpoint —
//! the home server). The relay bridges them. Crucially it is **blind**: there
//! are two layers of Noise.
//!
//! * **Outer** — each device ↔ relay control session ([`ik_initiator`] on the
//!   device, [`ik_responder`] here). It authenticates the device to the relay
//!   (ring-membership check, see [`Relay::authorize`]) and encrypts the relay
//!   control metadata. The relay terminates this layer.
//! * **Inner** — the end-to-end [`ik_initiator`]/[`ik_responder`] session
//!   *between the two peers*, tunnelled through a [`RelayStream`] that wraps the
//!   inner Noise wire bytes in [`Frame::relay_data`] frames. The relay forwards
//!   those payloads verbatim; it holds none of the inner keys and reads nothing.
//!
//! Authorization is by ring membership only — there is **no open relay**. A
//! device that is not in the relay's ring (or presents a transport key that does
//! not match its ring row) is rejected at [`Relay::serve`].
//!
//! Roles on a circuit, decided by the **first frame** after the outer handshake
//! (so a single read disambiguates without blocking a parked target):
//!
//! * [`StateAnnounce`](crate::proto::StateAnnounce) ⇒ "I am reachable." The
//!   relay parks the session keyed by device-id; the connecting peer drives it.
//! * [`RelayConnect`](crate::proto::RelayConnect) ⇒ "bridge me to `target`."
//!   The relay removes the parked target and splices the two sessions, forwarding
//!   [`RelayData`](crate::proto::RelayData) full-duplex until either side closes.
//!
//! A device that wants to be both reachable *and* an initiator opens two
//! connections (one parked, one initiating).
//!
//! **M5a scope / follow-ups (M5b):** parked registrations age out after
//! [`REGISTRATION_TTL`] (pruned lazily on the next register / connect / observe),
//! so a target whose connection died no longer lingers to be spliced as a corpse
//! by the next initiator; a still-reachable target simply re-announces to refresh
//! its slot (a standing keepalive/reconnect is still a follow-up). There is no
//! relay-side fairness/bandwidth limit; and the inner protocol here is
//! request/response, so full-duplex bulk throughput is untested (the split
//! forwarder supports it, but M5b's data plane should stress it).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::attest::{verify_static_attestation, KEY_LEN, SIG_LEN};
use crate::error::{NetError, Result};
use crate::pairing::LocalDevice;
use crate::proto::{frame, Frame, HelloPayload};
use crate::ring::Ring;
use crate::transport::{ik_initiator, ik_responder, NoiseReader, NoiseSession, NoiseWriter, SplitIo};

// --- Device side: the tunnel adapter + client entry points -----------------

/// A duplex byte stream that tunnels the **inner** end-to-end Noise session
/// through a device's **outer** relay control session. Writes become
/// [`Frame::relay_data`] frames; reads pull `RelayData` payloads back and serve
/// them as a contiguous byte stream (re-framing across `RelayData` boundaries is
/// transparent, since the relay preserves byte order). Used as the IO substrate
/// for [`ik_initiator`]/[`ik_responder`] on a relayed connection.
pub struct RelayStream<S> {
    outer: NoiseSession<S>,
    inbuf: Vec<u8>,
    pos: usize,
}

impl<S: Read + Write> RelayStream<S> {
    /// Wrap an established outer relay control session.
    pub fn new(outer: NoiseSession<S>) -> Self {
        Self {
            outer,
            inbuf: Vec::new(),
            pos: 0,
        }
    }
}

impl<S: Read + Write> Read for RelayStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.inbuf.len() {
            match self.outer.recv_frame().map_err(net_to_io)?.kind {
                Some(frame::Kind::RelayData(d)) => {
                    self.inbuf = d.payload;
                    self.pos = 0;
                }
                // Anything else on a spliced channel is a protocol error.
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "relay: expected RelayData on the tunnel",
                    ))
                }
            }
        }
        let n = (self.inbuf.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.inbuf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<S: Read + Write> Write for RelayStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outer
            .send_frame(&Frame::relay_data(buf.to_vec()))
            .map_err(net_to_io)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // send_frame already flushes the underlying stream per message.
        Ok(())
    }
}

/// Connect to the relay, register as reachable, and accept an incoming relayed
/// peer as the **inner** Noise IK *responder*. Blocks until a peer reaches us
/// through the relay (or the relay closes). Returns the end-to-end session.
///
/// `relay_static` is the relay's X25519 transport public key (known from having
/// paired with the relay). `local` is this device's transport material.
pub fn relay_accept<S: Read + Write>(
    relay_io: S,
    relay_static: &[u8; KEY_LEN],
    local: &LocalDevice,
) -> Result<NoiseSession<RelayStream<S>>> {
    let mut outer = ik_initiator(relay_io, &local.transport_secret, relay_static, &local.hello())?;
    outer.send_frame(&Frame::state_announce(local.device_id.to_vec(), true))?;
    let stream = RelayStream::new(outer);
    ik_responder(stream, &local.transport_secret, &local.hello())
}

/// Connect to the relay, ask it to bridge to `target_device_id`, and run the
/// **inner** Noise IK *initiator* end-to-end through the relay. `target_static`
/// is the target's X25519 transport key from our ring (keys the inner IK).
pub fn relay_connect<S: Read + Write>(
    relay_io: S,
    relay_static: &[u8; KEY_LEN],
    local: &LocalDevice,
    target_device_id: &[u8; KEY_LEN],
    target_static: &[u8; KEY_LEN],
) -> Result<NoiseSession<RelayStream<S>>> {
    let mut outer = ik_initiator(relay_io, &local.transport_secret, relay_static, &local.hello())?;
    outer.send_frame(&Frame::relay_connect(target_device_id.to_vec()))?;
    let stream = RelayStream::new(outer);
    ik_initiator(stream, &local.transport_secret, target_static, &local.hello())
}

// --- Relay side: authorize, park, splice -----------------------------------

/// How long a parked registration lives before it is pruned. A parked target
/// has no keepalive reader (its `serve` returns after parking), so a slot whose
/// connection died is otherwise indistinguishable from a live idle one; this
/// bounds how long a dead slot can linger before it ages out. Mirrors keeperd's
/// `PAIRING_TTL`. A still-reachable target re-announces to refresh its slot.
const REGISTRATION_TTL: Duration = Duration::from_secs(300);

/// A parked (reachable) registration: the parked outer session plus the instant
/// it was registered, so a stale slot can age out (see [`REGISTRATION_TTL`]).
struct Parked<S> {
    session: NoiseSession<S>,
    since: Instant,
}

/// A blind, ring-authorized relay. Generic over the stream type so it can run
/// over loopback `TcpStream` in production and any duplex stream in tests; the
/// accept loop ([`run`]) is `TcpStream`-specific.
pub struct Relay<S: SplitIo + Read + Write + Send + 'static> {
    relay_secret: [u8; KEY_LEN],
    relay_hello: HelloPayload,
    ring: Ring,
    registry: Mutex<HashMap<[u8; KEY_LEN], Parked<S>>>,
    registration_ttl: Duration,
}

impl<S: SplitIo + Read + Write + Send + 'static> Relay<S> {
    /// Build a relay that authorizes registrations against `ring`. `relay_device`
    /// supplies the relay's own X25519 transport secret and the identity hello
    /// for the outer handshake (keeperd assembles it from its vault in M5a-4).
    /// Parked registrations age out after [`REGISTRATION_TTL`].
    pub fn new(relay_device: &LocalDevice, ring: Ring) -> Arc<Self> {
        Self::new_with_ttl(relay_device, ring, REGISTRATION_TTL)
    }

    /// As [`new`](Self::new) but with an explicit parked-registration TTL. Mainly
    /// a tuning/test seam (a short TTL lets a stale-slot timeout be exercised
    /// without waiting [`REGISTRATION_TTL`]).
    pub fn new_with_ttl(relay_device: &LocalDevice, ring: Ring, registration_ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            relay_secret: relay_device.transport_secret,
            relay_hello: relay_device.hello(),
            ring,
            registry: Mutex::new(HashMap::new()),
            registration_ttl,
        })
    }

    /// Number of currently-parked (reachable) registrations, after pruning any
    /// that have aged out. Lets a caller/test observe that a target has
    /// registered before initiating to it.
    pub fn registered(&self) -> usize {
        let mut registry = self.registry.lock().unwrap();
        self.prune(&mut registry);
        registry.len()
    }

    /// Whether `device_id` is currently parked as reachable. Prunes first, so an
    /// aged-out (dead) slot is not reported as reachable.
    pub fn is_registered(&self, device_id: &[u8; KEY_LEN]) -> bool {
        let mut registry = self.registry.lock().unwrap();
        self.prune(&mut registry);
        registry.contains_key(device_id)
    }

    /// Drop parked registrations older than [`Self::registration_ttl`]. Lazy
    /// prune-on-access (run before every register, connect, and observe), so a
    /// parked target whose connection died ages out instead of being spliced as
    /// a corpse by the next initiator — no background thread, keeping the relay's
    /// blind, no-per-slot-reader model.
    fn prune(&self, registry: &mut HashMap<[u8; KEY_LEN], Parked<S>>) {
        registry.retain(|_, p| p.since.elapsed() < self.registration_ttl);
    }

    /// Serve one connection end-to-end: outer handshake, authorize against the
    /// ring, then dispatch on the first frame (register-and-park, or
    /// connect-and-splice). Returns when the circuit tears down or registration
    /// completes.
    pub fn serve(self: &Arc<Self>, io: S) -> Result<()> {
        let mut session = ik_responder(io, &self.relay_secret, &self.relay_hello)?;
        let device_id = self.authorize(session.peer_hello(), session.peer_static())?;

        match session.recv_frame()?.kind {
            Some(frame::Kind::StateAnnounce(_)) => {
                // Reachable target: park keyed by the authenticated device-id,
                // stamped with the registration time so a dead slot ages out
                // (prune-on-access) instead of lingering until an initiator
                // splices a corpse. The connecting peer's serve() removes and
                // drives it; a re-announce refreshes the slot (overwrites the key).
                let mut registry = self.registry.lock().unwrap();
                self.prune(&mut registry);
                registry.insert(
                    device_id,
                    Parked {
                        session,
                        since: Instant::now(),
                    },
                );
                Ok(())
            }
            Some(frame::Kind::RelayConnect(rc)) => {
                let target: [u8; KEY_LEN] = rc
                    .target_device_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| NetError::Protocol("relay target id wrong length"))?;
                let target_session = {
                    let mut registry = self.registry.lock().unwrap();
                    self.prune(&mut registry);
                    registry
                        .remove(&target)
                        .ok_or(NetError::Protocol("relay target not registered"))?
                        .session
                };
                splice(session, target_session)
            }
            _ => Err(NetError::Protocol("unexpected first relay frame")),
        }
    }

    /// Ring-membership authorization. The outer IK handshake already proved the
    /// peer holds the private key for `peer_static`; we require that the peer's
    /// claimed `device_id` is a ring member whose stored transport key *is*
    /// `peer_static`, and that the in-handshake attestation binds the two. No
    /// match ⇒ rejected (no open relay).
    fn authorize(
        &self,
        hello: &HelloPayload,
        peer_static: &[u8; KEY_LEN],
    ) -> Result<[u8; KEY_LEN]> {
        let device_id: [u8; KEY_LEN] = hello
            .device_id
            .as_slice()
            .try_into()
            .map_err(|_| NetError::Protocol("relay client device_id wrong length"))?;
        let attestation: [u8; SIG_LEN] = hello
            .static_attestation
            .as_slice()
            .try_into()
            .map_err(|_| NetError::Protocol("relay client attestation wrong length"))?;

        if !verify_static_attestation(&device_id, peer_static, &attestation) {
            return Err(NetError::Protocol("relay client attestation does not verify"));
        }
        match self.ring.get(&device_id) {
            Some(entry) if &entry.transport_pubkey == peer_static => Ok(device_id),
            Some(_) => Err(NetError::Protocol(
                "relay client transport key does not match its ring row",
            )),
            None => Err(NetError::Protocol("relay client is not a ring member")),
        }
    }
}

/// Run the relay accept loop over a TCP listener (production). Blocks forever,
/// spawning a thread per connection.
pub fn run(relay: Arc<Relay<TcpStream>>, listener: TcpListener) -> Result<()> {
    for conn in listener.incoming() {
        let conn = conn?;
        let relay = Arc::clone(&relay);
        thread::spawn(move || {
            // A failed connection (bad auth, closed peer) is per-connection; log
            // sites belong to keeperd (M5a-4). Drop the error here.
            let _ = relay.serve(conn);
        });
    }
    Ok(())
}

/// Bridge two authenticated outer sessions, forwarding `RelayData` payloads
/// full-duplex until either side closes. One direction runs on a spawned thread,
/// the other on the caller's thread; the split halves touch disjoint cipher
/// directions, so no locking is needed.
fn splice<S: SplitIo + Read + Write + Send + 'static>(
    a: NoiseSession<S>,
    b: NoiseSession<S>,
) -> Result<()> {
    let (a_read, a_write) = a.split()?;
    let (b_read, b_write) = b.split()?;
    let a_to_b = thread::spawn(move || pump(a_read, b_write));
    let b_to_a = pump(b_read, a_write);
    let _ = a_to_b.join();
    b_to_a
}

/// Forward `RelayData` payloads from `from` to `to` until the channel closes.
/// A read/write error (peer gone) ends the pump cleanly — circuit teardown, not
/// a relay fault.
fn pump<R: Read, W: Write>(mut from: NoiseReader<R>, mut to: NoiseWriter<W>) -> Result<()> {
    loop {
        let frame = match from.recv_frame() {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };
        match frame.kind {
            Some(frame::Kind::RelayData(d)) => {
                if to.send_frame(&Frame::relay_data(d.payload)).is_err() {
                    return Ok(());
                }
            }
            _ => return Ok(()),
        }
    }
}

fn net_to_io(e: NetError) -> io::Error {
    match e {
        NetError::Io(io) => io,
        other => io::Error::other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    //! Authorization predicate tests (no network). The end-to-end forwarding /
    //! non-member-rejection-over-TCP tests live in `tests/relay_tcp.rs`.

    use super::*;
    use crate::attest::static_attestation_message;
    use crate::ring::RingEntry;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a device's transport material + a verifiable ring row for it.
    fn member(id_seed: u8, tk_seed: u8, name: &str) -> (LocalDevice, [u8; 32], RingEntry) {
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
        (local, transport_pubkey, entry)
    }

    /// A relay whose ring contains `members`.
    fn relay_with(members: &[RingEntry]) -> Arc<Relay<TcpStream>> {
        let (relay_dev, _, _) = member(200, 201, "relay");
        let mut ring = Ring::default();
        for e in members {
            ring.upsert(e.clone());
        }
        Relay::new(&relay_dev, ring)
    }

    #[test]
    fn authorizes_a_ring_member_with_matching_key() {
        let (dev, tpub, entry) = member(1, 2, "laptop");
        let relay = relay_with(&[entry]);
        assert_eq!(relay.authorize(&dev.hello(), &tpub).unwrap(), dev.device_id);
    }

    #[test]
    fn rejects_a_non_member() {
        let (_a, _atp, a_entry) = member(1, 2, "laptop");
        let (stranger, stranger_tp, _se) = member(9, 8, "stranger");
        // Ring has only the laptop; the stranger must be rejected (no open relay).
        let relay = relay_with(&[a_entry]);
        assert!(relay.authorize(&stranger.hello(), &stranger_tp).is_err());
    }

    #[test]
    fn rejects_member_presenting_a_different_transport_key() {
        let (dev, _tpub, entry) = member(3, 4, "phone");
        let relay = relay_with(&[entry]);
        // A handshake static that is not the one the ring row records for this
        // device-id: the peer proved possession of *a* key, but not the bound one.
        let wrong = x25519_dalek::x25519([77u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        assert!(relay.authorize(&dev.hello(), &wrong).is_err());
    }

    #[test]
    fn rejects_member_with_a_tampered_attestation() {
        let (mut dev, tpub, entry) = member(5, 6, "tablet");
        dev.static_attestation[0] ^= 0x01; // forged self-attestation
        let relay = relay_with(&[entry]);
        assert!(relay.authorize(&dev.hello(), &tpub).is_err());
    }
}
