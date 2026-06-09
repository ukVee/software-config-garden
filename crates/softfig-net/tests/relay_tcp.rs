//! End-to-end relay forwarding over real loopback TCP. Two clients establish an
//! **end-to-end** Noise IK session *through* an in-process relay that only
//! forwards opaque `RelayData` payloads. Also exercises rejection of a
//! registration from a device the relay does not have in its ring. Focused
//! authorization-predicate tests live in the `relay` module's unit tests.

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use softfig_net::proto::frame;
use softfig_net::{
    relay, relay_accept, relay_connect, static_attestation_message, Frame, LocalDevice, Ring,
    RingEntry,
};

/// A device's transport material + the ring row a peer would store for it.
struct Device {
    local: LocalDevice,
    transport_pubkey: [u8; 32],
}

fn device(name: &str, id_seed: u8, transport_seed: u8) -> Device {
    let id = SigningKey::from_bytes(&[id_seed; 32]);
    let transport_secret = [transport_seed; 32];
    let transport_pubkey =
        x25519_dalek::x25519(transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    let static_attestation = id
        .sign(&static_attestation_message(&transport_pubkey))
        .to_bytes();
    Device {
        local: LocalDevice {
            transport_secret,
            device_id: id.verifying_key().to_bytes(),
            device_name: name.into(),
            static_attestation,
        },
        transport_pubkey,
    }
}

impl Device {
    fn ring_entry(&self) -> RingEntry {
        RingEntry {
            device_id: self.local.device_id,
            name: self.local.device_name.clone(),
            transport_pubkey: self.transport_pubkey,
            endpoints: vec![],
            attestation: self.local.static_attestation,
            paired_at: 1,
        }
    }
}

/// Start a relay listening on loopback whose ring contains `members`. Returns
/// the relay handle (for `is_registered`) and its bound address.
fn start_relay(relay_dev: &Device, members: &[&Device]) -> (Arc<relay::Relay<TcpStream>>, String) {
    let mut ring = Ring::default();
    for m in members {
        ring.upsert(m.ring_entry());
    }
    let relay = relay::Relay::new(&relay_dev.local, ring);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind relay");
    let addr = listener.local_addr().unwrap().to_string();
    let relay_for_thread = Arc::clone(&relay);
    thread::spawn(move || {
        let _ = relay::run(relay_for_thread, listener);
    });
    (relay, addr)
}

fn wait_until<F: Fn() -> bool>(cond: F) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("condition not met within timeout");
}

#[test]
fn relay_forwards_end_to_end_ik_session_between_two_clients() {
    let relay_dev = device("relay", 100, 101);
    let alice = device("alice", 1, 2);
    let bob = device("bob", 3, 4);

    // The relay is paired with both clients (ring membership = relay authz).
    let (relay, addr) = start_relay(&relay_dev, &[&alice, &bob]);
    let relay_static = relay_dev.transport_pubkey;
    let bob_id = bob.local.device_id;
    let bob_static = bob.transport_pubkey;

    // --- Bob registers and waits to be reached (inner IK responder). ---
    let bob_local = bob.local.clone();
    let bob_addr = addr.clone();
    let bob_thread = thread::spawn(move || {
        let conn = TcpStream::connect(&bob_addr).expect("bob connect relay");
        let mut sess = relay_accept(conn, &relay_static, &bob_local).expect("bob relayed session");
        // Serve one ping/pong, end-to-end with alice (relay can't read it).
        let f = sess.recv_frame().expect("bob recv ping");
        let nonce = match f.kind {
            Some(frame::Kind::Ping(p)) => p.nonce,
            other => panic!("bob expected ping, got {other:?}"),
        };
        sess.send_frame(&Frame::pong(nonce)).expect("bob send pong");
    });

    // Don't let alice initiate until bob is parked at the relay.
    wait_until(|| relay.is_registered(&bob_id));

    // --- Alice connects through the relay (inner IK initiator). ---
    let conn = TcpStream::connect(&addr).expect("alice connect relay");
    let mut alice_sess =
        relay_connect(conn, &relay_static, &alice.local, &bob_id, &bob_static).expect("alice session");
    alice_sess.send_frame(&Frame::ping(0xABCD)).expect("alice ping");
    let reply = alice_sess.recv_frame().expect("alice recv pong");
    assert!(
        matches!(reply.kind, Some(frame::Kind::Pong(p)) if p.nonce == 0xABCD),
        "expected end-to-end pong(0xABCD) forwarded through the blind relay, got {:?}",
        reply.kind
    );

    bob_thread.join().unwrap();
}

#[test]
fn relay_rejects_registration_from_a_non_ring_member() {
    let relay_dev = device("relay", 100, 101);
    let alice = device("alice", 1, 2);
    let stranger = device("stranger", 9, 8);

    // The relay's ring has alice only — the stranger is not a member.
    let (_relay, addr) = start_relay(&relay_dev, &[&alice]);
    let relay_static = relay_dev.transport_pubkey;

    let conn = TcpStream::connect(&addr).expect("stranger connect relay");
    // The outer IK handshake itself may complete (the relay learns the static),
    // but authorization fails and the relay drops the connection, so the
    // stranger's attempt to register + accept a relayed peer fails.
    let result = relay_accept(conn, &relay_static, &stranger.local);
    assert!(
        result.is_err(),
        "a non-ring-member registration must be rejected by the relay"
    );
}
