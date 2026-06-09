//! End-to-end pairing over real loopback TCP: two "keepers" pair, persist
//! their rings to disk, reload, and reconnect via `IK` keyed by the stored
//! transport key — the realistic pair-then-reconnect path the daemon will run
//! in M5a-4. Focused MITM / tamper / SAS cases live in the `pairing` and `ring`
//! module unit tests.

use std::net::{TcpListener, TcpStream};
use std::thread;

use ed25519_dalek::{Signer, SigningKey};
use softfig_net::proto::frame;
use softfig_net::{
    ik_initiator, ik_responder, pair_initiator, pair_responder, ring_path,
    static_attestation_message, Frame, LocalDevice, Ring,
};

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    (client, server)
}

/// A device with a self-attestation, exactly as keeperd would assemble it from
/// a `VaultSession` (`transport_secret`, `transport_pubkey`, `device_id`, and
/// `sign(static_attestation_message(..))`).
fn device(name: &str, id_seed: u8, transport_seed: u8) -> (LocalDevice, [u8; 32]) {
    let id = SigningKey::from_bytes(&[id_seed; 32]);
    let transport_secret = [transport_seed; 32];
    let transport_pubkey =
        x25519_dalek::x25519(transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    let static_attestation = id
        .sign(&static_attestation_message(&transport_pubkey))
        .to_bytes();
    (
        LocalDevice {
            transport_secret,
            device_id: id.verifying_key().to_bytes(),
            device_name: name.into(),
            static_attestation,
        },
        transport_secret,
    )
}

#[test]
fn pair_persist_reload_then_ik_reconnect() {
    let (alice, alice_sk) = device("alice", 1, 2);
    let (bob, bob_sk) = device("bob", 3, 4);

    let alice_root = tempfile::tempdir().unwrap();
    let bob_root = tempfile::tempdir().unwrap();

    // --- pair over TCP ---
    let (c, s) = tcp_pair();
    let bob_for_thread = bob.clone();
    let responder = thread::spawn(move || pair_responder(s, &bob_for_thread).expect("bob pairs"));
    let alice_pending = pair_initiator(c, &alice).expect("alice pairs");
    let bob_pending = responder.join().unwrap();

    // SAS matches → users confirm on both sides.
    assert_eq!(alice_pending.sas().code(), bob_pending.sas().code());
    let (_a_sess, alice_sees_bob) = alice_pending.confirm();
    let (_b_sess, bob_sees_alice) = bob_pending.confirm();

    // --- persist each ring, then reload (re-verifying attestations) ---
    let alice_ring_path = ring_path(alice_root.path());
    let bob_ring_path = ring_path(bob_root.path());

    let mut alice_ring = Ring::default();
    alice_ring.upsert(alice_sees_bob);
    alice_ring.save(&alice_ring_path).unwrap();

    let mut bob_ring = Ring::default();
    bob_ring.upsert(bob_sees_alice);
    bob_ring.save(&bob_ring_path).unwrap();

    let alice_ring = Ring::load(&alice_ring_path).unwrap();
    let bob_ring = Ring::load(&bob_ring_path).unwrap();

    let bob_in_alice = alice_ring.get(&bob.device_id).expect("bob in alice's ring");
    let alice_in_bob = bob_ring.get(&alice.device_id).expect("alice in bob's ring");
    assert_eq!(bob_in_alice.name, "bob");
    assert_eq!(alice_in_bob.name, "alice");

    // --- IK reconnect, keyed by the *stored* transport key from the ring ---
    let bob_static = bob_in_alice.transport_pubkey;
    let (c, s) = tcp_pair();
    let bob_server = thread::spawn(move || {
        let mut sess = ik_responder(s, &bob_sk, &bob.into_hello()).expect("bob ik");
        let f = sess.recv_frame().expect("recv ping");
        let nonce = match f.kind {
            Some(frame::Kind::Ping(p)) => p.nonce,
            other => panic!("expected ping, got {other:?}"),
        };
        sess.send_frame(&Frame::pong(nonce)).expect("send pong");
    });

    let mut alice_client =
        ik_initiator(c, &alice_sk, &bob_static, &alice.into_hello()).expect("alice ik");
    alice_client.send_frame(&Frame::ping(123)).expect("ping");
    let reply = alice_client.recv_frame().expect("pong");
    assert!(matches!(reply.kind, Some(frame::Kind::Pong(p)) if p.nonce == 123));
    bob_server.join().unwrap();
}

/// Small extension so the test can reuse a `LocalDevice` as a handshake hello.
trait IntoHello {
    fn into_hello(self) -> softfig_net::HelloPayload;
}
impl IntoHello for LocalDevice {
    fn into_hello(self) -> softfig_net::HelloPayload {
        let mut h = softfig_net::HelloPayload::new(self.device_id.to_vec(), self.device_name);
        h.static_attestation = self.static_attestation.to_vec();
        h
    }
}
