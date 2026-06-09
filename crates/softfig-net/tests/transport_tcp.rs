//! Behavioural tests over real loopback `TcpStream`s (the production
//! substrate). Internals-poking tests (tamper, wrong-key) live in the
//! transport module's unit tests.

use std::net::{TcpListener, TcpStream};
use std::thread;

use softfig_net::proto::frame;
use softfig_net::{ik_initiator, ik_responder, xx_initiator, xx_responder, Frame, HelloPayload};

/// A connected pair of loopback TCP streams: `(client, server)`.
fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    (client, server)
}

fn hello(name: &str) -> HelloPayload {
    HelloPayload::new(name.as_bytes().to_vec(), name)
}

#[test]
fn xx_channel_round_trips_ping_pong_over_loopback_tcp() {
    let (client, server) = tcp_pair();
    let sk_i = [11u8; 32];
    let sk_r = [22u8; 32];

    let server = thread::spawn(move || {
        let mut s = xx_responder(server, &sk_r, &hello("responder")).expect("responder handshake");
        let f = s.recv_frame().expect("recv ping");
        let nonce = match f.kind {
            Some(frame::Kind::Ping(p)) => p.nonce,
            other => panic!("expected ping, got {other:?}"),
        };
        s.send_frame(&Frame::pong(nonce)).expect("send pong");
        s.peer_hello().device_name.clone()
    });

    let mut client = xx_initiator(client, &sk_i, &hello("initiator")).expect("initiator handshake");
    client.send_frame(&Frame::ping(42)).expect("send ping");
    let reply = client.recv_frame().expect("recv pong");
    assert!(
        matches!(reply.kind, Some(frame::Kind::Pong(p)) if p.nonce == 42),
        "expected pong(42), got {:?}",
        reply.kind
    );
    assert_eq!(client.peer_hello().device_name, "responder");

    let initiator_name_seen_by_responder = server.join().unwrap();
    assert_eq!(initiator_name_seen_by_responder, "initiator");
}

#[test]
fn ik_reconnect_round_trips_over_loopback_tcp() {
    // First pair over XX to learn the responder's static (what the ring would
    // store), then reconnect over IK using it.
    let sk_i = [33u8; 32];
    let sk_r = [44u8; 32];

    let (c, s) = tcp_pair();
    let pair_server = thread::spawn(move || {
        let sess = xx_responder(s, &sk_r, &hello("responder")).expect("xx responder");
        // Hold until the initiator side has captured the static, then drop.
        drop(sess);
    });
    let resp_static = {
        let sess = xx_initiator(c, &sk_i, &hello("initiator")).expect("xx initiator");
        *sess.peer_static()
    };
    pair_server.join().unwrap();

    let (c, s) = tcp_pair();
    let reconnect_server = thread::spawn(move || {
        let mut sess = ik_responder(s, &sk_r, &hello("responder")).expect("ik responder");
        let f = sess.recv_frame().expect("recv ping");
        let nonce = match f.kind {
            Some(frame::Kind::Ping(p)) => p.nonce,
            other => panic!("expected ping, got {other:?}"),
        };
        sess.send_frame(&Frame::pong(nonce)).expect("send pong");
    });

    let mut client = ik_initiator(c, &sk_i, &resp_static, &hello("initiator")).expect("ik initiator");
    client.send_frame(&Frame::ping(7)).expect("send ping");
    let reply = client.recv_frame().expect("recv pong");
    assert!(matches!(reply.kind, Some(frame::Kind::Pong(p)) if p.nonce == 7));
    reconnect_server.join().unwrap();
}

/// A message far larger than Noise's 64 KiB ciphertext cap must chunk on send
/// and reassemble on receive, byte-for-byte.
#[test]
fn large_message_round_trips_across_noise_chunks() {
    let (client, server) = tcp_pair();
    let sk_i = [55u8; 32];
    let sk_r = [66u8; 32];

    // ~200 KiB > MAX_PLAINTEXT_CHUNK (65519): forces several Noise messages.
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8).collect();
    let expected = payload.clone();

    let server = thread::spawn(move || {
        let mut s = xx_responder(server, &sk_r, &hello("responder")).expect("responder handshake");
        let got = s.recv_bytes().expect("recv bytes");
        // Echo it straight back to prove both directions chunk/reassemble.
        s.send_bytes(&got).expect("echo bytes");
    });

    let mut client = xx_initiator(client, &sk_i, &hello("initiator")).expect("initiator handshake");
    client.send_bytes(&payload).expect("send bytes");
    let echoed = client.recv_bytes().expect("recv echoed bytes");

    assert_eq!(echoed.len(), expected.len());
    assert_eq!(echoed, expected, "large message corrupted across chunk boundaries");
    server.join().unwrap();
}
