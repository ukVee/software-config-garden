//! The **role discriminator** invariant that keeperd's inbound listener depends
//! on: a Noise `XX` first message (pairing) and a Noise `IK` first message
//! (reconnect) are distinguishable from their 2-byte length prefix alone,
//! before a single handshake byte is consumed.
//!
//! `XX`'s first message is `-> e` with an **empty** payload and no key yet, so
//! it is exactly the 32-byte ephemeral public key. `IK`'s first message is
//! `-> e, es, s, ss` and carries the `HelloPayload`, so it is
//! `32 (e) + 48 (s+tag) + len(hello) + 16 (tag)` — never anywhere near 32.
//!
//! If a future change gives `XX`'s first message a payload, or shrinks `IK`'s,
//! this test fails loudly — because `serve_inbound` would start mis-roling
//! connections again (the bug behind task 057).

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread;

use ed25519_dalek::{Signer, SigningKey};
use softfig_net::{pair_initiator, static_attestation_message, LocalDevice};
use softfig_net::transport::ik_initiator;

fn device(name: &str, id_seed: u8, transport_seed: u8) -> LocalDevice {
    let id = SigningKey::from_bytes(&[id_seed; 32]);
    let transport_secret = [transport_seed; 32];
    let transport_pubkey =
        x25519_dalek::x25519(transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    let static_attestation = id
        .sign(&static_attestation_message(&transport_pubkey))
        .to_bytes();
    LocalDevice {
        transport_secret,
        device_id: id.verifying_key().to_bytes(),
        device_name: name.into(),
        static_attestation,
    }
}

/// Accept one connection, read just the 2-byte length prefix of the first
/// handshake message, and return it. The handshake is never completed — we only
/// care about what a responder can know *before* it commits to a role.
fn first_message_len(dial: impl FnOnce(TcpStream) + Send + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let dialer = thread::spawn(move || {
        let stream = TcpStream::connect(addr).expect("connect");
        dial(stream);
    });
    let (mut conn, _) = listener.accept().expect("accept");
    let mut len_buf = [0u8; 2];
    conn.read_exact(&mut len_buf).expect("read length prefix");
    drop(conn);
    let _ = dialer.join();
    u16::from_be_bytes(len_buf)
}

#[test]
fn xx_first_message_is_exactly_the_32_byte_ephemeral_key() {
    let alice = device("alice", 1, 2);
    let len = first_message_len(move |s| {
        let _ = pair_initiator(s, &alice);
    });
    assert_eq!(
        len, 32,
        "XX `-> e` must stay a bare 32-byte ephemeral key; keeperd's role \
         discriminator reads pairing off exactly this length"
    );
}

#[test]
fn ik_first_message_is_far_larger_than_the_xx_one() {
    let alice = device("alice", 1, 2);
    let bob = device("bob", 3, 4);
    let bob_static =
        x25519_dalek::x25519(bob.transport_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    let hello = alice.hello();
    let len = first_message_len(move |s| {
        let _ = ik_initiator(s, &alice.transport_secret, &bob_static, &hello);
    });
    // 32 (e) + 32+16 (encrypted static) + 16 (payload tag) = 96 floor, plus the
    // hello itself. The only property the discriminator needs is `!= 32`, but
    // assert the real floor so a shrink can never creep up on it.
    assert!(
        len >= 112,
        "IK `-> e, es, s, ss` carries the hello and must stay well clear of 32; got {len}"
    );
    assert_ne!(len, 32, "IK first message must never be 32 bytes");
}
