//! Noise-over-TCP sessions and the length-delimited frame codec.
//!
//! Cipher suite: `25519` (X25519) + `ChaChaPoly` (ChaCha20-Poly1305) +
//! `BLAKE2s` — the primitives already in soft-fig's crypto stack. Two patterns:
//!
//! * **`XX`** — first contact / pairing. Both static keys are exchanged and
//!   mutually authenticated inside the handshake; neither side needs to know
//!   the other's key in advance. The [`HelloPayload`] (Ed25519 identity, name)
//!   rides in the encrypted handshake payloads.
//! * **`IK`** — reconnect. The initiator already holds the responder's static
//!   key (from the peer ring), so the channel comes up in one round trip.
//!
//! On top of the established session, [`NoiseSession::send_bytes`] /
//! [`recv_bytes`](NoiseSession::recv_bytes) carry an arbitrary-length message
//! as a 4-byte length prefix followed by the body, chunked across Noise
//! transport messages so each stays under Noise's 64 KiB ciphertext cap;
//! [`send_frame`](NoiseSession::send_frame) /
//! [`recv_frame`](NoiseSession::recv_frame) layer the protobuf [`Frame`] on
//! top. The codec is generic over `Read + Write`, so `TcpStream` is the
//! production substrate while tests can use any duplex stream.

use std::io::{Read, Write};

use prost::Message;
use snow::{HandshakeState, TransportState};

use crate::error::{NetError, Result};
use crate::proto::{Frame, HelloPayload};

const NOISE_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const NOISE_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Length of an X25519 static key.
const KEY_LEN: usize = 32;

/// Length of the Noise handshake hash. BLAKE2s (our Noise hash) is 256-bit, so
/// `get_handshake_hash()` always returns 32 bytes; the SAS is derived from it.
const HASH_LEN: usize = 32;

/// Noise's hard cap on a single transport/handshake message (including the
/// 16-byte AEAD tag). Both the on-wire length prefix (a `u16`) and our chunk
/// size derive from this.
const NOISE_MAX_MSG: usize = 65535;
const NOISE_TAG_LEN: usize = 16;

/// Largest plaintext we hand to a single Noise `write_message`, leaving room
/// for the AEAD tag within [`NOISE_MAX_MSG`].
const MAX_PLAINTEXT_CHUNK: usize = NOISE_MAX_MSG - NOISE_TAG_LEN;

/// Sanity cap on a reassembled message, so a hostile/buggy peer can't make us
/// allocate without bound. The control plane is tiny; raise this deliberately
/// when the data plane (M5b+) needs larger transfers.
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

/// An established, encrypted session with an authenticated peer. Generic over
/// the byte stream (`TcpStream` in production).
pub struct NoiseSession<S> {
    io: S,
    transport: TransportState,
    peer_static: [u8; KEY_LEN],
    peer_hello: HelloPayload,
    handshake_hash: [u8; HASH_LEN],
}

impl<S> std::fmt::Debug for NoiseSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseSession")
            .field("peer", &self.peer_hello.device_name)
            .finish_non_exhaustive()
    }
}

impl<S> NoiseSession<S> {
    /// The peer's authenticated X25519 static key. For a freshly `XX`-paired
    /// peer this is what gets stored in the ring and reused for `IK` reconnect.
    pub fn peer_static(&self) -> &[u8; KEY_LEN] {
        &self.peer_static
    }

    /// The identity payload the peer presented inside the handshake.
    pub fn peer_hello(&self) -> &HelloPayload {
        &self.peer_hello
    }

    /// The Noise handshake hash `h` — identical on both honest endpoints of a
    /// session, divergent across the two legs of a man-in-the-middle. The SAS
    /// short code is derived from this (see [`crate::sas`]). Captured before
    /// the handshake state was consumed into transport mode.
    pub fn handshake_hash(&self) -> &[u8; HASH_LEN] {
        &self.handshake_hash
    }
}

impl<S: Read + Write> NoiseSession<S> {
    /// Send an arbitrary-length message: a 4-byte big-endian length prefix
    /// followed by `msg`, chunked into Noise transport messages.
    pub fn send_bytes(&mut self, msg: &[u8]) -> Result<()> {
        let len = u32::try_from(msg.len()).map_err(|_| NetError::Protocol("message too large"))?;

        // Header + body as one logical stream, partitioned into Noise-sized
        // chunks. The last chunk is partial, so the receiver lands on exactly
        // `4 + len` plaintext bytes with nothing straddling into the next
        // message — which is why no inter-call buffering is needed on recv.
        let mut framed = Vec::with_capacity(4 + msg.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(msg);

        let mut out = vec![0u8; NOISE_MAX_MSG];
        for chunk in framed.chunks(MAX_PLAINTEXT_CHUNK) {
            let n = self.transport.write_message(chunk, &mut out)?;
            write_lp(&mut self.io, &out[..n])?;
        }
        self.io.flush()?;
        Ok(())
    }

    /// Receive one message sent by [`send_bytes`](Self::send_bytes).
    pub fn recv_bytes(&mut self) -> Result<Vec<u8>> {
        let mut acc: Vec<u8> = Vec::new();
        let mut expected: Option<usize> = None;
        let mut out = vec![0u8; NOISE_MAX_MSG];

        loop {
            let ct = read_lp(&mut self.io)?;
            let n = self.transport.read_message(&ct, &mut out)?;
            acc.extend_from_slice(&out[..n]);

            if expected.is_none() && acc.len() >= 4 {
                let len = u32::from_be_bytes(acc[..4].try_into().unwrap()) as usize;
                if len > MAX_MESSAGE_LEN {
                    return Err(NetError::Protocol("message exceeds maximum length"));
                }
                expected = Some(len);
            }
            if let Some(len) = expected {
                if acc.len() >= 4 + len {
                    acc.drain(..4);
                    acc.truncate(len);
                    return Ok(acc);
                }
            }
        }
    }

    /// Send a protobuf control [`Frame`].
    pub fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        self.send_bytes(&frame.encode_to_vec())
    }

    /// Receive a protobuf control [`Frame`].
    pub fn recv_frame(&mut self) -> Result<Frame> {
        let bytes = self.recv_bytes()?;
        Ok(Frame::decode(bytes.as_slice())?)
    }
}

// --- Handshakes ------------------------------------------------------------

/// Run the `XX` handshake as the **initiator** (first contact / pairing).
pub fn xx_initiator<S: Read + Write>(
    mut io: S,
    local_private: &[u8; KEY_LEN],
    hello: &HelloPayload,
) -> Result<NoiseSession<S>> {
    let mut hs = build_handshake(NOISE_XX, local_private, None, true)?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];

    // -> e
    let n = hs.write_message(&[], &mut buf)?;
    write_lp(&mut io, &buf[..n])?;
    // <- e, ee, s, es   (responder's hello)
    let peer_hello = read_handshake_hello(&mut hs, &read_lp(&mut io)?)?;
    // -> s, se          (our hello)
    let n = hs.write_message(&hello.encode_to_vec(), &mut buf)?;
    write_lp(&mut io, &buf[..n])?;

    finish(io, hs, peer_hello)
}

/// Run the `XX` handshake as the **responder**.
pub fn xx_responder<S: Read + Write>(
    mut io: S,
    local_private: &[u8; KEY_LEN],
    hello: &HelloPayload,
) -> Result<NoiseSession<S>> {
    let mut hs = build_handshake(NOISE_XX, local_private, None, false)?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];

    // <- e
    read_handshake_hello(&mut hs, &read_lp(&mut io)?)?; // payload empty
    // -> e, ee, s, es   (our hello)
    let n = hs.write_message(&hello.encode_to_vec(), &mut buf)?;
    write_lp(&mut io, &buf[..n])?;
    // <- s, se          (peer's hello)
    let peer_hello = read_handshake_hello(&mut hs, &read_lp(&mut io)?)?;

    finish(io, hs, peer_hello)
}

/// Run the `IK` handshake as the **initiator** (reconnect; we already hold the
/// responder's static key from the ring).
pub fn ik_initiator<S: Read + Write>(
    mut io: S,
    local_private: &[u8; KEY_LEN],
    remote_static: &[u8; KEY_LEN],
    hello: &HelloPayload,
) -> Result<NoiseSession<S>> {
    let mut hs = build_handshake(NOISE_IK, local_private, Some(remote_static), true)?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];

    // -> e, es, s, ss   (our hello)
    let n = hs.write_message(&hello.encode_to_vec(), &mut buf)?;
    write_lp(&mut io, &buf[..n])?;
    // <- e, ee, se      (responder's hello)
    let peer_hello = read_handshake_hello(&mut hs, &read_lp(&mut io)?)?;

    finish(io, hs, peer_hello)
}

/// Run the `IK` handshake as the **responder**.
pub fn ik_responder<S: Read + Write>(
    mut io: S,
    local_private: &[u8; KEY_LEN],
    hello: &HelloPayload,
) -> Result<NoiseSession<S>> {
    let mut hs = build_handshake(NOISE_IK, local_private, None, false)?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];

    // <- e, es, s, ss   (initiator's hello)
    let peer_hello = read_handshake_hello(&mut hs, &read_lp(&mut io)?)?;
    // -> e, ee, se      (our hello)
    let n = hs.write_message(&hello.encode_to_vec(), &mut buf)?;
    write_lp(&mut io, &buf[..n])?;

    finish(io, hs, peer_hello)
}

// --- Internals -------------------------------------------------------------

fn build_handshake(
    pattern: &str,
    local_private: &[u8; KEY_LEN],
    remote_static: Option<&[u8; KEY_LEN]>,
    initiator: bool,
) -> Result<HandshakeState> {
    let params = pattern
        .parse()
        .map_err(|_| NetError::Protocol("invalid noise parameter string"))?;
    let mut builder = snow::Builder::new(params).local_private_key(local_private)?;
    if let Some(rs) = remote_static {
        builder = builder.remote_public_key(rs)?;
    }
    let hs = if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    };
    Ok(hs)
}

/// Decrypt a handshake message and parse its payload as a [`HelloPayload`].
/// An empty payload (e.g. XX message 1) decodes to the default `HelloPayload`.
fn read_handshake_hello(hs: &mut HandshakeState, msg: &[u8]) -> Result<HelloPayload> {
    let mut payload = vec![0u8; msg.len()];
    let n = hs.read_message(msg, &mut payload)?;
    Ok(HelloPayload::decode(&payload[..n])?)
}

/// Capture the peer static and the handshake hash (both before the handshake
/// state is consumed), then transition into transport mode.
fn finish<S>(io: S, hs: HandshakeState, peer_hello: HelloPayload) -> Result<NoiseSession<S>> {
    let peer_static = remote_static(&hs)?;
    let handshake_hash = handshake_hash(&hs)?;
    let transport = hs.into_transport_mode()?;
    Ok(NoiseSession {
        io,
        transport,
        peer_static,
        peer_hello,
        handshake_hash,
    })
}

fn handshake_hash(hs: &HandshakeState) -> Result<[u8; HASH_LEN]> {
    hs.get_handshake_hash()
        .try_into()
        .map_err(|_| NetError::Protocol("handshake hash wrong length"))
}

fn remote_static(hs: &HandshakeState) -> Result<[u8; KEY_LEN]> {
    hs.get_remote_static()
        .ok_or(NetError::Protocol("peer static key missing after handshake"))?
        .try_into()
        .map_err(|_| NetError::Protocol("peer static key wrong length"))
}

/// Write a length-prefixed blob: 2-byte big-endian length, then the bytes.
/// Used for both handshake messages and transport ciphertexts, each of which
/// is bounded by [`NOISE_MAX_MSG`] and so fits a `u16`.
fn write_lp<S: Write>(io: &mut S, bytes: &[u8]) -> Result<()> {
    let len =
        u16::try_from(bytes.len()).map_err(|_| NetError::Protocol("noise message too large"))?;
    io.write_all(&len.to_be_bytes())?;
    io.write_all(bytes)?;
    Ok(())
}

fn read_lp<S: Read>(io: &mut S) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    io.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    //! Unit tests that need access to the session internals (crafting a
    //! corrupted ciphertext, poking the raw stream). Behavioural tests over
    //! loopback TCP live in `tests/transport_tcp.rs`.

    use super::*;
    use crate::proto::frame;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn hello(name: &str) -> HelloPayload {
        HelloPayload::new(name.as_bytes().to_vec(), name)
    }

    /// Establish an XX session pair over an in-process socket pair.
    fn xx_pair(
        sk_i: [u8; KEY_LEN],
        sk_r: [u8; KEY_LEN],
    ) -> (NoiseSession<UnixStream>, NoiseSession<UnixStream>) {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let responder = thread::spawn(move || xx_responder(b, &sk_r, &hello("responder")).unwrap());
        let initiator = xx_initiator(a, &sk_i, &hello("initiator")).unwrap();
        (initiator, responder.join().unwrap())
    }

    #[test]
    fn xx_establishes_and_exchanges_hellos() {
        let (init, resp) = xx_pair([1u8; 32], [2u8; 32]);
        assert_eq!(init.peer_hello().device_name, "responder");
        assert_eq!(resp.peer_hello().device_name, "initiator");
        assert_ne!(init.peer_static(), &[0u8; 32]);
        // Each side authenticated the other's static; they are different keys.
        assert_ne!(init.peer_static(), resp.peer_static());
    }

    #[test]
    fn tampered_transport_message_is_rejected() {
        let (mut init, mut resp) = xx_pair([3u8; 32], [4u8; 32]);

        // Hand-encrypt a framed Ping, flip a byte in the AEAD tag, write it raw.
        let body = Frame::ping(1).encode_to_vec();
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        let mut out = vec![0u8; NOISE_MAX_MSG];
        let n = init.transport.write_message(&framed, &mut out).unwrap();
        out[n - 1] ^= 0x01;
        write_lp(&mut init.io, &out[..n]).unwrap();

        match resp.recv_frame() {
            Err(NetError::Noise(_)) => {}
            other => panic!("expected Noise decrypt failure, got {other:?}"),
        }
    }

    #[test]
    fn ik_reconnect_with_known_static_round_trips() {
        // Pair via XX so the initiator learns the responder's static, then
        // reconnect via IK using it — the realistic pair-then-reconnect path.
        let sk_i = [5u8; 32];
        let sk_r = [6u8; 32];
        let (init, _resp) = xx_pair(sk_i, sk_r);
        let resp_static = *init.peer_static();

        let (a, b) = UnixStream::pair().unwrap();
        let responder = thread::spawn(move || {
            let mut s = ik_responder(b, &sk_r, &hello("responder")).unwrap();
            let f = s.recv_frame().unwrap();
            let nonce = match f.kind {
                Some(frame::Kind::Ping(p)) => p.nonce,
                other => panic!("expected ping, got {other:?}"),
            };
            s.send_frame(&Frame::pong(nonce)).unwrap();
        });

        let mut client = ik_initiator(a, &sk_i, &resp_static, &hello("initiator")).unwrap();
        client.send_frame(&Frame::ping(99)).unwrap();
        let reply = client.recv_frame().unwrap();
        assert!(matches!(reply.kind, Some(frame::Kind::Pong(p)) if p.nonce == 99));
        responder.join().unwrap();
    }

    #[test]
    fn ik_wrong_static_key_is_rejected() {
        let (a, b) = UnixStream::pair().unwrap();
        let sk_r = [8u8; 32];
        // The initiator targets a static that is not the responder's, so the
        // responder cannot decrypt message 1.
        let wrong_static = [0x55u8; 32];
        let responder = thread::spawn(move || ik_responder(b, &sk_r, &hello("responder")));
        let client = ik_initiator(a, &[7u8; 32], &wrong_static, &hello("initiator"));

        let responder_result = responder.join().unwrap();
        assert!(
            responder_result.is_err(),
            "responder should reject a handshake aimed at the wrong static key"
        );
        // The initiator then fails too (responder dropped the connection).
        assert!(client.is_err());
    }
}
