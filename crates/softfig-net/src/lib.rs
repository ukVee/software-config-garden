//! soft-fig networking (M5a) — the frontend-neutral transport + control plane
//! for cross-device sync.
//!
//! This crate is the foundation slice (M5a-1): a vault-keyed X25519 static key
//! drives an application-level [Noise] tunnel (the [`snow`] crate) over an
//! ordinary `TcpStream`, carrying a length-delimited protobuf control plane.
//! No kernel network interface and no elevated privileges — keeperd runs as an
//! unprivileged user unit, so a WireGuard-style interface is off the table.
//! Logic lives here; CLI/TUI are thin wrappers and keeperd hosts an instance
//! (the `softfig-deploy` / `softfig-onboard` precedent).
//!
//! M5a-2 adds pairing: the [`sas`] short code derived from the Noise handshake
//! hash, the Ed25519 transport [`attest`]ation carried in the handshake, the
//! [`pairing`] state machine, and the signed peer [`ring`] (`peers.toml`).
//!
//! M5a-3 makes peers reachable, LAN and off-LAN: [`discovery`] announces and
//! browses `_softfig._tcp` over mDNS (refreshing ring endpoints), the
//! [`relay`] is a blind, ring-authorized dumb-pipe for off-LAN peers (the
//! end-to-end Noise session tunnels through it as opaque `RelayData`), and
//! [`connect`] picks a route — LAN-direct first, relay as fallback.
//!
//! # Concurrency model: sync + threads (decision)
//!
//! The transport is **blocking, thread-per-connection**, not async/`tokio`.
//! Rationale: it matches the existing daemon/IPC style (blocking sockets,
//! `SO_PEERCRED`), device counts in a personal mesh are tiny (a handful of
//! peers, not thousands of connections), and it keeps the dependency surface
//! and reasoning small. A `TcpStream` per peer plus the relay's two standing
//! connections is well within what threads handle comfortably. If a future
//! milestone needs to fan out to many relayed peers at once, revisit this —
//! the [`NoiseSession`] codec is `Read + Write`-generic, so swapping the IO
//! substrate later does not touch the crypto/framing.
//!
//! [Noise]: https://noiseprotocol.org/

#![forbid(unsafe_code)]

pub mod attest;
pub mod ceremony;
pub mod connect;
pub mod discovery;
pub mod endpoint_cache;
pub mod error;
pub mod pairing;
pub mod proto;
pub mod relay;
pub mod replica;
pub mod ring;
pub mod sas;
pub mod transport;

pub use attest::{static_attestation_message, verify_static_attestation};
pub use ceremony::{
    commit_signing_bytes, commitment, derive_shared_key, key_id, reveal_signing_bytes,
    verify_commit_sig, verify_reveal_sig, Ceremony, Contribution, MemberContribution, Phase,
    SharedKey, Transcript, TranscriptEntry,
};
pub use connect::{connect_first, plan_routes, Route};
pub use discovery::{Advertisement, DiscoveredPeer, PeerTxt};
pub use endpoint_cache::{endpoint_cache_path, EndpointCache};
pub use error::{NetError, Result};
pub use pairing::{pair_initiator, pair_responder, LocalDevice, PendingPair};
pub use proto::{
    CommitData, Frame, GetCommit, GetObject, GetTip, GetTree, HelloPayload, ObjectData, Ping, Pong,
    RelayConnect, RelayData, ReplicaDone, ReplicaGrant, StateAnnounce, TipAnnounce, TreeData,
    TreeEntryMsg,
};
pub use relay::{relay_accept, relay_connect, Relay, RelayStream};
pub use replica::{
    grant_signing_bytes, pull_replication, pull_replication_pipelined, serve_replication,
    tipannounce_signing_bytes, verify_grant, verify_tipannounce, PullSummary, ReplicaSink,
    ReplicaSource, ServeSummary,
};
pub use ring::{ring_path, Ring, RingEntry};
pub use sas::Sas;
pub use transport::{
    ik_initiator, ik_responder, xx_initiator, xx_responder, NoiseReader, NoiseSession, NoiseWriter,
    SplitIo, SplitSession,
};

/// Control-plane protocol version, carried in the handshake [`HelloPayload`].
/// Bump on an incompatible control-plane change.
pub const PROTOCOL_VERSION: u32 = 1;
