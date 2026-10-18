//! Error type for the networking layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A Noise handshake or transport-message failure. Covers decrypt/auth
    /// failures (tampered ciphertext, wrong static key), so it doubles as the
    /// "authentication failed" signal.
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),

    #[error("protobuf decode: {0}")]
    Decode(#[from] prost::DecodeError),

    /// Failed to parse the `peers.toml` ring file.
    #[error("ring decode: {0}")]
    RingDecode(#[from] toml::de::Error),

    /// Failed to serialize the `peers.toml` ring file.
    #[error("ring encode: {0}")]
    RingEncode(#[from] toml::ser::Error),

    /// An mDNS discovery failure (`mdns-sd`).
    #[error("mdns: {0}")]
    Mdns(#[from] mdns_sd::Error),

    /// A framing or protocol-level violation that isn't a crypto failure
    /// (e.g. an oversized frame, a key of the wrong length, a malformed ring
    /// entry, or a rejected pairing attestation).
    #[error("protocol: {0}")]
    Protocol(&'static str),

    /// Task 059: the peer answered a shared-chain push with a signed
    /// `ChainRejected` frame instead of pulling the tree — a *decision*, not a
    /// transport failure. Boxed to keep `NetError` small. The caller must
    /// distinguish this from every other variant: the rest mean "try again",
    /// this one may mean "you are not a member and never will be by retrying".
    #[error("peer refused chain {}: {}", .0.chain, .0.reason)]
    ChainRejected(Box<crate::turn::ChainRejection>),

    /// The runner certificate failed verification (expired, revoked, wrong
    /// identity, bad signature, or a handshake-static mismatch) — a
    /// local-fallback trigger (spec §3.3), never a job.
    #[error("runner certificate: {0}")]
    RunnerCert(String),

    /// Requester-side `config/runner.toml` parsing/resolution failed (slice
    /// 007). Carries a dynamic message so a bad config is a *clear* error, never
    /// a silent default.
    #[error("config: {0}")]
    Config(String),

    /// A source-transfer failure on the requester side (snapshot/bundle build
    /// failed — e.g. a git error) carrying a dynamic message. Slice 004.
    #[error("source: {0}")]
    Source(String),

    /// M5b: a replication sink/source failure carrying a dynamic message —
    /// a storage error, a malformed wire row, or a security-relevant check the
    /// host rejected (bad commit signature, wrong author, content-address
    /// mismatch). The caller surfaces these (and alarms on the tamper cases).
    #[error("replica: {0}")]
    Replica(String),
}

pub type Result<T> = std::result::Result<T, NetError>;
