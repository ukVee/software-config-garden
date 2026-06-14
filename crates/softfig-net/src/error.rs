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

    /// M5b: a replication sink/source failure carrying a dynamic message —
    /// a storage error, a malformed wire row, or a security-relevant check the
    /// host rejected (bad commit signature, wrong author, content-address
    /// mismatch). The caller surfaces these (and alarms on the tamper cases).
    #[error("replica: {0}")]
    Replica(String),
}

pub type Result<T> = std::result::Result<T, NetError>;
