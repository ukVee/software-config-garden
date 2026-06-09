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

    /// A framing or protocol-level violation that isn't a crypto failure
    /// (e.g. an oversized frame, or a key of the wrong length).
    #[error("protocol: {0}")]
    Protocol(&'static str),
}

pub type Result<T> = std::result::Result<T, NetError>;
