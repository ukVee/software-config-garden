//! Runner daemon errors.

use std::io;

/// Top-level error type for `softfig-runnerd`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("malformed {what}: {why}")]
    Malformed { what: &'static str, why: String },

    #[error("config parse error: {0}")]
    ConfigToml(#[from] toml::de::Error),

    #[error("config serialize error: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("admin protocol error: {0}")]
    Protocol(String),

    #[error("network error: {0}")]
    Net(#[from] softfig_net::NetError),

    #[error("toolchain missing: run `{0}` on the runner")]
    ToolchainMissing(String),
}

impl Error {
    /// Build a [`Error::Malformed`] from a `what` and a `why`.
    pub fn malformed(what: &'static str, why: impl Into<String>) -> Self {
        Error::Malformed {
            what,
            why: why.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
