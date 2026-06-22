//! soft-fig IPC: JSON-Lines protocol shared by the daemon, the CLI's
//! daemon-bridge code path, and the MCP bridge.
//!
//! Wire format: one JSON object per line, `\n`-terminated. Both directions
//! identical. See `meta/spec-keeper.md` "IPC protocol" in the soft-fig
//! garden for the design rationale.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod client;
pub mod proto;
pub mod socket;
pub mod verbs;

pub use client::{call, call_reconnecting, connect, ClientError, ReconnectError, RetryPolicy};
pub use proto::{ErrorKind, Request, Response};
pub use socket::runtime_socket_path;
pub use verbs::*;

/// Bumped on incompatible wire-format changes. M1c ships v1.
pub const PROTOCOL_VERSION: u8 = 1;
