//! soft-fig IPC client: connect, call and reconnect over the daemons' Unix
//! sockets, and the build stamp every request carries (`compat`).
//! `softfig-ipc` re-exports everything here. See
//! `meta/spec-softfig-tui-frontend-split.md` §3.3 in the soft-fig garden.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod client;
pub mod compat;
pub mod socket;

pub use client::{
    call, call_reconnecting, connect, connect_stream, ClientError, ReconnectError, RetryPolicy,
};
pub use socket::{growlightd_runtime_socket_path, runtime_socket_path};

use softfig_protocol_keeperd::proto;
