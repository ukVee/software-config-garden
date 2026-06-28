//! soft-fig IPC: JSON-Lines protocol shared by the daemon, the CLI's
//! daemon-bridge code path, and the MCP bridge.
//!
//! Wire format: one JSON object per line, `\n`-terminated. Both directions
//! identical. See `meta/spec-keeper.md` "IPC protocol" in the soft-fig
//! garden for the design rationale.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod client;
pub mod growlightd;
pub mod proto;
pub mod socket;
pub mod verbs;

pub use client::{call, call_reconnecting, connect, ClientError, ReconnectError, RetryPolicy};
pub use proto::{ErrorKind, Request, Response};
pub use socket::{growlightd_runtime_socket_path, runtime_socket_path};
pub use verbs::*;

/// Bumped on incompatible wire-format changes. M1c ships v1.
pub const PROTOCOL_VERSION: u8 = 1;

/// The in-garden config directory (`<garden_root>/config/`) holding the
/// encrypted, versioned, M5b-backed daemon config files.
pub const GARDEN_CONFIG_DIR: &str = "config";

/// The in-garden fleet config file, relative to the garden root
/// (`<garden_root>/config/growlight.toml`). growlightd reads the full fleet
/// schema (gate + roster) from it through the mount; keeperd reads only its
/// `fleet_enabled` gate to decide whether to start the growlightd unit on
/// unlock. Shared here so those two readers — in separate crates that can't
/// depend on each other — can never drift on the path. See
/// `journal/decisions/decision-growlight-config-in-garden.md`.
pub const GROWLIGHT_CONFIG_FILE: &str = "growlight.toml";
