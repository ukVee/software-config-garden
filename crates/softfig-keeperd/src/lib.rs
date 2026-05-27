//! soft-fig per-device daemon.
//!
//! Holds the unlocked `VaultSession` for the lifetime of the process,
//! serves the IPC verbs from `softfig-ipc` over a Unix socket, and runs
//! the filesystem watcher that fires `manual_edit` commits.
//!
//! Library entry: [`Daemon::start`] binds the socket, returns a handle
//! that owns the accept loop. The handle can be `join()`ed for blocking
//! mode (`softfig daemon start`) or driven by tests in-process.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod classify;
pub mod config;
pub mod daemon;
pub mod fuse_sink;
pub mod handlers;
pub mod keeper_toml;
pub mod layer_b;
pub mod migrate;
pub mod peer;
pub mod server;
pub mod state;
pub mod watcher;

pub use config::KeeperConfig;
pub use daemon::{Daemon, DaemonHandle, KeeperError};
pub use keeper_toml::KeeperToml;
pub use state::State;
