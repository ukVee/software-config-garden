//! soft-fig keeperd wire protocol: the JSON-Lines envelope and the keeperd verb
//! types, with no IO. `softfig-ipc` re-exports everything here. See
//! `meta/spec-softfig-tui-frontend-split.md` §3.1 in the soft-fig garden.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod proto;
pub mod queue_v2;
pub mod verbs;

pub use proto::{ErrorKind, Request, Response};
pub use verbs::*;

/// Bumped on incompatible wire-format changes. M1c ships v1.
pub const PROTOCOL_VERSION: u8 = 1;
