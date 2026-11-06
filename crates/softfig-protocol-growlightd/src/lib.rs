//! soft-fig growlightd wire protocol, with no IO. `softfig-ipc` re-exports
//! everything here. See `meta/spec-softfig-tui-frontend-split.md` §3.2 in the
//! soft-fig garden.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod growlightd;

pub use growlightd::*;

use softfig_protocol_keeperd::verbs;
