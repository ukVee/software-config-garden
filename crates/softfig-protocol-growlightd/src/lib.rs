//! soft-fig growlightd wire protocol, with no IO. `softfig-ipc` re-exports
//! everything here. See `meta/spec-softfig-tui-frontend-split.md` §3.2 in the
//! soft-fig garden.
//!
//! **Unstable.** This crate is `0.x` and makes no stability promise: any version
//! bump may break it. A client that depends on it accepts that drift, and opts in
//! visibly in its own `Cargo.toml`. `softfig-protocol-keeperd` is the surface
//! that will become stable: see `docs/protocol-stability.md`.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod growlightd;

pub use growlightd::*;

use softfig_protocol_keeperd::verbs;
