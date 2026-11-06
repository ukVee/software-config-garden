//! soft-fig IPC client: connect, call and reconnect over the daemons' Unix
//! sockets. `softfig-ipc` re-exports everything here. See
//! `meta/spec-softfig-tui-frontend-split.md` §3.3 in the soft-fig garden.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
