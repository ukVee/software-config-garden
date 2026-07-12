//! Shared harness helpers for the `softfig-keeperd` integration tests.
//!
//! Each integration test file compiles as its own binary and pulls in only the
//! subset of these helpers it needs, so `#![allow(dead_code)]` keeps `-D
//! warnings` happy for the unused remainder.
//!
//! Only helpers that were **byte-for-byte identical** across the test files (or
//! a strict superset in the case of [`wait_for_socket`]) live here. Per-file
//! domain fixtures, passphrase constants, and near-duplicate variants that
//! diverge semantically stay local to each test.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use softfig_ipc::{ErrorKind, Request, Response};
use softfig_vault::params::VaultParams;

/// Minimum-cost Argon2id so the suite stays under a second per the project's
/// test-perf convention.
pub fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

/// Wait (up to 5s) for the daemon's Unix socket to become *connectable*, not
/// merely present — a `UnixStream::connect` must succeed. Strictly stronger
/// than an existence-only poll, so it is safe for every caller.
pub fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            if let Ok(stream) = UnixStream::connect(path) {
                drop(stream);
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("socket {} did not appear", path.display());
}

/// Send one request over a fresh connection and read back the single-line reply.
pub fn send(socket: &Path, req: &Request) -> Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    let mut bytes = serde_json::to_vec(req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

/// Unwrap an `Ok` response's data, panicking with the error detail otherwise.
pub fn ok_data(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("expected Ok, got {kind:?}: {error}"),
    }
}

/// Unwrap an `Err` response's kind, panicking if it was `Ok`.
pub fn err_kind(resp: Response) -> ErrorKind {
    match resp {
        Response::Err { kind, .. } => kind,
        Response::Ok { data, .. } => panic!("expected Err, got Ok: {data}"),
    }
}
