//! Default socket path resolution.

use std::path::PathBuf;

pub const SOCKET_BASENAME: &str = "softfig-keeperd.sock";

/// growlightd's own listen socket (spec-growlight-orchestrator §2/§13). The
/// orchestrator daemon is a *separate* process from keeperd, so it binds a
/// distinct socket beside it under the same per-user runtime dir.
pub const GROWLIGHTD_SOCKET_BASENAME: &str = "softfig-growlightd.sock";

/// Returns `$XDG_RUNTIME_DIR/softfig-keeperd.sock` when `XDG_RUNTIME_DIR`
/// is set; otherwise falls back to `/tmp/softfig-keeperd-<uid>.sock`.
///
/// The fallback is intentional: a running daemon under a misconfigured
/// shell shouldn't quietly bind to a globally-readable path. The
/// `<uid>` suffix on the `/tmp/` fallback keeps the path per-user.
pub fn runtime_socket_path() -> PathBuf {
    runtime_socket_for(SOCKET_BASENAME, "softfig-keeperd")
}

/// Like [`runtime_socket_path`] but for growlightd's socket — same
/// `$XDG_RUNTIME_DIR`-or-per-user-`/tmp` resolution, distinct basename.
pub fn growlightd_runtime_socket_path() -> PathBuf {
    runtime_socket_for(GROWLIGHTD_SOCKET_BASENAME, "softfig-growlightd")
}

/// Shared resolver: `$XDG_RUNTIME_DIR/<basename>` when set, else a per-user
/// `/tmp/<tmp_prefix>-<uid>.sock` fallback.
fn runtime_socket_for(basename: &str, tmp_prefix: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join(basename);
    }
    let uid = current_uid();
    PathBuf::from(format!("/tmp/{tmp_prefix}-{uid}.sock"))
}

fn current_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, never fails, and returns a
    // plain integer. The `unsafe` is only required by libc's FFI rules.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}
