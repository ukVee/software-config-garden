//! Default socket path resolution.

use std::path::PathBuf;

pub const SOCKET_BASENAME: &str = "softfig-keeperd.sock";

/// Returns `$XDG_RUNTIME_DIR/softfig-keeperd.sock` when `XDG_RUNTIME_DIR`
/// is set; otherwise falls back to `/tmp/softfig-keeperd-<uid>.sock`.
///
/// The fallback is intentional: a running daemon under a misconfigured
/// shell shouldn't quietly bind to a globally-readable path. The
/// `<uid>` suffix on the `/tmp/` fallback keeps the path per-user.
pub fn runtime_socket_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join(SOCKET_BASENAME);
    }
    let uid = current_uid();
    PathBuf::from(format!("/tmp/softfig-keeperd-{uid}.sock"))
}

fn current_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, never fails, and returns a
    // plain integer. The `unsafe` is only required by libc's FFI rules.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}
