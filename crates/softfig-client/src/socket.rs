//! Default socket path resolution.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

pub const SOCKET_BASENAME: &str = "softfig-keeperd.sock";

/// growlightd's own listen socket (spec-growlight-orchestrator §2/§13). The
/// orchestrator daemon is a *separate* process from keeperd, so it binds a
/// distinct socket beside it under the same per-user runtime dir.
pub const GROWLIGHTD_SOCKET_BASENAME: &str = "softfig-growlightd.sock";

/// `XDG_RUNTIME_DIR` is unset, empty or relative, so there is no private
/// directory for a daemon socket or a runtime secret.
///
/// There is deliberately no fallback (report 174). The old one was `/tmp`, a
/// world-writable directory: another local user could bind
/// `/tmp/<prefix>-<uid>.sock` first, so the daemon's own `bind` failed, and a
/// client would connect to the squatter and send it `unlock`'s passphrase.
/// keeperd's relock token and `reveal`'s plaintext fell back to `/tmp` the
/// same way.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "XDG_RUNTIME_DIR is not set to an absolute path, so there is no private directory for \
     {purpose}. softfig does not fall back to /tmp, where another local user could get there \
     first. Run from a login session (systemd sets XDG_RUNTIME_DIR there), or export \
     XDG_RUNTIME_DIR=/run/user/$(id -u), or pass an explicit socket path where the command \
     takes one."
)]
pub struct NoRuntimeDir {
    /// What needed the directory (a socket's basename, "the relock token"),
    /// so the message says which.
    pub purpose: &'static str,
}

impl From<NoRuntimeDir> for io::Error {
    fn from(e: NoRuntimeDir) -> Self {
        io::Error::new(io::ErrorKind::InvalidInput, e)
    }
}

/// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`, or [`NoRuntimeDir`] when the
/// variable is unset, empty or relative.
pub fn runtime_socket_path() -> Result<PathBuf, NoRuntimeDir> {
    socket_in(std::env::var_os("XDG_RUNTIME_DIR").as_deref(), SOCKET_BASENAME)
}

/// Like [`runtime_socket_path`] but for growlightd's socket: the same
/// `$XDG_RUNTIME_DIR` rule, distinct basename.
pub fn growlightd_runtime_socket_path() -> Result<PathBuf, NoRuntimeDir> {
    socket_in(std::env::var_os("XDG_RUNTIME_DIR").as_deref(), GROWLIGHTD_SOCKET_BASENAME)
}

/// `$XDG_RUNTIME_DIR` itself: the per-user tmpfs for anything that must not
/// sit where another user can reach it first, sockets included. `purpose`
/// names the caller in the refusal.
pub fn runtime_dir(purpose: &'static str) -> Result<PathBuf, NoRuntimeDir> {
    runtime_dir_in(std::env::var_os("XDG_RUNTIME_DIR").as_deref(), purpose)
}

/// The rule, pure over the variable's value. A relative value is refused
/// along with an absent one: the XDG spec says to ignore it, and it would put
/// the file wherever the caller's working directory happens to be.
fn runtime_dir_in(value: Option<&OsStr>, purpose: &'static str) -> Result<PathBuf, NoRuntimeDir> {
    match value.map(Path::new) {
        Some(dir) if dir.is_absolute() => Ok(dir.to_path_buf()),
        _ => Err(NoRuntimeDir { purpose }),
    }
}

fn socket_in(value: Option<&OsStr>, basename: &'static str) -> Result<PathBuf, NoRuntimeDir> {
    runtime_dir_in(value, basename).map(|dir| dir.join(basename))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_runtime_dir_holds_the_socket() {
        assert_eq!(
            socket_in(Some(OsStr::new("/run/user/1000")), SOCKET_BASENAME),
            Ok(PathBuf::from("/run/user/1000/softfig-keeperd.sock"))
        );
    }

    #[test]
    fn no_usable_runtime_dir_is_refused_not_guessed() {
        for dir in [None, Some(""), Some("run/user/1000"), Some("./x")] {
            let got = socket_in(dir.map(OsStr::new), GROWLIGHTD_SOCKET_BASENAME);
            assert_eq!(got, Err(NoRuntimeDir { purpose: GROWLIGHTD_SOCKET_BASENAME }), "{dir:?}");
        }
    }

    #[test]
    fn the_refusal_names_the_socket_and_the_remedy_and_never_tmp_as_a_path() {
        let msg = NoRuntimeDir { purpose: SOCKET_BASENAME }.to_string();
        assert!(msg.contains("softfig-keeperd.sock"), "{msg}");
        assert!(msg.contains("XDG_RUNTIME_DIR=/run/user/$(id -u)"), "{msg}");
        assert!(!msg.contains("/tmp/"), "{msg}");
    }
}
