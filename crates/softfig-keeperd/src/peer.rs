//! `SO_PEERCRED` check: defense-in-depth over filesystem permissions.
//!
//! Filesystem mode `0600` on the socket file is the primary boundary,
//! but a chmod accident or weird umask shouldn't accidentally hand a
//! key-holding daemon to another local user. Every accepted connection
//! has its peer UID checked against the daemon's own. The same credentials
//! carry the peer's pid, which [`crate::caller`] reads the peer's member from.

use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[allow(unsafe_code)]
fn peer_cred(stream: &UnixStream) -> io::Result<libc::ucred> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into `cred`,
    // which is sized exactly `len`. `fd` outlives the call (we hold
    // the `UnixStream`). No threading hazards — getsockopt is MT-safe.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred)
}

/// The pid of the process on the other end of `stream`, as the kernel recorded
/// it at `connect`. `0` when the peer is in another pid namespace.
pub fn peer_pid(stream: &UnixStream) -> io::Result<u32> {
    Ok(peer_cred(stream)?.pid as u32)
}

#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and returns a plain integer.
    unsafe { libc::geteuid() }
}

/// Returns Ok(()) if the peer's UID matches the daemon's own. Returns
/// an error in every other case (peer is a different uid, or the
/// getsockopt call itself failed).
pub fn require_same_uid(stream: &UnixStream) -> io::Result<()> {
    let me = current_uid();
    let them = peer_cred(stream)?.uid;
    if me == them {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer uid {them} != daemon uid {me}"),
        ))
    }
}
