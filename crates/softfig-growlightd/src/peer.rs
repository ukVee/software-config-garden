//! `SO_PEERCRED` check: defense-in-depth over the `0600` socket mode, mirroring
//! keeperd's `peer.rs`. A chmod accident shouldn't hand the orchestrator's
//! control surface to another local user.

use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[allow(unsafe_code)]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into `cred`, which is
    // sized exactly `len`. `fd` outlives the call (we hold the `UnixStream`).
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
    Ok(cred.uid)
}

#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and returns a plain integer.
    unsafe { libc::geteuid() }
}

/// Ok(()) iff the peer's uid matches the daemon's own.
pub fn require_same_uid(stream: &UnixStream) -> io::Result<()> {
    let me = current_uid();
    let them = peer_uid(stream)?;
    if me == them {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer uid {them} != daemon uid {me}"),
        ))
    }
}
