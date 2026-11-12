//! One growlightd per socket (review 061 F3).
//!
//! `server::start` unlinks and re-binds the socket unconditionally, and the boot
//! reconcile requeues every `active` entry it cannot see a holder for. A second
//! growlightd started by hand would therefore steal the live instance's socket,
//! requeue its running entries and claim them again: two members on one worktree.
//!
//! The guard is an exclusive, non-blocking `flock` on a lock file beside the
//! socket, taken first thing in `main`, before the socket is unlinked or anything
//! reconciles. The kernel drops the lock when the holder's fd closes on any exit
//! (a crash included), so there is no stale-pidfile logic. The holder writes its
//! pid into the file as a courtesy for the loser's error message; the lock, not
//! the pid, is the truth.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Why [`InstanceLock::acquire`] did not hand back a lock.
#[derive(Debug, thiserror::Error)]
pub enum SingletonError {
    /// Another growlightd holds the lock for this socket.
    #[error("another softfig-growlightd already serves {socket}{}", holder_suffix(*.holder))]
    Held {
        socket: PathBuf,
        /// The holder's pid, when its lock file could be read.
        holder: Option<u32>,
    },
    /// The lock file could not be opened or locked for a reason other than a
    /// holder, so the singleton cannot be vouched for and the daemon must not
    /// start.
    #[error("cannot take the growlightd instance lock {lock}: {source}")]
    Io { lock: PathBuf, source: io::Error },
}

fn holder_suffix(holder: Option<u32>) -> String {
    holder.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
}

/// The held lock. Keep it alive for the whole run; dropping it (or exiting)
/// releases it.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

/// The lock file for a socket: `<socket>.lock`, in the same directory.
pub fn lock_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

impl InstanceLock {
    /// Take the singleton lock for `socket`, or say who holds it. Never touches
    /// the socket itself.
    pub fn acquire(socket: &Path) -> Result<InstanceLock, SingletonError> {
        let lock = lock_path(socket);
        let io_err = |source| SingletonError::Io { lock: lock.clone(), source };
        if let Some(parent) = lock.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        // No truncate: the file carries the holder's pid, and a loser must not
        // wipe it before reading it.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock)
            .map_err(io_err)?;
        match try_flock_exclusive(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(SingletonError::Held {
                    socket: socket.to_path_buf(),
                    holder: read_pid(&mut file),
                });
            }
            Err(e) => return Err(io_err(e)),
        }
        // Ours now: record the pid. Best effort, the lock is already the truth.
        let _ = file.set_len(0);
        let _ = write!(file, "{}", std::process::id());
        let _ = file.flush();
        Ok(InstanceLock { _file: file })
    }
}

fn read_pid(file: &mut File) -> Option<u32> {
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    text.trim().parse().ok()
}

#[allow(unsafe_code)]
fn try_flock_exclusive(file: &File) -> io::Result<()> {
    loop {
        // SAFETY: `flock` takes a valid open fd (borrowed from `file` for the
        // call) and a flag word, and touches no memory.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("growlightd.sock")
    }

    #[test]
    fn the_lock_file_sits_beside_the_socket() {
        assert_eq!(
            lock_path(Path::new("/run/user/1000/softfig-growlightd.sock")),
            PathBuf::from("/run/user/1000/softfig-growlightd.sock.lock")
        );
    }

    #[test]
    fn a_second_acquire_is_refused_naming_the_socket_and_the_holder_pid() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_in(&dir);
        let _held = InstanceLock::acquire(&socket).unwrap();

        let err = InstanceLock::acquire(&socket).unwrap_err();
        match &err {
            SingletonError::Held { socket: s, holder } => {
                assert_eq!(s, &socket);
                assert_eq!(*holder, Some(std::process::id()), "the holder wrote its pid");
            }
            other => panic!("expected Held, got {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains(&socket.display().to_string()), "{msg}");
        assert!(msg.contains(&std::process::id().to_string()), "{msg}");
    }

    #[test]
    fn a_refused_acquire_leaves_the_holders_pid_and_the_socket_alone() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_in(&dir);
        std::fs::write(&socket, b"live socket stand-in").unwrap();
        let _held = InstanceLock::acquire(&socket).unwrap();

        let _ = InstanceLock::acquire(&socket).unwrap_err();
        let _ = InstanceLock::acquire(&socket).unwrap_err();

        assert_eq!(std::fs::read(&socket).unwrap(), b"live socket stand-in");
        let pid = std::fs::read_to_string(lock_path(&socket)).unwrap();
        assert_eq!(pid, std::process::id().to_string(), "a loser never truncates the pid");
    }

    #[test]
    fn dropping_the_holder_frees_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_in(&dir);
        let held = InstanceLock::acquire(&socket).unwrap();
        assert!(InstanceLock::acquire(&socket).is_err());
        drop(held);
        InstanceLock::acquire(&socket).expect("the kernel dropped the lock with the fd");
    }

    #[test]
    fn a_leftover_lock_file_with_no_holder_is_not_a_holder() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_in(&dir);
        std::fs::write(lock_path(&socket), "999999").unwrap();
        InstanceLock::acquire(&socket).expect("a stale pid in an unlocked file is not a lock");
        assert_eq!(
            std::fs::read_to_string(lock_path(&socket)).unwrap(),
            std::process::id().to_string(),
            "the new holder overwrote the stale pid"
        );
    }

    #[test]
    fn an_unusable_lock_path_is_an_error_not_a_pass() {
        let dir = tempfile::tempdir().unwrap();
        // The lock file's name is a directory: opening it for write fails.
        let socket = socket_in(&dir);
        std::fs::create_dir(lock_path(&socket)).unwrap();
        assert!(matches!(
            InstanceLock::acquire(&socket),
            Err(SingletonError::Io { .. })
        ));
    }
}
