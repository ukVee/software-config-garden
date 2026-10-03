//! Clipboard copy for the reveal flow.
//!
//! The daemon writes a revealed secret to a `0600` temp file under
//! `$XDG_RUNTIME_DIR` and hands the TUI only the *path*. To honor the
//! user's "copy the value" action without the plaintext ever entering the
//! TUI's own memory, we spawn `wl-copy` with its stdin redirected straight
//! from that file — the bytes flow kernel → `wl-copy`, never through a Rust
//! buffer in this process.
//!
//! Wayland-only (`wl-clipboard`). If the tool is missing, the caller falls
//! back to just showing the temp-file path.

use std::fs::File;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

/// Is a usable Wayland clipboard tool on `PATH`?
pub fn clipboard_available() -> bool {
    Command::new("wl-copy")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Pipe the contents of `path` into `wl-copy`'s stdin. The plaintext never
/// lands in this process's heap. Returns an error if the tool is absent or
/// exits non-zero.
pub fn copy_file_to_clipboard(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    let status = Command::new("wl-copy")
        .stdin(Stdio::from(file))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("wl-copy exited with {status}")))
    }
}

/// Pipe a string into `wl-copy`'s stdin — the editor's user-initiated "copy
/// selection". Unlike the reveal flow the bytes are necessarily already in
/// this process (they are the editor buffer, which the daemon already
/// redacted before handing it over); this only fires on an explicit copy
/// action, mirroring the reveal flow's clipboard posture.
pub fn copy_text_to_clipboard(text: &str) -> io::Result<()> {
    use std::io::Write;

    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(text.as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("wl-copy exited with {status}")))
    }
}
