//! Daemon-side relock-token plumbing: where the on-tmpfs artifacts live, how
//! they're written `0600`, and the expiry-only prune. The crypto itself lives
//! in `softfig-vault` (`relock.rs`); this module is just filesystem glue plus
//! the canonical paths shared by the mint/redeem handlers and `status`.
//!
//! Both artifacts live in `$XDG_RUNTIME_DIR` (tmpfs), never under `.softfig/`:
//! a reboot wipes them, and the durable vault never gains KEK-recoverable
//! material. The filename embeds a short vault fingerprint so two gardens'
//! daemons can't collide.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use softfig_vault::relock::{vault_fingerprint, RelockBlob};
use softfig_vault::VaultPaths;

/// tmpfs base for the relock artifacts. Mirrors `write_reveal_temp_file`.
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Short hex fingerprint of the vault at `state_dir`, used to name the
/// artifacts so distinct gardens don't share a relock file. `None` when the
/// vault isn't initialized (no `k.self` to hash).
fn fingerprint_tag(state_dir: &Path) -> Option<String> {
    let paths = VaultPaths::for_state_root(state_dir);
    let fp = vault_fingerprint(&paths).ok()?;
    Some(hex::encode(&fp[..6]))
}

/// Canonical path of the wrapped-KEK blob for this garden's daemon.
pub fn blob_path(state_dir: &Path) -> Option<PathBuf> {
    let tag = fingerprint_tag(state_dir)?;
    Some(runtime_dir().join(format!("softfig-relock-{tag}.blob")))
}

/// Canonical path of the persisted token (only written in `relock-arm` mode).
pub fn token_path(state_dir: &Path) -> Option<PathBuf> {
    let tag = fingerprint_tag(state_dir)?;
    Some(runtime_dir().join(format!("softfig-relock-{tag}.token")))
}

/// Write `bytes` to `path` with mode `0600`, replacing any existing file.
/// Truncates an old artifact so a re-mint never appends.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all().ok();
    Ok(())
}

/// Delete the blob + persisted token for this garden (single-use cleanup on a
/// successful redeem). Best-effort.
pub fn remove_artifacts(state_dir: &Path) {
    if let Some(p) = blob_path(state_dir) {
        let _ = std::fs::remove_file(p);
    }
    if let Some(p) = token_path(state_dir) {
        let _ = std::fs::remove_file(p);
    }
}

/// Drop the relock artifacts **only if the blob has expired** (or is
/// unreadable / malformed). A live, unexpired blob is left in place — that's
/// the one a pending `cycle`/`relock` will redeem after the restart. Called at
/// startup, on shutdown, and lazily from `status`.
pub fn prune_expired(state_dir: &Path, now: i64) {
    let Some(bp) = blob_path(state_dir) else {
        return;
    };
    let stale = match std::fs::read(&bp) {
        Ok(bytes) => match RelockBlob::decode(&bytes) {
            Ok(blob) => now >= blob.expires_at,
            Err(_) => true, // malformed → not a usable token, clear it
        },
        Err(_) => return, // no blob present, nothing to prune
    };
    if stale {
        remove_artifacts(state_dir);
    }
}

/// If a live (unexpired) relock blob is armed for this garden, return its
/// `expires_at`. Prunes an expired/malformed one as a side effect. Surfaced in
/// `status` as `relock_pending` + `relock_expires_at`.
pub fn pending_expires_at(state_dir: &Path, now: i64) -> Option<i64> {
    let bp = blob_path(state_dir)?;
    let bytes = std::fs::read(&bp).ok()?;
    match RelockBlob::decode(&bytes) {
        Ok(blob) if now < blob.expires_at => Some(blob.expires_at),
        _ => {
            // Expired or malformed — clean it up and report nothing pending.
            remove_artifacts(state_dir);
            None
        }
    }
}
