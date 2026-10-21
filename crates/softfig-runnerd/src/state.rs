//! The runner's durable state root (`/var/lib/softfig-runner/` by default,
//! overridable for tests).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// Default state root for the system service (spec §3.1).
pub const DEFAULT_STATE_ROOT: &str = "/var/lib/softfig-runner";

/// The runner's state root and the paths it owns. Everything under it is the
/// runner's alone; the runner never reads a garden, and an escape landing here
/// (the `softfig-runner` uid) must not reach anything else.
#[derive(Debug, Clone)]
pub struct StateRoot {
    root: PathBuf,
}

impl StateRoot {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `keys/` — transport static + attest key, mode 0700.
    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    /// The enforced copy of the garden's `[serve]` table.
    pub fn serve_toml(&self) -> PathBuf {
        self.root.join("serve.toml")
    }

    /// The allowlist of granted requesters.
    pub fn accept_toml(&self) -> PathBuf {
        self.root.join("accept.toml")
    }

    /// The signed runner certificate, written on `enable` once the device
    /// identity has signed it (slice 003 wires the handshake; stored here so
    /// `status` can report expiry).
    pub fn cert_toml(&self) -> PathBuf {
        self.root.join("cert.toml")
    }

    /// `log/` — the durable job run log (`jobs.ndjson`, §6 step 9).
    pub fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }

    /// The signed revocation record (`revocation.toml`), written by
    /// `revoke-cert` and held locally until slice 003 distributes it.
    pub fn revocation_toml(&self) -> PathBuf {
        self.root.join("revocation.toml")
    }

    /// `repos/` — one bare mirror per repo key (slice 004). Purged by
    /// `revoke`/`purge`.
    pub fn repos_dir(&self) -> PathBuf {
        self.root.join("repos")
    }

    /// `cache/` — per-(repo key, toolchain) target caches (slice 006).
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    /// `jobs/` — per-job scratch (the materialized tree, the transient unit's
    /// spec/result files, a fresh cache), one `jobs/<devicehex>/<jobhex>` dir
    /// per job (`JobKey::scratch_dir`). Lives under the state root rather
    /// than `/tmp` because the unit's `PrivateTmp` hides `/tmp` from its
    /// payload, and `ProtectSystem=strict` re-opens only the state root via
    /// `ReadWritePaths` (slice 006 chunk 2).
    pub fn jobs_dir(&self) -> PathBuf {
        self.root.join("jobs")
    }

    /// `cargo/` — the cargo home the fetch step fills and the run step reads
    /// read-only (spec §7.1). Shared across one requester's repos (§7.3).
    pub fn cargo_home_dir(&self) -> PathBuf {
        self.root.join("cargo")
    }

    /// The rustup toolchain root (`RUSTUP_HOME`), bound read-only at
    /// `/opt/toolchain` (spec §7.1). `softfig runner toolchain add` installs
    /// channels here. A test can symlink this path to a real rustup home.
    pub fn rustup_home(&self) -> PathBuf {
        self.root.join("rustup")
    }

    /// Create the state-root layout with the runner's ownership modes (root and
    /// `keys/` 0700; `log/` 0700). Idempotent.
    pub fn ensure_dirs(&self) -> Result<()> {
        create_private_dir(&self.root)?;
        create_private_dir(&self.keys_dir())?;
        create_private_dir(&self.log_dir())?;
        Ok(())
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_paths_are_under_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path());
        assert_eq!(root.keys_dir(), dir.path().join("keys"));
        assert_eq!(root.serve_toml(), dir.path().join("serve.toml"));
        assert_eq!(root.accept_toml(), dir.path().join("accept.toml"));
        assert_eq!(root.cert_toml(), dir.path().join("cert.toml"));
        assert_eq!(root.log_dir(), dir.path().join("log"));
    }

    #[test]
    fn ensure_dirs_creates_private_layout() {
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path().join("state"));
        root.ensure_dirs().unwrap();

        for p in [root.root().to_path_buf(), root.keys_dir(), root.log_dir()] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} must be 0700", p.display());
        }
    }

    #[test]
    fn ensure_dirs_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path());
        root.ensure_dirs().unwrap();
        root.ensure_dirs().unwrap();
    }
}
