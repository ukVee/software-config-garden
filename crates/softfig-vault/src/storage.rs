use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::error::{Result, VaultError};
use crate::params::{ActiveKey, VaultParams, CURRENT_FORMAT_VERSION};

/// `.softfig/vault/` lives under the state root (M1c default: same as garden root).
pub const VAULT_DIR: &str = ".softfig/vault";
pub const PARAMS_FILE: &str = "params.toml";
pub const ACTIVE_FILE: &str = "active.toml";
pub const KEK_SELF_FILE: &str = "k.self";
pub const KEK_RECOVERY_FILE: &str = "k.recovery";
pub const IDENTITY_FILE: &str = "identity.key";
pub const TRANSPORT_FILE: &str = "transport.key";
pub const MASTER_DIR: &str = "master";
pub const SHARED_KEYS_DIR: &str = "shared-keys";

/// Path helper centralizing the on-disk layout. Construct via `VaultPaths::for_garden`.
#[derive(Debug, Clone)]
pub struct VaultPaths {
    pub root: PathBuf,
}

impl VaultPaths {
    /// State root holds the `.softfig/` tree. M1c-compat passes the
    /// garden root; M2a passes the relocated state root.
    pub fn for_state_root(state_root: &Path) -> Self {
        Self {
            root: state_root.join(VAULT_DIR),
        }
    }

    /// Backwards-compat alias for [`Self::for_state_root`]. M1c callers
    /// pass the garden root, which (in M1c-compat mode) equals the
    /// state root.
    pub fn for_garden(garden_root: &Path) -> Self {
        Self::for_state_root(garden_root)
    }

    pub fn params(&self) -> PathBuf {
        self.root.join(PARAMS_FILE)
    }
    pub fn active(&self) -> PathBuf {
        self.root.join(ACTIVE_FILE)
    }
    pub fn kek_self(&self) -> PathBuf {
        self.root.join(KEK_SELF_FILE)
    }
    pub fn kek_recovery(&self) -> PathBuf {
        self.root.join(KEK_RECOVERY_FILE)
    }
    pub fn identity(&self) -> PathBuf {
        self.root.join(IDENTITY_FILE)
    }
    pub fn transport(&self) -> PathBuf {
        self.root.join(TRANSPORT_FILE)
    }
    pub fn master_dir(&self) -> PathBuf {
        self.root.join(MASTER_DIR)
    }
    pub fn master(&self, id: u32) -> PathBuf {
        self.master_dir().join(format!("{id}.key"))
    }
    /// M5d — sealed shared-subtree keys, one file per `key_id`. Each holds an
    /// externally-derived key `S` (the collaborative ceremony's output) sealed
    /// under the master key, so it is readable only through an unlocked
    /// session. See [`crate::session::VaultSession::store_shared_key`].
    pub fn shared_keys_dir(&self) -> PathBuf {
        self.root.join(SHARED_KEYS_DIR)
    }
    /// The sealed file for one shared key. `key_id` must already be validated
    /// (the session methods own that) — this only joins the path.
    pub fn shared_key(&self, key_id: &str) -> PathBuf {
        self.shared_keys_dir().join(format!("{key_id}.key"))
    }

    pub fn exists(&self) -> bool {
        self.params().exists()
    }
}

/// Walk up from `start` looking for a directory containing `.softfig/`.
/// Returns the garden root (the dir that contains `.softfig`).
pub fn discover_garden(start: &Path) -> Option<PathBuf> {
    let mut here = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(start)
    };
    loop {
        if here.join(".softfig").is_dir() {
            return Some(here);
        }
        if !here.pop() {
            return None;
        }
    }
}

pub fn load_params(paths: &VaultPaths) -> Result<VaultParams> {
    if !paths.exists() {
        return Err(VaultError::NotInitialized(paths.root.clone()));
    }
    let raw = fs::read_to_string(paths.params())?;
    let params: VaultParams = toml::from_str(&raw)?;
    if params.format_version != CURRENT_FORMAT_VERSION {
        return Err(VaultError::UnsupportedFormat(params.format_version));
    }
    Ok(params)
}

pub fn store_params(paths: &VaultPaths, params: &VaultParams) -> Result<()> {
    let raw = toml::to_string_pretty(params)?;
    fs::write(paths.params(), raw)?;
    Ok(())
}

pub fn load_active(paths: &VaultPaths) -> Result<ActiveKey> {
    let raw = fs::read_to_string(paths.active())?;
    Ok(toml::from_str(&raw)?)
}

pub fn store_active(paths: &VaultPaths, active: &ActiveKey) -> Result<()> {
    let raw = toml::to_string_pretty(active)?;
    fs::write(paths.active(), raw)?;
    Ok(())
}

pub fn ensure_dirs(paths: &VaultPaths) -> Result<()> {
    fs::create_dir_all(&paths.root)?;
    fs::create_dir_all(paths.master_dir())?;
    Ok(())
}

/// Crash-atomic write with an explicit mode. Stage the bytes to a
/// same-directory temp file created **at `mode` from the start**, fsync them
/// durable, `rename` over the target, then fsync the **containing directory** —
/// an atomic *and* crash-durable publish within one filesystem. A crash leaves
/// either the prior file or an orphan `*.tmp.*` sibling, **never a torn
/// target**, so a half-written sealed key can never wedge its id (a reader
/// either decrypts the old bytes or sees the file absent). The caller owns
/// creating `path`'s parent.
pub(crate) fn atomic_write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = tmp_sibling(path);
    {
        // Create the temp already at `mode` rather than `File::create` (process
        // umask, typically 0644) + a post-hoc chmod: the latter leaves a brief
        // window where the sealed bytes are group/world-readable (LEAK-3).
        // `create_new` refuses a pre-existing path — the temp name is
        // pid+nanotime-unique, so that only fires on a genuine collision, where
        // refusing (rather than clobbering another writer's temp) is correct.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    // fsync the parent directory so the rename (the dirent) is durable, not just
    // the file's data — otherwise a crash right after the rename can drop the
    // just-published entry on some filesystems though the bytes were fsynced,
    // contradicting the "crash-atomic publish" contract above (ROTATE-3).
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    fs::File::open(parent.unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    Ok(())
}

/// A unique same-directory temp path for [`atomic_write_mode`]. Pid + nanotime
/// suffix (matching `softfig-store`'s object writer) — no RNG dep for a name
/// that only needs to avoid a concurrent-writer collision.
fn tmp_sibling(target: &Path) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let name = format!(
        "{}.tmp.{}.{}",
        target.file_name().and_then(|s| s.to_str()).unwrap_or("key"),
        std::process::id(),
        nonce
    );
    target.with_file_name(name)
}

pub fn list_master_ids(paths: &VaultPaths) -> Result<Vec<u32>> {
    let mut ids = Vec::new();
    let dir = paths.master_dir();
    if !dir.is_dir() {
        return Ok(ids);
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".key") {
            if let Ok(id) = stem.parse::<u32>() {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // M5d slice 018 — `atomic_write_mode` publishes the sealed-key bytes at the
    // requested mode with no looser umask window (LEAK-3) and cleans up its temp
    // sibling on a successful rename. The parent-dir fsync (ROTATE-3) is a
    // durability guarantee that isn't observable without crashing the kernel, so
    // it rides on review + the docstring; these tests pin the observable surface:
    // round-trip, published mode, clean publish, and overwrite-existing.

    #[test]
    fn atomic_write_mode_roundtrips_and_publishes_at_mode() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("secret.key");

        atomic_write_mode(&target, b"sealed-ciphertext", 0o600).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"sealed-ciphertext");
        // Published at exactly 0600. Because the temp is created via
        // create_new(mode) and never chmod'd afterward, the bytes are never on
        // disk at a looser mode even transiently.
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // A successful publish leaves no orphan temp sibling.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp sibling must be renamed away");
    }

    #[test]
    fn atomic_write_mode_overwrites_an_existing_target() {
        // create_new(true) applies to the *unique* temp, not the target, so a
        // rename over an existing target still replaces it atomically.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("secret.key");

        atomic_write_mode(&target, b"old", 0o600).unwrap();
        atomic_write_mode(&target, b"new-longer-bytes", 0o600).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new-longer-bytes");
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
