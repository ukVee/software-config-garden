use std::fs;
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
