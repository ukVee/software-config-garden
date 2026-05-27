//! `keeper.toml` — per-garden config consumed by the daemon and the
//! `softfig migrate` CLI subcommands.
//!
//! Lives at `<garden_root>/.softfig/keeper.toml` (M1c-compat layout) so
//! the file can be discovered without first knowing the state-root
//! relocation. After a successful `softfig migrate prepare`, the same
//! file is written into the new state root so the daemon can read it
//! once the FUSE mount is up.
//!
//! Schema for v1 (open question #1 lean — top-level field):
//!
//! ```toml
//! state_root = "/home/.../<repo_id>/"
//! ```
//!
//! Absent file or absent `state_root` field both mean "M1c-compat
//! layout, no FUSE."

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const KEEPER_TOML: &str = "keeper.toml";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KeeperToml {
    /// Absolute path to the directory containing the on-disk `.softfig/`
    /// tree. When set, the daemon runs in M2a (FUSE) mode and mounts the
    /// garden root as a FUSE filesystem.
    #[serde(default)]
    pub state_root: Option<PathBuf>,
    /// M2b: `softfig reveal` re-prompt policy. Absent table defaults to
    /// `idle_seconds = 0` (always re-prompt).
    #[serde(default)]
    pub reveal: RevealToml,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RevealToml {
    /// Number of seconds after a successful reveal during which the
    /// next reveal may skip the master-password prompt. `0` = always
    /// re-prompt.
    #[serde(default)]
    pub idle_seconds: u64,
}

impl KeeperToml {
    /// Load `keeper.toml` from the location next to a `.softfig/`. Both
    /// "file absent" and "empty file" return [`KeeperToml::default()`]
    /// (i.e., M1c-compat). Other parse errors propagate.
    pub fn load(softfig_parent: &Path) -> std::io::Result<Self> {
        let path = softfig_parent.join(".softfig").join(KEEPER_TOML);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)?;
        toml::from_str(&raw).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })
    }

    /// Write `keeper.toml` next to a `.softfig/`. Creates the parent dir
    /// if absent.
    pub fn store(&self, softfig_parent: &Path) -> std::io::Result<()> {
        let dir = softfig_parent.join(".softfig");
        fs::create_dir_all(&dir)?;
        let path = dir.join(KEEPER_TOML);
        let raw = toml::to_string_pretty(self).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
        fs::write(path, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_missing_returns_default() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = KeeperToml::load(tmp.path()).unwrap();
        assert!(cfg.state_root.is_none());
    }

    #[test]
    fn round_trip_state_root() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = KeeperToml {
            state_root: Some(PathBuf::from("/var/lib/softfig/abc")),
            reveal: RevealToml::default(),
        };
        cfg.store(tmp.path()).unwrap();
        let back = KeeperToml::load(tmp.path()).unwrap();
        assert_eq!(back.state_root, cfg.state_root);
        assert_eq!(back.reveal.idle_seconds, 0);
    }
}
