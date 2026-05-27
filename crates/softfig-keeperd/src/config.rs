//! Daemon configuration: garden root + (optional) relocated state root +
//! socket path.

use std::path::{Path, PathBuf};

use crate::keeper_toml::KeeperToml;

#[derive(Debug, Clone)]
pub struct KeeperConfig {
    pub garden_root: PathBuf,
    /// When `Some(state_root)`, the daemon runs in M2a (FUSE) mode:
    /// `.softfig/` lives at `state_root/.softfig/` and the garden root
    /// is the FUSE mount path. When `None`, the daemon runs in
    /// M1c-compat mode: `.softfig/` lives at `garden_root/.softfig/`.
    pub state_root: Option<PathBuf>,
    pub socket_path: PathBuf,
    /// When true, the watcher thread is started after `unlock`. Tests
    /// disable this to keep the runtime predictable.
    pub enable_watcher: bool,
    /// When true (M2a mode only), the daemon mounts a FUSE filesystem
    /// over `garden_root` after the unlock transition. Tests disable
    /// this to exercise the daemon's M2a wiring without the real mount.
    pub enable_fuse: bool,
    /// M2b: `softfig reveal` re-prompt policy.
    pub reveal: RevealConfig,
}

/// M2b: `softfig reveal` configuration. `idle_seconds = 0` (the default)
/// makes every reveal re-prompt the master password; a positive value
/// permits the daemon to skip re-prompt if the previous successful
/// reveal happened within that window.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevealConfig {
    pub idle_seconds: u64,
}

impl KeeperConfig {
    pub fn new(garden_root: impl AsRef<Path>) -> Self {
        Self {
            garden_root: garden_root.as_ref().to_path_buf(),
            state_root: None,
            socket_path: softfig_ipc::runtime_socket_path(),
            enable_watcher: true,
            enable_fuse: true,
            reveal: RevealConfig::default(),
        }
    }

    /// Build the config and resolve `state_root` from `keeper.toml`.
    ///
    /// Search order matches what `softfig migrate` writes:
    /// 1. `<garden_root>/.softfig/keeper.toml` (pre-finalize layout —
    ///    `.softfig/` still in the garden, `keeper.toml` here points at
    ///    the new state root).
    /// 2. (No fallback. If the user manually relocated `.softfig/`
    ///    without writing keeper.toml in the garden root, the daemon
    ///    can't find it. That's deliberate — the daemon refuses to
    ///    guess.)
    pub fn discover(garden_root: impl AsRef<Path>) -> std::io::Result<Self> {
        let garden_root = garden_root.as_ref().to_path_buf();
        let cfg = KeeperToml::load(&garden_root)?;
        Ok(Self {
            garden_root,
            state_root: cfg.state_root,
            socket_path: softfig_ipc::runtime_socket_path(),
            enable_watcher: true,
            enable_fuse: true,
            reveal: RevealConfig {
                idle_seconds: cfg.reveal.idle_seconds,
            },
        })
    }

    pub fn with_reveal_idle_seconds(mut self, secs: u64) -> Self {
        self.reveal.idle_seconds = secs;
        self
    }

    pub fn with_socket(mut self, path: impl AsRef<Path>) -> Self {
        self.socket_path = path.as_ref().to_path_buf();
        self
    }

    pub fn with_state_root(mut self, state_root: impl AsRef<Path>) -> Self {
        self.state_root = Some(state_root.as_ref().to_path_buf());
        self
    }

    pub fn without_watcher(mut self) -> Self {
        self.enable_watcher = false;
        self
    }

    pub fn without_fuse(mut self) -> Self {
        self.enable_fuse = false;
        self
    }

    /// Directory containing the on-disk `.softfig/`. Equals
    /// `garden_root` in M1c-compat mode, the relocated state root in
    /// M2a mode.
    pub fn state_dir(&self) -> &Path {
        self.state_root.as_deref().unwrap_or(&self.garden_root)
    }

    pub fn is_fuse_mode(&self) -> bool {
        self.state_root.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discover_without_keeper_toml_is_m1c_compat() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = KeeperConfig::discover(tmp.path()).unwrap();
        assert!(!cfg.is_fuse_mode(), "no keeper.toml → no FUSE");
        assert_eq!(cfg.state_dir(), tmp.path());
    }

    #[test]
    fn discover_born_in_fuse_keeper_toml_enters_fuse_mode() {
        // A born-in-FUSE garden (as `softfig onboard` writes it): the
        // garden root holds a keeper.toml pointing at a relocated state
        // root. `discover` must put the daemon in FUSE mode.
        let garden = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let softfig = garden.path().join(".softfig");
        fs::create_dir_all(&softfig).unwrap();
        fs::write(
            softfig.join("keeper.toml"),
            format!("state_root = {:?}\n", state.path()),
        )
        .unwrap();

        let cfg = KeeperConfig::discover(garden.path()).unwrap();
        assert!(cfg.is_fuse_mode(), "keeper.toml with state_root → FUSE");
        assert_eq!(cfg.state_dir(), state.path());
    }
}
