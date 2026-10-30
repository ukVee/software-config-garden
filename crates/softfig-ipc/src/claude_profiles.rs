//! The claude-login slot store (`claude-login-switcher` slice 006): the ONE
//! resolver that the `softfig claude-login` CLI, `softfig growlight start` and
//! growlightd share, so a slot name can never resolve two ways.
//!
//! A **slot** is a real `CLAUDE_CONFIG_DIR`, `<store>/<slot>/`. Claude Code
//! owns `.credentials.json`, `.claude.json` and `.oauth_refresh.lock` inside
//! it (decision `decision-claude-login-config-dir-slots`). The store is
//! `$XDG_DATA_HOME/softfig/claude-profiles/` (an absolute `$XDG_DATA_HOME`
//! only, else `~/.local/share/softfig/claude-profiles/`). It sits outside
//! `~/.config/softfig/**`, so a fleet member's write grant never covers a
//! credential, and outside `~/.claude/`, so the shared-dir inventory stays
//! clean.
//!
//! The reserved slot [`HOME_SLOT`] means "Claude's default config dir, env
//! var unset". It is the pre-migration state and the fallback.
//!
//! `<store>/active` is a relative symlink whose target text is a bare slot
//! name. It is softfig's pointer, never followed by Claude: readers
//! `readlink` it and resolve the name through [`slot_dir`]. Absent means
//! [`HOME_SLOT`].
//!
//! Path policy is pure (the caller passes the environment in); the
//! inspectors below only stat and readlink, never write.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::slot_name::{validate_slot_name, SlotNameError};

/// The env var that relocates Claude Code's whole config dir.
pub const CONFIG_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";
/// The reserved slot: the default config dir with [`CONFIG_DIR_ENV`] unset.
pub const HOME_SLOT: &str = "home";
/// The store's active-slot pointer (a relative symlink).
pub const ACTIVE_LINK: &str = "active";
/// Claude's OAuth bundle inside a config dir.
pub const CREDENTIALS_FILE: &str = ".credentials.json";
/// Claude's per-account state file inside a config dir (`oauthAccount`,
/// trust, MCP). Under [`HOME_SLOT`] it is `~/.claude.json`, beside, not
/// inside, `~/.claude/`.
pub const ACCOUNT_FILE: &str = ".claude.json";

/// `<data-home>/softfig/claude-profiles`. A relative `$XDG_DATA_HOME` is
/// ignored, as the XDG spec requires and `softfig-deploy` already does.
pub fn store_root(xdg_data_home: Option<&OsStr>, home: &Path) -> PathBuf {
    xdg_data_home
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".local/share"))
        .join("softfig")
        .join("claude-profiles")
}

/// [`store_root`] from the process environment. `None` when `HOME` is unset
/// and `$XDG_DATA_HOME` is not absolute: there is no store to name.
pub fn store_root_from_env() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_DATA_HOME");
    let xdg_ok = xdg.as_deref().is_some_and(|v| Path::new(v).is_absolute());
    let home = std::env::var_os("HOME").map(PathBuf::from);
    match (xdg_ok, home) {
        (_, Some(h)) => Some(store_root(xdg.as_deref(), &h)),
        (true, None) => Some(store_root(xdg.as_deref(), Path::new("/"))),
        (false, None) => None,
    }
}

/// Where a slot name points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotDir {
    /// [`HOME_SLOT`]: run claude with [`CONFIG_DIR_ENV`] unset.
    Home,
    /// A store slot: run claude with [`CONFIG_DIR_ENV`] set to this dir.
    Store(PathBuf),
}

impl SlotDir {
    /// The value to set [`CONFIG_DIR_ENV`] to, or `None` to unset it.
    pub fn config_dir_env(&self) -> Option<&Path> {
        match self {
            SlotDir::Home => None,
            SlotDir::Store(p) => Some(p),
        }
    }
}

/// Shape-check `slot` and name its directory. Does not touch the disk: a
/// store slot that doesn't exist yet still resolves (so `add` can create it).
pub fn slot_dir(store: &Path, slot: &str) -> Result<SlotDir, SlotNameError> {
    validate_slot_name(slot)?;
    if slot == HOME_SLOT {
        return Ok(SlotDir::Home);
    }
    Ok(SlotDir::Store(store.join(slot)))
}

/// Why `<store>/active` does not name a usable slot.
#[derive(Debug)]
pub enum ActiveError {
    /// `stat`/`readlink` failed for a reason other than "absent".
    Io(io::Error),
    /// `active` exists but is not a symlink.
    NotASymlink,
    /// The link's target text is not a bare, well-formed slot name.
    BadTarget(String),
    /// The link names a store slot whose directory is missing (or not a dir).
    Missing(String),
}

impl fmt::Display for ActiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActiveError::Io(e) => write!(f, "cannot read the active pointer: {e}"),
            ActiveError::NotASymlink => write!(f, "the active pointer is not a symlink"),
            ActiveError::BadTarget(t) => {
                write!(f, "the active pointer names {t:?}, which is not a slot name")
            }
            ActiveError::Missing(s) => {
                write!(f, "the active pointer names slot {s:?}, which has no directory")
            }
        }
    }
}

impl std::error::Error for ActiveError {}

/// The slot name `<store>/active` points at, without checking the slot
/// exists. Absent (or a missing store) reads as [`HOME_SLOT`].
pub fn read_active(store: &Path) -> Result<String, ActiveError> {
    let link = store.join(ACTIVE_LINK);
    match fs::symlink_metadata(&link) {
        Ok(md) if md.file_type().is_symlink() => {}
        Ok(_) => return Err(ActiveError::NotASymlink),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HOME_SLOT.to_string()),
        Err(e) => return Err(ActiveError::Io(e)),
    }
    let target = fs::read_link(&link).map_err(ActiveError::Io)?;
    let text = target.to_string_lossy().into_owned();
    match target.to_str() {
        Some(name) if validate_slot_name(name).is_ok() => Ok(name.to_string()),
        _ => Err(ActiveError::BadTarget(text)),
    }
}

/// [`read_active`], resolved to a [`SlotDir`] whose store directory exists.
/// This is what the shell shim (`claude-login dir --active`) and an unpooled
/// spawn act on.
pub fn resolve_active(store: &Path) -> Result<(String, SlotDir), ActiveError> {
    let name = read_active(store)?;
    let dir = slot_dir(store, &name).map_err(|_| ActiveError::BadTarget(name.clone()))?;
    if let SlotDir::Store(p) = &dir
        && !fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
    {
        return Err(ActiveError::Missing(name));
    }
    Ok((name, dir))
}

/// The state of a config dir's `.credentials.json`, judged without reading
/// a byte of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialState {
    /// A regular file, mode `0600` or tighter.
    Ok,
    /// No file at all (a fresh `add --no-login`, or a logged-out slot).
    Missing,
    /// A symlink, directory or other non-regular file. Claude's strict
    /// credential store refuses symlinks, and a rename-on-refresh would
    /// replace one anyway.
    NotRegular,
    /// A regular file readable or writable by group/other (the mode bits).
    LoosePerms(u32),
}

/// Inspect `<config_dir>/.credentials.json` (`lstat` only).
pub fn credential_state(config_dir: &Path) -> io::Result<CredentialState> {
    match fs::symlink_metadata(config_dir.join(CREDENTIALS_FILE)) {
        Ok(md) if !md.file_type().is_file() => Ok(CredentialState::NotRegular),
        Ok(md) => {
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                Ok(CredentialState::LoosePerms(mode))
            } else {
                Ok(CredentialState::Ok)
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(CredentialState::Missing),
        Err(e) => Err(e),
    }
}

/// Why a slot cannot be handed to a `claude` launch (slice 007). Every
/// variant names the slot, so a refused spawn says which account it was for.
#[derive(Debug)]
pub enum LaunchSlotError {
    /// The name is not a slot name.
    BadName(String, SlotNameError),
    /// `<store>/active` does not name a usable slot.
    Active(ActiveError),
    /// The store slot has no directory (or it is not a directory).
    MissingDir(String, PathBuf),
    /// The slot's `.credentials.json` is absent, not a regular file, or
    /// readable by group/other.
    Credential(String, CredentialState),
    /// `lstat` failed on the slot or its credential.
    Io(String, io::Error),
}

impl fmt::Display for LaunchSlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchSlotError::BadName(s, e) => write!(f, "claude-login slot {s:?}: {e}"),
            LaunchSlotError::Active(e) => write!(f, "claude-login: {e}"),
            LaunchSlotError::MissingDir(s, p) => write!(
                f,
                "claude-login slot {s:?} has no directory at {} — `softfig claude-login add {s}`",
                p.display()
            ),
            LaunchSlotError::Credential(s, state) => {
                let what = match state {
                    CredentialState::Missing => "has no .credentials.json (not logged in)".into(),
                    CredentialState::NotRegular => {
                        ".credentials.json is not a regular file".to_string()
                    }
                    CredentialState::LoosePerms(m) => {
                        format!(".credentials.json has loose mode {m:o} (want 0600)")
                    }
                    CredentialState::Ok => "is ok".into(),
                };
                write!(f, "claude-login slot {s:?} {what} — see `softfig claude-login doctor`")
            }
            LaunchSlotError::Io(s, e) => write!(f, "claude-login slot {s:?}: {e}"),
        }
    }
}

impl std::error::Error for LaunchSlotError {}

/// Resolve `slot` for a `claude` launch, failing closed. [`HOME_SLOT`] is
/// returned unchecked: it is Claude's own default config dir, exactly what
/// every launch used before the store existed. A store slot must be a real
/// directory (not a symlink) whose `.credentials.json` is
/// [`CredentialState::Ok`]. There is no fallback to `home` or to another
/// slot: a launch meant for one account never silently runs on another.
///
/// growlightd's spawn seam and `softfig growlight start --profile` both call
/// this, so the fleet and the interactive loop refuse the same slots.
pub fn launch_slot(store: &Path, slot: &str) -> Result<SlotDir, LaunchSlotError> {
    let dir = slot_dir(store, slot).map_err(|e| LaunchSlotError::BadName(slot.into(), e))?;
    let SlotDir::Store(path) = &dir else {
        return Ok(dir);
    };
    match fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() => {}
        Ok(_) => return Err(LaunchSlotError::MissingDir(slot.into(), path.clone())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(LaunchSlotError::MissingDir(slot.into(), path.clone()))
        }
        Err(e) => return Err(LaunchSlotError::Io(slot.into(), e)),
    }
    match credential_state(path) {
        Ok(CredentialState::Ok) => Ok(dir),
        Ok(state) => Err(LaunchSlotError::Credential(slot.into(), state)),
        Err(e) => Err(LaunchSlotError::Io(slot.into(), e)),
    }
}

/// [`launch_slot`] on whatever `<store>/active` names (absent = [`HOME_SLOT`]),
/// read now, so a launch follows the human's latest `use`.
pub fn launch_active(store: &Path) -> Result<(String, SlotDir), LaunchSlotError> {
    let name = read_active(store).map_err(LaunchSlotError::Active)?;
    let dir = launch_slot(store, &name)?;
    Ok((name, dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, OpenOptionsExt};

    #[test]
    fn store_root_prefers_absolute_xdg_data_home() {
        let home = Path::new("/h");
        assert_eq!(
            store_root(Some(OsStr::new("/x")), home),
            PathBuf::from("/x/softfig/claude-profiles")
        );
        assert_eq!(
            store_root(None, home),
            PathBuf::from("/h/.local/share/softfig/claude-profiles")
        );
        assert_eq!(
            store_root(Some(OsStr::new("rel")), home),
            PathBuf::from("/h/.local/share/softfig/claude-profiles"),
            "a relative XDG_DATA_HOME is ignored",
        );
    }

    #[test]
    fn home_is_reserved_and_names_no_dir() {
        let store = Path::new("/s");
        assert_eq!(slot_dir(store, HOME_SLOT).unwrap(), SlotDir::Home);
        assert_eq!(SlotDir::Home.config_dir_env(), None);
        let s = slot_dir(store, "slot2").unwrap();
        assert_eq!(s, SlotDir::Store(PathBuf::from("/s/slot2")));
        assert_eq!(s.config_dir_env(), Some(Path::new("/s/slot2")));
        assert!(slot_dir(store, "../etc").is_err());
    }

    #[test]
    fn absent_active_reads_as_home() {
        let td = tempfile::TempDir::new().unwrap();
        assert_eq!(read_active(td.path()).unwrap(), HOME_SLOT);
        assert_eq!(read_active(&td.path().join("no-store")).unwrap(), HOME_SLOT);
        assert_eq!(resolve_active(td.path()).unwrap(), (HOME_SLOT.into(), SlotDir::Home));
    }

    #[test]
    fn active_resolves_a_present_slot_and_refuses_the_rest() {
        let td = tempfile::TempDir::new().unwrap();
        let store = td.path();
        fs::create_dir(store.join("slot1")).unwrap();
        symlink("slot1", store.join(ACTIVE_LINK)).unwrap();
        assert_eq!(
            resolve_active(store).unwrap(),
            ("slot1".into(), SlotDir::Store(store.join("slot1")))
        );

        fs::remove_file(store.join(ACTIVE_LINK)).unwrap();
        symlink("ghost", store.join(ACTIVE_LINK)).unwrap();
        assert_eq!(read_active(store).unwrap(), "ghost");
        assert!(matches!(resolve_active(store), Err(ActiveError::Missing(s)) if s == "ghost"));

        fs::remove_file(store.join(ACTIVE_LINK)).unwrap();
        symlink("../slot1", store.join(ACTIVE_LINK)).unwrap();
        assert!(matches!(read_active(store), Err(ActiveError::BadTarget(_))));

        fs::remove_file(store.join(ACTIVE_LINK)).unwrap();
        fs::write(store.join(ACTIVE_LINK), "slot1").unwrap();
        assert!(matches!(read_active(store), Err(ActiveError::NotASymlink)));
    }

    #[test]
    fn active_naming_home_resolves_to_home() {
        let td = tempfile::TempDir::new().unwrap();
        symlink(HOME_SLOT, td.path().join(ACTIVE_LINK)).unwrap();
        assert_eq!(resolve_active(td.path()).unwrap(), (HOME_SLOT.into(), SlotDir::Home));
    }

    #[test]
    fn credential_state_classifies_each_shape() {
        let td = tempfile::TempDir::new().unwrap();
        let d = td.path();
        assert_eq!(credential_state(d).unwrap(), CredentialState::Missing);

        let write = |mode| {
            let _ = fs::remove_file(d.join(CREDENTIALS_FILE));
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(d.join(CREDENTIALS_FILE))
                .unwrap();
            fs::set_permissions(d.join(CREDENTIALS_FILE), fs::Permissions::from_mode(mode))
                .unwrap();
        };
        write(0o600);
        assert_eq!(credential_state(d).unwrap(), CredentialState::Ok);
        write(0o644);
        assert_eq!(credential_state(d).unwrap(), CredentialState::LoosePerms(0o644));

        fs::remove_file(d.join(CREDENTIALS_FILE)).unwrap();
        fs::write(d.join("real.json"), "{}").unwrap();
        symlink(d.join("real.json"), d.join(CREDENTIALS_FILE)).unwrap();
        assert_eq!(credential_state(d).unwrap(), CredentialState::NotRegular);
    }

    fn slot_with_creds(store: &Path, slot: &str, mode: u32) {
        fs::create_dir_all(store.join(slot)).unwrap();
        let creds = store.join(slot).join(CREDENTIALS_FILE);
        fs::write(&creds, "{}").unwrap();
        fs::set_permissions(&creds, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn launch_slot_accepts_home_unchecked_and_a_healthy_store_slot() {
        let td = tempfile::TempDir::new().unwrap();
        let store = td.path();
        assert_eq!(launch_slot(store, HOME_SLOT).unwrap(), SlotDir::Home);
        slot_with_creds(store, "slot1", 0o600);
        assert_eq!(launch_slot(store, "slot1").unwrap(), SlotDir::Store(store.join("slot1")));
    }

    #[test]
    fn launch_slot_fails_closed_naming_the_slot() {
        let td = tempfile::TempDir::new().unwrap();
        let store = td.path();
        let err = launch_slot(store, "ghost").unwrap_err();
        assert!(matches!(err, LaunchSlotError::MissingDir(ref s, _) if s == "ghost"));
        assert!(err.to_string().contains("\"ghost\""), "{err}");

        fs::create_dir(store.join("bare")).unwrap();
        assert!(matches!(
            launch_slot(store, "bare"),
            Err(LaunchSlotError::Credential(_, CredentialState::Missing))
        ));

        slot_with_creds(store, "loose", 0o644);
        assert!(matches!(
            launch_slot(store, "loose"),
            Err(LaunchSlotError::Credential(_, CredentialState::LoosePerms(0o644)))
        ));

        fs::create_dir(store.join("linked")).unwrap();
        fs::write(td.path().join("real.json"), "{}").unwrap();
        symlink(td.path().join("real.json"), store.join("linked").join(CREDENTIALS_FILE)).unwrap();
        assert!(matches!(
            launch_slot(store, "linked"),
            Err(LaunchSlotError::Credential(_, CredentialState::NotRegular))
        ));

        // A symlinked slot dir is not a slot: `active`'s resolver refuses it too.
        slot_with_creds(store, "real", 0o600);
        symlink(store.join("real"), store.join("alias")).unwrap();
        assert!(matches!(launch_slot(store, "alias"), Err(LaunchSlotError::MissingDir(..))));

        assert!(matches!(launch_slot(store, "../x"), Err(LaunchSlotError::BadName(..))));
    }

    #[test]
    fn launch_active_follows_the_pointer() {
        let td = tempfile::TempDir::new().unwrap();
        let store = td.path();
        assert_eq!(launch_active(store).unwrap(), (HOME_SLOT.into(), SlotDir::Home));
        slot_with_creds(store, "slot2", 0o600);
        symlink("slot2", store.join(ACTIVE_LINK)).unwrap();
        assert_eq!(
            launch_active(store).unwrap(),
            ("slot2".into(), SlotDir::Store(store.join("slot2")))
        );
        fs::remove_file(store.join("slot2").join(CREDENTIALS_FILE)).unwrap();
        assert!(matches!(launch_active(store), Err(LaunchSlotError::Credential(..))));
    }
}
