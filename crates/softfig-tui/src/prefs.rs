//! Best-effort TUI-local interface preferences.
//!
//! Two things the user shapes by hand and expects to persist: where the
//! floating menu button sits, and which editor view new files open in. These
//! are *interface* preferences only — no garden content, no file paths beyond
//! the user's own, no secrets. The file lives under the XDG state dir, outside
//! both the garden and its vault, and every operation is best-effort: an
//! unreadable or corrupt file falls back to defaults, and a failed save never
//! interrupts the session (a UI preference is not worth an error dialog).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The persisted UI preferences. `Default` = default corner, raw source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UiPrefs {
    /// Floating menu button top-left cell; `None` = the default corner.
    pub fab: Option<(u16, u16)>,
    /// The editor view new files open in (the last one the user selected):
    /// `true` = bionic reading view, `false` = raw source.
    pub editor_bionic: bool,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    fab_col: Option<u16>,
    fab_row: Option<u16>,
    #[serde(default)]
    editor_bionic: bool,
}

/// The state file path, when the environment gives us a home.
pub fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("softfig").join("tui-ui.json"))
}

pub fn load() -> UiPrefs {
    match path() {
        Some(p) => load_from(&p),
        None => UiPrefs::default(),
    }
}

pub fn save(prefs: &UiPrefs) {
    if let Some(p) = path() {
        save_to(&p, prefs);
    }
}

fn load_from(path: &Path) -> UiPrefs {
    let Ok(text) = std::fs::read_to_string(path) else {
        return UiPrefs::default();
    };
    let Ok(wire) = serde_json::from_str::<Wire>(&text) else {
        return UiPrefs::default();
    };
    UiPrefs {
        fab: wire.fab_col.zip(wire.fab_row),
        editor_bionic: wire.editor_bionic,
    }
}

fn save_to(path: &Path, prefs: &UiPrefs) {
    let wire = Wire {
        fab_col: prefs.fab.map(|f| f.0),
        fab_row: prefs.fab.map(|f| f.1),
        editor_bionic: prefs.editor_bionic,
    };
    let Ok(json) = serde_json::to_string_pretty(&wire) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Temp + rename so a torn write can never leave a half-file behind.
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, json).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("softfig-prefs-{tag}-{nonce}.json"))
    }

    #[test]
    fn round_trips_through_the_state_file() {
        let p = temp_path("roundtrip");
        let prefs = UiPrefs {
            fab: Some((12, 7)),
            editor_bionic: true,
        };
        save_to(&p, &prefs);
        assert_eq!(load_from(&p), prefs);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn absent_and_corrupt_files_fall_back_to_defaults() {
        assert_eq!(load_from(Path::new("/nonexistent/tui-ui.json")), UiPrefs::default());
        let p = temp_path("corrupt");
        std::fs::write(&p, "{ not json").unwrap();
        assert_eq!(load_from(&p), UiPrefs::default());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_half_written_fab_position_is_not_a_position() {
        let p = temp_path("half");
        std::fs::write(&p, r#"{"fab_col": 4, "editor_bionic": true}"#).unwrap();
        let prefs = load_from(&p);
        assert_eq!(prefs.fab, None, "a column without a row is not usable");
        assert!(prefs.editor_bionic, "the other field still loads");
        let _ = std::fs::remove_file(&p);
    }
}
