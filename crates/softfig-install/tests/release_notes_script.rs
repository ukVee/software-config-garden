//! `scripts/release-notes.sh` — the release workflow's notes extraction
//! (report 080): a tag must never publish blank or stale notes.

use std::path::{Path, PathBuf};
use std::process::Command;

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/release-notes.sh")
}

/// Run the script for `version` over `changelog`: `Ok(stdout)` on success,
/// `Err(stderr)` on failure.
fn notes(version: &str, changelog: &str) -> Result<String, String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("CHANGELOG.md");
    std::fs::write(&path, changelog).unwrap();
    let out = Command::new("bash").arg(script()).arg(version).arg(&path).output().unwrap();
    if out.status.success() {
        Ok(String::from_utf8(out.stdout).unwrap())
    } else {
        Err(String::from_utf8(out.stderr).unwrap())
    }
}

const RELEASED: &str = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] - 2026-11-01\n\n### Added\n\n- the thing\n\n## [0.9.0] - 2026-10-01\n\n- old\n";

#[test]
fn the_tags_section_is_printed() {
    let out = notes("1.0.0", RELEASED).unwrap();
    assert!(out.starts_with("## [1.0.0] - 2026-11-01"), "{out}");
    assert!(out.contains("- the thing"), "{out}");
    assert!(!out.contains("old"), "the next section leaked in: {out}");
}

#[test]
fn a_missing_section_fails() {
    let err = notes("1.1.0", RELEASED).unwrap_err();
    assert!(err.contains("no '## [1.1.0]' section"), "{err}");
}

#[test]
fn an_empty_section_fails() {
    let err = notes("1.0.0", "## [Unreleased]\n\n## [1.0.0] - 2026-11-01\n\n## [0.9.0]\n- old\n").unwrap_err();
    assert!(err.contains("is empty"), "{err}");
}

/// The near case at review time: entries under [Unreleased] and a
/// pre-pipeline section for the tag would publish the old notes.
#[test]
fn entries_left_under_unreleased_fail() {
    let stale = "## [Unreleased]\n\n### Added\n\n- new pipeline\n\n## [1.0.0] - 2026-10-17\n\n- pre-pipeline\n";
    let err = notes("1.0.0", stale).unwrap_err();
    assert!(err.contains("still lists entries under [Unreleased]"), "{err}");
}

#[test]
fn a_versions_dots_are_not_wildcards() {
    let err = notes("1.0.0", "## [Unreleased]\n\n## [1x0x0]\n\n- nope\n").unwrap_err();
    assert!(err.contains("no '## [1.0.0]' section"), "{err}");
}
