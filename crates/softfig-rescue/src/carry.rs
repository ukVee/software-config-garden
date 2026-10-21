//! The carry-file — phase 1's one portable output (`meta/spec-packs.md` →
//! "Recovery packs" → phase 1). A single self-contained **plaintext** file the
//! rescue binary writes to whatever writable media exists (usually the rescue
//! USB itself), and which `softfig onboard` later grows into a garden (phase 2,
//! `recovery-pack-v1`).
//!
//! Three constraints, all load-bearing:
//!
//! - **Plaintext, and the file says so.** There is no key at phase 1 —
//!   inventing one mid-panic is worse than plaintext on the user's own USB.
//!   So the file states, in its own header and in a machine-readable field,
//!   that it is unencrypted and what it contains. This slice performs **no
//!   secret screening** — that is `recovery-pack-v1`'s allowlist capture, not
//!   this slice's — so the header says so rather than claiming a screen the
//!   code does not perform.
//! - **Versioned.** [`CARRY_FORMAT_VERSION`] is stamped into the file so a
//!   later `onboard` — possibly months newer, offline, with no rendezvous with
//!   the writing binary — refuses a file newer than it understands with a
//!   clear message instead of misparsing it (`meta/spec-release.md` → Open
//!   questions → carry-file axis, closed 2026-10-17).
//! - **One document.** Not a directory, not a garden: a single TOML document a
//!   later `onboard` parses in one read.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The carry-file format version. Bump on an incompatible change to the
/// layout. A reader refuses a file whose version is *newer* than this
/// constant ([`CarryError::NewerFormat`]) — the phase-1↔phase-2 compatibility
/// surface.
pub const CARRY_FORMAT_VERSION: u32 = 1;

/// The format marker in the file's `format` field. A reader checks this first:
/// a file without it is not a carry-file.
pub const CARRY_FORMAT: &str = "softfig-carry";

/// The literal header the writer puts above the TOML. It is the human-facing
/// half of the plaintext declaration (the machine-facing half is the
/// `plaintext = true` field): it says, in the file's own words, that the file
/// is unencrypted, what it contains, and how to treat it.
pub const CARRY_HEADER: &str = "\
# soft-fig carry-file — PLAINTEXT
# This file is NOT encrypted. It was written by the soft-fig rescue binary to
# the machine's own writable media (usually the rescue USB) at recovery time.
# It contains a machine manifest, a step log, and the run outcome. It is not
# screened for secrets — treat it as sensitive but not secret: do not copy it
# off the machine it describes without the owner's say-so.
";

/// A carry-file: the header fields plus the three sections `recovery-pack-v1`
/// fills in. This slice writes the header only; the sections are the format's
/// named slots, parsed-but-empty here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarryFile {
    /// [`CARRY_FORMAT`].
    pub format: String,
    /// [`CARRY_FORMAT_VERSION`].
    pub carry_format_version: u32,
    /// The writing binary, `name version`.
    pub generated_by: String,
    /// Creation time, UNIX epoch seconds (UTC). Stored as an integer so the
    /// rescue binary needs no date library; phase 2 (`onboard`) formats it.
    pub created_at_unix: u64,
    /// Always `true` in this format: the file is unencrypted plaintext. An
    /// explicit field, not an implication, so a reader can never mistake this
    /// file for an encrypted one (or vice versa).
    pub plaintext: bool,
    /// The as-found machine manifest. `recovery-pack-v1` populates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<toml::Table>,
    /// The step log. `recovery-pack-v1` populates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steps: Option<toml::Table>,
    /// The run outcome, derived from check results only. `recovery-pack-v1`
    /// populates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<toml::Table>,
}

impl CarryFile {
    /// A fresh, empty carry-file for this build: the header fields, no
    /// sections yet. `now_unix` is the creation time as UNIX epoch seconds.
    pub fn new(now_unix: u64) -> Self {
        Self {
            format: CARRY_FORMAT.to_string(),
            carry_format_version: CARRY_FORMAT_VERSION,
            generated_by: format!("softfig-rescue {}", env!("CARGO_PKG_VERSION")),
            created_at_unix: now_unix,
            plaintext: true,
            machine: None,
            steps: None,
            outcome: None,
        }
    }

    /// Serialize to the on-disk form: the plaintext header, then the TOML.
    pub fn to_document(&self) -> String {
        let mut doc = CARRY_HEADER.to_string();
        doc.push('\n');
        doc.push_str(&toml::to_string_pretty(self).expect("CarryFile serializes to TOML"));
        doc
    }

    /// Write this carry-file to `path`: owner-only (0600 — it is plaintext
    /// and unscreened), and atomically (a sibling temp file, fsynced, renamed
    /// over `path`), so a crash or a yanked USB never leaves a half-written
    /// carry-file (report 081 item 4).
    pub fn write_to(&self, path: &Path) -> Result<(), CarryError> {
        let io_err = |source| CarryError::Io {
            path: path.to_path_buf(),
            source,
        };
        let name = path.file_name().ok_or_else(|| io_err(io::Error::other("no file name")))?;
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(".tmp-{}", std::process::id()));
        let tmp = path.with_file_name(tmp_name);
        let written = (|| {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(self.to_document().as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&tmp, path)?;
            // The rename's directory entry, durable too.
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::File::open(dir)?.sync_all()?;
            }
            Ok(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written.map_err(io_err)
    }

    /// Read and validate a carry-file from `path`. Refuses a file that is not
    /// a carry-file, is a newer format than this build, or claims to be
    /// encrypted.
    pub fn read_from(path: &Path) -> Result<Self, CarryError> {
        let bytes = std::fs::read(path).map_err(|source| CarryError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| CarryError::Parse(format!("{}: not UTF-8 ({e})", path.display())))?;
        // Parse the raw table first so a *future* format (newer version, extra
        // fields) refuses with `NewerFormat` rather than a missing-field parse
        // error.
        let table: toml::Table =
            toml::from_str(text).map_err(|e| CarryError::Parse(format!("{}: {e}", path.display())))?;
        check_format(&table)?;
        let carry: CarryFile = toml::from_str(text)
            .map_err(|e| CarryError::Parse(format!("{}: {e}", path.display())))?;
        if !carry.plaintext {
            return Err(CarryError::NotPlaintext);
        }
        Ok(carry)
    }

    /// The format/version/plaintext checks a reader applies. `write` paths
    /// (tests) use it to confirm a freshly-built file is valid before it ever
    /// touches disk.
    pub fn validate(&self) -> Result<(), CarryError> {
        if self.format != CARRY_FORMAT {
            return Err(CarryError::NotCarryFile(self.format.clone()));
        }
        if self.carry_format_version > CARRY_FORMAT_VERSION {
            return Err(CarryError::NewerFormat {
                found: self.carry_format_version,
                understood: CARRY_FORMAT_VERSION,
            });
        }
        if !self.plaintext {
            return Err(CarryError::NotPlaintext);
        }
        Ok(())
    }
}

impl fmt::Display for CarryFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let section = |v: &Option<toml::Table>| v.as_ref().map_or("empty", |_| "present");
        write!(
            f,
            "{} v{} — written by {} at unix {} — plaintext: {} — machine: {} · steps: {} · outcome: {}",
            self.format,
            self.carry_format_version,
            self.generated_by,
            self.created_at_unix,
            self.plaintext,
            section(&self.machine),
            section(&self.steps),
            section(&self.outcome),
        )
    }
}

/// The format/version checks applied to a raw table *before* full
/// deserialization, so a future format refuses cleanly.
fn check_format(table: &toml::Table) -> Result<(), CarryError> {
    let format = table.get("format").and_then(toml::Value::as_str).unwrap_or_default();
    if format != CARRY_FORMAT {
        return Err(CarryError::NotCarryFile(format.to_string()));
    }
    if let Some(v) = table.get("carry_format_version").and_then(toml::Value::as_integer)
        && v > CARRY_FORMAT_VERSION as i64
    {
        return Err(CarryError::NewerFormat {
            found: v as u32,
            understood: CARRY_FORMAT_VERSION,
        });
    }
    Ok(())
}

/// Everything that can go wrong reading a carry-file.
#[derive(Debug, thiserror::Error)]
pub enum CarryError {
    /// The `format` field is absent or not [`CARRY_FORMAT`].
    #[error("not a soft-fig carry-file (format = {0:?})")]
    NotCarryFile(String),
    /// The file is a newer format than this build understands. This is the
    /// phase-1↔phase-2 refusal: `onboard` shows it verbatim.
    #[error(
        "carry-file format v{found} is newer than this build understands \
         (v{understood}) — run a newer softfig to read it"
    )]
    NewerFormat { found: u32, understood: u32 },
    /// The file is marked encrypted; this build only reads plaintext
    /// carry-files.
    #[error("carry-file is marked encrypted; this build only reads plaintext carry-files")]
    NotPlaintext,
    /// The file is not well-formed TOML (or not UTF-8).
    #[error("{0}")]
    Parse(String),
    /// The file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_carry_file_is_valid_and_round_trips() {
        let carry = CarryFile::new(1_792_327_145);
        assert_eq!(carry.format, CARRY_FORMAT);
        assert_eq!(carry.carry_format_version, CARRY_FORMAT_VERSION);
        assert!(carry.plaintext);
        assert!(carry.validate().is_ok());

        let doc = carry.to_document();
        assert!(doc.starts_with("# soft-fig carry-file"), "{doc}");
        assert!(doc.contains("NOT encrypted"), "header must state plaintext-ness");
        assert!(doc.contains("plaintext = true"), "field must state plaintext-ness");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carry.toml");
        carry.write_to(&path).unwrap();
        let back = CarryFile::read_from(&path).unwrap();
        assert_eq!(back, carry);
    }

    /// Report 081 item 4: the plaintext carry-file is owner-only, replaces an
    /// existing file whole, and leaves no temp file behind.
    #[test]
    fn the_carry_file_is_written_0600_and_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carry.toml");
        std::fs::write(&path, "stale").unwrap();

        CarryFile::new(0).write_to(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
        assert!(CarryFile::read_from(&path).is_ok());
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["carry.toml"], "a temp file was left behind");
    }

    #[test]
    fn a_newer_format_is_refused_with_a_clear_message() {
        let mut carry = CarryFile::new(0);
        carry.carry_format_version = CARRY_FORMAT_VERSION + 1;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carry.toml");
        carry.write_to(&path).unwrap();
        let err = CarryFile::read_from(&path).unwrap_err();
        match &err {
            CarryError::NewerFormat { found, understood } => {
                assert_eq!(*found, CARRY_FORMAT_VERSION + 1);
                assert_eq!(*understood, CARRY_FORMAT_VERSION);
            }
            other => panic!("expected NewerFormat, got {other:?}"),
        }
        assert!(err.to_string().contains("newer than this build understands"), "{err}");
    }

    #[test]
    fn a_file_that_is_not_a_carry_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("junk.toml");
        std::fs::write(&path, "hello = \"world\"\n").unwrap();
        let err = CarryFile::read_from(&path).unwrap_err();
        assert!(matches!(err, CarryError::NotCarryFile(_)), "{err:?}");
    }

    #[test]
    fn an_encrypted_carry_file_is_refused() {
        let mut carry = CarryFile::new(0);
        carry.plaintext = false;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carry.toml");
        carry.write_to(&path).unwrap();
        let err = CarryFile::read_from(&path).unwrap_err();
        assert!(matches!(err, CarryError::NotPlaintext), "{err:?}");
    }

    #[test]
    fn a_newer_version_refuses_even_with_unknown_extra_fields() {
        // A future format adds fields this build doesn't know. The version
        // check must fire before deserialization, so the extra fields are not
        // a parse error.
        let raw = "\
format = \"softfig-carry\"
carry_format_version = 2
generated_by = \"softfig-rescue 2.0.0\"
created_at_unix = 0
plaintext = true
future_field_this_build_ignores = 123
";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.toml");
        std::fs::write(&path, raw).unwrap();
        let err = CarryFile::read_from(&path).unwrap_err();
        assert!(matches!(err, CarryError::NewerFormat { found: 2, .. }), "{err:?}");
    }
}
