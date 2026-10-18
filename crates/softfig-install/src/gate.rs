//! The toolchain gate (round-2 decision 6): accept a distro `rustc` that is
//! recent enough for the from-source program build, else print the exact
//! `rustup` bootstrap command and stop. The helper never silently installs a
//! second toolchain — that is the user's consented choice.
//!
//! The gate compares `rustc --version` against the *required* minimum read from
//! the source's own `Cargo.toml` (`[workspace.package] rust-version`, falling
//! back to `[package] rust-version`), so the gate tracks the workspace
//! `rust-version` bump automatically instead of a manual constant that drifts.
//! [`Gate::check`] is deliberately a **pure** check over the version string +
//! required minimum, so the unit tests exercise the decision without a
//! toolchain on `PATH`; [`Gate::probe`] is the thin I/O wrapper that runs
//! `rustc --version` *in the source dir* (so a pinned `rust-toolchain.toml`
//! applies) and fails closed (`RUSTUP_AUTO_INSTALL=0`) instead of silently
//! installing a second toolchain.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use semver::Version;

/// What the gate found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// `rustc` present and recent enough.
    Recent { version: Version },
    /// `rustc` present but older than the required minimum.
    TooOld { version: Version, required: Version },
    /// `rustc` not found (or its `--version` output didn't parse).
    Absent { required: Version },
}

impl Gate {
    /// Gate on the output of `rustc --version` (`None` when the command is
    /// absent or failed) against the required minimum. Pure over the string.
    pub fn check(required: &Version, rustc_version_output: Option<&str>) -> Gate {
        let Some(output) = rustc_version_output else {
            return Gate::Absent { required: required.clone() };
        };
        match version_from_rustc_output(output) {
            Some(version) if version >= *required => Gate::Recent { version },
            Some(version) => Gate::TooOld { version, required: required.clone() },
            None => Gate::Absent { required: required.clone() },
        }
    }

    /// Run `rustc --version` *in the source dir* and gate it against the
    /// required minimum read from the source's own manifest. The probe itself
    /// is best-effort (a spawn failure reads as [`Gate::Absent`]); the
    /// required-version read is a hard error — a source that declares no
    /// `rust-version` cannot be gated, so refuse rather than guess.
    pub fn probe(source: &Path) -> Result<Gate> {
        let required = required_rustc(source)?;
        let out = Command::new("rustc")
            .arg("--version")
            // `cwd = source` so a pinned `rust-toolchain.toml` in the source
            // applies; the env fails closed so a probe can never trigger a
            // silent rustup auto-install of a second toolchain.
            .current_dir(source)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
        Ok(Gate::check(&required, out.as_deref()))
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Gate::Recent { .. })
    }
}

/// The minimum `rustc` the from-source build accepts, read from the source's
/// own `Cargo.toml`: `[workspace.package] rust-version`, falling back to
/// `[package] rust-version` (the same TOML-read pattern as `declared_version()`
/// in `cmd_upgrade.rs`). Every member here inherits `rust-version.workspace =
/// true`, so the workspace value is what the build will require.
pub fn required_rustc(source: &Path) -> Result<Version> {
    let manifest = source.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let doc: toml::Value = toml::from_str(&text)
        .with_context(|| format!("parsing {}", manifest.display()))?;
    let declared = doc
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("rust-version"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            doc.get("package")
                .and_then(|p| p.get("rust-version"))
                .and_then(|v| v.as_str())
        });
    let Some(declared) = declared else {
        bail!(
            "no rust-version declared in {} — cannot gate the toolchain",
            manifest.display()
        );
    };
    parse_required(declared)
        .with_context(|| format!("invalid rust-version {declared:?} in {}", manifest.display()))
}

/// Parse a declared `rust-version`. Cargo allows a two-component form
/// (`"1.88"`, as this workspace uses); pad the missing patch so
/// `semver::Version` parses it — the two spell the same minimum.
fn parse_required(declared: &str) -> Result<Version> {
    if let Ok(v) = Version::parse(declared) {
        return Ok(v);
    }
    Ok(Version::parse(&format!("{declared}.0"))?)
}

/// Extract the version from `rustc --version` output (`rustc 1.88.0 (…) …`).
/// The comparison is done on the **core** (major.minor.patch), so a nightly or
/// beta `rustc 1.95.0-nightly (…)` reads as `1.95.0` — recent enough for the
/// build rather than rejected on a pre-release suffix.
fn version_from_rustc_output(output: &str) -> Option<Version> {
    let token = output.split_whitespace().nth(1)?;
    let core = token.split(['-', '+']).next()?;
    Version::parse(core).ok()
}

/// The canonical rustup bootstrap command, printed verbatim on a failed gate.
/// `RUSTUP_AUTO_INSTALL=0` carries the gate's fail-closed posture through to
/// the copy-paste command: rustup installs *itself* but not a toolchain — the
/// toolchain is the user's explicit next step, never a silent second install.
pub const RUSTUP_BOOTSTRAP: &str =
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | RUSTUP_AUTO_INSTALL=0 sh";

/// The message for a failed gate — what the helper prints before stopping.
/// Empty for a passing gate.
pub fn failure_message(gate: &Gate) -> String {
    let (why, required) = match gate {
        Gate::Absent { required } => ("no Rust toolchain found".to_string(), required.clone()),
        Gate::TooOld { version, required } => (
            format!("rustc {version} is older than the required {required}"),
            required.clone(),
        ),
        Gate::Recent { .. } => return String::new(),
    };
    format!(
        "{why}.\n\
         soft-fig builds from source, so it needs rustc >= {required}.\n\
         Install the latest stable Rust with rustup (recommended):\n\
         \n    {RUSTUP_BOOTSTRAP}\n\
         \n\
         …then re-run softfig-install. (This helper never installs a toolchain \
         for you — that is your choice to make.)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required() -> Version {
        Version::new(1, 88, 0)
    }

    #[test]
    fn a_recent_rustc_passes() {
        assert!(matches!(
            Gate::check(&required(), Some("rustc 1.95.0 (59807616e 2026-04-14)")),
            Gate::Recent { version } if version >= required()
        ));
    }

    #[test]
    fn an_old_rustc_is_too_old() {
        assert!(matches!(
            Gate::check(&required(), Some("rustc 1.70.0 (90c541806 2023-05-31)")),
            Gate::TooOld { .. }
        ));
    }

    #[test]
    fn an_absent_rustc_is_absent() {
        assert_eq!(
            Gate::check(&required(), None),
            Gate::Absent { required: required() }
        );
    }

    #[test]
    fn a_nightly_reads_as_its_core() {
        // A nightly of a recent version must pass — its core is >= 1.88.
        assert!(matches!(
            Gate::check(&required(), Some("rustc 1.95.0-nightly (deadbeef 2026-01-01)")),
            Gate::Recent { .. }
        ));
    }

    #[test]
    fn garbage_output_is_absent_not_a_crash() {
        assert_eq!(
            Gate::check(&required(), Some("not really rustc output")),
            Gate::Absent { required: required() }
        );
    }

    #[test]
    fn the_failure_message_names_rustup_and_stops() {
        let msg = failure_message(&Gate::Absent { required: required() });
        assert!(msg.contains(RUSTUP_BOOTSTRAP), "{msg}");
        assert!(msg.contains("never installs a toolchain"), "{msg}");
        // A passing gate has no failure message.
        assert_eq!(
            failure_message(&Gate::check(&required(), Some("rustc 1.95.0 (x)"))),
            ""
        );
    }

    #[test]
    fn required_rustc_reads_the_workspace_rust_version() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace.package]\nrust-version = \"1.88\"\n",
        )
        .unwrap();
        assert_eq!(required_rustc(dir.path()).unwrap(), Version::new(1, 88, 0));
    }

    #[test]
    fn required_rustc_falls_back_to_the_package_rust_version() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\nrust-version = \"1.85.0\"\n",
        )
        .unwrap();
        assert_eq!(required_rustc(dir.path()).unwrap(), Version::new(1, 85, 0));
    }

    #[test]
    fn required_rustc_errors_without_a_rust_version() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        assert!(required_rustc(dir.path()).is_err());
    }
}
