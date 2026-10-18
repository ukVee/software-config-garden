//! The toolchain gate (round-2 decision 6): accept a distro `rustc` that is
//! recent enough for the from-source program build, else print the exact
//! `rustup` bootstrap command and stop. The helper never silently installs a
//! second toolchain — that is the user's consented choice.
//!
//! The gate compares `rustc --version` against the workspace `rust-version`.
//! It is deliberately a **pure** check over a version string (plus a thin
//! [`Gate::probe`] that runs `rustc --version`), so the unit tests exercise
//! the decision without a toolchain on `PATH`.

use semver::Version;

/// The workspace `rust-version` — the minimum `rustc` the from-source build
/// accepts. Must track the workspace `rust-version` bump; the CI MSRV job pins
/// the same number (`meta/spec-release.md` → "What CI must prove").
///
/// The workspace declares `rust-version = "1.88"` (two components, which cargo
/// allows); written here in full semver form `1.88.0` so `semver::Version`
/// parses it. The two spell the same minimum: rustc 1.88.0 or later.
pub const REQUIRED_RUSTC: &str = "1.88.0";

/// What the gate found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// `rustc` present and recent enough.
    Recent { version: Version },
    /// `rustc` present but older than [`REQUIRED_RUSTC`].
    TooOld { version: Version, required: Version },
    /// `rustc` not found (or its `--version` output didn't parse).
    Absent,
}

impl Gate {
    /// Gate on the output of `rustc --version` (`None` when the command is
    /// absent or failed).
    pub fn check(rustc_version_output: Option<&str>) -> Gate {
        let required = Version::parse(REQUIRED_RUSTC).expect("REQUIRED_RUSTC is a valid version");
        let Some(output) = rustc_version_output else {
            return Gate::Absent;
        };
        match version_from_rustc_output(output) {
            Some(version) if version >= required => Gate::Recent { version },
            Some(version) => Gate::TooOld { version, required },
            None => Gate::Absent,
        }
    }

    /// Run `rustc --version` and gate it. Best-effort: a spawn failure reads as
    /// [`Gate::Absent`], which the caller turns into the "install rustup" stop.
    pub fn probe() -> Gate {
        let out = std::process::Command::new("rustc")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
        Gate::check(out.as_deref())
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Gate::Recent { .. })
    }
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
pub const RUSTUP_BOOTSTRAP: &str =
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh";

/// The message for a failed gate — what the helper prints before stopping.
/// Empty for a passing gate.
pub fn failure_message(gate: &Gate) -> String {
    let why = match gate {
        Gate::Absent => "no Rust toolchain found".to_string(),
        Gate::TooOld { version, required } => {
            format!("rustc {version} is older than the required {required}")
        }
        Gate::Recent { .. } => return String::new(),
    };
    format!(
        "{why}.\n\
         soft-fig builds from source, so it needs rustc >= {REQUIRED_RUSTC}.\n\
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

    #[test]
    fn a_recent_rustc_passes() {
        assert!(matches!(
            Gate::check(Some("rustc 1.95.0 (59807616e 2026-04-14)")),
            Gate::Recent { version } if version >= Version::parse(REQUIRED_RUSTC).unwrap()
        ));
    }

    #[test]
    fn an_old_rustc_is_too_old() {
        assert!(matches!(
            Gate::check(Some("rustc 1.70.0 (90c541806 2023-05-31)")),
            Gate::TooOld { .. }
        ));
    }

    #[test]
    fn an_absent_rustc_is_absent() {
        assert_eq!(Gate::check(None), Gate::Absent);
    }

    #[test]
    fn a_nightly_reads_as_its_core() {
        // A nightly of a recent version must pass — its core is >= 1.88.
        assert!(matches!(
            Gate::check(Some("rustc 1.95.0-nightly (deadbeef 2026-01-01)")),
            Gate::Recent { .. }
        ));
    }

    #[test]
    fn garbage_output_is_absent_not_a_crash() {
        assert_eq!(Gate::check(Some("not really rustc output")), Gate::Absent);
    }

    #[test]
    fn the_failure_message_names_rustup_and_stops() {
        let msg = failure_message(&Gate::Absent);
        assert!(msg.contains(RUSTUP_BOOTSTRAP), "{msg}");
        assert!(msg.contains("never installs a toolchain"), "{msg}");
        // A passing gate has no failure message.
        assert_eq!(failure_message(&Gate::check(Some("rustc 1.95.0 (x)"))), "");
    }
}
