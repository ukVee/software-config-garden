//! Requester-side `config/runner.toml` (spec remote-runner §5.1): the `[use]`
//! and `[[project]]` tables. The runner-side `[serve]` table (spec §5.2) is a
//! different concern owned by `softfig-runnerd`; this module only tolerates it
//! (the two tables share one file) and never interprets it.
//!
//! The file is in-garden and committed on the requester's device chain. It is
//! read through keeperd (`read_file`) so it works in FUSE and Disk modes alike;
//! this module is a pure parser + resolver and knows nothing about the garden.
//!
//! "Bad config is a clear error, never a silent default" (slice 007): every
//! hand-edited field is `deny_unknown_fields`, unknown top-level keys are
//! rejected, and the closed enumerations (`fallback`, `cache`, `network`,
//! `submodules`, `fetch`) reject unknown strings at load time.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{NetError, Result};

/// The decided fallback modes (spec §9). `local` runs the command in the repo;
/// `wait` retries until `wait_timeout`; `fail` exits 254 at once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    #[default]
    Local,
    Wait,
    Fail,
}

/// How a snapshot treats gitlinks (submodules) in the tree (spec §4.2). Local
/// to this crate (softfig-net has no dependency on softfig-source); the caller
/// maps it onto `softfig_source::SubmodulePolicy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Submodules {
    #[default]
    Refuse,
    Ignore,
}

fn default_version() -> u32 {
    1
}
fn default_wait_timeout() -> String {
    "20m".to_string()
}
fn default_connect_timeout() -> String {
    "10s".to_string()
}
fn default_cache() -> String {
    "shared".to_string()
}
fn default_network() -> String {
    "none".to_string()
}

/// The `[use]` table (spec §5.1): which peers are eligible runners and how to
/// behave when none is reachable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UseConfig {
    /// Runner peers (ring names or device-id fingerprints). Selection is
    /// least-loaded; ties break by list order (spec §5.1).
    #[serde(default)]
    pub peers: Vec<String>,
    /// `local` | `wait` | `fail` (decided default: `local`).
    #[serde(default)]
    pub fallback: Fallback,
    /// Used only by `fallback = "wait"`.
    #[serde(default = "default_wait_timeout")]
    pub wait_timeout: String,
    /// How long to wait for a runner before declaring it unreachable.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: String,
}

impl Default for UseConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            fallback: Fallback::Local,
            wait_timeout: default_wait_timeout(),
            connect_timeout: default_connect_timeout(),
        }
    }
}

/// One profile under `[project.profile.<name>]` (spec §5.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// The resolved command (`cmd = [...]`). Required — a profile with no
    /// command is a clear error, never a silent no-op.
    pub cmd: Vec<String>,
    /// Names and literal values; the requester's environment is never
    /// forwarded wholesale (spec §5.1).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Per-job `RuntimeMaxSec` shorthand ("45m"). Optional.
    #[serde(default)]
    pub time_max: Option<String>,
    /// `shared` | `fresh`.
    #[serde(default = "default_cache")]
    pub cache: String,
    /// `none` | `egress`.
    #[serde(default = "default_network")]
    pub network: String,
    /// Artifact globs (repo-root-relative; the glob base is report #057).
    #[serde(default)]
    pub artifacts: Vec<String>,
    /// `refuse` | `ignore` gitlinks in the snapshot.
    #[serde(default)]
    pub submodules: Submodules,
    /// Whether to fold git metadata into the snapshot. Listed in §5.1 but
    /// under-specified; carried through and currently inert (see the slice doc).
    #[serde(default)]
    pub git_metadata: Option<bool>,
}

/// One `[[project]]` entry: a repo path prefix and its profiles (spec §5.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub name: String,
    /// Any worktree under this path matches. `~` is expanded by the resolver.
    pub repo: String,
    /// The toolchain the project uses ("rust").
    pub toolchain: String,
    /// The fetch kind: `cargo` (from a skeleton) or `none` (offline only).
    pub fetch: String,
    /// `[project.profile.<name>]` tables, keyed by profile name.
    #[serde(default)]
    pub profile: BTreeMap<String, ProfileConfig>,
}

/// The requester half of `config/runner.toml`. `serve` is the runner's table
/// and is tolerated-but-ignored here (parsed by `softfig runner apply`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default, rename = "use")]
    pub use_: UseConfig,
    #[serde(default)]
    pub project: Vec<ProjectConfig>,
    #[serde(default)]
    pub serve: Option<toml::Value>,
}

/// A resolved run: the profile (or ad-hoc command) matched against a project.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedRun {
    pub project: String,
    /// The matched repo prefix (expanded, not canonicalized).
    pub repo: String,
    pub toolchain: String,
    pub fetch: String,
    /// The profile name, or `<ad-hoc>` when the command came from `--`.
    pub profile: String,
    pub cmd: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub time_max: Option<String>,
    pub cache: String,
    pub network: String,
    pub artifacts: Vec<String>,
    pub submodules: Submodules,
    pub git_metadata: Option<bool>,
}

/// Parse a human-readable duration ("60m", "10s", "2h", "1d", bare seconds)
/// into whole seconds. Mirrors `softfig-runnerd::executor::parse_duration`
/// (the two crates must agree; a shared util is a follow-up).
pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(NetError::Config("duration is empty".into()));
    }
    let (num, mult) = if let Some(v) = s.strip_suffix('m') {
        (v, 60u64)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, 3600)
    } else if let Some(v) = s.strip_suffix('d') {
        (v, 86400)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1)
    } else {
        (s, 1)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| NetError::Config(format!("bad duration {s:?}")))?;
    Ok(n * mult)
}

/// Expand a leading `~/` using `$HOME` (the only tilde form the config accepts).
fn expand_tilde(s: &str) -> Result<PathBuf> {
    let s = s.trim();
    if s == "~" {
        return home();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        return Ok(home()?.join(rest));
    }
    if s.starts_with('~') {
        return Err(NetError::Config(format!(
            "only a leading `~/` is supported in repo path {s:?}"
        )));
    }
    Ok(PathBuf::from(s))
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| NetError::Config("$HOME is not set".into()))
}

fn check_enum(value: &str, what: &str, allowed: &[&str]) -> Result<()> {
    if !allowed.contains(&value) {
        return Err(NetError::Config(format!(
            "{what} {value:?} is not one of {}",
            allowed
                .iter()
                .map(|a| format!("{a:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

impl RunnerConfig {
    /// Parse `config/runner.toml` from `raw`, rejecting bad config with a clear
    /// error (unknown keys, bad enums, unparsable durations, wrong version).
    pub fn parse(raw: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(raw).map_err(|e| NetError::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load and validate the file at `path`. A missing file is a clear error.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(NetError::Config(format!(
                "{} does not exist",
                path.display()
            )));
        }
        let raw = fs::read_to_string(path)?;
        Self::parse(&raw)
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(NetError::Config(format!(
                "unsupported config version {} (expected 1)",
                self.version
            )));
        }
        parse_duration(&self.use_.wait_timeout)?;
        parse_duration(&self.use_.connect_timeout)?;
        for p in &self.project {
            if p.name.trim().is_empty() {
                return Err(NetError::Config("a [[project]] has an empty name".into()));
            }
            if p.repo.trim().is_empty() {
                return Err(NetError::Config(format!(
                    "project {:?} has an empty repo path",
                    p.name
                )));
            }
            check_enum(&p.fetch, "fetch", &["cargo", "none"])?;
            expand_tilde(&p.repo)?; // reject an unsupported tilde form at load
            for (profile_name, prof) in &p.profile {
                if prof.cmd.is_empty() {
                    return Err(NetError::Config(format!(
                        "project {:?} profile {profile_name:?} has an empty cmd",
                        p.name
                    )));
                }
                check_enum(&prof.cache, "cache", &["shared", "fresh"])?;
                check_enum(&prof.network, "network", &["none", "egress"])?;
                if let Some(tm) = &prof.time_max {
                    parse_duration(tm)?;
                }
            }
        }
        Ok(())
    }

    /// Resolve the project matching `cwd` (longest repo-prefix match) and the
    /// profile or ad-hoc command. `profile` and `ad_hoc` are mutually
    /// exclusive; one must be given.
    pub fn resolve(
        &self,
        cwd: &Path,
        profile: Option<&str>,
        ad_hoc: Option<Vec<String>>,
    ) -> Result<ResolvedRun> {
        let (profile, ad_hoc) = match (profile, ad_hoc) {
            (Some(_), Some(_)) => {
                return Err(NetError::Config(
                    "--profile and a trailing command are mutually exclusive".into(),
                ))
            }
            (Some(p), None) => (Some(p), None),
            (None, a) => (None, a),
        };

        let cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());

        // Longest-prefix match: a project whose expanded repo prefix is a
        // prefix of the canonicalized cwd, most specific (longest) first.
        let mut matches: Vec<(&ProjectConfig, PathBuf)> = self
            .project
            .iter()
            .filter_map(|p| expand_tilde(&p.repo).ok().map(|r| (p, r)))
            .filter(|(_, r)| cwd.starts_with(r))
            .collect();
        matches.sort_by_key(|(_, r)| std::cmp::Reverse(r.as_os_str().len()));
        let (project, repo) = match matches.first() {
            Some((p, r)) => (*p, r.clone()),
            None => {
                return Err(NetError::Config(format!(
                    "no [[project]] matches {}",
                    cwd.display()
                )))
            }
        };

        let (profile_name, cmd, env, time_max, cache, network, artifacts, submodules, git_metadata) =
            match profile {
                Some(name) => {
                    let prof = project.profile.get(name).ok_or_else(|| {
                        NetError::Config(format!(
                            "project {:?} has no profile {name:?} (have: {})",
                            project.name,
                            project
                                .profile
                                .keys()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                    })?;
                    (
                        name.to_string(),
                        prof.cmd.clone(),
                        prof.env.clone(),
                        prof.time_max.clone(),
                        prof.cache.clone(),
                        prof.network.clone(),
                        prof.artifacts.clone(),
                        prof.submodules,
                        prof.git_metadata,
                    )
                }
                None => {
                    // Ad-hoc (spec §5.1): the project's toolchain + fetch kind,
                    // shared cache, no artifacts, no env, network none.
                    let cmd = ad_hoc.ok_or_else(|| {
                        NetError::Config(
                            "specify --profile <name> or a command after `--`".into(),
                        )
                    })?;
                    (
                        "<ad-hoc>".to_string(),
                        cmd,
                        BTreeMap::new(),
                        None,
                        "shared".to_string(),
                        "none".to_string(),
                        Vec::new(),
                        Submodules::Refuse,
                        None,
                    )
                }
            };

        Ok(ResolvedRun {
            project: project.name.clone(),
            repo: repo.display().to_string(),
            toolchain: project.toolchain.clone(),
            fetch: project.fetch.clone(),
            profile: profile_name,
            cmd,
            env,
            time_max,
            cache,
            network,
            artifacts,
            submodules,
            git_metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
version = 1

[use]
peers = ["sillyguy76"]

[[project]]
name = "softfig"
repo = "~/projects/softfig"
toolchain = "rust"
fetch = "cargo"

[project.profile.gate]
cmd = ["cargo", "test", "--workspace"]
time_max = "45m"

[project.profile.release]
cmd = ["cargo", "build", "--release", "--locked"]
cache = "fresh"
artifacts = ["target/release/softfig"]
"#;

    #[test]
    fn parses_minimal_config_and_defaults() {
        let cfg = RunnerConfig::parse(MINIMAL).unwrap();
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.use_.peers, vec!["sillyguy76"]);
        assert_eq!(cfg.use_.fallback, Fallback::Local);
        assert_eq!(cfg.use_.wait_timeout, "20m");
        assert_eq!(cfg.use_.connect_timeout, "10s");
        assert_eq!(cfg.project.len(), 1);
        let gate = cfg.project[0].profile.get("gate").unwrap();
        assert_eq!(gate.cmd, vec!["cargo", "test", "--workspace"]);
        assert_eq!(gate.cache, "shared"); // default
        assert_eq!(gate.network, "none"); // default
        let release = cfg.project[0].profile.get("release").unwrap();
        assert_eq!(release.cache, "fresh");
        assert_eq!(release.artifacts, vec!["target/release/softfig"]);
    }

    #[test]
    fn swallows_the_runner_side_serve_table() {
        let raw = format!("{MINIMAL}\n[serve]\nenabled = true\nmax_jobs = 2\n");
        let cfg = RunnerConfig::parse(&raw).unwrap();
        assert!(cfg.serve.is_some());
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let raw = MINIMAL.replace("[use]", "[us]");
        assert!(matches!(
            RunnerConfig::parse(&raw),
            Err(NetError::Config(_))
        ));
    }

    #[test]
    fn rejects_unknown_use_field() {
        let raw = MINIMAL.replace("peers =", "fallbak = \"x\"\npeers =");
        assert!(matches!(
            RunnerConfig::parse(&raw),
            Err(NetError::Config(_))
        ));
    }

    #[test]
    fn rejects_bad_fallback_enum() {
        let raw = MINIMAL.replace("peers = [\"sillyguy76\"]", "peers = []\nfallback = \"bogus\"");
        assert!(matches!(
            RunnerConfig::parse(&raw),
            Err(NetError::Config(_))
        ));
    }

    #[test]
    fn rejects_bad_cache_and_network_values() {
        let bad_cache = MINIMAL.replace("cache = \"fresh\"", "cache = \"stale\"");
        assert!(matches!(
            RunnerConfig::parse(&bad_cache),
            Err(NetError::Config(_))
        ));
        let bad_network = MINIMAL.replace("cache = \"fresh\"", "network = \"egres\"");
        assert!(matches!(
            RunnerConfig::parse(&bad_network),
            Err(NetError::Config(_))
        ));
    }

    #[test]
    fn rejects_bad_duration() {
        let bad = MINIMAL.replace("time_max = \"45m\"", "time_max = \"45x\"");
        assert!(matches!(
            RunnerConfig::parse(&bad),
            Err(NetError::Config(_))
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let bad = MINIMAL.replace("version = 1", "version = 2");
        assert!(matches!(
            RunnerConfig::parse(&bad),
            Err(NetError::Config(_))
        ));
    }

    #[test]
    fn rejects_empty_profile_cmd() {
        let bad = MINIMAL.replace("cmd = [\"cargo\", \"test\", \"--workspace\"]", "cmd = []");
        assert!(matches!(
            RunnerConfig::parse(&bad),
            Err(NetError::Config(_))
        ));
    }

    #[test]
    fn parse_duration_handles_suffixes() {
        assert_eq!(parse_duration("10s").unwrap(), 10);
        assert_eq!(parse_duration("45m").unwrap(), 2700);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration("30").unwrap(), 30);
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn resolve_matches_longest_prefix_and_profile() {
        let cfg = RunnerConfig::parse(MINIMAL).unwrap();
        let home = home().unwrap();
        let cwd = home.join("projects").join("softfig").join("codebase").join("remote-runner");
        let r = cfg.resolve(&cwd, Some("gate"), None).unwrap();
        assert_eq!(r.project, "softfig");
        assert_eq!(r.profile, "gate");
        assert_eq!(r.cmd, vec!["cargo", "test", "--workspace"]);
        assert_eq!(r.toolchain, "rust");
        assert_eq!(r.fetch, "cargo");
    }

    #[test]
    fn resolve_ad_hoc_uses_project_defaults() {
        let cfg = RunnerConfig::parse(MINIMAL).unwrap();
        let home = home().unwrap();
        let cwd = home.join("projects").join("softfig");
        let r = cfg.resolve(&cwd, None, Some(vec!["cargo".into(), "build".into()])).unwrap();
        assert_eq!(r.profile, "<ad-hoc>");
        assert_eq!(r.cmd, vec!["cargo", "build"]);
        assert_eq!(r.cache, "shared");
        assert_eq!(r.network, "none");
        assert!(r.artifacts.is_empty());
        assert!(r.env.is_empty());
    }

    #[test]
    fn resolve_errors_when_no_project_matches() {
        let cfg = RunnerConfig::parse(MINIMAL).unwrap();
        let err = cfg.resolve(Path::new("/unmatched/dir"), Some("gate"), None);
        assert!(matches!(err, Err(NetError::Config(_))));
    }

    #[test]
    fn resolve_errors_on_unknown_profile() {
        let cfg = RunnerConfig::parse(MINIMAL).unwrap();
        let home = home().unwrap();
        let cwd = home.join("projects").join("softfig");
        let err = cfg.resolve(&cwd, Some("nope"), None);
        assert!(matches!(err, Err(NetError::Config(_))));
    }

    #[test]
    fn resolve_errors_when_neither_profile_nor_command() {
        let cfg = RunnerConfig::parse(MINIMAL).unwrap();
        let home = home().unwrap();
        let cwd = home.join("projects").join("softfig");
        assert!(matches!(cfg.resolve(&cwd, None, None), Err(NetError::Config(_))));
    }

    #[test]
    fn resolve_rejects_profile_and_command_together() {
        let cfg = RunnerConfig::parse(MINIMAL).unwrap();
        let home = home().unwrap();
        let cwd = home.join("projects").join("softfig");
        assert!(matches!(
            cfg.resolve(&cwd, Some("gate"), Some(vec!["true".into()])),
            Err(NetError::Config(_))
        ));
    }
}
