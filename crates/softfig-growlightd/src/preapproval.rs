//! Per-agent pre-approval generation (`growlight-live-fleet` slice 004) — the
//! fail-closed §15 operational must-have.
//!
//! Headless `claude -p` sessions **error out** on a permission prompt, they do
//! not pause — so with N agents one missing allow-rule silently kills an agent
//! mid-run. growlightd therefore GENERATES each fleet agent's pre-approval
//! `loop.json` + `mcp.json` (+ its `inject.sh`) BEFORE it spawns, pre-approving
//! that agent's full toolset, so the headless session never stalls on a prompt.
//!
//! ## Where the files live (locked decision)
//!
//! The generated files land in the growlight **runtime namespace**
//! `$XDG_CONFIG_HOME/softfig/growlight/agents/<id>/` — the same churny-runtime
//! space `softfig growlight start` already owns — **never under `~/.claude/**`**
//! (the harness-sensitive surface: the OAuth token + harness settings). This
//! re-expresses the single-agent `growlight start` generators per-agent;
//! growlightd copies the pure generators rather than importing them from the
//! `softfig` binary crate (the established "growlightd copies what it needs from
//! the bin/keeperd crates, it does not depend on them" posture).
//!
//! ## Fail-closed (the security crux)
//!
//! [`PreApproval::generate`] returns `Err` if it cannot lay down a complete,
//! correct pre-approval — an un-expressable agent id, a target under `~/.claude`,
//! an un-creatable directory, or any write failure.
//! [`ClaudeBackend::spawn`](crate::claude_backend::ClaudeBackend) calls it FIRST
//! and turns an `Err` into a [`SpawnError`](crate::supervisor::SpawnError) BEFORE
//! it execs `claude`, so an agent whose pre-approval can't be generated is NEVER
//! spawned — the drive loop surfaces it as an operator alert (slice 004 also
//! dispatches `SpawnFailed`) instead of a spawned-but-doomed headless session.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The tools every fleet agent pre-approves (§15 "pre-approve its full
/// toolset"). Mirrors the single-agent `growlight start` grant: the garden is
/// worked through `softfig-mcp` (raw `Edit`/`Write` INTO the garden tree are
/// denied below, so the MCP-only house rule is structural — `deny` overrides
/// `allow`), the code repos through `Read`/`Edit`/`Write`/`Bash`. A headless
/// session errors out on any un-listed tool, so this is the agent's whole
/// surface (the coordination-bus inbox is read through the granted
/// `mcp__softfig-mcp` `read_inbox` verb, so "protocol + baton + inbox" needs no
/// extra grant).
pub const ALLOW: &[&str] = &["mcp__softfig-mcp", "Read", "Edit", "Write", "Bash"];

/// The per-agent files [`PreApproval::generate`] lays down, derived from the
/// agents dir + the agent id. `loop_settings` / `mcp_config` are the paths the
/// [`AgentSpec`](crate::supervisor::AgentSpec) carries and the backend shells
/// `claude -p --settings/--mcp-config` with; `inject` + `baton` are referenced
/// by the generated `loop.json`'s SessionStart hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPaths {
    /// The per-agent runtime dir (`agents/<id>/`).
    pub dir: PathBuf,
    /// `loop.json` — the pre-approved toolset + SessionStart hook settings.
    pub loop_settings: PathBuf,
    /// `mcp.json` — the softfig-mcp attach config.
    pub mcp_config: PathBuf,
    /// `inject.sh` — the SessionStart hook body (protocol + this agent's baton).
    pub inject: PathBuf,
    /// `baton.md` — this agent's carried state (referenced by `inject.sh`).
    pub baton: PathBuf,
}

/// Derive the per-agent runtime paths under `agents_dir/<id>/`. Pure — the single
/// source of the per-agent path scheme, shared by [`PreApproval::generate`]
/// (which WRITES them) and fleet assembly (which builds the `AgentSpec` from
/// them), so the spec the backend shells and the files generation writes can
/// never drift. `agent_id` is joined verbatim; [`PreApproval::generate`] is the
/// fail-closed gate that rejects an id that isn't a safe single component.
pub fn agent_paths(agents_dir: &Path, agent_id: &str) -> AgentPaths {
    let dir = agents_dir.join(agent_id);
    AgentPaths {
        loop_settings: dir.join("loop.json"),
        mcp_config: dir.join("mcp.json"),
        inject: dir.join("inject.sh"),
        baton: dir.join("baton.md"),
        dir,
    }
}

/// The context growlightd generates each agent's pre-approval from: the runtime
/// `agents/` namespace it writes into, the shared garden `protocol.md` the
/// SessionStart hook injects, the `garden_root` the `Edit`/`Write` deny rules
/// anchor to, the `softfig-mcp` binary `mcp.json` attaches, and the `~/.claude`
/// dir (whose `projects/` subtree is granted, and which the fail-closed guard
/// refuses to write under). Pure data; cloneable so the backend holds one and
/// regenerates per spawn / re-roll.
#[derive(Debug, Clone)]
pub struct PreApproval {
    agents_dir: PathBuf,
    protocol: PathBuf,
    garden_root: PathBuf,
    mcp_bin: PathBuf,
    /// `~/.claude` — the harness-sensitive root. Its `projects/` subtree is the
    /// only part granted (claude-memory lives outside the garden workspace); the
    /// generator refuses to WRITE anything under it (the locked decision).
    claude_dir: PathBuf,
}

impl PreApproval {
    /// Build the generation context. `claude_dir` is `~/.claude`; its `projects/`
    /// subtree is granted as an `additionalDirectory` and the rest is off-limits.
    pub fn new(
        agents_dir: impl Into<PathBuf>,
        protocol: impl Into<PathBuf>,
        garden_root: impl Into<PathBuf>,
        mcp_bin: impl Into<PathBuf>,
        claude_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            agents_dir: agents_dir.into(),
            protocol: protocol.into(),
            garden_root: garden_root.into(),
            mcp_bin: mcp_bin.into(),
            claude_dir: claude_dir.into(),
        }
    }

    /// The `~/.claude/projects` subtree granted to the agent (its claude-memory
    /// pointers live outside the garden workspace).
    fn claude_projects(&self) -> PathBuf {
        self.claude_dir.join("projects")
    }

    /// Generate `agent`'s pre-approval `loop.json` + `mcp.json` (+ its `inject.sh`)
    /// under `agents/<id>/`, returning the paths the backend shells. **Fail-closed**
    /// — an `Err` means the caller must NOT spawn the agent (it would error out
    /// headless on the first un-approved tool): an un-expressable id, a target that
    /// would land under `~/.claude`, an un-creatable dir, or any write error all
    /// abort the spawn. Idempotent: it overwrites on every call, so a re-roll
    /// re-lays the current pre-approval.
    pub fn generate(&self, agent: &str) -> Result<AgentPaths, GenError> {
        validate_agent_id(agent)?;
        let paths = agent_paths(&self.agents_dir, agent);
        // Defense-in-depth on the locked decision: never write under ~/.claude,
        // even if `agents_dir` were misconfigured to point there. The structural
        // derivation already keeps us out of it; this refuses anyway.
        if paths.dir.starts_with(&self.claude_dir) {
            return Err(GenError::ClaudeDir(paths.dir.clone()));
        }
        fs::create_dir_all(&paths.dir).map_err(|e| GenError::io("create agent dir", &paths.dir, e))?;
        // inject.sh first (0755), then the settings that reference it.
        write_script(&paths.inject, &inject_script(&self.protocol, &paths.baton))?;
        write_file(
            &paths.loop_settings,
            &loop_json(&paths.inject, &self.garden_root, &self.claude_projects()),
        )?;
        write_file(&paths.mcp_config, &mcp_json(&self.mcp_bin))?;
        Ok(paths)
    }
}

/// Why pre-approval generation failed — every variant is fail-closed (the agent
/// is NOT spawned). Carries enough context for the [`SpawnError`] text the drive
/// loop surfaces as an operator alert.
///
/// [`SpawnError`]: crate::supervisor::SpawnError
#[derive(Debug)]
pub enum GenError {
    /// The agent id is not a safe single path component (empty, `.`/`..`, or
    /// contains a path separator / NUL) — it can't address a runtime dir.
    BadAgentId(String),
    /// The target dir resolved under `~/.claude` (the harness-sensitive surface);
    /// refused rather than written (the locked decision).
    ClaudeDir(PathBuf),
    /// A filesystem op (create dir / write file / chmod) failed.
    Io {
        /// What was being attempted (for the message).
        what: String,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

impl GenError {
    fn io(what: &str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            what: what.to_string(),
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for GenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenError::BadAgentId(id) => {
                write!(f, "agent id {id:?} is not a safe path component")
            }
            GenError::ClaudeDir(p) => write!(
                f,
                "refusing to write pre-approval under ~/.claude: {}",
                p.display()
            ),
            GenError::Io { what, path, source } => {
                write!(f, "{what} {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for GenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GenError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Reject an agent id that isn't a safe single path component, so it can never
/// escape the `agents/` namespace or break the runtime layout.
fn validate_agent_id(id: &str) -> Result<(), GenError> {
    let bad =
        id.is_empty() || id == "." || id == ".." || id.contains(['/', '\\', '\0']);
    if bad {
        Err(GenError::BadAgentId(id.to_string()))
    } else {
        Ok(())
    }
}

// ---- pure generators (re-expressed from the single-agent `growlight start`) --

/// The per-agent `loop.json` (`--settings`): the full-toolset pre-approval plus
/// the SessionStart hook injecting this agent's protocol + baton.
///
/// Two deliberate divergences from the single-agent `growlight start` loop.json:
/// (1) **no `statusLine`** — a headless `claude -p` agent has no status line; the
/// drive loop reads its budget from the stream-json `result` line
/// ([`crate::claude_backend`]), not a teed `usage.json`. (2) the SessionStart
/// hook points at THIS agent's own `inject.sh`, so each work-stream boots from
/// its own carried baton.
///
/// `Edit`/`Write` INTO the garden tree are DENIED (the MCP-only house rule made
/// structural — `deny` overrides `allow`); `~/.claude/projects` is granted as an
/// `additionalDirectory` so the agent can keep its own claude-memory pointers
/// (which live outside the garden workspace) — the agent's runtime *access*,
/// distinct from where the pre-approval files are *written* (never under
/// `~/.claude`). The garden path is anchored absolute (`//…`, as the box's
/// settings use), matching the single-agent generator.
fn loop_json(inject: &Path, garden_root: &Path, claude_projects: &Path) -> String {
    let inject = inject.display().to_string();
    let session_start_block = |source: &str| {
        serde_json::json!({
            "matcher": source,
            "hooks": [ { "type": "command", "command": inject } ]
        })
    };
    let garden = garden_root.display();
    let v = serde_json::json!({
        "permissions": {
            "allow": ALLOW,
            "deny": [
                format!("Edit(/{garden}/**)"),
                format!("Write(/{garden}/**)")
            ],
            "additionalDirectories": [
                claude_projects.display().to_string()
            ]
        },
        "hooks": {
            "SessionStart": [
                session_start_block("startup"),
                session_start_block("clear"),
            ]
        }
    });
    format!("{}\n", serde_json::to_string_pretty(&v).unwrap())
}

/// The per-agent `mcp.json` (`--mcp-config`): attach `softfig-mcp` so the garden
/// verbs exist for this agent regardless of its launch cwd (the project-scoped
/// `~/.claude.json` registration only loads with cwd in the garden, but a fleet
/// agent is shelled from growlightd). Mirrors the single-agent generator.
fn mcp_json(mcp_bin: &Path) -> String {
    let v = serde_json::json!({
        "mcpServers": {
            "softfig-mcp": {
                "type": "stdio",
                "command": mcp_bin.display().to_string(),
                "args": [],
                "env": {}
            }
        }
    });
    format!("{}\n", serde_json::to_string_pretty(&v).unwrap())
}

/// This agent's SessionStart hook body: cat the fixed protocol (the shared garden
/// pillar) + this agent's OWN baton to stdout, which Claude Code folds into the
/// fresh session's context on `startup` and `/clear`. Mirrors the single-agent
/// `inject.sh`; the baton path is per-agent.
fn inject_script(protocol: &Path, baton: &Path) -> String {
    const TPL: &str = r#"#!/usr/bin/env bash
# GENERATED by softfig-growlightd (per-agent pre-approval) — do not edit
# (regenerated on every spawn / re-roll). SessionStart hook: inject the fixed
# operating protocol + this agent's baton into a fresh session on startup and on
# /clear. stdout becomes context.
set -u
printf '=== SOFT-FIG GROWLIGHT · OPERATING PROTOCOL ===\n\n'
cat @PROTOCOL@ 2>/dev/null || printf '(protocol.md missing — run `softfig growlight init`)\n'
printf '\n\n=== CURRENT BATON (your only carried state) ===\n\n'
cat @BATON@ 2>/dev/null || printf '(no baton yet)\n'
"#;
    TPL.replace("@PROTOCOL@", &shell_quote(protocol))
        .replace("@BATON@", &shell_quote(baton))
}

/// Single-quote a path for safe embedding in a generated shell script.
fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
}

// ---- fail-closed file writers ------------------------------------------------

fn write_file(path: &Path, content: &str) -> Result<(), GenError> {
    fs::write(path, content).map_err(|e| GenError::io("write", path, e))
}

fn write_script(path: &Path, content: &str) -> Result<(), GenError> {
    write_file(path, content)?;
    let mut perms = fs::metadata(path)
        .map_err(|e| GenError::io("stat", path, e))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).map_err(|e| GenError::io("chmod", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn pre(agents_dir: &Path) -> PreApproval {
        PreApproval::new(
            agents_dir,
            "/garden/growlight/protocol.md",
            "/garden",
            "/usr/bin/softfig-mcp",
            "/home/u/.claude",
        )
    }

    #[test]
    fn loop_json_pre_approves_the_full_toolset_and_carries_the_session_start_hook() {
        let s = loop_json(
            Path::new("/cfg/agents/a1/inject.sh"),
            Path::new("/garden"),
            Path::new("/home/u/.claude/projects"),
        );
        let v: Value = serde_json::from_str(&s).unwrap();

        // The whole toolset is pre-approved (headless errors out on any un-listed
        // tool).
        let allow: Vec<&str> = v["permissions"]["allow"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(allow, ALLOW, "the full toolset is pre-approved");

        // Raw Edit/Write into the garden tree are denied (MCP-only is structural).
        let deny: Vec<&str> = v["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert!(deny.contains(&"Edit(//garden/**)"), "garden Edit denied: {deny:?}");
        assert!(deny.contains(&"Write(//garden/**)"), "garden Write denied: {deny:?}");

        // The SessionStart hook fires on startup AND /clear, running this agent's
        // own inject.sh; a headless `-p` agent needs no statusLine.
        let ss = v["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(ss.len(), 2, "startup + clear");
        assert_eq!(ss[0]["matcher"], "startup");
        assert_eq!(ss[1]["matcher"], "clear");
        assert_eq!(ss[0]["hooks"][0]["command"], "/cfg/agents/a1/inject.sh");
        assert!(v.get("statusLine").is_none(), "headless agents carry no statusLine");
    }

    #[test]
    fn mcp_json_attaches_softfig_mcp() {
        let s = mcp_json(Path::new("/usr/bin/softfig-mcp"));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["mcpServers"]["softfig-mcp"]["command"], "/usr/bin/softfig-mcp");
        assert_eq!(v["mcpServers"]["softfig-mcp"]["type"], "stdio");
    }

    #[test]
    fn generate_writes_the_pre_approval_into_the_runtime_namespace_not_claude() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("softfig/growlight/agents");
        let paths = pre(&agents).generate("builder").expect("generates");

        // Lands in the runtime namespace, never under ~/.claude.
        assert_eq!(paths.dir, agents.join("builder"));
        assert!(!paths.loop_settings.starts_with("/home/u/.claude"));
        assert!(paths.loop_settings.exists(), "loop.json written");
        assert!(paths.mcp_config.exists(), "mcp.json written");
        assert!(paths.inject.exists(), "inject.sh written");

        // The settings carry the pre-approval + a hook pointing at THIS agent's
        // inject.sh, which in turn references the per-agent baton + the protocol.
        let loop_v: Value = serde_json::from_str(&fs::read_to_string(&paths.loop_settings).unwrap()).unwrap();
        assert_eq!(loop_v["permissions"]["allow"][0], "mcp__softfig-mcp");
        assert_eq!(loop_v["hooks"]["SessionStart"][0]["hooks"][0]["command"], paths.inject.display().to_string());
        let inject = fs::read_to_string(&paths.inject).unwrap();
        assert!(inject.contains(&paths.baton.display().to_string()), "hook injects the per-agent baton");
        assert!(inject.contains("/garden/growlight/protocol.md"), "hook injects the protocol");

        // inject.sh is executable (0755).
        let mode = fs::metadata(&paths.inject).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "inject.sh is executable");
    }

    #[test]
    fn generate_is_idempotent_so_a_reroll_relays_the_pre_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("agents");
        let g = pre(&agents);
        let first = g.generate("a1").unwrap();
        let before = fs::read_to_string(&first.loop_settings).unwrap();
        // A second generation (the re-roll path) overwrites with identical content.
        let second = g.generate("a1").unwrap();
        assert_eq!(first, second);
        assert_eq!(before, fs::read_to_string(&second.loop_settings).unwrap());
    }

    #[test]
    fn generate_refuses_an_unsafe_agent_id_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let g = pre(&tmp.path().join("agents"));
        for bad in ["", ".", "..", "a/b", "../escape", "x\0y"] {
            assert!(
                matches!(g.generate(bad), Err(GenError::BadAgentId(_))),
                "an unsafe id {bad:?} is rejected, not written",
            );
        }
    }

    #[test]
    fn generate_refuses_to_write_under_claude_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let claude = tmp.path().join(".claude");
        // agents_dir maliciously under ~/.claude — the guard refuses it.
        let g = PreApproval::new(
            claude.join("projects/agents"),
            "/garden/growlight/protocol.md",
            "/garden",
            "/usr/bin/softfig-mcp",
            &claude,
        );
        assert!(
            matches!(g.generate("a1"), Err(GenError::ClaudeDir(_))),
            "a target under ~/.claude is refused, not written",
        );
        assert!(!claude.exists(), "nothing was created under ~/.claude");
    }

    #[test]
    fn generate_fails_closed_when_the_dir_cannot_be_created() {
        let tmp = tempfile::tempdir().unwrap();
        // A FILE where the agents dir should be → create_dir_all under it fails.
        let blocker = tmp.path().join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let g = pre(&blocker);
        assert!(
            matches!(g.generate("a1"), Err(GenError::Io { .. })),
            "an un-creatable dir fails closed",
        );
    }
}
