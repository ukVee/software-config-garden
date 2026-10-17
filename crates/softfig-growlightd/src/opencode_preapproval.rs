//! Headless opencode pre-approval generation (`opencode-fleet-backend` slice
//! 003) — the fail-closed §4 `preapprove` + `inject_baton` + `attach_mcp` legs
//! for a fleet member that runs on **opencode** instead of `claude -p`.
//!
//! The sibling of [`crate::preapproval`], and deliberately growlightd's **own**
//! generator rather than a call into `softfig-cli`: growlightd depends only on
//! `softfig-ipc`, and the CLI's `opencode_config` is the *interactive* variant
//! (see below). Everything fail-closed is shared, not
//! re-expressed — `validate_agent_id`, the `~/.claude` refusal, [`GenError`],
//! and the `agent_paths` layout all come from the claude module, so the two
//! generators can never drift on what they refuse or where they write.
//!
//! ## What it shares with the interactive config, and where it differs
//!
//! The permission rules come from the ONE floor builder both generators call,
//! [`softfig_ipc::opencode::floor`], with [`Posture::Headless`]. The CLI's
//! interactive config calls the same builder with `Posture::Interactive`. The two
//! floors are identical except where a human could answer a prompt: a headless
//! member **cannot prompt** (opencode auto-rejects the ask), so where the
//! interactive loop asks, a member is denied. That includes code-repo edits: the
//! interactive floor re-opens them to the human's prompt, the headless floor
//! leaves them under the garden write guard until a folder grant opens them.
//!
//! `--auto` is **rejected** as the alternative: it auto-approves everything not
//! explicitly denied, which is too blunt for an unattended fleet.
//!
//! ## What it writes
//!
//! One file per member, `agents/<id>/opencode.json` — the single file
//! `OPENCODE_CONFIG` points at (opencode's analog of claude's `--settings` plus
//! `--mcp-config` in one) — into the existing runtime namespace
//! `$XDG_CONFIG_HOME/softfig/growlight/agents/<id>/`, **never under `~/.claude`**.
//! Native opencode 2.x keys only (`agents`, `system`, `permissions`,
//! `mcp.servers`), never the v1 spellings opencode would auto-translate.
//!
//! - `permissions` (top level) — the headless floor: reset every global grant,
//!   reach the loop's own state, guard the garden against raw writes, re-open the
//!   runtime root, and leave the memory tree read-only ([`MEMBER_MEMORY`]).
//!   **Top level, not on the agent**: top-level rules
//!   govern every agent the member's private server loads, including the built-in
//!   `general` / `explore` subagents a `subagent` call spawns, which run on their
//!   own agent's rules. Rules placed on the member's agent alone would leave every
//!   global grant one subagent away. See the floor builder for the order.
//! - `agents.<id>.system` — the **fleet** protocol (`protocol-fleet.md`, per
//!   `crate::fleet`'s `fleet_protocol`; never the single-agent `protocol.md`,
//!   since every member growlightd spawns is a fleet member) pulled in by a
//!   `{file:…}` reference so the text is *reused*, never copied (house rule 1),
//!   plus a step-0 line naming **this member's** `agents/<id>/baton.md`. opencode
//!   has no SessionStart hook, so the prompt IS the boot injection: a fresh
//!   session rebuilds the system prompt, reloads the protocol, and step 0
//!   re-reads the live baton. After those comes the session context
//!   ([`softfig_ipc::opencode::context`], slice 005): the garden root `CLAUDE.md`,
//!   the memory read rules, and the memory index `MEMORY.md`, each by `{file:}`
//!   reference and each only if it exists at spawn. opencode 2.x reads neither
//!   `CLAUDE.md` nor claude-memory on its own.
//! - **No model.** opencode 2.x `run` ignores `agents.<id>.model` (probe-proven,
//!   opencode-v2-repin slice 001 L7: even a valid id fell back to opencode's own
//!   default), so the member's model rides argv `--model` instead, the one path
//!   that fails closed on a bad id. See [`crate::opencode_backend::ModelSelection`].
//! - `mcp.servers.softfig-mcp` — the explicit project-scoped attach, resolved
//!   exactly as the claude `mcp.json` is, so the garden verbs exist regardless of
//!   the user's global `~/.config/opencode` registration. Its `environment`
//!   carries `SOFTFIG_MEMBER=<agent>`, the member identity softfig-mcp reads at
//!   startup (spec-growlight-queue §6, [`softfig_ipc::member`]); `environment` is
//!   opencode 2.x's native `Mcp.LocalConfig` key for the server's env.
//!
//! ## Known gap — no code repo is writable yet
//!
//! opencode's cwd for a member is the garden root, and `external_directory` is
//! what governs everything outside cwd. The floor grants only the loop's own
//! state, so a member can reach no code repo: the repo is a property of the
//! *claimed queue*, not of the member, and growlightd does not model it yet. That
//! is step 2 of `decision-opencode-v2-fleet-safety-order` (milestone/slice folder
//! grants), which appends its rules after the floor.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use softfig_ipc::opencode::{context, file_ref, floor, Context, Floor, MemoryPolicy, Posture};

use crate::preapproval::{agent_paths, validate_agent_id, write_file, AgentPaths, GenError};

/// opencode's agent `mode` for a fleet member: `primary`, the same mode the
/// interactive `softfig-loop` agent uses — the member IS the session, not a
/// subagent it delegates to.
const AGENT_MODE: &str = "primary";

/// A fleet member's claude-memory write policy. **Read-only for now**
/// (`decision-opencode-v2-fleet-safety-order` § Memory, resolved 2026-10-10): an
/// unattended member gets write access only once the keeperd memory chain makes
/// every write tracked and revertable. This one value drives both halves, the
/// floor's memory `edit` rule and whether the write rules are injected, so the
/// flip is this line.
const MEMBER_MEMORY: MemoryPolicy = MemoryPolicy::ReadOnly;

/// The context growlightd generates each **opencode** member's pre-approval from
/// — the mirror of [`PreApproval`](crate::preapproval::PreApproval), differing
/// where opencode does: the member's reach and write rights are opencode
/// permission rules (the shared floor), not claude `allow`/`deny` lists. Pure
/// data; cloneable so the backend holds one and regenerates per spawn.
#[derive(Debug, Clone)]
pub struct OpencodePreApproval {
    agents_dir: PathBuf,
    /// The garden root: the member's cwd, the home of the injected `CLAUDE.md`
    /// and memory rules, and what its claude-memory dir is derived from.
    garden_root: PathBuf,
    protocol: PathBuf,
    runtime_root: PathBuf,
    mcp_bin: PathBuf,
    /// `~/.claude` — the harness-sensitive root. Its `projects/` subtree is the
    /// only part granted (claude-memory lives outside the garden workspace); the
    /// generator refuses to WRITE anything under it (the locked decision, mirrored
    /// from the claude generator).
    claude_dir: PathBuf,
    /// opencode's data dir (`softfig_ipc::opencode::opencode_data_dir`); the floor
    /// re-grants its `shell/` + `tool-output/` subdirs read-only.
    opencode_data: PathBuf,
}

impl OpencodePreApproval {
    /// Build the generation context. `garden_root` is the member's cwd;
    /// `protocol` is the **fleet** protocol
    /// (`growlight/protocol-fleet.md`); `runtime_root` is the growlight runtime
    /// grant root (`$XDG_CONFIG_HOME/softfig`, the parent of the pillar dir, so
    /// sibling runtime state is covered by one rule); `claude_dir` is `~/.claude`;
    /// `opencode_data` is opencode's data dir.
    pub fn new(
        agents_dir: impl Into<PathBuf>,
        garden_root: impl Into<PathBuf>,
        protocol: impl Into<PathBuf>,
        runtime_root: impl Into<PathBuf>,
        mcp_bin: impl Into<PathBuf>,
        claude_dir: impl Into<PathBuf>,
        opencode_data: impl Into<PathBuf>,
    ) -> Self {
        Self {
            agents_dir: agents_dir.into(),
            garden_root: garden_root.into(),
            protocol: protocol.into(),
            runtime_root: runtime_root.into(),
            mcp_bin: mcp_bin.into(),
            claude_dir: claude_dir.into(),
            opencode_data: opencode_data.into(),
        }
    }

    /// The `~/.claude/projects` subtree granted to the member (its claude-memory
    /// pointers live outside the garden workspace).
    fn claude_projects(&self) -> PathBuf {
        self.claude_dir.join("projects")
    }

    /// Generate `agent`'s `opencode.json` under `agents/<id>/`, returning the
    /// paths the backend shells. **Fail-closed** — an `Err` means the caller must
    /// NOT spawn the member: an un-expressable id, a target that would land under
    /// `~/.claude`, a floor directory that cannot be a safe rule, a context file
    /// opencode's `{file:}` cannot name, an un-creatable
    /// dir, or a write error all abort the spawn, exactly as they do for claude,
    /// because a headless session that starts without its rules runs on whatever
    /// the global config grants. Idempotent: it overwrites on every call, so a
    /// re-roll re-lays the current pre-approval.
    ///
    /// The agent id doubles as the opencode **agent name** (`agents.<id>`, and
    /// what the argv passes to `--agent`), so one member id names its runtime dir,
    /// its baton, and its agent block.
    pub fn generate(&self, agent: &str) -> Result<AgentPaths, GenError> {
        validate_agent_id(agent)?;
        let paths = agent_paths(&self.agents_dir, agent);
        // Defense-in-depth on the locked decision: never write under ~/.claude,
        // even if `agents_dir` were misconfigured to point there.
        if paths.dir.starts_with(&self.claude_dir) {
            return Err(GenError::ClaudeDir(paths.dir.clone()));
        }
        // Checked per spawn, so a fresh member sees the memory as it is now and
        // never names a file that has since gone (which would fail opencode's
        // whole location).
        let context = context(&Context {
            garden_root: &self.garden_root,
            claude_projects: &self.claude_projects(),
            memory: MEMBER_MEMORY,
        })
        .map_err(GenError::Context)?;
        // Rendered before anything touches the filesystem, so a bad floor leaves
        // no half-written member dir behind.
        let config = opencode_json(&AgentInputs {
            agent_name: agent,
            protocol: &self.protocol,
            baton: &paths.baton,
            context: &context,
            runtime_root: &self.runtime_root,
            claude_projects: &self.claude_projects(),
            opencode_data: &self.opencode_data,
            mcp_bin: &self.mcp_bin,
        })?;
        fs::create_dir_all(&paths.dir)
            .map_err(|e| GenError::io("create agent dir", &paths.dir, e))?;
        write_file(&paths.opencode_config, &config)?;
        Ok(paths)
    }
}

// ---- the pure generator ------------------------------------------------------

/// What [`opencode_json`] renders. A struct rather than eight positional
/// arguments for the same reason the CLI's `OpencodeConfigInputs` is one: six of
/// these are `&Path` and a value in the wrong slot would generate a plausible,
/// wrong config in silence.
struct AgentInputs<'a> {
    /// The member id — opencode's `agents.<name>` and the argv's `--agent` value.
    agent_name: &'a str,
    /// The garden's `growlight/protocol-fleet.md`, pulled into the prompt by
    /// `{file:…}` reference (never copied).
    protocol: &'a Path,
    /// **This member's** `agents/<id>/baton.md`, named by the step-0 boot line.
    baton: &'a Path,
    /// The rendered session context ([`softfig_ipc::opencode::context`]), appended
    /// after the step-0 line; empty when there is nothing to inject.
    context: &'a str,
    /// The growlight runtime grant root (`$XDG_CONFIG_HOME/softfig`).
    runtime_root: &'a Path,
    /// The claude-memory tree (`~/.claude/projects`).
    claude_projects: &'a Path,
    /// opencode's data dir.
    opencode_data: &'a Path,
    /// The `softfig-mcp` binary the project-scoped `mcp` block runs.
    mcp_bin: &'a Path,
}

/// Render a headless member's `opencode.json`. Pure — builds the string, never
/// writes or spawns — so the whole rule list, prompt, and mcp attach are
/// unit-testable without touching a filesystem or a real `opencode`. Fails closed
/// on a floor directory the shared builder refuses, or a protocol path `{file:}`
/// cannot name.
fn opencode_json(cfg: &AgentInputs<'_>) -> Result<String, GenError> {
    // The system prompt IS the boot injection (opencode has no SessionStart
    // hook): the fleet protocol by reference + a step-0 line naming this member's
    // own baton path in English. That naming is the task-035 cure carried over
    // from the claude `inject.sh` — a member that is only *seeded* with a baton
    // path can misroute its handoff write to the legacy root `baton.md`, which is
    // how the fleet once stalled for four hours.
    let mut system = format!(
        "{protocol}\n\n\
         STEP 0 (every session, first): read YOUR BATON FILE — the exact path \
         `{baton}` — and follow the fleet operating protocol above. That file is \
         your only carried state AND the exact path you rewrite at handoff; never \
         the legacy root `baton.md`. opencode has no SessionStart hook, so a fresh \
         session (`/new` or a relaunch) re-reads it here; that reread IS the roll.",
        protocol = file_ref("protocol", cfg.protocol).map_err(GenError::Context)?,
        baton = cfg.baton.display(),
    );
    if !cfg.context.is_empty() {
        system.push_str("\n\n");
        system.push_str(cfg.context);
    }

    let permissions = floor(
        Posture::Headless,
        &Floor {
            runtime_root: cfg.runtime_root,
            claude_projects: cfg.claude_projects,
            opencode_data: cfg.opencode_data,
            memory: MEMBER_MEMORY,
        },
    )
    .map_err(GenError::Floor)?;

    // No `model` key: `run` ignores the agent's model on 2.x, so the member's
    // model rides argv (see the module doc). A key here would be dead config that
    // reads as if it pinned something. No agent-level `permissions` either: the
    // floor is top-level so it also governs the subagents (see the module doc).
    let mut agents = serde_json::Map::new();
    agents.insert(
        cfg.agent_name.to_string(),
        serde_json::json!({ "mode": AGENT_MODE, "system": system }),
    );

    let v = serde_json::json!({
        "$schema": "https://opencode.ai/config.json",
        "permissions": permissions,
        "mcp": {
            "servers": {
                "softfig-mcp": {
                    "type": "local",
                    "command": [ cfg.mcp_bin.display().to_string() ],
                    "environment": { softfig_ipc::MEMBER_ENV: cfg.agent_name },
                }
            }
        },
        "agents": Value::Object(agents),
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&v).unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pre(agents_dir: &Path) -> OpencodePreApproval {
        OpencodePreApproval::new(
            agents_dir,
            "/garden",
            "/garden/growlight/protocol-fleet.md",
            "/home/u/.config/softfig",
            "/usr/bin/softfig-mcp",
            "/home/u/.claude",
            "/home/u/.local/share/opencode",
        )
    }

    fn generated(agent: &str) -> (Value, AgentPaths, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("softfig/growlight/agents");
        let paths = pre(&agents).generate(agent).expect("generates");
        let raw = fs::read_to_string(&paths.opencode_config).unwrap();
        (serde_json::from_str(&raw).expect("emitted JSON parses"), paths, tmp)
    }

    fn agent_block<'a>(v: &'a Value, agent: &str) -> &'a Value {
        &v["agents"][agent]
    }

    /// The emitted top-level rules as `action resource effect` lines.
    fn rule_lines(v: &Value) -> Vec<String> {
        v["permissions"]
            .as_array()
            .expect("top-level permissions is an array")
            .iter()
            .map(|r| format!("{} {} {}", r["action"].as_str().unwrap(), r["resource"].as_str().unwrap(), r["effect"].as_str().unwrap()))
            .collect()
    }

    #[test]
    fn the_member_config_carries_exactly_the_headless_floor_at_top_level() {
        let (v, _paths, _tmp) = generated("a");
        // Pinned in full: the order is the design (last match wins). The reset
        // first, so no global `~/projects/**`-style grant survives; the garden
        // guard (`edit * deny`) before every edit allow; nothing that asks, since
        // a headless member cannot answer; and the memory tree reachable and
        // readable but not writable (MEMBER_MEMORY, the human's 2026-10-10 call).
        assert_eq!(
            rule_lines(&v),
            vec![
                "external_directory * deny",
                "external_directory /home/u/.config/softfig/** allow",
                "external_directory /home/u/.claude/projects/** allow",
                "external_directory /home/u/.local/share/opencode/shell/*/* allow",
                "external_directory /home/u/.local/share/opencode/tool-output/* allow",
                "read * allow",
                "read *.env deny",
                "read *.env.* deny",
                "read *.env.example allow",
                "shell * allow",
                "softfig-mcp* * allow",
                "edit * deny",
                "edit /home/u/.config/softfig/** allow",
                "edit /home/u/.claude/projects/** deny",
            ],
        );
        // Top level, NOT on the agent: top-level rules govern every agent the
        // member's server loads, so a `subagent` call cannot escape the reset.
        assert!(agent_block(&v, "a").get("permissions").is_none(), "{v}");
    }

    #[test]
    fn only_native_v2_keys_are_emitted() {
        let (v, _paths, _tmp) = generated("a");
        for v1 in ["agent", "permission"] {
            assert!(v.get(v1).is_none(), "v1 key `{v1}` emitted: {v}");
        }
        let agent = agent_block(&v, "a");
        for v1 in ["prompt", "permission", "tools"] {
            assert!(agent.get(v1).is_none(), "v1 agent key `{v1}`: {agent}");
        }
        assert!(v["mcp"]["softfig-mcp"].is_null(), "v1 mcp shape: {v}");
        assert!(v["mcp"]["servers"]["softfig-mcp"].get("enabled").is_none(), "v1 `enabled`: {v}");
    }

    #[test]
    fn the_prompt_boots_from_the_fleet_protocol_and_this_members_baton() {
        let (v, paths, _tmp) = generated("b");
        let prompt = agent_block(&v, "b")["system"].as_str().unwrap();

        // The FLEET protocol, by reference — never the single-agent protocol.md,
        // and never copied (house rule 1).
        assert!(
            prompt.contains("{file:/garden/growlight/protocol-fleet.md}"),
            "the fleet protocol is pulled in by reference: {prompt}",
        );
        assert!(
            !prompt.contains("protocol.md}"),
            "never the single-agent protocol: {prompt}",
        );
        // THIS member's baton, named by its own absolute path (task 035: a member
        // that misroutes its handoff to the legacy root baton.md stalls the fleet).
        assert!(
            prompt.contains(&paths.baton.display().to_string()),
            "step 0 names this member's baton: {prompt}",
        );
        assert!(
            paths.baton.ends_with("agents/b/baton.md"),
            "the named baton is the per-member one, not the root: {}",
            paths.baton.display(),
        );
    }

    /// A real (temporary) garden + `~/.claude`, so the context's existence checks
    /// see files. `with_files` lays down the garden map, both memory-rule halves
    /// and the member's `MEMORY.md`.
    struct Garden {
        tmp: tempfile::TempDir,
    }

    impl Garden {
        fn new(with_files: bool) -> Self {
            let g = Self { tmp: tempfile::tempdir().unwrap() };
            fs::create_dir_all(g.root().join("growlight")).unwrap();
            if with_files {
                for f in ["CLAUDE.md", "growlight/memory-read.md", "growlight/memory-write.md"] {
                    fs::write(g.root().join(f), "x\n").unwrap();
                }
                fs::create_dir_all(g.memory_dir()).unwrap();
                fs::write(g.memory_dir().join("MEMORY.md"), "- [a](a.md) — index-line-marker\n").unwrap();
            }
            g
        }
        fn root(&self) -> PathBuf {
            self.tmp.path().join("garden")
        }
        fn claude(&self) -> PathBuf {
            self.tmp.path().join(".claude")
        }
        fn memory_dir(&self) -> PathBuf {
            softfig_ipc::opencode::claude_memory_dir(&self.claude().join("projects"), &self.root())
                .unwrap()
        }
        fn pre(&self) -> OpencodePreApproval {
            OpencodePreApproval::new(
                self.tmp.path().join("agents"),
                self.root(),
                self.root().join("growlight/protocol-fleet.md"),
                "/home/u/.config/softfig",
                "/usr/bin/softfig-mcp",
                self.claude(),
                "/home/u/.local/share/opencode",
            )
        }
        fn system(&self, agent: &str) -> String {
            let paths = self.pre().generate(agent).expect("generates");
            let v: Value =
                serde_json::from_str(&fs::read_to_string(&paths.opencode_config).unwrap()).unwrap();
            v["agents"][agent]["system"].as_str().unwrap().to_string()
        }
    }

    #[test]
    fn the_prompt_injects_the_garden_map_and_the_memory_index_after_step_0() {
        let g = Garden::new(true);
        let system = g.system("a");
        let at = |needle: &str| {
            system.find(needle).unwrap_or_else(|| panic!("missing {needle:?} in {system}"))
        };
        let refs = [
            format!("{{file:{}}}", g.root().join("growlight/protocol-fleet.md").display()),
            "STEP 0".to_string(),
            format!("{{file:{}}}", g.root().join("CLAUDE.md").display()),
            format!("{{file:{}}}", g.root().join("growlight/memory-read.md").display()),
            format!("{{file:{}}}", g.memory_dir().join("MEMORY.md").display()),
        ];
        // All by reference (house rule 1), in boot order: the protocol and step 0
        // stay first, then the map, the memory rules, and the index.
        let order: Vec<usize> = refs.iter().map(|r| at(r)).collect();
        assert!(order.is_sorted(), "{order:?} in {system}");
        assert!(!system.contains("index-line-marker"), "the index is referenced, never copied: {system}");
        // The memory dir is the one Claude Code itself uses for this garden.
        assert!(g.memory_dir().ends_with(format!(
            "projects/{}/memory",
            g.root().display().to_string().replace(|c: char| !c.is_ascii_alphanumeric(), "-"),
        )));
    }

    #[test]
    fn a_member_reads_memory_but_never_gets_the_write_rules() {
        // The write half exists in the garden; a read-only member still never
        // sees it, and its floor refuses the write (pinned above). One constant
        // drives both, so the day tracking lands they flip together.
        let g = Garden::new(true);
        let system = g.system("a");
        assert!(system.contains("growlight/memory-read.md}"), "{system}");
        assert!(!system.contains("memory-write.md"), "{system}");
        assert_eq!(MEMBER_MEMORY, MemoryPolicy::ReadOnly);
    }

    #[test]
    fn a_fresh_install_without_memory_still_generates_and_names_nothing_missing() {
        // opencode fails the whole location on a `{file:}` naming a missing file,
        // so only the protocol may be referenced here.
        let g = Garden::new(false);
        let system = g.system("a");
        assert_eq!(system.matches("{file:").count(), 1, "{system}");
        assert!(system.contains("has no `MEMORY.md` yet"), "{system}");
    }

    #[test]
    fn a_protocol_path_file_cannot_name_fails_closed_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("agents");
        let g = OpencodePreApproval::new(
            &agents,
            "/garden",
            "/gar}den/growlight/protocol-fleet.md",
            "/home/u/.config/softfig",
            "/usr/bin/softfig-mcp",
            "/home/u/.claude",
            "/home/u/.local/share/opencode",
        );
        let err = g.generate("a1").expect_err("a `}` would cut the {file:} short");
        assert!(matches!(err, GenError::Context(_)), "{err}");
        assert!(err.to_string().starts_with("opencode session context: protocol "), "{err}");
        assert!(!agents.exists(), "no member dir is left behind");
    }

    #[test]
    fn the_mcp_block_names_the_resolved_binary() {
        let (v, _paths, _tmp) = generated("a");
        let mcp = &v["mcp"]["servers"]["softfig-mcp"];
        assert_eq!(mcp["command"][0], "/usr/bin/softfig-mcp");
        assert_eq!(mcp["type"], "local");
    }

    #[test]
    fn the_mcp_block_carries_exactly_this_members_identity_and_nothing_else_changes() {
        // The whole `mcp` block, pinned: one server, its two existing keys, and
        // an `environment` holding the member id under the shared key — once.
        for agent in ["a", "b"] {
            let (v, _paths, _tmp) = generated(agent);
            assert_eq!(
                v["mcp"],
                serde_json::json!({
                    "servers": {
                        "softfig-mcp": {
                            "type": "local",
                            "command": ["/usr/bin/softfig-mcp"],
                            "environment": { "SOFTFIG_MEMBER": agent }
                        }
                    }
                }),
                "{agent}",
            );
            // The rest of the config keeps its shape: the same top-level keys.
            let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, ["$schema", "agents", "mcp", "permissions"], "{agent}");
        }
    }

    #[test]
    fn the_model_never_rides_the_config() {
        // opencode 2.x `run` ignores `agents.<id>.model` (slice 001 L7), so a model
        // key here would be dead config that reads as if it pinned the member.
        // The model is argv's job (`opencode_backend::ModelSelection`).
        let (v, _paths, _tmp) = generated("a");
        assert!(agent_block(&v, "a").get("model").is_none(), "no agent model: {v}");
        assert!(agent_block(&v, "a").get("variant").is_none(), "no agent variant: {v}");
        assert!(v.get("model").is_none(), "no top-level model either: {v}");
    }

    #[test]
    fn generate_writes_into_the_runtime_namespace_under_the_member_id() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("softfig/growlight/agents");
        let paths = pre(&agents)
            .generate("builder")
            .expect("generates");

        assert_eq!(paths.dir, agents.join("builder"));
        assert_eq!(paths.opencode_config, agents.join("builder/opencode.json"));
        assert!(paths.opencode_config.exists(), "opencode.json written");
        // The agent block is keyed by the member id — one id names the dir, the
        // baton, and the `--agent` the argv passes.
        let v: Value =
            serde_json::from_str(&fs::read_to_string(&paths.opencode_config).unwrap()).unwrap();
        assert!(v["agents"]["builder"].is_object(), "agents.<id> is the member id");
        assert_eq!(v["agents"]["builder"]["mode"], AGENT_MODE);
        // The claude files are a different generator's job — this one writes one file.
        assert!(!paths.loop_settings.exists(), "no claude loop.json");
        assert!(!paths.mcp_config.exists(), "no claude mcp.json");
    }

    #[test]
    fn generate_is_idempotent_so_a_reroll_relays_the_pre_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let g = pre(&tmp.path().join("agents"));
        let first = g.generate("a1").unwrap();
        let before = fs::read_to_string(&first.opencode_config).unwrap();
        let second = g.generate("a1").unwrap();
        assert_eq!(first, second);
        assert_eq!(before, fs::read_to_string(&second.opencode_config).unwrap());
    }

    #[test]
    fn generate_refuses_an_unsafe_agent_id_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let g = pre(&tmp.path().join("agents"));
        for bad in ["", ".", "..", "a/b", "../escape", "x\0y"] {
            assert!(
                matches!(
                    g.generate(bad),
                    Err(GenError::BadAgentId(_))
                ),
                "an unsafe id {bad:?} is rejected, not written",
            );
        }
    }

    #[test]
    fn generate_refuses_to_write_under_claude_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let claude = tmp.path().join(".claude");
        // agents_dir maliciously under ~/.claude — the guard refuses it.
        let g = OpencodePreApproval::new(
            claude.join("projects/agents"),
            "/garden",
            "/garden/growlight/protocol-fleet.md",
            "/home/u/.config/softfig",
            "/usr/bin/softfig-mcp",
            &claude,
            "/home/u/.local/share/opencode",
        );
        assert!(
            matches!(
                g.generate("a1"),
                Err(GenError::ClaudeDir(_))
            ),
            "a target under ~/.claude is refused, not written",
        );
        assert!(!claude.exists(), "nothing was created under ~/.claude");
    }

    #[test]
    fn generate_fails_closed_on_an_unsafe_floor_and_writes_nothing() {
        // A relative runtime root would render `edit <rel>/** allow`, which matches
        // the garden's own (cwd-relative) resources: a write hole through the guard.
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("agents");
        let g = OpencodePreApproval::new(
            &agents,
            "/garden",
            "/garden/growlight/protocol-fleet.md",
            "growlight",
            "/usr/bin/softfig-mcp",
            "/home/u/.claude",
            "/home/u/.local/share/opencode",
        );
        let err = g.generate("a1").expect_err("a relative floor root is refused");
        assert!(matches!(err, GenError::Floor(_)), "{err}");
        assert!(
            err.to_string().starts_with("opencode permission floor: runtime_root growlight is not absolute"),
            "the operator alert names the field and the reason: {err}",
        );
        assert!(!agents.exists(), "no member dir is left behind");
    }

    #[test]
    fn generate_fails_closed_when_the_dir_cannot_be_created() {
        let tmp = tempfile::tempdir().unwrap();
        // A FILE where the agents dir should be → create_dir_all under it fails.
        let blocker = tmp.path().join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let g = pre(&blocker);
        assert!(
            matches!(
                g.generate("a1"),
                Err(GenError::Io { .. })
            ),
            "an un-creatable dir fails closed",
        );
    }
}
