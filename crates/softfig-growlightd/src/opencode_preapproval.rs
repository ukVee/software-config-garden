//! Headless opencode pre-approval generation (`opencode-fleet-backend` slice
//! 003) — the fail-closed §4 `preapprove` + `inject_baton` + `attach_mcp` legs
//! for a fleet member that runs on **opencode** instead of `claude -p`.
//!
//! The sibling of [`crate::preapproval`], and deliberately growlightd's **own**
//! generator rather than a call into `softfig-cli`: growlightd depends only on
//! `softfig-ipc`, and the CLI's `opencode_config` is the *interactive* variant
//! that grants strictly less (see below). Everything fail-closed is shared, not
//! re-expressed — `validate_agent_id`, the `~/.claude` refusal, [`GenError`],
//! and the `agent_paths` layout all come from the claude module, so the two
//! generators can never drift on what they refuse or where they write.
//!
//! ## Why it cannot reuse the interactive config
//!
//! The CLI's `opencode_config` grants `read` / `bash` / `external_directory` /
//! `softfig-mcp*` and **no `edit` rule at all** — correct there, because a human
//! approves each edit at the TUI prompt. A headless member **cannot prompt**: it
//! errors out and dies on its first code change. So the headless map carries
//! `edit` (and `write`) explicitly. That is the whole delta, and it is the §4
//! "a missing rule silently kills an agent mid-run" clause
//! (`journal/decisions/decision-opencode-fleet-backend.md`, locked decision 6).
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
//!
//! - `agent.<id>.prompt` — the **fleet** protocol (`protocol-fleet.md`, per
//!   `crate::fleet`'s `fleet_protocol`; never the single-agent `protocol.md`,
//!   since every member growlightd spawns is a fleet member) pulled in by a
//!   `{file:…}` reference so the text is *reused*, never copied (house rule 1),
//!   plus a step-0 line naming **this member's** `agents/<id>/baton.md`. opencode
//!   has no SessionStart hook, so the prompt IS the boot injection: a fresh
//!   session rebuilds the system prompt, reloads the protocol, and step 0
//!   re-reads the live baton.
//! - `agent.<id>.permission` — the headless map (`read`/`edit`/`write`/`bash`),
//!   `softfig-mcp*`, and the `external_directory` grants the loop's own state
//!   needs.
//! - `agent.<id>.model` / `.variant` — emitted only when the caller resolved
//!   them ([`ModelSelection`]); slice 005 fills them from the member's config.
//! - `mcp.softfig-mcp` — the explicit project-scoped attach, resolved exactly as
//!   the claude `mcp.json` is, so the garden verbs exist regardless of the user's
//!   global `~/.config/opencode` registration.
//!
//! ## Known gap — the code repo is not granted yet (slice 004)
//!
//! opencode's cwd for a member is the garden root (slice 004's argv), and
//! `external_directory` is what governs everything outside cwd. The code repo a
//! member actually edits is outside it, and the grant list here covers only the
//! loop's own state — because the repo is a property of the *claimed queue*, not
//! of the member, and nothing at generation time knows it yet. Slice 004 spawns
//! with the assignment in hand and must add that grant, or a headless member dies
//! on its first repo write. Recorded here rather than guessed at: an
//! `external_directory` `allow` is read **and** write with no read-only form, so
//! it is not a rule to invent speculatively.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::preapproval::{agent_paths, validate_agent_id, write_file, AgentPaths, GenError};

/// opencode's agent `mode` for a fleet member: `primary`, the same mode the
/// interactive `softfig-loop` agent uses — the member IS the session, not a
/// subagent it delegates to.
const AGENT_MODE: &str = "primary";

/// The permission keys a **headless** member must carry, and why each one is
/// here (the emitted JSON sorts them; this order is the argument).
///
/// - `read` / `bash` — the interactive grant, unchanged.
/// - `edit` — the headless delta. On opencode 1.18.15 this single key gates ALL
///   file modification (write and apply_patch included), so it is the rule that
///   actually keeps a member alive through its first code change.
/// - `write` — emitted alongside `edit` because the spec's non-negotiable names
///   both. On the pinned 1.18.15 it is **inert** (probe-proven: `edit` is the
///   only gate), so this is belt-and-braces against a future version wiring it,
///   not a second enforcement point. Recorded so nobody later "discovers" it does
///   nothing and deletes it as dead config.
const HEADLESS_TOOLS: &[&str] = &["read", "edit", "write", "bash"];

/// The MCP permission glob granting the member every `softfig-mcp` verb — the
/// garden is mutated only through them (house rule), so a member that could not
/// call them could not do its job.
const MCP_PERMISSION: &str = "softfig-mcp*";

/// The per-member model the generated agent block pins, as resolved by the
/// caller. Owned (not borrowed) so the backend flavor can hold one across spawns,
/// and a distinct type rather than two adjacent `Option<String>` arguments —
/// exactly the call site where a value lands in the wrong slot silently.
///
/// Both fields absent (the [`Default`]) is the honest "not resolved yet" state:
/// the keys are then omitted entirely and opencode keeps its own defaults, which
/// is not the same as pinning a name we invented. Slice 005 fills them from
/// `config/growlight.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModelSelection {
    /// The opencode model id (`provider/model`), e.g. `deepseek/deepseek-v4-flash`.
    pub model: Option<String>,
    /// The model's `variant` (opencode's `AgentConfig.variant`).
    pub variant: Option<String>,
}

impl ModelSelection {
    /// A selection pinning `model`, with the model's own default variant.
    pub fn model(model: impl Into<String>) -> Self {
        Self {
            model: Some(model.into()),
            variant: None,
        }
    }

    /// Pin a `variant` alongside the model.
    pub fn with_variant(mut self, variant: impl Into<String>) -> Self {
        self.variant = Some(variant.into());
        self
    }
}

/// The context growlightd generates each **opencode** member's pre-approval from
/// — the mirror of [`PreApproval`](crate::preapproval::PreApproval), differing
/// only where opencode does: it grants the runtime root through
/// `external_directory` (the baton is the loop's only carried state and every
/// handoff rewrites it) instead of anchoring `Edit`/`Write` deny rules to the
/// garden, because on opencode 1.18.15 no garden deny is expressible without also
/// blocking that handoff write. Pure data; cloneable so the backend holds one and
/// regenerates per spawn.
#[derive(Debug, Clone)]
pub struct OpencodePreApproval {
    agents_dir: PathBuf,
    protocol: PathBuf,
    runtime_root: PathBuf,
    mcp_bin: PathBuf,
    /// `~/.claude` — the harness-sensitive root. Its `projects/` subtree is the
    /// only part granted (claude-memory lives outside the garden workspace); the
    /// generator refuses to WRITE anything under it (the locked decision, mirrored
    /// from the claude generator).
    claude_dir: PathBuf,
}

impl OpencodePreApproval {
    /// Build the generation context. `protocol` is the **fleet** protocol
    /// (`growlight/protocol-fleet.md`); `runtime_root` is the growlight runtime
    /// grant root (`$XDG_CONFIG_HOME/softfig`, the parent of the pillar dir, so
    /// sibling runtime state is covered by one rule); `claude_dir` is `~/.claude`.
    pub fn new(
        agents_dir: impl Into<PathBuf>,
        protocol: impl Into<PathBuf>,
        runtime_root: impl Into<PathBuf>,
        mcp_bin: impl Into<PathBuf>,
        claude_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            agents_dir: agents_dir.into(),
            protocol: protocol.into(),
            runtime_root: runtime_root.into(),
            mcp_bin: mcp_bin.into(),
            claude_dir: claude_dir.into(),
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
    /// `~/.claude`, an un-creatable dir, or a write error all abort the spawn,
    /// exactly as they do for claude, because a headless opencode session that
    /// starts without its permission map dies on its first edit rather than
    /// prompting. Idempotent: it overwrites on every call, so a re-roll re-lays
    /// the current pre-approval.
    ///
    /// The agent id doubles as the opencode **agent name** (`agent.<id>`, and
    /// what slice 004's argv passes to `--agent`), so one member id names its
    /// runtime dir, its baton, and its agent block.
    pub fn generate(
        &self,
        agent: &str,
        model: &ModelSelection,
    ) -> Result<AgentPaths, GenError> {
        validate_agent_id(agent)?;
        let paths = agent_paths(&self.agents_dir, agent);
        // Defense-in-depth on the locked decision: never write under ~/.claude,
        // even if `agents_dir` were misconfigured to point there.
        if paths.dir.starts_with(&self.claude_dir) {
            return Err(GenError::ClaudeDir(paths.dir.clone()));
        }
        fs::create_dir_all(&paths.dir)
            .map_err(|e| GenError::io("create agent dir", &paths.dir, e))?;
        write_file(
            &paths.opencode_config,
            &opencode_json(&AgentInputs {
                agent_name: agent,
                protocol: &self.protocol,
                baton: &paths.baton,
                runtime_root: &self.runtime_root,
                claude_projects: &self.claude_projects(),
                mcp_bin: &self.mcp_bin,
                model,
            }),
        )?;
        Ok(paths)
    }
}

// ---- the pure generator ------------------------------------------------------

/// What [`opencode_json`] renders. A struct rather than seven positional
/// arguments for the same reason the CLI's `OpencodeConfigInputs` is one: five of
/// these are `&Path` and a value in the wrong slot would generate a plausible,
/// wrong config in silence.
struct AgentInputs<'a> {
    /// The member id — opencode's `agent.<name>` and slice 004's `--agent` value.
    agent_name: &'a str,
    /// The garden's `growlight/protocol-fleet.md`, pulled into the prompt by
    /// `{file:…}` reference (never copied).
    protocol: &'a Path,
    /// **This member's** `agents/<id>/baton.md`, named by the step-0 boot line.
    baton: &'a Path,
    /// The growlight runtime grant root (`$XDG_CONFIG_HOME/softfig`).
    runtime_root: &'a Path,
    /// The claude-memory tree (`~/.claude/projects`).
    claude_projects: &'a Path,
    /// The `softfig-mcp` binary the project-scoped `mcp` block runs.
    mcp_bin: &'a Path,
    /// The resolved model/variant, each omitted when unset.
    model: &'a ModelSelection,
}

/// Render a headless member's `opencode.json`. Pure — builds the string, never
/// writes or spawns — so the whole permission map, prompt, and mcp attach are
/// unit-testable without touching a filesystem or a real `opencode`.
fn opencode_json(cfg: &AgentInputs<'_>) -> String {
    // The system prompt IS the boot injection (opencode has no SessionStart
    // hook): the fleet protocol by reference + a step-0 line naming this member's
    // own baton path in English. That naming is the task-035 cure carried over
    // from the claude `inject.sh` — a member that is only *seeded* with a baton
    // path can misroute its handoff write to the legacy root `baton.md`, which is
    // how the fleet once stalled for four hours.
    let prompt = format!(
        "{{file:{protocol}}}\n\n\
         STEP 0 (every session, first): read YOUR BATON FILE — the exact path \
         `{baton}` — and follow the fleet operating protocol above. That file is \
         your only carried state AND the exact path you rewrite at handoff; never \
         the legacy root `baton.md`. opencode has no SessionStart hook, so a fresh \
         session (`/new` or a relaunch) re-reads it here; that reread IS the roll.",
        protocol = cfg.protocol.display(),
        baton = cfg.baton.display(),
    );

    // `external_directory` grants what lives OUTSIDE the member's cwd (the garden
    // root, per slice 004's argv). Both entries are load-bearing for the loop
    // itself: the runtime root because the baton is its only carried state and
    // every handoff rewrites it (granted at the `softfig/` level so sibling
    // runtime state — usage, questions, the other members' dirs — needs no new
    // rule), and the claude-memory tree because protocol §3 has the member keep
    // its own pointers in sync. Surgical, never a bare `allow`: the ~/.claude
    // OAuth token and harness settings stay out of reach. See the module's
    // "Known gap" — the claimed queue's code repo still needs its own grant.
    let mut external = serde_json::Map::new();
    external.insert(glob(cfg.runtime_root), Value::from("allow"));
    external.insert(glob(cfg.claude_projects), Value::from("allow"));

    let mut permission = serde_json::Map::new();
    for tool in HEADLESS_TOOLS {
        permission.insert((*tool).to_string(), Value::from("allow"));
    }
    permission.insert("external_directory".to_string(), Value::Object(external));
    permission.insert(MCP_PERMISSION.to_string(), Value::from("allow"));

    let mut agent = serde_json::json!({
        "mode": AGENT_MODE,
        "prompt": prompt,
        "permission": Value::Object(permission),
    });
    // Only emit what was actually resolved — an absent key leaves opencode on its
    // own default, which is not the same as pinning a guessed name.
    if let Some(model) = cfg.model.model.as_deref() {
        agent["model"] = Value::from(model);
    }
    if let Some(variant) = cfg.model.variant.as_deref() {
        agent["variant"] = Value::from(variant);
    }
    let mut agents = serde_json::Map::new();
    agents.insert(cfg.agent_name.to_string(), agent);

    let v = serde_json::json!({
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "softfig-mcp": {
                "type": "local",
                "command": [ cfg.mcp_bin.display().to_string() ],
                "enabled": true,
            }
        },
        "agent": Value::Object(agents),
    });
    format!("{}\n", serde_json::to_string_pretty(&v).unwrap())
}

/// The recursive `external_directory` key for a granted root. `**` is the only
/// pattern form opencode 1.18.15 matches reliably against absolute paths.
fn glob(root: &Path) -> String {
    format!("{}/**", root.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pre(agents_dir: &Path) -> OpencodePreApproval {
        OpencodePreApproval::new(
            agents_dir,
            "/garden/growlight/protocol-fleet.md",
            "/home/u/.config/softfig",
            "/usr/bin/softfig-mcp",
            "/home/u/.claude",
        )
    }

    fn generated(agent: &str, model: &ModelSelection) -> (Value, AgentPaths, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("softfig/growlight/agents");
        let paths = pre(&agents).generate(agent, model).expect("generates");
        let raw = fs::read_to_string(&paths.opencode_config).unwrap();
        (serde_json::from_str(&raw).expect("emitted JSON parses"), paths, tmp)
    }

    fn agent_block<'a>(v: &'a Value, agent: &str) -> &'a Value {
        &v["agent"][agent]
    }

    #[test]
    fn the_headless_permission_map_allows_edit_and_write() {
        let (v, _paths, _tmp) = generated("a", &ModelSelection::default());
        let perm = &agent_block(&v, "a")["permission"];

        // THE delta from the interactive config, and the whole point of the slice:
        // a headless member cannot answer a permission prompt, so the rule that
        // lets it change a file must be granted before it starts.
        assert_eq!(perm["edit"], "allow", "headless members must carry `edit`");
        assert_eq!(perm["write"], "allow", "headless members must carry `write`");
        // The interactive grant, unchanged.
        assert_eq!(perm["read"], "allow");
        assert_eq!(perm["bash"], "allow");
        // The garden is mutated only through the MCP verbs, so they are granted.
        assert_eq!(perm[MCP_PERMISSION], "allow");
    }

    #[test]
    fn external_directory_grants_the_runtime_root_and_claude_memory_only() {
        let (v, _paths, _tmp) = generated("a", &ModelSelection::default());
        let ext = agent_block(&v, "a")["permission"]["external_directory"]
            .as_object()
            .expect("external_directory is a map");

        assert_eq!(ext["/home/u/.config/softfig/**"], "allow", "the baton is rewritten every handoff");
        assert_eq!(ext["/home/u/.claude/projects/**"], "allow", "claude-memory pointers");
        // Surgical: ~/.claude itself (the OAuth token + harness settings) is never
        // granted, and no bare wildcard slips in.
        assert_eq!(ext.len(), 2, "no grant beyond the two the loop needs: {ext:?}");
        for key in ext.keys() {
            assert!(
                !key.starts_with("/home/u/.claude/**"),
                "the harness-sensitive root is never granted: {key}",
            );
        }
    }

    #[test]
    fn the_prompt_boots_from_the_fleet_protocol_and_this_members_baton() {
        let (v, paths, _tmp) = generated("b", &ModelSelection::default());
        let prompt = agent_block(&v, "b")["prompt"].as_str().unwrap();

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

    #[test]
    fn the_mcp_block_names_the_resolved_binary() {
        let (v, _paths, _tmp) = generated("a", &ModelSelection::default());
        let mcp = &v["mcp"]["softfig-mcp"];
        assert_eq!(mcp["command"][0], "/usr/bin/softfig-mcp");
        assert_eq!(mcp["type"], "local");
        assert_eq!(mcp["enabled"], true);
    }

    #[test]
    fn model_and_variant_are_emitted_only_when_resolved() {
        // Unresolved (the slice-005-pending default): both keys absent, so
        // opencode keeps its own default rather than a name we invented.
        let (bare, _p, _t) = generated("a", &ModelSelection::default());
        assert!(agent_block(&bare, "a").get("model").is_none());
        assert!(agent_block(&bare, "a").get("variant").is_none());

        // Resolved: exactly what the caller pinned.
        let sel = ModelSelection::model("deepseek/deepseek-v4-flash").with_variant("thinking");
        let (pinned, _p, _t) = generated("a", &sel);
        assert_eq!(agent_block(&pinned, "a")["model"], "deepseek/deepseek-v4-flash");
        assert_eq!(agent_block(&pinned, "a")["variant"], "thinking");

        // A model with no variant pins only the model.
        let (model_only, _p, _t) = generated("a", &ModelSelection::model("deepseek/deepseek-v4-pro"));
        assert_eq!(agent_block(&model_only, "a")["model"], "deepseek/deepseek-v4-pro");
        assert!(agent_block(&model_only, "a").get("variant").is_none());
    }

    #[test]
    fn generate_writes_into_the_runtime_namespace_under_the_member_id() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("softfig/growlight/agents");
        let paths = pre(&agents)
            .generate("builder", &ModelSelection::default())
            .expect("generates");

        assert_eq!(paths.dir, agents.join("builder"));
        assert_eq!(paths.opencode_config, agents.join("builder/opencode.json"));
        assert!(paths.opencode_config.exists(), "opencode.json written");
        // The agent block is keyed by the member id — one id names the dir, the
        // baton, and the `--agent` slice 004 passes.
        let v: Value =
            serde_json::from_str(&fs::read_to_string(&paths.opencode_config).unwrap()).unwrap();
        assert!(v["agent"]["builder"].is_object(), "agent.<id> is the member id");
        assert_eq!(v["agent"]["builder"]["mode"], AGENT_MODE);
        // The claude files are a different generator's job — this one writes one file.
        assert!(!paths.loop_settings.exists(), "no claude loop.json");
        assert!(!paths.mcp_config.exists(), "no claude mcp.json");
    }

    #[test]
    fn generate_is_idempotent_so_a_reroll_relays_the_pre_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let g = pre(&tmp.path().join("agents"));
        let sel = ModelSelection::model("deepseek/deepseek-v4-flash");
        let first = g.generate("a1", &sel).unwrap();
        let before = fs::read_to_string(&first.opencode_config).unwrap();
        let second = g.generate("a1", &sel).unwrap();
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
                    g.generate(bad, &ModelSelection::default()),
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
            "/garden/growlight/protocol-fleet.md",
            "/home/u/.config/softfig",
            "/usr/bin/softfig-mcp",
            &claude,
        );
        assert!(
            matches!(
                g.generate("a1", &ModelSelection::default()),
                Err(GenError::ClaudeDir(_))
            ),
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
            matches!(
                g.generate("a1", &ModelSelection::default()),
                Err(GenError::Io { .. })
            ),
            "an un-creatable dir fails closed",
        );
    }
}

