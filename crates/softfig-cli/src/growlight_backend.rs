//! growlight agent-backend seam (spec-growlight.md §12) — the semi-auto
//! launch half only. The headless `--auto` CLI driver was retired in favour of
//! growlightd, the one control plane (single-control-plane); its `claude -p`
//! usage parser, clock/probe seams and `AgentBackend` driver left with it.
//!
//! What remains is the interactive (`growlight start`) seam: the `Backend`
//! chooser (`claude` | `opencode`), the per-backend launch argv (`claude`
//! rooted at the garden; `opencode` handed a generated `opencode.json` over
//! `OPENCODE_CONFIG`), and the opencode config generator shared with the
//! launch. `claude` is never hardcoded into the loop logic — the launch
//! machinery lives here, as free functions.
use std::path::Path;
use std::process::Command;

use anyhow::Result;
use serde_json::Value;
use softfig_ipc::opencode::{
    Context as SessionContext, Floor, MemoryPolicy, Posture, context, file_ref, floor,
};

/// The model grammar + resolution now live in `softfig-ipc` (queue v2 §6.4 —
/// also needed by the grants spec): re-exported here so this crate's call sites
/// and tests keep their names. The **launch** machinery (argv/env/cwd
/// construction) stays in this crate, as free functions below.
pub use softfig_ipc::model_choice::{
    Backend, DEEPSEEK_FLASH, DEEPSEEK_REASONING, ModelChoice, ModelSpec, item_doc_candidates,
    parse_model_spec, resolve_item_models,
};

/// The launcher binary name for a backend, for the spawn and user-facing
/// messages. (Formerly `Backend::agent_bin`; the enum moved to `softfig-ipc`,
/// the launch side stayed here.)
pub fn agent_bin(backend: Backend) -> &'static str {
    match backend {
        Backend::Claude => "claude",
        Backend::Opencode => "opencode",
    }
}

/// `provider/model` or `provider/model#variant`: opencode 2.x's one-string model
/// reference — the generated config's top-level `model` spelling.
/// `ModelChoice::opencode_model_ref` covers the same spelling from a choice;
/// this render helper serves the config path that holds model + variant loose.
fn opencode_model_ref(model: &str, variant: Option<&str>) -> String {
    match variant {
        Some(variant) => format!("{model}#{variant}"),
        None => model.to_string(),
    }
}

/// The inputs an interactive launch needs, across backends. Each backend
/// consumes only the subset relevant to it (claude: the name, `loop_settings`,
/// `mcp_config`, and `garden_root`; opencode: the name, `opencode_config`,
/// `garden_root`, and `boot_prompt`), so the seam stays a single call while
/// neither backend has to fabricate the paths the other needs. Borrows throughout
/// (the caller owns the generated runtime paths); pure data, no I/O.
pub struct InteractiveLaunch<'a> {
    /// The loop session's tag: claude's `--name`, opencode's `--agent`.
    pub agent_name: &'a str,
    /// claude `--settings`: the generated `loop.json` (SessionStart hooks +
    /// statusline). Ignored by opencode.
    pub loop_settings: &'a Path,
    /// claude `--mcp-config`: the generated `mcp.json` attaching softfig-mcp.
    /// Ignored by opencode (its mcp block lives inside `opencode_config`).
    pub mcp_config: &'a Path,
    /// opencode `OPENCODE_CONFIG`: the generated `opencode.json` (the
    /// `softfig-loop` agent = protocol-by-reference + step-0 baton boot +
    /// runtime grant + explicit softfig-mcp block, slice 002). Ignored by claude.
    pub opencode_config: &'a Path,
    /// The launch cwd for **both** backends — the garden root.
    ///
    /// For claude this is slice 005's auto-cd: `growlight start` behaves the same
    /// from any directory and the session picks up the garden's own `CLAUDE.md`
    /// instead of whatever tree the human happened to be standing in. The claude
    /// **argv** is still byte-identical to the original hardwired invocation; only
    /// the cwd, which that invocation merely inherited, is now pinned.
    ///
    /// For opencode this is slice 006. It used to root at the runtime dir so the
    /// garden would be "external" and deniable — but the loop then had no way to
    /// READ the garden at all (softfig-mcp has no read verb), and on opencode
    /// 1.18.15 the deny turned out to be unenforceable anyway. Rooting at the
    /// garden makes garden docs ordinary in-project reads, which is what the loop
    /// actually needs; the baton is granted back via `external_directory`. On 2.x
    /// the garden write guard is the config's universal `edit` deny instead (see
    /// [`opencode_config`]). softfig-mcp is attached explicitly, so it resolves
    /// regardless of cwd.
    pub garden_root: &'a Path,
    /// opencode first-turn kick (`--prompt`): tells the fresh session to begin
    /// its iteration (step 0 = read the baton, then follow the protocol).
    /// claude's interactive TUI takes no kick — the human sends the first turn —
    /// so this is opencode-only.
    pub boot_prompt: &'a str,
}

/// Build the interactive loop command for a backend. Pure (constructs,
/// never spawns) so the argv/env/cwd are unit-testable. (Formerly
/// `Backend::interactive_command`; the enum moved to `softfig-ipc`, the launch
/// side stayed here.)
///
/// - **claude** reproduces the original hardwired argv exactly —
///   `claude --name <name> --settings <loop.json> --mcp-config <mcp.json>` —
///   inheriting the caller's environment, and rooted at the garden
///   (`launch.garden_root`, slice 005's auto-cd) instead of wherever the human
///   invoked it from. It still sets no env.
/// - **opencode** launches the TUI on the generated agent —
///   `opencode --standalone --prompt <boot>` (see [`opencode_interactive_args`]
///   for why `--standalone`, and why no `--agent`) — with `OPENCODE_CONFIG`
///   pointing at the generated `opencode.json` (opencode's analog of claude's
///   `--settings`; the agent, its selection as `default_agent`, its permission
///   map, and the softfig-mcp block all live in that one file, so there is no
///   separate `--mcp-config`) and
///   cwd set to the **garden** (`launch.garden_root`) — the same root claude
///   gets — so garden docs are ordinary in-project reads; see
///   [`InteractiveLaunch::garden_root`]. The `--prompt`
///   is the reseed kick: opencode has no SessionStart hook, so the roll is the
///   agent prompt's step-0 baton read, and this first turn nudges the fresh
///   session into it.
pub fn interactive_command(backend: Backend, launch: &InteractiveLaunch) -> Result<Command> {
    let mut cmd = Command::new(agent_bin(backend));
    match backend {
        Backend::Claude => {
            cmd.arg("--name")
                .arg(launch.agent_name)
                .arg("--settings")
                .arg(launch.loop_settings)
                .arg("--mcp-config")
                .arg(launch.mcp_config)
                .current_dir(launch.garden_root);
        }
        Backend::Opencode => {
            cmd.args(opencode_interactive_args())
                .arg("--prompt")
                .arg(launch.boot_prompt)
                .env("OPENCODE_CONFIG", launch.opencode_config)
                .current_dir(launch.garden_root);
        }
    }
    Ok(cmd)
}

/// The interactive opencode argv up to (not including) the first-turn `--prompt`:
/// just `--standalone`. Shared by the real launch and the `--no-launch` hint, so
/// the command a human copy-pastes cannot lose a flag the launcher has.
///
/// `--standalone` is a correctness flag on opencode 2.x, not hygiene. Without it
/// the TUI attaches to the per-user shared service, and a running one **ignores
/// the client's `OPENCODE_CONFIG`** (opencode-v2-repin slice 001, finding 1): the
/// session silently becomes the built-in `build` agent, with no protocol prompt,
/// no baton boot, allow-all permissions and every global grant. `--standalone`
/// gives the session a private server that loads this launch's config and exits
/// with it.
///
/// There is no `--agent`: the 2.x root (TUI) command has neither `--agent` nor
/// `--model` (only `run` and `mini` do), and refuses the launch with
/// `unrecognized flag: --agent`. The agent is selected by the config's top-level
/// `default_agent` instead ([`opencode_config`]), as the model is by its top-level
/// `model`.
pub fn opencode_interactive_args() -> [&'static str; 1] {
    ["--standalone"]
}

/// The interactive loop's claude-memory policy: **read and write**, as Claude Code
/// sessions have it (`decision-opencode-v2-fleet-safety-order` § Memory). The
/// human is at the keyboard, unlike a fleet member (growlightd's
/// `MEMBER_MEMORY`). Drives both the floor's memory `edit` rule and whether
/// [`opencode_context`] injects the write rules.
pub const INTERACTIVE_MEMORY: MemoryPolicy = MemoryPolicy::ReadWrite;

/// The session context the interactive loop's `system` prompt carries after the
/// step-0 line ([`softfig_ipc::opencode::context`] under [`INTERACTIVE_MEMORY`]):
/// the garden root `CLAUDE.md`, both memory-rule halves, and the memory index,
/// each by `{file:}` reference and only if it exists now. opencode 2.x reads
/// neither `CLAUDE.md` nor claude-memory on its own (opencode-v2-repin slice 005).
/// Checked at every launch, so a relaunch sees the memory as it is then.
pub fn opencode_context(garden_root: &Path, claude_projects: &Path) -> Result<String> {
    Ok(context(&SessionContext {
        garden_root,
        claude_projects,
        memory: INTERACTIVE_MEMORY,
    })?)
}

/// The inputs [`opencode_config`] renders into an `opencode.json`: where the
/// fixed pieces live (`protocol`, `claude_projects`, `opencode_data`),
/// where this run's churny pieces live (`baton`, `mcp_bin`, `context`), and what
/// the launch resolved to (`model`, `variant`). Grouped for the same reason
/// [`InteractiveLaunch`] is — the generator's inputs accrete as the seam grows
/// (slice 005 added two on its own), and a widening positional argument list is
/// the kind of call site where a `&Path` lands in the wrong slot silently.
/// Borrows throughout (the caller owns the paths); pure data, no I/O.
#[derive(Clone, Copy)]
pub struct OpencodeConfigInputs<'a> {
    /// The generated agent's name — opencode's `agent.<name>`, and what the
    /// launch passes to `--agent`.
    pub agent_name: &'a str,
    /// The garden's `growlight/protocol.md`, pulled into the agent prompt by
    /// `{file:…}` reference (never copied) so a fresh session reloads it.
    pub protocol: &'a Path,
    /// The runtime baton the step-0 boot line names.
    pub baton: &'a Path,
    /// The rendered session context ([`opencode_context`]), appended after the
    /// step-0 line; empty when there is nothing to inject.
    pub context: &'a str,
    /// The growlight runtime root (`$XDG_CONFIG_HOME/softfig`), granted via
    /// `external_directory` so the loop can read and rewrite its baton. The garden
    /// root is deliberately absent: it is the launch cwd, so it needs no grant.
    pub runtime_root: &'a Path,
    /// The `softfig-mcp` binary the explicit project-scoped `mcp` block runs.
    pub mcp_bin: &'a Path,
    /// The claude-memory tree (`~/.claude/projects`), granted so the loop's own
    /// memory pointers stay reachable + editable.
    pub claude_projects: &'a Path,
    /// opencode's data dir (`softfig_ipc::opencode::opencode_data_dir`); the floor
    /// re-grants its `shell/` + `tool-output/` subdirs read-only so truncated tool
    /// output stays readable.
    pub opencode_data: &'a Path,
    /// The resolved opencode model id (`provider/model`).
    pub model: &'a str,
    /// The resolved opencode `variant`, rendered as the model's `#variant` suffix
    /// and omitted when `None`.
    pub variant: Option<&'a str>,
}

/// The protocol §2b override an opencode session gets ahead of its step-0 line.
/// `usage.json` is written only by Claude Code's statusline, so here it reports
/// the Claude subscription's rate windows and says nothing about this session's
/// provider.
pub const OPENCODE_BUDGET_NOTE: &str = "§2b ON THIS BACKEND: `usage.json` is written by \
    Claude Code's statusline, so it holds the Claude subscription's rate windows, not this \
    opencode session's. They do not bind you: never halt on them, and omit `session_5h_pct` \
    / `session_7d_pct` from the baton head, saying in prose that this backend's rate windows \
    are not read. A baton a Claude session left HALTED_RATE_LIMIT on a Claude window is \
    resumable here immediately; set it IN_PROGRESS and run its NEXT ACTION. The context \
    budget (§2) still applies.";

/// Generate the opencode-native equivalent of claude's `loop.json` + `mcp.json`:
/// an `opencode.json` (loaded via `OPENCODE_CONFIG=<path>` — opencode's analog of
/// claude's `--settings`) defining a `softfig-loop` **agent**. This carries the
/// three interactive legs of the seam for opencode (spec-agents §4.1 /
/// decision-semi-auto-backend-seam's mapping table): `inject_baton`,
/// `preapprove`, and `attach_mcp`. Pure (builds the string, never writes/spawns)
/// so it's unit-testable like the claude generators. Native opencode 2.x keys
/// only (`agents`, `system`, `permissions`, `mcp.servers`).
///
/// - **inject_baton (the reseed bootstrap).** opencode has no SessionStart hook,
///   so the roll can't re-cat a baton the way claude's `/clear` does. Instead the
///   agent's `system` prompt = the garden `protocol.md` (pulled in by opencode's
///   `{file:…}` reference, so the protocol text is *reused*, never duplicated) +
///   a step-0 line naming the baton path. A fresh session (`/new` / relaunch)
///   rebuilds the system prompt → reloads the protocol → step 0 re-reads the
///   current baton. The protocol *is* the bootstrap. The session context follows
///   (the garden map, the memory rules and the memory index; see
///   [`opencode_context`]).
/// - **preapprove.** The top-level `permissions` are the shared floor
///   ([`softfig_ipc::opencode::floor`]) in the **interactive** posture, the same
///   builder growlightd's fleet members use, so the two can never drift. Read,
///   shell and the softfig-mcp verbs never prompt. Everything the floor does not
///   grant is put to the human (`ask`) rather than denied: an outside directory
///   (the global `~/projects/**`-style grants are reset to `ask`, so the human
///   approves a code repo instead of the loop silently reaching it) and an edit
///   outside the garden.
/// - **the garden write guard is back.** On opencode 1.18.15 no garden write-deny
///   was expressible without also blocking the loop's own baton write (semi-auto
///   slice 006 removed it after four probes). 2.x can express it
///   (opencode-v2-repin slice 001, L3c): the floor's universal `edit * deny`
///   refuses every raw garden write, and the later absolute allows re-open the
///   runtime root (the baton) and the memory tree ([`INTERACTIVE_MEMORY`]:
///   writable). In-cwd resources are matched
///   cwd-relative, so the interactive `edit /* ask` that re-opens code repos to the
///   human never reaches the garden. Garden mutations go through softfig-mcp.
/// - **top level, not on the agent.** Top-level rules govern every agent the
///   private server loads: a `subagent` call's built-in `general` / `explore`, and
///   the `build` / `plan` primaries a human can Tab to. Rules on `softfig-loop`
///   alone would leave every global grant one agent switch away.
/// - **the garden is the cwd (slice 006).** Garden docs are ordinary in-project
///   reads, which is what the loop needs (softfig-mcp has no read verb).
/// - **attach_mcp.** Emits an explicit project-scoped `mcp.servers.softfig-mcp`
///   block (mirroring why claude gets an explicit `--mcp-config`) so the garden
///   verbs exist regardless of launch cwd, without depending on the user's global
///   `~/.config/opencode` registration. The binary is resolved the same way as
///   the claude `mcp.json` (`softfig_mcp_path` — the sibling of the running exe).
/// - **model / variant.** Both are passed in, never inlined — the slice-005
///   resolution (picker choice, `--model` flag, or the active backlog item's
///   `> Model:` declaration) decides them and hands the answer down. They land in
///   the config's **top-level** `model` as one `provider/model[#variant]` string,
///   not on the agent: on opencode 2.x the agent block's `model` is ignored and
///   the top-level one wins (opencode-v2-repin slice 001, L7), and the interactive
///   root command has no `--model` flag. The catch is that a bad top-level id
///   silently falls back to `opencode/exo-free` and sends the prompt there, so
///   the launcher checks the id against the live catalog before it launches
///   (`crate::opencode_catalog`).
///
/// **Fail-closed:** a floor directory the shared builder refuses (relative,
/// non-UTF-8, a pattern metacharacter, or `/`), or a protocol path opencode's
/// `{file:}` cannot carry, is an error, and no config is written.
pub fn opencode_config(cfg: &OpencodeConfigInputs<'_>) -> Result<String> {
    let OpencodeConfigInputs {
        agent_name,
        protocol,
        baton,
        context,
        runtime_root,
        mcp_bin,
        claude_projects,
        opencode_data,
        model,
        variant,
    } = *cfg;

    // The system prompt: the protocol by reference (opencode expands `{file:…}`
    // at config load — verified to resolve an absolute path) + the §2b budget
    // override + the step-0 baton-boot line that makes every fresh session
    // re-read the live baton + the session context.
    //
    // §2b reads `usage.json`, which only Claude Code's statusline writes, so on
    // this backend it holds the Claude subscription's windows, never this
    // session's. Without the override an opencode session halts on a Claude
    // window, which is exactly when the human reaches for opencode.
    let mut system = format!(
        "{protocol}\n\n\
         {OPENCODE_BUDGET_NOTE}\n\n\
         STEP 0 (every session, first): Read your baton at `{baton}` and follow the \
         operating protocol above — the baton is your only carried state. opencode has \
         no SessionStart hook, so a fresh session (`/new` or a relaunch) re-reads the \
         baton here; that reread IS the roll.",
        protocol = file_ref("protocol", protocol)?,
        baton = baton.display(),
    );
    if !context.is_empty() {
        system.push_str("\n\n");
        system.push_str(context);
    }

    let permissions = floor(
        Posture::Interactive,
        &Floor {
            runtime_root,
            claude_projects,
            opencode_data,
            memory: INTERACTIVE_MEMORY,
        },
    )?;

    let mut agents = serde_json::Map::new();
    agents.insert(
        agent_name.to_string(),
        serde_json::json!({ "mode": "primary", "system": system }),
    );

    let v = serde_json::json!({
        "$schema": "https://opencode.ai/config.json",
        // Top-level, where 2.x honors it (see the doc above). No variant → the bare
        // id, which leaves the model on its own default variant.
        "model": opencode_model_ref(model, variant),
        // The TUI's agent selection: the 2.x root command has no `--agent` flag
        // (see `opencode_interactive_args`), so a fresh session starts on the
        // config's default primary agent. Without this it starts on `build`.
        "default_agent": agent_name,
        "permissions": permissions,
        "mcp": {
            "servers": {
                "softfig-mcp": {
                    "type": "local",
                    "command": [ mcp_bin.display().to_string() ],
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

    use softfig_ipc::model_choice::item_model_field;

    /// The claude launch argv is the hardwired seam contract: `--name` /
    /// `--settings` / `--mcp-config`, rooted at the garden.
    #[test]
    fn claude_interactive_command_is_the_hardwired_argv_rooted_at_the_garden() {
        use std::ffi::{OsStr, OsString};
        let loop_path = Path::new("/run/softfig/growlight/loop.json");
        let mcp_path = Path::new("/run/softfig/growlight/mcp.json");
        let garden = Path::new("/home/u/garden");
        let launch = InteractiveLaunch {
            agent_name: "softfig-loop",
            loop_settings: loop_path,
            mcp_config: mcp_path,
            garden_root: garden,
            // opencode-only fields — the claude arm must ignore them entirely.
            opencode_config: Path::new("/run/softfig/growlight/opencode.json"),
            boot_prompt: "begin",
        };
        let cmd =
            interactive_command(Backend::Claude, &launch).expect("claude backend builds a command");
        assert_eq!(cmd.get_program(), OsStr::new("claude"));
        let args: Vec<OsString> = cmd.get_args().map(OsStr::to_owned).collect();
        assert_eq!(
            args,
            vec![
                OsString::from("--name"),
                OsString::from("softfig-loop"),
                OsString::from("--settings"),
                OsString::from(loop_path),
                OsString::from("--mcp-config"),
                OsString::from(mcp_path),
            ]
        );
        // The argv stays byte-identical to the original hardwired invocation; the
        // cwd is now pinned to the garden (slice 005 auto-cd) rather than inherited,
        // so `growlight start` behaves the same from any directory.
        assert_eq!(cmd.get_current_dir(), Some(garden), "claude roots at the garden");
        assert!(
            !cmd.get_envs()
                .any(|(k, _)| k == OsStr::new("OPENCODE_CONFIG")),
            "claude must not set OPENCODE_CONFIG"
        );
    }

    /// The generator's inputs with the paths a given test doesn't care about
    /// already filled in, so each test states only what it is actually asserting.
    fn opencode_inputs<'a>(model: &'a str, variant: Option<&'a str>) -> OpencodeConfigInputs<'a> {
        OpencodeConfigInputs {
            agent_name: "softfig-loop",
            protocol: Path::new("/g/growlight/protocol.md"),
            baton: Path::new("/rt/baton.md"),
            context: "",
            runtime_root: Path::new("/rt"),
            mcp_bin: Path::new("/usr/bin/softfig-mcp"),
            claude_projects: Path::new("/home/u/.claude/projects"),
            opencode_data: Path::new("/home/u/.local/share/opencode"),
            model,
            variant,
        }
    }

    /// The emitted top-level rules as `action resource effect` lines.
    fn rule_lines(v: &Value) -> Vec<String> {
        v["permissions"]
            .as_array()
            .expect("top-level permissions is an array")
            .iter()
            .map(|r| {
                format!(
                    "{} {} {}",
                    r["action"].as_str().unwrap(),
                    r["resource"].as_str().unwrap(),
                    r["effect"].as_str().unwrap()
                )
            })
            .collect()
    }

    #[test]
    fn opencode_config_wires_agent_runtime_grant_mcp_and_model() {
        let cfg = opencode_config(&opencode_inputs("deepseek/deepseek-reasoner", None))
            .expect("generates");
        // Must be valid JSON that opencode can load (real-config validation is the
        // on-device check; here we assert structure).
        let v: Value = serde_json::from_str(&cfg).expect("generated opencode config is valid JSON");

        // Native 2.x keys only, never the v1 spellings opencode auto-translates.
        for v1 in ["agent", "permission"] {
            assert!(v.get(v1).is_none(), "v1 key `{v1}` emitted: {v}");
        }

        // The agent: primary, selectable as `softfig-loop`. The model is the
        // passed-in param (never inlined) at the TOP level, where opencode 2.x
        // honors it; the agent block's `model` is ignored on 2.x (slice 001 L7),
        // so it is not emitted there at all.
        let agent = &v["agents"]["softfig-loop"];
        assert_eq!(agent["mode"], "primary");
        // ...and selected by the config, not argv: the 2.x TUI has no `--agent`.
        assert_eq!(v["default_agent"], "softfig-loop");
        assert_eq!(v["model"], "deepseek/deepseek-reasoner");
        assert!(agent["model"].is_null(), "no dead agent-level model");
        // No variant declared → the bare id, no `#` suffix, leaving the model's own
        // default rather than pinning a guessed name.
        assert!(agent["variant"].is_null(), "v2 agent blocks have no variant key");

        // inject_baton: protocol reused BY REFERENCE (no duplicated text) + a
        // step-0 line naming the runtime baton path (the reseed bootstrap).
        let system = agent["system"].as_str().expect("system is a string");
        assert!(
            system.contains("{file:/g/growlight/protocol.md}"),
            "protocol must be pulled in by reference, not duplicated: {system}"
        );
        assert!(
            system.contains("STEP 0") && system.contains("/rt/baton.md"),
            "step-0 boot must name the baton path: {system}"
        );
        // §2b: usage.json is Claude's, so the override sits between the protocol
        // and step 0, where a session reads it before acting on the baton.
        let note = system.find(OPENCODE_BUDGET_NOTE).expect("budget override present");
        assert!(note > system.find("{file:").unwrap() && note < system.find("STEP 0").unwrap(), "{system}");

        // attach_mcp: explicit project-scoped softfig-mcp block, binary resolved
        // like the claude mcp.json (cwd-independent).
        let mcp = &v["mcp"]["servers"]["softfig-mcp"];
        assert_eq!(mcp["type"], "local");
        assert_eq!(mcp["command"][0], "/usr/bin/softfig-mcp");
    }

    #[test]
    fn opencode_config_carries_exactly_the_interactive_floor_at_top_level() {
        let cfg = opencode_config(&opencode_inputs(DEEPSEEK_FLASH, None)).expect("generates");
        let v: Value = serde_json::from_str(&cfg).expect("valid JSON");
        // Pinned in full: the order is the design (last match wins).
        // - The reset is `ask`, not deny: the global `~/projects/**`-style grants
        //   stop applying, and the human approves each outside directory instead.
        // - On 2.x the base is `* * allow`, so without the `edit` rules the loop
        //   would edit anything unasked. The garden guard (`edit * deny`) is back
        //   (slice 001 L3c); `edit /* ask` re-opens only ABSOLUTE resources (outside
        //   the garden cwd) to the human; the runtime root (the baton) and the memory
        //   tree are re-opened last.
        assert_eq!(
            rule_lines(&v),
            vec![
                "external_directory * ask",
                "external_directory /rt/** allow",
                "external_directory /home/u/.claude/projects/** allow",
                "external_directory /home/u/.local/share/opencode/shell/*/* allow",
                "external_directory /home/u/.local/share/opencode/tool-output/* allow",
                "read * allow",
                "read *.env ask",
                "read *.env.* ask",
                "read *.env.example allow",
                "shell * allow",
                "softfig-mcp* * allow",
                "edit * deny",
                "edit /* ask",
                "edit /rt/** allow",
                "edit /home/u/.claude/projects/** allow",
            ],
        );
        // Top level, NOT on the agent, so a subagent or a Tab to `build` cannot
        // step outside it.
        assert!(v["agents"]["softfig-loop"].get("permissions").is_none(), "{v}");
    }

    #[test]
    fn the_interactive_loop_reads_and_writes_memory() {
        // The human's 2026-10-10 call: interactive sessions read and write; only
        // fleet members are read-only. The floor's last rule re-opens the memory
        // tree, and the context carries both rule halves.
        assert_eq!(INTERACTIVE_MEMORY, MemoryPolicy::ReadWrite);
        let v: Value =
            serde_json::from_str(&opencode_config(&opencode_inputs(DEEPSEEK_FLASH, None)).unwrap())
                .unwrap();
        assert_eq!(
            rule_lines(&v).last().map(String::as_str),
            Some("edit /home/u/.claude/projects/** allow"),
        );

        let dir = std::env::temp_dir().join(format!("softfig-ctx-{}", std::process::id()));
        let garden = dir.join("garden");
        let projects = dir.join(".claude/projects");
        for f in ["CLAUDE.md", "growlight/memory-read.md", "growlight/memory-write.md"] {
            let p = garden.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x\n").unwrap();
        }
        let ctx = opencode_context(&garden, &projects).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        for f in ["CLAUDE.md", "growlight/memory-read.md", "growlight/memory-write.md"] {
            assert!(ctx.contains(&format!("{{file:{}}}", garden.join(f).display())), "{f}: {ctx}");
        }
    }

    #[test]
    fn the_context_lands_after_the_step_0_line() {
        let mut inputs = opencode_inputs(DEEPSEEK_FLASH, None);
        inputs.context = "Contents of `/g/CLAUDE.md` …:\n\n{file:/g/CLAUDE.md}";
        let v: Value = serde_json::from_str(&opencode_config(&inputs).unwrap()).unwrap();
        let system = v["agents"]["softfig-loop"]["system"].as_str().unwrap();
        assert!(system.ends_with("that reread IS the roll.\n\nContents of `/g/CLAUDE.md` …:\n\n{file:/g/CLAUDE.md}"), "{system}");
        // Empty context → the system prompt ends at step 0, no dangling blank lines.
        let v: Value =
            serde_json::from_str(&opencode_config(&opencode_inputs(DEEPSEEK_FLASH, None)).unwrap())
                .unwrap();
        assert!(v["agents"]["softfig-loop"]["system"].as_str().unwrap().ends_with("IS the roll."));
    }

    #[test]
    fn opencode_config_fails_closed_on_a_protocol_path_file_cannot_carry() {
        let mut inputs = opencode_inputs(DEEPSEEK_FLASH, None);
        inputs.protocol = Path::new("/g}/growlight/protocol.md");
        let err = opencode_config(&inputs).expect_err("a `}` would cut the {file:} short");
        assert!(err.to_string().starts_with("opencode session context: protocol "), "{err}");
    }

    #[test]
    fn opencode_config_fails_closed_on_an_unsafe_floor() {
        // A relative runtime root would render `edit rt/** allow`, which matches the
        // garden's own cwd-relative resources: a hole straight through the guard.
        let mut inputs = opencode_inputs(DEEPSEEK_FLASH, None);
        inputs.runtime_root = Path::new("rt");
        let err = opencode_config(&inputs).expect_err("a relative floor root is refused");
        assert!(err.to_string().contains("runtime_root"), "{err}");
    }

    #[test]
    fn opencode_interactive_command_wires_agent_config_env_and_garden_cwd() {
        use std::ffi::OsStr;
        let opencode_cfg = Path::new("/rt/opencode.json");
        let garden = Path::new("/home/u/garden");
        let launch = InteractiveLaunch {
            agent_name: "softfig-loop",
            // claude-only fields — the opencode arm must ignore them entirely.
            loop_settings: Path::new("/rt/loop.json"),
            mcp_config: Path::new("/rt/mcp.json"),
            garden_root: garden,
            opencode_config: opencode_cfg,
            boot_prompt: "Begin your growlight iteration.",
        };
        let cmd = interactive_command(Backend::Opencode, &launch)
            .expect("opencode backend builds a command");

        assert_eq!(cmd.get_program(), OsStr::new("opencode"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // A private server (`--standalone`: the shared service would ignore
        // OPENCODE_CONFIG, slice 001 finding 1) and the first-turn kick (the reseed
        // roll, since opencode has no SessionStart hook). No `--agent`: the 2.x TUI
        // refuses it (`unrecognized flag`); the config's `default_agent` selects
        // the generated agent instead.
        assert_eq!(
            args,
            vec![
                "--standalone",
                "--prompt",
                "Begin your growlight iteration."
            ]
        );
        assert!(!args.iter().any(|a| a == "--agent" || a == "--model"), "{args:?}");

        // The generated config is handed over via OPENCODE_CONFIG (opencode's
        // analog of claude's --settings), not a flag — and no --settings/
        // --mcp-config leaks through from the ignored claude fields.
        let opencode_env = cmd
            .get_envs()
            .find(|(k, _)| *k == OsStr::new("OPENCODE_CONFIG"))
            .and_then(|(_, v)| v)
            .map(|v| v.to_string_lossy().into_owned());
        assert_eq!(opencode_env.as_deref(), Some("/rt/opencode.json"));
        assert!(!args.iter().any(|a| a == "--settings" || a == "--mcp-config"));

        // cwd = the GARDEN (slice 006), so garden docs are ordinary in-project
        // reads. Both backends root here now; the baton is reached the other way,
        // via the external_directory grant in the generated config.
        assert_eq!(cmd.get_current_dir(), Some(garden));
    }

    #[test]
    fn opencode_config_emits_a_declared_variant_as_the_model_suffix() {
        // 2.x spells model + variant as one `provider/model#variant` string; an
        // agent-level `variant` key does not exist in the v2 schema.
        let cfg = opencode_config(&opencode_inputs(DEEPSEEK_FLASH, Some("high"))).expect("generates");
        let v: Value = serde_json::from_str(&cfg).expect("valid JSON");
        assert_eq!(v["model"], "deepseek/deepseek-flash#high");
        assert!(v["agents"]["softfig-loop"]["variant"].is_null());

        let choice = match parse_model_spec("flash variant=high").unwrap() {
            ModelSpec::Fixed(c) => c,
            ModelSpec::Auto => panic!("fixed spec"),
        };
        assert_eq!(choice.opencode_model_ref(), "deepseek/deepseek-flash#high");
        assert_eq!(
            ModelChoice::opencode(DEEPSEEK_REASONING).opencode_model_ref(),
            "deepseek/deepseek-v4-pro",
            "no variant → no trailing '#'",
        );
    }

    #[test]
    fn a_hash_in_a_model_spec_is_refused_so_the_suffix_stays_unambiguous() {
        // The variant has one home (`variant=`) and is rendered after a `#`, so an
        // id or variant carrying its own `#` could not be read back.
        let err = parse_model_spec("deepseek/deepseek-flash#high").unwrap_err().to_string();
        assert!(
            err.contains("deepseek/deepseek-flash variant=high"),
            "suggests the right spelling: {err}",
        );
        assert!(parse_model_spec("flash variant=hi#gh").is_err());
    }

    #[test]
    fn model_spec_parses_every_alias_and_the_passthrough() {
        let fixed = |s: &str| match parse_model_spec(s).unwrap() {
            ModelSpec::Fixed(c) => c,
            ModelSpec::Auto => panic!("`{s}` should not be auto"),
        };

        assert_eq!(fixed("claude"), ModelChoice::claude());
        // The human's 2026-08-08 call: "reasoning" is the pinned v4-pro, NOT the
        // floating `deepseek-reasoner` alias.
        assert_eq!(
            fixed("reasoning").model.as_deref(),
            Some("deepseek/deepseek-v4-pro")
        );
        assert_eq!(fixed("deepseek-reasoning"), fixed("reasoning"));
        // `deepseek-v4-flash` left opencode 2.x's catalog (slice 001 finding 12).
        assert_eq!(
            fixed("flash").model.as_deref(),
            Some("deepseek/deepseek-flash")
        );
        assert_eq!(fixed("deepseek-flash"), fixed("flash"));
        assert_eq!(fixed("Flash"), fixed("flash"), "aliases are case-insensitive");

        // An unrecognised `provider/model` passes through verbatim; a bare
        // unrecognised word is a typo, not a model.
        assert_eq!(
            fixed("deepseek/deepseek-chat").model.as_deref(),
            Some("deepseek/deepseek-chat")
        );
        assert!(parse_model_spec("gpt").is_err());
        assert!(parse_model_spec("").is_err());

        assert_eq!(parse_model_spec("auto").unwrap(), ModelSpec::Auto);
        assert!(
            parse_model_spec("auto variant=x").is_err(),
            "`auto` has no model of its own to vary"
        );
    }

    #[test]
    fn model_spec_carries_variant_on_opencode_and_drops_it_on_claude() {
        let opencode = match parse_model_spec("flash effort=high").unwrap() {
            ModelSpec::Fixed(c) => c,
            ModelSpec::Auto => unreachable!(),
        };
        // `effort=` is an accepted alias for opencode's one `variant` knob.
        assert_eq!(opencode.variant.as_deref(), Some("high"));
        assert_eq!(
            parse_model_spec("flash variant=high").unwrap(),
            ModelSpec::Fixed(opencode)
        );

        // claude's effort isn't settable from this launch path, so a variant on a
        // claude spec parses (no error for the human) but is not carried.
        let claude = match parse_model_spec("claude variant=high").unwrap() {
            ModelSpec::Fixed(c) => c,
            ModelSpec::Auto => unreachable!(),
        };
        assert_eq!(claude, ModelChoice::claude());

        assert!(parse_model_spec("flash speed=fast").is_err(), "unknown key");
        assert!(parse_model_spec("flash high").is_err(), "not key=value");
        assert!(
            parse_model_spec("flash variant=").is_err(),
            "an empty value is a typo, not `no variant`"
        );
    }

    #[test]
    fn item_model_field_reads_the_blockquote_declaration_only() {
        let doc = "# A slice\n\n\
                   > Last reviewed: 2026-08-08\n\
                   > Model: flash effort=high\n\n\
                   ## Do\n\nUse reasoning here? Model: claude — prose, not a declaration.\n";
        assert_eq!(item_model_field(doc), Some("flash effort=high"));
        assert_eq!(
            parse_model_spec(item_model_field(doc).unwrap()).unwrap(),
            parse_model_spec("flash variant=high").unwrap()
        );

        // No declaration → None (the caller falls back to the milestone doc, then
        // to flash). A bare `Model:` with nothing after it is not a declaration,
        // and a non-blockquote line never counts.
        assert_eq!(item_model_field("# A slice\n\n> Last reviewed: 2026-08-08\n"), None);
        assert_eq!(item_model_field("> Model:   \n"), None);
        assert_eq!(item_model_field("Model: flash\n"), None);
        // First declaration wins.
        assert_eq!(item_model_field("> Model: claude\n> Model: flash\n"), Some("claude"));
    }
}
