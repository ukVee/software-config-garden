//! growlight agent-backend seam (spec-growlight.md §12) + the headless `-p`
//! usage parser (§6, the full-auto budget read path).
//!
//! The full-auto orchestrator drives the agent by spawning a fresh process per
//! iteration (the fresh process *is* the context ROLL). To keep that driver
//! unit-testable without spawning Claude, every invocation goes through the
//! [`AgentBackend`] trait: [`ClaudeBackend`] shells `claude -p`, while tests use
//! a scripted fake. `claude` is never hardcoded into the loop logic — only into
//! [`ClaudeBackend`], so a future backend swaps in here.
//!
//! Headless budget read path (§6). The interactive loop tees budgets to
//! `usage.json` from the statusline; a headless `claude -p` has no statusline,
//! so budgets are parsed from its `--output-format stream-json` event stream by
//! the pure [`parse_stream`] instead. Two findings from probing Claude Code
//! 2.1.179 shape this:
//!   - plain `--output-format json` drops the `rate_limit_event`; only
//!     `stream-json` emits it, so the real backend uses `stream-json`.
//!   - the stream carries each rate window's reset time + a coarse `status`
//!     ("allowed"/…) but **no** used-percentage. Context % is derivable from
//!     the result's token totals ÷ the model's context window; rate-limit % is
//!     not available headlessly (see [`RateWindow`]).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use serde_json::Value;
use softfig_ipc::opencode::{
    Context as SessionContext, Floor, MemoryPolicy, Posture, context, file_ref, floor,
};

/// Which agent the human-driven semi-auto loop (`softfig growlight start`) runs
/// on — the CLI-side interactive-first landing of the AgentBackend seam
/// (spec-agents §4.1 / decision-semi-auto-backend-seam). `Claude` is
/// byte-for-byte identical to the original hardwired path; `Opencode` is being
/// wired up across the `semi-auto-backend-seam` milestone (generated config =
/// slice 002, interactive launch = slice 003, headless `--auto` = slice 004).
///
/// Distinct from the [`AgentBackend`] trait below: that is the headless `-p`
/// per-iteration seam the `--auto` driver shells; this enum is the CLI selector
/// that *chooses* which agent (and which interactive argv) to run. The fleet
/// (growlightd) has its own backend config and is intentionally untouched.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Backend {
    /// Claude Code (`claude`) — the default; behaviour unchanged.
    #[default]
    Claude,
    /// opencode — interactive-first; headless `--auto` deferred to slice 004.
    Opencode,
}

/// DeepSeek's reasoning model — picker option 2 / `--model reasoning`. The
/// version-pinned top-tier V4 rather than the floating `deepseek/deepseek-reasoner`
/// alias (the human's call, 2026-08-08, closing the slice-005 open sub-question),
/// so the loop's model can't move under it without a code change.
pub const DEEPSEEK_REASONING: &str = "deepseek/deepseek-v4-pro";

/// DeepSeek's fast model — picker option 3 / `--model flash`, and the fallback
/// whenever "let growlight decide" finds no `> Model:` declaration on the active
/// backlog item (cheap by default; reasoning is opt-in).
///
/// V4.1 Flash. The earlier `deepseek/deepseek-v4-flash` id is gone from opencode
/// 2.x's catalog (opencode-v2-repin slice 001, finding 12).
pub const DEEPSEEK_FLASH: &str = "deepseek/deepseek-flash";

/// A resolved interactive launch target: which backend, and (for opencode) which
/// model + variant to generate the agent config with.
///
/// `model`/`variant` are opencode-only. claude's model + effort are the harness's
/// own (there is no interactive flag for them), so a claude choice carries `None`
/// and a `variant=` on a claude spec is inert — see [`parse_model_spec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelChoice {
    pub backend: Backend,
    /// The opencode model id (`provider/model`), e.g. [`DEEPSEEK_FLASH`].
    pub model: Option<String>,
    /// The opencode agent's `variant` (opencode `AgentConfig.variant`: "default
    /// model variant for this agent") — the effort/variant knob a backlog item
    /// can declare alongside its model.
    pub variant: Option<String>,
}

impl ModelChoice {
    /// The claude backend: no model/variant of our choosing (the harness owns them).
    pub fn claude() -> Self {
        Self {
            backend: Backend::Claude,
            model: None,
            variant: None,
        }
    }

    /// The opencode backend on a given model id.
    pub fn opencode(model: &str) -> Self {
        Self {
            backend: Backend::Opencode,
            model: Some(model.to_string()),
            variant: None,
        }
    }

    /// The model id to generate the opencode config with, falling back to
    /// [`DEEPSEEK_FLASH`] for a choice that names none.
    pub fn opencode_model(&self) -> &str {
        self.model.as_deref().unwrap_or(DEEPSEEK_FLASH)
    }

    /// The model + variant as opencode 2.x spells one value:
    /// `provider/model`, or `provider/model#variant`. This is what the generated
    /// config's top-level `model` carries (see [`opencode_config`]).
    pub fn opencode_model_ref(&self) -> String {
        opencode_model_ref(self.opencode_model(), self.variant.as_deref())
    }
}

/// `provider/model` or `provider/model#variant`: opencode 2.x's one-string model
/// reference. 2.x has no separate variant key on an agent and no `--variant` flag;
/// the variant rides the `#` suffix, which opencode parses into
/// `{providerID, model, variant}` (checked against a private server's
/// `/api/config`, opencode-v2-repin slice 002).
fn opencode_model_ref(model: &str, variant: Option<&str>) -> String {
    match variant {
        Some(variant) => format!("{model}#{variant}"),
        None => model.to_string(),
    }
}

/// What a `--model` flag or a picker choice resolves to *before* the active
/// backlog item is consulted.
///
/// `Auto` is "let growlight decide": rather than guessing from the work's shape,
/// growlight reads the model the **active backlog item declares for itself** — the
/// optional `> Model: <spec>` line on its slice doc (falling back to the milestone
/// doc, then to [`DEEPSEEK_FLASH`]). The human writes the field when they queue the
/// work, where the judgement actually belongs; the launcher only obeys it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelSpec {
    /// Resolve from the active backlog item's declared `> Model:` field.
    Auto,
    /// A choice made outright, with no item lookup.
    Fixed(ModelChoice),
}

/// Parse a model spec — the shared grammar behind `--model <spec>`, the picker,
/// and a backlog item's `> Model:` line, so all three accept exactly the same
/// words. Pure.
///
/// `<token> [key=value …]` where `<token>` is one of:
///   - `claude` — the claude backend.
///   - `reasoning` / `deepseek-reasoning` → opencode on [`DEEPSEEK_REASONING`].
///   - `flash` / `deepseek-flash` → opencode on [`DEEPSEEK_FLASH`].
///   - `auto` → [`ModelSpec::Auto`] (only meaningful from the CLI/picker; an item
///     doc that declares `auto` would be circular, so callers treat it as absent).
///   - any `provider/model` id → opencode on that id verbatim (an escape hatch for
///     a model neither alias covers; opencode validates it at launch).
///
/// The optional `key=value` tail carries the effort/variant knob: `variant=<v>`
/// (or its alias `effort=<v>`) sets the opencode agent's `variant`. It is inert on
/// a `claude` spec — claude's effort isn't settable from this launch path — so it
/// parses without error and is simply not carried.
pub fn parse_model_spec(spec: &str) -> Result<ModelSpec> {
    let mut words = spec.split_whitespace();
    let Some(token) = words.next() else {
        bail!("empty model spec");
    };

    let mut variant: Option<String> = None;
    for pair in words {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("model spec: expected `key=value`, got `{pair}` in `{spec}`"))?;
        match key {
            // `effort` is accepted as an alias so the field reads naturally for
            // either mental model; both land on opencode's one `variant` knob.
            // An empty value is a typo, not "no variant" — emitting `"variant": ""`
            // would pin the agent to a nameless variant.
            "variant" | "effort" if value.is_empty() => {
                bail!("model spec: `{key}=` has no value in `{spec}`")
            }
            // The variant is rendered after a `#` (`provider/model#variant`), so
            // one carrying its own `#` could not be read back unambiguously.
            "variant" | "effort" if value.contains('#') => {
                bail!("model spec: `{key}={value}` contains '#' in `{spec}`")
            }
            "variant" | "effort" => variant = Some(value.to_string()),
            _ => bail!("model spec: unknown key `{key}` in `{spec}` (expected `variant=`)"),
        }
    }

    let mut choice = match token.to_ascii_lowercase().as_str() {
        "auto" => {
            if variant.is_some() {
                bail!("model spec: `auto` takes no `variant=` — declare it on the item instead");
            }
            return Ok(ModelSpec::Auto);
        }
        "claude" => ModelChoice::claude(),
        "reasoning" | "deepseek-reasoning" => ModelChoice::opencode(DEEPSEEK_REASONING),
        "flash" | "deepseek-flash" => ModelChoice::opencode(DEEPSEEK_FLASH),
        // A `#variant` suffix on the id is opencode's own spelling, but here the
        // variant has exactly one home (`variant=`), so the two cannot disagree.
        other if other.contains('#') => bail!(
            "model spec: `{token}` carries a '#variant' suffix — write it as \
             `{} variant={}` instead",
            token.split_once('#').map_or(token, |(m, _)| m),
            token.split_once('#').map_or("", |(_, v)| v),
        ),
        // A raw `provider/model` passthrough — anything else is a typo, not a model.
        other if other.contains('/') => ModelChoice::opencode(token),
        other => bail!(
            "unknown model `{other}` — expected claude | reasoning | flash | auto | provider/model"
        ),
    };
    // Inert on claude (the harness owns its effort), carried on opencode.
    if choice.backend == Backend::Opencode {
        choice.variant = variant;
    }
    Ok(ModelSpec::Fixed(choice))
}

/// Pull a backlog item's optional `> Model: <spec>` declaration out of its doc.
///
/// The field rides the same leading blockquote metadata block the item docs
/// already use for `> Last reviewed:` / `> Design:`, so declaring a model is one
/// line and needs no new file. Only a blockquote line counts — prose mentioning a
/// model can't be mistaken for a declaration — and the first one wins. Pure.
pub fn item_model_field(doc: &str) -> Option<&str> {
    doc.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix('>')?;
        let (key, value) = rest.trim().split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case("model")
            .then(|| value.trim())
            .filter(|v| !v.is_empty())
    })
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

impl Backend {
    /// The launcher binary name, for the spawn and user-facing messages.
    pub fn agent_bin(&self) -> &'static str {
        match self {
            Backend::Claude => "claude",
            Backend::Opencode => "opencode",
        }
    }

    /// Build the interactive loop command for this backend. Pure (constructs,
    /// never spawns) so the argv/env/cwd are unit-testable.
    ///
    /// - **claude** reproduces the original hardwired argv exactly —
    ///   `claude --name <name> --settings <loop.json> --mcp-config <mcp.json>` —
    ///   inheriting the caller's environment, and rooted at the garden
    ///   (`launch.garden_root`, slice 005's auto-cd) instead of wherever the human
    ///   invoked it from. It still sets no env.
    /// - **opencode** launches the TUI on the generated agent —
    ///   `opencode --standalone --agent <name> --prompt <boot>` (see
    ///   [`opencode_interactive_args`] for why `--standalone`) — with `OPENCODE_CONFIG`
    ///   pointing at the generated `opencode.json` (opencode's analog of claude's
    ///   `--settings`; the agent, its permission map, and the softfig-mcp block
    ///   all live in that one file, so there is no separate `--mcp-config`) and
    ///   cwd set to the **garden** (`launch.garden_root`) — the same root claude
    ///   gets — so garden docs are ordinary in-project reads; see
    ///   [`InteractiveLaunch::garden_root`]. The `--prompt`
    ///   is the reseed kick: opencode has no SessionStart hook, so the roll is the
    ///   agent prompt's step-0 baton read, and this first turn nudges the fresh
    ///   session into it.
    pub fn interactive_command(&self, launch: &InteractiveLaunch) -> Result<Command> {
        let mut cmd = Command::new(self.agent_bin());
        match self {
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
                cmd.args(opencode_interactive_args(launch.agent_name))
                    .arg("--prompt")
                    .arg(launch.boot_prompt)
                    .env("OPENCODE_CONFIG", launch.opencode_config)
                    .current_dir(launch.garden_root);
            }
        }
        Ok(cmd)
    }
}

/// The interactive opencode argv up to (not including) the first-turn `--prompt`:
/// `--standalone --agent <name>`. Shared by the real launch and the `--no-launch`
/// hint, so the command a human copy-pastes cannot lose a flag the launcher has.
///
/// `--standalone` is a correctness flag on opencode 2.x, not hygiene. Without it
/// the TUI attaches to the per-user shared service, and a running one **ignores
/// the client's `OPENCODE_CONFIG`** (opencode-v2-repin slice 001, finding 1): the
/// session silently becomes the built-in `build` agent, with no protocol prompt,
/// no baton boot, allow-all permissions and every global grant. `--standalone`
/// gives the session a private server that loads this launch's config and exits
/// with it.
pub fn opencode_interactive_args(agent_name: &str) -> [&str; 3] {
    ["--standalone", "--agent", agent_name]
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
    // at config load — verified to resolve an absolute path) + the step-0
    // baton-boot line that makes every fresh session re-read the live baton +
    // the session context.
    let mut system = format!(
        "{protocol}\n\n\
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

/// What the driver hands a backend for one iteration: the generated loop
/// settings (whose SessionStart hook injects protocol + baton — confirmed to
/// fire under `-p`), the generated MCP config that *attaches* `softfig-mcp`
/// (the settings file only *permits* it — without this the garden verbs don't
/// exist and the agent can't advance the baton, regardless of cwd), and the
/// kick prompt that starts the turn.
pub struct IterationRequest {
    pub settings: PathBuf,
    pub mcp_config: PathBuf,
    pub prompt: String,
}

/// One iteration's backend-agnostic outcome.
pub struct IterationOutcome {
    /// The agent reported `is_error` on its terminal result event.
    pub is_error: bool,
    /// The agent's final result text, if the run produced one.
    pub result_text: Option<String>,
    /// Budgets parsed from the run, in the persisted `usage.json` shape.
    pub usage: UsageSnapshot,
}

/// The agent backend seam (§12). Swapping a future backend touches only this
/// impl, never the driver.
pub trait AgentBackend {
    /// Run exactly one headless iteration and return its parsed outcome.
    fn run_iteration(&self, req: &IterationRequest) -> Result<IterationOutcome>;
}

/// The `usage.json` shape — defined once in [`softfig_ipc::usage`] and re-exported
/// here, because this driver is only one of its writers: the interactive
/// statusline and (task 048) growlightd's headless capture write the same file, and
/// a per-writer copy of the shape is exactly how those three drift apart. See that
/// module for what a reading may and may not claim.
pub use softfig_ipc::usage::{ContextWindow, RateLimits, RateWindow, UsageSnapshot};

/// Parse a `claude -p --output-format stream-json` event stream (newline-
/// delimited JSON) into an [`IterationOutcome`]. Pure — no process spawn — so
/// the budget read path is unit-tested without Claude. Also accepts a plain
/// `--output-format json` single object (one line, no rate events).
///
/// Extracts the `rate_limit_event`(s) → [`RateLimits`] and the terminal
/// `result` event → `is_error`, result text, and the context window (token
/// totals ÷ `modelUsage.<model>.contextWindow`).
pub fn parse_stream(stream: &str, now_unix: f64) -> Result<IterationOutcome> {
    let mut rate_limits = RateLimits::default();
    let mut result_event: Option<Value> = None;

    for line in stream.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip non-JSON lines defensively; stdout should be pure events.
        let Ok(ev) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match ev.get("type").and_then(Value::as_str) {
            Some("rate_limit_event") => apply_rate_limit_event(&mut rate_limits, &ev),
            Some("result") => result_event = Some(ev),
            _ => {}
        }
    }

    let result = result_event.ok_or_else(|| {
        anyhow!(
            "no terminal `result` event in claude -p output ({} byte(s) seen)",
            stream.len()
        )
    })?;

    Ok(IterationOutcome {
        is_error: result
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        result_text: result
            .get("result")
            .and_then(Value::as_str)
            .map(str::to_string),
        usage: UsageSnapshot {
            context_window: Some(derive_context(&result)),
            rate_limits,
            ts: now_unix,
        },
    })
}

/// Route a `rate_limit_event` into the matching window (reset time + status).
fn apply_rate_limit_event(rate: &mut RateLimits, ev: &Value) {
    let Some(info) = ev.get("rate_limit_info") else {
        return;
    };
    let window = match info.get("rateLimitType").and_then(Value::as_str) {
        Some("five_hour") => &mut rate.five_hour,
        Some("seven_day") => &mut rate.seven_day,
        _ => return,
    };
    if let Some(resets_at) = info.get("resetsAt").and_then(Value::as_i64) {
        window.resets_at = Some(resets_at);
    }
    if let Some(status) = info.get("status").and_then(Value::as_str) {
        window.status = Some(status.to_string());
    }
}

/// Derive context-window occupancy from a terminal `result` event: the prompt
/// footprint (`input + cache_read + cache_creation` tokens) over the model's
/// `contextWindow`.
fn derive_context(result: &Value) -> ContextWindow {
    let usage = result.get("usage");
    let tok = |k: &str| {
        usage
            .and_then(|u| u.get(k))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let current_tokens =
        tok("input_tokens") + tok("cache_read_input_tokens") + tok("cache_creation_input_tokens");

    // Window size = the largest `contextWindow` across modelUsage entries
    // (normally a single model).
    let context_window_size = result
        .get("modelUsage")
        .and_then(Value::as_object)
        .map(|m| {
            m.values()
                .filter_map(|v| v.get("contextWindow").and_then(Value::as_u64))
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0);

    // `current_tokens` is cumulative (input + every cache read across the
    // session), so the ratio can legitimately exceed the window in a long run —
    // the percentage is occupancy-ish, not an exact live footprint (spec §6).
    // Clamp to a saturating 0..=100 floor BEFORE the cast: a bare `f64 as u8`
    // saturates huge values to 255 and passes 101..=255 straight through (e.g.
    // 135), either of which reads as garbage to the governor. The else branch
    // keeps an unknown window at 0 — we never coerce a present over-100 into a
    // misleading wrapped number, nor an unknown into a false reading here.
    let used_percentage = if context_window_size > 0 {
        (((current_tokens as f64 / context_window_size as f64) * 100.0).round()).clamp(0.0, 100.0)
            as u8
    } else {
        0
    };

    ContextWindow {
        used_percentage,
        remaining_percentage: 100u8.saturating_sub(used_percentage),
        context_window_size,
        current_tokens,
    }
}

/// Now as Unix seconds (matches the statusline `usage.json` `ts`).
pub fn unix_now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// A wall-clock seam so the between-iteration budget governor's "wait until the
/// rate-limit window resets" is unit-testable without real sleeps — mirrors the
/// [`AgentBackend`] seam. The production [`SystemClock`] sleeps the thread; tests
/// use a fake that records the requested wake times and advances virtual time.
pub trait Clock {
    /// Current wall time, Unix seconds.
    fn now_unix(&self) -> i64;
    /// Block until `unix` (Unix seconds); a no-op if already at/after it.
    fn sleep_until(&self, unix: i64);
}

/// The production clock: real time, real sleeps.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn sleep_until(&self, unix: i64) {
        let now = self.now_unix();
        if unix > now {
            std::thread::sleep(std::time::Duration::from_secs((unix - now) as u64));
        }
    }
}

/// Identity of an on-disk binary, for the stale-orchestrator guard (task 007).
/// A reinstall replaces the file at the launch path with a fresh inode (and
/// typically a new mtime/size), so any change here means the long-lived `--auto`
/// orchestrator is now executing superseded code. Compared by value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeIdentity {
    pub dev: u64,
    pub ino: u64,
    pub mtime: i64,
    pub size: u64,
}

/// A seam for "what binary is on disk at my launch path right now", so the
/// stale-orchestrator guard is unit-testable without a real reinstall — mirrors
/// the [`Clock`] / [`AgentBackend`] seams. The production [`SystemExeProbe`]
/// re-stats the path captured from `current_exe()` at startup; tests use a fake
/// that flips identity on cue.
pub trait ExeProbe {
    /// The identity of the binary on disk at the orchestrator's launch path, or
    /// `None` if it can't be determined — a missing reading must never trip the
    /// guard, so an un-stattable path simply disables it (never a false stop).
    fn current_identity(&self) -> Option<ExeIdentity>;
}

/// The production probe: re-stat the launch path captured once at startup.
///
/// The path is taken from `current_exe()` *before* any reinstall and then
/// re-statted each iteration — we must not call `current_exe()` again, because
/// once the running file is replaced `/proc/self/exe` reads back
/// `…/softfig (deleted)`, which would never match the new on-disk file.
pub struct SystemExeProbe {
    path: Option<PathBuf>,
}

impl SystemExeProbe {
    /// Capture the running binary's launch path now (resolved via
    /// `current_exe()`) for later re-stat. Infallible: an unresolvable path is
    /// stored as `None`, which disables the guard rather than failing the loop.
    pub fn capture() -> Self {
        Self {
            path: std::env::current_exe().ok(),
        }
    }
}

impl ExeProbe for SystemExeProbe {
    fn current_identity(&self) -> Option<ExeIdentity> {
        self.path.as_deref().and_then(stat_identity)
    }
}

/// Stat a path into an [`ExeIdentity`] (Unix dev/ino/mtime/size); `None` if it
/// can't be statted. Pure-ish (filesystem read only) so the production probe and
/// its test are both thin.
fn stat_identity(path: &Path) -> Option<ExeIdentity> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(ExeIdentity {
        dev: m.dev(),
        ino: m.ino(),
        mtime: m.mtime(),
        size: m.size(),
    })
}

/// The supported backend: shell out to Claude Code in headless single-shot mode.
pub struct ClaudeBackend {
    bin: String,
}

impl ClaudeBackend {
    pub fn new(bin: &str) -> Self {
        Self {
            bin: bin.to_string(),
        }
    }
}

impl AgentBackend for ClaudeBackend {
    fn run_iteration(&self, req: &IterationRequest) -> Result<IterationOutcome> {
        // SessionStart (confirmed to fire under `-p`) injects protocol + baton
        // via the same generated `--settings`; `--mcp-config` *attaches*
        // softfig-mcp so the garden verbs actually exist under `-p` (the
        // settings allow-list alone can't conjure an unregistered server);
        // `stream-json --verbose` is required to surface the `rate_limit_event`
        // (plain `json` drops it).
        let output = Command::new(&self.bin)
            .arg("-p")
            .arg(&req.prompt)
            .arg("--settings")
            .arg(&req.settings)
            .arg("--mcp-config")
            .arg(&req.mcp_config)
            .arg("--output-format")
            .arg("stream-json")
            .arg("--verbose")
            .output()
            .with_context(|| format!("failed to launch `{} -p` — is it on PATH?", self.bin))?;
        if !output.status.success() {
            bail!(
                "`{} -p` exited with {}: {}",
                self.bin,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        parse_stream(&String::from_utf8_lossy(&output.stdout), unix_now_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A realistic stream-json run: init + assistant + a five_hour rate event +
    // the terminal result (token totals + the model's context window).
    const STREAM: &str = r#"
{"type":"system","subtype":"init","model":"claude-opus-4-8"}
{"type":"assistant","message":{"role":"assistant"}}
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","resetsAt":1781666400,"rateLimitType":"five_hour"}}
{"type":"result","subtype":"success","is_error":false,"result":"OK","usage":{"input_tokens":2539,"cache_read_input_tokens":7891,"cache_creation_input_tokens":1930},"modelUsage":{"claude-opus-4-8":{"contextWindow":1000000}}}
"#;

    #[test]
    fn parse_stream_extracts_context_and_rate_limits() {
        let out = parse_stream(STREAM, 123.0).unwrap();
        assert!(!out.is_error);
        assert_eq!(out.result_text.as_deref(), Some("OK"));

        let cw = out
            .usage
            .context_window
            .as_ref()
            .expect("a result line carries a context window");
        assert_eq!(cw.context_window_size, 1_000_000);
        assert_eq!(cw.current_tokens, 2539 + 7891 + 1930); // 12_360
        assert_eq!(cw.used_percentage, 1); // round(1.236)
        assert_eq!(cw.remaining_percentage, 99);

        let five = &out.usage.rate_limits.five_hour;
        assert_eq!(five.resets_at, Some(1781666400));
        assert_eq!(five.status.as_deref(), Some("allowed"));
        // No seven_day event in this run.
        assert!(out.usage.rate_limits.seven_day.resets_at.is_none());
        assert!(out.usage.rate_limits.seven_day.status.is_none());
        assert_eq!(out.usage.ts, 123.0);
    }

    #[test]
    fn parse_stream_accepts_plain_json_single_result_without_rate_events() {
        let single = r#"{"type":"result","is_error":false,"result":"hi","usage":{"input_tokens":100},"modelUsage":{"m":{"contextWindow":200000}}}"#;
        let out = parse_stream(single, 0.0).unwrap();
        assert_eq!(out.usage.context_window.as_ref().unwrap().context_window_size, 200_000);
        assert_eq!(out.usage.context_window.as_ref().unwrap().current_tokens, 100);
        assert_eq!(out.usage.context_window.as_ref().unwrap().used_percentage, 0); // round(0.05)
        // No rate_limit_event → windows stay empty.
        assert!(out.usage.rate_limits.five_hour.resets_at.is_none());
        assert!(out.usage.rate_limits.five_hour.status.is_none());
    }

    #[test]
    fn parse_stream_errors_without_a_result_event() {
        let err = parse_stream("{\"type\":\"system\"}\n{\"type\":\"assistant\"}\n", 0.0);
        assert!(err.is_err());
    }

    #[test]
    fn unknown_window_size_yields_zero_percent_not_a_panic() {
        let no_window = r#"{"type":"result","is_error":true,"usage":{"input_tokens":50}}"#;
        let out = parse_stream(no_window, 0.0).unwrap();
        assert!(out.is_error);
        assert_eq!(out.usage.context_window.as_ref().unwrap().context_window_size, 0);
        assert_eq!(out.usage.context_window.as_ref().unwrap().used_percentage, 0);
        assert_eq!(out.usage.context_window.as_ref().unwrap().remaining_percentage, 100);
    }

    #[test]
    fn cumulative_tokens_over_the_window_saturate_at_100_never_wrap() {
        // A long agentic run: cumulative input + cache totals (~3.93M) far
        // exceed a 1M window. The raw ratio is 393% — a bare `f64 as u8` would
        // saturate that to 255 (and a ~135% run would pass through as 135). The
        // clamp must floor it at exactly 100, with remaining 0.
        let over = r#"{"type":"result","is_error":false,"usage":{"input_tokens":30000,"cache_read_input_tokens":3800000,"cache_creation_input_tokens":100000},"modelUsage":{"claude-opus-4-8":{"contextWindow":1000000}}}"#;
        let out = parse_stream(over, 0.0).unwrap();
        let cw = out.usage.context_window.as_ref().unwrap();
        assert_eq!(cw.current_tokens, 3_930_000);
        assert_eq!(cw.used_percentage, 100, "must saturate, never wrap to 255");
        assert_eq!(cw.remaining_percentage, 0);

        // A milder overshoot (1.35M / 1M = 135%) — the case `as u8` would have
        // let slip through unchanged — also floors at 100.
        let mild = r#"{"type":"result","usage":{"input_tokens":1350000},"modelUsage":{"m":{"contextWindow":1000000}}}"#;
        let mild_out = parse_stream(mild, 0.0).unwrap();
        assert_eq!(mild_out.usage.context_window.as_ref().unwrap().used_percentage, 100);
        assert_eq!(mild_out.usage.context_window.as_ref().unwrap().remaining_percentage, 0);
    }

    #[test]
    fn stat_identity_distinguishes_a_replaced_file_and_matches_a_stable_one() {
        // A reinstall replaces the file at the same path with a new inode/size.
        // We simulate that by overwriting a temp file with different content and
        // asserting the identity changes — no real `softfig` reinstall needed.
        let dir = std::env::temp_dir().join(format!("softfig-exeid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bin");

        std::fs::write(&path, b"v1").unwrap();
        let a = stat_identity(&path).expect("stat v1");
        // Same file, re-statted → identical identity (the guard must NOT trip).
        assert_eq!(stat_identity(&path).as_ref(), Some(&a));

        // Replace the file (drop + recreate → new inode/size, like a reinstall).
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"v2-longer").unwrap();
        let b = stat_identity(&path).expect("stat v2");
        assert_ne!(a, b, "a replaced file must read a different identity");

        assert!(stat_identity(&dir.join("does-not-exist")).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn usage_serializes_to_the_usage_json_shape_omitting_unknown_rate_percentages() {
        let out = parse_stream(STREAM, 7.0).unwrap();
        let v = serde_json::to_value(&out.usage).unwrap();
        // Context window keys the downstream budget read path expects.
        assert!(v["context_window"]["used_percentage"].is_number());
        assert_eq!(v["context_window"]["context_window_size"], 1_000_000);
        // five_hour carries reset + status, but NOT a used_percentage headlessly.
        assert_eq!(v["rate_limits"]["five_hour"]["resets_at"], 1781666400i64);
        assert_eq!(v["rate_limits"]["five_hour"]["status"], "allowed");
        assert!(v["rate_limits"]["five_hour"]["used_percentage"].is_null());
        assert!(v["ts"].is_number());
    }

    #[test]
    fn claude_backend_is_the_default() {
        assert_eq!(Backend::default(), Backend::Claude);
    }

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
        let cmd = Backend::Claude
            .interactive_command(&launch)
            .expect("claude backend builds a command");
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
        let cmd = Backend::Opencode
            .interactive_command(&launch)
            .expect("opencode backend builds a command");

        assert_eq!(cmd.get_program(), OsStr::new("opencode"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // A private server (`--standalone`: the shared service would ignore
        // OPENCODE_CONFIG, slice 001 finding 1), the generated primary agent, and
        // the first-turn kick (the reseed roll, since opencode has no SessionStart
        // hook).
        assert_eq!(
            args,
            vec![
                "--standalone",
                "--agent",
                "softfig-loop",
                "--prompt",
                "Begin your growlight iteration."
            ]
        );

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
