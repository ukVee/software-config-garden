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
use serde::Serialize;
use serde_json::Value;

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

/// The inputs an interactive launch needs, across backends. Each backend
/// consumes only the subset relevant to it (claude: the name, `loop_settings`,
/// and `mcp_config`; opencode: the name, `opencode_config`, `cwd`, and
/// `boot_prompt`), so the seam stays a single call while neither backend has to
/// fabricate the paths the other needs. Borrows throughout (the caller owns the
/// generated runtime paths); pure data, no I/O.
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
    /// garden edit-deny + explicit softfig-mcp block, slice 002). Ignored by
    /// claude.
    pub opencode_config: &'a Path,
    /// opencode launch cwd = the **runtime dir** (where the baton lives), NOT the
    /// garden. opencode makes the cwd its "project root" and matches in-project
    /// files by their project-relative path while gating everything outside it
    /// behind `external_directory`; rooting at the runtime dir keeps the baton
    /// in-project (freely read + rewritten each handoff) and the garden external
    /// (denied to raw edits, reachable only via softfig-mcp — see
    /// `opencode_config`). Ignored by claude (which inherits the caller's cwd,
    /// unchanged). softfig-mcp is attached explicitly, so it resolves regardless
    /// of cwd.
    pub cwd: &'a Path,
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
    /// - **claude** reproduces the original hardwired invocation exactly —
    ///   `claude --name <name> --settings <loop.json> --mcp-config <mcp.json>` —
    ///   inheriting the caller's environment and cwd (byte-identical to before
    ///   the seam existed: it sets neither env nor `current_dir`).
    /// - **opencode** launches the TUI on the generated agent —
    ///   `opencode --agent <name> --prompt <boot>` — with `OPENCODE_CONFIG`
    ///   pointing at the generated `opencode.json` (opencode's analog of claude's
    ///   `--settings`; the agent, its permission map, and the softfig-mcp block
    ///   all live in that one file, so there is no separate `--mcp-config`) and
    ///   cwd set to the runtime dir (`launch.cwd`) so the baton is in-project and
    ///   the garden is external — see [`InteractiveLaunch::cwd`]. The `--prompt`
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
                    .arg(launch.mcp_config);
            }
            Backend::Opencode => {
                cmd.arg("--agent")
                    .arg(launch.agent_name)
                    .arg("--prompt")
                    .arg(launch.boot_prompt)
                    .env("OPENCODE_CONFIG", launch.opencode_config)
                    .current_dir(launch.cwd);
            }
        }
        Ok(cmd)
    }
}

/// Generate the opencode-native equivalent of claude's `loop.json` + `mcp.json`:
/// an `opencode.json` (loaded via `OPENCODE_CONFIG=<path>` — opencode's analog of
/// claude's `--settings`) defining a `softfig-loop` **agent**. This carries the
/// three interactive legs of the seam for opencode (spec-agents §4.1 /
/// decision-semi-auto-backend-seam's mapping table): `inject_baton`,
/// `preapprove`, and `attach_mcp`. Pure (builds the string, never writes/spawns)
/// so it's unit-testable like the claude generators. Slice 003 wires the launch
/// that consumes it.
///
/// - **inject_baton (the reseed bootstrap).** opencode has no SessionStart hook,
///   so the roll can't re-cat a baton the way claude's `/clear` does. Instead the
///   agent's `prompt` = the garden `protocol.md` (pulled in by opencode's
///   `{file:…}` reference, so the protocol text is *reused*, never duplicated) +
///   a step-0 line naming the baton path. A fresh session (`/new` / relaunch)
///   rebuilds the system prompt → reloads the protocol → step 0 re-reads the
///   current baton. The protocol *is* the bootstrap.
/// - **preapprove.** Translates claude's `loop.json` allow/deny, shaped by three
///   on-device findings about opencode's permission model: (1) the `edit`
///   permission gates ALL file modification (the `write` + `apply_patch` tools
///   too); (2) it matches IN-project files (under cwd) by their project-RELATIVE
///   path and does NOT match an EXTERNAL file's absolute path, so an `edit` deny is
///   a no-op for anything outside cwd; and (3) a broad `*` deny is deny-overrides —
///   it beats every specific allow, so a `*` default-deny would also block the
///   loop's OWN baton rewrite. The launch roots opencode at the RUNTIME dir (see
///   `InteractiveLaunch::cwd`): the baton is in-project (freely read + rewritten at
///   opencode's default-allow), and the garden is external — guarded not by `edit`
///   but by `external_directory` (next bullet). `softfig-mcp*` is allowed so the
///   garden verbs don't prompt; `read`/`bash` mirror the claude allow-list (a
///   `bash` write into the garden stays possible — accepted, like claude's
///   Bash-allow posture).
/// - **external_directory (the garden guard).** cwd is the runtime dir, so the
///   garden, the code repos, and the claude-memory tree are all "external", and on
///   this opencode version external access is ALL-OR-NOTHING here (an `allow`
///   permits read AND write; there is no external read-only). So DENY the garden
///   outright: raw read/edit/write of the garden is refused and the agent reaches
///   garden content the only intended way — through softfig-mcp verbs (the
///   protocol's "everything else lives in the garden, read via softfig-mcp
///   pointers"). Grant the claude-memory tree so its pointers stay reachable +
///   editable. Surgical, never a bare `allow`: the `~/.claude` OAuth token +
///   harness settings stay out of reach, and code repos fall through to opencode's
///   default (the interactive human approves them per-prompt; unattended external
///   edits are the headless slice-004 concern).
/// - **attach_mcp.** Emits an explicit project-scoped `mcp.softfig-mcp` block
///   (mirroring why claude gets an explicit `--mcp-config`) so the garden verbs
///   exist regardless of launch cwd, without depending on the user's global
///   `~/.config/opencode` registration. The binary is resolved the same way as
///   the claude `mcp.json` (`softfig_mcp_path` — the sibling of the running exe).
/// - **model.** A DeepSeek id, held as a passed-in param (never inlined): until
///   the slice-005 picker/`--model` supplies it, the caller passes a default.
pub fn opencode_config(
    agent_name: &str,
    protocol: &Path,
    baton: &Path,
    garden_root: &Path,
    mcp_bin: &Path,
    model: &str,
    claude_projects: &Path,
) -> String {
    // The system prompt: the protocol by reference (opencode expands `{file:…}`
    // at prompt-build time — verified to resolve an absolute path) + the step-0
    // baton-boot line that makes every fresh session re-read the live baton.
    let prompt = format!(
        "{{file:{protocol}}}\n\n\
         STEP 0 (every session, first): Read your baton at `{baton}` and follow the \
         operating protocol above — the baton is your only carried state. opencode has \
         no SessionStart hook, so a fresh session (`/new` or a relaunch) re-reads the \
         baton here; that reread IS the roll.",
        protocol = protocol.display(),
        baton = baton.display(),
    );

    let garden_glob = format!("{}/**", garden_root.display());
    let memory_glob = format!("{}/**", claude_projects.display());

    // `external_directory` is the garden guard. Launched from the runtime dir
    // (cwd), the garden is EXTERNAL, and opencode gates external access here — and,
    // on this version, it is ALL-OR-NOTHING for external paths: an `external_
    // directory` allow permits read AND write, while the `edit` permission's
    // pattern (matched relative to cwd) does NOT match an external absolute path,
    // so an `edit` deny is a no-op for the garden (both proven on-device). So DENY
    // the garden outright: raw read/edit/write of the garden is refused, and the
    // agent reaches garden content the ONLY intended way — through softfig-mcp
    // verbs (the protocol's "everything else lives in the garden, read via
    // softfig-mcp pointers"). The claude-memory tree is granted so its pointers
    // stay reachable + editable. The baton + the rest of the runtime dir are
    // in-project (the cwd), so they need no grant — the loop reads and rewrites its
    // baton there freely. Surgical, never a bare `allow`: the ~/.claude OAuth token
    // + harness settings stay out of reach, and code repos fall through to
    // opencode's default (the interactive human approves them per-prompt). A `bash`
    // write into the garden stays possible — accepted, same as claude's Bash-allow.
    let mut external = serde_json::Map::new();
    external.insert(garden_glob, Value::from("deny"));
    external.insert(memory_glob, Value::from("allow"));

    let mut permission = serde_json::Map::new();
    permission.insert("read".to_string(), Value::from("allow"));
    permission.insert("bash".to_string(), Value::from("allow"));
    permission.insert("external_directory".to_string(), Value::Object(external));
    permission.insert("softfig-mcp*".to_string(), Value::from("allow"));

    let agent = serde_json::json!({
        "mode": "primary",
        "model": model,
        "prompt": prompt,
        "permission": Value::Object(permission),
    });
    let mut agents = serde_json::Map::new();
    agents.insert(agent_name.to_string(), agent);

    let v = serde_json::json!({
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "softfig-mcp": {
                "type": "local",
                "command": [ mcp_bin.display().to_string() ],
                "enabled": true,
            }
        },
        "agent": Value::Object(agents),
    });
    format!("{}\n", serde_json::to_string_pretty(&v).unwrap())
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

/// Budgets in the same shape the statusline tees to `usage.json` (§6), so
/// downstream loop code is backend-agnostic across semi-auto and full-auto.
#[derive(Serialize)]
pub struct UsageSnapshot {
    pub context_window: ContextWindow,
    pub rate_limits: RateLimits,
    /// Unix seconds, matching the statusline tee's `ts`.
    pub ts: f64,
}

#[derive(Serialize)]
pub struct ContextWindow {
    /// Derived: `round(100 * current_tokens / context_window_size)`, clamped to
    /// a saturating `0..=100` (0 when the window size is unknown). The clamp
    /// matters because `current_tokens` is cumulative — see its note — so the
    /// raw ratio can exceed 100 in a long session.
    pub used_percentage: u8,
    pub remaining_percentage: u8,
    pub context_window_size: u64,
    /// The token figure the percentage was derived from: `input + cache_read +
    /// cache_creation`. This is cumulative across the session (cache reads
    /// accrue per request), NOT the exact live prompt footprint, so it can run
    /// past `context_window_size` — hence the clamp on `used_percentage`.
    pub current_tokens: u64,
}

#[derive(Serialize, Default)]
pub struct RateLimits {
    pub five_hour: RateWindow,
    pub seven_day: RateWindow,
}

/// One rolling rate-limit window. Headless mode learns the `resets_at` time and
/// a coarse `status` ("allowed"/"warning"/"rejected") from the
/// `rate_limit_event`, but **not** a used-percentage — so the §6 full-auto
/// governor (slice 003) must key off `status`, not a number. `used_percentage`
/// stays `None` headlessly (and is omitted from `usage.json`).
#[derive(Serialize, Default)]
pub struct RateWindow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_percentage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

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
            context_window: derive_context(&result),
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

        let cw = &out.usage.context_window;
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
        assert_eq!(out.usage.context_window.context_window_size, 200_000);
        assert_eq!(out.usage.context_window.current_tokens, 100);
        assert_eq!(out.usage.context_window.used_percentage, 0); // round(0.05)
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
        assert_eq!(out.usage.context_window.context_window_size, 0);
        assert_eq!(out.usage.context_window.used_percentage, 0);
        assert_eq!(out.usage.context_window.remaining_percentage, 100);
    }

    #[test]
    fn cumulative_tokens_over_the_window_saturate_at_100_never_wrap() {
        // A long agentic run: cumulative input + cache totals (~3.93M) far
        // exceed a 1M window. The raw ratio is 393% — a bare `f64 as u8` would
        // saturate that to 255 (and a ~135% run would pass through as 135). The
        // clamp must floor it at exactly 100, with remaining 0.
        let over = r#"{"type":"result","is_error":false,"usage":{"input_tokens":30000,"cache_read_input_tokens":3800000,"cache_creation_input_tokens":100000},"modelUsage":{"claude-opus-4-8":{"contextWindow":1000000}}}"#;
        let out = parse_stream(over, 0.0).unwrap();
        let cw = &out.usage.context_window;
        assert_eq!(cw.current_tokens, 3_930_000);
        assert_eq!(cw.used_percentage, 100, "must saturate, never wrap to 255");
        assert_eq!(cw.remaining_percentage, 0);

        // A milder overshoot (1.35M / 1M = 135%) — the case `as u8` would have
        // let slip through unchanged — also floors at 100.
        let mild = r#"{"type":"result","usage":{"input_tokens":1350000},"modelUsage":{"m":{"contextWindow":1000000}}}"#;
        let mild_out = parse_stream(mild, 0.0).unwrap();
        assert_eq!(mild_out.usage.context_window.used_percentage, 100);
        assert_eq!(mild_out.usage.context_window.remaining_percentage, 0);
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
    fn claude_interactive_command_is_the_hardwired_argv() {
        use std::ffi::{OsStr, OsString};
        let loop_path = Path::new("/run/softfig/growlight/loop.json");
        let mcp_path = Path::new("/run/softfig/growlight/mcp.json");
        let launch = InteractiveLaunch {
            agent_name: "softfig-loop",
            loop_settings: loop_path,
            mcp_config: mcp_path,
            // opencode-only fields — the claude arm must ignore them entirely.
            opencode_config: Path::new("/run/softfig/growlight/opencode.json"),
            cwd: Path::new("/run/softfig/growlight"),
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
        // Byte-identical means the claude arm touches neither cwd nor env — it
        // inherits the caller's exactly as the original hardwired invocation did.
        assert!(cmd.get_current_dir().is_none(), "claude must not set cwd");
        assert!(
            !cmd.get_envs()
                .any(|(k, _)| k == OsStr::new("OPENCODE_CONFIG")),
            "claude must not set OPENCODE_CONFIG"
        );
    }

    #[test]
    fn opencode_config_wires_agent_garden_deny_mcp_and_model() {
        let cfg = opencode_config(
            "softfig-loop",
            Path::new("/g/growlight/protocol.md"),
            Path::new("/rt/baton.md"),
            Path::new("/g"),
            Path::new("/usr/bin/softfig-mcp"),
            "deepseek/deepseek-reasoner",
            Path::new("/home/u/.claude/projects"),
        );
        // Must be valid JSON that opencode can load (real-config validation is the
        // slice-002 on-device check; here we assert structure).
        let v: Value = serde_json::from_str(&cfg).expect("generated opencode config is valid JSON");

        // The agent: primary, DeepSeek model held as config (the passed-in param,
        // never inlined), selectable as `softfig-loop`.
        let agent = &v["agent"]["softfig-loop"];
        assert_eq!(agent["mode"], "primary");
        assert_eq!(agent["model"], "deepseek/deepseek-reasoner");

        // inject_baton: protocol reused BY REFERENCE (no duplicated text) + a
        // step-0 line naming the runtime baton path (the reseed bootstrap).
        let prompt = agent["prompt"].as_str().expect("prompt is a string");
        assert!(
            prompt.contains("{file:/g/growlight/protocol.md}"),
            "protocol must be pulled in by reference, not duplicated: {prompt}"
        );
        assert!(
            prompt.contains("STEP 0") && prompt.contains("/rt/baton.md"),
            "step-0 boot must name the baton path: {prompt}"
        );

        // preapprove: the garden is guarded by external_directory (below), NOT by
        // an `edit` entry — an `edit` deny is a no-op for external paths, and a `*`
        // default-deny would block the in-project baton rewrite. So there is no
        // `edit` key at all; in-project baton edits keep opencode's default (allow).
        assert!(agent["permission"]["edit"].is_null(), "no edit key (garden guarded via external_directory)");
        assert!(agent["permission"]["write"].is_null(), "no separate write key");
        assert_eq!(agent["permission"]["softfig-mcp*"], "allow");
        assert_eq!(agent["permission"]["read"], "allow");

        // external_directory (the garden guard): the garden is DENIED outright (raw
        // read/edit/write refused → garden reached only via softfig-mcp), and the
        // claude-memory tree is allowed. Nothing else granted, so code repos +
        // ~/.claude credentials stay gated. The baton is in-project (not listed).
        let ext = &agent["permission"]["external_directory"];
        assert_eq!(ext["/g/**"], "deny", "garden denied (MCP-only; no raw read/write)");
        assert_eq!(ext["/home/u/.claude/projects/**"], "allow", "memory reachable + editable");
        assert_eq!(ext.as_object().unwrap().len(), 2, "only the garden (deny) + memory (allow)");

        // attach_mcp: explicit project-scoped softfig-mcp block, binary resolved
        // like the claude mcp.json (cwd-independent).
        assert_eq!(v["mcp"]["softfig-mcp"]["type"], "local");
        assert_eq!(v["mcp"]["softfig-mcp"]["command"][0], "/usr/bin/softfig-mcp");
        assert_eq!(v["mcp"]["softfig-mcp"]["enabled"], true);
    }

    #[test]
    fn opencode_interactive_command_wires_agent_config_env_and_runtime_cwd() {
        use std::ffi::OsStr;
        let opencode_cfg = Path::new("/rt/opencode.json");
        let runtime = Path::new("/rt");
        let launch = InteractiveLaunch {
            agent_name: "softfig-loop",
            // claude-only fields — the opencode arm must ignore them entirely.
            loop_settings: Path::new("/rt/loop.json"),
            mcp_config: Path::new("/rt/mcp.json"),
            opencode_config: opencode_cfg,
            cwd: runtime,
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
        // Selects the generated primary agent + kicks the first turn (the reseed
        // roll, since opencode has no SessionStart hook).
        assert_eq!(
            args,
            vec![
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

        // cwd = the runtime dir (baton in-project, garden external — see
        // InteractiveLaunch::cwd), NOT the garden.
        assert_eq!(cmd.get_current_dir(), Some(runtime));
    }
}
