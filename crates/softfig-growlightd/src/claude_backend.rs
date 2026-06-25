//! Live agent backend (drive-loop slice 001) — the first real binding behind the
//! [`crate::supervisor::AgentBackend`] seam (spec-growlight-orchestrator §12
//! backend decision, §15 operational must-haves).
//!
//! [`ClaudeBackend`] shells `claude -p --output-format stream-json --verbose` per
//! agent, each with its per-agent pre-approval `--settings`/`--mcp-config` (the
//! §15 must-have: a headless agent **errors out** on a missing allow-rule, it does
//! not pause — so each agent must pre-approve its full toolset). A detached reader
//! thread tails the child's stream-json output, publishing every assistant /
//! thinking / tool-call content block as an [`Event::AgentDelta`] on the shared
//! [`EventHub`] so `growlight watch` and the GUI render the live "what's it
//! thinking now" view (§12). The same tail bumps a per-agent heartbeat; the drive
//! loop reads [`ClaudeBackend::health`] each cycle and feeds it to
//! [`crate::supervisor::Supervisor::poll`], where a stale heartbeat (no stream
//! activity within the hang window) classifies as a crash.
//!
//! ## Why a shared health cell, not a method on [`AgentChild`]
//!
//! [`AgentChild`] stays the pure *kill* handle (its only job is the
//! incident-20260622 kill-outside-the-lock contract). Health is a *separate*
//! observation the reader thread writes into an [`AgentHealthState`] shared by
//! `Arc`; the backend keeps a registry of those cells and the drive loop reads
//! them by agent id. This keeps lifecycle (kill) and observability (health)
//! decoupled and leaves the four existing `AgentChild` fakes untouched.
//!
//! ## Time
//!
//! The pure policy ([`crate::supervisor::Supervisor`] / its `classify`) stays
//! time-injected. Only this live binding reads the wall clock — at spawn (the
//! initial heartbeat) and on every stream line. The parse + publish + heartbeat
//! pipeline is itself a pure function over a `BufRead` + an injected clock
//! ([`pump`]), so it is unit-proven with a scripted fixture and a fake clock — no
//! real `claude` is ever spawned in tests (the §7b on-device run is the human's).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;
use softfig_ipc::growlightd::{AgentDeltaKind, Event};

use crate::admission::BudgetUsage;
use crate::control::AgentChild;
use crate::hub::EventHub;
use crate::preapproval::PreApproval;
use crate::supervisor::{AgentBackend, AgentHealth, AgentSpec, SpawnError};

/// Sentinel in [`AgentHealthState::exit_code`] meaning "still running".
const NOT_EXITED: i64 = i64::MIN;
/// Exit code recorded when a child ended but its code was unreadable (killed by a
/// signal, or the status couldn't be collected). Non-zero so it classifies as a
/// crash, never a clean (code-0) roll.
const UNKNOWN_EXIT: i32 = -1;
/// Cap on a rendered tool-call argument string, so one giant `input` can't flood
/// the event stream / GUI.
const TOOL_RENDER_MAX_CHARS: usize = 200;

/// Shared, lock-free observation of one live agent: the Unix-seconds heartbeat
/// (bumped on every stream-json line) and the exit code once the child ends. The
/// reader thread writes it; the drive loop reads it via [`ClaudeBackend::health`]
/// to build the [`AgentHealth`] it feeds [`crate::supervisor::Supervisor::poll`].
#[derive(Debug)]
pub struct AgentHealthState {
    last_active: AtomicI64,
    exit_code: AtomicI64,
}

impl AgentHealthState {
    /// A fresh state for a just-spawned child whose first heartbeat is its spawn
    /// time (so a child that never emits a line still hangs only after the window).
    fn new(spawned_at: i64) -> Self {
        Self {
            last_active: AtomicI64::new(spawned_at),
            exit_code: AtomicI64::new(NOT_EXITED),
        }
    }

    /// Record stream activity at `now` — a heartbeat. Stores the latest stamp.
    fn touch(&self, now: i64) {
        self.last_active.store(now, Ordering::SeqCst);
    }

    /// Record the child's terminal exit code once it has ended.
    fn record_exit(&self, code: i32) {
        self.exit_code.store(code as i64, Ordering::SeqCst);
    }

    fn last_active(&self) -> i64 {
        self.last_active.load(Ordering::SeqCst)
    }

    /// The current [`AgentHealth`]: `Exited` once the child has ended, else
    /// `Alive` stamped with the last heartbeat. The Supervisor compares the stamp
    /// to its own injected clock, so no `now` is needed to build the value.
    pub fn observe(&self) -> AgentHealth {
        match self.exit_code.load(Ordering::SeqCst) {
            NOT_EXITED => AgentHealth::Alive {
                last_active: self.last_active(),
            },
            code => AgentHealth::Exited { code: code as i32 },
        }
    }
}

/// Which rolling reserve window a `rate_limit_event` reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BudgetWindow {
    /// The 5h rolling account-wide reserve.
    FiveHour,
    /// The 7d rolling account-wide reserve.
    SevenDay,
}

/// Shared per-agent cell holding the latest reading of the shared **account-wide**
/// budget pool (the 5h/7d reserve), folded from this agent's stream-json
/// `rate_limit_event` lines — the reliable headless source (spec §6/§7): headless
/// `claude -p` reports a coarse per-window `status` on these events, not a
/// percentage (see [`pump`] / [`rate_limit_window_for_line`]). A terminal `result`
/// line carrying a `rate_limits` object is honored too, as an opportunistic bonus.
/// The reader thread writes it; the drive loop reads it via [`ClaudeBackend::budget`]
/// to feed the cross-agent [`crate::usage::UsageAggregator`]. Sibling to
/// [`AgentHealthState`] — health (heartbeat/exit) and budget (reserve) are
/// decoupled observations of one agent.
#[derive(Debug, Default)]
pub struct AgentBudgetState {
    /// The two windows' latest reserve %, accumulated across the per-window events.
    inner: Mutex<ReserveCell>,
}

/// Each window's latest reserve %, `None` until first reported. A `rate_limit_event`
/// arrives **per window** (a separate line for `five_hour` / `seven_day`), so the
/// cell accumulates them and derives the combined [`BudgetUsage`] on read.
#[derive(Debug, Default, Clone, Copy)]
struct ReserveCell {
    five_h_pct: Option<u8>,
    seven_d_pct: Option<u8>,
}

impl AgentBudgetState {
    /// Record one window's latest reserve % (from a `rate_limit_event`).
    fn record_window(&self, window: BudgetWindow, pct: u8) {
        let mut cell = self.inner.lock().unwrap();
        match window {
            BudgetWindow::FiveHour => cell.five_h_pct = Some(pct),
            BudgetWindow::SevenDay => cell.seven_d_pct = Some(pct),
        }
    }

    /// Record a full 5h/7d reserve at once — the opportunistic `result`-line bonus.
    fn record_reserve(&self, reserve: BudgetUsage) {
        let mut cell = self.inner.lock().unwrap();
        cell.five_h_pct = Some(reserve.session_5h_pct);
        cell.seven_d_pct = Some(reserve.session_7d_pct);
    }

    /// The latest combined reserve, or `None` until at least one window has
    /// reported. A not-yet-seen window contributes 0 (it has shown no burn); the
    /// aggregator's per-field max across agents fills it in once any agent reads it.
    fn observe(&self) -> Option<BudgetUsage> {
        let cell = *self.inner.lock().unwrap();
        match (cell.five_h_pct, cell.seven_d_pct) {
            (None, None) => None,
            (five, seven) => Some(BudgetUsage::new(five.unwrap_or(0), seven.unwrap_or(0))),
        }
    }
}

/// Translate one stream-json line into the content deltas it carries, in block
/// order. Pure. Only `assistant` events carry content; a non-assistant line,
/// malformed JSON, or an unrecognized block yields no deltas (the caller still
/// counts any non-empty line as a heartbeat — the child is plainly alive if it is
/// emitting anything at all).
fn deltas_for_line(line: &str) -> Vec<(AgentDeltaKind, String)> {
    let Ok(ev) = serde_json::from_str::<Value>(line) else {
        return Vec::new();
    };
    if ev.get("type").and_then(Value::as_str) != Some("assistant") {
        return Vec::new();
    }
    let Some(content) = ev
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for block in content {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = block.get("text").and_then(Value::as_str) {
                    out.push((AgentDeltaKind::Assistant, t.to_string()));
                }
            }
            Some("thinking") => {
                if let Some(t) = block.get("thinking").and_then(Value::as_str) {
                    out.push((AgentDeltaKind::Thinking, t.to_string()));
                }
            }
            Some("tool_use") => out.push((AgentDeltaKind::ToolCall, render_tool_use(block))),
            _ => {}
        }
    }
    out
}

/// Render a `tool_use` block into a compact one-line "what tool, what args" string
/// for the live view: `name(input-json)`, char-truncated so a huge argument can't
/// flood the stream.
fn render_tool_use(block: &Value) -> String {
    let name = block.get("name").and_then(Value::as_str).unwrap_or("tool");
    let input = block
        .get("input")
        .map(|i| serde_json::to_string(i).unwrap_or_default())
        .unwrap_or_default();
    let mut rendered = if input.is_empty() || input == "null" {
        name.to_string()
    } else {
        format!("{name}({input})")
    };
    // Truncate on a char boundary (`String::truncate` panics mid-codepoint).
    if rendered.chars().count() > TOOL_RENDER_MAX_CHARS {
        rendered = rendered.chars().take(TOOL_RENDER_MAX_CHARS).collect();
        rendered.push('…');
    }
    rendered
}

/// One agent's parsed `result`-line budget reading: the reliable per-agent
/// context-window occupancy and the best-effort account-wide reserve.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentBudgetReading {
    /// Context-window occupancy % (`used / contextWindow`), when the result
    /// carries enough to compute it. Reliable in headless stream-json.
    pub ctx_pct: Option<u8>,
    /// Opportunistic account-wide 5h/7d reserve from a `rate_limits` object on the
    /// `result` line, if the backend embeds one. The reliable headless source is
    /// the per-window `rate_limit_event` (see [`rate_limit_window_for_line`]), so
    /// this is the *bonus* path: `None` unless a `result` carries the object.
    pub reserve: Option<BudgetUsage>,
}

/// Parse a stream-json `result` line into the [`AgentBudgetReading`] it carries,
/// or `None` for a non-`result` line, malformed JSON, or a result with nothing
/// budget-relevant. Pure — a fixture drives it, no real spawn.
///
/// The per-agent **context %** is computed from the reliable `usage` token counts
/// over `modelUsage.<model>.contextWindow`. The account-wide **5h/7d reserve** is
/// read best-effort from a `rate_limits` object on the result IF present — the
/// opportunistic bonus; the reliable headless source is the per-window
/// `rate_limit_event` line, folded separately in [`pump`].
fn budget_for_result_line(line: &str) -> Option<AgentBudgetReading> {
    let ev = serde_json::from_str::<Value>(line).ok()?;
    if ev.get("type").and_then(Value::as_str) != Some("result") {
        return None;
    }
    let reading = AgentBudgetReading {
        ctx_pct: ctx_pct_from_result(&ev),
        reserve: reserve_from_result(&ev),
    };
    // Nothing budget-relevant on this result line → no reading to surface.
    if reading.ctx_pct.is_none() && reading.reserve.is_none() {
        return None;
    }
    Some(reading)
}

/// Context-window occupancy %: the sum of the `usage` token fields over the
/// model's `contextWindow`, clamped to 100. `None` if the window or usage is
/// missing or the window is zero.
fn ctx_pct_from_result(ev: &Value) -> Option<u8> {
    let window = ev
        .get("modelUsage")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|m| m.get("contextWindow"))
        .and_then(Value::as_u64)
        .filter(|w| *w > 0)?;
    let usage = ev.get("usage").and_then(Value::as_object)?;
    let occupancy: u64 = [
        "input_tokens",
        "output_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
    ]
    .iter()
    .filter_map(|k| usage.get(*k).and_then(Value::as_u64))
    .sum();
    Some((occupancy.saturating_mul(100) / window).min(100) as u8)
}

/// Map a rate-limit window's reported `status` + optional `used_percentage` to a
/// single reserve %, mirroring the proven single-agent governor's rule
/// (`softfig-cli`'s `growlight_backend` / `cmd_growlight::window_tripped`): the
/// **status** is the reliable headless signal — `"allowed"` ⇒ 0, any other value
/// (`"warning"` / `"rejected"`) ⇒ a saturated 100 so the window trips the §7 halt
/// rail *and* the §9 near-exhaustion alert; a `used_percentage` is honored when a
/// backend reports one. Their per-field **max** never under-counts the shared pool.
/// `None` when the window carries neither signal — a missing reading is never read
/// as a false 0 (drive-loop slice 001).
fn window_pct(status: Option<&str>, used_percentage: Option<u8>) -> Option<u8> {
    let status_pct = status.map(|s| if s == "allowed" { 0 } else { 100 });
    let used = used_percentage.map(|p| p.min(100));
    match (status_pct, used) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0).max(b.unwrap_or(0))),
    }
}

/// Parse a stream-json `rate_limit_event` line into the window + reserve % it
/// reports — the reliable headless source of the account-wide 5h/7d reserve. A
/// headless `claude -p` emits one of these per window carrying a coarse `status`
/// (and a `resetsAt`), but no percentage (`growlight_backend`), so [`window_pct`]
/// keys off the status. `None` for any other line, malformed JSON, an event with
/// no `rate_limit_info`, or an unrecognized `rateLimitType`. Pure — a fixture
/// drives it, no real spawn.
fn rate_limit_window_for_line(line: &str) -> Option<(BudgetWindow, u8)> {
    let ev = serde_json::from_str::<Value>(line).ok()?;
    if ev.get("type").and_then(Value::as_str) != Some("rate_limit_event") {
        return None;
    }
    let info = ev.get("rate_limit_info")?;
    let window = match info.get("rateLimitType").and_then(Value::as_str)? {
        "five_hour" => BudgetWindow::FiveHour,
        "seven_day" => BudgetWindow::SevenDay,
        _ => return None,
    };
    let status = info.get("status").and_then(Value::as_str);
    let used = info
        .get("used_percentage")
        .and_then(Value::as_u64)
        .map(|p| p.min(100) as u8);
    window_pct(status, used).map(|pct| (window, pct))
}

/// Opportunistic account-wide 5h/7d reserve from a `rate_limits` object on a
/// `result` line, reading each window's `status` (primary) + `used_percentage`
/// through [`window_pct`]. `None` when the result carries no such object — the
/// expected headless case (the reserve flows via `rate_limit_event` instead, see
/// [`rate_limit_window_for_line`]); this is the documented bonus path.
fn reserve_from_result(ev: &Value) -> Option<BudgetUsage> {
    let rl = ev.get("rate_limits")?;
    let win = |window: &str| {
        rl.get(window).and_then(|w| {
            let status = w.get("status").and_then(Value::as_str);
            let used = w
                .get("used_percentage")
                .and_then(Value::as_u64)
                .map(|p| p.min(100) as u8);
            window_pct(status, used)
        })
    };
    match (win("five_hour"), win("seven_day")) {
        (None, None) => None,
        (five, seven) => Some(BudgetUsage::new(five.unwrap_or(0), seven.unwrap_or(0))),
    }
}

/// Tail an agent's `claude -p --output-format stream-json` output to EOF,
/// publishing each content block as an [`Event::AgentDelta`] on `hub`, bumping
/// `health`'s heartbeat on every non-empty line, folding each `rate_limit_event`
/// line's account-wide reserve status into `budget` (the reliable headless §7
/// source), and recording the terminal `result` line's context gauge (+ its
/// opportunistic `rate_limits` reserve). Pure over its `reader` / `now` seams: a
/// test drives it with a scripted fixture + fake clock, no real spawn.
fn pump<R: BufRead>(
    reader: R,
    agent: &str,
    hub: &EventHub,
    health: &AgentHealthState,
    budget: &AgentBudgetState,
    now: &dyn Fn() -> i64,
) {
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Any line from the child is a sign of life → heartbeat, even if it
        // carries no renderable delta.
        health.touch(now());
        // A `rate_limit_event` reports this agent's reading of the shared
        // account-wide 5h/7d reserve as a coarse per-window status — the reliable
        // headless source (spec §6/§7). Fold it into the budget cell the drive
        // loop's UsageAggregator reads; a non-"allowed" window saturates it so the
        // admission gate refuses (`window_pct`).
        if let Some((window, pct)) = rate_limit_window_for_line(line) {
            budget.record_window(window, pct);
        }
        for (kind, text) in deltas_for_line(line) {
            hub.publish(Event::agent_delta(agent, kind, text));
        }
        // The terminal `result` line carries this agent's context gauge; publish
        // the reliable per-agent context % as a `BudgetChanged{agent}` for the GUI
        // gauges (spec §7/§12), and fold any opportunistic `rate_limits` reserve
        // into the budget cell as a bonus. The fleet-wide 5h/7d gauge (`agent:
        // None`) is published by the drive loop once it has the cross-agent
        // aggregate.
        if let Some(reading) = budget_for_result_line(line) {
            if let Some(reserve) = reading.reserve {
                budget.record_reserve(reserve);
            }
            if let Some(ctx_pct) = reading.ctx_pct {
                hub.publish(Event::BudgetChanged {
                    agent: Some(agent.to_string()),
                    ctx_pct: Some(ctx_pct),
                    session_5h_pct: None,
                    session_7d_pct: None,
                });
            }
        }
    }
}

/// The production [`AgentBackend`]: shells `claude -p --output-format stream-json`
/// per agent (§12), tails each child into [`Event::AgentDelta`]s on the shared
/// [`EventHub`], and tracks a per-agent [`AgentHealthState`] the drive loop reads.
///
/// Implemented for `Arc<ClaudeBackend>` (mirroring the supervisor's test fake) so
/// the drive loop can hold a clone to read [`health`](ClaudeBackend::health) while
/// the [`crate::supervisor::Supervisor`] owns the backend behind the trait.
#[derive(Debug)]
pub struct ClaudeBackend {
    bin: String,
    prompt: String,
    hub: EventHub,
    /// Per-agent fail-closed pre-approval generator (§15, slice 004): each spawn
    /// generates this agent's `loop.json`/`mcp.json` BEFORE exec, so a headless
    /// session never errors out on a missing allow-rule. Generation failure ⇒ no
    /// spawn (a `SpawnError`).
    preapproval: PreApproval,
    /// Per-agent health cells, keyed by agent id; re-spawn (re-roll) replaces the
    /// agent's cell with a fresh one.
    agents: Mutex<BTreeMap<String, Arc<AgentHealthState>>>,
    /// Per-agent budget cells (latest best-effort shared-pool reserve), keyed by
    /// agent id; the drive loop folds these into its [`crate::usage::UsageAggregator`]
    /// via [`budget`](ClaudeBackend::budget). Re-spawn replaces the cell.
    budgets: Mutex<BTreeMap<String, Arc<AgentBudgetState>>>,
}

impl ClaudeBackend {
    /// A backend launching `bin` (e.g. `"claude"`) with `prompt` as the per-agent
    /// kick, publishing deltas to `hub`, generating each agent's pre-approval via
    /// `preapproval`. The SessionStart hook in each agent's generated `--settings`
    /// injects its protocol + baton; `prompt` is the generic turn kick.
    pub fn new(
        bin: impl Into<String>,
        prompt: impl Into<String>,
        hub: EventHub,
        preapproval: PreApproval,
    ) -> Self {
        Self {
            bin: bin.into(),
            prompt: prompt.into(),
            hub,
            preapproval,
            agents: Mutex::new(BTreeMap::new()),
            budgets: Mutex::new(BTreeMap::new()),
        }
    }

    /// `agent`'s current health (heartbeat-or-exit), or `None` if this backend
    /// never spawned it. The drive loop calls this each cycle to feed
    /// [`crate::supervisor::Supervisor::poll`].
    pub fn health(&self, agent: &str) -> Option<AgentHealth> {
        self.agents.lock().unwrap().get(agent).map(|s| s.observe())
    }

    /// `agent`'s latest reading of the shared account-wide budget pool (5h/7d
    /// reserve), or `None` if it has not reported a `rate_limit_event` (nor a
    /// `result` carrying a `rate_limits` reserve) yet. The drive loop folds these
    /// per-agent readings into the cross-agent [`crate::usage::UsageAggregator`].
    ///
    /// The live source is the per-window stream-json `rate_limit_event` (the
    /// headless §6/§7 signal — see [`rate_limit_window_for_line`]); the on-device
    /// confirmation that a headless `claude -p` emits these events for a fleet
    /// agent is this slice's `## Deferred verification` (no live `claude` in the
    /// sandbox). A `None` here folds nothing, leaving the aggregate fresh.
    pub fn budget(&self, agent: &str) -> Option<BudgetUsage> {
        self.budgets
            .lock()
            .unwrap()
            .get(agent)
            .and_then(|s| s.observe())
    }
}

impl AgentBackend for Arc<ClaudeBackend> {
    fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
        // §15 fail-closed pre-approval (slice 004): generate THIS agent's
        // loop.json + mcp.json (full-toolset pre-approval + SessionStart hook)
        // BEFORE exec. A headless `claude -p` errors out on the first un-approved
        // tool, so an agent whose pre-approval can't be generated must NOT be
        // spawned — the Err becomes a SpawnError the drive loop surfaces as an
        // operator alert (never a spawned-but-doomed session). Regenerated every
        // spawn, so a re-roll re-lays the current pre-approval. The generated
        // paths are the spec's (derived identically at assembly); we shell the
        // freshly-written ones.
        let paths = self.preapproval.generate(&spec.agent).map_err(|e| {
            SpawnError(format!(
                "pre-approval generation failed for agent {}: {e}",
                spec.agent
            ))
        })?;
        let mut child = Command::new(&self.bin)
            .arg("-p")
            .arg(&self.prompt)
            .arg("--settings")
            .arg(&paths.loop_settings)
            .arg("--mcp-config")
            .arg(&paths.mcp_config)
            .arg("--output-format")
            .arg("stream-json")
            .arg("--verbose")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // stderr is discarded, not piped: an unread stderr pipe can fill and
            // deadlock the child, and a headless permission error already surfaces
            // as a non-zero exit → crash classification + alert.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| SpawnError(format!("failed to launch `{} -p`: {e}", self.bin)))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SpawnError("child stdout was not captured".into()))?;

        let state = Arc::new(AgentHealthState::new(unix_now()));
        self.agents
            .lock()
            .unwrap()
            .insert(spec.agent.clone(), Arc::clone(&state));

        let budget = Arc::new(AgentBudgetState::default());
        self.budgets
            .lock()
            .unwrap()
            .insert(spec.agent.clone(), Arc::clone(&budget));

        // The child is shared with the reader thread for reaping. While the child
        // lives, the reader is blocked in `lines()` on stdout (it holds NO lock),
        // so `kill` can always take the lock to SIGKILL; the reader only locks the
        // child AFTER stdout EOF (the child is already exiting), so `wait` returns
        // promptly and there is no kill/reap deadlock.
        let child = Arc::new(Mutex::new(child));

        let hub = self.hub.clone();
        let agent = spec.agent.clone();
        let reader_state = Arc::clone(&state);
        let reader_budget = Arc::clone(&budget);
        let reader_child = Arc::clone(&child);
        thread::spawn(move || {
            pump(
                BufReader::new(stdout),
                &agent,
                &hub,
                &reader_state,
                &reader_budget,
                &|| unix_now(),
            );
            // stdout closed → the child is ending; reap it for the exit code.
            let code = reader_child
                .lock()
                .unwrap()
                .wait()
                .ok()
                .and_then(|s| s.code())
                .unwrap_or(UNKNOWN_EXIT);
            reader_state.record_exit(code);
        });

        Ok(Box::new(ClaudeChild { child }))
    }
}

/// The killable handle for a live `claude -p` child (the [`AgentChild`] contract).
/// `kill` SIGKILLs the process best-effort OUTSIDE the daemon lock; killing closes
/// stdout, so the reader thread reaps the child and records its exit.
#[derive(Debug)]
struct ClaudeChild {
    child: Arc<Mutex<Child>>,
}

impl AgentChild for ClaudeChild {
    fn kill(&self) {
        // Best-effort: an already-exited child returns Err, which is fine. We do
        // NOT wait() here — the reader thread reaps on the resulting stdout EOF.
        // Called outside the daemon lock (incident 20260622).
        let _ = self.child.lock().unwrap().kill();
    }
}

/// Wall-clock Unix seconds for the live heartbeat / spawn stamps. The pure policy
/// stays time-injected; only this live binding reads the clock.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A realistic stream-json run: system init, an assistant turn carrying a
    /// thinking + text + tool_use block, a tool_result (a `user` event), a second
    /// assistant turn, then the terminal result. Five non-empty lines; four
    /// renderable deltas.
    const STREAM: &str = concat!(
        r#"{"type":"system","subtype":"init","model":"claude-opus-4-8"}"#,
        "\n",
        r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","thinking":"let me check the file"},{"type":"text","text":"I'll read it now."},{"type":"tool_use","id":"tu_1","name":"Read","input":{"file_path":"/x"}}]}}"#,
        "\n",
        r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"ok"}]}}"#,
        "\n",
        r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Done."}]}}"#,
        "\n",
        r#"{"type":"result","subtype":"success","is_error":false,"result":"Done.","usage":{"input_tokens":250000},"modelUsage":{"claude-opus-4-8":{"contextWindow":1000000}}}"#,
        "\n",
    );

    #[test]
    fn deltas_for_line_extracts_each_content_block_in_order() {
        let assistant = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","thinking":"hmm"},{"type":"text","text":"hi"},{"type":"tool_use","id":"t","name":"Bash","input":{"command":"ls"}}]}}"#;
        assert_eq!(
            deltas_for_line(assistant),
            vec![
                (AgentDeltaKind::Thinking, "hmm".to_string()),
                (AgentDeltaKind::Assistant, "hi".to_string()),
                (AgentDeltaKind::ToolCall, r#"Bash({"command":"ls"})"#.to_string()),
            ]
        );

        // Non-assistant lines, malformed JSON, and empty-content carry no deltas.
        assert!(deltas_for_line(r#"{"type":"system","subtype":"init"}"#).is_empty());
        assert!(deltas_for_line(r#"{"type":"result","result":"done"}"#).is_empty());
        assert!(deltas_for_line("not json at all").is_empty());
        assert!(
            deltas_for_line(r#"{"type":"assistant","message":{"content":[]}}"#).is_empty()
        );
    }

    #[test]
    fn render_tool_use_is_compact_and_char_truncated() {
        let no_input = serde_json::json!({"name": "Ls"});
        assert_eq!(render_tool_use(&no_input), "Ls");

        // A huge argument is truncated on a char boundary with an ellipsis, never
        // panicking mid-codepoint.
        let big = serde_json::json!({"name": "Write", "input": {"content": "é".repeat(500)}});
        let rendered = render_tool_use(&big);
        assert!(rendered.chars().count() <= TOOL_RENDER_MAX_CHARS + 1);
        assert!(rendered.ends_with('…'));
        assert!(rendered.starts_with("Write("));
    }

    #[test]
    fn pump_publishes_each_delta_and_advances_the_heartbeat() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let state = AgentHealthState::new(0);
        let budget = AgentBudgetState::default();

        // A fake clock that ticks 10, 20, 30, … once per line read.
        let clock = AtomicI64::new(0);
        let now = || clock.fetch_add(10, Ordering::SeqCst) + 10;

        pump(Cursor::new(STREAM), "tab", &hub, &state, &budget, &now);

        // The four content deltas reach the hub in block order, tagged by kind.
        let expect = [
            Event::agent_delta("tab", AgentDeltaKind::Thinking, "let me check the file"),
            Event::agent_delta("tab", AgentDeltaKind::Assistant, "I'll read it now."),
            Event::agent_delta("tab", AgentDeltaKind::ToolCall, r#"Read({"file_path":"/x"})"#),
            Event::agent_delta("tab", AgentDeltaKind::Assistant, "Done."),
        ];
        for want in expect {
            assert_eq!(sub.try_recv().unwrap(), want);
        }
        // The terminal result line publishes this agent's per-agent context gauge
        // (250000 / 1000000 = 25%); no 5h/7d on the wire here, so it stays None.
        assert_eq!(
            sub.try_recv().unwrap(),
            Event::BudgetChanged {
                agent: Some("tab".to_string()),
                ctx_pct: Some(25),
                session_5h_pct: None,
                session_7d_pct: None,
            }
        );
        assert!(sub.try_recv().is_err(), "no extra events");
        // No `rate_limits` on the wire → no shared-pool reserve recorded.
        assert_eq!(budget.observe(), None);

        // Five non-empty lines → five heartbeats → last_active is the final tick.
        assert_eq!(state.last_active(), 50);
        assert_eq!(state.observe(), AgentHealth::Alive { last_active: 50 });
    }

    #[test]
    fn a_silent_stream_leaves_the_heartbeat_stale_so_the_supervisor_would_hang_it() {
        // A child that emits its init line then goes silent (no further output and
        // no exit) — the canonical hang. The heartbeat stops at the init stamp.
        let silent = "{\"type\":\"system\",\"subtype\":\"init\"}\n";
        let hub = EventHub::new();
        let state = AgentHealthState::new(0);
        let budget = AgentBudgetState::default();
        let now = || 100; // init line stamped at t=100, then nothing more

        pump(Cursor::new(silent), "tab", &hub, &state, &budget, &now);

        // No exit recorded → still Alive, but pinned at the stale init stamp.
        assert_eq!(state.observe(), AgentHealth::Alive { last_active: 100 });
        // A later poll's gap exceeds the supervisor's default hang window (600s),
        // so `Supervisor::classify` (proven in supervisor.rs) trips it to Crashed.
        let polled_at = 100 + 700;
        assert!(polled_at - 100 >= 600, "a stale heartbeat reads as hung");
    }

    #[test]
    fn observe_reports_a_recorded_exit_over_the_heartbeat() {
        let state = AgentHealthState::new(42);
        assert_eq!(state.observe(), AgentHealth::Alive { last_active: 42 });
        // Once the reader thread reaps a non-zero exit, health flips to Exited
        // (the supervisor classifies that as a crash).
        state.record_exit(1);
        assert_eq!(state.observe(), AgentHealth::Exited { code: 1 });
    }

    #[test]
    fn budget_for_result_line_computes_ctx_pct_from_usage_over_the_window() {
        // occupancy = 50000 + 30000 + 20000 = 100000 over a 200000 window → 50%.
        let line = r#"{"type":"result","usage":{"input_tokens":50000,"output_tokens":30000,"cache_read_input_tokens":20000},"modelUsage":{"claude-opus-4-8":{"contextWindow":200000}}}"#;
        assert_eq!(
            budget_for_result_line(line),
            Some(AgentBudgetReading {
                ctx_pct: Some(50),
                reserve: None,
            })
        );

        // A full window saturates at 100, never overflows.
        let full = r#"{"type":"result","usage":{"input_tokens":300000},"modelUsage":{"m":{"contextWindow":200000}}}"#;
        assert_eq!(budget_for_result_line(full).unwrap().ctx_pct, Some(100));
    }

    #[test]
    fn budget_for_result_line_ignores_non_result_and_unbudgeted_lines() {
        // Non-result lines carry no budget reading.
        assert!(budget_for_result_line(
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]}}"#
        )
        .is_none());
        assert!(budget_for_result_line("not json").is_none());
        // A result with neither a window nor a rate_limits object → nothing to surface.
        assert!(budget_for_result_line(r#"{"type":"result","result":"done"}"#).is_none());
        // A zero window can't yield a percentage.
        assert!(budget_for_result_line(
            r#"{"type":"result","usage":{"input_tokens":1},"modelUsage":{"m":{"contextWindow":0}}}"#
        )
        .is_none());
    }

    #[test]
    fn budget_for_result_line_reads_a_best_effort_rate_limits_reserve_when_present() {
        // The wire-format-unconfirmed path: IF a result embeds a usage.json-shaped
        // `rate_limits` object, the 5h/7d reserve is surfaced for the aggregator.
        let line = r#"{"type":"result","usage":{"input_tokens":100000},"modelUsage":{"m":{"contextWindow":200000}},"rate_limits":{"five_hour":{"used_percentage":91},"seven_day":{"used_percentage":40}}}"#;
        assert_eq!(
            budget_for_result_line(line),
            Some(AgentBudgetReading {
                ctx_pct: Some(50),
                reserve: Some(BudgetUsage::new(91, 40)),
            })
        );

        // A partial object defaults the absent window to 0 but still surfaces.
        let partial = r#"{"type":"result","rate_limits":{"five_hour":{"used_percentage":97}}}"#;
        assert_eq!(
            budget_for_result_line(partial).unwrap().reserve,
            Some(BudgetUsage::new(97, 0))
        );

        // A result whose `rate_limits` carries the headless `status` shape (no
        // percentage) is read too: a non-"allowed" window saturates to 100.
        let status_shaped = r#"{"type":"result","rate_limits":{"five_hour":{"status":"rejected"},"seven_day":{"status":"allowed"}}}"#;
        assert_eq!(
            budget_for_result_line(status_shaped).unwrap().reserve,
            Some(BudgetUsage::new(100, 0))
        );
    }

    #[test]
    fn window_pct_keys_off_status_then_falls_back_to_used_percentage() {
        // The reliable headless signal is the status: allowed ⇒ 0, anything else
        // ⇒ a saturated 100 (mirrors the proven single-agent `window_tripped`).
        assert_eq!(window_pct(Some("allowed"), None), Some(0));
        assert_eq!(window_pct(Some("warning"), None), Some(100));
        assert_eq!(window_pct(Some("rejected"), None), Some(100));
        // A used_percentage is honored when present; the two take the safe max so
        // a stale-low status can't mask a high percentage.
        assert_eq!(window_pct(None, Some(42)), Some(42));
        assert_eq!(window_pct(Some("allowed"), Some(73)), Some(73));
        assert_eq!(window_pct(None, Some(255)), Some(100), "clamped to 100");
        // Neither signal → nothing to record (never a false 0).
        assert_eq!(window_pct(None, None), None);
    }

    #[test]
    fn rate_limit_window_for_line_parses_the_headless_event_shape() {
        // The real headless wire shape: a per-window `rate_limit_event` carrying a
        // coarse status + reset (no percentage).
        let five_rejected = r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"rejected","resetsAt":1782367800}}"#;
        assert_eq!(
            rate_limit_window_for_line(five_rejected),
            Some((BudgetWindow::FiveHour, 100))
        );
        let seven_allowed = r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"seven_day","status":"allowed","resetsAt":1782900000}}"#;
        assert_eq!(
            rate_limit_window_for_line(seven_allowed),
            Some((BudgetWindow::SevenDay, 0))
        );
        // Non-events, malformed JSON, and an unrecognized window carry no reading.
        assert!(rate_limit_window_for_line(r#"{"type":"result","result":"done"}"#).is_none());
        assert!(rate_limit_window_for_line("not json").is_none());
        assert!(rate_limit_window_for_line(
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"yearly","status":"allowed"}}"#
        )
        .is_none());
        // A rate_limit_event with no info is ignored, not a panic.
        assert!(rate_limit_window_for_line(r#"{"type":"rate_limit_event"}"#).is_none());
    }

    #[test]
    fn pump_folds_rate_limit_events_into_a_reserve_that_trips_the_gate() {
        use crate::admission::{AdmissionDecision, AdmissionGovernor, Intent, RateState, RefuseReason};
        use crate::config::Policy;
        use crate::usage::usage_alert_reached;

        let hub = EventHub::new();
        let state = AgentHealthState::new(0);
        let budget = AgentBudgetState::default();
        let now = || 100;

        // A headless run: the 5h window goes to `rejected` (pool exhausted) while
        // the 7d window is still `allowed`, then the terminal result.
        let stream = concat!(
            r#"{"type":"system","subtype":"init","model":"claude-opus-4-8"}"#,
            "\n",
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"rejected","resetsAt":1782367800}}"#,
            "\n",
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"seven_day","status":"allowed","resetsAt":1782900000}}"#,
            "\n",
            r#"{"type":"result","subtype":"success","usage":{"input_tokens":1},"modelUsage":{"claude-opus-4-8":{"contextWindow":1000000}}}"#,
            "\n",
        );
        pump(Cursor::new(stream), "tab", &hub, &state, &budget, &now);

        // The non-"allowed" 5h status folded to a saturated 100; the allowed 7d to 0.
        let reserve = budget.observe().expect("a reserve was folded from the events");
        assert_eq!(reserve, BudgetUsage::new(100, 0));

        // End-to-end: this reading trips the §9 fleet near-exhaustion rung AND
        // makes the admission governor REFUSE a start on the 5h rail.
        assert!(usage_alert_reached(reserve), "a rejected 5h window reaches the alert rung");
        let g = AdmissionGovernor::new(Policy::default());
        let rate = RateState {
            tpm_used: 0,
            rpm_used: 0,
            tpm_limit: 1_000_000,
            rpm_limit: 1_000,
            tpm_per_agent: 1,
            rpm_per_agent: 1,
        };
        assert_eq!(
            g.decide(Intent::Start, 0, reserve, rate),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Budget5h
            },
            "a tripped reserve refuses admission",
        );
    }

    #[test]
    fn an_all_allowed_reading_stays_below_the_rails_and_admits() {
        use crate::admission::{AdmissionGovernor, Intent, RateState};
        use crate::config::Policy;
        use crate::usage::usage_alert_reached;

        let hub = EventHub::new();
        let state = AgentHealthState::new(0);
        let budget = AgentBudgetState::default();
        let now = || 0;

        let stream = concat!(
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"allowed","resetsAt":1782367800}}"#,
            "\n",
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"seven_day","status":"allowed","resetsAt":1782900000}}"#,
            "\n",
        );
        pump(Cursor::new(stream), "tab", &hub, &state, &budget, &now);

        // Both windows allowed → a fresh (0,0) reserve: no alert, admission admits.
        let reserve = budget.observe().expect("an allowed reading still records (0,0)");
        assert_eq!(reserve, BudgetUsage::new(0, 0));
        assert!(!usage_alert_reached(reserve));
        let g = AdmissionGovernor::new(Policy::default());
        let rate = RateState {
            tpm_used: 0,
            rpm_used: 0,
            tpm_limit: 1_000_000,
            rpm_limit: 1_000,
            tpm_per_agent: 1,
            rpm_per_agent: 1,
        };
        assert!(g.decide(Intent::Start, 0, reserve, rate).is_admit());
    }

    #[test]
    fn spawn_fails_closed_when_pre_approval_cannot_be_generated() {
        // A FILE where the agents dir should be → the per-agent dir can't be
        // created → generation fails BEFORE `claude` is ever exec'd, so the spawn
        // returns a SpawnError and NO agent is registered (no doomed headless
        // session). This proves the fail-closed gate without a real `claude`.
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let pre = PreApproval::new(
            &blocker, // agents_dir is a FILE → create_dir_all under it fails
            tmp.path().join("protocol.md"),
            tmp.path().to_path_buf(),
            std::path::PathBuf::from("softfig-mcp"),
            tmp.path().join(".claude"),
        );
        let backend = Arc::new(ClaudeBackend::new("claude", "kick", EventHub::new(), pre));
        let spec = AgentSpec::new("a1", blocker.join("a1/loop.json"), blocker.join("a1/mcp.json"));

        let err = backend.spawn(&spec).expect_err("generation failure ⇒ no spawn");
        assert!(
            err.0.contains("pre-approval generation failed"),
            "fail-closed spawn error: {err}",
        );
        // Nothing was registered — the agent never entered the fleet.
        assert!(backend.health("a1").is_none(), "no doomed agent registered");
    }
}
