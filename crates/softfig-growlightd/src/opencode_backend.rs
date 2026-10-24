//! The opencode backend — opencode's **flavor** of the backend-agnostic
//! [`crate::agent_harness`] (spec-agents §10 phase 2).
//!
//! Two halves. The **wire format** (slice 002, re-pinned by opencode-v2-repin
//! slice 004): the NDJSON per-line fold that normalizes `opencode run --format
//! json` output into growlightd's canonical [`Event::AgentDelta`] + heartbeat +
//! rate pipeline. And the **backend** (slice 004): [`OpencodeBackend`], a
//! [`Harness`] bound to this module's [`BackendFlavor`], which the drive loop
//! consumes through exactly the trait objects it already consumes claude through.
//! Everything structural — the transient systemd scope, build caps, health cells,
//! stderr ring, rolling-minute meter, and the `live_scopes` / `kill_handles`
//! registries — is the harness's and is not duplicated here; the flavor is five
//! methods.
//!
//! ## The wire format (PINNED against opencode 2.0.24, 2026-10-10)
//!
//! NDJSON, one object per line: `{type, timestamp, sessionID, part}`, or a
//! top-level `{type: "error", timestamp, sessionID, error}` with no `part`. The
//! fixtures in `tests/fixtures/` are real captured runs and are the substitute for
//! a live `opencode` — **no `opencode` process is ever spawned in tests**. The
//! 1.18.15 fixtures stay beside the 2.x ones as the historical baseline, and the
//! fold passes over both: it reads no field only one version carries.
//!
//! | `type` | carries | folded into |
//! |---|---|---|
//! | `step_start` | nothing we read | one model request (the step count), and opens a step |
//! | `text` | `part.text` | [`AgentDeltaKind::Assistant`] |
//! | `reasoning` | `part.text` (emitted only under `--thinking`) | [`AgentDeltaKind::Thinking`] |
//! | `tool_use` | `part.tool`, `part.state.{status,title,input,error}` | [`AgentDeltaKind::ToolCall`] |
//! | `step_finish` | `part.tokens.{input,output,reasoning,cache.{read,write}}`, `part.cost` | the rate meter + [`AgentSpendState`]; closes the step |
//! | `error` | `error.{type,message}` | the member's crash reason ([`OpencodeBackend::stderr_tail`]) |
//! | anything else | — | heartbeat only, never fatal: 2.x is moving fast |
//!
//! What 2.x changed, and where each change lands:
//!
//! - **`tokens.total` is gone.** A step's tokens are the sum of its parts, which
//!   equals the old `total` on every 1.18.15 step (a test proves it).
//! - **The final step has no `step_finish`**, so the stream never carries the last
//!   step's tokens or cost. The run's end is the child's stdout EOF
//!   ([`LineObserver::finish`]), never a line. See "Run end" below.
//! - **`error` is new.** opencode sets exit 1 whenever it emits one, and in
//!   `--format json` it writes the message to stdout only, never stderr. Without
//!   this fold the crash alert would page with no reason.
//! - `callID` became `partID` (unread), `state.input.filePath` became `path`, and
//!   `state.title` is now just the tool's name. A refused call has
//!   `status: "error"` + `state.error` and no `title`. See [`render_tool_use`].
//!
//! `timestamp` is **milliseconds** (claude's `stream-json` is not) — which is
//! precisely why this fold ignores it and uses the harness's `at` stamp, the same
//! injected clock reading that bumped the heartbeat. There is no ms/s unit to get
//! wrong.
//!
//! ## Run end: settling against opencode's session record
//!
//! At stdout EOF the fold reads the run's totals from opencode's own session record
//! ([`crate::opencode_ledger`], keyed by the stream's `sessionID`, subagent
//! sessions included):
//!
//! - **Spend** is raised to the recorded total. It is never lowered, so a stale or
//!   partial read can only leave the streamed lower bound in place.
//! - **Rate**: the tokens the stream never showed go into the rolling-minute meter
//!   as one more request, the final step's. Without it a text-only run, whose one
//!   step streams nothing, would meter zero.
//!
//! If the record can't be read, the member keeps the streamed figures and the
//! daemon logs why. Accounting never fails a member.
//!
//! ## What opencode does NOT report, and why that is load-bearing
//!
//! No `rate_limit_event`, no terminal `result` line, no `rate_limits` object, no
//! context-window percentage — claude's parser keys on exactly those four. So:
//!
//! - **No 5h/7d reserve, ever.** There is deliberately no budget cell in this
//!   module: [`crate::claude_backend::AgentBudgetState`] is the *Anthropic account
//!   pool* that gates admission, and a metered provider must never synthesize a
//!   reading into that aggregate (opencode-fleet-backend locked decision). Slice
//!   004's `budget()` returns `None` because there is structurally nothing here to
//!   return.
//! - **No per-agent context gauge.** This fold publishes no
//!   [`Event::BudgetChanged`] at all; a `ctx_pct` would have to be invented.
//!
//! ## Rate: one step is one request
//!
//! claude meters one turn per terminal `result`; opencode runs one step **per
//! model turn**, so a multi-tool run meters several requests. That is the truthful
//! reading — each step really is a separate API call — so it is not a bug to
//! "fix" into one-per-run. A member's subagent steps run in child sessions that the
//! stream does not carry; their tokens reach the meter only through the run-end
//! settlement, as part of that one final request.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use softfig_ipc::growlightd::{AgentDeltaKind, Event};

use crate::admission::BudgetUsage;
use crate::agent_harness::{
    AgentRateState, BackendFlavor, EnvChange, Harness, LineObserver, TOOL_RENDER_MAX_CHARS,
    truncate_chars,
};
use crate::config::BuildCaps;
use crate::control::{AgentChild, LiveKill};
use crate::hub::EventHub;
use crate::opencode_ledger::SessionLedger;
use crate::opencode_preapproval::OpencodePreApproval;
use crate::preapproval::AgentPaths;
use crate::supervisor::{AgentBackend, AgentHealth, AgentSpec, SpawnError};

// Imports for the test-only opencode-shaped `pump` seam below, which wires
// borrowed cells into the harness's line loop so a fixture drives the real
// pipeline.
#[cfg(test)]
use crate::agent_harness::AgentHealthState;
#[cfg(test)]
use std::io::BufRead;

/// Fixed-point scale for accumulated spend: nano-USD per USD.
///
/// The slice specs call for "integer micro-USD, not `f64` accumulation" — the
/// accumulation is integer here and [`AgentSpend::micro_usd`] is the reading slice
/// 006 surfaces. The *internal* unit is one thousandth of that because a
/// `deepseek/deepseek-flash` step really does cost `7.9e-05` USD (≈79 µUSD in the
/// captured 2.x fixture): quantizing each step to whole µUSD would put a ~1% error
/// on exactly the model this backend exists to run. Nano-USD costs nothing (same
/// `u64`, one constant) and removes the class — `u64::MAX` nano-USD is ~1.8e10 USD.
const NANO_USD_PER_USD: f64 = 1_000_000_000.0;

/// How many `error` events a member's crash reason keeps. opencode exits 1 after
/// the first, so more than one is rare; the bound only stops a pathological stream
/// from growing the cell.
const ERROR_RING_MAX: usize = 5;

/// Per-line cap (chars) on a kept `error` message — the same cap the harness puts
/// on a stderr line, since the two are read side by side.
const ERROR_LINE_MAX_CHARS: usize = 512;

/// `usd` in nano-USD. A non-finite or negative cost is 0: a malformed line must not
/// corrupt a total.
fn nano_usd(usd: f64) -> u64 {
    if usd.is_finite() && usd > 0.0 {
        (usd * NANO_USD_PER_USD).round().min(u64::MAX as f64) as u64
    } else {
        0
    }
}

/// One opencode member's accumulated session spend and step count — the accounting
/// slice 006 surfaces on `growlight status` / the TUI roster, so a metered member
/// reads as "opencode · $0.14 this session" instead of showing an empty Anthropic
/// reserve gauge and looking broken.
///
/// Bounded in-memory counters, deliberately: no spend log file on this device
/// (SSD/eMMC wear — spec §6 storage note). The counters are lost on a growlightd
/// restart, which is the accepted trade.
///
/// **Accounting only.** The spend *cap* and its enforcement, the metered 429
/// `retry-after` hold, and per-provider pool separation are spec-agents §7 phase 4
/// — this is not an oversight, it is the data phase 4 will arrive to.
#[derive(Debug, Default)]
pub struct AgentSpendState {
    /// Accumulated cost in nano-USD (see [`NANO_USD_PER_USD`]).
    nano_usd: AtomicU64,
    /// Model steps started (one per `step_start`).
    steps: AtomicU64,
}

/// A snapshot reading of one agent's [`AgentSpendState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AgentSpend {
    /// Accumulated spend in **micro-USD** (1e-6 USD), rounded from the nano-USD
    /// accumulator at read time — so rounding happens once, not per step.
    pub micro_usd: u64,
    /// Model steps (`step_start` events) this session. Counted at the start
    /// because the final step never streams a `step_finish`.
    pub steps: u64,
}

impl AgentSpendState {
    /// One model step started: one real API request.
    pub(crate) fn record_step(&self) {
        self.steps.fetch_add(1, Ordering::SeqCst);
    }

    /// Fold one `step_finish`'s USD cost into the accumulator.
    pub(crate) fn record_cost(&self, cost_usd: f64) {
        self.nano_usd.fetch_add(nano_usd(cost_usd), Ordering::SeqCst);
    }

    /// Raise the accumulator to `total_usd`, the run's total from opencode's
    /// session record. Never lowers it: the streamed sum is a floor the record can
    /// only confirm or exceed, so a stale read changes nothing.
    pub(crate) fn settle(&self, total_usd: f64) {
        self.nano_usd.fetch_max(nano_usd(total_usd), Ordering::SeqCst);
    }

    /// The current reading.
    pub fn observe(&self) -> AgentSpend {
        AgentSpend {
            micro_usd: self.nano_usd.load(Ordering::SeqCst) / 1_000,
            steps: self.steps.load(Ordering::SeqCst),
        }
    }
}

/// One member's `error` events, rendered, oldest first: its crash reason. In-memory
/// and replaced every spawn, like the harness's stderr ring it is read beside.
#[derive(Debug, Default)]
struct AgentErrorState {
    inner: Mutex<VecDeque<String>>,
}

impl AgentErrorState {
    fn push(&self, line: String) {
        let mut ring = self.inner.lock().unwrap();
        ring.push_back(truncate_chars(&line, ERROR_LINE_MAX_CHARS));
        while ring.len() > ERROR_RING_MAX {
            ring.pop_front();
        }
    }

    fn lines(&self) -> Vec<String> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }
}

/// The per-member cells this flavor keeps beside the harness's own, replaced
/// together on every spawn so both always describe the CURRENT child.
#[derive(Debug, Default)]
struct MemberCells {
    spend: AgentSpendState,
    errors: AgentErrorState,
}

/// One run's bookkeeping, private to its fold: what the run-end settlement needs to
/// know about what the stream already showed.
#[derive(Debug, Default)]
struct RunState {
    /// The stream's `sessionID`, from the first line carrying one. Every line of a
    /// run names the same session.
    session_id: Option<String>,
    /// Tokens already metered from streamed `step_finish` lines.
    streamed_tokens: u64,
    /// A `step_start` with no `step_finish` yet. On 2.x the final step always ends
    /// open.
    open_step: bool,
}

/// The content deltas one event carries. Pure. A type that carries no renderable
/// content (`step_start`, `step_finish`, `error`, anything unknown), or a known
/// type missing its text, yields none — the harness still counted the line as a
/// heartbeat, since a child emitting anything at all is plainly alive.
fn deltas_for(ev: &Value) -> Vec<(AgentDeltaKind, String)> {
    let Some(part) = ev.get("part") else {
        return Vec::new();
    };
    let text = |kind| {
        part.get("text")
            .and_then(Value::as_str)
            .map(|t| vec![(kind, t.to_string())])
            .unwrap_or_default()
    };
    match ev.get("type").and_then(Value::as_str) {
        Some("text") => text(AgentDeltaKind::Assistant),
        Some("tool_use") => vec![(AgentDeltaKind::ToolCall, render_tool_use(part))],
        // Source-read from the 2.0.24 bundle: `run` emits
        // `{type:"reasoning", part:{type:"reasoning", text, …}}`, and only when
        // `--thinking` is set (members don't pass it today). Not yet captured live.
        Some("reasoning") => text(AgentDeltaKind::Thinking),
        _ => Vec::new(),
    }
}

/// Render a `tool_use` part into a compact one-line "what tool, what args" string
/// for the live view, char-truncated so a huge argument can't flood the stream.
///
/// A non-`completed` status is carried in the render (`write[error](…)`) rather
/// than suppressed: opencode was only ever observed emitting one event per call, at
/// its final status, so filtering on one status would risk silently dropping a
/// call if intermediate states do stream. A refused call (`status: "error"`) ends
/// with its reason, `: Permission denied: edit`, after the arguments, so the path
/// survives truncation.
fn render_tool_use(part: &Value) -> String {
    let tool = part.get("tool").and_then(Value::as_str).unwrap_or("tool");
    let state = part.get("state");
    let status = state
        .and_then(|s| s.get("status"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = tool_subject(tool, state);

    let head = match status {
        "" | "completed" => tool.to_string(),
        other => format!("{tool}[{other}]"),
    };
    let mut rendered = if args.is_empty() {
        head
    } else {
        format!("{head}({args})")
    };
    if let Some(error) = state.and_then(|s| s.get("error")).and_then(Value::as_str) {
        rendered = format!("{rendered}: {error}");
    }
    truncate_chars(&rendered, TOOL_RENDER_MAX_CHARS)
}

/// The input keys that name what a call acts on: `path` on 2.x, `filePath` on
/// 1.18.15. Both proven in the fixtures; any other tool falls back to its raw input.
const TOOL_SUBJECT_KEYS: &[&str] = &["path", "filePath"];

/// What a tool call acts on. 1.18.15 pre-rendered a label into `state.title`
/// (`garden/hello.txt`), which is still preferred when present. 2.x sets `title` to
/// the bare tool name (`write`) and omits it on a refused call, so a title that
/// only repeats the tool says nothing. Then the input's subject (its path), then
/// the raw input JSON.
fn tool_subject(tool: &str, state: Option<&Value>) -> String {
    let title = state
        .and_then(|s| s.get("title"))
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty() && *t != tool);
    if let Some(title) = title {
        return title.to_string();
    }
    let input = state.and_then(|s| s.get("input")).filter(|i| !i.is_null());
    let subject = input.and_then(|i| {
        TOOL_SUBJECT_KEYS
            .iter()
            .find_map(|k| i.get(*k).and_then(Value::as_str))
    });
    match (subject, input) {
        (Some(subject), _) => subject.to_string(),
        (None, Some(input)) => serde_json::to_string(input).unwrap_or_default(),
        (None, None) => String::new(),
    }
}

/// What one completed model step cost: the tokens feeding the rolling-minute meter
/// and the USD this step spent.
#[derive(Debug, Clone, Copy, PartialEq)]
struct StepFinish {
    /// `input + output + reasoning + cache.read + cache.write`. 2.x dropped
    /// `tokens.total`; on every 1.18.15 step the sum equals it. A missing part
    /// counts 0, so a `step_finish` with no `tokens` still meters one request at
    /// zero tokens, mirroring claude's `Some(0)` for a `result` with no `usage`.
    tokens: u64,
    /// `part.cost`, USD for THIS step (not a running total).
    cost_usd: f64,
}

/// A `step_finish` event's tokens and cost, or `None` for any other type or a
/// `step_finish` with no `part`. Pure — a fixture drives it, no real spawn.
fn step_finish_of(ev: &Value) -> Option<StepFinish> {
    if ev.get("type").and_then(Value::as_str) != Some("step_finish") {
        return None;
    }
    let part = ev.get("part")?;
    let tokens = part.get("tokens");
    let count = |path: &[&str]| {
        path.iter()
            .try_fold(tokens?, |v, k| v.get(*k))
            .and_then(Value::as_u64)
    };
    let sum = [
        count(&["input"]),
        count(&["output"]),
        count(&["reasoning"]),
        count(&["cache", "read"]),
        count(&["cache", "write"]),
    ]
    .into_iter()
    .flatten()
    .fold(0u64, u64::saturating_add);
    Some(StepFinish {
        tokens: sum,
        cost_usd: part.get("cost").and_then(Value::as_f64).unwrap_or(0.0),
    })
}

/// A top-level `error` event as one crash-reason line, or `None` for any other
/// type. `opencode error [provider.no-route]: Model unavailable: …`. An error with
/// no `message` keeps its raw JSON, so nothing it said is lost.
fn error_of(ev: &Value) -> Option<String> {
    if ev.get("type").and_then(Value::as_str) != Some("error") {
        return None;
    }
    let error = ev.get("error");
    let kind = error
        .and_then(|e| e.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let message = error
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| error.map(Value::to_string).unwrap_or_default());
    Some(format!("opencode error [{kind}]: {message}"))
}

/// One spawn's fold: every cell it writes, borrowed. The live reader thread's
/// [`OpencodeSpawnObserver`] lends its `Arc`s into one of these per call, and the
/// unit tests build one over plain borrows, so both run the SAME fold.
struct Fold<'a> {
    agent: &'a str,
    hub: &'a EventHub,
    member: &'a MemberCells,
    rate: &'a AgentRateState,
    run: &'a Mutex<RunState>,
    ledger: &'a dyn SessionLedger,
}

impl LineObserver for Fold<'_> {
    /// Publish this line's content deltas on `hub`; on a `step_start` count one
    /// request; on a `step_finish` meter its tokens into `rate` and accrue its cost;
    /// on an `error` keep the reason.
    ///
    /// Note what is NOT here versus [`crate::claude_backend::observe_claude_line`]:
    /// no reserve fold and no [`Event::BudgetChanged`] — opencode's wire format
    /// carries neither a rate-limit window nor a context gauge, and inventing one
    /// would corrupt the admission aggregate governing the claude members (see the
    /// module docs).
    fn observe(&self, line: &str, at: i64) {
        // A line that isn't JSON (a partial write at EOF, stray output) was already
        // a heartbeat; it carries nothing else.
        let Ok(ev) = serde_json::from_str::<Value>(line) else {
            return;
        };
        for (kind, text) in deltas_for(&ev) {
            self.hub.publish(Event::agent_delta(self.agent, kind, text));
        }
        let mut run = self.run.lock().unwrap();
        if run.session_id.is_none() {
            run.session_id = ev.get("sessionID").and_then(Value::as_str).map(str::to_string);
        }
        if ev.get("type").and_then(Value::as_str) == Some("step_start") {
            self.member.spend.record_step();
            run.open_step = true;
        }
        // One `step_finish` == one completed model turn == one real API call
        // costing its tokens. See the module docs on why this is per-step.
        if let Some(step) = step_finish_of(&ev) {
            run.open_step = false;
            run.streamed_tokens = run.streamed_tokens.saturating_add(step.tokens);
            self.rate.record(at, step.tokens);
            self.member.spend.record_cost(step.cost_usd);
        }
        if let Some(reason) = error_of(&ev) {
            self.member.errors.push(reason);
        }
    }

    /// Settle the run against opencode's session record (module docs, "Run end").
    fn finish(&self, at: i64) {
        let run = self.run.lock().unwrap();
        // No line ever named a session: the child died before opencode started
        // one, and there is nothing to settle.
        let Some(session) = run.session_id.as_deref() else {
            return;
        };
        match self.ledger.totals(session) {
            Ok(totals) => {
                self.member.spend.settle(totals.cost_usd);
                let unseen = totals.tokens.saturating_sub(run.streamed_tokens);
                if run.open_step || unseen > 0 {
                    self.rate.record(at, unseen);
                }
                if !totals.settled {
                    eprintln!(
                        "growlightd: opencode member {}: session {session} was still running \
                         when read; its final step may be missing from spend",
                        self.agent
                    );
                }
            }
            Err(e) => {
                // The open step was still a real request; only its tokens are
                // unknown.
                if run.open_step {
                    self.rate.record(at, 0);
                }
                eprintln!(
                    "growlightd: opencode member {}: spend stays the streamed lower bound: {e}",
                    self.agent
                );
            }
        }
    }
}

/// The owned [`LineObserver`] a live spawn's reader thread holds — the cells this
/// generation writes into, `Arc`-shared with the backend's registries.
#[derive(Debug)]
pub(crate) struct OpencodeSpawnObserver {
    agent: String,
    hub: EventHub,
    member: Arc<MemberCells>,
    rate: Arc<AgentRateState>,
    run: Mutex<RunState>,
    ledger: Arc<dyn SessionLedger>,
}

impl OpencodeSpawnObserver {
    fn fold(&self) -> Fold<'_> {
        Fold {
            agent: &self.agent,
            hub: &self.hub,
            member: &self.member,
            rate: &self.rate,
            run: &self.run,
            ledger: self.ledger.as_ref(),
        }
    }
}

impl LineObserver for OpencodeSpawnObserver {
    fn observe(&self, line: &str, at: i64) {
        self.fold().observe(line, at);
    }

    fn finish(&self, at: i64) {
        self.fold().finish(at);
    }
}

/// Tail an agent's `opencode run --format json` output to EOF through the
/// harness's [`pump`](crate::agent_harness::pump), folding each line and the
/// run end with [`Fold`]. The opencode-shaped seam the unit tests drive: it wires
/// borrowed cells into the SAME harness loop + SAME fold the live reader thread
/// uses, so the fixtures prove the production pipeline rather than a parallel one.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn pump<R: BufRead>(
    reader: R,
    agent: &str,
    hub: &EventHub,
    health: &AgentHealthState,
    member: &MemberCells,
    rate: &AgentRateState,
    ledger: &dyn SessionLedger,
    now: &dyn Fn() -> i64,
) {
    let run = Mutex::new(RunState::default());
    crate::agent_harness::pump(
        reader,
        health,
        &Fold {
            agent,
            hub,
            member,
            rate,
            run: &run,
            ledger,
        },
        now,
    );
}

// ---- the backend ------------------------------------------------------------

/// The model an opencode member runs on, as the operator declared it on its
/// `[[fleet]]` entry. It reaches opencode as argv `--model`, never the generated
/// config: on 2.x `run` ignores `agent.<id>.model` entirely, and argv `--model` is
/// the only path that fails closed on a bad id (opencode-v2-repin slice 001, L5 +
/// L7; a config-borne bad id silently fell back to `opencode/exo-free` and SENT the
/// prompt there).
///
/// `model` is required, not optional. A member with no model would leave opencode
/// to pick its own default, which is the same silent fallback seen from the other
/// side, so [`crate::fleet`] refuses such a member at parse time and this type
/// cannot express one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSelection {
    /// The opencode model id (`provider/model`), e.g. `deepseek/deepseek-flash`.
    pub model: String,
    /// The model's variant (one of the catalog's `variants[].id`, e.g. `high` on
    /// DeepSeek), or `None` to run the model's own default.
    pub variant: Option<String>,
}

impl ModelSelection {
    /// A selection pinning `model`, with the model's own default variant.
    pub fn model(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            variant: None,
        }
    }

    /// Pin a `variant` alongside the model.
    pub fn with_variant(mut self, variant: impl Into<String>) -> Self {
        self.variant = Some(variant.into());
        self
    }

    /// The `--model` argv value: `provider/model`, or `provider/model#variant`.
    /// 2.x has no separate `--variant` flag; the variant rides the `#` suffix
    /// (`opencode run --help`: "provider/model#variant").
    pub fn argv_value(&self) -> String {
        match &self.variant {
            Some(variant) => format!("{}#{variant}", self.model),
            None => self.model.clone(),
        }
    }
}

/// What an opencode member is launched *as*: the binary, the turn kick, the model
/// it runs on, and the directory it runs in. Grouped rather than passed as four
/// more positional arguments to [`OpencodeBackend::new`] — three of the four are
/// strings, and a value in the wrong slot would spawn a plausible, wrong agent.
#[derive(Debug, Clone)]
pub struct OpencodeLaunch {
    /// The `opencode` binary (a bare name is resolved on PATH).
    pub bin: String,
    /// The per-turn kick prompt. opencode's system prompt (the generated agent's
    /// `prompt`) is the protocol + baton bootstrap; this is the turn's "go".
    pub prompt: String,
    /// The model/variant to run on, carried on **argv** (`--model`). This reverses
    /// the 1.18-era choice to pin it in the generated config: 2.x `run` ignores the
    /// agent block's model, so the config copy was never the source. See
    /// [`ModelSelection`].
    pub model: ModelSelection,
    /// The garden root — the member's cwd, so garden docs are ordinary in-project
    /// reads (the finding that drove the interactive seam's slice 006) and the
    /// same root a claude member works from.
    pub garden_root: PathBuf,
}

/// opencode's [`BackendFlavor`]: the five things the shared harness cannot know —
/// the fail-closed pre-approval, the argv, the child's env and cwd, and the NDJSON
/// fold with its run-end settlement.
#[derive(Debug)]
struct OpencodeFlavor {
    launch: OpencodeLaunch,
    hub: EventHub,
    /// Per-member fail-closed pre-approval generator: each spawn writes this
    /// member's `opencode.json` BEFORE exec, so a headless session — which cannot
    /// answer a permission prompt — never dies on a missing rule. Generation
    /// failure ⇒ no spawn (a [`SpawnError`]).
    preapproval: OpencodePreApproval,
    /// Where each run's authoritative totals are read at stdout EOF (module docs,
    /// "Run end").
    ledger: Arc<dyn SessionLedger>,
    /// Per-agent spend + error cells, keyed by agent id; re-spawn replaces the
    /// cell, the same lifecycle the harness gives its own health/rate/stderr cells.
    members: Mutex<BTreeMap<String, Arc<MemberCells>>>,
}

impl OpencodeFlavor {
    fn member(&self, agent: &str) -> Option<Arc<MemberCells>> {
        self.members.lock().unwrap().get(agent).cloned()
    }

    /// `agent`'s accumulated session spend, or the zero reading if it was never
    /// spawned by this backend.
    fn spend(&self, agent: &str) -> AgentSpend {
        self.member(agent)
            .map(|m| m.spend.observe())
            .unwrap_or_default()
    }

    /// `agent`'s rendered `error` events, oldest first, or none.
    fn errors(&self, agent: &str) -> Vec<String> {
        self.member(agent)
            .map(|m| m.errors.lines())
            .unwrap_or_default()
    }
}

/// The `opencode run` invocation that goes AFTER the harness's `systemd-run … --`
/// separator — the argv half that is genuinely opencode's. The wrapper half
/// (scope, `--collect`, `--unit=`, the gentle build caps) is the harness's, shared
/// byte-for-byte with claude.
///
/// Each flag is load-bearing on opencode 2.x (opencode-v2-repin slice 001):
///
/// - `--standalone` gives the member a **private** server, a child that sits in the
///   member's own scope and dies with it (L6). Without it, `run` attaches to the
///   per-user shared service, which **ignores the child's `OPENCODE_CONFIG`**
///   (finding 1). The member would then run as the built-in `build` agent with
///   allow-all plus every global grant, outside its scope, its build caps and the
///   kill path. This is a correctness flag, not hygiene.
/// - `--model` is the only model source `run` honors that fails closed on a bad id
///   (see [`ModelSelection`]).
/// - `--format json` is what makes the output the NDJSON this module's fold parses;
///   without it there is nothing to observe.
fn opencode_command_argv(
    bin: &str,
    prompt: &str,
    agent: &str,
    model: &ModelSelection,
) -> Vec<OsString> {
    vec![
        bin.into(),
        "run".into(),
        "--standalone".into(),
        "--format".into(),
        "json".into(),
        "--agent".into(),
        agent.into(),
        "--model".into(),
        model.argv_value().into(),
        prompt.into(),
    ]
}

/// The environment variable naming the generated per-member config — opencode's
/// analog of claude's `--settings` plus `--mcp-config`, except it is an env var
/// rather than a flag, which is the whole reason [`BackendFlavor::child_env`]
/// exists.
const OPENCODE_CONFIG_ENV: &str = "OPENCODE_CONFIG";

impl BackendFlavor for OpencodeFlavor {
    fn generate_preapproval(&self, agent: &str) -> Result<AgentPaths, SpawnError> {
        self.preapproval
            .generate(agent)
            .map_err(|e| {
                SpawnError(format!(
                    "opencode pre-approval generation failed for agent {agent}: {e}"
                ))
            })
    }

    fn command_argv(
        &self,
        agent: &str,
        _paths: &AgentPaths,
        model: Option<&ModelSelection>,
    ) -> Vec<OsString> {
        // The member id IS the opencode agent name the generated config keys its
        // `agent.<name>` block on — one id names the runtime dir, the baton, and
        // the agent block, so `--agent` can never point at a block that was not
        // just written. `model` overrides the roster default for THIS spawn
        // (queue-v2-scheduling slice 006 — the assignment's resolved `> Model:`
        // choice rides argv `--model`, the one path `run` honors fail-closed).
        opencode_command_argv(
            &self.launch.bin,
            &self.launch.prompt,
            agent,
            model.unwrap_or(&self.launch.model),
        )
    }

    fn child_env(
        &self,
        _agent: &str,
        paths: &AgentPaths,
    ) -> Result<Vec<EnvChange>, crate::supervisor::SpawnError> {
        Ok(vec![(
            OPENCODE_CONFIG_ENV.into(),
            Some(paths.opencode_config.clone().into_os_string()),
        )])
    }

    fn working_dir(&self) -> Option<PathBuf> {
        Some(self.launch.garden_root.clone())
    }

    fn spawned(&self, _agent: &str) {
        // Nothing to commit: opencode picks no account per spawn.
    }

    fn new_observer(&self, agent: &str, rate: Arc<AgentRateState>) -> Box<dyn LineObserver> {
        // Fresh spend + error cells for this spawn, overwriting any prior
        // generation's — so `spend` and the crash reason always read the CURRENT
        // child, the same replace-on-re-roll lifecycle as the harness's own cells.
        let member = Arc::new(MemberCells::default());
        self.members
            .lock()
            .unwrap()
            .insert(agent.to_string(), Arc::clone(&member));
        Box::new(OpencodeSpawnObserver {
            agent: agent.to_string(),
            hub: self.hub.clone(),
            member,
            rate,
            run: Mutex::new(RunState::default()),
            ledger: Arc::clone(&self.ledger),
        })
    }
}

/// The production opencode [`AgentBackend`]: a [`Harness`] bound to an
/// [`OpencodeFlavor`], shelling `opencode run --format json` per member, tailing
/// each child into [`Event::AgentDelta`]s on the shared [`EventHub`], and tracking
/// the per-member state the drive loop reads.
///
/// Structurally identical to [`ClaudeBackend`](crate::claude_backend::ClaudeBackend)
/// — same transient scope, same build caps, same `live_scopes`/`kill_handles`
/// registration, so `force_stop --hard-kill`, `request_restart` and the boot
/// reconciler address an opencode member exactly as they do a claude one. That is
/// not a coincidence: all of it is the harness's, and this type adds only the
/// flavor.
///
/// Implemented for `Arc<OpencodeBackend>` (mirroring claude) so the same `Arc` can
/// be cloned into every seam the [`DriveLoop::new`](crate::drive_loop::DriveLoop)
/// contract requires.
#[derive(Debug)]
pub struct OpencodeBackend {
    /// The shared supervision machinery (scope, health, stderr, rate, registries).
    harness: Harness,
    /// The SAME flavor the harness holds behind its `Arc<dyn BackendFlavor>`, kept
    /// concretely here so the opencode-only spend accessor reaches its cells.
    flavor: Arc<OpencodeFlavor>,
}

impl OpencodeBackend {
    /// A backend launching `launch.bin` per member, publishing deltas to `hub`,
    /// generating each member's `opencode.json` via `preapproval`, and settling
    /// each run's spend against `ledger` (production: [`crate::opencode_ledger::OpencodeDb`]).
    /// The shared `build_caps` / `live_scopes` / `kill_handles` cells are the
    /// daemon's — the same ones a [`ClaudeBackend`](crate::claude_backend::ClaudeBackend)
    /// is given — so `set_resources` and the kill paths reach an opencode member too.
    pub fn new(
        launch: OpencodeLaunch,
        hub: EventHub,
        preapproval: OpencodePreApproval,
        ledger: Arc<dyn SessionLedger>,
        build_caps: Arc<Mutex<BuildCaps>>,
        live_scopes: Arc<Mutex<BTreeMap<String, String>>>,
        kill_handles: Arc<Mutex<BTreeMap<String, LiveKill>>>,
    ) -> Self {
        let flavor = Arc::new(OpencodeFlavor {
            launch,
            hub,
            preapproval,
            ledger,
            members: Mutex::new(BTreeMap::new()),
        });
        Self {
            harness: Harness::new(
                Arc::clone(&flavor) as Arc<dyn BackendFlavor>,
                build_caps,
                live_scopes,
                kill_handles,
            ),
            flavor,
        }
    }

    /// `agent`'s current health (heartbeat-or-exit), or `None` if this backend
    /// never spawned it.
    pub fn health(&self, agent: &str) -> Option<AgentHealth> {
        self.harness.health(agent)
    }

    /// Always `None` — and this is the milestone's one irreversible mistake to
    /// avoid, not an unimplemented stub.
    ///
    /// [`BudgetUsage`] is the **Anthropic account pool** (the 5h/7d subscription
    /// reserve) that gates admission for the claude members. A metered DeepSeek run
    /// has no such windows and opencode reports none, so `None` is the honest
    /// answer: this member simply does not contribute to the fleet aggregate.
    /// Synthesising a percentage here would corrupt the gate governing every other
    /// member (opencode-fleet-backend locked decision 2).
    ///
    /// What opencode *does* report is metered instead: each step's tokens feed the
    /// harness's provider-neutral rolling-minute TPM/RPM meter, and its cost accrues
    /// as [`spend`](Self::spend), settled against opencode's session record at the
    /// run's end.
    pub fn budget(&self, _agent: &str) -> Option<BudgetUsage> {
        None
    }

    /// Always `None`: the reopen instant is the Anthropic rate-limit window's
    /// `resetsAt`, and opencode emits no `rate_limit_event` at all — there is
    /// structurally nothing to report. The metered-provider 429 `retry-after` hold
    /// is spec-agents §7 phase 4, deliberately not invented here.
    pub fn rate_limit_reopen(&self, _agent: &str) -> Option<i64> {
        None
    }

    /// The **fleet-wide** rolling-minute `(tpm_used, rpm_used)` at `now`, summed
    /// across this backend's members. The window is provider-neutral — tokens per
    /// minute mean the same thing on either provider — so unlike `budget` this one
    /// really does report.
    pub fn rate_used(&self, now: i64) -> (u32, u32) {
        self.harness.rate_used(now)
    }

    /// `agent`'s crash reason: its most recent stderr lines (oldest→newest), then
    /// its `error` events. Empty if it was never spawned or reported nothing.
    ///
    /// The `error` events are part of it because opencode reports a failed run on
    /// STDOUT: in `--format json` it emits the `error` event, sets exit 1, and
    /// writes nothing to stderr. The stderr ring alone would page the crash with no
    /// reason. They go last, newest last, so the `AgentCrashed` alert and the
    /// drive loop's network-error classifier read them like stderr.
    pub fn stderr_tail(&self, agent: &str) -> Vec<String> {
        let mut tail = self.harness.stderr_tail(agent);
        tail.extend(self.flavor.errors(agent));
        tail
    }

    /// `agent`'s accumulated session spend (micro-USD + step count), or the zero
    /// reading if it was never spawned. The accounting slice 006 surfaces.
    pub fn spend(&self, agent: &str) -> AgentSpend {
        self.flavor.spend(agent)
    }

    /// The argv this backend would exec for `agent` after the `systemd-run … --`
    /// separator, given the paths a spawn's pre-approval writes — `opencode run
    /// --standalone --format json --agent <id> --model <m> <prompt>`, wrapper
    /// excluded. The routing seam
    /// (slice 005) asserts an opencode-backed member through it. `model` is the
    /// per-spawn override (slice 006), `None` = the roster default.
    pub fn command_argv(
        &self,
        agent: &str,
        paths: &AgentPaths,
        model: Option<&ModelSelection>,
    ) -> Vec<OsString> {
        self.harness.command_argv(agent, paths, model)
    }
}

/// Test-only: accrue spend into a member's cell WITHOUT spawning a child.
///
/// No `opencode` process is ever spawned in tests (the fixtures are the substitute
/// for a live one), and the spend cells are created at spawn — so without this a
/// test can only ever ask the other seams about a member that has never worked.
/// What needs proving is the opposite case: that a member which has genuinely been
/// billed still reports no Anthropic budget and still contributes nothing to the
/// subscription aggregate. This folds through the real [`AgentSpendState`]
/// methods, so what accrues here is what one streamed step (`step_start` +
/// `step_finish`) accrues.
#[cfg(test)]
impl OpencodeBackend {
    pub(crate) fn accrue_spend_for_test(&self, agent: &str, cost_usd: f64) {
        let mut members = self.flavor.members.lock().unwrap();
        let member = members.entry(agent.to_string()).or_default();
        member.spend.record_step();
        member.spend.record_cost(cost_usd);
    }
}

impl AgentBackend for Arc<OpencodeBackend> {
    fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
        self.harness.spawn(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opencode_ledger::{LedgerError, SessionTotals};
    use std::io::Cursor;
    use std::path::Path;
    use std::sync::atomic::AtomicI64;

    /// The real captured runs (see `tests/fixtures/README.md`) — the substitute for
    /// a live `opencode`, so these tests prove the parser against the wire format
    /// rather than against a hand-written guess of it. 1.18.15 is the historical
    /// baseline; 2.0.24 is what the device runs.
    const TEXT_RUN: &str = include_str!("../tests/fixtures/opencode-text-run.jsonl");
    const TOOL_RUN: &str = include_str!("../tests/fixtures/opencode-tool-run.jsonl");
    const TEXT_RUN_2: &str = include_str!("../tests/fixtures/opencode2-text-run.jsonl");
    const TOOL_RUN_2: &str = include_str!("../tests/fixtures/opencode2-tool-run.jsonl");
    const DENIED_RUN_2: &str = include_str!("../tests/fixtures/opencode2-denied-run.jsonl");
    const ASK_RUN_2: &str = include_str!("../tests/fixtures/opencode2-ask-rejected-run.jsonl");
    const ERROR_RUN_2: &str = include_str!("../tests/fixtures/opencode2-error-run.jsonl");

    /// What opencode's `session_v2` recorded for each 2.x fixture run, read back
    /// from the device's store on 2026-10-10 (`tests/fixtures/README.md`, "Session
    /// records"): `(sessionID, cost USD, input + output + reasoning + cache)`.
    const TEXT_RECORD: (&str, f64, u64) = ("ses_edb4e6137ffevobqsOjPLb2ShB", 0.000118278, 141 + 2 + 133 + 5376);
    const TOOL_RECORD: (&str, f64, u64) = ("ses_edb507527ffeDOLsUIum3cdXE1", 0.000429444, 594 + 355 + 154 + 11648);
    const DENIED_RECORD: (&str, f64, u64) = ("ses_edb4f3774ffeeZNTSGtzwiLk1s", 0.001026492, 1438 + 904 + 263 + 36864);
    const ASK_RECORD: (&str, f64, u64) = ("ses_edb4ed3e5ffe1zQESYhNhl1VlN", 0.000221442, 515 + 136 + 48 + 11264);
    const ERROR_RECORD: (&str, f64, u64) = ("ses_edb4eb51cffeuHdYNxtm7br913", 0.0, 0);

    /// A [`SessionLedger`] holding scripted records, counting its reads. An id it
    /// doesn't hold is `NoSession`, the same error a real store gives.
    #[derive(Debug, Default)]
    struct FakeLedger {
        sessions: BTreeMap<String, SessionTotals>,
        reads: AtomicU64,
    }

    impl FakeLedger {
        fn with((id, cost_usd, tokens): (&str, f64, u64)) -> Self {
            let mut ledger = Self::default();
            ledger.sessions.insert(
                id.to_string(),
                SessionTotals {
                    cost_usd,
                    tokens,
                    settled: true,
                },
            );
            ledger
        }

        fn reads(&self) -> u64 {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl SessionLedger for FakeLedger {
        fn totals(&self, session_id: &str) -> Result<SessionTotals, LedgerError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.sessions
                .get(session_id)
                .copied()
                .ok_or_else(|| LedgerError::NoSession {
                    path: PathBuf::from("fake"),
                    session: session_id.to_string(),
                })
        }
    }

    /// A clock that advances `step` seconds once per read: once per line, plus once
    /// at EOF for the run-end settlement.
    ///
    /// The step matters: [`AgentRateState`] meters a **trailing minute**, so a run
    /// whose lines are spread over more than 60 fake seconds will legitimately age
    /// its first samples out. Real opencode steps land seconds apart.
    fn ticking_clock(step: i64) -> impl Fn() -> i64 {
        let clock = AtomicI64::new(0);
        move || clock.fetch_add(step, Ordering::SeqCst) + step
    }

    /// Everything one fixture run leaves behind.
    struct Ran {
        deltas: Vec<Event>,
        health: AgentHealthState,
        member: MemberCells,
        rate: AgentRateState,
    }

    /// Pump `run` through the production fold, one fake second per clock read,
    /// settling against `ledger`.
    fn run(run: &str, ledger: &dyn SessionLedger) -> Ran {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let ran = Ran {
            deltas: Vec::new(),
            health: AgentHealthState::new(0),
            member: MemberCells::default(),
            rate: AgentRateState::default(),
        };
        let now = ticking_clock(1);
        pump(
            Cursor::new(run),
            "a",
            &hub,
            &ran.health,
            &ran.member,
            &ran.rate,
            ledger,
            &now,
        );
        let mut deltas = Vec::new();
        while let Ok(ev) = sub.try_recv() {
            deltas.push(ev);
        }
        Ran { deltas, ..ran }
    }

    fn deltas_for_line(line: &str) -> Vec<(AgentDeltaKind, String)> {
        serde_json::from_str(line)
            .map(|ev| deltas_for(&ev))
            .unwrap_or_default()
    }

    fn step_finish_for_line(line: &str) -> Option<StepFinish> {
        serde_json::from_str(line).ok().as_ref().and_then(step_finish_of)
    }

    #[test]
    fn deltas_for_line_maps_each_event_type_it_carries() {
        let text = r#"{"type":"text","timestamp":1786641917492,"part":{"type":"text","text":"pong"}}"#;
        assert_eq!(
            deltas_for_line(text),
            vec![(AgentDeltaKind::Assistant, "pong".to_string())]
        );

        let tool = r#"{"type":"tool_use","part":{"tool":"read","state":{"status":"completed","title":"garden/hello.txt","input":{"filePath":"/garden/hello.txt"}}}}"#;
        assert_eq!(
            deltas_for_line(tool),
            vec![(AgentDeltaKind::ToolCall, "read(garden/hello.txt)".to_string())]
        );

        // Source-read from 2.0.24 (see `deltas_for`): emitted only under
        // `--thinking`, its text in `part.text`.
        let reasoning = r#"{"type":"reasoning","part":{"type":"reasoning","text":"weighing it"}}"#;
        assert_eq!(
            deltas_for_line(reasoning),
            vec![(AgentDeltaKind::Thinking, "weighing it".to_string())]
        );

        // Turn boundaries, metering lines and errors carry no renderable content; a
        // malformed line, a partless line, and a text part with no text carry none
        // either — and none of them may panic.
        for quiet in [
            r#"{"type":"step_start","part":{"type":"step-start"}}"#,
            r#"{"type":"step_finish","part":{"reason":"stop","cost":0.1}}"#,
            r#"{"type":"error","error":{"type":"provider.no-route","message":"x"}}"#,
            r#"{"type":"text"}"#,
            r#"{"type":"text","part":{"type":"text"}}"#,
            r#"{"type":"unheard_of","part":{"x":1}}"#,
            "not json at all",
            "",
        ] {
            assert!(deltas_for_line(quiet).is_empty(), "unexpected delta: {quiet}");
        }
    }

    #[test]
    fn render_tool_use_names_what_the_call_acts_on_and_is_char_truncated() {
        // 1.18.15: a pre-rendered title label wins.
        let labelled = serde_json::json!({
            "tool": "read",
            "state": {"status": "completed", "title": "garden/hello.txt", "input": {"filePath": "/garden/hello.txt"}},
        });
        assert_eq!(render_tool_use(&labelled), "read(garden/hello.txt)");

        // 2.x: the title only repeats the tool, so the input's `path` names it.
        let v2 = serde_json::json!({
            "tool": "write",
            "state": {"status": "completed", "title": "write", "input": {"content": "r1", "path": "/runtime/r1.txt"}},
        });
        assert_eq!(render_tool_use(&v2), "write(/runtime/r1.txt)");

        // No title and no path → the raw input JSON.
        let raw = serde_json::json!({
            "tool": "shell",
            "state": {"status": "completed", "input": {"command": "ls"}},
        });
        assert_eq!(render_tool_use(&raw), r#"shell({"command":"ls"})"#);

        // No state at all, and an unknown tool name.
        assert_eq!(render_tool_use(&serde_json::json!({"tool": "ls"})), "ls");
        assert_eq!(render_tool_use(&serde_json::json!({})), "tool");

        // A non-completed status is carried, not suppressed.
        let running = serde_json::json!({
            "tool": "bash",
            "state": {"status": "running", "title": "cargo test"},
        });
        assert_eq!(render_tool_use(&running), "bash[running](cargo test)");

        // A huge argument truncates on a char boundary with an ellipsis, never
        // panicking mid-codepoint.
        let big = serde_json::json!({
            "tool": "write",
            "state": {"status": "completed", "title": "é".repeat(500)},
        });
        let rendered = render_tool_use(&big);
        assert!(rendered.chars().count() <= TOOL_RENDER_MAX_CHARS + 1);
        assert!(rendered.ends_with('…'));
        assert!(rendered.starts_with("write("));
    }

    #[test]
    fn step_tokens_are_the_sum_of_their_parts_which_is_the_old_total() {
        // 2.x dropped `total`; the parts remain.
        let v2 = r#"{"type":"step_finish","part":{"reason":"tool-calls","cost":0.000193578,"tokens":{"input":251,"output":167,"reasoning":66,"cache":{"read":5376,"write":0}}}}"#;
        assert_eq!(
            step_finish_for_line(v2),
            Some(StepFinish {
                tokens: 251 + 167 + 66 + 5376,
                cost_usd: 0.000193578
            })
        );

        // On EVERY captured 1.18.15 step, the sum of the parts is exactly the
        // `total` 1.18 reported. Summing therefore meters both versions the same.
        let mut checked = 0;
        for line in TEXT_RUN.lines().chain(TOOL_RUN.lines()) {
            let ev: Value = serde_json::from_str(line).unwrap();
            let Some(step) = step_finish_of(&ev) else { continue };
            let total = ev["part"]["tokens"]["total"].as_u64().unwrap();
            assert_eq!(step.tokens, total, "sum ≠ 1.18 total on {line}");
            checked += 1;
        }
        assert_eq!(checked, 4, "every 1.18.15 step_finish was checked");

        // A step with neither field still meters one request at zero cost — it is a
        // real completed turn. A part missing from `tokens` counts 0.
        assert_eq!(
            step_finish_for_line(r#"{"type":"step_finish","part":{"reason":"stop"}}"#),
            Some(StepFinish {
                tokens: 0,
                cost_usd: 0.0
            })
        );
        assert_eq!(
            step_finish_for_line(r#"{"type":"step_finish","part":{"tokens":{"input":7}}}"#),
            Some(StepFinish {
                tokens: 7,
                cost_usd: 0.0
            })
        );

        // Anything that is not a step_finish meters nothing.
        for other in [
            r#"{"type":"text","part":{"text":"hi"}}"#,
            r#"{"type":"step_start","part":{"type":"step-start"}}"#,
            r#"{"type":"step_finish"}"#,
            "not json at all",
        ] {
            assert_eq!(step_finish_for_line(other), None, "metered: {other}");
        }
    }

    // ---- 1.18.15: the historical baseline ------------------------------------

    #[test]
    fn pump_publishes_the_text_run_and_advances_the_heartbeat() {
        let ran = run(TEXT_RUN, &FakeLedger::default());

        // The one text part reaches the hub as an Assistant delta, and nothing else
        // does. In particular NO BudgetChanged: opencode reports no context gauge
        // and no 5h/7d reserve, and this fold never invents one.
        assert_eq!(
            ran.deltas,
            vec![Event::agent_delta("a", AgentDeltaKind::Assistant, "pong")]
        );

        // Three non-empty lines → three heartbeats; the EOF read is not one.
        assert_eq!(ran.health.last_active(), 3);
        assert_eq!(ran.health.observe(), AgentHealth::Alive { last_active: 3 });

        // One step, closed by its step_finish → one request of 12729 tokens,
        // costing 0.00178248 USD → 1782 µUSD. No session record (1.18 predates
        // `session_v2`), and with no open step nothing more is metered at EOF.
        assert_eq!(ran.rate.window(4), (12729, 1));
        assert_eq!(
            ran.member.spend.observe(),
            AgentSpend {
                micro_usd: 1782,
                steps: 1
            }
        );
    }

    #[test]
    fn pump_meters_every_step_of_a_multi_tool_run_and_sums_the_spend() {
        let ran = run(TOOL_RUN, &FakeLedger::default());

        // Both tool calls render from their pre-rendered titles, in order, then the
        // closing text — and again no BudgetChanged.
        assert_eq!(
            ran.deltas,
            vec![
                Event::agent_delta("a", AgentDeltaKind::ToolCall, "read(garden/hello.txt)"),
                Event::agent_delta("a", AgentDeltaKind::ToolCall, "write(garden/out.txt)"),
                Event::agent_delta("a", AgentDeltaKind::Assistant, "DONE"),
            ]
        );

        // THREE model turns → three metered requests, not one: a multi-tool run is
        // several real API calls (the claude backend meters one per terminal
        // `result`, which opencode does not emit at all).
        assert_eq!(ran.rate.window(10), (11082 + 11322 + 11341, 3));

        // Spend sums across the steps: 0.00156954 + 0.0000939624 + 0.0000427392 USD
        // = 0.0017062416 → 1706 µUSD. Summed in fixed point, so the tiny per-step
        // costs neither round to zero nor drift.
        assert_eq!(
            ran.member.spend.observe(),
            AgentSpend {
                micro_usd: 1706,
                steps: 3
            }
        );

        // Nine non-empty lines → nine heartbeats.
        assert_eq!(ran.health.last_active(), 9);
    }

    #[test]
    fn a_garbage_line_is_skipped_without_ending_the_pump() {
        // A truncated JSON line (a partial write at EOF is normal), a blank line,
        // and a plain-text line are all interleaved into a real run. None of them
        // may kill the fold or cost the run its metering.
        let mixed = format!(
            "{}\n{}\n\n{}\n{}",
            r#"{"type":"text","part":{"type":"text","text":"before"}}"#,
            r#"{"type":"step_finish","part":{"reason":"tool-calls","toke"#,
            "opencode: something unstructured on stdout",
            TEXT_RUN.trim(),
        );

        let ran = run(&mixed, &FakeLedger::default());

        // The pump ran to EOF: the deltas on BOTH sides of the garbage arrived.
        assert_eq!(
            ran.deltas,
            vec![
                Event::agent_delta("a", AgentDeltaKind::Assistant, "before"),
                Event::agent_delta("a", AgentDeltaKind::Assistant, "pong"),
            ]
        );

        // Six non-empty lines (the blank one is skipped by the harness, and even
        // the unparseable ones are signs of life) → six heartbeats.
        assert_eq!(ran.health.last_active(), 6);
        // Only the one WELL-FORMED step_finish metered; the truncated one did not.
        assert_eq!(ran.rate.window(7), (12729, 1));
        assert_eq!(ran.member.spend.observe().steps, 1);
    }

    // ---- 2.0.24: what the device runs ----------------------------------------

    #[test]
    fn a_2x_text_run_streams_no_cost_and_settles_from_the_session_record() {
        // The whole run is one step, and 2.x streams no `step_finish` for a final
        // step: `step_start`, `text`, EOF. Without the run-end settlement this
        // member would read $0 and meter zero requests.
        let ledger = FakeLedger::with(TEXT_RECORD);
        let ran = run(TEXT_RUN_2, &ledger);

        assert_eq!(
            ran.deltas,
            vec![Event::agent_delta("a", AgentDeltaKind::Assistant, "OK")]
        );
        assert_eq!(ledger.reads(), 1, "settled once, at EOF");
        // 0.000118278 USD → 118 µUSD; one step, counted at its start.
        assert_eq!(
            ran.member.spend.observe(),
            AgentSpend {
                micro_usd: 118,
                steps: 1
            }
        );
        // The open step meters at EOF (clock 3) with every token the record holds.
        assert_eq!(ran.rate.window(3), (TEXT_RECORD.2, 1));
        assert_eq!(ran.health.last_active(), 2, "the EOF read is not a heartbeat");
    }

    #[test]
    fn a_2x_tool_run_meters_its_streamed_step_then_the_final_one_at_exit() {
        let ledger = FakeLedger::with(TOOL_RECORD);
        let ran = run(TOOL_RUN_2, &ledger);

        // 2.x tool titles are just the tool name, so the render names the path.
        assert_eq!(ran.deltas.len(), 4);
        assert_eq!(
            ran.deltas[..3],
            [
                Event::agent_delta("a", AgentDeltaKind::Assistant, "I'll perform both write operations."),
                Event::agent_delta("a", AgentDeltaKind::ToolCall, "write(/tmp/oc-probe-other/r1.txt)"),
                Event::agent_delta("a", AgentDeltaKind::ToolCall, "write(/runtime/r1.txt)"),
            ]
        );

        // Two requests: the streamed step (251+167+66+5376 = 5860 tokens) and the
        // final one, metered at EOF with what the record holds beyond the stream.
        let streamed = 251 + 167 + 66 + 5376;
        assert_eq!(ran.rate.window(9), (TOOL_RECORD.2, 2));
        assert!(TOOL_RECORD.2 > streamed, "the final step was real traffic");
        // Streamed $0.000194 is raised to the recorded $0.000429 (slice 001's
        // under-report, closed).
        assert_eq!(
            ran.member.spend.observe(),
            AgentSpend {
                micro_usd: 429,
                steps: 2
            }
        );
    }

    #[test]
    fn a_2x_denied_run_renders_each_refusal_with_its_reason() {
        let ran = run(DENIED_RUN_2, &FakeLedger::with(DENIED_RECORD));

        let calls: Vec<String> = ran
            .deltas
            .iter()
            .filter_map(|e| match e {
                Event::AgentDelta { kind: AgentDeltaKind::ToolCall, text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            calls,
            [
                "write[error](/garden/new.md): Permission denied: edit",
                "write[error](new2.md): Permission denied: edit",
                "write[error](sub/deep.md): Permission denied: edit",
                "edit[error](note.md): Permission denied: edit",
                "write(/runtime/baton.md)",
            ]
        );
        // A refused tool is the model's business, not a member failure: no crash
        // reason is recorded.
        assert!(ran.member.errors.lines().is_empty());

        // Six steps: five streamed, the final one settled.
        assert_eq!(ran.rate.window(30), (DENIED_RECORD.2, 6));
        assert_eq!(
            ran.member.spend.observe(),
            AgentSpend {
                micro_usd: 1026,
                steps: 6
            }
        );
    }

    #[test]
    fn a_2x_headless_ask_is_rejected_as_a_refused_call_not_a_hang() {
        let ran = run(ASK_RUN_2, &FakeLedger::with(ASK_RECORD));

        let Event::AgentDelta { kind, text, .. } = &ran.deltas[0] else {
            panic!("a tool delta first: {:?}", ran.deltas);
        };
        assert_eq!(*kind, AgentDeltaKind::ToolCall);
        // The path survives truncation; the rejection reason follows it.
        assert!(
            text.starts_with(
                "read[error](/var/tmp/oc-probe-ask/hello.txt): This non-interactive run cannot ask"
            ),
            "{text}"
        );
        assert!(ran.member.errors.lines().is_empty());
        assert_eq!(ran.rate.window(6), (ASK_RECORD.2, 2));
        assert_eq!(ran.member.spend.observe().micro_usd, 221);
    }

    #[test]
    fn a_2x_error_event_becomes_the_crash_reason() {
        // `--model deepseek/deepseek-v4-flash` (gone): one top-level `error`, no
        // `part`, exit 1, nothing on stderr.
        let ran = run(ERROR_RUN_2, &FakeLedger::with(ERROR_RECORD));

        assert!(ran.deltas.is_empty(), "an error is not narration");
        assert_eq!(
            ran.member.errors.lines(),
            ["opencode error [provider.no-route]: Model unavailable: deepseek/deepseek-v4-flash"]
        );
        // No step ever started: nothing metered, nothing spent.
        assert_eq!(ran.rate.window(2), (0, 0));
        assert_eq!(ran.member.spend.observe(), AgentSpend::default());

        // An error with no message keeps its raw JSON.
        let bare: Value = serde_json::from_str(r#"{"type":"error","error":{"type":"aborted"}}"#).unwrap();
        assert_eq!(
            error_of(&bare).unwrap(),
            r#"opencode error [aborted]: {"type":"aborted"}"#
        );
    }

    #[test]
    fn an_unreadable_session_record_keeps_the_streamed_lower_bound() {
        // The store is missing, locked or drifted: the member keeps what streamed,
        // and its open final step still counts as a request, at unknown tokens.
        let ledger = FakeLedger::default();
        let ran = run(TOOL_RUN_2, &ledger);

        assert_eq!(ledger.reads(), 1);
        assert_eq!(ran.rate.window(9), (251 + 167 + 66 + 5376, 2));
        assert_eq!(
            ran.member.spend.observe(),
            AgentSpend {
                micro_usd: 193,
                steps: 2
            }
        );
    }

    #[test]
    fn a_stale_record_can_never_lower_what_streamed() {
        // A record read before opencode projected the run (lower than the stream):
        // spend keeps the streamed floor, and no negative residual is metered.
        let ledger = FakeLedger::with((TOOL_RECORD.0, 0.0001, 100));
        let ran = run(TOOL_RUN_2, &ledger);

        assert_eq!(ran.member.spend.observe().micro_usd, 193);
        assert_eq!(ran.rate.window(9), (251 + 167 + 66 + 5376, 2));
    }

    #[test]
    fn a_child_that_never_named_a_session_settles_nothing() {
        let ledger = FakeLedger::default();
        let ran = run("opencode: crashed before starting\n", &ledger);

        assert_eq!(ledger.reads(), 0, "no session to look up");
        assert_eq!(ran.rate.window(2), (0, 0));
        assert_eq!(ran.health.last_active(), 1, "the stray line was still a heartbeat");
    }

    #[test]
    fn an_unknown_event_type_is_a_heartbeat_and_never_fatal() {
        // 2.x is moving fast: a kind this fold has never seen, with or without a
        // `part`, lands mid-run. The run around it folds exactly as without it.
        let mut lines: Vec<&str> = TOOL_RUN_2.lines().collect();
        lines.insert(
            2,
            r#"{"type":"session_compacted","timestamp":1,"sessionID":"ses_edb507527ffeDOLsUIum3cdXE1","part":{"type":"compaction"}}"#,
        );
        lines.insert(4, r#"{"type":"brand_new","sessionID":"ses_other"}"#);
        let ran = run(&lines.join("\n"), &FakeLedger::with(TOOL_RECORD));

        assert_eq!(ran.deltas.len(), 4, "the same four deltas");
        assert_eq!(ran.health.last_active(), 9, "seven fixture lines + two unknown");
        assert_eq!(ran.rate.window(11), (TOOL_RECORD.2, 2));
        assert_eq!(ran.member.spend.observe().micro_usd, 429);
        assert!(ran.member.errors.lines().is_empty());
    }

    #[test]
    fn spend_is_fixed_point_and_settling_only_ever_raises_it() {
        let spend = AgentSpendState::default();
        spend.record_step();
        spend.record_cost(0.001); // 1000 µUSD
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -5.0] {
            spend.record_cost(bad);
        }
        // The garbage contributed nothing to the total.
        assert_eq!(
            spend.observe(),
            AgentSpend {
                micro_usd: 1000,
                steps: 1
            }
        );

        // A lower or malformed record changes nothing; a higher one raises it.
        for lower in [0.0005, f64::NAN, -1.0] {
            spend.settle(lower);
            assert_eq!(spend.observe().micro_usd, 1000);
        }
        spend.settle(0.0025);
        assert_eq!(spend.observe().micro_usd, 2500);
    }

    // ---- slice 004: the backend ---------------------------------------------

    /// Build a production [`OpencodeFlavor`] rooted at `tmp` — the real type the
    /// harness holds, so these assertions are about what actually spawns.
    fn flavor(tmp: &Path, garden: &Path) -> OpencodeFlavor {
        OpencodeFlavor {
            launch: OpencodeLaunch {
                bin: "opencode".to_string(),
                prompt: "kick".to_string(),
                model: ModelSelection::model("deepseek/deepseek-flash").with_variant("high"),
                garden_root: garden.to_path_buf(),
            },
            hub: EventHub::new(),
            preapproval: OpencodePreApproval::new(
                tmp.join("agents"),
                garden,
                garden.join("growlight/protocol-fleet.md"),
                tmp.join("runtime"),
                PathBuf::from("softfig-mcp"),
                tmp.join(".claude"),
                tmp.join("opencode-data"),
            ),
            ledger: Arc::new(FakeLedger::default()),
            members: Mutex::new(BTreeMap::new()),
        }
    }

    fn backend(tmp: &Path, garden: &Path) -> Arc<OpencodeBackend> {
        let f = flavor(tmp, garden);
        Arc::new(OpencodeBackend::new(
            f.launch.clone(),
            f.hub.clone(),
            f.preapproval.clone(),
            Arc::clone(&f.ledger),
            Arc::new(Mutex::new(BuildCaps::default())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
        ))
    }

    #[test]
    fn the_spawn_argv_wraps_opencode_run_in_the_same_transient_user_scope_as_claude() {
        let tmp = tempfile::tempdir().unwrap();
        let f = flavor(tmp.path(), Path::new("/garden"));
        let paths = crate::preapproval::agent_paths(&tmp.path().join("agents"), "a1");
        // Composed through the PRODUCTION combinator with the PRODUCTION halves —
        // `Harness::spawn` shells exactly this join, so there is no second path
        // that could drift. No `systemd-run` and no `opencode` are executed.
        let argv = crate::agent_harness::spawn_argv(
            &crate::agent_harness::scope_base_name_gen("a1", 7),
            &BuildCaps::default(),
            f.command_argv("a1", &paths, None),
        );
        let s: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();

        // The wrapper half is the harness's, shared byte-for-byte with claude.
        assert_eq!(s[0], "systemd-run");
        assert!(s.contains(&"--user".to_string()));
        assert!(s.contains(&"--scope".to_string()));
        assert!(s.contains(&"--collect".to_string()));
        assert!(s.contains(&"--unit=growlight-agent-a1-7".to_string()));

        // The command half is opencode's, after the `--`.
        let sep = s.iter().position(|a| a == "--").expect("a `--` separates wrapper from command");
        assert_eq!(
            &s[sep + 1..],
            &[
                "opencode".to_string(),
                "run".to_string(),
                "--standalone".to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--agent".to_string(),
                "a1".to_string(),
                "--model".to_string(),
                "deepseek/deepseek-flash#high".to_string(),
                "kick".to_string(),
            ],
            "the opencode invocation, prompt last",
        );
    }

    #[test]
    fn a_member_runs_on_a_private_server_or_its_config_is_ignored() {
        // opencode 2.x (slice 001 finding 1): without `--standalone`, `run` attaches
        // to the per-user shared service, which IGNORES the child's OPENCODE_CONFIG.
        // The member would silently run as the built-in `build` agent (allow-all +
        // every global grant), in a server outside its scope and the kill path.
        let tmp = tempfile::tempdir().unwrap();
        let f = flavor(tmp.path(), Path::new("/garden"));
        let paths = crate::preapproval::agent_paths(&tmp.path().join("agents"), "a1");
        let argv = f.command_argv("a1", &paths, None);
        assert_eq!(argv[1], "run");
        assert_eq!(argv[2], "--standalone", "the flag sits right after the subcommand");
        assert_eq!(
            argv.iter().filter(|a| *a == "--server").count(),
            0,
            "never pointed at a shared server: {argv:?}",
        );
    }

    #[test]
    fn the_model_rides_argv_because_run_ignores_the_agent_block() {
        // slice 001 L7: `run` ignores `agent.<id>.model`, even a valid one, and a
        // config-borne bad id silently falls back to opencode/exo-free and SENDS
        // the prompt. argv `--model` is the only path that fails closed (L5).
        let tmp = tempfile::tempdir().unwrap();
        let f = flavor(tmp.path(), Path::new("/garden"));
        let paths = crate::preapproval::agent_paths(&tmp.path().join("agents"), "a1");
        let argv: Vec<String> = f
            .command_argv("a1", &paths, None)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let at = argv.iter().position(|a| a == "--model").expect("--model on argv");
        assert_eq!(argv[at + 1], "deepseek/deepseek-flash#high", "variant rides the # suffix");
        assert!(!argv.contains(&"--variant".to_string()), "2.x has no --variant flag");

        // A selection with no variant passes the bare id: no trailing `#`.
        assert_eq!(
            ModelSelection::model("deepseek/deepseek-v4-pro").argv_value(),
            "deepseek/deepseek-v4-pro",
        );
    }

    #[test]
    fn a_per_spawn_model_override_replaces_the_roster_default_on_argv() {
        // queue-v2-scheduling slice 006: the assignment's resolved `> Model:`
        // choice overrides the roster default for THIS spawn — the override rides
        // the same argv `--model` slot, so `run`'s model source stays the one that
        // fails closed. `None` keeps the roster default (proven above).
        let tmp = tempfile::tempdir().unwrap();
        let f = flavor(tmp.path(), Path::new("/garden"));
        let paths = crate::preapproval::agent_paths(&tmp.path().join("agents"), "a1");
        let argv: Vec<String> = f
            .command_argv(
                "a1",
                &paths,
                Some(&ModelSelection::model("deepseek/deepseek-v4-pro")),
            )
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let at = argv.iter().position(|a| a == "--model").expect("--model on argv");
        assert_eq!(
            argv[at + 1],
            "deepseek/deepseek-v4-pro",
            "the override replaces the roster default (deepseek/deepseek-flash#high)",
        );
    }

    #[test]
    fn the_child_carries_opencode_config_and_runs_in_the_garden() {
        let tmp = tempfile::tempdir().unwrap();
        let garden = Path::new("/garden");
        let f = flavor(tmp.path(), garden);
        let paths = crate::preapproval::agent_paths(&tmp.path().join("agents"), "a1");

        // OPENCODE_CONFIG names THIS member's generated file — opencode's analog of
        // claude's `--settings`, and an env var rather than a flag, which is why
        // the harness seam carries an env at all.
        let env = f.child_env("a1", &paths).expect("opencode child_env never fails");
        assert_eq!(env.len(), 1, "one variable, nothing incidental: {env:?}");
        assert_eq!(env[0].0, OsString::from("OPENCODE_CONFIG"));
        assert_eq!(env[0].1, Some(paths.opencode_config.clone().into_os_string()));
        assert!(
            paths.opencode_config.ends_with("agents/a1/opencode.json"),
            "the per-member config, not a shared one: {}",
            paths.opencode_config.display(),
        );

        // cwd is the garden root, so garden docs are ordinary in-project reads
        // (interactive seam slice 006) and everything else needs an explicit
        // `external_directory` grant.
        assert_eq!(f.working_dir(), Some(garden.to_path_buf()));
    }

    #[test]
    fn spawn_fails_closed_when_pre_approval_cannot_be_generated() {
        // A FILE where the agents dir should be → the per-member dir can't be
        // created → generation fails BEFORE `opencode` is ever exec'd, so the spawn
        // returns a SpawnError and NO member is registered (no doomed headless
        // session, which for opencode means one that dies on its first edit).
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let backend = Arc::new(OpencodeBackend::new(
            OpencodeLaunch {
                bin: "opencode".to_string(),
                prompt: "kick".to_string(),
                model: ModelSelection::model("deepseek/deepseek-flash"),
                garden_root: tmp.path().to_path_buf(),
            },
            EventHub::new(),
            OpencodePreApproval::new(
                &blocker, // agents_dir is a FILE → create_dir_all under it fails
                tmp.path(),
                tmp.path().join("growlight/protocol-fleet.md"),
                tmp.path().to_path_buf(),
                PathBuf::from("softfig-mcp"),
                tmp.path().join(".claude"),
                tmp.path().join("opencode-data"),
            ),
            Arc::new(FakeLedger::default()),
            Arc::new(Mutex::new(BuildCaps::default())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
        ));
        let spec = AgentSpec::new("a1", blocker.join("a1/loop.json"), blocker.join("a1/mcp.json"));

        let err = backend.spawn(&spec).expect_err("generation failure ⇒ no spawn");
        assert!(
            err.0.contains("opencode pre-approval generation failed"),
            "fail-closed spawn error names its own generator: {err}",
        );
        // Nothing was registered — the member never entered the fleet.
        assert!(backend.health("a1").is_none(), "no doomed member registered");
        assert!(
            backend.spend("a1") == AgentSpend::default(),
            "a fail-closed spawn accrues no spend",
        );
    }

    #[test]
    fn one_arc_fills_every_seam_the_drive_loop_consumes() {
        use crate::drive_loop::{AgentHealthSource, AgentStderrSource, BudgetSampleSource};

        let tmp = tempfile::tempdir().unwrap();
        let backend = backend(tmp.path(), Path::new("/garden"));
        // The `DriveLoop::new` contract: the SAME Arc behind every seam, so health,
        // stderr and budget are read off the same cells the supervisor spawns
        // through. Clones of one Arc, exactly as `assemble_fleet` wires claude.
        let spawner: Box<dyn AgentBackend> = Box::new(Arc::clone(&backend));
        let health: Box<dyn AgentHealthSource> = Box::new(Arc::clone(&backend));
        let stderr: Box<dyn AgentStderrSource> = Box::new(Arc::clone(&backend));
        let samples: Box<dyn BudgetSampleSource> = Box::new(Arc::clone(&backend));

        // An unspawned member reads as absent through every seam rather than
        // panicking or inventing a value.
        assert!(health.health("a1").is_none());
        assert!(stderr.stderr_tail("a1").is_empty());
        assert!(samples.budget("a1").is_none());
        assert!(samples.rate_limit_reopen("a1").is_none());
        // The spawner is the same object; drop it explicitly so the binding is not
        // merely unused.
        drop(spawner);
    }

    #[test]
    fn a_members_error_events_reach_the_crash_alert_through_its_stderr_tail() {
        use crate::drive_loop::AgentStderrSource;

        let tmp = tempfile::tempdir().unwrap();
        let backend = backend(tmp.path(), Path::new("/garden"));
        // The cells a spawn installs, folded through the production observer the
        // reader thread holds: an error run, then EOF.
        let observer = backend
            .flavor
            .new_observer("a1", Arc::new(AgentRateState::default()));
        for line in ERROR_RUN_2.lines() {
            observer.observe(line, 1);
        }
        observer.finish(2);

        // The drive loop reads the crash reason through this seam for the
        // `AgentCrashed` alert and the network classifier. opencode wrote nothing
        // to stderr, so without the fold the alert would carry no reason at all.
        let source: Box<dyn AgentStderrSource> = Box::new(Arc::clone(&backend));
        assert_eq!(
            source.stderr_tail("a1"),
            ["opencode error [provider.no-route]: Model unavailable: deepseek/deepseek-v4-flash"]
        );
        // A different member's tail is its own.
        assert!(source.stderr_tail("a2").is_empty());

        // A re-spawn replaces the cells: the next run starts with no reason.
        let _ = backend
            .flavor
            .new_observer("a1", Arc::new(AgentRateState::default()));
        assert!(source.stderr_tail("a1").is_empty());
    }

    #[test]
    fn opencode_never_contributes_a_synthetic_anthropic_reserve() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = backend(tmp.path(), Path::new("/garden"));
        // The milestone's one irreversible mistake: a synthesized 5h/7d percentage
        // here would corrupt the admission gate governing the CLAUDE members. There
        // is no cell to read and no code path that could produce one — `None` is
        // structural, not "not implemented yet".
        assert!(backend.budget("a1").is_none());
        assert!(backend.rate_limit_reopen("a1").is_none());
        // What opencode does report IS metered: the provider-neutral rolling-minute
        // window is live from the first spawn (zero until one meters).
        assert_eq!(backend.rate_used(1_000), (0, 0));
    }
}
