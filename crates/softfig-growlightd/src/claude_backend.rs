//! The claude backend — the `claude -p` **flavor** bound to the backend-agnostic
//! [`crate::agent_harness`] (spec-growlight-orchestrator §12 backend decision,
//! §15 operational must-haves).
//!
//! [`ClaudeBackend`] shells `claude -p --output-format stream-json --verbose` per
//! agent, each with its per-agent pre-approval `--settings`/`--mcp-config` (the
//! §15 must-have: a headless agent **errors out** on a missing allow-rule, it does
//! not pause — so each agent must pre-approve its full toolset).
//!
//! ## What lives here vs in the harness
//!
//! Since opencode-fleet-backend slice 001 this module holds ONLY what is specific
//! to claude's CLI and wire format — the three [`BackendFlavor`] methods:
//!
//! - **argv** ([`claude_command_argv`]) — the `claude -p … --output-format
//!   stream-json --verbose` invocation that goes after `systemd-run … --`.
//! - **pre-approval** ([`PreApproval`]) — the fail-closed per-agent
//!   `loop.json`/`mcp.json` generation.
//! - **the per-line fold** ([`observe_claude_line`]) — stream-json parsing:
//!   assistant / thinking / tool_use content blocks published as
//!   [`Event::AgentDelta`]s on the shared [`EventHub`], the account-wide 5h/7d
//!   reserve folded out of `rate_limit_event` lines, and the terminal `result`
//!   line's context gauge + token cost.
//!
//! Everything else — the transient systemd user scope, the heartbeat, the bounded
//! stderr ring, the rolling-minute rate meter, the live scope + kill registries,
//! and the two reader threads — is [`crate::agent_harness::Harness`]'s, shared
//! with every other backend. See that module for the incidents it encodes.
//!
//! ## The account-wide reserve is claude's, not the harness's
//!
//! [`AgentBudgetState`] deliberately stays here: the 5h/7d reserve is the
//! **Anthropic** account pool that gates admission. A non-Anthropic backend must
//! report `budget() → None` rather than synthesize a reading into that aggregate
//! (opencode-fleet-backend locked decision), so the cell belongs to this flavor.
//!
//! ## Time
//!
//! The pure policy ([`crate::supervisor::Supervisor`] / its `classify`) stays
//! time-injected. The harness stamps each line's arrival once and hands it to the
//! fold below, so the parse + publish pipeline is unit-proven with a scripted
//! fixture and a fake clock — no real `claude` is ever spawned in tests (the §7b
//! on-device run is the human's).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use softfig_ipc::growlightd::{AgentDeltaKind, Event};

use crate::admission::BudgetUsage;
use crate::agent_harness::{
    AgentRateState, BackendFlavor, Harness, LineObserver, TOOL_RENDER_MAX_CHARS, truncate_chars,
};
use crate::config::BuildCaps;
use crate::control::{AgentChild, LiveKill};
use crate::hub::EventHub;
use crate::preapproval::{AgentPaths, PreApproval};
use crate::supervisor::{AgentBackend, AgentHealth, AgentSpec, SpawnError};

// Imports for the test-only claude-shaped `pump` seam below, which wires borrowed
// cells into the harness's line loop so a fixture drives the real pipeline.
#[cfg(test)]
use crate::agent_harness::AgentHealthState;
#[cfg(test)]
use std::io::BufRead;

// The rendered-tool-call cap + its char-safe truncation are provider-neutral and
// live in the harness ([`crate::agent_harness::TOOL_RENDER_MAX_CHARS`] /
// [`truncate_chars`]), shared with every other flavor's renderer.

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
/// percentage (see [`observe_claude_line`] / [`rate_limit_window_for_line`]). A
/// terminal `result` line carrying a `rate_limits` object is honored too, as an
/// opportunistic bonus. The reader thread writes it; the drive loop reads it via
/// [`ClaudeBackend::budget`] to feed the cross-agent
/// [`crate::usage::UsageAggregator`]. Sibling to
/// [`crate::agent_harness::AgentHealthState`] — health (heartbeat/exit) and
/// budget (reserve) are decoupled observations of one agent.
///
/// **Claude-specific by design** (slice 001): this is the Anthropic account pool.
/// A non-Anthropic backend reports no reading rather than synthesizing one into
/// the aggregate that governs the claude members.
#[derive(Debug, Default)]
pub struct AgentBudgetState {
    /// The two windows' latest reserve %, accumulated across the per-window events.
    inner: Mutex<ReserveCell>,
}

/// A bounded fail-safe hold applied when a window is hard-`rejected` but the wire
/// reported no `resetsAt` (task 037 fix ①). The true reopen is unknown, so the
/// backend pins a concrete `now + RATE_LIMIT_FALLBACK_HOLD_SECS` deadline into the
/// cell at parse time — a FIXED future instant (not re-derived each tick, which
/// would never elapse), so the drive loop's hold self-clears at `now >= it` and the
/// member re-probes with a single spawn. Five minutes: a genuine multi-hour
/// exhaustion re-probes only a handful of times an hour (vs the ~1/tick spin that
/// burns the shared pool — the regression the task-031 forget would otherwise enable
/// now that the deleted `--auto` no-reset hard-stop is gone), while a transient or
/// misreported trip resumes promptly. The real-`resetsAt` path holds to the true
/// boundary and ignores this.
const RATE_LIMIT_FALLBACK_HOLD_SECS: i64 = 300;

/// One rate-limit window's current TRIP — present only when the window's latest
/// status is hard-`rejected` (the window is CLOSED). A `warning` saturates the
/// window's pct (so it throttles the live aggregate) but is deliberately NOT a
/// trip: it never latches a timed hold (task 037 fix ②). `reopen` is the concrete
/// instant (unix secs) admission may re-probe the window: the wire's `resetsAt`
/// when it gave one, else a pinned `now + RATE_LIMIT_FALLBACK_HOLD_SECS` fail-safe
/// (fix ①). Always concrete — never re-derived — so the hold reliably elapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowTrip {
    reopen: i64,
}

/// Each window's latest reserve %, `None` until first reported. A `rate_limit_event`
/// arrives **per window** (a separate line for `five_hour` / `seven_day`), so the
/// cell accumulates them and derives the combined [`BudgetUsage`] on read.
#[derive(Debug, Default, Clone, Copy)]
struct ReserveCell {
    five_h_pct: Option<u8>,
    seven_d_pct: Option<u8>,
    /// Each window's current [`WindowTrip`] — `Some` only while the window's latest
    /// status is hard-`rejected`, cleared by a later `warning`/`allowed` reading.
    /// Its `reopen` is a concrete future instant that self-clears (`now >= reopen`),
    /// so retaining the trip past the reporting agent's exit can never wedge
    /// admission (unlike the pct the task-031 forget drops). Only a `rejected` window
    /// sets this — a `warning` updates the pct but leaves the trip `None` (fix ②).
    five_h_trip: Option<WindowTrip>,
    seven_d_trip: Option<WindowTrip>,
}

impl AgentBudgetState {
    /// Record one window's latest reserve % + its [`WindowTrip`] (from a
    /// `rate_limit_event`). The trip is `Some` only for a hard-`rejected` window
    /// (carrying its `resetsAt` if the wire gave one); a `warning`/`allowed` reading
    /// passes `None`, clearing any prior trip — the pct still gates via the aggregate
    /// while the reporting agent is live, but no timed hold latches (task 037 fix ②).
    fn record_window(&self, window: BudgetWindow, pct: u8, trip: Option<WindowTrip>) {
        let mut cell = self.inner.lock().unwrap();
        match window {
            BudgetWindow::FiveHour => {
                cell.five_h_pct = Some(pct);
                cell.five_h_trip = trip;
            }
            BudgetWindow::SevenDay => {
                cell.seven_d_pct = Some(pct);
                cell.seven_d_trip = trip;
            }
        }
    }

    /// Record a full 5h/7d reserve at once — the opportunistic `result`-line bonus.
    /// `rejected` is each window's hard-`rejected` status from the same result line;
    /// a rejected window with no preceding `rate_limit_event` marks a no-reset trip
    /// so it fail-safe holds rather than spins (task 037 fix ①, the result-line path).
    /// Additive: it never downgrades a known-reset trip an event already set (result
    /// lines carry no `resetsAt`), and a non-rejected window leaves the trip alone —
    /// the event path owns clearing.
    fn record_reserve(&self, reserve: BudgetUsage, rejected: [bool; 2], now: i64) {
        let mut cell = self.inner.lock().unwrap();
        cell.five_h_pct = Some(reserve.session_5h_pct);
        cell.seven_d_pct = Some(reserve.session_7d_pct);
        // A result line carries no `resetsAt`, so a newly-rejected window pins the
        // bounded fail-safe reopen off `now` (fix ①).
        let fallback = WindowTrip {
            reopen: now + RATE_LIMIT_FALLBACK_HOLD_SECS,
        };
        if rejected[0] && cell.five_h_trip.is_none() {
            cell.five_h_trip = Some(fallback);
        }
        if rejected[1] && cell.seven_d_trip.is_none() {
            cell.seven_d_trip = Some(fallback);
        }
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

    /// The instant admission may re-probe this member's rejected windows — the LATER
    /// of the 5h/7d [`WindowTrip`] reopens (admission clears only once every rejected
    /// window has reopened), or `None` when no window is rejected. Each reopen is a
    /// concrete instant (the wire's `resetsAt` or a pinned fail-safe). Only a
    /// hard-`rejected` status trips a window, so a `warning` never appears here (task
    /// 037 fix ②); its pct still gates the aggregate while the agent is live.
    fn rate_limit_reopen(&self) -> Option<i64> {
        let cell = *self.inner.lock().unwrap();
        [cell.five_h_trip, cell.seven_d_trip]
            .into_iter()
            .flatten()
            .map(|trip| trip.reopen)
            .max()
    }
}

/// Sum of the `usage` token fields on a stream-json `result` line — the per-turn
/// token cost feeding the rolling TPM meter, and a one-request RPM tick. `None`
/// for a non-`result` line or malformed JSON; `Some(0)` for a `result` with no
/// (or an empty) `usage` object (the turn still counts as one request). Sums the
/// same four fields [`ctx_pct_from_result`] uses for occupancy. Pure — a fixture
/// drives it, no real spawn.
fn result_usage_tokens(line: &str) -> Option<u64> {
    let ev = serde_json::from_str::<Value>(line).ok()?;
    if ev.get("type").and_then(Value::as_str) != Some("result") {
        return None;
    }
    let tokens = ev
        .get("usage")
        .and_then(Value::as_object)
        .map(|usage| {
            [
                "input_tokens",
                "output_tokens",
                "cache_read_input_tokens",
                "cache_creation_input_tokens",
            ]
            .iter()
            .filter_map(|k| usage.get(*k).and_then(Value::as_u64))
            .sum()
        })
        .unwrap_or(0);
    Some(tokens)
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
    let rendered = if input.is_empty() || input == "null" {
        name.to_string()
    } else {
        format!("{name}({input})")
    };
    truncate_chars(&rendered, TOOL_RENDER_MAX_CHARS)
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
    /// Each reserve window's hard-`rejected` status `[five_hour, seven_day]` from
    /// the same `rate_limits` object — carried so a rejected result-line window
    /// fail-safe holds (task 037 fix ①) while a `warning` does not (fix ②).
    /// `[false, false]` when no reserve object was present.
    pub reserve_rejected: [bool; 2],
}

/// Parse a stream-json `result` line into the [`AgentBudgetReading`] it carries,
/// or `None` for a non-`result` line, malformed JSON, or a result with nothing
/// budget-relevant. Pure — a fixture drives it, no real spawn.
///
/// The per-agent **context %** is computed from the reliable `usage` token counts
/// over `modelUsage.<model>.contextWindow`. The account-wide **5h/7d reserve** is
/// read best-effort from a `rate_limits` object on the result IF present — the
/// opportunistic bonus; the reliable headless source is the per-window
/// `rate_limit_event` line, folded separately in [`observe_claude_line`].
fn budget_for_result_line(line: &str) -> Option<AgentBudgetReading> {
    let ev = serde_json::from_str::<Value>(line).ok()?;
    if ev.get("type").and_then(Value::as_str) != Some("result") {
        return None;
    }
    let reserve = reserve_from_result(&ev);
    let reading = AgentBudgetReading {
        ctx_pct: ctx_pct_from_result(&ev),
        reserve: reserve.map(|(usage, _)| usage),
        reserve_rejected: reserve.map_or([false, false], |(_, rejected)| rejected),
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
/// Returns `(window, pct, rejected, resets_at)`: `rejected` is the hard-`rejected`
/// status (only that latches a hold — fix ②; [`observe_claude_line`] builds the
/// [`WindowTrip`] since it owns the clock the no-`resetsAt` fail-safe needs, fix ①),
/// `resets_at` the wire's reopen when present.
fn rate_limit_window_for_line(line: &str) -> Option<(BudgetWindow, u8, bool, Option<i64>)> {
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
    // The window's reopen time — the reliable headless signal for the timed-resume
    // (task 037). Present on both `rejected` and `allowed` events; acted on only for
    // a rejected window (an allowed window is open, so its reset is irrelevant).
    let resets_at = info.get("resetsAt").and_then(Value::as_i64);
    window_pct(status, used).map(|pct| (window, pct, status == Some("rejected"), resets_at))
}

/// Opportunistic account-wide 5h/7d reserve from a `rate_limits` object on a
/// `result` line, reading each window's `status` (primary) + `used_percentage`
/// through [`window_pct`]. `None` when the result carries no such object — the
/// expected headless case (the reserve flows via `rate_limit_event` instead, see
/// [`rate_limit_window_for_line`]); this is the documented bonus path.
fn reserve_from_result(ev: &Value) -> Option<(BudgetUsage, [bool; 2])> {
    let rl = ev.get("rate_limits")?;
    let win = |window: &str| -> Option<(u8, bool)> {
        rl.get(window).and_then(|w| {
            let status = w.get("status").and_then(Value::as_str);
            let used = w
                .get("used_percentage")
                .and_then(Value::as_u64)
                .map(|p| p.min(100) as u8);
            // Carry the hard-`rejected` status alongside the pct so the result-line
            // path can fail-safe hold a rejected window (task 037 fix ①) without a
            // `warning` (pct 100, not rejected) latching one (fix ②).
            window_pct(status, used).map(|pct| (pct, status == Some("rejected")))
        })
    };
    match (win("five_hour"), win("seven_day")) {
        (None, None) => None,
        (five, seven) => Some((
            BudgetUsage::new(five.map_or(0, |w| w.0), seven.map_or(0, |w| w.0)),
            [five.is_some_and(|w| w.1), seven.is_some_and(|w| w.1)],
        )),
    }
}

/// Claude's per-line fold — the wire-format half of the reader thread, called by
/// the harness once per non-empty stdout line with the arrival stamp `at` it
/// already used for the heartbeat.
///
/// Publishes each content block as an [`Event::AgentDelta`] on `hub`, folds each
/// `rate_limit_event` line's account-wide reserve status into `budget` (the
/// reliable headless §7 source), and records the terminal `result` line's context
/// gauge (+ its opportunistic `rate_limits` reserve) and token cost into `rate`.
/// Pure over its cells: a test drives it through [`pump`] with a scripted fixture
/// + fake clock, no real spawn.
fn observe_claude_line(
    line: &str,
    at: i64,
    agent: &str,
    hub: &EventHub,
    budget: &AgentBudgetState,
    rate: &AgentRateState,
) {
    // A `rate_limit_event` reports this agent's reading of the shared
    // account-wide 5h/7d reserve as a coarse per-window status — the reliable
    // headless source (spec §6/§7). Fold it into the budget cell the drive
    // loop's UsageAggregator reads; a non-"allowed" window saturates it so the
    // admission gate refuses (`window_pct`).
    if let Some((window, pct, rejected, resets_at)) = rate_limit_window_for_line(line) {
        // Only a hard `rejected` window latches a hold (task 037 fix ②). Pin a
        // concrete reopen: the wire's `resetsAt`, else a bounded fail-safe deadline
        // off THIS line's clock so a rejected-without-reset window can't spin the
        // fleet (fix ①). A `warning`/`allowed` passes `None`, clearing any prior trip.
        let trip = rejected.then(|| WindowTrip {
            reopen: resets_at.unwrap_or(at + RATE_LIMIT_FALLBACK_HOLD_SECS),
        });
        budget.record_window(window, pct, trip);
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
            budget.record_reserve(reserve, reading.reserve_rejected, at);
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
    // The terminal `result` also closes one turn (one request) costing its
    // summed `usage` tokens — fold it into this agent's rolling-minute meter so
    // the drive loop's fleet-wide sum gates admission's TPM/RPM window (§7).
    if let Some(tokens) = result_usage_tokens(line) {
        rate.record(at, tokens);
    }
}

/// The owned [`LineObserver`] a live spawn's reader thread holds — the cells this
/// generation writes into, `Arc`-shared with the backend's registries.
#[derive(Debug)]
struct ClaudeSpawnObserver {
    agent: String,
    hub: EventHub,
    budget: Arc<AgentBudgetState>,
    rate: Arc<AgentRateState>,
}

impl LineObserver for ClaudeSpawnObserver {
    fn observe(&self, line: &str, at: i64) {
        observe_claude_line(line, at, &self.agent, &self.hub, &self.budget, &self.rate);
    }
}

/// The borrowing [`LineObserver`] the unit tests drive — the SAME
/// [`observe_claude_line`] fold over borrowed cells, so a fixture can assert the
/// pipeline without constructing a spawn's `Arc`s. Test-only: production always
/// folds through the owned [`ClaudeSpawnObserver`] the reader thread holds.
#[cfg(test)]
struct ClaudeBorrowedObserver<'a> {
    agent: &'a str,
    hub: &'a EventHub,
    budget: &'a AgentBudgetState,
    rate: &'a AgentRateState,
}

#[cfg(test)]
impl LineObserver for ClaudeBorrowedObserver<'_> {
    fn observe(&self, line: &str, at: i64) {
        observe_claude_line(line, at, self.agent, self.hub, self.budget, self.rate);
    }
}

/// Tail an agent's `claude -p --output-format stream-json` output to EOF through
/// the harness's [`pump`](crate::agent_harness::pump), folding each line with
/// [`observe_claude_line`]. The claude-shaped seam the unit tests drive: it wires
/// borrowed cells into the SAME harness loop + SAME fold the live reader thread
/// uses, so the fixture proves the production pipeline rather than a parallel one.
#[cfg(test)]
fn pump<R: BufRead>(
    reader: R,
    agent: &str,
    hub: &EventHub,
    health: &AgentHealthState,
    budget: &AgentBudgetState,
    rate: &AgentRateState,
    now: &dyn Fn() -> i64,
) {
    crate::agent_harness::pump(
        reader,
        health,
        &ClaudeBorrowedObserver {
            agent,
            hub,
            budget,
            rate,
        },
        now,
    );
}

/// The `claude -p` invocation that goes AFTER the harness's `systemd-run … --`
/// separator — the argv half that is genuinely claude's (spec §12). The wrapper
/// half (scope, `--collect`, `--unit=`, the gentle build caps) is the harness's.
fn claude_command_argv(
    bin: &str,
    prompt: &str,
    loop_settings: &Path,
    mcp_config: &Path,
) -> Vec<OsString> {
    vec![
        bin.into(),
        "-p".into(),
        prompt.into(),
        "--settings".into(),
        loop_settings.as_os_str().to_os_string(),
        "--mcp-config".into(),
        mcp_config.as_os_str().to_os_string(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
    ]
}

/// Claude's [`BackendFlavor`]: the three things the shared harness cannot know —
/// the argv, the fail-closed pre-approval, and the stream-json per-line fold.
#[derive(Debug)]
struct ClaudeFlavor {
    bin: String,
    prompt: String,
    hub: EventHub,
    /// Per-agent fail-closed pre-approval generator (§15, slice 004): each spawn
    /// generates this agent's `loop.json`/`mcp.json` BEFORE exec, so a headless
    /// session never errors out on a missing allow-rule. Generation failure ⇒ no
    /// spawn (a `SpawnError`).
    preapproval: PreApproval,
    /// Per-agent budget cells (latest best-effort shared-pool reserve), keyed by
    /// agent id; the drive loop folds these into its [`crate::usage::UsageAggregator`]
    /// via [`budget`](ClaudeBackend::budget). Re-spawn replaces the cell — the same
    /// lifecycle the harness gives its own health/rate/stderr cells.
    budgets: Mutex<BTreeMap<String, Arc<AgentBudgetState>>>,
}

impl ClaudeFlavor {
    /// `agent`'s latest account-wide reserve reading, or `None` if it has not
    /// reported one yet.
    fn budget(&self, agent: &str) -> Option<BudgetUsage> {
        self.budgets
            .lock()
            .unwrap()
            .get(agent)
            .and_then(|s| s.observe())
    }

    /// The instant admission may re-probe any window `agent` reports `rejected`.
    fn rate_limit_reopen(&self, agent: &str) -> Option<i64> {
        self.budgets
            .lock()
            .unwrap()
            .get(agent)
            .and_then(|s| s.rate_limit_reopen())
    }
}

impl BackendFlavor for ClaudeFlavor {
    fn generate_preapproval(&self, agent: &str) -> Result<AgentPaths, SpawnError> {
        self.preapproval.generate(agent).map_err(|e| {
            SpawnError(format!(
                "pre-approval generation failed for agent {agent}: {e}"
            ))
        })
    }

    fn command_argv(&self, paths: &AgentPaths) -> Vec<OsString> {
        claude_command_argv(
            &self.bin,
            &self.prompt,
            &paths.loop_settings,
            &paths.mcp_config,
        )
    }

    fn new_observer(&self, agent: &str, rate: Arc<AgentRateState>) -> Box<dyn LineObserver> {
        // Fresh reserve cell for this spawn, overwriting any prior generation's —
        // so `budget` always reads the CURRENT child's reading. The exact
        // replace-on-re-roll lifecycle of the harness's own per-agent cells.
        let budget = Arc::new(AgentBudgetState::default());
        self.budgets
            .lock()
            .unwrap()
            .insert(agent.to_string(), Arc::clone(&budget));
        Box::new(ClaudeSpawnObserver {
            agent: agent.to_string(),
            hub: self.hub.clone(),
            budget,
            rate,
        })
    }
}

/// The production claude [`AgentBackend`]: a [`Harness`] bound to a
/// [`ClaudeFlavor`], shelling `claude -p --output-format stream-json` per agent
/// (§12), tailing each child into [`Event::AgentDelta`]s on the shared
/// [`EventHub`], and tracking the per-agent state the drive loop reads.
///
/// Implemented for `Arc<ClaudeBackend>` (mirroring the supervisor's test fake) so
/// the drive loop can hold a clone to read [`health`](ClaudeBackend::health) while
/// the [`crate::supervisor::Supervisor`] owns the backend behind the trait.
#[derive(Debug)]
pub struct ClaudeBackend {
    /// The shared supervision machinery (scope, health, stderr, rate, registries).
    harness: Harness,
    /// The SAME flavor the harness holds behind its `Arc<dyn BackendFlavor>`, kept
    /// concretely here so the claude-only reserve accessors reach its budget cells.
    flavor: Arc<ClaudeFlavor>,
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
        build_caps: Arc<Mutex<BuildCaps>>,
        live_scopes: Arc<Mutex<BTreeMap<String, String>>>,
        kill_handles: Arc<Mutex<BTreeMap<String, LiveKill>>>,
    ) -> Self {
        let flavor = Arc::new(ClaudeFlavor {
            bin: bin.into(),
            prompt: prompt.into(),
            hub,
            preapproval,
            budgets: Mutex::new(BTreeMap::new()),
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
    /// never spawned it. The drive loop calls this each cycle to feed
    /// [`crate::supervisor::Supervisor::poll`].
    pub fn health(&self, agent: &str) -> Option<AgentHealth> {
        self.harness.health(agent)
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
        self.flavor.budget(agent)
    }

    /// The instant admission may re-probe any rate-limit window `agent` currently
    /// reports as `rejected` (`None` when none is). Sibling to
    /// [`budget`](Self::budget): the drive loop holds admission until this boundary
    /// then resumes without a human bounce — the capability the deleted `--auto`
    /// governor had (task 037) — the reopen being the wire's `resetsAt` or a pinned
    /// bounded fail-safe (fix ①). Read for a down-but-not-yet-re-rolled agent too —
    /// the budget cell retains the reading until the next spawn replaces it, so a
    /// window tripped in the same ~1s tick the agent exits is not missed.
    pub fn rate_limit_reopen(&self, agent: &str) -> Option<i64> {
        self.flavor.rate_limit_reopen(agent)
    }

    /// The **fleet-wide** rolling-minute `(tpm_used, rpm_used)` at `now`: the sum
    /// across every agent's rate meter of the tokens/requests observed in the
    /// trailing minute. Feeds the live [`crate::drive_loop::LiveRate`] source's
    /// `used` fields, which the admission governor checks against the per-device
    /// limits (spec §7).
    pub fn rate_used(&self, now: i64) -> (u32, u32) {
        self.harness.rate_used(now)
    }

    /// `agent`'s most recent stderr lines (oldest→newest), or an empty vec if it
    /// was never spawned or has emitted no stderr (crash-diagnostics slice 001).
    /// The drive loop reads this to enrich an `AgentCrashed` alert with the crash
    /// reason. Ephemeral: a growlightd restart loses the buffer — the alert, not a
    /// file, carries the diagnostic forward.
    pub fn stderr_tail(&self, agent: &str) -> Vec<String> {
        self.harness.stderr_tail(agent)
    }
}

impl AgentBackend for Arc<ClaudeBackend> {
    fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
        self.harness.spawn(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_harness::{scope_base_name_gen, spawn_argv};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicI64, Ordering};

    /// The full claude spawn argv, composed from the two PRODUCTION halves through
    /// the production combinator: the harness's scope wrapper
    /// ([`crate::agent_harness::scope_wrapper_argv`], via [`spawn_argv`]) plus
    /// [`claude_command_argv`]. `Harness::spawn` shells exactly this — there is no
    /// second join that could drift — so asserting on it asserts on what really
    /// execs.
    fn scoped_spawn_argv(
        bin: &str,
        prompt: &str,
        loop_settings: &Path,
        mcp_config: &Path,
        scope_base: &str,
        caps: &BuildCaps,
    ) -> Vec<OsString> {
        spawn_argv(
            scope_base,
            caps,
            claude_command_argv(bin, prompt, loop_settings, mcp_config),
        )
    }

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
        let rate_meter = AgentRateState::default();

        // A fake clock that ticks 10, 20, 30, … once per line read.
        let clock = AtomicI64::new(0);
        let now = || clock.fetch_add(10, Ordering::SeqCst) + 10;

        pump(Cursor::new(STREAM), "tab", &hub, &state, &budget, &rate_meter, &now);

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
        let rate_meter = AgentRateState::default();
        let now = || 100; // init line stamped at t=100, then nothing more

        pump(Cursor::new(silent), "tab", &hub, &state, &budget, &rate_meter, &now);

        // No exit recorded → still Alive, but pinned at the stale init stamp.
        assert_eq!(state.observe(), AgentHealth::Alive { last_active: 100 });
        // A later poll's gap exceeds the supervisor's default hang window (600s),
        // so `Supervisor::classify` (proven in supervisor.rs) trips it to Crashed.
        let polled_at = 100 + 700;
        assert!(polled_at - 100 >= 600, "a stale heartbeat reads as hung");
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
                reserve_rejected: [false, false],
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
                // A pure `used_percentage` reading is not a hard rejection.
                reserve_rejected: [false, false],
            })
        );

        // A partial object defaults the absent window to 0 but still surfaces.
        let partial = r#"{"type":"result","rate_limits":{"five_hour":{"used_percentage":97}}}"#;
        assert_eq!(
            budget_for_result_line(partial).unwrap().reserve,
            Some(BudgetUsage::new(97, 0))
        );

        // A result whose `rate_limits` carries the headless `status` shape (no
        // percentage) is read too: a non-"allowed" window saturates to 100, and a
        // hard-`rejected` window surfaces its rejected flag (task 037 fix ①) while
        // an `allowed` one does not.
        let status_shaped = r#"{"type":"result","rate_limits":{"five_hour":{"status":"rejected"},"seven_day":{"status":"allowed"}}}"#;
        let reading = budget_for_result_line(status_shaped).unwrap();
        assert_eq!(reading.reserve, Some(BudgetUsage::new(100, 0)));
        assert_eq!(reading.reserve_rejected, [true, false]);

        // A `warning` window saturates the pct but is NOT a hard rejection — it must
        // not carry a rejected flag (task 037 fix ②).
        let warned = r#"{"type":"result","rate_limits":{"five_hour":{"status":"warning"},"seven_day":{"status":"allowed"}}}"#;
        let reading = budget_for_result_line(warned).unwrap();
        assert_eq!(reading.reserve, Some(BudgetUsage::new(100, 0)));
        assert_eq!(reading.reserve_rejected, [false, false]);
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
        // A hard-`rejected` window: rejected=true, carrying its reopen boundary.
        let five_rejected = r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"rejected","resetsAt":1782367800}}"#;
        assert_eq!(
            rate_limit_window_for_line(five_rejected),
            Some((BudgetWindow::FiveHour, 100, true, Some(1782367800)))
        );
        // An `allowed` window is not rejected → pct 0, rejected=false (its resetsAt,
        // present on allowed events too, is ignored downstream — the window is open).
        let seven_allowed = r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"seven_day","status":"allowed","resetsAt":1782900000}}"#;
        assert_eq!(
            rate_limit_window_for_line(seven_allowed),
            Some((BudgetWindow::SevenDay, 0, false, Some(1782900000)))
        );
        // A `warning` saturates the pct (throttling the live aggregate) but is NOT a
        // rejection → rejected=false, so it never latches a timed hold (task 037 ②).
        let five_warning = r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"warning","resetsAt":1782367800}}"#;
        assert_eq!(
            rate_limit_window_for_line(five_warning),
            Some((BudgetWindow::FiveHour, 100, false, Some(1782367800)))
        );
        // A rejected window with no `resetsAt`: rejected=true, resets_at absent — pump
        // pins the bounded fail-safe reopen rather than letting it spin (task 037 ①).
        let five_no_reset = r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"rejected"}}"#;
        assert_eq!(
            rate_limit_window_for_line(five_no_reset),
            Some((BudgetWindow::FiveHour, 100, true, None))
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
        let rate_meter = AgentRateState::default();
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
        pump(Cursor::new(stream), "tab", &hub, &state, &budget, &rate_meter, &now);

        // The non-"allowed" 5h status folded to a saturated 100; the allowed 7d to 0.
        let reserve = budget.observe().expect("a reserve was folded from the events");
        assert_eq!(reserve, BudgetUsage::new(100, 0));

        // The tripped 5h window surfaces its `resetsAt` for the timed-resume hold
        // (task 037); the allowed 7d window is not rejected, so the reopen boundary
        // is the 5h one alone.
        assert_eq!(
            budget.rate_limit_reopen(),
            Some(1782367800),
            "the tripped 5h window's reset boundary is exposed for the hold",
        );

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
    fn a_rejected_window_without_a_reset_pins_a_bounded_fail_safe_reopen() {
        // Task 037 fix ①: a hard-`rejected` 5h window whose event carries NO
        // `resetsAt` must still surface a reopen so the drive loop holds instead of
        // re-rolling into the closed window — a concrete `now + fallback` deadline,
        // pinned once off this line's clock (not re-derived), so the hold elapses and
        // the member re-probes rather than spinning the shared pool.
        let hub = EventHub::new();
        let state = AgentHealthState::new(0);
        let budget = AgentBudgetState::default();
        let rate_meter = AgentRateState::default();
        let now = || 100;
        let stream = concat!(
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"rejected"}}"#,
            "\n",
        );
        pump(Cursor::new(stream), "tab", &hub, &state, &budget, &rate_meter, &now);
        // The pct still saturates (throttles the aggregate)...
        assert_eq!(budget.observe(), Some(BudgetUsage::new(100, 0)));
        // ...and the reopen is the bounded fail-safe off the line's clock (100), not
        // `None` (which pre-fix let admission re-roll straight back in and spin).
        assert_eq!(
            budget.rate_limit_reopen(),
            Some(100 + RATE_LIMIT_FALLBACK_HOLD_SECS),
            "a rejected window with no resetsAt pins a bounded fail-safe reopen (fix ①)",
        );
    }

    #[test]
    fn a_warning_window_saturates_the_pct_but_never_arms_a_hold() {
        // Task 037 fix ②: a `warning` (still running, not closed) saturates the pct
        // so it throttles the live aggregate, but sets no trip — so it can never
        // freeze the fleet on a member that is merely warned, even when the event
        // carries a `resetsAt` (which pre-fix latched a fleet-wide hold to it).
        let hub = EventHub::new();
        let state = AgentHealthState::new(0);
        let budget = AgentBudgetState::default();
        let rate_meter = AgentRateState::default();
        let now = || 100;
        let stream = concat!(
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"warning","resetsAt":1782367800}}"#,
            "\n",
        );
        pump(Cursor::new(stream), "tab", &hub, &state, &budget, &rate_meter, &now);
        assert_eq!(
            budget.observe(),
            Some(BudgetUsage::new(100, 0)),
            "a warning saturates the pct (throttles the live aggregate)",
        );
        assert_eq!(
            budget.rate_limit_reopen(),
            None,
            "but a warning never arms a hold (fix ②) — the fleet is not frozen",
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
        let rate_meter = AgentRateState::default();
        let now = || 0;

        let stream = concat!(
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"five_hour","status":"allowed","resetsAt":1782367800}}"#,
            "\n",
            r#"{"type":"rate_limit_event","rate_limit_info":{"rateLimitType":"seven_day","status":"allowed","resetsAt":1782900000}}"#,
            "\n",
        );
        pump(Cursor::new(stream), "tab", &hub, &state, &budget, &rate_meter, &now);

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
    fn result_usage_tokens_sums_the_usage_fields_and_ticks_every_result() {
        // The four usage fields sum (same set ctx_pct uses).
        let line = r#"{"type":"result","usage":{"input_tokens":50000,"output_tokens":30000,"cache_read_input_tokens":20000,"cache_creation_input_tokens":5000}}"#;
        assert_eq!(result_usage_tokens(line), Some(105_000));
        // A result with no usage object still counts as one request, 0 tokens.
        assert_eq!(
            result_usage_tokens(r#"{"type":"result","subtype":"success"}"#),
            Some(0)
        );
        // A partial usage object sums only the present fields.
        assert_eq!(
            result_usage_tokens(r#"{"type":"result","usage":{"output_tokens":7}}"#),
            Some(7)
        );
        // Non-result lines + malformed JSON carry no rate sample.
        assert_eq!(
            result_usage_tokens(r#"{"type":"assistant","usage":{"input_tokens":9}}"#),
            None
        );
        assert_eq!(result_usage_tokens("not json"), None);
    }

    #[test]
    fn pump_meters_result_usage_into_a_rate_that_trips_the_tpm_gate() {
        use crate::admission::{AdmissionDecision, AdmissionGovernor, Intent, RateState, RefuseReason};
        use crate::config::{Policy, RateLimits};

        let hub = EventHub::new();
        let state = AgentHealthState::new(0);
        let budget = AgentBudgetState::default();
        let rate_meter = AgentRateState::default();
        let now = || 1000; // every line stamped inside one minute

        // A headless turn whose terminal result reports 90k tokens of usage.
        let stream = concat!(
            r#"{"type":"system","subtype":"init","model":"claude-opus-4-8"}"#,
            "\n",
            r#"{"type":"result","subtype":"success","usage":{"input_tokens":80000,"output_tokens":10000},"modelUsage":{"claude-opus-4-8":{"contextWindow":1000000}}}"#,
            "\n",
        );
        pump(Cursor::new(stream), "tab", &hub, &state, &budget, &rate_meter, &now);

        // The meter observed 90k tokens / 1 request in the trailing minute.
        let (tpm_used, rpm_used) = rate_meter.window(1000);
        assert_eq!((tpm_used, rpm_used), (90_000, 1));

        // Build the fleet-wide RateState the live source pairs with the per-device
        // limits. A helper so both halves of the proof use the metered `used`.
        let g = AdmissionGovernor::new(Policy::default());
        let with_limits = |limits: RateLimits| RateState {
            tpm_used: tpm_used as u32,
            rpm_used: rpm_used as u32,
            tpm_limit: limits.tpm_limit,
            rpm_limit: limits.rpm_limit,
            tpm_per_agent: limits.tpm_per_agent,
            rpm_per_agent: limits.rpm_per_agent,
        };

        // 90k used + a 20k per-agent burst > a 100k TPM limit → Refuse. Note the
        // per-agent headroom is what tips it: 90k alone is under the limit, so this
        // also proves the per-agent burst is honored on top of the fleet-wide used.
        let tight = RateLimits {
            tpm_limit: 100_000,
            rpm_limit: 1_000,
            tpm_per_agent: 20_000,
            rpm_per_agent: 10,
        };
        assert_eq!(
            g.decide(Intent::Start, 0, BudgetUsage::new(10, 5), with_limits(tight)),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Tpm
            },
            "metered fleet TPM + per-agent headroom over the limit refuses",
        );

        // The SAME metered usage under the roomier default ceiling (2M) admits —
        // the gate is driven by real data, not a permissive constant.
        assert!(
            g.decide(Intent::Start, 0, BudgetUsage::new(10, 5), with_limits(RateLimits::default()))
                .is_admit(),
            "the same 90k under a 2M ceiling admits",
        );
    }

    #[test]
    fn the_metered_request_count_trips_the_rpm_gate() {
        use crate::admission::{AdmissionDecision, AdmissionGovernor, Intent, RateState, RefuseReason};
        use crate::config::Policy;

        // Three completed turns in the minute → 3 requests (token-cheap).
        let m = AgentRateState::default();
        for t in [10, 20, 30] {
            m.record(t, 1);
        }
        let (tokens, reqs) = m.window(40);
        assert_eq!((tokens, reqs), (3, 3));

        // With an RPM limit of 4 and a per-agent burst of 2, 3 used + 2 > 4 → the
        // request window refuses even though tokens are trivial.
        let g = AdmissionGovernor::new(Policy::default());
        let rate = RateState {
            tpm_used: tokens as u32,
            rpm_used: reqs as u32,
            tpm_limit: 1_000_000,
            rpm_limit: 4,
            tpm_per_agent: 1,
            rpm_per_agent: 2,
        };
        assert_eq!(
            g.decide(Intent::Start, 0, BudgetUsage::new(10, 5), rate),
            AdmissionDecision::Refuse {
                reason: RefuseReason::Rpm
            },
        );
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
        let backend = Arc::new(ClaudeBackend::new(
            "claude",
            "kick",
            EventHub::new(),
            pre,
            Arc::new(Mutex::new(BuildCaps::default())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
        ));
        let spec = AgentSpec::new("a1", blocker.join("a1/loop.json"), blocker.join("a1/mcp.json"));

        let err = backend.spawn(&spec).expect_err("generation failure ⇒ no spawn");
        assert!(
            err.0.contains("pre-approval generation failed"),
            "fail-closed spawn error: {err}",
        );
        // Nothing was registered — the agent never entered the fleet (no kill
        // handle, no health cell).
        assert!(backend.health("a1").is_none(), "no doomed agent registered");
        assert!(
            backend.harness.kill_handles.lock().unwrap().is_empty(),
            "a fail-closed spawn registers no kill handle",
        );
    }

    #[test]
    fn scoped_spawn_argv_wraps_the_claude_invocation_in_a_transient_user_scope() {
        let caps = BuildCaps::default();
        let argv = scoped_spawn_argv(
            "claude",
            "kick",
            Path::new("/run/agents/a1/loop.json"),
            Path::new("/run/agents/a1/mcp.json"),
            &scope_base_name_gen("a1", 7),
            &caps,
        );
        // The paths here are valid UTF-8, so render for readable assertions.
        let s: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();

        // The controller is `systemd-run` in the USER manager, a `--scope` (so it
        // inherits our stdio for the stream-json tail, not a detached `--service`),
        // `--collect` (no residue), named per-agent.
        assert_eq!(s[0], "systemd-run");
        assert!(s.contains(&"--user".to_string()));
        assert!(s.contains(&"--scope".to_string()));
        assert!(s.contains(&"--collect".to_string()));
        assert!(s.contains(&"--unit=growlight-agent-a1-7".to_string()));

        let sep = s
            .iter()
            .position(|a| a == "--")
            .expect("a `--` separates the scope wrapper from the command");

        // The GENTLE build caps (slice 002) are `systemd-run` scope options, so
        // they sit BEFORE the `--`: a low CARGO_BUILD_JOBS + a SOFT MemoryHigh + a
        // deprioritizing CPUWeight. Never a hard kill cap (MemoryMax/TasksMax).
        let scope_opts = &s[..sep];
        assert!(scope_opts.contains(&"--setenv=CARGO_BUILD_JOBS=2".to_string()));
        assert!(scope_opts.contains(&"--property=MemoryHigh=3G".to_string()));
        assert!(scope_opts.contains(&"--property=CPUWeight=50".to_string()));
        assert!(
            !scope_opts
                .iter()
                .any(|a| a.contains("MemoryMax") || a.contains("TasksMax")),
            "the caps throttle, never kill: no MemoryMax/TasksMax",
        );

        // Everything after the `--` separator is the ORIGINAL `claude -p`
        // stream-json invocation, unchanged — the wrapper adds the scope + caps and
        // touches nothing about the command itself.
        assert_eq!(
            &s[sep + 1..],
            &[
                "claude",
                "-p",
                "kick",
                "--settings",
                "/run/agents/a1/loop.json",
                "--mcp-config",
                "/run/agents/a1/mcp.json",
                "--output-format",
                "stream-json",
                "--verbose",
            ]
        );
    }

    #[test]
    fn the_claude_argv_is_byte_identical_to_the_pre_harness_invocation() {
        // slice 001 is a PURE REFACTOR: extracting the supervision harness must not
        // move a single byte of what `claude` is actually exec'd with. The historical
        // argv is pinned here in full — element for element, in order, wrapper
        // included — so a future flavor/harness edit that shifts, reorders, or drops
        // any of it fails loudly instead of being eyeballed.
        let argv = scoped_spawn_argv(
            "claude",
            "kick",
            Path::new("/run/agents/a1/loop.json"),
            Path::new("/run/agents/a1/mcp.json"),
            &scope_base_name_gen("a1", 7),
            &BuildCaps::default(),
        );
        let s: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(
            s,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--collect",
                "--unit=growlight-agent-a1-7",
                "--setenv=CARGO_BUILD_JOBS=2",
                "--property=MemoryHigh=3G",
                "--property=CPUWeight=50",
                "--",
                "claude",
                "-p",
                "kick",
                "--settings",
                "/run/agents/a1/loop.json",
                "--mcp-config",
                "/run/agents/a1/mcp.json",
                "--output-format",
                "stream-json",
                "--verbose",
            ],
            "the claude invocation is byte-identical across the harness extraction",
        );
    }
}
