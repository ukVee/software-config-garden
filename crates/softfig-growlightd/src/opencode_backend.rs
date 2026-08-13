//! The opencode backend — opencode's **flavor** of the backend-agnostic
//! [`crate::agent_harness`] (spec-agents §10 phase 2).
//!
//! This module currently holds the wire-format half only: the NDJSON per-line fold
//! that normalizes `opencode run --format json` output into growlightd's canonical
//! [`Event::AgentDelta`] + heartbeat + rate pipeline (opencode-fleet-backend slice
//! 002). The argv, the fail-closed pre-approval, and the [`BackendFlavor`] /
//! `AgentBackend` wiring arrive in slices 003–004; everything structural — the
//! transient systemd scope, health cells, stderr ring, rolling-minute meter, kill
//! registries — is already the harness's and is not duplicated here.
//!
//! ## The wire format (PINNED against opencode 1.18.15, 2026-08-13)
//!
//! NDJSON, one object per line: `{type, timestamp, sessionID, part}`. The fixtures
//! in `tests/fixtures/` are real captured runs and are the substitute for a live
//! `opencode` — **no `opencode` process is ever spawned in tests**.
//!
//! | `type` | carries | folded into |
//! |---|---|---|
//! | `step_start` | nothing we read | heartbeat only (the harness bumps it) |
//! | `text` | `part.text` | [`AgentDeltaKind::Assistant`] |
//! | `tool_use` | `part.tool`, `part.state.{status,title,input}` | [`AgentDeltaKind::ToolCall`] |
//! | `step_finish` | `part.tokens.total`, `part.cost` | the rate meter + [`AgentSpendState`] |
//!
//! `part.timestamp` is **milliseconds** (claude's `stream-json` is not) — which is
//! precisely why this fold ignores it and uses the harness's `at` stamp, the same
//! injected clock reading that bumped the heartbeat. There is no ms/s unit to get
//! wrong.
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
//! claude meters one turn per terminal `result`; opencode emits one
//! `step_start`/`step_finish` pair **per model turn**, so a multi-tool run meters
//! several requests (the 2-tool fixture is three steps). That is the truthful
//! reading — each step really is a separate API call — so it is not a bug to
//! "fix" into one-per-run.

// Slice 002 lands this fold + its cells fully unit-proven, but nothing in
// production *calls* it until slice 004 builds the `BackendFlavor` that installs
// the observer — so every item below is legitimately unreachable for exactly one
// commit. Scoped to this module and removed by slice 004, rather than eight
// scattered attributes.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use softfig_ipc::growlightd::{AgentDeltaKind, Event};

use crate::agent_harness::{AgentRateState, LineObserver, TOOL_RENDER_MAX_CHARS, truncate_chars};
use crate::hub::EventHub;

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
/// `deepseek-v4-flash` step really does cost `4.27392e-05` USD (≈43 µUSD in the
/// captured fixture): quantizing each step to whole µUSD would put a ~1% error on
/// exactly the model this backend exists to run. Nano-USD costs nothing (same
/// `u64`, one constant) and removes the class — `u64::MAX` nano-USD is ~1.8e10 USD.
const NANO_USD_PER_USD: f64 = 1_000_000_000.0;

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
    /// Completed model steps observed (one per `step_finish`).
    steps: AtomicU64,
}

/// A snapshot reading of one agent's [`AgentSpendState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AgentSpend {
    /// Accumulated spend in **micro-USD** (1e-6 USD), rounded from the nano-USD
    /// accumulator at read time — so rounding happens once, not per step.
    pub micro_usd: u64,
    /// Completed model steps (`step_finish` events) this session.
    pub steps: u64,
}

impl AgentSpendState {
    /// Fold one `step_finish`'s USD cost into the accumulator. A non-finite or
    /// negative cost contributes 0 (a malformed line must not corrupt the total),
    /// but the step still counts — it happened.
    pub(crate) fn record(&self, cost_usd: f64) {
        let nano = if cost_usd.is_finite() && cost_usd > 0.0 {
            (cost_usd * NANO_USD_PER_USD).round().min(u64::MAX as f64) as u64
        } else {
            0
        };
        self.nano_usd.fetch_add(nano, Ordering::SeqCst);
        self.steps.fetch_add(1, Ordering::SeqCst);
    }

    /// The current reading.
    pub fn observe(&self) -> AgentSpend {
        AgentSpend {
            micro_usd: self.nano_usd.load(Ordering::SeqCst) / 1_000,
            steps: self.steps.load(Ordering::SeqCst),
        }
    }
}

/// Translate one NDJSON line into the content deltas it carries. Pure. A line of
/// a type that carries no renderable content (`step_start`, `step_finish`),
/// malformed JSON, or a known type missing its text yields no deltas — the caller
/// still counts any non-empty line as a heartbeat, since a child emitting anything
/// at all is plainly alive.
fn deltas_for_line(line: &str) -> Vec<(AgentDeltaKind, String)> {
    let Ok(ev) = serde_json::from_str::<Value>(line) else {
        return Vec::new();
    };
    let Some(part) = ev.get("part") else {
        return Vec::new();
    };
    match ev.get("type").and_then(Value::as_str) {
        Some("text") => part
            .get("text")
            .and_then(Value::as_str)
            .map(|t| vec![(AgentDeltaKind::Assistant, t.to_string())])
            .unwrap_or_default(),
        Some("tool_use") => vec![(AgentDeltaKind::ToolCall, render_tool_use(part))],
        // UNPROBED: opencode reports a `reasoning` token count, but no reasoning
        // event was observed in either captured run (`--thinking` was not
        // exercised). If such an event exists it is mapped best-effort here, reading
        // the same `part.text` every other text-bearing part in this format uses. A
        // reasoning event shaped differently yields no delta rather than a wrong
        // one — the run is unaffected either way, since the heartbeat and all
        // metering come from other events. Re-probe with `--thinking` to settle it.
        Some("reasoning") => part
            .get("text")
            .and_then(Value::as_str)
            .map(|t| vec![(AgentDeltaKind::Thinking, t.to_string())])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Render a `tool_use` part into a compact one-line "what tool, what args" string
/// for the live view, char-truncated so a huge argument can't flood the stream.
///
/// Prefers `state.title` — opencode pre-renders a human label there
/// (`garden/hello.txt`), which beats truncating raw `state.input` JSON. A
/// non-`completed` status is carried in the render (`read[running](…)`) rather than
/// suppressed: opencode was only ever observed emitting one event per call, at
/// `completed`, so filtering on that status would risk silently dropping a tool
/// call if intermediate states do stream. Deltas are a live narration, so a
/// running→completed pair reads fine; a dropped call would not.
fn render_tool_use(part: &Value) -> String {
    let tool = part.get("tool").and_then(Value::as_str).unwrap_or("tool");
    let state = part.get("state");
    let status = state
        .and_then(|s| s.get("status"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = state
        .and_then(|s| s.get("title"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            state
                .and_then(|s| s.get("input"))
                .filter(|i| !i.is_null())
                .map(|i| serde_json::to_string(i).unwrap_or_default())
        })
        .unwrap_or_default();

    let head = match status {
        "" | "completed" => tool.to_string(),
        other => format!("{tool}[{other}]"),
    };
    let rendered = if args.is_empty() {
        head
    } else {
        format!("{head}({args})")
    };
    truncate_chars(&rendered, TOOL_RENDER_MAX_CHARS)
}

/// What one completed model step cost: the tokens feeding the rolling-minute meter
/// and the USD this step spent.
#[derive(Debug, Clone, Copy, PartialEq)]
struct StepFinish {
    /// `part.tokens.total` — already inclusive of input + output + reasoning +
    /// cache in every captured step. `0` when the field is absent: the step still
    /// happened and still counts as one request, mirroring claude's `Some(0)` for a
    /// `result` with no `usage`.
    tokens: u64,
    /// `part.cost`, USD for THIS step (not a running total).
    cost_usd: f64,
}

/// Parse a `step_finish` line into what it metered, or `None` for any other type
/// or malformed JSON. Pure — a fixture drives it, no real spawn.
fn step_finish_for_line(line: &str) -> Option<StepFinish> {
    let ev = serde_json::from_str::<Value>(line).ok()?;
    if ev.get("type").and_then(Value::as_str) != Some("step_finish") {
        return None;
    }
    let part = ev.get("part")?;
    Some(StepFinish {
        tokens: part
            .get("tokens")
            .and_then(|t| t.get("total"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cost_usd: part.get("cost").and_then(Value::as_f64).unwrap_or(0.0),
    })
}

/// The per-line fold for an opencode agent: publish this line's content deltas on
/// `hub`, and on a `step_finish` meter one completed request into `rate` and
/// accrue its cost into `spend`.
///
/// Note what is NOT here versus [`crate::claude_backend::observe_claude_line`]: no
/// reserve fold and no [`Event::BudgetChanged`] — opencode's wire format carries
/// neither a rate-limit window nor a context gauge, and inventing one would corrupt
/// the admission aggregate governing the claude members (see the module docs).
///
/// Pure over its cells: a test drives it through [`pump`] with the captured
/// fixtures + a fake clock, no real spawn.
fn observe_opencode_line(
    line: &str,
    at: i64,
    agent: &str,
    hub: &EventHub,
    spend: &AgentSpendState,
    rate: &AgentRateState,
) {
    for (kind, text) in deltas_for_line(line) {
        hub.publish(Event::agent_delta(agent, kind, text));
    }
    // One `step_finish` == one completed model turn == one real API call costing
    // its `tokens.total`. See the module docs on why this is per-step, not per-run.
    if let Some(step) = step_finish_for_line(line) {
        rate.record(at, step.tokens);
        spend.record(step.cost_usd);
    }
}

/// The owned [`LineObserver`] a live spawn's reader thread holds — the cells this
/// generation writes into, `Arc`-shared with the backend's registries.
#[derive(Debug)]
pub(crate) struct OpencodeSpawnObserver {
    pub(crate) agent: String,
    pub(crate) hub: EventHub,
    pub(crate) spend: Arc<AgentSpendState>,
    pub(crate) rate: Arc<AgentRateState>,
}

impl LineObserver for OpencodeSpawnObserver {
    fn observe(&self, line: &str, at: i64) {
        observe_opencode_line(line, at, &self.agent, &self.hub, &self.spend, &self.rate);
    }
}

/// The borrowing [`LineObserver`] the unit tests drive — the SAME
/// [`observe_opencode_line`] fold over borrowed cells, so a fixture can assert the
/// pipeline without constructing a spawn's `Arc`s. Test-only: production always
/// folds through the owned [`OpencodeSpawnObserver`] the reader thread holds.
#[cfg(test)]
struct OpencodeBorrowedObserver<'a> {
    agent: &'a str,
    hub: &'a EventHub,
    spend: &'a AgentSpendState,
    rate: &'a AgentRateState,
}

#[cfg(test)]
impl LineObserver for OpencodeBorrowedObserver<'_> {
    fn observe(&self, line: &str, at: i64) {
        observe_opencode_line(line, at, self.agent, self.hub, self.spend, self.rate);
    }
}

/// Tail an agent's `opencode run --format json` output to EOF through the
/// harness's [`pump`](crate::agent_harness::pump), folding each line with
/// [`observe_opencode_line`]. The opencode-shaped seam the unit tests drive: it
/// wires borrowed cells into the SAME harness loop + SAME fold the live reader
/// thread uses, so the fixtures prove the production pipeline rather than a
/// parallel one.
#[cfg(test)]
fn pump<R: BufRead>(
    reader: R,
    agent: &str,
    hub: &EventHub,
    health: &AgentHealthState,
    spend: &AgentSpendState,
    rate: &AgentRateState,
    now: &dyn Fn() -> i64,
) {
    crate::agent_harness::pump(
        reader,
        health,
        &OpencodeBorrowedObserver {
            agent,
            hub,
            spend,
            rate,
        },
        now,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::AgentHealth;
    use std::io::Cursor;
    use std::sync::atomic::AtomicI64;

    /// The real captured runs (see `tests/fixtures/README.md`) — the substitute for
    /// a live `opencode`, so these tests prove the parser against the wire format
    /// rather than against a hand-written guess of it.
    const TEXT_RUN: &str = include_str!("../tests/fixtures/opencode-text-run.jsonl");
    const TOOL_RUN: &str = include_str!("../tests/fixtures/opencode-tool-run.jsonl");

    /// A clock that advances `step` seconds once per line read.
    ///
    /// The step matters: [`AgentRateState`] meters a **trailing minute**, so a run
    /// whose lines are spread over more than 60 fake seconds will legitimately age
    /// its first samples out. Real opencode steps land seconds apart.
    fn ticking_clock(step: i64) -> impl Fn() -> i64 {
        let clock = AtomicI64::new(0);
        move || clock.fetch_add(step, Ordering::SeqCst) + step
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

        // Best-effort, UNPROBED (see `deltas_for_line`): if a reasoning event
        // exists it maps to Thinking; a differently-shaped one yields nothing.
        let reasoning = r#"{"type":"reasoning","part":{"type":"reasoning","text":"weighing it"}}"#;
        assert_eq!(
            deltas_for_line(reasoning),
            vec![(AgentDeltaKind::Thinking, "weighing it".to_string())]
        );

        // Turn boundaries and metering lines carry no renderable content; a
        // malformed line, a partless line, and a text part with no text carry none
        // either — and none of them may panic.
        for quiet in [
            r#"{"type":"step_start","part":{"type":"step-start"}}"#,
            r#"{"type":"step_finish","part":{"reason":"stop","cost":0.1}}"#,
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
    fn render_tool_use_prefers_the_title_and_is_char_truncated() {
        // No title → fall back to the raw input JSON.
        let no_title = serde_json::json!({
            "tool": "write",
            "state": {"status": "completed", "input": {"filePath": "/x"}},
        });
        assert_eq!(render_tool_use(&no_title), r#"write({"filePath":"/x"})"#);

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
    fn step_finish_for_line_reads_the_tokens_and_cost_it_metered() {
        let step = r#"{"type":"step_finish","part":{"reason":"stop","tokens":{"total":12729,"input":12726,"output":3,"reasoning":0,"cache":{"write":0,"read":0}},"cost":0.00178248}}"#;
        assert_eq!(
            step_finish_for_line(step),
            Some(StepFinish {
                tokens: 12729,
                cost_usd: 0.00178248
            })
        );

        // A step with neither field still meters one request at zero cost — it is a
        // real completed turn.
        assert_eq!(
            step_finish_for_line(r#"{"type":"step_finish","part":{"reason":"stop"}}"#),
            Some(StepFinish {
                tokens: 0,
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

    #[test]
    fn pump_publishes_the_text_run_and_advances_the_heartbeat() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let health = AgentHealthState::new(0);
        let spend = AgentSpendState::default();
        let rate = AgentRateState::default();
        let now = ticking_clock(10);

        pump(Cursor::new(TEXT_RUN), "a", &hub, &health, &spend, &rate, &now);

        // The one text part reaches the hub as an Assistant delta …
        assert_eq!(
            sub.try_recv().unwrap(),
            Event::agent_delta("a", AgentDeltaKind::Assistant, "pong")
        );
        // … and nothing else does. In particular NO BudgetChanged: opencode reports
        // no context gauge and no 5h/7d reserve, and this fold never invents one.
        assert!(sub.try_recv().is_err(), "no extra events");

        // Three non-empty lines → three heartbeats → last_active is the final tick.
        assert_eq!(health.last_active(), 30);
        assert_eq!(health.observe(), AgentHealth::Alive { last_active: 30 });

        // One step_finish → one request of 12729 tokens in the trailing minute,
        // costing 0.00178248 USD → 1782 µUSD.
        assert_eq!(rate.window(30), (12729, 1));
        assert_eq!(
            spend.observe(),
            AgentSpend {
                micro_usd: 1782,
                steps: 1
            }
        );
    }

    #[test]
    fn pump_meters_every_step_of_a_multi_tool_run_and_sums_the_spend() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let health = AgentHealthState::new(0);
        let spend = AgentSpendState::default();
        let rate = AgentRateState::default();
        // One second per line, so all three steps land inside the meter's trailing
        // minute — a real 3-turn run takes seconds, not minutes.
        let now = ticking_clock(1);

        pump(Cursor::new(TOOL_RUN), "a", &hub, &health, &spend, &rate, &now);

        // Both tool calls render from their pre-rendered titles, in order, then the
        // closing text — and again no BudgetChanged.
        for want in [
            Event::agent_delta("a", AgentDeltaKind::ToolCall, "read(garden/hello.txt)"),
            Event::agent_delta("a", AgentDeltaKind::ToolCall, "write(garden/out.txt)"),
            Event::agent_delta("a", AgentDeltaKind::Assistant, "DONE"),
        ] {
            assert_eq!(sub.try_recv().unwrap(), want);
        }
        assert!(sub.try_recv().is_err(), "no extra events");

        // THREE model turns → three metered requests, not one: a multi-tool run is
        // several real API calls (the claude backend meters one per terminal
        // `result`, which opencode does not emit at all).
        let (tokens, requests) = rate.window(9);
        assert_eq!(requests, 3);
        assert_eq!(tokens, 11082 + 11322 + 11341);

        // Spend sums across the steps: 0.00156954 + 0.0000939624 + 0.0000427392 USD
        // = 0.0017062416 → 1706 µUSD. Summed in fixed point, so the tiny per-step
        // costs neither round to zero nor drift.
        assert_eq!(
            spend.observe(),
            AgentSpend {
                micro_usd: 1706,
                steps: 3
            }
        );

        // Nine non-empty lines → nine heartbeats.
        assert_eq!(health.last_active(), 9);
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

        let hub = EventHub::new();
        let sub = hub.subscribe();
        let health = AgentHealthState::new(0);
        let spend = AgentSpendState::default();
        let rate = AgentRateState::default();
        let now = ticking_clock(10);

        pump(Cursor::new(mixed), "a", &hub, &health, &spend, &rate, &now);

        // The pump ran to EOF: the deltas on BOTH sides of the garbage arrived.
        assert_eq!(
            sub.try_recv().unwrap(),
            Event::agent_delta("a", AgentDeltaKind::Assistant, "before")
        );
        assert_eq!(
            sub.try_recv().unwrap(),
            Event::agent_delta("a", AgentDeltaKind::Assistant, "pong")
        );
        assert!(sub.try_recv().is_err(), "no extra events");

        // Six non-empty lines (the blank one is skipped by the harness, and even
        // the unparseable ones are signs of life) → six heartbeats.
        assert_eq!(health.last_active(), 60);
        // Only the one WELL-FORMED step_finish metered; the truncated one did not.
        assert_eq!(rate.window(60), (12729, 1));
        assert_eq!(spend.observe().steps, 1);
    }

    #[test]
    fn a_malformed_cost_cannot_corrupt_the_running_total() {
        let spend = AgentSpendState::default();
        spend.record(0.001); // 1000 µUSD
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -5.0] {
            spend.record(bad);
        }
        // The garbage contributed nothing to the total, but each step is still
        // counted — it did happen.
        assert_eq!(
            spend.observe(),
            AgentSpend {
                micro_usd: 1000,
                steps: 5
            }
        );
    }
}
