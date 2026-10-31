//! Layer-1 token telemetry capture (token-telemetry-p1 slice 004, spec
//! [[spec-token-telemetry]] §4): one [`RequestRow`] per API request, folded
//! out of the event streams growlightd already tails.
//!
//! - **claude** (`claude -p --output-format stream-json`): every `assistant`
//!   event carries its `message.{id, model, usage, stop_reason, content[]}`, and
//!   one response arrives as several `assistant` events sharing one
//!   `message.id` (one per content block, the latest `usage` the most complete).
//!   [`ClaudeCapture`] keeps the open request per *lane* and closes it on an id
//!   change in that lane, on the terminal `result` line, or at
//!   [`finish`](ClaudeCapture::finish). A lane is the event's
//!   `parent_tool_use_id`, so a subagent's interleaved requests never split the
//!   parent's open one into two rows.
//! - **opencode** (`opencode run --format json`): one `step_finish` is one model
//!   call, built by [`opencode_step_row`]; whatever the session ledger settled
//!   beyond the stream is one [`opencode_ledger_row`] at run end.
//!
//! Fail-soft by construction: nothing here returns an error or blocks. A line
//! that does not parse is skipped, and the [`Recorder`] is a non-blocking ring.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value;
use softfig_telemetry::{
    Backend, PriceTable, Recorder, RequestRow, SettledFrom, Speed, TokenCounts,
};

/// The backlog coordinates a spawn's rows are keyed by. Filled by the drive
/// loop from the claim (item, queue) and the member's baton (slice) at each
/// spawn; all `None` for a spawn outside the queue.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TelemetryTags {
    pub item_id: Option<String>,
    pub slice_id: Option<String>,
    pub queue: Option<String>,
}

/// Where a daemon's rows go and how they are priced. Shared by every backend;
/// [`Default`] drops every row (a test, or a daemon whose store failed to open).
#[derive(Clone)]
pub struct TelemetrySink {
    pub recorder: Arc<dyn Recorder>,
    /// `None` when `config/pricing.toml` failed to load: rows store null cost.
    pub prices: Option<Arc<PriceTable>>,
}

impl Default for TelemetrySink {
    fn default() -> Self {
        Self {
            recorder: Arc::new(softfig_telemetry::NullRecorder),
            prices: None,
        }
    }
}

impl std::fmt::Debug for TelemetrySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetrySink")
            .field("priced", &self.prices.is_some())
            .finish_non_exhaustive()
    }
}

/// One spawn's identity, stamped on every row it produces.
#[derive(Debug, Clone)]
pub struct CaptureContext {
    pub sink: TelemetrySink,
    pub member: String,
    pub profile: Option<String>,
    pub tags: TelemetryTags,
    /// The effort resolved at spawn (`--effort`), when one was passed.
    pub effort: Option<String>,
}

impl CaptureContext {
    /// A streamed row with this spawn's identity, completed at `ts`, nothing
    /// measured yet.
    fn row(
        &self,
        backend: Backend,
        (provider, model): (&str, &str),
        session_id: &str,
        request_id: &str,
        ts: i64,
    ) -> RequestRow {
        RequestRow {
            ts,
            backend,
            provider: provider.to_string(),
            model: model.to_string(),
            session_id: session_id.to_string(),
            request_id: request_id.to_string(),
            member: self.member.clone(),
            profile: self.profile.clone(),
            item_id: self.tags.item_id.clone(),
            slice_id: self.tags.slice_id.clone(),
            queue: self.tags.queue.clone(),
            turn_index: 0,
            tokens: TokenCounts::default(),
            effort: self.effort.clone(),
            speed: None,
            stop_reason: None,
            tool_use_count: 0,
            latency_ms: None,
            cost_usd: None,
            settled_from: SettledFrom::Stream,
        }
    }

    /// Record a row whose cost is already settled, as built — an opencode
    /// step row (priced with the wire fallback) or a ledger row. Pricing it
    /// again would drop the fallback.
    pub fn record_settled(&self, row: RequestRow) {
        self.sink.recorder.record(row);
    }

    /// Price `row` (a ledger row keeps its own cost) and hand it to the recorder.
    fn emit(&self, mut row: RequestRow) {
        if let Some(prices) = &self.sink.prices {
            prices.price_row(&mut row);
        }
        self.sink.recorder.record(row);
    }
}

/// One claude `assistant` event's view of its request.
#[derive(Debug, Clone, PartialEq)]
pub struct AssistantRequest {
    pub id: String,
    pub model: String,
    /// `parent_tool_use_id`: `None` for the main thread, the spawning tool
    /// call's id for a subagent's request.
    pub lane: Option<String>,
    /// `None` when this event carries no `usage` (an earlier one may have).
    pub tokens: Option<TokenCounts>,
    pub speed: Option<Speed>,
    pub stop_reason: Option<String>,
    /// The `id`s of this event's `tool_use` content blocks.
    pub tool_use_ids: Vec<String>,
}

/// An `assistant` stream-json event's request, or `None` for any other line or
/// one with no `message.id`. Pure, beside
/// [`deltas_for_line`](crate::claude_backend). claude's `output_tokens`
/// includes thinking; the row stores them apart (`row.rs` `TokenCounts`).
pub fn request_for_assistant(ev: &Value) -> Option<AssistantRequest> {
    if ev.get("type").and_then(Value::as_str) != Some("assistant") {
        return None;
    }
    let msg = ev.get("message")?;
    let id = msg.get("id").and_then(Value::as_str)?.to_string();
    let str_at = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let usage = msg.get("usage").filter(|u| u.is_object());
    let tokens = usage.map(|u| {
        let n = |path: &[&str]| {
            path.iter()
                .try_fold(u, |v, k| v.get(*k))
                .and_then(Value::as_u64)
        };
        let output_tokens = n(&["output_tokens"]).unwrap_or(0);
        let thinking = n(&["output_tokens_details", "thinking_tokens"]);
        TokenCounts {
            input: n(&["input_tokens"]).unwrap_or(0),
            output: output_tokens.saturating_sub(thinking.unwrap_or(0)),
            cache_read: n(&["cache_read_input_tokens"]).unwrap_or(0),
            cache_creation: n(&["cache_creation_input_tokens"]).unwrap_or(0),
            cache_creation_1h: n(&["cache_creation", "ephemeral_1h_input_tokens"]).unwrap_or(0),
            thinking,
        }
    });
    let speed = usage
        .and_then(|u| u.get("speed"))
        .and_then(Value::as_str)
        .and_then(|s| match s {
            "fast" => Some(Speed::Fast),
            "standard" | "normal" => Some(Speed::Standard),
            _ => None,
        });
    let tool_use_ids = msg
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"))
        .filter_map(|b| str_at(b, "id"))
        .collect();
    Some(AssistantRequest {
        id,
        model: str_at(msg, "model").unwrap_or_default(),
        lane: str_at(ev, "parent_tool_use_id"),
        tokens,
        speed,
        stop_reason: str_at(msg, "stop_reason"),
        tool_use_ids,
    })
}

/// A request still receiving `assistant` events.
#[derive(Debug)]
struct OpenRequest {
    id: String,
    model: String,
    tokens: TokenCounts,
    speed: Option<Speed>,
    stop_reason: Option<String>,
    tool_use_ids: BTreeSet<String>,
    /// The arrival time of its latest event: the request's completion time.
    last_at: i64,
}

impl OpenRequest {
    fn new(req: AssistantRequest, at: i64) -> Self {
        let mut open = Self {
            id: req.id.clone(),
            model: String::new(),
            tokens: TokenCounts::default(),
            speed: None,
            stop_reason: None,
            tool_use_ids: BTreeSet::new(),
            last_at: at,
        };
        open.merge(req, at);
        open
    }

    /// Fold a later event of the same request: the latest usage, model, speed
    /// and stop reason win; tool calls accumulate by id, so a stream that
    /// repeats earlier blocks counts each once.
    fn merge(&mut self, req: AssistantRequest, at: i64) {
        if !req.model.is_empty() {
            self.model = req.model;
        }
        if let Some(tokens) = req.tokens {
            self.tokens = tokens;
        }
        self.speed = req.speed.or(self.speed);
        if req.stop_reason.is_some() {
            self.stop_reason = req.stop_reason;
        }
        self.tool_use_ids.extend(req.tool_use_ids);
        self.last_at = at;
    }
}

#[derive(Debug, Default)]
struct ClaudeState {
    session_id: Option<String>,
    open: BTreeMap<Option<String>, OpenRequest>,
    turn_index: u32,
}

/// One claude spawn's request fold. Driven line by line from the member's
/// stdout reader thread; [`finish`](Self::finish) at EOF flushes what is open.
#[derive(Debug)]
pub struct ClaudeCapture {
    ctx: CaptureContext,
    state: Mutex<ClaudeState>,
}

impl ClaudeCapture {
    pub fn new(ctx: CaptureContext) -> Self {
        Self {
            ctx,
            state: Mutex::new(ClaudeState::default()),
        }
    }

    /// Fold one stdout line that arrived at `at`.
    pub fn observe(&self, line: &str, at: i64) {
        let Ok(ev) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.session_id.is_none() {
            state.session_id = ev
                .get("session_id")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if ev.get("type").and_then(Value::as_str) == Some("result") {
            self.close_all(&mut state);
            return;
        }
        let Some(req) = request_for_assistant(&ev) else {
            return;
        };
        let lane = req.lane.clone();
        match state.open.remove(&lane) {
            Some(mut open) if open.id == req.id => {
                open.merge(req, at);
                state.open.insert(lane, open);
            }
            prior => {
                if let Some(prior) = prior {
                    self.close(&mut state, prior);
                }
                state.open.insert(lane, OpenRequest::new(req, at));
            }
        }
    }

    /// The child's stdout ended: close every request still open.
    pub fn finish(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.close_all(&mut state);
    }

    fn close_all(&self, state: &mut ClaudeState) {
        // Oldest completion first, so turn_index follows the wire order.
        let mut open: Vec<OpenRequest> = std::mem::take(&mut state.open).into_values().collect();
        open.sort_by_key(|o| o.last_at);
        for o in open {
            self.close(state, o);
        }
    }

    fn close(&self, state: &mut ClaudeState, open: OpenRequest) {
        let mut row = self.ctx.row(
            Backend::Claude,
            ("anthropic", &open.model),
            state.session_id.as_deref().unwrap_or_default(),
            &open.id,
            open.last_at,
        );
        row.turn_index = state.turn_index;
        row.tokens = open.tokens;
        row.speed = open.speed;
        row.stop_reason = open.stop_reason;
        row.tool_use_count = u32::try_from(open.tool_use_ids.len()).unwrap_or(u32::MAX);
        state.turn_index = state.turn_index.saturating_add(1);
        self.ctx.emit(row);
    }
}

/// opencode's per-class step tokens (`part.tokens`): `reasoning` sits beside
/// `output`, so it maps straight onto [`TokenCounts::thinking`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StepTokens {
    pub input: u64,
    pub output: u64,
    pub reasoning: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl StepTokens {
    /// Every class summed: the meter's per-request token cost.
    pub fn total(&self) -> u64 {
        [
            self.input,
            self.output,
            self.reasoning,
            self.cache_read,
            self.cache_write,
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }

    fn counts(&self) -> TokenCounts {
        TokenCounts {
            input: self.input,
            output: self.output,
            cache_read: self.cache_read,
            cache_creation: self.cache_write,
            cache_creation_1h: 0,
            thinking: Some(self.reasoning),
        }
    }
}

/// `provider/model` → its two halves; a bare id has no provider.
fn split_model(model: &str) -> (&str, &str) {
    model.split_once('/').unwrap_or(("", model))
}

/// One opencode step's row. `model` is the spawn's `provider/model` (the step
/// event names none). The cost is the pricing table's; when the table has no
/// price for the model, the wire's own `part.cost` is kept, since opencode
/// already priced the step.
#[allow(clippy::too_many_arguments)]
pub fn opencode_step_row(
    ctx: &CaptureContext,
    model: &str,
    session_id: &str,
    message_id: &str,
    turn_index: u32,
    tokens: StepTokens,
    stop_reason: Option<String>,
    wire_cost: Option<f64>,
    at: i64,
) -> RequestRow {
    let mut row = ctx.row(
        Backend::Opencode,
        split_model(model),
        session_id,
        message_id,
        at,
    );
    row.turn_index = turn_index;
    row.tokens = tokens.counts();
    row.stop_reason = stop_reason;
    if let Some(prices) = &ctx.sink.prices {
        prices.price_row(&mut row);
    }
    if row.cost_usd.is_none() {
        row.cost_usd = wire_cost;
    }
    row
}

/// The run-end remainder: tokens the session ledger settled beyond what the
/// stream carried, unsplit in `input`, costing the ledger's USD difference.
pub fn opencode_ledger_row(
    ctx: &CaptureContext,
    model: &str,
    session_id: &str,
    turn_index: u32,
    unseen_tokens: u64,
    cost_usd: f64,
    at: i64,
) -> RequestRow {
    let mut row = ctx.row(
        Backend::Opencode,
        split_model(model),
        session_id,
        "ledger",
        at,
    );
    row.settled_from = SettledFrom::Ledger;
    row.turn_index = turn_index;
    row.tokens.input = unseen_tokens;
    row.cost_usd = Some(cost_usd.max(0.0));
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Collect(Mutex<Vec<RequestRow>>);
    impl Recorder for Collect {
        fn record(&self, row: RequestRow) {
            self.0.lock().unwrap().push(row);
        }
    }

    fn ctx(rec: Arc<Collect>, prices: Option<PriceTable>) -> CaptureContext {
        CaptureContext {
            sink: TelemetrySink {
                recorder: rec,
                prices: prices.map(Arc::new),
            },
            member: "a".into(),
            profile: Some("slot1".into()),
            tags: TelemetryTags {
                item_id: Some("token-telemetry-p1".into()),
                slice_id: Some("004".into()),
                queue: Some("default".into()),
            },
            effort: Some("high".into()),
        }
    }

    /// A claude 2.x stream-json run built from the slice-001-verified keys
    /// only: `system`/`init`, one response split over two `assistant` events
    /// sharing `msg_01`, a second response `msg_02`, then `result`.
    const CLAUDE_RUN: &str = include_str!("../tests/fixtures/claude-assistant-usage-run.jsonl");

    #[test]
    fn two_assistant_events_sharing_a_message_id_make_one_row() {
        let rec = Arc::new(Collect::default());
        let cap = ClaudeCapture::new(ctx(Arc::clone(&rec), None));
        for (i, line) in CLAUDE_RUN.lines().enumerate() {
            cap.observe(line, 100 + i as i64);
        }
        cap.finish();
        let rows = rec.0.lock().unwrap();
        assert_eq!(rows.len(), 2, "{rows:#?}");

        let first = &rows[0];
        assert_eq!(first.request_id, "msg_01");
        assert_eq!(first.session_id, "sess-1");
        assert_eq!(first.model, "claude-opus-5-5");
        assert_eq!(
            (first.provider.as_str(), first.backend),
            ("anthropic", Backend::Claude)
        );
        assert_eq!(first.turn_index, 0);
        // The later event's usage wins, thinking carved out of output.
        assert_eq!(
            first.tokens,
            TokenCounts {
                input: 12,
                output: 300 - 120,
                cache_read: 5000,
                cache_creation: 2000,
                cache_creation_1h: 1500,
                thinking: Some(120),
            }
        );
        assert_eq!(first.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(first.tool_use_count, 1);
        assert_eq!(first.speed, Some(Speed::Standard));
        assert_eq!(first.ts, 102, "completion = the request's last event");
        assert_eq!(first.member, "a");
        assert_eq!(first.profile.as_deref(), Some("slot1"));
        assert_eq!(first.item_id.as_deref(), Some("token-telemetry-p1"));
        assert_eq!(first.slice_id.as_deref(), Some("004"));
        assert_eq!(first.queue.as_deref(), Some("default"));
        assert_eq!(first.effort.as_deref(), Some("high"));
        assert_eq!(first.settled_from, SettledFrom::Stream);

        let second = &rows[1];
        assert_eq!(second.request_id, "msg_02");
        assert_eq!(second.turn_index, 1);
        assert_eq!(
            second.tokens.thinking, None,
            "no thinking split on the wire"
        );
        assert_eq!(second.tokens.output, 40);
        assert_eq!(second.stop_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn the_result_line_closes_the_open_request_and_finish_adds_nothing() {
        let rec = Arc::new(Collect::default());
        let cap = ClaudeCapture::new(ctx(Arc::clone(&rec), None));
        for line in CLAUDE_RUN.lines() {
            cap.observe(line, 1);
        }
        assert_eq!(rec.0.lock().unwrap().len(), 2, "closed by `result`");
        cap.finish();
        assert_eq!(rec.0.lock().unwrap().len(), 2);
    }

    #[test]
    fn finish_flushes_a_request_cut_off_before_result() {
        let rec = Arc::new(Collect::default());
        let cap = ClaudeCapture::new(ctx(Arc::clone(&rec), None));
        for line in CLAUDE_RUN.lines().take(3) {
            cap.observe(line, 1);
        }
        assert!(rec.0.lock().unwrap().is_empty(), "msg_01 still open");
        cap.finish();
        let rows = rec.0.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].request_id, "msg_01");
    }

    #[test]
    fn a_subagent_lane_does_not_split_the_parents_open_request() {
        let asst = |id: &str, lane: Option<&str>, out: u64| {
            serde_json::json!({
                "type": "assistant", "session_id": "s", "parent_tool_use_id": lane,
                "message": {"id": id, "model": "claude-sonnet-5-5",
                            "usage": {"input_tokens": 1, "output_tokens": out}}
            })
            .to_string()
        };
        let rec = Arc::new(Collect::default());
        let cap = ClaudeCapture::new(ctx(Arc::clone(&rec), None));
        cap.observe(&asst("p1", None, 1), 1);
        cap.observe(&asst("sub1", Some("toolu_9"), 5), 2);
        cap.observe(&asst("p1", None, 7), 3);
        cap.finish();
        let rows = rec.0.lock().unwrap();
        let ids: Vec<_> = rows
            .iter()
            .map(|r| (r.request_id.as_str(), r.tokens.output))
            .collect();
        assert_eq!(ids, [("sub1", 5), ("p1", 7)]);
    }

    #[test]
    fn a_priced_claude_row_carries_its_cost() {
        let prices = PriceTable::parse(
            "[[model]]\nprovider = \"anthropic\"\nmodel = \"claude-opus-5-5\"\n\
             input_per_mtok = 1.0\noutput_per_mtok = 1.0\ncache_read_per_mtok = 0.0\n\
             cache_create_per_mtok = 0.0\n",
        )
        .unwrap();
        let rec = Arc::new(Collect::default());
        let cap = ClaudeCapture::new(ctx(Arc::clone(&rec), Some(prices)));
        for line in CLAUDE_RUN.lines() {
            cap.observe(line, 1);
        }
        let rows = rec.0.lock().unwrap();
        // 12 input + 180 output + 120 thinking (priced at output) = 312 tokens at $1/Mtok.
        assert!(
            (rows[0].cost_usd.unwrap() - 312e-6).abs() < 1e-12,
            "{:?}",
            rows[0].cost_usd
        );
        assert_eq!(rows[1].cost_usd, None, "unknown model stays null, never 0");
    }

    #[test]
    fn non_assistant_and_unparseable_lines_are_ignored() {
        assert_eq!(
            request_for_assistant(&serde_json::json!({"type": "user"})),
            None
        );
        assert_eq!(
            request_for_assistant(&serde_json::json!({"type": "assistant", "message": {}})),
            None,
            "no message.id, no request"
        );
        let rec = Arc::new(Collect::default());
        let cap = ClaudeCapture::new(ctx(Arc::clone(&rec), None));
        cap.observe("not json {", 1);
        cap.finish();
        assert!(rec.0.lock().unwrap().is_empty());
    }

    #[test]
    fn an_opencode_step_maps_reasoning_beside_output_and_keeps_the_wire_cost_when_unpriced() {
        let rec = Arc::new(Collect::default());
        let c = ctx(rec, None);
        let tokens = StepTokens {
            input: 251,
            output: 167,
            reasoning: 66,
            cache_read: 5376,
            cache_write: 0,
        };
        let row = opencode_step_row(
            &c,
            "deepseek/deepseek-flash",
            "ses_1",
            "msg_1",
            3,
            tokens,
            Some("tool-calls".into()),
            Some(0.0002),
            9,
        );
        assert_eq!(
            (row.provider.as_str(), row.model.as_str()),
            ("deepseek", "deepseek-flash")
        );
        assert_eq!(row.backend, Backend::Opencode);
        assert_eq!(row.tokens.thinking, Some(66));
        assert_eq!(row.tokens.output, 167);
        assert_eq!(row.tokens.total(), tokens.total());
        assert_eq!(row.cost_usd, Some(0.0002));
        assert_eq!(row.turn_index, 3);
        assert_eq!(row.stop_reason.as_deref(), Some("tool-calls"));
    }

    #[test]
    fn the_ledger_row_keeps_its_own_cost_through_pricing() {
        let prices = PriceTable::parse(
            "[[model]]\nprovider = \"deepseek\"\nmodel = \"deepseek-flash\"\n\
             input_per_mtok = 1.0\noutput_per_mtok = 1.0\ncache_read_per_mtok = 0.0\n\
             cache_create_per_mtok = 0.0\n",
        )
        .unwrap();
        let rec = Arc::new(Collect::default());
        let c = ctx(Arc::clone(&rec), Some(prices));
        let row = opencode_ledger_row(&c, "deepseek/deepseek-flash", "ses_1", 4, 900, 0.01, 9);
        assert_eq!(row.settled_from, SettledFrom::Ledger);
        assert_eq!(row.tokens.input, 900);
        c.emit(row);
        let rows = rec.0.lock().unwrap();
        assert_eq!(
            rows[0].cost_usd,
            Some(0.01),
            "price_row leaves a ledger row alone"
        );
    }
}
