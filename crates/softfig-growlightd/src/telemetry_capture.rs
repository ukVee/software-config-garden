//! Layer-1 token telemetry capture (token-telemetry-p1 slice 004, spec
//! [[spec-token-telemetry]] §4): one [`RequestRow`] per API request, folded
//! out of the event streams growlightd already tails.
//!
//! - **claude** (`claude -p --output-format stream-json`): every `assistant`
//!   event carries its `message.{id, model, usage, stop_reason, content[]}`, and
//!   one response arrives as several `assistant` events sharing one
//!   `message.id` (one per content block, the latest `usage` the most complete).
//!   [`ClaudeCapture`] runs softfig-telemetry's [`ClaudeFold`] over them (the
//!   one `message.id` close rule, shared with the semi-auto transcript
//!   ingester): the open request per *lane* (`parent_tool_use_id`), closed on
//!   an id change in that lane, on the terminal `result` line, or at
//!   [`finish`](ClaudeCapture::finish).
//! - **opencode** (`opencode run --format json`): one `step_finish` is one model
//!   call, built by [`opencode_step_row`]; whatever the session ledger settled
//!   beyond the stream is one [`opencode_ledger_row`] at run end.
//!
//! Fail-soft by construction: nothing here returns an error or blocks. A line
//! that does not parse is skipped, and the [`Recorder`] is a non-blocking ring.

use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value;
use softfig_telemetry::{
    Backend, ClaudeFold, ClosedRequest, PriceTable, Recorder, RequestRow, SettledFrom,
    TokenCounts, request_for_assistant,
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
            vendor_cost_usd: None,
            settled_from: SettledFrom::Stream,
        }
    }

    /// Record a row already priced as built — an opencode step or ledger row.
    pub fn record_settled(&self, row: RequestRow) {
        self.sink.recorder.record(row);
    }

    /// Price `row` and hand it to the recorder.
    fn emit(&self, mut row: RequestRow) {
        if let Some(prices) = &self.sink.prices {
            prices.price_row(&mut row);
        }
        self.sink.recorder.record(row);
    }
}

#[derive(Debug, Default)]
struct ClaudeState {
    session_id: Option<String>,
    fold: ClaudeFold,
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
        if let Some(closed) = state.fold.observe(req, at) {
            self.emit(&state, closed);
        }
    }

    /// The child's stdout ended: close every request still open.
    pub fn finish(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.close_all(&mut state);
    }

    fn close_all(&self, state: &mut ClaudeState) {
        for closed in state.fold.close_all() {
            self.emit(state, closed);
        }
    }

    fn emit(&self, state: &ClaudeState, closed: ClosedRequest) {
        let mut row = self.ctx.row(
            Backend::Claude,
            ("anthropic", &closed.model),
            state.session_id.as_deref().unwrap_or_default(),
            &closed.id,
            closed.at,
        );
        row.turn_index = closed.turn_index;
        row.tokens = closed.tokens;
        row.speed = closed.speed;
        row.stop_reason = closed.stop_reason;
        row.tool_use_count = closed.tool_use_count;
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

    /// Class-wise sum, saturating.
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            input: self.input.saturating_add(other.input),
            output: self.output.saturating_add(other.output),
            reasoning: self.reasoning.saturating_add(other.reasoning),
            cache_read: self.cache_read.saturating_add(other.cache_read),
            cache_write: self.cache_write.saturating_add(other.cache_write),
        }
    }

    /// Class-wise difference, floored at zero: a class the stream carried more
    /// of than the ledger is no remainder, never a negative one.
    pub fn saturating_sub(self, other: Self) -> Self {
        Self {
            input: self.input.saturating_sub(other.input),
            output: self.output.saturating_sub(other.output),
            reasoning: self.reasoning.saturating_sub(other.reasoning),
            cache_read: self.cache_read.saturating_sub(other.cache_read),
            cache_write: self.cache_write.saturating_sub(other.cache_write),
        }
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
/// event names none). `cost_usd` is the pricing table's alone, null when the
/// table has no price for the model; the wire's own `part.cost` is kept apart
/// in `vendor_cost_usd` and never stands in for it.
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
    row.vendor_cost_usd = wire_cost;
    row
}

/// The run-end remainder: the tokens the session ledger settled beyond what
/// the stream carried, by class, priced from the garden table like a streamed
/// row. The ledger's USD difference is the vendor cross-check.
pub fn opencode_ledger_row(
    ctx: &CaptureContext,
    model: &str,
    session_id: &str,
    turn_index: u32,
    unseen: StepTokens,
    vendor_cost_usd: f64,
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
    row.tokens = unseen.counts();
    if let Some(prices) = &ctx.sink.prices {
        prices.price_row(&mut row);
    }
    row.vendor_cost_usd = Some(vendor_cost_usd.max(0.0));
    row
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_telemetry::Speed;

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
    const CLAUDE_RUN: &str = include_str!("../../softfig-telemetry/tests/fixtures/claude-assistant-usage-run.jsonl");

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
        let rec = Arc::new(Collect::default());
        let cap = ClaudeCapture::new(ctx(Arc::clone(&rec), None));
        cap.observe("not json {", 1);
        cap.observe(r#"{"type":"user","session_id":"s"}"#, 2);
        cap.observe(r#"{"type":"assistant","message":{}}"#, 3);
        cap.finish();
        assert!(rec.0.lock().unwrap().is_empty());
    }

    const FLASH_TABLE: &str = "[[model]]\nprovider = \"deepseek\"\nmodel = \"deepseek-flash\"\n\
         input_per_mtok = 0.30\noutput_per_mtok = 1.20\ncache_read_per_mtok = 0.006\n\
         cache_create_per_mtok = 0.0\npeak_hours_utc = [[1, 4], [6, 10]]\n\
         off_peak_multiplier = 0.5\n";

    fn step_tokens() -> StepTokens {
        StepTokens {
            input: 167,
            output: 49,
            reasoning: 14,
            cache_read: 5376,
            cache_write: 0,
        }
    }

    /// 2026-10-10 (Saturday) 07:22 UTC: off-peak. 2026-10-08 (Thursday) 07:22
    /// UTC: inside the 06-10 peak window.
    const OFF_PEAK: i64 = 1_791_616_920;
    const PEAK: i64 = 1_791_616_920 - 2 * 86_400;

    fn flash_step(c: &CaptureContext, at: i64, wire: Option<f64>) -> RequestRow {
        opencode_step_row(
            c,
            "deepseek/deepseek-flash",
            "ses_1",
            "msg_1",
            0,
            step_tokens(),
            None,
            wire,
            at,
        )
    }

    #[test]
    fn an_opencode_step_maps_reasoning_beside_output() {
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
        assert_eq!(row.turn_index, 3);
        assert_eq!(row.stop_reason.as_deref(), Some("tool-calls"));
    }

    #[test]
    fn an_unpriced_opencode_step_stays_null_and_keeps_the_wire_total_apart() {
        let c = ctx(Arc::new(Collect::default()), None);
        let row = flash_step(&c, OFF_PEAK, Some(0.0002));
        assert_eq!(row.cost_usd, None, "no table price: null, never the wire figure");
        assert_eq!(row.vendor_cost_usd, Some(0.0002));
    }

    /// The vendor's `part.cost` has no time dimension, so the same step costs the
    /// same to opencode at any hour; the table's figure doubles at peak.
    #[test]
    fn an_opencode_step_is_table_priced_at_peak_and_off_peak_beside_the_flat_vendor_total() {
        let prices = PriceTable::parse(FLASH_TABLE).unwrap();
        let c = ctx(Arc::new(Collect::default()), Some(prices));
        let vendor = 0.000_078_978; // the captured off-peak step's part.cost
        let off = flash_step(&c, OFF_PEAK, Some(vendor));
        let peak = flash_step(&c, PEAK, Some(vendor));
        // 167 in + 49 out + 14 reasoning (at output) + 5376 cache read, per Mtok.
        let peak_usd = (167.0 * 0.30 + 63.0 * 1.20 + 5376.0 * 0.006) / 1e6;
        assert!((peak.cost_usd.unwrap() - peak_usd).abs() < 1e-12, "{:?}", peak.cost_usd);
        assert!((off.cost_usd.unwrap() - peak_usd / 2.0).abs() < 1e-12, "{:?}", off.cost_usd);
        assert!((off.cost_usd.unwrap() - vendor).abs() < 1e-9, "off-peak matches the vendor");
        for row in [&off, &peak] {
            assert_eq!(row.vendor_cost_usd, Some(vendor), "the wire total is stored apart");
        }
    }

    #[test]
    fn the_ledger_row_is_table_priced_per_class_with_the_vendor_difference_beside_it() {
        let prices = PriceTable::parse(FLASH_TABLE).unwrap();
        let rec = Arc::new(Collect::default());
        let c = ctx(Arc::clone(&rec), Some(prices));
        let row = opencode_ledger_row(&c, "deepseek/deepseek-flash", "ses_1", 4, step_tokens(), 0.01, PEAK);
        assert_eq!(row.settled_from, SettledFrom::Ledger);
        assert_eq!((row.tokens.input, row.tokens.cache_read), (167, 5376));
        assert_eq!((row.tokens.output, row.tokens.thinking), (49, Some(14)));
        let peak_usd = (167.0 * 0.30 + 63.0 * 1.20 + 5376.0 * 0.006) / 1e6;
        assert!((row.cost_usd.unwrap() - peak_usd).abs() < 1e-12, "{:?}", row.cost_usd);
        assert_eq!(row.vendor_cost_usd, Some(0.01));
        c.emit(row);
        let rows = rec.0.lock().unwrap();
        assert!((rows[0].cost_usd.unwrap() - peak_usd).abs() < 1e-12, "emit prices it again to the same figure");
    }

    #[test]
    fn an_unpriced_ledger_row_stays_null_with_a_non_negative_vendor_difference() {
        let c = ctx(Arc::new(Collect::default()), None);
        let row = opencode_ledger_row(&c, "deepseek/deepseek-flash", "ses_1", 4, step_tokens(), -0.5, 9);
        assert_eq!(row.cost_usd, None);
        assert_eq!(row.vendor_cost_usd, Some(0.0));
    }

    #[test]
    fn step_tokens_subtract_per_class_without_going_negative() {
        let a = StepTokens { input: 5, output: 1, reasoning: 0, cache_read: 9, cache_write: 2 };
        let b = StepTokens { input: 2, output: 4, reasoning: 0, cache_read: 9, cache_write: 0 };
        assert_eq!(
            a.saturating_sub(b),
            StepTokens { input: 3, output: 0, reasoning: 0, cache_read: 0, cache_write: 2 }
        );
        assert_eq!(a.saturating_add(b).total(), a.total() + b.total());
    }
}
