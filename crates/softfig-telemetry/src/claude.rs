//! The claude request fold, shared by both claude capture points (spec §4):
//! growlightd's stream-json `ClaudeCapture` and the semi-auto
//! [`transcript`](crate::transcript) ingester.
//!
//! One response arrives as several `assistant` lines sharing one `message.id`
//! (one per content block, the latest `usage` the most complete). [`ClaudeFold`]
//! keeps the open request per *lane* and closes it when that lane's id
//! changes; the caller closes the rest with [`ClaudeFold::close_all`] at its
//! end of input. A lane is the line's `parent_tool_use_id` (stream-json) or
//! `agentId` (a transcript's sidechain), so a subagent's interleaved requests
//! never split the parent's open one into two rows.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::row::{Speed, TokenCounts};

/// One claude `assistant` line's view of its request.
#[derive(Debug, Clone, PartialEq)]
pub struct AssistantRequest {
    pub id: String,
    pub model: String,
    /// `None` for the main thread; the spawning tool call's id
    /// (`parent_tool_use_id`) or the subagent's `agentId` for a subagent's
    /// request.
    pub lane: Option<String>,
    /// `None` when this line carries no `usage` (an earlier one may have).
    pub tokens: Option<TokenCounts>,
    pub speed: Option<Speed>,
    pub stop_reason: Option<String>,
    /// The `id`s of this line's `tool_use` content blocks.
    pub tool_use_ids: Vec<String>,
}

/// An `assistant` line's request, or `None` for any other line or one with no
/// `message.id`. Pure. claude's `output_tokens` includes thinking; the row
/// stores them apart (`row.rs` [`TokenCounts`]).
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
        lane: str_at(ev, "parent_tool_use_id").or_else(|| str_at(ev, "agentId")),
        tokens,
        speed,
        stop_reason: str_at(msg, "stop_reason"),
        tool_use_ids,
    })
}

/// A request the fold has closed: everything a row needs from the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct ClosedRequest {
    pub id: String,
    pub model: String,
    pub tokens: TokenCounts,
    pub speed: Option<Speed>,
    pub stop_reason: Option<String>,
    pub tool_use_count: u32,
    /// The arrival time of its latest line: the request's completion time.
    pub at: i64,
    /// 0-based close order within this fold.
    pub turn_index: u32,
}

/// A request still receiving `assistant` lines.
#[derive(Debug)]
struct OpenRequest {
    id: String,
    model: String,
    tokens: TokenCounts,
    speed: Option<Speed>,
    stop_reason: Option<String>,
    tool_use_ids: BTreeSet<String>,
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

    /// Fold a later line of the same request: the latest usage, model, speed
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

/// The `message.id` close rule over one claude session's `assistant` lines.
#[derive(Debug, Default)]
pub struct ClaudeFold {
    open: BTreeMap<Option<String>, OpenRequest>,
    turn_index: u32,
}

impl ClaudeFold {
    /// Fold one request line that arrived at `at`. Returns the lane's previous
    /// request when this line starts a new one.
    pub fn observe(&mut self, req: AssistantRequest, at: i64) -> Option<ClosedRequest> {
        let lane = req.lane.clone();
        match self.open.remove(&lane) {
            Some(mut open) if open.id == req.id => {
                open.merge(req, at);
                self.open.insert(lane, open);
                None
            }
            prior => {
                self.open.insert(lane, OpenRequest::new(req, at));
                prior.map(|p| self.close(p))
            }
        }
    }

    /// End of input (or claude's terminal `result` line): close every request
    /// still open, oldest completion first, so `turn_index` follows the wire
    /// order.
    pub fn close_all(&mut self) -> Vec<ClosedRequest> {
        let mut open: Vec<OpenRequest> = std::mem::take(&mut self.open).into_values().collect();
        open.sort_by_key(|o| o.last_at);
        open.into_iter().map(|o| self.close(o)).collect()
    }

    fn close(&mut self, open: OpenRequest) -> ClosedRequest {
        let closed = ClosedRequest {
            id: open.id,
            model: open.model,
            tokens: open.tokens,
            speed: open.speed,
            stop_reason: open.stop_reason,
            tool_use_count: u32::try_from(open.tool_use_ids.len()).unwrap_or(u32::MAX),
            at: open.last_at,
            turn_index: self.turn_index,
        };
        self.turn_index = self.turn_index.saturating_add(1);
        closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn assistant(id: &str, lane: Option<&str>, out: u64) -> AssistantRequest {
        request_for_assistant(&json!({
            "type": "assistant",
            "parent_tool_use_id": lane,
            "message": {"id": id, "model": "claude-opus-5-5", "usage": {"output_tokens": out}},
        }))
        .unwrap()
    }

    #[test]
    fn non_assistant_lines_and_missing_ids_make_no_request() {
        assert_eq!(request_for_assistant(&json!({"type": "user"})), None);
        assert_eq!(
            request_for_assistant(&json!({"type": "assistant", "message": {}})),
            None,
            "no message.id, no request"
        );
    }

    #[test]
    fn a_transcript_agent_id_is_a_lane() {
        let req = request_for_assistant(&json!({
            "type": "assistant", "isSidechain": true, "agentId": "a84",
            "message": {"id": "msg_s"},
        }))
        .unwrap();
        assert_eq!(req.lane.as_deref(), Some("a84"));
    }

    #[test]
    fn an_id_change_closes_the_prior_request_with_its_latest_usage() {
        let mut fold = ClaudeFold::default();
        assert_eq!(fold.observe(assistant("m1", None, 1), 10), None);
        assert_eq!(fold.observe(assistant("m1", None, 50), 11), None);
        let closed = fold.observe(assistant("m2", None, 7), 12).unwrap();
        assert_eq!((closed.id.as_str(), closed.tokens.output, closed.at), ("m1", 50, 11));
        assert_eq!(closed.turn_index, 0);
        let rest = fold.close_all();
        assert_eq!(rest.len(), 1);
        assert_eq!((rest[0].id.as_str(), rest[0].turn_index), ("m2", 1));
        assert!(fold.close_all().is_empty());
    }

    #[test]
    fn another_lane_does_not_close_the_open_request() {
        let mut fold = ClaudeFold::default();
        fold.observe(assistant("p1", None, 1), 1);
        assert_eq!(fold.observe(assistant("s1", Some("toolu_1"), 1), 2), None);
        assert_eq!(fold.observe(assistant("p1", None, 9), 3), None);
        let ids: Vec<_> = fold.close_all().into_iter().map(|c| c.id).collect();
        assert_eq!(ids, ["s1", "p1"], "closed oldest completion first");
    }
}
