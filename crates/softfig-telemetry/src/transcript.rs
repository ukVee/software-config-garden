//! Semi-auto capture (spec §4.2): an interactive `claude` session's transcript
//! JSONL, ingested in one batch by `softfig telemetry ingest-transcript` from
//! claude's `SessionEnd` hook.
//!
//! A transcript line is a stream-json event plus bookkeeping (`timestamp`,
//! `sessionId`, `isSidechain`, `agentId`, `effort`), so the request fold is
//! the very one growlightd runs over a member's stdout: [`ClaudeFold`], the
//! same `message.id` close rule. Rows are [`SettledFrom::Transcript`] and keyed
//! `(session_id, message.id)`, so a re-ingest of the same transcript is a
//! no-op in [`Store::insert_batch`](crate::Store::insert_batch).

use std::collections::HashMap;
use std::io::BufRead;

use serde_json::Value;

use crate::claude::{ClaudeFold, ClosedRequest, request_for_assistant};
use crate::row::{Backend, RequestRow, SettledFrom};
use crate::ts::parse_iso8601_utc;

/// The identity every row from one ingest carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TranscriptKeys {
    /// `semi-auto` for the `SessionEnd` hook.
    pub member: String,
    /// The session a line names no session for (the hook's `session_id`). A
    /// line's own `sessionId` wins, so history a resumed session carries over
    /// keeps the key it was first ingested under.
    pub session_id: Option<String>,
    pub profile: Option<String>,
    pub item_id: Option<String>,
    pub slice_id: Option<String>,
    pub queue: Option<String>,
}

/// What a request's first line said that the fold does not carry.
struct LineMeta {
    session_id: String,
    effort: Option<String>,
}

/// One row per closed request in `reader`, in completion order, numbered per
/// session. Pure: a line that does not parse is skipped, a line with no
/// readable `timestamp` takes the previous line's (or `now`). Every request
/// is kept however old: a backfill's history belongs in `daily_rollup`, and
/// the retention sweep that follows the insert puts it there.
pub fn ingest_transcript(reader: impl BufRead, keys: &TranscriptKeys, now: i64) -> Vec<RequestRow> {
    let mut fold = ClaudeFold::default();
    let mut meta: HashMap<String, LineMeta> = HashMap::new();
    let mut closed: Vec<ClosedRequest> = Vec::new();
    let mut at = now;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Ok(ev) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(ts) = ev.get("timestamp").and_then(Value::as_str).and_then(parse_iso8601_utc) {
            at = ts;
        }
        let Some(mut req) = request_for_assistant(&ev) else {
            continue;
        };
        let id = fold.identify(&mut req);
        let str_at = |k: &str| ev.get(k).and_then(Value::as_str).map(str::to_string);
        meta.entry(id).or_insert_with(|| LineMeta {
            session_id: str_at("sessionId")
                .or_else(|| str_at("session_id"))
                .or_else(|| keys.session_id.clone())
                .unwrap_or_default(),
            effort: str_at("effort"),
        });
        closed.extend(fold.observe(req, at));
    }
    closed.extend(fold.close_all());

    let mut rows: Vec<RequestRow> = closed
        .into_iter()
        .map(|c| {
            let m = meta.remove(&c.id);
            row(keys, c, m)
        })
        .collect();
    renumber_turns(&mut rows);
    rows
}

/// Order `rows` by completion and give each session's rows a 0-based
/// `turn_index` — after merging a session's main transcript with its
/// `subagents/*.jsonl`, whose folds each counted from 0.
pub fn renumber_turns(rows: &mut [RequestRow]) {
    rows.sort_by_key(|r| r.ts);
    let mut next: HashMap<String, u32> = HashMap::new();
    for r in rows {
        let n = next.entry(r.session_id.clone()).or_default();
        r.turn_index = *n;
        *n = n.saturating_add(1);
    }
}

fn row(keys: &TranscriptKeys, c: ClosedRequest, meta: Option<LineMeta>) -> RequestRow {
    let (session_id, effort) = meta.map_or_else(
        || (keys.session_id.clone().unwrap_or_default(), None),
        |m| (m.session_id, m.effort),
    );
    RequestRow {
        ts: c.at,
        backend: Backend::Claude,
        provider: "anthropic".to_string(),
        model: c.model,
        session_id,
        request_id: c.id,
        member: keys.member.clone(),
        profile: keys.profile.clone(),
        item_id: keys.item_id.clone(),
        slice_id: keys.slice_id.clone(),
        queue: keys.queue.clone(),
        turn_index: c.turn_index,
        tokens: c.tokens,
        effort,
        speed: c.speed,
        stop_reason: c.stop_reason,
        tool_use_count: c.tool_use_count,
        latency_ms: None,
        cost_usd: None,
        settled_from: SettledFrom::Transcript,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::{Speed, TokenCounts};

    const TRANSCRIPT: &str = include_str!("../tests/fixtures/claude-transcript.jsonl");
    const STREAM_RUN: &str = include_str!("../tests/fixtures/claude-assistant-usage-run.jsonl");

    fn keys() -> TranscriptKeys {
        TranscriptKeys {
            member: "semi-auto".to_string(),
            session_id: Some("hook-session".to_string()),
            profile: Some("slot2".to_string()),
            item_id: Some("token-telemetry-p1".to_string()),
            ..TranscriptKeys::default()
        }
    }

    fn at(s: &str) -> i64 {
        parse_iso8601_utc(s).unwrap()
    }

    const NOW: &str = "2026-10-31T19:00:00Z";

    #[test]
    fn one_row_per_message_id_with_the_latest_usage_and_every_tool_call() {
        let rows = ingest_transcript(TRANSCRIPT.as_bytes(), &keys(), at(NOW));
        let ids: Vec<_> = rows.iter().map(|r| r.request_id.as_str()).collect();
        assert_eq!(ids, ["msg_t1", "msg_s1", "msg_t2"], "completion order, sidechain in its own lane");
        let t1 = &rows[0];
        assert_eq!(t1.ts, at("2026-10-31T18:00:05Z"), "the request's last line");
        assert_eq!(
            t1.tokens,
            TokenCounts {
                input: 2,
                output: 184,
                cache_read: 0,
                cache_creation: 27_224,
                cache_creation_1h: 27_224,
                thinking: Some(12),
            }
        );
        assert_eq!((t1.tool_use_count, t1.stop_reason.as_deref()), (2, Some("tool_use")));
        assert_eq!((t1.effort.as_deref(), t1.speed), (Some("high"), Some(Speed::Standard)));
        assert_eq!(rows[2].speed, Some(Speed::Fast));
        assert_eq!(rows[1].effort, None, "the sidechain line names no effort");
        let turns: Vec<_> = rows.iter().map(|r| r.turn_index).collect();
        assert_eq!(turns, [0, 1, 2]);
    }

    #[test]
    fn rows_carry_the_keys_and_the_transcripts_own_session() {
        for r in ingest_transcript(TRANSCRIPT.as_bytes(), &keys(), at(NOW)) {
            assert_eq!(r.session_id, "sess-t", "a line's sessionId beats the hook's");
            assert_eq!((r.member.as_str(), r.profile.as_deref()), ("semi-auto", Some("slot2")));
            assert_eq!(r.item_id.as_deref(), Some("token-telemetry-p1"));
            assert_eq!((r.backend, r.provider.as_str()), (Backend::Claude, "anthropic"));
            assert_eq!((r.settled_from, r.cost_usd), (SettledFrom::Transcript, None));
        }
    }

    #[test]
    fn the_stream_fixture_folds_to_the_same_requests_as_growlightds_capture() {
        let now = at(NOW);
        let rows = ingest_transcript(STREAM_RUN.as_bytes(), &keys(), now);
        let ids: Vec<_> = rows.iter().map(|r| r.request_id.as_str()).collect();
        assert_eq!(ids, ["msg_01", "msg_02"]);
        assert_eq!(rows[0].session_id, "sess-1");
        assert_eq!((rows[0].tokens.output, rows[0].tokens.thinking), (180, Some(120)));
        assert!(rows.iter().all(|r| r.ts == now), "no timestamps: ingest time");
    }

    #[test]
    fn requests_older_than_the_retention_horizon_are_kept() {
        // The sweep rolls them up after the insert; dropping them here would
        // lose a backfill's history.
        let rows = ingest_transcript(TRANSCRIPT.as_bytes(), &keys(), at(NOW) + 400 * 86_400);
        let ids: Vec<_> = rows.iter().map(|r| r.request_id.as_str()).collect();
        assert_eq!(ids, ["msg_t1", "msg_s1", "msg_t2"]);
    }

    #[test]
    fn a_session_less_line_falls_back_to_the_hooks_session() {
        let line = r#"{"type":"assistant","message":{"id":"m","model":"claude-opus-5-5"}}"#;
        let rows = ingest_transcript(line.as_bytes(), &keys(), at(NOW));
        assert_eq!(rows[0].session_id, "hook-session");
    }

    #[test]
    fn an_id_less_line_with_usage_becomes_a_row_keyed_by_its_session() {
        let lines = concat!(
            r#"{"type":"assistant","sessionId":"sess-t","message":{"model":"claude-opus-5-5","usage":{"output_tokens":7}}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"sess-t","message":{"model":"claude-opus-5-5","usage":{"output_tokens":9}}}"#,
        );
        let rows = ingest_transcript(lines.as_bytes(), &keys(), at(NOW));
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r.session_id.as_str(), r.request_id.as_str(), r.tokens.output))
            .collect();
        assert_eq!(got, [("sess-t", "anon:main:0", 7), ("sess-t", "anon:main:1", 9)]);
        let again = ingest_transcript(lines.as_bytes(), &keys(), at(NOW));
        let key = |rs: &[RequestRow]| rs.iter().map(|r| r.request_id.clone()).collect::<Vec<_>>();
        assert_eq!(key(&rows), key(&again), "a re-ingest names the lines the same way");
    }

    #[test]
    fn renumbering_merges_subagent_files_per_session_in_time_order() {
        let mut rows = ingest_transcript(TRANSCRIPT.as_bytes(), &keys(), at(NOW));
        let sub = r#"{"type":"assistant","sessionId":"sess-t","agentId":"b1","timestamp":"2026-10-31T18:00:06.000Z","message":{"id":"msg_b1"}}"#;
        rows.extend(ingest_transcript(sub.as_bytes(), &keys(), at(NOW)));
        renumber_turns(&mut rows);
        let order: Vec<_> = rows.iter().map(|r| (r.request_id.as_str(), r.turn_index)).collect();
        assert_eq!(order, [("msg_t1", 0), ("msg_b1", 1), ("msg_s1", 2), ("msg_t2", 3)]);
    }
}
