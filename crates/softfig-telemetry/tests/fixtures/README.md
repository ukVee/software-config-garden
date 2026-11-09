# softfig-telemetry fixtures

- `claude-assistant-usage-run.jsonl` — a hand-built claude stream-json run, shared with
  growlightd's capture tests. Its provenance is in
  `crates/softfig-growlightd/tests/fixtures/README.md`.
- `claude-transcript.jsonl` — **hand-built** for slice 005, in the shape of an
  interactive claude transcript: each `assistant` line adds `timestamp`, `sessionId`,
  `isSidechain`, `requestId` and `effort`, and an inline sidechain line adds `agentId`. The
  keys and the `usage` block were read off a real 2026-10-31 transcript (structure only, no
  content). It holds one response split over two lines carrying two tool calls, an
  interleaved sidechain response, non-assistant lines, and a line that is not JSON.
  Current claude writes a subagent's lines to `<session>/subagents/agent-*.jsonl` (same
  `sessionId`, `isSidechain: true`, `agentId`) rather than inline. The ingest verb reads
  those files too.
