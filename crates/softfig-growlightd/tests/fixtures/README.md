# opencode headless event fixtures

Captured from the **real** `opencode` binary (v1.18.15) on 2026-08-13, driving
`deepseek/deepseek-v4-flash`, so the `OpencodeBackend` parser is written against the
wire format rather than a guess. Absolute paths were redacted to `/garden`; nothing else
was edited. No live `opencode` is ever spawned in tests — these files are the substitute.

| file | captured from |
|---|---|
| `opencode-text-run.jsonl` | `opencode run --format json -m deepseek/deepseek-v4-flash "Reply with exactly the word: pong"` — the minimal text-only turn |
| `opencode-tool-run.jsonl` | a read + write tool run under a generated agent whose `permission` allowed `read`/`edit`/`bash` — three model turns |

## Format

NDJSON, one object per line: `{type, timestamp, sessionID, part}`. `timestamp` is
**milliseconds** since epoch (claude's `stream-json` is not — do not reuse claude's
clock handling).

| `type` | `part` fields used |
|---|---|
| `step_start` | `type: "step-start"` — turn boundary, heartbeat only |
| `text` | `text` |
| `tool_use` | `tool`, `callID`, `state.{status,input,output,title,metadata,time}` |
| `step_finish` | `reason` (`tool-calls`\|`stop`), `tokens{total,input,output,reasoning,cache{write,read}}`, `cost` (USD, per step) |

`state.title` is a pre-rendered human-readable label (e.g. `garden/hello.txt`) — prefer
it for the tool delta over truncating `state.input` JSON.

One `step_start`/`step_finish` pair per model turn; the run ends after the final
`step_finish` with `reason: "stop"`.

## What is absent (the load-bearing part)

No `rate_limit_event`, no `result` line, no `rate_limits` object, no context-window
percentage. claude's parser keys on exactly those four, which is why opencode reports
**no 5h/7d reserve** — see `decision-opencode-fleet-backend` in the garden.
