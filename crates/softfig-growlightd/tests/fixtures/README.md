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

## opencode 2.x (2.0.24, captured 2026-10-10, `opencode-v2-repin` slice 001)

Captured from `opencode run --standalone --format json --agent member [--model …]`
on `deepseek/deepseek-flash`. Paths were redacted: the fake garden cwd became `/garden`,
the runtime root became `/runtime`, and other scratch paths became `/probe`. Nothing else was edited.
The 1.18.15 files above stay as the historical baseline. Slice 004 re-pins the parser
onto these.

| file | captured from |
|---|---|
| `opencode2-text-run.jsonl` | "Reply with just the word OK." The minimal text-only turn, with the model from the config's top-level `model` |
| `opencode2-tool-run.jsonl` | two `write` calls, both completed |
| `opencode2-denied-run.jsonl` | five model turns. Four `write`/`edit` calls refused (`Permission denied: edit`) and one completed |
| `opencode2-ask-rejected-run.jsonl` | a `read` outside every grant, which falls to the built-in `external_directory * ask` and is auto-rejected headless |
| `opencode2-error-run.jsonl` | `--model deepseek/deepseek-v4-flash` (a stale id). One top-level `error` event, exit 1 |

### What changed from 1.18.15 (load-bearing)

- **The final step has no `step_finish`.** Every 2.x run ends with `step_start` + `text`
  and stops. So the last step's tokens and cost are never in the stream, and summing
  `step_finish.cost` under-reports a run. Observed: $0.00019 streamed against $0.00043 in
  the session record, and $0 streamed against $0.00012 for a text-only run. The
  authoritative per-session totals are opencode's session record (`cost`, `tokens_*`).
- **`step_finish.tokens.total` is gone.** Only `input`, `output`, `reasoning` and
  `cache{read,write}` remain.
- **`tool_use.part.callID` is gone.** `part.partID` is new. `state.input` uses `path`
  (was `filePath`). A refused call has `state.status: "error"` + `state.error` and no
  `title`/`output`.
- **New top-level `error` event**, `{type:"error", timestamp, sessionID, error:{type,message,…}}`
  with **no `part`**. Seen for an unavailable model (`provider.no-route`) and for a
  provider rejection (`provider.invalid-request`, status 410).
- A headless permission `ask` is **auto-rejected**, not hung. The tool result reads "This
  non-interactive run cannot ask the user for permission, so the request was rejected."
  stderr carries `permission requested: external_directory (…); auto-rejecting`.

Still absent: `rate_limit_event`, a `result` line, `rate_limits`, and any context-window %.
