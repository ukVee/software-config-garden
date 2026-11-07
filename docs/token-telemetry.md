# Token telemetry — what is recorded, where, and how

> Phase 1 of the garden's `meta/spec-token-telemetry.md` (§3.1, §4, §5, §6, §10).
> Built by the `token-telemetry-p1` milestone, slices 001–005, on `feat/token-telemetry`.

Every model API request a growlight session makes becomes one row in a local
sqlite db. A request is one assistant message from claude, or one step from
opencode. Each row records:

- who made the request: backend, provider, model, session, member, profile;
- what it was for: item, slice, queue;
- what it used: input, output, cache-read, cache-write and thinking tokens;
- what it cost: `cost_usd`, derived once at write time from the garden's
  price table.

Phase 1 is capture and storage only. Nothing reads the db yet. The schedule's
work projection and the slice-cost estimates come later and will read it.

## The crate

`crates/softfig-telemetry` is frontend-neutral. It depends on rusqlite, serde,
toml and thiserror, and on no other workspace crate.

| Module | What it holds |
|---|---|
| `row` | `RequestRow`, `TokenCounts` (disjoint classes: claude's thinking tokens are carved out of `output_tokens`, so pricing never counts them twice), `SettledFrom` |
| `schema` | the DDL and every tuning constant (ring size, flush thresholds, retention) |
| `store` | `Store`: open + migrate, `insert_batch` (idempotent), `sweep_retention` |
| `ring` | `RingRecorder`, the bounded in-memory ring capture points record into |
| `flush` | `Flusher` / `FlushHandle`, the thread that drains the ring into the store |
| `recorder` | the `Recorder` seam plus `NullRecorder` |
| `pricing` | `PriceTable`: load `config/pricing.toml`, `price_row` |
| `claude` | `ClaudeFold`, the per-`message.id` request merge shared by the stream and transcript paths |
| `transcript` | `ingest_transcript`, `renumber_turns` (semi-auto) |
| `ts` | unix seconds → `YYYY-MM-DDTHH:MM:SSZ` text, hand-rolled (no chrono). The text sorts in time order, so the retention sweep compares strings. |

## The db

- **Path:** `$XDG_STATE_HOME/softfig/telemetry.db`, falling back to
  `~/.local/state/softfig/telemetry.db` (`default_db_path`). It lives outside the
  garden, so it is never committed or replicated. That is deliberate:
  telemetry is per-device and high-churn.
- **Permissions:** the db and its `-wal` and `-shm` sidecars are `0600`. The
  files are created that way whatever the umask, and tightened on open if an
  older build left them wider. Schema v5 is current.
- **`requests`:** one row per request. The unique key is
  `(session_id, request_id)`, so re-ingesting a request adds nothing.
  - `cost_usd` is `NULL` when the model has no price, never `0`. The garden
    price table prices every row on every backend, so one basis sums.
  - `vendor_cost_usd` (schema v4) is the backend's own figure for the request
    (opencode's `part.cost`, or the ledger's USD difference on the remainder
    row). It is a cross-check, `NULL` where the wire carries none, never summed
    into `cost_usd` and not rolled up.
  - `cache_creation_1h_input_tokens` is a subset of
    `cache_creation_input_tokens`, priced at the 1-hour cache-write rate.
  - `settled_from` is `stream`, `ledger` or `transcript`.
- **`daily_rollup`:** per `(day, model, backend, provider, slice_id)` sums,
  kept forever. `cost_usd` sums only the priced rows; `unpriced_requests`
  (schema v3) counts the rest. A rollup row is exact only where
  `unpriced_requests = 0`, and a row with `unpriced_requests = requests` has no
  cost known at all, never a free one.
- **Retention:** raw rows live 90 days (`RAW_RETENTION_DAYS`). Once a day the
  sweep rolls older rows into `daily_rollup` and deletes them, in one
  transaction. `ingest-transcript` runs the same sweep after its insert, so a
  device with no flush thread still rolls up and prunes, and a backfill of old
  history lands in the rollup instead of being dropped. A per-session
  `rollup_watermark` (schema v2) keeps a resumed session's already-rolled-up
  history from being counted twice.
- **Wear:** the tablet's eMMC is wear-sensitive.
  - The ring holds up to 10 000 rows. On overflow it drops the oldest and
    counts the drop (`FlushStats::dropped`). A flush that saw new drops logs one
    `telemetry: ring overflowed, N row(s) dropped` line.
  - The flush runs every 30 s, or as soon as 1 000 rows are pending.
  - Each flush is one transaction, and an idle flush opens none.
  - growlightd's shutdown journals the flush thread's totals:
    `softfig-growlightd: telemetry: N row(s) in B batch(es), F failed; D dropped by the ring; R rolled up in S sweep(s)`.

Telemetry never blocks a member or the daemon. Any of these logs a line and
drops rows rather than failing the session:

- a db that won't open;
- a failed batch (counted in `failed_batches`; the spec accepts the loss).

A missing or unparseable price table drops nothing. growlightd logs one line
(`no price table, rows stay unpriced`) and keeps the ring recorder, so every
row is still recorded, with `cost_usd = NULL`.

## The three capture points

growlightd has no HTTP client. It shells out to `claude -p` and `opencode run`, and
semi-auto runs an interactive `claude`. So capture reads the events those
already emit (spec §4):

1. **claude fleet members** (`settled_from = stream`). growlightd folds the
   `--output-format stream-json` `assistant` events and emits one row per closed
   `message.id`. A message spans several events, one per content block, and
   carries the same usage on each.
   - A row closes when a different id appears in the same lane, or at EOF.
   - An id the fold already closed is ignored if a later line re-emits it, so
     the ring shows the rows the db's `UNIQUE(session_id, request_id)` keeps.
   - A line with a `usage` but no `message.id` is its own request, named
     `anon:<lane or main>:<n>` (`n` counts the id-less lines in that fold), so
     its tokens are kept and a re-ingest names it the same way. An id-less line
     with no `usage` is dropped.
   - A lane is the line's `parent_tool_use_id` (stream-json), or its `agentId`
     (a transcript's subagent lines). So a subagent's interleaved messages never
     close the parent's.
2. **opencode fleet members.** There are two kinds of row:
   - one row per `step_finish` event (`stream`);
   - one remainder row at EOF (`ledger`). opencode 2.x never streams its final
     step, so this row is settled against opencode's `session_v2` totals: its
     token classes are the ledger's per-class totals minus the streamed sums.
     It is priced from the garden table like any other row.

   opencode's `part.cost` has no peak-hour dimension, while the garden table
   charges DeepSeek peak rates (weekday UTC hours 01-04 and 06-10). So
   `sum(cost_usd)` for a session matches `session_v2` off-peak and runs up to 2x
   above it at peak, which is expected. Compare `session_v2` against
   `sum(vendor_cost_usd)`.
3. **semi-auto claude** (`transcript`). A `SessionEnd` hook ingests the
   session's transcript JSONL in one batch. See below.

Fleet capture is wired only while the fleet is armed (`fleet_enabled = true`).
A disarmed growlightd records nothing. Fleet rows carry the member id, the
item, the slice and the profile slot. A v2 spawn's `queue` tag is the entry's
project, because v2 has no named queues.

## The price table — `config/pricing.toml`

The table lives in the garden, so it is versioned, encrypted at rest and
editable through the mount. Each `[[model]]` row is keyed by
`(provider, model)`. Prices are USD per million tokens:

- `input`, `output` and `cache_read_per_mtok`;
- `cache_create_per_mtok`, for 5-minute cache writes;
- `cache_create_1h_per_mtok`, which defaults to the 5-minute price;
- `thinking_per_mtok`, which defaults to the output price.

There are optional modifiers too: a `fast_mode_multiplier`, long-context tier
rows (`prompt_tokens_over`), and peak/off-peak windows. The file's header
documents every field.

- **Lookup** tries the exact model id first. Then it tries the id with any
  `[…]` tag and `-YYYYMMDD` snapshot date stripped. There is deliberately no
  longest-prefix match, so an unknown id is never priced at a sibling model's
  price.
- **An unknown model stores `cost_usd = NULL`, never 0.** A null cost means
  "unpriced". A 0 would look like "free" and quietly understate every sum.
- **The cost is fixed at write time.** Editing a price never rewrites history.
- **When the table is loaded:** growlightd loads it once at startup, so a price
  edit reaches the fleet at the next growlightd restart. The semi-auto verb
  loads it on every run.
- **Validate after editing:**
  `SOFTFIG_PRICING_TOML=<file> cargo test -p softfig-telemetry -- --ignored seeded_table_parses`.

## Semi-auto: the `SessionEnd` hook

`softfig growlight start` generates `loop.json`. Its `hooks.SessionEnd` runs:

```text
'<softfig>' telemetry ingest-transcript --garden-root '<garden>' --config-dir '<runtime dir>'
```

Claude Code hands the hook `{session_id, transcript_path, …}` on stdin. The
garden root and runtime dir are baked in, so the rows are priced from, and
keyed by, the garden and root baton that the launch used, with no daemon
round-trip at session end. The hook is only in the generated file. Never
hand-edit the live `loop.json`: `start` rewrites it on every launch.

How the verb keys the rows:

| Column | Source |
|---|---|
| `member` | always `semi-auto` |
| `session_id` | each transcript line's own `sessionId`, else the hook's `session_id`, else the file stem. A line's id wins, so history carried across a resume keeps the key it was first written under. |
| `item_id` / `slice_id` | the root `baton.md` head (`item:` / `slice:`, quotes stripped) |
| `profile` | the slot named by `CLAUDE_CONFIG_DIR` (its last path component) |
| `effort` | read from each line |
| `queue` | always null; see the known gaps |

The rest of the verb's behaviour:

- **Subagents.** Current claude writes a subagent's messages to
  `<dir>/<session>/subagents/*.jsonl`, with the parent's `sessionId`. The verb
  ingests those files after the main transcript, in sorted order. A subagent
  file that disappears mid-read costs only its own rows.
- **Timestamps.** A line with no timestamp takes the previous line's, or the
  current time if no line before it had one.
  `renumber_turns` sorts the rows by time and numbers the turns per session.
- **Pricing.** The verb reads the table from `--garden-root`. Without that flag
  it asks the running daemon for the garden root. If the table can't be found
  or parsed, it prints a line to stderr and the rows stay unpriced.
- **Repeat `SessionEnd`.** The db keeps a per-file byte mark
  (`transcript_marks`, schema v5). If no file of the session has grown past its
  mark, the verb skips the parse and the insert (the retention sweep still
  runs). If any file grew, it re-reads the whole set so `turn_index` stays
  whole-session, then advances the marks once the batch is in. A transcript
  rewritten to the same or a shorter length is not re-read.
- **Idempotent and fail-soft.** Running the verb twice adds nothing. It always
  exits 0 and reports problems only on stderr, so the hook can never fail a
  session.
- **Backfill by hand:**
  `softfig telemetry ingest-transcript --path <transcript.jsonl> [--session-id S] [--db P]`.
- **No double capture.** Fleet members launch with their own per-agent
  settings, so this hook never runs inside a fleet member's session. If it did,
  the `(session_id, request_id)` key would deduplicate the rows anyway.

## Known gaps (phase 1)

- **Semi-auto opencode is not captured.** opencode has no session-end hook, so
  `softfig growlight start --opencode` records nothing.
- **Semi-auto rows always have `queue = NULL`.** The root baton has no `queue:`
  field, and the launcher doesn't resolve one.
- **A fleet member's first session on an item has `slice_id = NULL` unless its
  baton already named a slice.** growlightd reads the slice from the member's
  baton before the claim seeds it. A kept baton (the same item) carries its
  slice; a fresh seed names none, and growlightd attributes nothing rather than
  guess, journalling `telemetry: <agent>'s first session on <queue>/<item> is
  unattributed to a slice`. A re-roll reads the slice the member handed off, so
  later sessions are attributed.
- **No surfaces yet.** There is no `softfig telemetry` report verb, no TUI pane
  and no budget projection. Read the db with `sqlite3` for now:

  ```sh
  sqlite3 ~/.local/state/softfig/telemetry.db \
    'select member, model, count(*), sum(cost_usd) from requests group by 1, 2'
  ```
