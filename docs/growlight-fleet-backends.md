# growlight fleet backends — putting a member on opencode

> Applies to `config/growlight.toml` in the garden, read by growlightd at arm time.
> Added by the `opencode-fleet-backend` milestone (spec-agents phase 2), slices 005-006.

A growlight fleet member runs on `claude -p` by default. It can instead run on
`opencode run` (over a metered provider such as DeepSeek), chosen **per member**, so
a roster can mix the two.

## The keys

```toml
fleet_enabled = true

# Which queue model growlightd schedules from (spec-growlight-queue §11).
# Default `legacy` (today's backlog tables + queues); `v2` reads the v2 files.
# Unknown values are refused at arm time. The migration session flips it,
# after `softfig growlight queue migrate` (docs/growlight-queue-migrate.md).
# queue = "legacy"

# The v2 handshake's grace: seconds a member may linger after growlightd asks
# it to roll before its session is terminated (spec-growlight-queue §6.3 step 4).
# Omit for the default. Only read when `queue = "v2"`.
# roll_grace_secs = 20

# The binaries each backend shells. Both are resolved on PATH when omitted.
# claude_bin   = "claude"
# opencode_bin = "opencode"

[[fleet]]
agent = "a"                              # backend omitted ⇒ claude

[[fleet]]
agent   = "b"
backend = "opencode"                     # claude (default) | opencode
model   = "deepseek/deepseek-flash"      # opencode only; REQUIRED — no model ⇒ refused
variant = "high"                         # opencode only; optional
```

`backend` defaults to `claude`, so a config written before this existed keeps running
exactly as it did — there is no migration.

`queue` defaults to `legacy`, so scheduling is unchanged until the v2 migration flips
it (spec-growlight-queue §11). An unknown value is a parse error — growlightd logs it
and stays disarmed, never silently meaning legacy.

`roll_grace_secs` (default 20) is the v2 handshake's grace window (spec-growlight-queue
§6.3 step 4). When growlightd asks a member to roll into a fresh session — context full,
model change, preemption — it lets the member finish the verb it is on, then terminates
its session when it exits **or** after the grace, whichever comes first. The grace is
the hard bound, not a polite request: a member that ignores the handshake and keeps
running is stopped at `roll_grace_secs` rather than left occupying the assignment.
It is only read when `queue = "v2"`; a legacy fleet ignores it.

`model` / `variant` ride **argv** (`--model provider/model[#variant]`), not the generated
config. opencode 2.x `run` ignores `agent.<id>.model` entirely, and argv is the one model
source that fails closed on a bad id (opencode-v2-repin slice 001, L5 + L7), so the config
carries no model key at all. The member's `opencode.json` (still written fresh per spawn,
still holding the permission map) and the argv are built by the same spawn path, so the
model a member runs on and the permission map that member was granted cannot drift apart.

## Declaring a claude member's model

A claude member picks up its model and effort from the same `[[fleet]]` block,
in a grammar that mirrors `claude -p`'s own `--model` / `--effort`:

```toml
[[fleet]]
agent   = "a"                            # backend omitted ⇒ claude, no --model/--effort
# model   = "claude:claude-opus-4-7"     # optional; spawn adds `--model claude-opus-4-7`
# variant = "high"                       # optional; spawn adds `--effort high`

[[fleet]]
agent   = "b"
backend = "claude"
model   = "claude:fable[1m]"             # alias + 1M-context suffix also parse
variant = "max"                          # closed set: low | medium | high | xhigh | max
```

- `model` on a claude member is **optional**. Omitting it spawns `claude -p`
  without `--model`, which is byte-identical to a pre-`claude-model-select`
  claude member.
- When set, it must be prefixed `claude:<alias|id>`; `<alias>` is one of
  `opus | sonnet | haiku | fable`, `<id>` matches
  `claude-[a-z0-9]+(-[a-z0-9]+)*`, and either may carry the `[1m]` suffix. A
  bare `<id>` without the `claude:` prefix is refused at arm time with a parse
  message naming the fix. An opencode-shape `provider/model` on a claude member
  stays refused as opencode-only.
- `variant` names the effort and is passed as `--effort <v>`. It is a **closed
  set** on claude: `low | medium | high | xhigh | max`; a value outside the set
  is refused at parse time.
- An item's declared `> Model: claude:<m>` (plus optional `effort=`) overrides
  the roster entry on spawn; the roster entry is the member's default for work
  with no `> Model:` line. See `spec-growlight-queue.md` §6.4 for the full
  resolution chain.
- When Claude Code refuses the requested model (`model_not_found` / 404), the
  REFUSING MEMBER parks (its `not_before` is set to `i64::MAX`) with a single
  alert carrying the refusal reason — there is no crash loop and no backoff
  retry (`claude-model-select` slice 003, 2026-10-23). The ITEM is parked at
  the same time (`park_item` through keeperd + `pause_v2_entry` for a v2
  assignment), the member's claim is released, and its slot is freed, so a
  sibling member runs other work; the refusing member stays registered and
  parked (`claude-login-pool-wiring` slice 004 M-E, 2026-10-24). Every
  subsequent tick runs a reconcile pass that re-reads the item's `> Model:`
  chain (slice doc → milestone doc) and the live roster through the §6.4
  resolver, compares the resolved choice to the latched refused one, and —
  if they differ — **releases the member at an item boundary**
  (`supervisor.retire` + `aggregator.forget` + the latch drop; slice 008,
  2026-10-28). The same tick's step 3 then picks + claims + copies a fresh
  §3.6 baton + spawns on the live-resolved model, so a human edit to the
  item declaration or the roster model un-parks the member on the next tick
  with no daemon restart and no stale baton re-roll. A v2 paused entry is
  pickable by `pick_v2` so an edited entry resumes through a real claim; a
  legacy `blocked` item stays blocked by default and the freed member moves
  to the next workable part (the human re-queues the item to re-run it). An
  unreadable item doc is treated as "undeclared" so a transient keeperd miss
  cannot spuriously un-park. The single ModelRefused alert is never
  re-emitted while the park stands.
- **Known gap (review 048 M-A/M-B/M-C, tracked in `claude-login-pool-wiring`
  milestone):** with `profile_pool` configured, the admission budget rail folds
  fleet-wide (one slot's `allowed_warning` can halt members pooled on other
  accounts), `RateLimitHolds` is memory-only (so a daemon restart loses the
  hold and may spin the member against a still-closed window until it
  observes a fresh `rate_limit_event`), and `pick_pool_slot` does not filter
  credential-missing or already-held slots before its LRU sort (so a slot made
  with `add --no-login` can keep winning and wedging the member). With no
  `profile_pool` configured (today's `config/growlight.toml`), behaviour is
  byte-identical to the pre-switcher spawn, so the gaps are gated behind the
  owner enabling pools in config.

## What is refused

Four config mistakes are reported and refused at arm time rather than defaulted. All
four are the same hazard — **a member running on a pool the operator did not choose** —
and a fleet that silently ran claude while its operator believed it was on DeepSeek would
burn the Anthropic subscription without anyone noticing:

| Written | Result |
|---|---|
| `backend = "opencde"` (any unknown value) | refused, naming the member and the valid backends |
| `backend = "opencode"` with no `model` | refused — on 2.x a member with no model would run on opencode's own default provider, which the operator never chose |
| `model = "…"` with no `backend = "opencode"` | refused — those keys are opencode-only |
| `backends = "opencode"` (any unknown key) | refused — a dropped typo would silently mean claude |

A refusal fails **closed**: growlightd logs the message and the fleet stays disarmed. A
config problem can never arm a fleet, let alone arm one onto the wrong provider.

Each opencode member also launches on a **private server** (`opencode run --standalone`),
a child that lives and dies inside the member's own transient scope. Without the flag the
member's tools would run in the per-user shared service, which ignores the client's
`OPENCODE_CONFIG` — the member would silently run as the built-in `build` agent with
allow-all permissions and every global grant (opencode-v2-repin slice 001, finding 1).

## What an opencode member may touch

Each member's `opencode.json` carries an ordered list of opencode 2.x permission rules at
the config's **top level**. The same builder (`softfig_ipc::opencode::floor`) writes the
interactive `growlight start --opencode` config, so the two never drift. The last
matching rule wins, which makes the order the design:

| # | Rule | Why |
|---|---|---|
| 1 | `external_directory * deny` | resets the global `~/.config/opencode` grants (`~/projects/**`, `~/dotfiles/**`, `/tmp/**`, …) and opencode's built-in allow on its own config dir |
| 2 | `external_directory <runtime>/**`, `<~/.claude/projects>/** allow` | the baton and the memory tree |
| 3 | `external_directory <opencode data>/shell/*/*`, `…/tool-output/* allow` | truncated tool output stays readable (read-only: no `edit` rule opens them) |
| 4 | `read * allow`, then `read *.env` / `*.env.*` deny, `*.env.example` allow | opencode's own `.env` caution, restated because `read *` would override it |
| 5 | `shell * allow`, `softfig-mcp* * allow` | the member's tools and the garden verbs |
| 6 | `edit * deny` | the garden write guard: garden mutations go through softfig-mcp |
| 7 | *(interactive config only)* `edit /* ask` | see below |
| 8 | `edit <runtime>/** allow`, then `edit <~/.claude/projects>/** deny` | the baton write; the memory tree stays read-only (see below) |

Three facts make this shape work, all probe-proven on 2.0.24 (opencode-v2-repin slice 001):

- A path inside the garden (the member's cwd) is matched as a **cwd-relative** resource, so
  an absolute garden glob never matches. The guard has to be the universal deny, with
  everything writable re-opened after it.
- Top-level rules govern **every** agent the member's private server loads, including the
  `general` / `explore` subagents a `subagent` call spawns. A subagent runs on its own
  agent's rules, so rules placed only on the member's agent would leave every global grant
  one subagent call away.
- A headless member cannot answer a prompt, so nothing here asks. The interactive config
  differs only where a human can answer: rule 1 and the `.env` rules `ask`, and rule 7,
  `edit /* ask`, puts code-repo edits (absolute resources) to the human without
  reaching the garden (relative resources).

**Memory is read-only for a fleet member.** The interactive config ends rule 8 on
`edit <~/.claude/projects>/** allow`; a member's ends on `deny`. The human's call
(2026-10-10, `decision-opencode-v2-fleet-safety-order` § Memory): unattended members get
memory write access only once every write is tracked and revertable. One constant,
`MEMBER_MEMORY` in `opencode_preapproval`, sets both this rule and whether the member's
prompt carries the write rules, so the flip is one line. The deny is explicit rather
than left to rule 6, so read-only would hold even under the interactive `edit /* ask`.

Generation fails **closed**: a floor directory that is relative, non-UTF-8, carries a `*`
or `?`, or is `/` refuses the spawn. A relative root would render `edit <rel>/** allow`,
which matches the garden's own resources and opens a hole through the guard.

The **shell is not a boundary.** `shell * allow` runs with full host authority, so these
rules stop well-behaved tool calls, not a determined command line. The OS-level boundary is
the Landlock step of `decision-opencode-v2-fleet-safety-order`.

## What an opencode member is told

opencode 2.x loads `AGENTS.md` only. It never falls back to `CLAUDE.md`, ignores the
`instructions` field, and has no notion of claude-memory. So the member's
`agents.<id>.system` carries everything a Claude Code session would have been handed, in
this order, every piece by `{file:}` reference (house rule 1: never copied):

1. the fleet protocol, `growlight/protocol-fleet.md` (`growlight/protocol-fleet-v2.md` under
   `queue = "v2"`);
2. the step-0 line naming this member's own `agents/<id>/baton.md`;
3. the garden root `CLAUDE.md` (the map and the house rules);
4. `growlight/memory-read.md`, the read half of the memory rules;
5. `growlight/memory-write.md`, the write half, **only** where memory is writable
   (the interactive loop, never a member today);
6. the memory directory and its index, `MEMORY.md`.

The memory directory is the one Claude Code itself keeps for the garden:
`~/.claude/projects/<slug>/memory`, where the slug is the garden path with every
character outside `[A-Za-z0-9]` replaced by `-` (`/home/u/soft-fig_garden` →
`-home-u-soft-fig-garden`). A path whose slug passes 200 characters, which Claude Code
would hash, gets no memory section.

The builder is `softfig_ipc::opencode::context`, shared with the interactive config.
It references a file **only if it exists and is readable at spawn**: opencode fails the
whole location (HTTP 500 on every call) on a `{file:}` naming a missing file, so a fresh
install with no `MEMORY.md`, or a garden whose pillar predates the memory rules, still
generates. Since generation runs per spawn, each member sees memory as it is when it
starts.

Also probe-proven on 2.0.24 (slice 005): `{file:}` expands by position in one pass over
the raw config text. The content is trimmed and lands verbatim, and a `{file:}` or
`{env:}` literal inside an injected file is never expanded. Because the path is read out
of the raw JSON text, a path containing `{`, `}`, `"`, `\` or a control character
refuses the spawn rather than naming the wrong file.

## What each backend contributes to admission

The two providers are not symmetric, and the asymmetry is deliberate:

- **The 5h/7d account budget** is the Anthropic subscription pool. Only claude members
  report it. An opencode member contributes **nothing** — `budget()` is structurally
  `None`. A synthesised percentage would corrupt the gate governing the claude members,
  so a mixed fleet's budget aggregate is exactly its claude members' aggregate.
- **The rolling-minute TPM/RPM window** is provider-neutral — tokens per minute mean the
  same thing either side — so it sums across **every** backend. It is summed over the
  distinct backends, not over members: several claude members share one backend, whose
  window is already fleet-wide across them.

- **Per-member USD spend** is the mirror image of the budget: only an opencode member
  reports it, and a claude member contributes **nothing** — its cost *is* the 5h/7d
  reserve above. The spend seam is structurally `None` for claude for the same reason
  `budget()` is structurally `None` for opencode.

On opencode 2.x the stream never carries a run's **final** step: there is no closing
`step_finish`. So while a member runs, its spend and its rolling-minute tokens are what
streamed, a lower bound. When its output closes, growlightd reads the run's totals from
opencode's own session store (`$XDG_DATA_HOME/opencode/opencode.db`, read-only) and
settles:

- **Spend** is raised to the recorded total, which includes any subagent sessions the
  member started. It is never lowered.
- **Rate**: the tokens the stream never showed are metered as one more request, the
  final step's. Without this, a one-step text run would meter nothing at all.

If the store can't be read (missing, locked, or a schema opencode has since changed), the
member keeps the streamed figures and growlightd logs
`spend stays the streamed lower bound: …` to its journal. Accounting never fails a member.

Each seam answers `None` for the provider it does not describe, and nothing invents the
other reading. That symmetry is what makes the status surface honest — see below.

The interactive `growlight start --opencode` loop has no admission at all. Its only budget
source is protocol §2b's `usage.json`, and only Claude Code's statusline writes that file.
So the generated agent prompt carries a §2b override ahead of the step-0 line
(`OPENCODE_BUDGET_NOTE`): the Claude windows do not bind an opencode session, it never
halts on them, and it omits the 5h/7d percentages from the baton. Without that override, a
session started while the Claude window was spent would halt immediately, and that is
exactly when the human reaches for opencode.

## When members run: the `[schedule]` table

`[schedule]` in `config/growlight.toml` is an admission filter on top of everything above
(growlight-schedule spec §3). `fleet_enabled` stays the master arm. With
`[schedule] enabled = true`, an armed fleet admits a member only while one of its windows
is open, in local time:

```toml
[schedule]
enabled = true
windows = ["23:00-07:00"]          # every day, every member
reserve_weekly_pct = { slot1 = 20, "*" = 0 }

[[schedule.window]]
days     = ["mon-fri"]
start    = "10:00"
end      = "20:00"
backends = ["opencode"]            # and/or members = ["b"]
```

- **Windows union.** A member is admitted when any window whose filters match it is open.
  `backends` and `members` must both match. A window that crosses midnight belongs to the
  day it starts.
- **A close never kills.** A member mid-iteration finishes, and its re-roll waits for the
  next open window. Past `close_grace_minutes` (default 45) it is flagged `overrun`.
- **Timed items.** With `tasks = true` (the default), an item whose `> Not before:` has
  arrived may run outside every window.
- **The weekly reserve** is per claude-login slot. A slot is held once its vouchable 7d
  reading reaches `100 − reserve`, until the window resets. opencode members are never
  reserve-held, because they draw on no weekly window.
- **Restart after an edit.** growlightd reads `[schedule]` once, at start, so an edit
  takes effect after `systemctl --user restart softfig-growlightd`. There is no reload.
  Each open or close edge is one line in the journal (`schedule: window <label> opened`),
  not on the coordination bus.
- **Fail-closed.** An unknown key, a bad time or day, or a `members` id with no `[[fleet]]`
  agent disables the fleet at load. An unreadable local zone closes the schedule for
  everyone.

The shipped template (`templates/default-garden/config/growlight.toml`) documents every
key.

## Reading a mixed fleet: `growlight status`

`growlight status` reports two lists, and the difference matters:

- **`roster`** — what `config/growlight.toml` declares. Always present, even while the
  fleet is disarmed.
- **`agents`** — one live row per member of an **armed** fleet. Empty while disarmed:
  nothing is assembled then, so there is no runtime state to report and inventing a
  roster echo here would claim liveness the daemon cannot observe.

Its `queue` line is the §11 switch as growlightd read it at boot, `legacy` or `v2`, armed or
not. `protocol` is the wire version and stays `v1` under either, so read `queue` to see that a
flip took. A growlightd older than the field prints no `queue` line.

```
roster:
  a                pin=queue:default
  b                (fallback)
agents:
  a                running      claude
  b                running      opencode · deepseek/deepseek-flash (high) · $0.14 this session (3 steps)
```

The TUI fleet panel carries the same reading, terser (`b:running · opencode ·
deepseek/deepseek-flash · $0.14`).

Note what a **claude** row does *not* show: a dollar figure. There is no per-member
reserve or spend column at all, and that is the design, not an omission. A claude
member's cost is the shared 5h/7d subscription reserve — a fleet-level reading, shown on
the `policy` line — so there is no per-member number to print. Before this, `agents` was
hardcoded empty, so an armed fleet read `0 agent(s) running (roster: a)` however many
members were live, and a working metered member appeared against an empty Anthropic
reserve gauge and looked broken. Two consequences of the fix are worth knowing:

- A metered member that has billed nothing shows `$0.00 … (0 steps)` — the metered
  posture at zero, naming the pool it spends from. A claude member shows **no** spend
  field. `$0.00` and absent are different readings and are not collapsed, on the wire or
  on screen.
- `agents` now lists **idle** members too, so a client counting running agents must
  filter on the row's `running` flag rather than counting rows.

A third list, **`held`**, names the `queued` items an armed fleet is leaving for the
human (task 068): each one whose item doc carries a `> Fleet:` line with any value but
`yes`, with the skip reason the journal gave. A held item is not blocked, so it pages no
one, and this list is where it shows. Removing the line frees the item; a hold is
trusted for 60 seconds, then the next member to reach the item reads its doc again.

```
held:
  default/hover-view-sticky        human-only (> Fleet: no)
```

Below the lists come the **`[schedule]`** block (growlight-schedule spec §3.8) and the
live **build caps**. The schedule block is the drive loop's last verdict: whether a
window is open, the next open or close edge in local time, each member the schedule
holds and why, the items waiting on their `> Not before:`, and every claude-login
slot's weekly reserve and budget projection. It reads `schedule (none)` while no
`[schedule] enabled = true` is loaded; a disarmed fleet isn't the cause, because with no
growlightd running `status` has nothing to answer it.

```
schedule      closed (zone America/New_York)
  next edge     2026-10-31 23:00 -04:00
  held          a                outside window
  held          b                overrun
  waiting       default/084 at 2026-11-01 02:00 -04:00
  reserve       slot1            keep 20% · 7d used unknown · clear
  projection    slot1            5h           resets first, resets in 2h
  projection    slot1            7d           cap in 1d–3d, resets in 4d
  projection    slot1            reserve 80%  cap in 18h at the earliest, or resets first, resets in 4d
build caps    (live default — the next spawn's throttle)
  cargo_build_jobs  2
  …
  test_threads      2
```

- **`overrun`** replaces a member's window reason once it has kept running more than
  `close_grace_minutes` past its window's close. It raises one `ScheduleOverrun` alert
  (GUI and log, not the phone). It is information only: the member still finishes its
  iteration, and nothing is killed. A member spawned while its window was already closed
  (a due timed item) is never flagged.
- **A reserve reads `unknown`** when no reading can vouch for the slot's 7d percentage.
  A headless capture records no percentage, so this is the usual state until an
  interactive statusline writes one. An unknown reserve does not hold.
- **`projection`** rows (spec §3.11) say when each claude-login slot's 5h and 7d windows
  are projected to reach 100%, and, for a slot that keeps a reserve, when its 7d window
  reaches the reserve threshold. Each row is a range, never a point. The fastest and
  slowest burn over a few recent look-back spans give its two ends. `at the earliest,
  or resets first` means only the fastest burn reaches the cap before the window
  resets, and `resets first` means none does. The samples are the same per-slot
  readings the reserve reads. They are kept in memory only, so a restarted growlightd
  reads `unknown` until two fresh measured readings land in the current window. A
  window reset or an expired reading (`resets_at` passed) also makes the row `unknown`.
  The projection is information only and holds nothing. opencode (metered) members get
  no row.

### Spend accounting is session-scoped, and it is not a cap

- **In memory only.** The counters live in the backend's cells and are lost on a
  growlightd restart. Deliberate: there is no per-event spend log on this device (eMMC
  wear). A durable rollup, if ever wanted, belongs in `snapshots/growlight/`.
- **A step is counted when it starts**, since the final one never reports finishing. A
  member's subagent steps are not in its stream, so they are not counted, though their
  cost and tokens are in the settled totals.
- **Nothing enforces a limit on it.** The spend *cap* and its enforcement, the metered
  429 `retry-after` hold, and per-provider pool separation are all **spec-agents §7
  phase 4**. What exists today is the accounting phase 4 will arrive to rather than have
  to backfill. A reader finding no cap has found a stub, not an oversight.

## What is shared regardless of backend

An opencode member is supervised exactly like a claude one — same transient
`systemd-run --user --scope` per spawn, same gentle build caps, same scope and
kill-handle registries. So `growlight force-stop --hard-kill`, `request_restart`, the
`set_resources` throttle and the boot reconciler all address it the same way. The only
backend-specific parts are argv, the pre-approval it generates, and the wire format it
parses.

The build caps come from `[build_caps]` in `config/growlight.toml`. `test_threads`
(default `2`) sets `RUST_TEST_THREADS` on every scope beside `CARGO_BUILD_JOBS`, so a
member's `cargo test` runs at most that many tests at once per test binary. It
supersedes the `softfig-growlightd.service.d/50-test-threads.conf` drop-in, which the
growlight-schedule deploy runbook removes. A `0` disables the fleet at load, because
libtest refuses it.

Three differences worth knowing when reading logs:

- An opencode member's **cwd is the garden**, so garden docs are ordinary in-project
  reads; a claude member inherits growlightd's cwd and finds the garden through its
  baton.
- An opencode member's config is handed over in the `OPENCODE_CONFIG` environment
  variable rather than on argv, because opencode has no `--settings` equivalent.
- An opencode member's **crash reason** is not only its stderr. opencode reports a
  failed run (an unavailable model, a provider rejection, an interrupted session) as an
  `error` event on stdout, exits 1, and writes nothing to stderr. growlightd appends those
  events to the member's stderr tail as `opencode error [<type>]: <message>`, so the
  `AgentCrashed` alert carries them. A network error reported this way also counts toward
  the transient-network classification, the same as one on stderr.

## When a member stops progressing: the spin guard

A member that exits cleanly on a continue status is re-rolled. The spin guard stops one
that keeps re-rolling without getting anywhere, before it burns the shared budget. Two
things count as progress:

- a changed `# NEXT ACTION` in the member's baton;
- the item's repo moving, meaning a new `HEAD` or a changed dirty tree (task 069). A
  session can do real work and still exit without a handoff, and before this, one such
  session was enough to park the item.

The repo is taken from the item doc's `> Worktree:` line, else from the queue registry's
`repo` column, else there is none. A value this device can't probe gives no repo signal:
a remote `host:/path`, a relative path, or a doc keeperd couldn't serve. The guard then
decides on NEXT ACTION alone, as it did before. A default-queue item only gets the repo
signal once its doc carries `> Worktree:`, since the default queue has no registry row.
The repo is read once per session exit, with `git --no-optional-locks`, never once per
tick.

Under `queue = "v2"` the guard reads the repo the member's claim resolved, the same one
the dirty-tree guard below reads (queue-v2-parity row 7). A remote or ambiguous repo gives
no repo signal, the same as an unprobeable legacy repo.

The repo excuses at most three repeats of one NEXT ACTION, and only a repo state not
already seen during that NEXT ACTION's run. A tree that churns forever, or flips between
two states, still trips. On a trip (two exits on the same NEXT ACTION with nothing to
excuse them) the member is released and its item parked `blocked`, the same as for a
member-written `STUCK`. The page names the guard instead of asking for a decision:

```
`069` stuck (spin guard): 2 sessions ended with no new handoff — repo dirty: 3 files
```

The tail reads `repo clean` or `repo unknown` when that is the case. A member-declared
`BLOCKED_ON_HUMAN` still pages as `` `X` is blocked on a human decision ``. Both kinds
use the same reminder ladder (30 min → 2 h → 8 h → daily) under separate identities, and
both are forgotten once the item leaves the parked set. The spin record is kept in
memory only, so after a growlightd restart a spin park that is still standing pages as a
human block.

## Before a member boots: the dirty-tree guard

Report 001's failure was a member cut off mid-slice by a network drop. It left
uncommitted edits, no baton rewrite and no commit, and the next session booted onto a
baton that knew nothing about them (task 064). So before each member spawns, growlightd
checks the item's repo, resolved exactly as the spin guard resolves it, against the
member's baton:

- a **re-roll** boots onto its carried baton, so dirt newer than the baton's last write
  is surfaced (checked in the supervisor's pre-spawn hook, so it lands before the member
  boots);
- a **fresh start** that keeps the member's own baton for the item compares the same way;
- a fresh start that seeds a **new** baton has no handoff to compare against, so any dirt
  is surfaced.

A hit is one journal line and a `# ⚠️ PRE-EXISTING DIRTY TREE` section in the member's
baton, replaced in place if it fires again:

```
growlightd: boot dirty tree: psy/booking (a): /home/u/psy has 3 uncommitted path(s), newest ~840s newer than the baton handoff
```

The guard is read-only: it never reverts, stages or commits, and ignored paths such as
`target/` don't count. Semi-auto gets the same line from `softfig growlight start` and,
on every boot and `/clear`, from the `softfig growlight boot-check` call in the generated
`inject.sh`. Protocol step 1b tells the member what to do with it.

Under `queue = "v2"` the guard runs on the same two spawns (queue-v2-parity row 6). The
repo is the entry's project `repo` from `queue.toml`, resolved once when the member claims
the entry and only when the project is local: `~`, `~/…` and `~<you>/…` expand against
your home, and a remote or ambiguous repo gets no guard. The v2 start rewrites the member
baton from the entry baton, so a fresh start compares against the entry baton's last
write, which is its last handoff. An entry with no baton yet is seeded, so any dirt is
surfaced. A re-roll compares against the member's carried baton, as under legacy. The
line names the entry rather than `<queue>/<part>`:

```
growlightd: boot dirty tree: queue-v2-parity (a): /home/u/repo has 11 uncommitted path(s), newest ~533s newer than the baton handoff
```

## Queue v2: the stack's git probes are bounded

Only under `queue = "v2"`. The §8 stack model reads git (`git_stack.rs`) to record a first
claim's `parent`/`base`, to spot a stale stack and to decide when a restack's bases can be
re-recorded. `git_probe.rs` keeps that from stalling the drive loop: one worker-thread probe
per repo under one overall deadline, memoised for the tick so a claim, the handshake and a
second entry's first claim share the answers, and a repo whose probe misses its deadline is
held with a doubling backoff across ticks. A probe that cannot answer is "unknown", never
"stack is fine": a first claim fails closed (no spawn, retried after the backoff) and
detection skips the repo until it answers.

`queue show` and `growlight status` read the stack the same way, on a probe cache of their
own, so a human reading the list never holds a repo for the scheduler. A repo that can't
answer shows "stack unknown" with the reason, and its started branches show the same, never
an empty stack or a merged branch.

Under v2 a hold lives only in the entry's `fleet` / `not_before` fields. Both surfaces and the
TUI print them beside the status as `(human-only)` and `(not before …)`. An item doc's
`> Fleet:` or `> Not before:` line holds nothing, so `queue show` prints one `warning:` line
per entry whose doc line disagrees with the entry, along with the `queue fleet` / `queue
not-before` command that would make the entry match. For the same reason, keeperd's member
guard stops protecting the `> Fleet:` line once `config/growlight.toml` says `queue = "v2"`.
Under legacy, or with a switch it can't read, the guard stays on. A member may not write
`config/growlight.toml`.

`not_before` gates only a `queued` entry's claim: a `paused` or orphaned `active` entry is
past its claim, so a start time set on one holds nothing. `queue not-before` keeps it all
the same (it applies if the entry is queued again) and says so with a `note:` line after
the list. The reply's `notes` field carries the sentence, and the MCP summary prints it too.

A branch a first claim resumed (the baton's `resume <branch>` case) is written
`auto_restack = false` on its row. The loop never judges it stale, never enqueues a restack
over it and never re-records its base, because it is usually work the human already stacked
other entries on. It still anchors its children's `--onto`. A fleet-cut branch keeps the
default `true`. Only the human turns it back on, with `queue_update_entry auto_restack` or
`softfig growlight queue auto-restack <id> yes|no [--dry-run]`. A restack row takes none.
`queue show`, `growlight status` and the TUI do not mark a held-out entry yet; it shows in
`queue.toml` as `auto_restack = false`.

One bad byte in a v2 file stops all scheduling. A `queue.toml`, `queue-archive.toml` or
`slices.toml` that won't read or parse fails the snapshot closed (spec §3), where legacy
held only the one item whose doc it couldn't read. The journal gets one line per incident,
naming the file, the line and column, and the parser's reason, and the first tick after
the fix resumes:

```
growlightd: v2 queue source failed (scheduling nothing from v2 until it is fixed): growlight/backlog/queue.toml: invalid TOML at line 9, column 9: invalid type: string "no", expected a boolean
```

## Known gaps

The `growlight` **GUI**'s fleet panel does not yet show backend or spend — its per-agent
row carries id/status/ctx only. `growlight status` and the TUI do. Surfacing it there is
its own change. Neither the GUI nor the TUI lists `held` items yet; only `growlight
status` does.

A headless opencode member cannot write to a **code repo**. The permission floor reaches
only the loop's own state, so an ungranted repo yields a refusal a headless session cannot
answer. growlightd resolves an item's repo only to see whether it moved (the spin guard
above), and nothing grants a member write access to that repo. Until the folder grants
land (step 2 of `decision-opencode-v2-fleet-safety-order`, appended after rule 8), an
opencode member is limited to garden work through the softfig-mcp verbs.
