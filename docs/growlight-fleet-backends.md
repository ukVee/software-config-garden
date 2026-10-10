# growlight fleet backends — putting a member on opencode

> Applies to `config/growlight.toml` in the garden, read by growlightd at arm time.
> Added by the `opencode-fleet-backend` milestone (spec-agents phase 2), slices 005-006.

A growlight fleet member runs on `claude -p` by default. It can instead run on
`opencode run` (over a metered provider such as DeepSeek), chosen **per member**, so
a roster can mix the two.

## The keys

```toml
fleet_enabled = true

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

`model` / `variant` ride **argv** (`--model provider/model[#variant]`), not the generated
config. opencode 2.x `run` ignores `agent.<id>.model` entirely, and argv is the one model
source that fails closed on a bad id (opencode-v2-repin slice 001, L5 + L7), so the config
carries no model key at all. The member's `opencode.json` (still written fresh per spawn,
still holding the permission map) and the argv are built by the same spawn path, so the
model a member runs on and the permission map that member was granted cannot drift apart.

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
| 8 | `edit <runtime>/**`, `<~/.claude/projects>/** allow` | the baton write and memory pointers |

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

Generation fails **closed**: a floor directory that is relative, non-UTF-8, carries a `*`
or `?`, or is `/` refuses the spawn. A relative root would render `edit <rel>/** allow`,
which matches the garden's own resources and opens a hole through the guard.

The **shell is not a boundary.** `shell * allow` runs with full host authority, so these
rules stop well-behaved tool calls, not a determined command line. The OS-level boundary is
the Landlock step of `decision-opencode-v2-fleet-safety-order`.

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
  reports it (accumulated from each `step_finish.cost`), and a claude member contributes
  **nothing** — its cost *is* the 5h/7d reserve above. The spend seam is structurally
  `None` for claude for the same reason `budget()` is structurally `None` for opencode.

Each seam answers `None` for the provider it does not describe, and nothing invents the
other reading. That symmetry is what makes the status surface honest — see below.

## Reading a mixed fleet: `growlight status`

`growlight status` reports two lists, and the difference matters:

- **`roster`** — what `config/growlight.toml` declares. Always present, even while the
  fleet is disarmed.
- **`agents`** — one live row per member of an **armed** fleet. Empty while disarmed:
  nothing is assembled then, so there is no runtime state to report and inventing a
  roster echo here would claim liveness the daemon cannot observe.

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

### Spend accounting is session-scoped, and it is not a cap

- **In memory only.** The counters live in the backend's cells and are lost on a
  growlightd restart. Deliberate: there is no per-event spend log on this device (eMMC
  wear). A durable rollup, if ever wanted, belongs in `snapshots/growlight/`.
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

Two differences worth knowing when reading logs:

- An opencode member's **cwd is the garden**, so garden docs are ordinary in-project
  reads; a claude member inherits growlightd's cwd and finds the garden through its
  baton.
- An opencode member's config is handed over in the `OPENCODE_CONFIG` environment
  variable rather than on argv, because opencode has no `--settings` equivalent.

## Known gaps

The `growlight` **GUI**'s fleet panel does not yet show backend or spend — its per-agent
row carries id/status/ctx only. `growlight status` and the TUI do. Surfacing it there is
its own change.

A headless opencode member cannot write to a **code repo**. The permission floor reaches
only the loop's own state, so an ungranted repo yields a refusal a headless session cannot
answer. growlightd does not model repos at all today (the queue→repo binding is dropped
when the registry is parsed), so there is nothing to grant from. Until the folder grants
land (step 2 of `decision-opencode-v2-fleet-safety-order`, appended after rule 8), an
opencode member is limited to garden work through the softfig-mcp verbs.
