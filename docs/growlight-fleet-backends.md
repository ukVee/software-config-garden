# growlight fleet backends — putting a member on opencode

> Applies to `config/growlight.toml` in the garden, read by growlightd at arm time.
> Added by the `opencode-fleet-backend` milestone (spec-agents phase 2), slice 005.

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
model   = "deepseek/deepseek-v4-flash"   # opencode only; omit to let opencode choose
variant = "high"                         # opencode only; optional
```

`backend` defaults to `claude`, so a config written before this existed keeps running
exactly as it did — there is no migration.

`model` / `variant` ride the **generated opencode config**, not argv. growlightd writes
each opencode member's `opencode.json` fresh on every spawn, so the model a member runs
on and the permission map that member was granted are written by one act and cannot
drift apart.

## What is refused

Three config mistakes are reported and refused at arm time rather than defaulted. All
three are the same hazard — **a member running on a pool the operator did not choose** —
and a fleet that silently ran claude while its operator believed it was on DeepSeek would
burn the Anthropic subscription without anyone noticing:

| Written | Result |
|---|---|
| `backend = "opencde"` (any unknown value) | refused, naming the member and the valid backends |
| `model = "…"` with no `backend = "opencode"` | refused — those keys are opencode-only |
| `backends = "opencode"` (any unknown key) | refused — a dropped typo would silently mean claude |

A refusal fails **closed**: growlightd logs the message and the fleet stays disarmed. A
config problem can never arm a fleet, let alone arm one onto the wrong provider.

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

Per-member USD spend on a metered provider is accumulated (`step_finish.cost`) and
surfaced by slice 006.

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

## Known gap

A headless opencode member cannot write to a **code repo**. Its cwd is the garden, and
opencode's `external_directory` governs every path outside cwd, so an ungranted repo
yields a permission refusal a headless session cannot answer. growlightd does not model
repos at all today (the queue→repo binding is dropped when the registry is parsed), so
there is nothing to grant from. Until that is closed, an opencode member is limited to
garden work.
