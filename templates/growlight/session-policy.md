# growlight session policy

Editable per-garden budget policy for the growlight loop. The operating contract
in `protocol.md` enforces these numbers; tune them here. (This is a policy
contract, not state commentary, so it carries no `Last reviewed:` stamp.)

## The two budgets

| Budget | Source field (usage.json) | Soft / Hard | Action |
|---|---|---|---|
| Context (per-conversation) | `context_window.used_percentage` | 50% / 60% | ROLL — finish the atomic step, then fresh `/clear` reseed |
| Session (5h rolling) | `rate_limits.five_hour.used_percentage` | reserve at 85% | HALT — finish the step, write the baton, `status: HALTED_RATE_LIMIT` + reset time |
| Weekly (guard) | `rate_limits.seven_day.used_percentage` | 90% | HALT, longer pause |

## The 85% reserve

Stop *starting* new steps once the 5h budget reaches 85%. That headroom is what
lets the in-flight step finish and a clean baton get written — so resume is
always the cheap baton reseed, never a mid-thought cutoff.

## Value-max

The 5h clock starts at the first prompt and resets 5h later, so once a window is
open, don't leave it idle: batch loop work to fill it, and size each chunk to
*fit* the remaining window. If the afternoon input window falls inside the
morning's still-open 5h window, it draws the same budget — plan accordingly.

## Reset-time handling

At boot the loop records the 5h reset time (from `usage.json` if the backend
provides it; the statusline dump captures the whole `rate_limits` object so the
reset time is available) and plans the session to land a clean handoff before
exhaustion.
