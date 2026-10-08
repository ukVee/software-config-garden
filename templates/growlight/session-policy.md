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

A percentage in that column counts only while its own window's `resets_at` is
still in the future, and only when the reading actually carried one — see
*Reset-time handling*. An absent or expired percentage is not a low percentage.

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

Every reading carries each window's own `resets_at`, and that boundary — not the
age of the file — is what says whether the reading still describes the window you
are in. The windows are anchored to account time rather than rolling from the
moment of the read, so a reading taken minutes ago can already be describing a
window that has reset, and a reading from hours ago can still be perfectly good.

At boot the loop therefore records each window's reset time and judges the window
by it. Past its boundary, or carrying no `used_percentage` at all (a headless
capture records `status` + `resets_at` only, by design), the window has **no
usable percentage**: report it as absent — never the previous baton's number, and
never a `0`, which reads as an empty pool and silently disables the governors —
and plan the session to land a clean handoff before exhaustion. `protocol.md` §2b
is the enforcing rule; `RateWindow::vouchable_pct_at` in `softfig-ipc::usage` is
the same judgement in code.
