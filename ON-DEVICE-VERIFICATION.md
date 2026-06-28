# On-device verification checklist

Consolidated from the scattered `## Deferred verification` sections after the full-auto growlight
run (25 iterations, ended `QUEUE_EMPTY` by design). Everything below shipped **code-complete +
CI-green**; what's left is on-device smoke the loop couldn't safely run itself, plus a branch merge.

This file is a scratch working doc (untracked, in the code repo). Delete it once everything ticks.
When an item passes, tell me the result and I'll record it via the MCP verb noted (`set_item_status` /
`reorder_backlog_item`) — those are garden writes, not shell commands.

---

## ⚠️ The one rule that orders everything

After incident `20260622-daemon-cycle-stop-strands-locked`, **do not `softfig daemon cycle`** to
deploy. `cycle` is the very thing task 014 repairs; running the *old* `cycle` can strand keeperd
`Locked` and need a cold passphrase to recover.

**Deploy the safe way:** `softfig daemon stop` + a cold `softfig unlock`. Only *after* the fixed
binary is live do you test `cycle` (that's 014's own check). Tasks 011/012/013/014 are all gated
behind this single safe deploy, so do them in one sitting.

---

## ▶ RESUME STATE (Part A COMPLETE, 2026-06-23)
- On branch **`main`** @ `29b7007` (Part A code). Feature branch untouched.
- A0 ✓ build clean + 4 bins installed (Jun 22 23:58). A1 ✓ safe deploy.
- **Part A DONE.** A2 ✓ real `cycle` (74007→**80488**, same tip `f926c52d…`, no passphrase). A3 ✓ busy-mount `add_note` committed (`0070ff83`) under a concurrent FUSE read-hammer, no wedge. A4 ✓ first MCP write after the cycle bounce returned clean (reconnect, no `-32000`). A5 ✓ `reorder_backlog_item` idempotent + status-preserving (m5b→#1, re-run same commit). **011/012/013/014 all marked `done`; m5b-hardening re-queued at #1.**
- relock note: `allow_relock=true` lives in the in-garden bootstrap pointer `<garden>/.softfig/keeper.toml` (under the mount); the `…/d1e4f2f5/.softfig/keeper.toml` self-pointer carries only `state_root` by design — NOT a clobbered opt-in. Cycle proves relock intact.
- **NEXT: Part B** (review + merge `feat/growlight-orchestrator`), then **Part C** (milestone smoke — needs `softfig-growlightd` built + a real `claude -p`).

## Part A — Build, deploy, and the four `main` tasks (one pass)

The four reliability fixes (011/012/013/014) are committed on `main` but not in the live daemon
(currently the 011-era build). One safe deploy brings them all live.

### A0 · Build + install
```bash
cd ~/projects/software-config_garden
cargo build --release
# NOTE: the existing one-liner omits softfig-growlightd (new on the feature branch).
# For just the main-branch tasks below, the standard four are enough:
install -m0755 target/release/{softfig,softfig-keeperd,softfig-mcp,softfig-tui} ~/.local/bin/
```
- [x] `cargo build --release` clean (2m04s, no warnings, on `main` @ 29b7007)
- [x] binaries installed to `~/.local/bin` (Jun 22 23:58; old keeperd pid 69272)

### A1 · Safe deploy (the gate)
```bash
pgrep softfig-keeperd          # record the OLD pid
softfig daemon stop            # now tolerates close-without-ack (014); won't spuriously error
softfig unlock                 # cold unlock (passphrase) — NOT `daemon cycle`
softfig daemon status          # expect: state unlocked, FUSE mounted, same tip as before
```
- [x] keeperd pid changed (69272 → **74007**), daemon back `unlocked` at the **same tip** (`f926c52d…`), mount healthy (`fuse.softfig` in /proc/mounts) ✓ 2026-06-23

### A2 · Task 014 — `daemon cycle` survives a lost stop-ack
With the **fixed** keeperd now live + unlocked:
```bash
softfig daemon cycle
```
- **Expect:** `cycle: relock token armed …` → `stopping daemon…` → `daemon restarted; redeeming…`
  → `cycle: daemon resumed (unlocked)`. **No passphrase prompt.** `softfig daemon status` shows
  `state unlocked` at the **same tip**, FUSE remounted. (criteria 3 + 5)
- *(optional, criterion 2)* abort-recovery: `softfig daemon relock-arm`, restart keeperd by hand,
  `softfig daemon relock` → resumes unlocked (an aborted `cycle` is now recoverable the same way,
  no cold passphrase).
- [x] real `cycle` resumes unlocked, same tip, no passphrase → **`014` done** ✓ 2026-06-23 (74007→80488, tip `f926c52d…`, no prompt)

### A3 · Task 011 — `validate_repo_path` off the mount
On the new keeperd, issue an MCP write verb while the mount is **busy** (e.g. an `add_note` under a
concurrent read of the mount).
- **Expect:** the verb validates + commits without wedging — no hang, no SIGKILL. (deploy
  confirmation; correctness already covered by tests)
- [x] busy-mount `add_note` commits cleanly → **`011` done** ✓ 2026-06-23 (`0070ff83` under a 30s FUSE read-hammer, no wedge/SIGKILL)

### A4 · Task 012 — MCP reconnect across a keeperd restart
Requires (a) the new `softfig-mcp` live = a Claude Code / loop restart, and (b) a keeperd bounce —
the `cycle` from A2 is the natural trigger.
```bash
pgrep softfig-keeperd          # note pid
softfig daemon cycle           # from OUTSIDE the mount
# during/just-after the bounce, fire a cheap MCP verb (e.g. log_baton)
```
- **Expect:** the verb returns **OK via reconnect** (rides out the ~3s window). If keeperd stays
  down past the budget, a clear `keeperd unreachable at <socket>…`. **A bare `-32000 Connection
  closed` is a regression.**
- [x] verb survives the cycle via reconnect → **`012` done** ✓ 2026-06-23 (first MCP write after the 80488 bounce returned clean, no `-32000`)

### A5 · Task 013 — `reorder_backlog_item` verb
Live only on the new daemon (old one returns unknown-op).
1. **Live verb:** reorder a queued task to `top` → its row becomes `#1`, all status cells
   unchanged, exactly one `backlog_item_reordered` commit. Re-run the same move → no new commit
   (idempotent). Try `before`/`after` with a `ref_id`; confirm the `#` column re-renders.
2. **Criterion 7 — reprioritize for real:** stop abusing `deferred` as a deprioritizer. Set
   `m5b-hardening` back to `queued`, then `reorder_backlog_item` it and the four 2026-06-22
   reliability fixes (009–012) into their intended priority order.
- [x] live reorder behaves (idempotent, status-preserving) → **`013` done** ✓ 2026-06-23 (m5b→`top`=#1, all status cells intact, re-run = same commit `35c3891…`)
- [~] m5b-hardening reprioritized via the verb (criterion 7): set `deferred`→`queued` + moved to `#1`. 009–012 are now all `done`, so reprioritizing them is moot. **Open: confirm the exact intended queue order — m5b at `#1` (above the done items) is a default, easily moved (e.g. `before growlight-orchestrator-daemon`).**

---

## Part B — Review + merge `feat/growlight-orchestrator`

7 commits ahead of `main`, theory-code, **never on main** by design. The branch is yours to review
+ merge. Two whole milestones (orchestrator-daemon phase 1, coordination-bus phase 2).

```
7f9a817 coordination-bus slice 003 — bus over subscribe + alert + human-post
a996ff8 coordination-bus slice 002 — post_message + read_inbox verbs
7d21242 coordination-bus slice 001 — message store + per-agent lanes
68c8521 orchestrator slice 004 — CLI clients (status/watch/stop/pause)
f6b26ab orchestrator slice 003 — control verbs (pause/resume, stop-levels, inject)
ddbb796 orchestrator slice 002 — subscribe / event hub
e8be7f4 orchestrator slice 001 — control-plane daemon skeleton + IPC
```
- [x] review the diff — reviewed together, looked good ✓ 2026-06-23
- [x] merge to `main` — fast-forward `29b7007..7f9a817` (linear history preserved) ✓ 2026-06-23
- [x] **at merge:** add `softfig-growlightd` to the install one-liner in `README.md` (+ onboard script) → commit `a02a156` ✓
- [x] **at merge:** amend `meta/spec-vcs.md`'s intent list with `chat_message_posted`, `inbox_read` → garden commit `5db9c77` (payloads verified vs merged code) ✓
- [x] **post-merge smoke:** `cargo build --release` clean (2m24s, no warnings); `cargo test --release` all green — `softfig-growlightd` lib 24, bus/control/socket/subscribe integration all pass, keeperd `growlight.rs` 32, zero failures workspace-wide ✓ 2026-06-23
- [x] **backlog:** orchestrator phases 3–7 re-queued (garden-cas next), `m5b-hardening` → bottom; phase-1/2 milestones left `deferred` pending Part C ✓ 2026-06-23
- [ ] **NEXT (on-device):** install the 5 freshly-built bins via the **safe deploy** (`daemon stop` + cold `unlock`, not `cycle`), then run Part C below

---

## Part C — Milestone smoke (needs live keeperd + a real `claude -p`)

Run after the branch is merged + `softfig-growlightd` installed.

### C1 · growlight-orchestrator-daemon (phase 1) — keystone: a client never kills the work
- **Boot:** run real `softfig-growlightd` against live keeperd — it derives the garden root from the
  keeperd `status` handshake (never a literal path) and binds its own `softfig-growlightd.sock`.
- **Observe:** `softfig growlight status` shows the running fleet + policy + gate; `softfig growlight
  watch` renders a real `claude -p` agent's stream-json deltas (assistant / tool-call / thinking).
- **Control:** `softfig growlight pause` → `status` shows `paused:true`; `resume` clears it.
  `softfig growlight stop --agent <id> --level after-slice|after-iteration` records a boundary
  intent honoured at the next handoff; `--level hard-kill` interrupts a real child via the
  kill-safety path; an inject is delivered at the agent's next baton.
- **Keystone (spec §2):** closing a `watch`/client never kills the fleet — the daemon survives
  client disconnects and keeps running.
- [x] boot · observe · control all behave; client-disconnect doesn't kill work → **milestone `done`** ✓ 2026-06-23 (growlightd pid via live keeperd 23496; pause/resume reflected; keystone — killed `watch`, daemon stayed alive. The real-`claude -p`-deltas + agent-targeted stop/inject are N/A until the phase-6 fleet exists.)

### C2 · growlight-coordination-bus (phase 2)
1. **Live fan-out:** unlock garden, run keeperd + growlightd, `softfig growlight watch` in one
   terminal; in another, MCP `post_message` (or a loop agent posts at handoff). Expect it to render
   live as `bus <from>→<to> [<kind>] <body>` within ~250ms (tailer poll interval).
2. **Human post → live + inbox:** `softfig growlight say --to @all "standup in 5"` → prints
   `posted msg N → @all [info]`, shows live in `watch` as `bus human→all [info] standup in 5`, and
   lands in a fresh agent's `read_inbox` at next boot.
3. **Alert rides the bus:** `softfig growlight say --kind alert --to @human "disk full"` →
   `watch` renders `bus human→human [alert] disk full`.
4. **No churn:** `tail_bus` polling mints no commits — `softfig log` tip unchanged while only
   tailing; only `post_message`/`read_inbox` commit.
- [x] fan-out · say · alert · no-churn all behave → **milestone `done`** ✓ 2026-06-23 (`say @all`→`bus human→all [info] standup in 5` live; alert→`bus human→human [alert] disk full`; tip +2 on the two `say`s then unchanged while only tailing. read_inbox-at-boot store-populated on disk + test-covered; full drain at next loop agent boot.)

---

## Not in scope (parked by design)
`004` config-in-garden dogfood · `005` .softfigignore · `m5b-hardening` · orchestrator phases 3–7.
These stay `deferred`/`queued` until you choose to pull them.
