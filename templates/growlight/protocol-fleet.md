SOFT-FIG GROWLIGHT — operating protocol

Your carried state is the single baton injected above. Everything else lives in
the garden (read via softfig-mcp pointers) and the code repos (git). This
protocol is fixed; the baton changes each iteration.

1. BOOT. Read the baton. Load ONLY the files/sections under READ FIRST — never
   slurp the garden or whole crates. Confirm status is IN_PROGRESS and NEXT
   ACTION is still valid. If BLOCKED_ON_HUMAN and unanswered: surface it (semi)
   or take the documented default and flag it (auto).

2. CONTEXT BUDGET. Work band 25-50% of window. At ~50% used: finish the current
   atomic step, then hand off. At ~60%: hand off NOW, recording a precise resume
   point in NEXT ACTION. NEVER /compact — a curated baton beats a lossy summary.

2b. SESSION BUDGET. Read usage.json at boot. Before starting any new step, if 5h
   used >= 85% (or 7d >= 90%): do not start it — write the baton, set status
   HALTED_RATE_LIMIT with the reset time, stop. Plan each chunk to fit the
   remaining 5h window; don't leave a started window idle.

3. WORK. Execute NEXT ACTION as one coherent chunk. Obey all standing feedback
   (garden edits only via softfig-mcp; commit code on main after each unit;
   root-cause fixes, no patchwork; refresh garden+project docs when a milestone
   verifies). When a milestone verifies, also keep your own claude-memory
   pointers under `~/.claude/projects/<garden>/memory/` in sync — you may
   Edit/Write those directly now (only that subtree is writable; credentials and
   harness settings elsewhere in `~/.claude` stay off-limits). Never relitigate
   LOCKED DECISIONS.

3b. DAEMON RESTART (relock). If a step needs the keeperd daemon cycled (e.g. you
   rebuilt softfig-keeperd), run `softfig daemon cycle` as ONE step: it bounces
   the daemon and resumes the unlocked session without the passphrase, holding
   the one-time token in its own RAM (never logged, never in the baton). If it
   reports relock is disabled (or returns RelockDisabled): do NOT work around it
   — `[growlight] allow_relock` is the human's to set. Write the baton, set
   status BLOCKED_ON_HUMAN ("needs daemon restart; relock disabled"), stop. Never
   attempt a cold unlock (you don't have the passphrase).

4. HUMAN CHECKPOINTS. For choices that are genuinely the user's (direction,
   scope, irreversible/outward-facing, ambiguous requirements): append to FOR
   THE HUMAN with a proposed default. Semi: proceed on the default but flag it;
   pause only if risky. Auto: take the safest default, flag loudly in the log.
   When answered, fold into LOCKED DECISIONS and drop the question. A manual
   SMOKETEST you physically can't run (a second device, a live TTY, multicast,
   hardware) is NOT a checkpoint and NOT a blocker — never BLOCKED_ON_HUMAN it;
   defer it via step 7b.

5. HANDOFF. (a) Rewrite the baton: collapse finished work to one-liners +
   pointers; make NEXT ACTION runnable; update FINISH CRITERIA; bump
   updated/status/ctx_pct/session_5h_pct. (b) log_baton one entry. (c) Persist
   durable outcomes: garden via softfig-mcp, code via git commit on main. Then
   semi -> tell the user "handoff ready - /clear"; auto -> exit for the orchestrator.

6. STUCK. If NEXT ACTION is materially unchanged across 2+ iterations with no
   progress: set status STUCK, write what's blocking, stop. Do not spin.

7. QUEUE / DONE (fleet member). When FINISH CRITERIA are met AND verified: run
   set_item_status done, write a SHORT terminal baton (status ITEM_COMPLETE +
   one line on what you finished), log_baton, then EXIT. Do NOT pull or reseed
   the next item — the orchestrator owns the queue: it claims and seeds your next
   part through its own handshake (a fleet member NEVER self-pulls; self-pull
   would race the orchestrator's claim and double-assign the part). If no
   workable part remains, the orchestrator releases you to idle. A milestone is
   done only when all slices are done AND integration verified.

7b. DEFERRED VERIFICATION. If the ONLY unmet criteria are manual smoketests you
   physically can't run, do NOT block. Finish and verify everything you can, then
   record each pending test in the item doc under a `## Deferred verification`
   section (what to run, expected result) AND in FOR THE HUMAN; run
   set_item_status <id> deferred; log_baton with status ITEM_DEFERRED; then EXIT.
   Do NOT pull or reseed — the orchestrator claims and seeds your next part. A
   `deferred` item waits for the human and never re-enters the loop. Reserve
   `blocked`/BLOCKED_ON_HUMAN strictly for when YOU can't proceed without a human
   decision or config change (steps 4, 3b).
