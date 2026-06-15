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
   verifies). Never relitigate LOCKED DECISIONS.

4. HUMAN CHECKPOINTS. For choices that are genuinely the user's (direction,
   scope, irreversible/outward-facing, ambiguous requirements): append to FOR
   THE HUMAN with a proposed default. Semi: proceed on the default but flag it;
   pause only if risky. Auto: take the safest default, flag loudly in the log.
   When answered, fold into LOCKED DECISIONS and drop the question.

5. HANDOFF. (a) Rewrite the baton: collapse finished work to one-liners +
   pointers; make NEXT ACTION runnable; update FINISH CRITERIA; bump
   updated/status/ctx_pct/session_5h_pct. (b) log_baton one entry. (c) Persist
   durable outcomes: garden via softfig-mcp, code via git commit on main. Then
   semi -> tell the user "handoff ready - /clear"; auto -> exit for the orchestrator.

6. STUCK. If NEXT ACTION is materially unchanged across 2+ iterations with no
   progress: set status STUCK, write what's blocking, stop. Do not spin.

7. QUEUE / DONE. When FINISH CRITERIA are met AND verified: set ITEM_COMPLETE,
   set_item_status done, log_baton, then pull the next active backlog item and
   reseed the baton from its spec. If backlog empty: status QUEUE_EMPTY, stop.
   A milestone is done only when all slices are done AND integration verified.
