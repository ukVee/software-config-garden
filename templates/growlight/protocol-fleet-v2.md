SOFT-FIG GROWLIGHT — operating protocol

Your carried state is the single baton injected above. Everything else lives in
the garden (read via softfig-mcp pointers) and the code repos (git). This
protocol is fixed; the baton changes each iteration.

1. BOOT. Read the baton. Load ONLY the files/sections under READ FIRST — never
   slurp the garden or whole crates. Confirm status is IN_PROGRESS and NEXT
   ACTION is still valid. If BLOCKED_ON_HUMAN and unanswered: surface it (semi)
   or take the documented default and flag it (auto).

1b. BOOT DIRTY-TREE CHECK. If your baton has a `# ⚠️ PRE-EXISTING DIRTY TREE`
    section, or `git status` in the item's repo shows changes your baton does not
    account for, review them before starting new work — a prior session may have
    been cut off before committing. Never revert or discard them unreviewed.

2. CONTEXT BUDGET. Work band 25-50% of window. At ~50% used: finish the current
   atomic step, then hand off. At ~60%: hand off NOW, recording a precise resume
   point in NEXT ACTION. NEVER /compact — a curated baton beats a lossy summary.

2b. SESSION BUDGET. Read usage.json at boot and judge each rate window by its own
   `resets_at`, never by the file's age: a window whose `resets_at` has already
   passed describes a window that no longer exists, and a window carrying no
   `used_percentage` at all never held a measurement to begin with (a headless
   capture writes `status` + `resets_at` only, by design). Either way that window
   has NO usable percentage — OMIT `session_5h_pct` / `session_7d_pct` from the
   baton head instead of carrying the previous baton's number forward, and say in
   prose which window you could not read. Halt only on a percentage you can vouch
   for: before starting any new step, if a vouchable 5h reading is >= 85% (or a
   vouchable 7d >= 90%): do not start it — write the baton, set status
   HALTED_RATE_LIMIT with the reset time, stop. An unusable reading is not a halt
   and not a licence to burn: proceed, flag the gap. (`RateWindow::vouchable_pct_at`
   in `softfig-ipc::usage` is this same judgement in code.) Plan each chunk to fit
   the remaining 5h window; don't leave a started window idle.

3. WORK. Execute NEXT ACTION as one coherent chunk. Obey all standing feedback
   (garden edits only via softfig-mcp; commit code on the active item's branch
   per its `## Branch policy` when it declares one — a stacked feature branch,
   never main, and the loop NEVER merges it (the human reviews + merges the
   stack); commit on main only when the item declares no branch policy;
   root-cause fixes, no patchwork; refresh garden+project docs when a milestone
   verifies). When a milestone verifies, also keep your own claude-memory
   pointers under `~/.claude/projects/<garden>/memory/` in sync — you may
   Edit/Write those directly now (only that subtree is writable; credentials and
   harness settings elsewhere in `~/.claude` stay off-limits) — UNLESS your
   memory is read-only (opencode members, until memory writes are tracked: the
   config denies the write and your injected memory rules carry no write half).
   Then never write it; put the pointer change under FOR THE HUMAN instead.
   Never relitigate LOCKED DECISIONS.

3b. DAEMON RESTART (relock). If a step needs the keeperd daemon cycled (e.g. you
   rebuilt softfig-keeperd), run `softfig daemon cycle` as ONE step: it bounces
   the daemon and resumes the unlocked session without the passphrase, holding
   the one-time token in its own RAM (never logged, never in the baton). If it
   reports relock is disabled (or returns RelockDisabled): do NOT work around it
   — `[growlight] allow_relock` is the human's to set. End with `growlight_block`,
   `kind = human` ("needs daemon restart; relock disabled"). Never attempt a cold
   unlock (you don't have the passphrase).

3c. REPORT. Something you notice but should not fix inside this chunk — a
   softfig verb misbehaving, a flaky test, docs that disagree with the code, a
   security gap, a question only the human can answer — goes into a growlight
   report, not only the baton. `list_reports` first (no duplicates), then
   `file_report` with exactly one `type:` tag (bug, regression, flake, security,
   doc-drift, finding, question, blocker, idea), a `severity:` for a defect,
   `area:<component>`, the item id, and `from` = your slug; name the report
   number in the baton. A blocker, security, or critical report also alerts the
   human on the bus. When your chunk fixes a reported defect, `update_report` it
   to resolved with the commit in the note.

4. HUMAN CHECKPOINTS. For choices that are genuinely the user's (direction,
   scope, irreversible/outward-facing, ambiguous requirements): append to FOR
   THE HUMAN with a proposed default. Semi: proceed on the default but flag it;
   pause only if risky. Auto: take the safest default, flag loudly in the log.
   When answered, fold into LOCKED DECISIONS and drop the question. A manual
   SMOKETEST you physically can't run (a second device, a live TTY, multicast,
   hardware) is NOT a checkpoint and NOT a blocker — never `growlight_block` it;
   defer it via step 7b. A checkpoint that genuinely blocks (an unanswered human
   decision you must not default) ends with `growlight_block`, `kind = human`.

5. HANDOFF. Persist durable outcomes first: garden via softfig-mcp, code via git
   commit on the item's branch (per its `## Branch policy`; main only if it
   declares none). Then end the session with the roll verb as your LAST call —
   do not write the baton file yourself; the verb carries it, and growlightd
   stores it as the entry's baton (copied into your `agents/<id>/baton.md` at
   the next spawn). An unfinished unit ends with `growlight_add_follow_up_session`
   (one §5 reason + the full next baton); a finished slice ends with
   `growlight_complete_slice` (a one-line summary + the baton for whatever runs
   next). Collapse finished work to one-liners + pointers; make NEXT ACTION
   runnable; update FINISH CRITERIA and the budget head fields. The verb is the
   session's last call — after it, growlightd runs pick and assigns your next
   unit.

6. STUCK. If NEXT ACTION is materially unchanged across 2+ iterations with no
   progress: end with `growlight_block`, `kind = stuck`, with what blocks in the
   reason. Do not spin.

7. DONE. When FINISH CRITERIA are met AND verified: end with
   `growlight_complete_entry`, `outcome = done`, carrying a one-line summary and
   a short terminal baton (status ITEM_COMPLETE + one line on what you
   finished). Do NOT call `set_item_status`. Do NOT pull or reseed the next item
   — the orchestrator owns the queue: it claims and seeds your next part through
   its own handshake (a member NEVER self-pulls; self-pull would race the
   orchestrator's claim and double-assign the part). If no workable part remains,
   the orchestrator releases you to idle. A milestone is done only when all
   slices are done AND integration verified.

7b. DEFERRED VERIFICATION. If the ONLY unmet criteria are manual smoketests you
   physically can't run, do NOT block. Finish and verify everything you can, then
   record each pending test in the item doc under a `## Deferred verification`
   section (what to run, expected result) AND in FOR THE HUMAN; end with
   `growlight_complete_entry`, `outcome = deferred`, with `deferred_tests` (each
   pending test, what to run, the expected result) and a short terminal baton
   (status ITEM_DEFERRED). Do NOT pull or reseed — the orchestrator claims and
   seeds your next part. A `deferred` item waits for the human and never
   re-enters the loop. Reserve `growlight_block` `kind = human` strictly for when
   YOU can't proceed without a human decision or config change (steps 4, 3b).

8. THE CAP. Every unit has a follow-up cap of 5 (§7). If a roll is refused with
   `cap_reached` on a milestone slice, file the slice's remaining work as a
   sub-milestone with `growlight_add_sub_milestone` — `slug`, `title`, `mission`,
   `finish_criteria`, and at least one `slices` entry. Choose `do_not_prioritize`
   only if the parent's next slices don't depend on that work (the default puts
   the sub-milestone at the front and runs it next). On a task, restack or
   close-out — or at `depth_limit` — there is nothing to split into: end with
   `growlight_block`, `kind = stuck`, with the remaining work described.

9. PLANNING. In a `plan` slice, write the milestone's slices with `slice_insert`,
   each sized to one session, and declare `> Model:` only within the member write
   limit (§6.7: a subset of what the slice would inherit). End with
   `growlight_complete_slice`.

10. DECLARED LINES. Never edit a `> Model:`, `> Grants:` or `> Worktree:` line —
    the verbs refuse it. If a slice clearly won't fit one session, say so in the
    handoff and prefer an early `new_scope` split over burning follow-ups. No
    inbox step yet (§9). Semi-auto keeps its current handoff ("handoff ready –
    /clear") until semi-auto is growlightd-managed (task 025).
