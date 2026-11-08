# [bug] Spin guard parks a member that IS progressing — one non-handoff session trips it, and the page reads "blocked on a human decision"

> Last reviewed: 2026-10-17
> Not before: 2026-11-02 09:00 Z

## Mission

Filed 2026-10-17 from growlight report 011 and the 2026-10-16 psy-booking park. Related: report 001 and task 064 (boot-time dirty-tree guard).

**The bug.** `supervisor.rs` `roll_or_spin` uses the baton's `# NEXT ACTION` as its *only* progress signal, and `STALL_LIMIT = 2` (`supervisor.rs:111`). A member that hands off normally (NEXT ACTION = X) and then has ONE session that works but exits without rewriting its baton is parked on the second exit. Seen twice on 2026-10-16:
- **18:59, `psy-booking`:** iteration 4 handed off at 18:40 with NEXT ACTION "Execute slice 004". The 18:40→18:59 session wrote slice 004 (**+278 lines uncommitted** in `feat/psy-booking`: `book.ts`, `booking.test.ts`, `booking.spec.ts`) and exited without a baton rewrite. Result: "stuck (spin guard)", item parked `blocked`.
- **13:51, `psy-events`** (report 011): an opencode member ended its turn waiting on a background gate, and the guard parked a progressing slice. The observer had to recover the WIP by hand.

**Compounding:** the page for a spin-guard park reads exactly like a member-declared human block: `notifications.rs:235` "`<item>` is blocked on a human decision". The journal tags it `spin_guard`; the bus and phone don't. On 10-16 the owner got a "human decision" alert for psy-booking, where no decision existed.

**Fix (keep the budget protection the guard exists for):**
- (a) Count **repo movement** as progress: an advanced HEAD, or a changed dirty-tree fingerprint (e.g. a hash of `git status --porcelain` + `git diff` stat) in the item's repo, resets the streak just like a changed NEXT ACTION. growlightd doesn't know an item's repo today (the queue `repo` column is documentary), so coordinate with task 064, which needs the same lookup. Build it once and use it twice.
- (b) A spin park gets its **own alert identity and text**, e.g. "`<item>` stuck: N sessions ended without a handoff (repo dirty: k files)". A reader can then tell "the loop jammed" from "the loop needs your decision".
- (c) Optional, your call in the slice: on a park with a dirty, newer tree, allow one recovery re-roll carrying a "your previous session left uncommitted work — review and adopt it" line, before parking.

Branch: off `main` `e7e25ce`, `fix/spin-guard-progress`, own worktree. Note any overlap with `feat/queue-v2-scheduling`'s `drive_loop.rs` in the handoff. Never merge or deploy.

## Finish criteria

1. Supervisor tests:
   - same NEXT ACTION + repo moved (HEAD or dirty fingerprint) → re-roll, no park;
   - same NEXT ACTION + repo unchanged across STALL_LIMIT exits → park, as today;
   - a changed NEXT ACTION still resets.
2. A test reproducing the 10-16 18:59 psy-booking sequence (handoff with X, then one working session with no handoff and a dirty tree) does not park.
3. A spin-guard park emits a distinct alert identity and text, never "blocked on a human decision". A member-declared `BLOCKED_ON_HUMAN` still reads as today. Notification tests cover both.
4. The repo lookup is shared with task 064 (one helper), or 064's slice notes say why not.
5. Existing supervisor and drive-loop tests pass unchanged; workspace gate green; clippy `-D warnings` clean; parked `deferred`.

## Outcome (2026-10-17)

Code-complete on `fix/spin-guard-progress`. Worktree: `codebase/069-spin-guard-progress`. Tip: `cd16f54`.

⚠️ **Branch base differs from the Mission's.** The branch is **stacked on 068** (`fix/fleet-human-only-items` @ `8d884ff`, itself off `main` `e735f40`), not cut off `main` `e7e25ce`. It reuses 068's `ItemDocReader` / `KeeperdItemDocReader` to read the item doc. **Merge 068 first.** If 068 is rejected, rebase this onto `main` and lift the reader across.

Commits:
- `2de72cc` `softfig_ipc::item_repo`: `worktree_field` / `resolve_repo` / `probe` / `RepoState`. This is the one helper shared with 064 (criterion 4); see 064's `## Reuse` section.
- `acdbfb5` supervisor `poll_with_progress` and the repo streak rule. When NEXT ACTION repeats, a repo state not seen in that NEXT ACTION's run resets the streak to 1, at most `REPO_EXCUSE_LIMIT` = 3 times. "Not seen in the run" means an A/B oscillation still trips.
- `d0d6e71` the drive-loop wiring:
  - `RepoProbe` seam and `KeeperdRepoProbe`. Lookup order: `> Worktree:`, then registry `repo`, then none. An unreadable item doc counts as no signal.
  - `registry_repo`.
  - `NotifyEvent::SpinGuardParked`: identity `stuck:{item}`, on BlockedOnHuman's reminder ladder, forgotten by `reconcile_blocked`. The text is `` `X` stuck (spin guard): 2 sessions ended with no new handoff — repo dirty: K files `` (or `repo clean` / `repo unknown`).
- `cd16f54` docs: `docs/growlight-fleet-backends.md` gets a spin-guard section and a corrected Known-gaps note; repo `CLAUDE.md` ipc row.

Fix (c), the recovery re-roll, was **declined**: with (a) in place, a moving dirty tree never parks. The case left over is 064's boot guard, and the (b) text carries the dirty count.

Criteria:
- 1 ✅ supervisor tests.
- 2 ✅ `a_session_that_worked_without_a_handoff_is_not_parked` replays psy-booking 10-16 18:59.
- 3 ✅ two notification tests plus `a_member_declared_block_after_a_spin_park_reads_as_a_human_decision`.
- 4 ✅ one helper.
- 5 ✅ every pre-existing test unchanged. `cargo test --workspace`: 2025 passed, 0 failed. `cargo clippy --workspace --all-targets -D warnings` is clean.

**Known limits:**
- The spin record (`spin_parks`) is in memory, so after a growlightd restart a standing spin park pages as BlockedOnHuman.
- Default-queue (softfig) items get the repo signal only once their doc carries `> Worktree:`, because the default queue has no registry row.
- psy items get it from the registry.

**Overlap:** `feat/queue-v2-scheduling` changes `drive_loop.rs` by +2303 against `f7e5555`. Expect conflicts at the poll call site (`poll_with_exits` → `poll_with_progress`), in the `PollOutcome::Blocked` arm, and in `dispatch`'s parked loop.

## Deferred verification

Both checks need 068 + 069 merged, built, installed and growlightd restarted. The loop never merges or deploys, so they wait for the human.

1. **A working session with no handoff re-rolls on a live fleet.** psy-booking is the natural case. It is still `blocked`, with slice-004 WIP uncommitted on `feat/psy-booking`. Re-queue it, or use any item whose queue has a local registry `repo` or whose doc carries `> Worktree:`. Let a member end a session after editing files but without rewriting its baton.
   - **Expected:** the journal's exit disposition reads `rolling (continue status)`, the item is not parked, and nothing pages.
2. **A real spin park pages as itself.** Let a member exit twice on the same NEXT ACTION with no repo movement. The easiest way is an item with no edits to make.
   - **Expected:** the bus/phone alert reads `` `<item>` stuck (spin guard): 2 sessions ended with no new handoff — repo … ``, with a dirty count, `repo clean` or `repo unknown`. It never reads "blocked on a human decision".
   - **Expected:** the journal's exit disposition reads `stuck (spin guard — no progress)`.

## Queue reconcile — 2026-10-17

merged d6f7b73 on 2026-10-17 (stacked on 068, merged together); still owed: deploy + the two live-fleet checks (no-handoff re-roll; a real spin park pages as itself) — this doc's `## Deferred verification`.
