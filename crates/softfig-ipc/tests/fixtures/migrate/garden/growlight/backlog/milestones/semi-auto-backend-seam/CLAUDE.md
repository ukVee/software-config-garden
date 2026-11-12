# backlog: Semi-auto growlight: real AgentBackend seam (claude|opencode)

> Milestone `semi-auto-backend-seam`. Status + queue order live in the backlog queue table (`../../CLAUDE.md`); slices run in order and this item is done only when all are done and integration is verified.

## Mission

Make the semi-auto `softfig growlight start` launch path a real AgentBackend seam (per [[spec-agents]] §4.1 / [[decision-semi-auto-backend-seam]]) so the human-driven loop can run on **opencode** as well as Claude Code — instead of the hardwired `claude` binary. **Interactive-first**; the `--auto` headless variant and the growlightd fleet are explicitly out of scope. `claude` behavior must stay byte-identical.

## Finish criteria

- [ ] `Backend` selector (`claude`|`opencode`) in softfig-cli; `--opencode` / `--backend <name>` on `StartArgs`; the `claude` path is byte-identical (existing behavior + workspace tests green, clippy `-D warnings` clean).
- [ ] Generated opencode config: a `softfig-loop` agent (prompt/`instructions` = protocol + baton-boot step; `permission` maps loop.json allow/deny incl. the garden edit/write deny), `model` wired, softfig-mcp reachable.
- [ ] `softfig growlight start --opencode` opens an interactive opencode session that carries the protocol, reads the current baton, can call softfig-mcp verbs, and is refused raw edit/write into the garden tree.
- [ ] Reseed proven: a fresh opencode session (`/new` or relaunch) re-reads the current baton via the protocol's step-0 bootstrap.
- [ ] `--no-launch` hint updated for the opencode backend + in-repo `docs/` updated in the same commits; on-device smoke recorded.
- [ ] DEFERRED (not required to close this milestone): `--auto` headless opencode (opencode-JSON parser + budget stub) — captured as slice 004.

<!-- softfig:index slices -->

| # | Note | Reviewed |
|---|------|----------|
| 001 | [CLI Backend selector + flag (claude byte-identical)](slices/001-cli-backend-seam.md) | 2026-07-31 |
| 002 | [Generate opencode agent + permission + mcp config](slices/002-opencode-generated-config.md) | 2026-07-31 |
| 003 | [opencode interactive launch + instructions-bootstrap reseed + smoke](slices/003-opencode-interactive-launch.md) | 2026-07-31 |
| 004 | [(DEFERRED) opencode --auto headless: JSON parser + budget stub](slices/004-opencode-auto-headless-deferred.md) | 2026-07-31 |
| 005 | [Interactive backend/model picker + --model + auto-cd into garden](slices/005-backend-model-picker.md) | 2026-08-12 |
| 006 | [Root opencode at the garden — give the loop a real read channel](slices/006-garden-read-channel.md) | 2026-08-13 |

<!-- /softfig:index slices -->

## Deferred verification (2026-08-12) — all buildable slices are done

**MERGED to `main` 2026-08-12** — merge `8a8abc3` (`--no-ff`), plus a docs
follow-up `40b62a1`. `main` is now **8 ahead of `origin/main`** and still
LOCAL-ONLY: the human owes the push. `feat/semi-auto-backend-seam` is retained
at `837118c` (merged, safe to delete whenever).

All six buildable slices (001 · 002 · 003 · 005 · 006) are in. Slice 004 is
DEFERRED by design and explicitly not required to close this milestone.

**Pre-merge review found one real defect, fixed before merging (`837118c`):**
the `--no-launch` opencode hint still printed `cd <runtime dir>` — the cwd slice
006 moved away from. A human following that hint got a session rooted where the
generated config grants only the runtime root + the claude-memory tree, so the
garden was unreadable: exactly the failure slice 006 existed to remove, and one
that looks fine from inside the session. Root cause was that the hint was
hand-written from the same knowledge as the launch rather than derived from it.
The `InteractiveLaunch` is now built once **before** the `--no-launch` branch and
both the hint (pure `no_launch_hint`) and the real spawn read their cwd from it;
a regression test asserts the hint's `cd` equals
`interactive_command().get_current_dir()` on both backends. The claude hint
gained the same `cd <garden>` (slice 005 pinned its cwd too). Argv unchanged on
both arms.

**Gate on the merged tree:** `cargo test --workspace` **1467 passed / 67 suites /
0 failed** + clippy `--workspace --all-targets -D warnings` clean. (The merged
tree hash is identical to the gated branch tip, so the result carries exactly.)

**Deployed:** `softfig` (CLI only) rebuilt release from `main` and installed to
`~/.local/bin/softfig` 2026-08-12 23:05. keeperd/growlightd/tui were NOT
redeployed — they don't need to be for this feature (the only shared change is
an additive `BatonView.slice` field). This retires the old caveat that the
opencode smoke had to run a branch binary: the installed `softfig growlight
start` now carries the seam.

**CONFIRMED in-session 2026-08-12 (the human's relaunch, iteration 4) — all four
checks pass inside the seam-launched opencode session itself:**
1. ✅ Garden docs read with plain reads — Read tool on `/home/owner/soft-fig_garden/…`
   works directly (no `cat "$(ls -d …)"` contortion). The slice-006 garden-root
   fix is live.
2. ✅ `~/.config/softfig/` reachable — `usage.json` + `questions.md` read via the
   `external_directory` grant (`/home/owner/.config/softfig/**`).
3. ✅ **The baton still rewrites at handoff** — proven by the iteration-4 handoff
   write to `~/.config/softfig/growlight/baton.md`; the runtime grant survives.
4. ✅ Relaunch branch of the reseed — this session WAS a fresh relaunch (branch
   binary @ 21:41, config regenerated post-`ba7ca3b`) and it re-read the current
   baton at step 0. The `/new` keystroke sub-branch remains a human TUI test.

Also re-verified post-merge against the installed binary: both `--no-launch`
hints now name the garden, and the generated `opencode.json` still loads —
`opencode agent list` resolves `softfig-loop (primary)` with the runtime grant,
the `~/.claude/projects/**` grant, and `softfig-mcp*` allowed.

Remaining — **two human-at-keyboard items, nothing blocking:**
- The `/new` keystroke reseed inside the opencode TUI (the relaunch branch is
  proven; only the keystroke sub-branch is not).
- The claude-backend regression eyeball (`growlight start` → pick 1; argv is
  unit-asserted byte-identical + shim-verified, the garden cwd is the part worth
  a human's eyes).
- Push `main` (8 ahead of `origin/main`, local-only).
- Owed cleanup: `! rm /home/owner/soft-fig_garden/inbox/opencode-smoke-DELETEME.md`
  (harness gates garden deletes).

Status stays **`deferred`** rather than `done` for the same §7b reason as before
— the two smokes above are physically the human's to run. Flip it to `done` once
they pass.

## Queue reconcile — 2026-10-17

merged 8a8abc3 on 2026-08-12; still owed: the `/new` keystroke reseed inside the opencode TUI (the relaunch branch is proven) — this doc's `## Deferred verification (2026-08-12)`.
