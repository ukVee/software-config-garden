# backlog: [human/semi-auto, fleet-core] Folder grants — per-item allowed folders for fleet members (`> Grants:` / `> Worktree:`), enforced in opencode's rules

> Milestone `folder-grants`. Status + queue order live in the backlog queue table (`../../CLAUDE.md`); slices run in order and this item is done only when all are done and integration is verified.

## Mission

> **HELD 2026-10-11 — do not start.** [[decision-growlight-queue-redesign]] replaces the queue registry and `default_repo` that slice 002 builds, and makes slice assignment growlightd-owned. [[spec-growlight-queue]] was specced 2026-10-11 (§14 item 9): revise the grants spec and these slices only after the three queue-v2 milestones (`queue-v2-state`, `queue-v2-scheduling`, `queue-v2-git`) **and** the backlog migration session have landed. **Reaffirmed by the owner 2026-10-17:** follow the order — no grants build until then. **Updated 2026-10-18:** `queue-v2-scheduling` is merged (`843c17c` in `main` `5a1dc78`) and the fleet is building `queue-v2-git` under an owner ruling. **Owner directive 2026-10-18 (later):** the only remaining start gate is **`queue-v2-git`**. The moment it reaches a terminal state (`done` or `deferred`), the hold lifts — `> Fleet: no` → `> Fleet: yes` — and the fleet builds the milestone; the owner dropped the backlog-migration session as a *start* gate. The grants spec/slice revision remains the milestone's **first** work, rebased on the merged queue-v2 design, before any build.

> Model: claude
> Fleet: no
> Worktree: ~/projects/software-config_garden/codebase/folder-grants

Step 2 of [[decision-opencode-v2-fleet-safety-order]]. Today a headless opencode member can neither read nor write any code repo through its file tools, so it can do no real work, and claude members are not confined at all. Build the contract in [[spec-growlight-grants]]: milestones, slices and tasks declare which folders a member may write, read, or must not touch. One shared resolver turns those declarations into an ordered list at each spawn, refuses the spawn on anything unsafe, and feeds it into opencode's permission rules. The same list is what the Landlock layer (step 4) will enforce against the shell later. The spec is the source of truth; this doc only tracks the build.

## Owner ruling 2026-10-18 — the fleet builds it, gated on `queue-v2-git`

The owner directed the fleet to take this milestone the moment `queue-v2-git` lands. This ruling supersedes, **for this item only**:

- "Fleet-core work is hand / semi-auto only" (rules §7) and the standing constraint to keep `fleet_enabled = false` — the gate is already `true` for other work and must **not** be touched for this item;
- the backlog-migration session as a *start* gate (see the Mission block). The migration is still owed by the human; do not assume it has run.

What still holds, and why:

- **Spec first.** Before any build, revise [[spec-growlight-grants]] and these slices against the merged queue-v2 design ([[spec-growlight-queue]] §14 item 9), recording every place the pre-queue-v2 text no longer matches in the slice's `## Built` note.
- **Never set `queue = "v2"` in the live `config/growlight.toml`**, and never flip `fleet_enabled`. You are supervised by the legacy queue; changing it moves your own scheduler.
- **Never deploy, merge, restart or `daemon cycle`.** Code-complete work parks `deferred` for the human (rules §6).
- **Slice 006 (live smoke) is the human's.** It needs the owner present and a disarmed fleet; a member that reaches it writes the exact commands and parks `deferred`. It never flips the switch or the roster.
- **Refusals park; they never re-roll** — every new fail-closed path goes through the slice-002 park classification.

## Finish criteria

- [ ] `softfig-ipc` holds the one grant resolver (parse, variables, canonicalization, ceiling, ordered resolution with origins + widened flag), and the `> Model:` resolver shares its doc-chain walk. Unit tests cover every fail-closed refusal in spec §5/§6.
- [ ] growlightd resolves grants at each spawn from the seeded baton, keeps the registry repo column, honors `default_repo`, and a refusal **parks the member and alerts once** (no re-roll). A launch-time `provider.no-route` parks the same way.
- [ ] Both opencode postures emit grant rules in the spec §7 positions. rw/ro/deny/`.git`/ceiling verdicts are proven on a private serve with opencode's own matcher at zero spend, and the literal-vs-resolved path question is settled.
- [ ] softfig-mcp refuses a member-originated change to a `> Grants:`/`> Worktree:` line (member identity via the MCP server `env`, not the self-declared `editor`). Members see their grants via an injected `grants.md`, and `protocol-fleet.md` carries the roll-on-slice-change rule.
- [ ] `growlight status` + the TUI fleet panel show each member's grants with origins and widenings (claude: `advisory`), and `softfig growlight grants <item> [--slice N]` dry-runs the resolution.
- [ ] Live smoke (spec §13 slice 6) passes on-device with one opencode member.
- [ ] `cargo test --workspace` green and `cargo clippy --workspace --all-targets -- -D warnings` clean on the branch tip. Repo docs + `growlight/backlog/CLAUDE.md` "Declaring grants" section updated. The loop never merges; the human reviews and merges.

## Branch policy

Branch `feat/folder-grants` off `main` (`5ed0ea3` or later), in its own worktree (`codebase/folder-grants`), which is also the `> Worktree:` header above (inert until this milestone builds the parser, and it dogfoods the header). Commit per slice. The loop never merges; the human reviews and merges.

## Standing constraints

- **Fleet-core work is hand / semi-auto only** (rules §7). Keep `config/growlight.toml` at `fleet_enabled = false` until slice 006's smoke, and seed throwaway items only while growlightd is stopped.
- **Spec first.** [[spec-growlight-grants]] is the contract. A slice that finds the spec wrong records the finding and fixes the spec in the same slice, rather than drifting from it silently.
- **This is not a sandbox.** The member's shell stays `shell * allow`. Do not describe grants as confinement in code comments, docs or status output. Step 4 (Landlock) confines the shell.
- **Keep the claude launch path byte-identical** (spec §10): claude members get `advisory` grants in status only.
- **opencode probes use a private `opencode serve` or `--standalone`, never the shared service** (facts: `growlight/backlog/milestones/opencode-v2-repin/slices/001-probe-v2-facts.md` `## Outcome`). Zero-spend verdict checks only, until slice 006.
- **Refusals park; they never re-roll.** Any new fail-closed path added here must go through the slice-002 park classification.

<!-- softfig:index slices -->

| # | Note | Reviewed |
|---|------|----------|
| 001 | [The grant model in softfig-ipc — parse, expand, canonicalize, ceiling, resolve](slices/001-grant-model-in-ipc.md) | 2026-10-11 |
| 002 | [growlightd: resolve at spawn, keep the repo binding, park on refusal](slices/002-growlightd-spawn-resolution.md) | 2026-10-11 |
| 003 | [Emit grant rules into the opencode floor — headless + interactive, proven on a private serve](slices/003-rule-emission-both-postures.md) | 2026-10-11 |
| 004 | [Grant integrity (members can't edit grant headers) + grants.md + roll-on-slice-change](slices/004-integrity-and-member-context.md) | 2026-10-11 |
| 005 | [Surface grants (status, TUI, dry-run verb) + docs + device headers](slices/005-surfacing-and-docs.md) | 2026-10-11 |
| 006 | [Live smoke — one opencode member on a throwaway repo](slices/006-live-smoke.md) | 2026-10-11 |

<!-- /softfig:index slices -->
