# growlight/backlog/

The growlight work queue. Each row is a backlog item the loop drains — a milestone (with ordered slices) or a standalone task. One item is `active` at a time; the loop pulls the next `queued` item by order.

Item docs live in `milestones/<id>/` and `tasks/NNN-<slug>.md`. Status + order are owned by the daemon-managed queue table below — change it only via `add_backlog_item` / `set_item_status`, never by hand.

## Queue

<!-- softfig:queue -->

| # | id | type | title | status |
|---|----|------|-------|--------|
| 94 | semi-auto-backend-seam | milestone | Semi-auto growlight: real AgentBackend seam (claude\|opencode) | deferred |
| 111 | 069 | task | [bug] Spin guard parks a member that IS progressing — one non-handoff session trips it, and the page reads "blocked on a human decision" | deferred |
| 118 | folder-grants | milestone | [human/semi-auto, fleet-core] Folder grants — per-item allowed folders for fleet members (`> Grants:` / `> Worktree:`), enforced in opencode's rules | queued |
| 131 | claude-login-pool-wiring | milestone | [semi-auto] claude-login pool wiring — consume per-profile machinery in production (review 048 M-A/B/C/E) | done |

<!-- /softfig:queue -->

## Queues

<!-- softfig:queues -->

| queue | repo |
|-------|------|
| docs | /home/ukv/projects/softfig-docs |
| roadeye | otg-travel:/home/sshukv/projects/roadeye (REMOTE — ssh otg-travel, port 42218) |
| hoverview | /home/ukv/projects/hover-view |
| fixes | ~/projects/software-config_garden/codebase |

<!-- /softfig:queues -->

## Queue: docs

<!-- softfig:queue:docs -->

| # | id | type | title | status |
|---|----|------|-------|--------|

<!-- /softfig:queue:docs -->

## Queue: roadeye

<!-- softfig:queue:roadeye -->

| # | id | type | title | status |
|---|----|------|-------|--------|
| 3 | roadeye-m2-daemon-core | milestone | roadeye M2 — roadeyed core: routing, capture, AGC, encode, socket | queued |

<!-- /softfig:queue:roadeye -->

## Queue: hoverview

<!-- softfig:queue:hoverview -->

| # | id | type | title | status |
|---|----|------|-------|--------|
| 1 | hover-view-sticky | milestone | hover-view — Firefox PiP becomes a cross-workspace floating video box (sticky, snap-resize, double-tap back to tab) | blocked |
| 2 | hover-view-player | milestone | [blocked on hover-view-sticky] hover-view own player — layer-shell surface, any video source, MPRIS playhead handoff | blocked |

<!-- /softfig:queue:hoverview -->
