# backlog: roadeye M2 — roadeyed core: routing, capture, AGC, encode, socket

> Milestone `roadeye-m2-daemon-core`. Status + queue order live in the backlog queue table (`../../CLAUDE.md`); slices run in order and this item is done only when all are done and integration is verified.
> Fleet: no

## Mission

> Model: claude

The first real code. `roadeyed` runs as the **video group, not root** (SPEC.md §3.1) and owns
the whole video path: media-graph routing → V4L2 capture → AGC → debayer → Venus encode, with a
JSON-RPC socket for control.

Every piece of it is a spike promoted to production: 0.2's `media-ctl` sequence becomes the
startup routine, 0.1's control loop becomes the AGC, 0.4's encoder setup becomes the sink. The
debayer stage exists only if M1 said it does.

Daemon + socket + separate UI follows the **`l-lightning`** pattern — see
`projects/l-lightning/` in this garden, including `notes/002-m3-0-touch-spike.md` for why the
UI is egui and not a TUI.

Slice when it reaches the queue head, against the locked M1 spec.

Repo: `/home/sshukv/projects/roadeye` on **`otg-travel`**. `cargo build -j2` — zram-only swap,
`systemd-oomd` kills bigger link steps.

## Finish criteria

- [ ] `roadeyed` runs as the `video` group with **no root**, and is verified to.
- [ ] Media-graph routing applied at startup from 0.2's proven sequence; both cameras stream.
- [ ] Closed-loop AGC from 0.1, tuned for driving (SPEC.md §3.3).
- [ ] Debayer stage present or absent per M1's decision — not left as dead code either way.
- [ ] Venus encode producing a fragmented, power-loss-safe container.
- [ ] JSON-RPC socket with the control surface M4/M5 need.
- [ ] Clean start/stop with no leaked media-graph state — a second start must succeed after
      an unclean stop.
