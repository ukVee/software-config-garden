# backlog: hover-view — Firefox PiP becomes a cross-workspace floating video box (sticky, snap-resize, double-tap back to tab)

> Milestone `hover-view-sticky`. Status + queue order live in the backlog queue table (`../../CLAUDE.md`); slices run in order and this item is done only when all are done and integration is verified.
> Fleet: no

## Mission

Give this device an iPhone-style floating video box: pop a YouTube video out of Firefox into a small always-visible window that **follows you across all four workspaces**, moves and resizes under touch, and **double-taps back to full size in the tab it came from, on that tab's workspace**.

Phase 1 of two. This milestone rides **Firefox's own Picture-in-Picture window** and adds the compositor-side behavior it lacks. Phase 2 (`hover-view-player`) replaces the surface with our own layer-shell player and is seeded `blocked` on what this milestone learns. The phasing, and the four decisions behind it, are on record in `journal/decisions/decision-hover-view-firefox-pip-first.md`.

## Starting state, verified on device 2026-09-27

Wayfire 0.11 (`0.11.0-d3990237`, wlroots 0.20.2). Output `eDP-1`, id 1, **logical 1280x853 at scale 1.5** (native 1920x1280 3:2). Workspace grid **2x2** (`[core] vwidth/vheight = 2`).

**What already works.** Firefox's built-in PiP is present and has been used — the profile `~/.mozilla/firefox/owfbndfv.default-release` carries `media.videocontrols.picture-in-picture.video-toggle.has-used = true` and `...enable-when-switching-tabs.enabled = true`. So "pop the video out into a floating box" is not work; it is a button that already exists.

**What is missing** is every compositor-side property that makes it feel like iPhone PiP: it is not sticky, not always-on-top, it is rendered at 70% opacity by an existing window rule, it does not snap, and its double-click does the wrong thing.

**The compositor exposes enough to fix all of it without patching Firefox.** `ipc` + `ipc-rules` are loaded and the socket is live at `$WAYFIRE_SOCKET` (`/run/user/1000/wayfire-wayland-1-.socket`); the wire format is a 4-byte native-endian length prefix followed by `{"method": ..., "data": {...}}`. Verified by querying it during planning.

- `window-rules/list-views` returns, per view: `id`, `pid`, `title`, `app-id`, `geometry`, `base-geometry`, `bbox`, `output-id`, `output-name`, `role`, `layer`, `mapped`, `fullscreen`, `minimized`, `activated`, **`sticky`**, **`always-on-top`**, `wset-index`, `tiled-edges`, `min-size`, `max-size`, `focusable`, `last-focus-timestamp`, `parent`.
- Other `ipc-rules` methods: `view-info`, `configure-view`, `focus-view`, `close-view`, `get-focused-view`, `get-focused-output`, `get-view-property`, `set-view-property`, `list-outputs`, `output-info`, `list-wsets`, `wset-info`, `get-cursor-position`, `unblock-map`, **`events/watch`**.
- `vswitch/set-workspace` (workspace switching), `move/activate`, `resize/activate` (the binary also carries a `preserve_aspect` string), `view-shot/capture`.
- `wm-actions` is **installed but NOT loaded**; loading it adds `wm-actions/set-sticky`, `set-always-on-top`, `set-fullscreen`, `set-minimized`, `send-to-back`, `bring-to-front`.
- `window-rules` (loaded) supports the actions `set alpha <double>`, `set geometry x y w h`, `set geometry <x11-geometry-string>`, `set geometry_ppt`, plus sticky, always_on_top and `assign_workspace` (symbols `_make_sticky`, `_always_on_top` in `libwindow-rules.so`).
- Also installed and unloaded: `pin-view`, `stipc`, `blur`, `pixdecor`, `wsets`.

**Absolute geometry encodes the workspace.** A view sitting one workspace to the left reported `geometry.x = -1275` where the same layout on the current workspace reports `x = 5` — a stride of exactly the output width (1280). The `[vswitch] gap = 20` is transition-animation only and does **not** enter the layout stride. Any geometry math in this milestone has to respect that.

**The PiP window is matchable by title.** `pictureinpicture.ftl` in `/usr/lib/firefox/omni.ja` defines `pictureinpicture-player-title = Picture-in-Picture`, and that is the player window's title. `app-id` is `firefox` for every Firefox toplevel, so title is the discriminator.

**Firefox's own double-click is the wrong action.** `chrome/toolkit/content/global/pictureinpicture/player.js` `onDblClick` fires `fullscreenModeToggle()` and only when `event.target.id == "controls"` — it fullscreens the *box*, on the *current* workspace. The affordance we actually want is the `unpip` button, which calls `PictureInPicture.focusTabAndClosePip(window, this.actor)`; `ESC` runs the same `onClose` path. A tap on the video body is `draggableregionleftmousedown` (a window-move start), **not** play/pause — which is why an observe-only double-tap over the box is safe.

**The trap.** `~/dotfiles/src/wayfire.ini` already carries `alpha_70 = on created if (type is "toplevel" & fullscreen is false) then set alpha 0.7`. Left alone, that renders the floating video at 70% opacity. Any PiP rule must opt out of it **without weakening the 70% default for every other window**.

**The gesture broker is drag-only.** `touch-drawer` (loaded) brokers zones that emit `drag-begin`/`drag`/`drag-end` for `up`/`down`/`bidir` directions (protocol v3: `register <id> <x> <y> <w> <h> <dir> <reply-socket> <begin-arg...> [enabled]`, plus `unregister`, `set-enabled`, `update-bounds`; `commit_threshold = 10`). It has **no tap primitive**, errors are silently dropped, zone priority is implicitly registration order, and there is no notion of *which service* a registration came from. Its only client today is `swipe-panel`. This milestone makes it multi-client, which is a protocol and a **security** change, not just a feature — see slice 003.

`extra-gestures` is loaded at defaults (`move_fingers = 3`, `move_delay = 750`, `close_fingers = 20` i.e. disabled). Turning `move_fingers` down to 1 globally would make every 250ms finger-hold-and-drag move a window instead of scrolling a page, so per-view gating is required rather than a config tweak.

## Locked decisions (user, 2026-09-27)

1. **Phased, Firefox PiP first.** Phase 1 rides Firefox's PiP window; phase 2 (`hover-view-player`) is a separate milestone, seeded `blocked` on phase 1's findings, and is built only if phase 1's residual friction justifies it.
2. **One gesture broker, isolated clients.** The double-tap goes through `touch-drawer`, not a second plugin. In exchange, `touch-drawer` must gain **clear separation of concerns and isolation between different services' calls** — plus **overlapping-zone flagging** and a conflict-resolution policy that is deliberately *both* security-focused and performance-focused. This is a first-class requirement of slice 003, not a nice-to-have.
3. **"Open fully" means return to the tab, on that tab's workspace.** The video goes back inline into the Firefox tab it came from, the compositor switches to that tab's workspace and focuses it. Not "fullscreen the box where it is", and not "also send `f`".
4. **Name: `hover-view`.** Repo `~/projects/hover-view/`, garden `projects/hover-view/`, daemon binary `hover-viewd`, growlight queue `hoverview`.

**Backend/model:** seeded for a **human-directed semi-auto** session with `growlightd` stopped (`fleet_enabled = false` at seed time, per seeding rule 3). Not fleet work: slices 001, 004, 005 and 007 need a human physically touching the screen and watching a video, and slice 003 edits a loaded compositor plugin whose failure mode is "touch input stops working". Slice 003 also warrants a reasoning model — it is a security boundary.

**Nothing new gets installed.** Phase 1 needs no new package: Firefox, `playerctl`, `wtype`, `jq`, `yt-dlp` are present; `mpv` is deliberately **not** installed and must not be, in this milestone. The only compositor change is loading the already-installed `wm-actions`.

## Repos this touches

| repo | what changes |
|---|---|
| `~/projects/hover-view/` | **new** — `hover-viewd`, Rust, the Wayfire IPC controller |
| `~/projects/touch-drawer/touch-drawer/` | protocol v4: tap zones, service identity, overlap policy, lock-free hot path |
| `~/dotfiles/` | `src/wayfire.ini` (load `wm-actions`, PiP window rules) + the session unit |

Per the queue binding, `hoverview` → `/home/ukv/projects/hover-view`. Slices that build in a different repo say so in their own header; a slice never assumes the queue repo is the repo it edits.

## Finish criteria

Each criterion names the observation that settles it. "It works" without the stated evidence does not satisfy any of them.

1. **Sticky across the whole grid.** A PiP window popped out on one workspace is visible and interactive on all four workspaces of the 2x2 grid — verified both by eye on each workspace and by `window-rules/list-views` reporting `sticky: true` for that view id. No ghost copy, no duplicate, no view left behind on the origin workspace.
2. **Opaque, without collateral damage.** The PiP window renders at full opacity while every other non-fullscreen toplevel still renders at 0.7. Asserted by reading the rule set *and* by observing a second window at 70% in the same screenshot — the fix must not be "drop `alpha_70`".
3. **Above the stack.** `always-on-top: true` in `list-views`, and the box stays visible over a normal toplevel on every workspace. Behavior over a *fullscreen* window is **recorded as a finding**, not asserted as a pass — a fullscreen client may legitimately win.
4. **Move.** One-finger drag moves the box. On release it snaps to the nearest corner with a fixed margin; the snapped rect is fully on-screen on every workspace and never lands under a panel/bar or off the output edge. Checked at all four corners.
5. **Resize.** A resize gesture steps the box through discrete sizes with the video's aspect ratio preserved — no letterbox or pillarbox introduced by us. The box never shrinks below the view's advertised `min-size` nor grows past the configured max fraction of the output.
6. **Double-tap returns the video to its tab, on that tab's workspace.** Performed from a workspace *different* from the origin, and observed: the video resumes inline in the origin Firefox tab, the compositor lands on the origin workspace, that window has focus, and **the playhead is continuous** (not restarted, not rewound). The origin workspace and the double-tap workspace are both recorded in the handoff.
7. **Degraded double-tap is defined.** With the origin window closed, moved to a different workspace, or moved to a different output since pop-out, double-tap does a documented, non-crashing thing. Each of the three cases is exercised and its behavior written down. An unhandled error or a hung daemon fails this.
8. **Survives a reload.** A `bombadil link` + Wayfire `auto_reload_config` pass, and a full Firefox restart, both leave the PiP posture correct with no stale `touch-drawer` zone registrations. After the PiP window closes, the broker's live zone count returns to its pre-PiP baseline — asserted by a broker query, not inferred.
9. **Service isolation is enforced, not documented.** A second service cannot register into another service's zone namespace, cannot point a reply socket outside its own runtime directory, and cannot silently shadow another service's zone. Each attempt receives an **explicit error reply** (v3 dropped errors silently; v4 must not). Demonstrated with a hostile test client, not by reading the code.
10. **Overlap is flagged.** Registering a zone that intersects a live zone produces a reported overlap; a cross-service identical-rect registration is refused outright. Both paths are exercised.
11. **No input-latency regression.** The touch-down classify path takes no lock (copy-on-write snapshot). Taps on Firefox's own PiP controls — play/pause, unpip, fullscreen — still work while a tap zone covers the box, because tap zones observe and never grab. `swipe-panel`'s open and close drags behave exactly as they did on v3, confirmed by using the panel.
12. **Idle cost is measured.** With no PiP window present, `hover-viewd` sits at ~0% CPU and wakes only on compositor events — it must not poll. Stated as a measurement (sampled CPU time over a fixed window), not as a design claim. This device hard-resets under thermal load; an idle busy-loop is a defect.
13. **Garden is honest.** `projects/hover-view/` documents the architecture and the Firefox-PiP dependency; `services/wayfire/notes/` carries the probe answers from slice 001 and the window-rules commentary; `projects/touch-drawer/` documents protocol v4 and **supersedes** the "zone priority is registration order" note; `journal/decisions/decision-hover-view-firefox-pip-first.md` is cross-linked from both milestones.
14. **Everything installed is bombadil-sourced.** The session unit and any wrapper are rendered from `~/dotfiles/src/`; nothing hand-written lands under `~/.config/` or `~/.local/bin/`. `bombadil link` from a clean checkout reproduces the setup including file modes.

<!-- softfig:index slices -->

| # | Note | Reviewed |
|---|------|----------|
| 001 | [The config-only win, and the nine things we do not know yet](slices/001-probe-and-window-rules.md) | 2026-09-27 |
| 002 | [hover-viewd — the Wayfire IPC controller, PiP identity, and origin capture](slices/002-hover-viewd-ipc-controller.md) | 2026-09-27 |
| 003 | [touch-drawer v4 — tap zones, derived service identity, declared overlap, lock-free hot path](slices/003-touch-drawer-v4-multi-service.md) | 2026-09-27 |
| 004 | [Move, corner-snap, and aspect-locked size steps](slices/004-move-snap-resize.md) | 2026-09-27 |
| 005 | [Double-tap — back to the tab, on the workspace it came from](slices/005-double-tap-return-to-tab.md) | 2026-09-27 |
| 006 | [Session unit, bombadil sourcing, and the garden write-up](slices/006-session-unit-and-garden-docs.md) | 2026-09-27 |
| 007 | [On-device verification — run the fourteen criteria and decide phase 2](slices/007-on-device-verification.md) | 2026-09-27 |

<!-- /softfig:index slices -->
