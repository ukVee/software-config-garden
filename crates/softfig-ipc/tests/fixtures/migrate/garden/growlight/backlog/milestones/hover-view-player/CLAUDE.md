# backlog: [blocked on hover-view-sticky] hover-view own player — layer-shell surface, any video source, MPRIS playhead handoff

> Milestone `hover-view-player`. Status + queue order live in the backlog queue table (`../../CLAUDE.md`); slices run in order and this item is done only when all are done and integration is verified.
> Fleet: no

## Mission

Phase 2. Replace Firefox's Picture-in-Picture window with **our own surface**, so the floating box is not a borrowed window we decorate from outside but a thing we own: our touch handling, our chrome, any video source, no Firefox dependency.

**This milestone is `blocked` on purpose and must stay blocked until `hover-view-sticky` slice 007 answers its three gating questions.** It exists now so the phase-1 work is measured against something, not so it gets built. If phase 1 lands and the box already feels right, the correct outcome is to close this out unbuilt and say why.

## The gate

Slice 007 of `hover-view-sticky` answers these. Do not start until all three are written down there:

1. **Does touch move/resize of Firefox's PiP window still hurt** after phase 1's corner-snap and size steps?
2. **Did control-tap conflicts materialise** — does the double-tap leave the video paused, do Firefox's own buttons still work under an observe-only tap zone?
3. **Is Firefox-only a real limit in practice** on this device?

A "no" to all three closes this milestone. Build it because phase 1 left something broken, not because it was planned.

## What phase 1 proved, which changes this milestone's shape

Two things were unknown when this was first sketched and are now settled facts:

**The URL and playhead handoff is solved, not speculative.** Firefox exposes MPRIS with everything needed — verified live on device 2026-09-27 against a playing YouTube video:

```
xesam:url      https://www.youtube.com/watch?v=FkEh4B5CKfI
xesam:title    How to Crack any Software
mpris:length   1820000000
Position       1157000000   (int64, microseconds)
CanSeek        true
CanPause       true
```

So the round trip is ordinary work: read `xesam:url` + `Position`, pause Firefox, launch our player seeked to that position; on return, read our position, seek Firefox with `playerctl position <t>`, resume, switch workspace, focus. `playerctl` is installed. Instances are enumerable with `playerctl -l` (the sampled instance was `firefox.instance_1_60`), so multiple simultaneous media elements are addressable. **MPRIS identifies a media element, not a window** — so it is the playhead authority and a sanity check on the URL, never the way to find which window to return to. That stays phase 1's `origin.rs` job.

**Layer-shell gives stickiness for free.** A `wlr-layer-shell` surface is bound to an *output*, not a workspace, so it appears on every workspace by construction — no `wm-actions`, no sticky flag, no window rules, and no 70%-opacity collision with `alpha_70`. `gtk4-layer-shell` 0.5 is installed and `swipe-panel` already uses it with `gtk4` 0.9, so this is the house stack rather than a new one.

That trade is the real content of this milestone: layer-shell hands us stickiness and full touch ownership, and takes away being a normal window — no compositor move/resize plugins, no `alpha`, no window rules. **Everything phase 1 got from Wayfire, we would have to implement.** That is the cost to weigh at the gate, and it is not small.

## Open decisions, none locked

- **Video stack.** `libmpv` render API into a GTK4 `GLArea`, versus `gstreamer` + `gtk4paintablesink`. `mpv` is **not installed** (deliberately — phase 1 forbids installing it); `gstreamer`, `gst-plugin-gtk4`, `gst-plugin-pipewire` and `ffmpeg` all are. The gstreamer route adds no package. Neither is chosen.
- **Stream resolution.** `yt-dlp` is installed and `projects/yt-pipe/` already carries the hard-won cookie knowledge: bulk YouTube access 403s without cookies, and `COOKIES=1` rides the Firefox session (`projects/yt-pipe/troubleshooting/001-http-403-forbidden.md`). A player that re-resolves the stream URL inherits that problem — and inherits it on the *interactive* path, where a 403 is a black box instead of a failed batch job. Handing the media element off from an already-authenticated browser avoids it entirely. This is an argument for the browser's PiP, and the gate should weigh it.
- **Scope beyond YouTube.** "Any video source" is the stated draw; whether anything on this device actually needs it is gating question 3.
- **Chrome and gestures.** Ours to build: play/pause, seek, close, return-to-tab, drag, pinch-resize. Per the house rule (`feedback_sliver_dock_no_local_gestures`) complex touch goes through `touch-drawer`, **not** GTK `GestureDrag` — so this consumes the v4 broker from phase 1 slice 003 rather than hand-rolling gestures in the client.

## Non-goals

- Not a general media player. `Roudy-Player` streams SoundCloud, `yt-pipe` archives YouTube; this is a floating box for something you are already watching. Growing it into a third player is out of scope.
- Not a replacement for phase 1's `hover-viewd` posture logic if phase 1 shipped and works — a layer-shell surface makes that logic unnecessary for *our* surface, but Firefox's PiP window would still exist and might still be worth governing.

## Finish criteria

Provisional — the gate may change these, and they must be re-derived from slice 007's answers before any code is written.

0. **The gate is answered in writing** in `hover-view-sticky` slice 007, and at least one of its three questions came back "yes, this still hurts". Without that, the correct completion of this milestone is to close it unbuilt with the reasoning recorded.
1. The box is visible and interactive on all four workspaces **without** any sticky flag, window rule or `wm-actions` involvement — stickiness comes from being a layer surface, asserted by checking no window rule matches it.
2. A video playing in Firefox hands off to the box with the playhead continuous to within one second, measured from MPRIS `Position` either side of the handoff, and Firefox's own playback is paused rather than left running in the background burning battery.
3. Double-tap returns the video to its tab: the box closes, Firefox is seeked to the box's position, resumed, and the compositor lands on that tab's workspace with it focused. Playhead continuity measured, not eyeballed.
4. Drag and resize are handled through the `touch-drawer` v4 broker, not GTK gestures, per the standing house rule.
5. Touch latency on the box is not visibly worse than Firefox's PiP window was — compared side by side, with the comparison recorded.
6. Power draw while playing is measured against phase 1's Firefox-PiP baseline and does not regress. This device hard-resets under thermal load; an own-player that decodes less efficiently than the browser is a defect, not a trade-off.
7. A stream that fails to resolve (403, expired cookies, network loss) surfaces a legible failure in the box and leaves the origin tab untouched and still playable — never a silent black rectangle. `projects/yt-pipe/troubleshooting/001-http-403-forbidden.md` is the prior art.
8. `projects/hover-view/` documents both phases, which one is live, and how to fall back to the other.
