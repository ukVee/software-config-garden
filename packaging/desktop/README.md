# desktop integration

`.desktop` launchers so soft-fig front-ends can be pinned or launched from a
graphical dock or app menu:

- `growlight-gui.desktop` — the growlight fleet console (native `iced`/Wayland
  GUI).
- `softfig-tui.desktop` — the ratatui keeper/garden TUI, run inside a terminal.

Install by copying into your user applications dir:

```
cp packaging/desktop/growlight-gui.desktop ~/.local/share/applications/
cp packaging/desktop/softfig-tui.desktop   ~/.local/share/applications/
```

## growlight-gui.desktop

`growlight-gui` is a native `iced` (Wayland) window, **not** a terminal app, so
it sets `Terminal=false`. Its Wayland `app_id` is pinned to `growlight-gui` in
code (`crates/softfig-growlight-gui/src/runtime.rs::window_settings`, the
freedesktop "match the `.desktop` basename" convention); `StartupWMClass=growlight-gui`
mirrors it so a dock associates the live window with the pinned entry. iced
otherwise leaves the app-id empty, which a dock keying on the toplevel app-id
can't match.

The binary is built only with the `gui` feature; the default workspace build
never compiles the heavy iced dependency:

```
cargo install --path crates/softfig-growlight-gui --features gui --root ~/.local --force
```

## softfig-tui.desktop

`softfig-tui` is a ratatui TUI, so the launcher runs it inside `foot` and tags
the window with `--app-id=softfig-tui` (matching `StartupWMClass`). Swap `foot`
for your terminal if you use another one.

## `Exec` and PATH — read before installing

Both launchers use bare binary names in `Exec=`, which assumes the binaries are
on the launcher's `PATH`. With the default `~/.local/bin` install that often
**isn't** true: a dock or launcher started as a systemd user service inherits a
`PATH` like `/usr/local/bin:/usr/bin` without `~/.local/bin`, and a `.desktop`
`Exec` field has no `~`/`%h` expansion. If the launcher does nothing, patch the
absolute path into your installed copy:

```
Exec=/home/<you>/.local/bin/growlight-gui
Exec=foot --app-id=softfig-tui /home/<you>/.local/bin/softfig-tui
```

Keep the drafts in this directory generic.

## Icons

Both use stock placeholders (`utilities-system-monitor`, `utilities-terminal`)
— there is no soft-fig icon yet.
