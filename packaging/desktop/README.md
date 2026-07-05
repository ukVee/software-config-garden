# desktop integration

`.desktop` launchers so soft-fig front-ends can be pinned/launched from a
graphical dock or app menu:

- `growlight-gui.desktop` — the growlight fleet console (native iced/Wayland
  GUI). **This is the dock's soft-fig entry as of 2026-07-05.**
- `softfig-tui.desktop` — the ratatui keeper/garden TUI. Still shipped for
  standalone use; **no longer pinned in sliver-dock** (the GUI replaced it).

AUR packaging is a later milestone (M7); on this device, install by copying
into your user applications dir:

```
cp growlight-gui.desktop ~/.local/share/applications/
cp softfig-tui.desktop   ~/.local/share/applications/
```

(`~/.local/share/applications/` is **not** toml-bombadil managed on this
device — it holds hand-installed launchers directly, so this is a plain copy,
not a `bombadil link`. Contrast with `../systemd/`, which renders through
dotfiles.)

The dock roster itself (which of these is pinned) lives in
`~/dotfiles/src/sliver-dock/apps.toml` and is applied with `bombadil link` +
a `sliver-dock` restart — separate from installing the launcher here.

## growlight-gui.desktop

`growlight-gui` is a native `iced` (Wayland) window, **not** a terminal app —
so unlike the TUI it needs no `foot` wrapper and sets `Terminal=false`. Its
Wayland `app_id` is pinned to `growlight-gui` in code
(`crates/softfig-growlight-gui/src/runtime.rs::window_settings`, the freedesktop
"match the `.desktop` basename" convention); `StartupWMClass=growlight-gui`
mirrors it so a dock associates the live window with the pinned entry. iced
otherwise leaves the app-id empty, which a dock keying its running-app set on
the toplevel app-id (sliver-dock) can't match.

The binary is built only with the `gui` feature
(`cargo install --path crates/softfig-growlight-gui --features gui --root ~/.local --force`);
the default workspace build never compiles the heavy iced dependency.

The same `Exec`/PATH caveat as the TUI applies — the installed copy hardcodes
the absolute path:

```
Exec=/home/ukv/.local/bin/growlight-gui
```

Icon is `utilities-system-monitor`, a stock placeholder (a fleet monitor); swap
for a real logo when one exists.

## softfig-tui.desktop

`softfig-tui` is a ratatui TUI, so the launcher runs it inside `foot` and tags
the window with `--app-id=softfig-tui` (matching `StartupWMClass`) so a dock
can associate the running window with the pinned entry.

### `Exec` and PATH — read before installing

The `Exec=` here uses the bare names `foot` and `softfig-tui`, assuming both
are on the launcher's `PATH`. That holds once `softfig-tui` is installed to a
standard bindir (e.g. `/usr/bin` via the future AUR package).

**On this device it is not on PATH.** `softfig-tui` lives in `~/.local/bin`,
and the launcher is spawned by `sliver-dock` — a systemd **user** service
whose inherited `PATH` is `/usr/local/bin:/usr/bin:...` and does **not**
include `~/.local/bin`. A `.desktop` `Exec` field has no `%h`/`~` expansion
(unlike the systemd units, which use the `%h` specifier), so the bare name
would fail to resolve. The installed copy therefore hardcodes the absolute
path:

```
Exec=foot --app-id=softfig-tui /home/ukv/.local/bin/softfig-tui
```

Keep this draft generic; patch the absolute path into the installed copy (or
move the binary onto the dock daemon's PATH).

### Icon

`utilities-terminal` is a stock placeholder — there is no softfig icon on the
system yet. Swap `Icon=` for a real logo (installed under
`~/.local/share/icons/hicolor/.../softfig-tui.png` and referenced by name)
when one exists.
