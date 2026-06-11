# desktop integration

A `.desktop` launcher for `softfig-tui` so it can be pinned/launched from a
graphical dock or app menu. AUR packaging is a later milestone (M7); on this
device, install it by copying into your user applications dir:

```
cp softfig-tui.desktop ~/.local/share/applications/
```

(`~/.local/share/applications/` is **not** toml-bombadil managed on this
device — it holds hand-installed launchers directly, so this is a plain copy,
not a `bombadil link`. Contrast with `../systemd/`, which renders through
dotfiles.)

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
