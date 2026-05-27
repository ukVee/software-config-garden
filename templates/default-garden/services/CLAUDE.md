# services/

Daemons, systemd units, and the desktop/compositor stack on this machine. One subfolder per service worth documenting (e.g. `services/network/`, `services/bluetooth/`).

This dir holds **commentary on the resulting runtime behavior**. The unit *source files* belong wherever they're actually managed (a dotfile manager, `/etc/systemd/...`, `~/.config/systemd/user/...`) — point at them, don't copy them.

## How to behave here

- Document a service when it's load-bearing or has non-obvious behavior worth remembering.
- Networking nests under `services/network/`.
- For a unit that a code project ships, cross-ref the project's `projects/<name>/` folder.

## Cross-refs

- `os/` — the kernel / init layer beneath systemd.
- `packages/` — the package that provides a daemon.
