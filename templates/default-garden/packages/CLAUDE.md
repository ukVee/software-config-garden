# packages/

Concept folders for the package managers on this machine. One subfolder per tool (e.g. `packages/pacman/`, `packages/yay/`, `packages/flatpak/`).

A concept folder here holds **stable knowledge**: how to use the tool, quirks specific to this machine, links to canonical docs. The *installed list* and the script that refreshes it live in the mirror at `snapshots/packages/<tool>/` — not here.

## How to behave here

- "How do I use <tool>?" → `packages/<tool>/instructions.md`.
- "What's installed?" → `snapshots/packages/<tool>/`.
- "Why is <package> pinned / what broke?" → `packages/<tool>/notes/`.
- Create a new `packages/<tool>/` when a new package manager is adopted, and a matching `snapshots/packages/<tool>/` for its list.

## Cross-refs

- `snapshots/packages/` — the mutating installed lists + refresh scripts.
- `services/` — when a package ships a daemon worth documenting.
