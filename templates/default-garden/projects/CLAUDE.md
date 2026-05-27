# projects/

Garden-side commentary on the code projects on this machine. The actual code stays in its own repos — this dir holds *the framing*: how each project fits into this system, when it was last touched, what to remember across sessions.

The repo's own `CLAUDE.md` (inside the real project) tells claude how to work in the code. The garden's `CLAUDE.md` (here) tells claude how to think about the project as a piece of the system. They're complementary — point at the repo's `CLAUDE.md` from `refs.md`; don't duplicate.

## How to behave here

- Add a `projects/<name>/` folder per active project, mirroring the real projects directory.
- Code-level questions (build, architecture, FFI) → follow `refs.md` to the real repo's `CLAUDE.md`.
- System-level questions (how it interacts with services/dotfiles, why it exists here, what state it's in) → the garden's `CLAUDE.md` here.
- Don't migrate code-level details into the garden.

## Cross-refs

- `services/` — when a project ships or relies on a unit.
- `hardware/` — device constraints a project targets.
