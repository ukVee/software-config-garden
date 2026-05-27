# meta/

Documentation **about the garden itself** — its conventions and its schema.

Read this dir before changing how the garden is structured. Don't read it for everyday questions about the system.

## Children

- `conventions.md` — the rule book. How files are named, when to write a `Last reviewed:` header, the source-of-truth + commentary rule, archive-don't-delete, the boundary rule. **Read this first.**
- `reserved-filenames.md` — authoritative list of reserved names (`CLAUDE.md`, `instructions.md`, `notes.md`, `last_updated.md`, `refs.md`, `troubleshooting.md`) and their purposes. Don't reuse them for anything else.

## How to behave here

- If a convention changes, update `conventions.md` first, then propagate.
- If a reserved name is added or repurposed, update `reserved-filenames.md` first.
- Keep this dir about *the garden's structure*, not about any one machine's specifics — those belong in the concept dirs.
