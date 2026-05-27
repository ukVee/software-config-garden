# Conventions

The rules every other directory follows. If a rule changes, update this file first, then propagate.

## Source of truth

When a real file outside the garden is the canonical thing (`/etc/...`, a unit file, a dotfile manager's source), the garden does **not** copy it. The garden writes the **commentary** on it: why a choice was made, what was tried, gotchas, the time it broke, what to look for when it breaks again.

Every file that references mutable external state has a `Last reviewed: YYYY-MM-DD` header so staleness is visible. Reviewing means re-reading the source and confirming the commentary still applies — not just bumping the date.

## Don't delete, archive

Things that are no longer current go to `journal/archive/<slug>/`, not the trash. Abandoned projects, obsolete decisions, retired hardware notes — all kept. The garden's history is part of its value.

## Filenames

- Lowercase, ASCII, no spaces. Use `-` between words (`pacman-packages.md`, not `Pacman_Packages.md`).
- Reserved names recur in every folder of a section with the same meaning everywhere. See `reserved-filenames.md`.
- Freeform-semantic when a folder holds many like-kind items (one file per package, one per ssid, one per service).
- Time-prefixed for time-sensitive files:
  - `incident-YYYYMMDD-<slug>.md`
  - `decision-<slug>.md` (date is in the first line, not the filename, since decisions are referenced by name)
  - Journal entries: `journal/<bucket>/YYYY-MM-DD-<slug>.md`

## Concept folders vs snapshots folders

A concept folder (e.g., `packages/<tool>/`) holds **stable knowledge** about a thing: how to use it, what's quirky on this device, links to canonical sources. No scripts. No mutating data.

A snapshot folder (e.g., `snapshots/packages/<tool>/`) holds **mutating state** plus the script that refreshes it. The script lives next to the data subfolder; a `CLAUDE.md` in the snapshot folder describes both.

Refresh scripts produce **formatted markdown**, not raw command output. Header with timestamp and source command, grouped sections, browsable structure.

## CLAUDE.md per directory

Every meaningful directory has a `CLAUDE.md` that:
1. Says what the directory is.
2. Maps each child (file and subdir) — what it's for, when claude should read it.
3. States how to behave here (write rules, naming exceptions, who owns adjacent concepts).
4. Cross-references domains that touch this one.

Sub-`CLAUDE.md` files are NOT auto-loaded. The top garden `CLAUDE.md` and per-section `CLAUDE.md` files must explicitly tell claude when to read which sub-`CLAUDE.md`.

## Boundary rule

Own each concept once; cross-reference from any other domain that touches it. If two top-level dirs could plausibly own the same thing, the top `CLAUDE.md` decides — and the loser cross-refs to the winner.

## Last reviewed header

When commentary references a real source-of-truth file or external system, the file starts with:

```
> Last reviewed: YYYY-MM-DD
> Source: /etc/...
```

For snapshots, the refresh script writes the timestamp into the output file's header automatically.

## History is managed by soft-fig

This garden's version history, encryption-at-rest, and selective-secret sealing are handled by **soft-fig** (the program that scaffolded it). There is no `.git` here — the garden's `.softfig/` store (relocated under the daemon's state root when FUSE-mounted) is the canonical history. Don't add a parallel `git init`.

## No secrets in plaintext

If a file would need a real secret (API key, ssh private key contents), don't put the secret in the garden in the clear. Either write a pointer ("the API key lives in <encrypted source>") or seal it with soft-fig's Layer B:

- File-level: `softfig vault seal '<glob>'` (e.g. `secrets/**`).
- Region-level: wrap the secret in an inline `<vault id="some-name">SECRET</vault>` tag; on read through the mount it shows `<vault id="some-name">[encrypted]</vault>`.

Reveals are user-initiated (`softfig reveal`) and never expose plaintext to Claude.
