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
  - `decision-<slug>.md` (date is in frontmatter or the first line, not the filename, since decisions are referenced by name)
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

## Config sources vs environment commentary

When a domain has both a **config source** (a file rendered/managed elsewhere) and an **environment** (the resulting behavior at runtime), they live in different dirs:

- The config source belongs wherever it is actually rendered from — usually your dotfile manager's source tree.
- The commentary on the resulting environment belongs in the matching concept folder.

Examples:
- `services/` documents daemons; the dotfile source tree holds the unit files.
- `shell/` documents the shell environment (aliases, functions, prompt, env); the dotfile source holds the rc files.

Keep the `dotfiles/` stub (if you add one) about the rendering pipeline itself, not about any specific tool's environment. Don't grow it into a catch-all.

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

## Small files: numbered note folders

The two **accretive** reserved files are **folders**, not monolithic files: `notes/` and `troubleshooting/` hold single-fact docs named `NNN-slug.md` (e.g. `services/<daemon>/notes/001-startup-quirk.md`). Narrative whole-read docs stay monolithic: `CLAUDE.md`, `instructions.md`, `refs.md`.

- **Per-folder numbering.** Monotonic `+1`, never reused, 3-digit zero-pad (`001`). The number is a creation-order stamp — highest present = newest. Each accretive folder is an independent sequence with its own daemon-owned `.seq` high-water mark (never hand-edited). Archiving a note leaves a gap; numbers are never renumbered.
- **Immutable address.** A note's filename, slug, number, and title are fixed for life. To "rename," archive the note and add a new one. This is what keeps `[[…]]` cross-references stable.
- **Cross-references** use `[[NNN-slug]]` or `[[path]]`. The daemon maintains a backlink section and per-folder index tables in **managed regions** (fenced, daemon-owned) — never hand-edit inside those markers.

**All garden mutations go through soft-fig's MCP verbs** — never raw `mv`/`sed`/editor writes. The daemon owns every mechanical field (dates, numbers, headers, filenames, index tables, backlinks, and the commit), so you emit only the irreducible new content. North-star rule: *the unit of change equals the unit of output.* Verb surface:

- Notes: `add_note`, `revise_note` (body-only), `archive`.
- Any markdown doc: `add_section`, `edit_section`, `append_to_section`.
- Whole-doc: `set_reviewed` (date bump), `replace_file` (break-glass — verbatim bytes, no stamping, discouraged).
- Kind-specific: `log_decision`, `log_incident`, `add_project`, `refresh_snapshot`.

## Excluding paths from the VCS (`.softfigignore`)

The garden VCS excludes `.softfig` (VCS state) and `.claude` (agent scratch) by default. To exclude **additional** top-level paths, add their names to a `.softfigignore` file at the garden root — one name per line, `#` comments and blank lines ignored, a single trailing `/` tolerated. v1 matches top-level names only (like the built-ins); the built-ins themselves can't be un-ignored.

The file is itself tracked (so the ignore set versions + replicates with the garden) and is read fresh on each commit/event — an edit takes effect with no daemon restart. See `reserved-filenames.md` ("VCS ignore file").

## Never put data or values in section headings

Headings are **immutable addresses**, not content. The section verbs (`edit_section`, `append_to_section`) address a section by its heading text and *keep the heading line* — there is no "rename heading" verb, and a note's title is fixed for life (see "Small files" above). So any **mutable value** baked into a heading goes stale the moment it changes and can only be corrected with a whole-file `replace_file` break-glass.

Keep values — percentages, versions, dates, counts, prices, sizes, absolute paths, anything that can change — in the **body**, never the heading. Write headings as stable *topics*:

- Bad: `## Volume: 30% baseline` → wrong after a retune, un-renameable.
- Good: `## Volume: baseline + toggle`, with "0.20 (20%)" in the body.

If a value needs to be visible at a glance, put it in the first body line, not the heading. This keeps every heading a durable anchor for `edit_section` and `[[…]]` cross-references.
