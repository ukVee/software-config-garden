# {{machine}} garden

The on-device knowledge base for this machine ({{machine}}). Many small semantically-named directories of `CLAUDE.md` + reserved-name `.md` files. This file is the map.

You (Claude) are opened from this dir, so this `CLAUDE.md` is always loaded. **Sub-`CLAUDE.md` files are NOT auto-loaded** — read them on demand using the routing below.

This garden was scaffolded by **soft-fig** on {{date}}. The default layout below is a starting point — add, rename, or remove directories as this machine's reality demands. The conventions in `meta/` are what keep it coherent.

---

## House rules

1. **Source-of-truth files outside the garden are not duplicated.** When commentary references `/etc/...`, a dotfile, a unit file, etc., write *commentary on it*, not a copy. Add a `Last reviewed: YYYY-MM-DD` header so staleness is visible.
2. **Concept folders hold stable knowledge; `snapshots/` holds mutating state.** A concept folder (`packages/<tool>/`) has no scripts and no auto-refreshed data. The matching `snapshots/packages/<tool>/` owns the refresh script and the data subfolder.
3. **Reserved filenames** (`CLAUDE.md`, `instructions.md`, `notes.md`, `last_updated.md`, `refs.md`, `troubleshooting.md`) recur with the same meaning everywhere. See `meta/reserved-filenames.md`.
4. **Don't delete, archive.** Things that age out go to `journal/archive/<slug>/`.
5. **No secrets in plaintext.** Pointer-only, or use soft-fig's Layer B (`softfig vault seal` / inline `<vault id="…">…</vault>` tags).
6. **Lowercase, ASCII, no spaces** in filenames. Time-prefixed for time-sensitive: `incident-YYYYMMDD-<slug>.md`, `decision-<slug>.md`.

Full rules: `meta/conventions.md`. Read that before changing anything structural.

---

## Where does X belong? (boundary decision table)

This table is a starting skeleton — extend it as the garden grows.

| If the question is about... | Read first | Then maybe |
|---|---|---|
| how to use a package manager | `packages/<tool>/` | `snapshots/packages/<tool>/` for the installed list |
| what's installed on the system | `snapshots/packages/<tool>/` | `packages/<tool>/notes.md` for quirks |
| systemd units, daemons, the compositor/desktop | `services/` | the dotfile source that configures them |
| networking | `services/network/` | the NetworkManager / dns / vpn source files |
| filesystems, partitions, mounts, encryption-at-rest | `storage/` | `hardware/` for disk specifics |
| the kernel, boot, init, the OS layer | `os/` | `services/` for systemd |
| keyboards, touch, gestures, pointing devices | `input/` | `hardware/` for the physical device |
| audio | `audio/` | `services/` for the sound daemon |
| account, sudo, polkit, gpg/ssh keys | `users/` | each domain owns its own security posture |
| the physical machine, peripherals | `hardware/` | — |
| my code projects | `projects/<project>/` | the real repo's own `CLAUDE.md` |
| shell environment (aliases, functions, prompt, PATH, env) | `shell/` | the rendered shell rc source |
| a decision about how the garden is structured | `journal/decisions/decision-<slug>.md` | `meta/conventions.md` if it changes a rule |
| something that broke and got fixed | `journal/incidents/incident-YYYYMMDD-<slug>.md` | the affected domain's `troubleshooting.md` |
| a quick note not yet filed | `inbox/` | triage later |
| how the garden itself works | `meta/CLAUDE.md` | `meta/conventions.md`, `meta/reserved-filenames.md` |

Boundary rule: own each concept once; cross-reference from any other domain that touches it.

---

## Top-level map

- `meta/` — docs about the garden itself (conventions, reserved filenames). Read before changing structure.
- `inbox/` — triage drawer for unfiled notes.
- `journal/` — dated decisions, incidents, and the archive.
- `hardware/`, `os/`, `storage/`, `input/`, `audio/`, `users/`, `shell/` — concept dirs. Mostly empty stubs; grow them from real questions.
- `packages/` — package-manager concept folders.
- `services/` — daemons + units; networking nests inside.
- `snapshots/` — mutating state + refresh scripts; mirrors the concept dirs.
- `projects/` — commentary on the code projects under this machine's projects directory (the real code stays in its own repos).

---

## How to behave when working in the garden

- **Before answering a question**, route via the table above to the right `CLAUDE.md` and read it.
- **When the user changes something on the system**, update the relevant `notes.md` and bump the `Last reviewed:` header on anything that referenced the old state. If a snapshot exists for the changed thing, run its refresh script.
- **When you don't know where something belongs**, drop a placeholder file in `inbox/` and tell the user — don't fabricate a category.
- **When something breaks and gets fixed**, write a `journal/incidents/incident-YYYYMMDD-<slug>.md`.
- **When making a structural decision**, write a `journal/decisions/decision-<slug>.md` AND update `meta/conventions.md` if the rule itself changed.
- **Never duplicate** content from a real repo's `CLAUDE.md` or a source-of-truth config. Point at it; comment on it.

---

## Onboarding this garden (fresh scaffold)

This garden was just created and is mostly empty stubs. To make it useful, help the user survey {{machine}} and fill the concept dirs from what's actually on the machine:

1. **Packages** — list installed packages for each package manager; write the snapshot under `snapshots/packages/<tool>/` and quirks under `packages/<tool>/notes.md`.
2. **Services** — enumerate enabled systemd units (system + user); document the load-bearing ones in `services/`.
3. **Hardware** — capture the machine model, CPU/GPU, peripherals in `hardware/`.
4. **Shell + dotfiles** — note the shell environment in `shell/`; point at the dotfile manager's source rather than copying it.
5. **Projects** — for each active code project, add a `projects/<name>/` commentary folder pointing at the real repo.

Work incrementally, one domain at a time, and follow `meta/conventions.md` for naming and the source-of-truth rule. Drop anything you can't classify into `inbox/`.
