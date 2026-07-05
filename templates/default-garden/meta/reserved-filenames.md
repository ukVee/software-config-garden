# Reserved filenames

These names recur across the garden with **the same meaning everywhere**. Predictability beats expressiveness — claude (and you) should always know where to look.

Don't reuse these names for anything else.

## v1 reserved set

| Name | Purpose | Required where |
|---|---|---|
| `CLAUDE.md` | Navigator: what this dir is, what each child is for, how to behave here, mapping to real filesystem, cross-refs to adjacent domains. | Every meaningful directory. |
| `instructions.md` | How to use the thing this dir represents — commands, workflows, day-to-day verbs. | Whenever there's a "how do I do X" answer for this domain. |
| `notes/` | Personal observations, quirks, gotchas specific to *this* device or *this* setup. Not generic docs — the stuff a reader of the wiki wouldn't already know. A **folder** of `NNN-slug.md` notes; see *Accretive reserved files are folders* below. | Whenever there's a "watch out for X" worth recording. |
| `last_updated.md` | Pointers to sibling/snapshot files + when each was last reviewed or refreshed. The dir's staleness dashboard. | Required for any concept dir whose snapshots auto-refresh. Optional otherwise. |
| `refs.md` | External pointers: URLs, paths to source-of-truth files elsewhere on disk (`/etc/...`), wiki links, vendor docs. | When the dir cites a lot of external sources. |
| `troubleshooting/` | How things broke in this domain and what fixed them. Distinct from `journal/incidents/` — that's chronological/garden-wide; this is "fixes I'll need again." A **folder** of `NNN-slug.md` docs; see below. | Optional. Add when it would be useful. |
| `backlog.md` | Forward-looking open work for a project/domain — what's queued, not what happened. Distinct from `notes/` (running narrative). | Optional. Add where a project has tracked forward work. |
| `backlog-archive.md` | Terse log of shipped/closed `backlog.md` items (date — item — what closed it). The quick "what's been knocked off" view. | Optional. Pairs with `backlog.md`. |

## Refresh script naming

Inside `snapshots/<area>/<tool>/`:

- `refresh-<tool>.sh` — the executable script.
- `<tool>-packages.md` (or domain-appropriate name) inside a child folder named for the data category — the formatted output.

## Reserved-but-not-yet-used

These are reserved for future use; don't use them for anything else:

- `history.md` — chronological log of changes/decisions specific to one folder. Not adopted in v1; `journal/decisions/` covers garden-wide decisions for now.
- `glossary.md` — domain-specific term definitions. Add when a domain has enough jargon to need one.
- `index.md` — explicit outline of children when a `CLAUDE.md` is too dense to also be the navigator.

## Accretive reserved files are folders

The two **accretive** reserved files are directories, not single files:

- `notes/` — holds `NNN-slug.md` notes.
- `troubleshooting/` — holds `NNN-slug.md` fixes.

Each folder has a daemon-owned `.seq` high-water counter and its own independent numbering sequence (`notes/` and `troubleshooting/` in the same dir count separately, both from `001`). The reserved *name* denotes the folder; add entries with `add_note`, never by hand. The monolithic reserved files — `CLAUDE.md`, `instructions.md`, `refs.md` — are unchanged.

See `meta/conventions.md` ("Small files: numbered note folders").

## VCS ignore file (`.softfigignore`)

`.softfigignore` — an optional file at the **garden root** listing extra top-level directory/file names to exclude from the garden VCS, on top of the built-in `.softfig`/`.claude` (which it cannot un-ignore). One name per line; `#` comments and blank lines ignored; a single trailing `/` tolerated. v1 honors top-level names only. It is itself tracked, so the ignore set versions + replicates with the garden. Don't reuse the name for anything else.

See `meta/conventions.md` ("Excluding paths from the VCS").

## Updating this list

This file is the authoritative source for reserved names. To add or rename, update here first, then update `meta/conventions.md` if the rule changes, then propagate to every existing directory.
