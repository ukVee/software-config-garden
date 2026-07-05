# journal/

Time-ordered records: decisions, incidents, and the archive.

Distinct from per-folder `notes/` (domain-specific running observations). Journal entries are *garden-wide* and worth a chronological view.

## Children

- `decisions/` — `decision-<slug>.md` files for choices that shape the garden or the system. Date in the file's first line, not the filename (decisions are referenced by name).
- `incidents/` — `incident-YYYYMMDD-<slug>.md` files for things that broke and got fixed. Date in the filename for sortability.
- `archive/` — abandoned projects, retired notes, anything that shouldn't live in a current concept folder but shouldn't be deleted. See `meta/conventions.md` "Don't delete, archive."

## How to behave here

- Writing a decision: name it after the choice (`decision-no-swap.md`), not after when it happened. Open with a date line.
- Writing an incident: include the date in the filename. Inside: what happened, what was tried, what fixed it, what changed to prevent recurrence.
- Archiving: move the original folder/file under `archive/<slug>/` rather than deleting. Add a one-line note about why.
