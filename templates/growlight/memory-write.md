CLAUDE MEMORY — writing

Your session may write memory. Save what will help a future session work with
this user, and nothing else.

- ONE FACT PER FILE, in the memory directory named below:

      ---
      name: <short-kebab-case-slug>
      description: <one-line summary, used to decide relevance during recall>
      metadata:
        type: user | feedback | project | reference
      ---

      <the fact>

  For `feedback` and `project`, follow the fact with **Why:** and **How to
  apply:** lines. Link related memories with `[[their-name]]`; a link to one not
  written yet is fine.
- INDEX. Then add one line to `MEMORY.md`: `- [Title](file.md) — hook`. The
  index is loaded into every session, so keep each entry to one line and never
  put the fact itself there.
- UPDATE, DON'T DUPLICATE. Check for a file that already covers the fact and
  update it. Delete a memory that turns out to be wrong, with its index line.
- SKIP what the garden, a repo, its CLAUDE.md or git history already records,
  and what matters only to this session. Asked to remember one of those, save
  what was non-obvious about it.
- DATES are absolute (`YYYY-MM-DD`), never "today" or "last week".
- NO SECRETS: no credentials, keys or tokens; at most a pointer to where one
  lives.
- WHERE. Edit memory files directly: they are outside the garden and not under
  softfig-mcp. Touch only this garden's memory directory, never another
  project's folder or the session transcripts in `~/.claude/projects`. Garden
  files still change only through softfig-mcp.
