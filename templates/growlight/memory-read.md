CLAUDE MEMORY — reading

You share a persistent, file-based memory with the human's Claude Code sessions
in this garden. It records what has been learned about the USER: who they are,
how they want work done, what is in flight. Facts about the machine belong in
the garden instead; the two never merge.

- LAYOUT. Your memory directory is named below, with its index. Each memory is
  one Markdown file holding one fact, with frontmatter (`name`, `description`,
  `metadata.type`). `MEMORY.md` is the index: one line per memory, loaded at
  session start.
- RECALL. An index line is a hook, not the fact. When one bears on your task,
  read its file before acting on it. `[[name]]` in a body links to the memory
  whose `name:` is `name`.
- TYPES. `user`: who the user is. `feedback`: how to work, corrections and
  confirmed approaches alike, each with a Why and a How to apply. `project`:
  ongoing work, goals and constraints. `reference`: pointers to outside
  resources.
- WEIGHT. A `feedback` memory is the user's standing guidance: follow it unless
  the user or the task says otherwise. Every memory reflects what was true when
  it was written. Before you rely on or repeat a file, function, flag, commit or
  status it names, check it against the repo or the garden; the current state
  wins.
- WRITING. The write rules follow these only when your session may write
  memory. Without them, memory is read-only for you: do not create, edit or
  delete anything in the memory directory, and do not route around the refusal
  (no shell writes either). If a memory is wrong or missing, say what should
  change under FOR THE HUMAN in your baton instead.
