# shell/

The shell **environment**: aliases, functions, prompt, `PATH`, env vars, completion. Commentary on the runtime behavior.

The shell's *config sources* (the rc / profile files) live where they're managed (a dotfile manager, `~/.bashrc`, etc.) — point at them; don't copy them here. Same config-source-vs-environment split that `services/` uses for units.

## How to behave here

- Document what the environment does and why (a non-obvious alias, a PATH ordering gotcha), not a copy of the rc file.

## Cross-refs

- the dotfile source that renders the shell rc.
- `users/` — login shell selection.
