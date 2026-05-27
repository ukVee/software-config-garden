# snapshots/

Mutating state + the scripts that refresh it. Mirrors the concept-dir tree: `snapshots/packages/<tool>/` matches `packages/<tool>/`, and so on.

The split (see `meta/conventions.md`): concept folders hold **stable knowledge**; snapshot folders hold **auto-refreshed data** plus the refresh script.

## How to behave here

- A snapshot folder owns: a `refresh-<tool>.sh` script and a data subfolder holding its formatted-markdown output.
- Refresh scripts write **formatted markdown** (timestamped header + source command + grouped sections), not raw command dumps.
- When the system changes, re-run the relevant refresh script and bump any `Last reviewed:` headers that referenced the old state.

## Cross-refs

- The matching concept dir (`packages/`, `services/`, …) for the stable knowledge.
