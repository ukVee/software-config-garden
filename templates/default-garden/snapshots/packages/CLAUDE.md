# snapshots/packages/

Installed-package lists + their refresh scripts, one subfolder per package manager (mirrors `packages/`).

## How to behave here

- Each `snapshots/packages/<tool>/` holds a `refresh-<tool>.sh` and a data subfolder with the formatted list (e.g. `<tool>-packages.md`).
- Re-run the script after installing/removing packages; the script stamps the output with a timestamp + the source command.

## Cross-refs

- `packages/<tool>/` — how to use the tool + quirks.
