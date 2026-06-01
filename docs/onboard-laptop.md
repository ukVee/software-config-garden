# Onboarding soft-fig on a new device

This is the manual runbook for bringing soft-fig up on a second machine
(the laptop). It produces **one standalone, single-device garden** that
documents *that* machine — it does **not** copy the tablet's garden
content. Cloning moves the *program* (the schema), never a garden's
*instance* (the knowledge). Cross-device **sync** is a later milestone
(M5); for now the laptop garden stands alone.

AUR packaging (M7) will automate all of the below. Until then, this is the
correct short path.

## Prerequisites

- Rust toolchain (the workspace targets Rust ≥ 1.85, edition 2024).
- `fuse3` (Arch: `sudo pacman -S fuse3`). The daemon serves the decrypted
  garden through a FUSE mount at the garden root; the on-disk `.softfig/`
  state stays encrypted under `~/.local/share/softfig/<name>/`.
- `~/.local/bin` on your `PATH`.

## 1. Clone the program

```bash
git clone <repo-url> ~/projects/software-config_garden
cd ~/projects/software-config_garden
```

## 2. Build + install the binaries

Either run the helper script:

```bash
./scripts/onboard-device.sh
```

…which builds `--release`, installs `softfig`, `softfig-keeperd`,
`softfig-mcp`, and `softfig-tui` into `~/.local/bin`, checks for `fuse3`,
then **prompts** before enabling the systemd user unit and before
registering the MCP server in `~/.claude.json`.

Or do it by hand:

```bash
cargo build --release
install -m0755 target/release/softfig         ~/.local/bin/
install -m0755 target/release/softfig-keeperd  ~/.local/bin/
install -m0755 target/release/softfig-mcp      ~/.local/bin/
install -m0755 target/release/softfig-tui      ~/.local/bin/
```

## 3. Scaffold the garden

`softfig onboard` is interactive — it prompts for a master passphrase at a
TTY, so it can't run fully non-interactively (a `--yes` run with no TTY
stops before the passphrase step with a message).

```bash
softfig onboard
# optional flags:
#   --garden-root PATH   (default ~/soft-fig_garden)
#   --state-root PATH    (default ~/.local/share/softfig/<garden-dir-name>/)
#   --machine NAME       (default: system hostname)
#   --customize          interactively toggle which concept dirs to include
#   --yes                accept the full default layout, skip dir prompts
```

What it does (born-in-FUSE — no plaintext ever lands at the garden root):

1. Resolves `garden_root` / `state_root` / machine identity.
2. `vault init` — prompts the passphrase twice, then prints the **12-word
   recovery phrase ONCE**. Write it down offline; it is the only way back
   in if you forget the passphrase, and it is never stored in plaintext.
3. Stamps the embedded default skeleton into a throwaway tempdir,
   substitutes `{{machine}}` / `{{date}}` placeholders.
4. Writes the genesis `init` commit, encrypting the skeleton into
   `state_root/.softfig/`, then discards the plaintext staging.
5. Writes the `keeper.toml` state-root pointer the daemon discovers.

## 4. Start the daemon + unlock

If you let the script enable the unit:

```bash
systemctl --user status softfig-keeperd   # confirm it's running (LOCKED)
softfig daemon unlock                      # once per boot — prompts passphrase
```

Otherwise start it in the foreground / by hand:

```bash
softfig daemon start --garden ~/soft-fig_garden
softfig daemon unlock
```

The daemon reads `~/soft-fig_garden/.softfig/keeper.toml`, sees the
`state_root`, enters FUSE mode, and mounts the decrypted garden at
`~/soft-fig_garden`. On unlock the tree becomes readable/writable through
the mount; saves are committed by the watcher.

> **Smoke check (do this on the real machine — FUSE can't mount in a dev
> sandbox):** after unlock, `ls ~/soft-fig_garden` should show `CLAUDE.md`,
> `meta/`, the concept-dir stubs, etc. Unmounting (stop the daemon) makes
> the garden root show only the `keeper.toml` pointer again — the plaintext
> only ever exists through the mount.

## 5. Fill the garden

Open a Claude session at `~/soft-fig_garden`. The stamped routing
`CLAUDE.md` carries a "how to behave on a fresh garden" note: Claude reads
the skeleton, then helps survey the machine (installed packages, enabled
services, hardware, the device's bombadil profile) and fill the concept
stubs. The `snapshots/` refresh-script pattern (e.g. `refresh-pacman.sh`)
is the model for capturing mutating state.

## 6. (optional) Drive the garden from the terminal (M3b TUI)

`softfig-tui` is a ratatui frontend over the running daemon — handy on a
headless box over SSH, or just for a tactile view. It talks to the same
socket as the CLI and MCP; start the daemon + unlock first (the TUI can
also unlock in-app).

```bash
softfig-tui
```

Keys: `1`/`2` switch Browse / History · `j k ↑ ↓` move · `Enter`/`l`/`→`
open file or expand dir · `h`/`←` collapse · `u` unlock · `:` command
palette (runs `log_decision`, `log_incident`, `archive`, `add_project`,
`refresh_snapshot`, `propose`) · `r` refresh · `?` help · `q` quit.

Browse content comes through the daemon's read-only `list_tree` /
`read_file` verbs, which redact server-side: sealed files show
`[sealed:<path>]`, inline `<vault id="…">` regions show `[encrypted]` —
the TUI never receives sealed plaintext (reveals stay CLI-only:
`softfig reveal`).

## What's deferred

- **Templating + symlink deploy** (M4) — onboarding does dumb one-shot
  `{{name}}` substitution, not the templating engine.
- **Cross-device sync / pairing** (M5) — "clone" here is plain git; the
  laptop garden is standalone.
- **AUR packaging + post-install automation** (M7) — this runbook is the
  manual stand-in.
