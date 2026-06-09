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

Keys: `1`/`2`/`3` switch Browse / History / Vault · `j k ↑ ↓` move ·
`Enter`/`l`/`→` open file / expand dir / reveal (Vault) · `h`/`←` collapse ·
scroll the preview (right pane) vim-style: `^e`/`^y` line, `^d`/`^u`
half-page, `^f`/`^b` (or `PgDn`/`PgUp`) full-page, `g`/`G` top / bottom,
mouse wheel line-wise · `x` reveal selected sealed file · `c` copy the last
reveal's value · `u` unlock · `:` command palette (runs `log_decision`,
`log_incident`, `archive`, `add_project`, `refresh_snapshot`, `propose`,
`seal`, `unseal`) · `r` refresh · `?` help · `q` quit.

Browse content comes through the daemon's read-only `list_tree` /
`read_file` verbs, which redact server-side: sealed files show
`[sealed:<path>]`, inline `<vault id="…">` regions show `[encrypted]` —
the TUI never receives sealed plaintext.

The **`3:Vault` tab** lists the sealed-path globs + the files they match.
`seal` / `unseal` (palette) add or remove a glob. **Reveal** (`x` or `Enter`)
prompts for the master password and shows only the daemon's `0600` temp-file
path + re-auth expiry — the plaintext is *never* rendered in the TUI. `c`
copies that value to the Wayland clipboard by piping the temp file straight
into `wl-copy` (needs `wl-clipboard`; the bytes never pass through the TUI's
memory). Whole-file reveal only — inline `<vault id="…">` region reveal stays
CLI-only (`softfig reveal --id`).

## Troubleshooting

### `softfig daemon unlock` fails with `Operation not permitted (os error 1)`

The daemon reached the FUSE-mount step and the `mount(2)` was denied with
EPERM. This identical symptom has had **two distinct, unrelated root causes**
on real devices — both are documented below. The quickest split: run the
daemon **outside** systemd (Cause 1's last block). If that *fixes* it, you
have Cause 1 (the unit). If it *still* fails the same way, you have Cause 2
(the mount options).

#### Cause 1 — systemd unit hardening fighting the FUSE mount (seen on the laptop)

The daemon mounts via the setuid-root `fusermount3` helper, which is broken by:

- `NoNewPrivileges=true` — makes `execve()` ignore the setuid bit, so
  `fusermount3` runs unprivileged and the `mount(2)` syscall returns EPERM.
- `ProtectSystem=` / `PrivateTmp=` and other namespacing options — give the
  unit its own mount namespace, so even a successful mount stays invisible
  to your shell (`ls ~/soft-fig_garden` shows only `keeper.toml`).

The shipped `packaging/systemd/softfig-keeperd.service` carries none of
these. If you hit the error, you're likely running an **older copy of the
unit** — reinstall it and restart:

```bash
install -m0644 packaging/systemd/softfig-keeperd.service \
  ~/.config/systemd/user/softfig-keeperd.service
systemctl --user daemon-reload
systemctl --user restart softfig-keeperd
softfig daemon unlock
```

To confirm the unit is the culprit, run the daemon **outside systemd** —
if it works there, none of the hardening applies and the unit is the problem:

```bash
systemctl --user stop softfig-keeperd
softfig daemon start --garden "$HOME/soft-fig_garden"
softfig daemon unlock        # succeeds -> Cause 1; still EPERM -> Cause 2
```

#### Cause 2 — `allow_other` pulled in by `AutoUnmount` (seen on the tablet)

Independent of systemd. `fuser` silently appends `allow_other` whenever the
daemon requests the `AutoUnmount` mount option, and `fusermount3` rejects
`allow_other` unless `user_allow_other` is enabled in `/etc/fuse.conf` — which
surfaces as the same opaque EPERM. The tell is this line in the daemon's
stderr / journal:

```bash
journalctl --user -u softfig-keeperd -e | grep fusermount3
# fusermount3: option allow_other only allowed if 'user_allow_other' is set in /etc/fuse.conf
```

Fixed in `softfig-fuse`: the daemon no longer requests `AutoUnmount`, so the
garden mounts **owner-only** with no `/etc/fuse.conf` change. (Enabling
`user_allow_other` would "fix" it too, but it exposes the decrypted plaintext
to other uids/root — the wrong trade for a vault, so we don't.) The daemon
unmounts explicitly on every clean path and reclaims a crashed daemon's stale
mount on the next mount, so dropping `AutoUnmount` costs nothing. If you see
the line above, you're on a pre-fix build — rebuild and reinstall the binaries.

## What's deferred

- **Templating + secret-aware deploy** (M4b/M4c) — the static deploy spine
  (`softfig deploy`, M4a) has landed, but onboarding still does dumb one-shot
  `{{name}}` substitution, not the MiniJinja templating engine (M4b) or
  render-time Vault secrets/posthooks (M4c). A freshly onboarded laptop garden
  has no `config/` tree to deploy yet — that arrives at the dogfood ceremony.
- **Cross-device sync / pairing** (M5) — "clone" here is plain git; the
  laptop garden is standalone.
- **AUR packaging + post-install automation** (M7) — this runbook is the
  manual stand-in.
