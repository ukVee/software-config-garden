# soft-fig

> One tool for the files that describe your machine: a **memory garden**, a
> **dotfile manager**, an **encryption-at-rest store**, and a **version
> control system** — sharing one config and one CLI, instead of four tools
> stitched together.

A "garden" is the set of files that describe a machine — how it's configured,
what's installed, why a choice was made, what broke and how it got fixed.
`soft-fig` (binary: `softfig`) treats that as one first-class object: an
encrypted-at-rest, version-controlled tree of small, semantically-named
directories that a human or an LLM can navigate without being told. It started
as a personal knowledge base for one Arch laptop, worked well enough to become
a program others could adopt, and this repo is that program. The garden is the
product; everything soft-fig ships — the Growlight work loop included — exists
to serve it.

## 📖 Documentation

**The full documentation lives at
<https://ukvee.github.io/software-config-docs>** — start there. It covers what
a garden is, installing and growing your first one, working with Claude, the
Growlight loop, task guides, and the complete CLI / MCP / config / crypto
reference, plus a codebase tour. This README is just the front door.

> The docs are the narrative and reference surface; the design specs (the
> vision and the per-pillar thinking) live in the garden this repo is a
> prototype for — see [Design](#design-where-the-thinking-lives).

## Status

**1.0.0-alpha.1 — the first public alpha.** Built and used daily on one device
by one author: expect rough edges, and read [SECURITY.md](SECURITY.md) before
trusting it with anything you can't afford to lose (the cryptography has not
been independently audited). What ships:

- **Engine** — the Vault (encryption at rest + selective secrets), the
  content-addressed ciphertext VCS, the per-device daemon, the FUSE
  plaintext-on-demand view, and the source-agnostic watcher.
- **Keeper surfaces** — the `softfig` CLI, the `softfig-mcp` bridge (typed,
  convention-stamping write verbs for Claude sessions; reads stay native;
  Vault ops never exposed to the model), and the `softfig-tui` terminal UI.
- **First run** — `softfig onboard`, a wizard that scaffolds a fresh garden
  and writes a *born-in-FUSE* genesis commit (no plaintext ever touches the
  garden root).
- **Recovery as a declared policy** — `vault status`, escrow export/verify,
  guarded recovery-door add/drop, and Argon2 cost `rewrap`.
- **Deploy** — `softfig deploy` materializes a declarative
  `config/deploy.toml` source→target table (symlink-to-cache or stamped copy).
- **Cross-device sync** — device pairing over a SAS-confirmed Noise channel,
  zero-knowledge replica backup to your own devices (LAN, relayable off-LAN),
  and shared subtrees between paired devices. Young and lightly tested across
  devices.
- **Growlight** — an autonomous work loop (a curated *baton* carried across
  agent sessions), run interactively with `softfig growlight start` or
  unattended by the supervised `growlightd` fleet.

Not built yet: template rendering (profile-scoped vars + render-time secrets),
a general desktop GUI, prebuilt packages (AUR, `.deb`, …) and a
`softfig upgrade` command. Linux + systemd + FUSE only. Full, dated detail:
[the docs status page](https://ukvee.github.io/software-config-docs/internals/status/).

## Quickstart

There are no prebuilt packages yet, so build from source. This produces **one
standalone garden that documents the machine it runs on** — cloning this repo
to a new device moves the *program* (the schema), never another device's
*content*. The full runbook is in the
[install guide](https://ukvee.github.io/software-config-docs/start/install/)
and [first-garden tutorial](https://ukvee.github.io/software-config-docs/start/first-garden/);
the short path:

**Prerequisites:** a Rust toolchain (workspace targets Rust ≥ 1.88, edition
2024); `protoc` and fuse3 with its development headers (Arch:
`sudo pacman -S protobuf fuse3`; Debian/Ubuntu:
`sudo apt install protobuf-compiler libfuse3-dev fuse3`); and `~/.local/bin` on
your `PATH`.

```bash
# 1. Clone
git clone https://github.com/ukVee/software-config-garden.git ~/projects/software-config_garden
cd ~/projects/software-config_garden

# 2. Build + install the binaries. The helper builds --release, installs them,
#    checks for fuse3, then prompts before enabling the systemd user unit and
#    registering the MCP server with Claude Code (user scope).
./scripts/onboard-device.sh

# 3. Scaffold the garden. Interactive: prompts for a passphrase, prints a
#    12-word recovery phrase ONCE (write it down offline), writes a
#    born-in-FUSE genesis commit.
softfig onboard            # --customize to pick concept dirs, --yes for defaults

# 4. Start the daemon + unlock (once per boot; mounts the FUSE view).
softfig daemon start --garden ~/soft-fig_garden
softfig daemon unlock
```

Then open Claude from the garden root (its `CLAUDE.md` is the always-loaded
map) and drive the garden through the MCP verbs, or browse it with
`softfig-tui`. See
[working with Claude](https://ukvee.github.io/software-config-docs/garden/working-with-claude/).

## Design: where the thinking lives

This repo is the *implementation*. The *design* — the vision, the per-pillar
spec playgrounds, and the dated decision log — lives in the garden it's a
prototype for. Each milestone has a corresponding `decision-softfig-*.md`
recording the locked design picks and as-built deltas. The specs are
deliberately allowed to be incomplete and to contradict each other; they are
thinking surfaces, not contracts. The [codebase tour](https://ukvee.github.io/software-config-docs/internals/architecture/)
in the docs is the way into the crates.

## License

AGPL-3.0-or-later — strong copyleft: any modified version must be offered
under the same terms, including when it is run as a network service (the
§13 "Remote Network Interaction" clause). See [LICENSE](LICENSE) for the
full text.
