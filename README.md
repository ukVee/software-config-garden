# soft-fig

> One tool for the files that describe your machine: a **memory garden**, a
> **dotfile manager**, an **encryption-at-rest store**, and a **version
> control system** — sharing one config and one CLI, instead of four tools
> stitched together.

`soft-fig` (binary: `softfig`) is the reference implementation of an idea
that started as a personal knowledge base. The knowledge base — a tree of
small, semantically-named directories of `CLAUDE.md` + reserved-name `.md`
files documenting one Arch laptop — worked well enough that it became the
prototype for a program other people could adopt. This repo is that program.

**Status:** the engine and first-run experience are built and self-hosting;
sync, templating/symlink deployment, the GUI/TUI, and AUR packaging are not
started. See [Status](#status). This is a single-author work in progress, not
a released tool.

---

## The idea

A "garden" is the set of files that describe a machine — how it's
configured, what's installed, why a choice was made, what broke and how it
got fixed. Today people scatter that across dotfile repos, wiki pages, shell
history, and memory. soft-fig treats it as one first-class object with four
properties:

1. **The directory layout *is* the schema.** Knowledge lives in concept
   folders (`packages/pacman/`, `services/network/`) with reserved filenames
   that mean the same thing everywhere (`CLAUDE.md` = "what this dir is and
   how to behave here"; `notes.md` = device-specific quirks; etc.). An LLM or
   a human can navigate it without being told.
2. **Commentary, not copies.** When a real file outside the garden is the
   source of truth (`/etc/pacman.conf`, a systemd unit), the garden stores
   *why* and *what to watch for*, with a `Last reviewed:` date — never a
   duplicate that silently rots.
3. **History is part of the value.** Nothing is deleted; obsolete things are
   archived. Every change is a typed, signed commit you can query by intent
   ("decisions this month," "everything that touched this project").
4. **Encrypted at rest, plaintext on demand.** The on-disk store is
   ciphertext. The working tree is a FUSE mount the daemon serves only while
   unlocked. Secrets can be sealed even *within* the otherwise-plaintext view,
   so an AI assistant reading the garden never sees them.

The result: adopt soft-fig once and get a memory store, a config deployer, an
at-rest vault, and a versioning system that share a single mental model.

## The five pillars

| Pillar | What it does | Replaces |
|---|---|---|
| **Machine memory** | The `CLAUDE.md` + concept-folder + snapshots schema as a first-class abstraction. | ad-hoc notes / wikis |
| **Templating + theming** | Render source files into deployable configs with profile-scoped variables; secrets resolved at render time. | [toml-bombadil](https://github.com/oknozor/toml-bombadil) render side |
| **Symlink deployment** | Declarative source→target table that materializes a system from sources. | `bombadil link`, GNU Stow |
| **Integrated VCS** | Linear, signed, intent-classified history over content-addressed ciphertext blobs + a queryable SQLite index. | git, for this use case |
| **Vault** | Encryption-at-rest, key management, secrets, and a trust system that lets devices unlock each other. | LUKS + GPG + `pass`, partially |

### The Keeper

The **Keeper** is the user-facing client over the pillars:

- a **per-device daemon** (`softfig-keeperd`) that owns all writes to the
  local garden, runs the filesystem watcher, and serves the FUSE mount;
- an **MCP server** (`softfig-mcp`) so any local Claude session can *propose*
  garden writes through one well-defined interface — reads stay native
  filesystem ops; Vault operations (reveals, key rotation, trust changes) are
  deliberately **never** exposed to the model;
- a **GUI and TUI** (planned) with parity for headless boxes;
- **cross-device sync** (planned): one garden per device, daemons meshing
  over a WireGuard LAN to mirror peer gardens read-only. Single owner per
  garden — no multi-master merging.

## Status

Built and tested (`cargo test --workspace` green, 99 tests):

- **M1a–M1d** — Vault (crypto + key lifecycle), VCS (content-addressed
  ciphertext store + signed commits + SQLite metadata), the headless daemon,
  the MCP bridge, and the source-agnostic watcher pipeline.
- **M2a–M2c** — the FUSE plaintext-view; **Layer B** selective secrets at two
  granularities: whole-file seals (glob-matched) and inline
  `<vault id="…">…</vault>` regions; the `softfig reveal` flow with per-region
  `--id` reveals; reveal/seal audit intents.
- **M-onboard** — `softfig onboard`, a first-run wizard that scaffolds a fresh
  garden from an embedded skeleton, inits the Vault, and writes a
  *born-in-FUSE* genesis commit (no plaintext ever touches the garden root).

Not started:

- **M3** — GUI (Iced, tentative) + TUI (ratatui) + the full MCP action surface.
- **M4** — the templating + symlink-deployment pillars (the bombadil replacement).
- **M5** — cross-device sync, pairing, the trust matrix, peer-assisted unlock.
- **M7** — AUR packaging + post-install automation.

> The design specs are the source of truth for *intent*; they live in the
> garden, not this repo — see [Design](#design-where-the-thinking-lives).

## How the encryption works

Two layers, two threat models:

- **Layer A — whole-garden encryption at rest.** Every blob in
  `.softfig/objects/` is ciphertext. Decryption happens at read time inside
  the daemon; consumers see plaintext only through the FUSE mount. Defends
  against a stolen disk, a stolen backup, a compromised replica host.
- **Layer B — selective secrets inside the plaintext view.** Sealed files and
  inline `<vault>` regions stay encrypted *past* Layer A's decryption. The
  FUSE mount shows `[sealed:<path>]` or `<vault id="x">[encrypted]</vault>`
  placeholders. Reveal is user-initiated only — Claude is never in the loop.
  Defends against prompt injection and accidental AI/app exposure.

Primitives:

| Concern | Choice |
|---|---|
| AEAD | XChaCha20-Poly1305 |
| Hashing (object/tree/commit addresses) | BLAKE3 |
| Password KDF | Argon2id (OWASP 2023: `m=64 MiB, t=3, p=4`) |
| Subkey derivation | HKDF-SHA-256 |
| Commit signing | Ed25519 (per-device identity key) |
| Recovery phrase | BIP39, 12 words, shown once at setup |
| Canonicalization | RFC 8785 JCS (`serde_jcs`) for everything hashed/signed |

Blobs use **master-keyed convergent encryption** so the VCS can
content-address ciphertext and dedup: identical plaintext under the same
master key produces identical ciphertext (and hash), yet the bytes are
indistinguishable without the key.

## Repository layout

A Cargo workspace (Rust 2024 edition, ≥ 1.85) of nine crates:

```
crates/
├── softfig-vault/     crypto + key lifecycle (init, unlock, encrypt, sign, rotate, recover)
├── softfig-store/     ciphertext object dir + SQLite metadata schema
├── softfig-core/      VCS: garden walker, trees, signed commits, log, fsck
├── softfig-ipc/       JSON-Lines protocol over a Unix socket
├── softfig-keeperd/   the daemon: watcher, FUSE mount, Layer B hooks, IPC handlers
├── softfig-mcp/       stateless stdio MCP bridge for Claude sessions
├── softfig-cli/       the `softfig` binary
├── softfig-fuse/      FUSE plaintext-view of the encrypted store
└── softfig-onboard/   frontend-agnostic scaffold core (embedded skeleton + born-in-FUSE)

templates/default-garden/   the embedded skeleton, baked in via include_dir!
scripts/onboard-device.sh    build + install helper
docs/onboard-laptop.md       manual onboarding runbook
packaging/systemd/           drafted softfig-keeperd user unit
```

The deeper architecture (on-disk layout, the IPC verb set, the watcher's
classifier rules) is documented in [`CLAUDE.md`](./CLAUDE.md).

## Getting started

**Prerequisites:** a Rust toolchain (≥ 1.85), `fuse3`, and `~/.local/bin` on
your `PATH`.

```bash
# build + test
cargo build --workspace
cargo test  --workspace          # ~3s — the suite uses minimum Argon2 cost
cargo clippy --workspace --all-targets -- -D warnings

# install the three binaries (or run ./scripts/onboard-device.sh)
cargo build --release
install -m0755 target/release/{softfig,softfig-keeperd,softfig-mcp} ~/.local/bin/

# scaffold a fresh, encrypted, version-controlled garden for this machine
softfig onboard                  # interactive: prompts a passphrase, prints a recovery phrase ONCE

# run it
softfig daemon start             # comes up LOCKED
softfig daemon unlock            # once per boot — mounts the FUSE plaintext view
```

`softfig onboard` produces **one standalone garden that documents the machine
it runs on** — cloning this repo to a new device moves the *program* (the
schema), never another device's *content*. The full path is in
[`docs/onboard-laptop.md`](./docs/onboard-laptop.md).

### CLI surface

```text
softfig onboard [--garden-root P] [--state-root P] [--machine NAME] [--customize] [--yes]
softfig vault   init | status | rotate-key | recover
softfig init                                  # genesis commit over an existing vault
softfig commit --intent <name> -m <msg> [-f <path>]... [--kv k=v]...
softfig log [--limit N]   |   show [<hex>]   |   fsck
softfig daemon start | stop | status | unlock
softfig reveal <path> [--id <region-id>]...   # plaintext to a 0600 temp file; never to stdout
softfig vault   seal | unseal | list-sealed
softfig migrate [prepare | finalize]          # convert a legacy non-FUSE garden
```

`commit`/`log`/`show`/`fsck` auto-detect a running daemon and route through it
(no per-command passphrase prompt), falling back to direct mode only when the
socket is absent.

## Design — where the thinking lives

This repo is the *implementation*. The *design* — the vision, the per-pillar
spec playgrounds, and the dated decision log — lives in the garden it's a
prototype for, alongside the conventions that shaped the schema. Each
milestone above has a corresponding `decision-softfig-*.md` recording the
locked design picks and as-built deltas. The specs are deliberately allowed to
be incomplete and to contradict each other; they are thinking surfaces, not
contracts.

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/).
