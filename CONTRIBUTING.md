# Contributing to soft-fig

soft-fig keeps the files that describe a machine — configuration, decisions,
installed packages, what broke and how it was fixed — as one navigable,
versioned, encrypted-at-rest tree, and gives a human or an LLM typed tools to
work on it. It is a Rust workspace: a `softfig` CLI, a `softfig-keeperd` daemon,
a FUSE view, a `softfig-tui`, an MCP bridge for agent sessions, an onboard
scaffolder, a deploy spine, a sync/replication crate, and the Growlight work
loop. The full narrative documentation lives at
<https://ukvee.github.io/software-config-docs>.

The project is licensed **AGPL-3.0-or-later** (see `LICENSE`). Contributions are
accepted under the terms in `CLA.md`.

## Before you start

- **Open an issue first for anything larger than a bug fix.** The architecture is
  opinionated on purpose (no privilege escalation to mount, typed MCP writes, the
  curated-baton work loop); a short discussion before a large PR saves a rewrite.
- **Security reports do not go in issues.** See `SECURITY.md`.
- **Small, focused fixes are welcome without ceremony** — a typo, a broken link, a
  one-line bug fix.
- The project is an early alpha and single-maintainer. Review is best effort,
  not a service.

## Building

Rust 1.88 or newer is required (`rust-version` in `Cargo.toml`). Two system
packages are needed at build time: `protoc` (`softfig-net` compiles protobuf
definitions) and the libfuse3 development headers (`softfig-fuse`) — e.g.
`protobuf-compiler libfuse3-dev` on Debian/Ubuntu, `protobuf fuse3` on Arch.

```sh
cargo build --workspace
```

## The local gate

Run these three before opening a pull request. CI runs the same set, and a PR
that fails any of them will not be merged.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The tree is not yet rustfmt-clean, so `cargo fmt --check` is not part of the
gate. Run `rustfmt` on the files you touch, but don't reformat files you didn't
otherwise change (see *No unrelated formatting sweeps* below).

If you touched crypto, sync, or anything with a filesystem side effect, say in
the PR what you ran beyond the gate — a test that proves the failure path is
worth more than a test that proves the happy one.

## What a good change looks like

- **One logical change per commit and per pull request.** A refactor plus a
  feature in one diff cannot be reviewed or reverted independently.
- **The commit message says *why*.** What the code now does is visible in the
  diff; the reason it should is not. The first line is a short summary in the
  imperative mood ("fix: …", "docs: …", "feat: …"); the body explains the
  problem and the shape of the fix.
- **Tests come with the behaviour.** A bug fix gets a test that fails before and
  passes after.
- **Match the surrounding code.** Comments, naming, module layout and error
  handling in this repo are deliberate; a diff that imports a different idiom
  reads as a second author's voice.
- **Do not force-push `main`.** Do not force-push a branch with an open PR unless
  the reviewer asked for a rebase — it destroys the review history.
- **No unrelated formatting sweeps.** They bury the real change and inflate the
  gate's surface.

## Review and merge

**The maintainer reviews and merges every change.** There is no self-merge, no
auto-merge, and no delegated maintainership yet. Expect comments, and expect a
review that asks for the reason behind a change rather than its mechanics.

A PR is merged when it is correct, tested, documented where it changes user-
visible behaviour, and the three gate commands pass.

## Contributor License Agreement

Before a pull request can be merged, the contributor must agree to `CLA.md`.
The mechanism is one line in the PR description:

> I have read the CLA and I agree to it.

The CLA grants the maintainer a perpetual licence to the contribution,
**including the right to relicense**, and it does **not** assign copyright: the
contributor keeps it. It exists for one reason: without the relicensing right,
this project could never be dual-licensed or move to a future licence, because a
single outside contribution would permanently remove that option. It cannot be
retrofitted, so it applies from the first contribution onward.

## Code of conduct

Participation is governed by `CODE_OF_CONDUCT.md`. Report problems to
unkownvee@protonmail.com.

## Documentation and specs

- User-facing docs: <https://ukvee.github.io/software-config-docs>.
- In-tree notes: `CLAUDE.md` (workspace layout and per-crate state) and `docs/`.
- Design intent for a pillar (vault, sync, deploy, Growlight) lives in the
  project's garden specs. If a change alters a design decision, say so in the PR
  rather than only in the code.

## Good first contributions

Documentation drift (docs that no longer match the code), missing tests around an
error path, and small CLI ergonomics are genuinely useful and are the easiest
places to start a conversation with the maintainer.
