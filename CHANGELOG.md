# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are grouped by what a user of the tool can observe, and each points at the
decision record or crate that owns it, rather than at every internal change.

## [Unreleased]

### Added

- `claude:<alias|id>[1m] [effort=<low|medium|high|xhigh|max>]` grammar across
  `softfig growlight start --model`, the interactive picker, `> Model:` lines
  and `[[fleet]] model` entries, so the claude backend's model and effort are
  choosable per session, per item and per fleet member — matching Claude Code's
  own `--model` / `--effort` flags (`claude-model-select`; CLI slices 001–002,
  fleet slice 003). A claude member whose model Claude Code refuses
  (`model_not_found` / 404) parks the unit with an alert carrying the reason;
  there is no crash loop and no backoff retry.

## [1.0.0-alpha.1] - 2026-10-17

The first public alpha: everything that exists so far, released as source. Built
and used daily on one device; expect rough edges. Linux + systemd + FUSE only, and
install is build-from-source (no prebuilt packages yet).

### Added

- **The garden as one object** — an encrypted-at-rest, version-controlled tree of
  small semantically-named directories that a human or an agent can navigate
  (crates `softfig-store`, `softfig-vcs`).
- **The vault** — whole-garden encryption at rest (Layer A), per-file sealed paths
  (Layer B), and inline `<vault id="…">…</vault>` regions with their own subkeys,
  plus `softfig vault {seal,unseal,list-sealed}` and `softfig reveal [--id]`
  (crate `softfig-vault`; `decision-softfig-vault-impl`,
  `decision-softfig-layer-b-impl`, `decision-softfig-m2c-impl`).
- **Recovery as a declared policy** — `vault status` reports the declared recovery
  shape next to the wrappings actually on disk and any divergence, with
  `vault escrow export|verify`, `vault recovery add|drop` and a verified copy
  required before a door can be removed (`decision-vault-recovery-policy`).
- **`softfig-keeperd`** — a per-device user daemon holding the unlocked session and
  serving the garden through IPC and a FUSE plaintext view that exists only while
  unlocked (crates `softfig-keeperd`, `softfig-fuse`).
- **The `softfig` CLI** — vault, repo, daemon and migrate subcommands, with a
  daemon fast path for commit/log/show/fsck (crate `softfig-cli`).
- **`softfig-tui`** — a terminal frontend with browse/history/actions, an in-app
  unlock, vault and peers tabs, deploy and backup views, and a read-only Growlight
  view (crate `softfig-tui`; `decision-softfig-m3b-impl`,
  `decision-softfig-m3b-vault-tui-impl`, `decision-tui-file-editor`,
  `decision-tui-text-selection`).
- **`softfig-mcp`** — a thin stdio bridge exposing the daemon's typed write verbs
  to an agent session. Vault operations are never exposed to the model
  (crate `softfig-mcp`; `decision-softfig-m3a-impl`).
- **`softfig onboard`** — a first-run wizard that scaffolds a fresh garden born in
  the FUSE layout, so no plaintext ever touches the garden root
  (crate `softfig-onboard`; `decision-softfig-onboard-impl`).
- **`softfig deploy`** — a declarative `config/deploy.toml` source→target table
  materialized as symlinks into a persistent plaintext deploy cache, or as stamped
  copies (crate `softfig-deploy`; `decision-softfig-m4-impl`).
- **Device pairing and sync transport** — mDNS discovery, a SAS-confirmed
  authentication handshake over an application-level Noise tunnel, an Ed25519
  attestation ring, and a blind relay for off-LAN peers (crate `softfig-net`;
  `decision-softfig-m5a-impl`).
- **Zero-knowledge replica** — the owner pushes signed device-chain ciphertext to
  granted backup hosts, which verify and store it and cannot decrypt it; the
  transfer is fast-forward-only and two-sided-consented
  (`decision-softfig-m5b-impl`).
- **Shared subtrees** — union-mount visibility, shared-chain keying,
  recipient-chosen placement of incoming content, and write-turn coordination
  between peers (`decision-shared-subtree-sync`,
  `decision-softfig-shared-subtrees-impl`,
  `decision-shared-subtree-recipient-placement`, `decision-m5e-shared-pull-intent`).
- **Growlight** — an autonomous work loop carried across fresh agent sessions by a
  curated baton, over a backlog of milestones and slices, driven by `growlightd`
  (crate `softfig-growlightd`) as a supervised fleet, a single-agent run being a
  fleet-of-one (`decision-growlight-loop`).
- **`softfig growlight init|start`** — an idempotent pillar scaffolder and a
  launcher that generates the loop runtime and starts an agent session on the
  `claude` or `opencode` backend (`decision-growlight-loop`,
  `decision-agents-multi-backend-provider`).
- **The growlight backlog queue** — a daemon-parsed queue with per-item state,
  slices, leases and scheduling, plus a reports surface for findings raised during
  a loop (`decision-growlight-queue-redesign`, `decision-growlight-reports`).
- **Per-garden configuration** — `config/keeper.toml` and `config/peers.toml` live
  inside the encrypted garden instead of plaintext beside the vault
  (`decision-softfig-config-in-garden`).

### Changed

- **Config in the garden** — post-unlock policy and peer membership are read from
  the garden at unlock, with the plaintext pointer kept for bootstrap only
  (`decision-softfig-config-in-garden`).
- **Deploy materialization** — targets symlink to a persistent plaintext cache
  (or copy with a stamp) rather than to ephemeral FUSE sources, so they survive a
  lock (`decision-softfig-m4-impl`).
- **Agent backends** — the loop's launch is a backend seam, so a session can run on
  Claude Code or on an opencode-driven provider without changing the protocol
  (`decision-agents-multi-backend-provider`).

### Fixed

- **`manual_edit` is a valid commit intent** — the classifier could produce an
  intent the closed-enum validator silently rejected (crate `softfig-vcs`).
- **Empty commits are impossible** — a write whose tree equals its parent's is
  skipped instead of recorded, with an explicit opt-in for audit-only intents
  (crate `softfig-vcs`).
- **Pairing to a device that already holds a peer** — the inbound responder role is
  read per connection from the peer's first handshake message instead of from the
  local ring's emptiness, so a device with one peer can still be paired to
  (`decision-softfig-m5a-impl`).
- **A shared-chain push refusal is visible to the pusher** — a non-member push is
  answered with a signed, reasoned rejection rather than a silent close
  (`decision-m5e-sync-conflict-intent`).

### Security

- **Encryption at rest in three shapes** — whole garden, per-file sealed globs, and
  inline regions, all with HKDF-separated subkeys from one master key
  (`decision-vault-pillar`, `decision-softfig-m2c-impl`).
- **The relock token is a documented weakening** — it exists so an autonomous loop
  can survive a daemon restart, is opt-in and off by default, is time-boxed and
  single-use, and is invalidated by `vault rewrap`
  (`decision-softfig-relock-token`).
- **Recovery can be passphrase-only, deliberately** — the weaker recovery door may
  be removed, but only against a verified escrow copy of what remains, and
  `vault status` never lets a garden fall silent about its shape
  (`decision-vault-recovery-policy`).
- **The agent surface is typed** — garden content is data, never instructions, and
  the write verbs are narrow and convention-stamping with vault operations
  withheld from the model entirely (`decision-garden-read-channel-read-only-tools`).
- **Alpha and unaudited** — see `SECURITY.md`. No third party has reviewed this
  cryptography, and the project is maintained by one person on a best-effort
  basis.

[Unreleased]: https://github.com/ukVee/software-config-garden/compare/v1.0.0-alpha.1...HEAD
[1.0.0-alpha.1]: https://github.com/ukVee/software-config-garden/releases/tag/v1.0.0-alpha.1
