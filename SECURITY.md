# Security policy

> **Not audited, pre-1.0 — a design in progress.** soft-fig has not had an
> independent security review. The cryptography is designed carefully and
> tested, but "carefully designed by one maintainer" is not "audited". Do not
> use it for anything you cannot afford to lose.

soft-fig is a single-maintainer, pre-1.0 project. It keeps a machine's garden
(configuration, decisions, history), encrypts secrets at rest, syncs a
ciphertext replica to other devices, and can deploy files into live dotfiles. A
defect in any of those paths can expose data or the integrity of the machine, so
reports are welcome and taken seriously.

## Reporting a vulnerability

**Email: [unkownvee@protonmail.com](mailto:unkownvee@protonmail.com)**

Please report privately to that address. Do **not** open a public issue, a pull
request, or a discussion for a suspected vulnerability — public disclosure
before a fix exists takes away the only chance to ship one.

There is no PGP key, no `security@` alias and no ticket tracker. If you need an
encrypted channel, say so in your first message and one will be arranged before
you send details.

A useful report contains the version or commit, the platform, what you did, what
you expected, what happened, and — if you have one — a minimal reproduction. A
theory with a clear reasoning trail is still worth sending.

## Supported versions

**Latest release only.**

soft-fig is pre-1.0 and has no releases yet; every install today is built from
source at a commit. Once releases exist, fixes land on the latest one.

- No backports to older versions.
- No security branches or long-term-support lines.
- If you run a modified build, verify the fix is present in your tree.

## What to expect

One maintainer, best effort. There is **no SLA and no bug bounty**.

- **Acknowledgement:** within about 7 days, usually sooner.
- **Then:** triage, a fix, and coordinated disclosure. The advisory text is
  shared with the reporter before publication, and reporters are credited unless
  they would rather not be.
- **Timelines are honest, not promised.** A deep crypto or sync defect in a
  single-maintainer project can take longer than a week to fix. If a report is
  going to sit, the reporter is told rather than left waiting.

If a report has its own deadline (for example a downstream project is affected),
say so up front and one will be agreed.

## Scope

The parts below are in scope, each with the short version of what an attacker
gains.

### The privileged daemon (`softfig-keeperd`)

`keeperd` runs as a user unit, holds the unlocked vault session in memory, and
serves the garden's plaintext through a FUSE view plus a local IPC socket. An
attacker who reaches that session or that socket gets what an unlocked garden
shows: the machine's configuration map and every unsealed file. The socket is
believed to be tightly permissioned; that belief has **not** been independently
audited.

### The vault and its key material (Layer B)

The vault is the encryption-at-rest store: whole-file Layer A, selected-path
Layer B, and inline `<vault>` regions. What is worth attacking is not the
ciphertext but the key material — the master key and its wrappings — and the
**relock token**, which exists so an autonomous work loop can survive a daemon
cycle. The relock token is a deliberate, documented weakening: it is a
credential that lets a running loop unlock without a human re-entering the
passphrase, so anyone who can read it while it is live can unlock the way the
loop does. Its lifetime is bounded — a `vault rewrap` invalidates every
outstanding token.

### The sync and replication protocol

Pairing (a SAS-confirmed Noise handshake) and the replica push. Peers verify and
store ciphertext but cannot decrypt it, and transport is end-to-end encrypted. An
attacker who breaks pairing can impersonate a peer at the transport layer; one
who breaks the trust ring can get a device to accept a chain it should reject.
soft-fig hides contents, not the fact that two devices are talking.

### `deploy` writing into live dotfiles

`softfig deploy` materializes a declarative source→target table onto the real
filesystem, symlinking through a persistent plaintext deploy cache or writing a
stamped copy. A defect here can overwrite or expose real files in a home
directory — including files that are not soft-fig's. The cache is plaintext by
design, so it is a target: an attacker who can read it gets the deployed content
without unlocking the garden.

### Packs that execute code

> Designed, not shipped: the pack subsystem is a design in this project's specs,
> not yet part of this tree.

The intended recovery-pack design runs commands as the user, often as root, on a
machine whose owner is already in trouble. That is the worst possible consent
environment, so unsigned packs must not run, destructive acts must be consented
individually, and an `applies-to` mismatch must be a refusal rather than a
warning. A weakness that lets a pack run unsigned, or apply to the wrong machine,
is a full compromise of the box.

## Out of scope

- **A compromised account or machine that already holds the passphrase.** If the
  attacker is already the owner, encryption at rest is not the boundary it
  protects.
- **Physical access to an unlocked device, or a human at an unlocked screen.**
  soft-fig is not a screen lock.
- **A compromised running machine while the garden is unlocked**, including
  another process with the owner's privileges reading the FUSE plaintext view.
- **Multi-user separation.** There is one owner per garden; shared subtrees
  assume mutual trust. Little is promised between intentionally sharing peers.
- **Anonymity.** soft-fig does not hide metadata about who syncs with whom.
- **Vault loss from a forgotten passphrase with no escrow copy.** Recovery is the
  passphrase *and* the key file; no server holds a copy. `vault status` reports
  the declared recovery shape and any divergence from it.
- **Prompt injection through garden content.** Garden content is data. An agent
  that reads a malicious document and chooses to act on it is misbehaving — but
  report it if a softfig verb makes that conversion possible.

## What this project does not claim

No "military-grade" or "unbreakable" cryptography, no audit, no certification
and no security guarantee. Single maintainer, pre-1.0, best effort.
