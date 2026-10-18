# AUR — `soft-fig` (source) + `soft-fig-bin`

The first channel: two AUR packages that make V1 gate #1 (`pacman -S soft-fig`
works cold on a fresh box) literally true. Channels package what the release
pipeline produces; they never fork behavior (`meta/spec-release.md` → Channels):
each PKGBUILD **sets paths** (binaries to `/usr/bin`, units to
`/usr/lib/systemd/user/`, the desktop entry to `/usr/share/applications/`) and
**declares dependencies** (`fuse3`, `systemd`, `foot`), and never patches a
default — the garden location, config parsing, and feature set are exactly the
shipped binaries.

| Package | Builds from | `check()` | arch |
|---|---|---|---|
| `soft-fig` | the tagged source tarball (`git` tag archive) | the full test suite (`cargo test --workspace`, reduced-Argon2 as CI does) | `x86_64` |
| `soft-fig-bin` | the tier-1 program tarball from GitHub Releases | verifies the `SHA256SUMS` minisign signature, then the tarball's `SHA256SUMS` entry | `x86_64` |

Both install the **installed set** — the five binaries
(`softfig`, `softfig-keeperd`, `softfig-growlightd`, `softfig-mcp`,
`softfig-tui`), the two systemd **user** units, the `softfig-tui` desktop
entry, and the AGPL license text. `growlight-gui` is deliberately absent
(opt-in, never installed or published — see `meta/spec-release.md` → Binary
set). `arch` is `x86_64` for both: tier-1 is the only *tested* target.
`aarch64` (tier 2) is built but untested, so it is not offered here — add it to
`soft-fig`'s `arch` once it is verified on hardware (a channel must not imply a
tier it does not have).

## Verifying a release before you install

Release artifacts are signed two ways (see `meta/spec-release.md` → "Signing
and the trust root"):

- **Build provenance (sigstore).** Every artifact is attested in CI; verify
  before executing, using tooling independent of the artifact itself:

  ```
  gh attestation verify <tarball> --repo ukVee/software-config-garden
  ```

- **A signed checksum manifest** for consumers without `gh`. `SHA256SUMS` is
  signed with the maintainer's minisign key, and the public key is published
  next to it as `minisign.pub` on the release page:

  ```
  minisign -Vm SHA256SUMS -p minisign.pub
  ```

`soft-fig-bin`'s `check()` runs that same `minisign` verification against its
own checksum-pinned copy of the public key before installing anything.

## Install order (fresh box)

Scaffold the garden **first**, then start the daemon against it, then unlock.
The keeperd unit points `--garden %h/soft-fig_garden`, so enabling it before
the garden exists boots the daemon against a path it cannot use:

```
softfig onboard                                  # scaffold a garden (interactive, needs a TTY)
systemctl --user enable --now softfig-keeperd   # the keeper daemon (boots Locked)
softfig daemon unlock                            # once per session
```

## Maintenance

> **STATUS: PROPOSED — pending the owner's H9 answer.** This statement records
> the recommended default from `meta/spec-release.md` → Open questions → "AUR
> owner and update latency"; it is **not** the owner's decision until H9 is
> answered. Fill in the `# Maintainer:` line and this section from that answer
> before uploading.

- **Maintainer:** the owner as **sole maintainer** (recommended; see below).
- **Update-latency promise:** within **7 days of a tagged release**.

The three options weighed (owner's call, H9):

- **(a) Sole owner** — zero coordination, a single point of failure, but honest:
  an AUR package with an absentee co-maintainer is worse than one with a slow
  owner. *Recommended to start.*
- **(b) A second maintainer** — spreads load but shares the owner's private
  account surface; premature before H5 (CLA/legal) is settled.
- **(c) An automation bot as co-maintainer** — updates fast, but is its own
  supply-chain surface.

**Flagging a stale package:** open an issue at
https://github.com/ukVee/software-config-garden (title the issue with the
package name), or comment on the AUR page. If a release has shipped and the AUR
package has not updated within the promised latency window, that is a bug in
this statement's promise — flag it the same way.

## What the loop did, and what the owner must do

The release-pipeline slices wrote these PKGBUILDs + this statement and
committed them on `feat/release-pipeline` (unmerged). The loop never
pushes/tags/publishes. Before `soft-fig`/`soft-fig-bin` go live, the owner:

1. Answers **H9** and finalizes the `# Maintainer:` line + this section.
2. **Creates the minisign signing keypair** — commit the public key as
   `packaging/signing/minisign.pub`, store the secret key as the
   `MINISIGN_SECRET_KEY` repository secret. See `packaging/signing/README.md`.
3. Cuts the tag `v1.0.0-alpha.1` and lets the release workflow build the
   artifacts (the tarball, `SHA256SUMS`, `SHA256SUMS.minisig` and
   `minisign.pub` that this `-bin` package downloads).
4. Fills the real `sha256sums=` into both PKGBUILDs — they are **all-zero
   placeholders that fail closed** until the tag exists — and regenerates
   `.SRCINFO` (`makepkg --printsrcinfo > .SRCINFO`).
5. Uploads each package directory to the AUR as its own git repo.

`soft-fig` and `soft-fig-bin` `conflicts`/`provides` each other (identical
installed file set); install one or the other, never both.
