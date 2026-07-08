# systemd integration

Drafts of the user units soft-fig will install. AUR packaging is a later
milestone (M7); on this device, copy these files into
`~/dotfiles/src/system/systemd/user/` so toml-bombadil renders them
into `~/.config/systemd/user/`.

## softfig-keeperd.service

The keeper daemon. Boots in **Locked** state — run
`softfig daemon unlock` once per session before any verb that needs the
vault.

```
systemctl --user enable --now softfig-keeperd
softfig daemon unlock
```

The default `ExecStart` assumes `~/.local/bin/softfig-keeperd` and
`~/soft-fig_garden`. Override `--garden` if your garden lives elsewhere.

### Redeploying — copy the unit too, not just the binary

growlightd supervision (keeperd starting the autonomous fleet on unlock) is
gated on `Environment=SOFTFIG_SUPERVISE_GROWLIGHTD=1`, which **only this unit
file exports** — a deliberate guard so a test-spawned keeperd
(`CARGO_BIN_EXE`) never shells `systemctl` against the host's real fleet
(incident-20260706 Bug A). The consequence: a **binary-only redeploy** — the
routine `cargo build && cp target/…/softfig-keeperd ~/.local/bin/` with no
unit-file refresh — leaves the new keeperd **without** the env var, so it
**silently never starts growlightd** and autonomous growlight work just stops
with nothing erroring.

keeperd now warns loudly about this in its journal (task 041): if the in-garden
gate is armed (`config/growlight.toml fleet_enabled = true`) but
`SOFTFIG_SUPERVISE_GROWLIGHTD` is unset, unlock logs a `WARNING — … this
keeperd will NOT start softfig-growlightd.service`. Watch for it with
`journalctl --user -u softfig-keeperd`. The fix is to always redeploy the
**unit + binary** together:

```
cargo build --release --workspace                  # 1. rebuild
cp target/release/softfig* ~/.local/bin/           #    install the binaries
cp packaging/systemd/*.service \
   ~/dotfiles/src/system/systemd/user/ && \
   toml-bombadil link                              # 2. refresh the units (bombadil-rendered)
systemctl --user daemon-reload                     # 3. reload the unit definitions
softfig daemon cycle                               # 4. relock-resume onto the new binaries
```

Step 2 is the one a binary-only redeploy skips. `softfig daemon cycle`
(step 4) bounces keeperd and resumes the unlocked session without re-prompting
for the passphrase, so the new keeperd inherits `SOFTFIG_SUPERVISE_GROWLIGHTD=1`
from the refreshed unit and re-arms growlightd on resume.

### No sandboxing — on purpose

The unit carries **no** `NoNewPrivileges=`, `ProtectSystem=`, `PrivateTmp=`,
etc. The daemon projects a FUSE mount into your login session via the
setuid-root `fusermount3` helper, and those knobs break it:

- `NoNewPrivileges=true` defeats the setuid bit → `fusermount3` can't mount
  → `softfig daemon unlock` fails with `Operation not permitted (os
  error 1)` (EPERM).
- Namespacing options (`ProtectSystem=`, `PrivateTmp=`, …) give the unit its
  own mount namespace, so the FUSE mount stays trapped inside it and never
  becomes visible to your shell.

Don't add them back without `MountFlags=shared` and without
`NoNewPrivileges`. See `docs/onboard-laptop.md` (Troubleshooting).
