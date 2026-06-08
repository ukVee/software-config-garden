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
