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
