# systemd integration

The two systemd **user** units soft-fig runs under. `scripts/onboard-device.sh`
offers to install and enable `softfig-keeperd.service`; install
`softfig-growlightd.service` alongside it if you plan to run the growlight fleet.
Both go in `~/.config/systemd/user/` (or wherever your dotfile manager renders
user units).

```
cp packaging/systemd/softfig-keeperd.service    ~/.config/systemd/user/
cp packaging/systemd/softfig-growlightd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now softfig-keeperd
softfig daemon unlock
```

## softfig-keeperd.service

The keeper daemon. Boots **Locked** — run `softfig daemon unlock` once per
session before any verb that needs the vault.

The default `ExecStart` assumes `~/.local/bin/softfig-keeperd` and
`~/soft-fig_garden`. Override `--garden` if your garden lives elsewhere.

## softfig-growlightd.service

The growlight fleet supervisor. It has **no `[Install]` section** and is never
enabled: keeperd starts it after an unlock when `config/growlight.toml` sets
`fleet_enabled = true`, and stops it on lock. Installing the file is enough.

## Redeploying — copy the unit too, not just the binary

keeperd only supervises growlightd when its environment sets
`SOFTFIG_SUPERVISE_GROWLIGHTD=1`, which **only the shipped keeperd unit
exports** — a guard so a test-spawned keeperd never drives the host's real
fleet. A binary-only redeploy with a stale unit leaves the new keeperd without
the variable, so it **silently never starts growlightd**. keeperd logs a
`WARNING — … this keeperd will NOT start softfig-growlightd.service` on unlock
when the fleet is armed but the variable is missing; check with
`journalctl --user -u softfig-keeperd`.

Always redeploy **unit + binary** together:

```
cargo build --release --workspace                                    # 1. rebuild
install -m 0755 target/release/{softfig,softfig-keeperd,softfig-mcp,softfig-tui,softfig-growlightd} \
  ~/.local/bin/                                                      #    install the binaries
cp packaging/systemd/*.service ~/.config/systemd/user/               # 2. refresh the units
systemctl --user daemon-reload                                       # 3. reload unit definitions
softfig daemon cycle                                                 # 4. resume onto the new binaries
```

`softfig daemon cycle` bounces keeperd and resumes the unlocked session without
re-prompting for the passphrase, so the new keeperd picks up the refreshed unit
and re-arms growlightd on resume. After upgrading `softfig-mcp`, restart any
open Claude Code session — it keeps the old MCP server process until then.

## No sandboxing — on purpose

Neither unit carries `NoNewPrivileges=`, `ProtectSystem=`, `PrivateTmp=`, etc.
keeperd projects a FUSE mount into your login session via the setuid-root
`fusermount3` helper, and growlightd must see that mount. Those knobs break it:

- `NoNewPrivileges=true` defeats the setuid bit → `fusermount3` can't mount
  → `softfig daemon unlock` fails with `Operation not permitted (os
  error 1)` (EPERM).
- Namespacing options (`ProtectSystem=`, `PrivateTmp=`, …) give the unit its
  own mount namespace, so the FUSE mount stays trapped inside it and never
  becomes visible to your shell or to growlightd.

Don't add them back without `MountFlags=shared` and without
`NoNewPrivileges`. See `docs/onboard-laptop.md` (Troubleshooting).
