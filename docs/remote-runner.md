# remote runner — install + operate

The runner is a paired peer running `softfig-runnerd` as a **system** service
under its own `softfig-runner` uid (spec `remote-runner` §3). It holds a
delegated runner key — an X25519 transport static + Ed25519 attest key, bound
to the device by a certificate the device identity signs — and an `accept.toml`
allowlist of requesters written through an admin socket that only the owner uid
may reach.

> **Status (slice 002):** the identity + install skeleton ships here. Job
> transport, sandboxing, and the wire frames land in slices 003–007, so
> `enable`/`grant`/`status` work today but no job will run yet.

## Install (the human's root step)

Run these on the runner device (`sillyguy76`), as root or with sudo. **Rollback
is last, fenced separately** — undo it only if the install misbehaves.

```sh
# 1. Build + install the binary (system-wide, so the unit can run it).
cargo build --release --workspace
install -Dm0755 target/release/softfig-runnerd /usr/local/bin/softfig-runnerd

# 2. Create the softfig-runner system user (no login shell).
install -Dm0644 packaging/sysusers.d/softfig-runner.conf /etc/sysusers.d/softfig-runner.conf
systemd-sysusers

# 3. Create the state root /var/lib/softfig-runner (0700, owned by the runner).
install -Dm0644 packaging/tmpfiles.d/softfig-runner.conf /etc/tmpfiles.d/softfig-runner.conf
systemd-tmpfiles --create

# 4. Install + enable the unit. Set --owner-uid to the laptop owner's uid first
#    (`id -u <owner>`); the shipped default is 1000.
install -Dm0644 packaging/systemd/softfig-runnerd.service /etc/systemd/system/softfig-runnerd.service
systemctl daemon-reload
systemctl enable --now softfig-runnerd

# 5. Issue the certificate + grant the tablet (needs the garden unlocked).
softfig runner enable
softfig runner grant <tablet-fingerprint-or-name>
```

**Rollback** — only if the install breaks something (e.g. the unit fails to
start and you want it gone):

```sh
systemctl disable --now softfig-runnerd
rm /etc/systemd/system/softfig-runnerd.service
rm /etc/sysusers.d/softfig-runner.conf
rm /etc/tmpfiles.d/softfig-runner.conf
systemd-sysusers  # re-reads; the account stays until you userdel it
userdel softfig-runner
rm -rf /var/lib/softfig-runner
```

## Operate

```
softfig runner status                     # certificate expiry + accepted requesters
softfig runner enable                     # generate keys + issue the certificate
softfig runner renew                      # re-issue (new serial + window)
softfig runner revoke-cert                # sign + store a revocation for the serial
softfig runner grant <peer>               # allow a ring peer (reads the ring)
softfig runner revoke <peer>              # remove + purge that peer
softfig runner apply                      # copy config/runner.toml [serve] -> serve.toml
softfig runner purge                      # clear mirrors + caches
softfig runner toolchain list             # toolchains [serve] declares
softfig runner toolchain add <spec>       # prints the root command (rustup as runner)
```

`enable`/`renew`/`revoke-cert` need the garden unlocked (keeperd signs with the
device identity). `apply` reads the garden's `config/runner.toml` `[serve]`
table through keeperd; add that table before applying:

```toml
# config/runner.toml (runner device)
[serve]
enabled = true
max_jobs = 1
cpu_weight = 20
nice = 10
io_class = "idle"
memory_max = "8G"
tasks_max = 4096
time_max = "60m"
scratch_max = "20G"
cache_max = "60G"
on_battery = "allow"
on_battery_caps = { cpu_weight = 10, memory_max = "4G", tasks_max = 2048, time_max = "20m" }
toolchains = ["rust"]
egress = ["index.crates.io", "static.crates.io", "crates.io", "github.com", "codeload.github.com"]
```

## Hardening (provisional)

`packaging/systemd/softfig-runnerd.service` carries a **provisional** hardening
set. The exact directive set is settled by slice 001's laptop probe (spec §15
"systemd directive set"), still pending — see the unit's header comment and the
milestone's slice 001 `## Deferred verification`.
