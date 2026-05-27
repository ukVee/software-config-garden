# services/network/

Networking on this machine: the network manager, DNS, VPN, ssh client config, firewall. Commentary only — the config sources live where they're managed; point at them.

## How to behave here

- One concern per file when it grows (e.g. `notes.md` for quirks, `refs.md` for the source-of-truth config paths).
- Per-SSID or per-connection notes can be freeform-semantic files when there are many.

## Cross-refs

- `services/` — the parent (other daemons).
- `hardware/` — the physical network adapter.
