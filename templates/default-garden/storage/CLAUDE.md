# storage/

Filesystems, partitions, mounts, swap, and encryption-at-rest for this machine's disks. Commentary; the real config (`/etc/fstab`, crypttab, etc.) is the source of truth.

## How to behave here

- Document the partition layout, mount options, and any encryption setup.
- Disk *hardware* specifics (model, health) lean on `hardware/`.

## Cross-refs

- `hardware/` — the physical disks.
- `os/` — what the boot process mounts.
