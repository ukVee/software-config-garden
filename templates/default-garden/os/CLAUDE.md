# os/

The OS layer: kernel, boot, init, distro-specific bits below systemd. Subfolders as needed (e.g. `os/boot/`).

## How to behave here

- Kernel params, bootloader config, early-boot behavior → here (commentary; the real config is the source of truth).
- systemd *services* belong in `services/`, not here. This dir is the layer beneath.

## Cross-refs

- `services/` — systemd units and daemons.
- `storage/` — filesystems and mounts the boot process depends on.
- `hardware/` — firmware / the physical machine.
