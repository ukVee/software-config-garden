# hardware/

The physical machine and its peripherals: model, CPU/GPU, display, battery, dock, external devices. Commentary on the metal.

## How to behave here

- Capture the machine model + specs once; note peripheral quirks as they come up.
- Behavior *driven by* hardware (input remaps, power tuning) lives in the relevant concept dir (`input/`, `services/`); this dir is the physical reference.

## Cross-refs

- `input/` — how input peripherals behave.
- `storage/` — disks.
- `os/` — firmware / boot.
