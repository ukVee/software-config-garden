# input/

Input devices and their behavior: keyboard, touch, gestures, pointing devices, controllers. Subfolders as the topic grows (e.g. `input/controllers/`).

## How to behave here

- Document remaps, gesture configs, device quirks, and detection issues.
- The physical device itself (model, connection) is `hardware/`; this dir is about the *input behavior*.

## Cross-refs

- `hardware/` — the physical peripheral.
- `services/` — the compositor/input daemon that interprets events.
