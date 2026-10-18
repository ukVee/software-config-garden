# remote runner — requester usage (`softfig run`)

> Last reviewed: 2026-10-18

How to offload a build or test to a paired runner (`softfig-runnerd`) from the
requester side. The runner-side install is in
[`remote-runner.md`](remote-runner.md); this page is the requester surface
(spec `remote-runner` §5.1, §9).

**Explicit, not transparent.** You call `softfig run` yourself; nothing on the
PATH quietly sends `cargo test` elsewhere, so every gate line says where it
ran.

## The command

```
softfig run run [--on <peer|host:port>] [--profile <name>] [--fallback local|wait|fail]
            [--detach] [--fetch <glob>]... [-- <cmd...>]
softfig run ls
softfig run show <job> [--attestation]
softfig run logs <job> [-f]
softfig run attach <job>
softfig run cancel <job>
softfig run fetch <job> <path> [-o <dest>]
```

> **`run` is a subcommand group** (`softfig run run …`), because the same
> namespace holds the inspection verbs (`ls`/`show`/`logs`/`attach`/`cancel`/
> `fetch`). Spec §9 writes the single `run`; the shipped grammar is the double
> `run run` — see the spec's §9 "as built" note and report #065.

- `--on` — run on this runner: `host:port` (direct dial) or a peer
  name/fingerprint resolved through the ring.
- `--profile <name>` — a named profile under the matched `[[project]]`.
- `--fallback local|wait|fail` — override `[use] fallback` for this call.
- `--detach` — start the job, print its id, exit 0; resume with
  `softfig run attach <job>`. Remote-only: a detached job has no local fallback.
- `--fetch <glob>` — artifact glob to fetch after the job (parked — report #057).
- `-- <cmd…>` — an ad-hoc command instead of a profile
  (`softfig run run -- cargo test`).

## Exit code and fallback

- **Exit code.** `softfig run` exits with the job's own exit code. Runner-side
  failures (rejected, lost, source mismatch) exit **254** and print the reason.
- **Fallback (default `local`).**
  - **Triggers:** no runner reachable within `connect_timeout`; an invalid or
    revoked certificate; a reject for `disabled`, `draining`, `on-battery`,
    `busy-timeout`.
  - **Not a trigger:** a job that ran and failed — that is a real result, and
    its exit code passes through.
  - **`local`** runs the command in the repo and prints `ran LOCALLY: <reason>`;
    the result is `where: local` with no attestation.
  - **`wait`** retries until `wait_timeout`; **`fail`** exits 254 at once.

## Configuration — `config/runner.toml`

In-garden on the requester, committed to the device chain and read through
keeperd (so it is edited like any other garden file). Unknown keys are refused
(never a silent default).

```toml
version = 1

[use]
peers = ["sillyguy76"]   # eligible runners; least-loaded first, ties by list order
fallback = "local"       # local | wait | fail   (default: local)
wait_timeout = "20m"     # used only by fallback = "wait"
connect_timeout = "10s"

[[project]]
name = "softfig"
repo = "~/projects/software-config_garden/codebase"   # longest-path-prefix match
toolchain = "rust"
fetch = "cargo"

[project.profile.gate]
cmd = ["cargo", "test", "--workspace"]
time_max = "45m"

[project.profile.release]
cmd = ["cargo", "build", "--release", "--locked"]
cache = "fresh"
artifacts = ["target/release/softfig", "target/release/softfig-keeperd"]
```

- **`[use]`** — `peers` (the runner list), `fallback`, `wait_timeout`,
  `connect_timeout`.
- **`[[project]]`** — matched by the longest path prefix under `repo`. Keys:
  `name`, `repo`, `toolchain`, `fetch`, and a `profile` map.
- **Profile keys.** `cmd`, `env` (names + literal values only — the requester's
  environment is never forwarded wholesale), `time_max`, `cache`
  (`shared` | `fresh`, default `shared`), `network` (`none` | `egress`, default
  `none`), `artifacts` (globs), `submodules` (`refuse` | `ignore`, default
  `refuse`), `git_metadata` (carried through but inert in v1 — report #061).
- **Ad hoc.** `softfig run run -- <cmd>` with no profile uses the project's
  toolchain + fetch kind, shared cache, no artifacts.

## Job inspection

`ls` / `show` / `logs` / `attach` / `cancel` read the keeperd job table — an
in-memory, bounded (last 128) table holding a log ring per job, reset on a
daemon cycle. A log file is written only on request, defaulting to
`$XDG_RUNTIME_DIR`.

- `softfig run ls` — recent jobs.
- `softfig run show <job> [--attestation]` — one job's result (+ its signed
  attestation hash; `attestation: (none — local run)` for a local fallback).
- `softfig run logs <job> [-f]` — the sanitized log (follow live with `-f`).
- `softfig run attach <job>` — re-attach to a detached job and replay the tail.
- `softfig run cancel <job>` — cancel a running job.

Artifact fetch (`softfig run fetch`) is parked on report #057: the artifact
glob base is unresolved (builds write to `/cache/target`, not the repo tree).

## MCP verbs (agent surface)

| Verb | In | Out |
|---|---|---|
| `run_job` | `repo` (absolute path; required), `profile` or `cmd`, `wait_secs` | `{job_id, state, exit?, where: remote\|local, tail (last 60 lines), attestation_hash?}` |
| `job_log` | `job_id`, `from_seq?`, `max_bytes` | a windowed read (last N bytes, default 8192); never the whole log by default |
| `job_cancel` | `job_id` | final state |

`run_job` is **remote-only** — no local fallback in the MCP verb (an agent
should not be surprised into local execution; a runner-side failure is a clear
error naming the reason). It runs synchronously to completion, bounded by the
runner's `time_max` + `connect_timeout`; `wait_secs` is accepted for the §9
shape but does not time the run. `job_log.from_seq` (the live-follow cursor) is
ignored — live-follow is a later chunk.

## Sandboxing and security

The runner executes the job in its own transient systemd unit inside a
bwrap + Landlock + seccomp sandbox (`softfig-sandbox`). The run step has no
network and no secrets; repo code never runs during the fetch step. Logs are
untrusted bytes — the shared control-sequence stripper protects the requester's
terminal and the TUI later. See [`remote-runner.md`](remote-runner.md) for the
runner-side hardening and install.
