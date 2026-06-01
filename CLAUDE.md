# software-config_garden

Implementation repo for **soft-fig** — the program that combines machine memory (the CLAUDE.md garden schema), templating, symlink deployment, integrated VCS, and the Keeper client into one tool. Distributed via AUR.

## Status

**M1a + M1b + M1c + M1d + M2a + M2b + M2c done (2026-05-05 → 2026-05-16); M-onboard done (2026-05-26); M3a done (2026-05-30); M3b done (2026-05-31).** This garden is self-hosting under signed VCS history with two encryption layers at three granularities: Layer A whole-garden ciphertext, Layer B per-file selective secrets, and M2c per-region inline `<vault id="…">…</vault>` secrets. The daemon mounts a FUSE plaintext-view at the garden root when configured with a relocated `state_root`; sealed paths (matching `.softfig/vault/sealed-paths.toml` globs) are encrypted under per-file HKDF subkeys and projected as `[sealed:<path>]\n` placeholders. Files containing inline `<vault>` tags get per-region HKDF subkeys, base64-inline ciphertext on disk, and `<vault id="…">[encrypted]</vault>` projected through FUSE on read. `softfig reveal <path>` writes plaintext to a 0600 file under `$XDG_RUNTIME_DIR` and commits a `vault_reveal` audit intent; the `--id <id>` repeatable flag reveals just one or more region plaintexts. The same `softfig-keeperd` binary handles M1c-compat, M2a, M2b, and M2c configs from one binary; Layer B is inert until the first `sealed-paths.toml` lands and inline-region encryption is inert until `<vault>` bytes appear in a tracked file.

**M-onboard** adds the first-run front door: `softfig onboard` scaffolds a fresh garden from an embedded default-layout skeleton (`templates/default-garden/`, baked in via `include_dir!`), inits the Vault, and writes a born-in-FUSE genesis commit directly in the `state_root` layout — no plaintext is ever written at the garden root, and the three-phase `migrate` dance is reserved for converting the legacy tablet garden. The scaffold logic lives in the frontend-agnostic `softfig-onboard` crate so a future MCP tool wraps the same `onboard()` entry point. The daemon now resolves its config via `KeeperConfig::discover` (reads `<garden>/.softfig/keeper.toml`), so a born-in-FUSE or migrated garden boots straight into FUSE mode. Install plumbing is a documented runbook (`docs/onboard-laptop.md`) plus `scripts/onboard-device.sh`.

**M3b** adds the first Keeper *human* surface: `softfig-tui`, a ratatui frontend over the daemon (master/detail Browse + History + Action forms + in-app unlock). It introduces two **read-only** IPC verbs — `list_tree` and `read_file` — that serve garden content from the committed tip and apply the same `LayerBHook` redaction the FUSE read path uses, so the TUI receives `[sealed:<path>]` / `[encrypted]` projections, never sealed plaintext. The TUI is a separate binary; the lean-core slice keeps vault reveal/seal surfaces CLI-only for now.

| Area | State |
|---|---|
| Cargo workspace | ✅ ten member crates |
| `softfig-vault` crate | ✅ init / unlock / encrypt-blob / decrypt-blob / sign / rotate-key / recover; `at_state_root` for the M2a relocated layout; **M2b**: `layer_b` module with `derive_subkey` / `encrypt` / `decrypt`, `VaultSession::encrypt_layer_b` / `decrypt_layer_b` / `verify_master_passphrase`; **M2c**: `derive_region_subkey(M, path, id)` (`HKDF(M, salt=path‖0x00‖id, info=b"softfig:layer-b-region/v1")`) + `VaultSession::{encrypt_layer_b_region, decrypt_layer_b_region}` |
| `softfig-store` crate | ✅ ciphertext object directory (`.softfig/objects/<aa>/<rest>`) + sqlite metadata schema; WAL mode set on every open; `StorePaths` accepts a `state_root` distinct from `garden_root` |
| `softfig-core` crate | ✅ garden walker, tree blueprint, JCS-canonicalized + signed commits, log iteration, fsck; `Repo::open_with` accepts a state_root; `Repo::set_tip_changed_callback` for the FUSE driver to subscribe; **M2b**: `BlobEncryptor` trait + `Repo::set_blob_encryptor` + `tree::build_with` extension point so the daemon can route sealed paths through Layer B without leaking glob logic into `softfig-core`; **M2c**: `"manual_edit"` added to `KNOWN_INTENTS` (latent bug fix — classifier produced it but the closed-enum validator silently rejected it) |
| `softfig-ipc` crate | ✅ JSON-Lines protocol envelope + typed verb args/replies + sync `connect`/`call` over `UnixStream`; includes `migrate_finalize`; **M2b**: `vault_reveal` / `vault_seal` / `vault_unseal` / `vault_list_sealed` verbs + corresponding args/replies + `MasterPasswordRequired` / `SealedPathNotFound` / `IdleStatusOnly` error kinds; **M2c**: `VaultRevealArgs.id: Option<String>` (skip-serializing) + `MalformedVaultTag` / `DuplicateVaultId` error kinds; **M3a**: `op::{log_decision, log_incident, archive, add_project, refresh_snapshot}` + five `*Args`/`*Reply` struct pairs + `InvalidSlug` / `InvalidProjectName` / `PathAlreadyExists` / `SourceNotFound` / `InvalidSnapshotPath` error kinds; **M3b**: `op::{list_tree, read_file}` read-only verbs + `ListTreeArgs`/`ListTreeReply` (`Vec<TreeEntry>`) + `ReadFileArgs`/`ReadFileReply` (`{path, content, sealed}`) |
| `softfig-keeperd` binary | ✅ daemon with `SO_PEERCRED` + 0600 socket, full IPC verb set, mixed-mode dispatch on keeper.toml's `state_root` (**M-onboard**: `main.rs` now boots via `KeeperConfig::discover` so a born-in-FUSE/migrated garden auto-enters FUSE mode; absent keeper.toml falls back to M1c-compat), shared `DirtySetAccumulator` consumed by both `InotifyDriver` and FUSE via `AccumulatorSink`; **M2b**: `layer_b` module with `SealedPaths` matcher (globset-based) + `LayerBHook` doubling as `BlobEncryptor` and `SealedQuery`; four new IPC handlers; `DaemonInner` carries the shared hook + `last_reveal_at` idle-window state; `keeper.toml` gains `[reveal] idle_seconds = 0`; **M2c**: `layer_b` restructured as directory module — `layer_b/regions.rs` (RegionParser registry, scan + base64-disambiguator, write-path placeholder preservation, `with_substitutions` helper) + `layer_b/mod.rs` extensions (`LayerBHook` gains session + prior-tip slots, `BlobEncryptor::encrypt` got region-aware write path, `SealedQuery::redact_regions` impl, `PriorTipGuard` RAII helper around every commit_workdir site, `promote_manual_edit_for_new_ids` watcher sub-rule); `vault_reveal` handler gains the `id` branch (region-only reveal + temp-file naming + audit-intent extension); **M3a**: new `actions/` module (`conventions.rs` with hardcoded path/header/stub templates + slug/name/date validators + a civil-from-days date helper, plus one file per action) servicing the five typed write verbs — each validates, reject-on-exists, registers self-writes, then one `commit_workdir` under a `PriorTipGuard` via `actions::commit_now`; `server::dispatch` routes the five verbs straight to `actions::*`; `require_unlocked` / `validate_repo_path` / `path_to_repo_rel_string` promoted to `pub(crate)`; **M3b**: new read-only `reads` module (`list_tree` / `read_file` dispatch arms) — walks the tip tree via `Repo`, applies the installed `LayerBHook` (`is_sealed` → `[sealed:<path>]`, `redact_regions` → `[encrypted]`); reuses the M3a `pub(crate)` helpers, require-unlocked, no commits |
| `softfig-tui` binary | ✅ **M3b** — ratatui frontend (lib + bin): master/detail Browse (lazy `list_tree` tree + `read_file` preview), History (`log`/`show`), modal Action forms over the six M3a write verbs (built-in multi-line text area, no `$EDITOR`), in-app unlock, `:` command palette; worker-thread IPC client (`ipc.rs`), pure-state modules (`tree`, `forms`, `command`, `textarea`, `app`) carry the unit tests + a `TestBackend` render snapshot |
| `softfig-mcp` binary | ✅ stateless stdio bridge — `initialize` / `tools/list` / `tools/call`; **M3a**: six tools — `propose_doc_update` (verbatim escape hatch) + `log_decision` / `log_incident` / `archive` / `add_project` / `refresh_snapshot`. `tool_defs()` returns the six schemas; pure `resolve_tool(name, args)` maps a tool name → IPC op + validated args (unit-tested); `summarize()` renders the one-line reply |
| `softfig-cli` (`softfig` binary) | ✅ vault subcommands + VCS subcommands + `daemon {start, stop, status, unlock}` + bridge fast path on commit/log/show/fsck + `migrate {prepare, finalize}` + no-arg `migrate` phase status; migrated gardens refuse direct-mode `commit/log/show/fsck`; **M2b**: `softfig reveal <path>` and `softfig vault {seal, unseal, list-sealed}`; **M2c**: repeatable `--id <id>` flag on `reveal` with single-prompt master-password caching across multiple region calls; **M-onboard**: `softfig onboard [--garden-root P] [--state-root P] [--machine NAME] [--customize] [--yes]` first-run wizard (`cmd_onboard.rs`), thin TTY frontend over `softfig-onboard`; stops before the passphrase step when no TTY |
| `softfig-onboard` crate | ✅ **M-onboard** — frontend-agnostic scaffold core: embedded `templates/default-garden/` via `include_dir!`, `OnboardOptions` / `ScaffoldPlan`, `plan()` (placeholder substitution + concept-dir filter + defensive `.keep` synthesis), `apply()`, `onboard()` / `onboard_with_params()` (Vault init at `state_root` → stamp to tempdir → `Repo::create_fresh` → drop staging → write keeper.toml pointer); depends on `softfig-vault` + `softfig-core` |
| `softfig-fuse` crate | ✅ M2a — `FuseMount::mount(garden, state, session, sink)` returns a `MountHandle`; reads decrypt blobs via the shared `VaultSession`, writes go through an in-memory overlay that the daemon's M1d accumulator flushes into commits; `MountHandle::on_tip_changed` clears the overlay + stat cache on each new tip; **M2b**: `FuseMount::mount_with(..., Option<Arc<dyn SealedQuery>>)` projects `[sealed:<path>]\n` placeholders for sealed reads (computed on read, never stored); **M2c**: `SealedQuery::redact_regions` default-impl method + `SharedState::redacted_cache` (broadcast invalidation on `tip_changed`); read path funnels post-Layer-A bytes through `redact_regions` for non-whole-file-sealed paths |
| Layer B selective secrets | ✅ M2b file-level seal/unseal + `softfig reveal` flow + auto-migration on glob add; ✅ M2c inline `<vault id="…">…</vault>` regions + per-region reveal + classifier auto-promotion on new-id introduction |
| Onboarding / first-run | ✅ **M-onboard** — `softfig onboard` scaffolds a fresh garden born-in-FUSE; install runbook + `scripts/onboard-device.sh`; program repo under local git |
| MCP action surface | ✅ **M3a** — six daemon-mediated MCP tools; the daemon stamps garden conventions (path/header/intent/payload) from hardcoded Rust defaults, so any Claude session writes the right file without learning the conventions |
| TUI (ratatui) | ✅ **M3b** — `softfig-tui` over the daemon (Browse/History/Actions/unlock) + read-only `list_tree`/`read_file` verbs with daemon-side redaction; vault TUI surfaces deferred to an M3b follow-up |
| Sync, Templating + symlinks pillars, GUI, AUR | not started — M4+ |

Spec source-of-truth still lives in the garden at `~/soft-fig_garden/meta/spec-*.md`. Read those for design intent.

## Workspace layout

```
software-config_garden/
├── Cargo.toml                          # [workspace]
├── .gitignore                          # excludes target/, keeps Cargo.lock
├── templates/default-garden/           # M-onboard — embedded skeleton (include_dir!)
├── scripts/onboard-device.sh           # M-onboard — install runbook script
├── docs/onboard-laptop.md              # M-onboard — manual onboarding runbook
├── packaging/systemd/
│   └── softfig-keeperd.service         # drafted user unit (mirror to ~/dotfiles/...)
└── crates/
    ├── softfig-vault/                  # crypto + key lifecycle
    │   └── src/{lib,vault,session,kek,master,identity,blob,recovery,storage,params,error}.rs
    ├── softfig-store/                  # objects + sqlite metadata
    │   └── src/{lib,db,objects,paths,hash,error}.rs
    ├── softfig-core/                   # VCS operations
    │   └── src/{lib,repo,walk,tree,commit,intent,log,fsck,error}.rs
    ├── softfig-ipc/                    # JSON-Lines protocol + client
    │   └── src/{lib,proto,verbs,socket,client}.rs
    ├── softfig-keeperd/                # daemon binary
    │   ├── src/{lib,main,config,daemon,server,handlers,reads,peer,classify,watcher,state,
    │   │        keeper_toml,migrate,fuse_sink}.rs
    │   ├── src/layer_b/{mod,regions}.rs  # M2b matcher + hook; M2c regions + write-path
    │   └── src/actions/{mod,conventions,log_decision,log_incident,archive,
    │            add_project,refresh_snapshot}.rs  # M3a typed write verbs
    ├── softfig-mcp/                    # stdio MCP bridge
    │   └── src/main.rs
    ├── softfig-cli/                    # `softfig` binary
    │   └── src/{main,cmd_vault,cmd_repo,cmd_daemon,cmd_migrate,cmd_reveal,cmd_onboard}.rs
    ├── softfig-fuse/                   # M2a — FUSE plaintext-view of Layer A
    │   └── src/{lib,fs,inodes,overlay,tree_view}.rs
    ├── softfig-onboard/                # M-onboard — scaffold core (frontend-agnostic)
    │   └── src/{lib,keeper_pointer,tests}.rs
    └── softfig-tui/                    # M3b — ratatui frontend (lib + bin)
        └── src/{lib,main,app,ui,ipc,tree,forms,command,textarea}.rs
```

## On-disk layout

**M1c-compat (no `state_root` in keeper.toml):**

```
<garden_root>/.softfig/
├── vault/              # owned by softfig-vault: master keys, identity, KEK wrappings, params
├── objects/<aa>/<rest> # ciphertext blobs, addressed by BLAKE3(ciphertext)
├── db.sqlite           # commits / trees / tree_entries / refs / meta (schema_version = 1)
└── keeper.toml         # optional; absent or empty = M1c-compat
```

**M2a (FUSE-mounted):** the daemon mounts a FUSE filesystem at
`<garden_root>` (the mount hides whatever plaintext is there during
the prepare phase, then `migrate finalize` deletes the orphan).
On-disk state moves to `<state_root>/.softfig/` (default
`~/.local/share/softfig/<repo_id>/.softfig/`):

```
<state_root>/.softfig/   # canonical state in M2a
├── vault/
├── objects/<aa>/<rest>
├── db.sqlite
└── keeper.toml          # state_root = "<state_root>"
```

**Born-in-FUSE (M-onboard):** `softfig onboard` creates this same M2a
layout directly (no `migrate`). The encrypted state is written to
`<state_root>/.softfig/` from the first commit; a `keeper.toml` pointer is
written to **both** `<garden_root>/.softfig/keeper.toml` (where
`KeeperConfig::discover` reads it) and `<state_root>/.softfig/keeper.toml`.
No plaintext is ever written at `<garden_root>` — the daemon serves it via
FUSE on unlock.

## Crypto + canonicalization

- AEAD: XChaCha20-Poly1305 (Vault blob layer)
- Hash: BLAKE3 (object addresses, tree hashes, commit hashes)
- Password KDF: Argon2id (OWASP 2023 default `m=64 MiB, t=3, p=4`)
- Subkey KDF: HKDF-SHA-256
- Signing: Ed25519 (identity key, signs each commit's hash)
- Recovery phrase: BIP39 12-word
- **Canonicalization for hashing/signing: RFC 8785 JCS** via `serde_jcs`. Trees, commits, and intent payloads all canonicalize through it.

Blobs use **master-keyed convergent encryption** so the VCS layer can content-address ciphertext and dedup: `nonce = BLAKE3-keyed(M, plaintext)[..24]`, `per_blob_key = HKDF-SHA-256(salt=nonce, ikm=M, info="softfig.blob.v1")`, `blob_file = varint(master_key_id) ‖ nonce ‖ AEAD-body`. Same plaintext + same M → same ciphertext → same hash. Indistinguishable without M.

Commits are signed by hashing the canonical commit form first: `commit_hash = BLAKE3(JCS({parent, root_tree, author_device, author_pubkey, intent, payload, master_key_id, timestamp}))`, then `signature = identity.sign(commit_hash)`. Verifiers re-canonicalize, re-hash, and check both the hash matches the stored row and the Ed25519 signature verifies under `author_pubkey`.

## Build / test / run

```bash
cd ~/projects/software-config_garden
cargo build --workspace          # debug build
cargo test --workspace           # 158 tests (M3b: +9 m3b_reads integration, +19 softfig-tui unit, +2 render snapshot; M3a + M-onboard + M2x carryovers), <3s with fast Argon2
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p softfig-cli -- --help
cargo run -p softfig-cli -- vault --help
cargo run -p softfig-cli -- init --help
```

Tests use minimum Argon2id cost (`m_cost=8 KiB, t_cost=1, p_cost=1`) so the suite runs in <1 second; production defaults are OWASP 2023.

## CLI surface

```text
softfig onboard [--garden-root P] [--state-root P] [--machine NAME] [--customize] [--yes]  # M-onboard first-run wizard
softfig vault init        | status | rotate-key | recover         # crypto state
softfig init              # writes a genesis commit over the existing vault
softfig commit --intent <name> -m <msg> [-f <path>]... [--kv k=v]... [--payload-json '{...}']
softfig log [--limit N]
softfig show [<commit-hex>]
softfig fsck
softfig daemon start | stop | status | unlock                     # M1c daemon controls
softfig migrate                                                    # M2a — phase status (no daemon needed)
softfig migrate prepare [--state-root <path>]                      # M2a phase 1 (no daemon, refuses if socket present)
softfig migrate finalize                                           # M2a phase 3 (IPC verb to running M2a daemon)
```

`commit/log/show/fsck` auto-detect a running daemon by `connect()`-ing
to `$XDG_RUNTIME_DIR/softfig-keeperd.sock`; on success the operation
runs through the daemon (no per-command passphrase prompt). The CLI
falls back to direct mode **only** when the socket is absent
(`ENOENT`/`ECONNREFUSED`). A reachable-but-erroring daemon (e.g.,
`vault_locked`) is surfaced verbatim — never bypassed — so the
"daemon, when present, is the sole writer" invariant holds.

## IPC surface (softfig-ipc)

JSON-Lines on a Unix socket. Verbs: `status`, `unlock`, `commit`,
`log`, `show`, `fsck`, `propose_doc_update`, `migrate_finalize`,
`shutdown`; M2b: `vault_reveal` / `vault_seal` / `vault_unseal` /
`vault_list_sealed`; **M3a**: `log_decision` / `log_incident` /
`archive` / `add_project` / `refresh_snapshot`; **M3b**: `list_tree` /
`read_file` (read-only browse; daemon redacts sealed content). Auth = filesystem mode 0600 + `SO_PEERCRED` UID-match
on every accept. Daemon boots in **Locked** state; only `status`
and `unlock` are answerable until `unlock` succeeds. All M3a/M3b verbs
require Unlocked.
`migrate_finalize` requires `state_root` to be set in `keeper.toml`
AND the daemon to have an active FUSE mount.

## Cross-refs

- Garden view: `~/soft-fig_garden/projects/software-config_garden/` — milestone tracking, decisions, notes.
- Vision: `~/soft-fig_garden/meta/program-vision.md`.
- Design playgrounds: `~/soft-fig_garden/meta/spec-{vault,vcs,keeper,sync,templating,symlinks}.md`.
- Decision log: `~/soft-fig_garden/journal/decisions/decision-add-keeper-vision.md`, `decision-vault-pillar.md`, `decision-trust-matrix.md`, `decision-softfig-vault-impl.md`, `decision-softfig-vcs-impl.md`, `decision-softfig-keeperd-impl.md`, `decision-softfig-watcher-refactor-impl.md`, `decision-softfig-fuse-impl.md`, `decision-softfig-layer-b-impl.md`, `decision-softfig-m2c-impl.md`, `decision-softfig-onboard-impl.md`, `decision-softfig-m3a-impl.md`, `decision-softfig-m3b-impl.md`.

## How to behave here

- Code-level architecture, build commands, FFI contracts → expand this CLAUDE.md.
- Planning, milestones, decisions → garden's `projects/software-config_garden/`.
- Don't duplicate spec content from `meta/spec-*.md` here; point at it.
- Multi-device features (trust matrix, peer unlock, panic counter), TPM self-path, replica-only mode — **all deferred**. Don't add them ad-hoc; each warrants its own iteration with a decision file. Layer B shipped in M2b (whole-file seals) and M2c (inline `<vault id="…">…</vault>` regions); the FUSE plaintext view, the `softfig reveal` flow, and the audit-intent shape are all live.
- Daemon/MCP shipped in M1c; the live `notify-debouncer-full` event loop landed same-day (2026-05-09). M1d (2026-05-10) restructured the watcher into a source-agnostic `DirtySetAccumulator` + `DirtySetSource` trait + `InotifyDriver`. M2a (2026-05-10) added the FUSE driver as the second source: writes through the FUSE mount fire `DirtyEvent`s into the SAME accumulator inotify uses (single classifier pipeline). 200 ms debounce, 500 ms suppress TTL, classifier rules (`decision_logged`, `incident_logged`, `archive_move`, `manual_edit`) all preserved bit-for-bit.
- M2a runs in **mixed mode**: a single `softfig-keeperd` binary handles both M1c-compat (no `state_root` in keeper.toml) and M2a (state_root present). Choosing between modes is data-driven — there is no flag — so the binary is daily-driveable against an unmigrated garden today. Migration is non-destructive and three-phase (`migrate prepare` → daemon start → `migrate finalize`); reversible at every phase until finalize.
- Schema migrations: add new variants to the `Intent` closed enum + bump `KNOWN_INTENTS` only after updating `meta/spec-vcs.md` and writing a `decision-*` file. The `init` variant added in M1b is an example.
- Sqlite schema lives in `softfig-store::db::SCHEMA_V1`. Future migrations go through a migration table; don't edit the v1 string in place.
