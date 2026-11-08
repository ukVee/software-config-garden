# growlight queue migrate — the legacy → v2 backlog converter

`softfig growlight queue migrate` converts the legacy backlog (the queue tables
in `growlight/backlog/CLAUDE.md` plus the item docs and slice folders) into the
queue v2 files: `queue.toml`, `queue-archive.toml` and one `slices.toml` per
live milestone. The contract is spec-growlight-queue §11, "The converter
contract"; the mapping table is the `queue-v2-migrate` milestone doc's
`## Mapping`.

It never guesses. When it can't map something with certainty, it raises a
**judgment call** and leaves it to you. When the v2 model can't represent
something at all, it raises a **refusal**. It never flips `queue = "v2"` and
never edits the legacy tables.

## 1. Dry run

```sh
softfig growlight queue migrate --dry-run [--answers answers.toml] \
    [--garden ~/soft-fig_garden] [--config-dir ~/.config/softfig/growlight]
```

This reads the backlog off the mount, plus the runtime batons (the root
`baton.md` and each `agents/<id>/baton.md`). It writes nothing and calls no
daemon. It prints:

- `backlog doc version: <hash>`: the value to pass to `--apply --expect`;
- the counts, the projects, the entries in list order, the `slices.toml`
  files and the baton copies;
- every judgment call, `[open]` or `[settled]`, with its evidence and its
  proposal;
- every refusal;
- `N calls need you` last.

A doc whose metadata the mount hides is a refusal: a whole-file-sealed doc
(`[sealed:<path>]`), one with a sealed `<vault id="…">` region, or one whose
vault tags don't parse. That holds for the backlog doc, and for a live item's
own doc and its slice docs. A `> Fleet: no` or `> Not before:` could be hiding
there, so the row isn't migrated without it. Reveal or unseal the doc first.
An archived (`done`) row's docs raise nothing.

## 2. Settle the calls: the answers file

```toml
schema = 1

[class]            # one answer for every call of a class
list_order = "default-then-registry"
project_main = "main"

[call]             # one call, by its `<class>:<subject>` key; beats [class]
"project_repo:softfig" = "~/projects/software-config_garden/codebase"
"baton:baton.md" = "skip"
```

Class names are `list_order`, `project_repo`, `project_main`, `same_repo`,
`unknown_cell`, `duplicate_id`, `item_doc`, `blocked_on`, `branch`,
`stack_base`, `slice_progress`, `not_before`, `model`, `active_per_repo` and
`baton`. Re-run the dry run with `--answers` until no call is open and no
refusal is left.

## 3. Apply

```sh
softfig growlight queue migrate --apply --answers answers.toml --expect <version>
```

`--apply` is a thin client over the keeperd op `queue_v2_migrate_apply`.
keeperd re-reads the backlog from its own working tree, projected the way the
mount serves it (sealed docs and regions as their placeholders), recomputes the plan
under your answers, and writes every v2 file in **one** `queue_v2_migrated`
commit. The same commit also renders the §3.4 views as new managed regions:
`softfig:queue-v2` in the backlog doc and `softfig:slices-v2` in each milestone
`CLAUDE.md`. The legacy tables and the doc prose stay byte-for-byte unchanged.

Before writing anything, keeperd refuses with an error that leads with the code:

| code | when |
|---|---|
| `fleet_armed` | `config/growlight.toml` has `fleet_enabled = true` |
| `switch_is_v2` | `config/growlight.toml` already says `queue = "v2"` |
| `v2_files_present` | `queue.toml`, `queue-archive.toml` or a `slices.toml` exists |
| `legacy_changed` | the backlog doc is not at the `--expect` version: re-run the dry run |
| `not_applicable` | the recomputed plan still has a refusal or an open call |

A malformed `config/growlight.toml`, or a `queue` value keeperd doesn't know,
is refused too; the apply never assumes a default.

### Baton copies (§3.6)

After the commit lands, the CLI copies each in-flight baton the plan names into
the per-entry store, `$XDG_CONFIG_HOME/softfig/growlight/entries/<id>/baton.md`.
It writes the bytes it sent to keeperd, so the copy is exactly what the plan
judged. A copy **never overwrites** an existing target (that one is reported
`skipped, target exists`) and **never removes** the source. Each copy prints
one line: `copied`, `skipped, target exists`, or `FAILED, <reason>`.

## 4. After the apply

The switch is still `legacy`. Flipping `queue = "v2"` is a separate,
deliberate step, done with the fleet disarmed. The rest of the owner's
migration session (merge order, deploy, smoke, retiring the legacy files) is
the runbook in the `queue-v2-migrate` milestone doc's
`## Deferred verification`.
