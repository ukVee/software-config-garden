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

- `snapshot version: <hash>`: the value to pass to `--apply --expect`. It is
  a digest over every `.md` it read under `growlight/backlog/` and every
  baton, so editing any of them before the apply moves it;
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

Each class takes one answer shape. A malformed answer is refused at plan
time, so the dry run shows it:

| class | subject | answer |
|---|---|---|
| `list_order` | `list` | `default-then-registry`, or every queue name, comma-separated, in list order |
| `project_repo` | project | the repo, as one local path (`/…`, `~/…`) or `host:/path`. A cell under `/tmp` is always a call |
| `project_main` | project | the branch the project merges into, e.g. `main` |
| `same_repo` | `a+b+…` | the one spelling every project in the group gets |
| `unknown_cell` | `<id>.type` / `<id>.status` | `milestone` or `task` / a legacy status: `queued`, `active`, `deferred`, `blocked`, `done` |
| `duplicate_id` | id | the queue whose row is kept. The evidence prints every row |
| `item_doc` | id | `keep`. Acknowledgment only, and the answer is not read: v2 finds an entry's doc by its path |
| `blocked_on` | id | `none` (the tag stays in the title), or the id of a known item, which becomes `after` |
| `branch` | id | the branch name. A `done` row asks too, so the archive keeps its real branch |
| `stack_base` | id | `parent=<id> base=<commit>`: an empty parent is `main`, and an empty base is an explicit unknown, which the restack doc blocks on. The parent must be another item in the backlog, and the base a 7–40 digit hex commit |
| `slice_progress` | id | one slice status for every slice, or `NNN=<status>, …` (unnamed slices stay `queued`). Empty leaves all `queued` |
| `not_before` | id | a time that parses, or `none` (drop the hold). Repeating the value keeps it, and it then holds fail-closed |
| `model` | id | `keep`. Acknowledgment only: the `> Model:` line stays in the doc |
| `active_per_repo` | repo | the id of the one entry that stays `active`; the others become `queued` |
| `baton` | baton path | `copy` (only for a live entry, one baton per entry) or `skip` |

The `stack_base` proposal reads the branch policy. "stacked on `feat/Y`"
proposes `parent=Y` with the first commit the prose gives after that branch
(its tip), ahead of any off-`main` sha in the same prose. A bare "off `main`
`<sha>`" proposes `parent= base=<sha>`. A `## Branch policy` heading may carry
a suffix (`(stacked)`, `(locked …)`, `— …`). A baton's quoted `item:` /
`slice:` reads without its quotes.

### `stack_base` answers from git

You don't have to write the `stack_base` answers by hand. Have git propose them:

```sh
softfig growlight queue migrate --dry-run --answers answers.toml --stack-answers stack.toml
```

This prints the dry run as usual. It also writes `stack.toml`, an answers
file with one `[call]` line for every `stack_base` call that is still open.
Each line comes with a comment that says where the answer came from. Git runs
read-only in each project's repo, with the same probe rules growlightd uses.

| the entry's branch | the line |
|---|---|
| live and not merged into the project's `main` | `parent=<p> base=<merge-base>`: the merge-base with the parent's branch, or with `main` when the prose names no parent or the parent's branch is gone |
| gone, or merged into `main` | `parent=<p> base=`, the explicit unknown |
| in a remote or ambiguous repo, in a repo git can't read, or with the prose naming a parent that isn't an item; or missing while its name is still an open `branch` call's proposal; or the project's `repo` is still unsettled | commented out, with the reason. The call stays open: settle the other call and re-run |

`<p>` is the parent the `stack_base` proposal names. Nothing applies the file
by itself, and `--stack-answers` can't be combined with `--apply`. An existing
`stack.toml` is never overwritten. Review it, then either pass it alone as
`--answers` or paste its lines into your own answers file's `[call]` table.

Re-run the dry run with `--answers` until no call is open and no refusal is
left.

## 3. Apply

```sh
softfig growlight queue migrate --apply --answers answers.toml --expect <version>
```

`--garden` is refused here: keeperd reads its own working tree, so a garden
path would name a copy the apply never looks at.

`--apply` is a thin client over the keeperd op `queue_v2_migrate_apply`.
keeperd re-reads the backlog from its own working tree, projected the way the
mount serves it (sealed docs and regions as their placeholders), recomputes the plan
under your answers, and writes every v2 file in **one** `queue_v2_migrated`
commit. The same commit also renders the §3.4 views, each into a new file of
its own: `softfig:queue-v2` in `growlight/backlog/queue.md` and
`softfig:slices-v2` in each milestone's `slices.md`. No `CLAUDE.md` changes:
the legacy tables and the doc prose stay byte-for-byte unchanged.

Before writing anything, keeperd refuses with an error that leads with the code:

| code | when |
|---|---|
| `member_not_allowed` | a fleet member calls it, by its softfig-mcp stamp or from its scope's shell: the migration is the human's |
| `fleet_armed` | `config/growlight.toml` has `fleet_enabled = true` |
| `switch_is_v2` | `config/growlight.toml` already says `queue = "v2"` |
| `v2_files_present` | `queue.toml`, `queue-archive.toml` or a `slices.toml` exists: an earlier apply landed (see §4) |
| `legacy_changed` | the snapshot (every backlog `.md` and baton the plan reads) is not at the `--expect` version: something changed since the dry run, so re-run it |
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

A failed copy makes the command exit non-zero. The other copies still run, and
the output ends with a `mkdir -p … && cp -n …` line for each failed one. Run
those lines by hand: the v2 files are already committed, so a second `--apply`
refuses `v2_files_present` and won't redo the copies.

## 4. After the apply

**If the apply failed**, it says which half it reached:

- The keeperd op errored. Nothing was committed, and keeperd put back every
  file it had staged, so the error ends `nothing was committed and the staged
  files were put back`. Fix the cause and run the same `--apply` again. If a
  file couldn't be put back, the error names it instead; remove that file
  (or restore it with `softfig show`) before the retry.
- The commit landed and a baton copy failed. The command exits non-zero after
  printing a `commit <hash>` line, and it ends with the `mkdir -p … && cp -n …`
  lines to run (§3, "Baton copies"). Don't re-run `--apply`.

A later `--apply` that refuses `v2_files_present` means a migration landed:
`softfig log` shows its `queue_v2_migrated` commit.

The switch is still `legacy`. Flipping `queue = "v2"` is a separate,
deliberate step, done with the fleet disarmed. The rest of the owner's
migration session (merge order, deploy, smoke, retiring the legacy files) is
the runbook in the `queue-v2-migrate` milestone doc's
`## Deferred verification`.
