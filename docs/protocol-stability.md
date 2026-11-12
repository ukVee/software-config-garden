# Protocol stability

**Nothing is stable yet.** `softfig-protocol-keeperd` and
`softfig-protocol-growlightd` are both `0.1.0`, and either can break in any
commit. Don't build a third-party client against them expecting otherwise.
keeperd `1.0` waits for an alt-client: the contract is only frozen once a second
client has proved it.

This page records what each crate will promise, so the crates can be held to it
later. The full design is in `meta/spec-softfig-tui-frontend-split.md` §7 in the
soft-fig garden.

## What each crate will promise

| Crate | Today | Target |
|---|---|---|
| `softfig-protocol-keeperd` | `0.x`, no promise | SemVer from `1.0`: a minor adds, a major breaks. A field or verb is deprecated for at least one minor before it goes. A breaking change needs a decision file. |
| `softfig-protocol-growlightd` | `0.x`, no promise | Stays `0.x`. Any version bump may break it. A client that depends on it accepts that, and opts in visibly in its own `Cargo.toml`. |
| `softfig-client` | Workspace version | Not part of the wire contract. It is the IO layer over `softfig-protocol-keeperd`. |
| `softfig-ipc` | Workspace version | A facade for in-repo consumers, and not a public surface. Every path it re-exports is a path in the crate that defines it (next section). |

## What `softfig-ipc` re-exports

`feat/tui-split-protocol` moved the wire out of `softfig-ipc`. The facade
re-exports everything moved, unchanged, so keeperd, growlightd and the CLI kept
every `use` line. A promise about a facade path is a promise about the crate
that now defines it.

| Item | Defined in |
|---|---|
| `proto::{Request, Response, ErrorKind}`, `PROTOCOL_VERSION`, `verbs::*` (the op strings, the verb args and replies, `DeferredTestSpec`, `human_age_secs`) | `softfig-protocol-keeperd` |
| `queue_v2::{EntryKind, Lane, SliceStatus}` and their `Display` impls | `softfig-protocol-keeperd::queue_v2` |
| `queue_v2::{RestackBranch, hold_annotation}` | `softfig-protocol-keeperd::queue_v2` |
| `queue_v2::migrate::{Answers, CallClass, BatonMove}` | `softfig-protocol-keeperd::queue_v2::migrate` |
| `fleet::{holds, parse_not_before, days_from_civil}` (the pure item-doc value rules) | `softfig-protocol-keeperd::fleet` |
| `growlightd::*`, including the five member-verb `op` aliases | `softfig-protocol-growlightd` |
| `client`, `socket`, `call`, `call_reconnecting`, `connect`, `RetryPolicy`, the runtime socket paths | `softfig-client` |

**`queue_v2` and `fleet` are split on purpose, and the split is the stability
line.** What a wire type needs is in the protocol crate, IO-free: the three
enums and their `Display` impls (the orphan rule forces the impls to follow the
types), `RestackBranch`, `hold_annotation`, the three `migrate` wire types, and
the `not_before` grammar. What reads the garden stays in the facade: the
state-file parsing and validation in `queue_v2::{mod, validate}`, the whole
plan/apply half of `queue_v2::migrate` (it reads `$HOME` and imports
`backlog_doc`, `model_choice`, `baton` and `fleet`), and the `> Fleet:` /
`> Not before:` item-doc scanner in `fleet`. A third party that wants the wire
types does not get a filesystem reader with them.

## Already pinned by tests

- The envelope round-trips (`proto`), and the growlightd reply types round-trip
  with their defaults kept off the wire.
- The six closed `queue_v2` vocabularies render exactly their TOML wire name
  (`queue_v2::tests::wire_names` in the protocol crate, and
  `display_matches_wire_names` through the facade).
- The five member-verb `op` strings are frozen
  (`verbs::op_wire_values::member_verb_op_values_are_frozen`). Single-sourcing
  them stops the crates diverging; only a test stops a value changing under
  deployed clients.

## Still open before keeperd `1.0`

- **Reply strictness (report 110).** `deny_unknown_fields` on replies would make
  every additive reply field break older clients, so it can't coexist with
  additive minors. The code today is tolerant on replies, and strict only on
  growlightd's member-verb request args. `tui-split-directord` ruling 6 settles
  it.
- **`#[non_exhaustive]`.** No public enum carries it. It changes no wire bytes,
  but it stops consumers' exhaustive matches compiling, so it lands in its own
  change before `1.0`.
- **Version negotiation.** `PROTOCOL_VERSION: u8 = 1` is still the only version
  on the wire. Per-crate SemVer negotiation arrives with `softfig-directord`.
- **The build stamp.** Unmerged `feat/release-pipeline` has a daemon refuse a
  stamped request from another build, which can't coexist with SemVer
  negotiation. `tui-split-directord` ruling 7 decides.
- **Packaging (review 060 F9).** The three crates are path-only workspace
  members: `softfig-client` and `softfig-protocol-growlightd` depend on
  `softfig-protocol-keeperd.workspace = true`, which carries no `version`, so
  `cargo package` and `cargo publish` refuse them and nothing is on crates.io.
  That is consistent with the rest of the workspace and blocks nothing here,
  but this page tells a third party to depend on the crates directly, and today
  the only way to do that is to build from this workspace.
