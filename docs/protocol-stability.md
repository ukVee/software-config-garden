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
| `softfig-ipc` | Workspace version | A facade for in-repo consumers, and not a public surface. |

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
