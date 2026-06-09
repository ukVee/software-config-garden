# M5a implementation plan — transport + pairing (sub-sliced)

**Status:** design-locked, unbuilt. This is the coding plan for M5a, the foundation slice of
M5 (cross-device sync). It is sliced into four single-session sub-slices, each run in a **fresh
Claude session**.

- **Authoritative design (read first):** the garden decision doc
  `~/soft-fig_garden/journal/decisions/decision-softfig-m5a-impl.md` (full rationale + locked
  picks) and `~/soft-fig_garden/meta/spec-sync.md` (Transport + Pairing sections). The garden is
  FUSE-mounted only while the keeper daemon is unlocked; if you can't read those paths, the
  **Locked design summary** below is self-contained enough to proceed.
- **Code-level conventions:** `~/projects/software-config_garden/CLAUDE.md` (auto-loads when you
  open Claude from the program repo — always open coding sessions from there).
- The CLAUDE.md "How to behave" note says multi-device features are deferred and "each warrants
  its own iteration with a decision file." **This is that sanctioned iteration** — the decision
  file exists.

## Locked design summary (the 5 picks)

1. **Transport security = app-level Noise (`snow` crate)**, NOT WireGuard (keeperd is an
   unprivileged user unit; WG needs `CAP_NET_ADMIN`, re-breaking the FUSE/no-priv model). Noise
   `XX` for first pairing, `IK` for reconnect. X25519 + ChaCha20-Poly1305 (already in-tree).
2. **RPC = Protobuf** (`prost` + `prost-build`). Signed messages sign canonical/wire bytes
   (protobuf is not canonical by default — sign exact serialized bytes, never a re-serialization).
3. **Pairing = SAS short-code** derived from the Noise `XX` handshake hash, confirmed on an
   already-paired device. Defeats LAN MITM; no camera (works headless).
4. **Off-LAN = relay through the always-on server** (zero-trust ciphertext dumb-pipe; holds no
   keys) + **LAN-direct via mDNS**. Substrate **TCP**. Hole-punching deferred.
5. **Transport key = a separate X25519 key**, minted at vault init beside the existing Ed25519
   identity (signing-only), bound by a signed attestation; auto-generate on unlock for existing
   vaults.

**Decided-not-asked:** new frontend-neutral **`softfig-net`** crate (12th workspace member;
follows the `softfig-deploy`/`softfig-onboard` precedent — logic in the crate, CLI/TUI are thin
wrappers, keeperd hosts it). Network trust ring `.softfig/peers.toml`, **distinct** from the
unlock-ACL `trust.toml` and future shared-subtree membership (three trust layers: pairing ≠
unlock ≠ subtree membership). Control-plane protobuf only this milestone. **No new VCS intents**
(M5a writes only vault-internal keys + `peers.toml`).

**Out of M5a entirely** (later milestones): data/VCS sync (M5b replica, M5c+ shared chains), the
multi-ref union-mount refactor (M5c), the collaborative `S` key ceremony + subtree membership
(M5d), the write-turn lease + `shared_pull`/conflict handling (M5e), the unlock protocol
(`k-request`/`k-response` — vault/trust-matrix's concern), the catastrophic-panic broadcast,
direct P2P hole-punching, home-server LVM replica hosting.

## The four sub-slices (dependency-ordered)

### M5a-1 — Secure pipe foundation
The bedrock: a vault transport key, the new crate, the protobuf scaffold, and a working Noise
channel over loopback TCP. Fully testable headless.
- **Vault:** add a K-wrapped X25519 transport key (generate at `vault init` alongside the Ed25519
  identity; `Session::transport_secret()` / `transport_pubkey()`; zeroize on lock; **auto-generate
  on unlock if absent** for already-initialised vaults). Mirror the existing `identity.rs` pattern
  (`aad::TRANSPORT`, `transport.key`).
- **New `softfig-net` crate** (lib); add to the workspace `members`.
- **Protobuf scaffold:** `prost` + `prost-build` (build.rs); a minimal control-plane `.proto` —
  a frame envelope + `HelloPayload` (carried in the Noise handshake) + `Ping`/`Pong`. Design the
  envelope to extend (pairing/relay messages arrive in later slices).
- **Noise transport module** (`snow`): establish `XX` (mutual auth) and `IK` (reconnect, initiator
  knows the responder's static) sessions over `TcpStream`; length-prefixed protobuf frame codec
  with Noise's 64 KiB message cap handled (chunk/reassemble).
- **Early impl decision to make + record:** sync-threaded vs `tokio` for the net layer. Lean
  **sync + threads** to match the existing daemon/IPC style (device counts are tiny); note the
  tradeoff if you diverge.
- **Done when:** `cargo test -p softfig-net -p softfig-vault` green; clippy clean; two in-process
  endpoints complete a Noise channel over loopback TCP and round-trip a protobuf `Ping`/`Pong`;
  tests cover XX handshake, IK reconnect, frame round-trip, tamper rejection, wrong-static-key
  rejection.

### M5a-2 — Pairing (SAS) + network trust ring
Turn the raw channel into a recognised peer.
- **SAS derivation** from the XX handshake hash (HKDF → short code; pick numeric digits vs word
  list and document it).
- **Ed25519 attestation:** the in-handshake `HelloPayload` carries each device's Ed25519 identity
  pubkey + an Ed25519 signature over its own X25519 static; verify the peer's (binds the two keys,
  since XX authenticates only the X25519 static).
- **`peers.toml` ring** at `<state_root>/.softfig/peers.toml`: schema (device-id = Ed25519 pubkey,
  name, X25519 transport pubkey, endpoints, attestation sig, paired-at); read/write + attestation
  verification.
- **Pairing state machine:** begin (initiator/responder) → XX handshake → compute SAS → await user
  confirm → on confirm write symmetric ring entries.
- **Done when:** two in-process keepers pair → matching SAS + symmetric ring entries; a simulated
  MITM yields mismatched SAS; tampered attestation rejected; unpair removes the entry. Tests green,
  clippy clean.

### M5a-3 — Discovery + relay
Real reachability, LAN and off-LAN.
- **mDNS** (`mdns-sd` or similar): announce `_softfig._tcp` (TXT = device-id fingerprint +
  paired/unpaired); browse + resolve peer endpoints.
- **Relay client:** maintain a standing Noise-authenticated control connection to the relay;
  register reachability by device-id; request connect-to-peer.
- **Relay server:** keeperd `[relay]` config (`enabled`, `listen`); accept registrations from
  **ring members only** (authorize against the ring — no open relay); forward ciphertext between
  two peers addressed by device-id (the relay is blind — Noise is end-to-end).
- **Connection selection:** try LAN-direct (mDNS endpoint) → fall back to relay.
- **Done when:** relay forwards an end-to-end Noise session between two clients through an
  in-process relay; non-member registration rejected; LAN/relay selection unit-tested. **mDNS
  announce/browse is a documented manual smoke step** if it can't run headless in the sandbox
  (same posture as FUSE/TUI). Tests green, clippy clean.

### M5a-4 — Daemon + CLI/IPC wiring; close M5a
Make it operable and finish the milestone per the ritual.
- **keeperd:** host a `softfig-net` instance — on unlock, load the transport key, start the mDNS
  responder, start the relay listener if configured, accept/open Noise sessions; expose pairing
  state.
- **IPC:** new local verbs `pair_begin` / `pair_confirm` / `pair_list` / `pair_remove` in
  `softfig-ipc` (+ args/replies; require Unlocked; existing `SO_PEERCRED` auth).
- **CLI:** `softfig pair <fingerprint>`, `softfig peers`, `softfig unpair <id>`; relay enabled via
  `keeper.toml [relay]`.
- **TUI:** pairing surface may be **stubbed/minimal** (note the posture; live render is a manual
  smoke step anyway).
- **Ritual close (mandatory):** append `## Update YYYY-MM-DD — landed` to
  `decision-softfig-m5a-impl.md`; refresh the program `CLAUDE.md` status table + this plan doc;
  refresh garden `spec-sync.md` + the milestone-tracker memory. The live two-device pair/relay is
  the remaining **manual real-machine smoke step** — document it.
- **Done when:** `cargo test --workspace` green, clippy clean, CLI smoke on the real binary, all
  docs refreshed, manual smoke documented.

## Session protocol (chain of prompts)

Each session works **one slice**, then hands off. At the **end** of every session:

1. **Commit** the slice's work on `main` (solo dev — commit directly on main; the user does the
   final push). One coherent commit per slice (or a small logical series).
2. **Update this plan doc** — mark the slice ✅ done, record the test count, and note any design
   deltas / decisions made (e.g. the sync-vs-tokio call, SAS encoding).
3. **Print the next slice's starter prompt** as a copy-pasteable fenced block, using the template
   below, so the user can paste it into a fresh Claude session.

The **final session (M5a-4)** does the ritual close instead of emitting a next prompt, and prints
a short "M5a complete — next is M5b (read-only replica), undesigned; design-lock it before coding"
note.

> Do **not** pre-write all four starter prompts. Generate only the *next* one, at the end of your
> session, reflecting what actually landed (real test counts, file names, any scope deltas).

### Starter-prompt template

```
Coding session for soft-fig M5a-<N> — <slice title>.

Open from ~/projects/software-config_garden (its CLAUDE.md auto-loads). This is slice <N> of 4
of the M5a (transport + pairing) impl — the foundation of M5 cross-device sync.

Read first:
- docs/m5a-impl-plan.md (this slice's scope + done-criteria + the locked design summary)
- ~/soft-fig_garden/journal/decisions/decision-softfig-m5a-impl.md (authoritative design; needs
  the garden daemon unlocked to read via FUSE — the plan doc's summary suffices if it's locked)
- Prior slices' notes in the plan doc (what landed, any deltas)

Scope (M5a-<N>): <one-paragraph recap of the slice's deliverables from the plan doc>

Conventions: solo dev → commit on main after the work (user pushes); frontend-neutral logic in
softfig-net, thin CLI/TUI wrappers; fast-Argon2 tests; cargo test/clippy --workspace must be
green with -D warnings; NO new VCS intents; network/mDNS/two-device/TUI-render are documented
manual smoke steps (no TTY/real-net in the sandbox), matching the FUSE/TUI posture.

When done: commit; update docs/m5a-impl-plan.md (mark M5a-<N> ✅ + test count + deltas); then
print the M5a-<N+1> starter prompt per the template in the plan doc. (If you are M5a-4, do the
ritual close instead.)
```

## Slice status

- [ ] **M5a-1** — secure pipe foundation
- [ ] **M5a-2** — pairing (SAS) + network trust ring
- [ ] **M5a-3** — discovery + relay
- [ ] **M5a-4** — daemon + CLI/IPC wiring; close M5a
