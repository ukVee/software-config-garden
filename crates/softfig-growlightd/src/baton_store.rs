//! The per-member baton store (`fleet-loop-spin` slice 002) — the WRITE + READ
//! sides of `agents/<id>/baton.md`, the durable carried state slice 001 reads on
//! exit.
//!
//! ## The gap this closes
//!
//! [`crate::preapproval`] wires only the *injection* side: each agent's generated
//! `inject.sh` does `cat agents/<id>/baton.md || '(no baton yet)'`. Nothing ever
//! **seeded** that file on spawn and nothing **read it back** on exit, so a fleet
//! member booted stateless (`(no baton yet)`) and slice 001's
//! [`crate::drive_loop::BatonStatusSource`] had no real source — it shipped as the
//! deferred [`crate::drive_loop::DeferredBatonStatus`] (always `None`). This module
//! is that source, plus the seeder that gives an assigned member its baton.
//!
//! ## One file, two halves, no drift
//!
//! [`FsBatonStore`] owns the runtime `agents/` namespace and derives the per-agent
//! baton path through [`crate::preapproval::agent_paths`] — the SAME scheme the
//! pre-approval generator and fleet assembly use, so the file the seeder writes,
//! the file `inject.sh` cats, and the file the reader parses can never diverge.
//! `Arc<FsBatonStore>` implements BOTH seams (mirroring `Arc<ClaudeBackend>`
//! standing behind health + budget + baton): the live assembly builds one store
//! and clones it into the [`BatonSeeder`](crate::drive_loop::BatonSeeder) box and
//! the [`BatonStatusSource`](crate::drive_loop::BatonStatusSource) box.
//!
//! ## Seed vs carry (the re-roll contract)
//!
//! The drive loop seeds **only on a fresh start** — the step-3 spawn of an
//! un-registered member, where the claimed `(queue, part)` is known. A **re-roll**
//! ([`crate::supervisor::Supervisor::tick`]) re-spawns through the backend WITHOUT
//! re-seeding, so the member's own write-back from the prior iteration is what its
//! next session boots from — curated state carried across iterations, exactly like
//! the single-agent loop's baton survives its `claude -p` re-invocations. The seed
//! is therefore the fleet analog of the single-agent loop's bootstrap reseed: it
//! names the assigned item and points the agent at the spec to flesh out (the agent
//! rewrites the baton at its handoff, protocol step 5).

use std::fs;
use std::path::{Path, PathBuf};

use softfig_ipc::baton::parse_baton;

use crate::drive_loop::{BatonRead, BatonSeeder, BatonStatusSource};
use crate::preapproval::agent_paths;

/// The filesystem-backed per-member baton store over the runtime `agents/`
/// namespace (`$XDG_CONFIG_HOME/softfig/growlight/agents/` in production — the
/// same dir [`crate::preapproval::PreApproval`] writes each agent's `loop.json`
/// into, derived in [`crate::fleet::assemble_fleet`]). Holds the dir + the garden
/// name (a cosmetic `loop:` tag in the seed, matching the single-agent baton's
/// frontmatter).
#[derive(Debug, Clone)]
pub struct FsBatonStore {
    agents_dir: PathBuf,
    garden_name: String,
}

impl FsBatonStore {
    /// Build a store over `agents_dir` (the runtime per-agent namespace) tagging
    /// seeds with `garden_name` (the garden root's file name, purely cosmetic).
    pub fn new(agents_dir: impl Into<PathBuf>, garden_name: impl Into<String>) -> Self {
        Self {
            agents_dir: agents_dir.into(),
            garden_name: garden_name.into(),
        }
    }

    /// This agent's baton path under `agents/<id>/baton.md` — the one file the
    /// seeder writes, `inject.sh` cats, and the reader parses.
    fn baton_path(&self, agent: &str) -> PathBuf {
        agent_paths(&self.agents_dir, agent).baton
    }

    /// The LEGACY single-agent baton path — `<growlight>/baton.md`, one level ABOVE
    /// the per-agent `agents/` namespace. A fleet member that follows the
    /// single-agent protocol's "rewrite THIS baton" WITHOUT knowing its per-member
    /// file writes HERE by mistake (task 035), so growlightd's read of the
    /// per-member path finds only the stale spawn seed and misclassifies the exit —
    /// the 2026-07-07 `ITEM_COMPLETE`-into-a-stall bug (task 042). Read as a
    /// fresher-wins fallback (+ a misroute diagnostic the caller routes through the
    /// tick log's exit entry-edge, so a latched member warns once — not once per
    /// tick) so a misrouting member's terminal status is still honored until task 035
    /// makes the member write the right file.
    fn legacy_baton_path(&self) -> Option<PathBuf> {
        self.agents_dir.parent().map(|p| p.join("baton.md"))
    }
}

impl BatonSeeder for FsBatonStore {
    fn seed(&self, agent: &str, queue: &str, part: &str) -> Result<(), String> {
        let path = self.baton_path(agent);
        // A fresh start on the SAME item keeps the member's own baton: after a
        // growlightd restart the boot reaper resets the orphaned-`active` item to
        // `queued`, so the loop resumes it through this fresh-start path — but the
        // baton on disk is the member's curated write-back from its last
        // iteration (branch, done criteria, next step), which is exactly the
        // carry-forward a re-roll would have preserved. Overwriting it with the
        // generic template would throw that context away on every daemon bounce
        // (the task-032 phantom stops made bounces a live concern). A baton for a
        // DIFFERENT item (or none, or unparseable) seeds fresh as before.
        if let Ok(existing) = fs::read_to_string(&path) {
            if parse_baton(&existing).item.as_deref() == Some(part) {
                return Ok(());
            }
        }
        // The agent dir is created by the pre-approval generator on spawn, but the
        // seed is written BEFORE that spawn (so the SessionStart hook finds a
        // baton), so create it here too — idempotent with `generate`'s create.
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .map_err(|e| format!("create agent dir {}: {e}", dir.display()))?;
        }
        let body = seed_baton(&self.garden_name, agent, queue, part, &path);
        fs::write(&path, body).map_err(|e| format!("write baton {}: {e}", path.display()))
    }
}

impl BatonStatusSource for FsBatonStore {
    fn status(&self, agent: &str) -> BatonRead {
        let per_member_path = self.baton_path(agent);
        let per_member_raw = fs::read_to_string(&per_member_path).ok();

        // Misroute fallback (task 042 / 035). A fleet member that rewrote its baton
        // to the LEGACY single-agent path instead of its per-member file left the
        // per-member baton as the stale spawn seed; reading THAT would misclassify
        // the exit (the 2026-07-07 `ITEM_COMPLETE` stall — the member finished but
        // growlightd read `IN_PROGRESS` from the seed). Honor the legacy baton over
        // the stale seed ONLY when every guard holds, so the fallback fires on an
        // ACTUAL misroute and never lets a stray single-agent baton shadow a live
        // member's real status:
        //   - stamped for THIS agent (`agent:` frontmatter) — one member's misroute
        //     is never read as another's;
        //   - carries a `status:` — a truncated legacy baton (frontmatter but no
        //     status) falls THROUGH to the per-member file instead of forcing a
        //     re-roll (hardening (b));
        //   - FRESHER than the per-member file — the member's most recent write
        //     landed on the legacy path (in normal operation the per-member write is
        //     always the fresher of the two);
        //   - does not CONTRADICT the per-member seed's `item:` — a real misroute
        //     writes the member's CURRENT item to the wrong path, so when BOTH
        //     sides name an item they must agree; a genuinely-stale single-agent
        //     baton for OTHER work names a different item and must not shadow,
        //     even if fresher (hardening (a) — correctness stops resting on the
        //     mtime invariant alone). An item ABSENT on either side is
        //     match-UNKNOWN, not a mismatch (task 044): the fleet protocol's
        //     step-7 "SHORT terminal baton (status ITEM_COMPLETE + one line)"
        //     legitimately omits `item:`, and that terminal handoff is exactly
        //     the misrouted write this fallback exists to honor — treating the
        //     omission as a mismatch silently read the stale seed's IN_PROGRESS
        //     and relapsed the 042 stall. The agent-stamp + freshness checks
        //     above stay the load-bearing guards in the unknown case.
        // The misroute is RETURNED as a diagnostic (not logged here): the drive loop
        // routes it through the tick log's exit entry-edge dedup, so a member latched
        // `Exited` and re-read every ~1s tick warns ONCE, not once per tick (task
        // 042; the eMMC/log-churn fix). The real fix (the member writes its own path
        // deterministically) is task 035; this keeps the fleet self-sustaining until
        // that lands.
        if let Some(legacy_path) = self.legacy_baton_path() {
            if let Ok(legacy_raw) = fs::read_to_string(&legacy_path) {
                let legacy = parse_baton(&legacy_raw);
                // Hardening (a): the seed `item:` to cross-check against (absent when
                // the per-member file is missing/unparseable → the guard is
                // inapplicable and defers to the agent-stamp + fresher checks).
                let seed_item = per_member_raw
                    .as_deref()
                    .and_then(|raw| parse_baton(raw).item);
                // Reject only a POSITIVE mismatch (both sides name an item and they
                // differ); either side silent → match-unknown, defer to the guards
                // above (see the block comment — task 044).
                let item_matches = match (seed_item.as_deref(), legacy.item.as_deref()) {
                    (Some(seed), Some(legacy_item)) => seed == legacy_item,
                    _ => true,
                };
                if frontmatter_agent(&legacy_raw).as_deref() == Some(agent)
                    && legacy.status.is_some()
                    && legacy_is_fresher(&legacy_path, &per_member_path)
                    && item_matches
                {
                    return BatonRead {
                        status: legacy.status,
                        // The NEXT ACTION comes from the SAME (legacy) baton the status
                        // was read from, so the spin guard compares like with like even
                        // through the misroute fallback (task 038).
                        next_action: legacy.next_action,
                        misroute: Some((
                            legacy_path.display().to_string(),
                            per_member_path.display().to_string(),
                        )),
                    };
                }
            }
        }

        // A missing/unreadable baton is the clean-exit fallback (None → re-roll),
        // identical to the deferred source slice 001 shipped against. Parse ONCE and
        // carry both the status and the NEXT ACTION (the spin-guard progress signal,
        // task 038) off the same read.
        let view = per_member_raw.as_deref().map(parse_baton).unwrap_or_default();
        BatonRead {
            status: view.status,
            next_action: view.next_action,
            misroute: None,
        }
    }
}

/// The `agent:` frontmatter field of a baton, if present — used to confirm a
/// legacy-path write belongs to the agent being polled before falling back to it,
/// so one member's misroute can never be read as another member's status. Kept
/// local (the shared [`parse_baton`] intentionally does not surface `agent:`,
/// which single-agent batons omit).
fn frontmatter_agent(baton: &str) -> Option<String> {
    let mut lines = baton.lines();
    if lines.next().map(str::trim) != Some("---") {
        return None;
    }
    for line in lines {
        let line = line.trim();
        if line == "---" {
            break;
        }
        if let Some(v) = line.strip_prefix("agent:") {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Whether `legacy` was modified strictly AFTER `per_member` — the misroute signal
/// (the member's most recent baton write landed on the legacy path). A
/// missing/unreadable per-member file counts as older than any existing legacy
/// write; an unreadable legacy mtime never wins (no fallback).
fn legacy_is_fresher(legacy: &Path, per_member: &Path) -> bool {
    let mtime = |p: &Path| fs::metadata(p).and_then(|md| md.modified()).ok();
    match (mtime(legacy), mtime(per_member)) {
        (Some(l), Some(pm)) => l > pm,
        (Some(_), None) => true,
        _ => false,
    }
}

/// The per-member seed baton (pure) — the fleet analog of the single-agent loop's
/// bootstrap reseed (`softfig-cli`'s `seed_baton`), but keyed to the already-claimed
/// item instead of "read the queue and pick one". `status: IN_PROGRESS` so a member
/// that exits cleanly without rewriting the baton still re-rolls (a continue
/// status); the `item:`/`queue:` frontmatter is the slice's "reflects the claimed
/// item"; the NEXT ACTION + READ FIRST point the agent at the spec to flesh the
/// baton out from (mission + finish criteria live in the item doc, which the agent
/// reads — growlightd does not embed them, matching the single-agent reseed where
/// the agent fills them in on its first iteration).
fn seed_baton(garden_name: &str, agent: &str, queue: &str, part: &str, baton_path: &Path) -> String {
    // The full status vocabulary, sourced from the single shared list so the seed
    // can never drift from the classifier (cosmetic gap #3). A fleet member may
    // legitimately write any of these.
    let statuses = softfig_ipc::baton::STATUS_VOCABULARY.join(" / ");
    // The absolute per-member baton path, stamped into BOTH a `baton-path:`
    // frontmatter field and a prose "YOUR BATON FILE" anchor so the member knows
    // deterministically which file to rewrite at handoff — it can never guess the
    // legacy single-agent root `baton.md` and silently misroute its terminal
    // status (task 035). This is the WRITE-side root cure that makes 042's
    // read-side legacy fallback belt-and-suspenders.
    let baton_path = baton_path.display().to_string();
    format!(
        "---\n\
         loop: {garden_name}\n\
         mode: fleet\n\
         agent: {agent}\n\
         status: IN_PROGRESS\n\
         item: {part}\n\
         queue: {queue}\n\
         iteration: 0\n\
         baton-path: {baton_path}\n\
         ---\n\n\
         > YOUR BATON FILE — rewrite THIS exact path at every handoff: {baton_path}\n\n\
         # NEXT ACTION\n\
         You are fleet member `{agent}`, assigned backlog item `{part}` on queue `{queue}`.\n\
         Read its spec (the item doc under `growlight/backlog/`) and the protocol injected\n\
         above, reseed this baton from that spec (mission + finish criteria + the first\n\
         slice/step), then execute one coherent chunk of work. Hand off by rewriting your\n\
         baton at the path in `baton-path:` / the 'YOUR BATON FILE' anchor above (your\n\
         per-member `agents/<id>/baton.md` — NEVER the legacy root `baton.md`): set\n\
         `status:` to the right value from the growlight baton vocabulary\n\
         ({statuses}) — `IN_PROGRESS` carries the SAME part forward; at an item boundary\n\
         (`ITEM_COMPLETE` / `ITEM_DEFERRED`) run `set_item_status` then EXIT and the\n\
         orchestrator claims your next part (a fleet member never self-pulls).\n\n\
         # MISSION\n\
         Drive backlog item `{part}` to completion, handing off via this baton instead of\n\
         `/compact`.\n\n\
         # FINISH CRITERIA\n\
         (reseed from the item's spec on your first iteration)\n\n\
         # READ FIRST\n\
         - the item doc for `{part}` (its mission + finish criteria)\n\
         - `growlight/backlog/CLAUDE.md` — the queue table (status + order)\n\
         - `growlight/protocol.md` — your operating contract\n\n\
         # STATE\n\
         Seeded by growlightd on spawn (fleet member `{agent}`, item `{part}`).\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Arc;

    fn store(dir: &Path) -> Arc<FsBatonStore> {
        Arc::new(FsBatonStore::new(dir.join("agents"), "garden"))
    }

    #[test]
    fn seed_then_read_back_round_trips_the_status() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());

        // No baton yet → the clean-exit fallback (None → re-roll), exactly like the
        // deferred source slice 001 shipped against.
        assert_eq!(s.status("builder").status, None, "no baton yet reads as None");

        // Seed it: the member boots WITH a baton (no `(no baton yet)`), and the
        // reader reads back the seed's IN_PROGRESS continue status.
        s.seed("builder", "queue:build", "001-foo").expect("seeds");
        assert_eq!(
            s.status("builder").status.as_deref(),
            Some("IN_PROGRESS"),
            "a seeded member reads back its continue status",
        );

        // The seed reflects the claimed item: id + queue in the frontmatter, and a
        // runnable NEXT ACTION naming both.
        let raw = fs::read_to_string(s.baton_path("builder")).unwrap();
        let view = parse_baton(&raw);
        assert_eq!(view.item.as_deref(), Some("001-foo"), "seed names the claimed item");
        assert!(raw.contains("queue: queue:build"), "seed names the claimed queue");
        assert!(
            view.next_action.is_some_and(|na| na.contains("001-foo") && na.contains("queue:build")),
            "NEXT ACTION names the assigned item + queue",
        );
    }

    #[test]
    fn seed_next_action_enumerates_the_full_status_vocabulary() {
        // Cosmetic gap #3: the seed lists EVERY status an agent may write, sourced
        // from the shared `softfig-ipc` vocabulary so it can't drift.
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a1", "default", "t1").expect("seeds");
        let na = parse_baton(&fs::read_to_string(s.baton_path("a1")).unwrap())
            .next_action
            .expect("seed has a NEXT ACTION");
        for status in softfig_ipc::baton::STATUS_VOCABULARY {
            assert!(na.contains(status), "NEXT ACTION must list {status}");
        }
    }

    #[test]
    fn seed_stamps_the_per_member_baton_path() {
        // 035 write-side determinism: the member must be told its OWN absolute
        // baton path — in the `baton-path:` frontmatter AND a prose "YOUR BATON
        // FILE" anchor — so it can never guess the legacy single-agent root
        // `baton.md` and silently misroute its terminal status. Guards finish
        // criteria #1/#3 (042 owns the read-side fallback; this is the write cure).
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a", "default", "035").expect("seeds");

        let abs = s.baton_path("a").to_str().unwrap().to_string();
        assert!(abs.ends_with("/agents/a/baton.md"), "sanity: per-member baton path");

        let raw = fs::read_to_string(s.baton_path("a")).unwrap();
        assert!(
            raw.contains(&format!("baton-path: {abs}")),
            "seed stamps the absolute baton path in a `baton-path:` frontmatter field",
        );
        assert!(
            raw.contains(&format!(
                "YOUR BATON FILE — rewrite THIS exact path at every handoff: {abs}"
            )),
            "seed stamps the absolute baton path in a prose anchor near the top of the body",
        );
        assert!(
            raw.contains("NEVER the legacy root `baton.md`"),
            "the NEXT ACTION steers the member away from the legacy root baton.md",
        );
        // The old, path-less "rewriting THIS baton" phrasing is what let a member
        // guess the legacy location — it must be gone.
        assert!(
            !raw.contains("rewriting THIS"),
            "seed no longer uses the ambiguous path-less 'rewriting THIS baton' phrasing",
        );
    }

    #[test]
    fn a_same_item_seed_keeps_the_members_own_baton() {
        // The restart-resume path: growlightd bounces, the boot reaper resets the
        // orphaned-`active` item to `queued`, and the loop fresh-starts the member
        // on the SAME item — through `seed`. The baton on disk is the member's
        // curated write-back from its last iteration; a same-item seed must keep
        // it (it IS the carry-forward), while a different-item seed replaces it.
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a1", "default", "020").expect("seeds");

        let curated = "---\nstatus: IN_PROGRESS\nitem: 020\n---\n\
                       # NEXT ACTION\nslice B on branch feat/020 — design is locked.\n";
        fs::write(s.baton_path("a1"), curated).unwrap();

        s.seed("a1", "default", "020").expect("same-item re-seed is a keep");
        let kept = fs::read_to_string(s.baton_path("a1")).unwrap();
        assert_eq!(kept, curated, "a same-item seed preserves the curated baton");

        s.seed("a1", "default", "021").expect("new-item seed writes fresh");
        let fresh = parse_baton(&fs::read_to_string(s.baton_path("a1")).unwrap());
        assert_eq!(
            fresh.item.as_deref(),
            Some("021"),
            "a different-item seed replaces the stale baton",
        );
    }

    #[test]
    fn read_back_returns_the_agents_own_write_back() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a1", "default", "t1").expect("seeds");

        // The agent rewrites its baton at handoff (protocol step 5) — the store
        // reads back THAT terminal status, which is what slice 001's poll consumes.
        let rewritten =
            "---\nstatus: QUEUE_EMPTY\nitem: t1\niteration: 3\n---\n# NEXT ACTION\ndrained\n";
        fs::write(s.baton_path("a1"), rewritten).unwrap();
        assert_eq!(
            s.status("a1").status.as_deref(),
            Some("QUEUE_EMPTY"),
            "the read-back is the agent's own terminal status, not the seed",
        );
    }

    #[test]
    fn seed_carry_then_reseed_a_new_item_overwrites() {
        // A fresh start on a NEW item overwrites the prior baton (new work, fresh
        // seed); the carry-across-re-rolls property is the drive loop NOT calling
        // seed on a re-roll (proven in drive_loop), not anything the store enforces.
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a1", "default", "t1").expect("seeds");
        // Agent worked t1 then it drained; later a fresh start assigns t2.
        s.seed("a1", "default", "t2").expect("reseeds");
        let view = parse_baton(&fs::read_to_string(s.baton_path("a1")).unwrap());
        assert_eq!(view.item.as_deref(), Some("t2"), "a fresh seed reflects the new item");
        assert_eq!(view.status.as_deref(), Some("IN_PROGRESS"));
    }

    #[test]
    fn seed_creates_the_agent_dir_when_absent() {
        // The seed runs BEFORE the pre-approval generator's create_dir_all on a
        // fresh start, so it must create the per-agent dir itself.
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        assert!(!s.baton_path("new").parent().unwrap().exists());
        s.seed("new", "default", "t9").expect("creates the dir + seeds");
        assert!(s.baton_path("new").exists(), "the baton was written under a freshly-created dir");
    }

    #[test]
    fn seed_fails_closed_when_the_dir_cannot_be_created() {
        // A FILE where the agents dir should be → create_dir_all under it fails →
        // the seed errors, which the drive loop turns into a fail-closed no-spawn.
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("agents");
        fs::write(&blocker, b"x").unwrap();
        let s = Arc::new(FsBatonStore::new(&blocker, "garden"));
        assert!(s.seed("a1", "default", "t1").is_err(), "an un-creatable dir fails closed");
    }

    /// The legacy single-agent baton lives one level ABOVE the `agents/` namespace.
    fn legacy_path(dir: &Path) -> PathBuf {
        dir.join("baton.md")
    }
    /// Stamp a file's mtime deterministically so the fresher-wins comparison is not
    /// at the mercy of filesystem timestamp resolution.
    fn set_mtime(path: &Path, secs: u64) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
            .unwrap();
    }

    /// TASK 042 / 035 — the misroute fallback. A fleet member that rewrote its
    /// terminal baton to the LEGACY single-agent path (the 2026-07-07 stall) left
    /// its per-member file as the stale spawn seed. When the legacy baton is fresher
    /// AND stamped for this agent, the store honors it — so growlightd reads the
    /// member's real `ITEM_COMPLETE` instead of the seed's `IN_PROGRESS` and the
    /// fleet-of-one continues.
    #[test]
    fn a_fresher_legacy_baton_stamped_for_this_agent_is_honored_over_the_stale_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());

        // The per-member file is the stale spawn seed (IN_PROGRESS).
        s.seed("a", "default", "020").expect("seeds");
        assert_eq!(s.status("a").status.as_deref(), Some("IN_PROGRESS"), "seed reads IN_PROGRESS");

        // The member wrote its REAL terminal handoff to the legacy path instead.
        let legacy = legacy_path(tmp.path());
        std::fs::write(
            &legacy,
            "---\nmode: fleet\nagent: a\nstatus: ITEM_COMPLETE\nitem: 020\niteration: 4\n---\n# NEXT ACTION\ndone\n",
        )
        .unwrap();
        set_mtime(&s.baton_path("a"), 1_000); // seed: older
        set_mtime(&legacy, 2_000); // misrouted terminal handoff: fresher

        let read = s.status("a");
        assert_eq!(
            read.status.as_deref(),
            Some("ITEM_COMPLETE"),
            "the fresher agent-stamped legacy write is honored over the stale per-member seed",
        );
        // The misroute is SURFACED (not logged per-call): the drive loop routes this
        // through the tick log's exit entry-edge so it warns once, not once per tick.
        assert!(
            read.misroute.is_some(),
            "honoring the legacy baton surfaces the misroute diagnostic to the caller",
        );
    }

    /// The fallback is PRECISE: a live member's own per-member write (the normal
    /// path) is always the freshest of the two, so an old legacy baton lying around
    /// on disk never shadows the real status.
    #[test]
    fn a_stale_legacy_baton_never_shadows_a_fresh_per_member_write() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a", "default", "020").expect("seeds");

        // A member that DID write its own per-member baton, freshly.
        std::fs::write(
            s.baton_path("a"),
            "---\nmode: fleet\nagent: a\nstatus: ITEM_COMPLETE\nitem: 020\n---\n# NEXT ACTION\ndone\n",
        )
        .unwrap();
        // A stale legacy baton (older) also stamped for this agent.
        let legacy = legacy_path(tmp.path());
        std::fs::write(&legacy, "---\nagent: a\nstatus: QUEUE_EMPTY\n---\n").unwrap();
        set_mtime(&legacy, 1_000); // older
        set_mtime(&s.baton_path("a"), 2_000); // the real write: fresher

        let read = s.status("a");
        assert_eq!(
            read.status.as_deref(),
            Some("ITEM_COMPLETE"),
            "the fresher per-member write wins — the stale legacy baton is ignored",
        );
        assert!(read.misroute.is_none(), "the normal per-member read reports no misroute");
    }

    /// One member's misroute can never be read as ANOTHER member's status: the
    /// legacy baton is honored only when its `agent:` frontmatter matches the agent
    /// being polled.
    #[test]
    fn a_legacy_baton_for_a_different_agent_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("b", "default", "021").expect("seeds"); // b's per-member seed

        // A fresher legacy baton — but stamped for agent `a`, not `b`.
        let legacy = legacy_path(tmp.path());
        std::fs::write(&legacy, "---\nagent: a\nstatus: ITEM_COMPLETE\n---\n").unwrap();
        set_mtime(&s.baton_path("b"), 1_000);
        set_mtime(&legacy, 2_000);

        assert_eq!(
            s.status("b").status.as_deref(),
            Some("IN_PROGRESS"),
            "a legacy write stamped for agent `a` is not honored when polling agent `b`",
        );
    }

    /// Hardening (a) — the item cross-check. A fresher, agent-stamped legacy baton
    /// that names a DIFFERENT item than the per-member seed is a genuinely-stale
    /// single-agent baton from OTHER work, not this member's misrouted handoff. It
    /// must NOT shadow the per-member status even though it is fresher: correctness
    /// no longer rests on the mtime invariant alone.
    #[test]
    fn a_fresher_legacy_baton_for_a_different_item_is_not_honored() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a", "default", "020").expect("seeds"); // per-member seed names item 020

        // A fresher, agent-stamped legacy baton — but for item 099, not 020.
        let legacy = legacy_path(tmp.path());
        std::fs::write(
            &legacy,
            "---\nmode: fleet\nagent: a\nstatus: ITEM_COMPLETE\nitem: 099\n---\n# NEXT ACTION\ndone\n",
        )
        .unwrap();
        set_mtime(&s.baton_path("a"), 1_000); // seed: older
        set_mtime(&legacy, 2_000); // stale single-agent leftover: fresher, wrong item

        let read = s.status("a");
        assert_eq!(
            read.status.as_deref(),
            Some("IN_PROGRESS"),
            "a fresher legacy baton for a DIFFERENT item does not shadow the per-member seed",
        );
        assert!(read.misroute.is_none(), "a mismatched-item legacy baton is not a misroute");
    }

    /// TASK 044 — the protocol-shaped SHORT terminal baton. Fleet protocol step 7
    /// says "write a SHORT terminal baton (status ITEM_COMPLETE + one line)", so a
    /// misrouted terminal handoff plausibly OMITS `item:` — in exactly the terminal
    /// case the fallback exists to honor. An absent legacy `item:` is
    /// match-UNKNOWN (the agent-stamp + freshness guards carry the decision), not
    /// a mismatch: before this, `None != Some(seed)` silently failed the guard —
    /// no fallback AND no misroute diagnostic — so growlightd read the stale
    /// seed's IN_PROGRESS and the 042 stall relapsed.
    #[test]
    fn a_terminal_legacy_baton_missing_its_item_is_still_honored_and_diagnosed() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a", "default", "020").expect("seeds"); // per-member seed names item 020

        // The step-7 SHORT terminal handoff, misrouted to the legacy path:
        // agent-stamped, carries a status, fresher — but no `item:` line at all.
        let legacy = legacy_path(tmp.path());
        std::fs::write(
            &legacy,
            "---\nmode: fleet\nagent: a\nstatus: ITEM_COMPLETE\n---\n# NEXT ACTION\nfinished.\n",
        )
        .unwrap();
        set_mtime(&s.baton_path("a"), 1_000); // seed: older
        set_mtime(&legacy, 2_000); // misrouted terminal handoff: fresher

        let read = s.status("a");
        assert_eq!(
            read.status.as_deref(),
            Some("ITEM_COMPLETE"),
            "an item-less terminal legacy baton is honored (match-unknown, not mismatch)",
        );
        assert!(
            read.misroute.is_some(),
            "and the misroute diagnostic is surfaced — never a silent stale-seed read",
        );
    }

    /// Hardening (b) — the status-less fall-through. A truncated legacy baton with
    /// frontmatter but NO `status:` (a member killed mid-write) must fall THROUGH to
    /// the per-member file rather than force a re-roll on a `None` legacy status.
    #[test]
    fn a_status_less_legacy_baton_falls_through_to_the_per_member_file() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.seed("a", "default", "020").expect("seeds");

        // A fresher, agent-stamped, same-item legacy baton — but truncated: no status.
        let legacy = legacy_path(tmp.path());
        std::fs::write(&legacy, "---\nmode: fleet\nagent: a\nitem: 020\n---\n# NEXT ACTION\n").unwrap();
        set_mtime(&s.baton_path("a"), 1_000);
        set_mtime(&legacy, 2_000);

        let read = s.status("a");
        assert_eq!(
            read.status.as_deref(),
            Some("IN_PROGRESS"),
            "a status-less legacy baton falls through to the per-member file, not a re-roll",
        );
        assert!(read.misroute.is_none(), "a status-less legacy baton is not honored as a misroute");
    }
}
