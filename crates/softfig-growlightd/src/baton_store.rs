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

use crate::drive_loop::{BatonSeeder, BatonStatusSource};
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
    /// fresher-wins fallback (+ a journal warning) so a misrouting member's terminal
    /// status is still honored until task 035 makes the member write the right file.
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
        let body = seed_baton(&self.garden_name, agent, queue, part);
        fs::write(&path, body).map_err(|e| format!("write baton {}: {e}", path.display()))
    }
}

impl BatonStatusSource for FsBatonStore {
    fn status(&self, agent: &str) -> Option<String> {
        let per_member_path = self.baton_path(agent);

        // Misroute fallback (task 042 / 035). A fleet member that rewrote its baton
        // to the LEGACY single-agent path instead of its per-member file left the
        // per-member baton as the stale spawn seed; reading THAT would misclassify
        // the exit (the 2026-07-07 `ITEM_COMPLETE` stall — the member finished but
        // growlightd read `IN_PROGRESS` from the seed). When the legacy baton is
        // FRESHER than the per-member file AND is stamped for THIS agent, honor it
        // instead and WARN — so a misrouting fleet-of-one still continues, and the
        // misroute is diagnosable from the journal. The real fix (the member writes
        // its own path deterministically) is task 035; this keeps the fleet
        // self-sustaining until that lands. The check is precise — it fires ONLY on
        // an actual misroute (in normal operation the member's per-member write is
        // always the fresher of the two), so a genuinely-old single-agent baton left
        // on disk never shadows a live member's real status.
        if let Some(legacy_path) = self.legacy_baton_path() {
            if let Ok(legacy_raw) = fs::read_to_string(&legacy_path) {
                if frontmatter_agent(&legacy_raw).as_deref() == Some(agent)
                    && legacy_is_fresher(&legacy_path, &per_member_path)
                {
                    eprintln!(
                        "softfig-growlightd: fleet: {agent} baton misrouted to the legacy \
                         single-agent path {} (task 035) — honoring it as the terminal status \
                         over the stale per-member {}",
                        legacy_path.display(),
                        per_member_path.display(),
                    );
                    return parse_baton(&legacy_raw).status;
                }
            }
        }

        // A missing/unreadable baton is the clean-exit fallback (None → re-roll),
        // identical to the deferred source slice 001 shipped against.
        let raw = fs::read_to_string(&per_member_path).ok()?;
        parse_baton(&raw).status
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
fn seed_baton(garden_name: &str, agent: &str, queue: &str, part: &str) -> String {
    // The full status vocabulary, sourced from the single shared list so the seed
    // can never drift from the classifier (cosmetic gap #3). A fleet member may
    // legitimately write any of these.
    let statuses = softfig_ipc::baton::STATUS_VOCABULARY.join(" / ");
    format!(
        "---\n\
         loop: {garden_name}\n\
         mode: fleet\n\
         agent: {agent}\n\
         status: IN_PROGRESS\n\
         item: {part}\n\
         queue: {queue}\n\
         iteration: 0\n\
         ---\n\n\
         # NEXT ACTION\n\
         You are fleet member `{agent}`, assigned backlog item `{part}` on queue `{queue}`.\n\
         Read its spec (the item doc under `growlight/backlog/`) and the protocol injected\n\
         above, reseed this baton from that spec (mission + finish criteria + the first\n\
         slice/step), then execute one coherent chunk of work. Hand off by rewriting THIS\n\
         baton: set `status:` to the right value from the growlight baton vocabulary\n\
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
        assert_eq!(s.status("builder"), None, "no baton yet reads as None");

        // Seed it: the member boots WITH a baton (no `(no baton yet)`), and the
        // reader reads back the seed's IN_PROGRESS continue status.
        s.seed("builder", "queue:build", "001-foo").expect("seeds");
        assert_eq!(
            s.status("builder").as_deref(),
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
            s.status("a1").as_deref(),
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
        assert_eq!(s.status("a").as_deref(), Some("IN_PROGRESS"), "seed reads IN_PROGRESS");

        // The member wrote its REAL terminal handoff to the legacy path instead.
        let legacy = legacy_path(tmp.path());
        std::fs::write(
            &legacy,
            "---\nmode: fleet\nagent: a\nstatus: ITEM_COMPLETE\nitem: 020\niteration: 4\n---\n# NEXT ACTION\ndone\n",
        )
        .unwrap();
        set_mtime(&s.baton_path("a"), 1_000); // seed: older
        set_mtime(&legacy, 2_000); // misrouted terminal handoff: fresher

        assert_eq!(
            s.status("a").as_deref(),
            Some("ITEM_COMPLETE"),
            "the fresher agent-stamped legacy write is honored over the stale per-member seed",
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

        assert_eq!(
            s.status("a").as_deref(),
            Some("ITEM_COMPLETE"),
            "the fresher per-member write wins — the stale legacy baton is ignored",
        );
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
            s.status("b").as_deref(),
            Some("IN_PROGRESS"),
            "a legacy write stamped for agent `a` is not honored when polling agent `b`",
        );
    }
}
