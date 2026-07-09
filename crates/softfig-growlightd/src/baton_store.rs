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
    fn status(&self, agent: &str) -> Option<String> {
        // A missing/unreadable baton is the clean-exit fallback (None → re-roll),
        // identical to the deferred source slice 001 shipped against.
        let raw = fs::read_to_string(self.baton_path(agent)).ok()?;
        parse_baton(&raw).status
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

        // The path stamped in the baton is exactly the file `inject.sh` cats and
        // the reader parses — the same-file-no-drift invariant the whole store rests
        // on — so a member that rewrites `baton-path:` writes the file growlightd reads.
        assert_eq!(
            abs,
            s.baton_path("a").to_str().unwrap(),
            "the stamped path is the store's own baton_path (no drift)",
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
}
