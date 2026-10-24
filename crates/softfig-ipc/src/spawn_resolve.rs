//! Baton → grant resolution: the per-spawn helper that reads a member's seeded
//! baton, walks the item's doc chain with [`item_doc_candidates`], loads each
//! doc off disk, and calls [`grants::resolve`]. One function the opencode spawn
//! path (`folder-grants` slice 002), the `softfig growlight grants` dry-run verb
//! (slice 005), and the integration tests all share, so none can disagree about
//! how the chain is partitioned into milestone + slice.
//!
//! Pure over `std::fs`: tests use a tempdir garden; nothing here touches
//! keeperd or opencode.
//!
//! Every refusal in [`SpawnResolveError`] is **deterministic** — same inputs,
//! same result — so the opencode spawn path never re-rolls on one (spec §8).

use std::fs;
use std::path::{Path, PathBuf};

use crate::baton::parse_baton;
use crate::grants::{self, GitProbe, Grant, GrantDoc, GrantError, ProjectRepo, ResolveInputs};
use crate::model_choice::{item_doc_candidates, Backend};

/// Context the spawn resolver needs beyond the baton content and garden root.
/// Mirrors the subset of [`ResolveInputs`] that the caller is responsible for;
/// the chain and slice doc are filled in from the baton + garden layout.
#[derive(Debug)]
pub struct SpawnResolveCtx<'a> {
    /// The garden root (what [`item_doc_candidates`] resolves the chain against).
    pub garden_root: &'a Path,
    /// `$HOME` for `~` expansion and the ceiling (§6).
    pub home: &'a Path,
    /// How the item's queue binds to a local repo (§4). The caller resolves
    /// this from the queue registry; this module does not look at keeperd.
    pub project_repo: ProjectRepo<'a>,
    /// Which backend runs this spawn (§9: a remote `$REPO` refuses an opencode
    /// spawn before any lines resolve).
    pub backend: Backend,
    /// Extra ceiling entries from `config/growlight.toml`'s
    /// `grant_ceiling_extra` (§6). Add-only.
    pub extra_ceiling: &'a [PathBuf],
    /// keeperd's state root; `None` leaves it out of the ceiling.
    pub keeperd_state_root: Option<&'a Path>,
    /// keeperd's vault key material path; `None` leaves it out.
    pub keeperd_vault_root: Option<&'a Path>,
    /// softfig's runtime root (`$XDG_CONFIG_HOME/softfig`), floor-managed per
    /// §6. `None` leaves it out.
    pub softfig_runtime_root: Option<&'a Path>,
    /// The garden mount path; `None` leaves it out of the ceiling.
    pub garden_mount: Option<&'a Path>,
}

/// Every fail-closed refusal in the spawn-resolve path. A refusal parks the
/// spawn and alerts once (§8); none of these are ever retried.
#[derive(Debug, thiserror::Error)]
pub enum SpawnResolveError {
    /// The item's doc chain could not be enumerated — most commonly two docs
    /// share one slice/task number (review 042 G74-2). The chain lookup fails
    /// closed rather than taking the first match.
    #[error("item `{item}`: doc chain could not be enumerated: {reason}")]
    DocChain { item: String, reason: String },
    /// A doc the chain names could not be read from disk.
    #[error("item doc `{}`: {source}", path.display())]
    DocRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A doc the chain named vanished between enumeration and read (defensive;
    /// [`item_doc_candidates`] only emits paths it found).
    #[error("item doc `{}`: file not found at resolve time", path.display())]
    DocMissing { path: PathBuf },
    /// A grant line in the chain failed one of §5's fail-closed checks.
    #[error(transparent)]
    Grant(#[from] GrantError),
}

/// What [`resolve_from_baton`] returns on success — the grants list plus the
/// item + slice they were resolved for, so `grants.md` and `growlight status`
/// can name the slice the resolution was for (spec §7 "Member context").
#[derive(Debug)]
pub struct SpawnResolution {
    /// The ordered, resolved grant list — floor-only (empty) when the baton
    /// names no item (§5 "No baton item"). Includes the trailing ceiling
    /// denies.
    pub grants: Vec<Grant>,
    /// The item slug the chain was resolved from — `None` when the baton was
    /// pre-claim (empty `item:`) and `grants` is therefore empty.
    pub item: Option<String>,
    /// The active slice this chain was resolved for, if any — `None` for a
    /// task, a milestone close-out, or a pre-claim resolution.
    pub slice: Option<String>,
}

/// Resolve the grants a member should spawn with, from its seeded baton.
///
/// Reads the item + slice from the baton frontmatter via [`parse_baton`], walks
/// the garden with [`item_doc_candidates`], reads each doc through
/// `std::fs::read_to_string`, partitions the result into the milestone chain
/// (outer → inner, per §5 step 2) and the active slice doc (per §5 step 3),
/// builds a [`ResolveInputs`] from `ctx`, and calls [`grants::resolve`].
///
/// A baton with no `item:` returns `Ok(SpawnResolution { grants: vec![], .. })`
/// — the "No baton item" case: floor only, no grants (§5 last paragraph).
pub fn resolve_from_baton(
    baton: &str,
    ctx: &SpawnResolveCtx<'_>,
    probe: &dyn GitProbe,
) -> Result<SpawnResolution, SpawnResolveError> {
    let view = parse_baton(baton);
    let Some(item) = view.item else {
        return Ok(SpawnResolution { grants: Vec::new(), item: None, slice: None });
    };
    let slice = view.slice;
    let paths = item_doc_candidates(ctx.garden_root, &item, slice.as_deref())
        .map_err(|reason| SpawnResolveError::DocChain {
            item: item.clone(),
            reason,
        })?;

    // Read every doc up front so a mid-chain unreadable file aborts BEFORE the
    // resolver sees a partial chain (§8 fail-closed).
    let mut loaded: Vec<LoadedDoc> = Vec::with_capacity(paths.len());
    for path in paths {
        match fs::read_to_string(&path) {
            Ok(content) => loaded.push((path, content)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SpawnResolveError::DocMissing { path });
            }
            Err(source) => return Err(SpawnResolveError::DocRead { path, source }),
        }
    }

    // Partition the loaded chain: the slice doc (if any) is the first element
    // whose parent directory is named `slices` — item_doc_candidates always
    // emits a slice doc first when it finds one, before the enclosing
    // CLAUDE.md chain (innermost first).
    let (slice_entry, chain_innermost_first) = split_off_slice(loaded);
    // §5 step 2 walks the milestone chain outer → inner, so reverse.
    let chain_outer_to_inner: Vec<LoadedDoc> =
        chain_innermost_first.into_iter().rev().collect();

    // Own the labels (short, garden-relative paths) so GrantDoc can borrow them
    // for the resolve call. Keeps `grants.md` / status output consistent with
    // whatever the dry-run verb prints.
    let chain_labelled: Vec<(String, String)> = chain_outer_to_inner
        .into_iter()
        .map(|(path, content)| (label_for(ctx.garden_root, &path), content))
        .collect();
    let slice_labelled: Option<(String, String)> = slice_entry
        .map(|(path, content)| (label_for(ctx.garden_root, &path), content));

    let chain_docs: Vec<GrantDoc<'_>> = chain_labelled
        .iter()
        .map(|(label, content)| GrantDoc {
            label: label.as_str(),
            content: content.as_str(),
        })
        .collect();
    let slice_doc = slice_labelled.as_ref().map(|(label, content)| GrantDoc {
        label: label.as_str(),
        content: content.as_str(),
    });

    let inputs = ResolveInputs {
        milestone_chain: &chain_docs,
        slice: slice_doc,
        project_repo: ctx.project_repo.clone(),
        home: ctx.home,
        extra_ceiling: ctx.extra_ceiling,
        backend: ctx.backend,
        keeperd_state_root: ctx.keeperd_state_root,
        keeperd_vault_root: ctx.keeperd_vault_root,
        softfig_runtime_root: ctx.softfig_runtime_root,
        garden_mount: ctx.garden_mount,
    };
    let grants = grants::resolve(&inputs, probe)?;
    Ok(SpawnResolution {
        grants,
        item: Some(item),
        slice,
    })
}

/// One loaded doc from the chain: its path (for the GrantDoc label) and its
/// content. Owns both so the resolver can borrow them for the ResolveInputs
/// call.
type LoadedDoc = (PathBuf, String);

/// If the first element of `loaded` is a slice doc (its parent dir is `slices`),
/// split it off and return `(Some(slice_entry), rest)`. Otherwise return
/// `(None, loaded)` unchanged. The one-line partition that keeps the slice doc
/// out of the milestone chain.
fn split_off_slice(mut loaded: Vec<LoadedDoc>) -> (Option<LoadedDoc>, Vec<LoadedDoc>) {
    let first_is_slice = loaded
        .first()
        .and_then(|(p, _)| p.parent())
        .and_then(|d| d.file_name())
        .and_then(|n| n.to_str())
        == Some("slices");
    if first_is_slice {
        let slice = loaded.remove(0);
        (Some(slice), loaded)
    } else {
        (None, loaded)
    }
}

/// Short label for `path` relative to the garden root (what `grants.md` and
/// `growlight status` print). Falls back to the full display path when `path`
/// is not under `garden_root` — defensive, [`item_doc_candidates`] always joins
/// to it.
fn label_for(garden_root: &Path, path: &Path) -> String {
    path.strip_prefix(garden_root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::Tier;
    use std::fs;

    /// A GitProbe that answers "yes, same common dir" to any pair — the tests
    /// here never exercise the `$WORKTREE` vs `$REPO` relation, only the
    /// baton → chain walk → resolve wiring.
    struct YesProbe;
    impl GitProbe for YesProbe {
        fn same_common_dir(&self, _worktree: &Path, _repo: &Path) -> bool {
            true
        }
    }

    /// Build a mini garden at `tmp` with the usual `growlight/backlog/`
    /// layout. Returns the garden root.
    fn mini_garden(tmp: &Path) -> PathBuf {
        let root = tmp.join("garden");
        fs::create_dir_all(root.join("growlight/backlog/milestones")).unwrap();
        fs::create_dir_all(root.join("growlight/backlog/tasks")).unwrap();
        root
    }

    fn write_milestone(root: &Path, id: &str, body: &str) {
        let dir = root.join("growlight/backlog/milestones").join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("CLAUDE.md"), body).unwrap();
    }

    fn write_slice(root: &Path, item: &str, slug: &str, body: &str) {
        let dir = root
            .join("growlight/backlog/milestones")
            .join(item)
            .join("slices");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{slug}.md")), body).unwrap();
    }

    fn write_task(root: &Path, slug: &str, body: &str) {
        let dir = root.join("growlight/backlog/tasks");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{slug}.md")), body).unwrap();
    }

    fn home_in(dir: &Path) -> PathBuf {
        let h = dir.join("home/u");
        fs::create_dir_all(&h).unwrap();
        h
    }

    fn baton(item: Option<&str>, slice: Option<&str>) -> String {
        let mut s = String::from("---\nstatus: IN_PROGRESS\n");
        if let Some(i) = item {
            s.push_str(&format!("item: {i}\n"));
        }
        if let Some(sl) = slice {
            s.push_str(&format!("slice: {sl}\n"));
        }
        s.push_str("---\n");
        s
    }

    fn ctx<'a>(garden: &'a Path, home: &'a Path, repo: &'a Path) -> SpawnResolveCtx<'a> {
        SpawnResolveCtx {
            garden_root: garden,
            home,
            project_repo: ProjectRepo::Local(repo),
            backend: Backend::Opencode,
            extra_ceiling: &[],
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        }
    }

    // ---- the four input shapes ----------------------------------------------

    #[test]
    fn a_baton_with_no_item_resolves_to_floor_only_no_grants() {
        // §5 last paragraph: "A member spawned before any claim: floor only,
        // no grants." The chain lookup never runs, so the garden layout is
        // irrelevant.
        let tmp = tempfile::tempdir().unwrap();
        let garden = mini_garden(tmp.path());
        let home = home_in(tmp.path());
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        let r = resolve_from_baton(&baton(None, None), &ctx(&garden, &home, &repo), &YesProbe)
            .expect("floor-only resolves");
        assert!(r.grants.is_empty(), "floor-only is empty, {:?}", r.grants);
        assert_eq!(r.item, None);
        assert_eq!(r.slice, None);
    }

    #[test]
    fn a_milestone_with_slice_walks_the_chain_and_marks_slice_as_slice_tier() {
        // §5: project default + milestone + slice entries, in that order. The
        // chain walk is what this helper owns; this test proves the slice doc
        // reaches the resolver tagged as slice (not milestone).
        let tmp = tempfile::tempdir().unwrap();
        let garden = mini_garden(tmp.path());
        let home = home_in(tmp.path());
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        let extra = home.join("dotfiles");
        fs::create_dir_all(&extra).unwrap();
        write_milestone(&garden, "demo", "# demo\n> Last reviewed: 2026-10-24\n");
        write_slice(
            &garden,
            "demo",
            "002-wire",
            &format!("# slice\n> Grants: rw {}\n", extra.display()),
        );
        let r = resolve_from_baton(
            &baton(Some("demo"), Some("002")),
            &ctx(&garden, &home, &repo),
            &YesProbe,
        )
        .expect("resolves");
        assert_eq!(r.item.as_deref(), Some("demo"));
        assert_eq!(r.slice.as_deref(), Some("002"));
        // The project default (rw $REPO) must be there, and the slice's rw
        // dotfiles grant must be tagged Slice (not MilestoneOrTask).
        let modes_and_tiers: Vec<_> = r
            .grants
            .iter()
            .filter(|g| g.origin.tier != Tier::CeilingDeny && g.origin.tier != Tier::GitGuard)
            .map(|g| (g.mode, g.origin.tier))
            .collect();
        assert!(
            modes_and_tiers.contains(&(crate::grants::Mode::Rw, Tier::ProjectDefault)),
            "project default present: {modes_and_tiers:?}",
        );
        assert!(
            modes_and_tiers.contains(&(crate::grants::Mode::Rw, Tier::Slice)),
            "slice grant tagged as slice: {modes_and_tiers:?}",
        );
    }

    #[test]
    fn a_milestone_whose_slice_doc_is_absent_falls_through_to_milestone_only() {
        // item_doc_candidates only emits a slice-doc path when the file exists.
        // So a milestone with a slice-less baton (or a missing slice) resolves
        // the milestone chain alone — no spurious "slice doc missing" refusal
        // (§5 "slice doc": absent slice is a legal state).
        let tmp = tempfile::tempdir().unwrap();
        let garden = mini_garden(tmp.path());
        let home = home_in(tmp.path());
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        write_milestone(&garden, "demo", "# demo\n");
        let r = resolve_from_baton(
            &baton(Some("demo"), Some("999")),
            &ctx(&garden, &home, &repo),
            &YesProbe,
        )
        .expect("resolves without the missing slice doc");
        assert_eq!(r.slice.as_deref(), Some("999"), "slice is still carried for grants.md");
        // Only one non-ceiling tier: the project default (no slice doc = no
        // slice-tier grants).
        let tiers: Vec<_> = r
            .grants
            .iter()
            .map(|g| g.origin.tier)
            .filter(|t| *t != Tier::CeilingDeny && *t != Tier::GitGuard)
            .collect();
        assert_eq!(tiers, vec![Tier::ProjectDefault], "no slice tier: {tiers:?}");
    }

    #[test]
    fn a_task_resolves_as_a_single_doc_chain() {
        // §4: a task is one doc for the whole chain; no slices.
        let tmp = tempfile::tempdir().unwrap();
        let garden = mini_garden(tmp.path());
        let home = home_in(tmp.path());
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        let extra = home.join("dotfiles");
        fs::create_dir_all(&extra).unwrap();
        write_task(
            &garden,
            "042-demo",
            &format!("# 042\n> Grants: ro {}\n", extra.display()),
        );
        let r = resolve_from_baton(
            &baton(Some("042"), None),
            &ctx(&garden, &home, &repo),
            &YesProbe,
        )
        .expect("task resolves");
        assert_eq!(r.item.as_deref(), Some("042"));
        assert_eq!(r.slice, None);
        // The ro grant must be tagged MilestoneOrTask (task docs resolve into
        // that tier — slice tier only exists for milestone slices).
        let tiers: Vec<_> = r
            .grants
            .iter()
            .filter(|g| g.origin.tier != Tier::CeilingDeny && g.origin.tier != Tier::GitGuard)
            .map(|g| g.origin.tier)
            .collect();
        assert!(tiers.contains(&Tier::MilestoneOrTask), "task's grant: {tiers:?}");
        assert!(!tiers.contains(&Tier::Slice), "no slice tier for a task: {tiers:?}");
    }

    // ---- fail-closed refusals -----------------------------------------------

    #[test]
    fn a_remote_repo_on_opencode_refuses_before_any_doc_is_read() {
        // §9: a remote `$REPO` refuses an opencode spawn up front. The chain
        // doesn't need to exist for the refusal to land.
        let tmp = tempfile::tempdir().unwrap();
        let garden = mini_garden(tmp.path());
        let home = home_in(tmp.path());
        let mut c = ctx(&garden, &home, Path::new("/dev/null"));
        c.project_repo = ProjectRepo::Remote("otg-travel:/srv/x");
        // Milestone doesn't exist on disk; if the chain were walked we'd get
        // DocChain or similar. The §9 pre-check short-circuits that.
        let err = resolve_from_baton(&baton(Some("some-milestone"), None), &c, &YesProbe)
            .expect_err("remote repo refuses");
        match err {
            SpawnResolveError::Grant(GrantError::RemoteRepoOnOpencode { repo }) => {
                assert_eq!(repo, "otg-travel:/srv/x");
            }
            other => panic!("expected RemoteRepoOnOpencode, got {other:?}"),
        }
    }

    #[test]
    fn two_slices_sharing_a_number_fail_closed_at_the_chain_step() {
        // Review 042 G74-2: a shadow doc beside the real one is how a
        // malicious actor would steer the chain. The chain lookup fails closed
        // and surfaces as DocChain — never silently takes the first.
        let tmp = tempfile::tempdir().unwrap();
        let garden = mini_garden(tmp.path());
        let home = home_in(tmp.path());
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        write_milestone(&garden, "demo", "# demo\n");
        write_slice(&garden, "demo", "002-wire", "# a\n");
        write_slice(&garden, "demo", "002-shadow", "# shadow\n");
        let err = resolve_from_baton(
            &baton(Some("demo"), Some("002")),
            &ctx(&garden, &home, &repo),
            &YesProbe,
        )
        .expect_err("shadow slice fails the chain lookup");
        match err {
            SpawnResolveError::DocChain { item, reason } => {
                assert_eq!(item, "demo");
                assert!(reason.contains("002"), "{reason}");
            }
            other => panic!("expected DocChain, got {other:?}"),
        }
    }

    #[test]
    fn a_grant_entry_that_hits_the_ceiling_propagates_as_grant_refusal() {
        // §6: a grant on a ceiling root (`~/.ssh`) is refused. The resolver's
        // GrantError bubbles through the module's `#[from]` conversion.
        let tmp = tempfile::tempdir().unwrap();
        let garden = mini_garden(tmp.path());
        let home = home_in(tmp.path());
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        let ssh = home.join(".ssh");
        fs::create_dir_all(&ssh).unwrap();
        write_milestone(
            &garden,
            "demo",
            &format!("# demo\n> Grants: ro {}\n", ssh.display()),
        );
        let err = resolve_from_baton(
            &baton(Some("demo"), None),
            &ctx(&garden, &home, &repo),
            &YesProbe,
        )
        .expect_err("ceiling hit refused");
        match err {
            SpawnResolveError::Grant(GrantError::CeilingHit { .. }) => {}
            other => panic!("expected CeilingHit, got {other:?}"),
        }
    }

    // ---- the partition helper -----------------------------------------------

    #[test]
    fn split_off_slice_takes_first_only_when_parent_is_slices_dir() {
        let s = |p: &str| (PathBuf::from(p), String::new());
        // First path is a slice: split it off.
        let (slice, rest) = split_off_slice(vec![
            s("growlight/backlog/milestones/demo/slices/001-x.md"),
            s("growlight/backlog/milestones/demo/CLAUDE.md"),
        ]);
        assert!(slice.is_some());
        assert_eq!(rest.len(), 1);
        // First path is NOT a slice (CLAUDE.md): no split.
        let (slice, rest) = split_off_slice(vec![
            s("growlight/backlog/milestones/demo/CLAUDE.md"),
            s("growlight/backlog/milestones/demo/outer/CLAUDE.md"),
        ]);
        assert!(slice.is_none());
        assert_eq!(rest.len(), 2);
        // Empty is a no-op.
        let (slice, rest) = split_off_slice(Vec::<(PathBuf, String)>::new());
        assert!(slice.is_none());
        assert!(rest.is_empty());
    }

    #[test]
    fn label_for_strips_the_garden_root() {
        let garden = PathBuf::from("/g");
        assert_eq!(
            label_for(&garden, Path::new("/g/growlight/backlog/milestones/x/CLAUDE.md")),
            "growlight/backlog/milestones/x/CLAUDE.md",
        );
        // Fallback: path isn't under garden_root; use the full display path.
        assert_eq!(
            label_for(&garden, Path::new("/other/CLAUDE.md")),
            "/other/CLAUDE.md",
        );
    }
}
