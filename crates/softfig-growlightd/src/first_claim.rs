//! The §8 **first-claim** computation (queue-v2-git slice 002): turn the v2
//! snapshot and the entry growlightd just picked into the `parent`/`base` the
//! claim records on the entry and the concrete §8 base line the baton seeds.
//!
//! This is the *wiring* between the pure stack model ([`crate::git_stack`]) and
//! the drive loop: it reduces the snapshot's live entries to the stack model's
//! [`StackEntry`] inputs, classifies the repo, and returns one [`FirstClaim`]
//! (or `None` for a restack, which has no branch to cut). The drive loop calls
//! it between `pick_v2` and the claim, and it is the only thing in growlightd
//! that runs the stack model against a live repo — so it is unit-proven against
//! temp git repos, exactly as the model itself is.
//!
//! ## An entry whose branch already exists
//!
//! A migrated or hand-seeded entry can carry work on its branch before it is
//! ever claimed (report 171). The first claim then records the base the branch
//! really has — its merge-base with its parent's branch or `main`
//! ([`git_stack::existing_branch_base`]) — and the baton says `resume <branch>`,
//! never `create`, so nothing re-cuts a branch that holds commits.
//!
//! ## One repo resolver
//!
//! The repo a claim probes is the entry's **project repo**, resolved by
//! [`Repo::of`] — the same resolver the boot and spin guards use
//! ([`crate::v2_repo::local_repo`]). An item doc's `> Worktree:` line is the
//! legacy lookup and the v2 path never reads it: a project whose repo is not a
//! git repo is a data error to repair on the row, and a claim that probed some
//! other repo than the guards do could stack and guard different trees. Such a
//! repo fails the claim with [`FirstClaimError::NotARepo`], which names the
//! entry, its project and the path.
//!
//! ## First claim vs resume
//!
//! The caller decides *whether* to call this: only when the entry's `claimed`
//! is still empty (a never-claimed entry, `queued → active`). A resume
//! (`paused → active`) or a re-claim has already recorded its base and must not
//! recompute it.

use std::path::Path;

use softfig_ipc::queue_v2::Lane;

use crate::git_probe::ProbeCache;
use crate::git_stack::{self, Git, Repo, Stack, StackEntry};
use crate::scheduler_v2::{EntryView, V2Snapshot};

/// Why a first claim could not be computed. Either way the claim fails closed
/// and backs off; the text is what the journal and the alert carry.
#[derive(Debug, thiserror::Error)]
pub enum FirstClaimError {
    /// The entry's project names a local repo that is not a git repo (report
    /// 171: `remote-runner` and `fixes` name the non-repo parent of their
    /// worktrees). It cannot clear by waiting, so the text says what to fix,
    /// with the human verbs that do it.
    #[error(
        "entry {entry}: project {project}'s repo {repo} is not a git repository; \
         point the project at a git checkout (`softfig growlight queue project \
         set-repo {project} <repo>`), or move the entry to a project whose repo \
         is one (`softfig growlight queue repair {entry} --project <project>`)"
    )]
    NotARepo { entry: String, project: String, repo: std::path::PathBuf },
    #[error(transparent)]
    Git(#[from] git_stack::GitError),
}

/// What a first claim records (§8): the `parent`/`base` pair the claim op
/// writes, plus the entry's `branch` so the caller can seed the concrete
/// `create <branch> from <base>` baton line (or `resume <branch>`, when
/// [`existing`](Self::existing)) with the same values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstClaim {
    /// The entry's branch (`feat/<id>` / `fix/<id>`) — the baton's `create`
    /// branch.
    pub branch: String,
    /// `parent`: the entry whose branch this was cut from (`""` = `main`).
    pub parent: String,
    /// `base`: the commit cut from (local) or the parent branch name (remote).
    /// For an [`existing`](Self::existing) branch, the merge-base it shares
    /// with its parent's branch or `main`.
    pub base: String,
    /// The branch already exists, so the baton resumes it instead of creating
    /// it (report 171).
    pub existing: bool,
}

/// Compute what `entry`'s first claim records, or `None` when the entry has no
/// branch (a restack — nothing to cut, nothing to seed). Pure over the snapshot
/// plus the read-only git surface; `home` expands `~` repo paths. The git runs
/// as one probe on a worker thread under `probes` (V13): bounded by a deadline,
/// sharing this tick's answers, and backed off after a timeout.
///
/// The stack candidates are the snapshot's live entries on the same repo,
/// whichever project names it, in claim order. An **urgent** entry skips the stack entirely — it branches
/// from `main`, so its base never depends on it and the probes are saved. A
/// sibling whose branch is not cut yet is not a candidate (see
/// [`git_stack::stack_candidates`]), so it never blocks a normal claim either.
pub fn first_claim(
    snapshot: &V2Snapshot,
    entry: &EntryView,
    home: Option<&Path>,
    user: Option<&str>,
    probes: &ProbeCache,
) -> Result<Option<FirstClaim>, FirstClaimError> {
    if entry.branch.is_empty() {
        return Ok(None); // a restack — no branch, so no base to record
    }
    // The entry's project must exist (a §3.1 writer invariant the source
    // already validated); fail-closed with no base rather than panic.
    let Some(project) = snapshot.projects.iter().find(|p| p.name == entry.project) else {
        return Ok(None);
    };
    let repo = Repo::of(project, home, user);
    let stack_entries: Vec<StackEntry> = snapshot
        .entries_in_repo(&project.repo)
        .map(|e| StackEntry {
            id: e.id.clone(),
            branch: e.branch.clone(),
            lane: e.lane,
            claimed: e.claimed.clone(),
        })
        .collect();
    let main = project.main.clone();
    let lane = entry.lane;
    // The entry's recorded parent, while its branch is known (a live entry or
    // an archive row): the base an existing branch is measured against.
    let parent = (!entry.parent.is_empty())
        .then(|| {
            let branch = snapshot
                .entries
                .iter()
                .find(|e| e.id == entry.parent)
                .map(|e| e.branch.clone())
                .or_else(|| snapshot.done_branches.get(&entry.parent).cloned())?;
            Some((entry.parent.clone(), branch))
        })
        .flatten();
    let branch = entry.branch.clone();
    let compute = {
        let repo = repo.clone();
        move |git: &Git| {
            if let Repo::Local(path) = &repo
                && !git.is_repo()?
            {
                return Err(git_stack::GitError::NotARepo { repo: path.clone() });
            }
            let parent = parent.as_ref().map(|(id, b)| (id.as_str(), b.as_str()));
            if let Some(found) = git_stack::existing_branch_base(&repo, &main, &branch, parent, git)? {
                return Ok(found);
            }
            let stack = if lane == Lane::Urgent {
                Stack::default() // urgent branches from `main`; the stack is irrelevant
            } else {
                git_stack::stack_candidates(&repo, &main, &stack_entries, git)?
            };
            git_stack::claim_base(&repo, &main, lane, &stack, git)
        }
    };
    let base = match &repo {
        // One bounded probe for the whole chain (V13), sharing this tick's
        // answers with every other probe of the repo.
        Repo::Local(path) => probes.spawn(path, compute).wait(),
        // A remote project runs no git (§8); the handle is never touched.
        Repo::Remote => compute(&Git::new(std::path::PathBuf::new())),
    }
    .map_err(|e| match e {
        git_stack::GitError::NotARepo { repo } => FirstClaimError::NotARepo {
            entry: entry.id.clone(),
            project: project.name.clone(),
            repo,
        },
        other => FirstClaimError::Git(other),
    })?;
    Ok(Some(FirstClaim {
        branch: entry.branch.clone(),
        parent: base.parent,
        base: base.base,
        existing: base.existing,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler_v2::{EntryView, ProjectView};
    use softfig_ipc::queue_v2::{EntryKind, EntryStatus, Lane, RepoLocality};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::Path;
    use std::process::{Command, Stdio};

    fn sh_git(repo: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .arg("-C")
            .arg(repo)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run git")
            .success();
        assert!(ok, "git {args:?}");
    }

    fn rev_parse(repo: &Path, rev: &str) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["rev-parse", rev])
            .output()
            .expect("run git rev-parse");
        assert!(out.status.success(), "git rev-parse {rev}");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// A repo on `main` with one commit, plus open (unmerged) branches
    /// `feat/one` and `feat/two`. Returns the temp dir and `main`'s tip.
    fn seeded_repo() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        sh_git(repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join("a.txt"), "base\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "base"]);
        let main = rev_parse(repo, "main");
        for name in ["feat/one", "feat/two"] {
            sh_git(repo, &["checkout", "-q", "-b", name]);
            fs::write(
                repo.join(format!("{}.txt", name.replace('/', "_"))),
                format!("{name}\n"),
            )
            .unwrap();
            sh_git(repo, &["add", "."]);
            sh_git(repo, &["commit", "-q", "-m", name]);
            sh_git(repo, &["checkout", "-q", "main"]);
        }
        (dir, main)
    }

    fn entry(id: &str, branch: &str, lane: Lane, status: EntryStatus, claimed: &str) -> EntryView {
        EntryView {
            id: id.into(),
            kind: EntryKind::Milestone,
            project: "softfig".into(),
            lane,
            status,
            after: vec![],
            branch: branch.into(),
            claimed: claimed.into(),
            parent: String::new(),
            base: String::new(),
            follow_ups: 0,
            pending: None,
            fleet: true,
            not_before: None,
            auto_restack: true,
            holder: None,
            models: None,
        }
    }

    fn snap(projects: Vec<ProjectView>, entries: Vec<EntryView>) -> V2Snapshot {
        V2Snapshot {
            projects,
            entries,
            trees: BTreeMap::new(),
            done_ids: BTreeSet::new(),
            done_branches: Default::default(),
            now_unix: 0,
            done_projects: Default::default(),
            re_records_due: Default::default(),
        }
    }

    /// A snapshot whose single project points at a local repo path `dir`.
    fn local_snap(dir: &Path, entries: Vec<EntryView>) -> V2Snapshot {
        snap(
            vec![ProjectView {
                name: "softfig".into(),
                repo: dir.display().to_string(),
                locality: softfig_ipc::queue_v2::RepoLocality::of(&dir.display().to_string(), None),
                main: "main".into(),
            }],
            entries,
        )
    }

    #[test]
    fn normal_first_claim_stacks_on_the_newest_claimed_unmerged_branch() {
        let (dir, _main) = seeded_repo();
        let two_tip = rev_parse(dir.path(), "feat/two");

        let entries = vec![
            entry("one", "feat/one", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z"),
            entry("two", "feat/two", Lane::Normal, EntryStatus::Blocked, "2026-10-02T00:00:00Z"),
            // the entry being claimed — never claimed, so not its own candidate
            entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, ""),
        ];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.iter().find(|e| e.id == "three").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert_eq!(fc.branch, "feat/three");
        assert_eq!(fc.parent, "two", "cut from the newest-claimed candidate");
        assert_eq!(fc.base, two_tip, "local base is the cut-from commit");
    }

    /// §8: the stack is per repo. A project sharing the repo is in it, and one
    /// on another repo isn't, however new its claim.
    #[test]
    fn a_first_claim_stacks_across_the_projects_that_share_its_repo() {
        let (dir, _main) = seeded_repo();
        let (elsewhere, _) = seeded_repo();
        let one_tip = rev_parse(dir.path(), "feat/one");
        let repo = dir.path().display().to_string();
        let mut one =
            entry("one", "feat/one", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z");
        one.project = "mirror".into();
        let mut other =
            entry("two", "feat/two", Lane::Normal, EntryStatus::Blocked, "2026-10-02T00:00:00Z");
        other.project = "elsewhere".into();
        let project = |name: &str, repo: &str| ProjectView {
            name: name.into(),
            repo: repo.into(),
            locality: RepoLocality::of(repo, None),
            main: "main".into(),
        };
        let snapshot = snap(
            vec![
                project("softfig", &repo),
                project("mirror", &repo),
                project("elsewhere", &elsewhere.path().display().to_string()),
            ],
            vec![one, other, entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, "")],
        );
        let claiming = snapshot.entries.iter().find(|e| e.id == "three").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert_eq!(fc.parent, "one", "the sibling project's branch is the stack top");
        assert_eq!(fc.base, one_tip);
    }

    /// Owner ruling (V19): an urgent branch lands alone, so the newest live
    /// claim being urgent sends a normal claim to the newest normal entry.
    #[test]
    fn a_normal_claim_skips_a_newer_urgent_branch_for_the_newest_normal_one() {
        let (dir, _main) = seeded_repo();
        let one_tip = rev_parse(dir.path(), "feat/one");
        let entries = vec![
            entry("two", "feat/two", Lane::Urgent, EntryStatus::Blocked, "2026-10-02T00:00:00Z"),
            entry("one", "feat/one", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z"),
            entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, ""),
        ];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.iter().find(|e| e.id == "three").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert_eq!(fc.parent, "one", "the urgent branch is never a parent");
        assert_eq!(fc.base, one_tip);
    }

    #[test]
    fn a_normal_claim_with_only_an_urgent_branch_live_cuts_from_main() {
        let (dir, main_tip) = seeded_repo();
        let entries = vec![
            entry("two", "feat/two", Lane::Urgent, EntryStatus::Blocked, "2026-10-02T00:00:00Z"),
            entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, ""),
        ];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.iter().find(|e| e.id == "three").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert_eq!(fc.parent, "", "records no parent");
        assert_eq!(fc.base, main_tip);
    }

    #[test]
    fn a_remote_normal_claim_skips_an_urgent_branch_too() {
        let entries = vec![
            entry("two", "feat/two", Lane::Urgent, EntryStatus::Blocked, "2026-10-02T00:00:00Z"),
            entry("one", "feat/one", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z"),
            entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, ""),
        ];
        let snapshot = snap(
            vec![ProjectView {
                name: "softfig".into(),
                repo: "host:/srv/repo".into(),
                locality: RepoLocality::Remote,
                main: "main".into(),
            }],
            entries,
        );
        let claiming = snapshot.entries.iter().find(|e| e.id == "three").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert_eq!(fc.parent, "one");
        assert_eq!(fc.base, "feat/one");
    }

    #[test]
    fn empty_stack_branches_from_main() {
        let (dir, main_tip) = seeded_repo();
        let entries = vec![entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, "")];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.first().unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert_eq!(fc.parent, "", "main has no parent entry");
        assert_eq!(fc.base, main_tip, "branches from main's tip");
        assert!(!fc.existing, "a branch that is not there yet is created");
    }

    /// Report 171: the entry's branch already exists with work on it. The claim
    /// records the base it really has and says so, so the baton resumes it
    /// instead of cutting `<branch> from <main tip>` over its commits.
    #[test]
    fn an_existing_branch_is_resumed_with_its_real_base() {
        let (dir, main_tip) = seeded_repo();
        // `main` moves on after `feat/one` was cut, as it does for a long-lived branch.
        sh_git(dir.path(), &["commit", "-q", "--allow-empty", "-m", "main moved"]);
        assert_ne!(rev_parse(dir.path(), "main"), main_tip);
        let entries = vec![entry("one", "feat/one", Lane::Normal, EntryStatus::Queued, "")];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.first().unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert!(fc.existing);
        assert_eq!(fc.branch, "feat/one");
        assert_eq!(fc.base, main_tip, "the merge-base with main, not main's moved tip");
        assert_eq!(fc.parent, "");
    }

    /// An entry recorded with a parent whose branch is live and unmerged measures
    /// its base against that branch, and keeps the parent.
    #[test]
    fn an_existing_branch_with_a_live_parent_is_based_on_the_parent() {
        let (dir, _main) = seeded_repo();
        let one_tip = rev_parse(dir.path(), "feat/one");
        sh_git(dir.path(), &["checkout", "-q", "-b", "feat/child", "feat/one"]);
        fs::write(dir.path().join("child.txt"), "child\n").unwrap();
        sh_git(dir.path(), &["add", "."]);
        sh_git(dir.path(), &["commit", "-q", "-m", "child"]);
        sh_git(dir.path(), &["checkout", "-q", "main"]);
        let mut child = entry("child", "feat/child", Lane::Normal, EntryStatus::Queued, "");
        child.parent = "one".into();
        let entries = vec![
            entry("one", "feat/one", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z"),
            child,
        ];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.iter().find(|e| e.id == "child").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert!(fc.existing);
        assert_eq!(fc.parent, "one");
        assert_eq!(fc.base, one_tip);
    }

    /// An existing branch whose recorded parent's branch is gone falls back to
    /// `main` and records no parent.
    #[test]
    fn an_existing_branch_whose_parent_branch_is_gone_is_based_on_main() {
        let (dir, main_tip) = seeded_repo();
        let mut two = entry("two", "feat/two", Lane::Normal, EntryStatus::Queued, "");
        two.parent = "ghost".into();
        let entries = vec![
            entry("ghost", "feat/ghost", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z"),
            two,
        ];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.iter().find(|e| e.id == "two").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert!(fc.existing);
        assert_eq!((fc.parent.as_str(), fc.base.as_str()), ("", main_tip.as_str()));
    }

    /// A remote project runs no git, so it cannot see an existing branch: its
    /// first claim is the list-state one it always was.
    #[test]
    fn a_remote_first_claim_is_never_an_existing_branch() {
        let snapshot = snap(
            vec![ProjectView {
                name: "softfig".into(),
                repo: "host:/srv/repo".into(),
                locality: RepoLocality::Remote,
                main: "main".into(),
            }],
            vec![entry("one", "feat/one", Lane::Normal, EntryStatus::Queued, "")],
        );
        let claiming = snapshot.entries.first().unwrap();
        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert!(!fc.existing);
    }

    /// Report 171: a project whose `repo` is a plain directory (the parent of
    /// its worktrees) fails the claim with one reason that names the entry, the
    /// project and the path — not the bare exit 128 of whichever query ran first.
    #[test]
    fn a_project_repo_that_is_not_a_git_repo_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![entry("089", "fix/089", Lane::Normal, EntryStatus::Queued, "")];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.first().unwrap();

        let err = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap_err();
        assert!(
            matches!(&err, FirstClaimError::NotARepo { entry, project, repo }
                if entry == "089" && project == "softfig" && repo == dir.path()),
            "{err:?}",
        );
        let text = err.to_string();
        for want in ["089", "softfig", &dir.path().display().to_string(), "not a git repository"] {
            assert!(text.contains(want), "{want:?} missing from {text:?}");
        }
        // Report 171: the text names the two human verbs that repair the row.
        for want in ["queue project set-repo softfig", "queue repair 089 --project"] {
            assert!(text.contains(want), "{want:?} missing from {text:?}");
        }
    }

    #[test]
    fn a_started_entry_with_no_branch_does_not_block_a_normal_first_claim() {
        // V3: `ghost` was claimed (then blocked/deferred) before its branch was
        // cut. It must not fail the repo's other first claims; the stack just
        // skips it and the new entry stacks on the real branch below it.
        let (dir, _main) = seeded_repo();
        let one_tip = rev_parse(dir.path(), "feat/one");
        let entries = vec![
            entry("one", "feat/one", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z"),
            entry("ghost", "feat/ghost", Lane::Normal, EntryStatus::Blocked, "2026-10-02T00:00:00Z"),
            entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, ""),
        ];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.iter().find(|e| e.id == "three").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new())
            .expect("an uncut sibling branch must not fail the claim")
            .unwrap();
        assert_eq!(fc.parent, "one", "the uncut ghost is skipped");
        assert_eq!(fc.base, one_tip);
    }

    #[test]
    fn urgent_branches_from_main_and_skips_the_stack() {
        let (dir, main_tip) = seeded_repo();
        // A sibling branch that does not exist yet (a member claimed it but has
        // not cut the branch): urgent skips the stack entirely, so the missing
        // `feat/ghost` is never probed.
        let entries = vec![
            entry("one", "feat/ghost", Lane::Normal, EntryStatus::Active, "2026-10-01T00:00:00Z"),
            entry("hotfix", "feat/hotfix", Lane::Urgent, EntryStatus::Queued, ""),
        ];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.iter().find(|e| e.id == "hotfix").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert_eq!(fc.parent, "", "urgent branches from main");
        assert_eq!(fc.base, main_tip);
    }

    #[test]
    fn remote_resolves_by_list_state_and_never_runs_git() {
        let entries = vec![
            entry("one", "feat/one", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z"),
            entry("two", "feat/two", Lane::Normal, EntryStatus::Blocked, "2026-10-02T00:00:00Z"),
            entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, ""),
        ];
        // A remote `host:path` project — `first_claim` must never touch git.
        let snapshot = snap(
            vec![ProjectView {
                name: "softfig".into(),
                repo: "host:/srv/repo".into(),
                locality: softfig_ipc::queue_v2::RepoLocality::of("host:/srv/repo", None),
                main: "main".into(),
            }],
            entries,
        );
        let claiming = snapshot.entries.iter().find(|e| e.id == "three").unwrap();

        let fc = first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap().unwrap();
        assert_eq!(fc.parent, "two", "newest claimed by list state");
        assert_eq!(fc.base, "feat/two", "remote base is the branch name, not a commit");
    }

    #[test]
    fn a_restack_has_no_branch_so_no_base() {
        let entries = vec![entry("nnn", "", Lane::Urgent, EntryStatus::Queued, "")];
        let snapshot = snap(
            vec![ProjectView {
                name: "softfig".into(),
                repo: "host:/srv/repo".into(),
                locality: softfig_ipc::queue_v2::RepoLocality::of("host:/srv/repo", None),
                main: "main".into(),
            }],
            entries,
        );
        let claiming = snapshot.entries.first().unwrap();

        assert_eq!(first_claim(&snapshot, claiming, None, None, &ProbeCache::new()).unwrap(), None);
    }
}
