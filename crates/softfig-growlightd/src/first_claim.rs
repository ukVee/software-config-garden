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
//! ## First claim vs resume
//!
//! The caller decides *whether* to call this: only when the entry's `claimed`
//! is still empty (a never-claimed entry, `queued → active`). A resume
//! (`paused → active`) or a re-claim has already recorded its base and must not
//! recompute it.

use std::path::Path;

use softfig_ipc::queue_v2::Lane;

use crate::git_stack::{self, Git, Repo, Stack, StackEntry};
use crate::scheduler_v2::{EntryView, V2Snapshot};

/// What a first claim records (§8): the `parent`/`base` pair the claim op
/// writes, plus the entry's `branch` so the caller can seed the concrete
/// `create <branch> from <base>` baton line with the same values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstClaim {
    /// The entry's branch (`feat/<id>` / `fix/<id>`) — the baton's `create`
    /// branch.
    pub branch: String,
    /// `parent`: the entry whose branch this was cut from (`""` = `main`).
    pub parent: String,
    /// `base`: the commit cut from (local) or the parent branch name (remote).
    pub base: String,
}

/// Compute what `entry`'s first claim records, or `None` when the entry has no
/// branch (a restack — nothing to cut, nothing to seed). Pure over the snapshot
/// plus the read-only git surface; `home` expands `~` repo paths.
///
/// The stack candidates are the snapshot's live entries in the same project,
/// in claim order. An **urgent** entry skips the stack entirely — it branches
/// from `main`, and skipping keeps a sibling branch that a member has not yet
/// created from failing the read-only `merge-base` probe.
pub fn first_claim(
    snapshot: &V2Snapshot,
    entry: &EntryView,
    home: Option<&Path>,
) -> Result<Option<FirstClaim>, git_stack::GitError> {
    if entry.branch.is_empty() {
        return Ok(None); // a restack — no branch, so no base to record
    }
    // The entry's project must exist (a §3.1 writer invariant the source
    // already validated); fail-closed with no base rather than panic.
    let Some(project) = snapshot.projects.iter().find(|p| p.name == entry.project) else {
        return Ok(None);
    };
    let repo = Repo::classify(&project.repo, home);
    let git = match &repo {
        Repo::Local(path) => Git::new(path.clone()),
        // A remote project runs no git (§8); the handle is never touched.
        Repo::Remote => Git::new(std::path::PathBuf::new()),
    };
    let stack_entries: Vec<StackEntry> = snapshot
        .entries
        .iter()
        .filter(|e| e.project == entry.project)
        .map(|e| StackEntry {
            id: e.id.clone(),
            branch: e.branch.clone(),
            lane: e.lane,
            claimed: e.claimed.clone(),
        })
        .collect();
    let stack = if entry.lane == Lane::Urgent {
        Stack::default() // urgent branches from `main`; the stack is irrelevant
    } else {
        git_stack::stack_candidates(&repo, &project.main, &stack_entries, &git)?
    };
    let base = git_stack::claim_base(&repo, &project.main, entry.lane, &stack, &git)?;
    Ok(Some(FirstClaim {
        branch: entry.branch.clone(),
        parent: base.parent,
        base: base.base,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler_v2::{EntryView, ProjectView};
    use softfig_ipc::queue_v2::{EntryKind, EntryStatus, Lane};
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
            follow_ups: 0,
            pending: None,
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
        }
    }

    /// A snapshot whose single project points at a local repo path `dir`.
    fn local_snap(dir: &Path, entries: Vec<EntryView>) -> V2Snapshot {
        snap(
            vec![ProjectView {
                name: "softfig".into(),
                repo: dir.display().to_string(),
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

        let fc = first_claim(&snapshot, claiming, None).unwrap().unwrap();
        assert_eq!(fc.branch, "feat/three");
        assert_eq!(fc.parent, "two", "cut from the newest-claimed candidate");
        assert_eq!(fc.base, two_tip, "local base is the cut-from commit");
    }

    #[test]
    fn empty_stack_branches_from_main() {
        let (dir, main_tip) = seeded_repo();
        let entries = vec![entry("three", "feat/three", Lane::Normal, EntryStatus::Queued, "")];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.first().unwrap();

        let fc = first_claim(&snapshot, claiming, None).unwrap().unwrap();
        assert_eq!(fc.parent, "", "main has no parent entry");
        assert_eq!(fc.base, main_tip, "branches from main's tip");
    }

    #[test]
    fn urgent_branches_from_main_and_skips_the_stack() {
        let (dir, main_tip) = seeded_repo();
        // A sibling branch that does not exist yet (a member claimed it but has
        // not cut the branch) must not fail the urgent claim: urgent skips the
        // stack entirely, so the missing `feat/ghost` is never probed.
        let entries = vec![
            entry("one", "feat/ghost", Lane::Normal, EntryStatus::Active, "2026-10-01T00:00:00Z"),
            entry("hotfix", "feat/hotfix", Lane::Urgent, EntryStatus::Queued, ""),
        ];
        let snapshot = local_snap(dir.path(), entries);
        let claiming = snapshot.entries.iter().find(|e| e.id == "hotfix").unwrap();

        let fc = first_claim(&snapshot, claiming, None).unwrap().unwrap();
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
                main: "main".into(),
            }],
            entries,
        );
        let claiming = snapshot.entries.iter().find(|e| e.id == "three").unwrap();

        let fc = first_claim(&snapshot, claiming, None).unwrap().unwrap();
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
                main: "main".into(),
            }],
            entries,
        );
        let claiming = snapshot.entries.first().unwrap();

        assert_eq!(first_claim(&snapshot, claiming, None).unwrap(), None);
    }
}
