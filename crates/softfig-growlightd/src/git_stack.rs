//! The §8 **git stack** — the pure computation growlightd runs to decide where
//! a new entry's branch is cut from, and the thin read-only git surface it runs
//! through. Spec: `meta/spec-growlight-queue.md` §8 (git policy: linear
//! history) and §12 (the git-stack seam — new code in growlightd).
//!
//! ## The model
//!
//! - **Stack candidates** ([`stack_candidates`]) are the branches of *live*
//!   entries in one repo that are *started* (first-claimed, `claimed` set) and
//!   whose tip is **not** an ancestor of `main` (`git merge-base
//!   --is-ancestor`, read-only). Archived entries never reach this module, so
//!   they never pin the stack. A restack entry has no branch (`branch = ""`)
//!   and contributes nothing.
//! - **Stack top** ([`stack_top`]) is the newest-claimed candidate; with none,
//!   the stack is empty and the next branch is cut from `main`.
//! - **Urgent entries branch from `main`**, not the stack top, so they can
//!   merge first.
//! - **The remote-project proxy**: a `host:path` project runs no git, so list
//!   state stands in — every claimed entry is a candidate, and `base` records
//!   the newest-claimed entry's branch *name* (growlightd can't resolve a
//!   commit there). A remote repo's `git` argument is never touched.
//!
//! ## The seam
//!
//! The model is pure: it takes the entries (plain data) plus a [`Git`] handle
//! and returns data. [`Git`] is the *only* thing that talks to the repo, and
//! every call is read-only (`merge-base --is-ancestor`, `rev-parse`) and takes
//! `--no-optional-locks`, so it never races the member's own git in the same
//! worktree (the same guard [`crate::item_repo`]'s probe uses). The unit tests
//! exercise the whole model against temp git repos, plus the remote path with a
//! `Git` pointed at a non-repo to prove it is never touched.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use softfig_ipc::queue_v2::{Lane, RestackBranch};

/// How long one read-only `git` call may run before it is killed. The stack is
/// computed at claim time, on the drive loop's one thread, so it must never
/// wedge the supervisor on a hung mount.
const GIT_TIMEOUT: Duration = Duration::from_secs(10);

/// A read-only git call that failed: git could not be run, the repo is not a
/// git repo, a rev does not resolve, or the call outlived its timeout.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// The child could not be spawned or waited on, or its exit status made no
    /// sense for the call (`merge-base --is-ancestor` other than 0/1; a failed
    /// `rev-parse`).
    #[error("git {cmd} in {repo}: {cause}")]
    Run {
        cmd: String,
        repo: PathBuf,
        cause: String,
    },
    /// The call outlived [`GIT_TIMEOUT`] and was killed.
    #[error("git {cmd} in {repo}: timed out after {secs}s")]
    Timeout {
        cmd: String,
        repo: PathBuf,
        secs: u64,
    },
}

/// The read-only git surface the stack model runs through. Production points it
/// at the entry's repo worktree; the unit tests point it at a temp repo.
#[derive(Debug, Clone)]
pub struct Git {
    repo: PathBuf,
}

impl Git {
    /// A handle over `repo`, used only for read-only queries.
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        Self { repo: repo.into() }
    }

    /// `git merge-base --is-ancestor <ancestor> <descendant>`: is `ancestor`
    /// reachable from `descendant`? Exit 0 = yes, exit 1 = no, anything else is
    /// an error (a non-commit, a bad repo, a timeout).
    pub fn is_ancestor(&self, ancestor: &str, descendant: &str) -> Result<bool, GitError> {
        let (status, _) = self.run(&["merge-base", "--is-ancestor", ancestor, descendant])?;
        match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GitError::Run {
                cmd: "merge-base --is-ancestor".into(),
                repo: self.repo.clone(),
                cause: status.to_string(),
            }),
        }
    }

    /// `git rev-parse <rev>`: resolve a committish (a branch name or a full
    /// hash) to its tip commit. Fails on an unknown rev.
    pub fn rev_parse(&self, rev: &str) -> Result<String, GitError> {
        let (status, out) = self.run(&["rev-parse", rev])?;
        if !status.success() {
            return Err(GitError::Run {
                cmd: "rev-parse".into(),
                repo: self.repo.clone(),
                cause: status.to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&out).trim().to_string())
    }

    /// `git rev-parse --abbrev-ref <branch>@{upstream}`: does `branch` track
    /// an upstream? `true` when git resolves it (exit 0), `false` when git
    /// reports none (exit 128 — a branch with no upstream, or no such branch),
    /// and an error on anything else (a bad repo, a timeout).
    pub fn has_upstream(&self, branch: &str) -> Result<bool, GitError> {
        let upstream = format!("{branch}@{{upstream}}");
        let (status, _) = self.run(&["rev-parse", "--abbrev-ref", &upstream])?;
        match status.code() {
            Some(0) => Ok(true),
            Some(128) => Ok(false),
            _ => Err(GitError::Run {
                cmd: "rev-parse --abbrev-ref <branch>@{upstream}".into(),
                repo: self.repo.clone(),
                cause: status.to_string(),
            }),
        }
    }

    /// `git merge-base <a> <b>`: the merge base of two committishes. Fails on
    /// an unknown rev.
    pub fn merge_base(&self, a: &str, b: &str) -> Result<String, GitError> {
        let (status, out) = self.run(&["merge-base", a, b])?;
        if !status.success() {
            return Err(GitError::Run {
                cmd: "merge-base".into(),
                repo: self.repo.clone(),
                cause: status.to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&out).trim().to_string())
    }

    fn run(&self, args: &[&str]) -> Result<(ExitStatus, Vec<u8>), GitError> {
        let mut child = Command::new("git")
            .arg("--no-optional-locks")
            .arg("-C")
            .arg(&self.repo)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| GitError::Run {
                cmd: args[0].into(),
                repo: self.repo.clone(),
                cause: e.to_string(),
            })?;
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let reader = thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stdout.read_to_end(&mut out);
            out
        });
        let deadline = Instant::now() + GIT_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5))
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(GitError::Timeout {
                        cmd: args[0].into(),
                        repo: self.repo.clone(),
                        secs: GIT_TIMEOUT.as_secs(),
                    });
                }
                Err(e) => {
                    let _ = reader.join();
                    return Err(GitError::Run {
                        cmd: "wait".into(),
                        repo: self.repo.clone(),
                        cause: e.to_string(),
                    });
                }
            }
        };
        let out = reader
            .join()
            .map_err(|_| GitError::Run {
                cmd: args[0].into(),
                repo: self.repo.clone(),
                cause: "stdout reader panicked".into(),
            })?;
        Ok((status, out))
    }
}

/// Where a repo's `main` lives and whether growlightd can run git against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repo {
    /// A local path — growlightd runs the read-only git queries against it.
    Local(PathBuf),
    /// A `host:path` project — growlightd runs no git; list state stands in
    /// (the remote proxy, §8). A `Repo::Remote` never touches the `Git` handle.
    Remote,
}

impl Repo {
    /// Classify a `[[project]]` `repo` value (§3.1): a `host:path` remote, or a
    /// local path (after `~` expansion against `home`). The same `:` test the
    /// grants spec and [`crate::item_repo::resolve_repo`] use to tell the two
    /// apart.
    pub fn classify(repo: &str, home: Option<&Path>) -> Repo {
        let value = repo.trim().trim_matches('`').trim();
        if value.contains(':') {
            return Repo::Remote;
        }
        let path = if value == "~" {
            match home {
                Some(h) => h.to_path_buf(),
                None => return Repo::Remote,
            }
        } else if let Some(rest) = value.strip_prefix("~/") {
            match home {
                Some(h) => h.join(rest),
                None => return Repo::Remote,
            }
        } else {
            PathBuf::from(value)
        };
        if path.is_absolute() {
            Repo::Local(path)
        } else {
            // A relative path or `~user` form is not probeable here; treat it
            // as remote rather than guess (mirrors item_repo's "no repo signal").
            Repo::Remote
        }
    }
}

/// One live entry reduced to what the stack computation reads. A live entry is
/// any entry still in the list (archived rows never reach this — §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackEntry {
    /// The entry id: a milestone's dir name, or a task's/restack's NNN.
    pub id: String,
    /// The entry's branch (`feat/<id>` / `fix/<id>`; `""` for a restack).
    pub branch: String,
    /// The entry's lane — urgent entries branch from `main`, not the stack top.
    pub lane: Lane,
    /// First-claim time, UTC (`""` = never claimed = not started). Orders the
    /// stack: the writer stamps it `YYYY-MM-DDTHH:MM:SSZ`, which orders
    /// lexicographically, so this module compares it as an opaque key (never
    /// parses it).
    pub claimed: String,
}

/// The stack for one repo: the live, started, unmerged entries that pin it, in
/// **claim order** (oldest first) — the order a bottom-first merge and a
/// restack walk them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Stack {
    pub candidates: Vec<StackEntry>,
}

impl Stack {
    /// The newest-claimed candidate (the stack top), or `None` when the stack
    /// is empty — then the next branch is cut from `main`.
    pub fn top(&self) -> Option<&StackEntry> {
        self.candidates.last()
    }
}

/// What a first claim records (§8): `parent` (the entry whose branch this was
/// cut from, `""` = `main`) and `base` (the commit cut from, local; the branch
/// *name*, remote).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimBase {
    pub parent: String,
    pub base: String,
}

/// Compute the stack candidates for `repo` from the live entries: every
/// started (`claimed` set) entry with a branch, in claim order, plus — for a
/// local repo — the read-only exclusion of any branch whose tip is an ancestor
/// of `main` (§8). A remote repo runs no git, so every claimed entry is a
/// candidate and `git` is never called.
pub fn stack_candidates(
    repo: &Repo,
    main: &str,
    entries: &[StackEntry],
    git: &Git,
) -> Result<Stack, GitError> {
    let mut candidates = Vec::new();
    for entry in entries {
        if entry.claimed.is_empty() || entry.branch.is_empty() {
            continue; // never claimed, or a restack with no branch
        }
        if let Repo::Local(_) = repo
            && git.is_ancestor(&entry.branch, main)?
        {
            continue; // already merged — not a candidate
        }
        candidates.push(entry.clone());
    }
    // Claim order = oldest first (a stable sort; equal stamps keep list order).
    candidates.sort_by(|a, b| a.claimed.cmp(&b.claimed));
    Ok(Stack { candidates })
}

/// The newest-claimed candidate (the stack top), or `None` with an empty
/// stack.
pub fn stack_top(stack: &Stack) -> Option<&StackEntry> {
    stack.top()
}

/// Compute what a first claim records for an entry in `lane` (§8):
///
/// - **urgent** branches from `main` (`parent = ""`), so it can merge first;
/// - **normal** branches from the stack top, or `main` when the stack is empty;
/// - local `base` is the cut-from branch's commit (`git rev-parse`); remote
///   `base` is the branch *name*.
pub fn claim_base(
    repo: &Repo,
    main: &str,
    lane: Lane,
    stack: &Stack,
    git: &Git,
) -> Result<ClaimBase, GitError> {
    let (parent, base_ref) = if lane == Lane::Urgent {
        (String::new(), main.to_string())
    } else {
        match stack.top() {
            Some(top) => (top.id.clone(), top.branch.clone()),
            None => (String::new(), main.to_string()),
        }
    };
    let base = match repo {
        Repo::Local(_) => git.rev_parse(&base_ref)?,
        Repo::Remote => base_ref,
    };
    Ok(ClaimBase { parent, base })
}

/// One live entry reduced to what restack detection reads: the §8 first-claim
/// fields ([`StackEntry`]) plus the recorded `parent` and `base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestackEntry {
    pub id: String,
    pub branch: String,
    pub lane: Lane,
    pub claimed: String,
    /// The recorded `parent` — the entry whose branch this was cut from;
    /// `""` = `main` (§8).
    pub parent: String,
    /// The recorded `base` — the commit cut from (local) / the parent branch
    /// name (remote). `""` = never claimed.
    pub base: String,
}

/// Detect a §8 restack: `main` moved under the open stack (an urgent fix
/// merged, or a lower branch amended in review). Walks the stack candidates in
/// claim order (read-only, via [`stack_candidates`]) and returns the ordered
/// stack — each branch with its recorded `parent`/`base` and the resolved
/// `--onto` target — when any branch's recorded `base` is no longer an
/// ancestor of its parent's tip (or `main`). `None` when the stack is healthy
/// (no false positive), empty, or remote (a remote repo never auto-enqueues,
/// §8 — growlightd can't see `main` move there). `git` is never written to.
pub fn detect_restack(
    repo: &Repo,
    main: &str,
    entries: &[RestackEntry],
    git: &Git,
) -> Result<Option<Vec<RestackBranch>>, GitError> {
    if matches!(repo, Repo::Remote) {
        return Ok(None);
    }
    let stack_input: Vec<StackEntry> = entries
        .iter()
        .map(|e| StackEntry {
            id: e.id.clone(),
            branch: e.branch.clone(),
            lane: e.lane,
            claimed: e.claimed.clone(),
        })
        .collect();
    let stack = stack_candidates(repo, main, &stack_input, git)?;
    if stack.candidates.is_empty() {
        return Ok(None);
    }
    // id → branch (to resolve a parent entry's branch), and branch → the
    // recorded (parent, base) pair.
    let branch_of: std::collections::HashMap<&str, &str> = entries
        .iter()
        .filter(|e| !e.branch.is_empty())
        .map(|e| (e.id.as_str(), e.branch.as_str()))
        .collect();
    let recorded: std::collections::HashMap<&str, (&str, &str)> = entries
        .iter()
        .filter(|e| !e.branch.is_empty())
        .map(|e| (e.branch.as_str(), (e.parent.as_str(), e.base.as_str())))
        .collect();

    let mut stale = false;
    let mut out = Vec::with_capacity(stack.candidates.len());
    for c in &stack.candidates {
        let Some(&(parent, base)) = recorded.get(c.branch.as_str()) else {
            continue; // a candidate with no recorded branch data — skip it
        };
        // The `--onto` target: the parent's branch, or `main` for a
        // main-rooted branch. A missing parent entry falls back to `main`
        // (defensive — a live parent is the §8 invariant).
        let onto = if parent.is_empty() {
            main.to_string()
        } else {
            branch_of.get(parent).copied().unwrap_or(main).to_string()
        };
        // Stale when the recorded base is no longer an ancestor of the parent's
        // tip (or `main`). An empty base (never recorded) can't be judged.
        if !base.is_empty() && !git.is_ancestor(base, &onto)? {
            stale = true;
        }
        out.push(RestackBranch {
            branch: c.branch.clone(),
            parent: parent.to_string(),
            base: base.to_string(),
            onto,
        });
    }
    if stale {
        Ok(Some(out))
    } else {
        Ok(None)
    }
}

/// One restacked branch's re-recorded base (§8): the `entry` it belongs to,
/// its `branch`, and the recomputed `base` (growlightd resolved it read-only
/// with `git merge-base` after the restack completed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReRecordedBase {
    pub entry: String,
    pub branch: String,
    pub base: String,
}

/// The result of a §8 re-record pass (queue-v2-git slice 004): either one new
/// base per restacked branch (claim order), or a branch that tracks an
/// upstream — which the loop never rewrites, so the restack blocks for the
/// human instead (`growlight_block kind = human`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReRecord {
    /// The new base per restacked branch, in claim order.
    Bases(Vec<ReRecordedBase>),
    /// A branch tracks an upstream: the loop must not rewrite it; block.
    Upstream { branch: String },
}

/// Re-record the restacked branches' bases after a restack completes (§8):
/// each branch's new `base` is `git merge-base <branch> <its parent's tip or
/// main>`. A branch that has an upstream is never rewritten — the pass returns
/// [`ReRecord::Upstream`] and the loop blocks for the human. A remote repo runs
/// no git and has no commit to resolve, so its pass is empty (the human
/// re-records by hand, §8). `git` is never written to.
pub fn re_record_bases(
    repo: &Repo,
    main: &str,
    entries: &[RestackEntry],
    git: &Git,
) -> Result<ReRecord, GitError> {
    if matches!(repo, Repo::Remote) {
        return Ok(ReRecord::Bases(Vec::new()));
    }
    let stack_input: Vec<StackEntry> = entries
        .iter()
        .map(|e| StackEntry {
            id: e.id.clone(),
            branch: e.branch.clone(),
            lane: e.lane,
            claimed: e.claimed.clone(),
        })
        .collect();
    let stack = stack_candidates(repo, main, &stack_input, git)?;
    if stack.candidates.is_empty() {
        return Ok(ReRecord::Bases(Vec::new()));
    }
    // branch → its recorded entry (for the parent), and id → branch (to
    // resolve a parent entry's branch), mirroring [`detect_restack`].
    let recorded: std::collections::HashMap<&str, &RestackEntry> = entries
        .iter()
        .filter(|e| !e.branch.is_empty())
        .map(|e| (e.branch.as_str(), e))
        .collect();
    let branch_of: std::collections::HashMap<&str, &str> = entries
        .iter()
        .filter(|e| !e.branch.is_empty())
        .map(|e| (e.id.as_str(), e.branch.as_str()))
        .collect();

    let mut out = Vec::with_capacity(stack.candidates.len());
    for c in &stack.candidates {
        let Some(entry) = recorded.get(c.branch.as_str()) else {
            continue; // a candidate with no recorded branch data — skip it
        };
        // The loop never rewrites a branch that tracks an upstream.
        if git.has_upstream(&c.branch)? {
            return Ok(ReRecord::Upstream {
                branch: c.branch.clone(),
            });
        }
        let onto = if entry.parent.is_empty() {
            main.to_string()
        } else {
            branch_of
                .get(entry.parent.as_str())
                .copied()
                .unwrap_or(main)
                .to_string()
        };
        let base = git.merge_base(&c.branch, &onto)?;
        out.push(ReRecordedBase {
            entry: c.id.clone(),
            branch: c.branch.clone(),
            base,
        });
    }
    Ok(ReRecord::Bases(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sh_git(repo: &Path, args: &[&str]) {
        git_with_stdin(repo, args, Stdio::null());
    }

    fn git_with_stdin(repo: &Path, args: &[&str], stdin: Stdio) {
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
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run git")
            .success();
        assert!(ok, "git {args:?}");
    }

    fn rev_parse_sh(repo: &Path, rev: &str) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["rev-parse", rev])
            .output()
            .expect("run git rev-parse");
        assert!(out.status.success(), "git rev-parse {rev}");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// A repo on `main` with one commit. Returns the temp dir and `main`'s tip.
    fn seeded_repo() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        sh_git(repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join("a.txt"), "base\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "base"]);
        let main = rev_parse_sh(repo, "main");
        (dir, main)
    }

    /// A branch off the current tip with one commit on it; returns to `main`
    /// and gives the branch's tip.
    fn open_branch(repo: &Path, name: &str) -> String {
        sh_git(repo, &["checkout", "-q", "-b", name]);
        let file = format!("{}.txt", name.replace('/', "_"));
        fs::write(repo.join(&file), format!("{name}\n")).unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", name]);
        sh_git(repo, &["checkout", "-q", "main"]);
        rev_parse_sh(repo, name)
    }

    /// A branch off the current tip, merged back into `main` (fast-forward), so
    /// its tip IS an ancestor of `main`.
    fn merged_branch(repo: &Path, name: &str) -> String {
        open_branch(repo, name);
        sh_git(repo, &["merge", "--ff-only", "-q", name]);
        rev_parse_sh(repo, name)
    }

    fn entry(id: &str, branch: &str, lane: Lane, claimed: &str) -> StackEntry {
        StackEntry {
            id: id.into(),
            branch: branch.into(),
            lane,
            claimed: claimed.into(),
        }
    }

    #[test]
    fn candidates_are_started_open_local_branches_only() {
        let (dir, _main) = seeded_repo();
        let repo = dir.path();
        open_branch(repo, "feat/one");
        merged_branch(repo, "feat/merged");
        open_branch(repo, "feat/unclaimed");

        let entries = vec![
            entry("one", "feat/one", Lane::Normal, "2026-10-01T00:00:00Z"),
            entry("merged", "feat/merged", Lane::Normal, "2026-10-02T00:00:00Z"),
            // never claimed — not started, never pins the stack
            entry("unclaimed", "feat/unclaimed", Lane::Normal, ""),
            // a restack has no branch
            entry("restack", "", Lane::Urgent, "2026-10-03T00:00:00Z"),
        ];

        let git = Git::new(repo.to_path_buf());
        let stack = stack_candidates(&Repo::Local(repo.to_path_buf()), "main", &entries, &git)
            .unwrap();
        let ids: Vec<&str> = stack.candidates.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["one"]);
    }

    #[test]
    fn candidates_sort_in_claim_order_and_top_is_newest() {
        let (dir, _main) = seeded_repo();
        let repo = dir.path();
        open_branch(repo, "feat/a");
        open_branch(repo, "feat/b");
        open_branch(repo, "feat/c");

        // List order is deliberately not claim order.
        let entries = vec![
            entry("c", "feat/c", Lane::Normal, "2026-10-03T00:00:00Z"),
            entry("a", "feat/a", Lane::Normal, "2026-10-01T00:00:00Z"),
            entry("b", "feat/b", Lane::Normal, "2026-10-02T00:00:00Z"),
        ];

        let git = Git::new(repo.to_path_buf());
        let stack = stack_candidates(&Repo::Local(repo.to_path_buf()), "main", &entries, &git)
            .unwrap();
        let ids: Vec<&str> = stack.candidates.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b", "c"], "claim order, oldest first");
        assert_eq!(stack_top(&stack).unwrap().id, "c", "newest claimed is the top");
    }

    #[test]
    fn claim_base_normal_follows_stack_top_and_urgent_uses_main_local() {
        let (dir, main_commit) = seeded_repo();
        let repo = dir.path();
        let _one = open_branch(repo, "feat/one");
        let two_tip = open_branch(repo, "feat/two");

        let entries = vec![
            entry("one", "feat/one", Lane::Normal, "2026-10-01T00:00:00Z"),
            entry("two", "feat/two", Lane::Normal, "2026-10-02T00:00:00Z"),
        ];

        let git = Git::new(repo.to_path_buf());
        let repo_kind = Repo::Local(repo.to_path_buf());
        let stack = stack_candidates(&repo_kind, "main", &entries, &git).unwrap();

        let normal = claim_base(&repo_kind, "main", Lane::Normal, &stack, &git).unwrap();
        assert_eq!(normal.parent, "two", "cut from the stack top");
        assert_eq!(normal.base, two_tip, "local base is the cut-from commit");

        let urgent = claim_base(&repo_kind, "main", Lane::Urgent, &stack, &git).unwrap();
        assert_eq!(urgent.parent, "", "urgent branches from main");
        assert_eq!(urgent.base, main_commit);
    }

    #[test]
    fn empty_stack_branches_from_main_local() {
        let (dir, main_commit) = seeded_repo();
        let repo = dir.path();
        let git = Git::new(repo.to_path_buf());
        let repo_kind = Repo::Local(repo.to_path_buf());
        let stack = stack_candidates(&repo_kind, "main", &[], &git).unwrap();
        assert!(stack.candidates.is_empty());

        let base = claim_base(&repo_kind, "main", Lane::Normal, &stack, &git).unwrap();
        assert_eq!(base.parent, "");
        assert_eq!(base.base, main_commit);
    }

    #[test]
    fn remote_resolves_by_list_state_and_never_runs_git() {
        // Point git at a non-repo: if the remote path ever touched git, these
        // calls would fail. They must not.
        let git = Git::new("/nonexistent/not-a-repo");
        let repo_kind = Repo::Remote;

        let entries = vec![
            entry("one", "feat/one", Lane::Normal, "2026-10-01T00:00:00Z"),
            entry("two", "feat/two", Lane::Normal, "2026-10-02T00:00:00Z"),
            // Even a branch that would be "merged" locally is a candidate: no git.
            entry("x", "feat/x", Lane::Normal, "2026-10-03T00:00:00Z"),
        ];

        let stack = stack_candidates(&repo_kind, "main", &entries, &git).unwrap();
        let ids: Vec<&str> = stack.candidates.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["one", "two", "x"], "every claimed entry pins the stack");

        let base = claim_base(&repo_kind, "main", Lane::Normal, &stack, &git).unwrap();
        assert_eq!(base.parent, "x", "newest claimed");
        assert_eq!(base.base, "feat/x", "remote base is the branch name, not a commit");

        let urgent = claim_base(&repo_kind, "main", Lane::Urgent, &stack, &git).unwrap();
        assert_eq!(urgent.parent, "");
        assert_eq!(urgent.base, "main");

        let empty = claim_base(&repo_kind, "main", Lane::Normal, &Stack::default(), &git).unwrap();
        assert_eq!(empty.parent, "");
        assert_eq!(empty.base, "main");
    }

    #[test]
    fn classify_splits_local_from_remote() {
        let home = Some(Path::new("/home/u"));
        assert_eq!(
            Repo::classify("~/p/repo", home),
            Repo::Local(PathBuf::from("/home/u/p/repo"))
        );
        assert_eq!(Repo::classify("~", home), Repo::Local(PathBuf::from("/home/u")));
        assert_eq!(
            Repo::classify("/abs/repo", home),
            Repo::Local(PathBuf::from("/abs/repo"))
        );
        assert_eq!(Repo::classify("otg-travel:/home/x", home), Repo::Remote);
        assert_eq!(Repo::classify("host:path", home), Repo::Remote);
        assert_eq!(Repo::classify("relative/repo", home), Repo::Remote);
        assert_eq!(Repo::classify("~/x", None), Repo::Remote, "no home to expand against");
    }

    #[test]
    fn is_ancestor_and_rev_parse_read_only() {
        let (dir, main_commit) = seeded_repo();
        let repo = dir.path();
        let git = Git::new(repo.to_path_buf());
        assert_eq!(git.rev_parse("main").unwrap(), main_commit);

        let child = open_branch(repo, "feat/child");
        // main is an ancestor of the child; the child is not an ancestor of main.
        assert!(git.is_ancestor(&main_commit, "feat/child").unwrap());
        assert!(git.is_ancestor("main", &child).unwrap());
        assert!(!git.is_ancestor("feat/child", "main").unwrap());

        // A rev that does not resolve is an error, not a panic or a false.
        assert!(git.rev_parse("no-such-branch").is_err());
        assert!(git.is_ancestor("no-such", "main").is_err());
    }

    // ---- restack detection (queue-v2-git slice 003) ----------------------

    /// A branch off `from` with one commit on it; returns to `main` and gives
    /// the branch's tip (so a stack can be cut branch-off-branch).
    fn open_branch_from(repo: &Path, name: &str, from: &str) -> String {
        sh_git(repo, &["checkout", "-q", from]);
        sh_git(repo, &["checkout", "-q", "-b", name]);
        let file = format!("{}.txt", name.replace('/', "_"));
        fs::write(repo.join(&file), format!("{name}\n")).unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", name]);
        sh_git(repo, &["checkout", "-q", "main"]);
        rev_parse_sh(repo, name)
    }

    /// Rewrite `main`'s tip so the recorded base commit is abandoned (an
    /// amend — the new tip is no longer a descendant of the old one).
    fn amend_main(repo: &Path) -> String {
        sh_git(repo, &["checkout", "-q", "main"]);
        fs::write(repo.join("a.txt"), "amended\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "--amend", "-m", "main rewritten"]);
        rev_parse_sh(repo, "main")
    }

    fn restack_entry(id: &str, branch: &str, parent: &str, base: &str, claimed: &str) -> RestackEntry {
        RestackEntry {
            id: id.into(),
            branch: branch.into(),
            lane: Lane::Normal,
            claimed: claimed.into(),
            parent: parent.into(),
            base: base.into(),
        }
    }

    #[test]
    fn detect_restack_fires_when_main_moves_under_a_two_branch_stack() {
        let (dir, main_commit) = seeded_repo();
        let repo = dir.path();
        let one_tip = open_branch_from(repo, "feat/one", "main");
        let two_tip = open_branch_from(repo, "feat/two", "feat/one");
        // main is rewritten AFTER the stack was cut: feat/one's recorded base
        // (the old main tip) is no longer an ancestor of main.
        let _new_main = amend_main(repo);

        let entries = vec![
            restack_entry("one", "feat/one", "", &main_commit, "2026-10-01T00:00:00Z"),
            restack_entry("two", "feat/two", "one", &one_tip, "2026-10-02T00:00:00Z"),
        ];

        let git = Git::new(repo.to_path_buf());
        let need = detect_restack(&Repo::Local(repo.to_path_buf()), "main", &entries, &git)
            .unwrap()
            .expect("a restack is needed");
        // The whole stack, in claim order, with each branch's parent/base/onto.
        assert_eq!(need.len(), 2, "{need:?}");
        assert_eq!(need[0].branch, "feat/one");
        assert_eq!(need[0].parent, "");
        assert_eq!(need[0].base, main_commit, "cut from the old main tip");
        assert_eq!(need[0].onto, "main");
        assert_eq!(need[1].branch, "feat/two");
        assert_eq!(need[1].parent, "one");
        assert_eq!(need[1].base, one_tip, "cut from feat/one's tip");
        assert_eq!(need[1].onto, "feat/one");
        // The two tips are untouched by the read-only detection.
        assert_eq!(rev_parse_sh(repo, "feat/one"), one_tip);
        assert_eq!(rev_parse_sh(repo, "feat/two"), two_tip);
    }

    #[test]
    fn detect_restack_is_silent_when_main_is_unchanged() {
        let (dir, _main) = seeded_repo();
        let repo = dir.path();
        let one_tip = open_branch_from(repo, "feat/one", "main");
        let _two_tip = open_branch_from(repo, "feat/two", "feat/one");

        let entries = vec![
            restack_entry("one", "feat/one", "", &rev_parse_sh(repo, "main"), "2026-10-01T00:00:00Z"),
            restack_entry("two", "feat/two", "one", &one_tip, "2026-10-02T00:00:00Z"),
        ];

        let git = Git::new(repo.to_path_buf());
        let need = detect_restack(&Repo::Local(repo.to_path_buf()), "main", &entries, &git).unwrap();
        assert!(need.is_none(), "no false positive when main is unchanged: {need:?}");
    }

    #[test]
    fn detect_restack_never_auto_enqueues_a_remote_repo() {
        // A remote repo runs no git — point the handle at a non-repo; if the
        // detection ever touched it, these calls would fail. They must not.
        let git = Git::new("/nonexistent/not-a-repo");
        let entries = vec![
            restack_entry("one", "feat/one", "", "deadbeef", "2026-10-01T00:00:00Z"),
        ];
        let need = detect_restack(&Repo::Remote, "main", &entries, &git).unwrap();
        assert!(need.is_none(), "a remote repo never auto-enqueues");
    }

    #[test]
    fn detect_restack_fires_when_a_lower_branch_is_rewritten() {
        let (dir, _main) = seeded_repo();
        let repo = dir.path();
        open_branch_from(repo, "feat/one", "main");
        let two_tip = open_branch_from(repo, "feat/two", "feat/one");
        // Amend feat/one (the lower branch): feat/two's recorded base (feat/one's
        // old tip) is no longer an ancestor of feat/one's new tip.
        sh_git(repo, &["checkout", "-q", "feat/one"]);
        fs::write(repo.join("feat_one.txt"), "rewritten\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "--amend", "-m", "one rewritten"]);
        sh_git(repo, &["checkout", "-q", "main"]);

        let entries = vec![
            restack_entry("one", "feat/one", "", &rev_parse_sh(repo, "main"), "2026-10-01T00:00:00Z"),
            restack_entry("two", "feat/two", "one", &two_tip, "2026-10-02T00:00:00Z"),
        ];

        let git = Git::new(repo.to_path_buf());
        let need = detect_restack(&Repo::Local(repo.to_path_buf()), "main", &entries, &git)
            .unwrap()
            .expect("a restack is needed");
        assert_eq!(need.len(), 2, "{need:?}");
        assert_eq!(need[0].branch, "feat/one");
        assert_eq!(need[1].branch, "feat/two");
        assert_eq!(need[1].base, two_tip, "feat/two's recorded base is feat/one's old tip");
        assert_eq!(need[1].onto, "feat/one");
    }

    // ---- restack execution (queue-v2-git slice 004) ---------------------

    /// Point `branch` at a fabricated `origin/<remote_branch>` remote-tracking
    /// ref, so `git rev-parse <branch>@{upstream}` resolves — the minimal
    /// upstream a branch can track in a temp repo.
    fn track_upstream(repo: &Path, branch: &str, remote_branch: &str) {
        let tip = rev_parse_sh(repo, "main");
        let remote_ref = format!("refs/remotes/origin/{remote_branch}");
        sh_git(repo, &["update-ref", &remote_ref, &tip]);
        // Register the remote so `--set-upstream-to` maps refs/heads/<remote>
        // to refs/remotes/origin/<remote> (a bare config `remote.origin.url`
        // alone is not enough — git requires the remote to be a real remote).
        sh_git(repo, &["remote", "add", "origin", "https://example.invalid/origin"]);
        let upstream = format!("origin/{remote_branch}");
        sh_git(repo, &["branch", "--set-upstream-to", &upstream, branch]);
    }

    #[test]
    fn re_record_recomputes_each_branch_base_as_merge_base() {
        let (dir, main_commit) = seeded_repo();
        let repo = dir.path();
        let one_tip = open_branch_from(repo, "feat/one", "main");
        let _two_tip = open_branch_from(repo, "feat/two", "feat/one");

        let entries = vec![
            restack_entry("one", "feat/one", "", &main_commit, "2026-10-01T00:00:00Z"),
            restack_entry("two", "feat/two", "one", &one_tip, "2026-10-02T00:00:00Z"),
        ];

        let git = Git::new(repo.to_path_buf());
        let ReRecord::Bases(bases) =
            re_record_bases(&Repo::Local(repo.to_path_buf()), "main", &entries, &git).unwrap()
        else {
            panic!("expected re-recorded bases");
        };
        assert_eq!(bases.len(), 2, "{bases:?}");
        assert_eq!(bases[0].entry, "one");
        assert_eq!(bases[0].branch, "feat/one");
        assert_eq!(
            bases[0].base, main_commit,
            "feat/one's base is merge-base(feat/one, main)"
        );
        assert_eq!(bases[1].entry, "two");
        assert_eq!(bases[1].branch, "feat/two");
        assert_eq!(
            bases[1].base, one_tip,
            "feat/two's base is merge-base(feat/two, feat/one)"
        );
        // The tips are untouched by the read-only re-record.
        assert_eq!(rev_parse_sh(repo, "feat/one"), one_tip);
    }

    #[test]
    fn re_record_blocks_on_an_upstream_branch_and_never_rewrites() {
        let (dir, main_commit) = seeded_repo();
        let repo = dir.path();
        let one_tip = open_branch_from(repo, "feat/one", "main");
        track_upstream(repo, "feat/one", "main");

        let entries = vec![
            restack_entry("one", "feat/one", "", &main_commit, "2026-10-01T00:00:00Z"),
        ];

        let git = Git::new(repo.to_path_buf());
        let outcome =
            re_record_bases(&Repo::Local(repo.to_path_buf()), "main", &entries, &git).unwrap();
        assert_eq!(
            outcome,
            ReRecord::Upstream {
                branch: "feat/one".to_string()
            },
            "an upstream branch is never rewritten: block for the human",
        );
        assert_eq!(rev_parse_sh(repo, "feat/one"), one_tip, "the tip is untouched");
    }

    #[test]
    fn re_record_is_empty_for_a_remote_repo() {
        let git = Git::new("/nonexistent/not-a-repo");
        let entries = vec![
            restack_entry("one", "feat/one", "", "deadbeef", "2026-10-01T00:00:00Z"),
        ];
        let outcome = re_record_bases(&Repo::Remote, "main", &entries, &git).unwrap();
        assert_eq!(outcome, ReRecord::Bases(Vec::new()), "no git against a remote repo");
    }
}
