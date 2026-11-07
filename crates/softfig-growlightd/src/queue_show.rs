//! The §6.9 **human surfaces' read model** (queue-v2-git slice 006): reduce the
//! v2 snapshot to what `growlight status` and `queue show` render — the two
//! lanes' entries, the archive (§3.2), the per-repo stack with its **live
//! git-stack annotations** (which branches are still open, via slice 001's
//! stack model), and the §3.5 session log.
//!
//! ## Why growlightd owns this
//!
//! The stack annotation needs the read-only git surface ([`crate::git_stack`])
//! — `merge-base --is-ancestor` decides whether a started branch is still open
//! or already merged into `main`. keeperd runs no git (§8), so only growlightd
//! can answer "the stack per repo" and the per-entry `open` flag. Both human
//! surfaces call growlightd's `queue_show` op for it.
//!
//! ## Fail-soft, never fail-closed
//!
//! Unlike the scheduling path, a surface must not fail because one repo is not
//! a git repo yet (a member claimed a branch it has not cut) or a doc is
//! missing. [`build`] therefore reports a git error as that repo's
//! `stack_unknown`, and a missing doc as no session lines — it shows what it
//! can. It never reports a failed read as an empty stack: that renders every
//! started branch as merged. A v2 file that does not *parse* is still a hard
//! error, because the writer owns that invariant; the caller
//! (`server::queue_show`) surfaces it.
//!
//! ## Bounded
//!
//! The git runs through [`crate::git_probe`]: one probe per repo, all started
//! before any is waited on, so wedged repos cost one deadline between them and
//! not one each, and a repo that missed its deadline is held instead of being
//! waited on again by the next `queue show`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use softfig_ipc::growlightd::{
    QueueProjectStack, QueueShowEntry, QueueShowReply, QueueShowSession, QueueShowSlice,
    QueueShowTree, QueueStackBranch,
};
use softfig_ipc::queue_v2::{
    milestone_path, EntryKind, QueueArchiveToml, SliceKind, QUEUE_ARCHIVE_FILE,
};

use crate::git_probe::{Probe, ProbeCache};
use crate::git_stack::{self, Git, GitError, Repo, Stack, StackEntry};
use crate::scheduler_v2::{EntryView, ProjectView, V2Snapshot};

/// `growlight/backlog/tasks/` — a task or restack doc lives here as
/// `NNN-<slug>.md` (§8; the keeperd v2 writer's `paths::tasks_dir`).
const TASKS_DIR: &str = "growlight/backlog/tasks";

/// Build the surface reply from an assembled snapshot: the per-repo stack (with
/// the live open/merged annotation), the entries in file order, and the §3.5
/// session-log lines. Pure over the snapshot + the read-only git surface + the
/// garden files it reads (`garden_root`, the mount in production; a temp garden
/// in tests). `home` expands `~` repo paths ([`Repo::classify`]). `probes` runs
/// the git, and `now` (Unix seconds) is the time its holds are judged by.
pub fn build(
    snapshot: &V2Snapshot,
    garden_root: &Path,
    home: Option<&Path>,
    probes: &ProbeCache,
    now: i64,
) -> QueueShowReply {
    let mut reply = QueueShowReply {
        list: true,
        projects: Vec::new(),
        entries: Vec::new(),
        archived: Vec::new(),
        sessions: Vec::new(),
        trees: Vec::new(),
    };

    // The entries whose branch is open — the live annotation the entry rows and
    // the per-repo stacks share, computed once per repo.
    let mut open: HashSet<String> = HashSet::new();

    // The projects whose stack could not be read: their started branches are
    // unknown, not closed.
    let mut unknown: HashSet<String> = HashSet::new();

    // One row per repo (§8): the projects naming a repo share its stack, so one
    // read answers them all, judged against the first one's `main`.
    let mut repos: Vec<Vec<&ProjectView>> = Vec::new();
    for project in &snapshot.projects {
        match repos.iter_mut().find(|group| group[0].repo == project.repo) {
            Some(group) => group.push(project),
            None => repos.push(vec![project]),
        }
    }

    probes.begin_tick(now);
    let reads: Vec<StackRead> = repos
        .iter()
        .map(|group| StackRead::start(snapshot, group[0], home, probes))
        .collect();

    for (group, read) in repos.iter().zip(reads) {
        let project = group[0];
        let local = matches!(read, StackRead::Probing(_));
        // A real git error (not-a-repo, a hung mount) is that repo's unknown: the
        // surface shows what it can, never fails. (A not-yet-cut branch is not an
        // error — `stack_candidates` just skips it.)
        let (stack, stack_unknown) = match read.wait() {
            Ok(stack) => (stack, None),
            Err(e) => {
                unknown.extend(group.iter().map(|p| p.name.clone()));
                (Stack::default(), Some(e.to_string()))
            }
        };

        // Record each candidate's parent/base from the snapshot (the fields the
        // §8 first claim wrote), and mark its branch open.
        let mut branches = Vec::with_capacity(stack.candidates.len());
        for candidate in &stack.candidates {
            let (parent, base) = snapshot
                .entries
                .iter()
                .find(|e| e.id == candidate.id)
                .map(|e| (e.parent.clone(), e.base.clone()))
                .unwrap_or_default();
            open.insert(candidate.id.clone());
            branches.push(QueueStackBranch {
                entry: candidate.id.clone(),
                branch: candidate.branch.clone(),
                parent,
                base,
                claimed: candidate.claimed.clone(),
            });
        }
        reply.projects.push(QueueProjectStack {
            name: group.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "),
            repo: project.repo.clone(),
            main: project.main.clone(),
            local,
            stack: branches,
            stack_unknown,
        });
    }

    for entry in &snapshot.entries {
        reply.entries.push(QueueShowEntry {
            id: entry.id.clone(),
            kind: entry.kind.to_string(),
            project: entry.project.clone(),
            lane: entry.lane.to_string(),
            status: entry.status.to_string(),
            after: entry.after.clone(),
            branch: entry.branch.clone(),
            base: entry.base.clone(),
            claimed: entry.claimed.clone(),
            pending_status: entry.pending.map(|s| s.to_string()),
            open: open.contains(&entry.id),
            open_unknown: !entry.branch.is_empty()
                && !entry.claimed.is_empty()
                && unknown.contains(&entry.project),
        });
    }

    for entry in &snapshot.entries {
        collect_sessions(snapshot, entry, garden_root, &mut reply.sessions);
    }

    // Each live milestone's slice tree (§3.3), in file order — the §6.9 "expands
    // to its slice list" half. A sessionless slice is still visible here (unlike
    // the session log, which only names a slice once it has rolled), so the TUI
    // can address any slice's `slice_update` verb by id.
    for (identity, tree) in &snapshot.trees {
        reply.trees.push(QueueShowTree {
            milestone: identity.clone(),
            slices: tree
                .items
                .iter()
                .map(|item| QueueShowSlice {
                    id: item.id.clone(),
                    kind: item.kind.to_string(),
                    status: item.status.to_string(),
                })
                .collect(),
        });
    }

    // The archive (§3.2): every row that left the list, `done`/`dropped` in the
    // order it left. Read here, not from the snapshot (which reduces the archive
    // to `done_ids` for `after` resolution) — and fail-soft: a missing or
    // unparseable archive contributes nothing, the live lanes are the core render.
    if let Ok(text) = std::fs::read_to_string(garden_root.join(QUEUE_ARCHIVE_FILE))
        && let Ok(archive) = QueueArchiveToml::parse(&text)
    {
        for a in archive.entries {
            reply.archived.push(QueueShowEntry {
                id: a.row.id,
                kind: a.row.kind.to_string(),
                project: a.row.project,
                lane: String::new(),
                status: a.final_status.to_string(),
                after: a.row.after,
                branch: a.row.branch,
                base: a.row.base,
                claimed: a.row.claimed,
                pending_status: None,
                open: false,
                open_unknown: false,
            });
        }
    }

    reply
}

/// One repo's stack on its way: a local repo's bounded probe, or a remote
/// repo's list-state answer, which runs no git.
enum StackRead {
    Probing(Probe<Stack>),
    Remote(Result<Stack, GitError>),
}

impl StackRead {
    fn start(
        snapshot: &V2Snapshot,
        project: &ProjectView,
        home: Option<&Path>,
        probes: &ProbeCache,
    ) -> Self {
        let entries: Vec<StackEntry> = snapshot
            .entries_in_repo(&project.repo)
            .map(|e| StackEntry {
                id: e.id.clone(),
                branch: e.branch.clone(),
                lane: e.lane,
                claimed: e.claimed.clone(),
            })
            .collect();
        let main = project.main.clone();
        let repo = Repo::classify(&project.repo, home);
        match &repo {
            Repo::Local(path) => {
                let path = path.clone();
                Self::Probing(probes.spawn(&path, move |git| {
                    git_stack::stack_candidates(&repo, &main, &entries, git)
                }))
            }
            Repo::Remote => {
                let nowhere = Git::new(PathBuf::new());
                Self::Remote(git_stack::stack_candidates(&repo, &main, &entries, &nowhere))
            }
        }
    }

    fn wait(self) -> Result<Stack, GitError> {
        match self {
            Self::Probing(probe) => probe.wait(),
            Self::Remote(stack) => stack,
        }
    }
}

/// Collect one entry's §3.5 session-log lines: the entry's own doc (a
/// milestone's `CLAUDE.md` close-out, a task/restack doc), plus — for a
/// milestone — every slice doc in its tree and sub-trees, and each sub's own
/// close-out. A missing doc (or a missing `## Sessions` section) contributes
/// nothing.
fn collect_sessions(
    snapshot: &V2Snapshot,
    entry: &EntryView,
    root: &Path,
    out: &mut Vec<QueueShowSession>,
) {
    match entry.kind {
        EntryKind::Milestone => {
            let close = format!("{}/CLAUDE.md", milestone_path(&entry.id));
            push_session(root, &close, &entry.id, None, None, out);
            // The entry's own tree and every sub-milestone tree under it.
            let prefix = format!("{}/", entry.id);
            for (identity, tree) in &snapshot.trees {
                if identity == &entry.id || identity.starts_with(&prefix) {
                    let sub = (identity != &entry.id).then_some(identity.as_str());
                    if sub.is_some() {
                        let close = format!("{}/CLAUDE.md", milestone_path(identity));
                        push_session(root, &close, &entry.id, sub, None, out);
                    }
                    let dir = format!("{}/slices", milestone_path(identity));
                    for item in &tree.items {
                        if item.kind == SliceKind::Slice
                            && let Some(doc) = find_by_number(root, &dir, &item.id)
                        {
                            push_session(root, &doc, &entry.id, sub, Some(&item.id), out);
                        }
                    }
                }
            }
        }
        EntryKind::Task | EntryKind::Restack => {
            if let Some(doc) = find_by_number(root, TASKS_DIR, &entry.id) {
                push_session(root, &doc, &entry.id, None, None, out);
            }
        }
    }
}

/// Read `rel`'s `## Sessions` section and append one [`QueueShowSession`] when
/// it carries lines.
fn push_session(
    root: &Path,
    rel: &str,
    entry: &str,
    tree: Option<&str>,
    unit: Option<&str>,
    out: &mut Vec<QueueShowSession>,
) {
    let Ok(content) = std::fs::read_to_string(root.join(rel)) else {
        return;
    };
    let lines = extract_sessions(&content);
    if !lines.is_empty() {
        out.push(QueueShowSession {
            entry: entry.to_string(),
            tree: tree.map(str::to_string),
            unit: unit.map(str::to_string),
            path: rel.to_string(),
            lines,
        });
    }
}

/// The `- <ts> · …` lines of a doc's `## Sessions` section, in order. The
/// section ends at the next heading; anything else in it that is not a list
/// line is ignored (keeperd writes only list lines there).
fn extract_sessions(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## Sessions") {
            in_section = true;
            continue;
        }
        if !in_section {
            continue;
        }
        if trimmed.starts_with('#') {
            break; // the next section ends the log
        }
        if trimmed.starts_with("- ") {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Find `<dir>/<n>-<slug>.md` by listing `dir` (the slice/task docs carry the
/// number in the filename; the slug is not in the TOML). `None` when the dir
/// does not exist or no file matches.
fn find_by_number(root: &Path, dir: &str, n: &str) -> Option<String> {
    let full = root.join(dir);
    let entries = std::fs::read_dir(&full).ok()?;
    let prefix = format!("{n}-");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".md") {
            return Some(format!("{dir}/{name}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler_v2::{ItemView, ProjectView, TreeView};
    use softfig_ipc::queue_v2::{ArchivedEntry, Entry, EntryStatus, FinalStatus, Lane};
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

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

    /// [`build`] over real git, with no hold in play.
    fn show(snapshot: &V2Snapshot, root: &Path) -> QueueShowReply {
        build(snapshot, root, None, &ProbeCache::new(), 0)
    }

    /// A repo on `main`, plus an open branch and a merged branch.
    fn seeded_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        dir
    }

    fn seed(repo: &Path) {
        sh_git(repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join("a.txt"), "base\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "base"]);
        // An open branch (cut from main, left unmerged).
        sh_git(repo, &["checkout", "-q", "-b", "feat/open"]);
        fs::write(repo.join("open.txt"), "open\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "feat/open"]);
        sh_git(repo, &["checkout", "-q", "main"]);
        // A branch cut from main and fast-forwarded back: its tip becomes an
        // ancestor of main, so it is not an open candidate.
        sh_git(repo, &["checkout", "-q", "-b", "feat/merged"]);
        fs::write(repo.join("merged.txt"), "merged\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "feat/merged"]);
        sh_git(repo, &["checkout", "-q", "main"]);
        sh_git(repo, &["merge", "--ff-only", "-q", "feat/merged"]);
        sh_git(repo, &["checkout", "-q", "main"]);
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
            holder: None,
            models: None,
        }
    }

    fn snap(repo: &Path, entries: Vec<EntryView>, trees: BTreeMap<String, TreeView>) -> V2Snapshot {
        V2Snapshot {
            projects: vec![ProjectView {
                name: "softfig".into(),
                repo: repo.display().to_string(),
                main: "main".into(),
            }],
            entries,
            trees,
            done_ids: Default::default(),
            done_branches: Default::default(),
            done_projects: Default::default(),
            re_records_due: Default::default(),
        }
    }

    fn item(kind: SliceKind, id: &str) -> ItemView {
        ItemView {
            kind,
            id: id.into(),
            status: softfig_ipc::queue_v2::SliceStatus::Queued,
            models: None,
            follow_ups: 0,
        }
    }

    #[test]
    fn build_annotates_open_vs_merged_and_lists_the_stack() {
        let repo = seeded_repo();
        let root = repo.path();
        let entries = vec![
            entry("open", "feat/open", Lane::Normal, EntryStatus::Active, "2026-10-01T00:00:00Z"),
            entry("merged", "feat/merged", Lane::Normal, EntryStatus::Blocked, "2026-10-02T00:00:00Z"),
            entry("queued", "feat/queued", Lane::Normal, EntryStatus::Queued, ""),
        ];
        let snapshot = snap(root, entries, BTreeMap::new());
        let reply = show(&snapshot, root);

        assert!(reply.list);
        assert_eq!(reply.entries.len(), 3, "file order is list order");
        let open = reply.entries.iter().find(|e| e.id == "open").unwrap();
        assert!(open.open, "an unmerged started branch is open");
        assert_eq!(open.status, "active");
        assert_eq!(open.lane, "normal");
        let merged = reply.entries.iter().find(|e| e.id == "merged").unwrap();
        assert!(!merged.open, "a branch merged into main is not open");
        let queued = reply.entries.iter().find(|e| e.id == "queued").unwrap();
        assert!(!queued.open, "a never-claimed entry has no open branch");

        // The stack per repo: only the open branch, in claim order.
        assert_eq!(reply.projects.len(), 1);
        let proj = &reply.projects[0];
        assert!(proj.local);
        assert_eq!(proj.stack.len(), 1);
        assert_eq!(proj.stack[0].branch, "feat/open");
        assert_eq!(proj.stack[0].entry, "open");
    }

    #[test]
    fn a_pending_human_status_reaches_the_reply() {
        // An `active` entry a human has marked `blocked` still reads `active`
        // until the handshake applies it; the reply must say what is waiting.
        let repo = seeded_repo();
        let root = repo.path();
        let mut waiting = entry("w", "feat/w", Lane::Normal, EntryStatus::Active, "2026-10-01T00:00:00Z");
        waiting.pending = Some(EntryStatus::Blocked);
        let plain = entry("p", "feat/p", Lane::Normal, EntryStatus::Active, "2026-10-01T00:00:00Z");
        let reply = show(&snap(root, vec![waiting, plain], BTreeMap::new()), root);
        let w = reply.entries.iter().find(|e| e.id == "w").unwrap();
        assert_eq!((w.status.as_str(), w.pending_status.as_deref()), ("active", Some("blocked")));
        let p = reply.entries.iter().find(|e| e.id == "p").unwrap();
        assert_eq!(p.pending_status, None);
        // Absent on the wire when none is pending, and tolerated when absent.
        let json = serde_json::to_value(p).unwrap();
        assert!(json.get("pending_status").is_none(), "{json}");
        let back: softfig_ipc::growlightd::QueueShowEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.pending_status, None);
    }

    #[test]
    fn a_remote_repo_is_list_state_and_never_runs_git() {
        // A `host:path` project: every claimed branch is open (no git), and the
        // git handle is pointed nowhere but never touched.
        let mut one = entry("one", "feat/one", Lane::Normal, EntryStatus::Blocked, "2026-10-01T00:00:00Z");
        one.project = "phone".into();
        let mut two = entry("two", "feat/two", Lane::Normal, EntryStatus::Active, "2026-10-02T00:00:00Z");
        two.project = "phone".into();
        let entries = vec![one, two];
        let snapshot = V2Snapshot {
            projects: vec![ProjectView {
                name: "phone".into(),
                repo: "otg-travel:/srv/roadeye".into(),
                main: "main".into(),
            }],
            entries,
            trees: BTreeMap::new(),
            done_ids: Default::default(),
            done_branches: Default::default(),
            done_projects: Default::default(),
            re_records_due: Default::default(),
        };
        let reply = show(&snapshot, Path::new("/nonexistent"));
        assert_eq!(reply.projects.len(), 1);
        assert!(!reply.projects[0].local);
        assert_eq!(reply.projects[0].stack.len(), 2, "list state: every claimed entry");
        assert!(reply.entries.iter().all(|e| e.open));
    }

    #[test]
    fn a_not_yet_cut_branch_is_not_open_and_does_not_hide_its_siblings() {
        // A claimed entry whose branch does not exist yet in the repo is simply
        // not a candidate. It is not open, and it no longer blanks the whole
        // project's stack (V3).
        let repo = tempfile::tempdir().unwrap();
        sh_git(repo.path(), &["init", "-q", "-b", "main"]);
        fs::write(repo.path().join("a.txt"), "base\n").unwrap();
        sh_git(repo.path(), &["add", "."]);
        sh_git(repo.path(), &["commit", "-q", "-m", "base"]);

        sh_git(repo.path(), &["checkout", "-q", "-b", "feat/real"]);
        fs::write(repo.path().join("b.txt"), "real\n").unwrap();
        sh_git(repo.path(), &["add", "."]);
        sh_git(repo.path(), &["commit", "-q", "-m", "real"]);
        sh_git(repo.path(), &["checkout", "-q", "main"]);

        let entries = vec![
            entry("ghost", "feat/ghost", Lane::Normal, EntryStatus::Active, "2026-10-01T00:00:00Z"),
            entry("real", "feat/real", Lane::Normal, EntryStatus::Active, "2026-10-02T00:00:00Z"),
        ];
        let snapshot = snap(repo.path(), entries, BTreeMap::new());
        let reply = show(&snapshot, repo.path());
        assert_eq!(reply.projects[0].stack.len(), 1, "only the cut branch is in the stack");
        assert_eq!(reply.projects[0].stack[0].entry, "real");
        let open = |id: &str| reply.entries.iter().find(|e| e.id == id).unwrap().open;
        assert!(!open("ghost"));
        assert!(open("real"));
    }

    /// A `git` that hangs on any repo whose path says `wedged`, until `thawed`
    /// appears in `dir`, and is the real one everywhere else. Logs each call.
    /// Returns `(script, log)`.
    fn wedging_git(dir: &Path) -> (PathBuf, PathBuf) {
        let log = dir.join("calls.log");
        let script = dir.join("fake-git");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{log}'\ncase \"$*\" in *wedged*) [ -e '{thawed}' ] || exec sleep 30 ;; esac\nexec git \"$@\"\n",
                log = log.display(),
                thawed = dir.join("thawed").display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        (script, log)
    }

    fn wedged_repo() -> tempfile::TempDir {
        let dir = tempfile::Builder::new().prefix("wedged").tempdir().unwrap();
        seed(dir.path());
        dir
    }

    fn project(name: &str, repo: &Path) -> ProjectView {
        ProjectView {
            name: name.into(),
            repo: repo.display().to_string(),
            main: "main".into(),
        }
    }

    /// A started entry of `project`, on `branch`.
    fn started(id: &str, project: &str, branch: &str) -> EntryView {
        let mut e = entry(id, branch, Lane::Normal, EntryStatus::Active, "2026-10-01T00:00:00Z");
        e.project = project.into();
        e
    }

    fn snapshot_of(projects: Vec<ProjectView>, entries: Vec<EntryView>) -> V2Snapshot {
        V2Snapshot {
            projects,
            entries,
            trees: BTreeMap::new(),
            done_ids: Default::default(),
            done_branches: Default::default(),
            done_projects: Default::default(),
            re_records_due: Default::default(),
        }
    }

    #[test]
    fn wedged_repos_answer_within_one_deadline_with_an_explicit_unknown() {
        let bin = tempfile::tempdir().unwrap();
        let (git, _) = wedging_git(bin.path());
        let probes = ProbeCache::with(Duration::from_secs(1), git);
        let (one, two, three) = (wedged_repo(), wedged_repo(), wedged_repo());
        let healthy = seeded_repo();
        let mut never_claimed = started("queued", "one", "feat/queued");
        never_claimed.claimed = String::new();
        let snapshot = snapshot_of(
            vec![
                project("one", one.path()),
                project("two", two.path()),
                project("three", three.path()),
                project("healthy", healthy.path()),
            ],
            vec![
                started("a", "one", "feat/open"),
                never_claimed,
                started("b", "two", "feat/open"),
                started("c", "three", "feat/open"),
                started("open", "healthy", "feat/open"),
                started("merged", "healthy", "feat/merged"),
            ],
        );

        let begun = Instant::now();
        let reply = build(&snapshot, bin.path(), None, &probes, 1000);
        // One after another, these would cost three deadlines.
        assert!(begun.elapsed() < Duration::from_secs(2), "{:?}", begun.elapsed());

        let wire = |id: &str| reply.entries.iter().find(|e| e.id == id).unwrap();
        for p in &reply.projects[..3] {
            let why = p.stack_unknown.as_deref().unwrap_or_default();
            assert!(why.contains("timed out"), "{p:?}");
            assert!(p.stack.is_empty() && p.local, "{p:?}");
        }
        for id in ["a", "b", "c"] {
            assert!(wire(id).open_unknown && !wire(id).open, "{:?}", wire(id));
        }
        assert!(!wire("queued").open_unknown, "a never-claimed entry has no branch to be unsure of");

        // The wedged repos don't touch their healthy neighbour's answer.
        assert_eq!(reply.projects[3].stack_unknown, None);
        assert_eq!(reply.projects[3].stack.len(), 1);
        assert!(wire("open").open && !wire("open").open_unknown);
        assert!(!wire("merged").open && !wire("merged").open_unknown);
    }

    #[test]
    fn a_repo_that_missed_the_deadline_is_held_then_read_again() {
        let bin = tempfile::tempdir().unwrap();
        let (git, log) = wedging_git(bin.path());
        let probes = ProbeCache::with(Duration::from_millis(300), git);
        let repo = wedged_repo();
        let snapshot = snapshot_of(
            vec![project("one", repo.path())],
            vec![started("a", "one", "feat/open")],
        );
        let unknown = |reply: &QueueShowReply| reply.projects[0].stack_unknown.clone();

        let first = build(&snapshot, bin.path(), None, &probes, 1000);
        assert!(unknown(&first).is_some_and(|why| why.contains("timed out")), "{first:?}");
        let spawned = fs::read_to_string(&log).unwrap().lines().count();

        // The next `queue show` doesn't wait the deadline out again, and spawns nothing.
        let begun = Instant::now();
        let held = build(&snapshot, bin.path(), None, &probes, 1001);
        assert!(begun.elapsed() < Duration::from_millis(250), "{:?}", begun.elapsed());
        assert!(unknown(&held).is_some_and(|why| why.contains("held")), "{held:?}");
        assert!(held.entries[0].open_unknown, "{held:?}");
        assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), spawned);

        // Past the hold, a repo that recovered reads as it is.
        fs::write(bin.path().join("thawed"), "").unwrap();
        let back = 1000 + crate::drive_loop::v2_claim_backoff_secs(1);
        let reply = build(&snapshot, bin.path(), None, &probes, back);
        assert_eq!(unknown(&reply), None, "{reply:?}");
        assert_eq!(reply.projects[0].stack.len(), 1);
        assert!(reply.entries[0].open && !reply.entries[0].open_unknown, "{reply:?}");
    }

    /// §8: `queue show` lists the stack per repo, so two projects on one repo
    /// are one row, and each one's entry reads as open from it.
    #[test]
    fn two_projects_on_one_repo_show_one_stack() {
        let repo = seeded_repo();
        sh_git(repo.path(), &["checkout", "-q", "-b", "feat/two"]);
        fs::write(repo.path().join("two.txt"), "two\n").unwrap();
        sh_git(repo.path(), &["add", "."]);
        sh_git(repo.path(), &["commit", "-q", "-m", "two"]);
        sh_git(repo.path(), &["checkout", "-q", "main"]);
        let mut two = started("two", "mirror", "feat/two");
        two.claimed = "2026-10-02T00:00:00Z".into();
        let snapshot = snapshot_of(
            vec![project("softfig", repo.path()), project("mirror", repo.path())],
            vec![started("one", "softfig", "feat/open"), two],
        );

        let reply = show(&snapshot, repo.path());

        assert_eq!(reply.projects.len(), 1, "{:?}", reply.projects);
        assert_eq!(reply.projects[0].name, "softfig, mirror");
        let branches: Vec<&str> =
            reply.projects[0].stack.iter().map(|b| b.branch.as_str()).collect();
        assert_eq!(branches, ["feat/open", "feat/two"]);
        assert!(reply.entries.iter().all(|e| e.open), "{:?}", reply.entries);
    }

    #[test]
    fn a_path_that_is_not_a_repo_is_unknown_not_an_empty_stack() {
        let not_a_repo = tempfile::tempdir().unwrap();
        let snapshot = snapshot_of(
            vec![project("one", not_a_repo.path())],
            vec![started("a", "one", "feat/a")],
        );
        let reply = show(&snapshot, not_a_repo.path());
        assert!(reply.projects[0].stack_unknown.is_some(), "{reply:?}");
        assert!(reply.entries[0].open_unknown, "{reply:?}");
    }

    #[test]
    fn session_logs_read_from_close_out_and_slice_docs() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        let mut entries = vec![entry(
            "m",
            "feat/m",
            Lane::Normal,
            EntryStatus::Active,
            "2026-10-01T00:00:00Z",
        )];
        entries[0].kind = EntryKind::Milestone;
        // A tree with two slices.
        let mut trees = BTreeMap::new();
        trees.insert(
            "m".to_string(),
            TreeView {
                items: vec![item(SliceKind::Slice, "001"), item(SliceKind::Slice, "002")],
                models: None,
            },
        );
        let snapshot = snap(root, entries, trees);

        // The milestone close-out doc and the two slice docs, each with a
        // `## Sessions` section.
        fs::create_dir_all(root.join("growlight/backlog/milestones/m/slices")).unwrap();
        fs::write(
            root.join("growlight/backlog/milestones/m/CLAUDE.md"),
            "# m\n\n## Sessions\n\n- 2026-10-11T15:40Z · completed · reasoning · member oc · $0.04\n",
        )
        .unwrap();
        fs::write(
            root.join("growlight/backlog/milestones/m/slices/001-first.md"),
            "# 001\n\n## Sessions\n\n- 2026-10-11T15:30Z · context_full · flash · member oc · $0.01\n",
        )
        .unwrap();
        fs::write(
            root.join("growlight/backlog/milestones/m/slices/002-second.md"),
            "# 002\n\n## Notes\n\nno sessions yet\n",
        )
        .unwrap();

        let reply = show(&snapshot, root);
        // The slice tree is carried too — a sessionless slice (002) is still
        // visible in `trees`, so the TUI can address its `slice_update` by id.
        assert_eq!(reply.trees.len(), 1, "{:?}", reply.trees);
        assert_eq!(reply.trees[0].milestone, "m");
        let tree_ids: Vec<&str> = reply.trees[0]
            .slices
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(tree_ids, vec!["001", "002"]);
        // Close-out + slice 001 have lines; slice 002 has none.
        assert_eq!(reply.sessions.len(), 2, "{:?}", reply.sessions);
        let close = reply.sessions.iter().find(|s| s.unit.is_none()).unwrap();
        assert!(close.path.ends_with("milestones/m/CLAUDE.md"), "{close:?}");
        assert_eq!(close.lines.len(), 1);
        assert!(close.lines[0].contains("completed"));
        let slice = reply.sessions.iter().find(|s| s.unit.as_deref() == Some("001")).unwrap();
        assert!(slice.path.ends_with("001-first.md"), "{slice:?}");
        assert!(slice.lines[0].contains("context_full"));
    }

    #[test]
    fn a_sub_s_session_lines_carry_its_tree_and_stay_apart_from_the_parent_s() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut entries = vec![entry(
            "m",
            "feat/m",
            Lane::Normal,
            EntryStatus::Active,
            "2026-10-01T00:00:00Z",
        )];
        entries[0].kind = EntryKind::Milestone;
        let mut trees = BTreeMap::new();
        for identity in ["m", "m/rest"] {
            trees.insert(
                identity.to_string(),
                TreeView { items: vec![item(SliceKind::Slice, "001")], models: None },
            );
        }
        let snapshot = snap(root, entries, trees);

        let parent = root.join("growlight/backlog/milestones/m");
        let sub = parent.join("subs/rest");
        for d in [&parent, &sub] {
            fs::create_dir_all(d.join("slices")).unwrap();
        }
        fs::write(parent.join("slices/001-a.md"), "## Sessions\n\n- parent slice\n").unwrap();
        fs::write(sub.join("slices/001-b.md"), "## Sessions\n\n- sub slice\n").unwrap();
        fs::write(sub.join("CLAUDE.md"), "## Sessions\n\n- sub close-out\n").unwrap();

        let mut out = Vec::new();
        collect_sessions(&snapshot, &snapshot.entries[0], root, &mut out);
        let of = |line: &str| out.iter().find(|s| s.lines == [line]).unwrap();
        let parent_slice = of("- parent slice");
        assert_eq!((parent_slice.tree.as_deref(), parent_slice.unit.as_deref()), (None, Some("001")));
        let sub_slice = of("- sub slice");
        assert_eq!((sub_slice.tree.as_deref(), sub_slice.unit.as_deref()), (Some("m/rest"), Some("001")));
        let close = of("- sub close-out");
        assert_eq!((close.tree.as_deref(), close.unit.as_deref()), (Some("m/rest"), None));
        assert!(out.iter().all(|s| s.entry == "m"), "{out:?}");
    }

    #[test]
    fn extract_sessions_stops_at_the_next_heading() {
        let doc = "## Sessions\n- a\n- b\n## Next\n- not a session\n";
        assert_eq!(extract_sessions(doc), vec!["- a", "- b"]);
        assert_eq!(extract_sessions("no sections\n"), Vec::<String>::new());
    }

    /// An archive row whose `final_status` and (for a drop) `reason` are set;
    /// the flattened entry `row` is the minimum the writer would have moved.
    fn archived(id: &str, final_status: FinalStatus, reason: Option<&str>) -> ArchivedEntry {
        ArchivedEntry {
            row: Entry {
                id: id.into(),
                kind: EntryKind::Milestone,
                title: "archived entry".into(),
                project: "softfig".into(),
                lane: Lane::Normal,
                status: EntryStatus::Queued,
                after: vec![],
                added: "2026-10-01T00:00:00Z".into(),
                branch: format!("feat/{id}"),
                parent: String::new(),
                base: String::new(),
                claimed: "2026-10-01T00:00:00Z".into(),
                follow_ups: 0,
                pending_status: None,
            },
            finished: "2026-10-02T00:00:00Z".into(),
            final_status,
            reason: reason.map(str::to_string),
            re_record_due: false,
        }
    }

    #[test]
    fn archive_rows_carry_final_status_and_no_lane() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        // No live entries — the archive is orthogonal to the live lanes.
        let snapshot = snap(root, vec![], BTreeMap::new());
        let archive = QueueArchiveToml::new(vec![
            archived("done-one", FinalStatus::Done, None),
            archived("dropped-one", FinalStatus::Dropped, Some("abandoned")),
        ]);
        fs::create_dir_all(root.join("growlight/backlog")).unwrap();
        fs::write(
            root.join(QUEUE_ARCHIVE_FILE),
            archive.to_toml().expect("serialize archive"),
        )
        .unwrap();

        let reply = show(&snapshot, root);
        assert_eq!(reply.archived.len(), 2, "archive order is exit order");
        let done = &reply.archived[0];
        assert_eq!(done.id, "done-one");
        assert_eq!(done.status, "done");
        assert!(done.lane.is_empty(), "an archive row has no lane");
        assert!(!done.open, "an archive row is never an open branch");
        assert_eq!(done.project, "softfig");
        let dropped = &reply.archived[1];
        assert_eq!(dropped.status, "dropped");
        assert_eq!(dropped.branch, "feat/dropped-one");
    }

    #[test]
    fn a_missing_archive_contributes_no_rows() {
        let repo = tempfile::tempdir().unwrap();
        let snapshot = snap(repo.path(), vec![], BTreeMap::new());
        let reply = show(&snapshot, repo.path());
        assert!(reply.archived.is_empty(), "no archive file → empty archive");
    }
}
