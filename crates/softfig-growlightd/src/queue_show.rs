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
//! missing. [`build`] therefore collapses a git error to an empty stack for
//! that repo, and a missing doc to no session lines — it shows what it can.
//! A v2 file that does not *parse* is still a hard error, because the writer
//! owns that invariant; the caller (`server::queue_show`) surfaces it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use softfig_ipc::growlightd::{
    QueueProjectStack, QueueShowEntry, QueueShowReply, QueueShowSession, QueueShowSlice,
    QueueShowTree, QueueStackBranch,
};
use softfig_ipc::queue_v2::{
    milestone_path, EntryKind, QueueArchiveToml, SliceKind, QUEUE_ARCHIVE_FILE,
};

use crate::git_stack::{self, Git, Repo, StackEntry};
use crate::scheduler_v2::{EntryView, V2Snapshot};

/// `growlight/backlog/tasks/` — a task or restack doc lives here as
/// `NNN-<slug>.md` (§8; the keeperd v2 writer's `paths::tasks_dir`).
const TASKS_DIR: &str = "growlight/backlog/tasks";

/// Build the surface reply from an assembled snapshot: the per-repo stack (with
/// the live open/merged annotation), the entries in file order, and the §3.5
/// session-log lines. Pure over the snapshot + the read-only git surface + the
/// garden files it reads (`garden_root`, the mount in production; a temp garden
/// in tests). `home` expands `~` repo paths ([`Repo::classify`]).
pub fn build(snapshot: &V2Snapshot, garden_root: &Path, home: Option<&Path>) -> QueueShowReply {
    let mut reply = QueueShowReply {
        list: true,
        projects: Vec::new(),
        entries: Vec::new(),
        archived: Vec::new(),
        sessions: Vec::new(),
        trees: Vec::new(),
    };

    // The open branches per (project, branch) — the live annotation the entry
    // rows and the per-repo stacks share, computed once per repo.
    let mut open: HashSet<(String, String)> = HashSet::new();

    for project in &snapshot.projects {
        let repo_kind = Repo::classify(&project.repo, home);
        let local = matches!(repo_kind, Repo::Local(_));
        let git = match &repo_kind {
            Repo::Local(path) => Git::new(path.clone()),
            Repo::Remote => Git::new(PathBuf::new()),
        };
        let stack_entries: Vec<StackEntry> = snapshot
            .entries
            .iter()
            .filter(|e| e.project == project.name)
            .map(|e| StackEntry {
                id: e.id.clone(),
                branch: e.branch.clone(),
                lane: e.lane,
                claimed: e.claimed.clone(),
            })
            .collect();
        // A git error (not-a-repo, a not-yet-cut branch, a hung mount) collapses
        // to an empty stack: the surface shows what it can, never fails.
        let stack = git_stack::stack_candidates(&repo_kind, &project.main, &stack_entries, &git)
            .unwrap_or_default();

        // Record each candidate's parent/base from the snapshot (the fields the
        // §8 first claim wrote), and mark its branch open.
        let mut branches = Vec::with_capacity(stack.candidates.len());
        for candidate in &stack.candidates {
            let (parent, base) = snapshot
                .entries
                .iter()
                .find(|e| e.project == project.name && e.branch == candidate.branch)
                .map(|e| (e.parent.clone(), e.base.clone()))
                .unwrap_or_default();
            open.insert((project.name.clone(), candidate.branch.clone()));
            branches.push(QueueStackBranch {
                entry: candidate.id.clone(),
                branch: candidate.branch.clone(),
                parent,
                base,
                claimed: candidate.claimed.clone(),
            });
        }
        reply.projects.push(QueueProjectStack {
            name: project.name.clone(),
            repo: project.repo.clone(),
            main: project.main.clone(),
            local,
            stack: branches,
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
            open: !entry.branch.is_empty()
                && open.contains(&(entry.project.clone(), entry.branch.clone())),
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
                open: false,
            });
        }
    }

    reply
}

/// Collect one entry's §3.5 session-log lines: the entry's own doc (a
/// milestone's `CLAUDE.md` close-out, a task/restack doc), plus — for a
/// milestone — every slice doc in its tree and sub-trees. A missing doc (or a
/// missing `## Sessions` section) contributes nothing.
fn collect_sessions(
    snapshot: &V2Snapshot,
    entry: &EntryView,
    root: &Path,
    out: &mut Vec<QueueShowSession>,
) {
    match entry.kind {
        EntryKind::Milestone => {
            let close = format!("{}/CLAUDE.md", milestone_path(&entry.id));
            push_session(root, &close, &entry.id, None, out);
            // The entry's own tree and every sub-milestone tree under it.
            let prefix = format!("{}/", entry.id);
            for (identity, tree) in &snapshot.trees {
                if identity == &entry.id || identity.starts_with(&prefix) {
                    let dir = format!("{}/slices", milestone_path(identity));
                    for item in &tree.items {
                        if item.kind == SliceKind::Slice
                            && let Some(doc) = find_by_number(root, &dir, &item.id)
                        {
                            push_session(root, &doc, &entry.id, Some(&item.id), out);
                        }
                    }
                }
            }
        }
        EntryKind::Task | EntryKind::Restack => {
            if let Some(doc) = find_by_number(root, TASKS_DIR, &entry.id) {
                push_session(root, &doc, &entry.id, None, out);
            }
        }
    }
}

/// Read `rel`'s `## Sessions` section and append one [`QueueShowSession`] when
/// it carries lines.
fn push_session(root: &Path, rel: &str, entry: &str, unit: Option<&str>, out: &mut Vec<QueueShowSession>) {
    let Ok(content) = std::fs::read_to_string(root.join(rel)) else {
        return;
    };
    let lines = extract_sessions(&content);
    if !lines.is_empty() {
        out.push(QueueShowSession {
            entry: entry.to_string(),
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

    /// A repo on `main`, plus an open branch and a merged branch.
    fn seeded_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
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
        dir
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
        let reply = build(&snapshot, root, None);

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
        };
        let reply = build(&snapshot, Path::new("/nonexistent"), None);
        assert_eq!(reply.projects.len(), 1);
        assert!(!reply.projects[0].local);
        assert_eq!(reply.projects[0].stack.len(), 2, "list state: every claimed entry");
        assert!(reply.entries.iter().all(|e| e.open));
    }

    #[test]
    fn a_not_yet_cut_branch_collapses_to_no_open_not_a_failure() {
        // A claimed entry whose branch does not exist yet in the repo: the
        // read-only git probe fails, and the surface shows an empty stack
        // rather than erroring.
        let repo = tempfile::tempdir().unwrap();
        sh_git(repo.path(), &["init", "-q", "-b", "main"]);
        fs::write(repo.path().join("a.txt"), "base\n").unwrap();
        sh_git(repo.path(), &["add", "."]);
        sh_git(repo.path(), &["commit", "-q", "-m", "base"]);

        let entries = vec![entry(
            "ghost",
            "feat/ghost",
            Lane::Normal,
            EntryStatus::Active,
            "2026-10-01T00:00:00Z",
        )];
        let snapshot = snap(repo.path(), entries, BTreeMap::new());
        let reply = build(&snapshot, repo.path(), None);
        assert!(reply.projects[0].stack.is_empty());
        assert!(!reply.entries[0].open);
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

        let reply = build(&snapshot, root, None);
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

        let reply = build(&snapshot, root, None);
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
        let reply = build(&snapshot, repo.path(), None);
        assert!(reply.archived.is_empty(), "no archive file → empty archive");
    }
}
