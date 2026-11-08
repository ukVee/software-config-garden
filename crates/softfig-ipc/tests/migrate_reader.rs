//! `queue_v2::migrate::read_legacy` over `tests/fixtures/migrate/`: a trimmed,
//! read-only copy of the live garden backlog (2026-10-30) — `garden/` mirrors
//! the garden root, `batons/` the growlight runtime dir. Slice docs are cut to
//! their heading line and member batons to their head. Two edits are synthetic,
//! since the live garden has neither shape: task 069's `> Not before:` line,
//! and agent c's baton naming 069 (live: 064).

mod common;

use softfig_ipc::queue_v2::migrate::{LegacyBacklog, LegacyItem, read_legacy};

fn fixture() -> LegacyBacklog {
    read_legacy(&common::fixture_files()).unwrap()
}

fn item<'a>(backlog: &'a LegacyBacklog, id: &str) -> &'a LegacyItem {
    backlog.queues.iter().flat_map(|q| &q.items).find(|i| i.id == id).unwrap()
}

#[test]
fn queues_are_default_then_the_registry_in_order_with_their_repo_cells() {
    let backlog = fixture();
    let shape: Vec<_> = backlog
        .queues
        .iter()
        .map(|q| (q.name.as_str(), q.repo.as_deref(), q.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>()))
        .collect();
    assert_eq!(shape, vec![
        ("default", None, vec!["semi-auto-backend-seam", "069", "folder-grants", "claude-login-pool-wiring"]),
        ("docs", Some("/home/owner/projects/softfig-docs"), vec![]),
        (
            "roadeye",
            Some("build.example.invalid:/srv/roadeye (REMOTE — ssh build.example.invalid, port 2222)"),
            vec!["roadeye-m2-daemon-core"],
        ),
        ("hoverview", Some("/home/owner/projects/hover-view"), vec!["hover-view-sticky", "hover-view-player"]),
        ("fixes", Some("~/projects/software-config_garden/codebase"), vec![]),
    ]);
    assert!(backlog.orphan_tables.is_empty());
}

#[test]
fn a_deferred_milestone_reads_its_slices_in_number_order_and_its_unescaped_title() {
    let backlog = fixture();
    let seam = item(&backlog, "semi-auto-backend-seam");
    assert_eq!((seam.kind.as_str(), seam.status.as_str()), ("milestone", "deferred"));
    assert_eq!(seam.title, "Semi-auto growlight: real AgentBackend seam (claude|opencode)");
    assert_eq!(seam.docs, vec!["growlight/backlog/milestones/semi-auto-backend-seam/CLAUDE.md"]);
    assert_eq!(seam.slices, vec!["001", "002", "003", "004", "005", "006"]);
    assert!(seam.subs.is_empty());
    assert_eq!(seam.meta.fleet, None);
}

#[test]
fn a_task_reads_its_one_doc_tag_and_not_before() {
    let backlog = fixture();
    let task = item(&backlog, "069");
    assert_eq!(task.kind, "task");
    assert_eq!(task.docs, vec!["growlight/backlog/tasks/069-spin-guard-parks-progressing-work.md"]);
    assert_eq!(task.tags, vec!["bug"]);
    assert_eq!(task.meta.not_before.as_deref(), Some("2026-11-02 09:00 Z"));
    assert!(task.slices.is_empty());
}

#[test]
fn metadata_and_branch_policy_read_as_growlightd_reads_them() {
    let backlog = fixture();
    let grants = item(&backlog, "folder-grants");
    assert_eq!(grants.tags, vec!["human/semi-auto, fleet-core"]);
    assert_eq!(grants.meta.fleet.as_deref(), Some("no"));
    assert_eq!(grants.meta.model.as_deref(), Some("claude"));
    assert_eq!(grants.meta.worktree.as_deref(), Some("~/projects/software-config_garden/codebase/folder-grants"));
    let policy = grants.branch_policy.as_deref().unwrap();
    assert!(policy.starts_with("Branch `feat/folder-grants` off `main` (`5ed0ea3` or later)"), "{policy}");
    assert!(!policy.contains("## Standing constraints"));
    assert_eq!(grants.slices.len(), 6);
    assert_eq!(item(&backlog, "roadeye-m2-daemon-core").meta.model.as_deref(), Some("claude"));
}

#[test]
fn a_named_queue_item_keeps_its_blocked_on_tag_and_a_done_row_its_missing_doc() {
    let backlog = fixture();
    let player = item(&backlog, "hover-view-player");
    assert_eq!(player.tags, vec!["blocked on hover-view-sticky"]);
    assert!(player.title.starts_with("[blocked on hover-view-sticky] "));
    assert_eq!(player.meta.fleet.as_deref(), Some("no"));
    assert_eq!(player.branch_policy, None);
    let done = item(&backlog, "claude-login-pool-wiring");
    assert_eq!(done.status, "done");
    assert!(done.docs.is_empty(), "the fixture omits the done milestone's doc");
}

#[test]
fn batons_are_the_root_and_member_heads_never_parked_copies() {
    let backlog = fixture();
    let batons: Vec<_> = backlog
        .batons
        .iter()
        .map(|b| (b.path.as_str(), b.item.as_str(), b.status.as_deref()))
        .collect();
    assert_eq!(batons, vec![
        ("agents/b/baton.md", "072", Some("IN_PROGRESS")),
        ("agents/c/baton.md", "069", Some("IN_PROGRESS")),
        ("baton.md", "claude-login-pool-wiring", Some("ITEM_DEFERRED")),
    ]);
}
