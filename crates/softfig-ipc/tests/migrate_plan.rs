//! `queue_v2::migrate::plan` end to end: `read_legacy` → `plan`, one test per
//! `## Mapping` row (M and R) and per `CallClass`, then the golden run over
//! the whole fixture under `tests/fixtures/migrate/answers.toml`. Where the
//! fixture (see `migrate_reader.rs`) lacks a shape, the test builds a small
//! `LegacyFiles` inline. The apply-time row (`v2_files_present`) is slice 005's.

mod common;

use std::collections::BTreeMap;

use softfig_ipc::queue_v2::migrate::{
    ANSWERS_SCHEMA_VERSION, Answers, BatonMove, CallClass, LIST_ORDER_PROPOSAL, LegacyFiles, MigrationPlan, plan,
    read_legacy,
};
use softfig_ipc::queue_v2::{
    Entry, EntryKind, EntryStatus, FinalStatus, Lane, QueueArchiveToml, QueueToml, SliceKind, SliceStatus,
    SlicesToml,
};

const NOW: &str = "2026-11-01T00:00:00Z";
const BACKLOG: &str = "growlight/backlog/CLAUDE.md";

fn answers() -> Answers {
    let raw = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/migrate/answers.toml"),
    )
    .unwrap();
    toml::from_str(&raw).unwrap()
}

fn fixture_plan() -> MigrationPlan {
    plan(&read_legacy(&common::fixture_files()).unwrap(), &answers(), NOW)
}

/// Answers that settle the calls every inline backlog raises.
fn base_answers() -> Answers {
    Answers {
        schema: ANSWERS_SCHEMA_VERSION,
        class: BTreeMap::from([
            (CallClass::ListOrder, LIST_ORDER_PROPOSAL.to_string()),
            (CallClass::ProjectMain, "main".to_string()),
        ]),
        call: BTreeMap::from([("project_repo:softfig".to_string(), "/srv/softfig".to_string())]),
    }
}

/// A queue table: `(id, type, title, status)` rows under `softfig:<tag>`.
fn table(tag: &str, rows: &[(&str, &str, &str, &str)]) -> String {
    let mut s = format!("<!-- softfig:{tag} -->\n\n| # | id | type | title | status |\n|---|---|---|---|---|");
    for (i, (id, kind, title, status)) in rows.iter().enumerate() {
        s.push_str(&format!("\n| {} | {id} | {kind} | {title} | {status} |", i + 1));
    }
    s + &format!("\n\n<!-- /softfig:{tag} -->\n\n")
}

fn registry(rows: &[(&str, &str)]) -> String {
    let mut s = "<!-- softfig:queues -->\n\n| queue | repo |\n|---|---|".to_string();
    for (queue, repo) in rows {
        s.push_str(&format!("\n| {queue} | {repo} |"));
    }
    s + "\n\n<!-- /softfig:queues -->\n\n"
}

fn files(garden: &[(&str, &str)], batons: &[(&str, &str)]) -> LegacyFiles {
    let map = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    LegacyFiles { garden: map(garden), batons: map(batons) }
}

fn milestone_doc(id: &str) -> String {
    format!("growlight/backlog/milestones/{id}/CLAUDE.md")
}

fn task_doc(id: &str) -> String {
    format!("growlight/backlog/tasks/{id}-t.md")
}

fn inline_plan(garden: &[(&str, &str)], batons: &[(&str, &str)]) -> MigrationPlan {
    plan(&read_legacy(&files(garden, batons)).unwrap(), &base_answers(), NOW)
}

fn keys(plan: &MigrationPlan) -> Vec<String> {
    plan.calls.iter().map(|c| c.key.to_string()).collect()
}

fn has_call(plan: &MigrationPlan, key: &str) {
    assert!(keys(plan).iter().any(|k| k == key), "{key} missing from {:?}", keys(plan));
}

fn entry<'a>(plan: &'a MigrationPlan, id: &str) -> &'a Entry {
    plan.queue.entries.iter().find(|e| e.id == id).unwrap_or_else(|| panic!("no entry {id}"))
}

fn slices<'a>(plan: &'a MigrationPlan, id: &str) -> &'a SlicesToml {
    &plan.slices.iter().find(|(m, _)| m == id).unwrap_or_else(|| panic!("no slices.toml for {id}")).1
}

fn calls_about(plan: &MigrationPlan, id: &str) -> Vec<String> {
    plan.calls.iter().filter(|c| c.key.subject == id).map(|c| c.key.to_string()).collect()
}

// ── `## Mapping`: the mechanical (M) rows ──────────────────────────────────

#[test]
fn m_live_statuses_keep_their_name() {
    let doc = table("queue", &[
        ("001", "task", "Q", "queued"),
        ("002", "task", "A", "active"),
        ("003", "task", "D", "deferred"),
        ("004", "task", "B", "blocked"),
    ]);
    let (d1, d2, d3, d4) = (task_doc("001"), task_doc("002"), task_doc("003"), task_doc("004"));
    let plan = inline_plan(&[(BACKLOG, &doc), (&d1, ""), (&d2, ""), (&d3, ""), (&d4, "")], &[]);
    let statuses: Vec<_> = plan.queue.entries.iter().map(|e| (e.id.as_str(), e.status)).collect();
    assert_eq!(statuses, vec![
        ("001", EntryStatus::Queued),
        ("002", EntryStatus::Active),
        ("003", EntryStatus::Deferred),
        ("004", EntryStatus::Blocked),
    ]);
}

#[test]
fn m_a_done_row_is_an_archive_row_finished_at_apply_time() {
    let plan = fixture_plan();
    let [done] = plan.archive.entries.as_slice() else { panic!("{:?}", plan.archive.entries) };
    assert_eq!((done.row.id.as_str(), done.final_status, done.finished.as_str()), (
        "claude-login-pool-wiring",
        FinalStatus::Done,
        NOW
    ));
    assert!(plan.queue.entries.iter().all(|e| e.id != "claude-login-pool-wiring"));
}

#[test]
fn m_every_entry_is_on_the_normal_lane() {
    assert!(fixture_plan().queue.entries.iter().all(|e| e.lane == Lane::Normal));
}

#[test]
fn m_a_clean_registry_cell_is_the_project_repo() {
    let plan = fixture_plan();
    let hover = plan.queue.projects.iter().find(|p| p.name == "hoverview").unwrap();
    assert_eq!(hover.repo, "/home/ukv/projects/hover-view");
    assert!(calls_about(&plan, "hoverview").iter().all(|k| k.starts_with("project_main:")));
}

#[test]
fn m_a_milestone_row_is_a_milestone_entry_named_by_its_dir() {
    let plan = fixture_plan();
    let seam = entry(&plan, "semi-auto-backend-seam");
    assert_eq!((seam.kind, seam.project.as_str()), (EntryKind::Milestone, "softfig"));
    assert_eq!(entry(&plan, "roadeye-m2-daemon-core").project, "roadeye");
}

#[test]
fn m_a_task_row_is_a_task_entry_named_by_its_number() {
    let plan = fixture_plan();
    assert_eq!(entry(&plan, "069").kind, EntryKind::Task);
}

#[test]
fn m_titles_stay_verbatim_minus_a_resolved_blocked_on_tag() {
    let plan = fixture_plan();
    assert!(entry(&plan, "hover-view-player").title.starts_with("hover-view own player — "));
    assert!(entry(&plan, "folder-grants").title.starts_with("[human/semi-auto, fleet-core] Folder grants"));
}

#[test]
fn m_blocked_on_a_known_id_is_after() {
    let plan = fixture_plan();
    assert_eq!(entry(&plan, "hover-view-player").after, vec!["hover-view-sticky"]);
    assert!(calls_about(&plan, "hover-view-player").iter().all(|k| !k.starts_with("blocked_on:")));
}

#[test]
fn m_added_is_apply_time() {
    assert!(fixture_plan().queue.entries.iter().all(|e| e.added == NOW));
}

#[test]
fn m_no_branch_policy_is_the_default_branch() {
    let plan = fixture_plan();
    assert_eq!(entry(&plan, "semi-auto-backend-seam").branch, "feat/semi-auto-backend-seam");
    assert_eq!(entry(&plan, "069").branch, "fix/069");
}

#[test]
fn m_a_branch_policy_naming_the_default_branch_and_its_worktree_dir_is_that_branch() {
    // Live prose: "Branch `feat/folder-grants` off `main` …, in its own
    // worktree (`codebase/folder-grants`)" — the second token is the
    // `> Worktree:` directory, not a branch.
    let plan = fixture_plan();
    assert_eq!(entry(&plan, "folder-grants").branch, "feat/folder-grants");
    assert!(!keys(&plan).contains(&"branch:folder-grants".to_string()), "{:?}", keys(&plan));
}

#[test]
fn m_a_never_started_entry_has_no_parent_base_or_claim() {
    let plan = fixture_plan();
    for id in ["folder-grants", "roadeye-m2-daemon-core"] {
        let e = entry(&plan, id);
        assert_eq!((e.parent.as_str(), e.base.as_str(), e.claimed.as_str()), ("", "", ""), "{id}");
    }
}

#[test]
fn m_slices_are_in_filename_number_order_with_no_follow_ups() {
    let plan = fixture_plan();
    let seam = slices(&plan, "semi-auto-backend-seam");
    let ids: Vec<_> = seam.items.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["001", "002", "003", "004", "005", "006"]);
    assert!(seam.items.iter().all(|s| s.kind == SliceKind::Slice && s.follow_ups == Some(0)));
}

#[test]
fn m_a_queued_milestone_has_every_slice_queued() {
    let plan = fixture_plan();
    let grants = slices(&plan, "folder-grants");
    assert_eq!(grants.items.len(), 6);
    assert!(grants.items.iter().all(|s| s.status == SliceStatus::Queued));
    assert!(calls_about(&plan, "folder-grants").is_empty(), "{:?}", calls_about(&plan, "folder-grants"));
}

#[test]
fn m_a_done_milestone_has_no_slices_file() {
    assert!(fixture_plan().slices.iter().all(|(id, _)| id != "claude-login-pool-wiring"));
}

#[test]
fn m_fleet_absent_or_yes_is_fleet_true() {
    assert!(entry(&fixture_plan(), "semi-auto-backend-seam").fleet);
    let doc = table("queue", &[("001", "task", "T", "queued")]);
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("001"), "> Fleet: yes\n")], &[]);
    assert!(entry(&plan, "001").fleet);
}

#[test]
fn m_fleet_any_other_value_is_fleet_false() {
    let plan = fixture_plan();
    assert!(!entry(&plan, "folder-grants").fleet);
    assert!(!entry(&plan, "hover-view-player").fleet);
}

#[test]
fn m_a_parsing_not_before_is_kept_verbatim() {
    let plan = fixture_plan();
    assert_eq!(entry(&plan, "069").not_before.as_deref(), Some("2026-11-02 09:00 Z"));
    assert!(!keys(&plan).contains(&"not_before:069".to_string()));
}

#[test]
fn m_a_single_entry_model_line_raises_nothing() {
    let plan = fixture_plan();
    for id in ["folder-grants", "roadeye-m2-daemon-core"] {
        assert!(!keys(&plan).contains(&format!("model:{id}")), "{id}");
    }
}

#[test]
fn m_worktree_and_grants_lines_stay_in_the_doc() {
    // Neither is an entry field, and neither raises a call. folder-grants
    // declares `> Worktree:` (see the queued-milestone test); `> Grants:` is
    // inline, since no fixture doc carries one.
    let doc = table("queue", &[("001", "task", "T", "queued")]);
    let meta = "> Worktree: ~/w/001\n> Grants: ~/w/001, ~/notes\n";
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("001"), meta)], &[]);
    assert!(calls_about(&plan, "001").is_empty(), "{:?}", calls_about(&plan, "001"));
    assert_eq!((entry(&plan, "001").branch.as_str(), entry(&plan, "001").base.as_str()), ("fix/001", ""));
}

#[test]
fn m_an_in_progress_baton_naming_one_live_entry_is_copied() {
    let plan = fixture_plan();
    assert_eq!(plan.batons, vec![BatonMove { from: "agents/c/baton.md".into(), entry: "069".into() }]);
    assert!(!keys(&plan).contains(&"baton:agents/c/baton.md".to_string()));
}

// ── `## Mapping`: the refusal (R) rows ─────────────────────────────────────

#[test]
fn r_subs_under_a_legacy_milestone_refuse() {
    let doc = table("queue", &[("m", "milestone", "M", "queued")]);
    let (m, sub) = (milestone_doc("m"), "growlight/backlog/milestones/m/subs/s/CLAUDE.md");
    let plan = inline_plan(&[(BACKLOG, &doc), (&m, "# m\n"), (sub, "# s\n")], &[]);
    let subjects: Vec<_> = plan.refusals.iter().map(|r| r.subject.as_str()).collect();
    assert_eq!(subjects, vec!["m"]);
    assert!(!plan.applicable());
}

#[test]
fn r_an_unregistered_queue_table_refuses() {
    let doc = table("queue", &[]) + &table("queue:ghost", &[("g", "task", "G", "queued")]);
    let plan = inline_plan(&[(BACKLOG, &doc)], &[]);
    let subjects: Vec<_> = plan.refusals.iter().map(|r| r.subject.as_str()).collect();
    assert_eq!(subjects, vec!["queue:ghost"]);
    assert!(plan.queue.entries.is_empty() && !plan.applicable());
}

/// Report 128: the read view hides a doc's metadata, so its `> Fleet: no`
/// could be anywhere. The row refuses and never lands as `fleet = true`.
fn assert_refused_unread(plan: &MigrationPlan, id: &str, path: &str) {
    let refusals: Vec<_> = plan.refusals.iter().filter(|r| r.subject == id).collect();
    assert_eq!(refusals.len(), 1, "{:?}", plan.refusals);
    assert!(refusals[0].reason.starts_with(&format!("{path}: ")), "{}", refusals[0].reason);
    assert!(plan.queue.entries.iter().all(|e| e.id != id), "a refused row migrates nothing");
    assert!(!plan.applicable());
}

#[test]
fn r_a_whole_file_sealed_item_doc_refuses() {
    let doc = table("queue", &[("x", "milestone", "X", "queued")]);
    let m = milestone_doc("x");
    let plan = inline_plan(&[(BACKLOG, &doc), (&m, &format!("[sealed:{m}]\n"))], &[]);
    assert_refused_unread(&plan, "x", &m);
}

#[test]
fn r_a_hold_inside_a_sealed_region_refuses() {
    let doc = table("queue", &[("001", "task", "T", "queued")]);
    let t = task_doc("001");
    let plan = inline_plan(&[(BACKLOG, &doc), (&t, "# t\n\n<vault id=\"h\">[encrypted]</vault>\n")], &[]);
    assert_refused_unread(&plan, "001", &t);
}

#[test]
fn r_a_sealed_slice_doc_refuses_its_milestone() {
    let doc = table("queue", &[("x", "milestone", "X", "active")]);
    let s = "growlight/backlog/milestones/x/slices/001-a.md";
    let plan = inline_plan(&[(BACKLOG, &doc), (&milestone_doc("x"), "# x\n"), (s, &format!("[sealed:{s}]\n"))], &[]);
    assert_refused_unread(&plan, "x", s);
}

#[test]
fn r_a_backlog_doc_with_a_sealed_region_refuses() {
    let doc = table("queue", &[]) + "<vault id=\"q\">[encrypted]</vault>\n";
    let plan = inline_plan(&[(BACKLOG, &doc)], &[]);
    let subjects: Vec<_> = plan.refusals.iter().map(|r| r.subject.as_str()).collect();
    assert_eq!(subjects, vec![BACKLOG]);
    assert!(!plan.applicable());
}

#[test]
fn r_an_archived_row_with_a_sealed_doc_raises_nothing() {
    let doc = table("queue", &[("x", "milestone", "X", "done")]);
    let m = milestone_doc("x");
    let plan = inline_plan(&[(BACKLOG, &doc), (&m, &format!("[sealed:{m}]\n"))], &[]);
    assert!(plan.refusals.is_empty(), "{:?}", plan.refusals);
    assert_eq!(plan.archive.entries.len(), 1);
}

// ── one test per `CallClass` ───────────────────────────────────────────────

#[test]
fn call_list_order() {
    has_call(&fixture_plan(), "list_order:list");
}

#[test]
fn call_project_repo() {
    let plan = fixture_plan();
    has_call(&plan, "project_repo:softfig");
    has_call(&plan, "project_repo:roadeye");
    assert_eq!(plan.queue.projects[0].name, "softfig", "the default queue is project `softfig`");
}

#[test]
fn call_project_main() {
    let plan = fixture_plan();
    for project in ["softfig", "docs", "roadeye", "hoverview", "fixes"] {
        has_call(&plan, &format!("project_main:{project}"));
    }
}

#[test]
fn call_same_repo() {
    let doc = registry(&[("a", "/r/code"), ("b", "/r/code/")]) + &table("queue", &[]);
    has_call(&inline_plan(&[(BACKLOG, &doc)], &[]), "same_repo:a+b");
}

#[test]
fn call_unknown_cell() {
    let doc = table("queue", &[("001", "epic", "T", "parked")]);
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("001"), "")], &[]);
    has_call(&plan, "unknown_cell:001.type");
    has_call(&plan, "unknown_cell:001.status");
}

#[test]
fn call_duplicate_id() {
    let doc = registry(&[("q", "/r/q")])
        + &table("queue", &[("001", "task", "T", "queued")])
        + &table("queue:q", &[("001", "task", "T", "queued")]);
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("001"), "")], &[]);
    has_call(&plan, "duplicate_id:001");
    assert_eq!(plan.queue.entries.len(), 1);
}

#[test]
fn call_item_doc() {
    let doc = table("queue", &[("001", "task", "T", "queued"), ("002", "task", "T", "queued")]);
    let two = "growlight/backlog/tasks/002-b.md";
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("002"), ""), (two, "")], &[]);
    has_call(&plan, "item_doc:001");
    has_call(&plan, "item_doc:002");
}

#[test]
fn call_blocked_on() {
    let doc = table("queue", &[("001", "task", "[blocked on X] T", "queued")]);
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("001"), "")], &[]);
    has_call(&plan, "blocked_on:001");
    assert_eq!(entry(&plan, "001").title, "[blocked on X] T", "an unresolved tag stays");
}

#[test]
fn call_branch() {
    let doc = table("queue", &[("m", "milestone", "M", "queued")]);
    let body = "# m\n\n## Branch policy\n\nWork on `feat/m-long`.\n";
    let plan = inline_plan(&[(BACKLOG, &doc), (&milestone_doc("m"), body)], &[]);
    has_call(&plan, "branch:m");
    assert_eq!(entry(&plan, "m").branch, "feat/m-long", "a single named branch is the proposal");
}

#[test]
fn call_stack_base() {
    let plan = fixture_plan();
    has_call(&plan, "stack_base:069");
    let e = entry(&plan, "hover-view-player");
    assert_eq!((e.parent.as_str(), e.base.as_str(), e.claimed.as_str()), ("hover-view-sticky", "a1b2c3d", NOW));
}

#[test]
fn call_slice_progress() {
    let plan = fixture_plan();
    has_call(&plan, "slice_progress:semi-auto-backend-seam");
    assert!(slices(&plan, "semi-auto-backend-seam").items.iter().all(|s| s.status == SliceStatus::Done));
    let sticky: Vec<_> = slices(&plan, "hover-view-sticky").items.iter().map(|s| s.status).collect();
    assert_eq!(&sticky[..4], &[SliceStatus::Done, SliceStatus::Done, SliceStatus::Active, SliceStatus::Queued]);
    assert!(
        !keys(&plan).contains(&"slice_progress:hover-view-player".to_string()),
        "a started milestone with no slices has nothing to settle"
    );
}

#[test]
fn call_not_before() {
    let doc = table("queue", &[("001", "task", "T", "queued")]);
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("001"), "> Not before: tomorrow\n")], &[]);
    has_call(&plan, "not_before:001");
}

#[test]
fn call_model() {
    let doc = table("queue", &[("001", "task", "T", "queued")]);
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("001"), "> Model: claude, flash\n")], &[]);
    has_call(&plan, "model:001");
}

#[test]
fn call_active_per_repo() {
    let doc = table("queue", &[("001", "task", "T", "active"), ("002", "task", "T", "active")]);
    let plan = inline_plan(&[(BACKLOG, &doc), (&task_doc("001"), ""), (&task_doc("002"), "")], &[]);
    has_call(&plan, "active_per_repo:/srv/softfig");
    assert_eq!(entry(&plan, "002").status, EntryStatus::Queued, "the proposal keeps the first active");
}

#[test]
fn call_baton() {
    let plan = fixture_plan();
    has_call(&plan, "baton:agents/b/baton.md");
    has_call(&plan, "baton:baton.md");
}

// ── the golden run ─────────────────────────────────────────────────────────

#[test]
fn golden_the_whole_fixture_converts_under_the_fixture_answers() {
    let plan = fixture_plan();
    assert!(plan.refusals.is_empty(), "{:?}", plan.refusals);
    assert!(plan.applicable(), "open: {:?}", plan.open_calls().collect::<Vec<_>>());
    assert_eq!((plan.queue.entries.len(), plan.archive.entries.len(), plan.slices.len()), (6, 1, 5));

    let mut sorted = keys(&plan);
    sorted.sort();
    assert_eq!(sorted, vec![
        "baton:agents/b/baton.md",
        "baton:baton.md",
        "list_order:list",
        "project_main:docs",
        "project_main:fixes",
        "project_main:hoverview",
        "project_main:roadeye",
        "project_main:softfig",
        "project_repo:roadeye",
        "project_repo:softfig",
        "slice_progress:hover-view-sticky",
        "slice_progress:semi-auto-backend-seam",
        "stack_base:069",
        "stack_base:hover-view-player",
        "stack_base:hover-view-sticky",
        "stack_base:semi-auto-backend-seam",
    ]);

    let order: Vec<_> = plan.queue.entries.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(order, vec![
        "semi-auto-backend-seam",
        "069",
        "folder-grants",
        "roadeye-m2-daemon-core",
        "hover-view-sticky",
        "hover-view-player",
    ]);

    let queue = QueueToml::parse(&plan.queue.to_toml().unwrap()).unwrap();
    assert_eq!(queue, plan.queue);
    let archive = QueueArchiveToml::parse(&plan.archive.to_toml().unwrap()).unwrap();
    assert_eq!(archive, plan.archive);
    assert_eq!(queue.validate(&archive), Ok(()));
    for (id, file) in &plan.slices {
        let parsed = SlicesToml::parse(&file.to_toml().unwrap()).unwrap();
        assert_eq!(&parsed, file);
        assert_eq!(parsed.validate(id), Ok(()), "{id}");
    }
}
