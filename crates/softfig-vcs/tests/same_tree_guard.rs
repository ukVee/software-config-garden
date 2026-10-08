//! Task 028 — the same-tree guard in the commit path.
//!
//! The commit path used to write a commit whenever it was asked to, even when
//! the resulting (ignore-filtered) tree was byte-identical to the parent's.
//! Two independent callers minted empty commits that way: a change confined to
//! a user-`.softfigignore`'d path (the dirty-set flush bails only on an empty
//! dirty set, never on an unchanged tree), and a re-stamp that rewrites a file
//! with the bytes it already had — the `set_reviewed` shape. The guard lives at
//! the writer, so these tests exercise it through the disk-walk entry point and
//! trust every other caller to inherit it.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use softfig_vault::{params::VaultParams, Vault, VaultSession};
use softfig_vcs::{Intent, Repo};

const PASS: &[u8] = b"correct horse battery staple";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn init_vault_at(garden: &Path) -> VaultSession {
    let (_v, session, _recovery) =
        Vault::init_with_params(garden, PASS, fast_params()).expect("vault init");
    session
}

fn edit_intent(summary: &str) -> Intent {
    Intent::new("memory_edit", serde_json::json!({ "summary": summary, "files": [] })).unwrap()
}

fn commit_count(repo: &Repo) -> usize {
    repo.db().list_commits().unwrap().len()
}

/// (1) A change confined to a user-`.softfigignore`'d path is invisible to the
/// commit tree, so it must mint no commit at all.
#[test]
fn ignored_path_change_mints_no_commit() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join(".softfigignore"), "scratch\n").unwrap();
    fs::write(tmp.path().join("a.md"), "tracked").unwrap();
    let session = init_vault_at(tmp.path());
    let (mut repo, genesis) = Repo::init(tmp.path(), &session).unwrap();
    let before = commit_count(&repo);

    fs::create_dir_all(tmp.path().join("scratch")).unwrap();
    fs::write(tmp.path().join("scratch/notes.log"), "churn").unwrap();

    let outcome = repo
        .commit_workdir_outcome(&session, edit_intent("ignored churn"))
        .unwrap();

    assert!(outcome.is_no_op(), "an ignored-only change must not commit");
    assert_eq!(outcome.hash, genesis, "the no-op returns the untouched tip");
    assert_eq!(repo.tip().unwrap(), Some(genesis), "the ref never moved");
    assert_eq!(commit_count(&repo), before, "no commit row was written");
}

/// (2) The `set_reviewed` re-stamp shape at the commit path: a file rewritten
/// with the bytes it already had. Same tree, so no commit.
#[test]
fn rewriting_identical_bytes_mints_no_commit() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("n.md"), "> Last reviewed: 2026-09-05\n").unwrap();
    let session = init_vault_at(tmp.path());
    let (mut repo, genesis) = Repo::init(tmp.path(), &session).unwrap();
    let before = commit_count(&repo);

    // The same stamp, written again the same day.
    fs::write(tmp.path().join("n.md"), "> Last reviewed: 2026-09-05\n").unwrap();

    let outcome = repo
        .commit_workdir_outcome(&session, edit_intent("re-stamp"))
        .unwrap();

    assert!(outcome.is_no_op(), "an identical re-write must not commit");
    assert_eq!(outcome.hash, genesis);
    assert_eq!(commit_count(&repo), before);
}

/// (3) A real content change still commits — exactly once. The guard must not
/// swallow work: the follow-up call with nothing further changed is the no-op.
#[test]
fn real_change_mints_exactly_one_commit() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("a.md"), "before").unwrap();
    let session = init_vault_at(tmp.path());
    let (mut repo, genesis) = Repo::init(tmp.path(), &session).unwrap();
    let before = commit_count(&repo);

    fs::write(tmp.path().join("a.md"), "after").unwrap();
    let first = repo
        .commit_workdir_outcome(&session, edit_intent("real edit"))
        .unwrap();

    assert!(first.committed, "a real change must commit");
    assert_ne!(first.hash, genesis);
    assert_eq!(repo.tip().unwrap(), Some(first.hash));
    assert_eq!(commit_count(&repo), before + 1, "exactly one commit");

    // Committing again with nothing changed adds nothing.
    let second = repo
        .commit_workdir_outcome(&session, edit_intent("nothing changed"))
        .unwrap();
    assert!(second.is_no_op());
    assert_eq!(second.hash, first.hash);
    assert_eq!(commit_count(&repo), before + 1);
}

/// The no-op must **not** fire `tip_changed`. That callback is the FUSE
/// rotation, which absorbs the overlay entries a commit captured — and an
/// ignored path is captured by no commit, so firing it on a no-op would drop a
/// staged write that lives nowhere else.
#[test]
fn no_op_does_not_fire_the_tip_changed_callback() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join(".softfigignore"), "scratch\n").unwrap();
    fs::write(tmp.path().join("a.md"), "tracked").unwrap();
    let session = init_vault_at(tmp.path());
    let (mut repo, _genesis) = Repo::init(tmp.path(), &session).unwrap();

    let fired = Arc::new(AtomicUsize::new(0));
    let counter = fired.clone();
    repo.set_tip_changed_callback(move |_, _, _| {
        counter.fetch_add(1, Ordering::SeqCst);
    });

    fs::create_dir_all(tmp.path().join("scratch")).unwrap();
    fs::write(tmp.path().join("scratch/notes.log"), "churn").unwrap();
    repo.commit_workdir(&session, edit_intent("ignored churn"))
        .unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 0, "no-op must not rotate");

    fs::write(tmp.path().join("a.md"), "changed").unwrap();
    repo.commit_workdir(&session, edit_intent("real edit"))
        .unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 1, "a real commit rotates");
}

/// The re-author path ([`Repo::commit_over_tree`], the m5e `shared_pull` apply)
/// carries the same guard. `shared_pull` dedups by content upstream, so this is
/// a backstop — but re-authoring the tree we already hold must never mint an
/// empty commit.
#[test]
fn commit_over_tree_skips_the_tip_s_own_tree() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("a.md"), "content").unwrap();
    let session = init_vault_at(tmp.path());
    let (mut repo, genesis) = Repo::init(tmp.path(), &session).unwrap();
    let before = commit_count(&repo);

    let tip_tree = repo.db().get_commit(&genesis).unwrap().root_tree;
    let outcome = repo
        .commit_over_tree_outcome(
            softfig_vcs::TIP_REF,
            &session,
            tip_tree,
            Intent::new("shared_pull", serde_json::json!({ "summary": "same tree" })).unwrap(),
        )
        .unwrap();

    assert!(outcome.is_no_op(), "re-authoring our own tree must not commit");
    assert_eq!(outcome.hash, genesis);
    assert_eq!(commit_count(&repo), before);
}

/// The deliberate exception: [`SameTreePolicy::Record`] mints the commit even
/// though the tree is unchanged. This is what keeps the vault's audit intents —
/// `vault_reveal`, and the `sealed-paths.toml` edits whose file is never in the
/// tree — in the history, since for them the commit *is* the record.
#[test]
fn record_policy_commits_an_unchanged_tree() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("a.md"), "content").unwrap();
    let session = init_vault_at(tmp.path());
    let (mut repo, genesis) = Repo::init(tmp.path(), &session).unwrap();
    let before = commit_count(&repo);

    let outcome = repo
        .commit_workdir_with(
            &session,
            Intent::new(
                "vault_reveal",
                serde_json::json!({ "path": "a.md", "actor": "device:local", "timestamp": 0 }),
            )
            .unwrap(),
            softfig_vcs::SameTreePolicy::Record,
        )
        .unwrap();

    assert!(outcome.committed, "Record must write the audit commit");
    assert_ne!(outcome.hash, genesis);
    assert_eq!(commit_count(&repo), before + 1);

    // ...and it is a genuine no-content commit: same tree as its parent.
    let row = repo.db().get_commit(&outcome.hash).unwrap();
    let parent = repo.db().get_commit(&row.parent.unwrap()).unwrap();
    assert_eq!(row.root_tree, parent.root_tree);
}
