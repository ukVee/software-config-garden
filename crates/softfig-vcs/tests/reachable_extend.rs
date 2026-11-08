//! `reachable_extend` (report 092): advancing a cached closure to a newer tip
//! walks only the commits added since, and is always exactly the closure a fresh
//! `reachable_from` would build.

use std::collections::HashSet;

use softfig_store::{Hash, ReadCounts};
use softfig_vault::{params::VaultParams, Vault, VaultSession};
use softfig_vcs::{reachable_extend, reachable_from, Intent, Reachable, Repo};

const PASS: &[u8] = b"correct horse battery staple";

fn init() -> (tempfile::TempDir, Repo, VaultSession) {
    let tmp = tempfile::tempdir().unwrap();
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    let (_v, session, _r) = Vault::init_with_params(tmp.path(), PASS, p).unwrap();
    let (repo, _genesis) = Repo::init(tmp.path(), &session).unwrap();
    (tmp, repo, session)
}

fn commit_file(tmp: &tempfile::TempDir, repo: &mut Repo, session: &VaultSession, rel: &str) -> Hash {
    let path = tmp.path().join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, format!("body of {rel}")).unwrap();
    let intent = Intent::new("manual_edit", serde_json::json!({ "path": rel })).unwrap();
    repo.commit_workdir(session, intent).unwrap()
}

fn same(a: &Reachable, b: &Reachable) -> bool {
    let eq = |x: &HashSet<Hash>, y: &HashSet<Hash>| x == y;
    eq(&a.commits, &b.commits) && eq(&a.trees, &b.trees) && eq(&a.blobs, &b.blobs)
}

#[test]
fn same_tip_walks_nothing() {
    let (tmp, mut repo, session) = init();
    let tip = commit_file(&tmp, &mut repo, &session, "a.md");
    let base = reachable_from(repo.db(), tip).unwrap();
    let (ext, walked) = reachable_extend(repo.db(), base, tip, tip).unwrap();
    assert_eq!(walked, 0);
    assert!(same(&ext, &reachable_from(repo.db(), tip).unwrap()));
}

#[test]
fn newer_tip_walks_only_the_new_commits_and_matches_a_fresh_walk() {
    let (tmp, mut repo, session) = init();
    let old = commit_file(&tmp, &mut repo, &session, "a.md");
    commit_file(&tmp, &mut repo, &session, "dir/b.md");
    let new = commit_file(&tmp, &mut repo, &session, "dir/c.md");

    let base = reachable_from(repo.db(), old).unwrap();
    let (ext, walked) = reachable_extend(repo.db(), base, old, new).unwrap();
    assert_eq!(walked, 2, "two commits since the cached tip");
    assert!(same(&ext, &reachable_from(repo.db(), new).unwrap()));
}

#[test]
fn a_tip_that_does_not_descend_falls_back_to_an_exact_fresh_walk() {
    let (tmp, mut repo, session) = init();
    let first = commit_file(&tmp, &mut repo, &session, "a.md");
    let second = commit_file(&tmp, &mut repo, &session, "b.md");

    // The cached closure is of the newer tip; asking for the older one is a
    // rollback, so the cached set holds objects the older tip cannot reach.
    let base = reachable_from(repo.db(), second).unwrap();
    let (ext, walked) = reachable_extend(repo.db(), base, second, first).unwrap();
    let fresh = reachable_from(repo.db(), first).unwrap();
    assert!(same(&ext, &fresh), "must not serve a superset of the tip's closure");
    assert_eq!(walked, fresh.commits.len());
}

/// Report 092's real cost is the tree reads, so pin them: advancing across two
/// commits reads each new root tree and only the subtrees it changed. A subtree
/// the cached closure already holds is not read again (`walk_tree`'s early
/// stop), which is what keeps a tick off the 18.7k trees of a grown store.
#[test]
fn extend_reads_only_the_new_root_trees_and_the_subtrees_they_change() {
    let (tmp, mut repo, session) = init();
    commit_file(&tmp, &mut repo, &session, "a.md");
    commit_file(&tmp, &mut repo, &session, "dir/b.md");
    let old = commit_file(&tmp, &mut repo, &session, "other/x.md");
    let base = reachable_from(repo.db(), old).unwrap();

    // Changes root + `dir`; `other` is untouched.
    commit_file(&tmp, &mut repo, &session, "dir/c.md");
    // Changes the root alone; `dir` and `other` are both untouched.
    let new = commit_file(&tmp, &mut repo, &session, "a2.md");

    let before = repo.db().read_counts();
    let (ext, walked) = reachable_extend(repo.db(), base, old, new).unwrap();
    let after = repo.db().read_counts();

    assert_eq!(walked, 2);
    assert_eq!(
        ReadCounts {
            commits: after.commits - before.commits,
            trees: after.trees - before.trees,
        },
        // Two new commits; first root + changed `dir`, then the second root.
        ReadCounts { commits: 2, trees: 3 },
        "extend read trees the cached closure already holds"
    );
    assert!(same(&ext, &reachable_from(repo.db(), new).unwrap()));
}
