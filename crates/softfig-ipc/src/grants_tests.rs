// Unit tests for `softfig_ipc::grants`. Included from `grants.rs` via `include!`
// inside its `#[cfg(test)] mod tests { ... }` block.
//
// The tests set up small chain scenarios on real tempdirs where I/O matters
// (the `.git` guard, canonicalization) and plain in-memory inputs for the
// pure refusal cases. The integration test proving `GitProbe` against a real
// `git worktree add` lives at the bottom of this file.

use super::*;
use std::fs;
use std::path::{Path, PathBuf};

/// Minimal probe that lies: `yes` says every pair is a worktree-of-repo.
struct YesProbe;
impl GitProbe for YesProbe {
    fn same_common_dir(&self, _worktree: &Path, _repo: &Path) -> bool {
        true
    }
}
/// Minimal probe that lies the other way.
struct NoProbe;
impl GitProbe for NoProbe {
    fn same_common_dir(&self, _worktree: &Path, _repo: &Path) -> bool {
        false
    }
}

fn home_in(dir: &Path) -> PathBuf {
    let h = dir.join("home/u");
    fs::create_dir_all(&h).unwrap();
    h
}

fn make_doc<'a>(label: &'a str, content: &'a str) -> GrantDoc<'a> {
    GrantDoc { label, content }
}

// ---- happy path ------------------------------------------------------------

#[test]
fn default_is_rw_repo_when_no_worktree_or_grants_declared() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    let milestone = make_doc("CLAUDE.md", "# m\n> Last reviewed: 2026-10-23\n");
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .expect("clean default");

    // Project default on $REPO, plus trailing ceiling denies.
    let non_ceiling: Vec<_> = out
        .iter()
        .filter(|g| g.origin.tier != Tier::CeilingDeny)
        .collect();
    assert_eq!(non_ceiling.len(), 1);
    assert_eq!(non_ceiling[0].mode, Mode::Rw);
    assert_eq!(non_ceiling[0].origin.tier, Tier::ProjectDefault);
    assert_eq!(non_ceiling[0].path, fs::canonicalize(&repo).unwrap());
}

#[test]
fn default_is_rw_worktree_when_declared_on_the_milestone() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    let wt = tmp.path().join("worktree");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&wt).unwrap();

    let m_body = format!("# m\n> Worktree: {}\n", wt.display());
    let milestone = make_doc("CLAUDE.md", &m_body);
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .expect("worktree is a worktree-of-repo per YesProbe");

    let non_ceiling: Vec<_> = out
        .iter()
        .filter(|g| g.origin.tier != Tier::CeilingDeny)
        .collect();
    assert_eq!(non_ceiling.len(), 1);
    assert_eq!(non_ceiling[0].mode, Mode::Rw);
    assert_eq!(non_ceiling[0].path, fs::canonicalize(&wt).unwrap());
    assert_eq!(non_ceiling[0].origin.tier, Tier::ProjectDefault);
    assert_eq!(non_ceiling[0].origin.doc, "CLAUDE.md");
}

#[test]
fn resolution_is_last_match_wins_across_the_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let dotfiles = home.join("dotfiles");
    fs::create_dir_all(&dotfiles).unwrap();

    let milestone = make_doc(
        "CLAUDE.md",
        "# m\n> Grants: rw ~/dotfiles, ro ~/dotfiles\n",
    );
    let slice_body = "> Grants: deny ~/dotfiles\n".to_string();
    let slice = make_doc("001-slice.md", &slice_body);
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: Some(slice),
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .expect("ok");

    let dotfiles_canon = fs::canonicalize(&dotfiles).unwrap();
    // Last entry on ~/dotfiles is the slice's deny.
    let on_dotfiles: Vec<_> = out
        .iter()
        .filter(|g| g.path == dotfiles_canon && g.origin.tier != Tier::CeilingDeny)
        .collect();
    assert_eq!(on_dotfiles.len(), 1);
    assert_eq!(on_dotfiles[0].mode, Mode::Deny);
    assert_eq!(on_dotfiles[0].origin.tier, Tier::Slice);
}

#[test]
fn slice_widening_is_flagged_against_steps_1_and_2() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let extra = home.join("extra");
    fs::create_dir_all(&extra).unwrap();
    let inside_repo = repo.join("inside");
    fs::create_dir_all(&inside_repo).unwrap();

    let milestone = make_doc("CLAUDE.md", "# m\n> Grants: ro ~/extra\n");
    let slice_body = format!(
        "> Grants: rw ~/extra, rw {}, ro {}\n",
        inside_repo.display(),
        inside_repo.display()
    );
    let slice = make_doc("001-s.md", &slice_body);
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: Some(slice),
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .expect("ok");

    let repo_canon = fs::canonicalize(&repo).unwrap();
    let extra_canon = fs::canonicalize(&extra).unwrap();
    let inside_canon = fs::canonicalize(&inside_repo).unwrap();

    // ~/extra: slice rw replaces milestone ro — widened (access upgraded).
    let on_extra = out
        .iter()
        .find(|g| g.path == extra_canon && g.origin.tier == Tier::Slice)
        .unwrap();
    assert_eq!(on_extra.mode, Mode::Rw);
    assert!(on_extra.widened, "slice rw over milestone ro is widened");

    // inside_repo: last slice entry on it is `ro`. Step 1 (project default
    // `rw $REPO`) covers `rw $REPO/inside` at rw-strength, so the final `ro`
    // on inside_repo is NOT widened.
    let on_inside = out
        .iter()
        .rfind(|g| g.path == inside_canon && g.origin.tier == Tier::Slice)
        .unwrap();
    assert_eq!(on_inside.mode, Mode::Ro);
    assert!(
        !on_inside.widened,
        "slice ro inside a step-1 rw is covered, not widened"
    );
    // Project default is still there, on the repo root.
    assert!(out
        .iter()
        .any(|g| g.path == repo_canon && g.origin.tier == Tier::ProjectDefault));
}

#[test]
fn an_implicit_deny_git_follows_each_rw_over_a_checkout() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    // One `rw` entry over a git-checkout-looking dir, one over a plain dir.
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    let plain = tmp.path().join("plain");
    fs::create_dir_all(&plain).unwrap();

    let m_body = format!("# m\n> Grants: rw {}\n", plain.display());
    let milestone = make_doc("CLAUDE.md", &m_body);
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .expect("ok");

    let repo_canon = fs::canonicalize(&repo).unwrap();
    let plain_canon = fs::canonicalize(&plain).unwrap();
    let repo_git = fs::canonicalize(repo.join(".git")).unwrap();

    // Exactly one git-guard, for the repo (has `.git`); none for the plain dir.
    let guards: Vec<_> = out
        .iter()
        .filter(|g| g.origin.tier == Tier::GitGuard)
        .collect();
    assert_eq!(guards.len(), 1);
    assert_eq!(guards[0].mode, Mode::Deny);
    assert_eq!(guards[0].path, repo_git);
    assert!(
        out.iter()
            .any(|g| g.path == plain_canon && g.mode == Mode::Rw),
        "plain rw stayed"
    );
    assert!(
        out.iter()
            .any(|g| g.path == repo_canon && g.origin.tier == Tier::ProjectDefault),
        "project default on the repo stayed"
    );
}

// ---- fail-closed refusals (every §5 variant has a test) --------------------

#[test]
fn parse_error_on_an_entry_that_is_not_mode_space_path() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    // No whitespace between mode and path.
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw~/x\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::Parse { .. }), "{err:?}");

    // Unknown mode.
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: write ~/x\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::Parse { .. }), "{err:?}");

    // Empty entry (doubled comma).
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw ~/x,, ro ~/y\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::Parse { .. }), "{err:?}");
}

#[test]
fn unknown_variable_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw $BOGUS/path\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::UnknownVariable { name, .. } if name == "BOGUS"));
}

#[test]
fn unresolvable_variable_fails_closed_on_repo_or_worktree() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());

    // $REPO absent (legacy default queue): any line using $REPO is refused.
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw $REPO/sub\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::None,
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::UnresolvableVariable { name, .. } if name == "REPO"));

    // $WORKTREE used with no `> Worktree:` on the milestone.
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw $WORKTREE\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::UnresolvableVariable { name, .. } if name == "WORKTREE"));
}

#[test]
fn relative_path_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw relative/path\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::RelativePath { .. }), "{err:?}");

    // ~user is NOT home-expanded; stays relative-looking.
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw ~bob/x\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::RelativePath { .. }), "{err:?}");
}

#[test]
fn wildcard_or_control_char_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    for bad in ["~/d*/x", "~/d?/x", "~/d\u{0007}/x"] {
        let body = format!("# m\n> Grants: rw {bad}\n");
        let doc = make_doc("CLAUDE.md", &body);
        let err = resolve(
            &ResolveInputs {
                milestone_chain: &[doc],
                slice: None,
                project_repo: ProjectRepo::Local(&repo),
                home: &home,
                extra_ceiling: &[],
                backend: Backend::Opencode,
                keeperd_state_root: None,
                keeperd_vault_root: None,
                softfig_runtime_root: None,
                garden_mount: None,
            },
            &YesProbe,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantError::IllegalChar { .. }),
            "`{bad}` ⇒ {err:?}"
        );
    }
}

#[test]
fn ceiling_hits_equal_inside_and_ancestor_of() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    // Equal: grant on ~/.ssh itself.
    fs::create_dir_all(home.join(".ssh")).unwrap();
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: ro ~/.ssh\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        GrantError::CeilingHit {
            relation: CeilingRelation::Equal,
            ..
        }
    ));

    // Inside: ~/.ssh/sub-dir.
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: ro ~/.ssh/sub\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        GrantError::CeilingHit {
            relation: CeilingRelation::Inside,
            ..
        }
    ));

    // AncestorOf: ro ~/.config is refused because ~/.config/opencode is a
    // ceiling. (Spec §6's named example.)
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: ro ~/.config\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            GrantError::CeilingHit {
                relation: CeilingRelation::AncestorOf,
                ..
            }
        ),
        "`ro ~/.config` must refuse as AncestorOf (covers ~/.config/opencode): {err:?}"
    );

    // Bare $HOME is not a grantable root (§6: "Grantable roots are only paths
    // under `$HOME`"), so `rw ~` refuses as `UngrantableRoot`, not CeilingHit.
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw ~\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::UngrantableRoot { .. }), "{err:?}");
}

#[test]
fn ungrantable_roots_are_refused_before_the_ceiling() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    // `/` → refused (not under $HOME, not under /tmp/<name>/).
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw /\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::UngrantableRoot { .. }), "{err:?}");

    // Bare /tmp → refused (requires a `<name>/` under it).
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw /tmp\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::UngrantableRoot { .. }), "{err:?}");

    // /var/log/x → refused (neither under $HOME nor /tmp/<name>/).
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw /var/log/sf\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::UngrantableRoot { .. }), "{err:?}");

    // `/tmp/<name>/sub` → OK (unless it hits a ceiling like `/tmp/opencode`).
    fs::create_dir_all("/tmp/sf-grants-ok").ok();
    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw /tmp/sf-grants-ok\n");
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    );
    assert!(out.is_ok(), "/tmp/<name>/ is grantable: {out:?}");
    let _ = fs::remove_dir_all("/tmp/sf-grants-ok");
}

#[test]
fn opencode_tmp_scratch_is_a_ceiling_root() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw /tmp/opencode\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::CeilingHit { .. }));

    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw /tmp/opencode/sub\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::CeilingHit { .. }));
}

#[test]
fn a_symlink_cannot_smuggle_past_the_ceiling() {
    #[cfg(unix)]
    {
        let tmp = tempfile::tempdir().unwrap();
        let home = home_in(tmp.path());
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();

        // Make ~/.ssh real so the ceiling entry canonicalizes correctly.
        fs::create_dir_all(home.join(".ssh")).unwrap();
        let shortcut = home.join("shortcut");
        std::os::unix::fs::symlink(home.join(".ssh"), &shortcut).unwrap();

        let body = format!("# m\n> Grants: ro {}\n", shortcut.display());
        let doc = make_doc("CLAUDE.md", &body);
        let err = resolve(
            &ResolveInputs {
                milestone_chain: &[doc],
                slice: None,
                project_repo: ProjectRepo::Local(&repo),
                home: &home,
                extra_ceiling: &[],
                backend: Backend::Opencode,
                keeperd_state_root: None,
                keeperd_vault_root: None,
                softfig_runtime_root: None,
                garden_mount: None,
            },
            &YesProbe,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantError::CeilingHit { .. }),
            "a symlink into ~/.ssh must still hit the ceiling: {err:?}"
        );
    }
}

#[test]
fn worktree_not_of_repo_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    // The worktree exists but we tell the probe it is not a worktree of this repo.
    let wt = tmp.path().join("some-other-dir");
    fs::create_dir_all(&wt).unwrap();

    let body = format!("# m\n> Worktree: {}\n", wt.display());
    let doc = make_doc("CLAUDE.md", &body);
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &NoProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::WorktreeNotOfRepo { .. }), "{err:?}");
}

#[test]
fn worktree_may_not_yet_exist_as_long_as_its_parent_does() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    // Parent exists, worktree does not yet (slice 001 will create it).
    let parent = tmp.path().join("codebase");
    fs::create_dir_all(&parent).unwrap();
    let wt = parent.join("folder-grants");

    let body_ok = format!("# m\n> Worktree: {}\n", wt.display());
    let doc = make_doc("CLAUDE.md", &body_ok);
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &NoProbe, // probe is not called on a non-existing path.
    )
    .expect("ok");
    // Project default lands on the canonicalized worktree path.
    let non_ceiling: Vec<_> = out
        .iter()
        .filter(|g| g.origin.tier == Tier::ProjectDefault)
        .collect();
    assert_eq!(non_ceiling.len(), 1);
    // Parent is canonical, then the final component is appended.
    assert_eq!(non_ceiling[0].path, fs::canonicalize(&parent).unwrap().join("folder-grants"));

    // But a non-existing worktree whose parent ALSO doesn't exist fails closed.
    let bad = tmp.path().join("totally/missing/wt");
    let body_bad = format!("# m\n> Worktree: {}\n", bad.display());
    let doc = make_doc("CLAUDE.md", &body_bad);
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &NoProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::WorktreeParentMissing { .. }), "{err:?}");
}

#[test]
fn remote_repo_refuses_an_opencode_spawn_but_not_a_claude_one() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());

    let milestone = make_doc("CLAUDE.md", "# m\n> Last reviewed: 2026-10-23\n");

    // opencode on a remote repo: refused up front (§9).
    let err = resolve(
        &ResolveInputs {
            milestone_chain: std::slice::from_ref(&milestone),
            slice: None,
            project_repo: ProjectRepo::Remote("otg-travel:/home/sshukv/projects/roadeye"),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::RemoteRepoOnOpencode { .. }), "{err:?}");

    // claude on a remote repo: resolves to empty project default (no `$REPO`
    // to canonicalize), the §10 "advisory" caller's problem.
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: None,
            project_repo: ProjectRepo::Remote("otg-travel:/home/sshukv/projects/roadeye"),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Claude,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .expect("claude proceeds");
    let non_ceiling: Vec<_> = out
        .iter()
        .filter(|g| g.origin.tier != Tier::CeilingDeny)
        .collect();
    assert!(
        non_ceiling.is_empty(),
        "no project default for a remote repo, no grants = floor only ({:?})",
        non_ceiling
    );
}

#[test]
fn worktree_on_a_slice_doc_is_a_parse_error() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    let milestone = make_doc("CLAUDE.md", "# m\n");
    let slice = make_doc("001-s.md", "> Worktree: /some/path\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: Some(slice),
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::WorktreeOnSlice { .. }), "{err:?}");
}

#[test]
fn no_baton_item_resolves_to_floor_only() {
    // Spec §5: a member spawned before any claim has no doc chain, no repo,
    // no grants. The resolver returns an empty list (plus trailing ceiling
    // denies).
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[],
            slice: None,
            project_repo: ProjectRepo::None,
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .expect("ok");
    let non_ceiling: Vec<_> = out
        .iter()
        .filter(|g| g.origin.tier != Tier::CeilingDeny)
        .collect();
    assert!(non_ceiling.is_empty(), "{non_ceiling:?}");
}

#[test]
fn fenced_lines_do_not_declare_a_grant() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    // The fenced block looks like a grant but is an example; `fields` skips it.
    let doc = make_doc(
        "CLAUDE.md",
        "# m\n```\n> Grants: rw /banned\n```\n> Grants: ro ~/dotfiles\n",
    );
    fs::create_dir_all(home.join("dotfiles")).unwrap();
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .expect("ok");
    // No entry on /banned anywhere in the resolved list.
    assert!(
        !out.iter().any(|g| g.path.as_path() == Path::new("/banned")),
        "a fenced example must not resolve"
    );
    // Milestone's ro ~/dotfiles did land.
    assert!(out.iter().any(|g| g.origin.tier == Tier::MilestoneOrTask && g.mode == Mode::Ro));
}

#[test]
fn extra_ceiling_entries_participate_in_the_check() {
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let no_touch = home.join("no-touch");
    fs::create_dir_all(&no_touch).unwrap();

    let doc = make_doc("CLAUDE.md", "# m\n> Grants: rw ~/no-touch\n");
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[doc],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: std::slice::from_ref(&no_touch),
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &YesProbe,
    )
    .unwrap_err();
    assert!(
        matches!(err, GrantError::CeilingHit { relation: CeilingRelation::Equal, .. }),
        "{err:?}"
    );
}

// ---- integration test: a real `git worktree add` tempdir -------------------

/// §4 at spawn: a declared `> Worktree:` must be a worktree of `$REPO`. This
/// runs a real `git worktree add` and a real `RealGitProbe`.
#[test]
fn git_worktree_check_runs_against_a_real_repo() {
    // Only run when `git` is on PATH; otherwise skip. (CI has it; a bare dev
    // box might not.)
    if std::process::Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let home = home_in(tmp.path());
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    crate::testing::git(&repo, &["init", "-q"]);
    fs::write(repo.join("x.txt"), "x\n").unwrap();
    crate::testing::git(&repo, &["add", "x.txt"]);
    crate::testing::git(&repo, &["commit", "-q", "-m", "base"]);

    let wt = tmp.path().join("wt");
    crate::testing::git(&repo, &["worktree", "add", wt.to_str().unwrap(), "-q"]);

    // RealGitProbe accepts the pair.
    struct RealGitProbe;
    impl GitProbe for RealGitProbe {
        fn same_common_dir(&self, worktree: &Path, repo: &Path) -> bool {
            fn common(p: &Path) -> Option<PathBuf> {
                let out = std::process::Command::new("git")
                    .args(["--no-optional-locks", "-C"])
                    .arg(p)
                    .args(["rev-parse", "--git-common-dir"])
                    .output()
                    .ok()?;
                if !out.status.success() {
                    return None;
                }
                let txt = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let path = PathBuf::from(&txt);
                let abs = if path.is_absolute() { path } else { p.join(path) };
                std::fs::canonicalize(abs).ok()
            }
            match (common(worktree), common(repo)) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            }
        }
    }
    let body_good = format!("# m\n> Worktree: {}\n", wt.display());
    let milestone = make_doc("CLAUDE.md", &body_good);
    let out = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &RealGitProbe,
    )
    .expect("the worktree is of the repo");
    assert!(out
        .iter()
        .any(|g| g.origin.tier == Tier::ProjectDefault && g.path == fs::canonicalize(&wt).unwrap()));

    // A random dir that is NOT a worktree of the repo fails closed.
    let not_a_wt = tmp.path().join("not-a-wt");
    fs::create_dir_all(&not_a_wt).unwrap();
    let body_bad = format!("# m\n> Worktree: {}\n", not_a_wt.display());
    let milestone = make_doc("CLAUDE.md", &body_bad);
    let err = resolve(
        &ResolveInputs {
            milestone_chain: &[milestone],
            slice: None,
            project_repo: ProjectRepo::Local(&repo),
            home: &home,
            extra_ceiling: &[],
            backend: Backend::Opencode,
            keeperd_state_root: None,
            keeperd_vault_root: None,
            softfig_runtime_root: None,
            garden_mount: None,
        },
        &RealGitProbe,
    )
    .unwrap_err();
    assert!(matches!(err, GrantError::WorktreeNotOfRepo { .. }), "{err:?}");
}
