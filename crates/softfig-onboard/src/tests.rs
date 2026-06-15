//! Tests for the onboarding scaffold core. The pure `plan`/`apply` layer
//! needs no Vault; the full `onboard_with_params` path dials Argon2id cost
//! down (m=8 KiB, t=1, p=1) so the suite stays sub-second, matching the
//! `softfig-vault` integration harness.

use std::collections::BTreeSet;

use softfig_vcs::Repo;
use softfig_store::TreeEntryKind;
use softfig_vault::params::{Argon2Params, VaultParams};

use super::*;

const PASSPHRASE: &[u8] = b"correct horse battery staple";

/// Minimum Argon2id cost — see `softfig-vault/tests/integration.rs`.
fn fast_params() -> VaultParams {
    VaultParams {
        format_version: softfig_vault::params::CURRENT_FORMAT_VERSION,
        argon2: Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        },
    }
}

fn opts(garden_root: &Path, state_root: &Path) -> OnboardOptions {
    OnboardOptions {
        garden_root: garden_root.to_path_buf(),
        state_root: state_root.to_path_buf(),
        machine: "test-machine".to_string(),
        date: "2026-05-26".to_string(),
        include: None,
    }
}

#[test]
fn plan_default_includes_skeleton_and_excludes_program_meta() {
    let plan = plan(&opts(Path::new("/g"), Path::new("/s"))).unwrap();

    // Skeleton landmarks present.
    assert!(plan.contains("CLAUDE.md"), "top routing CLAUDE.md");
    assert!(plan.contains("meta/conventions.md"));
    assert!(plan.contains("meta/reserved-filenames.md"));
    assert!(plan.contains("journal/decisions/.keep"));
    // Config-in-garden: every fresh garden is born with an editable in-garden
    // daemon config.
    assert!(plan.contains("config/keeper.toml"), "in-garden config scaffolded");

    // At least one stub per always-on dir and a sampling of concept dirs.
    assert!(plan.contains("inbox/CLAUDE.md"));
    assert!(plan.contains("packages/CLAUDE.md"));
    assert!(plan.contains("services/CLAUDE.md"));

    // Program-meta MUST NOT ship in a user's scaffold.
    assert!(!plan.contains("meta/program-vision.md"), "program-meta leaked");
    for f in &plan.files {
        let p = f.path.to_string_lossy();
        assert!(
            !p.starts_with("meta/spec-"),
            "spec-*.md must not ship in scaffold: {p}"
        );
    }
}

#[test]
fn substitution_leaves_no_placeholders() {
    let plan = plan(&opts(Path::new("/home/me/soft-fig_garden"), Path::new("/s"))).unwrap();
    let top = plan
        .files
        .iter()
        .find(|f| f.path == Path::new("CLAUDE.md"))
        .expect("top CLAUDE.md");
    let text = std::str::from_utf8(&top.contents).unwrap();

    assert!(text.contains("test-machine"), "machine substituted");
    assert!(text.contains("2026-05-26"), "date substituted");
    assert!(
        !text.contains("{{"),
        "no unresolved placeholders should remain"
    );
}

#[test]
fn customize_drops_toggled_off_concept_dir_keeps_always_on() {
    // Include only `packages`; drop everything else toggleable.
    let mut include = BTreeSet::new();
    include.insert("packages".to_string());

    let mut o = opts(Path::new("/g"), Path::new("/s"));
    o.include = Some(include);
    let plan = plan(&o).unwrap();

    // Selected concept dir survives.
    assert!(plan.contains("packages/CLAUDE.md"), "selected dir kept");

    // Unselected concept dir is gone.
    assert!(!plan.contains("services/CLAUDE.md"), "unselected dir dropped");
    assert!(!plan.contains("audio/CLAUDE.md"), "unselected dir dropped");

    // Always-on dirs + top-level files survive regardless.
    assert!(plan.contains("CLAUDE.md"), "top file kept");
    assert!(plan.contains("meta/conventions.md"), "always-on meta kept");
    assert!(plan.contains("inbox/CLAUDE.md"), "always-on inbox kept");
    assert!(plan.contains("journal/decisions/.keep"), "always-on journal kept");
}

#[test]
fn onboard_born_in_fuse_creates_state_without_plaintext() {
    let garden = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let o = opts(garden.path(), state.path());

    let outcome = onboard_with_params(&o, PASSPHRASE, fast_params()).unwrap();

    // Genesis hash + 12-word recovery phrase returned.
    assert_eq!(outcome.genesis.len(), 64, "genesis is a 32-byte hex hash");
    assert_eq!(
        outcome.recovery_phrase.split_whitespace().count(),
        12,
        "12-word BIP39 recovery phrase"
    );
    assert!(outcome.file_count > 0);

    // State lives under state_root/.softfig, NOT under garden_root.
    let state_softfig = state.path().join(".softfig");
    assert!(state_softfig.join("db.sqlite").exists(), "db at state root");
    assert!(state_softfig.join("vault").is_dir(), "vault at state root");

    // keeper.toml pointer at the garden root carries the state_root.
    let pointer = garden.path().join(".softfig/keeper.toml");
    assert!(pointer.exists(), "keeper.toml at garden root");
    let body = std::fs::read_to_string(&pointer).unwrap();
    assert!(body.contains("state_root"), "pointer names state_root");

    // Encryption-at-rest: no plaintext skeleton at the garden root.
    assert!(
        !garden.path().join("CLAUDE.md").exists(),
        "no plaintext CLAUDE.md at garden root"
    );
    assert!(
        !garden.path().join("meta").exists(),
        "no plaintext meta/ at garden root"
    );

    // The genesis tree, read back through the relocated state, holds the
    // skeleton's top-level entries.
    let repo = Repo::open_with(garden.path(), Some(state.path())).unwrap();
    let tip = repo.tip().unwrap().expect("tip set after genesis");
    let row = repo.db().get_commit(&tip).unwrap();
    let entries = repo.db().get_tree(&row.root_tree).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"CLAUDE.md"), "tree has CLAUDE.md: {names:?}");
    assert!(names.contains(&"meta"), "tree has meta/: {names:?}");
    let meta = entries.iter().find(|e| e.name == "meta").unwrap();
    assert_eq!(meta.kind, TreeEntryKind::Tree, "meta is a subtree");
}

#[test]
fn onboard_refuses_existing_state() {
    let garden = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let o = opts(garden.path(), state.path());

    onboard_with_params(&o, PASSPHRASE, fast_params()).unwrap();
    let again = onboard_with_params(&o, PASSPHRASE, fast_params());
    assert!(
        matches!(again, Err(OnboardError::AlreadyExists(_)) | Err(OnboardError::Vault(_))),
        "second onboard must refuse to clobber, got {again:?}"
    );
}
