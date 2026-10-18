//! Guard: `softfig-runnerd` must never link `softfig-vault`.
//!
//! Spec §3.1 — the runner serves while the laptop garden is locked, so its key
//! material is *not* vault-sealed, and it must not be able to read the garden.
//! A sandbox escape that lands in the `softfig-runner` uid must not reach a key
//! that can decrypt a chain. This test fails loudly the moment someone declares
//! a `softfig-vault` dependency in this crate's manifest.

/// Whether the manifest declares a `softfig-vault` dependency in any
/// `[dependencies]`, `[dev-dependencies]` or `[build-dependencies]` section
/// (flat or table style). Comments and unrelated sections are ignored.
fn vault_dep_declared(raw: &str) -> bool {
    let mut in_deps = false;
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(stripped) = t.strip_prefix('[') {
            let section = stripped.trim_end_matches(']').trim();
            in_deps = matches!(
                section,
                "dependencies" | "dev-dependencies" | "build-dependencies"
            );
            // Table style: `[dependencies.softfig-vault]`.
            if section == "dependencies.softfig-vault"
                || section == "dev-dependencies.softfig-vault"
                || section == "build-dependencies.softfig-vault"
            {
                return true;
            }
            continue;
        }
        if in_deps && t.starts_with("softfig-vault") {
            return true;
        }
    }
    false
}

#[test]
fn runnerd_does_not_depend_on_softfig_vault() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let raw = std::fs::read_to_string(manifest).unwrap();
    assert!(
        !vault_dep_declared(&raw),
        "softfig-runnerd must not depend on softfig-vault (spec §3.1: the runner \
         serves while the garden is locked; an escape must not reach a garden-reading key)"
    );
}

#[test]
fn vault_dep_parser_flags_a_declared_dependency() {
    // Sanity-check the parser against a manifest that *does* declare it.
    let raw = "\
[dependencies]\n\
ed25519-dalek = \"2\"\n\
softfig-vault = { path = \"../softfig-vault\" }\n\
";
    assert!(vault_dep_declared(raw));

    let table_style = "[dev-dependencies.softfig-vault]\npath = \"../softfig-vault\"\n";
    assert!(vault_dep_declared(table_style));
}

#[test]
fn vault_dep_parser_ignores_comments_and_other_sections() {
    let raw = "\
# this crate never links softfig-vault (spec §3.1)\n\
[dependencies]\n\
ed25519-dalek = \"2\"\n\
x25519-dalek = \"2\"\n\
[package.metadata]\n\
softfig-vault = \"mention only\"\n\
";
    assert!(!vault_dep_declared(raw));
}
