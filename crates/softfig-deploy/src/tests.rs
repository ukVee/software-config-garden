//! M4a deploy-spine tests. Pure filesystem fixtures in a tempdir — no Vault,
//! no daemon. Covers config parsing, the plan diff (create / skip / replace /
//! conflict), symlink + copy materialization, the 0600/0700 perms, the
//! managed-by stamp, --force backup, and the input-validation rejections.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::*;

struct Fixture {
    _tmp: tempfile::TempDir,
    paths: DeployPaths,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        // The garden lives *under* $HOME (as on-device: ~/soft-fig_garden), so a
        // target can resolve into it — the self-write case resolve_target refuses.
        let garden_root = home.join("garden");
        let config_dir = garden_root.join("config");
        std::fs::create_dir_all(config_dir.join("source")).unwrap();
        let paths = DeployPaths {
            garden_root,
            config_dir,
            home,
            cache_root: root.join("cache"),
        };
        Fixture { _tmp: tmp, paths }
    }

    /// A `std::fs` source reader over this fixture's `config/source/` — the
    /// stand-in for the CLI / non-FUSE-daemon read path.
    fn source(&self) -> FsSource {
        FsSource::new(&self.paths)
    }

    fn write_source(&self, rel: &str, bytes: &[u8]) {
        let p = self.paths.source_dir().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn write_config(&self, toml: &str) {
        std::fs::write(self.paths.config_file(), toml).unwrap();
    }

    fn load(&self) -> DeployConfig {
        DeployConfig::load(&self.paths.config_file()).unwrap()
    }

    fn target(&self, rel: &str) -> PathBuf {
        self.paths.home.join(rel)
    }

    fn mode_of(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }
}

#[test]
fn parse_defaults_method_to_symlink() {
    let cfg = DeployConfig::parse(
        r#"
[dots]
bashrc  = { source = "bashrc",       target = ".bashrc" }
weather = { source = "weather.conf", target = ".config/w", method = "copy" }
"#,
    )
    .unwrap();
    assert_eq!(cfg.dots["bashrc"].method, Method::Symlink);
    assert_eq!(cfg.dots["weather"].method, Method::Copy);

    assert!(DeployConfig::parse("").unwrap().dots.is_empty());
}

#[test]
fn missing_config_is_config_not_found() {
    let fx = Fixture::new();
    let err = DeployConfig::load(&fx.paths.config_file()).unwrap_err();
    assert!(matches!(err, DeployError::ConfigNotFound(_)), "got {err:?}");
}

#[test]
fn create_symlink_sets_perms_then_skips() {
    let fx = Fixture::new();
    fx.write_source("bashrc", b"export A=1\n");
    fx.write_config(
        r#"[dots]
bashrc = { source = "bashrc", target = ".bashrc" }
"#,
    );
    let cfg = fx.load();

    let p = plan(&cfg, &fx.paths, &fx.source()).unwrap();
    assert_eq!(p.entries.len(), 1);
    assert_eq!(p.entries[0].action, Action::CreateSymlink);

    // plan is read-only: nothing materialized yet.
    assert!(!fx.target(".bashrc").exists());
    assert!(!fx.paths.cache_root.exists());

    let report = apply(&p, &fx.paths, &ApplyOptions::default()).unwrap();
    assert_eq!(report.created, vec!["bashrc".to_string()]);

    let target = fx.target(".bashrc");
    let md = std::fs::symlink_metadata(&target).unwrap();
    assert!(md.file_type().is_symlink(), "target is a symlink");
    let dest = std::fs::read_link(&target).unwrap();
    assert_eq!(dest, fx.paths.cache_root.join("bashrc"));
    assert_eq!(std::fs::read(&target).unwrap(), b"export A=1\n", "reads through");

    assert_eq!(Fixture::mode_of(&dest), 0o600, "cache file 0600");
    assert_eq!(Fixture::mode_of(&fx.paths.cache_root), 0o700, "cache dir 0700");

    // Idempotent: a second plan is a no-op.
    let p2 = plan(&cfg, &fx.paths, &fx.source()).unwrap();
    assert_eq!(p2.entries[0].action, Action::SkipUnchanged);
}

#[test]
fn changed_source_replaces_managed() {
    let fx = Fixture::new();
    fx.write_source("bashrc", b"export A=1\n");
    fx.write_config(
        r#"[dots]
bashrc = { source = "bashrc", target = ".bashrc" }
"#,
    );
    let cfg = fx.load();
    apply(&plan(&cfg, &fx.paths, &fx.source()).unwrap(), &fx.paths, &ApplyOptions::default()).unwrap();

    fx.write_source("bashrc", b"export A=2\n");
    let p = plan(&cfg, &fx.paths, &fx.source()).unwrap();
    assert_eq!(p.entries[0].action, Action::ReplaceManaged);

    let report = apply(&p, &fx.paths, &ApplyOptions::default()).unwrap();
    assert_eq!(report.replaced, vec!["bashrc".to_string()]);
    assert_eq!(std::fs::read(fx.target(".bashrc")).unwrap(), b"export A=2\n");
}

#[test]
fn foreign_file_conflicts_then_force_backs_up() {
    let fx = Fixture::new();
    fx.write_source("bashrc", b"managed\n");
    fx.write_config(
        r#"[dots]
bashrc = { source = "bashrc", target = ".bashrc" }
"#,
    );
    let cfg = fx.load();

    std::fs::write(fx.target(".bashrc"), b"hand written\n").unwrap();

    let p = plan(&cfg, &fx.paths, &fx.source()).unwrap();
    assert_eq!(p.entries[0].action, Action::Conflict);

    // No --force: refused, target untouched.
    let r = apply(&p, &fx.paths, &ApplyOptions { force: false }).unwrap();
    assert_eq!(r.conflicts.len(), 1);
    assert!(r.created.is_empty());
    assert_eq!(std::fs::read(fx.target(".bashrc")).unwrap(), b"hand written\n");
    assert!(!std::fs::symlink_metadata(fx.target(".bashrc")).unwrap().file_type().is_symlink());

    // --force: back up the foreign file, then symlink.
    let p2 = plan(&cfg, &fx.paths, &fx.source()).unwrap();
    let r2 = apply(&p2, &fx.paths, &ApplyOptions { force: true }).unwrap();
    assert_eq!(r2.forced, vec!["bashrc".to_string()]);
    assert!(std::fs::symlink_metadata(fx.target(".bashrc")).unwrap().file_type().is_symlink());
    assert_eq!(
        std::fs::read(fx.paths.home.join(".bashrc.softfig-bak")).unwrap(),
        b"hand written\n",
        "old bytes preserved in the backup"
    );
}

#[test]
fn copy_mode_stamps_and_detects_foreign_edit() {
    let fx = Fixture::new();
    fx.write_source("weather.conf", b"key = abc\n");
    fx.write_config(
        r#"[dots]
weather = { source = "weather.conf", target = ".config/weather-core/config.conf", method = "copy" }
"#,
    );
    let cfg = fx.load();

    let p = plan(&cfg, &fx.paths, &fx.source()).unwrap();
    assert_eq!(p.entries[0].action, Action::CopyStamped);
    let report = apply(&p, &fx.paths, &ApplyOptions::default()).unwrap();
    assert_eq!(report.copied, vec!["weather".to_string()]);
    assert!(report.warnings.is_empty(), ".conf has a known comment leader");

    let target = fx.target(".config/weather-core/config.conf");
    let md = std::fs::symlink_metadata(&target).unwrap();
    assert!(md.file_type().is_file(), "copy mode writes a real file, not a symlink");
    let body = std::fs::read_to_string(&target).unwrap();
    assert!(body.contains("managed by softfig"), "stamp present");
    assert!(body.contains("key = abc"), "source body present");
    assert_eq!(Fixture::mode_of(&target), 0o600);

    // Idempotent.
    assert_eq!(plan(&cfg, &fx.paths, &fx.source()).unwrap().entries[0].action, Action::SkipUnchanged);

    // A hand edit that drops the stamp is detected as a conflict.
    std::fs::write(&target, b"hand edited\n").unwrap();
    assert_eq!(plan(&cfg, &fx.paths, &fx.source()).unwrap().entries[0].action, Action::Conflict);
}

#[test]
fn absolute_target_outside_home_is_rejected() {
    let fx = Fixture::new();
    fx.write_source("x", b"x");
    fx.write_config(
        r#"[dots]
x = { source = "x", target = "/etc/foo" }
"#,
    );
    let err = plan(&fx.load(), &fx.paths, &fx.source()).unwrap_err();
    assert!(matches!(err, DeployError::InvalidTarget { .. }), "got {err:?}");
}

#[test]
fn parent_dir_traversal_in_target_is_rejected() {
    let fx = Fixture::new();
    fx.write_source("x", b"x");
    fx.write_config(
        r#"[dots]
x = { source = "x", target = "../escape" }
"#,
    );
    let err = plan(&fx.load(), &fx.paths, &fx.source()).unwrap_err();
    assert!(matches!(err, DeployError::InvalidTarget { .. }), "got {err:?}");
}

#[test]
fn directory_source_is_rejected_in_m4a() {
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.paths.source_dir().join("adir")).unwrap();
    fx.write_config(
        r#"[dots]
d = { source = "adir", target = ".adir" }
"#,
    );
    let err = plan(&fx.load(), &fx.paths, &fx.source()).unwrap_err();
    assert!(matches!(err, DeployError::DirectorySource { .. }), "got {err:?}");
}

#[test]
fn missing_source_is_reported() {
    let fx = Fixture::new();
    fx.write_config(
        r#"[dots]
gone = { source = "nope", target = ".nope" }
"#,
    );
    let err = plan(&fx.load(), &fx.paths, &fx.source()).unwrap_err();
    assert!(matches!(err, DeployError::SourceNotFound { .. }), "got {err:?}");
}

#[test]
fn unsafe_dot_name_is_rejected() {
    let fx = Fixture::new();
    fx.write_source("x", b"x");
    fx.write_config(
        r#"[dots]
"a/b" = { source = "x", target = ".x" }
"#,
    );
    let err = plan(&fx.load(), &fx.paths, &fx.source()).unwrap_err();
    assert!(matches!(err, DeployError::InvalidName(_)), "got {err:?}");
}

// --- cache-root resolution (slice 005: one policy both frontends share) ---

#[test]
fn resolve_data_base_prefers_absolute_xdg() {
    use std::ffi::OsStr;
    let base = resolve_data_base(Some(OsStr::new("/xdg/data")), Some(OsStr::new("/home/u")));
    assert_eq!(base, PathBuf::from("/xdg/data"));
}

#[test]
fn resolve_data_base_rejects_relative_xdg_and_falls_back_to_home() {
    use std::ffi::OsStr;
    // The bug this slice closes: a *relative* $XDG_DATA_HOME made the CLI
    // (accepted any non-empty value) and the daemon (filtered on is_absolute)
    // resolve DIFFERENT cache roots. Unified policy = reject relative, fall
    // back to $HOME/.local/share, so both frontends land on the same root.
    let base = resolve_data_base(
        Some(OsStr::new("relative/data")),
        Some(OsStr::new("/home/u")),
    );
    assert_eq!(base, PathBuf::from("/home/u/.local/share"));
}

#[test]
fn resolve_data_base_empty_xdg_falls_back_to_home() {
    use std::ffi::OsStr;
    let base = resolve_data_base(Some(OsStr::new("")), Some(OsStr::new("/home/u")));
    assert_eq!(base, PathBuf::from("/home/u/.local/share"));
}

#[test]
fn resolve_data_base_no_home_is_relative_dot() {
    let base = resolve_data_base(None, None);
    assert_eq!(base, PathBuf::from("."));
}

#[test]
fn default_cache_root_composes_off_the_base() {
    // Read-only over process env: whatever the base resolves to, the deploy
    // cache root is always `<base>/softfig/deployed`.
    assert_eq!(default_cache_root(), xdg_data_home().join("softfig").join("deployed"));
    assert!(default_cache_root().ends_with("softfig/deployed"));
}

// ---- mount-safety seam (task 036) ------------------------------------
//
// These stand in for FUSE mode (the workspace suite has no `/dev/fuse`): the
// daemon snapshots each source's plaintext from its mount-safe working-tree
// view into a `MemSource`, and the engine reads *only* through that. The tests
// prove the two guarantees of the blocker fix.

#[test]
fn mem_source_supplies_plaintext_not_the_on_disk_redacted_bytes() {
    // Finding (b): a `fs::read` of a Layer-B-sealed source returns the
    // reader-redacted `[sealed:…]` placeholder, which would deploy into a live
    // dotfile (e.g. ~/.ssh/config). The daemon instead captures the mount's
    // *plaintext*; the engine must materialize that, never the on-disk view.
    let fx = Fixture::new();
    // What a reader — and thus a naive fs::read of the mount — sees for a
    // whole-file-sealed source:
    let redacted = b"[sealed:config/source/ssh_config]\n".to_vec();
    fx.write_source("ssh_config", &redacted);
    fx.write_config(
        r#"[dots]
ssh = { source = "ssh_config", target = ".ssh/config" }
"#,
    );
    let cfg = fx.load();

    // The daemon's WorkTree read yields plaintext, captured in-memory:
    let plaintext = b"Host prod\n  IdentityFile ~/.ssh/id_prod\n".to_vec();
    let mut mem = MemSource::new();
    mem.insert_file("ssh_config", plaintext.clone());

    let p = plan(&cfg, &fx.paths, &mem).unwrap();
    assert_eq!(p.entries[0].action, Action::CreateSymlink);
    apply(&p, &fx.paths, &ApplyOptions::default()).unwrap();

    let got = std::fs::read(fx.target(".ssh/config")).unwrap();
    assert_eq!(got, plaintext, "target got the working-tree plaintext");
    assert_ne!(
        got, redacted,
        "the reader-redacted placeholder must never reach a live dotfile"
    );

    // Contrast: the naive fs::read path (FsSource) leaks the placeholder — the
    // exact bug the daemon's MemSource snapshot avoids.
    let fx2 = Fixture::new();
    fx2.write_source("ssh_config", &redacted);
    fx2.write_config(
        r#"[dots]
ssh = { source = "ssh_config", target = ".ssh/config" }
"#,
    );
    let p2 = plan(&fx2.load(), &fx2.paths, &fx2.source()).unwrap();
    apply(&p2, &fx2.paths, &ApplyOptions::default()).unwrap();
    assert_eq!(
        std::fs::read(fx2.target(".ssh/config")).unwrap(),
        redacted,
        "FsSource reads whatever is on disk — the leak the daemon avoids"
    );
}

#[test]
fn target_inside_garden_is_rejected() {
    // Finding (c): a target resolving inside garden_root is a self-write of the
    // garden mount / an uncommitted garden mutation — refused (any source).
    let fx = Fixture::new();
    fx.write_source("x", b"x\n");
    // garden_root = <home>/garden, so a home-relative "garden/…" lands inside it.
    fx.write_config(
        r#"[dots]
sneaky = { source = "x", target = "garden/config/source/evil" }
"#,
    );
    let err = plan(&fx.load(), &fx.paths, &fx.source()).unwrap_err();
    assert!(matches!(err, DeployError::InvalidTarget { .. }), "got {err:?}");
}

// ---- canonicalization-based garden refusal (036 review follow-up) ----
//
// The lexical `starts_with` refusal had two symlink escapes (record 017,
// finding 1): a symlinked *parent* smuggling the write into the garden, and
// unresolved symlink components in the configured roots (`/home → /var/home`)
// silently disarming the comparison. `resolve_target` now canonicalizes the
// target's parent chain and compares against the canonical garden root.

#[test]
fn symlink_parent_into_garden_is_refused() {
    // `~/.config/foo` is a symlink to a dir inside the garden: the target
    // string never mentions the garden, but apply's create_dir_all + tempfile
    // + rename all operate *through* the parent — a garden write.
    let fx = Fixture::new();
    fx.write_source("x", b"x\n");
    let inside = fx.paths.garden_root.join("smuggle");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::create_dir_all(fx.paths.home.join(".config")).unwrap();
    std::os::unix::fs::symlink(&inside, fx.paths.home.join(".config/foo")).unwrap();
    fx.write_config(
        r#"[dots]
x = { source = "x", target = ".config/foo/bar" }
"#,
    );
    let err = plan(&fx.load(), &fx.paths, &fx.source()).unwrap_err();
    assert!(matches!(err, DeployError::InvalidTarget { .. }), "got {err:?}");
    assert!(!inside.join("bar").exists(), "nothing written into the garden");
}

#[test]
fn benign_symlink_parent_outside_garden_still_deploys() {
    // A symlinked parent that resolves *outside* the garden is legitimate
    // (e.g. ~/.config on another disk) — the canonical check must not refuse it.
    let fx = Fixture::new();
    fx.write_source("x", b"payload\n");
    let elsewhere = fx.paths.home.join("real-config");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, fx.paths.home.join(".config")).unwrap();
    fx.write_config(
        r#"[dots]
x = { source = "x", target = ".config/app.conf" }
"#,
    );
    let p = plan(&fx.load(), &fx.paths, &fx.source()).unwrap();
    assert_eq!(p.entries[0].action, Action::CreateSymlink);
    apply(&p, &fx.paths, &ApplyOptions::default()).unwrap();
    assert_eq!(
        std::fs::read(elsewhere.join("app.conf")).unwrap(),
        b"payload\n",
        "deployed through the benign symlinked parent"
    );
}

#[test]
fn direct_target_symlink_stays_a_conflict_not_an_error() {
    // The final component is deliberately left unresolved: apply *replaces* a
    // target symlink atomically, never follows it, so a symlink target keeps
    // its Conflict semantics — whether it points outside or inside the garden.
    let fx = Fixture::new();
    fx.write_source("x", b"x\n");
    std::fs::write(fx.paths.home.join("other"), b"other\n").unwrap();
    std::os::unix::fs::symlink(fx.paths.home.join("other"), fx.target(".out")).unwrap();
    let garden_file = fx.paths.garden_root.join("gfile");
    std::fs::write(&garden_file, b"garden\n").unwrap();
    std::os::unix::fs::symlink(&garden_file, fx.target(".in")).unwrap();
    fx.write_config(
        r#"[dots]
a = { source = "x", target = ".out" }
b = { source = "x", target = ".in" }
"#,
    );
    let p = plan(&fx.load(), &fx.paths, &fx.source()).unwrap();
    assert!(p.entries.iter().all(|e| e.action == Action::Conflict), "{:?}", p.entries);

    // Forcing replaces the symlinks themselves; the garden file is untouched.
    apply(&p, &fx.paths, &ApplyOptions { force: true }).unwrap();
    assert_eq!(std::fs::read(&garden_file).unwrap(), b"garden\n");
    assert_eq!(std::fs::read(fx.paths.home.join("other")).unwrap(), b"other\n");
}

#[test]
fn unresolved_root_symlink_components_still_refuse_garden_targets() {
    // `/home → /var/home` systems: the deploy $HOME is spelled through a
    // symlink while garden_root is configured canonically. The lexical
    // comparison never fired here; the canonical one must.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let real_home = root.join("varhome/u");
    let garden_root = real_home.join("garden");
    std::fs::create_dir_all(garden_root.join("config/source")).unwrap();
    std::os::unix::fs::symlink(root.join("varhome"), root.join("home")).unwrap();
    let paths = DeployPaths {
        garden_root: garden_root.clone(),
        config_dir: garden_root.join("config"),
        home: root.join("home/u"), // the symlinked spelling
        cache_root: root.join("cache"),
    };
    std::fs::write(paths.source_dir().join("x"), b"x\n").unwrap();
    let cfg = DeployConfig::parse(
        r#"[dots]
x = { source = "x", target = "garden/evil" }
"#,
    )
    .unwrap();
    let err = plan(&cfg, &paths, &FsSource::new(&paths)).unwrap_err();
    assert!(matches!(err, DeployError::InvalidTarget { .. }), "got {err:?}");
}

#[test]
fn cache_root_inside_garden_is_rejected() {
    // Review follow-up finding 3: a configured deploy-cache inside the garden
    // would make every symlink dot a garden write (and dangle on lock).
    let fx = Fixture::new();
    fx.write_source("x", b"x\n");
    fx.write_config(
        r#"[dots]
x = { source = "x", target = ".x" }
"#,
    );
    let mut paths = fx.paths.clone();
    paths.cache_root = paths.garden_root.join("cache");
    let err = plan(&fx.load(), &paths, &FsSource::new(&paths)).unwrap_err();
    assert!(matches!(err, DeployError::CacheRootInsideGarden(_)), "got {err:?}");
}

#[test]
fn source_traversal_and_absolute_sources_are_rejected() {
    // Review follow-up finding 5: `source` is an address under config/source/
    // (and, in daemon mode, the working-tree read key) — `..` or an absolute
    // path could read + deploy an arbitrary garden or host file.
    let fx = Fixture::new();
    for src in ["../deploy.toml", "/etc/passwd", ""] {
        fx.write_config(&format!(
            r#"[dots]
x = {{ source = {src:?}, target = ".x" }}
"#
        ));
        let err = plan(&fx.load(), &fx.paths, &fx.source()).unwrap_err();
        assert!(matches!(err, DeployError::InvalidSource { .. }), "{src:?}: got {err:?}");
    }
}

#[test]
fn mem_source_classifies_directory_and_missing() {
    let fx = Fixture::new();
    fx.write_config(
        r#"[dots]
d = { source = "adir", target = ".adir" }
"#,
    );
    // A directory in the working tree → the M4a directory-source rejection.
    let mut mem = MemSource::new();
    mem.insert_directory("adir");
    let err = plan(&fx.load(), &fx.paths, &mem).unwrap_err();
    assert!(matches!(err, DeployError::DirectorySource { .. }), "got {err:?}");

    // A source the daemon never captured (absent in the working tree) → not found.
    let err2 = plan(&fx.load(), &fx.paths, &MemSource::new()).unwrap_err();
    assert!(matches!(err2, DeployError::SourceNotFound { .. }), "got {err2:?}");
}
