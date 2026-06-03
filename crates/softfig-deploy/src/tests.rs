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
        let config_dir = root.join("config");
        std::fs::create_dir_all(config_dir.join("source")).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let paths = DeployPaths {
            config_dir,
            home,
            cache_root: root.join("cache"),
        };
        Fixture { _tmp: tmp, paths }
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

    let p = plan(&cfg, &fx.paths).unwrap();
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
    let p2 = plan(&cfg, &fx.paths).unwrap();
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
    apply(&plan(&cfg, &fx.paths).unwrap(), &fx.paths, &ApplyOptions::default()).unwrap();

    fx.write_source("bashrc", b"export A=2\n");
    let p = plan(&cfg, &fx.paths).unwrap();
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

    let p = plan(&cfg, &fx.paths).unwrap();
    assert_eq!(p.entries[0].action, Action::Conflict);

    // No --force: refused, target untouched.
    let r = apply(&p, &fx.paths, &ApplyOptions { force: false }).unwrap();
    assert_eq!(r.conflicts.len(), 1);
    assert!(r.created.is_empty());
    assert_eq!(std::fs::read(fx.target(".bashrc")).unwrap(), b"hand written\n");
    assert!(!std::fs::symlink_metadata(fx.target(".bashrc")).unwrap().file_type().is_symlink());

    // --force: back up the foreign file, then symlink.
    let p2 = plan(&cfg, &fx.paths).unwrap();
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

    let p = plan(&cfg, &fx.paths).unwrap();
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
    assert_eq!(plan(&cfg, &fx.paths).unwrap().entries[0].action, Action::SkipUnchanged);

    // A hand edit that drops the stamp is detected as a conflict.
    std::fs::write(&target, b"hand edited\n").unwrap();
    assert_eq!(plan(&cfg, &fx.paths).unwrap().entries[0].action, Action::Conflict);
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
    let err = plan(&fx.load(), &fx.paths).unwrap_err();
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
    let err = plan(&fx.load(), &fx.paths).unwrap_err();
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
    let err = plan(&fx.load(), &fx.paths).unwrap_err();
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
    let err = plan(&fx.load(), &fx.paths).unwrap_err();
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
    let err = plan(&fx.load(), &fx.paths).unwrap_err();
    assert!(matches!(err, DeployError::InvalidName(_)), "got {err:?}");
}
