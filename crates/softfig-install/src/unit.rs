//! The systemd unit render — the helper installs a **rendered** unit, never the
//! template verbatim. The template (`packaging/systemd/softfig-keeperd.service`)
//! hardcodes `%h/.local/bin` and `%h/soft-fig_garden` as its *defaults*; a
//! `--prefix` / `--garden` install must start the daemon it actually installed
//! against the garden it actually scaffolded, so the installer substitutes the
//! resolved paths before writing the unit (release-pipeline slice 008, M5).
//!
//! Split into a **pure** half — [`render_unit`] and [`exec_start`], text in /
//! text out — and an **impure** half ([`is_executable`], which reads the
//! filesystem), mirroring the split in [`crate::detect`].

use std::path::Path;

/// The template's default bin prefix. Replaced with the resolved install prefix
/// when rendering.
const TEMPLATE_BIN: &str = "%h/.local/bin";
/// The template's default garden. Replaced with the resolved garden when
/// rendering.
const TEMPLATE_GARDEN: &str = "%h/soft-fig_garden";

/// Render the unit from its template text, substituting the resolved install
/// `prefix` and `garden` for the `%h`-based defaults the template hardcodes.
/// Pure: template text in, rendered text out. The caller writes the result,
/// never the template.
pub fn render_unit(template: &str, prefix: &Path, garden: &Path) -> String {
    template
        .replace(TEMPLATE_BIN, &prefix.display().to_string())
        .replace(TEMPLATE_GARDEN, &garden.display().to_string())
}

/// Extract the `ExecStart=` executable from a rendered unit: the first
/// whitespace-delimited token after `ExecStart=` (arguments follow). `None` if
/// the unit carries no `ExecStart=` line. Pure, so tests can assert the
/// rendered unit points at the right binary.
pub fn exec_start(rendered: &str) -> Option<&str> {
    rendered
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart=")?.split_whitespace().next())
}

/// Is `path` an executable file — exists, is a regular file, and carries at
/// least one execute bit? The impure half of the check (reads the filesystem,
/// like [`crate::detect::which`]).
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real shipped template, so the render tests run against exactly what
    /// will be installed — not a re-typed copy that could drift.
    const TEMPLATE: &str = include_str!("../../../packaging/systemd/softfig-keeperd.service");

    #[test]
    fn render_substitutes_the_resolved_paths() {
        let rendered = render_unit(
            TEMPLATE,
            Path::new("/opt/softfig/bin"),
            Path::new("/srv/softfig-garden"),
        );
        let exec = rendered
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("template has an ExecStart line");
        assert_eq!(
            exec,
            "ExecStart=/opt/softfig/bin/softfig-keeperd --garden /srv/softfig-garden"
        );
        assert!(!exec.contains("%h"), "no %h may survive in ExecStart");
    }

    #[test]
    fn render_keeps_the_rest_of_the_unit_intact() {
        let rendered = render_unit(
            TEMPLATE,
            Path::new("/opt/softfig/bin"),
            Path::new("/srv/softfig-garden"),
        );
        // The non-path directives must survive untouched.
        assert!(rendered.contains("Type=simple"));
        assert!(rendered.contains("Restart=always"));
        assert!(rendered.contains("WantedBy=default.target"));
        assert!(rendered.contains("Environment=SOFTFIG_SUPERVISE_GROWLIGHTD=1"));
    }

    #[test]
    fn exec_start_extracts_the_binary() {
        let rendered =
            render_unit(TEMPLATE, Path::new("/opt/softfig/bin"), Path::new("/srv/garden"));
        assert_eq!(exec_start(&rendered), Some("/opt/softfig/bin/softfig-keeperd"));
    }

    #[test]
    fn exec_start_is_none_without_an_execstart_line() {
        assert_eq!(exec_start("[Unit]\nDescription=nope\n"), None);
    }

    #[test]
    fn is_executable_reads_the_execute_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("daemon");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        // Written without an execute bit => not executable.
        assert!(!is_executable(&bin));
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable(&bin));
    }

    #[test]
    fn is_executable_is_false_for_a_missing_path() {
        assert!(!is_executable(Path::new("/nonexistent/softfig-keeperd")));
    }
}
