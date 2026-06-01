//! One `TestBackend` frame snapshot: render the Browse view with a small
//! tree + preview and assert the key chrome and content appear. Proves the
//! render path wires together without a real terminal (the live key
//! handling is a manual smoke step).

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use softfig_ipc::TreeEntry;
use softfig_tui::app::App;
use softfig_tui::ui;

fn entry(name: &str, is_dir: bool) -> TreeEntry {
    TreeEntry {
        name: name.to_string(),
        path: name.to_string(),
        is_dir,
    }
}

#[test]
fn renders_browse_frame() {
    let mut app = App::new();
    app.locked = false;
    app.garden_root = "/home/ukv/soft-fig_garden".into();
    app.tree
        .set_children("", vec![entry("meta", true), entry("CLAUDE.md", false)]);
    app.preview = "# soft-fig garden".into();
    app.preview_title = "CLAUDE.md".into();
    app.status = "ready".into();

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("softfig-tui"), "header missing:\n{rendered}");
    assert!(rendered.contains("Browse"), "tab bar missing");
    assert!(rendered.contains("meta"), "tree dir missing");
    assert!(rendered.contains("CLAUDE.md"), "tree file missing");
    assert!(rendered.contains("soft-fig garden"), "preview missing");
}

#[test]
fn renders_vault_frame() {
    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Vault;
    app.vault_globs = vec!["secrets/**".into()];
    app.vault_files = vec!["secrets/api-keys.toml".into()];
    app.vault_loaded = true;
    app.reveal = Some(softfig_tui::app::RevealInfo {
        path: "secrets/api-keys.toml".into(),
        temp_path: "/run/user/1000/softfig-reveal-abc.toml".into(),
        expires_at: 1000,
    });

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("Vault"), "vault tab missing:\n{rendered}");
    assert!(rendered.contains("api-keys.toml"), "sealed file missing");
    assert!(rendered.contains("sealed globs"), "globs panel missing");
    assert!(rendered.contains("temp"), "reveal temp path missing");
}

#[test]
fn renders_help_overlay() {
    let mut app = App::new();
    app.locked = false;
    app.overlay = softfig_tui::app::Overlay::Help;

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("command palette"), "help text missing");
}
