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
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

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
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("Vault"), "vault tab missing:\n{rendered}");
    assert!(rendered.contains("api-keys.toml"), "sealed file missing");
    assert!(rendered.contains("sealed globs"), "globs panel missing");
    assert!(rendered.contains("temp"), "reveal temp path missing");
}

#[test]
fn renders_peers_frame() {
    use softfig_ipc::{PairPeer, PendingPairing};

    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Peers;
    app.peers = vec![PairPeer {
        fingerprint: "1".repeat(64),
        name: "tablet".into(),
        transport_pubkey: "a".repeat(64),
        endpoints: vec!["192.168.1.5:9100".into()],
        paired_at: 1_700_000_000,
    }];
    app.pending = vec![PendingPairing {
        pairing_id: "pid-1".into(),
        sas: "123 456".into(),
        fingerprint: "2".repeat(64),
        name: "laptop".into(),
    }];
    app.peers_loaded = true;
    app.peer_rows = vec![
        softfig_tui::app::PeerRow::Peer(0),
        softfig_tui::app::PeerRow::Pending(0),
    ];

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("Peers"), "peers tab missing:\n{rendered}");
    assert!(rendered.contains("tablet"), "ring member missing");
    assert!(rendered.contains("laptop"), "pending peer missing");
    assert!(rendered.contains("123 456"), "SAS missing");
    assert!(rendered.contains("ring member"), "detail header missing");
}

#[test]
fn renders_backup_frame() {
    use softfig_ipc::HostedChain;

    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Backup;
    app.replica_host = true;
    app.replica_push_to = vec!["1".repeat(64)];
    app.hosted = vec![HostedChain {
        fingerprint: "2".repeat(64),
        name: Some("tablet".into()),
        tip: Some("deadbeefcafe".into()),
        height: 7,
        objects: 21,
        bytes: 8192,
        last_sync: Some(1_700_000_000),
    }];
    app.backup_loaded = true;
    app.backup_rows = vec![
        softfig_tui::app::BackupRow::PushTo(0),
        softfig_tui::app::BackupRow::Hosted(0),
    ];
    // Select the hosted chain so the detail pane shows the mirror stats.
    app.backup_selected = 1;

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("Backup"), "backup tab missing:\n{rendered}");
    assert!(rendered.contains("hosts me"), "push_to row missing");
    assert!(rendered.contains("I host"), "hosted row missing");
    assert!(rendered.contains("tablet"), "hosted owner name missing");
    assert!(rendered.contains("hosted chain"), "detail header missing");
    assert!(rendered.contains("height"), "mirror stats missing");
}

#[test]
fn renders_grant_overlay() {
    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Backup;
    app.overlay = softfig_tui::app::Overlay::ReplicaGrant {
        fingerprint: "abc123".into(),
        error: None,
    };

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("grant backup host"), "overlay title missing:\n{rendered}");
    assert!(rendered.contains("abc123"), "typed fingerprint missing");
    assert!(rendered.contains("Enter grant"), "grant hint missing");
}

#[test]
fn renders_pair_confirm_overlay() {
    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Peers;
    app.overlay = softfig_tui::app::Overlay::PairConfirm {
        pairing_id: "pid-1".into(),
        sas: "987 654".into(),
        fingerprint: "f".repeat(64),
        name: "laptop".into(),
        error: None,
    };

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("confirm pairing"), "overlay title missing:\n{rendered}");
    assert!(rendered.contains("987 654"), "SAS missing in overlay");
    assert!(rendered.contains("y confirm"), "confirm hint missing");
}

#[test]
fn renders_scrolled_preview() {
    // A preview taller than the pane, scrolled down, must show the lower
    // lines (not the top) and surface a scroll-position indicator.
    let mut app = App::new();
    app.locked = false;
    app.tree.set_children("", vec![entry("long.md", false)]);
    app.preview = (0..100)
        .map(|i| format!("line{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    app.preview_title = "long.md".into();
    app.preview_scroll = 40;

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    // At offset 40 the top of the file is scrolled away and line40+ is shown.
    assert!(rendered.contains("line40"), "scrolled content missing:\n{rendered}");
    assert!(!rendered.contains("line0 "), "top line should be scrolled off");
    assert!(rendered.contains('%'), "scroll-position indicator missing");
    // The renderer recorded the live geometry for the key/mouse handlers.
    assert!(app.preview_total >= 100, "wrapped total not recorded");
    assert!(app.preview_viewport > 0, "viewport not recorded");
}

#[test]
fn renders_help_overlay() {
    let mut app = App::new();
    app.locked = false;
    app.overlay = softfig_tui::app::Overlay::Help;

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("command palette"), "help text missing");
}

#[test]
fn renders_deploy_frame() {
    use softfig_ipc::{DeployAction, DeployPlanEntry};

    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Deploy;
    app.deploy_loaded = true;
    app.deploy_entries = vec![
        DeployPlanEntry {
            name: "bashrc".into(),
            action: DeployAction::CreateSymlink,
            target: "/home/u/.bashrc".into(),
            conflict_reason: None,
        },
        DeployPlanEntry {
            name: "vimrc".into(),
            action: DeployAction::Conflict,
            target: "/home/u/.vimrc".into(),
            conflict_reason: Some("target is an existing file".into()),
        },
    ];
    app.deploy_has_conflicts = true;
    // Select the conflicting entry so the detail pane shows its reason.
    app.deploy_selected = 1;

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("Deploy"), "deploy tab missing:\n{rendered}");
    assert!(rendered.contains("bashrc"), "symlink dot missing");
    assert!(rendered.contains("CONFLICT"), "conflict row missing");
    assert!(rendered.contains("existing file"), "conflict reason missing");
    assert!(rendered.contains("a apply"), "apply hint missing");
}

#[test]
fn renders_deploy_force_overlay() {
    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Deploy;
    app.overlay = softfig_tui::app::Overlay::DeployForce { error: None };

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("force deploy"), "overlay title missing:\n{rendered}");
    assert!(rendered.contains("softfig-bak"), "backup explanation missing");
    assert!(rendered.contains("y force"), "confirm hint missing");
}
