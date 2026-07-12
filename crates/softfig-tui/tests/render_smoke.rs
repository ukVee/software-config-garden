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
    app.vault.items = vec!["secrets/api-keys.toml".into()];
    app.vault.loaded = true;
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
    app.peer_list.loaded = true;
    app.peer_list.items = vec![
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
    app.backup.loaded = true;
    app.backup.items = vec![
        softfig_tui::app::BackupRow::PushTo(0),
        softfig_tui::app::BackupRow::Hosted(0),
    ];
    // Select the hosted chain so the detail pane shows the mirror stats.
    app.backup.selected = 1;

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
fn renders_region_picker_overlay() {
    // M2c: the inline `<vault id=…>` region picker lists the ids and its keys.
    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Browse;
    app.overlay = softfig_tui::app::Overlay::RevealRegion {
        path: "config/db.toml".into(),
        ids: vec!["db-pw".into(), "api-token".into()],
        selected: 1,
    };

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("pick a region"), "picker title missing:\n{rendered}");
    assert!(rendered.contains("config/db.toml"), "file path missing");
    assert!(rendered.contains("db-pw"), "region id missing");
    assert!(rendered.contains("api-token"), "second region id missing");
    assert!(rendered.contains("Enter reveal region"), "picker hint missing");
}

#[test]
fn renders_region_reveal_prompt() {
    // The masked-password prompt for a single region names the region target.
    let mut app = App::new();
    app.locked = false;
    app.overlay = softfig_tui::app::Overlay::Reveal {
        path: "config/db.toml".into(),
        buf: "pw".into(),
        error: None,
        id: Some("db-pw".into()),
    };

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("reveal secret"), "reveal title missing:\n{rendered}");
    assert!(rendered.contains("region <db-pw>"), "region target missing");
    assert!(rendered.contains("config/db.toml"), "file path missing");
}

#[test]
fn renders_preview_region_hint() {
    // A previewed file with inline regions flags them in the pane title.
    let mut app = App::new();
    app.locked = false;
    app.tree
        .set_children("", vec![entry("db.toml", false)]);
    app.preview = "pw = <vault id=\"db-pw\">[encrypted]</vault>\n".into();
    app.preview_title = "config/db.toml".into();
    app.regions = vec!["db-pw".into()];
    app.regions_path = Some("config/db.toml".into());

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("vault region"), "region hint missing:\n{rendered}");
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
    app.deploy.loaded = true;
    app.deploy.items = vec![
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
    // `deploy_has_conflicts()` is now derived from the entries (the `vimrc`
    // Conflict above), so the "conflicts!" title still renders.
    // Select the conflicting entry so the detail pane shows its reason.
    app.deploy.selected = 1;

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

#[test]
fn renders_growlight_frame_when_enabled() {
    use softfig_tui::app::GrowlightRow;

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    app.growlight.items = vec![
        GrowlightRow {
            id: "m5b-hardening".into(),
            title: "M5b replication hardening".into(),
            status: "done".into(),
        },
        GrowlightRow {
            id: "tui-modernize".into(),
            title: "Modernize the TUI".into(),
            status: "active".into(),
        },
    ];
    app.growlight.selected = 1;
    app.growlight_baton_title = Some("103-tui-modernize-003.md".into());
    app.growlight_baton = Some("shipped slice 003 — inline-region reveal".into());

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("7:Growlight"), "growlight tab missing:\n{rendered}");
    assert!(rendered.contains("tui-modernize"), "queue item missing");
    assert!(rendered.contains("active"), "status missing");
    assert!(
        rendered.contains("active: tui-modernize"),
        "active-item line missing"
    );
    assert!(rendered.contains("latest baton"), "baton panel missing");
    assert!(rendered.contains("shipped slice 003"), "baton body missing");
}

#[test]
fn growlight_tab_absent_when_disabled() {
    // The load-bearing requirement: when growlight is not enabled the tab does
    // not appear at all — no tab, no empty pane, no error.
    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(false);
    app.view = softfig_tui::app::View::Browse;

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("6:Deploy"), "other tabs should still render");
    assert!(
        !rendered.contains("Growlight"),
        "growlight tab must be absent when disabled:\n{rendered}"
    );
}
