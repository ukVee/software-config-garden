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
fn renders_shares_frame() {
    use softfig_ipc::SharedSubtreeInfo;

    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Shares;
    app.shares = vec![
        SharedSubtreeInfo {
            id: "journals".into(),
            mount_path: "projects/journals".into(),
            ref_name: "chain/journals".into(),
            enabled: true,
            key_id: Some("S-deadbeef".into()),
        },
        SharedSubtreeInfo {
            id: "notes".into(),
            mount_path: "projects/notes".into(),
            ref_name: "chain/notes".into(),
            enabled: false,
            key_id: None,
        },
    ];
    app.shares_loaded = true;
    // Select the keyed share so the detail pane shows its ceremony outcome.
    app.shares_selected = 0;

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("7:Shares"), "shares tab missing:\n{rendered}");
    assert!(rendered.contains("projects/journals"), "shared folder missing");
    assert!(rendered.contains("keyed"), "keyed ceremony state missing");
    assert!(
        rendered.contains("ceremony pending"),
        "pending ceremony state missing"
    );
    assert!(rendered.contains("S-deadbeef"), "key_id missing from detail");
    assert!(
        rendered.contains("transcript verified"),
        "ceremony verification line missing"
    );
}

#[test]
fn renders_shares_divergence_banner() {
    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Shares;
    app.shared_key_divergence =
        Some("shared-key divergence for chain chain/journals: differs".into());

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(
        rendered.contains("shared-key divergence"),
        "divergence banner missing:\n{rendered}"
    );
}

#[test]
fn renders_add_share_overlay() {
    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Shares;
    app.overlay = softfig_tui::app::Overlay::AddShare {
        mount_path: "projects/journals".into(),
        error: None,
    };

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("share a folder"), "overlay title missing:\n{rendered}");
    assert!(rendered.contains("projects/journals"), "typed path missing");
    assert!(rendered.contains("Enter share"), "share hint missing");
}

#[test]
fn renders_growlight_frame_when_enabled() {
    use softfig_tui::tree::BacklogItem;

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    // Left pane: a navigable backlog tree (populated via the pure tree API).
    app.growlight_tree.set_items(vec![
        BacklogItem {
            id: "m5b-hardening".into(),
            title: "M5b replication hardening".into(),
            status: "done".into(),
            is_milestone: true,
        },
        BacklogItem {
            id: "tui-modernize".into(),
            title: "Modernize the TUI".into(),
            status: "active".into(),
            is_milestone: true,
        },
    ]);
    app.growlight_tree.selected = 1;
    // Right pane: the fleet-header baton stub + the selected node's markdown.
    app.growlight_baton_title = Some("103-tui-modernize-003.md".into());
    app.growlight_baton = Some("---\nstatus: IN_PROGRESS\n---\n\n# NEXT ACTION\nship slice 002".into());
    app.growlight_preview_title = "tui-modernize".into();
    app.growlight_preview = "## Mission\nright-pane markdown viewer, scrollable".into();

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("8:Growlight"), "growlight tab missing:\n{rendered}");
    assert!(rendered.contains("tui-modernize"), "queue item missing");
    assert!(rendered.contains("active"), "status missing");
    // Fleet-header strip: the latest-baton headline (frontmatter skipped).
    assert!(rendered.contains("loop baton"), "baton header missing");
    assert!(rendered.contains("NEXT ACTION"), "baton headline missing");
    // Right-pane node viewer renders the selected node's markdown.
    assert!(
        rendered.contains("right-pane markdown viewer"),
        "node body missing"
    );
}

#[test]
fn renders_growlight_loop_context_and_clamps_node_scroll() {
    use softfig_tui::tree::LoopContextNode;

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    app.growlight_tree
        .set_loop_context(vec![LoopContextNode {
            label: "protocol.md".into(),
            path: "growlight/protocol.md".into(),
        }]);
    // A long node body + an over-large scroll offset must clamp to the bottom.
    app.growlight_preview_title = "protocol.md".into();
    app.growlight_preview = (0..100)
        .map(|i| format!("proto-line{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    app.preview_scroll = 400;

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("protocol.md"), "loop-context row/title missing:\n{rendered}");
    // The renderer clamped the shared offset to the real bottom (< 400) and
    // recorded the viewport for the scroll keys.
    assert!(app.preview_scroll < 400, "scroll not clamped to content bottom");
    assert_eq!(
        app.preview_scroll,
        app.preview_total.saturating_sub(app.preview_viewport),
        "clamped to exactly the last page"
    );
    assert!(app.preview_total >= 100, "wrapped total not recorded");
    assert!(rendered.contains("proto-line99"), "bottom line should be visible");
}

#[test]
fn renders_live_fleet_header_from_status_poll() {
    use softfig_tui::app::FleetHeader;

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    // A decoded growlightd `status` reply drives the live header.
    let reply: softfig_ipc::growlightd::FleetStatusReply = serde_json::from_value(serde_json::json!({
        "state": "running",
        "garden_root": "/g",
        "protocol_version": 1,
        "policy": {
            "max_concurrent_agents": 2,
            "ctx_roll_pct": 50,
            "ctx_handoff_pct": 60,
            "session_5h_halt_pct": 85,
            "session_7d_halt_pct": 90
        },
        "fleet_enabled": true,
        "paused": false,
        "agents": [{ "id": "a", "status": "running" }]
    }))
    .unwrap();
    app.fleet = FleetHeader::Live(reply);

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("armed"), "fleet gate missing:\n{rendered}");
    assert!(rendered.contains("agent(s) running"), "agent count missing");
    assert!(rendered.contains("a:running"), "agent roster line missing");
    assert!(rendered.contains("budgets"), "policy budget line missing");
    assert!(rendered.contains("halt 5h 85%"), "budget thresholds missing");
}

#[test]
fn growlight_header_soft_fails_when_growlightd_unreachable() {
    use softfig_tui::app::FleetHeader;
    use softfig_tui::tree::BacklogItem;

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    // growlightd is down: the header soft-fails, but the garden-only tree + body
    // must keep rendering (never gate the page on growlightd).
    app.fleet = FleetHeader::Unreachable;
    app.growlight_tree.set_items(vec![BacklogItem {
        id: "tui-modernize".into(),
        title: "Modernize the TUI".into(),
        status: "active".into(),
        is_milestone: true,
    }]);
    app.growlight_preview_title = "tui-modernize".into();
    app.growlight_preview = "## Mission\nstill readable with growlightd down".into();

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    // One dim unreachable line, no error splat.
    assert!(rendered.contains("growlightd unreachable"), "dim line missing:\n{rendered}");
    // The garden-only page still works.
    assert!(rendered.contains("tui-modernize"), "backlog tree gone");
    assert!(rendered.contains("still readable"), "node body gone");
}

#[test]
fn growlight_header_shows_the_live_runtime_baton_headline() {
    use softfig_ipc::growlightd::BatonReply;
    use softfig_tui::app::FleetHeader;

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    // Even with the growlightd STATUS poll unreachable, the LIVE runtime baton
    // (its own verb) still drives the header baton-headline (slice 004).
    app.fleet = FleetHeader::Unreachable;
    app.growlight_runtime_baton = Some(BatonReply {
        agent: None,
        path: "/x/baton.md".into(),
        text: "---\nstatus: IN_PROGRESS\nitem: growlight-tui-detail-pane\nslice: 004\n---\n\
               # NEXT ACTION\ngo"
            .into(),
    });

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("runtime baton"), "live baton headline missing:\n{rendered}");
    assert!(rendered.contains("IN_PROGRESS"), "parsed baton status missing:\n{rendered}");
    assert!(rendered.contains("growlight-tui-detail-pane"), "parsed baton item missing");
}

#[test]
fn selecting_the_live_baton_node_renders_it_from_the_polled_reply() {
    use softfig_ipc::growlightd::BatonReply;
    use softfig_tui::tree::{BacklogItem, BacklogKind};

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    // A tree with the live-baton node turned on; select that node.
    app.growlight_tree.set_items(vec![BacklogItem {
        id: "tui-modernize".into(),
        title: "Modernize the TUI".into(),
        status: "active".into(),
        is_milestone: true,
    }]);
    app.growlight_tree.set_runtime_baton(true);
    let vis = app.growlight_tree.visible();
    let baton_idx = vis.iter().position(|r| r.kind == BacklogKind::RuntimeBaton).unwrap();
    app.growlight_tree.selected = baton_idx;
    // The polled runtime baton drives the right pane directly (no keeperd read).
    app.growlight_runtime_baton = Some(BatonReply {
        agent: None,
        path: "/x/baton.md".into(),
        text: "---\nstatus: IN_PROGRESS\nitem: tui-modernize\nslice: 002\n---\n\
               # NEXT ACTION\nfinish the node viewer"
            .into(),
    });

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    // The node label in the tree, the parsed compact head, and the stripped body.
    assert!(rendered.contains("live runtime baton"), "baton tree node missing:\n{rendered}");
    assert!(rendered.contains("tui-modernize"), "parsed baton item missing:\n{rendered}");
    assert!(rendered.contains("NEXT ACTION"), "baton body missing:\n{rendered}");
}

#[test]
fn selecting_the_bus_node_renders_history_newest_first_with_alerts_loud() {
    use ratatui::style::{Color, Modifier};
    use softfig_tui::app::BusRow;
    use softfig_tui::tree::{BacklogItem, BacklogKind};

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    app.growlight_tree.set_items(vec![BacklogItem {
        id: "tui-modernize".into(),
        title: "Modernize the TUI".into(),
        status: "active".into(),
        is_milestone: true,
    }]);
    app.growlight_tree.set_bus(true);
    // Eagerly-loaded bus rows (already newest-first, as `bus_rows` produces): an
    // alert on top, an info below.
    app.growlight_bus = vec![
        BusRow {
            from: "b".into(),
            to: "@all".into(),
            kind: "alert".into(),
            body: "wifi down".into(),
            is_alert: true,
        },
        BusRow {
            from: "a".into(),
            to: "b".into(),
            kind: "info".into(),
            body: "rebased ok".into(),
            is_alert: false,
        },
    ];
    // Select the bus node (it closes the tree).
    let vis = app.growlight_tree.visible();
    app.growlight_tree.selected = vis
        .iter()
        .position(|r| r.kind == BacklogKind::Bus)
        .unwrap();

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("coordination bus"), "bus pane title missing:\n{rendered}");
    assert!(rendered.contains("wifi down"), "alert message missing");
    assert!(rendered.contains("rebased ok"), "info message missing");
    // The alert row is rendered loud (bold red) — inspect the cell styles of the
    // buffer row where the alert body sits, not just the text. The whole `alert`
    // line is styled, so every visible content cell in that row is bold red.
    let buf = terminal.backend().buffer();
    let mut checked_alert_row = false;
    for y in 0..buf.area.height {
        // Reconstruct the row (column-wise, one symbol per cell) to find the alert
        // line — column index, not byte offset, so the multi-byte `→` is harmless.
        let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
        if !row.contains("wifi down") {
            continue;
        }
        checked_alert_row = true;
        // Every non-blank, non-border content cell on this row is bold red.
        let loud = (0..buf.area.width)
            .map(|x| &buf[(x, y)])
            .filter(|c| !c.symbol().trim().is_empty() && c.symbol() != "│")
            .all(|c| c.fg == Color::Red && c.modifier.contains(Modifier::BOLD));
        assert!(loud, "the alert row must render bold red:\n{rendered}");
        break;
    }
    assert!(checked_alert_row, "alert row not found in the buffer:\n{rendered}");
}

#[test]
fn selecting_the_injected_context_node_shows_both_protocol_and_baton_halves() {
    use softfig_ipc::growlightd::BatonReply;
    use softfig_tui::tree::{BacklogItem, BacklogKind};

    let mut app = App::new();
    app.locked = false;
    app.growlight_enabled = Some(true);
    app.view = softfig_tui::app::View::Growlight;
    app.growlight_tree.set_items(vec![BacklogItem {
        id: "tui-modernize".into(),
        title: "Modernize the TUI".into(),
        status: "active".into(),
        is_milestone: true,
    }]);
    app.growlight_tree.set_injected_context(true);
    // Both halves loaded: the protocol (a keeperd read cached on select) + the live
    // runtime baton (the polled growlightd reply). The pane assembles them in the
    // `inject.sh` boot framing.
    app.growlight_injected_protocol = Some("the PROTOMARK operating body".into());
    app.growlight_runtime_baton = Some(BatonReply {
        agent: None,
        path: "/x/baton.md".into(),
        text: "---\nstatus: IN_PROGRESS\n---\n# NEXT ACTION\nBATONMARK go".into(),
    });
    // Select the injected-context node (it closes the tree).
    let vis = app.growlight_tree.visible();
    app.growlight_tree.selected = vis
        .iter()
        .position(|r| r.kind == BacklogKind::InjectedContext)
        .unwrap();

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("injected context"), "pane title missing:\n{rendered}");
    // Boot framing: both section headers appear (right pane ~60 cols → no wrap).
    assert!(rendered.contains("OPERATING PROTOCOL"), "protocol header missing:\n{rendered}");
    assert!(rendered.contains("CURRENT BATON"), "baton header missing:\n{rendered}");
    // Both halves' content: a protocol marker AND a baton marker.
    assert!(rendered.contains("PROTOMARK"), "protocol half body missing:\n{rendered}");
    assert!(rendered.contains("BATONMARK"), "baton half body missing:\n{rendered}");
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
