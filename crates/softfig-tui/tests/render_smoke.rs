//! One `TestBackend` frame snapshot: render the Browse view with a small
//! tree + preview and assert the key chrome and content appear. Proves the
//! render path wires together without a real terminal (the live key
//! handling is a manual smoke step).
//!
//! The pointer/touch tests at the bottom go one step further: they render a
//! real frame, read a hit zone out of `App::hits`, and dispatch a synthetic
//! mouse event at that zone — so the drawn geometry and the tap handling are
//! proven to agree, not just each half in isolation.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Modifier;
use ratatui::Terminal;
use softfig_ipc::TreeEntry;
use softfig_tui::app::{App, Overlay, View};
use softfig_tui::hit::Hit;
use softfig_tui::ipc::IpcClient;
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
    use softfig_ipc::{HostedChain, PushTarget};

    // Task 058: the stale push target must show its ⚠ marker and its reason in
    // the list itself, without the user opening the detail pane.
    fn push_target(fp: &str) -> PushTarget {
        PushTarget {
            fingerprint: fp.into(),
            name: Some("otg-travel".into()),
            last_ok: Some(1_700_000_000),
            last_ok_age_secs: Some(27 * 86_400),
            stale: true,
            state: "no-route".into(),
            state_since: Some(1_700_000_000),
            detail: None,
        }
    }

    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Backup;
    app.replica_host = true;
    app.replica_push_to = vec![push_target(&"1".repeat(64))];
    app.hosted = vec![HostedChain {
        fingerprint: "2".repeat(64),
        name: Some("tablet".into()),
        tip: Some("deadbeefcafe".into()),
        height: 7,
        objects: 21,
        bytes: 8192,
        last_sync: Some(1_700_000_000),
        last_sync_age_secs: Some(90),
        stale: false,
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
    assert!(rendered.contains("STALE"), "stale push target unmarked:\n{rendered}");
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
    use softfig_ipc::{PendingShareOfferInfo, SharedSubtreeInfo};

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
            // Divergent placement: this device chose projects/journals; the
            // sharer recommended rec/j. The detail pane surfaces the hint.
            recommended_path: Some("rec/j".into()),
        },
        SharedSubtreeInfo {
            id: "notes".into(),
            mount_path: "projects/notes".into(),
            ref_name: "chain/notes".into(),
            enabled: false,
            key_id: None,
            recommended_path: None,
        },
    ];
    // M5f slice 006: a pending offer surfaces as a trailing row + a detail block.
    app.share_offers = vec![PendingShareOfferInfo {
        id: "wiki".into(),
        ref_name: "chain/wiki".into(),
        recommended_path: Some("rec/w".into()),
        offered_by: "a1b2c3d4e5f6".into(),
    }];
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
    // M5f slice 006 surface: the divergent recommendation on the selected share,
    // plus the pending offer (id + its recommended path).
    assert!(
        rendered.contains("rec/j"),
        "sharer-recommended path missing from share detail:\n{rendered}"
    );
    assert!(rendered.contains("wiki"), "pending offer row missing:\n{rendered}");
    assert!(
        rendered.contains("rec/w"),
        "pending offer recommended path missing:\n{rendered}"
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

// ---- pointer/touch: drawn geometry drives the synthetic events ------------

/// The top-left cell of the first recorded zone matching `wanted`.
fn point_at(app: &App, wanted: impl Fn(Hit) -> bool) -> (u16, u16) {
    let zone = app
        .hits
        .zones()
        .iter()
        .find(|z| wanted(z.hit))
        .expect("zone not recorded");
    (zone.rect.x, zone.rect.y)
}

/// A synthetic left-button press at a cell (what a tap / touch-pointer click
/// delivers to the event loop).
fn press(app: &mut App, ipc: &mut IpcClient, column: u16, row: u16) {
    app.handle_mouse(
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        },
        ipc,
    );
}

fn dummy_ipc() -> IpcClient {
    // A bogus socket: the worker idles/errors on connect and never blocks the
    // test. State mutations happen synchronously before any send.
    IpcClient::spawn(PathBuf::from("/nonexistent/softfig.sock"))
}

fn draw(app: &mut App) {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, app)).unwrap();
}

#[test]
fn a_tap_on_the_history_tab_switches_view() {
    let mut app = App::new();
    app.locked = false;
    draw(&mut app);

    let (column, row) = point_at(&app, |h| {
        matches!(h, Hit::Key(k) if k.code == KeyCode::Char('2'))
    });
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    assert_eq!(app.view, View::History);
}

#[test]
fn a_tap_on_a_visible_row_selects_and_opens_it() {
    let mut app = App::new();
    app.locked = false;
    app.tree
        .set_children("", vec![entry("CLAUDE.md", false), entry("meta", true)]);
    draw(&mut app);

    let (column, row) = point_at(&app, |h| matches!(h, Hit::Row { index: 1, .. }));
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    assert_eq!(app.tree.selected, 1, "the tap lands on the drawn row");
    // Smoke: the file/folder trees open on the first tap.
    assert!(app.tree.is_expanded("meta"), "one tap opens the folder");
}

// (The old footer action-chip test is superseded by the floating-button menu
// tests below: the chips moved into the menu button.)

#[test]
fn a_modal_blocks_page_taps_and_records_its_own_chips() {
    let mut app = App::new();
    app.locked = false;
    app.view = View::Peers;
    app.tree.set_children("", vec![entry("meta", true)]);
    app.overlay = Overlay::PairConfirm {
        pairing_id: "pid-1".into(),
        sas: "123 456".into(),
        fingerprint: "f".repeat(64),
        name: "laptop".into(),
        error: None,
    };
    draw(&mut app);

    assert!(
        app.hits
            .zones()
            .iter()
            .all(|z| !matches!(z.hit, Hit::Row { .. })),
        "page rows must be inert while a modal is open"
    );
    let (column, row) = point_at(&app, |h| {
        matches!(h, Hit::Key(k) if k.code == KeyCode::Char('y'))
    });
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    assert!(app.status.contains("confirming"), "the y chip confirmed");
    assert!(
        matches!(app.overlay, Overlay::PairConfirm { .. }),
        "the modal stays open until the daemon answers"
    );
}

#[test]
fn a_tap_anywhere_dismisses_the_help_overlay() {
    let mut app = App::new();
    app.locked = false;
    app.overlay = Overlay::Help;
    draw(&mut app);

    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, 50, 15);
    assert!(
        !matches!(app.overlay, Overlay::Help),
        "the help card must dismiss on tap"
    );
}

// ---- floating menu button + editor switches -------------------------------

fn release(app: &mut App, ipc: &mut IpcClient, column: u16, row: u16) {
    app.handle_mouse(
        MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        },
        ipc,
    );
}

#[test]
fn the_floating_button_opens_the_menu_and_outside_taps_close_it() {
    let mut app = App::new();
    app.locked = false;
    draw(&mut app);
    let (column, row) = point_at(&app, |h| matches!(h, Hit::Fab));
    let mut ipc = dummy_ipc();
    // Press + release with no motion is a tap on the floating button.
    press(&mut app, &mut ipc, column, row);
    release(&mut app, &mut ipc, column, row);
    assert!(
        matches!(app.overlay, Overlay::Menu { .. }),
        "a tap opens the action menu"
    );

    // Redraw so the menu's rows are recorded, then tap one: it runs and closes.
    draw(&mut app);
    let wanted = app
        .menu_actions()
        .iter()
        .position(|(label, _)| *label == "? help")
        .expect("help is always in the menu");
    let (c, r) = point_at(&app, |h| matches!(h, Hit::MenuRow(i) if i == wanted));
    press(&mut app, &mut ipc, c, r);
    assert!(
        matches!(app.overlay, Overlay::Help),
        "the tapped row ran its key after closing the menu"
    );

    // Reopen, then tap the top-left cell (away from the card): outside closes.
    app.overlay = Overlay::Menu { selected: 0 };
    draw(&mut app);
    press(&mut app, &mut ipc, 0, 0);
    assert!(
        matches!(app.overlay, Overlay::None),
        "a tap outside the card closes the menu"
    );
}

#[test]
fn the_editor_view_switch_is_drawn_and_tappable() {
    use softfig_tui::editor::{Editor, EditorMode};

    let mut app = App::new();
    app.locked = false;
    app.view = View::Editor;
    app.editor = Some(Editor::from_read(
        "meta/x.md",
        "# T\nbody\n",
        Some("v1".into()),
        false,
        &[],
    ));
    draw(&mut app);

    let (column, row) = point_at(&app, |h| matches!(h, Hit::EditorView(true)));
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    assert_eq!(
        app.editor.as_ref().unwrap().mode,
        EditorMode::Bionic,
        "the drawn switch selects bionic"
    );
}

#[test]
fn a_palette_row_runs_without_typing() {
    let mut app = App::new();
    app.locked = false;
    app.view = View::Deploy;
    app.overlay = Overlay::Palette(String::new());
    draw(&mut app);

    // `browse` is the first row, always within the visible budget.
    let (column, row) = point_at(&app, |h| matches!(h, Hit::PalettePick("browse")));
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    assert_eq!(app.view, View::Browse, "the tapped row ran `browse`");
    assert!(matches!(app.overlay, Overlay::None), "the palette closed");
}

#[test]
fn the_palette_list_scrolls_for_rows_past_the_budget() {
    let mut app = App::new();
    app.locked = false;
    app.overlay = Overlay::Palette(String::new());
    draw(&mut app);

    let (column, row) = point_at(&app, |h| matches!(h, Hit::PaletteBody));
    let mut ipc = dummy_ipc();
    app.handle_mouse(
        MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        },
        &mut ipc,
    );
    assert_eq!(app.palette_scroll, 3, "the wheel scrolls the command list");
}

#[test]
fn tapping_a_form_field_focuses_it() {
    use softfig_tui::forms::{ActionForm, ActionKind};

    let mut app = App::new();
    app.locked = false;
    app.overlay = Overlay::Form(ActionForm::for_kind(ActionKind::Archive));
    draw(&mut app);

    let (column, row) = point_at(&app, |h| matches!(h, Hit::FormField(1)));
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    match &app.overlay {
        Overlay::Form(form) => assert_eq!(form.focus, 1, "the tapped field is focused"),
        other => panic!("form closed unexpectedly: {other:?}"),
    }
}

#[test]
fn the_selection_magnifier_follows_a_drag_in_the_editor() {
    use softfig_tui::editor::Editor;

    let mut app = App::new();
    app.locked = false;
    app.view = View::Editor;
    app.editor = Some(Editor::from_read(
        "notes/x.md",
        "the quick brown fox\nsecond line\n",
        Some("v1".into()),
        false,
        &[],
    ));
    draw(&mut app);

    let (column, row) = point_at(&app, |h| matches!(h, Hit::EditorLine { row: 0, .. }));
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    app.handle_mouse(
        MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column: column + 4,
            row: row + 1,
            modifiers: KeyModifiers::NONE,
        },
        &mut ipc,
    );
    assert!(app.selection_pointer().is_some(), "gesture in progress");
    assert!(
        app.editor.as_ref().unwrap().has_selection(),
        "the drag selected text"
    );

    // Redraw: the magnifier card must be part of the frame.
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| softfig_tui::ui::render(f, &mut app)).unwrap();
    let rendered = format!("{}", terminal.backend());
    assert!(
        rendered.contains("cursor "),
        "magnifier card missing:\n{rendered}"
    );
}

// ---- M3c editor frames ----

#[test]
fn renders_editor_raw_frame() {
    use softfig_tui::editor::Editor;

    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Editor;
    app.editor = Some(Editor::from_read(
        "meta/spec-keeper.md",
        "# Keeper spec\n\nHello world API\n\n```\ncode line\n```\n",
        Some("v1".into()),
        false,
        &[],
    ));
    app.status = "editing".into();

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(
        rendered.contains("edit meta/spec-keeper.md"),
        "editor title missing:\n{rendered}"
    );
    assert!(rendered.contains("raw"), "raw mode badge missing");
    assert!(rendered.contains("Hello world API"), "source line missing");
    assert!(rendered.contains("code line"), "fenced line missing");
    assert!(rendered.contains("Tab toggle"), "key hint missing");
}

#[test]
fn renders_editor_bionic_frame() {
    use softfig_tui::editor::{Editor, EditorMode};

    let mut app = App::new();
    app.locked = false;
    app.view = softfig_tui::app::View::Editor;
    let mut ed = Editor::from_read(
        "meta/spec-keeper.md",
        "# Keeper spec\n\nThe API reads plain text.\n\n```\nAPI stays code\n```\n",
        Some("v1".into()),
        false,
        &[],
    );
    ed.toggle_mode();
    assert_eq!(ed.mode, EditorMode::Bionic);
    app.editor = Some(ed);
    app.status = "reading".into();

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();

    let rendered = format!("{}", terminal.backend());
    assert!(
        rendered.contains("bionic (read-only)"),
        "bionic badge missing:\n{rendered}"
    );
    assert!(
        rendered.contains("The API reads plain text."),
        "bionic text missing"
    );
    assert!(rendered.contains("API stays code"), "code line missing");
}

/// The selected span must actually render reversed in the frame — both for a
/// double-tap word selection and mid-drag (manual smoke: selection state
/// existed but was invisible on the device).
#[test]
fn editor_selection_renders_reversed_cells() {
    use softfig_tui::editor::Editor;

    let mut app = App::new();
    app.locked = false;
    app.view = View::Editor;
    let mut ed = Editor::from_read(
        "notes/sel.md",
        "the quick brown fox\nsecond line\n",
        Some("v1".into()),
        false,
        &[],
    );
    ed.select_word_at(0, 5); // selects "quick"
    app.editor = Some(ed);
    assert_reversed(&mut app, "quick");

    // The live drag path must light up mid-gesture, not only at rest.
    app.editor = Some(Editor::from_read(
        "notes/sel.md",
        "the quick brown fox\nsecond line\n",
        Some("v1".into()),
        false,
        &[],
    ));
    app.hits = softfig_tui::hit::HitMap::new();
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    let (column, row) = point_at(&app, |h| matches!(h, Hit::EditorLine { row: 0, .. }));
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    app.handle_mouse(
        MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column: column + 4,
            row,
            modifiers: KeyModifiers::NONE,
        },
        &mut ipc,
    );
    assert!(
        app.editor.as_ref().unwrap().has_selection(),
        "drag created a selection"
    );
    assert_reversed(&mut app, "the q");
}

/// Bionic is the persisted default editor view; a double-tap word selection
/// must highlight there too (smoke finding: selection looked impossible).
#[test]
fn bionic_editor_selection_renders_reversed_cells() {
    use softfig_tui::editor::{Editor, EditorMode};

    let mut app = App::new();
    app.locked = false;
    app.view = View::Editor;
    let mut ed = Editor::from_read(
        "notes/sel.md",
        "the quick brown fox\nsecond line\n",
        Some("v1".into()),
        false,
        &[],
    );
    ed.set_mode(EditorMode::Bionic);
    ed.select_word_at(0, 5);
    app.editor = Some(ed);
    assert_reversed(&mut app, "quick");
}

/// The top-left cell of the first frame occurrence of `needle`, scanned
/// char-exact per row (border glyphs are multi-byte).
fn find_text(buf: &Buffer, needle: &str) -> (u16, u16) {
    let rows: Vec<Vec<char>> = (0..buf.area.height)
        .map(|y| {
            (0..buf.area.width)
                .map(|x| {
                    buf.cell((x, y))
                        .and_then(|c| c.symbol().chars().next())
                        .unwrap_or(' ')
                })
                .collect()
        })
        .collect();
    let pat: Vec<char> = needle.chars().collect();
    rows.iter()
        .enumerate()
        .find_map(|(y, cs)| {
            cs.windows(pat.len())
                .position(|w| w == pat.as_slice())
                .map(|x| (x as u16, y as u16))
        })
        .unwrap_or_else(|| panic!("{needle:?} not rendered"))
}

/// Render `app` at the standard test size and assert every frame cell of
/// `needle` carries the REVERSED modifier.
fn assert_reversed(app: &mut App, needle: &str) {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, app)).unwrap();
    let buf = terminal.backend().buffer();
    let (x, y) = find_text(buf, needle);
    for (i, _) in needle.chars().enumerate() {
        let cell = buf.cell((x + i as u16, y)).unwrap();
        assert!(
            cell.modifier.contains(Modifier::REVERSED),
            "{needle:?} char {i} is not reversed: {cell:?}"
        );
    }
}

/// The Browse preview's `[ bionic ]` chip toggles the reading view on tap and
/// the frame then renders the bionic lead (bold) from the preview content.
#[test]
fn browse_preview_bionic_chip_toggles_and_bolds() {
    let mut app = App::new();
    app.locked = false;
    app.preview = "# Title\n\nThe quick brown fox\n".into();
    app.preview_title = "notes/x.md".into();
    draw(&mut app);

    let (column, row) = point_at(&app, |h| matches!(h, Hit::PreviewBionic));
    let mut ipc = dummy_ipc();
    press(&mut app, &mut ipc, column, row);
    assert!(app.preview_bionic, "the chip tap toggled the bionic preview");

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::render(f, &mut app)).unwrap();
    let buf = terminal.backend().buffer();
    let (x, y) = find_text(buf, "The quick");
    let cell = buf.cell((x, y)).unwrap();
    assert!(
        cell.modifier.contains(Modifier::BOLD),
        "the bionic lead 'T' is bold: {cell:?}"
    );
    let rendered = format!("{}", terminal.backend());
    assert!(rendered.contains("bionic"), "the toggle chip is visible");
}
