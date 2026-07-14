//! Rendering. Master/detail: left tree (or history list), right preview,
//! a header tab bar and a footer status line, with centered overlays for
//! the palette, unlock prompt, action forms, and help.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{
    baton_headline, short_fp, App, BackupRow, FleetHeader, Overlay, PairField, PeerRow, View,
};
use crate::command::command_hints;
use crate::forms::{ActionForm, FieldValue};
use softfig_ipc::DeployAction;

fn sel_style() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

pub fn render(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    render_body(f, app, chunks[1]);
    render_footer(f, app, chunks[2]);

    match &app.overlay {
        Overlay::None => {}
        Overlay::Palette(buf) => render_palette(f, buf, area),
        Overlay::Unlock { buf, error } => render_unlock(f, buf, error.as_deref(), area),
        Overlay::Reveal {
            path,
            buf,
            error,
            id,
        } => render_reveal(f, path, id.as_deref(), buf, error.as_deref(), area),
        Overlay::RevealRegion {
            path,
            ids,
            selected,
        } => render_reveal_region(f, path, ids, *selected, area),
        Overlay::Form(form) => render_form(f, form, area),
        Overlay::PairBegin {
            fingerprint,
            endpoint,
            focus,
            error,
        } => render_pair_begin(f, fingerprint, endpoint, *focus, error.as_deref(), area),
        Overlay::PairConfirm {
            sas,
            fingerprint,
            name,
            error,
            ..
        } => render_pair_confirm(f, sas, fingerprint, name, error.as_deref(), area),
        Overlay::Unpair {
            fingerprint,
            name,
            error,
        } => render_unpair(f, fingerprint, name, error.as_deref(), area),
        Overlay::ReplicaGrant { fingerprint, error } => {
            render_replica_grant(f, fingerprint, error.as_deref(), area)
        }
        Overlay::ReplicaRevoke {
            fingerprint,
            name,
            error,
        } => render_replica_revoke(f, fingerprint, name.as_deref(), error.as_deref(), area),
        Overlay::DeployForce { error } => render_deploy_force(f, error.as_deref(), area),
        Overlay::Help => render_help(f, area),
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let active = Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::Gray);
    let tab = |label: &'static str, on: bool| -> Span<'static> {
        if on {
            Span::styled(format!(" {label} "), active)
        } else {
            Span::styled(format!(" {label} "), dim)
        }
    };
    let state = if app.locked { "locked" } else { "unlocked" };
    let tip = app
        .tip
        .as_deref()
        .map(|h| h.chars().take(10).collect::<String>())
        .unwrap_or_else(|| "—".into());
    let mut spans = vec![
        Span::styled("softfig-tui ", Style::default().add_modifier(Modifier::BOLD)),
        tab("1:Browse", app.view == View::Browse),
        tab("2:History", app.view == View::History),
        tab("3:Vault", app.view == View::Vault),
        tab("4:Peers", app.view == View::Peers),
        tab("5:Backup", app.view == View::Backup),
        tab("6:Deploy", app.view == View::Deploy),
    ];
    // The Growlight tab appears ONLY when growlight is enabled on this garden —
    // no tab, no empty pane, no error otherwise (the load-bearing gate).
    if app.growlight_enabled == Some(true) {
        spans.push(tab("7:Growlight", app.view == View::Growlight));
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled(format!("[{state}] tip:{tip}"), dim));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_body(f: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    match app.view {
        View::Browse => {
            render_tree(f, app, cols[0]);
            render_preview(f, app, cols[1]);
        }
        View::History => {
            render_history(f, app, cols[0]);
            render_preview(f, app, cols[1]);
        }
        View::Vault => {
            render_vault(f, app, cols[0]);
            render_vault_detail(f, app, cols[1]);
        }
        View::Peers => {
            render_peers(f, app, cols[0]);
            render_peers_detail(f, app, cols[1]);
        }
        View::Backup => {
            render_backup(f, app, cols[0]);
            render_backup_detail(f, app, cols[1]);
        }
        View::Deploy => {
            render_deploy(f, app, cols[0]);
            render_deploy_detail(f, app, cols[1]);
        }
        View::Growlight => {
            render_growlight(f, app, cols[0]);
            render_growlight_detail(f, app, cols[1]);
        }
    }
}

fn render_tree(f: &mut Frame, app: &App, area: Rect) {
    let rows = app.tree.visible();
    let items: Vec<ListItem> = rows
        .iter()
        .map(|r| {
            let indent = "  ".repeat(r.depth);
            let marker = if r.is_dir {
                if r.expanded {
                    "- "
                } else {
                    "+ "
                }
            } else {
                "  "
            };
            ListItem::new(format!("{indent}{marker}{}", r.name))
        })
        .collect();

    let mut st = ListState::default();
    if !rows.is_empty() {
        st.select(Some(app.tree.selected.min(rows.len() - 1)));
    }
    let title = if app.garden_root.is_empty() {
        "browse".to_string()
    } else {
        format!("browse — {}", app.garden_root)
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(sel_style());
    f.render_stateful_widget(list, area, &mut st);
}

fn render_history(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .history
        .iter()
        .map(|h| {
            let hash = h.hash.chars().take(8).collect::<String>();
            ListItem::new(format!("{hash} {:<16} {}", h.intent, h.summary))
        })
        .collect();
    let mut st = ListState::default();
    if !app.history.is_empty() {
        st.select(Some(app.history_selected.min(app.history.len() - 1)));
    }
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("history"))
        .highlight_style(sel_style());
    f.render_stateful_widget(list, area, &mut st);
}

fn render_vault(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.vault.items.is_empty() {
        vec![ListItem::new("(no sealed files — :seal a pattern to start)")]
    } else {
        app.vault
            .items
            .iter()
            .map(|p| ListItem::new(format!("🔒 {p}")))
            .collect()
    };
    let mut st = ListState::default();
    if !app.vault.items.is_empty() {
        st.select(Some(app.vault.selected.min(app.vault.items.len() - 1)));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("vault — sealed files"),
        )
        .highlight_style(sel_style());
    f.render_stateful_widget(list, area, &mut st);
}

fn render_vault_detail(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::styled(
        "sealed globs",
        Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
    ));
    if app.vault_globs.is_empty() {
        lines.push(Line::raw("  (none)"));
    } else {
        for g in &app.vault_globs {
            lines.push(Line::raw(format!("  {g}")));
        }
    }
    lines.push(Line::raw(""));

    if let Some(info) = &app.reveal {
        lines.push(Line::styled(
            "last reveal",
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        ));
        lines.push(Line::raw(format!("  path:    {}", info.path)));
        lines.push(Line::raw(format!("  temp:    {}", info.temp_path)));
        lines.push(Line::raw(format!("  re-auth: expires at {} (unix)", info.expires_at)));
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "  c copy value to clipboard · plaintext is never shown here",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        lines.push(Line::styled(
            "Enter / x reveal selected · plaintext goes to a 0600 temp file, never this pane",
            Style::default().fg(Color::DarkGray),
        ));
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("vault detail"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_peers(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.peer_list.items.is_empty() {
        vec![ListItem::new("(no paired devices — p to pair)")]
    } else {
        app.peer_list
            .items
            .iter()
            .map(|row| match row {
                PeerRow::Peer(i) => {
                    let p = &app.peers[*i];
                    ListItem::new(format!("🔗 {}  {}", p.name, short_fp(&p.fingerprint)))
                }
                PeerRow::Pending(i) => {
                    let p = &app.pending[*i];
                    ListItem::new(Line::styled(
                        format!("⏳ {}  SAS {}", p.name, p.sas),
                        Style::default().fg(Color::Yellow),
                    ))
                }
                PeerRow::Discovered(i) => {
                    let d = &app.discovered[*i];
                    let name = d.name.as_deref().unwrap_or("(unnamed)");
                    ListItem::new(Line::styled(
                        format!("📡 {}  {}", name, short_fp(&d.fingerprint)),
                        Style::default().fg(Color::Cyan),
                    ))
                }
            })
            .collect()
    };
    let mut st = ListState::default();
    if !app.peer_list.items.is_empty() {
        st.select(Some(app.peer_list.selected.min(app.peer_list.items.len() - 1)));
    }
    let title = format!(
        "peers — {} paired · {} pending · {} nearby",
        app.peers.len(),
        app.pending.len(),
        app.discovered.len()
    );
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(sel_style());
    f.render_stateful_widget(list, area, &mut st);
}

fn render_peers_detail(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match app.selected_peer_row() {
        Some(PeerRow::Peer(i)) => {
            let p = &app.peers[i];
            lines.push(Line::styled(
                "ring member",
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
            ));
            lines.push(Line::raw(format!("  name:        {}", p.name)));
            lines.push(Line::raw(format!("  fingerprint: {}", p.fingerprint)));
            lines.push(Line::raw(format!("  transport:   {}", p.transport_pubkey)));
            let endpoints = if p.endpoints.is_empty() {
                "(none discovered)".to_string()
            } else {
                p.endpoints.join(", ")
            };
            lines.push(Line::raw(format!("  endpoints:   {endpoints}")));
            lines.push(Line::raw(format!("  paired at:   {} (unix)", p.paired_at)));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  D unpair this device",
                Style::default().fg(Color::DarkGray),
            ));
        }
        Some(PeerRow::Pending(i)) => {
            let p = &app.pending[i];
            lines.push(Line::styled(
                "pending — awaiting SAS confirmation",
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow),
            ));
            lines.push(Line::raw(format!("  name:        {}", p.name)));
            lines.push(Line::raw(format!("  fingerprint: {}", p.fingerprint)));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format!("  SAS  {}", p.sas),
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
            ));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  compare the SAS on both devices, then Enter to confirm",
                Style::default().fg(Color::DarkGray),
            ));
        }
        Some(PeerRow::Discovered(i)) => {
            let d = &app.discovered[i];
            lines.push(Line::styled(
                "discovered nearby — not yet paired",
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
            ));
            lines.push(Line::raw(format!(
                "  name:        {}",
                d.name.as_deref().unwrap_or("(unnamed)")
            )));
            lines.push(Line::raw(format!("  fingerprint: {}", d.fingerprint)));
            lines.push(Line::raw(format!(
                "  endpoint:    {}",
                d.endpoint.as_deref().unwrap_or("(none)")
            )));
            lines.push(Line::raw(format!("  last seen:   {}s ago", d.last_seen_secs)));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  p / Enter to pair (then compare the SAS)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        None => {
            lines.push(Line::styled(
                "no devices",
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
            ));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  p initiate pairing with a peer's fingerprint",
                Style::default().fg(Color::DarkGray),
            ));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "p pair · Enter confirm/pair · D unpair · r refresh",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("peer detail"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_backup(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.backup.items.is_empty() {
        vec![ListItem::new("(no backup grants — g to grant a paired host)")]
    } else {
        app.backup
            .items
            .iter()
            .map(|row| match row {
                BackupRow::PushTo(i) => {
                    let fp = &app.replica_push_to[*i];
                    let label = app.peer_name_for(fp).unwrap_or_else(|| short_fp(fp));
                    ListItem::new(Line::styled(
                        format!("⬆ {label}  hosts me"),
                        Style::default().fg(Color::Cyan),
                    ))
                }
                BackupRow::Hosted(i) => {
                    let c = &app.hosted[*i];
                    let label = c.name.as_deref().unwrap_or_else(|| short_fp(&c.fingerprint));
                    ListItem::new(Line::styled(
                        format!("⬇ {label}  I host  (h{})", c.height),
                        Style::default().fg(Color::Green),
                    ))
                }
            })
            .collect()
    };
    let mut st = ListState::default();
    if !app.backup.items.is_empty() {
        st.select(Some(app.backup.selected.min(app.backup.items.len() - 1)));
    }
    let title = format!(
        "backup — {} host me · {} I host · host:{}",
        app.replica_push_to.len(),
        app.hosted.len(),
        if app.replica_host { "on" } else { "off" },
    );
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(sel_style());
    f.render_stateful_widget(list, area, &mut st);
}

fn render_backup_detail(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match app.selected_backup_row() {
        Some(BackupRow::PushTo(i)) => {
            let fp = &app.replica_push_to[i];
            lines.push(Line::styled(
                "host — backs up my chain",
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
            ));
            if let Some(name) = app.peer_name_for(fp) {
                lines.push(Line::raw(format!("  name:        {name}")));
            }
            lines.push(Line::raw(format!("  fingerprint: {fp}")));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  I push my signed ciphertext here; this host verifies + stores",
                Style::default().fg(Color::DarkGray),
            ));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  D revoke this grant (the host keeps what it already holds)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        Some(BackupRow::Hosted(i)) => {
            let c = &app.hosted[i];
            lines.push(Line::styled(
                "hosted chain — opaque mirror",
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
            ));
            if let Some(name) = &c.name {
                lines.push(Line::raw(format!("  owner:       {name}")));
            }
            lines.push(Line::raw(format!("  fingerprint: {}", c.fingerprint)));
            let tip = c.tip.as_deref().unwrap_or("(nothing synced yet)");
            lines.push(Line::raw(format!("  tip:         {tip}")));
            lines.push(Line::raw(format!("  height:      {}", c.height)));
            lines.push(Line::raw(format!("  objects:     {}", c.objects)));
            lines.push(Line::raw(format!("  bytes:       {}", c.bytes)));
            let last = c
                .last_sync
                .map(|t| format!("{t} (unix)"))
                .unwrap_or_else(|| "never".into());
            lines.push(Line::raw(format!("  last sync:   {last}")));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  ciphertext only — I verify + store it but cannot read it",
                Style::default().fg(Color::DarkGray),
            ));
        }
        None => {
            lines.push(Line::styled(
                "no backup grants",
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
            ));
            lines.push(Line::raw(""));
            lines.push(Line::raw(format!(
                "  this device {} host peer chains",
                if app.replica_host {
                    "does"
                } else {
                    "does not"
                },
            )));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  g grant a paired device to back up this chain",
                Style::default().fg(Color::DarkGray),
            ));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "g grant · D revoke · r refresh",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("backup detail"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

/// A deploy action's compact verb + display colour (green create, yellow
/// replace, dim skip, red conflict) — shared by the list + detail panes.
fn deploy_action_style(a: DeployAction) -> (&'static str, Color) {
    // The verb string is shared with the CLI via the wire enum's `verb()`;
    // only the colour is a TUI concern, so it stays local here.
    let color = match a {
        DeployAction::CreateSymlink => Color::Green,
        DeployAction::ReplaceManaged => Color::Yellow,
        DeployAction::CopyStamped => Color::Green,
        DeployAction::SkipUnchanged => Color::DarkGray,
        DeployAction::Conflict => Color::Red,
    };
    (a.verb(), color)
}

fn render_deploy(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.deploy.items.is_empty() {
        vec![ListItem::new("(no dots in config/deploy.toml)")]
    } else {
        app.deploy
            .items
            .iter()
            .map(|e| {
                let (verb, color) = deploy_action_style(e.action);
                ListItem::new(Line::styled(
                    format!("{verb:>8}  {}", e.name),
                    Style::default().fg(color),
                ))
            })
            .collect()
    };
    let mut st = ListState::default();
    if !app.deploy.items.is_empty() {
        st.select(Some(app.deploy.selected.min(app.deploy.items.len() - 1)));
    }
    let title = format!(
        "deploy — {} dot(s){}",
        app.deploy.items.len(),
        if app.deploy_has_conflicts() {
            " · conflicts!"
        } else {
            ""
        },
    );
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(sel_style());
    f.render_stateful_widget(list, area, &mut st);
}

fn render_deploy_detail(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match app.selected_deploy_entry() {
        Some(e) => {
            let (verb, color) = deploy_action_style(e.action);
            lines.push(Line::styled(
                format!("{}  —  {verb}", e.name),
                Style::default().add_modifier(Modifier::BOLD).fg(color),
            ));
            lines.push(Line::raw(""));
            lines.push(Line::raw(format!("  target: {}", e.target)));
            if let Some(reason) = &e.conflict_reason {
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    format!("  conflict: {reason}"),
                    Style::default().fg(Color::Red),
                ));
                lines.push(Line::styled(
                    "  a leaves it alone · F backs it up (.softfig-bak) + overwrites",
                    Style::default().fg(Color::DarkGray),
                ));
            }
        }
        None => {
            lines.push(Line::styled(
                "nothing to deploy",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  config/deploy.toml has no dots (or the garden is locked)",
                Style::default().fg(Color::DarkGray),
            ));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "a apply · F force · r refresh",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("deploy detail"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

/// A backlog item's status colour — active stands out, done recedes, blocked is
/// loud. Shared by the queue list + the detail pane's active line.
fn growlight_status_color(status: &str) -> Color {
    match status {
        "active" => Color::Cyan,
        "awaiting-smoke" => Color::Magenta,
        "done" => Color::DarkGray,
        "blocked" => Color::Red,
        "deferred" => Color::Yellow,
        "context" => Color::Blue, // loop-context section leaves
        _ => Color::Gray,         // queued / unknown
    }
}

/// Left pane of the read-only Growlight section: the backlog as a navigable
/// tree — milestone/task items in drain order, each milestone expandable to its
/// slices (`+`/`-`), rows coloured by status (queue status, or a slice's
/// derived status), the active item bold.
fn render_growlight(f: &mut Frame, app: &App, area: Rect) {
    let rows = app.growlight_tree.visible();
    let items: Vec<ListItem> = if rows.is_empty() {
        vec![ListItem::new("(queue empty or not loaded)")]
    } else {
        rows.iter()
            .map(|r| {
                let indent = "  ".repeat(r.depth);
                let marker = if r.expandable {
                    if r.expanded {
                        "- "
                    } else {
                        "+ "
                    }
                } else {
                    "  "
                };
                let mut style = Style::default().fg(growlight_status_color(&r.status));
                if r.status == "active" {
                    style = style.add_modifier(Modifier::BOLD);
                }
                ListItem::new(Line::styled(
                    format!("{indent}{marker}{:<14} {}", r.status, r.label),
                    style,
                ))
            })
            .collect()
    };
    let mut st = ListState::default();
    if !rows.is_empty() {
        st.select(Some(app.growlight_tree.selected.min(rows.len() - 1)));
    }
    let title = format!("growlight — {} row(s)", rows.len());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(sel_style());
    f.render_stateful_widget(list, area, &mut st);
}

/// Right pane of the Growlight section: a fleet-header strip above a scrollable
/// markdown viewer of the selected tree node. Read-only — this section never
/// controls the loop.
fn render_growlight_detail(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(1)])
        .split(area);
    render_growlight_header(f, app, rows[0]);

    let placeholder =
        "(select a node — milestone · slice · task · loop context — to view its markdown)";
    let title = if app.growlight_preview.is_empty() {
        "growlight detail (read-only)".to_string()
    } else {
        format!("{}  (read-only)", app.growlight_preview_title)
    };
    let content: &str = if app.growlight_preview.is_empty() {
        placeholder
    } else {
        app.growlight_preview.as_str()
    };
    render_scroll_body(
        f,
        rows[1],
        content,
        &title,
        &mut app.preview_scroll,
        &mut app.preview_viewport,
        &mut app.preview_total,
    );
}

/// The always-visible fleet header strip. Slice 003 renders live growlightd
/// process-state from the `status` poll ([`App::fleet`]): the admission gate,
/// running agents, and policy budgets, above the garden-sourced baton headline.
/// Soft-fails: an unreachable growlightd collapses the live lines to a single
/// dim "unreachable" line, but the baton headline (a keeperd/garden read) stays,
/// so the header is useful even with growlightd down.
///
/// v1 shows no *live* budget % — that per-agent reading only arrives over the
/// `subscribe` event stream, which is out of scope for this milestone (no
/// streaming); the header surfaces the policy budget THRESHOLDS the `status`
/// poll does carry.
fn render_growlight_header(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match &app.fleet {
        FleetHeader::Live(s) => {
            let (arm, arm_color) = if s.fleet_enabled {
                ("armed", Color::Green)
            } else {
                ("disarmed", Color::DarkGray)
            };
            let (gate, gate_color) = if s.paused {
                ("paused", Color::Yellow)
            } else {
                ("active", arm_color)
            };
            // Line 1: the fleet gate + running-agent count.
            lines.push(Line::from(vec![
                Span::styled("fleet · ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    arm,
                    Style::default().fg(arm_color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" · "),
                Span::styled(gate, Style::default().fg(gate_color)),
                Span::raw(format!(" · {} agent(s) running", s.agents.len())),
            ]));
            // Line 2: which agents are running (or the configured roster when the
            // fleet is idle/disarmed and nothing has spawned).
            let agents = if !s.agents.is_empty() {
                s.agents
                    .iter()
                    .map(|a| format!("{}:{}", a.id, a.status))
                    .collect::<Vec<_>>()
                    .join(" · ")
            } else if !s.roster.is_empty() {
                let names = s
                    .roster
                    .iter()
                    .map(|m| m.agent.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("none running (roster: {names})")
            } else {
                "none running".to_string()
            };
            lines.push(Line::styled(
                format!("agents · {agents}"),
                Style::default().fg(Color::Gray),
            ));
            // Line 3: the policy budget thresholds this device runs under.
            let p = &s.policy;
            lines.push(Line::styled(
                format!(
                    "budgets · ctx roll {}% / handoff {}% · halt 5h {}% 7d {}% · ≤{} concurrent",
                    p.ctx_roll_pct,
                    p.ctx_handoff_pct,
                    p.session_5h_halt_pct,
                    p.session_7d_halt_pct,
                    p.max_concurrent_agents,
                ),
                Style::default().fg(Color::DarkGray),
            ));
        }
        FleetHeader::Unreachable => lines.push(Line::styled(
            "growlightd unreachable — fleet status unavailable",
            Style::default().fg(Color::DarkGray),
        )),
        FleetHeader::Unknown => lines.push(Line::styled(
            "growlightd · fleet status not yet polled",
            Style::default().fg(Color::DarkGray),
        )),
    }
    // The loop's latest handoff headline — a garden (keeperd/baton-log) read,
    // independent of growlightd, so it stays visible even when the fleet lines
    // soft-fail to the dim "unreachable" line.
    let title = app.growlight_baton_title.as_deref().unwrap_or("(none yet)");
    match app.growlight_baton.as_deref().and_then(baton_headline) {
        Some(h) => lines.push(Line::styled(
            format!("loop baton · {title} — {h}"),
            Style::default().fg(Color::Cyan),
        )),
        None => lines.push(Line::styled(
            "loop baton · (no baton-log entries yet)",
            Style::default().fg(Color::DarkGray),
        )),
    }
    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("fleet"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_deploy_force(f: &mut Frame, error: Option<&str>, area: Rect) {
    let rect = centered_rect(70, 40, area);
    f.render_widget(Clear, rect);
    let mut lines: Vec<Line> = vec![
        Line::raw("Force-apply the deploy plan?"),
        Line::raw(""),
        Line::styled(
            "Each conflicting target is moved to <target>.softfig-bak, then overwritten.",
            Style::default().fg(Color::DarkGray),
        ),
    ];
    if let Some(e) = error {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "y force · n / Esc cancel",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("force deploy"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

/// Render `content` into `area` as a bordered, wrapped, vertically-scrollable
/// `Paragraph`, recording the live viewport + total wrapped-line count so the
/// shared scroll keys can page and clamp, and clamping `scroll` to the real
/// bottom. `title_base` gains a ` [NN%]` suffix when the content overflows the
/// viewport. Shared by the Browse preview and the growlight detail body so both
/// scroll byte-identically (the scroll keys drive the same `preview_*` fields).
fn render_scroll_body(
    f: &mut Frame,
    area: Rect,
    content: &str,
    title_base: &str,
    scroll: &mut u16,
    viewport: &mut u16,
    total_out: &mut u16,
) {
    // Borders take one row/column on each side; wrapping + clamping work in
    // terms of that inner content box.
    let inner_w = area.width.saturating_sub(2);
    let inner_h = area.height.saturating_sub(2);

    let text = Paragraph::new(content).wrap(Wrap { trim: false });
    let total = text.line_count(inner_w) as u16;

    *viewport = inner_h;
    *total_out = total;
    let max = total.saturating_sub(inner_h);
    let offset = (*scroll).min(max);
    *scroll = offset;

    let title = if total > inner_h {
        let pct = if max == 0 {
            100
        } else {
            (offset as u32 * 100 / max as u32) as u16
        };
        format!("{title_base}  [{pct}%]")
    } else {
        title_base.to_string()
    };

    let p = text
        .block(Block::default().borders(Borders::ALL).title(title))
        .scroll((offset, 0));
    f.render_widget(p, area);
}

fn render_preview(f: &mut Frame, app: &mut App, area: Rect) {
    let mut title = app.preview_title.clone();
    // M2c: flag inline `<vault id=…>` regions so the user knows `x` opens the
    // per-region reveal picker for this file.
    if !app.regions.is_empty() {
        let n = app.regions.len();
        let plural = if n == 1 { "region" } else { "regions" };
        title.push_str(&format!("  · {n} vault {plural} (x)"));
    }
    render_scroll_body(
        f,
        area,
        &app.preview,
        &title,
        &mut app.preview_scroll,
        &mut app.preview_viewport,
        &mut app.preview_total,
    );
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hint = " :cmd  ?help  q quit ";
    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", app.status),
            Style::default().fg(Color::Black).bg(Color::Gray),
        ),
        Span::raw(" "),
        Span::styled(hint, Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn centered_rect(px: u16, py: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - py) / 2),
            Constraint::Percentage(py),
            Constraint::Percentage((100 - py) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - px) / 2),
            Constraint::Percentage(px),
            Constraint::Percentage((100 - px) / 2),
        ])
        .split(v[1])[1]
}

fn render_palette(f: &mut Frame, buf: &str, area: Rect) {
    let rect = centered_rect(80, 30, area);
    f.render_widget(Clear, rect);
    let body = format!(":{buf}\n\n{}", command_hints());
    let p = Paragraph::new(body)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("command (Enter run · Esc cancel)"),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_unlock(f: &mut Frame, buf: &str, error: Option<&str>, area: Rect) {
    let rect = centered_rect(60, 30, area);
    f.render_widget(Clear, rect);
    let masked: String = "*".repeat(buf.chars().count());
    let mut body = format!("passphrase: {masked}\n\nEnter unlock · Esc cancel");
    if let Some(e) = error {
        body.push_str(&format!("\n\nerror: {e}"));
    }
    let p = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title("unlock vault"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_reveal(
    f: &mut Frame,
    path: &str,
    id: Option<&str>,
    buf: &str,
    error: Option<&str>,
    area: Rect,
) {
    let rect = centered_rect(70, 35, area);
    f.render_widget(Clear, rect);
    let masked: String = "*".repeat(buf.chars().count());
    // Name the exact target: a single inline region (M2c) vs. the whole file (M2b).
    let target = match id {
        Some(id) => format!("region <{id}> of {path}"),
        None => path.to_string(),
    };
    let mut body = format!(
        "reveal {target}\n\nmaster password: {masked}\n\nEnter reveal · Esc cancel\n\n\
         plaintext is written to a 0600 temp file — never shown here"
    );
    if let Some(e) = error {
        body.push_str(&format!("\n\nerror: {e}"));
    }
    let p = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title("reveal secret"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

/// M2c: the inline-region picker. Lists the file's `<vault id=…>` region ids;
/// `Enter` on the highlighted one advances to the masked-password prompt.
fn render_reveal_region(f: &mut Frame, path: &str, ids: &[String], selected: usize, area: Rect) {
    let rect = centered_rect(70, 45, area);
    f.render_widget(Clear, rect);
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::raw(format!("inline vault regions in {path}")));
    lines.push(Line::raw(""));
    for (i, id) in ids.iter().enumerate() {
        let marker = if i == selected { "› " } else { "  " };
        let style = if i == selected {
            sel_style()
        } else {
            Style::default()
        };
        lines.push(Line::styled(format!("{marker}<{id}>"), style));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "j/k select · Enter reveal region · Esc cancel",
        Style::default().fg(Color::DarkGray),
    ));
    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("reveal — pick a region"),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_pair_begin(
    f: &mut Frame,
    fingerprint: &str,
    endpoint: &str,
    focus: PairField,
    error: Option<&str>,
    area: Rect,
) {
    let rect = centered_rect(75, 45, area);
    f.render_widget(Clear, rect);

    let focused = Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan);
    let unfocused = Style::default().fg(Color::Gray);
    let mark = |on: bool| if on { "> " } else { "  " };
    let fp_on = focus == PairField::Fingerprint;
    let ep_on = focus == PairField::Endpoint;

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                format!("{}fingerprint: ", mark(fp_on)),
                if fp_on { focused } else { unfocused },
            ),
            Span::raw(fingerprint.to_string()),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{}endpoint:    ", mark(ep_on)),
                if ep_on { focused } else { unfocused },
            ),
            Span::raw(endpoint.to_string()),
        ]),
        Line::styled(
            "  (endpoint optional — host:port; leave blank to use mDNS discovery)",
            Style::default().fg(Color::DarkGray),
        ),
        Line::raw(""),
    ];
    if let Some(e) = error {
        lines.push(Line::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        ));
    }
    lines.push(Line::styled(
        "Enter pair · Tab switch field · Esc cancel",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("pair a device"),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_pair_confirm(
    f: &mut Frame,
    sas: &str,
    fingerprint: &str,
    name: &str,
    error: Option<&str>,
    area: Rect,
) {
    let rect = centered_rect(70, 45, area);
    f.render_widget(Clear, rect);
    let mut lines: Vec<Line> = vec![
        Line::raw(format!("peer:        {name}")),
        Line::raw(format!("fingerprint: {fingerprint}")),
        Line::raw(""),
        Line::styled(
            format!("SAS  {sas}"),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green),
        ),
        Line::raw(""),
        Line::raw("Compare this code with the other device."),
    ];
    if let Some(e) = error {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "y confirm (codes match) · n / Esc abort",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("confirm pairing"),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_unpair(f: &mut Frame, fingerprint: &str, name: &str, error: Option<&str>, area: Rect) {
    let rect = centered_rect(65, 35, area);
    f.render_widget(Clear, rect);
    let mut lines: Vec<Line> = vec![
        Line::raw(format!("Remove {name} from the trust ring?")),
        Line::raw(format!("  {fingerprint}")),
    ];
    if let Some(e) = error {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "y unpair · n / Esc cancel",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("unpair device"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_replica_grant(f: &mut Frame, fingerprint: &str, error: Option<&str>, area: Rect) {
    let rect = centered_rect(75, 40, area);
    f.render_widget(Clear, rect);
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                "fingerprint: ",
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
            ),
            Span::raw(fingerprint.to_string()),
        ]),
        Line::styled(
            "  (a paired device's id — full or a unique prefix)",
            Style::default().fg(Color::DarkGray),
        ),
        Line::raw(""),
        Line::raw("Grant this device permission to back up my chain (ciphertext only)."),
        Line::raw(""),
    ];
    if let Some(e) = error {
        lines.push(Line::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        ));
    }
    lines.push(Line::styled(
        "Enter grant · Esc cancel",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("grant backup host"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_replica_revoke(
    f: &mut Frame,
    fingerprint: &str,
    name: Option<&str>,
    error: Option<&str>,
    area: Rect,
) {
    let rect = centered_rect(70, 40, area);
    f.render_widget(Clear, rect);
    let who = name.unwrap_or("this host");
    let mut lines: Vec<Line> = vec![
        Line::raw(format!("Stop backing up my chain to {who}?")),
        Line::raw(format!("  {fingerprint}")),
        Line::raw(""),
        Line::styled(
            "It keeps any ciphertext already pushed; only future pushes stop.",
            Style::default().fg(Color::DarkGray),
        ),
    ];
    if let Some(e) = error {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "y revoke · n / Esc cancel",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("revoke backup host"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_form(f: &mut Frame, form: &ActionForm, area: Rect) {
    let rect = centered_rect(80, 70, area);
    f.render_widget(Clear, rect);

    let mut lines: Vec<Line> = Vec::new();
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let marker = if focused { "> " } else { "  " };
        let label_style = if focused {
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)
        } else {
            Style::default().fg(Color::Gray)
        };
        match &field.value {
            FieldValue::Line(s) => {
                lines.push(Line::from(vec![
                    Span::styled(format!("{marker}{}: ", field.label), label_style),
                    Span::raw(s.clone()),
                ]));
            }
            FieldValue::Body(t) => {
                lines.push(Line::styled(
                    format!("{marker}{}:", field.label),
                    label_style,
                ));
                for bl in t.lines() {
                    lines.push(Line::from(format!("    {bl}")));
                }
            }
        }
    }
    lines.push(Line::raw(""));
    if let Some(e) = &form.error {
        lines.push(Line::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        ));
    }
    lines.push(Line::styled(
        "Ctrl-S submit · Tab/↑↓ field · Enter newline(body) · Esc cancel",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(form.kind.title()),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

fn render_help(f: &mut Frame, area: Rect) {
    let rect = centered_rect(82, 90, area);
    f.render_widget(Clear, rect);
    let body = "\
soft-fig TUI — keys

  1 2 3 4 5 6  switch Browse / History / Vault / Peers / Backup / Deploy
  7            growlight (read-only): backlog → slices, loop-context, node viewer
  j k ↑ ↓      move selection (wraps top↔bottom; a growlight node shows its md)
  Enter l →    open file / expand dir / show commit / reveal (vault)
               / confirm pending pairing (peers)
               / expand milestone → slices (growlight)
  h ←          collapse dir / milestone (growlight)
  scroll preview / growlight node (right pane):
    ^e ^y      line down / up        wheel  line-wise
    ^d ^u      half-page down / up
    ^f ^b      full-page down / up   PgDn/PgUp same
    g G        top / bottom
  x            reveal selected sealed file; on a file with inline
               <vault id=…> regions, pick one region to reveal
  c            copy last reveal's value to clipboard
  p            pair a device (peers view)
  D            unpair / revoke selected (peers / backup view)
  g            grant a backup host (backup view)
  a F          apply / force-apply deploy plan (deploy view)
  r            refresh view
  u            unlock (when locked)
  :            command palette
  ?            this help
  q            quit

command palette runs actions: log_decision, log_incident,
archive, add_project, refresh_snapshot, propose, seal, unseal,
pair / unpair / peers, backup / grant / revoke, deploy / apply

vault: reveal writes plaintext to a 0600 temp file and never
shows it in this TUI; c pipes that file straight to wl-copy

peers: pairing rides the Noise XX handshake; compare the SAS
short code on both devices before confirming (defeats a MITM)

backup (M5b): grant a paired host to store this device's chain
as verified ciphertext it cannot decrypt; revoke stops future
pushes; chains I host for others show as read-only mirrors

any key closes this help";
    let p = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title("help"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}
