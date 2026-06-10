//! Rendering. Master/detail: left tree (or history list), right preview,
//! a header tab bar and a footer status line, with centered overlays for
//! the palette, unlock prompt, action forms, and help.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{short_fp, App, Overlay, PairField, PeerRow, View};
use crate::command::command_hints;
use crate::forms::{ActionForm, FieldValue};

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
        Overlay::Reveal { path, buf, error } => {
            render_reveal(f, path, buf, error.as_deref(), area)
        }
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
    let line = Line::from(vec![
        Span::styled("softfig-tui ", Style::default().add_modifier(Modifier::BOLD)),
        tab("1:Browse", app.view == View::Browse),
        tab("2:History", app.view == View::History),
        tab("3:Vault", app.view == View::Vault),
        tab("4:Peers", app.view == View::Peers),
        Span::raw("  "),
        Span::styled(format!("[{state}] tip:{tip}"), dim),
    ]);
    f.render_widget(Paragraph::new(line), area);
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
    let items: Vec<ListItem> = if app.vault_files.is_empty() {
        vec![ListItem::new("(no sealed files — :seal a pattern to start)")]
    } else {
        app.vault_files
            .iter()
            .map(|p| ListItem::new(format!("🔒 {p}")))
            .collect()
    };
    let mut st = ListState::default();
    if !app.vault_files.is_empty() {
        st.select(Some(app.vault_selected.min(app.vault_files.len() - 1)));
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
    let items: Vec<ListItem> = if app.peer_rows.is_empty() {
        vec![ListItem::new("(no paired devices — p to pair)")]
    } else {
        app.peer_rows
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
            })
            .collect()
    };
    let mut st = ListState::default();
    if !app.peer_rows.is_empty() {
        st.select(Some(app.peers_selected.min(app.peer_rows.len() - 1)));
    }
    let title = format!(
        "peers — {} paired · {} pending",
        app.peers.len(),
        app.pending.len()
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
        "p pair · Enter confirm pending · D unpair · r refresh",
        Style::default().fg(Color::DarkGray),
    ));

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("peer detail"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_preview(f: &mut Frame, app: &mut App, area: Rect) {
    // Borders take one row/column on each side; wrapping + clamping work in
    // terms of that inner content box.
    let inner_w = area.width.saturating_sub(2);
    let inner_h = area.height.saturating_sub(2);

    let text = Paragraph::new(app.preview.as_str()).wrap(Wrap { trim: false });
    let total = text.line_count(inner_w) as u16;

    // Record the live geometry so key/mouse handlers can size pages and clamp.
    app.preview_viewport = inner_h;
    app.preview_total = total;
    let max = total.saturating_sub(inner_h);
    let offset = app.preview_scroll.min(max);
    app.preview_scroll = offset;

    let title = if total > inner_h {
        let pct = if max == 0 {
            100
        } else {
            (offset as u32 * 100 / max as u32) as u16
        };
        format!("{}  [{pct}%]", app.preview_title)
    } else {
        app.preview_title.clone()
    };

    let p = text
        .block(Block::default().borders(Borders::ALL).title(title))
        .scroll((offset, 0));
    f.render_widget(p, area);
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

fn render_reveal(f: &mut Frame, path: &str, buf: &str, error: Option<&str>, area: Rect) {
    let rect = centered_rect(70, 35, area);
    f.render_widget(Clear, rect);
    let masked: String = "*".repeat(buf.chars().count());
    let mut body = format!(
        "reveal {path}\n\nmaster password: {masked}\n\nEnter reveal · Esc cancel\n\n\
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

  1 / 2 / 3 / 4  switch Browse / History / Vault / Peers
  j k ↑ ↓      move selection
  Enter l →    open file / expand dir / show commit / reveal (vault)
               / confirm pending pairing (peers)
  h ←          collapse dir
  scroll preview (right pane):
    ^e ^y      line down / up        wheel  line-wise
    ^d ^u      half-page down / up
    ^f ^b      full-page down / up   PgDn/PgUp same
    g G        top / bottom
  x            reveal selected sealed file
  c            copy last reveal's value to clipboard
  p            pair a device (peers view)
  D            unpair selected device (peers view)
  r            refresh view
  u            unlock (when locked)
  :            command palette
  ?            this help
  q            quit

command palette runs actions: log_decision, log_incident,
archive, add_project, refresh_snapshot, propose, seal, unseal,
and pair / unpair / peers

vault: reveal writes plaintext to a 0600 temp file and never
shows it in this TUI; c pipes that file straight to wl-copy

peers: pairing rides the Noise XX handshake; compare the SAS
short code on both devices before confirming (defeats a MITM)

any key closes this help";
    let p = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title("help"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}
