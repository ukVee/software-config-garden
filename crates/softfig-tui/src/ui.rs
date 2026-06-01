//! Rendering. Master/detail: left tree (or history list), right preview,
//! a header tab bar and a footer status line, with centered overlays for
//! the palette, unlock prompt, action forms, and help.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Overlay, View};
use crate::command::command_hints;
use crate::forms::{ActionForm, FieldValue};

fn sel_style() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

pub fn render(f: &mut Frame, app: &App) {
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
        Span::raw("  "),
        Span::styled(format!("[{state}] tip:{tip}"), dim),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn render_body(f: &mut Frame, app: &App, area: Rect) {
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

fn render_preview(f: &mut Frame, app: &App, area: Rect) {
    let p = Paragraph::new(app.preview.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.preview_title.clone()),
        )
        .wrap(Wrap { trim: false });
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
    let rect = centered_rect(70, 60, area);
    f.render_widget(Clear, rect);
    let body = "\
soft-fig TUI — keys

  1 / 2 / 3    switch Browse / History / Vault
  j k ↑ ↓      move selection
  Enter l →    open file / expand dir / show commit / reveal (vault)
  h ←          collapse dir
  x            reveal selected sealed file
  c            copy last reveal's value to clipboard
  r            refresh view
  u            unlock (when locked)
  :            command palette
  ?            this help
  q            quit

command palette runs actions: log_decision, log_incident,
archive, add_project, refresh_snapshot, propose, seal, unseal

vault: reveal writes plaintext to a 0600 temp file and never
shows it in this TUI; c pipes that file straight to wl-copy

any key closes this help";
    let p = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title("help"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}
