//! soft-fig terminal UI (M3b).
//!
//! A ratatui frontend over `softfig-keeperd`: browse the garden, read
//! history, run the M3a write actions, and unlock the vault — all over the
//! existing IPC verbs plus the M3b read-only `list_tree`/`read_file`. The
//! daemon enforces redaction server-side, so the TUI never sees sealed
//! plaintext.

use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use softfig_tui::app::App;
use softfig_tui::ipc::IpcClient;
use softfig_tui::ui;

type Term = Terminal<CrosstermBackend<Stdout>>;

fn main() -> Result<()> {
    let socket = softfig_ipc::runtime_socket_path();
    let mut ipc = IpcClient::spawn(socket);
    // A SECOND, independent IPC channel — growlightd's own socket — for the live
    // fleet header (its `status` poll). Kept distinct from the keeperd garden
    // reads on purpose: process-state is the one permanent growlightd read and
    // never migrates to the future garden mount. Its worker idles until the
    // Growlight tab is active; an unreachable socket soft-fails in the header.
    let growlightd_socket = softfig_ipc::growlightd_runtime_socket_path();
    let mut growlightd = IpcClient::spawn(growlightd_socket);
    let mut app = App::new();
    app.bootstrap(&mut ipc);

    install_panic_hook();
    let mut terminal = setup_terminal()?;
    let res = run(&mut terminal, &mut app, &mut ipc, &mut growlightd);
    restore_terminal(&mut terminal)?;
    res
}

/// How often the live fleet header is repolled while the Growlight tab is the
/// active view (spec: ~1–2 s). Off-tab the poll is skipped entirely, so
/// growlightd is never hammered from another tab.
const FLEET_POLL_INTERVAL: Duration = Duration::from_millis(1500);

fn setup_terminal() -> Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    // Mouse capture lets the wheel scroll the preview; it also means terminal
    // text selection is taken over while the TUI runs, which is the usual
    // trade-off for a mouse-driven full-screen app.
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Best-effort terminal restore on panic, so a crash doesn't leave the
/// user's terminal in raw mode / the alternate screen.
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        prev(info);
    }));
}

fn run(
    terminal: &mut Term,
    app: &mut App,
    ipc: &mut IpcClient,
    growlightd: &mut IpcClient,
) -> Result<()> {
    // `None` whenever we're off the Growlight tab, so re-entering it polls the
    // fleet header immediately instead of waiting out the interval.
    let mut last_fleet_poll: Option<Instant> = None;
    loop {
        terminal.draw(|f| ui::render(f, app))?;

        for reply in ipc.drain() {
            app.apply_reply(reply, ipc);
        }
        // The growlightd channel only ever carries `FleetStatus` replies; route
        // them through the same sink (the keeperd `ipc` is unused by that arm).
        // An unreachable socket comes back as an `Err` and soft-fails there.
        for reply in growlightd.drain() {
            app.apply_reply(reply, ipc);
        }
        // Poll the live fleet header on a ~1.5 s cadence, but only while the
        // Growlight tab is the active, enabled view (mirrors the view-gated
        // loads) — and immediately on entry so the header isn't blank for a tick.
        if app.should_poll_fleet() {
            let due = last_fleet_poll.is_none_or(|t| t.elapsed() >= FLEET_POLL_INTERVAL);
            if due {
                app.poll_fleet_status(growlightd);
                last_fleet_poll = Some(Instant::now());
            }
        } else {
            last_fleet_poll = None;
        }

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    app.handle_key(key, ipc);
                }
                Event::Mouse(me) => app.handle_mouse(me, ipc),
                _ => {}
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}
