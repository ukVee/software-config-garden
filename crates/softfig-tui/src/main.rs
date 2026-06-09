//! soft-fig terminal UI (M3b).
//!
//! A ratatui frontend over `softfig-keeperd`: browse the garden, read
//! history, run the M3a write actions, and unlock the vault — all over the
//! existing IPC verbs plus the M3b read-only `list_tree`/`read_file`. The
//! daemon enforces redaction server-side, so the TUI never sees sealed
//! plaintext.

use std::io::{self, Stdout};
use std::time::Duration;

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
    let mut app = App::new();
    app.bootstrap(&mut ipc);

    install_panic_hook();
    let mut terminal = setup_terminal()?;
    let res = run(&mut terminal, &mut app, &mut ipc);
    restore_terminal(&mut terminal)?;
    res
}

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

fn run(terminal: &mut Term, app: &mut App, ipc: &mut IpcClient) -> Result<()> {
    loop {
        terminal.draw(|f| ui::render(f, app))?;

        for reply in ipc.drain() {
            app.apply_reply(reply, ipc);
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
