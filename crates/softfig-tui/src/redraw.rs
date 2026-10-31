//! Redraw-on-change decision for the event loop.
//!
//! A full `ui::render` pass plus the terminal emulator digesting the diff is the
//! expensive part of an idle TUI, not the 100 ms input poll. The loop therefore
//! draws only when [`RedrawGate`] says something visible can have changed: a
//! key press, a non-motion mouse event, a resize, or a drained IPC reply. The
//! render path reads no clock (no spinner, no relative timestamp), so an idle
//! tick is never a reason; a future visible timer calls [`RedrawGate::mark`]
//! when it fires.

use crossterm::event::{Event, KeyEventKind, MouseEventKind};

/// Dirty flag for the draw loop. Starts dirty so the first frame is painted.
#[derive(Debug)]
pub struct RedrawGate {
    dirty: bool,
}

impl Default for RedrawGate {
    fn default() -> Self {
        Self { dirty: true }
    }
}

impl RedrawGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Something visible changed (a timer fired, state was set out of band).
    pub fn mark(&mut self) {
        self.dirty = true;
    }

    /// An input event arrived. Key releases/repeats and bare pointer motion
    /// change nothing on screen (`App::pointer` is never rendered), so they
    /// don't count; everything else, including a resize, does.
    pub fn on_event(&mut self, ev: &Event) {
        let visible = match ev {
            Event::Key(k) => k.kind == KeyEventKind::Press,
            Event::Mouse(m) => m.kind != MouseEventKind::Moved,
            Event::Resize(..) => true,
            _ => false,
        };
        if visible {
            self.dirty = true;
        }
    }

    /// `n` IPC replies were drained; each one may have changed app state.
    pub fn on_replies(&mut self, n: usize) {
        if n > 0 {
            self.dirty = true;
        }
    }

    /// Whether to draw this iteration. Consumes the flag.
    pub fn take(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };

    fn key(kind: KeyEventKind) -> Event {
        let mut k = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE);
        k.kind = kind;
        Event::Key(k)
    }

    fn mouse(kind: MouseEventKind) -> Event {
        Event::Mouse(MouseEvent {
            kind,
            column: 3,
            row: 4,
            modifiers: KeyModifiers::NONE,
        })
    }

    #[test]
    fn first_frame_is_drawn_then_idle_ticks_are_not() {
        let mut g = RedrawGate::new();
        assert!(g.take(), "the first frame must be painted");
        for _ in 0..100 {
            g.on_replies(0);
            assert!(!g.take(), "an idle tick must not redraw");
        }
    }

    #[test]
    fn input_redraws_exactly_once() {
        let mut g = RedrawGate::new();
        g.take();
        g.on_event(&key(KeyEventKind::Press));
        assert!(g.take());
        assert!(!g.take());
        g.on_event(&mouse(MouseEventKind::Down(MouseButton::Left)));
        assert!(g.take());
        g.on_event(&mouse(MouseEventKind::ScrollDown));
        assert!(g.take());
        g.on_event(&Event::Resize(80, 24));
        assert!(g.take());
    }

    #[test]
    fn invisible_events_do_not_redraw() {
        let mut g = RedrawGate::new();
        g.take();
        g.on_event(&key(KeyEventKind::Release));
        g.on_event(&mouse(MouseEventKind::Moved));
        g.on_event(&Event::FocusGained);
        assert!(!g.take());
    }

    #[test]
    fn a_drained_reply_redraws() {
        let mut g = RedrawGate::new();
        g.take();
        g.on_replies(2);
        assert!(g.take());
        assert!(!g.take());
    }

    #[test]
    fn a_visible_timer_redraws_when_it_marks() {
        let mut g = RedrawGate::new();
        g.take();
        g.mark();
        assert!(g.take());
        assert!(!g.take());
    }
}
