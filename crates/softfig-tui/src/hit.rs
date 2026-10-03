//! Pointer/touch hit-testing: the renderer records *where* every clickable
//! thing is, and a mouse event maps back to the action a keyboard user would
//! have taken.
//!
//! Why record geometry during render instead of reconstructing the layout from
//! state: the panes already compute their split, borders, scroll windows and
//! overlay rects while drawing, so recording there is exact under any resize
//! and stays correct when a new widget is added. A tap can then never drift
//! from what the user sees.
//!
//! Touch path (Surface Go 3, foot, the touch-pointer Wayfire plugin): a tap
//! arrives as a left mouse down, a double-tap as a right click, and a
//! two-finger drag as wheel events. Nothing here is touch-specific beyond that
//! mapping — the same zones serve a mouse, which keeps one code path for both.
//!
//! Security: a [`HitMap`] holds only geometry and the *key* a tap replays. It
//! never carries garden content, paths, or authority — every tap re-enters the
//! existing key handlers, so the daemon-side trust boundary (redaction, CAS,
//! vault refusal) is untouched.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;

/// The primary selection list a tapped row belongs to. One variant per tab /
/// pane that renders a selectable list; the mapping back to the owning model
/// lives in `App` (see `App::select_list`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListId {
    Browse,
    History,
    Vault,
    Peers,
    Backup,
    Deploy,
    Shares,
    Growlight,
    Coordination,
}

/// The action a tap performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    /// Replay this key through the normal key dispatcher (tabs, footer action
    /// chips, overlay confirm/cancel chips, field-focus chips). This is what
    /// gives touch full action parity without a second action vocabulary.
    Key(KeyEvent),
    /// Select `index` in `list`; tapping the already-selected row activates it
    /// (opens a file, expands a directory/milestone, confirms a pairing, …).
    Row { list: ListId, index: usize },
    /// Select `index` in the open region picker; tapping the selected row again
    /// advances (Enter) to the masked reveal prompt.
    RegionRow(usize),
    /// Dismiss the open overlay (help — tap anywhere).
    Dismiss,
    /// The preview/detail pane: mouse-down starts a drag-scroll anchor.
    Preview,
}

/// One recorded clickable region. `rect` is in terminal cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HitZone {
    pub rect: Rect,
    pub hit: Hit,
}

/// The per-frame zone set. Small (a few hundred zones at most) and rebuilt
/// from scratch on every draw; lookup is a reverse linear scan so the most
/// recently recorded — visually topmost — zone wins.
#[derive(Debug, Default)]
pub struct HitMap {
    zones: Vec<HitZone>,
}

impl HitMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.zones.clear();
    }

    pub fn push(&mut self, rect: Rect, hit: Hit) {
        if rect.width > 0 && rect.height > 0 {
            self.zones.push(HitZone { rect, hit });
        }
    }

    /// The zone under a terminal cell, if any. Later zones win (overlays are
    /// recorded after the page they cover).
    pub fn hit_at(&self, column: u16, row: u16) -> Option<Hit> {
        self.zones
            .iter()
            .rev()
            .find(|z| {
                column >= z.rect.x
                    && column < z.rect.x + z.rect.width
                    && row >= z.rect.y
                    && row < z.rect.y + z.rect.height
            })
            .map(|z| z.hit)
    }

    pub fn zones(&self) -> &[HitZone] {
        &self.zones
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

/// The first visible row of a selection list drawn in `height` content rows:
/// minimal scroll that keeps `selected` on screen, measured from offset 0.
///
/// Every list renderer sets `ListState::offset` to this same value before
/// drawing, so the rows the user sees and the rows a tap maps to are computed
/// by one rule (rather than ratatui's internal auto-scroll, which the input
/// side could not read back).
pub fn list_window(len: usize, selected: usize, height: usize) -> usize {
    let h = height.max(1);
    let len = len.max(1);
    let sel = selected.min(len - 1);
    if sel < h {
        0
    } else {
        (sel + 1 - h).min(len - h)
    }
}

/// A key event with no modifiers — the shorthand for the chips the renderer
/// records (`y`, `n`, `Enter`, `Esc`, `1`…).
pub fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_at_finds_the_cell_and_misses_outside() {
        let mut map = HitMap::new();
        map.push(Rect::new(3, 4, 5, 2), Hit::Key(key(KeyCode::Char('a'))));
        assert_eq!(map.hit_at(3, 4), Some(Hit::Key(key(KeyCode::Char('a')))));
        assert_eq!(map.hit_at(7, 5), Some(Hit::Key(key(KeyCode::Char('a')))));
        assert_eq!(map.hit_at(8, 4), None);
        assert_eq!(map.hit_at(3, 6), None);
    }

    #[test]
    fn later_zones_win_so_overlays_beat_the_page() {
        let mut map = HitMap::new();
        map.push(Rect::new(0, 0, 10, 10), Hit::Preview);
        map.push(Rect::new(2, 2, 4, 4), Hit::Dismiss);
        assert_eq!(map.hit_at(3, 3), Some(Hit::Dismiss));
        assert_eq!(map.hit_at(0, 0), Some(Hit::Preview));
    }

    #[test]
    fn zero_sized_zones_are_ignored() {
        let mut map = HitMap::new();
        map.push(Rect::new(0, 0, 0, 5), Hit::Preview);
        map.push(Rect::new(0, 0, 5, 0), Hit::Preview);
        assert!(map.is_empty());
    }

    #[test]
    fn list_window_keeps_the_selection_visible_with_minimal_scroll() {
        // Everything fits: no scroll.
        assert_eq!(list_window(3, 2, 5), 0);
        // Selection below the fold: the window slides just enough.
        assert_eq!(list_window(10, 5, 3), 3);
        assert_eq!(list_window(10, 9, 3), 7);
        // Out-of-range selections clamp to the last row.
        assert_eq!(list_window(10, 99, 3), 7);
        // Degenerate sizes never panic.
        assert_eq!(list_window(0, 0, 0), 0);
        assert_eq!(list_window(0, 0, 4), 0);
    }
}
