//! A small generic master-list selection model shared by the triplet tabs.
//!
//! Several tabs (Vault, Deploy, Growlight, and the flattened Peers/Backup
//! selection lists) previously carried the same three fields —
//! `items: Vec<T>` / `selected: usize` / `loaded: bool` — plus hand-copied
//! nav/clamp arithmetic. `ListPane<T>` factors that triplet into one type.
//! The arithmetic replicates the pre-existing sites exactly (no behavior
//! change): `up` saturates, `down` stops one before the end, `clamp` pins the
//! selection into range, `selected` is a plain `get`.

/// The `items` / `selected` / `loaded` triplet plus its selection arithmetic.
#[derive(Debug, Default)]
pub struct ListPane<T> {
    pub items: Vec<T>,
    pub selected: usize,
    pub loaded: bool,
}

impl<T> ListPane<T> {
    pub fn new() -> Self {
        ListPane {
            items: Vec::new(),
            selected: 0,
            loaded: false,
        }
    }

    /// Move the selection up one, saturating at 0.
    pub fn up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Move the selection down one, stopping one before the end.
    pub fn down(&mut self) {
        if self.selected + 1 < self.items.len() {
            self.selected += 1;
        }
    }

    /// Pin the selection into range after the item list shrinks.
    pub fn clamp(&mut self) {
        if self.selected >= self.items.len() {
            self.selected = self.items.len().saturating_sub(1);
        }
    }

    /// The currently-selected item, if any.
    pub fn selected(&self) -> Option<&T> {
        self.items.get(self.selected)
    }

    /// Store a fresh item list, mark the pane loaded, and clamp the selection.
    pub fn set_items(&mut self, items: Vec<T>) {
        self.items = items;
        self.loaded = true;
        self.clamp();
    }
}
