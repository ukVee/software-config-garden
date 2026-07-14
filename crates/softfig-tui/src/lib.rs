//! soft-fig terminal UI (M3b) — library half.
//!
//! A ratatui frontend over `softfig-keeperd`. The pure state model (tree,
//! forms, command palette, text area) lives here and carries the unit
//! tests; the binary (`src/main.rs`) is the terminal lifecycle + event
//! loop. Browse content arrives via the M3b read-only `list_tree` /
//! `read_file` verbs, which the daemon redacts server-side, so the TUI
//! never receives sealed plaintext.

pub mod app;
pub mod clip;
pub mod command;
pub mod forms;
pub mod growlight_source;
pub mod ipc;
pub mod listpane;
pub mod textarea;
pub mod tree;
pub mod ui;
