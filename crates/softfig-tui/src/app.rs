//! Central TUI state + the key→IPC and reply→state glue.
//!
//! Pure-state helpers (the tree model, forms, palette parsing) live in
//! their own modules and carry the unit tests; this module wires them to
//! the worker-thread [`IpcClient`] and the key stream.

use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use serde_json::{json, Value};
use softfig_ipc::{
    LogReply, ReadFileReply, ShowReply, StatusReply, VaultListSealedReply, VaultRevealReply,
};

use crate::clip;
use crate::command::{parse_command, Command};
use crate::forms::{ActionForm, ActionKind};
use crate::ipc::{IpcClient, Reply, Tag};
use crate::tree::TreeModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Browse,
    History,
    Vault,
}

#[derive(Debug)]
pub enum Overlay {
    None,
    Palette(String),
    Unlock { buf: String, error: Option<String> },
    /// Masked master-password prompt for `vault_reveal` against `path`.
    Reveal { path: String, buf: String, error: Option<String> },
    Form(ActionForm),
    Help,
}

/// The result of a successful reveal — the daemon's temp-file path + the
/// re-auth expiry. Never holds the plaintext itself.
#[derive(Debug, Clone)]
pub struct RevealInfo {
    pub path: String,
    pub temp_path: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct HistoryLine {
    pub hash: String,
    pub intent: String,
    pub summary: String,
}

#[derive(Debug)]
pub struct App {
    pub locked: bool,
    pub tip: Option<String>,
    pub garden_root: String,
    pub view: View,
    pub tree: TreeModel,
    pub preview: String,
    pub preview_title: String,
    /// Vertical scroll offset of the preview pane, in wrapped-line units.
    pub preview_scroll: u16,
    /// Visible content rows of the preview pane; written by the renderer so
    /// page/half-page key math and clamping have the live viewport height.
    pub preview_viewport: u16,
    /// Total wrapped line count of the current preview at the last render
    /// width; written by the renderer so scrolling clamps to the real bottom.
    pub preview_total: u16,
    pub history: Vec<HistoryLine>,
    pub history_selected: usize,
    pub vault_globs: Vec<String>,
    pub vault_files: Vec<String>,
    pub vault_selected: usize,
    pub vault_loaded: bool,
    pub reveal: Option<RevealInfo>,
    pub overlay: Overlay,
    pub status: String,
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        App {
            locked: true,
            tip: None,
            garden_root: String::new(),
            view: View::Browse,
            tree: TreeModel::new(),
            preview: String::new(),
            preview_title: "preview".into(),
            preview_scroll: 0,
            preview_viewport: 0,
            preview_total: 0,
            history: Vec::new(),
            history_selected: 0,
            vault_globs: Vec::new(),
            vault_files: Vec::new(),
            vault_selected: 0,
            vault_loaded: false,
            reveal: None,
            overlay: Overlay::None,
            status: "starting…".into(),
            should_quit: false,
        }
    }

    /// First contact: ask the daemon for its state.
    pub fn bootstrap(&mut self, ipc: &mut IpcClient) {
        ipc.send("status", json!({}), Tag::Status);
    }

    // ---- request helpers ----

    fn load_dir(&self, ipc: &mut IpcClient, dir: &str) {
        ipc.send(
            "list_tree",
            json!({ "path": dir }),
            Tag::ListTree { dir: dir.to_string() },
        );
    }

    fn open_file(&self, ipc: &mut IpcClient, path: &str) {
        ipc.send(
            "read_file",
            json!({ "path": path }),
            Tag::ReadFile { path: path.to_string() },
        );
    }

    fn load_history(&self, ipc: &mut IpcClient) {
        ipc.send("log", json!({ "limit": 200 }), Tag::History);
    }

    fn load_vault(&self, ipc: &mut IpcClient) {
        ipc.send("vault_list_sealed", json!({}), Tag::VaultList);
    }

    /// Re-fetch every directory whose children are loaded, so the view
    /// reflects a write that just landed.
    fn refresh_view(&self, ipc: &mut IpcClient) {
        for dir in self.tree.loaded_dirs() {
            self.load_dir(ipc, &dir);
        }
        ipc.send("status", json!({}), Tag::Status);
        if self.view == View::History {
            self.load_history(ipc);
        }
        if self.vault_loaded {
            self.load_vault(ipc);
        }
    }

    // ---- reply handling ----

    pub fn apply_reply(&mut self, reply: Reply, ipc: &mut IpcClient) {
        match reply.tag {
            Tag::Status => match reply.result {
                Ok(v) => {
                    if let Ok(s) = serde_json::from_value::<StatusReply>(v) {
                        let was_locked = self.locked;
                        self.locked = s.state != "unlocked";
                        self.tip = s.tip;
                        self.garden_root = s.garden_root;
                        if !self.locked && (was_locked || !self.tree.is_loaded("")) {
                            self.load_dir(ipc, "");
                        }
                        if self.locked {
                            self.status = "locked — press u to unlock".into();
                        } else if self.status == "starting…" {
                            self.status = "ready".into();
                        }
                    }
                }
                Err((_, m)) => self.status = format!("status failed: {m}"),
            },
            Tag::Unlock => match reply.result {
                Ok(_) => {
                    self.locked = false;
                    self.overlay = Overlay::None;
                    self.status = "unlocked".into();
                    self.load_dir(ipc, "");
                    ipc.send("status", json!({}), Tag::Status);
                }
                Err((_, m)) => {
                    if let Overlay::Unlock { error, .. } = &mut self.overlay {
                        *error = Some(m);
                    } else {
                        self.status = format!("unlock failed: {m}");
                    }
                }
            },
            Tag::ListTree { dir } => match reply.result {
                Ok(v) => {
                    if let Ok(r) =
                        serde_json::from_value::<softfig_ipc::ListTreeReply>(v)
                    {
                        self.tree.set_children(&dir, r.entries);
                        self.tree.clamp_selection();
                    }
                }
                Err((_, m)) => self.status = format!("list_tree {dir}: {m}"),
            },
            Tag::ReadFile { path } => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<ReadFileReply>(v) {
                        self.preview = r.content;
                        self.preview_title = if r.sealed {
                            format!("{path}  [sealed]")
                        } else {
                            path
                        };
                        self.preview_scroll = 0;
                    }
                }
                Err((_, m)) => self.status = format!("read_file {path}: {m}"),
            },
            Tag::History => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<LogReply>(v) {
                        self.history = r
                            .commits
                            .into_iter()
                            .map(|c| HistoryLine {
                                hash: c.hash,
                                intent: c.intent,
                                summary: c.summary,
                            })
                            .collect();
                        if self.history_selected >= self.history.len() {
                            self.history_selected = self.history.len().saturating_sub(1);
                        }
                    }
                }
                Err((_, m)) => self.status = format!("log: {m}"),
            },
            Tag::Show => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<ShowReply>(v) {
                        self.preview = format_commit(&r);
                        self.preview_title = format!("commit {}", short_hash(&r.commit.hash));
                        self.preview_scroll = 0;
                    }
                }
                Err((_, m)) => self.status = format!("show: {m}"),
            },
            Tag::Action { title } => match reply.result {
                Ok(v) => {
                    self.status = format!("{title}: {}", summarize_action(&v));
                    self.overlay = Overlay::None;
                    self.refresh_view(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("{title} failed ({kind:?}): {m}");
                    if let Overlay::Form(f) = &mut self.overlay {
                        f.error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::VaultList => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<VaultListSealedReply>(v) {
                        self.vault_globs = r.globs;
                        self.vault_files = r.matching_files;
                        self.vault_loaded = true;
                        if self.vault_selected >= self.vault_files.len() {
                            self.vault_selected = self.vault_files.len().saturating_sub(1);
                        }
                    }
                }
                Err((_, m)) => self.status = format!("vault list: {m}"),
            },
            Tag::Reveal { path } => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<VaultRevealReply>(v) {
                        self.status = format!(
                            "revealed {path} → {} · press c to copy",
                            r.temp_path
                        );
                        self.reveal = Some(RevealInfo {
                            path,
                            temp_path: r.temp_path,
                            expires_at: r.expires_at,
                        });
                        self.overlay = Overlay::None;
                    }
                }
                Err((kind, m)) => {
                    let msg = format!("reveal {path} failed ({kind:?}): {m}");
                    if let Overlay::Reveal { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
        }
    }

    // ---- key handling ----

    pub fn handle_key(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        match &mut self.overlay {
            Overlay::None => self.handle_key_main(key, ipc),
            Overlay::Palette(_) => self.handle_key_palette(key, ipc),
            Overlay::Unlock { .. } => self.handle_key_unlock(key, ipc),
            Overlay::Reveal { .. } => self.handle_key_reveal(key, ipc),
            Overlay::Form(_) => self.handle_key_form(key, ipc),
            Overlay::Help => {
                self.overlay = Overlay::None;
            }
        }
    }

    fn handle_key_main(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        // Vim-style preview scrolling on the Ctrl chord, kept off the bare
        // h/j/k/l keys so list navigation is untouched. Half/full page sizes
        // come from the viewport the renderer recorded last frame.
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            let half = (self.preview_viewport / 2).max(1) as i32;
            let full = self.preview_viewport.max(1) as i32;
            match key.code {
                KeyCode::Char('e') => return self.scroll_preview(1),
                KeyCode::Char('y') => return self.scroll_preview(-1),
                KeyCode::Char('d') => return self.scroll_preview(half),
                KeyCode::Char('u') => return self.scroll_preview(-half),
                KeyCode::Char('f') => return self.scroll_preview(full),
                KeyCode::Char('b') => return self.scroll_preview(-full),
                _ => {}
            }
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.overlay = Overlay::Help,
            KeyCode::Char(':') => self.overlay = Overlay::Palette(String::new()),
            KeyCode::Char('u') if self.locked => {
                self.overlay = Overlay::Unlock {
                    buf: String::new(),
                    error: None,
                };
            }
            KeyCode::Char('1') => self.view = View::Browse,
            KeyCode::Char('2') => {
                self.view = View::History;
                if self.history.is_empty() && !self.locked {
                    self.load_history(ipc);
                }
            }
            KeyCode::Char('3') => {
                self.view = View::Vault;
                if !self.vault_loaded && !self.locked {
                    self.load_vault(ipc);
                }
            }
            KeyCode::Char('r') if !self.locked => self.refresh_view(ipc),
            _ if self.locked => {}
            KeyCode::Char('x') => self.start_reveal(ipc),
            KeyCode::Char('c') => self.copy_reveal(),
            KeyCode::Up | KeyCode::Char('k') => self.nav_up(),
            KeyCode::Down | KeyCode::Char('j') => self.nav_down(ipc),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.activate(ipc),
            KeyCode::Left | KeyCode::Char('h') => self.collapse_selected(),
            KeyCode::PageDown => self.scroll_preview(self.preview_viewport.max(1) as i32),
            KeyCode::PageUp => self.scroll_preview(-(self.preview_viewport.max(1) as i32)),
            KeyCode::Char('g') => self.preview_to_top(),
            KeyCode::Char('G') => self.preview_to_bottom(),
            _ => {}
        }
    }

    /// Wheel events scroll the preview pane, three lines per notch.
    pub fn handle_mouse(&mut self, ev: MouseEvent, _ipc: &mut IpcClient) {
        match ev.kind {
            MouseEventKind::ScrollDown => self.scroll_preview(3),
            MouseEventKind::ScrollUp => self.scroll_preview(-3),
            _ => {}
        }
    }

    /// Largest valid scroll offset: enough to bring the last wrapped line to
    /// the bottom of the viewport, never past it.
    fn preview_max_scroll(&self) -> u16 {
        self.preview_total.saturating_sub(self.preview_viewport)
    }

    /// Move the preview offset by `delta` lines (negative = up), clamped to
    /// `[0, preview_max_scroll]`.
    fn scroll_preview(&mut self, delta: i32) {
        let max = self.preview_max_scroll() as i32;
        let next = (self.preview_scroll as i32 + delta).clamp(0, max);
        self.preview_scroll = next as u16;
    }

    fn preview_to_top(&mut self) {
        self.preview_scroll = 0;
    }

    fn preview_to_bottom(&mut self) {
        self.preview_scroll = self.preview_max_scroll();
    }

    fn nav_up(&mut self) {
        match self.view {
            View::Browse => self.tree.move_up(),
            View::History => {
                self.history_selected = self.history_selected.saturating_sub(1);
            }
            View::Vault => {
                self.vault_selected = self.vault_selected.saturating_sub(1);
            }
        }
    }

    fn nav_down(&mut self, _ipc: &mut IpcClient) {
        match self.view {
            View::Browse => self.tree.move_down(),
            View::History => {
                if self.history_selected + 1 < self.history.len() {
                    self.history_selected += 1;
                }
            }
            View::Vault => {
                if self.vault_selected + 1 < self.vault_files.len() {
                    self.vault_selected += 1;
                }
            }
        }
    }

    fn activate(&mut self, ipc: &mut IpcClient) {
        match self.view {
            View::Browse => {
                let Some(row) = self.tree.selected_row() else {
                    return;
                };
                if row.is_dir {
                    if self.tree.is_expanded(&row.path) {
                        self.tree.collapse(&row.path);
                    } else {
                        self.tree.expand(&row.path);
                        if !self.tree.is_loaded(&row.path) {
                            self.load_dir(ipc, &row.path);
                        }
                    }
                    self.tree.clamp_selection();
                } else {
                    self.open_file(ipc, &row.path);
                }
            }
            View::History => {
                if let Some(h) = self.history.get(self.history_selected) {
                    ipc.send("show", json!({ "hash": h.hash }), Tag::Show);
                }
            }
            View::Vault => self.start_reveal(ipc),
        }
    }

    fn collapse_selected(&mut self) {
        if self.view != View::Browse {
            return;
        }
        if let Some(row) = self.tree.selected_row() {
            if row.is_dir && self.tree.is_expanded(&row.path) {
                self.tree.collapse(&row.path);
                self.tree.clamp_selection();
            }
        }
    }

    fn handle_key_palette(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::Palette(buf) = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Enter => {
                let cmd = parse_command(buf);
                self.overlay = Overlay::None;
                self.run_command(cmd, ipc);
            }
            _ => {}
        }
    }

    fn run_command(&mut self, cmd: Command, ipc: &mut IpcClient) {
        match cmd {
            Command::Browse => self.view = View::Browse,
            Command::History => {
                self.view = View::History;
                if !self.locked {
                    self.load_history(ipc);
                }
            }
            Command::Vault => {
                self.view = View::Vault;
                if !self.locked {
                    self.load_vault(ipc);
                }
            }
            Command::Reveal => self.start_reveal(ipc),
            Command::Reload if !self.locked => self.refresh_view(ipc),
            Command::Reload => {}
            Command::Unlock => {
                if self.locked {
                    self.overlay = Overlay::Unlock {
                        buf: String::new(),
                        error: None,
                    };
                }
            }
            Command::Quit => self.should_quit = true,
            Command::Help => self.overlay = Overlay::Help,
            Command::Action(kind) => self.open_form(kind),
            Command::Unknown(s) => self.status = format!("unknown command: {s}"),
        }
    }

    fn open_form(&mut self, kind: ActionKind) {
        if self.locked {
            self.status = "locked — unlock before running actions".into();
            return;
        }
        self.overlay = Overlay::Form(ActionForm::for_kind(kind));
    }

    fn handle_key_unlock(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::Unlock { buf, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Enter => {
                let pass = buf.clone();
                ipc.send("unlock", json!({ "passphrase": pass }), Tag::Unlock);
                self.status = "unlocking…".into();
            }
            _ => {}
        }
    }

    /// Open the masked reveal prompt for the currently-selected sealed file.
    fn start_reveal(&mut self, _ipc: &mut IpcClient) {
        if self.locked {
            self.status = "locked — unlock before revealing".into();
            return;
        }
        let target = match self.view {
            View::Vault => self.vault_files.get(self.vault_selected).cloned(),
            View::Browse => self
                .tree
                .selected_row()
                .filter(|r| !r.is_dir)
                .map(|r| r.path.clone()),
            View::History => None,
        };
        match target {
            Some(path) => {
                self.overlay = Overlay::Reveal {
                    path,
                    buf: String::new(),
                    error: None,
                }
            }
            None => self.status = "select a sealed file to reveal".into(),
        }
    }

    fn handle_key_reveal(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::Reveal { path, buf, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Enter => {
                let path = path.clone();
                let pass = buf.clone();
                ipc.send(
                    "vault_reveal",
                    json!({ "path": path, "master_password": pass }),
                    Tag::Reveal { path: path.clone() },
                );
                self.status = format!("revealing {path}…");
            }
            _ => {}
        }
    }

    /// Copy the last reveal's plaintext into the Wayland clipboard. The
    /// bytes flow from the daemon's 0600 temp file straight into `wl-copy`'s
    /// stdin — they never enter this process's memory.
    fn copy_reveal(&mut self) {
        let Some(info) = self.reveal.clone() else {
            self.status = "nothing to copy — reveal a secret first".into();
            return;
        };
        if !clip::clipboard_available() {
            self.status =
                format!("no clipboard tool (wl-copy) — temp file at {}", info.temp_path);
            return;
        }
        self.status = match clip::copy_file_to_clipboard(Path::new(&info.temp_path)) {
            Ok(()) => format!("copied {} to clipboard", info.path),
            Err(e) => format!("copy failed: {e} — temp file at {}", info.temp_path),
        };
    }

    fn handle_key_form(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        // Ctrl-S submits regardless of focused field.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.submit_form(ipc);
            return;
        }
        let Overlay::Form(form) = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Tab | KeyCode::Down => form.focus_next(),
            KeyCode::BackTab | KeyCode::Up => form.focus_prev(),
            KeyCode::Enter => form.enter(),
            KeyCode::Backspace => form.backspace(),
            KeyCode::Char(c) => form.input_char(c),
            _ => {}
        }
    }

    fn submit_form(&mut self, ipc: &mut IpcClient) {
        let Overlay::Form(form) = &mut self.overlay else {
            return;
        };
        match form.to_request() {
            Ok((op, args)) => {
                let title = form.kind.title().to_string();
                form.error = None;
                self.status = format!("{title}…");
                ipc.send(op, args, Tag::Action { title });
            }
            Err(e) => form.error = Some(e),
        }
    }
}

fn short_hash(h: &str) -> String {
    h.chars().take(10).collect()
}

fn summarize_action(v: &Value) -> String {
    // Vault seal: report how many tracked files were newly Layer-B-sealed.
    if let Some(sealed) = v.get("newly_sealed").and_then(|x| x.as_array()) {
        return format!("sealed {} file(s)", sealed.len());
    }
    // Vault unseal: whether the pattern was actually present.
    if let Some(removed) = v.get("removed").and_then(|x| x.as_bool()) {
        return if removed {
            "removed".into()
        } else {
            "pattern not present".into()
        };
    }
    for key in ["path", "to", "hash"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            return format!("{key}={s}");
        }
    }
    "ok".into()
}

fn format_commit(r: &ShowReply) -> String {
    let c = &r.commit;
    let mut out = String::new();
    out.push_str(&format!("hash:    {}\n", c.hash));
    if let Some(p) = &c.parent {
        out.push_str(&format!("parent:  {p}\n"));
    }
    out.push_str(&format!("intent:  {}\n", c.intent));
    out.push_str(&format!("author:  {}\n", c.author_device));
    out.push_str(&format!("payload: {}\n\n", c.payload));
    out.push_str("root tree:\n");
    for e in &r.root_tree {
        out.push_str(&format!("  {:<4} {}\n", e.kind, e.name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_blocks_actions_and_nav() {
        let mut app = App::new();
        assert!(app.locked);
        app.open_form(ActionKind::LogDecision);
        // open_form refuses while locked → still no overlay
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn unlocked_opens_form() {
        let mut app = App::new();
        app.locked = false;
        app.open_form(ActionKind::Archive);
        assert!(matches!(app.overlay, Overlay::Form(_)));
    }

    #[test]
    fn summarize_prefers_path() {
        assert_eq!(
            summarize_action(&json!({"path":"journal/x.md","hash":"abc"})),
            "path=journal/x.md"
        );
        assert_eq!(summarize_action(&json!({"hash":"abc"})), "hash=abc");
        assert_eq!(summarize_action(&json!({})), "ok");
    }

    #[test]
    fn summarize_vault_replies() {
        assert_eq!(
            summarize_action(&json!({"newly_sealed":["a","b"],"schema_commit":"x"})),
            "sealed 2 file(s)"
        );
        assert_eq!(summarize_action(&json!({"removed":true})), "removed");
        assert_eq!(
            summarize_action(&json!({"removed":false})),
            "pattern not present"
        );
    }

    fn dummy_ipc() -> IpcClient {
        // The worker thread idles until a send; the VaultList / Reveal Ok
        // paths issue none, so a bogus socket path is never connected.
        IpcClient::spawn(std::path::PathBuf::from("/nonexistent/softfig.sock"))
    }

    #[test]
    fn vault_list_populates_view() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::VaultList,
                result: Ok(json!({
                    "globs": ["secrets/**"],
                    "matching_files": ["secrets/api-keys.toml", "secrets/coords.txt"],
                })),
            },
            &mut ipc,
        );
        assert!(app.vault_loaded);
        assert_eq!(app.vault_globs, vec!["secrets/**".to_string()]);
        assert_eq!(app.vault_files.len(), 2);
    }

    #[test]
    fn reveal_reply_records_path_not_plaintext() {
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::Reveal {
            path: "secrets/api-keys.toml".into(),
            buf: "pw".into(),
            error: None,
        };
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 2,
                tag: Tag::Reveal {
                    path: "secrets/api-keys.toml".into(),
                },
                result: Ok(json!({
                    "temp_path": "/run/user/1000/softfig-reveal-abc.toml",
                    "expires_at": 1000,
                })),
            },
            &mut ipc,
        );
        let info = app.reveal.expect("reveal recorded");
        assert_eq!(info.temp_path, "/run/user/1000/softfig-reveal-abc.toml");
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("press c to copy"));
    }

    #[test]
    fn preview_scroll_clamps_and_pages() {
        let mut app = App::new();
        // Renderer-supplied geometry: 10 visible rows over 50 wrapped lines.
        app.preview_viewport = 10;
        app.preview_total = 50;
        assert_eq!(app.preview_scroll, 0);

        app.scroll_preview(5);
        assert_eq!(app.preview_scroll, 5);
        app.scroll_preview(-100); // clamp at the top
        assert_eq!(app.preview_scroll, 0);

        app.preview_to_bottom();
        assert_eq!(app.preview_scroll, 40, "max = total - viewport");
        app.scroll_preview(100); // never past the bottom
        assert_eq!(app.preview_scroll, 40);
        app.preview_to_top();
        assert_eq!(app.preview_scroll, 0);
    }

    #[test]
    fn short_preview_does_not_scroll() {
        let mut app = App::new();
        // Content shorter than the viewport → max scroll is zero.
        app.preview_viewport = 20;
        app.preview_total = 5;
        app.scroll_preview(10);
        assert_eq!(app.preview_scroll, 0);
        app.preview_to_bottom();
        assert_eq!(app.preview_scroll, 0);
    }

    #[test]
    fn preview_scroll_resets_on_new_file() {
        let mut app = App::new();
        app.locked = false;
        app.preview_viewport = 10;
        app.preview_total = 50;
        app.preview_scroll = 20;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::ReadFile {
                    path: "meta/CLAUDE.md".into(),
                },
                result: Ok(json!({
                    "path": "meta/CLAUDE.md",
                    "content": "fresh file",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert_eq!(app.preview, "fresh file");
        assert_eq!(app.preview_scroll, 0, "opening a new file jumps to the top");
    }

    #[test]
    fn mouse_wheel_scrolls_preview() {
        let mut app = App::new();
        app.preview_viewport = 5;
        app.preview_total = 100;
        let mut ipc = dummy_ipc();
        let wheel = |kind| MouseEvent {
            kind,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        };
        app.handle_mouse(wheel(MouseEventKind::ScrollDown), &mut ipc);
        assert_eq!(app.preview_scroll, 3);
        app.handle_mouse(wheel(MouseEventKind::ScrollDown), &mut ipc);
        assert_eq!(app.preview_scroll, 6);
        app.handle_mouse(wheel(MouseEventKind::ScrollUp), &mut ipc);
        assert_eq!(app.preview_scroll, 3);
    }

    #[test]
    fn start_reveal_needs_a_selected_file() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Vault;
        let mut ipc = dummy_ipc();
        // No sealed files loaded → no overlay, a hint instead.
        app.start_reveal(&mut ipc);
        assert!(matches!(app.overlay, Overlay::None));

        app.vault_files = vec!["secrets/api-keys.toml".into()];
        app.start_reveal(&mut ipc);
        match &app.overlay {
            Overlay::Reveal { path, .. } => assert_eq!(path, "secrets/api-keys.toml"),
            other => panic!("expected reveal overlay, got {other:?}"),
        }
    }
}
