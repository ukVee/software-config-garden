//! Central TUI state + the key→IPC and reply→state glue.
//!
//! Pure-state helpers (the tree model, forms, palette parsing) live in
//! their own modules and carry the unit tests; this module wires them to
//! the worker-thread [`IpcClient`] and the key stream.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{json, Value};
use softfig_ipc::{LogReply, ReadFileReply, ShowReply, StatusReply};

use crate::command::{parse_command, Command};
use crate::forms::{ActionForm, ActionKind};
use crate::ipc::{IpcClient, Reply, Tag};
use crate::tree::TreeModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Browse,
    History,
}

#[derive(Debug)]
pub enum Overlay {
    None,
    Palette(String),
    Unlock { buf: String, error: Option<String> },
    Form(ActionForm),
    Help,
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
    pub history: Vec<HistoryLine>,
    pub history_selected: usize,
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
            history: Vec::new(),
            history_selected: 0,
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
        }
    }

    // ---- key handling ----

    pub fn handle_key(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        match &mut self.overlay {
            Overlay::None => self.handle_key_main(key, ipc),
            Overlay::Palette(_) => self.handle_key_palette(key, ipc),
            Overlay::Unlock { .. } => self.handle_key_unlock(key, ipc),
            Overlay::Form(_) => self.handle_key_form(key, ipc),
            Overlay::Help => {
                self.overlay = Overlay::None;
            }
        }
    }

    fn handle_key_main(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
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
            KeyCode::Char('r') if !self.locked => self.refresh_view(ipc),
            _ if self.locked => {}
            KeyCode::Up | KeyCode::Char('k') => self.nav_up(),
            KeyCode::Down | KeyCode::Char('j') => self.nav_down(ipc),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.activate(ipc),
            KeyCode::Left | KeyCode::Char('h') => self.collapse_selected(),
            _ => {}
        }
    }

    fn nav_up(&mut self) {
        match self.view {
            View::Browse => self.tree.move_up(),
            View::History => {
                self.history_selected = self.history_selected.saturating_sub(1);
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
}
