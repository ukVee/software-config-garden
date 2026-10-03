//! The M3c in-TUI file editor.
//!
//! A pure, single-buffer line editor plus the save seam. The buffer is a
//! `Vec<String>` (one entry per raw line, `'\n'`-split) with a char-indexed
//! cursor; each open keeps one pristine copy for dirty-check + discard, and
//! keystrokes mutate a single line — the whole file is never cloned per
//! keystroke. Raw/bionic view spans are cached per line ([`crate::bionic`]):
//! a line edit restyles just that line, and only a fence-marker edit re-walks
//! the tail (the rare case).
//!
//! ## Save seam (the one non-wired piece)
//!
//! [`WritePath`] is the seam. The prototype ships [`UnwiredWritePath`] (the
//! app default) and a test-only [`FakeWritePath`]. The locked real
//! implementation is ONE `patch_file` IPC call —
//!
//! ```text
//! patch_file { path, old: <exact read_file content>, new: <buffer>,
//!              expected_version: <read_file.version> }
//! ```
//!
//! — which is daemon-mediated, mount-safe (`WorkTree`), vault-refusing
//! (`load_unprotected`) and whole-file CAS. `replace_file` is NOT the save
//! verb: it skips the vault refusal, so writing a `[sealed:…]` projection
//! through it would re-seal the marker over the secret. See
//! `journal/decisions/decision-tui-file-editor.md`.
//!
//! ## Client-side refusal gate
//!
//! [`Editor::from_read`] refuses editing (read-only viewing still works) when
//! the daemon projection is sealed, carries `[sealed:`/`[encrypted]`, has
//! non-empty `region_ids`, is binary, or is truncated — the last because
//! `read_file` caps at 512 KiB and saving a truncated view would drop the
//! tail. The daemon refuses these targets again on write.

use ratatui::text::Line;

use crate::bionic;

/// Which view of the buffer is shown. Bionic is read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorMode {
    Raw,
    Bionic,
}

/// One pending save handed to a [`WritePath`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorWrite {
    pub path: String,
    pub content: String,
    pub expected_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// No daemon bridge exists in this prototype (the intentional gap).
    Unwired(String),
    /// Whole-file CAS failed (`Conflict` from the daemon) — buffer kept.
    Conflict(String),
    /// The daemon refused a vault-protected target.
    Refused(String),
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveOutcome {
    pub version: Option<String>,
    pub message: String,
}

/// The save seam. A real implementation will bridge to the IPC worker and
/// issue the locked `patch_file` composition documented in the module docs;
/// the prototype's default is [`UnwiredWritePath`].
pub trait WritePath: std::fmt::Debug {
    fn save(&mut self, write: &EditorWrite) -> Result<SaveOutcome, WriteError>;
}

/// The prototype default: save is not wired to the daemon. The UI surfaces
/// the error and keeps the buffer dirty (no edits are lost).
#[derive(Debug, Default)]
pub struct UnwiredWritePath;

impl WritePath for UnwiredWritePath {
    fn save(&mut self, _write: &EditorWrite) -> Result<SaveOutcome, WriteError> {
        Err(WriteError::Unwired(
            "the daemon save bridge is not shipped in this prototype; the locked path is one \
             `patch_file` call (see editor.rs docs)"
                .into(),
        ))
    }
}

/// Test double: records every call and returns a configured result (default:
/// success), so the app's save behavior is provable without a daemon.
#[derive(Debug, Default)]
pub struct FakeWritePath {
    pub calls: Vec<EditorWrite>,
    pub result: Option<Result<SaveOutcome, WriteError>>,
}

impl WritePath for FakeWritePath {
    fn save(&mut self, write: &EditorWrite) -> Result<SaveOutcome, WriteError> {
        self.calls.push(write.clone());
        match &self.result {
            Some(r) => r.clone(),
            None => Ok(SaveOutcome {
                version: Some("fake-v2".into()),
                message: "saved (fake)".into(),
            }),
        }
    }
}

/// A single-file editing session over a `read_file` projection.
#[derive(Debug)]
pub struct Editor {
    pub path: String,
    pub mode: EditorMode,
    pub dirty: bool,
    /// `Some(reason)` = read-only: viewing allowed, editing + saving refused.
    pub read_only: Option<String>,
    /// Whole-file CAS token from `read_file.version`, refreshed after a save.
    pub expected_version: Option<String>,
    /// First visible line (renderer-managed; cursor kept in view on render).
    pub scroll: u16,
    /// Visible content rows from the last render (page math).
    pub viewport: u16,
    ratio: f32,
    lines: Vec<String>,
    pristine: Vec<String>,
    row: usize,
    col: usize,
    raw_cache: Vec<Line<'static>>,
    fence_after: Vec<bool>,
    bionic_cache: Option<Vec<Line<'static>>>,
}

impl Editor {
    /// Build an editor from a daemon `read_file` reply. Applies the
    /// client-side refusal gate; refused files still open (read-only).
    pub fn from_read(
        path: &str,
        content: &str,
        version: Option<String>,
        sealed: bool,
        region_ids: &[String],
    ) -> Editor {
        let lines: Vec<String> = content.split('\n').map(str::to_string).collect();
        let read_only = refusal_reason(sealed, content, region_ids);
        let mut ed = Editor {
            path: path.to_string(),
            mode: EditorMode::Raw,
            dirty: false,
            read_only,
            expected_version: version.filter(|v| !v.is_empty()),
            scroll: 0,
            viewport: 0,
            ratio: bionic::DEFAULT_BOLD_RATIO,
            pristine: lines.clone(),
            lines,
            row: 0,
            col: 0,
            raw_cache: Vec::new(),
            fence_after: Vec::new(),
            bionic_cache: None,
        };
        ed.rebuild_raw();
        ed
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.is_some()
    }

    /// 0-based (row, char-column) cursor.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// 1-based (line, column) for the title/status display.
    pub fn position(&self) -> (usize, usize) {
        (self.row + 1, self.col + 1)
    }

    /// The full buffer as text (only used for save / tests — never per frame).
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// Replace the bionic bold fraction (configurable; CLI default 0.4).
    pub fn set_ratio(&mut self, ratio: f32) {
        self.ratio = ratio;
        self.bionic_cache = None;
    }

    /// The payload the real bridge will send. `old` (the pristine content) is
    /// the caller's concern in v1: it equals the daemon content this editor
    /// opened when the file has not been touched elsewhere.
    pub fn pending_write(&self) -> EditorWrite {
        EditorWrite {
            path: self.path.clone(),
            content: self.text(),
            expected_version: self.expected_version.clone(),
        }
    }

    /// The pristine content as first read (the `patch_file.old` operand).
    pub fn pristine_text(&self) -> String {
        self.pristine.join("\n")
    }

    fn editable(&self) -> bool {
        self.read_only.is_none()
    }

    // ---- views ----

    pub fn toggle_mode(&mut self) {
        self.mode = match self.mode {
            EditorMode::Raw => EditorMode::Bionic,
            EditorMode::Bionic => EditorMode::Raw,
        };
        if self.mode == EditorMode::Bionic && self.bionic_cache.is_none() {
            self.bionic_cache = Some(bionic::render_bionic_lines(&self.lines, self.ratio));
        }
    }

    /// Select a view directly — the touch toggle switch's left/right halves.
    /// Idempotent (unlike [`Self::toggle_mode`]).
    pub fn set_mode(&mut self, mode: EditorMode) {
        if self.mode != mode {
            self.toggle_mode();
        }
    }

    /// Place the caret (a tap): clamped to a real line and a real char column.
    pub fn set_cursor(&mut self, row: usize, col: usize) {
        if self.lines.is_empty() {
            return;
        }
        self.row = row.min(self.lines.len() - 1);
        self.col = col.min(self.lines[self.row].chars().count());
    }

    /// Free-scroll the reading view by `delta` lines (bionic mode), clamped to
    /// the content. Raw mode scrolls by moving the caret instead — the renderer
    /// keeps the caret in view.
    pub fn scroll_by(&mut self, delta: i32) {
        self.set_scroll((self.scroll as i32 + delta).max(0) as u16);
    }

    /// Set the first visible line, clamped to `[0, len - viewport]`.
    pub fn set_scroll(&mut self, offset: u16) {
        let v = self.viewport.max(1) as usize;
        let max = self.lines.len().saturating_sub(v);
        self.scroll = (offset as usize).min(max) as u16;
    }

    /// The styled lines for the active view; the bionic cache is built lazily
    /// on first use (once per toggle — never per frame).
    pub fn doc(&mut self) -> &[Line<'static>] {
        match self.mode {
            EditorMode::Raw => &self.raw_cache,
            EditorMode::Bionic => {
                if self.bionic_cache.is_none() {
                    self.bionic_cache = Some(bionic::render_bionic_lines(&self.lines, self.ratio));
                }
                self.bionic_cache.as_deref().unwrap_or(&[])
            }
        }
    }

    pub fn set_viewport(&mut self, rows: u16) {
        self.viewport = rows;
    }

    /// Keep the cursor row inside the visible window (render calls this).
    pub fn scroll_to_cursor(&mut self) {
        let v = self.viewport.max(1) as usize;
        if self.row < self.scroll as usize {
            self.scroll = self.row as u16;
        } else if self.row >= self.scroll as usize + v {
            self.scroll = (self.row + 1 - v).min(u16::MAX as usize) as u16;
        }
        let max = self.lines.len().saturating_sub(v);
        if self.scroll as usize > max {
            self.scroll = max as u16;
        }
    }

    // ---- editing ----

    pub fn insert_char(&mut self, c: char) {
        if !self.editable() || c == '\n' {
            return;
        }
        let line = &mut self.lines[self.row];
        let byte = char_to_byte(line, self.col);
        line.insert(byte, c);
        self.col += 1;
        self.after_line_edit(self.row);
    }

    pub fn newline(&mut self) {
        if !self.editable() {
            return;
        }
        let line = &mut self.lines[self.row];
        let byte = char_to_byte(line, self.col);
        let rest = line.split_off(byte);
        self.lines.insert(self.row + 1, rest);
        self.row += 1;
        self.col = 0;
        self.structural_change(self.row - 1);
    }

    pub fn backspace(&mut self) {
        if !self.editable() {
            return;
        }
        if self.col > 0 {
            let line = &mut self.lines[self.row];
            let start = char_to_byte(line, self.col - 1);
            let end = char_to_byte(line, self.col);
            line.replace_range(start..end, "");
            self.col -= 1;
            self.after_line_edit(self.row);
        } else if self.row > 0 {
            let cur = self.lines.remove(self.row);
            self.row -= 1;
            self.col = self.lines[self.row].chars().count();
            self.lines[self.row].push_str(&cur);
            self.structural_change(self.row);
        }
    }

    pub fn delete(&mut self) {
        if !self.editable() {
            return;
        }
        let len = self.lines[self.row].chars().count();
        if self.col < len {
            let line = &mut self.lines[self.row];
            let start = char_to_byte(line, self.col);
            let end = char_to_byte(line, self.col + 1);
            line.replace_range(start..end, "");
            self.after_line_edit(self.row);
        } else if self.row + 1 < self.lines.len() {
            let next = self.lines.remove(self.row + 1);
            self.lines[self.row].push_str(&next);
            self.structural_change(self.row);
        }
    }

    // ---- cursor movement ----

    pub fn move_left(&mut self) {
        if self.col > 0 {
            self.col -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.col = self.lines[self.row].chars().count();
        }
    }

    pub fn move_right(&mut self) {
        let len = self.lines[self.row].chars().count();
        if self.col < len {
            self.col += 1;
        } else if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = 0;
        }
    }

    pub fn move_up(&mut self) {
        if self.row > 0 {
            self.row -= 1;
            self.col = self.col.min(self.lines[self.row].chars().count());
        }
    }

    pub fn move_down(&mut self) {
        if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = self.col.min(self.lines[self.row].chars().count());
        }
    }

    pub fn move_home(&mut self) {
        self.col = 0;
    }

    pub fn move_end(&mut self) {
        self.col = self.lines[self.row].chars().count();
    }

    pub fn page_up(&mut self) {
        let step = self.viewport.max(1) as usize;
        self.row = self.row.saturating_sub(step);
        self.col = self.col.min(self.lines[self.row].chars().count());
    }

    pub fn page_down(&mut self) {
        let step = self.viewport.max(1) as usize;
        self.row = (self.row + step).min(self.lines.len().saturating_sub(1));
        self.col = self.col.min(self.lines[self.row].chars().count());
    }

    // ---- outcomes ----

    /// After a successful save: clear dirty, refresh the pristine copy and the
    /// CAS token.
    pub fn mark_saved(&mut self, version: Option<String>) {
        self.dirty = false;
        self.pristine = self.lines.clone();
        if version.is_some() {
            self.expected_version = version;
        }
    }

    /// Revert to the pristine content (discard).
    pub fn discard(&mut self) {
        self.lines = self.pristine.clone();
        self.dirty = false;
        self.bionic_cache = None;
        self.rebuild_raw();
        self.row = self.row.min(self.lines.len().saturating_sub(1));
        self.col = self.col.min(self.lines[self.row].chars().count());
    }

    // ---- caches ----

    fn rebuild_raw(&mut self) {
        self.raw_cache = Vec::with_capacity(self.lines.len());
        self.fence_after = Vec::with_capacity(self.lines.len());
        let mut state = false;
        for line in &self.lines {
            let (styled, after) = bionic::markdown_line(line, state);
            self.raw_cache.push(styled);
            self.fence_after.push(after);
            state = after;
        }
    }

    fn rebuild_raw_from(&mut self, start: usize) {
        if start >= self.lines.len() {
            return;
        }
        let mut state = if start == 0 {
            false
        } else {
            self.fence_after[start - 1]
        };
        for i in start..self.lines.len() {
            let (styled, after) = bionic::markdown_line(&self.lines[i], state);
            self.raw_cache[i] = styled;
            self.fence_after[i] = after;
            state = after;
        }
    }

    /// In-line edit: restyle the edited line, and re-walk the tail only when
    /// that line's fence state changed (the rare, marker-typed case).
    fn after_line_edit(&mut self, row: usize) {
        self.dirty = true;
        self.bionic_cache = None;
        let before = if row == 0 {
            false
        } else {
            self.fence_after[row - 1]
        };
        let (styled, after) = bionic::markdown_line(&self.lines[row], before);
        self.raw_cache[row] = styled;
        let old_after = self.fence_after[row];
        self.fence_after[row] = after;
        if after != old_after {
            self.rebuild_raw_from(row + 1);
        }
    }

    /// Structural edit (line inserted/removed): resize the caches and rebuild
    /// from the affected row.
    fn structural_change(&mut self, row: usize) {
        self.dirty = true;
        self.bionic_cache = None;
        let start = row.min(self.lines.len().saturating_sub(1));
        self.raw_cache.resize(self.lines.len(), Line::default());
        self.fence_after.resize(self.lines.len(), false);
        self.rebuild_raw_from(start);
    }
}

/// The client-side refusal gate. Order matters only for message readability.
fn refusal_reason(sealed: bool, content: &str, region_ids: &[String]) -> Option<String> {
    if sealed {
        return Some("file is sealed ([sealed])".into());
    }
    if !region_ids.is_empty() {
        return Some("file contains sealed <vault> region(s)".into());
    }
    if content.contains("[sealed:") {
        return Some("projected sealed-file placeholder".into());
    }
    if content.contains("[encrypted]") {
        return Some("projected [encrypted] vault region".into());
    }
    if content.starts_with("[binary file:") {
        return Some("binary content (no editor)".into());
    }
    if content.contains("[… truncated]") {
        return Some("projection was truncated; saving could drop the tail".into());
    }
    None
}

fn char_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(content: &str) -> Editor {
        Editor::from_read("notes/test.md", content, Some("v1".into()), false, &[])
    }

    #[test]
    fn insert_backspace_newline_roundtrip() {
        let mut ed = open("hello");
        ed.move_end();
        for c in " world".chars() {
            ed.insert_char(c);
        }
        assert_eq!(ed.text(), "hello world");
        ed.newline();
        ed.insert_char('x');
        assert_eq!(ed.text(), "hello world\nx");
        ed.backspace();
        ed.backspace();
        assert_eq!(ed.text(), "hello world");
        assert_eq!(ed.cursor(), (0, 11));
    }

    #[test]
    fn delete_forward_joins_lines() {
        let mut ed = open("ab\ncd");
        ed.move_home();
        ed.move_down();
        ed.move_home();
        ed.delete(); // remove 'c'
        assert_eq!(ed.text(), "ab\nd");
        ed.move_home();
        ed.move_up();
        ed.move_end();
        ed.delete(); // cursor at end of "ab": join with "d"
        assert_eq!(ed.text(), "abd");
        assert_eq!(ed.cursor(), (0, 2));
    }

    #[test]
    fn cursor_wraps_and_clamps() {
        let mut ed = open("ab\ncdef");
        assert_eq!(ed.cursor(), (0, 0));
        ed.move_left(); // no-op at head
        assert_eq!(ed.cursor(), (0, 0));
        ed.move_end();
        ed.move_right(); // wraps to next line head
        assert_eq!(ed.cursor(), (1, 0));
        ed.move_end(); // col 4
        ed.move_up(); // clamp to len 2
        assert_eq!(ed.cursor(), (0, 2));
        ed.page_down();
        assert_eq!(ed.cursor().0, 1);
    }

    #[test]
    fn unicode_cursor_is_char_indexed() {
        let mut ed = open("é日");
        ed.move_end();
        ed.backspace();
        assert_eq!(ed.text(), "é");
        ed.backspace();
        assert_eq!(ed.text(), "");
    }

    #[test]
    fn dirty_tracks_edits_and_discard_restores() {
        let mut ed = open("# Title\nbody");
        assert!(!ed.dirty);
        ed.insert_char('x');
        assert!(ed.dirty);
        assert_eq!(ed.text(), "x# Title\nbody");
        ed.discard();
        assert!(!ed.dirty);
        assert_eq!(ed.text(), "# Title\nbody");
    }

    #[test]
    fn toggle_builds_bionic_cache_once_and_shows_the_same_text() {
        let mut ed = open("The API is great");
        assert_eq!(ed.mode, EditorMode::Raw);
        let raw_text: String = ed
            .doc()
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect();
        ed.toggle_mode();
        assert_eq!(ed.mode, EditorMode::Bionic);
        let bionic_text: String = ed
            .doc()
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect();
        assert_eq!(raw_text, bionic_text);
        // Toggling back and forth keeps the text identical (cache reuse).
        ed.toggle_mode();
        assert_eq!(ed.mode, EditorMode::Raw);
        ed.toggle_mode();
        assert!(ed.bionic_cache.is_some());
    }

    #[test]
    fn edit_invalidates_the_bionic_cache() {
        let mut ed = open("hello");
        ed.toggle_mode(); // build bionic cache
        assert!(ed.bionic_cache.is_some());
        ed.toggle_mode(); // back to raw, edit
        ed.insert_char('X');
        assert!(ed.bionic_cache.is_none());
    }

    #[test]
    fn fence_edit_rewalks_the_tail() {
        let mut ed = open("a\nb\nc");
        ed.move_end();
        ed.newline(); // cursor at start of the new line 1
        for c in "```".chars() {
            ed.insert_char(c);
        }
        // The opening fence flips every following line into code.
        ed.move_down();
        ed.newline();
        ed.insert_char('x');
        assert!(ed.fence_after.contains(&true));
        let last = ed.doc().last().unwrap();
        assert_eq!(last.spans[0].style.fg, Some(ratatui::style::Color::Yellow));
    }

    #[test]
    fn refusal_gate_covers_every_projection_shape() {
        let cases: Vec<(bool, &str, Vec<String>)> = vec![
            (true, "anything", vec![]),
            (false, "[sealed:secrets/x]", vec![]),
            (false, "a <vault id=\"x\">[encrypted]</vault> b", vec![]),
            (false, "plain", vec!["region".into()]),
            (false, "[binary file: 42 bytes]", vec![]),
            (false, "body\n[… truncated]", vec![]),
        ];
        for (sealed, content, ids) in cases {
            let ed = Editor::from_read("p", content, Some("v".into()), sealed, &ids);
            assert!(
                ed.is_read_only(),
                "must refuse: sealed={sealed} content={content}"
            );
        }
        let ed = Editor::from_read("p", "normal **markdown**", Some("v".into()), false, &[]);
        assert!(!ed.is_read_only());
    }

    #[test]
    fn read_only_edits_are_noops_but_viewing_works() {
        let mut ed = Editor::from_read("p", "[sealed:p]", None, true, &[]);
        ed.insert_char('x');
        ed.newline();
        ed.backspace();
        ed.delete();
        assert_eq!(ed.text(), "[sealed:p]");
        assert!(!ed.dirty);
        ed.toggle_mode();
        assert_eq!(ed.mode, EditorMode::Bionic);
    }

    #[test]
    fn fake_save_records_the_cas_token_and_clears_dirty() {
        let mut ed = open("hi");
        assert!(!ed.dirty);
        ed.insert_char('t');
        let mut fake = FakeWritePath::default();
        let write = ed.pending_write();
        assert_eq!(write.path, "notes/test.md");
        assert_eq!(write.content, "thi");
        assert_eq!(write.expected_version.as_deref(), Some("v1"));
        let out = fake.save(&write).unwrap();
        ed.mark_saved(out.version);
        assert_eq!(fake.calls.len(), 1);
        assert!(!ed.dirty);
        assert_eq!(ed.expected_version.as_deref(), Some("fake-v2"));
    }

    #[test]
    fn unwired_save_keeps_the_buffer_dirty() {
        let mut ed = open("hi");
        ed.insert_char('t');
        let mut unwired = UnwiredWritePath;
        let err = unwired.save(&ed.pending_write()).unwrap_err();
        assert!(matches!(err, WriteError::Unwired(_)));
        assert!(ed.dirty);
        assert_eq!(ed.text(), "thi");
    }

    #[test]
    fn scroll_to_cursor_keeps_the_row_visible() {
        let lines: Vec<String> = (0..100).map(|i| format!("line {i}")).collect();
        let mut ed = open(&lines.join("\n"));
        ed.set_viewport(10);
        for _ in 0..30 {
            ed.move_down();
        }
        ed.scroll_to_cursor();
        assert!(ed.scroll as usize <= ed.row);
        assert!(ed.row < ed.scroll as usize + 10);
        // Clamp at the bottom.
        for _ in 0..100 {
            ed.move_down();
        }
        ed.scroll_to_cursor();
        assert!(ed.scroll as usize + 10 <= ed.line_count().max(10));
    }

    #[test]
    fn cursor_position_is_one_based() {
        let ed = open("a\nbc");
        assert_eq!(ed.position(), (1, 1));
        let mut ed = ed;
        ed.move_end();
        ed.move_down();
        // move_end puts col at 1; move_down clamps to the same col on line 2.
        assert_eq!(ed.position(), (2, 2));
    }

    #[test]
    fn large_buffer_edits_stay_line_local() {
        // 20k lines; a char insert at the top must not disturb other lines'
        // caches (they keep identity by content-equality of rendered text).
        let lines: Vec<String> = (0..20_000).map(|i| format!("line {i}")).collect();
        let mut ed = open(&lines.join("\n"));
        let before = ed.doc()[19_999].clone();
        ed.insert_char('X');
        let after = ed.doc()[19_999].clone();
        assert_eq!(before.spans[0].content, after.spans[0].content);
    }
}
