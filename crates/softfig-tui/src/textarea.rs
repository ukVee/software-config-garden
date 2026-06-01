//! A minimal multi-line text editor for action bodies.
//!
//! Hand-rolled (no external widget dependency) so it stays clippy-clean
//! and dependency-light — the body fields are plain markdown with no
//! syntax features. Cursor and edit ops are tracked in char units.

#[derive(Debug, Clone)]
pub struct TextArea {
    lines: Vec<String>,
    row: usize,
    col: usize,
}

impl Default for TextArea {
    fn default() -> Self {
        Self::new()
    }
}

impl TextArea {
    pub fn new() -> Self {
        Self {
            lines: vec![String::new()],
            row: 0,
            col: 0,
        }
    }

    pub fn from_text(s: &str) -> Self {
        let mut lines: Vec<String> = s.split('\n').map(String::from).collect();
        if lines.is_empty() {
            lines.push(String::new());
        }
        let row = lines.len() - 1;
        let col = lines[row].chars().count();
        Self { lines, row, col }
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    pub fn is_blank(&self) -> bool {
        self.lines.iter().all(|l| l.trim().is_empty())
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Cursor position as (row, col), both 0-based char offsets.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    pub fn insert_char(&mut self, c: char) {
        let line = &mut self.lines[self.row];
        let byte = char_to_byte(line, self.col);
        line.insert(byte, c);
        self.col += 1;
    }

    pub fn newline(&mut self) {
        let line = &mut self.lines[self.row];
        let byte = char_to_byte(line, self.col);
        let rest = line.split_off(byte);
        self.lines.insert(self.row + 1, rest);
        self.row += 1;
        self.col = 0;
    }

    pub fn backspace(&mut self) {
        if self.col > 0 {
            let line = &mut self.lines[self.row];
            let start = char_to_byte(line, self.col - 1);
            let end = char_to_byte(line, self.col);
            line.replace_range(start..end, "");
            self.col -= 1;
        } else if self.row > 0 {
            let cur = self.lines.remove(self.row);
            self.row -= 1;
            self.col = self.lines[self.row].chars().count();
            self.lines[self.row].push_str(&cur);
        }
    }

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

    #[test]
    fn insert_and_text() {
        let mut ta = TextArea::new();
        for c in "hello".chars() {
            ta.insert_char(c);
        }
        ta.newline();
        for c in "world".chars() {
            ta.insert_char(c);
        }
        assert_eq!(ta.text(), "hello\nworld");
        assert_eq!(ta.cursor(), (1, 5));
    }

    #[test]
    fn backspace_joins_lines() {
        let mut ta = TextArea::from_text("ab\ncd");
        // cursor at end of "cd"
        ta.move_left();
        ta.move_left();
        // now at col 0 of row 1
        assert_eq!(ta.cursor(), (1, 0));
        ta.backspace();
        assert_eq!(ta.text(), "abcd");
        assert_eq!(ta.cursor(), (0, 2));
    }

    #[test]
    fn from_text_roundtrip_and_blank() {
        assert!(TextArea::new().is_blank());
        assert!(TextArea::from_text("   \n\t").is_blank());
        let ta = TextArea::from_text("# title\n\nbody");
        assert_eq!(ta.text(), "# title\n\nbody");
        assert!(!ta.is_blank());
        assert_eq!(ta.lines().len(), 3);
    }

    #[test]
    fn unicode_cursor() {
        let mut ta = TextArea::new();
        ta.insert_char('é');
        ta.insert_char('x');
        assert_eq!(ta.text(), "éx");
        ta.backspace();
        ta.backspace();
        assert_eq!(ta.text(), "");
    }
}
