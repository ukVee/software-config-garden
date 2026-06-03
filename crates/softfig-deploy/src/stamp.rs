//! The "managed by softfig" stamp for `method = "copy"` dots. A symlink is
//! self-evidently managed (`ls -la` shows the arrow); a copied file is a
//! plain file, so it carries a header comment that lets a re-deploy tell its
//! own output from a hand-edited target.

use std::path::Path;

/// The marker substring a copied target's header carries. Detection looks
/// for this; the full stamp line wraps it in the file's comment syntax.
pub const MANAGED_MARKER: &str = "managed by softfig — edits will be overwritten";

/// A single-line comment leader for the target's extension, or `None` when
/// we don't know a *safe* line-comment syntax (e.g. JSON has none, CSS has
/// no portable single-line comment). `None` means "copy without a stamp".
fn comment_leader(target: &Path) -> Option<&'static str> {
    let ext = target
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let leader = match ext.as_str() {
        "rs" | "c" | "h" | "cpp" | "cc" | "js" | "ts" | "go" | "java" => "//",
        "sh" | "bash" | "zsh" | "fish" | "py" | "rb" | "pl" | "toml" | "yaml" | "yml"
        | "conf" | "cfg" | "ini" | "txt" | "env" | "service" | "target" | "timer"
        | "socket" | "rules" | "gitignore" | "" => "#",
        "lua" | "sql" | "hs" => "--",
        _ => return None,
    };
    Some(leader)
}

/// Detect our stamp in a file's head. Scans the first few lines so a shebang
/// on line 1 (which pushes the stamp to line 2) is still recognized.
pub fn has_managed_stamp(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(512)];
    match std::str::from_utf8(head) {
        Ok(s) => s.lines().take(3).any(|l| l.contains(MANAGED_MARKER)),
        Err(_) => false,
    }
}

/// Compose the exact bytes a `copy` deploy writes to the target: the source
/// with a managed-by stamp prepended (or inserted after a `#!` shebang so it
/// stays valid). Returns `(bytes, stamped)` — `stamped == false` when the
/// target's type has no known comment syntax, in which case the bytes are
/// the source verbatim and the caller should warn.
pub fn compose_copy(target: &Path, source: &[u8], source_rel: &str) -> (Vec<u8>, bool) {
    let Some(leader) = comment_leader(target) else {
        return (source.to_vec(), false);
    };
    let stamp = format!("{leader} {MANAGED_MARKER} (source: config/source/{source_rel})\n");

    // Keep a shebang on line 1: insert the stamp after the first newline.
    if source.starts_with(b"#!") {
        if let Some(nl) = source.iter().position(|&b| b == b'\n') {
            let mut out = Vec::with_capacity(source.len() + stamp.len());
            out.extend_from_slice(&source[..=nl]);
            out.extend_from_slice(stamp.as_bytes());
            out.extend_from_slice(&source[nl + 1..]);
            return (out, true);
        }
    }

    let mut out = Vec::with_capacity(source.len() + stamp.len());
    out.extend_from_slice(stamp.as_bytes());
    out.extend_from_slice(source);
    (out, true)
}
