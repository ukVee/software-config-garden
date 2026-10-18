//! Terminal control-sequence stripping (spec remote-runner §6 Logs, §12
//! "Terminal or prompt injection via logs").
//!
//! Job logs are **untrusted bytes**: a job can print ANSI escapes, OSC
//! (operating-system-command) sequences, and raw C0 controls that would inject
//! into the requester's terminal or agent context. This helper strips them so a
//! log can be rendered safely. It keeps the printable characters and the three
//! whitespace controls a log legitimately uses (`\t`, `\n`, `\r`); everything
//! else — CSI (`ESC [`), OSC (`ESC ]`), other `ESC` sequences, and the C0/C1
//! control range — is dropped. It is a byte-level state machine: no regex, no
//! allocation beyond the returned buffer, and it never panics on malformed or
//! truncated input.

/// Whether a byte is a C1 control (0x80–0x9F) or a C0 control (0x00–0x1F, 0x7F).
#[inline]
fn is_control(b: u8) -> bool {
    b < 0x20 || b == 0x7F || (0x80..=0x9F).contains(&b)
}

/// Strip terminal control sequences from log bytes, returning a clean byte
/// vector. `\t`, `\n` and `\r` are preserved; every other control byte and every
/// `ESC`-introduced sequence (CSI `ESC [` / `ESC` intermediate / OSC `ESC ]`) is
/// removed. Never panics on truncated or malformed input.
pub fn strip_control_sequences(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    let n = input.len();
    while i < n {
        let b = input[i];
        match b {
            b'\t' | b'\n' | b'\r' => {
                out.push(b);
                i += 1;
            }
            // ESC: an escape sequence. Consume it wholesale (matched before the
            // control guard, since ESC itself is a C0 control).
            0x1B => {
                i += 1;
                // CSI: ESC [ ... final byte 0x40–0x7E.
                if i < n && input[i] == b'[' {
                    i += 1;
                    while i < n && !(0x40..=0x7E).contains(&input[i]) {
                        i += 1;
                    }
                    if i < n {
                        i += 1; // the final byte
                    }
                } else if i < n && input[i] == b']' {
                    // OSC: ESC ] ... (BEL) or ESC ] ... ESC \ .
                    i += 1;
                    while i < n {
                        let c = input[i];
                        if c == 0x07 {
                            i += 1;
                            break;
                        }
                        if c == 0x1B {
                            // possible ST: ESC \
                            if i + 1 < n && input[i + 1] == b'\\' {
                                i += 2;
                            } else {
                                i += 1;
                            }
                            break;
                        }
                        i += 1;
                    }
                } else {
                    // Other escape: ESC (intermediates 0x20–0x2F)* final 0x30–0x7E.
                    while i < n && (0x20..=0x2F).contains(&input[i]) {
                        i += 1;
                    }
                    if i < n && (0x30..=0x7E).contains(&input[i]) {
                        i += 1;
                    }
                }
            }
            // C0/C1 control or DEL — drop (except the kept whitespace above,
            // which is already matched).
            _ if is_control(b) => {
                i += 1;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_plain_text_and_whitespace() {
        let s = b"cargo test\n  ok\ttab\r\n";
        assert_eq!(strip_control_sequences(s), s.to_vec());
    }

    #[test]
    fn strips_csi_color_codes() {
        let s = b"\x1b[31mred\x1b[0m plain";
        assert_eq!(strip_control_sequences(s), b"red plain");
    }

    #[test]
    fn strips_osc_title_and_bell() {
        let s = b"\x1b]0;title\x07hello";
        assert_eq!(strip_control_sequences(s), b"hello");
    }

    #[test]
    fn strips_osc_with_st_terminator() {
        let s = b"a\x1b]8;;http://x\x1b\\b";
        assert_eq!(strip_control_sequences(s), b"ab");
    }

    #[test]
    fn strips_other_escapes() {
        // ESC ( B — a common charset designation.
        let s = b"\x1b(Btext";
        assert_eq!(strip_control_sequences(s), b"text");
    }

    #[test]
    fn strips_c0_and_c1_controls() {
        let s = b"a\x01b\x0cc\x7fd\x9be";
        assert_eq!(strip_control_sequences(s), b"abcde");
    }

    #[test]
    fn truncated_sequences_do_not_panic() {
        assert_eq!(strip_control_sequences(b"\x1b"), b"");
        assert_eq!(strip_control_sequences(b"\x1b["), b"");
        assert_eq!(strip_control_sequences(b"\x1b]abc"), b"");
        assert_eq!(strip_control_sequences(b"\x1b]0;x\x1b"), b"");
    }

    #[test]
    fn mixed_stream_is_clean() {
        let s = b"\x1b[1mBuilding\x1b[0m\n\x1b[32m   Compiling softfig\x1b[0m\r\n";
        assert_eq!(
            strip_control_sequences(s),
            b"Building\n   Compiling softfig\r\n"
        );
    }
}
