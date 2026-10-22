//! The claude-login profile slot naming rules (`claude-login-switcher`).
//!
//! A **slot** names a stored Anthropic OAuth bundle at
//! `~/.claude/credentials.d/<slot>.json` (slice 001). Three places read the
//! name: the `softfig claude-login` CLI (slot create/activate), the fleet
//! config loader (slice 003 — `profile_pool` entries must shape-check), and the
//! growlightd spawn path (which composes a filename from it). They would read
//! the same rules three ways if the validator lived next to only one; here is
//! the shared source.
//!
//! The charset mirrors a conservative single-path-component:
//! `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. It rejects anything a path separator or
//! leading dot would make dangerous (`..`, `/etc/passwd`, `.hidden`), and
//! bounds the length so a slot name never overflows a filesystem's component
//! cap.
//!
//! Pure, no I/O, no `std::env`: a presence check (does
//! `~/.claude/credentials.d/<slot>.json` exist?) is a separate concern the
//! caller runs, so this module stays trivially fuzzable.

use std::fmt;

/// What a bad slot name is, in a form the fleet loader and the CLI can both
/// render without agreeing on prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotNameError {
    /// The empty string or one past 64 bytes.
    BadLength(usize),
    /// First byte is not `[A-Za-z0-9]` — covers the hidden-file / `..` family.
    BadStart,
    /// Some byte is not in `[A-Za-z0-9._-]`.
    BadChar(char),
}

impl fmt::Display for SlotNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlotNameError::BadLength(n) => {
                write!(f, "slot name length must be 1..=64 bytes (got {n})")
            }
            SlotNameError::BadStart => write!(f, "slot name must start with [A-Za-z0-9]"),
            SlotNameError::BadChar(c) => {
                write!(f, "slot name may only contain [A-Za-z0-9._-] (got {c:?})")
            }
        }
    }
}

impl std::error::Error for SlotNameError {}

/// Validate a slot name's shape. `Ok(())` ⇒ the name is safe to use as the
/// stem of `~/.claude/credentials.d/<slot>.json`; see [`SlotNameError`] for
/// what each refusal means.
pub fn validate_slot_name(name: &str) -> Result<(), SlotNameError> {
    let len = name.len();
    if len == 0 || len > 64 {
        return Err(SlotNameError::BadLength(len));
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(SlotNameError::BadStart);
    }
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
            return Err(SlotNameError::BadChar(b as char));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_rejected() {
        assert_eq!(validate_slot_name(""), Err(SlotNameError::BadLength(0)));
    }

    #[test]
    fn too_long_is_rejected() {
        let long = "x".repeat(65);
        assert_eq!(validate_slot_name(&long), Err(SlotNameError::BadLength(65)));
    }

    #[test]
    fn path_separator_is_rejected() {
        assert!(matches!(validate_slot_name("/bad"), Err(SlotNameError::BadStart)));
        assert!(matches!(
            validate_slot_name("sub/dir"),
            Err(SlotNameError::BadChar('/'))
        ));
    }

    #[test]
    fn leading_dot_is_rejected() {
        assert_eq!(validate_slot_name(".."), Err(SlotNameError::BadStart));
        assert_eq!(validate_slot_name(".hidden"), Err(SlotNameError::BadStart));
    }

    #[test]
    fn whitespace_is_rejected() {
        assert!(matches!(
            validate_slot_name("has space"),
            Err(SlotNameError::BadChar(' '))
        ));
        assert!(matches!(
            validate_slot_name("has\nnewline"),
            Err(SlotNameError::BadChar('\n'))
        ));
    }

    #[test]
    fn well_formed_slots_pass() {
        assert!(validate_slot_name("good").is_ok());
        assert!(validate_slot_name("slot1").is_ok());
        assert!(validate_slot_name("my.slot_1-a").is_ok());
    }
}
