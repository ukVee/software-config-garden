//! The claude-login profile slot naming rules (`claude-login-switcher`).
//!
//! A **slot** names one Claude Code config dir in the profile store,
//! `<store>/<slot>/` (slice 006; see [`crate::claude_profiles`]). Three places
//! read the name: the `softfig claude-login` CLI (slot create/activate), the
//! fleet config loader (`profile_pool` entries must shape-check), and the
//! growlightd spawn path (which composes a directory from it). They would read
//! the same rules three ways if the validator lived next to only one; here is
//! the shared source.
//!
//! The charset mirrors a conservative single-path-component:
//! `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. It rejects anything a path separator or
//! leading dot would make dangerous (`..`, `/etc/passwd`, `.hidden`), and
//! bounds the length so a slot name never overflows a filesystem's component
//! cap. A `.lock` suffix is reserved for Claude Code's own lock dirs.
//!
//! Pure, no I/O, no `std::env`: a presence check (does `<store>/<slot>/`
//! exist?) is a separate concern the caller runs, so this module stays
//! trivially fuzzable.

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
    /// Ends in `.lock`: Claude Code's proper-lockfile takes a legacy
    /// `<config dir>.lock` directory beside a slot, which would otherwise read
    /// as a second slot.
    ReservedSuffix,
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
            SlotNameError::ReservedSuffix => {
                write!(f, "slot name may not end in `.lock` (Claude's lock dirs use it)")
            }
        }
    }
}

impl std::error::Error for SlotNameError {}

/// Validate a slot name's shape. `Ok(())` ⇒ the name is safe to use as one
/// path component under the profile store; see [`SlotNameError`] for what
/// each refusal means.
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
    if name.ends_with(".lock") {
        return Err(SlotNameError::ReservedSuffix);
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
    fn lock_suffix_is_rejected() {
        assert_eq!(validate_slot_name("slot1.lock"), Err(SlotNameError::ReservedSuffix));
        assert!(validate_slot_name("lock").is_ok());
        assert!(validate_slot_name("slot1.locked").is_ok());
    }

    #[test]
    fn well_formed_slots_pass() {
        assert!(validate_slot_name("good").is_ok());
        assert!(validate_slot_name("slot1").is_ok());
        assert!(validate_slot_name("my.slot_1-a").is_ok());
    }
}
