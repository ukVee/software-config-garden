//! The fleet-member identity seam — `spec-growlight-queue` §6 "Identity" (and
//! `spec-growlight-grants` §8, which reuses it).
//!
//! growlightd writes `SOFTFIG_MEMBER=<agent>` into the `env` of the softfig-mcp
//! server entry in every member's generated MCP config — claude's `mcp.json`
//! `env`, opencode's `mcp.servers.softfig-mcp.environment` — and softfig-mcp
//! reads it from its own process env once, at startup. The identity therefore
//! comes from the launch env, **never from a tool argument**, so a model cannot
//! name itself a member it isn't.
//!
//! The writer and the reader share [`MEMBER_ENV`] and [`is_safe_member_id`] from
//! here, so the key both sides spell and the ids both sides accept cannot drift.
//!
//! What this does NOT guard: a member's own shell can launch softfig-mcp (or the
//! `softfig` CLI) with any env. That is the §6.7 honest gap, closed by grants
//! step 4, not by this seam.

use std::ffi::OsStr;
use std::fmt;

/// The env var carrying the member id into softfig-mcp.
pub const MEMBER_ENV: &str = "SOFTFIG_MEMBER";

/// Whether `id` can name a member: a non-empty single path component (it names
/// the member's runtime dir `agents/<id>/`), so not `.`/`..` and no `/`, `\` or
/// NUL. growlightd refuses to generate a member config for any other id, and
/// softfig-mcp refuses to serve one.
pub fn is_safe_member_id(id: &str) -> bool {
    !(id.is_empty() || id == "." || id == ".." || id.contains(['/', '\\', '\0']))
}

/// Who a softfig-mcp process serves, as its launch env declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberIdentity {
    /// No [`MEMBER_ENV`]: a human-directed or semi-auto session. Every legacy
    /// verb serves it exactly as before.
    NotAMember,
    /// A fleet member growlightd spawned, by its roster id.
    Member(String),
    /// [`MEMBER_ENV`] is set but cannot name a member (empty, not UTF-8, or not
    /// a safe id). Fail closed: never treated as [`NotAMember`](Self::NotAMember),
    /// because a garbled member must not inherit a human's reach.
    Invalid(String),
}

impl MemberIdentity {
    /// Classify the raw value of [`MEMBER_ENV`] (`None` = unset).
    pub fn from_env_value(value: Option<&OsStr>) -> Self {
        let Some(raw) = value else {
            return Self::NotAMember;
        };
        match raw.to_str() {
            Some(id) if is_safe_member_id(id) => Self::Member(id.to_string()),
            Some(id) => Self::Invalid(format!("{MEMBER_ENV}={id:?} is not a safe member id")),
            None => Self::Invalid(format!("{MEMBER_ENV} is not valid UTF-8")),
        }
    }

    /// Read [`MEMBER_ENV`] from this process's env.
    pub fn from_process_env() -> Self {
        Self::from_env_value(std::env::var_os(MEMBER_ENV).as_deref())
    }

    /// The member id, when this is a member.
    pub fn member(&self) -> Option<&str> {
        match self {
            Self::Member(id) => Some(id),
            _ => None,
        }
    }
}

impl fmt::Display for MemberIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAMember => f.write_str("not a fleet member"),
            Self::Member(id) => write!(f, "fleet member {id}"),
            Self::Invalid(why) => write!(f, "invalid member identity: {why}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn unset_is_not_a_member() {
        assert_eq!(MemberIdentity::from_env_value(None), MemberIdentity::NotAMember);
        assert_eq!(MemberIdentity::NotAMember.member(), None);
    }

    #[test]
    fn a_safe_id_is_that_member() {
        let id = MemberIdentity::from_env_value(Some(OsStr::new("oc")));
        assert_eq!(id, MemberIdentity::Member("oc".into()));
        assert_eq!(id.member(), Some("oc"));
    }

    #[test]
    fn a_set_but_unusable_value_is_invalid_never_not_a_member() {
        for bad in ["", ".", "..", "a/b", "../escape", "a\\b"] {
            let id = MemberIdentity::from_env_value(Some(OsStr::new(bad)));
            assert!(matches!(id, MemberIdentity::Invalid(_)), "{bad:?} -> {id:?}");
            assert_eq!(id.member(), None, "{bad:?}");
        }
        let not_utf8 = OsString::from_vec(vec![b'a', 0xff]);
        assert!(matches!(
            MemberIdentity::from_env_value(Some(&not_utf8)),
            MemberIdentity::Invalid(_)
        ));
    }

    #[test]
    fn the_id_rule_matches_what_growlightd_refuses_to_generate() {
        for ok in ["a", "builder", "oc-1", "member.b"] {
            assert!(is_safe_member_id(ok), "{ok:?}");
        }
        for bad in ["", ".", "..", "a/b", "../escape", "x\0y", "a\\b"] {
            assert!(!is_safe_member_id(bad), "{bad:?}");
        }
    }
}
