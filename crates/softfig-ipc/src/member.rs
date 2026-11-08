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
//! A member's own shell can launch softfig-mcp (or the `softfig` CLI) with any
//! env, so the env alone can't stop it. keeperd therefore also reads a
//! connection's member from the peer's cgroup: every member session runs in a
//! `growlight-agent-<id>-<gen>.scope` ([`SCOPE_PREFIX`], [`cgroup_scope`],
//! [`scope_member`]), and everything it forks stays there. What stays open is a
//! member's shell writing the mount directly (§6.7), closed by grants step 4.

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

/// The unit-name bounds of a member's transient scope,
/// `growlight-agent-<id>-<gen>.scope`. growlightd names every member session's
/// scope this way and its boot reconcile globs for it, and keeperd reads a
/// connection's member out of it ([`scope_member`]).
pub const SCOPE_PREFIX: &str = "growlight-agent-";
/// See [`SCOPE_PREFIX`].
pub const SCOPE_SUFFIX: &str = ".scope";

/// The member a `growlight-agent-<id>-<gen>.scope` unit runs, or `None` for any
/// other unit. `<id>` may itself hold `-`, so the prefix and the last `-<gen>`
/// are what come off. A roster id is `[a-z0-9-]` (growlightd refuses any
/// other), so what is left is the id exactly.
pub fn scope_member(unit: &str) -> Option<&str> {
    let base = unit.strip_prefix(SCOPE_PREFIX)?.strip_suffix(SCOPE_SUFFIX)?;
    let (id, generation) = base.rsplit_once('-')?;
    let numbered = !generation.is_empty() && generation.bytes().all(|b| b.is_ascii_digit());
    (!id.is_empty() && numbered).then_some(id)
}

/// The member scope unit a `/proc/<pid>/cgroup` body places its process in, or
/// `None` when it runs in no member's scope. The unified (v2) line's path is
/// searched from the leaf up, so a sub-cgroup made under the scope still counts.
pub fn cgroup_scope(cgroup: &str) -> Option<&str> {
    let path = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    path.rsplit('/').find(|unit| scope_member(unit).is_some())
}

/// The queue-shaping verbs that are the human's alone (§6.7). A fleet member is
/// refused each one, by softfig-mcp's gate and by keeperd's.
pub const HUMAN_QUEUE_VERBS: [&str; 3] = ["queue_add_project", "queue_update_entry", "queue_drop"];

/// Why a member is refused a [`HUMAN_QUEUE_VERBS`] verb, in the words both
/// gates use.
pub const HUMAN_QUEUE_VERB_WHY: &str = "a fleet member may add found work with \
    queue_add_entry, and move slices in its own entry; shaping the queue is the human's";

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

    #[test]
    fn a_scope_unit_names_its_member_hyphens_and_all() {
        assert_eq!(scope_member("growlight-agent-qa-33.scope"), Some("qa"));
        assert_eq!(scope_member("growlight-agent-oc-1-7.scope"), Some("oc-1"));
        assert_eq!(scope_member("growlight-agent-two-agents-x-0.scope"), Some("two-agents-x"));
        for not_a_member in [
            "growlight-agent-qa.scope",
            "growlight-agent--3.scope",
            "growlight-agent-qa-.scope",
            "growlight-agent-qa-3x.scope",
            "growlight-agent-qa-3",
            "growlightd.service",
            "growlight-thermal-guard.service",
        ] {
            assert_eq!(scope_member(not_a_member), None, "{not_a_member:?}");
        }
    }

    #[test]
    fn a_cgroup_body_places_its_process_in_a_member_scope_or_none() {
        let base = "0::/user.slice/user-1000.slice/user@1000.service/app.slice";
        let member = format!("{base}/growlight-agent-qa-33.scope\n");
        assert_eq!(cgroup_scope(&member), Some("growlight-agent-qa-33.scope"));
        let nested = format!("{base}/growlight-agent-oc-1-2.scope/build\n");
        assert_eq!(cgroup_scope(&nested), Some("growlight-agent-oc-1-2.scope"));
        let human = format!("{base}/wayfire.service\n");
        assert_eq!(cgroup_scope(&human), None);
        assert_eq!(cgroup_scope("12:pids:/growlight-agent-qa-1.scope\n"), None, "v1 lines are not read");
        assert_eq!(cgroup_scope(""), None);
    }
}
