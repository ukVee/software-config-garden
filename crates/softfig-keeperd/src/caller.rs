//! The calling fleet member, for the length of one IPC request
//! (spec-growlight-queue §6.7, queue-v2-scheduling slice 011).
//!
//! A member session's softfig-mcp stamps its `SOFTFIG_MEMBER` identity on
//! every request ([`Request::member`](softfig_ipc::Request::member)); every
//! other client — the CLI, the TUI, growlightd's own calls — sends none.
//! [`server::dispatch`](crate::server) enters a [`Scope`] around the handler,
//! so the member write limits read the caller where the writes happen (the
//! [`WorkTree`](crate::actions::WorkTree) guard) without threading an identity
//! through every verb's signature.
//!
//! The scope is per thread, and keeperd runs each request start to finish on
//! its connection's thread, so it reaches exactly that request's own writes.
//! A write a handler hands to another thread is not a member write here — the
//! same honest gap as a member's shell writing the mount directly (§6.7).
//!
//! The stamp alone would leave the CLI open: `softfig growlight queue …` run
//! from a member's shell sends no stamp (report 118). So keeperd also reads the
//! member from the connection ([`peer_member`]): the peer's pid from
//! `SO_PEERCRED`, its `/proc/<pid>/cgroup`, and the
//! `growlight-agent-<id>-<gen>.scope` it runs in. Both backends keep a member's
//! shell in that scope — claude's tool children and opencode's `--standalone`
//! server are the member's own descendants. [`resolve`] joins the two, and a
//! stamp that disagrees with the scope is refused.

use std::cell::{Cell, RefCell};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use softfig_ipc::member::{cgroup_scope, scope_member};

thread_local! {
    static MEMBER: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// The member the current request runs for, or `None` for a human-directed,
/// semi-auto or daemon request.
pub fn member() -> Option<String> {
    MEMBER.with(|m| m.borrow().clone())
}

/// Run the rest of this request as `member` — `None` for a non-member
/// request. The previous caller comes back when the guard drops, so a nested
/// scope (a test calling `dispatch` twice on one thread) can't leak.
pub fn enter(member: Option<String>) -> Scope {
    let previous = MEMBER.with(|m| m.replace(member));
    Scope { previous }
}

/// The member a request runs for: its stamp if it carries one, else the
/// member whose scope the connection came from. A stamp naming a different
/// member than the scope is refused, so a member can't pass itself off as
/// another. `Err` is the refusal text.
pub fn resolve(stamp: Option<&str>, connection: Option<&str>) -> Result<Option<String>, String> {
    match (stamp, connection) {
        (Some(stamp), Some(scope)) if stamp != scope => Err(format!(
            "request member {stamp:?} disagrees with the connection's scope, which runs member \
             {scope:?} (spec-growlight-queue §6.7)"
        )),
        (stamp, connection) => Ok(stamp.or(connection).map(str::to_string)),
    }
}

/// The member whose scope the process `pid` runs in, read from `/proc`.
pub fn peer_member(pid: u32) -> Option<String> {
    let read = |pid: &str| std::fs::read_to_string(format!("/proc/{pid}/cgroup"));
    connection_member(read(&pid.to_string()), read("self"))
}

/// Logged the first time `/proc` can't be read, and never again.
static UNREADABLE_LOGGED: AtomicBool = AtomicBool::new(false);

/// The member a connection comes from, given the peer's and keeperd's own
/// `/proc/<pid>/cgroup` bodies. The seam [`peer_member`] reads `/proc` through.
///
/// - A peer in keeperd's own scope is not told apart: a member running
///   keeperd's test suite starts daemons inside its scope, and every request
///   those tests send would otherwise run as that member.
/// - When either body can't be read, the caller is a non-member, logged once.
///   Failing closed here would lock the human out of their own daemon.
pub fn connection_member(peer: io::Result<String>, own: io::Result<String>) -> Option<String> {
    let (peer, own) = match (peer, own) {
        (Ok(peer), Ok(own)) => (peer, own),
        (Err(e), _) | (_, Err(e)) => {
            if !UNREADABLE_LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "keeperd: can't read a connection's cgroup ({e}); serving it as a non-member \
                     (logged once)"
                );
            }
            return None;
        }
    };
    let unit = cgroup_scope(&peer)?;
    if cgroup_scope(&own) == Some(unit) {
        return None;
    }
    scope_member(unit).map(str::to_string)
}

/// Restores the caller [`enter`] replaced.
#[derive(Debug)]
#[must_use = "the caller scope ends when this guard drops"]
pub struct Scope {
    previous: Option<String>,
}

impl Drop for Scope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        MEMBER.with(|m| *m.borrow_mut() = previous);
    }
}

thread_local! {
    static STATE_VOUCH: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// The verb that has vouched for this request's queue v2 state writes, if one
/// has. keeperd's typed writer refuses a member's write to a state file
/// ([`WorkTree::check_structured`](crate::actions::WorkTree::check_structured))
/// unless the verb running it held the member's call to §6.7 first and said so
/// with [`vouch_for_state`] — today only `queue_add_entry`, whose found work
/// lands as a new `queue.toml` row. A verb that never vouches can't reach the
/// state files for a member, however it builds its writes (review 054 F8).
pub fn state_vouch() -> Option<&'static str> {
    STATE_VOUCH.with(Cell::get)
}

/// Vouch, until the guard drops, that `verb` has held this request's member
/// to §6.7, so the state rows keeperd renders from its typed fields may land.
/// Call it after the verb's own member checks, never before.
pub fn vouch_for_state(verb: &'static str) -> Vouch {
    Vouch {
        previous: STATE_VOUCH.with(|v| v.replace(Some(verb))),
    }
}

/// Restores the vouch [`vouch_for_state`] replaced.
#[derive(Debug)]
#[must_use = "the vouch ends when this guard drops"]
pub struct Vouch {
    previous: Option<&'static str>,
}

impl Drop for Vouch {
    fn drop(&mut self) {
        STATE_VOUCH.with(|v| v.set(self.previous));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_sets_the_member_and_restores_the_previous_caller() {
        assert_eq!(member(), None);
        {
            let _outer = enter(Some("a".into()));
            assert_eq!(member().as_deref(), Some("a"));
            {
                let _inner = enter(None);
                assert_eq!(member(), None, "a non-member request inside is a non-member");
            }
            assert_eq!(member().as_deref(), Some("a"));
        }
        assert_eq!(member(), None);
    }

    #[test]
    fn the_scope_is_per_thread() {
        let _scope = enter(Some("a".into()));
        let other = std::thread::spawn(member).join().unwrap();
        assert_eq!(other, None, "another thread's writes are not this request's");
    }

    const APP: &str = "0::/user.slice/user-1000.slice/user@1000.service/app.slice";

    fn body(unit: &str) -> io::Result<String> {
        Ok(format!("{APP}/{unit}\n"))
    }

    #[test]
    fn a_connection_from_a_member_scope_is_that_member() {
        let own = body("softfig-keeperd.service");
        assert_eq!(
            connection_member(body("growlight-agent-oc-1-4.scope"), own).as_deref(),
            Some("oc-1")
        );
        let human = body("wayfire.service");
        assert_eq!(connection_member(human, body("softfig-keeperd.service")), None);
    }

    /// A member running keeperd's own suite starts daemons in its scope: their
    /// clients are not that member. A daemon in one member's scope still reads a
    /// client in another's.
    #[test]
    fn a_peer_in_the_daemons_own_scope_is_not_a_member() {
        let scope = "growlight-agent-qa-33.scope";
        assert_eq!(connection_member(body(scope), body(scope)), None);
        assert_eq!(
            connection_member(body("growlight-agent-oc-2.scope"), body(scope)).as_deref(),
            Some("oc")
        );
    }

    #[test]
    fn an_unreadable_proc_serves_a_non_member() {
        let gone = || Err(io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(connection_member(gone(), body("softfig-keeperd.service")), None);
        assert_eq!(connection_member(body("growlight-agent-qa-1.scope"), gone()), None);
    }

    #[test]
    fn a_stamp_must_agree_with_the_scope() {
        assert_eq!(resolve(None, None), Ok(None));
        assert_eq!(resolve(Some("a"), None), Ok(Some("a".into())));
        assert_eq!(resolve(None, Some("qa")), Ok(Some("qa".into())), "an unstamped CLI call");
        assert_eq!(resolve(Some("qa"), Some("qa")), Ok(Some("qa".into())));
        let refused = resolve(Some("other"), Some("qa")).unwrap_err();
        assert!(refused.contains("disagrees"), "{refused}");
    }

    /// The real path, end to end: `SO_PEERCRED` gives the connecting process's
    /// pid, and a client in the test's own scope (a member running this suite
    /// included) reads as no member.
    #[test]
    fn a_client_in_the_daemons_own_process_is_not_a_member() {
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let pid = crate::peer::peer_pid(&ours).unwrap();
        assert_eq!(pid, std::process::id());
        assert_eq!(peer_member(pid), None);
    }
}
