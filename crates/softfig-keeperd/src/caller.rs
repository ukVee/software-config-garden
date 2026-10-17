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

use std::cell::RefCell;

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
}
