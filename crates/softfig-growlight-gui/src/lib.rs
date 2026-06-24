//! soft-fig growlight GUI — the **view-model** half of the iced app (spec §11).
//!
//! iced's value is its `Subscription` model: tail growlightd's `subscribe` stream
//! and fold each event into an Elm-style state. This crate is everything that
//! holds *without a window*:
//!
//! - [`App`] — the panel state model (fleet status, the per-agent thoughts feed,
//!   the groupchat, the lease/roster, budgets, policy).
//! - [`Message`] + [`update`] — the pure reducer, the tested heart.
//! - [`command`] — the control half: a [`Command`] gesture → the exact
//!   [`WireRequest`] (post via keeperd, control verbs via growlightd) the live
//!   binding sends; plus the optimistic-post path in [`update`]/[`state`].
//! - [`dispatch`] — the live one-shot *send*: route a built [`WireRequest`] to
//!   its daemon socket and put it on the wire via the already-tested
//!   [`softfig_ipc::call_reconnecting`] (the write mirror of [`drive_messages`]).
//! - [`selectors`] — pure derivations (filter/join/order) the panels walk: the
//!   per-agent thoughts window, the roster⋈leases "who holds what", the fleet rows.
//! - [`render`] — text-shaped panel content the deferred `view()` maps to widgets.
//! - [`drive_messages`] — the bridge: run the shared reconnecting subscribe client
//!   ([`softfig_growlightd_client`]) and hand each frame to the runtime as a
//!   [`Message`]. This is the exact body the iced `Subscription` runs.
//!
//! ## What's deferred (§7b live render binding)
//!
//! The literal `iced` dependency, the `Subscription`/`view()`/window, and the
//! on-device visual check are the **live render binding** — deferred to the human
//! per the milestone's pure-core discipline ("the live binding defers to its
//! natural phase behind a default-absent seam"; tests prove the view-model, not
//! pixels). Adding iced is a heavy, unverifiable-in-headless step and is flagged
//! for the merge. When it lands, the iced app is thin: hold an [`App`], call
//! [`update`] from a `Subscription` fed by [`drive_messages`], and render the
//! [`render`] projections.

pub mod command;
pub mod dispatch;
pub mod render;
pub mod selectors;
pub mod state;
pub mod update;

/// The live iced render binding — window, event loop, `Subscription`, `view()`.
/// Gated behind the off-by-default `gui` feature (the heavy, headless-unverifiable
/// §7b piece) so the always-built view-model + reducer + dispatch stay window-free.
#[cfg(feature = "gui")]
pub mod runtime;

pub use command::{Command, Daemon, WireRequest, HUMAN_SENDER};
pub use dispatch::{
    dispatch, load_status, send, socket_for, status_request, ReconnectingTransport, StatusError,
    Transport,
};
pub use selectors::{
    agent_thoughts, agents_with_thoughts, fleet_status_rows, who_holds_what, RosterEntry,
    WhoHoldsWhat,
};
pub use state::{
    strip_sigil, AgentRow, App, Budgets, ChatLine, ConnState, LeaseRow, ThoughtLine, HUMAN_FROM,
    MAX_CHAT, MAX_THOUGHTS,
};
pub use update::{update, Message};

// Re-export the client seams a frontend wires the subscription over, so the GUI
// binary depends on this one crate.
pub use softfig_growlightd_client::{
    run_subscribe, ClientEvent, Connector, ReconnectPolicy, Sleeper, ThreadSleeper, UnixConnector,
};

/// Run the reconnecting subscribe driver, mapping each [`ClientEvent`] to a
/// [`Message`] and handing it to `emit`. This is precisely the body the deferred
/// iced `Subscription` runs (with `emit` pushing into the iced channel) — kept
/// here, pure over its [`Connector`]/[`Sleeper`] seams, so the bridge from the
/// IPC client to the reducer is proven end to end without iced.
pub fn drive_messages(
    connector: &mut impl Connector,
    policy: ReconnectPolicy,
    sleeper: &mut impl Sleeper,
    stop: &dyn Fn() -> bool,
    emit: &mut dyn FnMut(Message),
) {
    run_subscribe(connector, policy, sleeper, stop, &mut |ev| {
        emit(Message::from(ev))
    });
}
