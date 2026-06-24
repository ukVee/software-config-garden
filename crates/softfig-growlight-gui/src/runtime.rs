//! The live **iced render binding** (spec §11) — the thin layer that turns the
//! window-free view-model into an on-screen `iced` application. Gated behind the
//! off-by-default `gui` feature: this is the heavy, headless-unverifiable §7b
//! piece (a real window, a GPU/software surface, an event loop), so it never
//! enters `cargo check --workspace` and the always-built crate stays window-free.
//!
//! Pure-core discipline ([[spec-growlight-orchestrator]] §12): everything hard is
//! already a proven pure unit elsewhere in this crate, and this module only
//! *instantiates and wires* it — it adds no new logic that isn't trivially
//! visible:
//!
//! - **state** is the existing [`App`] (the tested reducer target), wrapped in a
//!   thin [`GuiState`] so later slices can hang UI-local fields off it;
//! - **update** delegates a wrapped [`Message`] straight to the pure
//!   [`crate::update::update`] reducer, and a control gesture straight to the
//!   tested [`crate::dispatch::send`];
//! - the **subscription** runs the already-tested reconnecting
//!   [`crate::drive_messages`] body on a worker thread and forwards each
//!   [`Message`] into iced's channel — it does **not** re-implement decode or
//!   reconnect;
//! - **boot** seeds the model with the tested [`crate::dispatch::load_status`]
//!   one-shot before the stream takes over.
//!
//! The slice-001 [`view`] is intentionally minimal (a status line + the
//! pause/resume controls — enough to exercise the control-dispatch wiring); the
//! full observe/control/chat panels over the selectors are slice 002.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use iced::futures::{SinkExt, Stream, StreamExt};
use iced::widget::{button, column, row, text};
use iced::{Element, Subscription, Task};

use crate::command::{Command, Daemon};
use crate::dispatch::{load_status, send, socket_for, ReconnectingTransport};
use crate::state::App;
use crate::update::{update as reduce, Message};
use crate::{drive_messages, ReconnectPolicy, ThreadSleeper, UnixConnector};

/// Backpressure buffer between the subscribe worker thread and the iced runtime.
/// The driver also bridges through an *unbounded* channel first, so this only
/// bounds how many decoded messages iced batches per poll.
const STREAM_BUFFER: usize = 256;

/// The iced application state. A thin wrapper over the tested [`App`] view-model
/// so later slices can add UI-local fields (the compose box, the selected agent
/// tab) without touching the reducer.
#[derive(Debug, Default)]
pub struct GuiState {
    /// The pure view-model the reducer folds events into.
    pub app: App,
}

impl GuiState {
    fn new() -> Self {
        Self::default()
    }
}

/// The iced message: a reducer [`Message`] (from the subscription / the boot
/// load), a control gesture to dispatch, or a side-effect completion to drop.
/// `Debug + Clone` is all iced asks of a message.
#[derive(Debug, Clone)]
pub enum GuiMessage {
    /// A view-model [`Message`] to fold into [`GuiState::app`] via the pure
    /// reducer (a subscription frame or the boot `status` reply).
    Reduce(Message),
    /// A control gesture (pause/resume/force-stop/set-policy or a human post) to
    /// turn into a [`crate::command::WireRequest`] and send.
    Control(Command),
    /// A fire-and-forget side effect finished; nothing to fold. The real effect
    /// is observed back on the live stream (the optimistic-UI philosophy already
    /// in the reducer), so dispatch failures are logged, not modelled into state.
    Done,
}

/// Run a blocking closure off the UI thread and resolve to its result as a
/// future — so a one-shot IPC round-trip (which may briefly retry across a daemon
/// `cycle`) never stalls iced's event loop. Executor-agnostic: a short-lived
/// thread hands the result back over a oneshot, so this needs no async runtime of
/// its own.
fn perform_blocking<T, F>(work: F) -> impl Future<Output = T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = iced::futures::channel::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    async move { rx.await.expect("growlight-gui: blocking worker dropped its result") }
}

/// Boot: the empty model plus a one-shot `status` fetch that seeds the roster /
/// policy before the live stream takes over (off the UI thread).
fn boot() -> (GuiState, Task<GuiMessage>) {
    let load = Task::perform(
        perform_blocking(|| load_status(&mut ReconnectingTransport).map_err(|e| e.to_string())),
        |result| match result {
            Ok(msg) => GuiMessage::Reduce(msg),
            Err(e) => {
                eprintln!("growlight-gui: initial status load failed ({e}); the stream will seed the model");
                GuiMessage::Done
            }
        },
    );
    (GuiState::new(), load)
}

/// The reducer adapter: fold a stream/boot message into the pure view-model, or
/// turn a control gesture into a dispatched [`crate::command::WireRequest`]. The
/// iced layer stays thin — the reducer and the send are the tested units.
fn update(state: &mut GuiState, message: GuiMessage) -> Task<GuiMessage> {
    match message {
        GuiMessage::Reduce(msg) => {
            reduce(&mut state.app, msg);
            Task::none()
        }
        GuiMessage::Control(cmd) => match cmd.to_request() {
            Ok(req) => Task::perform(
                perform_blocking(move || send(&req).map(|_| ()).map_err(|e| e.to_string())),
                |result| {
                    if let Err(e) = result {
                        eprintln!("growlight-gui: control dispatch failed: {e}");
                    }
                    GuiMessage::Done
                },
            ),
            Err(e) => {
                eprintln!("growlight-gui: could not build the control request: {e}");
                Task::none()
            }
        },
        GuiMessage::Done => Task::none(),
    }
}

/// Sets the stop flag when dropped, so tearing down the iced subscription (the
/// future is dropped) signals the blocking worker thread to exit at its next I/O
/// boundary. The worker is detached, not joined — a join could otherwise block on
/// a quiet blocking socket read.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// The subscription stream: run the shared reconnecting [`drive_messages`] body
/// on a worker thread and forward each decoded [`Message`] into iced. This is the
/// no-arg `fn` [`Subscription::run`] takes (iced's documented worker pattern — a
/// `fn(&D) -> impl Stream` can't coerce to `run_with`'s HRTB fn pointer); it
/// reuses the tested driver verbatim — no decode/reconnect logic lives here. The
/// socket is always growlightd's, resolved here so no captured data is needed.
fn subscribe_stream() -> impl Stream<Item = GuiMessage> {
    let socket = socket_for(Daemon::Growlightd);
    iced::stream::channel(
        STREAM_BUFFER,
        // The explicit `output` type pins the stream item to `GuiMessage`.
        move |mut output: iced::futures::channel::mpsc::Sender<GuiMessage>| async move {
            let stop = Arc::new(AtomicBool::new(false));
            // Drops with the future on teardown → tells the worker to stop.
            let _guard = StopOnDrop(stop.clone());
            let (tx, mut rx) = iced::futures::channel::mpsc::unbounded::<Message>();

            // The blocking driver lives on its own thread; it pushes each Message
            // into the unbounded channel and rides out daemon restarts (default
            // policy = retry forever) until `stop` is set.
            std::thread::spawn(move || {
                let mut connector = UnixConnector::new(socket);
                let mut sleeper = ThreadSleeper;
                drive_messages(
                    &mut connector,
                    ReconnectPolicy::default(),
                    &mut sleeper,
                    &|| stop.load(Ordering::Relaxed),
                    &mut |m| {
                        let _ = tx.unbounded_send(m);
                    },
                );
            });

            // Forward the worker's messages into iced until iced drops the receiver
            // (teardown) or the worker ends (all senders dropped → `rx` closes).
            while let Some(m) = rx.next().await {
                if output.send(GuiMessage::Reduce(m)).await.is_err() {
                    break;
                }
            }
        },
    )
}

/// The live event source: tail growlightd's `subscribe` stream off its socket.
fn subscription(_state: &GuiState) -> Subscription<GuiMessage> {
    Subscription::run(subscribe_stream)
}

/// The slice-001 minimal view: the status line plus the pause/resume controls —
/// enough to drive the control-dispatch wiring on a real window. The full observe
/// / control / chat panels over the selectors are slice 002.
fn view(state: &GuiState) -> Element<'_, GuiMessage> {
    column![
        text(crate::render::status_summary(&state.app)),
        row![
            button("Pause").on_press(GuiMessage::Control(Command::Pause)),
            button("Resume").on_press(GuiMessage::Control(Command::Resume)),
        ]
        .spacing(8),
    ]
    .spacing(12)
    .padding(16)
    .into()
}

/// Launch the growlight fleet console: a window driving the pure reducer from the
/// live `subscribe` subscription, with the control widgets dispatching over the
/// reconnecting transport. The window itself is the §7b on-device deferred check.
pub fn run() -> iced::Result {
    iced::application(boot, update, view)
        .title("soft-fig growlight")
        .subscription(subscription)
        .run()
}
