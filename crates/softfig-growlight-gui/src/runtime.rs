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
use iced::widget::{button, column, row, scrollable, text, text_input};
use iced::{Element, Length, Subscription, Task};

use softfig_ipc::growlightd::StopLevel;

use crate::command::{Command, Daemon};
use crate::dispatch::{load_status, send, socket_for, ReconnectingTransport};
use crate::selectors::{agent_thoughts, agents_with_thoughts, fleet_status_rows, who_holds_what};
use crate::state::App;
use crate::update::{update as reduce, Message};
use crate::{drive_messages, ReconnectPolicy, ThreadSleeper, UnixConnector};

/// Backpressure buffer between the subscribe worker thread and the iced runtime.
/// The driver also bridges through an *unbounded* channel first, so this only
/// bounds how many decoded messages iced batches per poll.
const STREAM_BUFFER: usize = 256;

/// How many of an agent's most-recent thought fragments the thoughts panel shows
/// — the *display* scrollback over the already-[`MAX_THOUGHTS`](crate::state::MAX_THOUGHTS)-capped
/// feed. The scrollable keeps the window navigable without rendering every line.
const THOUGHTS_WINDOW: usize = 200;

/// The iced application state: the tested [`App`] view-model plus the UI-local
/// fields the reducer doesn't own — the compose box (and its `to`/`kind` tokens)
/// and the selected thoughts tab. The reducer never sees these; `view()` reads
/// them and the local arms of [`update`] mutate them.
#[derive(Debug)]
pub struct GuiState {
    /// The pure view-model the reducer folds events into.
    pub app: App,
    /// The human input-box text (presentation-local; not in the reducer).
    compose: String,
    /// The post recipient token in wire form (`@all`/`@human`/slug).
    compose_to: String,
    /// The post kind token (`note`/`info`/`alert`/…).
    compose_kind: String,
    /// The agent whose thoughts the per-agent panel shows; `None` falls back to
    /// the first agent that has produced thoughts.
    selected_agent: Option<String>,
}

impl Default for GuiState {
    fn default() -> Self {
        Self {
            app: App::default(),
            compose: String::new(),
            // Sensible compose defaults so a bare "type + Enter" broadcasts a note.
            compose_to: "@all".to_string(),
            compose_kind: "note".to_string(),
            selected_agent: None,
        }
    }
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
    /// A control gesture (pause/resume/force-stop/set-policy) to turn into a
    /// [`crate::command::WireRequest`] and send. The human-post gesture is
    /// [`GuiMessage::Submit`] instead, because it ALSO folds an optimistic line.
    Control(Command),
    /// The input box text changed.
    ComposeChanged(String),
    /// The recipient token changed.
    ComposeToChanged(String),
    /// The kind token changed.
    ComposeKindChanged(String),
    /// Submit the input box: fold the optimistic `pending` chat line AND dispatch
    /// the matching `post_message` (same `to`/`kind`/`body`), then clear the box.
    Submit,
    /// Select which agent's thoughts the per-agent panel shows.
    SelectAgent(String),
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
        GuiMessage::Control(cmd) => dispatch_command(cmd),
        GuiMessage::ComposeChanged(s) => {
            state.compose = s;
            Task::none()
        }
        GuiMessage::ComposeToChanged(s) => {
            state.compose_to = s;
            Task::none()
        }
        GuiMessage::ComposeKindChanged(s) => {
            state.compose_kind = s;
            Task::none()
        }
        GuiMessage::SelectAgent(agent) => {
            state.selected_agent = Some(agent);
            Task::none()
        }
        GuiMessage::Submit => submit(state),
        GuiMessage::Done => Task::none(),
    }
}

/// Submit the input box: the optimistic-UI half of the human post (spec §11).
/// Folds the `pending` chat line through the reducer NOW (so it shows instantly)
/// and dispatches the matching `post_message` with the SAME `to`/`kind`/`body` —
/// the bus echo later reconciles the line. An empty body is a no-op; empty
/// `to`/`kind` fall back to the broadcast-note defaults. The box clears on submit.
fn submit(state: &mut GuiState) -> Task<GuiMessage> {
    let body = state.compose.trim().to_string();
    if body.is_empty() {
        return Task::none();
    }
    let to = non_empty_or(&state.compose_to, "@all");
    let kind = non_empty_or(&state.compose_kind, "note");
    // Optimistic line first (same args as the wire post), then clear the box.
    reduce(
        &mut state.app,
        Message::HumanPosted {
            to: to.clone(),
            kind: kind.clone(),
            body: body.clone(),
        },
    );
    state.compose.clear();
    dispatch_command(Command::PostHuman { to, kind, body })
}

/// The trimmed field, or `fallback` if it is blank.
fn non_empty_or(field: &str, fallback: &str) -> String {
    let t = field.trim();
    if t.is_empty() {
        fallback.to_string()
    } else {
        t.to_string()
    }
}

/// Turn a control [`Command`] into its [`crate::command::WireRequest`] and send it
/// off the UI thread via the tested one-shot [`send`]. Shared by the control
/// widgets and the human-post [`submit`] path. Dispatch failures are logged, not
/// modelled — the real effect is observed back on the live stream.
fn dispatch_command(cmd: Command) -> Task<GuiMessage> {
    match cmd.to_request() {
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

/// The full console view (spec §11): a status header over two surfaces —
/// **observe** (thoughts / roster⋈leases / fleet rows) and **control + chat**
/// (the groupchat, the human input box, and the control knobs). Presentation
/// only: every projection comes from the pure [`crate::selectors`] /
/// [`crate::render`]; `view()` adds no view-model logic, just iced widgets.
fn view(state: &GuiState) -> Element<'_, GuiMessage> {
    let header = text(crate::render::status_summary(&state.app));
    let surfaces = row![observe_column(state), control_column(state)].spacing(16);
    column![header, surfaces]
        .spacing(12)
        .padding(16)
        .into()
}

/// The **observe** surface: the per-agent thoughts feed, the roster⋈leases join,
/// and the fleet status rows.
fn observe_column(state: &GuiState) -> Element<'_, GuiMessage> {
    column![
        text("observe"),
        thoughts_panel(state),
        roster_panel(&state.app),
        fleet_panel(&state.app),
    ]
    .spacing(12)
    .width(Length::Fill)
    .into()
}

/// The per-agent **thoughts** panel: a tab button per agent that has produced
/// thoughts, over a scrollable of the selected agent's recent fragments.
fn thoughts_panel(state: &GuiState) -> Element<'_, GuiMessage> {
    let app = &state.app;
    let agents = agents_with_thoughts(app);

    let tabs: Vec<Element<'_, GuiMessage>> = agents
        .iter()
        .map(|a| {
            button(text((*a).to_string()))
                .on_press(GuiMessage::SelectAgent((*a).to_string()))
                .into()
        })
        .collect();

    // The selected tab, falling back to the first agent with thoughts.
    let selected: Option<&str> = match &state.selected_agent {
        Some(sel) if agents.contains(&sel.as_str()) => Some(sel.as_str()),
        _ => agents.first().copied(),
    };

    let lines: Vec<Element<'_, GuiMessage>> = match selected {
        Some(agent) => agent_thoughts(app, agent, THOUGHTS_WINDOW)
            .iter()
            .map(|t| text(crate::render::thought_line(t)).into())
            .collect(),
        None => vec![text("(no thoughts yet)").into()],
    };

    column![
        text("thoughts"),
        row(tabs).spacing(6),
        scrollable(column(lines).spacing(2)).height(Length::Fill),
    ]
    .spacing(6)
    .into()
}

/// The **roster⋈leases** "who holds what" panel: each roster agent with the
/// leases it holds, then the free/orphan leases.
fn roster_panel(app: &App) -> Element<'_, GuiMessage> {
    let who = who_holds_what(app);
    let mut rows: Vec<Element<'_, GuiMessage>> = Vec::new();
    for entry in &who.agents {
        rows.push(text(format!("{} [{}]", entry.agent.id, entry.agent.status)).into());
        for l in &entry.held {
            rows.push(text(format!("  {}", crate::render::lease_line(l))).into());
        }
    }
    if !who.free.is_empty() {
        rows.push(text("free:").into());
        for l in &who.free {
            rows.push(text(format!("  {}", crate::render::lease_line(l))).into());
        }
    }
    if rows.is_empty() {
        rows.push(text("(no agents)").into());
    }
    column![
        text("roster ⋈ leases"),
        scrollable(column(rows).spacing(2)).height(Length::Fill),
    ]
    .spacing(6)
    .into()
}

/// The **fleet status** panel: one row per agent (id · status · ctx) with the
/// three §8 force-stop levels.
fn fleet_panel(app: &App) -> Element<'_, GuiMessage> {
    let mut rows: Vec<Element<'_, GuiMessage>> = fleet_status_rows(app)
        .iter()
        .map(|r| {
            let ctx = r
                .ctx_pct
                .map(|c| format!(" · ctx {c}%"))
                .unwrap_or_default();
            row![
                text(format!("{} [{}]{}", r.id, r.status, ctx)),
                force_stop_button("stop▸", &r.id, StopLevel::AfterSlice),
                force_stop_button("stop⌛", &r.id, StopLevel::AfterIteration),
                force_stop_button("kill", &r.id, StopLevel::HardKill),
            ]
            .spacing(6)
            .into()
        })
        .collect();
    if rows.is_empty() {
        rows.push(text("(no agents)").into());
    }
    column![text("fleet"), column(rows).spacing(4)]
        .spacing(6)
        .into()
}

/// A single §8 force-stop button targeting `agent` at `level`.
fn force_stop_button(label: &str, agent: &str, level: StopLevel) -> Element<'static, GuiMessage> {
    button(text(label.to_string()))
        .on_press(GuiMessage::Control(Command::ForceStop {
            agent: agent.to_string(),
            level,
        }))
        .into()
}

/// The **control + chat** surface: the groupchat, the human input box, and the
/// control knobs (pause/resume + the `max_concurrent_agents` set-policy nudge).
fn control_column(state: &GuiState) -> Element<'_, GuiMessage> {
    column![
        text("control + chat"),
        chat_panel(&state.app),
        compose_box(state),
        controls(state),
    ]
    .spacing(12)
    .width(Length::Fill)
    .into()
}

/// The **groupchat** panel: the coordination-bus history, including any optimistic
/// (`pending`) human post — `render::chat_line` already marks it with `…`.
fn chat_panel(app: &App) -> Element<'_, GuiMessage> {
    let mut lines: Vec<Element<'_, GuiMessage>> = app
        .chat
        .iter()
        .map(|c| text(crate::render::chat_line(c)).into())
        .collect();
    if lines.is_empty() {
        lines.push(text("(no messages)").into());
    }
    scrollable(column(lines).spacing(2))
        .height(Length::Fill)
        .into()
}

/// The human **input box** (spec §11): the recipient/kind tokens plus the message
/// field. Enter (or "send") fires [`GuiMessage::Submit`] — the optimistic fold +
/// the live `post_message`.
fn compose_box(state: &GuiState) -> Element<'_, GuiMessage> {
    row![
        text_input("@all", &state.compose_to)
            .on_input(GuiMessage::ComposeToChanged)
            .width(Length::Fixed(90.0)),
        text_input("note", &state.compose_kind)
            .on_input(GuiMessage::ComposeKindChanged)
            .width(Length::Fixed(90.0)),
        text_input("message…", &state.compose)
            .on_input(GuiMessage::ComposeChanged)
            .on_submit(GuiMessage::Submit),
        button(text("send")).on_press(GuiMessage::Submit),
    ]
    .spacing(6)
    .into()
}

/// The control **knobs**: the fleet pause/resume gate plus a `set_policy` nudge of
/// `max_concurrent_agents` (the tweak-knobs panel — only shown once a policy has
/// loaded, since the nudge replaces the current one).
fn controls(state: &GuiState) -> Element<'_, GuiMessage> {
    let mut col = column![row![
        button(text("Pause")).on_press(GuiMessage::Control(Command::Pause)),
        button(text("Resume")).on_press(GuiMessage::Control(Command::Resume)),
    ]
    .spacing(8)]
    .spacing(8);

    if let Some(policy) = state.app.policy {
        let mut down = policy;
        down.max_concurrent_agents = policy.max_concurrent_agents.saturating_sub(1);
        let mut up = policy;
        up.max_concurrent_agents = policy.max_concurrent_agents.saturating_add(1);
        col = col.push(
            row![
                text(format!("max agents: {}", policy.max_concurrent_agents)),
                button(text("-")).on_press(GuiMessage::Control(Command::SetPolicy { policy: down })),
                button(text("+")).on_press(GuiMessage::Control(Command::SetPolicy { policy: up })),
            ]
            .spacing(6),
        );
    }
    col.into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChatLine, ConnState, ThoughtLine};
    use softfig_ipc::growlightd::{AgentDeltaKind, PolicySummary};

    fn policy() -> PolicySummary {
        PolicySummary {
            max_concurrent_agents: 2,
            ctx_roll_pct: 50,
            ctx_handoff_pct: 60,
            session_5h_halt_pct: 85,
            session_7d_halt_pct: 90,
        }
    }

    /// A model mid-stream: two agents (one with a ctx reading), a held and a free
    /// lease, a chat line, and a loaded policy — so every observe/control panel
    /// has real selector output to render.
    fn populated() -> App {
        let mut app = App {
            state_label: "running".into(),
            conn: ConnState::Connected,
            policy: Some(policy()),
            ..Default::default()
        };
        app.touch_agent("loop-1");
        app.touch_agent("loop-2");
        app.set_agent_ctx("loop-1", 42);
        app.push_thought(ThoughtLine {
            agent: "loop-1".into(),
            kind: AgentDeltaKind::Assistant,
            text: "working on 001".into(),
        });
        app.push_thought(ThoughtLine {
            agent: "loop-2".into(),
            kind: AgentDeltaKind::ToolCall,
            text: "edit(dock.rs)".into(),
        });
        app.upsert_lease("dock.rs".into(), Some("loop-1".into()), "granted".into());
        app.upsert_lease("free.rs".into(), None, "waiting".into());
        app.push_chat(ChatLine::confirmed("loop-1", "all", "note", "starting 001"));
        app
    }

    fn gui(app: App) -> GuiState {
        GuiState {
            app,
            ..GuiState::default()
        }
    }

    #[test]
    fn view_builds_over_empty_populated_and_pending_states() {
        // Empty model (booted, nothing streamed yet).
        let _ = view(&gui(App::default()));

        // Mid-stream: thoughts + roster⋈leases + fleet rows + chat + policy knobs.
        let _ = view(&gui(populated()));

        // An optimistic, not-yet-echoed human post — the `…` pending chat line.
        let mut pending = App::default();
        pending.push_human_post("@all", "info", "deploy starting");
        let _ = view(&gui(pending));

        // A selected tab that no longer exists must fall back (not panic).
        let mut stale = gui(populated());
        stale.selected_agent = Some("ghost".into());
        let _ = view(&stale);

        // A valid selected tab renders that agent's thoughts.
        let mut sel = gui(populated());
        sel.selected_agent = Some("loop-2".into());
        let _ = view(&sel);
    }

    #[test]
    fn local_update_arms_mutate_ui_state_without_dispatch() {
        let mut s = GuiState::default();
        // Compose-box edits land on the UI-local fields, never the reducer.
        let _ = update(&mut s, GuiMessage::ComposeChanged("hi".into()));
        assert_eq!(s.compose, "hi");
        let _ = update(&mut s, GuiMessage::ComposeToChanged("loop-1".into()));
        assert_eq!(s.compose_to, "loop-1");
        let _ = update(&mut s, GuiMessage::ComposeKindChanged("alert".into()));
        assert_eq!(s.compose_kind, "alert");
        let _ = update(&mut s, GuiMessage::SelectAgent("loop-2".into()));
        assert_eq!(s.selected_agent.as_deref(), Some("loop-2"));
        // None of these touch the reducer-owned chat/roster state.
        assert!(s.app.chat.is_empty());
    }

    #[test]
    fn submit_with_a_blank_box_folds_nothing_and_does_not_dispatch() {
        // The live PostHuman dispatch is deliberately NOT exercised: keeperd may be
        // up on the dev box and a real submit would post to the live coordination
        // bus. `submit` only composes two already-tested units — the optimistic
        // fold (`Message::HumanPosted`, `update.rs`) and the PostHuman→keeperd
        // mapping (`command.rs`) — so the blank-box guard is what's new here.
        let mut s = GuiState::default(); // compose is blank
        let _ = update(&mut s, GuiMessage::Submit);
        assert!(s.app.chat.is_empty(), "a blank submit is a no-op");
        assert!(s.compose.is_empty());
    }

    #[test]
    fn non_empty_or_trims_and_falls_back_when_blank() {
        assert_eq!(non_empty_or("   ", "@all"), "@all");
        assert_eq!(non_empty_or("  loop-1 ", "@all"), "loop-1");
    }
}
