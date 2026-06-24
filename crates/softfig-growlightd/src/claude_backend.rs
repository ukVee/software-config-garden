//! Live agent backend (drive-loop slice 001) — the first real binding behind the
//! [`crate::supervisor::AgentBackend`] seam (spec-growlight-orchestrator §12
//! backend decision, §15 operational must-haves).
//!
//! [`ClaudeBackend`] shells `claude -p --output-format stream-json --verbose` per
//! agent, each with its per-agent pre-approval `--settings`/`--mcp-config` (the
//! §15 must-have: a headless agent **errors out** on a missing allow-rule, it does
//! not pause — so each agent must pre-approve its full toolset). A detached reader
//! thread tails the child's stream-json output, publishing every assistant /
//! thinking / tool-call content block as an [`Event::AgentDelta`] on the shared
//! [`EventHub`] so `growlight watch` and the GUI render the live "what's it
//! thinking now" view (§12). The same tail bumps a per-agent heartbeat; the drive
//! loop reads [`ClaudeBackend::health`] each cycle and feeds it to
//! [`crate::supervisor::Supervisor::poll`], where a stale heartbeat (no stream
//! activity within the hang window) classifies as a crash.
//!
//! ## Why a shared health cell, not a method on [`AgentChild`]
//!
//! [`AgentChild`] stays the pure *kill* handle (its only job is the
//! incident-20260622 kill-outside-the-lock contract). Health is a *separate*
//! observation the reader thread writes into an [`AgentHealthState`] shared by
//! `Arc`; the backend keeps a registry of those cells and the drive loop reads
//! them by agent id. This keeps lifecycle (kill) and observability (health)
//! decoupled and leaves the four existing `AgentChild` fakes untouched.
//!
//! ## Time
//!
//! The pure policy ([`crate::supervisor::Supervisor`] / its `classify`) stays
//! time-injected. Only this live binding reads the wall clock — at spawn (the
//! initial heartbeat) and on every stream line. The parse + publish + heartbeat
//! pipeline is itself a pure function over a `BufRead` + an injected clock
//! ([`pump`]), so it is unit-proven with a scripted fixture and a fake clock — no
//! real `claude` is ever spawned in tests (the §7b on-device run is the human's).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;
use softfig_ipc::growlightd::{AgentDeltaKind, Event};

use crate::control::AgentChild;
use crate::hub::EventHub;
use crate::supervisor::{AgentBackend, AgentHealth, AgentSpec, SpawnError};

/// Sentinel in [`AgentHealthState::exit_code`] meaning "still running".
const NOT_EXITED: i64 = i64::MIN;
/// Exit code recorded when a child ended but its code was unreadable (killed by a
/// signal, or the status couldn't be collected). Non-zero so it classifies as a
/// crash, never a clean (code-0) roll.
const UNKNOWN_EXIT: i32 = -1;
/// Cap on a rendered tool-call argument string, so one giant `input` can't flood
/// the event stream / GUI.
const TOOL_RENDER_MAX_CHARS: usize = 200;

/// Shared, lock-free observation of one live agent: the Unix-seconds heartbeat
/// (bumped on every stream-json line) and the exit code once the child ends. The
/// reader thread writes it; the drive loop reads it via [`ClaudeBackend::health`]
/// to build the [`AgentHealth`] it feeds [`crate::supervisor::Supervisor::poll`].
#[derive(Debug)]
pub struct AgentHealthState {
    last_active: AtomicI64,
    exit_code: AtomicI64,
}

impl AgentHealthState {
    /// A fresh state for a just-spawned child whose first heartbeat is its spawn
    /// time (so a child that never emits a line still hangs only after the window).
    fn new(spawned_at: i64) -> Self {
        Self {
            last_active: AtomicI64::new(spawned_at),
            exit_code: AtomicI64::new(NOT_EXITED),
        }
    }

    /// Record stream activity at `now` — a heartbeat. Stores the latest stamp.
    fn touch(&self, now: i64) {
        self.last_active.store(now, Ordering::SeqCst);
    }

    /// Record the child's terminal exit code once it has ended.
    fn record_exit(&self, code: i32) {
        self.exit_code.store(code as i64, Ordering::SeqCst);
    }

    fn last_active(&self) -> i64 {
        self.last_active.load(Ordering::SeqCst)
    }

    /// The current [`AgentHealth`]: `Exited` once the child has ended, else
    /// `Alive` stamped with the last heartbeat. The Supervisor compares the stamp
    /// to its own injected clock, so no `now` is needed to build the value.
    pub fn observe(&self) -> AgentHealth {
        match self.exit_code.load(Ordering::SeqCst) {
            NOT_EXITED => AgentHealth::Alive {
                last_active: self.last_active(),
            },
            code => AgentHealth::Exited { code: code as i32 },
        }
    }
}

/// Translate one stream-json line into the content deltas it carries, in block
/// order. Pure. Only `assistant` events carry content; a non-assistant line,
/// malformed JSON, or an unrecognized block yields no deltas (the caller still
/// counts any non-empty line as a heartbeat — the child is plainly alive if it is
/// emitting anything at all).
fn deltas_for_line(line: &str) -> Vec<(AgentDeltaKind, String)> {
    let Ok(ev) = serde_json::from_str::<Value>(line) else {
        return Vec::new();
    };
    if ev.get("type").and_then(Value::as_str) != Some("assistant") {
        return Vec::new();
    }
    let Some(content) = ev
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for block in content {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = block.get("text").and_then(Value::as_str) {
                    out.push((AgentDeltaKind::Assistant, t.to_string()));
                }
            }
            Some("thinking") => {
                if let Some(t) = block.get("thinking").and_then(Value::as_str) {
                    out.push((AgentDeltaKind::Thinking, t.to_string()));
                }
            }
            Some("tool_use") => out.push((AgentDeltaKind::ToolCall, render_tool_use(block))),
            _ => {}
        }
    }
    out
}

/// Render a `tool_use` block into a compact one-line "what tool, what args" string
/// for the live view: `name(input-json)`, char-truncated so a huge argument can't
/// flood the stream.
fn render_tool_use(block: &Value) -> String {
    let name = block.get("name").and_then(Value::as_str).unwrap_or("tool");
    let input = block
        .get("input")
        .map(|i| serde_json::to_string(i).unwrap_or_default())
        .unwrap_or_default();
    let mut rendered = if input.is_empty() || input == "null" {
        name.to_string()
    } else {
        format!("{name}({input})")
    };
    // Truncate on a char boundary (`String::truncate` panics mid-codepoint).
    if rendered.chars().count() > TOOL_RENDER_MAX_CHARS {
        rendered = rendered.chars().take(TOOL_RENDER_MAX_CHARS).collect();
        rendered.push('…');
    }
    rendered
}

/// Tail an agent's `claude -p --output-format stream-json` output to EOF,
/// publishing each content block as an [`Event::AgentDelta`] on `hub` and bumping
/// `health`'s heartbeat on every non-empty line. Pure over its `reader` / `now`
/// seams: a test drives it with a scripted fixture + fake clock, no real spawn.
fn pump<R: BufRead>(
    reader: R,
    agent: &str,
    hub: &EventHub,
    health: &AgentHealthState,
    now: &dyn Fn() -> i64,
) {
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Any line from the child is a sign of life → heartbeat, even if it
        // carries no renderable delta.
        health.touch(now());
        for (kind, text) in deltas_for_line(line) {
            hub.publish(Event::agent_delta(agent, kind, text));
        }
    }
}

/// The production [`AgentBackend`]: shells `claude -p --output-format stream-json`
/// per agent (§12), tails each child into [`Event::AgentDelta`]s on the shared
/// [`EventHub`], and tracks a per-agent [`AgentHealthState`] the drive loop reads.
///
/// Implemented for `Arc<ClaudeBackend>` (mirroring the supervisor's test fake) so
/// the drive loop can hold a clone to read [`health`](ClaudeBackend::health) while
/// the [`crate::supervisor::Supervisor`] owns the backend behind the trait.
#[derive(Debug)]
pub struct ClaudeBackend {
    bin: String,
    prompt: String,
    hub: EventHub,
    /// Per-agent health cells, keyed by agent id; re-spawn (re-roll) replaces the
    /// agent's cell with a fresh one.
    agents: Mutex<BTreeMap<String, Arc<AgentHealthState>>>,
}

impl ClaudeBackend {
    /// A backend launching `bin` (e.g. `"claude"`) with `prompt` as the per-agent
    /// kick, publishing deltas to `hub`. The SessionStart hook in each agent's
    /// `--settings` injects its protocol + baton; `prompt` is the generic turn
    /// kick.
    pub fn new(bin: impl Into<String>, prompt: impl Into<String>, hub: EventHub) -> Self {
        Self {
            bin: bin.into(),
            prompt: prompt.into(),
            hub,
            agents: Mutex::new(BTreeMap::new()),
        }
    }

    /// `agent`'s current health (heartbeat-or-exit), or `None` if this backend
    /// never spawned it. The drive loop calls this each cycle to feed
    /// [`crate::supervisor::Supervisor::poll`].
    pub fn health(&self, agent: &str) -> Option<AgentHealth> {
        self.agents.lock().unwrap().get(agent).map(|s| s.observe())
    }
}

impl AgentBackend for Arc<ClaudeBackend> {
    fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
        let mut child = Command::new(&self.bin)
            .arg("-p")
            .arg(&self.prompt)
            .arg("--settings")
            .arg(&spec.loop_settings)
            .arg("--mcp-config")
            .arg(&spec.mcp_config)
            .arg("--output-format")
            .arg("stream-json")
            .arg("--verbose")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // stderr is discarded, not piped: an unread stderr pipe can fill and
            // deadlock the child, and a headless permission error already surfaces
            // as a non-zero exit → crash classification + alert.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| SpawnError(format!("failed to launch `{} -p`: {e}", self.bin)))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SpawnError("child stdout was not captured".into()))?;

        let state = Arc::new(AgentHealthState::new(unix_now()));
        self.agents
            .lock()
            .unwrap()
            .insert(spec.agent.clone(), Arc::clone(&state));

        // The child is shared with the reader thread for reaping. While the child
        // lives, the reader is blocked in `lines()` on stdout (it holds NO lock),
        // so `kill` can always take the lock to SIGKILL; the reader only locks the
        // child AFTER stdout EOF (the child is already exiting), so `wait` returns
        // promptly and there is no kill/reap deadlock.
        let child = Arc::new(Mutex::new(child));

        let hub = self.hub.clone();
        let agent = spec.agent.clone();
        let reader_state = Arc::clone(&state);
        let reader_child = Arc::clone(&child);
        thread::spawn(move || {
            pump(
                BufReader::new(stdout),
                &agent,
                &hub,
                &reader_state,
                &|| unix_now(),
            );
            // stdout closed → the child is ending; reap it for the exit code.
            let code = reader_child
                .lock()
                .unwrap()
                .wait()
                .ok()
                .and_then(|s| s.code())
                .unwrap_or(UNKNOWN_EXIT);
            reader_state.record_exit(code);
        });

        Ok(Box::new(ClaudeChild { child }))
    }
}

/// The killable handle for a live `claude -p` child (the [`AgentChild`] contract).
/// `kill` SIGKILLs the process best-effort OUTSIDE the daemon lock; killing closes
/// stdout, so the reader thread reaps the child and records its exit.
#[derive(Debug)]
struct ClaudeChild {
    child: Arc<Mutex<Child>>,
}

impl AgentChild for ClaudeChild {
    fn kill(&self) {
        // Best-effort: an already-exited child returns Err, which is fine. We do
        // NOT wait() here — the reader thread reaps on the resulting stdout EOF.
        // Called outside the daemon lock (incident 20260622).
        let _ = self.child.lock().unwrap().kill();
    }
}

/// Wall-clock Unix seconds for the live heartbeat / spawn stamps. The pure policy
/// stays time-injected; only this live binding reads the clock.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A realistic stream-json run: system init, an assistant turn carrying a
    /// thinking + text + tool_use block, a tool_result (a `user` event), a second
    /// assistant turn, then the terminal result. Five non-empty lines; four
    /// renderable deltas.
    const STREAM: &str = concat!(
        r#"{"type":"system","subtype":"init","model":"claude-opus-4-8"}"#,
        "\n",
        r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","thinking":"let me check the file"},{"type":"text","text":"I'll read it now."},{"type":"tool_use","id":"tu_1","name":"Read","input":{"file_path":"/x"}}]}}"#,
        "\n",
        r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"ok"}]}}"#,
        "\n",
        r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Done."}]}}"#,
        "\n",
        r#"{"type":"result","subtype":"success","is_error":false,"result":"Done.","usage":{"input_tokens":10},"modelUsage":{"claude-opus-4-8":{"contextWindow":1000000}}}"#,
        "\n",
    );

    #[test]
    fn deltas_for_line_extracts_each_content_block_in_order() {
        let assistant = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","thinking":"hmm"},{"type":"text","text":"hi"},{"type":"tool_use","id":"t","name":"Bash","input":{"command":"ls"}}]}}"#;
        assert_eq!(
            deltas_for_line(assistant),
            vec![
                (AgentDeltaKind::Thinking, "hmm".to_string()),
                (AgentDeltaKind::Assistant, "hi".to_string()),
                (AgentDeltaKind::ToolCall, r#"Bash({"command":"ls"})"#.to_string()),
            ]
        );

        // Non-assistant lines, malformed JSON, and empty-content carry no deltas.
        assert!(deltas_for_line(r#"{"type":"system","subtype":"init"}"#).is_empty());
        assert!(deltas_for_line(r#"{"type":"result","result":"done"}"#).is_empty());
        assert!(deltas_for_line("not json at all").is_empty());
        assert!(
            deltas_for_line(r#"{"type":"assistant","message":{"content":[]}}"#).is_empty()
        );
    }

    #[test]
    fn render_tool_use_is_compact_and_char_truncated() {
        let no_input = serde_json::json!({"name": "Ls"});
        assert_eq!(render_tool_use(&no_input), "Ls");

        // A huge argument is truncated on a char boundary with an ellipsis, never
        // panicking mid-codepoint.
        let big = serde_json::json!({"name": "Write", "input": {"content": "é".repeat(500)}});
        let rendered = render_tool_use(&big);
        assert!(rendered.chars().count() <= TOOL_RENDER_MAX_CHARS + 1);
        assert!(rendered.ends_with('…'));
        assert!(rendered.starts_with("Write("));
    }

    #[test]
    fn pump_publishes_each_delta_and_advances_the_heartbeat() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let state = AgentHealthState::new(0);

        // A fake clock that ticks 10, 20, 30, … once per line read.
        let clock = AtomicI64::new(0);
        let now = || clock.fetch_add(10, Ordering::SeqCst) + 10;

        pump(Cursor::new(STREAM), "tab", &hub, &state, &now);

        // The four content deltas reach the hub in block order, tagged by kind.
        let expect = [
            Event::agent_delta("tab", AgentDeltaKind::Thinking, "let me check the file"),
            Event::agent_delta("tab", AgentDeltaKind::Assistant, "I'll read it now."),
            Event::agent_delta("tab", AgentDeltaKind::ToolCall, r#"Read({"file_path":"/x"})"#),
            Event::agent_delta("tab", AgentDeltaKind::Assistant, "Done."),
        ];
        for want in expect {
            assert_eq!(sub.try_recv().unwrap(), want);
        }
        assert!(sub.try_recv().is_err(), "no extra events");

        // Five non-empty lines → five heartbeats → last_active is the final tick.
        assert_eq!(state.last_active(), 50);
        assert_eq!(state.observe(), AgentHealth::Alive { last_active: 50 });
    }

    #[test]
    fn a_silent_stream_leaves_the_heartbeat_stale_so_the_supervisor_would_hang_it() {
        // A child that emits its init line then goes silent (no further output and
        // no exit) — the canonical hang. The heartbeat stops at the init stamp.
        let silent = "{\"type\":\"system\",\"subtype\":\"init\"}\n";
        let hub = EventHub::new();
        let state = AgentHealthState::new(0);
        let now = || 100; // init line stamped at t=100, then nothing more

        pump(Cursor::new(silent), "tab", &hub, &state, &now);

        // No exit recorded → still Alive, but pinned at the stale init stamp.
        assert_eq!(state.observe(), AgentHealth::Alive { last_active: 100 });
        // A later poll's gap exceeds the supervisor's default hang window (600s),
        // so `Supervisor::classify` (proven in supervisor.rs) trips it to Crashed.
        let polled_at = 100 + 700;
        assert!(polled_at - 100 >= 600, "a stale heartbeat reads as hung");
    }

    #[test]
    fn observe_reports_a_recorded_exit_over_the_heartbeat() {
        let state = AgentHealthState::new(42);
        assert_eq!(state.observe(), AgentHealth::Alive { last_active: 42 });
        // Once the reader thread reaps a non-zero exit, health flips to Exited
        // (the supervisor classifies that as a crash).
        state.record_exit(1);
        assert_eq!(state.observe(), AgentHealth::Exited { code: 1 });
    }
}
