//! softfig-mcp — stateless stdio bridge translating MCP JSON-RPC tool
//! calls into IPC requests against a running `softfig-keeperd`.
//!
//! Spawned per Claude Code session. Exposes the typed garden-write verbs
//! plus the `replace_file` break-glass escape hatch.
//!
//! MCP wire shape (subset of JSON-RPC 2.0): one request per stdin line,
//! one response per stdout line. We implement the minimum the Claude
//! Code MCP client invokes: `initialize`, `tools/list`, `tools/call`.

use std::io::{self, BufRead, Write};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use softfig_ipc::{
    self,
    verbs::{
        op, AddBacklogItemArgs, AddNoteArgs, AddProjectArgs, AddSectionArgs, AddSliceArgs,
        AppendToSectionArgs, ArchiveArgs, EditSectionArgs, LogBatonArgs, LogDecisionArgs,
        LogIncidentArgs, PostMessageArgs, ReadInboxArgs, RefreshSnapshotArgs,
        ReorderBacklogItemArgs, ReplaceFileArgs, ReviseNoteArgs, SetItemStatusArgs, SetReviewedArgs,
    },
    Request, Response,
};

const PROTOCOL: &str = "2024-11-05";

#[derive(Debug, Deserialize)]
struct Rpc {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct RpcOk<'a> {
    jsonrpc: &'a str,
    id: Value,
    result: Value,
}

#[derive(Debug, Serialize)]
struct RpcErr<'a> {
    jsonrpc: &'a str,
    id: Value,
    error: RpcErrBody,
}

#[derive(Debug, Serialize)]
struct RpcErrBody {
    code: i32,
    message: String,
}

fn ok(id: Value, result: Value) -> Value {
    serde_json::to_value(RpcOk {
        jsonrpc: "2.0",
        id,
        result,
    })
    .unwrap()
}

fn err(id: Value, code: i32, message: impl Into<String>) -> Value {
    serde_json::to_value(RpcErr {
        jsonrpc: "2.0",
        id,
        error: RpcErrBody {
            code,
            message: message.into(),
        },
    })
    .unwrap()
}

fn main() -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = handle_line(&line);
        let mut bytes = serde_json::to_vec(&resp)?;
        bytes.push(b'\n');
        out.write_all(&bytes)?;
        out.flush()?;
    }
    Ok(())
}

fn handle_line(line: &str) -> Value {
    let rpc: Rpc = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return err(Value::Null, -32700, format!("parse: {e}")),
    };
    let id = rpc.id.clone().unwrap_or(Value::Null);

    match rpc.method.as_str() {
        "initialize" => ok(
            id,
            json!({
                "protocolVersion": PROTOCOL,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "softfig-mcp", "version": env!("CARGO_PKG_VERSION") },
            }),
        ),
        "notifications/initialized" => Value::Null, // notification; no reply
        "tools/list" => ok(id, json!({ "tools": tool_defs() })),
        "tools/call" => match call_tool(&rpc.params) {
            Ok(v) => ok(id, v),
            Err(e) => err(id, -32000, e.to_string()),
        },
        other => err(id, -32601, format!("unknown method {other:?}")),
    }
}

fn tool_defs() -> Vec<Value> {
    vec![
        json!({
            "name": "log_decision",
            "description": "Record a garden decision. The keeper daemon writes \
                            journal/decisions/decision-<slug>.md with a stamped \
                            '# decision: <title>' + Date header and your body below, then \
                            commits decision_logged. You supply only slug + body.",
            "inputSchema": {
                "type": "object",
                "required": ["slug", "body"],
                "properties": {
                    "slug": { "type": "string", "description": "[a-z0-9-]+, 1-64 chars" },
                    "summary": { "type": "string", "description": "title; defaults to slug" },
                    "body": { "type": "string", "description": "markdown body below the header" },
                },
            },
        }),
        json!({
            "name": "log_incident",
            "description": "Record an incident. The daemon writes \
                            journal/incidents/incident-<date>-<slug>.md with a stamped \
                            '# <YYYY-MM-DD> — <summary>' header and commits incident_logged.",
            "inputSchema": {
                "type": "object",
                "required": ["slug", "summary", "body"],
                "properties": {
                    "slug": { "type": "string", "description": "[a-z0-9-]+, 1-64 chars" },
                    "summary": { "type": "string", "description": "one-line incident summary" },
                    "body": { "type": "string", "description": "what happened / tried / fixed" },
                    "date": { "type": "string", "description": "YYYYMMDD; defaults to today" },
                },
            },
        }),
        json!({
            "name": "add_note",
            "description": "Append a numbered note to an accretive folder (a notes/ or \
                            troubleshooting/ dir). The daemon assigns the next number from the \
                            folder's hidden .seq counter, writes dir/NNN-slug.md, and stamps the \
                            '# <title>' header + '> Last reviewed:' line — you supply only dir, \
                            slug, and body (title defaults to slug). Prefer this over \
                            replace_file for adding a note: it costs you only the new \
                            content, never the whole file.",
            "inputSchema": {
                "type": "object",
                "required": ["dir", "slug", "body"],
                "properties": {
                    "dir": { "type": "string", "description": "garden-relative accretive folder, e.g. services/waydroid/notes" },
                    "slug": { "type": "string", "description": "[a-z0-9-]+, 1-64; the terse filename address (immutable)" },
                    "title": { "type": "string", "description": "header title; defaults to slug" },
                    "body": { "type": "string", "description": "markdown body below the header" },
                },
            },
        }),
        json!({
            "name": "revise_note",
            "description": "Replace the body of an existing numbered note in place, re-stamping \
                            its '> Last reviewed:' date. Title, slug, and number are immutable — \
                            to 'rename' a note, archive it and add_note a new one. Identify the \
                            note by its folder + number.",
            "inputSchema": {
                "type": "object",
                "required": ["dir", "id", "body"],
                "properties": {
                    "dir": { "type": "string", "description": "the note's accretive folder" },
                    "id": { "type": "integer", "description": "the note's number (the NNN in its filename)" },
                    "body": { "type": "string", "description": "the replacement markdown body" },
                },
            },
        }),
        json!({
            "name": "edit_section",
            "description": "Replace the body of an existing heading-addressed section in ANY \
                            markdown doc (note, CLAUDE.md, decision), keeping the heading line. \
                            You emit only the new body — never the rest of the file. Address the \
                            section by its heading text (case-sensitive, level-agnostic): 'Cross-refs' \
                            or '## Cross-refs' both match; the match must be unique. Refused on \
                            vault-sealed targets. Prefer this over replace_file for editing one \
                            section.",
            "inputSchema": {
                "type": "object",
                "required": ["path", "heading", "body"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative markdown doc" },
                    "heading": { "type": "string", "description": "section heading text; '#' prefix optional" },
                    "body": { "type": "string", "description": "replacement markdown body (heading kept by daemon)" },
                },
            },
        }),
        json!({
            "name": "append_to_section",
            "description": "Add a row/bullet/line to the end of an existing section's body (before \
                            the next heading) in any markdown doc — the cheap 'add one item' op. \
                            You emit only the new line(s). Same heading addressing + vault refusal \
                            as edit_section.",
            "inputSchema": {
                "type": "object",
                "required": ["path", "heading", "text"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative markdown doc" },
                    "heading": { "type": "string", "description": "target section heading text; '#' prefix optional" },
                    "text": { "type": "string", "description": "new content to append (e.g. a list row)" },
                },
            },
        }),
        json!({
            "name": "add_section",
            "description": "Append a brand-new section to the end of any markdown doc. The daemon \
                            stamps the heading line; you emit the heading text + body. Include \
                            leading '#'s to set the level ('## Foo' → level 2), else it defaults to \
                            '##'. The heading must not already exist. Refused on vault-sealed targets.",
            "inputSchema": {
                "type": "object",
                "required": ["path", "heading", "body"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative markdown doc" },
                    "heading": { "type": "string", "description": "new section heading text; '#' prefix sets level" },
                    "body": { "type": "string", "description": "markdown body below the new heading" },
                },
            },
        }),
        json!({
            "name": "set_reviewed",
            "description": "Bump a doc's 'Last reviewed:' line (optionally '> '-quoted) to today's \
                            date. Zero content — you pass only the path; the daemon owns the date. \
                            Errors if the doc has no such line.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative doc with a 'Last reviewed:' line" },
                },
            },
        }),
        json!({
            "name": "archive",
            "description": "Move a garden path under journal/archive/<name>/ and commit \
                            archive_move. archive_name defaults to the basename of src.",
            "inputSchema": {
                "type": "object",
                "required": ["src"],
                "properties": {
                    "src": { "type": "string", "description": "garden-relative path to archive" },
                    "archive_name": { "type": "string", "description": "bucket dir; default = basename(src)" },
                },
            },
        }),
        json!({
            "name": "add_project",
            "description": "Scaffold projects/<name>/ with the four reserved-name stubs \
                            (CLAUDE.md, instructions.md, notes.md, refs.md) in one \
                            project_added commit.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "[a-z0-9]([a-z0-9-]*[a-z0-9])?, 1-64" },
                    "repo_path": { "type": "string", "description": "absolute path of the real code repo" },
                    "summary": { "type": "string", "description": "one-line project description" },
                },
            },
        }),
        json!({
            "name": "refresh_snapshot",
            "description": "Write caller-supplied content to a path under snapshots/ and \
                            commit snapshot_refresh. Run the data-gathering command yourself \
                            (Bash) and pass the result as content — the daemon never executes \
                            user code. The parent dir under snapshots/ must already exist.",
            "inputSchema": {
                "type": "object",
                "required": ["path", "content"],
                "properties": {
                    "path": { "type": "string", "description": "must be under snapshots/" },
                    "content": { "type": "string" },
                },
            },
        }),
        json!({
            "name": "log_baton",
            "description": "growlight: append a numbered iteration entry to growlight/baton-log/ \
                            (the work-loop audit log). The daemon assigns the number from the \
                            folder's .seq counter, derives the filename, and stamps the \
                            iteration-metadata block (item/slice/iteration/status/budgets) above \
                            your summary. Append-only audit; never injected into a session and \
                            excluded from the backlink graph.",
            "inputSchema": {
                "type": "object",
                "required": ["item", "iteration", "summary"],
                "properties": {
                    "item": { "type": "string", "description": "backlog item id worked this iteration (milestone id or task NNN)" },
                    "iteration": { "type": "integer", "description": "the baton's iteration counter" },
                    "summary": { "type": "string", "description": "what shipped this iteration + pointers (the entry body)" },
                    "item_type": { "type": "string", "description": "milestone | task; defaults to milestone" },
                    "slice": { "type": "string", "description": "active slice id (milestones only)" },
                    "status": { "type": "string", "description": "loop status at handoff, e.g. IN_PROGRESS / HALTED_RATE_LIMIT" },
                    "ctx_pct": { "type": "integer", "description": "last observed context-window used %" },
                    "session_5h_pct": { "type": "integer", "description": "last observed 5h-session rate used %" },
                    "slug": { "type": "string", "description": "[a-z0-9-]+ filename slug; defaults to <item>-iter-<iteration>" },
                },
            },
        }),
        json!({
            "name": "add_backlog_item",
            "description": "growlight: seed a backlog item and enqueue it (status queued). A \
                            milestone creates growlight/backlog/milestones/<slug>/ (mission + \
                            finish criteria + an empty slices folder); a task creates a numbered \
                            growlight/backlog/tasks/NNN-<slug>.md. Status + order live only in the \
                            managed queue table in backlog/CLAUDE.md — change them with \
                            set_item_status, never by hand. slug is [a-z0-9-]+ (lowercase).",
            "inputSchema": {
                "type": "object",
                "required": ["item_type", "slug", "title", "mission", "finish_criteria"],
                "properties": {
                    "item_type": { "type": "string", "description": "milestone | task" },
                    "slug": { "type": "string", "description": "[a-z0-9-]+, 1-64; milestone id / dir name, or the task filename slug" },
                    "title": { "type": "string", "description": "human title for the queue table + item heading" },
                    "mission": { "type": "string", "description": "why this item exists (## Mission)" },
                    "finish_criteria": { "type": "string", "description": "checkable completion criteria (## Finish criteria)" },
                },
            },
        }),
        json!({
            "name": "add_slice",
            "description": "growlight: append a numbered slice doc under an existing milestone \
                            (growlight/backlog/milestones/<id>/slices/NNN-<slug>.md) and refresh the \
                            milestone's slices index. The daemon assigns the slice number from the \
                            folder's .seq counter and stamps the header + reviewed date.",
            "inputSchema": {
                "type": "object",
                "required": ["milestone", "slug", "body"],
                "properties": {
                    "milestone": { "type": "string", "description": "the owning milestone's id (its milestones/<id>/ dir)" },
                    "slug": { "type": "string", "description": "[a-z0-9-]+, 1-64; the slice's terse filename address" },
                    "title": { "type": "string", "description": "slice heading; defaults to slug" },
                    "body": { "type": "string", "description": "the slice's plan/spec markdown body" },
                },
            },
        }),
        json!({
            "name": "set_item_status",
            "description": "growlight: set a backlog item's status (queued|active|done|blocked|deferred) \
                            by flipping its cell in the authoritative queue table in \
                            growlight/backlog/CLAUDE.md. At most one item may be active — setting \
                            active is refused while another item is active. `deferred` parks an item \
                            whose only gap is a manual smoketest the loop can't run (non-terminal; the \
                            loop drains on). Identify the item by its queue id (milestone slug or task NNN).",
            "inputSchema": {
                "type": "object",
                "required": ["id", "status"],
                "properties": {
                    "id": { "type": "string", "description": "the item's queue id (milestone slug or task NNN)" },
                    "status": { "type": "string", "description": "queued | active | done | blocked | deferred" },
                },
            },
        }),
        json!({
            "name": "reorder_backlog_item",
            "description": "growlight: move a backlog item's row in the authoritative queue table \
                            in growlight/backlog/CLAUDE.md WITHOUT changing its status — the \
                            first-class way to reprioritize the drain order (don't abuse `deferred`). \
                            position is top|bottom|before|after; ref_id names the item to move \
                            before/after (required for before/after, omit for top/bottom). The # \
                            column re-renders to the new order. Idempotent: a move that doesn't \
                            change the order makes no commit. Identify items by queue id (milestone \
                            slug or task NNN).",
            "inputSchema": {
                "type": "object",
                "required": ["id", "position"],
                "properties": {
                    "id": { "type": "string", "description": "the item to move (milestone slug or task NNN)" },
                    "position": { "type": "string", "description": "top | bottom | before | after" },
                    "ref_id": { "type": "string", "description": "the item to move before/after (required for before/after; omit for top/bottom)" },
                },
            },
        }),
        json!({
            "name": "post_message",
            "description": "growlight: post a message to the coordination bus (the fleet's \
                            human-visible groupchat). Appends a numbered message under \
                            growlight/chat/messages/ addressed to an agent slug, @all (every \
                            agent's lane), or @human. kind is one of info | coord-request | \
                            lease-request | question | alert | restart-request. The daemon assigns \
                            the number and stamps the timestamp. Async turn-boundary: post at \
                            handoff, not mid-iteration.",
            "inputSchema": {
                "type": "object",
                "required": ["from", "to", "kind", "body"],
                "properties": {
                    "from": { "type": "string", "description": "sender: this agent's slug, or @human" },
                    "to": { "type": "string", "description": "addressee: an agent slug, @all, or @human" },
                    "kind": { "type": "string", "description": "info | coord-request | lease-request | question | alert | restart-request" },
                    "body": { "type": "string", "description": "the message text (non-empty)" },
                },
            },
        }),
        json!({
            "name": "read_inbox",
            "description": "growlight: read an agent's unread coordination-bus inbox — its lane \
                            messages (direct + @all, minus its own posts) numbered above its cursor, \
                            oldest first — and advance the cursor past them so the next read returns \
                            only newer messages. Read your inbox at boot. Returns a list of \
                            {number, from, to, kind, body, ts}.",
            "inputSchema": {
                "type": "object",
                "required": ["agent"],
                "properties": {
                    "agent": { "type": "string", "description": "the reading agent's slug" },
                },
            },
        }),
        json!({
            "name": "replace_file",
            "description": "BREAK-GLASS: overwrite a garden file with verbatim bytes — no \
                            convention stamping, so you hand-write the ENTIRE file (frontmatter, \
                            dates, headers, and all). Expensive and discouraged. Prefer the \
                            structural verbs, which stamp conventions and cost you only the new \
                            content: add_note/revise_note (notes), \
                            add_section/edit_section/append_to_section (any markdown doc), \
                            set_reviewed (date bumps), log_decision/log_incident/archive/\
                            add_project/refresh_snapshot (their kinds). Reach for replace_file \
                            only when no structural verb fits — e.g. creating or rewriting a \
                            monolithic CLAUDE.md/instructions.md/refs.md. Commits memory_edit.",
            "inputSchema": {
                "type": "object",
                "required": ["path", "content"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative path to overwrite" },
                    "content": { "type": "string", "description": "verbatim file bytes (you write the whole file)" },
                },
            },
        }),
    ]
}

/// Map an MCP tool name + arguments onto the IPC op + validated args.
/// Pure (no socket) so it's unit-testable; the typed `*Args` round-trip
/// rejects malformed arguments before we ever open the socket.
fn resolve_tool(name: &str, args: Value) -> Result<(&'static str, Value)> {
    let pair = match name {
        "replace_file" => {
            let a: ReplaceFileArgs = serde_json::from_value(args)?;
            (op::REPLACE_FILE, serde_json::to_value(a)?)
        }
        "log_decision" => {
            let a: LogDecisionArgs = serde_json::from_value(args)?;
            (op::LOG_DECISION, serde_json::to_value(a)?)
        }
        "log_incident" => {
            let a: LogIncidentArgs = serde_json::from_value(args)?;
            (op::LOG_INCIDENT, serde_json::to_value(a)?)
        }
        "add_note" => {
            let a: AddNoteArgs = serde_json::from_value(args)?;
            (op::ADD_NOTE, serde_json::to_value(a)?)
        }
        "revise_note" => {
            let a: ReviseNoteArgs = serde_json::from_value(args)?;
            (op::REVISE_NOTE, serde_json::to_value(a)?)
        }
        "edit_section" => {
            let a: EditSectionArgs = serde_json::from_value(args)?;
            (op::EDIT_SECTION, serde_json::to_value(a)?)
        }
        "append_to_section" => {
            let a: AppendToSectionArgs = serde_json::from_value(args)?;
            (op::APPEND_TO_SECTION, serde_json::to_value(a)?)
        }
        "add_section" => {
            let a: AddSectionArgs = serde_json::from_value(args)?;
            (op::ADD_SECTION, serde_json::to_value(a)?)
        }
        "set_reviewed" => {
            let a: SetReviewedArgs = serde_json::from_value(args)?;
            (op::SET_REVIEWED, serde_json::to_value(a)?)
        }
        "archive" => {
            let a: ArchiveArgs = serde_json::from_value(args)?;
            (op::ARCHIVE, serde_json::to_value(a)?)
        }
        "add_project" => {
            let a: AddProjectArgs = serde_json::from_value(args)?;
            (op::ADD_PROJECT, serde_json::to_value(a)?)
        }
        "refresh_snapshot" => {
            let a: RefreshSnapshotArgs = serde_json::from_value(args)?;
            (op::REFRESH_SNAPSHOT, serde_json::to_value(a)?)
        }
        "log_baton" => {
            let a: LogBatonArgs = serde_json::from_value(args)?;
            (op::LOG_BATON, serde_json::to_value(a)?)
        }
        "add_backlog_item" => {
            let a: AddBacklogItemArgs = serde_json::from_value(args)?;
            (op::ADD_BACKLOG_ITEM, serde_json::to_value(a)?)
        }
        "add_slice" => {
            let a: AddSliceArgs = serde_json::from_value(args)?;
            (op::ADD_SLICE, serde_json::to_value(a)?)
        }
        "set_item_status" => {
            let a: SetItemStatusArgs = serde_json::from_value(args)?;
            (op::SET_ITEM_STATUS, serde_json::to_value(a)?)
        }
        "reorder_backlog_item" => {
            let a: ReorderBacklogItemArgs = serde_json::from_value(args)?;
            (op::REORDER_BACKLOG_ITEM, serde_json::to_value(a)?)
        }
        "post_message" => {
            let a: PostMessageArgs = serde_json::from_value(args)?;
            (op::POST_MESSAGE, serde_json::to_value(a)?)
        }
        "read_inbox" => {
            let a: ReadInboxArgs = serde_json::from_value(args)?;
            (op::READ_INBOX, serde_json::to_value(a)?)
        }
        other => anyhow::bail!("unknown tool {other:?}"),
    };
    Ok(pair)
}

/// Render a human summary of a verb's success `data`. Handles every reply
/// shape in the tool surface (path / from+to / the `read_inbox` message list).
/// The MCP forwards only this text to the caller, so `read_inbox` must render
/// its messages here — that IS how an agent reads its inbox.
fn summarize(name: &str, data: &Value) -> String {
    if name == "read_inbox" {
        let msgs = data.get("messages").and_then(|v| v.as_array());
        return match msgs {
            Some(ms) if !ms.is_empty() => {
                let lines: Vec<String> = ms
                    .iter()
                    .map(|m| {
                        let g = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("?");
                        let n = m.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
                        format!(
                            "#{n} [{}] {} -> {}: {}",
                            g("kind"),
                            g("from"),
                            g("to"),
                            g("body")
                        )
                    })
                    .collect();
                format!("read_inbox: {} unread\n{}", ms.len(), lines.join("\n"))
            }
            _ => "read_inbox: inbox empty".to_string(),
        };
    }
    let hash = data.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
    if let (Some(from), Some(to)) = (
        data.get("from").and_then(|v| v.as_str()),
        data.get("to").and_then(|v| v.as_str()),
    ) {
        return format!("{name}: {from} -> {to}; commit {hash}");
    }
    if let Some(p) = data.get("path").and_then(|v| v.as_str()) {
        return format!("{name}: wrote {p}; commit {hash}");
    }
    format!("{name}: commit {hash}")
}

fn call_tool(params: &Value) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing tool name"))?;
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    let (op_name, ipc_args) = resolve_tool(name, args)?;

    // softfig-mcp holds no persistent keeperd connection — it connects per
    // request. A verb issued during a keeperd restart window (daemon
    // cycle/stop/start or a crash-respawn) would otherwise bubble up the
    // momentary socket outage as a hard error. `call_reconnecting` rides out a
    // transient restart with bounded backoff, retrying ONLY pre-send failures
    // (connect/write — provably not applied) and surfacing a post-send drop
    // distinctly so a committing verb is never blindly double-applied.
    let socket = softfig_ipc::runtime_socket_path();
    let req = Request::new(op_name, ipc_args);
    let resp = softfig_ipc::call_reconnecting(&socket, &req, softfig_ipc::RetryPolicy::default())?;
    match resp {
        Response::Ok { data, .. } => Ok(json!({
            "content": [{ "type": "text", "text": summarize(name, &data) }],
        })),
        Response::Err { error, kind, .. } => {
            anyhow::bail!("keeperd ({:?}): {}", kind, error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_list_has_nineteen() {
        let defs = tool_defs();
        assert_eq!(defs.len(), 19);
        let names: Vec<&str> = defs.iter().map(|d| d["name"].as_str().unwrap()).collect();
        for n in [
            "replace_file",
            "log_decision",
            "log_incident",
            "add_note",
            "revise_note",
            "edit_section",
            "append_to_section",
            "add_section",
            "set_reviewed",
            "archive",
            "add_project",
            "refresh_snapshot",
            "log_baton",
            "add_backlog_item",
            "add_slice",
            "set_item_status",
            "reorder_backlog_item",
            "post_message",
            "read_inbox",
        ] {
            assert!(names.contains(&n), "missing tool {n}");
        }
    }

    #[test]
    fn tools_list_via_handle_line() {
        let resp = handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 19);
    }

    #[test]
    fn resolve_tool_maps_each_name() {
        let cases = [
            (
                "log_decision",
                json!({ "slug": "x", "body": "b" }),
                op::LOG_DECISION,
            ),
            (
                "log_incident",
                json!({ "slug": "x", "summary": "s", "body": "b" }),
                op::LOG_INCIDENT,
            ),
            (
                "add_note",
                json!({ "dir": "services/waydroid/notes", "slug": "x", "body": "b" }),
                op::ADD_NOTE,
            ),
            (
                "revise_note",
                json!({ "dir": "services/waydroid/notes", "id": 3, "body": "b" }),
                op::REVISE_NOTE,
            ),
            (
                "edit_section",
                json!({ "path": "services/x/notes/001-a.md", "heading": "Foo", "body": "b" }),
                op::EDIT_SECTION,
            ),
            (
                "append_to_section",
                json!({ "path": "refs.md", "heading": "Cross-refs", "text": "- row" }),
                op::APPEND_TO_SECTION,
            ),
            (
                "add_section",
                json!({ "path": "CLAUDE.md", "heading": "## New", "body": "b" }),
                op::ADD_SECTION,
            ),
            ("set_reviewed", json!({ "path": "notes.md" }), op::SET_REVIEWED),
            ("archive", json!({ "src": "a/b" }), op::ARCHIVE),
            ("add_project", json!({ "name": "x" }), op::ADD_PROJECT),
            (
                "refresh_snapshot",
                json!({ "path": "snapshots/x", "content": "c" }),
                op::REFRESH_SNAPSHOT,
            ),
            (
                "log_baton",
                json!({ "item": "m5b", "iteration": 7, "summary": "shipped the pipe" }),
                op::LOG_BATON,
            ),
            (
                "add_backlog_item",
                json!({ "item_type": "task", "slug": "sigterm-unmount", "title": "t", "mission": "m", "finish_criteria": "f" }),
                op::ADD_BACKLOG_ITEM,
            ),
            (
                "add_slice",
                json!({ "milestone": "m5b", "slug": "secure-pipe", "body": "b" }),
                op::ADD_SLICE,
            ),
            (
                "set_item_status",
                json!({ "id": "m5b", "status": "active" }),
                op::SET_ITEM_STATUS,
            ),
            (
                "reorder_backlog_item",
                json!({ "id": "010", "position": "before", "ref_id": "005" }),
                op::REORDER_BACKLOG_ITEM,
            ),
            (
                "post_message",
                json!({ "from": "roudy", "to": "@all", "kind": "info", "body": "hi" }),
                op::POST_MESSAGE,
            ),
            (
                "read_inbox",
                json!({ "agent": "roudy" }),
                op::READ_INBOX,
            ),
            (
                "replace_file",
                json!({ "path": "p", "content": "c" }),
                op::REPLACE_FILE,
            ),
        ];
        for (name, args, want) in cases {
            let (got, _) = resolve_tool(name, args).expect(name);
            assert_eq!(got, want, "tool {name}");
        }
    }

    #[test]
    fn resolve_tool_rejects_unknown() {
        assert!(resolve_tool("nope", Value::Null).is_err());
    }

    #[test]
    fn summarize_shapes() {
        assert!(summarize("log_decision", &json!({ "path": "p", "hash": "h" }))
            .contains("wrote p"));
        assert!(summarize("archive", &json!({ "from": "a", "to": "b", "hash": "h" }))
            .contains("a -> b"));
        assert!(summarize("replace_file", &json!({ "path": "p", "hash": "h" })).contains("wrote p"));
        // post_message reports the written message doc.
        assert!(summarize(
            "post_message",
            &json!({ "number": 3, "path": "growlight/chat/messages/003-a-to-all.md", "hash": "h" })
        )
        .contains("wrote growlight/chat/messages/003-a-to-all.md"));
        // read_inbox renders the messages themselves (the MCP forwards only text).
        let inbox = summarize(
            "read_inbox",
            &json!({ "messages": [
                { "number": 2, "from": "roudy", "to": "@all", "kind": "info", "body": "rebased" },
            ] }),
        );
        assert!(inbox.contains("1 unread"));
        assert!(inbox.contains("#2 [info] roudy -> @all: rebased"));
        assert!(summarize("read_inbox", &json!({ "messages": [] })).contains("inbox empty"));
    }
}
