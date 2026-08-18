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
    growlightd::{ReleaseLeaseArgs, RequestLeaseArgs},
    verbs::{
        op, AddBacklogItemArgs, AddCodeReviewArgs, AddNoteArgs, AddProjectArgs, AddQueueArgs,
        AddSectionArgs, AddSliceArgs,
        AppendToSectionArgs, ArchiveArgs, BatchArgs, EditSectionArgs, FileProvenanceArgs,
        LogBatonArgs, LogDecisionArgs, LogIncidentArgs, PatchFileArgs, PostMessageArgs,
        ReadInboxArgs, ReadVersionsArgs, RemoveSectionArgs,
        RefreshSnapshotArgs, ReorderBacklogItemArgs, ReplaceFileArgs, ReviseNoteArgs,
        SetItemStatusArgs, SetReviewedArgs, UnlinkArgs,
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
            "name": "add_code_review",
            "description": "Record a code review as a durable numbered record in a code-reviews/ \
                            folder (primary home projects/<project>/code-reviews/). Same machinery \
                            as add_note: the daemon assigns NNN from the folder's .seq counter, \
                            writes dir/NNN-slug.md, and stamps the '# <title>' header + '> Last \
                            reviewed:' line. The body should follow the review template \
                            (journal/decisions/decision-softfig-code-review-records.md): a \
                            reviewer+scope line, then '## Verdict', '## Garden-standards \
                            adherence', '## Spec adherence', '## Gaps (not defects)', \
                            '## Deferred verification'.",
            "inputSchema": {
                "type": "object",
                "required": ["dir", "slug", "body"],
                "properties": {
                    "dir": { "type": "string", "description": "garden-relative code-reviews/ folder, e.g. projects/software-config_garden/code-reviews" },
                    "slug": { "type": "string", "description": "[a-z0-9-]+, 1-64; the terse filename address (immutable). Don't repeat a 'code-review-' prefix — the folder carries that semantic" },
                    "title": { "type": "string", "description": "header title; defaults to slug" },
                    "body": { "type": "string", "description": "markdown review body below the header, following the review template" },
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
                    "expected_version": { "type": "string", "description": "optional CAS guard: the section version you read (from read_file / a prior edit reply). The edit applies only if the section is unchanged, else Conflict. Omit for last-writer-wins." },
                    "editor": { "type": "string", "description": "optional per-agent identity for the contention detector (multi-agent fleets); an A↔B ping-pong on one section nudges the bus. Omit in single-agent mode." },
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
                    "expected_version": { "type": "string", "description": "optional CAS guard: the section version you read; applies only if unchanged, else Conflict. Omit for last-writer-wins." },
                    "editor": { "type": "string", "description": "optional per-agent identity for the contention detector (multi-agent fleets); see edit_section. Omit in single-agent mode." },
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
                            archive_move. archive_name defaults to the basename of src. \
                            Archive preserves + rewrites references; deliberate DELETION of an \
                            unreferenced leaf is unlink's job.",
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
                    "queue": { "type": "string", "description": "named work-stream queue to enqueue into; omit for the default queue. A named queue must be registered first via add_queue" },
                },
            },
        }),
        json!({
            "name": "add_queue",
            "description": "growlight: register a named work-stream queue with a bound repo path \
                            (the fleet scheduler's multi-queue model). Seeds the registry + an empty \
                            per-queue backlog table in growlight/backlog/CLAUDE.md, so several agents \
                            can drain different queues (projects). The default queue is implicit — \
                            don't register it. name is [a-z0-9-]+ (lowercase), not `default`.",
            "inputSchema": {
                "type": "object",
                "required": ["name", "repo"],
                "properties": {
                    "name": { "type": "string", "description": "[a-z0-9-]+, 1-64; the queue name (not `default`)" },
                    "repo": { "type": "string", "description": "the repo path the queue's parts build against (non-empty)" },
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
                    "queue": { "type": "string", "description": "which queue the item lives in; omit to locate it across all queues (pass only to disambiguate a cross-queue id collision)" },
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
                    "queue": { "type": "string", "description": "which queue the item lives in (reorder is per-queue); omit to locate it across all queues" },
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
            "name": "request_lease",
            "description": "growlight: request a supervisor-arbitrated lease over a shared \
                            resource/action (spec §4c). Dangerous shared work — a whole-file \
                            rewrite, restarting another agent, a build touching a shared dep — \
                            does NOT go through chat: you REQUEST a lease by an opaque key (for a \
                            contended garden section, the thrash target label 'path §heading'), \
                            and growlightd grants it, queues you behind the holder, or denies it. \
                            Agents never act on each other directly. Re-requesting is idempotent. \
                            Returns {key, state: granted|waiting|denied, holder, position}. \
                            Requires growlightd running (the fleet orchestrator).",
            "inputSchema": {
                "type": "object",
                "required": ["agent", "key"],
                "properties": {
                    "agent": { "type": "string", "description": "this agent's (work-stream) id" },
                    "key": { "type": "string", "description": "the lease key naming the shared resource/action (e.g. 'dock.rs §Layout')" },
                },
            },
        }),
        json!({
            "name": "release_lease",
            "description": "growlight: release a lease you hold (spec §4c), promoting the head \
                            waiter (if any) to holder so the resource is handed on. A release by a \
                            non-holder is refused (state: denied) and changes nothing. Returns \
                            {key, state: released|denied, holder} where holder is the promoted \
                            waiter, or null if the key is now free. Release as soon as the \
                            dangerous action completes.",
            "inputSchema": {
                "type": "object",
                "required": ["agent", "key"],
                "properties": {
                    "agent": { "type": "string", "description": "this agent's id (must be the current holder)" },
                    "key": { "type": "string", "description": "the lease key to release" },
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
                            add_code_review (code reviews), \
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
                    "expected_version": { "type": "string", "description": "optional CAS guard: the whole-file version you read; the write applies only if the file is unchanged (and still exists), else Conflict. Omit for last-writer-wins / create." },
                },
            },
        }),
        json!({
            "name": "file_provenance",
            "description": "Who & when last edited a garden path, plus its recent edit history — \
                            the contention-awareness query (spec §4d). Read-only, derived from \
                            commit history: each entry is {hash, author_device, timestamp, intent} \
                            for a commit that changed the path, most-recent-first (edits[0] is the \
                            last editor). Use before editing a hot file to see if another writer \
                            is active on it.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative path to trace" },
                    "limit": { "type": "integer", "description": "max recent edits to return (default 20)" },
                },
            },
        }),
        json!({
            "name": "read_versions",
            "description": "A garden file's current CAS version tokens, WITHOUT its content — a \
                            coordination primitive, not a content read (content reads stay native). \
                            Returns the whole-file version plus per-section versions computed over \
                            the daemon-redacted content, so you can seed an `expected_version` guard \
                            on the very first edit in a session (edit replies only hand back the \
                            NEW version, so without this verb the first version can only be learned \
                            by making an edit). Also flags whole-file-sealed paths, which the write \
                            verbs refuse. Read-only.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative file to project versions for" },
                },
            },
        }),
        json!({
            "name": "patch_file",
            "description": "Surgical old→new exact string replacement in a garden file — the \
                            opencode-Edit-tool model, keeperd-mediated. `old` must occur exactly \
                            once within the search window (the whole file, or the `anchor`'s line \
                            range when given): zero matches → TextNotFound, several → TextAmbiguous \
                            (narrow it with `anchor`). Exact match only, no whitespace \
                            normalization. `new` may be empty to delete the matched text. \
                            Whole-file CAS via `expected_version` (seed it from read_versions / a \
                            prior reply). Refused on vault-sealed targets. Whole-section deletion \
                            is remove_section's job; whole-file deletion is unlink's.",
            "inputSchema": {
                "type": "object",
                "required": ["path", "old", "new"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative file to patch" },
                    "old": { "type": "string", "description": "exact text to replace (may be multi-line); must occur exactly once within the search window" },
                    "new": { "type": "string", "description": "replacement text; may be empty to delete the matched text" },
                    "expected_version": { "type": "string", "description": "optional whole-file CAS guard: the version you read (from read_versions / a prior reply). Applies only if the file is unchanged, else Conflict. Omit for last-writer-wins." },
                    "anchor": { "type": "string", "description": "optional disambiguator: a string occurring exactly once in the file; its line range becomes the search window for `old`" },
                    "editor": { "type": "string", "description": "optional per-agent identity for the contention detector (multi-agent fleets); see edit_section. Omit in single-agent mode." },
                },
            },
        }),
        json!({
            "name": "remove_section",
            "description": "Delete one section of a garden file by heading address — the delete \
                            counterpart to add_section/edit_section. The heading text must match \
                            exactly one heading (case-sensitive, level-agnostic; a '#' prefix is \
                            optional); the whole section goes (heading line + body, subsections \
                            included) — you emit no content, the daemon owns the deletion window. \
                            Section-level CAS via `expected_version` (seed it from read_versions \
                            / a prior edit reply): the guard proves you're deleting what you read. \
                            Refused when the section is the file's last remaining heading (unlink \
                            the file instead), when the deletion would touch a daemon-managed \
                            `<!-- softfig:index -->` region, and on vault-sealed targets.",
            "inputSchema": {
                "type": "object",
                "required": ["path", "heading"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative file to delete a section from" },
                    "heading": { "type": "string", "description": "the section to delete, addressed like edit_section ('#' prefix optional, case-sensitive, level-agnostic); must be unique" },
                    "expected_version": { "type": "string", "description": "optional section-level CAS guard: the version you read for this heading (from read_versions / a prior reply). Deletes only if the section is unchanged, else Conflict. Omit for last-writer-wins." },
                    "editor": { "type": "string", "description": "optional per-agent identity for the contention detector (multi-agent fleets); see edit_section. Omit in single-agent mode." },
                },
            },
        }),
        json!({
            "name": "unlink",
            "description": "Delete one garden FILE — the deliberate, guarded exception to the \
                            garden's don't-delete-archive rule. Files only (no directories, no \
                            recursion). Refused (ReferencedElsewhere) when the file is listed in a \
                            daemon-managed <!-- softfig:index --> region or has inbound [[…]] \
                            backlinks — unlink can only cut an unreferenced leaf; for anything \
                            referenced use `archive`, which preserves it and rewrites the \
                            references. Vault-sealed targets ARE deletable; the deleted bytes stay \
                            recoverable from history (softfig show <hash> / rollback). Optional \
                            whole-file CAS via `expected_version` (seed it from read_versions).",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "garden-relative FILE to delete (a leaf nothing points at)" },
                    "expected_version": { "type": "string", "description": "optional whole-file CAS guard: the version you read (from read_versions / a prior reply). Deletes only if the file is unchanged, else Conflict. Omit for last-writer-wins." },
                    "editor": { "type": "string", "description": "optional per-agent identity for the contention detector (multi-agent fleets); see edit_section. Omit in single-agent mode." },
                },
            },
        }),
        json!({
            "name": "batch",
            "description": "Atomic multi-op commit: apply several file-mutation sub-ops as ONE commit — \
                            all-or-nothing. `ops` runs in order against one working state (op N sees \
                            op N−1's result, so two ops on the same file compose). EVERY op is validated \
                            (args shape, path, vault refusal, CAS, uniqueness) BEFORE anything is \
                            written; any failure aborts the whole batch with nothing changed and the \
                            error names the failing op index + kind. WHITELIST (v1): patch_file, \
                            edit_section, append_to_section, add_section, remove_section, set_reviewed, \
                            add_note, revise_note. Refused sub-ops: batch itself (no nesting), unlink, \
                            archive, add_project, log_decision, log_incident, and every growlight verb. \
                            Each sub-op may carry its own expected_version (whole-file or section, per \
                            that verb's contract). One batch_applied commit; the reply is the commit \
                            hash + the deduped mutated paths.",
            "inputSchema": {
                "type": "object",
                "required": ["ops"],
                "properties": {
                    "ops": {
                        "type": "array",
                        "description": "ordered sub-ops; each is {op: <whitelisted name>, args: <that verb's typed args>}",
                        "items": {
                            "type": "object",
                            "required": ["op", "args"],
                            "properties": {
                                "op": { "type": "string", "description": "patch_file | edit_section | append_to_section | add_section | remove_section | set_reviewed | add_note | revise_note" },
                                "args": { "type": "object", "description": "that verb's own args shape (see its tool description)" },
                            },
                        },
                    },
                    "editor": { "type": "string", "description": "optional per-agent identity for the contention detector (multi-agent fleets); propagated to every sub-op. Omit in single-agent mode." },
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
        "add_code_review" => {
            let a: AddCodeReviewArgs = serde_json::from_value(args)?;
            (op::ADD_CODE_REVIEW, serde_json::to_value(a)?)
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
        "add_queue" => {
            let a: AddQueueArgs = serde_json::from_value(args)?;
            (op::ADD_QUEUE, serde_json::to_value(a)?)
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
        "file_provenance" => {
            let a: FileProvenanceArgs = serde_json::from_value(args)?;
            (op::FILE_PROVENANCE, serde_json::to_value(a)?)
        }
        "read_versions" => {
            let a: ReadVersionsArgs = serde_json::from_value(args)?;
            (op::READ_VERSIONS, serde_json::to_value(a)?)
        }
        "patch_file" => {
            let a: PatchFileArgs = serde_json::from_value(args)?;
            (op::PATCH_FILE, serde_json::to_value(a)?)
        }
        "remove_section" => {
            let a: RemoveSectionArgs = serde_json::from_value(args)?;
            (op::REMOVE_SECTION, serde_json::to_value(a)?)
        }
        "unlink" => {
            let a: UnlinkArgs = serde_json::from_value(args)?;
            (op::UNLINK, serde_json::to_value(a)?)
        }
        "batch" => {
            let a: BatchArgs = serde_json::from_value(args)?;
            (op::BATCH, serde_json::to_value(a)?)
        }
        "request_lease" => {
            let a: RequestLeaseArgs = serde_json::from_value(args)?;
            (op::REQUEST_LEASE, serde_json::to_value(a)?)
        }
        "release_lease" => {
            let a: ReleaseLeaseArgs = serde_json::from_value(args)?;
            (op::RELEASE_LEASE, serde_json::to_value(a)?)
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
    if name == "file_provenance" {
        let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let edits = data.get("edits").and_then(|v| v.as_array());
        return match edits {
            Some(es) if !es.is_empty() => {
                let lines: Vec<String> = es
                    .iter()
                    .map(|e| {
                        let g = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("?");
                        let ts = e.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
                        let h = g("hash");
                        let short = &h[..h.len().min(8)];
                        format!("{short} [{}] {} @ {ts}", g("intent"), g("author_device"))
                    })
                    .collect();
                format!("file_provenance {path}: {} edit(s)\n{}", es.len(), lines.join("\n"))
            }
            _ => format!("file_provenance {path}: no recorded edits"),
        };
    }
    if name == "read_versions" {
        // A coordination primitive: render the version tokens (the whole point),
        // not content. Callers feed these straight into `expected_version` guards.
        let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let version = data.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let sealed = data.get("sealed").and_then(|v| v.as_bool()).unwrap_or(false);
        let flag = if sealed { " (sealed)" } else { "" };
        let sections = data.get("sections").and_then(|v| v.as_array());
        let sec_lines: Vec<String> = sections
            .map(|ss| {
                ss.iter()
                    .map(|s| {
                        let g = |k: &str| s.get(k).and_then(|v| v.as_str()).unwrap_or("?");
                        format!("  {}: {}", g("heading"), g("version"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if sec_lines.is_empty() {
            return format!("read_versions {path}: {version}{flag}");
        }
        return format!("read_versions {path}: {version}{flag}\n{}", sec_lines.join("\n"));
    }
    if name == "request_lease" || name == "release_lease" {
        let g = |k: &str| data.get(k).and_then(|v| v.as_str()).unwrap_or("?");
        let key = g("key");
        let state = g("state");
        let mut detail = String::new();
        if let Some(h) = data.get("holder").and_then(|v| v.as_str()) {
            detail.push_str(&format!(" (holder {h})"));
        } else if state == "released" {
            detail.push_str(" (free)");
        }
        if let Some(p) = data.get("position").and_then(|v| v.as_u64()) {
            detail.push_str(&format!(" [position {p}]"));
        }
        if let Some(r) = data.get("reason").and_then(|v| v.as_str()) {
            detail.push_str(&format!(" — {r}"));
        }
        return format!("{name} {key}: {state}{detail}");
    }
    if name == "remove_section" {
        // A deletion, not a "wrote": the generic write summary would mislead.
        let p = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let hash = data.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
        return match data.get("version").and_then(|v| v.as_str()) {
            Some(v) if !v.is_empty() => {
                format!("remove_section: removed the section from {p}; commit {hash}; version {v}")
            }
            _ => format!("remove_section: removed the section from {p}; commit {hash}"),
        };
    }
    if name == "unlink" {
        // A deletion, not a "wrote"; there is no post-delete version to chain.
        let p = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let hash = data.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
        return format!("unlink: deleted {p}; commit {hash}");
    }
    if name == "batch" {
        // An atomic multi-op commit: the op count + the deduped paths it
        // touched (one commit hash — that's the whole point).
        let hash = data.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
        let ops = data.get("ops").and_then(|v| v.as_u64()).unwrap_or(0);
        let paths = data
            .get("paths")
            .and_then(|v| v.as_array())
            .map(|ps| {
                ps.iter()
                    .map(|p| p.as_str().unwrap_or("?").to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        return format!("batch: {ops} op(s) applied to {paths}; commit {hash}");
    }
    let hash = data.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
    if let (Some(from), Some(to)) = (
        data.get("from").and_then(|v| v.as_str()),
        data.get("to").and_then(|v| v.as_str()),
    ) {
        return format!("{name}: {from} -> {to}; commit {hash}");
    }
    if let Some(p) = data.get("path").and_then(|v| v.as_str()) {
        // CAS verbs also hand back the post-edit content version (feed it as the
        // next `expected_version`); surface it when present.
        return match data.get("version").and_then(|v| v.as_str()) {
            Some(v) if !v.is_empty() => format!("{name}: wrote {p}; commit {hash}; version {v}"),
            _ => format!("{name}: wrote {p}; commit {hash}"),
        };
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
    fn tools_list_has_twenty_nine() {
        let defs = tool_defs();
        assert_eq!(defs.len(), 29);
        let names: Vec<&str> = defs.iter().map(|d| d["name"].as_str().unwrap()).collect();
        for n in [
            "replace_file",
            "log_decision",
            "log_incident",
            "add_note",
            "revise_note",
            "add_code_review",
            "edit_section",
            "append_to_section",
            "add_section",
            "set_reviewed",
            "archive",
            "add_project",
            "refresh_snapshot",
            "log_baton",
            "add_backlog_item",
            "add_queue",
            "add_slice",
            "set_item_status",
            "reorder_backlog_item",
            "post_message",
            "read_inbox",
            "file_provenance",
            "read_versions",
            "patch_file",
            "remove_section",
            "unlink",
            "batch",
            "request_lease",
            "release_lease",
        ] {
            assert!(names.contains(&n), "missing tool {n}");
        }
    }

    #[test]
    fn tools_list_via_handle_line() {
        let resp = handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 29);
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
                "add_code_review",
                json!({ "dir": "projects/demo/code-reviews", "slug": "fleet-loop-spin", "body": "b" }),
                op::ADD_CODE_REVIEW,
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
                "add_queue",
                json!({ "name": "softfig", "repo": "~/projects/software-config_garden" }),
                op::ADD_QUEUE,
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
                "file_provenance",
                json!({ "path": "meta/conventions.md" }),
                op::FILE_PROVENANCE,
            ),
            (
                "read_versions",
                json!({ "path": "meta/conventions.md" }),
                op::READ_VERSIONS,
            ),
            (
                "patch_file",
                json!({ "path": "doc.md", "old": "was", "new": "now", "anchor": "## S", "expected_version": "abc", "editor": "a" }),
                op::PATCH_FILE,
            ),
            (
                "remove_section",
                json!({ "path": "doc.md", "heading": "Old", "expected_version": "abc", "editor": "a" }),
                op::REMOVE_SECTION,
            ),
            (
                "unlink",
                json!({ "path": "junk.md", "expected_version": "abc", "editor": "a" }),
                op::UNLINK,
            ),
            (
                "batch",
                json!({ "ops": [
                    { "op": "patch_file", "args": { "path": "a.md", "old": "x", "new": "y" } },
                    { "op": "set_reviewed", "args": { "path": "b.md" } },
                ], "editor": "a" }),
                op::BATCH,
            ),
            (
                "request_lease",
                json!({ "agent": "roudy", "key": "dock.rs §Layout" }),
                op::REQUEST_LEASE,
            ),
            (
                "release_lease",
                json!({ "agent": "roudy", "key": "dock.rs §Layout" }),
                op::RELEASE_LEASE,
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
        // CAS verbs surface the post-edit version alongside the commit.
        assert!(summarize("edit_section", &json!({ "path": "p", "hash": "h", "version": "deadbeef" }))
            .contains("version deadbeef"));
        assert!(summarize("patch_file", &json!({ "path": "p", "hash": "h", "version": "cafe" }))
            .contains("wrote p") && summarize("patch_file", &json!({ "path": "p", "hash": "h", "version": "cafe" }))
            .contains("version cafe"));
        // remove_section renders a deletion, not a "wrote".
        let rm = summarize("remove_section", &json!({ "path": "p", "hash": "h", "version": "cafe" }));
        assert!(rm.contains("removed the section from p") && rm.contains("version cafe"));
        // unlink renders a deletion, not a "wrote"; no version to chain.
        assert_eq!(
            summarize("unlink", &json!({ "path": "p", "hash": "h" })),
            "unlink: deleted p; commit h"
        );
        // batch renders the atomic multi-op shape: op count + paths + hash.
        assert_eq!(
            summarize(
                "batch",
                &json!({ "hash": "h", "ops": 2, "paths": ["a.md", "b.md"] })
            ),
            "batch: 2 op(s) applied to a.md, b.md; commit h"
        );
        // file_provenance renders its edit list (the MCP forwards only text).
        let prov = summarize(
            "file_provenance",
            &json!({ "path": "meta/x.md", "edits": [
                { "hash": "abcdef1234", "author_device": "tablet", "timestamp": 1782000000, "intent": "section_edited" },
            ] }),
        );
        assert!(prov.contains("1 edit(s)"));
        assert!(prov.contains("abcdef12 [section_edited] tablet"));
        assert!(summarize("file_provenance", &json!({ "path": "p", "edits": [] })).contains("no recorded edits"));
        // read_versions renders the version tokens (the whole point) — and must
        // NOT fall through to the generic "wrote …; commit ?" shape.
        let rv = summarize(
            "read_versions",
            &json!({ "path": "meta/x.md", "version": "abc123", "sections": [
                { "heading": "Child", "version": "def456" },
                { "heading": "Cross-refs", "version": "789aaa" },
            ], "sealed": false }),
        );
        assert!(rv.contains("read_versions meta/x.md: abc123"));
        assert!(rv.contains("  Child: def456"));
        assert!(rv.contains("  Cross-refs: 789aaa"));
        assert!(!rv.contains("wrote"), "read_versions must not use the write summary: {rv}");
        assert_eq!(
            summarize("read_versions", &json!({ "path": "s", "version": "v", "sections": [], "sealed": true })),
            "read_versions s: v (sealed)"
        );
        // lease replies render key + state + holder/position/reason (no commit hash).
        assert_eq!(
            summarize("request_lease", &json!({ "key": "dock.rs §Layout", "state": "granted", "holder": "a" })),
            "request_lease dock.rs §Layout: granted (holder a)"
        );
        assert_eq!(
            summarize("request_lease", &json!({ "key": "k", "state": "waiting", "holder": "a", "position": 2 })),
            "request_lease k: waiting (holder a) [position 2]"
        );
        assert_eq!(
            summarize("release_lease", &json!({ "key": "k", "state": "released" })),
            "release_lease k: released (free)"
        );
        assert_eq!(
            summarize("release_lease", &json!({ "key": "k", "state": "released", "holder": "b" })),
            "release_lease k: released (holder b)"
        );
        assert_eq!(
            summarize("release_lease", &json!({ "key": "k", "state": "denied", "reason": "only the lease holder may release it" })),
            "release_lease k: denied — only the lease holder may release it"
        );
    }
}
