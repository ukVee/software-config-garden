//! softfig-mcp — stateless stdio bridge translating MCP JSON-RPC tool
//! calls into IPC requests against a running `softfig-keeperd`.
//!
//! Spawned per Claude Code session. One method exposed for v1:
//! `propose_doc_update(summary, files, project)`.
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
        op, AddProjectArgs, ArchiveArgs, LogDecisionArgs, LogIncidentArgs,
        ProposeDocUpdateArgs, RefreshSnapshotArgs,
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
            "name": "propose_doc_update",
            "description": "Free-form escape hatch: propose a documentation update inside \
                            the soft-fig garden. The keeper daemon writes the verbatim files \
                            and creates a memory_edit commit. Prefer the typed verbs \
                            (log_decision, log_incident, archive, add_project, \
                            refresh_snapshot) when one fits — they stamp garden conventions \
                            for you.",
            "inputSchema": {
                "type": "object",
                "required": ["summary", "files", "project"],
                "properties": {
                    "summary": { "type": "string" },
                    "project": { "type": "string" },
                    "files": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["path", "content"],
                            "properties": {
                                "path": { "type": "string" },
                                "content": { "type": "string" },
                            },
                        },
                    },
                },
            },
        }),
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
    ]
}

/// Map an MCP tool name + arguments onto the IPC op + validated args.
/// Pure (no socket) so it's unit-testable; the typed `*Args` round-trip
/// rejects malformed arguments before we ever open the socket.
fn resolve_tool(name: &str, args: Value) -> Result<(&'static str, Value)> {
    let pair = match name {
        "propose_doc_update" => {
            let a: ProposeDocUpdateArgs = serde_json::from_value(args)?;
            (op::PROPOSE_DOC_UPDATE, serde_json::to_value(a)?)
        }
        "log_decision" => {
            let a: LogDecisionArgs = serde_json::from_value(args)?;
            (op::LOG_DECISION, serde_json::to_value(a)?)
        }
        "log_incident" => {
            let a: LogIncidentArgs = serde_json::from_value(args)?;
            (op::LOG_INCIDENT, serde_json::to_value(a)?)
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
        other => anyhow::bail!("unknown tool {other:?}"),
    };
    Ok(pair)
}

/// Render a one-line human summary of a verb's success `data`. Handles
/// every reply shape in the six-tool surface (path / from+to / files).
fn summarize(name: &str, data: &Value) -> String {
    let hash = data.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
    if let (Some(from), Some(to)) = (
        data.get("from").and_then(|v| v.as_str()),
        data.get("to").and_then(|v| v.as_str()),
    ) {
        return format!("{name}: {from} -> {to}; commit {hash}");
    }
    if let Some(n) = data.get("files_written").and_then(|v| v.as_u64()) {
        return format!("{name}: wrote {n} file(s); commit {hash}");
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

    let socket = softfig_ipc::runtime_socket_path();
    let mut stream = softfig_ipc::connect(&socket)
        .map_err(|e| anyhow::anyhow!("connect to keeperd at {}: {e}", socket.display()))?;
    let req = Request::new(op_name, ipc_args);
    let resp = softfig_ipc::call(&mut stream, &req)?;
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
    fn tools_list_has_six() {
        let defs = tool_defs();
        assert_eq!(defs.len(), 6);
        let names: Vec<&str> = defs.iter().map(|d| d["name"].as_str().unwrap()).collect();
        for n in [
            "propose_doc_update",
            "log_decision",
            "log_incident",
            "archive",
            "add_project",
            "refresh_snapshot",
        ] {
            assert!(names.contains(&n), "missing tool {n}");
        }
    }

    #[test]
    fn tools_list_via_handle_line() {
        let resp = handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 6);
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
            ("archive", json!({ "src": "a/b" }), op::ARCHIVE),
            ("add_project", json!({ "name": "x" }), op::ADD_PROJECT),
            (
                "refresh_snapshot",
                json!({ "path": "snapshots/x", "content": "c" }),
                op::REFRESH_SNAPSHOT,
            ),
            (
                "propose_doc_update",
                json!({ "summary": "s", "files": [{ "path": "p", "content": "c" }], "project": "x" }),
                op::PROPOSE_DOC_UPDATE,
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
        assert!(
            summarize("propose_doc_update", &json!({ "files_written": 2, "hash": "h" }))
                .contains("2 file(s)")
        );
    }
}
