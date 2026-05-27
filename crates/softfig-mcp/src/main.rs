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
    verbs::{op, ProposeDocUpdateArgs, ProposeDocUpdateReply},
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
        "tools/list" => ok(id, json!({ "tools": [tool_def()] })),
        "tools/call" => match call_tool(&rpc.params) {
            Ok(v) => ok(id, v),
            Err(e) => err(id, -32000, e.to_string()),
        },
        other => err(id, -32601, format!("unknown method {other:?}")),
    }
}

fn tool_def() -> Value {
    json!({
        "name": "propose_doc_update",
        "description": "Propose a documentation update inside the soft-fig garden. \
                        The keeper daemon writes the files and creates a memory_edit commit.",
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
    })
}

fn call_tool(params: &Value) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing tool name"))?;
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    if name != "propose_doc_update" {
        anyhow::bail!("unknown tool {name:?}");
    }
    let typed: ProposeDocUpdateArgs = serde_json::from_value(args)?;

    let socket = softfig_ipc::runtime_socket_path();
    let mut stream = softfig_ipc::connect(&socket)
        .map_err(|e| anyhow::anyhow!("connect to keeperd at {}: {e}", socket.display()))?;
    let req = Request::new(op::PROPOSE_DOC_UPDATE, serde_json::to_value(&typed)?);
    let resp = softfig_ipc::call(&mut stream, &req)?;
    match resp {
        Response::Ok { data, .. } => {
            let reply: ProposeDocUpdateReply = serde_json::from_value(data)?;
            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "wrote {} file(s); commit {}",
                        reply.files_written, reply.hash
                    ),
                }],
            }))
        }
        Response::Err { error, kind, .. } => {
            anyhow::bail!("keeperd ({:?}): {}", kind, error)
        }
    }
}
