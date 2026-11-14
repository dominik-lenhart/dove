//! `dove mcp catalog`: a stdio MCP server that only describes Dove. It answers `initialize` and `tools/list` with
//! every tool Dove has, and refuses every tool call. It opens no mailbox, store, socket or network connection and
//! needs no credential, so registries (Glama builds the repository's `Dockerfile` and calls `tools/list`) can list
//! and score the tools of a server that otherwise only runs self-hosted.

use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, BufReader};

use super::stdio::{LineRead, read_line_bounded};
use crate::mcp::{STRUCTURED_SINCE, initialize_result, rpc_error, rpc_result};

const CALL_REFUSED: &str = "This is Dove's catalog mode: it lists the tools but has no mailboxes. Run your own Dove \
server (https://github.com/dominik-lenhart/dove#quickstart) and connect to it with `dove mcp stdio --profile <p>` \
or its /mcp URL.";

pub async fn run() -> anyhow::Result<()> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut version: &'static str = "";
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let reply = match read_line_bounded(&mut stdin, &mut buf).await? {
            LineRead::Eof => return Ok(()),
            LineRead::TooLong => Some(rpc_error(Value::Null, -32600, "message too large")),
            LineRead::Line => match std::str::from_utf8(&buf).map(str::trim) {
                Ok("") => None,
                Ok(text) => match serde_json::from_str::<Value>(text) {
                    Ok(msg) => answer(&msg, &mut version),
                    Err(_) => Some(rpc_error(Value::Null, -32700, "parse error")),
                },
                Err(_) => Some(rpc_error(Value::Null, -32700, "parse error")),
            },
        };
        if let Some(reply) = reply {
            stdout.write_all(format!("{reply}\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
}

/// One JSON-RPC message in, at most one response out. Notifications and client responses get none.
fn answer(msg: &Value, version: &mut &'static str) -> Option<Value> {
    let method = msg.get("method").and_then(Value::as_str)?;
    let id = msg.get("id").cloned()?;
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    Some(match method {
        "initialize" => {
            let (result, negotiated) = initialize_result(&params);
            *version = negotiated;
            rpc_result(id, result)
        }
        "ping" => rpc_result(id, json!({})),
        "tools/list" => rpc_result(id, json!({ "tools": crate::tools::catalog(*version >= STRUCTURED_SINCE) })),
        "tools/call" => {
            rpc_result(id, json!({ "isError": true, "content": [{ "type": "text", "text": CALL_REFUSED }] }))
        }
        "resources/list" => rpc_result(id, json!({ "resources": [] })),
        "prompts/list" => rpc_result(id, json!({ "prompts": [] })),
        _ => rpc_error(id, -32601, "method not found"),
    })
}
