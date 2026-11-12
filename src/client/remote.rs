//! HTTP calls from the client to a Dove server: invitation redemption, revocation, health and MCP tool calls.
//! Only the connection's bearer token is ever sent; nothing here knows about the admin socket.

use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Responses larger than this are refused (bounded buffers).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub fn http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("dove-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("cannot build HTTP client")
}

/// Reads a response body with a size cap.
pub async fn read_bounded(mut resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len() + chunk.len() > MAX_RESPONSE_BYTES {
            bail!("response from the server is too large");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

pub struct Remote {
    pub http: reqwest::Client,
    pub server: String,
    pub token: Zeroizing<String>,
}

/// Outcome of one tool call as the CLI presents it.
pub struct ToolResult {
    pub is_error: bool,
    pub structured: Value,
    pub text: String,
}

impl Remote {
    pub fn new(server: &str, token: Zeroizing<String>) -> anyhow::Result<Self> {
        Ok(Self { http: http_client()?, server: server.to_string(), token })
    }

    /// One JSON-RPC request to `/mcp` (stateless Streamable HTTP). Returns the JSON-RPC response object.
    pub async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .http
            .post(format!("{}/mcp", self.server))
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .bearer_auth(self.token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("cannot reach the Dove server at {} ({})", self.server, e.without_url()))?;
        match resp.status().as_u16() {
            200 => {}
            401 => bail!(
                "the server rejected this connection's credential (revoked, expired or not allowed from this \
                 address); ask the operator for a new invitation and run `dove login` again"
            ),
            429 => bail!("rate limited by the server; try again shortly"),
            s => bail!("unexpected HTTP status {s} from the server"),
        }
        let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let bytes = read_bounded(resp).await?;
        let v: Value = if ctype.starts_with("text/event-stream") {
            sse_messages(&bytes).into_iter().find(|m| m.get("id").is_some()).ok_or_else(|| anyhow!("empty response"))?
        } else {
            serde_json::from_slice(&bytes).context("invalid JSON from the server")?
        };
        if let Some(e) = v.get("error") {
            bail!("server error: {}", e["message"].as_str().unwrap_or("unknown"));
        }
        Ok(v)
    }

    pub async fn call_tool(&self, name: &str, args: Value) -> anyhow::Result<ToolResult> {
        let v = self.rpc("tools/call", json!({ "name": name, "arguments": args })).await?;
        let r = &v["result"];
        let text = r["content"]
            .as_array()
            .map(|c| c.iter().filter_map(|i| i["text"].as_str()).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        let structured = r
            .get("structuredContent")
            .cloned()
            .unwrap_or_else(|| serde_json::from_str(&text).unwrap_or(Value::String(text.clone())));
        Ok(ToolResult { is_error: r["isError"].as_bool().unwrap_or(false), structured, text })
    }

    pub async fn tool_names(&self) -> anyhow::Result<Vec<String>> {
        let v = self.rpc("tools/list", json!({})).await?;
        Ok(v["result"]["tools"]
            .as_array()
            .map(|t| t.iter().filter_map(|t| t["name"].as_str().map(str::to_string)).collect())
            .unwrap_or_default())
    }

    /// Effective mailboxes and actions of this connection (via `list_accounts`).
    pub async fn rights(&self) -> anyhow::Result<Vec<Value>> {
        let r = self.call_tool("list_accounts", json!({})).await?;
        if r.is_error {
            bail!("list_accounts failed: {}", r.text);
        }
        Ok(r.structured["accounts"].as_array().cloned().unwrap_or_default())
    }

    /// Revokes this connection on the server (RFC 7009 endpoint, possession of the token suffices).
    pub async fn revoke_self(&self) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/oauth/dove/revoke", self.server))
            .form(&[("token", self.token.as_str()), ("token_type_hint", "access_token")])
            .send()
            .await
            .map_err(|e| anyhow!("cannot reach the server to revoke ({})", e.without_url()))?;
        if !resp.status().is_success() {
            bail!("the server refused the revocation (HTTP {})", resp.status().as_u16());
        }
        Ok(())
    }
}

/// POST `/connect/redeem`. The invitation travels only in the body.
pub async fn redeem(server: &str, invitation: &str) -> anyhow::Result<Value> {
    let http = http_client()?;
    let resp = http
        .post(format!("{server}/connect/redeem"))
        .json(&json!({ "invitation": invitation }))
        .send()
        .await
        .map_err(|e| anyhow!("cannot reach the Dove server at {server} ({})", e.without_url()))?;
    let status = resp.status().as_u16();
    let bytes = read_bounded(resp).await?;
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    match status {
        200 => Ok(v),
        429 => bail!("too many attempts; wait a minute and try again"),
        400 => {
            bail!("{}", v["error_description"].as_str().unwrap_or("the invitation is invalid, expired or already used"))
        }
        s => bail!("unexpected HTTP status {s} from the server"),
    }
}

/// Splits a `text/event-stream` body into its JSON `data` messages.
pub fn sse_messages(body: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();
    let mut data = String::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if !data.is_empty() {
                if let Ok(v) = serde_json::from_str(&data) {
                    out.push(v);
                }
                data.clear();
            }
        } else if let Some(d) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(d.strip_prefix(' ').unwrap_or(d));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn sse_parsing() {
        let body = b"event: message\ndata: {\"id\":1,\n data: \"result\":{}}\n\n: comment\ndata: {\"id\":2}\n";
        let msgs = super::sse_messages(body);
        assert_eq!(msgs.len(), 1, "a continuation line without data: prefix is not part of the payload");
        let body = b"data: {\"id\":1,\ndata: \"result\":{}}\n\ndata: {\"id\":2}\n";
        let msgs = super::sse_messages(body);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1]["id"], 2);
    }
}
