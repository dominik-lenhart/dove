//! `dove mcp stdio`: bridges a local MCP host (newline-delimited JSON-RPC on stdin/stdout) to the remote Dove
//! Streamable HTTP endpoint with the profile's connection token (spec 5.6).
//!
//! stdout carries only protocol messages; diagnostics go to stderr. Lines and responses are size-bounded, at most
//! `MAX_IN_FLIGHT` requests run at once, `notifications/cancelled` aborts the matching in-flight request (its
//! response is dropped), and requests that never reached the server (connect errors) are retried. Requests that
//! may have reached the server are not replayed, so a draft write cannot be submitted twice by the bridge.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use super::remote::{self, MAX_RESPONSE_BYTES};

/// Largest request line from the MCP host: a create_draft with the largest allowed inline attachments
/// (`limits.draft_attachment_bytes` is at most 16 MiB, about 21.4 MiB as base64) plus the rest of the request.
pub const MAX_LINE_BYTES: usize = 24 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 8;
const CONNECT_RETRIES: u32 = 3;

struct Bridge {
    http: reqwest::Client,
    /// The server origin (checked before every request, P1) and its MCP endpoint.
    server: String,
    url: String,
    token: zeroize::Zeroizing<String>,
    /// Negotiated protocol version, sent as `MCP-Protocol-Version` after initialize.
    version: Mutex<Option<String>>,
    out: mpsc::Sender<String>,
}

fn rpc_error(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

fn id_key(id: &Value) -> String {
    id.to_string()
}

pub async fn run(server: &str, token: zeroize::Zeroizing<String>) -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::channel::<String>(64);
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(line) = rx.recv().await {
            if stdout.write_all(line.as_bytes()).await.is_err()
                || stdout.write_all(b"\n").await.is_err()
                || stdout.flush().await.is_err()
            {
                break;
            }
        }
    });
    let bridge = Arc::new(Bridge {
        http: remote::http_client()?,
        server: server.to_string(),
        url: format!("{server}/mcp"),
        token,
        version: Mutex::new(None),
        out: tx,
    });
    let in_flight: Arc<Mutex<HashMap<String, tokio::task::AbortHandle>>> = Arc::default();
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks = JoinSet::new();
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut buf = Vec::new();
    eprintln!("dove: bridging stdio to {server}/mcp");
    loop {
        buf.clear();
        match read_line_bounded(&mut stdin, &mut buf).await? {
            LineRead::Eof => break,
            LineRead::TooLong => {
                eprintln!("dove: dropped an input line larger than {MAX_LINE_BYTES} bytes");
                let _ = bridge.out.send(rpc_error(Value::Null, -32600, "message too large")).await;
                continue;
            }
            LineRead::Line => {}
        }
        let text = String::from_utf8_lossy(&buf);
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => {
                let _ = bridge.out.send(rpc_error(Value::Null, -32700, "parse error")).await;
                continue;
            }
        };
        if msg.get("method").and_then(Value::as_str) == Some("notifications/cancelled") {
            let key = id_key(&msg["params"]["requestId"]);
            if let Some(h) = in_flight.lock().expect("lock").remove(&key) {
                h.abort();
            }
            continue;
        }
        let id = msg.get("id").cloned().filter(|_| msg.get("method").is_some());
        let permit = permits.clone().acquire_owned().await.context("bridge stopped")?;
        let (b, flight) = (bridge.clone(), in_flight.clone());
        let key = id.as_ref().map(id_key);
        let handle = tasks.spawn(async move {
            let _permit = permit;
            forward(&b, msg, id.clone()).await;
            if let Some(k) = id.as_ref().map(id_key) {
                flight.lock().expect("lock").remove(&k);
            }
        });
        if let Some(k) = key {
            in_flight.lock().expect("lock").insert(k, handle);
        }
        while tasks.try_join_next().is_some() {}
        in_flight.lock().expect("lock").retain(|_, h| !h.is_finished());
    }
    // Input closed: let running requests finish (bounded), then flush the writer.
    let _ = tokio::time::timeout(Duration::from_secs(30), async { while tasks.join_next().await.is_some() {} }).await;
    tasks.abort_all();
    drop(bridge);
    let _ = writer.await;
    Ok(())
}

enum LineRead {
    Line,
    TooLong,
    Eof,
}

/// Reads one `\n`-terminated line into `buf` without buffering more than `MAX_LINE_BYTES` of it.
async fn read_line_bounded<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> anyhow::Result<LineRead> {
    let mut too_long = false;
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(if buf.is_empty() && !too_long {
                LineRead::Eof
            } else if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
        let (take, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if !too_long {
            if buf.len() + take > MAX_LINE_BYTES {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&chunk[..take]);
            }
        }
        r.consume(take);
        if done {
            return Ok(if too_long { LineRead::TooLong } else { LineRead::Line });
        }
    }
}

async fn forward(b: &Bridge, msg: Value, id: Option<Value>) {
    let is_initialize = msg.get("method").and_then(Value::as_str) == Some("initialize");
    let body = msg.to_string();
    let mut attempt = 0;
    let resp = loop {
        // Every attempt carries the bearer token: a plain-http loopback port must belong to this user (P1). Checked
        // again before each retry, because a retry follows a refused connection, when the port was free to take.
        if let Err(e) = super::loopback::check_server(&b.server) {
            eprintln!("dove: {e:#}");
            if let Some(id) = id {
                let _ = b
                    .out
                    .send(rpc_error(
                        id,
                        -32603,
                        "Dove refused to send the credential: the local server port is not held by this user",
                    ))
                    .await;
            }
            return;
        }
        let mut req = b
            .http
            .post(&b.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .bearer_auth(b.token.as_str())
            .body(body.clone());
        if let Some(v) = b.version.lock().expect("lock").clone().filter(|_| !is_initialize) {
            req = req.header("mcp-protocol-version", v);
        }
        match req.send().await {
            Ok(r) => break Ok(r),
            // A connect error means the request never reached the server, so it is safe to try again.
            Err(e) if e.is_connect() && attempt < CONNECT_RETRIES => {
                attempt += 1;
                eprintln!("dove: server unreachable, retrying ({attempt}/{CONNECT_RETRIES})");
                tokio::time::sleep(Duration::from_millis(250 * 2u64.pow(attempt))).await;
            }
            Err(e) => break Err(e),
        }
    };
    let reply = |code: i64, m: &str| id.clone().map(|id| rpc_error(id, code, m));
    let lines: Vec<String> = match resp {
        Err(e) => {
            eprintln!("dove: request failed: {}", e.without_url());
            reply(-32603, "the Dove server could not be reached").into_iter().collect()
        }
        Ok(r) => match r.status().as_u16() {
            202 => vec![],
            401 => {
                eprintln!("dove: the server rejected the credential; run `dove login` again");
                reply(
                    -32001,
                    "Dove rejected this connection's credential (revoked or expired). Run `dove login` again.",
                )
                .into_iter()
                .collect()
            }
            200 => {
                let ctype = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                match remote::read_bounded(r).await {
                    Err(e) => {
                        eprintln!("dove: {e}");
                        reply(-32603, &format!("response exceeded {MAX_RESPONSE_BYTES} bytes or failed"))
                            .into_iter()
                            .collect()
                    }
                    Ok(bytes) if ctype.starts_with("text/event-stream") => {
                        remote::sse_messages(&bytes).into_iter().map(|v| v.to_string()).collect()
                    }
                    Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(Value::Array(items)) => items.into_iter().map(|v| v.to_string()).collect(),
                        Ok(v) => {
                            if is_initialize && let Some(pv) = v["result"]["protocolVersion"].as_str() {
                                *b.version.lock().expect("lock") = Some(pv.to_string());
                            }
                            vec![v.to_string()]
                        }
                        Err(_) => reply(-32603, "invalid JSON from the Dove server").into_iter().collect(),
                    },
                }
            }
            s => {
                eprintln!("dove: server answered HTTP {s}");
                reply(-32603, &format!("the Dove server answered HTTP {s}")).into_iter().collect()
            }
        },
    };
    for l in lines {
        if b.out.send(l).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P1: the bridge checks the loopback port's owner before an attempt carries the token. Nothing listening is a
    /// refusal with its own message, not a connect error that is retried and reported as "could not be reached".
    #[cfg(any(target_os = "linux", windows))]
    #[tokio::test]
    async fn the_bridge_refuses_a_loopback_port_it_cannot_attribute() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (tx, mut rx) = mpsc::channel(4);
        let server = format!("http://127.0.0.1:{port}");
        let b = Bridge {
            http: remote::http_client().unwrap(),
            url: format!("{server}/mcp"),
            server,
            token: zeroize::Zeroizing::new("dove_test".into()),
            version: Mutex::new(None),
            out: tx,
        };
        let started = std::time::Instant::now();
        forward(&b, json!({"jsonrpc": "2.0", "id": 7, "method": "ping"}), Some(json!(7))).await;
        let reply: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(reply["id"], 7);
        assert!(reply["error"]["message"].as_str().unwrap().contains("refused to send the credential"), "{reply}");
        assert!(started.elapsed() < std::time::Duration::from_millis(400), "no connect retries");
    }

    #[tokio::test]
    async fn bounded_line_reader() {
        let mut data = vec![b'a'; MAX_LINE_BYTES + 10];
        data.push(b'\n');
        data.extend_from_slice(b"{\"x\":1}\nlast");
        let mut r = BufReader::with_capacity(1024, &data[..]);
        let mut buf = Vec::new();
        assert!(matches!(read_line_bounded(&mut r, &mut buf).await.unwrap(), LineRead::TooLong));
        assert!(buf.len() <= MAX_LINE_BYTES);
        buf.clear();
        assert!(matches!(read_line_bounded(&mut r, &mut buf).await.unwrap(), LineRead::Line));
        assert_eq!(buf, b"{\"x\":1}\n");
        buf.clear();
        assert!(matches!(read_line_bounded(&mut r, &mut buf).await.unwrap(), LineRead::Line));
        assert_eq!(buf, b"last");
        buf.clear();
        assert!(matches!(read_line_bounded(&mut r, &mut buf).await.unwrap(), LineRead::Eof));
    }
}
