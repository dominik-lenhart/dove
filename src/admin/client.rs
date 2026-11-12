//! CLI side of the admin socket. Sends one request, prints the response. Carries no authority of its own.

use std::path::Path;

use anyhow::{Context, bail};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::{AdminRequest, AdminResponse};

pub async fn send(socket: &Path, req: &AdminRequest) -> anyhow::Result<Value> {
    let stream = UnixStream::connect(socket).await.with_context(|| {
        format!(
            "cannot connect to the admin socket {} (is the service running and are you the operator?)",
            socket.display()
        )
    })?;
    let (rd, mut wr) = stream.into_split();
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    wr.write_all(&line).await?;
    wr.shutdown().await.ok();
    let mut reader = BufReader::new(rd);
    let mut resp = String::new();
    reader.read_line(&mut resp).await?;
    let resp: AdminResponse = serde_json::from_str(&resp).context("invalid response from admin socket")?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "request failed".into()));
    }
    Ok(resp.result.unwrap_or(Value::Null))
}
