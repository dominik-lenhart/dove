//! CLI side of the admin socket. Sends one request, prints the response. Carries no authority of its own.

use std::path::Path;

use anyhow::{Context, bail};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::{AdminRequest, AdminResponse};

pub async fn send(socket: &Path, req: &AdminRequest) -> anyhow::Result<Value> {
    let stream = super::transport::connect(socket).await?;
    let (rd, mut wr) = tokio::io::split(stream);
    // The request may carry a mailbox password: wipe the serialized copy after sending.
    // No push onto the buffer: a reallocation would leave an unwiped copy behind.
    let line = zeroize::Zeroizing::new(serde_json::to_vec(req)?);
    wr.write_all(&line).await?;
    wr.write_all(b"\n").await?;
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
