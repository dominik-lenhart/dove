//! Operator-registered webhook sinks: push delivery of watch events (design 0.2 section 3).
//!
//! - Only the operator creates sinks (`dove sinks add <name> --url https://... --secret-file <path>`, admin socket).
//!   Agents see sink names only and can name one on a watch; they never supply a URL.
//! - The signing secret is sealed by the vault (kind `sink_secret`, scope = sink id) and re-wrapped by
//!   `dove keys rotate`, like account grants; the service never needs to read the operator's file again.
//! - Delivery is an HTTPS POST of the content-free event JSON through the gateway, which allows exactly the
//!   registered sink URLs. Headers: `Content-Type: application/json`, `Dove-Event-Id`, and
//!   `Dove-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`.
//! - A 2xx answer is success. Network errors, timeouts, 408, 429 and 5xx are retried with backoff
//!   ([`BACKOFF_SECS`]) up to [`MAX_ATTEMPTS`] attempts; any other status fails at once. Undelivered events stay
//!   readable with `list_watch_events`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use futures::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::EventRow;
use crate::admin::ops;
use crate::admin::server::AdminCall;
use crate::app::App;
use crate::gmail::gateway::{GatewayError, SinkUrl};
use crate::util;
use crate::vault::Vault;

/// Vault kind of a sealed sink secret (scope = sink id).
const SECRET_KIND: &str = "sink_secret";
/// Shortest accepted signing secret (for example `openssl rand -hex 32` gives 64 characters).
pub const MIN_SECRET_LEN: usize = 32;
pub const MAX_SECRET_LEN: usize = 1024;
/// Delivery attempts per event and sink, the first included.
pub const MAX_ATTEMPTS: i64 = 6;
/// Wait after the n-th failed attempt (n = 1..5).
pub const BACKOFF_SECS: [i64; 5] = [10, 60, 300, 1800, 7200];
/// Wall-clock bound of one POST, connection included.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Deliveries taken per tick, and how many run at once.
const BATCH: i64 = 50;
const CONCURRENCY: usize = 4;
pub const SIGNATURE_HEADER: &str = "dove-signature";
pub const EVENT_ID_HEADER: &str = "dove-event-id";

/// Hex HMAC-SHA256 over `"<timestamp>.<body>"`.
pub fn sign(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    util::hex(&mac.finalize().into_bytes())
}

/// The `Dove-Signature` header value.
pub fn signature_header(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    format!("t={timestamp},v1={}", sign(secret, timestamp, body))
}

// ------------------------------------------------------------------ admin verbs

/// `sinks add`: validates name, URL and secret, seals the secret and allowlists the URL.
pub async fn add(
    call: &mut AdminCall<'_>,
    name: String,
    url: String,
    secret: Zeroizing<String>,
) -> anyhow::Result<Value> {
    if !ops::valid_name(&name) {
        bail!("invalid sink name '{name}' (lowercase letters, digits, '-' and '_', up to 64 characters)");
    }
    let app = call.app.clone();
    let url =
        SinkUrl::parse(&url, app.google.gateway().plain_http_sinks()).map_err(|e| anyhow!("invalid --url: {e}"))?;
    let secret = secret.trim();
    if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&secret.len()) {
        bail!(
            "the sink secret must be {MIN_SECRET_LEN} to {MAX_SECRET_LEN} characters (for example openssl rand -hex 32)"
        );
    }
    let id = util::new_id();
    let sealed = app.vault.seal_aux(SECRET_KIND, &id, secret.as_bytes())?;
    let u = url.as_str().to_string();
    let v = call
        .tx(move |tx| {
            let exists: bool =
                tx.query_row("SELECT EXISTS(SELECT 1 FROM sinks WHERE name = ?1)", [&name], |r| r.get(0))?;
            if exists {
                bail!("a sink named '{name}' already exists; remove it first to change it");
            }
            let now = util::now_unix();
            tx.execute(
                "INSERT INTO sinks(id, name, url, secret, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, name, u, sealed, now],
            )?;
            Ok(json!({ "sink": name, "url": u, "created_at": util::rfc3339(now) }))
        })
        .await?;
    reload_allowlist(&app).await?;
    Ok(v)
}

/// `sinks list`: names, URLs and delivery counters (never the secret).
pub async fn list(call: &AdminCall<'_>) -> anyhow::Result<Value> {
    call.read(|c| {
        let mut st = c.prepare(
            "SELECT s.name, s.url, s.created_at, \
             (SELECT count(*) FROM watches w WHERE w.sink_id = s.id AND w.state = 'active'), \
             (SELECT count(*) FROM sink_deliveries d WHERE d.sink_id = s.id AND d.state = 'pending'), \
             (SELECT count(*) FROM sink_deliveries d WHERE d.sink_id = s.id AND d.state = 'delivered'), \
             (SELECT count(*) FROM sink_deliveries d WHERE d.sink_id = s.id AND d.state = 'failed') \
             FROM sinks s ORDER BY s.name",
        )?;
        let rows = st.query_map([], |r| {
            Ok(json!({
                "sink": r.get::<_, String>(0)?,
                "url": r.get::<_, String>(1)?,
                "created_at": util::rfc3339(r.get(2)?),
                "active_watches": r.get::<_, i64>(3)?,
                "pending": r.get::<_, i64>(4)?,
                "delivered": r.get::<_, i64>(5)?,
                "failed": r.get::<_, i64>(6)?,
            }))
        })?;
        Ok(Value::Array(rows.collect::<Result<_, _>>()?))
    })
    .await
}

/// `sinks remove`: watches that named the sink keep working without push; queued deliveries are dropped.
pub async fn remove(call: &mut AdminCall<'_>, name: String) -> anyhow::Result<Value> {
    let app = call.app.clone();
    let v = call
        .tx(move |tx| {
            let id: String = tx
                .query_row("SELECT id FROM sinks WHERE name = ?1", [&name], |r| r.get(0))
                .optional()?
                .ok_or_else(|| anyhow!("unknown sink '{name}'"))?;
            let watches: i64 = tx.query_row("SELECT count(*) FROM watches WHERE sink_id = ?1", [&id], |r| r.get(0))?;
            // ON DELETE: watches.sink_id becomes NULL, deliveries cascade.
            tx.execute("DELETE FROM sinks WHERE id = ?1", [&id])?;
            Ok(json!({ "sink": name, "removed": true, "watches_without_push": watches }))
        })
        .await?;
    reload_allowlist(&app).await?;
    Ok(v)
}

/// The registered sink URLs that still validate.
pub fn registered_urls(conn: &Connection, plain_loopback: bool) -> anyhow::Result<Vec<SinkUrl>> {
    let mut st = conn.prepare("SELECT url FROM sinks")?;
    let urls: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(urls.iter().filter_map(|u| SinkUrl::parse(u, plain_loopback).ok()).collect())
}

/// Installs the operator's current sink URLs as the gateway's sink allowlist.
pub async fn reload_allowlist(app: &Arc<App>) -> anyhow::Result<()> {
    let plain = app.google.gateway().plain_http_sinks();
    let urls = app.store.call(move |c| registered_urls(c, plain)).await?;
    app.google.gateway().set_sink_allowlist(urls);
    Ok(())
}

// ------------------------------------------------------------------ key rotation

fn blob_version(b: &[u8]) -> Option<u32> {
    b.get(..4).map(|v| u32::from_be_bytes(v.try_into().expect("4 bytes")))
}

/// Re-seals sink secrets and watch filters under the current KEK version (`dove keys rotate`). Returns how many
/// rows changed.
pub fn rewrap_sealed(tx: &Connection, vault: &Vault) -> anyhow::Result<usize> {
    let current = vault.current_kek_version();
    let mut n = 0;
    for (table, col, kind) in [("sinks", "secret", SECRET_KIND), ("watches", "filter", super::FILTER_KIND)] {
        let rows: Vec<(String, Vec<u8>)> = {
            let mut st = tx.prepare(&format!("SELECT id, {col} FROM {table} WHERE {col} IS NOT NULL"))?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
        };
        for (id, blob) in rows {
            if blob_version(&blob) == Some(current) {
                continue;
            }
            let plain = vault.open_aux(kind, &id, &blob)?;
            let sealed = vault.seal_aux(kind, &id, &plain)?;
            tx.execute(&format!("UPDATE {table} SET {col} = ?1 WHERE id = ?2"), params![sealed, id])?;
            n += 1;
        }
    }
    Ok(n)
}

/// KEK versions still used by sink secrets and watch filters.
pub fn sealed_versions(conn: &Connection) -> anyhow::Result<Vec<u32>> {
    let mut out = Vec::new();
    for sql in ["SELECT secret FROM sinks", "SELECT filter FROM watches WHERE filter IS NOT NULL"] {
        let mut st = conn.prepare(sql)?;
        for b in st.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            if let Some(v) = blob_version(&b?)
                && !out.contains(&v)
            {
                out.push(v);
            }
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------ delivery

/// What one [`deliver_due`] pass did.
#[derive(Debug, Default, Clone, Serialize)]
pub struct DeliveryReport {
    pub attempted: usize,
    pub delivered: usize,
    pub retrying: usize,
    pub failed: usize,
}

struct Due {
    event: EventRow,
    sink_id: String,
    sink_name: String,
    url: String,
    secret: Vec<u8>,
    attempts: i64,
}

enum Outcome {
    Delivered(u16),
    Retry(Option<u16>),
    Fail(Option<u16>),
}

/// Sends the deliveries due at `now` (unix seconds; tests pass a chosen clock) and records their outcome. The
/// signature timestamp is always the real time, so receivers can check freshness.
pub async fn deliver_due(app: &Arc<App>, now: i64) -> anyhow::Result<DeliveryReport> {
    let due: Vec<Due> = app
        .store
        .call(move |c| {
            let mut st = c.prepare_cached(&format!(
                "SELECT {}, d.sink_id, s.name, s.url, s.secret, d.attempts FROM sink_deliveries d \
                 JOIN watch_events e ON e.seq = d.event_seq JOIN accounts a ON a.id = e.account_id \
                 JOIN sinks s ON s.id = d.sink_id \
                 WHERE d.state = 'pending' AND d.next_attempt_at <= ?1 ORDER BY d.next_attempt_at, d.event_seq LIMIT ?2",
                EventRow::COLUMNS
            ))?;
            let rows = st.query_map(params![now, BATCH], |r| {
                Ok(Due {
                    event: EventRow::from_row(r)?,
                    sink_id: r.get(8)?,
                    sink_name: r.get(9)?,
                    url: r.get(10)?,
                    secret: r.get(11)?,
                    attempts: r.get(12)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await?;
    let mut report = DeliveryReport { attempted: due.len(), ..Default::default() };
    if due.is_empty() {
        return Ok(report);
    }
    let results: Vec<(i64, String, i64, Outcome)> = futures::stream::iter(due)
        .map(|d| async move {
            let outcome = deliver_one(app, &d).await;
            (d.event.seq, d.sink_id, d.attempts, outcome)
        })
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;
    for (_, _, _, o) in &results {
        match o {
            Outcome::Delivered(_) => report.delivered += 1,
            Outcome::Retry(_) => report.retrying += 1,
            Outcome::Fail(_) => report.failed += 1,
        }
    }
    app.store
        .call(move |c| {
            let tx = c.transaction()?;
            for (seq, sink, attempts, outcome) in results {
                let attempts = attempts + 1;
                let (state, status, next) = match outcome {
                    Outcome::Delivered(s) => ("delivered", Some(s), now),
                    Outcome::Retry(s) if attempts < MAX_ATTEMPTS => {
                        ("pending", s, now + BACKOFF_SECS[(attempts as usize - 1).min(BACKOFF_SECS.len() - 1)])
                    }
                    Outcome::Retry(s) | Outcome::Fail(s) => ("failed", s, now),
                };
                tx.execute(
                    "UPDATE sink_deliveries SET state = ?1, attempts = ?2, next_attempt_at = ?3, last_status = ?4, \
                     updated_at = ?5 WHERE event_seq = ?6 AND sink_id = ?7 AND state = 'pending'",
                    params![state, attempts, next, status, util::now_unix(), seq, sink],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(report)
}

async fn deliver_one(app: &Arc<App>, d: &Due) -> Outcome {
    let Ok(secret) = app.vault.open_aux(SECRET_KIND, &d.sink_id, &d.secret) else {
        tracing::error!(sink = %d.sink_name, "a sink secret could not be opened; delivery failed");
        return Outcome::Fail(None);
    };
    let body = match serde_json::to_vec(&d.event.to_json()) {
        Ok(b) => b,
        Err(_) => return Outcome::Fail(None),
    };
    let t = util::now_unix();
    let headers = [
        ("content-type", "application/json".to_string()),
        (EVENT_ID_HEADER, super::event_id(d.event.seq)),
        (SIGNATURE_HEADER, signature_header(&secret, t, &body)),
    ];
    let r = app.google.gateway().post_sink(&d.url, &headers, body, Instant::now() + DELIVERY_TIMEOUT).await;
    let outcome = match r {
        Ok(s) if (200..300).contains(&s) => Outcome::Delivered(s),
        Ok(s) if s == 408 || s == 429 || s >= 500 => Outcome::Retry(Some(s)),
        Ok(s) => Outcome::Fail(Some(s)),
        Err(GatewayError::NotAllowed) => Outcome::Fail(None),
        Err(_) => Outcome::Retry(None),
    };
    if !matches!(outcome, Outcome::Delivered(_)) {
        let status = match &outcome {
            Outcome::Retry(s) | Outcome::Fail(s) => *s,
            Outcome::Delivered(_) => None,
        };
        tracing::warn!(sink = %d.sink_name, status = ?status, attempt = d.attempts + 1, "sink delivery failed");
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_covers_timestamp_and_body() {
        // Reference value: printf '1700000000.{"a":1}' | openssl dgst -sha256 -hmac 'k'
        let s = sign(b"k", 1_700_000_000, br#"{"a":1}"#);
        assert_eq!(s, "1b6ad1bc9bf48c52ce01939866d5877c6cc4e87ddad27e16673cb8c4964394a3");
        assert_ne!(s, sign(b"k", 1_700_000_001, br#"{"a":1}"#));
        assert_ne!(s, sign(b"k", 1_700_000_000, br#"{"a":2}"#));
        assert_ne!(s, sign(b"k2", 1_700_000_000, br#"{"a":1}"#));
        assert_eq!(signature_header(b"k", 1_700_000_000, br#"{"a":1}"#), format!("t=1700000000,v1={s}"));
    }
}
