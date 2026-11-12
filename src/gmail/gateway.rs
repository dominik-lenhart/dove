//! Outbound gateway: the single HTTP client to Google (spec 7.1, 7.5, 7.7).
//!
//! Requests can only be expressed through [`GmailOp`], whose variants are exactly the allowlisted method/path pairs.
//! Path segments are validated, redirects are disabled and origins are fixed per [`Upstream`]. `drafts.send` needs a
//! [`SendPermit`], which only the gated send path can create.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::Limits;
use crate::util;

/// Upper bound for any Gmail response body: a 25 MiB raw message (the MIME parser's limit) base64url-encoded, plus
/// its JSON envelope. Bodies are streamed and counted; a larger one is an error, never a partial parse.
pub const MAX_RESPONSE_BYTES: usize = 40 * 1024 * 1024;
/// Upper bound for error bodies (only the reason is read) and for token/certificate responses.
const MAX_SMALL_RESPONSE_BYTES: usize = 1024 * 1024;

/// Fixed upstream origins. Production uses [`Upstream::google`]; tests point all of them at a fake server.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub auth_url: String,
    pub token_url: String,
    pub revoke_url: String,
    pub certs_url: String,
    pub gmail_base: String,
}

impl Upstream {
    pub fn google() -> Self {
        Self {
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            revoke_url: "https://oauth2.googleapis.com/revoke".into(),
            certs_url: "https://www.googleapis.com/oauth2/v3/certs".into(),
            gmail_base: "https://gmail.googleapis.com/gmail/v1/users/me/".into(),
        }
    }

    /// All endpoints on one origin with Google's paths (used by tests with the fake server).
    pub fn single_origin(base: &str) -> Self {
        let b = base.trim_end_matches('/');
        Self {
            auth_url: format!("{b}/o/oauth2/v2/auth"),
            token_url: format!("{b}/token"),
            revoke_url: format!("{b}/revoke"),
            certs_url: format!("{b}/oauth2/v3/certs"),
            gmail_base: format!("{b}/gmail/v1/users/me/"),
        }
    }
}

/// Proof that the send gate was passed (spec 6.3). Only constructible inside the crate's send path.
pub struct SendPermit(pub(crate) ());

/// The allowlisted Gmail operations (spec 7.5). Nothing else can be sent.
pub enum GmailOp<'a> {
    Profile,
    ListMessages,
    GetMessage(&'a str),
    History,
    GetThread(&'a str),
    Labels,
    ListDrafts,
    GetDraft(&'a str),
    CreateDraft,
    UpdateDraft(&'a str),
    SendDraft(SendPermit),
    SendAs,
}

/// Gmail ids are short URL-safe tokens. Anything else is rejected before a request is built.
pub fn valid_id(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl GmailOp<'_> {
    fn method_path(&self) -> Result<(Method, String), GatewayError> {
        let seg = |id: &str| if valid_id(id) { Ok(id.to_string()) } else { Err(GatewayError::InvalidId) };
        Ok(match self {
            GmailOp::Profile => (Method::GET, "profile".into()),
            GmailOp::ListMessages => (Method::GET, "messages".into()),
            GmailOp::GetMessage(id) => (Method::GET, format!("messages/{}", seg(id)?)),
            GmailOp::History => (Method::GET, "history".into()),
            GmailOp::GetThread(id) => (Method::GET, format!("threads/{}", seg(id)?)),
            GmailOp::Labels => (Method::GET, "labels".into()),
            GmailOp::ListDrafts => (Method::GET, "drafts".into()),
            GmailOp::GetDraft(id) => (Method::GET, format!("drafts/{}", seg(id)?)),
            GmailOp::CreateDraft => (Method::POST, "drafts".into()),
            GmailOp::UpdateDraft(id) => (Method::PUT, format!("drafts/{}", seg(id)?)),
            GmailOp::SendDraft(_) => (Method::POST, "drafts/send".into()),
            GmailOp::SendAs => (Method::GET, "settings/sendAs".into()),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            GmailOp::Profile => "profile",
            GmailOp::ListMessages => "messages.list",
            GmailOp::GetMessage(_) => "messages.get",
            GmailOp::History => "history.list",
            GmailOp::GetThread(_) => "threads.get",
            GmailOp::Labels => "labels.list",
            GmailOp::ListDrafts => "drafts.list",
            GmailOp::GetDraft(_) => "drafts.get",
            GmailOp::CreateDraft => "drafts.create",
            GmailOp::UpdateDraft(_) => "drafts.update",
            GmailOp::SendDraft(_) => "drafts.send",
            GmailOp::SendAs => "settings.sendAs.list",
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum GatewayError {
    #[error("invalid object id")]
    InvalidId,
    /// Google answered with an error status.
    #[error("upstream status {status}")]
    Status { status: u16, reason: Option<String>, retry_after: Option<u64> },
    /// The request was not dispatched (connect failure, queue deadline). Safe to retry.
    #[error("upstream unavailable before dispatch")]
    NotDispatched,
    /// The request may have reached Google but no usable response came back. Writes must report outcome_unknown.
    #[error("upstream outcome unknown")]
    Unknown,
    #[error("deadline exceeded")]
    Deadline,
    #[error("invalid upstream response")]
    BadResponse,
    /// The response body exceeds the caller's byte limit; reading stopped at the limit.
    #[error("upstream response too large")]
    TooLarge,
}

impl GatewayError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, GatewayError::Status { status: 404, .. })
    }
    pub fn is_auth(&self) -> bool {
        matches!(self, GatewayError::Status { status: 401, .. })
    }
}

/// Foreground calls may use every slot; background sync leaves a reserve for interactive work (spec 7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Interactive,
    Background,
}

pub struct Gateway {
    http: reqwest::Client,
    pub upstream: Upstream,
    global: Arc<Semaphore>,
    background: Arc<Semaphore>,
    per_mailbox: Mutex<HashMap<String, Arc<Semaphore>>>,
    per_mailbox_limit: usize,
    request_timeout: Duration,
    /// Upstream calls made, including retries (for quota accounting and tests).
    pub calls: std::sync::atomic::AtomicU64,
    /// Response body bytes read from Google (tests check that size limits stop reading early).
    pub bytes_read: Arc<std::sync::atomic::AtomicU64>,
}

enum ReadError {
    TooLarge,
    Io,
}

/// Reads a response body of at most `cap` bytes. A declared length over the cap is refused before reading; otherwise
/// the body is streamed and counted, and reading stops as soon as the cap would be exceeded.
async fn read_capped(
    mut resp: reqwest::Response,
    cap: usize,
    counter: &std::sync::atomic::AtomicU64,
) -> Result<Vec<u8>, ReadError> {
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err(ReadError::TooLarge);
    }
    let mut buf = Vec::with_capacity(resp.content_length().map_or(0, |n| n as usize));
    while let Some(chunk) = resp.chunk().await.map_err(|_| ReadError::Io)? {
        counter.fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
        if buf.len() + chunk.len() > cap {
            return Err(ReadError::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

struct Permits {
    _global: OwnedSemaphorePermit,
    _mailbox: Option<OwnedSemaphorePermit>,
    _background: Option<OwnedSemaphorePermit>,
}

impl Gateway {
    pub fn new(upstream: Upstream, limits: &Limits) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(limits.upstream_request_timeout_secs))
            .pool_idle_timeout(Duration::from_secs(60))
            .user_agent(concat!("dove/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("http client");
        let total = limits.upstream_total_inflight.max(2);
        Self {
            http,
            upstream,
            global: Arc::new(Semaphore::new(total)),
            background: Arc::new(Semaphore::new((total - total / 4).max(1))),
            per_mailbox: Mutex::new(HashMap::new()),
            per_mailbox_limit: limits.upstream_per_mailbox.max(1),
            request_timeout: Duration::from_secs(limits.upstream_request_timeout_secs),
            calls: Default::default(),
            bytes_read: Default::default(),
        }
    }

    fn mailbox_sem(&self, account_id: &str) -> Arc<Semaphore> {
        let mut map = self.per_mailbox.lock().expect("lock");
        map.entry(account_id.to_string()).or_insert_with(|| Arc::new(Semaphore::new(self.per_mailbox_limit))).clone()
    }

    async fn acquire(&self, account: Option<&str>, prio: Priority, deadline: Instant) -> Result<Permits, GatewayError> {
        let wait = deadline.saturating_duration_since(Instant::now());
        let fut = async {
            let background = match prio {
                Priority::Background => Some(self.background.clone().acquire_owned().await.ok()?),
                Priority::Interactive => None,
            };
            let mailbox = match account {
                Some(a) => Some(self.mailbox_sem(a).acquire_owned().await.ok()?),
                None => None,
            };
            let global = self.global.clone().acquire_owned().await.ok()?;
            Some(Permits { _global: global, _mailbox: mailbox, _background: background })
        };
        match tokio::time::timeout(wait, fut).await {
            Ok(Some(p)) => Ok(p),
            _ => Err(GatewayError::NotDispatched),
        }
    }

    /// Calls an allowlisted Gmail operation for one mailbox and parses the JSON answer (at most
    /// [`MAX_RESPONSE_BYTES`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn gmail(
        &self,
        account_id: &str,
        access_token: &str,
        op: GmailOp<'_>,
        query: &[(&str, String)],
        body: Option<&Value>,
        prio: Priority,
        deadline: Instant,
    ) -> Result<Value, GatewayError> {
        let idempotent = op.method_path()?.0 == Method::GET;
        let bytes =
            self.gmail_bytes(account_id, access_token, op, query, body, prio, deadline, MAX_RESPONSE_BYTES).await?;
        serde_json::from_slice(&bytes)
            .map_err(|_| if idempotent { GatewayError::BadResponse } else { GatewayError::Unknown })
    }

    /// Like [`Self::gmail`] but returns the raw body of at most `max_bytes` (callers parse it without an extra copy).
    /// An over-limit body is [`GatewayError::TooLarge`] for reads and `Unknown` for writes (the write was applied).
    #[allow(clippy::too_many_arguments)]
    pub async fn gmail_bytes(
        &self,
        account_id: &str,
        access_token: &str,
        op: GmailOp<'_>,
        query: &[(&str, String)],
        body: Option<&Value>,
        prio: Priority,
        deadline: Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, GatewayError> {
        let (method, path) = op.method_path()?;
        let url = format!("{}{}", self.upstream.gmail_base, path);
        let idempotent = method == Method::GET;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let _permits = self.acquire(Some(account_id), prio, deadline).await?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(GatewayError::Deadline);
            }
            let mut req = self
                .http
                .request(method.clone(), &url)
                .bearer_auth(access_token)
                .timeout(remaining.min(self.request_timeout))
                .query(query);
            if let Some(b) = body {
                req = req.json(b);
            }
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let result = req.send().await;
            let err = match result {
                Ok(resp) if resp.status().is_success() => {
                    return match read_capped(resp, max_bytes.min(MAX_RESPONSE_BYTES), &self.bytes_read).await {
                        Ok(b) => Ok(b),
                        Err(_) if !idempotent => Err(GatewayError::Unknown),
                        Err(ReadError::TooLarge) => Err(GatewayError::TooLarge),
                        Err(ReadError::Io) => Err(GatewayError::BadResponse),
                    };
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let retry_after = resp
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok());
                    let reason = read_capped(resp, MAX_SMALL_RESPONSE_BYTES, &self.bytes_read)
                        .await
                        .ok()
                        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                        .and_then(|v| error_reason(&v));
                    GatewayError::Status { status, reason, retry_after }
                }
                Err(e) if e.is_connect() => GatewayError::NotDispatched,
                Err(_) if idempotent => GatewayError::NotDispatched,
                // A write that may have been sent: never replayed (spec 7.7).
                Err(_) => return Err(GatewayError::Unknown),
            };
            let retryable = match &err {
                GatewayError::Status { status, reason, .. } => {
                    *status == 429
                        || *status >= 500
                        || (*status == 403 && reason.as_deref().is_some_and(|r| r.contains("rateLimitExceeded")))
                }
                GatewayError::NotDispatched => true,
                _ => false,
            };
            let may_retry = retryable && attempt < 3 && (idempotent || matches!(err, GatewayError::NotDispatched));
            if !may_retry {
                return Err(err);
            }
            let base = match &err {
                GatewayError::Status { retry_after: Some(s), .. } => Duration::from_secs(*s),
                _ => Duration::from_millis(200 * 2u64.pow(attempt)),
            };
            let jitter = Duration::from_millis(u64::from(util::random_bytes::<1>()[0]));
            let sleep = base + jitter;
            if Instant::now() + sleep >= deadline {
                return Err(err);
            }
            tokio::time::sleep(sleep).await;
        }
    }

    /// POST form to Google's token endpoint. Not retried (code exchange is single use).
    pub async fn token_request(&self, form: &[(&str, &str)]) -> Result<Value, GatewayError> {
        let deadline = Instant::now() + self.request_timeout;
        let _p = self.acquire(None, Priority::Interactive, deadline).await?;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let resp = self
            .http
            .post(&self.upstream.token_url)
            .form(form)
            .send()
            .await
            .map_err(|e| if e.is_connect() { GatewayError::NotDispatched } else { GatewayError::Unknown })?;
        let status = resp.status().as_u16();
        let b = read_capped(resp, MAX_SMALL_RESPONSE_BYTES, &self.bytes_read)
            .await
            .map_err(|_| GatewayError::BadResponse)?;
        let v: Value = serde_json::from_slice(&b).map_err(|_| GatewayError::BadResponse)?;
        if (200..300).contains(&status) {
            Ok(v)
        } else {
            Err(GatewayError::Status { status, reason: v["error"].as_str().map(str::to_string), retry_after: None })
        }
    }

    pub async fn revoke(&self, token: &str) -> Result<(), GatewayError> {
        let deadline = Instant::now() + self.request_timeout;
        let _p = self.acquire(None, Priority::Interactive, deadline).await?;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let resp = self
            .http
            .post(&self.upstream.revoke_url)
            .form(&[("token", token)])
            .send()
            .await
            .map_err(|_| GatewayError::NotDispatched)?;
        let status = resp.status().as_u16();
        // 400 invalid_token means it is already revoked or expired; treat as done.
        if (200..300).contains(&status) || status == 400 {
            Ok(())
        } else {
            Err(GatewayError::Status { status, reason: None, retry_after: None })
        }
    }

    pub async fn certs(&self) -> Result<Value, GatewayError> {
        let deadline = Instant::now() + self.request_timeout;
        let _p = self.acquire(None, Priority::Interactive, deadline).await?;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let resp = self.http.get(&self.upstream.certs_url).send().await.map_err(|_| GatewayError::NotDispatched)?;
        if !resp.status().is_success() {
            return Err(GatewayError::Status { status: resp.status().as_u16(), reason: None, retry_after: None });
        }
        let b = read_capped(resp, MAX_SMALL_RESPONSE_BYTES, &self.bytes_read)
            .await
            .map_err(|_| GatewayError::BadResponse)?;
        serde_json::from_slice(&b).map_err(|_| GatewayError::BadResponse)
    }
}

fn error_reason(v: &Value) -> Option<String> {
    let e = &v["error"];
    e["errors"][0]["reason"].as_str().or_else(|| e["status"].as_str()).or_else(|| e.as_str()).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves a 1 MiB body in 8 KiB chunks, optionally without a Content-Length (streamed).
    async fn big_body_server(declare_length: bool) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback(move || async move {
            let chunks = (0..128).map(|_| Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'a'; 8192])));
            let body = if declare_length {
                axum::body::Body::from(vec![b'a'; 128 * 8192])
            } else {
                axum::body::Body::from_stream(futures::stream::iter(chunks))
            };
            axum::response::Response::builder().status(200).body(body).unwrap()
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        base
    }

    #[tokio::test]
    async fn response_bodies_are_capped_while_reading() {
        for declare_length in [true, false] {
            let gw = Gateway::new(Upstream::single_origin(&big_body_server(declare_length).await), &Limits::default());
            let deadline = Instant::now() + Duration::from_secs(10);
            let get = |cap| {
                gw.gmail_bytes("a", "t", GmailOp::GetMessage("m1"), &[], None, Priority::Interactive, deadline, cap)
            };
            let err = get(20_000).await.unwrap_err();
            assert!(matches!(err, GatewayError::TooLarge), "{err:?}");
            let read = gw.bytes_read.load(std::sync::atomic::Ordering::Relaxed);
            // A declared length is refused unread; a streamed body stops within one chunk of the cap.
            assert!(read <= 20_000 + 64 * 1024, "read {read} bytes of a 1 MiB body");
            if declare_length {
                assert_eq!(read, 0);
            }
            // Within the cap the whole body arrives; a too-large body is never retried.
            assert_eq!(get(2 * 1024 * 1024).await.unwrap().len(), 128 * 8192);
            assert_eq!(gw.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
        }
    }

    #[test]
    fn ids_and_paths_are_strict() {
        assert!(valid_id("18c2f0a1b2c3d4e5"));
        assert!(valid_id("r-12345_abc"));
        assert!(!valid_id("../settings/filters"));
        assert!(!valid_id("a/b"));
        assert!(!valid_id("a?b"));
        assert!(!valid_id(""));
        assert!(matches!(GmailOp::GetMessage("../x").method_path(), Err(GatewayError::InvalidId)));
        let (m, p) = GmailOp::UpdateDraft("r123").method_path().unwrap();
        assert_eq!((m, p.as_str()), (Method::PUT, "drafts/r123"));
        let (m, p) = GmailOp::SendDraft(SendPermit(())).method_path().unwrap();
        assert_eq!((m, p.as_str()), (Method::POST, "drafts/send"));
    }
}
