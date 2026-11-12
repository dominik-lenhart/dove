//! Google APIs: outbound gateway, OAuth connect, token manager and typed Gmail calls (spec 7.3, 7.5, 7.8).

pub mod connect;
pub mod gateway;
pub mod tokens;

use std::sync::Arc;
use std::time::Instant;

use serde_json::Value;

use crate::error::{ErrorCode, ToolError};
use gateway::{Gateway, GatewayError, GmailOp, Priority, Upstream};
use tokens::TokenManager;

pub const SCOPE_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const SCOPE_COMPOSE: &str = "https://www.googleapis.com/auth/gmail.compose";
/// Scopes requested at connect. Both Gmail scopes must be granted (spec 7.3 step 8).
pub const REQUIRED_SCOPES: &[&str] = &["openid", "email", SCOPE_READONLY, SCOPE_COMPOSE];

/// Bundles the gateway, token manager and JWKS cache.
pub struct Google {
    gateway: Arc<Gateway>,
    tokens: TokenManager,
    jwks: connect::JwksCache,
}

impl Google {
    pub fn new(gateway: Arc<Gateway>, tokens: TokenManager) -> Self {
        Self { gateway, tokens, jwks: Default::default() }
    }
    pub fn gateway(&self) -> &Gateway {
        &self.gateway
    }
    pub fn upstream(&self) -> &Upstream {
        &self.gateway.upstream
    }
    pub fn tokens(&self) -> &TokenManager {
        &self.tokens
    }

    pub async fn jwks(&self, force: bool) -> anyhow::Result<Value> {
        if !force && let Some(v) = self.jwks.get() {
            return Ok(v);
        }
        let v = self.gateway.certs().await?;
        self.jwks.put(v.clone());
        Ok(v)
    }

    /// Calls Gmail for `account_id` with a valid access token. A 401 evicts the cached token and retries once.
    pub async fn call<'a>(
        &self,
        account_id: &str,
        op: impl Fn() -> GmailOp<'a>,
        query: &[(&str, String)],
        body: Option<&Value>,
        prio: Priority,
        deadline: Instant,
    ) -> Result<Value, ToolError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let token = self.tokens.access_token(account_id).await?;
            match self.gateway.gmail(account_id, &token, op(), query, body, prio, deadline).await {
                Err(e) if e.is_auth() && attempt == 1 => {
                    self.tokens.evict(account_id);
                    continue;
                }
                other => return other.map_err(map_err),
            }
        }
    }
}

/// A failed Gmail write and whether Google may have received it (spec 6.3, 7.7).
#[derive(Debug)]
pub struct WriteError {
    pub error: ToolError,
    /// False only when the request certainly never reached Google; then a retry is safe.
    pub dispatched: bool,
}

impl Google {
    /// Performs a Gmail write. Server errors, lost responses and unreadable success bodies become
    /// `outcome_unknown`: Google may have applied the write, so it must not be repeated automatically.
    pub async fn write<'a>(
        &self,
        account_id: &str,
        op: impl Fn() -> GmailOp<'a>,
        body: &Value,
        deadline: Instant,
    ) -> Result<Value, WriteError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let token =
                self.tokens.access_token(account_id).await.map_err(|error| WriteError { error, dispatched: false })?;
            match self.gateway.gmail(account_id, &token, op(), &[], Some(body), Priority::Interactive, deadline).await {
                Ok(v) => return Ok(v),
                // A 401 is a definitive rejection before the write was applied.
                Err(e) if e.is_auth() && attempt == 1 => self.tokens.evict(account_id),
                Err(e) => return Err(classify_write(e)),
            }
        }
    }
}

fn classify_write(e: GatewayError) -> WriteError {
    match e {
        GatewayError::NotDispatched | GatewayError::Deadline | GatewayError::InvalidId => {
            WriteError { error: map_err(e), dispatched: false }
        }
        GatewayError::Status { status, .. } if status < 500 => WriteError { error: map_err(e), dispatched: true },
        GatewayError::Status { .. } | GatewayError::Unknown | GatewayError::BadResponse => WriteError {
            error: ToolError::new(ErrorCode::OutcomeUnknown, "the Gmail write may or may not have been applied"),
            dispatched: true,
        },
    }
}

/// Maps gateway failures to stable agent error codes. Never includes upstream bodies.
pub fn map_err(e: GatewayError) -> ToolError {
    match e {
        GatewayError::Status { status: 404, .. } | GatewayError::InvalidId => ToolError::not_found(),
        GatewayError::Status { status: 429, retry_after, .. } => ToolError::rate_limited(retry_after),
        GatewayError::Status { status: 403, reason: Some(r), retry_after } if r.contains("ateLimit") => {
            ToolError::rate_limited(retry_after)
        }
        GatewayError::Status { status, .. } => ToolError::upstream(format!("Gmail returned HTTP {status}")),
        GatewayError::NotDispatched => ToolError::upstream("Gmail is unreachable"),
        GatewayError::Deadline => ToolError::upstream("Gmail did not answer in time"),
        GatewayError::BadResponse => ToolError::upstream("unexpected Gmail response"),
        GatewayError::Unknown => {
            ToolError::new(ErrorCode::OutcomeUnknown, "the Gmail request may or may not have been applied")
        }
    }
}
