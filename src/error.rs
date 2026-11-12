//! Stable error codes returned to agents (spec 5.4).
//!
//! Messages are short and never contain tokens, mail content, stack traces or data about accounts the caller
//! cannot see. Internal causes are logged by request id, not returned.

use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotFound,
    Forbidden,
    InvalidArgument,
    AccountUnavailable,
    RateLimited,
    UpstreamError,
    Internal,
    DraftConflict,
    OutcomeUnknown,
    CursorInvalid,
    QueryTooBroad,
    IndexIncomplete,
    BudgetExceeded,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotFound => "not_found",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::AccountUnavailable => "account_unavailable",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::UpstreamError => "upstream_error",
            ErrorCode::Internal => "internal",
            ErrorCode::DraftConflict => "draft_conflict",
            ErrorCode::OutcomeUnknown => "outcome_unknown",
            ErrorCode::CursorInvalid => "cursor_invalid",
            ErrorCode::QueryTooBroad => "query_too_broad",
            ErrorCode::IndexIncomplete => "index_incomplete",
            ErrorCode::BudgetExceeded => "budget_exceeded",
        }
    }
}

/// An error that is safe to return to an MCP client.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_after_seconds: Option<u64>,
    /// Extra structured detail (for example coverage reasons). Must already be authorization-filtered.
    pub details: Option<Value>,
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after_seconds: None,
            details: None,
        }
    }
    /// The single not-found shape used for unknown and out-of-scope objects alike (FR-P5).
    pub fn not_found() -> Self {
        Self::new(ErrorCode::NotFound, "not found")
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }
    pub fn internal() -> Self {
        Self::new(ErrorCode::Internal, "internal error")
    }
    pub fn unavailable() -> Self {
        Self::new(ErrorCode::AccountUnavailable, "account unavailable")
    }
    pub fn upstream(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::UpstreamError, message)
    }
    pub fn rate_limited(retry_after: Option<u64>) -> Self {
        Self {
            retry_after_seconds: retry_after,
            ..Self::new(ErrorCode::RateLimited, "rate limited")
        }
    }
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn to_json(&self) -> Value {
        let mut v = json!({ "code": self.code.as_str(), "message": self.message });
        if let Some(r) = self.retry_after_seconds {
            v["retry_after_seconds"] = json!(r);
        }
        if let Some(d) = &self.details {
            v["details"] = d.clone();
        }
        v
    }
}

/// Converts an internal error into the generic `internal` code, logging the cause without content.
pub fn internal_from(err: impl std::fmt::Display) -> ToolError {
    tracing::error!(error = %crate::logging::redact(&err.to_string()), "internal error");
    ToolError::internal()
}

impl From<anyhow::Error> for ToolError {
    fn from(err: anyhow::Error) -> Self {
        if let Some(te) = err.downcast_ref::<ToolError>() {
            return te.clone();
        }
        internal_from(err)
    }
}
