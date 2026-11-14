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
    /// The requested object exceeds a size limit (for example `limits.attachment_bytes`).
    TooLarge,
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
            ErrorCode::TooLarge => "too_large",
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
        Self { code, message: message.into(), retry_after_seconds: None, details: None }
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
    /// `invalid_argument` that names the offending argument. `field` is a path built from the tool's own structure
    /// (`where.all[1].op`, `limit`), never from caller-supplied text, so it is safe to keep in the audit record. The
    /// message starts with the path and says how to fix the call.
    pub fn invalid_at(field: impl Into<String>, message: impl AsRef<str>) -> Self {
        let field = field.into();
        Self::invalid(format!("{field}: {}", message.as_ref())).with_details(json!({ "field": field }))
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
        Self { retry_after_seconds: retry_after, ..Self::new(ErrorCode::RateLimited, "rate limited") }
    }
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Adds one key to `details` (creating it).
    pub fn with_detail(mut self, key: &str, value: Value) -> Self {
        let d = self.details.get_or_insert_with(|| json!({}));
        if let Some(o) = d.as_object_mut() {
            o.insert(key.to_string(), value);
        }
        self
    }

    /// A valid example of the argument (`details.example`), for `invalid_argument` errors.
    pub fn with_example(self, example: Value) -> Self {
        self.with_detail("example", example)
    }

    /// The coarse, content-free kind of an `invalid_argument` error for the audit record: the argument path with
    /// list indices removed (`where.all[].op`). `None` for other codes, errors without a path and anything that does
    /// not look like a path built by [`ToolError::invalid_at`].
    pub fn audit_field(&self) -> Option<String> {
        if self.code != ErrorCode::InvalidArgument {
            return None;
        }
        let f = self.details.as_ref()?.get("field")?.as_str()?;
        let mut out = String::new();
        let mut in_index = false;
        for c in f.chars() {
            match c {
                '[' => {
                    in_index = true;
                    out.push('[');
                }
                ']' => {
                    in_index = false;
                    out.push(']');
                }
                _ if in_index => {}
                'a'..='z' | '_' | '.' => out.push(c),
                _ => return None,
            }
        }
        (!out.is_empty() && out.len() <= 48).then_some(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_field_keeps_only_a_path_of_argument_names() {
        let f = |field: &str| ToolError::invalid_at(field, "x").audit_field();
        assert_eq!(f("where.all[12].op").as_deref(), Some("where.all[].op"));
        assert_eq!(f("limit").as_deref(), Some("limit"));
        // Anything that is not a plain path (caller text, digits, spaces, quotes) is dropped, never recorded.
        for bad in ["Where", "where field", "where.\"x\"", "select2", "a@b.test", "", &"a".repeat(49)] {
            assert_eq!(f(bad), None, "{bad}");
        }
        // Only invalid_argument carries a kind, and only when the error names a field.
        assert_eq!(
            ToolError::new(ErrorCode::NotFound, "x").with_details(json!({"field": "limit"})).audit_field(),
            None
        );
        assert_eq!(ToolError::invalid("x").audit_field(), None);
    }
}
