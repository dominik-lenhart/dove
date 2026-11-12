//! Google APIs: outbound gateway, OAuth, token manager and typed Gmail operations (spec 7.3, 7.5, 7.8).

pub const SCOPE_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const SCOPE_COMPOSE: &str = "https://www.googleapis.com/auth/gmail.compose";
/// Scopes requested at connect. Both Gmail scopes must be granted (spec 7.3 step 8).
pub const REQUIRED_SCOPES: &[&str] = &["openid", "email", SCOPE_READONLY, SCOPE_COMPOSE];
