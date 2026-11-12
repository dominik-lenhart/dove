//! Downstream OAuth authorization server for MCP hosts (spec 5.6). Implemented in step 4.

use std::sync::Arc;

use axum::Router;

use crate::app::App;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
}
