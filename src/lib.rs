//! Dove: a self-hosted mail MCP server for AI agents. See `docs/spec.md`.

pub mod admin;
pub mod app;
pub mod audit;
pub mod cli;
pub mod config;
pub mod content;
pub mod error;
pub mod gmail;
pub mod index;
pub mod logging;
pub mod mime;
pub mod notifier;
pub mod policy;
pub mod secrets;
pub mod serve;
pub mod store;
pub mod tokens;
pub mod util;
pub mod vault;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
