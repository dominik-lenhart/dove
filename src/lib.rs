//! Dove: a self-hosted mail MCP server for AI agents. See `docs/spec.md`.

pub mod admin;
pub mod app;
pub mod attachment_text;
pub mod audit;
pub mod calendar;
pub mod cli;
pub mod client;
pub mod config;
pub mod content;
pub mod error;
pub mod gmail;
pub mod http;
pub mod identity;
pub mod imap;
pub mod index;
pub mod invite;
pub mod logging;
pub mod mail;
pub mod mcp;
pub mod mime;
pub mod notifier;
pub mod oauth;
pub mod policy;
pub mod secrets;
pub mod serve;
pub mod store;
pub mod tailscale;
pub mod tokens;
pub mod tools;
pub mod update;
pub mod util;
pub mod vault;
pub mod watch;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
