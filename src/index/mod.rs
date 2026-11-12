//! Encrypted search index and mailbox sync (spec 7.9).

pub mod db;

use crate::app::App;

/// Removes every derived index row of an account and invalidates its cursors (account removal, index disable).
/// Implemented with the sync engine; until then there is nothing to purge.
pub async fn purge_account(_app: &App, _account_id: &str) {}

/// Wakes incremental sync for an account after a successful Dove write (spec 7.9 step 4).
pub fn wake(_app: &App, _account_id: &str) {}
