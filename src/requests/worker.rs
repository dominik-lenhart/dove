//! The scheduled-send worker (design 2026-11-14 section 4.4).

use rusqlite::Connection;

/// Startup recovery: an item found in `sending` may or may not have gone out. It ends as `send_unknown` and is never
/// retried.
pub fn recover_after_restart(c: &Connection) -> anyhow::Result<usize> {
    let now = crate::util::now_unix();
    Ok(c.execute(
        "UPDATE request_items SET state = 'send_unknown', reason = 'restart', updated_at = ?1 WHERE state = 'sending'",
        [now],
    )?)
}
