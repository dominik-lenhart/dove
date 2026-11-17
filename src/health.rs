//! The health watcher (design 2026-11-17): every few minutes it checks what an agent would only notice as stale
//! answers, and alerts the owner through [`crate::notifier`] (log, webhook, push):
//!
//! - a mailbox with indexing on whose sync has not succeeded for [`STALL_SECS`] while it is failing or already
//!   complete (a first backfill that makes progress is not stalled), with one "syncs again" alert on recovery;
//! - less than [`LOW_DISK_BYTES`] free for the data directory, cleared above [`DISK_OK_BYTES`].
//!
//! Mailboxes that need reconnecting are not checked here: the token and IMAP paths alert at the moment of the refusal.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::app::App;
use crate::notifier::Alert;
use crate::util;

pub const STALL_SECS: i64 = 2 * 3600;
pub const LOW_DISK_BYTES: u64 = 1 << 30;
pub const DISK_OK_BYTES: u64 = 2 << 30;
const POLL: Duration = Duration::from_secs(300);
const DISK_KEY: &str = "disk:low";

/// What one [`tick`] found.
#[derive(Debug, Default, Clone, Serialize, PartialEq, Eq)]
pub struct Report {
    /// Aliases whose sync is stalled now.
    pub stalled: Vec<String>,
    /// Aliases that synced again after a stall alert.
    pub recovered: Vec<String>,
    pub disk_free: Option<u64>,
    pub disk_low: bool,
}

/// One mailbox's sync freshness, from the state store and the index.
#[derive(Debug, Clone, Serialize)]
pub struct MailboxSync {
    pub account_id: String,
    pub alias: String,
    /// Seconds since the last successful sync (or since indexing was enabled, before the first one).
    pub lag_secs: i64,
    pub stalled: bool,
}

/// Free bytes for unprivileged writers on the file system holding `path`; `None` where it cannot be read.
pub fn disk_free(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        let s = nix::sys::statvfs::statvfs(path).ok()?;
        Some((s.blocks_available() as u64).saturating_mul(s.fragment_size() as u64))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Sync freshness of every active mailbox with indexing on and a sync state.
pub async fn mailbox_sync(app: &Arc<App>, now: i64) -> anyhow::Result<Vec<MailboxSync>> {
    let accounts: Vec<(String, String)> = app
        .store
        .call(|c| {
            let mut st = c.prepare(
                "SELECT id, alias FROM accounts WHERE status = 'active' AND index_enabled = 1 ORDER BY alias",
            )?;
            Ok(st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
        })
        .await?;
    if accounts.is_empty() {
        return Ok(vec![]);
    }
    // A polling interval set above the threshold must not look like a stall.
    let stall = STALL_SECS.max(3 * app.cfg.index.poll_interval_secs as i64);
    // (account, reference time, stalled-eligible)
    let states: Vec<(String, i64, bool)> = app
        .index
        .write(|c| {
            let mut st = c.prepare(
                "SELECT account_id, coalesce(last_success_at, enabled_at), \
                        stage = 'ready' OR last_error IS NOT NULL FROM sync_state",
            )?;
            Ok(st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?)
        })
        .await?;
    Ok(accounts
        .into_iter()
        .filter_map(|(id, alias)| {
            let (_, since, eligible) = states.iter().find(|s| s.0 == id)?;
            let lag_secs = (now - since).max(0);
            Some(MailboxSync { account_id: id, alias, lag_secs, stalled: *eligible && lag_secs > stall })
        })
        .collect())
}

/// Runs the checks once at `now`, with the data directory's free space read from disk.
pub async fn tick(app: &Arc<App>, now: i64) -> anyhow::Result<Report> {
    let free = disk_free(&app.cfg.data_dir);
    tick_with(app, now, free).await
}

/// [`tick`] with a given free-space reading, for tests.
pub async fn tick_with(app: &Arc<App>, now: i64, disk_free: Option<u64>) -> anyhow::Result<Report> {
    let mut report = Report { disk_free, ..Report::default() };
    for m in mailbox_sync(app, now).await? {
        let key = format!("stalled:{}", m.account_id);
        if m.stalled {
            app.notifier.notify_once(&key, Alert::sync_stalled(&m.alias, m.lag_secs / 3600)).await?;
            report.stalled.push(m.alias);
        } else if app.notifier.clear(&key).await? {
            app.notifier.send(Alert::sync_recovered(&m.alias)).await;
            report.recovered.push(m.alias);
        }
    }
    match disk_free {
        Some(free) if free < LOW_DISK_BYTES => {
            app.notifier.notify_once(DISK_KEY, Alert::low_disk(free >> 20)).await?;
            report.disk_low = true;
        }
        Some(free) if free >= DISK_OK_BYTES => {
            app.notifier.clear(DISK_KEY).await?;
        }
        _ => report.disk_low = app.notifier.is_open(DISK_KEY).await?,
    }
    Ok(report)
}

/// Starts the watcher loop.
pub fn start(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL).await;
            if let Err(e) = tick(&app, util::now_unix()).await {
                tracing::warn!(error = %e, "health check pass failed");
            }
        }
    })
}
