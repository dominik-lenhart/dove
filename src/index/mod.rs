//! Encrypted search index and mailbox sync (spec 7.9).
//!
//! - [`db`]: SQLCipher open + startup self-check.
//! - [`schema`]: index-side migrations.
//! - [`ingest`]: Gmail message -> derived row (normalized addresses, labels, attachment metadata, FTS text).
//! - [`sync`]: backfill into generations, history polling, rebuild on history expiry, fencing.
//! - [`query`]: typed search request -> parameterized SQL.
//! - [`cursor`]: bounded in-memory cursor store.
//! - [`admin`]: `dove index enable|disable|status|rebuild`.
//!
//! Concurrency (spec 8.1a): one writer connection, at most `reader_connections` (default 3) readers, each with an
//! 8 MiB page cache. Every database call runs on a blocking thread; no transaction spans a network await.

pub mod admin;
pub mod cursor;
pub mod db;
pub mod ingest;
pub mod query;
pub mod schema;
pub mod sync;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::app::App;
use crate::config::IndexConfig;
use crate::error::{ErrorCode, ToolError};
use crate::secrets::KeyRing;
use crate::util;

pub struct Index {
    path: PathBuf,
    key: Arc<KeyRing>,
    pub cfg: IndexConfig,
    writer: Arc<Mutex<Option<Connection>>>,
    /// Set once the schema is migrated. Readers check it without touching the writer lock, so a long write never
    /// delays a search (WAL readers do not wait for the writer).
    migrated: Arc<AtomicBool>,
    migrate_lock: Arc<Mutex<()>>,
    readers: Arc<Mutex<Vec<Connection>>>,
    reader_sem: Arc<Semaphore>,
    /// Admission for body fetch/parse jobs across all mailboxes (spec 8.1a: 2 by default).
    pub body_jobs: Arc<Semaphore>,
    pub cursors: cursor::CursorStore,
    /// Per-account single flight for sync passes (engine and explicit test calls never overlap).
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Cancellation of the running sync job per account (disable, remove, rebuild).
    cancels: Mutex<HashMap<String, CancellationToken>>,
    woken: Mutex<HashSet<String>>,
    wake: Notify,
}

/// Raised inside a write transaction when the job's fence no longer matches: the account was purged, disabled
/// or rebuilt after the job started. The transaction rolls back and the job stops.
#[derive(Debug, thiserror::Error)]
#[error("sync job fenced off")]
pub struct Fenced;

impl Index {
    pub fn new(data_path: PathBuf, key: Arc<KeyRing>, cfg: IndexConfig) -> Self {
        let readers = cfg.reader_connections.clamp(1, 3);
        let jobs = cfg.body_jobs.clamp(1, 8);
        Self {
            path: data_path,
            key,
            cfg,
            writer: Arc::new(Mutex::new(None)),
            migrated: Arc::new(AtomicBool::new(false)),
            migrate_lock: Arc::new(Mutex::new(())),
            readers: Arc::new(Mutex::new(Vec::new())),
            reader_sem: Arc::new(Semaphore::new(readers)),
            body_jobs: Arc::new(Semaphore::new(jobs)),
            cursors: Default::default(),
            locks: Default::default(),
            cancels: Default::default(),
            woken: Default::default(),
            wake: Notify::new(),
        }
    }

    /// Runs `f` on the single writer connection on a blocking thread. Migrates the index on first use.
    pub async fn write<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&mut Connection) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let writer = self.writer.clone();
        let opener = self.opener();
        let migrate = self.migrator();
        tokio::task::spawn_blocking(move || {
            migrate()?;
            let mut guard = writer.lock().map_err(|_| anyhow::anyhow!("index writer poisoned"))?;
            if guard.is_none() {
                *guard = Some(opener()?);
            }
            f(guard.as_mut().expect("opened"))
        })
        .await
        .context("index writer task failed")?
    }

    /// Migrates the schema once, on its own connection and outside the writer lock.
    fn migrator(&self) -> impl Fn() -> anyhow::Result<()> + Send + 'static {
        let (done, lock, opener) = (self.migrated.clone(), self.migrate_lock.clone(), self.opener());
        move || {
            if done.load(Ordering::Acquire) {
                return Ok(());
            }
            let _g = lock.lock().map_err(|_| anyhow::anyhow!("index migration lock poisoned"))?;
            if !done.load(Ordering::Acquire) {
                let mut c = opener()?;
                schema::migrate(&mut c)?;
                done.store(true, Ordering::Release);
            }
            Ok(())
        }
    }

    fn opener(&self) -> impl Fn() -> anyhow::Result<Connection> + Send + 'static {
        let path = self.path.clone();
        let key = self.key.clone();
        let cfg = self.cfg.clone();
        move || {
            let (_, k) = key.current();
            db::open(&path, k, &cfg)
        }
    }

    /// Ensures the schema exists. Never takes the writer lock.
    pub async fn ensure_open(&self) -> anyhow::Result<()> {
        if self.migrated.load(Ordering::Acquire) {
            return Ok(());
        }
        tokio::task::spawn_blocking(self.migrator()).await.context("index migration task failed")?
    }

    /// Runs `f` on a pooled reader connection. The statement is interrupted at `deadline`; SQLite interrupts map to
    /// `query_too_broad`, out-of-memory to `budget_exceeded`.
    pub async fn read<F, T>(&self, deadline: Instant, f: F) -> Result<T, ToolError>
    where
        F: FnOnce(&Connection) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.ensure_open().await.map_err(crate::error::internal_from)?;
        let wait = deadline.saturating_duration_since(Instant::now());
        let _permit = tokio::time::timeout(wait, self.reader_sem.clone().acquire_owned())
            .await
            .map_err(|_| ToolError::new(ErrorCode::QueryTooBroad, "the index is busy; retry shortly"))?
            .map_err(|_| ToolError::internal())?;
        let readers = self.readers.clone();
        let opener = self.opener();
        let rt = tokio::runtime::Handle::current();
        let r = tokio::task::spawn_blocking(move || -> anyhow::Result<T> {
            let conn = readers.lock().map_err(|_| anyhow::anyhow!("reader pool poisoned"))?.pop();
            let conn = match conn {
                Some(c) => c,
                None => {
                    let c = opener()?;
                    c.execute_batch("PRAGMA query_only = ON;")?;
                    c
                }
            };
            let handle = conn.get_interrupt_handle();
            let timer = rt.spawn(async move {
                tokio::time::sleep_until(deadline.into()).await;
                handle.interrupt();
            });
            let out = f(&conn);
            timer.abort();
            if let Ok(mut pool) = readers.lock() {
                pool.push(conn);
            }
            out
        })
        .await
        .map_err(|_| ToolError::internal())?;
        r.map_err(map_sql_err)
    }

    fn lock_for(&self, account_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().expect("lock").entry(account_id.to_string()).or_default().clone()
    }

    fn cancel_token(&self, account_id: &str) -> CancellationToken {
        self.cancels.lock().expect("lock").entry(account_id.to_string()).or_default().clone()
    }

    /// Cancels the running job of an account; the next job gets a fresh token.
    fn cancel(&self, account_id: &str) {
        if let Some(t) = self.cancels.lock().expect("lock").remove(account_id) {
            t.cancel();
        }
    }

    pub fn take_woken(&self) -> HashSet<String> {
        std::mem::take(&mut *self.woken.lock().expect("lock"))
    }
}

/// Maps index database errors for agents: interrupts are deadline hits, NOMEM is the SQL heap limit (spec 8.1a).
pub fn map_sql_err(e: anyhow::Error) -> ToolError {
    if let Some(te) = e.downcast_ref::<ToolError>() {
        return te.clone();
    }
    if let Some(rusqlite::Error::SqliteFailure(f, _)) = e.downcast_ref::<rusqlite::Error>() {
        match f.code {
            rusqlite::ErrorCode::OperationInterrupted => {
                return ToolError::new(ErrorCode::QueryTooBroad, "the query exceeded its time budget; narrow it");
            }
            rusqlite::ErrorCode::OutOfMemory => {
                return ToolError::new(ErrorCode::BudgetExceeded, "the query exceeded the memory budget; narrow it");
            }
            _ => {}
        }
    }
    crate::error::internal_from(e)
}

// ------------------------------------------------------------------ fencing and state helpers

/// Allocates a new, never reused fence value.
pub(crate) fn next_fence(tx: &Connection) -> anyhow::Result<i64> {
    tx.execute("UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'fence_seq'", [])?;
    Ok(tx.query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'fence_seq'", [], |r| r.get(0))?)
}

/// Fails with [`Fenced`] unless the account still exists in the index with this fence.
pub(crate) fn check_fence(tx: &Connection, account_id: &str, fence: i64) -> anyhow::Result<()> {
    let cur: Option<i64> =
        tx.query_row("SELECT fence FROM sync_state WHERE account_id = ?1", [account_id], |r| r.get(0)).optional()?;
    if cur != Some(fence) {
        return Err(Fenced.into());
    }
    Ok(())
}

/// Creates a building generation for an account.
pub(crate) fn new_generation(tx: &Connection, account_id: &str) -> anyhow::Result<i64> {
    tx.execute(
        "INSERT INTO generations(account_id, state, created_at) VALUES (?1, 'building', ?2)",
        params![account_id, util::now_unix()],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Deletes up to `limit` derived rows of a generation (FTS postings first). Returns rows deleted.
pub(crate) fn delete_gen_chunk(tx: &Connection, gen_id: i64, limit: i64) -> anyhow::Result<usize> {
    let ids: Vec<i64> = {
        let mut st = tx.prepare_cached("SELECT id FROM messages WHERE gen = ?1 LIMIT ?2")?;
        st.query_map(params![gen_id, limit], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    for id in &ids {
        ingest::delete_row(tx, *id)?;
    }
    Ok(ids.len())
}

/// Removes a whole generation (rows, retry records, the generation itself).
pub(crate) fn drop_generation(tx: &Connection, gen_id: i64) -> anyhow::Result<()> {
    while delete_gen_chunk(tx, gen_id, 10_000)? > 0 {}
    tx.execute("DELETE FROM pending WHERE gen = ?1", [gen_id])?;
    tx.execute("DELETE FROM generations WHERE id = ?1", [gen_id])?;
    Ok(())
}

/// Creates the sync state of a newly enabled account (idempotent). Returns true if it was created.
/// Runs under the account lock and only while the operator's choice (state store) still says enabled, so a
/// concurrent disable can never be followed by a re-created state.
pub async fn ensure_state(app: &App, account_id: &str) -> anyhow::Result<bool> {
    let lock = app.index.lock_for(account_id);
    let _guard = lock.lock().await;
    let aid = account_id.to_string();
    let enabled = app
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT index_enabled FROM accounts WHERE id = ?1", [&aid], |r| r.get::<_, bool>(0))
                .optional()?
                .unwrap_or(false))
        })
        .await?;
    if !enabled {
        return Ok(false);
    }
    let aid = account_id.to_string();
    app.index
        .write(move |c| {
            let tx = c.transaction()?;
            let exists: bool =
                tx.query_row("SELECT EXISTS(SELECT 1 FROM sync_state WHERE account_id = ?1)", [&aid], |r| r.get(0))?;
            if exists {
                return Ok(false);
            }
            // Leftovers from an interrupted purge are removed before a new generation starts.
            let old: Vec<i64> = {
                let mut st = tx.prepare("SELECT id FROM generations WHERE account_id = ?1")?;
                st.query_map([&aid], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            for g in old {
                drop_generation(&tx, g)?;
            }
            let fence = next_fence(&tx)?;
            let g = new_generation(&tx, &aid)?;
            tx.execute(
                "INSERT INTO sync_state(account_id, fence, stage, building_gen, enabled_at) \
                 VALUES (?1, ?2, 'backfill', ?3, ?4)",
                params![aid, fence, g, util::now_unix()],
            )?;
            tx.commit()?;
            Ok(true)
        })
        .await
}

/// Removes every derived index row of an account, cancels and fences its jobs and invalidates its cursors
/// (account removal, index disable; spec 7.9 step 3).
pub async fn purge_account(app: &App, account_id: &str) {
    if let Err(e) = try_purge(app, account_id).await {
        tracing::error!(error = %e, "index purge failed; it is retried by the sync scheduler");
    }
}

async fn try_purge(app: &App, account_id: &str) -> anyhow::Result<()> {
    // Cancel first so a running job releases the account lock promptly, then purge under the lock.
    app.index.cancel(account_id);
    app.index.cursors.invalidate_account(account_id);
    let lock = app.index.lock_for(account_id);
    let _guard = lock.lock().await;
    let aid = account_id.to_string();
    let removed = app
        .index
        .write(move |c| {
            let tx = c.transaction()?;
            // Deleting the sync state first fences every job of this account.
            tx.execute("DELETE FROM sync_state WHERE account_id = ?1", [&aid])?;
            let gens: Vec<i64> = {
                let mut st = tx.prepare("SELECT id FROM generations WHERE account_id = ?1")?;
                st.query_map([&aid], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            let n: i64 = tx.query_row("SELECT count(*) FROM messages WHERE account_id = ?1", [&aid], |r| r.get(0))?;
            for g in gens {
                drop_generation(&tx, g)?;
            }
            // Rows whose generation row is already gone (interrupted earlier purge).
            let stray: Vec<i64> = {
                let mut st = tx.prepare("SELECT id FROM messages WHERE account_id = ?1")?;
                st.query_map([&aid], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            for id in stray {
                ingest::delete_row(&tx, id)?;
            }
            tx.commit()?;
            if n > 0 {
                // Merge away tombstoned postings so purged terms do not linger in FTS segments.
                c.execute("INSERT INTO fts(fts) VALUES ('optimize')", [])?;
            }
            Ok(n)
        })
        .await?;
    app.index.cursors.invalidate_account(account_id);
    tracing::info!(rows = removed, "index purged for an account");
    Ok(())
}

/// Wakes incremental sync for an account after a successful Dove write (spec 7.9 step 4).
pub fn wake(app: &App, account_id: &str) {
    app.index.woken.lock().expect("lock").insert(account_id.to_string());
    app.index.wake.notify_one();
}

/// Starts the background sync scheduler (called from `dove serve`).
pub fn start(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(sync::scheduler(app))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestEnv;

    /// A search never waits for the writer: while a long write transaction holds the writer connection, reads
    /// still complete well within their deadline (also on the very first use of the index).
    #[tokio::test]
    async fn reads_do_not_wait_for_a_long_write() {
        let env = TestEnv::new();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let index = env.app.clone();
        let long = tokio::spawn(async move {
            index
                .index
                .write(move |c| {
                    let t = c.transaction()?;
                    t.execute("UPDATE meta SET value = value WHERE key = 'fence_seq'", [])?;
                    let _ = started_tx.send(());
                    let _ = rx.recv_timeout(std::time::Duration::from_secs(30));
                    t.commit()?;
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let read = env
            .app
            .index
            .read(deadline, |c| Ok(c.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))?));
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), read).await;
        tx.send(()).unwrap();
        long.await.unwrap().unwrap();
        assert_eq!(n.expect("the read waited for the writer").unwrap(), 0);
    }

    #[tokio::test]
    async fn deadline_interrupts_query_as_too_broad() {
        let env = TestEnv::new();
        let deadline = Instant::now() + std::time::Duration::from_millis(100);
        let err = env
            .app
            .index
            .read(deadline, |c| {
                let n: i64 = c.query_row(
                    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c",
                    [],
                    |r| r.get(0),
                )?;
                Ok(n)
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::QueryTooBroad);
        // The pooled connection is usable afterwards.
        let n = env
            .app
            .index
            .read(Instant::now() + std::time::Duration::from_secs(5), |c| {
                Ok(c.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))?)
            })
            .await
            .unwrap();
        assert_eq!(n, 0);
    }
}
