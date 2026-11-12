//! Mailbox sync (spec 7.9 "Full and incremental sync").
//!
//! Backfill fills a fresh generation: capture the history id first, enumerate pages newest-first and index each
//! page before listing the next (the first page is the recent-mail priority pass), record failures for retry,
//! reconcile with history.list from the captured id, then publish. Incremental sync replays history from the
//! committed checkpoint and advances it only after every derived write through that history id has committed.
//! An expired history id (404) starts a rebuild into a new generation; the old one is deleted after cutover.
//!
//! Every write transaction re-checks the job's fence, so a job that outlives a disable/remove/rebuild can never
//! write again. Network calls happen strictly between transactions.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use tokio::sync::Semaphore;

use super::ingest::{self, Doc, GmailMeta};
use super::{Fenced, check_fence, new_generation};
use crate::app::App;
use crate::error::{ErrorCode, ToolError};
use crate::gmail::gateway::{GmailOp, Priority};
use crate::util;

/// Messages fetched per hydrate step.
const BATCH: usize = 16;
/// Distinct changed messages one history replay may carry before it is treated as a gap (rebuild).
const MAX_HISTORY_IDS: usize = 100_000;
/// Base delay for retrying a message that failed transiently.
const RETRY_BASE_SECS: i64 = 30;
const MAX_BACKOFF_SECS: i64 = 15 * 60;
/// Concurrent account sync jobs in the background scheduler.
const MAX_JOBS: usize = 2;

#[derive(Debug, Clone)]
pub struct SyncState {
    pub account_id: String,
    pub fence: i64,
    pub stage: String,
    pub active_gen: Option<i64>,
    pub building_gen: Option<i64>,
    pub checkpoint: Option<String>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
    pub last_error_at: Option<i64>,
    pub backoff_secs: i64,
    pub next_run_at: i64,
    pub data_seq: i64,
}

impl SyncState {
    /// The generation searches read: the published one, or the first backfill while it is still partial.
    pub fn serving_gen(&self) -> Option<i64> {
        self.active_gen.or(self.building_gen)
    }
}

const STATE_COLS: &str = "account_id, fence, stage, active_gen, building_gen, checkpoint, last_success_at, \
    last_error, last_error_at, backoff_secs, next_run_at, data_seq";

fn state_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SyncState> {
    Ok(SyncState {
        account_id: r.get(0)?,
        fence: r.get(1)?,
        stage: r.get(2)?,
        active_gen: r.get(3)?,
        building_gen: r.get(4)?,
        checkpoint: r.get(5)?,
        last_success_at: r.get(6)?,
        last_error: r.get(7)?,
        last_error_at: r.get(8)?,
        backoff_secs: r.get(9)?,
        next_run_at: r.get(10)?,
        data_seq: r.get(11)?,
    })
}

pub fn load_state(c: &Connection, account_id: &str) -> anyhow::Result<Option<SyncState>> {
    Ok(c.query_row(&format!("SELECT {STATE_COLS} FROM sync_state WHERE account_id = ?1"), [account_id], state_from_row)
        .optional()?)
}

pub fn load_all_states(c: &Connection) -> anyhow::Result<Vec<SyncState>> {
    let mut st = c.prepare(&format!("SELECT {STATE_COLS} FROM sync_state ORDER BY account_id"))?;
    Ok(st.query_map([], state_from_row)?.collect::<Result<_, _>>()?)
}

#[derive(Debug, Clone)]
struct GenRow {
    id: i64,
    start_history_id: Option<String>,
    page_token: Option<String>,
    enum_done: bool,
}

fn load_gen(c: &Connection, id: i64) -> anyhow::Result<GenRow> {
    Ok(c.query_row("SELECT id, start_history_id, page_token, enum_done FROM generations WHERE id = ?1", [id], |r| {
        Ok(GenRow { id: r.get(0)?, start_history_id: r.get(1)?, page_token: r.get(2)?, enum_done: r.get(3)? })
    })?)
}

/// Outcome of one explicit sync run (tests and `index status`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SyncReport {
    pub stage: String,
    pub indexed: usize,
    pub removed: usize,
    pub failed: usize,
    pub steps: usize,
    /// The job stopped because the account was disabled, removed or rebuilt meanwhile.
    pub fenced: bool,
    pub skipped_inactive: bool,
    pub error: Option<String>,
}

enum Step {
    More,
    Idle,
}

/// Job identity: account plus the fence it started with.
#[derive(Clone)]
struct Job {
    app: Arc<App>,
    account_id: String,
    fence: i64,
}

impl Job {
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    async fn gmail(&self, op: impl Fn() -> GmailOp<'static>, query: &[(&str, String)]) -> Result<Value, ToolError> {
        self.app.google.call(&self.account_id, op, query, None, Priority::Background, Self::deadline()).await
    }

    async fn gmail_get(&self, id: &str, format: &str) -> Result<Value, ToolError> {
        let id = id.to_string();
        self.app
            .google
            .call(
                &self.account_id,
                || GmailOp::GetMessage(&id),
                &[("format", format.to_string())],
                None,
                Priority::Background,
                Self::deadline(),
            )
            .await
    }

    /// Runs `f` in a write transaction that first re-checks the fence.
    async fn tx<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&Connection) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let (aid, fence) = (self.account_id.clone(), self.fence);
        self.app
            .index
            .write(move |c| {
                let tx = c.transaction()?;
                check_fence(&tx, &aid, fence)?;
                let v = f(&tx)?;
                tx.commit()?;
                Ok(v)
            })
            .await
    }

    async fn state(&self) -> anyhow::Result<SyncState> {
        let aid = self.account_id.clone();
        let fence = self.fence;
        self.app
            .index
            .write(move |c| match load_state(c, &aid)? {
                Some(s) if s.fence == fence => Ok(s),
                _ => Err(Fenced.into()),
            })
            .await
    }
}

/// Is the account active and index-enabled in the durable state store?
async fn account_ready(app: &App, account_id: &str) -> anyhow::Result<bool> {
    let aid = account_id.to_string();
    app.store
        .call(move |c| {
            Ok(c.query_row("SELECT status = 'active' AND index_enabled = 1 FROM accounts WHERE id = ?1", [&aid], |r| {
                r.get::<_, bool>(0)
            })
            .optional()?
            .unwrap_or(false))
        })
        .await
}

fn is_rate_limited(e: &anyhow::Error) -> Option<Option<u64>> {
    e.downcast_ref::<ToolError>().filter(|t| t.code == ErrorCode::RateLimited).map(|t| t.retry_after_seconds)
}

fn error_code(e: &anyhow::Error) -> String {
    if let Some(t) = e.downcast_ref::<ToolError>() {
        return t.code.as_str().to_string();
    }
    if let Some(rusqlite::Error::SqliteFailure(f, _)) = e.downcast_ref::<rusqlite::Error>()
        && f.code == rusqlite::ErrorCode::DiskFull
    {
        return "disk_full".into();
    }
    "internal".into()
}

fn jitter_secs(base: u64) -> i64 {
    let spread = (base / 10).max(1);
    let r = u64::from(u16::from_le_bytes(util::random_bytes::<2>()));
    (r % (spread + 1)) as i64
}

/// Runs sync for one account until it is idle: completes (or continues) a backfill, then one incremental pass.
/// Deterministic entry point used by the scheduler and by tests.
pub async fn sync_account(app: &Arc<App>, account_id: &str) -> anyhow::Result<SyncReport> {
    sync_steps(app, account_id, usize::MAX).await
}

/// Like [`sync_account`] but stops after `max_steps` units of work (capture, one list page, one fetch batch,
/// reconcile + publish, one incremental pass). Lets tests observe a backfill or rebuild in progress.
pub async fn sync_steps(app: &Arc<App>, account_id: &str, max_steps: usize) -> anyhow::Result<SyncReport> {
    // The cancel token is taken before the lock: a disable or rebuild that lands while this job waits for the lock
    // or checks readiness cancels this token, never a fresh one the job would only pick up afterwards.
    let cancel = app.index.cancel_token(account_id);
    let lock = app.index.lock_for(account_id);
    let _guard = lock.lock().await;
    let mut report = SyncReport::default();
    if !account_ready(app, account_id).await? {
        report.skipped_inactive = true;
        return Ok(report);
    }
    let aid = account_id.to_string();
    let Some(st) = app.index.write(move |c| load_state(c, &aid)).await? else {
        return Ok(report);
    };
    let job = Job { app: app.clone(), account_id: account_id.to_string(), fence: st.fence };
    let mut result: anyhow::Result<()> = Ok(());
    loop {
        if cancel.is_cancelled() {
            report.fenced = true;
            break;
        }
        if report.steps >= max_steps {
            break;
        }
        let step = tokio::select! {
            _ = cancel.cancelled() => { report.fenced = true; break; }
            r = one_step(&job, &mut report) => r,
        };
        report.steps += 1;
        match step {
            Ok(Step::More) => continue,
            Ok(Step::Idle) => break,
            Err(e) if e.is::<Fenced>() => {
                report.fenced = true;
                break;
            }
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    if let Err(e) = result {
        let code = error_code(&e);
        report.error = Some(code.clone());
        let rl = is_rate_limited(&e);
        let interval = app.cfg.index.poll_interval_secs.max(1) as i64;
        let aid = account_id.to_string();
        let fence = job.fence;
        let now = util::now_unix();
        let w = app
            .index
            .write(move |c| {
                let tx = c.transaction()?;
                check_fence(&tx, &aid, fence)?;
                let prev: i64 =
                    tx.query_row("SELECT backoff_secs FROM sync_state WHERE account_id = ?1", [&aid], |r| r.get(0))?;
                // Adaptive backoff on quota limits; other failures retry at the normal interval.
                let backoff = match rl {
                    Some(Some(after)) => (after as i64).clamp(1, MAX_BACKOFF_SECS),
                    Some(None) => (prev.max(interval / 2) * 2).clamp(interval, MAX_BACKOFF_SECS),
                    None => interval,
                };
                tx.execute(
                    "UPDATE sync_state SET last_error = ?1, last_error_at = ?2, backoff_secs = ?3, next_run_at = ?4 \
                     WHERE account_id = ?5",
                    params![code, now, if rl.is_some() { backoff } else { 0 }, now + backoff, aid],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await;
        if let Err(e) = w {
            tracing::warn!(error = %e, "could not record sync error");
        }
        tracing::warn!(code = %report.error.as_deref().unwrap_or(""), "index sync pass failed");
    }
    let aid = account_id.to_string();
    report.stage = app
        .index
        .write(move |c| Ok(load_state(c, &aid)?.map(|s| s.stage).unwrap_or_else(|| "disabled".into())))
        .await?;
    Ok(report)
}

async fn one_step(job: &Job, report: &mut SyncReport) -> anyhow::Result<Step> {
    let st = job.state().await?;
    if let Some(g) = st.building_gen {
        return backfill_step(job, &st, g, report).await;
    }
    if let Some(a) = st.active_gen {
        return incremental(job, &st, a, report).await;
    }
    Ok(Step::Idle)
}

// ------------------------------------------------------------------ backfill

async fn backfill_step(job: &Job, st: &SyncState, gen_id: i64, report: &mut SyncReport) -> anyhow::Result<Step> {
    let generation = job.app.index.write(move |c| load_gen(c, gen_id)).await?;
    // 1. Capture the history id before enumeration, so reconciliation covers everything after it.
    let Some(start) = generation.start_history_id.clone() else {
        let profile = job.gmail(|| GmailOp::Profile, &[]).await?;
        let hid = history_id_of(&profile)
            .ok_or_else(|| anyhow::Error::from(ToolError::upstream("profile without history id")))?;
        job.tx(move |tx| {
            tx.execute("UPDATE generations SET start_history_id = ?1 WHERE id = ?2", params![hid, gen_id])?;
            Ok(())
        })
        .await?;
        return Ok(Step::More);
    };
    let now = util::now_unix();
    let (fresh, due): (i64, i64) = job
        .app
        .index
        .write(move |c| {
            Ok(c.query_row(
                "SELECT count(*) FILTER (WHERE attempts = 0), count(*) FILTER (WHERE next_attempt_at <= ?2) \
                 FROM pending WHERE gen = ?1",
                params![gen_id, now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .await?;
    // 2. Index the page already listed before listing more (newest pages first = recent-mail priority).
    if fresh > 0 {
        hydrate(job, gen_id, report).await?;
        return Ok(Step::More);
    }
    if !generation.enum_done {
        list_page(job, &generation).await?;
        return Ok(Step::More);
    }
    if due > 0 {
        let before = report.indexed + report.removed;
        hydrate(job, gen_id, report).await?;
        if report.indexed + report.removed > before {
            return Ok(Step::More);
        }
    }
    // 3. Reconcile arrivals, label changes and deletions since the captured id, then publish.
    let (changes, latest) = match collect_history(job, &start).await? {
        History::Changes(c, h) => (c, h),
        History::Expired => {
            // The captured id expired while backfilling: start over in a fresh generation.
            restart_generation(job, gen_id).await?;
            return Ok(Step::More);
        }
    };
    apply_changes(job, gen_id, changes, report).await?;
    publish(job, st, gen_id, latest).await?;
    Ok(Step::More)
}

async fn restart_generation(job: &Job, old_gen: i64) -> anyhow::Result<()> {
    let aid = job.account_id.clone();
    job.tx(move |tx| {
        let g = new_generation(tx, &aid)?;
        tx.execute("UPDATE sync_state SET building_gen = ?1 WHERE account_id = ?2", params![g, aid])?;
        Ok(())
    })
    .await?;
    job.app.index.cursors.invalidate_account(&job.account_id);
    super::drop_generation(&job.app.index, old_gen).await
}

fn history_id_of(v: &Value) -> Option<String> {
    match &v["historyId"] {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn is_bad_request(e: &ToolError) -> bool {
    e.code == ErrorCode::UpstreamError && e.message.ends_with("HTTP 400")
}

async fn list_page(job: &Job, generation: &GenRow) -> anyhow::Result<()> {
    let page_size = job.app.cfg.index.list_page_size.clamp(1, 500);
    let mut q: Vec<(&str, String)> =
        vec![("maxResults", page_size.to_string()), ("includeSpamTrash", "true".to_string())];
    if let Some(t) = &generation.page_token {
        q.push(("pageToken", t.clone()));
    }
    let gen_id = generation.id;
    let resp = match job.gmail(|| GmailOp::ListMessages, &q).await {
        Ok(v) => v,
        Err(e) if generation.page_token.is_some() && is_bad_request(&e) => {
            // Invalid page token: restart enumeration; upserts and the pending set are idempotent.
            job.tx(move |tx| {
                tx.execute("UPDATE generations SET page_token = NULL WHERE id = ?1", [gen_id])?;
                Ok(())
            })
            .await?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let ids: Vec<String> = resp["messages"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["id"].as_str())
                .filter(|id| crate::gmail::gateway::valid_id(id))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let next = resp["nextPageToken"].as_str().map(str::to_string);
    job.tx(move |tx| {
        let listed: i64 = tx.query_row("SELECT listed FROM generations WHERE id = ?1", [gen_id], |r| r.get(0))?;
        let mut ins = tx.prepare_cached(
            "INSERT OR IGNORE INTO pending(gen, gmail_id, seq) \
             SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM messages WHERE gen = ?1 AND gmail_id = ?2)",
        )?;
        for (i, id) in ids.iter().enumerate() {
            ins.execute(params![gen_id, id, listed + i as i64])?;
        }
        tx.execute(
            "UPDATE generations SET page_token = ?1, enum_done = ?2, listed = listed + ?3 WHERE id = ?4",
            params![next, next.is_none(), ids.len() as i64, gen_id],
        )?;
        Ok(())
    })
    .await
}

enum Fetched {
    Doc(Box<Doc>),
    Labels(GmailMeta),
    Gone,
    Failed(String),
}

/// Most bytes a `format=raw` answer may have for a message of `max_message_bytes`: base64url (4/3) plus the JSON
/// envelope (ids, labels, snippet).
pub fn raw_response_cap(max_message_bytes: usize) -> usize {
    max_message_bytes.div_ceil(3) * 4 + 64 * 1024
}

/// The fields of a `format=raw` answer. `raw` borrows from the response body (base64url needs no JSON escapes), so
/// the encoded message exists once in memory, not twice.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAnswer<'a> {
    #[serde(default)]
    id: Value,
    #[serde(default)]
    thread_id: Value,
    #[serde(default)]
    label_ids: Value,
    #[serde(default)]
    internal_date: Value,
    #[serde(default)]
    size_estimate: Value,
    #[serde(default)]
    snippet: Value,
    /// Empty when absent. Not `Option<Cow<..>>`: serde never borrows through an Option, it would copy.
    #[serde(borrow, default)]
    raw: std::borrow::Cow<'a, str>,
}

/// Parses a raw answer within the per-job memory budget (spec 8.1a): the response body was read with a byte cap,
/// and the encoded message is decoded in place inside that buffer, so it is held once (about 4/3 of the message)
/// plus the MIME parser's working set.
pub fn doc_from_raw_answer(body: Vec<u8>, max_bytes: usize, max_chars: usize) -> Option<Doc> {
    enum Raw {
        Missing,
        At(std::ops::Range<usize>),
        Escaped(Vec<u8>),
    }
    let (meta, raw) = {
        let a: RawAnswer<'_> = serde_json::from_slice(&body).ok()?;
        let meta = GmailMeta::from_json(&serde_json::json!({
            "id": a.id, "threadId": a.thread_id, "labelIds": a.label_ids, "internalDate": a.internal_date,
            "sizeEstimate": a.size_estimate, "snippet": a.snippet,
        }))?;
        let raw = match &a.raw {
            r if r.is_empty() => Raw::Missing,
            std::borrow::Cow::Borrowed(r) => {
                let start = r.as_ptr() as usize - body.as_ptr() as usize;
                Raw::At(start..start + r.len())
            }
            // JSON escapes inside base64url are not expected from Gmail; decode the unescaped copy.
            std::borrow::Cow::Owned(r) => Raw::Escaped(util::b64url_decode(r)?),
        };
        (meta, raw)
    };
    let raw = match raw {
        Raw::Missing => None,
        Raw::At(range) => Some(util::b64url_decode_in_place(body, range)?),
        Raw::Escaped(r) => {
            drop(body);
            Some(r)
        }
    };
    Some(match raw {
        Some(raw) => Doc::from_raw(meta, &raw, max_bytes, max_chars),
        None => Doc::metadata_only(meta),
    })
}

/// Fetches and parses one message under the body-job admission limit. A message whose raw answer exceeds the
/// byte cap is not read further: it is indexed from Gmail metadata only, with incomplete body and MIME coverage.
async fn fetch_full(job: &Job, id: &str) -> Result<Fetched, ToolError> {
    let _permit = job.app.index.body_jobs.clone().acquire_owned().await.map_err(|_| ToolError::internal())?;
    let max_bytes = job.app.cfg.index.max_message_bytes;
    let max_chars = job.app.cfg.index.max_body_chars;
    let owned = id.to_string();
    let fetched = job
        .app
        .google
        .call_bytes(
            &job.account_id,
            || GmailOp::GetMessage(&owned),
            &[("format", "raw".to_string())],
            Priority::Background,
            Job::deadline(),
            raw_response_cap(max_bytes),
        )
        .await;
    let body = match fetched {
        Ok(b) => b,
        Err(e) if e.code == ErrorCode::BudgetExceeded => {
            return Ok(match fetch_labels(job, id).await? {
                Fetched::Labels(meta) => Fetched::Doc(Box::new(Doc::metadata_only(meta))),
                other => other,
            });
        }
        Err(e) if e.code == ErrorCode::NotFound => return Ok(Fetched::Gone),
        Err(e) if matches!(e.code, ErrorCode::RateLimited | ErrorCode::AccountUnavailable) => return Err(e),
        Err(e) => return Ok(Fetched::Failed(e.code.as_str().into())),
    };
    let doc = tokio::task::spawn_blocking(move || doc_from_raw_answer(body, max_bytes, max_chars))
        .await
        .map_err(|_| ToolError::internal())?;
    Ok(match doc {
        Some(d) => Fetched::Doc(Box::new(d)),
        None => Fetched::Failed("upstream_error".into()),
    })
}

async fn fetch_labels(job: &Job, id: &str) -> Result<Fetched, ToolError> {
    match job.gmail_get(id, "minimal").await {
        Ok(v) => Ok(GmailMeta::from_json(&v).map(Fetched::Labels).unwrap_or(Fetched::Failed("upstream_error".into()))),
        Err(e) if e.code == ErrorCode::NotFound => Ok(Fetched::Gone),
        Err(e) if matches!(e.code, ErrorCode::RateLimited | ErrorCode::AccountUnavailable) => Err(e),
        Err(e) => Ok(Fetched::Failed(e.code.as_str().into())),
    }
}

fn retry_delay(attempts: i64) -> i64 {
    (RETRY_BASE_SECS << attempts.clamp(0, 10)).min(6 * 3600)
}

/// Applies fetched results to a generation in one fenced transaction. Failures become retry records.
async fn commit_results(
    job: &Job,
    gen_id: i64,
    results: Vec<(String, Fetched)>,
    report: &mut SyncReport,
) -> anyhow::Result<()> {
    let aid = job.account_id.clone();
    let now = util::now_unix();
    let (indexed, removed, failed) = job
        .tx(move |tx| {
            let (mut indexed, mut removed, mut failed) = (0, 0, 0);
            for (id, r) in &results {
                match r {
                    Fetched::Doc(d) => {
                        ingest::upsert(tx, gen_id, &aid, d)?;
                        tx.execute("DELETE FROM pending WHERE gen = ?1 AND gmail_id = ?2", params![gen_id, id])?;
                        indexed += 1;
                    }
                    Fetched::Labels(m) => {
                        if ingest::update_labels(tx, gen_id, id, &m.labels)? {
                            indexed += 1;
                        }
                    }
                    Fetched::Gone => {
                        // A vanished message removes the candidate (spec 7.9 step 1).
                        ingest::remove(tx, gen_id, id)?;
                        tx.execute("DELETE FROM pending WHERE gen = ?1 AND gmail_id = ?2", params![gen_id, id])?;
                        removed += 1;
                    }
                    Fetched::Failed(code) => {
                        let attempts: i64 = tx
                            .query_row(
                                "SELECT attempts FROM pending WHERE gen = ?1 AND gmail_id = ?2",
                                params![gen_id, id],
                                |r| r.get(0),
                            )
                            .optional()?
                            .unwrap_or(0);
                        tx.execute(
                            "INSERT INTO pending(gen, gmail_id, seq, attempts, next_attempt_at, last_error) \
                             VALUES (?1, ?2, 0, ?3, ?4, ?5) \
                             ON CONFLICT(gen, gmail_id) DO UPDATE SET attempts = excluded.attempts, \
                             next_attempt_at = excluded.next_attempt_at, last_error = excluded.last_error",
                            params![gen_id, id, attempts + 1, now + retry_delay(attempts), code],
                        )?;
                        failed += 1;
                    }
                }
            }
            if indexed + removed > 0 {
                tx.execute("UPDATE sync_state SET data_seq = data_seq + 1 WHERE account_id = ?1", [&aid])?;
            }
            Ok((indexed, removed, failed))
        })
        .await?;
    report.indexed += indexed;
    report.removed += removed;
    report.failed += failed;
    Ok(())
}

/// Fetches and indexes one batch of due pending messages.
async fn hydrate(job: &Job, gen_id: i64, report: &mut SyncReport) -> anyhow::Result<()> {
    let now = util::now_unix();
    let ids: Vec<String> = job
        .app
        .index
        .write(move |c| {
            let mut st = c.prepare_cached(
                "SELECT gmail_id FROM pending WHERE gen = ?1 AND next_attempt_at <= ?2 \
                 ORDER BY next_attempt_at, seq LIMIT ?3",
            )?;
            Ok(st.query_map(params![gen_id, now, BATCH as i64], |r| r.get(0))?.collect::<Result<_, _>>()?)
        })
        .await?;
    let jobs = job.app.index.cfg.body_jobs.clamp(1, 8);
    let results: Vec<(String, Result<Fetched, ToolError>)> = stream::iter(ids)
        .map(|id| async move {
            let r = fetch_full(job, &id).await;
            (id, r)
        })
        .buffered(jobs)
        .collect()
        .await;
    let mut fatal = None;
    let mut ok = vec![];
    for (id, r) in results {
        match r {
            Ok(f) => ok.push((id, f)),
            Err(e) => fatal = fatal.or(Some(e)),
        }
    }
    commit_results(job, gen_id, ok, report).await?;
    match fatal {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

// ------------------------------------------------------------------ history

#[derive(Debug, Default, Clone, Copy)]
struct Change {
    added: bool,
    deleted: bool,
    labels: bool,
}

enum History {
    Changes(BTreeMap<String, Change>, String),
    /// history.list returned 404: the start id is older than Gmail keeps.
    Expired,
}

fn ids_in(rec: &Value, key: &str) -> Vec<String> {
    rec[key]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x["message"]["id"].as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Reads every history page from `start`, coalescing repeated message ids. Returns the history id of the first page
/// response: everything up to it is covered by this pass. Later pages may report a newer mailbox id while records
/// appended during pagination are not on them; taking that id would let the checkpoint pass unseen records.
/// Records newer than the first page's id that did show up are applied now and replayed next pass (idempotent).
async fn collect_history(job: &Job, start: &str) -> anyhow::Result<History> {
    let mut changes: BTreeMap<String, Change> = BTreeMap::new();
    let mut token: Option<String> = None;
    let mut covered: Option<String> = None;
    loop {
        let mut q: Vec<(&str, String)> = vec![("startHistoryId", start.to_string()), ("maxResults", "500".into())];
        if let Some(t) = &token {
            q.push(("pageToken", t.clone()));
        }
        let resp = match job.gmail(|| GmailOp::History, &q).await {
            Ok(v) => v,
            Err(e) if e.code == ErrorCode::NotFound => return Ok(History::Expired),
            Err(e) => return Err(e.into()),
        };
        if token.is_none() {
            // First page.
            covered = history_id_of(&resp);
        }
        for rec in resp["history"].as_array().into_iter().flatten() {
            for id in ids_in(rec, "messagesAdded") {
                changes.entry(id).or_default().added = true;
            }
            for id in ids_in(rec, "messagesDeleted") {
                changes.entry(id).or_default().deleted = true;
            }
            for id in ids_in(rec, "labelsAdded").into_iter().chain(ids_in(rec, "labelsRemoved")) {
                changes.entry(id).or_default().labels = true;
            }
        }
        if changes.len() > MAX_HISTORY_IDS {
            // Too much change to replay safely: treat like a history gap.
            return Ok(History::Expired);
        }
        token = resp["nextPageToken"].as_str().map(str::to_string);
        if token.is_none() {
            break;
        }
    }
    changes.retain(|id, _| crate::gmail::gateway::valid_id(id));
    Ok(History::Changes(changes, covered.unwrap_or_else(|| start.to_string())))
}

/// Fetches canonical state for changed messages and writes it in fenced chunks.
async fn apply_changes(
    job: &Job,
    gen_id: i64,
    changes: BTreeMap<String, Change>,
    report: &mut SyncReport,
) -> anyhow::Result<()> {
    let all: Vec<(String, Change)> = changes.into_iter().collect();
    for chunk in all.chunks(BATCH) {
        let ids: Vec<String> = chunk.iter().map(|(i, _)| i.clone()).collect();
        let known: HashSet<String> = job
            .app
            .index
            .write(move |c| {
                let mut out = HashSet::new();
                let mut st = c.prepare_cached("SELECT 1 FROM messages WHERE gen = ?1 AND gmail_id = ?2")?;
                for id in ids {
                    if st.exists(params![gen_id, id])? {
                        out.insert(id);
                    }
                }
                Ok(out)
            })
            .await?;
        let jobs = job.app.index.cfg.body_jobs.clamp(1, 8);
        let known = &known;
        let results: Vec<(String, Result<Fetched, ToolError>)> = stream::iter(chunk.iter().cloned())
            .map(|(id, ch)| async move {
                let r = if ch.deleted {
                    Ok(Fetched::Gone)
                } else if ch.added || !known.contains(&id) {
                    fetch_full(job, &id).await
                } else {
                    fetch_labels(job, &id).await
                };
                (id, r)
            })
            .buffered(jobs)
            .collect()
            .await;
        let mut fatal = None;
        let mut ok = vec![];
        for (id, r) in results {
            match r {
                Ok(f) => ok.push((id, f)),
                Err(e) => fatal = fatal.or(Some(e)),
            }
        }
        commit_results(job, gen_id, ok, report).await?;
        if let Some(e) = fatal {
            return Err(e.into());
        }
    }
    Ok(())
}

/// Cutover: the building generation becomes active at history id `latest`; a previous one is retired and deleted.
async fn publish(job: &Job, st: &SyncState, gen_id: i64, latest: String) -> anyhow::Result<()> {
    let aid = job.account_id.clone();
    let old = st.active_gen;
    let now = util::now_unix();
    let interval = job.app.cfg.index.poll_interval_secs.max(1);
    let next = now + interval as i64 + jitter_secs(interval);
    job.tx(move |tx| {
        tx.execute("UPDATE generations SET state = 'active', completed_at = ?1 WHERE id = ?2", params![now, gen_id])?;
        if let Some(o) = old {
            tx.execute("UPDATE generations SET state = 'retired' WHERE id = ?1", [o])?;
        }
        tx.execute(
            "UPDATE sync_state SET active_gen = ?1, building_gen = NULL, stage = 'ready', checkpoint = ?2, \
             last_success_at = ?3, last_error = NULL, backoff_secs = 0, next_run_at = ?4, data_seq = data_seq + 1 \
             WHERE account_id = ?5",
            params![gen_id, latest, now, next, aid],
        )?;
        Ok(())
    })
    .await?;
    job.app.index.cursors.invalidate_account(&job.account_id);
    if let Some(o) = old {
        // Delete the retired generation in bounded chunks so the writer is never held for long.
        super::drop_generation(&job.app.index, o).await?;
    }
    Ok(())
}

// ------------------------------------------------------------------ incremental

async fn incremental(job: &Job, st: &SyncState, gen_id: i64, report: &mut SyncReport) -> anyhow::Result<Step> {
    let Some(start) = st.checkpoint.clone() else {
        return Ok(Step::Idle);
    };
    let (changes, latest) = match collect_history(job, &start).await? {
        History::Changes(c, h) => (c, h),
        History::Expired => {
            // History gap: mark rebuilding, invalidate cursors, reconcile fully into a new generation. The old
            // generation stays readable but is never reported complete.
            let aid = job.account_id.clone();
            job.tx(move |tx| {
                let g = new_generation(tx, &aid)?;
                tx.execute(
                    "UPDATE sync_state SET stage = 'rebuilding', building_gen = ?1, data_seq = data_seq + 1 \
                     WHERE account_id = ?2",
                    params![g, aid],
                )?;
                Ok(())
            })
            .await?;
            job.app.index.cursors.invalidate_account(&job.account_id);
            return Ok(Step::More);
        }
    };
    let changed = !changes.is_empty();
    apply_changes(job, gen_id, changes, report).await?;
    // Every derived write through `latest` has committed: advance the checkpoint and record the check.
    let aid = job.account_id.clone();
    let now = util::now_unix();
    let interval = job.app.cfg.index.poll_interval_secs.max(1);
    let next = now + interval as i64 + jitter_secs(interval);
    job.tx(move |tx| {
        tx.execute(
            "UPDATE sync_state SET checkpoint = ?1, last_success_at = ?2, last_error = NULL, backoff_secs = 0, \
             next_run_at = ?3, data_seq = data_seq + ?4 WHERE account_id = ?5",
            params![latest, now, next, changed as i64, aid],
        )?;
        Ok(())
    })
    .await?;
    // Retry records that are due.
    let due: i64 = job
        .app
        .index
        .write(move |c| {
            Ok(c.query_row(
                "SELECT count(*) FROM pending WHERE gen = ?1 AND next_attempt_at <= ?2",
                params![gen_id, now],
                |r| r.get(0),
            )?)
        })
        .await?;
    if due > 0 {
        hydrate(job, gen_id, report).await?;
    }
    Ok(Step::Idle)
}

// ------------------------------------------------------------------ scheduler

/// Background loop: reconciles enabled accounts with index state, then runs due accounts (poll interval with
/// jitter, wake-ups after Dove writes, backoff after quota errors). At most [`MAX_JOBS`] accounts sync at once.
pub async fn scheduler(app: Arc<App>) {
    let sem = Arc::new(Semaphore::new(MAX_JOBS));
    let running: Arc<std::sync::Mutex<HashSet<String>>> = Default::default();
    let collecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
    loop {
        if let Err(e) = tick(&app, &sem, &running).await {
            tracing::warn!(error = %e, "index scheduler tick failed");
        }
        // Unreferenced generations (interrupted purge or drop, abandoned by the V3 migration) are collected in the
        // background in bounded transactions; one collector at a time.
        if !collecting.swap(true, std::sync::atomic::Ordering::AcqRel) {
            let (app, collecting) = (app.clone(), collecting.clone());
            tokio::spawn(async move {
                if let Err(e) = super::collect_garbage(&app.index, None).await {
                    tracing::warn!(error = %e, "index garbage collection failed");
                }
                collecting.store(false, std::sync::atomic::Ordering::Release);
            });
        }
        tokio::select! {
            _ = app.index.wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn tick(
    app: &Arc<App>,
    sem: &Arc<Semaphore>,
    running: &Arc<std::sync::Mutex<HashSet<String>>>,
) -> anyhow::Result<()> {
    let enabled: HashMap<String, bool> = app
        .store
        .call(|c| {
            let mut st = c.prepare("SELECT id, status = 'active' FROM accounts WHERE index_enabled = 1")?;
            Ok(st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
        })
        .await?;
    let states: Vec<SyncState> = app.index.write(|c| load_all_states(c)).await?;
    for s in &states {
        if !enabled.contains_key(&s.account_id) {
            super::purge_account(app, &s.account_id).await;
        }
    }
    let known: HashSet<&str> = states.iter().map(|s| s.account_id.as_str()).collect();
    for aid in enabled.keys() {
        if !known.contains(aid.as_str()) {
            super::ensure_state(app, aid).await?;
        }
    }
    let woken = app.index.take_woken();
    let now = util::now_unix();
    let next_run: HashMap<&str, i64> = states.iter().map(|s| (s.account_id.as_str(), s.next_run_at)).collect();
    for (aid, active) in &enabled {
        if !active {
            continue;
        }
        let due = woken.contains(aid) || next_run.get(aid.as_str()).is_none_or(|t| *t <= now);
        if !due || !running.lock().expect("lock").insert(aid.clone()) {
            continue;
        }
        let (app, sem, running, aid) = (app.clone(), sem.clone(), running.clone(), aid.clone());
        tokio::spawn(async move {
            let _permit = sem.acquire_owned().await;
            if let Err(e) = sync_account(&app, &aid).await {
                tracing::warn!(error = %e, "index sync failed");
            }
            running.lock().expect("lock").remove(&aid);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestEnv;

    async fn enabled_account(env: &TestEnv, alias: &str) -> String {
        let aid = env.add_account(alias, &format!("{alias}@example.com"), "rt");
        let a = aid.clone();
        env.app
            .store
            .call(move |c| {
                c.execute("UPDATE accounts SET index_enabled = 1 WHERE id = ?1", [&a])?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(super::super::ensure_state(&env.app, &aid).await.unwrap());
        aid
    }

    async fn rows(env: &TestEnv) -> i64 {
        env.app.index.write(|c| Ok(c.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?)).await.unwrap()
    }

    /// A disable that lands after a job passed its readiness check (here: while it waits for the account lock) cancels
    /// that job: it stops without a Gmail call instead of backfilling a mailbox that is being purged.
    #[tokio::test]
    async fn cancel_while_waiting_for_the_lock_stops_the_job() {
        // Nothing listens on the discard port, so a job that wrongly runs fails fast instead of reaching Google.
        let env = TestEnv::with_upstream(crate::gmail::gateway::Upstream::single_origin("http://127.0.0.1:9"), |_| {});
        let aid = enabled_account(&env, "info").await;
        let lock = env.app.index.lock_for(&aid);
        let guard = lock.lock().await;
        let (app, a) = (env.app.clone(), aid.clone());
        let job = tokio::spawn(async move { sync_steps(&app, &a, usize::MAX).await });
        // Wait until the job holds its cancel token and blocks on the lock.
        for _ in 0..10_000 {
            if env.app.index.cancels.lock().unwrap().contains_key(&aid) {
                break;
            }
            tokio::task::yield_now().await;
        }
        env.app.index.cancel(&aid);
        drop(guard);
        let r = job.await.unwrap().unwrap();
        assert!(r.fenced, "{r:?}");
        assert_eq!(r.steps, 0, "{r:?}");
        assert_eq!(env.app.google.gateway().calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    /// The fence alone (without cancellation or the account lock) stops a job that outlived a rebuild or purge.
    #[tokio::test]
    async fn stale_fence_cannot_write() {
        let env = TestEnv::new();
        let aid = enabled_account(&env, "info").await;
        let a = aid.clone();
        let st = env.app.index.write(move |c| load_state(c, &a)).await.unwrap().unwrap();
        let job = Job { app: env.app.clone(), account_id: aid.clone(), fence: st.fence };
        let doc = Doc::metadata_only(GmailMeta { id: "abc".into(), thread_id: "t".into(), ..Default::default() });

        // Same fence: the write lands.
        let (a, d, g) = (aid.clone(), doc.clone(), st.building_gen.unwrap());
        job.tx(move |tx| ingest::upsert(tx, g, &a, &d)).await.unwrap();
        assert_eq!(rows(&env).await, 1);

        // After a rebuild the old job is fenced off.
        super::super::admin::start_rebuild(&env.app, &aid).await.unwrap();
        let a = aid.clone();
        let st2 = env.app.index.write(move |c| load_state(c, &a)).await.unwrap().unwrap();
        assert_ne!(st2.fence, st.fence);
        let (a, d, g2) = (aid.clone(), doc.clone(), st2.building_gen.unwrap());
        let err = job.tx(move |tx| ingest::upsert(tx, g2, &a, &d)).await.unwrap_err();
        assert!(err.is::<Fenced>(), "{err}");

        // After a purge a job with the current fence is fenced off too and nothing is repopulated.
        let job2 = Job { app: env.app.clone(), account_id: aid.clone(), fence: st2.fence };
        super::super::purge_account(&env.app, &aid).await;
        assert_eq!(rows(&env).await, 0);
        let (a, d) = (aid.clone(), doc.clone());
        let err = job2.tx(move |tx| ingest::upsert(tx, g2, &a, &d)).await.unwrap_err();
        assert!(err.is::<Fenced>(), "{err}");
        assert_eq!(rows(&env).await, 0);
    }
}
