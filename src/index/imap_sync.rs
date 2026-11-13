//! IMAP mailbox sync (design "Search and index"). Same generations, fences, cursors and pending/retry records as the
//! Gmail engine in [`super::sync`], which runs this one for IMAP accounts under the same account lock, cancellation
//! and error handling.
//!
//! Index rows are keyed by the agent-visible id `f<folder>-<uidvalidity>-<uid>`, so one folder's rows of one
//! UIDVALIDITY are a contiguous key range of `messages(gen, gmail_id)`. Each folder has a checkpoint per generation
//! (`imap_checkpoints`: UIDVALIDITY, UIDNEXT, HIGHESTMODSEQ). A job runs one scan over all folders, then fetches the
//! pending messages in batches; a backfill publishes its generation after that.
//!
//! One folder scan:
//! - New or reset folder (no checkpoint, or UIDVALIDITY changed): checkpoint first, drop the folder's rows of any
//!   other UIDVALIDITY (old ids become `not_found`), then all UIDs into `pending`, newest first. Ranks are per
//!   folder, so batches take the newest message of every folder before older ones (recent mail first).
//! - Known folder: new UIDs from the checkpoint's UIDNEXT; flag changes via CONDSTORE `CHANGEDSINCE` (with QRESYNC
//!   `VANISHED` for expunges); deletions otherwise by count and, only on a mismatch, a `UID SEARCH ALL` diff.
//! - Without CONDSTORE (Strato, for example) flags are re-read with flags-only FETCHes: every scan re-reads the
//!   newest [`RECENT_FLAGS`] UIDs (where read/unread changes happen) plus a rotating window of [`ROTATE_FLAGS`]
//!   older ones, in commands of [`FLAG_CHUNK`] UIDs. A scan therefore costs at most
//!   (`RECENT_FLAGS` + `ROTATE_FLAGS`) / `FLAG_CHUNK` + 1 FETCH commands per folder whatever its size, and a folder
//!   of n messages is fully refreshed within ceil(n / `ROTATE_FLAGS`) scans.
//!
//! Network calls never run inside an index transaction; every write re-checks the job's fence.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};

use super::ingest::{self, Doc};
use super::sync::{self, BATCH, Fetched, Job, Step, SyncReport, commit_results, load_state};
use crate::app::App;
use crate::error::ToolError;
use crate::gmail::gateway::Priority;
use crate::imap::account::{self, Folder};
use crate::imap::{FetchedMeta, FolderStatus, ImapError, ImapMsgId, ImapSession};
use crate::mail::{self, MessageMeta};
use crate::util;

/// Newest UIDs per folder whose flags every scan re-reads when the server lacks CONDSTORE.
pub const RECENT_FLAGS: usize = 256;
/// Older UIDs per folder re-read per scan, in rotation, when the server lacks CONDSTORE.
pub const ROTATE_FLAGS: usize = 1024;
/// UIDs per flags FETCH command.
pub const FLAG_CHUNK: usize = 512;
/// Pending records written per transaction when a folder is enumerated.
const ENUM_CHUNK: usize = 5000;
/// Rows deleted per transaction when a folder is dropped or reset.
const DROP_ROWS: i64 = 2000;
/// Most thread members `get_thread` resolves from the index.
pub const MAX_THREAD: i64 = 500;

/// Wall-clock bound of one scan or one fetch batch (`index.imap_step_timeout_secs`). Every read already has the
/// command timeout, but a slow or hostile server answering just inside it could otherwise hold a session and its
/// upstream slots for as long as it likes.
fn step_deadline(app: &App) -> Duration {
    Duration::from_secs(app.cfg.index.imap_step_timeout_secs.max(1))
}

fn step_timed_out() -> ToolError {
    ToolError::upstream("the mail server is too slow: the sync step ran out of time")
}

/// Entry point with the same contract as [`sync::sync_steps`] (which dispatches IMAP accounts here).
pub async fn sync_steps(app: &Arc<App>, account_id: &str, max_steps: usize) -> anyhow::Result<SyncReport> {
    sync::sync_steps(app, account_id, max_steps).await
}

/// Per-job progress: one scan per job, then batches until nothing fresh is pending.
#[derive(Default)]
pub(super) struct JobState {
    scanned_at: Option<i64>,
    retried: bool,
}

pub(super) async fn one_step(job: &Job, js: &mut JobState, report: &mut SyncReport) -> anyhow::Result<Step> {
    let st = job.state().await?;
    let Some(gen_id) = st.building_gen.or(st.active_gen) else {
        return Ok(Step::Idle);
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
    if fresh > 0 {
        hydrate(job, gen_id, report).await?;
        return Ok(Step::More);
    }
    let Some(as_of) = js.scanned_at else {
        // Data is complete as of the scan start: everything after it is caught by the next scan.
        let at = util::now_unix();
        scan(job, gen_id, report).await?;
        js.scanned_at = Some(at);
        return Ok(Step::More);
    };
    if due > 0 && !js.retried {
        js.retried = true;
        hydrate(job, gen_id, report).await?;
        return Ok(Step::More);
    }
    if st.building_gen == Some(gen_id) {
        sync::publish(job, &st, gen_id, None, as_of).await?;
        return Ok(Step::Idle);
    }
    let aid = job.account_id.clone();
    let interval = job.app.cfg.index.poll_interval_secs.max(1);
    let next = util::now_unix() + interval as i64 + sync::jitter_secs(interval);
    job.tx(move |tx| {
        tx.execute(
            "UPDATE sync_state SET last_success_at = ?1, last_error = NULL, backoff_secs = 0, next_run_at = ?2 \
             WHERE account_id = ?3",
            params![as_of, next, aid],
        )?;
        Ok(())
    })
    .await?;
    Ok(Step::Idle)
}

/// One bounded INBOX pass for search freshness (`imap_idle::ensure_fresh`): new mail, CONDSTORE flag changes and
/// expunges of INBOX, then one fetch batch. Runs under the account lock, fence and cancellation like a job, only on
/// a ready index, and never advances `last_success_at` (it did not look at the other folders), so `as_of` stays
/// honest. Returns the number of messages indexed. Callers bound it with a timeout; dropping it is safe because no
/// transaction spans network I/O.
pub async fn quick_inbox(app: &Arc<App>, account_id: &str) -> anyhow::Result<usize> {
    let cancel = app.index.cancel_token(account_id);
    let lock = app.index.lock_for(account_id);
    let _guard = lock.lock().await;
    if sync::account_ready(app, account_id).await?.as_deref() != Some("imap") {
        return Ok(0);
    }
    let aid = account_id.to_string();
    let Some(st) = app.index.write(move |c| load_state(c, &aid)).await? else { return Ok(0) };
    let (Some(gen_id), None) = (st.active_gen, st.building_gen) else { return Ok(0) };
    let job = Job { app: app.clone(), account_id: account_id.to_string(), fence: st.fence };
    let mut report = SyncReport::default();
    let work = async {
        let sc = Scanner { job: job.clone(), gen_id, stats: Arc::default() };
        let r = account::with_session(app, account_id, move |s| {
            Box::pin(async move {
                match sc.inbox(s).await {
                    Ok(()) => Ok(Ok(())),
                    Err(ScanErr::Imap(e)) => Err(e),
                    Err(ScanErr::Db(e)) => Ok(Err(e)),
                }
            })
        })
        .await;
        match r {
            Ok(inner) => inner?,
            Err(e) => return Err(anyhow::Error::from(e)),
        }
        hydrate(&job, gen_id, &mut report).await
    };
    tokio::select! {
        _ = cancel.cancelled() => {}
        r = work => r?,
    }
    Ok(report.indexed)
}

// ------------------------------------------------------------------ id ranges

/// Key range `[lo, hi)` of a folder's ids: all UIDVALIDITYs, or one. `-` sorts right before `.`, so the prefix
/// `f3-` is exactly `[f3-, f3.)` and does not include folder 31.
fn folder_range(folder_id: i64, uidvalidity: Option<u32>) -> (String, String) {
    match uidvalidity {
        None => (format!("f{folder_id}-"), format!("f{folder_id}.")),
        Some(v) => (format!("f{folder_id}-{v}-"), format!("f{folder_id}-{v}.")),
    }
}

fn msg_id(folder_id: i64, uidvalidity: u32, uid: u32) -> String {
    ImapMsgId { folder_id, uidvalidity, uid }.encode()
}

// ------------------------------------------------------------------ checkpoints

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Checkpoint {
    uidvalidity: u32,
    uidnext: u32,
    highestmodseq: Option<u64>,
    enumerated: bool,
    flag_cursor: u32,
}

fn load_checkpoints(c: &Connection, account_id: &str, gen_id: i64) -> anyhow::Result<HashMap<i64, Checkpoint>> {
    let mut st = c.prepare_cached(
        "SELECT folder_id, uidvalidity, uidnext, highestmodseq, enumerated, flag_cursor FROM imap_checkpoints \
         WHERE account_id = ?1 AND gen = ?2",
    )?;
    let rows = st.query_map(params![account_id, gen_id], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            Checkpoint {
                uidvalidity: r.get(1)?,
                uidnext: r.get(2)?,
                highestmodseq: r.get::<_, Option<i64>>(3)?.map(|m| m as u64),
                enumerated: r.get(4)?,
                flag_cursor: r.get(5)?,
            },
        ))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// What a folder scan changed (merged into the job report).
#[derive(Default)]
struct Stats {
    updated: usize,
    removed: usize,
}

/// Scan errors: the wire error drops the session; an index error (including [`super::Fenced`]) does not.
enum ScanErr {
    Imap(ImapError),
    Db(anyhow::Error),
}

impl From<ImapError> for ScanErr {
    fn from(e: ImapError) -> Self {
        ScanErr::Imap(e)
    }
}

impl From<anyhow::Error> for ScanErr {
    fn from(e: anyhow::Error) -> Self {
        ScanErr::Db(e)
    }
}

/// One scan of all folders of a generation on one pooled session.
#[derive(Clone)]
struct Scanner {
    job: Job,
    gen_id: i64,
    stats: Arc<Mutex<Stats>>,
}

async fn scan(job: &Job, gen_id: i64, report: &mut SyncReport) -> anyhow::Result<()> {
    let sc = Scanner { job: job.clone(), gen_id, stats: Arc::default() };
    let stats = sc.stats.clone();
    let session = account::with_session_prio(&job.app, &job.account_id, Priority::Background, move |s| {
        Box::pin(async move {
            match sc.run(s).await {
                Ok(()) => Ok(Ok(())),
                Err(ScanErr::Imap(e)) => Err(e),
                Err(ScanErr::Db(e)) => Ok(Err(e)),
            }
        })
    });
    // Folders finished before the deadline keep their checkpoints; the next scan continues cheaply.
    let r = tokio::time::timeout(step_deadline(&job.app), session).await.unwrap_or_else(|_| Err(step_timed_out()));
    {
        let st = stats.lock().expect("lock");
        report.indexed += st.updated;
        report.removed += st.removed;
    }
    match r {
        Ok(inner) => inner,
        Err(e) => Err(e.into()),
    }
}

impl Scanner {
    async fn tx<F, T>(&self, f: F) -> Result<T, ScanErr>
    where
        F: FnOnce(&Connection) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        Ok(self.job.tx(f).await?)
    }

    async fn run(&self, s: &mut ImapSession) -> Result<(), ScanErr> {
        // Expunges are reported as VANISHED when the server offers QRESYNC (no-op otherwise).
        s.enable_qresync().await?;
        let listed = s.list_folders().await?;
        let live_names: HashSet<String> = listed.iter().filter(|f| f.selectable).map(|f| f.raw_name.clone()).collect();
        let aid = self.job.account_id.clone();
        let folders: Vec<Folder> = self
            .job
            .app
            .store
            .call(move |c| {
                let tx = c.transaction()?;
                account::upsert_folders(&tx, &aid, &listed, None)?;
                tx.commit()?;
                account::load_folders(c, &aid)
            })
            .await?;
        let live: Vec<Folder> = folders.into_iter().filter(|f| live_names.contains(&f.name)).collect();
        let (aid, g) = (self.job.account_id.clone(), self.gen_id);
        let cps = self.job.app.index.write(move |c| load_checkpoints(c, &aid, g)).await?;
        // A folder that is gone (deleted or renamed: a rename is a new folder) takes its rows with it.
        let live_ids: HashSet<i64> = live.iter().map(|f| f.folder_id).collect();
        for fid in cps.keys().filter(|f| !live_ids.contains(f)) {
            self.drop_folder(*fid, None).await?;
        }
        for f in &live {
            let st = match s.select(&f.name, true).await {
                Ok(st) => st,
                Err(ImapError::Missing) => {
                    self.drop_folder(f.folder_id, None).await?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            match cps.get(&f.folder_id) {
                Some(cp) if cp.uidvalidity == st.uidvalidity && cp.enumerated => {
                    self.incremental(s, f, *cp, st, true).await?
                }
                cp => self.enumerate(s, f, cp.copied(), st).await?,
            }
        }
        Ok(())
    }

    async fn write_checkpoint(&self, folder_id: i64, cp: Checkpoint) -> Result<(), ScanErr> {
        let (aid, g) = (self.job.account_id.clone(), self.gen_id);
        self.tx(move |tx| {
            tx.execute(
                "INSERT INTO imap_checkpoints(account_id, gen, folder_id, uidvalidity, uidnext, highestmodseq, \
                 enumerated, flag_cursor) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                 ON CONFLICT(account_id, gen, folder_id) DO UPDATE SET uidvalidity = excluded.uidvalidity, \
                 uidnext = excluded.uidnext, highestmodseq = excluded.highestmodseq, enumerated = excluded.enumerated, \
                 flag_cursor = excluded.flag_cursor",
                params![
                    aid,
                    g,
                    folder_id,
                    cp.uidvalidity,
                    cp.uidnext,
                    cp.highestmodseq.map(|m| m as i64),
                    cp.enumerated,
                    cp.flag_cursor
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// (Re)starts a folder: checkpoint, drop rows of other UIDVALIDITYs, all UIDs into `pending` newest first.
    async fn enumerate(
        &self,
        s: &mut ImapSession,
        f: &Folder,
        old: Option<Checkpoint>,
        st: FolderStatus,
    ) -> Result<(), ScanErr> {
        let mut cp = Checkpoint {
            uidvalidity: st.uidvalidity,
            uidnext: st.uidnext,
            highestmodseq: st.highestmodseq,
            enumerated: false,
            flag_cursor: 0,
        };
        // From here on an interruption re-enumerates (enumerated = 0); stale rows are dropped every time.
        self.write_checkpoint(f.folder_id, cp).await?;
        if self.drop_folder(f.folder_id, Some(st.uidvalidity)).await? > 0
            || old.is_some_and(|o| o.uidvalidity != st.uidvalidity)
        {
            // Ids changed under paged results: cursors over this mailbox are invalid.
            self.job.app.index.cursors.invalidate_account(&self.job.account_id);
        }
        let mut uids = s.uid_search_all().await?;
        uids.sort_unstable_by(|a, b| b.cmp(a));
        for (n, chunk) in uids.chunks(ENUM_CHUNK).enumerate() {
            self.add_pending(f.folder_id, st.uidvalidity, chunk, (n * ENUM_CHUNK) as i64).await?;
        }
        cp.enumerated = true;
        cp.uidnext = cp.uidnext.max(uids.first().map_or(0, |u| u.saturating_add(1)));
        self.write_checkpoint(f.folder_id, cp).await
    }

    /// The quick INBOX pass of [`quick_inbox`]: INBOX only, from the folder list Dove already has (no `LIST`), and
    /// only when its checkpoint is current. New folders and UIDVALIDITY resets are left to the full scan.
    async fn inbox(&self, s: &mut ImapSession) -> Result<(), ScanErr> {
        let aid = self.job.account_id.clone();
        let folders = self.job.app.store.call(move |c| account::load_folders(c, &aid)).await?;
        let Some(f) = folders.into_iter().find(|f| f.name.eq_ignore_ascii_case("INBOX")) else { return Ok(()) };
        let (aid, g) = (self.job.account_id.clone(), self.gen_id);
        let cps = self.job.app.index.write(move |c| load_checkpoints(c, &aid, g)).await?;
        let Some(cp) = cps.get(&f.folder_id).copied().filter(|cp| cp.enumerated) else { return Ok(()) };
        s.enable_qresync().await?;
        let st = s.select(&f.name, true).await?;
        if st.uidvalidity != cp.uidvalidity {
            return Ok(());
        }
        self.incremental(s, &f, cp, st, false).await
    }

    /// Records UIDs as pending (unless already indexed); `seq` grows with the rank, newest first.
    async fn add_pending(
        &self,
        folder_id: i64,
        uidvalidity: u32,
        uids: &[u32],
        first_rank: i64,
    ) -> Result<(), ScanErr> {
        if uids.is_empty() {
            return Ok(());
        }
        let g = self.gen_id;
        let ids: Vec<String> = uids.iter().map(|u| msg_id(folder_id, uidvalidity, *u)).collect();
        self.tx(move |tx| {
            let mut ins = tx.prepare_cached(
                "INSERT OR IGNORE INTO pending(gen, gmail_id, seq) \
                 SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM messages WHERE gen = ?1 AND gmail_id = ?2)",
            )?;
            for (i, id) in ids.iter().enumerate() {
                ins.execute(params![g, id, first_rank + i as i64])?;
            }
            Ok(())
        })
        .await
    }

    /// UIDs of the folder (one UIDVALIDITY) that are indexed, and those still pending.
    async fn known(&self, folder_id: i64, uidvalidity: u32) -> Result<(Vec<u32>, Vec<u32>), ScanErr> {
        let g = self.gen_id;
        let (lo, hi) = folder_range(folder_id, Some(uidvalidity));
        let r = self
            .job
            .app
            .index
            .write(move |c| {
                let uid = |id: String| ImapMsgId::parse(&id).map(|m| m.uid);
                let mut st = c.prepare_cached(
                    "SELECT gmail_id FROM messages WHERE gen = ?1 AND gmail_id >= ?2 AND gmail_id < ?3",
                )?;
                let mut indexed: Vec<u32> =
                    st.query_map(params![g, lo, hi], |r| r.get(0))?.filter_map(|r| r.ok().and_then(uid)).collect();
                let mut st = c.prepare_cached(
                    "SELECT gmail_id FROM pending WHERE gen = ?1 AND gmail_id >= ?2 AND gmail_id < ?3",
                )?;
                let mut pending: Vec<u32> =
                    st.query_map(params![g, lo, hi], |r| r.get(0))?.filter_map(|r| r.ok().and_then(uid)).collect();
                indexed.sort_unstable();
                pending.sort_unstable();
                Ok((indexed, pending))
            })
            .await?;
        Ok(r)
    }

    async fn incremental(
        &self,
        s: &mut ImapSession,
        f: &Folder,
        cp: Checkpoint,
        st: FolderStatus,
        refresh_flags: bool,
    ) -> Result<(), ScanErr> {
        let uv = st.uidvalidity;
        let condstore = cp.highestmodseq.is_some()
            && st.highestmodseq.is_some()
            && (s.has_cap("CONDSTORE") || s.has_cap("QRESYNC"));
        // 1. Flag changes and (QRESYNC) expunges since the checkpoint.
        if condstore && st.highestmodseq > cp.highestmodseq {
            let ch = s.changed_since(cp.highestmodseq.unwrap_or(0)).await?;
            // VANISHED stays a set of ranges (it may cover UIDs that never existed); only the UIDs Dove knows are
            // looked up in it. An incomplete set (`None`) is left to the count check below.
            if let Some(v) = ch.vanished.as_ref().filter(|v| !v.is_empty()) {
                let (indexed, pending) = self.known(f.folder_id, uv).await?;
                let mut gone: Vec<u32> = indexed.into_iter().chain(pending).filter(|u| v.contains(*u)).collect();
                gone.sort_unstable();
                gone.dedup();
                self.remove_uids(f.folder_id, uv, &gone).await?;
            }
            self.apply_flags(f, uv, ch.changed).await?;
        }
        // 2. New mail: UIDs only grow, so everything new is at or above the checkpoint's UIDNEXT.
        let new: Vec<u32> =
            if st.uidnext > cp.uidnext { s.uid_search_since_uid(cp.uidnext).await? } else { Vec::new() };
        // 3. Deletions. The UIDs Dove knows below UIDNEXT are a superset of the server's (the server cannot add UIDs
        //    there), so equal counts mean nothing was expunged; only a mismatch costs a `UID SEARCH ALL`.
        let (mut indexed, pending) = self.known(f.folder_id, uv).await?;
        let known_old =
            indexed.iter().chain(pending.iter()).filter(|u| **u < cp.uidnext).collect::<BTreeSet<_>>().len() as i64;
        let server_old = i64::from(st.exists) - new.len() as i64;
        if server_old != known_old {
            let all: BTreeSet<u32> = s.uid_search_all().await?.into_iter().collect();
            let gone: Vec<u32> = indexed
                .iter()
                .chain(pending.iter())
                .filter(|u| **u < cp.uidnext && !all.contains(u))
                .copied()
                .collect();
            self.remove_uids(f.folder_id, uv, &gone).await?;
            let gone: HashSet<u32> = gone.into_iter().collect();
            indexed.retain(|u| !gone.contains(u));
            // Self-heal: messages below UIDNEXT that Dove never recorded (an interrupted enumeration).
            let mut missing: Vec<u32> = all
                .iter()
                .filter(|u| **u < cp.uidnext && indexed.binary_search(u).is_err() && pending.binary_search(u).is_err())
                .copied()
                .collect();
            missing.sort_unstable_by(|a, b| b.cmp(a));
            self.add_pending(f.folder_id, uv, &missing, 0).await?;
        }
        // 4. Without CONDSTORE: bounded flag refresh (module docs).
        let mut flag_cursor = cp.flag_cursor;
        if !condstore && refresh_flags {
            let (window, next) = refresh_window(&indexed, cp.flag_cursor, RECENT_FLAGS, ROTATE_FLAGS);
            for chunk in window.chunks(FLAG_CHUNK) {
                let metas = s.fetch_meta(chunk).await?;
                self.apply_flags(f, uv, metas).await?;
            }
            flag_cursor = next;
        }
        // 5. New mail into pending (newest first), then advance the checkpoint: every write it covers has committed.
        let mut newest_first = new.clone();
        newest_first.sort_unstable_by(|a, b| b.cmp(a));
        self.add_pending(f.folder_id, uv, &newest_first, 0).await?;
        let uidnext = cp.uidnext.max(st.uidnext).max(new.iter().max().map_or(0, |u| u.saturating_add(1)));
        let next =
            Checkpoint { uidvalidity: uv, uidnext, highestmodseq: st.highestmodseq, enumerated: true, flag_cursor };
        if next != cp {
            self.write_checkpoint(f.folder_id, next).await?;
        }
        Ok(())
    }

    /// Writes changed labels of indexed messages (one transaction); unchanged ones are not rewritten.
    async fn apply_flags(&self, f: &Folder, uidvalidity: u32, metas: Vec<FetchedMeta>) -> Result<(), ScanErr> {
        if metas.is_empty() {
            return Ok(());
        }
        let (g, aid) = (self.gen_id, self.job.account_id.clone());
        let updates: Vec<(String, Vec<String>)> = metas
            .iter()
            .map(|m| (msg_id(f.folder_id, uidvalidity, m.uid), mail::imap_labels(&f.name_utf8, &m.flags, f.special)))
            .collect();
        let n = self
            .tx(move |tx| {
                let mut n = 0usize;
                for (id, labels) in &updates {
                    let stored: Option<String> = tx
                        .prepare_cached("SELECT labels FROM messages WHERE gen = ?1 AND gmail_id = ?2")?
                        .query_row(params![g, id], |r| r.get(0))
                        .optional()?;
                    let Some(stored) = stored else { continue };
                    let mut old: Vec<String> = serde_json::from_str(&stored).unwrap_or_default();
                    let mut new = labels.clone();
                    old.sort();
                    new.sort();
                    if old != new && ingest::update_labels(tx, g, id, labels)? {
                        n += 1;
                    }
                }
                if n > 0 {
                    tx.execute("UPDATE sync_state SET data_seq = data_seq + 1 WHERE account_id = ?1", [&aid])?;
                }
                Ok(n)
            })
            .await?;
        self.stats.lock().expect("lock").updated += n;
        Ok(())
    }

    /// Removes expunged messages (rows and pending records).
    async fn remove_uids(&self, folder_id: i64, uidvalidity: u32, uids: &[u32]) -> Result<(), ScanErr> {
        for chunk in uids.chunks(DROP_ROWS as usize) {
            let (g, aid) = (self.gen_id, self.job.account_id.clone());
            let ids: Vec<String> = chunk.iter().map(|u| msg_id(folder_id, uidvalidity, *u)).collect();
            let n = self
                .tx(move |tx| {
                    let mut n = 0usize;
                    for id in &ids {
                        if ingest::remove(tx, g, id)? {
                            n += 1;
                        }
                        tx.execute("DELETE FROM pending WHERE gen = ?1 AND gmail_id = ?2", params![g, id])?;
                    }
                    if n > 0 {
                        tx.execute("UPDATE sync_state SET data_seq = data_seq + 1 WHERE account_id = ?1", [&aid])?;
                    }
                    Ok(n)
                })
                .await?;
            self.stats.lock().expect("lock").removed += n;
        }
        Ok(())
    }

    /// Deletes a folder's rows and pending records in bounded transactions: all of them (`keep` = None, the
    /// checkpoint goes too) or those of every UIDVALIDITY but `keep`. Returns rows deleted.
    async fn drop_folder(&self, folder_id: i64, keep: Option<u32>) -> Result<usize, ScanErr> {
        let ranges: Vec<(String, String)> = match keep {
            None => vec![folder_range(folder_id, None)],
            Some(v) => {
                let (all_lo, all_hi) = folder_range(folder_id, None);
                let (keep_lo, keep_hi) = folder_range(folder_id, Some(v));
                vec![(all_lo, keep_lo), (keep_hi, all_hi)]
            }
        };
        let mut total = 0;
        for (lo, hi) in ranges {
            loop {
                let (g, aid, lo, hi) = (self.gen_id, self.job.account_id.clone(), lo.clone(), hi.clone());
                let (rows, pend) = self
                    .tx(move |tx| {
                        let ids: Vec<i64> = {
                            let mut st = tx.prepare_cached(
                                "SELECT id FROM messages WHERE gen = ?1 AND gmail_id >= ?2 AND gmail_id < ?3 LIMIT ?4",
                            )?;
                            st.query_map(params![g, lo, hi, DROP_ROWS], |r| r.get(0))?.collect::<Result<_, _>>()?
                        };
                        for id in &ids {
                            ingest::delete_row(tx, g, *id)?;
                        }
                        let pend = tx.execute(
                            "DELETE FROM pending WHERE gen = ?1 AND gmail_id IN (SELECT gmail_id FROM pending \
                             WHERE gen = ?1 AND gmail_id >= ?2 AND gmail_id < ?3 LIMIT ?4)",
                            params![g, lo, hi, DROP_ROWS],
                        )?;
                        if !ids.is_empty() {
                            tx.execute("UPDATE sync_state SET data_seq = data_seq + 1 WHERE account_id = ?1", [&aid])?;
                        }
                        Ok((ids.len(), pend))
                    })
                    .await?;
                total += rows;
                if rows == 0 && pend == 0 {
                    break;
                }
            }
        }
        if keep.is_none() {
            let (g, aid) = (self.gen_id, self.job.account_id.clone());
            self.tx(move |tx| {
                tx.execute(
                    "DELETE FROM imap_checkpoints WHERE account_id = ?1 AND gen = ?2 AND folder_id = ?3",
                    params![aid, g, folder_id],
                )?;
                Ok(())
            })
            .await?;
        }
        if total > 0 {
            self.job.app.index.cursors.invalidate_account(&self.job.account_id);
        }
        self.stats.lock().expect("lock").removed += total;
        Ok(total)
    }
}

/// The UIDs whose flags one scan re-reads without CONDSTORE: the newest `recent` of `uids` (sorted ascending) and
/// the next `rotate` older ones after `cursor` (wrapping around). Returns them ascending with the next cursor.
pub fn refresh_window(uids: &[u32], cursor: u32, recent: usize, rotate: usize) -> (Vec<u32>, u32) {
    let split = uids.len().saturating_sub(recent);
    let (older, newest) = uids.split_at(split);
    let mut out: Vec<u32> = newest.to_vec();
    let mut next = cursor;
    if !older.is_empty() && rotate > 0 {
        let start = match older.partition_point(|u| *u <= cursor) {
            s if s >= older.len() => 0,
            s => s,
        };
        let end = (start + rotate).min(older.len());
        // Next time continue after the last UID read; at the end, start over at the oldest.
        next = if end == older.len() { 0 } else { older[end - 1] };
        out.extend_from_slice(&older[start..end]);
    }
    out.sort_unstable();
    out.dedup();
    (out, next)
}

// ------------------------------------------------------------------ hydrate

/// Fetches and indexes one batch of due pending messages over one session, folder by folder. A message the
/// server will not deliver (protocol error) becomes a retry record; a lost connection or a login failure ends the
/// step after committing what was fetched.
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
    let aid = job.account_id.clone();
    let folders: HashMap<i64, Folder> = job
        .app
        .store
        .call(move |c| Ok(account::load_folders(c, &aid)?.into_iter().map(|f| (f.folder_id, f)).collect()))
        .await?;
    let mut done: Vec<(String, Fetched)> = Vec::new();
    let mut groups: Vec<(Folder, Vec<(String, ImapMsgId)>)> = Vec::new();
    for id in ids {
        match ImapMsgId::parse(&id).and_then(|m| folders.get(&m.folder_id).map(|f| (f, m))) {
            Some((f, m)) => match groups.iter_mut().find(|(g, _)| g.folder_id == f.folder_id) {
                Some((_, items)) => items.push((id, m)),
                None => groups.push((f.clone(), vec![(id, m)])),
            },
            None => done.push((id, Fetched::Gone)),
        }
    }
    let shared: Arc<Mutex<Fetch>> = Arc::default();
    let r = if groups.is_empty() {
        Ok(())
    } else {
        let (sh, app) = (shared.clone(), job.app.clone());
        let session = account::with_session_prio(&job.app, &job.account_id, Priority::Background, move |s| {
            Box::pin(fetch_groups(s, app, groups, sh))
        });
        // Messages fetched before the deadline are still committed below.
        tokio::time::timeout(step_deadline(&job.app), session).await.unwrap_or_else(|_| Err(step_timed_out()))
    };
    let mut fetch = std::mem::take(&mut *shared.lock().expect("lock"));
    done.append(&mut fetch.results);
    let fatal = match r {
        Ok(()) => None,
        // The server refused or garbled this message: retry it later instead of blocking the batch.
        Err(_) if matches!(fetch.error, Some(ImapError::Protocol(_))) && fetch.current.is_some() => {
            done.push((fetch.current.take().expect("checked"), Fetched::Failed("upstream_error".into())));
            None
        }
        Err(e) => Some(e),
    };
    commit_results(job, gen_id, done, report).await?;
    match fatal {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

/// Results of one batch, kept outside the session closure so a failing session still delivers what it fetched.
#[derive(Default)]
struct Fetch {
    results: Vec<(String, Fetched)>,
    current: Option<String>,
    error: Option<ImapError>,
}

async fn fetch_groups(
    s: &mut ImapSession,
    app: Arc<App>,
    groups: Vec<(Folder, Vec<(String, ImapMsgId)>)>,
    out: Arc<Mutex<Fetch>>,
) -> Result<(), ImapError> {
    let r = fetch_groups_inner(s, &app, groups, &out).await;
    if let Err(e) = &r {
        out.lock().expect("lock").error = Some(e.clone());
    }
    r
}

async fn fetch_groups_inner(
    s: &mut ImapSession,
    app: &App,
    groups: Vec<(Folder, Vec<(String, ImapMsgId)>)>,
    out: &Mutex<Fetch>,
) -> Result<(), ImapError> {
    let max_bytes = app.cfg.index.max_message_bytes;
    let max_chars = app.cfg.index.max_body_chars;
    let att = app.cfg.index.attachment_cfg();
    let push = |id: String, f: Fetched| out.lock().expect("lock").results.push((id, f));
    for (folder, items) in groups {
        let st = match s.select(&folder.name, true).await {
            Ok(st) => st,
            Err(ImapError::Missing) => {
                items.into_iter().for_each(|(id, _)| push(id, Fetched::Gone));
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut live = Vec::new();
        for (id, m) in items {
            if m.uidvalidity == st.uidvalidity { live.push((id, m.uid)) } else { push(id, Fetched::Gone) }
        }
        let uids: Vec<u32> = live.iter().map(|(_, u)| *u).collect();
        let metas: HashMap<u32, FetchedMeta> = s.fetch_meta(&uids).await?.into_iter().map(|m| (m.uid, m)).collect();
        for (id, uid) in live {
            let Some(m) = metas.get(&uid) else {
                push(id, Fetched::Gone);
                continue;
            };
            out.lock().expect("lock").current = Some(id.clone());
            // Same admission limit as Gmail bodies: at most `body_jobs` raw messages in memory at once.
            let _permit = app.index.body_jobs.clone().acquire_owned().await.map_err(|_| ImapError::NotDispatched)?;
            let raw = match s.fetch_raw(uid, max_bytes).await {
                Ok(r) => r,
                Err(ImapError::Missing) => {
                    push(id, Fetched::Gone);
                    continue;
                }
                Err(e) => return Err(e),
            };
            let meta = MessageMeta {
                id: id.clone(),
                thread_id: String::new(),
                labels: mail::imap_labels(&folder.name_utf8, &m.flags, folder.special),
                internal_date_ms: m.internal_date_s.saturating_mul(1000),
                size_estimate: m.size as i64,
                snippet: None,
            };
            let doc = tokio::task::spawn_blocking({
                let att = att.clone();
                move || Doc::from_imap(meta, raw.as_deref(), max_bytes, max_chars, &att)
            })
                .await
                .map_err(|_| ImapError::Protocol("message could not be processed"))?;
            out.lock().expect("lock").current = None;
            push(id, Fetched::Doc(Box::new(doc)));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ threads (get_thread)

/// Members of a thread in the index serving `account_id`, oldest first (at most [`MAX_THREAD`]), and whether the
/// index was complete. `None` when the mailbox has no indexed data.
pub async fn thread_members(
    app: &App,
    account_id: &str,
    thread_id: &str,
    deadline: Instant,
) -> Result<Option<(Vec<String>, bool)>, ToolError> {
    let (aid, tid) = (account_id.to_string(), thread_id.to_string());
    app.index
        .read(deadline, move |c| {
            let Some(s) = load_state(c, &aid)? else { return Ok(None) };
            let Some(g) = s.serving_gen() else { return Ok(None) };
            let pending: bool =
                c.query_row("SELECT EXISTS(SELECT 1 FROM pending WHERE gen = ?1)", [g], |r| r.get(0))?;
            let mut st = c.prepare_cached(
                "SELECT gmail_id FROM messages WHERE thread_id = ?1 AND gen = ?2 \
                 ORDER BY received_at, gmail_id LIMIT ?3",
            )?;
            let ids: Vec<String> =
                st.query_map(params![tid, g, MAX_THREAD], |r| r.get(0))?.collect::<Result<_, _>>()?;
            let complete = s.stage == "ready" && !pending && (ids.len() as i64) < MAX_THREAD;
            Ok(Some((ids, complete)))
        })
        .await
}

/// The thread id the index holds for a message, if it is indexed.
pub async fn indexed_thread_of(
    app: &App,
    account_id: &str,
    message_id: &str,
    deadline: Instant,
) -> Result<Option<String>, ToolError> {
    let (aid, mid) = (account_id.to_string(), message_id.to_string());
    app.index
        .read(deadline, move |c| {
            let Some(g) = load_state(c, &aid)?.and_then(|s| s.serving_gen()) else { return Ok(None) };
            Ok(c.query_row("SELECT thread_id FROM messages WHERE gen = ?1 AND gmail_id = ?2", params![g, mid], |r| {
                r.get(0)
            })
            .optional()?)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_ranges_do_not_overlap_other_folders() {
        let (lo, hi) = folder_range(3, None);
        let inside = |id: &str| id >= lo.as_str() && id < hi.as_str();
        assert!(inside("f3-1-1") && inside("f3-99-123"));
        assert!(!inside("f31-1-1") && !inside("f30-1-1") && !inside("f2-1-1") && !inside("f4-1-1"));
        let (lo, hi) = folder_range(3, Some(12));
        let inside = |id: &str| id >= lo.as_str() && id < hi.as_str();
        assert!(inside("f3-12-1") && inside("f3-12-99999"));
        assert!(!inside("f3-123-1") && !inside("f3-1-1") && !inside("f3-13-1"));
    }

    /// Every scan reads at most `recent + rotate` UIDs, always the newest ones, and the rotation covers every older
    /// UID within ceil(older / rotate) scans before it starts over.
    #[test]
    fn refresh_window_is_bounded_and_covers_the_folder() {
        let uids: Vec<u32> = (1..=10_000).collect();
        let (recent, rotate) = (100, 1000);
        let mut cursor = 0;
        let mut seen = HashSet::new();
        let scans = (uids.len() - recent).div_ceil(rotate);
        for _ in 0..scans {
            let (w, next) = refresh_window(&uids, cursor, recent, rotate);
            assert!(w.len() <= recent + rotate, "{}", w.len());
            assert!(uids[uids.len() - recent..].iter().all(|u| w.binary_search(u).is_ok()), "newest always read");
            seen.extend(w);
            cursor = next;
        }
        assert_eq!(seen.len(), uids.len(), "whole folder refreshed within {scans} scans");
        assert_eq!(cursor, 0, "rotation starts over");
        // Small folders: everything, every time.
        let (w, next) = refresh_window(&uids[..50], 0, recent, rotate);
        assert_eq!((w.len(), next), (50, 0));
        let (w, _) = refresh_window(&uids[..500], 0, recent, rotate);
        assert_eq!(w.len(), 500);
    }

    /// The folder-range, checkpoint and thread queries use the intended indexes (fixed planner statistics, V2/V4).
    #[test]
    fn query_plans() {
        let mut c = Connection::open_in_memory().unwrap();
        super::super::schema::migrate(&mut c).unwrap();
        let plan = |sql: &str| -> String {
            let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let rows: Vec<String> = st.query_map([], |r| r.get::<_, String>(3)).unwrap().map(|r| r.unwrap()).collect();
            rows.join("\n")
        };
        let p = plan("SELECT id FROM messages WHERE gen = 1 AND gmail_id >= 'f3-' AND gmail_id < 'f3.' LIMIT 10");
        assert!(p.contains("sqlite_autoindex_messages_1 (gen=? AND gmail_id>? AND gmail_id<?)"), "{p}");
        let p = plan("SELECT gmail_id FROM pending WHERE gen = 1 AND gmail_id >= 'f3-' AND gmail_id < 'f3.'");
        assert!(p.contains("PRIMARY KEY (gen=? AND gmail_id>? AND gmail_id<?)"), "{p}");
        let p = plan("SELECT * FROM imap_checkpoints WHERE account_id = 'a' AND gen = 1");
        assert!(p.contains("PRIMARY KEY (account_id=? AND gen=?)"), "{p}");
        let p = plan("SELECT gmail_id FROM messages WHERE thread_id = 't' AND gen = 1 ORDER BY received_at, gmail_id");
        assert!(p.contains("messages_thread (thread_id=? AND gen=?)"), "{p}");
    }
}
