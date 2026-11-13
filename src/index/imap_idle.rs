//! IMAP IDLE push (RFC 2177) and search freshness for IMAP mailboxes (owner request 2026-11-12: new INBOX mail
//! searchable within seconds instead of after the 60 s poll).
//!
//! **Push.** A supervisor keeps one dedicated, long-lived connection per active, index-enabled IMAP mailbox (never
//! taken from the request pool, never holding a pool or global upstream permit). It `EXAMINE`s INBOX and idles;
//! `EXISTS`, `EXPUNGE`, `FETCH` and `VANISHED` wake the account's index sync ([`super::wake`]) after a short debounce.
//! IDLE is re-issued at least every `index.idle_renew_secs` (at most 25 min). Network errors reconnect with
//! exponential backoff and jitter; an authentication failure marks the mailbox `reauth_required` once (the same rule
//! as every other IMAP login) and the connection stays down until the operator reconnects it (new credential
//! generation). Servers without IDLE are polled only. The supervisor reconciles every second (and when poked), so
//! disable, removal, index disable, reauth and reconnect stop or restart the connection within about a second.
//!
//! **Freshness.** [`ensure_fresh`] runs before an index search reads IMAP mailboxes: for a mailbox without a healthy
//! IDLE connection whose last full sync is older than [`FRESH_AFTER_SECS`], one INBOX-only incremental pass
//! ([`super::imap_sync::quick_inbox`]) runs within [`FRESH_BUDGET`] (and at most half of the remaining tool call
//! time). On timeout the search answers from the index as before; `as_of` stays the last full sync.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::params;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::app::App;
use crate::error::ErrorCode;
use crate::imap::account;
use crate::imap::{IdleEvent, ImapError, ImapSession};
use crate::util;

/// Quiet time after a change notification before the sync is woken (a burst of notifications wakes it once).
pub const DEBOUNCE: Duration = Duration::from_millis(300);
/// Longest a wake is delayed by a continuous stream of notifications.
pub const MAX_DEBOUNCE: Duration = Duration::from_secs(1);
/// Upper bound for `index.idle_renew_secs` (RFC 2177 asks for at least every 29 minutes; Dove uses 25).
pub const MAX_RENEW_SECS: u64 = 25 * 60;
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// A connection that stayed up this long resets the backoff.
const STABLE: Duration = Duration::from_secs(60);
/// Index searches check an IMAP INBOX when the last full sync is older than this and IDLE is not healthy.
pub const FRESH_AFTER_SECS: i64 = 5;
/// Time budget of one freshness check (all mailboxes of the search together).
pub const FRESH_BUDGET: Duration = Duration::from_secs(2);

/// Shared IDLE state: which mailboxes are idling right now, and when each was last checked for freshness.
#[derive(Default)]
pub struct Registry {
    healthy: Mutex<HashSet<String>>,
    checked: Mutex<HashMap<String, std::time::Instant>>,
    poke: Notify,
}

impl Registry {
    /// True while the account's IDLE connection is idling on INBOX (the server accepted `IDLE`).
    pub fn is_healthy(&self, account_id: &str) -> bool {
        self.healthy.lock().expect("lock").contains(account_id)
    }

    fn set_healthy(&self, account_id: &str, on: bool) {
        let mut h = self.healthy.lock().expect("lock");
        if on {
            h.insert(account_id.to_string());
        } else {
            h.remove(account_id);
        }
    }

    /// Reconcile the IDLE connections now instead of within the next second (account state changed).
    pub fn poke(&self) {
        self.poke.notify_one();
    }

    /// Claims the account's next freshness check; false if one started within the last [`FRESH_AFTER_SECS`].
    fn claim_check(&self, account_id: &str) -> bool {
        let mut c = self.checked.lock().expect("lock");
        let now = std::time::Instant::now();
        match c.get(account_id) {
            Some(t) if now.duration_since(*t) < Duration::from_secs(FRESH_AFTER_SECS as u64) => false,
            _ => {
                c.insert(account_id.to_string(), now);
                true
            }
        }
    }
}

// ------------------------------------------------------------------ supervisor

/// Starts the IDLE supervisor (called from `dove serve`). Aborting the returned task stops every IDLE connection.
pub fn start(app: Arc<App>) -> JoinHandle<()> {
    tokio::spawn(supervise(app))
}

struct Running {
    generation: i64,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

async fn supervise(app: Arc<App>) {
    let parent = CancellationToken::new();
    // Dropping the supervisor (abort, shutdown) cancels every connection task.
    let _guard = parent.clone().drop_guard();
    let mut running: HashMap<String, Running> = HashMap::new();
    // Tasks that stopped on their own (auth failure, no IDLE, account gone) for this credential generation.
    let mut stopped: HashMap<String, i64> = HashMap::new();
    loop {
        let want = if app.cfg.index.imap_idle { desired(&app).await } else { Ok(HashMap::new()) };
        match want {
            Ok(want) => reconcile(&app, &parent, &want, &mut running, &mut stopped),
            Err(e) => tracing::warn!(error = %e, "IMAP IDLE supervisor could not read the accounts"),
        }
        tokio::select! {
            _ = app.index.idle.poke.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

/// Active, index-enabled IMAP mailboxes with their credential generation.
async fn desired(app: &App) -> anyhow::Result<HashMap<String, i64>> {
    app.store
        .call(|c| {
            let mut st = c.prepare(
                "SELECT id, grant_generation FROM accounts \
                 WHERE provider = 'imap' AND status = 'active' AND index_enabled = 1",
            )?;
            Ok(st.query_map(params![], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
        })
        .await
}

fn reconcile(
    app: &Arc<App>,
    parent: &CancellationToken,
    want: &HashMap<String, i64>,
    running: &mut HashMap<String, Running>,
    stopped: &mut HashMap<String, i64>,
) {
    running.retain(|aid, r| {
        if r.handle.is_finished() {
            // Cancelled tasks are removed below; a finished one stopped itself and is not restarted for this
            // credential generation.
            stopped.insert(aid.clone(), r.generation);
            return false;
        }
        if want.get(aid) != Some(&r.generation) {
            r.cancel.cancel();
            return false;
        }
        true
    });
    stopped.retain(|aid, g| want.get(aid) == Some(g));
    for (aid, g) in want {
        if running.contains_key(aid) || stopped.get(aid) == Some(g) {
            continue;
        }
        let cancel = parent.child_token();
        let handle = tokio::spawn(run_account(app.clone(), aid.clone(), *g, cancel.clone()));
        running.insert(aid.clone(), Running { generation: *g, cancel, handle });
    }
}

/// Exponential backoff with jitter: between half and all of `min(BACKOFF_MAX, BACKOFF_MIN * 2^failures)`.
fn backoff(failures: u32) -> Duration {
    let full = BACKOFF_MIN.saturating_mul(1u32 << failures.min(16)).min(BACKOFF_MAX);
    let r = u64::from(u16::from_le_bytes(util::random_bytes::<2>()));
    let half = full.as_millis() as u64 / 2;
    Duration::from_millis(half + r % (half + 1))
}

enum End {
    Cancelled,
    /// Not retried for this credential generation.
    Stop,
    Retry,
}

async fn run_account(app: Arc<App>, aid: String, generation: i64, cancel: CancellationToken) {
    let mut failures = 0u32;
    loop {
        let started = Instant::now();
        let end = connection(&app, &aid, generation, &cancel).await;
        app.index.idle.set_healthy(&aid, false);
        match end {
            End::Cancelled | End::Stop => return,
            End::Retry => {
                if started.elapsed() >= STABLE {
                    failures = 0;
                }
                let delay = backoff(failures);
                failures = failures.saturating_add(1);
                tracing::info!(retry_ms = delay.as_millis() as u64, "IMAP IDLE connection lost; reconnecting");
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

/// One connection: login, `EXAMINE INBOX` (All Mail in Gmail mode), IDLE cycles until cancelled or an error.
async fn connection(app: &Arc<App>, aid: &str, generation: i64, cancel: &CancellationToken) -> End {
    let (settings, creds) = match account::load(app, aid).await {
        Ok(v) => v,
        Err(e) if e.code == ErrorCode::Internal => return End::Retry,
        // Removed, disabled or no longer IMAP: the supervisor decides.
        Err(_) => return End::Stop,
    };
    if settings.generation != generation {
        return End::Stop;
    }
    let timeout = app.imap.cmd_timeout();
    let connect = ImapSession::connect(app.imap.connector(), &settings.imap, &creds, timeout);
    let mut s = tokio::select! {
        _ = cancel.cancelled() => return End::Cancelled,
        r = connect => match r {
            Ok(s) => s,
            Err(ImapError::Auth) => {
                tracing::warn!("IMAP IDLE login rejected; the mailbox needs a reconnect");
                account::mark_auth_failure(app, aid, settings.generation, &settings.alias).await;
                return End::Stop;
            }
            Err(ImapError::Capability(_)) => return End::Stop,
            Err(_) => return End::Retry,
        }
    };
    drop(creds);
    if !s.has_cap("IDLE") {
        tracing::info!("the mail server does not offer IDLE; the mailbox is polled");
        let _ = tokio::time::timeout(timeout, s.logout()).await;
        return End::Stop;
    }
    // Gmail mode idles on All Mail, where new inbox mail lands too (PLAN A57).
    let folder = match (settings.gmail, settings.all_folder.clone()) {
        (true, Some(all)) => all,
        _ => "INBOX".to_string(),
    };
    let end = idle_loop(app, aid, &mut s, &folder, cancel).await;
    if matches!(end, End::Cancelled | End::Stop) {
        // Polite close; the connection is dropped either way.
        let _ = tokio::time::timeout(timeout, async move {
            if s.idle_done().await.is_ok() {
                s.logout().await;
            }
        })
        .await;
    }
    end
}

async fn idle_loop(app: &Arc<App>, aid: &str, s: &mut ImapSession, folder: &str, cancel: &CancellationToken) -> End {
    let renew = Duration::from_secs(app.cfg.index.idle_renew_secs.clamp(1, MAX_RENEW_SECS));
    match tokio::select! { _ = cancel.cancelled() => return End::Cancelled, r = s.select(folder, true) => r } {
        Ok(_) => {}
        Err(_) => return End::Retry,
    }
    let mut first = true;
    loop {
        let started = Instant::now();
        let changed = match tokio::select! { _ = cancel.cancelled() => return End::Cancelled, r = s.idle_start() => r }
        {
            Ok(c) => c,
            Err(ImapError::Capability(_)) => {
                tracing::info!("the mail server refused IDLE; the mailbox is polled");
                return End::Stop;
            }
            Err(_) => return End::Retry,
        };
        app.index.idle.set_healthy(aid, true);
        // After (re)connecting, catch up on whatever arrived while no connection was idling.
        if first || changed {
            super::wake(app, aid);
        }
        first = false;
        let renew_at = started + renew;
        let mut due: Option<(Instant, Instant)> = None;
        let mut server_ended = false;
        loop {
            let wake_at = due.map(|(first, last)| (last + DEBOUNCE).min(first + MAX_DEBOUNCE));
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return End::Cancelled,
                _ = tokio::time::sleep_until(wake_at.unwrap_or(renew_at)), if wake_at.is_some() => {
                    super::wake(app, aid);
                    due = None;
                }
                _ = tokio::time::sleep_until(renew_at) => break,
                ev = s.idle_next() => match ev {
                    Ok(IdleEvent::Changed) => {
                        let now = Instant::now();
                        due = Some((due.map_or(now, |d| d.0), now));
                    }
                    Ok(IdleEvent::Other) => {}
                    Ok(IdleEvent::Ended) => {
                        server_ended = true;
                        break;
                    }
                    Err(_) => return End::Retry,
                },
            }
        }
        let changed = match tokio::select! { _ = cancel.cancelled() => return End::Cancelled, r = s.idle_done() => r } {
            Ok(c) => c,
            Err(_) => return End::Retry,
        };
        if changed || due.is_some() {
            super::wake(app, aid);
        }
        // A server that ends every IDLE at once is retried with backoff, not in a tight loop.
        if server_ended && started.elapsed() < Duration::from_secs(1) {
            return End::Retry;
        }
    }
}

// ------------------------------------------------------------------ search freshness

/// Before an index search: IMAP mailboxes (`account_ids`, index-enabled) without a healthy IDLE connection whose last
/// full sync is older than [`FRESH_AFTER_SECS`] get one quick INBOX pass, all within one budget (at most
/// [`FRESH_BUDGET`] and half of the time left before `deadline`). Never fails the search: errors and timeouts leave
/// the index as it is.
pub async fn ensure_fresh(app: &Arc<App>, account_ids: Vec<String>, deadline: std::time::Instant) {
    let candidates: Vec<String> = account_ids.into_iter().filter(|a| !app.index.idle.is_healthy(a)).collect();
    if candidates.is_empty() {
        return;
    }
    let start = std::time::Instant::now();
    let budget = FRESH_BUDGET.min(deadline.saturating_duration_since(start) / 2);
    if budget < Duration::from_millis(100) {
        return;
    }
    let until = start + budget;
    let ids = candidates.clone();
    let last = app
        .index
        .read(until, move |c| {
            let mut out = Vec::new();
            for aid in ids {
                let s = super::sync::load_state(c, &aid)?;
                out.push((aid, s.and_then(|s| s.last_success_at)));
            }
            Ok(out)
        })
        .await;
    let Ok(last) = last else { return };
    let now = util::now_unix();
    let due: Vec<String> = last
        .into_iter()
        .filter(|(aid, t)| t.is_some_and(|t| now - t > FRESH_AFTER_SECS) && app.index.idle.claim_check(aid))
        .map(|(aid, _)| aid)
        .collect();
    if due.is_empty() {
        return;
    }
    let work = futures::future::join_all(due.iter().map(|aid| async move {
        if let Err(e) = super::imap_sync::quick_inbox(app, aid).await {
            tracing::info!(error = %e, "search freshness check failed; answering from the index");
        }
    }));
    if tokio::time::timeout_at(Instant::from_std(until), work).await.is_err() {
        tracing::info!(budget_ms = budget.as_millis() as u64, "search freshness check hit its budget");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_with_jitter_and_is_capped() {
        for f in 0..30 {
            let full = BACKOFF_MIN.saturating_mul(1u32 << f.min(16)).min(BACKOFF_MAX);
            for _ in 0..50 {
                let d = backoff(f);
                assert!(d >= full / 2 && d <= full, "{f}: {d:?} vs {full:?}");
            }
        }
        assert!(backoff(30) <= BACKOFF_MAX);
    }

    #[test]
    fn freshness_checks_are_throttled_per_account() {
        let r = Registry::default();
        assert!(r.claim_check("a"));
        assert!(!r.claim_check("a"));
        assert!(r.claim_check("b"));
    }
}
