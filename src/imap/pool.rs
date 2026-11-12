//! A few logged-in IMAP sessions per account (default 2, idle timeout 60 s), inside the global upstream limit.
//! Background work (index sync) also takes a slot of the background sub-limit the Gmail gateway uses, so it can never
//! hold every global slot and starve interactive calls (spec 7.7).
//!
//! A session goes back to the pool only after a call succeeded. Any error drops it, so a half-read stream (lost
//! connection mid-FETCH, timeout mid-literal) is never reused.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::session::ImapSession;
use super::{Credentials, ImapConnector, ImapError, ServerEndpoint};
use crate::gmail::gateway::Priority;

pub const DEFAULT_PER_ACCOUNT: usize = 2;
pub const DEFAULT_IDLE: Duration = Duration::from_secs(60);

struct Idle {
    session: ImapSession,
    since: Instant,
    key: String,
}

#[derive(Default)]
struct Slot {
    idle: Vec<Idle>,
}

pub type SessionFuture<'s, T> = Pin<Box<dyn Future<Output = Result<T, ImapError>> + Send + 's>>;

pub struct ImapPool {
    connector: ImapConnector,
    cmd_timeout: Duration,
    per_account: usize,
    idle_timeout: Duration,
    global: Option<Arc<Semaphore>>,
    background: Option<Arc<Semaphore>>,
    sems: Mutex<HashMap<String, Arc<Semaphore>>>,
    slots: Mutex<HashMap<String, Slot>>,
    /// New connections opened (tests check that broken sessions are replaced).
    pub connects: AtomicU64,
}

impl ImapPool {
    pub fn new(connector: ImapConnector, cmd_timeout: Duration) -> Self {
        Self {
            connector,
            cmd_timeout,
            per_account: DEFAULT_PER_ACCOUNT,
            idle_timeout: DEFAULT_IDLE,
            global: None,
            background: None,
            sems: Mutex::default(),
            slots: Mutex::default(),
            connects: AtomicU64::new(0),
        }
    }

    /// Shares the global upstream in-flight limit and its background sub-limit with the Gmail gateway.
    pub fn with_global_limit(mut self, global: Arc<Semaphore>, background: Arc<Semaphore>) -> Self {
        self.global = Some(global);
        self.background = Some(background);
        self
    }

    pub fn with_limits(mut self, per_account: usize, idle_timeout: Duration) -> Self {
        self.per_account = per_account.max(1);
        self.idle_timeout = idle_timeout;
        self
    }

    pub fn connector(&self) -> &ImapConnector {
        &self.connector
    }

    pub fn cmd_timeout(&self) -> Duration {
        self.cmd_timeout
    }

    /// Drops every idle session of the account (reconnect, disable, removal).
    pub fn evict(&self, account_id: &str) {
        self.slots.lock().expect("lock").remove(account_id);
    }

    fn key(ep: &ServerEndpoint, creds: &Credentials) -> String {
        format!("{}:{}:{:?}:{}", ep.host, ep.port, ep.tls, creds.username)
    }

    async fn permits(&self, account_id: &str, prio: Priority) -> Result<Vec<OwnedSemaphorePermit>, ImapError> {
        let sem = self
            .sems
            .lock()
            .expect("lock")
            .entry(account_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.per_account)))
            .clone();
        // Same order as the gateway: background sub-limit, then the mailbox, then the global limit.
        let wait = async {
            let mut held = Vec::with_capacity(3);
            if let (Priority::Background, Some(b)) = (prio, &self.background) {
                held.push(b.clone().acquire_owned().await.ok()?);
            }
            held.push(sem.acquire_owned().await.ok()?);
            if let Some(g) = &self.global {
                held.push(g.clone().acquire_owned().await.ok()?);
            }
            Some(held)
        };
        match tokio::time::timeout(self.cmd_timeout, wait).await {
            Ok(Some(p)) => Ok(p),
            _ => Err(ImapError::NotDispatched),
        }
    }

    /// Runs `f` on a logged-in session for the account, reusing an idle one when its endpoint and user match.
    pub async fn with_session<T, F>(
        &self,
        account_id: &str,
        endpoint: &ServerEndpoint,
        creds: &Credentials,
        f: F,
    ) -> Result<T, ImapError>
    where
        F: for<'s> FnOnce(&'s mut ImapSession) -> SessionFuture<'s, T>,
    {
        self.with_session_prio(account_id, endpoint, creds, Priority::Interactive, f).await
    }

    /// [`Self::with_session`] at a given priority: background work also holds a background slot.
    pub async fn with_session_prio<T, F>(
        &self,
        account_id: &str,
        endpoint: &ServerEndpoint,
        creds: &Credentials,
        prio: Priority,
        f: F,
    ) -> Result<T, ImapError>
    where
        F: for<'s> FnOnce(&'s mut ImapSession) -> SessionFuture<'s, T>,
    {
        let _permits = self.permits(account_id, prio).await?;
        let key = Self::key(endpoint, creds);
        let reused = {
            let mut slots = self.slots.lock().expect("lock");
            let slot = slots.entry(account_id.to_string()).or_default();
            let now = Instant::now();
            slot.idle.retain(|i| now.duration_since(i.since) < self.idle_timeout && i.key == key);
            slot.idle.pop()
        };
        let mut session = match reused {
            Some(i) => i.session,
            None => {
                self.connects.fetch_add(1, Ordering::Relaxed);
                ImapSession::connect(&self.connector, endpoint, creds, self.cmd_timeout).await?
            }
        };
        let out = f(&mut session).await;
        if out.is_ok() {
            let mut slots = self.slots.lock().expect("lock");
            let slot = slots.entry(account_id.to_string()).or_default();
            if slot.idle.len() < self.per_account {
                slot.idle.push(Idle { session, since: Instant::now(), key });
            }
        }
        out
    }
}
