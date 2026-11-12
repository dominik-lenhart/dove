//! Bounded in-memory search cursors (spec 5.3, 8.1a).
//!
//! A cursor is an opaque random id; its state never leaves the process. Limits: 15 minute TTL, at most 1,000 live
//! cursors and 8 MiB of payload together, and at most 100 live cursors per client (a client over its share evicts its
//! own oldest cursor, never another client's). Expired, evicted, foreign or invalidated cursors all yield
//! `cursor_invalid`. Purge, rebuild and generation cutover invalidate every cursor that covers the account.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{ErrorCode, ToolError};
use crate::util;

pub const TTL: Duration = Duration::from_secs(15 * 60);
pub const MAX_CURSORS: usize = 1000;
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PER_CLIENT: usize = 100;

#[derive(Debug, Clone)]
pub struct Cursor {
    pub client_id: String,
    pub auth_epoch: i64,
    /// Account ids the cursor covers (for invalidation).
    pub accounts: Vec<String>,
    pub payload: Payload,
}

#[derive(Debug, Clone)]
pub enum Payload {
    Index(IndexPage),
    Live(LivePage),
}

/// Index route continuation: the normalized request, the generations it was bound to and the last row's key.
#[derive(Debug, Clone)]
pub struct IndexPage {
    pub req: super::query::SearchReq,
    /// (account_id, generation, fence, data_seq at the first page)
    pub bound: Vec<(String, i64, i64, i64)>,
    pub after: Vec<super::query::KeyValue>,
}

/// Live Gmail route continuation: buffered upstream ids and page tokens per mailbox.
#[derive(Debug, Clone)]
pub struct LivePage {
    pub gmail_query: String,
    pub select: Vec<String>,
    pub limit: usize,
    pub include_spam_trash: bool,
    pub accounts: Vec<LiveAccount>,
    /// Round-robin position for fair interleaving.
    pub next: usize,
}

#[derive(Debug, Clone)]
pub struct LiveAccount {
    pub account_id: String,
    /// (message id, thread id) received but not yet returned, in upstream order.
    pub buffer: VecDeque<(String, String)>,
    pub page_token: Option<String>,
    pub started: bool,
    pub failed: bool,
}

impl LiveAccount {
    pub fn exhausted(&self) -> bool {
        self.failed || (self.started && self.buffer.is_empty() && self.page_token.is_none())
    }
}

impl Cursor {
    fn approx_bytes(&self) -> usize {
        let base = 128 + self.client_id.len() + self.accounts.iter().map(|a| a.len() + 16).sum::<usize>();
        base + match &self.payload {
            Payload::Index(p) => {
                p.req.approx_bytes()
                    + p.bound.iter().map(|b| b.0.len() + 32).sum::<usize>()
                    + p.after.iter().map(|k| k.approx_bytes()).sum::<usize>()
            }
            Payload::Live(p) => {
                p.gmail_query.len()
                    + p.select.iter().map(|s| s.len() + 8).sum::<usize>()
                    + p.accounts
                        .iter()
                        .map(|a| {
                            a.account_id.len()
                                + a.page_token.as_ref().map_or(0, |t| t.len())
                                + a.buffer.iter().map(|(m, t)| m.len() + t.len() + 16).sum::<usize>()
                                + 48
                        })
                        .sum::<usize>()
            }
        }
    }
}

struct Entry {
    cursor: Cursor,
    bytes: usize,
    expires: Instant,
}

struct Limits {
    ttl: Duration,
    max_count: usize,
    max_bytes: usize,
    per_client: usize,
}

struct Inner {
    map: HashMap<String, Entry>,
    order: VecDeque<String>,
    bytes: usize,
    /// Live cursors per client id.
    per_client: HashMap<String, usize>,
    limits: Limits,
}

pub struct CursorStore {
    inner: Mutex<Inner>,
}

impl Default for CursorStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
                per_client: HashMap::new(),
                limits: Limits { ttl: TTL, max_count: MAX_CURSORS, max_bytes: MAX_BYTES, per_client: MAX_PER_CLIENT },
            }),
        }
    }
}

pub fn invalid() -> ToolError {
    ToolError::new(ErrorCode::CursorInvalid, "the cursor is invalid or expired; run the query again")
}

impl Inner {
    fn remove(&mut self, id: &str) {
        if let Some(e) = self.map.remove(id) {
            self.bytes -= e.bytes;
            if let Some(n) = self.per_client.get_mut(&e.cursor.client_id) {
                *n -= 1;
                if *n == 0 {
                    self.per_client.remove(&e.cursor.client_id);
                }
            }
        }
    }

    fn evict(&mut self, now: Instant, client_id: &str, incoming: usize) {
        self.order.retain(|id| self.map.get(id).is_some_and(|e| e.expires > now));
        let expired: Vec<String> = self.map.iter().filter(|(_, e)| e.expires <= now).map(|(k, _)| k.clone()).collect();
        for id in expired {
            self.remove(&id);
        }
        // A client at its share makes room among its own cursors first (oldest first).
        while self.per_client.get(client_id).copied().unwrap_or(0) + 1 > self.limits.per_client {
            let Some(pos) =
                self.order.iter().position(|id| self.map.get(id).is_some_and(|e| e.cursor.client_id == client_id))
            else {
                break;
            };
            if let Some(old) = self.order.remove(pos) {
                self.remove(&old);
            }
        }
        while (self.map.len() + 1 > self.limits.max_count || self.bytes + incoming > self.limits.max_bytes)
            && let Some(old) = self.order.pop_front()
        {
            self.remove(&old);
        }
    }
}

impl CursorStore {
    /// Stores a cursor and returns its opaque id. Oldest cursors are evicted to stay within the caps.
    pub fn insert(&self, cursor: Cursor) -> Result<String, ToolError> {
        let bytes = cursor.approx_bytes();
        let mut g = self.inner.lock().expect("lock");
        if bytes > g.limits.max_bytes {
            return Err(ToolError::new(ErrorCode::BudgetExceeded, "the result cursor is too large; narrow the query"));
        }
        let now = Instant::now();
        g.evict(now, &cursor.client_id, bytes);
        let id = format!("c_{}", util::b64url(&util::random_bytes::<18>()));
        let expires = now + g.limits.ttl;
        g.bytes += bytes;
        *g.per_client.entry(cursor.client_id.clone()).or_default() += 1;
        g.map.insert(id.clone(), Entry { cursor, bytes, expires });
        g.order.push_back(id.clone());
        Ok(id)
    }

    /// Returns the cursor if it exists, is unexpired and belongs to this client at this auth epoch.
    pub fn get(&self, id: &str, client_id: &str, auth_epoch: i64) -> Result<Cursor, ToolError> {
        let mut g = self.inner.lock().expect("lock");
        let now = Instant::now();
        let Some(e) = g.map.get(id) else {
            return Err(invalid());
        };
        if e.expires <= now {
            g.remove(id);
            return Err(invalid());
        }
        if e.cursor.client_id != client_id || e.cursor.auth_epoch != auth_epoch {
            return Err(invalid());
        }
        Ok(e.cursor.clone())
    }

    /// Rows a resumed page may return: the limit stored with the cursor, or None if the cursor is not usable by this
    /// client (resuming it then fails with `cursor_invalid` and returns no rows). Does not refresh or consume it.
    pub fn page_limit(&self, id: &str, client_id: &str, auth_epoch: i64) -> Option<usize> {
        let g = self.inner.lock().expect("lock");
        let e = g.map.get(id)?;
        if e.expires <= Instant::now() || e.cursor.client_id != client_id || e.cursor.auth_epoch != auth_epoch {
            return None;
        }
        Some(match &e.cursor.payload {
            Payload::Index(p) => p.req.limit,
            Payload::Live(p) => p.limit,
        })
    }

    pub fn invalidate_account(&self, account_id: &str) {
        let mut g = self.inner.lock().expect("lock");
        let ids: Vec<String> = g
            .map
            .iter()
            .filter(|(_, e)| e.cursor.accounts.iter().any(|a| a == account_id))
            .map(|(k, _)| k.clone())
            .collect();
        for id in ids {
            g.remove(&id);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("lock").map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes(&self) -> usize {
        self.inner.lock().expect("lock").bytes
    }

    /// Overrides TTL and caps (tests exercise expiry and eviction without waiting 15 minutes).
    pub fn set_limits(&self, ttl: Duration, max_count: usize, max_bytes: usize) {
        self.inner.lock().expect("lock").limits = Limits { ttl, max_count, max_bytes, per_client: MAX_PER_CLIENT };
    }

    /// Overrides the per-client share (tests).
    pub fn set_per_client_limit(&self, n: usize) {
        self.inner.lock().expect("lock").limits.per_client = n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(client: &str, account: &str, ids: usize) -> Cursor {
        Cursor {
            client_id: client.into(),
            auth_epoch: 1,
            accounts: vec![account.into()],
            payload: Payload::Live(LivePage {
                gmail_query: "x".into(),
                select: vec![],
                limit: 10,
                include_spam_trash: false,
                accounts: vec![LiveAccount {
                    account_id: account.into(),
                    buffer: (0..ids).map(|i| (format!("m{i}"), "t".into())).collect(),
                    page_token: None,
                    started: true,
                    failed: false,
                }],
                next: 0,
            }),
        }
    }

    #[test]
    fn binding_expiry_and_caps() {
        let s = CursorStore::default();
        let id = s.insert(live("c1", "a1", 1)).unwrap();
        assert!(s.get(&id, "c1", 1).is_ok());
        assert_eq!(s.get(&id, "c2", 1).unwrap_err().code, ErrorCode::CursorInvalid);
        assert_eq!(s.get(&id, "c1", 2).unwrap_err().code, ErrorCode::CursorInvalid);
        s.invalidate_account("a1");
        assert_eq!(s.get(&id, "c1", 1).unwrap_err().code, ErrorCode::CursorInvalid);

        // Count cap evicts the oldest.
        s.set_limits(TTL, 3, MAX_BYTES);
        let ids: Vec<String> = (0..4).map(|_| s.insert(live("c1", "a", 1)).unwrap()).collect();
        assert_eq!(s.len(), 3);
        assert_eq!(s.get(&ids[0], "c1", 1).unwrap_err().code, ErrorCode::CursorInvalid);
        assert!(s.get(&ids[3], "c1", 1).is_ok());

        // Byte cap evicts too, and the total never exceeds it.
        s.set_limits(TTL, 1000, 4096);
        for _ in 0..20 {
            s.insert(live("c1", "a", 20)).unwrap();
            assert!(s.bytes() <= 4096);
        }
        // A single oversized cursor is refused rather than evicting everything.
        assert_eq!(s.insert(live("c1", "a", 500)).unwrap_err().code, ErrorCode::BudgetExceeded);

        // TTL.
        s.set_limits(Duration::from_millis(0), 1000, MAX_BYTES);
        let id = s.insert(live("c1", "a", 1)).unwrap();
        assert_eq!(s.get(&id, "c1", 1).unwrap_err().code, ErrorCode::CursorInvalid);
    }

    #[test]
    fn one_client_cannot_evict_another() {
        let s = CursorStore::default();
        // The victim's cursors are the oldest in the store.
        let victim: Vec<String> = (0..3).map(|_| s.insert(live("victim", "a", 1)).unwrap()).collect();
        let first_flood = s.insert(live("flood", "b", 1)).unwrap();
        for _ in 0..(2 * MAX_PER_CLIENT) {
            s.insert(live("flood", "b", 1)).unwrap();
        }
        for id in &victim {
            assert!(s.get(id, "victim", 1).is_ok(), "another client's flood evicted a cursor");
        }
        assert_eq!(s.len(), 3 + MAX_PER_CLIENT);
        // The flooding client lost its own oldest cursors first.
        assert_eq!(s.get(&first_flood, "flood", 1).unwrap_err().code, ErrorCode::CursorInvalid);

        // The global caps still hold and still evict globally oldest-first beyond the per-client share.
        s.set_limits(TTL, 4, MAX_BYTES);
        s.set_per_client_limit(3);
        let c: Vec<String> = (0..3).map(|_| s.insert(live("c", "a", 1)).unwrap()).collect();
        assert!(s.len() <= 4);
        assert!(c.iter().all(|id| s.get(id, "c", 1).is_ok()));
        s.insert(live("c", "a", 1)).unwrap();
        assert_eq!(s.get(&c[0], "c", 1).unwrap_err().code, ErrorCode::CursorInvalid, "own oldest goes first");
        assert!(s.get(&c[1], "c", 1).is_ok());
    }
}
