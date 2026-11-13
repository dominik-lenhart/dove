//! Watches and watch events (design 0.2 section 3).
//!
//! A watch belongs to the client (connection) that created it and to one mailbox it may read. Kinds:
//! - `thread_reply`: a new message in thread X from someone other than the mailbox owner;
//! - `from`: new mail from an address or a domain;
//! - `query`: new mail matching a typed `where` filter (the `search_messages` schema), evaluated against newly indexed
//!   messages only;
//! - `no_reply_by`: thread X gets no message from others before a deadline; fires once, at the deadline.
//!
//! Event production: the sync engines call [`messages_indexed`] after a fenced index transaction committed messages
//! that are new to the account's serving generation (Gmail history sync, IMAP polling and IDLE alike; never during a
//! backfill or rebuild). Matching reads the index, then records events in one state-store transaction: no transaction
//! spans network I/O. `no_reply_by` is decided by [`tick`], which takes the clock as an argument.
//!
//! For every kind only messages count that were not sent by the mailbox owner ([`owner_addresses`]), are not drafts
//! and not in spam or trash. Thread kinds count only messages newer than the thread's newest message when the watch
//! was created (`baseline_ms`); `from` and `query` only messages received at most [`RECEIVED_SLACK_SECS`] before the
//! watch was created. Either way an old message that is merely re-filed (for example moved between IMAP folders and
//! indexed again under a new id) does not fire.
//!
//! Events carry ids and timestamps only: watch id, kind, account alias, message id, thread id, received_at. No
//! subject, sender or body. They are kept [`RETENTION_SECS`] and read with `list_watch_events` (pull); a watch may
//! also name an operator-registered sink (push, [`sinks`]).
//!
//! A watch ends when it expires, fires (`no_reply_by`), its client is revoked or expires, its client loses `read` on
//! the mailbox, or the mailbox is disabled, stops being indexed or is removed (rows cascade).

pub mod sinks;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::app::App;
use crate::index::ingest::{ROLE_FROM, domain_of, norm_addr, norm_domain};
use crate::index::query::{self, Expr, Scope, Target};
use crate::policy::{self, Capability};
use crate::util;
use crate::vault::Vault;

/// Active watches per client.
pub const MAX_ACTIVE_PER_CLIENT: i64 = 50;
/// Expiry when `expires_at` is not given.
pub const DEFAULT_EXPIRY_SECS: i64 = 30 * 86_400;
/// Latest allowed `expires_at` / `deadline`, from now.
pub const MAX_EXPIRY_SECS: i64 = 180 * 86_400;
/// Events (and ended watches) are deleted this long after they were created (ended).
pub const RETENTION_SECS: i64 = 14 * 86_400;
/// A message counts for a watch if it was received at most this long before the watch was created: mail that
/// arrived while the agent was setting the watch up still fires, an old message re-filed later does not.
pub const RECEIVED_SLACK_SECS: i64 = 900;
/// `no_reply_by` fires as soon as the index is known complete past the deadline, or this long after it at the latest.
pub const NO_REPLY_GRACE_SECS: i64 = 3600;
/// Background tick: expiry, `no_reply_by`, retention, sink delivery.
const TICK: Duration = Duration::from_secs(15);
/// Vault kind of a sealed watch filter (scope = watch id).
pub(crate) const FILTER_KIND: &str = "watch_filter";

/// Runtime state shared through [`App`]: wakes the background worker when new events need delivery.
#[derive(Default)]
pub struct Runtime {
    wake: Notify,
}

/// Wakes the background worker (new events with a sink).
pub fn wake(app: &App) {
    app.watch.wake.notify_one();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    ThreadReply,
    From,
    Query,
    NoReplyBy,
}

impl Kind {
    pub const ALL: &'static [&'static str] = &["thread_reply", "from", "query", "no_reply_by"];

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "thread_reply" => Kind::ThreadReply,
            "from" => Kind::From,
            "query" => Kind::Query,
            "no_reply_by" => Kind::NoReplyBy,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::ThreadReply => "thread_reply",
            Kind::From => "from",
            Kind::Query => "query",
            Kind::NoReplyBy => "no_reply_by",
        }
    }
}

/// The sender a `from` watch matches: one normalized address, or an exact domain (no subdomains, like the search
/// field `from_domain`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "v", rename_all = "snake_case")]
pub enum FromMatch {
    Address(String),
    Domain(String),
}

impl FromMatch {
    /// `alice@example.com` is an address; `example.com` or `@example.com` a domain.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() || s.len() > 256 || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("'from' must be an email address or a domain".into());
        }
        let m = match s.rsplit_once('@') {
            Some(("", d)) => FromMatch::Domain(norm_domain(d)),
            Some((_, d)) if !d.is_empty() => FromMatch::Address(norm_addr(s)),
            Some(_) => return Err("'from' must be an email address or a domain".into()),
            None => FromMatch::Domain(norm_domain(s)),
        };
        if let FromMatch::Domain(d) = &m
            && (!d.contains('.') || d.contains('@'))
        {
            return Err("'from' must be an email address or a domain".into());
        }
        Ok(m)
    }

    fn matches(&self, senders: &[String]) -> bool {
        match self {
            FromMatch::Address(a) => senders.iter().any(|s| s == a),
            FromMatch::Domain(d) => senders.iter().any(|s| domain_of(s) == *d),
        }
    }

    pub fn display(&self) -> String {
        match self {
            FromMatch::Address(a) => a.clone(),
            FromMatch::Domain(d) => d.clone(),
        }
    }
}

/// A watch's match arguments, sealed in `watches.filter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<FromMatch>,
    /// The `where` object of a `query` watch, as the agent sent it (re-parsed on use).
    #[serde(default, rename = "where", skip_serializing_if = "Option::is_none")]
    pub query: Option<Value>,
}

pub fn seal_filter(vault: &Vault, watch_id: &str, f: &Filter) -> anyhow::Result<Vec<u8>> {
    vault.seal_aux(FILTER_KIND, watch_id, &serde_json::to_vec(f)?)
}

pub fn open_filter(vault: &Vault, watch_id: &str, blob: &[u8]) -> anyhow::Result<Filter> {
    Ok(serde_json::from_slice(&vault.open_aux(FILTER_KIND, watch_id, blob)?)?)
}

/// Normalized addresses that count as the mailbox owner (mail from them never fires a watch). The single place to
/// extend when a mailbox gains send-as aliases.
pub fn owner_addresses(conn: &Connection, account_id: &str) -> anyhow::Result<Vec<String>> {
    let email: Option<String> =
        conn.query_row("SELECT email FROM accounts WHERE id = ?1", [account_id], |r| r.get(0)).optional()?;
    let mut out: Vec<String> = email.map(|e| vec![norm_addr(&e)]).unwrap_or_default();
    // Send-as aliases are the owner too: mail sent from an alias is never "a reply from someone else".
    for alias in crate::identity::load_aliases(conn, account_id)? {
        out.push(norm_addr(&alias.address));
    }
    Ok(out)
}

/// Why a watch of `client_id` on `account_id` can no longer fire, or None while it can.
pub fn end_reason(
    conn: &Connection,
    client_id: &str,
    account_id: &str,
    now: i64,
) -> anyhow::Result<Option<&'static str>> {
    let client: Option<(Option<i64>, Option<i64>)> = conn
        .query_row("SELECT revoked_at, expires_at FROM clients WHERE id = ?1", [client_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    match client {
        None | Some((Some(_), _)) => return Ok(Some("client_revoked")),
        Some((None, Some(e))) if e <= now => return Ok(Some("client_expired")),
        _ => {}
    }
    let account: Option<(String, bool)> = conn
        .query_row("SELECT status, index_enabled FROM accounts WHERE id = ?1", [account_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    match account {
        None => return Ok(Some("account_removed")),
        Some((status, _)) if status == "disabled" => return Ok(Some("account_disabled")),
        Some((_, false)) => return Ok(Some("index_disabled")),
        _ => {}
    }
    // The same effective grants the policy uses for requests (grant ∩ project membership).
    let readable = policy::load_mailboxes(conn, client_id)?
        .iter()
        .any(|m| m.account_id == account_id && m.actions.has(Capability::Read));
    Ok(if readable { None } else { Some("access_lost") })
}

/// Ends a watch. Reasons that withdraw access also drop its undelivered pushes.
pub fn end_watch(conn: &Connection, watch_id: &str, reason: &str, now: i64) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE watches SET state = 'ended', ended_at = ?1, end_reason = ?2 WHERE id = ?3 AND state = 'active'",
        params![now, reason, watch_id],
    )?;
    if !matches!(reason, "expired" | "fired" | "replied") {
        conn.execute(
            "DELETE FROM sink_deliveries WHERE state = 'pending' \
             AND event_seq IN (SELECT seq FROM watch_events WHERE watch_id = ?1)",
            [watch_id],
        )?;
    }
    Ok(())
}

/// One matched message (or, for `no_reply_by`, the deadline without one).
#[derive(Debug, Clone)]
pub struct Hit {
    pub message_id: Option<String>,
    pub thread_id: Option<String>,
    /// Unix milliseconds (index `received_at`).
    pub received_at: Option<i64>,
}

/// Records events for a live, active watch in the caller's transaction. Returns how many are new (a message fires a
/// watch at most once) and whether a push was queued.
pub fn record_events(conn: &Connection, watch_id: &str, hits: &[Hit], now: i64) -> anyhow::Result<(usize, bool)> {
    let w: Option<(String, String, String, Option<String>, String)> = conn
        .query_row("SELECT client_id, account_id, kind, sink_id, state FROM watches WHERE id = ?1", [watch_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .optional()?;
    let Some((client_id, account_id, kind, sink_id, state)) = w else { return Ok((0, false)) };
    if state != "active" {
        return Ok((0, false));
    }
    if let Some(reason) = end_reason(conn, &client_id, &account_id, now)? {
        end_watch(conn, watch_id, reason, now)?;
        return Ok((0, false));
    }
    let mut new = 0;
    for h in hits {
        let n = conn.execute(
            "INSERT OR IGNORE INTO watch_events(watch_id, client_id, account_id, kind, message_id, thread_id, \
             received_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![watch_id, client_id, account_id, kind, h.message_id, h.thread_id, h.received_at, now],
        )?;
        if n == 0 {
            continue;
        }
        new += 1;
        if let Some(sink) = &sink_id {
            conn.execute(
                "INSERT INTO sink_deliveries(event_seq, sink_id, state, attempts, next_attempt_at, updated_at) \
                 VALUES (?1, ?2, 'pending', 0, ?3, ?3)",
                params![conn.last_insert_rowid(), sink, now],
            )?;
        }
    }
    if new > 0 {
        conn.execute(
            "UPDATE watches SET fired = fired + ?1, last_fired_at = ?2 WHERE id = ?3",
            params![new as i64, now, watch_id],
        )?;
    }
    Ok((new, new > 0 && sink_id.is_some()))
}

// ------------------------------------------------------------------ matching new messages

#[derive(Debug, Clone)]
struct WatchRow {
    id: String,
    kind: Kind,
    thread_id: Option<String>,
    baseline_ms: Option<i64>,
    filter: Option<Vec<u8>>,
    created_at: i64,
}

/// A newly indexed message as matching sees it.
#[derive(Debug, Clone)]
struct NewMsg {
    row: i64,
    gmail_id: String,
    thread_id: String,
    received_at: i64,
    senders: Vec<String>,
    eligible: bool,
}

/// Hook for the sync engines, called after a fenced transaction committed `message_ids` as new rows of the
/// account's serving generation `gen_id`. Never fails the sync: errors are logged (without content).
pub async fn messages_indexed(app: &Arc<App>, account_id: &str, gen_id: i64, message_ids: Vec<String>) {
    if message_ids.is_empty() {
        return;
    }
    if let Err(e) = match_new(app, account_id, gen_id, message_ids).await {
        tracing::warn!(error = %e, "watch matching failed");
    }
}

async fn match_new(app: &Arc<App>, account_id: &str, gen_id: i64, ids: Vec<String>) -> anyhow::Result<()> {
    let now = util::now_unix();
    let aid = account_id.to_string();
    let (watches, owners, alias) = app
        .store
        .call(move |c| {
            let mut st = c.prepare_cached(
                "SELECT id, kind, thread_id, baseline_ms, filter, created_at FROM watches \
                 WHERE account_id = ?1 AND state = 'active' AND expires_at > ?2",
            )?;
            let rows: Vec<WatchRow> = st
                .query_map(params![aid, now], |r| {
                    Ok(WatchRow {
                        id: r.get(0)?,
                        kind: Kind::parse(&r.get::<_, String>(1)?).unwrap_or(Kind::Query),
                        thread_id: r.get(2)?,
                        baseline_ms: r.get(3)?,
                        filter: r.get(4)?,
                        created_at: r.get(5)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            let alias: Option<String> =
                c.query_row("SELECT alias FROM accounts WHERE id = ?1", [&aid], |r| r.get(0)).optional()?;
            Ok((rows, owner_addresses(c, &aid)?, alias))
        })
        .await?;
    let Some(alias) = alias else { return Ok(()) };
    if watches.is_empty() {
        return Ok(());
    }
    // Open sealed filters; a watch whose filter cannot be opened or parsed is skipped (logged once per batch).
    let mut prepared: Vec<(WatchRow, Filter, Option<Expr>)> = Vec::new();
    for w in watches {
        let f = match &w.filter {
            Some(b) => match open_filter(&app.vault, &w.id, b) {
                Ok(f) => f,
                Err(_) => {
                    tracing::warn!("a watch filter could not be opened; the watch is skipped");
                    continue;
                }
            },
            None => Filter::default(),
        };
        let expr = match w.kind {
            Kind::Query => match query::parse_where(f.query.as_ref()) {
                Ok(Some(e)) => Some(e),
                _ => continue,
            },
            _ => None,
        };
        prepared.push((w, f, expr));
    }
    let queries: Vec<(usize, Expr)> =
        prepared.iter().enumerate().filter_map(|(i, (_, _, e))| e.clone().map(|e| (i, e))).collect();
    let aid = account_id.to_string();
    let owners_set: HashSet<String> = owners.into_iter().collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    let (msgs, query_hits) = app
        .index
        .read(deadline, move |c| {
            let tx = c.unchecked_transaction()?;
            // Only rows of the generation that still serves the account (a rebuild may have replaced it).
            if crate::index::sync::load_state(&tx, &aid)?.and_then(|s| s.active_gen) != Some(gen_id) {
                return Ok((Vec::new(), HashMap::new()));
            }
            let mut msgs = Vec::new();
            {
                let mut st = tx.prepare_cached(
                    "SELECT id, thread_id, received_at, is_draft, spam_trash FROM messages WHERE gen = ?1 AND gmail_id = ?2",
                )?;
                let mut from = tx.prepare_cached("SELECT addr FROM addrs WHERE msg = ?1 AND role = ?2")?;
                for id in &ids {
                    let row = st
                        .query_row(params![gen_id, id], |r| {
                            Ok((
                                r.get::<_, i64>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, i64>(2)?,
                                r.get::<_, bool>(3)?,
                                r.get::<_, bool>(4)?,
                            ))
                        })
                        .optional()?;
                    let Some((row, thread_id, received_at, draft, spam_trash)) = row else { continue };
                    let senders: Vec<String> =
                        from.query_map(params![row, ROLE_FROM], |r| r.get(0))?.collect::<Result<_, _>>()?;
                    msgs.push(NewMsg { row, gmail_id: id.clone(), thread_id, received_at, senders, eligible: !draft && !spam_trash });
                }
            }
            let rows: Vec<i64> = msgs.iter().map(|m| m.row).collect();
            let att_fts: bool =
                tx.query_row("SELECT att_fts FROM generations WHERE id = ?1", [gen_id], |r| r.get(0))?;
            let targets = [Target { account_id: aid.clone(), alias: alias.clone(), gen_id, att_fts }];
            let known: HashMap<String, String> = [(alias.clone(), aid.clone())].into();
            // No own addresses: watches refuse `from_self` (`tools::watches`), so it never needs them here.
            let selves = HashMap::new();
            let scope = Scope { targets: &targets, known: &known, selves: &selves };
            let mut hits: HashMap<usize, HashSet<i64>> = HashMap::new();
            for (i, e) in &queries {
                // A filter that no longer compiles (for example a qualifier naming another mailbox) matches nothing.
                if let Ok(m) = query::matching_rows(&tx, e, &scope, &rows) {
                    hits.insert(*i, m.into_iter().collect());
                }
            }
            Ok((msgs, hits))
        })
        .await
        .map_err(|e| anyhow!("index read failed: {}", e.code.as_str()))?;
    let mut fire: Vec<(String, Vec<Hit>)> = Vec::new();
    let mut replied: Vec<String> = Vec::new();
    for (i, (w, f, _)) in prepared.iter().enumerate() {
        let mut hits = Vec::new();
        for m in &msgs {
            let from_owner = m.senders.iter().any(|s| owners_set.contains(s));
            if !m.eligible || from_owner {
                continue;
            }
            let matched = match w.kind {
                // Not older than the thread's newest message when the watch was created (an old message of the
                // thread that is indexed again, for example after a move, does not count). `>=`: the message is new
                // to the index, and IMAP dates have second precision, so a quick reply can share the instant.
                Kind::ThreadReply | Kind::NoReplyBy => {
                    w.thread_id.as_deref() == Some(m.thread_id.as_str()) && m.received_at >= w.baseline_ms.unwrap_or(0)
                }
                _ if m.received_at < (w.created_at - RECEIVED_SLACK_SECS) * 1000 => false,
                Kind::From => f.from.as_ref().is_some_and(|fm| fm.matches(&m.senders)),
                Kind::Query => query_hits.get(&i).is_some_and(|s| s.contains(&m.row)),
            };
            if matched {
                hits.push(Hit {
                    message_id: Some(m.gmail_id.clone()),
                    thread_id: Some(m.thread_id.clone()),
                    received_at: Some(m.received_at),
                });
            }
        }
        if hits.is_empty() {
            continue;
        }
        if w.kind == Kind::NoReplyBy {
            // A reply from someone else arrived: the watch ends quietly (it fires only on silence).
            replied.push(w.id.clone());
        } else {
            fire.push((w.id.clone(), hits));
        }
    }
    if fire.is_empty() && replied.is_empty() {
        return Ok(());
    }
    let push = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let mut push = false;
            for (wid, hits) in &fire {
                push |= record_events(&tx, wid, hits, now)?.1;
            }
            for wid in &replied {
                end_watch(&tx, wid, "replied", now)?;
            }
            tx.commit()?;
            Ok(push)
        })
        .await?;
    if push {
        wake(app);
    }
    Ok(())
}

// ------------------------------------------------------------------ background tick

/// What one [`tick`] did (tests).
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct TickReport {
    pub ended: usize,
    pub no_reply_fired: usize,
    pub pruned_events: usize,
    pub pruned_watches: usize,
    pub deliveries: sinks::DeliveryReport,
}

/// One maintenance pass at time `now` (unix seconds): `no_reply_by` deadlines, expiry and loss of access, retention,
/// then due sink deliveries. Tests call it with a chosen clock; the service runs it every few seconds.
pub async fn tick(app: &Arc<App>, now: i64) -> anyhow::Result<TickReport> {
    let mut report = TickReport { no_reply_fired: no_reply_due(app, now).await?, ..Default::default() };
    report.ended = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let rows: Vec<(String, String, String, i64)> = {
                let mut st =
                    tx.prepare("SELECT id, client_id, account_id, expires_at FROM watches WHERE state = 'active'")?;
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?
            };
            let mut cache: HashMap<(String, String), Option<&'static str>> = HashMap::new();
            let mut n = 0;
            for (id, client, account, expires_at) in rows {
                let reason = match cache.get(&(client.clone(), account.clone())) {
                    Some(r) => *r,
                    None => {
                        let r = end_reason(&tx, &client, &account, now)?;
                        cache.insert((client, account), r);
                        r
                    }
                };
                let reason = reason.or((expires_at <= now).then_some("expired"));
                if let Some(r) = reason {
                    end_watch(&tx, &id, r, now)?;
                    n += 1;
                }
            }
            tx.commit()?;
            Ok(n)
        })
        .await?;
    let cutoff = now - RETENTION_SECS;
    (report.pruned_events, report.pruned_watches) = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let e = tx.execute("DELETE FROM watch_events WHERE created_at < ?1", [cutoff])?;
            let w = tx.execute("DELETE FROM watches WHERE state = 'ended' AND ended_at < ?1", [cutoff])?;
            tx.commit()?;
            Ok((e, w))
        })
        .await?;
    report.deliveries = sinks::deliver_due(app, now).await?;
    Ok(report)
}

/// Decides `no_reply_by` watches whose deadline passed: a message from others newer than the watch's baseline ends it
/// quietly; otherwise it fires once the index has synced past the deadline (or [`NO_REPLY_GRACE_SECS`] after it).
async fn no_reply_due(app: &Arc<App>, now: i64) -> anyhow::Result<usize> {
    let due: Vec<(String, String, String, i64, i64)> = app
        .store
        .call(move |c| {
            let mut st = c.prepare(
                "SELECT id, account_id, thread_id, coalesce(baseline_ms, 0), deadline FROM watches \
                 WHERE state = 'active' AND kind = 'no_reply_by' AND deadline <= ?1",
            )?;
            Ok(st
                .query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                .collect::<Result<_, _>>()?)
        })
        .await?;
    let mut fired = 0;
    for (wid, aid, thread_id, baseline_ms, deadline) in due {
        let a = aid.clone();
        let owners = app.store.call(move |c| owner_addresses(c, &a)).await?;
        let (a, t) = (aid.clone(), thread_id.clone());
        let state = app
            .index
            .read(Instant::now() + Duration::from_secs(10), move |c| {
                let tx = c.unchecked_transaction()?;
                let Some(s) = crate::index::sync::load_state(&tx, &a)? else { return Ok(None) };
                let Some(g) = s.active_gen else { return Ok(None) };
                let mut st = tx.prepare_cached(
                    "SELECT m.id FROM messages m WHERE m.gen = ?1 AND m.thread_id = ?2 AND m.received_at > ?3 \
                     AND m.is_draft = 0 AND m.spam_trash = 0",
                )?;
                let rows: Vec<i64> =
                    st.query_map(params![g, t, baseline_ms], |r| r.get(0))?.collect::<Result<_, _>>()?;
                let mut from = tx.prepare_cached("SELECT addr FROM addrs WHERE msg = ?1 AND role = ?2")?;
                let mut replied = false;
                for r in rows {
                    let senders: Vec<String> =
                        from.query_map(params![r, ROLE_FROM], |x| x.get(0))?.collect::<Result<_, _>>()?;
                    if !senders.iter().any(|s| owners.contains(s)) {
                        replied = true;
                        break;
                    }
                }
                Ok(Some((replied, s.last_success_at.unwrap_or(0))))
            })
            .await
            .map_err(|e| anyhow!("index read failed: {}", e.code.as_str()))?;
        let decision = match state {
            // Not indexed any more: the regular end check below ends the watch.
            None => continue,
            Some((true, _)) => "replied",
            Some((false, synced)) if synced >= deadline || now >= deadline + NO_REPLY_GRACE_SECS => "fired",
            Some(_) => continue,
        };
        let tid = thread_id.clone();
        let push = app
            .store
            .call(move |c| {
                let tx = c.transaction()?;
                let mut push = false;
                if decision == "fired" {
                    let hit = Hit { message_id: None, thread_id: Some(tid), received_at: None };
                    let (n, p) = record_events(&tx, &wid, &[hit], now)?;
                    push = p;
                    if n > 0 {
                        end_watch(&tx, &wid, "fired", now)?;
                    }
                } else {
                    end_watch(&tx, &wid, "replied", now)?;
                }
                tx.commit()?;
                Ok(push)
            })
            .await?;
        if decision == "fired" {
            fired += 1;
        }
        if push {
            wake(app);
        }
    }
    Ok(fired)
}

/// Starts the background worker (called from `dove serve`): runs [`tick`] every few seconds and right after new
/// events with a sink.
pub fn start(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = tick(&app, util::now_unix()).await {
                tracing::warn!(error = %e, "watch maintenance tick failed");
            }
            tokio::select! {
                _ = app.watch.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
        }
    })
}

// ------------------------------------------------------------------ agent-facing rows

/// Opaque cursor of `list_watch_events`: the last event position the caller has seen.
pub fn encode_cursor(seq: i64) -> String {
    format!("wc_{}", util::b64url(seq.to_string().as_bytes()))
}

pub fn decode_cursor(s: &str) -> Option<i64> {
    let raw = util::b64url_decode(s.strip_prefix("wc_")?)?;
    std::str::from_utf8(&raw).ok()?.parse::<i64>().ok().filter(|n| *n >= 0)
}

/// Agent-visible event id.
pub fn event_id(seq: i64) -> String {
    format!("e{seq}")
}

/// One stored event, as the agent and a sink see it.
#[derive(Debug, Clone)]
pub struct EventRow {
    pub seq: i64,
    pub watch_id: String,
    pub kind: String,
    pub alias: String,
    pub message_id: Option<String>,
    pub thread_id: Option<String>,
    /// Unix milliseconds.
    pub received_at: Option<i64>,
    pub created_at: i64,
}

impl EventRow {
    /// Columns for [`EventRow::from_row`]; the query must join `accounts a` on the event's account.
    pub const COLUMNS: &'static str =
        "e.seq, e.watch_id, e.kind, a.alias, e.message_id, e.thread_id, e.received_at, e.created_at";

    pub fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            seq: r.get(0)?,
            watch_id: r.get(1)?,
            kind: r.get(2)?,
            alias: r.get(3)?,
            message_id: r.get(4)?,
            thread_id: r.get(5)?,
            received_at: r.get(6)?,
            created_at: r.get(7)?,
        })
    }

    /// The content-free event payload, identical for pull (`list_watch_events`) and push (sinks): ids and
    /// timestamps, never subject, sender or body.
    pub fn to_json(&self) -> Value {
        json!({
            "event_id": event_id(self.seq),
            "watch_id": self.watch_id,
            "kind": self.kind,
            "account": self.alias,
            "message_id": self.message_id,
            "thread_id": self.thread_id,
            "received_at": self.received_at.map(util::rfc3339_ms),
            "created_at": util::rfc3339(self.created_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_match_parses_addresses_and_exact_domains() {
        assert_eq!(FromMatch::parse(" Ann@Example.COM ").unwrap(), FromMatch::Address("ann@example.com".into()));
        assert_eq!(FromMatch::parse("@Example.com.").unwrap(), FromMatch::Domain("example.com".into()));
        assert_eq!(FromMatch::parse("example.com").unwrap(), FromMatch::Domain("example.com".into()));
        for bad in ["", "ann@", "localhost", "a b@example.com", "x@@", "@"] {
            assert!(FromMatch::parse(bad).is_err(), "{bad}");
        }
        let d = FromMatch::Domain("example.com".into());
        assert!(d.matches(&["ann@example.com".into()]));
        assert!(!d.matches(&["ann@sub.example.com".into()]));
        assert!(!d.matches(&["ann@example.com.evil.test".into()]));
    }

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        assert_eq!(decode_cursor(&encode_cursor(0)), Some(0));
        assert_eq!(decode_cursor(&encode_cursor(123_456)), Some(123_456));
        for bad in ["", "wc_", "wc_!!", "123", &format!("wc_{}", util::b64url(b"-5"))] {
            assert_eq!(decode_cursor(bad), None, "{bad}");
        }
    }
}
