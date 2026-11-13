//! Mail intelligence queries over the index (v0.2 design section 4): contact search and the thread digest.
//!
//! Like [`super::query`], these only read generations the caller's mailboxes currently serve (`Target`s are fixed
//! before any predicate runs), bind every value and build no identifier from input. Both run inside the caller's read
//! transaction on a blocking thread and are bounded: contact search looks at most [`MAX_CANDIDATES`] addresses, the
//! digest at most one year of mail and `limit + 1` threads per page.

use std::collections::{BTreeMap, HashMap};

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, params_from_iter};
use serde::Serialize;

use super::ingest::{ROLE_BCC, ROLE_CC, ROLE_FROM, ROLE_TO};
use super::query::Target;
use crate::content;
use crate::mime::{self, Category};
use crate::util;

/// Addresses ranked per contact search.
pub const MAX_CANDIDATES: usize = 2000;
/// Newest messages whose addresses are the candidates of a contact search without a query.
pub const RECENT_MESSAGES: i64 = 2000;
/// Addresses per statistics statement (keeps the bound-parameter count low).
const CHUNK: usize = 200;
/// Longest `query` of a contact search, in characters.
pub const MAX_QUERY_CHARS: usize = 100;
/// Shortest `query` of a contact search: a single letter would match most of the address book.
pub const MIN_QUERY_CHARS: usize = 2;

pub const DEFAULT_LIMIT: usize = 20;
pub const MAX_LIMIT: usize = 50;
/// Oldest `since` a digest accepts, relative to now (bounds the scan).
pub const MAX_WINDOW_DAYS: i64 = 366;
/// Messages per thread whose senders are listed as participants.
const PARTICIPANT_MESSAGES: i64 = 5;
/// Most participants named per thread.
const MAX_PARTICIPANTS: usize = 5;
/// Characters of a digest snippet.
pub const SNIPPET_CHARS: usize = 160;
pub const MAX_FOLDERS: usize = 10;

fn gens(t: &[Target]) -> Vec<SqlValue> {
    t.iter().map(|t| SqlValue::Integer(t.gen_id)).collect()
}

fn marks(n: usize) -> String {
    format!("({})", vec!["?"; n.max(1)].join(", "))
}

// ------------------------------------------------------------------ contacts

#[derive(Debug, Clone, Serialize)]
pub struct Contact {
    pub address: String,
    pub name: Option<String>,
    /// Messages from this address.
    pub received: i64,
    /// Sent messages (label `SENT`) that have this address as a recipient.
    pub sent: i64,
    pub first_contact: String,
    pub last_contact: String,
    /// Aliases of the mailboxes the contact was seen in.
    pub accounts: Vec<String>,
    #[serde(skip)]
    pub last_ms: i64,
    #[serde(skip)]
    pub score: f64,
}

pub struct ContactReq<'a> {
    pub query: Option<&'a str>,
    pub include_automated: bool,
    pub limit: usize,
    /// Own mailbox addresses (lower case): never listed as contacts.
    pub own: Vec<String>,
    pub now_ms: i64,
}

pub struct ContactResult {
    pub contacts: Vec<Contact>,
    /// More matching addresses than [`MAX_CANDIDATES`]: the ranking covers only the first ones found.
    pub truncated: bool,
}

/// LIKE pattern matching `s` anywhere, with the wildcard characters of `s` escaped (`ESCAPE '\'`).
fn like_contains(s: &str) -> String {
    let mut out = String::from("%");
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// Rank: the logarithm of the message count (mail you sent counts double, so one more message matters less the more
/// there already are) times a 90 day half-life on the last contact, so a recent correspondent outranks a prolific
/// but long-silent one.
pub fn score(sent: i64, received: i64, last_ms: i64, now_ms: i64) -> f64 {
    let age_days = ((now_ms - last_ms).max(0) as f64) / 86_400_000.0;
    ((2 * sent + received) as f64).ln_1p() * 0.5f64.powf(age_days / 90.0)
}

/// Candidate addresses: those matching `query` in the address or a display name, or (no query) those of the newest
/// [`RECENT_MESSAGES`] messages. Returns the addresses and whether the cap cut the list.
fn candidates(conn: &Connection, t: &[Target], req: &ContactReq<'_>) -> anyhow::Result<(Vec<String>, bool)> {
    let mut params: Vec<SqlValue> = vec![];
    let sql = match req.query {
        Some(q) => {
            let pat = SqlValue::Text(like_contains(&q.to_lowercase()));
            let g = marks(t.len());
            for _ in 0..2 {
                params.push(pat.clone());
                params.extend(gens(t));
            }
            // Two covering index scans (addrs_addr, addrs_name) instead of one scan with OR.
            format!(
                "SELECT addr FROM addrs WHERE addr LIKE ? ESCAPE '\\' AND gen IN {g} \
                 UNION SELECT addr FROM addrs WHERE name_lc LIKE ? ESCAPE '\\' AND gen IN {g} LIMIT {}",
                MAX_CANDIDATES + 1
            )
        }
        None => {
            params.extend(gens(t));
            params.extend(gens(t));
            params.push(SqlValue::Integer(RECENT_MESSAGES));
            // The unary `+` keeps several mailboxes on the `messages_recent` newest-first walk, as in search.
            let walk = if t.len() > 1 { "+m.gen" } else { "m.gen" };
            format!(
                "SELECT DISTINCT addr FROM addrs WHERE gen IN {} AND msg IN \
                 (SELECT m.id FROM messages m WHERE {walk} IN {} AND m.spam_trash = 0 \
                  ORDER BY m.received_at DESC LIMIT ?)",
                marks(t.len()),
                marks(t.len())
            )
        }
    };
    let mut st = conn.prepare(&sql)?;
    let mut found: Vec<String> = st.query_map(params_from_iter(params), |r| r.get(0))?.collect::<Result<_, _>>()?;
    let truncated = found.len() > MAX_CANDIDATES;
    found.truncate(MAX_CANDIDATES);
    found.retain(|a| !req.own.contains(a) && (req.include_automated || !mime::is_noreply(a)));
    Ok((found, truncated))
}

/// `EXPLAIN QUERY PLAN` of the candidate statement (tests verify it stays on the covering indexes).
pub fn explain_candidates(conn: &Connection, t: &[Target], req: &ContactReq<'_>) -> anyhow::Result<Vec<String>> {
    let (sql, params) = candidate_sql(t, req);
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
    let rows = st.query_map(params_from_iter(params), |r| r.get::<_, String>(3))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn candidate_sql(t: &[Target], req: &ContactReq<'_>) -> (String, Vec<SqlValue>) {
    // Same text as in `candidates`, rebuilt for EXPLAIN without running it.
    let mut params: Vec<SqlValue> = vec![];
    match req.query {
        Some(q) => {
            let pat = SqlValue::Text(like_contains(&q.to_lowercase()));
            let g = marks(t.len());
            for _ in 0..2 {
                params.push(pat.clone());
                params.extend(gens(t));
            }
            (
                format!(
                    "SELECT addr FROM addrs WHERE addr LIKE ? ESCAPE '\\' AND gen IN {g} \
                     UNION SELECT addr FROM addrs WHERE name_lc LIKE ? ESCAPE '\\' AND gen IN {g} LIMIT {}",
                    MAX_CANDIDATES + 1
                ),
                params,
            )
        }
        None => {
            params.extend(gens(t));
            params.extend(gens(t));
            params.push(SqlValue::Integer(RECENT_MESSAGES));
            let walk = if t.len() > 1 { "+m.gen" } else { "m.gen" };
            (
                format!(
                    "SELECT DISTINCT addr FROM addrs WHERE gen IN {} AND msg IN \
                     (SELECT m.id FROM messages m WHERE {walk} IN {} AND m.spam_trash = 0 \
                      ORDER BY m.received_at DESC LIMIT ?)",
                    marks(t.len()),
                    marks(t.len())
                ),
                params,
            )
        }
    }
}

/// Contacts of the mailboxes in `t`, best first. Statistics count only exchanged mail: messages from the address
/// and sent mail to it (not mail that merely names it in Cc).
pub fn contacts(conn: &Connection, t: &[Target], req: &ContactReq<'_>) -> anyhow::Result<ContactResult> {
    if t.is_empty() {
        return Ok(ContactResult { contacts: vec![], truncated: false });
    }
    let (cands, truncated) = candidates(conn, t, req)?;
    let alias: HashMap<String, &str> = HashMap::new();
    let _ = alias;
    let alias_of = |account_id: &str| t.iter().find(|x| x.account_id == account_id).map(|x| x.alias.clone());
    let mut out: BTreeMap<String, Contact> = BTreeMap::new();
    for chunk in cands.chunks(CHUNK) {
        let sql = format!(
            "SELECT addr, \
                sum(role = {ROLE_FROM}), sum(role > {ROLE_FROM}), min(at), max(at), \
                max(CASE WHEN name IS NOT NULL THEN printf('%020d', at) || name END), \
                group_concat(DISTINCT acc) \
             FROM (SELECT a.addr AS addr, a.role AS role, a.name AS name, m.received_at AS at, m.account_id AS acc, \
                      (a.role IN ({ROLE_TO}, {ROLE_CC}, {ROLE_BCC}) AND EXISTS \
                         (SELECT 1 FROM labels l WHERE l.label = 'SENT' AND l.gen = a.gen AND l.msg = a.msg)) AS is_sent \
                   FROM addrs a JOIN messages m ON m.id = a.msg \
                   WHERE a.addr IN {} AND a.gen IN {} AND m.spam_trash = 0) \
             WHERE role = {ROLE_FROM} OR is_sent GROUP BY addr",
            marks(chunk.len()),
            marks(t.len())
        );
        let mut params: Vec<SqlValue> = chunk.iter().map(|a| SqlValue::Text(a.clone())).collect();
        params.extend(gens(t));
        let mut st = conn.prepare(&sql)?;
        let mut rows = st.query(params_from_iter(params))?;
        while let Some(r) = rows.next()? {
            let address: String = r.get(0)?;
            let (received, sent): (i64, i64) = (r.get(1)?, r.get(2)?);
            let (first, last): (i64, i64) = (r.get(3)?, r.get(4)?);
            let name = r.get::<_, Option<String>>(5)?.and_then(|n| n.get(20..).map(str::to_string));
            let accounts: Vec<String> = r
                .get::<_, Option<String>>(6)?
                .unwrap_or_default()
                .split(',')
                .filter_map(alias_of)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            out.insert(
                address.clone(),
                Contact {
                    address,
                    name,
                    received,
                    sent,
                    first_contact: util::rfc3339_ms(first),
                    last_contact: util::rfc3339_ms(last),
                    accounts,
                    last_ms: last,
                    score: score(sent, received, last, req.now_ms),
                },
            );
        }
    }
    let mut v: Vec<Contact> = out.into_values().collect();
    v.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.last_ms.cmp(&a.last_ms))
            .then(a.address.cmp(&b.address))
    });
    v.truncate(req.limit);
    Ok(ContactResult { contacts: v, truncated })
}

// ------------------------------------------------------------------ digest

/// A validated digest request. Cursors store it, so a resumed page runs the same query.
#[derive(Debug, Clone, Serialize)]
pub struct DigestReq {
    pub accounts: Option<Vec<String>>,
    pub since_ms: i64,
    pub folders: Vec<String>,
    pub category: Option<Category>,
    pub limit: usize,
}

impl DigestReq {
    pub fn approx_bytes(&self) -> usize {
        serde_json::to_vec(self).map(|v| v.len()).unwrap_or(2048)
    }
}

/// Last thread of the previous page: the keyset of `(newest DESC, account_id, thread_id)`.
pub type DigestKey = (i64, String, String);

#[derive(Debug, Clone, Serialize)]
pub struct ThreadRow {
    pub account_id: String,
    pub thread_id: String,
    pub subject: Option<String>,
    pub participants: Vec<String>,
    /// Messages of the thread in the window that match the folders and category.
    pub count: i64,
    pub newest_received_at: String,
    pub unread: bool,
    pub category: Option<String>,
    pub snippet: Option<String>,
    /// Message id of the newest matching message.
    pub message_id: String,
    #[serde(skip)]
    pub newest_ms: i64,
}

/// The filter shared by the thread query and the per-thread detail query: window, folders, category.
fn filter(sql: &mut String, params: &mut Vec<SqlValue>, req: &DigestReq, t: &[Target]) {
    sql.push_str(&format!(
        " AND m.spam_trash = 0 AND m.received_at >= ? AND EXISTS \
         (SELECT 1 FROM labels l WHERE l.msg = m.id AND l.gen = m.gen AND l.label IN {})",
        marks(req.folders.len()),
    ));
    params.push(SqlValue::Integer(req.since_ms));
    params.extend(req.folders.iter().map(|f| SqlValue::Text(f.clone())));
    if let Some(c) = req.category {
        sql.push_str(" AND IFNULL(m.category = ?, 0)");
        params.push(SqlValue::Text(c.as_str().to_string()));
    }
}

/// The thread page query (before details): newest-first threads after `after`, `limit + 1` of them.
pub fn thread_sql(req: &DigestReq, t: &[Target], after: Option<&DigestKey>) -> (String, Vec<SqlValue>) {
    let mut sql = format!(
        "SELECT m.account_id, m.thread_id, max(m.received_at) AS newest, count(*), max(m.is_unread) \
         FROM messages m WHERE m.gen IN {}",
        marks(t.len())
    );
    let mut params = gens(t);
    filter(&mut sql, &mut params, req, t);
    sql.push_str(" GROUP BY m.account_id, m.thread_id");
    if let Some((newest, acc, thread)) = after {
        sql.push_str(
            " HAVING newest < ? OR (newest = ? AND (m.account_id > ? OR (m.account_id = ? AND m.thread_id > ?)))",
        );
        params.extend([
            SqlValue::Integer(*newest),
            SqlValue::Integer(*newest),
            SqlValue::Text(acc.clone()),
            SqlValue::Text(acc.clone()),
            SqlValue::Text(thread.clone()),
        ]);
    }
    sql.push_str(" ORDER BY newest DESC, m.account_id ASC, m.thread_id ASC LIMIT ?");
    params.push(SqlValue::Integer(req.limit as i64 + 1));
    (sql, params)
}

/// `EXPLAIN QUERY PLAN` of the thread page query.
pub fn explain_threads(conn: &Connection, req: &DigestReq, t: &[Target]) -> anyhow::Result<Vec<String>> {
    let (sql, params) = thread_sql(req, t, None);
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
    let rows = st.query_map(params_from_iter(params), |r| r.get::<_, String>(3))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// One cleaned, single-line, bounded snippet.
pub fn clean_snippet(s: &str) -> String {
    let flat = content::clean_text(s).split_whitespace().collect::<Vec<_>>().join(" ");
    content::truncate_chars(&flat, SNIPPET_CHARS).0
}

/// A page of threads and whether another page follows.
pub fn digest_page(
    conn: &Connection,
    req: &DigestReq,
    t: &[Target],
    after: Option<&DigestKey>,
) -> anyhow::Result<(Vec<ThreadRow>, bool)> {
    if t.is_empty() {
        return Ok((vec![], false));
    }
    let (sql, params) = thread_sql(req, t, after);
    let mut st = conn.prepare(&sql)?;
    let heads: Vec<(String, String, i64, i64, i64)> = st
        .query_map(params_from_iter(params), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
        .collect::<Result<_, _>>()?;
    let more = heads.len() > req.limit;
    let mut out = Vec::with_capacity(heads.len().min(req.limit));
    for (account_id, thread_id, newest, count, unread) in heads.into_iter().take(req.limit) {
        let Some(gen_id) = t.iter().find(|x| x.account_id == account_id).map(|x| x.gen_id) else { continue };
        let one = [t.iter().find(|x| x.gen_id == gen_id).expect("present").clone()];
        let mut dsql = String::from(
            "SELECT m.gmail_id, m.subject, m.from_list, m.snippet, m.category FROM messages m \
             WHERE m.gen = ? AND m.thread_id = ?",
        );
        let mut dparams = vec![SqlValue::Integer(gen_id), SqlValue::Text(thread_id.clone())];
        filter(&mut dsql, &mut dparams, req, &one);
        dsql.push_str(&format!(" ORDER BY m.received_at DESC, m.gmail_id DESC LIMIT {PARTICIPANT_MESSAGES}"));
        let mut dst = conn.prepare_cached(&dsql)?;
        let mut rows = dst.query(params_from_iter(dparams))?;
        let (mut message_id, mut subject, mut snippet, mut category) = (String::new(), None, None, None);
        let mut participants: Vec<String> = vec![];
        let mut first = true;
        while let Some(r) = rows.next()? {
            if first {
                message_id = r.get(0)?;
                subject = r.get::<_, Option<String>>(1)?.map(|s| clean_snippet(&s)).filter(|s| !s.is_empty());
                snippet = r.get::<_, Option<String>>(3)?.map(|s| clean_snippet(&s)).filter(|s| !s.is_empty());
                category = r.get(4)?;
                first = false;
            }
            let from: Vec<String> = serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or_default();
            if let Some(f) = from.first() {
                let f = clean_snippet(f);
                if !f.is_empty() && !participants.contains(&f) && participants.len() < MAX_PARTICIPANTS {
                    participants.push(f);
                }
            }
        }
        if first {
            // The thread changed between the two statements (same read transaction: cannot happen); skip defensively.
            continue;
        }
        out.push(ThreadRow {
            account_id,
            thread_id,
            subject,
            participants,
            count,
            newest_received_at: util::rfc3339_ms(newest),
            unread: unread != 0,
            category,
            snippet,
            message_id,
            newest_ms: newest,
        });
    }
    Ok((out, more))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_patterns_escape_wildcards() {
        assert_eq!(like_contains("anna_b"), "%anna\\_b%");
        assert_eq!(like_contains("50%\\"), "%50\\%\\\\%");
    }

    #[test]
    fn score_prefers_recent_and_sent() {
        let now = 1_000 * 86_400_000;
        let day = 86_400_000;
        // One message yesterday outranks fifty messages a year ago.
        assert!(score(0, 1, now - day, now) > score(0, 50, now - 365 * day, now));
        // Mail sent to someone counts more than mail received from them.
        assert!(score(1, 0, now, now) > score(0, 1, now, now));
        // Frequency still matters at equal recency.
        assert!(score(0, 10, now - day, now) > score(0, 2, now - day, now));
        // Future timestamps do not blow up the decay.
        assert!(score(0, 1, now + day, now).is_finite());
    }
}
