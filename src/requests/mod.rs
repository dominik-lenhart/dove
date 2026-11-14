//! Agent requests (design 2026-11-14 section 4, PLAN A71, A73). Stage 1: scheduled send of a client's own drafts.
//! Stage 2: access requests and temporary grants ([`access`]).
//!
//! An agent asks with `request_send`; the operator approves with `dove requests approve` (admin socket only); the
//! worker ([`worker::tick`]) sends exactly the approved revision of each approved item at its time, or not at all.
//!
//! Request status: `pending` → `approved` | `denied` | `cancelled` | `expired`; an approved request ends as `done` once
//! no item is `pending`, `scheduled` or `sending` ([`close_if_finished`]).
//!
//! Item state: `pending` (awaiting the decision) → `scheduled` (approved) → `sending` (claimed by the worker, before
//! the upstream write) → `sent` | `failed` | `send_unknown`; or `skipped`, `missed`, `cancelled`, `denied`. `sending`
//! after a restart and every unknown outcome end as `send_unknown`, which is never retried.
//!
//! Nothing here carries mail content. The agent's note is sealed with the vault ([`NOTE_KIND`]) and shown to the
//! operator only; audit records carry ids and result codes.

pub mod access;
pub mod admin;
pub mod worker;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;

use crate::audit::{self, AuditRecord};
use crate::config::Config;
use crate::util;

/// Vault kind of a sealed request note (scope = request id).
pub const NOTE_KIND: &str = "request_note";
/// Longest note an agent may attach, in characters.
pub const MAX_NOTE_CHARS: usize = 500;
/// Latest `send_at`, from the time of the request.
pub const MAX_AHEAD_SECS: i64 = 30 * 86_400;
/// Item states that may still lead to a send.
pub const OPEN_ITEM_STATES: &str = "('pending', 'scheduled', 'sending')";
/// Request statuses that count as open (limit per client, one open request per draft).
pub const OPEN_STATUSES: &str = "('pending', 'approved')";
/// Agent-visible request statuses (`list_requests` filter).
pub const STATUSES: &[&str] = &["pending", "approved", "denied", "cancelled", "expired", "done"];
/// Audit actor of the worker and of automatic cascades.
pub const SCHEDULER: &str = "scheduler";
/// Closed requests one client keeps at most; beyond it the oldest are deleted ([`prune_closed`]).
pub const MAX_CLOSED_PER_CLIENT: i64 = 500;
/// Requests deleted per [`prune_closed`] call, so one pass never holds the store long.
const PRUNE_BATCH: i64 = 1000;
/// When a closed request closed: its decision, or the last change of an item (an approved request becomes `done`
/// when its last item ends).
const CLOSED_AT: &str = "max(coalesce(r.decided_at, r.created_at), \
     coalesce((SELECT max(i.updated_at) FROM request_items i WHERE i.request_id = r.id), 0))";

/// One draft of a new send request.
#[derive(Debug, Clone)]
pub struct NewItem {
    pub draft_id: String,
    pub requested_rev: String,
    pub send_at: i64,
    pub thread_id: Option<String>,
    pub baseline_ms: Option<i64>,
    pub baseline_ids: Option<Vec<String>>,
}

/// A new send request. `id` is chosen by the caller, since the note is sealed with the request id as its scope.
#[derive(Debug, Clone)]
pub struct NewSend {
    pub id: String,
    pub client_id: String,
    pub project_id: String,
    pub account_id: String,
    pub unless_reply: bool,
    pub note_sealed: Option<Vec<u8>>,
    pub items: Vec<NewItem>,
}

#[derive(Debug)]
pub enum CreateError {
    /// The client already has `limits.client_open_requests` open requests.
    TooManyOpen,
    /// The draft of this item index is already in an open item (of this or another open request), or twice in this one.
    DraftAlreadyRequested(usize),
    Store(anyhow::Error),
}

impl From<rusqlite::Error> for CreateError {
    fn from(e: rusqlite::Error) -> Self {
        CreateError::Store(e.into())
    }
}

/// Request ids are `r_` + a random URL-safe id.
pub fn new_request_id() -> String {
    format!("r_{}", util::new_id())
}

/// Whether `s` has the shape of a request id (anything else is `not_found` without a lookup).
pub fn valid_request_id(s: &str) -> bool {
    s.strip_prefix("r_").is_some_and(|r| {
        (1..=64).contains(&r.len()) && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Records a new `pending` send request with its items. Refuses when the client has too many open requests or a
/// draft already sits in an open item, so no draft can be scheduled twice.
pub fn create_send(tx: &Transaction, cfg: &Config, new: NewSend, now: i64) -> Result<String, CreateError> {
    let open: i64 = tx.query_row(
        &format!("SELECT count(*) FROM requests WHERE client_id = ?1 AND status IN {OPEN_STATUSES}"),
        [&new.client_id],
        |r| r.get(0),
    )?;
    if open >= i64::from(cfg.limits.client_open_requests) {
        return Err(CreateError::TooManyOpen);
    }
    for (i, item) in new.items.iter().enumerate() {
        if new.items[..i].iter().any(|o| o.draft_id == item.draft_id) {
            return Err(CreateError::DraftAlreadyRequested(i));
        }
        // Any client of any project: a draft id is per mailbox, and one open item per draft is the rule.
        let taken: bool = tx.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM request_items i JOIN requests r ON r.id = i.request_id \
                 WHERE r.account_id = ?1 AND i.draft_id = ?2 AND r.status IN {OPEN_STATUSES} \
                 AND i.state IN {OPEN_ITEM_STATES})"
            ),
            params![new.account_id, item.draft_id],
            |r| r.get(0),
        )?;
        if taken {
            return Err(CreateError::DraftAlreadyRequested(i));
        }
    }
    let expires_at = now + cfg.requests.pending_days * 86_400;
    tx.execute(
        "INSERT INTO requests(id, client_id, project_id, account_id, kind, status, unless_reply, note_sealed, \
         created_at, expires_at) VALUES (?1, ?2, ?3, ?4, 'send', 'pending', ?5, ?6, ?7, ?8)",
        params![
            new.id,
            new.client_id,
            new.project_id,
            new.account_id,
            new.unless_reply,
            new.note_sealed,
            now,
            expires_at
        ],
    )?;
    for (i, item) in new.items.iter().enumerate() {
        let ids = item.baseline_ids.as_ref().map(|v| serde_json::json!(v).to_string());
        tx.execute(
            "INSERT INTO request_items(request_id, idx, draft_id, requested_rev, send_at, state, thread_id, \
             baseline_ms, baseline_ids, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?8, ?9)",
            params![
                new.id,
                i as i64,
                item.draft_id,
                item.requested_rev,
                item.send_at,
                item.thread_id,
                item.baseline_ms,
                ids,
                now
            ],
        )?;
    }
    Ok(new.id)
}

/// `n` times spread evenly over `[from, to]` (both ends included), in input order. One item gets `from`.
pub fn spread(from: i64, to: i64, n: usize) -> Vec<i64> {
    match n {
        0 => vec![],
        1 => vec![from],
        _ => {
            let span = i128::from(to - from);
            (0..n).map(|i| from + (span * i as i128 / (n as i128 - 1)) as i64).collect()
        }
    }
}

/// One item as agents and the operator see it.
#[derive(Debug, Clone, Serialize)]
pub struct ItemView {
    pub idx: u32,
    pub draft_id: String,
    pub send_at: String,
    pub state: String,
    pub reason: Option<String>,
    pub sent_message_id: Option<String>,
}

/// One request as its client sees it (`list_requests`). Never carries the note: it is write-only for the agent.
#[derive(Debug, Clone, Serialize)]
pub struct RequestView {
    pub request_id: String,
    pub kind: String,
    pub status: String,
    pub account: Option<String>,
    pub unless_reply: bool,
    pub created_at: String,
    pub expires_at: String,
    pub decided_at: Option<String>,
    pub items: Vec<ItemView>,
    /// Kind `access`: the asked grants, their state and the expiry of approved temporary grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<access::AccessView>,
}

pub fn load_items(c: &Connection, request_id: &str) -> anyhow::Result<Vec<ItemView>> {
    let mut st = c.prepare_cached(
        "SELECT idx, draft_id, send_at, state, reason, sent_message_id FROM request_items WHERE request_id = ?1 \
         ORDER BY idx",
    )?;
    let rows = st.query_map([request_id], |r| {
        Ok(ItemView {
            idx: r.get(0)?,
            draft_id: r.get(1)?,
            send_at: util::rfc3339(r.get(2)?),
            state: r.get(3)?,
            reason: r.get(4)?,
            sent_message_id: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

const VIEW_COLS: &str =
    "r.id, r.kind, r.status, a.alias, r.unless_reply, r.created_at, r.expires_at, r.decided_at, r.payload";

fn view_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RequestView> {
    Ok(RequestView {
        request_id: r.get(0)?,
        kind: r.get(1)?,
        status: r.get(2)?,
        account: r.get(3)?,
        unless_reply: r.get(4)?,
        created_at: util::rfc3339(r.get(5)?),
        expires_at: util::rfc3339(r.get(6)?),
        decided_at: r.get::<_, Option<i64>>(7)?.map(util::rfc3339),
        items: vec![],
        access: None,
    })
}

/// Fills in what is not in the request row: items (send) or the access view (access).
fn complete(c: &Connection, v: &mut RequestView, payload: &str) -> anyhow::Result<()> {
    v.items = load_items(c, &v.request_id)?;
    if v.kind == "access" {
        v.access = Some(access::view(c, &v.request_id, &v.status, payload, util::now_unix())?);
    }
    Ok(())
}

/// The client's own requests, newest first (at most 200), optionally with one status.
pub fn list_for_client(c: &Connection, client_id: &str, status: Option<&str>) -> anyhow::Result<Vec<RequestView>> {
    let mut st = c.prepare(&format!(
        "SELECT {VIEW_COLS} FROM requests r LEFT JOIN accounts a ON a.id = r.account_id \
         WHERE r.client_id = ?1 AND (?2 IS NULL OR r.status = ?2) ORDER BY r.created_at DESC, r.id LIMIT 200"
    ))?;
    let rows: Vec<(RequestView, String)> =
        st.query_map(params![client_id, status], |r| Ok((view_from_row(r)?, r.get(8)?)))?.collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for (mut v, payload) in rows {
        complete(c, &mut v, &payload)?;
        out.push(v);
    }
    Ok(out)
}

/// One request of `client_id`, or None (unknown and foreign ids alike).
pub fn view_for_client(c: &Connection, client_id: &str, id: &str) -> anyhow::Result<Option<RequestView>> {
    let v = c
        .query_row(
            &format!(
                "SELECT {VIEW_COLS} FROM requests r LEFT JOIN accounts a ON a.id = r.account_id \
                 WHERE r.client_id = ?1 AND r.id = ?2"
            ),
            params![client_id, id],
            |r| Ok((view_from_row(r)?, r.get::<_, String>(8)?)),
        )
        .optional()?;
    match v {
        Some((mut v, payload)) => {
            complete(c, &mut v, &payload)?;
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

/// Cancels a request of this client: a pending one entirely, an approved one's unsent (`pending`, `scheduled`)
/// items. Returns false for unknown ids and ids of other clients, and changes nothing then.
pub fn cancel_by_client(tx: &Transaction, client_id: &str, id: &str, now: i64) -> anyhow::Result<bool> {
    let status: Option<String> = tx
        .query_row("SELECT status FROM requests WHERE id = ?1 AND client_id = ?2", params![id, client_id], |r| r.get(0))
        .optional()?;
    let Some(status) = status else { return Ok(false) };
    cancel_one(tx, id, &status, "cancelled_by_client", now)?;
    Ok(true)
}

/// Cancels one request in `status`: pending → `cancelled` with all items; approved → its unsent items and its
/// temporary grants (an access request; the agent may give rights back early). Items carry `reason`. Returns whether
/// anything changed.
pub(crate) fn cancel_one(tx: &Transaction, id: &str, status: &str, reason: &str, now: i64) -> anyhow::Result<bool> {
    let n = match status {
        "pending" => {
            tx.execute(
                "UPDATE requests SET status = 'cancelled', decided_at = ?1 WHERE id = ?2 AND status = 'pending'",
                params![now, id],
            )?;
            tx.execute(
                "UPDATE request_items SET state = 'cancelled', reason = ?1, updated_at = ?2 \
                 WHERE request_id = ?3 AND state = 'pending'",
                params![reason, now, id],
            )? + 1
        }
        "approved" => {
            tx.execute(
                "UPDATE request_items SET state = 'cancelled', reason = ?1, updated_at = ?2 \
                 WHERE request_id = ?3 AND state IN ('pending', 'scheduled')",
                params![reason, now, id],
            )? + access::drop_extras(tx, access::Scope::Request(id))?
        }
        _ => 0,
    };
    close_if_finished(tx, id)?;
    Ok(n > 0)
}

/// An approved request is `done` once no item can still lead to a send and no temporary grant of it is left.
pub fn close_if_finished(tx: &Connection, request_id: &str) -> anyhow::Result<()> {
    tx.execute(
        &format!(
            "UPDATE requests SET status = 'done' WHERE id = ?1 AND status = 'approved' \
             AND NOT EXISTS (SELECT 1 FROM request_items WHERE request_id = ?1 AND state IN {OPEN_ITEM_STATES}) \
             AND NOT EXISTS (SELECT 1 FROM client_grant_extras WHERE request_id = ?1)"
        ),
        [request_id],
    )?;
    Ok(())
}

/// Cancels open requests matching `filter` (a column of `requests`) for a cascade, with one audit record each.
fn cancel_where(tx: &Transaction, column: &str, value: &str, reason: &str, now: i64) -> anyhow::Result<usize> {
    let rows: Vec<(String, String, Option<String>)> = {
        let mut st = tx.prepare(&format!(
            "SELECT r.id, r.status, p.name FROM requests r LEFT JOIN projects p ON p.id = r.project_id \
             WHERE r.{column} = ?1 AND r.status IN {OPEN_STATUSES}"
        ))?;
        st.query_map([value], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?
    };
    let mut n = 0;
    for (id, status, project) in rows {
        if cancel_one(tx, &id, &status, reason, now)? {
            audit_event(tx, SCHEDULER, "request.cancel", project, None, vec![id], reason)?;
            n += 1;
        }
    }
    Ok(n)
}

/// On revoke: the client's pending requests and its not-yet-sent items are cancelled.
pub fn cancel_for_client(tx: &Transaction, client_id: &str, now: i64) -> anyhow::Result<usize> {
    cancel_where(tx, "client_id", client_id, "client_revoked", now)
}

/// On removing a mailbox: the requests that name it are cancelled like on revoke; access requests that name it are
/// cancelled (pending) or lose their temporary grant on it (approved).
pub fn cancel_for_account(tx: &Transaction, account_id: &str, now: i64) -> anyhow::Result<usize> {
    Ok(cancel_where(tx, "account_id", account_id, "account_removed", now)?
        + access::cancel_naming_account(tx, account_id, None, "account_removed", now)?)
}

/// On disabling a mailbox: as [`cancel_for_account`], with the reason `account_disabled`.
pub fn cancel_for_disabled_account(tx: &Transaction, account_id: &str, now: i64) -> anyhow::Result<usize> {
    cancel_where(tx, "account_id", account_id, "account_disabled", now)
}

/// Deletes closed requests (denied, cancelled, expired, done) with their items and notes: those closed more than
/// `retention_secs` before `now`, and each client's oldest beyond [`MAX_CLOSED_PER_CLIENT`]. At most
/// [`PRUNE_BATCH`] per call; returns how many went. Audit records stay (they hold ids only).
pub fn prune_closed(tx: &Transaction, now: i64, retention_secs: i64) -> anyhow::Result<usize> {
    let closed = "('denied', 'cancelled', 'expired', 'done')";
    let old = tx.execute(
        &format!(
            "DELETE FROM requests WHERE id IN (SELECT r.id FROM requests r WHERE r.status IN {closed} \
             AND {CLOSED_AT} < ?1 LIMIT {PRUNE_BATCH})"
        ),
        [now - retention_secs],
    )?;
    let over = tx.execute(
        &format!(
            "DELETE FROM requests WHERE id IN (SELECT id FROM (SELECT r.id, row_number() OVER \
             (PARTITION BY r.client_id ORDER BY {CLOSED_AT} DESC, r.created_at DESC, r.id DESC) AS n \
             FROM requests r WHERE r.status IN {closed}) WHERE n > ?1 LIMIT {PRUNE_BATCH})"
        ),
        [MAX_CLOSED_PER_CLIENT],
    )?;
    Ok(old + over)
}

/// Writes one audit record for a request event (ids and a result code only).
pub fn audit_event(
    c: &Connection,
    actor: &str,
    action: &str,
    project: Option<String>,
    account: Option<String>,
    object_ids: Vec<String>,
    code: &str,
) -> anyhow::Result<()> {
    let rec = AuditRecord {
        request_id: util::new_id(),
        actor: actor.to_string(),
        project,
        tool_or_action: action.to_string(),
        account_alias: account,
        object_ids,
        result_code: code.to_string(),
        ..Default::default()
    };
    audit::append(c, &rec)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn cfg() -> Config {
        let dir = tempfile::tempdir().unwrap();
        crate::testing::test_config(dir.path(), 1000)
    }

    /// A store with project `p`, clients `c1` and `c2` of it and account `a`.
    fn store() -> Store {
        let s = Store::open_in_memory().unwrap();
        s.call_blocking(|c| {
            c.execute_batch(
                "INSERT INTO projects(id, name, created_at) VALUES ('p', 'p', 0);
                 INSERT INTO clients(id, name, project_id, kind, created_at, created_via) VALUES
                   ('c1', 'c1', 'p', 'token', 0, 'cli'), ('c2', 'c2', 'p', 'token', 0, 'cli');
                 INSERT INTO accounts(id, alias, email, status) VALUES ('a', 'a', 'a@example.com', 'active');",
            )?;
            Ok(())
        })
        .unwrap();
        s
    }

    fn item(d: &str) -> NewItem {
        NewItem {
            draft_id: d.into(),
            requested_rev: format!("rev-{d}"),
            send_at: 1000,
            thread_id: None,
            baseline_ms: None,
            baseline_ids: None,
        }
    }

    fn send(client: &str, drafts: &[&str]) -> NewSend {
        NewSend {
            id: new_request_id(),
            client_id: client.into(),
            project_id: "p".into(),
            account_id: "a".into(),
            unless_reply: false,
            note_sealed: None,
            items: drafts.iter().map(|d| item(d)).collect(),
        }
    }

    fn create(s: &Store, cfg: &Config, new: NewSend) -> Result<String, CreateError> {
        s.call_blocking(|c| {
            let tx = c.transaction()?;
            let r = create_send(&tx, cfg, new, 10);
            tx.commit()?;
            Ok(r)
        })
        .unwrap()
    }

    fn exec(s: &Store, sql: &str) {
        let sql = sql.to_string();
        s.call_blocking(move |c| Ok(c.execute_batch(&sql)?)).unwrap();
    }

    fn status(s: &Store, id: &str) -> String {
        let id = id.to_string();
        s.call_blocking(move |c| Ok(c.query_row("SELECT status FROM requests WHERE id = ?1", [id], |r| r.get(0))?))
            .unwrap()
    }

    fn count(s: &Store, sql: &str) -> i64 {
        let sql = sql.to_string();
        s.call_blocking(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn prune(s: &Store, now: i64, retention: i64) -> usize {
        s.call_blocking(move |c| {
            let tx = c.transaction()?;
            let n = prune_closed(&tx, now, retention)?;
            tx.commit()?;
            Ok(n)
        })
        .unwrap()
    }

    #[test]
    fn closed_requests_are_pruned_by_age_and_per_client_cap() {
        let s = store();
        let day = 86_400;
        let now = 1000 * day;
        // c1, retention 90 days: closed 91 days ago (gone), 89 days ago (kept); a request created long ago that
        // closed recently (its last item changed 10 days ago: kept); old open requests are never touched.
        exec(
            &s,
            &format!(
                "INSERT INTO requests(id, client_id, project_id, account_id, kind, status, created_at, expires_at, decided_at) VALUES
                   ('old', 'c1', 'p', 'a', 'send', 'denied', 0, 0, {d91}),
                   ('recent', 'c1', 'p', 'a', 'send', 'cancelled', 0, 0, {d89}),
                   ('done', 'c1', 'p', 'a', 'send', 'done', 0, 0, {d100}),
                   ('expired', 'c1', 'p', 'a', 'send', 'expired', {d100}, 0, NULL),
                   ('pending', 'c1', 'p', 'a', 'send', 'pending', 0, 0, NULL),
                   ('approved', 'c1', 'p', 'a', 'send', 'approved', 0, 0, {d100});
                 INSERT INTO request_items(request_id, idx, draft_id, requested_rev, send_at, state, updated_at) VALUES
                   ('old', 0, 'd', 'r', 0, 'denied', {d91}),
                   ('done', 0, 'd', 'r', 0, 'sent', {d10}),
                   ('approved', 0, 'd', 'r', 0, 'scheduled', 0);",
                d91 = now - 91 * day,
                d89 = now - 89 * day,
                d100 = now - 100 * day,
                d10 = now - 10 * day,
            ),
        );
        assert_eq!(prune(&s, now, 90 * day), 2);
        let left = |s: &Store| {
            s.call_blocking(|c| {
                let mut st = c.prepare("SELECT id FROM requests WHERE client_id = 'c1' ORDER BY id")?;
                Ok(st.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap()
        };
        assert_eq!(left(&s), vec!["approved", "done", "pending", "recent"]);
        assert_eq!(count(&s, "SELECT count(*) FROM request_items WHERE request_id = 'old'"), 0, "items go too");
        // c2: 502 closed requests, the first two oldest. The cap keeps the newest 500 of c2 and leaves c1 alone.
        let values: Vec<String> = (0..502)
            .map(|i| format!("('c2-{i:03}', 'c2', 'p', 'a', 'send', 'done', 0, 0, {})", now - 1000 + i))
            .collect();
        exec(
            &s,
            &format!(
                "INSERT INTO requests(id, client_id, project_id, account_id, kind, status, created_at, expires_at, decided_at) VALUES {};",
                values.join(",")
            ),
        );
        // An open request of c2 does not count towards the cap.
        exec(
            &s,
            "INSERT INTO requests(id, client_id, project_id, account_id, kind, status, created_at, expires_at) \
             VALUES ('c2-open', 'c2', 'p', 'a', 'send', 'pending', 0, 0)",
        );
        assert_eq!(prune(&s, now, 90 * day), 2);
        assert_eq!(count(&s, "SELECT count(*) FROM requests WHERE client_id = 'c2' AND status = 'done'"), 500);
        assert_eq!(count(&s, "SELECT count(*) FROM requests WHERE id IN ('c2-000', 'c2-001')"), 0, "oldest first");
        assert_eq!(count(&s, "SELECT count(*) FROM requests WHERE id = 'c2-open'"), 1);
        assert_eq!(left(&s).len(), 4);
        assert_eq!(prune(&s, now, 90 * day), 0);
    }

    #[test]
    fn spread_includes_both_ends() {
        assert_eq!(spread(100, 200, 1), vec![100]);
        assert_eq!(spread(100, 200, 2), vec![100, 200]);
        let twenty = spread(0, 19 * 60, 20);
        assert_eq!(twenty.len(), 20);
        assert_eq!(twenty, (0..20).map(|i| i * 60).collect::<Vec<_>>());
        assert_eq!(spread(9 * 3600, 17 * 3600, 5), vec![9 * 3600, 11 * 3600, 13 * 3600, 15 * 3600, 17 * 3600]);
    }

    #[test]
    fn open_request_limit_and_one_open_item_per_draft() {
        let s = store();
        let mut cfg = cfg();
        cfg.limits.client_open_requests = 20;
        for i in 0..20 {
            create(&s, &cfg, send("c1", &[&format!("d{i}")])).unwrap();
        }
        assert!(matches!(create(&s, &cfg, send("c1", &["x"])), Err(CreateError::TooManyOpen)));
        // Another client is counted on its own.
        create(&s, &cfg, send("c2", &["y"])).unwrap();
        // A draft in another open request (even another client's), or twice in this one, is refused.
        assert!(matches!(create(&s, &cfg, send("c2", &["z", "d3"])), Err(CreateError::DraftAlreadyRequested(1))));
        assert!(matches!(create(&s, &cfg, send("c2", &["z", "w", "z"])), Err(CreateError::DraftAlreadyRequested(2))));
        // Finished items and closed requests free the draft again.
        exec(&s, "UPDATE requests SET status = 'denied' WHERE client_id = 'c1'");
        exec(&s, "UPDATE request_items SET state = 'denied'");
        create(&s, &cfg, send("c1", &["d3"])).unwrap();
        let approved = create(&s, &cfg, send("c2", &["v"])).unwrap();
        exec(&s, &format!("UPDATE requests SET status = 'approved' WHERE id = '{approved}'"));
        exec(&s, &format!("UPDATE request_items SET state = 'sent' WHERE request_id = '{approved}'"));
        create(&s, &cfg, send("c1", &["v"])).unwrap();
    }

    #[test]
    fn cancel_by_client_only_touches_own_requests() {
        let s = store();
        let cfg = cfg();
        let id = create(&s, &cfg, send("c1", &["d1", "d2"])).unwrap();
        let id2 = id.clone();
        let foreign = s
            .call_blocking(move |c| {
                let tx = c.transaction()?;
                let r = cancel_by_client(&tx, "c2", &id2, 20)?;
                tx.commit()?;
                Ok(r)
            })
            .unwrap();
        assert!(!foreign);
        assert_eq!(status(&s, &id), "pending");
        let id2 = id.clone();
        let own = s
            .call_blocking(move |c| {
                let tx = c.transaction()?;
                let r = cancel_by_client(&tx, "c1", &id2, 20)?;
                tx.commit()?;
                Ok(r)
            })
            .unwrap();
        assert!(own);
        assert_eq!(status(&s, &id), "cancelled");
        let items = s.call_blocking(move |c| load_items(c, &id)).unwrap();
        assert!(items.iter().all(|i| i.state == "cancelled"), "{items:?}");
    }

    #[test]
    fn close_if_finished_waits_for_open_items() {
        let s = store();
        let cfg = cfg();
        let id = create(&s, &cfg, send("c1", &["d1", "d2"])).unwrap();
        let close = |s: &Store, id: &str| {
            let id = id.to_string();
            s.call_blocking(move |c| {
                let tx = c.transaction()?;
                close_if_finished(&tx, &id)?;
                tx.commit()?;
                Ok(())
            })
            .unwrap()
        };
        // Pending requests are never closed this way.
        exec(&s, &format!("UPDATE request_items SET state = 'sent' WHERE request_id = '{id}'"));
        close(&s, &id);
        assert_eq!(status(&s, &id), "pending");
        exec(&s, &format!("UPDATE requests SET status = 'approved' WHERE id = '{id}'"));
        for open in ["pending", "scheduled", "sending"] {
            exec(&s, &format!("UPDATE request_items SET state = '{open}' WHERE request_id = '{id}' AND idx = 1"));
            close(&s, &id);
            assert_eq!(status(&s, &id), "approved", "{open}");
        }
        exec(&s, &format!("UPDATE request_items SET state = 'failed' WHERE request_id = '{id}' AND idx = 1"));
        close(&s, &id);
        assert_eq!(status(&s, &id), "done");
    }

    #[test]
    fn cascades_cancel_unsent_items_and_audit() {
        let s = store();
        let cfg = cfg();
        let pending = create(&s, &cfg, send("c1", &["d1"])).unwrap();
        let approved = create(&s, &cfg, send("c1", &["d2", "d3"])).unwrap();
        exec(&s, &format!("UPDATE requests SET status = 'approved' WHERE id = '{approved}'"));
        exec(&s, &format!("UPDATE request_items SET state = 'scheduled' WHERE request_id = '{approved}' AND idx = 0"));
        exec(&s, &format!("UPDATE request_items SET state = 'sending' WHERE request_id = '{approved}' AND idx = 1"));
        let other = create(&s, &cfg, send("c2", &["d4"])).unwrap();
        let n = s
            .call_blocking(|c| {
                let tx = c.transaction()?;
                let n = cancel_for_client(&tx, "c1", 30)?;
                tx.commit()?;
                Ok(n)
            })
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(status(&s, &pending), "cancelled");
        // The in-flight item is not touched (its outcome is recorded by the worker); the request stays approved.
        assert_eq!(status(&s, &approved), "approved");
        let a2 = approved.clone();
        let items = s.call_blocking(move |c| load_items(c, &a2)).unwrap();
        assert_eq!(
            items.iter().map(|i| (i.state.as_str(), i.reason.as_deref())).collect::<Vec<_>>(),
            vec![("cancelled", Some("client_revoked")), ("sending", None)]
        );
        assert_eq!(status(&s, &other), "pending");
        let audits: i64 = s
            .call_blocking(|c| {
                Ok(c.query_row("SELECT count(*) FROM audit WHERE tool_or_action = 'request.cancel'", [], |r| r.get(0))?)
            })
            .unwrap();
        assert_eq!(audits, 2);
        let n = s
            .call_blocking(|c| {
                let tx = c.transaction()?;
                let n = cancel_for_account(&tx, "a", 30)?;
                tx.commit()?;
                Ok(n)
            })
            .unwrap();
        assert_eq!(n, 1, "only c2's pending request was still cancellable");
        assert_eq!(status(&s, &other), "cancelled");
    }
}
