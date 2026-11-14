//! Admin verbs for requests (`dove requests list|show|approve|deny|cancel`, design 2026-11-14 section 4.7).
//!
//! `show` reads each draft fresh through the `get_draft` code path, as the requesting client, and returns its content
//! to the admin socket only (the audit record holds the request id). `approve` binds the approval to the revisions the
//! operator was shown: if any chosen draft changed in between, nothing is approved.

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use anyhow::{anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use super::{NOTE_KIND, close_if_finished};
use crate::admin::server::AdminCall;
use crate::admin::{Late, ShownItem};
use crate::tools::ToolCx;
use crate::util;

/// The operator's list: every client's requests, newest first (at most 500), without notes and draft content.
pub fn list(c: &Connection, status: Option<&str>) -> anyhow::Result<Value> {
    if let Some(s) = status
        && !super::STATUSES.contains(&s)
    {
        bail!("unknown status '{s}' (one of {})", super::STATUSES.join(", "));
    }
    let mut st = c.prepare(
        "SELECT r.id, r.kind, r.status, cl.name, p.name, a.alias, r.unless_reply, r.created_at, r.expires_at, \
         r.decided_at, r.decided_by, r.note_sealed IS NOT NULL \
         FROM requests r JOIN clients cl ON cl.id = r.client_id JOIN projects p ON p.id = r.project_id \
         LEFT JOIN accounts a ON a.id = r.account_id \
         WHERE (?1 IS NULL OR r.status = ?1) ORDER BY r.created_at DESC, r.id LIMIT 500",
    )?;
    let rows: Vec<Value> = st
        .query_map([status], |r| {
            Ok(json!({
                "request_id": r.get::<_, String>(0)?,
                "kind": r.get::<_, String>(1)?,
                "status": r.get::<_, String>(2)?,
                "client": r.get::<_, String>(3)?,
                "project": r.get::<_, String>(4)?,
                "account": r.get::<_, Option<String>>(5)?,
                "unless_reply": r.get::<_, bool>(6)?,
                "created_at": util::rfc3339(r.get(7)?),
                "expires_at": util::rfc3339(r.get(8)?),
                "decided_at": r.get::<_, Option<i64>>(9)?.map(util::rfc3339),
                "decided_by": r.get::<_, Option<String>>(10)?,
                "has_note": r.get::<_, bool>(11)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for mut v in rows {
        let items = super::load_items(c, v["request_id"].as_str().unwrap_or_default())?;
        v["items"] = json!(items);
        out.push(v);
    }
    Ok(json!(out))
}

/// One request as stored, for show and approve.
struct Stored {
    client_id: String,
    client: String,
    project: String,
    account_id: Option<String>,
    alias: Option<String>,
    kind: String,
    status: String,
    unless_reply: bool,
    note_sealed: Option<Vec<u8>>,
    created_at: i64,
    expires_at: i64,
    decided_at: Option<i64>,
    decided_by: Option<String>,
    items: Vec<StoredItem>,
}

struct StoredItem {
    idx: u32,
    draft_id: String,
    requested_rev: String,
    approved_rev: Option<String>,
    send_at: i64,
    state: String,
    reason: Option<String>,
    sent_message_id: Option<String>,
}

fn load(c: &Connection, id: &str) -> anyhow::Result<Stored> {
    let mut s = c
        .query_row(
            "SELECT r.client_id, cl.name, p.name, r.account_id, a.alias, r.kind, r.status, r.unless_reply, \
             r.note_sealed, r.created_at, r.expires_at, r.decided_at, r.decided_by \
             FROM requests r JOIN clients cl ON cl.id = r.client_id JOIN projects p ON p.id = r.project_id \
             LEFT JOIN accounts a ON a.id = r.account_id WHERE r.id = ?1",
            [id],
            |r| {
                Ok(Stored {
                    client_id: r.get(0)?,
                    client: r.get(1)?,
                    project: r.get(2)?,
                    account_id: r.get(3)?,
                    alias: r.get(4)?,
                    kind: r.get(5)?,
                    status: r.get(6)?,
                    unless_reply: r.get(7)?,
                    note_sealed: r.get(8)?,
                    created_at: r.get(9)?,
                    expires_at: r.get(10)?,
                    decided_at: r.get(11)?,
                    decided_by: r.get(12)?,
                    items: vec![],
                })
            },
        )
        .optional()?
        .ok_or_else(|| anyhow!("unknown request '{}'", id.chars().take(80).collect::<String>()))?;
    let mut st = c.prepare(
        "SELECT idx, draft_id, requested_rev, approved_rev, send_at, state, reason, sent_message_id \
         FROM request_items WHERE request_id = ?1 ORDER BY idx",
    )?;
    s.items = st
        .query_map([id], |r| {
            Ok(StoredItem {
                idx: r.get(0)?,
                draft_id: r.get(1)?,
                requested_rev: r.get(2)?,
                approved_rev: r.get(3)?,
                send_at: r.get(4)?,
                state: r.get(5)?,
                reason: r.get(6)?,
                sent_message_id: r.get(7)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(s)
}

/// A draft as read fresh for the operator.
struct Current {
    revision: String,
    /// The draft is still Dove's at this revision (`own_drafts` row of the project, `active`, same message id): only
    /// then can it be sent.
    sendable: bool,
    content: Value,
}

/// Reads each draft of `items` through the `get_draft` code path as the requesting client. Per draft: its current
/// state, or the error code that prevented reading it.
async fn read_drafts(
    call: &AdminCall<'_>,
    s: &Stored,
    items: &[&StoredItem],
) -> anyhow::Result<HashMap<u32, Result<Current, String>>> {
    let app = call.app.clone();
    let (cid, allow_send) = (s.client_id.clone(), app.cfg.allow_send);
    let account_id = s.account_id.clone().unwrap_or_default();
    let (ctx, own) = call
        .read(move |c| {
            let ctx = crate::policy::load_client(c, &cid, allow_send)?;
            let project = ctx.as_ref().map(|x| x.project_id.clone()).unwrap_or_default();
            let mut st = c.prepare(
                "SELECT draft_id, message_id, state FROM own_drafts WHERE account_id = ?1 AND project_id = ?2",
            )?;
            let own: HashMap<String, (String, String)> = st
                .query_map(params![account_id, project], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?
                .collect::<Result<_, _>>()?;
            Ok((ctx, own))
        })
        .await?;
    let mut out = HashMap::new();
    let Some(ctx) = ctx else {
        for it in items {
            out.insert(it.idx, Err("client_revoked".to_string()));
        }
        return Ok(out);
    };
    let alias = s.alias.clone().unwrap_or_default();
    let cx = ToolCx::new(app.clone(), ctx, call.actor.request_id.clone(), Instant::now());
    for it in items {
        let args =
            json!({ "account": alias, "draft_id": it.draft_id, "max_body_chars": crate::tools::read::MAX_BODY_CHARS });
        let r = match crate::tools::call(&cx, "get_draft", args).await {
            Ok(out) => {
                let v = out.structured;
                let revision = v["revision"].as_str().unwrap_or_default().to_string();
                let sendable = own
                    .get(&it.draft_id)
                    .is_some_and(|(mid, state)| *mid == revision && state == "active" && !revision.is_empty());
                let m = &v["message"];
                let attachments: Vec<Value> = m["attachments"]
                    .as_array()
                    .map(|a| {
                        a.iter().map(|x| json!({ "name": x["filename"], "size": x["size_bytes"] })).collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let content = json!({
                    "from": m["from"], "to": m["to"], "cc": m["cc"], "bcc": m["bcc"], "subject": m["subject"],
                    "body_text": m["body_text"], "body_truncated": m["body_truncated"], "attachments": attachments,
                });
                Ok(Current { revision, sendable, content })
            }
            Err(e) => Err(e.code.as_str().to_string()),
        };
        out.insert(it.idx, r);
    }
    Ok(out)
}

/// `dove requests show`: the request, its unsealed note and every item's draft as it is now.
pub async fn show(call: &mut AdminCall<'_>, id: String) -> anyhow::Result<Value> {
    let rid = id.clone();
    let s = call.read(move |c| load(c, &rid)).await?;
    let note = match &s.note_sealed {
        Some(b) => {
            let plain = call.app.vault.open_aux(NOTE_KIND, &id, b)?;
            Some(String::from_utf8_lossy(&plain).into_owned())
        }
        None => None,
    };
    // Content is read only for items that can still be approved or sent.
    let live: Vec<&StoredItem> =
        s.items.iter().filter(|i| matches!(i.state.as_str(), "pending" | "scheduled")).collect();
    let drafts = read_drafts(call, &s, &live).await?;
    let now = util::now_unix();
    let items: Vec<Value> = s
        .items
        .iter()
        .map(|it| {
            let mut v = json!({
                "idx": it.idx, "draft_id": it.draft_id, "send_at": util::rfc3339(it.send_at), "state": it.state,
                "reason": it.reason, "requested_revision": it.requested_rev, "approved_revision": it.approved_rev,
                "sent_message_id": it.sent_message_id,
                "late": it.state == "pending" && it.send_at <= now,
            });
            match drafts.get(&it.idx) {
                Some(Ok(cur)) => {
                    v["revision"] = json!(cur.revision);
                    v["changed_since_request"] = json!(cur.revision != it.requested_rev);
                    v["sendable"] = json!(cur.sendable);
                    if let (Some(o), Some(c)) = (v.as_object_mut(), cur.content.as_object()) {
                        o.extend(c.clone());
                    }
                }
                Some(Err(code)) => v["error"] = json!(code),
                None => {}
            }
            v
        })
        .collect();
    Ok(json!({
        "request_id": id, "kind": s.kind, "status": s.status, "client": s.client, "project": s.project,
        "account": s.alias, "unless_reply": s.unless_reply, "note": note,
        "created_at": util::rfc3339(s.created_at), "expires_at": util::rfc3339(s.expires_at),
        "decided_at": s.decided_at.map(util::rfc3339), "decided_by": s.decided_by, "items": items,
    }))
}

/// `dove requests approve`: approves the chosen pending items at the revisions in `shown`, or nothing.
pub async fn approve(
    call: &mut AdminCall<'_>,
    id: String,
    shown: Vec<ShownItem>,
    chosen: Option<Vec<u32>>,
    late: Late,
) -> anyhow::Result<Value> {
    let rid = id.clone();
    let s = call.read(move |c| load(c, &rid)).await?;
    if s.kind != "send" {
        bail!("only send requests can be approved in this version");
    }
    if s.status != "pending" {
        bail!("request {id} is {}, not pending", s.status);
    }
    let pending: Vec<&StoredItem> = s.items.iter().filter(|i| i.state == "pending").collect();
    let chosen: Vec<u32> = match chosen {
        Some(c) => {
            for i in &c {
                if !pending.iter().any(|p| p.idx == *i) {
                    bail!("item {i} is not a pending item of request {id}");
                }
            }
            let mut c = c;
            c.sort_unstable();
            c.dedup();
            c
        }
        None => pending.iter().map(|p| p.idx).collect(),
    };
    if chosen.is_empty() {
        bail!("no item chosen; to refuse the request use `dove requests deny`");
    }
    let shown: HashMap<u32, String> = shown.into_iter().map(|s| (s.idx, s.revision)).collect();
    for i in &chosen {
        if !shown.contains_key(i) {
            bail!("item {i} was not shown; run `dove requests show {id}` and approve what it printed");
        }
    }
    // Fresh read: the approval binds the revision the operator saw, and only drafts Dove may still send.
    let chosen_items: Vec<&StoredItem> = pending.iter().copied().filter(|p| chosen.contains(&p.idx)).collect();
    let current = read_drafts(call, &s, &chosen_items).await?;
    for i in &chosen {
        match current.get(i) {
            Some(Ok(cur)) if Some(&cur.revision) == shown.get(i) && cur.sendable => {}
            Some(Ok(cur)) if Some(&cur.revision) != shown.get(i) => {
                bail!(
                    "item {i}'s draft changed since it was shown; nothing was approved. Look at it again (`dove requests show {id}`)"
                );
            }
            Some(Ok(_)) => bail!("item {i}'s draft was changed outside Dove and cannot be sent; nothing was approved"),
            Some(Err(code)) => bail!("item {i}'s draft cannot be read ({code}); nothing was approved"),
            None => bail!("item {i} was not read; nothing was approved"),
        }
    }
    let now = util::now_unix();
    let cap = i64::from(call.app.cfg.limits.scheduled_sends_per_day);
    let decided_by = call.actor.name.clone();
    let account_id = s.account_id.clone().unwrap_or_default();
    call.tx(move |tx| {
        // The state may have moved while the drafts were read (cancel, expiry, an edit through Dove).
        let status: String = tx.query_row("SELECT status FROM requests WHERE id = ?1", [&id], |r| r.get(0))?;
        if status != "pending" {
            bail!("request {id} is {status} now; nothing was approved");
        }
        let plan = still_as_shown(tx, &id, &account_id, &chosen, &shown)?;
        // Late items: the operator's choice, skip by default.
        let to_send: Vec<(u32, i64)> = plan
            .iter()
            .filter_map(|&(i, t)| match (t <= now, late) {
                (false, _) => Some((i, t)),
                (true, Late::Send) => Some((i, now)),
                (true, Late::Skip) => None,
            })
            .collect();
        // Server-wide daily cap on what approvals can queue (per UTC day).
        let mut per_day: BTreeMap<i64, i64> = BTreeMap::new();
        for (_, t) in &to_send {
            *per_day.entry(t.div_euclid(86_400)).or_default() += 1;
        }
        for (day, n) in &per_day {
            let existing: i64 = tx.query_row(
                "SELECT count(*) FROM request_items WHERE state IN ('scheduled', 'sending', 'sent', 'send_unknown') \
                 AND send_at >= ?1 AND send_at < ?2",
                params![day * 86_400, (day + 1) * 86_400],
                |r| r.get(0),
            )?;
            if existing + n > cap {
                bail!(
                    "approval refused: {} sends on {} would exceed limits.scheduled_sends_per_day ({cap}); nothing was approved",
                    existing + n,
                    &util::rfc3339(day * 86_400)[..10]
                );
            }
        }
        for (i, t) in &to_send {
            tx.execute(
                "UPDATE request_items SET state = 'scheduled', approved_rev = ?1, send_at = ?2, updated_at = ?3 \
                 WHERE request_id = ?4 AND idx = ?5 AND state = 'pending'",
                params![shown.get(i), t, now, id, i],
            )?;
        }
        for (i, _) in plan.iter().filter(|(i, _)| !to_send.iter().any(|(j, _)| j == i)) {
            tx.execute(
                "UPDATE request_items SET state = 'skipped', reason = 'late', updated_at = ?1 \
                 WHERE request_id = ?2 AND idx = ?3 AND state = 'pending'",
                params![now, id, i],
            )?;
        }
        tx.execute(
            "UPDATE request_items SET state = 'denied', reason = 'not_approved', updated_at = ?1 \
             WHERE request_id = ?2 AND state = 'pending'",
            params![now, id],
        )?;
        tx.execute(
            "UPDATE requests SET status = 'approved', decided_at = ?1, decided_by = ?2 WHERE id = ?3",
            params![now, decided_by, id],
        )?;
        close_if_finished(tx, &id)?;
        let status: String = tx.query_row("SELECT status FROM requests WHERE id = ?1", [&id], |r| r.get(0))?;
        Ok(json!({ "request_id": id, "status": status, "items": super::load_items(tx, &id)? }))
    })
    .await
}

/// Inside the approval transaction: every chosen item is still `pending` and its draft is still Dove's at the shown
/// revision (`own_drafts`, active). The fresh read happened before the transaction; this closes the window in
/// between. Returns (idx, send_at) per chosen item.
fn still_as_shown(
    tx: &Connection,
    id: &str,
    account_id: &str,
    chosen: &[u32],
    shown: &HashMap<u32, String>,
) -> anyhow::Result<Vec<(u32, i64)>> {
    let mut st = tx.prepare(
        "SELECT i.state, i.send_at, o.message_id, o.state FROM request_items i JOIN requests r ON r.id = i.request_id \
         LEFT JOIN own_drafts o ON o.account_id = ?2 AND o.draft_id = i.draft_id AND o.project_id = r.project_id \
         WHERE i.request_id = ?1 AND i.idx = ?3",
    )?;
    let mut plan = Vec::new();
    for i in chosen {
        let (state, send_at, mid, ostate): (String, i64, Option<String>, Option<String>) =
            st.query_row(params![id, account_id, i], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        if state != "pending" {
            bail!("item {i} is {state} now; nothing was approved");
        }
        if mid.as_ref() != shown.get(i) || ostate.as_deref() != Some("active") {
            bail!("item {i}'s draft changed since it was shown; nothing was approved");
        }
        plan.push((*i, send_at));
    }
    Ok(plan)
}

/// `dove requests deny`: a pending request and all its items become `denied`.
pub async fn deny(call: &mut AdminCall<'_>, id: String) -> anyhow::Result<Value> {
    let decided_by = call.actor.name.clone();
    call.tx(move |tx| {
        let now = util::now_unix();
        let status: Option<String> =
            tx.query_row("SELECT status FROM requests WHERE id = ?1", [&id], |r| r.get(0)).optional()?;
        match status.as_deref() {
            None => bail!("unknown request '{}'", id.chars().take(80).collect::<String>()),
            Some("pending") => {}
            Some(s) => bail!("request {id} is {s}, not pending (stop an approved request with `dove requests cancel`)"),
        }
        tx.execute(
            "UPDATE requests SET status = 'denied', decided_at = ?1, decided_by = ?2 WHERE id = ?3",
            params![now, decided_by, id],
        )?;
        tx.execute(
            "UPDATE request_items SET state = 'denied', reason = 'denied', updated_at = ?1 \
             WHERE request_id = ?2 AND state = 'pending'",
            params![now, id],
        )?;
        Ok(json!({ "request_id": id, "status": "denied", "items": super::load_items(tx, &id)? }))
    })
    .await
}

/// `dove requests cancel`: stops unsent items (all, or the chosen ones) of a pending or approved request. A pending
/// request without `--items` is cancelled as a whole.
pub async fn cancel(call: &mut AdminCall<'_>, id: String, items: Option<Vec<u32>>) -> anyhow::Result<Value> {
    call.tx(move |tx| {
        let now = util::now_unix();
        let status: Option<String> =
            tx.query_row("SELECT status FROM requests WHERE id = ?1", [&id], |r| r.get(0)).optional()?;
        let status = status.ok_or_else(|| anyhow!("unknown request '{}'", id.chars().take(80).collect::<String>()))?;
        if !matches!(status.as_str(), "pending" | "approved") {
            bail!("request {id} is {status}; nothing left to cancel");
        }
        match &items {
            None => {
                super::cancel_one(tx, &id, &status, "cancelled_by_operator", now)?;
            }
            Some(list) => {
                for i in list {
                    let n = tx.execute(
                        "UPDATE request_items SET state = 'cancelled', reason = 'cancelled_by_operator', updated_at = ?1 \
                         WHERE request_id = ?2 AND idx = ?3 AND state IN ('pending', 'scheduled')",
                        params![now, id, i],
                    )?;
                    if n == 0 {
                        bail!("item {i} of request {id} is not waiting to be sent; nothing was cancelled");
                    }
                }
                // A pending request with no item left to decide is cancelled.
                tx.execute(
                    "UPDATE requests SET status = 'cancelled', decided_at = ?1 WHERE id = ?2 AND status = 'pending' \
                     AND NOT EXISTS (SELECT 1 FROM request_items WHERE request_id = ?2 AND state = 'pending')",
                    params![now, id],
                )?;
                close_if_finished(tx, &id)?;
            }
        }
        let status: String = tx.query_row("SELECT status FROM requests WHERE id = ?1", [&id], |r| r.get(0))?;
        Ok(json!({ "request_id": id, "status": status, "items": super::load_items(tx, &id)? }))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    /// The in-transaction check alone (the fresh read before it hides it in end-to-end tests): a stale `shown`, a
    /// draft that is no longer active, and an item that was decided meanwhile all refuse.
    #[test]
    fn approval_transaction_rechecks_the_shown_revision() {
        let s = Store::open_in_memory().unwrap();
        s.call_blocking(|c| {
            c.execute_batch(
                "INSERT INTO projects(id, name, created_at) VALUES ('p', 'p', 0);
                 INSERT INTO clients(id, name, project_id, kind, created_at, created_via) VALUES ('c', 'c', 'p', 'token', 0, 'cli');
                 INSERT INTO accounts(id, alias, email, status) VALUES ('a', 'a', 'a@example.com', 'active');
                 INSERT INTO own_drafts(account_id, draft_id, message_id, thread_id, project_id, client_id, created_at, updated_at, state)
                   VALUES ('a', 'd', 'rev2', 't', 'p', 'c', 0, 0, 'active');
                 INSERT INTO requests(id, client_id, project_id, account_id, kind, status, created_at, expires_at)
                   VALUES ('r', 'c', 'p', 'a', 'send', 'pending', 0, 100);
                 INSERT INTO request_items(request_id, idx, draft_id, requested_rev, send_at, state, updated_at)
                   VALUES ('r', 0, 'd', 'rev1', 50, 'pending', 0);",
            )?;
            let shown = |rev: &str| HashMap::from([(0u32, rev.to_string())]);
            assert_eq!(still_as_shown(c, "r", "a", &[0], &shown("rev2"))?, vec![(0, 50)]);
            let e = still_as_shown(c, "r", "a", &[0], &shown("rev1")).unwrap_err().to_string();
            assert!(e.contains("changed since it was shown"), "{e}");
            assert!(still_as_shown(c, "r", "a", &[0], &HashMap::new()).is_err());
            c.execute("UPDATE own_drafts SET state = 'sending'", [])?;
            assert!(still_as_shown(c, "r", "a", &[0], &shown("rev2")).is_err());
            c.execute("UPDATE own_drafts SET state = 'active'", [])?;
            c.execute("UPDATE request_items SET state = 'cancelled'", [])?;
            let e = still_as_shown(c, "r", "a", &[0], &shown("rev2")).unwrap_err().to_string();
            assert!(e.contains("cancelled now"), "{e}");
            Ok(())
        })
        .unwrap();
    }
}
