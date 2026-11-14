//! The scheduled-send worker (design 2026-11-14 section 4.4, PLAN A71).
//!
//! [`tick`] takes the clock as an argument (tests drive it; the service runs it every [`TICK`]). Per pass:
//! 1. pending requests past `expires_at` expire; temporary grants past their expiry are deleted with one audit record
//!    each (the policy stopped honouring them at their expiry already, PLAN A73);
//! 2. scheduled items more than `late_grace_minutes` past their time end as `missed` (or `skipped:
//!    condition_unknown` when they were waiting for a fresh index), before anything is sent; closed requests past
//!    `retention_days` or beyond [`super::MAX_CLOSED_PER_CLIENT`] per client are deleted;
//! 3. at most [`BATCH`] due items, oldest first, one at a time: request still approved, client live, mailbox active
//!    and still granted with `draft`, the `unless_reply` condition, then the claim `scheduled → sending` (recorded
//!    before the upstream write), then `tools::drafts::send_core` with the approved revision.
//!
//! An item in `sending` after a restart and every unknown outcome end as `send_unknown` and are never retried. A send
//! that was not dispatched is tried again within the grace; an upstream refusal three times, five minutes apart.
//! Every terminal outcome writes one audit record (actor `scheduler`, action `request.send_item`, ids only).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::{Connection, params};
use serde::Serialize;

use super::{SCHEDULER, audit_event, close_if_finished};
use crate::app::App;
use crate::error::ErrorCode;
use crate::policy::{self, Capability};
use crate::tools::ToolCx;
use crate::tools::drafts::{SendAuth, send_core};
use crate::util;
use crate::watch::{self, Baseline};

/// Background tick interval.
const TICK: Duration = Duration::from_secs(30);
/// Sends per tick: a long downtime cannot turn into a burst.
pub const BATCH: usize = 10;
/// Pause before a send that was not dispatched or was refused upstream is tried again.
pub const RETRY_SECS: i64 = 300;
/// Upstream refusals before an item fails.
pub const MAX_UPSTREAM_ATTEMPTS: i64 = 3;
/// `unless_reply` needs an index synced at most this long before the send.
pub const FRESH_SECS: i64 = 600;
/// Reason of a scheduled item that waits for a fresh index (`unless_reply`); at the end of the grace it becomes
/// `skipped: condition_unknown` instead of `missed`.
const WAITING_FOR_SYNC: &str = "waiting_for_sync";

/// What one [`tick`] did (tests).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct TickReport {
    pub sent: usize,
    pub failed: usize,
    pub skipped: usize,
    pub missed: usize,
    pub unknown: usize,
    pub expired: usize,
    pub deferred: usize,
    /// Temporary grants deleted at their expiry.
    pub grants_expired: usize,
}

/// Startup recovery: an item found in `sending` may or may not have gone out. It ends as `send_unknown` and is never
/// retried.
pub fn recover_after_restart(c: &Connection) -> anyhow::Result<usize> {
    let rows: Vec<(String, i64)> = {
        let mut st = c.prepare("SELECT request_id, idx FROM request_items WHERE state = 'sending'")?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
    };
    let tx = c.unchecked_transaction()?;
    let now = util::now_unix();
    for (rid, idx) in &rows {
        tx.execute(
            "UPDATE request_items SET state = 'send_unknown', reason = 'restart', updated_at = ?1 \
             WHERE request_id = ?2 AND idx = ?3 AND state = 'sending'",
            params![now, rid, idx],
        )?;
        audit_event(
            &tx,
            SCHEDULER,
            "request.send_item",
            None,
            None,
            vec![rid.clone(), format!("item:{idx}")],
            "send_unknown",
        )?;
        close_if_finished(&tx, rid)?;
    }
    tx.commit()?;
    Ok(rows.len())
}

/// Starts the background worker (called from `dove serve`).
pub fn start(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = tick(&app, util::now_unix()).await {
                tracing::warn!(error = %e, "scheduled send tick failed");
            }
            tokio::time::sleep(TICK).await;
        }
    })
}

/// One item that is due.
#[derive(Debug, Clone)]
struct Due {
    request_id: String,
    idx: i64,
    draft_id: String,
    approved_rev: String,
    client_id: String,
    account_id: String,
    project: Option<String>,
    alias: Option<String>,
    unless_reply: bool,
    thread_id: Option<String>,
    baseline_ms: Option<i64>,
    baseline_ids: Option<String>,
}

/// A terminal or deferring outcome for one item.
enum Outcome {
    Sent(Option<String>),
    /// Terminal: `state` with `reason`.
    End(&'static str, String),
    /// Back to `scheduled`, tried again at `next_try_at` (None: next tick) with a reason hint.
    Defer(Option<i64>, &'static str),
    /// Back to `scheduled` after an upstream refusal (counted towards [`MAX_UPSTREAM_ATTEMPTS`]).
    Refused(String),
}

/// A scheduled item past its grace: request id, index, reason, project name, mailbox alias.
type LateRow = (String, i64, Option<String>, Option<String>, Option<String>);

/// One pass of the worker at `now`: expiry, late items, then at most [`BATCH`] due sends (tests drive the clock).
pub async fn tick(app: &Arc<App>, now: i64) -> anyhow::Result<TickReport> {
    let started = Instant::now();
    let mut report = TickReport::default();
    let grace = app.cfg.requests.grace_secs();

    // 1 and 2: expiry and missed items, in one transaction; then old closed requests go.
    let retention = app.cfg.requests.retention_days * 86_400;
    let (expired, ended, grants_expired) = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let expiring: Vec<(String, Option<String>)> = {
                let mut st = tx.prepare(
                    "SELECT r.id, p.name FROM requests r LEFT JOIN projects p ON p.id = r.project_id \
                     WHERE r.status = 'pending' AND r.expires_at <= ?1",
                )?;
                st.query_map([now], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
            };
            for (id, project) in &expiring {
                tx.execute(
                    "UPDATE requests SET status = 'expired', decided_at = ?1 WHERE id = ?2 AND status = 'pending'",
                    params![now, id],
                )?;
                tx.execute(
                    "UPDATE request_items SET state = 'cancelled', reason = 'expired', updated_at = ?1 \
                     WHERE request_id = ?2 AND state = 'pending'",
                    params![now, id],
                )?;
                audit_event(&tx, SCHEDULER, "request.expire", project.clone(), None, vec![id.clone()], "expired")?;
            }
            let late: Vec<LateRow> = {
                let mut st = tx.prepare(
                    "SELECT i.request_id, i.idx, i.reason, p.name, a.alias FROM request_items i \
                     JOIN requests r ON r.id = i.request_id LEFT JOIN projects p ON p.id = r.project_id \
                     LEFT JOIN accounts a ON a.id = r.account_id \
                     WHERE i.state = 'scheduled' AND i.send_at + ?1 < ?2",
                )?;
                st.query_map(params![grace, now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                    .collect::<Result<_, _>>()?
            };
            let mut ended = Vec::new();
            for (rid, idx, reason, project, alias) in late {
                // Never sent after the grace; an unless_reply item whose condition could not be established is
                // reported as such, not as late.
                let (state, reason) = if reason.as_deref() == Some(WAITING_FOR_SYNC) {
                    ("skipped", "condition_unknown")
                } else {
                    ("missed", "late")
                };
                tx.execute(
                    "UPDATE request_items SET state = ?1, reason = ?2, next_try_at = NULL, updated_at = ?3 \
                     WHERE request_id = ?4 AND idx = ?5 AND state = 'scheduled'",
                    params![state, reason, now, rid, idx],
                )?;
                let code = if state == "missed" { "missed" } else { reason };
                audit_event(
                    &tx,
                    SCHEDULER,
                    "request.send_item",
                    project,
                    alias,
                    vec![rid.clone(), format!("item:{idx}")],
                    code,
                )?;
                close_if_finished(&tx, &rid)?;
                ended.push(state);
            }
            let grants_expired = super::access::expire(&tx, now)?;
            let pruned = super::prune_closed(&tx, now, retention)?;
            if pruned > 0 {
                tracing::info!(pruned, "deleted closed requests past retention");
            }
            tx.commit()?;
            Ok((expiring.len(), ended, grants_expired))
        })
        .await?;
    report.expired = expired;
    report.grants_expired = grants_expired;
    report.missed = ended.iter().filter(|s| **s == "missed").count();
    report.skipped = ended.len() - report.missed;

    // With the feature switched off nothing is sent; approved items end as missed after the grace.
    if !app.cfg.requests.enabled {
        return Ok(report);
    }

    // 3: due items, oldest first, bounded.
    let due: Vec<Due> = app
        .store
        .call(move |c| {
            let mut st = c.prepare(&format!(
                "SELECT i.request_id, i.idx, i.draft_id, i.approved_rev, r.client_id, r.account_id, p.name, \
                 a.alias, r.unless_reply, i.thread_id, i.baseline_ms, i.baseline_ids FROM request_items i \
                 JOIN requests r ON r.id = i.request_id LEFT JOIN projects p ON p.id = r.project_id \
                 LEFT JOIN accounts a ON a.id = r.account_id \
                 WHERE i.state = 'scheduled' AND i.send_at <= ?1 AND (i.next_try_at IS NULL OR i.next_try_at <= ?1) \
                 AND r.status = 'approved' AND i.approved_rev IS NOT NULL \
                 ORDER BY i.send_at, i.request_id, i.idx LIMIT {BATCH}"
            ))?;
            Ok(st
                .query_map([now], |r| {
                    Ok(Due {
                        request_id: r.get(0)?,
                        idx: r.get(1)?,
                        draft_id: r.get(2)?,
                        approved_rev: r.get(3)?,
                        client_id: r.get(4)?,
                        account_id: r.get(5)?,
                        project: r.get(6)?,
                        alias: r.get(7)?,
                        unless_reply: r.get(8)?,
                        thread_id: r.get(9)?,
                        baseline_ms: r.get(10)?,
                        baseline_ids: r.get(11)?,
                    })
                })?
                .collect::<Result<_, _>>()?)
        })
        .await?;
    for item in due {
        // The clock moves while earlier items are sent: the grace is checked against the time of this claim.
        let at = now + started.elapsed().as_secs() as i64;
        let outcome = send_one(app, &item, at, grace).await?;
        record(app, &item, outcome, at, &mut report).await?;
    }
    Ok(report)
}

/// Decides one due item up to and including the send. `Ok(None)` from the claim means another pass took it.
async fn send_one(app: &Arc<App>, item: &Due, now: i64, grace: i64) -> anyhow::Result<Option<Outcome>> {
    // Re-checks from the durable store: client live, mailbox active and still granted with draft.
    let (cid, allow_send) = (item.client_id.clone(), app.cfg.allow_send);
    let ctx = app.store.call(move |c| policy::load_client(c, &cid, allow_send)).await?;
    let Some(ctx) = ctx else { return Ok(Some(Outcome::End("failed", "client_revoked".into()))) };
    let Some(mb) = ctx.mailboxes.iter().find(|m| m.account_id == item.account_id).cloned() else {
        return Ok(Some(Outcome::End("failed", "access_lost".into())));
    };
    if !mb.actions.has(Capability::Draft) {
        return Ok(Some(Outcome::End("failed", "access_lost".into())));
    }
    match mb.status.as_str() {
        "active" => {}
        "disabled" => return Ok(Some(Outcome::End("failed", "account_disabled".into()))),
        // Reauthorization needed: not dispatched, tried again within the grace.
        _ => return Ok(Some(Outcome::Defer(Some(now + RETRY_SECS), "account_unavailable"))),
    }
    if item.unless_reply {
        match reply_condition(app, item, &mb, now).await {
            Condition::NoReply => {}
            Condition::Replied => return Ok(Some(Outcome::End("skipped", "replied".into()))),
            Condition::Unknown => return Ok(Some(Outcome::End("skipped", "condition_unknown".into()))),
            Condition::Stale => {
                crate::index::wake(app, &item.account_id);
                return Ok(Some(Outcome::Defer(None, WAITING_FOR_SYNC)));
            }
        }
    }
    // The claim is recorded before the upstream write; only one pass can make it, and never past the grace. Its
    // `state = 'scheduled'` is what makes a cancel effective that came in after the due list was read (while an
    // earlier item of this pass was being sent).
    let (rid, idx) = (item.request_id.clone(), item.idx);
    let claimed = app
        .store
        .call(move |c| {
            Ok(c.execute(
                "UPDATE request_items SET state = 'sending', updated_at = ?1 WHERE request_id = ?2 AND idx = ?3 \
                 AND state = 'scheduled' AND send_at <= ?1 AND send_at + ?4 >= ?1 \
                 AND EXISTS (SELECT 1 FROM requests WHERE id = ?2 AND status = 'approved')",
                params![now, rid, idx, grace],
            )?)
        })
        .await?;
    if claimed != 1 {
        return Ok(None);
    }
    let cx = ToolCx::new(app.clone(), ctx, util::new_id(), Instant::now());
    Ok(Some(match send_core(&cx, &mb, &item.draft_id, &item.approved_rev, SendAuth::Approved).await {
        Ok(sent) => Outcome::Sent(sent.sent_message_id),
        Err(e) => match e.code {
            ErrorCode::OutcomeUnknown => Outcome::End("send_unknown", "outcome_unknown".into()),
            ErrorCode::DraftConflict => Outcome::End("failed", "draft_changed".into()),
            ErrorCode::NotFound => Outcome::End("failed", "not_found".into()),
            ErrorCode::RateLimited | ErrorCode::AccountUnavailable => {
                Outcome::Defer(Some(now + RETRY_SECS), e.code.as_str())
            }
            ErrorCode::UpstreamError => Outcome::Refused(e.code.as_str().into()),
            other => Outcome::End("failed", other.as_str().into()),
        },
    }))
}

/// Writes the outcome of one item, its audit record (terminal outcomes) and closes the request when it is finished.
async fn record(
    app: &Arc<App>,
    item: &Due,
    outcome: Option<Outcome>,
    now: i64,
    report: &mut TickReport,
) -> anyhow::Result<()> {
    let Some(outcome) = outcome else { return Ok(()) };
    let it = item.clone();
    let counted = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            // Pre-claim outcomes apply to a `scheduled` item, post-claim ones to the `sending` item this pass claimed.
            let mut ids = vec![it.request_id.clone(), format!("item:{}", it.idx), it.draft_id.clone()];
            let (state, reason, sent_id, code): (&str, Option<String>, Option<String>, String) = match outcome {
                Outcome::Sent(id) => {
                    ids.extend(id.clone());
                    ("sent", None, id, "ok".into())
                }
                Outcome::End(state, reason) => {
                    let code = if state == "send_unknown" { state.to_string() } else { reason.clone() };
                    (state, Some(reason), None, code)
                }
                Outcome::Defer(next, reason) => {
                    tx.execute(
                        "UPDATE request_items SET state = 'scheduled', reason = ?1, next_try_at = ?2, updated_at = ?3 \
                         WHERE request_id = ?4 AND idx = ?5 AND state IN ('scheduled', 'sending')",
                        params![reason, next, now, it.request_id, it.idx],
                    )?;
                    tx.commit()?;
                    return Ok("deferred");
                }
                Outcome::Refused(code) => {
                    let attempts: i64 = tx.query_row(
                        "UPDATE request_items SET attempts = attempts + 1 WHERE request_id = ?1 AND idx = ?2 \
                         RETURNING attempts",
                        params![it.request_id, it.idx],
                        |r| r.get(0),
                    )?;
                    if attempts < MAX_UPSTREAM_ATTEMPTS {
                        tx.execute(
                            "UPDATE request_items SET state = 'scheduled', reason = ?1, next_try_at = ?2, updated_at = ?3 \
                             WHERE request_id = ?4 AND idx = ?5 AND state = 'sending'",
                            params![code, now + RETRY_SECS, now, it.request_id, it.idx],
                        )?;
                        tx.commit()?;
                        return Ok("deferred");
                    }
                    ("failed", Some(code.clone()), None, code)
                }
            };
            let n = tx.execute(
                "UPDATE request_items SET state = ?1, reason = ?2, sent_message_id = ?3, next_try_at = NULL, \
                 updated_at = ?4 WHERE request_id = ?5 AND idx = ?6 AND state IN ('scheduled', 'sending')",
                params![state, reason, sent_id, now, it.request_id, it.idx],
            )?;
            if n == 0 {
                // Cancelled while this pass decided it before the claim: nothing to record.
                tx.commit()?;
                return Ok("none");
            }
            audit_event(&tx, SCHEDULER, "request.send_item", it.project.clone(), it.alias.clone(), ids, &code)?;
            close_if_finished(&tx, &it.request_id)?;
            tx.commit()?;
            Ok(state)
        })
        .await?;
    match counted {
        "sent" => report.sent += 1,
        "failed" => report.failed += 1,
        "skipped" => report.skipped += 1,
        "send_unknown" => report.unknown += 1,
        "deferred" => report.deferred += 1,
        _ => {}
    }
    if counted == "send_unknown" {
        tracing::warn!(request = %item.request_id, item = item.idx, "scheduled send has an unknown outcome");
    }
    Ok(())
}

/// The `unless_reply` condition at send time.
enum Condition {
    NoReply,
    Replied,
    /// No index to decide with (indexing off, no serving generation): the item is skipped.
    Unknown,
    /// The index is not fresh enough; a sync is requested and the item waits (within the grace).
    Stale,
}

/// Whether the item's thread got a message from someone else after the request was created (the `no_reply_by` rule,
/// PLAN A70, except that replies in spam or trash count), decided only on an index synced within [`FRESH_SECS`] with
/// no message waiting in its retry queue. Fails closed: never `NoReply` on doubt.
async fn reply_condition(app: &Arc<App>, item: &Due, mb: &policy::Mailbox, now: i64) -> Condition {
    let (Some(thread_id), Some(ms)) = (item.thread_id.clone(), item.baseline_ms) else { return Condition::Unknown };
    if !mb.index_enabled {
        return Condition::Unknown;
    }
    let ids: Option<Vec<String>> = item.baseline_ids.as_deref().and_then(|s| serde_json::from_str(s).ok());
    let Some(ids) = ids else { return Condition::Unknown };
    let a = item.account_id.clone();
    let owners: HashSet<String> = match app.store.call(move |c| watch::owner_addresses(c, &a)).await {
        Ok(o) => o.into_iter().collect(),
        Err(_) => return Condition::Stale,
    };
    let a = item.account_id.clone();
    let baseline = Baseline { ms, ids: Some(ids) };
    let r = app
        .index
        .read(Instant::now() + Duration::from_secs(10), move |c| {
            let tx = c.unchecked_transaction()?;
            let Some(s) = crate::index::sync::load_state(&tx, &a)? else { return Ok(None) };
            let Some(g) = s.serving_gen() else { return Ok(None) };
            let replied = watch::first_reply(&tx, g, &thread_id, &baseline, &owners, watch::Replies::Any)?.is_some();
            // A message whose fetch failed waits in `pending` (unknown thread) while `last_success_at` advances: it may
            // be the reply, so the index cannot prove that nobody answered until it is resolved.
            let gaps: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM pending WHERE gen = ?1)", [g], |r| r.get(0))?;
            Ok(Some((replied, s.last_success_at, gaps)))
        })
        .await;
    match r {
        Ok(None) => Condition::Unknown,
        Ok(Some((true, _, _))) => Condition::Replied,
        Ok(Some((false, Some(synced), false))) if synced >= now - FRESH_SECS => Condition::NoReply,
        Ok(Some((false, _, _))) | Err(_) => Condition::Stale,
    }
}
