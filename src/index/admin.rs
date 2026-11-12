//! `dove index enable|disable|status|rebuild <alias>` (spec 7.9, 5.5). Each verb yields exactly one audit record:
//! enable/disable commit the operator's choice together with its audit record in the state store; status and
//! rebuild are audited once by the dispatcher.

use std::sync::Arc;

use anyhow::bail;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use super::sync::{SyncState, load_all_states};
use super::{check_fence, new_generation, next_fence};
use crate::admin::ops;
use crate::admin::server::AdminCall;
use crate::app::App;
use crate::util;

pub async fn enable(call: &mut AdminCall<'_>, alias: String) -> anyhow::Result<Value> {
    let app = call.app.clone();
    let a = alias.clone();
    let account_id = call
        .tx(move |tx| {
            let id = ops::account_id(tx, &a)?;
            tx.execute("UPDATE accounts SET index_enabled = 1 WHERE id = ?1", [&id])?;
            Ok(id)
        })
        .await?;
    let created = super::ensure_state(&app, &account_id).await?;
    super::wake(&app, &account_id);
    Ok(json!({ "account": alias, "index": "enabled", "started_backfill": created }))
}

pub async fn disable(call: &mut AdminCall<'_>, alias: String) -> anyhow::Result<Value> {
    let app = call.app.clone();
    let a = alias.clone();
    let account_id = call
        .tx(move |tx| {
            let id = ops::account_id(tx, &a)?;
            tx.execute("UPDATE accounts SET index_enabled = 0 WHERE id = ?1", [&id])?;
            Ok(id)
        })
        .await?;
    // Reads stop immediately (searches check index_enabled per request); then jobs are fenced and rows purged.
    super::purge_account(&app, &account_id).await;
    Ok(json!({ "account": alias, "index": "disabled", "purged": true }))
}

pub async fn rebuild(call: &mut AdminCall<'_>, alias: String) -> anyhow::Result<Value> {
    let app = call.app.clone();
    let a = alias.clone();
    let (account_id, enabled): (String, bool) = call
        .read(move |c| {
            let id = ops::account_id(c, &a)?;
            let en: bool = c.query_row("SELECT index_enabled FROM accounts WHERE id = ?1", [&id], |r| r.get(0))?;
            Ok((id, en))
        })
        .await?;
    if !enabled {
        bail!("indexing is not enabled for '{alias}'; run `dove index enable {alias}` first");
    }
    super::ensure_state(&app, &account_id).await?;
    start_rebuild(&app, &account_id).await?;
    super::wake(&app, &account_id);
    Ok(json!({ "account": alias, "index": "rebuilding" }))
}

/// Starts a full rebuild into a fresh generation: cancels and fences the running job, invalidates cursors.
pub async fn start_rebuild(app: &Arc<App>, account_id: &str) -> anyhow::Result<()> {
    app.index.cancel(account_id);
    app.index.cursors.invalidate_account(account_id);
    let lock = app.index.lock_for(account_id);
    let _guard = lock.lock().await;
    let aid = account_id.to_string();
    app.index
        .write(move |c| {
            let tx = c.transaction()?;
            let old_fence: i64 =
                tx.query_row("SELECT fence FROM sync_state WHERE account_id = ?1", [&aid], |r| r.get(0))?;
            check_fence(&tx, &aid, old_fence)?;
            let building: Option<i64> = tx
                .query_row("SELECT building_gen FROM sync_state WHERE account_id = ?1", [&aid], |r| r.get(0))
                .optional()?
                .flatten();
            if let Some(b) = building {
                super::drop_generation(&tx, b)?;
            }
            let fence = next_fence(&tx)?;
            let g = new_generation(&tx, &aid)?;
            tx.execute(
                "UPDATE sync_state SET fence = ?1, building_gen = ?2, \
                 stage = CASE WHEN active_gen IS NULL THEN 'backfill' ELSE 'rebuilding' END, \
                 next_run_at = 0, data_seq = data_seq + 1 WHERE account_id = ?3",
                params![fence, g, aid],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    app.index.cursors.invalidate_account(account_id);
    Ok(())
}

/// Status without mail content: stage, counts, freshness and the last error code.
pub async fn status(app: &Arc<App>, alias: Option<String>) -> anyhow::Result<Value> {
    let accounts: Vec<(String, String, bool, String)> = app
        .store
        .call(move |c| {
            let mut st = c.prepare("SELECT id, alias, index_enabled, status FROM accounts ORDER BY alias")?;
            let rows: Vec<(String, String, bool, String)> =
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?;
            if let Some(a) = &alias {
                let found: Vec<_> = rows.into_iter().filter(|r| &r.1 == a).collect();
                if found.is_empty() {
                    bail!("no account '{a}'");
                }
                return Ok(found);
            }
            Ok(rows)
        })
        .await?;
    let details = app
        .index
        .write(move |c| {
            let states = load_all_states(c)?;
            let mut out = vec![];
            for s in states {
                let count = |g: Option<i64>| -> rusqlite::Result<i64> {
                    match g {
                        Some(g) => c.query_row("SELECT count(*) FROM messages WHERE gen = ?1", [g], |r| r.get(0)),
                        None => Ok(0),
                    }
                };
                let indexed = count(s.active_gen)?;
                let building = count(s.building_gen)?;
                let pending: i64 = match s.serving_gen() {
                    Some(g) => c.query_row("SELECT count(*) FROM pending WHERE gen = ?1", [g], |r| r.get(0))?,
                    None => 0,
                };
                let listed: i64 = match s.building_gen {
                    Some(g) => c.query_row("SELECT listed FROM generations WHERE id = ?1", [g], |r| r.get(0))?,
                    None => 0,
                };
                out.push((s, indexed, building, pending, listed));
            }
            Ok(out)
        })
        .await?;
    let now = util::now_unix();
    let rows: Vec<Value> = accounts
        .into_iter()
        .map(|(id, alias, enabled, account_status)| {
            let d: Option<&(SyncState, i64, i64, i64, i64)> = details.iter().find(|d| d.0.account_id == id);
            match d {
                Some((s, indexed, building, pending, listed)) if enabled => json!({
                    "account": alias,
                    "enabled": true,
                    "account_status": account_status,
                    "stage": s.stage,
                    "indexed_messages": indexed,
                    "backfill": s.building_gen.map(|_| json!({ "listed": listed, "indexed": building })),
                    "retry_pending": pending,
                    "last_success_at": s.last_success_at.map(util::rfc3339),
                    "lag_seconds": s.last_success_at.map(|t| now - t),
                    "last_error": s.last_error,
                    "last_error_at": s.last_error_at.map(util::rfc3339),
                }),
                _ => json!({ "account": alias, "enabled": enabled, "account_status": account_status,
                             "stage": if enabled { "pending" } else { "disabled" } }),
            }
        })
        .collect();
    Ok(json!({ "accounts": rows }))
}
