//! Access requests and temporary grants (design 2026-11-14 section 4.5, PLAN A73).
//!
//! An agent asks with `request_access` for actions on mailboxes of its project, for `duration_secs` or for good. The
//! request is a `requests` row of kind `access` with `account_id` NULL; the asked grants sit in `payload` (account ids
//! and action names only). Approval happens on the admin socket only ([`super::admin`]):
//! - permanent: the approved actions are added to `client_mailboxes` (old ∪ approved), the request is `done`;
//! - temporary: one `client_grant_extras` row per approved mailbox; the request stays `approved` while it has rows and
//!   is `done` when the last one is gone ([`super::close_if_finished`]).
//!
//! `policy::load_mailboxes_at` unites the base grant with the rows that have `expires_at > now`, so expiry needs no
//! write. [`expire`] (run by the requests worker) deletes expired rows with one audit record each; every other path
//! that ends a temporary grant (revoke, `clients set-grants`, cancel, mailbox removal) goes through [`drop_extras`].

use std::collections::{BTreeMap, HashSet};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{CreateError, OPEN_STATUSES, SCHEDULER, audit_event, close_if_finished};
use crate::config::Config;
use crate::policy::Actions;
use crate::util;

/// Longest temporary grant an agent may ask for (and the operator may approve), in minutes: 30 days.
pub const MAX_DURATION_MINUTES: i64 = 30 * 24 * 60;

/// One asked grant: an account of the client's project and the expanded action list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskedGrant {
    pub account_id: String,
    pub actions: String,
}

/// The operator's decision as stored after approval.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Indexes into `grants` that were approved.
    pub granted: Vec<u32>,
    /// Expiry of the temporary grants (unix seconds); None for a permanent approval.
    pub expires_at: Option<i64>,
}

/// `requests.payload` of an access request: ids, action names and times only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub grants: Vec<AskedGrant>,
    /// Asked duration in seconds; None asks for a permanent grant.
    pub duration_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
}

impl Payload {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

/// A new access request. `id` is chosen by the caller (the note is sealed with it as scope).
#[derive(Debug, Clone)]
pub struct NewAccess {
    pub id: String,
    pub client_id: String,
    pub project_id: String,
    pub note_sealed: Option<Vec<u8>>,
    pub payload: Payload,
}

/// Whether the client may open another request (`limits.client_open_requests`). `request_access` asks this before it
/// resolves any mailbox name, so the limit's error cannot tell whether a name is in the project.
pub fn has_room(c: &Connection, client_id: &str, limit: u32) -> rusqlite::Result<bool> {
    let open: i64 = c.query_row(
        &format!("SELECT count(*) FROM requests WHERE client_id = ?1 AND status IN {OPEN_STATUSES}"),
        [client_id],
        |r| r.get(0),
    )?;
    Ok(open < i64::from(limit))
}

/// Records a `pending` access request; refuses when the client has `limits.client_open_requests` open requests.
pub fn create(tx: &Transaction, cfg: &Config, new: NewAccess, now: i64) -> Result<String, CreateError> {
    if !has_room(tx, &new.client_id, cfg.limits.client_open_requests)? {
        return Err(CreateError::TooManyOpen);
    }
    let payload = serde_json::to_string(&new.payload).map_err(|e| CreateError::Store(e.into()))?;
    tx.execute(
        "INSERT INTO requests(id, client_id, project_id, account_id, kind, status, note_sealed, payload, created_at, \
         expires_at) VALUES (?1, ?2, ?3, NULL, 'access', 'pending', ?4, ?5, ?6, ?7)",
        params![
            new.id,
            new.client_id,
            new.project_id,
            new.note_sealed,
            payload,
            now,
            now + cfg.requests.pending_days * 86_400
        ],
    )?;
    Ok(new.id)
}

/// One asked grant as agents and the operator see it.
#[derive(Debug, Clone, Serialize)]
pub struct GrantView {
    pub idx: u32,
    /// The mailbox alias; None once the mailbox was removed from Dove.
    pub account: Option<String>,
    pub actions: String,
    /// `pending`, `granted` (permanent), `active` (temporary, not expired), `ended` (temporary, expired or taken back),
    /// `not_approved` (unticked by the operator), or the request's own end (`denied`, `cancelled`, `expired`).
    pub state: String,
}

/// The access part of a request view.
#[derive(Debug, Clone, Serialize)]
pub struct AccessView {
    /// Asked duration; None asks for a permanent grant.
    pub duration_minutes: Option<i64>,
    /// When the approved temporary grants end (None: permanent, or not approved).
    pub expires_at: Option<String>,
    pub grants: Vec<GrantView>,
}

/// Builds the access view of request `id` with `status` from its stored payload at `now`.
pub fn view(c: &Connection, id: &str, status: &str, payload: &str, now: i64) -> anyhow::Result<AccessView> {
    let p = Payload::parse(payload)?;
    let live: HashSet<String> = {
        let mut st =
            c.prepare_cached("SELECT account_id FROM client_grant_extras WHERE request_id = ?1 AND expires_at > ?2")?;
        st.query_map(params![id, now], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    let mut alias = c.prepare_cached("SELECT alias FROM accounts WHERE id = ?1")?;
    let mut grants = Vec::with_capacity(p.grants.len());
    for (i, g) in p.grants.iter().enumerate() {
        let i = i as u32;
        let state = match (status, &p.decision) {
            ("pending", _) => "pending",
            ("approved" | "done", Some(d)) if !d.granted.contains(&i) => "not_approved",
            ("approved" | "done", Some(d)) if d.expires_at.is_none() => "granted",
            ("approved" | "done", Some(_)) if live.contains(&g.account_id) => "active",
            ("approved" | "done", _) => "ended",
            (other, _) => other,
        };
        grants.push(GrantView {
            idx: i,
            account: alias.query_row([&g.account_id], |r| r.get(0)).optional()?,
            actions: g.actions.clone(),
            state: state.to_string(),
        });
    }
    Ok(AccessView {
        duration_minutes: p.duration_secs.map(|s| s / 60),
        expires_at: p.decision.as_ref().and_then(|d| d.expires_at).map(util::rfc3339),
        grants,
    })
}

/// Which temporary grants to drop.
pub enum Scope<'a> {
    /// Every row of one client (revoke, `clients set-grants`).
    Client(&'a str),
    /// The rows of one request (cancel).
    Request(&'a str),
    /// The rows on one account held by clients of one project (`projects remove-account`).
    ProjectAccount { project_id: &'a str, account_id: &'a str },
    /// Every row on one account (`accounts remove`; the row would go by cascade anyway).
    Account(&'a str),
}

/// Deletes temporary grants in `scope`; bumps the epoch of every client that lost one (cursors made with the wider
/// scope stop working) and closes the requests left without rows. Returns how many rows went.
pub fn drop_extras(tx: &Transaction, scope: Scope<'_>) -> anyhow::Result<usize> {
    let (filter, args): (&str, Vec<&str>) = match &scope {
        Scope::Client(c) => ("client_id = ?1", vec![c]),
        Scope::Request(r) => ("request_id = ?1", vec![r]),
        Scope::ProjectAccount { project_id, account_id } => (
            "account_id = ?1 AND client_id IN (SELECT id FROM clients WHERE project_id = ?2)",
            vec![account_id, project_id],
        ),
        Scope::Account(a) => ("account_id = ?1", vec![a]),
    };
    let rows: Vec<(String, String)> = {
        let mut st =
            tx.prepare(&format!("DELETE FROM client_grant_extras WHERE {filter} RETURNING client_id, request_id"))?;
        st.query_map(rusqlite::params_from_iter(args), |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
    };
    settle(tx, &rows)?;
    Ok(rows.len())
}

/// After rows went: bump the clients' epochs and close their requests.
fn settle(tx: &Connection, rows: &[(String, String)]) -> anyhow::Result<()> {
    let clients: HashSet<&str> = rows.iter().map(|(c, _)| c.as_str()).collect();
    for c in clients {
        tx.execute("UPDATE clients SET auth_epoch = auth_epoch + 1 WHERE id = ?1", [c])?;
    }
    let requests: HashSet<&str> = rows.iter().map(|(_, r)| r.as_str()).collect();
    for r in requests {
        close_if_finished(tx, r)?;
    }
    Ok(())
}

/// The worker's sweep: deletes temporary grants with `expires_at <= now`, one audit record each (actor `scheduler`,
/// action `request.grant_expire`, request id and mailbox alias). The policy stopped honouring them at their expiry
/// already; this makes the end visible and closes the requests. At most 1000 rows per call.
pub fn expire(tx: &Transaction, now: i64) -> anyhow::Result<usize> {
    let rows: Vec<(String, String, Option<String>, Option<String>)> = {
        let mut st = tx.prepare(
            "DELETE FROM client_grant_extras WHERE rowid IN (SELECT rowid FROM client_grant_extras \
             WHERE expires_at <= ?1 ORDER BY expires_at LIMIT 1000) \
             RETURNING client_id, request_id, \
             (SELECT alias FROM accounts WHERE id = account_id), \
             (SELECT p.name FROM clients c JOIN projects p ON p.id = c.project_id WHERE c.id = client_id)",
        )?;
        st.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?
    };
    for (_, request_id, alias, project) in &rows {
        audit_event(
            tx,
            SCHEDULER,
            "request.grant_expire",
            project.clone(),
            alias.clone(),
            vec![request_id.clone()],
            "expired",
        )?;
    }
    let pairs: Vec<(String, String)> = rows.into_iter().map(|(c, r, _, _)| (c, r)).collect();
    settle(tx, &pairs)?;
    Ok(pairs.len())
}

/// Open access requests that name `account_id` (optionally only of one project): pending ones are cancelled with
/// `reason`; approved ones lose their rows on the account (and close when none is left). One audit record per request.
pub fn cancel_naming_account(
    tx: &Transaction,
    account_id: &str,
    project_id: Option<&str>,
    reason: &str,
    now: i64,
) -> anyhow::Result<usize> {
    let rows: Vec<(String, String, Option<String>)> = {
        let mut st = tx.prepare(&format!(
            "SELECT r.id, r.status, p.name FROM requests r LEFT JOIN projects p ON p.id = r.project_id \
             WHERE r.kind = 'access' AND r.status IN {OPEN_STATUSES} AND (?2 IS NULL OR r.project_id = ?2) \
             AND EXISTS (SELECT 1 FROM json_each(r.payload, '$.grants') WHERE json_extract(value, '$.account_id') = ?1)"
        ))?;
        st.query_map(params![account_id, project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?
    };
    let mut n = 0;
    for (id, status, project) in rows {
        let changed = if status == "pending" {
            super::cancel_one(tx, &id, &status, reason, now)?
        } else {
            let gone: Vec<(String, String)> = {
                let mut st = tx.prepare(
                    "DELETE FROM client_grant_extras WHERE request_id = ?1 AND account_id = ?2 \
                     RETURNING client_id, request_id",
                )?;
                st.query_map(params![id, account_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
            };
            settle(tx, &gone)?;
            !gone.is_empty()
        };
        if changed {
            audit_event(tx, SCHEDULER, "request.cancel", project, None, vec![id], reason)?;
            n += 1;
        }
    }
    Ok(n)
}

/// What the client holds now on each asked mailbox, for the operator's review: base grant and temporary grants.
pub fn current_rights(c: &Connection, client_id: &str, payload: &Payload, now: i64) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::with_capacity(payload.grants.len());
    for g in &payload.grants {
        let account: Option<(String, String, bool)> = c
            .query_row(
                "SELECT a.alias, a.status, EXISTS(SELECT 1 FROM project_accounts pa JOIN clients cl \
                 ON cl.project_id = pa.project_id WHERE cl.id = ?2 AND pa.account_id = a.id) \
                 FROM accounts a WHERE a.id = ?1",
                params![g.account_id, client_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let base: Option<String> = c
            .query_row(
                "SELECT actions FROM client_mailboxes WHERE client_id = ?1 AND account_id = ?2",
                params![client_id, g.account_id],
                |r| r.get(0),
            )
            .optional()?;
        let temporary: Vec<Value> = {
            let mut st = c.prepare_cached(
                "SELECT actions, expires_at FROM client_grant_extras WHERE client_id = ?1 AND account_id = ?2 \
                 AND expires_at > ?3 ORDER BY expires_at",
            )?;
            st.query_map(params![client_id, g.account_id, now], |r| {
                Ok(json!({ "actions": r.get::<_, String>(0)?, "expires_at": util::rfc3339(r.get(1)?) }))
            })?
            .collect::<Result<_, _>>()?
        };
        out.push(json!({
            "account": account.as_ref().map(|a| a.0.clone()),
            "status": account.as_ref().map(|a| a.1.clone()),
            "in_project": account.as_ref().is_some_and(|a| a.2),
            "asked": g.actions,
            "has": base,
            "temporary": temporary,
        }));
    }
    Ok(out)
}

/// Grants of a permanent approval merged into the client's existing grants: old ∪ approved per mailbox, so an
/// approval can only add. `existing` are the stored `client_mailboxes` rows (account id → actions).
pub fn merged(existing: &BTreeMap<String, Actions>, approved: &BTreeMap<String, Actions>) -> BTreeMap<String, Actions> {
    let mut out = existing.clone();
    for (aid, a) in approved {
        let e = out.entry(aid.clone()).or_default();
        *e = e.union(a);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_approval_only_adds() {
        let a = |s: &str| Actions::parse(s).unwrap();
        let existing = BTreeMap::from([("x".to_string(), a("read,draft,organize")), ("y".to_string(), a("read"))]);
        let approved = BTreeMap::from([("y".to_string(), a("read,draft")), ("z".to_string(), a("read"))]);
        let m = merged(&existing, &approved);
        assert_eq!(m["x"], a("read,draft,organize"));
        assert_eq!(m["y"], a("read,draft"));
        assert_eq!(m["z"], a("read"));
        // Asking for less never removes anything.
        let m = merged(&existing, &BTreeMap::from([("x".to_string(), a("read"))]));
        assert_eq!(m["x"], a("read,draft,organize"));
    }

    #[test]
    fn payload_round_trip_holds_ids_only() {
        let p = Payload {
            grants: vec![AskedGrant { account_id: "acc1".into(), actions: "read,draft".into() }],
            duration_secs: Some(3600),
            decision: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, r#"{"grants":[{"account_id":"acc1","actions":"read,draft"}],"duration_secs":3600}"#);
        assert_eq!(Payload::parse(&s).unwrap(), p);
    }
}
