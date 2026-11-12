//! Admin state operations (FR-A*, FR-P*, 5.2a). Each runs in one transaction and writes one audit record.
//!
//! These functions are only reachable through the admin socket after the peer-uid check, never from MCP.

use std::collections::BTreeMap;

use anyhow::{Context, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::audit::{self, AuditRecord};
use crate::policy::Actions;
use crate::tokens::{self, Pepper};
use crate::util;

pub fn valid_alias(s: &str) -> bool {
    (2..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn valid_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Context for audit records of admin actions.
#[derive(Debug, Clone)]
pub struct Actor {
    pub name: String,
    pub request_id: String,
}

pub fn audit_admin(
    tx: &Connection,
    actor: &Actor,
    action: &str,
    project: Option<&str>,
    account: Option<&str>,
    object_ids: Vec<String>,
    code: &str,
) -> anyhow::Result<()> {
    audit::append(
        tx,
        &AuditRecord {
            request_id: actor.request_id.clone(),
            actor: actor.name.clone(),
            project: project.map(str::to_string),
            tool_or_action: action.to_string(),
            account_alias: account.map(str::to_string),
            object_ids,
            result_code: code.to_string(),
            ..Default::default()
        },
    )?;
    Ok(())
}

pub fn project_id(conn: &Connection, name: &str) -> anyhow::Result<String> {
    conn.query_row("SELECT id FROM projects WHERE name = ?1", [name], |r| r.get(0))
        .optional()?
        .ok_or_else(|| anyhow!("unknown project '{name}'"))
}

pub fn account_id(conn: &Connection, alias: &str) -> anyhow::Result<String> {
    conn.query_row("SELECT id FROM accounts WHERE alias = ?1", [alias], |r| r.get(0))
        .optional()?
        .ok_or_else(|| anyhow!("unknown account '{alias}'"))
}

fn client_row(conn: &Connection, name: &str) -> anyhow::Result<(String, String)> {
    conn.query_row("SELECT id, project_id FROM clients WHERE name = ?1", [name], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or_else(|| anyhow!("unknown client '{name}'"))
}

// ---------------------------------------------------------------- projects

pub fn project_create(tx: &Transaction, name: &str) -> anyhow::Result<Value> {
    if !valid_name(name) {
        bail!("project name must match [a-z0-9][a-z0-9_-]{{0,63}}");
    }
    let id = util::new_id();
    tx.execute("INSERT INTO projects(id, name, created_at) VALUES (?1, ?2, ?3)", params![id, name, util::now_unix()])
        .map_err(|e| if is_unique(&e) { anyhow!("project '{name}' already exists") } else { e.into() })?;
    Ok(json!({ "project": name }))
}

pub fn project_add_account(tx: &Transaction, project: &str, alias: &str) -> anyhow::Result<Value> {
    let pid = project_id(tx, project)?;
    let aid = account_id(tx, alias)?;
    let n = tx.execute(
        "INSERT OR IGNORE INTO project_accounts(project_id, account_id, added_at) VALUES (?1, ?2, ?3)",
        params![pid, aid, util::now_unix()],
    )?;
    // Adding a project mailbox grants existing tokens zero new access (FR-P2): grants are explicit per client.
    Ok(
        json!({ "project": project, "account": alias, "added": n == 1, "note": "existing connections gain no access; use clients set-grants" }),
    )
}

/// Removes the account from the project and deletes all client grants on it in that project, transactionally
/// (FR-P3). Re-adding the account later does not resurrect access.
pub fn project_remove_account(tx: &Transaction, project: &str, alias: &str) -> anyhow::Result<Value> {
    let pid = project_id(tx, project)?;
    let aid = account_id(tx, alias)?;
    let removed =
        tx.execute("DELETE FROM project_accounts WHERE project_id = ?1 AND account_id = ?2", params![pid, aid])?;
    let grants = tx.execute(
        "DELETE FROM client_mailboxes WHERE account_id = ?1 AND client_id IN (SELECT id FROM clients WHERE project_id = ?2)",
        params![aid, pid],
    )?;
    tx.execute("UPDATE clients SET auth_epoch = auth_epoch + 1 WHERE project_id = ?1", [&pid])?;
    // Outstanding invitations of the project could otherwise resurrect access after a re-add.
    let invitations = tx.execute("DELETE FROM invitations WHERE project_id = ?1 AND used_at IS NULL", [&pid])?;
    Ok(json!({ "project": project, "account": alias, "removed": removed == 1, "client_grants_deleted": grants,
               "pending_invitations_cancelled": invitations }))
}

pub fn project_list(conn: &Connection) -> anyhow::Result<Value> {
    let mut stmt = conn.prepare(
        "SELECT p.name, (SELECT COUNT(*) FROM project_accounts pa WHERE pa.project_id = p.id), \
         (SELECT COUNT(*) FROM clients c WHERE c.project_id = p.id AND c.revoked_at IS NULL) FROM projects p ORDER BY p.name",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(json!({ "name": r.get::<_, String>(0)?, "accounts": r.get::<_, i64>(1)?, "active_clients": r.get::<_, i64>(2)? }))
    })?;
    Ok(Value::Array(rows.collect::<Result<_, _>>()?))
}

pub fn project_show(conn: &Connection, name: &str) -> anyhow::Result<Value> {
    let pid = project_id(conn, name)?;
    let mut stmt = conn.prepare(
        "SELECT a.alias, a.email, a.status FROM project_accounts pa JOIN accounts a ON a.id = pa.account_id \
         WHERE pa.project_id = ?1 ORDER BY a.alias",
    )?;
    let accounts: Vec<Value> = stmt
        .query_map([&pid], |r| {
            Ok(json!({ "alias": r.get::<_, String>(0)?, "email": r.get::<_, String>(1)?, "status": r.get::<_, String>(2)? }))
        })?
        .collect::<Result<_, _>>()?;
    let mut stmt = conn.prepare("SELECT name FROM clients WHERE project_id = ?1 ORDER BY name")?;
    let clients: Vec<String> = stmt.query_map([&pid], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(json!({ "name": name, "accounts": accounts, "clients": clients }))
}

// ---------------------------------------------------------------- accounts

pub fn account_list(conn: &Connection) -> anyhow::Result<Value> {
    let mut stmt = conn.prepare(
        "SELECT alias, email, display_name, status, granted_scopes, connected_at, last_used_at, last_error_code, \
         index_enabled FROM accounts ORDER BY alias",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "alias": r.get::<_, String>(0)?, "email": r.get::<_, String>(1)?,
            "display_name": r.get::<_, Option<String>>(2)?, "status": r.get::<_, String>(3)?,
            "granted_scopes": r.get::<_, String>(4)?,
            "connected_at": r.get::<_, Option<i64>>(5)?.map(util::rfc3339),
            "last_used_at": r.get::<_, Option<i64>>(6)?.map(util::rfc3339),
            "last_error": r.get::<_, Option<String>>(7)?,
            "index_enabled": r.get::<_, i64>(8)? != 0,
        }))
    })?;
    Ok(Value::Array(rows.collect::<Result<_, _>>()?))
}

pub fn account_set_enabled(tx: &Transaction, alias: &str, enabled: bool) -> anyhow::Result<Value> {
    let aid = account_id(tx, alias)?;
    let status: String = tx.query_row("SELECT status FROM accounts WHERE id = ?1", [&aid], |r| r.get(0))?;
    let new_status = match (enabled, status.as_str()) {
        (false, _) => "disabled",
        // Enabling returns to active only if a grant exists; reauth stays reauth.
        (true, "disabled") => {
            let has_grant: bool =
                tx.query_row("SELECT EXISTS(SELECT 1 FROM grants WHERE account_id = ?1)", [&aid], |r| r.get(0))?;
            if has_grant { "active" } else { "reauth_required" }
        }
        (true, s) => s,
    }
    .to_string();
    tx.execute("UPDATE accounts SET status = ?1 WHERE id = ?2", params![new_status, aid])?;
    Ok(json!({ "account": alias, "status": new_status }))
}

// ---------------------------------------------------------------- clients

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantSpec {
    pub account: String,
    pub actions: String,
}

/// Parses `alias=read,draft` CLI arguments.
pub fn parse_grant_args(args: &[String]) -> anyhow::Result<Vec<GrantSpec>> {
    args.iter()
        .map(|g| {
            let (a, actions) =
                g.split_once('=').ok_or_else(|| anyhow!("grant '{g}' must look like alias=read,draft"))?;
            Ok(GrantSpec { account: a.trim().to_string(), actions: actions.trim().to_string() })
        })
        .collect()
}

/// Resolves aliases to immutable account ids and validates them against the project ceiling and send gate.
pub fn resolve_grants(
    conn: &Connection,
    project_id: &str,
    grants: &[GrantSpec],
    allow_send: bool,
) -> anyhow::Result<BTreeMap<String, (String, Actions)>> {
    if grants.is_empty() {
        bail!("at least one explicit --grant alias=actions is required");
    }
    let mut out = BTreeMap::new();
    for g in grants {
        let actions = Actions::parse(&g.actions).map_err(|e| anyhow!("grant {}: {e}", g.account))?;
        if actions.send && !allow_send {
            bail!("grant {}: send requires allow_send = true in the server configuration (spec 6.3)", g.account);
        }
        let aid = account_id(conn, &g.account)?;
        let in_project: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM project_accounts WHERE project_id = ?1 AND account_id = ?2)",
            params![project_id, aid],
            |r| r.get(0),
        )?;
        if !in_project {
            bail!("account '{}' is not in this client's project", g.account);
        }
        if out.insert(aid, (g.account.clone(), actions)).is_some() {
            bail!("duplicate grant for '{}'", g.account);
        }
    }
    Ok(out)
}

pub fn write_grants(
    tx: &Transaction,
    client_id: &str,
    grants: &BTreeMap<String, (String, Actions)>,
) -> anyhow::Result<()> {
    tx.execute("DELETE FROM client_mailboxes WHERE client_id = ?1", [client_id])?;
    for (aid, (_, actions)) in grants {
        tx.execute(
            "INSERT INTO client_mailboxes(client_id, account_id, actions) VALUES (?1, ?2, ?3)",
            params![client_id, aid, actions.to_string()],
        )?;
    }
    Ok(())
}

pub struct NewClient<'a> {
    pub name: &'a str,
    pub project: &'a str,
    pub grants: &'a [GrantSpec],
    pub expires_in_secs: Option<i64>,
    pub allowed_cidrs: &'a [String],
    pub kind: &'a str,
    pub created_via: &'a str,
}

pub fn validate_cidrs(cidrs: &[String]) -> anyhow::Result<String> {
    for c in cidrs {
        c.parse::<ipnet::IpNet>().with_context(|| format!("invalid CIDR '{c}'"))?;
    }
    Ok(serde_json::to_string(cidrs)?)
}

/// Creates a client and, for `kind = token`, returns its bearer token once.
pub fn client_create(
    tx: &Transaction,
    pepper: &Pepper,
    allow_send: bool,
    nc: &NewClient<'_>,
) -> anyhow::Result<(String, Option<String>, Value)> {
    if !valid_name(nc.name) {
        bail!("client name must match [a-z0-9][a-z0-9_-]{{0,63}}");
    }
    let pid = project_id(tx, nc.project)?;
    let grants = resolve_grants(tx, &pid, nc.grants, allow_send)?;
    let cidrs = validate_cidrs(nc.allowed_cidrs)?;
    let id = util::new_id();
    let token = (nc.kind == "token").then(|| tokens::generate(tokens::CLIENT_TOKEN_PREFIX));
    let hash = token.as_ref().map(|t| pepper.hash("client", t));
    let now = util::now_unix();
    let expires_at = nc.expires_in_secs.map(|s| now + s);
    tx.execute(
        "INSERT INTO clients(id, name, project_id, kind, token_hash, allowed_cidrs, expires_at, created_at, created_via) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![id, nc.name, pid, nc.kind, hash, cidrs, expires_at, now, nc.created_via],
    )
    .map_err(|e| if is_unique(&e) { anyhow!("client '{}' already exists", nc.name) } else { e.into() })?;
    write_grants(tx, &id, &grants)?;
    let effective: Vec<Value> =
        grants.values().map(|(alias, a)| json!({ "account": alias, "actions": a.to_string() })).collect();
    Ok((
        id,
        token,
        json!({ "client": nc.name, "project": nc.project, "grants": effective, "expires_at": expires_at.map(util::rfc3339) }),
    ))
}

pub fn client_set_grants(
    tx: &Transaction,
    allow_send: bool,
    name: &str,
    grants: &[GrantSpec],
) -> anyhow::Result<Value> {
    let (cid, pid) = client_row(tx, name)?;
    let resolved = resolve_grants(tx, &pid, grants, allow_send)?;
    write_grants(tx, &cid, &resolved)?;
    tx.execute("UPDATE clients SET auth_epoch = auth_epoch + 1 WHERE id = ?1", [&cid])?;
    client_show(tx, name)
}

pub fn client_rotate(tx: &Transaction, pepper: &Pepper, name: &str) -> anyhow::Result<(String, Value)> {
    let (cid, _) = client_row(tx, name)?;
    let kind: String = tx.query_row("SELECT kind FROM clients WHERE id = ?1", [&cid], |r| r.get(0))?;
    if kind != "token" {
        bail!("client '{name}' is an OAuth connection; revoke it and connect again");
    }
    let token = tokens::generate(tokens::CLIENT_TOKEN_PREFIX);
    tx.execute(
        "UPDATE clients SET token_hash = ?1, auth_epoch = auth_epoch + 1 WHERE id = ?2",
        params![pepper.hash("client", &token), cid],
    )?;
    Ok((token, json!({ "client": name, "rotated": true })))
}

pub fn client_revoke(tx: &Transaction, name: &str) -> anyhow::Result<Value> {
    let (cid, _) = client_row(tx, name)?;
    let now = util::now_unix();
    tx.execute(
        "UPDATE clients SET revoked_at = COALESCE(revoked_at, ?1), auth_epoch = auth_epoch + 1 WHERE id = ?2",
        params![now, cid],
    )?;
    tx.execute(
        "UPDATE oauth_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE connection_id = ?2",
        params![now, cid],
    )?;
    Ok(json!({ "client": name, "revoked": true }))
}

#[allow(clippy::type_complexity)]
pub fn client_show(conn: &Connection, name: &str) -> anyhow::Result<Value> {
    let (cid, _) = client_row(conn, name)?;
    let (project, kind, cidrs, expires_at, revoked_at, created_at, created_via, last_used_at, last_ip): (
        String,
        String,
        String,
        Option<i64>,
        Option<i64>,
        i64,
        String,
        Option<i64>,
        Option<String>,
    ) = conn.query_row(
        "SELECT p.name, c.kind, c.allowed_cidrs, c.expires_at, c.revoked_at, c.created_at, c.created_via, \
         c.last_used_at, c.last_ip FROM clients c JOIN projects p ON p.id = c.project_id WHERE c.id = ?1",
        [&cid],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)),
    )?;
    let effective: Vec<Value> = crate::policy::load_mailboxes(conn, &cid)?
        .into_iter()
        .map(|m| json!({ "account": m.alias, "email": m.email, "actions": m.actions.to_string(), "status": m.status }))
        .collect();
    let mut stmt = conn.prepare(
        "SELECT a.alias, cm.actions FROM client_mailboxes cm JOIN accounts a ON a.id = cm.account_id WHERE cm.client_id = ?1 ORDER BY a.alias",
    )?;
    let granted: Vec<Value> = stmt
        .query_map([&cid], |r| Ok(json!({ "account": r.get::<_, String>(0)?, "actions": r.get::<_, String>(1)? })))?
        .collect::<Result<_, _>>()?;
    Ok(json!({
        "client": name, "project": project, "kind": kind, "created_via": created_via,
        "allowed_cidrs": serde_json::from_str::<Value>(&cidrs).unwrap_or(json!([])),
        "created_at": util::rfc3339(created_at), "expires_at": expires_at.map(util::rfc3339),
        "revoked_at": revoked_at.map(util::rfc3339), "last_used_at": last_used_at.map(util::rfc3339), "last_ip": last_ip,
        "grants": granted, "effective": effective,
    }))
}

pub fn client_list(conn: &Connection) -> anyhow::Result<Value> {
    let mut stmt = conn.prepare(
        "SELECT c.name, p.name, c.kind, c.revoked_at, c.expires_at, c.last_used_at FROM clients c \
         JOIN projects p ON p.id = c.project_id ORDER BY p.name, c.name",
    )?;
    let now = util::now_unix();
    let rows = stmt.query_map([], |r| {
        let revoked: Option<i64> = r.get(3)?;
        let expires: Option<i64> = r.get(4)?;
        let state = if revoked.is_some() {
            "revoked"
        } else if expires.is_some_and(|e| e <= now) {
            "expired"
        } else {
            "active"
        };
        Ok(json!({ "client": r.get::<_, String>(0)?, "project": r.get::<_, String>(1)?, "kind": r.get::<_, String>(2)?,
                   "state": state, "last_used_at": r.get::<_, Option<i64>>(5)?.map(util::rfc3339) }))
    })?;
    Ok(Value::Array(rows.collect::<Result<_, _>>()?))
}

/// Export of projects, clients and accounts without secrets (FR-C2).
pub fn export(conn: &Connection) -> anyhow::Result<Value> {
    let mut clients = Vec::new();
    let names: Vec<String> = {
        let mut stmt = conn.prepare("SELECT name FROM clients ORDER BY name")?;
        stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    for n in names {
        clients.push(client_show(conn, &n)?);
    }
    let projects: Vec<Value> = {
        let mut stmt = conn.prepare("SELECT name FROM projects ORDER BY name")?;
        let names: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
        names.iter().map(|n| project_show(conn, n)).collect::<anyhow::Result<_>>()?
    };
    Ok(json!({ "accounts": account_list(conn)?, "projects": projects, "clients": clients }))
}

pub fn is_unique(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        || f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
}
