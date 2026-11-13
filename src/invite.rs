//! One-time connection invitations (spec 5.2a, 5.6).
//!
//! The operator creates an invitation over the admin socket. It pre-authorizes one named connection in one project
//! with explicit, immutable account-id grants (`all` is expanded once at creation). The secret is `dovei_` + 256
//! random bits; only its keyed hash is stored. It expires after 10 minutes and is consumed atomically by exactly one
//! redemption: `dove login` (POST `/connect/redeem`, issues a connection token) or the OAuth approval page (issues
//! an OAuth connection). Redemption can only keep or narrow the invited rights.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{anyhow, bail};
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admin::ops::{self, GrantSpec};
use crate::app::App;
use crate::audit::{self, AuditRecord};
use crate::policy::Actions;
use crate::tokens::{self, Pepper};
use crate::util;

/// Invitation lifetime (spec 5.6: 10-minute expiry).
pub const TTL_SECS: i64 = 600;
const HASH_PURPOSE: &str = "invite";

/// One pre-authorized mailbox grant, bound to the immutable account id at creation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteGrant {
    pub account_id: String,
    pub alias: String,
    pub actions: String,
}

pub struct NewInvite<'a> {
    pub name: &'a str,
    pub project: &'a str,
    /// `["all"]` or explicit aliases.
    pub accounts: &'a [String],
    pub capabilities: &'a str,
    pub expires_in_secs: Option<i64>,
    pub allow_ip: &'a [String],
}

/// Creates an invitation (admin socket only). Returns the secret once and a description of the expansion.
pub fn create(tx: &Transaction, pepper: &Pepper, allow_send: bool, ni: &NewInvite<'_>) -> anyhow::Result<Value> {
    if !ops::valid_name(ni.name) {
        bail!("connection name must match [a-z0-9][a-z0-9_-]{{0,63}}");
    }
    let pid = ops::project_id(tx, ni.project)?;
    let now = util::now_unix();
    let taken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM clients WHERE name = ?1) \
         OR EXISTS(SELECT 1 FROM invitations WHERE connection_name = ?1 AND used_at IS NULL AND expires_at > ?2)",
        params![ni.name, now],
        |r| r.get(0),
    )?;
    if taken {
        bail!("a connection or open invitation named '{}' already exists", ni.name);
    }
    Actions::parse_grant(ni.capabilities).map_err(|e| anyhow!("--capabilities: {e}"))?;
    let aliases: Vec<String> = if ni.accounts.len() == 1 && ni.accounts[0] == "all" {
        // `all` expands to the project's current accounts, once, now (spec 5.2a).
        let mut stmt = tx.prepare(
            "SELECT a.alias FROM project_accounts pa JOIN accounts a ON a.id = pa.account_id \
             WHERE pa.project_id = ?1 ORDER BY a.alias",
        )?;
        stmt.query_map([&pid], |r| r.get(0))?.collect::<Result<_, _>>()?
    } else {
        if ni.accounts.iter().any(|a| a == "all") {
            bail!("--accounts takes either 'all' or a list of aliases");
        }
        ni.accounts.to_vec()
    };
    if aliases.is_empty() {
        bail!("the invitation would grant no mailbox (project '{}' has none)", ni.project);
    }
    let specs: Vec<GrantSpec> =
        aliases.iter().map(|a| GrantSpec { account: a.clone(), actions: ni.capabilities.to_string() }).collect();
    let resolved = ops::resolve_grants(tx, &pid, &specs, allow_send)?;
    let mut grants: Vec<InviteGrant> = resolved
        .iter()
        .map(|(aid, (alias, a))| InviteGrant { account_id: aid.clone(), alias: alias.clone(), actions: a.to_string() })
        .collect();
    grants.sort_by(|a, b| a.alias.cmp(&b.alias));
    let cidrs = ops::validate_cidrs(ni.allow_ip)?;
    if ni.expires_in_secs.is_some_and(|s| s <= 0) {
        bail!("--expires must be positive");
    }
    let secret = tokens::generate(tokens::INVITE_PREFIX);
    let id = util::new_id();
    let expires_at = now + TTL_SECS;
    tx.execute(
        "INSERT INTO invitations(id, secret_hash, project_id, connection_name, grants, expires_in_secs, allowed_cidrs, \
         created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id,
            pepper.hash(HASH_PURPOSE, &secret),
            pid,
            ni.name,
            serde_json::to_string(&grants)?,
            ni.expires_in_secs,
            cidrs,
            now,
            expires_at
        ],
    )?;
    Ok(json!({
        "invitation": secret,
        "connection": ni.name,
        "project": ni.project,
        "grants": grants.iter().map(|g| json!({ "account": g.alias, "actions": g.actions })).collect::<Vec<_>>(),
        "invitation_expires_at": util::rfc3339(expires_at),
        "connection_expires_in_secs": ni.expires_in_secs,
        "note": "Single use, valid 10 minutes. Give it to the user over a trusted channel. Redeem with \
                 `dove login --server <url> --profile <name>` or on the approval page of an MCP host's OAuth sign-in.",
    }))
}

/// A valid (unused, unexpired) invitation with its grants filtered to current project membership.
#[derive(Debug, Clone)]
pub struct Invitation {
    pub id: String,
    pub project_id: String,
    pub project_name: String,
    pub connection_name: String,
    pub grants: Vec<InviteGrant>,
    pub expires_in_secs: Option<i64>,
    pub allowed_cidrs: String,
}

/// Looks up a usable invitation by its secret. Unknown, used and expired all yield `None`.
pub fn peek(conn: &Connection, pepper: &Pepper, secret: &str) -> anyhow::Result<Option<Invitation>> {
    let secret = secret.trim();
    if !tokens::looks_valid(tokens::INVITE_PREFIX, secret) {
        return Ok(None);
    }
    let id: Option<String> = conn
        .query_row("SELECT id FROM invitations WHERE secret_hash = ?1", [pepper.hash(HASH_PURPOSE, secret)], |r| {
            r.get(0)
        })
        .optional()?;
    match id {
        Some(id) => load(conn, &id),
        None => Ok(None),
    }
}

/// Loads a usable invitation by id (the approval page binds the id after the user entered the secret).
pub fn load(conn: &Connection, id: &str) -> anyhow::Result<Option<Invitation>> {
    let now = util::now_unix();
    let row = conn
        .query_row(
            "SELECT i.project_id, p.name, i.connection_name, i.grants, i.expires_in_secs, i.allowed_cidrs \
             FROM invitations i JOIN projects p ON p.id = i.project_id \
             WHERE i.id = ?1 AND i.used_at IS NULL AND i.expires_at > ?2",
            params![id, now],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((project_id, project_name, connection_name, grants, expires_in_secs, allowed_cidrs)) = row else {
        return Ok(None);
    };
    let all: Vec<InviteGrant> = serde_json::from_str(&grants)?;
    // Accounts that left the project (or were removed) since the invitation was made are dropped.
    let mut grants = Vec::new();
    for g in all {
        let member: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM project_accounts WHERE project_id = ?1 AND account_id = ?2)",
            params![project_id, g.account_id],
            |r| r.get(0),
        )?;
        if member {
            grants.push(g);
        }
    }
    Ok(Some(Invitation {
        id: id.to_string(),
        project_id,
        project_name,
        connection_name,
        grants,
        expires_in_secs,
        allowed_cidrs,
    }))
}

/// Intersects the invited grants with what the approver selected. Nothing outside the invitation can be added:
/// unknown accounts are ignored and every action must already be invited. The dependency rules hold for the result
/// (draft and organize need read, delete needs organize, send needs draft).
pub fn narrow(invited: &[InviteGrant], selected: &BTreeMap<String, Actions>) -> Vec<InviteGrant> {
    let mut out = Vec::new();
    for g in invited {
        let Some(want) = selected.get(&g.account_id) else { continue };
        let Ok(have) = Actions::parse(&g.actions) else { continue };
        let a = have.intersect(want);
        if !a.read {
            continue;
        }
        out.push(InviteGrant { account_id: g.account_id.clone(), alias: g.alias.clone(), actions: a.to_string() });
    }
    out
}

/// Consumes the invitation and creates its connection in the caller's transaction. Returns the new client id and,
/// for `kind = "token"`, its bearer token. Fails if another redemption won the race (conditional update).
pub fn consume(
    tx: &Transaction,
    pepper: &Pepper,
    inv: &Invitation,
    grants: &[InviteGrant],
    kind: &str,
    created_via: &str,
) -> anyhow::Result<Option<(String, Option<String>)>> {
    if grants.is_empty() {
        bail!("no mailbox selected");
    }
    let now = util::now_unix();
    let won = tx.execute(
        "UPDATE invitations SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL AND expires_at > ?1",
        params![now, inv.id],
    )?;
    if won != 1 {
        return Ok(None);
    }
    let client_id = util::new_id();
    let token = (kind == "token").then(|| tokens::generate(tokens::CLIENT_TOKEN_PREFIX));
    let hash = token.as_ref().map(|t| pepper.hash("client", t));
    let expires_at = inv.expires_in_secs.map(|s| now + s);
    tx.execute(
        "INSERT INTO clients(id, name, project_id, kind, token_hash, allowed_cidrs, expires_at, created_at, created_via) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![client_id, inv.connection_name, inv.project_id, kind, hash, inv.allowed_cidrs, expires_at, now, created_via],
    )
    .map_err(|e| {
        if ops::is_unique(&e) { anyhow!("a connection named '{}' already exists", inv.connection_name) } else { e.into() }
    })?;
    let map: BTreeMap<String, (String, Actions)> = grants
        .iter()
        .filter_map(|g| Some((g.account_id.clone(), (g.alias.clone(), Actions::parse(&g.actions).ok()?))))
        .collect();
    ops::write_grants(tx, &client_id, &map)?;
    tx.execute("UPDATE invitations SET issued_client_id = ?1 WHERE id = ?2", params![client_id, inv.id])?;
    Ok(Some((client_id, token)))
}

/// Writes one audit record for an onboarding/OAuth state change (spec 5.6: authentication changes are audited).
pub fn audit_auth(
    conn: &Connection,
    action: &str,
    actor: &str,
    project: Option<&str>,
    object_ids: Vec<String>,
    code: &str,
    ip: Option<std::net::IpAddr>,
) -> anyhow::Result<()> {
    audit::append(
        conn,
        &AuditRecord {
            request_id: util::new_id(),
            actor: actor.to_string(),
            project: project.map(str::to_string),
            tool_or_action: action.to_string(),
            object_ids,
            result_code: code.to_string(),
            source_ip: ip.map(|i| i.to_string()),
            ..Default::default()
        },
    )?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemBody {
    invitation: String,
}

fn json_no_store(status: StatusCode, v: Value) -> Response {
    let mut r = (status, axum::Json(v)).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.headers_mut().insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

/// POST `/connect/redeem` with `{"invitation": "dovei_..."}`. Issues one connection token. The invitation travels
/// only in the request body. Any failure is the same generic `invalid_invitation`.
pub async fn redeem(State(app): State<Arc<App>>, req: Request) -> Response {
    let ip = crate::http::request_ip(&req);
    let limit = app.cfg.oauth.redeem_per_minute;
    let key = format!("redeem:{}", crate::oauth::ip_bucket(ip));
    if let Some(wait) = app.rate_limiter.check(&key, limit, limit) {
        let mut r = json_no_store(StatusCode::TOO_MANY_REQUESTS, json!({ "error": "rate_limited" }));
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(wait));
        return r;
    }
    let body: Bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return json_no_store(StatusCode::PAYLOAD_TOO_LARGE, json!({ "error": "invalid_request" })),
    };
    let Ok(body) = serde_json::from_slice::<RedeemBody>(&body) else {
        return json_no_store(StatusCode::BAD_REQUEST, json!({ "error": "invalid_request" }));
    };
    let pepper = app.pepper.clone();
    let mcp_url = crate::mcp::resource_url(&app);
    let result = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let Some(inv) = peek(&tx, &pepper, &body.invitation)? else {
                drop(tx);
                audit_auth(c, "invite.redeem", "anonymous", None, vec![], "invalid_invitation", ip)?;
                return Ok(None);
            };
            // The connection would refuse every request from here anyway (`--allow-ip`); refusing now keeps the
            // invitation for the address it was meant for. Same generic error as an unknown invitation.
            if !crate::policy::ip_allowed(&inv.allowed_cidrs, ip) {
                drop(tx);
                audit_auth(
                    c,
                    "invite.redeem",
                    &inv.connection_name,
                    Some(&inv.project_name),
                    vec![],
                    "ip_not_allowed",
                    ip,
                )?;
                return Ok(None);
            }
            let grants = inv.grants.clone();
            if grants.is_empty() {
                drop(tx);
                audit_auth(c, "invite.redeem", &inv.connection_name, Some(&inv.project_name), vec![], "no_grants", ip)?;
                return Ok(None);
            }
            let Some((client_id, token)) = consume(&tx, &pepper, &inv, &grants, "token", "invite")? else {
                drop(tx);
                audit_auth(c, "invite.redeem", &inv.connection_name, Some(&inv.project_name), vec![], "lost_race", ip)?;
                return Ok(None);
            };
            let mailboxes: Vec<Value> = crate::policy::load_mailboxes(&tx, &client_id)?
                .into_iter()
                .map(|m| json!({ "account": m.alias, "email": m.email, "actions": m.actions.to_string() }))
                .collect();
            let expires_at: Option<i64> =
                tx.query_row("SELECT expires_at FROM clients WHERE id = ?1", [&client_id], |r| r.get(0))?;
            audit_auth(
                &tx,
                "invite.redeem",
                &inv.connection_name,
                Some(&inv.project_name),
                vec![inv.connection_name.clone()],
                "ok",
                ip,
            )?;
            tx.commit()?;
            Ok(Some(json!({
                "token": token,
                "connection": inv.connection_name,
                "project": inv.project_name,
                "mailboxes": mailboxes,
                "mcp_url": mcp_url,
                "expires_at": expires_at.map(util::rfc3339),
            })))
        })
        .await;
    match result {
        Ok(Some(v)) => json_no_store(StatusCode::OK, v),
        Ok(None) => json_no_store(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_invitation", "error_description": "The invitation is invalid, expired or already used. Ask the operator for a new one." }),
        ),
        Err(e) => {
            tracing::error!(error = %e, "invitation redemption failed internally");
            json_no_store(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "server_error" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(id: &str, a: &str) -> InviteGrant {
        InviteGrant { account_id: id.into(), alias: id.into(), actions: a.into() }
    }

    /// The conditional update is the last line of defense when two redemptions loaded the same invitation.
    #[test]
    fn consume_is_single_use_even_with_a_stale_view() {
        let env = crate::testing::TestEnv::new();
        env.add_account("info", "info@acme.test", "rt");
        let app = env.app.clone();
        app.store
            .call_blocking(|c| {
                let tx = c.transaction()?;
                ops::project_create(&tx, "acme")?;
                ops::project_add_account(&tx, "acme", "info")?;
                let ni = NewInvite {
                    name: "dup",
                    project: "acme",
                    accounts: &["info".to_string()],
                    capabilities: "read",
                    expires_in_secs: None,
                    allow_ip: &[],
                };
                let secret = create(&tx, &app.pepper, false, &ni)?["invitation"].as_str().unwrap().to_string();
                let inv = peek(&tx, &app.pepper, &secret)?.expect("valid");
                let first = consume(&tx, &app.pepper, &inv, &inv.grants, "token", "invite")?;
                assert!(first.is_some());
                // Same (stale) view again: must not create a second connection.
                tx.execute("DELETE FROM clients", [])?;
                let second = consume(&tx, &app.pepper, &inv, &inv.grants, "token", "invite")?;
                assert!(second.is_none());
                assert!(peek(&tx, &app.pepper, &secret)?.is_none(), "used invitations are not found");
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn narrowing_never_broadens() {
        let all = |s: &str| Actions::parse_grant(s).unwrap();
        let invited = vec![g("a", "read,draft"), g("b", "read"), g("c", "read,organize,delete")];
        let mut sel = BTreeMap::new();
        sel.insert("a".to_string(), all("full,send"));
        sel.insert("b".to_string(), all("assistant"));
        sel.insert("c".to_string(), all("full,send"));
        sel.insert("x".to_string(), all("full,send"));
        let out = narrow(&invited, &sel);
        assert_eq!(out, vec![g("a", "read,draft"), g("b", "read"), g("c", "read,organize,delete")]);
        // Dropping read drops the mailbox; dropping draft keeps read; dropping organize drops delete.
        let mut sel = BTreeMap::new();
        sel.insert("a".to_string(), Actions { read: true, ..Default::default() });
        sel.insert("b".to_string(), Actions { draft: true, ..Default::default() });
        sel.insert("c".to_string(), Actions { read: true, delete: true, ..Default::default() });
        assert_eq!(narrow(&invited, &sel), vec![g("a", "read"), g("c", "read")]);
    }
}
