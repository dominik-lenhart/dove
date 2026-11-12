//! Authorization: the single place that decides (spec 7.1 "Policy", 5.2, FR-P5).
//!
//! A client's effective mailboxes are the intersection of its explicit mailbox grants and its project's current
//! accounts. Every request reloads this from the state store, so admin changes apply on the next request (FR-P4).

use std::net::IpAddr;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::error::{ErrorCode, ToolError};
use crate::tokens::{self, Pepper};
use crate::util;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Read,
    Draft,
    Send,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Actions {
    pub read: bool,
    pub draft: bool,
    pub send: bool,
}

impl Actions {
    /// Parses `read,draft[,send]`. Enforces draft => read and send => read + draft (FR-P2).
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut a = Actions::default();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part {
                "read" => a.read = true,
                "draft" => a.draft = true,
                "send" => a.send = true,
                other => {
                    return Err(format!("unknown action '{other}' (expected read, draft or send)"));
                }
            }
        }
        if !a.read && !a.draft && !a.send {
            return Err("empty action list".into());
        }
        if a.draft && !a.read {
            return Err("draft requires read".into());
        }
        if a.send && !(a.read && a.draft) {
            return Err("send requires read and draft".into());
        }
        Ok(a)
    }

    pub fn has(&self, cap: Capability) -> bool {
        match cap {
            Capability::Read => self.read,
            Capability::Draft => self.draft,
            Capability::Send => self.send,
        }
    }
}

impl std::fmt::Display for Actions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.read {
            parts.push("read");
        }
        if self.draft {
            parts.push("draft");
        }
        if self.send {
            parts.push("send");
        }
        f.write_str(&parts.join(","))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Mailbox {
    pub account_id: String,
    pub alias: String,
    pub email: String,
    pub status: String,
    pub actions: Actions,
    pub index_enabled: bool,
}

/// The authenticated caller, loaded fresh for each request.
#[derive(Debug, Clone)]
pub struct ClientCtx {
    pub client_id: String,
    pub client_name: String,
    pub project_id: String,
    pub project_name: String,
    pub auth_epoch: i64,
    pub source_ip: Option<IpAddr>,
    pub mailboxes: Vec<Mailbox>,
    /// Instance send gate at load time (spec 6.3).
    pub allow_send: bool,
}

impl ClientCtx {
    /// Resolves an alias or email within the effective grants. Anything else is `not_found`.
    pub fn resolve(&self, account: &str) -> Result<&Mailbox, ToolError> {
        let account = account.trim();
        self.mailboxes
            .iter()
            .find(|m| m.alias == account || m.email.eq_ignore_ascii_case(account))
            .ok_or_else(ToolError::not_found)
    }

    pub fn resolve_id(&self, account_id: &str) -> Result<&Mailbox, ToolError> {
        self.mailboxes.iter().find(|m| m.account_id == account_id).ok_or_else(ToolError::not_found)
    }

    fn effective(&self, m: &Mailbox, cap: Capability) -> bool {
        m.actions.has(cap) && (cap != Capability::Send || self.allow_send)
    }

    /// `authorize(client, capability, account)`: resolve, check capability, check account status.
    pub fn authorize(&self, cap: Capability, account: &str) -> Result<&Mailbox, ToolError> {
        let m = self.resolve(account)?;
        self.check(cap, m)?;
        Ok(m)
    }

    pub fn authorize_id(&self, cap: Capability, account_id: &str) -> Result<&Mailbox, ToolError> {
        let m = self.resolve_id(account_id)?;
        self.check(cap, m)?;
        Ok(m)
    }

    fn check(&self, cap: Capability, m: &Mailbox) -> Result<(), ToolError> {
        if !self.effective(m, cap) {
            return Err(ToolError::new(
                ErrorCode::Forbidden,
                format!("this connection lacks {cap:?} on this mailbox").to_lowercase(),
            ));
        }
        if m.status != "active" {
            return Err(ToolError::unavailable());
        }
        Ok(())
    }

    /// Mailboxes on which `cap` is granted (regardless of status).
    pub fn with_capability(&self, cap: Capability) -> impl Iterator<Item = &Mailbox> {
        self.mailboxes.iter().filter(move |m| self.effective(m, cap))
    }

    pub fn has_any(&self, cap: Capability) -> bool {
        self.with_capability(cap).next().is_some()
    }
}

/// Loads effective mailboxes for a client: grants intersected with current project membership.
pub fn load_mailboxes(conn: &Connection, client_id: &str) -> anyhow::Result<Vec<Mailbox>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, a.alias, a.email, a.status, cm.actions, a.index_enabled \
         FROM client_mailboxes cm \
         JOIN clients c ON c.id = cm.client_id \
         JOIN accounts a ON a.id = cm.account_id \
         JOIN project_accounts pa ON pa.project_id = c.project_id AND pa.account_id = a.id \
         WHERE cm.client_id = ?1 ORDER BY a.alias",
    )?;
    let rows = stmt.query_map([client_id], |r| {
        let actions: String = r.get(4)?;
        Ok(Mailbox {
            account_id: r.get(0)?,
            alias: r.get(1)?,
            email: r.get(2)?,
            status: r.get(3)?,
            actions: Actions::parse(&actions).unwrap_or_default(),
            index_enabled: r.get::<_, i64>(5)? != 0,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

#[derive(Debug)]
pub enum AuthFailure {
    /// Unknown, revoked, expired or wrong-IP token. All map to HTTP 401 with no detail.
    Unauthorized,
}

/// Checks whether `ip` is within any CIDR in the JSON list. An empty list allows any address.
pub fn ip_allowed(cidrs_json: &str, ip: Option<IpAddr>) -> bool {
    let cidrs: Vec<String> = serde_json::from_str(cidrs_json).unwrap_or_default();
    if cidrs.is_empty() {
        return true;
    }
    let Some(ip) = ip else { return false };
    cidrs.iter().filter_map(|c| c.parse::<ipnet::IpNet>().ok()).any(|net| net.contains(&ip))
}

pub struct Authenticated {
    pub ctx: ClientCtx,
    /// True when this IP was not seen before for this client (notifier input).
    pub new_ip: bool,
}

/// Authenticates a bearer secret (client token or downstream OAuth access token) and loads the caller.
pub fn authenticate(
    conn: &Connection,
    pepper: &Pepper,
    bearer: &str,
    ip: Option<IpAddr>,
    allow_send: bool,
    resource: &str,
) -> anyhow::Result<Result<Authenticated, AuthFailure>> {
    let now = util::now_unix();
    let client_id: Option<String> = if tokens::looks_valid(tokens::CLIENT_TOKEN_PREFIX, bearer) {
        conn.query_row(
            "SELECT id FROM clients WHERE token_hash = ?1 AND kind = 'token'",
            [pepper.hash("client", bearer)],
            |r| r.get(0),
        )
        .optional()?
    } else if tokens::looks_valid(tokens::OAUTH_ACCESS_PREFIX, bearer) {
        conn.query_row(
            "SELECT connection_id FROM oauth_tokens WHERE token_hash = ?1 AND kind = 'access' \
             AND revoked_at IS NULL AND expires_at > ?2 AND resource = ?3",
            params![pepper.hash("oauth-access", bearer), now, resource],
            |r| r.get(0),
        )
        .optional()?
    } else {
        None
    };
    let Some(client_id) = client_id else {
        return Ok(Err(AuthFailure::Unauthorized));
    };
    let row = conn
        .query_row(
            "SELECT c.name, c.project_id, p.name, c.auth_epoch, c.allowed_cidrs, c.expires_at, c.revoked_at, c.last_ip \
             FROM clients c JOIN projects p ON p.id = c.project_id WHERE c.id = ?1",
            [&client_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((name, project_id, project_name, epoch, cidrs, expires_at, revoked_at, last_ip)) = row else {
        return Ok(Err(AuthFailure::Unauthorized));
    };
    if revoked_at.is_some() || expires_at.is_some_and(|e| e <= now) || !ip_allowed(&cidrs, ip) {
        return Ok(Err(AuthFailure::Unauthorized));
    }
    let ip_s = ip.map(|i| i.to_string());
    let new_ip = last_ip.is_some() && ip_s.is_some() && last_ip != ip_s;
    conn.execute(
        "UPDATE clients SET last_used_at = ?1, last_ip = COALESCE(?2, last_ip) WHERE id = ?3",
        params![now, ip_s, client_id],
    )?;
    let mailboxes = load_mailboxes(conn, &client_id)?;
    Ok(Ok(Authenticated {
        ctx: ClientCtx {
            client_id,
            client_name: name,
            project_id,
            project_name,
            auth_epoch: epoch,
            source_ip: ip,
            mailboxes,
            allow_send,
        },
        new_ip,
    }))
}

/// Re-reads whether the client is still valid and returns its current epoch (cursor resume / release checks).
pub fn current_epoch(conn: &Connection, client_id: &str) -> anyhow::Result<Option<i64>> {
    let now = util::now_unix();
    Ok(conn
        .query_row(
            "SELECT auth_epoch FROM clients WHERE id = ?1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?2)",
            params![client_id, now],
            |r| r.get(0),
        )
        .optional()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_rules() {
        assert!(Actions::parse("read").is_ok());
        assert!(Actions::parse("read,draft").is_ok());
        assert!(Actions::parse("draft").is_err());
        assert!(Actions::parse("read,send").is_err());
        assert!(Actions::parse("read,draft,send").is_ok());
        assert!(Actions::parse("read,admin").is_err());
        assert_eq!(Actions::parse("draft,read").unwrap().to_string(), "read,draft");
    }

    #[test]
    fn cidr_allowlist() {
        assert!(ip_allowed("[]", None));
        assert!(ip_allowed(r#"["10.0.0.0/8"]"#, Some("10.1.2.3".parse().unwrap())));
        assert!(!ip_allowed(r#"["10.0.0.0/8"]"#, Some("192.168.1.1".parse().unwrap())));
        assert!(!ip_allowed(r#"["10.0.0.0/8"]"#, None));
    }

    fn ctx(allow_send: bool) -> ClientCtx {
        let mb = |id: &str, alias: &str, a: &str, status: &str| Mailbox {
            account_id: id.into(),
            alias: alias.into(),
            email: format!("{alias}@example.com"),
            status: status.into(),
            actions: Actions::parse(a).unwrap(),
            index_enabled: false,
        };
        ClientCtx {
            client_id: "c".into(),
            client_name: "c".into(),
            project_id: "p".into(),
            project_name: "p".into(),
            auth_epoch: 1,
            source_ip: None,
            mailboxes: vec![
                mb("1", "info", "read,draft", "active"),
                mb("2", "billing", "read", "active"),
                mb("3", "ops", "read,draft,send", "active"),
                mb("4", "old", "read", "reauth_required"),
            ],
            allow_send,
        }
    }

    #[test]
    fn authorize_matrix() {
        let c = ctx(false);
        assert!(c.authorize(Capability::Draft, "info").is_ok());
        assert!(c.authorize(Capability::Read, "INFO@example.com").is_ok());
        assert_eq!(c.authorize(Capability::Draft, "billing").unwrap_err().code, ErrorCode::Forbidden);
        assert_eq!(c.authorize(Capability::Read, "secret").unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(c.authorize(Capability::Read, "old").unwrap_err().code, ErrorCode::AccountUnavailable);
        // Send needs the instance gate too.
        assert_eq!(c.authorize(Capability::Send, "ops").unwrap_err().code, ErrorCode::Forbidden);
        assert!(!c.has_any(Capability::Send));
        let c = ctx(true);
        assert!(c.authorize(Capability::Send, "ops").is_ok());
        assert_eq!(c.authorize(Capability::Send, "info").unwrap_err().code, ErrorCode::Forbidden);
    }
}
