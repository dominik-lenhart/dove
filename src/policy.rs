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
    Organize,
    Delete,
    Send,
}

impl Capability {
    pub const ALL: [Capability; 5] =
        [Capability::Read, Capability::Draft, Capability::Organize, Capability::Delete, Capability::Send];

    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Read => "read",
            Capability::Draft => "draft",
            Capability::Organize => "organize",
            Capability::Delete => "delete",
            Capability::Send => "send",
        }
    }
}

/// The actions one grant allows on one mailbox (design 2026-11-13 section 1). Stored expanded as a comma list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Actions {
    pub read: bool,
    pub draft: bool,
    pub organize: bool,
    pub delete: bool,
    pub send: bool,
}

/// Presets: input sugar for `--grant` and the approval page. Never stored, so a preset changed later never widens
/// an existing grant. `send` is in none of them.
pub const PRESETS: &[(&str, &str)] = &[
    ("reader", "read"),
    ("drafter", "read,draft"),
    ("assistant", "read,draft,organize"),
    ("full", "read,draft,organize,delete"),
];

impl Actions {
    /// Parses a stored action list (`read,draft,organize`). Presets are not accepted here; see
    /// [`Actions::parse_grant`] for operator input. Enforces the dependency rules.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut a = Actions::default();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if !a.set(part) {
                return Err(format!(
                    "unknown action '{}' (expected read, draft, organize, delete or send)",
                    part.chars().take(32).collect::<String>()
                ));
            }
        }
        a.validate()?;
        Ok(a)
    }

    /// Parses operator input: actions and presets, mixed (`assistant,send`, `reader,organize`). Unknown words are an
    /// error that names the accepted ones.
    pub fn parse_grant(s: &str) -> Result<Self, String> {
        let mut a = Actions::default();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let word = part.to_ascii_lowercase();
            if let Some((_, expanded)) = PRESETS.iter().find(|(name, _)| *name == word) {
                for w in expanded.split(',') {
                    a.set(w);
                }
            } else if !a.set(&word) {
                return Err(format!(
                    "unknown action or preset '{}' (actions: read, draft, organize, delete, send; presets: reader, \
                     drafter, assistant, full)",
                    part.chars().take(32).collect::<String>()
                ));
            }
        }
        a.validate()?;
        Ok(a)
    }

    /// The actions of a preset by name.
    pub fn preset(name: &str) -> Option<Self> {
        PRESETS.iter().find(|(n, _)| *n == name).map(|(_, a)| Actions::parse(a).expect("valid preset"))
    }

    fn set(&mut self, word: &str) -> bool {
        match word {
            "read" => self.read = true,
            "draft" => self.draft = true,
            "organize" => self.organize = true,
            "delete" => self.delete = true,
            "send" => self.send = true,
            _ => return false,
        }
        true
    }

    /// draft => read, organize => read, delete => organize, send => draft (FR-P2, design section 1).
    fn validate(&self) -> Result<(), String> {
        if *self == Actions::default() {
            return Err("empty action list".into());
        }
        if self.draft && !self.read {
            return Err("draft requires read".into());
        }
        if self.organize && !self.read {
            return Err("organize requires read".into());
        }
        if self.delete && !self.organize {
            return Err("delete requires organize".into());
        }
        if self.send && !(self.read && self.draft) {
            return Err("send requires read and draft".into());
        }
        Ok(())
    }

    /// Actions in both sets. The result still satisfies the dependency rules (or is empty).
    pub fn intersect(&self, other: &Actions) -> Actions {
        let read = self.read && other.read;
        let draft = read && self.draft && other.draft;
        let organize = read && self.organize && other.organize;
        let delete = organize && self.delete && other.delete;
        let send = draft && self.send && other.send;
        Actions { read, draft, organize, delete, send }
    }

    /// Actions in either set (a base grant and temporary grants, design 2026-11-14 section 4.5), re-validated by the
    /// dependency rules. Two valid sets always give a valid union; anything else yields no access at all (fail
    /// closed), never a partial set.
    pub fn union(&self, other: &Actions) -> Actions {
        let u = Actions {
            read: self.read || other.read,
            draft: self.draft || other.draft,
            organize: self.organize || other.organize,
            delete: self.delete || other.delete,
            send: self.send || other.send,
        };
        if u.validate().is_ok() { u } else { Actions::default() }
    }

    pub fn has(&self, cap: Capability) -> bool {
        match cap {
            Capability::Read => self.read,
            Capability::Draft => self.draft,
            Capability::Organize => self.organize,
            Capability::Delete => self.delete,
            Capability::Send => self.send,
        }
    }
}

impl std::fmt::Display for Actions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<&str> = Capability::ALL.iter().filter(|c| self.has(**c)).map(|c| c.as_str()).collect();
        f.write_str(&parts.join(","))
    }
}

/// Which upstream a mailbox lives on. Tools dispatch on it; authorization does not depend on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    Gmail,
    Imap,
}

impl Provider {
    pub fn parse(s: &str) -> Self {
        if s == "imap" { Provider::Imap } else { Provider::Gmail }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Gmail => "gmail",
            Provider::Imap => "imap",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Mailbox {
    pub account_id: String,
    pub alias: String,
    pub email: String,
    pub status: String,
    /// The effective actions: the base grant united with every unexpired temporary grant.
    pub actions: Actions,
    pub index_enabled: bool,
    pub provider: Provider,
    /// Unexpired temporary grants on this mailbox (approved access requests), soonest expiry first. Their actions are
    /// already part of `actions`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub temporary: Vec<TempGrant>,
}

/// One temporary grant (`client_grant_extras` row) as the policy saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TempGrant {
    pub actions: Actions,
    /// Unix seconds.
    pub expires_at: i64,
    pub request_id: String,
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
    /// Hide secrets in overview results (`clients set-redaction`, PLAN A60).
    pub redact_secrets: bool,
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
                format!("this connection lacks {} on this mailbox", cap.as_str()),
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

/// Loads effective mailboxes for a client: grants intersected with current project membership, united with its
/// unexpired temporary grants (also intersected with project membership).
pub fn load_mailboxes(conn: &Connection, client_id: &str) -> anyhow::Result<Vec<Mailbox>> {
    load_mailboxes_at(conn, client_id, util::now_unix())
}

/// [`load_mailboxes`] at `now` (unix seconds): a temporary grant counts while `expires_at > now`. Expiry therefore
/// takes effect on the first request after it, without waiting for the worker that deletes the row.
pub fn load_mailboxes_at(conn: &Connection, client_id: &str, now: i64) -> anyhow::Result<Vec<Mailbox>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, a.alias, a.email, a.status, cm.actions, a.index_enabled, a.provider \
         FROM client_mailboxes cm \
         JOIN clients c ON c.id = cm.client_id \
         JOIN accounts a ON a.id = cm.account_id \
         JOIN project_accounts pa ON pa.project_id = c.project_id AND pa.account_id = a.id \
         WHERE cm.client_id = ?1 ORDER BY a.alias",
    )?;
    let row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<Mailbox> {
        let actions: String = r.get(4)?;
        Ok(Mailbox {
            account_id: r.get(0)?,
            alias: r.get(1)?,
            email: r.get(2)?,
            status: r.get(3)?,
            actions: Actions::parse(&actions).unwrap_or_default(),
            index_enabled: r.get::<_, i64>(5)? != 0,
            provider: Provider::parse(&r.get::<_, String>(6)?),
            temporary: vec![],
        })
    };
    let mut out: Vec<Mailbox> = stmt.query_map([client_id], row)?.collect::<Result<_, _>>()?;
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, a.alias, a.email, a.status, e.actions, a.index_enabled, a.provider, e.expires_at, e.request_id \
         FROM client_grant_extras e \
         JOIN clients c ON c.id = e.client_id \
         JOIN accounts a ON a.id = e.account_id \
         JOIN project_accounts pa ON pa.project_id = c.project_id AND pa.account_id = a.id \
         WHERE e.client_id = ?1 AND e.expires_at > ?2 ORDER BY e.expires_at, e.request_id",
    )?;
    let extras: Vec<(Mailbox, TempGrant)> = stmt
        .query_map(params![client_id, now], |r| {
            let m = row(r)?;
            let t = TempGrant { actions: m.actions, expires_at: r.get(7)?, request_id: r.get(8)? };
            Ok((m, t))
        })?
        .collect::<Result<_, _>>()?;
    for (m, t) in extras {
        // A stored list that does not parse grants nothing (`parse` refused it, so its actions are empty).
        if t.actions == Actions::default() {
            continue;
        }
        match out.iter_mut().find(|b| b.account_id == m.account_id) {
            Some(b) => {
                b.actions = b.actions.union(&t.actions);
                b.temporary.push(t);
            }
            None => out.push(Mailbox { temporary: vec![t], ..m }),
        }
    }
    // A broken base row (empty actions) with no temporary grant stays as before: listed, allowing nothing.
    out.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(out)
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
            "SELECT c.name, c.project_id, p.name, c.auth_epoch, c.allowed_cidrs, c.expires_at, c.revoked_at, c.last_ip, \
             c.redact_secrets FROM clients c JOIN projects p ON p.id = c.project_id WHERE c.id = ?1",
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
                    r.get::<_, bool>(8)?,
                ))
            },
        )
        .optional()?;
    let Some((name, project_id, project_name, epoch, cidrs, expires_at, revoked_at, last_ip, redact_secrets)) = row
    else {
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
            redact_secrets,
        },
        new_ip,
    }))
}

/// Loads a live client (not revoked, not expired) by id, as [`authenticate`] does after a token lookup, for work Dove
/// does on the client's behalf without a request (scheduled sends) and for the operator's view of its drafts. None
/// when the client is unknown, revoked or expired.
pub fn load_client(conn: &Connection, client_id: &str, allow_send: bool) -> anyhow::Result<Option<ClientCtx>> {
    let now = util::now_unix();
    let row = conn
        .query_row(
            "SELECT c.name, c.project_id, p.name, c.auth_epoch, c.redact_secrets FROM clients c \
             JOIN projects p ON p.id = c.project_id \
             WHERE c.id = ?1 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > ?2)",
            params![client_id, now],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, bool>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((client_name, project_id, project_name, auth_epoch, redact_secrets)) = row else { return Ok(None) };
    Ok(Some(ClientCtx {
        client_id: client_id.to_string(),
        client_name,
        project_id,
        project_name,
        auth_epoch,
        source_ip: None,
        mailboxes: load_mailboxes(conn, client_id)?,
        allow_send,
        redact_secrets,
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
        // New actions and their dependencies.
        assert_eq!(Actions::parse("read,organize").unwrap().to_string(), "read,organize");
        assert_eq!(Actions::parse("delete,organize,read").unwrap().to_string(), "read,organize,delete");
        assert!(Actions::parse("organize").is_err());
        assert!(Actions::parse("read,delete").is_err());
        assert!(Actions::parse("read,organize,send").is_err());
        // Stored lists never take presets.
        assert!(Actions::parse("full").is_err());
        assert!(Actions::parse("").is_err());
    }

    #[test]
    fn presets_expand_and_mix() {
        let p = |s: &str| Actions::parse_grant(s).map(|a| a.to_string());
        assert_eq!(p("reader").unwrap(), "read");
        assert_eq!(p("drafter").unwrap(), "read,draft");
        assert_eq!(p("assistant").unwrap(), "read,draft,organize");
        assert_eq!(p("full").unwrap(), "read,draft,organize,delete");
        assert_eq!(p("assistant,send").unwrap(), "read,draft,organize,send");
        assert_eq!(p("full,send").unwrap(), "read,draft,organize,delete,send");
        assert_eq!(p("reader,organize").unwrap(), "read,organize");
        assert_eq!(p("Read, Draft").unwrap(), "read,draft");
        assert_eq!(p("read,draft,organize").unwrap(), "read,draft,organize");
        // Send is in no preset.
        for (name, _) in PRESETS {
            assert!(!Actions::parse_grant(name).unwrap().send, "{name}");
        }
        let e = Actions::parse_grant("assistent").unwrap_err();
        assert!(e.contains("assistent") && e.contains("presets"), "{e}");
        assert!(Actions::parse_grant("reader,send").unwrap_err().contains("send requires"));
        assert!(Actions::parse_grant("reader,delete").unwrap_err().contains("delete requires organize"));
        assert!(Actions::parse_grant("read,admin").is_err());
        // Every expansion is a valid stored list.
        for (name, _) in PRESETS {
            let a = Actions::parse_grant(name).unwrap();
            assert_eq!(Actions::parse(&a.to_string()).unwrap(), a);
        }
    }

    #[test]
    fn intersect_keeps_dependencies() {
        let full = Actions::parse_grant("full,send").unwrap();
        let no_read = Actions { delete: true, organize: true, ..Default::default() };
        assert_eq!(full.intersect(&no_read), Actions::default());
        let no_org = Actions::parse("read,draft,send").unwrap();
        let a = Actions { delete: true, ..full }.intersect(&Actions { organize: false, ..full });
        assert_eq!(a.to_string(), "read,draft,send");
        assert_eq!(full.intersect(&no_org).to_string(), "read,draft,send");
    }

    #[test]
    fn union_keeps_dependencies() {
        let p = |s: &str| Actions::parse(s).unwrap();
        assert_eq!(p("read").union(&p("read,draft")), p("read,draft"));
        assert_eq!(p("read,draft").union(&p("read,organize")), p("read,draft,organize"));
        assert_eq!(
            p("read,draft,send").union(&p("read,organize,delete")).to_string(),
            "read,draft,organize,delete,send"
        );
        // An invalid operand cannot produce a partial set: the union is empty then.
        let broken = Actions { draft: true, ..Default::default() };
        assert_eq!(Actions::default().union(&broken), Actions::default());
        assert_eq!(broken.union(&Actions { delete: true, ..Default::default() }), Actions::default());
    }

    /// Temporary grants: united with the base grant while unexpired, intersected with the project, and a broken
    /// stored list grants nothing.
    #[test]
    fn load_mailboxes_unites_unexpired_temporary_grants() {
        let s = crate::store::Store::open_in_memory().unwrap();
        s.call_blocking(|c| {
            c.execute_batch(
                "INSERT INTO projects(id, name, created_at) VALUES ('p', 'p', 0), ('q', 'q', 0);
                 INSERT INTO clients(id, name, project_id, kind, created_at, created_via) VALUES ('c', 'c', 'p', 'token', 0, 'cli');
                 INSERT INTO accounts(id, alias, email, status) VALUES ('a', 'a', 'a@x.test', 'active'),
                   ('b', 'b', 'b@x.test', 'active'), ('o', 'o', 'o@x.test', 'active'), ('z', 'z', 'z@x.test', 'active');
                 INSERT INTO project_accounts(project_id, account_id, added_at) VALUES ('p', 'a', 0), ('p', 'b', 0),
                   ('q', 'o', 0), ('p', 'z', 0);
                 INSERT INTO requests(id, client_id, project_id, kind, status, created_at, expires_at)
                   VALUES ('r', 'c', 'p', 'access', 'approved', 0, 0);
                 INSERT INTO client_mailboxes(client_id, account_id, actions) VALUES ('c', 'a', 'read');
                 INSERT INTO client_grant_extras(client_id, account_id, request_id, actions, granted_at, expires_at) VALUES
                   ('c', 'a', 'r', 'read,draft', 0, 100), ('c', 'b', 'r', 'read', 0, 100),
                   ('c', 'o', 'r', 'read', 0, 100), ('c', 'z', 'r', 'draft', 0, 100);",
            )?;
            let view = |now| -> anyhow::Result<Vec<(String, String, usize)>> {
                Ok(load_mailboxes_at(c, "c", now)?
                    .into_iter()
                    .map(|m| (m.alias, m.actions.to_string(), m.temporary.len()))
                    .collect())
            };
            let s = |a: &str, b: &str, n| (a.to_string(), b.to_string(), n);
            // `o` is outside the project, `z`'s stored list breaks the rules: neither appears.
            assert_eq!(view(99)?, vec![s("a", "read,draft", 1), s("b", "read", 1)]);
            // At the expiry only the base grant is left.
            assert_eq!(view(100)?, vec![s("a", "read", 0)]);
            Ok(())
        })
        .unwrap();
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
            provider: Provider::Gmail,
            temporary: vec![],
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
                mb("5", "tidy", "read,organize", "active"),
                mb("6", "bin", "read,organize,delete", "active"),
            ],
            allow_send,
            redact_secrets: false,
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
        // Organize and delete are separate grants.
        assert!(c.authorize(Capability::Organize, "tidy").is_ok());
        assert_eq!(c.authorize(Capability::Delete, "tidy").unwrap_err().code, ErrorCode::Forbidden);
        assert_eq!(c.authorize(Capability::Organize, "info").unwrap_err().code, ErrorCode::Forbidden);
        assert!(c.authorize(Capability::Delete, "bin").is_ok());
        assert_eq!(c.authorize(Capability::Delete, "nowhere").unwrap_err().code, ErrorCode::NotFound);
        let names: Vec<&str> = c.with_capability(Capability::Delete).map(|m| m.alias.as_str()).collect();
        assert_eq!(names, vec!["bin"]);
    }
}
