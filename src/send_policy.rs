//! Recipient rules for direct sends (PLAN A82).
//!
//! Per mailbox the owner can restrict where an agent may send on its own (`send_draft` with the `send` grant):
//! `allow_domains` (empty: any domain; a rule matches the exact domain and its subdomains) and
//! `unknown_recipients` (`refuse`: only addresses the mailbox has exchanged mail with). Owner-approved sends
//! (`request_send`) are not checked: the owner saw the recipients when approving.
//!
//! "Exchanged mail with" is read from the published index generation of the mailbox: a message from the address, or a
//! `SENT` message to it (To, Cc or Bcc). Without a published generation the rule cannot be checked and the send is
//! refused (fail closed). From headers can be forged, so `refuse` keeps an agent away from new addresses but does not
//! stop a sender who already wrote to the mailbox; `allow_domains` is the hard limit.
//!
//! Domains are configuration of the owner and stay out of logs and audit records, which carry counts only.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};

use crate::admin::ops::account_id;
use crate::app::App;
use crate::error::{ErrorCode, ToolError};
use crate::index::ingest::{ROLE_BCC, ROLE_CC, ROLE_FROM, ROLE_TO};
use crate::util;

/// At most this many domains per mailbox.
pub const MAX_DOMAINS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unknown {
    Allow,
    Refuse,
}

impl Unknown {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "refuse" => Ok(Self::Refuse),
            _ => bail!("unknown_recipients must be 'allow' or 'refuse'"),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Refuse => "refuse",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPolicy {
    /// Lowercased ASCII domains; empty means any.
    pub allow_domains: Vec<String>,
    pub unknown_recipients: Unknown,
}

impl SendPolicy {
    /// Whether the policy restricts anything at all.
    pub fn is_open(&self) -> bool {
        self.allow_domains.is_empty() && self.unknown_recipients == Unknown::Allow
    }

    pub fn to_json(&self) -> Value {
        json!({ "allow_domains": self.allow_domains, "unknown_recipients": self.unknown_recipients.as_str() })
    }
}

/// A domain rule as the owner typed it, normalized: lowercase, no leading `@` or `*.`, no trailing dot; at least two
/// labels (a bare top-level domain would allow a whole country); ASCII letters, digits and `-` in non-empty labels of
/// at most 63 characters (internationalized domains in their `xn--` form).
pub fn parse_domain(s: &str) -> anyhow::Result<String> {
    let d = s.trim().trim_start_matches('@').trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
    let ok = d.contains('.')
        && d.len() <= 253
        && d.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        });
    if !ok {
        bail!("'{}' is not a domain name (use the xn-- form for internationalized domains)", s.trim());
    }
    Ok(d)
}

/// Normalized, deduplicated domain list.
pub fn parse_domains(list: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for s in list.iter().flat_map(|s| s.split([',', ' ', '\n'])).filter(|s| !s.trim().is_empty()) {
        let d = parse_domain(s)?;
        if !out.contains(&d) {
            out.push(d);
        }
    }
    if out.len() > MAX_DOMAINS {
        bail!("at most {MAX_DOMAINS} domains");
    }
    Ok(out)
}

/// The domain of an address, lowercased, without a trailing dot; empty when there is none.
fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@').map(|(_, d)| d.trim_end_matches('.').to_lowercase()).unwrap_or_default()
}

/// Whether `addr` is in one of `domains` (exact domain or a subdomain); any address when `domains` is empty.
pub fn domain_allowed(addr: &str, domains: &[String]) -> bool {
    if domains.is_empty() {
        return true;
    }
    let d = domain_of(addr);
    !d.is_empty() && domains.iter().any(|r| d == *r || d.strip_suffix(r.as_str()).is_some_and(|p| p.ends_with('.')))
}

pub fn load(conn: &Connection, account_id: &str) -> anyhow::Result<Option<SendPolicy>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT allow_domains, unknown_recipients FROM account_send_policy WHERE account_id = ?1",
            [account_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((domains, unknown)) = row else { return Ok(None) };
    let allow_domains: Vec<String> =
        serde_json::from_str(&domains).map_err(|_| anyhow!("stored send policy is unreadable"))?;
    Ok(Some(SendPolicy { allow_domains, unknown_recipients: Unknown::parse(&unknown)? }))
}

/// Admin verb `accounts.send_policy_set`. An open policy (no domains, unknown allowed) removes the row.
pub fn set(tx: &Transaction, mailbox: &str, domains: &[String], unknown: &str) -> anyhow::Result<Value> {
    let aid = account_id(tx, mailbox)?;
    let policy = SendPolicy { allow_domains: parse_domains(domains)?, unknown_recipients: Unknown::parse(unknown)? };
    if policy.is_open() {
        tx.execute("DELETE FROM account_send_policy WHERE account_id = ?1", [&aid])?;
    } else {
        tx.execute(
            "INSERT INTO account_send_policy(account_id, allow_domains, unknown_recipients, updated_at) \
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(account_id) DO UPDATE SET allow_domains = excluded.allow_domains, \
             unknown_recipients = excluded.unknown_recipients, updated_at = excluded.updated_at",
            params![
                aid,
                serde_json::to_string(&policy.allow_domains)?,
                policy.unknown_recipients.as_str(),
                util::now_unix()
            ],
        )?;
    }
    Ok(json!({ "account": mailbox, "send_policy": policy.to_json() }))
}

/// Admin verb `accounts.send_policy_show`.
pub fn show(conn: &Connection, mailbox: &str) -> anyhow::Result<Value> {
    let aid = account_id(conn, mailbox)?;
    let policy = load(conn, &aid)?.unwrap_or(SendPolicy { allow_domains: vec![], unknown_recipients: Unknown::Allow });
    Ok(json!({ "account": mailbox, "send_policy": policy.to_json() }))
}

/// Whether the published generation `gen_id` has a message from `addr` or a `SENT` message to it.
fn exchanged(c: &Connection, gen_id: i64, addr: &str) -> rusqlite::Result<bool> {
    c.prepare_cached(&format!(
        "SELECT EXISTS(SELECT 1 FROM addrs a WHERE a.addr = ?1 AND a.gen = ?2 AND (a.role = {ROLE_FROM} OR \
         (a.role IN ({ROLE_TO}, {ROLE_CC}, {ROLE_BCC}) AND EXISTS(SELECT 1 FROM labels l \
          WHERE l.label = ?3 AND l.gen = ?2 AND l.msg = a.msg))))"
    ))?
    .query_row(params![addr, gen_id, crate::index::query::SENT_LABEL], |r| r.get(0))
}

fn refused(reason: &str, count: usize) -> ToolError {
    let what = match reason {
        "recipients_unverified" => format!(
            "this mailbox only sends directly to known recipients, and its index cannot confirm them right now \
             ({count} recipient(s) unchecked)"
        ),
        _ => format!("{count} recipient(s) are outside this mailbox's sending rules"),
    };
    ToolError::new(
        ErrorCode::Forbidden,
        format!("{what}; use request_send so the owner can approve this send, or change the recipients"),
    )
    .with_details(json!({ "reason": reason, "count": count }))
}

/// Checks the draft's recipients (To, Cc and Bcc) of an agent-initiated send against the mailbox's policy. Runs
/// before the send is claimed and before any upstream write.
pub async fn check(app: &App, account_id: &str, index_enabled: bool, recipients: &[String]) -> Result<(), ToolError> {
    let aid = account_id.to_string();
    let Some(policy) = app.store.call(move |c| load(c, &aid)).await? else { return Ok(()) };
    let mut rcpts: Vec<String> = recipients.iter().map(|r| crate::index::ingest::norm_addr(r)).collect();
    rcpts.sort();
    rcpts.dedup();
    let outside = rcpts.iter().filter(|r| !domain_allowed(r, &policy.allow_domains)).count();
    if outside > 0 {
        return Err(refused("recipient_not_allowed", outside));
    }
    if policy.unknown_recipients == Unknown::Allow || rcpts.is_empty() {
        return Ok(());
    }
    if !index_enabled {
        return Err(refused("recipients_unverified", rcpts.len()));
    }
    let aid = account_id.to_string();
    let n = rcpts.len();
    let unknown = app
        .index
        .read(Instant::now() + Duration::from_secs(5), move |c| {
            let tx = c.unchecked_transaction()?;
            let Some(g) = crate::index::sync::load_state(&tx, &aid)?.and_then(|s| s.active_gen) else {
                return Ok(None);
            };
            let mut unknown = 0;
            for r in &rcpts {
                if !exchanged(&tx, g, r)? {
                    unknown += 1;
                }
            }
            Ok(Some(unknown))
        })
        .await;
    match unknown {
        Ok(Some(0)) => Ok(()),
        Ok(Some(k)) => Err(refused("recipient_not_allowed", k)),
        // No published generation, or the index could not be read in time: fail closed.
        Ok(None) | Err(_) => Err(refused("recipients_unverified", n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_match_exactly_or_as_subdomain() {
        let d = parse_domains(&["Example.org".into(), "@kunde.de, *.partner.test.".into()]).unwrap();
        assert_eq!(d, vec!["example.org", "kunde.de", "partner.test"]);
        assert!(domain_allowed("a@example.org", &d));
        assert!(domain_allowed("a@MAIL.Example.ORG", &d));
        assert!(domain_allowed("a@x.partner.test.", &d));
        assert!(!domain_allowed("a@badexample.org", &d));
        assert!(!domain_allowed("a@example.org.evil.test", &d));
        assert!(!domain_allowed("no-at-sign", &d));
        assert!(domain_allowed("anyone@anywhere.test", &[]));
        for bad in ["", "de", "a..b", "-a.de", "a b.de", "exa_mple.org", "bücher.de", "a@b.de"] {
            assert!(parse_domain(bad).is_err(), "{bad:?}");
        }
        assert!(parse_domains(&(0..=MAX_DOMAINS).map(|i| format!("d{i}.de")).collect::<Vec<_>>()).is_err());
    }
}
