//! Sending identities (design 2026-11-13 section 5): send-as aliases of IMAP mailboxes and plain-text signatures.
//!
//! Aliases and signatures are operator configuration set over the admin socket; agents only see the resulting list
//! of allowed `from_address` values. Gmail keeps its own send-as list (the API is the source of truth there), so
//! aliases can only be added to IMAP mailboxes. Signatures work for both providers.
//!
//! Rules:
//! - An alias address passes the same strict parser as every address Dove puts in a header, and a display name is a
//!   single clean line, so neither can inject a header or an SMTP command.
//! - A signature is plain text, at most [`MAX_SIGNATURE_BYTES`], with no control characters other than line breaks
//!   and tabs. It is stored with `\n` line ends and no trailing whitespace.
//! - Signature lookup for a sender is exact: the alias's own signature if it has one, else the mailbox's.

use anyhow::{Context, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};

use crate::admin::ops::account_id;
use crate::mime;
use crate::util;

/// Largest signature, in bytes.
pub const MAX_SIGNATURE_BYTES: usize = 4096;

/// At most this many aliases per mailbox.
pub const MAX_ALIASES: usize = 50;

/// Address key of the mailbox's own (default) signature in `account_signatures`.
const MAILBOX_SIGNATURE: &str = "";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    /// Lowercased.
    pub address: String,
    pub name: Option<String>,
    /// The SMTP server accepts this address as envelope sender (`MAIL FROM`).
    pub envelope: bool,
}

/// A bare address (no display name), lowercased, through the strict header parser.
pub fn parse_bare_address(s: &str) -> anyhow::Result<String> {
    let a = mime::parse_address(s).map_err(|_| anyhow!("'{s}' is not a valid email address"))?;
    if a.name.is_some() || s.contains(['<', '>', '"']) {
        bail!("give the bare address (name@example.org); set the display name with --name");
    }
    Ok(a.email.to_lowercase())
}

fn clean_display_name(s: &str) -> anyhow::Result<Option<String>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if s.chars().count() > 100 || s.chars().any(char::is_control) || s.contains(['<', '>', '"', '\\']) {
        bail!("the display name must be one line of at most 100 characters without < > \" or backslash");
    }
    Ok(Some(s.to_string()))
}

/// Validates and normalizes a signature: `\n` line ends, no trailing whitespace, size and character limits. An
/// empty result is an error (use `--clear` to remove a signature).
pub fn clean_signature(raw: &str) -> anyhow::Result<String> {
    let text = raw.replace("\r\n", "\n").replace('\r', "\n");
    if text.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        bail!("a signature is plain text: no control characters other than line breaks and tabs");
    }
    let text = text.trim_end().to_string();
    let text = text.trim_start_matches('\n').to_string();
    if text.is_empty() {
        bail!("the signature is empty; use --clear to remove it");
    }
    if text.len() > MAX_SIGNATURE_BYTES {
        bail!("the signature is {} bytes; at most {MAX_SIGNATURE_BYTES} are allowed", text.len());
    }
    Ok(text)
}

/// The body followed by `-- ` and the signature, the usual separator. The signature comes before any quote or
/// forward block the caller adds afterwards.
pub fn with_signature(body: &str, signature: &str) -> String {
    let head = body.trim_end();
    let sep = if head.is_empty() { "" } else { "\n\n" };
    format!("{head}{sep}-- \n{signature}\n")
}

fn provider_of(conn: &Connection, account_id: &str) -> anyhow::Result<String> {
    Ok(conn.query_row("SELECT provider FROM accounts WHERE id = ?1", [account_id], |r| r.get(0))?)
}

// ------------------------------------------------------------------ aliases

/// All aliases of an account (empty for Gmail), ordered by address.
pub fn load_aliases(conn: &Connection, account_id: &str) -> anyhow::Result<Vec<Alias>> {
    let mut stmt = conn.prepare_cached(
        "SELECT address, display_name, envelope FROM account_aliases WHERE account_id = ?1 ORDER BY address",
    )?;
    let rows = stmt.query_map([account_id], |r| {
        Ok(Alias { address: r.get(0)?, name: r.get(1)?, envelope: r.get::<_, i64>(2)? != 0 })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Aliases of several accounts at once, as (account id, alias).
pub fn load_aliases_for(conn: &Connection, ids: &[String]) -> anyhow::Result<Vec<(String, Alias)>> {
    let mut out = Vec::new();
    for id in ids {
        for a in load_aliases(conn, id)? {
            out.push((id.clone(), a));
        }
    }
    Ok(out)
}

pub fn alias_add(
    tx: &Transaction,
    mailbox: &str,
    address: &str,
    name: Option<&str>,
    envelope: bool,
) -> anyhow::Result<Value> {
    let aid = account_id(tx, mailbox)?;
    if provider_of(tx, &aid)? != "imap" {
        bail!("'{mailbox}' is a Gmail mailbox: its send-as addresses come from Gmail settings, not from Dove");
    }
    let address = parse_bare_address(address)?;
    let email: String = tx.query_row("SELECT email FROM accounts WHERE id = ?1", [&aid], |r| r.get(0))?;
    if address.eq_ignore_ascii_case(&email) {
        bail!("{address} is the mailbox's own address; it needs no alias");
    }
    let name = name.map(clean_display_name).transpose()?.flatten();
    let n: i64 = tx.query_row("SELECT COUNT(*) FROM account_aliases WHERE account_id = ?1", [&aid], |r| r.get(0))?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_aliases WHERE account_id = ?1 AND address = ?2)",
        params![aid, address],
        |r| r.get(0),
    )?;
    if exists {
        bail!("{address} is already an alias of '{mailbox}'; remove it first to change it");
    }
    if n as usize >= MAX_ALIASES {
        bail!("a mailbox can have at most {MAX_ALIASES} aliases");
    }
    tx.execute(
        "INSERT INTO account_aliases(account_id, address, display_name, envelope, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![aid, address, name, envelope as i64, util::now_unix()],
    )?;
    Ok(json!({ "account": mailbox, "address": address, "name": name, "envelope": envelope }))
}

pub fn alias_remove(tx: &Transaction, mailbox: &str, address: &str) -> anyhow::Result<Value> {
    let aid = account_id(tx, mailbox)?;
    let address = parse_bare_address(address)?;
    let n = tx.execute("DELETE FROM account_aliases WHERE account_id = ?1 AND address = ?2", params![aid, address])?;
    if n == 0 {
        bail!("{address} is not an alias of '{mailbox}'");
    }
    // Its signature goes with it.
    tx.execute("DELETE FROM account_signatures WHERE account_id = ?1 AND address = ?2", params![aid, address])?;
    Ok(json!({ "account": mailbox, "address": address, "removed": true }))
}

pub fn alias_list(conn: &Connection, mailbox: &str) -> anyhow::Result<Value> {
    let aid = account_id(conn, mailbox)?;
    let email: String = conn.query_row("SELECT email FROM accounts WHERE id = ?1", [&aid], |r| r.get(0))?;
    let provider = provider_of(conn, &aid)?;
    let sigs: Vec<String> = {
        let mut stmt = conn.prepare("SELECT address FROM account_signatures WHERE account_id = ?1")?;
        stmt.query_map([&aid], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    let aliases: Vec<Value> = load_aliases(conn, &aid)?
        .into_iter()
        .map(|a| {
            json!({ "address": a.address, "name": a.name, "envelope": a.envelope,
                    "signature": sigs.contains(&a.address) })
        })
        .collect();
    Ok(json!({ "account": mailbox, "provider": provider, "address": email,
               "signature": sigs.iter().any(|s| s == MAILBOX_SIGNATURE), "aliases": aliases }))
}

// ------------------------------------------------------------------ signatures

/// Sets (`Some`) or clears (`None`) the signature of the mailbox, or of `alias` when given.
pub fn signature_set(
    tx: &Transaction,
    mailbox: &str,
    alias: Option<&str>,
    signature: Option<&str>,
) -> anyhow::Result<Value> {
    let aid = account_id(tx, mailbox)?;
    let key = signature_key(tx, &aid, mailbox, alias)?;
    match signature {
        Some(raw) => {
            let body = clean_signature(raw)?;
            tx.execute(
                "INSERT INTO account_signatures(account_id, address, body, updated_at) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(account_id, address) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at",
                params![aid, key, body, util::now_unix()],
            )?;
            Ok(json!({ "account": mailbox, "alias": alias.map(|_| &key), "signature_bytes": body.len() }))
        }
        None => {
            let n =
                tx.execute("DELETE FROM account_signatures WHERE account_id = ?1 AND address = ?2", params![aid, key])?;
            Ok(json!({ "account": mailbox, "alias": alias.map(|_| &key), "cleared": n > 0 }))
        }
    }
}

pub fn signature_show(conn: &Connection, mailbox: &str, alias: Option<&str>) -> anyhow::Result<Value> {
    let aid = account_id(conn, mailbox)?;
    let key = signature_key(conn, &aid, mailbox, alias)?;
    let body: Option<String> = conn
        .query_row(
            "SELECT body FROM account_signatures WHERE account_id = ?1 AND address = ?2",
            params![aid, key],
            |r| r.get(0),
        )
        .optional()?;
    Ok(json!({ "account": mailbox, "alias": alias.map(|_| &key), "signature": body }))
}

/// The `account_signatures.address` key for the mailbox (`''`) or one of its alias addresses. An IMAP alias must
/// exist; a Gmail send-as address cannot be checked without Google, so any valid address is accepted there and is
/// simply unused until the agent sends from it.
fn signature_key(conn: &Connection, aid: &str, mailbox: &str, alias: Option<&str>) -> anyhow::Result<String> {
    let Some(alias) = alias else { return Ok(MAILBOX_SIGNATURE.to_string()) };
    let address = parse_bare_address(alias)?;
    let email: String = conn.query_row("SELECT email FROM accounts WHERE id = ?1", [aid], |r| r.get(0))?;
    if address.eq_ignore_ascii_case(&email) {
        bail!("{address} is the mailbox's own address; set the mailbox signature without --alias");
    }
    if provider_of(conn, aid)? == "imap" {
        let known = load_aliases(conn, aid)?.iter().any(|a| a.address == address);
        if !known {
            bail!("{address} is not an alias of '{mailbox}'; add it with `dove accounts aliases add` first");
        }
    }
    Ok(address)
}

/// The signature to append for mail sent as `from_email`: the alias's own, else the mailbox's, else none.
pub fn signature_for(conn: &Connection, account_id: &str, from_email: &str) -> anyhow::Result<Option<String>> {
    let mut stmt = conn.prepare_cached("SELECT body FROM account_signatures WHERE account_id = ?1 AND address = ?2")?;
    let from = from_email.to_lowercase();
    for key in [from.as_str(), MAILBOX_SIGNATURE] {
        if let Some(b) = stmt.query_row(params![account_id, key], |r| r.get::<_, String>(0)).optional()? {
            return Ok(Some(b));
        }
    }
    Ok(None)
}

/// Whether `from` is the mailbox address or one of its IMAP aliases, with the alias's display name when it has one.
pub fn imap_sender(
    conn: &Connection,
    account_id: &str,
    mailbox_email: &str,
    from: &str,
) -> anyhow::Result<Option<Alias>> {
    let from = from.to_lowercase();
    if from == mailbox_email.to_lowercase() {
        return Ok(Some(Alias { address: from, name: None, envelope: true }));
    }
    Ok(load_aliases(conn, account_id).context("loading aliases")?.into_iter().find(|a| a.address == from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_cleaning() {
        assert_eq!(clean_signature("Dominik\r\nCtrl\r\n\r\n").unwrap(), "Dominik\nCtrl");
        assert_eq!(clean_signature("\n\nA\tB").unwrap(), "A\tB");
        assert!(clean_signature("  \n ").is_err());
        assert!(clean_signature("a\0b").is_err());
        assert!(clean_signature("a\u{1b}[31mb").is_err());
        assert!(clean_signature(&"x".repeat(MAX_SIGNATURE_BYTES)).is_ok());
        assert!(clean_signature(&"x".repeat(MAX_SIGNATURE_BYTES + 1)).is_err());
    }

    #[test]
    fn signature_placement_text() {
        assert_eq!(with_signature("Hallo\n\n", "Gruß\nD"), "Hallo\n\n-- \nGruß\nD\n");
        assert_eq!(with_signature("", "D"), "-- \nD\n");
    }

    #[test]
    fn addresses_and_names_are_strict() {
        assert_eq!(parse_bare_address("Sales@Example.ORG").unwrap(), "sales@example.org");
        for bad in
            ["Ann <a@example.org>", "a@example.org\r\nBcc: x@evil.org", "a@example.org, b@example.org", "nope", ""]
        {
            assert!(parse_bare_address(bad).is_err(), "{bad:?}");
        }
        assert!(clean_display_name("Acme \"Sales\"").is_err());
        assert!(clean_display_name("Acme\r\nBcc: x@evil.org").is_err());
        assert_eq!(clean_display_name("  ").unwrap(), None);
        assert_eq!(clean_display_name("Acme Sales").unwrap().as_deref(), Some("Acme Sales"));
    }
}
