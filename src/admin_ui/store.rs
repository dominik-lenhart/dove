//! Passkeys, enrolment links and sessions in the state store (PLAN A74). Tokens are stored as SHA-256 only.

use anyhow::{anyhow, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::webauthn::NewCredential;
use crate::admin::ops::valid_name;
use crate::util;

/// An enrolment link is valid this long.
pub const ENROL_TTL_SECS: i64 = 5 * 60;
/// A session lasts this long from sign-in (no sliding renewal).
pub const SESSION_TTL_SECS: i64 = 12 * 3600;
/// Open enrolment links at once (expired ones are deleted first).
const MAX_OPEN_ENROLMENTS: i64 = 10;
/// Passkeys at most.
const MAX_PASSKEYS: i64 = 32;
/// Sessions at most; the oldest are ended first.
const MAX_SESSIONS: i64 = 32;

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn check_label(name: &str) -> anyhow::Result<()> {
    if !valid_name(name) {
        bail!("invalid passkey name '{name}': use 1-64 of a-z, 0-9, '-' and '_', starting with a letter or digit");
    }
    Ok(())
}

/// `passkeys add`: a one-time enrolment link for a passkey named `name`. Returns the link (with the token in the
/// fragment, so it never reaches a server or proxy log) and the token's expiry.
pub fn enrol_link(tx: &Transaction, name: &str, origin: &str) -> anyhow::Result<Value> {
    check_label(name)?;
    let now = util::now_unix();
    tx.execute("DELETE FROM admin_enrolments WHERE expires_at <= ?1 OR used_at IS NOT NULL", [now])?;
    if tx.query_row("SELECT COUNT(*) FROM admin_passkeys WHERE label = ?1", [name], |r| r.get::<_, i64>(0))? > 0 {
        bail!("a passkey named '{name}' exists; remove it first or choose another name");
    }
    let open: i64 = tx.query_row("SELECT COUNT(*) FROM admin_enrolments", [], |r| r.get(0))?;
    if open >= MAX_OPEN_ENROLMENTS {
        bail!("too many open enrolment links; wait until they expire (5 minutes)");
    }
    let passkeys: i64 = tx.query_row("SELECT COUNT(*) FROM admin_passkeys", [], |r| r.get(0))?;
    if passkeys >= MAX_PASSKEYS {
        bail!("at most {MAX_PASSKEYS} passkeys; remove one first");
    }
    let token = util::b64url(&util::random_bytes::<32>());
    tx.execute(
        "INSERT INTO admin_enrolments (token_hash, label, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash(&token), name, now, now + ENROL_TTL_SECS],
    )?;
    Ok(json!({
        "name": name,
        "open_this_link": format!("{origin}/admin/enroll#{token}"),
        "expires_in_minutes": ENROL_TTL_SECS / 60,
        "next": "Open the link on the device that holds (or will hold) the passkey, within 5 minutes. It works once. \
                 If the page says the link was already used and that was not you, remove the passkey at once: \
                 dove admin passkey remove <name>",
    }))
}

/// The label of an open enrolment link (not used, not expired), or `None`.
pub fn enrolment_label(c: &Connection, token: &str, now: i64) -> anyhow::Result<Option<String>> {
    Ok(c.query_row(
        "SELECT label FROM admin_enrolments WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
        params![token_hash(token), now],
        |r| r.get(0),
    )
    .optional()?)
}

/// Consumes the enrolment link and stores the passkey, in one transaction. Returns the new passkey's id.
pub fn finish_enrolment(
    tx: &Transaction,
    token: &str,
    label: &str,
    user_handle: &[u8],
    cred: &NewCredential,
    now: i64,
) -> anyhow::Result<String> {
    let used = tx.execute(
        "UPDATE admin_enrolments SET used_at = ?3 WHERE token_hash = ?1 AND label = ?2 AND used_at IS NULL \
         AND expires_at > ?3",
        params![token_hash(token), label, now],
    )?;
    if used != 1 {
        bail!("enrolment link used or expired");
    }
    let taken: i64 = tx.query_row(
        "SELECT COUNT(*) FROM admin_passkeys WHERE label = ?1 OR credential_id = ?2",
        params![label, cred.credential_id],
        |r| r.get(0),
    )?;
    if taken > 0 {
        bail!("this passkey or name is already enrolled");
    }
    let id = util::new_id();
    tx.execute(
        "INSERT INTO admin_passkeys (id, label, credential_id, user_handle, alg, public_key, sign_count, \
         backup_eligible, backup_state, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            id,
            label,
            cred.credential_id,
            user_handle,
            cred.alg,
            cred.public_key,
            i64::from(cred.sign_count),
            cred.backup_eligible,
            cred.backup_state,
            now
        ],
    )?;
    Ok(id)
}

/// A stored passkey.
#[derive(Debug, Clone)]
pub struct Passkey {
    pub id: String,
    pub label: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub alg: i64,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub backup_eligible: bool,
}

const PASSKEY_COLS: &str = "id, label, credential_id, user_handle, alg, public_key, sign_count, backup_eligible";

fn passkey_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Passkey> {
    Ok(Passkey {
        id: r.get(0)?,
        label: r.get(1)?,
        credential_id: r.get(2)?,
        user_handle: r.get(3)?,
        alg: r.get(4)?,
        public_key: r.get(5)?,
        sign_count: u32::try_from(r.get::<_, i64>(6)?).unwrap_or(u32::MAX),
        backup_eligible: r.get(7)?,
    })
}

pub fn passkey_by_credential(c: &Connection, credential_id: &[u8]) -> anyhow::Result<Option<Passkey>> {
    Ok(c.query_row(
        &format!("SELECT {PASSKEY_COLS} FROM admin_passkeys WHERE credential_id = ?1"),
        [credential_id],
        passkey_row,
    )
    .optional()?)
}

pub fn passkey_by_id(c: &Connection, id: &str) -> anyhow::Result<Option<Passkey>> {
    Ok(c.query_row(&format!("SELECT {PASSKEY_COLS} FROM admin_passkeys WHERE id = ?1"), [id], passkey_row)
        .optional()?)
}

/// Stores the counter and backup state of a successful assertion. Fails when the counter moved meanwhile (two
/// assertions racing): only one of them may count.
pub fn record_use(c: &Connection, p: &Passkey, sign_count: u32, backup_state: bool, now: i64) -> anyhow::Result<()> {
    let n = c.execute(
        "UPDATE admin_passkeys SET sign_count = ?2, backup_state = ?3, last_used_at = ?4 WHERE id = ?1 \
         AND sign_count = ?5",
        params![p.id, i64::from(sign_count), backup_state, now, i64::from(p.sign_count)],
    )?;
    if n != 1 {
        bail!("passkey changed during sign-in");
    }
    Ok(())
}

pub fn passkey_list(c: &Connection) -> anyhow::Result<Value> {
    let mut st = c.prepare(
        "SELECT p.label, p.alg, p.backup_eligible, p.backup_state, p.created_at, p.last_used_at, \
         (SELECT COUNT(*) FROM admin_sessions s WHERE s.passkey_id = p.id AND s.expires_at > ?1) \
         FROM admin_passkeys p ORDER BY p.created_at, p.label",
    )?;
    let rows = st.query_map([util::now_unix()], |r| {
        Ok(json!({
            "name": r.get::<_, String>(0)?,
            "algorithm": if r.get::<_, i64>(1)? == super::webauthn::ALG_EDDSA { "EdDSA" } else { "ES256" },
            "backup_eligible": r.get::<_, bool>(2)?,
            "backed_up": r.get::<_, bool>(3)?,
            "created_at": util::rfc3339(r.get(4)?),
            "last_used_at": r.get::<_, Option<i64>>(5)?.map(util::rfc3339),
            "sessions": r.get::<_, i64>(6)?,
        }))
    })?;
    Ok(json!(rows.collect::<Result<Vec<_>, _>>()?))
}

/// Removes a passkey; its sessions end with it (foreign key cascade).
pub fn passkey_remove(tx: &Transaction, name: &str) -> anyhow::Result<Value> {
    let ended: i64 = tx.query_row(
        "SELECT COUNT(*) FROM admin_sessions s JOIN admin_passkeys p ON p.id = s.passkey_id WHERE p.label = ?1",
        [name],
        |r| r.get(0),
    )?;
    let n = tx.execute("DELETE FROM admin_passkeys WHERE label = ?1", [name])?;
    if n == 0 {
        return Err(anyhow!("no passkey named '{name}'"));
    }
    Ok(json!({ "removed": name, "sessions_ended": ended }))
}

/// A valid session.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub passkey_id: String,
    pub label: String,
    pub expires_at: i64,
}

/// Creates a session for `passkey_id`; returns its id. Ends the oldest sessions beyond [`MAX_SESSIONS`].
pub fn session_create(c: &Connection, token: &str, passkey_id: &str, now: i64) -> anyhow::Result<String> {
    c.execute("DELETE FROM admin_sessions WHERE expires_at <= ?1", [now])?;
    c.execute(
        "DELETE FROM admin_sessions WHERE id IN (SELECT id FROM admin_sessions ORDER BY created_at DESC, id \
         LIMIT -1 OFFSET ?1)",
        [MAX_SESSIONS - 1],
    )?;
    let id = util::new_id();
    c.execute(
        "INSERT INTO admin_sessions (id, token_hash, passkey_id, created_at, expires_at, last_seen_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?4)",
        params![id, token_hash(token), passkey_id, now, now + SESSION_TTL_SECS],
    )?;
    Ok(id)
}

/// The session for a cookie token, if it exists and has not expired. Updates `last_seen_at` at most once a minute.
pub fn session_lookup(c: &Connection, token: &str, now: i64) -> anyhow::Result<Option<Session>> {
    let row = c
        .query_row(
            "SELECT s.id, s.passkey_id, p.label, s.expires_at, s.last_seen_at FROM admin_sessions s \
             JOIN admin_passkeys p ON p.id = s.passkey_id WHERE s.token_hash = ?1 AND s.expires_at > ?2",
            params![token_hash(token), now],
            |r| {
                Ok((
                    Session { id: r.get(0)?, passkey_id: r.get(1)?, label: r.get(2)?, expires_at: r.get(3)? },
                    r.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((s, seen)) = row else { return Ok(None) };
    if now - seen >= 60 {
        c.execute("UPDATE admin_sessions SET last_seen_at = ?2 WHERE id = ?1", params![s.id, now])?;
    }
    Ok(Some(s))
}

pub fn session_delete(c: &Connection, id: &str) -> anyhow::Result<()> {
    c.execute("DELETE FROM admin_sessions WHERE id = ?1", [id])?;
    Ok(())
}

pub fn sessions_list(c: &Connection) -> anyhow::Result<Value> {
    let now = util::now_unix();
    let mut st = c.prepare(
        "SELECT s.id, p.label, s.created_at, s.expires_at, s.last_seen_at FROM admin_sessions s \
         JOIN admin_passkeys p ON p.id = s.passkey_id WHERE s.expires_at > ?1 ORDER BY s.created_at DESC",
    )?;
    let rows = st.query_map([now], |r| {
        Ok(json!({
            "id": r.get::<_, String>(0)?,
            "passkey": r.get::<_, String>(1)?,
            "created_at": util::rfc3339(r.get(2)?),
            "expires_at": util::rfc3339(r.get(3)?),
            "last_seen_at": util::rfc3339(r.get(4)?),
        }))
    })?;
    Ok(json!(rows.collect::<Result<Vec<_>, _>>()?))
}

/// Ends one session (`id`) or all of them.
pub fn sessions_revoke(tx: &Transaction, id: Option<&str>) -> anyhow::Result<Value> {
    let n = match id {
        Some(id) => {
            let n = tx.execute("DELETE FROM admin_sessions WHERE id = ?1", [id])?;
            if n == 0 {
                bail!("no session with id '{id}'");
            }
            n
        }
        None => tx.execute("DELETE FROM admin_sessions", [])?,
    };
    Ok(json!({ "sessions_ended": n }))
}
