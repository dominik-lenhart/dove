//! An IMAP account's settings, folders and credentials, and the reauth rule: an explicit authentication failure
//! marks the account `reauth_required` once per credential generation (same fence and notification as Gmail).

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::pool::SessionFuture;
use super::session::{FolderInfo, ImapSession, Special};
use super::{Credentials, ImapError, ServerEndpoint, utf7};
use crate::app::App;
use crate::error::{ToolError, internal_from};
use crate::gmail::gateway::Priority;
use crate::util;
use crate::vault::SealedGrant;

/// Stored in `accounts.imap_settings` (no secrets). Fields marked `skip` are filled by [`load`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapSettings {
    pub imap: ServerEndpoint,
    pub smtp: ServerEndpoint,
    pub username: String,
    #[serde(default)]
    pub smtp_username: Option<String>,
    pub save_sent_copy: bool,
    /// Wire name of the Drafts folder (from `imap_folders`).
    #[serde(skip)]
    pub drafts_folder: Option<String>,
    /// Wire name of the Sent folder, if any.
    #[serde(skip)]
    pub sent_folder: Option<String>,
    /// Credential generation the password belongs to (fences reauth marking).
    #[serde(skip)]
    pub generation: i64,
    #[serde(skip)]
    pub alias: String,
    #[serde(skip)]
    pub email: String,
}

impl ImapSettings {
    /// Credentials for SMTP: the same password, with `smtp_username` when the provider needs a different login.
    pub fn smtp_credentials(&self, creds: &Credentials) -> Credentials {
        Credentials {
            username: self.smtp_username.clone().unwrap_or_else(|| creds.username.clone()),
            password: creds.password.clone(),
        }
    }
}

/// One row of `imap_folders`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub folder_id: i64,
    /// Wire name (modified UTF-7).
    pub name: String,
    /// Decoded name: the agent-visible label.
    pub name_utf8: String,
    pub special: Option<Special>,
}

pub fn load_folders(conn: &Connection, account_id: &str) -> anyhow::Result<Vec<Folder>> {
    let mut stmt = conn
        .prepare_cached("SELECT folder_id, name, special FROM imap_folders WHERE account_id = ?1 ORDER BY folder_id")?;
    let rows = stmt.query_map([account_id], |r| {
        let name: String = r.get(1)?;
        let special: Option<String> = r.get(2)?;
        Ok(Folder {
            folder_id: r.get(0)?,
            name_utf8: utf7::display_name(&name),
            name,
            special: special.as_deref().and_then(Special::parse),
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Records listed folders: new selectable folders get the next free id; existing ids never change. Special-use
/// assignments follow `specials` (wire name → role) when given, else the server's attributes.
pub fn upsert_folders(
    tx: &Transaction,
    account_id: &str,
    folders: &[FolderInfo],
    specials: Option<&[(String, Special)]>,
) -> anyhow::Result<()> {
    let mut next: i64 = tx.query_row(
        "SELECT COALESCE(MAX(folder_id), 0) + 1 FROM imap_folders WHERE account_id = ?1",
        [account_id],
        |r| r.get(0),
    )?;
    for f in folders.iter().filter(|f| f.selectable) {
        let special = match specials {
            Some(s) => s.iter().find(|(n, _)| *n == f.raw_name).map(|(_, sp)| *sp),
            None => f.special,
        };
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM imap_folders WHERE account_id = ?1 AND name = ?2)",
            params![account_id, f.raw_name],
            |r| r.get(0),
        )?;
        if exists {
            if specials.is_some() {
                tx.execute(
                    "UPDATE imap_folders SET special = ?3 WHERE account_id = ?1 AND name = ?2",
                    params![account_id, f.raw_name, special.map(Special::as_str)],
                )?;
            }
            continue;
        }
        tx.execute(
            "INSERT INTO imap_folders(account_id, folder_id, name, special) VALUES (?1, ?2, ?3, ?4)",
            params![account_id, next, f.raw_name, special.map(Special::as_str)],
        )?;
        next += 1;
    }
    Ok(())
}

struct Row {
    status: String,
    provider: String,
    settings: Option<String>,
    generation: i64,
    alias: String,
    email: String,
    sealed: Option<SealedGrant>,
}

fn load_row(c: &Connection, account_id: &str) -> anyhow::Result<Option<(Row, Vec<Folder>)>> {
    let row = c
        .query_row(
            "SELECT a.status, a.provider, a.imap_settings, a.grant_generation, a.alias, a.email, \
             g.dek_wrapped, g.kek_version, g.refresh_token_ciphertext, g.nonce \
             FROM accounts a LEFT JOIN grants g ON g.account_id = a.id WHERE a.id = ?1",
            [account_id],
            |r| {
                let dek: Option<Vec<u8>> = r.get(6)?;
                Ok(Row {
                    status: r.get(0)?,
                    provider: r.get(1)?,
                    settings: r.get(2)?,
                    generation: r.get(3)?,
                    alias: r.get(4)?,
                    email: r.get(5)?,
                    sealed: match dek {
                        Some(dek_wrapped) => Some(SealedGrant {
                            dek_wrapped,
                            kek_version: r.get(7)?,
                            ciphertext: r.get(8)?,
                            nonce: r.get(9)?,
                        }),
                        None => None,
                    },
                })
            },
        )
        .optional()?;
    match row {
        Some(r) => Ok(Some((r, load_folders(c, account_id)?))),
        None => Ok(None),
    }
}

/// Settings and credentials of an active IMAP account. Unknown or non-IMAP accounts are `not_found`; inactive
/// ones `account_unavailable`.
pub async fn load(app: &App, account_id: &str) -> Result<(ImapSettings, Credentials), ToolError> {
    let id = account_id.to_string();
    let loaded = app.store.call(move |c| load_row(c, &id)).await.map_err(internal_from)?;
    let Some((row, folders)) = loaded else { return Err(ToolError::not_found()) };
    if row.provider != "imap" {
        return Err(ToolError::not_found());
    }
    if row.status != "active" {
        return Err(ToolError::unavailable());
    }
    let mut settings: ImapSettings =
        serde_json::from_str(row.settings.as_deref().unwrap_or_default()).map_err(internal_from)?;
    let sealed = row.sealed.as_ref().ok_or_else(ToolError::unavailable)?;
    let password = app.vault.open_password(account_id, sealed).map_err(internal_from)?;
    settings.drafts_folder = folders.iter().find(|f| f.special == Some(Special::Drafts)).map(|f| f.name.clone());
    settings.sent_folder = folders.iter().find(|f| f.special == Some(Special::Sent)).map(|f| f.name.clone());
    settings.generation = row.generation;
    settings.alias = row.alias;
    settings.email = row.email;
    let creds = Credentials { username: settings.username.clone(), password };
    Ok((settings, creds))
}

/// Marks `reauth_required` only while the credential generation is unchanged (a late failure for an old password
/// cannot touch a newer one) and notifies the owner once per generation.
pub async fn mark_auth_failure(app: &App, account_id: &str, generation: i64, alias: &str) {
    let id = account_id.to_string();
    let changed = app
        .store
        .call(move |c| {
            Ok(c.execute(
                "UPDATE accounts SET status = 'reauth_required', last_error_code = 'auth_failed', last_error_at = ?1 \
                 WHERE id = ?2 AND grant_generation = ?3 AND status = 'active'",
                params![util::now_unix(), id, generation],
            )?)
        })
        .await
        .unwrap_or(0);
    app.imap.evict(account_id);
    if changed == 1 {
        let _ = app
            .notifier
            .notify_once(
                &format!("reauth:{account_id}:{generation}"),
                &format!(
                    "Mailbox '{alias}' rejected its password: run `dove accounts reconnect {alias}` with the current \
                     (app) password."
                ),
            )
            .await;
    }
}

/// Maps a wire error to a tool error, marking reauth on an authentication failure.
pub async fn tool_error(app: &App, settings: &ImapSettings, account_id: &str, e: ImapError) -> ToolError {
    if e == ImapError::Auth {
        mark_auth_failure(app, account_id, settings.generation, &settings.alias).await;
    }
    ToolError::from(e)
}

/// Runs `f` on a pooled, logged-in session of the account with its Drafts/Sent targets set.
pub async fn with_session<T, F>(app: &App, account_id: &str, f: F) -> Result<T, ToolError>
where
    F: for<'s> FnOnce(&'s mut ImapSession) -> SessionFuture<'s, T>,
{
    with_session_prio(app, account_id, Priority::Interactive, f).await
}

/// [`with_session`] for background work (index sync): it also holds a slot of the background sub-limit.
pub async fn with_session_prio<T, F>(app: &App, account_id: &str, prio: Priority, f: F) -> Result<T, ToolError>
where
    F: for<'s> FnOnce(&'s mut ImapSession) -> SessionFuture<'s, T>,
{
    let (settings, creds) = load(app, account_id).await?;
    let (drafts, sent) = (settings.drafts_folder.clone(), settings.sent_folder.clone());
    let r = app
        .imap
        .with_session_prio(account_id, &settings.imap, &creds, prio, move |s| {
            s.set_append_targets(drafts, sent);
            f(s)
        })
        .await;
    match r {
        Ok(v) => Ok(v),
        Err(e) => Err(tool_error(app, &settings, account_id, e).await),
    }
}

/// Wraps a password read from an admin request.
pub fn credentials(username: &str, password: &str) -> Credentials {
    Credentials { username: username.to_string(), password: Zeroizing::new(password.to_string()) }
}
