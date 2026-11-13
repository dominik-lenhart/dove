//! `dove accounts connect-imap`, `reconnect` and `check` for IMAP accounts (design "Account model and connect").
//!
//! Everything is verified before anything is stored: verified TLS on both servers, IMAP login, required
//! capabilities, a Drafts folder (special-use or by name) and, when Dove files sent copies, a Sent folder, then SMTP
//! AUTH. A failure stores nothing and names the failed step; errors never contain the password or server text.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::account::{self, ImapSettings};
use super::session::{FolderInfo, ImapSession, Special};
use super::{Credentials, ImapError, ServerEndpoint, presets, smtp};
use crate::admin::ops::{self, valid_alias};
use crate::admin::server::AdminCall;
use crate::app::App;
use crate::util;

const DRAFTS_NAMES: &[&str] = &["Drafts", "Entwürfe", "Draft"];
const SENT_NAMES: &[&str] =
    &["Sent", "Sent Messages", "Sent Items", "Gesendet", "Gesendete Objekte", "Gesendete Elemente"];
pub(crate) const JUNK_NAMES: &[&str] = &["Junk", "Spam", "Junk E-Mail", "Junk-E-Mail", "Bulk Mail"];
pub(crate) const TRASH_NAMES: &[&str] =
    &["Trash", "Deleted Messages", "Deleted Items", "Papierkorb", "Gelöschte Elemente", "Gelöschte Objekte"];

pub struct ConnectImap {
    pub alias: String,
    pub email: String,
    pub username: Option<String>,
    pub smtp_username: Option<String>,
    pub password: Zeroizing<String>,
    pub imap: Option<ServerEndpoint>,
    pub smtp: Option<ServerEndpoint>,
    pub drafts_folder: Option<String>,
    pub preset: Option<String>,
}

fn step_error(server: &str, ep: &ServerEndpoint, e: &ImapError) -> anyhow::Error {
    let at = format!("{}:{}", ep.host, ep.port);
    match e {
        ImapError::Auth => anyhow!("{server} login failed at {at}: the server rejected the username or password"),
        ImapError::Tls => {
            anyhow!("{server} TLS failed at {at}: the certificate could not be verified or STARTTLS failed")
        }
        ImapError::Network | ImapError::NotDispatched => anyhow!("{server} connection failed: cannot reach {at}"),
        ImapError::Capability(c) => anyhow!("{server} server {at} lacks the required capability {c}"),
        ImapError::Missing | ImapError::Protocol(_) | ImapError::OutcomeUnknown => {
            anyhow!("{server} step failed at {at}: unexpected server response")
        }
    }
}

fn leaf(f: &FolderInfo) -> &str {
    match f.delimiter {
        Some(d) => f.name_utf8.rsplit(d).next().unwrap_or(&f.name_utf8),
        None => &f.name_utf8,
    }
}

/// Picks the folder for `role`: the special-use flag first, then a known name (last path segment, any case).
fn find<'a>(folders: &'a [FolderInfo], role: Special, names: &[&str]) -> Option<&'a FolderInfo> {
    let usable = || folders.iter().filter(|f| f.selectable);
    usable()
        .find(|f| f.special == Some(role))
        .or_else(|| names.iter().find_map(|n| usable().find(|f| leaf(f).eq_ignore_ascii_case(n))))
}

/// Resolves Drafts, Sent, Junk and Trash. `drafts_override` matches the decoded or the wire name exactly.
pub fn resolve_specials(
    folders: &[FolderInfo],
    drafts_override: Option<&str>,
    need_sent: bool,
) -> anyhow::Result<Vec<(String, Special)>> {
    let drafts = match drafts_override {
        Some(name) => folders
            .iter()
            .find(|f| f.selectable && (f.name_utf8 == name || f.raw_name == name))
            .ok_or_else(|| anyhow!("the folder given with --drafts-folder does not exist on the server"))?,
        None => find(folders, Special::Drafts, DRAFTS_NAMES).ok_or_else(|| {
            anyhow!(
                "no Drafts folder found (looked for the \\Drafts special-use flag and the names {}); pass \
                 --drafts-folder",
                DRAFTS_NAMES.join(", ")
            )
        })?,
    };
    let mut out = vec![(drafts.raw_name.clone(), Special::Drafts)];
    let others = [(Special::Sent, SENT_NAMES), (Special::Junk, JUNK_NAMES), (Special::Trash, TRASH_NAMES)];
    for (role, names) in others {
        match find(folders, role, names) {
            Some(f) if !out.iter().any(|(n, _)| *n == f.raw_name) => out.push((f.raw_name.clone(), role)),
            _ if role == Special::Sent && need_sent => bail!(
                "no Sent folder found (looked for the \\Sent special-use flag and the names {})",
                SENT_NAMES.join(", ")
            ),
            _ => {}
        }
    }
    Ok(out)
}

fn timeout(app: &App) -> Duration {
    Duration::from_secs(app.cfg.limits.upstream_request_timeout_secs.max(5))
}

/// IMAP login, capabilities and folder list on a fresh (unpooled) connection.
async fn verify_imap(app: &App, s: &ImapSettings, creds: &Credentials) -> anyhow::Result<Vec<FolderInfo>> {
    let mut session = ImapSession::connect(app.imap.connector(), &s.imap, creds, timeout(app))
        .await
        .map_err(|e| step_error("IMAP", &s.imap, &e))?;
    let folders = session.list_folders().await.map_err(|e| step_error("IMAP", &s.imap, &e))?;
    session.logout().await;
    Ok(folders)
}

async fn verify_smtp(app: &App, s: &ImapSettings, creds: &Credentials) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout(app) * 3;
    smtp::verify_login(app.imap.connector(), &s.smtp, &s.smtp_credentials(creds), deadline)
        .await
        .map_err(|e| step_error("SMTP", &s.smtp, &e.kind))
}

fn endpoint_or_preset(
    explicit: Option<ServerEndpoint>,
    preset: Option<&ServerEndpoint>,
    which: &str,
) -> anyhow::Result<ServerEndpoint> {
    let ep = explicit.or_else(|| preset.cloned()).ok_or_else(|| {
        anyhow!("unknown mail provider for this address: pass --{which}-host (and port/TLS) or --preset strato|icloud")
    })?;
    ep.validate().map_err(|e| anyhow!("--{which}-host: {e}"))?;
    Ok(ep)
}

pub async fn connect(call: &mut AdminCall<'_>, req: ConnectImap) -> anyhow::Result<Value> {
    let app = call.app.clone();
    if !valid_alias(&req.alias) {
        bail!("alias must match [a-z0-9-]{{2,40}}");
    }
    let email = req.email.trim().to_lowercase();
    if !email_address::EmailAddress::is_valid(&email) {
        bail!("invalid email address");
    }
    if req.password.is_empty() {
        bail!("the password is empty");
    }
    let preset = match req.preset.as_deref() {
        Some(p) => Some(presets::by_name(p).ok_or_else(|| anyhow!("unknown preset (known: strato, icloud)"))?),
        None => presets::for_email(&email),
    };
    let settings = ImapSettings {
        imap: endpoint_or_preset(req.imap, preset.as_ref().map(|p| &p.imap), "imap")?,
        smtp: endpoint_or_preset(req.smtp, preset.as_ref().map(|p| &p.smtp), "smtp")?,
        username: req.username.clone().filter(|u| !u.trim().is_empty()).unwrap_or_else(|| email.clone()),
        smtp_username: req.smtp_username.clone().filter(|u| !u.trim().is_empty()),
        save_sent_copy: preset.as_ref().is_none_or(|p| p.save_sent_copy),
        drafts_folder: None,
        sent_folder: None,
        generation: 1,
        alias: req.alias.clone(),
        email: email.clone(),
    };
    // Cheap checks first: nothing reaches the network for a name that is taken.
    let (a, e) = (req.alias.clone(), email.clone());
    app.store
        .call(move |c| {
            if c.query_row("SELECT 1 FROM accounts WHERE alias = ?1", [&a], |_| Ok(())).optional()?.is_some() {
                bail!("account alias '{a}' already exists; use reconnect");
            }
            if c.query_row("SELECT 1 FROM accounts WHERE email = ?1 COLLATE NOCASE", [&e], |_| Ok(()))
                .optional()?
                .is_some()
            {
                bail!("this email address is already connected under another alias");
            }
            Ok(())
        })
        .await?;
    let creds = Credentials { username: settings.username.clone(), password: req.password.clone() };
    let folders = verify_imap(&app, &settings, &creds).await?;
    let specials = resolve_specials(&folders, req.drafts_folder.as_deref(), settings.save_sent_copy)?;
    verify_smtp(&app, &settings, &creds).await?;

    let id = util::new_id();
    let sealed = app.vault.seal_password(&id, &req.password)?;
    let json = serde_json::to_string(&settings)?;
    let (id2, alias, email2) = (id.clone(), req.alias.clone(), email.clone());
    let specials2 = specials.clone();
    call.tx(move |tx| {
        let now = util::now_unix();
        tx.execute(
            "INSERT INTO accounts(id, alias, email, status, provider, imap_settings, connected_at, index_enabled) \
             VALUES (?1, ?2, ?3, 'active', 'imap', ?4, ?5, 1)",
            params![id2, alias, email2, json, now],
        )
        .map_err(|e| if ops::is_unique(&e) { anyhow!("alias or email address already connected") } else { e.into() })?;
        tx.execute(
            "INSERT INTO grants(account_id, dek_wrapped, kek_version, refresh_token_ciphertext, nonce, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id2, sealed.dek_wrapped, sealed.kek_version, sealed.ciphertext, sealed.nonce, now],
        )?;
        account::upsert_folders(tx, &id2, &folders, Some(&specials2))?;
        Ok(())
    })
    .await?;
    let name_of = |role: Special| {
        specials
            .iter()
            .find(|(_, s)| *s == role)
            .map(|(raw, _)| super::utf7::decode(raw).unwrap_or_else(|| raw.clone()))
    };
    Ok(json!({
        "account": req.alias,
        "email": email,
        "provider": "imap",
        "imap": format!("{}:{}", settings.imap.host, settings.imap.port),
        "smtp": format!("{}:{}", settings.smtp.host, settings.smtp.port),
        "preset": preset.map(|p| p.name),
        "drafts_folder": name_of(Special::Drafts),
        "sent_folder": name_of(Special::Sent),
        "save_sent_copy": settings.save_sent_copy,
        "index": "enabled",
    }))
}

/// Replaces the sealed password after the new one passes IMAP and SMTP login. Nothing changes on failure.
pub async fn reconnect(call: &mut AdminCall<'_>, alias: &str, password: Zeroizing<String>) -> anyhow::Result<Value> {
    let app = call.app.clone();
    let a = alias.to_string();
    let (id, provider, settings): (String, String, Option<String>) = app
        .store
        .call(move |c| {
            let id = ops::account_id(c, &a)?;
            let (p, s) = c.query_row("SELECT provider, imap_settings FROM accounts WHERE id = ?1", [&id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
            Ok((id, p, s))
        })
        .await?;
    if provider != "imap" {
        bail!("'{alias}' is a Gmail mailbox; reconnect it without a password (browser authorization)");
    }
    let settings: ImapSettings = serde_json::from_str(settings.as_deref().unwrap_or_default())?;
    let creds = Credentials { username: settings.username.clone(), password: password.clone() };
    verify_imap(&app, &settings, &creds).await?;
    verify_smtp(&app, &settings, &creds).await?;
    let sealed = app.vault.seal_password(&id, &password)?;
    let id2 = id.clone();
    let generation = call
        .tx(move |tx| {
            let now = util::now_unix();
            tx.execute(
                "UPDATE grants SET dek_wrapped = ?1, kek_version = ?2, refresh_token_ciphertext = ?3, nonce = ?4, \
                 rotated_at = ?5 WHERE account_id = ?6",
                params![sealed.dek_wrapped, sealed.kek_version, sealed.ciphertext, sealed.nonce, now, id2],
            )?;
            tx.execute(
                "UPDATE accounts SET status = 'active', connected_at = ?1, last_error_code = NULL, \
                 grant_generation = grant_generation + 1 WHERE id = ?2",
                params![now, id2],
            )?;
            Ok(tx.query_row("SELECT grant_generation FROM accounts WHERE id = ?1", [&id2], |r| r.get::<_, i64>(0))?)
        })
        .await?;
    app.imap.evict(&id);
    Ok(json!({ "account": alias, "provider": "imap", "status": "active", "generation": generation }))
}

/// `accounts check` for one active IMAP account: IMAP login + NOOP, SMTP login. An authentication failure marks
/// the account `reauth_required`.
pub async fn check(app: &Arc<App>, account_id: &str, alias: &str) -> Value {
    let (settings, creds) = match account::load(app, account_id).await {
        Ok(v) => v,
        Err(e) => return json!({ "account": alias, "provider": "imap", "imap_ok": false, "error": e.code.as_str() }),
    };
    let imap = async {
        let mut s = ImapSession::connect(app.imap.connector(), &settings.imap, &creds, timeout(app)).await?;
        s.noop().await?;
        s.logout().await;
        Ok::<(), ImapError>(())
    }
    .await;
    let deadline = Instant::now() + timeout(app) * 3;
    let smtp = smtp::verify_login(app.imap.connector(), &settings.smtp, &settings.smtp_credentials(&creds), deadline)
        .await
        .map_err(|e| e.kind);
    if imap.as_ref().err() == Some(&ImapError::Auth) || smtp.as_ref().err() == Some(&ImapError::Auth) {
        account::mark_auth_failure(app, account_id, settings.generation, &settings.alias).await;
    }
    let id = account_id.to_string();
    let status: String = app
        .store
        .call(move |c| Ok(c.query_row("SELECT status FROM accounts WHERE id = ?1", [id], |r| r.get(0))?))
        .await
        .unwrap_or_default();
    let err =
        |r: &Result<(), ImapError>| r.as_ref().err().map(|e| crate::error::ToolError::from(e.clone()).code.as_str());
    json!({ "account": alias, "provider": "imap", "status": status, "imap_ok": imap.is_ok(), "smtp_ok": smtp.is_ok(),
            "imap_error": err(&imap), "smtp_error": err(&smtp) })
}
