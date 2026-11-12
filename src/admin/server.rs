//! Admin socket server: peer-uid check, request dispatch, exactly one audit record per admin action.

use std::os::unix::fs::PermissionsExt;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use rusqlite::Transaction;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use super::ops::{self, Actor};
use super::{AdminRequest, AdminResponse, MAX_REQUEST_BYTES};
use crate::app::App;
use crate::audit::{self, AuditRecord};
use crate::util;

/// Binds the admin socket with mode 0660. The directory is expected to be owned by the service user and the
/// operator group (for example systemd `RuntimeDirectory=dove` with `RuntimeDirectoryMode=0750`).
pub fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path).with_context(|| format!("cannot remove stale socket {}", path.display()))?;
    }
    let listener = UnixListener::bind(path).with_context(|| format!("cannot bind admin socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

pub async fn serve(app: Arc<App>, listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(app, stream).await {
                        tracing::warn!(error = %e, "admin connection error");
                    }
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "admin accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

/// Returns true when `uid` may administer this instance.
pub fn uid_allowed(app: &App, uid: u32) -> bool {
    uid == 0 || uid == app.cfg.admin.operator_uid
}

async fn handle_conn(app: Arc<App>, stream: UnixStream) -> anyhow::Result<()> {
    let cred = stream.peer_cred().context("cannot read peer credentials")?;
    let uid = cred.uid();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd).take(MAX_REQUEST_BYTES as u64 + 1);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let request_id = util::new_id();
    let actor = Actor { name: format!("uid:{uid}"), request_id: request_id.clone() };

    let response = if !uid_allowed(&app, uid) {
        // Denied before parsing: the request content is untrusted and not interpreted.
        write_audit(&app, &actor, ("admin.denied", None, None, vec![]), "forbidden").await;
        AdminResponse::err("permission denied: this user may not administer Dove")
    } else if line.len() > MAX_REQUEST_BYTES {
        AdminResponse::err("request too large")
    } else {
        match serde_json::from_str::<AdminRequest>(&line) {
            Ok(req) => dispatch(&app, &actor, req).await,
            Err(e) => {
                write_audit(&app, &actor, ("admin.invalid", None, None, vec![]), "invalid_argument").await;
                AdminResponse::err(format!("invalid request: {e}"))
            }
        }
    };
    let mut out = serde_json::to_vec(&response)?;
    out.push(b'\n');
    wr.write_all(&out).await?;
    wr.shutdown().await.ok();
    Ok(())
}

type AuditFields = (&'static str, Option<String>, Option<String>, Vec<String>);

fn record(actor: &Actor, f: &AuditFields, code: &str) -> AuditRecord {
    AuditRecord {
        request_id: actor.request_id.clone(),
        actor: actor.name.clone(),
        project: f.1.clone(),
        tool_or_action: f.0.to_string(),
        account_alias: f.2.clone(),
        object_ids: f.3.clone(),
        result_code: code.to_string(),
        ..Default::default()
    }
}

async fn write_audit(app: &App, actor: &Actor, f: AuditFields, code: &str) {
    let rec = record(actor, &f, code);
    if let Err(e) = app.store.call(move |c| audit::append(c, &rec).map(|_| ())).await {
        tracing::error!(error = %e, "audit write failed");
    }
}

/// One admin call. `tx` commits the state change and its audit record atomically.
pub struct AdminCall<'a> {
    pub app: &'a Arc<App>,
    pub actor: &'a Actor,
    fields: AuditFields,
    audited: bool,
    started: std::time::Instant,
}

impl AdminCall<'_> {
    pub async fn tx<F, T>(&mut self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&Transaction) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if self.audited {
            bail!("internal: admin call already committed");
        }
        let mut rec = record(self.actor, &self.fields, "ok");
        rec.duration_ms = self.started.elapsed().as_millis() as i64;
        let v = self
            .app
            .store
            .call(move |c| {
                let tx = c.transaction()?;
                let v = f(&tx)?;
                audit::append(&tx, &rec)?;
                tx.commit()?;
                Ok(v)
            })
            .await?;
        self.audited = true;
        Ok(v)
    }

    /// Read-only access without auditing (the dispatcher audits reads once at the end).
    pub async fn read<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&rusqlite::Connection) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.app.store.call(move |c| f(c)).await
    }
}

pub async fn dispatch(app: &Arc<App>, actor: &Actor, req: AdminRequest) -> AdminResponse {
    let fields = req.audit_fields();
    let mut call = AdminCall { app, actor, fields: fields.clone(), audited: false, started: std::time::Instant::now() };
    let result = execute(&mut call, req).await;
    match result {
        Ok(v) => {
            if !call.audited {
                write_audit(app, actor, fields, "ok").await;
            }
            AdminResponse::ok(v)
        }
        Err(e) => {
            if !call.audited {
                write_audit(app, actor, fields, "error").await;
            }
            AdminResponse::err(format!("{e:#}"))
        }
    }
}

fn parse_expiry(expires: Option<&str>) -> anyhow::Result<Option<i64>> {
    expires
        .map(|e| util::parse_duration_secs(e).ok_or_else(|| anyhow!("invalid --expires '{e}' (use e.g. 90d, 12h)")))
        .transpose()
}

async fn execute(call: &mut AdminCall<'_>, req: AdminRequest) -> anyhow::Result<Value> {
    use AdminRequest::*;
    let app = call.app.clone();
    let allow_send = app.cfg.allow_send;
    match req {
        ProjectsCreate { name } => call.tx(move |tx| ops::project_create(tx, &name)).await,
        ProjectsAddAccount { project, account } => {
            call.tx(move |tx| ops::project_add_account(tx, &project, &account)).await
        }
        ProjectsRemoveAccount { project, account } => {
            call.tx(move |tx| ops::project_remove_account(tx, &project, &account)).await
        }
        ProjectsList => call.read(ops::project_list).await,
        ProjectsShow { name } => call.read(move |c| ops::project_show(c, &name)).await,
        AccountsList => call.read(ops::account_list).await,
        AccountsDisable { alias } => call.tx(move |tx| ops::account_set_enabled(tx, &alias, false)).await,
        AccountsEnable { alias } => call.tx(move |tx| ops::account_set_enabled(tx, &alias, true)).await,
        ClientsCreate { name, project, grants, expires, allow_ip } => {
            let expires_in = parse_expiry(expires.as_deref())?;
            let pepper = app.pepper.clone();
            call.tx(move |tx| {
                let nc = ops::NewClient {
                    name: &name,
                    project: &project,
                    grants: &grants,
                    expires_in_secs: expires_in,
                    allowed_cidrs: &allow_ip,
                    kind: "token",
                    created_via: "cli",
                };
                let (_, token, mut v) = ops::client_create(tx, &pepper, allow_send, &nc)?;
                v["token"] = json!(token);
                Ok(v)
            })
            .await
        }
        ClientsSetGrants { name, grants } => {
            call.tx(move |tx| ops::client_set_grants(tx, allow_send, &name, &grants)).await
        }
        ClientsRotate { name } => {
            let pepper = app.pepper.clone();
            call.tx(move |tx| {
                let (token, mut v) = ops::client_rotate(tx, &pepper, &name)?;
                v["token"] = json!(token);
                Ok(v)
            })
            .await
        }
        ClientsRevoke { name } => call.tx(move |tx| ops::client_revoke(tx, &name)).await,
        ClientsInvite { name, project, accounts, capabilities, expires, allow_ip } => {
            let expires_in = parse_expiry(expires.as_deref())?;
            let pepper = app.pepper.clone();
            call.tx(move |tx| {
                let ni = crate::invite::NewInvite {
                    name: &name,
                    project: &project,
                    accounts: &accounts,
                    capabilities: &capabilities,
                    expires_in_secs: expires_in,
                    allow_ip: &allow_ip,
                };
                crate::invite::create(tx, &pepper, allow_send, &ni)
            })
            .await
        }
        ClientsShow { name } => call.read(move |c| ops::client_show(c, &name)).await,
        ClientsList => call.read(ops::client_list).await,
        AuditTail { limit } => {
            call.read(move |c| Ok(json!(audit::tail(c, limit.unwrap_or(50).clamp(1, 10_000))?))).await
        }
        AuditSearch { filter } => call.read(move |c| Ok(json!(audit::search(c, &filter)?))).await,
        AuditVerify => call.read(|c| Ok(json!(audit::verify(c)?))).await,
        AuditPrune => {
            let days = app.cfg.audit.retention_days;
            let rid = call.actor.request_id.clone();
            // prune writes its own audit record ("audit.prune"); mark this call as audited.
            let n = app.store.call(move |c| audit::prune(c, days, &rid)).await?;
            call.audited = true;
            Ok(json!({ "deleted": n }))
        }
        Export => call.read(ops::export).await,
        AccountsConnect { alias, email } => {
            let url = crate::gmail::connect::start(&app, &alias, Some(&email), false).await?;
            Ok(json!({ "open_this_link": url, "expires_in_minutes": 10,
                       "next": "Sign in as the expected address and approve. Then check `dove accounts list`." }))
        }
        AccountsReconnect { alias } => {
            let url = crate::gmail::connect::start(&app, &alias, None, true).await?;
            Ok(json!({ "open_this_link": url, "expires_in_minutes": 10 }))
        }
        AccountsRemove { alias } => accounts_remove(call, &alias).await,
        AccountsCheck { alias } => accounts_check(&app, alias).await,
        KeysRotate => keys_rotate(call).await,
        Doctor => Ok(doctor(&app).await),
        IndexEnable { alias } => crate::index::admin::enable(call, alias).await,
        IndexDisable { alias } => crate::index::admin::disable(call, alias).await,
        IndexStatus { alias } => crate::index::admin::status(&app, alias).await,
        IndexRebuild { alias } => crate::index::admin::rebuild(call, alias).await,
        other => Err(anyhow!("'{}' is not available in this build yet", other.audit_fields().0)),
    }
}

async fn accounts_remove(call: &mut AdminCall<'_>, alias: &str) -> anyhow::Result<Value> {
    let app = call.app.clone();
    let a = alias.to_string();
    let (account_id, row) = app
        .store
        .call(move |c| {
            let id = ops::account_id(c, &a)?;
            let row = crate::gmail::tokens::load_grant(c, &id)?;
            Ok((id, row))
        })
        .await?;
    // Revoke at Google first (best effort); local deletion happens regardless (spec 7.9 step 3, FR-A4).
    let mut revoked = "no_grant";
    if let Some(sealed) = row.and_then(|r| r.sealed) {
        revoked = match app.vault.open_grant(&account_id, &sealed) {
            Ok(rt) => match app.google.gateway().revoke(&rt).await {
                Ok(()) => "revoked",
                Err(_) => "revocation_failed_remove_access_in_google_account",
            },
            Err(_) => "grant_unreadable",
        };
    }
    app.google.tokens().evict(&account_id);
    let id = account_id.clone();
    call.tx(move |tx| {
        // Cascades: grant + DEK, project membership, client grants, owned-draft records.
        tx.execute("DELETE FROM accounts WHERE id = ?1", [&id])?;
        Ok(())
    })
    .await?;
    crate::index::purge_account(&app, &account_id).await;
    Ok(json!({ "account": alias, "removed": true, "google_revocation": revoked }))
}

async fn accounts_check(app: &Arc<App>, alias: Option<String>) -> anyhow::Result<Value> {
    let accounts: Vec<(String, String, String)> = app
        .store
        .call(move |c| {
            let mut stmt =
                c.prepare("SELECT id, alias, status FROM accounts WHERE (?1 IS NULL OR alias = ?1) ORDER BY alias")?;
            let rows = stmt.query_map([&alias], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await?;
    let mut out = Vec::new();
    for (id, alias, status) in accounts {
        if status != "active" {
            out.push(json!({ "account": alias, "status": status }));
            continue;
        }
        app.google.tokens().evict(&id);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let r = app
            .google
            .call(
                &id,
                || crate::gmail::gateway::GmailOp::Profile,
                &[],
                None,
                crate::gmail::gateway::Priority::Interactive,
                deadline,
            )
            .await;
        let id2 = id.clone();
        let status_now: String = app
            .store
            .call(move |c| Ok(c.query_row("SELECT status FROM accounts WHERE id = ?1", [id2], |r| r.get(0))?))
            .await?;
        out.push(match r {
            Ok(p) => json!({ "account": alias, "status": status_now, "profile_ok": true,
                             "messages_total": p["messagesTotal"] }),
            Err(e) => json!({ "account": alias, "status": status_now, "profile_ok": false, "error": e.code.as_str() }),
        });
    }
    Ok(Value::Array(out))
}

async fn keys_rotate(call: &mut AdminCall<'_>) -> anyhow::Result<Value> {
    let vault = call.app.vault.clone();
    let current = vault.current_kek_version();
    let (rewrapped, remaining) = call
        .tx(move |tx| {
            #[allow(clippy::type_complexity)] // one row of the grants table
            let rows: Vec<(String, Vec<u8>, u32, Vec<u8>, Vec<u8>)> = {
                let mut stmt = tx.prepare(
                    "SELECT account_id, dek_wrapped, kek_version, refresh_token_ciphertext, nonce FROM grants",
                )?;
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                    .collect::<Result<_, _>>()?
            };
            let mut n = 0;
            for (id, dek_wrapped, kek_version, ciphertext, nonce) in rows {
                if kek_version == current {
                    continue;
                }
                let sealed = crate::vault::SealedGrant { dek_wrapped, kek_version, ciphertext, nonce };
                let new = vault.rewrap(&id, &sealed)?;
                tx.execute(
                    "UPDATE grants SET dek_wrapped = ?1, kek_version = ?2, refresh_token_ciphertext = ?3, nonce = ?4, \
                     rotated_at = ?5 WHERE account_id = ?6",
                    rusqlite::params![
                        new.dek_wrapped,
                        new.kek_version,
                        new.ciphertext,
                        new.nonce,
                        util::now_unix(),
                        id
                    ],
                )?;
                n += 1;
            }
            let mut stmt = tx.prepare("SELECT DISTINCT kek_version FROM grants")?;
            let remaining: Vec<u32> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            crate::store::set_meta(tx, "kek_version", &current.to_string())?;
            Ok((n, remaining))
        })
        .await?;
    let removable: Vec<u32> = call.app.vault.kek_versions().into_iter().filter(|v| !remaining.contains(v)).collect();
    Ok(json!({ "current_version": current, "rewrapped": rewrapped, "versions_in_use": remaining,
               "versions_safe_to_delete_from_kek_file": removable }))
}

async fn doctor(app: &Arc<App>) -> Value {
    let mut checks = Vec::new();
    let mut add =
        |name: &str, ok: bool, detail: String| checks.push(json!({ "check": name, "ok": ok, "detail": detail }));
    add("config", app.cfg.validate().is_ok(), app.cfg.validate().err().map(|e| e.to_string()).unwrap_or_default());
    let uid = nix::unistd::getuid().as_raw();
    add(
        "service_user",
        uid != app.cfg.admin.operator_uid && uid != 0,
        format!("service uid {uid}, operator uid {}", app.cfg.admin.operator_uid),
    );
    let data_mode = std::fs::metadata(&app.cfg.data_dir).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
    add("data_dir_mode", data_mode & 0o077 == 0, format!("{data_mode:o}"));
    let sock_mode = std::fs::metadata(&app.cfg.admin.socket_path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
    add("admin_socket_mode", sock_mode & 0o007 == 0, format!("{sock_mode:o}"));
    add("allow_send", true, app.cfg.allow_send.to_string());
    let google = app.google.jwks(true).await;
    add("google_reachable", google.is_ok(), google.err().map(|e| e.to_string()).unwrap_or_default());
    let (_, key) = app.index_key.current();
    let idx = crate::index::db::open(&app.cfg.index_db_path(), key, &app.cfg.index);
    add("index_encryption", idx.is_ok(), idx.err().map(|e| e.to_string()).unwrap_or_default());
    let verify = app.store.call(|c| audit::verify(c)).await;
    add(
        "audit_chain",
        verify.as_ref().is_ok_and(|v| v.ok),
        verify.map(|v| format!("{} records", v.records)).unwrap_or_default(),
    );
    // Public URL TLS check: a HEAD to /healthz through the proxy.
    let health = format!("{}/healthz", app.cfg.public_base());
    let tls =
        reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().map(|c| c.get(&health).send());
    let tls_ok = match tls {
        Ok(f) => f.await.map(|r| r.status().is_success()).unwrap_or(false),
        Err(_) => false,
    };
    add("public_url_tls", tls_ok, health);
    json!(checks)
}
