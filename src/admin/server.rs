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
        other => Err(anyhow!("'{}' is not available in this build yet", other.audit_fields().0)),
    }
}
