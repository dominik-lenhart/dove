//! Step 1 acceptance: admin socket authority, grants intersection, token lifecycle and audit (AC1, AC2, AC11,
//! AC16, AC19 partial).

// Unix only: drives the admin Unix socket and its peer-uid check (the Windows pipe is tested in
// `dove::admin::transport`).
#![cfg(unix)]

use std::net::IpAddr;
use std::sync::Arc;

use dove::admin::ops::GrantSpec;
use dove::admin::{AdminRequest, client, server};
use dove::policy::{self, AuthFailure, Capability};
use dove::testing::TestEnv;
use serde_json::Value;

async fn start(env: &TestEnv) -> std::path::PathBuf {
    let path = env.app.cfg.admin.socket_path.clone();
    let listener = server::bind(&path).unwrap();
    tokio::spawn(server::serve(env.app.clone(), listener));
    path
}

fn g(account: &str, actions: &str) -> GrantSpec {
    GrantSpec { account: account.into(), actions: actions.into() }
}

async fn auth(env: &TestEnv, token: &str, ip: Option<IpAddr>) -> Result<policy::ClientCtx, AuthFailure> {
    let app = env.app.clone();
    let token = token.to_string();
    app.store
        .clone()
        .call(move |c| policy::authenticate(c, &app.pepper, &token, ip, app.cfg.allow_send, "res"))
        .await
        .unwrap()
        .map(|a| a.ctx)
}

async fn audit_count(env: &TestEnv) -> i64 {
    env.app.store.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))?)).await.unwrap()
}

#[tokio::test]
async fn intersected_grants_and_token_lifecycle() {
    let env = TestEnv::new();
    let sock = start(&env).await;
    for a in ["info", "billing", "secret"] {
        env.add_account(a, &format!("{a}@acme.test"), "1//rt");
    }
    let send = |r: AdminRequest| {
        let sock = sock.clone();
        async move { client::send(&sock, &r).await }
    };
    send(AdminRequest::ProjectsCreate { name: "acme".into() }).await.unwrap();
    for a in ["info", "billing", "secret"] {
        send(AdminRequest::ProjectsAddAccount { project: "acme".into(), account: a.into() }).await.unwrap();
    }
    // Draft without read is rejected; send without the instance gate is rejected.
    let bad = send(AdminRequest::ClientsCreate {
        name: "x".into(),
        project: "acme".into(),
        grants: vec![g("info", "draft")],
        expires: None,
        allow_ip: vec![],
    })
    .await;
    assert!(bad.unwrap_err().to_string().contains("draft requires read"));
    let bad = send(AdminRequest::ClientsCreate {
        name: "x".into(),
        project: "acme".into(),
        grants: vec![g("info", "read,draft,send")],
        expires: None,
        allow_ip: vec![],
    })
    .await;
    assert!(bad.unwrap_err().to_string().contains("allow_send"));

    let created = send(AdminRequest::ClientsCreate {
        name: "support".into(),
        project: "acme".into(),
        grants: vec![g("info", "read,draft"), g("billing", "read")],
        expires: Some("90d".into()),
        allow_ip: vec![],
    })
    .await
    .unwrap();
    let token = created["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("dove_"));

    // AC1: info=read,draft and billing=read; the third project account is invisible.
    let ctx = auth(&env, &token, None).await.unwrap();
    let aliases: Vec<_> = ctx.mailboxes.iter().map(|m| m.alias.as_str()).collect();
    assert_eq!(aliases, vec!["billing", "info"]);
    assert!(ctx.authorize(Capability::Draft, "info").is_ok());
    assert_eq!(ctx.authorize(Capability::Draft, "billing").unwrap_err().code, dove::error::ErrorCode::Forbidden);
    let hidden = ctx.authorize(Capability::Read, "secret").unwrap_err();
    let unknown = ctx.authorize(Capability::Read, "does-not-exist").unwrap_err();
    assert_eq!(hidden.to_json(), unknown.to_json(), "identical not_found for hidden and unknown");

    // A newly added project account stays invisible until granted.
    env.add_account("new", "new@acme.test", "1//rt");
    send(AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "new".into() }).await.unwrap();
    assert!(auth(&env, &token, None).await.unwrap().resolve("new").is_err());

    // Remove + re-add of a mailbox revokes the old grant for good.
    send(AdminRequest::ProjectsRemoveAccount { project: "acme".into(), account: "billing".into() }).await.unwrap();
    send(AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "billing".into() }).await.unwrap();
    assert!(auth(&env, &token, None).await.unwrap().resolve("billing").is_err());

    // set-grants replaces the whole set atomically.
    let shown = send(AdminRequest::ClientsSetGrants { name: "support".into(), grants: vec![g("billing", "read")] })
        .await
        .unwrap();
    assert_eq!(shown["effective"].as_array().unwrap().len(), 1);
    let ctx = auth(&env, &token, None).await.unwrap();
    assert!(ctx.resolve("info").is_err() && ctx.resolve("billing").is_ok());

    // AC11: rotation works immediately and invalidates the old secret.
    let rotated = send(AdminRequest::ClientsRotate { name: "support".into() }).await.unwrap();
    let new_token = rotated["token"].as_str().unwrap().to_string();
    assert!(auth(&env, &token, None).await.is_err());
    assert!(auth(&env, &new_token, None).await.is_ok());
    send(AdminRequest::ClientsRevoke { name: "support".into() }).await.unwrap();
    assert!(auth(&env, &new_token, None).await.is_err());
}

#[tokio::test]
async fn expired_and_ip_bound_tokens_fail() {
    let env = TestEnv::new();
    let sock = start(&env).await;
    env.add_account("info", "info@acme.test", "1//rt");
    client::send(&sock, &AdminRequest::ProjectsCreate { name: "acme".into() }).await.unwrap();
    client::send(&sock, &AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "info".into() })
        .await
        .unwrap();
    let created = client::send(
        &sock,
        &AdminRequest::ClientsCreate {
            name: "laptop".into(),
            project: "acme".into(),
            grants: vec![g("info", "read")],
            expires: None,
            allow_ip: vec!["10.0.0.0/8".into()],
        },
    )
    .await
    .unwrap();
    let token = created["token"].as_str().unwrap();
    assert!(auth(&env, token, Some("10.2.3.4".parse().unwrap())).await.is_ok());
    assert!(auth(&env, token, Some("192.0.2.1".parse().unwrap())).await.is_err());
    env.app.store.call(|c| Ok(c.execute("UPDATE clients SET expires_at = 1", [])?)).await.unwrap();
    assert!(auth(&env, token, Some("10.2.3.4".parse().unwrap())).await.is_err());
    // Malformed and unknown tokens.
    assert!(auth(&env, "dove_short", None).await.is_err());
    assert!(auth(&env, &dove::tokens::generate("dove_"), None).await.is_err());
}

#[tokio::test]
async fn non_operator_uid_is_denied_without_state_change() {
    // The operator is a different uid than the one running this test (AC19, same-host variant).
    let me = nix::unistd::getuid().as_raw();
    let env = TestEnv::with(|cfg| cfg.admin.operator_uid = me.wrapping_add(4242));
    if me == 0 {
        eprintln!("running as root, which is always allowed; skipping");
        return;
    }
    let sock = start(&env).await;
    let before = audit_count(&env).await;
    let err = client::send(&sock, &AdminRequest::ProjectsCreate { name: "evil".into() }).await.unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
    let n: i64 =
        env.app.store.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0))?)).await.unwrap();
    assert_eq!(n, 0);
    let denied: Value = env.app.store.call(|c| Ok(serde_json::to_value(dove::audit::tail(c, 1)?)?)).await.unwrap();
    assert_eq!(denied[0]["tool_or_action"], "admin.denied");
    assert_eq!(audit_count(&env).await, before + 1);
}

#[tokio::test]
async fn every_admin_action_writes_exactly_one_audit_record() {
    let env = TestEnv::new();
    let sock = start(&env).await;
    env.add_account("info", "info@acme.test", "1//rt");
    let reqs = vec![
        AdminRequest::ProjectsCreate { name: "acme".into() },
        AdminRequest::ProjectsCreate { name: "acme".into() }, // fails: duplicate
        AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "info".into() },
        AdminRequest::ProjectsList,
        AdminRequest::ClientsList,
        AdminRequest::AuditVerify,
    ];
    for (i, r) in reqs.into_iter().enumerate() {
        let before = audit_count(&env).await;
        let _ = client::send(&sock, &r).await;
        assert_eq!(audit_count(&env).await, before + 1, "request #{i}");
    }
    let report = client::send(&sock, &AdminRequest::AuditVerify).await.unwrap();
    assert_eq!(report["ok"], true);
    // Admin audit records carry no secrets.
    let created = client::send(
        &sock,
        &AdminRequest::ClientsCreate {
            name: "c1".into(),
            project: "acme".into(),
            grants: vec![g("info", "read")],
            expires: None,
            allow_ip: vec![],
        },
    )
    .await
    .unwrap();
    let token = created["token"].as_str().unwrap().to_string();
    let dump: String = env.app.store.call(|c| Ok(serde_json::to_string(&dove::audit::tail(c, 1000)?)?)).await.unwrap();
    assert!(!dump.contains(&token[5..]));
    let _ = Arc::clone(&env.app);
}

/// `dove upgrade` and `dove doctor` read the running service's version over the admin socket; the call is audited
/// like every admin action.
#[tokio::test]
async fn service_reports_its_version() {
    let env = TestEnv::new();
    let sock = start(&env).await;
    let before = audit_count(&env).await;
    let v = client::send(&sock, &AdminRequest::Version).await.unwrap();
    assert_eq!(v, serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "mode": "server" }));
    assert_eq!(audit_count(&env).await, before + 1);
    let doctor = client::send(&sock, &AdminRequest::Doctor).await.unwrap();
    let row = doctor.as_array().unwrap().iter().find(|c| c["check"] == "service_version").cloned().unwrap();
    assert_eq!(row["detail"], env!("CARGO_PKG_VERSION"));
}
