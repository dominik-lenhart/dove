//! Google connect/reconnect callback (spec 7.3) and the reauth lifecycle over HTTP. Covers AC7 and AC10.

mod support;

use dove::admin::AdminRequest;
use dove::gmail::{SCOPE_COMPOSE, SCOPE_READONLY};
use serde_json::json;
use support::fake_google::{CodeSpec, MessageSpec};
use support::harness::{HOST, Harness, g};

fn all_scopes() -> Vec<String> {
    ["openid", "email", SCOPE_READONLY, SCOPE_COMPOSE].iter().map(|s| s.to_string()).collect()
}

/// Starts a connect or reconnect and returns (state, code_challenge) from the authorization URL.
async fn begin(h: &Harness, req: AdminRequest) -> (String, String) {
    let v = h.admin(req).await.expect("admin connect");
    let url = url::Url::parse(v["open_this_link"].as_str().unwrap()).unwrap();
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["access_type"], "offline");
    (q["state"].clone(), q["code_challenge"].clone())
}

async fn callback(h: &Harness, query: &[(&str, &str)]) -> (u16, String) {
    let r =
        h.http.get(format!("{}/oauth/google/callback", h.base)).header("host", HOST).query(query).send().await.unwrap();
    let status = r.status().as_u16();
    assert_eq!(r.headers()["cache-control"], "no-store");
    (status, r.text().await.unwrap())
}

fn spec(email: &str, sub: &str, challenge: &str) -> CodeSpec {
    CodeSpec {
        email: email.into(),
        sub: sub.into(),
        email_verified: true,
        scopes: all_scopes(),
        code_challenge: challenge.into(),
        aud: None,
        with_refresh_token: true,
    }
}

async fn account_row(h: &Harness, alias: &str) -> Option<(String, i64)> {
    let alias = alias.to_string();
    h.app()
        .store
        .call(move |c| {
            use rusqlite::OptionalExtension;
            Ok(c.query_row("SELECT status, grant_generation FROM accounts WHERE alias = ?1", [alias], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?)
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn connect_succeeds_once_and_state_is_single_use() {
    let h = Harness::start().await;
    h.google.add_mailbox("sales@acme.test", "sub-sales");
    let (state, challenge) =
        begin(&h, AdminRequest::AccountsConnect { alias: "sales".into(), email: "sales@acme.test".into() }).await;
    h.google.register_code("code-1", spec("sales@acme.test", "sub-sales", &challenge));
    let (status, page) = callback(&h, &[("code", "code-1"), ("state", &state)]).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("sales@acme.test") && !page.contains("code-1"));
    assert_eq!(account_row(&h, "sales").await.unwrap().0, "active");
    // Replaying the same state is refused.
    h.google.register_code("code-2", spec("sales@acme.test", "sub-sales", &challenge));
    let (status, _) = callback(&h, &[("code", "code-2"), ("state", &state)]).await;
    assert_eq!(status, 400);
    // Unknown state, Google-side error.
    assert_eq!(callback(&h, &[("code", "x"), ("state", "bogus")]).await.0, 400);
    // A state that already failed once cannot be retried with a valid code.
    h.google.add_mailbox("ops@acme.test", "sub-ops");
    let (st2, ch2) =
        begin(&h, AdminRequest::AccountsConnect { alias: "ops".into(), email: "ops@acme.test".into() }).await;
    assert_eq!(callback(&h, &[("error", "access_denied"), ("state", &st2)]).await.0, 400);
    h.google.register_code("code-ops", spec("ops@acme.test", "sub-ops", &ch2));
    assert_eq!(callback(&h, &[("code", "code-ops"), ("state", &st2)]).await.0, 400);
    assert!(account_row(&h, "ops").await.is_none());
    // The connected mailbox is usable through MCP.
    h.project("p", &["sales"]).await;
    let token = h.token("p", "agent", vec![g("sales", "read")]).await;
    let id = h.google.add_message(
        "sales@acme.test",
        MessageSpec {
            from: "a@b.example".into(),
            subject: "s".into(),
            text: Some("t".into()),
            internal_date_ms: 1,
            ..Default::default()
        },
    );
    h.ok(&token, "get_message", json!({"account":"sales","message_id":id})).await;
    h.google.assert_no_violations();
}

#[tokio::test]
async fn callback_rejections_leave_no_account_and_revoke_nothing() {
    let h = Harness::start().await;
    h.google.add_mailbox("sales@acme.test", "sub-sales");
    h.google.add_mailbox("other@acme.test", "sub-other");
    type Mutate = fn(&mut CodeSpec);
    let cases: Vec<(&str, Mutate)> = vec![
        ("wrong account", |s| {
            s.email = "other@acme.test".into();
            s.sub = "sub-other".into();
        }),
        ("unverified email", |s| s.email_verified = false),
        ("missing compose scope", |s| s.scopes.retain(|x| x != SCOPE_COMPOSE)),
        ("missing readonly scope", |s| s.scopes.retain(|x| x != SCOPE_READONLY)),
        ("foreign audience", |s| s.aud = Some("someone-else.apps.googleusercontent.com".into())),
        ("no refresh token", |s| s.with_refresh_token = false),
        ("pkce mismatch", |s| s.code_challenge = "not-the-challenge".into()),
    ];
    for (i, (name, mutate)) in cases.into_iter().enumerate() {
        let (state, challenge) =
            begin(&h, AdminRequest::AccountsConnect { alias: "sales".into(), email: "sales@acme.test".into() }).await;
        let mut s = spec("sales@acme.test", "sub-sales", &challenge);
        mutate(&mut s);
        let code = format!("code-{i}");
        h.google.register_code(&code, s);
        let (status, page) = callback(&h, &[("code", &code), ("state", &state)]).await;
        assert_eq!(status, 400, "{name}: {page}");
        assert!(account_row(&h, "sales").await.is_none(), "{name}");
    }
    assert!(h.google.revoked_tokens().is_empty(), "rejections must not revoke shared grants");
    let n: i64 = h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row("SELECT count(*) FROM audit WHERE tool_or_action = 'accounts.connect_callback'", [], |r| {
                r.get(0)
            })?)
        })
        .await
        .unwrap();
    assert_eq!(n, 7, "one audit record per callback");
}

#[tokio::test]
async fn reauth_then_reconnect_restores_access_and_notifies_per_generation() {
    let mut h = Harness::start().await;
    h.mailbox("info", "info@acme.test");
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read")]).await;
    let id = h.google.add_message(
        "info@acme.test",
        MessageSpec {
            from: "a@b.example".into(),
            subject: "s".into(),
            text: Some("t".into()),
            internal_date_ms: 1,
            ..Default::default()
        },
    );
    let notes = |h: &Harness| h.app().notifier.sent.lock().unwrap().iter().filter(|m| m.contains("'info'")).count();
    h.google.invalidate_refresh_tokens("info@acme.test");
    for _ in 0..2 {
        assert_eq!(
            h.err(&token, "get_message", json!({"account":"info","message_id":id})).await,
            "account_unavailable"
        );
    }
    let (status, gen1) = account_row(&h, "info").await.unwrap();
    assert_eq!((status.as_str(), notes(&h)), ("reauth_required", 1));

    // Reconnect with a different Google identity is refused (sub pinning).
    let (state, challenge) = begin(&h, AdminRequest::AccountsReconnect { alias: "info".into() }).await;
    h.google.register_code("evil", spec("info@acme.test", "sub-someone-else", &challenge));
    assert_eq!(callback(&h, &[("code", "evil"), ("state", &state)]).await.0, 400);
    assert_eq!(account_row(&h, "info").await.unwrap().0, "reauth_required");

    // Proper reconnect: new generation, access restored without restart.
    let (state, challenge) = begin(&h, AdminRequest::AccountsReconnect { alias: "info".into() }).await;
    h.google.register_code("good", spec("info@acme.test", "sub-info", &challenge));
    let (status, page) = callback(&h, &[("code", "good"), ("state", &state)]).await;
    assert_eq!(status, 200, "{page}");
    let (status, gen2) = account_row(&h, "info").await.unwrap();
    assert_eq!(status, "active");
    assert!(gen2 > gen1);
    h.ok(&token, "get_message", json!({"account":"info","message_id":id})).await;
    // The reconnected grant survives a restart (fresh token manager, refresh from the stored grant).
    h.restart().await;
    h.ok(&token, "get_message", json!({"account":"info","message_id":id})).await;
    assert!(h.google.revoked_tokens().is_empty(), "a successful reconnect revokes nothing");

    // A later revocation of the new grant notifies again, once.
    h.google.invalidate_refresh_tokens("info@acme.test");
    let acct: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT id FROM accounts WHERE alias='info'", [], |r| r.get(0))?))
        .await
        .unwrap();
    h.app().google.tokens().evict(&acct);
    for _ in 0..2 {
        assert_eq!(
            h.err(&token, "get_message", json!({"account":"info","message_id":id})).await,
            "account_unavailable"
        );
    }
    // This process (restarted after the first notification) sent exactly one; durable keys show one per generation.
    assert_eq!(notes(&h), 1);
    let keys: i64 = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT count(*) FROM notifications WHERE key LIKE 'reauth:%'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(keys, 2);
}

#[tokio::test]
async fn expired_state_is_rejected_without_storing_anything() {
    let h = Harness::start().await;
    h.google.add_mailbox("sales@acme.test", "sub-sales");
    let (state, challenge) =
        begin(&h, AdminRequest::AccountsConnect { alias: "sales".into(), email: "sales@acme.test".into() }).await;
    h.app().store.call(|c| Ok(c.execute("UPDATE pending_connects SET expires_at = 1", [])?)).await.unwrap();
    h.google.register_code("late", spec("sales@acme.test", "sub-sales", &challenge));
    let (status, page) = callback(&h, &[("code", "late"), ("state", &state)]).await;
    assert_eq!(status, 400, "{page}");
    assert!(account_row(&h, "sales").await.is_none());
    assert_eq!(h.google.count("POST", "token"), 0, "an expired state never reaches the code exchange");
}
