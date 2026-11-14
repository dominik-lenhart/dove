//! Invitations and `/connect/redeem` (spec 5.2a, 5.6, AC22 server side) over real HTTP.

mod support;

use dove::admin::AdminRequest;
use serde_json::{Value, json};
use support::harness::{HOST, Harness};

async fn setup(customize: impl FnOnce(&mut dove::config::Config)) -> Harness {
    let h = Harness::start_with(customize).await;
    h.mailbox("info", "info@acme.test");
    h.mailbox("billing", "billing@acme.test");
    h.project("acme", &["info", "billing"]).await;
    h
}

async fn invite(h: &Harness, name: &str, accounts: &[&str], caps: &str) -> Result<Value, String> {
    h.admin(AdminRequest::ClientsInvite {
        name: name.into(),
        project: "acme".into(),
        accounts: accounts.iter().map(|s| s.to_string()).collect(),
        capabilities: caps.into(),
        expires: None,
        allow_ip: vec![],
        redact_secrets: None,
    })
    .await
}

async fn redeem(h: &Harness, body: Value) -> (u16, Value) {
    let r = h.http.post(format!("{}/connect/redeem", h.base)).header("host", HOST).json(&body).send().await.unwrap();
    assert_eq!(r.headers()["cache-control"], "no-store");
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

async fn clients_named(h: &Harness, name: &'static str) -> i64 {
    h.app()
        .store
        .call(move |c| Ok(c.query_row("SELECT COUNT(*) FROM clients WHERE name = ?1", [name], |r| r.get(0))?))
        .await
        .unwrap()
}

#[tokio::test]
async fn redeem_issues_one_independent_connection() {
    let h = setup(|_| {}).await;
    let v = invite(&h, "laptop", &["info"], "read,draft").await.unwrap();
    let inv = v["invitation"].as_str().unwrap().to_string();
    assert!(inv.starts_with("dovei_") && inv.len() >= 6 + 43, "at least 256 random bits");
    // Hash-only storage.
    let stored: Vec<u8> = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT secret_hash FROM invitations", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_ne!(stored, inv.as_bytes());
    let (s, r) = redeem(&h, json!({ "invitation": inv })).await;
    assert_eq!(s, 200, "{r}");
    let token = r["token"].as_str().unwrap();
    assert_eq!(r["mailboxes"], json!([{ "account": "info", "email": "info@acme.test", "actions": "read,draft" }]));
    assert_eq!(r["mcp_url"], "https://dove.example.com/mcp");
    let acc = h.ok(token, "list_accounts", json!({})).await;
    assert_eq!(acc["accounts"].as_array().unwrap().len(), 1);
    // Single use.
    let (s, r) = redeem(&h, json!({ "invitation": inv })).await;
    assert_eq!((s, r["error"].as_str().unwrap()), (400, "invalid_invitation"));
    // Independently revocable; the operator sees it like any other connection.
    let show = h.admin(AdminRequest::ClientsShow { name: "laptop".into() }).await.unwrap();
    assert_eq!((show["kind"].as_str(), show["created_via"].as_str()), (Some("token"), Some("invite")));
    h.admin(AdminRequest::ClientsRevoke { name: "laptop".into() }).await.unwrap();
    let r = h.post_mcp(Some(token), json!({"jsonrpc":"2.0","id":1,"method":"ping"}), &[]).await;
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn concurrent_redemption_has_exactly_one_winner() {
    let h = setup(|c| c.oauth.redeem_per_minute = 1000).await;
    let inv = invite(&h, "race", &["all"], "read").await.unwrap()["invitation"].as_str().unwrap().to_string();
    let futs = (0..16).map(|_| redeem(&h, json!({ "invitation": inv })));
    let results = futures::future::join_all(futs).await;
    let winners = results.iter().filter(|(s, _)| *s == 200).count();
    assert_eq!(winners, 1, "{results:?}");
    assert_eq!(clients_named(&h, "race").await, 1);
}

#[tokio::test]
async fn expired_unknown_and_malformed_invitations() {
    let h = setup(|c| c.oauth.redeem_per_minute = 1000).await;
    let inv = invite(&h, "late", &["info"], "read").await.unwrap()["invitation"].as_str().unwrap().to_string();
    h.app().store.call(|c| Ok(c.execute("UPDATE invitations SET expires_at = 1", [])?)).await.unwrap();
    assert_eq!(redeem(&h, json!({ "invitation": inv })).await.0, 400);
    assert_eq!(clients_named(&h, "late").await, 0);
    // A client token is not an invitation.
    let token = h.token("acme", "draft-only", vec![support::harness::g("info", "read,draft")]).await;
    assert_eq!(redeem(&h, json!({ "invitation": token })).await.0, 400);
    // Extra fields cannot add grants; the invitation is not consumed by the rejected request.
    let inv = invite(&h, "extra", &["info"], "read").await.unwrap()["invitation"].as_str().unwrap().to_string();
    let (s, _) =
        redeem(&h, json!({ "invitation": inv, "grants": [{"account": "billing", "actions": "read,draft,send"}] }))
            .await;
    assert_eq!(s, 400);
    // The invitation never travels in a URL: GET is not routed and a query parameter is ignored.
    let r =
        h.http.get(format!("{}/connect/redeem?invitation={inv}", h.base)).header("host", HOST).send().await.unwrap();
    assert_eq!(r.status(), 405);
    let r = h
        .http
        .post(format!("{}/connect/redeem?invitation={inv}", h.base))
        .header("host", HOST)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let (s, r) = redeem(&h, json!({ "invitation": inv })).await;
    assert_eq!(s, 200);
    assert_eq!(r["mailboxes"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn redemption_is_rate_limited() {
    let h = setup(|c| c.oauth.redeem_per_minute = 3).await;
    let mut statuses = vec![];
    for _ in 0..5 {
        statuses.push(redeem(&h, json!({ "invitation": "dovei_nope" })).await.0);
    }
    assert_eq!(statuses, [400, 400, 400, 429, 429]);
}

#[tokio::test]
async fn all_expands_once_and_invitation_rules() {
    let h = setup(|c| c.oauth.redeem_per_minute = 1000).await;
    let v = invite(&h, "all-reader", &["all"], "read").await.unwrap();
    assert_eq!(v["grants"], json!([{"account": "billing", "actions": "read"}, {"account": "info", "actions": "read"}]));
    let inv = v["invitation"].as_str().unwrap().to_string();
    // A mailbox added to the project after the invitation is not part of it.
    h.mailbox("later", "later@acme.test");
    h.admin(AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "later".into() }).await.unwrap();
    let (s, r) = redeem(&h, json!({ "invitation": inv })).await;
    assert_eq!(s, 200);
    let token = r["token"].as_str().unwrap();
    assert_eq!(h.err(token, "list_labels", json!({"account": "later"})).await, "not_found");
    assert_eq!(r["mailboxes"].as_array().unwrap().len(), 2);

    // Send needs the instance gate; draft needs read; names are unique; unknown accounts fail.
    assert!(invite(&h, "s", &["info"], "read,draft,send").await.unwrap_err().contains("allow_send"));
    assert!(invite(&h, "d", &["info"], "draft").await.is_err());
    assert!(invite(&h, "all-reader", &["info"], "read").await.unwrap_err().contains("already exists"));
    assert!(invite(&h, "x", &["nope"], "read").await.is_err());
    invite(&h, "pending", &["info"], "read").await.unwrap();
    assert!(invite(&h, "pending", &["info"], "read").await.is_err(), "open invitation reserves the name");

    // Removing a mailbox from the project cancels open invitations, so a re-add cannot resurrect them.
    let inv = invite(&h, "cancelled", &["billing"], "read").await.unwrap()["invitation"].as_str().unwrap().to_string();
    h.admin(AdminRequest::ProjectsRemoveAccount { project: "acme".into(), account: "billing".into() }).await.unwrap();
    h.admin(AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "billing".into() }).await.unwrap();
    assert_eq!(redeem(&h, json!({ "invitation": inv })).await.0, 400);
}

#[tokio::test]
async fn removing_an_account_cancels_open_invitations_listing_it() {
    let h = setup(|_| {}).await;
    let inv = invite(&h, "rm", &["all"], "read").await.unwrap()["invitation"].as_str().unwrap().to_string();
    let v = h.admin(AdminRequest::AccountsRemove { alias: "billing".into() }).await.unwrap();
    assert_eq!(v["pending_invitations_cancelled"], 1);
    // The invitation no longer matches what the operator issued, so it is not redeemed with a shorter list.
    let (s, r) = redeem(&h, json!({ "invitation": inv })).await;
    assert_eq!(s, 400, "{r}");
}

#[tokio::test]
async fn agent_token_cannot_reach_onboarding_authority() {
    let h = setup(|_| {}).await;
    let token = h.token("acme", "agent", vec![support::harness::g("info", "read,draft")]).await;
    // No MCP tool mints invitations or changes grants.
    assert_eq!(h.err(&token, "clients_invite", json!({"name": "x", "project": "acme"})).await, "invalid_argument");
    let names = h.tool_names(&token).await;
    assert!(names.iter().all(|n| !n.contains("invite") && !n.contains("client") && !n.contains("grant")), "{names:?}");
    // No admin route over HTTP, with or without the token.
    for path in ["/admin", "/admin/clients/invite", "/connect/invite"] {
        let r = h.http.post(format!("{}{path}", h.base)).header("host", HOST).bearer_auth(&token).send().await.unwrap();
        assert_eq!(r.status(), 404, "{path}");
    }
}

/// An invitation's `--allow-ip` list applies to `dove login`: from another address the redemption fails with the
/// generic error and the invitation stays usable.
#[tokio::test]
async fn redeem_checks_the_invitation_ip_allowlist() {
    let h = setup(|_| {}).await;
    let inv = h
        .admin(AdminRequest::ClientsInvite {
            name: "office".into(),
            project: "acme".into(),
            accounts: vec!["info".into()],
            capabilities: "read".into(),
            expires: None,
            allow_ip: vec!["192.0.2.0/24".into()],
            redact_secrets: None,
        })
        .await
        .unwrap()["invitation"]
        .as_str()
        .unwrap()
        .to_string();
    let secret = h.app().proxy_secret.as_deref().unwrap().to_string();
    let redeem_from = |ip: &'static str| {
        let (h, inv, secret) = (&h, inv.clone(), secret.clone());
        async move {
            let r = h
                .http
                .post(format!("{}/connect/redeem", h.base))
                .header("host", HOST)
                .header("x-forwarded-for", ip)
                .header("x-dove-proxy-auth", secret)
                .json(&json!({ "invitation": inv }))
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.json::<Value>().await.unwrap())
        }
    };
    let (s, r) = redeem_from("198.51.100.1").await;
    assert_eq!((s, r["error"].as_str().unwrap()), (400, "invalid_invitation"), "{r}");
    assert_eq!(r, redeem(&h, json!({ "invitation": "dovei_unknown" })).await.1, "indistinguishable from unknown");
    assert_eq!(clients_named(&h, "office").await, 0);
    let (s, r) = redeem_from("192.0.2.10").await;
    assert_eq!(s, 200, "the invitation was not used up: {r}");
    assert_eq!(clients_named(&h, "office").await, 1);
}
