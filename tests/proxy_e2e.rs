//! Client address behind the reverse proxy (spec 6.6): a local process that connects to the loopback listener
//! directly must not be able to pick its source address with X-Forwarded-For.

mod support;

use dove::admin::AdminRequest;
use serde_json::{Value, json};
use support::harness::{HOST, Harness, g};

const PUBLIC_IP: &str = "203.0.113.7";

fn ping() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
}

/// A token that may only be used from 203.0.113.0/24.
async fn allow_ip_token(h: &Harness) -> String {
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let v = h
        .admin(AdminRequest::ClientsCreate {
            name: "office".into(),
            project: "acme".into(),
            grants: vec![g("info", "read")],
            expires: None,
            allow_ip: vec!["203.0.113.0/24".into()],
        })
        .await
        .unwrap();
    v["token"].as_str().unwrap().to_string()
}

fn secret(h: &Harness) -> String {
    h.app().proxy_secret.as_deref().expect("test config sets a proxy secret").to_string()
}

async fn mcp(h: &Harness, token: &str, headers: &[(&str, &str)]) -> u16 {
    h.post_mcp(Some(token), ping(), headers).await.status().as_u16()
}

#[tokio::test]
async fn forwarded_for_counts_only_with_the_proxy_secret() {
    let h = Harness::start().await;
    let token = allow_ip_token(&h).await;
    let secret = secret(&h);
    let wrong = format!("{}x", &secret[..secret.len() - 1]);
    // The loopback peer itself is outside the allowlist.
    assert_eq!(mcp(&h, &token, &[]).await, 401);
    // A local process forging the header, with no or a wrong proxy secret, is still the loopback peer.
    assert_eq!(mcp(&h, &token, &[("x-forwarded-for", PUBLIC_IP)]).await, 401);
    assert_eq!(mcp(&h, &token, &[("x-forwarded-for", PUBLIC_IP), ("x-dove-proxy-auth", &wrong)]).await, 401);
    assert_eq!(mcp(&h, &token, &[("x-forwarded-for", PUBLIC_IP), ("x-dove-proxy-auth", "")]).await, 401);
    // The proxy (it knows the secret) is believed.
    assert_eq!(mcp(&h, &token, &[("x-forwarded-for", PUBLIC_IP), ("x-dove-proxy-auth", &secret)]).await, 200);
    let last_ip: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT last_ip FROM clients WHERE name = 'office'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(last_ip, PUBLIC_IP);
}

#[tokio::test]
async fn forged_forwarded_for_shares_the_loopback_rate_limit() {
    let h = Harness::start_with(|c| c.oauth.redeem_per_minute = 2).await;
    let secret = secret(&h);
    let redeem = |ip: String, auth: Option<String>| {
        let mut r = h
            .http
            .post(format!("{}/connect/redeem", h.base))
            .header("host", HOST)
            .header("x-forwarded-for", ip)
            .json(&json!({"invitation": "dovei_invalid"}));
        if let Some(a) = auth {
            r = r.header("x-dove-proxy-auth", a);
        }
        async move { r.send().await.unwrap().status().as_u16() }
    };
    // Rotating forged addresses does not give a local caller fresh limits: all three count as 127.0.0.1.
    let mut forged = vec![];
    for i in 1..=3 {
        forged.push(redeem(format!("198.51.100.{i}"), None).await);
    }
    assert_eq!(forged[2], 429, "{forged:?}");
    assert!(forged[..2].iter().all(|s| *s != 429), "{forged:?}");
    // Through the proxy each client address has its own bucket.
    for i in 1..=3 {
        assert_ne!(redeem(format!("192.0.2.{i}"), Some(secret.clone())).await, 429);
    }
}

#[tokio::test]
async fn without_a_proxy_secret_loopback_is_trusted_as_before() {
    let h = Harness::start_with(|c| c.secrets.proxy_secret_file = None).await;
    assert!(h.app().proxy_secret.is_none());
    let token = allow_ip_token(&h).await;
    assert_eq!(mcp(&h, &token, &[]).await, 401);
    assert_eq!(mcp(&h, &token, &[("x-forwarded-for", PUBLIC_IP)]).await, 200);
}

/// Local mode has no reverse proxy (PLAN A58): X-Forwarded-For is ignored even with the proxy secret, and without one
/// (the local-mode default) a local process cannot pick its address either.
#[tokio::test]
async fn local_mode_never_trusts_forwarded_for() {
    let h = Harness::start_local(|_| {}).await;
    let host = h.base.trim_start_matches("http://").to_string();
    let token = allow_ip_token(&h).await;
    let secret = secret(&h);
    assert_eq!(mcp(&h, &token, &[("host", &host), ("x-forwarded-for", PUBLIC_IP)]).await, 401);
    let forged = [("host", host.as_str()), ("x-forwarded-for", PUBLIC_IP), ("x-dove-proxy-auth", &secret)];
    assert_eq!(mcp(&h, &token, &forged).await, 401);

    let h = Harness::start_local(|c| c.secrets.proxy_secret_file = None).await;
    let host = h.base.trim_start_matches("http://").to_string();
    let token = allow_ip_token(&h).await;
    assert_eq!(mcp(&h, &token, &[("host", &host), ("x-forwarded-for", PUBLIC_IP)]).await, 401);
}
