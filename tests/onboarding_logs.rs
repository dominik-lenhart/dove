//! Secret hygiene of onboarding and OAuth (spec 5.6, 6.2, AC9 for authentication changes).
//!
//! Captures every log line of the process at TRACE level *without* the redaction layer, runs invitations, login
//! redemption, dynamic registration, approval, code exchange, refresh, reuse and revocation, and then checks that no
//! invitation, connection token, code, access/refresh token or PKCE verifier appears in the logs, in the audit
//! table or in plaintext in the state store files. One test per file: the subscriber is process-global.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use dove::admin::AdminRequest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::harness::{HOST, Harness};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn b64url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn field(html: &str, name: &str) -> String {
    let pat = format!("name=\"{name}\" value=\"");
    let start = html.find(&pat).unwrap() + pat.len();
    html[start..].split('"').next().unwrap().to_string()
}

#[tokio::test]
async fn no_onboarding_secret_reaches_logs_audit_or_store() {
    let cap = Capture::default();
    let writer = cap.clone();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("trace"))
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .init();

    let h = Harness::start_with(|c| c.oauth.redeem_per_minute = 1000).await;
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let web = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let url = |p: &str| format!("{}{p}", h.base);
    let invite = |name: &str| {
        h.admin(AdminRequest::ClientsInvite {
            name: name.into(),
            project: "acme".into(),
            accounts: vec!["all".into()],
            capabilities: "read".into(),
            expires: None,
            allow_ip: vec![],
        })
    };
    let mut secrets: Vec<String> = Vec::new();

    // Login redemption, then a reuse attempt and a tool call with the issued token.
    let inv = invite("laptop").await.unwrap()["invitation"].as_str().unwrap().to_string();
    let r: Value = web
        .post(url("/connect/redeem"))
        .header("host", HOST)
        .json(&json!({"invitation": inv}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = r["token"].as_str().unwrap().to_string();
    web.post(url("/connect/redeem")).header("host", HOST).json(&json!({"invitation": inv})).send().await.unwrap();
    h.ok(&token, "list_accounts", json!({})).await;
    secrets.extend([inv, token]);

    // OAuth: register, approve, exchange, refresh, replay the old refresh token (family revocation).
    let redirect = "https://claude.ai/api/mcp/auth_callback";
    let reg: Value = web
        .post(url("/oauth/dove/register"))
        .header("host", HOST)
        .json(&json!({"redirect_uris": [redirect]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = reg["client_id"].as_str().unwrap().to_string();
    let verifier = b64url(&Sha256::digest(b"canary-verifier-seed"));
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    let inv = invite("web").await.unwrap()["invitation"].as_str().unwrap().to_string();
    let mut auth = url::Url::parse(&url("/oauth/dove/authorize")).unwrap();
    auth.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", redirect),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", "s"),
    ]);
    let r = web.get(auth).header("host", HOST).send().await.unwrap();
    let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let html = r.text().await.unwrap();
    let (rid, csrf) = (field(&html, "rid"), field(&html, "csrf"));
    let post = |form: Vec<(&str, String)>| {
        web.post(url("/oauth/dove/authorize")).header("host", HOST).header("cookie", cookie.clone()).form(&form).send()
    };
    let html = post(vec![
        ("rid", rid.clone()),
        ("csrf", csrf.clone()),
        ("step", "invitation".into()),
        ("action", "continue".into()),
        ("invitation", inv.clone()),
    ])
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    // The checkbox carries the account id: read.<id>.
    let read = html.split("name=\"").find(|s| s.starts_with("read.")).unwrap().split('"').next().unwrap().to_string();
    let r = post(vec![
        ("rid", rid),
        ("csrf", csrf.clone()),
        ("step", "approve".into()),
        ("action", "approve".into()),
        (read.as_str(), "on".into()),
    ])
    .await
    .unwrap();
    let loc = url::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    let code = loc.query_pairs().find(|(k, _)| k == "code").unwrap().1.into_owned();
    let token_req =
        |form: Vec<(&'static str, String)>| web.post(url("/oauth/dove/token")).header("host", HOST).form(&form).send();
    let t1: Value = token_req(vec![
        ("grant_type", "authorization_code".into()),
        ("code", code.clone()),
        ("redirect_uri", redirect.into()),
        ("client_id", client_id.clone()),
        ("code_verifier", verifier.clone()),
    ])
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let (at1, rt1) =
        (t1["access_token"].as_str().unwrap().to_string(), t1["refresh_token"].as_str().unwrap().to_string());
    h.ok(&at1, "list_accounts", json!({})).await;
    let t2: Value = token_req(vec![
        ("grant_type", "refresh_token".into()),
        ("refresh_token", rt1.clone()),
        ("client_id", client_id.clone()),
    ])
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let (at2, rt2) =
        (t2["access_token"].as_str().unwrap().to_string(), t2["refresh_token"].as_str().unwrap().to_string());
    // Replays and failures go through the error paths too.
    token_req(vec![
        ("grant_type", "refresh_token".into()),
        ("refresh_token", rt1.clone()),
        ("client_id", client_id.clone()),
    ])
    .await
    .unwrap();
    token_req(vec![
        ("grant_type", "authorization_code".into()),
        ("code", code.clone()),
        ("redirect_uri", redirect.into()),
        ("client_id", client_id.clone()),
        ("code_verifier", verifier.clone()),
    ])
    .await
    .unwrap();
    web.post(url("/oauth/dove/revoke"))
        .header("host", HOST)
        .form(&[("token", rt2.as_str()), ("client_id", &client_id)])
        .send()
        .await
        .unwrap();
    h.post_mcp(Some(&at2), json!({"jsonrpc":"2.0","id":1,"method":"ping"}), &[]).await;
    secrets.extend([inv, code, verifier, at1, rt1, at2, rt2, csrf]);

    // Logs.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let logs = String::from_utf8_lossy(&cap.0.lock().unwrap()).into_owned();
    assert!(logs.len() > 1000, "the capture should contain real log output ({} bytes)", logs.len());
    // Audit table: every column of every row.
    let audit: String = h
        .app()
        .store
        .call(|c| {
            let mut s = c.prepare(
                "SELECT actor || '|' || COALESCE(project,'') || '|' || tool_or_action || '|' || object_ids || '|' || result_code FROM audit",
            )?;
            let rows: Vec<String> = s.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            Ok(rows.join("\n"))
        })
        .await
        .unwrap();
    assert!(
        audit.contains("oauth.refresh|refresh_reuse_revoked") || audit.contains("refresh_reuse_revoked"),
        "{audit}"
    );
    // State store files (hash-only storage).
    let db = h.app().cfg.state_db_path();
    h.app().store.call(|c| Ok(c.execute_batch("PRAGMA wal_checkpoint(FULL);")?)).await.unwrap();
    let mut bytes = std::fs::read(&db).unwrap();
    if let Ok(w) = std::fs::read(format!("{}-wal", db.display())) {
        bytes.extend(w);
    }
    for s in &secrets {
        // Strip only Dove's known prefixes; unprefixed secrets (codes, PKCE verifier, CSRF) contain '_' at random.
        let body =
            ["dovei_", "doveat_", "dovert_", "dovec_", "dove_"].iter().find_map(|p| s.strip_prefix(p)).unwrap_or(s);
        assert!(body.len() >= 20, "canary too short to be meaningful");
        assert!(!logs.contains(body), "secret found in logs: {}...", &s[..8.min(s.len())]);
        assert!(!audit.contains(body), "secret found in audit");
        assert!(!bytes.windows(body.len()).any(|w| w == body.as_bytes()), "secret stored in plaintext: {}...", &s[..8]);
    }
}
