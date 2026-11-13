//! Downstream OAuth (spec 5.6, AC23 server side) and invitation redemption over real HTTP.
//! Host compatibility with real ChatGPT/Claude is not tested here (unverified, see docs/PLAN.md).

mod support;

use std::collections::HashMap;

use dove::admin::AdminRequest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::harness::{HOST, Harness};

const REDIRECT: &str = "https://host.example/callback";

fn b64url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn verifier() -> String {
    b64url(&rand_bytes())
}

fn rand_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn challenge(v: &str) -> String {
    b64url(&Sha256::digest(v.as_bytes()))
}

struct Oauth {
    h: Harness,
    web: reqwest::Client,
}

fn field(html: &str, name: &str) -> String {
    let pat = format!("name=\"{name}\" value=\"");
    let start = html.find(&pat).unwrap_or_else(|| panic!("no field {name} in {html}")) + pat.len();
    html[start..].split('"').next().unwrap().to_string()
}

/// The full name of the first form field starting with `prefix` (checkbox names carry account ids).
fn field_name(html: &str, prefix: &str) -> String {
    let pat = format!("name=\"{prefix}");
    let start = html.find(&pat).unwrap_or_else(|| panic!("no field {prefix} in {html}")) + 6;
    html[start..].split('"').next().unwrap().to_string()
}

/// Translates a positional check such as `read.0` (the n-th mailbox on the approval page) into the real field
/// name, which carries the account id. Anything else is passed through unchanged.
fn check_name(html: &str, check: &str) -> String {
    let ids: Vec<&str> = html.split("name=\"read.").skip(1).filter_map(|s| s.split('"').next()).collect();
    match check.split_once('.') {
        Some((kind, n)) if n.parse::<usize>().is_ok_and(|n| n < ids.len()) => {
            format!("{kind}.{}", ids[n.parse::<usize>().unwrap()])
        }
        _ => check.to_string(),
    }
}

fn query_of(location: &str) -> HashMap<String, String> {
    url::Url::parse(location).unwrap().query_pairs().into_owned().collect()
}

impl Oauth {
    async fn new() -> Self {
        Self::with(|_| {}).await
    }

    async fn with(customize: impl FnOnce(&mut dove::config::Config)) -> Self {
        let h = Harness::start_with(customize).await;
        h.mailbox("info", "info@acme.test");
        h.mailbox("billing", "billing@acme.test");
        h.mailbox("secret", "secret@acme.test");
        h.project("acme", &["info", "billing"]).await;
        h.project("other", &["secret"]).await;
        let web = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        Self { h, web }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.h.base)
    }

    async fn invite(&self, name: &str, accounts: &[&str], caps: &str) -> String {
        let v = self
            .h
            .admin(AdminRequest::ClientsInvite {
                name: name.into(),
                project: "acme".into(),
                accounts: accounts.iter().map(|s| s.to_string()).collect(),
                capabilities: caps.into(),
                expires: None,
                allow_ip: vec![],
            })
            .await
            .unwrap();
        v["invitation"].as_str().unwrap().to_string()
    }

    async fn register(&self, redirect: &str) -> String {
        let r = self
            .web
            .post(self.url("/oauth/dove/register"))
            .header("host", HOST)
            .json(&json!({ "redirect_uris": [redirect], "client_name": "Test host" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 201);
        r.json::<Value>().await.unwrap()["client_id"].as_str().unwrap().to_string()
    }

    async fn authorize_get(&self, params: &[(&str, &str)]) -> reqwest::Response {
        let mut url = url::Url::parse(&self.url("/oauth/dove/authorize")).unwrap();
        url.query_pairs_mut().extend_pairs(params);
        self.web.get(url).header("host", HOST).send().await.unwrap()
    }

    fn params<'a>(client_id: &'a str, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", "st-123"),
            ("resource", "https://dove.example.com/mcp"),
        ]
    }

    async fn post_form(&self, cookie: &str, form: &[(&str, &str)]) -> reqwest::Response {
        self.web
            .post(self.url("/oauth/dove/authorize"))
            .header("host", HOST)
            .header("cookie", cookie)
            .form(form)
            .send()
            .await
            .unwrap()
    }

    /// Runs the browser part: returns (cookie, rid, csrf, step-2 html).
    async fn enter_invitation(
        &self,
        client_id: &str,
        chal: &str,
        invitation: &str,
    ) -> (String, String, String, String) {
        let r = self.authorize_get(&Self::params(client_id, chal)).await;
        assert_eq!(r.status(), 200);
        let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
        assert!(r.headers()["content-security-policy"].to_str().unwrap().contains("frame-ancestors 'none'"));
        let html = r.text().await.unwrap();
        let (rid, csrf) = (field(&html, "rid"), field(&html, "csrf"));
        let r = self
            .post_form(
                &cookie,
                &[
                    ("rid", &rid),
                    ("csrf", &csrf),
                    ("step", "invitation"),
                    ("action", "continue"),
                    ("invitation", invitation),
                ],
            )
            .await;
        assert_eq!(r.status(), 200);
        let html = r.text().await.unwrap();
        (cookie, rid, csrf, html)
    }

    /// Full approval; `checks` are the checkbox names to submit. Returns the code from the redirect.
    async fn approve(&self, client_id: &str, chal: &str, invitation: &str, checks: &[&str]) -> String {
        let (cookie, rid, csrf, html) = self.enter_invitation(client_id, chal, invitation).await;
        assert!(html.contains("Approve"), "{html}");
        let names: Vec<String> = checks.iter().map(|c| check_name(&html, c)).collect();
        let mut form: Vec<(&str, &str)> =
            vec![("rid", &rid), ("csrf", &csrf), ("step", "approve"), ("action", "approve")];
        form.extend(names.iter().map(|c| (c.as_str(), "on")));
        let r = self.post_form(&cookie, &form).await;
        assert_eq!(r.status(), 303);
        let q = query_of(r.headers()["location"].to_str().unwrap());
        assert_eq!(q["state"], "st-123");
        assert_eq!(q["iss"], "https://dove.example.com");
        q["code"].clone()
    }

    async fn token(&self, form: &[(&str, &str)]) -> (u16, Value) {
        let r = self.web.post(self.url("/oauth/dove/token")).header("host", HOST).form(form).send().await.unwrap();
        assert_eq!(r.headers()["cache-control"], "no-store");
        (r.status().as_u16(), r.json().await.unwrap())
    }

    async fn exchange(&self, client_id: &str, code: &str, verifier: &str) -> (u16, Value) {
        self.token(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ])
        .await
    }

    async fn refresh(&self, client_id: &str, rt: &str) -> (u16, Value) {
        self.token(&[("grant_type", "refresh_token"), ("refresh_token", rt), ("client_id", client_id)]).await
    }

    /// A connected host: returns (client_id, token response).
    async fn connected(&self, name: &str, caps: &str, checks: &[&str]) -> (String, Value) {
        let inv = self.invite(name, &["all"], caps).await;
        let client_id = self.register(REDIRECT).await;
        let v = verifier();
        let code = self.approve(&client_id, &challenge(&v), &inv, checks).await;
        let (status, tok) = self.exchange(&client_id, &code, &v).await;
        assert_eq!(status, 200, "{tok}");
        (client_id, tok)
    }

    async fn mcp_status(&self, token: &str) -> u16 {
        self.h.post_mcp(Some(token), json!({"jsonrpc":"2.0","id":1,"method":"ping"}), &[]).await.status().as_u16()
    }
}

#[tokio::test]
async fn discovery_metadata() {
    let o = Oauth::new().await;
    for path in ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"] {
        let v: Value = o.web.get(o.url(path)).header("host", HOST).send().await.unwrap().json().await.unwrap();
        assert_eq!(v["resource"], "https://dove.example.com/mcp");
        assert_eq!(v["authorization_servers"], json!(["https://dove.example.com"]));
    }
    let v: Value = o
        .web
        .get(o.url("/.well-known/oauth-authorization-server"))
        .header("host", HOST)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["issuer"], "https://dove.example.com");
    assert_eq!(v["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(v["token_endpoint"], "https://dove.example.com/oauth/dove/token");
    assert_eq!(v["registration_endpoint"], "https://dove.example.com/oauth/dove/register");
}

#[tokio::test]
async fn approval_narrows_and_never_broadens() {
    let o = Oauth::new().await;
    // Invitation: read,draft on info and billing. The user keeps info read+draft, billing read only, and tries
    // to smuggle in send and an index that does not exist.
    let (_, tok) = o.connected("web-host", "read,draft", &["read.0", "read.1", "draft.0", "send.0", "read.7"]).await;
    let at = tok["access_token"].as_str().unwrap();
    assert!(at.starts_with("doveat_") && tok["refresh_token"].as_str().unwrap().starts_with("dovert_"));
    let accounts = o.h.ok(at, "list_accounts", json!({})).await;
    let got: Vec<(String, String)> = accounts["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["account"].as_str().unwrap().to_string(),
                a["actions"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect::<Vec<_>>().join(","),
            )
        })
        .collect();
    // Aliases sort: billing (index 0), info (index 1).
    assert_eq!(got, vec![("billing".into(), "read,draft".into()), ("info".into(), "read".into())]);
    let tools = o.h.rpc(at, "tools/list", json!({})).await;
    assert_eq!(tools["result"]["tools"][0]["securitySchemes"], json!([{ "type": "oauth2", "scopes": ["mail"] }]));
    // The other project's mailbox is invisible.
    assert_eq!(o.h.err(at, "list_labels", json!({"account": "secret"})).await, "not_found");
    assert_eq!(o.h.err(at, "create_draft", json!({"account": "info", "request_key": uuid::Uuid::new_v4().to_string(), "to": ["a@b.test"], "subject": "x", "body_text": "y"})).await, "forbidden");
    // The connection is a visible, separately revocable OAuth connection.
    let show = o.h.admin(AdminRequest::ClientsShow { name: "web-host".into() }).await.unwrap();
    assert_eq!(show["kind"], "oauth");
    // A read-only invitation stays read-only even when the form is forged to add draft and send.
    let (_, tok) = o.connected("ro-host", "read", &["read.0", "draft.0", "send.0", "draft.1"]).await;
    let acc = o.h.ok(tok["access_token"].as_str().unwrap(), "list_accounts", json!({})).await;
    for a in acc["accounts"].as_array().unwrap() {
        assert_eq!(a["actions"], json!(["read"]), "{acc}");
    }
}

#[tokio::test]
async fn pkce_redirect_and_resource_checks() {
    let o = Oauth::new().await;
    let client_id = o.register(REDIRECT).await;
    let v = verifier();
    let chal = challenge(&v);
    // Unregistered redirect: error page, never a redirect.
    let mut p = Oauth::params(&client_id, &chal);
    p[2] = ("redirect_uri", "https://host.example/other");
    let r = o.authorize_get(&p).await;
    assert_eq!(r.status(), 400);
    assert!(r.headers().get("location").is_none());
    // Unknown client: error page.
    let r = o.authorize_get(&Oauth::params("dcr-unknown", &chal)).await;
    assert_eq!(r.status(), 400);
    // plain PKCE and missing PKCE are refused via redirect.
    for (k, val) in [("code_challenge_method", "plain"), ("code_challenge", "")] {
        let mut p = Oauth::params(&client_id, &chal);
        p.retain(|(x, _)| *x != k);
        p.push((k, val));
        let r = o.authorize_get(&p).await;
        assert_eq!(r.status(), 303);
        assert_eq!(query_of(r.headers()["location"].to_str().unwrap())["error"], "invalid_request");
    }
    // Wrong resource (audience) is refused.
    let mut p = Oauth::params(&client_id, &chal);
    p[6] = ("resource", "https://other.example/mcp");
    let r = o.authorize_get(&p).await;
    assert_eq!(query_of(r.headers()["location"].to_str().unwrap())["error"], "invalid_target");
    // Repeated parameters are refused.
    let mut p = Oauth::params(&client_id, &chal);
    p.push(("state", "again"));
    assert_eq!(o.authorize_get(&p).await.status(), 400);

    // Wrong verifier burns the code: the right verifier afterwards fails too.
    let inv = o.invite("pkce", &["info"], "read").await;
    let code = o.approve(&client_id, &chal, &inv, &["read.0"]).await;
    let (s, e) = o.exchange(&client_id, &code, &verifier()).await;
    assert_eq!((s, e["error"].as_str().unwrap()), (400, "invalid_grant"));
    let (s, _) = o.exchange(&client_id, &code, &v).await;
    assert_eq!(s, 400);

    // Redirect mismatch at the token endpoint.
    let inv = o.invite("redir", &["info"], "read").await;
    let code = o.approve(&client_id, &chal, &inv, &["read.0"]).await;
    let (s, e) = o
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://host.example/other"),
            ("client_id", &client_id),
            ("code_verifier", &v),
        ])
        .await;
    assert_eq!((s, e["error"].as_str().unwrap()), (400, "invalid_grant"));

    // Wrong resource at the token endpoint.
    let inv = o.invite("aud", &["info"], "read").await;
    let code = o.approve(&client_id, &chal, &inv, &["read.0"]).await;
    let (s, e) = o
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", &client_id),
            ("code_verifier", &v),
            ("resource", "https://other.example/mcp"),
        ])
        .await;
    assert_eq!((s, e["error"].as_str().unwrap()), (400, "invalid_target"));

    // A code issued to one client cannot be redeemed by another.
    let other = o.register(REDIRECT).await;
    let inv = o.invite("swap", &["info"], "read").await;
    let code = o.approve(&client_id, &chal, &inv, &["read.0"]).await;
    let (s, _) = o.exchange(&other, &code, &v).await;
    assert_eq!(s, 400);
}

#[tokio::test]
async fn access_token_audience_is_bound_to_mcp() {
    let o = Oauth::new().await;
    let (_, tok) = o.connected("aud-host", "read", &["read.0"]).await;
    let at = tok["access_token"].as_str().unwrap().to_string();
    assert_eq!(o.mcp_status(&at).await, 200);
    // The same token row bound to another resource is not accepted here.
    o.h.app()
        .store
        .call(|c| Ok(c.execute("UPDATE oauth_tokens SET resource = 'https://other.example/mcp'", [])?))
        .await
        .unwrap();
    assert_eq!(o.mcp_status(&at).await, 401);
}

#[tokio::test]
async fn code_reuse_revokes_issued_tokens() {
    let o = Oauth::new().await;
    let inv = o.invite("reuse", &["info"], "read").await;
    let client_id = o.register(REDIRECT).await;
    let v = verifier();
    let code = o.approve(&client_id, &challenge(&v), &inv, &["read.0"]).await;
    let (s, tok) = o.exchange(&client_id, &code, &v).await;
    assert_eq!(s, 200);
    let at = tok["access_token"].as_str().unwrap();
    assert_eq!(o.mcp_status(at).await, 200);
    let (s, e) = o.exchange(&client_id, &code, &v).await;
    assert_eq!((s, e["error"].as_str().unwrap()), (400, "invalid_grant"));
    assert_eq!(o.mcp_status(at).await, 401);
    let (s, _) = o.refresh(&client_id, tok["refresh_token"].as_str().unwrap()).await;
    assert_eq!(s, 400);
}

#[tokio::test]
async fn refresh_rotation_and_reuse_detection() {
    let o = Oauth::new().await;
    let (client_id, t1) = o.connected("rot", "read", &["read.0"]).await;
    let (s, t2) = o.refresh(&client_id, t1["refresh_token"].as_str().unwrap()).await;
    assert_eq!(s, 200, "{t2}");
    assert_ne!(t1["refresh_token"], t2["refresh_token"]);
    // Rotation retires the old access token; the new one works and keeps the same (narrow) rights.
    assert_eq!(o.mcp_status(t1["access_token"].as_str().unwrap()).await, 401);
    let at2 = t2["access_token"].as_str().unwrap();
    let acc = o.h.ok(at2, "list_accounts", json!({})).await;
    assert_eq!(acc["accounts"].as_array().unwrap().len(), 1);
    // Another client cannot use the refresh token.
    let other = o.register(REDIRECT).await;
    assert_eq!(o.refresh(&other, t2["refresh_token"].as_str().unwrap()).await.0, 400);
    // Replaying the first refresh token revokes the whole family and the connection.
    let (s, e) = o.refresh(&client_id, t1["refresh_token"].as_str().unwrap()).await;
    assert_eq!((s, e["error"].as_str().unwrap()), (400, "invalid_grant"));
    assert_eq!(o.mcp_status(at2).await, 401);
    assert_eq!(o.refresh(&client_id, t2["refresh_token"].as_str().unwrap()).await.0, 400);
    let show = o.h.admin(AdminRequest::ClientsShow { name: "rot".into() }).await.unwrap();
    assert!(show["revoked_at"].is_string());
}

async fn epoch(o: &Oauth, name: &'static str) -> i64 {
    o.h.app()
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT auth_epoch FROM clients WHERE name = ?1", [name], |r| r.get::<_, i64>(0))?)
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn revocation_kills_access_and_refresh() {
    let o = Oauth::new().await;
    // Operator revocation of the connection.
    let (client_id, tok) = o.connected("rev-admin", "read", &["read.0"]).await;
    let before = epoch(&o, "rev-admin").await;
    o.h.admin(AdminRequest::ClientsRevoke { name: "rev-admin".into() }).await.unwrap();
    assert!(epoch(&o, "rev-admin").await > before, "revocation must invalidate cursors");
    assert_eq!(o.mcp_status(tok["access_token"].as_str().unwrap()).await, 401);
    assert_eq!(o.refresh(&client_id, tok["refresh_token"].as_str().unwrap()).await.0, 400);

    // RFC 7009 revocation by the host with its refresh token.
    let (client_id, tok) = o.connected("rev-host", "read", &["read.0"]).await;
    let revoke = |form: Vec<(&'static str, String)>| {
        o.web.post(o.url("/oauth/dove/revoke")).header("host", HOST).form(&form).send()
    };
    // Without client authentication nothing happens.
    let r = revoke(vec![("token", tok["refresh_token"].as_str().unwrap().to_string())]).await.unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(o.mcp_status(tok["access_token"].as_str().unwrap()).await, 200);
    let r =
        revoke(vec![("token", tok["refresh_token"].as_str().unwrap().to_string()), ("client_id", client_id.clone())])
            .await
            .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(o.mcp_status(tok["access_token"].as_str().unwrap()).await, 401);
    assert_eq!(o.refresh(&client_id, tok["refresh_token"].as_str().unwrap()).await.0, 400);
    // Unknown tokens get 200 (no oracle).
    let r = revoke(vec![("token", "dovert_unknown".into()), ("client_id", client_id.clone())]).await.unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn approval_page_csrf_and_invitation_rules() {
    let o = Oauth::with(|c| c.oauth.redeem_per_minute = 1000).await;
    let client_id = o.register(REDIRECT).await;
    let chal = challenge(&verifier());
    let r = o.authorize_get(&Oauth::params(&client_id, &chal)).await;
    let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let html = r.text().await.unwrap();
    let (rid, csrf) = (field(&html, "rid"), field(&html, "csrf"));
    let inv = o.invite("csrf-host", &["info"], "read").await;
    let base = |csrf: &str| -> Vec<(String, String)> {
        vec![
            ("rid".into(), rid.clone()),
            ("csrf".into(), csrf.into()),
            ("step".into(), "invitation".into()),
            ("action".into(), "continue".into()),
            ("invitation".into(), inv.clone()),
        ]
    };
    // Wrong CSRF token, missing cookie, foreign Origin: all refused.
    let r =
        o.post_form(&cookie, &base("wrong").iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>()).await;
    assert_eq!(r.status(), 403);
    let r = o.web.post(o.url("/oauth/dove/authorize")).header("host", HOST).form(&base(&csrf)).send().await.unwrap();
    assert_eq!(r.status(), 403);
    let r = o
        .web
        .post(o.url("/oauth/dove/authorize"))
        .header("host", HOST)
        .header("cookie", &cookie)
        .header("origin", "https://evil.example")
        .form(&base(&csrf))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // An invalid invitation shows an error and lets the user retry; a wrong CSRF did not consume the request.
    let (cookie2, _, _, html) =
        o.enter_invitation(&client_id, &chal, "dovei_notavalidinvitationatallxxxxxxxxxxxxxxxxx").await;
    assert!(html.contains("invalid, expired or already used"), "{html}");
    drop(cookie2);

    // Expired invitation.
    o.h.app()
        .store
        .call(|c| Ok(c.execute("UPDATE invitations SET expires_at = 1 WHERE connection_name = 'csrf-host'", [])?))
        .await
        .unwrap();
    let (_, _, _, html) = o.enter_invitation(&client_id, &chal, &inv).await;
    assert!(html.contains("invalid, expired or already used"));

    // An invitation already redeemed by `dove login` cannot be approved again.
    let inv = o.invite("used-host", &["info"], "read").await;
    let r = o
        .web
        .post(o.url("/connect/redeem"))
        .header("host", HOST)
        .json(&json!({"invitation": inv}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let (_, _, _, html) = o.enter_invitation(&client_id, &chal, &inv).await;
    assert!(html.contains("invalid, expired or already used"));

    // Deny redirects with access_denied.
    let inv = o.invite("deny-host", &["info"], "read").await;
    let (cookie, rid, csrf, _) = o.enter_invitation(&client_id, &chal, &inv).await;
    let r = o.post_form(&cookie, &[("rid", &rid), ("csrf", &csrf), ("step", "approve"), ("action", "cancel")]).await;
    assert_eq!(query_of(r.headers()["location"].to_str().unwrap())["error"], "access_denied");
    // Denying does not consume the invitation.
    let r = o
        .web
        .post(o.url("/connect/redeem"))
        .header("host", HOST)
        .json(&json!({"invitation": inv}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn dynamic_registration_has_no_authority_and_is_bounded() {
    let o = Oauth::with(|c| {
        c.oauth.max_dynamic_clients = 2;
        c.oauth.registrations_per_hour = 5;
    })
    .await;
    let post = |body: Value| o.web.post(o.url("/oauth/dove/register")).header("host", HOST).json(&body).send();
    let r = post(json!({"redirect_uris": ["http://evil.example/cb"]})).await.unwrap();
    assert_eq!(r.status(), 400);
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "invalid_redirect_uri");
    let id = o.register("http://127.0.0.1:4567/callback").await;
    // A registered client alone gets nothing: no client_credentials grant, no MCP access.
    let (s, e) = o.token(&[("grant_type", "client_credentials"), ("client_id", &id)]).await;
    assert_eq!((s, e["error"].as_str().unwrap()), (400, "unsupported_grant_type"));
    assert_eq!(o.mcp_status("doveat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").await, 401);
    // Confidential DCR is refused.
    let r =
        post(json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_basic"})).await.unwrap();
    assert_eq!(r.status(), 400);
    // Bounded: the second registration fills the cap; the next is refused, then the hourly rate limit applies.
    o.register(REDIRECT).await;
    let r = post(json!({"redirect_uris": [REDIRECT]})).await.unwrap();
    assert_eq!(r.status(), 503);
    let r = post(json!({"redirect_uris": [REDIRECT]})).await.unwrap();
    assert_eq!(r.status(), 429);
}

/// Registers from `ip` as the proxy would forward it. Returns (status, client_id when created).
async fn register_from(o: &Oauth, ip: &str) -> (u16, Option<String>) {
    let secret = o.h.app().proxy_secret.as_deref().unwrap().to_string();
    let r = o
        .web
        .post(o.url("/oauth/dove/register"))
        .header("host", HOST)
        .header("x-forwarded-for", ip)
        .header("x-dove-proxy-auth", secret)
        .json(&json!({ "redirect_uris": [REDIRECT] }))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let id = r.json::<Value>().await.unwrap()["client_id"].as_str().map(str::to_string);
    (status, id)
}

/// Moves a registration `secs` seconds into the past.
async fn age_registration(o: &Oauth, client_id: &str, secs: i64) {
    let id = client_id.to_string();
    o.h.app()
        .store
        .call(move |c| {
            c.execute(
                "UPDATE oauth_apps SET created_at = created_at - ?1 WHERE client_id = ?2",
                rusqlite::params![secs, id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
}

async fn registered(o: &Oauth, client_id: &str) -> bool {
    let id = client_id.to_string();
    o.h.app()
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM oauth_apps WHERE client_id = ?1)", [id], |r| r.get(0))?)
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn full_registration_table_evicts_old_unused_registrations() {
    let o = Oauth::with(|c| {
        c.oauth.max_dynamic_clients = 4;
        c.oauth.registrations_per_hour = 100;
    })
    .await;
    // One registration that led to a connection, then unused ones from three addresses.
    let (used, _) = o.connected("used-host", "read", &["read.0"]).await;
    let (_, a) = register_from(&o, "192.0.2.1").await;
    let (_, b) = register_from(&o, "192.0.2.2").await;
    let (_, c) = register_from(&o, "192.0.2.3").await;
    let (a, b, c) = (a.unwrap(), b.unwrap(), c.unwrap());
    // Full, and nothing is old enough to evict: refused.
    assert_eq!(register_from(&o, "192.0.2.4").await.0, 503);
    // Old enough: the oldest unused one goes. The used registration is older still and stays.
    age_registration(&o, &used, 5000).await;
    age_registration(&o, &a, 2000).await;
    age_registration(&o, &b, 1000).await;
    let (s, d) = register_from(&o, "192.0.2.4").await;
    assert_eq!(s, 201);
    assert!(!registered(&o, &a).await, "oldest unused registration evicted");
    assert!(registered(&o, &used).await && registered(&o, &b).await && registered(&o, &c).await);
    // A registration with an open sign-in request is not evicted, even when it is the oldest unused one.
    let r = o.authorize_get(&Oauth::params(&b, &challenge(&verifier()))).await;
    assert_eq!(r.status(), 200);
    age_registration(&o, &c, 1000).await;
    let (s, _) = register_from(&o, "192.0.2.5").await;
    assert_eq!(s, 201);
    assert!(registered(&o, &b).await, "in-flight registration kept");
    assert!(!registered(&o, &c).await);
    assert!(registered(&o, &d.unwrap()).await, "fresh registrations are never evicted");
}

#[tokio::test]
async fn approval_for_an_evicted_registration_keeps_the_invitation() {
    let o = Oauth::new().await;
    let inv = o.invite("evicted-host", &["info"], "read").await;
    let client_id = o.register(REDIRECT).await;
    let (cookie, rid, csrf, html) = o.enter_invitation(&client_id, &challenge(&verifier()), &inv).await;
    assert!(html.contains("Approve"));
    // The registration disappears between the two steps (eviction or the 24 h prune).
    let id = client_id.clone();
    o.h.app().store.call(move |c| Ok(c.execute("DELETE FROM oauth_apps WHERE client_id = ?1", [id])?)).await.unwrap();
    let read = field_name(&html, "read.");
    let r = o
        .post_form(
            &cookie,
            &[("rid", &rid), ("csrf", &csrf), ("step", "approve"), ("action", "approve"), (&read, "on")],
        )
        .await;
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("registration has expired"));
    // Nothing was consumed: the invitation still works for a fresh registration.
    let client_id = o.register(REDIRECT).await;
    let v = verifier();
    let code = o.approve(&client_id, &challenge(&v), &inv, &["read.0"]).await;
    assert_eq!(o.exchange(&client_id, &code, &v).await.0, 200);
}

#[tokio::test]
async fn approval_is_refused_when_the_invited_mailboxes_changed() {
    let o = Oauth::new().await;
    let inv = o.invite("changed-host", &["all"], "read").await;
    let client_id = o.register(REDIRECT).await;
    let (cookie, rid, csrf, html) = o.enter_invitation(&client_id, &challenge(&verifier()), &inv).await;
    // The page lists billing first, then info. The user keeps billing and deselects info.
    let billing = check_name(&html, "read.0");
    let info = check_name(&html, "read.1");
    assert!(html.find(">billing<").unwrap() < html.find(">info<").unwrap());
    assert!(!billing.ends_with(".0") && billing != info, "fields carry account ids: {billing}");
    // Meanwhile billing leaves the project without cancelling the invitation (only this guard can fire here:
    // the admin paths cancel the invitation as well).
    o.h.app()
        .store
        .call(|c| {
            Ok(c.execute(
                "DELETE FROM project_accounts WHERE account_id = (SELECT id FROM accounts WHERE alias = 'billing')",
                [],
            )?)
        })
        .await
        .unwrap();
    let r = o
        .post_form(
            &cookie,
            &[("rid", &rid), ("csrf", &csrf), ("step", "approve"), ("action", "approve"), (&billing, "on")],
        )
        .await;
    assert_eq!(r.status(), 409);
    let connections: i64 =
        o.h.app()
            .store
            .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM clients WHERE name = 'changed-host'", [], |r| r.get(0))?))
            .await
            .unwrap();
    assert_eq!(connections, 0, "the deselected mailbox was not granted");
}

#[tokio::test]
async fn removing_an_account_cancels_open_invitations_that_list_it() {
    let o = Oauth::new().await;
    let with_info = o.invite("has-info", &["info"], "read").await;
    let without =
        o.h.admin(AdminRequest::ClientsInvite {
            name: "no-info".into(),
            project: "other".into(),
            accounts: vec!["secret".into()],
            capabilities: "read".into(),
            expires: None,
            allow_ip: vec![],
        })
        .await
        .unwrap()["invitation"]
            .as_str()
            .unwrap()
            .to_string();
    let v = o.h.admin(AdminRequest::AccountsRemove { alias: "info".into() }).await.unwrap();
    assert_eq!(v["pending_invitations_cancelled"], 1);
    let redeem = |inv: String| {
        o.web.post(o.url("/connect/redeem")).header("host", HOST).json(&json!({ "invitation": inv })).send()
    };
    assert_eq!(redeem(with_info).await.unwrap().status(), 400);
    assert_eq!(redeem(without).await.unwrap().status(), 200);
}

#[tokio::test]
async fn unused_registrations_are_capped_per_address() {
    let o = Oauth::with(|c| c.oauth.registrations_per_hour = 100).await;
    let mut ids = vec![];
    for _ in 0..5 {
        let (s, id) = register_from(&o, "2001:db8:1:2::1").await;
        assert_eq!(s, 201);
        ids.push(id.unwrap());
    }
    // A sixth from the same /64 is refused while the others are fresh; other addresses are not affected.
    let (s, _) = register_from(&o, "2001:db8:1:2::99").await;
    assert_eq!(s, 429);
    assert_eq!(register_from(&o, "2001:db8:1:3::1").await.0, 201);
    // Once its oldest unused registration is old enough, it makes room.
    age_registration(&o, &ids[0], 1000).await;
    assert_eq!(register_from(&o, "2001:db8:1:2::1").await.0, 201);
    assert!(!registered(&o, &ids[0]).await);
    assert!(registered(&o, &ids[1]).await);
}

/// Token request as forwarded by the proxy for client address `ip`.
async fn token_from(o: &Oauth, ip: &str, form: &[(&str, &str)]) -> (u16, Value) {
    let secret = o.h.app().proxy_secret.as_deref().unwrap().to_string();
    let r = o
        .web
        .post(o.url("/oauth/dove/token"))
        .header("host", HOST)
        .header("x-forwarded-for", ip)
        .header("x-dove-proxy-auth", secret)
        .form(form)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

#[tokio::test]
async fn token_endpoint_enforces_the_connection_ip_allowlist() {
    let o = Oauth::new().await;
    let inv =
        o.h.admin(AdminRequest::ClientsInvite {
            name: "office-host".into(),
            project: "acme".into(),
            accounts: vec!["info".into()],
            capabilities: "read".into(),
            expires: None,
            allow_ip: vec!["192.0.2.0/24".into()],
        })
        .await
        .unwrap()["invitation"]
            .as_str()
            .unwrap()
            .to_string();
    let client_id = o.register(REDIRECT).await;
    let v = verifier();
    let code = o.approve(&client_id, &challenge(&v), &inv, &["read.0"]).await;
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("client_id", client_id.as_str()),
        ("code_verifier", v.as_str()),
    ];
    // From outside the allowlist: refused, and the code is not used up.
    let (s, e) = token_from(&o, "198.51.100.1", &exchange).await;
    assert_eq!((s, e["error"].as_str().unwrap()), (400, "invalid_grant"));
    let (s, tok) = token_from(&o, "192.0.2.10", &exchange).await;
    assert_eq!(s, 200, "{tok}");
    let rt = tok["refresh_token"].as_str().unwrap().to_string();
    let refresh = [("grant_type", "refresh_token"), ("refresh_token", rt.as_str()), ("client_id", client_id.as_str())];
    // A stolen refresh token used elsewhere neither rotates nor revokes anything.
    let (s, e) = token_from(&o, "198.51.100.1", &refresh).await;
    assert_eq!((s, e["error"].as_str().unwrap()), (400, "invalid_grant"));
    let (s, tok2) = token_from(&o, "192.0.2.10", &refresh).await;
    assert_eq!(s, 200, "the refresh token was not consumed: {tok2}");
    // Replaying the rotated token from outside does not trigger reuse revocation either.
    let (s, _) = token_from(&o, "198.51.100.1", &refresh).await;
    assert_eq!(s, 400);
    let at = tok2["access_token"].as_str().unwrap();
    let secret = o.h.app().proxy_secret.as_deref().unwrap().to_string();
    let r =
        o.h.post_mcp(
            Some(at),
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            &[("x-forwarded-for", "192.0.2.10"), ("x-dove-proxy-auth", &secret)],
        )
        .await;
    assert_eq!(r.status(), 200, "the connection is still alive");
}

#[tokio::test]
async fn authorize_requests_are_bounded_per_ip() {
    let o = Oauth::with(|c| c.oauth.token_requests_per_minute = 1000).await;
    let client_id = o.register(REDIRECT).await;
    let chal = challenge(&verifier());
    let mut statuses = vec![];
    for _ in 0..22 {
        statuses.push(o.authorize_get(&Oauth::params(&client_id, &chal)).await.status().as_u16());
    }
    assert_eq!(&statuses[..20], &[200; 20]);
    assert_eq!(&statuses[20..], &[429, 429], "open requests per IP are capped");
    let o = Oauth::with(|c| c.oauth.token_requests_per_minute = 3).await;
    let client_id = o.register(REDIRECT).await;
    let mut statuses = vec![];
    for _ in 0..4 {
        statuses.push(o.authorize_get(&Oauth::params(&client_id, &chal)).await.status().as_u16());
    }
    assert_eq!(statuses, [200, 200, 200, 429], "authorize is rate-limited per IP");
}

#[tokio::test]
async fn preregistered_confidential_client() {
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("oauth_secret");
    std::fs::write(&secret_file, "s3cret-value-for-test").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o400)).unwrap();
    let sf = secret_file.clone();
    let o = Oauth::with(move |c| {
        c.oauth.clients.push(dove::config::PreregisteredClient {
            client_id: "claude-web".into(),
            client_name: "Claude".into(),
            redirect_uris: vec![REDIRECT.into()],
            secret_file: Some(sf),
        })
    })
    .await;
    let inv = o.invite("pre", &["info"], "read").await;
    let v = verifier();
    let code = o.approve("claude-web", &challenge(&v), &inv, &["read.0"]).await;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", v.as_str()),
    ];
    // Public-style request without the secret: invalid_client, and the code stays usable.
    let mut f = form.to_vec();
    f.push(("client_id", "claude-web"));
    let (s, e) = o.token(&f).await;
    assert_eq!((s, e["error"].as_str().unwrap()), (401, "invalid_client"));
    let r = o
        .web
        .post(o.url("/oauth/dove/token"))
        .header("host", HOST)
        .basic_auth("claude-web", Some("wrong"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = o
        .web
        .post(o.url("/oauth/dove/token"))
        .header("host", HOST)
        .basic_auth("claude-web", Some("s3cret-value-for-test"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let tok: Value = r.json().await.unwrap();
    assert_eq!(o.mcp_status(tok["access_token"].as_str().unwrap()).await, 200);
}

#[tokio::test]
async fn every_oauth_state_change_is_audited() {
    let o = Oauth::new().await;
    let before = o.h.audit_count().await;
    let (client_id, tok) = o.connected("audited", "read", &["read.0"]).await;
    // invite (admin) + register + approve + token.
    assert_eq!(o.h.audit_count().await - before, 4);
    o.refresh(&client_id, tok["refresh_token"].as_str().unwrap()).await;
    assert_eq!(o.h.audit_count().await - before, 5);
    let actions: Vec<String> =
        o.h.app()
            .store
            .call(|c| {
                let mut s = c.prepare("SELECT tool_or_action || ':' || result_code FROM audit ORDER BY seq")?;
                Ok(s.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap();
    let tail: Vec<&str> = actions.iter().rev().take(5).rev().map(String::as_str).collect();
    assert_eq!(
        tail,
        ["clients.invite:ok", "oauth.register:ok", "oauth.approve:ok", "oauth.token:ok", "oauth.refresh:ok"]
    );
}

/// The `<input>` tag of the first field named `<kind>.<...>` on the approval page, for the mailbox with `id`.
fn input_tag(html: &str, kind: &str, id: &str) -> Option<String> {
    let pat = format!("name=\"{kind}.{id}\"");
    let at = html.find(&pat)?;
    let start = html[..at].rfind('<')?;
    Some(html[start..at + html[at..].find('>')?].to_string())
}

/// Actions per alias as list_accounts reports them.
async fn actions_of(h: &Harness, token: &str) -> Vec<(String, String)> {
    let v = h.ok(token, "list_accounts", json!({})).await;
    v["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let acts: Vec<&str> = a["actions"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
            (a["account"].as_str().unwrap().to_string(), acts.join(","))
        })
        .collect()
}

#[tokio::test]
async fn approval_page_presets_and_defaults() {
    let mut o = Oauth::with(|c| c.allow_send = true).await;
    let inv = o.invite("org-host", &["all"], "full,send").await;
    let client_id = o.register(REDIRECT).await;
    let v = verifier();
    let (cookie, rid, csrf, html) = o.enter_invitation(&client_id, &challenge(&v), &inv).await;
    let ids: Vec<String> =
        html.split("name=\"read.").skip(1).filter_map(|s| s.split('"').next()).map(String::from).collect();
    let (billing, info) = (&ids[0], &ids[1]);
    // Defaults: organize on (with read and draft), delete and send off.
    for (kind, checked) in [("read", true), ("draft", true), ("organize", true), ("delete", false), ("send", false)] {
        let tag = input_tag(&html, kind, info).unwrap_or_else(|| panic!("no {kind} box: {html}"));
        assert_eq!(tag.contains(" checked"), checked, "{kind}: {tag}");
    }
    for p in ["reader", "drafter", "assistant", "full"] {
        assert!(html.contains(&format!("<option value=\"{p}\">{p}</option>")), "{p}");
    }
    // billing by preset (its checkboxes are ignored, send stays separate); info by checkboxes.
    let (pb, sb, db, ri, oi, di) = (
        format!("preset.{billing}"),
        format!("send.{billing}"),
        format!("delete.{billing}"),
        format!("read.{info}"),
        format!("organize.{info}"),
        format!("delete.{info}"),
    );
    let form: Vec<(&str, &str)> = vec![
        ("rid", &rid),
        ("csrf", &csrf),
        ("step", "approve"),
        ("action", "approve"),
        (&pb, "assistant"),
        (&sb, "on"),
        (&db, "on"),
        (&ri, "on"),
        (&oi, "on"),
        (&di, "on"),
    ];
    let r = o.post_form(&cookie, &form).await;
    assert_eq!(r.status(), 303);
    let code = query_of(r.headers()["location"].to_str().unwrap())["code"].clone();
    let (status, tok) = o.exchange(&client_id, &code, &v).await;
    assert_eq!(status, 200, "{tok}");
    let at = tok["access_token"].as_str().unwrap();
    assert_eq!(
        actions_of(&o.h, at).await,
        vec![("billing".into(), "read,draft,organize,send".into()), ("info".into(), "read,organize,delete".into())]
    );

    // With sending switched off later, the page hides send and a forged send box grants nothing.
    let inv = o.invite("org-host-2", &["info"], "assistant,send").await;
    o.h.restart_with(|c| c.allow_send = false).await;
    let client_id = o.register(REDIRECT).await;
    let v = verifier();
    let (cookie, rid, csrf, html) = o.enter_invitation(&client_id, &challenge(&v), &inv).await;
    let id = html.split("name=\"read.").nth(1).and_then(|s| s.split('"').next()).unwrap().to_string();
    assert!(input_tag(&html, "send", &id).is_none(), "{html}");
    assert!(input_tag(&html, "delete", &id).is_none(), "delete was not invited: {html}");
    // Presets beyond the invitation are not offered.
    assert!(!html.contains("<option value=\"full\">"), "{html}");
    let (pi, si) = (format!("preset.{id}"), format!("send.{id}"));
    let form: Vec<(&str, &str)> =
        vec![("rid", &rid), ("csrf", &csrf), ("step", "approve"), ("action", "approve"), (&pi, "full"), (&si, "on")];
    let r = o.post_form(&cookie, &form).await;
    assert_eq!(r.status(), 303);
    let code = query_of(r.headers()["location"].to_str().unwrap())["code"].clone();
    let (_, tok) = o.exchange(&client_id, &code, &v).await;
    // A forged preset beyond the invitation is narrowed to it.
    assert_eq!(
        actions_of(&o.h, tok["access_token"].as_str().unwrap()).await,
        vec![("info".into(), "read,draft,organize".into())]
    );
    // The forged send box is not stored either (list_accounts hides send anyway while sending is off).
    let stored: String = o
        .h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row(
                "SELECT cm.actions FROM client_mailboxes cm JOIN clients c ON c.id = cm.client_id \
                 WHERE c.name = 'org-host-2'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(stored, "read,draft,organize");
}
