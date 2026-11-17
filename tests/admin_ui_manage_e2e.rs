//! Admin web UI part 2 (design 2026-11-14 section 5.4): Connections, Mailboxes, Projects, Watches and sinks, the
//! settings additions, shown-once results, and the request notice to a sink (section 4.6). Passkeys are the software
//! authenticator; no browser is involved.

mod support;

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use dove::admin::{AdminRequest, Password};
use dove::admin_ui::soft_authenticator::SoftAuthenticator;
use dove::imap::TlsMode;
use dove::util;
use serde_json::{Value, json};
use support::admin_ui::*;
use support::harness::{Harness, g};

/// Signs a browser in with a new passkey `phone`.
async fn signed_in(h: &Harness) -> (Browser, SoftAuthenticator) {
    let mut a = SoftAuthenticator::es256(ORIGIN);
    let mut b = Browser::new(h);
    let r = enrol_with(h, &mut b, "phone", &mut a).await;
    assert_eq!(r.status, 200, "{}", r.text);
    (b, a)
}

/// Runs a step-up form post to the end; returns the final answer of `/admin/stepup`.
async fn confirm(b: &mut Browser, a: &mut SoftAuthenticator, path: &str, fields: &[(&str, &str)]) -> Resp {
    let (p, ch, _) = stepup_begin(b, path, fields).await;
    stepup_finish(b, &p, &a.assert(&ch)).await
}

/// The redirect a confirmed action leads to.
fn redirect(r: &Resp) -> String {
    assert_eq!(r.status, 200, "{}", r.text);
    r.json()["redirect"].as_str().unwrap().to_string()
}

/// The value of the shown-once secret on a reveal page.
fn secret_on(page: &str) -> String {
    let start = page.find("class=\"secret__value\"").expect("a secret on the page");
    let rest = &page[start..];
    let v = &rest[rest.find("value=\"").unwrap() + 7..];
    v[..v.find('"').unwrap()].replace("&amp;", "&")
}

async fn audit_text(h: &Harness) -> String {
    h.app()
        .store
        .call(|c| {
            let mut st = c.prepare("SELECT * FROM audit ORDER BY seq")?;
            let n = st.column_count();
            let rows = st.query_map([], |r| {
                Ok((0..n)
                    .map(|i| match r.get::<_, rusqlite::types::Value>(i) {
                        Ok(rusqlite::types::Value::Text(t)) => t,
                        Ok(rusqlite::types::Value::Blob(b)) => String::from_utf8_lossy(&b).into_owned(),
                        Ok(v) => format!("{v:?}"),
                        Err(e) => e.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("|"))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
        })
        .await
        .unwrap()
}

/// Whether an agent token is accepted on `/mcp`.
async fn token_works(h: &Harness, token: &str) -> bool {
    let r =
        h.post_mcp(Some(token), json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }), &[]).await;
    r.status() == 200
}

/// Enrols a passkey from an enrolment link's token, as the device that opened the link.
async fn enrol_token(b: &mut Browser, token: &str, a: &mut SoftAuthenticator) -> Resp {
    let o = b.post_json("/admin/enroll/options", json!({ "token": token })).await;
    assert_eq!(o.status, 200, "{}", o.text);
    let o = o.json();
    let reg = a.register(&b64d(&o["publicKey"]["challenge"]), &b64d(&o["publicKey"]["user"]["id"]));
    b.post_json("/admin/enroll/finish", json!({ "id": o["id"], "credential": reg.to_json() })).await
}

async fn acme(h: &Harness) {
    h.mailbox("info", "info@acme.test");
    h.mailbox("sales", "sales@acme.test");
    h.project("acme", &["info", "sales"]).await;
}

// ------------------------------------------------------------------ connections

#[tokio::test]
async fn a_new_token_is_shown_once_to_the_session_that_confirmed_it() {
    let h = start().await;
    acme(&h).await;
    let (mut b, mut a) = signed_in(&h).await;
    let form = b.get("/admin/connections/new?kind=token").await;
    assert_eq!(form.status, 200);
    assert!(form.text.contains("name=\"account\" value=\"info\"") && form.text.contains("data-stepup"));

    // Validation errors come back before any confirmation is asked for.
    let r = b.post_form("/admin/connections/new", &[("kind", "token"), ("name", "bot"), ("project", "acme")]).await;
    assert!(r.json()["error"].as_str().unwrap().contains("mailbox"), "{}", r.text);

    let fields = [
        ("kind", "token"),
        ("name", "bot"),
        ("project", "acme"),
        ("account", "info"),
        ("action", "read"),
        ("action", "draft"),
        ("expires", "30d"),
    ];
    let to = redirect(&confirm(&mut b, &mut a, "/admin/connections/new", &fields).await);
    assert!(to.starts_with("/admin/reveal/"), "{to}");
    let v = h.admin(AdminRequest::ClientsShow { name: "bot".into() }).await.unwrap();
    assert_eq!(v["grants"], json!([{ "account": "info", "actions": "read,draft" }]));

    // Another signed-in browser cannot open (or use up) the result.
    let mut other = Browser::new(&h);
    let mut a2 = SoftAuthenticator::es256(ORIGIN);
    enrol_with(&h, &mut other, "laptop", &mut a2).await;
    let r = other.get(&to).await;
    assert_eq!(r.status, 200);
    assert!(r.text.contains("Nothing to show") && !r.text.contains("secret__value"));

    let page = b.get(&to).await;
    assert_eq!(page.header("cache-control"), "no-store");
    let token = secret_on(&page.text);
    assert!(token.len() > 20);
    h.ok(&token, "list_accounts", json!({})).await;
    // Once only.
    assert!(b.get(&to).await.text.contains("Nothing to show"));
    assert!(!audit_text(&h).await.contains(&token), "the token never reaches the audit log");
    assert!(audit_text(&h).await.lines().any(|l| l.contains("|web:phone|") && l.contains("clients.create")));
}

#[tokio::test]
async fn invitations_grants_redaction_rotation_and_revocation() {
    let h = start().await;
    acme(&h).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    let (mut b, mut a) = signed_in(&h).await;

    // Invitation: the code is shown once.
    let fields =
        [("kind", "invite"), ("name", "laptop"), ("project", "acme"), ("account", "sales"), ("action", "read")];
    let to = redirect(&confirm(&mut b, &mut a, "/admin/connections/new", &fields).await);
    let page = b.get(&to).await.text;
    assert!(page.contains("dove login --server") && page.contains("--profile laptop"), "{page}");
    assert!(!secret_on(&page).is_empty());

    // The detail page lists every mailbox of the project with the current actions ticked.
    let d = b.get("/admin/connections/agent").await;
    assert_eq!(d.status, 200);
    assert!(d.text.contains("name=\"a.info\" value=\"read\" checked"), "{}", d.text);
    assert!(d.text.contains("name=\"a.sales\" value=\"read\">"));

    // Widening grants needs the confirmation; it is bound to exactly those grants.
    let r = b.post_form("/admin/connections/agent/grants", &[("a.info", "read"), ("a.sales", "read")]).await;
    assert!(r.json()["stepup"].is_object(), "no write without a passkey: {}", r.text);
    let before = h.admin(AdminRequest::ClientsShow { name: "agent".into() }).await.unwrap();
    assert_eq!(before["grants"].as_array().unwrap().len(), 1);
    let fields = [("a.info", "read"), ("a.info", "draft"), ("a.sales", "read")];
    assert_eq!(
        redirect(&confirm(&mut b, &mut a, "/admin/connections/agent/grants", &fields).await),
        "/admin/connections/agent?done=grants"
    );
    let after = h.admin(AdminRequest::ClientsShow { name: "agent".into() }).await.unwrap();
    assert_eq!(
        after["grants"],
        json!([{ "account": "info", "actions": "read,draft" }, { "account": "sales", "actions": "read" }])
    );

    // Turning redaction on is a plain write; turning it off weakens a protection and needs the passkey (PLAN A83).
    let r = b.post_form("/admin/connections/agent/redaction", &[("enabled", "1")]).await;
    assert_eq!(r.status, 303, "{}", r.text);
    assert_eq!(h.admin(AdminRequest::ClientsShow { name: "agent".into() }).await.unwrap()["redact_secrets"], true);
    let page = b.get("/admin/connections/agent").await.text;
    assert!(page.contains("action=\"/admin/connections/agent/redaction\" data-stepup"), "{page}");
    let to = redirect(&confirm(&mut b, &mut a, "/admin/connections/agent/redaction", &[("enabled", "0")]).await);
    assert_eq!(to, "/admin/connections/agent?done=saved");
    assert_eq!(h.admin(AdminRequest::ClientsShow { name: "agent".into() }).await.unwrap()["redact_secrets"], false);

    // Rotation shows a new token; the old one stops working.
    let to = redirect(&confirm(&mut b, &mut a, "/admin/connections/agent/rotate", &[]).await);
    let new = secret_on(&b.get(&to).await.text);
    assert_ne!(new, token);
    h.ok(&new, "list_accounts", json!({})).await;
    assert!(!token_works(&h, &token).await);

    // Revocation.
    let r = b.post_form("/admin/connections/agent/revoke", &[]).await;
    assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/connections/agent?done=client_revoked"));
    assert!(!token_works(&h, &new).await);
    let list = b.get("/admin/connections").await.text;
    assert!(list.contains("Revoked and expired"));
}

// ------------------------------------------------------------------ mailboxes

#[tokio::test]
async fn imap_mailboxes_connect_and_are_managed_without_the_password_showing_up() {
    let h = start().await;
    h.project("acme", &[]).await;
    let password = format!("pw-{}", util::new_id());
    let email = "box@imap.test";
    h.imap.add_user(email, &password);
    for (name, special) in [("Drafts", "\\Drafts"), ("Sent", "\\Sent")] {
        h.imap.add_folder(email, name, Some(special));
    }
    let (imap, smtp) = h.imap_endpoints();
    let tls = |t: &TlsMode| if matches!(t, TlsMode::StartTls) { "starttls" } else { "implicit" };
    let (ip, sp) = (imap.port.to_string(), smtp.port.to_string());
    let (mut b, mut a) = signed_in(&h).await;
    let fields = [
        ("provider", "imap"),
        ("alias", "box"),
        ("email", email),
        ("password", password.as_str()),
        ("preset", "custom"),
        ("imap_host", imap.host.as_str()),
        ("imap_port", ip.as_str()),
        ("imap_tls", tls(&imap.tls)),
        ("smtp_host", smtp.host.as_str()),
        ("smtp_port", sp.as_str()),
        ("smtp_tls", tls(&smtp.tls)),
    ];
    let to = redirect(&confirm(&mut b, &mut a, "/admin/mailboxes/new", &fields).await);
    assert_eq!(to, "/admin/mailboxes/box?done=connected");
    let page = b.get(&to).await.text;
    assert!(page.contains("Mailbox connected.") && page.contains("Send-as addresses"), "{page}");

    // Send-as address and signature change outgoing mail: both need the passkey (PLAN A83). Then check, indexing,
    // disable and enable.
    let alias = [("do", "add"), ("address", "hello@imap.test")];
    let to = redirect(&confirm(&mut b, &mut a, "/admin/mailboxes/box/aliases", &alias).await);
    assert_eq!(to, "/admin/mailboxes/box?done=added");
    let sig = [("for", ""), ("signature", "Best,\r\nBox")];
    let to = redirect(&confirm(&mut b, &mut a, "/admin/mailboxes/box/signature", &sig).await);
    assert_eq!(to, "/admin/mailboxes/box?done=saved");
    let sig = h.admin(AdminRequest::AccountsSignatureShow { account: "box".into(), alias: None }).await.unwrap();
    assert_eq!(sig["signature"], "Best,\nBox");
    let page = b.get("/admin/mailboxes/box").await.text;
    assert!(page.contains("hello@imap.test") && page.contains("Signature for hello@imap.test"));
    let r = b.post_form("/admin/mailboxes/box/state", &[("do", "check")]).await;
    assert!(r.text.contains("The connection works."), "{}", r.text);
    assert_eq!(b.post_form("/admin/mailboxes/box/index", &[("do", "enable")]).await.status, 303);
    let ix = h.admin(AdminRequest::IndexStatus { alias: Some("box".into()) }).await.unwrap();
    assert_eq!(ix["accounts"][0]["enabled"], true);
    assert_eq!(b.post_form("/admin/mailboxes/box/state", &[("do", "disable")]).await.status, 303);
    assert!(b.get("/admin/mailboxes").await.text.contains("Disabled"));
    assert_eq!(b.post_form("/admin/mailboxes/box/state", &[("do", "enable")]).await.status, 303);

    // Reconnect with a new password, through the confirmation.
    let new_pw = format!("pw2-{}", util::new_id());
    h.imap.add_user(email, &new_pw);
    let to = redirect(&confirm(&mut b, &mut a, "/admin/mailboxes/box/reconnect", &[("password", &new_pw)]).await);
    assert_eq!(to, "/admin/mailboxes/box?done=reconnected");

    let audit = audit_text(&h).await;
    for pw in [&password, &new_pw] {
        assert!(!audit.contains(pw.as_str()), "a password reached the audit log");
        assert!(!b.get("/admin/mailboxes/box").await.text.contains(pw.as_str()));
    }
    assert!(audit.lines().any(|l| l.contains("|web:phone|") && l.contains("accounts.connect")));

    // Removal.
    let r = b.post_form("/admin/mailboxes/box/state", &[("do", "remove")]).await;
    assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/mailboxes?done=deleted"));
    assert!(h.admin(AdminRequest::AccountsList).await.unwrap().as_array().unwrap().is_empty());
}

#[tokio::test]
async fn connecting_gmail_shows_the_sign_in_link_once() {
    let h = start().await;
    let (mut b, mut a) = signed_in(&h).await;
    let fields = [("provider", "gmail"), ("alias", "work"), ("email", "me@gmail.test")];
    let r = b.post_form("/admin/mailboxes/new", &fields).await;
    assert!(r.json()["stepup"].is_object(), "connecting needs a passkey: {}", r.text);
    let r = confirm(&mut b, &mut a, "/admin/mailboxes/new", &fields).await;
    let to = redirect(&r);
    let page = b.get(&to).await.text;
    assert!(page.contains("Open Google sign-in") && page.contains("rel=\"noopener noreferrer\""), "{page}");
    assert!(b.get(&to).await.text.contains("Nothing to show"));
}

#[tokio::test]
async fn unknown_names_in_urls_are_an_error_page_not_a_crash() {
    let h = start().await;
    let (mut b, _a) = signed_in(&h).await;
    for path in ["/admin/mailboxes/nope", "/admin/connections/nope", "/admin/projects/nope"] {
        let r = b.get(path).await;
        assert_eq!(r.status, 409, "{path}: {}", r.text);
        assert!(r.text.contains("notice error"), "{path}");
    }
    // A name with characters that need encoding round-trips into the error text, escaped.
    let r = b.get("/admin/projects/%3Cb%3Ex").await;
    assert!(!r.text.contains("<b>x"), "{}", r.text);
}

// ------------------------------------------------------------------ projects

#[tokio::test]
async fn projects_are_created_and_their_mailboxes_changed() {
    let h = start().await;
    h.mailbox("info", "info@acme.test");
    let (mut b, _a) = signed_in(&h).await;
    assert!(b.get("/admin/projects").await.text.contains("No project yet"));
    let r = b.post_form("/admin/projects", &[("name", "acme")]).await;
    assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/projects/acme?done=created"));
    assert!(b.get("/admin/projects/acme").await.text.contains("<option value=\"info\">"));
    assert_eq!(b.post_form("/admin/projects/acme/accounts", &[("do", "add"), ("account", "info")]).await.status, 303);
    let v = h.admin(AdminRequest::ProjectsShow { name: "acme".into() }).await.unwrap();
    assert_eq!(v["accounts"][0]["alias"], "info");
    assert!(b.get("/admin/projects").await.text.contains("1 mailbox"));
    assert_eq!(
        b.post_form("/admin/projects/acme/accounts", &[("do", "remove"), ("account", "info")]).await.status,
        303
    );
    let v = h.admin(AdminRequest::ProjectsShow { name: "acme".into() }).await.unwrap();
    assert!(v["accounts"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn sending_rules_are_saved_with_a_passkey() {
    let h = start().await;
    h.mailbox("info", "info@acme.test");
    let (mut b, mut a) = signed_in(&h).await;
    let page = b.get("/admin/mailboxes/info").await;
    assert!(page.text.contains("Sending rules") && page.text.contains("value=\"allow\" checked"), "{}", page.text);
    let fields = [("domains", "Kunde.de\r\npartner.test"), ("unknown_recipients", "refuse")];
    // A typo is reported before the passkey prompt.
    let r = b
        .post_form("/admin/mailboxes/info/send-policy", &[("domains", "not a domain"), ("unknown_recipients", "allow")])
        .await;
    assert!(r.json().get("stepup").is_none() && r.text.contains("not a domain name"), "{}", r.text);
    // Saving needs the confirmation; nothing changes without it.
    let r = b.post_form("/admin/mailboxes/info/send-policy", &fields).await;
    assert!(r.json()["stepup"].is_object(), "{}", r.text);
    let shown = h.admin(AdminRequest::AccountsSendPolicyShow { account: "info".into() }).await.unwrap();
    assert_eq!(shown["send_policy"]["unknown_recipients"], "allow");
    assert_eq!(
        redirect(&confirm(&mut b, &mut a, "/admin/mailboxes/info/send-policy", &fields).await),
        "/admin/mailboxes/info?done=saved"
    );
    let shown = h.admin(AdminRequest::AccountsSendPolicyShow { account: "info".into() }).await.unwrap();
    assert_eq!(
        shown["send_policy"],
        json!({ "allow_domains": ["kunde.de", "partner.test"], "unknown_recipients": "refuse" })
    );
    let page = b.get("/admin/mailboxes/info").await;
    assert!(
        page.text.contains("kunde.de\npartner.test</textarea>") && page.text.contains("value=\"refuse\" checked"),
        "{}",
        page.text
    );
}

// ------------------------------------------------------------------ watches and sinks

#[tokio::test]
async fn watches_are_listed_and_removed_and_sinks_added_with_a_confirmation() {
    let h = start().await;
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    h.project("other", &[]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    let w =
        h.ok(&token, "create_watch", json!({ "account": "info", "kind": "from", "from": "boss@example.org" })).await;
    let id = w["watch_id"].as_str().unwrap().to_string();
    let (mut b, mut a) = signed_in(&h).await;
    let page = b.get("/admin/watches").await.text;
    assert!(page.contains("Mail from a sender") && page.contains(&id), "{page}");
    assert!(!page.contains("boss@example.org"), "filters are not shown");

    // Sinks: add needs a confirmation; the secret and the URL path are never shown again.
    let secret = "s".repeat(40);
    let fields = [
        ("name", "hook"),
        ("project", "acme"),
        ("url", "https://hooks.example.org/dove/abc123"),
        ("secret", secret.as_str()),
    ];
    let r = b.post_form("/admin/watches/sinks", &fields).await;
    assert!(r.json()["stepup"].is_object(), "{}", r.text);
    assert_eq!(redirect(&confirm(&mut b, &mut a, "/admin/watches/sinks", &fields).await), "/admin/watches?done=added");
    let page = b.get("/admin/watches").await.text;
    assert!(page.contains("https://hooks.example.org") && !page.contains("abc123") && !page.contains(&secret));
    assert!(!audit_text(&h).await.contains(&secret));
    let r = b.post_form("/admin/watches/sinks/hook", &[("do", "project"), ("project", "other")]).await;
    assert_eq!(r.status, 303, "{}", r.text);
    assert_eq!(h.admin(AdminRequest::SinksList).await.unwrap()[0]["project"], "other");
    assert_eq!(b.post_form("/admin/watches/sinks/hook", &[("do", "remove")]).await.status, 303);
    assert!(h.admin(AdminRequest::SinksList).await.unwrap().as_array().unwrap().is_empty());

    // Removing the agent's watch.
    let r = b.post_form(&format!("/admin/watches/{id}/remove"), &[]).await;
    assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/watches?done=ended"));
    assert!(h.admin(AdminRequest::WatchesList).await.unwrap().as_array().unwrap().is_empty());
    assert!(h.admin(AdminRequest::WatchesRemove { id }).await.unwrap_err().contains("unknown watch"));
}

// ------------------------------------------------------------------ settings

#[tokio::test]
async fn settings_add_a_passkey_export_and_rewrap() {
    let h = start().await;
    h.mailbox("info", "info@acme.test");
    let (mut b, mut a) = signed_in(&h).await;
    let to = redirect(&confirm(&mut b, &mut a, "/admin/settings/passkeys/add", &[("name", "ipad")]).await);
    let link = secret_on(&b.get(&to).await.text);
    assert!(link.starts_with(&format!("{ORIGIN}/admin/enroll#")), "the page shows an enrolment link for this origin");
    // The link works on another device.
    let mut ipad = Browser::new(&h);
    let mut a2 = SoftAuthenticator::es256(ORIGIN);
    let token = link.split('#').nth(1).unwrap().to_string();
    let r = enrol_token(&mut ipad, &token, &mut a2).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(h.admin(AdminRequest::PasskeysList).await.unwrap().as_array().unwrap().len(), 2);

    let r = b.get("/admin/settings/export").await;
    assert_eq!(r.status, 200);
    assert!(r.header("content-disposition").starts_with("attachment"));
    let v: Value = serde_json::from_str(&r.text).unwrap();
    assert_eq!(v["accounts"][0]["alias"], "info");

    let r = b.post_form("/admin/settings/keys/rewrap", &[]).await;
    assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/settings?done=rewrapped"));
    let r = b.post_form("/admin/audit/prune", &[]).await;
    assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/audit?done=pruned"));
    assert!(b.get("/admin/more").await.text.contains("/admin/watches"));
}

// ------------------------------------------------------------------ request notices

type Hit = (axum::http::HeaderMap, Vec<u8>);

async fn receiver(status: Arc<AtomicU16>) -> (String, Arc<Mutex<Vec<Hit>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits: Arc<Mutex<Vec<Hit>>> = Arc::default();
    let h2 = hits.clone();
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let (hits, status) = (h2.clone(), status.clone());
        async move {
            let headers = req.headers().clone();
            let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap().to_vec();
            hits.lock().unwrap().push((headers, body));
            axum::http::StatusCode::from_u16(status.load(Ordering::SeqCst)).unwrap()
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base, hits)
}

#[tokio::test]
async fn a_new_request_notifies_the_configured_sink_with_ids_only() {
    let h = start_with(|c| c.requests.notify_sink = Some("owner".into())).await;
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read,draft")]).await;
    let status = Arc::new(AtomicU16::new(503));
    let (base, hits) = receiver(status.clone()).await;
    h.app().google.gateway().allow_plain_http_sinks_for_tests();
    let secret = "k".repeat(40);
    h.admin(AdminRequest::SinksAdd {
        name: "owner".into(),
        project: "acme".into(),
        url: format!("{base}/notify"),
        secret: Password(zeroize::Zeroizing::new(secret.clone())),
    })
    .await
    .unwrap();

    let subject = format!("Subject {}", util::new_id());
    let d = h
        .ok(
            &token,
            "create_draft",
            json!({"account":"info","request_key":uuid::Uuid::new_v4().to_string(),"to":["c@example.org"],
                   "subject":subject,"body_text":"secret body"}),
        )
        .await;
    let v = h
        .ok(
            &token,
            "request_send",
            json!({ "account": "info", "items": [{ "draft_id": d["draft_id"], "expected_revision": d["revision"],
                    "send_at": util::rfc3339(util::now_unix() + 3600) }] }),
        )
        .await;
    let id = v["request_id"].as_str().unwrap().to_string();

    // A 503 is retried later, not dropped.
    let now = util::now_unix();
    let r = dove::watch::sinks::deliver_request_notices(h.app(), now).await.unwrap();
    assert_eq!((r.attempted, r.retrying), (1, 1));
    assert_eq!(dove::watch::sinks::deliver_request_notices(h.app(), now).await.unwrap().attempted, 0, "not due yet");
    status.store(200, Ordering::SeqCst);
    let r = dove::watch::sinks::deliver_request_notices(h.app(), now + 3600).await.unwrap();
    assert_eq!(r.delivered, 1);
    assert_eq!(dove::watch::sinks::deliver_request_notices(h.app(), now + 7200).await.unwrap().attempted, 0);

    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 2);
    let (headers, body) = &hits[1];
    let v: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(
        v,
        json!({ "event": "request_pending", "kind": "send", "request_id": id,
                "url": format!("{ORIGIN}/admin/requests/{id}") })
    );
    assert_eq!(headers["dove-event-id"], format!("req_{id}").as_str());
    let sig = headers["dove-signature"].to_str().unwrap();
    let t: i64 = sig.split(',').next().unwrap().trim_start_matches("t=").parse().unwrap();
    assert_eq!(sig, dove::watch::sinks::signature_header(secret.as_bytes(), t, body));
    let text = String::from_utf8_lossy(body);
    assert!(!text.contains(&subject) && !text.contains("secret body") && !text.contains("c@example.org"));
}

#[tokio::test]
async fn without_notify_sink_nothing_is_queued() {
    let h = start().await;
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    h.ok(&token, "request_access", json!({ "grants": [{ "account": "info", "actions": "read,draft" }] })).await;
    let n: i64 = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT count(*) FROM request_notices", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(n, 0);
}
