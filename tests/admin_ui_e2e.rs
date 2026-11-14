//! Admin web UI (design 2026-11-14 section 5, PLAN A73): the `/admin` guard, passkey enrolment and sign-in,
//! sessions, CSRF and Origin, step-up confirmation, the pages and their escaping. Passkeys are a software
//! authenticator (`dove::admin_ui::soft_authenticator`); no browser is involved.

mod support;

use dove::admin::AdminRequest;
use dove::admin_ui::soft_authenticator::SoftAuthenticator;
use dove::admin_ui::{ADMIN_PATHS, ADMIN_PUBLIC_PATHS, COOKIE, CSP};
use dove::util;
use serde_json::{Value, json};
use support::admin_ui::*;
use support::harness::{HOST, Harness, g};

const MB: &str = "info@acme.test";

/// A Gmail mailbox `info` in project `acme` and a `read,draft` agent token.
async fn mailbox(h: &Harness) -> String {
    h.mailbox("info", MB);
    h.project("acme", &["info"]).await;
    h.token("acme", "agent", vec![g("info", "read,draft")]).await
}

/// A pending send request for one new draft; returns the request id.
async fn pending_request(h: &Harness, token: &str, subject: &str, body: &str, note: Option<&str>) -> String {
    let c = h
        .ok(
            token,
            "create_draft",
            json!({"account":"info","request_key":uuid::Uuid::new_v4().to_string(),"to":["c@example.org"],
                   "subject":subject,"body_text":body}),
        )
        .await;
    let mut args = json!({ "account": "info", "items": [{ "draft_id": c["draft_id"], "expected_revision": c["revision"],
                           "send_at": util::rfc3339(util::now_unix() + 3600) }] });
    if let Some(n) = note {
        args["note"] = json!(n);
    }
    let v = h.ok(token, "request_send", args).await;
    v["request_id"].as_str().unwrap().to_string()
}

async fn request_status(h: &Harness, id: &str) -> Value {
    let v = h.admin(AdminRequest::RequestsShow { id: id.into() }).await.unwrap();
    json!({ "status": v["status"], "decided_by": v["decided_by"], "revision": v["items"][0]["revision"] })
}

async fn count(h: &Harness, sql: &'static str) -> i64 {
    h.app().store.call(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?)).await.unwrap()
}

/// Every audit row as one line of text.
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

fn concrete(path: &str) -> String {
    path.replace("{id}", "r_x").replace("{name}", "phone")
}

// ------------------------------------------------------------------ guard

#[tokio::test]
async fn admin_is_404_unless_enabled_and_on_its_own_host() {
    let off = Harness::start().await;
    let mut b = Browser::new(&off);
    for p in ["/admin", "/admin/login", "/admin/static/admin.js"] {
        assert_eq!(b.get(p).await.status, 404, "{p} while disabled");
    }
    assert!(
        off.admin(AdminRequest::PasskeysAdd { name: "phone".into() }).await.unwrap_err().contains("admin UI is off")
    );

    let h = start().await;
    let mut b = Browser::new(&h);
    assert_eq!(b.get("/admin/login").await.status, 200);
    let r = b.get("/admin").await;
    assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/login"));
    // The public host, a port variant and a look-alike are not the admin host.
    for host in [HOST, "dove-admin.tail1234.ts.net:8443", "dove-admin.tail1234.ts.net.evil.example"] {
        let r = b.raw("GET", "/admin/login", &[("host", host)], "").await;
        assert_eq!(r.status, 404, "{host}");
    }
    // The admin host serves nothing else (the public routes keep their own Host rule).
    let r = b.raw("POST", "/mcp", &[], "{}").await;
    assert_eq!(r.status, 421);
}

#[tokio::test]
async fn admin_ui_cannot_be_enabled_in_local_mode() {
    let env = dove::testing::TestEnv::new();
    let mut cfg = env.app.cfg.clone();
    cfg.admin_ui.enabled = true;
    cfg.admin_ui.origin = Some(ORIGIN.into());
    assert!(cfg.validate().is_ok());
    cfg.mode = dove::config::Mode::Local;
    cfg.public_url = format!("http://{}", cfg.listen);
    assert!(cfg.validate().unwrap_err().to_string().contains("local mode"));
    cfg.mode = dove::config::Mode::Server;
    cfg.public_url = "https://dove.example.com".into();
    for bad in ["http://dove-admin.example", "https://dove-admin.example/", "https://192.0.2.1", "https://a.example/x"]
    {
        cfg.admin_ui.origin = Some(bad.into());
        assert!(cfg.validate().is_err(), "{bad}");
    }
    cfg.admin_ui.origin = None;
    assert!(cfg.validate().is_err(), "enabled without an origin");
}

#[tokio::test]
async fn authorization_header_is_refused_even_with_a_session() {
    let h = start().await;
    let token = mailbox(&h).await;
    let mut b = Browser::new(&h);
    enrol(&h, &mut b, "phone").await;
    assert_eq!(b.get("/admin").await.status, 200);
    b.extra = vec![("authorization".into(), format!("Bearer {token}"))];
    for p in ["/admin", "/admin/login", "/admin/requests"] {
        assert_eq!(b.get(p).await.status, 403, "{p}");
    }
    let r = b.post_json("/admin/login/options", json!({})).await;
    assert_eq!(r.status, 403);
    // An agent token alone opens nothing.
    let mut agent = Browser::new(&h);
    agent.extra = vec![("authorization".into(), format!("Bearer {token}"))];
    assert_eq!(agent.get("/admin/settings").await.status, 403);
    // The token still works where it belongs.
    assert!(h.tool_names(&token).await.contains(&"list_accounts".to_string()));
}

#[tokio::test]
async fn nothing_answers_without_a_session() {
    let h = start().await;
    let mut b = Browser::new(&h);
    let a = enrol(&h, &mut Browser::new(&h), "phone").await;
    drop(a);
    let garbage = util::b64url(&[7u8; 32]);
    for cookie in [None, Some(garbage.as_str()), Some("not-a-token")] {
        b.cookie = cookie.map(str::to_string);
        for p in ADMIN_PATHS.iter().filter(|p| !ADMIN_PUBLIC_PATHS.contains(p)) {
            let path = concrete(p);
            let r = b.get(&path).await;
            assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/login"), "GET {path}");
            assert!(!r.text.contains("dove-csrf"));
            let r = b.post_form(&path, &[("csrf", "x")]).await;
            assert_eq!(r.status, 401, "POST {path}");
        }
    }
    // An expired session is no session.
    let mut s = Browser::new(&h);
    let mut a = SoftAuthenticator::es256(ORIGIN);
    enrol_with(&h, &mut s, "laptop", &mut a).await;
    assert_eq!(s.get("/admin/settings").await.status, 200);
    h.app().store.call(|c| Ok(c.execute("UPDATE admin_sessions SET expires_at = 1", [])?)).await.unwrap();
    assert_eq!(s.get("/admin/settings").await.status, 303);
    // Public pages carry no session data.
    for p in
        ADMIN_PUBLIC_PATHS.iter().filter(|p| !p.contains("options") && !p.contains("finish") && !p.contains("static"))
    {
        let r = Browser::new(&h).get(p).await;
        assert_eq!(r.status, 200, "{p}");
        assert!(!r.text.contains("dove-csrf"), "{p}");
    }
}

#[tokio::test]
async fn writes_need_csrf_origin_and_same_site() {
    let h = start().await;
    let mut a = SoftAuthenticator::es256(ORIGIN);
    let mut first = Browser::new(&h);
    enrol_with(&h, &mut first, "phone", &mut a).await;
    let mut b = Browser::new(&h);
    login(&mut b, &mut a).await;
    let sessions = || count(&h, "SELECT COUNT(*) FROM admin_sessions");
    assert_eq!(sessions().await, 2);
    let first_id: String = h
        .app()
        .store
        .call(
            |c| Ok(c.query_row("SELECT id FROM admin_sessions ORDER BY created_at, rowid LIMIT 1", [], |r| r.get(0))?),
        )
        .await
        .unwrap();
    let path = "/admin/settings/sessions/revoke";
    let cookie = format!("{COOKIE}={}", b.cookie.clone().unwrap());
    let csrf = b.csrf.clone().unwrap();
    let form = format!("id={first_id}&csrf={csrf}");
    let ct = ("content-type", "application/x-www-form-urlencoded");
    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, String, u16);
    let cases: Vec<Case> = vec![
        ("no csrf", vec![("cookie", &cookie), ("origin", ORIGIN), ct], format!("id={first_id}"), 403),
        ("wrong csrf", vec![("cookie", &cookie), ("origin", ORIGIN), ct], format!("id={first_id}&csrf=x{csrf}"), 403),
        (
            "other session's csrf",
            vec![("cookie", &cookie), ("origin", ORIGIN), ct],
            format!("id={first_id}&csrf={}", first.csrf.clone().unwrap()),
            403,
        ),
        ("no origin", vec![("cookie", &cookie), ct], form.clone(), 403),
        ("foreign origin", vec![("cookie", &cookie), ("origin", "https://evil.example"), ct], form.clone(), 403),
        ("public origin", vec![("cookie", &cookie), ("origin", "https://dove.example.com"), ct], form.clone(), 403),
        (
            "cross-site",
            vec![("cookie", &cookie), ("origin", ORIGIN), ("sec-fetch-site", "cross-site"), ct],
            form.clone(),
            403,
        ),
    ];
    for (name, headers, body, want) in cases {
        let r = b.raw("POST", path, &headers, &body).await;
        assert_eq!(r.status, want, "{name}: {}", r.text);
        assert_eq!(sessions().await, 2, "{name} changed nothing");
    }
    // A page load from a foreign origin (a cross-origin fetch) is refused by the guard, before any page.
    let r = b.raw("GET", "/admin/settings", &[("cookie", &cookie), ("origin", "https://evil.example")], "").await;
    assert_eq!(r.status, 403);
    // A CSRF header works like the form field; then the write happens.
    let r = b
        .raw(
            "POST",
            path,
            &[("cookie", &cookie), ("origin", ORIGIN), ("x-dove-csrf", &csrf), ct],
            &format!("id={first_id}"),
        )
        .await;
    assert_eq!(r.status, 303, "{}", r.text);
    assert_eq!(sessions().await, 1);
    assert_eq!(first.get("/admin").await.status, 303, "the other browser is signed out");
    // GET never writes: other methods are refused.
    let r = b.raw("PUT", path, &[("cookie", &cookie), ("origin", ORIGIN), ("x-dove-csrf", &csrf)], "").await;
    assert_eq!(r.status, 405);
}

#[tokio::test]
async fn security_headers_on_every_answer() {
    let h = start().await;
    let mut b = Browser::new(&h);
    enrol(&h, &mut b, "phone").await;
    for p in ["/admin", "/admin/requests", "/admin/audit", "/admin/settings", "/admin/login", "/admin/nope"] {
        let r = b.get(p).await;
        assert_eq!(r.header("content-security-policy"), CSP, "{p}");
        assert_eq!(r.header("x-frame-options"), "DENY", "{p}");
        assert_eq!(r.header("referrer-policy"), "same-origin", "{p}");
        assert_eq!(r.header("cache-control"), "no-store", "{p}");
        assert!(!r.text.contains("<script>") && !r.text.contains("style="), "{p}: no inline script or style");
    }
    assert_eq!(
        CSP,
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; \
         frame-ancestors 'none'; base-uri 'none'"
    );
    let js = b.get("/admin/static/admin.js").await;
    assert!(js.header("content-type").starts_with("text/javascript"));
    assert_eq!(js.header("content-security-policy"), CSP);
    assert!(b.get("/admin/static/admin.css").await.header("content-type").starts_with("text/css"));
}

#[tokio::test]
async fn rate_and_login_failure_limits_per_address() {
    let h = start_with(|c| {
        c.admin_ui.login_failures_per_hour = 3;
        c.admin_ui.requests_per_minute = 40;
    })
    .await;
    let mut b = Browser::new(&h);
    let mut a = SoftAuthenticator::es256(ORIGIN);
    enrol_with(&h, &mut b, "phone", &mut a).await;
    let mut other = SoftAuthenticator::es256(ORIGIN);
    other.user_handle = vec![1; 16];
    // Three failed sign-ins (an unknown passkey) use up the address's budget.
    for _ in 0..3 {
        let (id, ch) = login_options(&mut Browser::new(&h)).await;
        assert_eq!(login_finish(&mut Browser::new(&h), &id, &other.assert(&ch)).await.status, 401);
    }
    // Further failures from that address answer 429, sign-in and enrolment alike.
    let (id, ch) = login_options(&mut Browser::new(&h)).await;
    assert_eq!(login_finish(&mut Browser::new(&h), &id, &other.assert(&ch)).await.status, 429);
    assert_eq!(Browser::new(&h).post_json("/admin/enroll/options", json!({"token": "x"})).await.status, 429);
    // A valid passkey is never refused by it: behind Tailscale Serve everyone shares 127.0.0.1, and a local process
    // must not lock the owner out. A valid enrolment link still works too.
    let mut c = Browser::new(&h);
    login(&mut c, &mut a).await;
    assert_eq!(c.get("/admin").await.status, 200);
    enrol(&h, &mut Browser::new(&h), "laptop").await;
    // The bucket is per address: a failure from another address (proxy-authenticated X-Forwarded-For) is a plain 401.
    let secret = h.app().proxy_secret.as_ref().unwrap().to_string();
    let mut d = Browser::new(&h);
    d.extra = vec![("x-forwarded-for".into(), "203.0.113.9".into()), ("x-dove-proxy-auth".into(), secret.clone())];
    let (id, ch) = login_options(&mut d).await;
    assert_eq!(login_finish(&mut d, &id, &other.assert(&ch)).await.status, 401);
    // The request budget: 40 per minute per address.
    let mut e = Browser::new(&h);
    e.extra = vec![("x-forwarded-for".into(), "203.0.113.10".into()), ("x-dove-proxy-auth".into(), secret)];
    let mut codes = vec![];
    for _ in 0..45 {
        codes.push(e.get("/admin/login").await.status);
    }
    assert!(codes[..40].iter().all(|c| *c == 200) && codes[40..].iter().all(|c| *c == 429), "{codes:?}");
}

// ------------------------------------------------------------------ enrolment and sign-in

#[tokio::test]
async fn enrolment_links_work_once_for_five_minutes() {
    // Many refused enrolments below; the failure budget is not what this test is about.
    let h = start_with(|c| c.admin_ui.login_failures_per_hour = 100).await;
    assert!(h.admin(AdminRequest::PasskeysAdd { name: "Phone!".into() }).await.unwrap_err().contains("invalid"));
    let v = h.admin(AdminRequest::PasskeysAdd { name: "phone".into() }).await.unwrap();
    let link = v["open_this_link"].as_str().unwrap();
    assert!(link.starts_with(&format!("{ORIGIN}/admin/enroll#")), "{link}");
    assert_eq!(v["expires_in_minutes"], 5);
    let token = link.split_once('#').unwrap().1.to_string();
    // Only a hash of the token is stored; the audit row names the passkey, not the token.
    let stored: Vec<u8> = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT token_hash FROM admin_enrolments", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(stored.len(), 32);
    assert!(!audit_text(&h).await.contains(&token));

    let mut b = Browser::new(&h);
    let mut a = SoftAuthenticator::es256(ORIGIN);
    let o = b.post_json("/admin/enroll/options", json!({ "token": token })).await.json();
    assert_eq!(o["publicKey"]["rp"]["id"], "dove-admin.tail1234.ts.net");
    assert_eq!(o["publicKey"]["authenticatorSelection"]["userVerification"], "required");
    assert_eq!(o["publicKey"]["attestation"], "none");
    let reg = a.register(&b64d(&o["publicKey"]["challenge"]), &b64d(&o["publicKey"]["user"]["id"]));
    let r = b.post_json("/admin/enroll/finish", json!({ "id": o["id"], "credential": reg.to_json() })).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(b.cookie.is_some(), "enrolment signs in");
    // The link is used up.
    let r = Browser::new(&h).post_json("/admin/enroll/options", json!({ "token": token })).await;
    assert_eq!(r.status, 404);
    // A second ceremony started from the same link before the first finished cannot consume it again.
    let token2 = enrol_link(&h, "tablet").await;
    let mut c = Browser::new(&h);
    let o1 = c.post_json("/admin/enroll/options", json!({ "token": token2 })).await.json();
    let o2 = c.post_json("/admin/enroll/options", json!({ "token": token2 })).await.json();
    let mut t1 = SoftAuthenticator::es256(ORIGIN);
    let mut t2 = SoftAuthenticator::es256(ORIGIN);
    let r1 = t1.register(&b64d(&o1["publicKey"]["challenge"]), &b64d(&o1["publicKey"]["user"]["id"]));
    let r2 = t2.register(&b64d(&o2["publicKey"]["challenge"]), &b64d(&o2["publicKey"]["user"]["id"]));
    assert_eq!(
        c.post_json("/admin/enroll/finish", json!({ "id": o1["id"], "credential": r1.to_json() })).await.status,
        200
    );
    assert_eq!(
        c.post_json("/admin/enroll/finish", json!({ "id": o2["id"], "credential": r2.to_json() })).await.status,
        400
    );
    // A link stays used even when the passkey it created is removed: a second ceremony from it cannot enrol.
    let race = enrol_link(&h, "race").await;
    let mut c2 = Browser::new(&h);
    let p1 = c2.post_json("/admin/enroll/options", json!({ "token": race })).await.json();
    let p2 = c2.post_json("/admin/enroll/options", json!({ "token": race })).await.json();
    let mut u1 = SoftAuthenticator::es256(ORIGIN);
    let mut u2 = SoftAuthenticator::es256(ORIGIN);
    let q1 = u1.register(&b64d(&p1["publicKey"]["challenge"]), &b64d(&p1["publicKey"]["user"]["id"]));
    let q2 = u2.register(&b64d(&p2["publicKey"]["challenge"]), &b64d(&p2["publicKey"]["user"]["id"]));
    assert_eq!(
        c2.post_json("/admin/enroll/finish", json!({ "id": p1["id"], "credential": q1.to_json() })).await.status,
        200
    );
    h.admin(AdminRequest::PasskeysRemove { name: "race".into() }).await.unwrap();
    let r = c2.post_json("/admin/enroll/finish", json!({ "id": p2["id"], "credential": q2.to_json() })).await;
    assert_eq!(r.status, 400, "a used link cannot enrol again after its passkey was removed: {}", r.text);
    // A link that expires between the options and the finish.
    let late = enrol_link(&h, "late").await;
    let mut c3 = Browser::new(&h);
    let p = c3.post_json("/admin/enroll/options", json!({ "token": late })).await.json();
    h.app()
        .store
        .call(|c| Ok(c.execute("UPDATE admin_enrolments SET expires_at = 1 WHERE used_at IS NULL", [])?))
        .await
        .unwrap();
    let mut u = SoftAuthenticator::es256(ORIGIN);
    let q = u.register(&b64d(&p["publicKey"]["challenge"]), &b64d(&p["publicKey"]["user"]["id"]));
    assert_eq!(
        c3.post_json("/admin/enroll/finish", json!({ "id": p["id"], "credential": q.to_json() })).await.status,
        400
    );
    // The id the page claims must be the credential id inside the attestation.
    let claim = enrol_link(&h, "claim").await;
    let mut c4 = Browser::new(&h);
    let p = c4.post_json("/admin/enroll/options", json!({ "token": claim })).await.json();
    let mut u = SoftAuthenticator::es256(ORIGIN);
    let mut q = u.register(&b64d(&p["publicKey"]["challenge"]), &b64d(&p["publicKey"]["user"]["id"])).to_json();
    q["id"] = json!(util::b64url(&[5u8; 16]));
    assert_eq!(c4.post_json("/admin/enroll/finish", json!({ "id": p["id"], "credential": q })).await.status, 400);
    // An expired link.
    let token3 = enrol_link(&h, "watch").await;
    h.app()
        .store
        .call(|c| Ok(c.execute("UPDATE admin_enrolments SET expires_at = 1 WHERE used_at IS NULL", [])?))
        .await
        .unwrap();
    assert_eq!(Browser::new(&h).post_json("/admin/enroll/options", json!({ "token": token3 })).await.status, 404);
    // The same authenticator credential cannot be enrolled twice; a name is unique.
    let mut d = Browser::new(&h);
    let token4 = enrol_link(&h, "spare").await;
    let o = d.post_json("/admin/enroll/options", json!({ "token": token4 })).await.json();
    let mut again = SoftAuthenticator::es256(ORIGIN);
    again.credential_id = a.credential_id.clone();
    let reg = again.register(&b64d(&o["publicKey"]["challenge"]), &b64d(&o["publicKey"]["user"]["id"]));
    let r = d.post_json("/admin/enroll/finish", json!({ "id": o["id"], "credential": reg.to_json() })).await;
    assert_eq!(r.status, 400, "{}", r.text);
    assert!(h.admin(AdminRequest::PasskeysAdd { name: "phone".into() }).await.unwrap_err().contains("exists"));
    // A registration without user verification, or for another origin, is refused.
    for (name, bend) in [("nouv", 0), ("origin", 1)] {
        let t = enrol_link(&h, name).await;
        let mut e = Browser::new(&h);
        let o = e.post_json("/admin/enroll/options", json!({ "token": t })).await.json();
        let mut x = SoftAuthenticator::es256(ORIGIN);
        if bend == 0 {
            x.user_verified = false;
        } else {
            x.origin = "https://dove.example.com".into();
        }
        let reg = x.register(&b64d(&o["publicKey"]["challenge"]), &b64d(&o["publicKey"]["user"]["id"]));
        assert_eq!(
            e.post_json("/admin/enroll/finish", json!({ "id": o["id"], "credential": reg.to_json() })).await.status,
            400
        );
    }
    let names: Vec<String> = h
        .admin(AdminRequest::PasskeysList)
        .await
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["phone", "tablet"]);
}

#[tokio::test]
async fn sign_in_checks_every_part_of_the_assertion() {
    let h = start_with(|c| c.admin_ui.login_failures_per_hour = 100).await;
    let mut a = SoftAuthenticator::es256(ORIGIN);
    enrol_with(&h, &mut Browser::new(&h), "phone", &mut a).await;
    let mut b = Browser::new(&h);
    let (id, ch) = login_options(&mut b).await;
    let ok = a.assert(&ch);
    let r = login_finish(&mut b, &id, &ok).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let set = r.header("set-cookie");
    for attr in ["__Host-dove_admin=", "Path=/", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=43200"] {
        assert!(set.contains(attr), "{attr} in {set}");
    }
    let token = b.cookie.clone().unwrap();
    // Only the token's hash is stored.
    let hashes: Vec<Vec<u8>> = h
        .app()
        .store
        .call(|c| {
            let mut st = c.prepare("SELECT token_hash FROM admin_sessions")?;
            Ok(st.query_map([], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?)
        })
        .await
        .unwrap();
    assert!(hashes.contains(&dove::admin_ui::store::token_hash(&token)));
    assert!(!audit_text(&h).await.contains(&token));
    // Replay of the same assertion with the same ceremony id.
    assert_eq!(login_finish(&mut Browser::new(&h), &id, &ok).await.status, 401);

    let refused = |label: &'static str, bend: Box<dyn FnOnce(&mut SoftAuthenticator)>| (label, bend);
    let cases = vec![
        refused("no user verification", Box::new(|x| x.user_verified = false)),
        refused("no user presence", Box::new(|x| x.user_present = false)),
        refused("wrong origin", Box::new(|x| x.origin = "https://dove.example.com".into())),
        refused("wrong RP ID", Box::new(|x| x.rp_id = "dove.example.com".into())),
        refused("registration type", Box::new(|x| x.type_override = Some("webauthn.create".into()))),
        refused(
            "counter going back",
            Box::new(|x| {
                x.sign_count = 0;
                x.counter_step = 0
            }),
        ),
        refused("backup state without eligibility", Box::new(|x| x.backup_state = true)),
    ];
    // Each case bends the enrolled authenticator (same key and credential) for one ceremony, then restores it.
    for (label, bend) in cases {
        let saved = (a.origin.clone(), a.rp_id.clone(), a.user_present, a.user_verified, a.type_override.clone());
        let (count, step, backup) = (a.sign_count, a.counter_step, a.backup_state);
        bend(&mut a);
        let (id, ch) = login_options(&mut b).await;
        let assertion = a.assert(&ch);
        (a.origin, a.rp_id, a.user_present, a.user_verified, a.type_override) = saved;
        (a.sign_count, a.counter_step, a.backup_state) = (count.max(a.sign_count), step, backup);
        assert_eq!(login_finish(&mut Browser::new(&h), &id, &assertion).await.status, 401, "{label}");
    }
    // The unbent authenticator still signs in, so each refusal above was the bent part.
    let (id, ch) = login_options(&mut b).await;
    assert_eq!(login_finish(&mut Browser::new(&h), &id, &a.assert(&ch)).await.status, 200, "unbent");
    // Right after a sign-in the stored counter equals the authenticator's: the same value again is refused.
    a.counter_step = 0;
    let (id, ch) = login_options(&mut b).await;
    assert_eq!(login_finish(&mut Browser::new(&h), &id, &a.assert(&ch)).await.status, 401, "counter repeated");
    a.counter_step = 1;
    // Wrong challenge, tampered signature, another ceremony's id.
    let (id, _) = login_options(&mut b).await;
    assert_eq!(login_finish(&mut Browser::new(&h), &id, &a.assert(&[0u8; 32])).await.status, 401, "wrong challenge");
    let (id, ch) = login_options(&mut b).await;
    let mut bad = a.assert(&ch);
    let last = bad.signature.len() - 1;
    bad.signature[last] ^= 1;
    assert_eq!(login_finish(&mut Browser::new(&h), &id, &bad).await.status, 401, "tampered signature");
    let (id, ch) = login_options(&mut b).await;
    let mut stranger = a.assert(&ch);
    stranger.user_handle = vec![3; 16];
    assert_eq!(login_finish(&mut Browser::new(&h), &id, &stranger).await.status, 401, "another user handle");
    let (id1, ch1) = login_options(&mut b).await;
    let (id2, _) = login_options(&mut b).await;
    assert_eq!(login_finish(&mut Browser::new(&h), &id2, &a.assert(&ch1)).await.status, 401, "other ceremony");
    assert_eq!(login_finish(&mut Browser::new(&h), &id1, &a.assert(&ch1)).await.status, 200, "own ceremony still fine");
    let audit = audit_text(&h).await;
    assert!(audit.contains("web:phone|") || audit.contains("|web:phone|"), "{audit}");
    assert!(audit.contains("admin_ui.login|"));
}

#[tokio::test]
async fn sessions_end_on_revoke_passkey_removal_and_sign_out() {
    let h = start().await;
    let mut a = SoftAuthenticator::es256(ORIGIN);
    let mut b = Browser::new(&h);
    enrol_with(&h, &mut b, "phone", &mut a).await;
    let mut lap = Browser::new(&h);
    let mut l = SoftAuthenticator::es256(ORIGIN);
    enrol_with(&h, &mut lap, "laptop", &mut l).await;
    assert_eq!(h.admin(AdminRequest::SessionsList).await.unwrap().as_array().unwrap().len(), 2);
    // `dove admin sessions revoke`: everyone is out.
    h.admin(AdminRequest::SessionsRevoke { id: None }).await.unwrap();
    assert_eq!(b.get("/admin").await.status, 303);
    assert_eq!(lap.get("/admin").await.status, 303);
    login(&mut b, &mut a).await;
    login(&mut lap, &mut l).await;
    // Removing a passkey ends its sessions only.
    let v = h.admin(AdminRequest::PasskeysRemove { name: "laptop".into() }).await.unwrap();
    assert_eq!(v["sessions_ended"], 1);
    assert_eq!(lap.get("/admin").await.status, 303);
    assert_eq!(b.get("/admin").await.status, 200);
    // The removed passkey cannot sign in again.
    let (id, ch) = login_options(&mut lap).await;
    assert_eq!(login_finish(&mut lap, &id, &l.assert(&ch)).await.status, 401);
    // Sign out.
    let r = b.post_form("/admin/logout", &[]).await;
    assert_eq!((r.status, r.header("location").as_str()), (303, "/admin/login"));
    assert!(r.header("set-cookie").contains("Max-Age=0"));
    assert_eq!(count(&h, "SELECT COUNT(*) FROM admin_sessions").await, 0);
}

#[tokio::test]
async fn sign_counter_updates_are_compare_and_swap() {
    use dove::admin_ui::store::{passkey_by_credential, record_use};
    let h = start().await;
    let a = enrol(&h, &mut Browser::new(&h), "phone").await;
    let cid = a.credential_id.clone();
    let p = h.app().store.call(move |c| passkey_by_credential(c, &cid)).await.unwrap().unwrap();
    let stale = p.clone();
    h.app().store.call(move |c| record_use(c, &p, 5, false, 1)).await.unwrap();
    // A second update from the view read before the first (two sign-ins racing with one assertion) loses.
    let r = h.app().store.call(move |c| record_use(c, &stale, 6, false, 2)).await;
    assert!(r.is_err());
    let cid = a.credential_id.clone();
    let now = h.app().store.call(move |c| passkey_by_credential(c, &cid)).await.unwrap().unwrap();
    assert_eq!(now.sign_count, 5);
}

// ------------------------------------------------------------------ step-up

#[tokio::test]
async fn approval_needs_a_passkey_confirmation_bound_to_that_approval() {
    let h = start().await;
    let token = mailbox(&h).await;
    let r1 = pending_request(&h, &token, "First", "One", None).await;
    let r2 = pending_request(&h, &token, "Second", "Two", None).await;
    let mut a = SoftAuthenticator::es256(ORIGIN);
    let mut b = Browser::new(&h);
    enrol_with(&h, &mut b, "phone", &mut a).await;
    let rev1 = request_status(&h, &r1).await["revision"].as_str().unwrap().to_string();
    let rev2 = request_status(&h, &r2).await["revision"].as_str().unwrap().to_string();
    let detail = b.get(&format!("/admin/requests/{r1}")).await;
    assert!(detail.text.contains(&format!("name=\"rev.0\" value=\"{rev1}\"")), "the page carries the shown revision");

    // The session alone cannot run an approval, not even inside the service.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("cookie", format!("{COOKIE}={}", b.cookie.clone().unwrap()).parse().unwrap());
    let s = dove::admin_ui::auth::session_from_headers(h.app(), &headers).await.unwrap();
    let approve = |id: &str, rev: &str| AdminRequest::RequestsApprove {
        id: id.into(),
        shown: vec![dove::admin::ShownItem { idx: 0, revision: rev.into() }],
        items: Some(vec![0]),
        late: dove::admin::Late::Skip,
        duration_minutes: None,
    };
    let r = dove::admin_ui::auth::run_action(h.app(), &s, approve(&r1, &rev1)).await;
    assert!(!r.ok && r.error.unwrap().contains("passkey confirmation"));
    assert_eq!(request_status(&h, &r1).await["status"], "pending");

    let form1 = [("item", "0"), ("rev.0", rev1.as_str())];
    let form2 = [("item", "0"), ("rev.0", rev2.as_str())];
    let (p1, ch1, allowed) = stepup_begin(&mut b, &format!("/admin/requests/{r1}/approve"), &form1).await;
    assert_eq!(allowed, a.credential_id, "only the session's passkey may confirm");
    let (p2, ch2, _) = stepup_begin(&mut b, &format!("/admin/requests/{r2}/approve"), &form2).await;
    assert_ne!(ch1, ch2);
    assert_eq!(request_status(&h, &r1).await["status"], "pending", "nothing runs before the confirmation");

    // An assertion over the first approval's challenge, presented for the second: refused, and the second is used up.
    let wrong = a.assert(&ch1);
    let r = stepup_finish(&mut b, &p2, &wrong).await;
    assert_eq!(r.status, 403, "{}", r.text);
    assert_eq!(request_status(&h, &r2).await["status"], "pending");
    assert_eq!(stepup_finish(&mut b, &p2, &a.assert(&ch2)).await.status, 409, "single use");
    assert_eq!(request_status(&h, &r2).await["status"], "pending");

    // Another session (same passkey) cannot finish this session's confirmation.
    let mut other = Browser::new(&h);
    login(&mut other, &mut a).await;
    let r = stepup_finish(&mut other, &p1, &a.assert(&ch1)).await;
    assert_eq!(r.status, 403);
    assert_eq!(request_status(&h, &r1).await["status"], "pending");

    // Missing user verification, a wrong challenge, a tampered signature, another passkey: refused.
    let mut spare = SoftAuthenticator::es256(ORIGIN);
    enrol_with(&h, &mut Browser::new(&h), "spare", &mut spare).await;
    for case in ["no uv", "challenge", "signature", "other passkey", "other passkey's id"] {
        let (p, ch, _) = stepup_begin(&mut b, &format!("/admin/requests/{r1}/approve"), &form1).await;
        let assertion = match case {
            "no uv" => {
                a.user_verified = false;
                let x = a.assert(&ch);
                a.user_verified = true;
                x
            }
            "challenge" => a.assert(&[1u8; 32]),
            "signature" => {
                let mut x = a.assert(&ch);
                x.signature[8] ^= 1;
                x
            }
            "other passkey" => spare.assert(&ch),
            _ => {
                // Signed with this session's key, but claiming the other passkey's credential id.
                let own = std::mem::replace(&mut a.credential_id, spare.credential_id.clone());
                let x = a.assert(&ch);
                a.credential_id = own;
                x
            }
        };
        assert_eq!(stepup_finish(&mut b, &p, &assertion).await.status, 403, "{case}");
        assert_eq!(request_status(&h, &r1).await["status"], "pending", "{case}");
    }

    // The real thing: exactly the stored approval runs, once, as web:phone.
    let (p, ch, _) = stepup_begin(&mut b, &format!("/admin/requests/{r1}/approve"), &form1).await;
    let ok = a.assert(&ch);
    let r = stepup_finish(&mut b, &p, &ok).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.json()["redirect"], format!("/admin/requests/{r1}?done=approved"));
    let st = request_status(&h, &r1).await;
    assert_eq!((st["status"].as_str(), st["decided_by"].as_str()), (Some("approved"), Some("web:phone")));
    assert_eq!(request_status(&h, &r2).await["status"], "pending", "the other request is untouched");
    assert_eq!(stepup_finish(&mut b, &p, &ok).await.status, 409, "replay");
    let audit = audit_text(&h).await;
    assert!(audit.lines().any(|l| l.contains("|web:phone|") && l.contains("requests.approve") && l.contains("|ok|")));
    assert!(audit.contains("admin_ui.stepup"), "refused confirmations are audited");

    // A revision that the page did not show is refused by the approval itself.
    let (p, ch, _) =
        stepup_begin(&mut b, &format!("/admin/requests/{r2}/approve"), &[("item", "0"), ("rev.0", "stale")]).await;
    let r = stepup_finish(&mut b, &p, &a.assert(&ch)).await;
    assert_eq!(r.status, 409, "{}", r.text);
    assert_eq!(request_status(&h, &r2).await["status"], "pending");
}

#[tokio::test]
async fn removing_a_passkey_in_the_ui_needs_a_confirmation() {
    let h = start().await;
    let mut a = SoftAuthenticator::es256(ORIGIN);
    let mut b = Browser::new(&h);
    enrol_with(&h, &mut b, "phone", &mut a).await;
    enrol(&h, &mut Browser::new(&h), "old").await;
    let (p, ch, _) = stepup_begin(&mut b, "/admin/settings/passkeys/old/remove", &[]).await;
    assert_eq!(h.admin(AdminRequest::PasskeysList).await.unwrap().as_array().unwrap().len(), 2);
    let r = stepup_finish(&mut b, &p, &a.assert(&ch)).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(h.admin(AdminRequest::PasskeysList).await.unwrap().as_array().unwrap().len(), 1);
    assert!(audit_text(&h).await.lines().any(|l| l.contains("|web:phone|") && l.contains("passkeys.remove")));
}

// ------------------------------------------------------------------ pages

#[tokio::test]
async fn pages_show_drafts_as_text_and_escape_untrusted_values() {
    let h = start().await;
    let token = mailbox(&h).await;
    let xss = "<script>alert(1)</script><img src=x onerror=alert(2)>\"'";
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({"account":"info","request_key":uuid::Uuid::new_v4().to_string(),"to":["c@example.org"],
                   "cc":["d@example.org"],"subject":format!("Offer {xss}"),
                   "body_text":format!("Dear customer,\n<b>bold?</b> {xss}\nBye"),
                   "attachments":[{"filename":format!("{xss}.txt"),"mime_type":"text/plain","content_base64":"aGk="}]}),
        )
        .await;
    let v = h
        .ok(
            &token,
            "request_send",
            json!({ "account": "info", "note": format!("Please {xss}"), "items": [{ "draft_id": c["draft_id"],
                    "expected_revision": c["revision"], "send_at": util::rfc3339(util::now_unix() + 3600) }] }),
        )
        .await;
    let rid = v["request_id"].as_str().unwrap().to_string();
    // An audit row whose fields carry markup (actor, action, mailbox, ids, result).
    h.app()
        .store
        .call(move |c| {
            let rec = dove::audit::AuditRecord {
                request_id: "x".into(),
                actor: "<b>actor</b>".into(),
                tool_or_action: "<i>tool</i>".into(),
                account_alias: Some("<u>box</u>".into()),
                object_ids: vec!["<s>id</s>".into()],
                result_code: "<em>res</em>".into(),
                ..Default::default()
            };
            dove::audit::append(c, &rec).map(|_| ())
        })
        .await
        .unwrap();
    let mut b = Browser::new(&h);
    enrol(&h, &mut b, "phone").await;
    let pages = [
        b.get("/admin").await,
        b.get("/admin/requests").await,
        b.get(&format!("/admin/requests/{rid}")).await,
        b.get("/admin/audit?since=all").await,
        b.get("/admin/settings").await,
    ];
    for p in &pages {
        assert_eq!(p.status, 200, "{}", p.text);
        for raw in ["<script>alert", "<img src=x", "<b>actor", "<i>tool", "<u>box", "<s>id", "<em>res", "<b>bold"] {
            assert!(!p.text.contains(raw), "unescaped {raw}");
        }
    }
    let detail = &pages[2].text;
    for want in [
        "&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(2)&gt;&quot;&#39;",
        "Offer &lt;script&gt;",
        "Please &lt;script&gt;",
        "&lt;b&gt;bold?&lt;/b&gt;",
        "info@acme.test",
        "c@example.org",
        "d@example.org",
        ".txt",
        "2 bytes",
        "Approve selected",
        "Deny request",
    ] {
        assert!(detail.contains(want), "{want} missing");
    }
    assert!(detail.contains("<pre class=\"letter-body\">Dear customer,\n&lt;b&gt;"), "the body is text in <pre>");
    let audit = &pages[3].text;
    for want in ["&lt;b&gt;actor&lt;/b&gt;", "&lt;i&gt;tool&lt;/i&gt;", "&lt;u&gt;box&lt;/u&gt;", "&lt;em&gt;res"] {
        assert!(audit.contains(want), "{want}");
    }
    // The overview names the waiting request and its client.
    assert!(pages[0].text.contains("1 request waits for you") && pages[0].text.contains("agent"));
}

#[tokio::test]
async fn deny_stop_and_audit_go_through_the_admin_verbs_as_web() {
    let h = start().await;
    let token = mailbox(&h).await;
    let deny = pending_request(&h, &token, "A", "a", None).await;
    let stop = pending_request(&h, &token, "B", "b", None).await;
    let mut b = Browser::new(&h);
    enrol(&h, &mut b, "phone").await;
    b.get(&format!("/admin/requests/{deny}")).await;
    let r = b.post_form(&format!("/admin/requests/{deny}/deny"), &[]).await;
    assert_eq!((r.status, r.header("location")), (303, format!("/admin/requests/{deny}?done=denied")));
    assert_eq!(request_status(&h, &deny).await["status"], "denied");
    let page = b.get(&format!("/admin/requests/{deny}?done=denied")).await;
    assert!(page.text.contains("Request denied"));
    // Approve on the socket, stop in the UI.
    let rev = request_status(&h, &stop).await["revision"].as_str().unwrap().to_string();
    h.admin(AdminRequest::RequestsApprove {
        id: stop.clone(),
        shown: vec![dove::admin::ShownItem { idx: 0, revision: rev }],
        items: None,
        late: dove::admin::Late::Skip,
        duration_minutes: None,
    })
    .await
    .unwrap();
    let page = b.get(&format!("/admin/requests/{stop}")).await;
    assert!(page.text.contains("Stop this draft"));
    let r = b.post_form(&format!("/admin/requests/{stop}/cancel"), &[("item", "0")]).await;
    assert_eq!(r.status, 303, "{}", r.text);
    let v = h.admin(AdminRequest::RequestsShow { id: stop.clone() }).await.unwrap();
    assert_eq!(v["items"][0]["state"], "cancelled");
    // An error from the verb is shown, not swallowed (the request is no longer pending).
    let r = b.post_form(&format!("/admin/requests/{deny}/deny"), &[]).await;
    assert_eq!(r.status, 409);
    assert!(r.text.contains("not pending") || r.text.contains("denied"), "{}", r.text);
    // Audit search and chain verification work and the UI's actions carry the passkey name.
    let a = b.get("/admin/audit?actor=web%3Aphone&since=all").await;
    assert!(a.text.contains("requests.deny") && a.text.contains("requests.cancel"), "{}", a.text);
    let v = b.get("/admin/audit/verify").await;
    assert!(v.text.contains("The audit chain is intact"), "{}", v.text);
    let text = audit_text(&h).await;
    for action in ["requests.deny", "requests.cancel", "audit.search", "audit.verify", "requests.show"] {
        assert!(text.lines().any(|l| l.contains("|web:phone|") && l.contains(action)), "{action}");
    }
}

#[tokio::test]
async fn health_page_runs_the_doctor_and_the_overview_remembers_it() {
    let h = start().await;
    let mut b = Browser::new(&h);
    enrol(&h, &mut b, "phone").await;
    assert!(b.get("/admin").await.text.contains("Not checked since Dove started"));
    let r = b.get("/admin/health").await;
    assert_eq!(r.status, 200);
    assert!(r.text.contains("audit chain") && r.text.contains("service version"), "{}", r.text);
    assert!(b.get("/admin").await.text.contains("Checked"));
}
