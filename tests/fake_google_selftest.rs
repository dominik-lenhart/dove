mod support;

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::fake_google::*;

const ME: &str = "info@example.com";

async fn setup() -> (FakeGoogle, reqwest::Client, String) {
    let fg = FakeGoogle::start("cid", "csecret").await;
    fg.add_mailbox(ME, "sub-1");
    let tok = fg.access_token_for(ME);
    (fg, reqwest::Client::new(), tok)
}

fn g(fg: &FakeGoogle, rest: &str) -> String {
    format!("{}/gmail/v1/users/me/{rest}", fg.base_url)
}

async fn get(fg: &FakeGoogle, c: &reqwest::Client, tok: &str, rest: &str) -> (u16, Value) {
    let r = c.get(g(fg, rest)).bearer_auth(tok).send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

fn spec(subject: &str, date: i64, labels: &[&str]) -> MessageSpec {
    MessageSpec {
        from: "Alice <alice@example.org>".into(),
        to: vec![ME.into()],
        subject: subject.into(),
        text: Some(format!("body of {subject}")),
        labels: labels.iter().map(|s| s.to_string()).collect(),
        internal_date_ms: date,
        ..Default::default()
    }
}

fn raw_b64(subject: &str) -> String {
    let raw = format!("From: {ME}\r\nTo: bob@example.org\r\nSubject: {subject}\r\n\r\nhello\r\n");
    URL_SAFE_NO_PAD.encode(raw)
}

fn verifier_challenge(v: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}

fn code_spec(challenge: &str, refresh: bool) -> CodeSpec {
    CodeSpec {
        email: ME.into(),
        sub: "sub-1".into(),
        email_verified: true,
        scopes: vec!["openid".into(), "email".into()],
        code_challenge: challenge.into(),
        aud: None,
        with_refresh_token: refresh,
    }
}

async fn exchange(fg: &FakeGoogle, c: &reqwest::Client, code: &str, verifier: &str) -> (u16, Value) {
    let r = c
        .post(format!("{}/token", fg.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", "cid"),
            ("client_secret", "csecret"),
            ("redirect_uri", "https://dove.example/cb"),
        ])
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

async fn refresh(fg: &FakeGoogle, c: &reqwest::Client, rt: &str) -> (u16, Value) {
    let r = c
        .post(format!("{}/token", fg.base_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", "cid"),
            ("client_secret", "csecret"),
        ])
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

#[tokio::test]
async fn code_exchange_pkce_and_single_use() {
    let (fg, c, _) = setup().await;
    fg.register_code("good", code_spec(&verifier_challenge("verifier-1"), true));
    fg.register_code("nopkce", code_spec(&verifier_challenge("verifier-2"), false));

    let (s, b) = exchange(&fg, &c, "nopkce", "wrong-verifier").await;
    assert_eq!((s, b["error"].as_str()), (400, Some("invalid_grant")));
    let (s, b) = exchange(&fg, &c, "unknown", "x").await;
    assert_eq!((s, b["error"].as_str()), (400, Some("invalid_grant")));

    let (s, b) = exchange(&fg, &c, "good", "verifier-1").await;
    assert_eq!(s, 200);
    assert_eq!(b["token_type"], "Bearer");
    assert_eq!(b["expires_in"], 3599);
    assert_eq!(b["scope"], "openid email");
    assert!(b["refresh_token"].is_string() && b["access_token"].is_string());
    let (s, _) = exchange(&fg, &c, "good", "verifier-1").await;
    assert_eq!(s, 400, "code is single use");

    let (s, b) = exchange(&fg, &c, "nopkce", "verifier-2").await;
    assert_eq!(s, 200);
    assert!(b.get("refresh_token").is_none());

    // wrong client secret
    fg.register_code("c3", code_spec(&verifier_challenge("v3"), true));
    let r = c
        .post(format!("{}/token", fg.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "c3"),
            ("code_verifier", "v3"),
            ("client_id", "cid"),
            ("client_secret", "nope"),
            ("redirect_uri", "x"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    fg.assert_no_violations();
}

#[tokio::test]
async fn refresh_invalid_grant_and_revoke() {
    let (fg, c, _) = setup().await;
    let rt = fg.issue_refresh_token(ME);
    let (s, b) = refresh(&fg, &c, &rt).await;
    assert_eq!(s, 200);
    assert!(b.get("refresh_token").is_none());
    // The new access token works against Gmail.
    let tok = b["access_token"].as_str().unwrap();
    let (s, p) = get(&fg, &c, tok, "profile").await;
    assert_eq!(s, 200);
    assert_eq!(p["emailAddress"], ME);

    fg.invalidate_refresh_tokens(ME);
    let (s, b) = refresh(&fg, &c, &rt).await;
    assert_eq!((s, b["error"].as_str()), (400, Some("invalid_grant")));
    let (s, _) = refresh(&fg, &c, "unknown").await;
    assert_eq!(s, 400);

    let rt2 = fg.issue_refresh_token(ME);
    let r = c.post(format!("{}/revoke", fg.base_url)).form(&[("token", rt2.as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(fg.revoked_tokens(), vec![rt2.clone()]);
    assert_eq!(refresh(&fg, &c, &rt2).await.0, 400);
}

#[tokio::test]
async fn jwks_verifies_id_token() {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
    let (fg, c, _) = setup().await;
    fg.register_code("k", code_spec(&verifier_challenge("v"), false));
    let (_, tok) = exchange(&fg, &c, "k", "v").await;
    let id_token = tok["id_token"].as_str().unwrap();
    let jwks: Value = c.get(format!("{}/oauth2/v3/certs", fg.base_url)).send().await.unwrap().json().await.unwrap();
    let key = &jwks["keys"][0];
    assert_eq!(
        (key["kty"].as_str(), key["alg"].as_str(), key["use"].as_str()),
        (Some("RSA"), Some("RS256"), Some("sig"))
    );
    let header = decode_header(id_token).unwrap();
    assert_eq!(header.kid.as_deref(), key["kid"].as_str());
    let dk = DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap()).unwrap();
    let mut v = Validation::new(Algorithm::RS256);
    v.set_issuer(&["https://accounts.google.com"]);
    v.set_audience(&["cid"]);
    let data = decode::<Value>(id_token, &dk, &v).unwrap();
    assert_eq!(data.claims["email"], ME);
    assert_eq!(data.claims["sub"], "sub-1");
    assert_eq!(data.claims["email_verified"], true);
    // wrong audience is rejected
    v.set_audience(&["other"]);
    assert!(decode::<Value>(id_token, &dk, &v).is_err());
}

#[tokio::test]
async fn auth_required_and_labels() {
    let (fg, c, tok) = setup().await;
    let r = c.get(g(&fg, "profile")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let b: Value = r.json().await.unwrap();
    assert_eq!(b["error"]["status"], "UNAUTHENTICATED");
    assert_eq!(c.get(g(&fg, "profile")).bearer_auth("bogus").send().await.unwrap().status(), 401);

    fg.add_message(ME, spec("a", 1000, &["INBOX", "Clients"]));
    let (_, l) = get(&fg, &c, &tok, "labels").await;
    let labels = l["labels"].as_array().unwrap();
    assert!(labels.iter().any(|x| x["id"] == "INBOX" && x["type"] == "system"));
    assert!(labels.iter().any(|x| x["id"] == "Label_1" && x["name"] == "Clients" && x["type"] == "user"));
    assert_eq!(fg.requests().last().unwrap().mailbox.as_deref(), Some(ME));
}

#[tokio::test]
async fn messages_list_paging_filters_and_get() {
    let (fg, c, tok) = setup().await;
    let ids: Vec<String> =
        (1..=5).map(|i| fg.add_message(ME, spec(&format!("mail-{i}"), i * 1000, &["INBOX"]))).collect();
    let spam = fg.add_message(ME, spec("junk", 9000, &["SPAM"]));
    let trash = fg.add_message(ME, spec("bin", 9500, &["TRASH"]));

    let (s, p1) = get(&fg, &c, &tok, "messages?maxResults=2").await;
    assert_eq!(s, 200);
    let got1: Vec<&str> = p1["messages"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(got1, vec![ids[4].as_str(), ids[3].as_str()]);
    let t1 = p1["nextPageToken"].as_str().unwrap();
    let (_, p2) = get(&fg, &c, &tok, &format!("messages?maxResults=2&pageToken={t1}")).await;
    let got2: Vec<&str> = p2["messages"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(got2, vec![ids[2].as_str(), ids[1].as_str()]);
    let t2 = p2["nextPageToken"].as_str().unwrap();
    let (_, p3) = get(&fg, &c, &tok, &format!("messages?maxResults=2&pageToken={t2}")).await;
    assert_eq!(p3["messages"].as_array().unwrap().len(), 1);
    assert!(p3.get("nextPageToken").is_none());

    let (_, all) = get(&fg, &c, &tok, "messages?includeSpamTrash=true").await;
    let all: Vec<&str> = all["messages"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(all.contains(&spam.as_str()) && all.contains(&trash.as_str()) && all.len() == 7);
    let (_, def) = get(&fg, &c, &tok, "messages").await;
    assert_eq!(def["resultSizeEstimate"], 5);

    // q: free text and from:, ANDed
    let (_, q) = get(&fg, &c, &tok, "messages?q=BODY%20MAIL-3").await;
    assert_eq!(q["messages"].as_array().unwrap().len(), 1);
    let (_, q) = get(&fg, &c, &tok, "messages?q=from%3Aalice%40example.org%20mail").await;
    assert_eq!(q["messages"].as_array().unwrap().len(), 5);
    let (_, q) = get(&fg, &c, &tok, "messages?q=from%3Anobody%20mail").await;
    assert!(q.get("messages").is_none());
    let (_, q) = get(&fg, &c, &tok, "messages?labelIds=SPAM").await;
    assert_eq!(q["messages"].as_array().unwrap().len(), 1);

    // get: raw and minimal
    let (s, m) = get(&fg, &c, &tok, &format!("messages/{}?format=raw", ids[0])).await;
    assert_eq!(s, 200);
    let raw = URL_SAFE_NO_PAD.decode(m["raw"].as_str().unwrap()).unwrap();
    assert_eq!(m["sizeEstimate"], raw.len());
    assert!(String::from_utf8_lossy(&raw).contains("Subject: mail-1"));
    assert_eq!(m["internalDate"], "1000");
    assert_eq!(m["snippet"], "body of mail-1");
    assert!(m["historyId"].is_string());
    let (_, m) = get(&fg, &c, &tok, &format!("messages/{}?format=minimal", ids[0])).await;
    assert!(m.get("raw").is_none());
    assert_eq!(get(&fg, &c, &tok, "messages/deadbeef").await.0, 404);
    assert_ne!(m["id"], m["threadId"]);
    fg.assert_no_violations();
}

#[tokio::test]
async fn threads_and_profile() {
    let (fg, c, tok) = setup().await;
    let a = fg.add_message(ME, spec("first", 1000, &["INBOX"]));
    let (_, am) = get(&fg, &c, &tok, &format!("messages/{a}?format=minimal")).await;
    let tid = am["threadId"].as_str().unwrap().to_string();
    let mut s2 = spec("second", 2000, &["INBOX"]);
    s2.thread_id = Some(tid.clone());
    let b = fg.add_message(ME, s2);
    let (s, t) = get(&fg, &c, &tok, &format!("threads/{tid}?format=metadata")).await;
    assert_eq!(s, 200);
    let ids: Vec<&str> = t["messages"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec![a.as_str(), b.as_str()]);
    assert_eq!(get(&fg, &c, &tok, "threads/nope").await.0, 404);
    let (_, p) = get(&fg, &c, &tok, "profile").await;
    assert_eq!((p["messagesTotal"].as_u64(), p["threadsTotal"].as_u64()), (Some(2), Some(1)));
    assert_eq!(p["historyId"], fg.history_id(ME).to_string());
}

#[tokio::test]
async fn draft_lifecycle() {
    let (fg, c, tok) = setup().await;
    fg.add_send_as(ME, "alias@example.com");
    let (_, sa) = get(&fg, &c, &tok, "settings/sendAs").await;
    assert_eq!(sa["sendAs"].as_array().unwrap().len(), 2);
    assert_eq!(sa["sendAs"][0]["sendAsEmail"], ME);
    assert_eq!(sa["sendAs"][0]["isPrimary"], true);

    let r = c
        .post(g(&fg, "drafts"))
        .bearer_auth(&tok)
        .json(&json!({"message": {"raw": raw_b64("v1")}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let d: Value = r.json().await.unwrap();
    let did = d["id"].as_str().unwrap().to_string();
    let m1 = d["message"]["id"].as_str().unwrap().to_string();
    assert_eq!(d["message"]["labelIds"], json!(["DRAFT"]));
    let thread1 = d["message"]["threadId"].as_str().unwrap().to_string();

    let (_, dl) = get(&fg, &c, &tok, "drafts").await;
    assert_eq!(dl["drafts"][0]["id"], did.as_str());
    let (_, dg) = get(&fg, &c, &tok, &format!("drafts/{did}?format=raw")).await;
    assert_eq!(dg["message"]["id"], m1.as_str());
    assert!(dg["message"]["raw"].is_string());
    assert_eq!(get(&fg, &c, &tok, "drafts/nope").await.0, 404);

    let r = c
        .put(g(&fg, &format!("drafts/{did}")))
        .bearer_auth(&tok)
        .json(&json!({"id": did, "message": {"raw": raw_b64("v2"), "threadId": thread1}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let d2: Value = r.json().await.unwrap();
    let m2 = d2["message"]["id"].as_str().unwrap().to_string();
    assert_eq!(d2["id"], did.as_str());
    assert_ne!(m1, m2, "update yields a new message id");
    assert_eq!(d2["message"]["threadId"], thread1.as_str());
    assert_eq!(get(&fg, &c, &tok, &format!("messages/{m1}")).await.0, 404);
    assert!(String::from_utf8_lossy(&fg.draft_raw(ME, &did).unwrap()).contains("Subject: v2"));
    assert_eq!(fg.drafts(ME), vec![(did.clone(), m2.clone())]);
    let r = c
        .put(g(&fg, "drafts/nope"))
        .bearer_auth(&tok)
        .json(&json!({"message": {"raw": raw_b64("x")}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // external edit changes the message id again
    fg.replace_draft_externally(ME, &did, b"Subject: human\r\n\r\nedit\r\n");
    let m3 = fg.drafts(ME)[0].1.clone();
    assert_ne!(m2, m3);

    let r = c.post(g(&fg, "drafts/send")).bearer_auth(&tok).json(&json!({"id": did})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let sent: Value = r.json().await.unwrap();
    assert_eq!(sent["id"], m3.as_str());
    assert_eq!(sent["labelIds"], json!(["SENT"]));
    assert!(fg.drafts(ME).is_empty());
    assert_eq!(fg.sent_messages(ME), vec![m3.clone()]);
    assert_eq!(get(&fg, &c, &tok, &format!("drafts/{did}")).await.0, 404);
    let r = c.post(g(&fg, "drafts/send")).bearer_auth(&tok).json(&json!({"id": did})).send().await.unwrap();
    assert_eq!(r.status(), 404);
    fg.assert_no_violations();
}

#[tokio::test]
async fn history_records_and_floor() {
    let (fg, c, tok) = setup().await;
    let start = fg.history_id(ME);
    let a = fg.add_message(ME, spec("a", 1000, &["INBOX"]));
    fg.set_labels(ME, &a, &["STARRED"], &["INBOX"]);
    let b = fg.add_message(ME, spec("b", 2000, &["INBOX"]));
    fg.delete_message(ME, &b);
    assert_eq!(fg.history_id(ME), start + 4);

    let (s, h) = get(&fg, &c, &tok, &format!("history?startHistoryId={start}")).await;
    assert_eq!(s, 200);
    assert_eq!(h["historyId"], fg.history_id(ME).to_string());
    let recs = h["history"].as_array().unwrap();
    assert_eq!(recs.len(), 4);
    assert_eq!(recs[0]["messagesAdded"][0]["message"]["id"], a.as_str());
    assert_eq!(recs[1]["labelsAdded"][0]["labelIds"], json!(["STARRED"]));
    assert_eq!(recs[1]["labelsRemoved"][0]["labelIds"], json!(["INBOX"]));
    assert_eq!(recs[3]["messagesDeleted"][0]["message"]["id"], b.as_str());
    assert_eq!(recs[3]["messages"][0]["id"], b.as_str());

    let (_, h) = get(&fg, &c, &tok, &format!("history?startHistoryId={}", start + 2)).await;
    assert_eq!(h["history"].as_array().unwrap().len(), 2);
    let (_, h) = get(&fg, &c, &tok, &format!("history?startHistoryId={start}&maxResults=3")).await;
    assert_eq!(h["history"].as_array().unwrap().len(), 3);
    assert!(h["nextPageToken"].is_string());

    fg.set_history_floor(ME, start + 3);
    assert_eq!(get(&fg, &c, &tok, &format!("history?startHistoryId={start}")).await.0, 404);
    assert_eq!(get(&fg, &c, &tok, &format!("history?startHistoryId={}", start + 3)).await.0, 200);
}

#[tokio::test]
async fn allowlist_violations_are_403_and_recorded() {
    let (fg, c, tok) = setup().await;
    let r = c.post(g(&fg, "messages/send")).bearer_auth(&tok).json(&json!({"raw": "x"})).send().await.unwrap();
    assert_eq!(r.status(), 403);
    for (m, p) in [
        // Organize is allowlisted since 0.2; permanent deletion never is.
        (reqwest::Method::POST, "messages/batchDelete"),
        (reqwest::Method::DELETE, "messages/abc"),
        (reqwest::Method::DELETE, "drafts/abc"),
        (reqwest::Method::GET, "settings/filters"),
        (reqwest::Method::POST, "watch"),
        (reqwest::Method::POST, "messages/import"),
    ] {
        assert_eq!(c.request(m, g(&fg, p)).bearer_auth(&tok).send().await.unwrap().status(), 403, "{p}");
    }
    assert_eq!(fg.violations().len(), 7);
    assert!(fg.violations()[0].contains("POST") && fg.violations()[0].contains("messages/send"));
    assert_eq!(fg.count("POST", "messages/send"), 1);
    fg.clear_requests();
    assert!(fg.requests().is_empty());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fg.assert_no_violations()));
    assert!(result.is_err());
    fg.clear_violations();
    fg.assert_no_violations();
}

#[tokio::test]
async fn faults_status_delay_and_drop_after_apply() {
    let (fg, _, tok) = setup().await;
    let c = reqwest::Client::builder().timeout(Duration::from_millis(500)).build().unwrap();

    fg.fail_next("GET", "/profile", Fault::Status(429, json!({"error": {"code": 429}})));
    let r = c.get(g(&fg, "profile")).bearer_auth(&tok).send().await.unwrap();
    assert_eq!(r.status(), 429);
    // Only the next request is affected.
    assert_eq!(c.get(g(&fg, "profile")).bearer_auth(&tok).send().await.unwrap().status(), 200);

    fg.fail_next("GET", "/profile", Fault::Delay(Duration::from_secs(2)));
    assert!(c.get(g(&fg, "profile")).bearer_auth(&tok).send().await.unwrap_err().is_timeout());

    fg.fail_next("POST", "drafts", Fault::DropAfterApply);
    let err = c
        .post(g(&fg, "drafts"))
        .bearer_auth(&tok)
        .json(&json!({"message": {"raw": raw_b64("lost")}}))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_timeout());
    assert_eq!(fg.drafts(ME).len(), 1, "effect applied despite the lost response");
    assert_eq!(fg.count("POST", "/drafts"), 1);
}
