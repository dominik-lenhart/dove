//! Requests stage 1 (design 2026-11-14 section 4, PLAN A71): an agent asks for a scheduled send of its own drafts,
//! the operator approves exactly what was shown, and the worker sends exactly that revision at its time, at most
//! once, or not at all.

mod support;

use dove::admin::AdminRequest;
use dove::util;
use serde_json::{Value, json};
use support::harness::{Harness, g};

const MB: &str = "info@acme.test";
const DAY: i64 = 86_400;

/// Gmail mailbox `info` in project `acme`, a `read,draft` token (`allow_send` stays off).
async fn setup_with(customize: impl FnOnce(&mut dove::config::Config)) -> (Harness, String) {
    let h = Harness::start_with(customize).await;
    h.mailbox("info", MB);
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read,draft")]).await;
    (h, token)
}

async fn setup() -> (Harness, String) {
    setup_with(|_| {}).await
}

/// Creates a draft; returns (draft_id, revision).
async fn draft(h: &Harness, token: &str, account: &str) -> (String, String) {
    let c = h
        .ok(
            token,
            "create_draft",
            json!({"account":account,"request_key":uuid::Uuid::new_v4().to_string(),"to":["c@example.org"],
                   "subject":"Offer","body_text":"Dear customer"}),
        )
        .await;
    (c["draft_id"].as_str().unwrap().to_string(), c["revision"].as_str().unwrap().to_string())
}

fn at(t: i64) -> String {
    util::rfc3339(t)
}

/// `request_send` arguments for `info` with one `send_at` per draft.
fn send_args(items: &[(&str, &str, i64)]) -> Value {
    let items: Vec<Value> =
        items.iter().map(|(d, r, t)| json!({"draft_id": d, "expected_revision": r, "send_at": at(*t)})).collect();
    json!({ "account": "info", "items": items })
}

/// The full error object of a failing call.
async fn error(h: &Harness, token: &str, tool: &str, args: Value) -> Value {
    let (err, v) = h.call(token, tool, args).await;
    assert!(err, "{tool} unexpectedly succeeded: {v}");
    v["error"].clone()
}

/// Every audit row as one text line per row (all cells, blobs as lossy text).
async fn audit_text(h: &Harness) -> String {
    let rows: Vec<String> = h
        .app()
        .store
        .call(|c| {
            let mut st = c.prepare("SELECT * FROM audit")?;
            let n = st.column_count();
            let rows = st.query_map([], |r| {
                let cell = |i| match r.get::<_, rusqlite::types::Value>(i) {
                    Ok(rusqlite::types::Value::Text(t)) => t,
                    Ok(rusqlite::types::Value::Blob(b)) => String::from_utf8_lossy(&b).into_owned(),
                    Ok(v) => format!("{v:?}"),
                    Err(e) => format!("{e}"),
                };
                Ok((0..n).map(cell).collect::<Vec<_>>().join("|"))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
        .unwrap();
    rows.join("\n")
}

#[tokio::test]
async fn request_send_needs_draft_not_send() {
    let (h, token) = setup().await;
    assert!(!h.app().cfg.allow_send);
    let reader = h.token("acme", "reader", vec![g("info", "read")]).await;
    let names = h.tool_names(&token).await;
    for t in ["request_send", "list_requests", "cancel_request"] {
        assert!(names.contains(&t.to_string()), "{t}");
    }
    assert!(!names.contains(&"send_draft".to_string()));
    assert!(!h.tool_names(&reader).await.contains(&"request_send".to_string()));
    let (d, rev) = draft(&h, &token, "info").await;
    let now = util::now_unix();
    let v = h.ok(&token, "request_send", send_args(&[(&d, &rev, now + 3600)])).await;
    assert_eq!(v["status"], "pending");
    assert!(v["request_id"].as_str().unwrap().starts_with("r_"));
    assert_eq!(v["items"][0]["draft_id"], d.as_str());
    assert_eq!(v["items"][0]["send_at"], at(now + 3600));
    assert_eq!(h.err(&reader, "request_send", send_args(&[(&d, &rev, now + 3600)])).await, "forbidden");
    let list = h.ok(&token, "list_requests", json!({})).await;
    assert_eq!(list["requests"].as_array().unwrap().len(), 1);
    assert_eq!(list["requests"][0]["items"][0]["state"], "pending");
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
    assert!(h.google.sent_messages(MB).is_empty());
}

#[tokio::test]
async fn switched_off_requests_are_treated_like_send_without_allow_send() {
    let (h, token) = setup_with(|c| c.requests.enabled = false).await;
    let names = h.tool_names(&token).await;
    for t in ["request_send", "list_requests", "cancel_request", "send_draft"] {
        assert!(!names.contains(&t.to_string()), "{t}");
    }
    let (d, rev) = draft(&h, &token, "info").await;
    let refused = error(&h, &token, "request_send", send_args(&[(&d, &rev, util::now_unix() + 3600)])).await;
    let send = error(&h, &token, "send_draft", json!({"account":"info","draft_id":d,"expected_revision":rev})).await;
    assert_eq!(refused, send, "the same error as send_draft without allow_send");
    assert_eq!(error(&h, &token, "list_requests", json!({})).await, send);
    assert_eq!(error(&h, &token, "cancel_request", json!({"request_id":"r_x"})).await, send);
}

#[tokio::test]
async fn request_send_validates_times() {
    let (h, token) = setup().await;
    let (d, rev) = draft(&h, &token, "info").await;
    let now = util::now_unix();
    let item = |send_at: Option<&str>| match send_at {
        Some(s) => json!({"draft_id": d, "expected_revision": rev, "send_at": s}),
        None => json!({"draft_id": d, "expected_revision": rev}),
    };
    let window = |from: i64, to: i64| json!({"from": at(from), "to": at(to)});
    let cases: Vec<(Value, &str)> = vec![
        (json!({"account":"info","items":[item(Some("2030-01-02T09:00:00"))]}), "items[0].send_at"),
        (json!({"account":"info","items":[item(Some("2030-01-02"))]}), "items[0].send_at"),
        (json!({"account":"info","items":[item(Some(&at(now - 60)))]}), "items[0].send_at"),
        (json!({"account":"info","items":[item(Some(&at(now + 31 * DAY)))]}), "items[0].send_at"),
        (json!({"account":"info","items":[item(None)]}), "items[0].send_at"),
        (
            json!({"account":"info","items":[item(Some(&at(now + 3600)))],"window":window(now + 60, now + 120)}),
            "items[0].send_at",
        ),
        (json!({"account":"info","items":[item(None)],"window":window(now + 7200, now + 3600)}), "window"),
        (json!({"account":"info","items":[item(None)],"window":window(now + 3600, now + 3600)}), "window"),
        (json!({"account":"info","items":[item(None)],"window":window(now - 60, now + 3600)}), "window.from"),
        (json!({"account":"info","items":[item(None)],"window":window(now + 60, now + 31 * DAY)}), "window.to"),
        (
            json!({"account":"info","items":[item(None)],"window":{"from":"2030-01-02","to":at(now + 3600)}}),
            "window.from",
        ),
        (json!({"account":"info","items":[]}), "items"),
    ];
    for (args, field) in cases {
        let e = error(&h, &token, "request_send", args.clone()).await;
        assert_eq!(e["code"], "invalid_argument", "{args}: {e}");
        assert_eq!(e["details"]["field"], field, "{args}: {e}");
    }
    // The bounds themselves are accepted: 30 days out, one second from now.
    h.ok(&token, "request_send", send_args(&[(&d, &rev, util::now_unix() + 30 * DAY - 5)])).await;
    assert_eq!(h.ok(&token, "list_requests", json!({})).await["requests"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_draft_is_requested_once() {
    let (h, token) = setup().await;
    let (d1, r1) = draft(&h, &token, "info").await;
    let (d2, r2) = draft(&h, &token, "info").await;
    let t = util::now_unix() + 3600;
    let first = h.ok(&token, "request_send", send_args(&[(&d1, &r1, t)])).await;
    let e = error(&h, &token, "request_send", send_args(&[(&d2, &r2, t), (&d1, &r1, t)])).await;
    assert_eq!(
        (e["code"].as_str(), e["details"]["field"].as_str()),
        (Some("invalid_argument"), Some("items[1].draft_id"))
    );
    let e = error(&h, &token, "request_send", send_args(&[(&d2, &r2, t), (&d2, &r2, t + 60)])).await;
    assert_eq!(
        (e["code"].as_str(), e["details"]["field"].as_str()),
        (Some("invalid_argument"), Some("items[1].draft_id"))
    );
    // Another connection of the project cannot schedule it a second time either.
    let other = h.token("acme", "other", vec![g("info", "read,draft")]).await;
    let e = error(&h, &other, "request_send", send_args(&[(&d1, &r1, t)])).await;
    assert_eq!(e["details"]["field"], "items[0].draft_id");
    // Once the first request is cancelled the draft is free again.
    h.ok(&token, "cancel_request", json!({"request_id": first["request_id"]})).await;
    h.ok(&token, "request_send", send_args(&[(&d1, &r1, t), (&d2, &r2, t)])).await;
}

#[tokio::test]
async fn request_send_needs_own_unchanged_drafts() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    // Another project's draft on the same mailbox, and an unknown id: the same not_found.
    h.project("other", &["info"]).await;
    let foreign = h.token("other", "foreign", vec![g("info", "read,draft")]).await;
    let (fd, frev) = draft(&h, &foreign, "info").await;
    let unknown = error(&h, &token, "request_send", send_args(&[("r00000000000000a", "x", t)])).await;
    assert_eq!(unknown["code"], "not_found");
    assert_eq!(error(&h, &token, "request_send", send_args(&[(&fd, &frev, t)])).await, unknown);
    // A stale revision is a conflict.
    let (d, rev) = draft(&h, &token, "info").await;
    let u = h
        .ok(
            &token,
            "update_draft",
            json!({"account":"info","draft_id":d,"expected_revision":rev,"changes":{"body_text":"new"}}),
        )
        .await;
    let e = error(&h, &token, "request_send", send_args(&[(&d, &rev, t)])).await;
    assert_eq!(e["code"], "draft_conflict");
    h.ok(&token, "request_send", send_args(&[(&d, u["revision"].as_str().unwrap(), t)])).await;
    // unless_reply needs an indexed mailbox.
    let (d3, r3) = draft(&h, &token, "info").await;
    let mut args = send_args(&[(&d3, &r3, t)]);
    args["unless_reply"] = json!(true);
    let e = error(&h, &token, "request_send", args).await;
    assert_eq!((e["code"].as_str(), e["details"]["field"].as_str()), (Some("invalid_argument"), Some("unless_reply")));
}

#[tokio::test]
async fn window_spreads_items() {
    let (h, token) = setup().await;
    let mut items = Vec::new();
    for _ in 0..5 {
        items.push(draft(&h, &token, "info").await);
    }
    let day = (util::now_unix() / DAY + 1) * DAY;
    let list: Vec<Value> = items.iter().map(|(d, r)| json!({"draft_id": d, "expected_revision": r})).collect();
    let v = h
        .ok(
            &token,
            "request_send",
            json!({"account":"info","items":list,"window":{"from":at(day + 9 * 3600),"to":at(day + 17 * 3600)}}),
        )
        .await;
    let got: Vec<(String, String)> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["draft_id"].as_str().unwrap().to_string(), i["send_at"].as_str().unwrap().to_string()))
        .collect();
    let want: Vec<(String, String)> =
        items.iter().zip([9, 11, 13, 15, 17]).map(|((d, _), hour)| (d.clone(), at(day + hour * 3600))).collect();
    assert_eq!(got, want);
    // The stored times are what the agent was told.
    let listed = h.ok(&token, "list_requests", json!({})).await;
    let stored: Vec<&str> =
        listed["requests"][0]["items"].as_array().unwrap().iter().map(|i| i["send_at"].as_str().unwrap()).collect();
    assert_eq!(stored, want.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>());
}

#[tokio::test]
async fn requests_are_private_to_the_client() {
    let (h, token) = setup().await;
    let other = h.token("acme", "other", vec![g("info", "read,draft")]).await;
    let (d, rev) = draft(&h, &token, "info").await;
    let v = h.ok(&token, "request_send", send_args(&[(&d, &rev, util::now_unix() + 3600)])).await;
    let id = v["request_id"].as_str().unwrap();
    assert!(h.ok(&other, "list_requests", json!({})).await["requests"].as_array().unwrap().is_empty());
    let random = error(&h, &other, "cancel_request", json!({"request_id": "r_AAAAAAAAAAAAAAAAAAAAAA"})).await;
    assert_eq!(random["code"], "not_found");
    assert_eq!(error(&h, &other, "cancel_request", json!({"request_id": id})).await, random);
    assert_eq!(error(&h, &other, "cancel_request", json!({"request_id": "not a request"})).await, random);
    // Still pending for its owner.
    let mine = h.ok(&token, "list_requests", json!({"status":"pending"})).await;
    assert_eq!(mine["requests"][0]["request_id"], id);
    let e = error(&h, &token, "list_requests", json!({"status":"sent"})).await;
    assert_eq!(e["details"]["field"], "status");
}

#[tokio::test]
async fn note_is_sealed_and_absent_from_audit() {
    let (h, token) = setup().await;
    let (d, rev) = draft(&h, &token, "info").await;
    let note = "NOTE-CANARY-5d1e please send before the fair";
    let mut args = send_args(&[(&d, &rev, util::now_unix() + 3600)]);
    args["note"] = json!(note);
    let v = h.ok(&token, "request_send", args.clone()).await;
    let id = v["request_id"].as_str().unwrap().to_string();
    // Too long a note is refused.
    let (d2, r2) = draft(&h, &token, "info").await;
    let mut long = send_args(&[(&d2, &r2, util::now_unix() + 3600)]);
    long["note"] = json!("x".repeat(501));
    assert_eq!(error(&h, &token, "request_send", long).await["details"]["field"], "note");
    // The agent never reads its note back.
    let listed = h.ok(&token, "list_requests", json!({})).await;
    assert!(!listed.to_string().contains("NOTE-CANARY"), "{listed}");
    assert!(!audit_text(&h).await.contains("NOTE-CANARY"));
    let sealed: Vec<u8> = h
        .app()
        .store
        .call(move |c| Ok(c.query_row("SELECT note_sealed FROM requests WHERE id = ?1", [id], |r| r.get(0))?))
        .await
        .unwrap();
    assert!(!sealed.windows(11).any(|w| w == b"NOTE-CANARY"));
    assert!(sealed.len() > note.len(), "the note is stored sealed");
}

#[tokio::test]
async fn revoked_client_and_disabled_mailbox_cancel_requests() {
    let (h, token) = setup().await;
    let (d, rev) = draft(&h, &token, "info").await;
    let t = util::now_unix() + 3600;
    h.ok(&token, "request_send", send_args(&[(&d, &rev, t)])).await;
    let other = h.token("acme", "other", vec![g("info", "read,draft")]).await;
    let (d2, r2) = draft(&h, &other, "info").await;
    h.ok(&other, "request_send", send_args(&[(&d2, &r2, t)])).await;
    let v = h.admin(AdminRequest::ClientsRevoke { name: "agent".into() }).await.unwrap();
    assert_eq!(v["requests_cancelled"], 1);
    let v = h.admin(AdminRequest::AccountsDisable { alias: "info".into() }).await.unwrap();
    assert_eq!(v["requests_cancelled"], 1);
    let states: Vec<(String, String)> = h
        .app()
        .store
        .call(|c| {
            let mut st = c.prepare(
                "SELECT r.status, i.reason FROM requests r JOIN request_items i ON i.request_id = r.id ORDER BY i.reason",
            )?;
            Ok(st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
        })
        .await
        .unwrap();
    assert_eq!(
        states,
        vec![("cancelled".into(), "account_disabled".into()), ("cancelled".into(), "client_revoked".into())]
    );
}
