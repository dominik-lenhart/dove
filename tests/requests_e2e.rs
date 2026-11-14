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

// ------------------------------------------------------------------ approval (admin verbs)

/// Creates `n` drafts and one request for them at `times`; returns (request id, draft ids).
async fn requested(h: &Harness, token: &str, times: &[i64]) -> (String, Vec<String>) {
    let mut items = Vec::new();
    for _ in times {
        items.push(draft(h, token, "info").await);
    }
    let list: Vec<(&str, &str, i64)> =
        items.iter().zip(times).map(|((d, r), t)| (d.as_str(), r.as_str(), *t)).collect();
    let v = h.ok(token, "request_send", send_args(&list)).await;
    (v["request_id"].as_str().unwrap().to_string(), items.into_iter().map(|(d, _)| d).collect())
}

async fn show(h: &Harness, id: &str) -> Value {
    h.admin(AdminRequest::RequestsShow { id: id.into() }).await.unwrap()
}

/// The revisions `show` printed, for every item.
fn shown_of(v: &Value) -> Vec<dove::admin::ShownItem> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["revision"].is_string())
        .map(|i| dove::admin::ShownItem {
            idx: i["idx"].as_u64().unwrap() as u32,
            revision: i["revision"].as_str().unwrap().into(),
        })
        .collect()
}

async fn approve(
    h: &Harness,
    id: &str,
    shown: Vec<dove::admin::ShownItem>,
    items: Option<Vec<u32>>,
    late: dove::admin::Late,
) -> Result<Value, String> {
    h.admin(AdminRequest::RequestsApprove { id: id.into(), shown, items, late }).await
}

/// (request status, item states with reasons) as stored.
async fn states(h: &Harness, id: &str) -> (String, Vec<(String, Option<String>)>) {
    let id = id.to_string();
    h.app()
        .store
        .call(move |c| {
            let status: String = c.query_row("SELECT status FROM requests WHERE id = ?1", [&id], |r| r.get(0))?;
            let mut st = c.prepare("SELECT state, reason FROM request_items WHERE request_id = ?1 ORDER BY idx")?;
            let items = st.query_map([&id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            Ok((status, items))
        })
        .await
        .unwrap()
}

fn st(s: &str, reason: Option<&str>) -> (String, Option<String>) {
    (s.to_string(), reason.map(str::to_string))
}

/// Moves item `idx` of request `id` to `send_at` (as if the request had been made earlier).
async fn set_send_at(h: &Harness, id: &str, idx: u32, send_at: i64) {
    let id = id.to_string();
    h.app()
        .store
        .call(move |c| {
            let n = c.execute(
                "UPDATE request_items SET send_at = ?1 WHERE request_id = ?2 AND idx = ?3",
                rusqlite::params![send_at, id, idx],
            )?;
            assert_eq!(n, 1);
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn show_reads_the_drafts_fresh_and_content_stays_out_of_audit() {
    let (h, token) = setup().await;
    let (d, rev) = draft(&h, &token, "info").await;
    let mut args = send_args(&[(&d, &rev, util::now_unix() + 3600)]);
    args["note"] = json!("NOTE-CANARY-9a2c check the price");
    let id = h.ok(&token, "request_send", args).await["request_id"].as_str().unwrap().to_string();
    let v = show(&h, &id).await;
    assert_eq!(v["note"], "NOTE-CANARY-9a2c check the price");
    assert_eq!(v["client"], "agent");
    let it = &v["items"][0];
    assert_eq!((it["revision"].as_str(), it["sendable"].as_bool()), (Some(rev.as_str()), Some(true)));
    assert_eq!(it["changed_since_request"], false);
    assert_eq!(it["subject"], "Offer");
    assert!(it["body_text"].as_str().unwrap().contains("Dear customer"));
    assert_eq!(it["to"], json!(["c@example.org"]));
    let audit = audit_text(&h).await;
    for needle in ["Offer", "Dear customer", "c@example.org", "NOTE-CANARY"] {
        assert!(!audit.contains(needle), "{needle} reached the audit log");
    }
    assert!(audit.contains("requests.show") && audit.contains(&id));
    // A draft changed by a person shows as changed and not sendable.
    let raw = String::from_utf8(h.google.draft_raw(MB, &d).unwrap()).unwrap();
    h.google.replace_draft_externally(MB, &d, raw.replace("Dear customer", "Dear friend").as_bytes());
    let v = show(&h, &id).await;
    assert_eq!(
        (v["items"][0]["changed_since_request"].as_bool(), v["items"][0]["sendable"].as_bool()),
        (Some(true), Some(false))
    );
    let e = approve(&h, &id, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap_err();
    assert!(e.contains("changed outside Dove"), "{e}");
    assert_eq!(states(&h, &id).await.0, "pending");
}

#[tokio::test]
async fn approve_binds_what_was_shown() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, drafts) = requested(&h, &token, &[t, t + 60]).await;
    let v = show(&h, &id).await;
    let shown = shown_of(&v);
    // The agent edits a draft after the operator looked at it.
    h.ok(
        &token,
        "update_draft",
        json!({"account":"info","draft_id":drafts[1],"expected_revision":shown[1].revision,"changes":{"body_text":"other"}}),
    )
    .await;
    let e = approve(&h, &id, shown.clone(), None, dove::admin::Late::Skip).await.unwrap_err();
    assert!(e.contains("changed since it was shown"), "{e}");
    assert_eq!(states(&h, &id).await, ("pending".into(), vec![st("pending", None), st("pending", None)]));
    // An item that was not shown cannot be approved either.
    let e = approve(&h, &id, shown[..1].to_vec(), None, dove::admin::Late::Skip).await.unwrap_err();
    assert!(e.contains("not shown"), "{e}");
    // Shown again, the new revision is approved and bound.
    let v = show(&h, &id).await;
    assert_eq!(v["items"][1]["changed_since_request"], true);
    let r = approve(&h, &id, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap();
    assert_eq!(r["status"], "approved");
    assert_eq!(states(&h, &id).await, ("approved".into(), vec![st("scheduled", None), st("scheduled", None)]));
    let bound: Vec<Option<String>> = {
        let id = id.clone();
        h.app()
            .store
            .call(move |c| {
                let mut s = c.prepare("SELECT approved_rev FROM request_items WHERE request_id = ?1 ORDER BY idx")?;
                Ok(s.query_map([id], |r| r.get(0))?.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap()
    };
    assert_eq!(bound, shown_of(&v).into_iter().map(|s| Some(s.revision)).collect::<Vec<_>>());
    // A person edits a draft after the operator looked at it: only the fresh read at approval sees it.
    let (id2, drafts2) = requested(&h, &token, &[t]).await;
    let v2 = show(&h, &id2).await;
    let raw = String::from_utf8(h.google.draft_raw(MB, &drafts2[0]).unwrap()).unwrap();
    h.google.replace_draft_externally(MB, &drafts2[0], raw.replace("Dear customer", "Dear friend").as_bytes());
    let e = approve(&h, &id2, shown_of(&v2), None, dove::admin::Late::Skip).await.unwrap_err();
    assert!(e.contains("changed since it was shown"), "{e}");
    assert_eq!(states(&h, &id2).await.0, "pending");
    // Decided requests cannot be approved or denied again.
    assert!(approve(&h, &id, shown_of(&v), None, dove::admin::Late::Skip).await.is_err());
    assert!(h.admin(AdminRequest::RequestsDeny { id: id.clone() }).await.is_err());
    // The agent sees the decision.
    let listed = h.ok(&token, "list_requests", json!({"status":"approved"})).await;
    assert_eq!(listed["requests"].as_array().unwrap().len(), 1);
    assert_eq!(listed["requests"][0]["request_id"], id.as_str());
    assert_eq!(listed["requests"][0]["items"][0]["state"], "scheduled");
}

#[tokio::test]
async fn approve_selected_items_and_late_choice() {
    let (h, token) = setup().await;
    let now = util::now_unix();
    let (id, _) = requested(&h, &token, &[now + 3600, now + 3600, now + 7200]).await;
    set_send_at(&h, &id, 1, now - 60).await;
    let v = show(&h, &id).await;
    assert_eq!(v["items"][1]["late"], true);
    approve(&h, &id, shown_of(&v), Some(vec![0, 1]), dove::admin::Late::Skip).await.unwrap();
    assert_eq!(
        states(&h, &id).await,
        (
            "approved".into(),
            vec![st("scheduled", None), st("skipped", Some("late")), st("denied", Some("not_approved"))]
        )
    );
    // Late::Send schedules a passed item for now.
    let (id2, _) = requested(&h, &token, &[now + 3600]).await;
    set_send_at(&h, &id2, 0, now - 600).await;
    let v = show(&h, &id2).await;
    approve(&h, &id2, shown_of(&v), None, dove::admin::Late::Send).await.unwrap();
    assert_eq!(states(&h, &id2).await.1, vec![st("scheduled", None)]);
    let id3 = id2.clone();
    let send_at: i64 = h
        .app()
        .store
        .call(move |c| Ok(c.query_row("SELECT send_at FROM request_items WHERE request_id = ?1", [id3], |r| r.get(0))?))
        .await
        .unwrap();
    assert!(send_at >= now, "scheduled for now, not for the passed time");
    // Only skipped items: the request is done at once.
    let (id4, _) = requested(&h, &token, &[now + 3600]).await;
    set_send_at(&h, &id4, 0, now - 600).await;
    let v = show(&h, &id4).await;
    approve(&h, &id4, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap();
    assert_eq!(states(&h, &id4).await, ("done".into(), vec![st("skipped", Some("late"))]));
    // Deny and cancel by the operator.
    let (id5, _) = requested(&h, &token, &[now + 3600, now + 3600]).await;
    h.admin(AdminRequest::RequestsDeny { id: id5.clone() }).await.unwrap();
    assert_eq!(
        states(&h, &id5).await,
        ("denied".into(), vec![st("denied", Some("denied")), st("denied", Some("denied"))])
    );
    let (id6, _) = requested(&h, &token, &[now + 3600, now + 3600]).await;
    let v = show(&h, &id6).await;
    approve(&h, &id6, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap();
    h.admin(AdminRequest::RequestsCancel { id: id6.clone(), items: Some(vec![1]) }).await.unwrap();
    assert_eq!(states(&h, &id6).await.1, vec![st("scheduled", None), st("cancelled", Some("cancelled_by_operator"))]);
    h.admin(AdminRequest::RequestsCancel { id: id6.clone(), items: None }).await.unwrap();
    assert_eq!(states(&h, &id6).await.0, "done");
    let list = h.admin(AdminRequest::RequestsList { status: Some("done".into()) }).await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn daily_cap_refuses_the_approval() {
    let (h, token) = setup_with(|c| c.limits.scheduled_sends_per_day = 2).await;
    // Noon tomorrow (UTC), so all items share one UTC day.
    let day = (util::now_unix() / DAY + 1) * DAY + 12 * 3600;
    let (id, _) = requested(&h, &token, &[day, day + 60, day + 120]).await;
    let v = show(&h, &id).await;
    let e = approve(&h, &id, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap_err();
    assert!(e.contains("scheduled_sends_per_day"), "{e}");
    assert_eq!(states(&h, &id).await.0, "pending");
    approve(&h, &id, shown_of(&v), Some(vec![0, 1]), dove::admin::Late::Skip).await.unwrap();
    // The day is full; another day is not.
    let (id2, _) = requested(&h, &token, &[day + 600]).await;
    let v = show(&h, &id2).await;
    assert!(approve(&h, &id2, shown_of(&v), None, dove::admin::Late::Skip).await.is_err());
    let (id3, _) = requested(&h, &token, &[day + DAY]).await;
    let v = show(&h, &id3).await;
    approve(&h, &id3, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap();
}

// ------------------------------------------------------------------ the worker

use dove::requests::worker::{TickReport, tick};
use support::fake_google::Fault;

/// A request for one draft per time in `times`, shown and approved as a whole.
async fn approved(h: &Harness, token: &str, times: &[i64]) -> (String, Vec<String>) {
    let (id, drafts) = requested(h, token, times).await;
    let v = show(h, &id).await;
    approve(h, &id, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap();
    (id, drafts)
}

async fn run(h: &Harness, now: i64) -> TickReport {
    tick(h.app(), now).await.unwrap()
}

fn report(sent: usize, failed: usize, skipped: usize, missed: usize, unknown: usize, deferred: usize) -> TickReport {
    TickReport { sent, failed, skipped, missed, unknown, expired: 0, deferred }
}

async fn send_items_audit(h: &Harness) -> Vec<(String, String, String)> {
    h.app()
        .store
        .call(|c| {
            let mut st = c.prepare(
                "SELECT actor, object_ids, result_code FROM audit WHERE tool_or_action = 'request.send_item' ORDER BY seq",
            )?;
            Ok(st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?)
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn approved_items_are_sent_at_their_time() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, drafts) = approved(&h, &token, &[t, t + 600]).await;
    assert_eq!(run(&h, t - 1).await, TickReport::default());
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
    assert_eq!(run(&h, t).await, report(1, 0, 0, 0, 0, 0));
    assert_eq!(h.google.sent_messages(MB).len(), 1);
    assert_eq!(states(&h, &id).await, ("approved".into(), vec![st("sent", None), st("scheduled", None)]));
    assert_eq!(run(&h, t + 599).await, TickReport::default());
    assert_eq!(run(&h, t + 600).await, report(1, 0, 0, 0, 0, 0));
    assert_eq!(states(&h, &id).await, ("done".into(), vec![st("sent", None), st("sent", None)]));
    // Nothing is sent twice.
    assert_eq!(run(&h, t + 700).await, TickReport::default());
    assert_eq!(h.google.count("POST", "drafts/send"), 2);
    assert_eq!(h.google.sent_messages(MB).len(), 2);
    let listed = h.ok(&token, "list_requests", json!({})).await;
    let item = &listed["requests"][0]["items"][0];
    assert_eq!(item["state"], "sent");
    assert!(item["sent_message_id"].as_str().is_some_and(|s| !s.is_empty()));
    // The drafts are recorded as sent, like send_draft does.
    let (d0, d1) = (drafts[0].clone(), drafts[1].clone());
    let own: Vec<String> = h
        .app()
        .store
        .call(move |c| {
            let mut s = c.prepare("SELECT state FROM own_drafts WHERE draft_id IN (?1, ?2)")?;
            Ok(s.query_map([d0, d1], |r| r.get(0))?.collect::<Result<_, _>>()?)
        })
        .await
        .unwrap();
    assert_eq!(own, vec!["sent", "sent"]);
    h.google.assert_no_violations();
}

#[tokio::test]
async fn approved_items_are_sent_at_their_time_over_smtp() {
    let h = Harness::start().await;
    h.imap_mailbox("info", MB).await;
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read,draft")]).await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t]).await;
    assert_eq!(run(&h, t - 1).await, TickReport::default());
    assert!(h.imap.sent_mails().is_empty());
    assert_eq!(run(&h, t).await, report(1, 0, 0, 0, 0, 0));
    assert_eq!(h.imap.sent_mails().len(), 1);
    assert_eq!(states(&h, &id).await, ("done".into(), vec![st("sent", None)]));
    assert_eq!(run(&h, t + 60).await, TickReport::default());
    assert_eq!(h.imap.sent_mails().len(), 1);
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn approved_revision_is_binding() {
    let (h, token) = setup_with(|c| c.allow_send = true).await;
    let sender = h.token("acme", "sender", vec![g("info", "read,draft,send")]).await;
    let t = util::now_unix() + 3600;
    // Updated by the agent, deleted by the agent, edited by a person, and sent by the agent itself.
    let (id, drafts) = approved(&h, &token, &[t, t, t]).await;
    let (sid, sdrafts) = approved(&h, &sender, &[t]).await;
    let v = show(&h, &id).await;
    let rev = |i: usize| v["items"][i]["revision"].as_str().unwrap().to_string();
    h.ok(
        &token,
        "update_draft",
        json!({"account":"info","draft_id":drafts[0],"expected_revision":rev(0),"changes":{"body_text":"changed"}}),
    )
    .await;
    h.ok(&token, "delete_draft", json!({"account":"info","draft_id":drafts[1]})).await;
    let raw = String::from_utf8(h.google.draft_raw(MB, &drafts[2]).unwrap()).unwrap();
    h.google.replace_draft_externally(MB, &drafts[2], raw.replace("Dear customer", "Dear friend").as_bytes());
    let sv = show(&h, &sid).await;
    h.ok(
        &sender,
        "send_draft",
        json!({"account":"info","draft_id":sdrafts[0],"expected_revision":sv["items"][0]["revision"]}),
    )
    .await;
    assert_eq!(h.google.count("POST", "drafts/send"), 1);
    assert_eq!(run(&h, t).await, report(0, 4, 0, 0, 0, 0));
    assert_eq!(
        states(&h, &id).await,
        (
            "done".into(),
            vec![
                st("failed", Some("draft_changed")),
                st("failed", Some("not_found")),
                st("failed", Some("draft_changed"))
            ]
        )
    );
    assert_eq!(states(&h, &sid).await, ("done".into(), vec![st("failed", Some("not_found"))]));
    assert_eq!(h.google.count("POST", "drafts/send"), 1, "nothing sent by the worker, nothing twice");
}

#[tokio::test]
async fn refused_send_fails_after_three_attempts() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t]).await;
    for _ in 0..3 {
        h.google.fail_next("POST", "drafts/send", Fault::Status(400, json!({"error":{"code":400}})));
    }
    assert_eq!(run(&h, t).await, report(0, 0, 0, 0, 0, 1));
    assert_eq!(states(&h, &id).await.1, vec![st("scheduled", Some("upstream_error"))]);
    assert_eq!(run(&h, t + 299).await, TickReport::default(), "five minutes apart");
    assert_eq!(run(&h, t + 300).await, report(0, 0, 0, 0, 0, 1));
    assert_eq!(run(&h, t + 600).await, report(0, 1, 0, 0, 0, 0));
    assert_eq!(states(&h, &id).await, ("done".into(), vec![st("failed", Some("upstream_error"))]));
    assert_eq!(h.google.count("POST", "drafts/send"), 3);
    assert_eq!(run(&h, t + 900).await, TickReport::default());
    assert!(h.google.sent_messages(MB).is_empty());
}

#[tokio::test]
async fn not_dispatched_is_retried_until_grace() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t, t + 1800]).await;
    let set_status = |s: &'static str| {
        h.app().store.call(move |c| Ok(c.execute("UPDATE accounts SET status = ?1 WHERE alias = 'info'", [s])?))
    };
    // The mailbox needs reauthorization at send time: nothing is dispatched, the item waits.
    set_status("reauth_required").await.unwrap();
    assert_eq!(run(&h, t).await, report(0, 0, 0, 0, 0, 1));
    assert_eq!(run(&h, t + 299).await, TickReport::default(), "retried five minutes later");
    assert_eq!(run(&h, t + 300).await, report(0, 0, 0, 0, 0, 1));
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
    // Back within the grace: sent late, but within it.
    set_status("active").await.unwrap();
    assert_eq!(run(&h, t + 600).await, report(1, 0, 0, 0, 0, 0));
    assert_eq!(h.google.count("POST", "drafts/send"), 1);
    // The second item never gets a working mailbox within its grace: it is missed, never sent.
    set_status("reauth_required").await.unwrap();
    assert_eq!(run(&h, t + 1800).await, report(0, 0, 0, 0, 0, 1));
    set_status("active").await.unwrap();
    assert_eq!(run(&h, t + 1800 + 3601).await, report(0, 0, 0, 1, 0, 0));
    assert_eq!(states(&h, &id).await, ("done".into(), vec![st("sent", None), st("missed", Some("late"))]));
    assert_eq!(h.google.count("POST", "drafts/send"), 1);
}

#[tokio::test]
async fn due_items_are_bounded_and_missed_first() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t; 13]).await;
    // Two items fell due long ago (the server was down), one a minute before the others.
    set_send_at(&h, &id, 0, t - 3601).await;
    set_send_at(&h, &id, 1, t - 7200).await;
    set_send_at(&h, &id, 12, t - 60).await;
    assert_eq!(run(&h, t).await, report(10, 0, 0, 2, 0, 0));
    let (_, items) = states(&h, &id).await;
    assert_eq!(items[..2], [st("missed", Some("late")), st("missed", Some("late"))]);
    assert_eq!(items[12], st("sent", None), "oldest first");
    assert_eq!(items[11], st("scheduled", None));
    assert_eq!(items.iter().filter(|i| i.0 == "sent").count(), 10);
    assert_eq!(h.google.count("POST", "drafts/send"), 10);
    assert_eq!(run(&h, t + 30).await, report(1, 0, 0, 0, 0, 0));
    assert_eq!(states(&h, &id).await.0, "done");
}

#[tokio::test]
async fn unknown_outcome_is_never_retried() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t]).await;
    h.google.fail_next("POST", "drafts/send", Fault::Status(503, json!({"error":{"code":503}})));
    assert_eq!(run(&h, t).await, report(0, 0, 0, 0, 1, 0));
    assert_eq!(states(&h, &id).await, ("done".into(), vec![st("send_unknown", Some("outcome_unknown"))]));
    for later in [t + 300, t + 600, t + 3000] {
        assert_eq!(run(&h, later).await, TickReport::default());
    }
    assert_eq!(h.google.count("POST", "drafts/send"), 1);
}

#[tokio::test]
async fn restart_while_sending() {
    let (mut h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t]).await;
    let rid = id.clone();
    h.app()
        .store
        .call(move |c| Ok(c.execute("UPDATE request_items SET state = 'sending' WHERE request_id = ?1", [rid])?))
        .await
        .unwrap();
    h.restart().await;
    assert_eq!(states(&h, &id).await, ("done".into(), vec![st("send_unknown", Some("restart"))]));
    assert_eq!(run(&h, t).await, TickReport::default());
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
    let audit = send_items_audit(&h).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].2, "send_unknown");
}

#[tokio::test]
async fn revoked_client_lost_grant_and_removed_mailbox_stop_items() {
    let (h, token) = setup().await;
    h.mailbox("ops", "ops@acme.test");
    h.admin(AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "ops".into() }).await.unwrap();
    let t = util::now_unix() + 3600;
    let other = h.token("acme", "other", vec![g("info", "read,draft"), g("ops", "read,draft")]).await;
    let (revoked, _) = approved(&h, &token, &[t]).await;
    let (narrowed, _) = approved(&h, &other, &[t]).await;
    let mut ops_items = Vec::new();
    for _ in 0..1 {
        ops_items.push(draft(&h, &other, "ops").await);
    }
    let (od, orev) = &ops_items[0];
    let ops_req = h
        .ok(
            &other,
            "request_send",
            json!({"account":"ops","items":[{"draft_id":od,"expected_revision":orev,"send_at":at(t)}]}),
        )
        .await["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let v = show(&h, &ops_req).await;
    approve(&h, &ops_req, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap();
    h.admin(AdminRequest::ClientsRevoke { name: "agent".into() }).await.unwrap();
    assert_eq!(states(&h, &revoked).await, ("done".into(), vec![st("cancelled", Some("client_revoked"))]));
    h.admin(AdminRequest::AccountsRemove { alias: "ops".into() }).await.unwrap();
    let gone: i64 = {
        let r = ops_req.clone();
        h.app()
            .store
            .call(move |c| Ok(c.query_row("SELECT count(*) FROM requests WHERE id = ?1", [r], |x| x.get(0))?))
            .await
            .unwrap()
    };
    assert_eq!(gone, 0, "rows of a removed mailbox are deleted with it");
    assert!(audit_text(&h).await.contains(&ops_req), "the cancellation was audited before the rows went");
    // Narrowed to read only after approval: the re-check before the claim fails it.
    h.admin(AdminRequest::ClientsSetGrants { name: "other".into(), grants: vec![g("info", "read")] }).await.unwrap();
    assert_eq!(run(&h, t).await, report(0, 1, 0, 0, 0, 0));
    assert_eq!(states(&h, &narrowed).await, ("done".into(), vec![st("failed", Some("access_lost"))]));
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
}

#[tokio::test]
async fn pending_request_expires() {
    let (h, token) = setup().await;
    let now = util::now_unix();
    let (id, _) = requested(&h, &token, &[now + 3600]).await;
    assert_eq!(run(&h, now + 7 * DAY - 10).await, TickReport::default());
    let r = run(&h, now + 7 * DAY + 10).await;
    assert_eq!(r, TickReport { expired: 1, ..Default::default() });
    assert_eq!(states(&h, &id).await, ("expired".into(), vec![st("cancelled", Some("expired"))]));
    let v = show(&h, &id).await;
    assert!(approve(&h, &id, shown_of(&v), None, dove::admin::Late::Send).await.is_err());
}

#[tokio::test]
async fn scheduled_send_writes_one_audit_row_without_content() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, drafts) = approved(&h, &token, &[t]).await;
    run(&h, t).await;
    let rows = send_items_audit(&h).await;
    assert_eq!(rows.len(), 1);
    let (actor, ids, code) = &rows[0];
    assert_eq!((actor.as_str(), code.as_str()), ("scheduler", "ok"));
    assert!(ids.contains(&id) && ids.contains(&drafts[0]), "{ids}");
    let audit = audit_text(&h).await;
    for needle in ["Offer", "Dear customer", "c@example.org"] {
        assert!(!audit.contains(needle), "{needle} reached the audit log");
    }
}

#[tokio::test]
async fn switched_off_after_approval_sends_nothing() {
    let (mut h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t]).await;
    h.restart_with(|c| c.requests.enabled = false).await;
    assert_eq!(run(&h, t).await, TickReport::default());
    assert_eq!(run(&h, t + 3601).await, report(0, 0, 0, 1, 0, 0));
    assert_eq!(states(&h, &id).await.1, vec![st("missed", Some("late"))]);
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
}

#[tokio::test]
async fn expired_client_sends_nothing() {
    // Expiry, unlike revocation, cancels nothing up front: the re-check before the claim must stop the item.
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t]).await;
    h.app()
        .store
        .call(|c| Ok(c.execute("UPDATE clients SET expires_at = ?1 WHERE name = 'agent'", [util::now_unix() - 1])?))
        .await
        .unwrap();
    assert_eq!(run(&h, t).await, report(0, 1, 0, 0, 0, 0));
    assert_eq!(states(&h, &id).await, ("done".into(), vec![st("failed", Some("client_revoked"))]));
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
}

#[tokio::test]
async fn concurrent_passes_send_once() {
    let (h, token) = setup().await;
    let t = util::now_unix() + 3600;
    let (id, _) = approved(&h, &token, &[t, t, t]).await;
    let (a, b, c) = tokio::join!(run(&h, t), run(&h, t), run(&h, t));
    assert_eq!(a.sent + b.sent + c.sent, 3, "{a:?} {b:?} {c:?}");
    for r in [a, b, c] {
        assert_eq!((r.failed, r.unknown, r.skipped, r.missed, r.deferred), (0, 0, 0, 0, 0), "{r:?}");
    }
    assert_eq!(states(&h, &id).await, ("done".into(), vec![st("sent", None); 3]));
    assert_eq!(h.google.count("POST", "drafts/send"), 3);
    assert_eq!(send_items_audit(&h).await.len(), 3);
}

/// Two items due in one pass: while the first send is in flight, a cancel of the second must win. The due list was
/// read before the cancel and the request stays approved (item 2 is still open), so only the claim's
/// `state = 'scheduled'` condition stops the second send.
#[tokio::test]
async fn cancel_while_an_earlier_item_is_sending() {
    for by_agent in [false, true] {
        let (h, token) = setup().await;
        let t = util::now_unix() + 3600;
        let (id, _) = approved(&h, &token, &[t, t, t + 600]).await;
        if by_agent {
            // The agent cancels the whole request, which would close it once item 0 is recorded (and the claim's
            // request-status check would catch item 1). Item 2, held by another pass, keeps it approved.
            let rid = id.clone();
            h.app()
                .store
                .call(move |c| {
                    Ok(c.execute(
                        "UPDATE request_items SET state = 'sending' WHERE request_id = ?1 AND idx = 2",
                        [rid],
                    )?)
                })
                .await
                .unwrap();
        }
        h.google.fail_next("POST", "drafts/send", Fault::Delay(std::time::Duration::from_millis(1500)));
        let app = h.app().clone();
        let pass = tokio::spawn(async move { tick(&app, t).await.unwrap() });
        let started = std::time::Instant::now();
        while h.google.count("POST", "drafts/send") == 0 {
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "the first send never started");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if by_agent {
            h.ok(&token, "cancel_request", json!({ "request_id": id })).await;
        } else {
            h.admin(AdminRequest::RequestsCancel { id: id.clone(), items: Some(vec![1]) }).await.unwrap();
        }
        assert_eq!(pass.await.unwrap(), report(1, 0, 0, 0, 0, 0), "by_agent={by_agent}");
        let reason = if by_agent { "cancelled_by_client" } else { "cancelled_by_operator" };
        let (_, items) = states(&h, &id).await;
        assert_eq!(items[..2], [st("sent", None), st("cancelled", Some(reason))], "by_agent={by_agent}");
        assert_eq!(h.google.count("POST", "drafts/send"), 1, "exactly one send");
        let (status, items) = states(&h, &id).await;
        assert_eq!((status.as_str(), &items[2].0[..]), ("approved", if by_agent { "sending" } else { "scheduled" }));
    }
}

// ------------------------------------------------------------------ unless_reply

use dove::index::sync::sync_account;
use support::fake_google::MessageSpec;

fn msg(from: &str, labels: &[&str], at_ms: i64) -> MessageSpec {
    MessageSpec {
        from: from.into(),
        to: vec![MB.into()],
        subject: "Offer".into(),
        text: Some("hello there".into()),
        labels: labels.iter().map(|l| l.to_string()).collect(),
        thread_id: Some("thr1".into()),
        internal_date_ms: at_ms,
        ..Default::default()
    }
}

struct Reply {
    h: Harness,
    token: String,
    info: String,
    inbound: String,
}

impl Reply {
    /// `info` is indexed and has bob's mail in `thr1`, two minutes old.
    async fn start() -> Self {
        let h = Harness::start().await;
        let info = h.mailbox("info", MB);
        h.project("acme", &["info"]).await;
        let token = h.token("acme", "agent", vec![g("info", "read,draft")]).await;
        let inbound = h.google.add_message(MB, msg("bob@example.com", &["INBOX"], (util::now_unix() - 120) * 1000));
        h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
        let s = Self { h, token, info, inbound };
        s.sync().await;
        s
    }

    async fn sync(&self) {
        let r = sync_account(self.h.app(), &self.info).await.unwrap();
        assert_eq!((r.stage.as_str(), r.error.as_deref()), ("ready", None), "{r:?}");
    }

    /// `request_send` arguments with `unless_reply` for a new reply draft to bob's mail at `t`.
    async fn reply_args(&self, t: i64) -> Value {
        let inbound = &self.inbound;
        let d = self
            .h
            .ok(
                &self.token,
                "create_draft",
                json!({"account":"info","request_key":uuid::Uuid::new_v4().to_string(),
                       "reply_to_message_id":inbound,"body_text":"Thanks"}),
            )
            .await;
        let mut args = send_args(&[(d["draft_id"].as_str().unwrap(), d["revision"].as_str().unwrap(), t)]);
        args["unless_reply"] = json!(true);
        args
    }

    /// A reply draft requested with `unless_reply` for `t`; returns the request id.
    async fn request(&self, t: i64) -> String {
        let args = self.reply_args(t).await;
        self.h.ok(&self.token, "request_send", args).await["request_id"].as_str().unwrap().to_string()
    }

    async fn approve(&self, id: &str) {
        let v = show(&self.h, id).await;
        approve(&self.h, id, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap();
    }

    async fn set_index_enabled(&self, on: bool) {
        self.h
            .app()
            .store
            .call(move |c| Ok(c.execute("UPDATE accounts SET index_enabled = ?1 WHERE alias = 'info'", [on])?))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn reply_before_send_skips_the_item() {
    let r = Reply::start().await;
    let t = util::now_unix() + 60;
    let id = r.request(t).await;
    r.approve(&id).await;
    // The messages that existed at request time never count, even when synced again.
    assert_eq!(run(&r.h, t - 1).await, TickReport::default());
    r.h.google.add_message(MB, msg("bob@example.com", &["INBOX"], 0));
    r.sync().await;
    assert_eq!(run(&r.h, t).await, report(0, 0, 1, 0, 0, 0));
    assert_eq!(states(&r.h, &id).await, ("done".into(), vec![st("skipped", Some("replied"))]));
    assert_eq!(r.h.google.count("POST", "drafts/send"), 0);
}

#[tokio::test]
async fn own_follow_up_does_not_skip() {
    let r = Reply::start().await;
    let t = util::now_unix() + 60;
    // A message already in the thread at request time never counts, even when its date is after the baseline
    // (sender clock skew): the baseline ids hold it.
    r.h.google.add_message(MB, msg("bob@example.com", &["INBOX"], (util::now_unix() + 30) * 1000));
    r.sync().await;
    let id = r.request(t).await;
    r.approve(&id).await;
    r.h.google.add_message(MB, msg(MB, &["SENT"], 0));
    r.sync().await;
    assert_eq!(run(&r.h, t).await, report(1, 0, 0, 0, 0, 0));
    assert_eq!(states(&r.h, &id).await, ("done".into(), vec![st("sent", None)]));
    assert_eq!(r.h.google.count("POST", "drafts/send"), 1);
}

#[tokio::test]
async fn reply_between_request_and_approval_skips() {
    let r = Reply::start().await;
    let t = util::now_unix() + 60;
    let id = r.request(t).await;
    r.h.google.add_message(MB, msg("carol@example.com", &["INBOX"], 0));
    r.sync().await;
    r.approve(&id).await;
    assert_eq!(run(&r.h, t).await, report(0, 0, 1, 0, 0, 0));
    assert_eq!(states(&r.h, &id).await.1, vec![st("skipped", Some("replied"))]);
    assert_eq!(r.h.google.count("POST", "drafts/send"), 0);
}

#[tokio::test]
async fn stale_index_fails_closed() {
    let r = Reply::start().await;
    let t = util::now_unix() + 60;
    let id = r.request(t).await;
    r.approve(&id).await;
    let aid = r.info.clone();
    r.h.app()
        .index
        .write(move |c| {
            c.execute("UPDATE sync_state SET last_success_at = last_success_at - 3600 WHERE account_id = ?1", [aid])?;
            Ok(())
        })
        .await
        .unwrap();
    r.h.app().index.take_woken();
    assert_eq!(run(&r.h, t).await, report(0, 0, 0, 0, 0, 1));
    assert!(r.h.app().index.take_woken().contains(&r.info), "a sync was asked for");
    assert_eq!(states(&r.h, &id).await.1, vec![st("scheduled", Some("waiting_for_sync"))]);
    assert_eq!(run(&r.h, t + 60).await, report(0, 0, 0, 0, 0, 1), "still waiting, never sent on doubt");
    assert_eq!(run(&r.h, t + 3601).await, report(0, 0, 1, 0, 0, 0));
    assert_eq!(states(&r.h, &id).await, ("done".into(), vec![st("skipped", Some("condition_unknown"))]));
    assert_eq!(r.h.google.count("POST", "drafts/send"), 0);
}

#[tokio::test]
async fn indexing_switched_off_after_approval() {
    // Disabling purges the index; the account flag alone (before the purge ran) must already stop the send, and so
    // must an index without sync state while the flag is on (between enabling and its first state).
    for how in ["flag", "disable", "no_state"] {
        let r = Reply::start().await;
        let t = util::now_unix() + 60;
        let id = r.request(t).await;
        r.approve(&id).await;
        match how {
            "flag" => r.set_index_enabled(false).await,
            "disable" => {
                r.h.admin(AdminRequest::IndexDisable { alias: "info".into() }).await.unwrap();
            }
            _ => {
                let aid = r.info.clone();
                r.h.app()
                    .index
                    .write(move |c| Ok(c.execute("DELETE FROM sync_state WHERE account_id = ?1", [aid]).map(|_| ())?))
                    .await
                    .unwrap();
            }
        }
        assert_eq!(run(&r.h, t).await, report(0, 0, 1, 0, 0, 0), "{how}");
        assert_eq!(states(&r.h, &id).await.1, vec![st("skipped", Some("condition_unknown"))]);
        assert_eq!(r.h.google.count("POST", "drafts/send"), 0);
    }
}

#[tokio::test]
async fn unless_reply_needs_an_indexed_thread() {
    let r = Reply::start().await;
    let t = util::now_unix() + 60;
    let field =
        |v: &Value| (v["code"].as_str().map(str::to_string), v["details"]["field"].as_str().map(str::to_string));
    let want = (Some("invalid_argument".to_string()), Some("unless_reply".to_string()));
    // A new mail (no thread) has nothing to wait for.
    let (d, rev) = draft(&r.h, &r.token, "info").await;
    let mut args = send_args(&[(&d, &rev, t)]);
    args["unless_reply"] = json!(true);
    assert_eq!(field(&error(&r.h, &r.token, "request_send", args).await), want);
    // A reply to a message the index has not seen yet: no baseline can be taken.
    let fresh = r.h.google.add_message(
        MB,
        MessageSpec {
            thread_id: Some("thr2".into()),
            ..msg("dan@example.com", &["INBOX"], (util::now_unix() - 10) * 1000)
        },
    );
    let d =
        r.h.ok(
            &r.token,
            "create_draft",
            json!({"account":"info","request_key":uuid::Uuid::new_v4().to_string(),
                   "reply_to_message_id":fresh,"body_text":"Thanks"}),
        )
        .await;
    let mut args = send_args(&[(d["draft_id"].as_str().unwrap(), d["revision"].as_str().unwrap(), t)]);
    args["unless_reply"] = json!(true);
    assert_eq!(field(&error(&r.h, &r.token, "request_send", args).await), want);
    // Indexing switched off: the account flag alone (before the purge ran) refuses the condition.
    let args = r.reply_args(t).await;
    r.set_index_enabled(false).await;
    assert_eq!(field(&error(&r.h, &r.token, "request_send", args.clone()).await), want);
    r.set_index_enabled(true).await;
    r.h.ok(&r.token, "request_send", args).await;
}

#[tokio::test]
async fn index_enabled_again_waits_for_its_first_sync() {
    // Re-enabled after approval: the new generation is still building and has never completed a sync, so the item
    // waits for it (a partial index cannot prove that nobody answered) and is skipped when the grace runs out.
    let r = Reply::start().await;
    let t = util::now_unix() + 60;
    let id = r.request(t).await;
    r.approve(&id).await;
    r.h.admin(AdminRequest::IndexDisable { alias: "info".into() }).await.unwrap();
    r.h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    assert_eq!(run(&r.h, t).await, report(0, 0, 0, 0, 0, 1));
    assert_eq!(run(&r.h, t + 3601).await, report(0, 0, 1, 0, 0, 0));
    assert_eq!(states(&r.h, &id).await.1, vec![st("skipped", Some("condition_unknown"))]);
    assert_eq!(r.h.google.count("POST", "drafts/send"), 0);
}

/// Rows in the index's retry queue (messages whose fetch failed), and making them due now.
async fn pending_rows(h: &Harness) -> i64 {
    h.app().index.write(|c| Ok(c.query_row("SELECT count(*) FROM pending", [], |r| r.get(0))?)).await.unwrap()
}

async fn retry_now(h: &Harness) {
    h.app().index.write(|c| Ok(c.execute("UPDATE pending SET next_attempt_at = 0", []).map(|_| ())?)).await.unwrap();
}

/// A reply whose fetch failed waits in the index's retry queue while the sync still counts as a success: the index
/// cannot prove that nobody answered, so the item waits for the retry, and is never sent on that doubt.
#[tokio::test]
async fn reply_waiting_for_a_retry_blocks_the_send() {
    for resolves in [true, false] {
        let r = Reply::start().await;
        let t = util::now_unix() + 60;
        let id = r.request(t).await;
        r.approve(&id).await;
        let reply = r.h.google.add_message(MB, msg("bob@example.com", &["INBOX"], 0));
        r.h.google.fail_next("GET", &format!("/messages/{reply}"), Fault::Status(400, json!({"error": {}})));
        r.sync().await;
        assert_eq!(pending_rows(&r.h).await, 1, "the reply waits for a retry");
        assert_eq!(run(&r.h, t).await, report(0, 0, 0, 0, 0, 1), "resolves={resolves}");
        assert_eq!(states(&r.h, &id).await.1, vec![st("scheduled", Some("waiting_for_sync"))]);
        if resolves {
            retry_now(&r.h).await;
            r.sync().await;
            assert_eq!(pending_rows(&r.h).await, 0);
            assert_eq!(run(&r.h, t + 30).await, report(0, 0, 1, 0, 0, 0));
            assert_eq!(states(&r.h, &id).await, ("done".into(), vec![st("skipped", Some("replied"))]));
        } else {
            assert_eq!(run(&r.h, t + 3601).await, report(0, 0, 1, 0, 0, 0));
            assert_eq!(states(&r.h, &id).await, ("done".into(), vec![st("skipped", Some("condition_unknown"))]));
        }
        assert_eq!(r.h.google.count("POST", "drafts/send"), 0);
    }
}

/// A reply the owner already moved to Trash (or that landed in Spam) still answered the thread: the send is skipped.
#[tokio::test]
async fn reply_in_trash_or_spam_skips_the_item() {
    for label in ["TRASH", "SPAM"] {
        let r = Reply::start().await;
        let t = util::now_unix() + 60;
        let id = r.request(t).await;
        r.approve(&id).await;
        r.h.google.add_message(MB, msg("bob@example.com", &[label], 0));
        r.sync().await;
        assert_eq!(run(&r.h, t).await, report(0, 0, 1, 0, 0, 0), "{label}");
        assert_eq!(states(&r.h, &id).await.1, vec![st("skipped", Some("replied"))]);
        assert_eq!(r.h.google.count("POST", "drafts/send"), 0);
    }
}

// ------------------------------------------------------------------ unless_reply over IMAP

use support::fake_imap::Fault as ImapFault;

fn imap_raw(from: &str, subject: &str, msg_id: &str, refs: Option<&str>) -> Vec<u8> {
    let refs = refs.map(|r| format!("In-Reply-To: {r}\r\nReferences: {r}\r\n")).unwrap_or_default();
    format!(
        "From: {from}\r\nTo: {MB}\r\nSubject: {subject}\r\nMessage-ID: {msg_id}\r\n{refs}\
         Date: Thu, 12 Nov 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Hello there.\r\n"
    )
    .into_bytes()
}

/// `info` over IMAP, indexed, with bob's mail `<q@example.org>` in INBOX and an approved `unless_reply` request for a
/// reply to it at `t`.
struct ImapReply {
    h: Harness,
    u: support::harness::FakeImapUser,
    id: String,
    t: i64,
}

impl ImapReply {
    async fn start() -> Self {
        let h = Harness::start().await;
        let u = h.imap_mailbox("info", MB).await;
        h.project("acme", &["info"]).await;
        let token = h.token("acme", "agent", vec![g("info", "read,draft")]).await;
        let now = util::now_unix();
        h.imap.add_message_at(
            &u.user,
            "INBOX",
            &imap_raw("bob@example.com", "Offer", "<q@example.org>", None),
            &[],
            now - 120,
        );
        h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
        let r = Self { h, u, id: String::new(), t: now + 60 };
        r.sync().await;
        let rows = r.h.ok(&token, "search_messages", json!({ "select": ["message_id"] })).await;
        let inbound = rows["rows"][0][0].as_str().unwrap().to_string();
        let d =
            r.h.ok(
                &token,
                "create_draft",
                json!({"account":"info","request_key":uuid::Uuid::new_v4().to_string(),
                       "reply_to_message_id":inbound,"to":["bob@example.com"],"body_text":"Thanks"}),
            )
            .await;
        let mut args = send_args(&[(d["draft_id"].as_str().unwrap(), d["revision"].as_str().unwrap(), r.t)]);
        args["unless_reply"] = json!(true);
        let id = r.h.ok(&token, "request_send", args).await["request_id"].as_str().unwrap().to_string();
        let v = show(&r.h, &id).await;
        approve(&r.h, &id, shown_of(&v), None, dove::admin::Late::Skip).await.unwrap();
        Self { id, ..r }
    }

    async fn sync(&self) {
        let r = dove::index::imap_sync::sync_steps(self.h.app(), &self.u.account_id, usize::MAX).await.unwrap();
        assert_eq!(r.error, None, "{r:?}");
    }

    /// Bob's answer to `<q@example.org>` in `folder`, dated now.
    fn reply(&self, folder: &str) -> u32 {
        let raw = imap_raw("bob@example.com", "Re: Offer", "<q-re@example.org>", Some("<q@example.org>"));
        self.h.imap.add_message_at(&self.u.user, folder, &raw, &[], util::now_unix())
    }
}

#[tokio::test]
async fn imap_reply_waiting_for_a_retry_blocks_the_send() {
    for resolves in [true, false] {
        let r = ImapReply::start().await;
        let uid = r.reply("INBOX");
        r.h.imap.fail_next_containing("UID FETCH", &format!("UID FETCH {uid} (UID BODY.PEEK[])"), ImapFault::Bad);
        r.sync().await;
        assert_eq!(pending_rows(&r.h).await, 1, "the reply waits for a retry");
        assert_eq!(run(&r.h, r.t).await, report(0, 0, 0, 0, 0, 1), "resolves={resolves}");
        assert_eq!(states(&r.h, &r.id).await.1, vec![st("scheduled", Some("waiting_for_sync"))]);
        if resolves {
            retry_now(&r.h).await;
            r.sync().await;
            assert_eq!(pending_rows(&r.h).await, 0);
            assert_eq!(run(&r.h, r.t + 30).await, report(0, 0, 1, 0, 0, 0));
            assert_eq!(states(&r.h, &r.id).await, ("done".into(), vec![st("skipped", Some("replied"))]));
        } else {
            assert_eq!(run(&r.h, r.t + 3601).await, report(0, 0, 1, 0, 0, 0));
            assert_eq!(states(&r.h, &r.id).await, ("done".into(), vec![st("skipped", Some("condition_unknown"))]));
        }
        assert!(r.h.imap.sent_mails().is_empty());
    }
}

#[tokio::test]
async fn imap_reply_in_trash_skips_the_item() {
    let r = ImapReply::start().await;
    // Without a reply the item would go out: the fixture itself does not skip.
    r.sync().await;
    r.reply("Trash");
    r.sync().await;
    assert_eq!(run(&r.h, r.t).await, report(0, 0, 1, 0, 0, 0));
    assert_eq!(states(&r.h, &r.id).await.1, vec![st("skipped", Some("replied"))]);
    assert!(r.h.imap.sent_mails().is_empty());
}

#[tokio::test]
async fn imap_unless_reply_sends_without_a_reply() {
    let r = ImapReply::start().await;
    r.sync().await;
    let rep = run(&r.h, r.t).await;
    assert_eq!(rep, report(1, 0, 0, 0, 0, 0), "{:?}", states(&r.h, &r.id).await);
    assert_eq!(r.h.imap.sent_mails().len(), 1);
}
