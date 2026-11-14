//! `batch_read` over MCP (spec 5.3 "Batched reads", AC21): per-item authorization, input order, coalescing,
//! wire budget and the combined search-row budget.

mod support;

use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{Harness, g};

async fn setup() -> (Harness, String) {
    let h = Harness::start().await;
    h.mailbox("info", "info@acme.test");
    h.mailbox("secret", "secret@acme.test");
    h.project("acme", &["info", "secret"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    (h, token)
}

fn msg(h: &Harness, mailbox: &str, body: &str) -> String {
    h.google.add_message(
        mailbox,
        MessageSpec {
            from: "Sender <s@example.org>".into(),
            to: vec![mailbox.into()],
            subject: "Hello".into(),
            text: Some(body.into()),
            internal_date_ms: 1_700_000_000_000,
            ..Default::default()
        },
    )
}

fn item(id: &str, op: &str, args: Value) -> Value {
    json!({"id": id, "op": op, "args": args})
}

#[tokio::test]
async fn items_are_authorized_individually_and_returned_in_order() {
    let (h, token) = setup().await;
    let a = msg(&h, "info@acme.test", "first");
    let b = msg(&h, "info@acme.test", "second");
    let hidden = msg(&h, "secret@acme.test", "hidden");
    let thread =
        h.ok(&token, "get_message", json!({"account":"info","message_id":a})).await["message"]["thread_id"].clone();
    let before = h.audit_count().await;
    let v = h
        .ok(
            &token,
            "batch_read",
            json!({"items": [
                item("z", "get_message", json!({"account":"info","message_id":b})),
                item("hidden", "get_message", json!({"account":"secret","message_id":hidden})),
                item("a", "get_thread", json!({"account":"info","thread_id":thread})),
                item("bad", "get_message", json!({"account":"info"})),
            ]}),
        )
        .await;
    assert_eq!(h.audit_count().await, before + 1, "one audit record per MCP call");
    let items = v["items"].as_array().unwrap();
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["z", "hidden", "a", "bad"]);
    assert_eq!(items[0]["result"]["message"]["body_text"], "second");
    assert_eq!(items[1]["error"]["code"], "not_found");
    assert_eq!(items[2]["ok"], true, "{}", items[2]);
    assert_eq!(items[3]["error"]["code"], "invalid_argument");
    assert!(h.google.requests().iter().all(|r| r.mailbox.as_deref() != Some("secret@acme.test")));
    // Mutations and nesting are refused for the whole call.
    for op in ["create_draft", "batch_read", "send_draft"] {
        assert_eq!(h.err(&token, "batch_read", json!({"items": [item("x", op, json!({}))]})).await, "invalid_argument");
    }
}

#[tokio::test]
async fn duplicate_reads_are_coalesced() {
    let (h, token) = setup().await;
    let a = msg(&h, "info@acme.test", "body");
    h.ok(&token, "get_message", json!({"account":"info","message_id":a})).await; // warms the access token
    h.google.clear_requests();
    h.ok(&token, "get_message", json!({"account":"info","message_id":a})).await;
    let single = h.google.requests().len();
    h.google.clear_requests();
    let args = json!({"account":"info","message_id":a});
    let v = h
        .ok(
            &token,
            "batch_read",
            json!({"items": [item("1", "get_message", args.clone()), item("2", "get_message", args)]}),
        )
        .await;
    assert_eq!(v["ok_count"], 2);
    assert_eq!(h.google.requests().len(), single, "identical reads hit Gmail once");
}

#[tokio::test]
async fn response_stays_within_wire_budget() {
    let (h, token) = setup().await;
    let body = "x".repeat(19_000);
    let ids: Vec<String> = (0..4).map(|_| msg(&h, "info@acme.test", &body)).collect();
    let items: Vec<Value> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| item(&i.to_string(), "get_message", json!({"account":"info","message_id":id})))
        .collect();
    let v = h.rpc(&token, "tools/call", json!({"name":"batch_read","arguments":{"items": items}})).await;
    let result = &v["result"];
    let wire = serde_json::to_string(&result["structuredContent"]).unwrap().len()
        + result["content"][0]["text"].as_str().unwrap().len();
    assert!(wire <= 64 * 1024 + 512, "wire size {wire}");
    let out = result["structuredContent"]["items"].as_array().unwrap();
    assert_eq!(out.len(), 4, "every item reports a status");
    let ok = out.iter().filter(|i| i["ok"] == true).count();
    assert!(ok >= 1, "at least the first item fits");
    let over: Vec<&Value> = out.iter().filter(|i| i["error"]["code"] == "budget_exceeded").collect();
    assert_eq!(ok + over.len(), 4);
    assert!(!over.is_empty());
    assert!(over[0]["error"]["message"].as_str().unwrap().contains("max_body_chars"));
    // Smaller detail reads fit.
    let small: Vec<Value> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            item(&i.to_string(), "get_message", json!({"account":"info","message_id":id,"max_body_chars":2000}))
        })
        .collect();
    assert_eq!(h.ok(&token, "batch_read", json!({"items": small})).await["ok_count"], 4);
}

#[tokio::test]
async fn search_rows_share_one_budget() {
    let (h, token) = setup().await;
    let v = h
        .ok(
            &token,
            "batch_read",
            json!({"items": [
                item("s1", "search_messages", json!({"accounts":["info"],"limit":60})),
                item("s2", "search_messages", json!({"accounts":["info"],"limit":60})),
                item("s3", "search_messages", json!({"accounts":["info"],"count_only":true})),
            ]}),
        )
        .await;
    let items = v["items"].as_array().unwrap();
    assert_ne!(items[0]["error"]["code"], "budget_exceeded");
    assert_eq!(items[1]["error"]["code"], "budget_exceeded");
    assert!(items[1]["error"]["message"].as_str().unwrap().contains("40 remain"));
    assert_ne!(items[2]["error"]["code"], "budget_exceeded");
}

#[tokio::test]
async fn resumed_cursors_are_budgeted_at_their_stored_limit() {
    let (h, token) = setup().await;
    for i in 0..61 {
        msg(&h, "info@acme.test", &format!("m{i}"));
    }
    h.admin(dove::admin::AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    let aid: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT id FROM accounts WHERE alias='info'", [], |r| r.get(0))?))
        .await
        .unwrap();
    dove::index::sync::sync_account(h.app(), &aid).await.unwrap();
    let first = h.ok(&token, "search_messages", json!({"accounts":["info"],"select":["message_id"],"limit":60})).await;
    let cursor = first["next_cursor"].as_str().expect("a second page").to_string();
    let v = h
        .ok(
            &token,
            "batch_read",
            json!({"items": [
                item("resume", "search_messages", json!({"cursor": cursor})),
                item("more", "search_messages", json!({"accounts":["info"],"limit":60})),
            ]}),
        )
        .await;
    let items = v["items"].as_array().unwrap();
    assert_eq!(items[0]["ok"], true, "{}", items[0]);
    // The cursor holds a 60-row page, so only 40 of the 100 shared rows remain for the next item.
    assert_eq!(items[1]["error"]["code"], "budget_exceeded", "{}", items[1]);
    assert!(items[1]["error"]["message"].as_str().unwrap().contains("40 remain"), "{}", items[1]);
}

#[tokio::test]
async fn search_items_run_and_bad_cursors_or_fields_fail_per_item() {
    let (h, token) = setup().await;
    msg(&h, "info@acme.test", "indexed");
    h.admin(dove::admin::AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    let aid: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT id FROM accounts WHERE alias='info'", [], |r| r.get(0))?))
        .await
        .unwrap();
    dove::index::sync::sync_account(h.app(), &aid).await.unwrap();
    let v = h
        .ok(
            &token,
            "batch_read",
            json!({"items": [
                item("ok", "search_messages", json!({"accounts":["info"],"select":["subject"],"limit":5})),
                item("cursor", "search_messages", json!({"cursor":"c_bogus"})),
                item("field", "search_messages", json!({"where":{"field":"no_such_field","op":"eq","value":"x"}})),
                item("hidden", "search_messages", json!({"accounts":["secret"]})),
            ]}),
        )
        .await;
    let items = v["items"].as_array().unwrap();
    assert_eq!(items[0]["ok"], true, "{}", items[0]);
    assert!(items[0]["result"].to_string().contains("Hello"));
    assert_eq!(items[1]["error"]["code"], "cursor_invalid", "{}", items[1]);
    assert_eq!(items[2]["error"]["code"], "invalid_argument", "{}", items[2]);
    assert_eq!(items[3]["error"]["code"], "not_found", "{}", items[3]);
}

#[tokio::test]
async fn denied_items_count_as_denials_and_audit_names_each_mailbox() {
    let (h, token) = setup().await;
    let a = msg(&h, "info@acme.test", "visible");
    let hidden = msg(&h, "secret@acme.test", "hidden");
    let mut items = vec![item("CALLER-ITEM-ID", "get_message", json!({"account":"info","message_id":a}))];
    items.extend(
        (0..19).map(|i| item(&format!("d{i}"), "get_message", json!({"account":"secret","message_id":hidden}))),
    );
    let v = h.ok(&token, "batch_read", json!({ "items": items })).await;
    assert_eq!(v["error_count"], 19);
    // 19 denied items plus one more denied standalone call reach the burst threshold of 20.
    assert_eq!(h.err(&token, "get_message", json!({"account":"secret","message_id":hidden})).await, "not_found");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let sent = h.app().notifier.sent.lock().unwrap().clone();
    assert_eq!(sent.iter().filter(|m| m.contains("burst of denied calls")).count(), 1, "{sent:?}");
    let rec = h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row(
                "SELECT account_alias, object_ids FROM audit WHERE tool_or_action = 'batch_read' ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?)),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(rec.0.as_deref(), Some("info"));
    assert!(rec.1.contains(&format!("info:{a}")) && rec.1.contains("!not_found"), "{}", rec.1);
    assert!(!rec.1.contains("CALLER-ITEM-ID") && !rec.1.contains(&hidden), "{}", rec.1);
}

fn reply(h: &Harness, thread: &str, body: &str, at: i64) -> String {
    h.google.add_message(
        "info@acme.test",
        MessageSpec {
            from: "s@example.org".into(),
            to: vec!["info@acme.test".into()],
            subject: "Re: Hello".into(),
            text: Some(body.into()),
            thread_id: Some(thread.into()),
            internal_date_ms: at,
            ..Default::default()
        },
    )
}

/// get_thread by message_id reads that message in full first and takes the thread id from it (PLAN A69): no
/// `format=minimal` lookup and no second fetch of the same message.
#[tokio::test]
async fn gmail_thread_by_message_id_saves_the_lookup() {
    let (h, token) = setup().await;
    let a = msg(&h, "info@acme.test", "one");
    let tid = h.ok(&token, "get_message", json!({"account":"info","message_id":a})).await["message"]["thread_id"]
        .as_str()
        .unwrap()
        .to_string();
    let b = reply(&h, &tid, "two", 1_700_000_100_000);
    reply(&h, &tid, "three", 1_700_000_200_000);
    h.google.clear_requests();
    let v = h.ok(&token, "get_thread", json!({"account":"info","message_id":b})).await;
    let bodies: Vec<&str> =
        v["messages"].as_array().unwrap().iter().map(|m| m["body_text"].as_str().unwrap()).collect();
    assert_eq!(bodies, ["one", "two", "three"], "{v}");
    let reqs = h.google.requests();
    let gets: Vec<_> = reqs.iter().filter(|r| r.path.contains("/messages/")).collect();
    assert_eq!(gets.len(), 3, "each member once: {reqs:?}");
    assert!(gets.iter().all(|r| r.query.contains("format=raw")), "{reqs:?}");
    assert_eq!(reqs.len(), 4, "three messages and one thread listing: {reqs:?}");
}

/// Members are fetched in rounds and nothing is fetched once the thread body budget is spent (PLAN A69).
#[tokio::test]
async fn gmail_thread_stops_fetching_when_the_budget_is_spent() {
    let (h, token) = setup().await;
    let body = "y".repeat(20_000);
    let a = msg(&h, "info@acme.test", &body);
    let tid = h.ok(&token, "get_message", json!({"account":"info","message_id":a})).await["message"]["thread_id"]
        .as_str()
        .unwrap()
        .to_string();
    for i in 1..10 {
        reply(&h, &tid, &body, 1_700_000_000_000 + i * 1000);
    }
    h.google.clear_requests();
    let v = h.ok(&token, "get_thread", json!({"account":"info","thread_id":tid})).await;
    // 150,000 characters: seven full bodies and part of the eighth; the last two are left out.
    assert_eq!(v["messages"].as_array().unwrap().len(), 8, "{}", v["remaining_message_ids"]);
    assert_eq!(v["remaining_message_ids"].as_array().unwrap().len(), 2);
    let reqs = h.google.requests();
    assert_eq!(reqs.iter().filter(|r| r.path.contains("/messages/")).count(), 8, "{reqs:?}");
}

/// get_message with message_ids or refs: per-id status in input order, one audit record, the batch response budget,
/// and the single-id shape unchanged (PLAN A69).
#[tokio::test]
async fn get_message_reads_several_ids() {
    let (h, token) = setup().await;
    let a = msg(&h, "info@acme.test", "first");
    let b = msg(&h, "info@acme.test", "second");
    let hidden = msg(&h, "secret@acme.test", "hidden");
    let single = h.ok(&token, "get_message", json!({"account":"info","message_id":a})).await;
    assert_eq!(single["message"]["body_text"], "first", "single id keeps its shape: {single}");
    assert!(single.get("messages").is_none());
    let before = h.audit_count().await;
    let v = h
        .ok(&token, "get_message", json!({"account":"info","message_ids":[b, hidden, a],"select":["body_text"]}))
        .await;
    assert_eq!(h.audit_count().await, before + 1, "one audit record per MCP call");
    let m = v["messages"].as_array().unwrap();
    assert_eq!(m.len(), 3);
    assert_eq!((m[0]["id"].as_str(), &m[0]["message"]["body_text"]), (Some(b.as_str()), &json!("second")));
    assert_eq!(m[1]["error"]["code"], "not_found", "another mailbox's id is unknown here");
    assert_eq!(m[2]["message"]["body_text"], "first");
    assert_eq!((v["ok_count"].as_u64(), v["error_count"].as_u64()), (Some(2), Some(1)));
    assert_eq!(v["untrusted_content_notice"], dove::tools::UNTRUSTED_NOTICE);
    // refs work across mailboxes, each authorized on its own.
    let refs: Vec<Value> = single["message"]["ref"].as_str().map(|r| json!(r)).into_iter().collect();
    let v = h.ok(&token, "get_message", json!({"refs": refs})).await;
    assert_eq!(v["messages"][0]["message"]["body_text"], "first", "{v}");
    for bad in [
        json!({"account":"info","message_ids":[]}),
        json!({"message_ids":[a]}),
        json!({"account":"info","message_ids":[a],"refs":["x"]}),
        json!({"account":"info","message_ids":[a],"message_id":a}),
        json!({"account":"info","message_ids":(0..21).map(|_| a.clone()).collect::<Vec<_>>()}),
    ] {
        assert_eq!(h.err(&token, "get_message", bad.clone()).await, "invalid_argument", "{bad}");
    }
    // The shared 64 KiB budget: large bodies that do not fit report budget_exceeded, the rest still arrive.
    let body = "x".repeat(19_000);
    let big: Vec<String> = (0..4).map(|_| msg(&h, "info@acme.test", &body)).collect();
    let v = h.ok(&token, "get_message", json!({"account":"info","message_ids":big})).await;
    let m = v["messages"].as_array().unwrap();
    assert!(m[0]["ok"] == true && m[3]["error"]["code"] == "budget_exceeded", "{}", v["error_count"]);
}
