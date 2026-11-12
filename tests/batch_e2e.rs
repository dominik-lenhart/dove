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
