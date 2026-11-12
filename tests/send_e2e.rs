//! Optional sending (spec 6.3, AC3): instance gate, send grant, ownership, at-most-once submission.

mod support;

use serde_json::{Value, json};
use support::fake_google::Fault;
use support::harness::{Harness, g};

const MB: &str = "info@acme.test";

async fn setup(sends_per_hour: u32) -> (Harness, String) {
    let h = Harness::start_with(|c| {
        c.allow_send = true;
        c.limits.client_sends_per_hour = sends_per_hour;
    })
    .await;
    h.mailbox("info", MB);
    h.mailbox("billing", "billing@acme.test");
    h.project("acme", &["info", "billing"]).await;
    let sender = h.token("acme", "sender", vec![g("info", "read,draft,send"), g("billing", "read,draft")]).await;
    (h, sender)
}

async fn draft(h: &Harness, token: &str, account: &str) -> (Value, Value) {
    let c = h
        .ok(
            token,
            "create_draft",
            json!({"account":account,"request_key":uuid::Uuid::new_v4().to_string(),"to":["c@example.org"],"subject":"S","body_text":"b"}),
        )
        .await;
    (c["draft_id"].clone(), c["revision"].clone())
}

fn send_args(d: &Value, rev: &Value) -> Value {
    json!({"account":"info","draft_id":d,"expected_revision":rev})
}

#[tokio::test]
async fn send_requires_instance_gate_and_grant() {
    // Instance gate off: a send grant cannot even be issued, and no token sees the tool.
    let h = Harness::start().await;
    h.mailbox("info", MB);
    h.project("acme", &["info"]).await;
    let refused = h
        .admin(dove::admin::AdminRequest::ClientsCreate {
            project: "acme".into(),
            name: "s".into(),
            grants: vec![g("info", "read,draft,send")],
            expires: None,
            allow_ip: vec![],
        })
        .await;
    assert!(refused.is_err(), "{refused:?}");
    let drafter = h.token("acme", "drafter", vec![g("info", "read,draft")]).await;
    assert!(!h.tool_names(&drafter).await.contains(&"send_draft".to_string()));

    // Gate on: only the token with a send grant, and only for that mailbox.
    let (h, sender) = setup(20).await;
    let drafter = h.token("acme", "drafter", vec![g("info", "read,draft")]).await;
    assert!(h.tool_names(&sender).await.contains(&"send_draft".to_string()));
    assert!(!h.tool_names(&drafter).await.contains(&"send_draft".to_string()));
    let (d, rev) = draft(&h, &drafter, "info").await;
    assert_eq!(h.err(&drafter, "send_draft", send_args(&d, &rev)).await, "forbidden");
    let (bd, brev) = draft(&h, &sender, "billing").await;
    assert_eq!(
        h.err(&sender, "send_draft", json!({"account":"billing","draft_id":bd,"expected_revision":brev})).await,
        "forbidden"
    );
    assert!(h.google.sent_messages(MB).is_empty() && h.google.sent_messages("billing@acme.test").is_empty());
}

#[tokio::test]
async fn sends_owned_draft_exactly_once() {
    let (h, sender) = setup(20).await;
    let (d, rev) = draft(&h, &sender, "info").await;
    let r = h.ok(&sender, "send_draft", send_args(&d, &rev)).await;
    assert!(r["sent_message_id"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(h.google.sent_messages(MB).len(), 1);
    // Replays never submit again.
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "not_found");
    assert_eq!(h.google.sent_messages(MB).len(), 1);
    assert_eq!(h.google.count("POST", "drafts/send"), 1);
    h.google.assert_no_violations();
}

#[tokio::test]
async fn refuses_foreign_and_externally_changed_drafts() {
    let (h, sender) = setup(20).await;
    // A draft created by another project's connection on the same mailbox is not ours.
    h.project("other", &["info"]).await;
    let other = h.token("other", "other", vec![g("info", "read,draft")]).await;
    let (od, orev) = draft(&h, &other, "info").await;
    assert_eq!(h.err(&sender, "send_draft", send_args(&od, &orev)).await, "not_found");
    // A human edit in the mail client makes the draft human-owned.
    let (d, rev) = draft(&h, &sender, "info").await;
    let raw = String::from_utf8(h.google.draft_raw(MB, d.as_str().unwrap()).unwrap()).unwrap();
    h.google.replace_draft_externally(MB, d.as_str().unwrap(), raw.replace("\r\n\r\nb", "\r\n\r\nhuman").as_bytes());
    let fresh = h.ok(&sender, "get_draft", json!({"account":"info","draft_id":d})).await;
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "draft_conflict");
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &fresh["revision"])).await, "draft_conflict");
    assert!(h.google.sent_messages(MB).is_empty());
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
}

#[tokio::test]
async fn uncertain_outcomes_block_resubmission_and_definitive_failures_allow_retry() {
    let (h, sender) = setup(20).await;
    // Lost response after Google sent it.
    let (d1, r1) = draft(&h, &sender, "info").await;
    h.google.fail_next("POST", "drafts/send", Fault::DropAfterApply);
    assert_eq!(h.err(&sender, "send_draft", send_args(&d1, &r1)).await, "outcome_unknown");
    assert_eq!(h.err(&sender, "send_draft", send_args(&d1, &r1)).await, "outcome_unknown");
    assert_eq!(h.google.sent_messages(MB).len(), 1);
    // A server error may have been applied: unknown, never retried automatically.
    let (d2, r2) = draft(&h, &sender, "info").await;
    h.google.fail_next("POST", "drafts/send", Fault::Status(503, json!({"error":{"code":503}})));
    assert_eq!(h.err(&sender, "send_draft", send_args(&d2, &r2)).await, "outcome_unknown");
    assert_eq!(h.err(&sender, "send_draft", send_args(&d2, &r2)).await, "outcome_unknown");
    assert_eq!(h.google.count("POST", "drafts/send"), 2);
    // A definitive 4xx rejection is safe to retry.
    let (d3, r3) = draft(&h, &sender, "info").await;
    h.google.fail_next("POST", "drafts/send", Fault::Status(400, json!({"error":{"code":400}})));
    assert_eq!(h.err(&sender, "send_draft", send_args(&d3, &r3)).await, "upstream_error");
    h.ok(&sender, "send_draft", send_args(&d3, &r3)).await;
    assert_eq!(h.google.sent_messages(MB).len(), 2);
}

#[tokio::test]
async fn concurrent_sends_submit_once() {
    let (h, sender) = setup(20).await;
    let (d, rev) = draft(&h, &sender, "info").await;
    let results = futures::future::join_all((0..5).map(|_| h.call(&sender, "send_draft", send_args(&d, &rev)))).await;
    assert_eq!(results.iter().filter(|(e, _)| !e).count(), 1, "{results:?}");
    assert_eq!(h.google.sent_messages(MB).len(), 1);
    assert_eq!(h.google.count("POST", "drafts/send"), 1);
}

#[tokio::test]
async fn crash_during_send_is_unknown_after_restart_and_gate_change_applies() {
    let (mut h, sender) = setup(20).await;
    let (d, rev) = draft(&h, &sender, "info").await;
    let did = d.as_str().unwrap().to_string();
    // Simulate a crash after the in-flight state was persisted.
    h.app()
        .store
        .call(move |c| Ok(c.execute("UPDATE own_drafts SET state = 'sending' WHERE draft_id = ?1", [did])?))
        .await
        .unwrap();
    h.restart().await;
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "outcome_unknown");
    assert!(h.google.sent_messages(MB).is_empty());
    // Turning the instance gate off removes sending from existing tokens.
    let (d2, r2) = draft(&h, &sender, "info").await;
    h.restart_with(|c| c.allow_send = false).await;
    assert!(!h.tool_names(&sender).await.contains(&"send_draft".to_string()));
    assert_eq!(h.err(&sender, "send_draft", send_args(&d2, &r2)).await, "forbidden");
    assert!(h.google.sent_messages(MB).is_empty());
}

#[tokio::test]
async fn sends_have_their_own_hourly_budget() {
    let (h, sender) = setup(3).await;
    for _ in 0..3 {
        let (d, rev) = draft(&h, &sender, "info").await;
        h.ok(&sender, "send_draft", send_args(&d, &rev)).await;
    }
    let (d, rev) = draft(&h, &sender, "info").await;
    let (is_err, v) = h.call(&sender, "send_draft", send_args(&d, &rev)).await;
    assert!(is_err);
    assert_eq!(v["error"]["code"], "rate_limited");
    assert!(v["error"]["retry_after_seconds"].as_u64().unwrap() > 60, "hourly budget, not per minute: {v}");
    // Reads are unaffected.
    h.ok(&sender, "list_accounts", json!({})).await;
    assert_eq!(h.google.sent_messages(MB).len(), 3);
}
