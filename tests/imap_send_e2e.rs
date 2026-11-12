//! Sending IMAP drafts over SMTP (design "Send"): both gates, the at-most-once state machine, exact submission of the
//! draft's server bytes without `Bcc`, the Sent copy and the removal of exactly Dove's draft afterwards. Never against
//! a real server: the fake records what would have been sent.

mod support;

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use support::fake_imap::{Fault, SmtpFault, encode_utf7, verb_of};
use support::harness::{FakeImapUser, Harness, g};

const MB: &str = "info@example.org";

struct Setup {
    h: Harness,
    u: FakeImapUser,
    sender: String,
    drafter: String,
}

async fn setup() -> Setup {
    let h = Harness::start_with(|c| {
        c.allow_send = true;
        c.limits.client_sends_per_hour = 20;
    })
    .await;
    let u = h.imap_mailbox("info", MB).await;
    h.project("p", &["info"]).await;
    let sender = h.token("p", "sender", vec![g("info", "read,draft,send")]).await;
    let drafter = h.token("p", "drafter", vec![g("info", "read,draft")]).await;
    Setup { h, u, sender, drafter }
}

async fn draft(h: &Harness, token: &str) -> (Value, Value) {
    let c = h
        .ok(
            token,
            "create_draft",
            json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(), "to": ["Ann <ann@example.net>"],
                    "cc": ["cc@example.net"], "bcc": ["hidden@example.net"], "subject": "Angebot", "body_text": "Hallo Ann" }),
        )
        .await;
    (c["draft_id"].clone(), c["revision"].clone())
}

fn send_args(d: &Value, rev: &Value) -> Value {
    json!({ "account": "info", "draft_id": d, "expected_revision": rev })
}

fn uid_of(id: &Value) -> u32 {
    id.as_str().unwrap().rsplit('-').next().unwrap().parse().unwrap()
}

async fn state(h: &Harness, draft_id: &Value) -> (String, Option<String>) {
    let d = draft_id.as_str().unwrap().to_string();
    h.app()
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT state, sent_message_id FROM own_drafts WHERE draft_id = ?1", [d], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?)
        })
        .await
        .unwrap()
}

/// `UID STORE` / `UID EXPUNGE` commands as (verb, uid set); fails on any other deleting or moving verb.
fn deletions(h: &Harness) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for c in h.imap.commands() {
        let verb = verb_of(&c);
        assert!(!matches!(verb.as_str(), "EXPUNGE" | "STORE" | "MOVE" | "COPY" | "UID MOVE" | "UID COPY"), "{c}");
        if verb == "UID STORE" || verb == "UID EXPUNGE" {
            out.push((verb, c.split(' ').nth(2).unwrap_or_default().to_string()));
        }
    }
    out
}

fn data_count(h: &Harness) -> usize {
    h.imap.smtp_commands().iter().filter(|c| c.eq_ignore_ascii_case("DATA")).count()
}

#[tokio::test]
async fn send_requires_both_gates() {
    // Instance gate off: no send grant can be issued and nobody sees the tool.
    let h = Harness::start().await;
    h.imap_mailbox("info", MB).await;
    h.project("p", &["info"]).await;
    let refused = h
        .admin(dove::admin::AdminRequest::ClientsCreate {
            project: "p".into(),
            name: "s".into(),
            grants: vec![g("info", "read,draft,send")],
            expires: None,
            allow_ip: vec![],
        })
        .await;
    assert!(refused.is_err(), "{refused:?}");
    let drafter = h.token("p", "drafter", vec![g("info", "read,draft")]).await;
    assert!(!h.tool_names(&drafter).await.contains(&"send_draft".to_string()));
    let (d, rev) = draft(&h, &drafter).await;
    assert_eq!(h.err(&drafter, "send_draft", send_args(&d, &rev)).await, "forbidden");

    // Gate on: only the token with a send grant may send.
    let Setup { h, u, sender, drafter } = setup().await;
    let smtp_before = h.imap.smtp_connections();
    assert!(h.tool_names(&sender).await.contains(&"send_draft".to_string()));
    assert!(!h.tool_names(&drafter).await.contains(&"send_draft".to_string()));
    let (d, rev) = draft(&h, &drafter).await;
    assert_eq!(h.err(&drafter, "send_draft", send_args(&d, &rev)).await, "forbidden");
    assert_eq!(h.imap.smtp_connections(), smtp_before);
    assert!(h.imap.sent_mails().is_empty());
    assert_eq!(h.imap.uids(&u.user, "Drafts").len(), 1);
    // The sender may send a draft another token of the same project created.
    h.ok(&sender, "send_draft", send_args(&d, &rev)).await;
    assert_eq!(h.imap.sent_mails().len(), 1);
}

#[tokio::test]
async fn send_submits_exact_draft_bytes_without_bcc() {
    let Setup { h, u, sender, .. } = setup().await;
    // The server stores its own variant of the bytes; those are what Dove checked and sends.
    h.imap.rewrite_on_append(true);
    let (d, rev) = draft(&h, &sender).await;
    let stored = h.imap.message_raw(&u.user, "Drafts", uid_of(&rev)).unwrap();
    let r = h.ok(&sender, "send_draft", send_args(&d, &rev)).await;
    assert_eq!(r["draft_id"], d);
    let sent = h.imap.sent_mails();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].from, MB);
    assert_eq!(sent[0].rcpts, vec!["ann@example.net", "cc@example.net", "hidden@example.net"]);
    let text = String::from_utf8(stored).unwrap();
    assert!(text.contains("\r\nBcc: "), "{text}");
    let mut expected: String = text.split_inclusive("\r\n").filter(|l| !l.starts_with("Bcc:")).collect();
    // SMTP framing ends DATA with a line break.
    if !expected.ends_with("\r\n") {
        expected.push_str("\r\n");
    }
    assert_eq!(String::from_utf8(sent[0].data.clone()).unwrap(), expected);
    assert!(expected.starts_with("X-Fake-Stored: yes") && !expected.contains("hidden@"));
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn send_appends_sent_copy_and_removes_draft() {
    let Setup { h, u, sender, .. } = setup().await;
    let other = h.imap.add_message(&u.user, "Drafts", b"From: info@example.org\r\nSubject: human\r\n\r\nx\r\n", &[]);
    let (d, rev) = draft(&h, &sender).await;
    let stored = h.imap.message_raw(&u.user, "Drafts", uid_of(&rev)).unwrap();
    h.imap.clear_commands();
    let r = h.ok(&sender, "send_draft", send_args(&d, &rev)).await;
    // Sent copy: the draft's bytes (Bcc kept for the owner's record), marked read.
    let sent_uids = h.imap.uids(&u.user, "Sent");
    assert_eq!(sent_uids.len(), 1);
    assert_eq!(h.imap.message_raw(&u.user, "Sent", sent_uids[0]).unwrap(), stored);
    assert_eq!(h.imap.flags(&u.user, "Sent", sent_uids[0]).unwrap(), vec!["\\Seen".to_string()]);
    let sent_id = r["sent_message_id"].as_str().unwrap();
    assert!(sent_id.ends_with(&format!("-{}", sent_uids[0])), "{r}");
    let m = h.ok(&sender, "get_message", json!({ "account": "info", "message_id": sent_id })).await;
    assert_eq!(m["message"]["subject"], "Angebot");
    assert_eq!(r["thread_id"], m["message"]["thread_id"]);
    // Exactly Dove's draft UID was removed; the human's draft stays.
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![other]);
    let uid = uid_of(&rev).to_string();
    assert_eq!(deletions(&h), vec![("UID STORE".into(), uid.clone()), ("UID EXPUNGE".into(), uid)]);
    assert_eq!(state(&h, &d).await, ("sent".into(), Some(sent_id.to_string())));
    // A replay never submits again.
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "not_found");
    assert_eq!(h.imap.sent_mails().len(), 1);
    assert_eq!(data_count(&h), 1);
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn save_sent_copy_false_skips_append() {
    let Setup { h, u, sender, .. } = setup().await;
    let aid = u.account_id.clone();
    h.app()
        .store
        .call(move |c| {
            Ok(c.execute(
                "UPDATE accounts SET imap_settings = json_set(imap_settings, '$.save_sent_copy', json('false')) WHERE id = ?1",
                [aid],
            )?)
        })
        .await
        .unwrap();
    let (d, rev) = draft(&h, &sender).await;
    h.imap.clear_commands();
    let r = h.ok(&sender, "send_draft", send_args(&d, &rev)).await;
    assert_eq!(r["sent_message_id"], Value::Null);
    assert!(h.imap.uids(&u.user, "Sent").is_empty());
    assert!(!h.imap.commands().iter().any(|c| verb_of(c) == "APPEND"), "{:?}", h.imap.commands());
    assert!(h.imap.uids(&u.user, "Drafts").is_empty());
    assert_eq!(h.imap.sent_mails().len(), 1);
    assert_eq!(state(&h, &d).await, ("sent".into(), None));
}

#[tokio::test]
async fn drop_after_terminator_is_send_unknown_and_never_retried() {
    let Setup { h, u, sender, .. } = setup().await;
    let (d, rev) = draft(&h, &sender).await;
    h.imap.smtp_fail_next("DATA", SmtpFault::DropAfterTerminator);
    h.imap.clear_commands();
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "outcome_unknown");
    assert_eq!(state(&h, &d).await.0, "send_unknown");
    let smtp = h.imap.smtp_connections();
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "outcome_unknown");
    assert_eq!(h.imap.smtp_connections(), smtp, "no second SMTP connection");
    assert_eq!(h.imap.sent_mails().len(), 1);
    // Nothing is filed or deleted after an unknown outcome; the draft cannot be edited either.
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![uid_of(&rev)]);
    assert!(h.imap.uids(&u.user, "Sent").is_empty());
    assert!(deletions(&h).is_empty());
    let up = json!({ "account": "info", "draft_id": d, "expected_revision": rev, "changes": { "body_text": "x" } });
    assert_eq!(h.err(&sender, "update_draft", up).await, "outcome_unknown");
}

#[tokio::test]
async fn rejected_rcpt_returns_to_active() {
    let Setup { h, u, sender, .. } = setup().await;
    let (d, rev) = draft(&h, &sender).await;
    h.imap.smtp_fail_next("RCPT", SmtpFault::Reply(550));
    let (is_err, v) = h.call(&sender, "send_draft", send_args(&d, &rev)).await;
    assert!(is_err);
    assert_eq!(v["error"]["code"], "upstream_error");
    assert_eq!(v["error"]["details"]["smtp_code"], 550, "{v}");
    assert_eq!(state(&h, &d).await.0, "active");
    assert!(h.imap.sent_mails().is_empty());
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![uid_of(&rev)]);
    // A definitive refusal leaves the draft sendable.
    h.ok(&sender, "send_draft", send_args(&d, &rev)).await;
    assert_eq!(h.imap.sent_mails().len(), 1);
    assert_eq!(data_count(&h), 1);
}

#[tokio::test]
async fn crash_in_sending_becomes_send_unknown() {
    let Setup { mut h, u, sender, .. } = setup().await;
    let (d, rev) = draft(&h, &sender).await;
    let did = d.as_str().unwrap().to_string();
    h.app()
        .store
        .call(move |c| Ok(c.execute("UPDATE own_drafts SET state = 'sending' WHERE draft_id = ?1", [did])?))
        .await
        .unwrap();
    h.restart().await;
    let smtp = h.imap.smtp_connections();
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "outcome_unknown");
    assert_eq!(state(&h, &d).await.0, "send_unknown");
    assert_eq!(h.imap.smtp_connections(), smtp);
    assert!(h.imap.sent_mails().is_empty());
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![uid_of(&rev)]);
}

#[tokio::test]
async fn smtp_auth_failure_marks_reauth() {
    let Setup { h, u, sender, .. } = setup().await;
    let (d, rev) = draft(&h, &sender).await;
    h.imap.smtp_fail_next("AUTH", SmtpFault::Reply(535));
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "account_unavailable");
    let aid = u.account_id.clone();
    let status: String = h
        .app()
        .store
        .call(move |c| Ok(c.query_row("SELECT status FROM accounts WHERE id = ?1", [aid], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(status, "reauth_required");
    let notes = h.app().notifier.sent.lock().unwrap().iter().filter(|m| m.contains("'info'")).count();
    assert_eq!(notes, 1);
    // Nothing was sent; the draft is back to active for after the reconnect.
    assert!(h.imap.sent_mails().is_empty());
    assert_eq!(state(&h, &d).await.0, "active");
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "account_unavailable");
    assert_eq!(h.app().notifier.sent.lock().unwrap().iter().filter(|m| m.contains("'info'")).count(), 1);
}

#[tokio::test]
async fn concurrent_sends_submit_once() {
    let Setup { h, sender, .. } = setup().await;
    let (d, rev) = draft(&h, &sender).await;
    let results = futures::future::join_all((0..5).map(|_| h.call(&sender, "send_draft", send_args(&d, &rev)))).await;
    assert_eq!(results.iter().filter(|(e, _)| !e).count(), 1, "{results:?}");
    assert_eq!(h.imap.sent_mails().len(), 1);
    assert_eq!(data_count(&h), 1);
}

#[tokio::test]
async fn externally_changed_draft_is_not_sent() {
    let Setup { h, u, sender, .. } = setup().await;
    let (d, rev) = draft(&h, &sender).await;
    // Apple Mail re-saves the draft: new UID, the old one expunged.
    let raw = h.imap.message_raw(&u.user, "Drafts", uid_of(&rev)).unwrap();
    let human = h.imap.add_message(&u.user, "Drafts", &raw, &["\\Draft", "\\Seen"]);
    h.imap.expunge_external(&u.user, "Drafts", uid_of(&rev));
    let smtp = h.imap.smtp_connections();
    h.imap.clear_commands();
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "draft_conflict");
    assert_eq!(h.imap.smtp_connections(), smtp);
    assert!(h.imap.sent_mails().is_empty());
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![human]);
    assert!(deletions(&h).is_empty());
    // An APPEND failure of the Sent copy after a send is reported, not retried, and the draft still goes.
    let (d2, rev2) = draft(&h, &sender).await;
    h.imap.fail_next_containing("APPEND", &format!("\"{}\"", encode_utf7("Sent")), Fault::No);
    let r = h.ok(&sender, "send_draft", send_args(&d2, &rev2)).await;
    assert_eq!(r["sent_message_id"], Value::Null);
    assert!(h.imap.uids(&u.user, "Sent").is_empty());
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![human]);
    assert_eq!(state(&h, &d2).await.0, "sent");
    let notes = h.app().notifier.sent.lock().unwrap().clone();
    assert_eq!(notes.iter().filter(|m| m.contains(d2.as_str().unwrap())).count(), 1, "{notes:?}");
}

async fn audit_rows(h: &Harness, tool: &str) -> i64 {
    let t = tool.to_string();
    h.app()
        .store
        .call(move |c| Ok(c.query_row("SELECT count(*) FROM audit WHERE tool_or_action = ?1", [t], |r| r.get(0))?))
        .await
        .unwrap()
}

#[tokio::test]
async fn late_smtp_accept_still_records_files_and_removes_after_the_call_ends() {
    // Budget 8 s, so SMTP must finish by 6 s. It accepts at ~4.6 s; the Sent copy (2.5 s) and the draft's removal
    // (2.5 s) run past the call's deadline and must still happen.
    let Setup { h, u, sender, .. } = setup().await;
    let (d, rev) = draft(&h, &sender).await;
    let stored = h.imap.message_raw(&u.user, "Drafts", uid_of(&rev)).unwrap();
    h.imap.clear_commands();
    h.imap.smtp_fail_next("DATA", SmtpFault::Delay(Duration::from_millis(4500)));
    h.imap.fail_next_containing(
        "APPEND",
        &format!("\"{}\"", encode_utf7("Sent")),
        Fault::Delay(Duration::from_millis(2500)),
    );
    h.imap.fail_next("UID STORE", Fault::Delay(Duration::from_millis(2500)));
    let (is_err, v) = h.call(&sender, "send_draft", send_args(&d, &rev)).await;
    // The mail went out but the call ran out of time: unknown to the agent, never a retryable error.
    assert!(is_err);
    assert_eq!(v["error"]["code"], "outcome_unknown", "{v}");
    assert_eq!(h.imap.sent_mails().len(), 1);
    // The detached send finishes on its own: recorded as sent, Sent copy filed, exactly Dove's draft removed.
    let until = Instant::now() + Duration::from_secs(10);
    while (state(&h, &d).await.1.is_none() || !h.imap.uids(&u.user, "Drafts").is_empty()) && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let sent_uids = h.imap.uids(&u.user, "Sent");
    assert_eq!(sent_uids.len(), 1);
    assert_eq!(h.imap.message_raw(&u.user, "Sent", sent_uids[0]).unwrap(), stored);
    let (st, sent_id) = state(&h, &d).await;
    assert_eq!(st, "sent");
    assert!(sent_id.unwrap().ends_with(&format!("-{}", sent_uids[0])));
    assert!(h.imap.uids(&u.user, "Drafts").is_empty());
    let uid = uid_of(&rev).to_string();
    assert_eq!(deletions(&h), vec![("UID STORE".into(), uid.clone()), ("UID EXPUNGE".into(), uid)]);
    // A retry never submits again, and each call left exactly one audit record.
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "not_found");
    assert_eq!(h.imap.sent_mails().len(), 1);
    assert_eq!(data_count(&h), 1);
    assert_eq!(audit_rows(&h, "send_draft").await, 2);
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn smtp_gets_less_time_than_the_call() {
    // SMTP never answers the final `.`: Dove gives up at its own SMTP deadline, records `send_unknown` and answers
    // before the call's deadline (8 s), not by running into it.
    let Setup { h, u, sender, .. } = setup().await;
    let (d, rev) = draft(&h, &sender).await;
    h.imap.clear_commands();
    h.imap.smtp_fail_next("DATA", SmtpFault::Delay(Duration::from_secs(60)));
    let started = Instant::now();
    let (is_err, v) = h.call(&sender, "send_draft", send_args(&d, &rev)).await;
    let took = started.elapsed();
    assert!(is_err);
    assert_eq!(v["error"]["code"], "outcome_unknown", "{v}");
    assert!(took < Duration::from_millis(7500), "{took:?}");
    assert_eq!(state(&h, &d).await.0, "send_unknown");
    let smtp = h.imap.smtp_connections();
    assert_eq!(h.err(&sender, "send_draft", send_args(&d, &rev)).await, "outcome_unknown");
    assert_eq!(h.imap.smtp_connections(), smtp, "no second SMTP connection");
    assert_eq!(h.imap.sent_mails().len(), 1);
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![uid_of(&rev)]);
    assert!(h.imap.uids(&u.user, "Sent").is_empty());
    assert!(deletions(&h).is_empty());
}
