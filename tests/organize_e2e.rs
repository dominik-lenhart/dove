//! Grants with presets and the organize tools on Gmail (design 2026-11-13 sections 1 and 2): the authorization
//! matrix, preset expansion, `delete` for Trash/Spam, the exact Gmail write allowlist, old grants without
//! `gmail.modify`, and `delete_draft` for own drafts only.

mod support;

use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{Harness, g};

const INFO: &str = "info@acme.test";

fn msg(subject: &str, labels: &[&str]) -> MessageSpec {
    MessageSpec {
        from: "Kunde <kunde@example.net>".into(),
        to: vec![INFO.into()],
        subject: subject.into(),
        text: Some("Hallo".into()),
        labels: labels.iter().map(|l| l.to_string()).collect(),
        internal_date_ms: 1_700_000_000_000,
        ..Default::default()
    }
}

async fn setup() -> Harness {
    let h = Harness::start().await;
    h.mailbox("info", INFO);
    h.mailbox("other", "other@acme.test");
    h.project("acme", &["info", "other"]).await;
    h
}

async fn stored_actions(h: &Harness, client: &str) -> String {
    let c = client.to_string();
    h.app()
        .store
        .call(move |conn| {
            Ok(conn.query_row(
                "SELECT cm.actions FROM client_mailboxes cm JOIN clients c ON c.id = cm.client_id \
                 JOIN accounts a ON a.id = cm.account_id WHERE c.name = ?1 AND a.alias = 'info'",
                [c],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap()
}

/// Gmail write requests (anything but GET) as `METHOD /path-after-users/me`.
fn writes(h: &Harness) -> Vec<String> {
    h.google
        .requests()
        .into_iter()
        .filter(|r| r.method != "GET" && r.path.starts_with("/gmail/"))
        .map(|r| format!("{} {}", r.method, r.path.trim_start_matches("/gmail/v1/users/me")))
        .collect()
}

fn results(v: &Value) -> Vec<(String, bool, Option<String>)> {
    v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["id"].as_str().unwrap().to_string(),
                r["ok"].as_bool().unwrap(),
                r["error"]["code"].as_str().map(String::from),
            )
        })
        .collect()
}

#[tokio::test]
async fn presets_expand_and_tools_follow_grants() {
    let h = setup().await;
    let reader = h.token("acme", "reader", vec![g("info", "reader")]).await;
    let drafter = h.token("acme", "drafter", vec![g("info", "drafter")]).await;
    let assistant = h.token("acme", "assistant", vec![g("info", "assistant")]).await;
    let full = h.token("acme", "full", vec![g("info", "full")]).await;
    let mixed = h.token("acme", "mixed", vec![g("info", "reader,organize")]).await;
    let legacy = h.token("acme", "legacy", vec![g("info", "read,draft")]).await;
    // Stored expanded: presets never reach the store.
    assert_eq!(stored_actions(&h, "reader").await, "read");
    assert_eq!(stored_actions(&h, "drafter").await, "read,draft");
    assert_eq!(stored_actions(&h, "assistant").await, "read,draft,organize");
    assert_eq!(stored_actions(&h, "full").await, "read,draft,organize,delete");
    assert_eq!(stored_actions(&h, "mixed").await, "read,organize");
    assert_eq!(stored_actions(&h, "legacy").await, "read,draft");

    let has = |names: &[String], t: &str| names.iter().any(|n| n == t);
    let n = h.tool_names(&reader).await;
    assert!(!has(&n, "update_messages") && !has(&n, "move_messages") && !has(&n, "delete_draft"));
    let n = h.tool_names(&drafter).await;
    assert!(has(&n, "delete_draft") && !has(&n, "update_messages"));
    // An existing read,draft token keeps exactly what it had.
    let n = h.tool_names(&legacy).await;
    assert!(has(&n, "delete_draft") && !has(&n, "update_messages") && !has(&n, "move_messages"));
    for t in [&assistant, &full, &mixed] {
        let n = h.tool_names(t).await;
        assert!(has(&n, "update_messages") && has(&n, "move_messages"), "{n:?}");
    }
    let accounts = h.ok(&full, "list_accounts", json!({})).await;
    assert_eq!(accounts["accounts"][0]["actions"], json!(["read", "draft", "organize", "delete"]));

    let id = h.google.add_message(INFO, msg("a", &["INBOX", "UNREAD"]));
    let upd = json!({ "account": "info", "ids": [id], "remove_flags": ["UNREAD"] });
    // Hidden tool called directly, and a mailbox without organize.
    assert_eq!(h.err(&reader, "update_messages", upd.clone()).await, "forbidden");
    assert_eq!(
        h.err(&legacy, "move_messages", json!({ "account": "info", "ids": [id], "to": "archive" })).await,
        "forbidden"
    );
    let other_only = h.token("acme", "split", vec![g("info", "read"), g("other", "assistant")]).await;
    assert_eq!(h.err(&other_only, "update_messages", upd.clone()).await, "forbidden");
    // Unknown and out-of-project mailboxes look the same.
    for acct in ["nowhere", "other"] {
        let args = json!({ "account": acct, "ids": [id], "remove_flags": ["UNREAD"] });
        assert_eq!(h.err(&assistant, "update_messages", args).await, "not_found", "{acct}");
    }
    assert!(writes(&h).is_empty(), "{:?}", writes(&h));
    h.ok(&assistant, "update_messages", upd).await;
    assert_eq!(h.google.labels_of(INFO, &id).unwrap(), vec!["INBOX"]);

    // Unknown words and broken dependencies are refused with a clear message.
    let bad = |actions: &str| g("info", actions);
    for (actions, want) in [("assistent", "unknown action or preset"), ("reader,delete", "delete requires organize")] {
        let e = h
            .admin(dove::admin::AdminRequest::ClientsCreate {
                name: format!("bad-{}", actions.len()),
                project: "acme".into(),
                grants: vec![bad(actions)],
                expires: None,
                allow_ip: vec![],
                redact_secrets: false,
            })
            .await
            .unwrap_err();
        assert!(e.contains(want), "{e}");
    }
    // Send stays out of presets and behind allow_send.
    let e = h
        .admin(dove::admin::AdminRequest::ClientsSetGrants { name: "full".into(), grants: vec![bad("full,send")] })
        .await
        .unwrap_err();
    assert!(e.contains("allow_send"), "{e}");
    h.google.assert_no_violations();
}

#[tokio::test]
async fn update_messages_round_trips_flags_and_labels() {
    let h = setup().await;
    let t = h.token("acme", "agent", vec![g("info", "assistant")]).await;
    let a = h.google.add_message(INFO, msg("a", &["INBOX", "UNREAD", "Projekte"]));
    let b = h.google.add_message(INFO, msg("b", &["INBOX"]));
    let other = h.google.add_message("other@acme.test", msg("c", &["INBOX", "UNREAD"]));
    h.google.label_id(INFO, "Kunden");
    h.google.clear_requests();

    let r = h
        .ok(
            &t,
            "update_messages",
            json!({ "account": "info", "ids": [a, b, other, "../x"], "add_flags": ["STARRED"], "remove_flags": ["UNREAD"],
                    "add_labels": ["Kunden"], "remove_labels": ["Projekte"] }),
        )
        .await;
    // The other mailbox's id and a malformed id are per-id not_found, identical to an unknown id.
    assert_eq!(
        results(&r),
        vec![
            (a.clone(), true, None),
            (b.clone(), true, None),
            (other.clone(), false, Some("not_found".into())),
            ("../x".into(), false, Some("not_found".into())),
        ]
    );
    assert_eq!((r["succeeded"].as_u64(), r["failed"].as_u64()), (Some(2), Some(2)));
    let kunden = h.google.label_id(INFO, "Kunden");
    let mut la = h.google.labels_of(INFO, &a).unwrap();
    la.sort();
    let mut want = vec!["INBOX".to_string(), "STARRED".into(), kunden.clone()];
    want.sort();
    assert_eq!(la, want);
    assert_eq!(h.google.labels_of("other@acme.test", &other).unwrap(), vec!["INBOX", "UNREAD"]);
    // get_message shows the new state.
    let m = h.ok(&t, "get_message", json!({ "account": "info", "message_id": a })).await;
    assert_eq!(
        (m["message"]["is_starred"].as_bool(), m["message"]["is_unread"].as_bool()),
        (Some(true), Some(false)),
        "{m}"
    );
    // Exactly messages.modify per id: no trash, no batch, never DELETE.
    let w = writes(&h);
    assert_eq!(w.len(), 3, "{w:?}");
    assert!(w.iter().all(|x| x.starts_with("POST /messages/") && x.ends_with("/modify")), "{w:?}");

    // Back again.
    h.ok(
        &t,
        "update_messages",
        json!({ "account": "info", "ids": [a], "add_flags": ["UNREAD"], "remove_flags": ["STARRED"] }),
    )
    .await;
    let la = h.google.labels_of(INFO, &a).unwrap();
    assert!(la.contains(&"UNREAD".to_string()) && !la.contains(&"STARRED".to_string()), "{la:?}");

    // Labels are never created, and system labels go through flags or move_messages.
    h.google.clear_requests();
    for (args, what) in [
        (json!({ "account": "info", "ids": [a], "add_labels": ["Neu"] }), "unknown label"),
        (json!({ "account": "info", "ids": [a], "add_labels": ["TRASH"] }), "system label"),
        (json!({ "account": "info", "ids": [a], "add_flags": ["DELETED"] }), "flags"),
        (json!({ "account": "info", "ids": [a], "add_flags": ["STARRED"], "remove_flags": ["STARRED"] }), "same"),
        (json!({ "account": "info", "ids": [] }), "ids"),
        (json!({ "account": "info", "ids": [a] }), "nothing"),
    ] {
        assert_eq!(h.err(&t, "update_messages", args).await, "invalid_argument", "{what}");
    }
    let too_many: Vec<String> = (0..101).map(|i| format!("m{i}")).collect();
    assert_eq!(
        h.err(&t, "update_messages", json!({ "account": "info", "ids": too_many, "add_flags": ["STARRED"] })).await,
        "invalid_argument"
    );
    assert!(writes(&h).is_empty());
    h.google.assert_no_violations();
}

#[tokio::test]
async fn move_needs_delete_for_trash_and_spam() {
    let h = setup().await;
    let assistant = h.token("acme", "assistant", vec![g("info", "assistant")]).await;
    let full = h.token("acme", "full", vec![g("info", "full")]).await;
    let a = h.google.add_message(INFO, msg("a", &["INBOX"]));
    let b = h.google.add_message(INFO, msg("b", &["INBOX"]));
    h.google.label_id(INFO, "Erledigt");
    h.google.clear_requests();

    for to in ["trash", "Trash", "spam", "junk"] {
        let e = h.err(&assistant, "move_messages", json!({ "account": "info", "ids": [a], "to": to })).await;
        assert_eq!(e, "forbidden", "{to}");
    }
    assert!(writes(&h).is_empty(), "{:?}", writes(&h));

    // Archive and a label move are organize.
    h.ok(&assistant, "move_messages", json!({ "account": "info", "ids": [a], "to": "archive" })).await;
    assert!(h.google.labels_of(INFO, &a).unwrap().is_empty());
    let erledigt = h.google.label_id(INFO, "Erledigt");
    let r = h.ok(&assistant, "move_messages", json!({ "account": "info", "ids": [b], "to": "Erledigt" })).await;
    assert_eq!(r["results"][0]["new_id"], json!(b));
    assert_eq!(h.google.labels_of(INFO, &b).unwrap(), vec![erledigt]);

    // Trash with delete: messages.trash, recoverable.
    h.google.clear_requests();
    h.ok(&full, "move_messages", json!({ "account": "info", "ids": [a], "to": "trash" })).await;
    assert_eq!(writes(&h), vec![format!("POST /messages/{a}/trash")]);
    assert!(h.google.labels_of(INFO, &a).unwrap().contains(&"TRASH".to_string()));
    // Out of Trash is organize: untrash, then into the inbox.
    h.google.clear_requests();
    h.ok(&assistant, "move_messages", json!({ "account": "info", "ids": [a], "to": "inbox" })).await;
    assert_eq!(writes(&h), vec![format!("POST /messages/{a}/untrash"), format!("POST /messages/{a}/modify")]);
    assert_eq!(h.google.labels_of(INFO, &a).unwrap(), vec!["INBOX"]);
    // Spam with delete, and out again only with delete too: leaving Spam promotes what Gmail classified as spam.
    h.ok(&full, "move_messages", json!({ "account": "info", "ids": [a], "to": "spam" })).await;
    assert_eq!(h.google.labels_of(INFO, &a).unwrap(), vec!["SPAM"]);
    h.google.clear_requests();
    for to in ["inbox", "Erledigt"] {
        // One message in Spam refuses the whole call before any write, the other id included.
        let e = h.err(&assistant, "move_messages", json!({ "account": "info", "ids": [b, a], "to": to })).await;
        assert_eq!(e, "forbidden", "{to}");
    }
    assert!(writes(&h).is_empty(), "{:?}", writes(&h));
    assert_eq!(h.google.labels_of(INFO, &a).unwrap(), vec!["SPAM"]);
    // Archive leaves it in Spam (removes INBOX only), so organize suffices.
    h.ok(&assistant, "move_messages", json!({ "account": "info", "ids": [a], "to": "archive" })).await;
    assert_eq!(h.google.labels_of(INFO, &a).unwrap(), vec!["SPAM"]);
    h.ok(&full, "move_messages", json!({ "account": "info", "ids": [a], "to": "inbox" })).await;
    assert_eq!(h.google.labels_of(INFO, &a).unwrap(), vec!["INBOX"]);
    assert_eq!(
        h.err(&assistant, "move_messages", json!({ "account": "info", "ids": [a], "to": "Nirgends" })).await,
        "invalid_argument"
    );
    // Nothing outside the allowlist, never a DELETE or batchDelete.
    assert!(h.google.requests().iter().all(|r| r.method != "DELETE" && !r.path.contains("batchDelete")));
    h.google.assert_no_violations();
}

#[tokio::test]
async fn old_grants_without_modify_scope_get_a_clear_error() {
    let h = setup().await;
    let t = h.token("acme", "agent", vec![g("info", "full")]).await;
    let a = h.google.add_message(INFO, msg("a", &["INBOX"]));
    h.app()
        .store
        .call(|c| {
            Ok(c.execute(
                "UPDATE accounts SET granted_scopes = ?1 WHERE alias = 'info'",
                [format!("openid email {} {}", dove::gmail::SCOPE_READONLY, dove::gmail::SCOPE_COMPOSE)],
            )?)
        })
        .await
        .unwrap();
    h.google.clear_requests();
    for (tool, args) in [
        ("update_messages", json!({ "account": "info", "ids": [a], "add_flags": ["STARRED"] })),
        ("move_messages", json!({ "account": "info", "ids": [a], "to": "trash" })),
    ] {
        let (err, v) = h.call(&t, tool, args).await;
        assert!(err);
        assert_eq!(v["error"]["code"], "account_unavailable", "{v}");
        assert_eq!(v["error"]["details"]["reason"], "reauth_required");
        assert!(v["error"]["message"].as_str().unwrap().contains("dove accounts reconnect info"), "{v}");
    }
    // Reads and drafts keep working.
    h.ok(&t, "get_message", json!({ "account": "info", "message_id": a })).await;
    assert!(writes(&h).is_empty());
    // A reconnect that grants modify restores organize.
    h.app()
        .store
        .call(|c| {
            Ok(c.execute(
                "UPDATE accounts SET granted_scopes = ?1 WHERE alias = 'info'",
                [dove::gmail::REQUIRED_SCOPES.join(" ")],
            )?)
        })
        .await
        .unwrap();
    h.ok(&t, "update_messages", json!({ "account": "info", "ids": [a], "add_flags": ["STARRED"] })).await;
}

#[tokio::test]
async fn delete_draft_only_for_own_unchanged_drafts() {
    let h = setup().await;
    let t = h.token("acme", "agent", vec![g("info", "drafter")]).await;
    let create = |subject: &str| {
        json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(), "to": ["x@example.net"],
                "subject": subject, "body_text": "Entwurf" })
    };
    let d = h.ok(&t, "create_draft", create("eins")).await;
    let (draft_id, rev) = (d["draft_id"].as_str().unwrap().to_string(), d["revision"].as_str().unwrap().to_string());
    // A stale expected revision is a conflict; nothing is written.
    h.google.clear_requests();
    let e =
        h.err(&t, "delete_draft", json!({ "account": "info", "draft_id": draft_id, "expected_revision": "zzz" })).await;
    assert_eq!(e, "draft_conflict");
    assert!(writes(&h).is_empty());
    let audits = h.audit_count().await;
    let r =
        h.ok(&t, "delete_draft", json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev })).await;
    assert_eq!(r["deleted"], true);
    assert_eq!(h.audit_count().await, audits + 1);
    // Trash (recoverable), never drafts.delete.
    assert_eq!(writes(&h), vec![format!("POST /messages/{rev}/trash")]);
    assert!(h.google.drafts(INFO).is_empty());
    // Gone from Dove's records: a second delete is not_found.
    assert_eq!(h.err(&t, "delete_draft", json!({ "account": "info", "draft_id": draft_id })).await, "not_found");

    // A draft a person changed is theirs now.
    let d = h.ok(&t, "create_draft", create("zwei")).await;
    let id2 = d["draft_id"].as_str().unwrap().to_string();
    h.google.replace_draft_externally(INFO, &id2, b"From: info@acme.test\r\nSubject: edited\r\n\r\nmine\r\n");
    h.google.clear_requests();
    assert_eq!(h.err(&t, "delete_draft", json!({ "account": "info", "draft_id": id2 })).await, "draft_conflict");
    assert!(writes(&h).is_empty());
    assert_eq!(h.google.drafts(INFO).len(), 1);

    // Another project's token cannot see the draft at all; neither can a reader.
    let d = h.ok(&t, "create_draft", create("drei")).await;
    let id3 = d["draft_id"].as_str().unwrap().to_string();
    h.project("beta", &["info"]).await;
    let foreign = h.token("beta", "foreign", vec![g("info", "drafter")]).await;
    assert_eq!(h.err(&foreign, "delete_draft", json!({ "account": "info", "draft_id": id3 })).await, "not_found");
    let reader = h.token("acme", "reader", vec![g("info", "reader")]).await;
    assert_eq!(h.err(&reader, "delete_draft", json!({ "account": "info", "draft_id": id3 })).await, "forbidden");
    // A human draft that Dove never created is not_found.
    assert_eq!(
        h.err(&t, "delete_draft", json!({ "account": "info", "draft_id": id2.clone() + "x" })).await,
        "not_found"
    );
    assert_eq!(h.google.drafts(INFO).len(), 2);
    h.google.assert_no_violations();
}

#[tokio::test]
async fn one_audit_record_per_call_without_content() {
    let h = setup().await;
    let t = h.token("acme", "agent", vec![g("info", "full")]).await;
    let a = h.google.add_message(INFO, msg("Geheimer Betreff", &["INBOX", "UNREAD"]));
    let before = h.audit_count().await;
    h.ok(&t, "update_messages", json!({ "account": "info", "ids": [a, "nope"], "remove_flags": ["UNREAD"] })).await;
    h.ok(&t, "move_messages", json!({ "account": "info", "ids": [a], "to": "trash" })).await;
    h.err(&t, "move_messages", json!({ "account": "info", "ids": [a], "to": "Nirgends" })).await;
    assert_eq!(h.audit_count().await, before + 3);
    let rows: Vec<String> = h
        .app()
        .store
        .call(move |c| {
            let mut s = c.prepare(
                "SELECT tool_or_action || '|' || COALESCE(account_alias, '') || '|' || object_ids || '|' || result_code || '|' || \
                 COALESCE(result_count, -1) FROM audit WHERE seq > ?1 ORDER BY seq",
            )?;
            let rows = s.query_map([before], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
            Ok(rows)
        })
        .await
        .unwrap();
    assert!(rows[0].starts_with("update_messages|info|") && rows[0].ends_with("|ok|1"), "{rows:?}");
    assert!(rows[1].starts_with("move_messages|info|") && rows[1].ends_with("|ok|1"), "{rows:?}");
    assert!(rows[2].contains("invalid_argument"), "{rows:?}");
    for r in &rows {
        assert!(!r.contains("Geheim") && !r.contains("kunde@") && !r.contains("Nirgends"), "{r}");
    }
}

/// Organize writes spend a per-client hourly budget counted in messages: a call that does not fit is refused whole
/// before any write (and audited), ids that did not change are given back, and other clients are unaffected.
#[tokio::test]
async fn organize_budget_counts_changed_messages_per_client() {
    let h = Harness::start_with(|c| c.limits.client_organize_per_hour = 5).await;
    h.mailbox("info", INFO);
    h.project("acme", &["info"]).await;
    let t = h.token("acme", "agent", vec![g("info", "full")]).await;
    let other = h.token("acme", "other", vec![g("info", "full")]).await;
    let ids: Vec<String> = (0..6).map(|i| h.google.add_message(INFO, msg(&format!("m{i}"), &["INBOX"]))).collect();
    let star = |ids: &[String]| json!({ "account": "info", "ids": ids, "add_flags": ["STARRED"] });

    // More ids than the hourly budget can ever hold: a clear invalid_argument, nothing spent.
    assert_eq!(h.err(&t, "update_messages", star(&ids)).await, "invalid_argument");
    // Two unknown ids fail and are given back; a pre-write refusal (unknown folder) gives everything back.
    let r = h
        .ok(
            &t,
            "update_messages",
            json!({ "account": "info", "ids": [ids[0], "nope1", "nope2"], "add_flags": ["STARRED"] }),
        )
        .await;
    assert_eq!((r["succeeded"].as_i64(), r["failed"].as_i64()), (Some(1), Some(2)));
    let to_nowhere = json!({ "account": "info", "ids": ids[1..5], "to": "Nirgends" });
    assert_eq!(h.err(&t, "move_messages", to_nowhere).await, "invalid_argument");
    // 4 of 5 left: 3 messages fit, then 2 more do not; the refused call writes nothing.
    h.ok(&t, "move_messages", json!({ "account": "info", "ids": ids[1..4], "to": "archive" })).await;
    h.google.clear_requests();
    let (is_err, v) = h.call(&t, "update_messages", star(&ids[4..6])).await;
    assert!(is_err, "{v}");
    assert_eq!(v["error"]["code"], "rate_limited", "{v}");
    assert_eq!(v["error"]["details"]["budget"], "organize", "{v}");
    assert!(v["error"]["retry_after_seconds"].as_u64().is_some_and(|s| s > 0), "{v}");
    assert!(writes(&h).is_empty(), "{:?}", writes(&h));
    // The last unit is still there; afterwards the budget is used up, for both tools.
    h.ok(&t, "update_messages", star(&ids[4..5])).await;
    assert_eq!(h.err(&t, "update_messages", star(&ids[5..6])).await, "rate_limited");
    assert_eq!(
        h.err(&t, "move_messages", json!({ "account": "info", "ids": [ids[5]], "to": "inbox" })).await,
        "rate_limited"
    );
    // Another client has its own budget.
    h.ok(&other, "update_messages", star(&ids[..5])).await;
    // Refusals are audited like any other call.
    let refused: i64 = h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM audit WHERE result_code = 'rate_limited' AND tool_or_action IN ('update_messages', 'move_messages')",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(refused, 3);
}
