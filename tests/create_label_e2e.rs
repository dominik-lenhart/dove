//! `create_label` (PLAN A82): Gmail `labels.create` and IMAP `CREATE`, gated by `organize`, one unit of the hourly
//! organize budget, an existing name returned with `created: false`, and the new label usable by update_messages and
//! move_messages at once.

mod support;

use serde_json::{Value, json};
use support::fake_google::{Fault, MessageSpec};
use support::fake_imap::{FakeImap, Opts, verb_of};
use support::harness::{FakeImapUser, Harness, g};

const INFO: &str = "info@acme.test";

fn writes(h: &Harness) -> Vec<String> {
    h.google
        .requests()
        .into_iter()
        .filter(|r| r.method != "GET" && r.path.starts_with("/gmail/"))
        .map(|r| format!("{} {}", r.method, r.path.trim_start_matches("/gmail/v1/users/me")))
        .collect()
}

fn creates(h: &Harness) -> Vec<String> {
    h.imap.commands().into_iter().filter(|c| verb_of(c) == "CREATE").collect()
}

async fn refused(h: &Harness, token: &str, args: Value) -> Value {
    let (is_err, v) = h.call(token, "create_label", args.clone()).await;
    assert!(is_err, "{args}: {v}");
    v["error"].clone()
}

// ------------------------------------------------------------------ Gmail

async fn gmail() -> (Harness, String) {
    let h = Harness::start_with(|c| c.limits.client_organize_per_hour = 4).await;
    h.mailbox("info", INFO);
    h.project("acme", &["info"]).await;
    let t = h.token("acme", "agent", vec![g("info", "read,organize")]).await;
    (h, t)
}

#[tokio::test]
async fn gmail_creates_a_label_that_organize_can_use() {
    let (h, t) = gmail().await;
    let a = h.google.add_message(
        INFO,
        MessageSpec {
            from: "kunde@example.net".into(),
            subject: "Hallo".into(),
            labels: vec!["INBOX".into()],
            internal_date_ms: 1_700_000_000_000,
            ..Default::default()
        },
    );
    // Before: the error points at create_label.
    let (is_err, v) =
        h.call(&t, "update_messages", json!({ "account": "info", "ids": [a], "add_labels": ["Kunden/Acme"] })).await;
    assert!(is_err);
    assert!(v["error"]["message"].as_str().unwrap().contains("create_label"), "{v}");

    h.google.clear_requests();
    let c = h.ok(&t, "create_label", json!({ "account": "info", "name": " Kunden/Acme " })).await;
    assert_eq!(c["created"], true);
    assert_eq!(c["label"]["name"], "Kunden/Acme");
    let id = c["label"]["id"].as_str().unwrap().to_string();
    assert_eq!(writes(&h), vec!["POST /labels"]);
    assert_eq!(h.google.label_id(INFO, "Kunden/Acme"), id);

    // Existing (any case): returned, nothing written.
    h.google.clear_requests();
    let again = h.ok(&t, "create_label", json!({ "account": "info", "name": "kunden/acme" })).await;
    assert_eq!((again["created"].clone(), again["label"]["id"].clone()), (json!(false), json!(id)));
    assert!(writes(&h).is_empty());

    // Usable at once.
    h.ok(&t, "update_messages", json!({ "account": "info", "ids": [a], "add_labels": ["Kunden/Acme"] })).await;
    assert!(h.google.labels_of(INFO, &a).unwrap().contains(&id));
    let m = h.ok(&t, "move_messages", json!({ "account": "info", "ids": [a], "to": "Kunden/Acme" })).await;
    assert_eq!(m["succeeded"], 1, "{m}");
    h.google.assert_no_violations();
}

#[tokio::test]
async fn gmail_create_label_is_gated_validated_and_budgeted() {
    let (h, t) = gmail().await;
    // Without organize the tool is not there for this mailbox.
    let reader = h.token("acme", "reader", vec![g("info", "read,draft")]).await;
    let (is_err, v) = h.call(&reader, "create_label", json!({ "account": "info", "name": "X" })).await;
    assert!(is_err);
    assert_ne!(v["error"]["code"], "ok");
    // Names: system labels in any case, empty, too long, control characters.
    h.google.clear_requests();
    for (name, says) in [
        ("inbox", "system label"),
        ("Category_Promotions", "system label"),
        ("Starred", "system label"),
        ("   ", "empty"),
        ("a\nb", "control"),
    ] {
        let e = refused(&h, &t, json!({ "account": "info", "name": name })).await;
        assert_eq!(
            (e["code"].as_str(), e["details"]["field"].as_str()),
            (Some("invalid_argument"), Some("name")),
            "{e}"
        );
        assert!(e["message"].as_str().unwrap().contains(says), "{name:?}: {e}");
    }
    let long = "x".repeat(226);
    assert_eq!(refused(&h, &t, json!({ "account": "info", "name": long })).await["details"]["field"], "name");
    h.ok(&t, "create_label", json!({ "account": "info", "name": "y".repeat(225) })).await;
    // Budget 4 per hour: one used above, three more fit (existing names count too), the fifth is refused.
    for n in ["A", "B", "A"] {
        h.ok(&t, "create_label", json!({ "account": "info", "name": n })).await;
    }
    let e = refused(&h, &t, json!({ "account": "info", "name": "C" })).await;
    assert_eq!((e["code"].as_str(), e["details"]["budget"].as_str()), (Some("rate_limited"), Some("organize")), "{e}");
    h.google.assert_no_violations();
}

#[tokio::test]
async fn gmail_refusal_is_reported_and_refunded_unknown_is_not() {
    let (h, t) = gmail().await;
    // A definitive refusal (4xx, label still missing): the error comes back and the budget unit is given back.
    for _ in 0..5 {
        h.google.fail_next("POST", "/labels", Fault::Status(400, json!({"error": {"code": 400}})));
        let e = refused(&h, &t, json!({ "account": "info", "name": "Neu" })).await;
        assert_ne!(e["code"], "rate_limited", "{e}");
    }
    // An unknown outcome (5xx) keeps the unit: four fit the budget of four, the fifth call is refused before Gmail.
    for _ in 0..4 {
        h.google.fail_next("POST", "/labels", Fault::Status(503, json!({"error": {"code": 503}})));
        assert_eq!(refused(&h, &t, json!({ "account": "info", "name": "Neu" })).await["code"], "outcome_unknown");
    }
    assert_eq!(refused(&h, &t, json!({ "account": "info", "name": "Neu" })).await["code"], "rate_limited");
}

#[tokio::test]
async fn gmail_without_modify_scope_gets_the_organize_error() {
    let (h, t) = gmail().await;
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
    let e = refused(&h, &t, json!({ "account": "info", "name": "Neu" })).await;
    assert_eq!(
        (e["code"].as_str(), e["details"]["reason"].as_str()),
        (Some("account_unavailable"), Some("reauth_required"))
    );
    assert!(h.google.requests().iter().all(|r| !r.path.starts_with("/gmail/")), "{:?}", h.google.requests());
}

// ------------------------------------------------------------------ IMAP

async fn imap(opts: Opts) -> (Harness, FakeImapUser, String) {
    let mut h = Harness::start().await;
    h.imap = FakeImap::start_with(opts).await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.project("p", &["info"]).await;
    let t = h.token("p", "agent", vec![g("info", "read,organize")]).await;
    (h, u, t)
}

fn raw(subject: &str) -> Vec<u8> {
    format!(
        "From: a@example.net\r\nTo: info@example.org\r\nSubject: {subject}\r\nMessage-ID: <{subject}@x>\r\n\r\nHi\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn imap_creates_a_folder_that_move_messages_can_use() {
    let (h, u, t) = imap(Opts::default()).await;
    let uid = h.imap.add_message(&u.user, "INBOX", &raw("m1"), &[]);
    h.imap.clear_commands();
    let c = h.ok(&t, "create_label", json!({ "account": "info", "name": "Kunden/Käse" })).await;
    assert_eq!((c["created"].clone(), c["label"]["name"].clone()), (json!(true), json!("Kunden/Käse")));
    assert_eq!(c["label"]["id"], c["label"]["name"]);
    assert_eq!(creates(&h), vec!["CREATE \"Kunden/K&AOQ-se\""]);
    assert!(h.imap.folder_wire_names(&u.user).contains(&"Kunden/K&AOQ-se".to_string()));
    // Existing (any ASCII case): no second CREATE.
    let again = h.ok(&t, "create_label", json!({ "account": "info", "name": "kunden/Käse" })).await;
    assert_eq!(again["created"], false, "{again}");
    assert_eq!(creates(&h).len(), 1);
    // move_messages knows the folder without a list_labels call in between.
    let id = {
        let (a, n) = (u.account_id.clone(), "INBOX".to_string());
        let fid: i64 = h
            .app()
            .store
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT folder_id FROM imap_folders WHERE account_id = ?1 AND name = ?2",
                    [a, n],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        format!("f{fid}-{}-{uid}", h.imap.uidvalidity(&u.user, "INBOX"))
    };
    let m = h.ok(&t, "move_messages", json!({ "account": "info", "ids": [id], "to": "Kunden/Käse" })).await;
    assert_eq!(m["succeeded"], 1, "{m}");
    assert_eq!(h.imap.uids(&u.user, "Kunden/Käse").len(), 1);
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn imap_uses_the_server_separator_and_refuses_unusable_names() {
    let (h, u, t) = imap(Opts { delimiter: '.', ..Opts::default() }).await;
    h.imap.clear_commands();
    let c = h.ok(&t, "create_label", json!({ "account": "info", "name": "Kunden/Acme" })).await;
    assert_eq!(c["created"], true);
    assert_eq!(creates(&h), vec!["CREATE \"Kunden.Acme\""]);
    assert!(h.imap.folder_wire_names(&u.user).contains(&"Kunden.Acme".to_string()));
    // A level containing the server's separator, empty levels and wildcards: refused, nothing sent.
    for name in ["v1.2", "a//b", "/a", "Projekte/*", "50%"] {
        let e = refused(&h, &t, json!({ "account": "info", "name": name })).await;
        assert_eq!(
            (e["code"].as_str(), e["details"]["field"].as_str()),
            (Some("invalid_argument"), Some("name")),
            "{name}: {e}"
        );
    }
    assert_eq!(creates(&h).len(), 1);
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn gmail_over_imap_refuses_create_label() {
    let mut h = Harness::start().await;
    h.imap = FakeImap::start_with(Opts { gmail: true, qresync: false, ..Opts::default() }).await;
    h.imap.gmail_user("me@gmail.com", "pw-123456");
    h.admin(h.connect_imap_request("me", "me@gmail.com", "pw-123456")).await.expect("connect-imap");
    h.project("p", &["me"]).await;
    let t = h.token("p", "agent", vec![g("me", "read,organize")]).await;
    h.imap.clear_commands();
    let e = refused(&h, &t, json!({ "account": "me", "name": "Neu" })).await;
    assert_eq!(e["code"], "invalid_argument");
    assert!(e["message"].as_str().unwrap().contains("Gmail"), "{e}");
    assert!(creates(&h).is_empty());
}
