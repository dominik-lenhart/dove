//! `create_draft` with `reply_recipients` (PLAN A82): recipients derived from the original (Reply-To or From,
//! "all" adds its To and Cc), the mailbox's own addresses removed, explicit lists merged, for Gmail and IMAP.

mod support;

use dove::admin::AdminRequest;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{Harness, g};

fn key() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Header lines of a raw draft, unfolded, as (name, lowercased value).
fn header(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw).replace("\r\n ", " ").replace("\r\n\t", " ");
    let head = text.split("\r\n\r\n").next().unwrap_or("").to_string();
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with(&format!("{}:", name.to_ascii_lowercase())))
        .map(|l| l[name.len() + 1..].trim().to_ascii_lowercase())
}

/// The bare addresses of a header value, in order.
fn addrs(v: Option<String>) -> Vec<String> {
    let Some(v) = v else { return vec![] };
    v.split(',')
        .map(|p| {
            let p = p.trim();
            match (p.rfind('<'), p.rfind('>')) {
                (Some(a), Some(b)) if a < b => p[a + 1..b].to_string(),
                _ => p.to_string(),
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn raw_mail(from: &str, reply_to: Option<&str>, to: &str, cc: Option<&str>, mid: &str) -> Vec<u8> {
    let mut s = format!("From: {from}\r\nTo: {to}\r\n");
    if let Some(c) = cc {
        s.push_str(&format!("Cc: {c}\r\n"));
    }
    if let Some(r) = reply_to {
        s.push_str(&format!("Reply-To: {r}\r\n"));
    }
    s.push_str(&format!(
        "Subject: Termin\r\nMessage-ID: <{mid}@example.net>\r\nDate: Thu, 01 Jan 2026 10:00:00 +0000\r\n\r\nPasst Dienstag?\r\n"
    ));
    s.into_bytes()
}

// ------------------------------------------------------------------ Gmail

async fn gmail_setup() -> (Harness, String) {
    let h = Harness::start().await;
    h.mailbox("info", "info@acme.test");
    h.google.add_send_as("info@acme.test", "Sales@Acme.test");
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read,draft")]).await;
    (h, token)
}

fn gmail_orig(h: &Harness, raw: Vec<u8>, labels: &[&str]) -> String {
    h.google.add_message(
        "info@acme.test",
        MessageSpec {
            raw: Some(raw),
            internal_date_ms: 1_700_000_000_000,
            labels: labels.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
    )
}

async fn gmail_reply(h: &Harness, token: &str, args: Value) -> (Vec<String>, Vec<String>, Vec<String>) {
    let c = h.ok(token, "create_draft", args).await;
    let raw = h.google.draft_raw("info@acme.test", c["draft_id"].as_str().unwrap()).unwrap();
    (addrs(header(&raw, "To")), addrs(header(&raw, "Cc")), addrs(header(&raw, "Bcc")))
}

#[tokio::test]
async fn gmail_reply_to_sender_and_all() {
    let (h, token) = gmail_setup().await;
    let orig = gmail_orig(
        &h,
        raw_mail(
            "Daniel <daniel@example.net>",
            Some("Team <team@example.net>"),
            "info@acme.test, Eva <eva@example.net>, SALES@acme.test",
            Some("frank@example.net, daniel@example.net"),
            "o1",
        ),
        &["INBOX"],
    );
    // "sender": Reply-To wins over From.
    let base = json!({ "account": "info", "body_text": "Ja.", "reply_to_message_id": orig });
    let mut a = base.clone();
    a["request_key"] = json!(key());
    a["reply_recipients"] = json!("sender");
    assert_eq!(gmail_reply(&h, &token, a).await, (vec!["team@example.net".into()], vec![], vec![]));

    // "all": To and Cc of the original minus own addresses (account and send-as, any case) and duplicates.
    let mut a = base.clone();
    a["request_key"] = json!(key());
    a["reply_recipients"] = json!("all");
    let (to, cc, _) = gmail_reply(&h, &token, a).await;
    assert_eq!(to, vec!["team@example.net"]);
    assert_eq!(cc, vec!["eva@example.net", "frank@example.net", "daniel@example.net"]);

    // Explicit lists are added; an explicit address is not repeated by the derived lists.
    let mut a = base.clone();
    a["request_key"] = json!(key());
    a["reply_recipients"] = json!("all");
    a["to"] = json!(["boss@acme.test"]);
    a["bcc"] = json!(["Eva@example.net"]);
    let (to, cc, bcc) = gmail_reply(&h, &token, a).await;
    assert_eq!(to, vec!["team@example.net", "boss@acme.test"]);
    assert_eq!(cc, vec!["frank@example.net", "daniel@example.net"]);
    assert_eq!(bcc, vec!["eva@example.net"]);
}

#[tokio::test]
async fn gmail_reply_to_own_sent_mail_goes_to_its_recipients() {
    let (h, token) = gmail_setup().await;
    // Sent from a send-as address: "sender" means the original's To.
    let own = gmail_orig(
        &h,
        raw_mail("sales@acme.test", None, "kunde@example.net", Some("info@acme.test, x@example.net"), "o2"),
        &[],
    );
    let a = json!({ "account": "info", "request_key": key(), "body_text": "Nachfrage", "reply_to_message_id": own,
                    "reply_recipients": "sender" });
    assert_eq!(gmail_reply(&h, &token, a).await, (vec!["kunde@example.net".into()], vec![], vec![]));
    // Only the SENT label marks it as own (sender address unknown to Dove).
    let sent = gmail_orig(&h, raw_mail("someone@elsewhere.test", None, "kunde2@example.net", None, "o3"), &["SENT"]);
    let a = json!({ "account": "info", "request_key": key(), "body_text": "Nachfrage", "reply_to_message_id": sent,
                    "reply_recipients": "all" });
    assert_eq!(gmail_reply(&h, &token, a).await, (vec!["kunde2@example.net".into()], vec![], vec![]));
}

#[tokio::test]
async fn reply_recipients_arguments_are_checked() {
    let (h, token) = gmail_setup().await;
    let orig = gmail_orig(&h, raw_mail("a@example.net", None, "info@acme.test", None, "o4"), &["INBOX"]);
    // Without reply_to_message_id it has no meaning.
    let (is_err, v) = h
        .call(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "x", "reply_recipients": "all" }),
        )
        .await;
    assert!(is_err);
    assert_eq!(v["error"]["code"], "invalid_argument");
    assert_eq!(v["error"]["details"]["field"], "reply_recipients");
    let (is_err, v) = h
        .call(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "x",
                                              "reply_to_message_id": orig, "reply_recipients": "everyone" }),
        )
        .await;
    assert!(is_err);
    assert_eq!(v["error"]["details"]["field"], "reply_recipients");
    // The cap counts derived and explicit recipients together.
    let many: Vec<String> = (0..50).map(|i| format!("r{i}@example.net")).collect();
    let (is_err, v) = h
        .call(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "x",
                                              "reply_to_message_id": orig, "reply_recipients": "sender", "to": many }),
        )
        .await;
    assert!(is_err, "{v}");
    assert_eq!(v["error"]["code"], "invalid_argument");
    assert_eq!(v["error"]["details"]["field"], "reply_recipients");
    assert!(h.google.drafts("info@acme.test").is_empty());
    // The request key is bound to the argument: the same key with another mode is a different request.
    let k = key();
    let a = json!({ "account": "info", "request_key": k, "body_text": "x", "reply_to_message_id": orig,
                    "reply_recipients": "sender" });
    h.ok(&token, "create_draft", a.clone()).await;
    let mut b = a.clone();
    b["reply_recipients"] = json!("all");
    assert_eq!(h.err(&token, "create_draft", b).await, "invalid_argument");
    // Without the argument nothing is inferred.
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "x",
                                                 "reply_to_message_id": orig }),
        )
        .await;
    let raw = h.google.draft_raw("info@acme.test", c["draft_id"].as_str().unwrap()).unwrap();
    assert_eq!(addrs(header(&raw, "To")), Vec::<String>::new());
}

// ------------------------------------------------------------------ IMAP

#[tokio::test]
async fn imap_reply_recipients_drop_own_aliases() {
    let h = Harness::start().await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.admin(AdminRequest::AccountsAliasAdd {
        account: "info".into(),
        address: "hallo@example.org".into(),
        name: None,
        envelope: false,
    })
    .await
    .unwrap();
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read,draft")]).await;
    let uid = h.imap.add_message(
        &u.user,
        "INBOX",
        &raw_mail(
            "Daniel <daniel@example.net>",
            None,
            "HALLO@example.org, eva@example.net",
            Some("info@example.org"),
            "i1",
        ),
        &[],
    );
    let inbox = imap_id(&h, &u.account_id, &u.user, "INBOX", uid).await;
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "Ja.",
                                            "reply_to_message_id": inbox, "reply_recipients": "all" }),
        )
        .await;
    let raw = h.imap.message_raw(&u.user, "Drafts", uid_of(c["revision"].as_str().unwrap())).unwrap();
    assert_eq!(addrs(header(&raw, "To")), vec!["daniel@example.net"]);
    assert_eq!(addrs(header(&raw, "Cc")), vec!["eva@example.net"]);

    // A message in Sent (SENT label): "sender" replies to its recipients.
    let sent = h.imap.add_message(
        &u.user,
        "Sent",
        &raw_mail("hallo@example.org", None, "kunde@example.net", None, "i2"),
        &["\\Seen"],
    );
    let sent = imap_id(&h, &u.account_id, &u.user, "Sent", sent).await;
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "Nachfrage",
                                            "reply_to_message_id": sent, "reply_recipients": "sender" }),
        )
        .await;
    let raw = h.imap.message_raw(&u.user, "Drafts", uid_of(c["revision"].as_str().unwrap())).unwrap();
    assert_eq!(addrs(header(&raw, "To")), vec!["kunde@example.net"]);
    assert_eq!(header(&raw, "Cc"), None);
}

fn uid_of(id: &str) -> u32 {
    id.rsplit('-').next().unwrap().parse().unwrap()
}

async fn imap_id(h: &Harness, account_id: &str, user: &str, folder: &str, uid: u32) -> String {
    let (a, n) = (account_id.to_string(), folder.to_string());
    let fid: i64 = h
        .app()
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT folder_id FROM imap_folders WHERE account_id = ?1 AND name = ?2", [a, n], |r| {
                r.get(0)
            })?)
        })
        .await
        .unwrap();
    format!("f{fid}-{}-{uid}", h.imap.uidvalidity(user, folder))
}
