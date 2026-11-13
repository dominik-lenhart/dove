//! Secret redaction in overview results (PLAN A60): the operator's per-connection switch and what it changes in
//! `search_messages` (index and live), `digest`, `list_drafts` and `batch_read`, while `get_message` stays intact.

mod support;

use dove::admin::AdminRequest;
use dove::index::sync::sync_account;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{HOST, Harness, g};

const MB: &str = "info@acme.test";
const PASSWORD: &str = "S0mmer!2024x";
const OTP: &str = "482913";

fn mail(subject: &str, body: &str) -> Vec<u8> {
    format!(
        "From: support@shop.test\r\nTo: {MB}\r\nSubject: {subject}\r\nDate: Thu, 12 Nov 2026 10:00:00 +0000\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
    )
    .into_bytes()
}

struct Fx {
    h: Harness,
    /// Redaction on.
    on: String,
    /// Redaction off (the default).
    off: String,
    secret_id: String,
}

async fn setup() -> Fx {
    let h = Harness::start().await;
    h.mailbox("info", MB);
    h.project("acme", &["info"]).await;
    let now = dove::util::now_unix_ms();
    let secret_id = h.google.add_message(
        MB,
        MessageSpec {
            raw: Some(mail(
                &format!("{OTP} ist dein Bestätigungscode"),
                &format!("Hallo, hier die Zugangsdaten.\nBenutzer: kunde42\nPasswort: {PASSWORD}\nViele Grüße"),
            )),
            labels: vec!["INBOX".into()],
            internal_date_ms: now - 60_000,
            ..Default::default()
        },
    );
    h.google.add_message(
        MB,
        MessageSpec {
            raw: Some(mail("Termin am Dienstag", "Treffen um 14:30 in Raum 1205, bitte Passwort nicht vergessen.")),
            labels: vec!["INBOX".into()],
            internal_date_ms: now - 120_000,
            ..Default::default()
        },
    );
    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    let id: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT id FROM accounts WHERE alias = 'info'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(sync_account(h.app(), &id).await.unwrap().stage, "ready");
    let on = h.token("acme", "careful", vec![g("info", "read,draft")]).await;
    let off = h.token("acme", "plain", vec![g("info", "read,draft")]).await;
    h.admin(AdminRequest::ClientsSetRedaction { name: "careful".into(), enabled: true }).await.unwrap();
    Fx { h, on, off, secret_id }
}

/// Structured result and the text content of a successful call.
async fn both(h: &Harness, token: &str, tool: &str, args: Value) -> (Value, String) {
    let v = h.rpc(token, "tools/call", json!({ "name": tool, "arguments": args })).await;
    let r = &v["result"];
    assert_eq!(r["isError"], false, "{tool}: {v}");
    (r["structuredContent"].clone(), r["content"][0]["text"].as_str().unwrap().to_string())
}

fn leaks(s: &str) -> bool {
    s.contains(PASSWORD) || s.contains(OTP)
}

/// Rows of a columnar search result as objects keyed by column.
fn rows(v: &Value) -> Vec<serde_json::Map<String, Value>> {
    let cols: Vec<&str> = v["columns"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| cols.iter().zip(r.as_array().unwrap()).map(|(c, x)| (c.to_string(), x.clone())).collect())
        .collect()
}

#[tokio::test]
async fn overview_results_hide_secrets_and_targeted_reads_do_not() {
    let fx = setup().await;
    let h = &fx.h;
    let args = json!({ "select": ["message_id", "subject", "snippet"], "order_by": [{"field": "received_at", "dir": "desc"}] });

    // Index search: redacted for the careful connection, marked per row, text rendering included.
    let (v, text) = both(h, &fx.on, "search_messages", args.clone()).await;
    assert!(!leaks(&v.to_string()) && !leaks(&text), "{v}");
    let r = rows(&v);
    assert_eq!(r.len(), 2);
    let secret = r.iter().find(|r| r["message_id"] == fx.secret_id.as_str()).unwrap();
    assert_eq!(secret["redacted"], true);
    assert_eq!(secret["subject"], "[redacted] ist dein Bestätigungscode");
    let snippet = secret["snippet"].as_str().unwrap();
    assert!(snippet.contains("Benutzer: kunde42 Passwort: [redacted]"), "{snippet}");
    let other = r.iter().find(|r| r["message_id"] != fx.secret_id.as_str()).unwrap();
    assert_eq!(other["redacted"], false);
    assert_eq!(other["subject"], "Termin am Dienstag", "ordinary mail is untouched");

    // Default connection: unchanged, no extra column.
    let (v, text) = both(h, &fx.off, "search_messages", args.clone()).await;
    assert!(leaks(&v.to_string()) && leaks(&text));
    assert!(!v["columns"].as_array().unwrap().contains(&json!("redacted")));

    // Live Gmail search goes through the same projection.
    let live = json!({ "source": "gmail", "gmail_query": "kunde42", "select": ["message_id", "subject", "snippet"] });
    let (v, text) = both(h, &fx.on, "search_messages", live.clone()).await;
    assert!(!leaks(&v.to_string()) && !leaks(&text), "{v}");
    assert!(rows(&v).iter().any(|r| r["redacted"] == true), "{v}");
    assert!(leaks(&h.ok(&fx.off, "search_messages", live).await.to_string()));

    // Digest.
    let since = dove::util::rfc3339_ms(dove::util::now_unix_ms() - 86_400_000);
    let (v, text) = both(h, &fx.on, "digest", json!({ "since": since })).await;
    assert!(!leaks(&v.to_string()) && !leaks(&text), "{v}");
    let threads = v["threads"].as_array().unwrap();
    assert!(threads.iter().all(|t| t["redacted"].is_boolean()));
    assert!(threads.iter().any(|t| t["redacted"] == true));
    assert!(threads.iter().any(|t| t["redacted"] == false && t["subject"] == "Termin am Dienstag"), "{v}");
    assert!(leaks(&h.ok(&fx.off, "digest", json!({ "since": since })).await.to_string()));

    // Targeted read: full text, even for the careful connection.
    let (v, text) = both(h, &fx.on, "get_message", json!({ "account": "info", "message_id": fx.secret_id })).await;
    assert!(v.to_string().contains(PASSWORD) && text.contains(PASSWORD), "get_message must stay unredacted");

    // batch_read: the search item is redacted, the get_message item is not.
    let (v, _) = both(
        h,
        &fx.on,
        "batch_read",
        json!({ "items": [
            { "id": "s", "op": "search_messages", "args": args },
            { "id": "m", "op": "get_message", "args": { "account": "info", "message_id": fx.secret_id } },
        ]}),
    )
    .await;
    let items = v["items"].as_array().unwrap();
    assert!(!leaks(&items[0]["result"].to_string()), "{}", items[0]);
    assert!(items[1]["result"].to_string().contains(PASSWORD));

    // Audit: one record per call, the count of hidden fields, never the text.
    let audit: Vec<(String, String)> = h
        .app()
        .store
        .call(|c| {
            let mut s = c.prepare("SELECT tool_or_action, object_ids FROM audit ORDER BY seq")?;
            let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .unwrap();
    let all = format!("{audit:?}");
    assert!(!leaks(&all) && !all.contains("[redacted]"), "{all}");
    let marked: Vec<&(String, String)> = audit.iter().filter(|(_, ids)| ids.contains("~redacted=")).collect();
    // search (index), search (live), digest, batch_read.
    assert_eq!(marked.len(), 4, "{all}");
    assert!(marked.iter().any(|(t, ids)| t == "search_messages" && ids.contains("~redacted=2")), "{all}");
    assert!(marked.iter().any(|(t, _)| t == "batch_read"), "{all}");
}

#[tokio::test]
async fn list_drafts_redacts_subjects() {
    let fx = setup().await;
    let h = &fx.h;
    h.ok(
        &fx.off,
        "create_draft",
        json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(), "to": ["c@example.org"],
                "subject": format!("Zugang: PIN: {OTP}"), "body_text": "b" }),
    )
    .await;
    let args = json!({ "account": "info", "own_only": false });
    let (v, text) = both(h, &fx.on, "list_drafts", args.clone()).await;
    assert!(!leaks(&v.to_string()) && !leaks(&text), "{v}");
    assert_eq!(v["drafts"][0]["redacted"], true);
    assert!(leaks(&h.ok(&fx.off, "list_drafts", args).await.to_string()));
}

#[tokio::test]
async fn the_switch_is_operator_owned_visible_and_immediate() {
    let fx = setup().await;
    let h = &fx.h;
    let args = json!({ "select": ["subject"] });
    assert!(!leaks(&h.ok(&fx.on, "search_messages", args.clone()).await.to_string()));

    // Visible in list, show and export.
    let list = h.admin(AdminRequest::ClientsList).await.unwrap();
    let flag =
        |name: &str| list.as_array().unwrap().iter().find(|c| c["client"] == name).unwrap()["redact_secrets"].clone();
    assert_eq!((flag("careful"), flag("plain")), (json!(true), json!(false)));
    assert_eq!(h.admin(AdminRequest::ClientsShow { name: "careful".into() }).await.unwrap()["redact_secrets"], true);
    let export = h.admin(AdminRequest::Export).await.unwrap();
    assert!(
        export["clients"].as_array().unwrap().iter().any(|c| c["client"] == "careful" && c["redact_secrets"] == true)
    );

    // Turning it off applies to the next request, no restart and no new token.
    h.admin(AdminRequest::ClientsSetRedaction { name: "careful".into(), enabled: false }).await.unwrap();
    assert!(leaks(&h.ok(&fx.on, "search_messages", args).await.to_string()));
    assert!(h.admin(AdminRequest::ClientsSetRedaction { name: "nobody".into(), enabled: true }).await.is_err());

    // Created with the switch on.
    let v = h
        .admin(AdminRequest::ClientsCreate {
            name: "born-careful".into(),
            project: "acme".into(),
            grants: vec![g("info", "read")],
            expires: None,
            allow_ip: vec![],
            redact_secrets: true,
        })
        .await
        .unwrap();
    assert_eq!(v["redact_secrets"], true);
    let t = v["token"].as_str().unwrap();
    assert!(!leaks(&h.ok(t, "search_messages", json!({ "select": ["subject"] })).await.to_string()));
}

async fn redeem(h: &Harness, inv: &str) -> String {
    let r = h
        .http
        .post(format!("{}/connect/redeem", h.base))
        .header("host", HOST)
        .json(&json!({ "invitation": inv }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    v["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn invitations_carry_the_switch() {
    let fx = setup().await;
    let h = &fx.h;
    let invite = |name: &str, redact_secrets: bool| AdminRequest::ClientsInvite {
        name: name.into(),
        project: "acme".into(),
        accounts: vec!["info".into()],
        capabilities: "read".into(),
        expires: None,
        allow_ip: vec![],
        redact_secrets,
    };
    let args = json!({ "select": ["subject"] });

    // Set at invitation time.
    let v = h.admin(invite("laptop", true)).await.unwrap();
    assert_eq!(v["redact_secrets"], true);
    let t = redeem(h, v["invitation"].as_str().unwrap()).await;
    assert!(!leaks(&h.ok(&t, "search_messages", args.clone()).await.to_string()));

    // Set on an open invitation before it is redeemed.
    let v = h.admin(invite("tablet", false)).await.unwrap();
    let r = h.admin(AdminRequest::ClientsSetRedaction { name: "tablet".into(), enabled: true }).await.unwrap();
    assert_eq!(r["invitation"], "tablet");
    let t = redeem(h, v["invitation"].as_str().unwrap()).await;
    assert!(!leaks(&h.ok(&t, "search_messages", args.clone()).await.to_string()));

    // Default invitation: off.
    let v = h.admin(invite("phone", false)).await.unwrap();
    let t = redeem(h, v["invitation"].as_str().unwrap()).await;
    assert!(leaks(&h.ok(&t, "search_messages", args).await.to_string()));
}

#[tokio::test]
async fn imap_list_drafts_redacts_subjects() {
    let h = Harness::start().await;
    let _u = h.imap_mailbox("box", "box@imap.test").await;
    h.project("p", &["box"]).await;
    let token = h.token("p", "agent", vec![g("box", "read,draft")]).await;
    h.admin(AdminRequest::ClientsSetRedaction { name: "agent".into(), enabled: true }).await.unwrap();
    h.ok(
        &token,
        "create_draft",
        json!({ "account": "box", "request_key": uuid::Uuid::new_v4().to_string(), "to": ["c@example.org"],
                "subject": format!("Passwort: {PASSWORD}"), "body_text": "b" }),
    )
    .await;
    let (v, text) = both(&h, &token, "list_drafts", json!({ "account": "box" })).await;
    assert!(!leaks(&v.to_string()) && !leaks(&text), "{v}");
    assert_eq!(v["drafts"][0]["subject"], "Passwort: [redacted]");
    assert_eq!(v["drafts"][0]["redacted"], true);
}

/// The thread view (`group_by:"thread"`) renders through the same table step, so its rows are redacted too.
#[tokio::test]
async fn thread_view_rows_are_redacted() {
    let fx = setup().await;
    let h = &fx.h;
    let args = json!({ "select": ["thread_id", "subject", "snippet", "message_count"], "group_by": "thread" });
    let (v, text) = both(h, &fx.on, "search_messages", args.clone()).await;
    assert!(!leaks(&v.to_string()) && !leaks(&text), "{v}");
    let r = rows(&v);
    assert_eq!(r.len(), 2, "{v}");
    assert_eq!(r.iter().filter(|r| r["redacted"] == true).count(), 1, "{v}");
    let (v, _) = both(h, &fx.off, "search_messages", args).await;
    assert!(leaks(&v.to_string()), "the default connection sees the thread rows unchanged");
}
