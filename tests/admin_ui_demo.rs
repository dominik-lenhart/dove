//! A demo server for working on the admin UI in a real browser (not run by default).
//!
//! It starts the test harness (fake Google), enables the UI with the origin from `DOVE_DEMO_ORIGIN`, fills it with a
//! few agents, send requests (waiting, scheduled, denied) and an access request, prints the loopback address and an
//! enrolment link, and keeps serving for `DOVE_DEMO_SECS` seconds (default 1800). Put a TLS front with that origin
//! in front of the address (for example `tailscale serve` on the tailnet name), open the link, and sign in.
//!
//! `DOVE_DEMO_ORIGIN=https://<name>:<port> cargo test --test admin_ui_demo -- --ignored --nocapture`

mod support;

use dove::admin::{AdminRequest, Late, ShownItem};
use dove::util;
use serde_json::{Value, json};
use support::harness::{Harness, g};

async fn draft(h: &Harness, token: &str, account: &str, to: &str, subject: &str, body: &str) -> (String, String) {
    let c = h
        .ok(
            token,
            "create_draft",
            json!({"account": account, "request_key": uuid::Uuid::new_v4().to_string(), "to": [to],
                   "subject": subject, "body_text": body}),
        )
        .await;
    (c["draft_id"].as_str().unwrap().to_string(), c["revision"].as_str().unwrap().to_string())
}

async fn send_request(
    h: &Harness,
    token: &str,
    account: &str,
    drafts: &[(&str, &str, &str)],
    note: Option<&str>,
) -> String {
    let mut items = vec![];
    for (i, (to, subject, body)) in drafts.iter().enumerate() {
        let (d, rev) = draft(h, token, account, to, subject, body).await;
        let at = util::now_unix() + 3600 * (i as i64 + 2);
        items.push(json!({ "draft_id": d, "expected_revision": rev, "send_at": util::rfc3339(at) }));
    }
    let mut args = json!({ "account": account, "items": items });
    if let Some(n) = note {
        args["note"] = json!(n);
    }
    h.ok(token, "request_send", args).await["request_id"].as_str().unwrap().to_string()
}

async fn approve_all(h: &Harness, id: &str) {
    let v: Value = h.admin(AdminRequest::RequestsShow { id: id.into() }).await.unwrap();
    let shown = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|it| ShownItem {
            idx: it["idx"].as_u64().unwrap() as u32,
            revision: it["revision"].as_str().unwrap().to_string(),
        })
        .collect();
    h.admin(AdminRequest::RequestsApprove {
        id: id.into(),
        shown,
        items: None,
        late: Late::default(),
        duration_minutes: None,
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn demo_server() {
    let origin = std::env::var("DOVE_DEMO_ORIGIN").unwrap_or_else(|_| "https://dove-admin.tail1234.ts.net".into());
    let secs: u64 = std::env::var("DOVE_DEMO_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(1800);
    let h = Harness::start_with(|c| {
        c.admin_ui.enabled = true;
        c.admin_ui.origin = Some(origin.clone());
    })
    .await;
    h.mailbox("info", "info@acme.test");
    h.mailbox("billing", "billing@acme.test");
    h.mailbox("dominik", "dominik@acme.test");
    h.project("acme", &["info", "billing", "dominik"]).await;
    let outreach = h.token("acme", "outreach-agent", vec![g("info", "read,draft"), g("dominik", "read,draft")]).await;
    let support = h.token("acme", "support-agent", vec![g("info", "read,draft")]).await;

    send_request(
        &h,
        &outreach,
        "dominik",
        &[
            (
                "anna@example.org",
                "Kurze Rückfrage zum Angebot",
                "Hallo Anna,\n\ndanke für das Gespräch gestern. Passt dir \
              Dienstag 10 Uhr für die Abstimmung?\n\nViele Grüße\nDominik",
            ),
            (
                "ben@example.org",
                "Unterlagen für die Wohnung",
                "Hallo Ben,\n\nanbei wie besprochen die Unterlagen. \
              Melde dich gern, wenn etwas fehlt.\n\nBeste Grüße\nDominik",
            ),
            (
                "clara@example.org",
                "Termin nächste Woche",
                "Hi Clara,\n\nwollen wir den Termin auf Donnerstag \
              verschieben?\n\nLG Dominik",
            ),
        ],
        Some("Follow-ups to the three leads from Friday, spread over Tuesday morning as you asked."),
    )
    .await;
    send_request(
        &h,
        &support,
        "info",
        &[(
            "kunde@example.org",
            "Re: Rechnung 2026-114",
            "Guten Tag,\n\ndie korrigierte Rechnung ist unterwegs.\n\nFreundliche Grüße",
        )],
        None,
    )
    .await;
    let scheduled = send_request(
        &h,
        &support,
        "info",
        &[
            ("team@example.org", "Wochenrückblick", "Hallo zusammen,\n\nhier der Rückblick der Woche ..."),
            ("partner@example.org", "Monatsbericht November", "Hallo,\n\nanbei der Bericht für November."),
        ],
        None,
    )
    .await;
    approve_all(&h, &scheduled).await;
    let denied =
        send_request(&h, &outreach, "info", &[("press@example.org", "Pressemitteilung", "Entwurf ...")], None).await;
    h.admin(AdminRequest::RequestsDeny { id: denied }).await.unwrap();
    h.ok(
        &support,
        "request_access",
        json!({ "grants": [{ "account": "billing", "actions": "read" }], "duration_minutes": 120,
                "note": "Need the invoices from October to answer a customer question." }),
    )
    .await;

    // Part 2 pages: an IMAP mailbox with a send-as address, indexing, a project of its own, a watch and a sink.
    h.imap_mailbox("privat", "dominik@strato.test").await;
    h.admin(AdminRequest::AccountsAliasAdd {
        account: "privat".into(),
        address: "hallo@strato.test".into(),
        name: Some("Dominik".into()),
        envelope: false,
    })
    .await
    .unwrap();
    h.project("home", &["privat"]).await;
    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    h.ok(&support, "create_watch", json!({ "account": "info", "kind": "from", "from": "kunde@example.org" })).await;
    h.admin(AdminRequest::SinksAdd {
        name: "phone".into(),
        project: "acme".into(),
        url: "https://hooks.example.org/dove/notify".into(),
        secret: dove::admin::Password(zeroize::Zeroizing::new("d".repeat(40))),
    })
    .await
    .unwrap();
    // A second IMAP user on the fake server, to try "Connect IMAP" (servers below, password "demo-password").
    h.imap.add_user("neu@strato.test", "demo-password");
    h.imap.add_folder("neu@strato.test", "Drafts", Some("\\Drafts"));
    h.imap.add_folder("neu@strato.test", "Sent", Some("\\Sent"));
    let (imap, smtp) = h.imap_endpoints();
    println!("DEMO imap={}:{} {:?} smtp={}:{} {:?}", imap.host, imap.port, imap.tls, smtp.host, smtp.port, smtp.tls);

    let link = h.admin(AdminRequest::PasskeysAdd { name: "demo".into() }).await.unwrap();
    println!("\nDEMO base={} origin={origin}", h.base);
    println!("DEMO enrol={}", link["open_this_link"].as_str().unwrap());
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}
