//! Activity dashboard and audit search (design 2026-11-17 "dashboard"): the overview charts agent tool calls and lists
//! connections, the audit page suggests values, filters failures and object ids, hides watch polls and pages.

mod support;

use dove::audit::{self, AuditRecord};
use dove::util;
use serde_json::json;
use support::admin_ui::{self as ui, Browser};
use support::harness::{Harness, g};

async fn signed_in() -> (Harness, Browser, String) {
    let h = ui::start().await;
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    let mut b = Browser::new(&h);
    let mut a = ui::enrol(&h, &mut b, "owner").await;
    ui::login(&mut b, &mut a).await;
    (h, b, token)
}

#[tokio::test]
async fn the_overview_charts_real_tool_calls_per_connection() {
    let (h, mut b, token) = signed_in().await;
    h.ok(&token, "list_accounts", json!({})).await;
    h.ok(&token, "list_accounts", json!({})).await;
    assert_eq!(h.err(&token, "get_message", json!({"account": "info", "message_id": "nope"})).await, "not_found");

    let page = b.get("/admin").await;
    assert_eq!(page.status, 200);
    for want in [
        "<h2>Agent activity</h2>",
        "<svg class=\"chart\"",
        "3 agent calls in the last 14 days",
        "href=\"/admin/audit?since=7d&amp;actor=agent\"",
        "3 calls · 1 failed",
        "<strong>3</strong><span>calls today</span>",
        "<strong>1</strong><span>failed or refused today</span>",
    ] {
        assert!(page.text.contains(want), "missing {want:?}");
    }
    assert!(!page.text.contains("<strong>web:owner</strong>"), "the owner's own admin actions are not agent activity");
}

#[tokio::test]
async fn the_audit_page_filters_suggests_and_links() {
    let (h, mut b, token) = signed_in().await;
    h.ok(&token, "list_accounts", json!({})).await;
    assert_eq!(h.err(&token, "get_message", json!({"account": "info", "message_id": "nope"})).await, "not_found");

    let page = b.get("/admin/audit?result=failed").await;
    assert_eq!(page.status, 200);
    assert!(page.text.contains(">get_message</a>"), "the refused call is listed");
    assert!(!page.text.contains(">list_accounts</a>"), "successful calls are filtered out");
    assert!(page.text.contains("<option value=\"failed\" selected>"));
    assert!(
        page.text.contains("<datalist id=\"audit-actors\"><option value=\"") && page.text.contains("value=\"agent\"")
    );
    // A value in a row filters by it and keeps the other filters.
    assert!(page.text.contains("href=\"/admin/audit?result=failed&amp;actor=agent\""), "{}", page.text);

    // A reflected filter value is escaped.
    let page = b.get("/admin/audit?actor=%22%3Cx%3E").await;
    assert!(page.text.contains("value=\"&quot;&lt;x&gt;\"") && !page.text.contains("\"<x>"));
}

#[tokio::test]
async fn watch_polls_are_hidden_and_old_records_page() {
    let (h, mut b, _) = signed_in().await;
    h.app()
        .store
        .call(|c| {
            for i in 0..105 {
                let tool = if i % 2 == 0 { audit::POLL_TOOL } else { "search_messages" };
                audit::append(
                    c,
                    &AuditRecord {
                        request_id: util::new_id(),
                        actor: "bulk".into(),
                        tool_or_action: tool.into(),
                        object_ids: vec![format!("obj{i}")],
                        result_code: "ok".into(),
                        ..Default::default()
                    },
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();

    let page = b.get("/admin/audit?actor=bulk").await;
    assert!(page.text.contains("52 newest records. Watch polls are hidden."), "{}", page.text);
    assert!(!page.text.contains("Older records"));

    let page = b.get("/admin/audit?actor=bulk&polls=1").await;
    assert!(page.text.contains("100 newest records."));
    let start =
        page.text.find("href=\"/admin/audit?actor=bulk&amp;polls=1&amp;before=").expect("an older-records link");
    let href = &page.text[start + 6..];
    let href = &href[..href.find('"').unwrap()];
    let older = b.get(&href.replace("&amp;", "&")).await;
    assert!(older.text.contains("5 older records."), "{}", older.text);

    let one = b.get("/admin/audit?object=obj7").await;
    assert!(one.text.contains("1 newest records.") && one.text.contains("obj7"));
}
