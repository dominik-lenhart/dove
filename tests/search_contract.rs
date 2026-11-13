//! search_messages contract over MCP/HTTP against the fake Google server (spec 5.3, 7.9).
//! Covers AC1 (search scope, cursors), AC14 (partial failure), AC17 (search contract) and the query-side parts of
//! AC20 (body/MIME coverage, negation against truncated bodies, purge).

mod support;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use dove::admin::AdminRequest;
use dove::index::query::{self, Scope, Target};
use dove::index::sync::{load_state, sync_account};
use dove::util::parse_rfc3339_ms;
use serde_json::{Value, json};
use support::fake_google::{Fault, MessageSpec};
use support::harness::{Harness, g};

fn at(s: &str) -> i64 {
    parse_rfc3339_ms(s).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn m(from: &str, to: &[&str], subject: &str, text: &str, date: &str, labels: &[&str]) -> MessageSpec {
    MessageSpec {
        from: from.into(),
        to: to.iter().map(|s| s.to_string()).collect(),
        subject: subject.into(),
        text: Some(text.into()),
        labels: labels.iter().map(|s| s.to_string()).collect(),
        internal_date_ms: at(date),
        ..Default::default()
    }
}

const TIE: &str = "2026-10-12T12:00:00Z";

struct Fx {
    h: Harness,
    token: String,
    ids: HashMap<&'static str, String>,
    accounts: HashMap<&'static str, String>,
}

async fn fixture_with(customize: impl FnOnce(&mut dove::config::Config)) -> Fx {
    let h = Harness::start_with(customize).await;
    let mut accounts = HashMap::new();
    for (alias, email) in [
        ("info", "info@acme.test"),
        ("billing", "billing@acme.test"),
        ("ops", "ops@acme.test"),
        ("secret", "secret@acme.test"),
        ("plain", "plain@acme.test"),
    ] {
        accounts.insert(alias, h.mailbox(alias, email));
    }
    h.project("acme", &["info", "billing", "ops", "secret", "plain"]).await;
    let token = h
        .token(
            "acme",
            "agent",
            vec![g("info", "read,draft"), g("billing", "read"), g("ops", "read"), g("plain", "read")],
        )
        .await;
    let mut ids = HashMap::new();
    let mut add = |key: &'static str, email: &str, spec: MessageSpec| {
        ids.insert(key, h.google.add_message(email, spec));
    };
    let info = "info@acme.test";
    let mut a = m(
        "Hetzner Billing <billing@hetzner.com>",
        &[info],
        "Invoice October",
        "Your invoice is attached",
        "2026-10-05T10:00:00Z",
        &["INBOX"],
    );
    a.attachments = vec![("invoice-2026-10.pdf".into(), "application/pdf".into(), b"%PDF-1.4 a".to_vec())];
    add("A", info, a);
    add(
        "B",
        info,
        m("noreply@mail.hetzner.com", &[info], "Server alert", "disk usage high", "2026-09-30T21:59:59Z", &["INBOX"]),
    );
    let mut c = m(
        "anna@example.com",
        &[info],
        "Invoice October",
        "quarterly report attached",
        "2026-09-30T22:00:00Z",
        &["INBOX"],
    );
    c.attachments = vec![("report.xlsx".into(), "application/vnd.ms-excel".into(), b"xls".to_vec())];
    add("C", info, c);
    let mut d = m(info, &["bob@example.org"], "Re: lunch", "see you at noon", "2026-10-10T08:00:00Z", &["SENT"]);
    d.bcc = vec!["hidden@example.net".into()];
    add("D", info, d);
    add("E", info, m("spam@bad.example", &[info], "Win money", "click here", "2026-10-11T08:00:00Z", &["SPAM"]));
    add(
        "F",
        info,
        m("anna@example.com", &[info], "Lunch plans", "the quick brown fox", TIE, &["INBOX", "UNREAD", "STARRED"]),
    );
    add("G", info, m("carl@example.com", &[info], "", "fox report", TIE, &["INBOX"]));
    let billing = "billing@acme.test";
    let mut hh = m(
        "billing@hetzner.com",
        &[billing],
        "Invoice November",
        "november invoice",
        "2026-11-02T09:00:00Z",
        &["INBOX"],
    );
    hh.attachments = vec![("INVOICE-2026-11.PDF".into(), "application/pdf".into(), b"%PDF-1.4 b".to_vec())];
    add("H", billing, hh);
    add("I", billing, m("anna@example.com", &[billing], "Budget", "brown bear", TIE, &["INBOX"]));
    add("O", "ops@acme.test", m("x@example.com", &["ops@acme.test"], "Ops only", "ops text", TIE, &["INBOX"]));
    add(
        "S",
        "secret@acme.test",
        m("anna@example.com", &["secret@acme.test"], "Secret stuff", "brown secret", TIE, &["INBOX"]),
    );
    add(
        "P",
        "plain@acme.test",
        m("anna@example.com", &["plain@acme.test"], "Plain hello", "zulu plain", TIE, &["INBOX"]),
    );
    for alias in ["info", "billing", "ops", "secret"] {
        h.admin(AdminRequest::IndexEnable { alias: alias.into() }).await.unwrap();
        let r = sync_account(h.app(), &accounts[alias]).await.unwrap();
        assert_eq!(r.stage, "ready", "{alias}: {r:?}");
    }
    // ops loses its Google grant after indexing: its rows exist but must never be disclosed.
    h.app()
        .store
        .call(|c| Ok(c.execute("UPDATE accounts SET status = 'reauth_required' WHERE alias = 'ops'", [])?))
        .await
        .unwrap();
    Fx { h, token, ids, accounts }
}

async fn fixture() -> Fx {
    fixture_with(|_| {}).await
}

impl Fx {
    async fn search(&self, args: Value) -> Value {
        self.h.ok(&self.token, "search_messages", args).await
    }
    async fn err(&self, args: Value) -> String {
        self.h.err(&self.token, "search_messages", args).await
    }
    /// Sorted message keys (A..S) for a where clause over info + billing.
    async fn keys(&self, filter: Value) -> Vec<&'static str> {
        let v = self
            .search(json!({"accounts": ["info", "billing"], "where": filter, "select": ["message_id"], "limit": 100}))
            .await;
        let mut out: Vec<&'static str> = col(&v, "message_id")
            .iter()
            .map(|id| *self.ids.iter().find(|(_, v)| json!(v) == *id).map(|(k, _)| k).expect("known id"))
            .collect();
        out.sort();
        out
    }
}

fn col(v: &Value, name: &str) -> Vec<Value> {
    let i = v["columns"].as_array().unwrap().iter().position(|c| c == name).unwrap_or_else(|| panic!("{v}"));
    v["rows"].as_array().unwrap().iter().map(|r| r[i].clone()).collect()
}

fn pred(field: &str, op: &str, value: Value) -> Value {
    json!({"field": field, "op": op, "value": value})
}

#[tokio::test]
async fn boolean_precedence_domains_and_time_zones() {
    let fx = fixture().await;
    // Exact domain, no subdomains unless named.
    assert_eq!(fx.keys(pred("from_domain", "eq", json!("hetzner.com"))).await, vec!["A", "H"]);
    assert_eq!(fx.keys(pred("from_domain", "eq", json!("mail.hetzner.com"))).await, vec!["B"]);
    assert_eq!(
        fx.keys(pred("from_domain", "in", json!(["Mail.Hetzner.com", "hetzner.com"]))).await,
        vec!["A", "B", "H"]
    );
    // Time zone boundary: 2026-10-01T00:00+02:00 is 2026-09-30T22:00Z; inclusive start, exclusive end.
    let window = json!({"all": [
        pred("received_at", "gte", json!("2026-10-01T00:00:00+02:00")),
        pred("received_at", "lt", json!("2026-10-01T00:00:00+00:00")),
    ]});
    assert_eq!(fx.keys(window).await, vec!["C"]);
    // AND/OR/NOT precedence is the JSON structure.
    let a = json!({"any": [
        {"all": [pred("from_domain", "eq", json!("hetzner.com")), pred("has_attachment", "eq", json!(true))]},
        {"all": [pred("from", "eq", json!("anna@example.com")), {"not": pred("text", "terms", json!("report"))}]},
    ]});
    assert_eq!(fx.keys(a).await, vec!["A", "F", "H", "I"]);
    let b = json!({"all": [
        {"any": [pred("from_domain", "eq", json!("hetzner.com")), pred("from", "eq", json!("anna@example.com"))]},
        pred("has_attachment", "eq", json!(true)),
    ]});
    assert_eq!(fx.keys(b).await, vec!["A", "C", "H"]);
    // Negation complements within authorized, non-spam candidates of the requested mailboxes.
    let v = fx
        .search(json!({"accounts": ["info"], "where": {"not": pred("from_domain", "eq", json!("hetzner.com"))},
                       "select": ["subject"], "limit": 100}))
        .await;
    assert_eq!(v["rows"].as_array().unwrap().len(), 5);
    // Double negation is the identity.
    let dn = json!({"not": {"not": pred("label", "eq", json!("STARRED"))}});
    assert_eq!(fx.keys(dn).await, vec!["F"]);
    // size_bytes comparisons and flags.
    assert_eq!(fx.keys(pred("size_bytes", "gte", json!(0))).await.len(), 8);
    assert_eq!(fx.keys(pred("is_unread", "eq", json!(true))).await, vec!["F"]);
}

#[tokio::test]
async fn text_attachments_addresses_and_labels() {
    let fx = fixture().await;
    assert_eq!(fx.keys(pred("text", "phrase", json!("quick brown"))).await, vec!["F"]);
    assert!(fx.keys(pred("text", "phrase", json!("brown quick"))).await.is_empty());
    assert_eq!(fx.keys(pred("text", "terms", json!("BROWN"))).await, vec!["F", "I"]);
    assert_eq!(fx.keys(pred("body_text", "prefix", json!("repo"))).await, vec!["C", "G"]);
    assert_eq!(fx.keys(pred("subject", "terms", json!("invoice"))).await, vec!["A", "C", "H"]);
    assert_eq!(fx.keys(pred("subject", "phrase", json!("Invoice October"))).await, vec!["A", "C"]);
    // body_text does not see the subject, subject does not see the body.
    assert!(fx.keys(pred("body_text", "terms", json!("october"))).await.is_empty());
    assert!(fx.keys(pred("subject", "terms", json!("fox"))).await.is_empty());
    // FTS syntax in values is literal text, never operators.
    assert!(fx.keys(pred("text", "terms", json!("fox OR NEAR(bear)"))).await.is_empty());
    // Attachments: case-insensitive names, literal suffix, MIME types.
    assert_eq!(fx.keys(pred("attachment_name", "ends_with", json!(".pdf"))).await, vec!["A", "H"]);
    assert_eq!(fx.keys(pred("attachment_name", "eq", json!("REPORT.xlsx"))).await, vec!["C"]);
    assert_eq!(fx.keys(pred("attachment_mime", "eq", json!("application/pdf"))).await, vec!["A", "H"]);
    // Addresses: normalized, roles, Bcc only where the mailbox has it.
    assert_eq!(fx.keys(pred("from", "eq", json!("ANNA@example.com"))).await, vec!["C", "F", "I"]);
    assert_eq!(fx.keys(pred("bcc", "eq", json!("hidden@example.net"))).await, vec!["D"]);
    assert_eq!(fx.keys(pred("participant", "eq", json!("hidden@example.net"))).await, vec!["D"]);
    assert!(fx.keys(pred("to", "eq", json!("hidden@example.net"))).await.is_empty());
    assert_eq!(fx.keys(pred("recipient_domain", "eq", json!("example.net"))).await, vec!["D"]);
    // Labels, plain and mailbox-qualified.
    assert_eq!(fx.keys(pred("label", "eq", json!("SENT"))).await, vec!["D"]);
    assert_eq!(fx.keys(pred("label", "eq", json!("billing:INBOX"))).await, vec!["H", "I"]);
    assert_eq!(fx.keys(pred("thread_id", "in", json!([fx.ids["A"]]))).await.len(), 0);
    assert_eq!(fx.keys(pred("message_id", "eq", json!(format!("info:{}", fx.ids["A"])))).await, vec!["A"]);
    assert!(fx.keys(pred("message_id", "eq", json!(format!("billing:{}", fx.ids["A"])))).await.is_empty());
    // Unknown and out-of-scope qualifiers are the same not_found.
    let unknown =
        fx.h.call(&fx.token, "search_messages", json!({"where": pred("label", "eq", json!("nope:INBOX"))})).await;
    let secret =
        fx.h.call(&fx.token, "search_messages", json!({"where": pred("label", "eq", json!("secret:INBOX"))})).await;
    assert!(unknown.0 && secret.0);
    assert_eq!(unknown.1, secret.1);
    assert_eq!(unknown.1["error"]["code"], "not_found");
}

#[tokio::test]
async fn ordering_ties_paging_and_projection() {
    let fx = fixture().await;
    let all = fx
        .search(json!({"accounts": ["info", "billing"], "select": ["ref", "message_id", "account"], "limit": 100}))
        .await;
    let ids: Vec<Value> = col(&all, "message_id");
    assert_eq!(ids.len(), 8);
    assert_eq!(ids[0], json!(fx.ids["H"]), "newest first by default");
    // F, G (info) and I (billing) share a timestamp: ordered by (account_id, message_id) ascending.
    let mut tie: Vec<(String, String)> = vec![
        (fx.accounts["info"].clone(), fx.ids["F"].clone()),
        (fx.accounts["info"].clone(), fx.ids["G"].clone()),
        (fx.accounts["billing"].clone(), fx.ids["I"].clone()),
    ];
    tie.sort();
    let tie_ids: Vec<Value> = tie.iter().map(|(_, m)| json!(m)).collect();
    assert_eq!(&ids[1..4], &tie_ids[..]);
    // Oldest first.
    let asc = fx
        .search(json!({"accounts": ["info"], "select": ["message_id"], "order_by": [{"field": "received_at", "dir": "asc"}]}))
        .await;
    assert_eq!(col(&asc, "message_id")[0], json!(fx.ids["B"]));
    // Subject order: case-folded, duplicates kept, missing subject last in both directions.
    for dir in ["asc", "desc"] {
        let v = fx
            .search(
                json!({"accounts": ["info"], "select": ["subject"], "order_by": [{"field": "subject", "dir": dir}]}),
            )
            .await;
        let s = col(&v, "subject");
        assert_eq!(s.last().unwrap(), &json!(""), "{dir}: {s:?}");
        if dir == "asc" {
            assert_eq!(s[0], s[1], "duplicate subjects adjacent");
            assert_eq!(s[0], json!("Invoice October"));
        }
    }
    // Pages of 1 traverse exactly the single-page result: no duplicates, no gaps, same order.
    let mut paged = vec![];
    let mut v = fx.search(json!({"accounts": ["info", "billing"], "select": ["message_id"], "limit": 1})).await;
    loop {
        paged.extend(col(&v, "message_id"));
        let Some(c) = v["next_cursor"].as_str() else { break };
        v = fx.search(json!({"cursor": c})).await;
        assert_eq!(v["changed_since_first_page"], false);
    }
    assert_eq!(paged, ids);
    // Two-key order with paging.
    let two = json!({"accounts": ["info", "billing"], "select": ["message_id"],
        "order_by": [{"field": "subject", "dir": "asc"}, {"field": "received_at", "dir": "desc"}]});
    let mut full_args = two.clone();
    full_args["limit"] = json!(100);
    let full = fx.search(full_args).await;
    let mut paged = vec![];
    let mut args = two.clone();
    args["limit"] = json!(3);
    let mut v = fx.search(args).await;
    loop {
        paged.extend(col(&v, "message_id"));
        let Some(c) = v["next_cursor"].as_str() else { break };
        v = fx.search(json!({"cursor": c})).await;
    }
    assert_eq!(paged, col(&full, "message_id"));

    // Subject-only returns just subjects: no refs, ids, snippets or bodies anywhere in the result.
    let v = fx.search(json!({"accounts": ["info"], "select": ["subject"], "limit": 100})).await;
    assert_eq!(v["columns"], json!(["subject"]));
    let text = v.to_string();
    assert!(!text.contains("m_") && !text.contains(&fx.ids["A"]) && !text.contains("attached"), "{text}");
    assert!(v["rows"].as_array().unwrap().iter().all(|r| r.as_array().unwrap().len() == 1));
    // Default projection.
    let v = fx.search(json!({"accounts": ["info"], "limit": 1})).await;
    assert_eq!(v["columns"], json!(["ref", "received_at", "from", "subject"]));
    // A ref from search works with get_message.
    let v = fx.search(json!({"accounts": ["info"], "where": pred("message_id", "eq", json!(fx.ids["F"]))})).await;
    let r = col(&v, "ref")[0].clone();
    let msg = fx.h.ok(&fx.token, "get_message", json!({"ref": r})).await;
    assert_eq!(msg["message"]["subject"], "Lunch plans");

    // Rejections.
    for bad in [
        json!({"select": ["body_text"]}),
        json!({"select": ["subject", "subject"]}),
        json!({"order_by": [{"field": "from"}]}),
        json!({"order_by": [{"field": "subject"}, {"field": "size_bytes"}, {"field": "received_at"}]}),
        json!({"limit": 0}),
        json!({"limit": 101}),
        json!({"where": pred("nope", "eq", json!(1))}),
        json!({"where": {"all": []}}),
        json!({"bogus": 1}),
        json!({"count_only": true, "select": ["subject"]}),
        json!({"count_only": true, "order_by": [{"field": "received_at"}]}),
        json!({"count_only": true, "limit": 5}),
        json!({"gmail_query": "x"}),
        json!({"accounts": []}),
    ] {
        assert_eq!(fx.err(bad.clone()).await, "invalid_argument", "{bad}");
    }
}

#[tokio::test]
async fn coverage_counts_and_partial_failures() {
    let fx = fixture().await;
    // AC14: all mailboxes by default; reauth_required ops is one account_errors entry, plain is not indexed.
    let v = fx.search(json!({"select": ["account", "subject"], "limit": 100})).await;
    assert_eq!(v["coverage"], "partial");
    assert_eq!(v["account_errors"], json!([{"account": "ops", "code": "account_unavailable"}]));
    assert_eq!(v["exceptions"][0]["account"], "plain");
    assert_eq!(v["exceptions"][0]["stage"], "not_indexed");
    let accts: Vec<Value> = col(&v, "account");
    assert!(accts.iter().all(|a| a == "info" || a == "billing"), "{accts:?}");
    assert_eq!(accts.len(), 8);
    assert!(!v.to_string().contains("Ops only") && !v.to_string().contains("Secret stuff"));
    // Explicitly naming the reauth account still only reports it.
    let v = fx.search(json!({"accounts": ["info", "billing", "ops"], "select": ["account"]})).await;
    assert_eq!(v["account_errors"].as_array().unwrap().len(), 1);
    assert_eq!(
        fx.err(json!({"accounts": ["info", "ops"], "coverage_policy": "require_complete"})).await,
        "index_incomplete"
    );

    // Complete on the healthy, fresh mailboxes; as_of is the oldest included sync time.
    let v = fx.search(json!({"accounts": ["info", "billing"], "coverage_policy": "require_complete"})).await;
    assert_eq!(v["coverage"], "complete");
    assert!(v["as_of"].is_string());
    // Exact counts are opt-in and imply require_complete.
    let v = fx.search(json!({"accounts": ["info"], "count_only": true})).await;
    assert_eq!(v["count"], 6);
    assert!(v.get("rows").is_none());
    let v = fx.search(json!({"accounts": ["info"], "count_only": true, "include_spam_trash": true})).await;
    assert_eq!(v["count"], 7);
    assert_eq!(fx.err(json!({"count_only": true})).await, "index_incomplete");
    // Spam is excluded by default.
    let v = fx
        .search(json!({"accounts": ["info"], "where": pred("label", "eq", json!("SPAM")), "select": ["subject"]}))
        .await;
    assert_eq!(v["rows"], json!([]));
    let v = fx
        .search(json!({"accounts": ["info"], "where": pred("label", "eq", json!("SPAM")), "select": ["subject"], "include_spam_trash": true}))
        .await;
    assert_eq!(v["rows"], json!([["Win money"]]));

    // Freshness: an old checkpoint fails require_complete's default 60 s lag; an explicit max_lag_seconds overrides.
    let aid = fx.accounts["info"].clone();
    fx.h.app()
        .index
        .write(move |c| {
            Ok(c.execute(
                "UPDATE sync_state SET last_success_at = last_success_at - 3600 WHERE account_id = ?1",
                [aid],
            )?)
        })
        .await
        .unwrap();
    let (is_err, e) = fx.h.call(&fx.token, "search_messages", json!({"accounts": ["info"], "count_only": true})).await;
    assert!(is_err);
    assert_eq!(e["error"]["code"], "index_incomplete");
    assert_eq!(e["error"]["details"]["exceptions"][0]["stage"], "stale");
    let v = fx.search(json!({"accounts": ["info"], "count_only": true, "max_lag_seconds": 7200})).await;
    assert_eq!(v["count"], 6);
    let v = fx.search(json!({"accounts": ["info"], "max_lag_seconds": 60})).await;
    assert_eq!(v["coverage"], "partial");

    // Out-of-scope and unknown mailboxes are the same not_found.
    let s = fx.h.call(&fx.token, "search_messages", json!({"accounts": ["secret"]})).await;
    let u = fx.h.call(&fx.token, "search_messages", json!({"accounts": ["nope"]})).await;
    assert_eq!(s, u);
    assert_eq!(s.1["error"]["code"], "not_found");

    // Disabling the index purges the account from results and counts.
    fx.h.admin(AdminRequest::IndexDisable { alias: "billing".into() }).await.unwrap();
    let v = fx.search(json!({"accounts": ["billing"], "where": pred("text", "terms", json!("bear"))})).await;
    assert_eq!(v["rows"], json!([]));
    assert_eq!(v["exceptions"][0]["stage"], "not_indexed");
}

#[tokio::test]
async fn cursors_are_bound_and_invalidated() {
    let fx = fixture().await;
    let first = fx.search(json!({"accounts": ["info"], "select": ["message_id"], "limit": 2})).await;
    let cur = first["next_cursor"].as_str().unwrap().to_string();
    // Resume with the cursor only.
    assert_eq!(fx.err(json!({"cursor": cur, "limit": 5})).await, "invalid_argument");
    // Another client cannot use it.
    let other = fx.h.token("acme", "other", vec![g("info", "read")]).await;
    assert_eq!(fx.h.err(&other, "search_messages", json!({"cursor": cur})).await, "cursor_invalid");
    // Unknown cursors.
    assert_eq!(fx.err(json!({"cursor": "c_doesnotexist"})).await, "cursor_invalid");
    // Data changed between pages: rows still flow, flagged.
    fx.h.google.add_message(
        "info@acme.test",
        m("new@example.com", &["info@acme.test"], "New", "n", "2026-10-20T00:00:00Z", &["INBOX"]),
    );
    sync_account(fx.h.app(), &fx.accounts["info"]).await.unwrap();
    let v = fx.search(json!({"cursor": cur})).await;
    assert_eq!(v["changed_since_first_page"], true);
    assert_eq!(v["rows"].as_array().unwrap().len(), 2);
    // A grant change bumps the auth epoch: earlier cursors die.
    let c2 = fx.search(json!({"accounts": ["info"], "limit": 1})).await["next_cursor"].as_str().unwrap().to_string();
    fx.h.admin(AdminRequest::ClientsSetGrants {
        name: "agent".into(),
        grants: vec![g("info", "read,draft"), g("billing", "read"), g("ops", "read"), g("plain", "read")],
    })
    .await
    .unwrap();
    assert_eq!(fx.err(json!({"cursor": c2})).await, "cursor_invalid");
    // An index rebuild invalidates cursors.
    let c3 = fx.search(json!({"accounts": ["info"], "limit": 1})).await["next_cursor"].as_str().unwrap().to_string();
    fx.h.admin(AdminRequest::IndexRebuild { alias: "info".into() }).await.unwrap();
    assert_eq!(fx.err(json!({"cursor": c3})).await, "cursor_invalid");
    sync_account(fx.h.app(), &fx.accounts["info"]).await.unwrap();
    // Expiry and eviction.
    let cursors = &fx.h.app().index.cursors;
    cursors.set_limits(Duration::from_millis(0), 1000, 8 << 20);
    let c4 = fx.search(json!({"accounts": ["info"], "limit": 1})).await["next_cursor"].as_str().unwrap().to_string();
    assert_eq!(fx.err(json!({"cursor": c4})).await, "cursor_invalid");
    cursors.set_limits(Duration::from_secs(900), 1, 8 << 20);
    let c5 = fx.search(json!({"accounts": ["info"], "limit": 1})).await["next_cursor"].as_str().unwrap().to_string();
    let c6 = fx.search(json!({"accounts": ["info"], "limit": 1})).await["next_cursor"].as_str().unwrap().to_string();
    assert_eq!(fx.err(json!({"cursor": c5})).await, "cursor_invalid");
    assert!(fx.search(json!({"cursor": c6})).await["rows"].is_array());
    // Revoked access: removing a mailbox from the grants (epoch bump) and a later resume of a fresh cursor fails.
    cursors.set_limits(Duration::from_secs(900), 1000, 8 << 20);
    let c7 = fx.search(json!({"accounts": ["info"], "limit": 1})).await["next_cursor"].as_str().unwrap().to_string();
    fx.h.admin(AdminRequest::ClientsSetGrants { name: "agent".into(), grants: vec![g("billing", "read")] })
        .await
        .unwrap();
    assert_eq!(fx.err(json!({"cursor": c7})).await, "cursor_invalid");
    assert_eq!(fx.err(json!({"accounts": ["info"]})).await, "not_found");
}

#[tokio::test]
async fn indexed_search_makes_no_gmail_calls_and_uses_indexes() {
    let fx = fixture().await;
    fx.h.google.clear_requests();
    let v = fx.search(json!({"accounts": ["info", "billing"], "limit": 2})).await;
    fx.search(json!({"cursor": v["next_cursor"]})).await;
    fx.search(json!({"accounts": ["info", "billing"], "count_only": true})).await;
    fx.search(
        json!({"accounts": ["info", "billing"], "select": ["subject", "snippet", "to", "labels", "attachment_names"]}),
    )
    .await;
    fx.search(json!({"accounts": ["info", "billing"], "where": pred("text", "phrase", json!("quick brown"))})).await;
    assert_eq!(fx.h.google.requests().iter().filter(|r| r.path.contains("/gmail/")).count(), 0);

    // EXPLAIN QUERY PLAN on the hot paths.
    let mut targets = vec![];
    for alias in ["info", "billing"] {
        let aid = fx.accounts[alias].clone();
        let st = fx.h.app().index.write(move |c| Ok(load_state(c, &aid)?.unwrap())).await.unwrap();
        targets.push(Target {
            account_id: fx.accounts[alias].clone(),
            alias: alias.into(),
            gen_id: st.serving_gen().unwrap(),
            att_fts: true,
        });
    }
    let plan_n = |args: Value, n: usize| {
        let targets: Vec<Target> = targets[..n].to_vec();
        let app = fx.h.app().clone();
        async move {
            let req = dove::tools::search::parse_index_req(&args).unwrap();
            app.index
                .read(Instant::now() + Duration::from_secs(5), move |c| {
                    let known = HashMap::new();
                    query::explain(c, &req, &Scope { targets: &targets, known: &known })
                })
                .await
                .unwrap()
        }
    };
    let plan = |args: Value| plan_n(args, 2);
    // Single mailbox newest-first: the gen-prefixed date index already yields the order.
    let one = plan_n(json!({"select": ["subject"]}), 1).await;
    assert_eq!(one, vec!["SEARCH m USING INDEX messages_date (gen=? AND spam_trash=?)".to_string()]);
    let full_scan = |lines: &[String]| {
        lines.iter().any(|l| l.starts_with("SCAN m") || l.starts_with("SCAN addrs") || l.starts_with("SCAN labels"))
    };
    let date = plan(json!({"where": {"all": [pred("received_at", "gte", json!("2026-10-01T00:00:00Z")),
        pred("received_at", "lt", json!("2026-11-01T00:00:00Z"))]}, "select": ["subject"]}))
    .await;
    assert!(!full_scan(&date), "{date:?}");
    assert!(date.iter().any(|l| l.contains("received_at>? AND received_at<?")), "{date:?}");
    assert!(!date.iter().any(|l| l.contains("TEMP B-TREE")), "{date:?}");
    assert!(!date.iter().any(|l| l.contains("fts")), "{date:?}");
    let top = plan(json!({"select": ["subject"]})).await;
    assert!(!top.iter().any(|l| l.contains("TEMP B-TREE")), "top-N must not sort every row: {top:?}");
    let addr = plan(json!({"where": pred("from", "eq", json!("anna@example.com")), "select": ["subject"]})).await;
    assert!(!full_scan(&addr), "{addr:?}");
    assert!(addr.iter().any(|l| l.contains("addrs_addr")), "{addr:?}");
    assert!(addr.iter().any(|l| l.contains("INTEGER PRIMARY KEY")), "address lookups drive the join: {addr:?}");
    let dom = plan(json!({"where": pred("from_domain", "eq", json!("hetzner.com")), "count_only": true})).await;
    assert!(!full_scan(&dom), "{dom:?}");
    assert!(dom.iter().any(|l| l.contains("addrs_domain")), "{dom:?}");
    let meta =
        plan(json!({"where": {"all": [pred("label", "eq", json!("INBOX")), pred("is_unread", "eq", json!(true))]},
        "select": ["subject"]}))
        .await;
    assert!(!meta.iter().any(|l| l.contains("fts")), "metadata-only query must not touch FTS: {meta:?}");
    assert!(!full_scan(&meta), "{meta:?}");
    let text = plan(json!({"where": pred("text", "terms", json!("fox")), "select": ["subject"]})).await;
    assert!(text.iter().any(|l| l.contains("VIRTUAL TABLE INDEX")), "{text:?}");

    // Text predicates evaluate MATCH only on the eligible generations' own FTS tables (spec 7.9): the other indexed
    // mailboxes (ops, secret) have postings, but their tables appear neither in the SQL nor in the plan.
    let fts_names = |text: &str| -> std::collections::BTreeSet<String> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| w.starts_with("fts_g") && w[5..].chars().all(|c| c.is_ascii_digit()) && w.len() > 5)
            .map(str::to_string)
            .collect()
    };
    let all_tables: Vec<String> =
        fx.h.app()
            .index
            .write(|c| {
                let mut st = c.prepare("SELECT name FROM sqlite_schema WHERE sql LIKE 'CREATE VIRTUAL TABLE%fts5%'")?;
                Ok(st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap();
    assert_eq!(all_tables.len(), 4, "one FTS table per indexed mailbox: {all_tables:?}");
    assert!(!all_tables.iter().any(|t| t == "fts"), "the shared table is gone");
    let mine =
        |n: usize| targets[..n].iter().map(|t| format!("fts_g{}", t.gen_id)).collect::<std::collections::BTreeSet<_>>();
    for n in [1, 2] {
        let args = json!({"where": {"any": [pred("text", "terms", json!("fox")),
            {"not": pred("subject", "phrase", json!("quick brown"))}]}, "select": ["subject"]});
        let req = dove::tools::search::parse_index_req(&args).unwrap();
        let known = HashMap::new();
        let (sql, _) = query::page_sql(&req, &Scope { targets: &targets[..n], known: &known }, &[]).unwrap();
        assert_eq!(fts_names(&sql), mine(n), "{sql}");
        let lines = plan_n(args, n).await;
        assert_eq!(fts_names(&lines.join("\n")), mine(n), "{lines:?}");
    }
}

#[tokio::test]
async fn body_and_mime_coverage_affect_only_queries_using_them() {
    let fx = fixture_with(|c| {
        c.index.max_body_chars = 60;
        c.index.max_message_bytes = 4096;
    })
    .await;
    let info = "info@acme.test";
    let long = format!("{} needle at the end", "padding words ".repeat(10));
    fx.h.google
        .add_message(info, m("long@example.com", &[info], "Long body", &long, "2026-10-21T00:00:00Z", &["INBOX"]));
    fx.h.google.add_message(
        info,
        m("short@example.com", &[info], "Short body", "short needle", "2026-10-22T00:00:00Z", &["INBOX"]),
    );
    let mut big = m("big@example.com", &[info], "Too big", "x", "2026-10-23T00:00:00Z", &["INBOX", "STARRED"]);
    big.attachments = vec![("blob.bin".into(), "application/octet-stream".into(), vec![7u8; 8000])];
    fx.h.google.add_message(info, big);
    sync_account(fx.h.app(), &fx.accounts["info"]).await.unwrap();

    // Positive body query: the truncated body is a known gap.
    let body = |w: Value| json!({"accounts": ["info"], "where": w, "select": ["subject"], "limit": 100});
    let v = fx.search(body(pred("body_text", "terms", json!("needle")))).await;
    assert_eq!(v["rows"], json!([["Short body"]]));
    assert_eq!(v["coverage"], "partial");
    assert!(
        v["exceptions"].as_array().unwrap().iter().any(|e| e["reason"] == "body text incomplete for some messages")
    );
    let mut rc = body(pred("body_text", "terms", json!("needle")));
    rc["coverage_policy"] = json!("require_complete");
    assert_eq!(fx.err(rc).await, "index_incomplete");
    // Negated body query against a truncated body: cannot claim exact absence either.
    let v = fx.search(body(json!({"not": pred("body_text", "terms", json!("needle"))}))).await;
    assert_eq!(v["coverage"], "partial");
    let s: Vec<Value> = col(&v, "subject");
    assert!(s.contains(&json!("Long body")) && !s.contains(&json!("Short body")));
    // Metadata-only queries stay complete; a from filter needs MIME metadata, which the oversized message lacks.
    let v = fx
        .search(json!({"accounts": ["info"], "where": pred("label", "eq", json!("STARRED")),
        "select": ["message_id", "received_at"], "coverage_policy": "require_complete"}))
        .await;
    assert_eq!(v["coverage"], "complete");
    assert_eq!(v["rows"].as_array().unwrap().len(), 2);
    let v = fx.search(json!({"accounts": ["info"], "where": pred("from", "eq", json!("short@example.com")), "select": ["message_id"]})).await;
    assert_eq!(v["coverage"], "partial");
    assert!(
        v["exceptions"].as_array().unwrap().iter().any(|e| e["reason"] == "message metadata unknown for some messages")
    );
    // Unknown has_attachment never matches a positive predicate.
    let v = fx.search(json!({"accounts": ["info"], "where": pred("has_attachment", "eq", json!(true)), "select": ["subject"], "limit": 100})).await;
    assert_eq!(v["rows"], json!([["Invoice October"], ["Invoice October"]]));
}

#[tokio::test]
async fn live_gmail_route() {
    let fx = fixture().await;
    let h = &fx.h;
    for (email, n) in [("info@acme.test", 3), ("billing@acme.test", 2)] {
        for i in 0..n {
            h.google.add_message(
                email,
                m(
                    "live@example.com",
                    &[email],
                    &format!("Zulu {email} {i}"),
                    "zulu text",
                    &format!("2026-10-2{i}T00:00:00Z"),
                    &["INBOX"],
                ),
            );
        }
    }
    h.google.clear_requests();
    // Fair interleave across mailboxes, upstream order (newest first) within each; id-only projection skips GETs.
    let v = fx
        .search(json!({"source": "gmail", "gmail_query": "zulu", "accounts": ["info", "billing"],
                       "select": ["account", "message_id"], "limit": 4}))
        .await;
    assert_eq!(v["source"], "gmail");
    assert_eq!(col(&v, "account"), vec![json!("info"), json!("billing"), json!("info"), json!("billing")]);
    assert_eq!(h.google.requests().iter().filter(|r| r.path.contains("/messages/")).count(), 0);
    let c = v["next_cursor"].as_str().unwrap().to_string();
    let v2 = fx.search(json!({"cursor": c})).await;
    assert_eq!(col(&v2, "account"), vec![json!("info")]);
    assert!(v2.get("next_cursor").is_none());
    // Richer projection hydrates with format=metadata and shapes like the index route.
    h.google.clear_requests();
    let v = fx
        .search(json!({"source": "gmail", "gmail_query": "zulu", "accounts": ["info"], "select": ["subject", "from", "received_at", "labels"], "limit": 1}))
        .await;
    assert_eq!(v["rows"][0][0], "Zulu info@acme.test 2");
    assert_eq!(v["rows"][0][1], "live@example.com");
    assert_eq!(v["rows"][0][2], "2026-10-22T00:00:00Z");
    assert!(h.google.requests().iter().any(|r| r.path.contains("/messages/") && r.query.contains("format=metadata")));
    // Non-indexed mailboxes work live; the reauth one is an explicit account error.
    let v = fx
        .search(json!({"source": "gmail", "gmail_query": "zulu", "accounts": ["plain", "ops"], "select": ["subject"]}))
        .await;
    assert_eq!(v["rows"], json!([["Plain hello"]]));
    assert_eq!(v["account_errors"], json!([{"account": "ops", "code": "account_unavailable"}]));
    // Upstream failure in one mailbox is reported, the others still answer.
    h.google.fail_next("GET", "/messages", Fault::Status(400, json!({"error": {}})));
    let v = fx
        .search(
            json!({"source": "gmail", "gmail_query": "zulu", "accounts": ["info", "billing"], "select": ["account"]}),
        )
        .await;
    assert_eq!(v["account_errors"].as_array().unwrap().len(), 1);
    assert!(!v["rows"].as_array().unwrap().is_empty());
    // Local-only options are rejected on the live route; restricted select.
    for bad in [
        json!({"source": "gmail", "gmail_query": "x", "where": pred("is_unread", "eq", json!(true))}),
        json!({"source": "gmail", "gmail_query": "x", "order_by": [{"field": "received_at"}]}),
        json!({"source": "gmail", "gmail_query": "x", "count_only": true}),
        json!({"source": "gmail", "gmail_query": "x", "coverage_policy": "require_complete"}),
        json!({"source": "gmail", "gmail_query": "x", "max_lag_seconds": 5}),
        json!({"source": "gmail", "gmail_query": "x", "select": ["size_bytes"]}),
        json!({"source": "gmail"}),
        json!({"source": "gmail", "gmail_query": "a\nb"}),
    ] {
        assert_eq!(fx.err(bad.clone()).await, "invalid_argument", "{bad}");
    }
    // Live cursors are bound to the client too.
    let v = fx.search(json!({"source": "gmail", "gmail_query": "zulu", "accounts": ["info"], "select": ["message_id"], "limit": 1})).await;
    let other = h.token("acme", "other2", vec![g("info", "read")]).await;
    assert_eq!(h.err(&other, "search_messages", json!({"cursor": v["next_cursor"]})).await, "cursor_invalid");
    h.google.assert_no_violations();
}

#[tokio::test]
async fn grants_are_rechecked_before_release() {
    let fx = fixture().await;
    let h = &fx.h;
    // The live hydration GET is slow; the operator removes the mailbox grant while the call is in flight.
    let id = fx.ids["A"].clone();
    h.google.fail_next("GET", &format!("/messages/{id}"), Fault::Delay(Duration::from_millis(700)));
    let base = h.base.clone();
    let token = fx.token.clone();
    let call = tokio::spawn(async move {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "search_messages",
            "arguments": {"source": "gmail", "gmail_query": "invoice", "accounts": ["info"], "select": ["subject"]}}});
        reqwest::Client::new()
            .post(format!("{base}/mcp"))
            .header("host", support::harness::HOST)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-06-18")
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    h.admin(AdminRequest::ClientsSetGrants { name: "agent".into(), grants: vec![g("billing", "read")] }).await.unwrap();
    let v = call.await.unwrap();
    assert_eq!(v["result"]["isError"], true, "{v}");
    assert!(!v.to_string().contains("Invoice"), "{v}");
}
