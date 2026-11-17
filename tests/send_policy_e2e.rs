//! Recipient rules for direct sends (PLAN A82): `allow_domains` and `unknown_recipients` refuse an agent's own
//! `send_draft` before the send is claimed and before any upstream write; owner-approved sends are not checked.

mod support;

use dove::admin::AdminRequest;
use dove::index::sync::sync_account;
use dove::util;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{Harness, g};

const MB: &str = "info@acme.test";

struct Fx {
    h: Harness,
    token: String,
    account_id: String,
}

async fn setup() -> Fx {
    let h = Harness::start_with(|c| c.allow_send = true).await;
    let account_id = h.mailbox("info", MB);
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read,draft,send")]).await;
    Fx { h, token, account_id }
}

async fn policy(h: &Harness, domains: &[&str], unknown: &str) -> Result<Value, String> {
    h.admin(AdminRequest::AccountsSendPolicySet {
        account: "info".into(),
        allow_domains: domains.iter().map(|d| d.to_string()).collect(),
        unknown_recipients: unknown.into(),
    })
    .await
}

impl Fx {
    /// A draft with these recipients: (draft_id, revision).
    async fn draft(&self, to: &[&str], bcc: &[&str]) -> (String, String) {
        let c = self
            .h
            .ok(
                &self.token,
                "create_draft",
                json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(), "to": to, "bcc": bcc,
                        "subject": "Angebot", "body_text": "Hallo" }),
            )
            .await;
        (c["draft_id"].as_str().unwrap().to_string(), c["revision"].as_str().unwrap().to_string())
    }

    async fn send(&self, d: &(String, String)) -> (bool, Value) {
        self.h
            .call(&self.token, "send_draft", json!({ "account": "info", "draft_id": d.0, "expected_revision": d.1 }))
            .await
    }

    /// Sends `d` expecting a refusal; checks that nothing was written upstream and the draft was not claimed.
    async fn refused(&self, d: &(String, String), reason: &str, count: u64) {
        self.h.google.clear_requests();
        let (is_err, v) = self.send(d).await;
        assert!(is_err, "sent: {v}");
        let e = &v["error"];
        assert_eq!(e["code"], "forbidden", "{e}");
        assert_eq!(
            (e["details"]["reason"].as_str(), e["details"]["count"].as_u64()),
            (Some(reason), Some(count)),
            "{e}"
        );
        assert!(e["message"].as_str().unwrap().contains("request_send"), "{e}");
        let writes: Vec<String> = self
            .h
            .google
            .requests()
            .into_iter()
            .filter(|r| r.method != "GET")
            .map(|r| format!("{} {}", r.method, r.path))
            .collect();
        assert!(writes.is_empty(), "{writes:?}");
        let id = d.0.clone();
        let state: String = self
            .h
            .app()
            .store
            .call(move |c| Ok(c.query_row("SELECT state FROM own_drafts WHERE draft_id = ?1", [id], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(state, "active");
    }

    async fn sent(&self, d: &(String, String)) {
        let (is_err, v) = self.send(d).await;
        assert!(!is_err, "refused: {v}");
    }
}

#[tokio::test]
async fn allow_domains_match_exact_and_subdomains_any_case_and_count_bcc() {
    let fx = setup().await;
    // Domains as the owner typed them: case and an @ do not matter.
    let v = policy(&fx.h, &["Kunde.DE", "@partner.test"], "allow").await.unwrap();
    assert_eq!(v["send_policy"]["allow_domains"], json!(["kunde.de", "partner.test"]));

    fx.refused(&fx.draft(&["eve@evil.test"], &[]).await, "recipient_not_allowed", 1).await;
    // A look-alike is not a subdomain.
    fx.refused(&fx.draft(&["a@notkunde.de", "b@kunde.de.evil.test"], &[]).await, "recipient_not_allowed", 2).await;
    // Bcc counts like To.
    fx.refused(&fx.draft(&["a@kunde.de"], &["spy@evil.test"]).await, "recipient_not_allowed", 1).await;
    assert_eq!(fx.h.google.count("POST", "drafts/send"), 0);

    fx.sent(&fx.draft(&["Bob@KUNDE.DE"], &[]).await).await;
    fx.sent(&fx.draft(&["x@mail.Kunde.de"], &["y@deep.sub.partner.test"]).await).await;
    assert_eq!(fx.h.google.count("POST", "drafts/send"), 2);

    // An open policy removes the rules.
    policy(&fx.h, &[], "allow").await.unwrap();
    fx.sent(&fx.draft(&["eve@evil.test"], &[]).await).await;
    let shown = fx.h.admin(AdminRequest::AccountsSendPolicyShow { account: "info".into() }).await.unwrap();
    assert_eq!(shown["send_policy"], json!({ "allow_domains": [], "unknown_recipients": "allow" }));
    let rows: i64 =
        fx.h.app()
            .store
            .call(|c| Ok(c.query_row("SELECT count(*) FROM account_send_policy", [], |r| r.get(0))?))
            .await
            .unwrap();
    assert_eq!(rows, 0, "an open policy leaves no row");
}

#[tokio::test]
async fn unknown_recipients_refuse_needs_mail_exchanged_and_fails_closed() {
    let fx = setup().await;
    policy(&fx.h, &[], "refuse").await.unwrap();
    // No index: nothing can be confirmed.
    fx.refused(&fx.draft(&["known@partner.test"], &[]).await, "recipients_unverified", 1).await;

    let add = |from: &str, to: &str, labels: &[&str]| {
        fx.h.google.add_message(
            MB,
            MessageSpec {
                from: from.into(),
                to: vec![to.into()],
                subject: "Hallo".into(),
                text: Some("x".into()),
                labels: labels.iter().map(|l| l.to_string()).collect(),
                internal_date_ms: 1_700_000_000_000,
                ..Default::default()
            },
        )
    };
    add("known@partner.test", MB, &["INBOX"]);
    add(MB, "wrote-to@partner.test", &["SENT"]);
    // Being in To of someone else's mail is not an exchange.
    add("other@partner.test", "cc-only@partner.test", &["INBOX"]);
    fx.h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    // Enabled but not yet published: still unverified.
    fx.refused(&fx.draft(&["known@partner.test"], &[]).await, "recipients_unverified", 1).await;
    let r = sync_account(fx.h.app(), &fx.account_id).await.unwrap();
    assert_eq!(r.error, None, "{r:?}");

    fx.sent(&fx.draft(&["Known@Partner.test"], &[]).await).await;
    fx.sent(&fx.draft(&["wrote-to@partner.test"], &[]).await).await;
    fx.refused(
        &fx.draft(&["known@partner.test"], &["cc-only@partner.test", "new@partner.test"]).await,
        "recipient_not_allowed",
        2,
    )
    .await;

    // Domain rules come first and are reported on their own.
    policy(&fx.h, &["partner.test"], "refuse").await.unwrap();
    fx.refused(&fx.draft(&["known@partner.test", "x@evil.test"], &[]).await, "recipient_not_allowed", 1).await;

    // list_accounts tells the agent the rule.
    let v = fx.h.ok(&fx.token, "list_accounts", json!({})).await;
    assert_eq!(
        v["accounts"][0]["send_policy"],
        json!({ "allow_domains": ["partner.test"], "unknown_recipients": "refuse" })
    );
    // Without send rights the policy is not shown.
    let reader = fx.h.token("acme", "reader", vec![g("info", "read,draft")]).await;
    let v = fx.h.ok(&reader, "list_accounts", json!({})).await;
    assert!(v["accounts"][0].get("send_policy").is_none(), "{v}");
}

#[tokio::test]
async fn approved_requests_are_not_checked() {
    let fx = setup().await;
    policy(&fx.h, &["kunde.de"], "refuse").await.unwrap();
    let d = fx.draft(&["eve@evil.test"], &[]).await;
    fx.refused(&d, "recipient_not_allowed", 1).await;
    // The owner approves the same draft: it goes out despite the rules.
    let t = util::now_unix() + 3600;
    let v = fx
        .h
        .ok(
            &fx.token,
            "request_send",
            json!({ "account": "info", "items": [{ "draft_id": d.0, "expected_revision": d.1, "send_at": util::rfc3339(t) }] }),
        )
        .await;
    let id = v["request_id"].as_str().unwrap().to_string();
    let shown = fx.h.admin(AdminRequest::RequestsShow { id: id.clone() }).await.unwrap();
    let shown: Vec<dove::admin::ShownItem> = shown["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| dove::admin::ShownItem {
            idx: i["idx"].as_u64().unwrap() as u32,
            revision: i["revision"].as_str().unwrap().into(),
        })
        .collect();
    fx.h.admin(AdminRequest::RequestsApprove {
        id,
        shown,
        items: None,
        late: dove::admin::Late::Skip,
        duration_minutes: None,
    })
    .await
    .unwrap();
    dove::requests::worker::tick(fx.h.app(), t).await.unwrap();
    assert_eq!(fx.h.google.count("POST", "drafts/send"), 1);
}

#[tokio::test]
async fn admin_verbs_validate_and_audit_counts_only() {
    let fx = setup().await;
    for bad in [vec!["not a domain"], vec!["bücher.de"], vec!["a..b"]] {
        assert!(policy(&fx.h, &bad, "allow").await.is_err(), "{bad:?}");
    }
    assert!(policy(&fx.h, &["kunde.de"], "maybe").await.is_err());
    assert!(fx.h.admin(AdminRequest::AccountsSendPolicyShow { account: "nope".into() }).await.is_err());
    policy(&fx.h, &["geheim-kunde.de", "zweiter.test"], "refuse").await.unwrap();
    let shown = fx.h.admin(AdminRequest::AccountsSendPolicyShow { account: "info".into() }).await.unwrap();
    assert_eq!(shown["send_policy"]["unknown_recipients"], "refuse");
    let audit: Vec<String> =
        fx.h.app()
            .store
            .call(|c| {
                let mut st = c.prepare(
                    "SELECT tool_or_action, object_ids FROM audit WHERE tool_or_action LIKE 'accounts.send_policy%'",
                )?;
                let rows = st.query_map([], |r| {
                    Ok(format!("{} {}", r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default()))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
            .unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.contains("accounts.send_policy_set") && a.contains("domains:2") && a.contains("unknown:refuse")),
        "{audit:?}"
    );
    assert!(audit.iter().all(|a| !a.contains("geheim") && !a.contains("zweiter")), "{audit:?}");
    // Setting needs a passkey in the admin UI; showing does not.
    assert!(dove::admin_ui::needs_step_up(&AdminRequest::AccountsSendPolicySet {
        account: "info".into(),
        allow_domains: vec![],
        unknown_recipients: "allow".into()
    }));
    assert!(!dove::admin_ui::needs_step_up(&AdminRequest::AccountsSendPolicyShow { account: "info".into() }));
    // Removing the mailbox removes its rules.
    fx.h.admin(AdminRequest::AccountsRemove { alias: "info".into() }).await.unwrap();
    let left: i64 =
        fx.h.app()
            .store
            .call(|c| Ok(c.query_row("SELECT count(*) FROM account_send_policy", [], |r| r.get(0))?))
            .await
            .unwrap();
    assert_eq!(left, 0);
}

// ------------------------------------------------------------------ IMAP

#[tokio::test]
async fn imap_refusal_sends_no_smtp_command() {
    let h = Harness::start_with(|c| c.allow_send = true).await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read,draft,send")]).await;
    let _ = u;
    h.admin(AdminRequest::AccountsSendPolicySet {
        account: "info".into(),
        allow_domains: vec!["example.org".into()],
        unknown_recipients: "allow".into(),
    })
    .await
    .unwrap();
    let mk = |to: &'static str, bcc: &'static str| {
        let (h, token) = (&h, &token);
        async move {
            let c = h
                .ok(
                    token,
                    "create_draft",
                    json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(), "to": [to],
                            "bcc": if bcc.is_empty() { json!([]) } else { json!([bcc]) }, "body_text": "Hallo" }),
                )
                .await;
            json!({ "account": "info", "draft_id": c["draft_id"], "expected_revision": c["revision"] })
        }
    };
    let bad = mk("kunde@example.org", "spy@evil.test").await;
    h.imap.clear_commands();
    let (is_err, v) = h.call(&token, "send_draft", bad).await;
    assert!(is_err);
    assert_eq!(
        (v["error"]["code"].as_str(), v["error"]["details"]["count"].as_u64()),
        (Some("forbidden"), Some(1)),
        "{v}"
    );
    assert!(h.imap.smtp_commands().is_empty(), "{:?}", h.imap.smtp_commands());
    assert!(
        h.imap
            .commands()
            .iter()
            .all(|c| !c.starts_with("APPEND") && !c.starts_with("UID STORE") && !c.starts_with("UID EXPUNGE")),
        "{:?}",
        h.imap.commands()
    );
    let ok = mk("kunde@Sub.Example.org", "").await;
    h.ok(&token, "send_draft", ok).await;
    assert_eq!(h.imap.sent_mails().len(), 1);
}
