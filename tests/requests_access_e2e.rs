//! Requests stage 2 (design 2026-11-14 section 4.5, PLAN A73): an agent asks for more access with `request_access`,
//! only the operator's approval on the admin socket changes a right, temporary rights end at their expiry on the next
//! call, earlier rights stay, and no path (revoke, `clients set-grants`, mailbox removal, cancel) lets a temporary
//! right outlive it.

mod support;

use dove::admin::AdminRequest;
use dove::index::sync::sync_account;
use dove::requests::worker::tick;
use dove::util;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{Harness, g};

const INFO: &str = "info@acme.test";
const BILLING: &str = "billing@acme.test";

fn spec(from: &str, to: &str, subject: &str) -> MessageSpec {
    MessageSpec {
        from: from.into(),
        to: vec![to.into()],
        subject: subject.into(),
        text: Some("hello there".into()),
        labels: vec!["INBOX".into()],
        ..Default::default()
    }
}

struct Fx {
    h: Harness,
    token: String,
}

/// Gmail mailboxes `info` and `billing` in project `acme`, `other` in project `beta`; a token `agent` with `info=read`.
async fn setup_with(customize: impl FnOnce(&mut dove::config::Config)) -> Fx {
    let h = Harness::start_with(customize).await;
    h.mailbox("info", INFO);
    h.mailbox("billing", BILLING);
    h.mailbox("other", "other@beta.test");
    h.project("acme", &["info", "billing"]).await;
    h.project("beta", &["other"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    Fx { h, token }
}

async fn setup() -> Fx {
    setup_with(|_| {}).await
}

impl Fx {
    /// `request_access` that must succeed; returns the request id.
    async fn ask(&self, grants: Value, minutes: Option<i64>) -> String {
        let mut args = json!({ "grants": grants });
        if let Some(m) = minutes {
            args["duration_minutes"] = json!(m);
        }
        let v = self.h.ok(&self.token, "request_access", args).await;
        assert_eq!(v["status"], "pending");
        v["request_id"].as_str().unwrap().to_string()
    }

    async fn approve(&self, id: &str, items: Option<Vec<u32>>, minutes: Option<u32>) -> Result<Value, String> {
        self.h
            .admin(AdminRequest::RequestsApprove {
                id: id.into(),
                shown: vec![],
                items,
                late: Default::default(),
                duration_minutes: minutes,
            })
            .await
    }

    /// `list_accounts` as (alias → actions, comma joined).
    async fn accounts(&self) -> Vec<(String, String)> {
        let v = self.h.ok(&self.token, "list_accounts", json!({})).await;
        v["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let actions: Vec<&str> = a["actions"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
                (a["account"].as_str().unwrap().to_string(), actions.join(","))
            })
            .collect()
    }

    async fn sql_i64(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.h.app().store.call(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).await.unwrap()
    }

    async fn sql_str(&self, sql: &str) -> Option<String> {
        let sql = sql.to_string();
        self.h
            .app()
            .store
            .call(move |c| {
                use rusqlite::OptionalExtension;
                Ok(c.query_row(&sql, [], |r| r.get(0)).optional()?)
            })
            .await
            .unwrap()
    }

    async fn exec(&self, sql: &str) {
        let sql = sql.to_string();
        self.h.app().store.call(move |c| Ok(c.execute_batch(&sql)?)).await.unwrap();
    }

    async fn status(&self, id: &str) -> String {
        self.sql_str(&format!("SELECT status FROM requests WHERE id = '{id}'")).await.unwrap()
    }

    async fn extras(&self) -> i64 {
        self.sql_i64("SELECT count(*) FROM client_grant_extras").await
    }

    async fn grant_states(&self, id: &str) -> Vec<String> {
        let v = self.h.ok(&self.token, "list_requests", json!({})).await;
        let r = v["requests"].as_array().unwrap().iter().find(|r| r["request_id"] == id).unwrap().clone();
        r["access"]["grants"].as_array().unwrap().iter().map(|g| g["state"].as_str().unwrap().to_string()).collect()
    }

    async fn base_grants(&self) -> Vec<(String, String)> {
        let v = self.h.admin(AdminRequest::ClientsShow { name: "agent".into() }).await.unwrap();
        v["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| (x["account"].as_str().unwrap().to_string(), x["actions"].as_str().unwrap().to_string()))
            .collect()
    }
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

async fn audit_text(h: &Harness) -> String {
    let rows: Vec<String> = h
        .app()
        .store
        .call(|c| {
            let mut st = c.prepare("SELECT * FROM audit")?;
            let n = st.column_count();
            let rows = st.query_map([], |r| {
                let cell = |i| match r.get::<_, rusqlite::types::Value>(i) {
                    Ok(rusqlite::types::Value::Text(t)) => t,
                    Ok(rusqlite::types::Value::Blob(b)) => String::from_utf8_lossy(&b).into_owned(),
                    Ok(v) => format!("{v:?}"),
                    Err(e) => format!("{e}"),
                };
                Ok((0..n).map(cell).collect::<Vec<_>>().join("|"))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
        .unwrap();
    rows.join("\n")
}

#[tokio::test]
async fn access_request_needs_approval() {
    let fx = setup().await;
    let h = &fx.h;
    assert!(h.tool_names(&fx.token).await.contains(&"request_access".to_string()));
    let v = h
        .ok(
            &fx.token,
            "request_access",
            json!({ "grants": [{ "account": "billing", "actions": "reader" }], "duration_minutes": 60,
                    "note": "NOTE-CANARY need the invoices" }),
        )
        .await;
    let id = v["request_id"].as_str().unwrap().to_string();
    assert_eq!(v["grants"], json!([{ "idx": 0, "account": "billing", "actions": "read" }]));
    // Asking changes nothing.
    assert_eq!(fx.accounts().await, vec![pair("info", "read")]);
    assert_eq!(h.err(&fx.token, "list_labels", json!({ "account": "billing" })).await, "not_found");
    assert_eq!(fx.grant_states(&id).await, vec!["pending"]);
    assert_eq!(fx.extras().await, 0);
    // The operator sees the note and what the connection has now; the audit never holds the note.
    let shown = h.admin(AdminRequest::RequestsShow { id: id.clone() }).await.unwrap();
    assert_eq!(shown["kind"], "access");
    assert_eq!(shown["note"], "NOTE-CANARY need the invoices");
    assert_eq!(shown["duration_minutes"], 60);
    assert_eq!(shown["grants"][0]["account"], "billing");
    assert_eq!(shown["grants"][0]["asked"], "read");
    assert_eq!(shown["grants"][0]["has"], Value::Null);
    assert_eq!(shown["grants"][0]["in_project"], true);
    let list = h.admin(AdminRequest::RequestsList { status: Some("pending".into()) }).await.unwrap();
    assert_eq!(list[0]["access"]["grants"][0]["account"], "billing");
    // Deny: still nothing.
    h.admin(AdminRequest::RequestsDeny { id: id.clone() }).await.unwrap();
    assert_eq!(fx.grant_states(&id).await, vec!["denied"]);
    assert_eq!(h.err(&fx.token, "list_labels", json!({ "account": "billing" })).await, "not_found");
    assert!(fx.approve(&id, None, None).await.unwrap_err().contains("not pending"));
    assert_eq!(fx.extras().await, 0);
    assert!(!audit_text(h).await.contains("NOTE-CANARY"));
}

#[tokio::test]
async fn temporary_grant_works_then_expires_and_earlier_rights_stay() {
    let fx = setup().await;
    let h = &fx.h;
    let id = fx
        .ask(
            json!([{ "account": "info", "actions": "drafter" }, { "account": "billing", "actions": "read" }]),
            Some(60),
        )
        .await;
    let epoch = || fx.sql_i64("SELECT auth_epoch FROM clients WHERE name = 'agent'");
    let e0 = epoch().await;
    let before = util::now_unix();
    let v = fx.approve(&id, None, None).await.unwrap();
    assert_eq!(v["status"], "approved");
    assert_eq!(epoch().await, e0 + 1, "an approval changes the scope: cursors made before it end");
    let until = util::parse_rfc3339_ms(v["access"]["expires_at"].as_str().unwrap()).unwrap() / 1000;
    assert!((before + 3600..=util::now_unix() + 3600).contains(&until), "{v}");
    assert_eq!(fx.grant_states(&id).await, vec!["active", "active"]);
    assert_eq!(fx.accounts().await, vec![pair("billing", "read"), pair("info", "read,draft")]);
    let la = h.ok(&fx.token, "list_accounts", json!({})).await;
    let info = la["accounts"].as_array().unwrap().iter().find(|a| a["account"] == "info").unwrap().clone();
    assert_eq!(info["temporary"], json!([{ "actions": "read,draft", "expires_at": util::rfc3339(until) }]));
    let shown = h.admin(AdminRequest::ClientsShow { name: "agent".into() }).await.unwrap();
    assert_eq!(shown["temporary"].as_array().unwrap().len(), 2);
    assert_eq!(shown["grants"], json!([{ "account": "info", "actions": "read" }]));
    // The temporary rights work.
    h.ok(
        &fx.token,
        "create_draft",
        json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(),
        "to": ["c@example.org"], "subject": "Hi", "body_text": "x" }),
    )
    .await;
    h.ok(&fx.token, "list_labels", json!({ "account": "billing" })).await;

    // Not expired yet: the sweep keeps them.
    let r = tick(h.app(), until - 1).await.unwrap();
    assert_eq!(r.grants_expired, 0);
    // At the expiry the sweep deletes them with one audit record each; the request is done.
    let r = tick(h.app(), until).await.unwrap();
    assert_eq!(r.grants_expired, 2);
    assert_eq!(epoch().await, e0 + 2, "the sweep ends cursors made with the wider scope");
    assert_eq!(fx.extras().await, 0);
    assert_eq!(fx.status(&id).await, "done");
    assert_eq!(fx.grant_states(&id).await, vec!["ended", "ended"]);
    assert_eq!(
        fx.sql_i64("SELECT count(*) FROM audit WHERE tool_or_action = 'request.grant_expire' AND actor = 'scheduler'")
            .await,
        2
    );
    let aliases = fx
        .sql_str(
            "SELECT group_concat(account_alias, ',') FROM (SELECT account_alias FROM audit \
             WHERE tool_or_action = 'request.grant_expire' ORDER BY account_alias)",
        )
        .await;
    assert_eq!(aliases.as_deref(), Some("billing,info"));
    // Earlier rights stay, nothing more.
    assert_eq!(fx.accounts().await, vec![pair("info", "read")]);
    assert_eq!(fx.base_grants().await, vec![pair("info", "read")]);
    let e = h
        .err(
            &fx.token,
            "create_draft",
            json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(),
            "to": ["c@example.org"], "subject": "Hi", "body_text": "x" }),
        )
        .await;
    assert_eq!(e, "forbidden");
    assert_eq!(h.err(&fx.token, "list_labels", json!({ "account": "billing" })).await, "not_found");
}

#[tokio::test]
async fn expiry_takes_effect_on_the_next_call_without_the_worker() {
    let fx = setup().await;
    let h = &fx.h;
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(5)).await;
    fx.approve(&id, None, None).await.unwrap();
    h.ok(&fx.token, "list_labels", json!({ "account": "billing" })).await;
    // The clock passes the expiry; the worker has not run.
    fx.exec(&format!("UPDATE client_grant_extras SET expires_at = {}", util::now_unix())).await;
    assert_eq!(h.err(&fx.token, "list_labels", json!({ "account": "billing" })).await, "not_found");
    assert_eq!(fx.accounts().await, vec![pair("info", "read")]);
    assert_eq!(fx.extras().await, 1, "the row is still there; the policy ignores it");
    assert_eq!(fx.grant_states(&id).await, vec!["ended"]);
}

#[tokio::test]
async fn union_and_dependency_rules() {
    let fx = setup().await;
    let h = &fx.h;
    h.admin(AdminRequest::ClientsSetGrants { name: "agent".into(), grants: vec![g("info", "read,draft")] })
        .await
        .unwrap();
    // The grant syntax and its dependency rules apply to what is asked.
    for (actions, field) in
        [("delete", "grants[0].actions"), ("read,admin", "grants[0].actions"), ("", "grants[0].actions")]
    {
        let e = h
            .call(&fx.token, "request_access", json!({ "grants": [{ "account": "info", "actions": actions }] }))
            .await
            .1;
        assert_eq!(e["error"]["code"], "invalid_argument", "{actions}: {e}");
        assert_eq!(e["error"]["details"]["field"], field, "{actions}: {e}");
    }
    // read,organize on top of read,draft: the union.
    let id = fx.ask(json!([{ "account": "info", "actions": "reader,organize" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    assert_eq!(fx.accounts().await, vec![pair("info", "read,draft,organize")]);
    // Two temporary grants on one mailbox stay separate rows and unite as well.
    let id2 = fx.ask(json!([{ "account": "info", "actions": "full" }]), Some(5)).await;
    fx.approve(&id2, None, None).await.unwrap();
    assert_eq!(fx.accounts().await, vec![pair("info", "read,draft,organize,delete")]);
    fx.exec(&format!("UPDATE client_grant_extras SET expires_at = {} WHERE request_id = '{id2}'", util::now_unix()))
        .await;
    assert_eq!(fx.accounts().await, vec![pair("info", "read,draft,organize")]);
    // A stored temporary list that breaks the rules grants nothing (never part of it).
    fx.exec(&format!(
        "INSERT INTO client_grant_extras(client_id, account_id, request_id, actions, granted_at, expires_at) \
         SELECT c.id, a.id, '{id}', 'draft', 0, {} FROM clients c, accounts a WHERE c.name = 'agent' AND a.alias = 'billing'",
        util::now_unix() + 3600
    ))
    .await;
    assert_eq!(h.err(&fx.token, "list_labels", json!({ "account": "billing" })).await, "not_found");
    assert_eq!(fx.accounts().await, vec![pair("info", "read,draft,organize")]);
}

/// A mailbox held only through a temporary grant behaves like a granted one wherever the policy is consulted
/// (search scope and own addresses, reads, watches) and disappears everywhere at expiry.
#[tokio::test]
async fn temporary_mailbox_behaves_like_a_granted_one() {
    let fx = setup().await;
    let h = &fx.h;
    let info = fx.sql_str("SELECT id FROM accounts WHERE alias = 'info'").await.unwrap();
    let billing = fx.sql_str("SELECT id FROM accounts WHERE alias = 'billing'").await.unwrap();
    h.google.add_message(INFO, spec("bob@example.com", INFO, "To info"));
    let bmsg = h.google.add_message(BILLING, spec(INFO, BILLING, "From info to billing"));
    for (alias, aid) in [("info", &info), ("billing", &billing)] {
        h.admin(AdminRequest::IndexEnable { alias: alias.into() }).await.unwrap();
        sync_account(h.app(), aid).await.unwrap();
    }
    let rows = |v: &Value| v["rows"].as_array().unwrap().clone();
    let v = h.ok(&fx.token, "search_messages", json!({ "select": ["subject"] })).await;
    assert_eq!(rows(&v), vec![json!(["To info"])]);

    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    // Search covers it, with its own addresses (`from_self` needs them for every target).
    let v = h.ok(&fx.token, "search_messages", json!({ "select": ["subject", "from_self"] })).await;
    let mut got = rows(&v);
    got.sort_by_key(|r| r[0].as_str().unwrap().to_string());
    assert_eq!(got, vec![json!(["From info to billing", false]), json!(["To info", false])]);
    h.ok(&fx.token, "get_message", json!({ "account": "billing", "message_id": bmsg })).await;
    let w =
        h.ok(&fx.token, "create_watch", json!({ "account": "billing", "kind": "from", "from": "x@example.com" })).await;
    let wid = w["watch_id"].as_str().unwrap().to_string();

    // Expiry: gone from search, reads and the running watch.
    fx.exec(&format!("UPDATE client_grant_extras SET expires_at = {}", util::now_unix())).await;
    let v = h.ok(&fx.token, "search_messages", json!({ "select": ["subject"] })).await;
    assert_eq!(rows(&v), vec![json!(["To info"])]);
    assert_eq!(
        h.err(&fx.token, "search_messages", json!({ "accounts": ["billing"], "select": ["subject"] })).await,
        "not_found"
    );
    assert_eq!(h.err(&fx.token, "get_message", json!({ "account": "billing", "message_id": bmsg })).await, "not_found");
    dove::watch::tick(h.app(), util::now_unix()).await.unwrap();
    let state = fx.sql_str(&format!("SELECT state || ':' || end_reason FROM watches WHERE id = '{wid}'")).await;
    assert_eq!(state.as_deref(), Some("ended:access_lost"));
}

/// A scheduled send whose `draft` right came from a temporary grant fails `access_lost` after the expiry; nothing is
/// sent.
#[tokio::test]
async fn scheduled_send_ends_with_the_right() {
    let fx = setup().await;
    let h = &fx.h;
    let id = fx.ask(json!([{ "account": "info", "actions": "read,draft" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    let c = h
        .ok(
            &fx.token,
            "create_draft",
            json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(),
            "to": ["c@example.org"], "subject": "Offer", "body_text": "x" }),
        )
        .await;
    let (d, rev) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    let send_at = util::now_unix() + 2 * 3600;
    let v = h
        .ok(
            &fx.token,
            "request_send",
            json!({ "account": "info",
            "items": [{ "draft_id": d, "expected_revision": rev, "send_at": util::rfc3339(send_at) }] }),
        )
        .await;
    let sid = v["request_id"].as_str().unwrap().to_string();
    let shown = h.admin(AdminRequest::RequestsShow { id: sid.clone() }).await.unwrap();
    let rev_shown = shown["items"][0]["revision"].as_str().unwrap().to_string();
    h.admin(AdminRequest::RequestsApprove {
        id: sid.clone(),
        shown: vec![dove::admin::ShownItem { idx: 0, revision: rev_shown }],
        items: None,
        late: Default::default(),
        duration_minutes: None,
    })
    .await
    .unwrap();
    // The send is due after the right ended (the worker's sweep runs first in the same pass).
    let r = tick(h.app(), send_at).await.unwrap();
    assert_eq!((r.grants_expired, r.sent, r.failed), (1, 0, 1), "{r:?}");
    let reason =
        fx.sql_str(&format!("SELECT state || ':' || reason FROM request_items WHERE request_id = '{sid}'")).await;
    assert_eq!(reason.as_deref(), Some("failed:access_lost"));
    assert_eq!(h.google.count("POST", "drafts/send"), 0);
}

#[tokio::test]
async fn set_grants_revoke_and_mailbox_removal_drop_extras() {
    let fx = setup().await;
    let h = &fx.h;
    // clients set-grants: everything temporary goes, the request is done.
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    let v = h
        .admin(AdminRequest::ClientsSetGrants { name: "agent".into(), grants: vec![g("info", "read")] })
        .await
        .unwrap();
    assert_eq!(v["temporary_grants_deleted"], 1);
    assert_eq!((fx.extras().await, fx.status(&id).await.as_str()), (0, "done"));
    assert_eq!(h.err(&fx.token, "list_labels", json!({ "account": "billing" })).await, "not_found");

    // projects remove-account: the rows on that mailbox go, a pending request naming it is cancelled.
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    let pending = fx.ask(json!([{ "account": "billing", "actions": "drafter" }]), None).await;
    let v = h
        .admin(AdminRequest::ProjectsRemoveAccount { project: "acme".into(), account: "billing".into() })
        .await
        .unwrap();
    assert_eq!(v["temporary_grants_deleted"], 1);
    assert_eq!((fx.extras().await, fx.status(&id).await.as_str()), (0, "done"));
    assert_eq!(fx.status(&pending).await, "cancelled");
    // Both endings are on record, the approved request's as well as the pending one's.
    for r in [&id, &pending] {
        let q =
            format!("SELECT count(*) FROM audit WHERE tool_or_action = 'request.cancel' AND object_ids LIKE '%{r}%'");
        assert_eq!(fx.sql_i64(&q).await, 1, "request.cancel record of {r}");
    }
    // Adding it back resurrects nothing.
    h.admin(AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "billing".into() }).await.unwrap();
    assert_eq!(h.err(&fx.token, "list_labels", json!({ "account": "billing" })).await, "not_found");

    // accounts remove: the rows go with the mailbox, the requests close or are cancelled.
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    let pending = fx.ask(json!([{ "account": "billing", "actions": "drafter" }]), None).await;
    h.admin(AdminRequest::AccountsRemove { alias: "billing".into() }).await.unwrap();
    assert_eq!((fx.extras().await, fx.status(&id).await.as_str()), (0, "done"));
    assert_eq!(fx.status(&pending).await, "cancelled");

    // Removing one of two mailboxes keeps the request open for the other.
    h.mailbox("billing", BILLING);
    h.admin(AdminRequest::ProjectsAddAccount { project: "acme".into(), account: "billing".into() }).await.unwrap();
    let id = fx
        .ask(
            json!([{ "account": "info", "actions": "drafter" }, { "account": "billing", "actions": "read" }]),
            Some(60),
        )
        .await;
    fx.approve(&id, None, None).await.unwrap();
    h.admin(AdminRequest::ProjectsRemoveAccount { project: "acme".into(), account: "billing".into() }).await.unwrap();
    assert_eq!((fx.extras().await, fx.status(&id).await.as_str()), (1, "approved"));
    assert_eq!(fx.grant_states(&id).await, vec!["active", "ended"]);
    h.admin(AdminRequest::ClientsSetGrants { name: "agent".into(), grants: vec![g("info", "read")] }).await.unwrap();

    // Revoke: every temporary right of the client goes, also one whose request is no longer open.
    let stray = fx.ask(json!([{ "account": "info", "actions": "drafter" }]), Some(60)).await;
    fx.approve(&stray, None, None).await.unwrap();
    fx.exec(&format!("UPDATE requests SET status = 'done' WHERE id = '{stray}'")).await;
    let id = fx.ask(json!([{ "account": "info", "actions": "drafter" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    assert_eq!(fx.extras().await, 2);
    h.admin(AdminRequest::ClientsRevoke { name: "agent".into() }).await.unwrap();
    assert_eq!(fx.extras().await, 0);
    assert_eq!(fx.status(&id).await, "done");
}

/// The approval re-checks inside its transaction what the tick may not have marked yet.
#[tokio::test]
async fn approval_needs_a_live_client_and_an_unexpired_request() {
    let fx = setup().await;
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.exec(&format!("UPDATE requests SET expires_at = {} WHERE id = '{id}'", util::now_unix())).await;
    let e = fx.approve(&id, None, None).await.unwrap_err();
    assert!(e.contains("expired"), "{e}");
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.exec(&format!("UPDATE clients SET expires_at = {} WHERE name = 'agent'", util::now_unix())).await;
    let e = fx.approve(&id, None, None).await.unwrap_err();
    assert!(e.contains("revoked or expired"), "{e}");
    assert_eq!(fx.extras().await, 0);
}

#[tokio::test]
async fn switched_off_hides_request_access() {
    let fx = setup_with(|c| c.requests.enabled = false).await;
    assert!(!fx.h.tool_names(&fx.token).await.contains(&"request_access".to_string()));
    let (err, _) =
        fx.h.call(&fx.token, "request_access", json!({ "grants": [{ "account": "billing", "actions": "read" }] }))
            .await;
    assert!(err);
    assert_eq!(fx.sql_i64("SELECT count(*) FROM requests").await, 0);
}

#[tokio::test]
async fn unknown_and_out_of_project_alias_are_identical() {
    let fx = setup().await;
    let h = &fx.h;
    let ask = |account: &str| json!({ "grants": [{ "account": account, "actions": "read" }], "duration_minutes": 10 });
    let unknown = h.call(&fx.token, "request_access", ask("nope")).await;
    let foreign = h.call(&fx.token, "request_access", ask("other")).await;
    let foreign_mail = h.call(&fx.token, "request_access", ask("other@beta.test")).await;
    assert!(unknown.0 && foreign.0 && foreign_mail.0);
    assert_eq!(unknown.1["error"]["code"], "not_found");
    assert_eq!(unknown.1, foreign.1);
    assert_eq!(unknown.1, foreign_mail.1);
    // The same mailbox named by address works inside the project.
    fx.ask(json!([{ "account": "BILLING@acme.test", "actions": "read" }]), Some(10)).await;
    assert_eq!(fx.sql_i64("SELECT count(*) FROM requests WHERE kind = 'access'").await, 1);
}

/// A call that is refused without leaving a request must answer the same for a mailbox of the project and for a
/// foreign or unknown one; otherwise the agent could test project membership without the owner seeing anything.
#[tokio::test]
async fn refusals_do_not_tell_project_membership() {
    let fx = setup_with(|c| c.limits.client_open_requests = 1).await;
    let h = &fx.h;
    let before = fx.sql_i64("SELECT count(*) FROM requests").await;

    // A note that is too long: refused the same way for every name.
    let long = "n".repeat(501);
    let note = |account: &str| json!({ "grants": [{ "account": account, "actions": "read" }], "note": long });
    let inside = h.call(&fx.token, "request_access", note("billing")).await;
    assert_eq!(inside.1["error"]["code"], "invalid_argument", "{}", inside.1);
    assert_eq!(inside.1["error"]["details"]["field"], "note");
    assert_eq!(inside.1, h.call(&fx.token, "request_access", note("other")).await.1);
    assert_eq!(inside.1, h.call(&fx.token, "request_access", note("nope")).await.1);

    // A name given twice: with a foreign or unknown mailbox it stays not_found, inside the project it is one grant
    // with the actions of both entries (also when one entry uses the address).
    let twice = |account: &str| json!({ "grants": [{ "account": account, "actions": "read" }, { "account": account, "actions": "read" }] });
    assert_eq!(h.call(&fx.token, "request_access", twice("other")).await.1["error"]["code"], "not_found");
    assert_eq!(h.call(&fx.token, "request_access", twice("nope")).await.1["error"]["code"], "not_found");
    assert_eq!(fx.sql_i64("SELECT count(*) FROM requests").await, before);
    let merged = h
        .ok(
            &fx.token,
            "request_access",
            json!({ "grants": [{ "account": "billing", "actions": "read" },
                               { "account": "BILLING@acme.test", "actions": "drafter" }] }),
        )
        .await;
    assert_eq!(merged["grants"].as_array().unwrap().len(), 1, "{merged}");
    assert_eq!(merged["grants"][0]["actions"], "read,draft");

    // The open-request limit (now reached): the same answer for every name.
    let ask = |account: &str| json!({ "grants": [{ "account": account, "actions": "read" }] });
    let inside = h.call(&fx.token, "request_access", ask("info")).await;
    assert_eq!(inside.1["error"]["code"], "invalid_argument", "{}", inside.1);
    assert_eq!(inside.1, h.call(&fx.token, "request_access", ask("other")).await.1);
    assert_eq!(inside.1, h.call(&fx.token, "request_access", ask("nope")).await.1);
    assert_eq!(fx.sql_i64("SELECT count(*) FROM requests").await, before + 1);
}

#[tokio::test]
async fn send_needs_allow_send() {
    let fx = setup().await;
    let e =
        fx.h.call(&fx.token, "request_access", json!({ "grants": [{ "account": "info", "actions": "drafter,send" }] }))
            .await
            .1;
    assert_eq!(e["error"]["code"], "invalid_argument", "{e}");
    assert_eq!(e["error"]["details"]["field"], "grants[0].actions");
    assert_eq!(fx.sql_i64("SELECT count(*) FROM requests").await, 0);

    // With allow_send the request is taken; if the gate closes before the approval, nothing is granted.
    let mut fx = setup_with(|c| c.allow_send = true).await;
    let id = fx.ask(json!([{ "account": "info", "actions": "drafter,send" }]), Some(60)).await;
    fx.h.restart_with(|c| c.allow_send = false).await;
    let e = fx.approve(&id, None, None).await.unwrap_err();
    assert!(e.contains("allow_send"), "{e}");
    assert_eq!((fx.extras().await, fx.status(&id).await.as_str()), (0, "pending"));
    fx.h.restart_with(|c| c.allow_send = true).await;
    fx.approve(&id, None, None).await.unwrap();
    assert!(fx.h.tool_names(&fx.token).await.contains(&"send_draft".to_string()));
    // With the gate closed again the temporary right no longer lists `send`, like the mailbox's own actions.
    fx.h.restart_with(|c| c.allow_send = false).await;
    let accounts = fx.h.ok(&fx.token, "list_accounts", json!({})).await;
    let info = accounts["accounts"].as_array().unwrap().iter().find(|a| a["account"] == "info").unwrap();
    assert_eq!(info["temporary"][0]["actions"], "read,draft", "{info}");
    assert!(!info["actions"].as_array().unwrap().iter().any(|a| a == "send"), "{info}");
}

#[tokio::test]
async fn duration_bounds() {
    let fx = setup().await;
    for bad in [json!(0), json!(-1), json!(43_201), json!(1.5), json!("60")] {
        let e =
            fx.h.call(
                &fx.token,
                "request_access",
                json!({ "grants": [{ "account": "billing", "actions": "read" }], "duration_minutes": bad }),
            )
            .await
            .1;
        assert_eq!(e["error"]["code"], "invalid_argument", "{bad}: {e}");
        assert_eq!(e["error"]["details"]["field"], "duration_minutes", "{bad}: {e}");
    }
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(43_200)).await;
    let v = fx.h.ok(&fx.token, "list_requests", json!({})).await;
    assert_eq!(v["requests"][0]["access"]["duration_minutes"], 43_200);
    // The operator's duration has the same bounds.
    assert!(fx.approve(&id, None, Some(0)).await.is_err());
    assert!(fx.approve(&id, None, Some(43_201)).await.is_err());
    assert_eq!(fx.extras().await, 0);
    // No duration: a permanent grant is asked. The operator's bound holds there too (no asked duration to compare).
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), None).await;
    let e = fx.approve(&id, None, Some(43_201)).await.unwrap_err();
    assert!(e.contains("30 days"), "{e}");
    assert_eq!((fx.extras().await, fx.status(&id).await.as_str()), (0, "pending"));
    let v = fx.h.ok(&fx.token, "list_requests", json!({})).await;
    let r = v["requests"].as_array().unwrap().iter().find(|r| r["request_id"] == id.as_str()).unwrap().clone();
    assert_eq!(r["access"]["duration_minutes"], Value::Null);
}

#[tokio::test]
async fn operator_shortens_and_unticks() {
    let fx = setup().await;
    let h = &fx.h;
    let id = fx
        .ask(
            json!([{ "account": "info", "actions": "drafter" }, { "account": "billing", "actions": "read" }]),
            Some(600),
        )
        .await;
    // Longer than asked: refused, nothing granted.
    let e = fx.approve(&id, None, Some(601)).await.unwrap_err();
    assert!(e.contains("only shorten"), "{e}");
    assert!(fx.approve(&id, Some(vec![2]), None).await.unwrap_err().contains("not a grant"));
    assert_eq!(fx.extras().await, 0);
    let before = util::now_unix();
    let v = fx.approve(&id, Some(vec![1]), Some(60)).await.unwrap();
    let until = util::parse_rfc3339_ms(v["access"]["expires_at"].as_str().unwrap()).unwrap() / 1000;
    assert!((before + 3600..=util::now_unix() + 3600).contains(&until), "{v}");
    assert_eq!(fx.grant_states(&id).await, vec!["not_approved", "active"]);
    assert_eq!(fx.accounts().await, vec![pair("billing", "read"), pair("info", "read")]);

    // A permanent request approved with a duration becomes temporary.
    let id = fx.ask(json!([{ "account": "info", "actions": "drafter" }]), None).await;
    let v = fx.approve(&id, None, Some(30)).await.unwrap();
    assert_eq!(v["status"], "approved");
    assert!(v["access"]["expires_at"].is_string());
    assert_eq!(fx.base_grants().await, vec![pair("info", "read")]);

    // Permanent: added to the grants (old ∪ approved), done at once, nothing removed.
    h.admin(AdminRequest::ClientsSetGrants { name: "agent".into(), grants: vec![g("info", "assistant")] })
        .await
        .unwrap();
    let id = fx
        .ask(json!([{ "account": "info", "actions": "read" }, { "account": "billing", "actions": "drafter" }]), None)
        .await;
    let shown = h.admin(AdminRequest::RequestsShow { id: id.clone() }).await.unwrap();
    assert_eq!(shown["grants"][0]["has"], "read,draft,organize");
    let v = fx.approve(&id, None, None).await.unwrap();
    assert_eq!(v["status"], "done");
    assert_eq!(fx.grant_states(&id).await, vec!["granted", "granted"]);
    assert_eq!(fx.base_grants().await, vec![pair("billing", "read,draft"), pair("info", "read,draft,organize")]);
    assert_eq!(fx.extras().await, 0);
}

#[tokio::test]
async fn cancel_gives_rights_back() {
    let fx = setup().await;
    let h = &fx.h;
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    let e = h.admin(AdminRequest::RequestsCancel { id: id.clone(), items: Some(vec![0]) }).await.unwrap_err();
    assert!(e.contains("as a whole"), "{e}");
    let v = h.ok(&fx.token, "cancel_request", json!({ "request_id": id })).await;
    assert_eq!(v["status"], "done");
    assert_eq!(fx.extras().await, 0);
    assert_eq!(h.err(&fx.token, "list_labels", json!({ "account": "billing" })).await, "not_found");
    // The operator can end a temporary grant early the same way.
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    h.admin(AdminRequest::RequestsCancel { id: id.clone(), items: None }).await.unwrap();
    assert_eq!((fx.extras().await, fx.status(&id).await.as_str()), (0, "done"));
    // Another client cannot cancel it (identical not_found).
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    let other = h.token("acme", "other", vec![g("info", "read")]).await;
    let a = h.call(&other, "cancel_request", json!({ "request_id": id })).await.1;
    let b = h.call(&other, "cancel_request", json!({ "request_id": "r_nope" })).await.1;
    assert_eq!(a["error"]["code"], "not_found");
    assert_eq!(a, b);
    assert_eq!(fx.status(&id).await, "pending");
}

/// Approved temporary requests count as open until they end, like approved send requests.
#[tokio::test]
async fn open_request_limit_counts_active_grants() {
    let fx = setup_with(|c| c.limits.client_open_requests = 1).await;
    let id = fx.ask(json!([{ "account": "billing", "actions": "read" }]), Some(60)).await;
    fx.approve(&id, None, None).await.unwrap();
    let e =
        fx.h.call(&fx.token, "request_access", json!({ "grants": [{ "account": "billing", "actions": "drafter" }] }))
            .await
            .1;
    assert_eq!(e["error"]["code"], "invalid_argument", "{e}");
    tick(fx.h.app(), util::now_unix() + 3600).await.unwrap();
    fx.ask(json!([{ "account": "billing", "actions": "drafter" }]), None).await;
}
