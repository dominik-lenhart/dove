//! search_messages thread view and `from_self` (PLAN A59): one row per thread with reply status, over the Gmail API
//! (fake Google), plain IMAP and Gmail over IMAP (fake IMAP server).

mod support;

use std::collections::HashMap;

use dove::admin::AdminRequest;
use dove::index::imap_sync::sync_steps;
use dove::index::sync::sync_account;
use dove::util::parse_rfc3339_ms;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::fake_imap::{FakeImap, Opts};
use support::harness::{Harness, g};

const INFO: &str = "info@acme.test";
const SECRET: &str = "secret@acme.test";

fn at(hm: &str) -> i64 {
    parse_rfc3339_ms(&format!("2026-11-02T{hm}Z")).unwrap()
}

fn spec(from: &str, subject: &str, thread: &str, time: &str, labels: &[&str]) -> MessageSpec {
    MessageSpec {
        from: from.into(),
        to: vec!["someone@example.com".into()],
        subject: subject.into(),
        text: Some("body".into()),
        labels: labels.iter().map(|s| s.to_string()).collect(),
        thread_id: Some(thread.into()),
        internal_date_ms: at(time),
        ..Default::default()
    }
}

struct Fx {
    h: Harness,
    token: String,
    /// message key -> Gmail message id
    ids: HashMap<&'static str, String>,
}

/// Mailbox `info` with ten threads (`T1`..`T10`), and `secret` (not granted) sharing thread id `T8`.
async fn fixture() -> Fx {
    let h = Harness::start().await;
    let info = h.mailbox("info", INFO);
    let secret = h.mailbox("secret", SECRET);
    h.project("acme", &["info", "secret"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    let mut ids = HashMap::new();
    let mut add = |key: &'static str, email: &str, s: MessageSpec| {
        ids.insert(key, h.google.add_message(email, s));
    };
    // T1: answered.
    add("a1", INFO, spec("anna@example.com", "Project", "T1", "10:00:00", &["INBOX"]));
    add("a2", INFO, spec(INFO, "Re: Project", "T1", "11:00:00", &["SENT"]));
    // T2: never answered.
    add("b1", INFO, spec("bob@example.com", "Question", "T2", "12:00:00", &["INBOX"]));
    // T3: own outreach without an answer.
    add("c1", INFO, spec(INFO, "Offer", "T3", "09:00:00", &["SENT"]));
    // T4: the reply is only a draft.
    add("d1", INFO, spec("carl@example.com", "Invoice question", "T4", "08:00:00", &["INBOX"]));
    add("d2", INFO, spec(INFO, "Re: Invoice question", "T4", "13:00:00", &["DRAFT"]));
    // T5: answered, then they wrote again.
    add("e1", INFO, spec("anna@example.com", "Again", "T5", "07:00:00", &["INBOX"]));
    add("e2", INFO, spec(INFO, "Re: Again", "T5", "07:30:00", &["SENT"]));
    add("e3", INFO, spec("anna@example.com", "Re: Again", "T5", "14:00:00", &["INBOX"]));
    // T6: sent from a Gmail send-as address Dove does not know: the SENT label marks it.
    add("f1", INFO, spec("sales@acme-alias.test", "Brochure", "T6", "06:00:00", &["SENT"]));
    // T7: reply at the same instant as the inbound message counts as the reply.
    add("g1", INFO, spec("eve@example.com", "Tie", "T7", "05:00:00", &["INBOX"]));
    add("g2", INFO, spec(INFO, "Re: Tie", "T7", "05:00:00", &["SENT"]));
    // T8: the same thread id in another mailbox holds a reply; it must not count for info.
    add("h1", INFO, spec("frank@example.com", "Shared", "T8", "04:00:00", &["INBOX"]));
    add("h2", SECRET, spec(SECRET, "Re: Shared", "T8", "04:30:00", &["SENT"]));
    // T9: the reply is in the trash.
    add("i1", INFO, spec("gina@example.com", "Trashed", "T9", "03:00:00", &["INBOX"]));
    add("i2", INFO, spec(INFO, "Re: Trashed", "T9", "03:30:00", &["SENT", "TRASH"]));
    // T10: a copy to self from the mailbox address (no SENT label), written in upper case.
    add("j1", INFO, spec("INFO@ACME.test", "Note to self", "T10", "02:00:00", &["INBOX"]));
    for (alias, aid) in [("info", &info), ("secret", &secret)] {
        h.admin(AdminRequest::IndexEnable { alias: alias.into() }).await.unwrap();
        let r = sync_account(h.app(), aid).await.unwrap();
        assert_eq!(r.stage, "ready", "{alias}: {r:?}");
    }
    Fx { h, token, ids }
}

fn col(v: &Value, name: &str) -> Vec<Value> {
    let i = v["columns"].as_array().unwrap().iter().position(|c| c == name).unwrap_or_else(|| panic!("{name}: {v}"));
    v["rows"].as_array().unwrap().iter().map(|r| r[i].clone()).collect()
}

fn pred(field: &str, op: &str, value: Value) -> Value {
    json!({"field": field, "op": op, "value": value})
}

impl Fx {
    async fn search(&self, args: Value) -> Value {
        self.h.ok(&self.token, "search_messages", args).await
    }
    async fn err(&self, args: Value) -> String {
        self.h.err(&self.token, "search_messages", args).await
    }
    fn key(&self, id: &Value) -> &'static str {
        self.ids.iter().find(|(_, v)| json!(v) == *id).map(|(k, _)| *k).unwrap_or_else(|| panic!("unknown {id}"))
    }
    async fn message_keys(&self, filter: Value) -> Vec<&'static str> {
        let v = self.search(json!({"where": filter, "select": ["message_id"], "limit": 100})).await;
        let mut out: Vec<_> = col(&v, "message_id").iter().map(|id| self.key(id)).collect();
        out.sort();
        out
    }
    /// Thread ids of a thread-view search, in result order.
    async fn threads(&self, mut args: Value) -> Vec<String> {
        args["group_by"] = json!("thread");
        args["select"] = json!(["thread_id"]);
        args["limit"] = json!(100);
        let v = self.search(args).await;
        col(&v, "thread_id").iter().map(|t| t.as_str().unwrap().to_string()).collect()
    }
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn strs(v: &[&str]) -> Vec<String> {
    sorted(v.iter().map(|s| s.to_string()).collect())
}

#[tokio::test]
async fn from_self_matches_own_address_and_sent_label() {
    let fx = fixture().await;
    assert_eq!(
        fx.message_keys(pred("from_self", "eq", json!(true))).await,
        vec!["a2", "c1", "d2", "e2", "f1", "g2", "j1"]
    );
    // Negation is the exact complement within the visible rows (i2 is in the trash).
    assert_eq!(
        fx.message_keys(pred("from_self", "eq", json!(false))).await,
        vec!["a1", "b1", "d1", "e1", "e3", "g1", "h1", "i1"]
    );
    assert_eq!(
        fx.message_keys(json!({"all": [pred("from_self", "eq", json!(true)), pred("label", "eq", json!("INBOX"))]}))
            .await,
        vec!["j1"]
    );
    // As a column.
    let v = fx.search(json!({"select": ["message_id", "from_self"], "limit": 100, "include_spam_trash": true})).await;
    let got: HashMap<&str, bool> = col(&v, "message_id")
        .iter()
        .zip(col(&v, "from_self"))
        .map(|(id, s)| (fx.key(id), s.as_bool().unwrap()))
        .collect();
    for k in ["a2", "c1", "d2", "e2", "f1", "g2", "i2", "j1"] {
        assert!(got[k], "{k}");
    }
    for k in ["a1", "b1", "d1", "e1", "e3", "g1", "h1", "i1"] {
        assert!(!got[k], "{k}");
    }
    assert_eq!(got.len(), 16);
    // Only meaningful for searches: watches refuse it.
    let w =
        fx.h.err(
            &fx.token,
            "create_watch",
            json!({"account": "info", "kind": "query", "where": pred("from_self", "eq", json!(false))}),
        )
        .await;
    assert_eq!(w, "invalid_argument");
}

#[tokio::test]
async fn thread_rows_carry_latest_message_and_reply_status() {
    let fx = fixture().await;
    let audit_before = fx.h.audit_count().await;
    let v = fx
        .search(json!({"group_by": "thread", "limit": 100, "select": ["thread_id", "message_id", "is_draft", "from",
            "received_at", "message_count", "matched_count", "last_sender_is_self", "last_inbound_at",
            "last_outbound_at", "awaiting_reply"]}))
        .await;
    assert_eq!(fx.h.audit_count().await, audit_before + 1, "one audit record per call");
    assert_eq!(v["coverage"], "complete", "{v}");
    let tids: Vec<&str> = v["rows"].as_array().unwrap().iter().map(|r| r[0].as_str().unwrap()).collect();
    // Newest thread activity first (drafts included, spam and trash not).
    assert_eq!(tids, vec!["T5", "T4", "T2", "T1", "T3", "T6", "T7", "T8", "T9", "T10"]);
    let row = |t: &str| -> HashMap<String, Value> {
        let r = v["rows"].as_array().unwrap().iter().find(|r| r[0] == t).unwrap().as_array().unwrap().clone();
        v["columns"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).zip(r).collect()
    };
    let ts = |hm: &str| json!(dove::util::rfc3339_ms(at(hm)));

    let t1 = row("T1");
    assert_eq!(fx.key(&t1["message_id"]), "a2");
    assert_eq!(t1["message_count"], 2);
    assert_eq!(t1["matched_count"], 2);
    assert_eq!(t1["last_sender_is_self"], true);
    assert_eq!(t1["awaiting_reply"], false);
    assert_eq!(t1["last_inbound_at"], ts("10:00:00"));
    assert_eq!(t1["last_outbound_at"], ts("11:00:00"));
    assert_eq!(t1["received_at"], ts("11:00:00"));

    // The latest message is the draft, but drafts never count as a reply.
    let t4 = row("T4");
    assert_eq!(fx.key(&t4["message_id"]), "d2");
    assert_eq!(t4["is_draft"], true);
    assert_eq!(t4["awaiting_reply"], true);
    assert_eq!(t4["last_sender_is_self"], false);
    assert_eq!(t4["last_outbound_at"], Value::Null);

    let t3 = row("T3");
    assert_eq!((t3["awaiting_reply"].clone(), t3["last_sender_is_self"].clone()), (json!(false), json!(true)));
    assert_eq!(t3["last_inbound_at"], Value::Null);
    assert_eq!(row("T5")["awaiting_reply"], true);
    assert_eq!(row("T5")["message_count"], 3);
    assert_eq!(row("T6")["awaiting_reply"], false);
    assert_eq!(row("T7")["awaiting_reply"], false, "a reply at the same instant counts");
    assert_eq!(row("T10")["awaiting_reply"], false, "mail from the own address counts as from self");
    // Another mailbox's messages with the same thread id never count.
    assert_eq!(row("T8")["message_count"], 1);
    assert_eq!(row("T8")["awaiting_reply"], true);
    // Trash follows the spam/trash policy for the status too.
    assert_eq!(row("T9")["message_count"], 1);
    assert_eq!(row("T9")["awaiting_reply"], true);
    let all = fx
        .search(json!({"group_by": "thread", "include_spam_trash": true, "limit": 100,
            "where": pred("thread_id", "eq", json!("T9")), "select": ["message_count", "awaiting_reply"]}))
        .await;
    assert_eq!(all["rows"], json!([[2, false]]));

    // Default projection.
    let d = fx.search(json!({"group_by": "thread", "limit": 1})).await;
    assert_eq!(
        d["columns"],
        json!(["ref", "thread_id", "received_at", "from", "subject", "message_count", "awaiting_reply"])
    );
}

#[tokio::test]
async fn filters_pick_threads_and_status_ignores_the_filter() {
    let fx = fixture().await;
    // Any matching message selects the thread; the status still sees the SENT reply outside the filter.
    let v = fx
        .search(json!({"group_by": "thread", "where": pred("label", "eq", json!("INBOX")), "limit": 100,
            "select": ["thread_id", "message_count", "matched_count", "awaiting_reply"]}))
        .await;
    let rows = v["rows"].as_array().unwrap();
    let t1 = rows.iter().find(|r| r[0] == "T1").unwrap();
    assert_eq!(t1, &json!(["T1", 2, 1, false]));
    assert_eq!(
        sorted(col(&v, "thread_id").iter().map(|t| t.as_str().unwrap().to_string()).collect()),
        strs(&["T1", "T10", "T2", "T4", "T5", "T7", "T8", "T9"])
    );

    let open = strs(&["T2", "T4", "T5", "T8", "T9"]);
    assert_eq!(fx.threads(json!({"awaiting_reply": true})).await, vec!["T5", "T4", "T2", "T8", "T9"]);
    assert_eq!(sorted(fx.threads(json!({"awaiting_reply": false})).await), strs(&["T1", "T10", "T3", "T6", "T7"]));
    // The typical question: threads with mail from others in a window that wait for an answer.
    let window = json!({"all": [pred("from_self", "eq", json!(false)),
        pred("received_at", "gte", json!("2026-11-02T05:00:00Z"))]});
    assert_eq!(sorted(fx.threads(json!({"awaiting_reply": true, "where": window})).await), strs(&["T2", "T4", "T5"]));
    let c = fx.search(json!({"group_by": "thread", "awaiting_reply": true, "count_only": true})).await;
    assert_eq!(c["count"], open.len());
    let c = fx.search(json!({"group_by": "thread", "count_only": true})).await;
    assert_eq!(c["count"], 10);
}

#[tokio::test]
async fn thread_cursor_pages_without_gaps_or_duplicates() {
    let fx = fixture().await;
    for (args, want) in [
        (json!({}), vec!["T5", "T4", "T2", "T1", "T3", "T6", "T7", "T8", "T9", "T10"]),
        (
            json!({"order_by": [{"field": "received_at", "dir": "asc"}]}),
            vec!["T10", "T9", "T8", "T7", "T6", "T3", "T1", "T2", "T4", "T5"],
        ),
        (json!({"awaiting_reply": true}), vec!["T5", "T4", "T2", "T8", "T9"]),
    ] {
        let mut a = args.clone();
        a["group_by"] = json!("thread");
        a["select"] = json!(["thread_id"]);
        a["limit"] = json!(3);
        let mut v = fx.search(a).await;
        let mut got: Vec<String> = vec![];
        loop {
            got.extend(col(&v, "thread_id").iter().map(|t| t.as_str().unwrap().to_string()));
            let Some(c) = v["next_cursor"].as_str() else { break };
            v = fx.search(json!({"cursor": c})).await;
            assert_eq!(v["changed_since_first_page"], false);
        }
        assert_eq!(got, want, "{args}");
    }
}

#[tokio::test]
async fn thread_view_rejects_bad_combinations_and_foreign_mailboxes() {
    let fx = fixture().await;
    for args in [
        json!({"awaiting_reply": true}),
        json!({"select": ["message_count"]}),
        json!({"group_by": "thread", "order_by": [{"field": "size_bytes"}]}),
        json!({"group_by": "conversation"}),
        json!({"group_by": "thread", "awaiting_reply": "yes"}),
        json!({"source": "gmail", "gmail_query": "x", "group_by": "thread"}),
        json!({"group_by": "thread", "count_only": true, "select": ["thread_id"]}),
    ] {
        assert_eq!(fx.err(args.clone()).await, "invalid_argument", "{args}");
    }
    assert_eq!(fx.err(json!({"group_by": "thread", "accounts": ["secret"]})).await, "not_found");
    // A thread id that exists only in an ungranted mailbox yields nothing.
    let v = fx
        .search(json!({"group_by": "thread", "where": pred("thread_id", "eq", json!("T8")),
        "select": ["message_count"]}))
        .await;
    assert_eq!(v["rows"], json!([[1]]));
}

/// Own addresses are per mailbox: mail between two of the caller's mailboxes is inbound for the receiving one.
#[tokio::test]
async fn own_addresses_are_per_mailbox() {
    let h = Harness::start().await;
    let info = h.mailbox("info", INFO);
    let billing = h.mailbox("billing", "billing@acme.test");
    h.project("acme", &["info", "billing"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read"), g("billing", "read")]).await;
    h.google.add_message(INFO, spec("billing@acme.test", "From billing", "X1", "10:00:00", &["INBOX"]));
    h.google.add_message("billing@acme.test", spec(INFO, "From info", "X2", "11:00:00", &["INBOX"]));
    for (alias, aid) in [("info", &info), ("billing", &billing)] {
        h.admin(AdminRequest::IndexEnable { alias: alias.into() }).await.unwrap();
        sync_account(h.app(), aid).await.unwrap();
    }
    let v = h.ok(&token, "search_messages", json!({"select": ["subject", "from_self"]})).await;
    assert_eq!(v["rows"], json!([["From info", false], ["From billing", false]]));
    let v = h
        .ok(&token, "search_messages", json!({"where": pred("from_self", "eq", json!(true)), "count_only": true}))
        .await;
    assert_eq!(v["count"], 0);
    let v =
        h.ok(&token, "search_messages", json!({"group_by": "thread", "select": ["thread_id", "awaiting_reply"]})).await;
    assert_eq!(v["rows"], json!([["X2", true], ["X1", true]]));
}

// ------------------------------------------------------------------ IMAP

const PW: &str = "app-password-abcd";

fn raw(from: &str, subject: &str, msg_id: &str, in_reply_to: Option<&str>) -> Vec<u8> {
    let refs = in_reply_to.map(|r| format!("In-Reply-To: <{r}>\r\nReferences: <{r}>\r\n")).unwrap_or_default();
    format!(
        "From: {from}\r\nTo: someone@example.com\r\nSubject: {subject}\r\nMessage-ID: <{msg_id}>\r\n{refs}\
         Date: Mon, 02 Nov 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhi\r\n"
    )
    .into_bytes()
}

fn thread_rows(v: &Value) -> Vec<(i64, bool, bool)> {
    let (n, a, s) = (col(v, "message_count"), col(v, "awaiting_reply"), col(v, "last_sender_is_self"));
    n.iter()
        .zip(a)
        .zip(s)
        .map(|((n, a), s)| (n.as_i64().unwrap(), a.as_bool().unwrap(), s.as_bool().unwrap()))
        .collect()
}

/// Plain IMAP: the Sent folder is indexed, a reply filed there joins the inbound message's derived thread, and alias
/// changes apply to the next query without a resync.
#[tokio::test]
async fn imap_sent_replies_join_the_thread_and_aliases_apply_at_once() {
    let mut h = Harness::start().await;
    h.imap = FakeImap::start().await;
    let me = "me@example.org";
    let u = h.imap_mailbox("me", me).await;
    h.project("p", &["me"]).await;
    let token = h.token("p", "agent", vec![g("me", "read")]).await;
    let t0 = dove::util::now_unix() - 7200;
    h.imap.add_message_at(&u.user, "INBOX", &raw("Anna <anna@example.com>", "Project", "root@x.test", None), &[], t0);
    h.imap.add_message_at(
        &u.user,
        "Sent",
        &raw(me, "Re: Project", "reply@x.test", Some("root@x.test")),
        &["\\Seen"],
        t0 + 60,
    );
    // A copy of mail sent from an alias Dove does not know yet, in INBOX only.
    h.imap.add_message_at(
        &u.user,
        "INBOX",
        &raw("Sales <sales@alias.example>", "Promo", "promo@x.test", None),
        &[],
        t0 + 120,
    );
    h.admin(AdminRequest::IndexEnable { alias: "me".into() }).await.unwrap();
    let r = sync_steps(h.app(), &u.account_id, usize::MAX).await.unwrap();
    assert_eq!(r.error, None, "{r:?}");

    let sel = json!(["subject", "message_count", "awaiting_reply", "last_sender_is_self"]);
    let v = h.ok(&token, "search_messages", json!({"group_by": "thread", "select": sel})).await;
    assert_eq!(col(&v, "subject"), vec![json!("Promo"), json!("Re: Project")], "{v}");
    assert_eq!(thread_rows(&v), vec![(1, true, false), (2, false, true)]);
    let sent = h
        .ok(&token, "search_messages", json!({"where": pred("label", "eq", json!("SENT")), "select": ["from_self"]}))
        .await;
    assert_eq!(sent["rows"], json!([[true]]), "the Sent folder is indexed as SENT");

    h.admin(AdminRequest::AccountsAliasAdd {
        account: "me".into(),
        address: "Sales@Alias.example".into(),
        name: None,
        envelope: false,
    })
    .await
    .unwrap();
    let v = h.ok(&token, "search_messages", json!({"group_by": "thread", "select": sel})).await;
    assert_eq!(thread_rows(&v), vec![(1, false, true), (2, false, true)]);
    let n = h
        .ok(&token, "search_messages", json!({"where": pred("from_self", "eq", json!(true)), "count_only": true}))
        .await;
    assert_eq!(n["count"], 2);
}

/// Gmail over IMAP: the reply's copy in `[Gmail]/Sent Mail` comes in through All Mail with the SENT label and the same
/// derived thread id.
#[tokio::test]
async fn gmail_imap_sent_replies_join_the_thread() {
    let mut h = Harness::start().await;
    h.imap = FakeImap::start_with(Opts { gmail: true, qresync: false, ..Opts::default() }).await;
    let me = "me@gmail.com";
    h.imap.gmail_user(me, PW);
    h.admin(h.connect_imap_request("me", me, PW)).await.expect("connect-imap");
    let aid: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT id FROM accounts WHERE alias = 'me'", [], |r| r.get(0))?))
        .await
        .unwrap();
    h.project("p", &["me"]).await;
    let token = h.token("p", "agent", vec![g("me", "read")]).await;
    let t0 = dove::util::now_unix() - 7200;
    h.imap.gm_add(me, &["INBOX"], &raw("Anna <anna@example.com>", "Project", "root@x.test", None), &[], t0);
    h.imap.gm_add(
        me,
        &["[Gmail]/Sent Mail"],
        &raw(me, "Re: Project", "reply@x.test", Some("root@x.test")),
        &["\\Seen"],
        t0 + 60,
    );
    h.imap.gm_add(me, &["INBOX"], &raw("Bob <bob@example.com>", "Open", "open@x.test", None), &[], t0 + 120);
    h.admin(AdminRequest::IndexEnable { alias: "me".into() }).await.unwrap();
    let r = sync_steps(h.app(), &aid, usize::MAX).await.unwrap();
    assert_eq!(r.error, None, "{r:?}");
    let v = h
        .ok(
            &token,
            "search_messages",
            json!({"group_by": "thread",
            "select": ["subject", "message_count", "awaiting_reply", "last_sender_is_self"]}),
        )
        .await;
    assert_eq!(col(&v, "subject"), vec![json!("Open"), json!("Re: Project")], "{v}");
    assert_eq!(thread_rows(&v), vec![(1, true, false), (2, false, true)]);
}
