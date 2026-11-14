//! `no_reply_by` on one message (PLAN A70): the deadline fires with the message's id, a reply from someone else ends
//! the watch quietly (at indexing time and, if the hook missed it, at the deadline), the owner's own follow-ups do not
//! count (address, alias or only the `SENT` label), a reply in the same second as the baseline counts while the
//! baseline's own messages do not, a restart in between loses nothing, and ids outside the mailbox are `not_found`.

mod support;

use dove::admin::AdminRequest;
use dove::index::sync::sync_account;
use dove::util;
use dove::watch;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{Harness, g};

const OWNER: &str = "info@acme.test";

fn spec(from: &str, thread: &str, labels: &[&str], at_ms: i64) -> MessageSpec {
    MessageSpec {
        from: from.into(),
        to: vec!["bob@example.com".into()],
        subject: "Offer".into(),
        text: Some("hello there".into()),
        labels: labels.iter().map(|l| l.to_string()).collect(),
        thread_id: Some(thread.into()),
        internal_date_ms: at_ms,
        ..Default::default()
    }
}

struct Fx {
    h: Harness,
    info: String,
    token: String,
    /// The owner's sent mail in thread `thr1`, one minute old.
    sent: String,
    /// A message of the `other` mailbox, which the token may not read.
    foreign: String,
}

/// Gmail mailboxes `info` (granted, indexed, the owner's sent mail in `thr1`) and `other` (indexed, not granted).
async fn gmail() -> Fx {
    let h = Harness::start().await;
    let info = h.mailbox("info", OWNER);
    let other = h.mailbox("other", "other@acme.test");
    h.project("acme", &["info", "other"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    let minute_ago = (util::now_unix() - 60) * 1000;
    let sent = h.google.add_message(OWNER, spec(OWNER, "thr1", &["SENT"], minute_ago));
    let foreign = h.google.add_message("other@acme.test", spec("x@example.com", "thrx", &["INBOX"], minute_ago));
    for (alias, id) in [("info", &info), ("other", &other)] {
        h.admin(AdminRequest::IndexEnable { alias: alias.into() }).await.unwrap();
        let r = sync_account(h.app(), id).await.unwrap();
        assert_eq!((r.stage.as_str(), r.error.as_deref()), ("ready", None), "{r:?}");
    }
    Fx { h, info, token, sent, foreign }
}

impl Fx {
    async fn sync(&self) {
        let r = sync_account(self.h.app(), &self.info).await.unwrap();
        assert_eq!(r.error, None, "{r:?}");
    }

    async fn no_reply_to(&self, message_id: &str, deadline: i64) -> Value {
        let args = json!({ "account": "info", "kind": "no_reply_by", "message_id": message_id,
                           "deadline": util::rfc3339(deadline) });
        self.h.ok(&self.token, "create_watch", args).await
    }

    async fn events(&self) -> Vec<Value> {
        self.h.ok(&self.token, "list_watch_events", json!({})).await["events"].as_array().unwrap().clone()
    }

    async fn state(&self, id: &str) -> (String, Option<String>) {
        state_of(&self.h, &self.token, id).await
    }
}

async fn state_of(h: &Harness, token: &str, id: &str) -> (String, Option<String>) {
    let ws = h.ok(token, "list_watches", json!({})).await;
    let w = ws["watches"].as_array().unwrap().iter().find(|w| w["watch_id"] == id).unwrap().clone();
    (w["state"].as_str().unwrap().to_string(), w["end_reason"].as_str().map(str::to_string))
}

/// Puts an ended watch back to active, as if the sync hook had never seen the reply (it does not run during a
/// rebuild or backfill): the deadline check must then find the reply by itself.
async fn reopen(h: &Harness, id: &str) {
    let id = id.to_string();
    h.app()
        .store
        .call(move |c| {
            let n = c.execute(
                "UPDATE watches SET state = 'active', ended_at = NULL, end_reason = NULL WHERE id = ?1",
                [&id],
            )?;
            assert_eq!(n, 1);
            Ok(())
        })
        .await
        .unwrap();
}

fn active() -> (String, Option<String>) {
    ("active".into(), None)
}

fn ended(reason: &str) -> (String, Option<String>) {
    ("ended".into(), Some(reason.into()))
}

#[tokio::test]
async fn silence_fires_at_the_deadline_with_the_message_id_and_own_follow_ups_do_not_count() {
    let fx = gmail().await;
    let h = &fx.h;
    let deadline = util::now_unix() + 600;
    let v = fx.no_reply_to(&fx.sent, deadline).await;
    let w = v["watch_id"].as_str().unwrap().to_string();
    assert_eq!((v["thread_id"].as_str(), v["message_id"].as_str()), (Some("thr1"), Some(fx.sent.as_str())));
    assert_eq!(v["state"], "active");

    // The owner's own follow-ups: from the mailbox address, and from a Gmail send-as address Dove only knows by the
    // SENT label (IMAP aliases are covered in watches_e2e). Neither is a reply.
    h.google.add_message(OWNER, spec(OWNER, "thr1", &["SENT"], 0));
    h.google.add_message(OWNER, spec("sales@acme-sendas.test", "thr1", &["SENT"], 0));
    // Not a reply either: mail from someone else that landed in spam.
    h.google.add_message(OWNER, spec("bob@example.com", "thr1", &["SPAM"], 0));
    fx.sync().await;
    assert_eq!(fx.state(&w).await, active());
    // At the deadline itself the check still sees no reply (the grace period covers an index not synced yet).
    assert_eq!(watch::tick(h.app(), deadline + 1).await.unwrap().no_reply_fired, 0);
    assert_eq!(fx.state(&w).await, active());

    assert_eq!(watch::tick(h.app(), deadline + watch::NO_REPLY_GRACE_SECS).await.unwrap().no_reply_fired, 1);
    assert_eq!(watch::tick(h.app(), deadline + watch::NO_REPLY_GRACE_SECS + 30).await.unwrap().no_reply_fired, 0);
    let ev = fx.events().await;
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!((ev[0]["watch_id"].as_str(), ev[0]["kind"].as_str()), (Some(w.as_str()), Some("no_reply_by")));
    // The event names the unanswered message, so the agent can read it and follow up.
    assert_eq!((ev[0]["message_id"].as_str(), ev[0]["thread_id"].as_str()), (Some(fx.sent.as_str()), Some("thr1")));
    assert!(ev[0]["received_at"].is_string(), "{ev:?}");
    assert_eq!(fx.state(&w).await, ended("fired"));
}

#[tokio::test]
async fn a_reply_from_someone_else_ends_the_watch_quietly() {
    let fx = gmail().await;
    let h = &fx.h;
    let deadline = util::now_unix() + 600;
    let w = fx.no_reply_to(&fx.sent, deadline).await["watch_id"].as_str().unwrap().to_string();
    h.google.add_message(OWNER, spec("bob@example.com", "thr1", &["INBOX"], 0));
    fx.sync().await;
    assert_eq!(fx.state(&w).await, ended("replied"), "the sync hook ends it");

    // The deadline check finds the reply by itself when the hook missed it.
    reopen(h, &w).await;
    assert_eq!(watch::tick(h.app(), deadline + watch::NO_REPLY_GRACE_SECS).await.unwrap().no_reply_fired, 0);
    assert_eq!(fx.state(&w).await, ended("replied"));
    assert!(fx.events().await.is_empty(), "a reply never produces an event");

    // A message that is already answered: the watch is recorded as ended at once.
    let again = fx.no_reply_to(&fx.sent, deadline).await;
    assert_eq!((again["state"].as_str(), again["end_reason"].as_str()), (Some("ended"), Some("replied")));
    assert_eq!(watch::tick(h.app(), deadline + watch::NO_REPLY_GRACE_SECS).await.unwrap().no_reply_fired, 0);
    assert!(fx.events().await.is_empty());
}

#[tokio::test]
async fn a_restart_between_creation_and_deadline_loses_nothing() {
    let mut fx = gmail().await;
    let deadline = util::now_unix() + 600;
    let silent = fx.no_reply_to(&fx.sent, deadline).await["watch_id"].as_str().unwrap().to_string();
    let other = fx.h.google.add_message(OWNER, spec(OWNER, "thr2", &["SENT"], (util::now_unix() - 30) * 1000));
    fx.sync().await;
    let answered = fx.no_reply_to(&other, deadline).await["watch_id"].as_str().unwrap().to_string();

    fx.h.restart().await;
    // After the restart the stored baseline still decides: the reply in thr2 ends that watch, silence in thr1 fires
    // with the stored message id.
    fx.h.google.add_message(OWNER, spec("bob@example.com", "thr2", &["INBOX"], 0));
    fx.sync().await;
    assert_eq!(fx.state(&answered).await, ended("replied"));
    assert_eq!(watch::tick(fx.h.app(), deadline + watch::NO_REPLY_GRACE_SECS).await.unwrap().no_reply_fired, 1);
    let ev = fx.events().await;
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(
        (ev[0]["watch_id"].as_str(), ev[0]["message_id"].as_str()),
        (Some(silent.as_str()), Some(fx.sent.as_str()))
    );
}

#[tokio::test]
async fn ids_outside_the_mailbox_are_not_found_and_arguments_are_checked() {
    let fx = gmail().await;
    let h = &fx.h;
    let deadline = util::rfc3339(util::now_unix() + 600);
    let token = &fx.token;
    let err = |args: Value| async move { h.err(token, "create_watch", args).await };
    let nr = |extra: Value| {
        let mut a = json!({ "account": "info", "kind": "no_reply_by", "deadline": deadline });
        a.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        a
    };
    // A message of a mailbox the token may not read, through the readable mailbox or its own alias, an unknown id and
    // a malformed one: all the same not_found.
    assert_eq!(err(nr(json!({ "message_id": fx.foreign }))).await, "not_found");
    let mut via_other = nr(json!({ "message_id": fx.foreign }));
    via_other["account"] = json!("other");
    assert_eq!(err(via_other).await, "not_found");
    assert_eq!(err(nr(json!({ "message_id": "doesnotexist" }))).await, "not_found");
    assert_eq!(err(nr(json!({ "message_id": "../x" }))).await, "not_found");

    // Exactly one target; message_id only for no_reply_by; a draft cannot be answered.
    assert_eq!(err(nr(json!({ "message_id": fx.sent, "thread_id": "thr1" }))).await, "invalid_argument");
    assert_eq!(err(nr(json!({}))).await, "invalid_argument");
    assert_eq!(
        err(json!({ "account": "info", "kind": "thread_reply", "message_id": fx.sent })).await,
        "invalid_argument"
    );
    let draft = h.google.add_message(OWNER, spec(OWNER, "thr3", &["DRAFT"], 0));
    fx.sync().await;
    assert_eq!(err(nr(json!({ "message_id": draft }))).await, "invalid_argument");
    // Nothing was created by any of these.
    assert_eq!(h.ok(&fx.token, "list_watches", json!({})).await["watches"], json!([]));
}

// ------------------------------------------------------------------ IMAP: second-precision dates

fn imap_raw(from: &str, msg_id: &str, refs: Option<&str>) -> Vec<u8> {
    let refs = refs.map(|r| format!("In-Reply-To: {r}\r\nReferences: {r}\r\n")).unwrap_or_default();
    format!(
        "From: {from}\r\nTo: ann@example.org\r\nSubject: Offer\r\nMessage-ID: {msg_id}\r\n{refs}\
         Date: Thu, 12 Nov 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Hello there.\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn imap_replies_in_the_baselines_second_count_but_the_baseline_does_not() {
    let h = Harness::start_with(|c| c.index.poll_interval_secs = 3600).await;
    let u = h.imap_mailbox("box", "box@example.org").await;
    h.project("p", &["box"]).await;
    let token = h.token("p", "agent", vec![g("box", "read")]).await;
    let t0 = util::now_unix() - 120;
    // Thread A: the owner's sent mail. Thread B: ann's question, the thread's newest message.
    h.imap.add_message_at(&u.user, "Sent", &imap_raw("box@example.org", "<a@example.org>", None), &["\\Seen"], t0);
    h.imap.add_message_at(&u.user, "INBOX", &imap_raw("ann@example.org", "<b@example.org>", None), &[], t0);
    h.admin(AdminRequest::IndexEnable { alias: "box".into() }).await.unwrap();
    let sync = || async {
        let r = dove::index::imap_sync::sync_steps(h.app(), &u.account_id, usize::MAX).await.unwrap();
        assert_eq!(r.error, None, "{r:?}");
    };
    sync().await;
    let s = h.ok(&token, "search_messages", json!({ "select": ["message_id", "thread_id", "from_self"] })).await;
    let rows = s["rows"].as_array().unwrap();
    let mine = rows.iter().find(|r| r[2] == true).unwrap();
    let theirs = rows.iter().find(|r| r[2] == false).unwrap();
    let (sent, thread_b) = (mine[0].as_str().unwrap().to_string(), theirs[1].as_str().unwrap().to_string());

    let deadline = util::now_unix() + 600;
    let create = |args: Value| {
        let (h, token) = (&h, &token);
        async move {
            let mut a = json!({ "account": "box", "kind": "no_reply_by", "deadline": util::rfc3339(deadline) });
            a.as_object_mut().unwrap().extend(args.as_object().unwrap().clone());
            h.ok(token, "create_watch", a).await["watch_id"].as_str().unwrap().to_string()
        }
    };
    let on_message = create(json!({ "message_id": sent })).await;
    let on_thread = create(json!({ "thread_id": thread_b })).await;

    // Ann answers the sent mail within the same second (IMAP INTERNALDATE has no milliseconds).
    h.imap.add_message_at(
        &u.user,
        "INBOX",
        &imap_raw("ann@example.org", "<a-re@example.org>", Some("<a@example.org>")),
        &[],
        t0,
    );
    sync().await;
    assert_eq!(state_of(&h, &token, &on_message).await, ended("replied"), "the sync hook counts it");
    // And the deadline check counts it too; ann's question, the baseline of the thread watch, is no reply to itself.
    reopen(&h, &on_message).await;
    assert_eq!(watch::tick(h.app(), deadline + watch::NO_REPLY_GRACE_SECS).await.unwrap().no_reply_fired, 1);
    assert_eq!(state_of(&h, &token, &on_message).await, ended("replied"));
    assert_eq!(state_of(&h, &token, &on_thread).await, ended("fired"));
    let ev = h.ok(&token, "list_watch_events", json!({})).await["events"].as_array().unwrap().clone();
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(
        (ev[0]["watch_id"].as_str(), ev[0]["thread_id"].as_str()),
        (Some(on_thread.as_str()), Some(thread_b.as_str()))
    );
    assert!(ev[0]["message_id"].is_null(), "a thread watch names no message");
}
