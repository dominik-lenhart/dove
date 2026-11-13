//! Watches, watch events and webhook sinks (design 0.2 section 3): authorization and ownership, each kind against
//! the real sync engines (Gmail history via the fake Google server, IMAP polling and IDLE via the fake IMAP server),
//! `no_reply_by` with a chosen clock, content-free events (canary), signed sink delivery with bounded retries, the
//! gateway's sink allowlist, retention, and watches ending on revoke, grant loss, disable and removal.

mod support;

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dove::admin::{AdminRequest, Password};
use dove::index::sync::sync_account;
use dove::util;
use dove::watch;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use support::fake_google::MessageSpec;
use support::harness::{Harness, g};

const OWNER: &str = "info@acme.test";
const SECRET: &str = "0123456789abcdef0123456789abcdef-sink-secret";

fn spec(from: &str, subject: &str, thread: Option<&str>) -> MessageSpec {
    MessageSpec {
        from: from.into(),
        to: vec![OWNER.into()],
        subject: subject.into(),
        text: Some("hello there".into()),
        labels: vec!["INBOX".into(), "UNREAD".into()],
        thread_id: thread.map(Into::into),
        ..Default::default()
    }
}

struct Fx {
    h: Harness,
    info: String,
    token: String,
}

/// Gmail mailbox `info` (indexed, one thread `thr1` from bob) plus `other` (indexed, not granted to `agent`).
async fn gmail() -> Fx {
    let h = Harness::start().await;
    let info = h.mailbox("info", OWNER);
    let other = h.mailbox("other", "other@acme.test");
    h.project("acme", &["info", "other"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    h.google.add_message(OWNER, spec("bob@example.com", "Kickoff", Some("thr1")));
    for (alias, id) in [("info", &info), ("other", &other)] {
        h.admin(AdminRequest::IndexEnable { alias: alias.into() }).await.unwrap();
        let r = sync_account(h.app(), id).await.unwrap();
        assert_eq!((r.stage.as_str(), r.error.as_deref()), ("ready", None), "{r:?}");
    }
    Fx { h, info, token }
}

impl Fx {
    async fn sync(&self) {
        let r = sync_account(self.h.app(), &self.info).await.unwrap();
        assert_eq!(r.error, None, "{r:?}");
    }

    async fn events(&self, token: &str, args: Value) -> Vec<Value> {
        let v = self.h.ok(token, "list_watch_events", args).await;
        v["events"].as_array().unwrap().clone()
    }

    async fn watch(&self, args: Value) -> String {
        let v = self.h.ok(&self.token, "create_watch", args).await;
        v["watch_id"].as_str().unwrap().to_string()
    }
}

fn of_watch<'a>(events: &'a [Value], id: &str) -> Vec<&'a Value> {
    events.iter().filter(|e| e["watch_id"] == id).collect()
}

#[tokio::test]
async fn watches_belong_to_their_connection_and_mailbox_scope() {
    let fx = gmail().await;
    let h = &fx.h;
    let b = h.token("acme", "other-agent", vec![g("info", "read")]).await;
    for name in ["create_watch", "list_watches", "delete_watch", "list_watch_events"] {
        assert!(h.tool_names(&fx.token).await.contains(&name.to_string()), "{name}");
    }

    let audit = h.audit_count().await;
    let w = fx.watch(json!({ "account": "info", "kind": "from", "from": "carol@example.com" })).await;
    assert_eq!(h.audit_count().await, audit + 1, "one audit record per call");
    let listed = h.ok(&fx.token, "list_watches", json!({})).await;
    assert_eq!(listed["watches"].as_array().unwrap().len(), 1);
    assert_eq!(listed["watches"][0]["from"], "carol@example.com");

    // Another connection on the same mailbox sees nothing and cannot touch the watch.
    assert_eq!(h.ok(&b, "list_watches", json!({})).await["watches"], json!([]));
    assert_eq!(h.err(&b, "delete_watch", json!({ "watch_id": w })).await, "not_found");
    assert_eq!(h.err(&b, "list_watch_events", json!({ "watch_id": w })).await, "not_found");
    assert_eq!(h.err(&fx.token, "delete_watch", json!({ "watch_id": "w_doesnotexist" })).await, "not_found");
    assert_eq!(h.err(&fx.token, "delete_watch", json!({ "watch_id": "../x" })).await, "not_found");

    // Mailboxes outside the grants are not_found, exactly like unknown ones.
    let a =
        h.err(&fx.token, "create_watch", json!({ "account": "other", "kind": "from", "from": "x@example.com" })).await;
    let u =
        h.err(&fx.token, "create_watch", json!({ "account": "nope", "kind": "from", "from": "x@example.com" })).await;
    assert_eq!((a.as_str(), u.as_str()), ("not_found", "not_found"));
    // Unknown threads are not_found too.
    let t = h
        .err(&fx.token, "create_watch", json!({ "account": "info", "kind": "thread_reply", "thread_id": "nothread" }))
        .await;
    assert_eq!(t, "not_found");

    // Events of one connection's watch never reach another connection.
    h.google.add_message(OWNER, spec("carol@example.com", "Hi", None));
    fx.sync().await;
    assert_eq!(fx.events(&fx.token, json!({})).await.len(), 1);
    assert_eq!(fx.events(&b, json!({})).await.len(), 0);

    h.ok(&fx.token, "delete_watch", json!({ "watch_id": w })).await;
    assert_eq!(h.ok(&fx.token, "list_watches", json!({})).await["watches"], json!([]));
    assert_eq!(fx.events(&fx.token, json!({})).await.len(), 0, "events go with their watch");
}

#[tokio::test]
async fn gmail_history_sync_fires_each_kind_once() {
    let fx = gmail().await;
    let h = &fx.h;
    let thread = fx.watch(json!({ "account": "info", "kind": "thread_reply", "thread_id": "thr1" })).await;
    let addr = fx.watch(json!({ "account": "info", "kind": "from", "from": "Carol@Example.com" })).await;
    let domain = fx.watch(json!({ "account": "info", "kind": "from", "from": "@partner.test" })).await;
    let query = fx
        .watch(json!({ "account": "info", "kind": "query",
                       "where": { "field": "subject", "op": "terms", "value": "invoice" } }))
        .await;

    // Not matching anything: an unrelated sender, and the owner's own message in the watched thread.
    h.google.add_message(OWNER, spec("zed@elsewhere.test", "Lunch", None));
    let mut own = spec(OWNER, "Re: Kickoff", Some("thr1"));
    own.labels = vec!["SENT".into()];
    h.google.add_message(OWNER, own);
    fx.sync().await;
    assert_eq!(fx.events(&fx.token, json!({})).await, Vec::<Value>::new());

    let reply = h.google.add_message(OWNER, spec("bob@example.com", "Re: Kickoff", Some("thr1")));
    let carol = h.google.add_message(OWNER, spec("carol@example.com", "Invoice 42", None));
    let partner = h.google.add_message(OWNER, spec("ann@partner.test", "Status", None));
    // A subdomain is not the watched domain (exact domain, like from_domain in search).
    h.google.add_message(OWNER, spec("ann@sub.partner.test", "Status", None));
    fx.sync().await;
    let ev = fx.events(&fx.token, json!({})).await;
    let ids =
        |w: &str| of_watch(&ev, w).iter().map(|e| e["message_id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(ids(&thread), vec![reply.clone()]);
    assert_eq!(ids(&addr), vec![carol.clone()]);
    assert_eq!(ids(&domain), vec![partner]);
    assert_eq!(ids(&query), vec![carol]);
    let e = of_watch(&ev, &thread)[0];
    assert_eq!(
        (e["kind"].as_str(), e["account"].as_str(), e["thread_id"].as_str()),
        (Some("thread_reply"), Some("info"), Some("thr1"))
    );
    assert!(e["received_at"].as_str().unwrap().ends_with('Z'));

    // Label changes re-fetch messages and further passes replay history: no second event for the same message.
    h.google.set_labels(OWNER, &reply, &["STARRED"], &["UNREAD"]);
    fx.sync().await;
    fx.sync().await;
    assert_eq!(fx.events(&fx.token, json!({})).await.len(), 4);

    // The cursor returns only newer events, and is returned even when there are none.
    let first = h.ok(&fx.token, "list_watch_events", json!({ "limit": 3 })).await;
    assert_eq!((first["events"].as_array().unwrap().len(), first["has_more"].as_bool()), (3, Some(true)));
    let rest = h.ok(&fx.token, "list_watch_events", json!({ "cursor": first["next_cursor"] })).await;
    assert_eq!(rest["events"].as_array().unwrap().len(), 1);
    let none = h.ok(&fx.token, "list_watch_events", json!({ "cursor": rest["next_cursor"] })).await;
    assert_eq!((none["events"].as_array().unwrap().len(), &none["next_cursor"]), (0, &rest["next_cursor"]));
    assert_eq!(h.err(&fx.token, "list_watch_events", json!({ "cursor": "garbage" })).await, "cursor_invalid");
    let only = fx.events(&fx.token, json!({ "watch_id": addr })).await;
    assert_eq!(only.len(), 1);

    let listed = h.ok(&fx.token, "list_watches", json!({})).await;
    let fired: Vec<i64> = listed["watches"].as_array().unwrap().iter().map(|w| w["fired"].as_i64().unwrap()).collect();
    assert_eq!(fired, vec![1, 1, 1, 1]);
}

#[tokio::test]
async fn old_messages_refiled_later_do_not_fire() {
    let fx = gmail().await;
    let w = fx.watch(json!({ "account": "info", "kind": "from", "from": "carol@example.com" })).await;
    let mut old = spec("carol@example.com", "From last year", None);
    old.internal_date_ms = (util::now_unix() - 365 * 86_400) * 1000;
    fx.h.google.add_message(OWNER, old);
    fx.sync().await;
    assert!(of_watch(&fx.events(&fx.token, json!({})).await, &w).is_empty());
}

#[tokio::test]
async fn create_watch_validates_its_arguments_and_limits() {
    let fx = gmail().await;
    let h = &fx.h;
    let token = fx.token.clone();
    let token = &token;
    let bad = |args: Value| async move { h.err(token, "create_watch", args).await };
    assert_eq!(bad(json!({ "account": "info", "kind": "nope" })).await, "invalid_argument");
    assert_eq!(bad(json!({ "account": "info", "kind": "from", "from": "not an address" })).await, "invalid_argument");
    assert_eq!(
        bad(json!({ "account": "info", "kind": "from", "from": "a@b.test", "thread_id": "thr1" })).await,
        "invalid_argument"
    );
    assert_eq!(
        bad(json!({ "account": "info", "kind": "query", "where": { "field": "nope", "op": "eq", "value": 1 } })).await,
        "invalid_argument"
    );
    let far = util::rfc3339(util::now_unix() + 181 * 86_400);
    assert_eq!(
        bad(json!({ "account": "info", "kind": "from", "from": "a@b.test", "expires_at": far })).await,
        "invalid_argument"
    );
    let past = util::rfc3339(util::now_unix() - 10);
    assert_eq!(
        bad(json!({ "account": "info", "kind": "no_reply_by", "thread_id": "thr1", "deadline": past })).await,
        "invalid_argument"
    );
    // Agents can never hand Dove a URL: there is no such argument, and sinks are looked up by name only.
    assert_eq!(
        bad(json!({ "account": "info", "kind": "from", "from": "a@b.test", "url": "https://evil.test/" })).await,
        "invalid_argument"
    );
    assert_eq!(
        bad(json!({ "account": "info", "kind": "from", "from": "a@b.test", "sink": "https://evil.test/" })).await,
        "invalid_argument"
    );
    // The mailbox must be indexed.
    h.admin(AdminRequest::IndexDisable { alias: "info".into() }).await.unwrap();
    assert_eq!(bad(json!({ "account": "info", "kind": "from", "from": "a@b.test" })).await, "invalid_argument");
    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();

    let expires = util::rfc3339(util::now_unix() + 3600);
    let first = fx.watch(json!({ "account": "info", "kind": "from", "from": "a@b.test", "expires_at": expires })).await;
    let v = h.ok(&fx.token, "list_watches", json!({})).await;
    assert_eq!(v["watches"][0]["expires_at"], expires);
    for i in 1..watch::MAX_ACTIVE_PER_CLIENT {
        fx.watch(json!({ "account": "info", "kind": "from", "from": format!("a{i}@b.test") })).await;
    }
    assert_eq!(bad(json!({ "account": "info", "kind": "from", "from": "z@b.test" })).await, "invalid_argument");
    h.ok(&fx.token, "delete_watch", json!({ "watch_id": first })).await;
    fx.watch(json!({ "account": "info", "kind": "from", "from": "z@b.test" })).await;
}

#[tokio::test]
async fn no_reply_by_fires_once_at_the_deadline() {
    let fx = gmail().await;
    let h = &fx.h;
    let now = util::now_unix();
    let deadline = now + 600;
    let silent = fx.watch(json!({ "account": "info", "kind": "no_reply_by", "thread_id": "thr1", "deadline": util::rfc3339(deadline) })).await;

    // Before the deadline nothing happens; after it, the index has not synced past the deadline yet: still waiting.
    assert_eq!(watch::tick(h.app(), now + 60).await.unwrap().no_reply_fired, 0);
    assert_eq!(watch::tick(h.app(), deadline + 1).await.unwrap().no_reply_fired, 0);
    assert!(fx.events(&fx.token, json!({})).await.is_empty());
    // The owner's own follow-up is not a reply.
    let mut own = spec(OWNER, "Re: Kickoff", Some("thr1"));
    own.labels = vec!["SENT".into()];
    h.google.add_message(OWNER, own);
    fx.sync().await;
    // Once the index is known complete past the deadline the watch fires, exactly once.
    let aid = fx.info.clone();
    h.app()
        .index
        .write(move |c| {
            Ok(c.execute(
                "UPDATE sync_state SET last_success_at = ?1 WHERE account_id = ?2",
                rusqlite::params![deadline + 5, aid],
            )
            .map(|_| ())?)
        })
        .await
        .unwrap();
    assert_eq!(watch::tick(h.app(), deadline + 10).await.unwrap().no_reply_fired, 1);
    assert_eq!(watch::tick(h.app(), deadline + 20).await.unwrap().no_reply_fired, 0);
    let ev = fx.events(&fx.token, json!({})).await;
    assert_eq!(ev.len(), 1);
    assert_eq!((ev[0]["watch_id"].as_str(), ev[0]["kind"].as_str()), (Some(silent.as_str()), Some("no_reply_by")));
    assert_eq!((&ev[0]["thread_id"], &ev[0]["message_id"]), (&json!("thr1"), &Value::Null));
    let w = &h.ok(&fx.token, "list_watches", json!({})).await["watches"][0];
    assert_eq!((w["state"].as_str(), w["end_reason"].as_str()), (Some("ended"), Some("fired")));

    // A reply from someone else before the deadline ends the watch quietly.
    let deadline2 = util::now_unix() + 600;
    let answered = fx.watch(json!({ "account": "info", "kind": "no_reply_by", "thread_id": "thr1", "deadline": util::rfc3339(deadline2) })).await;
    h.google.add_message(OWNER, spec("bob@example.com", "Re: Kickoff", Some("thr1")));
    fx.sync().await;
    // Without a sync after the deadline the watch still fires at the latest after the grace period.
    let late = fx.watch(json!({ "account": "info", "kind": "no_reply_by", "thread_id": "thr1", "deadline": util::rfc3339(deadline2) })).await;
    watch::tick(h.app(), deadline2 + watch::NO_REPLY_GRACE_SECS).await.unwrap();
    let ev = fx.events(&fx.token, json!({})).await;
    assert!(of_watch(&ev, &answered).is_empty());
    assert_eq!(of_watch(&ev, &late).len(), 1);
    let ws = h.ok(&fx.token, "list_watches", json!({})).await;
    let reason = |id: &str| {
        ws["watches"].as_array().unwrap().iter().find(|w| w["watch_id"] == id).unwrap()["end_reason"].clone()
    };
    assert_eq!((reason(&answered), reason(&late)), (json!("replied"), json!("fired")));
}

/// One request a receiver got: path, headers, body.
type Hit = (String, axum::http::HeaderMap, Vec<u8>);

/// Collects the requests a webhook receiver gets and answers with a settable status.
#[derive(Clone)]
struct Receiver {
    hits: Arc<Mutex<Vec<Hit>>>,
    status: Arc<AtomicU16>,
    base: String,
}

impl Receiver {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let r = Receiver {
            hits: Arc::default(),
            status: Arc::new(AtomicU16::new(200)),
            base: format!("http://{}", listener.local_addr().unwrap()),
        };
        let rc = r.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let rc = rc.clone();
            async move {
                let path = req.uri().path().to_string();
                let headers = req.headers().clone();
                let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap().to_vec();
                rc.hits.lock().unwrap().push((path, headers, body));
                axum::http::StatusCode::from_u16(rc.status.load(Ordering::SeqCst)).unwrap()
            }
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        r
    }

    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// What a receiver does (docs/deployment.md "Watches and sinks"), written independently of Dove's signer.
fn verify(secret: &str, header: &str, body: &[u8]) -> bool {
    let mut t = None;
    let mut v1 = None;
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", x)) => t = Some(x.to_string()),
            Some(("v1", x)) => v1 = Some(x.to_string()),
            _ => {}
        }
    }
    let (Some(t), Some(v1)) = (t, v1) else { return false };
    if (util::now_unix() - t.parse::<i64>().unwrap()).abs() > 300 {
        return false;
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{t}.").as_bytes());
    mac.update(body);
    mac.verify_slice(&unhex(&v1)).is_ok()
}

async fn add_sink(h: &Harness, name: &str, url: &str) -> Result<Value, String> {
    h.admin(AdminRequest::SinksAdd {
        name: name.into(),
        url: url.into(),
        secret: Password(zeroize::Zeroizing::new(SECRET.into())),
    })
    .await
}

#[tokio::test]
async fn sink_delivery_is_signed_content_free_and_bounded() {
    let fx = gmail().await;
    let h = &fx.h;
    let rx = Receiver::start().await;
    // Production sinks must be HTTPS; plain loopback HTTP exists only in test builds and only when enabled.
    let url = format!("{}/hooks/dove", rx.base);
    assert!(add_sink(h, "hook", &url).await.unwrap_err().contains("https"));
    h.app().google.gateway().allow_plain_http_sinks_for_tests();
    for bad in [
        format!("{url}?token=x"),
        format!("{url}#frag"),
        "https://user:pw@hooks.example.com/x".to_string(),
        "ftp://hooks.example.com/x".to_string(),
        "http://hooks.example.com/x".to_string(),
    ] {
        assert!(add_sink(h, "hook", &bad).await.is_err(), "{bad}");
    }
    let short = h
        .admin(AdminRequest::SinksAdd {
            name: "s".into(),
            url: url.clone(),
            secret: Password(zeroize::Zeroizing::new("short".into())),
        })
        .await;
    assert!(short.is_err());
    add_sink(h, "hook", &url).await.unwrap();
    assert!(add_sink(h, "hook", &url).await.unwrap_err().contains("exists"));
    let listed = h.admin(AdminRequest::SinksList).await.unwrap();
    assert_eq!(listed[0]["url"], url);
    assert!(!listed.to_string().contains(SECRET), "the secret is never shown");
    // Agents see sink names only.
    let v = h.ok(&fx.token, "list_watches", json!({})).await;
    assert_eq!(v["sinks"], json!(["hook"]));

    let w = fx.watch(json!({ "account": "info", "kind": "from", "from": "carol@example.com", "sink": "hook" })).await;
    h.google.add_message(OWNER, spec("carol@example.com", "CANARY-SUBJECT-q81", None));
    fx.sync().await;
    let r = watch::sinks::deliver_due(h.app(), util::now_unix()).await.unwrap();
    assert_eq!((r.attempted, r.delivered), (1, 1), "{r:?}");
    let hits = rx.hits();
    assert_eq!(hits.len(), 1);
    let (path, headers, body) = &hits[0];
    assert_eq!(path, "/hooks/dove");
    let sig = headers.get("dove-signature").unwrap().to_str().unwrap();
    assert!(verify(SECRET, sig, body), "signature must verify: {sig}");
    assert!(!verify("another-secret-another-secret-12", sig, body));
    let mut tampered = body.clone();
    tampered.push(b' ');
    assert!(!verify(SECRET, sig, &tampered));
    let payload: Value = serde_json::from_slice(body).unwrap();
    let mut keys: Vec<&str> = payload.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        ["account", "created_at", "event_id", "kind", "message_id", "received_at", "thread_id", "watch_id"]
    );
    assert_eq!(payload["watch_id"], w.as_str());
    assert_eq!(headers.get("dove-event-id").unwrap().to_str().unwrap(), payload["event_id"]);
    // The same payload is what the agent pulls.
    assert_eq!(fx.events(&fx.token, json!({})).await, vec![payload]);
    let text = String::from_utf8_lossy(body);
    for canary in ["CANARY", "carol", "Carol", "hello there"] {
        assert!(!text.contains(canary), "{canary} leaked into the push body");
    }
    // Delivered once: later passes send nothing.
    assert_eq!(watch::sinks::deliver_due(h.app(), util::now_unix() + 10_000).await.unwrap().attempted, 0);

    // A receiver that keeps failing gets a bounded number of attempts with growing waits.
    rx.status.store(503, Ordering::SeqCst);
    h.google.add_message(OWNER, spec("carol@example.com", "Again", None));
    fx.sync().await;
    let mut now = util::now_unix();
    for attempt in 1..=watch::sinks::MAX_ATTEMPTS {
        let r = watch::sinks::deliver_due(h.app(), now).await.unwrap();
        assert_eq!(r.attempted, 1, "attempt {attempt}");
        // Not due again before the backoff.
        assert_eq!(watch::sinks::deliver_due(h.app(), now + 1).await.unwrap().attempted, 0);
        now += 3 * 3600;
    }
    assert_eq!(watch::sinks::deliver_due(h.app(), now + 86_400).await.unwrap().attempted, 0);
    assert_eq!(rx.hits().len(), 1 + watch::sinks::MAX_ATTEMPTS as usize);
    let listed = h.admin(AdminRequest::SinksList).await.unwrap();
    assert_eq!((&listed[0]["delivered"], &listed[0]["failed"]), (&json!(1), &json!(1)));

    // A client error is final at once.
    rx.status.store(404, Ordering::SeqCst);
    h.google.add_message(OWNER, spec("carol@example.com", "Third", None));
    fx.sync().await;
    let before = rx.hits().len();
    assert_eq!(watch::sinks::deliver_due(h.app(), now).await.unwrap().failed, 1);
    assert_eq!(watch::sinks::deliver_due(h.app(), now + 86_400).await.unwrap().attempted, 0);
    assert_eq!(rx.hits().len(), before + 1);

    // Removing the sink keeps the watch (pull only) and drops queued pushes.
    let v = h.admin(AdminRequest::SinksRemove { name: "hook".into() }).await.unwrap();
    assert_eq!(v["watches_without_push"], 1);
    let ws = h.ok(&fx.token, "list_watches", json!({})).await;
    assert_eq!((ws["watches"][0]["state"].as_str(), &ws["watches"][0]["sink"]), (Some("active"), &Value::Null));
    assert_eq!(ws["sinks"], json!([]));
}

#[tokio::test]
async fn gateway_posts_only_to_registered_sink_urls() {
    let h = Harness::start().await;
    let rx = Receiver::start().await;
    let other = Receiver::start().await;
    let gw = h.app().google.gateway();
    gw.allow_plain_http_sinks_for_tests();
    add_sink(&h, "hook", &format!("{}/hook", rx.base)).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let post = |u: String| async move { gw.post_sink(&u, &[], b"{}".to_vec(), deadline).await };
    // Exactly the registered URL: same host on another path, another port, or another host are refused unsent.
    for u in [
        format!("{}/hook/", rx.base),
        format!("{}/other", rx.base),
        format!("{}/hook", other.base),
        "https://example.com/hook".to_string(),
        format!("{}/hook?x=1", rx.base),
    ] {
        assert!(matches!(post(u.clone()).await, Err(dove::gmail::gateway::GatewayError::NotAllowed)), "{u}");
    }
    assert!(rx.hits().is_empty() && other.hits().is_empty());
    assert_eq!(post(format!("{}/hook", rx.base)).await.unwrap(), 200);
    assert_eq!(rx.hits().len(), 1);
    // After removal the URL is refused again.
    h.admin(AdminRequest::SinksRemove { name: "hook".into() }).await.unwrap();
    assert!(post(format!("{}/hook", rx.base)).await.is_err());
    assert_eq!(rx.hits().len(), 1);
}

#[tokio::test]
async fn events_and_watch_rows_carry_no_mail_content() {
    let fx = gmail().await;
    let h = &fx.h;
    fx.watch(json!({ "account": "info", "kind": "from", "from": "canary-sender@canary.test" })).await;
    fx.watch(json!({ "account": "info", "kind": "query", "where": { "field": "subject", "op": "terms", "value": "zebracanary" } })).await;
    let mut m = spec("canary-sender@canary.test", "zebracanary subject line", None);
    m.text = Some("CANARYBODY secret text".into());
    h.google.add_message(OWNER, m);
    fx.sync().await;
    let ev = fx.events(&fx.token, json!({})).await;
    assert_eq!(ev.len(), 2);
    let text = serde_json::to_string(&ev).unwrap();
    // Checkpoint the WAL so the database file holds everything, then scan the whole state store.
    h.app().store.call(|c| Ok(c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?)).await.unwrap();
    let db = std::fs::read(h.app().cfg.state_db_path()).unwrap();
    for canary in ["canary-sender", "zebracanary", "CANARYBODY", "canary.test"] {
        assert!(!text.contains(canary), "{canary} in events");
        assert!(!db.windows(canary.len()).any(|w| w == canary.as_bytes()), "{canary} in the state store");
    }
}

#[tokio::test]
async fn watches_end_on_revoke_grant_loss_disable_and_removal() {
    let fx = gmail().await;
    let h = &fx.h;
    let reason = |v: &Value, id: &str| {
        v["watches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["watch_id"] == id)
            .map(|w| (w["state"].clone(), w["end_reason"].clone()))
    };
    // Grant loss: no events from the moment the grant is gone, and the tick ends the watch.
    let lost = fx.watch(json!({ "account": "info", "kind": "from", "from": "carol@example.com" })).await;
    let other = h.token("acme", "second", vec![g("info", "read"), g("other", "read")]).await;
    let kept =
        h.ok(&other, "create_watch", json!({ "account": "info", "kind": "from", "from": "carol@example.com" })).await;
    let kept = kept["watch_id"].as_str().unwrap().to_string();
    h.admin(AdminRequest::ClientsSetGrants { name: "agent".into(), grants: vec![g("other", "read")] }).await.unwrap();
    h.google.add_message(OWNER, spec("carol@example.com", "x", None));
    fx.sync().await;
    assert_eq!(fx.events(&other, json!({})).await.len(), 1);
    h.admin(AdminRequest::ClientsSetGrants { name: "agent".into(), grants: vec![g("info", "read")] }).await.unwrap();
    // The watch was ended when its event was due; the event never reached the agent.
    assert!(fx.events(&fx.token, json!({})).await.is_empty());
    let v = h.ok(&fx.token, "list_watches", json!({})).await;
    assert_eq!(reason(&v, &lost), Some((json!("ended"), json!("access_lost"))));

    // Revocation: the tick ends the watch.
    h.admin(AdminRequest::ClientsRevoke { name: "second".into() }).await.unwrap();
    watch::tick(h.app(), util::now_unix()).await.unwrap();
    let state = |id: String| async move {
        h.app()
            .store
            .call(move |c| {
                Ok(c.query_row("SELECT state, end_reason FROM watches WHERE id = ?1", [id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
                })
                .ok())
            })
            .await
            .unwrap()
    };
    assert_eq!(state(kept.clone()).await, Some(("ended".into(), Some("client_revoked".into()))));

    // Disable ends, remove deletes.
    let w = fx.watch(json!({ "account": "info", "kind": "from", "from": "carol@example.com" })).await;
    h.admin(AdminRequest::AccountsDisable { alias: "info".into() }).await.unwrap();
    watch::tick(h.app(), util::now_unix()).await.unwrap();
    assert_eq!(state(w.clone()).await, Some(("ended".into(), Some("account_disabled".into()))));
    h.admin(AdminRequest::AccountsRemove { alias: "info".into() }).await.unwrap();
    assert_eq!(state(w).await, None);
    assert_eq!(state(lost).await, None);

    // Expiry.
    let fx = gmail().await;
    let w = fx.watch(json!({ "account": "info", "kind": "from", "from": "a@b.test", "expires_at": util::rfc3339(util::now_unix() + 60) })).await;
    fx.h.app().store.call(|_| Ok(())).await.unwrap();
    watch::tick(fx.h.app(), util::now_unix() + 61).await.unwrap();
    let v = fx.h.ok(&fx.token, "list_watches", json!({})).await;
    assert_eq!(reason(&v, &w), Some((json!("ended"), json!("expired"))));
}

#[tokio::test]
async fn events_and_ended_watches_are_pruned_after_14_days() {
    let fx = gmail().await;
    let h = &fx.h;
    let active = fx.watch(json!({ "account": "info", "kind": "from", "from": "carol@example.com" })).await;
    let ended = fx.watch(json!({ "account": "info", "kind": "from", "from": "dave@example.com", "expires_at": util::rfc3339(util::now_unix() + 60) })).await;
    h.google.add_message(OWNER, spec("carol@example.com", "x", None));
    fx.sync().await;
    let first = h.ok(&fx.token, "list_watch_events", json!({})).await;
    assert_eq!(first["events"].as_array().unwrap().len(), 1);
    let now = util::now_unix();
    let r = watch::tick(h.app(), now + 120).await.unwrap();
    assert_eq!((r.ended, r.pruned_events), (1, 0));
    let r = watch::tick(h.app(), now + watch::RETENTION_SECS + 3600).await.unwrap();
    assert_eq!((r.pruned_events, r.pruned_watches), (1, 1), "{r:?}");
    let v = h.ok(&fx.token, "list_watches", json!({})).await;
    let ids: Vec<&str> = v["watches"].as_array().unwrap().iter().map(|w| w["watch_id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec![active.as_str()]);
    assert!(!ids.contains(&ended.as_str()));
    // An old cursor keeps working: positions are never reused, so new events after pruning are not skipped.
    h.google.add_message(OWNER, spec("carol@example.com", "y", None));
    fx.sync().await;
    let next = h.ok(&fx.token, "list_watch_events", json!({ "cursor": first["next_cursor"] })).await;
    assert_eq!(next["events"].as_array().unwrap().len(), 1);
}

// Unix only: writes secret files with Unix modes.
#[cfg(unix)]
#[tokio::test]
async fn keys_rotate_rewraps_sink_secrets_and_watch_filters() {
    use std::os::unix::fs::PermissionsExt;
    let mut fx = gmail().await;
    let rx = Receiver::start().await;
    fx.h.app().google.gateway().allow_plain_http_sinks_for_tests();
    add_sink(&fx.h, "hook", &format!("{}/hook", rx.base)).await.unwrap();
    fx.watch(json!({ "account": "info", "kind": "from", "from": "carol@example.com", "sink": "hook" })).await;
    let kek = fx.h.app().cfg.secrets.kek_file.clone();
    let mut text = std::fs::read_to_string(&kek).unwrap();
    text.push('\n');
    text.push_str(&dove::secrets::generate_key_line(2));
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&kek, text).unwrap();
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o400)).unwrap();
    fx.h.restart().await;
    fx.h.app().google.gateway().allow_plain_http_sinks_for_tests();
    watch::sinks::reload_allowlist(fx.h.app()).await.unwrap();

    let v = fx.h.admin(AdminRequest::KeysRotate).await.unwrap();
    // Two Gmail grants, one sink secret, one watch filter.
    assert_eq!(v["rewrapped"], 4, "{v}");
    assert_eq!(v["versions_in_use"], json!([2]));
    // Both still open: the watch matches and the push is signed with the original secret.
    fx.h.google.add_message(OWNER, spec("carol@example.com", "after rotate", None));
    fx.sync().await;
    assert_eq!(watch::sinks::deliver_due(fx.h.app(), util::now_unix()).await.unwrap().delivered, 1);
    let (_, headers, body) = rx.hits().pop().unwrap();
    assert!(verify(SECRET, headers.get("dove-signature").unwrap().to_str().unwrap(), &body));
}

fn imap_raw(from: &str, subject: &str, msg_id: &str, refs: Option<&str>) -> Vec<u8> {
    let refs = refs.map(|r| format!("In-Reply-To: {r}\r\nReferences: {r}\r\n")).unwrap_or_default();
    format!(
        "From: {from}\r\nTo: box@example.org\r\nSubject: {subject}\r\nMessage-ID: {msg_id}\r\n{refs}\
         Date: Thu, 12 Nov 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Hello there.\r\n"
    )
    .into_bytes()
}

async fn wait_for<F, Fut>(what: &str, within: Duration, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let end = Instant::now() + within;
    while Instant::now() < end {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out after {within:?} waiting for {what}");
}

#[tokio::test]
async fn imap_polling_and_idle_produce_events() {
    // No poll during the test: only explicit sync passes or IDLE index new mail.
    let h = Harness::start_with(|c| c.index.poll_interval_secs = 3600).await;
    let u = h.imap_mailbox("box", "box@example.org").await;
    h.project("p", &["box"]).await;
    let token = h.token("p", "agent", vec![g("box", "read")]).await;
    h.imap.add_message_at(
        &u.user,
        "INBOX",
        &imap_raw("ann@example.org", "Plan", "<root@example.org>", None),
        &[],
        util::now_unix(),
    );
    h.admin(AdminRequest::IndexEnable { alias: "box".into() }).await.unwrap();
    let r = dove::index::imap_sync::sync_steps(h.app(), &u.account_id, usize::MAX).await.unwrap();
    assert_eq!((r.stage.as_str(), r.error.as_deref()), ("ready", None), "{r:?}");
    let s = h.ok(&token, "search_messages", json!({ "select": ["thread_id", "message_id"] })).await;
    let thread = s["rows"][0][0].as_str().unwrap().to_string();

    let ok = |args: Value| {
        let (h, token) = (&h, &token);
        async move { h.ok(token, "create_watch", args).await["watch_id"].as_str().unwrap().to_string() }
    };
    let tw = ok(json!({ "account": "box", "kind": "thread_reply", "thread_id": thread })).await;
    let fw = ok(json!({ "account": "box", "kind": "from", "from": "carol@example.org" })).await;
    let events = || async { h.ok(&token, "list_watch_events", json!({})).await["events"].as_array().unwrap().clone() };

    // Polling: a reply in the thread and the owner's own message in it (from Sent).
    h.imap.add_message_at(
        &u.user,
        "INBOX",
        &imap_raw("ann@example.org", "Re: Plan", "<r1@example.org>", Some("<root@example.org>")),
        &[],
        util::now_unix(),
    );
    h.imap.add_message_at(
        &u.user,
        "Sent",
        &imap_raw("box@example.org", "Re: Plan", "<r2@example.org>", Some("<root@example.org>")),
        &["\\Seen"],
        util::now_unix(),
    );
    // A send-as alias is the owner too: its message in the thread is not a reply from someone else.
    h.admin(AdminRequest::AccountsAliasAdd {
        account: "box".into(),
        address: "team@example.org".into(),
        name: None,
        envelope: false,
    })
    .await
    .unwrap();
    h.imap.add_message_at(
        &u.user,
        "INBOX",
        &imap_raw("team@example.org", "Re: Plan", "<r3@example.org>", Some("<root@example.org>")),
        &[],
        util::now_unix(),
    );
    let r = dove::index::imap_sync::sync_steps(h.app(), &u.account_id, usize::MAX).await.unwrap();
    assert_eq!(r.error, None, "{r:?}");
    let ev = events().await;
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!((ev[0]["watch_id"].as_str(), ev[0]["thread_id"].as_str()), (Some(tw.as_str()), Some(thread.as_str())));
    // The event's message id is readable with the agent's own token.
    let m = h.ok(&token, "get_message", json!({ "account": "box", "message_id": ev[0]["message_id"] })).await;
    assert!(m.to_string().contains("Re: Plan"));

    // IDLE: new INBOX mail produces the event within seconds, without a poll.
    let tasks = [dove::index::start(h.app().clone()), dove::index::imap_idle::start(h.app().clone())];
    wait_for("IDLE", Duration::from_secs(10), || async { h.app().index.idle.is_healthy(&u.account_id) }).await;
    let t0 = Instant::now();
    h.imap.add_message_at(
        &u.user,
        "INBOX",
        &imap_raw("carol@example.org", "Hello", "<c1@example.org>", None),
        &[],
        util::now_unix(),
    );
    wait_for("the from event", Duration::from_secs(10), || async {
        events().await.iter().any(|e| e["watch_id"] == fw.as_str())
    })
    .await;
    assert!(t0.elapsed() < Duration::from_secs(8), "took {:?}", t0.elapsed());
    for t in tasks {
        t.abort();
    }
    assert_eq!(events().await.len(), 2);
}

#[tokio::test]
async fn rebuilds_and_backfills_do_not_fire() {
    let fx = gmail().await;
    // Indexed before the watch exists, but recent enough for the slack window.
    fx.h.google.add_message(OWNER, spec("carol@example.com", "Earlier today", None));
    fx.sync().await;
    let w = fx.watch(json!({ "account": "info", "kind": "from", "from": "carol@example.com" })).await;
    // A rebuild indexes every message again into a new generation: none of that is new mail.
    fx.h.admin(AdminRequest::IndexRebuild { alias: "info".into() }).await.unwrap();
    fx.sync().await;
    let st = fx.h.admin(AdminRequest::IndexStatus { alias: Some("info".into()) }).await.unwrap();
    assert_eq!(st["accounts"][0]["stage"], "ready", "{st}");
    assert!(of_watch(&fx.events(&fx.token, json!({})).await, &w).is_empty());
    // New mail after the rebuild still fires.
    fx.h.google.add_message(OWNER, spec("carol@example.com", "Later", None));
    fx.sync().await;
    assert_eq!(of_watch(&fx.events(&fx.token, json!({})).await, &w).len(), 1);
}
