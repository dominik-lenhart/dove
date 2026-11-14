//! IMAP mailboxes in the encrypted index (design "Search and index"): per-folder checkpoints, backfill newest first,
//! new mail, flag changes with and without CONDSTORE, deletions via QRESYNC and the UID diff, UIDVALIDITY resets,
//! spam/trash exclusion, threads from the index, oversize messages, the live Gmail source, and no plaintext on
//! disk. Runs against the fake IMAP server through the deterministic sync entry point.

mod support;

use std::sync::{Arc, Mutex};

use dove::admin::AdminRequest;
use dove::index::imap_sync::sync_steps;
use serde_json::{Value, json};
use support::fake_imap::{FakeImap, Fault, Opts};
use support::harness::{FakeImapUser, Harness, g};

/// 2026-01-01T00:00:00Z
const DAY0: i64 = 1_767_225_600;

fn mail(from: &str, subject: &str, mid: &str, extra: &str, body: &str) -> Vec<u8> {
    format!(
        "From: {from}\r\nTo: info@example.org\r\nSubject: {subject}\r\nMessage-ID: <{mid}>\r\n{extra}\
         Date: Thu, 01 Jan 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         {body}\r\n"
    )
    .into_bytes()
}

fn simple(subject: &str) -> Vec<u8> {
    mail("Ann <ann@example.org>", subject, &format!("{}@example.org", subject.replace(' ', "-")), "", "Hello there.")
}

struct Fx {
    h: Harness,
    u: FakeImapUser,
    token: String,
}

async fn setup_with(opts: Opts, customize: impl FnOnce(&mut dove::config::Config)) -> Fx {
    let mut h = Harness::start_with(customize).await;
    h.imap = FakeImap::start_with(opts).await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read")]).await;
    Fx { h, u, token }
}

async fn setup(opts: Opts) -> Fx {
    setup_with(opts, |_| {}).await
}

/// The Strato case: no CONDSTORE, no QRESYNC.
fn plain() -> Opts {
    Opts { condstore: false, qresync: false, ..Default::default() }
}

impl Fx {
    /// Creates the sync state (connect already enabled indexing) and runs sync to idle.
    async fn sync(&self) -> dove::index::sync::SyncReport {
        self.h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
        let r = sync_steps(self.h.app(), &self.u.account_id, usize::MAX).await.unwrap();
        assert_eq!(r.error, None, "{r:?}");
        assert!(!r.fenced, "{r:?}");
        r
    }

    async fn search(&self, args: Value) -> Value {
        self.h.ok(&self.token, "search_messages", args).await
    }

    fn add(&self, folder: &str, raw: &[u8], flags: &[&str]) -> u32 {
        self.h.imap.add_message(&self.u.user, folder, raw, flags)
    }

    async fn id(&self, folder: &str, uid: u32) -> String {
        let f = folder_id(&self.h, &self.u.account_id, &support::fake_imap::encode_utf7(folder)).await;
        format!("f{f}-{}-{uid}", self.h.imap.uidvalidity(&self.u.user, folder))
    }

    /// Indexed ids of the account (any generation).
    async fn indexed(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .h
            .app()
            .index
            .write(|c| {
                let mut st = c.prepare("SELECT gmail_id FROM messages")?;
                Ok(st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap();
        v.sort();
        v
    }

    fn commands_since(&self, mark: usize) -> Vec<String> {
        self.h.imap.commands()[mark..].to_vec()
    }
}

async fn folder_id(h: &Harness, account_id: &str, name: &str) -> i64 {
    let (a, n) = (account_id.to_string(), name.to_string());
    h.app()
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT folder_id FROM imap_folders WHERE account_id = ?1 AND name = ?2", [a, n], |r| {
                r.get(0)
            })?)
        })
        .await
        .unwrap()
}

fn col(v: &Value, name: &str) -> Vec<Value> {
    let i = v["columns"].as_array().unwrap().iter().position(|c| c == name).unwrap_or_else(|| panic!("{name}: {v}"));
    v["rows"].as_array().unwrap().iter().map(|r| r[i].clone()).collect()
}

fn strs(v: Vec<Value>) -> Vec<String> {
    let mut s: Vec<String> = v.into_iter().map(|x| x.as_str().unwrap_or_default().to_string()).collect();
    s.sort();
    s
}

fn pred(field: &str, op: &str, value: Value) -> Value {
    json!({ "field": field, "op": op, "value": value })
}

/// Backfill takes the newest message of every folder before older ones (pending ranks are per folder), and the
/// finished index holds every folder with its path as label. Nothing sets `\Seen`.
#[tokio::test]
async fn backfill_all_folders_newest_first() {
    let fx = setup(Opts::default()).await;
    fx.h.imap.add_folder(&fx.u.user, "Archiv/2025", None);
    for i in 1..=20 {
        fx.add("INBOX", &simple(&format!("inbox {i}")), &[]);
    }
    for i in 1..=5 {
        fx.add("Archiv/2025", &simple(&format!("archive {i}")), &["\\Seen"]);
    }
    for i in 1..=3 {
        fx.add("Sent", &simple(&format!("sent {i}")), &["\\Seen"]);
    }
    fx.h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    // Step 1: scan (checkpoints, all UIDs pending). Step 2: one batch of 16.
    let r = sync_steps(fx.h.app(), &fx.u.account_id, 2).await.unwrap();
    assert_eq!(r.indexed, 16, "{r:?}");
    let got = fx.indexed().await;
    let mut want = vec![];
    for uid in 13..=20 {
        want.push(fx.id("INBOX", uid).await);
    }
    for uid in 1..=5 {
        want.push(fx.id("Archiv/2025", uid).await);
    }
    for uid in 1..=3 {
        want.push(fx.id("Sent", uid).await);
    }
    want.sort();
    assert_eq!(got, want, "newest of every folder first");

    let r = sync_steps(fx.h.app(), &fx.u.account_id, usize::MAX).await.unwrap();
    assert_eq!((r.stage.as_str(), r.error.as_deref()), ("ready", None), "{r:?}");
    assert_eq!(fx.indexed().await.len(), 28);
    let v = fx
        .search(
            json!({"where": pred("label", "eq", json!("Archiv/2025")), "select": ["subject", "labels"], "limit": 50}),
        )
        .await;
    assert_eq!(v["coverage"], "complete", "{v}");
    assert_eq!(strs(col(&v, "subject")), (1..=5).map(|i| format!("archive {i}")).collect::<Vec<_>>());
    let v = fx.search(json!({"where": pred("label", "eq", json!("SENT")), "select": ["subject"]})).await;
    assert_eq!(col(&v, "subject").len(), 3, "{v}");
    for uid in 1..=20 {
        assert!(!fx.h.imap.flags(&fx.u.user, "INBOX", uid).unwrap().contains(&"\\Seen".to_string()));
    }
    fx.h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn new_mail_appears_after_poll() {
    let fx = setup(plain()).await;
    fx.add("INBOX", &simple("first"), &["\\Seen"]);
    fx.sync().await;
    let uid = fx.add("INBOX", &simple("second arrival"), &[]);
    let r = fx.sync().await;
    assert_eq!(r.indexed, 1, "{r:?}");
    let v = fx
        .search(json!({"where": pred("subject", "terms", json!("arrival")), "select": ["message_id", "is_unread"]}))
        .await;
    assert_eq!(col(&v, "message_id"), vec![json!(fx.id("INBOX", uid).await)], "{v}");
    assert_eq!(col(&v, "is_unread"), vec![json!(true)]);
    // Disabling purges the folder checkpoints with the generation.
    assert!(checkpoints(&fx.h).await > 0);
    fx.h.admin(AdminRequest::IndexDisable { alias: "info".into() }).await.unwrap();
    assert_eq!(checkpoints(&fx.h).await, 0);
}

async fn checkpoints(h: &Harness) -> i64 {
    h.app().index.write(|c| Ok(c.query_row("SELECT count(*) FROM imap_checkpoints", [], |r| r.get(0))?)).await.unwrap()
}

/// A message the server refuses to deliver becomes a retry record instead of blocking the backfill; the rest is
/// indexed and the generation is published with the gap reported.
#[tokio::test]
async fn poison_message_becomes_retry_record() {
    let fx = setup(plain()).await;
    let uids: Vec<u32> = (0..3).map(|i| fx.add("INBOX", &simple(&format!("msg {i}")), &[])).collect();
    fx.h.imap.fail_next_containing("UID FETCH", &format!("UID FETCH {} (UID BODY.PEEK[])", uids[1]), Fault::Bad);
    let r = fx.sync().await;
    assert_eq!((r.stage.as_str(), r.indexed, r.failed), ("ready", 2, 1), "{r:?}");
    let bad = fx.id("INBOX", uids[1]).await;
    let attempts: i64 =
        fx.h.app()
            .index
            .write(move |c| Ok(c.query_row("SELECT attempts FROM pending WHERE gmail_id = ?1", [bad], |r| r.get(0))?))
            .await
            .unwrap();
    assert_eq!(attempts, 1);
    let v = fx.search(json!({"select": ["subject"]})).await;
    assert_eq!((v["coverage"].as_str(), col(&v, "subject").len()), (Some("partial"), 2), "{v}");
}

/// With CONDSTORE a flag change made by another client arrives through `CHANGEDSINCE`, without re-reading flags.
#[tokio::test]
async fn flag_change_via_condstore() {
    let fx = setup(Opts::default()).await;
    let uid = fx.add("INBOX", &simple("condstore flags"), &[]);
    for i in 0..3 {
        fx.add("INBOX", &simple(&format!("other {i}")), &[]);
    }
    fx.sync().await;
    let mark = fx.h.imap.commands().len();
    fx.h.imap.set_flags(&fx.u.user, "INBOX", uid, &["\\Seen", "\\Flagged"], &[]);
    let r = fx.sync().await;
    assert_eq!(r.indexed, 1, "{r:?}");
    let v = fx
        .search(json!({"where": pred("subject", "terms", json!("condstore")), "select": ["is_unread", "is_starred"]}))
        .await;
    assert_eq!((col(&v, "is_unread"), col(&v, "is_starred")), (vec![json!(false)], vec![json!(true)]), "{v}");
    let cmds = fx.commands_since(mark);
    assert!(cmds.iter().any(|c| c.contains("CHANGEDSINCE")), "{cmds:?}");
    assert!(
        !cmds.iter().any(|c| c.contains("UID FETCH") && c.contains("FLAGS") && !c.contains("CHANGEDSINCE")),
        "no flag re-read with CONDSTORE: {cmds:?}"
    );
}

/// Expunges by another client: reported by QRESYNC `VANISHED`, otherwise found by count and a `UID SEARCH ALL`
/// diff. A poll without deletions never lists the whole folder.
#[tokio::test]
async fn deletion_via_qresync_and_via_diff_fallback() {
    for (opts, via_vanished) in
        [(Opts::default(), true), (Opts { qresync: false, ..Default::default() }, false), (plain(), false)]
    {
        let fx = setup(opts.clone()).await;
        let uids: Vec<u32> = (0..4).map(|i| fx.add("INBOX", &simple(&format!("keep {i}")), &[])).collect();
        fx.sync().await;
        let mark = fx.h.imap.commands().len();
        let r = fx.sync().await;
        assert_eq!((r.indexed, r.removed), (0, 0), "{r:?}");
        assert!(!fx.commands_since(mark).iter().any(|c| c.contains("SEARCH ALL")), "{opts:?}: no diff without need");

        let gone = fx.id("INBOX", uids[1]).await;
        fx.h.imap.expunge_external(&fx.u.user, "INBOX", uids[1]);
        let mark = fx.h.imap.commands().len();
        let r = fx.sync().await;
        assert_eq!(r.removed, 1, "{opts:?} {r:?}");
        assert!(!fx.indexed().await.contains(&gone));
        assert_eq!(fx.indexed().await.len(), 3);
        let cmds = fx.commands_since(mark);
        assert_eq!(cmds.iter().any(|c| c.contains("SEARCH ALL")), !via_vanished, "{opts:?}: {cmds:?}");
        assert_eq!(cmds.iter().any(|c| c.contains("VANISHED")), via_vanished, "{opts:?}: {cmds:?}");
        let v = fx.search(json!({"select": ["message_id"]})).await;
        assert_eq!(col(&v, "message_id").len(), 3, "{v}");
    }
}

/// A server may report `VANISHED` as ranges that cover UIDs which never existed (RFC 7162). A range wider than a
/// million UIDs still removes the known messages inside it, without falling back to `UID SEARCH ALL`.
#[tokio::test]
async fn wide_vanished_ranges_remove_known_messages() {
    let fx = setup(Opts { wide_vanished: true, ..Default::default() }).await;
    let uids: Vec<u32> = (0..4).map(|i| fx.add("INBOX", &simple(&format!("keep {i}")), &[])).collect();
    fx.sync().await;
    let gone = [fx.id("INBOX", uids[1]).await, fx.id("INBOX", uids[3]).await];
    fx.h.imap.expunge_external(&fx.u.user, "INBOX", uids[1]);
    fx.h.imap.expunge_external(&fx.u.user, "INBOX", uids[3]);
    let mark = fx.h.imap.commands().len();
    let r = fx.sync().await;
    assert_eq!(r.removed, 2, "{r:?}");
    let left = fx.indexed().await;
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(gone.iter().all(|g| !left.contains(g)), "{left:?}");
    let cmds = fx.commands_since(mark);
    assert!(cmds.iter().any(|c| c.contains("VANISHED")), "{cmds:?}");
    assert!(!cmds.iter().any(|c| c.contains("SEARCH ALL")), "{cmds:?}");
}

/// One sync step has a wall-clock limit (`index.imap_step_timeout_secs`): a server that answers each command just
/// inside the command timeout cannot hold the session (and its upstream slots) for longer. The next poll recovers.
#[tokio::test]
async fn slow_scan_hits_the_step_deadline() {
    let fx = setup_with(Opts::default(), |c| c.index.imap_step_timeout_secs = 1).await;
    fx.add("INBOX", &simple("hello"), &[]);
    fx.sync().await;
    // Two folder selects of 600 ms each: every command is far inside the 3 s command timeout.
    for _ in 0..2 {
        fx.h.imap.fail_next("EXAMINE", Fault::Delay(std::time::Duration::from_millis(600)));
    }
    let t0 = std::time::Instant::now();
    let r = sync_steps(fx.h.app(), &fx.u.account_id, usize::MAX).await.unwrap();
    assert_eq!(r.error.as_deref(), Some("upstream_error"), "{r:?}");
    assert!(t0.elapsed() < std::time::Duration::from_millis(1500), "{:?}", t0.elapsed());
    fx.sync().await;
}

/// IMAP sync is background work: with every background slot of the shared upstream limit taken (by Gmail sync, say)
/// it is not dispatched, while an agent's call on the same mailbox still gets through.
#[tokio::test]
async fn sync_needs_a_background_slot() {
    let fx = setup(Opts::default()).await;
    fx.add("INBOX", &simple("hello"), &[]);
    fx.sync().await;
    let bg = fx.h.app().google.gateway().background_limit();
    let held = bg.clone().acquire_many_owned(bg.available_permits() as u32).await.unwrap();
    let r = sync_steps(fx.h.app(), &fx.u.account_id, usize::MAX).await.unwrap();
    assert_eq!(r.error.as_deref(), Some("upstream_error"), "{r:?}");
    fx.h.ok(&fx.token, "list_labels", json!({"account": "info"})).await;
    drop(held);
    fx.sync().await;
}

/// Without CONDSTORE (Strato advertises none, checked 2026-11-12) a `\Seen` change made by another client shows in
/// `is_unread` after the next poll, through the bounded flags-only refresh.
#[tokio::test]
async fn flags_refresh_without_condstore() {
    let fx = setup(plain()).await;
    let read_elsewhere = fx.add("INBOX", &simple("read elsewhere"), &[]);
    let unread_again = fx.add("INBOX", &simple("unread again"), &["\\Seen"]);
    let untouched = fx.add("INBOX", &simple("untouched"), &[]);
    fx.sync().await;
    let unread = |v: &Value| -> Vec<(String, bool)> {
        let mut out: Vec<(String, bool)> = col(v, "subject")
            .into_iter()
            .zip(col(v, "is_unread"))
            .map(|(s, u)| (s.as_str().unwrap().to_string(), u.as_bool().unwrap()))
            .collect();
        out.sort();
        out
    };
    let q = json!({"select": ["subject", "is_unread"]});
    assert_eq!(
        unread(&fx.search(q.clone()).await),
        vec![("read elsewhere".into(), true), ("unread again".into(), false), ("untouched".into(), true)]
    );
    fx.h.imap.set_flags(&fx.u.user, "INBOX", read_elsewhere, &["\\Seen"], &[]);
    fx.h.imap.set_flags(&fx.u.user, "INBOX", unread_again, &[], &["\\Seen"]);
    let mark = fx.h.imap.commands().len();
    let r = fx.sync().await;
    assert_eq!(r.indexed, 2, "{r:?}");
    assert_eq!(
        unread(&fx.search(q).await),
        vec![("read elsewhere".into(), false), ("unread again".into(), true), ("untouched".into(), true)]
    );
    let cmds = fx.commands_since(mark);
    assert!(cmds.iter().all(|c| !c.contains("CHANGEDSINCE")), "{cmds:?}");
    assert!(cmds.iter().any(|c| c.contains("UID FETCH") && c.contains("FLAGS")), "{cmds:?}");
    assert!(!fx.h.imap.flags(&fx.u.user, "INBOX", untouched).unwrap().contains(&"\\Seen".to_string()));
    fx.h.imap.assert_only_allowlisted();
}

/// A new UIDVALIDITY re-reads the folder: its old ids leave the index and resolve to `not_found`, other folders keep
/// their rows and ids.
#[tokio::test]
async fn uidvalidity_change_rebuilds_folder() {
    let fx = setup(plain()).await;
    for i in 0..3 {
        fx.add("INBOX", &simple(&format!("inbox {i}")), &[]);
    }
    let sent_uid = fx.add("Sent", &simple("sent one"), &["\\Seen"]);
    fx.sync().await;
    let old: Vec<String> = {
        let mut v = vec![];
        for uid in fx.h.imap.uids(&fx.u.user, "INBOX") {
            v.push(fx.id("INBOX", uid).await);
        }
        v
    };
    let sent_id = fx.id("Sent", sent_uid).await;
    fx.h.imap.set_uidvalidity(&fx.u.user, "INBOX", 777_000);
    let r = fx.sync().await;
    assert_eq!((r.indexed, r.removed), (3, 3), "{r:?}");
    let now = fx.indexed().await;
    assert!(old.iter().all(|o| !now.contains(o)), "old ids gone: {now:?}");
    assert!(now.contains(&sent_id), "other folders untouched");
    assert_eq!(now.iter().filter(|i| i.contains("-777000-")).count(), 3, "{now:?}");
    assert_eq!(fx.h.err(&fx.token, "get_message", json!({"account": "info", "message_id": old[0]})).await, "not_found");
    let new_id = now.iter().find(|i| i.contains("-777000-")).unwrap();
    fx.h.ok(&fx.token, "get_message", json!({"account": "info", "message_id": new_id})).await;
}

#[tokio::test]
async fn trash_and_junk_hidden_by_default() {
    let fx = setup(plain()).await;
    fx.add("INBOX", &simple("visible"), &[]);
    fx.add("Trash", &simple("binned"), &[]);
    fx.add("Junk", &simple("spammy"), &[]);
    fx.sync().await;
    let v = fx.search(json!({"select": ["subject"]})).await;
    assert_eq!(strs(col(&v, "subject")), vec!["visible"], "{v}");
    let v = fx.search(json!({"select": ["subject"], "include_spam_trash": true})).await;
    assert_eq!(strs(col(&v, "subject")), vec!["binned", "spammy", "visible"], "{v}");
    let v = fx
        .search(json!({"select": ["labels"], "where": pred("label", "eq", json!("TRASH")), "include_spam_trash": true}))
        .await;
    assert_eq!(col(&v, "labels").len(), 1, "{v}");
}

/// The "what is new" question: unread mail since a date, across the mailbox.
#[tokio::test]
async fn search_is_unread_since_date() {
    let fx = setup(plain()).await;
    let u = &fx.u.user;
    fx.h.imap.add_message_at(u, "INBOX", &simple("old unread"), &[], DAY0 - 86_400 * 30);
    fx.h.imap.add_message_at(u, "INBOX", &simple("new unread"), &[], DAY0 + 3600);
    fx.h.imap.add_message_at(u, "INBOX", &simple("new read"), &["\\Seen"], DAY0 + 7200);
    fx.h.imap.add_folder(u, "Projekte", None);
    fx.h.imap.add_message_at(u, "Projekte", &simple("new in folder"), &[], DAY0 + 10_800);
    fx.sync().await;
    let v = fx
        .search(json!({
            "where": {"all": [pred("is_unread", "eq", json!(true)), pred("received_at", "gte", json!("2026-01-01T00:00:00Z"))]},
            "select": ["subject", "received_at"],
            "order_by": [{"field": "received_at", "dir": "desc"}],
        }))
        .await;
    assert_eq!(col(&v, "subject"), vec![json!("new in folder"), json!("new unread")], "{v}");
    assert_eq!(col(&v, "received_at")[1], json!("2026-01-01T01:00:00Z"));
}

/// Thread members come from the index by the derived thread id (References/In-Reply-To root), across folders, oldest
/// first; by message id and by thread id alike.
#[tokio::test]
async fn get_thread_groups_by_references() {
    let fx = setup(plain()).await;
    let u = &fx.u.user;
    fx.h.imap.add_message_at(u, "INBOX", &mail("Ann <ann@example.org>", "Plan", "root@x", "", "first"), &[], DAY0);
    fx.h.imap.add_message_at(
        u,
        "Sent",
        &mail(
            "Me <info@example.org>",
            "Re: Plan",
            "r1@x",
            "In-Reply-To: <root@x>\r\nReferences: <root@x>\r\n",
            "second",
        ),
        &["\\Seen"],
        DAY0 + 60,
    );
    let last = fx.h.imap.add_message_at(
        u,
        "INBOX",
        &mail(
            "Ann <ann@example.org>",
            "Re: Plan",
            "r2@x",
            "In-Reply-To: <r1@x>\r\nReferences: <root@x> <r1@x>\r\n",
            "third",
        ),
        &[],
        DAY0 + 120,
    );
    fx.h.imap.add_message_at(u, "INBOX", &simple("unrelated"), &[], DAY0 + 30);
    // A stranger who knows the root Message-ID but not the subject cannot join the thread.
    fx.h.imap.add_message_at(
        u,
        "INBOX",
        &mail("Eve <eve@evil.example>", "Urgent: new bank details", "f@evil", "References: <root@x>\r\n", "forged"),
        &[],
        DAY0 + 90,
    );
    fx.sync().await;
    let by_msg =
        fx.h.ok(&fx.token, "get_thread", json!({"account": "info", "message_id": fx.id("INBOX", last).await})).await;
    let bodies: Vec<String> = by_msg["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["body_text"].as_str().unwrap().trim().to_string())
        .collect();
    assert_eq!(bodies, vec!["first", "second", "third"], "{by_msg}");
    assert_eq!(by_msg["thread_incomplete"], false);
    let tid = by_msg["thread_id"].as_str().unwrap();
    let by_tid = fx.h.ok(&fx.token, "get_thread", json!({"account": "info", "thread_id": tid})).await;
    assert_eq!(by_tid["messages"].as_array().unwrap().len(), 3);
    let unknown =
        fx.h.err(&fx.token, "get_thread", json!({"account": "info", "thread_id": "tAAAAAAAAAAAAAAAAAAAAAA"})).await;
    assert_eq!(unknown, "not_found");
    // Reading a thread never marks messages read.
    assert!(!fx.h.imap.flags(u, "INBOX", last).unwrap().contains(&"\\Seen".to_string()));
}

/// get_thread reads all members in one round (PLAN A69): one EXAMINE and one metadata FETCH per folder, one body
/// FETCH per message, no size probes. Before, every member cost its own session with EXAMINE, metadata, size and body.
#[tokio::test]
async fn get_thread_fetches_members_in_one_round() {
    let fx = setup(plain()).await;
    let u = &fx.u.user;
    fx.h.imap.add_message_at(u, "INBOX", &mail("Ann <ann@example.org>", "Plan", "root@x", "", "first"), &[], DAY0);
    let refs = |r: &str| format!("In-Reply-To: <{r}>\r\nReferences: <root@x>\r\n");
    fx.h.imap.add_message_at(
        u,
        "Sent",
        &mail("Me <info@example.org>", "Re: Plan", "r1@x", &refs("root@x"), "second"),
        &["\\Seen"],
        DAY0 + 60,
    );
    fx.h.imap.add_message_at(
        u,
        "INBOX",
        &mail("Ann <ann@example.org>", "Re: Plan", "r2@x", &refs("r1@x"), "third"),
        &[],
        DAY0 + 120,
    );
    let last = fx.h.imap.add_message_at(
        u,
        "INBOX",
        &mail("Ann <ann@example.org>", "Re: Plan", "r3@x", &refs("r2@x"), "fourth"),
        &[],
        DAY0 + 180,
    );
    fx.sync().await;
    let tid = fx
        .h
        .ok(&fx.token, "get_thread", json!({"account": "info", "message_id": fx.id("INBOX", last).await}))
        .await["thread_id"]
        .as_str()
        .unwrap()
        .to_string();
    let mark = fx.h.imap.commands().len();
    let v = fx.h.ok(&fx.token, "get_thread", json!({"account": "info", "thread_id": tid})).await;
    let bodies: Vec<&str> =
        v["messages"].as_array().unwrap().iter().map(|m| m["body_text"].as_str().unwrap().trim()).collect();
    assert_eq!(bodies, ["first", "second", "third", "fourth"], "{v}");
    let cmds = fx.commands_since(mark);
    let count = |pat: &str| cmds.iter().filter(|c| c.contains(pat)).count();
    assert_eq!(count("EXAMINE"), 2, "one per folder: {cmds:?}");
    assert_eq!(count("BODY.PEEK[]"), 4, "{cmds:?}");
    assert_eq!(count("(UID RFC822.SIZE)"), 0, "{cmds:?}");
    assert_eq!(count("UID FETCH"), 2 + 4, "one metadata fetch per folder plus one body fetch per message: {cmds:?}");
}

/// A message over `index.max_message_bytes` is indexed from IMAP metadata only; its body is never fetched.
#[tokio::test]
async fn oversize_message_metadata_only() {
    let fx = setup_with(plain(), |c| c.index.max_message_bytes = 4096).await;
    fx.add("INBOX", &simple("small one"), &[]);
    let big_body = "x".repeat(10_000);
    let big = fx.add("INBOX", &mail("Ann <ann@example.org>", "huge", "huge@x", "", &big_body), &[]);
    let mark = fx.h.imap.commands().len();
    fx.sync().await;
    assert_eq!(fx.indexed().await.len(), 2);
    let cmds = fx.commands_since(mark);
    assert!(!cmds.iter().any(|c| c.contains(&format!("UID FETCH {big} (UID BODY.PEEK[])"))), "{cmds:?}");
    // The size comes with the metadata fetch; no separate size probe (PLAN A69).
    assert!(!cmds.iter().any(|c| c.contains("(UID RFC822.SIZE)")), "{cmds:?}");
    let v = fx.search(json!({"select": ["message_id", "subject", "size_bytes"], "where": pred("size_bytes", "gte", json!(10_000))})).await;
    assert_eq!(col(&v, "message_id"), vec![json!(fx.id("INBOX", big).await)], "{v}");
    assert_eq!(col(&v, "subject"), vec![Value::Null], "headers unknown: {v}");
    let v = fx.search(json!({"where": pred("has_attachment", "eq", json!(false)), "select": ["subject"]})).await;
    assert_eq!(v["coverage"], "partial", "MIME metadata unknown for one message: {v}");
}

#[tokio::test]
async fn gmail_live_source_rejected_for_imap() {
    let fx = setup(plain()).await;
    fx.h.mailbox("gm", "gm@example.com");
    fx.h.project("mixed", &["info", "gm"]).await;
    let token = fx.h.token("mixed", "agent2", vec![g("info", "read"), g("gm", "read")]).await;
    let e =
        fx.h.err(&token, "search_messages", json!({"source": "gmail", "gmail_query": "x", "accounts": ["info"]})).await;
    assert_eq!(e, "invalid_argument");
    let e =
        fx.h.err(&token, "search_messages", json!({"source": "gmail", "gmail_query": "x", "accounts": ["info", "gm"]}))
            .await;
    assert_eq!(e, "invalid_argument");
    // Without an explicit list the IMAP mailbox is reported, not silently skipped.
    let v = fx.h.ok(&token, "search_messages", json!({"source": "gmail", "gmail_query": "x"})).await;
    assert_eq!(v["account_errors"], json!([{"account": "info", "code": "invalid_argument"}]), "{v}");
}

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// AC20 for IMAP: after indexing and searching, the data directory, the logs and the audit log hold no subject, body,
/// sender, folder name or password.
#[tokio::test]
async fn index_files_hold_no_plaintext() {
    let sink = Sink::default();
    assert!(dove::logging::install_service_logging(sink.clone(), tracing_subscriber::EnvFilter::new("trace")));
    let fx = setup(plain()).await;
    let (subject, body, sender, folder) =
        ("IMAPCANARY-SUBJ-4e1", "IMAPCANARY-BODY-77d wire money", "imapcanary-from-9@example.org", "IMAPCANARY-FOLDER");
    fx.h.imap.add_folder(&fx.u.user, folder, None);
    fx.add(folder, &mail(&format!("Canary Person <{sender}>"), subject, "canary@x", "", body), &[]);
    fx.sync().await;
    let v =
        fx.search(json!({"where": pred("text", "terms", json!("IMAPCANARY-BODY-77d")), "select": ["subject"]})).await;
    assert_eq!(col(&v, "subject"), vec![json!(subject)], "{v}");
    let v = fx.search(json!({"where": pred("label", "eq", json!(folder)), "select": ["subject"]})).await;
    assert_eq!(col(&v, "subject").len(), 1, "{v}");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let logs = sink.0.lock().unwrap().clone();
    let audit: String =
        fx.h.app().store.call(|c| Ok(serde_json::to_string(&dove::audit::tail(c, 10_000)?)?)).await.unwrap();
    let canaries = [subject, "IMAPCANARY-BODY", sender, "Canary Person", folder, fx.u.password.as_str()];
    for c in canaries {
        assert!(!contains(&logs, c), "canary {c:?} in logs");
        if c != subject && c != folder {
            // The search arguments are audited as the query; subject and folder were search terms above.
            assert!(!audit.contains(c), "canary {c:?} in the audit log");
        }
    }
    let mut files = 0;
    for e in std::fs::read_dir(&fx.h.app().cfg.data_dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            files += 1;
            let b = std::fs::read(&p).unwrap_or_default();
            // Folder names are account settings in the state store (`imap_folders`, as connect records them); the
            // index itself must not hold them in plaintext.
            let is_state = p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("state.db"));
            for c in canaries.iter().filter(|c| !(is_state && **c == folder)) {
                assert!(!contains(&b, c), "canary {c:?} in plaintext file {}", p.display());
            }
        }
    }
    assert!(files >= 3, "state and index files were checked");
}
