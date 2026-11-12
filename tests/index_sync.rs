//! Step 3: index admin verbs and the sync engine, driven through the admin dispatcher, the deterministic sync entry
//! point and MCP search over HTTP against the fake Google server. Covers AC16 (index verbs) and the AC20 sync
//! fixtures: arrival during backfill, label removal, deletion, history expiration, restart before checkpoint,
//! disable/remove purge, disk full.

mod support;

use std::time::Duration;

use dove::admin::AdminRequest;
use dove::index::sync::{sync_account, sync_steps};
use serde_json::{Value, json};
use support::fake_google::{Fault, MessageSpec};
use support::harness::{Harness, g};

const T0: i64 = 1_790_000_000_000; // 2026-09-21T...Z, fixed fixture time

fn msg(from: &str, subject: &str, text: &str, i: i64) -> MessageSpec {
    MessageSpec {
        from: from.into(),
        to: vec!["info@acme.test".into()],
        subject: subject.into(),
        text: Some(text.into()),
        labels: vec!["INBOX".into(), "UNREAD".into()],
        internal_date_ms: T0 + i * 60_000,
        ..Default::default()
    }
}

struct Fx {
    h: Harness,
    token: String,
    info: String,
    ids: Vec<String>,
}

async fn setup(page_size: u32, n: i64) -> Fx {
    let h = Harness::start_with(|c| c.index.list_page_size = page_size).await;
    let info = h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    let mut ids = vec![];
    for i in 0..n {
        ids.push(h.google.add_message(
            "info@acme.test",
            msg(&format!("sender{i}@example.com"), &format!("Message {i}"), &format!("body number{i}"), i),
        ));
    }
    Fx { h, token, info, ids }
}

async fn enable(h: &Harness) {
    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
}

async fn search(fx: &Fx, args: Value) -> Value {
    fx.h.ok(&fx.token, "search_messages", args).await
}

fn col(v: &Value, name: &str) -> Vec<Value> {
    let i = v["columns"].as_array().unwrap().iter().position(|c| c == name).unwrap();
    v["rows"].as_array().unwrap().iter().map(|r| r[i].clone()).collect()
}

fn subjects(v: &Value) -> Vec<String> {
    let mut s: Vec<String> = col(v, "subject").iter().map(|x| x.as_str().unwrap_or("").to_string()).collect();
    s.sort();
    s
}

async fn index_rows(h: &Harness) -> i64 {
    h.app().index.write(|c| Ok(c.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?)).await.unwrap()
}

async fn status(h: &Harness) -> Value {
    let v = h.admin(AdminRequest::IndexStatus { alias: Some("info".into()) }).await.unwrap();
    v["accounts"][0].clone()
}

fn gmail_calls(h: &Harness) -> usize {
    h.google.requests().iter().filter(|r| r.path.contains("/gmail/")).count()
}

#[tokio::test]
async fn admin_verbs_backfill_and_zero_gmail_search() {
    let fx = setup(3, 7).await;
    let h = &fx.h;
    // Disabled by default: no index, search reports the mailbox as not indexed.
    let v = search(&fx, json!({})).await;
    assert_eq!(v["coverage"], "partial");
    assert_eq!(v["exceptions"][0]["stage"], "not_indexed");
    assert_eq!(status(h).await["stage"], "disabled");

    // Every index verb is one audit record, also failures.
    let before = h.audit_count().await;
    let e = h.admin(AdminRequest::IndexRebuild { alias: "info".into() }).await.unwrap_err();
    assert!(e.contains("not enabled"), "{e}");
    assert!(h.admin(AdminRequest::IndexEnable { alias: "nope".into() }).await.is_err());
    enable(h).await;
    assert_eq!(status(h).await["stage"], "backfill");
    assert_eq!(h.audit_count().await, before + 4);

    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(r.indexed, 7, "{r:?}");
    assert_eq!(r.error, None);
    let st = status(h).await;
    assert_eq!(st["stage"], "ready");
    assert_eq!(st["indexed_messages"], 7);
    assert_eq!(st["retry_pending"], 0);
    // Seven messages with page size 3: three list calls, recorded with includeSpamTrash.
    let lists: Vec<_> = h.google.requests().into_iter().filter(|r| r.path.ends_with("/messages")).collect();
    assert_eq!(lists.len(), 3);
    assert!(lists.iter().all(|r| r.query.contains("includeSpamTrash=true")));
    // Status output carries no mail content.
    assert!(!st.to_string().contains("Message"));

    // Ready index: searches, counts and projections make zero Gmail calls.
    h.google.clear_requests();
    let v = search(&fx, json!({"select": ["subject", "from", "snippet"], "limit": 100})).await;
    assert_eq!(v["coverage"], "complete");
    assert_eq!(v["rows"].as_array().unwrap().len(), 7);
    let v = search(&fx, json!({"count_only": true})).await;
    assert_eq!(v["count"], 7);
    let v = search(&fx, json!({"where": {"field": "text", "op": "terms", "value": "number3"}})).await;
    assert_eq!(subjects(&v), vec!["Message 3"]);
    assert_eq!(gmail_calls(h), 0);

    // Disable: one audit record, rows purged, search back to not_indexed.
    let before = h.audit_count().await;
    h.admin(AdminRequest::IndexDisable { alias: "info".into() }).await.unwrap();
    assert_eq!(h.audit_count().await, before + 1);
    assert_eq!(index_rows(h).await, 0);
    let v = search(&fx, json!({})).await;
    assert_eq!(v["exceptions"][0]["stage"], "not_indexed");
    assert_eq!(v["rows"].as_array().unwrap().len(), 0);
    h.google.assert_no_violations();
}

#[tokio::test]
async fn reconcile_arrival_label_and_deletion_during_backfill() {
    let fx = setup(3, 7).await;
    let h = &fx.h;
    enable(h).await;
    // Capture history id, list page 1, index page 1.
    let r = sync_steps(h.app(), &fx.info, 3).await.unwrap();
    assert_eq!(r.indexed, 3, "{r:?}");
    // Partial results are exposed while the backfill runs; require_complete refuses.
    let v = search(&fx, json!({"select": ["subject"], "limit": 100})).await;
    assert_eq!(v["coverage"], "partial");
    assert_eq!(v["exceptions"][0]["stage"], "backfill");
    assert_eq!(subjects(&v), vec!["Message 4", "Message 5", "Message 6"]);
    let code = h.err(&fx.token, "search_messages", json!({"coverage_policy": "require_complete"})).await;
    assert_eq!(code, "index_incomplete");

    // Changes after the captured history id: arrival (newest, already past in enumeration), deletion of an indexed
    // message, label removal on an indexed message.
    let new_id = h.google.add_message("info@acme.test", msg("late@example.com", "Late arrival", "late body", 100));
    h.google.delete_message("info@acme.test", &fx.ids[6]);
    h.google.set_labels("info@acme.test", &fx.ids[5], &[], &["UNREAD"]);

    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(r.stage, "ready", "{r:?}");
    let v = search(&fx, json!({"select": ["subject", "is_unread", "message_id"], "limit": 100})).await;
    assert_eq!(v["coverage"], "complete");
    let s = subjects(&v);
    assert!(s.contains(&"Late arrival".to_string()));
    assert!(!s.contains(&"Message 6".to_string()));
    assert_eq!(s.len(), 7);
    let ids = col(&v, "message_id");
    let unread = col(&v, "is_unread");
    let i5 = ids.iter().position(|x| x == &json!(fx.ids[5])).unwrap();
    assert_eq!(unread[i5], json!(false));
    assert!(ids.contains(&json!(new_id)));
    let v =
        search(&fx, json!({"where": {"field": "is_unread", "op": "eq", "value": false}, "select": ["subject"]})).await;
    assert_eq!(subjects(&v), vec!["Message 5"]);
}

#[tokio::test]
async fn incremental_sync_advances_checkpoint_after_writes() {
    let fx = setup(500, 3).await;
    let h = &fx.h;
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    let ck1 = checkpoint(h, &fx.info).await;

    // Nothing changed: one history call, last successful check recorded, checkpoint unchanged.
    h.google.clear_requests();
    sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(h.google.count("GET", "/history"), 1);
    assert_eq!(gmail_calls(h), 1);
    assert_eq!(checkpoint(h, &fx.info).await, ck1);

    let id = h.google.add_message("info@acme.test", msg("new@example.com", "Fresh", "fresh text", 50));
    h.google.set_labels("info@acme.test", &id, &["STARRED"], &[]);
    h.google.set_labels("info@acme.test", &fx.ids[0], &["TRASH"], &["INBOX"]);
    h.google.delete_message("info@acme.test", &fx.ids[1]);
    h.google.clear_requests();
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(r.error, None, "{r:?}");
    // The new message is fetched once (coalesced add + label), the trashed one only for labels, the deleted one not.
    assert_eq!(h.google.count("GET", &format!("/messages/{id}")), 1);
    assert_eq!(h.google.count("GET", &format!("/messages/{}", fx.ids[1])), 0);
    assert_eq!(checkpoint(h, &fx.info).await, h.google.history_id("info@acme.test").to_string());

    let v = search(&fx, json!({"select": ["subject", "is_starred"]})).await;
    assert_eq!(subjects(&v), vec!["Fresh", "Message 2"]);
    // Trash is excluded by default and included on request.
    let v = search(&fx, json!({"select": ["subject"], "include_spam_trash": true})).await;
    assert_eq!(subjects(&v), vec!["Fresh", "Message 0", "Message 2"]);
    let v =
        search(&fx, json!({"where": {"field": "is_starred", "op": "eq", "value": true}, "select": ["subject"]})).await;
    assert_eq!(subjects(&v), vec!["Fresh"]);
}

async fn checkpoint(h: &Harness, aid: &str) -> String {
    let a = aid.to_string();
    h.app()
        .index
        .write(move |c| Ok(dove::index::sync::load_state(c, &a)?.unwrap().checkpoint.unwrap_or_default()))
        .await
        .unwrap()
}

#[tokio::test]
async fn interrupted_pass_replays_from_old_checkpoint() {
    let fx = setup(500, 1).await;
    let h = &fx.h;
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    let ck = checkpoint(h, &fx.info).await;
    let mut new = vec![];
    for i in 0..20 {
        new.push(h.google.add_message("info@acme.test", msg("bulk@example.com", &format!("Bulk {i}"), "x", 10 + i)));
    }
    // Changes apply in id order in chunks of 16. The 18th fetch hangs; the pass is aborted like a crash after the
    // first chunk committed.
    new.sort();
    h.google.fail_next("GET", &format!("/messages/{}", new[17]), Fault::Delay(Duration::from_secs(5)));
    let r = tokio::time::timeout(Duration::from_millis(1500), sync_account(h.app(), &fx.info)).await;
    assert!(r.is_err(), "the pass should still be waiting");
    assert!(index_rows(h).await > 1, "first chunk committed");
    assert!(index_rows(h).await < 21);
    assert_eq!(checkpoint(h, &fx.info).await, ck, "checkpoint must not move before all writes commit");
    // Restart: a fresh pass replays from the old checkpoint and loses nothing.
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(r.error, None);
    assert_eq!(index_rows(h).await, 21);
    assert_ne!(checkpoint(h, &fx.info).await, ck);
}

#[tokio::test]
async fn failed_message_is_recorded_and_retried() {
    let fx = setup(500, 3).await;
    let h = &fx.h;
    enable(h).await;
    h.google.fail_next("GET", &format!("/messages/{}", fx.ids[1]), Fault::Status(400, json!({"error": {}})));
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!((r.indexed, r.failed), (2, 1), "{r:?}");
    assert_eq!(status(h).await["stage"], "ready");
    assert_eq!(status(h).await["retry_pending"], 1);
    // The gap is reported: partial coverage, and require_complete refuses.
    let v = search(&fx, json!({"select": ["subject"]})).await;
    assert_eq!(v["coverage"], "partial");
    assert_eq!(v["exceptions"][0]["reason"], "messages pending retry");
    assert_eq!(h.err(&fx.token, "search_messages", json!({"count_only": true})).await, "index_incomplete");
    // Once due, the next pass retries it.
    h.app().index.write(|c| Ok(c.execute("UPDATE pending SET next_attempt_at = 0", [])?)).await.unwrap();
    sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(status(h).await["retry_pending"], 0);
    assert_eq!(search(&fx, json!({"count_only": true})).await["count"], 3);
}

#[tokio::test]
async fn history_expiry_rebuilds_into_new_generation() {
    let fx = setup(2, 5).await;
    let h = &fx.h;
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    let first = search(&fx, json!({"select": ["subject"], "limit": 2})).await;
    let cursor = first["next_cursor"].as_str().unwrap().to_string();

    // Gmail no longer has history from our checkpoint.
    let new_id = h.google.add_message("info@acme.test", msg("x@example.com", "After gap", "gap text", 60));
    h.google.set_history_floor("info@acme.test", h.google.history_id("info@acme.test"));
    // One incremental pass detects the gap and starts a rebuild; the old generation is served but never complete.
    sync_steps(h.app(), &fx.info, 1).await.unwrap();
    assert_eq!(status(h).await["stage"], "rebuilding");
    let v = search(&fx, json!({"select": ["subject"], "limit": 100})).await;
    assert_eq!(v["coverage"], "partial");
    assert_eq!(v["exceptions"][0]["stage"], "rebuilding");
    assert_eq!(subjects(&v).len(), 5);
    assert_eq!(h.err(&fx.token, "search_messages", json!({"count_only": true})).await, "index_incomplete");
    // Cursors from before the gap are invalid.
    assert_eq!(h.err(&fx.token, "search_messages", json!({"cursor": cursor})).await, "cursor_invalid");

    h.google.set_history_floor("info@acme.test", 0);
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(r.stage, "ready", "{r:?}");
    let v = search(&fx, json!({"select": ["subject", "message_id"], "limit": 100})).await;
    assert_eq!(v["coverage"], "complete");
    assert_eq!(subjects(&v).len(), 6);
    assert!(col(&v, "message_id").contains(&json!(new_id)));
    // The retired generation is gone: exactly one row per message and one generation.
    assert_eq!(index_rows(h).await, 6);
    let gens: i64 =
        h.app().index.write(|c| Ok(c.query_row("SELECT count(*) FROM generations", [], |r| r.get(0))?)).await.unwrap();
    assert_eq!(gens, 1);
}

/// An oversized message is never read whole (spec 8.1a): its raw answer is refused at the byte cap, and it is
/// indexed from Gmail metadata only with incomplete coverage for queries that need its body or MIME fields.
#[tokio::test]
async fn oversized_message_is_indexed_from_metadata_without_reading_it() {
    let h = Harness::start_with(|c| c.index.max_message_bytes = 4096).await;
    let info = h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    let mb = "info@acme.test";
    h.google.add_message(mb, msg("small@example.com", "Small one", "needle small", 1));
    let mut big = msg("big@example.com", "Huge one", "needle huge", 2);
    big.labels.push("STARRED".into());
    big.attachments = vec![("video.bin".into(), "application/octet-stream".into(), vec![7u8; 2 * 1024 * 1024])];
    let big_id = h.google.add_message(mb, big);
    let big_size = h.google.message_raw(mb, &big_id).unwrap().len();
    enable(&h).await;
    let before = h.app().google.gateway().bytes_read.load(std::sync::atomic::Ordering::Relaxed);
    let r = sync_account(h.app(), &info).await.unwrap();
    assert_eq!((r.indexed, r.failed, r.error.as_deref()), (2, 0, None), "{r:?}");
    let read = h.app().google.gateway().bytes_read.load(std::sync::atomic::Ordering::Relaxed) - before;
    assert!(read < 256 * 1024, "read {read} bytes while syncing a {big_size}-byte message");
    // The oversized raw answer was requested once and then only its metadata.
    let gets: Vec<String> = h
        .google
        .requests()
        .into_iter()
        .filter(|q| q.path.ends_with(&format!("/messages/{big_id}")))
        .map(|q| q.query)
        .collect();
    assert_eq!(gets, vec!["format=raw".to_string(), "format=minimal".to_string()]);

    let fx = Fx { h, token, info, ids: vec![] };
    // Metadata (labels, date) answers completely and finds it.
    let v = search(&fx, json!({"where": {"field": "label", "op": "eq", "value": "STARRED"}, "select": ["message_id"]}))
        .await;
    assert_eq!(col(&v, "message_id"), vec![json!(big_id)]);
    assert_eq!(v["coverage"], "complete");
    // A body query cannot claim to have searched it.
    let v =
        search(&fx, json!({"where": {"field": "body_text", "op": "terms", "value": "needle"}, "select": ["subject"]}))
            .await;
    assert_eq!(subjects(&v), vec!["Small one"]);
    assert_eq!(v["coverage"], "partial");
    fx.h.google.assert_no_violations();
}

/// A message that arrives while history.list is paginating is not on the later (snapshotted) pages; the checkpoint
/// must not move past it, so the next pass picks it up.
#[tokio::test]
async fn arrival_during_history_pagination_is_not_skipped() {
    let fx = setup(500, 3).await;
    let h = &fx.h;
    let mb = "info@acme.test";
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    for id in &fx.ids {
        h.google.set_labels(mb, id, &["STARRED"], &[]);
    }
    // Three records over two pages; the second page is held back while a new message arrives.
    h.google.set_history_page_size(mb, 2);
    h.google.fail_after("GET", "/history", 1, Fault::Delay(Duration::from_millis(800)));
    h.google.clear_requests();
    let (app, info) = (h.app().clone(), fx.info.clone());
    let pass = tokio::spawn(async move { sync_account(&app, &info).await });
    for _ in 0..500 {
        if h.google.count("GET", "/history") >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(h.google.count("GET", "/history"), 2, "second history page requested");
    let late = h.google.add_message(mb, msg("late@example.com", "Late arrival", "late text", 30));
    let r = pass.await.unwrap().unwrap();
    assert_eq!(r.error, None, "{r:?}");
    let starred = search(&fx, json!({"where": {"field": "is_starred", "op": "eq", "value": true}, "count_only": true}));
    assert_eq!(starred.await["count"], 3);

    // The next pass replays from the first page's history id and finds the late message.
    sync_account(h.app(), &fx.info).await.unwrap();
    let v = search(&fx, json!({"select": ["message_id"], "limit": 100})).await;
    assert!(col(&v, "message_id").contains(&json!(late)), "late arrival skipped: {v}");
    h.google.assert_no_violations();
}

#[tokio::test]
async fn admin_rebuild_cuts_over_and_fences_old_job() {
    let fx = setup(500, 4).await;
    let h = &fx.h;
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    h.admin(AdminRequest::IndexRebuild { alias: "info".into() }).await.unwrap();
    assert_eq!(status(h).await["stage"], "rebuilding");
    sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(status(h).await["stage"], "ready");
    assert_eq!(index_rows(h).await, 4);
}

fn files_contain(dir: &std::path::Path, needle: &str) -> bool {
    std::fs::read_dir(dir).unwrap().any(|e| {
        let p = e.unwrap().path();
        p.is_file() && std::fs::read(&p).unwrap().windows(needle.len()).any(|w| w == needle.as_bytes())
    })
}

/// Postings for `term` across every generation's FTS table.
async fn fts_hits(h: &Harness, term: &str) -> i64 {
    let t = format!("\"{term}\"");
    h.app()
        .index
        .write(move |c| {
            let tables: Vec<String> = {
                let mut st = c.prepare("SELECT name FROM sqlite_schema WHERE sql LIKE 'CREATE VIRTUAL TABLE%fts5%'")?;
                st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            let mut n = 0i64;
            for tb in tables {
                n += c.query_row(&format!("SELECT count(*) FROM {tb} WHERE {tb} MATCH ?1"), [&t], |r| {
                    r.get::<_, i64>(0)
                })?;
            }
            Ok(n)
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn disable_and_remove_purge_even_with_job_in_flight() {
    let fx = setup(500, 3).await;
    let h = &fx.h;
    let canary = "zebracanary4711";
    h.google.add_message("info@acme.test", msg("c@example.com", "Canary mail", &format!("secret {canary} text"), 9));
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    let v =
        search(&fx, json!({"where": {"field": "body_text", "op": "terms", "value": canary}, "select": ["subject"]}))
            .await;
    assert_eq!(subjects(&v), vec!["Canary mail"]);
    assert_eq!(fts_hits(h, canary).await, 1);
    // The encrypted index files never contain the canary in plaintext.
    let data = h.app().cfg.data_dir.clone();
    assert!(!files_contain(&data, canary));

    // A rebuild job is in flight (its first fetch hangs) when the operator disables indexing.
    h.admin(AdminRequest::IndexRebuild { alias: "info".into() }).await.unwrap();
    for id in &fx.ids {
        h.google.fail_next("GET", &format!("/messages/{id}"), Fault::Delay(Duration::from_millis(800)));
    }
    let app = h.app().clone();
    let aid = fx.info.clone();
    let job = tokio::spawn(async move { sync_account(&app, &aid).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    h.admin(AdminRequest::IndexDisable { alias: "info".into() }).await.unwrap();
    let r = job.await.unwrap().unwrap();
    assert!(r.fenced, "{r:?}");
    // Give any straggling work time to (wrongly) write, then verify nothing was repopulated.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(index_rows(h).await, 0);
    assert_eq!(fts_hits(h, canary).await, 0);
    let v = search(&fx, json!({"where": {"field": "body_text", "op": "terms", "value": canary}})).await;
    assert_eq!(v["rows"].as_array().unwrap().len(), 0);
    // A sync attempt for the disabled account does nothing.
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert!(r.skipped_inactive);
    assert_eq!(index_rows(h).await, 0);

    // Account removal purges too.
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    assert!(index_rows(h).await > 0);
    h.admin(AdminRequest::AccountsRemove { alias: "info".into() }).await.unwrap();
    assert_eq!(index_rows(h).await, 0);
    let states: i64 =
        h.app().index.write(|c| Ok(c.query_row("SELECT count(*) FROM sync_state", [], |r| r.get(0))?)).await.unwrap();
    assert_eq!(states, 0);
}

#[tokio::test]
async fn disk_full_pauses_sync_without_blocking_reads() {
    let fx = setup(500, 2).await;
    let h = &fx.h;
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    // Cap the index file at its current size.
    h.app()
        .index
        .write(|c| {
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            let n: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            c.query_row(&format!("PRAGMA max_page_count = {n}"), [], |_| Ok(()))?;
            Ok(())
        })
        .await
        .unwrap();
    for i in 0..30 {
        let big = "lorem ipsum dolor ".repeat(400);
        h.google.add_message("info@acme.test", msg("bulk@example.com", &format!("Big {i}"), &big, 20 + i));
    }
    let ck = checkpoint(h, &fx.info).await;
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(r.error.as_deref(), Some("disk_full"), "{r:?}");
    assert_eq!(checkpoint(h, &fx.info).await, ck);
    // Reads keep working (partial is honest: last success is older than now) and live reads are unaffected.
    let v = search(&fx, json!({"select": ["subject"]})).await;
    assert_eq!(subjects(&v).len(), 2);
    let m = fx.h.ok(&fx.token, "get_message", json!({"account": "info", "message_id": fx.ids[0]})).await;
    assert_eq!(m["message"]["subject"], "Message 0");
    // Space returns: sync recovers.
    h.app().index.write(|c| Ok(c.query_row("PRAGMA max_page_count = 1073741823", [], |_| Ok(()))?)).await.unwrap();
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(r.error, None);
    assert_eq!(index_rows(h).await, 32);
}

#[tokio::test]
async fn rate_limit_backs_off() {
    let fx = setup(500, 1).await;
    let h = &fx.h;
    enable(h).await;
    sync_account(h.app(), &fx.info).await.unwrap();
    for _ in 0..3 {
        h.google.fail_next("GET", "/history", Fault::Status(429, json!({"error": {"code": 429}})));
    }
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!(r.error.as_deref(), Some("rate_limited"));
    let a = fx.info.clone();
    let st = h.app().index.write(move |c| Ok(dove::index::sync::load_state(c, &a)?.unwrap())).await.unwrap();
    assert!(st.backoff_secs >= 60, "{st:?}");
    assert!(st.next_run_at > dove::util::now_unix() + 30);
    assert_eq!(status(h).await["last_error"], "rate_limited");
}

#[tokio::test]
async fn vanished_candidate_is_dropped_not_retried() {
    let fx = setup(500, 3).await;
    let h = &fx.h;
    enable(h).await;
    // Capture the history id and list the only page; nothing fetched yet.
    sync_steps(h.app(), &fx.info, 2).await.unwrap();
    h.google.delete_message("info@acme.test", &fx.ids[1]);
    let r = sync_account(h.app(), &fx.info).await.unwrap();
    assert_eq!((r.indexed, r.failed), (2, 0), "{r:?}");
    assert_eq!(status(h).await["retry_pending"], 0);
    let v = search(&fx, json!({"select": ["subject"], "coverage_policy": "require_complete"})).await;
    assert_eq!(subjects(&v), vec!["Message 0", "Message 2"]);
}

/// The background scheduler started by `dove serve`: enabling starts a backfill, a Dove draft write wakes sync.
#[tokio::test]
async fn scheduler_backfills_on_enable_and_wakes_after_writes() {
    let h = Harness::start().await;
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read,draft")]).await;
    h.google.add_message("info@acme.test", msg("a@example.com", "Hello", "hi", 1));
    let engine = dove::index::start(h.app().clone());
    enable(&h).await;
    let until = |cond: Value| {
        let (h, token) = (&h, &token);
        async move {
            for _ in 0..100 {
                let v = h.ok(token, "search_messages", json!({"select": ["subject", "is_draft"], "where": cond})).await;
                if v["coverage"] == "complete" && !v["rows"].as_array().unwrap().is_empty() {
                    return v;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("scheduler did not sync in time");
        }
    };
    let v = until(json!({})).await;
    assert_eq!(v["rows"], json!([["Hello", false]]));
    // Poll interval is 60 s; only the wake from create_draft makes the draft appear this fast.
    h.ok(
        &token,
        "create_draft",
        json!({"account": "info", "request_key": uuid::Uuid::new_v4().to_string(), "to": ["bob@example.org"], "subject": "Draft one", "body_text": "x"}),
    )
    .await;
    let v = until(json!({"field": "is_draft", "op": "eq", "value": true})).await;
    assert_eq!(v["rows"], json!([["Draft one", true]]));
    engine.abort();
}
