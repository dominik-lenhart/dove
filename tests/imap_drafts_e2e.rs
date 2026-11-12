//! IMAP drafts (design "Drafts"): APPEND to Drafts, own-draft content hashes, replace-then-expunge of exactly the
//! Dove-owned UID, conflicts on any outside change. Runs against the fake IMAP server; its command log proves that
//! no UID other than Dove's own draft is ever flagged `\Deleted` or expunged.

mod support;

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::fake_imap::{Fault, encode_utf7, verb_of};
use support::harness::{FakeImapUser, Harness, g};

const MB: &str = "info@example.org";

struct Setup {
    h: Harness,
    u: FakeImapUser,
    token: String,
}

async fn setup() -> Setup {
    let h = Harness::start().await;
    let u = h.imap_mailbox("info", MB).await;
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read,draft")]).await;
    Setup { h, u, token }
}

fn key() -> String {
    uuid::Uuid::new_v4().to_string()
}

async fn create(h: &Harness, token: &str, body: &str) -> Value {
    h.ok(
        token,
        "create_draft",
        json!({ "account": "info", "request_key": key(), "to": ["Zoë <zoe@example.net>"], "subject": "Angebot",
                "body_text": body }),
    )
    .await
}

fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

/// (message_id, content_hash, state) of an own-draft record.
async fn own(h: &Harness, draft_id: &str) -> (String, Option<Vec<u8>>, String) {
    let d = draft_id.to_string();
    h.app()
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT message_id, content_hash, state FROM own_drafts WHERE draft_id = ?1", [d], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?)
        })
        .await
        .unwrap()
}

/// UID of an agent-visible IMAP id (`f<folder>-<uidvalidity>-<uid>`).
fn uid_of(id: &str) -> u32 {
    id.rsplit('-').next().unwrap().parse().unwrap()
}

async fn folder_id(h: &Harness, account_id: &str, name: &str) -> i64 {
    let (a, n) = (account_id.to_string(), encode_utf7(name));
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

async fn imap_id(h: &Harness, u: &FakeImapUser, folder: &str, uid: u32) -> String {
    format!("f{}-{}-{uid}", folder_id(h, &u.account_id, folder).await, h.imap.uidvalidity(&u.user, folder))
}

/// Every `UID STORE` / `UID EXPUNGE` in the command log, as (verb, uid set). No other deleting verb may appear.
fn deletions(h: &Harness) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for c in h.imap.commands() {
        let verb = verb_of(&c);
        assert!(!matches!(verb.as_str(), "EXPUNGE" | "STORE" | "MOVE" | "COPY" | "UID MOVE" | "UID COPY"), "{c}");
        if verb == "UID STORE" || verb == "UID EXPUNGE" {
            out.push((verb, c.split(' ').nth(2).unwrap_or_default().to_string()));
        }
    }
    out
}

/// The log holds exactly one STORE and one EXPUNGE, both naming only `uid`.
fn assert_deleted_only(h: &Harness, uid: u32) {
    let d = deletions(h);
    let want = vec![("UID STORE".to_string(), uid.to_string()), ("UID EXPUNGE".to_string(), uid.to_string())];
    assert_eq!(d, want, "{:?}", h.imap.commands());
    let store = h.imap.commands().into_iter().find(|c| verb_of(c) == "UID STORE").unwrap();
    assert!(store.ends_with("+FLAGS.SILENT (\\Deleted)"), "{store}");
}

fn human_draft(subject: &str) -> Vec<u8> {
    format!(
        "From: info@example.org\r\nTo: x@example.net\r\nSubject: {subject}\r\nMessage-ID: <h-{subject}@example.org>\r\n\
         Date: Thu, 01 Jan 2026 10:00:00 +0000\r\n\r\nhuman text\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn create_appends_to_drafts_with_flags() {
    let Setup { h, u, token } = setup().await;
    let c = create(&h, &token, "Hallo Zoë").await;
    let draft_id = c["draft_id"].as_str().unwrap();
    assert!(draft_id.starts_with('d') && draft_id.len() == 23, "{draft_id}");
    let rev = c["revision"].as_str().unwrap();
    assert_eq!(c["message_id"], rev);
    let uids = h.imap.uids(&u.user, "Drafts");
    assert_eq!(uids.len(), 1);
    assert_eq!(rev, imap_id(&h, &u, "Drafts", uids[0]).await);
    let flags = h.imap.flags(&u.user, "Drafts", uids[0]).unwrap();
    assert!(flags.contains(&"\\Draft".to_string()) && flags.contains(&"\\Seen".to_string()), "{flags:?}");
    let raw = h.imap.message_raw(&u.user, "Drafts", uids[0]).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("From: <info@example.org>") || text.contains("From: info@example.org"), "{text}");
    assert!(text.contains("Subject: Angebot"));
    // The record holds the hash of the server's bytes and the agent-visible id as revision.
    let (mid, hash, state) = own(&h, draft_id).await;
    assert_eq!((mid.as_str(), state.as_str()), (rev, "active"));
    assert_eq!(hash.unwrap(), sha(&raw));
    assert!(c["thread_id"].as_str().unwrap().starts_with('t'));
    // Nothing else was touched; no deletion happened.
    assert!(h.imap.uids(&u.user, "INBOX").is_empty() && h.imap.uids(&u.user, "Sent").is_empty());
    assert!(deletions(&h).is_empty());
    h.imap.assert_only_allowlisted();

    // from_address must be the mailbox's own address (no send-as aliases for IMAP).
    let e = h
        .err(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "body_text": "x",
                    "from_address": "other@example.org" }),
        )
        .await;
    assert_eq!(e, "invalid_argument");
    assert_eq!(h.imap.uids(&u.user, "Drafts").len(), 1);
}

#[tokio::test]
async fn request_key_idempotent() {
    let Setup { h, u, token } = setup().await;
    let args = json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "body_text": "one" });
    let a = h.ok(&token, "create_draft", args.clone()).await;
    let b = h.ok(&token, "create_draft", args.clone()).await;
    assert_eq!(a["draft_id"], b["draft_id"]);
    assert_eq!(a["revision"], b["revision"]);
    let mut changed = args.clone();
    changed["body_text"] = json!("two");
    assert_eq!(h.err(&token, "create_draft", changed).await, "invalid_argument");
    let appends = || h.imap.commands().iter().filter(|c| verb_of(c) == "APPEND").count();
    assert_eq!(appends(), 1);
    assert_eq!(h.imap.uids(&u.user, "Drafts").len(), 1);

    // A connection lost after the APPEND was sent is an unknown outcome; the same key never appends again.
    let lost = json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "body_text": "lost" });
    h.imap.fail_next("APPEND", Fault::DropAfterApply);
    assert_eq!(h.err(&token, "create_draft", lost.clone()).await, "outcome_unknown");
    assert_eq!(h.err(&token, "create_draft", lost).await, "outcome_unknown");
    assert_eq!(appends(), 2);
    // A definitive refusal is recorded as failed; the key cannot be reused for a new attempt.
    let refused = json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "body_text": "no" });
    h.imap.fail_next("APPEND", Fault::No);
    assert_eq!(h.err(&token, "create_draft", refused.clone()).await, "upstream_error");
    assert_eq!(h.err(&token, "create_draft", refused).await, "upstream_error");
    assert_eq!(appends(), 3);
    assert!(deletions(&h).is_empty());
}

#[tokio::test]
async fn update_replaces_and_expunges_only_own_uid() {
    let Setup { h, u, token } = setup().await;
    // Human drafts around Dove's, one already flagged \Deleted (not yet expunged by its client): a plain EXPUNGE
    // would remove it, UID EXPUNGE of Dove's UID must not.
    let h1 = h.imap.add_message(&u.user, "Drafts", &human_draft("one"), &["\\Draft"]);
    let c = create(&h, &token, "erste Fassung").await;
    let h2 = h.imap.add_message(&u.user, "Drafts", &human_draft("two"), &["\\Draft", "\\Deleted"]);
    let inbox = h.imap.add_message(&u.user, "INBOX", &human_draft("inbox"), &[]);
    let (draft_id, rev1) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    let old_uid = uid_of(rev1);
    h.imap.clear_commands();

    let up = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev1,
                    "changes": { "body_text": "zweite Fassung" } }),
        )
        .await;
    let rev2 = up["revision"].as_str().unwrap();
    assert_ne!(rev2, rev1);
    assert_eq!(up["draft_id"], draft_id);
    let new_uid = uid_of(rev2);
    let mut drafts = h.imap.uids(&u.user, "Drafts");
    drafts.sort_unstable();
    assert_eq!(drafts, vec![h1, h2, new_uid]);
    assert_eq!(h.imap.uids(&u.user, "INBOX"), vec![inbox]);
    assert!(h.imap.flags(&u.user, "Drafts", h2).unwrap().contains(&"\\Deleted".to_string()));
    assert!(!h.imap.flags(&u.user, "Drafts", h1).unwrap().contains(&"\\Deleted".to_string()));
    assert_deleted_only(&h, old_uid);
    // The record moved to the new UID with the hash of the server's new bytes.
    let raw = h.imap.message_raw(&u.user, "Drafts", new_uid).unwrap();
    assert!(String::from_utf8_lossy(&raw).contains("zweite Fassung"));
    let (mid, hash, state) = own(&h, draft_id).await;
    assert_eq!((mid.as_str(), state.as_str()), (rev2, "active"));
    assert_eq!(hash.unwrap(), sha(&raw));
    // Recipients and subject were kept; the Message-ID stays the same across revisions.
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("zoe@example.net") && text.contains("Subject: Angebot"), "{text}");
    assert_eq!(up["thread_id"], c["thread_id"]);

    // The old revision is stale now.
    h.imap.clear_commands();
    let stale =
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev1, "changes": { "subject": "x" } });
    assert_eq!(h.err(&token, "update_draft", stale).await, "draft_conflict");
    assert!(deletions(&h).is_empty());
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn server_rewrite_is_not_conflict() {
    let Setup { h, u, token } = setup().await;
    // The server stores different bytes than Dove sent (CRLF normalisation, an added header).
    h.imap.rewrite_on_append(true);
    let c = create(&h, &token, "eins\nzwei").await;
    let (draft_id, rev) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    let raw = h.imap.message_raw(&u.user, "Drafts", uid_of(rev)).unwrap();
    assert!(String::from_utf8_lossy(&raw).starts_with("X-Fake-Stored: yes"));
    let d = h.ok(&token, "get_draft", json!({ "account": "info", "draft_id": draft_id })).await;
    assert_eq!(d["editable_by_dove"], true, "{d}");
    let up = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev, "changes": { "subject": "Neu" } }),
        )
        .await;
    let rev2 = up["revision"].as_str().unwrap();
    // And again from the rewritten second revision.
    h.ok(
        &token,
        "update_draft",
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev2, "changes": { "body_text": "drei" } }),
    )
    .await;
    assert_eq!(h.imap.uids(&u.user, "Drafts").len(), 1);
}

#[tokio::test]
async fn human_resave_is_conflict() {
    let Setup { h, u, token } = setup().await;
    let c = create(&h, &token, "von Dove").await;
    let (draft_id, rev) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    let old = uid_of(rev);
    // Apple Mail saves an edit as a new message and expunges the old one.
    let raw = h.imap.message_raw(&u.user, "Drafts", old).unwrap();
    let edited = String::from_utf8_lossy(&raw).replace("von Dove", "vom Menschen");
    let human = h.imap.add_message(&u.user, "Drafts", edited.as_bytes(), &["\\Draft", "\\Seen"]);
    h.imap.expunge_external(&u.user, "Drafts", old);
    h.imap.clear_commands();

    let up =
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev, "changes": { "body_text": "x" } });
    assert_eq!(h.err(&token, "update_draft", up).await, "draft_conflict");
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![human]);
    assert!(String::from_utf8_lossy(&h.imap.message_raw(&u.user, "Drafts", human).unwrap()).contains("vom Menschen"));
    assert!(deletions(&h).is_empty(), "{:?}", h.imap.commands());
    assert!(!h.imap.commands().iter().any(|c| verb_of(c) == "APPEND"));
    // The human's version is listed as a draft Dove does not own.
    let all = h.ok(&token, "list_drafts", json!({ "account": "info", "own_only": false })).await;
    let ds = all["drafts"].as_array().unwrap();
    assert_eq!(ds.len(), 1, "{all}");
    assert_eq!(ds[0]["owned"], false);
    assert_eq!(ds[0]["revision"], imap_id(&h, &u, "Drafts", human).await);
    let own_only = h.ok(&token, "list_drafts", json!({ "account": "info" })).await;
    assert_eq!(own_only["drafts"], json!([]));
}

#[tokio::test]
async fn uidvalidity_change_is_conflict() {
    let Setup { h, u, token } = setup().await;
    let c = create(&h, &token, "x").await;
    let (draft_id, rev) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    // A rebuilt folder renumbers its messages: the same UID may now name another message.
    h.imap.add_message(&u.user, "Drafts", &human_draft("other"), &["\\Draft"]);
    h.imap.set_uidvalidity(&u.user, "Drafts", 4242);
    assert!(h.imap.uids(&u.user, "Drafts").contains(&uid_of(rev)));
    h.imap.clear_commands();
    let up =
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev, "changes": { "body_text": "y" } });
    assert_eq!(h.err(&token, "update_draft", up).await, "draft_conflict");
    assert!(deletions(&h).is_empty(), "{:?}", h.imap.commands());
    assert_eq!(h.imap.uids(&u.user, "Drafts").len(), 2);
}

#[tokio::test]
async fn content_hash_mismatch_is_conflict() {
    let Setup { h, u, token } = setup().await;
    let c = create(&h, &token, "x").await;
    let (draft_id, rev) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    // Same UID and UIDVALIDITY, other bytes than Dove recorded (a server that reuses UIDs, or a broken record): not
    // provably Dove's draft, so neither replaced nor deleted.
    let d = draft_id.to_string();
    h.app()
        .store
        .call(move |c| Ok(c.execute("UPDATE own_drafts SET content_hash = x'00' WHERE draft_id = ?1", [d])?))
        .await
        .unwrap();
    h.imap.clear_commands();
    let up =
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev, "changes": { "body_text": "y" } });
    let (is_err, v) = h.call(&token, "update_draft", up).await;
    assert!(is_err);
    assert_eq!(v["error"]["code"], "draft_conflict");
    assert!(deletions(&h).is_empty() && !h.imap.commands().iter().any(|c| verb_of(c) == "APPEND"));
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![uid_of(rev)]);
    let g = h.ok(&token, "get_draft", json!({ "account": "info", "draft_id": draft_id })).await;
    assert_eq!(g["editable_by_dove"], false);
}

#[tokio::test]
async fn drafts_folder_change_is_conflict() {
    let Setup { h, u, token } = setup().await;
    let c = create(&h, &token, "x").await;
    let (draft_id, rev) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    // The operator points Drafts at another folder (with the same UIDVALIDITY and a message under the same UID):
    // Dove's old id no longer names a message in the Drafts folder, so nothing may be deleted there.
    h.imap.add_folder(&u.user, "Entwürfe", None);
    h.imap.set_uidvalidity(&u.user, "Entwürfe", h.imap.uidvalidity(&u.user, "Drafts"));
    let victim = h.imap.add_message(&u.user, "Entwürfe", &human_draft("victim"), &["\\Draft"]);
    assert_eq!(victim, uid_of(rev));
    let aid = u.account_id.clone();
    h.app()
        .store
        .call(move |c| {
            c.execute("UPDATE imap_folders SET special = NULL WHERE account_id = ?1 AND special = 'drafts'", [&aid])?;
            let next: i64 = c.query_row(
                "SELECT COALESCE(MAX(folder_id), 0) + 1 FROM imap_folders WHERE account_id = ?1",
                [&aid],
                |r| r.get(0),
            )?;
            c.execute(
                "INSERT INTO imap_folders(account_id, folder_id, name, special) VALUES (?1, ?2, ?3, 'drafts')",
                rusqlite::params![aid, next, encode_utf7("Entwürfe")],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    h.imap.clear_commands();
    let up =
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev, "changes": { "body_text": "y" } });
    assert_eq!(h.err(&token, "update_draft", up).await, "draft_conflict");
    assert!(deletions(&h).is_empty(), "{:?}", h.imap.commands());
    assert_eq!(h.imap.uids(&u.user, "Entwürfe"), vec![victim]);
}

#[tokio::test]
async fn append_lost_is_update_unknown() {
    let Setup { h, u, token } = setup().await;
    let c = create(&h, &token, "x").await;
    let (draft_id, rev) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    h.imap.clear_commands();
    h.imap.fail_next("APPEND", Fault::DropAfterApply);
    let up =
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev, "changes": { "body_text": "y" } });
    assert_eq!(h.err(&token, "update_draft", up.clone()).await, "outcome_unknown");
    assert_eq!(own(&h, draft_id).await.2, "update_unknown");
    // Blocked from then on; the old copy is never deleted on an unknown outcome.
    assert_eq!(h.err(&token, "update_draft", up).await, "outcome_unknown");
    assert!(deletions(&h).is_empty(), "{:?}", h.imap.commands());
    assert!(h.imap.uids(&u.user, "Drafts").contains(&uid_of(rev)));
    assert_eq!(h.imap.commands().iter().filter(|c| verb_of(c) == "APPEND").count(), 1);
}

#[tokio::test]
async fn failed_delete_moves_record_and_reports_once() {
    let Setup { h, u, token } = setup().await;
    let c = create(&h, &token, "x").await;
    let (draft_id, rev) = (c["draft_id"].as_str().unwrap(), c["revision"].as_str().unwrap());
    h.imap.fail_next("UID EXPUNGE", Fault::No);
    let up =
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev, "changes": { "body_text": "y" } });
    let r = h.ok(&token, "update_draft", up).await;
    let rev2 = r["revision"].as_str().unwrap();
    assert_eq!(own(&h, draft_id).await.0, rev2);
    // The stale copy stays (flagged, not expunged); the operator hears about it once, without content.
    assert_eq!(h.imap.uids(&u.user, "Drafts").len(), 2);
    let notes: Vec<String> = h.app().notifier.sent.lock().unwrap().clone();
    let stale: Vec<&String> = notes.iter().filter(|m| m.contains(draft_id)).collect();
    assert_eq!(stale.len(), 1, "{notes:?}");
    assert!(!stale[0].contains("zoe@") && !stale[0].contains("Angebot"), "{}", stale[0]);
    // Further updates work from the new revision and delete only that revision's UID.
    h.imap.clear_commands();
    let up =
        json!({ "account": "info", "draft_id": draft_id, "expected_revision": rev2, "changes": { "body_text": "z" } });
    h.ok(&token, "update_draft", up).await;
    assert_deleted_only(&h, uid_of(rev2));
}

#[tokio::test]
async fn list_and_get_drafts() {
    let Setup { h, u, token } = setup().await;
    let a = create(&h, &token, "erster").await;
    let b = create(&h, &token, "zweiter").await;
    let human = h.imap.add_message(&u.user, "Drafts", &human_draft("human"), &["\\Draft"]);
    let human_id = imap_id(&h, &u, "Drafts", human).await;

    let own_only = h.ok(&token, "list_drafts", json!({ "account": "info" })).await;
    let ds = own_only["drafts"].as_array().unwrap();
    assert_eq!(ds.len(), 2, "{own_only}");
    for d in ds {
        assert_eq!(d["owned"], true);
        assert_eq!(d["changed_outside_dove"], false);
        assert_eq!(d["subject"], "Angebot");
        assert_eq!(d["to"], json!(["Zoë <zoe@example.net>"]));
    }
    let ids: Vec<&Value> = ds.iter().map(|d| &d["draft_id"]).collect();
    assert!(ids.contains(&&a["draft_id"]) && ids.contains(&&b["draft_id"]));

    let all = h.ok(&token, "list_drafts", json!({ "account": "info", "own_only": false })).await;
    let ds = all["drafts"].as_array().unwrap();
    assert_eq!(ds.len(), 3, "{all}");
    let hd = ds.iter().find(|d| d["revision"] == human_id.as_str()).unwrap();
    assert_eq!(hd["owned"], false);
    assert_eq!(hd["draft_id"], human_id.as_str());
    // Paging through all drafts one at a time visits each once.
    let mut seen = Vec::new();
    let mut page: Option<String> = None;
    loop {
        let mut args = json!({ "account": "info", "own_only": false, "limit": 1 });
        if let Some(p) = &page {
            args["page_token"] = json!(p);
        }
        let v = h.ok(&token, "list_drafts", args).await;
        seen.extend(v["drafts"].as_array().unwrap().iter().map(|d| d["revision"].clone()));
        match v["next_page_token"].as_str() {
            Some(p) => page = Some(p.to_string()),
            None => break,
        }
        assert!(seen.len() <= 3);
    }
    assert_eq!(seen.len(), 3);

    let gd = h.ok(&token, "get_draft", json!({ "account": "info", "draft_id": a["draft_id"] })).await;
    assert_eq!(gd["owned"], true);
    assert_eq!(gd["editable_by_dove"], true);
    assert_eq!(gd["revision"], a["revision"]);
    assert!(gd["message"]["body_text"].as_str().unwrap().contains("erster"));
    let gh = h.ok(&token, "get_draft", json!({ "account": "info", "draft_id": human_id })).await;
    assert_eq!(gh["owned"], false);
    assert_eq!(gh["editable_by_dove"], false);
    // Reading drafts never sets \Seen on the human's draft.
    assert!(!h.imap.flags(&u.user, "Drafts", human).unwrap().contains(&"\\Seen".to_string()));
    // Ids outside Drafts and unknown draft ids are the same not_found.
    let inbox = h.imap.add_message(&u.user, "INBOX", &human_draft("mail"), &[]);
    let inbox_id = imap_id(&h, &u, "INBOX", inbox).await;
    let nf = h.call(&token, "get_draft", json!({ "account": "info", "draft_id": "dAAAAAAAAAAAAAAAAAAAAAA" })).await.1;
    assert_eq!(nf["error"]["code"], "not_found");
    assert_eq!(h.call(&token, "get_draft", json!({ "account": "info", "draft_id": inbox_id })).await.1, nf);

    // Another project's agent sees Dove's drafts as not owned and cannot edit them.
    h.project("q", &["info"]).await;
    let other = h.token("q", "other", vec![g("info", "read,draft")]).await;
    let v = h.ok(&other, "list_drafts", json!({ "account": "info" })).await;
    assert_eq!(v["drafts"], json!([]));
    let up = json!({ "account": "info", "draft_id": a["draft_id"], "expected_revision": a["revision"],
                     "changes": { "body_text": "fremd" } });
    assert_eq!(h.err(&other, "update_draft", up).await, "not_found");
    assert!(deletions(&h).is_empty());
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn reply_draft_threads_by_headers() {
    let Setup { h, u, token } = setup().await;
    let orig = b"From: Daniel <daniel@example.net>\r\nTo: info@example.org\r\nSubject: Termin\r\n\
Message-ID: <orig@example.net>\r\nReferences: <root@example.net>\r\nIn-Reply-To: <root@example.net>\r\n\
Date: Thu, 01 Jan 2026 10:00:00 +0000\r\n\r\nPasst Dienstag?\r\n";
    let uid = h.imap.add_message(&u.user, "INBOX", orig, &[]);
    let orig_id = imap_id(&h, &u, "INBOX", uid).await;
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "to": ["daniel@example.net"], "body_text": "Ja.",
                    "reply_to_message_id": orig_id }),
        )
        .await;
    let raw = h.imap.message_raw(&u.user, "Drafts", uid_of(c["revision"].as_str().unwrap())).unwrap();
    let text = String::from_utf8_lossy(&raw).replace("\r\n ", " ");
    assert!(text.contains("In-Reply-To: <orig@example.net>"), "{text}");
    assert!(text.contains("References: <root@example.net> <orig@example.net>"), "{text}");
    assert!(text.contains("Subject: Re: Termin"), "{text}");
    let m = h.ok(&token, "get_message", json!({ "account": "info", "message_id": orig_id })).await;
    assert_eq!(c["thread_id"], m["message"]["thread_id"]);
    // Replying never marks the original read.
    assert!(!h.imap.flags(&u.user, "INBOX", uid).unwrap().contains(&"\\Seen".to_string()));
}

/// `OwnDraftUid` is the only way to STORE/EXPUNGE; only the IMAP drafts tools may construct it.
#[test]
fn only_drafts_tools_construct_own_draft_uid() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    let mut users = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        // Unit tests of the allowlist build one in `ops.rs`'s test module; everything else counts.
        let code = text.split("#[cfg(test)]").next().unwrap();
        if code.contains("new_for_drafts(") {
            users.push(f.strip_prefix(root).unwrap().to_string_lossy().into_owned());
        }
    }
    users.sort();
    assert_eq!(users, vec!["src/imap/session.rs", "src/tools/drafts_imap.rs"]);
}

/// A 4 s call budget (writes dispatch by 3 s) and a 10 s IMAP command timeout, so one delayed command can outlive
/// the call.
async fn short_budget() -> Setup {
    let h = Harness::start_with(|c| {
        c.limits.tool_call_timeout_secs = 4;
        c.limits.upstream_request_timeout_secs = 10;
    })
    .await;
    let u = h.imap_mailbox("info", MB).await;
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read,draft")]).await;
    Setup { h, u, token }
}

async fn wait_for<F: std::future::Future<Output = bool>>(mut f: impl FnMut() -> F) {
    let until = Instant::now() + Duration::from_secs(10);
    while !f().await && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn create_whose_append_outlives_the_call_is_still_recorded() {
    let Setup { h, u, token } = short_budget().await;
    let args = json!({ "account": "info", "request_key": key(), "to": ["zoe@example.net"], "subject": "Spät",
                       "body_text": "late" });
    h.imap.fail_next("APPEND", Fault::Delay(Duration::from_secs(5)));
    let started = Instant::now();
    let (is_err, v) = h.call(&token, "create_draft", args.clone()).await;
    assert!(is_err);
    assert_eq!(v["error"]["code"], "outcome_unknown", "{v}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // The APPEND lands after the call ended; the detached write reads it back and records it.
    let app = h.app().clone();
    wait_for(|| {
        let app = app.clone();
        async move {
            app.store
                .call(|c| {
                    Ok(c.query_row("SELECT count(*) FROM create_operations WHERE state = 'succeeded'", [], |r| {
                        r.get::<_, i64>(0)
                    })?)
                })
                .await
                .unwrap()
                == 1
        }
    })
    .await;
    // Retrying the same request_key returns that draft instead of an unknown outcome or a second copy.
    let r = h.ok(&token, "create_draft", args).await;
    let uids = h.imap.uids(&u.user, "Drafts");
    assert_eq!(uids.len(), 1);
    assert_eq!(uid_of(r["revision"].as_str().unwrap()), uids[0]);
    let (rev, hash, state) = own(&h, r["draft_id"].as_str().unwrap()).await;
    assert_eq!((rev.as_str(), state.as_str()), (r["revision"].as_str().unwrap(), "active"));
    assert_eq!(hash, Some(sha(&h.imap.message_raw(&u.user, "Drafts", uids[0]).unwrap())));
}

#[tokio::test]
async fn update_whose_append_outlives_the_call_moves_the_record_and_removes_the_old_copy() {
    let Setup { h, u, token } = short_budget().await;
    let c = create(&h, &token, "v1").await;
    let (d, old) = (c["draft_id"].as_str().unwrap().to_string(), c["revision"].as_str().unwrap().to_string());
    h.imap.clear_commands();
    h.imap.fail_next("APPEND", Fault::Delay(Duration::from_secs(5)));
    let up = json!({ "account": "info", "draft_id": d, "expected_revision": old, "changes": { "body_text": "v2" } });
    let (is_err, v) = h.call(&token, "update_draft", up).await;
    assert!(is_err);
    assert_eq!(v["error"]["code"], "outcome_unknown", "{v}");
    wait_for(|| async { own(&h, &d).await.0 != old }).await;
    let (new, _, state) = own(&h, &d).await;
    assert_ne!(new, old, "the new revision was recorded");
    assert_eq!(state, "active");
    wait_for(|| async { h.imap.uids(&u.user, "Drafts") == vec![uid_of(&new)] }).await;
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![uid_of(&new)], "exactly one copy, the new one");
    let o = uid_of(&old).to_string();
    assert_eq!(deletions(&h), vec![("UID STORE".into(), o.clone()), ("UID EXPUNGE".into(), o)]);
    let up = json!({ "account": "info", "draft_id": d, "expected_revision": new, "changes": { "body_text": "v3" } });
    h.ok(&token, "update_draft", up).await;
}

#[tokio::test]
async fn update_that_runs_out_of_time_before_its_append_writes_nothing() {
    let Setup { h, u, token } = short_budget().await;
    let c = create(&h, &token, "v1").await;
    let (d, old) = (c["draft_id"].as_str().unwrap().to_string(), c["revision"].as_str().unwrap().to_string());
    h.imap.clear_commands();
    // The fresh read before the write takes longer than the whole call.
    h.imap.fail_next("UID FETCH", Fault::Delay(Duration::from_secs(5)));
    let up = json!({ "account": "info", "draft_id": d, "expected_revision": old, "changes": { "body_text": "v2" } });
    let (is_err, v) = h.call(&token, "update_draft", up).await;
    assert!(is_err);
    assert_eq!(v["error"]["code"], "upstream_error", "{v}");
    // The detached task finishes its read after the call ended and must stop at the commit gate.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(h.imap.commands().iter().any(|c| verb_of(c) == "UID FETCH"), "{:?}", h.imap.commands());
    assert!(!h.imap.commands().iter().any(|c| verb_of(c) == "APPEND"), "{:?}", h.imap.commands());
    let (rev, _, state) = own(&h, &d).await;
    assert_eq!((rev.as_str(), state.as_str()), (old.as_str(), "active"));
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![uid_of(&old)]);
    // Done reading at ~3.3 s, inside the 4 s budget but past the 3 s write deadline: too late to start a write.
    h.imap.fail_next("UID FETCH", Fault::Delay(Duration::from_millis(3300)));
    let up = json!({ "account": "info", "draft_id": d, "expected_revision": old, "changes": { "body_text": "v2" } });
    assert_eq!(h.err(&token, "update_draft", up).await, "upstream_error");
    assert!(!h.imap.commands().iter().any(|c| verb_of(c) == "APPEND"), "{:?}", h.imap.commands());
    assert_eq!(own(&h, &d).await.0, old);
}
