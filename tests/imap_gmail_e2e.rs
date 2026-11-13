//! Gmail over IMAP with an app password (design `docs/superpowers/specs/2026-11-13-gmail-imap-design.md`, PLAN A57):
//! detection at connect, the `gmail` preset, one index row per message from All Mail/Spam/Trash with labels from
//! `X-GM-LABELS`, IDLE and the quick pass on All Mail, and organize through `X-GM-LABELS` and `UID MOVE` only. The
//! fake server's Gmail mode keeps one copy per label folder, like Gmail; its command log proves Dove never sets
//! `\Deleted` or expunges outside Drafts.

mod support;

use std::time::{Duration, Instant};

use dove::admin::AdminRequest;
use dove::imap::{TlsMode, presets};
use dove::index::imap_sync::{quick_inbox, sync_steps};
use serde_json::{Value, json};
use support::fake_imap::{FakeImap, Opts, verb_of};
use support::harness::{FakeImapUser, Harness, g};

const PW: &str = "app-password-abcd";
const ALL: &str = "[Gmail]/All Mail";
const SPAM: &str = "[Gmail]/Spam";
const TRASH: &str = "[Gmail]/Trash";

fn gmail() -> Opts {
    Opts { gmail: true, qresync: false, ..Opts::default() }
}

fn mail(subject: &str) -> Vec<u8> {
    format!(
        "From: Anna <anna@example.com>\r\nTo: me@gmail.com\r\nSubject: {subject}\r\nMessage-ID: <{}@example.com>\r\n\
         Date: Thu, 01 Jan 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Hello there.\r\n",
        subject.replace(' ', "-")
    )
    .into_bytes()
}

fn now() -> i64 {
    dove::util::now_unix() - 3600
}

struct Fx {
    h: Harness,
    u: FakeImapUser,
    token: String,
}

/// Connects `me@gmail.com` on a Gmail-mode fake server through the real admin verb.
async fn setup_with(opts: Opts) -> Fx {
    setup_cfg(opts, |_| {}).await
}

async fn setup_cfg(opts: Opts, customize: impl FnOnce(&mut dove::config::Config)) -> Fx {
    let mut h = Harness::start_with(customize).await;
    h.imap = FakeImap::start_with(opts).await;
    let user = "me@gmail.com";
    h.imap.gmail_user(user, PW);
    h.admin(h.connect_imap_request("me", user, PW)).await.expect("connect-imap");
    let account_id: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT id FROM accounts WHERE alias = 'me'", [], |r| r.get(0))?))
        .await
        .unwrap();
    h.project("p", &["me"]).await;
    let actions = if h.app().cfg.allow_send { "full,send" } else { "full" };
    let token = h.token("p", "agent", vec![g("me", actions)]).await;
    let u = FakeImapUser { alias: "me".into(), email: user.into(), user: user.into(), password: PW.into(), account_id };
    Fx { h, u, token }
}

async fn setup() -> Fx {
    setup_with(gmail()).await
}

impl Fx {
    fn add(&self, labels: &[&str], subject: &str, flags: &[&str]) -> u64 {
        self.h.imap.gm_add(&self.u.user, labels, &mail(subject), flags, now())
    }

    async fn sync(&self) {
        self.h.admin(AdminRequest::IndexEnable { alias: "me".into() }).await.unwrap();
        let r = sync_steps(self.h.app(), &self.u.account_id, usize::MAX).await.unwrap();
        assert_eq!(r.error, None, "{r:?}");
    }

    async fn folder_id(&self, name: &str) -> i64 {
        let (a, n) = (self.u.account_id.clone(), support::fake_imap::encode_utf7(name));
        self.h
            .app()
            .store
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT folder_id FROM imap_folders WHERE account_id = ?1 AND name = ?2",
                    [a, n],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap()
    }

    /// The agent id of Gmail message `gm` in `folder`.
    async fn id(&self, folder: &str, gm: u64) -> String {
        let uid = self.h.imap.gm_uid(&self.u.user, folder, gm).unwrap_or_else(|| panic!("{gm} not in {folder}"));
        format!("f{}-{}-{uid}", self.folder_id(folder).await, self.h.imap.uidvalidity(&self.u.user, folder))
    }

    /// Indexed (id, labels) pairs, sorted by id.
    async fn rows(&self) -> Vec<(String, Vec<String>)> {
        let mut v: Vec<(String, String)> = self
            .h
            .app()
            .index
            .write(|c| {
                let mut st = c.prepare("SELECT gmail_id, labels FROM messages")?;
                Ok(st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap();
        v.sort();
        v.into_iter()
            .map(|(id, l)| {
                let mut l: Vec<String> = serde_json::from_str(&l).unwrap();
                l.sort();
                (id, l)
            })
            .collect()
    }

    async fn labels_of(&self, id: &str) -> Vec<String> {
        self.rows()
            .await
            .into_iter()
            .find(|(i, _)| i == id)
            .map(|(_, l)| l)
            .unwrap_or_else(|| panic!("{id} not indexed"))
    }

    async fn subjects(&self, label: &str) -> Vec<String> {
        let v = self
            .h
            .ok(
                &self.token,
                "search_messages",
                json!({"where": {"field": "label", "op": "eq", "value": label}, "select": ["subject"], "limit": 50}),
            )
            .await;
        let i = v["columns"].as_array().unwrap().iter().position(|c| c == "subject").unwrap();
        let mut s: Vec<String> =
            v["rows"].as_array().unwrap().iter().map(|r| r[i].as_str().unwrap_or_default().to_string()).collect();
        s.sort();
        s
    }
}

fn sorted(v: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = v.iter().map(|s| s.to_string()).collect();
    v.sort();
    v
}

/// Mailboxes the commands selected or examined (wire names, unquoted).
fn selected(cmds: &[String]) -> Vec<String> {
    cmds.iter()
        .filter(|c| matches!(verb_of(c).as_str(), "SELECT" | "EXAMINE"))
        .map(|c| c.split_once(' ').unwrap().1.split(" (").next().unwrap().trim_matches('"').to_string())
        .collect()
}

// ------------------------------------------------------------------ connect

#[test]
fn gmail_preset_for_gmail_addresses() {
    for addr in ["x@gmail.com", "x@GoogleMail.com"] {
        let p = presets::for_email(addr).unwrap();
        assert_eq!(p.name, "gmail");
        assert_eq!((p.imap.host.as_str(), p.imap.port, p.imap.tls), ("imap.gmail.com", 993, TlsMode::Implicit));
        assert_eq!((p.smtp.host.as_str(), p.smtp.port, p.smtp.tls), ("smtp.gmail.com", 465, TlsMode::Implicit));
        // Gmail files submitted mail in Sent itself.
        assert!(!p.save_sent_copy);
    }
    assert_eq!(presets::by_name("Gmail").map(|p| p.name), Some("gmail"));
    assert!(presets::for_email("x@gmail.example").is_none());
}

/// `X-GM-EXT-1` puts the account in Gmail mode (stored, `\All` recorded) even without the preset (a Workspace
/// domain), and Dove then files no Sent copy. Without the capability nothing changes.
#[tokio::test]
async fn connect_detects_gmail_mode() {
    let mut h = Harness::start().await;
    h.imap = FakeImap::start_with(gmail()).await;
    h.imap.gmail_user("me@firma.example", PW);
    let v = h.admin(h.connect_imap_request("ws", "me@firma.example", PW)).await.unwrap();
    assert_eq!(v["preset"], Value::Null, "{v}");
    assert_eq!((v["gmail"].as_bool(), v["save_sent_copy"].as_bool()), (Some(true), Some(false)), "{v}");
    assert_eq!(v["all_mail_folder"], ALL);
    assert_eq!(v["drafts_folder"], "[Gmail]/Drafts");
    let (settings, special): (String, String) = h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row(
                "SELECT a.imap_settings, f.special FROM accounts a JOIN imap_folders f ON f.account_id = a.id \
                 WHERE a.alias = 'ws' AND f.name = '[Gmail]/All Mail'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .await
        .unwrap();
    let s: Value = serde_json::from_str(&settings).unwrap();
    assert_eq!((s["gmail"].as_bool(), s["save_sent_copy"].as_bool()), (Some(true), Some(false)));
    assert_eq!(special, "all");
    // `[Gmail]` itself (\Noselect) is no folder.
    let n: i64 = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT count(*) FROM imap_folders WHERE name = '[Gmail]'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(n, 0);
    // Reconnect keeps the mode.
    h.admin(AdminRequest::AccountsReconnectImap {
        alias: "ws".into(),
        password: dove::admin::Password(zeroize::Zeroizing::new(PW.into())),
    })
    .await
    .unwrap();
    let settings: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT imap_settings FROM accounts WHERE alias = 'ws'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&settings).unwrap()["gmail"], true);

    // A server without the extension: no Gmail mode (and settings stored before 0.3 read as `gmail: false`).
    let mut h = Harness::start().await;
    h.imap = FakeImap::start().await;
    let u = h.imap_mailbox("plain", "info@example.org").await;
    let s: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT imap_settings FROM accounts WHERE alias = 'plain'", [], |r| r.get(0))?))
        .await
        .unwrap();
    let mut s: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(s["gmail"], false);
    s.as_object_mut().unwrap().remove("gmail");
    let old: dove::imap::account::ImapSettings = serde_json::from_value(s).unwrap();
    assert!(!old.gmail);
    let _ = u;
}

/// Gmail mode needs All Mail in IMAP; without it connect fails with a clear message and stores nothing.
#[tokio::test]
async fn connect_without_all_mail_is_refused() {
    let mut h = Harness::start().await;
    h.imap = FakeImap::start_with(gmail()).await;
    let user = "me@gmail.com";
    h.imap.add_user(user, PW);
    for (n, sp) in [("[Gmail]/Drafts", "\\Drafts"), ("[Gmail]/Sent Mail", "\\Sent"), ("[Gmail]/Trash", "\\Trash")] {
        h.imap.add_folder(user, n, Some(sp));
    }
    let e = h.admin(h.connect_imap_request("me", user, PW)).await.unwrap_err();
    assert!(e.contains("All Mail") && e.contains("Show in IMAP"), "{e}");
    let n: i64 =
        h.app().store.call(|c| Ok(c.query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))?)).await.unwrap();
    assert_eq!(n, 0);
    assert!(h.imap.smtp_commands().is_empty(), "IMAP failed first: SMTP was never tried");
}

// ------------------------------------------------------------------ index

/// One row per message from All Mail, Spam and Trash; labels from `X-GM-LABELS` (INBOX, user labels, IMPORTANT,
/// SENT) and flags. Label folders are never selected, have no checkpoints and no rows. Label and folder filters
/// and the digest's default inbox filter work as on other providers.
#[tokio::test]
async fn one_row_per_message_with_gmail_labels() {
    let fx = setup().await;
    let m1 = fx.add(&["INBOX", "Work"], "inbox and work", &[]);
    let m2 = fx.add(&["Work"], "archived work", &["\\Seen"]);
    let m3 = fx.add(&["INBOX", "[Gmail]/Important", "Privat/Kunden"], "important", &["\\Seen", "\\Flagged"]);
    let m4 = fx.add(&[SPAM], "spammy", &[]);
    let m5 = fx.add(&[TRASH], "trashed", &["\\Seen"]);
    let m6 = fx.add(&["[Gmail]/Sent Mail"], "sent by me", &["\\Seen"]);
    // The fake keeps a copy per label, like Gmail.
    assert_eq!(fx.h.imap.gm_folders(&fx.u.user, m1).len(), 3);
    fx.h.imap.clear_commands();
    fx.sync().await;

    let mut want = vec![
        (fx.id(ALL, m1).await, sorted(&["INBOX", "Work", "UNREAD"])),
        (fx.id(ALL, m2).await, sorted(&["Work"])),
        (fx.id(ALL, m3).await, sorted(&["INBOX", "IMPORTANT", "Privat/Kunden", "STARRED"])),
        (fx.id(SPAM, m4).await, sorted(&[SPAM, "SPAM", "UNREAD"])),
        (fx.id(TRASH, m5).await, sorted(&[TRASH, "TRASH"])),
        (fx.id(ALL, m6).await, sorted(&["SENT"])),
    ];
    want.sort();
    assert_eq!(fx.rows().await, want);

    let cmds = fx.h.imap.commands();
    let mut sel = selected(&cmds);
    sel.sort();
    sel.dedup();
    assert_eq!(sel, sorted(&[ALL, SPAM, TRASH]), "only All Mail, Spam and Trash are read");
    let meta: Vec<&String> = cmds.iter().filter(|c| c.starts_with("UID FETCH") && c.contains("FLAGS")).collect();
    assert!(!meta.is_empty() && meta.iter().all(|c| c.contains("X-GM-LABELS")), "{cmds:?}");
    let aid = fx.u.account_id.clone();
    let mut cp: Vec<String> =
        fx.h.app()
            .index
            .write(move |c| {
                let mut st = c.prepare("SELECT folder_id FROM imap_checkpoints WHERE account_id = ?1")?;
                Ok(st
                    .query_map([aid], |r| r.get::<_, i64>(0))?
                    .map(|r| r.map(|i| i.to_string()))
                    .collect::<Result<_, _>>()?)
            })
            .await
            .unwrap();
    cp.sort();
    let mut expect = vec![
        fx.folder_id(ALL).await.to_string(),
        fx.folder_id(SPAM).await.to_string(),
        fx.folder_id(TRASH).await.to_string(),
    ];
    expect.sort();
    assert_eq!(cp, expect, "checkpoints only for the scanned folders");

    assert_eq!(fx.subjects("INBOX").await, sorted(&["important", "inbox and work"]));
    assert_eq!(fx.subjects("Work").await, sorted(&["archived work", "inbox and work"]));
    assert_eq!(fx.subjects("SENT").await, sorted(&["sent by me"]));
    let since = dove::util::rfc3339_ms(dove::util::now_unix_ms() - 86_400_000);
    let d = fx.h.ok(&fx.token, "digest", json!({"since": since})).await;
    let mut subjects: Vec<String> =
        d["threads"].as_array().unwrap().iter().map(|t| t["subject"].as_str().unwrap().to_string()).collect();
    subjects.sort();
    assert_eq!(subjects, sorted(&["important", "inbox and work"]), "{d}");
    // get_message labels match the index.
    let id = fx.id(ALL, m1).await;
    let v = fx.h.ok(&fx.token, "get_message", json!({"account": "me", "message_id": id})).await;
    let mut labels: Vec<String> =
        v["message"]["labels"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect();
    labels.sort();
    assert_eq!(labels, sorted(&["INBOX", "Work", "UNREAD"]), "{v}");
    fx.h.imap.assert_only_allowlisted();
    assert!(fx.h.imap.flags(&fx.u.user, ALL, fx.h.imap.gm_uid(&fx.u.user, ALL, m1).unwrap()).unwrap().is_empty());
}

/// Label changes made on the server (archive, a new label) reach the index on the next sync: through CONDSTORE
/// (Gmail bumps MODSEQ on label changes) and, without CONDSTORE, through the flag refresh.
#[tokio::test]
async fn server_label_changes_reach_the_index() {
    for (opts, condstore) in [(gmail(), true), (Opts { condstore: false, ..gmail() }, false)] {
        let fx = setup_with(opts).await;
        let m1 = fx.add(&["INBOX"], "to archive", &[]);
        let m2 = fx.add(&["INBOX"], "to label", &["\\Seen"]);
        fx.sync().await;
        let (id1, id2) = (fx.id(ALL, m1).await, fx.id(ALL, m2).await);
        assert_eq!(fx.labels_of(&id1).await, sorted(&["INBOX", "UNREAD"]));
        fx.h.imap.gm_relabel(&fx.u.user, m1, &[], &["INBOX"]);
        fx.h.imap.gm_relabel(&fx.u.user, m2, &["Privat/Kunden"], &[]);
        fx.h.imap.clear_commands();
        fx.sync().await;
        assert_eq!(fx.labels_of(&id1).await, sorted(&["UNREAD"]), "archived: INBOX gone, same id");
        assert_eq!(fx.labels_of(&id2).await, sorted(&["INBOX", "Privat/Kunden"]));
        assert_eq!(fx.subjects("INBOX").await, sorted(&["to label"]));
        let cmds = fx.h.imap.commands();
        assert_eq!(cmds.iter().any(|c| c.contains("CHANGEDSINCE") && c.contains("X-GM-LABELS")), condstore, "{cmds:?}");
        assert_eq!(fx.rows().await.len(), 2);
    }
}

/// IDLE and the quick freshness pass watch All Mail in Gmail mode (new inbox mail lands there too).
#[tokio::test]
async fn idle_and_quick_pass_use_all_mail() {
    let fx = setup().await;
    fx.add(&["INBOX"], "first", &[]);
    fx.sync().await;
    fx.h.imap.clear_commands();
    let m = fx.add(&["INBOX"], "fresh", &[]);
    assert_eq!(quick_inbox(fx.h.app(), &fx.u.account_id).await.unwrap(), 1);
    assert_eq!(fx.labels_of(&fx.id(ALL, m).await).await, sorted(&["INBOX", "UNREAD"]));
    let cmds = fx.h.imap.commands();
    assert_eq!(selected(&cmds).into_iter().collect::<std::collections::BTreeSet<_>>(), [ALL.to_string()].into());

    fx.h.imap.clear_commands();
    let task = dove::index::imap_idle::start(fx.h.app().clone());
    let end = Instant::now() + Duration::from_secs(5);
    while !(fx.h.app().index.idle.is_healthy(&fx.u.account_id) && fx.h.imap.idling() == 1) {
        assert!(Instant::now() < end, "no IDLE connection");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    task.abort();
    let cmds = fx.h.imap.commands();
    let idle = cmds.iter().position(|c| c == "IDLE").expect("IDLE sent");
    assert_eq!(selected(&cmds[..idle]).last().map(String::as_str), Some(ALL), "{cmds:?}");
}

// ------------------------------------------------------------------ organize

/// Folders of a Gmail message, sorted wire names.
fn places(fx: &Fx, gm: u64) -> Vec<String> {
    let mut v = fx.h.imap.gm_folders(&fx.u.user, gm);
    v.sort();
    v
}

fn result(v: &Value) -> &Value {
    assert_eq!(v["results"].as_array().unwrap().len(), 1, "{v}");
    &v["results"][0]
}

/// Flags, labels, archive, inbox and label moves change `X-GM-LABELS` on the All Mail message (its id stays); Trash
/// and Spam are reached and left only with `UID MOVE`. Nothing is ever flagged `\Deleted` or expunged, no COPY.
#[tokio::test]
async fn organize_uses_labels_and_move_only() {
    let fx = setup().await;
    let m1 = fx.add(&["INBOX", "Work"], "one", &[]);
    let m2 = fx.add(&["INBOX"], "two", &[]);
    let m3 = fx.add(&["INBOX"], "three", &[]);
    let m4 = fx.add(&["Work"], "four", &["\\Seen"]);
    fx.sync().await;
    let (id1, id2, id3, id4) = (fx.id(ALL, m1).await, fx.id(ALL, m2).await, fx.id(ALL, m3).await, fx.id(ALL, m4).await);
    fx.h.imap.clear_commands();
    let call = |tool: &'static str, args: Value| {
        let fx = &fx;
        async move { fx.h.ok(&fx.token, tool, args).await }
    };

    let v = call(
        "update_messages",
        json!({"account": "me", "ids": [id1], "add_flags": ["STARRED"], "remove_flags": ["UNREAD"],
               "add_labels": ["privat/kunden"], "remove_labels": ["Work"]}),
    )
    .await;
    let r = result(&v);
    assert_eq!((r["ok"].as_bool(), r["new_id"].as_str()), (Some(true), Some(id1.as_str())), "{v}");
    let mut labels: Vec<String> = serde_json::from_value(r["labels"].clone()).unwrap();
    labels.sort();
    assert_eq!(labels, sorted(&["INBOX", "Privat/Kunden", "STARRED"]));
    assert_eq!(places(&fx, m1), sorted(&[ALL, "INBOX", "Privat/Kunden"]));
    let mut flags = fx.h.imap.gm_flags(&fx.u.user, m1);
    flags.sort();
    assert_eq!(flags, sorted(&["\\Flagged", "\\Seen"]));

    // Archive, label move, inbox: label changes only, ids unchanged.
    let v = call("move_messages", json!({"account": "me", "ids": [id2], "to": "archive"})).await;
    assert_eq!(result(&v)["new_id"], id2.as_str(), "{v}");
    assert_eq!(places(&fx, m2), sorted(&[ALL]));
    let v = call("move_messages", json!({"account": "me", "ids": [id3], "to": "Work"})).await;
    assert_eq!(result(&v)["new_id"], id3.as_str(), "{v}");
    assert_eq!(places(&fx, m3), sorted(&[ALL, "Work"]));
    let v = call("move_messages", json!({"account": "me", "ids": [id4], "to": "inbox"})).await;
    assert_eq!(result(&v)["new_id"], id4.as_str(), "{v}");
    assert_eq!(places(&fx, m4), sorted(&[ALL, "INBOX", "Work"]));
    let stores: Vec<String> = fx.h.imap.commands().into_iter().filter(|c| c.starts_with("UID STORE")).collect();
    assert!(stores.iter().any(|c| c.ends_with("-X-GM-LABELS (\\Inbox)")), "{stores:?}");
    assert!(stores.iter().any(|c| c.ends_with("+X-GM-LABELS (\\Inbox)")), "{stores:?}");
    assert!(stores.iter().any(|c| c.ends_with("+X-GM-LABELS (\"Work\")")), "{stores:?}");
    assert!(!fx.h.imap.commands().iter().any(|c| verb_of(c) == "UID MOVE"));

    // Trash: UID MOVE, a new Trash id; out again to the inbox: UID MOVE to INBOX (All Mail follows on Gmail).
    let v = call("move_messages", json!({"account": "me", "ids": [id2], "to": "trash"})).await;
    let trash_id = result(&v)["new_id"].as_str().unwrap().to_string();
    assert_eq!(trash_id, fx.id(TRASH, m2).await);
    assert_eq!(places(&fx, m2), sorted(&[TRASH]));
    // In Trash flags still change, labels do not (move it out first).
    let v = call("update_messages", json!({"account": "me", "ids": [trash_id], "add_labels": ["Work"]})).await;
    assert_eq!(result(&v)["error"]["code"], "invalid_argument", "{v}");
    let v = call("update_messages", json!({"account": "me", "ids": [trash_id], "add_flags": ["STARRED"]})).await;
    assert_eq!(result(&v)["labels"], json!([TRASH, "UNREAD", "STARRED", "TRASH"]), "{v}");
    assert_eq!(places(&fx, m2), sorted(&[TRASH]));
    let v = call("move_messages", json!({"account": "me", "ids": [trash_id], "to": "inbox"})).await;
    assert_eq!(result(&v)["new_id"].as_str().unwrap(), fx.id("INBOX", m2).await, "{v}");
    assert_eq!(places(&fx, m2), sorted(&[ALL, "INBOX"]));
    // Spam and back to the archive (All Mail).
    let v = call("move_messages", json!({"account": "me", "ids": [id3], "to": "spam"})).await;
    let spam_id = result(&v)["new_id"].as_str().unwrap().to_string();
    assert_eq!(places(&fx, m3), sorted(&[SPAM]));
    let v = call("move_messages", json!({"account": "me", "ids": [spam_id], "to": "archive"})).await;
    assert_eq!(result(&v)["new_id"].as_str().unwrap(), fx.id(ALL, m3).await, "{v}");
    assert_eq!(places(&fx, m3), sorted(&[ALL]));
    let moves: Vec<String> = fx.h.imap.commands().into_iter().filter(|c| verb_of(c) == "UID MOVE").collect();
    assert_eq!(moves.len(), 4, "{moves:?}");

    assert_eq!(fx.h.imap.assert_gmail_deletes_only_in_drafts(), 0);
    fx.h.imap.assert_only_allowlisted();
    // The index follows: still one row per message.
    fx.sync().await;
    let rows = fx.rows().await;
    assert_eq!(rows.len(), 4, "{rows:?}");
    assert_eq!(fx.subjects("INBOX").await, sorted(&["four", "one", "two"]));
}

/// Without MOVE, Trash and Spam are refused: never the COPY + `\Deleted` + EXPUNGE fallback. Label changes still work.
#[tokio::test]
async fn trash_without_move_is_refused() {
    let fx = setup_with(Opts { move_cap: false, ..gmail() }).await;
    let m = fx.add(&["INBOX"], "keep me", &[]);
    fx.sync().await;
    let id = fx.id(ALL, m).await;
    fx.h.imap.clear_commands();
    let v = fx.h.ok(&fx.token, "move_messages", json!({"account": "me", "ids": [id], "to": "trash"})).await;
    let r = result(&v);
    assert_eq!(r["ok"], false, "{v}");
    assert_eq!(r["error"]["code"], "upstream_error", "{v}");
    assert_eq!(places(&fx, m), sorted(&[ALL, "INBOX"]));
    let cmds = fx.h.imap.commands();
    assert!(
        !cmds.iter().any(|c| matches!(verb_of(c).as_str(), "UID STORE" | "UID COPY" | "UID MOVE" | "UID EXPUNGE")),
        "{cmds:?}"
    );
    let v = fx.h.ok(&fx.token, "move_messages", json!({"account": "me", "ids": [id], "to": "archive"})).await;
    assert_eq!(result(&v)["ok"], true, "{v}");
    assert_eq!(places(&fx, m), sorted(&[ALL]));
    assert_eq!(fx.h.imap.assert_gmail_deletes_only_in_drafts(), 0);
}

/// Unknown labels, system folders and ids of label folders are refused before any IMAP command: Dove creates no
/// labels and reaches system labels only through flags and move targets.
#[tokio::test]
async fn unknown_and_system_labels_are_refused_before_any_command() {
    let fx = setup().await;
    let m = fx.add(&["INBOX"], "x", &[]);
    fx.sync().await;
    let id = fx.id(ALL, m).await;
    let inbox_copy = fx.id("INBOX", m).await;
    fx.h.imap.clear_commands();
    for (tool, args, needle) in [
        ("update_messages", json!({"account": "me", "ids": [id], "add_labels": ["Nope"]}), "unknown label"),
        ("update_messages", json!({"account": "me", "ids": [id], "remove_labels": ["[Gmail]/Important"]}), "system"),
        ("update_messages", json!({"account": "me", "ids": [id], "add_labels": ["INBOX"]}), "system"),
        ("update_messages", json!({"account": "me", "ids": [id], "add_labels": ["\\Trash"]}), "unknown label"),
        ("move_messages", json!({"account": "me", "ids": [id], "to": "[Gmail]/Sent Mail"}), "system"),
        ("move_messages", json!({"account": "me", "ids": [id], "to": "Nope"}), "unknown label"),
    ] {
        let (is_error, v) = fx.h.call(&fx.token, tool, args).await;
        assert!(is_error, "{v}");
        assert_eq!(v["error"]["code"], "invalid_argument", "{v}");
        assert!(v.to_string().contains(needle), "{needle}: {v}");
    }
    // A label folder's copy is no organize source.
    let v = fx.h.ok(&fx.token, "move_messages", json!({"account": "me", "ids": [inbox_copy], "to": "archive"})).await;
    assert_eq!(result(&v)["error"]["code"], "invalid_argument", "{v}");
    assert!(fx.h.imap.commands().is_empty(), "{:?}", fx.h.imap.commands());
    assert_eq!(places(&fx, m), sorted(&[ALL, "INBOX"]));
}

/// Drafts and send work as on other IMAP servers: APPEND to Gmail's Drafts, own-draft deletion there only, no Sent
/// copy from Dove (Gmail files it); the index then holds the sent message once.
#[tokio::test]
async fn drafts_and_send_on_gmail() {
    let fx = setup_cfg(gmail(), |c| c.allow_send = true).await;
    fx.sync().await;
    fx.h.imap.clear_commands();
    let c = fx
        .h
        .ok(
            &fx.token,
            "create_draft",
            json!({ "account": "me", "request_key": uuid::Uuid::new_v4().to_string(), "to": ["Ann <ann@example.net>"],
                    "subject": "Angebot", "body_text": "Hallo Ann" }),
        )
        .await;
    let (d, rev) = (c["draft_id"].clone(), c["revision"].clone());
    fx.h.ok(&fx.token, "send_draft", json!({ "account": "me", "draft_id": d, "expected_revision": rev })).await;
    assert_eq!(fx.h.imap.sent_mails().len(), 1);
    let cmds = fx.h.imap.commands();
    let appends: Vec<&String> = cmds.iter().filter(|c| verb_of(c) == "APPEND").collect();
    assert_eq!(appends.len(), 1, "{cmds:?}");
    assert!(appends[0].starts_with("APPEND \"[Gmail]/Drafts\""), "{cmds:?}");
    assert!(fx.h.imap.assert_gmail_deletes_only_in_drafts() >= 2, "{cmds:?}");
    fx.h.imap.assert_only_allowlisted();
    fx.sync().await;
    assert_eq!(fx.subjects("SENT").await, vec!["Angebot".to_string()]);
    assert_eq!(fx.rows().await.len(), 1, "the draft is gone, the sent message indexed once");
}

/// Source scan: the Gmail-mode organize code can neither delete nor copy (no `\Deleted`, no expunge, no COPY, no
/// own-draft deletion), the session refuses the COPY fallback and the confirmed-copy expunge in Gmail mode, and the
/// label STORE is built only in `ops.rs` and sent only from `store_gm_labels`.
#[test]
fn gmail_mode_code_cannot_delete() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let organize = std::fs::read_to_string(root.join("src/tools/organize.rs")).unwrap();
    let start = organize.find("------ Gmail over IMAP (PLAN A57)").unwrap();
    let end = organize[start..].find("#[cfg(test)]").map(|i| i + start).unwrap();
    let gmail = &organize[start..end];
    for banned in ["Deleted", "xpunge", "delete_own", "UidCopy", "Copied", "copy"] {
        assert!(!gmail.contains(banned), "Gmail organize code mentions {banned}");
    }
    assert!(gmail.contains("move_group(") && gmail.contains("store_gm_labels("));
    let session = std::fs::read_to_string(root.join("src/imap/session.rs")).unwrap();
    let fn_body = |name: &str| {
        let s = session.find(name).unwrap_or_else(|| panic!("{name}"));
        let e =
            session[s + 1..].find("\n    pub async fn ").or_else(|| session[s + 1..].find("\n    async fn ")).unwrap();
        session[s..s + 1 + e].to_string()
    };
    let mv = fn_body("pub async fn move_uids(");
    let guard = mv.find("if self.gmail && !self.has_cap(\"MOVE\")").expect("MOVE-only guard in move_uids");
    assert!(guard < mv.find("UidCopy").unwrap(), "the guard comes before any COPY");
    assert!(fn_body("async fn expunge_copied(").contains("if self.gmail {"), "expunge_copied refuses Gmail mode");
    let mut builders = Vec::new();
    for f in ["src/imap/ops.rs", "src/imap/session.rs", "src/tools/organize.rs", "src/index/imap_sync.rs"] {
        let text = std::fs::read_to_string(root.join(f)).unwrap();
        let n = text.matches("ImapOp::UidStoreGmLabels {").count();
        if n > 0 {
            builders.push((f, n));
        }
    }
    assert_eq!(builders.iter().find(|(f, _)| *f == "src/imap/session.rs").map(|b| b.1), Some(2), "{builders:?}");
    assert!(builders.iter().all(|(f, _)| matches!(*f, "src/imap/ops.rs" | "src/imap/session.rs")), "{builders:?}");
    let store = fn_body("pub async fn store_gm_labels(");
    assert_eq!(store.matches("ImapOp::UidStoreGmLabels {").count(), 2);
}
