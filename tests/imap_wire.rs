//! IMAP/SMTP wire layer against the fake server: login, capability checks, read-only fetches, APPEND, the pool's
//! handling of broken sessions, SMTP outcome classification, folder name decoding and message ids.

mod support;

use std::time::{Duration, Instant};

use dove::imap::{
    AppendFlag, AppendTarget, Credentials, ImapConnector, ImapError, ImapMsgId, ImapPool, ImapSession, ServerEndpoint,
    Special, TlsMode, smtp, utf7,
};
use support::fake_imap::{FakeImap, Fault, Opts, SmtpFault};
use zeroize::Zeroizing;

const USER: &str = "owner@example.com";
const PASS: &str = "p\"a\\\u{df} w";
const T: Duration = Duration::from_secs(3);

fn ep(addr: std::net::SocketAddr) -> ServerEndpoint {
    ServerEndpoint { host: addr.ip().to_string(), port: addr.port(), tls: TlsMode::Implicit }
}

fn creds(password: &str) -> Credentials {
    Credentials { username: USER.into(), password: Zeroizing::new(password.into()) }
}

async fn session(f: &FakeImap) -> ImapSession {
    ImapSession::connect(&ImapConnector::plaintext_for_tests(), &ep(f.imap_addr), &creds(PASS), T).await.unwrap()
}

const MSG: &[u8] = b"From: Daniel <daniel@example.org>\r\nTo: owner@example.com\r\nSubject: Hallo\r\n\r\nBody text\r\n";

#[tokio::test]
async fn login_with_special_password() {
    for auth_plain in [false, true] {
        let f = FakeImap::start_with(Opts { auth_plain, ..Default::default() }).await;
        f.add_user(USER, PASS);
        let mut s = session(&f).await;
        s.noop().await.unwrap();
        let cmds = f.commands();
        let expected = if auth_plain { "AUTHENTICATE PLAIN ***" } else { "LOGIN owner@example.com ***" };
        assert!(cmds.iter().any(|c| c == expected), "{auth_plain}: {cmds:?}");
        // A wrong password is an authentication failure, not a network or protocol error.
        let err = ImapSession::connect(&ImapConnector::plaintext_for_tests(), &ep(f.imap_addr), &creds("p\"a\\"), T)
            .await
            .unwrap_err();
        assert_eq!(err, ImapError::Auth);
        f.assert_only_allowlisted();
    }
}

#[tokio::test]
async fn rejects_missing_uidplus() {
    let f = FakeImap::start_with(Opts { uidplus: false, ..Default::default() }).await;
    f.add_user(USER, PASS);
    let err = ImapSession::connect(&ImapConnector::plaintext_for_tests(), &ep(f.imap_addr), &creds(PASS), T)
        .await
        .unwrap_err();
    assert_eq!(err, ImapError::Capability("UIDPLUS"));
}

#[tokio::test]
async fn fetch_never_sets_seen() {
    let f = FakeImap::start().await;
    f.add_user(USER, PASS);
    let uid = f.add_message(USER, "INBOX", MSG, &["\\Flagged"]);
    let mut s = session(&f).await;
    // Read-write SELECT: a non-PEEK fetch would set \Seen here on a real server.
    let st = s.select("INBOX", false).await.unwrap();
    assert_eq!(st.exists, 1);
    assert_eq!(s.uid_search_all().await.unwrap(), vec![uid]);
    let meta = s.fetch_meta(&[uid]).await.unwrap();
    assert_eq!(meta[0].size, MSG.len() as u64);
    assert_eq!(meta[0].flags, vec!["\\Flagged".to_string()]);
    assert_eq!(meta[0].internal_date_s, 1_767_225_600);
    assert_eq!(s.fetch_raw(uid, 1 << 20).await.unwrap().as_deref(), Some(MSG));
    // Over the limit: only the size is fetched.
    let before = f.commands().len();
    assert_eq!(s.fetch_raw(uid, 10).await.unwrap(), None);
    assert!(f.commands()[before..].iter().all(|c| !c.contains("BODY")), "{:?}", f.commands());
    assert_eq!(s.fetch_raw(uid + 5, 1 << 20).await.unwrap_err(), ImapError::Missing);
    assert_eq!(f.flags(USER, "INBOX", uid).unwrap(), vec!["\\Flagged".to_string()]);
    let fetches: Vec<String> = f.commands().into_iter().filter(|c| c.starts_with("UID FETCH")).collect();
    assert!(fetches.iter().any(|c| c.contains("BODY.PEEK[]")), "{fetches:?}");
    f.assert_only_allowlisted();
}

#[tokio::test]
async fn append_returns_appenduid() {
    let f = FakeImap::start().await;
    f.add_user(USER, PASS);
    f.add_folder(USER, "Drafts", Some("\\Drafts"));
    f.add_message(USER, "Drafts", MSG, &[]);
    let mut s = session(&f).await;
    // Without a configured target nothing can be appended.
    assert_eq!(s.append(AppendTarget::Drafts, &[], MSG).await.unwrap_err(), ImapError::Missing);
    s.set_append_targets(Some("Drafts".into()), None);
    let a = s.append(AppendTarget::Drafts, &[AppendFlag::Draft, AppendFlag::Seen], MSG).await.unwrap();
    assert_eq!(a.uidvalidity, f.uidvalidity(USER, "Drafts"));
    assert_eq!(a.uid, 2);
    assert_eq!(f.message_raw(USER, "Drafts", 2).as_deref(), Some(MSG));
    let mut flags = f.flags(USER, "Drafts", 2).unwrap();
    flags.sort();
    assert_eq!(flags, vec!["\\Draft".to_string(), "\\Seen".to_string()]);
    assert_eq!(s.append(AppendTarget::Sent, &[], MSG).await.unwrap_err(), ImapError::Missing);
    // A connection lost after the message literal was sent is an unknown outcome, never a clean failure.
    f.fail_next("APPEND", Fault::DropAfterApply);
    assert_eq!(s.append(AppendTarget::Drafts, &[], MSG).await.unwrap_err(), ImapError::OutcomeUnknown);
    f.assert_only_allowlisted();
}

#[tokio::test]
async fn pool_discards_broken_session() {
    let f = FakeImap::start().await;
    f.add_user(USER, PASS);
    let uid = f.add_message(USER, "INBOX", MSG, &[]);
    let pool = ImapPool::new(ImapConnector::plaintext_for_tests(), Duration::from_millis(400));
    assert_eq!(pool_fetch(&pool, &f, uid).await.unwrap().as_deref(), Some(MSG));
    assert_eq!(pool_fetch(&pool, &f, uid).await.unwrap().as_deref(), Some(MSG));
    assert_eq!(f.connections(), 1, "an idle session is reused");
    // The body literal stalls half-way: the call times out with unread bytes on the stream.
    f.fail_next_containing("UID FETCH", "BODY.PEEK", Fault::StallMidResponse(Duration::from_millis(1500)));
    assert_eq!(pool_fetch(&pool, &f, uid).await.unwrap_err(), ImapError::Network);
    // The next call must not read the rest of that literal: it gets a fresh connection and the right bytes.
    assert_eq!(pool_fetch(&pool, &f, uid).await.unwrap().as_deref(), Some(MSG));
    assert_eq!(f.connections(), 2);
    f.fail_next_containing("UID FETCH", "BODY.PEEK", Fault::DropMidResponse);
    assert_eq!(pool_fetch(&pool, &f, uid).await.unwrap_err(), ImapError::Network);
    assert_eq!(pool_fetch(&pool, &f, uid).await.unwrap().as_deref(), Some(MSG));
    assert_eq!(f.connections(), 3);
}

async fn pool_fetch(pool: &ImapPool, f: &FakeImap, uid: u32) -> Result<Option<Vec<u8>>, ImapError> {
    pool.with_session("acct", &ep(f.imap_addr), &creds(PASS), |s| {
        Box::pin(async move {
            s.select("INBOX", true).await?;
            s.fetch_raw(uid, 1 << 20).await
        })
    })
    .await
}

async fn submit(f: &FakeImap, password: &str) -> Result<(), smtp::SmtpError> {
    let deadline = Instant::now() + T;
    let rcpts = vec!["a@example.org".to_string(), "hidden@example.org".to_string()];
    smtp::submit(&ImapConnector::plaintext_for_tests(), &ep(f.smtp_addr), &creds(password), USER, &rcpts, MSG, deadline)
        .await
}

#[tokio::test]
async fn smtp_unknown_after_terminator() {
    let f = FakeImap::start().await;
    f.add_user(USER, PASS);
    submit(&f, PASS).await.unwrap();
    let sent = f.sent_mails();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].from, USER);
    assert_eq!(sent[0].rcpts, vec!["a@example.org", "hidden@example.org"]);
    assert_eq!(sent[0].data, MSG);
    f.smtp_fail_next("DATA", SmtpFault::DropAfterTerminator);
    let e = submit(&f, PASS).await.unwrap_err();
    assert!(e.data_terminator_sent);
    assert_eq!(e.kind, ImapError::OutcomeUnknown);
    assert_eq!(f.sent_mails().len(), 2, "the server did receive it");
    f.assert_only_allowlisted();
}

#[tokio::test]
async fn smtp_definitive_before_data() {
    let f = FakeImap::start().await;
    f.add_user(USER, PASS);
    f.smtp_fail_next("RCPT", SmtpFault::Reply(550));
    let e = submit(&f, PASS).await.unwrap_err();
    assert!(!e.data_terminator_sent);
    assert_eq!(e.code, Some(550));
    assert!(f.sent_mails().is_empty());
    // A refusal after the terminator is definitive too, but the terminator was sent.
    f.smtp_fail_next("DATA", SmtpFault::Reply(554));
    let e = submit(&f, PASS).await.unwrap_err();
    assert!(!e.data_terminator_sent, "554 to DATA itself comes before any message byte");
    let e = submit(&f, "wrong").await.unwrap_err();
    assert_eq!(e.kind, ImapError::Auth);
    assert!(!e.data_terminator_sent);
    assert!(f.sent_mails().is_empty());
    // The password never appears in the SMTP command log.
    assert!(f.smtp_commands().iter().all(|c| !c.contains(PASS)));
    f.assert_only_allowlisted();
}

#[tokio::test]
async fn utf7_folder_names() {
    assert_eq!(utf7::decode("Entw&APw-rfe").as_deref(), Some("Entwürfe"));
    assert_eq!(utf7::encode("Entwürfe"), "Entw&APw-rfe");
    let f = FakeImap::start().await;
    f.add_user(USER, PASS);
    f.add_folder(USER, "Entwürfe", Some("\\Drafts"));
    f.add_folder(USER, "INBOX/Rechnungen", None);
    let mut s = session(&f).await;
    let folders = s.list_folders().await.unwrap();
    let d = folders.iter().find(|x| x.special == Some(Special::Drafts)).expect("drafts listed");
    assert_eq!(d.name_utf8, "Entwürfe");
    assert_eq!(d.raw_name, "Entw&APw-rfe");
    assert_eq!(d.delimiter, Some('/'));
    assert!(folders.iter().any(|x| x.name_utf8 == "INBOX/Rechnungen" && x.special.is_none()));
    // The wire name selects the folder.
    s.select(&d.raw_name, true).await.unwrap();
    assert_eq!(s.select("Entwürfe", true).await.unwrap_err(), ImapError::Missing);
}

#[test]
fn ids_roundtrip_and_valid() {
    for id in [
        ImapMsgId { folder_id: 1, uidvalidity: 1, uid: 1 },
        ImapMsgId { folder_id: 3, uidvalidity: 1_700_000_000, uid: 4211 },
        ImapMsgId { folder_id: i64::MAX, uidvalidity: u32::MAX, uid: u32::MAX },
    ] {
        let s = id.encode();
        assert!(dove::gmail::gateway::valid_id(&s), "{s}");
        assert_eq!(ImapMsgId::parse(&s), Some(id));
    }
    // A Gmail id never parses as an IMAP id.
    assert_eq!(ImapMsgId::parse("18c2f3a4b5d6e7f8"), None);
}

#[tokio::test]
async fn changed_since_reports_flags_and_vanished() {
    let f = FakeImap::start().await;
    f.add_user(USER, PASS);
    let a = f.add_message(USER, "INBOX", MSG, &[]);
    let b = f.add_message(USER, "INBOX", MSG, &[]);
    let mut s = session(&f).await;
    assert!(s.enable_qresync().await.unwrap());
    let st = s.select("INBOX", true).await.unwrap();
    let base = st.highestmodseq.expect("CONDSTORE");
    f.set_flags(USER, "INBOX", a, &["\\Seen"], &[]);
    f.expunge_external(USER, "INBOX", b);
    s.select("INBOX", true).await.unwrap();
    let ch = s.changed_since(base).await.unwrap();
    assert_eq!(ch.changed.len(), 1);
    assert_eq!(ch.changed[0].uid, a);
    assert!(ch.changed[0].flags.contains(&"\\Seen".to_string()));
    assert_eq!(ch.vanished, Some(vec![b]));
    assert_eq!(s.uid_search_since_uid(b + 10).await.unwrap(), Vec::<u32>::new());
}
