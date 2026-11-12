//! IMAP IDLE push and search freshness (`index::imap_idle`, owner request 2026-11-12): new INBOX mail is indexed within
//! seconds without waiting for the poll; the IDLE connection reconnects after drops, stops with the account, marks
//! reauth once on a rejected login, and falls back to polling on servers without IDLE; searches run one bounded INBOX
//! check when IDLE is not healthy. Runs against the fake IMAP server with the real scheduler and IDLE supervisor.

mod support;

use std::time::{Duration, Instant};

use dove::admin::AdminRequest;
use dove::index::imap_sync::sync_steps;
use serde_json::{Value, json};
use support::fake_imap::{FakeImap, Fault, Opts};
use support::harness::{FakeImapUser, Harness, g};

fn simple(subject: &str) -> Vec<u8> {
    format!(
        "From: Ann <ann@example.org>\r\nTo: info@example.org\r\nSubject: {subject}\r\nMessage-ID: <{}@example.org>\r\n\
         Date: Thu, 01 Jan 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Hello there.\r\n",
        subject.replace(' ', "-")
    )
    .into_bytes()
}

fn col(v: &Value, name: &str) -> Vec<String> {
    let i = v["columns"].as_array().unwrap().iter().position(|c| c == name).unwrap_or_else(|| panic!("{name}: {v}"));
    v["rows"].as_array().unwrap().iter().map(|r| r[i].as_str().unwrap_or_default().to_string()).collect()
}

struct Fx {
    h: Harness,
    u: FakeImapUser,
    token: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Fx {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// One IMAP mailbox with one INBOX message, indexed (sync run to idle). No scheduler or IDLE supervisor yet.
async fn setup(opts: Opts, customize: impl FnOnce(&mut dove::config::Config)) -> Fx {
    let mut h = Harness::start_with(customize).await;
    h.imap = FakeImap::start_with(opts).await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read")]).await;
    h.imap.add_message(&u.user, "INBOX", &simple("first"), &[]);
    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    let r = sync_steps(h.app(), &u.account_id, usize::MAX).await.unwrap();
    assert_eq!((r.stage.as_str(), r.error.as_deref()), ("ready", None), "{r:?}");
    Fx { h, u, token, tasks: Vec::new() }
}

/// The poll never runs during a test (an hour), so only IDLE or the freshness check can index new mail.
fn no_poll(c: &mut dove::config::Config) {
    c.index.poll_interval_secs = 3600;
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

impl Fx {
    fn start_scheduler(&mut self) {
        self.tasks.push(dove::index::start(self.h.app().clone()));
    }

    fn start_idle(&mut self) {
        self.tasks.push(dove::index::imap_idle::start(self.h.app().clone()));
    }

    fn healthy(&self) -> bool {
        self.h.app().index.idle.is_healthy(&self.u.account_id)
    }

    async fn wait_idling(&self) {
        wait_for("a healthy IDLE connection", Duration::from_secs(5), || async {
            self.healthy() && self.h.imap.idling() == 1
        })
        .await;
    }

    fn add(&self, subject: &str) -> u32 {
        self.h.imap.add_message(&self.u.user, "INBOX", &simple(subject), &[])
    }

    async fn indexed(&self) -> i64 {
        self.h.app().index.write(|c| Ok(c.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?)).await.unwrap()
    }

    async fn subjects(&self) -> (Vec<String>, Value) {
        let v = self.h.ok(&self.token, "search_messages", json!({"select": ["subject", "message_id"]})).await;
        (col(&v, "subject"), v)
    }

    async fn last_success(&self) -> Option<i64> {
        let aid = self.u.account_id.clone();
        self.h
            .app()
            .index
            .write(move |c| {
                Ok(c.query_row("SELECT last_success_at FROM sync_state WHERE account_id = ?1", [aid], |r| r.get(0))?)
            })
            .await
            .unwrap()
    }

    /// Pretends the last full sync was a minute ago (instead of waiting for the freshness threshold).
    async fn age_last_sync(&self) -> i64 {
        let aid = self.u.account_id.clone();
        let t = dove::util::now_unix() - 60;
        self.h
            .app()
            .index
            .write(move |c| {
                c.execute(
                    "UPDATE sync_state SET last_success_at = ?1 WHERE account_id = ?2",
                    rusqlite::params![t, aid],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        t
    }

    async fn status(&self) -> String {
        let aid = self.u.account_id.clone();
        self.h
            .app()
            .store
            .call(move |c| Ok(c.query_row("SELECT status FROM accounts WHERE id = ?1", [aid], |r| r.get(0))?))
            .await
            .unwrap()
    }

    fn commands_since(&self, mark: usize) -> Vec<String> {
        self.h.imap.commands()[mark..].to_vec()
    }
}

/// New INBOX mail is searchable within a few seconds through IDLE: the push wakes the index sync, the poll (an hour)
/// never runs, and the freshness check stays out of it because IDLE is healthy.
#[tokio::test]
async fn new_mail_is_searchable_within_seconds_via_idle() {
    let mut fx = setup(Opts::default(), no_poll).await;
    fx.start_scheduler();
    fx.start_idle();
    fx.wait_idling().await;
    // Let the catch-up pass that follows every (re)connect finish, so it cannot pick up the new message.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mark = fx.h.imap.commands().len();
    fx.add("pushed arrival");
    let t0 = Instant::now();
    wait_for("the pushed message in search results", Duration::from_secs(5), || async {
        fx.subjects().await.0.contains(&"pushed arrival".to_string())
    })
    .await;
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    // The searches never ran the freshness check (no EXAMINE on a pooled session besides the woken sync's scan).
    assert!(fx.healthy());
    let cmds = fx.commands_since(mark);
    assert!(cmds.iter().any(|c| c.starts_with("UID FETCH") && c.contains("BODY.PEEK[]")), "{cmds:?}");
    fx.h.imap.assert_only_allowlisted();
}

/// A push that arrives while a sync pass is running (and has already scanned INBOX) is not lost: the scheduler keeps
/// the wake and runs another pass right after, instead of leaving the message to the next poll.
#[tokio::test]
async fn push_during_a_running_pass_is_not_lost() {
    let mut fx = setup(Opts::default(), no_poll).await;
    fx.start_scheduler();
    fx.start_idle();
    fx.wait_idling().await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let before = fx.indexed().await;
    // The next pass stalls on a folder after INBOX; the second message arrives while it waits.
    fx.h.imap.fail_next_containing("EXAMINE", "Trash", Fault::Delay(Duration::from_secs(2)));
    let mark = fx.h.imap.commands().len();
    fx.add("during pass one");
    wait_for("the pass to reach Trash", Duration::from_secs(5), || async {
        fx.commands_since(mark).iter().any(|c| c.starts_with("EXAMINE") && c.contains("Trash"))
    })
    .await;
    fx.add("during pass two");
    wait_for("both pushed messages in the index", Duration::from_secs(8), || async {
        fx.indexed().await == before + 2
    })
    .await;
}

/// A dropped IDLE connection (no BYE) comes back after a short backoff, and pushes work again afterwards.
#[tokio::test]
async fn idle_reconnects_after_the_server_drops_the_connection() {
    let mut fx = setup(Opts::default(), no_poll).await;
    fx.start_scheduler();
    fx.start_idle();
    fx.wait_idling().await;
    let conns = fx.h.imap.connections();
    fx.h.imap.kick_idle();
    wait_for("IDLE to notice the drop", Duration::from_secs(3), || async { !fx.healthy() }).await;
    wait_for("a new IDLE connection", Duration::from_secs(5), || async {
        fx.healthy() && fx.h.imap.idling() == 1 && fx.h.imap.connections() > conns
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let before = fx.indexed().await;
    fx.add("after reconnect");
    wait_for("the pushed message in the index", Duration::from_secs(5), || async { fx.indexed().await == before + 1 })
        .await;
    fx.h.imap.assert_only_allowlisted();
}

/// The server ends IDLE with BYE after its own timeout: Dove reconnects. A short renewal interval re-issues IDLE
/// (DONE, then IDLE again) on the same connection.
#[tokio::test]
async fn idle_is_renewed_and_survives_a_server_timeout() {
    let mut fx = setup(Opts::default(), |c| {
        no_poll(c);
        c.index.idle_renew_secs = 1;
    })
    .await;
    fx.start_idle();
    fx.wait_idling().await;
    let (mark, conns) = (fx.h.imap.commands().len(), fx.h.imap.connections());
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let cmds = fx.commands_since(mark);
    let idles = cmds.iter().filter(|c| *c == "IDLE").count();
    let dones = cmds.iter().filter(|c| *c == "DONE").count();
    assert!(idles >= 2 && dones >= 2, "{cmds:?}");
    assert_eq!(fx.h.imap.connections(), conns, "renewal reuses the connection");

    let mut fx = setup(Opts { idle_timeout: Some(Duration::from_millis(700)), ..Default::default() }, no_poll).await;
    fx.start_idle();
    fx.wait_idling().await;
    let conns = fx.h.imap.connections();
    wait_for("a reconnect after the server's BYE", Duration::from_secs(6), || async {
        fx.h.imap.connections() > conns && fx.healthy()
    })
    .await;
}

/// Disabling the account stops its IDLE connection (politely, with DONE) and nothing reconnects; enabling starts it
/// again; disabling the index stops it too.
#[tokio::test]
async fn idle_stops_with_the_account_and_does_not_reconnect() {
    let mut fx = setup(Opts::default(), no_poll).await;
    fx.start_idle();
    fx.wait_idling().await;
    let mark = fx.h.imap.commands().len();
    fx.h.admin(AdminRequest::AccountsDisable { alias: "info".into() }).await.unwrap();
    wait_for("IDLE to stop", Duration::from_secs(3), || async { fx.h.imap.idling() == 0 && !fx.healthy() }).await;
    assert!(fx.commands_since(mark).iter().any(|c| c == "DONE"), "{:?}", fx.commands_since(mark));
    let conns = fx.h.imap.connections();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(fx.h.imap.connections(), conns, "no reconnect for a disabled account");
    assert_eq!(fx.h.imap.idling(), 0);

    fx.h.admin(AdminRequest::AccountsEnable { alias: "info".into() }).await.unwrap();
    fx.wait_idling().await;
    fx.h.admin(AdminRequest::IndexDisable { alias: "info".into() }).await.unwrap();
    wait_for("IDLE to stop after index disable", Duration::from_secs(3), || async {
        fx.h.imap.idling() == 0 && !fx.healthy()
    })
    .await;
    let conns = fx.h.imap.connections();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(fx.h.imap.connections(), conns);
    fx.h.imap.assert_only_allowlisted();
}

/// The password changes at the provider while IDLE runs: the reconnect's login fails once, the mailbox is marked
/// `reauth_required` with one notification, and IDLE does not try again.
#[tokio::test]
async fn auth_failure_on_reconnect_marks_reauth_once_and_stops() {
    let mut fx = setup(Opts::default(), no_poll).await;
    fx.start_idle();
    fx.wait_idling().await;
    fx.h.imap.set_password(&fx.u.user, "changed-elsewhere");
    let mark = fx.h.imap.commands().len();
    fx.h.imap.kick_idle();
    wait_for("reauth_required", Duration::from_secs(5), || async { fx.status().await == "reauth_required" }).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let logins = fx.commands_since(mark).iter().filter(|c| c.starts_with("LOGIN")).count();
    assert_eq!(logins, 1, "{:?}", fx.commands_since(mark));
    let notes = fx.h.app().notifier.sent.lock().unwrap().iter().filter(|m| m.contains("'info'")).count();
    assert_eq!(notes, 1);
    assert_eq!((fx.h.imap.idling(), fx.healthy()), (0, false));
}

/// A server without IDLE is polled: new mail arrives through the poll, IDLE is never sent, and the supervisor does
/// not keep reconnecting to find out again.
#[tokio::test]
async fn server_without_idle_is_polled() {
    let mut fx = setup(Opts { idle: false, ..Default::default() }, |c| c.index.poll_interval_secs = 1).await;
    fx.start_scheduler();
    fx.start_idle();
    let before = fx.indexed().await;
    fx.add("polled arrival");
    wait_for("the polled message in the index", Duration::from_secs(6), || async { fx.indexed().await == before + 1 })
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let conns = fx.h.imap.connections();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(fx.h.imap.connections() <= conns + 1, "{} -> {}", conns, fx.h.imap.connections());
    assert!(!fx.h.imap.commands().iter().any(|c| c == "IDLE"));
    assert!(!fx.healthy());
}

/// Without a healthy IDLE connection, a search whose mailbox was last synced more than 5 s ago checks INBOX first and
/// finds the new message. `as_of` stays the last full sync. A recent sync skips the check.
#[tokio::test]
async fn search_freshness_finds_new_mail_without_idle() {
    let fx = setup(Opts::default(), no_poll).await;
    fx.add("fresh arrival");
    // Recent full sync: no check, the message is not there yet.
    let mark = fx.h.imap.commands().len();
    let (subjects, _) = fx.subjects().await;
    assert_eq!(subjects, vec!["first".to_string()]);
    assert!(fx.commands_since(mark).is_empty(), "{:?}", fx.commands_since(mark));

    let aged = fx.age_last_sync().await;
    let (subjects, v) = fx.subjects().await;
    assert!(subjects.contains(&"fresh arrival".to_string()), "{v}");
    assert_eq!(v["as_of"].as_str(), Some(dove::util::rfc3339(aged).as_str()), "{v}");
    assert_eq!(fx.last_success().await, Some(aged));
    let cmds = fx.commands_since(mark);
    assert!(!cmds.iter().any(|c| c.starts_with("LIST")), "INBOX only: {cmds:?}");
    // A second search right away does not check again (throttled per mailbox).
    let mark = fx.h.imap.commands().len();
    fx.subjects().await;
    assert!(fx.commands_since(mark).is_empty(), "{:?}", fx.commands_since(mark));
    fx.h.imap.assert_only_allowlisted();
}

/// A stalled server cannot hold a search: the freshness check gives up after its ~2 s budget and the search answers
/// from the index.
#[tokio::test]
async fn search_freshness_respects_its_budget() {
    // Long command and tool timeouts, so only the freshness budget can end the wait.
    let fx = setup(Opts::default(), |c| {
        no_poll(c);
        c.limits.upstream_request_timeout_secs = 30;
        c.limits.tool_call_timeout_secs = 30;
    })
    .await;
    fx.add("stalled arrival");
    let aged = fx.age_last_sync().await;
    fx.h.imap.fail_next("EXAMINE", Fault::Delay(Duration::from_secs(10)));
    let t0 = Instant::now();
    let (subjects, v) = fx.subjects().await;
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(1500) && took < Duration::from_millis(3500), "{took:?}");
    assert_eq!(subjects, vec!["first".to_string()], "{v}");
    assert_eq!(v["as_of"].as_str(), Some(dove::util::rfc3339(aged).as_str()), "{v}");
}

/// IDLE costs exactly one extra connection per mailbox: with the pool busy (reads and a sync in parallel) the server
/// never sees more than pool size + 1 connections of the account.
#[tokio::test]
async fn idle_uses_one_connection_beyond_the_pool() {
    let mut fx = setup(Opts::default(), no_poll).await;
    for i in 0..6 {
        fx.add(&format!("pool {i}"));
    }
    sync_steps(fx.h.app(), &fx.u.account_id, usize::MAX).await.unwrap();
    let (_, v) = fx.subjects().await;
    let ids = col(&v, "message_id");
    assert_eq!(ids.len(), 7);
    fx.start_scheduler();
    fx.start_idle();
    fx.wait_idling().await;
    // Several supervisor rounds, while the pool is as busy as it gets.
    fx.h.imap.reset_max_open();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(2500) {
        let reads =
            ids.iter().map(|id| fx.h.ok(&fx.token, "get_message", json!({"account": "info", "message_id": id})));
        let (_, _) =
            tokio::join!(futures::future::join_all(reads), sync_steps(fx.h.app(), &fx.u.account_id, usize::MAX));
    }
    let pool = dove::imap::pool::DEFAULT_PER_ACCOUNT;
    let max = fx.h.imap.max_open_connections();
    // The pool was saturated (so the bound means something), and IDLE added exactly one.
    assert_eq!(max, pool + 1, "max open {max}, pool {pool}");
    assert_eq!(fx.h.imap.idling(), 1);
    fx.h.imap.assert_only_allowlisted();
}
