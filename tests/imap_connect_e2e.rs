//! IMAP accounts: `connect-imap` verifies before it stores, presets, Drafts discovery, reconnect, reauth marking,
//! removal and the optional `[google]` section (design "Account model and connect"). All against the fake server.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use dove::admin::{AdminRequest, Password};
use dove::imap::{TlsMode, presets};
use serde_json::{Value, json};
use support::fake_imap::{FakeImap, Opts, SmtpFault};
use support::harness::{Harness, g};
use zeroize::Zeroizing;

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
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

async fn count(h: &Harness, sql: &'static str, id: &str) -> i64 {
    let id = id.to_string();
    h.app().store.call(move |c| Ok(c.query_row(sql, [id], |r| r.get(0))?)).await.unwrap()
}

async fn accounts(h: &Harness) -> i64 {
    h.app().store.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))?)).await.unwrap()
}

async fn grant_row(h: &Harness, id: &str) -> (Vec<u8>, i64, String) {
    let id = id.to_string();
    h.app()
        .store
        .call(move |c| {
            Ok(c.query_row(
                "SELECT g.refresh_token_ciphertext, a.grant_generation, a.status FROM grants g \
                 JOIN accounts a ON a.id = g.account_id WHERE a.id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })
        .await
        .unwrap()
}

fn all_files(dir: &std::path::Path, out: &mut Vec<Vec<u8>>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            all_files(&p, out);
        } else {
            out.push(std::fs::read(&p).unwrap_or_default());
        }
    }
}

/// Only this test installs the process-wide log subscriber (the other tests' logs land in the same sink).
#[tokio::test]
async fn connect_verifies_before_storing() {
    let sink = Sink::default();
    assert!(dove::logging::install_service_logging(sink.clone(), tracing_subscriber::EnvFilter::new("trace")));
    let h = Harness::start().await;
    let right = "CANARY-right-pw-8842";
    let wrong = "CANARY-wrong-pw-1307";
    h.imap.add_user("box@example.org", right);
    h.imap.add_folder("box@example.org", "Drafts", Some("\\Drafts"));
    h.imap.add_folder("box@example.org", "Sent", Some("\\Sent"));

    // Wrong password: IMAP login fails, nothing is stored, the error names the step and not the password.
    let e = h.admin(h.connect_imap_request("box", "box@example.org", wrong)).await.unwrap_err();
    assert!(e.contains("IMAP login failed"), "{e}");
    assert!(!e.contains(wrong), "{e}");
    assert_eq!(accounts(&h).await, 0);

    // IMAP fine, SMTP AUTH refused: still nothing stored.
    h.imap.smtp_fail_next("AUTH", SmtpFault::Reply(535));
    let e = h.admin(h.connect_imap_request("box", "box@example.org", right)).await.unwrap_err();
    assert!(e.contains("SMTP login failed"), "{e}");
    assert!(!e.contains(right), "{e}");
    assert_eq!(accounts(&h).await, 0);
    assert_eq!(h.imap.sent_mails().len(), 0);

    // Unknown provider without explicit servers: refused before any connection.
    let before = h.imap.connections();
    let e = h
        .admin(AdminRequest::AccountsConnectImap {
            alias: "box".into(),
            email: "box@unknown-provider.example".into(),
            username: None,
            smtp_username: None,
            password: Password(Zeroizing::new(right.into())),
            imap: None,
            smtp: None,
            drafts_folder: None,
            preset: None,
        })
        .await
        .unwrap_err();
    assert!(e.contains("--imap-host"), "{e}");
    assert_eq!(h.imap.connections(), before);

    // Right password: stored as an IMAP account with its folders, index enabled.
    let v = h.admin(h.connect_imap_request("box", "box@example.org", right)).await.unwrap();
    assert_eq!(v["provider"], "imap");
    assert_eq!(v["drafts_folder"], "Drafts");
    assert_eq!(v["sent_folder"], "Sent");
    let (provider, status, index): (String, String, bool) = h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row("SELECT provider, status, index_enabled FROM accounts WHERE alias = 'box'", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?)
        })
        .await
        .unwrap();
    assert_eq!((provider.as_str(), status.as_str(), index), ("imap", "active", true));
    let list = h.admin(AdminRequest::AccountsList).await.unwrap();
    assert_eq!(list[0]["provider"], "imap");
    // A second connect with the same alias or address is refused without touching the network.
    let before = h.imap.connections();
    let e = h.admin(h.connect_imap_request("box", "box@example.org", right)).await.unwrap_err();
    assert!(e.contains("already exists"), "{e}");
    let e = h.admin(h.connect_imap_request("box2", "BOX@example.org", right)).await.unwrap_err();
    assert!(e.contains("already connected"), "{e}");
    assert_eq!(h.imap.connections(), before);

    // Neither password appears in logs, audit records or any file of the data directory (state store + WAL).
    let audit: Vec<String> = h
        .app()
        .store
        .call(|c| {
            let mut s = c.prepare("SELECT * FROM audit")?;
            let n = s.column_count();
            let rows = s.query_map([], |r| {
                use rusqlite::types::ValueRef;
                let cell = |i| match r.get_ref(i).unwrap() {
                    ValueRef::Text(b) | ValueRef::Blob(b) => String::from_utf8_lossy(b).into_owned(),
                    ValueRef::Integer(x) => x.to_string(),
                    ValueRef::Real(x) => x.to_string(),
                    ValueRef::Null => String::new(),
                };
                Ok((0..n).map(cell).collect::<Vec<_>>().join("|"))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
        .unwrap();
    assert!(audit.iter().any(|r| r.contains("accounts.connect_imap")));
    let mut files = Vec::new();
    all_files(&h.env.app.cfg.data_dir, &mut files);
    let logs = sink.0.lock().unwrap().clone();
    for pw in [right, wrong] {
        assert!(!contains(&logs, pw), "password in logs");
        assert!(!audit.iter().any(|r| r.contains(pw)), "password in audit");
        assert!(!files.iter().any(|f| contains(f, pw)), "password in a data file");
    }
}

#[test]
fn connect_with_preset_fills_hosts() {
    let s = presets::for_email("x@strato.de").unwrap();
    assert_eq!(s.name, "strato");
    assert_eq!((s.imap.host.as_str(), s.imap.port, s.imap.tls), ("imap.strato.de", 993, TlsMode::Implicit));
    assert_eq!((s.smtp.host.as_str(), s.smtp.port, s.smtp.tls), ("smtp.strato.de", 465, TlsMode::Implicit));
    assert!(s.save_sent_copy);
    for addr in ["x@icloud.com", "x@me.com", "x@mac.com"] {
        let i = presets::for_email(addr).unwrap();
        assert_eq!(i.name, "icloud");
        assert_eq!((i.imap.host.as_str(), i.imap.port), ("imap.mail.me.com", 993));
        assert_eq!((i.smtp.host.as_str(), i.smtp.port, i.smtp.tls), ("smtp.mail.me.com", 587, TlsMode::StartTls));
        // iCloud files sent mail itself.
        assert!(!i.save_sent_copy);
    }
    assert!(presets::for_email("x@gmail.com").is_none());
    assert!(presets::for_email("x@notstrato.de").is_none());
    assert_eq!(presets::by_name("ICLOUD").map(|p| p.name), Some("icloud"));
    assert!(presets::by_name("gmx").is_none());
}

#[tokio::test]
async fn drafts_found_by_utf7_name() {
    let mut h = Harness::start().await;
    h.imap = FakeImap::start_with(Opts { special_use: false, ..Opts::default() }).await;
    let pw = "pw-entwurf";
    h.imap.add_user("de@example.org", pw);
    h.imap.add_folder("de@example.org", "Entwürfe", None);
    h.imap.add_folder("de@example.org", "Gesendet", None);
    h.imap.add_folder("de@example.org", "Papierkorb", None);
    let v = h.admin(h.connect_imap_request("de", "de@example.org", pw)).await.unwrap();
    assert_eq!(v["drafts_folder"], "Entwürfe");
    assert_eq!(v["sent_folder"], "Gesendet");
    let rows: Vec<(String, Option<String>)> = h
        .app()
        .store
        .call(|c| {
            let mut s = c.prepare("SELECT name, special FROM imap_folders ORDER BY folder_id")?;
            let r = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(r.collect::<Result<_, _>>()?)
        })
        .await
        .unwrap();
    // Wire names stay modified UTF-7; the role is recorded once.
    assert!(rows.contains(&("Entw&APw-rfe".into(), Some("drafts".into()))), "{rows:?}");
    assert!(rows.contains(&("Gesendet".into(), Some("sent".into()))), "{rows:?}");
    assert!(rows.contains(&("Papierkorb".into(), Some("trash".into()))), "{rows:?}");
    assert!(rows.contains(&("INBOX".into(), None)), "{rows:?}");

    // No Drafts folder at all: refused with a hint; an explicit --drafts-folder works.
    h.imap.add_user("odd@example.org", pw);
    h.imap.add_folder("odd@example.org", "Mein Ordner", None);
    let e = h.admin(h.connect_imap_request("odd", "odd@example.org", pw)).await.unwrap_err();
    assert!(e.contains("--drafts-folder"), "{e}");
    assert_eq!(count(&h, "SELECT COUNT(*) FROM accounts WHERE alias = ?1", "odd").await, 0);
    let req = || {
        let mut req = h.connect_imap_request("odd", "odd@example.org", pw);
        if let AdminRequest::AccountsConnectImap { drafts_folder, .. } = &mut req {
            *drafts_folder = Some("Mein Ordner".into());
        }
        req
    };
    // Dove files sent copies for providers without a preset, so it needs a Sent folder too.
    let e = h.admin(req()).await.unwrap_err();
    assert!(e.contains("no Sent folder"), "{e}");
    h.imap.add_folder("odd@example.org", "Sent Items", None);
    let v = h.admin(req()).await.unwrap();
    assert_eq!(v["drafts_folder"], "Mein Ordner");
    assert_eq!(v["sent_folder"], "Sent Items");
}

#[tokio::test]
async fn reconnect_replaces_only_after_verify() {
    let h = Harness::start().await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    let (ct0, gen0, _) = grant_row(&h, &u.account_id).await;
    h.imap.set_password(&u.user, "new-app-password");

    let wrong = AdminRequest::AccountsReconnectImap {
        alias: "info".into(),
        password: Password(Zeroizing::new("still-wrong".into())),
    };
    let e = h.admin(wrong).await.unwrap_err();
    assert!(e.contains("IMAP login failed"), "{e}");
    assert_eq!(grant_row(&h, &u.account_id).await, (ct0.clone(), gen0, "active".into()));

    let right = AdminRequest::AccountsReconnectImap {
        alias: "info".into(),
        password: Password(Zeroizing::new("new-app-password".into())),
    };
    let v = h.admin(right).await.unwrap();
    assert_eq!(v["status"], "active");
    let (ct1, gen1, status) = grant_row(&h, &u.account_id).await;
    assert_ne!(ct1, ct0);
    assert_eq!((gen1, status.as_str()), (gen0 + 1, "active"));
    let (_, creds) = dove::imap::account::load(h.app(), &u.account_id).await.unwrap();
    assert_eq!(creds.password.as_str(), "new-app-password");

    // The Gmail verb refuses IMAP mailboxes, and the IMAP verb refuses Gmail ones.
    let e = h.admin(AdminRequest::AccountsReconnect { alias: "info".into() }).await.unwrap_err();
    assert!(e.contains("IMAP mailbox"), "{e}");
    h.mailbox("gm", "gm@example.com");
    let e = h
        .admin(AdminRequest::AccountsReconnectImap {
            alias: "gm".into(),
            password: Password(Zeroizing::new("x".into())),
        })
        .await
        .unwrap_err();
    assert!(e.contains("Gmail mailbox"), "{e}");
}

fn noop(s: &mut dove::imap::ImapSession) -> dove::imap::pool::SessionFuture<'_, ()> {
    Box::pin(async move { s.noop().await })
}

#[tokio::test]
async fn auth_failure_marks_reauth_once() {
    let h = Harness::start().await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read")]).await;
    let app = h.app().clone();
    dove::imap::account::with_session(&app, &u.account_id, noop).await.unwrap();
    let (_, gen0, _) = grant_row(&h, &u.account_id).await;

    // The password changes at the provider: the pooled session still works, a new login does not.
    h.imap.set_password(&u.user, "changed-elsewhere");
    app.imap.evict(&u.account_id);
    let e = dove::imap::account::with_session(&app, &u.account_id, noop).await.unwrap_err();
    assert_eq!(e.code.as_str(), "account_unavailable");
    let e = dove::imap::account::with_session(&app, &u.account_id, noop).await.unwrap_err();
    assert_eq!(e.code.as_str(), "account_unavailable");
    let (_, _, status) = grant_row(&h, &u.account_id).await;
    assert_eq!(status, "reauth_required");
    let notes = app.notifier.sent.lock().unwrap().iter().filter(|m| m.contains("'info'")).count();
    assert_eq!(notes, 1);
    let last_error: Option<String> = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT last_error_code FROM accounts WHERE alias = 'info'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(last_error.as_deref(), Some("auth_failed"));
    // Agents see the account as unavailable.
    assert_eq!(h.err(&token, "list_labels", json!({ "account": "info" })).await, "account_unavailable");

    // After a reconnect, a late failure for the old generation cannot mark the new password.
    h.admin(AdminRequest::AccountsReconnectImap {
        alias: "info".into(),
        password: Password(Zeroizing::new("changed-elsewhere".into())),
    })
    .await
    .unwrap();
    dove::imap::account::mark_auth_failure(&app, &u.account_id, gen0, "info").await;
    let (_, gen1, status) = grant_row(&h, &u.account_id).await;
    assert_eq!((gen1, status.as_str()), (gen0 + 1, "active"));
    dove::imap::account::with_session(&app, &u.account_id, noop).await.unwrap();
}

#[tokio::test]
async fn remove_deletes_credentials_and_index() {
    let h = Harness::start().await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    assert!(dove::index::ensure_state(h.app(), &u.account_id).await.unwrap());
    let id = u.account_id.clone();
    let states = || {
        let id = id.clone();
        h.app().index.write(move |c| {
            Ok(c.query_row("SELECT COUNT(*) FROM sync_state WHERE account_id = ?1", [id], |r| r.get::<_, i64>(0))?)
        })
    };
    assert_eq!(states().await.unwrap(), 1);
    assert!(count(&h, "SELECT COUNT(*) FROM imap_folders WHERE account_id = ?1", &id).await >= 5);

    let v = h.admin(AdminRequest::AccountsRemove { alias: "info".into() }).await.unwrap();
    assert_eq!(v["removed"], true);
    assert_eq!(v["google_revocation"], "not_applicable");
    for sql in [
        "SELECT COUNT(*) FROM accounts WHERE id = ?1",
        "SELECT COUNT(*) FROM grants WHERE account_id = ?1",
        "SELECT COUNT(*) FROM imap_folders WHERE account_id = ?1",
    ] {
        assert_eq!(count(&h, sql, &id).await, 0, "{sql}");
    }
    assert_eq!(states().await.unwrap(), 0);
    let e = dove::imap::account::load(h.app(), &id).await.unwrap_err();
    assert_eq!(e.code.as_str(), "not_found");
}

#[tokio::test]
async fn accounts_check_logs_in_and_marks_reauth() {
    let h = Harness::start().await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    let v = h.admin(AdminRequest::AccountsCheck { alias: Some("info".into()) }).await.unwrap();
    assert_eq!(v[0]["imap_ok"], true, "{v}");
    assert_eq!(v[0]["smtp_ok"], true, "{v}");
    assert!(h.imap.commands().iter().any(|c| c.contains("NOOP")));
    h.imap.set_password(&u.user, "rotated");
    let v = h.admin(AdminRequest::AccountsCheck { alias: Some("info".into()) }).await.unwrap();
    assert_eq!(v[0]["imap_ok"], false, "{v}");
    assert_eq!(v[0]["status"], "reauth_required", "{v}");
}

#[tokio::test]
async fn google_section_optional() {
    let h = Harness::start_with(|c| c.google = None).await;
    let e = h
        .admin(AdminRequest::AccountsConnect { alias: "gm".into(), email: "gm@example.com".into() })
        .await
        .unwrap_err();
    assert!(e.contains("[google]"), "{e}");
    // IMAP mailboxes work without it.
    h.imap_mailbox("info", "info@example.org").await;
    let doctor = h.admin(AdminRequest::Doctor).await.unwrap();
    let google: Vec<&Value> = doctor.as_array().unwrap().iter().filter(|c| c["check"] == "google_reachable").collect();
    assert_eq!(google.len(), 1);
    assert!(google[0]["detail"].as_str().unwrap().contains("[google]"));
}

#[tokio::test]
async fn keys_rotate_rewraps_imap_passwords() {
    use std::os::unix::fs::PermissionsExt;
    let mut h = Harness::start().await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.mailbox("gm", "gm@example.com");
    let kek = h.app().cfg.secrets.kek_file.clone();
    let mut text = std::fs::read_to_string(&kek).unwrap();
    text.push('\n');
    text.push_str(&dove::secrets::generate_key_line(2));
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&kek, text).unwrap();
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o400)).unwrap();
    h.restart().await;

    let v = h.admin(AdminRequest::KeysRotate).await.unwrap();
    assert_eq!(v["rewrapped"], 2, "{v}");
    assert_eq!(v["versions_in_use"], json!([2]));
    let (_, creds) = dove::imap::account::load(h.app(), &u.account_id).await.unwrap();
    assert_eq!(creds.password.as_str(), support::harness::IMAP_PASSWORD);
}
