//! Admin web UI hygiene (PLAN A74): session cookies, CSRF tokens, enrolment links, WebAuthn challenges and the
//! mail content shown on the pages never reach the service log, the audit log or the plaintext state store.
//! One test per file: it installs the process-wide log subscriber at TRACE level with the service log format.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use dove::admin::AdminRequest;
use dove::admin_ui::soft_authenticator::SoftAuthenticator;
use serde_json::json;
use support::admin_ui::*;
use support::harness::g;

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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn admin_ui_secrets_and_mail_stay_out_of_logs_audit_and_state() {
    let sink = Sink::default();
    assert!(dove::logging::install_service_logging(sink.clone(), tracing_subscriber::EnvFilter::new("trace")));
    let h = start().await;
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read,draft")]).await;

    let subject = "CANARY-UI-SUBJECT-4e1d";
    let body = "CANARY-UI-BODY-8b20 transfer now";
    let note = "CANARY-UI-NOTE-c3f9";
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({"account":"info","request_key":uuid::Uuid::new_v4().to_string(),"to":["canary-rcpt-71@example.org"],
                   "subject":subject,"body_text":body}),
        )
        .await;
    let v = h
        .ok(
            &token,
            "request_send",
            json!({"account":"info","note":note,"items":[{"draft_id":c["draft_id"],"expected_revision":c["revision"],
                   "send_at":dove::util::rfc3339(dove::util::now_unix() + 3600)}]}),
        )
        .await;
    let rid = v["request_id"].as_str().unwrap().to_string();

    // Enrol (the link's token), sign in again (a challenge), view the draft, approve with a confirmation.
    let enrol_token = enrol_link(&h, "phone").await;
    let mut b = Browser::new(&h);
    let mut a = SoftAuthenticator::es256(ORIGIN);
    let o = b.post_json("/admin/enroll/options", json!({ "token": enrol_token })).await.json();
    let enrol_challenge = o["publicKey"]["challenge"].as_str().unwrap().to_string();
    let reg = a.register(&b64d(&o["publicKey"]["challenge"]), &b64d(&o["publicKey"]["user"]["id"]));
    assert_eq!(
        b.post_json("/admin/enroll/finish", json!({ "id": o["id"], "credential": reg.to_json() })).await.status,
        200
    );
    let first_cookie = b.cookie.clone().unwrap();
    let (login_id, login_ch) = login_options(&mut b).await;
    assert_eq!(login_finish(&mut b, &login_id, &a.assert(&login_ch)).await.status, 200);
    let page = b.get(&format!("/admin/requests/{rid}")).await;
    assert!(page.text.contains(subject) && page.text.contains(note));
    let csrf = b.csrf.clone().unwrap();
    let cookie = b.cookie.clone().unwrap();
    let rev = h.admin(AdminRequest::RequestsShow { id: rid.clone() }).await.unwrap()["items"][0]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let (pid, ch, _) =
        stepup_begin(&mut b, &format!("/admin/requests/{rid}/approve"), &[("item", "0"), ("rev.0", rev.as_str())])
            .await;
    let r = stepup_finish(&mut b, &pid, &a.assert(&ch)).await;
    assert_eq!(r.status, 200, "{}", r.text);
    // A failed sign-in is logged as a failure, without its material.
    let (bad_id, bad_ch) = login_options(&mut Browser::new(&h)).await;
    let mut stranger = SoftAuthenticator::es256(ORIGIN);
    stranger.user_handle = vec![9; 16];
    assert_eq!(login_finish(&mut Browser::new(&h), &bad_id, &stranger.assert(&bad_ch)).await.status, 401);

    let logs = sink.0.lock().unwrap().clone();
    assert!(!logs.is_empty(), "the log sink received records");
    let audit: String =
        h.app().store.call(|c| Ok(serde_json::to_string(&dove::audit::tail(c, 10_000)?)?)).await.unwrap();
    assert!(audit.contains("web:phone"), "the UI's actions are audited");
    let db = h.app().cfg.state_db_path();
    let mut state = std::fs::read(&db).unwrap_or_default();
    state.extend(std::fs::read(db.with_extension("db-wal")).unwrap_or_default());
    let mut wal = db.clone().into_os_string();
    wal.push("-wal");
    state.extend(std::fs::read(wal).unwrap_or_default());
    assert!(state.len() > 4096, "state store files were read");

    let ch_b64 = dove::util::b64url(&ch);
    let login_ch_b64 = dove::util::b64url(&login_ch);
    let pid = pid.as_str().unwrap().to_string();
    let secrets: Vec<(&str, &str)> = vec![
        ("enrolment token", &enrol_token),
        ("enrolment challenge", &enrol_challenge),
        ("first session cookie", &first_cookie),
        ("session cookie", &cookie),
        ("csrf token", &csrf),
        ("login challenge", &login_ch_b64),
        ("step-up challenge", &ch_b64),
        ("step-up id", &pid),
    ];
    for (what, s) in &secrets {
        assert!(!contains(&logs, s.as_bytes()), "{what} in the service log");
        assert!(!audit.contains(s), "{what} in the audit log");
        assert!(!contains(&state, s.as_bytes()), "{what} in the plaintext state store");
    }
    for (what, s) in [("subject", subject), ("body", body), ("note", note), ("recipient", "canary-rcpt-71")] {
        assert!(!contains(&logs, s.as_bytes()), "{what} in the service log");
        assert!(!audit.contains(s), "{what} in the audit log");
    }
}
