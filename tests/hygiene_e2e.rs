//! AC8 (encryption at rest) and AC9 (log hygiene): canary values in bodies, subjects, addresses, tokens and
//! OAuth codes must not appear in service logs, the audit log or the plaintext state store and its WAL.
//! One test per file: it installs the process-wide log subscriber at TRACE level with the service log format.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use dove::admin::AdminRequest;
use dove::gmail::{SCOPE_COMPOSE, SCOPE_READONLY};
use serde_json::json;
use support::fake_google::{CodeSpec, MessageSpec};
use support::harness::{HOST, Harness, g};

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

fn file_bytes(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn canaries_never_reach_logs_audit_or_plaintext_state() {
    let sink = Sink::default();
    assert!(dove::logging::install_service_logging(sink.clone(), tracing_subscriber::EnvFilter::new("trace")));

    let h = Harness::start().await;
    // A mailbox with a known refresh token (AC8).
    h.google.add_mailbox("info@acme.test", "sub-info");
    let refresh = h.google.issue_refresh_token("info@acme.test");
    h.env.add_account("info", "info@acme.test", &refresh);
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read,draft")]).await;

    // Content canaries.
    let subject = "CANARY-SUBJECT-7f3a";
    let body = "CANARY-BODY-91c2 please wire money";
    let sender = "canary-sender-55@example.org";
    let id = h.google.add_message(
        "info@acme.test",
        MessageSpec {
            from: format!("Canary Name <{sender}>"),
            to: vec!["info@acme.test".into()],
            subject: subject.into(),
            text: Some(body.into()),
            internal_date_ms: 1_700_000_000_000,
            ..Default::default()
        },
    );
    h.ok(&token, "get_message", json!({"account":"info","message_id":id})).await;
    let draft_body = "CANARY-DRAFT-0d4e";
    let d = h
        .ok(
            &token,
            "create_draft",
            json!({"account":"info","request_key":uuid::Uuid::new_v4().to_string(),"to":[sender],"subject":subject,"body_text":draft_body}),
        )
        .await;
    let u = h
        .ok(
            &token,
            "update_draft",
            json!({"account":"info","draft_id":d["draft_id"],"expected_revision":d["revision"],"changes":{"body_text":"CANARY-DRAFT-2"}}),
        )
        .await;
    // A request note is agent free text that may quote mail: sealed, shown to the operator only (PLAN A71).
    let send_at = dove::util::rfc3339(dove::util::now_unix() + 3600);
    let req = h
        .ok(
            &token,
            "request_send",
            json!({"account":"info","note":"CANARY-NOTE-77ab","items":[{"draft_id":d["draft_id"],
                   "expected_revision":u["revision"],"send_at":send_at}]}),
        )
        .await;
    let _request_id = req["request_id"].as_str().unwrap().to_string();
    // Failing calls carry canaries in arguments too.
    let _ = h.call(&token, "get_message", json!({"account":"CANARY-ALIAS-ARG","message_id":"CANARYID1"})).await;
    let bogus_token = dove::tokens::generate("dove_");
    let r = h.post_mcp(Some(&bogus_token), json!({"jsonrpc":"2.0","id":1,"method":"ping"}), &[]).await;
    assert_eq!(r.status(), 401);

    // Google connect with a canary authorization code and state.
    h.google.add_mailbox("ops@acme.test", "sub-ops");
    let v =
        h.admin(AdminRequest::AccountsConnect { alias: "ops".into(), email: "ops@acme.test".into() }).await.unwrap();
    let url = url::Url::parse(v["open_this_link"].as_str().unwrap()).unwrap();
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let code = "CANARY-OAUTH-CODE-3b8e";
    h.google.register_code(
        code,
        CodeSpec {
            email: "ops@acme.test".into(),
            sub: "sub-ops".into(),
            email_verified: true,
            scopes: ["openid", "email", SCOPE_READONLY, SCOPE_COMPOSE].iter().map(|s| s.to_string()).collect(),
            code_challenge: q["code_challenge"].clone(),
            aud: None,
            with_refresh_token: true,
        },
    );
    let r = h
        .http
        .get(format!("{}/oauth/google/callback", h.base))
        .header("host", HOST)
        .query(&[("code", code), ("state", q["state"].as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // Index the mailbox and search it: canaries pass through ingest, FTS and the query compiler.
    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    let info_id: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT id FROM accounts WHERE alias='info'", [], |r| r.get(0))?))
        .await
        .unwrap();
    dove::index::sync::sync_account(h.app(), &info_id).await.unwrap();
    let found = h
        .ok(
            &token,
            "search_messages",
            json!({"where":{"field":"text","op":"terms","value":"CANARY-BODY-91c2"},"select":["subject"]}),
        )
        .await;
    assert!(found.to_string().contains(subject), "the indexed canary is searchable: {found}");
    // Invalid grant path (error logging and notification).
    h.google.invalidate_refresh_tokens("info@acme.test");
    let acct: String = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT id FROM accounts WHERE alias='info'", [], |r| r.get(0))?))
        .await
        .unwrap();
    h.app().google.tokens().evict(&acct);
    assert_eq!(h.err(&token, "get_message", json!({"account":"info","message_id":id})).await, "account_unavailable");
    let access_tokens: Vec<String> = vec![h.google.access_token_for("info@acme.test")];

    // Let spawned tasks finish their log lines.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let logs = sink.0.lock().unwrap().clone();
    let log_text = String::from_utf8_lossy(&logs).to_string();
    assert!(log_text.contains("\"tool call\""), "the capture must see service logs");
    let audit: String =
        h.app().store.call(|c| Ok(serde_json::to_string(&dove::audit::tail(c, 10_000)?)?)).await.unwrap();

    let mut canaries: Vec<String> = vec![
        subject.into(),
        "CANARY-BODY".into(),
        "canary-sender".into(),
        "Canary Name".into(),
        "CANARY-DRAFT".into(),
        "CANARY-NOTE".into(),
        "CANARY-ALIAS-ARG".into(),
        code.into(),
        q["state"].clone(),
        refresh.clone(),
        token.clone(),
        bogus_token.clone(),
        "ya29.".into(),
        "1//".into(),
    ];
    canaries.extend(access_tokens);
    for c in &canaries {
        assert!(!log_text.contains(c.as_str()), "canary {c:?} leaked into logs");
        assert!(!audit.contains(c.as_str()), "canary {c:?} leaked into the audit log");
    }

    // AC8: the plaintext state store and its WAL hold neither refresh nor connection tokens.
    let db = h.app().cfg.state_db_path();
    let wal = db.with_extension("db-wal");
    let mut bytes = file_bytes(&db);
    bytes.extend(file_bytes(&wal));
    assert!(bytes.len() > 4096, "state store files were read");
    for secret in [refresh.as_str(), token.as_str(), &token[5..], code, q["state"].as_str()] {
        assert!(!contains(&bytes, secret), "secret found in plaintext state files");
    }
    // AC20: the index DB, its WAL and any other file in the data directory hold no plaintext content.
    let data_dir = h.app().cfg.data_dir.clone();
    let mut files = 0;
    for e in std::fs::read_dir(&data_dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            files += 1;
            let b = file_bytes(&p);
            for c in [subject, "CANARY-BODY-91c2", "canary-sender-55", "wire money", "CANARY-NOTE"] {
                assert!(!contains(&b, c), "content canary {c:?} in plaintext file {}", p.display());
            }
        }
    }
    assert!(files >= 3, "state and index files were checked");
}
