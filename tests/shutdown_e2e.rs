//! Graceful shutdown (spec 8.2): in-flight requests finish, the grace period is a hard upper bound.

mod support;

use std::time::{Duration, Instant};

use serde_json::json;
use support::fake_google::{Fault, MessageSpec};
use support::harness::{HOST, Harness, g};

async fn fixture() -> (Harness, String, String) {
    let h = Harness::start().await;
    h.mailbox("info", "info@acme.test");
    h.project("acme", &["info"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    let id = h.google.add_message(
        "info@acme.test",
        MessageSpec {
            from: "a@b.example".into(),
            subject: "s".into(),
            text: Some("t".into()),
            internal_date_ms: 1,
            ..Default::default()
        },
    );
    // Warm the access token so only the delayed message fetch is in flight.
    h.ok(&token, "list_labels", json!({"account":"info"})).await;
    (h, token, id)
}

fn get_message(h: &Harness, base: &str, token: &str, id: &str) -> tokio::task::JoinHandle<Result<u16, String>> {
    let req = h
        .http
        .post(format!("{base}/mcp"))
        .header("host", HOST)
        .header("mcp-protocol-version", "2025-06-18")
        .bearer_auth(token)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_message","arguments":{"account":"info","message_id":id}}}));
    tokio::spawn(async move { req.send().await.map(|r| r.status().as_u16()).map_err(|e| e.to_string()) })
}

#[tokio::test]
async fn in_flight_requests_finish_and_new_connections_are_refused() {
    let (h, token, id) = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (sig_tx, sig_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(dove::serve::serve_until(
        h.app().clone(),
        listener,
        async {
            let _ = sig_rx.await;
        },
        Duration::from_secs(10),
    ));
    h.google.fail_next("GET", "/messages/", Fault::Delay(Duration::from_millis(800)));
    let inflight = get_message(&h, &base, &token, &id);
    tokio::time::sleep(Duration::from_millis(200)).await;
    sig_tx.send(()).unwrap();
    assert_eq!(inflight.await.unwrap(), Ok(200), "the in-flight call completes");
    tokio::time::timeout(Duration::from_secs(3), server).await.expect("server stops").unwrap().unwrap();
    let after = h.http.get(format!("{base}/healthz")).send().await;
    assert!(after.is_err(), "no new connections after shutdown");
}

#[tokio::test]
async fn grace_period_bounds_shutdown_time() {
    let (h, token, id) = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (sig_tx, sig_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(dove::serve::serve_until(
        h.app().clone(),
        listener,
        async {
            let _ = sig_rx.await;
        },
        Duration::from_millis(500),
    ));
    h.google.fail_next("GET", "/messages/", Fault::Delay(Duration::from_secs(5)));
    let _stuck = get_message(&h, &base, &token, &id);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t = Instant::now();
    sig_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(4), server).await.expect("bounded shutdown").unwrap().unwrap();
    assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
}
