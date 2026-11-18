//! Health alerts over Web Push (design 2026-11-17): owner notifications reach every push device with lock-screen text
//! that names only the mailbox or connection, the health watcher alerts once on a stalled sync and once on recovery,
//! and on low disk space with hysteresis.

mod support;

use dove::admin::AdminRequest;
use dove::health::{self, LOW_DISK_BYTES};
use dove::push;
use dove::util;
use serde_json::{Value, json};
use support::admin_ui::{self as ui, Browser};
use support::harness::{Harness, g};
use support::push::{Device, PushService};

struct Fx {
    h: Harness,
    svc: PushService,
    phone: Device,
    info: String,
}

/// Admin UI on, Gmail mailbox `info` indexed and synced, one push device.
async fn setup() -> Fx {
    setup_with(|_| {}).await
}

async fn setup_with(customize: impl FnOnce(&mut dove::config::Config)) -> Fx {
    let h = ui::start_with(customize).await;
    h.app().google.gateway().allow_loopback_push_for_tests();
    let info = h.mailbox("info", "info@acme.test");
    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    dove::index::sync::sync_account(h.app(), &info).await.unwrap();
    let svc = PushService::start().await;
    let phone = Device::new(1);
    h.admin(AdminRequest::PushAdd { name: "phone".into(), subscription: phone.subscription(&svc) }).await.unwrap();
    Fx { h, svc, phone, info }
}

impl Fx {
    /// Delivers what is due and returns the decrypted pushes the phone received since the last call.
    async fn pushes(&self) -> Vec<Value> {
        push::deliver_due(self.h.app(), util::now_unix()).await.unwrap();
        let hits = std::mem::take(&mut *self.svc.hits.lock().unwrap());
        hits.iter()
            .map(|(_, _, body)| {
                let plain = self.phone.open(body);
                assert_eq!(plain.len(), push::PAYLOAD_SIZE);
                serde_json::from_slice(&plain).unwrap()
            })
            .collect()
    }

    /// Sets the mailbox's sync state in the index.
    async fn sync_state(&self, sql: &str) {
        let (sql, id) = (sql.to_string(), self.info.clone());
        self.h.app().index.write(move |c| Ok(c.execute(&sql, [id])?)).await.unwrap();
    }

    async fn tick(&self) -> health::Report {
        health::tick_with(self.h.app(), util::now_unix(), Some(10 << 30)).await.unwrap()
    }
}

#[tokio::test]
async fn a_stalled_sync_alerts_once_and_its_recovery_once() {
    let fx = setup().await;
    assert_eq!(fx.tick().await, health::Report { disk_free: Some(10 << 30), ..Default::default() });
    assert!(fx.pushes().await.is_empty(), "a fresh mailbox raises nothing");

    let three_h_ago = util::now_unix() - 3 * 3600 - 60;
    fx.sync_state(&format!("UPDATE sync_state SET last_success_at = {three_h_ago} WHERE account_id = ?1")).await;
    assert_eq!(fx.tick().await.stalled, vec!["info"]);
    let p = fx.pushes().await;
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0]["title"], "Dove: sync stopped");
    assert_eq!(p[0]["body"], "info has not synced for 3 h");
    assert_eq!(p[0]["url"], "/admin/mailboxes/info");
    assert!(fx.h.app().notifier.sent.lock().unwrap().iter().any(|m| m.contains("'info' has not synced")));

    assert_eq!(fx.tick().await.stalled, vec!["info"], "still stalled");
    assert!(fx.pushes().await.is_empty(), "no second alert while it stays stalled");

    fx.sync_state(&format!("UPDATE sync_state SET last_success_at = {} WHERE account_id = ?1", util::now_unix())).await;
    assert_eq!(fx.tick().await.recovered, vec!["info"]);
    let p = fx.pushes().await;
    assert_eq!(
        (p.len(), p[0]["title"].as_str(), p[0]["body"].as_str()),
        (1, Some("Dove: sync is back"), Some("info syncs again"))
    );
    assert_eq!(fx.tick().await, health::Report { disk_free: Some(10 << 30), ..Default::default() });
    assert!(fx.pushes().await.is_empty(), "recovery is announced once");
}

/// A first backfill that is still making progress is not a stall; the same backfill failing is. A mailbox that needs
/// reconnecting is left to the reauth alert.
#[tokio::test]
async fn only_a_failing_or_finished_sync_counts_as_stalled() {
    let fx = setup().await;
    let five_h_ago = util::now_unix() - 5 * 3600;
    fx.sync_state(&format!(
        "UPDATE sync_state SET stage = 'backfill', last_success_at = NULL, last_error = NULL, \
         enabled_at = {five_h_ago} WHERE account_id = ?1"
    ))
    .await;
    assert!(fx.tick().await.stalled.is_empty(), "a progressing backfill");
    fx.sync_state("UPDATE sync_state SET last_error = 'upstream_unavailable' WHERE account_id = ?1").await;
    assert_eq!(fx.tick().await.stalled, vec!["info"], "a failing backfill measured from enabled_at");
    assert_eq!(fx.pushes().await[0]["body"], "info has not synced for 5 h");

    fx.h.app()
        .store
        .call(|c| Ok(c.execute("UPDATE accounts SET status = 'reauth_required' WHERE alias = 'info'", [])?))
        .await
        .unwrap();
    assert!(fx.tick().await.stalled.is_empty(), "reauth has its own alert");
}

/// With a polling interval longer than the threshold, a lag between two polls is not a stall.
#[tokio::test]
async fn a_long_polling_interval_raises_the_threshold() {
    let fx = setup_with(|c| c.index.poll_interval_secs = 3 * 3600).await;
    let four_h_ago = util::now_unix() - 4 * 3600;
    fx.sync_state(&format!("UPDATE sync_state SET last_success_at = {four_h_ago} WHERE account_id = ?1")).await;
    assert!(fx.tick().await.stalled.is_empty());
    let ten_h_ago = util::now_unix() - 10 * 3600;
    fx.sync_state(&format!("UPDATE sync_state SET last_success_at = {ten_h_ago} WHERE account_id = ?1")).await;
    assert_eq!(fx.tick().await.stalled, vec!["info"]);
}

#[tokio::test]
async fn low_disk_alerts_once_and_clears_above_the_upper_mark() {
    let fx = setup().await;
    let at = |free: u64| health::tick_with(fx.h.app(), util::now_unix(), Some(free));
    assert!(at(LOW_DISK_BYTES - (1 << 20)).await.unwrap().disk_low);
    let p = fx.pushes().await;
    assert_eq!((p.len(), p[0]["title"].as_str()), (1, Some("Dove: disk almost full")), "{p:?}");
    assert_eq!(p[0]["body"], "1023 MiB free for Dove's data");
    assert_eq!(p[0]["url"], "/admin/health");

    assert!(at(LOW_DISK_BYTES + (1 << 29)).await.unwrap().disk_low, "between the marks it stays low");
    assert!(at(LOW_DISK_BYTES - (1 << 20)).await.unwrap().disk_low);
    assert!(fx.pushes().await.is_empty(), "no repeat while it stays low");

    assert!(!at(2 << 30).await.unwrap().disk_low, "cleared at the upper mark");
    assert!(!at(LOW_DISK_BYTES + (1 << 29)).await.unwrap().disk_low, "between the marks after clearing");
    assert!(at(1 << 20).await.unwrap().disk_low);
    assert_eq!(fx.pushes().await.len(), 1, "low again after clearing alerts again");
}

/// The reauth alert reaches the phone and names the alias only: no address, no Google text.
#[tokio::test]
async fn reauth_pushes_the_alias_without_the_address() {
    let fx = setup().await;
    // A second mailbox: `info` has a cached access token from the sync in `setup`.
    fx.h.mailbox("billing", "billing@acme.test");
    fx.h.project("p", &["billing"]).await;
    let token = fx.h.token("p", "agent", vec![g("billing", "read")]).await;
    fx.h.google.invalidate_refresh_tokens("billing@acme.test");
    assert_eq!(
        fx.h.err(&token, "get_message", json!({"account": "billing", "message_id": "x"})).await,
        "account_unavailable"
    );
    let p = fx.pushes().await;
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0]["title"], "Dove: reconnect a mailbox");
    assert_eq!(p[0]["body"], "billing needs to be reconnected");
    assert_eq!(p[0]["url"], "/admin/mailboxes/billing");
    let raw = p[0].to_string();
    assert!(!raw.contains('@') && !raw.contains("acme"), "{raw}");
}

/// Alerts are queued only for devices that exist: without one, nothing is waiting in the outbox.
#[tokio::test]
async fn without_devices_alerts_go_to_the_log_only() {
    let fx = setup().await;
    let devices = fx.h.admin(AdminRequest::PushList).await.unwrap();
    let id = devices[0]["id"].as_str().unwrap().to_string();
    fx.h.admin(AdminRequest::PushRemove { id }).await.unwrap();
    health::tick_with(fx.h.app(), util::now_unix(), Some(1)).await.unwrap();
    let rows: i64 =
        fx.h.app()
            .store
            .call(|c| Ok(c.query_row("SELECT count(*) FROM push_outbox", [], |r| r.get(0))?))
            .await
            .unwrap();
    assert_eq!(rows, 0);
    assert!(fx.h.app().notifier.sent.lock().unwrap().iter().any(|m| m.contains("MiB are free")));
}

#[tokio::test]
async fn the_health_page_shows_mailbox_sync_and_alert_reach() {
    let fx = setup().await;
    let three_h_ago = util::now_unix() - 3 * 3600 - 60;
    fx.sync_state(&format!(
        "UPDATE sync_state SET last_success_at = {three_h_ago}, last_error = 'upstream_unavailable' \
         WHERE account_id = ?1"
    ))
    .await;
    let mut b = Browser::new(&fx.h);
    let mut a = ui::enrol(&fx.h, &mut b, "owner").await;
    ui::login(&mut b, &mut a).await;
    let page = b.get("/admin/health").await;
    assert_eq!(page.status, 200);
    for want in [
        "<h2>Mailboxes</h2>",
        "href=\"/admin/mailboxes/info\"",
        "Not syncing",
        "synced 3 h ago",
        "last error: upstream_unavailable",
        "1 device",
        "data dir free",
    ] {
        assert!(page.text.contains(want), "missing {want:?}");
    }
}

/// The new-address alert compares networks (IPv4 /16, IPv6 /32), not single addresses, and pushes at most once per
/// connection a day (PLAN A84): hosted connectors call from rotating addresses inside a few large blocks.
#[tokio::test]
async fn a_new_network_alerts_at_most_once_a_day_per_connection() {
    let fx = setup().await;
    fx.h.project("p", &["info"]).await;
    let token = fx.h.token("p", "cc", vec![g("info", "read")]).await;
    let secret = fx.h.app().proxy_secret.as_ref().unwrap().to_string();
    let store = fx.h.app().store.clone();
    let recorded = |key: &'static str| {
        let store = store.clone();
        async move {
            store
                .call(move |c| {
                    Ok(c.query_row("SELECT count(*) FROM notifications WHERE key = ?1", [key], |r| r.get::<_, i64>(0))?)
                })
                .await
                .unwrap()
                == 1
        }
    };
    let from = |ip: &'static str| {
        let (h, token, secret) = (&fx.h, token.clone(), secret.clone());
        async move {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
            let r = h.post_mcp(Some(&token), body, &[("x-forwarded-for", ip), ("x-dove-proxy-auth", &secret)]).await;
            assert_eq!(r.status(), 200);
        }
    };
    // The alert is written by a spawned task; wait for its record.
    let settle = |key: &'static str| {
        let recorded = &recorded;
        async move {
            for _ in 0..100 {
                if recorded(key).await {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            panic!("{key} was never recorded");
        }
    };

    from("160.79.104.5").await;
    from("160.79.111.200").await;
    from("160.79.104.6").await;
    assert!(fx.pushes().await.is_empty(), "rotation inside one network");
    assert!(fx.h.app().notifier.sent.lock().unwrap().is_empty());

    from("203.0.113.7").await;
    settle("newnet:cc:203.0.0.0/16").await;
    let p = fx.pushes().await;
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(
        (p[0]["title"].as_str(), p[0]["body"].as_str()),
        (Some("Dove: new network"), Some("cc was used from a new network"))
    );
    assert_eq!(p[0]["url"], "/admin/connections/cc");
    assert!(!p.iter().any(|v| v.to_string().contains("203.0.")), "{p:?}");

    // A second new network the same day is recorded but not pushed, and never pushes later.
    from("198.51.100.1").await;
    settle("newnet:cc:198.51.0.0/16").await;
    assert!(fx.pushes().await.is_empty());
    assert_eq!(fx.h.app().notifier.sent.lock().unwrap().len(), 1);
    store
        .call(|c| {
            Ok(c.execute(
                "UPDATE notifications SET last_sent_at = last_sent_at - 86400 WHERE key = 'limit:newnet:cc'",
                [],
            )?)
        })
        .await
        .unwrap();
    from("198.51.7.7").await;
    from("203.0.1.1").await;
    assert!(fx.pushes().await.is_empty(), "networks already seen stay quiet");

    // A day later a new network pushes again.
    from("192.0.2.1").await;
    settle("newnet:cc:192.0.0.0/16").await;
    assert_eq!(fx.pushes().await.len(), 1);
}
