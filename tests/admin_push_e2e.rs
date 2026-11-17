//! Web Push to the owner's devices (design 2026-11-16, PLAN A76): the admin UI subscribes a browser, a new agent
//! request pushes an encrypted, content-free notification to every device through a fake push service that decrypts
//! like a browser, and failures retry, expire or remove the device.

mod support;

use dove::admin::AdminRequest;
use std::sync::atomic::Ordering;

use dove::push;
use dove::util;
use serde_json::{Value, json};
use support::admin_ui::{self as ui, Browser, ORIGIN};
use support::harness::{Harness, g};
use support::push::{Device, PushService};

struct Fx {
    h: Harness,
    svc: PushService,
    token: String,
}

/// Admin UI on, Gmail mailboxes `info` and `billing` in project `acme`, a token `agent` with `info=read`, and a fake
/// push service the gateway may reach.
async fn setup() -> Fx {
    let h = ui::start().await;
    h.app().google.gateway().allow_loopback_push_for_tests();
    h.mailbox("info", "info@acme.test");
    h.mailbox("billing", "billing@acme.test");
    h.project("acme", &["info", "billing"]).await;
    let token = h.token("acme", "agent", vec![g("info", "read")]).await;
    Fx { h, svc: PushService::start().await, token }
}

impl Fx {
    async fn add(&self, name: &str, d: &Device) -> Result<Value, String> {
        self.h.admin(AdminRequest::PushAdd { name: name.into(), subscription: d.subscription(&self.svc) }).await
    }

    async fn ask_access(&self) -> String {
        let v = self
            .h
            .ok(&self.token, "request_access", json!({ "grants": [{ "account": "billing", "actions": "read" }] }))
            .await;
        v["request_id"].as_str().unwrap().to_string()
    }

    async fn deliver(&self) -> push::Report {
        push::deliver_due(self.h.app(), util::now_unix()).await.unwrap()
    }

    async fn exec(&self, sql: &'static str) {
        self.h.app().store.call(move |c| Ok(c.execute_batch(sql)?)).await.unwrap();
    }

    async fn i64(&self, sql: &'static str) -> i64 {
        self.h.app().store.call(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?)).await.unwrap()
    }

    async fn devices(&self) -> Vec<Value> {
        self.h.admin(AdminRequest::PushList).await.unwrap().as_array().unwrap().clone()
    }
}

#[tokio::test]
async fn a_new_request_pushes_to_every_device_encrypted_and_content_free() {
    let fx = setup().await;
    let (phone, laptop) = (Device::new(1), Device::new(2));
    // One device through the admin UI as admin.js sends it, one over the admin socket.
    let mut b = Browser::new(&fx.h);
    let mut a = ui::enrol(&fx.h, &mut b, "owner").await;
    ui::login(&mut b, &mut a).await;
    // Without any device the overview says so (PLAN A83).
    let over = b.get("/admin").await.text;
    assert!(over.contains("No device gets notifications"), "{over}");
    let page = b.get("/admin/settings").await;
    let key = push::public_key(fx.h.app()).await.unwrap();
    assert!(page.text.contains(&format!("data-push-key=\"{key}\"")), "the settings page carries the VAPID key");
    // A new device learns of every request, so registering one needs the passkey (PLAN A83).
    let r = b.post_json("/admin/settings/push", json!({ "name": "phone", "subscription": phone.json(&fx.svc) })).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let s = r.json()["stepup"].clone();
    assert!(s.is_object(), "{}", r.text);
    assert!(fx.devices().await.is_empty(), "nothing registered before the confirmation");
    let ch = ui::b64d(&s["publicKey"]["challenge"]);
    let r = ui::stepup_finish(&mut b, &s["id"], &a.assert(&ch)).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.json()["redirect"], "/admin/settings?done=push_on#notifications");
    fx.add("laptop", &laptop).await.unwrap();
    let page = b.get("/admin/settings").await;
    assert!(page.text.contains("phone") && page.text.contains("laptop"), "both devices are listed");
    // Each device row and the lost-subscription notice carry the endpoint fingerprint admin.js compares with.
    let fp = |d: &Device| {
        let e = d.subscription(&fx.svc).endpoint;
        util::b64url(&aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, e.as_bytes()).as_ref()[..12])
    };
    assert!(page.text.contains(&format!("data-fingerprint=\"{}\"", fp(&phone))), "{}", page.text);
    let over = b.get("/admin").await.text;
    assert!(!over.contains("No device gets notifications"));
    let lost = over.split("data-fingerprints=\"").nth(1).unwrap().split('"').next().unwrap();
    let mut got: Vec<&str> = lost.split(' ').collect();
    got.sort();
    let mut want = vec![fp(&phone), fp(&laptop)];
    want.sort();
    assert_eq!(got, want);

    let id = fx.ask_access().await;
    let report = fx.deliver().await;
    assert_eq!((report.attempted, report.delivered), (2, 2), "{report:?}");
    let hits = fx.svc.hits();
    assert_eq!(hits.len(), 2);
    for (dev, name) in [(&phone, "phone"), (&laptop, "laptop")] {
        let (_, headers, body) = hits.iter().find(|(p, _, _)| *p == dev.path).unwrap_or_else(|| panic!("{name}"));
        let plain = dev.open(body);
        assert_eq!(plain.len(), push::PAYLOAD_SIZE, "fixed size: the length tells nothing");
        let v: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(v["title"], "Dove: approval needed");
        assert_eq!(v["body"], "agent asks for access to billing");
        assert_eq!(v["url"], format!("/admin/requests/{id}"));
        assert_eq!(v["tag"], id);
        assert_eq!(v["badge"], 1, "the app badge counts open requests");
        let text = String::from_utf8(plain).unwrap();
        assert!(!text.contains('@'), "no address reaches the lock screen: {text}");
        let hv = |n: &str| headers.get(n).unwrap().to_str().unwrap().to_string();
        assert_eq!(
            (hv("ttl"), hv("urgency"), hv("content-encoding")),
            ("86400".into(), "high".into(), "aes128gcm".into())
        );
        // RFC 8292: a JWT for the push service's origin, signed with the key the browser subscribed with.
        let auth = hv("authorization");
        let (jwt, k) = auth.strip_prefix("vapid t=").unwrap().split_once(", k=").unwrap();
        assert_eq!(k, key);
        let parts: Vec<&str> = jwt.split('.').collect();
        let claims: Value = serde_json::from_slice(&util::b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], fx.svc.base);
        assert_eq!(claims["sub"], ORIGIN);
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
            util::b64url_decode(&key).unwrap(),
        )
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &util::b64url_decode(parts[2]).unwrap())
        .expect("valid VAPID signature");
    }
    // Delivered once: the next pass sends nothing, and both devices show a delivery.
    assert_eq!(fx.deliver().await.attempted, 0);
    assert_eq!(fx.svc.hits().len(), 2);
    assert!(fx.devices().await.iter().all(|d| d["last_delivered_at"].is_string() && d["failures"] == 0));
    // The audit log names the device, never the endpoint.
    let audit = fx.h.admin(AdminRequest::AuditTail { limit: Some(50) }).await.unwrap().to_string();
    assert!(audit.contains("push.add") && !audit.contains("/push/dev"), "{audit}");
}

#[tokio::test]
async fn a_send_request_names_the_mailbox_and_count() {
    let fx = setup().await;
    let d = Device::new(3);
    fx.add("phone", &d).await.unwrap();
    // Request text is built at delivery; check it directly for a send request with two items.
    let id = fx.ask_access().await;
    fx.h.app()
        .store
        .call({
            let id = id.clone();
            move |c| {
                c.execute("UPDATE requests SET kind = 'send', account_id = (SELECT id FROM accounts WHERE alias = 'info') WHERE id = ?1", [&id])?;
                for idx in 0..2 {
                    c.execute(
                        "INSERT INTO request_items(request_id, idx, draft_id, requested_rev, send_at, state, updated_at) \
                         VALUES (?1, ?2, 'd', 'r', 0, 'pending', 0)",
                        rusqlite::params![id, idx],
                    )?;
                }
                Ok(())
            }
        })
        .await
        .unwrap();
    fx.deliver().await;
    let (_, _, body) = fx.svc.hits().pop().unwrap();
    let v: Value = serde_json::from_slice(&d.open(&body)).unwrap();
    assert_eq!(v["body"], "agent wants to send 2 mails from info");
}

#[tokio::test]
async fn a_request_decided_before_delivery_is_not_pushed() {
    let fx = setup().await;
    fx.add("phone", &Device::new(4)).await.unwrap();
    let id = fx.ask_access().await;
    fx.h.admin(AdminRequest::RequestsDeny { id }).await.unwrap();
    let r = fx.deliver().await;
    assert_eq!((r.attempted, r.skipped), (1, 1), "{r:?}");
    assert!(fx.svc.hits().is_empty());
}

#[tokio::test]
async fn errors_retry_and_a_gone_subscription_removes_the_device() {
    let fx = setup().await;
    fx.add("phone", &Device::new(5)).await.unwrap();
    fx.ask_access().await;
    fx.svc.set(503);
    let r = fx.deliver().await;
    assert_eq!(r.retrying, 1, "{r:?}");
    assert_eq!(fx.i64("SELECT attempts FROM push_outbox WHERE state = 'pending'").await, 1);
    // Not due yet: nothing is sent again before the backoff.
    assert_eq!(fx.deliver().await.attempted, 0);
    fx.exec("UPDATE push_outbox SET next_attempt_at = 0").await;
    fx.svc.set(410);
    let r = fx.deliver().await;
    assert_eq!(r.devices_removed, 1, "{r:?}");
    assert!(fx.devices().await.is_empty(), "410: the device is gone, with its queued pushes");
    assert_eq!(fx.i64("SELECT count(*) FROM push_outbox").await, 0);
    assert_eq!(fx.svc.hits().len(), 2);
}

#[tokio::test]
async fn a_refusal_fails_at_once_and_old_pushes_expire() {
    let fx = setup().await;
    fx.add("phone", &Device::new(6)).await.unwrap();
    fx.ask_access().await;
    fx.svc.set(403);
    let r = fx.deliver().await;
    assert_eq!(r.failed, 1, "{r:?}");
    let d = &fx.devices().await[0];
    assert_eq!((d["last_status"].as_i64(), d["failures"].as_i64()), (Some(403), Some(1)));
    // A push that could not go out within the TTL is dropped instead of arriving a day late.
    fx.svc.set(201);
    fx.ask_access().await;
    fx.exec("UPDATE push_outbox SET created_at = created_at - 86400, next_attempt_at = 0 WHERE state = 'pending'")
        .await;
    assert_eq!(fx.deliver().await.attempted, 0);
    assert_eq!(fx.svc.hits().len(), 1);
}

#[tokio::test]
async fn subscriptions_are_checked_and_bounded() {
    let fx = setup().await;
    let d = Device::new(7);
    let mut foreign = d.subscription(&fx.svc);
    foreign.endpoint = "https://push.evil.example/x".into();
    let e = fx.h.admin(AdminRequest::PushAdd { name: "x".into(), subscription: foreign }).await.unwrap_err();
    assert!(e.contains("not on a known push service"), "{e}");
    let mut bad_key = d.subscription(&fx.svc);
    bad_key.keys.p256dh = util::b64url(&[4u8; 65]);
    assert!(fx.h.admin(AdminRequest::PushAdd { name: "x".into(), subscription: bad_key }).await.is_err());
    assert!(fx.add("a\u{7}b", &d).await.is_err(), "control characters in the name");

    // Re-subscribing the same endpoint renames the device instead of adding one.
    fx.add("old name", &d).await.unwrap();
    fx.add("phone", &d).await.unwrap();
    let list = fx.devices().await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "phone");
    for n in 0..(push::MAX_DEVICES - 1) {
        fx.add(&format!("d{n}"), &Device::new(20 + n as u8)).await.unwrap();
    }
    let e = fx.add("one too many", &Device::new(99)).await.unwrap_err();
    assert!(e.contains("16 devices"), "{e}");
    // A known device still refreshes at the limit.
    fx.add("phone again", &d).await.unwrap();

    // The UI route needs a session and the CSRF token, like every write.
    let mut anon = Browser::new(&fx.h);
    let r = anon.post_json("/admin/settings/push", json!({ "name": "x", "subscription": d.json(&fx.svc) })).await;
    assert_eq!(r.status, 401);
    let mut b = Browser::new(&fx.h);
    let mut a = ui::enrol(&fx.h, &mut b, "owner").await;
    ui::login(&mut b, &mut a).await;
    b.get("/admin/settings").await;
    b.csrf = Some("wrong".into());
    let r = b.post_json("/admin/settings/push", json!({ "name": "x", "subscription": d.json(&fx.svc) })).await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn test_notification_and_removal_from_the_settings_page() {
    let fx = setup().await;
    let d = Device::new(8);
    let added = fx.add("phone", &d).await.unwrap();
    let id = added["id"].as_str().unwrap().to_string();
    let mut b = Browser::new(&fx.h);
    let mut a = ui::enrol(&fx.h, &mut b, "owner").await;
    ui::login(&mut b, &mut a).await;
    b.get("/admin/settings").await;
    let r = b.post_form(&format!("/admin/settings/push/{id}/test"), &[]).await;
    assert_eq!(r.header("location"), "/admin/settings?done=push_sent#notifications", "{}", r.text);
    let (_, _, body) = fx.svc.hits().pop().unwrap();
    let v: Value = serde_json::from_slice(&d.open(&body)).unwrap();
    assert_eq!((v["title"].as_str(), v["url"].as_str()), (Some("Dove"), Some("/admin/settings")));

    fx.svc.set(400);
    let r = b.post_form(&format!("/admin/settings/push/{id}/test"), &[]).await;
    assert_eq!(r.header("location"), "/admin/settings?done=push_failed#notifications");

    let r = b.post_form(&format!("/admin/settings/push/{id}/remove"), &[]).await;
    assert_eq!(r.header("location"), "/admin/settings?done=push_off#notifications");
    assert!(fx.devices().await.is_empty());
    let e = fx.h.admin(AdminRequest::PushTest { id: None }).await.unwrap_err();
    assert!(e.contains("no device"), "{e}");
}

#[tokio::test]
async fn the_app_files_are_public_and_signed_out_links_come_back() {
    let fx = setup().await;
    let mut anon = Browser::new(&fx.h);
    let sw = anon.get("/admin/sw.js").await;
    assert_eq!(sw.status, 200);
    assert_eq!(sw.header("service-worker-allowed"), "/admin");
    assert!(sw.header("content-type").starts_with("text/javascript"));
    assert!(sw.text.contains("showNotification") && sw.text.contains("setAppBadge"));
    // The worker caches exactly the offline page and the current assets, under the asset version (PLAN A83).
    assert!(!sw.text.contains("__VERSION__") && !sw.text.contains("__OFFLINE__"), "{}", sw.text);
    let v = dove::admin_ui::asset_version();
    assert!(sw.text.contains(&format!("\"{v}\"")), "{}", sw.text);
    let list = serde_json::to_string(&dove::admin_ui::offline_assets()).unwrap();
    assert!(sw.text.contains(&list), "{}", sw.text);
    for asset in dove::admin_ui::offline_assets() {
        let r = anon.get(&asset).await;
        assert_eq!(r.status, 200, "{asset} is public, or the worker cannot install");
    }
    let off = anon.get("/admin/offline").await;
    assert!(off.text.contains("No connection") && !off.text.contains("dove-csrf"), "{}", off.text);
    let m = anon.get("/admin/manifest.webmanifest").await;
    assert_eq!(m.header("content-type"), "application/manifest+json");
    assert_eq!(m.json()["scope"], "/admin");
    let urls: Vec<String> =
        m.json()["shortcuts"].as_array().unwrap().iter().map(|s| s["url"].as_str().unwrap().to_string()).collect();
    assert_eq!(urls, ["/admin/requests", "/admin/settings"]);
    for icon in ["/admin/static/icon-192.png", "/admin/static/icon-512.png"] {
        let r = anon.get(icon).await;
        assert_eq!((r.status, r.header("content-type").as_str()), (200, "image/png"), "{icon}");
    }
    // A notification opens a request page; signed out, the sign-in page brings the browser back there.
    let r = anon.get("/admin/requests/r_abc-1").await;
    assert_eq!(r.header("location"), "/admin/login?next=/admin/requests/r_abc-1");
    for odd in ["/admin/requests/a.b", "/admin/requests/x%2Fy"] {
        let r = anon.get(odd).await;
        assert_eq!(r.header("location"), "/admin/login", "{odd}");
    }
    assert!(dove::admin_ui::safe_next("/admin") && dove::admin_ui::safe_next("/admin/requests/r_1"));
    for bad in ["/admin/", "/admin/../x", "/admin/x?y", "/adminx", "//evil", "/admin/%2e"] {
        assert!(!dove::admin_ui::safe_next(bad), "{bad}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn keys_rotate_rewraps_push_secrets() {
    use std::os::unix::fs::PermissionsExt;
    let mut fx = setup().await;
    let d = Device::new(9);
    fx.add("phone", &d).await.unwrap();
    let key = push::public_key(fx.h.app()).await.unwrap();
    let kek = fx.h.app().cfg.secrets.kek_file.clone();
    let mut text = std::fs::read_to_string(&kek).unwrap();
    text.push('\n');
    text.push_str(&dove::secrets::generate_key_line(2));
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&kek, text).unwrap();
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o400)).unwrap();
    fx.h.restart().await;
    fx.h.app().google.gateway().allow_loopback_push_for_tests();
    let v = fx.h.admin(AdminRequest::KeysRotate).await.unwrap();
    // Two Gmail grants, one subscription, the VAPID key.
    assert_eq!(v["rewrapped"], 4, "{v}");
    assert_eq!(v["versions_in_use"], json!([2]));
    // Same VAPID key afterwards (browsers stay subscribed), and the device still gets pushes.
    assert_eq!(push::public_key(fx.h.app()).await.unwrap(), key);
    fx.h.admin(AdminRequest::PushTest { id: None }).await.unwrap();
    let (_, _, body) = fx.svc.hits().pop().unwrap();
    d.open(&body);
}

#[tokio::test]
async fn the_gateway_posts_pushes_only_to_known_push_services() {
    let fx = setup().await;
    let gw = fx.h.app().google.gateway();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let before = gw.calls.load(Ordering::SeqCst);
    for url in ["https://push.evil.example/x", "https://web.push.apple.com.evil.example/x", "http://10.1.2.3/x"] {
        let r = gw.post_push(url, &[], vec![], deadline).await;
        assert!(matches!(r, Err(dove::gmail::gateway::GatewayError::NotAllowed)), "{url}");
    }
    assert_eq!(gw.calls.load(Ordering::SeqCst), before, "nothing was dispatched");
    // A stored subscription that no longer checks out fails without a request.
    fx.add("phone", &Device::new(10)).await.unwrap();
    fx.exec("UPDATE push_devices SET subscription_sealed = x'00000001'").await;
    fx.h.admin(AdminRequest::PushTest { id: None }).await.unwrap();
    assert!(fx.svc.hits().is_empty());
}
