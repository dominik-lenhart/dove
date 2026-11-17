//! Web Push to the owner's devices (design 2026-11-16 "admin push", PLAN A76).
//!
//! The admin UI's settings page subscribes a browser (`PushManager.subscribe` with Dove's VAPID key) and hands the
//! subscription to [`admin_add`]. Dove queues one [`push_outbox`](crate::store::schema) row per device for every new
//! agent request ([`queue_request`]) and for test notifications; [`deliver_due`] (every [`POLL`], see [`start`])
//! encrypts each payload for its device (RFC 8291, [`ece`]), signs a VAPID JWT (RFC 8292) and POSTs it through
//! `gmail::gateway::Gateway::post_push`, which only reaches the known push services ([`SERVICES`]).
//!
//! Push is availability only. The payload names the connection and the kind of request (owner's choice 2026-11-16),
//! never an address, subject, note or draft text, because the push service and the lock screen see it. A lost,
//! delayed or forged push approves nothing: tapping the notification opens the request page, where approval needs a
//! passkey as before. The subscription (endpoint and keys) and the VAPID private key are sealed with the vault.

pub mod ece;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::admin::server::AdminCall;
use crate::app::App;
use crate::gmail::gateway::GatewayError;
use crate::util;
use crate::vault::Vault;

/// The push services browsers use (Safari, Chrome and Android, Firefox, Edge). A host matches exactly or as a
/// subdomain; anything else is refused at subscribe time and again by the gateway before each POST.
pub const SERVICES: &[(&str, &str)] = &[
    ("web.push.apple.com", "Apple"),
    ("fcm.googleapis.com", "Google"),
    ("push.services.mozilla.com", "Mozilla"),
    ("notify.windows.com", "Microsoft"),
];
/// Most devices one Dove pushes to.
pub const MAX_DEVICES: usize = 16;
/// Every payload is padded to this size, so its length says nothing about the request.
pub const PAYLOAD_SIZE: usize = 512;
/// Longest device name.
pub const MAX_NAME_CHARS: usize = 64;
const MAX_ENDPOINT: usize = 2048;
/// A push not delivered within this time is dropped (the push service keeps it this long for an offline device too).
pub const TTL_SECS: i64 = 86_400;
/// How often the delivery loop looks for due pushes.
pub const POLL: Duration = Duration::from_secs(5);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
const BATCH: i64 = 50;
/// Delivered and failed rows are kept this long (for `push list`), then deleted.
const KEEP_SECS: i64 = 7 * 86_400;
/// Retries after 429, 5xx and network errors.
pub const MAX_ATTEMPTS: i64 = 5;
const BACKOFF_SECS: [i64; 4] = [10, 60, 300, 1800];
/// Vault kinds: the sealed subscription of a device (scope: device id) and the VAPID key (scope: [`VAPID_META`]).
pub const SUBSCRIPTION_KIND: &str = "push_subscription";
pub const VAPID_KIND: &str = "vapid_key";
/// `meta` key of the sealed VAPID private key (PKCS#8, base64url of the vault blob).
pub const VAPID_META: &str = "vapid_key_sealed";

/// In-memory state: one delivery pass at a time (the loop and a test notification can both start one).
#[derive(Default)]
pub struct Runtime {
    delivery: tokio::sync::Mutex<()>,
}

// ------------------------------------------------------------------ endpoints and subscriptions

/// A push endpoint Dove may POST to: https on a known push service, default port, no credentials or fragment.
/// Test builds can also allow plain http to a loopback address (`Gateway::allow_loopback_push_for_tests`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint(url::Url);

impl Endpoint {
    pub fn parse(s: &str, loopback_for_tests: bool) -> Result<Self, String> {
        if s.len() > MAX_ENDPOINT {
            return Err("the endpoint is too long".into());
        }
        let u = url::Url::parse(s).map_err(|_| "not a valid URL".to_string())?;
        if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
            return Err("the endpoint must not carry credentials or a fragment".into());
        }
        let loopback = matches!(u.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
            || matches!(u.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
        if loopback_for_tests && u.scheme() == "http" && loopback {
            return Ok(Self(u));
        }
        let known = matches!(u.host(), Some(url::Host::Domain(_))) && service_label(&u).is_some();
        if u.scheme() != "https" || u.port().is_some() || !known {
            return Err("the endpoint is not on a known push service".into());
        }
        Ok(Self(u))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// `scheme://host[:port]`, the VAPID `aud` claim.
    pub fn audience(&self) -> String {
        self.0.origin().ascii_serialization()
    }

    /// Which push service this is, for the device list ("Apple", "Google", ...).
    pub fn service(&self) -> &'static str {
        service_label(&self.0).unwrap_or("test")
    }
}

fn service_label(u: &url::Url) -> Option<&'static str> {
    let host = u.host_str()?.to_ascii_lowercase();
    SERVICES.iter().find(|(s, _)| host == *s || host.ends_with(&format!(".{s}"))).map(|(_, l)| *l)
}

/// One browser subscription as `PushSubscription.toJSON()` gives it. `Debug` hides the endpoint (a capability URL)
/// and the keys.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    pub endpoint: String,
    pub keys: SubscriptionKeys,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionKeys {
    pub p256dh: String,
    pub auth: String,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Subscription([redacted])")
    }
}

/// A checked subscription: endpoint, the browser's P-256 key and its 16-byte auth secret.
#[derive(Debug)]
pub struct Target {
    pub endpoint: Endpoint,
    pub public: Vec<u8>,
    pub auth: [u8; 16],
}

impl Subscription {
    pub fn check(&self, loopback_for_tests: bool) -> Result<Target, String> {
        let endpoint = Endpoint::parse(&self.endpoint, loopback_for_tests)?;
        let public = util::b64url_decode(&self.keys.p256dh).ok_or("the p256dh key is not base64url")?;
        if !ece::valid_public_key(&public) {
            return Err("the p256dh key is not a P-256 public key".into());
        }
        let auth: [u8; 16] = util::b64url_decode(&self.keys.auth)
            .and_then(|a| a.try_into().ok())
            .ok_or("the auth secret must be 16 bytes of base64url")?;
        Ok(Target { endpoint, public, auth })
    }
}

fn endpoint_hash(endpoint: &str) -> Vec<u8> {
    Sha256::digest(endpoint.as_bytes()).to_vec()
}

/// A device name: 1 to [`MAX_NAME_CHARS`] characters, no control characters, trimmed.
pub fn clean_name(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        bail!("a device name has 1 to {MAX_NAME_CHARS} characters and no control characters");
    }
    Ok(name.to_string())
}

// ------------------------------------------------------------------ VAPID

/// Dove's VAPID key (RFC 8292), ES256.
pub struct Vapid {
    key: EcdsaKeyPair,
}

impl std::fmt::Debug for Vapid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vapid").field("public", &self.public_b64()).finish_non_exhaustive()
    }
}

impl Vapid {
    fn from_pkcs8(der: &[u8]) -> anyhow::Result<Self> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .map_err(|_| anyhow!("the stored VAPID key is not a P-256 PKCS#8 key"))?;
        Ok(Self { key })
    }

    /// The `applicationServerKey` browsers subscribe with (uncompressed point, base64url).
    pub fn public_b64(&self) -> String {
        util::b64url(self.key.public_key().as_ref())
    }

    /// `Authorization: vapid t=<JWT>, k=<key>` for one endpoint. `subject` is the admin UI's https origin.
    pub fn authorization(&self, endpoint: &Endpoint, subject: &str, now: i64) -> anyhow::Result<String> {
        let header = util::b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = util::b64url(
            json!({ "aud": endpoint.audience(), "exp": now + 12 * 3600, "sub": subject }).to_string().as_bytes(),
        );
        let input = format!("{header}.{claims}");
        let sig = self.key.sign(&SystemRandom::new(), input.as_bytes()).map_err(|_| anyhow!("cannot sign"))?;
        Ok(format!("vapid t={input}.{}, k={}", util::b64url(sig.as_ref()), self.public_b64()))
    }
}

/// Loads the VAPID key, creating and sealing it on first use. Runs on the state store connection.
pub fn vapid(c: &Connection, vault: &Vault) -> anyhow::Result<Vapid> {
    if let Some(stored) = crate::store::get_meta(c, VAPID_META)? {
        let blob = util::b64url_decode(&stored).ok_or_else(|| anyhow!("the stored VAPID key is not base64url"))?;
        let der = vault.open_aux(VAPID_KIND, VAPID_META, &blob)?;
        return Vapid::from_pkcs8(&der);
    }
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .map_err(|_| anyhow!("cannot generate the VAPID key"))?;
    let sealed = vault.seal_aux(VAPID_KIND, VAPID_META, doc.as_ref())?;
    crate::store::set_meta(c, VAPID_META, &util::b64url(&sealed))?;
    Vapid::from_pkcs8(doc.as_ref())
}

/// The VAPID public key for the settings page (created on first use).
pub async fn public_key(app: &Arc<App>) -> anyhow::Result<String> {
    let vault = app.vault.clone();
    app.store.call(move |c| Ok(vapid(c, &vault)?.public_b64())).await
}

/// The VAPID `sub` claim: the admin UI's origin (Apple requires an https URL or a mailto).
fn subject(app: &App) -> anyhow::Result<String> {
    app.cfg
        .admin_ui
        .origin()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("push needs the admin UI: set [admin_ui] enabled = true and origin in the config file"))
}

// ------------------------------------------------------------------ key rotation

/// Re-seals the device subscriptions and the VAPID key under the current KEK version (`dove keys rotate`).
pub fn rewrap_sealed(c: &Connection, vault: &Vault) -> anyhow::Result<usize> {
    let current = vault.current_kek_version();
    let mut n = 0;
    let rows: Vec<(String, Vec<u8>)> = {
        let mut st = c.prepare("SELECT id, subscription_sealed FROM push_devices")?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
    };
    for (id, blob) in rows {
        if blob_version(&blob) == Some(current) {
            continue;
        }
        let plain = vault.open_aux(SUBSCRIPTION_KIND, &id, &blob)?;
        let sealed = vault.seal_aux(SUBSCRIPTION_KIND, &id, &plain)?;
        c.execute("UPDATE push_devices SET subscription_sealed = ?1 WHERE id = ?2", params![sealed, id])?;
        n += 1;
    }
    if let Some(stored) = crate::store::get_meta(c, VAPID_META)? {
        let blob = util::b64url_decode(&stored).ok_or_else(|| anyhow!("the stored VAPID key is not base64url"))?;
        if blob_version(&blob) != Some(current) {
            let der = vault.open_aux(VAPID_KIND, VAPID_META, &blob)?;
            let sealed = vault.seal_aux(VAPID_KIND, VAPID_META, &der)?;
            crate::store::set_meta(c, VAPID_META, &util::b64url(&sealed))?;
            n += 1;
        }
    }
    Ok(n)
}

/// KEK versions still used by push subscriptions and the VAPID key.
pub fn sealed_versions(c: &Connection) -> anyhow::Result<Vec<u32>> {
    let mut out = Vec::new();
    let mut st = c.prepare("SELECT subscription_sealed FROM push_devices")?;
    let mut blobs: Vec<Vec<u8>> = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    if let Some(stored) = crate::store::get_meta(c, VAPID_META)?
        && let Some(b) = util::b64url_decode(&stored)
    {
        blobs.push(b);
    }
    for b in blobs {
        if let Some(v) = blob_version(&b)
            && !out.contains(&v)
        {
            out.push(v);
        }
    }
    Ok(out)
}

fn blob_version(b: &[u8]) -> Option<u32> {
    b.get(..4).map(|v| u32::from_be_bytes(v.try_into().expect("4 bytes")))
}

// ------------------------------------------------------------------ queueing

/// Queues a push about a new pending request for every device. Runs in the transaction that creates the request.
/// The text is built at delivery time ([`request_text`]), when the request's items exist.
pub fn queue_request(tx: &Connection, request_id: &str, now: i64) -> rusqlite::Result<usize> {
    tx.execute(
        "INSERT INTO push_outbox(device_id, kind, ref, state, attempts, next_attempt_at, created_at) \
         SELECT id, 'request', ?1, 'pending', 0, ?2, ?2 FROM push_devices",
        params![request_id, now],
    )
}

/// Queues a push with a fixed text for the given devices (all when `None`) and returns the new row ids.
pub fn queue_text(
    tx: &Connection,
    kind: &str,
    devices: Option<&[String]>,
    text: &Text,
    now: i64,
) -> rusqlite::Result<Vec<i64>> {
    let ids: Vec<String> = match devices {
        Some(d) => d.to_vec(),
        None => {
            let mut st = tx.prepare("SELECT id FROM push_devices ORDER BY created_at")?;
            st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
        }
    };
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        tx.execute(
            "INSERT INTO push_outbox(device_id, kind, title, body, url, state, attempts, next_attempt_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6)",
            params![id, kind, text.title, text.body, text.url, now],
        )?;
        rows.push(tx.last_insert_rowid());
    }
    Ok(rows)
}

/// What a notification shows. `url` is an admin UI path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text {
    pub title: String,
    pub body: String,
    pub url: String,
}

/// A label for the lock screen: control characters dropped, at most 40 characters.
pub(crate) fn label(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).collect();
    if s.chars().count() > 40 { format!("{}…", s.chars().take(39).collect::<String>()) } else { s }
}

/// The text of a request notification, or `None` when the request is gone or no longer pending. Names the
/// connection and what it asks for (mailbox aliases), never addresses, subjects, notes or draft content.
pub fn request_text(c: &Connection, request_id: &str) -> anyhow::Result<Option<Text>> {
    let row: Option<(String, String, String, Option<String>, String)> = c
        .query_row(
            "SELECT r.kind, r.status, cl.name, (SELECT a.alias FROM accounts a WHERE a.id = r.account_id), r.payload \
             FROM requests r JOIN clients cl ON cl.id = r.client_id WHERE r.id = ?1",
            [request_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((kind, status, client, alias, payload)) = row else { return Ok(None) };
    if status != "pending" {
        return Ok(None);
    }
    let client = label(&client);
    let body = if kind == "send" {
        let n: i64 =
            c.query_row("SELECT count(*) FROM request_items WHERE request_id = ?1", [request_id], |r| r.get(0))?;
        let what = if n == 1 { "a mail".to_string() } else { format!("{n} mails") };
        match alias {
            Some(a) => format!("{client} wants to send {what} from {}", label(&a)),
            None => format!("{client} wants to send {what}"),
        }
    } else {
        let p = crate::requests::access::Payload::parse(&payload).unwrap_or_default();
        let mut names: Vec<String> = Vec::new();
        for g in &p.grants {
            let a: Option<String> =
                c.query_row("SELECT alias FROM accounts WHERE id = ?1", [&g.account_id], |r| r.get(0)).optional()?;
            if let Some(a) = a.map(|a| label(&a))
                && !names.contains(&a)
            {
                names.push(a);
            }
        }
        match names.as_slice() {
            [] => format!("{client} asks for more access"),
            [a] => format!("{client} asks for access to {a}"),
            [a, b] => format!("{client} asks for access to {a} and {b}"),
            [a, rest @ ..] => format!("{client} asks for access to {a} and {} more", rest.len()),
        }
    };
    Ok(Some(Text { title: "Dove: approval needed".into(), body, url: format!("/admin/requests/{request_id}") }))
}

/// The plaintext of one push: `{title, body, url, tag}`, padded with spaces (still valid JSON) to [`PAYLOAD_SIZE`].
pub fn payload(text: &Text, tag: &str) -> Vec<u8> {
    let mut body = text.body.clone();
    loop {
        let p = json!({ "title": text.title, "body": body, "url": text.url, "tag": tag }).to_string().into_bytes();
        if p.len() <= PAYLOAD_SIZE || body.is_empty() {
            let mut p = p;
            p.resize(PAYLOAD_SIZE.max(p.len()), b' ');
            return p;
        }
        body.pop();
    }
}

// ------------------------------------------------------------------ delivery

/// What one [`deliver_due`] pass did.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Report {
    pub attempted: usize,
    pub delivered: usize,
    pub retrying: usize,
    pub failed: usize,
    pub skipped: usize,
    pub devices_removed: usize,
}

enum Outcome {
    Delivered(u16),
    Retry(Option<u16>),
    Fail(Option<u16>),
    /// The push service says the subscription is gone (404, 410): the device is removed.
    Gone(u16),
    /// Nothing to send (the request was decided meanwhile).
    Skip,
}

struct Due {
    row: i64,
    device: String,
    sealed: Vec<u8>,
    kind: String,
    reference: Option<String>,
    text: Option<Text>,
    attempts: i64,
}

/// Sends the pushes due at `now` (at most [`BATCH`] per pass), expires undeliverable ones and deletes old rows.
pub async fn deliver_due(app: &Arc<App>, now: i64) -> anyhow::Result<Report> {
    let _one = app.push.delivery.lock().await;
    let (due, vapid) = {
        let vault = app.vault.clone();
        app.store
            .call(move |c| {
                c.execute(
                    "UPDATE push_outbox SET state = 'failed' WHERE state = 'pending' AND created_at <= ?1",
                    [now - TTL_SECS],
                )?;
                c.execute("DELETE FROM push_outbox WHERE state != 'pending' AND created_at <= ?1", [now - KEEP_SECS])?;
                let mut st = c.prepare_cached(
                    "SELECT o.id, o.device_id, d.subscription_sealed, o.kind, o.ref, o.title, o.body, o.url, o.attempts \
                     FROM push_outbox o JOIN push_devices d ON d.id = o.device_id \
                     WHERE o.state = 'pending' AND o.next_attempt_at <= ?1 ORDER BY o.next_attempt_at, o.id LIMIT ?2",
                )?;
                let rows = st.query_map(params![now, BATCH], |r| {
                    let text = match (r.get::<_, Option<String>>(5)?, r.get::<_, Option<String>>(6)?, r.get(7)?) {
                        (Some(title), Some(body), Some(url)) => Some(Text { title, body, url }),
                        _ => None,
                    };
                    Ok(Due {
                        row: r.get(0)?,
                        device: r.get(1)?,
                        sealed: r.get(2)?,
                        kind: r.get(3)?,
                        reference: r.get(4)?,
                        text,
                        attempts: r.get(8)?,
                    })
                })?;
                let mut due: Vec<Due> = rows.collect::<Result<_, _>>()?;
                for d in &mut due {
                    if d.kind == "request"
                        && let Some(id) = &d.reference
                    {
                        d.text = request_text(c, id)?;
                    }
                }
                let vapid = if due.is_empty() { None } else { Some(vapid(c, &vault)?) };
                Ok((due, vapid))
            })
            .await?
    };
    let mut report = Report { attempted: due.len(), ..Default::default() };
    let Some(vapid) = vapid else { return Ok(report) };
    let subject = subject(app);
    let loopback = app.google.gateway().loopback_push();
    let mut results = Vec::with_capacity(due.len());
    for d in due {
        let outcome = match (&d.text, &subject) {
            (None, _) => Outcome::Skip,
            (Some(_), Err(_)) => Outcome::Fail(None),
            (Some(text), Ok(subject)) => {
                let tag = d.reference.clone().unwrap_or_else(|| format!("dove-{}", d.kind));
                send_one(app, &vapid, subject, loopback, &d, text, &tag, now).await
            }
        };
        match &outcome {
            Outcome::Delivered(_) => report.delivered += 1,
            Outcome::Retry(_) => report.retrying += 1,
            Outcome::Fail(_) => report.failed += 1,
            Outcome::Gone(_) => report.devices_removed += 1,
            Outcome::Skip => report.skipped += 1,
        }
        if let Outcome::Retry(s) | Outcome::Fail(s) = &outcome {
            tracing::warn!(device = %d.device, status = ?s, attempt = d.attempts + 1, "push delivery failed");
        }
        if let Outcome::Gone(s) = &outcome {
            tracing::info!(device = %d.device, status = s, "push subscription gone; device removed");
        }
        results.push((d.row, d.device, d.attempts, outcome));
    }
    app.store
        .call(move |c| {
            let tx = c.transaction()?;
            for (row, device, attempts, outcome) in results {
                let attempts = attempts + 1;
                let (state, status, next) = match outcome {
                    // The device's queued rows go with it (ON DELETE CASCADE).
                    Outcome::Gone(_) => {
                        tx.execute("DELETE FROM push_devices WHERE id = ?1", [&device])?;
                        continue;
                    }
                    Outcome::Skip => ("skipped", None, now),
                    Outcome::Delivered(s) => {
                        tx.execute(
                            "UPDATE push_devices SET last_ok_at = ?1, last_status = ?2, failures = 0 WHERE id = ?3",
                            params![now, s, device],
                        )?;
                        ("delivered", Some(s), now)
                    }
                    Outcome::Retry(s) if attempts < MAX_ATTEMPTS => {
                        ("pending", s, now + BACKOFF_SECS[(attempts as usize - 1).min(BACKOFF_SECS.len() - 1)])
                    }
                    Outcome::Retry(s) | Outcome::Fail(s) => {
                        tx.execute(
                            "UPDATE push_devices SET last_status = ?1, failures = failures + 1 WHERE id = ?2",
                            params![s, device],
                        )?;
                        ("failed", s, now)
                    }
                };
                tx.execute(
                    "UPDATE push_outbox SET state = ?1, attempts = ?2, last_status = ?3, next_attempt_at = ?4 \
                     WHERE id = ?5",
                    params![state, attempts, status, next, row],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)] // one push: its row, key, subject and text
async fn send_one(
    app: &Arc<App>,
    vapid: &Vapid,
    subject: &str,
    loopback: bool,
    d: &Due,
    text: &Text,
    tag: &str,
    now: i64,
) -> Outcome {
    let built = (|| -> anyhow::Result<(Endpoint, String, Vec<u8>)> {
        let plain = app.vault.open_aux(SUBSCRIPTION_KIND, &d.device, &d.sealed)?;
        let sub: Subscription = serde_json::from_slice(&plain)?;
        let t = sub.check(loopback).map_err(|e| anyhow!(e))?;
        let auth = vapid.authorization(&t.endpoint, subject, now)?;
        let body = ece::encrypt(&payload(text, tag), &t.public, &t.auth).map_err(|e| anyhow!(e))?;
        Ok((t.endpoint, auth, body))
    })();
    let (endpoint, auth, body) = match built {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(device = %d.device, error = %e, "push subscription unusable");
            return Outcome::Fail(None);
        }
    };
    let headers = [
        ("ttl", TTL_SECS.to_string()),
        ("urgency", "high".to_string()),
        ("content-encoding", "aes128gcm".to_string()),
        ("content-type", "application/octet-stream".to_string()),
        ("authorization", auth),
    ];
    match app.google.gateway().post_push(endpoint.as_str(), &headers, body, Instant::now() + DELIVERY_TIMEOUT).await {
        Ok(s) if (200..300).contains(&s) => Outcome::Delivered(s),
        Ok(s @ (404 | 410)) => Outcome::Gone(s),
        Ok(s) if s == 408 || s == 429 || s >= 500 => Outcome::Retry(Some(s)),
        Ok(s) => Outcome::Fail(Some(s)),
        Err(GatewayError::NotAllowed) => Outcome::Fail(None),
        Err(_) => Outcome::Retry(None),
    }
}

/// Starts the delivery loop (called from `dove serve`).
pub fn start(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = deliver_due(&app, util::now_unix()).await {
                tracing::warn!(error = %e, "push delivery pass failed");
            }
            tokio::time::sleep(POLL).await;
        }
    })
}

// ------------------------------------------------------------------ admin verbs

/// `PushAdd`: registers (or refreshes, same endpoint) a device. At most [`MAX_DEVICES`].
pub async fn admin_add(call: &mut AdminCall<'_>, name: String, sub: Subscription) -> anyhow::Result<Value> {
    let name = clean_name(&name)?;
    let loopback = call.app.google.gateway().loopback_push();
    let target = sub.check(loopback).map_err(|e| anyhow!("this push subscription cannot be used: {e}"))?;
    let service = target.endpoint.service();
    let hash = endpoint_hash(&sub.endpoint);
    let plain = serde_json::to_vec(&sub)?;
    let vault = call.app.vault.clone();
    let now = util::now_unix();
    call.tx(move |tx| {
        let existing: Option<String> =
            tx.query_row("SELECT id FROM push_devices WHERE endpoint_hash = ?1", [&hash], |r| r.get(0)).optional()?;
        let id = match existing {
            Some(id) => id,
            None => {
                let n: i64 = tx.query_row("SELECT count(*) FROM push_devices", [], |r| r.get(0))?;
                if n >= MAX_DEVICES as i64 {
                    bail!("Dove already pushes to {MAX_DEVICES} devices; remove one first");
                }
                format!("d_{}", util::new_id())
            }
        };
        let sealed = vault.seal_aux(SUBSCRIPTION_KIND, &id, &plain)?;
        tx.execute(
            "INSERT INTO push_devices(id, name, endpoint_hash, subscription_sealed, service, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(id) DO UPDATE SET name = excluded.name, \
             subscription_sealed = excluded.subscription_sealed, failures = 0",
            params![id, name, hash, sealed, service, now],
        )?;
        // A new or renewed subscription starts with no queued pushes from before.
        Ok(json!({ "id": id, "name": name, "service": service }))
    })
    .await
}

/// `PushList`: the devices, newest first, with the outcome of their last push.
pub async fn admin_list(call: &AdminCall<'_>) -> anyhow::Result<Value> {
    call.read(|c| {
        let mut st = c.prepare(
            "SELECT d.id, d.name, d.service, d.created_at, d.last_ok_at, d.last_status, d.failures, \
             (SELECT count(*) FROM push_outbox o WHERE o.device_id = d.id AND o.state = 'pending') \
             FROM push_devices d ORDER BY d.created_at DESC, d.id",
        )?;
        let rows = st.query_map([], |r| {
            let last_ok: Option<i64> = r.get(4)?;
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "service": r.get::<_, String>(2)?,
                "created_at": util::rfc3339(r.get(3)?),
                "last_delivered_at": last_ok.map(util::rfc3339),
                "last_status": r.get::<_, Option<i64>>(5)?,
                "failures": r.get::<_, i64>(6)?,
                "pending": r.get::<_, i64>(7)?,
            }))
        })?;
        Ok(Value::Array(rows.collect::<Result<_, _>>()?))
    })
    .await
}

/// `PushRemove`: forgets a device and its queued pushes. The browser keeps its subscription until it is
/// unsubscribed there; pushes to it simply stop.
pub async fn admin_remove(call: &mut AdminCall<'_>, id: String) -> anyhow::Result<Value> {
    call.tx(move |tx| {
        let n = tx.execute("DELETE FROM push_devices WHERE id = ?1", [&id])?;
        if n == 0 {
            bail!("no push device with this id");
        }
        Ok(json!({ "removed": id }))
    })
    .await
}

/// `PushTest`: queues a test notification for one device (or all), delivers it now and reports each outcome.
pub async fn admin_test(call: &mut AdminCall<'_>, id: Option<String>) -> anyhow::Result<Value> {
    subject(call.app)?;
    let now = util::now_unix();
    let text = Text {
        title: "Dove".into(),
        body: "Test notification: push works on this device.".into(),
        url: "/admin/settings".into(),
    };
    let rows = call
        .tx(move |tx| {
            if let Some(id) = &id {
                let found: bool =
                    tx.query_row("SELECT EXISTS(SELECT 1 FROM push_devices WHERE id = ?1)", [id], |r| r.get(0))?;
                if !found {
                    bail!("no push device with this id");
                }
            }
            let devices = id.map(|i| vec![i]);
            Ok(queue_text(tx, "test", devices.as_deref(), &text, now)?)
        })
        .await?;
    if rows.is_empty() {
        bail!("no device receives pushes yet; turn them on in the admin UI under Settings");
    }
    deliver_due(call.app, now).await?;
    let out = call
        .app
        .store
        .call(move |c| {
            let mut out = Vec::new();
            for row in rows {
                let r: Option<(String, Option<String>, String, Option<i64>)> = c
                    .query_row(
                        "SELECT o.device_id, d.name, o.state, o.last_status FROM push_outbox o \
                         LEFT JOIN push_devices d ON d.id = o.device_id WHERE o.id = ?1",
                        [row],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                out.push(match r {
                    Some((device, name, state, status)) => {
                        json!({ "device": device, "name": name, "state": state, "status": status })
                    }
                    // The push service said the subscription is gone; the device (and this row) were removed.
                    None => json!({ "state": "device_removed" }),
                });
            }
            Ok(out)
        })
        .await?;
    Ok(json!({ "results": out }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(endpoint: &str, p256dh: &str, auth: &str) -> Subscription {
        Subscription { endpoint: endpoint.into(), keys: SubscriptionKeys { p256dh: p256dh.into(), auth: auth.into() } }
    }

    #[test]
    fn only_https_endpoints_on_known_push_services_with_valid_keys() {
        let p = util::b64url(&ece::public_key(&[7; 32]).unwrap());
        let a = util::b64url(&[9u8; 16]);
        for (ok, service) in [
            ("https://web.push.apple.com/QF8x", "Apple"),
            ("https://fcm.googleapis.com/fcm/send/x", "Google"),
            ("https://updates.push.services.mozilla.com/wpush/v2/x", "Mozilla"),
            ("https://wns2-par02p.notify.windows.com/w/?token=x", "Microsoft"),
        ] {
            let t = sub(ok, &p, &a).check(false).unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert_eq!(t.endpoint.service(), service);
        }
        for bad in [
            "http://web.push.apple.com/x",
            "https://web.push.apple.com:8443/x",
            "https://user:pw@web.push.apple.com/x",
            "https://web.push.apple.com/x#frag",
            "https://evil.example/x",
            "https://web.push.apple.com.evil.example/x",
            "https://xweb.push.apple.com/x",
            "https://127.0.0.1/x",
            "http://127.0.0.1:9/x",
            "not a url",
        ] {
            assert!(sub(bad, &p, &a).check(false).is_err(), "{bad}");
        }
        // Test builds may allow plain http to loopback, and only that.
        assert!(sub("http://127.0.0.1:9/x", &p, &a).check(true).is_ok());
        assert!(sub("http://10.0.0.1:9/x", &p, &a).check(true).is_err());
        let long = format!("https://web.push.apple.com/{}", "a".repeat(MAX_ENDPOINT));
        assert!(sub(&long, &p, &a).check(false).is_err());
        assert!(sub("https://web.push.apple.com/x", "AAAA", &a).check(false).is_err());
        assert!(sub("https://web.push.apple.com/x", &p, &util::b64url(&[9u8; 15])).check(false).is_err());
        assert_eq!(format!("{:?}", sub("https://web.push.apple.com/secret", &p, &a)), "Subscription([redacted])");
    }

    #[test]
    fn the_payload_is_fixed_size_json() {
        let t = Text {
            title: "Dove: approval needed".into(),
            body: "claude wants to send a mail".into(),
            url: "/admin/requests/r_1".into(),
        };
        let p = payload(&t, "r_1");
        assert_eq!(p.len(), PAYLOAD_SIZE);
        let v: Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(v, json!({ "title": t.title, "body": t.body, "url": t.url, "tag": "r_1" }));
        // An overlong body is cut until it fits; the JSON stays valid.
        let long = Text { body: "ä".repeat(600), ..t };
        let p = payload(&long, "r_1");
        assert_eq!(p.len(), PAYLOAD_SIZE);
        assert!(serde_json::from_slice::<Value>(&p).is_ok());
    }

    #[test]
    fn the_vapid_jwt_is_signed_for_the_endpoint_origin() {
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new()).unwrap();
        let v = Vapid::from_pkcs8(doc.as_ref()).unwrap();
        let key = util::b64url_decode(&v.public_b64()).unwrap();
        assert_eq!((key.len(), key[0]), (65, 4));
        let ep = Endpoint::parse("https://web.push.apple.com/QF8x?y=1", false).unwrap();
        let auth = v.authorization(&ep, "https://box.ts.net:43395", 1000).unwrap();
        let (t, k) = auth.strip_prefix("vapid t=").unwrap().split_once(", k=").unwrap();
        assert_eq!(k, v.public_b64());
        let parts: Vec<&str> = t.split('.').collect();
        let claims: Value = serde_json::from_slice(&util::b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            claims,
            json!({ "aud": "https://web.push.apple.com", "exp": 1000 + 12 * 3600, "sub": "https://box.ts.net:43395" })
        );
        let sig = util::b64url_decode(parts[2]).unwrap();
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED, &key)
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();
    }

    #[test]
    fn names_are_short_and_printable() {
        assert_eq!(clean_name("  iphone ").unwrap(), "iphone");
        assert!(clean_name("").is_err() && clean_name("a\nb").is_err());
        assert!(clean_name(&"x".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert_eq!(label("a\u{7}b"), "ab");
        assert_eq!(label(&"y".repeat(50)).chars().count(), 40);
    }
}
