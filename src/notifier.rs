//! Owner notifications (spec 7.1 "Notifier"): reauth needed, repeated upstream errors, denial bursts, new client IPs.
//! Messages carry no mail content. Each event key is sent at most once until it is cleared.

use std::sync::{Arc, Mutex};

use rusqlite::params;
use serde_json::json;

use crate::store::Store;
use crate::util;

#[derive(Clone)]
pub struct Notifier {
    webhook: Option<String>,
    http: reqwest::Client,
    store: Store,
    /// Every message that would be sent, for tests and `doctor`.
    pub sent: Arc<Mutex<Vec<String>>>,
}

impl Notifier {
    pub fn new(webhook: Option<String>, store: Store) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("http client");
        Self { webhook, http, store, sent: Arc::default() }
    }

    /// Sends `message` unless an earlier notification with the same `key` is still recorded.
    pub async fn notify_once(&self, key: &str, message: &str) -> anyhow::Result<bool> {
        let key_owned = key.to_string();
        let first = self
            .store
            .call(move |c| {
                Ok(c.execute(
                    "INSERT OR IGNORE INTO notifications(key, last_sent_at) VALUES (?1, ?2)",
                    params![key_owned, util::now_unix()],
                )? == 1)
            })
            .await?;
        if first {
            self.send(message).await;
        }
        Ok(first)
    }

    /// Allows the event `key` to notify again (for example after a successful reconnect).
    pub async fn clear(&self, key: &str) -> anyhow::Result<()> {
        let key = key.to_string();
        self.store.call(move |c| Ok(c.execute("DELETE FROM notifications WHERE key = ?1", [key]).map(|_| ())?)).await
    }

    pub async fn send(&self, message: &str) {
        tracing::warn!(notification = message, "owner notification");
        if let Ok(mut s) = self.sent.lock() {
            s.push(message.to_string());
        }
        if let Some(url) = &self.webhook {
            let body = json!({ "title": "Dove", "message": message });
            if let Err(e) = self.http.post(url).json(&body).send().await {
                tracing::error!(error = %crate::logging::redact(&e.to_string()), "notification webhook failed");
            }
        }
    }
}
