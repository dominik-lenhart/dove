//! Owner notifications (spec 7.1 "Notifier"): reauth needed, repeated upstream errors, denial bursts, new client IPs,
//! and the health watcher's alerts (`crate::health`). Messages carry no mail content. Each event key is sent at most
//! once until it is cleared.
//!
//! Every alert goes to the log, the optional webhook and, as a push, to every device of the owner (design
//! 2026-11-17). The push text is built here, in [`Alert`]'s constructors, so no caller can put free text on a lock
//! screen: it names a mailbox alias or connection name and the kind of problem, never an address, IP or server text.

use std::sync::{Arc, Mutex};

use rusqlite::{OptionalExtension, params};
use serde_json::json;

use crate::push::{self, Text};
use crate::store::Store;
use crate::util;

/// The new-network alert pushes at most once per connection within this window (PLAN A84).
pub const NEW_NETWORK_WINDOW_SECS: i64 = 24 * 3600;

/// One owner notification: `message` for the log and webhook, `push` for the lock screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub message: String,
    pub push: Text,
}

/// An admin UI path for a mailbox or connection page, or the health page when the name does not fit a path segment.
fn page(prefix: &str, name: &str) -> String {
    if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        format!("/admin/{prefix}/{name}")
    } else {
        "/admin/health".into()
    }
}

fn text(title: &str, body: String, url: String) -> Text {
    Text { title: format!("Dove: {title}"), body, url }
}

impl Alert {
    /// A mailbox's grant or password was refused; `hint` is the CLI step for the log.
    pub fn reauth(alias: &str, hint: &str) -> Self {
        Alert {
            message: format!("Mailbox '{alias}' {hint}"),
            push: text(
                "reconnect a mailbox",
                format!("{} needs to be reconnected", push::label(alias)),
                page("mailboxes", alias),
            ),
        }
    }

    /// A client's token was used from a network ([`crate::policy::alert_network`]) it had not used before. The
    /// network and the address go to the log only.
    pub fn new_network(client: &str, network: &str, ip: &str) -> Self {
        Alert {
            message: format!("Client '{client}' was used from a new network {network} (address {ip})."),
            push: text(
                "new network",
                format!("{} was used from a new network", push::label(client)),
                page("connections", client),
            ),
        }
    }

    /// A client had many denied calls in a short time.
    pub fn denial_burst(client: &str) -> Self {
        Alert {
            message: format!("Client '{client}' had a burst of denied calls in the last minutes."),
            push: text(
                "denied calls",
                format!("{} had a burst of denied calls", push::label(client)),
                page("connections", client),
            ),
        }
    }

    /// An agent created, changed or deleted a signature. `name` is a validated signature name (`[a-z0-9-]`); the push
    /// names the mailbox and the connection only.
    pub fn signature_changed(alias: &str, client: &str, name: &str, deleted: bool) -> Self {
        let verb = if deleted { "deleted" } else { "changed" };
        Alert {
            message: format!("Client '{client}' {verb} signature '{name}' of mailbox '{alias}'."),
            push: text(
                "signature changed",
                format!("{} {verb} a signature of {}", push::label(client), push::label(alias)),
                page("mailboxes", alias),
            ),
        }
    }

    /// A best-effort IMAP draft step failed; `message` names the mailbox and draft ids only.
    pub fn draft_cleanup(alias: &str, message: String) -> Self {
        Alert {
            message,
            push: text(
                "check Drafts",
                format!("{} needs a look in Drafts", push::label(alias)),
                page("mailboxes", alias),
            ),
        }
    }

    /// A mailbox's index has not synced for `hours`.
    pub fn sync_stalled(alias: &str, hours: i64) -> Self {
        Alert {
            message: format!("Mailbox '{alias}' has not synced for {hours} h; see `dove index status {alias}`."),
            push: text(
                "sync stopped",
                format!("{} has not synced for {hours} h", push::label(alias)),
                page("mailboxes", alias),
            ),
        }
    }

    /// A mailbox reported by [`Alert::sync_stalled`] syncs again.
    pub fn sync_recovered(alias: &str) -> Self {
        Alert {
            message: format!("Mailbox '{alias}' syncs again."),
            push: text("sync is back", format!("{} syncs again", push::label(alias)), page("mailboxes", alias)),
        }
    }

    /// The data directory's file system is almost full.
    pub fn low_disk(free_mib: u64) -> Self {
        Alert {
            message: format!("Only {free_mib} MiB are free for Dove's data directory."),
            push: text("disk almost full", format!("{free_mib} MiB free for Dove's data"), "/admin/health".into()),
        }
    }
}

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

    /// Sends `alert` unless an earlier notification with the same `key` is still recorded. The record and the pushes
    /// are written in one transaction.
    pub async fn notify_once(&self, key: &str, alert: Alert) -> anyhow::Result<bool> {
        let (key_owned, push) = (key.to_string(), alert.push.clone());
        let first = self
            .store
            .call(move |c| {
                let tx = c.transaction()?;
                let now = util::now_unix();
                let first = tx.execute(
                    "INSERT OR IGNORE INTO notifications(key, last_sent_at) VALUES (?1, ?2)",
                    params![key_owned, now],
                )? == 1;
                if first {
                    push::queue_text(&tx, "alert", None, &push, now)?;
                }
                tx.commit()?;
                Ok(first)
            })
            .await?;
        if first {
            self.announce(&alert.message).await;
        }
        Ok(first)
    }

    /// Like [`Self::notify_once`], but pushes at most once per `group` within `window_secs`. An event inside the
    /// window is still recorded under `key` (so it never alerts later) and goes to the log only. Returns whether the
    /// alert was sent.
    pub async fn notify_once_limited(
        &self,
        key: &str,
        group: &str,
        window_secs: i64,
        alert: Alert,
    ) -> anyhow::Result<bool> {
        let (key_owned, group_key, push) = (key.to_string(), format!("limit:{group}"), alert.push.clone());
        let outcome = self
            .store
            .call(move |c| {
                let tx = c.transaction()?;
                let now = util::now_unix();
                let first = tx.execute(
                    "INSERT OR IGNORE INTO notifications(key, last_sent_at) VALUES (?1, ?2)",
                    params![key_owned, now],
                )? == 1;
                if !first {
                    return Ok(None);
                }
                let last: Option<i64> = tx
                    .query_row("SELECT last_sent_at FROM notifications WHERE key = ?1", [&group_key], |r| r.get(0))
                    .optional()?;
                let send = last.is_none_or(|t| now - t >= window_secs);
                if send {
                    tx.execute(
                        "INSERT INTO notifications(key, last_sent_at) VALUES (?1, ?2) \
                         ON CONFLICT(key) DO UPDATE SET last_sent_at = excluded.last_sent_at",
                        params![group_key, now],
                    )?;
                    push::queue_text(&tx, "alert", None, &push, now)?;
                }
                tx.commit()?;
                Ok(Some(send))
            })
            .await?;
        match outcome {
            Some(true) => self.announce(&alert.message).await,
            Some(false) => tracing::info!(notification = alert.message, "owner notification suppressed (rate limit)"),
            None => {}
        }
        Ok(outcome == Some(true))
    }

    /// Allows the event `key` to notify again (for example after a successful reconnect). Returns whether it was open.
    pub async fn clear(&self, key: &str) -> anyhow::Result<bool> {
        let key = key.to_string();
        self.store.call(move |c| Ok(c.execute("DELETE FROM notifications WHERE key = ?1", [key])? == 1)).await
    }

    /// Whether the event `key` is recorded (sent and not cleared).
    pub async fn is_open(&self, key: &str) -> anyhow::Result<bool> {
        let key = key.to_string();
        self.store
            .call(move |c| {
                Ok(c.query_row("SELECT count(*) FROM notifications WHERE key = ?1", [key], |r| r.get::<_, i64>(0))? > 0)
            })
            .await
    }

    /// Sends `alert` without deduplication (the caller limits the rate).
    pub async fn send(&self, alert: Alert) {
        let push = alert.push.clone();
        let queued = self
            .store
            .call(move |c| {
                let tx = c.transaction()?;
                push::queue_text(&tx, "alert", None, &push, util::now_unix())?;
                tx.commit()?;
                Ok(())
            })
            .await;
        if let Err(e) = queued {
            tracing::error!(error = %e, "queueing an alert push failed");
        }
        self.announce(&alert.message).await;
    }

    async fn announce(&self, message: &str) {
        tracing::warn!(notification = message, "owner notification");
        if let Ok(mut s) = self.sent.lock() {
            s.push(message.to_string());
        }
        if let Some(url) = &self.webhook {
            let body = json!({ "title": "Dove", "message": message });
            if let Err(e) = self.http.post(url).json(&body).send().await {
                tracing::error!(error = %crate::logging::redact(&e.without_url().to_string()), "notification webhook failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock-screen text never carries the IP, and paths that do not fit the service worker's pattern fall back.
    #[test]
    fn push_text_names_only_the_alias_or_client() {
        let a = Alert::new_network("claude-code", "203.0.0.0/16", "203.0.113.7");
        assert!(a.message.contains("203.0.113.7") && a.message.contains("203.0.0.0/16"));
        assert!(!format!("{:?}", a.push).contains("203.0."), "{:?}", a.push);
        assert_eq!(a.push.url, "/admin/connections/claude-code");
        assert_eq!(Alert::reauth("info", "x").push.url, "/admin/mailboxes/info");
        assert_eq!(Alert::denial_burst("a/../b").push.url, "/admin/health");
        assert_eq!(Alert::denial_burst("").push.url, "/admin/health");
    }
}
