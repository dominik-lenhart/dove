//! Token manager (spec 7.1): one valid access token per account, refreshed ahead of expiry with single-flight per
//! account. Access tokens live only in memory. `invalid_grant` marks the account `reauth_required` and notifies once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use super::gateway::{Gateway, GatewayError};
use crate::error::{ErrorCode, ToolError};
use crate::notifier::Notifier;
use crate::store::Store;
use crate::util;
use crate::vault::{SealedGrant, Vault};

struct Cached {
    token: Zeroizing<String>,
    expires_at: Instant,
    generation: i64,
}

pub struct TokenManager {
    store: Store,
    vault: Vault,
    gateway: Arc<Gateway>,
    client_id: String,
    client_secret: Zeroizing<String>,
    notifier: Notifier,
    slots: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<Cached>>>>>,
}

/// Loaded grant row with the generation it belongs to.
pub struct GrantRow {
    pub status: String,
    pub generation: i64,
    pub alias: String,
    pub sealed: Option<SealedGrant>,
}

pub fn load_grant(conn: &rusqlite::Connection, account_id: &str) -> anyhow::Result<Option<GrantRow>> {
    Ok(conn
        .query_row(
            "SELECT a.status, a.grant_generation, a.alias, g.dek_wrapped, g.kek_version, g.refresh_token_ciphertext, g.nonce \
             FROM accounts a LEFT JOIN grants g ON g.account_id = a.id WHERE a.id = ?1",
            [account_id],
            |r| {
                let dek: Option<Vec<u8>> = r.get(3)?;
                Ok(GrantRow {
                    status: r.get(0)?,
                    generation: r.get(1)?,
                    alias: r.get(2)?,
                    sealed: match dek {
                        Some(dek_wrapped) => Some(SealedGrant {
                            dek_wrapped,
                            kek_version: r.get(4)?,
                            ciphertext: r.get(5)?,
                            nonce: r.get(6)?,
                        }),
                        None => None,
                    },
                })
            },
        )
        .optional()?)
}

impl TokenManager {
    pub fn new(
        store: Store,
        vault: Vault,
        gateway: Arc<Gateway>,
        client_id: String,
        client_secret: Zeroizing<String>,
        notifier: Notifier,
    ) -> Self {
        Self { store, vault, gateway, client_id, client_secret, notifier, slots: Mutex::default() }
    }

    fn slot(&self, account_id: &str) -> Arc<tokio::sync::Mutex<Option<Cached>>> {
        self.slots.lock().expect("lock").entry(account_id.to_string()).or_default().clone()
    }

    /// Drops any cached access token for the account (reconnect, disable, removal).
    pub fn evict(&self, account_id: &str) {
        self.slots.lock().expect("lock").remove(account_id);
    }

    /// Exchanges a refresh token for an access token. Used here and by the connect flow.
    pub async fn refresh_raw(&self, refresh_token: &str) -> Result<(Zeroizing<String>, u64), GatewayError> {
        let v = self
            .gateway
            .token_request(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .await?;
        let token = v["access_token"].as_str().ok_or(GatewayError::BadResponse)?;
        let expires_in = v["expires_in"].as_u64().unwrap_or(3600);
        Ok((Zeroizing::new(token.to_string()), expires_in))
    }

    /// Returns a valid access token or a safe tool error (`account_unavailable`, `upstream_error`).
    pub async fn access_token(&self, account_id: &str) -> Result<Zeroizing<String>, ToolError> {
        let slot = self.slot(account_id);
        let mut guard = slot.lock().await;
        if let Some(c) = guard.as_ref()
            && c.expires_at > Instant::now() + Duration::from_secs(60)
        {
            return Ok(c.token.clone());
        }
        let id = account_id.to_string();
        let row = self.store.call(move |c| load_grant(c, &id)).await.map_err(crate::error::internal_from)?;
        let Some(row) = row else { return Err(ToolError::not_found()) };
        if row.status != "active" {
            return Err(ToolError::unavailable());
        }
        let sealed = row.sealed.as_ref().ok_or_else(ToolError::unavailable)?;
        let refresh = self.vault.open_grant(account_id, sealed).map_err(crate::error::internal_from)?;
        match self.refresh_raw(&refresh).await {
            Ok((token, expires_in)) => {
                *guard = Some(Cached {
                    token: token.clone(),
                    expires_at: Instant::now() + Duration::from_secs(expires_in),
                    generation: row.generation,
                });
                let id = account_id.to_string();
                let _ = self
                    .store
                    .call(move |c| {
                        Ok(c.execute(
                            "UPDATE accounts SET last_used_at = ?1 WHERE id = ?2",
                            params![util::now_unix(), id],
                        )?)
                    })
                    .await;
                Ok(token)
            }
            Err(GatewayError::Status { status: 400, reason: Some(r), .. }) if r == "invalid_grant" => {
                *guard = None;
                self.mark_reauth(account_id, row.generation, &row.alias).await;
                Err(ToolError::unavailable())
            }
            Err(GatewayError::Status { status: 429, retry_after, .. }) => Err(ToolError::rate_limited(retry_after)),
            Err(_) => Err(ToolError::new(ErrorCode::UpstreamError, "token refresh failed")),
        }
    }

    /// Marks reauth only if the grant generation is unchanged: a late refresh for an older grant cannot touch a
    /// newer one (spec 7.3 step 11).
    async fn mark_reauth(&self, account_id: &str, generation: i64, alias: &str) {
        let id = account_id.to_string();
        let changed = self
            .store
            .call(move |c| {
                Ok(c.execute(
                    "UPDATE accounts SET status = 'reauth_required', last_error_code = 'invalid_grant', last_error_at = ?1 \
                     WHERE id = ?2 AND grant_generation = ?3 AND status = 'active'",
                    params![util::now_unix(), id, generation],
                )?)
            })
            .await
            .unwrap_or(0);
        if changed == 1 {
            let _ = self
                .notifier
                .notify_once(
                    &format!("reauth:{account_id}:{generation}"),
                    &format!("Mailbox '{alias}' needs to be reconnected: run `dove accounts reconnect {alias}`."),
                )
                .await;
        }
    }

    /// Generation of the cached token, for tests.
    pub async fn cached_generation(&self, account_id: &str) -> Option<i64> {
        self.slot(account_id).lock().await.as_ref().map(|c| c.generation)
    }
}
