//! Connecting a Google account (spec 7.3, AC7).
//!
//! The CLI asks the service (over the admin socket) to create a pending connect and prints the authorization URL.
//! The callback validates state, PKCE, the ID token, scopes and identity, exercises one refresh, checks the profile,
//! and only then stores the encrypted grant. Rejections store nothing. Revocation is never used as cleanup.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::gateway::{GatewayError, GmailOp, Priority};
use super::{REQUIRED_SCOPES, SCOPE_COMPOSE, SCOPE_READONLY};
use crate::admin::ops::valid_alias;
use crate::app::App;
use crate::audit::{self, AuditRecord};
use crate::util;

const PENDING_TTL_SECS: i64 = 600;

#[derive(Default)]
pub struct JwksCache(Mutex<Option<(Instant, Value)>>);

pub fn redirect_uri(app: &App) -> String {
    format!("{}/oauth/google/callback", app.cfg.public_base())
}

/// Creates a pending connect and returns the authorization URL (spec 7.3 steps 2-3).
pub async fn start(app: &App, alias: &str, email: Option<&str>, reconnect: bool) -> anyhow::Result<String> {
    let client_id = app.cfg.google_client_id()?.to_string();
    if !valid_alias(alias) {
        bail!("alias must match [a-z0-9-]{{2,40}}");
    }
    let state = util::b64url(&util::random_bytes::<32>());
    let verifier = util::b64url(&util::random_bytes::<32>());
    let challenge = util::b64url(&Sha256::digest(verifier.as_bytes()));
    let state_hash = app.pepper.hash("oauth-state", &state);
    let pkce = app.vault.seal_aux("pkce", &util::hex(&state_hash), verifier.as_bytes())?;
    let (alias_s, email_s) = (alias.to_string(), email.map(|e| e.trim().to_lowercase()));
    let expected_email = app
        .store
        .call(move |c| {
            let existing: Option<(String, String, String)> = c
                .query_row("SELECT id, email, provider FROM accounts WHERE alias = ?1", [&alias_s], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .optional()?;
            if existing.as_ref().is_some_and(|e| e.2 != "gmail") {
                bail!("'{alias_s}' is an IMAP mailbox; reconnect it with its password");
            }
            let existing = existing.map(|(id, email, _)| (id, email));
            let (mode, account_id, expected) = match (reconnect, existing) {
                (false, Some(_)) => bail!("account alias '{alias_s}' already exists; use reconnect"),
                (false, None) => {
                    let email = email_s.ok_or_else(|| anyhow!("--email is required"))?;
                    if !email_address::EmailAddress::is_valid(&email) {
                        bail!("invalid email address");
                    }
                    let taken: bool = c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM accounts WHERE email = ?1 COLLATE NOCASE)",
                        [&email],
                        |r| r.get(0),
                    )?;
                    if taken {
                        bail!("this email address is already connected under another alias");
                    }
                    ("connect", None, email)
                }
                (true, None) => bail!("unknown account '{alias_s}'"),
                (true, Some((id, email))) => ("reconnect", Some(id), email),
            };
            let now = util::now_unix();
            c.execute(
                "INSERT INTO pending_connects(state_hash, account_alias, expected_email, pkce_verifier_ciphertext, mode, \
                 account_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![state_hash, alias_s, expected, pkce, mode, account_id, now, now + PENDING_TTL_SECS],
            )?;
            // Housekeeping: expired pending rows are useless.
            c.execute("DELETE FROM pending_connects WHERE expires_at < ?1", [now - 86_400])?;
            Ok(expected)
        })
        .await?;
    let mut url = url::Url::parse(&app.google.upstream().auth_url)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri(app))
        .append_pair("scope", &REQUIRED_SCOPES.join(" "))
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("login_hint", &expected_email)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdClaims {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
}

/// Outcome shown on the callback page. Never includes tokens.
pub enum CallbackOutcome {
    Connected { alias: String, email: String },
    Rejected(String),
}

struct Pending {
    alias: String,
    expected_email: String,
    verifier: zeroize::Zeroizing<Vec<u8>>,
    reconnect_account: Option<String>,
}

/// Handles `/oauth/google/callback`. Every path records exactly one audit record.
pub async fn callback(app: &App, q: CallbackQuery) -> CallbackOutcome {
    let started = Instant::now();
    let (outcome, alias, code) = match handle(app, q).await {
        Ok((alias, email)) => (CallbackOutcome::Connected { alias: alias.clone(), email }, Some(alias), "ok"),
        Err((alias, reason, code)) => (CallbackOutcome::Rejected(reason), alias, code),
    };
    let rec = AuditRecord {
        request_id: util::new_id(),
        actor: "google-callback".into(),
        tool_or_action: "accounts.connect_callback".into(),
        account_alias: alias,
        result_code: code.into(),
        duration_ms: started.elapsed().as_millis() as i64,
        ..Default::default()
    };
    let _ = app.store.call(move |c| audit::append(c, &rec).map(|_| ())).await;
    outcome
}

type Reject = (Option<String>, String, &'static str);

fn reject(alias: Option<&str>, msg: &str, code: &'static str) -> Reject {
    (alias.map(str::to_string), msg.to_string(), code)
}

async fn take_pending(app: &App, state: &str) -> Result<Pending, Reject> {
    let state_hash = app.pepper.hash("oauth-state", state);
    let scope = util::hex(&state_hash);
    let row = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let now = util::now_unix();
            #[allow(clippy::type_complexity)] // one pending_connects row
            let row: Option<(String, String, Vec<u8>, Option<String>, i64, Option<i64>)> = tx
                .query_row(
                    "SELECT account_alias, expected_email, pkce_verifier_ciphertext, account_id, expires_at, used_at \
                     FROM pending_connects WHERE state_hash = ?1",
                    [&state_hash],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .optional()?;
            // Single use even on failure: mark used before anything else (spec 7.3 step 5).
            tx.execute(
                "UPDATE pending_connects SET used_at = COALESCE(used_at, ?1) WHERE state_hash = ?2",
                params![now, state_hash],
            )?;
            tx.commit()?;
            Ok(row.map(|r| (r, now)))
        })
        .await
        .map_err(|_| reject(None, "internal error", "internal"))?;
    let Some(((alias, expected_email, pkce, account_id, expires_at, used_at), now)) = row else {
        return Err(reject(
            None,
            "This sign-in link is not valid. Start again with `dove accounts connect`.",
            "invalid_state",
        ));
    };
    if used_at.is_some() || expires_at < now {
        return Err(reject(
            Some(&alias),
            "This sign-in link has expired or was already used. Start again.",
            "invalid_state",
        ));
    }
    let verifier =
        app.vault.open_aux("pkce", &scope, &pkce).map_err(|_| reject(Some(&alias), "internal error", "internal"))?;
    Ok(Pending { alias, expected_email, verifier, reconnect_account: account_id })
}

async fn record_outcome(app: &App, state: &str, outcome: &str) {
    let h = app.pepper.hash("oauth-state", state);
    let o = outcome.to_string();
    let _ = app
        .store
        .call(move |c| Ok(c.execute("UPDATE pending_connects SET outcome = ?1 WHERE state_hash = ?2", params![o, h])?))
        .await;
}

async fn handle(app: &App, q: CallbackQuery) -> Result<(String, String), Reject> {
    let state = q.state.ok_or_else(|| reject(None, "Missing state.", "invalid_state"))?;
    let pending = take_pending(app, &state).await?;
    let result = complete(app, &pending, q.code, q.error).await;
    record_outcome(
        app,
        &state,
        match &result {
            Ok(_) => "connected",
            Err((_, _, code)) => code,
        },
    )
    .await;
    result.map(|email| (pending.alias.clone(), email))
}

async fn complete(app: &App, p: &Pending, code: Option<String>, error: Option<String>) -> Result<String, Reject> {
    let alias = Some(p.alias.as_str());
    if let Some(e) = error {
        let msg = if e == "access_denied" {
            "Access was not granted. Nothing was stored."
        } else {
            "Google returned an error. Nothing was stored."
        };
        return Err(reject(alias, msg, "access_denied"));
    }
    let code = code.ok_or_else(|| reject(alias, "Missing authorization code.", "invalid_argument"))?;
    let verifier = std::str::from_utf8(&p.verifier).map_err(|_| reject(alias, "internal error", "internal"))?;
    let redirect = redirect_uri(app);
    let gw = app.google.gateway();
    let (Ok(client_id), Some(client_secret)) = (app.cfg.google_client_id(), app.google_client_secret.as_ref()) else {
        return Err(reject(alias, "Gmail is not configured on this server. Nothing was stored.", "internal"));
    };
    let tok = gw
        .token_request(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", verifier),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", &redirect),
        ])
        .await
        .map_err(|_| reject(alias, "The authorization code could not be exchanged. Start again.", "upstream_error"))?;

    // Step 7: ID token.
    let id_token =
        tok["id_token"].as_str().ok_or_else(|| reject(alias, "Google did not return an ID token.", "invalid_token"))?;
    let claims = verify_id_token(app, id_token)
        .await
        .map_err(|_| reject(alias, "The Google identity could not be verified.", "invalid_token"))?;
    if claims.email_verified != Some(true) {
        return Err(reject(alias, "The Google account's email address is not verified.", "identity_mismatch"));
    }
    let email = claims.email.unwrap_or_default();
    if !email.eq_ignore_ascii_case(&p.expected_email) {
        return Err(reject(
            alias,
            "You signed in with a different Google account than expected. Nothing was stored.",
            "identity_mismatch",
        ));
    }
    if let Some(aid) = &p.reconnect_account {
        let aid = aid.clone();
        let stored_sub: Option<String> = app
            .store
            .call(move |c| {
                Ok(c.query_row("SELECT google_sub FROM accounts WHERE id = ?1", [aid], |r| r.get(0))
                    .optional()?
                    .flatten())
            })
            .await
            .map_err(|_| reject(alias, "internal error", "internal"))?;
        if stored_sub.as_deref() != Some(claims.sub.as_str()) {
            return Err(reject(
                alias,
                "This is not the same Google identity as before. Nothing was changed.",
                "identity_mismatch",
            ));
        }
    }

    // Step 8: scopes. Missing scope: discard locally, no revocation.
    let scopes: Vec<&str> = tok["scope"].as_str().unwrap_or("").split_whitespace().collect();
    let missing: Vec<&str> = [SCOPE_READONLY, SCOPE_COMPOSE].into_iter().filter(|s| !scopes.contains(s)).collect();
    if !missing.is_empty() {
        return Err(reject(
            alias,
            &format!(
                "Required permissions were not granted ({}). Start again and keep all boxes ticked.",
                missing.join(", ")
            ),
            "missing_scope",
        ));
    }

    // Step 9: usable refresh token, one refresh, profile check.
    let refresh = tok["refresh_token"].as_str().map(|s| zeroize::Zeroizing::new(s.to_string())).ok_or_else(|| {
        reject(
            alias,
            "Google did not return a refresh token. Remove Dove's access in your Google account and start again.",
            "no_refresh_token",
        )
    })?;
    let (access, _) = app
        .google
        .tokens()
        .refresh_raw(&refresh)
        .await
        .map_err(|_| reject(alias, "The new grant could not be refreshed.", "upstream_error"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let profile = gw
        .gmail("connect", &access, GmailOp::Profile, &[], None, Priority::Interactive, deadline)
        .await
        .map_err(|e: GatewayError| reject(alias, &format!("Gmail profile check failed ({e})."), "upstream_error"))?;
    if !profile["emailAddress"].as_str().is_some_and(|e| e.eq_ignore_ascii_case(&p.expected_email)) {
        return Err(reject(alias, "The Gmail mailbox does not match the expected address.", "identity_mismatch"));
    }

    // Step 10/11: commit grant and status together.
    let granted = scopes.join(" ");
    let (alias_s, email_s, sub, reconnect) =
        (p.alias.clone(), email.to_lowercase(), claims.sub.clone(), p.reconnect_account.clone());
    let vault = app.vault.clone();
    let account_id = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let now = util::now_unix();
            let id = match &reconnect {
                Some(id) => {
                    tx.execute(
                        "UPDATE accounts SET status = 'active', granted_scopes = ?1, connected_at = ?2, last_error_code = NULL, \
                         grant_generation = grant_generation + 1 WHERE id = ?3",
                        params![granted, now, id],
                    )?;
                    id.clone()
                }
                None => {
                    let id = util::new_id();
                    tx.execute(
                        "INSERT INTO accounts(id, alias, email, status, granted_scopes, google_sub, connected_at) \
                         VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6)",
                        params![id, alias_s, email_s, granted, sub, now],
                    )?;
                    id
                }
            };
            let sealed = vault.seal_grant(&id, &refresh)?;
            tx.execute(
                "INSERT INTO grants(account_id, dek_wrapped, kek_version, refresh_token_ciphertext, nonce, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(account_id) DO UPDATE SET dek_wrapped = excluded.dek_wrapped, \
                 kek_version = excluded.kek_version, refresh_token_ciphertext = excluded.refresh_token_ciphertext, \
                 nonce = excluded.nonce, rotated_at = ?6",
                params![id, sealed.dek_wrapped, sealed.kek_version, sealed.ciphertext, sealed.nonce, now],
            )?;
            tx.commit()?;
            Ok(id)
        })
        .await
        .map_err(|_| reject(alias, "The account could not be stored (alias or address already in use?).", "internal"))?;
    app.google.tokens().evict(&account_id);
    Ok(email)
}

async fn verify_id_token(app: &App, token: &str) -> anyhow::Result<IdClaims> {
    let header = jsonwebtoken::decode_header(token)?;
    if header.alg != Algorithm::RS256 {
        bail!("unexpected algorithm");
    }
    let kid = header.kid.ok_or_else(|| anyhow!("no kid"))?;
    let jwks = app.google.jwks(false).await?;
    let key = match find_key(&jwks, &kid) {
        Some(k) => k,
        // Key rotation: refetch once.
        None => find_key(&app.google.jwks(true).await?, &kid).ok_or_else(|| anyhow!("unknown kid"))?,
    };
    let mut v = Validation::new(Algorithm::RS256);
    v.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    v.set_audience(&[app.cfg.google_client_id()?]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    Ok(jsonwebtoken::decode::<IdClaims>(token, &key, &v)?.claims)
}

fn find_key(jwks: &Value, kid: &str) -> Option<DecodingKey> {
    jwks["keys"]
        .as_array()?
        .iter()
        .find(|k| k["kid"].as_str() == Some(kid))
        .and_then(|k| DecodingKey::from_rsa_components(k["n"].as_str()?, k["e"].as_str()?).ok())
}

impl JwksCache {
    pub fn get(&self) -> Option<Value> {
        let g = self.0.lock().ok()?;
        g.as_ref().filter(|(t, _)| t.elapsed() < Duration::from_secs(3600)).map(|(_, v)| v.clone())
    }
    pub fn put(&self, v: Value) {
        if let Ok(mut g) = self.0.lock() {
            *g = Some((Instant::now(), v));
        }
    }
}
