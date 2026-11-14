//! Passkey sign-in, enrolment, sessions and step-up confirmation for the admin UI (design 5.2, PLAN A74).
//!
//! - Challenges are generated here, used once and short-lived. Enrolment and step-up challenges sit in bounded
//!   in-memory pools (taken out before they are checked). Sign-in challenges are public, so they keep no state a
//!   stranger could fill or push out: the id carries the challenge under a MAC ([`LoginChallenges`]), and a
//!   challenge is spent when an assertion over it verified.
//! - The session cookie carries 32 random bytes; the store keeps only their SHA-256. The CSRF token is derived from
//!   the cookie token by a one-way hash, so it needs no storage and reveals nothing about the cookie.
//! - Step-up: the server keeps the exact `AdminRequest` under the challenge (challenge = SHA-256 of a nonce and the
//!   request's canonical JSON); a valid assertion from the session's own passkey runs exactly that request, once.
//! - Nothing secret (tokens, challenges, client data) reaches logs or audit rows; failures are fixed codes.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::store::{self, SESSION_TTL_SECS};
use super::webauthn::{self, RelyingParty, StoredCredential};
use super::{COOKIE, html, needs_step_up};
use crate::admin::ops::Actor;
use crate::admin::{AdminRequest, AdminResponse};
use crate::app::App;
use crate::audit::{self, AuditRecord};
use crate::http::ClientIp;
use crate::util;

const LOGIN_TTL_SECS: i64 = 120;
/// Spent sign-in challenges kept until they expire. Only a verified assertion adds one.
const LOGIN_SPENT_CAP: usize = 256;
const ENROL_TTL: Duration = Duration::from_secs(300);
const ENROL_POOL: usize = 16;
const STEPUP_TTL: Duration = Duration::from_secs(120);
const STEPUP_POOL: usize = 64;
const STEPUP_PER_SESSION: usize = 4;
/// The browser's WebAuthn timeout (milliseconds), a little shorter than the pools' lifetime.
const CEREMONY_TIMEOUT_MS: u64 = 110_000;

// ------------------------------------------------------------------ challenge pools

struct Entry<T> {
    id: String,
    expires: Instant,
    value: T,
}

/// A bounded pool of pending ceremonies, keyed by a random id.
pub struct Pool<T> {
    entries: Mutex<VecDeque<Entry<T>>>,
}

impl<T> Default for Pool<T> {
    fn default() -> Self {
        Self { entries: Mutex::new(VecDeque::new()) }
    }
}

impl<T> Pool<T> {
    /// Adds an entry; when the pool is full the oldest entry goes.
    fn put_evicting(&self, cap: usize, ttl: Duration, id: String, value: T) {
        let now = Instant::now();
        let mut q = self.entries.lock().expect("lock");
        q.retain(|e| e.expires > now);
        while q.len() >= cap {
            q.pop_front();
        }
        q.push_back(Entry { id, expires: now + ttl, value });
    }

    /// Adds an entry unless the pool is full; entries for which `same_owner` holds beyond `per_owner` drop the oldest.
    fn put_bounded(
        &self,
        cap: usize,
        ttl: Duration,
        id: String,
        value: T,
        same_owner: impl Fn(&T) -> bool,
        per_owner: usize,
    ) -> bool {
        let now = Instant::now();
        let mut q = self.entries.lock().expect("lock");
        q.retain(|e| e.expires > now);
        while q.iter().filter(|e| same_owner(&e.value)).count() >= per_owner {
            let Some(i) = q.iter().position(|e| same_owner(&e.value)) else { break };
            q.remove(i);
        }
        if q.len() >= cap {
            return false;
        }
        q.push_back(Entry { id, expires: now + ttl, value });
        true
    }

    /// Takes the entry out (single use). An expired entry is taken out too, and not returned.
    fn take(&self, id: &str) -> Option<T> {
        let now = Instant::now();
        let mut q = self.entries.lock().expect("lock");
        let i = q.iter().position(|e| e.id.as_bytes().ct_eq(id.as_bytes()).into())?;
        let e = q.remove(i)?;
        (e.expires > now).then_some(e.value)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().expect("lock").len()
    }
}

struct EnrolPending {
    challenge: [u8; 32],
    token: String,
    label: String,
    user_handle: [u8; 16],
}

struct StepUp {
    challenge: [u8; 32],
    session_id: String,
    passkey_id: String,
    action: AdminRequest,
    return_to: String,
}

/// Sign-in challenges without server state. `/admin/login/options` is public, and behind Tailscale Serve every
/// caller is `127.0.0.1`; a pool of pending challenges could be filled or emptied by any local process, which
/// would keep the owner out. The ceremony id is `challenge || expiry || HMAC(key, expiry || challenge)` under a
/// key that lives as long as the process. Single use: a challenge is recorded as spent once an assertion over it
/// verified (only a passkey holder gets that far), until it expires.
pub struct LoginChallenges {
    key: [u8; 32],
    spent: Mutex<HashMap<[u8; 32], i64>>,
}

impl Default for LoginChallenges {
    fn default() -> Self {
        Self { key: util::random_bytes::<32>(), spent: Mutex::default() }
    }
}

impl LoginChallenges {
    fn mac(&self, expires: i64, challenge: &[u8; 32]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key).expect("any key length");
        mac.update(b"dove-admin-login\0");
        mac.update(&expires.to_be_bytes());
        mac.update(challenge);
        mac
    }

    /// A new challenge and its ceremony id.
    fn issue(&self, now: i64) -> (String, [u8; 32]) {
        let challenge = util::random_bytes::<32>();
        let expires = now + LOGIN_TTL_SECS;
        let mut id = Vec::with_capacity(72);
        id.extend_from_slice(&challenge);
        id.extend_from_slice(&expires.to_be_bytes());
        id.extend_from_slice(&self.mac(expires, &challenge).finalize().into_bytes());
        (util::b64url(&id), challenge)
    }

    /// The challenge of an id this process issued and that has not expired or been spent.
    fn open(&self, id: &str, now: i64) -> Option<[u8; 32]> {
        let raw = b64(id).filter(|r| r.len() == 72)?;
        let challenge: [u8; 32] = raw[..32].try_into().ok()?;
        let expires = i64::from_be_bytes(raw[32..40].try_into().ok()?);
        self.mac(expires, &challenge).verify_slice(&raw[40..]).ok()?;
        if expires <= now || self.spent.lock().expect("lock").contains_key(&challenge) {
            return None;
        }
        Some(challenge)
    }

    /// Marks a challenge spent after its assertion verified. False when it was spent already (the same assertion
    /// arriving twice) or the list is full.
    fn spend(&self, challenge: [u8; 32], now: i64) -> bool {
        let mut m = self.spent.lock().expect("lock");
        m.retain(|_, exp| *exp > now);
        if m.len() >= LOGIN_SPENT_CAP || m.contains_key(&challenge) {
            return false;
        }
        m.insert(challenge, now + LOGIN_TTL_SECS);
        true
    }
}

#[derive(Default)]
pub struct Pools {
    login: LoginChallenges,
    enrol: Pool<EnrolPending>,
    stepup: Pool<StepUp>,
    seen: SeenSessions,
}

const SEEN_CAP: usize = 64;

/// Hashes of session tokens the gate has found valid, with their expiry, kept in memory (at most [`SEEN_CAP`]). Only
/// the request budget uses them: once an address is over its budget, a request whose cookie is listed here still
/// passes the guard and draws from a budget of its own, without a state-store lookup (PLAN A74 (i)). They prove
/// nothing: the gate looks the session up as always, so a revoked session that is still listed is refused there.
#[derive(Default)]
struct SeenSessions(Mutex<HashMap<Vec<u8>, i64>>);

impl SeenSessions {
    fn note(&self, token: &str, expires_at: i64) {
        let now = util::now_unix();
        let mut m = self.0.lock().expect("lock");
        if m.len() >= SEEN_CAP {
            m.retain(|_, exp| *exp > now);
        }
        if m.len() >= SEEN_CAP
            && let Some(k) = m.iter().min_by_key(|(_, exp)| **exp).map(|(k, _)| k.clone())
        {
            m.remove(&k);
        }
        m.insert(store::token_hash(token), expires_at);
    }

    fn bucket(&self, token: &str) -> Option<String> {
        let h = store::token_hash(token);
        let m = self.0.lock().expect("lock");
        let listed = m.get(&h).is_some_and(|exp| *exp > util::now_unix());
        listed.then(|| format!("admin-session:{}", util::b64url(&h[..12])))
    }
}

/// The request-budget key of a browser whose session the gate has seen valid, or `None`. No state-store access.
pub fn seen_session_bucket(app: &App, headers: &HeaderMap) -> Option<String> {
    app.admin_ui.auth.seen.bucket(&cookie_token(headers)?)
}

fn new_ceremony_id() -> String {
    util::b64url(&util::random_bytes::<16>())
}

// ------------------------------------------------------------------ sessions

/// A signed-in browser, as the gate found it.
#[derive(Debug, Clone)]
pub struct WebSession {
    pub id: String,
    pub passkey_id: String,
    pub label: String,
    pub expires_at: i64,
    csrf: String,
}

impl WebSession {
    pub fn csrf(&self) -> &str {
        &self.csrf
    }

    /// The audit actor of everything this session does.
    pub fn actor(&self) -> Actor {
        Actor { name: format!("web:{}", self.label), request_id: util::new_id() }
    }
}

/// The CSRF token of the session whose cookie token is `token`.
fn csrf_for(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"dove-admin-csrf\0");
    h.update(token.as_bytes());
    util::b64url(&h.finalize())
}

pub fn csrf_matches(s: &WebSession, presented: &str) -> bool {
    s.csrf.len() == presented.len() && bool::from(s.csrf.as_bytes().ct_eq(presented.as_bytes()))
}

/// A cookie token is 32 random bytes in base64url (43 characters).
fn plausible_token(t: &str) -> bool {
    t.len() == 43 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The session cookie's value. Two cookies of that name (one planted) count as none.
fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let mut found = None;
    for v in headers.get_all(header::COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, v)) = part.trim().split_once('=')
                && k == COOKIE
            {
                if found.is_some() {
                    return None;
                }
                found = Some(v.to_string());
            }
        }
    }
    found.filter(|t| plausible_token(t))
}

pub async fn session_from_headers(app: &Arc<App>, headers: &HeaderMap) -> Option<WebSession> {
    let token = cookie_token(headers)?;
    let csrf = csrf_for(&token);
    let t = token.clone();
    let s = app.store.call(move |c| store::session_lookup(c, &t, util::now_unix())).await.ok()??;
    app.admin_ui.auth.seen.note(&token, s.expires_at);
    Some(WebSession { id: s.id, passkey_id: s.passkey_id, label: s.label, expires_at: s.expires_at, csrf })
}

fn set_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECS}"
    ))
    .expect("ascii")
}

fn clear_cookie() -> HeaderValue {
    HeaderValue::from_str(&format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")).expect("ascii")
}

// ------------------------------------------------------------------ verbs

/// Runs a verb for a signed-in session. Verbs that need a passkey confirmation are refused here: they run only
/// through [`begin_stepup`] and [`stepup_finish`].
pub async fn run_action(app: &Arc<App>, session: &WebSession, req: AdminRequest) -> AdminResponse {
    if needs_step_up(&req) {
        return AdminResponse::err("this action needs a passkey confirmation");
    }
    crate::admin::server::dispatch(app, &session.actor(), req).await
}

// ------------------------------------------------------------------ helpers

fn rp(app: &App) -> Option<(String, String)> {
    Some((app.cfg.admin_ui.rp_id()?, app.cfg.admin_ui.origin()?.to_string()))
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn login_fail_key(ip: Option<IpAddr>) -> String {
    format!("admin-login-fail:{}", super::addr_key(ip))
}

/// Charges a failed sign-in or enrolment to the per-address bucket and returns the status to answer: `refused`, or
/// 429 once the bucket is empty. Only failures are charged and nothing is refused before it is checked, so a valid
/// passkey always signs in: behind Tailscale Serve every caller shares `127.0.0.1`, and a local process must not be
/// able to lock the owner out (PLAN A74 (i), the same rule as bearer failures on `/mcp`).
fn login_failed(app: &App, ip: Option<IpAddr>, refused: StatusCode) -> StatusCode {
    let n = app.cfg.admin_ui.login_failures_per_hour;
    match app.rate_limiter.check_hourly(&login_fail_key(ip), n, n) {
        Some(_) => StatusCode::TOO_MANY_REQUESTS,
        None => refused,
    }
}

fn refused_json(status: StatusCode, msg: &'static str) -> Response {
    json_error(status, if status == StatusCode::TOO_MANY_REQUESTS { TOO_MANY } else { msg })
}

const TOO_MANY: &str = "Too many failed attempts from this address. Try again later.";

fn web_record(actor: String, action: &str, objects: Vec<String>, code: &str, ip: Option<IpAddr>) -> AuditRecord {
    AuditRecord {
        request_id: util::new_id(),
        actor,
        tool_or_action: action.to_string(),
        object_ids: objects,
        result_code: code.to_string(),
        source_ip: ip.map(|i| i.to_string()),
        ..Default::default()
    }
}

async fn audit_web(app: &App, actor: String, action: &str, code: &str, ip: Option<IpAddr>) {
    let rec = web_record(actor, action, vec![], code, ip);
    if let Err(e) = app.store.call(move |c| audit::append(c, &rec).map(|_| ())).await {
        tracing::error!(error = %e, "audit write failed");
    }
}

fn b64(s: &str) -> Option<Vec<u8>> {
    // WebAuthn fields are small; anything longer than the body cap could not have arrived anyway.
    util::b64url_decode(s)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish<C> {
    id: String,
    credential: C,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionJson {
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(rename = "userHandle", default)]
    user_handle: Option<String>,
}

struct Assertion {
    credential_id: Vec<u8>,
    client_data_json: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    user_handle: Option<Vec<u8>>,
}

impl AssertionJson {
    fn decode(&self) -> Option<Assertion> {
        Some(Assertion {
            credential_id: b64(&self.id)?,
            client_data_json: b64(&self.client_data_json)?,
            authenticator_data: b64(&self.authenticator_data)?,
            signature: b64(&self.signature)?,
            user_handle: match &self.user_handle {
                Some(h) if !h.is_empty() => Some(b64(h)?),
                _ => None,
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationJson {
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

/// Checks an assertion of `passkey` for `challenge`.
fn check_assertion(
    app: &App,
    challenge: &[u8],
    passkey: &store::Passkey,
    a: &Assertion,
) -> Result<webauthn::Asserted, webauthn::Error> {
    let (rp_id, origin) = rp(app).ok_or(webauthn::Error::Origin)?;
    if !bool::from(passkey.credential_id.ct_eq(&a.credential_id)) {
        return Err(webauthn::Error::CredentialId);
    }
    if let Some(h) = &a.user_handle
        && !bool::from(passkey.user_handle.ct_eq(h))
    {
        return Err(webauthn::Error::CredentialId);
    }
    webauthn::verify_assertion(
        RelyingParty { id: &rp_id, origin: &origin },
        challenge,
        StoredCredential {
            alg: passkey.alg,
            public_key: &passkey.public_key,
            sign_count: passkey.sign_count,
            backup_eligible: passkey.backup_eligible,
        },
        &a.client_data_json,
        &a.authenticator_data,
        &a.signature,
    )
}

// ------------------------------------------------------------------ sign-in

pub async fn login_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if session_from_headers(&app, &headers).await.is_some() {
        return Redirect::to("/admin").into_response();
    }
    html::respond(html::login_page())
}

pub async fn login_options(State(app): State<Arc<App>>) -> Response {
    let Some((rp_id, _)) = rp(&app) else { return json_error(StatusCode::NOT_FOUND, "not found") };
    let (id, challenge) = app.admin_ui.auth.login.issue(util::now_unix());
    // No allowCredentials: the page is public and must not list credential ids (discoverable credentials).
    Json(json!({ "id": id, "publicKey": {
        "challenge": util::b64url(&challenge), "rpId": rp_id, "userVerification": "required",
        "timeout": CEREMONY_TIMEOUT_MS,
    }}))
    .into_response()
}

const SIGN_IN_FAILED: &str = "Sign-in failed. Try again with a passkey enrolled for this Dove.";

pub async fn login_finish(
    State(app): State<Arc<App>>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    body: Bytes,
) -> Response {
    match login_check(&app, &body, ip).await {
        Ok(token) => {
            tracing::info!("admin UI sign-in");
            let mut r = Json(json!({ "redirect": "/admin" })).into_response();
            r.headers_mut().insert(header::SET_COOKIE, set_cookie(&token));
            r
        }
        Err(code) => {
            let status = login_failed(&app, ip, StatusCode::UNAUTHORIZED);
            tracing::info!(reason = code, "admin UI sign-in refused");
            audit_web(&app, "web".into(), "admin_ui.login", "denied", ip).await;
            refused_json(status, SIGN_IN_FAILED)
        }
    }
}

/// The checks of a sign-in; on success the new session's cookie token (audited inside the session's transaction).
async fn login_check(app: &Arc<App>, body: &[u8], ip: Option<IpAddr>) -> Result<String, &'static str> {
    let f: Finish<AssertionJson> = serde_json::from_slice(body).map_err(|_| "body")?;
    let challenge = app.admin_ui.auth.login.open(&f.id, util::now_unix()).ok_or("challenge")?;
    let a = f.credential.decode().ok_or("encoding")?;
    let cid = a.credential_id.clone();
    let passkey = app
        .store
        .call(move |c| store::passkey_by_credential(c, &cid))
        .await
        .map_err(|_| "store")?
        .ok_or("unknown_credential")?;
    let asserted = check_assertion(app, &challenge, &passkey, &a).map_err(webauthn::Error::code)?;
    // Single use: the same verified assertion never signs in twice.
    if !app.admin_ui.auth.login.spend(challenge, util::now_unix()) {
        return Err("challenge");
    }
    let token = util::b64url(&util::random_bytes::<32>());
    let t = token.clone();
    app.store
        .call(move |c| {
            let now = util::now_unix();
            let tx = c.transaction()?;
            store::record_use(&tx, &passkey, asserted.sign_count, asserted.backup_state, now)?;
            store::session_create(&tx, &t, &passkey.id, now)?;
            audit::append(&tx, &web_record(format!("web:{}", passkey.label), "admin_ui.login", vec![], "ok", ip))?;
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(|_| "store")?;
    Ok(token)
}

/// `POST /admin/logout`: ends this session.
pub async fn logout(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>) -> Response {
    let _ = run_action(&app, &s, AdminRequest::SessionsRevoke { id: Some(s.id.clone()) }).await;
    logout_redirect()
}

/// To the sign-in page, with the session cookie cleared.
pub fn logout_redirect() -> Response {
    let mut r = Redirect::to("/admin/login").into_response();
    r.headers_mut().insert(header::SET_COOKIE, clear_cookie());
    r
}

// ------------------------------------------------------------------ enrolment

pub async fn enrol_page() -> Response {
    html::respond(html::enrol_page())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolOptions {
    token: String,
}

const LINK_INVALID: &str = "This enrolment link is invalid, used or expired. Ask for a new one with: sudo dove admin passkey add --name <name>";

pub async fn enrol_options(
    State(app): State<Arc<App>>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    body: Bytes,
) -> Response {
    let Some((rp_id, _)) = rp(&app) else { return json_error(StatusCode::NOT_FOUND, "not found") };
    let token = match serde_json::from_slice::<EnrolOptions>(&body) {
        Ok(o) if plausible_token(&o.token) => o.token,
        _ => {
            return refused_json(login_failed(&app, ip, StatusCode::BAD_REQUEST), LINK_INVALID);
        }
    };
    let t = token.clone();
    let label = match app.store.call(move |c| store::enrolment_label(c, &t, util::now_unix())).await {
        Ok(Some(l)) => l,
        _ => {
            return refused_json(login_failed(&app, ip, StatusCode::NOT_FOUND), LINK_INVALID);
        }
    };
    let challenge = util::random_bytes::<32>();
    let user_handle = util::random_bytes::<16>();
    let id = new_ceremony_id();
    let options = json!({ "id": id, "name": label, "publicKey": {
        "rp": { "id": rp_id, "name": "Dove" },
        "user": { "id": util::b64url(&user_handle), "name": format!("dove-{label}"),
                  "displayName": format!("Dove admin ({label})") },
        "challenge": util::b64url(&challenge),
        "pubKeyCredParams": [ { "type": "public-key", "alg": webauthn::ALG_ES256 },
                              { "type": "public-key", "alg": webauthn::ALG_EDDSA } ],
        "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true,
                                    "userVerification": "required" },
        "attestation": "none",
        "timeout": CEREMONY_TIMEOUT_MS,
    }});
    app.admin_ui.auth.enrol.put_evicting(
        ENROL_POOL,
        ENROL_TTL,
        id,
        EnrolPending { challenge, token, label, user_handle },
    );
    Json(options).into_response()
}

pub async fn enrol_finish(
    State(app): State<Arc<App>>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    body: Bytes,
) -> Response {
    match enrol_check(&app, &body, ip).await {
        Ok(token) => {
            tracing::info!("admin UI passkey enrolled");
            let mut r = Json(json!({ "redirect": "/admin" })).into_response();
            r.headers_mut().insert(header::SET_COOKIE, set_cookie(&token));
            r
        }
        Err(code) => {
            let status = login_failed(&app, ip, StatusCode::BAD_REQUEST);
            tracing::info!(reason = code, "admin UI enrolment refused");
            audit_web(&app, "web".into(), "admin_ui.enrol", "denied", ip).await;
            let msg = match code {
                "challenge" | "link" => LINK_INVALID,
                "duplicate" => "This passkey or name is already enrolled.",
                _ => "The passkey could not be enrolled. Use a passkey with a PIN, fingerprint or face check.",
            };
            refused_json(status, msg)
        }
    }
}

async fn enrol_check(app: &Arc<App>, body: &[u8], ip: Option<IpAddr>) -> Result<String, &'static str> {
    let f: Finish<RegistrationJson> = serde_json::from_slice(body).map_err(|_| "body")?;
    let p = app.admin_ui.auth.enrol.take(&f.id).ok_or("challenge")?;
    let (rp_id, origin) = rp(app).ok_or("config")?;
    let cdj = b64(&f.credential.client_data_json).ok_or("encoding")?;
    let ao = b64(&f.credential.attestation_object).ok_or("encoding")?;
    let claimed = b64(&f.credential.id).ok_or("encoding")?;
    let cred = webauthn::verify_registration(RelyingParty { id: &rp_id, origin: &origin }, &p.challenge, &cdj, &ao)
        .map_err(webauthn::Error::code)?;
    if claimed != cred.credential_id {
        return Err("credential_id");
    }
    let token = util::b64url(&util::random_bytes::<32>());
    let t = token.clone();
    app.store
        .call(move |c| {
            let now = util::now_unix();
            let tx = c.transaction()?;
            let id = match store::finish_enrolment(&tx, &p.token, &p.label, &p.user_handle, &cred, now) {
                Ok(id) => id,
                Err(e) => {
                    let code = if e.to_string().contains("already enrolled") { "duplicate" } else { "link" };
                    return Ok(Err(code));
                }
            };
            store::session_create(&tx, &t, &id, now)?;
            let actor = format!("web:{}", p.label);
            audit::append(&tx, &web_record(actor, "admin_ui.enrol", vec![p.label.clone()], "ok", ip))?;
            tx.commit()?;
            Ok(Ok(()))
        })
        .await
        .map_err(|_| "store")??;
    Ok(token)
}

// ------------------------------------------------------------------ step-up

/// Starts a passkey confirmation of `action` for this session. Answers JSON for the page's script:
/// `{ stepup: { id, publicKey } }`. `return_to` is where the browser goes after the action ran.
pub async fn begin_stepup(app: &Arc<App>, s: &WebSession, action: AdminRequest, return_to: String) -> Response {
    if !needs_step_up(&action) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal: this action has no confirmation step");
    }
    let Some((rp_id, _)) = rp(app) else { return json_error(StatusCode::NOT_FOUND, "not found") };
    let pid = s.passkey_id.clone();
    let Ok(Some(passkey)) = app.store.call(move |c| store::passkey_by_id(c, &pid)).await else {
        return json_error(StatusCode::UNAUTHORIZED, "sign in again");
    };
    let Ok(canonical) = serde_json::to_vec(&action) else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
    };
    let mut h = Sha256::new();
    h.update(util::random_bytes::<32>());
    h.update(&canonical);
    let challenge: [u8; 32] = h.finalize().into();
    let id = new_ceremony_id();
    let session_id = s.id.clone();
    let entry = StepUp { challenge, session_id: s.id.clone(), passkey_id: s.passkey_id.clone(), action, return_to };
    let stored = app.admin_ui.auth.stepup.put_bounded(
        STEPUP_POOL,
        STEPUP_TTL,
        id.clone(),
        entry,
        |e| e.session_id == session_id,
        STEPUP_PER_SESSION,
    );
    if !stored {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many confirmations are open. Try again in two minutes.",
        );
    }
    Json(json!({ "stepup": { "id": id, "publicKey": {
        "challenge": util::b64url(&challenge), "rpId": rp_id, "userVerification": "required",
        "timeout": CEREMONY_TIMEOUT_MS,
        "allowCredentials": [ { "type": "public-key", "id": util::b64url(&passkey.credential_id) } ],
    }}}))
    .into_response()
}

const CONFIRM_FAILED: &str = "The passkey confirmation failed. Nothing was changed. Try again.";

/// `POST /admin/stepup`: checks the assertion against the pending entry and runs its stored action.
pub async fn stepup_finish(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    body: Bytes,
) -> Response {
    let f: Finish<AssertionJson> = match serde_json::from_slice(&body) {
        Ok(f) => f,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, CONFIRM_FAILED),
    };
    // Taken out before anything is checked: one attempt per challenge.
    let Some(p) = app.admin_ui.auth.stepup.take(&f.id) else {
        return json_error(StatusCode::CONFLICT, "This confirmation expired or was already used. Nothing was changed.");
    };
    let checked = async {
        if p.session_id != s.id || p.passkey_id != s.passkey_id {
            return Err("session");
        }
        let a = f.credential.decode().ok_or("encoding")?;
        let pid = p.passkey_id.clone();
        let passkey =
            app.store.call(move |c| store::passkey_by_id(c, &pid)).await.map_err(|_| "store")?.ok_or("passkey")?;
        let asserted = check_assertion(&app, &p.challenge, &passkey, &a).map_err(webauthn::Error::code)?;
        app.store
            .call(move |c| store::record_use(c, &passkey, asserted.sign_count, asserted.backup_state, util::now_unix()))
            .await
            .map_err(|_| "store")?;
        Ok(())
    }
    .await;
    if let Err(code) = checked {
        tracing::info!(reason = code, "admin UI confirmation refused");
        audit_web(&app, format!("web:{}", s.label), "admin_ui.stepup", "denied", ip).await;
        return json_error(StatusCode::FORBIDDEN, CONFIRM_FAILED);
    }
    let r = crate::admin::server::dispatch(&app, &s.actor(), p.action).await;
    if r.ok {
        Json(json!({ "redirect": p.return_to })).into_response()
    } else {
        json_error(StatusCode::CONFLICT, r.error.as_deref().unwrap_or("the action failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pools_are_single_use_bounded_and_expire() {
        let p: Pool<u32> = Pool::default();
        for i in 0..10 {
            p.put_evicting(4, Duration::from_secs(60), format!("id{i}"), i);
        }
        assert_eq!(p.len(), 4, "the oldest went");
        assert_eq!(p.take("id0"), None);
        assert_eq!(p.take("id9"), Some(9));
        assert_eq!(p.take("id9"), None, "single use");
        p.put_evicting(4, Duration::ZERO, "gone".into(), 1);
        assert_eq!(p.take("gone"), None, "expired");

        let b: Pool<(u32, u32)> = Pool::default();
        for i in 0..6 {
            assert!(b.put_bounded(5, Duration::from_secs(60), format!("a{i}"), (1, i), |v| v.0 == 1, 2));
        }
        assert_eq!(b.len(), 2, "two per owner");
        assert_eq!(b.take("a5"), Some((1, 5)));
        for i in 0..4 {
            assert!(b.put_bounded(5, Duration::from_secs(60), format!("b{i}"), (2 + i, 0), |v| v.0 == 2 + i, 2));
        }
        assert!(!b.put_bounded(5, Duration::from_secs(60), "c".into(), (9, 0), |v| v.0 == 9, 2), "full: refused");
    }

    #[test]
    fn login_challenges_are_bound_to_this_process_expire_and_are_spent_once() {
        let l = LoginChallenges::default();
        let (id, ch) = l.issue(1000);
        assert_eq!(l.open(&id, 1000), Some(ch));
        assert_eq!(l.open(&id, 1000 + LOGIN_TTL_SECS - 1), Some(ch), "opening spends nothing");
        assert_eq!(l.open(&id, 1000 + LOGIN_TTL_SECS), None, "expired");
        // Every part is under the MAC: the challenge, the expiry and the MAC itself.
        let raw = b64(&id).unwrap();
        assert_eq!(raw.len(), 72);
        for i in [0, 31, 32, 39, 40, 71] {
            let mut bent = raw.clone();
            bent[i] ^= 1;
            assert_eq!(l.open(&util::b64url(&bent), 1000), None, "byte {i}");
        }
        assert_eq!(l.open(&util::b64url(&raw[..71]), 1000), None);
        assert_eq!(l.open("", 1000), None);
        // Another process (another key) does not accept it.
        assert_eq!(LoginChallenges::default().open(&id, 1000), None);
        // Spent once, then closed until it would have expired anyway.
        assert!(l.spend(ch, 1001));
        assert!(!l.spend(ch, 1002), "spent twice");
        assert_eq!(l.open(&id, 1003), None, "spent");
        // The list only holds verified sign-ins; full, it refuses instead of forgetting one.
        let full = LoginChallenges::default();
        for i in 0..LOGIN_SPENT_CAP {
            let mut c = [0u8; 32];
            c[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(full.spend(c, 1000));
        }
        assert!(!full.spend([0xff; 32], 1000), "full");
        assert!(full.spend([0xff; 32], 1000 + LOGIN_TTL_SECS), "expired entries make room");
    }

    #[test]
    fn cookies_and_csrf() {
        let tok = util::b64url(&[5u8; 32]);
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, format!("a=b; {COOKIE}={tok}").parse().unwrap());
        assert_eq!(cookie_token(&h), Some(tok.clone()));
        h.append(header::COOKIE, format!("{COOKIE}={tok}").parse().unwrap());
        assert_eq!(cookie_token(&h), None, "two session cookies count as none");
        let mut bad = HeaderMap::new();
        bad.append(header::COOKIE, format!("{COOKIE}=short").parse().unwrap());
        assert_eq!(cookie_token(&bad), None);
        let csrf = csrf_for(&tok);
        assert_ne!(csrf, tok);
        assert_ne!(csrf, csrf_for(&util::b64url(&[6u8; 32])));
        let s =
            WebSession { id: "s".into(), passkey_id: "p".into(), label: "l".into(), expires_at: 0, csrf: csrf.clone() };
        assert!(csrf_matches(&s, &csrf));
        assert!(!csrf_matches(&s, &csrf[..42]));
        assert!(!csrf_matches(&s, ""));
    }
}
