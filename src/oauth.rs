//! Downstream OAuth authorization server for MCP hosts (spec 5.6).
//!
//! Dove is both the protected resource (`/mcp`) and its authorization server. Authority never comes from OAuth
//! itself: the browser approval consumes an operator-issued invitation, which creates one `kind = 'oauth'`
//! connection with the invited (or narrowed) grants. Codes and tokens only point at that connection, so a refresh
//! cannot broaden the account/action intersection, and revoking the connection kills every token at once.
//!
//! Profile: authorization code + PKCE S256 only, exact redirect URI match, single-use codes (60 s default), tokens
//! bound to the `/mcp` resource, rotating refresh tokens with reuse detection, dynamic registration (RFC 7591)
//! without authority, revocation (RFC 7009), metadata per RFC 8414 and RFC 9728, `iss` in the response (RFC 9207).
//! Hand-rolled: see docs/PLAN.md A17 for why no OAuth server crate is used.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::app::App;
use crate::config::OAuthConfig;
use crate::http::{html_escape, page};
use crate::invite::{self, audit_auth};
use crate::policy::Actions;
use crate::tokens::{self, Pepper};
use crate::util;

pub const AUTHORIZE_PATH: &str = "/oauth/dove/authorize";
pub const SCOPE: &str = "mail";
const CSRF_COOKIE: &str = "__Host-dove_authz";
const PENDING_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 10_000;
/// Open sign-in requests per source IP, so one client cannot crowd out everyone else.
const MAX_PENDING_PER_IP: usize = 20;
const MAX_INVITATION_ATTEMPTS: u32 = 5;
const DCR_STALE_SECS: i64 = 86_400;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(protected_resource))
        .route("/.well-known/oauth-protected-resource/mcp", get(protected_resource))
        .route("/.well-known/oauth-authorization-server", get(authorization_server))
        .route(AUTHORIZE_PATH, get(authorize_get).post(authorize_post))
        .route("/oauth/dove/token", post(token))
        .route("/oauth/dove/register", post(register))
        .route("/oauth/dove/revoke", post(revoke))
        .route("/connect/redeem", post(invite::redeem))
}

// ------------------------------------------------------------------ state

/// A registered application: pre-registered in the config file or dynamically registered (public client).
#[derive(Clone)]
pub struct OAuthApp {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub secret: Option<Arc<Zeroizing<String>>>,
    pub dynamic: bool,
}

/// An authorization request waiting for the user's decision on the approval page. Memory only, bounded.
struct Pending {
    app: OAuthApp,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    resource: String,
    csrf: String,
    binding: String,
    invitation_id: Option<String>,
    attempts: u32,
    created: Instant,
    ip_bucket: String,
}

pub struct OAuthState {
    pending: Mutex<HashMap<String, Pending>>,
    preregistered: Vec<OAuthApp>,
    registrations: Mutex<HashMap<String, (u32, Instant)>>,
}

impl OAuthState {
    /// Loads pre-registered applications and their secret files (strict modes, spec 6.4).
    pub fn load(cfg: &OAuthConfig) -> anyhow::Result<Self> {
        let mut preregistered = Vec::new();
        for c in &cfg.clients {
            let secret = match &c.secret_file {
                Some(f) => Some(Arc::new(crate::secrets::read_secret_string(f)?)),
                None => None,
            };
            preregistered.push(OAuthApp {
                client_id: c.client_id.clone(),
                client_name: c.client_name.clone(),
                redirect_uris: c.redirect_uris.clone(),
                secret,
                dynamic: false,
            });
        }
        Ok(Self { pending: Mutex::default(), preregistered, registrations: Mutex::default() })
    }

    /// Fixed-window counter per key; true when allowed.
    fn allow_registration(&self, key: &str, per_hour: u32) -> bool {
        let mut map = self.registrations.lock().expect("lock");
        let now = Instant::now();
        map.retain(|_, (_, start)| now.duration_since(*start) < Duration::from_secs(3600));
        let e = map.entry(key.to_string()).or_insert((0, now));
        e.0 += 1;
        e.0 <= per_hour
    }
}

fn find_app(app: &App, conn: &Connection, client_id: &str) -> anyhow::Result<Option<OAuthApp>> {
    if let Some(a) = app.oauth.preregistered.iter().find(|a| a.client_id == client_id) {
        return Ok(Some(a.clone()));
    }
    let row = conn
        .query_row(
            "SELECT client_name, redirect_uris FROM oauth_apps WHERE client_id = ?1 AND registered_via = 'dynamic'",
            [client_id],
            |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?;
    Ok(row.map(|(name, uris)| OAuthApp {
        client_id: client_id.to_string(),
        client_name: name.unwrap_or_else(|| "Unnamed application".into()),
        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
        secret: None,
        dynamic: true,
    }))
}

// ------------------------------------------------------------------ helpers

/// Redirect URIs: HTTPS with a host, or HTTP on a loopback host (native clients such as CLI hosts, RFC 8252).
/// No fragments, no user info, at most 512 bytes. Custom schemes are not supported.
pub fn validate_redirect_uri(u: &str) -> Result<(), String> {
    if u.len() > 512 {
        return Err("redirect URI too long".into());
    }
    let url = url::Url::parse(u).map_err(|_| format!("redirect URI '{u}' is not a URL"))?;
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err("redirect URI must not contain a fragment or user info".into());
    }
    let host = url.host_str().unwrap_or("");
    match url.scheme() {
        "https" if !host.is_empty() => Ok(()),
        "http" if matches!(host, "localhost" | "127.0.0.1" | "[::1]") => Ok(()),
        _ => Err(format!("redirect URI '{u}' must be https, or http on a loopback host")),
    }
}

/// Parses `application/x-www-form-urlencoded` (query or body). Repeated parameters are rejected (RFC 6749 3.1).
fn parse_params(raw: &[u8]) -> Option<HashMap<String, String>> {
    let mut out = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(raw) {
        if out.insert(k.into_owned(), v.into_owned()).is_some() {
            return None;
        }
    }
    Some(out)
}

fn peer_ip(req: &Request) -> Option<IpAddr> {
    crate::http::request_ip(req)
}

#[allow(clippy::result_large_err)] // the error is the finished HTTP response
async fn split(req: Request, limit: usize) -> Result<(HeaderMap, Option<IpAddr>, Bytes), Response> {
    let ip = peer_ip(&req);
    let (parts, body) = req.into_parts();
    match axum::body::to_bytes(body, limit).await {
        Ok(b) => Ok((parts.headers, ip, b)),
        Err(_) => Err(oauth_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request", "request too large")),
    }
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.headers_mut().insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    no_store((status, axum::Json(json!({ "error": error, "error_description": description }))).into_response())
}

fn rate_limited(wait: u64) -> Response {
    let mut r = oauth_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many requests");
    r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(wait));
    r
}

/// Rate-limit bucket of a source address: IPv4 as is, IPv6 by its /64, since one host usually controls a whole
/// /64 and could otherwise rotate addresses to get fresh limits.
pub fn ip_bucket(ip: Option<IpAddr>) -> String {
    match ip {
        Some(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Some(IpAddr::V6(v6)) => v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_default(),
        Some(IpAddr::V4(v4)) => v4.to_string(),
        None => String::new(),
    }
}

fn ip_key(prefix: &str, ip: Option<IpAddr>) -> String {
    format!("{prefix}:{}", ip_bucket(ip))
}

fn issuer(app: &App) -> String {
    app.cfg.public_base()
}

fn pkce_s256(verifier: &str) -> String {
    util::b64url(&Sha256::digest(verifier.as_bytes()))
}

/// RFC 7636: 43-128 characters from the unreserved set.
fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

fn valid_challenge(c: &str) -> bool {
    c.len() == 43 && c.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ------------------------------------------------------------------ metadata

/// RFC 9728 protected resource metadata for `/mcp`.
async fn protected_resource(State(app): State<Arc<App>>) -> Response {
    let base = issuer(&app);
    axum::Json(json!({
        "resource": crate::mcp::resource_url(&app),
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [SCOPE],
        "resource_name": "Dove mail",
    }))
    .into_response()
}

/// RFC 8414 authorization server metadata. The issuer is the public origin, so the path has no suffix.
async fn authorization_server(State(app): State<Arc<App>>) -> Response {
    let base = issuer(&app);
    axum::Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}{AUTHORIZE_PATH}"),
        "token_endpoint": format!("{base}/oauth/dove/token"),
        "registration_endpoint": format!("{base}/oauth/dove/register"),
        "revocation_endpoint": format!("{base}/oauth/dove/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "scopes_supported": [SCOPE],
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}

// ------------------------------------------------------------------ authorize (browser)

fn html(status: StatusCode, body: String, form_target: Option<&str>) -> Response {
    let mut r = (status, Html(body)).into_response();
    // Chrome applies form-action to the redirect after a form post, so the client's redirect origin is allowed.
    let form_action = match form_target {
        Some(o) => format!("'self' {o}"),
        None => "'self'".into(),
    };
    let csp = format!(
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action {form_action}"
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, v);
    }
    r.headers_mut().insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    no_store(r)
}

fn error_page(status: StatusCode, msg: &str) -> Response {
    html(status, page("Cannot continue", &format!("<p>{}</p>", html_escape(msg))), None)
}

fn origin_of(uri: &str) -> Option<String> {
    url::Url::parse(uri).ok().map(|u| u.origin().ascii_serialization())
}

/// Redirects back to the (already validated) client redirect URI with the given parameters.
fn redirect_to(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return error_page(StatusCode::BAD_REQUEST, "invalid redirect URI");
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
    }
    let mut r = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(url.as_str()) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    no_store(r)
}

fn redirect_error(app: &App, redirect_uri: &str, state: Option<&str>, error: &str, description: &str) -> Response {
    let iss = issuer(app);
    let mut p = vec![("error", error), ("error_description", description), ("iss", iss.as_str())];
    if let Some(s) = state {
        p.push(("state", s));
    }
    redirect_to(redirect_uri, &p)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn app_description(a: &OAuthApp, redirect_uri: &str) -> String {
    let host = url::Url::parse(redirect_uri).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    format!(
        "<p>Application: <b>{}</b><br>Client ID: <code>{}</code><br>Returns to: <code>{}</code><br>Registered: {}</p>\
         <p>Registering an application grants nothing. Access comes only from an invitation issued by the operator \
         of this Dove server, and this page can only keep or reduce the rights in it.</p>",
        html_escape(&a.client_name),
        html_escape(&a.client_id),
        html_escape(&host),
        if a.dynamic { "automatically by the application" } else { "by the operator" }
    )
}

fn hidden(rid: &str, csrf: &str, step: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"rid\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <input type=\"hidden\" name=\"step\" value=\"{}\">",
        html_escape(rid),
        html_escape(csrf),
        step
    )
}

fn invitation_page(p: &Pending, rid: &str, error: Option<&str>) -> Response {
    let err = error.map(|e| format!("<p role=\"alert\"><b>{}</b></p>", html_escape(e))).unwrap_or_default();
    let body = format!(
        "{app}{err}<form method=\"post\" action=\"{AUTHORIZE_PATH}\">{hidden}\
         <p><label>One-time invitation from your Dove operator<br>\
         <input name=\"invitation\" type=\"password\" autocomplete=\"off\" spellcheck=\"false\" size=\"40\"></label></p>\
         <p><button name=\"action\" value=\"continue\">Continue</button> \
         <button name=\"action\" value=\"cancel\">Cancel</button></p></form>",
        app = app_description(&p.app, &p.redirect_uri),
        hidden = hidden(rid, &p.csrf, "invitation"),
    );
    html(StatusCode::OK, page("Connect to Dove", &body), origin_of(&p.redirect_uri).as_deref())
}

fn approval_page(p: &Pending, rid: &str, inv: &invite::Invitation, error: Option<&str>) -> Response {
    let err = error.map(|e| format!("<p role=\"alert\"><b>{}</b></p>", html_escape(e))).unwrap_or_default();
    let mut rows = String::new();
    for (i, g) in inv.grants.iter().enumerate() {
        let a = Actions::parse(&g.actions).unwrap_or_default();
        rows.push_str(&format!(
            "<li><label><input type=\"checkbox\" name=\"read.{i}\" checked> <b>{}</b>: read</label>",
            html_escape(&g.alias)
        ));
        if a.draft {
            rows.push_str(&format!(
                " <label><input type=\"checkbox\" name=\"draft.{i}\" checked> create and edit drafts</label>"
            ));
        }
        if a.send {
            rows.push_str(&format!(
                " <label><input type=\"checkbox\" name=\"send.{i}\" checked> send own drafts</label>"
            ));
        }
        rows.push_str("</li>");
    }
    let body = format!(
        "{app}{err}<p>Project: <b>{project}</b><br>Connection name: <b>{conn}</b></p>\
         <form method=\"post\" action=\"{AUTHORIZE_PATH}\">{hidden}\
         <p>Mailboxes and actions this application may use:</p><ul>{rows}</ul>\
         <p><button name=\"action\" value=\"approve\">Approve</button> \
         <button name=\"action\" value=\"cancel\">Deny</button></p></form>",
        app = app_description(&p.app, &p.redirect_uri),
        project = html_escape(&inv.project_name),
        conn = html_escape(&inv.connection_name),
        hidden = hidden(rid, &p.csrf, "approve"),
    );
    html(StatusCode::OK, page("Approve access", &body), origin_of(&p.redirect_uri).as_deref())
}

/// GET `/oauth/dove/authorize`: validates the request and shows the invitation form.
async fn authorize_get(State(app): State<Arc<App>>, req: Request) -> Response {
    let ip = peer_ip(&req);
    let limit = app.cfg.oauth.token_requests_per_minute;
    if app.rate_limiter.check(&ip_key("authorize", ip), limit, limit).is_some() {
        return error_page(StatusCode::TOO_MANY_REQUESTS, "Too many sign-in requests. Wait a minute and try again.");
    }
    let headers = req.headers().clone();
    let query = req.uri().query().unwrap_or("").to_string();
    let Some(q) = parse_params(query.as_bytes()) else {
        return error_page(StatusCode::BAD_REQUEST, "The authorization request repeats a parameter.");
    };
    let client_id = q.get("client_id").cloned().unwrap_or_default();
    let app2 = app.clone();
    let found = app.store.call(move |c| find_app(&app2, c, &client_id)).await;
    let a = match found {
        Ok(Some(a)) => a,
        Ok(None) => return error_page(StatusCode::BAD_REQUEST, "Unknown application (client_id)."),
        Err(e) => {
            tracing::error!(error = %e, "oauth app lookup failed");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Internal error.");
        }
    };
    // Without an exactly registered redirect URI there is nowhere safe to send errors (RFC 6749 4.1.2.1).
    let Some(redirect_uri) = q.get("redirect_uri").filter(|r| a.redirect_uris.iter().any(|u| u == *r)).cloned() else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "The redirect URI is missing or not registered for this application.",
        );
    };
    let state = q.get("state").cloned();
    if state.as_ref().is_some_and(|s| s.len() > 512) {
        return error_page(StatusCode::BAD_REQUEST, "The state parameter is too long.");
    }
    let fail = |e: &str, d: &str| redirect_error(&app, &redirect_uri, state.as_deref(), e, d);
    if q.get("response_type").map(String::as_str) != Some("code") {
        return fail("unsupported_response_type", "only response_type=code is supported");
    }
    let challenge = q.get("code_challenge").cloned().unwrap_or_default();
    if q.get("code_challenge_method").map(String::as_str) != Some("S256") || !valid_challenge(&challenge) {
        return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
    }
    let resource_url = crate::mcp::resource_url(&app);
    let resource = q.get("resource").cloned().unwrap_or_else(|| resource_url.clone());
    if resource != resource_url {
        return fail("invalid_target", "resource must be this server's MCP endpoint");
    }
    // Scopes carry no authority here (the invitation does); unknown values are ignored, never granted.
    let binding = cookie_value(&headers, CSRF_COOKIE)
        .filter(|v| v.len() == 22 && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
        .unwrap_or_else(util::new_id);
    let rid = util::new_id();
    let pending = Pending {
        app: a,
        redirect_uri,
        state,
        code_challenge: challenge,
        resource,
        csrf: util::new_id(),
        binding: binding.clone(),
        invitation_id: None,
        attempts: 0,
        created: Instant::now(),
        ip_bucket: ip_bucket(ip),
    };
    let mut resp = invitation_page(&pending, &rid, None);
    {
        let mut map = app.oauth.pending.lock().expect("lock");
        map.retain(|_, p| p.created.elapsed() < PENDING_TTL);
        let bucket = ip_bucket(ip);
        if map.values().filter(|p| p.ip_bucket == bucket).count() >= MAX_PENDING_PER_IP {
            return error_page(StatusCode::TOO_MANY_REQUESTS, "Too many open sign-in requests. Try again later.");
        }
        if map.len() >= MAX_PENDING {
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Too many open sign-in requests. Try again later.");
        }
        map.insert(rid, pending);
    }
    let cookie = format!("{CSRF_COOKIE}={binding}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600");
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// POST `/oauth/dove/authorize`: invitation check (step 1) and approval (step 2). CSRF: the form token must match
/// the pending request and the browser-binding cookie; foreign `Origin` headers are refused by the HTTP guard.
async fn authorize_post(State(app): State<Arc<App>>, req: Request) -> Response {
    let (headers, ip, body) = match split(req, 16 * 1024).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(form) = parse_params(&body) else {
        return error_page(StatusCode::BAD_REQUEST, "The form repeats a field.");
    };
    let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
    let rid = get("rid").to_string();
    let cookie = cookie_value(&headers, CSRF_COOKIE).unwrap_or_default();
    // Take the pending request out while working on it; it is put back when the flow continues.
    let pending = {
        let mut map = app.oauth.pending.lock().expect("lock");
        match map.get(&rid) {
            Some(p)
                if p.created.elapsed() < PENDING_TTL
                    && ct_eq(&p.csrf, get("csrf"))
                    && !cookie.is_empty()
                    && ct_eq(&p.binding, &cookie) =>
            {
                map.remove(&rid)
            }
            _ => None,
        }
    };
    let Some(mut p) = pending else {
        return error_page(
            StatusCode::FORBIDDEN,
            "This sign-in request is unknown, expired or was not started in this browser. Start again from the application.",
        );
    };
    if get("action") == "cancel" {
        return redirect_error(&app, &p.redirect_uri, p.state.as_deref(), "access_denied", "the user denied access");
    }
    let put_back = |p: Pending| {
        app.oauth.pending.lock().expect("lock").insert(rid.clone(), p);
    };
    match (get("step"), p.invitation_id.clone()) {
        ("invitation", _) => {
            let limit = app.cfg.oauth.redeem_per_minute;
            if app.rate_limiter.check(&ip_key("redeem", ip), limit, limit).is_some() {
                let r = invitation_page(&p, &rid, Some("Too many attempts. Wait a minute and try again."));
                put_back(p);
                return r;
            }
            p.attempts += 1;
            let secret = Zeroizing::new(get("invitation").to_string());
            let pepper = app.pepper.clone();
            let found = app.store.call(move |c| invite::peek(c, &pepper, &secret)).await;
            match found {
                Ok(Some(inv)) if !inv.grants.is_empty() => {
                    p.invitation_id = Some(inv.id.clone());
                    let r = approval_page(&p, &rid, &inv, None);
                    put_back(p);
                    r
                }
                Ok(_) if p.attempts >= MAX_INVITATION_ATTEMPTS => error_page(
                    StatusCode::FORBIDDEN,
                    "Too many invalid invitations for this request. Start again from the application.",
                ),
                Ok(_) => {
                    let r = invitation_page(&p, &rid, Some("This invitation is invalid, expired or already used."));
                    put_back(p);
                    r
                }
                Err(e) => {
                    tracing::error!(error = %e, "invitation lookup failed");
                    error_page(StatusCode::INTERNAL_SERVER_ERROR, "Internal error.")
                }
            }
        }
        ("approve", Some(inv_id)) if get("action") == "approve" => {
            approve(&app, p, rid.clone(), inv_id, &form, ip).await
        }
        _ => error_page(StatusCode::BAD_REQUEST, "Unexpected form submission."),
    }
}

enum Approval {
    Done { code: String },
    InvitationGone,
    NothingSelected(invite::Invitation),
}

async fn approve(
    app: &Arc<App>,
    p: Pending,
    rid: String,
    inv_id: String,
    form: &HashMap<String, String>,
    ip: Option<IpAddr>,
) -> Response {
    let pepper = app.pepper.clone();
    let (app_client_id, redirect_uri, challenge, resource) =
        (p.app.client_id.clone(), p.redirect_uri.clone(), p.code_challenge.clone(), p.resource.clone());
    let code_ttl = app.cfg.oauth.code_ttl_secs;
    let form = form.clone();
    let result = app
        .store
        .call(move |c| {
            let checked = |k: String| form.get(&k).is_some_and(|v| v == "on");
            let tx = c.transaction()?;
            let Some(inv) = invite::load(&tx, &inv_id)? else {
                return Ok(Approval::InvitationGone);
            };
            let mut selected = BTreeMap::new();
            for (i, g) in inv.grants.iter().enumerate() {
                let a = Actions {
                    read: checked(format!("read.{i}")),
                    draft: checked(format!("draft.{i}")),
                    send: checked(format!("send.{i}")),
                };
                selected.insert(g.account_id.clone(), a);
            }
            let grants = invite::narrow(&inv.grants, &selected);
            if grants.is_empty() {
                return Ok(Approval::NothingSelected(inv));
            }
            let via = format!("oauth:{app_client_id}");
            let Some((connection_id, _)) = invite::consume(&tx, &pepper, &inv, &grants, "oauth", &via)? else {
                return Ok(Approval::InvitationGone);
            };
            let code = tokens::generate(tokens::OAUTH_CODE_PREFIX);
            tx.execute(
                "INSERT INTO oauth_codes(code_hash, app_client_id, connection_id, redirect_uri, code_challenge, resource, \
                 expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    pepper.hash("oauth-code", &code),
                    app_client_id,
                    connection_id,
                    redirect_uri,
                    challenge,
                    resource,
                    util::now_unix() + code_ttl
                ],
            )?;
            audit_auth(
                &tx,
                "oauth.approve",
                &inv.connection_name,
                Some(&inv.project_name),
                vec![inv.connection_name.clone(), app_client_id.clone()],
                "ok",
                ip,
            )?;
            tx.commit()?;
            Ok(Approval::Done { code })
        })
        .await;
    match result {
        Ok(Approval::Done { code }) => {
            let iss = issuer(app);
            let mut params = vec![("code", code.as_str()), ("iss", iss.as_str())];
            if let Some(s) = p.state.as_deref() {
                params.push(("state", s));
            }
            redirect_to(&p.redirect_uri, &params)
        }
        Ok(Approval::NothingSelected(inv)) => {
            let r = approval_page(&p, &rid, &inv, Some("Select at least one mailbox, or deny."));
            app.oauth.pending.lock().expect("lock").insert(rid, p);
            r
        }
        Ok(Approval::InvitationGone) => error_page(
            StatusCode::BAD_REQUEST,
            "The invitation is no longer valid (expired or already used). Ask the operator for a new one.",
        ),
        Err(e) => {
            tracing::error!(error = %e, "oauth approval failed");
            error_page(StatusCode::INTERNAL_SERVER_ERROR, "Internal error.")
        }
    }
}

// ------------------------------------------------------------------ client authentication

struct ClientCreds {
    client_id: String,
    secret: Option<Zeroizing<String>>,
    basic: bool,
}

/// Extracts client credentials: HTTP Basic (RFC 6749 2.3.1), `client_secret` in the body, or a bare `client_id`
/// for public clients. Using two methods at once is an error.
#[allow(clippy::result_large_err)]
fn client_creds(headers: &HeaderMap, form: &HashMap<String, String>) -> Result<ClientCreds, Response> {
    let bad = || oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed");
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")));
    if let Some(b64) = basic {
        let raw = util::b64_decode_any(b64).and_then(|b| String::from_utf8(b).ok()).ok_or_else(bad)?;
        let (id, secret) = raw.split_once(':').ok_or_else(bad)?;
        let dec =
            |s: &str| url::form_urlencoded::parse(format!("x={s}").as_bytes()).next().map(|(_, v)| v.into_owned());
        let (id, secret) = (dec(id).ok_or_else(bad)?, dec(secret).ok_or_else(bad)?);
        if form.contains_key("client_secret") || form.get("client_id").is_some_and(|f| *f != id) {
            return Err(bad());
        }
        return Ok(ClientCreds { client_id: id, secret: Some(Zeroizing::new(secret)), basic: true });
    }
    let id = form.get("client_id").filter(|s| !s.is_empty()).ok_or_else(bad)?;
    let secret = form.get("client_secret").filter(|s| !s.is_empty()).map(|s| Zeroizing::new(s.clone()));
    Ok(ClientCreds { client_id: id.clone(), secret, basic: false })
}

fn verify_client(app: &App, conn: &Connection, creds: &ClientCreds) -> anyhow::Result<Option<OAuthApp>> {
    let Some(a) = find_app(app, conn, &creds.client_id)? else { return Ok(None) };
    let ok = match (&a.secret, &creds.secret) {
        (Some(expected), Some(given)) => ct_eq(expected.as_str(), given.as_str()),
        (None, None) => true,
        _ => false,
    };
    Ok(ok.then_some(a))
}

fn invalid_client(basic: bool) -> Response {
    let mut r = oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed");
    if basic {
        r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"dove\""));
    }
    r
}

// ------------------------------------------------------------------ token endpoint

/// Revokes a connection and every token issued for it (family revocation, spec 5.6). Bumps the auth epoch so
/// cursors issued to the connection become invalid.
pub fn revoke_connection(tx: &Connection, connection_id: &str) -> anyhow::Result<()> {
    let now = util::now_unix();
    tx.execute(
        "UPDATE clients SET revoked_at = COALESCE(revoked_at, ?1), auth_epoch = auth_epoch + 1 WHERE id = ?2",
        params![now, connection_id],
    )?;
    tx.execute(
        "UPDATE oauth_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE connection_id = ?2",
        params![now, connection_id],
    )?;
    Ok(())
}

/// Connection name/project for audit records, and whether it may still receive tokens.
fn connection_info(conn: &Connection, connection_id: &str) -> anyhow::Result<(String, String, bool)> {
    let now = util::now_unix();
    Ok(conn.query_row(
        "SELECT c.name, p.name, c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > ?2) \
         FROM clients c JOIN projects p ON p.id = c.project_id WHERE c.id = ?1",
        params![connection_id, now],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?)
}

struct Issued {
    access: String,
    refresh: String,
    expires_in: i64,
}

fn issue_pair(
    tx: &Transaction,
    pepper: &Pepper,
    cfg: &OAuthConfig,
    connection_id: &str,
    app_client_id: &str,
    resource: &str,
) -> anyhow::Result<Issued> {
    let now = util::now_unix();
    let conn_expiry: Option<i64> =
        tx.query_row("SELECT expires_at FROM clients WHERE id = ?1", [connection_id], |r| r.get(0))?;
    let cap = |t: i64| conn_expiry.map_or(t, |e| t.min(e));
    let access_exp = cap(now + cfg.access_token_ttl_secs);
    let refresh_exp = cap(now + cfg.refresh_token_ttl_secs);
    let access = tokens::generate(tokens::OAUTH_ACCESS_PREFIX);
    let refresh = tokens::generate(tokens::OAUTH_REFRESH_PREFIX);
    // The family is the connection: one approval, one connection, one token family.
    for (kind, secret, purpose, exp) in
        [("access", &access, "oauth-access", access_exp), ("refresh", &refresh, "oauth-refresh", refresh_exp)]
    {
        tx.execute(
            "INSERT INTO oauth_tokens(token_hash, kind, family_id, connection_id, app_client_id, resource, created_at, \
             expires_at) VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7)",
            params![pepper.hash(purpose, secret), kind, connection_id, app_client_id, resource, now, exp],
        )?;
    }
    Ok(Issued { access, refresh, expires_in: (access_exp - now).max(0) })
}

enum TokenOutcome {
    Issued(Issued),
    Error(&'static str, &'static str),
}

/// POST `/oauth/dove/token`: `authorization_code` and `refresh_token` grants.
async fn token(State(app): State<Arc<App>>, req: Request) -> Response {
    let (headers, ip, body) = match split(req, 16 * 1024).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let limit = app.cfg.oauth.token_requests_per_minute;
    if let Some(wait) = app.rate_limiter.check(&ip_key("token", ip), limit, limit.min(30)) {
        return rate_limited(wait);
    }
    let Some(form) = parse_params(&body) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "repeated parameter");
    };
    let creds = match client_creds(&headers, &form) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let grant_type = form.get("grant_type").cloned().unwrap_or_default();
    if grant_type != "authorization_code" && grant_type != "refresh_token" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "use authorization_code or refresh_token",
        );
    }
    let resource_url = crate::mcp::resource_url(&app);
    if form.get("resource").is_some_and(|r| *r != resource_url) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_target", "resource must be this server's MCP endpoint");
    }
    let app2 = app.clone();
    let basic = creds.basic;
    let result = app
        .store
        .call(move |c| {
            let Some(client) = verify_client(&app2, c, &creds)? else {
                return Ok(None);
            };
            let tx = c.transaction()?;
            let out = if grant_type == "authorization_code" {
                exchange_code(&app2, &tx, &client, &form, ip)?
            } else {
                refresh(&app2, &tx, &client, &form, ip)?
            };
            tx.commit()?;
            Ok(Some(out))
        })
        .await;
    match result {
        Ok(None) => invalid_client(basic),
        Ok(Some(TokenOutcome::Issued(t))) => no_store(
            axum::Json(json!({
                "access_token": t.access,
                "token_type": "Bearer",
                "expires_in": t.expires_in,
                "refresh_token": t.refresh,
                "scope": SCOPE,
            }))
            .into_response(),
        ),
        Ok(Some(TokenOutcome::Error(e, d))) => oauth_error(StatusCode::BAD_REQUEST, e, d),
        Err(e) => {
            tracing::error!(error = %e, "token endpoint failed internally");
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "internal error")
        }
    }
}

fn exchange_code(
    app: &App,
    tx: &Transaction,
    client: &OAuthApp,
    form: &HashMap<String, String>,
    ip: Option<IpAddr>,
) -> anyhow::Result<TokenOutcome> {
    let code = form.get("code").map(String::as_str).unwrap_or("");
    if !tokens::looks_valid(tokens::OAUTH_CODE_PREFIX, code) {
        return Ok(TokenOutcome::Error("invalid_grant", "invalid authorization code"));
    }
    let hash = app.pepper.hash("oauth-code", code);
    let row = tx
        .query_row(
            "SELECT app_client_id, connection_id, redirect_uri, code_challenge, resource, expires_at, used_at \
             FROM oauth_codes WHERE code_hash = ?1",
            [&hash],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((app_client_id, connection_id, redirect_uri, challenge, resource, expires_at, used_at)) = row else {
        audit_auth(tx, "oauth.token", "anonymous", None, vec![client.client_id.clone()], "invalid_grant", ip)?;
        return Ok(TokenOutcome::Error("invalid_grant", "invalid authorization code"));
    };
    let (name, project, _) = connection_info(tx, &connection_id)?;
    let audit = |code: &str| {
        audit_auth(tx, "oauth.token", &name, Some(&project), vec![name.clone(), client.client_id.clone()], code, ip)
    };
    if used_at.is_some() {
        // A replayed code: revoke everything issued from it (RFC 6749 4.1.2).
        revoke_connection(tx, &connection_id)?;
        audit("code_reuse_revoked")?;
        return Ok(TokenOutcome::Error("invalid_grant", "invalid authorization code"));
    }
    // Single use even when the exchange fails below.
    tx.execute("UPDATE oauth_codes SET used_at = ?1 WHERE code_hash = ?2", params![util::now_unix(), hash])?;
    let verifier = form.get("code_verifier").map(String::as_str).unwrap_or("");
    let failure = if expires_at <= util::now_unix() {
        Some(("invalid_grant", "authorization code expired"))
    } else if app_client_id != client.client_id {
        Some(("invalid_grant", "authorization code was issued to another client"))
    } else if form.get("redirect_uri") != Some(&redirect_uri) {
        Some(("invalid_grant", "redirect_uri does not match the authorization request"))
    } else if !valid_verifier(verifier) || !ct_eq(&pkce_s256(verifier), &challenge) {
        Some(("invalid_grant", "PKCE verification failed"))
    } else if form.get("resource").is_some_and(|r| *r != resource) {
        Some(("invalid_target", "resource does not match the authorization request"))
    } else {
        None
    };
    if let Some((e, d)) = failure {
        audit(e)?;
        return Ok(TokenOutcome::Error(e, d));
    }
    if !connection_info(tx, &connection_id)?.2 {
        audit("connection_revoked")?;
        return Ok(TokenOutcome::Error("invalid_grant", "the connection was revoked or expired"));
    }
    let issued = issue_pair(tx, &app.pepper, &app.cfg.oauth, &connection_id, &client.client_id, &resource)?;
    audit("ok")?;
    Ok(TokenOutcome::Issued(issued))
}

fn refresh(
    app: &App,
    tx: &Transaction,
    client: &OAuthApp,
    form: &HashMap<String, String>,
    ip: Option<IpAddr>,
) -> anyhow::Result<TokenOutcome> {
    let rt = form.get("refresh_token").map(String::as_str).unwrap_or("");
    if !tokens::looks_valid(tokens::OAUTH_REFRESH_PREFIX, rt) {
        return Ok(TokenOutcome::Error("invalid_grant", "invalid refresh token"));
    }
    let hash = app.pepper.hash("oauth-refresh", rt);
    let row = tx
        .query_row(
            "SELECT connection_id, app_client_id, resource, expires_at, used_at, revoked_at FROM oauth_tokens \
             WHERE token_hash = ?1 AND kind = 'refresh'",
            [&hash],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((connection_id, app_client_id, resource, expires_at, used_at, revoked_at)) = row else {
        audit_auth(tx, "oauth.refresh", "anonymous", None, vec![client.client_id.clone()], "invalid_grant", ip)?;
        return Ok(TokenOutcome::Error("invalid_grant", "invalid refresh token"));
    };
    let (name, project, active) = connection_info(tx, &connection_id)?;
    let audit = |code: &str| {
        audit_auth(tx, "oauth.refresh", &name, Some(&project), vec![name.clone(), client.client_id.clone()], code, ip)
    };
    if app_client_id != client.client_id {
        audit("wrong_client")?;
        return Ok(TokenOutcome::Error("invalid_grant", "invalid refresh token"));
    }
    if used_at.is_some() && revoked_at.is_none() {
        // Reuse of a rotated refresh token: someone holds a copy. Revoke the whole family (the connection).
        revoke_connection(tx, &connection_id)?;
        audit("refresh_reuse_revoked")?;
        return Ok(TokenOutcome::Error("invalid_grant", "invalid refresh token"));
    }
    if revoked_at.is_some() || expires_at <= util::now_unix() || !active {
        audit("invalid_grant")?;
        return Ok(TokenOutcome::Error("invalid_grant", "invalid refresh token"));
    }
    if form.get("resource").is_some_and(|r| *r != resource) {
        audit("invalid_target")?;
        return Ok(TokenOutcome::Error("invalid_target", "resource does not match the grant"));
    }
    let now = util::now_unix();
    tx.execute("UPDATE oauth_tokens SET used_at = ?1 WHERE token_hash = ?2", params![now, hash])?;
    // Older access tokens of the family end with the rotation; only the newest pair stays usable.
    tx.execute(
        "UPDATE oauth_tokens SET revoked_at = ?1 WHERE connection_id = ?2 AND kind = 'access' AND revoked_at IS NULL",
        params![now, connection_id],
    )?;
    let issued = issue_pair(tx, &app.pepper, &app.cfg.oauth, &connection_id, &client.client_id, &resource)?;
    audit("ok")?;
    Ok(TokenOutcome::Issued(issued))
}

// ------------------------------------------------------------------ revocation (RFC 7009)

/// POST `/oauth/dove/revoke`. OAuth tokens need the owning client's authentication; a Dove connection token
/// (`dove_`) revokes its own connection by possession (used by `dove logout --revoke`). Always 200 for unknown
/// tokens, so the endpoint is no token oracle.
async fn revoke(State(app): State<Arc<App>>, req: Request) -> Response {
    let (headers, ip, body) = match split(req, 16 * 1024).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let limit = app.cfg.oauth.token_requests_per_minute;
    if let Some(wait) = app.rate_limiter.check(&ip_key("token", ip), limit, limit.min(30)) {
        return rate_limited(wait);
    }
    let Some(form) = parse_params(&body) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "repeated parameter");
    };
    let Some(token) = form.get("token").cloned() else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "token is required");
    };
    let token = Zeroizing::new(token);
    let ok = || no_store(StatusCode::OK.into_response());
    if tokens::looks_valid(tokens::CLIENT_TOKEN_PREFIX, &token) {
        let pepper = app.pepper.clone();
        let r = app
            .store
            .call(move |c| {
                let tx = c.transaction()?;
                let row: Option<String> = tx
                    .query_row(
                        "SELECT id FROM clients WHERE token_hash = ?1 AND kind = 'token'",
                        [pepper.hash("client", &token)],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(id) = row {
                    let (name, project, _) = connection_info(&tx, &id)?;
                    revoke_connection(&tx, &id)?;
                    audit_auth(&tx, "connection.self_revoke", &name, Some(&project), vec![name.clone()], "ok", ip)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await;
        return match r {
            Ok(()) => ok(),
            Err(e) => {
                tracing::error!(error = %e, "self revocation failed");
                oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "internal error")
            }
        };
    }
    let creds = match client_creds(&headers, &form) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let basic = creds.basic;
    let app2 = app.clone();
    let r = app
        .store
        .call(move |c| {
            let Some(client) = verify_client(&app2, c, &creds)? else { return Ok(false) };
            let (purpose, kind) = if tokens::looks_valid(tokens::OAUTH_REFRESH_PREFIX, &token) {
                ("oauth-refresh", "refresh")
            } else if tokens::looks_valid(tokens::OAUTH_ACCESS_PREFIX, &token) {
                ("oauth-access", "access")
            } else {
                return Ok(true);
            };
            let hash = app2.pepper.hash(purpose, &token);
            let tx = c.transaction()?;
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT connection_id, app_client_id FROM oauth_tokens WHERE token_hash = ?1 AND kind = ?2",
                    params![hash, kind],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((connection_id, owner)) = row.filter(|(_, owner)| *owner == client.client_id) {
                let (name, project, _) = connection_info(&tx, &connection_id)?;
                if kind == "refresh" {
                    // Revoking the refresh token ends the grant: the whole family and the connection.
                    revoke_connection(&tx, &connection_id)?;
                } else {
                    tx.execute(
                        "UPDATE oauth_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE token_hash = ?2",
                        params![util::now_unix(), hash],
                    )?;
                }
                audit_auth(&tx, "oauth.revoke", &name, Some(&project), vec![name.clone(), owner], kind, ip)?;
            }
            tx.commit()?;
            Ok(true)
        })
        .await;
    match r {
        Ok(true) => ok(),
        Ok(false) => invalid_client(basic),
        Err(e) => {
            tracing::error!(error = %e, "revocation failed");
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "internal error")
        }
    }
}

// ------------------------------------------------------------------ dynamic registration (RFC 7591)

/// POST `/oauth/dove/register`: public clients only, bounded and rate-limited. Registration has no mailbox
/// authority; it only lets an application start the approval flow.
async fn register(State(app): State<Arc<App>>, req: Request) -> Response {
    let (_, ip, body) = match split(req, 8 * 1024).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let invalid = |d: &str| oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", d);
    if !app.oauth.allow_registration(&ip_key("register", ip), app.cfg.oauth.registrations_per_hour) {
        return rate_limited(3600);
    }
    let Ok(meta) = serde_json::from_slice::<Value>(&body) else {
        return invalid("body must be a JSON object");
    };
    let Some(uris) = meta.get("redirect_uris").and_then(Value::as_array).filter(|a| (1..=5).contains(&a.len())) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", "1 to 5 redirect_uris are required");
    };
    let mut redirect_uris = Vec::new();
    for u in uris {
        let Some(s) = u.as_str() else { return invalid("redirect_uris must be strings") };
        if let Err(e) = validate_redirect_uri(s) {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", &e);
        }
        redirect_uris.push(s.to_string());
    }
    let method = meta.get("token_endpoint_auth_method").and_then(Value::as_str).unwrap_or("none");
    if method != "none" {
        return invalid("dynamic registration supports public clients only (token_endpoint_auth_method=none)");
    }
    let subset = |key: &str, allowed: &[&str]| {
        meta.get(key).is_none_or(|v| {
            v.as_array().is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(|s| allowed.contains(&s))))
        })
    };
    if !subset("grant_types", &["authorization_code", "refresh_token"]) || !subset("response_types", &["code"]) {
        return invalid("only authorization_code/refresh_token grants and the code response type are supported");
    }
    let name: String = meta
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("Unnamed application")
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    let cap = app.cfg.oauth.max_dynamic_clients;
    let (uris_json, name2) = (serde_json::to_string(&redirect_uris).unwrap_or_default(), name.clone());
    let r = app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let now = util::now_unix();
            // Prune stale registrations that never led to a connection, then enforce the bound.
            tx.execute(
                "DELETE FROM oauth_apps WHERE registered_via = 'dynamic' AND created_at < ?1 \
                 AND client_id NOT IN (SELECT app_client_id FROM oauth_codes) \
                 AND client_id NOT IN (SELECT app_client_id FROM oauth_tokens)",
                [now - DCR_STALE_SECS],
            )?;
            let count: i64 =
                tx.query_row("SELECT COUNT(*) FROM oauth_apps WHERE registered_via = 'dynamic'", [], |r| r.get(0))?;
            if count as usize >= cap {
                drop(tx);
                audit_auth(c, "oauth.register", "anonymous", None, vec![], "limit_reached", ip)?;
                return Ok(None);
            }
            let client_id = format!("dcr-{}", util::new_id());
            tx.execute(
                "INSERT INTO oauth_apps(client_id, client_name, redirect_uris, registered_via, created_at) \
                 VALUES (?1, ?2, ?3, 'dynamic', ?4)",
                params![client_id, name2, uris_json, now],
            )?;
            audit_auth(&tx, "oauth.register", "anonymous", None, vec![client_id.clone()], "ok", ip)?;
            tx.commit()?;
            Ok(Some((client_id, now)))
        })
        .await;
    match r {
        Ok(Some((client_id, now))) => no_store(
            (
                StatusCode::CREATED,
                axum::Json(json!({
                    "client_id": client_id,
                    "client_id_issued_at": now,
                    "client_name": name,
                    "redirect_uris": redirect_uris,
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                })),
            )
                .into_response(),
        ),
        Ok(None) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "registration limit reached; ask the operator",
        ),
        Err(e) => {
            tracing::error!(error = %e, "registration failed");
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "internal error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_rules() {
        assert!(validate_redirect_uri("https://claude.ai/api/mcp/auth_callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:33418/callback").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:5000/cb").is_ok());
        assert!(validate_redirect_uri("http://evil.example/cb").is_err());
        assert!(validate_redirect_uri("https://a.example/cb#frag").is_err());
        assert!(validate_redirect_uri("https://user:pw@a.example/cb").is_err());
        assert!(validate_redirect_uri("myapp://cb").is_err());
        assert!(validate_redirect_uri("javascript:alert(1)").is_err());
    }

    #[test]
    fn ipv6_limits_use_the_64() {
        let a = Some("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = Some("2001:db8:1:2:bbbb::9".parse().unwrap());
        let c = Some("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(ip_bucket(a), ip_bucket(b));
        assert_ne!(ip_bucket(a), ip_bucket(c));
        assert_eq!(ip_bucket(Some("::ffff:10.0.0.1".parse().unwrap())), "10.0.0.1");
        assert_eq!(ip_bucket(Some("10.0.0.1".parse().unwrap())), "10.0.0.1");
    }

    #[test]
    fn pkce_and_params() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // gitleaks:allow (RFC example)
        );
        assert!(valid_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        assert!(!valid_verifier("short"));
        assert!(parse_params(b"a=1&b=2").is_some());
        assert!(parse_params(b"a=1&a=2").is_none());
    }
}
