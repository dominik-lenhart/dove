//! Admin web UI under `/admin` (design 2026-11-14 section 5, PLAN A74).
//!
//! Layers, outermost first:
//! 1. [`guard`] (called by `http::guard` for every path under [`ADMIN_PREFIX`]): 404 unless the UI is enabled, not
//!    in local mode and the `Host` is the admin origin's; any `Authorization` header is refused (an agent token never
//!    becomes an admin credential); a foreign `Origin` is refused; per-address rate limit; security headers (strict
//!    CSP, no framing, no caching) on every answer.
//! 2. [`gate`] (middleware of the admin router): a POST must carry the admin origin in `Origin` (and no cross-site
//!    `Sec-Fetch-Site`). Outside [`ADMIN_PUBLIC_PATHS`] a valid session cookie is required, and every POST also
//!    needs the session's CSRF token (form field `csrf` or header `X-Dove-CSRF`).
//! 3. Handlers build [`AdminRequest`] values and run them through `admin::server::dispatch` with the actor
//!    `web:<passkey name>` ([`auth::run_action`]); verbs that [`needs_step_up`] run only after a fresh passkey
//!    assertion bound to exactly that request ([`auth::begin_stepup`], [`auth::stepup_finish`]).

pub mod auth;
pub mod cbor;
pub mod connections;
pub mod html;
pub mod kit;
pub mod mailboxes;
pub mod pages;
pub mod projects;
pub mod reveal;
#[cfg(any(test, feature = "testing"))]
pub mod soft_authenticator;
pub mod store;
pub mod watches;
pub mod webauthn;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};

use crate::admin::AdminRequest;
use crate::app::App;

/// Every admin route starts with this prefix; `dove tailscale setup --admin` mounts exactly it.
pub const ADMIN_PREFIX: &str = "/admin";

/// Every route of the admin UI (the drift test compares it with the routes registered below, keeps it disjoint
/// from `tailscale::PUBLIC_PATHS` and checks that no deploy template forwards it).
pub const ADMIN_PATHS: &[&str] = &[
    "/admin",
    "/admin/login",
    "/admin/login/options",
    "/admin/login/finish",
    "/admin/logout",
    "/admin/enroll",
    "/admin/enroll/options",
    "/admin/enroll/finish",
    "/admin/stepup",
    "/admin/static/admin.css",
    "/admin/static/admin.js",
    "/admin/static/inter.woff2",
    "/admin/health",
    "/admin/requests",
    "/admin/requests/{id}",
    "/admin/requests/{id}/approve",
    "/admin/requests/{id}/deny",
    "/admin/requests/{id}/cancel",
    "/admin/audit",
    "/admin/audit/verify",
    "/admin/settings",
    "/admin/settings/passkeys/{name}/remove",
    "/admin/settings/sessions/revoke",
    "/admin/settings/passkeys/add",
    "/admin/settings/keys/rewrap",
    "/admin/settings/export",
    "/admin/audit/prune",
    "/admin/more",
    "/admin/reveal/{id}",
    "/admin/connections",
    "/admin/connections/new",
    "/admin/connections/{name}",
    "/admin/connections/{name}/grants",
    "/admin/connections/{name}/redaction",
    "/admin/connections/{name}/rotate",
    "/admin/connections/{name}/revoke",
    "/admin/mailboxes",
    "/admin/mailboxes/new",
    "/admin/mailboxes/{alias}",
    "/admin/mailboxes/{alias}/state",
    "/admin/mailboxes/{alias}/reconnect",
    "/admin/mailboxes/{alias}/index",
    "/admin/mailboxes/{alias}/aliases",
    "/admin/mailboxes/{alias}/signature",
    "/admin/projects",
    "/admin/projects/{name}",
    "/admin/projects/{name}/accounts",
    "/admin/watches",
    "/admin/watches/{id}/remove",
    "/admin/watches/sinks",
    "/admin/watches/sinks/{name}",
];

/// The only admin routes that answer without a session.
pub const ADMIN_PUBLIC_PATHS: &[&str] = &[
    "/admin/login",
    "/admin/login/options",
    "/admin/login/finish",
    "/admin/enroll",
    "/admin/enroll/options",
    "/admin/enroll/finish",
    "/admin/static/admin.css",
    "/admin/static/admin.js",
    "/admin/static/inter.woff2",
];

/// Content-Security-Policy of every admin answer (design 5.4), exactly.
/// `connect-src 'self'` is required: the sign-in, enrolment and confirmation steps call the server with `fetch`, which
/// `default-src 'none'` alone blocks (Safari reports it as "Load failed").
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; \
                       form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// Session cookie name. `__Host-` makes browsers require `Secure`, `Path=/` and no `Domain`.
pub const COOKIE: &str = "__Host-dove_admin";

/// Header carrying the CSRF token on script requests.
pub const CSRF_HEADER: &str = "x-dove-csrf";

/// Largest request body under `/admin` (forms and WebAuthn responses are small).
pub const BODY_LIMIT: usize = 64 * 1024;

/// Whether `path` belongs to the admin UI.
pub fn is_admin_path(path: &str) -> bool {
    path == ADMIN_PREFIX || path.starts_with("/admin/")
}

/// In-memory state of the admin UI: challenge pools and the last health check.
#[derive(Default)]
pub struct Runtime {
    pub auth: auth::Pools,
    pub health: std::sync::Mutex<Option<(i64, serde_json::Value)>>,
}

pub fn routes(app: Arc<App>) -> Router<Arc<App>> {
    Router::new()
        .route("/admin", get(pages::overview))
        .route("/admin/login", get(auth::login_page))
        .route("/admin/login/options", post(auth::login_options))
        .route("/admin/login/finish", post(auth::login_finish))
        .route("/admin/logout", post(auth::logout))
        .route("/admin/enroll", get(auth::enrol_page))
        .route("/admin/enroll/options", post(auth::enrol_options))
        .route("/admin/enroll/finish", post(auth::enrol_finish))
        .route("/admin/stepup", post(auth::stepup_finish))
        .route("/admin/static/admin.css", get(static_css))
        .route("/admin/static/admin.js", get(static_js))
        .route("/admin/static/inter.woff2", get(static_font))
        .route("/admin/health", get(pages::health))
        .route("/admin/requests", get(pages::requests))
        .route("/admin/requests/{id}", get(pages::request_detail))
        .route("/admin/requests/{id}/approve", post(pages::request_approve))
        .route("/admin/requests/{id}/deny", post(pages::request_deny))
        .route("/admin/requests/{id}/cancel", post(pages::request_cancel))
        .route("/admin/audit", get(pages::audit))
        .route("/admin/audit/verify", get(pages::audit_verify))
        .route("/admin/settings", get(pages::settings))
        .route("/admin/settings/passkeys/{name}/remove", post(pages::passkey_remove))
        .route("/admin/settings/sessions/revoke", post(pages::sessions_revoke))
        .route("/admin/settings/passkeys/add", post(pages::passkey_add))
        .route("/admin/settings/keys/rewrap", post(pages::keys_rewrap))
        .route("/admin/settings/export", get(pages::export))
        .route("/admin/audit/prune", post(pages::audit_prune))
        .route("/admin/more", get(pages::more))
        .route("/admin/reveal/{id}", get(reveal::show))
        .route("/admin/connections", get(connections::list))
        .route("/admin/connections/new", get(connections::new_form).post(connections::create))
        .route("/admin/connections/{name}", get(connections::detail))
        .route("/admin/connections/{name}/grants", post(connections::set_grants))
        .route("/admin/connections/{name}/redaction", post(connections::redaction))
        .route("/admin/connections/{name}/rotate", post(connections::rotate))
        .route("/admin/connections/{name}/revoke", post(connections::revoke))
        .route("/admin/mailboxes", get(mailboxes::list))
        .route("/admin/mailboxes/new", get(mailboxes::new_form).post(mailboxes::create))
        .route("/admin/mailboxes/{alias}", get(mailboxes::detail))
        .route("/admin/mailboxes/{alias}/state", post(mailboxes::state))
        .route("/admin/mailboxes/{alias}/reconnect", post(mailboxes::reconnect))
        .route("/admin/mailboxes/{alias}/index", post(mailboxes::index))
        .route("/admin/mailboxes/{alias}/aliases", post(mailboxes::aliases))
        .route("/admin/mailboxes/{alias}/signature", post(mailboxes::signature))
        .route("/admin/projects", get(projects::list).post(projects::create))
        .route("/admin/projects/{name}", get(projects::detail))
        .route("/admin/projects/{name}/accounts", post(projects::accounts))
        .route("/admin/watches", get(watches::page_view))
        .route("/admin/watches/{id}/remove", post(watches::remove_watch))
        .route("/admin/watches/sinks", post(watches::add_sink))
        .route("/admin/watches/sinks/{name}", post(watches::sink))
        // `route_layer`, not `layer`: a layer would also wrap the fallback, and merged into the public router that
        // fallback answers every unknown path of the listener (a 303 to the sign-in page instead of 404).
        .route_layer(middleware::from_fn_with_state(app, gate))
        .route_layer(DefaultBodyLimit::max(BODY_LIMIT))
}

/// Header Tailscale sets on requests that came in through Funnel (the public internet).
const FUNNEL_HEADER: &str = "tailscale-funnel-request";

/// The rate-limit key of a client address. Every loopback address is one caller: behind Tailscale Serve the owner
/// is `127.0.0.1`, and a local process can pick any source address in `127.0.0.0/8`.
pub(crate) fn addr_key(ip: Option<std::net::IpAddr>) -> String {
    use std::net::IpAddr;
    match ip {
        Some(i) if i.is_loopback() => "loopback".into(),
        Some(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()) => "loopback".into(),
        Some(i) => i.to_string(),
        None => "unknown".into(),
    }
}

const CSS: &str = include_str!("static/admin.css");
const JS: &str = include_str!("static/admin.js");
/// Inter (latin subset, variable weight), the Keyset typeface; SIL Open Font License, see `static/inter-license.txt`.
const FONT: &[u8] = include_bytes!("static/inter-latin-variable.woff2");

async fn static_css() -> Response {
    asset(CSS, "text/css; charset=utf-8")
}

async fn static_font() -> Response {
    let mut r = FONT.into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("font/woff2"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=86400"));
    r
}

async fn static_js() -> Response {
    asset(JS, "text/javascript; charset=utf-8")
}

/// The `?v=` of the stylesheet and script URLs: a hash of both files, so a browser never keeps a stale copy after an
/// update (the version number alone stays the same between builds of one release).
pub fn asset_version() -> &'static str {
    static V: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(CSS.as_bytes());
        h.update(JS.as_bytes());
        crate::util::b64url(&h.finalize()[..9])
    });
    &V
}

fn asset(body: &'static str, ctype: &'static str) -> Response {
    let mut r = body.into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    // Versioned URLs (`?v=<version>`) make a short cache safe.
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=3600"));
    r
}

fn plain(status: StatusCode, text: &'static str) -> Response {
    (status, text).into_response()
}

/// The `/admin` part of `http::guard`. Runs after the client address is decided and the proxy secret removed.
pub async fn guard(app: Arc<App>, req: Request, next: Next) -> Response {
    let ui = &app.cfg.admin_ui;
    // Exactly one Host: with two, a proxy and Dove could each believe a different one.
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host = match (hosts.next(), hosts.next()) {
        (Some(h), None) => h.to_str().unwrap_or(""),
        _ => "",
    };
    let host_ok = ui.host().is_some_and(|h| h.eq_ignore_ascii_case(host));
    // Funnel switched on after setup would put `/admin` on the internet; such requests find nothing here.
    let funnel = req.headers().contains_key(FUNNEL_HEADER);
    let resp = if !ui.enabled || app.cfg.is_local() || !host_ok || funnel {
        plain(StatusCode::NOT_FOUND, "not found")
    } else if req.headers().contains_key(header::AUTHORIZATION) {
        // An agent token is never an admin credential, not even next to a valid session.
        plain(StatusCode::FORBIDDEN, "the admin UI does not accept an Authorization header")
    } else if req.headers().get_all(header::ORIGIN).iter().any(|o| Some(o.as_bytes()) != ui.origin().map(str::as_bytes))
    {
        plain(StatusCode::FORBIDDEN, "origin not allowed")
    } else {
        let ip = crate::http::request_ip(&req);
        let key = format!("admin:{}", addr_key(ip));
        let per_minute = ui.requests_per_minute;
        match app.rate_limiter.check(&key, per_minute, per_minute) {
            // Over the address budget, a browser whose session the gate has already seen valid draws from a budget of
            // its own: behind Tailscale Serve every caller is 127.0.0.1, and anonymous traffic from a local process
            // must not lock out the owner's session (PLAN A74 (i)). No state-store lookup on this path; the gate still
            // checks the session itself.
            Some(_) => match auth::seen_session_bucket(&app, req.headers()) {
                Some(k) if app.rate_limiter.check(&k, per_minute, per_minute).is_none() => next.run(req).await,
                _ => plain(StatusCode::TOO_MANY_REQUESTS, "too many requests; try again in a minute"),
            },
            None => next.run(req).await,
        }
    };
    secure_headers(resp)
}

fn secure_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    // same-origin keeps the real Origin on our own form posts (no-referrer would make it `null`).
    h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

/// Whether a write comes from the admin UI's own pages: exactly one `Origin`, equal to the admin origin, and no
/// cross-site fetch metadata. A missing `Origin` is refused (browsers send it on every POST).
fn same_origin_write(app: &App, headers: &HeaderMap) -> bool {
    let Some(origin) = app.cfg.admin_ui.origin() else { return false };
    let mut values = headers.get_all(header::ORIGIN).iter();
    let origin_ok = matches!((values.next(), values.next()), (Some(v), None) if v.as_bytes() == origin.as_bytes());
    let site_ok = headers.get("sec-fetch-site").is_none_or(|v| v.as_bytes() == b"same-origin");
    origin_ok && site_ok
}

/// Session, CSRF and Origin enforcement for the admin router (see the module docs).
async fn gate(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let write = method == Method::POST;
    if !write && method != Method::GET && method != Method::HEAD {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    if write && !same_origin_write(&app, req.headers()) {
        return plain(StatusCode::FORBIDDEN, "cross-origin request refused");
    }
    let path = req.uri().path().to_string();
    if ADMIN_PUBLIC_PATHS.contains(&path.as_str()) {
        return next.run(req).await;
    }
    let Some(session) = auth::session_from_headers(&app, req.headers()).await else {
        return if write {
            plain(StatusCode::UNAUTHORIZED, "sign in first")
        } else {
            Redirect::to("/admin/login").into_response()
        };
    };
    let req = if write {
        let (parts, body) = req.into_parts();
        let Ok(bytes) = axum::body::to_bytes(body, BODY_LIMIT).await else {
            return plain(StatusCode::PAYLOAD_TOO_LARGE, "request too large");
        };
        let header_token = parts.headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string);
        let token = header_token.or_else(|| {
            let form = parts
                .headers
                .get(header::CONTENT_TYPE)
                .is_some_and(|v| v.as_bytes().starts_with(b"application/x-www-form-urlencoded"));
            if !form {
                return None;
            }
            url::form_urlencoded::parse(&bytes).find(|(k, _)| k == "csrf").map(|(_, v)| v.into_owned())
        });
        if !token.is_some_and(|t| auth::csrf_matches(&session, &t)) {
            return plain(StatusCode::FORBIDDEN, "missing or wrong CSRF token; reload the page");
        }
        Request::from_parts(parts, Body::from(bytes))
    } else {
        req
    };
    let mut req = req;
    req.extensions_mut().insert(session);
    next.run(req).await
}

/// Admin verbs that need a fresh passkey assertion bound to the exact request (design 5.2): approving a request,
/// widening grants, creating or rotating a token, connecting or reconnecting a mailbox, adding a sink, adding or
/// removing a passkey. Exhaustive on purpose: a new verb must be classified here.
pub fn needs_step_up(req: &AdminRequest) -> bool {
    use AdminRequest::*;
    match req {
        RequestsApprove { .. }
        | ClientsCreate { .. }
        | ClientsSetGrants { .. }
        | ClientsRotate { .. }
        | ClientsInvite { .. }
        | AccountsConnect { .. }
        | AccountsReconnect { .. }
        | AccountsConnectImap { .. }
        | AccountsReconnectImap { .. }
        | SinksAdd { .. }
        | PasskeysAdd { .. }
        | PasskeysRemove { .. } => true,
        ProjectsCreate { .. }
        | ProjectsAddAccount { .. }
        | ProjectsRemoveAccount { .. }
        | ProjectsList
        | ProjectsShow { .. }
        | AccountsList
        | AccountsRemove { .. }
        | AccountsDisable { .. }
        | AccountsEnable { .. }
        | AccountsCheck { .. }
        | AccountsAliasAdd { .. }
        | AccountsAliasList { .. }
        | AccountsAliasRemove { .. }
        | AccountsSignatureSet { .. }
        | AccountsSignatureShow { .. }
        | ClientsRevoke { .. }
        | ClientsShow { .. }
        | ClientsSetRedaction { .. }
        | ClientsList
        | AuditTail { .. }
        | AuditSearch { .. }
        | AuditVerify
        | AuditPrune
        | KeysRotate
        | Doctor
        | Version
        | Shutdown
        | Export
        | IndexEnable { .. }
        | IndexDisable { .. }
        | IndexStatus { .. }
        | IndexRebuild { .. }
        | SinksList
        | SinksRemove { .. }
        | SinksSetProject { .. }
        | WatchesList
        | WatchesRemove { .. }
        | OperationsList
        | OperationsRemove { .. }
        | RequestsList { .. }
        | RequestsShow { .. }
        | RequestsDeny { .. }
        | RequestsCancel { .. }
        | PasskeysList
        | SessionsList
        | SessionsRevoke { .. } => false,
    }
}

/// Where each admin verb is reachable in the UI, or why it is not (design 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// The route whose handler builds this verb.
    Ui(&'static str),
    Excluded(&'static str),
}

const NO_OPERATIONS: &str =
    "the service does not implement the unknown-outcome operations verbs yet; they answer 'not available' everywhere";

/// Every `AdminRequest` variant by name. `tests::every_verb_is_covered` checks the list against the enum and the
/// handlers' source.
pub const COVERAGE: &[(&str, Reach)] = &[
    ("ProjectsCreate", Reach::Ui("/admin/projects")),
    ("ProjectsAddAccount", Reach::Ui("/admin/projects/{name}/accounts")),
    ("ProjectsRemoveAccount", Reach::Ui("/admin/projects/{name}/accounts")),
    ("ProjectsList", Reach::Ui("/admin/projects")),
    ("ProjectsShow", Reach::Ui("/admin/projects/{name}")),
    ("AccountsList", Reach::Ui("/admin/mailboxes")),
    ("AccountsConnect", Reach::Ui("/admin/mailboxes/new")),
    ("AccountsReconnect", Reach::Ui("/admin/mailboxes/{alias}/reconnect")),
    ("AccountsConnectImap", Reach::Ui("/admin/mailboxes/new")),
    ("AccountsReconnectImap", Reach::Ui("/admin/mailboxes/{alias}/reconnect")),
    ("AccountsRemove", Reach::Ui("/admin/mailboxes/{alias}/state")),
    ("AccountsDisable", Reach::Ui("/admin/mailboxes/{alias}/state")),
    ("AccountsEnable", Reach::Ui("/admin/mailboxes/{alias}/state")),
    ("AccountsCheck", Reach::Ui("/admin/mailboxes/{alias}/state")),
    ("AccountsAliasAdd", Reach::Ui("/admin/mailboxes/{alias}/aliases")),
    ("AccountsAliasList", Reach::Ui("/admin/mailboxes/{alias}")),
    ("AccountsAliasRemove", Reach::Ui("/admin/mailboxes/{alias}/aliases")),
    ("AccountsSignatureSet", Reach::Ui("/admin/mailboxes/{alias}/signature")),
    ("AccountsSignatureShow", Reach::Ui("/admin/mailboxes/{alias}")),
    ("ClientsCreate", Reach::Ui("/admin/connections/new")),
    ("ClientsSetGrants", Reach::Ui("/admin/connections/{name}/grants")),
    ("ClientsRotate", Reach::Ui("/admin/connections/{name}/rotate")),
    ("ClientsRevoke", Reach::Ui("/admin/connections/{name}/revoke")),
    ("ClientsShow", Reach::Ui("/admin/connections/{name}")),
    ("ClientsSetRedaction", Reach::Ui("/admin/connections/{name}/redaction")),
    ("ClientsList", Reach::Ui("/admin/connections")),
    ("ClientsInvite", Reach::Ui("/admin/connections/new")),
    ("AuditTail", Reach::Excluded("the Audit page's search with no filter shows the newest records (AuditSearch)")),
    ("AuditSearch", Reach::Ui("/admin/audit")),
    ("AuditVerify", Reach::Ui("/admin/audit/verify")),
    ("AuditPrune", Reach::Ui("/admin/audit/prune")),
    ("KeysRotate", Reach::Ui("/admin/settings/keys/rewrap")),
    ("Doctor", Reach::Ui("/admin/health")),
    ("Version", Reach::Excluded("the version is part of the health checks (Doctor)")),
    ("Shutdown", Reach::Excluded("local mode only, where the admin UI does not exist")),
    ("Export", Reach::Ui("/admin/settings/export")),
    ("IndexEnable", Reach::Ui("/admin/mailboxes/{alias}/index")),
    ("IndexDisable", Reach::Ui("/admin/mailboxes/{alias}/index")),
    ("IndexStatus", Reach::Ui("/admin")),
    ("IndexRebuild", Reach::Ui("/admin/mailboxes/{alias}/index")),
    ("SinksAdd", Reach::Ui("/admin/watches/sinks")),
    ("SinksList", Reach::Ui("/admin/watches")),
    ("SinksRemove", Reach::Ui("/admin/watches/sinks/{name}")),
    ("SinksSetProject", Reach::Ui("/admin/watches/sinks/{name}")),
    ("WatchesList", Reach::Ui("/admin/watches")),
    ("WatchesRemove", Reach::Ui("/admin/watches/{id}/remove")),
    ("OperationsList", Reach::Excluded(NO_OPERATIONS)),
    ("OperationsRemove", Reach::Excluded(NO_OPERATIONS)),
    ("RequestsList", Reach::Ui("/admin/requests")),
    ("RequestsShow", Reach::Ui("/admin/requests/{id}")),
    ("RequestsApprove", Reach::Ui("/admin/requests/{id}/approve")),
    ("RequestsDeny", Reach::Ui("/admin/requests/{id}/deny")),
    ("RequestsCancel", Reach::Ui("/admin/requests/{id}/cancel")),
    ("PasskeysAdd", Reach::Ui("/admin/settings/passkeys/add")),
    ("PasskeysList", Reach::Ui("/admin/settings")),
    ("PasskeysRemove", Reach::Ui("/admin/settings/passkeys/{name}/remove")),
    ("SessionsList", Reach::Ui("/admin/settings")),
    ("SessionsRevoke", Reach::Ui("/admin/settings/sessions/revoke")),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Variant names of `AdminRequest`, read from its source (4-space indented CamelCase lines inside the enum).
    fn variants() -> BTreeSet<String> {
        // Windows checkouts have CRLF line endings.
        let src = include_str!("../admin/mod.rs").replace("\r\n", "\n");
        let body = src.split("pub enum AdminRequest {").nth(1).unwrap().split("\n}\n").next().unwrap();
        body.lines()
            .filter(|l| l.starts_with("    ") && !l.starts_with("     "))
            .map(str::trim)
            .filter(|l| l.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
            .map(|l| l.split([' ', ',', '{']).next().unwrap().to_string())
            .collect()
    }

    /// Design 5.3: every admin verb is reachable in the UI or excluded with a reason; a verb marked reachable is
    /// built by a handler (outside tests) and its route exists.
    #[test]
    fn every_verb_is_covered() {
        let all = variants();
        assert!(all.len() > 50 && all.contains("RequestsApprove") && all.contains("SessionsRevoke"), "{all:?}");
        let covered: BTreeSet<String> = COVERAGE.iter().map(|(n, _)| (*n).to_string()).collect();
        assert_eq!(covered.len(), COVERAGE.len(), "duplicate entries");
        assert_eq!(covered, all, "COVERAGE must name every AdminRequest variant exactly once");
        let handlers: String = [
            include_str!("pages.rs"),
            include_str!("auth.rs"),
            include_str!("connections.rs"),
            include_str!("mailboxes.rs"),
            include_str!("projects.rs"),
            include_str!("watches.rs"),
        ]
        .iter()
        .map(|s| s.split("#[cfg(test)]").next().unwrap())
        .collect();
        for (name, reach) in COVERAGE {
            match reach {
                Reach::Ui(route) => {
                    assert!(ADMIN_PATHS.contains(route), "{name}: {route} is not an admin route");
                    assert!(handlers.contains(&format!("AdminRequest::{name}")), "{name} is not built by a handler");
                }
                Reach::Excluded(reason) => assert!(reason.len() > 10, "{name} needs a reason"),
            }
        }
    }

    #[test]
    fn public_paths_are_admin_paths_and_few() {
        for p in ADMIN_PUBLIC_PATHS {
            assert!(ADMIN_PATHS.contains(p), "{p}");
        }
        // Only sign-in, enrolment and the three static files answer without a session.
        assert_eq!(ADMIN_PUBLIC_PATHS.len(), 9);
        assert!(is_admin_path("/admin") && is_admin_path("/admin/x") && !is_admin_path("/administrator"));
    }
}
