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
pub mod html;
pub mod pages;
#[cfg(any(test, feature = "testing"))]
pub mod soft_authenticator;
pub mod store;
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
];

/// Content-Security-Policy of every admin answer (design 5.4), exactly.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; \
                       frame-ancestors 'none'; base-uri 'none'";

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
        .layer(middleware::from_fn_with_state(app, gate))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

const CSS: &str = include_str!("static/admin.css");
const JS: &str = include_str!("static/admin.js");

async fn static_css() -> Response {
    asset(CSS, "text/css; charset=utf-8")
}

async fn static_js() -> Response {
    asset(JS, "text/javascript; charset=utf-8")
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
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let host_ok = ui.host().is_some_and(|h| h.eq_ignore_ascii_case(host));
    let resp = if !ui.enabled || app.cfg.is_local() || !host_ok {
        plain(StatusCode::NOT_FOUND, "not found")
    } else if req.headers().contains_key(header::AUTHORIZATION) {
        // An agent token is never an admin credential, not even next to a valid session.
        plain(StatusCode::FORBIDDEN, "the admin UI does not accept an Authorization header")
    } else if req.headers().get_all(header::ORIGIN).iter().any(|o| Some(o.as_bytes()) != ui.origin().map(str::as_bytes))
    {
        plain(StatusCode::FORBIDDEN, "origin not allowed")
    } else {
        let ip = crate::http::request_ip(&req);
        let key = format!("admin:{}", ip.map(|i| i.to_string()).unwrap_or_else(|| "unknown".into()));
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

const PART2: &str = "part 2 of the admin UI (Connections, Mailboxes, Projects, Watches and sinks pages)";

/// Every `AdminRequest` variant by name. `tests::every_verb_is_covered` checks the list against the enum and the
/// handlers' source.
pub const COVERAGE: &[(&str, Reach)] = &[
    ("ProjectsCreate", Reach::Excluded(PART2)),
    ("ProjectsAddAccount", Reach::Excluded(PART2)),
    ("ProjectsRemoveAccount", Reach::Excluded(PART2)),
    ("ProjectsList", Reach::Excluded(PART2)),
    ("ProjectsShow", Reach::Excluded(PART2)),
    ("AccountsList", Reach::Excluded(PART2)),
    ("AccountsConnect", Reach::Excluded(PART2)),
    ("AccountsReconnect", Reach::Excluded(PART2)),
    ("AccountsConnectImap", Reach::Excluded(PART2)),
    ("AccountsReconnectImap", Reach::Excluded(PART2)),
    ("AccountsRemove", Reach::Excluded(PART2)),
    ("AccountsDisable", Reach::Excluded(PART2)),
    ("AccountsEnable", Reach::Excluded(PART2)),
    ("AccountsCheck", Reach::Excluded(PART2)),
    ("AccountsAliasAdd", Reach::Excluded(PART2)),
    ("AccountsAliasList", Reach::Excluded(PART2)),
    ("AccountsAliasRemove", Reach::Excluded(PART2)),
    ("AccountsSignatureSet", Reach::Excluded(PART2)),
    ("AccountsSignatureShow", Reach::Excluded(PART2)),
    ("ClientsCreate", Reach::Excluded(PART2)),
    ("ClientsSetGrants", Reach::Excluded(PART2)),
    ("ClientsRotate", Reach::Excluded(PART2)),
    ("ClientsRevoke", Reach::Excluded(PART2)),
    ("ClientsShow", Reach::Excluded(PART2)),
    ("ClientsSetRedaction", Reach::Excluded(PART2)),
    ("ClientsList", Reach::Excluded(PART2)),
    ("ClientsInvite", Reach::Excluded(PART2)),
    ("AuditTail", Reach::Excluded("the Audit page's search with no filter shows the newest records (AuditSearch)")),
    ("AuditSearch", Reach::Ui("/admin/audit")),
    ("AuditVerify", Reach::Ui("/admin/audit/verify")),
    ("AuditPrune", Reach::Excluded(PART2)),
    ("KeysRotate", Reach::Excluded(PART2)),
    ("Doctor", Reach::Ui("/admin/health")),
    ("Version", Reach::Excluded("the version is part of the health checks (Doctor)")),
    ("Shutdown", Reach::Excluded("local mode only, where the admin UI does not exist")),
    ("Export", Reach::Excluded(PART2)),
    ("IndexEnable", Reach::Excluded(PART2)),
    ("IndexDisable", Reach::Excluded(PART2)),
    ("IndexStatus", Reach::Ui("/admin")),
    ("IndexRebuild", Reach::Excluded(PART2)),
    ("SinksAdd", Reach::Excluded(PART2)),
    ("SinksList", Reach::Excluded(PART2)),
    ("SinksRemove", Reach::Excluded(PART2)),
    ("SinksSetProject", Reach::Excluded(PART2)),
    ("OperationsList", Reach::Excluded(PART2)),
    ("OperationsRemove", Reach::Excluded(PART2)),
    ("RequestsList", Reach::Ui("/admin/requests")),
    ("RequestsShow", Reach::Ui("/admin/requests/{id}")),
    ("RequestsApprove", Reach::Ui("/admin/requests/{id}/approve")),
    ("RequestsDeny", Reach::Ui("/admin/requests/{id}/deny")),
    ("RequestsCancel", Reach::Ui("/admin/requests/{id}/cancel")),
    (
        "PasskeysAdd",
        Reach::Excluded(
            "enrolment starts on the admin socket, the trust root (design 5.2); adding from the UI is part 2",
        ),
    ),
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
        let src = include_str!("../admin/mod.rs");
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
        let handlers: String = [include_str!("pages.rs"), include_str!("auth.rs")]
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
        // Only sign-in, enrolment and the two static files answer without a session.
        assert_eq!(ADMIN_PUBLIC_PATHS.len(), 8);
        assert!(is_admin_path("/admin") && is_admin_path("/admin/x") && !is_admin_path("/administrator"));
    }
}
