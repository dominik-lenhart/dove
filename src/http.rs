//! HTTP surface (spec 6.6, 7.1): loopback listener behind a TLS proxy.
//!
//! Every request passes the Host check (DNS rebinding) and, where browsers are not expected, the Origin check.
//! Routes: `/mcp`, `/healthz`, `/oauth/google/callback`, and the downstream connection/OAuth routes (spec 5.6).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use subtle::ConstantTimeEq;

use crate::app::App;
use crate::gmail::connect::{self, CallbackOutcome, CallbackQuery};

pub fn router(app: Arc<App>) -> Router {
    let mut r = Router::new()
        .route("/healthz", get(healthz))
        .route("/oauth/google/callback", get(google_callback))
        .merge(crate::mcp::routes())
        .merge(crate::oauth::routes());
    // The admin UI exists only when enabled, and never in local mode (the guard refuses `/admin` there anyway).
    if app.cfg.admin_ui.enabled && !app.cfg.is_local() {
        r = r.merge(crate::admin_ui::routes(app.clone()));
    }
    r.layer(middleware::from_fn_with_state(app.clone(), guard))
        .layer(DefaultBodyLimit::max(app.cfg.limits.body_bytes))
        .with_state(app)
}

/// Header the reverse proxy uses to prove that a loopback request comes from it (`secrets.proxy_secret_file`).
pub const PROXY_AUTH_HEADER: &str = "x-dove-proxy-auth";

/// The caller's address as decided by [`guard`], stored in the request extensions.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub Option<IpAddr>);

/// Client IP. The proxy runs on loopback and sets the real client address as the last X-Forwarded-For entry.
/// With a proxy secret configured, the header is trusted only on loopback requests whose single
/// `X-Dove-Proxy-Auth` value equals the secret (constant time); any other local process (an agent shell on the same
/// host) is seen as its loopback peer address. Without a secret every loopback peer is trusted (legacy behaviour).
pub fn client_ip(proxy_secret: Option<&str>, headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
    let peer_ip = peer.map(|p| p.ip());
    let proxied = match proxy_secret {
        None => true,
        Some(secret) => {
            let mut values = headers.get_all(PROXY_AUTH_HEADER).iter();
            match (values.next(), values.next()) {
                (Some(v), None) => {
                    let v = v.as_bytes();
                    v.len() == secret.len() && bool::from(v.ct_eq(secret.as_bytes()))
                }
                _ => false,
            }
        }
    };
    if peer_ip.is_none_or(|ip| ip.is_loopback())
        && proxied
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(last) = xff.rsplit(',').next()
        && let Ok(ip) = last.trim().parse::<IpAddr>()
    {
        return Some(ip);
    }
    peer_ip
}

/// The client IP of a request that passed [`guard`]. Without the guard's extension only the peer address counts.
pub fn request_ip(req: &Request) -> Option<IpAddr> {
    match req.extensions().get::<ClientIp>() {
        Some(c) => c.0,
        None => req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip()),
    }
}

/// Browser routes that legitimately carry our own Origin (the approval page posts to itself).
fn browser_route(path: &str) -> bool {
    path.starts_with("/oauth/dove/authorize")
}

async fn guard(State(app): State<Arc<App>>, mut req: Request, next: Next) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    // Local mode has no reverse proxy: X-Forwarded-For would only ever come from a local process forging it.
    let ip = if app.cfg.is_local() {
        peer.map(|p| p.ip())
    } else {
        client_ip(app.proxy_secret.as_deref().map(|s| s.as_str()), req.headers(), peer)
    };
    // The proxy secret goes no further than this point: handlers, logs and responses never see it.
    req.headers_mut().remove(PROXY_AUTH_HEADER);
    req.extensions_mut().insert(ClientIp(ip));
    let path = req.uri().path().to_string();
    // `/admin` has its own host, origin, credential and rate rules (design 2026-11-14 section 5.1).
    if crate::admin_ui::is_admin_path(&path) {
        return crate::admin_ui::guard(app, req, next).await;
    }
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    if path != "/healthz" && !host.eq_ignore_ascii_case(&app.cfg.public_host()) {
        return (StatusCode::MISDIRECTED_REQUEST, "wrong host").into_response();
    }
    if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok()) {
        let own = app.cfg.public_base();
        let allowed = app.cfg.allowed_origins.iter().any(|o| o == origin) || (browser_route(&path) && origin == own);
        if !allowed {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    // Under no-referrer a browser sends `Origin: null` with a form POST, so the approval page could not post to
    // itself. same-origin keeps the real Origin on our own form and still sends nothing to other sites.
    let referrer = if browser_route(&path) { "same-origin" } else { "no-referrer" };
    h.insert("referrer-policy", HeaderValue::from_static(referrer));
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

/// Returns only "ok" or "degraded" (spec 6.6).
async fn healthz(State(app): State<Arc<App>>) -> &'static str {
    let ok = app.store.call(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?)).await.is_ok();
    let reauth: i64 = app
        .store
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM accounts WHERE status = 'reauth_required'", [], |r| r.get(0))?))
        .await
        .unwrap_or(1);
    if ok && reauth == 0 { "ok" } else { "degraded" }
}

pub fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>{t}</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem}}\
         </style></head><body><h1>{t}</h1>{body}</body></html>",
        t = html_escape(title)
    )
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

async fn google_callback(State(app): State<Arc<App>>, Query(q): Query<CallbackQuery>) -> Response {
    let (status, html) = match connect::callback(&app, q).await {
        CallbackOutcome::Connected { alias, email } => (
            StatusCode::OK,
            page(
                "Mailbox connected",
                &format!(
                    "<p>The mailbox <b>{}</b> ({}) is now connected to Dove. You can close this tab.</p>",
                    html_escape(&alias),
                    html_escape(&email)
                ),
            ),
        ),
        CallbackOutcome::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, page("Not connected", &format!("<p>{}</p>", html_escape(&reason))))
        }
    };
    let mut resp = (status, Html(html)).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Serves the router on the configured loopback address until `shutdown` resolves.
pub async fn serve(
    app: Arc<App>,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let router = router(app);
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// Extracts the peer address when available (tests may call the router without connect info).
pub fn peer(req_ext: Option<&ConnectInfo<SocketAddr>>) -> Option<SocketAddr> {
    req_ext.map(|c| c.0)
}

#[allow(dead_code)]
fn _assert_body(_: Body) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    #[test]
    fn forwarded_for_needs_loopback_and_exactly_one_matching_secret() {
        let lo: Option<SocketAddr> = Some("127.0.0.1:5000".parse().unwrap());
        let remote: Option<SocketAddr> = Some("198.51.100.9:5000".parse().unwrap());
        let client: IpAddr = "203.0.113.7".parse().unwrap();
        let s = "s".repeat(40);
        let ok = headers(&[("x-forwarded-for", "10.0.0.1, 203.0.113.7"), (PROXY_AUTH_HEADER, &s)]);
        assert_eq!(client_ip(Some(&s), &ok, lo), Some(client));
        // Not from loopback: the peer is the client, whatever the headers say.
        assert_eq!(client_ip(Some(&s), &ok, remote), remote.map(|p| p.ip()));
        // A second header value (one forged, one from a proxy that appends) is refused.
        let twice = headers(&[("x-forwarded-for", "203.0.113.7"), (PROXY_AUTH_HEADER, &s), (PROXY_AUTH_HEADER, &s)]);
        assert_eq!(client_ip(Some(&s), &twice, lo), lo.map(|p| p.ip()));
        let prefix = headers(&[("x-forwarded-for", "203.0.113.7"), (PROXY_AUTH_HEADER, &s[..39])]);
        assert_eq!(client_ip(Some(&s), &prefix, lo), lo.map(|p| p.ip()));
        // Without a configured secret, loopback peers are trusted (legacy behaviour, warned about at startup).
        let bare = headers(&[("x-forwarded-for", "203.0.113.7")]);
        assert_eq!(client_ip(None, &bare, lo), Some(client));
    }
}
