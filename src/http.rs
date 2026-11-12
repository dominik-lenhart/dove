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

use crate::app::App;
use crate::gmail::connect::{self, CallbackOutcome, CallbackQuery};

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/oauth/google/callback", get(google_callback))
        .merge(crate::mcp::routes())
        .merge(crate::oauth::routes())
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .layer(DefaultBodyLimit::max(app.cfg.limits.body_bytes))
        .with_state(app)
}

/// Client IP: the proxy is on loopback and appends the real client address as the last X-Forwarded-For entry.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
    let peer_ip = peer.map(|p| p.ip());
    if peer_ip.is_none_or(|ip| ip.is_loopback())
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(last) = xff.rsplit(',').next()
        && let Ok(ip) = last.trim().parse::<IpAddr>()
    {
        return Some(ip);
    }
    peer_ip
}

/// Browser routes that legitimately carry our own Origin (the approval page posts to itself).
fn browser_route(path: &str) -> bool {
    path.starts_with("/oauth/dove/authorize")
}

async fn guard(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
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
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
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
