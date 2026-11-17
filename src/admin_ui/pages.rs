//! Admin UI pages. Handlers only build `AdminRequest` values and run them through `admin::server::dispatch`
//! ([`auth::run_action`], or [`auth::begin_stepup`] for verbs that need a passkey confirmation); the rest is
//! rendering through the escaping template layer ([`super::html`]).

use std::collections::HashMap;
use std::sync::Arc;

use axum::Extension;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::Value;

use super::auth::{self, WebSession, begin_stepup, run_action};
use super::html::{self, Markup, Nav, h, time_el};
use crate::admin::{AdminRequest, AdminResponse, Late, ShownItem};
use crate::app::App;
use crate::audit::SearchFilter;
use crate::util;

pub(super) fn page(s: &WebSession, title: &str, nav: Nav, body: Markup) -> Response {
    html::respond(html::page(title, nav, s.csrf(), &s.label, body))
}

pub(super) fn problem(s: &WebSession, title: &str, message: &str, back: &str) -> Response {
    let mut r = html::respond(html::problem(title, s.csrf(), &s.label, message, back));
    *r.status_mut() = axum::http::StatusCode::CONFLICT;
    r
}

pub(super) fn result(r: AdminResponse) -> Result<Value, String> {
    if r.ok { Ok(r.result.unwrap_or(Value::Null)) } else { Err(r.error.unwrap_or_else(|| "failed".into())) }
}

pub(super) fn csrf_input(s: &WebSession) -> Markup {
    h!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", s.csrf())
}

pub(super) fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

pub(super) fn list(v: &Value) -> String {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

/// Fixed confirmation messages after a redirect (`?done=`); unknown values show nothing, so a link cannot put text
/// on the page.
pub(super) fn done_notice(done: Option<&str>) -> Markup {
    let msg = match done {
        Some("approved") => "Approved. The drafts go out at their planned times.",
        Some("denied") => "Request denied. Nothing will be sent.",
        Some("stopped") => "Stopped. Those drafts will not be sent.",
        Some("removed") => "Passkey removed. Its sessions have ended.",
        Some("revoked") => "Sessions ended.",
        Some("saved") => "Saved.",
        Some("created") => "Created.",
        Some("added") => "Added.",
        Some("deleted") => "Removed.",
        Some("client_revoked") => "Connection revoked. Its token no longer works.",
        Some("grants") => "Access changed. Temporary grants of this connection were removed.",
        Some("enabled") => "Enabled.",
        Some("disabled") => "Disabled.",
        Some("connected") => "Mailbox connected.",
        Some("reconnected") => "Mailbox reconnected.",
        Some("indexing") => "Indexing is on. The first sync runs in the background.",
        Some("index_off") => "Indexing is off and the index was deleted.",
        Some("rebuild") => "The index is being rebuilt in the background.",
        Some("ended") => "Watch removed.",
        Some("pruned") => "Old audit records were deleted.",
        Some("rewrapped") => "Secrets are now sealed with the current key.",
        Some("push_on") => "Notifications are on for this device.",
        Some("push_off") => "That device no longer gets notifications.",
        Some("push_sent") => "Test notification sent. It should appear on the device in a few seconds.",
        Some("push_failed") => {
            "The test notification could not be delivered. Turn notifications off and on again on that device."
        }
        Some("push_gone") => "The push service says that device unsubscribed; it was removed.",
        _ => return Markup::default(),
    };
    h!("<p class=\"notice ok\" role=\"status\">{}</p>", msg)
}

#[derive(Deserialize, Default)]
pub struct Done {
    pub(super) done: Option<String>,
}

pub(super) fn state_chip(state: &str) -> Markup {
    let class = match state {
        "pending" => "wait",
        "approved" | "scheduled" | "sending" | "granted" | "active" => "go",
        "sent" | "done" => "done",
        "denied" | "failed" | "send_unknown" | "missed" | "revoked" | "reauth_required" => "bad",
        _ => "quiet",
    };
    let label = match state {
        "pending" => "Waiting",
        "approved" => "Approved",
        "scheduled" => "Scheduled",
        "sending" => "Sending",
        "sent" => "Sent",
        "done" => "Done",
        "denied" => "Denied",
        "cancelled" => "Stopped",
        "expired" => "Expired",
        "skipped" => "Skipped",
        "failed" => "Failed",
        "missed" => "Missed",
        "send_unknown" => "Unknown outcome",
        "granted" => "Granted",
        "active" => "Active",
        "revoked" => "Revoked",
        "disabled" => "Disabled",
        "reauth_required" => "Needs sign-in",
        "ended" => "Ended",
        "not_approved" => "Not approved",
        other => other,
    };
    h!("<span class=\"chip {}\">{}</span>", class, label.to_string())
}

// ------------------------------------------------------------------ Overview

pub async fn overview(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>) -> Response {
    let pending = result(run_action(&app, &s, AdminRequest::RequestsList { status: Some("pending".into()) }).await);
    let approved = result(run_action(&app, &s, AdminRequest::RequestsList { status: Some("approved".into()) }).await);
    let index = result(run_action(&app, &s, AdminRequest::IndexStatus { alias: None }).await);
    let stats = result(run_action(&app, &s, AdminRequest::AuditStats).await);
    let passkeys = result(run_action(&app, &s, AdminRequest::PasskeysList).await);
    let health = app.admin_ui.health.lock().map(|h| h.clone()).unwrap_or(None);
    let mut notices = Vec::new();
    if passkeys.ok().and_then(|v| v.as_array().map(Vec::len)) == Some(1) {
        notices.push(single_passkey_notice(true));
    }
    notices.push(push_state(&app, &s, true).await);

    let waiting = match &pending {
        Ok(v) => {
            let rows: Vec<&Value> = v.as_array().map(|a| a.iter().collect()).unwrap_or_default();
            if rows.is_empty() {
                Markup::lit("<p class=\"empty\">Nothing waits for your decision.</p>")
            } else {
                Markup::concat(rows.iter().take(8).map(|r| request_row(r)))
            }
        }
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let count = pending.as_ref().ok().and_then(|v| v.as_array().map(Vec::len)).unwrap_or(0);
    let next = match &approved {
        Ok(v) => next_sends(v),
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let mailboxes = match &index {
        Ok(v) => index_rows(v),
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let health = match health {
        Some((at, checks)) => {
            let failing: Vec<String> = checks
                .as_array()
                .map(|a| a.iter().filter(|c| c["ok"] == false).map(|c| text(&c["check"])).collect())
                .unwrap_or_default();
            let summary = if failing.is_empty() {
                h!("<p><span class=\"chip done\">All checks passed</span></p>")
            } else {
                h!("<p><span class=\"chip bad\">{} failing</span> {}</p>", failing.len(), failing.join(", "))
            };
            h!("{}<p class=\"meta\">Checked {}</p>", summary, time_el(&util::rfc3339(at)))
        }
        None => Markup::lit("<p class=\"meta\">Not checked since Dove started.</p>"),
    };
    let heading = if count == 0 {
        Markup::lit("<h1>All caught up</h1>")
    } else if count == 1 {
        Markup::lit("<h1>1 request waits for you</h1>")
    } else {
        h!("<h1>{} requests wait for you</h1>", count)
    };
    let body = h!(
        "{}{}{}<div class=\"grid\"><section class=\"block wide\"><h2>Waiting for a decision</h2>\
         <div class=\"rows\">{}</div><p><a href=\"/admin/requests\">All requests</a></p></section>\
         <section class=\"block\"><h2>Next sends</h2>{}</section>\
         <section class=\"block\"><h2>Health</h2>{}<p><a class=\"btn\" href=\"/admin/health\">Run checks</a></p>\
         </section><section class=\"block wide\"><h2>Agent activity</h2>{}</section>\
         <section class=\"block wide\"><h2>Mailboxes</h2>{}</section></div>",
        heading,
        pending_count(count),
        Markup::concat(notices),
        waiting,
        next,
        health,
        match &stats {
            Ok(v) => activity(v),
            Err(e) => h!("<p class=\"notice error\">{}</p>", e),
        },
        mailboxes
    );
    page(&s, "Overview", Nav::Overview, body)
}

/// The number of waiting requests for `admin.js`, which shows it on the app icon (Badging API).
pub(super) fn pending_count(n: usize) -> Markup {
    h!("<span data-pending-count=\"{}\" hidden></span>", n)
}

/// Whether notifications reach anyone: a warning when push is set up but no device is registered, and the
/// fingerprints of the registered devices, so `admin.js` can warn when this browser's own subscription is gone (iOS
/// drops subscriptions; the push service then answers 410 and Dove forgets the device, PLAN A83).
pub(super) async fn push_state(app: &Arc<App>, s: &WebSession, warn_none: bool) -> Markup {
    if crate::push::public_key(app).await.is_err() {
        return Markup::default();
    }
    let Ok(devices) = result(run_action(app, s, AdminRequest::PushList).await) else { return Markup::default() };
    let prints: Vec<String> = devices.as_array().into_iter().flatten().map(|d| text(&d["fingerprint"])).collect();
    let none = if warn_none && prints.is_empty() {
        Markup::lit(
            "<p class=\"notice warn\">No device gets notifications, so new requests wait unseen. \
             <a href=\"/admin/settings#notifications\">Turn notifications on</a></p>",
        )
    } else {
        Markup::default()
    };
    h!(
        "{}<p class=\"notice warn\" data-push-lost data-fingerprints=\"{}\" hidden>This device no longer gets \
         notifications. <a href=\"/admin/settings#notifications\">Turn them on again</a></p>",
        none,
        prints.join(" ")
    )
}

/// The overview's activity block: three numbers, a 14-day bar chart (inline SVG; the CSP allows no inline styles) and
/// one row per connection for 7 days. Watch polls are counted apart, they would bury everything else.
fn activity(v: &Value) -> Markup {
    let days: Vec<(String, i64, i64)> = v["days"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|d| (text(&d["date"]), d["ok"].as_i64().unwrap_or(0), d["failed"].as_i64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();
    let clients: Vec<&Value> = v["clients"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let (today_ok, today_failed) = days.last().map(|d| (d.1, d.2)).unwrap_or((0, 0));
    let writes: i64 = clients.iter().filter_map(|c| c["writes"].as_i64()).sum();
    let metric =
        |n: i64, label: &'static str| h!("<div class=\"metric\"><strong>{}</strong><span>{}</span></div>", n, label);
    let metrics = h!(
        "<div class=\"metrics\">{}{}{}</div>",
        metric(today_ok + today_failed, "calls today"),
        metric(today_failed, "failed or refused today"),
        metric(writes, "writes in 7 days")
    );
    let chart = bar_chart(&days);
    let rows = if clients.is_empty() {
        Markup::lit("<p class=\"empty\">No agent has called Dove in the last 7 days.</p>")
    } else {
        let rows = clients.iter().map(|c| {
            let actor = text(&c["actor"]);
            let n = |k: &str| c[k].as_i64().unwrap_or(0);
            let mut detail = vec![];
            if n("calls") > 0 || n("polls") == 0 {
                detail.push(format!("{} calls", n("calls")));
            }
            if n("failed") > 0 {
                detail.push(format!("{} failed", n("failed")));
            }
            if n("writes") > 0 {
                detail.push(format!("{} writes", n("writes")));
            }
            if n("polls") > 0 {
                detail.push(format!("{} watch polls", n("polls")));
            }
            h!(
                "<a class=\"row\" href=\"/admin/audit?since=7d&amp;actor={}\"><span class=\"row-main\"><strong>{}</strong>\
                 <span class=\"detail\">{}</span></span><span class=\"row-meta\">{}</span></a>",
                urlencode(&actor),
                actor,
                detail.join(" · "),
                time_el(&util::rfc3339(n("last_ts")))
            )
        });
        h!("<div class=\"rows\">{}</div>", Markup::concat(rows))
    };
    h!(
        "{}{}<h3>Connections, last 7 days</h3>{}<p class=\"meta\">Tool calls by agents, without watch polls. Days are \
         UTC. <a href=\"/admin/audit\">Search the audit log</a></p>",
        metrics,
        chart,
        rows
    )
}

/// Stacked bars per day: succeeded below, failed or refused on top. Each bar has a `<title>` with its numbers.
fn bar_chart(days: &[(String, i64, i64)]) -> Markup {
    const W: i64 = 20;
    const H: i64 = 72;
    let max = days.iter().map(|d| d.1 + d.2).max().unwrap_or(0).max(1);
    let scale = |n: i64| if n == 0 { 0 } else { (n * H / max).max(1) };
    let bars = days.iter().enumerate().map(|(i, (date, ok, failed))| {
        let x = i as i64 * W + 2;
        let (h_ok, h_failed) = (scale(*ok), scale(*failed));
        if h_ok + h_failed == 0 {
            // A quiet day still shows as a stub on the baseline, so the 14 days read as 14 days.
            return h!(
                "<g><title>{}: no calls</title><rect class=\"bar-hit\" x=\"{}\" y=\"0\" width=\"16\" \
                 height=\"{}\"></rect><rect class=\"bar-empty\" x=\"{}\" y=\"{}\" width=\"16\" height=\"2\"></rect></g>",
                date.clone(),
                x,
                H,
                x,
                H - 2
            );
        }
        h!(
            "<g><title>{}: {} ok, {} failed or refused</title>\
             <rect class=\"bar-hit\" x=\"{}\" y=\"0\" width=\"16\" height=\"{}\"></rect>\
             <rect class=\"bar-ok\" x=\"{}\" y=\"{}\" width=\"16\" height=\"{}\"></rect>\
             <rect class=\"bar-failed\" x=\"{}\" y=\"{}\" width=\"16\" height=\"{}\"></rect></g>",
            date.clone(),
            ok,
            failed,
            x,
            H,
            x,
            H - h_ok,
            h_ok,
            x,
            H - h_ok - h_failed,
            h_failed
        )
    });
    let date = |i: usize| days.get(i).map(|d| d.0.get(5..).unwrap_or_default().to_string()).unwrap_or_default();
    let total: i64 = days.iter().map(|d| d.1 + d.2).sum();
    h!(
        "<div class=\"chart-wrap\"><svg class=\"chart\" viewBox=\"0 0 {} {}\" preserveAspectRatio=\"none\" \
         role=\"img\" aria-label=\"{} agent calls in the last {} days, busiest day {}\">\
         <line class=\"axis\" x1=\"0\" y1=\"{}\" x2=\"{}\" y2=\"{}\" vector-effect=\"non-scaling-stroke\"></line>\
         {}</svg><div class=\"chart-axis\" aria-hidden=\"true\"><span>{}</span><span>{}</span></div></div>",
        days.len() as i64 * W,
        H,
        total,
        days.len(),
        max,
        H,
        days.len() as i64 * W,
        H,
        Markup::concat(bars),
        date(0),
        date(days.len().saturating_sub(1))
    )
}

fn request_row(r: &Value) -> Markup {
    if r["kind"] == "access" {
        let n = r["access"]["grants"].as_array().map(Vec::len).unwrap_or(0);
        let boxes = if n == 1 { "1 mailbox".to_string() } else { format!("{n} mailboxes") };
        return h!(
            "<a class=\"row\" href=\"/admin/requests/{}\"><span class=\"row-main\"><strong>{}</strong> \
             <span class=\"muted\">asks for access to</span> {}</span>\
             <span class=\"row-meta\">{} {} {}</span></a>",
            text(&r["request_id"]),
            text(&r["client"]),
            boxes,
            state_chip(&text(&r["status"])),
            duration_text(r["access"]["duration_minutes"].as_i64()),
            time_el(&text(&r["created_at"]))
        );
    }
    let items = r["items"].as_array().map(Vec::len).unwrap_or(0);
    let drafts = if items == 1 { "1 draft".to_string() } else { format!("{items} drafts") };
    h!(
        "<a class=\"row\" href=\"/admin/requests/{}\"><span class=\"row-main\"><strong>{}</strong> \
         <span class=\"muted\">wants to send from</span> <strong>{}</strong></span>\
         <span class=\"row-meta\">{} {} {}</span></a>",
        text(&r["request_id"]),
        text(&r["client"]),
        text(&r["account"]),
        state_chip(&text(&r["status"])),
        drafts,
        time_el(&text(&r["created_at"]))
    )
}

fn next_sends(approved: &Value) -> Markup {
    let mut items: Vec<(String, String, String, String)> = Vec::new();
    for r in approved.as_array().into_iter().flatten() {
        for it in r["items"].as_array().into_iter().flatten() {
            if it["state"] == "scheduled" {
                items.push((text(&it["send_at"]), text(&r["request_id"]), text(&r["client"]), text(&r["account"])));
            }
        }
    }
    items.sort();
    if items.is_empty() {
        return Markup::lit("<p class=\"empty\">No approved sends are scheduled.</p>");
    }
    let rows = items.iter().take(6).map(|(at, id, client, account)| {
        h!(
            "<a class=\"row\" href=\"/admin/requests/{}\"><span class=\"row-main\">{}</span>\
             <span class=\"row-meta\">{} <span class=\"muted\">for</span> {}</span></a>",
            id,
            time_el(at),
            account,
            client
        )
    });
    h!("<div class=\"rows\">{}</div>", Markup::concat(rows))
}

fn index_rows(v: &Value) -> Markup {
    let accounts: Vec<&Value> = v["accounts"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    if accounts.is_empty() {
        return Markup::lit("<p class=\"empty\">No mailboxes are connected.</p>");
    }
    let rows = accounts.iter().map(|a| {
        let stage = text(&a["stage"]);
        let (chip, label) = match (stage.as_str(), a["last_error"].is_string()) {
            ("disabled", _) => ("quiet", "Not indexed"),
            (_, true) => ("bad", "Sync error"),
            ("ready", false) => ("done", "Up to date"),
            _ => ("wait", "Indexing"),
        };
        let detail = match a["indexed_messages"].as_i64() {
            Some(n) => {
                let lag = a["lag_seconds"].as_i64().map(lag_text).unwrap_or_default();
                format!("{n} messages{lag}")
            }
            None => String::new(),
        };
        h!(
            "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong></span><span class=\"row-meta\">\
             <span class=\"chip {}\">{}</span> {}</span></div>",
            text(&a["account"]),
            chip,
            label,
            detail
        )
    });
    h!("<div class=\"rows\">{}</div>", Markup::concat(rows))
}

fn lag_text(secs: i64) -> String {
    match secs {
        ..=90 => ", synced just now".into(),
        91..=5400 => format!(", synced {} min ago", secs / 60),
        _ => format!(", synced {} h ago", secs / 3600),
    }
}

// ------------------------------------------------------------------ Health

pub async fn health(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>) -> Response {
    let r = result(run_action(&app, &s, AdminRequest::Doctor).await);
    let index = result(run_action(&app, &s, AdminRequest::IndexStatus { alias: None }).await);
    let devices = result(run_action(&app, &s, AdminRequest::PushList).await);
    let checks = match r {
        Ok(checks) => {
            if let Ok(mut h) = app.admin_ui.health.lock() {
                *h = Some((util::now_unix(), checks.clone()));
            }
            let rows = checks.as_array().into_iter().flatten().filter(|c| c["check"] != "public_url").map(|c| {
                let (chip, label) = if c["ok"] == true { ("done", "OK") } else { ("bad", "Check") };
                h!(
                    "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong><span class=\"detail\">{}\
                     </span></span><span class=\"row-meta\"><span class=\"chip {}\">{}</span></span></div>",
                    text(&c["check"]).replace('_', " "),
                    text(&c["detail"]),
                    chip,
                    label
                )
            });
            h!("<div class=\"rows\">{}</div>", Markup::concat(rows))
        }
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let mailboxes = match &index {
        Ok(v) => sync_rows(v),
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let alerts = match &devices {
        Ok(v) => {
            let n = v.as_array().map(Vec::len).unwrap_or(0);
            let reach = match n {
                0 => Markup::lit(
                    "<p><span class=\"chip wait\">No device</span> Alerts go to the log only. \
                     <a href=\"/admin/settings#notifications\">Turn on notifications</a> on your phone.</p>",
                ),
                1 => Markup::lit("<p><span class=\"chip done\">1 device</span> gets alerts as notifications.</p>"),
                n => h!("<p><span class=\"chip done\">{} devices</span> get alerts as notifications.</p>", n),
            };
            h!(
                "{}<p class=\"meta\">Dove alerts you when a mailbox needs reconnecting or has not synced for 2 hours, \
                 when the disk is almost full, when a connection is used from a new address, and after a burst of \
                 denied calls.</p>",
                reach
            )
        }
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let body = h!(
        "<h1>Health</h1><div class=\"grid\"><section class=\"block wide\"><h2>Mailboxes</h2>{}</section>\
         <section class=\"block wide\"><h2>Alerts</h2>{}</section>\
         <section class=\"block wide\"><h2>Checks</h2>{}</section></div>",
        mailboxes,
        alerts,
        checks
    );
    page(&s, "Health", Nav::Overview, body)
}

/// One row per mailbox on the health page: whether it can be used, how fresh its index is, and what failed last.
fn sync_rows(v: &Value) -> Markup {
    let accounts: Vec<&Value> = v["accounts"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    if accounts.is_empty() {
        return Markup::lit("<p class=\"empty\">No mailboxes are connected.</p>");
    }
    let rows = accounts.iter().map(|a| {
        let alias = text(&a["account"]);
        let lag = a["lag_seconds"].as_i64();
        let (chip, label) = match (text(&a["account_status"]).as_str(), text(&a["stage"]).as_str()) {
            ("reauth_required", _) => ("bad", "Reconnect"),
            ("disabled", _) => ("quiet", "Off"),
            (_, "disabled") => ("quiet", "Not indexed"),
            _ if lag.is_some_and(|l| l > crate::health::STALL_SECS) => ("bad", "Not syncing"),
            _ if a["last_error"].is_string() => ("wait", "Retrying"),
            (_, "ready") => ("done", "Up to date"),
            _ => ("wait", "Indexing"),
        };
        let mut detail = Vec::new();
        if let Some(l) = lag {
            detail.push(lag_text(l).trim_start_matches(", ").to_string());
        }
        if let Some(n) = a["retry_pending"].as_i64().filter(|n| *n > 0) {
            detail.push(format!("{n} messages to retry"));
        }
        if let Some(e) = a["last_error"].as_str() {
            let e: String = e.chars().take(120).collect();
            detail.push(format!("last error: {e}"));
        }
        h!(
            "<a class=\"row\" href=\"/admin/mailboxes/{}\"><span class=\"row-main\"><strong>{}</strong>\
             <span class=\"detail\">{}</span></span><span class=\"row-meta\"><span class=\"chip {}\">{}</span>\
             </span></a>",
            alias.clone(),
            alias,
            detail.join(" · "),
            chip,
            label
        )
    });
    h!("<div class=\"rows\">{}</div>", Markup::concat(rows))
}

// ------------------------------------------------------------------ Requests

#[derive(Deserialize, Default)]
pub struct RequestsQuery {
    show: Option<String>,
}

pub async fn requests(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Query(q): Query<RequestsQuery>,
) -> Response {
    let show = match q.show.as_deref() {
        Some("scheduled") => "scheduled",
        Some("history") => "history",
        _ => "pending",
    };
    let all = match result(run_action(&app, &s, AdminRequest::RequestsList { status: None }).await) {
        Ok(v) => v,
        Err(e) => return problem(&s, "Requests", &e, "/admin"),
    };
    let rows: Vec<&Value> = all
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| match (show, r["status"].as_str().unwrap_or("")) {
            ("pending", st) => st == "pending",
            ("scheduled", st) => st == "approved",
            (_, st) => st != "pending" && st != "approved",
        })
        .collect();
    let tab = |key: &'static str, label: &'static str| {
        if key == show {
            h!("<a href=\"/admin/requests?show={}\" aria-current=\"page\">{}</a>", key, label)
        } else {
            h!("<a href=\"/admin/requests?show={}\">{}</a>", key, label)
        }
    };
    let tabs = Markup::concat([tab("pending", "Waiting"), tab("scheduled", "Scheduled"), tab("history", "History")]);
    let list = if rows.is_empty() {
        Markup::lit(match show {
            "pending" => "<p class=\"empty\">No request waits for a decision. Agents ask with request_send.</p>",
            "scheduled" => "<p class=\"empty\">No approved request has drafts left to send.</p>",
            _ => "<p class=\"empty\">No decided requests yet.</p>",
        })
    } else {
        Markup::concat(rows.iter().map(|r| request_row(r)))
    };
    let waiting = all.as_array().into_iter().flatten().filter(|r| r["status"] == "pending").count();
    let body = h!(
        "<h1>Requests</h1>{}<nav class=\"tabs\" aria-label=\"Requests\">{}</nav><div class=\"rows\">{}</div>",
        pending_count(waiting),
        tabs,
        list
    );
    page(&s, "Requests", Nav::Requests, body)
}

pub async fn request_detail(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(id): Path<String>,
    Query(d): Query<Done>,
) -> Response {
    let v = match result(run_action(&app, &s, AdminRequest::RequestsShow { id: id.clone() }).await) {
        Ok(v) => v,
        Err(e) => return problem(&s, "Request", &e, "/admin/requests"),
    };
    page(&s, "Request", Nav::Requests, request_body(&s, &id, &v, d.done.as_deref()))
}

fn request_body(s: &WebSession, id: &str, v: &Value, done: Option<&str>) -> Markup {
    if v["kind"] == "access" {
        return access_body(s, id, v, done);
    }
    let status = text(&v["status"]);
    let note = match v["note"].as_str() {
        Some(n) => h!(
            "<figure class=\"note\"><figcaption>Note from the agent</figcaption><blockquote>{}</blockquote></figure>",
            n
        ),
        None => Markup::default(),
    };
    let reply = if v["unless_reply"] == true {
        Markup::lit("<p class=\"meta\">Each draft is skipped if someone replies in its thread first.</p>")
    } else {
        Markup::default()
    };
    let items: Vec<&Value> = v["items"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let decided = match v["decided_by"].as_str() {
        Some(by) => h!(
            "<p class=\"meta\">Decided by {} on {}</p>",
            by,
            v["decided_at"].as_str().map(time_el).unwrap_or_default()
        ),
        None => Markup::default(),
    };
    let head = h!(
        "<header class=\"req-head\"><p class=\"crumb\"><a href=\"/admin/requests\">Requests</a></p>\
         <h1><strong>{}</strong> wants to send {} from {}</h1>\
         <p class=\"meta\">{} Project {}. Asked {}, expires {}.</p>{}{}</header>",
        text(&v["client"]),
        if items.len() == 1 { "1 draft".to_string() } else { format!("{} drafts", items.len()) },
        text(&v["account"]),
        state_chip(&status),
        text(&v["project"]),
        time_el(&text(&v["created_at"])),
        time_el(&text(&v["expires_at"])),
        reply,
        decided
    );
    let pending = status == "pending";
    let letters = Markup::concat(items.iter().map(|it| letter(it, pending)));
    let actions = if pending {
        let late = items.iter().any(|it| it["late"] == true);
        let late_choice = if late {
            Markup::lit(
                "<fieldset class=\"late\"><legend>Some planned times have passed</legend>\
                 <label><input type=\"radio\" name=\"late\" value=\"skip\" checked> Skip those drafts</label>\
                 <label><input type=\"radio\" name=\"late\" value=\"send\"> Send them now</label></fieldset>",
            )
        } else {
            Markup::default()
        };
        h!(
            "<form id=\"approve\" method=\"post\" action=\"/admin/requests/{}/approve\" data-stepup>{}{}{}\
             <div class=\"actionbar\"><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <button type=\"submit\" class=\"btn primary\">Approve selected</button>\
             <button type=\"submit\" class=\"btn danger\" form=\"deny\">Deny request</button></div></form>\
             <form id=\"deny\" method=\"post\" action=\"/admin/requests/{}/deny\" data-confirm=\"Deny this request? \
             Nothing will be sent.\">{}</form>",
            id,
            csrf_input(s),
            letters,
            late_choice,
            id,
            csrf_input(s)
        )
    } else if status == "approved" {
        let stop_all = if items.iter().any(|it| it["state"] == "scheduled") {
            h!(
                "<form method=\"post\" action=\"/admin/requests/{}/cancel\" data-confirm=\"Stop every draft that \
                 has not been sent?\">{}<div class=\"actionbar\"><button type=\"submit\" class=\"btn danger\">\
                 Stop all unsent</button></div></form>",
                id,
                csrf_input(s)
            )
        } else {
            Markup::default()
        };
        let stops = Markup::concat(items.iter().map(|it| {
            let l = letter(it, false);
            if it["state"] == "scheduled" {
                h!(
                    "{}<form class=\"stop\" method=\"post\" action=\"/admin/requests/{}/cancel\">{}\
                     <input type=\"hidden\" name=\"item\" value=\"{}\"><button type=\"submit\" class=\"btn\">\
                     Stop this draft</button></form>",
                    l,
                    id,
                    csrf_input(s),
                    it["idx"].as_u64().unwrap_or(0)
                )
            } else {
                l
            }
        }));
        h!("{}{}", stops, stop_all)
    } else {
        letters
    };
    h!("{}{}{}{}", done_notice(done), head, note, actions)
}

/// `for 2 hours`, `for 3 days`, `for 45 minutes`, or `permanently` (None).
fn duration_text(minutes: Option<i64>) -> String {
    match minutes {
        None => "permanently".into(),
        Some(m) if m % 1440 == 0 => format!("for {} day{}", m / 1440, if m == 1440 { "" } else { "s" }),
        Some(m) if m % 60 == 0 => format!("for {} hour{}", m / 60, if m == 60 { "" } else { "s" }),
        Some(m) => format!("for {m} minute{}", if m == 1 { "" } else { "s" }),
    }
}

fn note_figure(v: &Value) -> Markup {
    match v["note"].as_str() {
        Some(n) => h!(
            "<figure class=\"note\"><figcaption>Note from the agent</figcaption><blockquote>{}</blockquote></figure>",
            n
        ),
        None => Markup::default(),
    }
}

/// An access request (`request_access`): what the agent asks for per mailbox, what it has now, and the approval with an
/// optional shorter duration. Approving widens grants, so it goes through the passkey confirmation like a send.
fn access_body(s: &WebSession, id: &str, v: &Value, done: Option<&str>) -> Markup {
    let status = text(&v["status"]);
    let pending = status == "pending";
    let decided = match v["decided_by"].as_str() {
        Some(by) => h!(
            "<p class=\"meta\">Decided by {} on {}</p>",
            by,
            v["decided_at"].as_str().map(time_el).unwrap_or_default()
        ),
        None => Markup::default(),
    };
    let until = match v["granted_until"].as_str() {
        Some(t) => h!("<p class=\"meta\">Granted until {}</p>", time_el(t)),
        None => Markup::default(),
    };
    let head = h!(
        "<header class=\"req-head\"><p class=\"crumb\"><a href=\"/admin/requests\">Requests</a></p>\
         <h1><strong>{}</strong> asks for access {}</h1>\
         <p class=\"meta\">{} Project {}. Asked {}, expires {}.</p>{}{}</header>",
        text(&v["client"]),
        duration_text(v["duration_minutes"].as_i64()),
        state_chip(&status),
        text(&v["project"]),
        time_el(&text(&v["created_at"])),
        time_el(&text(&v["expires_at"])),
        decided,
        until
    );
    let grants = Markup::concat(v["grants"].as_array().into_iter().flatten().map(|g| {
        let idx = g["idx"].as_u64().unwrap_or(0);
        let mailbox = g["account"].as_str().unwrap_or("a removed mailbox").to_string();
        let has = match g["has"].as_str() {
            Some(a) if !a.is_empty() => a.to_string(),
            _ => "nothing".into(),
        };
        let temporary = Markup::concat(
            g["temporary"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| h!("<dd>{} until {}</dd>", text(&t["actions"]), time_el(&text(&t["expires_at"])))),
        );
        let temporary = if g["temporary"].as_array().is_some_and(|a| !a.is_empty()) {
            h!("<dt>Temporary</dt>{}", temporary)
        } else {
            Markup::default()
        };
        let mut flags = Vec::new();
        if g["in_project"] == false {
            flags.push(Markup::lit("<span class=\"chip bad\">No longer in the project</span>"));
        }
        if let Some(st) = g["status"].as_str()
            && st != "active"
        {
            flags.push(h!("<span class=\"chip quiet\">Mailbox {}</span>", st.replace('_', " ")));
        }
        let pick = if pending {
            h!(
                "<label class=\"pick\"><input type=\"checkbox\" name=\"item\" value=\"{}\" checked> Grant this</label>",
                idx
            )
        } else {
            Markup::default()
        };
        h!(
            "<article class=\"grant\"><p class=\"when\">{} <strong>{}</strong> {}</p>{}\
             <dl class=\"envelope\"><dt>Asks for</dt><dd>{}</dd><dt>Has now</dt><dd>{}</dd>{}</dl></article>",
            state_chip(&text(&g["state"])),
            mailbox,
            Markup::concat(flags),
            pick,
            text(&g["asked"]),
            has,
            temporary
        )
    }));
    let actions = if pending {
        h!(
            "<form id=\"approve\" method=\"post\" action=\"/admin/requests/{}/approve\" data-stepup>{}\
             <input type=\"hidden\" name=\"kind\" value=\"access\">{}\
             <p class=\"field\"><label for=\"duration\">Shorter time in minutes (optional)</label>\
             <input id=\"duration\" name=\"duration\" type=\"number\" min=\"1\" max=\"43200\" inputmode=\"numeric\"></p>\
             <div class=\"actionbar\"><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <button type=\"submit\" class=\"btn primary\">Approve selected</button>\
             <button type=\"submit\" class=\"btn danger\" form=\"deny\">Deny request</button></div></form>\
             <form id=\"deny\" method=\"post\" action=\"/admin/requests/{}/deny\" data-confirm=\"Deny this request? \
             Nothing changes.\">{}</form>",
            id,
            csrf_input(s),
            grants,
            id,
            csrf_input(s)
        )
    } else if status == "approved" && v["granted_until"].is_string() {
        h!(
            "{}<form method=\"post\" action=\"/admin/requests/{}/cancel\" data-confirm=\"End this access now?\">{}\
             <div class=\"actionbar\"><button type=\"submit\" class=\"btn danger\">End access now</button></div></form>",
            grants,
            id,
            csrf_input(s)
        )
    } else {
        grants
    };
    let notice = match done {
        Some("approved") => Markup::lit("<p class=\"notice ok\" role=\"status\">Approved. The access is granted.</p>"),
        Some("denied") => Markup::lit("<p class=\"notice ok\" role=\"status\">Request denied. Nothing changes.</p>"),
        Some("stopped") => Markup::lit("<p class=\"notice ok\" role=\"status\">Access ended.</p>"),
        _ => Markup::default(),
    };
    h!("{}{}{}{}", notice, head, note_figure(v), actions)
}

/// One draft, shown like a letter. Pending items carry the approval checkbox and the revision that was shown.
fn letter(it: &Value, pending: bool) -> Markup {
    let idx = it["idx"].as_u64().unwrap_or(0);
    let state = text(&it["state"]);
    let mut flags = Vec::new();
    if it["late"] == true {
        flags.push(Markup::lit("<span class=\"chip wait\">Time has passed</span>"));
    }
    if it["changed_since_request"] == true {
        flags.push(Markup::lit("<span class=\"chip quiet\">Changed since the agent asked</span>"));
    }
    let sendable = it["sendable"] == true;
    if it.get("revision").is_some() && !sendable {
        flags.push(Markup::lit("<span class=\"chip bad\">Changed outside Dove, cannot be sent</span>"));
    }
    // An item left out at approval is "not approved", not a second "denied" chip next to its reason.
    let shown_state = if it["reason"] == "not_approved" { "not_approved".to_string() } else { state.clone() };
    if let Some(r) = it["reason"].as_str().filter(|r| *r != "not_approved") {
        flags.push(h!("<span class=\"chip quiet\">{}</span>", r.replace('_', " ")));
    }
    let when = h!(
        "<p class=\"when\">{} {} {}</p>",
        state_chip(&shown_state),
        time_el(&text(&it["send_at"])),
        Markup::concat(flags)
    );
    let pick = match (pending, it["revision"].as_str()) {
        (true, Some(rev)) if sendable => h!(
            "<label class=\"pick\"><input type=\"checkbox\" name=\"item\" value=\"{}\" checked> Send this draft</label>\
             <input type=\"hidden\" name=\"rev.{}\" value=\"{}\">",
            idx,
            idx,
            rev.to_string()
        ),
        _ => Markup::default(),
    };
    if let Some(e) = it["error"].as_str() {
        return h!(
            "<article class=\"letter unreadable\">{}<p class=\"notice error\">This draft cannot be read ({}). \
             It will not be sent.</p></article>",
            when,
            e.replace('_', " ")
        );
    }
    if it.get("revision").is_none() {
        return h!("<article class=\"letter compact\">{}</article>", when);
    }
    let row = |k: &'static str, v: String| {
        if v.is_empty() { Markup::default() } else { h!("<dt>{}</dt><dd>{}</dd>", k, v) }
    };
    let envelope = Markup::concat([
        row("From", one_address(&text(&it["from"]))),
        row("To", list(&it["to"])),
        row("Cc", list(&it["cc"])),
        row("Bcc", list(&it["bcc"])),
    ]);
    let subject = it["subject"].as_str().filter(|s| !s.is_empty()).unwrap_or("(no subject)").to_string();
    let attachments: Vec<Markup> = it["attachments"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| h!("<li><span>{}</span> <span class=\"muted\">{}</span></li>", text(&a["name"]), size(&a["size"])))
        .collect();
    let attachments = if attachments.is_empty() {
        Markup::default()
    } else {
        h!("<ul class=\"attachments\" aria-label=\"Attachments\">{}</ul>", Markup::concat(attachments))
    };
    let html_note = match it["html_signature"].as_str() {
        Some(sig) => h!(
            "<p class=\"hint\">Also sent as HTML: the same text with the signature '{}' and its images.</p>",
            sig.to_string()
        ),
        None => Markup::default(),
    };
    // The body is text and stays text: escaped into <pre>, never parsed as HTML.
    h!(
        "<article class=\"letter\"><div class=\"letter-top\">{}{}</div><dl class=\"envelope\">{}</dl>\
         <h2 class=\"subject\">{}</h2><pre class=\"letter-body\">{}</pre>{}{}</article>",
        when,
        pick,
        envelope,
        subject,
        text(&it["body_text"]),
        html_note,
        attachments
    )
}

fn size(v: &Value) -> String {
    match v.as_u64() {
        Some(n) if n >= 1024 * 1024 => format!("{:.1} MB", n as f64 / 1_048_576.0),
        Some(n) if n >= 1024 => format!("{} KB", n / 1024),
        Some(n) => format!("{n} bytes"),
        None => String::new(),
    }
}

/// Form fields as pairs (repeated `item` keys stay apart).
pub(super) type Fields = Form<Vec<(String, String)>>;

pub(super) fn chosen_items(fields: &[(String, String)]) -> Result<Vec<u32>, String> {
    fields
        .iter()
        .filter(|(k, _)| k == "item")
        .map(|(_, v)| v.parse::<u32>().map_err(|_| "invalid item".to_string()))
        .collect()
}

pub async fn request_approve(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(id): Path<String>,
    Form(fields): Fields,
) -> Response {
    let items = match chosen_items(&fields) {
        Ok(i) if !i.is_empty() => i,
        Ok(_) => {
            return axum::Json(serde_json::json!({ "error": "Select at least one item, or deny the request." }))
                .into_response();
        }
        Err(e) => return axum::Json(serde_json::json!({ "error": e })).into_response(),
    };
    if fields.iter().any(|(k, v)| k == "kind" && v == "access") {
        // Access requests have no drafts and no revisions; the verb refuses this shape for a send request.
        let duration_minutes = match fields.iter().find(|(k, _)| k == "duration").map(|(_, v)| v.trim()) {
            None | Some("") => None,
            Some(d) => match d.parse::<u32>() {
                Ok(m) => Some(m),
                Err(_) => {
                    return axum::Json(serde_json::json!({ "error": "Enter the time in whole minutes." }))
                        .into_response();
                }
            },
        };
        let action = AdminRequest::RequestsApprove {
            id: id.clone(),
            shown: vec![],
            items: Some(items),
            late: Late::Skip,
            duration_minutes,
        };
        return begin_stepup(&app, &s, action, format!("/admin/requests/{}?done=approved", urlencode(&id))).await;
    }
    let revs: HashMap<&str, &str> =
        fields.iter().filter_map(|(k, v)| k.strip_prefix("rev.").map(|i| (i, v.as_str()))).collect();
    let mut shown = Vec::new();
    for i in &items {
        let Some(rev) = revs.get(i.to_string().as_str()) else {
            return axum::Json(serde_json::json!({ "error": "Reload the page and try again." })).into_response();
        };
        shown.push(ShownItem { idx: *i, revision: (*rev).to_string() });
    }
    let late = match fields.iter().find(|(k, _)| k == "late").map(|(_, v)| v.as_str()) {
        Some("send") => Late::Send,
        _ => Late::Skip,
    };
    let action =
        AdminRequest::RequestsApprove { id: id.clone(), shown, items: Some(items), late, duration_minutes: None };
    begin_stepup(&app, &s, action, format!("/admin/requests/{}?done=approved", urlencode(&id))).await
}

pub async fn request_deny(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(id): Path<String>,
) -> Response {
    match result(run_action(&app, &s, AdminRequest::RequestsDeny { id: id.clone() }).await) {
        Ok(_) => Redirect::to(&format!("/admin/requests/{}?done=denied", urlencode(&id))).into_response(),
        Err(e) => problem(&s, "Not denied", &e, &format!("/admin/requests/{}", urlencode(&id))),
    }
}

pub async fn request_cancel(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(id): Path<String>,
    Form(fields): Fields,
) -> Response {
    let back = format!("/admin/requests/{}", urlencode(&id));
    let items = match chosen_items(&fields) {
        Ok(i) if i.is_empty() => None,
        Ok(i) => Some(i),
        Err(e) => return problem(&s, "Not stopped", &e, &back),
    };
    match result(run_action(&app, &s, AdminRequest::RequestsCancel { id, items }).await) {
        Ok(_) => Redirect::to(&format!("{back}?done=stopped")).into_response(),
        Err(e) => problem(&s, "Not stopped", &e, &back),
    }
}

/// `Name <addr>` as is, but a bare address when the name only repeats it (`a@x <a@x>` shows as `a@x`).
pub(super) fn one_address(from: &str) -> String {
    if let Some((name, rest)) = from.rsplit_once(" <")
        && let Some(addr) = rest.strip_suffix('>')
        && name.trim().trim_matches('"').eq_ignore_ascii_case(addr.trim())
    {
        return addr.trim().to_string();
    }
    from.to_string()
}

pub(super) fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ------------------------------------------------------------------ Audit

#[derive(Deserialize, Default, Clone)]
pub struct AuditQuery {
    actor: Option<String>,
    tool: Option<String>,
    account: Option<String>,
    /// Empty for any, `failed` for anything but ok, else one result code.
    result: Option<String>,
    since: Option<String>,
    object: Option<String>,
    before: Option<i64>,
    /// `1` includes watch polls.
    polls: Option<String>,
}

impl AuditQuery {
    /// This search as a link: `before` pages to older records, `set` replaces one filter (a value clicked in a row).
    fn link(&self, before: Option<i64>, set: Option<(&'static str, &str)>) -> String {
        let mut pairs: Vec<(&str, String)> = vec![];
        let mut put = |k: &'static str, v: &Option<String>| {
            if let Some(v) = nonempty(v) {
                pairs.push((k, v));
            }
        };
        put("actor", &self.actor);
        put("tool", &self.tool);
        put("account", &self.account);
        put("result", &self.result);
        put("since", &self.since);
        put("object", &self.object);
        put("polls", &self.polls);
        if let Some((k, v)) = set {
            pairs.retain(|(pk, _)| *pk != k);
            pairs.push((k, v.to_string()));
        }
        if let Some(b) = before {
            pairs.push(("before", b.to_string()));
        }
        let qs: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={}", urlencode(v))).collect();
        format!("/admin/audit?{}", qs.join("&"))
    }
}

const AUDIT_PAGE: i64 = 100;

fn nonempty(v: &Option<String>) -> Option<String> {
    v.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

const SINCE: &[(&str, &str, i64)] = &[
    ("1h", "Last hour", 3600),
    ("1d", "Last 24 hours", 86_400),
    ("7d", "Last 7 days", 7 * 86_400),
    ("30d", "Last 30 days", 30 * 86_400),
    ("all", "Any time", 0),
];

pub async fn audit(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Query(q): Query<AuditQuery>,
) -> Response {
    audit_page(&app, &s, &q, None).await
}

pub async fn audit_verify(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let v = result(run_action(&app, &s, AdminRequest::AuditVerify).await);
    let notice = match v {
        Ok(r) if r["ok"] == true => h!(
            "<p class=\"notice ok\" role=\"status\">The audit chain is intact: {} records checked.</p>",
            r["records"].as_i64().unwrap_or(0)
        ),
        Ok(r) => h!(
            "<p class=\"notice error\" role=\"status\">The audit chain is broken at record {}. Records were changed or \
             removed outside Dove.</p>",
            r["first_bad_seq"].as_i64().unwrap_or(0)
        ),
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    audit_page(&app, &s, &q, Some(notice)).await
}

async fn audit_page(app: &Arc<App>, s: &WebSession, q: &AuditQuery, notice: Option<Markup>) -> Response {
    let since_key = q.since.clone().unwrap_or_else(|| "7d".into());
    let since_secs = SINCE.iter().find(|(k, _, _)| *k == since_key).map(|x| x.2).unwrap_or(7 * 86_400);
    let result_sel = nonempty(&q.result).unwrap_or_default();
    let polls = q.polls.as_deref() == Some("1");
    let filter = SearchFilter {
        actor: nonempty(&q.actor),
        tool: nonempty(&q.tool),
        account: nonempty(&q.account),
        result_code: (!result_sel.is_empty() && result_sel != "failed").then(|| result_sel.clone()),
        failed: (result_sel == "failed").then_some(true),
        object: nonempty(&q.object),
        before: q.before,
        hide_polls: (!polls).then_some(true),
        since: (since_secs > 0).then(|| util::now_unix() - since_secs),
        limit: Some(AUDIT_PAGE),
    };
    let rows = result(run_action(app, s, AdminRequest::AuditSearch { filter }).await);
    let values = result(run_action(app, s, AdminRequest::AuditStats).await).map(|v| v["values"].clone()).ok();
    let suggestions = |id: &'static str, key: &str| {
        let opts = values.as_ref().and_then(|v| v[key].as_array().cloned()).unwrap_or_default();
        h!(
            "<datalist id=\"{}\">{}</datalist>",
            id,
            Markup::concat(opts.iter().map(|o| h!("<option value=\"{}\"></option>", text(o))))
        )
    };
    let field =
        |name: &'static str, label: &'static str, value: &Option<String>, hint: &'static str, list: &'static str| {
            h!(
                "<label><span>{}</span><input name=\"{}\" value=\"{}\" placeholder=\"{}\"{} \
             autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\"></label>",
                label,
                name,
                value.clone().unwrap_or_default(),
                hint,
                if list.is_empty() { Markup::lit("") } else { h!(" list=\"{}\"", list) }
            )
        };
    let options = Markup::concat(SINCE.iter().map(|(k, label, _)| {
        if *k == since_key {
            h!("<option value=\"{}\" selected>{}</option>", *k, *label)
        } else {
            h!("<option value=\"{}\">{}</option>", *k, *label)
        }
    }));
    let mut results: Vec<(String, String)> =
        vec![("".into(), "Any".into()), ("failed".into(), "Failed or refused".into())];
    for r in values.as_ref().and_then(|v| v["results"].as_array().cloned()).unwrap_or_default() {
        let r = text(&r);
        results.push((r.clone(), r));
    }
    if !result_sel.is_empty() && !results.iter().any(|(v, _)| *v == result_sel) {
        results.push((result_sel.clone(), result_sel.clone()));
    }
    let result_opts = Markup::concat(results.iter().map(|(v, label)| {
        if *v == result_sel {
            h!("<option value=\"{}\" selected>{}</option>", v.clone(), label.clone())
        } else {
            h!("<option value=\"{}\">{}</option>", v.clone(), label.clone())
        }
    }));
    let polls_box = if polls {
        Markup::lit("<input type=\"checkbox\" name=\"polls\" value=\"1\" checked>")
    } else {
        Markup::lit("<input type=\"checkbox\" name=\"polls\" value=\"1\">")
    };
    let form = h!(
        "<form class=\"filters\" method=\"get\" action=\"/admin/audit\">{}{}{}\
         <label><span>Result</span><select name=\"result\">{}</select></label>{}\
         <label><span>Time</span><select name=\"since\">{}</select></label>\
         <label class=\"check\">{}<span>Include watch polls</span></label>\
         <div class=\"filter-actions\"><button type=\"submit\" class=\"btn primary\">Search</button>\
         <a class=\"btn\" href=\"/admin/audit\">Clear</a>\
         <button type=\"submit\" class=\"btn\" formaction=\"/admin/audit/verify\">Verify chain</button></div>\
         {}{}{}</form>",
        field("actor", "Actor", &q.actor, "connection, web:phone, uid:1000", "audit-actors"),
        field("tool", "Action", &q.tool, "send_draft, requests.approve", "audit-actions"),
        field("account", "Mailbox", &q.account, "alias", "audit-accounts"),
        result_opts,
        field("object", "Object id", &q.object, "request, draft or message id", ""),
        options,
        polls_box,
        suggestions("audit-actors", "actors"),
        suggestions("audit-actions", "actions"),
        suggestions("audit-accounts", "accounts")
    );
    let filtered = |key: &'static str, value: &str| -> Markup {
        if value.is_empty() {
            return Markup::lit("<span></span>");
        }
        h!("<a href=\"{}\">{}</a>", q.link(None, Some((key, value))), value.to_string())
    };
    let list = match rows {
        Ok(v) => {
            let recs: Vec<&Value> = v.as_array().map(|a| a.iter().collect()).unwrap_or_default();
            if recs.is_empty() {
                Markup::lit("<p class=\"empty\">No records match. Widen the time or clear a filter.</p>")
            } else {
                let rows = recs.iter().map(|r| {
                    let result = text(&r["result_code"]);
                    let chip = if result == "ok" { "done" } else { "bad" };
                    h!(
                        "<li class=\"audit-row\"><div class=\"audit-main\"><strong>{}</strong> \
                         <span class=\"chip {}\">{}</span></div><div class=\"audit-meta\"><span>{}</span>\
                         {}{}<span>{}</span><span>{}</span></div></li>",
                        filtered("tool", &text(&r["tool_or_action"])),
                        chip,
                        result,
                        time_el(&util::rfc3339(r["ts"].as_i64().unwrap_or(0))),
                        filtered("actor", &text(&r["actor"])),
                        filtered("account", &text(&r["account_alias"])),
                        list(&r["object_ids"]),
                        text(&r["source_ip"])
                    )
                });
                let more = if recs.len() as i64 == AUDIT_PAGE {
                    let last = recs.last().and_then(|r| r["seq"].as_i64());
                    h!("<p><a class=\"btn\" href=\"{}\">Older records</a></p>", q.link(last, None))
                } else {
                    Markup::lit("")
                };
                let what = if q.before.is_some() { "older records" } else { "newest records" };
                let hidden = if polls { "" } else { " Watch polls are hidden." };
                h!(
                    "<p class=\"meta\">{} {}.{}</p><ol class=\"audit\">{}</ol>{}",
                    recs.len(),
                    what,
                    hidden,
                    Markup::concat(rows),
                    more
                )
            }
        }
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let prune = h!(
        "<section class=\"block\"><h2>Retention</h2><p>Records older than {} days can be deleted. The chain stays \
         verifiable from the oldest record kept.</p><form method=\"post\" action=\"/admin/audit/prune\" \
         data-confirm=\"Delete audit records older than {} days?\">{}<button type=\"submit\" class=\"btn\">\
         Delete old records</button></form></section>",
        app.cfg.audit.retention_days,
        app.cfg.audit.retention_days,
        csrf_input(s)
    );
    let body = h!("<h1>Audit log</h1>{}{}{}{}", notice, form, list, prune);
    page(s, "Audit log", Nav::Audit, body)
}

pub async fn audit_prune(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>) -> Response {
    match result(run_action(&app, &s, AdminRequest::AuditPrune).await) {
        Ok(_) => Redirect::to("/admin/audit?done=pruned").into_response(),
        Err(e) => problem(&s, "Not deleted", &e, "/admin/audit"),
    }
}

// ------------------------------------------------------------------ Settings

pub async fn settings(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Query(d): Query<Done>,
) -> Response {
    let passkeys = result(run_action(&app, &s, AdminRequest::PasskeysList).await);
    let sessions = result(run_action(&app, &s, AdminRequest::SessionsList).await);
    let single = passkeys.as_ref().ok().and_then(|v| v.as_array().map(Vec::len)) == Some(1);
    let pk = match passkeys {
        Ok(v) => Markup::concat(v.as_array().into_iter().flatten().map(|p| {
            let name = text(&p["name"]);
            let used = match p["last_used_at"].as_str() {
                Some(t) => h!("last used {}", time_el(t)),
                None => Markup::lit("never used"),
            };
            let synced = if p["backed_up"] == true { "synced passkey" } else { "device-bound passkey" };
            let this = if name == s.label {
                Markup::lit(" <span class=\"chip go\">This session</span>")
            } else {
                Markup::default()
            };
            h!(
                "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong>{}<span class=\"detail\">{}, {}, \
                 added {}</span></span><form method=\"post\" action=\"/admin/settings/passkeys/{}/remove\" \
                 data-stepup data-confirm=\"Remove the passkey {}? Its sessions end at once.\">{}\
                 <p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
                 <button type=\"submit\" class=\"btn danger small\">Remove</button></form></div>",
                name,
                this,
                synced,
                used,
                time_el(&text(&p["created_at"])),
                urlencode(&name),
                name,
                csrf_input(&s)
            )
        })),
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let ss = match sessions {
        Ok(v) => Markup::concat(v.as_array().into_iter().flatten().map(|x| {
            let id = text(&x["id"]);
            let this = if id == s.id {
                Markup::lit(" <span class=\"chip go\">This browser</span>")
            } else {
                Markup::default()
            };
            let device = match x["device"].as_str() {
                Some(d) => h!("{}, ", d),
                None => Markup::default(),
            };
            h!(
                "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong>{}<span class=\"detail\">{}signed in \
                 {}, active {}, ends {}</span></span><form method=\"post\" action=\"/admin/settings/sessions/revoke\">\
                 {}<input type=\"hidden\" name=\"id\" value=\"{}\"><button type=\"submit\" class=\"btn small\">\
                 End</button></form></div>",
                text(&x["passkey"]),
                this,
                device,
                time_el(&text(&x["created_at"])),
                time_el(&text(&x["last_seen_at"])),
                time_el(&text(&x["expires_at"])),
                csrf_input(&s),
                id
            )
        })),
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let body = h!(
        "{}<h1>Settings</h1><section class=\"block\" id=\"passkeys\"><h2>Passkeys</h2>{}<div class=\"rows\">{}</div>\
         <form class=\"inline-form\" method=\"post\" action=\"/admin/settings/passkeys/add\" data-stepup>{}\
         <div class=\"inline-fields\"><input name=\"name\" type=\"text\" required maxlength=\"64\" \
         placeholder=\"Device, e.g. ipad\" aria-label=\"Name of the new passkey\" autocomplete=\"off\"></div>\
         <button type=\"submit\" class=\"btn\">Add a passkey</button>\
         <p class=\"status\" role=\"status\" aria-live=\"polite\"></p></form>\
         <p class=\"hint\">Dove shows a link to open on the new device. On the server, \
         <code>sudo dove admin passkey add --name &lt;device&gt;</code> does the same.</p></section>\
         {}<section class=\"block\"><h2>Sessions</h2><div class=\"rows\">{}</div>\
         <form method=\"post\" action=\"/admin/settings/sessions/revoke\" data-confirm=\"End every session, this \
         one included?\">{}<button type=\"submit\" class=\"btn danger\">End all sessions</button></form></section>\
         <section class=\"block\"><h2>Keys</h2><p>After you add a new key file and restart Dove, seal every stored \
         secret with the new key. Then the old key file can go.</p><form method=\"post\" \
         action=\"/admin/settings/keys/rewrap\" data-confirm=\"Seal all stored secrets with the current key?\">{}\
         <button type=\"submit\" class=\"btn\">Seal with the current key</button></form></section>\
         <section class=\"block\"><h2>Export</h2><p>Projects, connections and mailboxes as JSON, without any \
         secret.</p><p><a class=\"btn\" href=\"/admin/settings/export\" download>Download export</a></p></section>",
        done_notice(d.done.as_deref()),
        if single { single_passkey_notice(false) } else { Markup::default() },
        pk,
        csrf_input(&s),
        super::push::settings_block(&app, &s).await,
        ss,
        csrf_input(&s),
        csrf_input(&s)
    );
    page(&s, "Settings", Nav::Settings, body)
}

/// Shown while only one passkey exists: losing that device locks the owner out of the admin pages (PLAN A83).
macro_rules! single_passkey_text {
    () => {
        "<p class=\"notice warn\">Only one passkey can sign in. If you lose this device, only <code>sudo dove admin \
         passkey add</code> on the server gets you back in. Add a second passkey on another device, such as a Mac or \
         a security key."
    };
}

pub(super) fn single_passkey_notice(link: bool) -> Markup {
    if link {
        Markup::lit(concat!(single_passkey_text!(), " <a href=\"/admin/settings#passkeys\">Add a passkey</a></p>"))
    } else {
        Markup::lit(concat!(single_passkey_text!(), "</p>"))
    }
}

pub async fn passkey_add(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Form(fields): Fields,
) -> Response {
    let Some(name) = super::kit::field(&fields, "name") else { return super::kit::form_error("Name the passkey.") };
    let after = super::auth::After::Reveal(super::auth::RevealKind::EnrolLink);
    super::auth::begin_stepup_then(&app, &s, AdminRequest::PasskeysAdd { name }, after).await
}

pub async fn keys_rewrap(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>) -> Response {
    match result(run_action(&app, &s, AdminRequest::KeysRotate).await) {
        Ok(_) => Redirect::to("/admin/settings?done=rewrapped").into_response(),
        Err(e) => problem(&s, "Not sealed", &e, "/admin/settings"),
    }
}

/// The export as a download. `no-store` like every admin answer.
pub async fn export(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>) -> Response {
    match result(run_action(&app, &s, AdminRequest::Export).await) {
        Ok(v) => {
            let body = serde_json::to_string_pretty(&v).unwrap_or_default();
            let mut r = body.into_response();
            let h = r.headers_mut();
            h.insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/json"));
            h.insert(
                axum::http::header::CONTENT_DISPOSITION,
                axum::http::HeaderValue::from_static("attachment; filename=\"dove-export.json\""),
            );
            r
        }
        Err(e) => problem(&s, "Export", &e, "/admin/settings"),
    }
}

/// The phone's "More" tab: the sections that do not fit in the bottom bar.
pub async fn more(Extension(s): Extension<WebSession>) -> Response {
    page(&s, "More", Nav::Settings, h!("<h1>More</h1><div class=\"rows\">{}</div>", html::more_links()))
}

pub async fn passkey_remove(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
) -> Response {
    let return_to = if name == s.label { "/admin/login".to_string() } else { "/admin/settings?done=removed".into() };
    begin_stepup(&app, &s, AdminRequest::PasskeysRemove { name }, return_to).await
}

pub async fn sessions_revoke(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Form(fields): Fields,
) -> Response {
    let id = fields.iter().find(|(k, _)| k == "id").map(|(_, v)| v.clone()).filter(|v| !v.is_empty());
    let own = id.as_deref().is_none_or(|i| i == s.id);
    match result(run_action(&app, &s, AdminRequest::SessionsRevoke { id }).await) {
        Ok(_) if own => auth::logout_redirect(),
        Ok(_) => Redirect::to("/admin/settings?done=revoked").into_response(),
        Err(e) => problem(&s, "Not ended", &e, "/admin/settings"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_from_that_repeats_its_address_shows_it_once() {
        assert_eq!(one_address("a@x.test <a@x.test>"), "a@x.test");
        assert_eq!(one_address("\"A@X.test\" <a@x.test>"), "a@x.test");
        assert_eq!(one_address("Ann <a@x.test>"), "Ann <a@x.test>");
        assert_eq!(one_address("a@x.test"), "a@x.test");
        assert_eq!(one_address("b@x.test <a@x.test>"), "b@x.test <a@x.test>");
    }
}
