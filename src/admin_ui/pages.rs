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

fn page(s: &WebSession, title: &str, nav: Nav, body: Markup) -> Response {
    html::respond(html::page(title, nav, s.csrf(), &s.label, body))
}

fn problem(s: &WebSession, title: &str, message: &str, back: &str) -> Response {
    let mut r = html::respond(html::problem(title, s.csrf(), &s.label, message, back));
    *r.status_mut() = axum::http::StatusCode::CONFLICT;
    r
}

fn result(r: AdminResponse) -> Result<Value, String> {
    if r.ok { Ok(r.result.unwrap_or(Value::Null)) } else { Err(r.error.unwrap_or_else(|| "failed".into())) }
}

fn csrf_input(s: &WebSession) -> Markup {
    h!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", s.csrf())
}

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn list(v: &Value) -> String {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

/// Fixed confirmation messages after a redirect (`?done=`); unknown values show nothing, so a link cannot put text
/// on the page.
fn done_notice(done: Option<&str>) -> Markup {
    let msg = match done {
        Some("approved") => "Approved. The drafts go out at their planned times.",
        Some("denied") => "Request denied. Nothing will be sent.",
        Some("stopped") => "Stopped. Those drafts will not be sent.",
        Some("removed") => "Passkey removed. Its sessions have ended.",
        Some("revoked") => "Sessions ended.",
        _ => return Markup::default(),
    };
    h!("<p class=\"notice ok\" role=\"status\">{}</p>", msg)
}

#[derive(Deserialize, Default)]
pub struct Done {
    done: Option<String>,
}

fn state_chip(state: &str) -> Markup {
    let class = match state {
        "pending" => "wait",
        "approved" | "scheduled" | "sending" => "go",
        "sent" | "done" => "done",
        "denied" | "failed" | "send_unknown" | "missed" => "bad",
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
        other => other,
    };
    h!("<span class=\"chip {}\">{}</span>", class, label.to_string())
}

// ------------------------------------------------------------------ Overview

pub async fn overview(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>) -> Response {
    let pending = result(run_action(&app, &s, AdminRequest::RequestsList { status: Some("pending".into()) }).await);
    let approved = result(run_action(&app, &s, AdminRequest::RequestsList { status: Some("approved".into()) }).await);
    let index = result(run_action(&app, &s, AdminRequest::IndexStatus { alias: None }).await);
    let health = app.admin_ui.health.lock().map(|h| h.clone()).unwrap_or(None);

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
        "{}<section class=\"block\"><h2>Waiting for a decision</h2><div class=\"rows\">{}</div>\
         <p><a href=\"/admin/requests\">All requests</a></p></section>\
         <section class=\"block\"><h2>Next sends</h2>{}</section>\
         <section class=\"block\"><h2>Mailboxes</h2>{}</section>\
         <section class=\"block\"><h2>Health</h2>{}<p><a class=\"btn\" href=\"/admin/health\">Run checks</a></p>\
         </section>",
        heading,
        waiting,
        next,
        mailboxes,
        health
    );
    page(&s, "Overview", Nav::Overview, body)
}

fn request_row(r: &Value) -> Markup {
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
    let body = match r {
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
            h!("<h1>Health</h1><div class=\"rows\">{}</div>", Markup::concat(rows))
        }
        Err(e) => h!("<h1>Health</h1><p class=\"notice error\">{}</p>", e),
    };
    page(&s, "Health", Nav::Overview, body)
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
    let body = h!(
        "<h1>Requests</h1><nav class=\"tabs\" aria-label=\"Requests\">{}</nav><div class=\"rows\">{}</div>",
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
    if let Some(r) = it["reason"].as_str() {
        flags.push(h!("<span class=\"chip quiet\">{}</span>", r.replace('_', " ")));
    }
    let when =
        h!("<p class=\"when\">{} {} {}</p>", state_chip(&state), time_el(&text(&it["send_at"])), Markup::concat(flags));
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
        row("From", text(&it["from"])),
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
    // The body is text and stays text: escaped into <pre>, never parsed as HTML.
    h!(
        "<article class=\"letter\"><div class=\"letter-top\">{}{}</div><dl class=\"envelope\">{}</dl>\
         <h2 class=\"subject\">{}</h2><pre class=\"letter-body\">{}</pre>{}</article>",
        when,
        pick,
        envelope,
        subject,
        text(&it["body_text"]),
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
type Fields = Form<Vec<(String, String)>>;

fn chosen_items(fields: &[(String, String)]) -> Result<Vec<u32>, String> {
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
            return axum::Json(serde_json::json!({ "error": "Select at least one draft, or deny the request." }))
                .into_response();
        }
        Err(e) => return axum::Json(serde_json::json!({ "error": e })).into_response(),
    };
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

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ------------------------------------------------------------------ Audit

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    actor: Option<String>,
    tool: Option<String>,
    account: Option<String>,
    result: Option<String>,
    since: Option<String>,
}

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
    let filter = SearchFilter {
        actor: nonempty(&q.actor),
        tool: nonempty(&q.tool),
        account: nonempty(&q.account),
        result_code: nonempty(&q.result),
        since: (since_secs > 0).then(|| util::now_unix() - since_secs),
        limit: Some(200),
    };
    let rows = result(run_action(app, s, AdminRequest::AuditSearch { filter }).await);
    let field = |name: &'static str, label: &'static str, value: &Option<String>, hint: &'static str| {
        h!(
            "<label><span>{}</span><input name=\"{}\" value=\"{}\" placeholder=\"{}\" autocomplete=\"off\" \
             autocapitalize=\"off\" spellcheck=\"false\"></label>",
            label,
            name,
            value.clone().unwrap_or_default(),
            hint
        )
    };
    let options = Markup::concat(SINCE.iter().map(|(k, label, _)| {
        if *k == since_key {
            h!("<option value=\"{}\" selected>{}</option>", *k, *label)
        } else {
            h!("<option value=\"{}\">{}</option>", *k, *label)
        }
    }));
    let form = h!(
        "<form class=\"filters\" method=\"get\" action=\"/admin/audit\">{}{}{}{}\
         <label><span>Time</span><select name=\"since\">{}</select></label>\
         <div class=\"filter-actions\"><button type=\"submit\" class=\"btn primary\">Search</button>\
         <button type=\"submit\" class=\"btn\" formaction=\"/admin/audit/verify\">Verify chain</button></div></form>",
        field("actor", "Actor", &q.actor, "web:phone, uid:1000, client name"),
        field("tool", "Action", &q.tool, "send_draft, requests.approve"),
        field("account", "Mailbox", &q.account, "alias"),
        field("result", "Result", &q.result, "ok, forbidden, error"),
        options
    );
    let list = match rows {
        Ok(v) => {
            let recs: Vec<&Value> = v.as_array().map(|a| a.iter().collect()).unwrap_or_default();
            if recs.is_empty() {
                Markup::lit("<p class=\"empty\">No records match. Widen the time or clear a filter.</p>")
            } else {
                let rows = recs.iter().map(|r| {
                    let result = text(&r["result_code"]);
                    let chip = if result == "ok" { "done" } else { "bad" };
                    let ids = list(&r["object_ids"]);
                    let ip = text(&r["source_ip"]);
                    h!(
                        "<li class=\"audit-row\"><div class=\"audit-main\"><strong>{}</strong> \
                         <span class=\"chip {}\">{}</span></div><div class=\"audit-meta\"><span>{}</span>\
                         <span>{}</span><span>{}</span><span>{}</span><span>{}</span></div></li>",
                        text(&r["tool_or_action"]),
                        chip,
                        result,
                        time_el(&util::rfc3339(r["ts"].as_i64().unwrap_or(0))),
                        text(&r["actor"]),
                        text(&r["account_alias"]),
                        ids,
                        ip
                    )
                });
                h!(
                    "<p class=\"meta\">{} newest records.</p><ol class=\"audit\">{}</ol>",
                    recs.len(),
                    Markup::concat(rows)
                )
            }
        }
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let body = h!("<h1>Audit log</h1>{}{}{}", notice, form, list);
    page(s, "Audit log", Nav::Audit, body)
}

// ------------------------------------------------------------------ Settings

pub async fn settings(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Query(d): Query<Done>,
) -> Response {
    let passkeys = result(run_action(&app, &s, AdminRequest::PasskeysList).await);
    let sessions = result(run_action(&app, &s, AdminRequest::SessionsList).await);
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
            h!(
                "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong>{}<span class=\"detail\">signed in \
                 {}, active {}, ends {}</span></span><form method=\"post\" action=\"/admin/settings/sessions/revoke\">\
                 {}<input type=\"hidden\" name=\"id\" value=\"{}\"><button type=\"submit\" class=\"btn small\">\
                 End</button></form></div>",
                text(&x["passkey"]),
                this,
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
        "{}<h1>Settings</h1><section class=\"block\"><h2>Passkeys</h2><div class=\"rows\">{}</div>\
         <p class=\"hint\">To add a passkey, run <code>sudo dove admin passkey add --name &lt;device&gt;</code> on \
         the server and open the link it prints on that device.</p></section>\
         <section class=\"block\"><h2>Sessions</h2><div class=\"rows\">{}</div>\
         <form method=\"post\" action=\"/admin/settings/sessions/revoke\" data-confirm=\"End every session, this \
         one included?\">{}<button type=\"submit\" class=\"btn danger\">End all sessions</button></form></section>",
        done_notice(d.done.as_deref()),
        pk,
        ss,
        csrf_input(&s)
    );
    page(&s, "Settings", Nav::Settings, body)
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
