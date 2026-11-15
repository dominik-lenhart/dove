//! Watches and sinks page: what agents wait for (across all connections) and the webhook sinks Dove pushes events
//! to. Adding a sink needs a passkey confirmation; its URL and secret are sealed and never shown again (the list shows
//! the URL's origin only).

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde_json::Value;

use super::auth::{WebSession, begin_stepup, run_action};
use super::html::{Markup, Nav, h, time_el};
use super::kit::{self, field, form_error};
use super::pages::{Done, Fields, csrf_input, done_notice, page, problem, result, state_chip, text, urlencode};
use crate::admin::{AdminRequest, Password};
use crate::app::App;

fn kind_text(kind: &str) -> &'static str {
    match kind {
        "thread_reply" => "Reply in a thread",
        "from" => "Mail from a sender",
        "query" => "Mail matching a search",
        "no_reply_by" => "No reply by a deadline",
        _ => "Watch",
    }
}

pub async fn page_view(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Query(d): Query<Done>,
) -> Response {
    let watches = match result(run_action(&app, &s, AdminRequest::WatchesList).await) {
        Ok(v) => v,
        Err(e) => return problem(&s, "Watches", &e, "/admin"),
    };
    let sinks = result(run_action(&app, &s, AdminRequest::SinksList).await).unwrap_or_default();
    let projects: Vec<String> = result(run_action(&app, &s, AdminRequest::ProjectsList).await)
        .ok()
        .map(|v| v.as_array().into_iter().flatten().map(|p| text(&p["name"])).collect())
        .unwrap_or_default();
    let all: Vec<&Value> = watches.as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let watch_row = |w: &&Value| {
        let id = text(&w["watch_id"]);
        let until = match (w["state"].as_str(), w["deadline"].as_str()) {
            (Some("active"), Some(dl)) => h!("<span class=\"muted\">deadline</span> {}", time_el(dl)),
            (Some("active"), None) => h!("<span class=\"muted\">until</span> {}", time_el(&text(&w["expires_at"]))),
            _ => h!("<span class=\"muted\">{}</span>", w["end_reason"].as_str().unwrap_or("ended").replace('_', " ")),
        };
        let events = w["events"].as_i64().unwrap_or(0);
        h!(
            "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong> <span class=\"muted\">for</span> {} \
             <span class=\"muted\">in</span> {}<span class=\"detail\">{} · {}{}</span></span><span class=\"row-meta\">\
             {} {}<form method=\"post\" action=\"/admin/watches/{}/remove\" data-confirm=\"Delete this watch? The agent \
             is no longer told about new mail for it.\">{}<button type=\"submit\" class=\"btn\">Delete</button></form>\
             </span></div>",
            kind_text(&text(&w["kind"])),
            text(&w["client"]),
            text(&w["account"]),
            if events == 1 { "1 event".to_string() } else { format!("{events} events") },
            id.clone(),
            w["sink"].as_str().map(|s| format!(" · pushes to {s}")),
            state_chip(&text(&w["state"])),
            until,
            urlencode(&id),
            csrf_input(&s)
        )
    };
    let watch_list = if all.is_empty() {
        Markup::lit(
            "<p class=\"empty\">No agent watches anything. Agents set up watches with the watch tools, for example to \
             hear about a reply.</p>",
        )
    } else {
        h!("<div class=\"rows\">{}</div>", Markup::concat(all.iter().map(watch_row)))
    };
    let sink_rows = Markup::concat(sinks.as_array().into_iter().flatten().map(|k| {
        let name = text(&k["sink"]);
        let failed = k["failed"].as_i64().unwrap_or(0);
        let move_form = h!(
            "<form class=\"inline-form\" method=\"post\" action=\"/admin/watches/sinks/{}\">{}<input type=\"hidden\" \
             name=\"do\" value=\"project\"><select name=\"project\" aria-label=\"Project\">{}</select>\
             <button type=\"submit\" class=\"btn\">Move</button></form>",
            urlencode(&name),
            csrf_input(&s),
            kit::options(&projects, k["project"].as_str())
        );
        h!(
            "<article class=\"grant\"><p class=\"when\"><strong>{}</strong> <span class=\"muted\">{}</span> {}</p>\
             <p class=\"meta\">{} · {} active watches · {} delivered · {} waiting{}</p><div class=\"button-row\">{}\
             <form method=\"post\" action=\"/admin/watches/sinks/{}\" data-confirm=\"Remove this sink? Watches that use \
             it keep working without push.\">{}<input type=\"hidden\" name=\"do\" value=\"remove\">\
             <button type=\"submit\" class=\"btn danger\">Remove</button></form></div></article>",
            name.clone(),
            text(&k["origin"]),
            if k["project"].is_null() {
                Markup::lit("<span class=\"chip bad\">No project</span>")
            } else {
                h!("<span class=\"chip quiet\">{}</span>", text(&k["project"]))
            },
            k["created_at"].as_str().map(time_el).unwrap_or_default(),
            k["active_watches"].as_i64().unwrap_or(0),
            k["delivered"].as_i64().unwrap_or(0),
            k["pending"].as_i64().unwrap_or(0),
            if failed > 0 { format!(" · {failed} failed") } else { String::new() },
            move_form,
            urlencode(&name),
            csrf_input(&s)
        )
    }));
    let sink_list = if sink_rows.as_str().is_empty() {
        Markup::lit("<p class=\"empty\">No sink yet. Without one, agents fetch their events themselves.</p>")
    } else {
        sink_rows
    };
    let add = if projects.is_empty() {
        Markup::lit("<p class=\"meta\">Create a project first; a sink serves the connections of one project.</p>")
    } else {
        h!(
            "<form class=\"card form\" method=\"post\" action=\"/admin/watches/sinks\" data-stepup>{}{}\
             <p class=\"field\"><label for=\"sink_project\">Project</label><select id=\"sink_project\" \
             name=\"project\">{}</select></p>{}{}\
             <div class=\"actionbar\"><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <button type=\"submit\" class=\"btn primary\">Add sink</button></div></form>",
            csrf_input(&s),
            kit::input("name", "Name", "text", "", " required maxlength=\"64\" autocomplete=\"off\""),
            kit::options(&projects, None),
            kit::input(
                "url",
                "HTTPS URL",
                "url",
                "",
                " required placeholder=\"https://hooks.example.com/dove\" \
                        autocomplete=\"off\""
            ),
            kit::input(
                "secret",
                "Signing secret (at least 32 characters)",
                "password",
                "",
                " required minlength=\"32\" \
                        autocomplete=\"new-password\""
            )
        )
    };
    let body = h!(
        "{}<header class=\"page-head\"><h1>Watches and sinks</h1><p class=\"lede\">Watches tell an agent when mail \
         it waits for arrives. Sinks are webhooks Dove pushes those events to, signed and without mail content.</p>\
         </header><section class=\"block\"><h2>Watches</h2>{}</section>\
         <section class=\"block\"><h2>Sinks</h2>{}</section><section class=\"block\"><h2>New sink</h2>{}\
         <p class=\"hint\">The receiver checks the signature with the same secret, for example one made with \
         <code>openssl rand -hex 32</code>. Dove seals URL and secret and shows neither again.</p></section>",
        done_notice(d.done.as_deref()),
        watch_list,
        sink_list,
        add
    );
    page(&s, "Watches and sinks", Nav::Watches, body)
}

pub async fn remove_watch(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(id): Path<String>,
) -> Response {
    match result(run_action(&app, &s, AdminRequest::WatchesRemove { id }).await) {
        Ok(_) => Redirect::to("/admin/watches?done=ended").into_response(),
        Err(e) => problem(&s, "Not deleted", &e, "/admin/watches"),
    }
}

pub async fn add_sink(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    axum::Form(f): Fields,
) -> Response {
    let Some(name) = field(&f, "name") else { return form_error("Enter a name.") };
    let Some(project) = field(&f, "project") else { return form_error("Choose a project.") };
    let Some(url) = field(&f, "url") else { return form_error("Enter the URL.") };
    let Some(secret) = field(&f, "secret") else { return form_error("Enter the signing secret.") };
    let action = AdminRequest::SinksAdd { name, project, url, secret: Password(secret.into()) };
    begin_stepup(&app, &s, action, "/admin/watches?done=added".into()).await
}

pub async fn sink(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let req = match field(&f, "do").as_deref() {
        Some("remove") => AdminRequest::SinksRemove { name },
        Some("project") => match field(&f, "project") {
            Some(project) => AdminRequest::SinksSetProject { name, project },
            None => return problem(&s, "Not moved", "Choose a project.", "/admin/watches"),
        },
        _ => return problem(&s, "Sink", "unknown action", "/admin/watches"),
    };
    let done = if matches!(req, AdminRequest::SinksRemove { .. }) { "deleted" } else { "saved" };
    match result(run_action(&app, &s, req).await) {
        Ok(_) => Redirect::to(&format!("/admin/watches?done={done}")).into_response(),
        Err(e) => problem(&s, "Not changed", &e, "/admin/watches"),
    }
}
