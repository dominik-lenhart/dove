//! Projects page: projects, their mailboxes and connections. A project draws the line around what its connections
//! can ever be granted.

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde_json::Value;

use super::auth::{WebSession, run_action};
use super::html::{Markup, Nav, h};
use super::kit::{self, field};
use super::pages::{Done, Fields, csrf_input, done_notice, page, problem, result, state_chip, text, urlencode};
use crate::admin::AdminRequest;
use crate::app::App;

fn base(name: &str) -> String {
    format!("/admin/projects/{}", urlencode(name))
}

pub async fn list(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>, Query(d): Query<Done>) -> Response {
    let projects = match result(run_action(&app, &s, AdminRequest::ProjectsList).await) {
        Ok(v) => v,
        Err(e) => return problem(&s, "Projects", &e, "/admin"),
    };
    let rows: Vec<Markup> = projects
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            let n = p["accounts"].as_i64().unwrap_or(0);
            let c = p["active_clients"].as_i64().unwrap_or(0);
            h!(
                "<a class=\"row\" href=\"{}\"><span class=\"row-main\"><strong>{}</strong></span>\
                 <span class=\"row-meta\">{} <span class=\"muted\">·</span> {}</span></a>",
                base(&text(&p["name"])),
                text(&p["name"]),
                if n == 1 { "1 mailbox".to_string() } else { format!("{n} mailboxes") },
                if c == 1 { "1 connection".to_string() } else { format!("{c} connections") }
            )
        })
        .collect();
    let list = if rows.is_empty() {
        Markup::lit("<p class=\"empty\">No project yet. Create one, then add mailboxes to it.</p>")
    } else {
        h!("<div class=\"rows\">{}</div>", Markup::concat(rows))
    };
    let body = h!(
        "{}<header class=\"page-head\"><h1>Projects</h1><p class=\"lede\">A project groups mailboxes. A connection \
         belongs to one project and can only ever reach that project's mailboxes.</p></header>\
         <section class=\"block\">{}</section>\
         <section class=\"block\"><h2>New project</h2><form class=\"inline-form\" method=\"post\" \
         action=\"/admin/projects\">{}<div class=\"inline-fields\"><input name=\"name\" type=\"text\" required \
         maxlength=\"64\" placeholder=\"Name, e.g. office\" aria-label=\"Project name\" autocomplete=\"off\"></div>\
         <button type=\"submit\" class=\"btn primary\">Create</button></form></section>",
        done_notice(d.done.as_deref()),
        list,
        csrf_input(&s)
    );
    page(&s, "Projects", Nav::Projects, body)
}

pub async fn create(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    axum::Form(f): Fields,
) -> Response {
    let Some(name) = field(&f, "name") else { return problem(&s, "Not created", "Enter a name.", "/admin/projects") };
    match result(run_action(&app, &s, AdminRequest::ProjectsCreate { name: name.clone() }).await) {
        Ok(_) => Redirect::to(&format!("{}?done=created", base(&name))).into_response(),
        Err(e) => problem(&s, "Not created", &e, "/admin/projects"),
    }
}

pub async fn detail(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
    Query(d): Query<Done>,
) -> Response {
    let p = match result(run_action(&app, &s, AdminRequest::ProjectsShow { name: name.clone() }).await) {
        Ok(v) => v,
        Err(e) => return problem(&s, "Project", &e, "/admin/projects"),
    };
    let b = base(&name);
    let members: Vec<&Value> = p["accounts"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let member_rows = Markup::concat(members.iter().map(|a| {
        let alias = text(&a["alias"]);
        h!(
            "<div class=\"row\"><span class=\"row-main\"><a href=\"/admin/mailboxes/{}\"><strong>{}</strong></a> \
             <span class=\"muted\">{}</span></span><span class=\"row-meta\">{}<form method=\"post\" \
             action=\"{}/accounts\" data-confirm=\"Take this mailbox out of the project? Connections of the project lose \
             access to it.\">{}<input type=\"hidden\" name=\"do\" value=\"remove\"><input type=\"hidden\" \
             name=\"account\" value=\"{}\"><button type=\"submit\" class=\"btn\">Remove</button></form></span></div>",
            urlencode(&alias),
            alias.clone(),
            text(&a["email"]),
            state_chip(&text(&a["status"])),
            b.clone(),
            csrf_input(&s),
            alias
        )
    }));
    let all: Vec<String> = result(run_action(&app, &s, AdminRequest::AccountsList).await)
        .ok()
        .map(|v| v.as_array().into_iter().flatten().map(|a| text(&a["alias"])).collect())
        .unwrap_or_default();
    let outside: Vec<String> = all.into_iter().filter(|a| !members.iter().any(|m| m["alias"] == a.as_str())).collect();
    let add = if outside.is_empty() {
        Markup::lit("<p class=\"meta\">Every mailbox is in this project already.</p>")
    } else {
        h!(
            "<form class=\"inline-form\" method=\"post\" action=\"{}/accounts\">{}<input type=\"hidden\" name=\"do\" \
             value=\"add\"><div class=\"inline-fields\"><select name=\"account\" aria-label=\"Mailbox\">{}</select></div>\
             <button type=\"submit\" class=\"btn\">Add mailbox</button></form>",
            b.clone(),
            csrf_input(&s),
            kit::options(&outside, None)
        )
    };
    let clients = kit::strings(&p["clients"]);
    let client_rows = Markup::concat(clients.iter().map(|c| {
        h!(
            "<a class=\"row\" href=\"/admin/connections/{}\"><span class=\"row-main\"><strong>{}</strong></span></a>",
            urlencode(c),
            c.clone()
        )
    }));
    let body = h!(
        "{}<header class=\"page-head\"><p class=\"crumb\"><a href=\"/admin/projects\">Projects</a></p><h1>{}</h1>\
         </header><section class=\"block\"><h2>Mailboxes</h2><div class=\"rows\">{}</div>{}</section>\
         <section class=\"block\"><h2>Connections</h2><div class=\"rows\">{}</div>\
         <p><a class=\"btn\" href=\"/admin/connections/new?kind=invite\">Invite</a></p></section>",
        done_notice(d.done.as_deref()),
        name,
        if members.is_empty() {
            Markup::lit("<p class=\"empty\">No mailbox in this project yet.</p>")
        } else {
            member_rows
        },
        add,
        if clients.is_empty() {
            Markup::lit("<p class=\"empty\">No connection uses this project.</p>")
        } else {
            client_rows
        }
    );
    page(&s, "Project", Nav::Projects, body)
}

pub async fn accounts(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let b = base(&name);
    let Some(account) = field(&f, "account") else { return problem(&s, "Not changed", "Choose a mailbox.", &b) };
    let (req, done) = match field(&f, "do").as_deref() {
        Some("add") => (AdminRequest::ProjectsAddAccount { project: name, account }, "added"),
        Some("remove") => (AdminRequest::ProjectsRemoveAccount { project: name, account }, "deleted"),
        _ => return problem(&s, "Not changed", "unknown action", &b),
    };
    match result(run_action(&app, &s, req).await) {
        Ok(_) => Redirect::to(&format!("{b}?done={done}")).into_response(),
        Err(e) => problem(&s, "Not changed", &e, &b),
    }
}
