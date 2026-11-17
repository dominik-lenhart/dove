//! Connections page: clients (token connections and redeemed invitations) and new invitations. Creating, rotating,
//! inviting and widening grants need a passkey confirmation; their tokens and codes are shown once on a reveal page.

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::Value;

use super::auth::{After, RevealKind, WebSession, begin_stepup_then, run_action};
use super::html::{Markup, Nav, h, time_el};
use super::kit::{self, field, fields_named, form_error, ticked};
use super::pages::{Done, Fields, csrf_input, done_notice, page, problem, result, state_chip, text, urlencode};
use crate::admin::AdminRequest;
use crate::admin::ops::GrantSpec;
use crate::app::App;

async fn names(app: &Arc<App>, s: &WebSession, req: AdminRequest, key: &str) -> Vec<String> {
    result(run_action(app, s, req).await)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.iter().map(|r| text(&r[key])).collect()))
        .unwrap_or_default()
}

pub async fn list(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>, Query(d): Query<Done>) -> Response {
    let clients = match result(run_action(&app, &s, AdminRequest::ClientsList).await) {
        Ok(v) => v,
        Err(e) => return problem(&s, "Connections", &e, "/admin"),
    };
    let rows: Vec<&Value> = clients.as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let (active, closed): (Vec<&Value>, Vec<&Value>) = rows.into_iter().partition(|c| c["state"] == "active");
    let row = |c: &&Value| {
        let kind = if c["kind"] == "token" { "Token" } else { "Signed in" };
        let used = match c["last_used_at"].as_str() {
            Some(t) => h!("<span class=\"muted\">used</span> {}", time_el(t)),
            None => Markup::lit("<span class=\"muted\">never used</span>"),
        };
        h!(
            "<a class=\"row\" href=\"/admin/connections/{}\"><span class=\"row-main\"><strong>{}</strong> \
             <span class=\"muted\">in</span> {}</span><span class=\"row-meta\">{} <span class=\"chip quiet\">{}</span> \
             {}</span></a>",
            urlencode(&text(&c["client"])),
            text(&c["client"]),
            text(&c["project"]),
            state_chip(&text(&c["state"])),
            kind,
            used
        )
    };
    let active_list = if active.is_empty() {
        Markup::lit("<p class=\"empty\">No connection is active. Create a token or invite an agent host.</p>")
    } else {
        h!("<div class=\"rows\">{}</div>", Markup::concat(active.iter().map(row)))
    };
    let closed_list = if closed.is_empty() {
        Markup::default()
    } else {
        h!(
            "<section class=\"block\"><h2>Revoked and expired</h2><div class=\"rows\">{}</div></section>",
            Markup::concat(closed.iter().map(row))
        )
    };
    let body = h!(
        "{}<header class=\"page-head\"><h1>Connections</h1><p class=\"lede\">Every agent host that can reach Dove, and \
         what it may do in which mailbox.</p><div class=\"head-actions\">\
         <a class=\"btn primary\" href=\"/admin/connections/new?kind=invite\">Invite</a>\
         <a class=\"btn\" href=\"/admin/connections/new?kind=token\">New token</a></div></header>\
         <section class=\"block\"><h2>Active</h2>{}</section>{}",
        done_notice(d.done.as_deref()),
        active_list,
        closed_list
    );
    page(&s, "Connections", Nav::Connections, body)
}

#[derive(Deserialize, Default)]
pub struct NewQuery {
    kind: Option<String>,
}

pub async fn new_form(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Query(q): Query<NewQuery>,
) -> Response {
    let invite = q.kind.as_deref() != Some("token");
    let projects = names(&app, &s, AdminRequest::ProjectsList, "name").await;
    if projects.is_empty() {
        return problem(&s, "No project yet", "Create a project and add a mailbox to it first.", "/admin/projects");
    }
    let mailboxes = names(&app, &s, AdminRequest::AccountsList, "alias").await;
    let boxes = Markup::concat(mailboxes.iter().map(|m| {
        h!(
            "<label class=\"check\"><input type=\"checkbox\" name=\"account\" value=\"{}\"> <span>{}</span></label>",
            m,
            m
        )
    }));
    let (title, lede, button) = if invite {
        (
            "Invite an agent host",
            "Dove makes a one-time code, valid for 10 minutes. Paste it into dove login on the other computer, or on \
             the approval page when ChatGPT or Claude connects.",
            "Create invitation",
        )
    } else {
        (
            "New token",
            "Dove makes a token for an MCP client that takes a bearer token. It is shown once.",
            "Create token",
        )
    };
    let redact = if app.cfg.clients.redact_secrets_default { " checked" } else { "" };
    let body = h!(
        "<header class=\"page-head\"><p class=\"crumb\"><a href=\"/admin/connections\">Connections</a></p>\
         <h1>{}</h1><p class=\"lede\">{}</p></header>\
         <form class=\"card form\" method=\"post\" action=\"/admin/connections/new\" data-stepup>{}\
         <input type=\"hidden\" name=\"kind\" value=\"{}\">\
         {}<p class=\"field\"><label for=\"project\">Project</label><select id=\"project\" name=\"project\">{}</select>\
         <span class=\"hint\">The connection can only reach mailboxes of this project.</span></p>\
         <fieldset class=\"field\"><legend>Mailboxes</legend><div class=\"checks\">{}</div></fieldset>\
         <fieldset class=\"field\"><legend>It may</legend><div class=\"checks\">{}</div>\
         <span class=\"hint\">Draft needs read, organize needs read, delete needs organize, send needs draft.</span>\
         </fieldset>{}{}\
         <label class=\"check\"><input type=\"checkbox\" name=\"redact\" value=\"1\"{}> <span>Hide secrets in \
         lists</span> <span class=\"muted\">codes and keys in subjects and snippets</span></label>\
         <div class=\"actionbar\"><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
         <button type=\"submit\" class=\"btn primary\">{}</button></div></form>",
        title,
        lede,
        csrf_input(&s),
        if invite { "invite" } else { "token" },
        kit::input("name", "Name", "text", "", " required maxlength=\"64\" autocomplete=\"off\""),
        kit::options(&projects, None),
        boxes,
        kit::action_boxes("action", &["read".to_string()], app.cfg.allow_send),
        kit::expiry_select("expires"),
        kit::input(
            "allow_ip",
            "Only from these addresses (optional)",
            "text",
            "",
            " placeholder=\"203.0.113.7, 10.0.0.0/8\""
        ),
        Markup::lit(redact),
        button
    );
    page(&s, title, Nav::Connections, body)
}

pub async fn create(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    axum::Form(f): Fields,
) -> Response {
    let Some(name) = field(&f, "name") else { return form_error("Enter a name.") };
    let Some(project) = field(&f, "project") else { return form_error("Choose a project.") };
    let accounts = fields_named(&f, "account");
    if accounts.is_empty() {
        return form_error("Choose at least one mailbox.");
    }
    let actions = fields_named(&f, "action").join(",");
    if actions.is_empty() {
        return form_error("Choose what the connection may do.");
    }
    let expires = field(&f, "expires");
    let allow_ip = kit::ip_list(field(&f, "allow_ip"));
    let redact_secrets = Some(ticked(&f, "redact"));
    if field(&f, "kind").as_deref() == Some("token") {
        let grants = accounts.into_iter().map(|account| GrantSpec { account, actions: actions.clone() }).collect();
        let action = AdminRequest::ClientsCreate { name, project, grants, expires, allow_ip, redact_secrets };
        begin_stepup_then(&app, &s, action, After::Reveal(RevealKind::Token)).await
    } else {
        let action = AdminRequest::ClientsInvite {
            name,
            project,
            accounts,
            capabilities: actions,
            expires,
            allow_ip,
            redact_secrets,
        };
        begin_stepup_then(&app, &s, action, After::Reveal(RevealKind::Invite)).await
    }
}

pub async fn detail(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
    Query(d): Query<Done>,
) -> Response {
    let c = match result(run_action(&app, &s, AdminRequest::ClientsShow { name: name.clone() }).await) {
        Ok(v) => v,
        Err(e) => return problem(&s, "Connection", &e, "/admin/connections"),
    };
    let project = text(&c["project"]);
    let base = format!("/admin/connections/{}", urlencode(&name));
    let state = if c["revoked_at"].is_string() {
        "revoked"
    } else if c["expires_at"].as_str().is_some_and(|e| e <= crate::util::rfc3339(crate::util::now_unix()).as_str()) {
        "expired"
    } else {
        "active"
    };
    let ips = kit::strings(&c["allowed_cidrs"]);
    let facts = Markup::concat([
        kit::fact("Project", project.clone()),
        kit::fact("Kind", if c["kind"] == "token" { "Token" } else { "Signed in with an invitation" }),
        kit::fact_m("Created", time_el(&text(&c["created_at"]))),
        kit::fact_m(
            "Expires",
            match c["expires_at"].as_str() {
                Some(t) => time_el(t),
                None => Markup::lit("Never"),
            },
        ),
        kit::fact_m(
            "Last used",
            match c["last_used_at"].as_str() {
                Some(t) => h!("{} {}", time_el(t), c["last_ip"].as_str().map(|ip| format!("from {ip}"))),
                None => Markup::lit("Never"),
            },
        ),
        kit::fact("Only from", if ips.is_empty() { "Any address".to_string() } else { ips.join(", ") }),
    ]);
    let temporary = Markup::concat(c["temporary"].as_array().into_iter().flatten().map(|t| {
        h!(
            "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong> {}</span><span class=\"row-meta\">\
             <span class=\"muted\">until</span> {} <a href=\"/admin/requests/{}\">request</a></span></div>",
            text(&t["account"]),
            text(&t["actions"]),
            time_el(&text(&t["expires_at"])),
            text(&t["request_id"])
        )
    }));
    let temporary = if temporary.as_str().is_empty() {
        Markup::default()
    } else {
        h!("<section class=\"block\"><h2>Temporary access</h2><div class=\"rows\">{}</div></section>", temporary)
    };
    let manage = if state == "revoked" {
        Markup::lit("<p class=\"notice\">This connection is revoked. Create a new one to connect again.</p>")
    } else {
        // Every mailbox of the project, with what this connection may do there now.
        let project_boxes: Vec<String> =
            result(run_action(&app, &s, AdminRequest::ProjectsShow { name: project }).await)
                .ok()
                .map(|p| p["accounts"].as_array().into_iter().flatten().map(|a| text(&a["alias"])).collect())
                .unwrap_or_default();
        let granted = |alias: &str| -> Vec<String> {
            c["grants"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|g| g["account"] == alias)
                .map(|g| text(&g["actions"]).split(',').map(str::to_string).collect())
                .unwrap_or_default()
        };
        let matrix = Markup::concat(project_boxes.iter().map(|alias| {
            h!(
                "<fieldset class=\"grant-row\"><legend>{}</legend><div class=\"checks\">{}</div></fieldset>",
                alias,
                kit::action_boxes(&format!("a.{alias}"), &granted(alias), app.cfg.allow_send)
            )
        }));
        let redaction = c["redact_secrets"] == true;
        h!(
            "<section class=\"block\"><h2>Access</h2><form method=\"post\" action=\"{}/grants\" data-stepup>{}{}\
             <p class=\"hint\">Leave a mailbox empty to take it away. Saving removes temporary access of this \
             connection.</p><div class=\"actionbar\"><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <button type=\"submit\" class=\"btn primary\">Save access</button></div></form></section>\
             <section class=\"block\"><h2>Lists</h2><form method=\"post\" action=\"{}/redaction\"{}>{}\
             <input type=\"hidden\" name=\"enabled\" value=\"{}\"><p>{}</p><button type=\"submit\" class=\"btn\">{}\
             </button><p class=\"status\" role=\"status\" aria-live=\"polite\"></p></form></section>\
             <section class=\"block\"><h2>Token</h2><div class=\"button-row\">{}\
             <form method=\"post\" action=\"{}/revoke\" data-confirm=\"Revoke this connection? Its token stops working \
             at once and its open requests are cancelled.\">{}<button type=\"submit\" class=\"btn danger\">Revoke\
             </button></form></div></section>",
            base,
            csrf_input(&s),
            matrix,
            base,
            // Showing secrets again weakens a protection: it needs the passkey (PLAN A83).
            if redaction { Markup::lit(" data-stepup") } else { Markup::default() },
            csrf_input(&s),
            if redaction { "0" } else { "1" },
            if redaction {
                "Secrets such as codes and keys are hidden in subjects and snippets of lists."
            } else {
                "Lists show subjects and snippets as they are."
            },
            if redaction { "Show secrets in lists" } else { "Hide secrets in lists" },
            if c["kind"] == "token" {
                h!(
                    "<form method=\"post\" action=\"{}/rotate\" data-stepup>{}<button type=\"submit\" class=\"btn\">\
                     New token</button><p class=\"status\" role=\"status\" aria-live=\"polite\"></p></form>",
                    base,
                    csrf_input(&s)
                )
            } else {
                Markup::default()
            },
            base,
            csrf_input(&s)
        )
    };
    let body = h!(
        "{}<header class=\"page-head\"><p class=\"crumb\"><a href=\"/admin/connections\">Connections</a></p>\
         <h1>{}</h1><p class=\"meta\">{}</p></header><section class=\"block\"><dl class=\"facts\">{}</dl></section>\
         {}{}",
        done_notice(d.done.as_deref()),
        name.clone(),
        state_chip(state),
        facts,
        temporary,
        manage
    );
    page(&s, "Connection", Nav::Connections, body)
}

pub async fn set_grants(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let mut by_box: Vec<(String, Vec<String>)> = Vec::new();
    for (k, v) in &f {
        let Some(alias) = k.strip_prefix("a.") else { continue };
        match by_box.iter_mut().find(|(a, _)| a == alias) {
            Some((_, acts)) => acts.push(v.clone()),
            None => by_box.push((alias.to_string(), vec![v.clone()])),
        }
    }
    let grants = by_box.into_iter().map(|(account, acts)| GrantSpec { account, actions: acts.join(",") }).collect();
    let back = format!("/admin/connections/{}?done=grants", urlencode(&name));
    super::auth::begin_stepup(&app, &s, AdminRequest::ClientsSetGrants { name, grants }, back).await
}

pub async fn redaction(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let back = format!("/admin/connections/{}", urlencode(&name));
    let enabled = field(&f, "enabled").as_deref() == Some("1");
    let req = AdminRequest::ClientsSetRedaction { name, enabled };
    if super::needs_step_up(&req) {
        return super::auth::begin_stepup(&app, &s, req, format!("{back}?done=saved")).await;
    }
    match result(run_action(&app, &s, req).await) {
        Ok(_) => Redirect::to(&format!("{back}?done=saved")).into_response(),
        Err(e) => problem(&s, "Not saved", &e, &back),
    }
}

pub async fn rotate(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
) -> Response {
    begin_stepup_then(&app, &s, AdminRequest::ClientsRotate { name }, After::Reveal(RevealKind::Token)).await
}

pub async fn revoke(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(name): Path<String>,
) -> Response {
    let back = format!("/admin/connections/{}", urlencode(&name));
    match result(run_action(&app, &s, AdminRequest::ClientsRevoke { name }).await) {
        Ok(_) => Redirect::to(&format!("{back}?done=client_revoked")).into_response(),
        Err(e) => problem(&s, "Not revoked", &e, &back),
    }
}
