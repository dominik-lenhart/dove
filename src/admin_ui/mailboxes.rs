//! Mailboxes page: connect Gmail (the existing Google sign-in, link shown once) and IMAP mailboxes, reconnect, check,
//! enable or disable, remove, indexing, send-as addresses and signatures. Connecting and reconnecting need a passkey
//! confirmation; an IMAP password travels as `admin::Password` and is never put on a page.

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::Value;

use super::auth::{After, RevealKind, WebSession, begin_stepup, begin_stepup_then, run_action};
use super::html::{Markup, Nav, h, time_el};
use super::kit::{self, field, form_error, ticked};
use super::pages::{Done, Fields, csrf_input, done_notice, page, problem, result, state_chip, text, urlencode};
use crate::admin::{AdminRequest, Password};
use crate::app::App;
use crate::imap::{ServerEndpoint, TlsMode};

fn base(alias: &str) -> String {
    format!("/admin/mailboxes/{}", urlencode(alias))
}

fn index_chip(ix: Option<&Value>) -> Markup {
    let Some(a) = ix else { return Markup::default() };
    let stage = text(&a["stage"]);
    let (chip, label) = match (stage.as_str(), a["last_error"].is_string()) {
        ("disabled", _) => ("quiet", "Not indexed"),
        (_, true) => ("bad", "Sync error"),
        ("ready", false) => ("done", "Indexed"),
        _ => ("wait", "Indexing"),
    };
    h!("<span class=\"chip {}\">{}</span>", chip, label)
}

pub async fn list(State(app): State<Arc<App>>, Extension(s): Extension<WebSession>, Query(d): Query<Done>) -> Response {
    let accounts = match result(run_action(&app, &s, AdminRequest::AccountsList).await) {
        Ok(v) => v,
        Err(e) => return problem(&s, "Mailboxes", &e, "/admin"),
    };
    let index = result(run_action(&app, &s, AdminRequest::IndexStatus { alias: None }).await).unwrap_or_default();
    let ix = |alias: &str| index["accounts"].as_array().and_then(|a| a.iter().find(|x| x["account"] == alias));
    let rows: Vec<Markup> = accounts
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            let alias = text(&a["alias"]);
            h!(
                "<a class=\"row\" href=\"{}\"><span class=\"row-main\"><strong>{}</strong> <span class=\"muted\">{}\
                 </span></span><span class=\"row-meta\">{} {} <span class=\"chip quiet\">{}</span></span></a>",
                base(&alias),
                alias.clone(),
                text(&a["email"]),
                state_chip(&text(&a["status"])),
                index_chip(ix(&alias)),
                if a["provider"] == "imap" { "IMAP" } else { "Gmail" }
            )
        })
        .collect();
    let list = if rows.is_empty() {
        Markup::lit("<p class=\"empty\">No mailbox is connected yet.</p>")
    } else {
        h!("<div class=\"rows\">{}</div>", Markup::concat(rows))
    };
    let body = h!(
        "{}<header class=\"page-head\"><h1>Mailboxes</h1><p class=\"lede\">The mailboxes Dove can reach. Agents see \
         only what a connection grants them.</p><div class=\"head-actions\">\
         <a class=\"btn primary\" href=\"/admin/mailboxes/new?provider=gmail\">Connect Gmail</a>\
         <a class=\"btn\" href=\"/admin/mailboxes/new?provider=imap\">Connect IMAP</a></div></header>\
         <section class=\"block\">{}</section>",
        done_notice(d.done.as_deref()),
        list
    );
    page(&s, "Mailboxes", Nav::Mailboxes, body)
}

#[derive(Deserialize, Default)]
pub struct NewQuery {
    provider: Option<String>,
}

fn endpoint_fields(which: &'static str, label: &'static str, port: &'static str) -> Markup {
    h!(
        "<fieldset class=\"field\"><legend>{}</legend><div class=\"inline-fields\">\
         <input name=\"{}_host\" type=\"text\" placeholder=\"Server, e.g. imap.example.com\" aria-label=\"{} server\" \
         autocomplete=\"off\"><input name=\"{}_port\" type=\"number\" min=\"1\" max=\"65535\" placeholder=\"{}\" \
         aria-label=\"{} port\" inputmode=\"numeric\"><select name=\"{}_tls\" aria-label=\"{} encryption\">\
         <option value=\"implicit\">TLS</option><option value=\"starttls\">STARTTLS</option></select></div></fieldset>",
        label,
        which,
        label,
        which,
        port,
        label,
        which,
        label
    )
}

pub async fn new_form(Extension(s): Extension<WebSession>, Query(q): Query<NewQuery>) -> Response {
    let imap = q.provider.as_deref() == Some("imap");
    let alias_hint = "<span class=\"hint\">A short name agents use for this mailbox, e.g. work.</span>";
    let body = if imap {
        h!(
            "<header class=\"page-head\"><p class=\"crumb\"><a href=\"/admin/mailboxes\">Mailboxes</a></p>\
             <h1>Connect an IMAP mailbox</h1><p class=\"lede\">Dove checks the login and the SMTP server before it \
             saves anything. The password is sealed and never shown again.</p></header>\
             <form class=\"card form\" method=\"post\" action=\"/admin/mailboxes/new\" data-stepup>{}\
             <input type=\"hidden\" name=\"provider\" value=\"imap\">\
             <div class=\"field-with-hint\">{}{}</div>{}{}\
             <p class=\"field\"><label for=\"preset\">Provider</label><select id=\"preset\" name=\"preset\">\
             <option value=\"\">Find out from the address</option><option value=\"strato\">Strato</option>\
             <option value=\"icloud\">iCloud</option><option value=\"gmail\">Google Workspace</option>\
             <option value=\"custom\">Other: enter the servers below</option></select></p>\
             <details class=\"more\"><summary>Servers and user names</summary>{}{}{}{}{}</details>\
             <div class=\"actionbar\"><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <button type=\"submit\" class=\"btn primary\">Connect</button></div></form>",
            csrf_input(&s),
            kit::input("alias", "Name", "text", "", " required maxlength=\"64\" autocomplete=\"off\""),
            Markup::lit(alias_hint),
            kit::input("email", "Address", "email", "", " required autocomplete=\"off\""),
            kit::input(
                "password",
                "Password or app password",
                "password",
                "",
                " required autocomplete=\"new-password\""
            ),
            endpoint_fields("imap", "IMAP", "993"),
            endpoint_fields("smtp", "SMTP", "465"),
            kit::input("username", "IMAP user name (if not the address)", "text", "", " autocomplete=\"off\""),
            kit::input("smtp_username", "SMTP user name (if different)", "text", "", " autocomplete=\"off\""),
            kit::input("drafts_folder", "Drafts folder (if Dove cannot find it)", "text", "", " autocomplete=\"off\"")
        )
    } else {
        h!(
            "<header class=\"page-head\"><p class=\"crumb\"><a href=\"/admin/mailboxes\">Mailboxes</a></p>\
             <h1>Connect a Gmail mailbox</h1><p class=\"lede\">After you confirm, Dove shows a Google sign-in link. Sign \
             in with this address and allow access.</p></header>\
             <form class=\"card form\" method=\"post\" action=\"/admin/mailboxes/new\" data-stepup>{}\
             <input type=\"hidden\" name=\"provider\" value=\"gmail\">\
             <div class=\"field-with-hint\">{}{}</div>{}\
             <div class=\"actionbar\"><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <button type=\"submit\" class=\"btn primary\">Continue</button></div></form>",
            csrf_input(&s),
            kit::input("alias", "Name", "text", "", " required maxlength=\"64\" autocomplete=\"off\""),
            Markup::lit(alias_hint),
            kit::input("email", "Gmail address", "email", "", " required autocomplete=\"off\"")
        )
    };
    page(&s, "Connect a mailbox", Nav::Mailboxes, body)
}

/// A server from the form, or `None` when its host is empty. The port defaults to the TLS mode's usual one.
fn endpoint(f: &[(String, String)], which: &str) -> Result<Option<ServerEndpoint>, String> {
    let Some(host) = field(f, &format!("{which}_host")) else { return Ok(None) };
    let tls = match field(f, &format!("{which}_tls")).as_deref() {
        Some("starttls") => TlsMode::StartTls,
        _ => TlsMode::Implicit,
    };
    let default = match (which, tls) {
        ("imap", TlsMode::Implicit) => 993,
        ("imap", TlsMode::StartTls) => 143,
        (_, TlsMode::Implicit) => 465,
        (_, TlsMode::StartTls) => 587,
    };
    let port = match field(f, &format!("{which}_port")) {
        Some(p) => p.parse::<u16>().map_err(|_| format!("The {} port must be a number.", which.to_uppercase()))?,
        None => default,
    };
    Ok(Some(ServerEndpoint { host, port, tls }))
}

pub async fn create(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    axum::Form(f): Fields,
) -> Response {
    let Some(alias) = field(&f, "alias") else { return form_error("Enter a name for the mailbox.") };
    let Some(email) = field(&f, "email") else { return form_error("Enter the address.") };
    if field(&f, "provider").as_deref() != Some("imap") {
        return begin_stepup_then(
            &app,
            &s,
            AdminRequest::AccountsConnect { alias, email },
            After::Reveal(RevealKind::GmailLink),
        )
        .await;
    }
    // Not trimmed: a password may start or end with a space.
    let Some(password) = f.iter().find(|(k, _)| k == "password").map(|(_, v)| v.clone()).filter(|v| !v.is_empty())
    else {
        return form_error("Enter the password.");
    };
    let (imap, smtp) = match (endpoint(&f, "imap"), endpoint(&f, "smtp")) {
        (Ok(i), Ok(s)) => (i, s),
        (Err(e), _) | (_, Err(e)) => return form_error(e),
    };
    let preset = field(&f, "preset").filter(|p| p != "custom");
    let back = base(&alias) + "?done=connected";
    let action = AdminRequest::AccountsConnectImap {
        alias,
        email,
        username: field(&f, "username"),
        smtp_username: field(&f, "smtp_username"),
        password: Password(password.into()),
        imap,
        smtp,
        drafts_folder: field(&f, "drafts_folder"),
        preset,
    };
    begin_stepup(&app, &s, action, back).await
}

async fn account(app: &Arc<App>, s: &WebSession, alias: &str) -> Result<Value, String> {
    let all = result(run_action(app, s, AdminRequest::AccountsList).await)?;
    all.as_array()
        .and_then(|a| a.iter().find(|x| x["alias"] == alias).cloned())
        .ok_or_else(|| format!("unknown mailbox '{alias}'"))
}

pub async fn detail(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(alias): Path<String>,
    Query(d): Query<Done>,
) -> Response {
    detail_page(&app, &s, &alias, done_notice(d.done.as_deref())).await
}

async fn signature_form(app: &Arc<App>, s: &WebSession, mailbox: &str, address: Option<&str>) -> Markup {
    let current = result(
        run_action(
            app,
            s,
            AdminRequest::AccountsSignatureShow { account: mailbox.to_string(), alias: address.map(str::to_string) },
        )
        .await,
    )
    .ok()
    .and_then(|v| v["signature"].as_str().map(str::to_string))
    .unwrap_or_default();
    let label = match address {
        Some(a) => format!("Signature for {a}"),
        None => "Signature".to_string(),
    };
    h!(
        "<form class=\"sig\" method=\"post\" action=\"{}/signature\" data-stepup>{}<input type=\"hidden\" name=\"for\" value=\"{}\">\
         <p class=\"field\"><label>{}<textarea name=\"signature\" rows=\"4\" maxlength=\"4000\">{}</textarea></label>\
         <span class=\"hint\">Plain text of the default signature (an HTML version stays). Leave empty to remove the default.</span></p>\
         <button type=\"submit\" class=\"btn\">Save signature</button><p class=\"status\" role=\"status\" aria-live=\"polite\"></p></form>",
        base(mailbox),
        csrf_input(s),
        address.unwrap_or("").to_string(),
        label,
        current
    )
}

/// Recipient rules for the agent's direct sends (PLAN A82). Saving needs a passkey: looser rules let an agent send
/// to more people on its own.
async fn send_policy_section(app: &Arc<App>, s: &WebSession, mailbox: &str) -> Markup {
    let v = result(run_action(app, s, AdminRequest::AccountsSendPolicyShow { account: mailbox.to_string() }).await)
        .unwrap_or_default();
    let p = &v["send_policy"];
    let domains: Vec<String> = p["allow_domains"].as_array().map(|a| a.iter().map(text).collect()).unwrap_or_default();
    let refuse = p["unknown_recipients"] == "refuse";
    let checked = |on: bool| if on { Markup::lit(" checked") } else { Markup::default() };
    h!(
        "<section class=\"block\"><h2>Sending rules</h2><p class=\"hint\">Apply when an agent sends on its own \
         (send_draft). Sends you approve as a request are not checked.</p>\
         <form class=\"sig\" method=\"post\" action=\"{}/send-policy\">{}\
         <p class=\"field\"><label>Allowed recipient domains<textarea name=\"domains\" rows=\"3\" maxlength=\"8000\">{}</textarea></label>\
         <span class=\"hint\">One per line; subdomains are included. Empty: any domain.</span></p>\
         <fieldset class=\"field\"><legend>Recipients this mailbox has never exchanged mail with</legend>\
         <label class=\"check\"><input type=\"radio\" name=\"unknown_recipients\" value=\"allow\"{}> <span>Allow</span></label>\
         <label class=\"check\"><input type=\"radio\" name=\"unknown_recipients\" value=\"refuse\"{}> <span>Refuse (needs the index)</span></label>\
         </fieldset><button type=\"submit\" class=\"btn\">Save sending rules</button></form></section>",
        base(mailbox),
        csrf_input(s),
        domains.join("\n"),
        checked(!refuse),
        checked(refuse)
    )
}

/// The mailbox's named signatures with their defaults; HTML and images come from the CLI or an agent.
async fn named_signatures(app: &Arc<App>, s: &WebSession, mailbox: &str) -> Markup {
    let list = result(
        run_action(app, s, AdminRequest::AccountsSignaturesList { account: mailbox.to_string(), include_html: false })
            .await,
    )
    .ok()
    .and_then(|v| v["signatures"].as_array().cloned())
    .unwrap_or_default();
    let hint = Markup::lit(
        "<p class=\"hint\">Agents pick a signature by name; the default is used when they do not. HTML signatures \
             with images are added with <code>dove accounts signatures set</code> or by an agent with the signatures \
             permission.</p>",
    );
    if list.is_empty() {
        return Markup::concat([Markup::lit("<p class=\"empty\">No named signatures yet.</p>"), hint]);
    }
    let rows = Markup::concat(list.iter().map(|x| {
        let name = text(&x["name"]);
        let defaults: Vec<String> = x["default_for"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        let images = x["images"].as_array().map(Vec::len).unwrap_or(0);
        let chips = Markup::concat([
            if x["has_html"] == true {
                Markup::lit("<span class=\"chip quiet\">HTML</span>")
            } else {
                Markup::default()
            },
            if images > 0 {
                h!("<span class=\"chip quiet\">{} images</span>", images.to_string())
            } else {
                Markup::default()
            },
            if defaults.is_empty() {
                Markup::default()
            } else {
                h!("<span class=\"chip\">Default for {}</span>", defaults.join(", "))
            },
        ]);
        let make_default = if defaults.iter().any(|d| d == "mailbox") {
            Markup::default()
        } else {
            h!(
                "<form method=\"post\" action=\"{}/signatures\" data-stepup>{}<input type=\"hidden\" name=\"do\" \
             value=\"default\"><input type=\"hidden\" name=\"name\" value=\"{}\"><button type=\"submit\" \
             class=\"btn\">Make default</button><p class=\"status\" role=\"status\" aria-live=\"polite\"></p></form>",
                base(mailbox),
                csrf_input(s),
                name.clone()
            )
        };
        h!(
            "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong> {}<span class=\"muted\">{}</span></span>\
             <span class=\"row-meta\">{}<form method=\"post\" action=\"{}/signatures\">{}\
             <input type=\"hidden\" name=\"do\" value=\"delete\"><input type=\"hidden\" name=\"name\" value=\"{}\">\
             <button type=\"submit\" class=\"btn\">Delete</button></form></span></div>",
            name.clone(),
            chips,
            text(&x["text"]).lines().next().unwrap_or_default().to_string(),
            make_default,
            base(mailbox),
            csrf_input(s),
            name
        )
    }));
    Markup::concat([h!("<div class=\"rows\">{}</div>", rows), hint])
}

async fn detail_page(app: &Arc<App>, s: &WebSession, alias: &str, notice: Markup) -> Response {
    let a = match account(app, s, alias).await {
        Ok(v) => v,
        Err(e) => return problem(s, "Mailbox", &e, "/admin/mailboxes"),
    };
    let imap = a["provider"] == "imap";
    let status = text(&a["status"]);
    let b = base(alias);
    let ix = result(run_action(app, s, AdminRequest::IndexStatus { alias: Some(alias.to_string()) }).await)
        .ok()
        .and_then(|v| v["accounts"].as_array().and_then(|x| x.first().cloned()));
    let facts = Markup::concat([
        kit::fact("Address", text(&a["email"])),
        kit::fact("Kind", if imap { "IMAP and SMTP" } else { "Gmail" }),
        kit::fact_m("Connected", a["connected_at"].as_str().map(time_el).unwrap_or_default()),
        kit::fact_m("Last used", a["last_used_at"].as_str().map(time_el).unwrap_or_default()),
        kit::fact("Last error", a["last_error"].as_str().unwrap_or("").replace('_', " ")),
    ]);
    let state_actions = {
        let toggle = if status == "disabled" {
            h!(
                "<form method=\"post\" action=\"{}/state\">{}<input type=\"hidden\" name=\"do\" value=\"enable\">\
                 <button type=\"submit\" class=\"btn\">Enable</button></form>",
                b.clone(),
                csrf_input(s)
            )
        } else {
            h!(
                "<form method=\"post\" action=\"{}/state\" data-confirm=\"Disable this mailbox? Agents lose access until \
                 you enable it again.\">{}<input type=\"hidden\" name=\"do\" value=\"disable\">\
                 <button type=\"submit\" class=\"btn\">Disable</button></form>",
                b.clone(),
                csrf_input(s)
            )
        };
        h!(
            "<div class=\"button-row\"><form method=\"post\" action=\"{}/state\">{}<input type=\"hidden\" name=\"do\" \
             value=\"check\"><button type=\"submit\" class=\"btn\">Check connection</button></form>{}\
             <form method=\"post\" action=\"{}/state\" data-confirm=\"Remove this mailbox from Dove? Its index, grants \
             and drafts records are deleted. The mailbox itself is not touched.\">{}<input type=\"hidden\" name=\"do\" \
             value=\"remove\"><button type=\"submit\" class=\"btn danger\">Remove</button></form></div>",
            b.clone(),
            csrf_input(s),
            toggle,
            b.clone(),
            csrf_input(s)
        )
    };
    let reconnect = if imap {
        h!(
            "<form method=\"post\" action=\"{}/reconnect\" data-stepup>{}\
             <p class=\"field\"><label for=\"password\">New password</label><input id=\"password\" name=\"password\" \
             type=\"password\" required autocomplete=\"new-password\"></p>\
             <div class=\"actionbar\"><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <button type=\"submit\" class=\"btn\">Reconnect</button></div></form>",
            b.clone(),
            csrf_input(s)
        )
    } else {
        h!(
            "<form method=\"post\" action=\"{}/reconnect\" data-stepup>{}<p>Sign in with Google again, for example \
             after the access was revoked.</p><div class=\"actionbar\"><p class=\"status\" role=\"status\" \
             aria-live=\"polite\"></p><button type=\"submit\" class=\"btn\">Reconnect</button></div></form>",
            b.clone(),
            csrf_input(s)
        )
    };
    let index = {
        let enabled = ix.as_ref().is_some_and(|x| x["enabled"] == true);
        let detail = match ix.as_ref().and_then(|x| x["indexed_messages"].as_i64()) {
            Some(n) => format!("{n} messages indexed."),
            None if enabled => "The first sync is running.".into(),
            None => "Search and digests need the index.".into(),
        };
        let err = ix
            .as_ref()
            .and_then(|x| x["last_error"].as_str())
            .map(|e| h!("<p class=\"notice error\">Last sync failed: {}</p>", e.replace('_', " ")))
            .unwrap_or_default();
        let buttons = if enabled {
            h!(
                "<div class=\"button-row\"><form method=\"post\" action=\"{}/index\" data-confirm=\"Rebuild the index? \
                 Search may be incomplete until it is done.\">{}<input type=\"hidden\" name=\"do\" value=\"rebuild\">\
                 <button type=\"submit\" class=\"btn\">Rebuild</button></form><form method=\"post\" action=\"{}/index\" \
                 data-confirm=\"Turn indexing off? The index is deleted at once.\">{}<input type=\"hidden\" name=\"do\" \
                 value=\"disable\"><button type=\"submit\" class=\"btn\">Turn off</button></form></div>",
                b.clone(),
                csrf_input(s),
                b.clone(),
                csrf_input(s)
            )
        } else {
            h!(
                "<form method=\"post\" action=\"{}/index\">{}<input type=\"hidden\" name=\"do\" value=\"enable\">\
                 <button type=\"submit\" class=\"btn\">Turn on indexing</button></form>",
                b.clone(),
                csrf_input(s)
            )
        };
        h!(
            "<section class=\"block\"><h2>Index</h2><p>{} {}</p>{}{}</section>",
            index_chip(ix.as_ref()),
            detail,
            err,
            buttons
        )
    };
    let identities = result(run_action(app, s, AdminRequest::AccountsAliasList { account: alias.to_string() }).await)
        .unwrap_or_default();
    let aliases: Vec<Value> = identities["aliases"].as_array().cloned().unwrap_or_default();
    let mut sigs = vec![named_signatures(app, s, alias).await, signature_form(app, s, alias, None).await];
    for x in &aliases {
        sigs.push(signature_form(app, s, alias, Some(&text(&x["address"]))).await);
    }
    let alias_section = if imap {
        let rows = Markup::concat(aliases.iter().map(|x| {
            let addr = text(&x["address"]);
            h!(
                "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong> <span class=\"muted\">{}</span>\
                 </span><span class=\"row-meta\">{}<form method=\"post\" action=\"{}/aliases\">{}\
                 <input type=\"hidden\" name=\"do\" value=\"remove\"><input type=\"hidden\" name=\"address\" value=\"{}\">\
                 <button type=\"submit\" class=\"btn\">Remove</button></form></span></div>",
                addr.clone(),
                text(&x["name"]),
                if x["envelope"] == true {
                    Markup::lit("<span class=\"chip quiet\">Own sender</span>")
                } else {
                    Markup::default()
                },
                b.clone(),
                csrf_input(s),
                addr
            )
        }));
        h!(
            "<section class=\"block\"><h2>Send-as addresses</h2><div class=\"rows\">{}</div>\
             <form class=\"inline-form\" method=\"post\" action=\"{}/aliases\" data-stepup>{}\
             <input type=\"hidden\" name=\"do\" value=\"add\"><div class=\"inline-fields\"><input name=\"address\" type=\"email\" required \
             placeholder=\"Address\" aria-label=\"Address\"><input name=\"name\" type=\"text\" placeholder=\"Name \
             (optional)\" aria-label=\"Name\"></div><label class=\"check\"><input type=\"checkbox\" name=\"envelope\" \
             value=\"1\"> <span>Use it as the SMTP sender too</span></label>\
             <button type=\"submit\" class=\"btn\">Add address</button><p class=\"status\" role=\"status\" aria-live=\"polite\"></p></form></section>",
            if aliases.is_empty() {
                Markup::lit("<p class=\"empty\">Drafts are sent from the mailbox's own address.</p>")
            } else {
                rows
            },
            b.clone(),
            csrf_input(s)
        )
    } else {
        Markup::default()
    };
    let body = h!(
        "{}<header class=\"page-head\"><p class=\"crumb\"><a href=\"/admin/mailboxes\">Mailboxes</a></p><h1>{}</h1>\
         <p class=\"meta\">{} {}</p></header><section class=\"block\"><dl class=\"facts\">{}</dl>{}</section>\
         <section class=\"block\"><h2>Reconnect</h2>{}</section>{}{}{}\
         <section class=\"block\"><h2>Signatures</h2>{}</section>",
        notice,
        alias.to_string(),
        state_chip(&status),
        index_chip(ix.as_ref()),
        facts,
        state_actions,
        reconnect,
        index,
        alias_section,
        send_policy_section(app, s, alias).await,
        Markup::concat(sigs)
    );
    page(s, "Mailbox", Nav::Mailboxes, body)
}

fn check_notice(v: &Value) -> Markup {
    let Some(r) = v.as_array().and_then(|a| a.first()) else { return Markup::default() };
    let ok = r["profile_ok"] == true || (r["imap_ok"] == true && r["smtp_ok"] == true);
    if ok {
        return Markup::lit("<p class=\"notice ok\" role=\"status\">The connection works.</p>");
    }
    if r["status"].as_str().is_some_and(|st| st != "active") {
        return h!(
            "<p class=\"notice error\" role=\"status\">Not checked: the mailbox is {}.</p>",
            text(&r["status"]).replace('_', " ")
        );
    }
    let parts: Vec<String> = [("IMAP", &r["imap_error"]), ("SMTP", &r["smtp_error"]), ("Gmail", &r["error"])]
        .iter()
        .filter_map(|(k, e)| e.as_str().map(|e| format!("{k}: {}", e.replace('_', " "))))
        .collect();
    h!("<p class=\"notice error\" role=\"status\">The check failed. {}</p>", parts.join(", "))
}

pub async fn state(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(alias): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let b = base(&alias);
    let (req, done) = match field(&f, "do").as_deref() {
        Some("check") => {
            let r = result(run_action(&app, &s, AdminRequest::AccountsCheck { alias: Some(alias.clone()) }).await);
            let notice = match r {
                Ok(v) => check_notice(&v),
                Err(e) => h!("<p class=\"notice error\">{}</p>", e),
            };
            return detail_page(&app, &s, &alias, notice).await;
        }
        Some("enable") => (AdminRequest::AccountsEnable { alias }, format!("{b}?done=enabled")),
        Some("disable") => (AdminRequest::AccountsDisable { alias }, format!("{b}?done=disabled")),
        Some("remove") => (AdminRequest::AccountsRemove { alias }, "/admin/mailboxes?done=deleted".to_string()),
        _ => return problem(&s, "Mailbox", "unknown action", &b),
    };
    match result(run_action(&app, &s, req).await) {
        Ok(_) => Redirect::to(&done).into_response(),
        Err(e) => problem(&s, "Not changed", &e, &b),
    }
}

pub async fn reconnect(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(alias): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let a = match account(&app, &s, &alias).await {
        Ok(v) => v,
        Err(e) => return form_error(e),
    };
    if a["provider"] == "imap" {
        let Some(password) = f.iter().find(|(k, _)| k == "password").map(|(_, v)| v.clone()).filter(|v| !v.is_empty())
        else {
            return form_error("Enter the new password.");
        };
        let back = base(&alias) + "?done=reconnected";
        let action = AdminRequest::AccountsReconnectImap { alias, password: Password(password.into()) };
        return begin_stepup(&app, &s, action, back).await;
    }
    begin_stepup_then(&app, &s, AdminRequest::AccountsReconnect { alias }, After::Reveal(RevealKind::GmailLink)).await
}

pub async fn index(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(alias): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let b = base(&alias);
    let (req, done) = match field(&f, "do").as_deref() {
        Some("enable") => (AdminRequest::IndexEnable { alias }, "indexing"),
        Some("disable") => (AdminRequest::IndexDisable { alias }, "index_off"),
        Some("rebuild") => (AdminRequest::IndexRebuild { alias }, "rebuild"),
        _ => return problem(&s, "Index", "unknown action", &b),
    };
    match result(run_action(&app, &s, req).await) {
        Ok(_) => Redirect::to(&format!("{b}?done={done}")).into_response(),
        Err(e) => problem(&s, "Not changed", &e, &b),
    }
}

pub async fn aliases(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(alias): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let b = base(&alias);
    let Some(address) = field(&f, "address") else { return problem(&s, "Address", "Enter an address.", &b) };
    let (req, done) = match field(&f, "do").as_deref() {
        Some("add") => (
            AdminRequest::AccountsAliasAdd {
                account: alias,
                address,
                name: field(&f, "name"),
                envelope: ticked(&f, "envelope"),
            },
            "added",
        ),
        Some("remove") => (AdminRequest::AccountsAliasRemove { account: alias, address }, "deleted"),
        _ => return problem(&s, "Address", "unknown action", &b),
    };
    if super::needs_step_up(&req) {
        return begin_stepup(&app, &s, req, format!("{b}?done={done}")).await;
    }
    match result(run_action(&app, &s, req).await) {
        Ok(_) => Redirect::to(&format!("{b}?done={done}")).into_response(),
        Err(e) => problem(&s, "Not changed", &e, &b),
    }
}

pub async fn signatures(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(alias): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let b = base(&alias);
    let Some(name) = field(&f, "name") else { return problem(&s, "Signature", "no signature named", &b) };
    let (req, done) = match field(&f, "do").as_deref() {
        Some("default") => {
            (AdminRequest::AccountsSignatureDefault { account: alias, alias: None, name: Some(name) }, "saved")
        }
        Some("delete") => (AdminRequest::AccountsSignatureDelete { account: alias, name }, "deleted"),
        _ => return problem(&s, "Signature", "unknown action", &b),
    };
    if super::needs_step_up(&req) {
        return begin_stepup(&app, &s, req, format!("{b}?done={done}")).await;
    }
    match result(run_action(&app, &s, req).await) {
        Ok(_) => Redirect::to(&format!("{b}?done={done}")).into_response(),
        Err(e) => problem(&s, "Not changed", &e, &b),
    }
}

pub async fn signature(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(alias): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let b = base(&alias);
    // Line ends from the browser are CRLF; the signature is stored with LF.
    let signature =
        f.iter().find(|(k, _)| k == "signature").map(|(_, v)| v.replace("\r\n", "\n")).filter(|v| !v.trim().is_empty());
    let req = AdminRequest::AccountsSignatureSet { account: alias, alias: field(&f, "for"), signature };
    begin_stepup(&app, &s, req, format!("{b}?done=saved")).await
}

pub async fn send_policy(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(alias): Path<String>,
    axum::Form(f): Fields,
) -> Response {
    let b = base(&alias);
    let domains: Vec<String> = f
        .iter()
        .filter(|(k, _)| k == "domains")
        .flat_map(|(_, v)| v.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect::<Vec<_>>())
        .collect();
    // Checked before the passkey prompt, so a typo does not cost a step-up.
    if let Err(e) = crate::send_policy::parse_domains(&domains) {
        return problem(&s, "Not saved", &e.to_string(), &b);
    }
    let unknown_recipients = match field(&f, "unknown_recipients").as_deref() {
        Some("refuse") => "refuse",
        _ => "allow",
    };
    let action = AdminRequest::AccountsSendPolicySet {
        account: alias,
        allow_domains: domains,
        unknown_recipients: unknown_recipients.to_string(),
    };
    begin_stepup(&app, &s, action, format!("{b}?done=saved")).await
}
