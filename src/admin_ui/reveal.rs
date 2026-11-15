//! The page that shows a confirmed action's secret result once: a token, an invitation code, the Google sign-in link
//! of a new Gmail mailbox, or a passkey enrolment link. The result lives in memory for five minutes, bound to the
//! session that confirmed the action, and is gone after the first view (`Cache-Control: no-store` like every admin
//! answer).

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, State};
use axum::response::Response;

use super::auth::{RevealKind, WebSession, take_reveal};
use super::html::{Markup, Nav, h};
use super::pages::{page, text};
use crate::app::App;

fn secret_box(value: &str) -> Markup {
    h!(
        "<div class=\"secret\"><input id=\"secret\" class=\"secret__value\" type=\"text\" readonly value=\"{}\" \
         spellcheck=\"false\" autocomplete=\"off\"><button type=\"button\" class=\"btn\" data-copy=\"secret\">Copy\
         </button></div>",
        value.to_string()
    )
}

pub async fn show(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(id): Path<String>,
) -> Response {
    let Some(r) = take_reveal(&app, &s, &id) else {
        let body = Markup::lit(
            "<section class=\"card\"><h1>Nothing to show</h1><p>This page shows a result only once, for five minutes, \
             in the browser that confirmed it. It was already shown or has expired. Create a new one if you need it.</p>\
             <p><a class=\"btn\" href=\"/admin\">Overview</a></p></section>",
        );
        return page(&s, "Shown already", Nav::None, body);
    };
    let v = &r.result;
    let public = app.cfg.public_url.trim_end_matches('/').to_string();
    let body = match r.kind {
        RevealKind::Token => h!(
            "<section class=\"card reveal\"><p class=\"crumb\"><a href=\"/admin/connections\">Connections</a></p>\
             <h1>Token for {}</h1><p class=\"notice\">Copy it now. Dove shows it only this once and keeps only a hash.\
             </p>{}<h2>Use it</h2><p>Give the MCP client the server address <code>{}/mcp</code> and this token as a \
             bearer token (header <code>Authorization: Bearer …</code>).</p>\
             <p><a class=\"btn primary\" href=\"/admin/connections/{}\">Done</a></p></section>",
            text(&v["client"]),
            secret_box(&text(&v["token"])),
            public.clone(),
            super::pages::urlencode(&text(&v["client"]))
        ),
        RevealKind::Invite => h!(
            "<section class=\"card reveal\"><p class=\"crumb\"><a href=\"/admin/connections\">Connections</a></p>\
             <h1>Invitation for {}</h1><p class=\"notice\">Valid once, for 10 minutes. Dove shows it only now.</p>{}\
             <h2>Use it</h2><p>On the other computer run <code>dove login --server {} --profile {}</code> and paste \
             the code. When ChatGPT or Claude connects to <code>{}/mcp</code>, paste it on the approval page instead.\
             </p><p><a class=\"btn primary\" href=\"/admin/connections\">Done</a></p></section>",
            text(&v["connection"]),
            secret_box(&text(&v["invitation"])),
            public.clone(),
            text(&v["connection"]),
            public.clone()
        ),
        RevealKind::GmailLink => h!(
            "<section class=\"card reveal\"><p class=\"crumb\"><a href=\"/admin/mailboxes\">Mailboxes</a></p>\
             <h1>Sign in with Google</h1><p>Open the link, sign in with the mailbox's address and allow access. The \
             link works once, for {} minutes.</p><p><a class=\"btn primary\" href=\"{}\" target=\"_blank\" \
             rel=\"noopener noreferrer\">Open Google sign-in</a></p><p class=\"meta\">Afterwards the mailbox shows up \
             as active under Mailboxes.</p><p><a class=\"btn\" href=\"/admin/mailboxes\">Back to mailboxes</a></p>\
             </section>",
            v["expires_in_minutes"].as_i64().unwrap_or(10),
            text(&v["open_this_link"])
        ),
        RevealKind::EnrolLink => h!(
            "<section class=\"card reveal\"><p class=\"crumb\"><a href=\"/admin/settings\">Settings</a></p>\
             <h1>Add the passkey {}</h1><p>Open this link on the device that should get the passkey, within {} \
             minutes. It works once.</p>{}<p><a class=\"btn primary\" href=\"/admin/settings\">Done</a></p></section>",
            text(&v["name"]),
            v["expires_in_minutes"].as_i64().unwrap_or(5),
            secret_box(&text(&v["open_this_link"]))
        ),
    };
    page(&s, "Shown once", Nav::None, body)
}
