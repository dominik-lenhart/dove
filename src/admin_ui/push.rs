//! Web Push in the admin UI (design 2026-11-16): the Notifications block of the settings page, subscribing this
//! browser, test notifications and removing devices. The service worker and the manifest are static files in
//! [`super`].

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{Value, json};

use super::auth::{WebSession, run_action};
use super::html::{Markup, h, time_el};
use super::pages::{csrf_input, problem, result, text, urlencode};
use crate::admin::AdminRequest;
use crate::app::App;

/// The Notifications block of the settings page. The VAPID public key rides on the form; `admin.js` reveals the
/// form only where the browser can subscribe, and the hint otherwise.
pub(super) async fn settings_block(app: &Arc<App>, s: &WebSession) -> Markup {
    let devices = match result(run_action(app, s, AdminRequest::PushList).await) {
        Ok(v) => {
            let rows: Vec<Markup> = v.as_array().into_iter().flatten().map(|d| device_row(s, d)).collect();
            if rows.is_empty() {
                Markup::lit("<p class=\"empty\">No device gets notifications yet.</p>")
            } else {
                h!("<div class=\"rows\">{}</div>", Markup::concat(rows))
            }
        }
        Err(e) => h!("<p class=\"notice error\">{}</p>", e),
    };
    let form = match crate::push::public_key(app).await {
        Ok(key) => h!(
            "<form class=\"inline-form\" data-push-form data-push-key=\"{}\" hidden>\
             <div class=\"inline-fields\"><input name=\"name\" type=\"text\" required maxlength=\"64\" \
             placeholder=\"Device, e.g. iphone\" aria-label=\"Name of this device\" autocomplete=\"off\"></div>\
             <button type=\"submit\" class=\"btn\">Turn on for this device</button>\
             <p class=\"status\" role=\"status\" aria-live=\"polite\"></p></form>",
            key
        ),
        Err(e) => h!("<p class=\"notice error\">{}</p>", e.to_string()),
    };
    h!(
        "<section class=\"block\" id=\"notifications\"><h2>Notifications</h2><p>Get a notification on your phone or \
         computer when an agent asks for something. It names the connection and what it asks for, nothing from your \
         mail. Tapping it opens the request; approving still needs your passkey.</p>{}{}\
         <p class=\"hint\" data-push-hint>On iPhone and iPad, add Dove to the Home Screen first (Share, then Add to \
         Home Screen), open it from there and turn notifications on in its Settings.</p></section>",
        devices,
        form
    )
}

fn device_row(s: &WebSession, d: &Value) -> Markup {
    let id = text(&d["id"]);
    let health = match (d["last_delivered_at"].as_str(), d["last_status"].as_i64(), d["failures"].as_i64()) {
        (_, Some(code), Some(f)) if f > 0 => h!("last push failed (HTTP {})", code.to_string()),
        (_, None, Some(f)) if f > 0 => Markup::lit("last push failed"),
        (Some(t), _, _) => h!("last delivered {}", time_el(t)),
        _ => Markup::lit("nothing sent yet"),
    };
    h!(
        "<div class=\"row\"><span class=\"row-main\"><strong>{}</strong><span class=\"detail\">{} push, added {}, \
         {}</span></span><span class=\"button-row\"><form class=\"inline-form\" method=\"post\" \
         action=\"/admin/settings/push/{}/test\">{}<button type=\"submit\" class=\"btn small\">Test</button></form>\
         <form class=\"inline-form\" method=\"post\" action=\"/admin/settings/push/{}/remove\" \
         data-confirm=\"Stop notifications to {}?\">{}<button type=\"submit\" class=\"btn danger small\">Remove\
         </button></form></span></div>",
        text(&d["name"]),
        text(&d["service"]),
        time_el(&text(&d["created_at"])),
        health,
        urlencode(&id),
        csrf_input(s),
        urlencode(&id),
        text(&d["name"]),
        csrf_input(s)
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddBody {
    name: String,
    subscription: crate::push::Subscription,
}

/// `POST /admin/settings/push` (JSON from `admin.js`): registers this browser's subscription.
pub async fn add(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    body: axum::body::Bytes,
) -> Response {
    let Ok(b) = serde_json::from_slice::<AddBody>(&body) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "The browser sent an unexpected subscription." })))
            .into_response();
    };
    match result(run_action(&app, &s, AdminRequest::PushAdd { name: b.name, subscription: b.subscription }).await) {
        Ok(_) => Json(json!({ "redirect": "/admin/settings?done=push_on#notifications" })).into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(json!({ "error": e }))).into_response(),
    }
}

/// `POST /admin/settings/push/{id}/test`.
pub async fn test(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(id): Path<String>,
) -> Response {
    match result(run_action(&app, &s, AdminRequest::PushTest { id: Some(id) }).await) {
        Ok(v) => {
            let state = v["results"][0]["state"].as_str().unwrap_or("");
            let done = match state {
                "delivered" => "push_sent",
                "device_removed" => "push_gone",
                _ => "push_failed",
            };
            Redirect::to(&format!("/admin/settings?done={done}#notifications")).into_response()
        }
        Err(e) => problem(&s, "No test sent", &e, "/admin/settings"),
    }
}

/// `POST /admin/settings/push/{id}/remove`.
pub async fn remove(
    State(app): State<Arc<App>>,
    Extension(s): Extension<WebSession>,
    Path(id): Path<String>,
) -> Response {
    match result(run_action(&app, &s, AdminRequest::PushRemove { id }).await) {
        Ok(_) => Redirect::to("/admin/settings?done=push_off#notifications").into_response(),
        Err(e) => problem(&s, "Not removed", &e, "/admin/settings"),
    }
}
