//! Small helpers shared by the management pages (connections, mailboxes, projects, watches): form field access,
//! answers for script-submitted (`data-stepup`) forms, and repeated bits of markup.

use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::html::{Markup, h};

/// The first value of form field `key`, trimmed; `None` when missing or empty.
pub fn field(fields: &[(String, String)], key: &str) -> Option<String> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Every non-empty value of the repeated form field `key`.
pub fn fields_named(fields: &[(String, String)], key: &str) -> Vec<String> {
    fields.iter().filter(|(k, _)| k == key).map(|(_, v)| v.trim().to_string()).filter(|v| !v.is_empty()).collect()
}

/// Whether the checkbox `key` was sent with any value.
pub fn ticked(fields: &[(String, String)], key: &str) -> bool {
    fields.iter().any(|(k, _)| k == key)
}

/// IP addresses or ranges from a free-text field: split on commas and whitespace.
pub fn ip_list(v: Option<String>) -> Vec<String> {
    v.map(|s| s.split([',', ' ', '\n', '\r', '\t']).filter(|p| !p.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

/// The answer to a script-submitted form that cannot start its confirmation; admin.js shows the message.
pub fn form_error(msg: impl Into<String>) -> Response {
    Json(json!({ "error": msg.into() })).into_response()
}

/// Strings of a JSON array.
pub fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
}

/// The grantable actions, in dependency order, with a short explanation.
pub const ACTIONS: &[(&str, &str)] = &[
    ("read", "search and read mail"),
    ("draft", "write drafts"),
    ("organize", "label, archive, move"),
    ("delete", "move to trash or spam"),
    ("send", "send drafts"),
    ("signatures", "create and change signatures"),
];

/// Checkboxes for the actions, named `name`, with the ones in `checked` ticked. `send` only when `allow_send`.
pub fn action_boxes(name: &str, checked: &[String], allow_send: bool) -> Markup {
    Markup::concat(ACTIONS.iter().filter(|(a, _)| allow_send || *a != "send").map(|(a, help)| {
        let on = if checked.iter().any(|c| c == a) { " checked" } else { "" };
        h!(
            "<label class=\"check\"><input type=\"checkbox\" name=\"{}\" value=\"{}\"{}> <span>{}</span> \
             <span class=\"muted\">{}</span></label>",
            name.to_string(),
            *a,
            Markup::lit(on),
            *a,
            *help
        )
    }))
}

/// `<option>`s for a select; `selected` marks one value.
pub fn options(values: &[String], selected: Option<&str>) -> Markup {
    Markup::concat(values.iter().map(|v| {
        if Some(v.as_str()) == selected {
            h!("<option value=\"{}\" selected>{}</option>", v, v)
        } else {
            h!("<option value=\"{}\">{}</option>", v, v)
        }
    }))
}

/// One labelled text input.
pub fn input(id: &str, label: &str, kind: &str, value: &str, extra: &'static str) -> Markup {
    h!(
        "<p class=\"field\"><label for=\"{}\">{}</label><input id=\"{}\" name=\"{}\" type=\"{}\" value=\"{}\"{}></p>",
        id.to_string(),
        label.to_string(),
        id.to_string(),
        id.to_string(),
        kind.to_string(),
        value.to_string(),
        Markup::lit(extra)
    )
}

/// The common expiry choices of a connection.
pub fn expiry_select(id: &str) -> Markup {
    h!(
        "<p class=\"field\"><label for=\"{}\">Expires</label><select id=\"{}\" name=\"{}\">\
         <option value=\"\">Never</option><option value=\"7d\">In 7 days</option>\
         <option value=\"30d\">In 30 days</option><option value=\"90d\" selected>In 90 days</option>\
         <option value=\"365d\">In a year</option></select></p>",
        id.to_string(),
        id.to_string(),
        id.to_string()
    )
}

/// A labelled list (`<dl>`) row, left out when the value is empty.
pub fn fact(k: &'static str, v: impl Into<String>) -> Markup {
    let v = v.into();
    if v.is_empty() { Markup::default() } else { h!("<dt>{}</dt><dd>{}</dd>", k, v) }
}

/// Same as [`fact`] with markup as the value.
pub fn fact_m(k: &'static str, v: Markup) -> Markup {
    if v.as_str().is_empty() { Markup::default() } else { h!("<dt>{}</dt><dd>{}</dd>", k, v) }
}
